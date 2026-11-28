// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::devices::virtio::pmem::device::{BackendPmem, PmemError};
use crate::vmm_config::RateLimiterConfig;

/// Errors associated wit the operations allowed on a pmem device
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemConfigError {
    /// Attempt to add pmem as a root device while the root device defined as a block device
    AddingSecondRootDevice,
    /// A root pmem device already exist
    RootPmemDeviceAlreadyExist,
    /// Unable to create the virtio-pmem device: {0}
    CreateDevice(#[from] PmemError),
    /// Error accessing underlying file: {0}
    File(std::io::Error),
    /// Unable to patch the pmem device: {0} Please verify the request arguments.
    DeviceUpdate(crate::VmmError),
    /// A pmem device takes either `path_on_host` or `size_mib`, one of them alone
    Backing,
    /// A pmem device's `size_mib` must be a positive multiple of 2 MiB: {0}
    Size(u64),
    /// A pmem device of `size_mib`, which the memory backend serves, is neither read-only nor the root device
    BackendFlags,
}

/// Configuration for updating a pmem device at runtime.
/// Only the rate limiter can be updated.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PmemDeviceUpdateConfig {
    /// The pmem device ID.
    pub id: String,
    /// New rate limiter config.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Use this structure to setup a Pmem device before boothing the kernel.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PmemConfig {
    /// Unique identifier of the device.
    pub id: String,
    /// Path of the drive. Empty for a device of `size_mib`.
    // No `skip_serializing_if` here or below: snapshots serialize the config with bitcode, which
    // must find every field.
    #[serde(default)]
    pub path_on_host: String,
    /// The size of a device with no backing file, whose memory the VM's memory backend serves,
    /// as it serves guest memory (`PUT /memory-backend`, `/snapshot/load`'s `mem_backend`).
    #[serde(default)]
    pub size_mib: Option<u64>,
    /// Use this pmem device for rootfs
    #[serde(default)]
    pub root_device: bool,
    /// Map the file as read only
    #[serde(default)]
    pub read_only: bool,
    /// Rate Limiter for flush operations.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Wrapper for the collection that holds all the Pmem device configs.
#[derive(Debug, Default)]
pub struct PmemBuilder {
    /// The list of pmem device configs
    pub configs: Vec<PmemConfig>,
    /// The memory of restored devices of `size_mib`, by ID, which the memory backend serves,
    /// made as their snapshot's guest memory is, for their devices to take as they are restored.
    pub backend: HashMap<String, BackendPmem>,
}

impl PmemConfig {
    /// Checks the device has one backing, a file or the memory backend, and for the latter, a
    /// size a pmem device can have and no flags only a file can take.
    pub fn validate(&self) -> Result<(), PmemConfigError> {
        match (self.path_on_host.is_empty(), self.size_mib) {
            (false, None) => Ok(()),
            (true, Some(size_mib)) => {
                if size_mib == 0 || size_mib % 2 != 0 {
                    return Err(PmemConfigError::Size(size_mib));
                }
                if self.read_only || self.root_device {
                    return Err(PmemConfigError::BackendFlags);
                }
                Ok(())
            }
            _ => Err(PmemConfigError::Backing),
        }
    }

    /// Whether the VM's memory backend serves the device's memory, as it serves guest memory.
    pub fn backend_served(&self) -> bool {
        self.size_mib.is_some()
    }
}

impl PmemBuilder {
    /// Specifies whether there is a root block device already present in the list.
    pub fn has_root_device(&self) -> bool {
        self.configs.iter().any(|c| c.root_device)
    }

    /// Add or replace a config, validating root device constraints.
    pub fn build(
        &mut self,
        config: PmemConfig,
        has_block_root: bool,
    ) -> Result<(), PmemConfigError> {
        config.validate()?;
        if config.root_device && has_block_root {
            return Err(PmemConfigError::AddingSecondRootDevice);
        }
        let position = self.configs.iter().position(|c| c.id == config.id);
        if let Some(index) = position {
            if !self.configs[index].root_device && config.root_device && self.has_root_device() {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            self.configs[index] = config;
        } else {
            if config.root_device && self.has_root_device() {
                return Err(PmemConfigError::RootPmemDeviceAlreadyExist);
            }
            self.configs.push(config);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device has a file or a size, one alone; one of a size, which the memory backend serves,
    /// is a multiple of 2 MiB, neither read-only nor the root device.
    #[test]
    fn test_pmem_config_validate() {
        let file = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            ..Default::default()
        };
        file.validate().unwrap();
        assert!(!file.backend_served());
        let sized = PmemConfig {
            id: "1".into(),
            size_mib: Some(64),
            ..Default::default()
        };
        sized.validate().unwrap();
        assert!(sized.backend_served());

        let both = PmemConfig {
            size_mib: Some(64),
            ..file.clone()
        };
        assert!(matches!(both.validate(), Err(PmemConfigError::Backing)));
        let neither = PmemConfig {
            id: "1".into(),
            ..Default::default()
        };
        assert!(matches!(neither.validate(), Err(PmemConfigError::Backing)));
        for size_mib in [0, 3] {
            let odd = PmemConfig {
                size_mib: Some(size_mib),
                ..sized.clone()
            };
            assert!(matches!(odd.validate(), Err(PmemConfigError::Size(s)) if s == size_mib));
        }
        for (read_only, root_device) in [(true, false), (false, true)] {
            let flagged = PmemConfig {
                read_only,
                root_device,
                ..sized.clone()
            };
            assert!(matches!(
                flagged.validate(),
                Err(PmemConfigError::BackendFlags)
            ));
        }
    }

    #[test]
    fn test_pmem_builder_build() {
        let mut builder = PmemBuilder::default();

        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        builder.build(config.clone(), false).unwrap();
        assert_eq!(builder.configs.len(), 1);
        assert!(builder.has_root_device());

        // First device got replaced with new one
        config.root_device = false;
        builder.build(config, false).unwrap();
        assert_eq!(builder.configs.len(), 1);
        assert!(!builder.has_root_device());
    }

    #[test]
    fn test_pmem_builder_build_seconde_root() {
        let mut builder = PmemBuilder::default();

        let mut config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        builder.build(config.clone(), false).unwrap();

        config.id = "2".into();
        assert!(matches!(
            builder.build(config.clone(), false).unwrap_err(),
            PmemConfigError::RootPmemDeviceAlreadyExist,
        ));
    }

    #[test]
    fn test_pmem_builder_build_root_with_block_already_a_root() {
        let mut builder = PmemBuilder::default();

        let config = PmemConfig {
            id: "1".into(),
            path_on_host: "/dummy".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            builder.build(config, true).unwrap_err(),
            PmemConfigError::AddingSecondRootDevice,
        ));
    }
}
