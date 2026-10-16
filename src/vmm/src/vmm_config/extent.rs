// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// The DAX window's sizes, and guest addresses, are multiples of this: huge pages'.
pub const DAX_WINDOW_ALIGNMENT: u64 = 2 << 20;

/// The most bytes a tag holds: the device's configuration space's.
const MAX_TAG_LEN: usize = 36;

/// Errors associated with the operations allowed on an extent-store device.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum ExtentConfigError {
    /// The tag {0:?} is empty or longer than 36 bytes
    InvalidTag(String),
    /// The DAX window's size, {0:#x} bytes, is not a nonzero multiple of 2 MiB
    InvalidDaxWindowSize(u64),
}

/// An extent-store device: the store of extents that a guest running fxdax's Fxfs itself keeps
/// its filesystem in (fxdax's backlog doc-4), which fxdax's extent daemon serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentDeviceConfig {
    /// Unique identifier of the device.
    pub id: String,
    /// The filesystem's name, which the guest mounts it by.
    pub tag: String,
    /// The extent store's directory, created if it doesn't exist.
    pub path_on_host: String,
    /// The most bytes a store created holds.
    pub capacity: u64,
    /// The size in bytes of the DAX window, the device's shared memory region the guest maps
    /// files' data from: none without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dax_window_size: Option<u64>,
    /// The socket of fxdax's extent daemon, which serves the store.
    pub extentd_socket: String,
}

/// The extent-store devices' configs.
#[derive(Debug, Default)]
pub struct ExtentBuilder {
    /// The configs, in the order the devices are attached.
    pub configs: Vec<ExtentDeviceConfig>,
}

impl ExtentBuilder {
    /// Adds `config`, or replaces the config with its ID.
    pub fn insert(&mut self, config: ExtentDeviceConfig) -> Result<(), ExtentConfigError> {
        if config.tag.is_empty() || config.tag.len() > MAX_TAG_LEN {
            return Err(ExtentConfigError::InvalidTag(config.tag));
        }
        if let Some(size) = config.dax_window_size
            && (size == 0 || !size.is_multiple_of(DAX_WINDOW_ALIGNMENT))
        {
            return Err(ExtentConfigError::InvalidDaxWindowSize(size));
        }
        match self.configs.iter_mut().find(|c| c.id == config.id) {
            Some(existing) => *existing = config,
            None => self.configs.push(config),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(id: &str) -> ExtentDeviceConfig {
        ExtentDeviceConfig {
            id: id.into(),
            tag: "fxfs".into(),
            path_on_host: "/store".into(),
            capacity: 1 << 30,
            dax_window_size: Some(64 << 20),
            extentd_socket: "/extentd.sock".into(),
        }
    }

    #[test]
    fn test_insert() {
        let mut builder = ExtentBuilder::default();
        builder.insert(config("a")).unwrap();
        builder.insert(config("b")).unwrap();
        let mut replaced = config("a");
        replaced.capacity = 1 << 20;
        builder.insert(replaced.clone()).unwrap();
        assert_eq!(builder.configs, vec![replaced, config("b")]);
    }

    #[test]
    fn test_insert_invalid() {
        let mut builder = ExtentBuilder::default();
        let mut long = config("a");
        long.tag = "x".repeat(37);
        assert_eq!(
            builder.insert(long.clone()),
            Err(ExtentConfigError::InvalidTag(long.tag))
        );
        let mut unaligned = config("a");
        unaligned.dax_window_size = Some(3 << 20 >> 1);
        assert_eq!(
            builder.insert(unaligned),
            Err(ExtentConfigError::InvalidDaxWindowSize(3 << 20 >> 1))
        );
        let mut none = config("a");
        none.dax_window_size = None;
        builder.insert(none).unwrap();
        assert_eq!(builder.configs.len(), 1);
    }

    #[test]
    fn test_deserialize() {
        let json = r#"{
            "id": "extents",
            "tag": "fxfs",
            "path_on_host": "/store",
            "capacity": 1073741824,
            "dax_window_size": 67108864,
            "extentd_socket": "/extentd.sock"
        }"#;
        let parsed: ExtentDeviceConfig = serde_json::from_str(json).unwrap();
        let mut expected = config("extents");
        expected.capacity = 1 << 30;
        assert_eq!(parsed, expected);
    }
}
