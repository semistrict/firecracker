// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store devices' configurations, which `PUT /extent/{id}` and a VM's configuration
//! file's `extent` give: fxdax's `virtio_extent::Config`, which says what each field means.

/// What the device does with the guest's asks for durability, as a block device's `cache_type`
/// does with its flushes (TASK-363).
pub use virtio_extent::CacheType;
/// An extent-store device: the store of extents that a guest running fxdax's Fxfs itself keeps
/// its filesystem in (fxdax's backlog doc-4), which fxdax's extent daemon serves.
pub use virtio_extent::Config as ExtentDeviceConfig;
/// Errors associated with the operations allowed on an extent-store device.
pub use virtio_extent::ConfigError as ExtentConfigError;
/// The DAX window's sizes, and guest addresses, are multiples of this: huge pages'.
pub use virtio_extent::protocol::DAX_WINDOW_ALIGNMENT;

/// The extent-store devices' configs.
#[derive(Debug, Default)]
pub struct ExtentBuilder {
    /// The configs, in the order the devices are attached.
    pub configs: Vec<ExtentDeviceConfig>,
}

impl ExtentBuilder {
    /// Adds `config`, or replaces the config with its ID, if it describes a device
    /// (`ExtentDeviceConfig::validate`).
    pub fn insert(&mut self, config: ExtentDeviceConfig) -> Result<(), ExtentConfigError> {
        config.validate()?;
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
            dax_private_max: None,
            extentd_socket: "/extentd.sock".into(),
            read_only: false,
            cache_type: CacheType::Writeback,
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

    /// A config that describes no device is refused, and replaces none.
    #[test]
    fn test_insert_invalid() {
        let mut builder = ExtentBuilder::default();
        builder.insert(config("a")).unwrap();
        let mut long = config("a");
        long.tag = "x".repeat(37);
        assert_eq!(
            builder.insert(long.clone()),
            Err(ExtentConfigError::InvalidTag(long.tag))
        );
        assert_eq!(builder.configs, vec![config("a")]);
    }

    /// The API's names of a device's cache, as its block devices' (TASK-363).
    #[test]
    fn test_deserialize() {
        let json = r#"{
            "id": "extents",
            "tag": "fxfs",
            "path_on_host": "/store",
            "capacity": 1073741824,
            "dax_window_size": 67108864,
            "extentd_socket": "/extentd.sock",
            "cache_type": "Unsafe"
        }"#;
        let parsed: ExtentDeviceConfig = serde_json::from_str(json).unwrap();
        let mut expected = config("extents");
        expected.cache_type = CacheType::Unsafe;
        assert_eq!(parsed, expected);
    }
}
