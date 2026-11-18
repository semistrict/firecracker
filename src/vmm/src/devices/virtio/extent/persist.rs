// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store device in a snapshot of its VM (TASK-39.1): its protocol version, its virtio
//! state, and what cladefs's `virtio_extent` saves of it (`virtio_extent::persist`, which says how
//! the snapshot is taken and restored). A restore by a VMM of another protocol version is refused.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use virtio_extent::protocol::{VIRTIO_EXTENT_VERSION, check_version};

use super::device::{Extent, ExtentError, Making};
use super::{EXTENT_QUEUE_SIZE, PrefaultGuestMemory};
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::snapshot::Persist;
use crate::vmm_config::cladefs::CladefsDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

/// What a snapshot of its VM holds of an extent-store device. Its fields serialize as the
/// device's did before the crate held them, `device`'s fields after `virtio_state`'s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtentState {
    /// cladefs: the device's protocol version, which its guest's driver checked at probe, and a
    /// restore by a VMM of another refuses (TASK-141.3): the guest's driver goes on as it was.
    pub protocol: u32,
    pub virtio_state: VirtioDeviceState,
    /// Its configuration, store, version and window, as the crate saves them.
    pub device: virtio_extent::persist::State,
}

/// What restoring an extent-store device needs.
#[derive(Debug)]
pub struct ExtentConstructorArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: Arc<KvmVm>,
    /// Maps the window's pages for the guest ahead of its accesses, if given.
    pub prefault: Option<Arc<dyn PrefaultGuestMemory>>,
}

/// Errors restoring an extent-store device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ExtentPersistError {
    /// Error restoring the virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Error making the extent-store device: {0}
    Extent(#[from] ExtentError),
}

impl<'a> Persist<'a> for Extent {
    type State = ExtentState;
    type ConstructorArgs = ExtentConstructorArgs<'a>;
    type Error = ExtentPersistError;

    /// The device's state, once [`Extent::take_snapshot`] took the snapshot of its store, as
    /// [`Vmm::save_state`](crate::Vmm::save_state) has it do first.
    fn save(&self) -> Self::State {
        ExtentState {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state: VirtioDeviceState::from_device(self),
            device: self.device().state(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        check_version(state.protocol).map_err(ExtentError::from)?;
        // cladefs: built as a device's not activated are, then those the driver set up initialized:
        // it may have set up fewer than the device has, one per CPU of the guest's.
        let unactivated = VirtioDeviceState {
            activated: false,
            ..state.virtio_state.clone()
        };
        // cladefs: as many queues as it had, its VM's vCPUs' (TASK-276), which `Extent::make`
        // bounds.
        let count = state.virtio_state.queues.len();
        let mut queues = unactivated.build_queues_checked(
            constructor_args.mem,
            VirtioDeviceType::Extent,
            count,
            EXTENT_QUEUE_SIZE,
        )?;
        if state.virtio_state.activated {
            for queue in queues.iter_mut().filter(|queue| queue.ready) {
                queue
                    .initialize(constructor_args.mem)
                    .map_err(VirtioStateError::QueueConstruction)?;
            }
        }
        let config = CladefsDeviceConfig::from(&state.device.config);
        let making = Making::Restore(&state.device);
        let mut extent = Extent::make(constructor_args.vm, config, count, making)?;
        if let Some(prefault) = constructor_args.prefault {
            extent.set_prefault(prefault);
        }
        extent.restored(queues, state.virtio_state.acked_features);
        Ok(extent)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use virtio_extent::CacheType;
    use virtio_extent::persist::{ConfigState, MappingContentsState, MappingState, State};

    use super::*;

    /// cladefs TASK-141.3: a snapshot's device of another protocol version is refused, naming both.
    #[test]
    fn snapshots_of_other_protocols_are_refused() {
        let refused = check_version(VIRTIO_EXTENT_VERSION + 1)
            .map_err(ExtentError::from)
            .unwrap_err()
            .to_string();
        assert_eq!(
            refused,
            "The snapshot's extent device is of protocol version 2, this VMM's 1: its guest's \
             driver is of another"
        );
    }

    /// The device's state as Firecracker's snapshots held it before cladefs's crate held its
    /// fields: one struct, the crate's fields after the virtio state's.
    #[derive(Serialize)]
    struct Before {
        protocol: u32,
        virtio_state: VirtioDeviceState,
        config: ConfigState,
        window_addr: Option<u64>,
        version: cladefs::CellVersion,
        mappings: Vec<MappingState>,
        frozen: bool,
    }

    /// A snapshot's extent device serializes as it did before cladefs's crate held its state: a
    /// snapshot taken before restores after, and the other way round, as no protocol changed.
    #[test]
    fn snapshots_serialize_as_before() {
        let virtio_state = VirtioDeviceState {
            device_type: VirtioDeviceType::Extent,
            avail_features: 0x1_2000_0951,
            acked_features: 0x1_2000_0951,
            queues: Vec::new(),
            activated: true,
        };
        let device = State {
            config: ConfigState {
                id: "extents".into(),
                tag: "fxfs".into(),
                path_on_host: "/store".into(),
                capacity: 1 << 30,
                dax_window_size: Some(64 << 20),
                dax_private_max: None,
                cladefsd_socket: "/cladefsd.sock".into(),
                cache_type: CacheType::Unsafe,
            },
            window_addr: Some(1 << 40),
            version: cladefs::CellVersion { tenant: 2, cell: 77, version: 5 },
            mappings: vec![
                MappingState {
                    window_offset: 4096,
                    len: 8192,
                    contents: MappingContentsState::Extent {
                        branch: 3,
                        sequence: 9,
                        offset: 0,
                    },
                },
                MappingState {
                    window_offset: 1 << 21,
                    len: 4096,
                    contents: MappingContentsState::Zeros,
                },
            ],
            frozen: true,
        };
        let before = Before {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state: virtio_state.clone(),
            config: device.config.clone(),
            window_addr: device.window_addr,
            version: device.version,
            mappings: device.mappings.clone(),
            frozen: device.frozen,
        };
        let now = ExtentState {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state,
            device,
        };
        let before = bitcode::serialize(&before).unwrap();
        assert_eq!(bitcode::serialize(&now).unwrap(), before);
        let read: ExtentState = bitcode::deserialize(&before).unwrap();
        assert_eq!(read.device, now.device);
    }
}
