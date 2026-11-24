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

/// What a snapshot of its VM holds of an extent-store device. `device` serializes as a
/// version-prefixed byte payload (`virtio_extent::persist::FORMAT`, doc-28, board 10058), so a
/// restore checks its version before decoding its fields.
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
            "The snapshot's extent device is of protocol version 3, this VMM's 2: its guest's \
             driver is of another"
        );
    }

    /// A future build's `ExtentState` carrying a newer device-state version and a completely
    /// different payload schema, serialized as `(version, FutureSchema)`.
    #[derive(Serialize)]
    struct FutureExtentState {
        protocol: u32,
        virtio_state: VirtioDeviceState,
        device: (u32, FutureDeviceV3),
    }

    #[derive(Serialize)]
    struct FutureDeviceV3 {
        extra_flag: bool,
        label: String,
        numbers: Vec<u128>,
    }

    /// Doc-28 (board 10058): `ExtentState` round-trips through `Snapshot::save` / `Snapshot::load`
    /// (including 262,144 distinct 4 KiB extent mappings well under Firecracker's 10 MB snapshot
    /// deserialization limit, hotbed review 90 finding 324), and a snapshot carrying a future
    /// device state version with an incompatible schema is refused by `FORMAT.check` before
    /// decoding `StateV2`'s fields.
    #[test]
    fn snapshots_version_device_state_before_decoding() {
        use crate::snapshot::Snapshot;

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
                dax_window_size: Some(1 << 30),
                dax_private_max_bytes: Some(1 << 20),
                cladefsd_socket: "/cladefsd.sock".into(),
                cache_type: CacheType::Unsafe,
            },
            window_addr: Some(1 << 40),
            target: cladefs::CellSnapshot::Version(cladefs::CellVersion {
                tenant: 2,
                cell: 77,
                version: 5,
            }),
            mappings: (0..262_144u64)
                .map(|i| MappingState {
                    window_offset: i * 4096,
                    len: 4096,
                    contents: if i % 2 == 0 {
                        MappingContentsState::Extent {
                            cell: 3,
                            sequence: i,
                            offset: 0,
                        }
                    } else {
                        MappingContentsState::Zeros
                    },
                })
                .collect(),
            frozen: true,
        };
        let now = ExtentState {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state: virtio_state.clone(),
            device: device.clone(),
        };
        let mut buf = Vec::new();
        Snapshot::new(now.clone()).save(&mut buf).unwrap();
        let loaded = Snapshot::<ExtentState>::load(&mut buf.as_slice()).unwrap();
        assert_eq!(loaded.data.device, now.device);

        // LocalEphemeral target also round-trips cleanly through Firecracker's bitcode snapshot.
        let ephemeral = ExtentState {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state: virtio_state.clone(),
            device: State {
                target: cladefs::CellSnapshot::LocalEphemeral {
                    tenant: 2,
                    cell: 88,
                    committed: 9,
                },
                mappings: Vec::new(),
                ..device
            },
        };
        let mut eph_buf = Vec::new();
        Snapshot::new(ephemeral.clone()).save(&mut eph_buf).unwrap();
        let loaded_eph = Snapshot::<ExtentState>::load(&mut eph_buf.as_slice()).unwrap();
        assert_eq!(loaded_eph.data.device, ephemeral.device);

        // Future device state version with a completely different schema: refused by FORMAT.check
        // before bitcode decodes StateV3.
        let future_version = virtio_extent::persist::FORMAT.current + 1;
        let future = FutureExtentState {
            protocol: VIRTIO_EXTENT_VERSION,
            virtio_state,
            device: (
                future_version,
                FutureDeviceV3 {
                    extra_flag: true,
                    label: "future schema".into(),
                    numbers: vec![1, 2, 3],
                },
            ),
        };
        let raw_encoded = bitcode::serialize(&future).unwrap();
        let err = bitcode::deserialize::<ExtentState>(&raw_encoded).unwrap_err();
        let expected = format!(
            "snapshot extent state version {future_version}: this build reads versions {} to {}",
            virtio_extent::persist::FORMAT.oldest,
            virtio_extent::persist::FORMAT.current
        );
        assert!(
            err.to_string().contains(&expected),
            "{expected:?} not in {err}"
        );
    }
}
