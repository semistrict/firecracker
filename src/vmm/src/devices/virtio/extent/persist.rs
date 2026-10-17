// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store device in a snapshot of its VM (TASK-39.1). The snapshot is taken with the
//! guest's filesystem frozen, nothing open on the device: the device forks its store then, to the
//! point the snapshot holds of it ([`Extent::take_snapshot`]), and saves the window's mappings. A
//! VM restored from the snapshot opens a store of its own, forked from that point if it doesn't
//! exist (each restore its own, given its path in the snapshot's load), and maps the window as
//! it was, where it was in guest memory; its guest learns its store's branch as its filesystem
//! thaws.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::device::{Extent, ExtentError, ExtentSnapshot, Making};
use super::window::PrefaultGuestMemory;
use super::{EXTENT_NUM_QUEUES, EXTENT_QUEUE_SIZE};
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::snapshot::Persist;
use crate::vmm_config::extent::ExtentDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

/// What a snapshot of its VM holds of an extent-store device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtentState {
    pub virtio_state: VirtioDeviceState,
    /// Its configuration: its store's path is the one a restore opens, unless the snapshot's
    /// load overrides it.
    pub config: ExtentConfigState,
    /// Where the window was in guest memory, if the device has one.
    pub window_addr: Option<u64>,
    /// The point the snapshot holds of the store: a fork of it.
    pub point: PathBuf,
    /// The point's branch, which a restore on another host takes from the extent daemon's bucket.
    pub point_branch: u64,
    /// The window's mappings.
    pub mappings: Vec<MappingState>,
    /// Whether the guest's filesystem was frozen: it is, as a snapshot is taken.
    pub frozen: bool,
}

/// An extent-store device's configuration ([`ExtentDeviceConfig`]), as a snapshot holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtentConfigState {
    pub id: String,
    pub tag: String,
    pub path_on_host: String,
    pub capacity: u64,
    pub dax_window_size: Option<u64>,
    pub extentd_socket: String,
}

impl From<&ExtentDeviceConfig> for ExtentConfigState {
    fn from(config: &ExtentDeviceConfig) -> Self {
        Self {
            id: config.id.clone(),
            tag: config.tag.clone(),
            path_on_host: config.path_on_host.clone(),
            capacity: config.capacity,
            dax_window_size: config.dax_window_size,
            extentd_socket: config.extentd_socket.clone(),
        }
    }
}

impl From<&ExtentConfigState> for ExtentDeviceConfig {
    fn from(config: &ExtentConfigState) -> Self {
        Self {
            id: config.id.clone(),
            tag: config.tag.clone(),
            path_on_host: config.path_on_host.clone(),
            capacity: config.capacity,
            dax_window_size: config.dax_window_size,
            extentd_socket: config.extentd_socket.clone(),
        }
    }
}

/// A mapping of the window ([`fxdax::WindowMapping`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingState {
    pub window_offset: u64,
    pub len: u64,
    pub contents: MappingContentsState,
}

/// What a mapping of the window maps ([`fxdax::MappingContents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MappingContentsState {
    Extent {
        branch: u64,
        sequence: u64,
        offset: u64,
        writable: bool,
    },
    Zeros,
}

impl From<&fxdax::WindowMapping> for MappingState {
    fn from(mapping: &fxdax::WindowMapping) -> Self {
        Self {
            window_offset: mapping.window_offset,
            len: mapping.len,
            contents: match mapping.contents {
                fxdax::MappingContents::Extent {
                    extent,
                    offset,
                    writable,
                } => MappingContentsState::Extent {
                    branch: extent.branch,
                    sequence: extent.sequence,
                    offset,
                    writable,
                },
                fxdax::MappingContents::Zeros => MappingContentsState::Zeros,
            },
        }
    }
}

impl From<&MappingState> for fxdax::WindowMapping {
    fn from(mapping: &MappingState) -> Self {
        Self {
            window_offset: mapping.window_offset,
            len: mapping.len,
            contents: match mapping.contents {
                MappingContentsState::Extent {
                    branch,
                    sequence,
                    offset,
                    writable,
                } => fxdax::MappingContents::Extent {
                    extent: fxdax::ExtentId { branch, sequence },
                    offset,
                    writable,
                },
                MappingContentsState::Zeros => fxdax::MappingContents::Zeros,
            },
        }
    }
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
        let snapshot = self
            .snapshot()
            .expect("an extent device's store is snapshotted before the device is saved");
        ExtentState {
            virtio_state: VirtioDeviceState::from_device(self),
            config: ExtentConfigState::from(&self.config),
            window_addr: self.window_addr(),
            point: snapshot.point.clone(),
            point_branch: snapshot.point_branch,
            mappings: snapshot.mappings.iter().map(MappingState::from).collect(),
            frozen: self.frozen(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            constructor_args.mem,
            VirtioDeviceType::Extent,
            EXTENT_NUM_QUEUES,
            EXTENT_QUEUE_SIZE,
        )?;
        let snapshot = ExtentSnapshot {
            point: state.point.clone(),
            point_branch: state.point_branch,
            mappings: state
                .mappings
                .iter()
                .map(fxdax::WindowMapping::from)
                .collect(),
        };
        let making = Making::Restore {
            snapshot: &snapshot,
            window_addr: state.window_addr,
        };
        let config = ExtentDeviceConfig::from(&state.config);
        let mut extent = Extent::make(constructor_args.vm, config, making)?;
        if let Some(prefault) = constructor_args.prefault {
            extent.set_prefault(prefault);
        }
        extent.restored(
            snapshot,
            queues,
            state.virtio_state.acked_features,
            state.frozen,
        );
        Ok(extent)
    }
}
