// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configurations used in the snapshotting context.

use std::path::PathBuf;

/// For crates that depend on `vmm` we export.
pub use semver::Version;
use serde::{Deserialize, Serialize};

use super::machine_config::HugePageConfig;

/// The snapshot type options that are available when
/// creating a new snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum SnapshotType {
    /// Diff snapshot.
    Diff,
    /// Full snapshot.
    #[default]
    Full,
}

/// Specifies the method through which guest memory will get populated when
/// resuming from a snapshot:
/// 1) A file that contains the guest memory to be loaded,
/// 2) An UDS where a custom page-fault handler process is listening for the UFFD set up by
///    Firecracker to handle its guest memory page faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum MemBackendType {
    /// Guest memory contents will be loaded from a file.
    File,
    /// Guest memory will be served through UFFD by a separate process.
    Uffd,
    /// Guest memory is made of the mappings a separate process lists, which it serves through
    /// UFFD, and persists itself when a snapshot is made (`memory_backend`).
    Mappings,
    /// cladefs: guest memory is a memory cell of the snapshot's cell, its store the backend's
    /// path, served by the extent daemon (TASK-456.3): its pages shared with every VM restored
    /// from the same snapshot on the host, a page the guest stores to a private copy of its own.
    /// `memory_cell` says where the snapshot's memory is and which daemon serves it.
    #[cfg(feature = "cladefs")]
    Cell,
}

/// cladefs: writes a VM's guest memory straight into its memory cell during `/snapshot/create`
/// (TASK-456.4), instead of writing a local memory file: a freshly booted VM's (board 14415) as a
/// restored VM's (`MemBackendType::Cell`), whose memory is the cell's window. Firecracker writes
/// only the window's private pages into it, commits, reclaims them back to the newly committed
/// extents, and makes a version; or, of an ephemeral memory cell, checkpoints it in place. A VM
/// restored from a `File` or `Uffd` backend has no memory cell, and snapshots to `mem_file_path`.
#[cfg(feature = "cladefs")]
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMemoryCellConfig {
    /// Whether the VM's memory cell is a host-local ephemeral one, as a check: `true` on a
    /// bucket-backed memory cell is refused. The memory cell's kind is the boot's (`memory-cell`)
    /// or the restore's choice.
    #[serde(default)]
    pub ephemeral: bool,
}

/// cladefs: the memory cell created or checkpointed by `/snapshot/create` with `memory_cell`
/// (TASK-456.4), returned as the HTTP 200 JSON body so callers can pass it to `/snapshot/load`.
#[cfg(feature = "cladefs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCellSnapshot {
    /// The memory cell's tenant.
    pub tenant: u64,
    /// The memory cell, by its ID.
    pub cell: u64,
    /// The version of the memory cell created by this snapshot (0 for host-local ephemeral
    /// memory cells).
    pub version: u64,
    /// True when the memory cell is a host-local ephemeral cell (zero bucket uploads).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

/// Stores the configuration that will be used for creating a snapshot.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshotParams {
    /// This marks the type of snapshot we want to create.
    /// The default value is `Full`, which means a full snapshot.
    #[serde(default = "SnapshotType::default")]
    pub snapshot_type: SnapshotType,
    /// Path to the file that will contain the microVM state.
    pub snapshot_path: PathBuf,
    /// Path to the file that will contain the guest memory: required, unless a `Mappings` memory
    /// backend persists guest memory itself. Mutually exclusive with cladefs's `memory_cell`.
    #[serde(default)]
    pub mem_file_path: Option<PathBuf>,
    /// Whether to fsync the snapshot state and guest memory files.
    /// Activated virtio-block devices are always fsync'd, independently of this.
    #[serde(default = "default_sync_snapshot_files")]
    pub sync_snapshot_files: bool,
    /// cladefs: write guest memory straight into a memory cell instead of `mem_file_path`
    /// (TASK-456.4). Mutually exclusive with `mem_file_path`.
    #[cfg(feature = "cladefs")]
    #[serde(default)]
    pub memory_cell: Option<CreateMemoryCellConfig>,
    /// cladefs: snapshot for live migration — records extent-store device state without requiring
    /// a guest filesystem freeze and without making a cell version. Restoring opens the
    /// handed-over cell directly instead of forking from a version.
    #[cfg(feature = "cladefs")]
    #[serde(default)]
    pub for_migration: bool,
}

/// Default value for [CreateSnapshotParams::sync_snapshot_files].
fn default_sync_snapshot_files() -> bool {
    true
}

/// Allows for changing the mapping between tap devices and host devices
/// during snapshot restore
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct NetworkOverride {
    /// The index of the interface to modify
    pub iface_id: String,
    /// The new name of the interface to be assigned
    pub host_dev_name: String,
}

/// cladefs: has an extent-store device restored from a snapshot open the store at `path_on_host`,
/// forked from the snapshot's version of its cell if it doesn't exist, rather than the store the
/// snapshotted VM had: a store of its own for each VM restored from one snapshot (TASK-39.1), on
/// any host, served by the extent daemon at `cladefsd_socket`.
#[cfg(feature = "cladefs")]
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CladefsOverride {
    /// The ID of the extent-store device to modify.
    pub id: String,
    /// The store's directory.
    pub path_on_host: String,
    /// The extent daemon's socket, if not the snapshotted VM's.
    #[serde(default)]
    pub cladefsd_socket: Option<String>,
}

/// cladefs: the memory cell a VM restored with `Cell` memory takes its memory from: either a
/// bucket-backed cell forked from `(tenant, cell, version)` if it doesn't exist, or (when
/// `ephemeral` is true) an existing host-local ephemeral memory cell reopened in place (`version`
/// must be 0; `tenant`/`cell` optional to verify identity).
#[cfg(feature = "cladefs")]
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCellConfig {
    /// The snapshot's memory cell's tenant (optional when `ephemeral` is true and `cell` is 0).
    #[serde(default)]
    pub tenant: u64,
    /// The memory cell, by its ID (optional when `ephemeral` is true).
    #[serde(default)]
    pub cell: u64,
    /// The version of the memory cell the snapshot holds (must be 0 when `ephemeral` is true).
    #[serde(default)]
    pub version: u64,
    /// The extent daemon's socket.
    pub cladefsd_socket: PathBuf,
    /// When true, reopen an existing host-local ephemeral memory cell in place without bucket I/O.
    #[serde(default)]
    pub ephemeral: bool,
    /// Additional sparse memory diff files (as produced by `snapshot_type: "Diff"`) to layer on
    /// top of the forked memory cell in order (oldest to newest) before mapping guest memory.
    /// Pages written in later files override earlier ones and the base version; holes keep the
    /// base memory cell's pages shared.
    #[serde(default)]
    pub diff_files: Vec<PathBuf>,
}

/// Allows for changing the host UDS of the vsock backend during snapshot restore
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct VsockOverride {
    /// The path to the UDS that will be used for the vsock interface
    pub uds_path: String,
}

/// Selects the huge-page configuration to use when loading a snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
pub enum SnapshotLoadHugePageConfig {
    /// Reuse the huge-page configuration serialized in the snapshot.
    #[default]
    Snapshot,
    /// Use the host's default memory-mapping behavior.
    None,
    /// Advise the kernel to use transparent huge pages for guest memory.
    Transparent,
    /// Back guest memory by 2 MiB hugetlbfs pages.
    #[serde(rename = "2M")]
    Hugetlbfs2M,
}

impl SnapshotLoadHugePageConfig {
    /// Resolves the configuration against the value serialized in the snapshot.
    pub fn resolve(self, snapshot: HugePageConfig) -> HugePageConfig {
        match self {
            Self::Snapshot => snapshot,
            Self::None => HugePageConfig::None,
            Self::Transparent => HugePageConfig::Transparent,
            Self::Hugetlbfs2M => HugePageConfig::Hugetlbfs2M,
        }
    }
}

/// Stores the configuration that will be used for loading a snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct LoadSnapshotParams {
    /// Path to the file that contains the microVM state to be loaded.
    pub snapshot_path: PathBuf,
    /// Specifies guest memory backend configuration.
    pub mem_backend: MemBackendConfig,
    /// Whether KVM dirty page tracking should be enabled, to space optimization
    /// of differential snapshots.
    pub track_dirty_pages: bool,
    /// When set to true, the vm is also resumed if the snapshot load
    /// is successful.
    pub resume_vm: bool,
    /// The network devices to override on load.
    pub network_overrides: Vec<NetworkOverride>,
    /// When set, the vsock backend UDS path will be overridden
    pub vsock_override: Option<VsockOverride>,
    /// cladefs: the extent-store devices whose stores to override on load.
    #[cfg(feature = "cladefs")]
    pub cladefs_overrides: Vec<CladefsOverride>,
    /// cladefs: with a `Cell` memory backend, the memory cell it takes its memory from.
    #[cfg(feature = "cladefs")]
    pub memory_cell: Option<MemoryCellConfig>,
    /// [x86_64 only] When set to true, passes `KVM_CLOCK_REALTIME` to `KVM_SET_CLOCK` on restore,
    /// advancing kvmclock by the wall-clock time elapsed since the snapshot was taken. When false
    /// (default), kvmclock resumes from where it was at snapshot time.
    pub clock_realtime: bool,
    /// Selects the huge-page configuration to use for the restored microVM.
    pub huge_pages: SnapshotLoadHugePageConfig,
}

/// Stores the configuration for loading a snapshot that is provided by the user.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadSnapshotConfig {
    /// Path to the file that contains the microVM state to be loaded.
    pub snapshot_path: PathBuf,
    /// Path to the file that contains the guest memory to be loaded. To be used only if
    /// `mem_backend` is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_file_path: Option<PathBuf>,
    /// Guest memory backend configuration. Is not to be used in conjunction with `mem_file_path`.
    /// None value is allowed only if `mem_file_path` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_backend: Option<MemBackendConfig>,
    /// Whether or not to enable KVM dirty page tracking.
    #[serde(default)]
    #[deprecated]
    pub enable_diff_snapshots: bool,
    /// Whether KVM dirty page tracking should be enabled.
    #[serde(default)]
    pub track_dirty_pages: bool,
    /// Whether or not to resume the vm post snapshot load.
    #[serde(default)]
    pub resume_vm: bool,
    /// The network devices to override on load.
    #[serde(default)]
    pub network_overrides: Vec<NetworkOverride>,
    /// Whether or not to override the vsock backend UDS path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock_override: Option<VsockOverride>,
    /// cladefs: the extent-store devices whose stores to override on load.
    #[cfg(feature = "cladefs")]
    #[serde(default)]
    pub cladefs_overrides: Vec<CladefsOverride>,
    /// cladefs: with a `Cell` memory backend, the memory cell it takes its memory from.
    #[cfg(feature = "cladefs")]
    #[serde(default)]
    pub memory_cell: Option<MemoryCellConfig>,
    /// [x86_64 only] When set to true, passes `KVM_CLOCK_REALTIME` to `KVM_SET_CLOCK` on restore.
    #[serde(default)]
    pub clock_realtime: bool,
    /// Selects the huge-page configuration to use for the restored microVM.
    #[serde(default)]
    pub huge_pages: SnapshotLoadHugePageConfig,
}

/// Stores the configuration used for managing guest memory: a snapshot's, and a booted VM's
/// (`PUT /memory-backend`, `Uffd` alone).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemBackendConfig {
    /// Path to the backend used to handle the guest memory.
    pub backend_path: PathBuf,
    /// Specifies the guest memory backend type.
    pub backend_type: MemBackendType,
}

/// Errors of a booted VM's memory backend.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum MemoryBackendConfigError {
    /// A booted VM's memory backend must be `Uffd` or `Mappings`: `{0:?}` names a snapshot's memory alone
    NotUffd(MemBackendType),
}

impl MemBackendConfig {
    /// Checks the backend may serve a booted VM's memory: `Uffd` or `Mappings`, as there is no
    /// snapshot memory to load.
    pub fn validate_for_boot(&self) -> Result<(), MemoryBackendConfigError> {
        match self.backend_type {
            MemBackendType::Uffd | MemBackendType::Mappings => Ok(()),
            other => Err(MemoryBackendConfigError::NotUffd(other)),
        }
    }
}

/// The microVM state options.
#[derive(Debug, Deserialize, Serialize)]
pub enum VmState {
    /// The microVM is paused, which means that we can create a snapshot of it.
    Paused,
    /// The microVM is resumed; this state should be set after we load a snapshot.
    Resumed,
}

/// Keeps the microVM state necessary in the snapshotting context.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vm {
    /// The microVM state, which can be `paused` or `resumed`.
    pub state: VmState,
}
