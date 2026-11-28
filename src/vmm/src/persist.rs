// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::forget;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use semver::Version;
use serde::{Deserialize, Serialize};
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::get_manufacturer_id_from_host;
use crate::builder::{self, BuildMicrovmFromSnapshotError};
use crate::cpu_config::templates::StaticCpuTemplate;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::CpuidTrait;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
use crate::device_manager::{DevicePersistError, DevicesState};
use crate::devices::virtio::pmem::device::{BackendPmem, PmemError};
// Re-exported so external crates inspecting a `MicrovmState` snapshot can match on the
// serialised virtio transport variant.
pub use crate::device_manager::VirtioDevicesState;
use crate::logger::{info, warn};
use crate::memory_backend::{self, MemoryBackend};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::snapshot::Snapshot;
use crate::utils::u64_to_usize;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{HugePageConfig, MachineConfigError, MachineConfigUpdate};
#[cfg(feature = "cladefs")]
use crate::vmm_config::snapshot::MemoryCellSnapshot;
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, MemBackendType};
use crate::vstate::kvm::KvmState;
#[cfg(feature = "cladefs")]
use crate::vstate::memory::GuestMemoryExtension;
use crate::vstate::memory::{
    self, GuestAddress, GuestMemoryState, GuestRegionMmap, GuestRegionType, MemoryError,
};
use crate::vstate::vcpu::{VcpuSendEventError, VcpuState};
use crate::vstate::vm::{VmError, VmState};
use crate::{EventManager, Vmm, vstate};

/// Holds information related to the VM that is not part of VmState.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
    /// smt information
    pub smt: bool,
    /// CPU template type
    pub cpu_template: StaticCpuTemplate,
    /// Boot source information.
    pub boot_source: BootSourceConfig,
    /// Huge page configuration
    pub huge_pages: HugePageConfig,
}

impl From<&VmResources> for VmInfo {
    fn from(value: &VmResources) -> Self {
        Self {
            mem_size_mib: value.machine_config.mem_size_mib as u64,
            smt: value.machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&value.machine_config.cpu_template),
            boot_source: value.boot_source.config.clone(),
            huge_pages: value.machine_config.huge_pages,
        }
    }
}

impl From<&Vmm> for VmInfo {
    fn from(value: &Vmm) -> Self {
        let machine_config = &value.machine_config;
        Self {
            mem_size_mib: machine_config.mem_size_mib as u64,
            smt: machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&machine_config.cpu_template),
            boot_source: value.boot_source_config.clone(),
            huge_pages: machine_config.huge_pages,
        }
    }
}

/// Contains the necessary state for saving/restoring a microVM.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MicrovmState {
    /// Miscellaneous VM info.
    pub vm_info: VmInfo,
    /// KVM KVM state.
    pub kvm_state: KvmState,
    /// VM KVM state.
    pub vm_state: VmState,
    /// Vcpu states.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states.
    pub device_states: DevicesState,
}

/// This describes the mapping between Firecracker base virtual address and
/// offset in the buffer or file backend for a guest memory region. It is used
/// to tell an external process/thread where to populate the guest memory data
/// for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the
/// backend at `offset` bytes from the beginning, and should be copied/populated
/// into `base_host_address`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestRegionUffdMapping {
    /// Base host virtual address where the guest memory contents for this
    /// region should be copied/populated.
    pub base_host_virt_addr: u64,
    /// Region size.
    pub size: usize,
    /// Offset in the backend file/buffer where the region contents are.
    pub offset: u64,
    /// The configured page size for this memory region.
    pub page_size: usize,
    /// The configured page size **in bytes** for this memory region. The name is
    /// wrong but cannot be changed due to being API, so this field is deprecated,
    /// to be removed in 2.0.
    #[deprecated]
    pub page_size_kib: usize,
    /// For the memory of a pmem device the backend serves (`size_mib`), the device's ID; none for
    /// guest memory. Its `offset` follows guest memory's, as if the backend held each device's
    /// contents after it, in the order given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmem_id: Option<String>,
}

/// Errors related to saving and restoring Microvm state.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MicrovmStateError {
    /// Operation not allowed: {0}
    NotAllowed(String),
    /// Cannot restore devices: {0}
    RestoreDevices(#[from] DevicePersistError),
    /// Cannot save Vcpu state: {0}
    SaveVcpuState(vstate::vcpu::VcpuError),
    /// Cannot save KvmVm state: {0}
    SaveVmState(vstate::vm::KvmVmError),
    /// Cannot signal Vcpu: {0}
    SignalVcpu(VcpuSendEventError),
    /// Vcpu is in unexpected state.
    UnexpectedVcpuResponse,
}

/// Errors associated with creating a snapshot.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CreateSnapshotError {
    /// Cannot get dirty bitmap: {0}
    DirtyBitmap(#[from] VmError),
    /// Cannot write memory file: {0}
    Memory(#[from] MemoryError),
    /// Cannot perform {0} on the memory backing file: {1}
    MemoryBackingFile(&'static str, io::Error),
    /// Cannot save the microVM state: {0}
    MicrovmState(MicrovmStateError),
    /// Cannot serialize the microVM state: {0}
    SerializeMicrovmState(#[from] crate::snapshot::SnapshotError),
    /// Cannot perform {0} on the snapshot backing file: {1}
    SnapshotBackingFile(&'static str, io::Error),
    /// cladefs: cannot write guest memory into a memory cell: {0}
    #[cfg(feature = "cladefs")]
    MemoryCell(#[from] crate::cladefs_memory::CellMemoryError),
    /// A snapshot's guest memory goes to one place: `mem_file_path`, or the `Mappings` memory backend, which persists it itself (or cladefs's `memory_cell`)
    MemoryTarget,
    /// The memory backend failed to persist guest memory: {0}
    MemoryBackend(#[from] crate::memory_backend::MemoryBackendError),
}

/// Snapshot version
pub const SNAPSHOT_VERSION: Version = Version::new(13, 0, 0);

/// What making a snapshot gave besides its files.
#[derive(Debug, Default)]
pub struct SnapshotOutcome {
    /// The `Mappings` memory backend's result, which persisted guest memory itself.
    pub memory_backend: Option<serde_json::Value>,
    /// cladefs: the memory cell's version guest memory was written into, with `memory_cell`
    /// (TASK-456.4).
    #[cfg(feature = "cladefs")]
    pub memory_cell: Option<MemoryCellSnapshot>,
}

/// Creates a Microvm snapshot.
#[cfg(not(feature = "cladefs"))]
pub fn create_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
) -> Result<SnapshotOutcome, CreateSnapshotError> {
    write_snapshot(vmm, vm_info, params)
}

/// Creates a Microvm snapshot.
#[cfg(feature = "cladefs")]
pub fn create_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
) -> Result<SnapshotOutcome, CreateSnapshotError> {
    // cladefs: the extent-store devices' stores first: a version of each one's cell (or migration
    // mappings without a version when `for_migration` is set), which the snapshot failing after
    // drops, as no snapshot file names it then (TASK-575).
    let taken = vmm
        .take_extent_snapshots(params.for_migration)
        .map_err(CreateSnapshotError::MicrovmState)?;
    let written = write_snapshot(vmm, vm_info, params);
    if written.is_err() {
        vmm.drop_extent_snapshots(&taken);
    }
    written
}

/// Writes a Microvm snapshot: its state, then its memory: through the `Mappings` memory backend,
/// which persists it itself, to `mem_file_path`, or (cladefs) straight into a memory cell.
fn write_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
) -> Result<SnapshotOutcome, CreateSnapshotError> {
    let kvm_vm = vmm.vm.as_kvm().ok_or_else(|| {
        CreateSnapshotError::MicrovmState(MicrovmStateError::NotAllowed(
            "snapshot requires KVM".into(),
        ))
    })?;
    let backend = kvm_vm.memory_backend().cloned();
    #[cfg(not(feature = "cladefs"))]
    let memory_cell = false;
    #[cfg(feature = "cladefs")]
    let memory_cell = params.memory_cell.is_some();
    // One place for guest memory: the backend, a file, or a memory cell.
    if usize::from(backend.is_some())
        + usize::from(params.mem_file_path.is_some())
        + usize::from(memory_cell)
        != 1
    {
        return Err(CreateSnapshotError::MemoryTarget);
    }

    let microvm_state = vmm
        .save_state(vm_info)
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        params.sync_snapshot_files,
    )?;

    let kvm_vm = vmm.vm.as_kvm().expect("checked above");
    let mut outcome = SnapshotOutcome::default();
    if let Some(backend) = backend {
        // Device state saved, the vCPUs paused: the handler persists memory as it now is.
        outcome.memory_backend = Some(backend.persist()?);
        kvm_vm.protect_unplugged_slots()?;
    } else if let Some(mem_file_path) = &params.mem_file_path {
        kvm_vm.snapshot_memory_to_file(
            mem_file_path,
            params.snapshot_type,
            params.sync_snapshot_files,
        )?;
    }
    #[cfg(feature = "cladefs")]
    if let Some(ref cell_cfg) = params.memory_cell {
        outcome.memory_cell = Some(crate::cladefs_memory::snapshot_memory(cell_cfg)?);
        if params.snapshot_type == crate::vmm_config::snapshot::SnapshotType::Full {
            kvm_vm.reset_dirty_bitmap();
            kvm_vm.guest_memory().reset_dirty();
        }
    }

    // We need to mark queues as dirty again for all activated devices. The reason we
    // do it here is that we don't mark pages as dirty during runtime
    // for queue objects.
    vmm.device_manager
        .mark_virtio_queue_memory_dirty(kvm_vm.guest_memory());

    Ok(outcome)
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &Path,
    sync_snapshot_files: bool,
) -> Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut snapshot_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(snapshot_path)
        .map_err(|err| SnapshotBackingFile("open", err))?;

    let snapshot = Snapshot::new(microvm_state);
    snapshot.save(&mut snapshot_file)?;
    snapshot_file
        .flush()
        .map_err(|err| SnapshotBackingFile("flush", err))?;
    if sync_snapshot_files {
        snapshot_file
            .sync_all()
            .map_err(|err| SnapshotBackingFile("sync_all", err))?;
    }
    Ok(())
}

/// Validates that snapshot CPU vendor matches the host CPU vendor.
///
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "x86_64")]
pub fn validate_cpu_vendor(microvm_state: &MicrovmState) {
    let host_vendor_id = get_vendor_id_from_host();
    let snapshot_vendor_id = microvm_state.vcpu_states[0].cpuid.vendor_id();
    match (host_vendor_id, snapshot_vendor_id) {
        (Ok(host_id), Some(snapshot_id)) => {
            info!("Host CPU vendor ID: {host_id:?}");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU vendor ID differs from the snapshotted one",);
            }
        }
        (Ok(host_id), None) => {
            info!("Host CPU vendor ID: {host_id:?}");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
        (Err(_), Some(snapshot_id)) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
        }
        (Err(_), None) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
    }
}

/// Validate that Snapshot Manufacturer ID matches
/// the one from the Host
///
/// The manufacturer ID for the Snapshot is taken from each VCPU state.
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "aarch64")]
pub fn validate_cpu_manufacturer_id(microvm_state: &MicrovmState) {
    let host_cpu_id = get_manufacturer_id_from_host();
    let snapshot_cpu_id = microvm_state.vcpu_states[0].regs.manifacturer_id();
    match (host_cpu_id, snapshot_cpu_id) {
        (Some(host_id), Some(snapshot_id)) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU manufacturer ID differs from the snapshotted one",);
            }
        }
        (Some(host_id), None) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
        (None, Some(snapshot_id)) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
        }
        (None, None) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
    }
}
/// Error type for [`snapshot_state_sanity_check`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum SnapShotStateSanityCheckError {
    /// No memory region defined.
    NoMemory,
    /// No DRAM memory region defined.
    NoDramMemory,
    /// DRAM memory has more than a single slot.
    DramMemoryTooManySlots,
    /// DRAM memory is unplugged.
    DramMemoryUnplugged,
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> Result<(), SnapShotStateSanityCheckError> {
    // Check that the snapshot contains at least 1 mem region, that at least one is Dram,
    // and that Dram region contains a single plugged slot.
    // Upper bound check will be done when creating guest memory by comparing against
    // KVM max supported value kvm_context.max_memslots().
    let regions = &microvm_state.vm_state.memory.regions;

    if regions.is_empty() {
        return Err(SnapShotStateSanityCheckError::NoMemory);
    }

    if !regions
        .iter()
        .any(|r| r.region_type == GuestRegionType::Dram)
    {
        return Err(SnapShotStateSanityCheckError::NoDramMemory);
    }

    for dram_region in regions
        .iter()
        .filter(|r| r.region_type == GuestRegionType::Dram)
    {
        if dram_region.plugged.len() != 1 {
            return Err(SnapShotStateSanityCheckError::DramMemoryTooManySlots);
        }

        if !dram_region.plugged[0] {
            return Err(SnapShotStateSanityCheckError::DramMemoryUnplugged);
        }
    }

    #[cfg(target_arch = "x86_64")]
    validate_cpu_vendor(microvm_state);
    #[cfg(target_arch = "aarch64")]
    validate_cpu_manufacturer_id(microvm_state);

    Ok(())
}

/// Error type for [`restore_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreFromSnapshotError {
    /// Failed to get snapshot state from file: {0}
    File(#[from] SnapshotStateFromFileError),
    /// Invalid snapshot state: {0}
    Invalid(#[from] SnapShotStateSanityCheckError),
    /// Failed to load guest memory: {0}
    GuestMemory(#[from] RestoreFromSnapshotGuestMemoryError),
    /// Failed to build microVM from snapshot: {0}
    Build(#[from] BuildMicrovmFromSnapshotError),
}
/// Sub-Error type for [`restore_from_snapshot`] to contain either [`GuestMemoryFromFileError`] or
/// [`GuestMemoryFromUffdError`] within [`RestoreFromSnapshotError`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreFromSnapshotGuestMemoryError {
    /// Error creating guest memory from file: {0}
    File(#[from] GuestMemoryFromFileError),
    /// Error creating guest memory from uffd: {0}
    Uffd(#[from] GuestMemoryFromUffdError),
    /// Error making the memory of a pmem device the memory backend serves: {0}
    BackendPmem(PmemError),
    /// A snapshot with pmem devices the memory backend serves (size_mib) loads with a Uffd or Mappings memory backend alone
    BackendPmemNeedsUffd,
    /// Error serving guest memory through a Mappings memory backend: {0}
    Mappings(#[from] MappingsMemoryError),
    /// cladefs: error restoring guest memory from a memory cell: {0}
    #[cfg(feature = "cladefs")]
    Cell(#[from] crate::cladefs_memory::CellMemoryError),
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn restore_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
    params: &LoadSnapshotParams,
    vm_resources: &mut VmResources,
) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
    let mut microvm_state = snapshot_state_from_file(&params.snapshot_path)?;
    for entry in &params.network_overrides {
        // Only the active transport carries virtio device state, so we look at whichever
        // variant this snapshot was saved with. The MMIO and PCI transports wrap their net
        // devices in distinct types, so we map down to the shared inner `NetState` in each arm.
        let device_state = match &mut microvm_state.device_states.virtio_state {
            VirtioDevicesState::Mmio(mmio_state) => mmio_state
                .net_devices
                .iter_mut()
                .map(|device| &mut device.device_state)
                .find(|x| x.id == entry.iface_id),
            VirtioDevicesState::Pci(pci_state) => pci_state
                .net_devices
                .iter_mut()
                .map(|device| &mut device.device_state)
                .find(|x| x.id == entry.iface_id),
        };
        device_state
            .map(|device_state| device_state.tap_if_name.clone_from(&entry.host_dev_name))
            .ok_or(SnapshotStateFromFileError::UnknownNetworkDevice)?;
    }

    if let Some(vsock_override) = &params.vsock_override {
        // There should only ever be at most one vsock device, therefore this
        // should correctly find it and modify the path if such a device exists.
        let device_state = match &mut microvm_state.device_states.virtio_state {
            VirtioDevicesState::Mmio(mmio_state) => mmio_state
                .vsock_device
                .as_mut()
                .map(|device| &mut device.device_state),
            VirtioDevicesState::Pci(pci_state) => pci_state
                .vsock_device
                .as_mut()
                .map(|device| &mut device.device_state),
        }
        .ok_or(SnapshotStateFromFileError::UnknownVsockDevice)?;

        device_state
            .backend
            .uds_path
            .clone_from(&vsock_override.uds_path);
    }

    // cladefs: the stores the extent-store devices open, each forked from the snapshot's version of
    // its cell if it doesn't exist.
    #[cfg(feature = "cladefs")]
    for entry in &params.cladefs_overrides {
        let extent_devices = match &mut microvm_state.device_states.virtio_state {
            VirtioDevicesState::Pci(pci_state) => Some(&mut pci_state.extent_devices),
            VirtioDevicesState::Mmio(_) => None,
        };
        extent_devices
            .and_then(|devices| {
                devices
                    .iter_mut()
                    .map(|device| &mut device.device_state)
                    .find(|state| state.device.config.id == entry.id)
            })
            .map(|state| {
                if let Some(path) = &entry.path_on_host {
                    state.device.config.path_on_host.clone_from(path);
                }
                if let Some(socket) = &entry.cladefsd_socket {
                    state.device.config.cladefsd_socket.clone_from(socket);
                }
                // cladefs board 14663: never in the snapshot, the restore's own.
                state.device.config.stream.clone_from(&entry.stream);
            })
            .ok_or_else(|| SnapshotStateFromFileError::UnknownCladefsDevice(entry.id.clone()))?;
    }

    let track_dirty_pages = params.track_dirty_pages;

    let vcpu_count = microvm_state
        .vcpu_states
        .len()
        .try_into()
        .map_err(|_| MachineConfigError::InvalidVcpuCount)
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    vm_resources
        .update_machine_config(&MachineConfigUpdate {
            vcpu_count: Some(vcpu_count),
            mem_size_mib: Some(u64_to_usize(microvm_state.vm_info.mem_size_mib)),
            smt: Some(microvm_state.vm_info.smt),
            cpu_template: Some(microvm_state.vm_info.cpu_template),
            track_dirty_pages: Some(track_dirty_pages),
            huge_pages: Some(params.huge_pages.resolve(microvm_state.vm_info.huge_pages)),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        })
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    // Some sanity checks before building the microvm.
    snapshot_state_sanity_check(&microvm_state)?;

    let mem_backend_path = &params.mem_backend.backend_path;
    let mem_state = &microvm_state.vm_state.memory;
    let backend_pmem = backend_pmem(&microvm_state.device_states)
        .map_err(RestoreFromSnapshotGuestMemoryError::BackendPmem)?;
    if !backend_pmem.is_empty()
        && !matches!(
            params.mem_backend.backend_type,
            MemBackendType::Uffd | MemBackendType::Mappings
        )
    {
        return Err(RestoreFromSnapshotGuestMemoryError::BackendPmemNeedsUffd.into());
    }
    let pmem: Vec<_> = (backend_pmem.iter())
        .map(|(id, memory)| (id.as_str(), memory))
        .collect();
    let mut memory_backend = None;

    let (guest_memory, uffd) = match params.mem_backend.backend_type {
        MemBackendType::File => {
            if vm_resources.machine_config.huge_pages.is_hugetlbfs() {
                return Err(RestoreFromSnapshotGuestMemoryError::File(
                    GuestMemoryFromFileError::HugetlbfsSnapshot,
                )
                .into());
            }
            (
                guest_memory_from_file(
                    mem_backend_path,
                    mem_state,
                    track_dirty_pages,
                    vm_resources.machine_config.huge_pages,
                )
                .map_err(RestoreFromSnapshotGuestMemoryError::File)?,
                None,
            )
        }
        MemBackendType::Uffd => {
            let (guest_memory, uffd) = guest_memory_from_uffd(
                mem_backend_path,
                mem_state.regions(),
                &pmem,
                track_dirty_pages,
                vm_resources.machine_config.huge_pages,
            )
            .map_err(RestoreFromSnapshotGuestMemoryError::Uffd)?;
            (guest_memory, Some(uffd))
        }
        MemBackendType::Mappings => {
            let (guest_memory, backend) = guest_memory_from_mappings(
                mem_backend_path,
                mem_state.regions(),
                &pmem,
                track_dirty_pages,
                vm_resources.machine_config.huge_pages,
                seccomp_filters,
            )
            .map_err(RestoreFromSnapshotGuestMemoryError::Mappings)?;
            memory_backend = Some(backend);
            (guest_memory, None)
        }
        // cladefs: a memory cell's window, by the code a fresh boot's is (TASK-456.3, board 14415).
        #[cfg(feature = "cladefs")]
        MemBackendType::Cell => (
            crate::cladefs_memory::guest_memory(
                crate::cladefs_memory::Source::Restore {
                    store: mem_backend_path,
                    config: params
                        .memory_cell
                        .as_ref()
                        .ok_or(crate::cladefs_memory::CellMemoryError::NoMemoryCell)
                        .map_err(RestoreFromSnapshotGuestMemoryError::Cell)?,
                },
                mem_state.regions(),
                track_dirty_pages,
                !matches!(
                    vm_resources.machine_config.huge_pages,
                    crate::vmm_config::machine_config::HugePageConfig::None
                ),
            )
            .map_err(RestoreFromSnapshotGuestMemoryError::Cell)?,
            None,
        ),
    };
    drop(pmem);
    vm_resources.pmem.backend.extend(backend_pmem);
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        uffd,
        memory_backend,
        seccomp_filters,
        vm_resources,
        params.clock_realtime,
    )
    .map_err(RestoreFromSnapshotError::Build)
}

/// The memory of the restored pmem devices the memory backend serves (`size_mib`), by ID, placed
/// where `devices` had them.
fn backend_pmem(devices: &DevicesState) -> Result<Vec<(String, BackendPmem)>, PmemError> {
    let pmem_states: Vec<_> = match &devices.virtio_state {
        VirtioDevicesState::Mmio(state) => (state.pmem_devices.iter())
            .map(|device| &device.device_state)
            .collect(),
        VirtioDevicesState::Pci(state) => (state.pmem_devices.iter())
            .map(|device| &device.device_state)
            .collect(),
    };
    pmem_states
        .into_iter()
        .filter(|state| state.config.backend_served())
        .map(|state| {
            Ok((
                state.config.id.clone(),
                BackendPmem::restore(state.config_space)?,
            ))
        })
        .collect()
}

/// Error type for [`snapshot_state_from_file`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotStateFromFileError {
    /// Failed to open snapshot file: {0}
    Open(#[from] std::io::Error),
    /// Failed to load snapshot state from file: {0}
    Load(#[from] crate::snapshot::SnapshotError),
    /// Unknown Network Device.
    UnknownNetworkDevice,
    /// Unknown Vsock Device.
    UnknownVsockDevice,
    /// cladefs: unknown extent-store device {0}.
    #[cfg(feature = "cladefs")]
    UnknownCladefsDevice(String),
}

fn snapshot_state_from_file(
    snapshot_path: &Path,
) -> Result<MicrovmState, SnapshotStateFromFileError> {
    let mut snapshot_reader = File::open(snapshot_path)?;
    let snapshot = Snapshot::load(&mut snapshot_reader)?;

    Ok(snapshot.data)
}

/// Error type for [`guest_memory_from_file`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GuestMemoryFromFileError {
    /// Failed to load guest memory: {0}
    File(#[from] std::io::Error),
    /// Failed to restore guest memory: {0}
    Restore(#[from] MemoryError),
    /// Cannot restore hugetlbfs backed snapshot by mapping the memory file. Please use uffd.
    HugetlbfsSnapshot,
}

fn guest_memory_from_file(
    mem_file_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, GuestMemoryFromFileError> {
    let mem_file = File::open(mem_file_path)?;
    let guest_mem =
        memory::snapshot_file(mem_file, mem_state.regions(), track_dirty_pages, huge_pages)?;
    Ok(guest_mem)
}

/// Error type for [`guest_memory_from_uffd`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GuestMemoryFromUffdError {
    /// Failed to restore guest memory: {0}
    Restore(#[from] MemoryError),
    /// Failed to UFFD object: {0}
    Create(userfaultfd::Error),
    /// Failed to register memory address range with the userfaultfd object: {0}
    Register(userfaultfd::Error),
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Failed to sends file descriptor: {0}
    Send(#[from] vmm_sys_util::errno::Error),
}

/// Guest memory of `regions`, anonymous, registered with a new userfaultfd for missing pages, and
/// handed with it to the handler listening at `mem_uds_path`, which fills each page as it is
/// first touched: a restored VM's memory, from its snapshot's, and a booted VM's
/// (`PUT /memory-backend`), from nothing. The memory of the pmem devices it serves, `pmem` by ID,
/// is registered and handed over with it, after it.
pub(crate) fn guest_memory_from_uffd(
    mem_uds_path: &Path,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    pmem: &[(&str, &BackendPmem)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<(Vec<GuestRegionMmap>, Uffd), GuestMemoryFromUffdError> {
    let (guest_memory, mut backend_mappings) =
        create_guest_memory(regions, track_dirty_pages, huge_pages)?;
    backend_mappings.extend(describe_pmem(&backend_mappings, pmem));

    let mut uffd_builder = UffdBuilder::new();

    // We only make use of this if balloon devices are present, but we can enable it unconditionally
    // because the only place the kernel checks this is in a hook from madvise, e.g. it doesn't
    // actively change the behavior of UFFD, only passively. Without balloon devices
    // we never call madvise anyway, so no need to put this into a conditional.
    uffd_builder.require_features(FeatureFlags::EVENT_REMOVE);

    let uffd = uffd_builder
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(false)
        .create()
        .map_err(GuestMemoryFromUffdError::Create)?;

    for mem_region in guest_memory.iter() {
        uffd.register(mem_region.as_ptr().cast(), mem_region.size() as _)
            .map_err(GuestMemoryFromUffdError::Register)?;
    }
    for (_, memory) in pmem {
        uffd.register(
            memory.mmap.mmap_ptr as *mut _,
            u64_to_usize(memory.mmap.mmap_len),
        )
        .map_err(GuestMemoryFromUffdError::Register)?;
    }

    send_uffd_handshake(mem_uds_path, &backend_mappings, &uffd)?;

    Ok((guest_memory, uffd))
}

/// Errors of guest memory a `Mappings` memory backend serves.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MappingsMemoryError {
    /// Failed to reserve guest memory: {0}
    Reserve(#[from] MemoryError),
    /// Guest memory of huge pages can't be made of a Mappings memory backend's 4 KiB mappings
    HugePages,
    /// No seccomp filter for the VMM thread, which the memory backend's thread runs under
    NoSeccompFilter,
    /// Guest memory whose host mapping is another's can't be a Mappings memory backend's
    Unowned,
    /// {0}
    Backend(#[from] crate::memory_backend::MemoryBackendError),
}

/// Guest memory of `regions`, reserved anonymous, and the memory of the pmem devices it serves,
/// `pmem` by ID, made of the mappings the `Mappings` handler listening at `mem_uds_path` lists,
/// which serves their faults: a restored VM's memory and a booted VM's.
pub(crate) fn guest_memory_from_mappings(
    mem_uds_path: &Path,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    pmem: &[(&str, &BackendPmem)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
    seccomp_filters: &BpfThreadMap,
) -> Result<(Vec<GuestRegionMmap>, Arc<MemoryBackend>), MappingsMemoryError> {
    let filter = seccomp_filters
        .get("vmm")
        .ok_or(MappingsMemoryError::NoSeccompFilter)?
        .clone();
    if huge_pages != HugePageConfig::None {
        return Err(MappingsMemoryError::HugePages);
    }
    let (guest_memory, mappings) = create_guest_memory(regions, track_dirty_pages, huge_pages)?;
    let pmem_mappings = describe_pmem(&mappings, pmem);
    let mut holds: Vec<Arc<dyn std::fmt::Debug + Send + Sync>> = Vec::new();
    for region in &guest_memory {
        holds.push(Arc::new(
            region.mapping().ok_or(MappingsMemoryError::Unowned)?,
        ));
    }
    holds.extend(
        pmem.iter()
            .map(|(_, memory)| Arc::clone(&memory.mmap) as Arc<dyn std::fmt::Debug + Send + Sync>),
    );
    let described = (mappings.into_iter().chain(pmem_mappings).zip(holds))
        .map(|(mapping, memory)| {
            let region = memory_backend::Region {
                host_addr: mapping.base_host_virt_addr,
                size: mapping.size as u64,
                guest_memory: mapping.pmem_id.is_none(),
                memory,
            };
            (region, mapping)
        })
        .collect();
    let backend = MemoryBackend::start(mem_uds_path, described, filter)?;
    Ok((guest_memory, backend))
}

/// The handshake's descriptions of the memory of the pmem devices a backend serves, `pmem` by ID,
/// after guest memory's, `guest_memory`.
fn describe_pmem(
    guest_memory: &[GuestRegionUffdMapping],
    pmem: &[(&str, &BackendPmem)],
) -> Vec<GuestRegionUffdMapping> {
    let mut offset: u64 = guest_memory.iter().map(|m| m.size as u64).sum();
    (pmem.iter())
        .map(|(id, memory)| {
            #[allow(deprecated)]
            let mapping = GuestRegionUffdMapping {
                base_host_virt_addr: memory.mmap.mmap_ptr,
                size: u64_to_usize(memory.mmap.mmap_len),
                offset,
                page_size: HugePageConfig::None.page_size(),
                page_size_kib: HugePageConfig::None.page_size(),
                pmem_id: Some((*id).to_string()),
            };
            offset += memory.mmap.mmap_len;
            mapping
        })
        .collect()
}

fn create_guest_memory(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<(Vec<GuestRegionMmap>, Vec<GuestRegionUffdMapping>), MemoryError> {
    let guest_memory = memory::anonymous(regions, track_dirty_pages, huge_pages)?;
    let mut backend_mappings = Vec::with_capacity(guest_memory.len());
    let mut offset = 0;
    for mem_region in guest_memory.iter() {
        #[allow(deprecated)]
        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: mem_region.as_ptr() as u64,
            size: mem_region.size(),
            offset,
            page_size: huge_pages.page_size(),
            page_size_kib: huge_pages.page_size(),
            pmem_id: None,
        });
        offset += mem_region.size() as u64;
    }

    Ok((guest_memory, backend_mappings))
}

fn send_uffd_handshake(
    mem_uds_path: &Path,
    backend_mappings: &[GuestRegionUffdMapping],
    uffd: &impl AsRawFd,
) -> Result<(), GuestMemoryFromUffdError> {
    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(backend_mappings).unwrap();

    let socket = UnixStream::connect(mem_uds_path)?;
    socket.send_with_fd(
        backend_mappings.as_bytes(),
        // In the happy case we can close the fd since the other process has it open and is
        // using it to serve us pages.
        //
        // The problem is that if other process crashes/exits, firecracker guest memory
        // will simply revert to anon-mem behavior which would lead to silent errors and
        // undefined behavior.
        //
        // To tackle this scenario, the page fault handler can notify Firecracker of any
        // crashes/exits. There is no need for Firecracker to explicitly send its process ID.
        // The external process can obtain Firecracker's PID by calling `getsockopt` with
        // `libc::SO_PEERCRED` option like so:
        //
        // let mut val = libc::ucred { pid: 0, gid: 0, uid: 0 };
        // let mut ucred_size: u32 = mem::size_of::<libc::ucred>() as u32;
        // libc::getsockopt(
        //      socket.as_raw_fd(),
        //      libc::SOL_SOCKET,
        //      libc::SO_PEERCRED,
        //      &mut val as *mut _ as *mut _,
        //      &mut ucred_size as *mut libc::socklen_t,
        // );
        //
        // Per this linux man page: https://man7.org/linux/man-pages/man7/unix.7.html,
        // `SO_PEERCRED` returns the credentials (PID, UID and GID) of the peer process
        // connected to this socket. The returned credentials are those that were in effect
        // at the time of the `connect` call.
        //
        // Moreover, Firecracker holds a copy of the UFFD fd as well, so that even if the
        // page fault handler process does not tear down Firecracker when necessary, the
        // uffd will still be alive but with no one to serve faults, leading to guest freeze.
        uffd.as_raw_fd(),
    )?;

    // We prevent Rust from closing the socket file descriptor to avoid a potential race condition
    // between the mappings message and the connection shutdown. If the latter arrives at the UFFD
    // handler first, the handler never sees the mappings.
    forget(socket);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::Vmm;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmclock_device;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmgenid_device;
    use crate::builder::tests::{
        CustomBlockConfig, default_kernel_cmdline, default_vmm, insert_balloon_device,
        insert_block_devices, insert_net_device, insert_vsock_device,
    };
    #[cfg(target_arch = "aarch64")]
    use crate::construct_kvm_mpidrs;
    use crate::devices::virtio::block::CacheType;
    use crate::snapshot::Persist;
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vstate::memory::{GuestMemoryRegionState, GuestRegionType};

    fn default_vmm_with_devices() -> Vmm {
        let mut event_manager = EventManager::new().expect("Cannot create EventManager");
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        // Add a balloon device.
        let balloon_config = BalloonDeviceConfig {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
            free_page_hinting: false,
            free_page_reporting: false,
        };
        insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_config);

        // Add a block device.
        let drive_id = String::from("root");
        let block_configs = vec![CustomBlockConfig::new(
            drive_id,
            true,
            None,
            true,
            CacheType::Unsafe,
        )];
        insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

        // Add net device.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            dmb_size_mib: None,
        };
        insert_net_device(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            network_interface,
        );

        // Add vsock device.
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);

        insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);

        #[cfg(target_arch = "x86_64")]
        insert_vmgenid_device(&mut vmm);
        #[cfg(target_arch = "x86_64")]
        insert_vmclock_device(&mut vmm);

        vmm
    }

    #[test]
    fn test_microvm_state_snapshot() {
        let vmm = default_vmm_with_devices();
        let states = vmm.device_manager.save();

        // Only checking that all devices are saved, actual device state
        // is tested by that device's tests.
        let VirtioDevicesState::Mmio(mmio_state) = &states.virtio_state else {
            panic!("expected MMIO virtio device state");
        };
        assert_eq!(mmio_state.block_devices.len(), 1);
        assert_eq!(mmio_state.net_devices.len(), 1);
        assert!(mmio_state.vsock_device.is_some());
        assert!(mmio_state.balloon_device.is_some());

        let vcpu_states = vec![VcpuState::default()];
        #[cfg(target_arch = "aarch64")]
        let mpidrs = construct_kvm_mpidrs(&vcpu_states);
        let microvm_state = MicrovmState {
            device_states: states,
            vcpu_states,
            kvm_state: Default::default(),
            vm_info: VmInfo {
                mem_size_mib: 1u64,
                ..Default::default()
            },
            #[cfg(target_arch = "aarch64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state(&mpidrs).unwrap(),
            #[cfg(target_arch = "x86_64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state().unwrap(),
        };

        let serialized_data = bitcode::serialize(&microvm_state).unwrap();

        let restored_microvm_state: MicrovmState = bitcode::deserialize(&serialized_data).unwrap();

        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);
        let (VirtioDevicesState::Mmio(restored_mmio), VirtioDevicesState::Mmio(mmio)) = (
            &restored_microvm_state.device_states.virtio_state,
            &microvm_state.device_states.virtio_state,
        ) else {
            panic!("expected MMIO virtio device state");
        };
        assert_eq!(restored_mmio, mmio)
    }

    #[test]
    fn test_create_guest_memory() {
        let mem_state = GuestMemoryState {
            regions: vec![GuestMemoryRegionState {
                base_address: 0,
                size: 0x20000,
                region_type: GuestRegionType::Dram,
                plugged: vec![true],
            }],
        };

        let (_, uffd_regions) =
            create_guest_memory(mem_state.regions(), false, HugePageConfig::None).unwrap();

        assert_eq!(uffd_regions.len(), 1);
        assert_eq!(uffd_regions[0].size, 0x20000);
        assert_eq!(uffd_regions[0].offset, 0);
        assert_eq!(uffd_regions[0].page_size, HugePageConfig::None.page_size());
    }

    #[test]
    fn test_send_uffd_handshake() {
        #[allow(deprecated)]
        let uffd_regions = vec![
            GuestRegionUffdMapping {
                base_host_virt_addr: 0,
                size: 0x100000,
                offset: 0,
                page_size: HugePageConfig::None.page_size(),
                page_size_kib: HugePageConfig::None.page_size(),
                pmem_id: None,
            },
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x100000,
                size: 0x200000,
                offset: 0,
                page_size: HugePageConfig::Hugetlbfs2M.page_size(),
                page_size_kib: HugePageConfig::Hugetlbfs2M.page_size(),
                pmem_id: None,
            },
        ];

        let uds_path = TempFile::new().unwrap();
        let uds_path = uds_path.as_path();
        std::fs::remove_file(uds_path).unwrap();

        let listener = UnixListener::bind(uds_path).expect("Cannot bind to socket path");

        send_uffd_handshake(uds_path, &uffd_regions, &std::io::stdin()).unwrap();

        let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

        let mut message_buf = vec![0u8; 1024];
        let (bytes_read, _) = stream
            .recv_with_fd(&mut message_buf[..])
            .expect("Cannot recv_with_fd");
        message_buf.resize(bytes_read, 0);

        let deserialized: Vec<GuestRegionUffdMapping> =
            serde_json::from_slice(&message_buf).unwrap();

        assert_eq!(uffd_regions, deserialized);
    }
}
