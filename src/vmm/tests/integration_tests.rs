// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::tests_outside_test_module)]

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vmm::builder::build_and_boot_microvm;
use vmm::devices::virtio::block::CacheType;
use vmm::memory_backend::{Entry, FromHandler, ToHandler, recv_frame, send_frame};
use vmm::persist::{
    GuestMemoryFromFileError, GuestRegionUffdMapping, MicrovmState, MicrovmStateError,
    RestoreFromSnapshotError, RestoreFromSnapshotGuestMemoryError, VirtioDevicesState, VmInfo,
    snapshot_state_sanity_check,
};
use vmm::resources::VmResources;
use vmm::rpc_interface::{
    LoadSnapshotError, PrebootApiController, RuntimeApiController, VmmAction, VmmActionError,
    VmmData,
};
use vmm::seccomp::get_empty_filters;
use vmm::snapshot::Snapshot;
use vmm::test_utils::mock_resources::{MockVmResources, NOISY_KERNEL_IMAGE};
use vmm::test_utils::{build_vmm, create_vmm, default_vmm, default_vmm_no_boot, mock_resources};
use vmm::vmm_config::balloon::BalloonDeviceConfig;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::machine_config::{HugePageConfig, MachineConfig, MachineConfigUpdate};
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::pmem::PmemConfig;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotParams, MemBackendConfig, MemBackendType,
    SnapshotLoadHugePageConfig, SnapshotType,
};
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::{DumpCpuConfigError, EventManager, FcExitCode, Vmm};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;
use vmm_sys_util::tempfile::TempFile;

#[allow(unused_mut, unused_variables)]
fn check_booted_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);

    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_and_boot_microvm() {
    // Error case: no boot source configured.
    {
        let resources: VmResources = MockVmResources::new().into();
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filters = get_empty_filters();

        let vmm_ret = build_and_boot_microvm(
            &InstanceInfo::default(),
            &resources,
            &mut event_manager,
            &empty_seccomp_filters,
        );
        assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
    }

    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, true, pci_enabled, memory_hotplug);
            check_booted_microvm(vmm, evmgr);
        }
    }
}

#[allow(unused_mut, unused_variables)]
fn check_build_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // The built microVM should be in the `VmState::Paused` state here.
    assert_eq!(vmm.lock().unwrap().instance_info().state, VmState::Paused);

    // The microVM should be able to resume and exit successfully.
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    vmm.lock().unwrap().resume_vm().unwrap();
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, false, pci_enabled, memory_hotplug);
            check_build_microvm(vmm, evmgr);
        }
    }
}

fn pause_resume_microvm(vmm: Arc<Mutex<Vmm>>) {
    let mut api_controller = RuntimeApiController::new(vmm.clone());
    let mut event_manager = EventManager::new().unwrap();

    // There's a race between this thread and the vcpu thread, but this thread
    // should be able to pause vcpu thread before it finishes running its test-binary.
    api_controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();
    // Pausing again the microVM should not fail (microVM remains in the
    // `Paused` state).
    api_controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();
    api_controller
        .handle_request(VmmAction::Resume, &mut event_manager)
        .unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_pause_resume_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            // Tests that pausing and resuming a microVM work as expected.
            let (vmm, _) = create_vmm(None, false, true, pci_enabled, memory_hotplug);

            pause_resume_microvm(vmm);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dirty_bitmap_success() {
    let vmms = [
        vmm::test_utils::dirty_tracking_vmm(Some(NOISY_KERNEL_IMAGE)),
        default_vmm(Some(NOISY_KERNEL_IMAGE)),
    ];

    for (vmm, _) in vmms {
        // Let it churn for a while and dirty some pages...
        thread::sleep(Duration::from_millis(100));
        let bitmap = vmm
            .lock()
            .unwrap()
            .vm
            .as_kvm()
            .unwrap()
            .get_dirty_bitmap()
            .unwrap();
        let num_dirty_pages: u32 = bitmap
            .values()
            .map(|bitmap_per_region| {
                // Gently coerce to u32
                let num_dirty_pages_per_region: u32 =
                    bitmap_per_region.iter().map(|n| n.count_ones()).sum();
                num_dirty_pages_per_region
            })
            .sum();
        assert!(num_dirty_pages > 0);
        vmm.lock().unwrap().stop(FcExitCode::Ok);
    }
}

#[test]
fn test_disallow_snapshots_without_pausing() {
    let (vmm, _) = default_vmm(Some(NOISY_KERNEL_IMAGE));
    let vm_info = VmInfo {
        mem_size_mib: 1u64,
        ..Default::default()
    };

    // Verify saving state while running is not allowed.
    assert!(matches!(
        vmm.lock().unwrap().save_state(&vm_info),
        Err(MicrovmStateError::NotAllowed(_))
    ));

    // Pause microVM.
    vmm.lock().unwrap().pause_vm().unwrap();
    // It is now allowed.
    vmm.lock().unwrap().save_state(&vm_info).unwrap();
    // Stop.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_disallow_dump_cpu_config_without_pausing() {
    let (vmm, _) = default_vmm_no_boot(Some(NOISY_KERNEL_IMAGE));

    // This call should succeed since the microVM is in the paused state before boot.
    vmm.lock().unwrap().dump_cpu_config().unwrap();

    // Boot the microVM.
    vmm.lock().unwrap().resume_vm().unwrap();

    // Verify this call is not allowed while running.
    assert!(matches!(
        vmm.lock().unwrap().dump_cpu_config(),
        Err(DumpCpuConfigError::NotAllowed(_))
    ));

    // Stop the microVM.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

fn verify_create_snapshot(
    is_diff: bool,
    pci_enabled: bool,
    memory_hotplug: bool,
) -> (TempFile, TempFile) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let (vmm, _) = create_vmm(
        Some(NOISY_KERNEL_IMAGE),
        is_diff,
        true,
        pci_enabled,
        memory_hotplug,
    );

    let vm_info = VmInfo::from(&*vmm.lock().unwrap());
    let mut controller = RuntimeApiController::new(vmm.clone());
    let mut event_manager = EventManager::new().unwrap();

    // Be sure that the microVM is running.
    thread::sleep(Duration::from_millis(200));

    // Pause microVM.
    controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();

    // Create snapshot.
    let snapshot_type = match is_diff {
        true => SnapshotType::Diff,
        false => SnapshotType::Full,
    };
    let snapshot_params = CreateSnapshotParams {
        snapshot_type,
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_file_path: Some(memory_file.as_path().to_path_buf()),
        sync_snapshot_files: true,
        #[cfg(feature = "cladefs")]
        memory_cell: None,
        #[cfg(feature = "cladefs")]
        for_migration: false,
    };

    controller
        .handle_request(
            VmmAction::CreateSnapshot(snapshot_params),
            &mut event_manager,
        )
        .unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);

    // Check that we can deserialize the microVM state from `snapshot_file`.
    let restored_microvm_state: MicrovmState =
        Snapshot::load(&mut snapshot_file.as_file()).unwrap().data;

    assert_eq!(restored_microvm_state.vm_info, vm_info);

    // Verify deserialized data.
    // The default vmm has no devices and one vCPU.
    match &restored_microvm_state.device_states.virtio_state {
        VirtioDevicesState::Mmio(state) => {
            assert!(!pci_enabled);
            assert_eq!(state.block_devices.len(), 0);
            assert_eq!(state.net_devices.len(), 0);
            assert!(state.vsock_device.is_none());
        }
        VirtioDevicesState::Pci(state) => {
            assert!(pci_enabled);
            assert_eq!(state.block_devices.len(), 0);
            assert_eq!(state.net_devices.len(), 0);
            assert!(state.vsock_device.is_none());
        }
    }
    assert_eq!(restored_microvm_state.vcpu_states.len(), 1);

    (snapshot_file, memory_file)
}

fn verify_load_snapshot(
    snapshot_file: TempFile,
    memory_file: TempFile,
    huge_pages: SnapshotLoadHugePageConfig,
) {
    let expected_huge_pages = huge_pages.resolve(HugePageConfig::None);
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            #[cfg(feature = "cladefs")]
            cladefs_overrides: vec![],
            #[cfg(feature = "cladefs")]
            memory_cell: None,
            clock_realtime: false,
            huge_pages,
        }))
        .unwrap();

    let vmm = preboot_api_controller.built_vmm.take().unwrap();

    {
        let vmm = vmm.lock().unwrap();
        assert_eq!(vmm.instance_info.state, VmState::Running);
        assert_eq!(vmm.machine_config.huge_pages, expected_huge_pages);
    }
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_create_and_load_snapshot() {
    for diff_snap in [false, true] {
        for pci_enabled in [false, true] {
            for memory_hotplug in [false, true] {
                // Create snapshot.
                let (snapshot_file, memory_file) =
                    verify_create_snapshot(diff_snap, pci_enabled, memory_hotplug);
                // Create a new microVm from snapshot. This only tests code-level logic; it verifies
                // that a microVM can be built with no errors from given snapshot.
                // It does _not_ verify that the guest is actually restored properly. We're using
                // python integration tests for that.
                verify_load_snapshot(
                    snapshot_file,
                    memory_file,
                    SnapshotLoadHugePageConfig::Snapshot,
                );
            }
        }
    }
}

#[test]
fn test_load_snapshot_huge_pages_override() {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);

    verify_load_snapshot(
        snapshot_file,
        memory_file,
        SnapshotLoadHugePageConfig::Transparent,
    );
}

#[test]
fn test_load_snapshot_rejects_hugetlbfs_with_file_backend() {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();
    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    let error = preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            #[cfg(feature = "cladefs")]
            cladefs_overrides: vec![],
            #[cfg(feature = "cladefs")]
            memory_cell: None,
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Hugetlbfs2M,
        }))
        .unwrap_err();

    assert!(matches!(
        error,
        VmmActionError::LoadSnapshot(LoadSnapshotError::RestoreFromSnapshot(
            RestoreFromSnapshotError::GuestMemory(RestoreFromSnapshotGuestMemoryError::File(
                GuestMemoryFromFileError::HugetlbfsSnapshot
            ))
        ))
    ));
}

#[test]
fn test_snapshot_load_sanity_checks() {
    let microvm_state = get_microvm_state_from_snapshot(false);
    check_snapshot(microvm_state);
    let microvm_state = get_microvm_state_from_snapshot(true);
    check_snapshot(microvm_state);
}

fn check_snapshot(mut microvm_state: MicrovmState) {
    use vmm::persist::SnapShotStateSanityCheckError;
    snapshot_state_sanity_check(&microvm_state).unwrap();

    // Remove memory regions.
    microvm_state.vm_state.memory.regions.clear();

    // Validate sanity checks fail because there is no mem region in state.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::NoMemory)
    );
}

fn get_microvm_state_from_snapshot(pci_enabled: bool) -> MicrovmState {
    // Create a diff snapshot
    let (snapshot_file, _) = verify_create_snapshot(true, pci_enabled, false);

    // Deserialize the microVM state.
    snapshot_file.as_file().seek(SeekFrom::Start(0)).unwrap();
    Snapshot::load(&mut snapshot_file.as_file()).unwrap().data
}

fn verify_load_snap_disallowed_after_boot_resources(res: VmmAction, res_name: &str) {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);

    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller.handle_preboot_request(res).unwrap();

    // Load snapshot should no longer be allowed.
    let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_backend: MemBackendConfig {
            backend_path: memory_file.as_path().to_path_buf(),
            backend_type: MemBackendType::File,
        },
        track_dirty_pages: false,
        resume_vm: false,
        network_overrides: vec![],
        vsock_override: None,
        #[cfg(feature = "cladefs")]
        cladefs_overrides: vec![],
        #[cfg(feature = "cladefs")]
        memory_cell: None,
        clock_realtime: false,
        huge_pages: SnapshotLoadHugePageConfig::Snapshot,
    });
    let err = preboot_api_controller.handle_preboot_request(req);
    assert!(
        matches!(
            err.unwrap_err(),
            VmmActionError::LoadSnapshot(LoadSnapshotError::LoadSnapshotNotAllowed)
        ),
        "LoadSnapshot should be disallowed after {}",
        res_name
    );
}

#[test]
fn test_preboot_load_snap_disallowed_after_boot_resources() {
    let tmp_file = TempFile::new().unwrap();
    let tmp_file = tmp_file.as_path().to_str().unwrap().to_string();
    // Verify LoadSnapshot not allowed after configuring various boot-specific resources.
    let req = VmmAction::ConfigureBootSource(BootSourceConfig {
        kernel_image_path: tmp_file.clone(),
        ..Default::default()
    });
    verify_load_snap_disallowed_after_boot_resources(req, "ConfigureBootSource");

    let config = BlockDeviceConfig {
        drive_id: String::new(),
        partuuid: None,
        is_root_device: false,
        cache_type: CacheType::Unsafe,

        is_read_only: Some(false),
        discard: None,
        path_on_host: Some(tmp_file),
        rate_limiter: None,
        file_engine_type: None,
        blk_size: None,
        topology: None,

        socket: None,
        dmb_size_mib: None,
    };

    let req = VmmAction::InsertBlockDevice(config);
    verify_load_snap_disallowed_after_boot_resources(req, "InsertBlockDevice");

    let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
        iface_id: String::new(),
        host_dev_name: String::new(),
        guest_mac: None,
        mtu: None,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
        dmb_size_mib: None,
    });
    verify_load_snap_disallowed_after_boot_resources(req, "InsertNetworkDevice");

    let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
    verify_load_snap_disallowed_after_boot_resources(req, "SetBalloonDevice");

    let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
        vsock_id: Some(String::new()),
        guest_cid: 0,
        uds_path: String::new(),
        dmb_size_mib: None,
    });
    verify_load_snap_disallowed_after_boot_resources(req, "SetVsockDevice");

    let req =
        VmmAction::UpdateMachineConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
    verify_load_snap_disallowed_after_boot_resources(req, "SetVmConfiguration");
}

/// A page fault handler on a thread of its own, as an external one would be: it takes the regions
/// and the userfaultfd Firecracker hands over at its socket, and fills each page as it is first
/// touched, from a snapshot's memory file, or with zeros for a booted VM. It keeps the regions,
/// and counts the pages it filled.
struct UffdHandler {
    regions: Arc<Mutex<Vec<GuestRegionUffdMapping>>>,
    filled: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UffdHandler {
    fn spawn(socket: &Path, memory: Option<File>) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let regions = Arc::new(Mutex::new(Vec::new()));
        let filled = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (regions, filled, stop) = (regions.clone(), filled.clone(), stop.clone());
            thread::spawn(move || Self::serve(&listener, memory.as_ref(), &regions, &filled, &stop))
        };
        Self {
            regions,
            filled,
            stop,
            thread: Some(thread),
        }
    }

    fn serve(
        listener: &UnixListener,
        memory: Option<&File>,
        handed: &Mutex<Vec<GuestRegionUffdMapping>>,
        filled: &AtomicUsize,
        stop: &AtomicBool,
    ) {
        let (stream, _) = listener.accept().unwrap();
        let mut body = vec![0u8; 4096];
        let (len, uffd) = stream.recv_with_fd(&mut body).unwrap();
        let regions: Vec<GuestRegionUffdMapping> = serde_json::from_slice(&body[..len]).unwrap();
        handed.lock().unwrap().clone_from(&regions);
        // SAFETY: Firecracker sent its userfaultfd, which no one else here owns.
        let uffd = unsafe { userfaultfd::Uffd::from_raw_fd(uffd.unwrap().into_raw_fd()) };
        let mut page = vec![0u8; regions[0].page_size];
        while !stop.load(Ordering::Relaxed) {
            let mut poll = libc::pollfd {
                fd: uffd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: Polls the one descriptor it is given.
            if unsafe { libc::poll(&mut poll, 1, 50) } <= 0 {
                continue;
            }
            let Some(userfaultfd::Event::Pagefault { addr, .. }) = uffd.read_event().unwrap()
            else {
                continue;
            };
            let addr = addr as u64 & !(page.len() as u64 - 1);
            let region = regions
                .iter()
                .find(|r| {
                    (r.base_host_virt_addr..r.base_host_virt_addr + r.size as u64).contains(&addr)
                })
                .unwrap();
            // A page two vCPUs faulted on is filled once; the other's fill finds it there.
            let done = match memory {
                Some(memory) => {
                    memory
                        .read_exact_at(&mut page, region.offset + addr - region.base_host_virt_addr)
                        .unwrap();
                    // SAFETY: Fills a page of the guest memory Firecracker registered.
                    unsafe { uffd.copy(page.as_ptr().cast(), addr as *mut _, page.len(), true) }
                }
                // SAFETY: Fills a page of the guest memory Firecracker registered.
                None => unsafe { uffd.zeropage(addr as *mut _, page.len(), true) },
            };
            if done.is_ok() {
                filled.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn filled(&self) -> usize {
        self.filled.load(Ordering::Relaxed)
    }

    /// The regions Firecracker handed over, pmem devices' by ID.
    fn regions(&self) -> Vec<(Option<String>, usize)> {
        (self.regions.lock().unwrap().iter())
            .map(|r| (r.pmem_id.clone(), r.size))
            .collect()
    }
}

impl Drop for UffdHandler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

/// Pauses the VM and makes a full snapshot of it: its state file and memory file.
fn snapshot(vmm: &Arc<Mutex<Vmm>>, event_manager: &mut EventManager) -> (TempFile, TempFile) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();
    let mut controller = RuntimeApiController::new(vmm.clone());
    controller
        .handle_request(VmmAction::Pause, event_manager)
        .unwrap();
    controller
        .handle_request(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Full,
                snapshot_path: snapshot_file.as_path().to_path_buf(),
                mem_file_path: Some(memory_file.as_path().to_path_buf()),
                sync_snapshot_files: true,
                #[cfg(feature = "cladefs")]
                memory_cell: None,
                #[cfg(feature = "cladefs")]
                for_migration: false,
            }),
            event_manager,
        )
        .unwrap();
    (snapshot_file, memory_file)
}

/// Restores `snapshot_file` with a `Uffd` memory backend at `socket`, resumed.
fn restore_with_uffd(snapshot_file: &TempFile, socket: &Path) -> Arc<Mutex<Vmm>> {
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();
    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );
    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: socket.to_path_buf(),
                backend_type: MemBackendType::Uffd,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            #[cfg(feature = "cladefs")]
            cladefs_overrides: vec![],
            #[cfg(feature = "cladefs")]
            memory_cell: None,
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Snapshot,
        }))
        .unwrap();
    let vmm = preboot_api_controller.built_vmm.take().unwrap();
    assert_eq!(vmm.lock().unwrap().instance_info.state, VmState::Running);
    vmm
}

/// Resources of a VM whose memory the `Uffd` backend at `socket` serves.
fn uffd_resources(socket: &Path) -> VmResources {
    let mut resources = mock_resources(Some(NOISY_KERNEL_IMAGE), false, false, false);
    resources
        .set_memory_backend(MemBackendConfig {
            backend_type: MemBackendType::Uffd,
            backend_path: socket.to_path_buf(),
        })
        .unwrap();
    resources
}

/// A VM booted with a `Uffd` memory backend has every page of its memory filled by the handler,
/// the kernel the VMM loads included; its snapshot restores through the same backend.
#[test]
fn test_boot_and_restore_with_uffd_memory_backend() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let boot_socket = dir.as_path().join("boot.sock");
    let handler = UffdHandler::spawn(&boot_socket, None);
    let (vmm, mut event_manager) = build_vmm(&uffd_resources(&boot_socket), true);
    // Loading the kernel filled pages before a vCPU ran.
    assert!(handler.filled() > 0);
    thread::sleep(Duration::from_millis(200));
    let (snapshot_file, memory_file) = snapshot(&vmm, &mut event_manager);
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    drop(handler);

    let restore_socket = dir.as_path().join("restore.sock");
    let handler = UffdHandler::spawn(
        &restore_socket,
        Some(File::open(memory_file.as_path()).unwrap()),
    );
    let vmm = restore_with_uffd(&snapshot_file, &restore_socket);
    thread::sleep(Duration::from_millis(200));
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    // The restored vCPUs' accesses were filled from the snapshot's memory.
    assert!(handler.filled() > 0);
}

/// A pmem device of `size_mib` has its memory handed to the memory backend with guest memory's, at
/// boot and at restore, where its snapshot placed it.
#[test]
fn test_uffd_memory_backend_serves_pmem() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let boot_socket = dir.as_path().join("boot.sock");
    let handler = UffdHandler::spawn(&boot_socket, None);
    let mut resources = uffd_resources(&boot_socket);
    resources
        .build_pmem_device(PmemConfig {
            id: "window".into(),
            size_mib: Some(4),
            ..Default::default()
        })
        .unwrap();
    let (vmm, mut event_manager) = build_vmm(&resources, true);
    let regions = handler.regions();
    assert_eq!(regions.last(), Some(&(Some("window".to_string()), 4 << 20)));
    assert_eq!(
        regions.iter().filter(|(id, _)| id.is_some()).count(),
        1,
        "{regions:?}"
    );
    let (snapshot_file, memory_file) = snapshot(&vmm, &mut event_manager);
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    drop(handler);

    let restore_socket = dir.as_path().join("restore.sock");
    let handler = UffdHandler::spawn(
        &restore_socket,
        Some(File::open(memory_file.as_path()).unwrap()),
    );
    let vmm = restore_with_uffd(&snapshot_file, &restore_socket);
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    assert_eq!(handler.regions(), regions);
}

/// A booted VM's memory backend is `Uffd` alone: there is no snapshot memory file to load.
#[test]
fn test_boot_memory_backend_must_be_uffd() {
    let mut resources = mock_resources(Some(NOISY_KERNEL_IMAGE), false, false, false);
    assert_eq!(
        resources.set_memory_backend(MemBackendConfig {
            backend_type: MemBackendType::File,
            backend_path: "/memory".into(),
        }),
        Err(vmm::vmm_config::snapshot::MemoryBackendConfigError::NotUffd(MemBackendType::File))
    );
    assert_eq!(resources.memory_backend, None);
}

/// The pages of guest memory a `MappingsHandler` lists lazy at start: the end of the first region,
/// which the test kernel leaves be.
const LAZY_PAGES: u64 = 16;

/// A `Mappings` handler on threads of its own, as an external one would be: it maps every region
/// as a private mapping of a memfd of its own, laid out as the handshake's offsets say, and
/// installs each page as it is first touched (`UFFDIO_CONTINUE`), writing zeros where the memfd
/// has none (a missing fault). It persists by copying guest memory into a second memfd, remapping
/// guest memory's regions onto it, and answering with how many bytes it kept.
struct MappingsHandler {
    /// Its state, which the test and its thread share.
    shared: Arc<Mutex<MappingsShared>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Default)]
struct MappingsShared {
    /// The regions Firecracker handed over.
    regions: Vec<GuestRegionUffdMapping>,
    /// The memfd guest memory is a private mapping of.
    memfd: Option<File>,
    /// The pages it installed.
    installed: usize,
    /// The maps Firecracker answered, by ID: whether applied.
    answers: Vec<(u64, bool)>,
    /// The socket to Firecracker, for maps the test asks for.
    stream: Option<std::os::unix::net::UnixStream>,
    /// Whether it serves a fresh boot, given no memory.
    booting: bool,
}

fn new_memfd(len: u64) -> File {
    // SAFETY: Makes a memfd, whose descriptor it owns at once.
    let fd = unsafe { libc::memfd_create(c"mappings-handler".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    // SAFETY: The descriptor is this one's alone.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_len(len).unwrap();
    file
}

impl MappingsHandler {
    /// Listens at `socket`; restored, its guest memory is `memory`'s.
    fn spawn(socket: &Path, memory: Option<File>) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let shared = Arc::new(Mutex::new(MappingsShared {
            booting: memory.is_none(),
            memfd: memory,
            ..Default::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (shared, stop) = (shared.clone(), stop.clone());
            thread::spawn(move || Self::serve(&listener, &shared, &stop))
        };
        Self {
            shared,
            stop,
            thread: Some(thread),
        }
    }

    /// The regions' entries mapping all of `memfd` as the handshake lays it out, guest memory's
    /// alone if `guest_only`; with `lazy_tail`, the first region's last [`LAZY_PAGES`] pages lazy
    /// instead.
    fn maps(
        regions: &[GuestRegionUffdMapping],
        guest_only: bool,
        lazy_tail: bool,
    ) -> Vec<FromHandler> {
        (regions.iter().enumerate())
            .filter(|(_, r)| !guest_only || r.pmem_id.is_none())
            .map(|(i, r)| {
                let lazy = if i == 0 && lazy_tail {
                    LAZY_PAGES * r.page_size as u64
                } else {
                    0
                };
                let size = r.size as u64 - lazy;
                let mut entries = vec![Entry::File {
                    fd: 0,
                    file_offset: r.offset,
                    offset: 0,
                    len: size,
                }];
                if lazy > 0 {
                    entries.push(Entry::Lazy {
                        offset: size,
                        len: lazy,
                    });
                }
                FromHandler::Map {
                    id: i as u64,
                    region: i,
                    entries,
                }
            })
            .collect()
    }

    fn serve(listener: &UnixListener, shared: &Mutex<MappingsShared>, stop: &AtomicBool) {
        let (stream, _) = listener.accept().unwrap();
        let (handshake, mut fds) = recv_frame::<ToHandler>(&stream).unwrap();
        let ToHandler::Handshake { regions } = handshake else {
            panic!("{handshake:?}")
        };
        // SAFETY: Firecracker sent its userfaultfd, which no one else here owns.
        let uffd = unsafe { userfaultfd::Uffd::from_raw_fd(fds.remove(0).into_raw_fd()) };
        let total: u64 = regions.iter().map(|r| r.size as u64).sum();
        // What guest memory is a private mapping of: the memfd the handler was given, restored.
        let mut memfd = {
            let mut shared = shared.lock().unwrap();
            shared.regions.clone_from(&regions);
            shared.stream = Some(stream.try_clone().unwrap());
            shared
                .memfd
                .get_or_insert_with(|| new_memfd(total))
                .try_clone()
                .unwrap()
        };
        // A fresh boot's handler lists the end of guest memory lazy; a restore's, all of it.
        let booting = shared.lock().unwrap().booting;
        for map in Self::maps(&regions, false, booting) {
            send_frame(&stream, &map, &[memfd.as_raw_fd()]).unwrap();
            assert!(matches!(
                recv_frame::<ToHandler>(&stream).unwrap().0,
                ToHandler::Mapped { .. }
            ));
        }
        send_frame(&stream, &FromHandler::Ready, &[]).unwrap();

        let mut copier: Option<thread::JoinHandle<File>> = None;
        while !stop.load(Ordering::Relaxed) {
            let mut polls = [
                libc::pollfd {
                    fd: uffd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: Polls the descriptors it is given.
            unsafe { libc::poll(polls.as_mut_ptr(), 2, 10) };
            if polls[0].revents & libc::POLLIN != 0 {
                Self::serve_fault(&uffd, &regions, &memfd, shared);
            }
            if polls[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let Ok((message, _)) = recv_frame::<ToHandler>(&stream) else {
                    break;
                };
                match message {
                    // Read guest memory on a thread of its own, this one serving its faults.
                    ToHandler::Persist => {
                        let regions = regions.clone();
                        copier = Some(thread::spawn(move || {
                            let kept = new_memfd(total);
                            for r in regions.iter().filter(|r| r.pmem_id.is_none()) {
                                // SAFETY: Guest memory Firecracker handed over, which it keeps
                                // still while it waits for the persist.
                                let bytes = unsafe {
                                    std::slice::from_raw_parts(
                                        r.base_host_virt_addr as *const u8,
                                        r.size,
                                    )
                                };
                                kept.write_all_at(bytes, r.offset).unwrap();
                            }
                            kept
                        }));
                    }
                    ToHandler::Mapped { id } => shared.lock().unwrap().answers.push((id, true)),
                    ToHandler::MapRefused { id, .. } => {
                        shared.lock().unwrap().answers.push((id, false))
                    }
                    ToHandler::Handshake { .. } => panic!("a second handshake"),
                }
            }
            if copier.as_ref().is_some_and(|c| c.is_finished()) {
                let kept = copier.take().unwrap().join().unwrap();
                for map in Self::maps(&regions, true, false) {
                    send_frame(&stream, &map, &[kept.as_raw_fd()]).unwrap();
                }
                memfd = kept.try_clone().unwrap();
                shared.lock().unwrap().memfd = Some(kept);
                let result = serde_json::json!({"kept": total});
                send_frame(&stream, &FromHandler::Persisted { result }, &[]).unwrap();
            }
        }
    }

    /// Installs the page of the fault `uffd` reports, from `memfd`, as `regions` lay it out:
    /// writing zeros there first where it has none (a missing fault).
    fn serve_fault(
        uffd: &userfaultfd::Uffd,
        regions: &[GuestRegionUffdMapping],
        memfd: &File,
        shared: &Mutex<MappingsShared>,
    ) {
        let Some(userfaultfd::Event::Pagefault { kind, addr, .. }) = uffd.read_event().unwrap()
        else {
            return;
        };
        let page = regions[0].page_size;
        let addr = addr as u64 & !(page as u64 - 1);
        let r = (regions.iter())
            .find(|r| {
                (r.base_host_virt_addr..r.base_host_virt_addr + r.size as u64).contains(&addr)
            })
            .unwrap();
        if kind == userfaultfd::FaultKind::Missing {
            let offset = r.offset + addr - r.base_host_virt_addr;
            memfd.write_all_at(&vec![0u8; page], offset).unwrap();
        }
        // A page two vCPUs faulted on is installed once.
        if uffd.r#continue(addr as *mut _, page, true).is_ok() {
            shared.lock().unwrap().installed += 1;
        }
    }

    fn installed(&self) -> usize {
        self.shared.lock().unwrap().installed
    }

    /// Asks Firecracker to map region `region` as zeros, as map `id`: all of it, or its last
    /// `pages` pages.
    fn map_zeros(&self, id: u64, region: usize, pages: Option<u64>) {
        let shared = self.shared.lock().unwrap();
        let r = &shared.regions[region];
        let len = pages.map_or(r.size as u64, |pages| pages * r.page_size as u64);
        let map = FromHandler::Map {
            id,
            region,
            entries: vec![Entry::Zeros {
                offset: r.size as u64 - len,
                len,
            }],
        };
        send_frame(shared.stream.as_ref().unwrap(), &map, &[]).unwrap();
    }

    /// Firecracker's answer to map `id`, once it came: whether applied.
    fn answer(&self, id: u64) -> bool {
        loop {
            if let Some((_, applied)) =
                (self.shared.lock().unwrap().answers.iter()).find(|(answered, _)| *answered == id)
            {
                return *applied;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn memory(&self) -> File {
        let shared = self.shared.lock().unwrap();
        shared.memfd.as_ref().unwrap().try_clone().unwrap()
    }
}

impl Drop for MappingsHandler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

/// A VM booted with a `Mappings` memory backend runs on the handler's mappings, every page of
/// them installed by it, the kernel the VMM loads included; its snapshot is the handler's, no
/// memory file, and restores through the same backend. The handler maps a pmem device's region
/// while the VM runs, and is refused guest memory's then.
#[test]
fn test_boot_snapshot_and_restore_with_mappings_memory_backend() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let boot_socket = dir.as_path().join("boot.sock");
    let handler = MappingsHandler::spawn(&boot_socket, None);
    let mut resources = mock_resources(Some(NOISY_KERNEL_IMAGE), false, false, false);
    resources
        .set_memory_backend(MemBackendConfig {
            backend_type: MemBackendType::Mappings,
            backend_path: boot_socket,
        })
        .unwrap();
    resources
        .build_pmem_device(PmemConfig {
            id: "window".into(),
            size_mib: Some(4),
            ..Default::default()
        })
        .unwrap();
    let (vmm, mut event_manager) = build_vmm(&resources, true);
    // Loading the kernel installed pages before a vCPU ran.
    assert!(handler.installed() > 0);
    thread::sleep(Duration::from_millis(200));

    // While the VM runs: the pmem device's region may be mapped; guest memory's may be over its
    // lazy entries alone, once.
    let regions = handler.shared.lock().unwrap().regions.len();
    handler.map_zeros(100, regions - 1, None);
    assert!(handler.answer(100));
    handler.map_zeros(101, 0, None);
    assert!(!handler.answer(101));
    handler.map_zeros(102, 0, Some(LAZY_PAGES));
    assert!(handler.answer(102));
    handler.map_zeros(103, 0, Some(LAZY_PAGES));
    assert!(!handler.answer(103));

    let snapshot_file = TempFile::new().unwrap();
    let mut controller = RuntimeApiController::new(vmm.clone());
    controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();
    let persisted = controller
        .handle_request(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Full,
                snapshot_path: snapshot_file.as_path().to_path_buf(),
                mem_file_path: None,
                sync_snapshot_files: true,
                #[cfg(feature = "cladefs")]
                memory_cell: None,
                #[cfg(feature = "cladefs")]
                for_migration: false,
            }),
            &mut event_manager,
        )
        .unwrap();
    let total: usize = (handler.shared.lock().unwrap().regions.iter())
        .map(|r| r.size)
        .sum();
    assert_eq!(
        persisted,
        VmmData::MemoryBackendPersisted(serde_json::json!({"kept": total}))
    );
    // Remapped onto what it kept, the VM runs on.
    controller
        .handle_request(VmmAction::Resume, &mut event_manager)
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    // The VM goes before its handler, which serves its vCPUs' faults until they are gone: the
    // handler going first would end the process (MemoryBackendLost).
    drop((controller, event_manager, vmm));
    let memory = handler.memory();
    drop(handler);

    let restore_socket = dir.as_path().join("restore.sock");
    let handler = MappingsHandler::spawn(&restore_socket, Some(memory));
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();
    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );
    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: restore_socket,
                backend_type: MemBackendType::Mappings,
            },
            track_dirty_pages: false,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            #[cfg(feature = "cladefs")]
            cladefs_overrides: vec![],
            #[cfg(feature = "cladefs")]
            memory_cell: None,
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Snapshot,
        }))
        .unwrap();
    let vmm = preboot_api_controller.built_vmm.take().unwrap();
    // Restored, guest memory is what the first handler kept, read through the mappings the second
    // listed (each page installed by it as this thread touches it).
    let (regions, memory) = {
        let shared = handler.shared.lock().unwrap();
        (
            shared.regions.clone(),
            shared.memfd.as_ref().unwrap().try_clone().unwrap(),
        )
    };
    for r in regions.iter().filter(|r| r.pmem_id.is_none()) {
        let mut kept = vec![0u8; r.size];
        memory.read_exact_at(&mut kept, r.offset).unwrap();
        // SAFETY: Guest memory Firecracker handed over, which the paused VM leaves be.
        let restored =
            unsafe { std::slice::from_raw_parts(r.base_host_virt_addr as *const u8, r.size) };
        // But for system memory, where loading writes devices' state anew (the VM generation ID,
        // the VMClock page): the first region's start, from DRAM's.
        let differing: Vec<u64> = (restored.chunks(r.page_size).zip(kept.chunks(r.page_size)))
            .enumerate()
            .filter(|(_, (restored, kept))| restored != kept)
            .map(|(page, _)| r.offset + (page * r.page_size) as u64)
            .collect();
        #[cfg(target_arch = "x86_64")]
        let dram_start = 0;
        #[cfg(target_arch = "aarch64")]
        let dram_start = vmm::arch::DRAM_MEM_START;
        let system_start = vmm::arch::SYSTEM_MEM_START - dram_start;
        let system = system_start..system_start + vmm::arch::SYSTEM_MEM_SIZE;
        assert!(
            differing.iter().all(|at| system.contains(at)),
            "pages differing past system memory {system:x?}: {differing:x?}"
        );
    }
    assert!(kept_kernel(&memory));
    let mut controller = RuntimeApiController::new(vmm.clone());
    controller
        .handle_request(VmmAction::Resume, &mut event_manager)
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    // The restored vCPUs' accesses were installed from what the first handler kept.
    assert!(handler.installed() > 0);
}

/// Whether `memory`, guest memory a handler kept, holds anything but zeros: the kernel the VMM
/// loaded at boot.
fn kept_kernel(memory: &File) -> bool {
    let mut page = vec![0u8; 1 << 20];
    (0..memory.metadata().unwrap().len())
        .step_by(page.len())
        .any(|at| {
            let read = memory.read_at(&mut page, at).unwrap();
            page[..read].iter().any(|byte| *byte != 0)
        })
}
