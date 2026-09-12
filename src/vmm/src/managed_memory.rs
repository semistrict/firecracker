//! Ownership of memory controlled by the host's volume pager.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sproutfs_vm_memory::{Control, Region, RegionKind, RegionSpec, Session};
use vm_memory::GuestAddress;

use crate::resources::ManagedMemoryConfig;
use crate::seccomp::{BpfProgram, BpfThreadMap};
use crate::vstate::memory::{GuestRegionMmap, MemoryError};

static WORKER_POLICY: OnceLock<Arc<BpfProgram>> = OnceLock::new();

/// Selects the explicit memory-worker policy before any attachment is created.
/// Missing filters fail closed, including when a custom policy is supplied.
pub fn configure_worker_policy(filters: &BpfThreadMap) -> io::Result<()> {
    let policy = filters
        .get("memory")
        .ok_or_else(|| io::Error::other("missing memory-worker seccomp filter"))?;
    let selected = WORKER_POLICY.get_or_init(|| policy.clone());
    if selected.as_slice() != policy.as_slice() {
        return Err(io::Error::other("memory-worker seccomp policy changed"));
    }
    Ok(())
}

/// Retains the Session, including after its service thread returns.
///
/// The last owner can drop only after memory users have stopped. Guest RAM
/// owns this through its mapping wrappers; PMEM owns it after its KVM slot.
pub struct Owner {
    worker_policy: Arc<BpfProgram>,
    socket_path: std::path::PathBuf,
    control: Control,
    regions: Vec<Region>,
    stopping: Arc<AtomicBool>,
    service: Mutex<Option<JoinHandle<Session>>>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedMemoryOwner")
            .field("regions", &self.regions)
            .finish_non_exhaustive()
    }
}

impl Owner {
    /// Connects before exposing any mapping and starts a dedicated service.
    pub fn connect(path: &std::path::Path, specs: &[RegionSpec]) -> io::Result<Arc<Self>> {
        let worker_policy = WORKER_POLICY
            .get()
            .ok_or_else(|| io::Error::other("memory-worker policy not configured"))?
            .clone();
        let service_policy = worker_policy.clone();
        let mut session = Session::connect(path, specs)?;
        let regions = session.regions();
        let control = session.control();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let service = thread::Builder::new()
            .name("sproutfs-memory".into())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&service_policy) {
                    eprintln!("Cannot install memory-worker policy: {err}");
                    #[allow(clippy::exit)]
                    std::process::exit(1);
                }
                let result = session.run();
                if !worker_stopping.load(Ordering::Acquire) {
                    eprintln!("Managed memory service ended unexpectedly: {result:?}");
                    // Closing UFFD while KVM keeps running can expose zero-filled
                    // anonymous trap pages. Process termination stops every user.
                    #[allow(clippy::exit)]
                    std::process::exit(1);
                }
                session
            })?;
        Ok(Arc::new(Self {
            worker_policy,
            socket_path: path.to_owned(),
            control,
            regions,
            stopping,
            service: Mutex::new(Some(service)),
        }))
    }

    /// Stable addresses retained by this owner.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Socket identity used to construct this attachment.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Installs the same bounded syscall policy on a device durability worker.
    pub fn apply_worker_policy(&self) -> io::Result<()> {
        crate::seccomp::apply_filter(&self.worker_policy).map_err(io::Error::other)
    }

    /// Waits for ingestion of a region's stores and its volume quorum.
    pub fn flush(&self, region: u64) -> io::Result<()> {
        self.control.flush(region, Duration::from_secs(30))
    }
}

/// Flush independently owned volume regions concurrently after guest CPUs and
/// device mutations have stopped for a coordinated capture.
pub fn seal_regions(regions: Vec<(Arc<Owner>, u64)>) -> io::Result<()> {
    let requests: Vec<_> = regions
        .iter()
        .map(|(owner, region)| owner.control.start_seal(*region))
        .collect::<io::Result<_>>()?;
    let mut result = Ok(());
    for request in requests {
        if let Err(err) = request.wait(Duration::from_secs(30)) {
            result = Err(err);
        }
    }
    result
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.control.disconnect();
        if let Some(service) = self.service.get_mut().unwrap().take() {
            // The returned Session retains the mappings until this join ends.
            drop(service.join().expect("managed memory service panicked"));
        }
    }
}

/// Allocates architecture RAM regions through the pager, without copying a
/// whole backing image or creating anonymous guest data pages.
pub fn ram(
    config: &ManagedMemoryConfig,
    layout: &[(GuestAddress, usize)],
    track_dirty: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let specs: Vec<_> = layout
        .iter()
        .map(|(_, len)| RegionSpec {
            kind: RegionKind::Ram,
            len: *len,
        })
        .collect();
    let owner = Owner::connect(&config.socket_path, &specs).map_err(MemoryError::Managed)?;
    layout
        .iter()
        .zip(owner.regions())
        .map(|((address, _), region)| {
            GuestRegionMmap::managed(*address, *region, owner.clone(), track_dirty)
        })
        .collect()
}
