// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store device: its configuration, features and DAX window, and the worker that
//! serves its requests once the driver activates it.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use event_manager::{EventOps, Events, MutEventSubscriber};
use fxdax::{ExtentStore, RemoteExtentStore};
use vmm_sys_util::eventfd::EventFd;

use super::window::{DaxWindow, DaxWindowError, PrefaultGuestMemory, WindowPrefault};
use super::worker::Worker;
use super::{
    ConfigSpace, DAX_WINDOW_SHM_ID, EXTENT_NUM_QUEUES, EXTENT_QUEUE_SIZE, MAX_EXTENT, MAX_ROOT,
    MAX_TRANSFER, Resizing, VIRTIO_EXTENT_F_DAX, VIRTIO_EXTENT_F_DAX_WRITE, VIRTIO_EXTENT_F_FREEZE,
    VIRTIO_EXTENT_F_RESIZE, VIRTIO_EXTENT_F_WRITE_COMMIT,
};
use super::{
    Following, VIRTIO_EXTENT_F_FREE_MANY, VIRTIO_EXTENT_F_MAP_AHEAD, VIRTIO_EXTENT_F_MAP_MANY, VIRTIO_EXTENT_F_READ_ONLY,
};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{
    ActiveState, DeviceState, VirtioDevice, VirtioDeviceType, VirtioShmRegion,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::impl_device_type;
use crate::logger::{error, warn};
use crate::vmm_config::extent::ExtentDeviceConfig;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};
use crate::vstate::vm::KvmVm;

/// Errors making an extent-store device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ExtentError {
    /// Cannot open the extent store {0}: {1}
    Store(String, fxdax::Error),
    /// The read-only extent device {0} is restored from no snapshot: it takes none
    ReadOnlyRestored(String),
    /// The tag {0:?} is longer than 36 bytes
    TagTooLong(String),
    /// Cannot make the DAX window: {0}
    DaxWindow(#[from] DaxWindowError),
    /// Error with EventFd: {0}
    EventFd(std::io::Error),
}

/// Errors taking a snapshot of an extent-store device (TASK-39.1).
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ExtentSnapshotError {
    /// Extent device {0}: its guest's filesystem is not frozen (fsfreeze it before the snapshot, and thaw it after)
    NotFrozen(String),
    /// Extent device {0}: it follows a store read-only, which a snapshot doesn't hold
    ReadOnly(String),
    /// Extent device {0}: cannot fork its store to {1}: {2}
    Fork(String, String, fxdax::Errno),
    /// Extent device {0}: cannot list its DAX window's mappings: {1}
    Mappings(String, fxdax::Errno),
    /// Extent device {0}: cannot name the snapshot's branch: {1}
    Branch(String, std::io::Error),
}

/// What a snapshot of the device holds of its store (TASK-39.1): the point it was taken at, a fork
/// of the store, which each VM restored from it forks again, and the window's mappings then, which
/// the restored VM's window maps again.
#[derive(Debug, Clone)]
pub struct ExtentSnapshot {
    pub point: PathBuf,
    /// The point's branch: a restore on another host takes it from the extent daemon's bucket.
    pub point_branch: u64,
    pub mappings: Vec<fxdax::WindowMapping>,
}

/// How a device is made: as its VM boots, or restored from a snapshot ([`ExtentSnapshot`]), its
/// window where the snapshot had it in guest memory.
pub(super) enum Making<'a> {
    Boot,
    Restore {
        snapshot: &'a ExtentSnapshot,
        window_addr: Option<u64>,
    },
}

/// A virtio extent-store device, on an extent store that fxdax's extent daemon serves.
pub struct Extent {
    pub config: ExtentDeviceConfig,
    // The store before the window, whose host memory the store's fault thread serves: the store
    // is dropped first.
    store: Arc<RemoteExtentStore>,
    window: Option<DaxWindow>,
    /// The window's shared memory region, if the device has a window.
    shm_regions: Vec<VirtioShmRegion>,
    /// Whether the store's window is created, which it is on the first activation.
    window_created: bool,
    /// Maps the window's pages for the guest as the store maps them.
    prefault: Option<Arc<dyn PrefaultGuestMemory>>,
    config_space: ConfigSpace,
    /// The store's capacity, as the daemon changes it.
    resizing: Arc<Resizing>,
    /// fxdax: a follower's writer's commits, as the daemon tells of them.
    following: Arc<Following>,
    /// fxdax: whether a follower's device was reset since its store was opened: it opens it
    /// anew as the driver activates it again, its guest remounting on a new view (doc-4).
    reopen: bool,

    // VirtIO fields
    avail_features: u64,
    acked_features: u64,

    // Transport fields
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// The workers serving the queues the driver set up, by index, while the device is activated,
    /// and not paused for a snapshot (`pause_worker`).
    workers: Vec<(usize, Worker)>,
    /// fxdax: whether the guest's filesystem is frozen (`VIRTIO_EXTENT_T_FREEZE`), as a snapshot
    /// needs it.
    frozen: Arc<AtomicBool>,
    /// fxdax: the snapshot taken of the device's store, or restored from (TASK-39.1).
    snapshot: Option<ExtentSnapshot>,
    /// fxdax: the window's mappings to map again as the window is created: those of the snapshot
    /// the device was restored from.
    mappings: Vec<fxdax::WindowMapping>,
}

impl fmt::Debug for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extent")
            .field("config", &self.config)
            .field("shm_regions", &self.shm_regions)
            .field("device_state", &self.device_state)
            .finish_non_exhaustive()
    }
}

impl Extent {
    /// A device as `config` describes, in `vm`, which opens its store, creating it if it doesn't
    /// exist, in the extent daemon, and maps its DAX window, if it has one, into the guest.
    pub fn new(vm: Arc<KvmVm>, config: ExtentDeviceConfig) -> Result<Self, ExtentError> {
        Self::make(vm, config, Making::Boot)
    }

    /// A device as `config` describes, made as `making` says: its store opened, or, restored from
    /// a snapshot, forked from the snapshot's point if it doesn't exist; its window in guest memory
    /// where the snapshot had it.
    pub(super) fn make(
        vm: Arc<KvmVm>,
        config: ExtentDeviceConfig,
        making: Making<'_>,
    ) -> Result<Self, ExtentError> {
        let mut config_space = ConfigSpace {
            tag: [0; 36],
            num_request_queues: u32::try_from(EXTENT_NUM_QUEUES)
                .expect("the queues are few")
                .to_le(),
            block_size: ExtentStore::BLOCK_SIZE.to_le(),
            map_alignment: u32::try_from(fxdax::pages::page_size())
                .expect("a page is small")
                .to_le(),
            max_transfer: MAX_TRANSFER.to_le(),
            max_segments: (u32::from(EXTENT_QUEUE_SIZE) - 2).to_le(),
            max_root: MAX_ROOT.to_le(),
            branch: 0,
            max_extent: MAX_EXTENT.to_le(),
            capacity: 0,
            asked: 0,
            committed: 0,
        };
        let tag = config.tag.as_bytes();
        if tag.len() > config_space.tag.len() {
            return Err(ExtentError::TagTooLong(config.tag.clone()));
        }
        config_space.tag[..tag.len()].copy_from_slice(tag);

        let store = match &making {
            Making::Boot if config.read_only => {
                RemoteExtentStore::connect_read_only(&config.extentd_socket, &config.path_on_host)
            }
            Making::Restore { .. } if config.read_only => {
                return Err(ExtentError::ReadOnlyRestored(config.id.clone()));
            }
            Making::Boot => RemoteExtentStore::connect(
                &config.extentd_socket,
                &config.path_on_host,
                config.capacity,
            ),
            Making::Restore { snapshot, .. } => RemoteExtentStore::connect_forked(
                &config.extentd_socket,
                &config.path_on_host,
                &snapshot.point,
                snapshot.point_branch,
                config.capacity,
            ),
        }
        .map_err(|err| ExtentError::Store(config.path_on_host.clone(), err))?;
        // fxdax: with the daemon gone, the guest's disk is gone: the VM stops at once, its exit
        // status saying why, rather than going on with every request failing (TASK-50.2).
        let id = config.id.clone();
        store.on_daemon_lost(move || {
            error!("extent device {id}: the extent daemon went; stopping the VM");
            std::process::exit(crate::FcExitCode::ExtentdLost as i32);
        });
        config_space.branch = store.branch().to_le();
        let resizing = Arc::new(Resizing::default());
        let info = store
            .info()
            .map_err(|err| ExtentError::Store(config.path_on_host.clone(), err.into()))?;
        resizing
            .capacity
            .store(info.capacity, std::sync::atomic::Ordering::Release);
        let changes = resizing.clone();
        store.on_capacity(move |capacity, ask| changes.changed(capacity, ask));
        let following = Arc::new(Following::default());
        hear_commits(&store, &following);

        // A follower's device writes nothing (doc-4's F_READ_ONLY). fxdax: notifications are
        // suppressed while the device takes the requests queued, and interrupts while the driver
        // takes the ones done (EVENT_IDX): each costs an exit, which nested virtualization makes
        // dear (TASK-41).
        let mut avail_features = if config.read_only {
            (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                | (1 << VIRTIO_EXTENT_F_FREEZE)
                | (1 << VIRTIO_EXTENT_F_READ_ONLY)
        } else {
            (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                | (1 << VIRTIO_EXTENT_F_WRITE_COMMIT)
                | (1 << VIRTIO_EXTENT_F_RESIZE)
                | (1 << VIRTIO_EXTENT_F_FREEZE)
                | (1 << VIRTIO_EXTENT_F_FREE_MANY)
        };
        let mut shm_regions = Vec::new();
        let window_addr = match making {
            Making::Boot => None,
            Making::Restore { window_addr, .. } => window_addr,
        };
        let window = match config.dax_window_size {
            Some(size) => {
                let window = match window_addr {
                    Some(addr) => DaxWindow::at(vm, addr, size)?,
                    None => DaxWindow::new(vm, size)?,
                };
                shm_regions.push(VirtioShmRegion {
                    id: DAX_WINDOW_SHM_ID,
                    guest_addr: window.guest_addr(),
                    len: window.len(),
                });
                // fxdax: a MAP may carry a chunk's pieces (doc-4's MAP_MANY, TASK-91.4), and say
                // the guest reads them next (MAP_AHEAD, TASK-112.1).
                avail_features |= (1 << VIRTIO_EXTENT_F_DAX)
                    | (1 << VIRTIO_EXTENT_F_MAP_MANY)
                    | (1 << VIRTIO_EXTENT_F_MAP_AHEAD);
                // The store maps open extents writably too (doc-4's DAX_WRITE): a writer's.
                if !config.read_only {
                    avail_features |= 1 << VIRTIO_EXTENT_F_DAX_WRITE;
                }
                Some(window)
            }
            None => None,
        };

        Ok(Self {
            config,
            store: Arc::new(store),
            window,
            shm_regions,
            window_created: false,
            prefault: None,
            config_space,
            resizing,
            following,
            reopen: false,
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            queues: (0..EXTENT_NUM_QUEUES)
                .map(|_| Queue::new(EXTENT_QUEUE_SIZE))
                .collect(),
            queue_events: (0..EXTENT_NUM_QUEUES)
                .map(|_| EventFd::new(libc::EFD_NONBLOCK).map_err(ExtentError::EventFd))
                .collect::<Result<_, _>>()?,
            workers: Vec::new(),
            frozen: Arc::default(),
            snapshot: None,
            mappings: Vec::new(),
        })
    }

    /// Has `prefault` map the DAX window's pages for the guest as the store maps them, rather
    /// than the guest faulting on each.
    pub fn set_prefault(&mut self, prefault: Arc<dyn PrefaultGuestMemory>) {
        self.prefault = Some(prefault);
    }

    /// Creates the store's DAX window in the window's host memory, unless the device has no
    /// window, or it exists.
    fn create_dax_window(&mut self) -> Result<(), fxdax::Error> {
        let Some(window) = &self.window else {
            return Ok(());
        };
        if self.window_created {
            return Ok(());
        }
        let prefault = self
            .prefault
            .clone()
            .map(|prefault| -> Arc<dyn fxdax::Prefault> {
                Arc::new(WindowPrefault {
                    guest_addr: window.guest_addr(),
                    prefault,
                })
            });
        // SAFETY: The window's host memory is the device's, which only the guest accesses, and
        // which outlives the store's connection, as the store is dropped first.
        unsafe {
            self.store.create_dax_window_in_host_memory(
                window.host_memory(),
                window.len(),
                prefault,
            )
        }?;
        self.window_created = true;
        Ok(())
    }

    /// fxdax: opens a follower's store anew, as of its writer's latest commit, with a window of
    /// its own, created as the driver activates the device: after a reset, its guest remounting
    /// on a new view, as it does once it was cut off (`ESTALE`).
    fn reopen(&mut self) -> Result<(), fxdax::Error> {
        let store = RemoteExtentStore::connect_read_only(
            &self.config.extentd_socket,
            &self.config.path_on_host,
        )?;
        self.following = Arc::new(Following::default());
        hear_commits(&store, &self.following);
        self.config_space.branch = store.branch().to_le();
        // The old connection goes, with its window's faults, before the new one creates its
        // window in the same memory, which it leaves inaccessible meanwhile (TASK-79.8).
        self.store = Arc::new(store);
        self.window_created = false;
        self.reopen = false;
        Ok(())
    }

    fn stop_worker(&mut self) {
        for (_, worker) in self.workers.drain(..) {
            worker.stop();
        }
    }

    /// Stops the workers, once the requests they took are served, and takes back their queues, as
    /// they left them, for a snapshot: the VM is paused, and the workers start again as it resumes
    /// (`VirtioDevice::kick`).
    fn pause_worker(&mut self) {
        for (index, worker) in std::mem::take(&mut self.workers) {
            if let Some(queue) = worker.stop() {
                self.queues[index] = queue;
            }
        }
    }

    /// Starts the workers again, if the device is activated and they are paused (`pause_worker`):
    /// one for each queue the driver set up.
    fn resume_worker(&mut self) -> Result<(), ActivateError> {
        let DeviceState::Activated(ActiveState { mem, interrupt }) = &self.device_state else {
            return Ok(());
        };
        if !self.workers.is_empty() {
            return Ok(());
        }
        let ready: Vec<usize> = (0..self.queues.len())
            .filter(|index| self.queues[*index].ready)
            .collect();
        let queues = self.queues.clone();
        let (queue_events, store) = (&self.queue_events, &self.store);
        let (resizing, frozen) = (&self.resizing, &self.frozen);
        let spawn = |index: usize| {
            // The worker serves the queue from here on, notified through a copy of its event.
            let queue_event = queue_events[index]
                .try_clone()
                .map_err(|_| ActivateError::EventFd)?;
            Worker::spawn(
                queues[index].clone(),
                u16::try_from(index).expect("the queues are few"),
                queue_event,
                interrupt.clone(),
                mem.clone(),
                store.clone(),
                resizing.clone(),
                frozen.clone(),
            )
            .map_err(|err| ActivateError::Extent(format!("starting a worker: {err}")))
        };
        let own = &mut self.queues;
        let workers = start_all(&ready, spawn, |index, worker: Worker| {
            if let Some(queue) = worker.stop() {
                own[index] = queue;
            }
        })?;
        self.workers = workers;
        Ok(())
    }

    /// Activates the device (`VirtioDevice::activate`), on a thread under the VMM's seccomp filter:
    /// opens the store anew if a snapshot left it, initializes the queues the driver set up, makes
    /// the DAX window, and starts the workers.
    fn activate_confined(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());
        // fxdax: those the driver set up, one per CPU of the guest's, up to the device's.
        let event_idx = self.acked_features & (1u64 << VIRTIO_RING_F_EVENT_IDX) != 0;
        for queue in self.queues.iter_mut().filter(|queue| queue.ready) {
            queue
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
            if event_idx {
                queue.enable_notif_suppression();
            }
        }
        // fxdax: once the queues are, so that an activation failing on them leaves the store as
        // it was, to open anew at the next (TASK-79.8).
        if self.reopen {
            self.reopen()
                .map_err(|err| ActivateError::Extent(format!("opening the store anew: {err:#}")))?;
        }
        self.create_dax_window()
            .map_err(|err| ActivateError::Extent(format!("creating the DAX window: {err:#}")))?;
        self.map_again().map_err(|errno| {
            ActivateError::Extent(format!("mapping the snapshot's window again: {errno}"))
        })?;
        *self.resizing.interrupt.lock().expect("Poisoned lock") = Some(interrupt.clone());
        *self.following.interrupt.lock().expect("Poisoned lock") = Some(interrupt.clone());
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        self.resume_worker()
    }

    /// fxdax: takes a snapshot of the device's store, for a snapshot of the VM, paused, whose
    /// guest's filesystem is frozen, with nothing open (TASK-39.1): forks the store to `point`,
    /// and records the window's mappings, which [`Persist::save`](crate::snapshot::Persist) saves.
    pub fn take_snapshot(&mut self, point: &Path) -> Result<(), ExtentSnapshotError> {
        let id = self.config.id.clone();
        if self.config.read_only {
            return Err(ExtentSnapshotError::ReadOnly(id));
        }
        if !self.frozen.load(Ordering::Acquire) {
            return Err(ExtentSnapshotError::NotFrozen(id));
        }
        // No request is in progress, which could change the window meanwhile.
        self.pause_worker();
        let branch = rand_branch().map_err(|err| ExtentSnapshotError::Branch(id.clone(), err))?;
        self.store.fork_quiescent(point, branch).map_err(|errno| {
            ExtentSnapshotError::Fork(id.clone(), point.display().to_string(), errno)
        })?;
        let mappings = self
            .store
            .window_mappings()
            .map_err(|errno| ExtentSnapshotError::Mappings(id, errno))?;
        self.snapshot = Some(ExtentSnapshot {
            point: point.to_owned(),
            point_branch: branch,
            mappings,
        });
        Ok(())
    }

    /// The snapshot taken of the device's store ([`Extent::take_snapshot`]), or restored from.
    pub fn snapshot(&self) -> Option<&ExtentSnapshot> {
        self.snapshot.as_ref()
    }

    /// Whether the guest's filesystem is frozen.
    pub(super) fn frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// The window's address in guest memory, if the device has a window.
    pub(super) fn window_addr(&self) -> Option<u64> {
        self.window.as_ref().map(DaxWindow::guest_addr)
    }

    /// The device as restored from a snapshot: its queues, features and the guest's freezing as
    /// they were, and the window's mappings to map again as it is activated.
    pub(super) fn restored(
        &mut self,
        snapshot: ExtentSnapshot,
        queues: Vec<Queue>,
        acked_features: u64,
        frozen: bool,
    ) {
        self.queues = queues;
        self.acked_features = acked_features;
        self.frozen.store(frozen, Ordering::Release);
        self.mappings.clone_from(&snapshot.mappings);
        self.snapshot = Some(snapshot);
    }

    /// Maps the window's mappings of the snapshot the device was restored from again.
    fn map_again(&mut self) -> Result<(), fxdax::Errno> {
        for mapping in std::mem::take(&mut self.mappings) {
            self.store.map_again(&mapping)?;
        }
        Ok(())
    }
}

/// fxdax: has `following` hear of the commits of the writer of `store`, a follower's, from the
/// one its view is as of.
fn hear_commits(store: &RemoteExtentStore, following: &Arc<Following>) {
    let heard = following.clone();
    store.on_committed(move |epoch| heard.committed(epoch));
    following.committed(store.committed());
}

/// A new branch's number, for a fork of the store, which names it in the extent daemon's bucket,
/// which hosts share: 64 bits of the kernel's random numbers (getrandom(2)), none 0. fxdax
/// TASK-79.26: not the clock's, whose xorshift gave about 38 bits, which two hosts' snapshots
/// could share: the second's uploads refused, or one tenant's filesystem restored for another.
fn rand_branch() -> std::io::Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        // SAFETY: getrandom(2) writes at most `bytes.len()` bytes, to `bytes`.
        let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        match usize::try_from(read) {
            // 8 bytes come whole from the kernel's pool once it is ready, which it waits for.
            Ok(8) => match u64::from_ne_bytes(bytes) {
                0 => continue,
                branch => return Ok(branch),
            },
            Ok(read) => unreachable!("getrandom(2) gave {read} bytes of 8"),
            Err(_) => {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

impl Drop for Extent {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

impl VirtioDevice for Extent {
    impl_device_type!(VirtioDeviceType::Extent);

    fn id(&self) -> &str {
        &self.config.id
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device not activated")
            .interrupt
            .as_ref()
    }

    // fxdax: the store's capacity, and the shrink the guest is asked to take, as they are now;
    // and a follower's writer's latest commit.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        use std::sync::atomic::Ordering;
        let config = ConfigSpace {
            capacity: self.resizing.capacity.load(Ordering::Acquire).to_le(),
            asked: self.resizing.asked.load(Ordering::Acquire).to_le(),
            committed: self.following.committed.load(Ordering::Acquire).to_le(),
            ..self.config_space
        };
        let config = config.as_slice();
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        if let Some(config_from_offset) = config.get(offset..) {
            let len = config_from_offset.len().min(data.len());
            data[..len].copy_from_slice(&config_from_offset[..len]);
            data[len..].fill(0);
        } else {
            data.fill(0);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "extent device: the driver wrote {} bytes of config at {offset:#x}",
            data.len()
        );
    }

    fn shm_regions(&self) -> &[VirtioShmRegion] {
        &self.shm_regions
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        // fxdax: on a thread of the extent threads' spawner, under the VMM thread's seccomp
        // filter, as the vCPU whose MMIO write activates the device waits: its work, opening the
        // DAX window's userfaultfd and the like, is the VMM's, not a vCPU's (TASK-50.1).
        let activated = fxdax::thread::run("fc_extent_activate", || {
            self.activate_confined(mem, interrupt)
        });
        activated.map_err(|err| ActivateError::Extent(format!("starting its activation: {err}")))?
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    // fxdax: the queues the driver set up alone: the others it never made ready.
    fn mark_queue_memory_dirty(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<(), crate::devices::virtio::queue::QueueError> {
        for queue in self.queues.iter_mut().filter(|queue| queue.ready) {
            queue.initialize(mem)?;
        }
        Ok(())
    }

    // fxdax: the worker starts again as the VM resumes after a snapshot (`pause_worker`), and
    // takes the requests queued meanwhile.
    fn kick(&mut self) {
        if let Err(err) = self.resume_worker() {
            error!("extent device {}: {err}", self.config.id);
        }
        if self.is_activated() {
            self.notify_queue_events();
        }
    }

    // fxdax: the queue as the worker left it, which no request changes: the VM is paused.
    fn prepare_save(&mut self) {
        self.pause_worker();
    }

    // fxdax: the worker stops, and the device is as before the driver activated it: a
    // follower's, its store opened anew as it is activated again.
    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // fxdax: as activation, on a thread under the VMM's seccomp filter, rather than the vCPU's
        // whose MMIO write resets the device (TASK-50.1).
        let reset = fxdax::thread::run("fc_extent_reset", || self.reset_confined());
        reset.unwrap_or_else(|err| {
            error!(
                "extent device {}: starting its reset: {err}",
                self.config.id
            );
            None
        })
    }
}

impl Extent {
    /// Resets the device (`VirtioDevice::reset`), on a thread under the VMM's seccomp filter.
    fn reset_confined(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        self.stop_worker();
        self.reopen = self.config.read_only;
        let DeviceState::Activated(ActiveState { interrupt, .. }) =
            std::mem::replace(&mut self.device_state, DeviceState::Inactive)
        else {
            return None;
        };
        self.acked_features = 0;
        let queue_events = self.queue_events.iter().map(EventFd::try_clone);
        Some((interrupt, queue_events.collect::<Result<_, _>>().ok()?))
    }
}

/// The device's events are the worker's own: the event manager has none to process.
impl MutEventSubscriber for Extent {
    fn init(&mut self, _ops: &mut EventOps) {}

    fn process(&mut self, _events: Events, _ops: &mut EventOps) {}
}

/// fxdax: starts a worker for each of `ready` by `spawn`: all of them, or, one failing, none,
/// those it started stopped by `stop`. Left running, no stop or reset would reach them, and the
/// next kick would start others on the same queues (TASK-79.44).
fn start_all<W, E>(
    ready: &[usize],
    mut spawn: impl FnMut(usize) -> Result<W, E>,
    mut stop: impl FnMut(usize, W),
) -> Result<Vec<(usize, W)>, E> {
    let mut started = Vec::with_capacity(ready.len());
    for &index in ready {
        match spawn(index) {
            Ok(worker) => started.push((index, worker)),
            Err(err) => {
                started.into_iter().for_each(|(index, worker)| stop(index, worker));
                return Err(err);
            }
        }
    }
    Ok(started)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TASK-79.44: a worker failing to start stops those started before it.
    #[test]
    fn workers_start_all_or_none() {
        let mut stopped = Vec::new();
        let spawn = |index: usize| if index == 5 { Err("no thread") } else { Ok(index * 10) };
        let stop = |index, worker| stopped.push((index, worker));
        assert_eq!(start_all(&[1, 3, 5, 7], spawn, stop), Err("no thread"));
        assert_eq!(stopped, vec![(1, 10), (3, 30)]);

        let mut stopped: Vec<(usize, usize)> = Vec::new();
        let started = start_all(&[1, 3], |index| Ok::<_, ()>(index * 10), |index, worker| {
            stopped.push((index, worker))
        });
        assert_eq!(started, Ok(vec![(1, 10), (3, 30)]));
        assert_eq!(stopped, vec![]);
    }

    /// The value `xorshift32` (13, 17, 5) gave `value`, as vmm-sys-util's `xor_pseudo_rng_u32`
    /// does the clock's, which is a bijection.
    fn unxorshift(value: u32) -> u32 {
        let unshift_left = |y: u32, by: u32| (0..32 / by).fold(y, |x, _| y ^ (x << by));
        let unshift_right = |y: u32, by: u32| (0..32 / by).fold(y, |x, _| y ^ (x >> by));
        unshift_left(unshift_right(unshift_left(value, 5), 17), 13)
    }

    /// fxdax TASK-79.26: a branch's halves aren't the clock's, through a xorshift, as they were:
    /// undone, neither is a reading of the clock (`timestamp_cycles`) between those taken before
    /// and after the branch was named, which a name from the kernel's random numbers is but by a
    /// chance of the clock's few ticks meanwhile in 2^32.
    #[test]
    fn branches_are_not_the_clocks() {
        use vmm_sys_util::rand::timestamp_cycles;

        for _ in 0..16 {
            let before = timestamp_cycles() as u32;
            let branch = rand_branch().unwrap();
            let after = timestamp_cycles() as u32;
            for half in [(branch >> 32) as u32, branch as u32] {
                let clock = unxorshift(half);
                assert!(
                    clock.wrapping_sub(before) > after.wrapping_sub(before),
                    "branch {branch:#x}: its half {half:#x} is the clock's {clock:#x}, read between \
                     {before:#x} and {after:#x}"
                );
            }
        }
    }

    /// The test's undoing of the xorshift undoes vmm-sys-util's.
    #[test]
    fn unxorshift_undoes_the_clocks_xorshift() {
        let shifted = |mut t: u32| {
            t ^= t << 13;
            t ^= t >> 17;
            t ^ (t << 5)
        };
        for value in [0, 1, 0x8000_0000, 0xdead_beef, u32::MAX] {
            assert_eq!(unxorshift(shifted(value)), value);
        }
    }
}
