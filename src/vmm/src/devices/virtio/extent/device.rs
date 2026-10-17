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
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{
    ActiveState, DeviceState, VirtioDevice, VirtioDeviceType, VirtioShmRegion,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
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
    /// Extent device {0}: cannot fork its store to {1}: {2}
    Fork(String, String, fxdax::Errno),
    /// Extent device {0}: cannot list its DAX window's mappings: {1}
    Mappings(String, fxdax::Errno),
}

/// What a snapshot of the device holds of its store (TASK-39.1): the point it was taken at, a fork
/// of the store, which each VM restored from it forks again, and the window's mappings then, which
/// the restored VM's window maps again.
#[derive(Debug, Clone)]
pub struct ExtentSnapshot {
    pub point: PathBuf,
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

    // VirtIO fields
    avail_features: u64,
    acked_features: u64,

    // Transport fields
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// The worker serving the queue, while the device is activated, and not paused for a snapshot
    /// (`pause_worker`).
    worker: Option<Worker>,
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
            map_alignment: u32::try_from(fxdax::kernel::page_size())
                .expect("a page is small")
                .to_le(),
            max_transfer: MAX_TRANSFER.to_le(),
            max_segments: (u32::from(EXTENT_QUEUE_SIZE) - 2).to_le(),
            max_root: MAX_ROOT.to_le(),
            branch: 0,
            max_extent: MAX_EXTENT.to_le(),
            capacity: 0,
            asked: 0,
        };
        let tag = config.tag.as_bytes();
        if tag.len() > config_space.tag.len() {
            return Err(ExtentError::TagTooLong(config.tag.clone()));
        }
        config_space.tag[..tag.len()].copy_from_slice(tag);

        let store = match &making {
            Making::Boot => RemoteExtentStore::connect(
                &config.extentd_socket,
                &config.path_on_host,
                config.capacity,
            ),
            Making::Restore { snapshot, .. } => RemoteExtentStore::connect_forked(
                &config.extentd_socket,
                &config.path_on_host,
                &snapshot.point,
            ),
        }
        .map_err(|err| ExtentError::Store(config.path_on_host.clone(), err))?;
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

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_EXTENT_F_WRITE_COMMIT)
            | (1 << VIRTIO_EXTENT_F_RESIZE)
            | (1 << VIRTIO_EXTENT_F_FREEZE);
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
                // The store maps open extents writably too (doc-4's DAX_WRITE).
                avail_features |= (1 << VIRTIO_EXTENT_F_DAX) | (1 << VIRTIO_EXTENT_F_DAX_WRITE);
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
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(EXTENT_QUEUE_SIZE)],
            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(ExtentError::EventFd)?],
            worker: None,
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

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.stop();
        }
    }

    /// Stops the worker, once the requests it took are served, and takes back its queue, as it
    /// left it, for a snapshot: the VM is paused, and the worker starts again as it resumes
    /// (`VirtioDevice::kick`).
    fn pause_worker(&mut self) {
        if let Some(queue) = self.worker.take().and_then(Worker::stop) {
            self.queues[0] = queue;
        }
    }

    /// Starts the worker again, if the device is activated and it is paused (`pause_worker`).
    fn resume_worker(&mut self) -> Result<(), ActivateError> {
        let DeviceState::Activated(ActiveState { mem, interrupt }) = &self.device_state else {
            return Ok(());
        };
        if self.worker.is_some() {
            return Ok(());
        }
        // The worker serves the queue from here on, notified through a copy of its event.
        let queue_event = self.queue_events[0]
            .try_clone()
            .map_err(|_| ActivateError::EventFd)?;
        let worker = Worker::spawn(
            self.queues[0].clone(),
            queue_event,
            interrupt.clone(),
            mem.clone(),
            self.store.clone(),
            self.resizing.clone(),
            self.frozen.clone(),
        )
        .map_err(|err| ActivateError::Extent(format!("starting the worker: {err}")))?;
        self.worker = Some(worker);
        Ok(())
    }

    /// fxdax: takes a snapshot of the device's store, for a snapshot of the VM, paused, whose
    /// guest's filesystem is frozen, with nothing open (TASK-39.1): forks the store to `point`,
    /// and records the window's mappings, which [`Persist::save`](crate::snapshot::Persist) saves.
    pub fn take_snapshot(&mut self, point: &Path) -> Result<(), ExtentSnapshotError> {
        let id = self.config.id.clone();
        if !self.frozen.load(Ordering::Acquire) {
            return Err(ExtentSnapshotError::NotFrozen(id));
        }
        // No request is in progress, which could change the window meanwhile.
        self.pause_worker();
        let branch = rand_branch();
        self.store.fork_quiescent(point, branch).map_err(|errno| {
            ExtentSnapshotError::Fork(id.clone(), point.display().to_string(), errno)
        })?;
        let mappings = self
            .store
            .window_mappings()
            .map_err(|errno| ExtentSnapshotError::Mappings(id, errno))?;
        self.snapshot = Some(ExtentSnapshot {
            point: point.to_owned(),
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

/// A new branch's number, for a fork of the store.
fn rand_branch() -> u64 {
    let rng = vmm_sys_util::rand::xor_pseudo_rng_u32;
    ((u64::from(rng()) << 32) | u64::from(rng())).max(1)
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

    // fxdax: the store's capacity, and the shrink the guest is asked to take, as they are now.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        use std::sync::atomic::Ordering;
        let config = ConfigSpace {
            capacity: self.resizing.capacity.load(Ordering::Acquire).to_le(),
            asked: self.resizing.asked.load(Ordering::Acquire).to_le(),
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
        assert!(!self.is_activated());
        for queue in self.queues.iter_mut() {
            queue
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }
        self.create_dax_window()
            .map_err(|err| ActivateError::Extent(format!("creating the DAX window: {err:#}")))?;
        self.map_again().map_err(|errno| {
            ActivateError::Extent(format!("mapping the snapshot's window again: {errno}"))
        })?;
        *self.resizing.interrupt.lock().expect("Poisoned lock") = Some(interrupt.clone());
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        self.resume_worker()
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
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

    // fxdax: the worker stops, and the device is as before the driver activated it.
    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        self.stop_worker();
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
