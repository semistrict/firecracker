// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store device as a virtio device of Firecracker's: cladefs's `virtio_extent::Device`,
//! its queues and their workers, which serve its requests once the driver activates it, and its
//! window's shared memory region.

use std::fmt;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use virtio_extent::Workers;
use virtio_extent::persist::SnapshotError;
use vmm_sys_util::eventfd::EventFd;

use super::window::ExtentVm;
use super::worker::{ExtentQueue, QueueVector};
use super::{ConfigInterrupt, EXTENT_MAX_QUEUES, EXTENT_QUEUE_SIZE, PrefaultGuestMemory};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{
    ActiveState, DeviceState, VirtioDevice, VirtioDeviceType, VirtioShmRegion,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::impl_device_type;
use crate::logger::error;
use crate::vmm_config::cladefs::CladefsDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

/// Errors making an extent-store device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ExtentError {
    /// {0}
    Device(#[from] virtio_extent::Error),
    /// Error with EventFd: {0}
    EventFd(std::io::Error),
    /// {0}
    Protocol(#[from] virtio_extent::protocol::VersionRefused),
    /// The extent device {0} has {1} request queues: it has one at least, and as many as a VM has vCPUs at most
    Queues(String, usize),
}

/// How a device is made: as its VM boots, or restored from a snapshot's state.
pub(super) enum Making<'a> {
    Boot,
    Restore(&'a virtio_extent::persist::State),
}

/// A virtio extent-store device, on an extent store that cladefs's extent daemon serves.
pub struct Extent {
    device: virtio_extent::Device,
    /// The window's shared memory region, if the device has a window.
    shm_regions: Vec<VirtioShmRegion>,

    // VirtIO fields
    avail_features: u64,
    acked_features: u64,

    // Transport fields
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// The workers serving the queues the driver set up, while the device is activated, and not
    /// paused for a snapshot (`pause_worker`).
    workers: Option<Workers<ExtentQueue>>,
}

impl fmt::Debug for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extent")
            .field("device", &self.device)
            .field("shm_regions", &self.shm_regions)
            .field("device_state", &self.device_state)
            .finish_non_exhaustive()
    }
}

impl Extent {
    /// A device as `config` describes, in `vm`, which opens its store, creating it if it doesn't
    /// exist, in the extent daemon, and maps its DAX window, if it has one, into the guest. cladefs:
    /// with `queues` request queues, its VM's vCPUs' ([`super::request_queues`], TASK-276).
    pub fn new(
        vm: Arc<KvmVm>,
        config: CladefsDeviceConfig,
        queues: usize,
    ) -> Result<Self, ExtentError> {
        Self::make(vm, config, queues, Making::Boot)
    }

    /// A device as `config` describes, with `queues` request queues, made as `making` says: its
    /// store opened, or, restored from a snapshot, forked from the snapshot's copy if it doesn't
    /// exist; its window in guest memory where the snapshot had it.
    pub(super) fn make(
        vm: Arc<KvmVm>,
        config: CladefsDeviceConfig,
        queues: usize,
        making: Making<'_>,
    ) -> Result<Self, ExtentError> {
        if !(1..=EXTENT_MAX_QUEUES).contains(&queues) {
            return Err(ExtentError::Queues(config.id.clone(), queues));
        }
        let count = u16::try_from(queues).expect("the queues are few");
        let window_vm = Arc::new(ExtentVm::new(vm));
        let lost = on_lost(&config.id);
        let device = match making {
            Making::Boot => virtio_extent::Device::new(config, count, window_vm, lost)?,
            Making::Restore(state) => {
                virtio_extent::Device::restore(state, count, window_vm, lost)?
            }
        };
        let shm_regions = device
            .shm_region()
            .map(|region| VirtioShmRegion {
                id: region.id,
                guest_addr: region.guest_addr,
                len: region.len,
            })
            .into_iter()
            .collect();
        // cladefs: notifications are suppressed while the device takes the requests queued, and
        // interrupts while the driver takes the ones done (EVENT_IDX): each costs an exit, which
        // nested virtualization makes dear (TASK-41).
        let avail_features =
            (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX) | device.features();
        Ok(Self {
            device,
            shm_regions,
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            queues: (0..queues).map(|_| Queue::new(EXTENT_QUEUE_SIZE)).collect(),
            queue_events: (0..queues)
                .map(|_| EventFd::new(libc::EFD_NONBLOCK).map_err(ExtentError::EventFd))
                .collect::<Result<_, _>>()?,
            workers: None,
        })
    }

    /// Its configuration.
    pub fn config(&self) -> &CladefsDeviceConfig {
        self.device.config()
    }

    /// The device, but its transport.
    pub(super) fn device(&self) -> &virtio_extent::Device {
        &self.device
    }

    /// Has `prefault` map the DAX window's pages for the guest as the store maps them, rather
    /// than the guest faulting on each.
    pub fn set_prefault(&mut self, prefault: Arc<dyn PrefaultGuestMemory>) {
        self.device.set_prefault(prefault);
    }

    fn stop_worker(&mut self) {
        if let Some(workers) = self.workers.take() {
            workers.stop();
        }
    }

    /// Stops the workers, once the requests they took are served, and takes back their queues, as
    /// they left them, for a snapshot: the VM is paused, and the workers start again as it resumes
    /// (`VirtioDevice::kick`).
    fn pause_worker(&mut self) {
        pause(&mut self.workers, &mut self.queues);
    }

    /// Starts the workers again, if the device is activated and they are paused (`pause_worker`):
    /// one for each queue the driver set up, notified through a copy of its event, all or none.
    fn resume_worker(&mut self) -> Result<(), ActivateError> {
        if self.device.is_cell_released() {
            return Err(ActivateError::Extent(format!(
                "extent device {}: its cell is released",
                self.config().id
            )));
        }
        let DeviceState::Activated(ActiveState { mem, interrupt }) = &self.device_state else {
            return Ok(());
        };
        if self.workers.is_some() {
            return Ok(());
        }
        let mut queues = Vec::new();
        for (index, queue) in self
            .queues
            .iter()
            .enumerate()
            .filter(|(_, queue)| queue.ready)
        {
            let index = u16::try_from(index).expect("the queues are few");
            let event = self.queue_events[usize::from(index)]
                .try_clone()
                .map_err(|_| ActivateError::EventFd)?;
            queues.push(virtio_extent::WorkerQueue {
                index,
                queue: ExtentQueue::new(queue.clone(), mem.clone()),
                // SAFETY: The copy's descriptor, which the worker owns from here on.
                event: unsafe { OwnedFd::from_raw_fd(event.into_raw_fd()) },
                interrupt: Arc::new(QueueVector {
                    interrupt: interrupt.clone(),
                    index,
                }),
            });
        }
        let workers = self
            .device
            .start_workers(queues, "fc_extent_q")
            .map_err(|err| ActivateError::Extent(format!("starting a worker: {err}")))?;
        self.workers = Some(workers);
        Ok(())
    }

    /// Activates the device (`VirtioDevice::activate`), on a thread under the VMM's seccomp filter:
    /// initializes the queues the driver set up, activates the device, which opens the store anew
    /// if a reset let it go and makes the DAX window, and starts the workers.
    fn activate_confined(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());
        virtio_extent::protocol::check_acked(self.avail_features, self.acked_features)
            .map_err(|refused| ActivateError::Extent(refused.to_string()))?;
        // cladefs: those the driver set up, one per CPU of the guest's, up to the device's.
        let event_idx = self.acked_features & (1u64 << VIRTIO_RING_F_EVENT_IDX) != 0;
        for queue in self.queues.iter_mut().filter(|queue| queue.ready) {
            queue
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
            if event_idx {
                queue.enable_notif_suppression();
            }
        }
        let config_interrupt = Arc::new(ConfigInterrupt(interrupt.clone()));
        self.device
            .activate(self.acked_features, config_interrupt)
            .map_err(|err| ActivateError::Extent(err.to_string()))?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        self.resume_worker()
    }

    /// cladefs: takes a snapshot of the device's store, for a snapshot of the VM, paused
    /// (TASK-39.1): with `SnapshotMode::Versioned`, requires the guest's filesystem to be frozen
    /// and makes a version of the store's cell; with `SnapshotMode::Migration`, checks quiescence
    /// and records the window's mappings without freezing or versioning, for a cell handed over by
    /// `HandOverCell`. No request is in progress meanwhile, which could change the window: the
    /// workers stop.
    pub fn take_snapshot(
        &mut self,
        mode: virtio_extent::SnapshotMode,
    ) -> Result<(), SnapshotError> {
        let (workers, queues) = (&mut self.workers, &mut self.queues);
        self.device
            .take_snapshot_with(mode, || pause(workers, queues))
    }

    /// cladefs: whether the device's cell has been released via [`Extent::release_cell`].
    pub fn is_cell_released(&self) -> bool {
        self.device.is_cell_released()
    }

    /// cladefs: closes the device's cell in the extent daemon on a paused VM so `HandOverCell`
    /// can take exclusive ownership without killing the VM process.
    pub fn release_cell(&mut self) -> Result<(), virtio_extent::ReleaseError> {
        let (workers, queues) = (&mut self.workers, &mut self.queues);
        self.device.release_cell(|| pause(workers, queues))
    }

    /// cladefs: reopens the device's cell after [`Extent::release_cell`] (e.g. when live migration
    /// aborts) and restores its DAX window mappings so the VM can resume.
    pub fn reopen_cell(&mut self) -> Result<(), virtio_extent::Error> {
        self.device.reopen_cell()
    }

    /// cladefs: drops the snapshot [`Extent::take_snapshot`] took, its version, for a snapshot of
    /// the VM that failed after it (TASK-575).
    pub fn drop_snapshot(&mut self) {
        self.device.drop_snapshot()
    }

    /// The snapshot taken of the device's store ([`Extent::take_snapshot`]), or restored from.
    pub fn snapshot(&self) -> Option<&virtio_extent::persist::Snapshot> {
        self.device.snapshot()
    }

    /// The device as restored from a snapshot: its queues and features as they were.
    pub(super) fn restored(&mut self, queues: Vec<Queue>, acked_features: u64) {
        self.queues = queues;
        self.acked_features = acked_features;
    }
}

/// What stops the VM as the extent daemon of the device `id` goes: the guest's disk is gone then,
/// and the VM stops at once, its exit status saying why, rather than going on with every request
/// failing (TASK-50.2).
fn on_lost(id: &str) -> virtio_extent::OnLost {
    let id = id.to_owned();
    Arc::new(move || {
        error!("extent device {id}: stopping the VM");
        // The VM can't go on, and nothing returns to the VMM's loop to stop it from here.
        #[allow(clippy::exit)]
        std::process::exit(crate::FcExitCode::CladefsdLost as i32);
    })
}

/// Stops `workers`, once the requests they took are served, and takes back their queues into
/// `queues`, as they left them.
fn pause(workers: &mut Option<Workers<ExtentQueue>>, queues: &mut [Queue]) {
    for (index, queue) in workers.take().map(Workers::stop).unwrap_or_default() {
        queues[usize::from(index)] = queue.queue;
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
        &self.config().id
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

    fn config_as_bytes(&self) -> &[u8] {
        // Live fields (capacity, asked, committed, stats_asked) are assembled on demand in
        // `read_config`; the extent device runs over virtio-PCI alone (not Nitro Enclave).
        &[]
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.device.read_config(offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        crate::logger::warn!(
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
        // cladefs: on a thread of the extent threads' spawner, under the VMM thread's seccomp
        // filter, as the vCPU whose MMIO write activates the device waits: its work, opening the
        // DAX window's userfaultfd and the like, is the VMM's, not a vCPU's (TASK-50.1).
        let activated = cladefs::thread::run("fc_extent_activate", || {
            self.activate_confined(mem, interrupt)
        });
        activated.map_err(|err| ActivateError::Extent(format!("starting its activation: {err}")))?
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    // cladefs: the queues the driver set up alone: the others it never made ready.
    fn mark_queue_memory_dirty(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<(), crate::devices::virtio::queue::QueueError> {
        for queue in self.queues.iter_mut().filter(|queue| queue.ready) {
            queue.initialize(mem)?;
        }
        Ok(())
    }

    // cladefs: the worker starts again as the VM resumes after a snapshot (`pause_worker`), and
    // takes the requests queued meanwhile.
    fn kick(&mut self) {
        if let Err(err) = self.resume_worker() {
            error!("extent device {}: {err}", self.config().id);
        }
        if self.is_activated() {
            self.notify_queue_events();
        }
    }

    // cladefs: the queue as the worker left it, which no request changes: the VM is paused.
    fn prepare_save(&mut self) {
        self.pause_worker();
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    // cladefs: the worker stops, and the device is as before the driver activated it.
    fn _reset(&mut self) -> bool {
        // cladefs: as activation, on a thread under the VMM's seccomp filter, rather than the vCPU's
        // whose MMIO write resets the device (TASK-50.1).
        let reset = cladefs::thread::run("fc_extent_reset", || {
            self.stop_worker();
            self.device.reset();
        });
        match reset {
            Ok(()) => true,
            Err(err) => {
                error!(
                    "extent device {}: starting its reset: {err}",
                    self.config().id
                );
                false
            }
        }
    }
}

/// The device's events are the worker's own: the event manager has none to process.
impl MutEventSubscriber for Extent {
    fn init(&mut self, _ops: &mut EventOps) {}

    fn process(&mut self, _events: Events, _ops: &mut EventOps) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cladefs TASK-141.3: a driver activating the device having taken fewer features than it
    /// offers is refused, naming them, as the crate's check says.
    #[test]
    fn drivers_take_every_feature_offered() {
        let offered =
            (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX) | (1 << 4) | 1;
        let refused = virtio_extent::protocol::check_acked(offered, offered & !(1 << 4))
            .map_err(|refused| ActivateError::Extent(refused.to_string()))
            .unwrap_err()
            .to_string();
        assert_eq!(
            refused,
            "Extent device: the driver took features 0x120000001 of the 0x120000011 offered, \
             where a driver of protocol version 3 takes every one: it is of another"
        );
    }
}
