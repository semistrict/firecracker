// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent-store device: its configuration, features and DAX window, and the worker that
//! serves its requests once the driver activates it.

use std::fmt;
use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use fxdax::{ExtentStore, RemoteExtentStore};
use vmm_sys_util::eventfd::EventFd;

use super::window::{DaxWindow, DaxWindowError, PrefaultGuestMemory, WindowPrefault};
use super::worker::Worker;
use super::{
    ConfigSpace, DAX_WINDOW_SHM_ID, EXTENT_NUM_QUEUES, EXTENT_QUEUE_SIZE, MAX_EXTENT, MAX_ROOT,
    MAX_TRANSFER, VIRTIO_EXTENT_F_DAX, VIRTIO_EXTENT_F_DAX_WRITE,
};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{
    ActiveState, DeviceState, VirtioDevice, VirtioDeviceType, VirtioShmRegion,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::impl_device_type;
use crate::logger::warn;
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

    // VirtIO fields
    avail_features: u64,
    acked_features: u64,

    // Transport fields
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// The worker serving the queue, while the device is activated.
    worker: Option<Worker>,
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
        };
        let tag = config.tag.as_bytes();
        if tag.len() > config_space.tag.len() {
            return Err(ExtentError::TagTooLong(config.tag.clone()));
        }
        config_space.tag[..tag.len()].copy_from_slice(tag);

        let store = RemoteExtentStore::connect(
            &config.extentd_socket,
            &config.path_on_host,
            config.capacity,
        )
        .map_err(|err| ExtentError::Store(config.path_on_host.clone(), err))?;
        config_space.branch = store.branch().to_le();

        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;
        let mut shm_regions = Vec::new();
        let window = match config.dax_window_size {
            Some(size) => {
                let window = DaxWindow::new(vm, size)?;
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
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(EXTENT_QUEUE_SIZE)],
            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(ExtentError::EventFd)?],
            worker: None,
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

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
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
        )
        .map_err(|err| ActivateError::Extent(format!("starting the worker: {err}")))?;
        self.worker = Some(worker);
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        self.stop_worker();
        true
    }
}

/// The device's events are the worker's own: the event manager has none to process.
impl MutEventSubscriber for Extent {
    fn init(&mut self, _ops: &mut EventOps) {}

    fn process(&mut self, _events: Events, _ops: &mut EventOps) {}
}
