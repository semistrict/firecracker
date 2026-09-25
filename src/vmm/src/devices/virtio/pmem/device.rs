// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
use serde::{Deserialize, Serialize};
use vm_allocator::{AllocPolicy, RangeInclusive};
use vm_memory::{GuestAddress, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::pmem::PMEM_QUEUE_SIZE;
use crate::devices::virtio::pmem::metrics::{PmemMetrics, PmemMetricsPerDevice};
use crate::devices::virtio::queue::{DescriptorChain, InvalidAvailIdx, Queue, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, error, info, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use crate::utils::u64_to_usize;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{ByteValued, Bytes, GuestMemoryMmap};
use crate::vstate::vm::{KvmVm, VmError};
use crate::{align_up, impl_device_type};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemError {
    /// Failed to allocate memory region
    AllocationFailed,
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(VmError),
    /// Unablet to allocate a KVM slot for the device
    NoKvmSlotAvailable,
    /// Error accessing backing file: {0}
    BackingFile(std::io::Error),
    /// Error backing file size is 0
    BackingFileZeroSize,
    /// Restored pmem size {0} does not match backing file mapping size {1}
    RestoredSizeMismatch(u64, u64),
    /// Error with EventFd: {0}
    EventFd(std::io::Error),
    /// Unexpected read-only descriptor
    ReadOnlyDescriptor,
    /// Unexpected write-only descriptor
    WriteOnlyDescriptor,
    /// Head descriptor has invalid length of {0} instead of 4
    Non4byteHeadDescriptor(u32),
    /// Status descriptor has invalid length of {0} instead of 4
    Non4byteStatusDescriptor(u32),
    /// UnknownRequestType: {0}
    UnknownRequestType(u32),
    /// Descriptor chain too short
    DescriptorChainTooShort,
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Error handling the VirtIO queue: {0}
    Queue(#[from] QueueError),
    /// Error during obtaining the descriptor from the queue: {0}
    QueuePop(#[from] InvalidAvailIdx),
}

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const SUCCESS: i32 = 0;
const FAILURE: i32 = -1;

/// Where a managed volume's flushes go: the host, which makes each durable and
/// then answers it. The answer may be seconds away, so a device never waits for
/// it; `flushed` runs once, on whatever thread the answer arrives on, unless
/// starting the request fails, in which case it never runs.
pub trait FlushHost: std::fmt::Debug + Send + Sync {
    fn start_flush(
        &self,
        flushed: Box<dyn FnOnce(std::io::Result<()>) + Send>,
    ) -> std::io::Result<()>;
}

/// One guest flush request the device has taken off its queue and not yet
/// completed: the head of its descriptor chain, and the guest address its
/// status goes to. A snapshot records these, so a guest restored elsewhere has
/// its waiting flushes asked of the host it is restored on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingFlush {
    pub head: u16,
    pub status: u64,
}

/// A managed volume's flushes between the queue and the host's answers.
///
/// Each queue drain is one request to the host covering every flush in it,
/// since one answer makes all of them durable. A request's answer is handed
/// over by the thread it arrives on through `answers` and `answered`, and the
/// device completes its flushes on its own thread when the event fires, so
/// the VMM thread never waits for the host.
#[derive(Debug)]
pub struct Flushes {
    host: Option<Arc<dyn FlushHost>>,
    /// Requests the host has been sent and has not answered, by request.
    sent: BTreeMap<u64, Vec<PendingFlush>>,
    /// Flushes the host this device now serves has never been asked: those a
    /// snapshot restored, and those held over a handoff. The next kick, which
    /// is the resume that runs the guest again, asks for them.
    unsent: Vec<PendingFlush>,
    next: u64,
    answers: Answers,
    pub answered: Arc<EventFd>,
}

/// The host's answers, by request, as the threads they arrive on hand them over.
type Answers = Arc<Mutex<Vec<(u64, std::io::Result<()>)>>>;

impl Flushes {
    fn new(host: Option<Arc<dyn FlushHost>>) -> Result<Self, PmemError> {
        Ok(Self {
            host,
            sent: BTreeMap::new(),
            unsent: Vec::new(),
            next: 0,
            answers: Arc::new(Mutex::new(Vec::new())),
            answered: Arc::new(EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?),
        })
    }

    /// Whether a host answers this device's flushes, rather than msync.
    fn hosted(&self) -> bool {
        self.host.is_some()
    }

    /// Asks the host to make these flushes durable. A request that cannot be
    /// started is answered with its error at once, through the same event.
    fn send(&mut self, flushes: Vec<PendingFlush>) {
        let Some(host) = &self.host else {
            return;
        };
        let request = self.next;
        self.next += 1;
        self.sent.insert(request, flushes);
        let answer = {
            let answers = self.answers.clone();
            let answered = self.answered.clone();
            move |result| {
                answers.lock().unwrap().push((request, result));
                if let Err(err) = answered.write(1) {
                    error!("pmem: Unable to signal a flush's answer: {err}");
                }
            }
        };
        if let Err(err) = host.start_flush(Box::new(answer)) {
            self.answers.lock().unwrap().push((request, Err(err)));
            if let Err(err) = self.answered.write(1) {
                error!("pmem: Unable to signal a flush's answer: {err}");
            }
        }
    }

    /// Takes the flushes the host has answered, with its answer. An answer to
    /// a request this device has since forgotten — over a reset, or a handoff
    /// that gave its flushes to the guest's next host — completes nothing.
    fn take_answered(&mut self) -> Vec<(Vec<PendingFlush>, std::io::Result<()>)> {
        // Read before the answers are taken: an answer pushed after this read
        // signals again, and one pushed before it is taken below.
        if let Err(err) = self.answered.read()
            && err.kind() != std::io::ErrorKind::WouldBlock
        {
            error!("pmem: Unable to consume a flush's answer: {err}");
        }
        let answers = std::mem::take(&mut *self.answers.lock().unwrap());
        answers
            .into_iter()
            .filter_map(|(request, result)| {
                self.sent.remove(&request).map(|flushes| (flushes, result))
            })
            .collect()
    }

    /// Every flush that is waiting, whether or not its host has been asked.
    pub fn pending(&self) -> Vec<PendingFlush> {
        let mut pending = self.unsent.clone();
        pending.extend(self.sent.values().flatten());
        pending
    }

    /// Takes back every flush sent to this host, which will never answer them:
    /// the guest is stopped for a destination, and its flushes are asked of the
    /// host it is restored on. If it runs here again instead, they are asked
    /// again on its resume.
    fn hand_off(&mut self) {
        let sent = std::mem::take(&mut self.sent);
        self.unsent.extend(sent.into_values().flatten());
    }

    /// Asks for the flushes this host has never been asked.
    fn resend(&mut self) {
        if !self.unsent.is_empty() && self.hosted() {
            let unsent = std::mem::take(&mut self.unsent);
            self.send(unsent);
        }
    }

    /// Records flushes a snapshot held, to be asked on the next resume.
    pub fn restore(&mut self, pending: &[PendingFlush]) {
        self.unsent.extend_from_slice(pending);
    }

    fn reset(&mut self) {
        self.sent.clear();
        self.unsent.clear();
    }
}

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct ConfigSpace {
    // Physical address of the first byte of the persistent memory region.
    pub start: u64,
    // Length of the address range
    pub size: u64,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(c)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// RAII wrapper for a guest address allocation. Frees the allocated region on drop.
#[derive(Debug)]
pub struct GuestPmemRegion {
    vm: Arc<KvmVm>,
    pub config_space: ConfigSpace,
}

impl GuestPmemRegion {
    /// Allocate a new region in past_mmio64 memory.
    fn new(vm: Arc<KvmVm>, size: u64) -> Result<Self, PmemError> {
        let start = {
            let mut alloc = vm.resource_allocator();
            alloc
                .past_mmio64_memory
                .allocate(size, Pmem::ALIGNMENT, AllocPolicy::FirstMatch)
                .map_err(|_| PmemError::AllocationFailed)?
                .start()
        };
        Ok(Self {
            vm,
            config_space: ConfigSpace { start, size },
        })
    }

    /// Wrap an existing allocation (e.g. from a snapshot) for RAII cleanup.
    pub fn from_state(vm: Arc<KvmVm>, config_space: ConfigSpace) -> Self {
        Self { vm, config_space }
    }
}

impl Drop for GuestPmemRegion {
    fn drop(&mut self) {
        let range = RangeInclusive::new(
            self.config_space.start,
            self.config_space.start + self.config_space.size - 1,
        )
        .expect("Invalid config_space range");
        let mut alloc = self.vm.resource_allocator();
        _ = alloc.past_mmio64_memory.free(&range);
    }
}

/// RAII wrapper for the KVM user memory region. Removes the region on drop.
#[derive(Debug)]
pub struct KvmMemSlot {
    vm: Arc<KvmVm>,
    slot: u32,
}

impl KvmMemSlot {
    fn new(
        vm: Arc<KvmVm>,
        gpa: u64,
        memory_size: u64,
        hva: u64,
        flags: u32,
    ) -> Result<Self, PmemError> {
        // FIXME: The KVM slot number itself is not returned. This is not an
        // issue currently since there are at least 32K slots available. But we
        // could improve this by implementing a slot allocator that allows us
        // to free slot numbers.
        let slot = vm.next_kvm_slot(1).ok_or(PmemError::NoKvmSlotAvailable)?;
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: gpa,
            memory_size,
            userspace_addr: hva,
            flags,
        };
        vm.set_user_memory_region(region)
            .map_err(PmemError::SetUserMemoryRegion)?;
        Ok(Self { vm, slot })
    }
}

impl Drop for KvmMemSlot {
    fn drop(&mut self) {
        let region = kvm_userspace_memory_region {
            slot: self.slot,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        _ = self.vm.set_user_memory_region(region);
    }
}

/// RAII wrapper for the pmem mmap region. Performs mmap on construction and munmap on drop.
#[derive(Debug)]
pub struct PmemMmap {
    #[cfg(feature = "sproutfs-memory")]
    managed: Option<Arc<crate::managed_memory::Owner>>,
    pub file_len: u64,
    pub mmap_ptr: u64,
    pub mmap_len: u64,
}

impl PmemMmap {
    const ALIGNMENT: u64 = Pmem::ALIGNMENT;

    #[cfg(feature = "sproutfs-memory")]
    pub fn managed_owner(&self) -> Option<&Arc<crate::managed_memory::Owner>> {
        self.managed.as_ref()
    }

    /// The host a managed volume's flushes go to; none for a file-backed one,
    /// which msync makes durable itself.
    fn flush_host(&self) -> Option<Arc<dyn FlushHost>> {
        #[cfg(feature = "sproutfs-memory")]
        if let Some(owner) = &self.managed {
            return Some(owner.clone());
        }
        None
    }

    fn from_config(config: &PmemConfig) -> Result<Self, PmemError> {
        if let Some(managed) = &config.managed {
            if !config.path_on_host.is_empty()
                || managed.length == 0
                || managed.length % Self::ALIGNMENT != 0
            {
                return Err(PmemError::BackingFile(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "managed PMEM requires an aligned nonzero length and no file path",
                )));
            }
            #[cfg(feature = "sproutfs-memory")]
            {
                let len =
                    usize::try_from(managed.length).map_err(|_| PmemError::AllocationFailed)?;
                let owner = crate::managed_memory::Owner::connect(
                    &managed.socket_path,
                    sproutfs_vm_memory::MemoryRegionSpec {
                        kind: sproutfs_vm_memory::MemoryRegionKind::Pmem,
                        len,
                    },
                )
                .map_err(PmemError::BackingFile)?;
                return Ok(Self {
                    mmap_ptr: owner.memory_region().address as u64,
                    file_len: managed.length,
                    mmap_len: managed.length,
                    managed: Some(owner),
                });
            }
            #[cfg(not(feature = "sproutfs-memory"))]
            return Err(PmemError::BackingFile(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "binary lacks managed-memory support",
            )));
        }
        Self::new(&config.path_on_host, config.read_only)
    }

    fn flush(&self) -> std::io::Result<()> {
        #[cfg(feature = "sproutfs-memory")]
        if self.managed.is_some() {
            // A managed volume's flush is the host's to answer, through the
            // device's FlushHost; there is no file here to sync.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a managed volume is flushed by its host",
            ));
        }
        // SAFETY: The mmap remains live for self's lifetime.
        if unsafe {
            libc::msync(
                self.mmap_ptr as *mut libc::c_void,
                u64_to_usize(self.file_len),
                libc::MS_SYNC,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn new(path: &str, read_only: bool) -> Result<Self, PmemError> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)
            .map_err(PmemError::BackingFile)?;
        let file_len = file.metadata().unwrap().len();
        if file_len == 0 {
            return Err(PmemError::BackingFileZeroSize);
        }

        let mut prot = libc::PROT_READ;
        if !read_only {
            prot |= libc::PROT_WRITE;
        }

        let mmap_len = align_up!(file_len, Self::ALIGNMENT);
        let mmap_ptr = if mmap_len == file_len {
            // SAFETY: We are calling the system call with valid arguments and checking the returned
            // value
            unsafe {
                let r = libc::mmap(
                    std::ptr::null_mut(),
                    u64_to_usize(file_len),
                    prot,
                    libc::MAP_SHARED | libc::MAP_NORESERVE,
                    file.as_raw_fd(),
                    0,
                );
                if r == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                r
            }
        } else {
            // SAFETY: We are calling system calls with valid arguments and checking returned
            // values
            //
            // The double mapping is done to ensure the underlying memory has the size of
            // `mmap_len` (wich is 2MB aligned as per `virtio-pmem` specification)
            // First mmap creates a mapping of `mmap_len` while second mmaps the actual
            // file on top. The remaining gap between the end of the mmaped file and
            // the actual end of the memory region is backed by PRIVATE | ANONYMOUS memory.
            unsafe {
                let mmap_ptr = libc::mmap(
                    std::ptr::null_mut(),
                    u64_to_usize(mmap_len),
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if mmap_ptr == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                let r = libc::mmap(
                    mmap_ptr,
                    u64_to_usize(file_len),
                    prot,
                    libc::MAP_SHARED | libc::MAP_NORESERVE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    0,
                );
                if r == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                mmap_ptr
            }
        };
        Ok(Self {
            #[cfg(feature = "sproutfs-memory")]
            managed: None,
            file_len,
            mmap_ptr: mmap_ptr as u64,
            mmap_len,
        })
    }
}

impl Drop for PmemMmap {
    fn drop(&mut self) {
        #[cfg(feature = "sproutfs-memory")]
        if self.managed.is_some() {
            return;
        }
        // SAFETY: `mmap_ptr` is a valid pointer since PmemMmap can only be created via `new()`.
        //         `mmap_len` is the same value used for the original mmap call.
        unsafe {
            _ = libc::munmap(
                self.mmap_ptr as *mut libc::c_void,
                u64_to_usize(self.mmap_len),
            );
        }
    }
}

#[derive(Debug)]
pub struct Pmem {
    // VirtIO fields
    pub avail_features: u64,
    pub acked_features: u64,
    pub activate_event: EventFd,

    // Transport fields
    pub device_state: DeviceState,
    pub queues: Vec<Queue>,
    pub queue_events: Vec<EventFd>,

    // Pmem specific fields
    // kvm_mem_slot must be declared before mmap so that its drop function runs
    // first before the HVA gets unmapped
    pub kvm_mem_slot: KvmMemSlot,
    pub guest_region: GuestPmemRegion,
    pub mmap: PmemMmap,
    pub metrics: Arc<PmemMetrics>,
    pub rate_limiter: RateLimiter,
    pub flushes: Flushes,

    pub config: PmemConfig,
}

impl Pmem {
    // Pmem devices need to have address and size to be
    // a multiple of 2MB
    pub const ALIGNMENT: u64 = 2 * 1024 * 1024;

    /// Create a new Pmem device with a backing file at `disk_image_path` path.
    pub fn new(vm: Arc<KvmVm>, config: PmemConfig) -> Result<Self, PmemError> {
        Self::new_with_queues(vm, config, vec![Queue::new(PMEM_QUEUE_SIZE)], 0u64, None)
    }

    /// Create a new Pmem device with a backing file at `disk_image_path` path using a pre-created
    /// set of queues.
    pub fn new_with_queues(
        vm: Arc<KvmVm>,
        config: PmemConfig,
        queues: Vec<Queue>,
        acked_features: u64,
        config_space: Option<ConfigSpace>,
    ) -> Result<Self, PmemError> {
        let mmap = PmemMmap::from_config(&config)?;
        let guest_region = match config_space {
            Some(cs) => {
                if cs.size != mmap.mmap_len {
                    return Err(PmemError::RestoredSizeMismatch(cs.size, mmap.mmap_len));
                }
                GuestPmemRegion::from_state(vm.clone(), cs)
            }
            None => GuestPmemRegion::new(vm.clone(), mmap.mmap_len)?,
        };

        let cs = &guest_region.config_space;
        let flags = if config.read_only {
            KVM_MEM_READONLY
        } else {
            0
        };
        let kvm_mem_slot = KvmMemSlot::new(vm, cs.start, cs.size, mmap.mmap_ptr, flags)?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiter::from)
            .unwrap_or_default();
        let flushes = Flushes::new(mmap.flush_host())?;

        Ok(Self {
            avail_features: 1u64 << VIRTIO_F_VERSION_1,
            acked_features,
            activate_event: EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?,
            device_state: DeviceState::Inactive,
            queues,
            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?],
            guest_region,
            metrics: PmemMetricsPerDevice::alloc(config.id.clone()),
            rate_limiter,
            flushes,
            config,
            mmap,
            kvm_mem_slot,
        })
    }

    pub fn handle_queue(&mut self) -> Result<(), PmemError> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        if self.queues[0].is_empty() {
            return Ok(());
        }

        // There is only 1 type of request pmem supports, so we can consume
        // rate-limiter before even looking at the queue. This is still valid
        // even if the queue will not have any valid requests since it indicate
        // broken guest driver and rate-limiting should still apply for such case.
        // Rate limit: consume 1 op and file_len bytes for the coalesced msync.
        // If the rate limiter is blocked, defer notification until the timer fires.
        if !self.rate_limiter.consume(1, TokenType::Ops) {
            self.metrics.rate_limiter_throttled_events.inc();
            return Ok(());
        }
        if !self
            .rate_limiter
            .consume(self.mmap.file_len, TokenType::Bytes)
        {
            self.rate_limiter.manual_replenish(1, TokenType::Ops);
            self.metrics.rate_limiter_throttled_events.inc();
            return Ok(());
        }

        let mut cached_result = None;
        // A managed volume's flushes wait for the host, all of this drain's as
        // one request; a file-backed one's are made durable here, by msync.
        let mut flushed = Vec::new();
        while let Some(head) = self.queues[0].pop()? {
            let processed = if self.flushes.hosted() {
                self.status_address(head).map(|status| {
                    flushed.push(PendingFlush {
                        head: head.index,
                        status: status.0,
                    });
                    false
                })
            } else {
                self.process_chain(head, &mut cached_result).map(|()| true)
            };
            let add_result = match processed {
                Ok(false) => continue,
                Ok(true) => self.queues[0].add_used(head.index, 4),
                Err(err) => {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                    self.queues[0].add_used(head.index, 0)
                }
            };
            if let Err(err) = add_result {
                error!("pmem: {err}");
                self.metrics.event_fails.inc();
                break;
            }
        }
        if !flushed.is_empty() {
            self.flushes.send(flushed);
        }

        self.queues[0].advance_used_ring_idx();
        if self.queues[0].prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|err| {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                });
        }
        Ok(())
    }

    fn process_chain(
        &self,
        head: DescriptorChain,
        cached_result: &mut Option<i32>,
    ) -> Result<(), PmemError> {
        let status_address = self.status_address(head)?;
        let active_state = self.device_state.active_state().unwrap();
        let status = if let Some(status) = *cached_result {
            status
        } else {
            let status = if let Err(err) = self.mmap.flush() {
                error!("pmem: Unable to make mapped stores durable: {err}");
                FAILURE
            } else {
                SUCCESS
            };
            *cached_result = Some(status);
            status
        };
        active_state.mem.write_obj(status, status_address)?;
        Ok(())
    }

    fn status_address(&self, head: DescriptorChain) -> Result<GuestAddress, PmemError> {
        let active_state = self.device_state.active_state().unwrap();

        // Virtio spec, section 5.19.6 Driver Operations
        // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-6970006
        if head.is_write_only() {
            return Err(PmemError::WriteOnlyDescriptor);
        }
        if head.len != 4 {
            return Err(PmemError::Non4byteHeadDescriptor(head.len));
        }
        let request: u32 = active_state.mem.read_obj(head.addr)?;
        if request != VIRTIO_PMEM_REQ_TYPE_FLUSH {
            return Err(PmemError::UnknownRequestType(request));
        }

        // Virtio spec, section 5.19.7 Device Operations
        // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-6980007
        let Some(status_descriptor) = head.next_descriptor() else {
            return Err(PmemError::DescriptorChainTooShort);
        };
        if !status_descriptor.is_write_only() {
            return Err(PmemError::ReadOnlyDescriptor);
        }
        if status_descriptor.len != 4 {
            return Err(PmemError::Non4byteStatusDescriptor(status_descriptor.len));
        }

        Ok(status_descriptor.addr)
    }

    /// Updates the parameters for the rate limiter.
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    pub fn process_queue(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_events[0].read() {
            error!("pmem: Failed to get queue event: {err:?}");
            self.metrics.event_fails.inc();
            return;
        }

        if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
            return;
        }

        self.handle_queue().unwrap_or_else(|err| {
            error!("pmem: {err:?}");
            self.metrics.event_fails.inc();
        });
    }

    /// Completes the flushes the host has answered: each gets the host's answer
    /// as its status, and the guest is interrupted once for all of them.
    pub fn process_flush_answers(&mut self) {
        let answered = self.flushes.take_answered();
        if answered.is_empty() {
            return;
        }
        let active_state = self.device_state.active_state().unwrap();
        for (flushes, result) in answered {
            let status = match result {
                Ok(()) => SUCCESS,
                Err(err) => {
                    error!("pmem: The host could not make a flush durable: {err}");
                    self.metrics.event_fails.inc();
                    FAILURE
                }
            };
            for flush in flushes {
                if let Err(err) = active_state
                    .mem
                    .write_obj(status, GuestAddress(flush.status))
                {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                }
                if let Err(err) = self.queues[0].add_used(flush.head, 4) {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                }
            }
        }
        self.queues[0].advance_used_ring_idx();
        if self.queues[0].prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|err| {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                });
        }
    }

    pub fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        if let Err(err) = self.rate_limiter.event_handler() {
            error!("pmem: Failed to get rate-limiter event: {err:?}");
            self.metrics.event_fails.inc();
            return;
        }

        self.handle_queue().unwrap_or_else(|err| {
            error!("pmem: {err:?}");
            self.metrics.event_fails.inc();
        });
    }
}

impl VirtioDevice for Pmem {
    impl_device_type!(VirtioDeviceType::Pmem);

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
            .deref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.guest_region.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.metrics.cfg_fails.inc();
        warn!(
            "virtio-pmem: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        if self.activate_event.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
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
        // The driver that made them is gone, so its flushes complete nothing,
        // and an answer to one arriving later is dropped.
        self.flushes.reset();
        true
    }

    fn kick(&mut self) {
        if self.is_activated() {
            info!("kick pmem {}.", self.config.id);
            // A kick is the resume that runs the guest again, and the host it
            // runs on is asked for the flushes it has never been asked for.
            self.flushes.resend();
            if let Err(err) = self.handle_queue() {
                error!("pmem: Failed to process queue: {err}");
            }
        }
    }

    fn prepare_handoff(&mut self) {
        // The host drops the flushes of a guest that leaves it and never answers
        // them, since an answer would write into memory the destination now
        // owns. They stay pending, and the snapshot being saved carries them to
        // the host the guest is restored on.
        self.flushes.hand_off();
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::Kvm;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};

    #[test]
    fn test_from_config() {
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(KvmVm::new(kvm).unwrap());

        let config = PmemConfig {
            id: "1".into(),
            path_on_host: "not_a_path".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            Pmem::new(vm.clone(), config).unwrap_err(),
            PmemError::BackingFile(_),
        ));

        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path.clone(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            Pmem::new(vm.clone(), config).unwrap_err(),
            PmemError::BackingFileZeroSize,
        ));

        dummy_file.as_file().set_len(0x20_0000).unwrap();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        Pmem::new(vm.clone(), config).unwrap();
    }

    #[test]
    fn test_process_chain() {
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(KvmVm::new(kvm).unwrap());

        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(0x20_0000).unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        let mut pmem = Pmem::new(vm.clone(), config).unwrap();

        let mem = default_mem();
        let interrupt = default_interrupt();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        pmem.queues[0] = vq.create_queue();
        pmem.activate(mem.clone(), interrupt).unwrap();

        // Valid request
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            let mut result = None;
            pmem.process_chain(head, &mut result).unwrap();
            assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2000)).unwrap(), 0);
            assert!(result.is_some());
        }

        // Valid request cached value reuse
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            let mut result = Some(0x69);
            pmem.process_chain(head, &mut result).unwrap();
            assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2000)).unwrap(), 0x69);
        }

        // Invalid request type
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            mem.write_obj::<u32>(0x69, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::UnknownRequestType(0x69),
            ));
        }

        // Short chain request
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, 0, 1);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::DescriptorChainTooShort,
            ));
        }

        // Write only first descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::WriteOnlyDescriptor,
            ));
        }

        // Read only second descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, 0, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::ReadOnlyDescriptor,
            ));
        }

        // Invalid length head descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 0x69, VIRTQ_DESC_F_NEXT, 1);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::Non4byteHeadDescriptor(0x69),
            ));
        }

        // Invalid length status descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 0x69, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::Non4byteStatusDescriptor(0x69),
            ));
        }
    }

    type Answer = Box<dyn FnOnce(std::io::Result<()>) + Send>;

    /// A host that answers nothing until the test says so, as a managed
    /// volume's host answers a flush only once it is durable.
    #[derive(Default)]
    struct HeldHost(Mutex<Vec<Answer>>);

    impl std::fmt::Debug for HeldHost {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HeldHost").finish_non_exhaustive()
        }
    }

    impl FlushHost for HeldHost {
        fn start_flush(&self, flushed: Answer) -> std::io::Result<()> {
            self.0.lock().unwrap().push(flushed);
            Ok(())
        }
    }

    impl HeldHost {
        fn asked(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        /// Answers the oldest request the host holds.
        fn answer(&self, result: std::io::Result<()>) {
            let flushed = self.0.lock().unwrap().remove(0);
            flushed(result);
        }
    }

    const REQUEST: u64 = 0x4000;
    const STATUS: u64 = 0x5000;
    const UNWRITTEN: i32 = 0x69;

    /// A file-backed device whose flushes go to `host`, with one flush request
    /// on its queue, whose chain is descriptors 0 and 1 and whose status the
    /// device has not written yet.
    struct Flushing {
        _backing: TempFile,
        vm: Arc<KvmVm>,
        pmem: Pmem,
    }

    fn flushing(mem: &GuestMemoryMmap, host: Arc<HeldHost>) -> (Flushing, VirtQueue<'_>) {
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(KvmVm::new(kvm).unwrap());
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(0x20_0000).unwrap();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: backing.as_path().to_str().unwrap().to_string(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        let mut pmem = Pmem::new(vm.clone(), config).unwrap();
        pmem.flushes.host = Some(host);
        // A restore checks the queue it is given against the device's own size.
        let vq = VirtQueue::new(GuestAddress(0), mem, PMEM_QUEUE_SIZE);
        pmem.queues[0] = vq.create_queue();
        pmem.activate(mem.clone(), default_interrupt()).unwrap();
        vq.avail.ring[0].set(0);
        vq.dtable[0].set(REQUEST, 4, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable[1].set(STATUS, 4, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj::<u32>(VIRTIO_PMEM_REQ_TYPE_FLUSH, GuestAddress(REQUEST))
            .unwrap();
        mem.write_obj::<i32>(UNWRITTEN, GuestAddress(STATUS))
            .unwrap();
        vq.used.idx.set(0);
        vq.avail.idx.set(1);
        (
            Flushing {
                _backing: backing,
                vm,
                pmem,
            },
            vq,
        )
    }

    fn status(mem: &GuestMemoryMmap) -> i32 {
        mem.read_obj::<i32>(GuestAddress(STATUS)).unwrap()
    }

    // A managed volume's flush waits for its host: the device takes it off the
    // queue and asks, and completes it — status, used ring and interrupt — only
    // once the answer is in, on its own thread and not while it waits.
    #[test]
    fn a_managed_flush_completes_when_its_host_answers() {
        let host = Arc::new(HeldHost::default());
        let mem = default_mem();
        let (mut f, vq) = flushing(&mem, host.clone());
        f.pmem.handle_queue().unwrap();
        assert_eq!(host.asked(), 1);
        assert_eq!(
            vq.used.idx.get(),
            0,
            "the flush completed before its host answered"
        );
        assert_eq!(status(&mem), UNWRITTEN);
        f.pmem.process_flush_answers();
        assert_eq!(
            vq.used.idx.get(),
            0,
            "the flush completed with no answer in"
        );

        host.answer(Ok(()));
        f.pmem.process_flush_answers();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(status(&mem), SUCCESS);
        assert_eq!(f.pmem.flushes.pending(), []);
    }

    // A session that ends answers every flush still waiting with EPIPE, and the
    // guest reads that as a failed flush rather than waiting forever.
    #[test]
    fn a_lost_host_fails_the_flush() {
        let host = Arc::new(HeldHost::default());
        let mem = default_mem();
        let (mut f, vq) = flushing(&mem, host.clone());
        f.pmem.handle_queue().unwrap();
        host.answer(Err(std::io::Error::from_raw_os_error(libc::EPIPE)));
        f.pmem.process_flush_answers();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(status(&mem), FAILURE);
    }

    // A snapshot taken while a flush waits carries it, and the device restored
    // from it asks its own host for it when the guest resumes — the host the
    // snapshot was taken on may never answer — and completes it on that answer.
    #[test]
    fn a_pending_flush_survives_a_snapshot() {
        use crate::devices::virtio::pmem::persist::PmemConstructorArgs;
        use crate::snapshot::Persist;

        let before = Arc::new(HeldHost::default());
        let mem = default_mem();
        let (mut f, vq) = flushing(&mem, before.clone());
        f.pmem.handle_queue().unwrap();
        f.pmem.prepare_handoff();
        let state = f.pmem.save();
        assert_eq!(
            state.pending_flushes,
            [PendingFlush {
                head: 0,
                status: STATUS
            }]
        );
        let Flushing { _backing, vm, pmem } = f;
        drop(pmem);

        let after = Arc::new(HeldHost::default());
        let mut restored = Pmem::restore(
            PmemConstructorArgs {
                mem: &mem,
                vm: vm.clone(),
            },
            &state,
        )
        .unwrap();
        restored.flushes.host = Some(after.clone());
        restored.activate(mem.clone(), default_interrupt()).unwrap();
        assert_eq!(
            after.asked(),
            0,
            "the flush was asked before the guest resumed"
        );
        restored.kick();
        assert_eq!(after.asked(), 1, "the restored device did not ask its host");
        assert_eq!(vq.used.idx.get(), 0);

        after.answer(Ok(()));
        restored.process_flush_answers();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(status(&mem), SUCCESS);
    }

    // The host a guest leaves never answers its flushes, and an answer that
    // arrives anyway — a session ending with EPIPE — completes nothing: those
    // flushes are the destination's. A guest that stays after all, because the
    // handoff was abandoned and the guest resumed here, asks again.
    #[test]
    fn a_handoff_gives_its_flushes_to_the_next_resume() {
        let host = Arc::new(HeldHost::default());
        let mem = default_mem();
        let (mut f, vq) = flushing(&mem, host.clone());
        f.pmem.handle_queue().unwrap();
        f.pmem.prepare_handoff();
        host.answer(Err(std::io::Error::from_raw_os_error(libc::EPIPE)));
        f.pmem.process_flush_answers();
        assert_eq!(vq.used.idx.get(), 0, "a handed-off flush was completed");
        assert_eq!(status(&mem), UNWRITTEN);

        f.pmem.kick();
        assert_eq!(host.asked(), 1);
        host.answer(Ok(()));
        f.pmem.process_flush_answers();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(status(&mem), SUCCESS);
    }
}
