// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent device's worker: a thread that takes the requests off the queue and sends them to
//! the store's daemon, several at once: the device applies requests in any order but across
//! barriers (doc-4), so a guest's `MAP` doesn't wait for the writes and durable commits queued
//! before it. fxdax: each is served as a future, which the thread receiving the daemon's reply
//! goes on with, completing the request (`fxdax::extentd::spawn_on_replies`): no thread is woken
//! between the reply and the guest's interrupt, nor waits for the store's I/O (TASK-41).

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use fxdax::{Commit, Errno, RemoteExtentStore};
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemory, GuestMemoryError};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use super::{
    CommitArgs, ExtentIdLe, Info, IoArgs, MAX_ROOT, MAX_TRANSFER, MapArgs, MapEntry, RequestHeader,
    Response, RootLen, UnmapArgs, VIRTIO_EXTENT_COMMIT_DURABLE, VIRTIO_EXTENT_COMMIT_ROOT,
    VIRTIO_EXTENT_MAP_AHEAD, VIRTIO_EXTENT_MAP_MANY, VIRTIO_EXTENT_MAP_WRITE, VIRTIO_EXTENT_T_COMMIT, VIRTIO_EXTENT_T_FREE, VIRTIO_EXTENT_T_INFO,
    VIRTIO_EXTENT_T_MAP, VIRTIO_EXTENT_T_READ, VIRTIO_EXTENT_T_ROOT, VIRTIO_EXTENT_T_UNMAP,
    VIRTIO_EXTENT_T_WRITE, write_barriers,
};
use super::{
    Epoch, INFO_LEN_WITHOUT_BRANCH, ResizedArgs, Resizing, VIRTIO_EXTENT_FREE_MANY,
    VIRTIO_EXTENT_FREEZE_FROZEN, VIRTIO_EXTENT_RESIZED_TOOK, VIRTIO_EXTENT_T_ADVANCE,
    VIRTIO_EXTENT_T_FREEZE, VIRTIO_EXTENT_T_LAST, VIRTIO_EXTENT_T_LET_GO, VIRTIO_EXTENT_T_PIN,
    VIRTIO_EXTENT_T_RESIZED, VIRTIO_EXTENT_T_UNPIN,
};
use crate::devices::virtio::queue::{DescriptorChain, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{error, info};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

/// The requests served, and the time serving them took, by type, logged as the worker stops:
/// against what the guest waits for a request (its driver's request_ns), what the transport
/// costs.
#[derive(Default)]
struct Served {
    count: [AtomicU64; VIRTIO_EXTENT_T_LAST as usize + 1],
    nanos: [AtomicU64; VIRTIO_EXTENT_T_LAST as usize + 1],
}

impl Served {
    fn add(&self, type_: Option<u32>, nanos: u64) {
        if let Some(type_) = type_.filter(|t| *t <= VIRTIO_EXTENT_T_LAST) {
            self.count[type_ as usize].fetch_add(1, Ordering::Relaxed);
            self.nanos[type_ as usize].fetch_add(nanos, Ordering::Relaxed);
        }
    }

    fn log(&self) {
        for type_ in 0..=VIRTIO_EXTENT_T_LAST as usize {
            let count = self.count[type_].load(Ordering::Relaxed);
            if count > 0 {
                #[allow(clippy::cast_precision_loss)]
                let mean = self.nanos[type_].load(Ordering::Relaxed) as f64 / count as f64;
                info!(
                    "extent device: served {count} requests of type {type_}, {:.1} us each",
                    mean / 1000.0
                );
            }
        }
    }
}

/// What the worker shares with the requests it serves.
struct Shared {
    queue: Mutex<Queue>,
    /// The queue's index among the device's.
    index: u16,
    interrupt: Arc<dyn VirtioInterrupt>,
    mem: GuestMemoryMmap,
    store: Arc<RemoteExtentStore>,
    resizing: Arc<Resizing>,
    /// Whether the guest's filesystem is frozen (`VIRTIO_EXTENT_T_FREEZE`).
    frozen: Arc<AtomicBool>,
    served: Served,
    /// The requests taken off the queue and not yet returned to the driver.
    serving: Mutex<usize>,
    /// Notified as the last of them is returned.
    idle: Condvar,
}

impl Shared {
    /// The type of the request `chain` holds, from its header.
    fn request_type(&self, chain: &DescriptorChain) -> Option<u32> {
        use vm_memory::Bytes;
        self.mem.read_obj::<u32>(chain.addr).ok().map(u32::from_le)
    }

    /// Serves the request in `chain`, and returns it to the driver, on this thread until it
    /// waits for the daemon, and then on the thread receiving the daemon's reply.
    fn serve(self: &Arc<Self>, chain: DescriptorChain) {
        *self.serving.lock().expect("Poisoned lock") += 1;
        let shared = self.clone();
        let (index, type_) = (chain.index, self.request_type(&chain));
        let start = Instant::now();
        // Its descriptors read now, the future holds its buffers alone.
        let buffers = Buffers::new(&self.mem, chain);
        fxdax::extentd::spawn_on_replies(async move {
            let len = match buffers {
                Ok(buffers) => {
                    handle(&shared.store, &shared.resizing, &shared.frozen, buffers).await
                }
                Err(err) => {
                    error!("extent device: {err}");
                    0
                }
            };
            #[allow(clippy::cast_possible_truncation)]
            shared.served.add(type_, start.elapsed().as_nanos() as u64);
            shared.complete(index, len);
            let mut serving = shared.serving.lock().expect("Poisoned lock");
            *serving -= 1;
            if *serving == 0 {
                shared.idle.notify_all();
            }
        });
    }

    /// Waits until the requests taken off the queue are returned to the driver.
    fn wait_idle(&self) {
        let serving = self.serving.lock().expect("Poisoned lock");
        drop(
            self.idle
                .wait_while(serving, |serving| *serving > 0)
                .expect("Poisoned lock"),
        );
    }

    /// Returns the request at `index` to the driver, with `len` bytes written to it.
    fn complete(&self, index: u16, len: u32) {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        if let Err(err) = queue.add_used(index, len) {
            error!("extent worker: adding a used element: {err}");
            return;
        }
        queue.advance_used_ring_idx();
        if queue.prepare_kick()
            && let Err(err) = self
                .interrupt
                .trigger(VirtioInterruptType::Queue(self.index))
        {
            error!("extent worker: signalling the queue: {err}");
        }
    }
}

/// The worker's thread, once spawned, which stops when told to.
#[derive(Debug)]
pub(super) struct Worker {
    /// Returns the queue, as the worker left it.
    thread: fxdax::thread::Thread<Queue>,
    stop: EventFd,
}

impl Worker {
    /// Spawns the worker for `queue`, the device's queue `index`, which the driver notifies
    /// through `queue_event`, serving the requests with `store`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        queue: Queue,
        index: u16,
        queue_event: EventFd,
        interrupt: Arc<dyn VirtioInterrupt>,
        mem: GuestMemoryMmap,
        store: Arc<RemoteExtentStore>,
        resizing: Arc<Resizing>,
        frozen: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let stop = EventFd::new(libc::EFD_NONBLOCK)?;
        let stop_theirs = stop.try_clone()?;
        let shared = Arc::new(Shared {
            queue: Mutex::new(queue),
            index,
            interrupt,
            mem,
            store,
            resizing,
            frozen,
            served: Served::default(),
            serving: Mutex::new(0),
            idle: Condvar::new(),
        });
        // fxdax: from the extent threads' spawner, under the VMM's seccomp filter, rather than
        // the vCPU's that activates the device (TASK-50.1).
        let thread = fxdax::thread::spawn(format!("fc_extent_q{index}"), move || {
            work(&shared, &queue_event, &stop_theirs)
        })?;
        Ok(Self { thread, stop })
    }

    /// Stops the worker once the requests it took are served, and returns the queue, as it left
    /// it: none if it panicked.
    pub(super) fn stop(self) -> Option<Queue> {
        if let Err(err) = self.stop.write(1) {
            error!("extent device: stopping the worker: {err}");
        }
        let stopped = self.thread.join();
        if stopped.is_err() {
            error!("extent device: the worker panicked");
        }
        stopped.ok()
    }
}

/// Serves the queue until `stop` is written, then waits for the requests it took to be returned
/// to the driver, and returns the queue as they left it.
fn work(shared: &Arc<Shared>, queue_event: &EventFd, stop: &EventFd) -> Queue {
    take_requests(shared, queue_event, stop);
    shared.wait_idle();
    shared.served.log();
    shared.queue.lock().expect("Poisoned lock").clone()
}

/// Takes the requests off the queue as the driver notifies `queue_event`, and serves them, until
/// `stop` is written.
fn take_requests(shared: &Arc<Shared>, queue_event: &EventFd, stop: &EventFd) {
    let epoll = match Epoll::new() {
        Ok(epoll) => epoll,
        Err(err) => {
            error!("extent worker: epoll: {err}");
            return;
        }
    };
    let queue_fd = queue_event.as_raw_fd();
    let stop_fd = stop.as_raw_fd();
    for fd in [queue_fd, stop_fd] {
        #[allow(clippy::cast_sign_loss)]
        let event = EpollEvent::new(EventSet::IN, fd as u64);
        if let Err(err) = epoll.ctl(ControlOperation::Add, fd, event) {
            error!("extent worker: epoll: {err}");
            return;
        }
    }
    let mut events = [EpollEvent::default(); 2];
    loop {
        let count = match epoll.wait(-1, &mut events) {
            Ok(count) => count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                error!("extent worker: epoll: {err}");
                return;
            }
        };
        for event in &events[..count] {
            let fd = event.fd();
            if fd == stop_fd {
                let _ = stop.read();
                return;
            }
            if fd != queue_fd {
                continue;
            }
            let _ = queue_event.read();
            let mut taken = Vec::new();
            {
                let mut queue = shared.queue.lock().expect("Poisoned lock");
                // fxdax: with EVENT_IDX, the driver notifies again only once the queue is taken
                // empty, which this rechecks after asking to be notified.
                loop {
                    match queue.pop_or_enable_notification() {
                        Ok(Some(chain)) => taken.push(chain),
                        Ok(None) => break,
                        Err(err) => {
                            error!("extent worker: {err}");
                            break;
                        }
                    }
                }
            }
            for chain in taken {
                shared.serve(chain);
            }
        }
    }
}

/// A part of a request's buffers in host memory: guest memory the descriptor names.
#[derive(Clone, Copy)]
struct Segment {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: Guest memory, mapped while the device is active, and so while the requests the worker
// took are served (`work`); each request's buffers are its future's alone.
unsafe impl Send for Segment {}
unsafe impl Sync for Segment {}

/// Why a descriptor chain is no request's buffers.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum BuffersError {
    /// a descriptor chain is not guest memory: {0}
    Memory(#[from] GuestMemoryError),
    /// a descriptor chain gives the device {0} bytes to write, more than its used length holds
    TooLong(u64),
}

/// A request's buffers: those the driver wrote, and those it gave the device to write, whose last
/// bytes are the response.
pub(super) struct Buffers {
    readable: Vec<Segment>,
    writable: Vec<Segment>,
}

impl Buffers {
    /// The buffers of the request in `chain`, all in `mem`. The writable ones are marked dirty,
    /// as the device writes them whole. fxdax TASK-79.25: refused if they take more bytes than the
    /// used ring's length holds, a u32, as a chain of descriptors naming the same memory again
    /// may: the device writes them whole, and says how much it wrote there.
    pub(super) fn new(mem: &GuestMemoryMmap, chain: DescriptorChain) -> Result<Self, BuffersError> {
        let mut buffers = Self {
            readable: Vec::new(),
            writable: Vec::new(),
        };
        let mut writable = 0u64;
        for descriptor in chain {
            if descriptor.is_write_only() {
                writable += u64::from(descriptor.len);
                if writable > u64::from(u32::MAX) {
                    return Err(BuffersError::TooLong(writable));
                }
            }
            let len = descriptor.len as usize;
            let slice = mem.get_slice(descriptor.addr, len)?;
            let segment = Segment {
                ptr: slice.ptr_guard_mut().as_ptr(),
                len,
            };
            if descriptor.is_write_only() {
                slice.bitmap().mark_dirty(0, len);
                buffers.writable.push(segment);
            } else {
                buffers.readable.push(segment);
            }
        }
        Ok(buffers)
    }

    fn writable_len(&self) -> usize {
        self.writable.iter().map(|segment| segment.len).sum()
    }
}

/// The `len` bytes at `offset` in `segments`, as parts of the segments, if they are there.
fn range(segments: &[Segment], mut offset: usize, mut len: usize) -> Option<Vec<Segment>> {
    let mut parts = Vec::new();
    for segment in segments {
        if len == 0 {
            break;
        }
        if offset >= segment.len {
            offset -= segment.len;
            continue;
        }
        let part = (segment.len - offset).min(len);
        // SAFETY: Within the segment.
        let ptr = unsafe { segment.ptr.add(offset) };
        parts.push(Segment { ptr, len: part });
        offset = 0;
        len -= part;
    }
    (len == 0).then_some(parts)
}

/// Reads what the driver wrote, in order.
struct Reader<'a> {
    segments: &'a [Segment],
    offset: usize,
}

impl Reader<'_> {
    /// The next `len` bytes, as the store copies them out of guest memory.
    fn slices(&mut self, len: usize) -> Result<Vec<fxdax::VolatileSlice<'_>>, Errno> {
        let parts = range(self.segments, self.offset, len).ok_or(Errno::EINVAL)?;
        self.offset += len;
        Ok(parts
            .iter()
            // SAFETY: Guest memory the request names, which outlives it, and which the guest may
            // change as it is copied.
            .map(|part| unsafe { fxdax::VolatileSlice::from_raw_parts(part.ptr, part.len) })
            .collect())
    }

    /// The next `len` bytes, copied.
    fn bytes(&mut self, len: usize) -> Result<Vec<u8>, Errno> {
        let mut bytes = vec![0; len];
        let mut at = 0;
        for slice in self.slices(len)? {
            at += slice.copy_to(&mut bytes[at..]);
        }
        Ok(bytes)
    }

    /// How many bytes are left to read.
    fn available(&self) -> usize {
        let len: usize = self.segments.iter().map(|segment| segment.len).sum();
        len.saturating_sub(self.offset)
    }

    /// The next object, copied.
    fn obj<T: ByteValued + Default>(&mut self) -> Result<T, Errno> {
        let mut obj = T::default();
        let bytes = self.bytes(size_of::<T>())?;
        obj.as_mut_slice().copy_from_slice(&bytes);
        Ok(obj)
    }
}

/// Writes what the device returns into the writable buffers, from their start.
struct Writer<'a> {
    segments: &'a [Segment],
}

impl Writer<'_> {
    /// `len` bytes at `offset`, as the store copies into guest memory.
    fn slices(&self, offset: usize, len: usize) -> Option<Vec<fxdax::VolatileSliceMut<'_>>> {
        Some(
            range(self.segments, offset, len)?
                .iter()
                // SAFETY: Guest memory the request gives the device to write, which outlives it,
                // and which the guest may access as it is copied.
                .map(|part| unsafe { fxdax::VolatileSliceMut::from_raw_parts(part.ptr, part.len) })
                .collect(),
        )
    }

    /// Writes `bytes` at `offset`, which must be within the buffers.
    fn write(&self, offset: usize, bytes: &[u8]) {
        let mut at = 0;
        for mut slice in self
            .slices(offset, bytes.len())
            .expect("a write past the request's buffers")
        {
            at += slice.copy_from(&bytes[at..]);
        }
    }

    /// Zeroes `len` bytes at `offset`, which must be within the buffers.
    fn zero(&self, offset: usize, len: usize) {
        for part in range(self.segments, offset, len).expect("zeroing past the request's buffers") {
            // SAFETY: Guest memory the request gives the device to write.
            unsafe { std::ptr::write_bytes(part.ptr, 0, part.len) };
        }
    }
}

/// Serves the request whose buffers are `buffers` ([`Buffers::new`]) with `store`, and returns the
/// length of what the device writes to it: its writable buffers, whose last bytes hold the
/// response.
pub(super) async fn handle(
    store: &RemoteExtentStore,
    resizing: &Resizing,
    frozen: &AtomicBool,
    buffers: Buffers,
) -> u32 {
    // The response is the chain's last bytes, after what the request returns.
    let writable = buffers.writable_len();
    let Some(room) = writable.checked_sub(size_of::<Response>()) else {
        error!("extent device: a request has no room for its response");
        return 0;
    };
    let mut reader = Reader {
        segments: &buffers.readable,
        offset: 0,
    };
    let writer = Writer {
        segments: &buffers.writable,
    };
    let (status, written) = match serve(store, resizing, frozen, &mut reader, &writer, room).await {
        Ok(written) => (0, written),
        Err(errno) => (errno.raw().cast_unsigned(), 0),
    };
    // What the request didn't return reads as zeros, as drivers read the buffers whole.
    writer.zero(written, room - written);
    let response = Response {
        status: status.to_le(),
        reserved: 0,
    };
    writer.write(room, response.as_slice());
    u32::try_from(writable).expect("a request's buffers' writable length fits in u32 (Buffers::new)")
}

/// Serves the request `reader` holds, writing what it returns with `writer`, which has `room`
/// bytes for it, and returns how many it wrote.
async fn serve(
    store: &RemoteExtentStore,
    resizing: &Resizing,
    frozen: &AtomicBool,
    reader: &mut Reader<'_>,
    writer: &Writer<'_>,
    room: usize,
) -> Result<usize, Errno> {
    let header: RequestHeader = reader.obj()?;
    let flags = u32::from_le(header.flags);
    match u32::from_le(header.type_) {
        VIRTIO_EXTENT_T_READ => {
            let args: IoArgs = reader.obj()?;
            let len = u32::from_le(args.len);
            if len > MAX_TRANSFER || room < len as usize {
                return Err(Errno::EINVAL);
            }
            let mut slices = writer.slices(0, len as usize).ok_or(Errno::EINVAL)?;
            store
                .read_async(args.id.into(), u64::from_le(args.offset), &mut slices)
                .await?;
            Ok(len as usize)
        }
        VIRTIO_EXTENT_T_WRITE => {
            let args: IoArgs = reader.obj()?;
            let len = u32::from_le(args.len);
            if len > MAX_TRANSFER {
                return Err(Errno::EINVAL);
            }
            let data = reader.slices(len as usize)?;
            // A barrier before orders, without waiting for durability (doc-4); one after, with
            // WRITE_COMMIT, waits as a COMMIT does. One round trip to the daemon either way.
            let barriers = write_barriers(flags).ok_or(Errno::EINVAL)?;
            store
                .write_with_barriers_async(
                    args.id.into(),
                    u64::from_le(args.offset),
                    &data,
                    barriers,
                )
                .await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_FREE => {
            if flags & !VIRTIO_EXTENT_FREE_MANY != 0 {
                return Err(Errno::EINVAL);
            }
            let id: ExtentIdLe = reader.obj()?;
            let mut extents = vec![id.into()];
            // fxdax: the rest of a flush's dead extents, each freed as it would be alone, in one
            // request of the daemon's, not one each (TASK-92.13): the first error fails the
            // request, the extents before it freed (`F_FREE_MANY`).
            if flags & VIRTIO_EXTENT_FREE_MANY != 0 {
                while reader.available() > 0 {
                    let id: ExtentIdLe = reader.obj()?;
                    extents.push(id.into());
                }
            }
            store.free_many_async(&extents).await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_MAP => {
            let args: MapArgs = reader.obj()?;
            let map_flags = VIRTIO_EXTENT_MAP_WRITE | VIRTIO_EXTENT_MAP_AHEAD;
            if flags & !(map_flags | VIRTIO_EXTENT_MAP_MANY) != 0 {
                return Err(Errno::EINVAL);
            }
            let mut maps = vec![(args, flags & map_flags)];
            // fxdax: the rest of a chunk's pieces (`F_MAP_MANY`), each with its own flags.
            if flags & VIRTIO_EXTENT_MAP_MANY != 0 {
                while reader.available() > 0 {
                    let entry: MapEntry = reader.obj()?;
                    let flags = u32::from_le(entry.flags);
                    if flags & !map_flags != 0 {
                        return Err(Errno::EINVAL);
                    }
                    maps.push((entry.map, flags));
                }
            }
            // Sent to the daemon at once, each as it would be alone: the first error fails the
            // request, whichever others it mapped (`F_MAP_MANY`). fxdax: what the guest reads
            // next (`F_MAP_AHEAD`) is then mapped for it, as the window maps writable pages
            // already (TASK-112.1).
            futures::future::try_join_all(maps.iter().map(|(args, flags)| async move {
                let (window_offset, len) =
                    (u64::from_le(args.window_offset), u64::from_le(args.len));
                let writable = flags & VIRTIO_EXTENT_MAP_WRITE != 0;
                store
                    .map_async(
                        args.id.into(),
                        u64::from_le(args.offset),
                        len,
                        window_offset,
                        writable,
                    )
                    .await?;
                if !writable && flags & VIRTIO_EXTENT_MAP_AHEAD != 0 {
                    store.prefault(window_offset, len);
                }
                Ok::<_, Errno>(())
            }))
            .await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_UNMAP => {
            let args: UnmapArgs = reader.obj()?;
            store
                .unmap_async(u64::from_le(args.window_offset), u64::from_le(args.len))
                .await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_COMMIT => {
            let args: CommitArgs = reader.obj()?;
            let mut root = None;
            if flags & VIRTIO_EXTENT_COMMIT_ROOT != 0 {
                let len = u32::from_le(args.root_len);
                if len > MAX_ROOT {
                    return Err(Errno::EINVAL);
                }
                root = Some(reader.bytes(len as usize)?);
            }
            // Without COMMIT_DURABLE, the commit completes once ordered: the daemon makes it
            // durable soon after (doc-4).
            let commit = if flags & VIRTIO_EXTENT_COMMIT_DURABLE != 0 {
                Commit::Durable
            } else {
                Commit::Ordered
            };
            store.commit_async(root.as_deref(), commit).await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_ROOT => {
            let returned = MAX_ROOT as usize + size_of::<RootLen>();
            let root = store.root_async().await?;
            if room < returned || root.len() > MAX_ROOT as usize {
                return Err(Errno::EINVAL);
            }
            writer.write(0, &root);
            writer.zero(root.len(), MAX_ROOT as usize - root.len());
            let len = RootLen {
                len: u32::try_from(root.len())
                    .expect("the root is short")
                    .to_le(),
                reserved: 0,
            };
            writer.write(MAX_ROOT as usize, len.as_slice());
            Ok(returned)
        }
        VIRTIO_EXTENT_T_INFO => {
            // A driver without VIRTIO_EXTENT_F_FREEZE has no room for the branch.
            if room < INFO_LEN_WITHOUT_BRANCH {
                return Err(Errno::EINVAL);
            }
            let info = store.info_async().await?;
            let info = Info {
                capacity: info.capacity.to_le(),
                used: info.used.to_le(),
                available: info.available.to_le(),
                next_sequence: info.next_sequence.to_le(),
                sequence_floor: info.sequence_floor.to_le(),
                branch: store.branch().to_le(),
            };
            let len = room.min(size_of::<Info>());
            writer.write(0, &info.as_slice()[..len]);
            Ok(len)
        }
        VIRTIO_EXTENT_T_FREEZE => {
            frozen.store(flags & VIRTIO_EXTENT_FREEZE_FROZEN != 0, Ordering::Release);
            Ok(0)
        }
        VIRTIO_EXTENT_T_RESIZED => {
            let args: ResizedArgs = reader.obj()?;
            let capacity = u64::from_le(args.capacity);
            let took = flags & VIRTIO_EXTENT_RESIZED_TOOK != 0;
            resizing.answered(capacity, took);
            store.resized_async(capacity, took).await?;
            Ok(0)
        }
        // fxdax: a follower's (doc-4's F_READ_ONLY); a writer's store refuses them (EINVAL).
        VIRTIO_EXTENT_T_ADVANCE => {
            if room < size_of::<Epoch>() {
                return Err(Errno::EINVAL);
            }
            let epoch = Epoch {
                epoch: store.advance_async().await?.to_le(),
                reserved: 0,
            };
            writer.write(0, epoch.as_slice());
            Ok(size_of::<Epoch>())
        }
        VIRTIO_EXTENT_T_LET_GO => {
            let epoch: Epoch = reader.obj()?;
            store.let_go_async(u64::from_le(epoch.epoch)).await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_PIN => {
            let id: ExtentIdLe = reader.obj()?;
            store.pin_async(id.into()).await?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_UNPIN => {
            let id: ExtentIdLe = reader.obj()?;
            store.unpin_async(id.into()).await?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;
    use std::thread;

    use fxdax::ExtentStore;

    use super::super::{
        VIRTIO_EXTENT_WRITE_BARRIER, VIRTIO_EXTENT_WRITE_COMMIT, VIRTIO_EXTENT_WRITE_DURABLE,
    };
    use super::*;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::VirtQueue;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Bytes, GuestAddress};

    const BLOCK: usize = ExtentStore::BLOCK_SIZE as usize;
    const RESPONSE: usize = size_of::<Response>();
    /// Where the request's buffers are in guest memory.
    const READABLE: GuestAddress = GuestAddress(0x10_0000);
    const WRITABLE: GuestAddress = GuestAddress(0x80_0000);

    /// A directory of the test's, removed once dropped.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "fc-extent-device-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A store of 1 MiB, which an extent daemon of the test's serves: a host's, which keeps its
    /// stores' branches in the bucket FXDAX_EXTENTD_REMOTE names (memory:///NAME, in tests), as
    /// of placement FXDAX_EXTENTD_TOKEN (1), which the tests' environment sets.
    fn store() -> (RemoteExtentStore, TestDir) {
        store_of(1 << 20)
    }

    /// A store of `capacity` bytes, as [`store`] makes one.
    fn store_of(capacity: u64) -> (RemoteExtentStore, TestDir) {
        let dir = TestDir::new();
        let socket = dir.0.join("extentd.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        thread::spawn(move || fxdax::extentd::serve(listener));
        let store = RemoteExtentStore::connect(&socket, dir.0.join("store"), capacity).unwrap();
        (store, dir)
    }

    /// fxdax: held by the tests whose daemons free extents, one at a time: the daemons' metrics
    /// are the process's, which a test counting the FREE requests they served then counts its own
    /// alone in ([`frees_served`]).
    static FREEING: Mutex<()> = Mutex::new(());

    /// fxdax: the requests freeing extents the daemons of this process have served (their
    /// metrics): their FREEs, of one, and FREE_MANYs, of many, a request of its own, which a daemon
    /// without it refuses (fxdax TASK-92.13).
    fn frees_served() -> u64 {
        let metrics = fxdax::extentd::metrics::render();
        let served = |kind: &str| -> u64 {
            let name = format!("fxdax_extentd_requests_total{{kind=\"{kind}\"}} ");
            let line = (metrics.lines()).find_map(|line| line.strip_prefix(&name));
            let line = line.unwrap_or_else(|| panic!("no {kind} requests counted in {metrics}"));
            line.parse().unwrap()
        };
        served("free") + served("free_many")
    }

    /// The bytes of a request's header and arguments, followed by `data`.
    fn bytes<T: ByteValued>(type_: u32, flags: u32, args: Option<T>, data: &[u8]) -> Vec<u8> {
        let header = RequestHeader {
            type_,
            flags,
            unique: 7,
        };
        let mut bytes = header.as_slice().to_vec();
        if let Some(args) = &args {
            bytes.extend_from_slice(args.as_slice());
        }
        bytes.extend_from_slice(data);
        bytes
    }

    /// Serves a request of `readable` bytes, with `writable` bytes for the device to write, the
    /// response included, split into descriptors of at most `split` bytes, and returns what the
    /// device wrote, the response apart, and the response's status.
    fn request_split(
        store: &RemoteExtentStore,
        readable: &[u8],
        writable: usize,
        split: usize,
    ) -> (Vec<u8>, u32) {
        let mem = single_region_mem(16 << 20);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let mut queue = vq.create_queue();
        mem.write_slice(readable, READABLE).unwrap();
        mem.write_slice(&vec![0xa5; writable], WRITABLE).unwrap();
        let mut descriptors = Vec::new();
        for (len, flags, base) in [
            (readable.len(), 0, READABLE),
            (writable, VIRTQ_DESC_F_WRITE, WRITABLE),
        ] {
            let mut at = 0;
            while at < len {
                let part = split.min(len - at);
                descriptors.push((base.0 + at as u64, part as u32, flags));
                at += part;
            }
        }
        for (i, (addr, len, flags)) in descriptors.iter().enumerate() {
            let last = i + 1 == descriptors.len();
            let flags = if last {
                *flags
            } else {
                flags | VIRTQ_DESC_F_NEXT
            };
            vq.dtable[i].set(*addr, *len, flags, (i + 1) as u16);
        }
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        let chain = queue.pop().unwrap().unwrap();
        let buffers = Buffers::new(&mem, chain).unwrap();
        let used = futures::executor::block_on(handle(
            store,
            &Resizing::default(),
            &AtomicBool::new(false),
            buffers,
        )) as usize;
        assert_eq!(
            used, writable,
            "the device wrote {used} of {writable} bytes"
        );
        let mut written = vec![0; writable];
        mem.read_slice(&mut written, WRITABLE).unwrap();
        let response_at = written.len() - RESPONSE;
        let response = *Response::from_slice(&written[response_at..]).unwrap();
        written.truncate(response_at);
        (written, response.status)
    }

    fn request(store: &RemoteExtentStore, readable: &[u8], writable: usize) -> (Vec<u8>, u32) {
        request_split(store, readable, writable, usize::MAX)
    }

    /// fxdax TASK-79.25: a chain whose descriptors give the device more bytes to write than a
    /// u32 holds, naming the same memory again and again, is refused, not served: its used
    /// length couldn't say what the device wrote, which aborted the VMM.
    #[test]
    fn chains_writing_past_u32_are_refused() {
        const LEN: u32 = 0x6000_0000;
        let mem = single_region_mem(LEN as usize);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let mut queue = vq.create_queue();
        for i in 0..3 {
            let next = if i < 2 { VIRTQ_DESC_F_NEXT } else { 0 };
            vq.dtable[i].set(0, LEN, VIRTQ_DESC_F_WRITE | next, (i + 1) as u16);
        }
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        let chain = queue.pop().unwrap().unwrap();
        let buffers = Buffers::new(&mem, chain);
        assert!(
            matches!(buffers, Err(BuffersError::TooLong(0x1_2000_0000))),
            "{:?}",
            buffers.map(|buffers| buffers.writable_len())
        );
    }

    fn io(store: &RemoteExtentStore, sequence: u64, offset: u64, len: usize) -> IoArgs {
        IoArgs {
            id: ExtentIdLe {
                branch: store.branch(),
                sequence,
            },
            offset,
            len: len as u32,
            reserved: 0,
        }
    }

    fn errno(errno: Errno) -> u32 {
        errno.raw().cast_unsigned()
    }

    #[test]
    fn test_writes_and_reads() {
        let _freeing = FREEING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (store, _dir) = store();
        let data: Vec<u8> = (0..2 * BLOCK).map(|i| i as u8).collect();
        let write = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 1, 0, data.len())),
            &data,
        );
        assert_eq!(request(&store, &write, RESPONSE), (vec![], 0));
        let read = bytes(
            VIRTIO_EXTENT_T_READ,
            0,
            Some(io(&store, 1, 0, data.len())),
            &[],
        );
        assert_eq!(
            request(&store, &read, data.len() + RESPONSE),
            (data.clone(), 0)
        );
        // Across descriptors of odd sizes, whose writes and reads the device splits and joins.
        assert_eq!(
            request_split(&store, &read, data.len() + RESPONSE, 1000),
            (data.clone(), 0)
        );
        let rewrite = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 2, 0, data.len())),
            &data,
        );
        assert_eq!(request_split(&store, &rewrite, RESPONSE, 777), (vec![], 0));
        let read2 = bytes(
            VIRTIO_EXTENT_T_READ,
            0,
            Some(io(&store, 2, 0, data.len())),
            &[],
        );
        assert_eq!(
            request(&store, &read2, data.len() + RESPONSE),
            (data.clone(), 0)
        );

        // An extent the store doesn't hold, and a write after a commit sealed the extent.
        let missing = bytes(VIRTIO_EXTENT_T_READ, 0, Some(io(&store, 3, 0, BLOCK)), &[]);
        assert_eq!(
            request(&store, &missing, BLOCK + RESPONSE),
            (vec![0; BLOCK], errno(Errno::ENOENT))
        );
        let commit = bytes(
            VIRTIO_EXTENT_T_COMMIT,
            VIRTIO_EXTENT_COMMIT_DURABLE,
            Some(CommitArgs::default()),
            &[],
        );
        assert_eq!(request(&store, &commit, RESPONSE), (vec![], 0));
        let sealed = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 1, 0, BLOCK)),
            &data[..BLOCK],
        );
        assert_eq!(request(&store, &sealed, RESPONSE).1, errno(Errno::EPERM));
        // A barrier commits what came before it.
        let barrier = bytes(
            VIRTIO_EXTENT_T_WRITE,
            VIRTIO_EXTENT_WRITE_BARRIER,
            Some(io(&store, 4, 0, BLOCK)),
            &data[..BLOCK],
        );
        assert_eq!(request(&store, &barrier, RESPONSE).1, 0);
        // A commit after a write seals what it wrote, in one request: and only a WRITE's flags
        // are a WRITE's.
        let committed = bytes(
            VIRTIO_EXTENT_T_WRITE,
            VIRTIO_EXTENT_WRITE_COMMIT | VIRTIO_EXTENT_WRITE_DURABLE,
            Some(io(&store, 5, 0, BLOCK)),
            &data[..BLOCK],
        );
        assert_eq!(request(&store, &committed, RESPONSE).1, 0);
        let after = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 5, BLOCK as u64, BLOCK)),
            &data[..BLOCK],
        );
        assert_eq!(request(&store, &after, RESPONSE).1, errno(Errno::EPERM));
        let unknown = bytes(
            VIRTIO_EXTENT_T_WRITE,
            VIRTIO_EXTENT_WRITE_DURABLE,
            Some(io(&store, 6, 0, BLOCK)),
            &data[..BLOCK],
        );
        assert_eq!(request(&store, &unknown, RESPONSE).1, errno(Errno::EINVAL));

        let free = bytes(
            VIRTIO_EXTENT_T_FREE,
            0,
            Some(ExtentIdLe {
                branch: store.branch(),
                sequence: 1,
            }),
            &[],
        );
        assert_eq!(request(&store, &free, RESPONSE), (vec![], 0));
        assert_eq!(
            request(&store, &read, data.len() + RESPONSE).1,
            errno(Errno::ENOENT)
        );
    }

    /// fxdax: a FREE with FREE_MANY, of a flush's dead extents, as many as the guest's Fxfs names
    /// in one (257), frees them in one request of the daemon's, not one each, each a round trip
    /// to it (TASK-92.13).
    #[test]
    fn test_frees_many_in_one_request() {
        const EXTENTS: u64 = 257;
        let _freeing = FREEING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (store, _dir) = store_of(4 << 20);
        let data = vec![7; BLOCK];
        let ids: Vec<ExtentIdLe> = (1..=EXTENTS)
            .map(|sequence| {
                let id = fxdax::ExtentId {
                    branch: store.branch(),
                    sequence,
                };
                store
                    .write(id, 0, &[fxdax::VolatileSlice::from(&data[..])])
                    .unwrap();
                ExtentIdLe {
                    branch: store.branch(),
                    sequence,
                }
            })
            .collect();
        store.commit(None).unwrap();
        let rest: Vec<u8> = ids[1..]
            .iter()
            .flat_map(|id| id.as_slice().to_vec())
            .collect();
        let free = bytes(
            VIRTIO_EXTENT_T_FREE,
            VIRTIO_EXTENT_FREE_MANY,
            Some(ids[0]),
            &rest,
        );
        let before = frees_served();
        let start = Instant::now();
        assert_eq!(request(&store, &free, RESPONSE), (vec![], 0));
        let took = start.elapsed();
        let served = frees_served() - before;
        println!("{EXTENTS} extents freed in {took:?}, in {served} of the daemon's requests");
        assert_eq!(served, 1);
        for sequence in [1, EXTENTS / 2, EXTENTS] {
            let read = bytes(
                VIRTIO_EXTENT_T_READ,
                0,
                Some(io(&store, sequence, 0, BLOCK)),
                &[],
            );
            assert_eq!(
                request(&store, &read, BLOCK + RESPONSE).1,
                errno(Errno::ENOENT),
                "extent {sequence} is still there"
            );
        }
    }

    #[test]
    fn test_roots_and_info() {
        let (store, _dir) = store();
        let root = bytes::<RootLen>(VIRTIO_EXTENT_T_ROOT, 0, None, &[]);
        let root_len = MAX_ROOT as usize + size_of::<RootLen>();
        let (written, status) = request(&store, &root, root_len + RESPONSE);
        assert_eq!(status, 0);
        assert_eq!(
            RootLen::from_slice(&written[MAX_ROOT as usize..])
                .unwrap()
                .len,
            0
        );

        let commit = bytes(
            VIRTIO_EXTENT_T_COMMIT,
            VIRTIO_EXTENT_COMMIT_ROOT,
            Some(CommitArgs {
                root_len: 5,
                reserved: 0,
            }),
            b"first",
        );
        assert_eq!(request(&store, &commit, RESPONSE), (vec![], 0));
        let (written, status) = request(&store, &root, root_len + RESPONSE);
        assert_eq!(status, 0);
        assert_eq!(&written[..5], b"first");
        assert!(written[5..MAX_ROOT as usize].iter().all(|b| *b == 0));
        assert_eq!(
            RootLen::from_slice(&written[MAX_ROOT as usize..])
                .unwrap()
                .len,
            5
        );

        let info = bytes::<Info>(VIRTIO_EXTENT_T_INFO, 0, None, &[]);
        let (written, status) = request(&store, &info, size_of::<Info>() + RESPONSE);
        assert_eq!(status, 0);
        assert_eq!(
            *Info::from_slice(&written).unwrap(),
            Info {
                capacity: 1 << 20,
                used: 0,
                available: 1 << 20,
                next_sequence: 0,
                // The store's branch is kept in the daemon's bucket: its writer mints from its
                // range, its first lease's (fxdax's doc-7, Fencing).
                sequence_floor: 1 << 40,
                branch: store.branch(),
            }
        );
        // A driver without VIRTIO_EXTENT_F_FREEZE has room for what comes before the branch.
        let (written, status) = request(&store, &info, INFO_LEN_WITHOUT_BRANCH + RESPONSE);
        assert_eq!(status, 0);
        assert_eq!(written.len(), INFO_LEN_WITHOUT_BRANCH);
    }

    /// fxdax: a follower's device reads its writer's store as of its view's commit, advances to
    /// the writer's latest, lets go of the commits before and pins extents; what the writer wrote
    /// since it reads as ENOENT, and what would write, it refuses (EROFS). A writer's device
    /// refuses a follower's requests (EINVAL).
    #[test]
    fn test_follows_a_writer() {
        let (store, dir) = store();
        let follower =
            RemoteExtentStore::connect_read_only(dir.0.join("extentd.sock"), dir.0.join("store"))
                .unwrap();
        let (heard, commits) = mpsc::channel();
        follower.on_committed(move |epoch| {
            // Unheard once the test stops listening.
            let _ = heard.send(epoch);
        });
        let data = vec![7; BLOCK];
        store
            .write(
                fxdax::ExtentId {
                    branch: store.branch(),
                    sequence: 1,
                },
                0,
                &[fxdax::VolatileSlice::from(&data[..])],
            )
            .unwrap();
        store.commit(None).unwrap();
        let epoch = commits.recv().unwrap();
        let read = bytes(VIRTIO_EXTENT_T_READ, 0, Some(io(&store, 1, 0, BLOCK)), &[]);
        assert_eq!(
            request(&follower, &read, BLOCK + RESPONSE),
            (vec![0; BLOCK], errno(Errno::ENOENT))
        );
        let advance = bytes::<Epoch>(VIRTIO_EXTENT_T_ADVANCE, 0, None, &[]);
        let (written, status) = request(&follower, &advance, size_of::<Epoch>() + RESPONSE);
        assert_eq!(status, 0);
        assert_eq!(
            *Epoch::from_slice(&written).unwrap(),
            Epoch { epoch, reserved: 0 }
        );
        assert_eq!(
            request(&follower, &read, BLOCK + RESPONSE),
            (data.clone(), 0)
        );
        let let_go = bytes(
            VIRTIO_EXTENT_T_LET_GO,
            0,
            Some(Epoch { epoch, reserved: 0 }),
            &[],
        );
        assert_eq!(request(&follower, &let_go, RESPONSE), (vec![], 0));
        let id = ExtentIdLe {
            branch: store.branch(),
            sequence: 1,
        };
        for type_ in [VIRTIO_EXTENT_T_PIN, VIRTIO_EXTENT_T_UNPIN] {
            let pin = bytes(type_, 0, Some(id), &[]);
            assert_eq!(request(&follower, &pin, RESPONSE), (vec![], 0));
            assert_eq!(request(&store, &pin, RESPONSE).1, errno(Errno::EINVAL));
        }
        let write = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 2, 0, BLOCK)),
            &data,
        );
        assert_eq!(request(&follower, &write, RESPONSE).1, errno(Errno::EROFS));
        let commit = bytes(VIRTIO_EXTENT_T_COMMIT, 0, Some(CommitArgs::default()), &[]);
        assert_eq!(request(&follower, &commit, RESPONSE).1, errno(Errno::EROFS));
        assert_eq!(
            request(&store, &advance, size_of::<Epoch>() + RESPONSE).1,
            errno(Errno::EINVAL)
        );
    }

    #[test]
    fn test_refuses_bad_requests() {
        let (store, _dir) = store();
        let unknown = bytes::<Info>(99, 0, None, &[]);
        assert_eq!(request(&store, &unknown, RESPONSE).1, errno(Errno::EINVAL));
        // A read with less room than it reads, and one whose header is short.
        let read = bytes(
            VIRTIO_EXTENT_T_READ,
            0,
            Some(io(&store, 1, 0, 2 * BLOCK)),
            &[],
        );
        assert_eq!(
            request(&store, &read, BLOCK + RESPONSE),
            (vec![0; BLOCK], errno(Errno::EINVAL))
        );
        assert_eq!(request(&store, &[0; 4], RESPONSE).1, errno(Errno::EINVAL));
        // A write whose data is shorter than it says.
        let short = bytes(
            VIRTIO_EXTENT_T_WRITE,
            0,
            Some(io(&store, 1, 0, BLOCK)),
            &[1; 100],
        );
        assert_eq!(request(&store, &short, RESPONSE).1, errno(Errno::EINVAL));
        // Without a DAX window, writable or not, one map or many; and a MAP flag the device
        // doesn't know, of the request or of one of its maps (`F_MAP_MANY`).
        let entries = |flags: &[u32]| -> Vec<u8> {
            (flags.iter())
                .flat_map(|flags| {
                    let entry = MapEntry {
                        flags: flags.to_le(),
                        ..MapEntry::default()
                    };
                    entry.as_slice().to_vec()
                })
                .collect()
        };
        let many = entries(&[VIRTIO_EXTENT_MAP_WRITE, VIRTIO_EXTENT_MAP_AHEAD, 0]);
        for flags in [0, VIRTIO_EXTENT_MAP_WRITE, VIRTIO_EXTENT_MAP_AHEAD] {
            let map = bytes(VIRTIO_EXTENT_T_MAP, flags, Some(MapArgs::default()), &[]);
            assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::ENOSYS));
            let map = bytes(
                VIRTIO_EXTENT_T_MAP,
                flags | VIRTIO_EXTENT_MAP_MANY,
                Some(MapArgs::default()),
                &many,
            );
            assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::ENOSYS));
        }
        let map = bytes(VIRTIO_EXTENT_T_MAP, 1 << 3, Some(MapArgs::default()), &[]);
        assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::EINVAL));
        let map = bytes(
            VIRTIO_EXTENT_T_MAP,
            VIRTIO_EXTENT_MAP_MANY,
            Some(MapArgs::default()),
            &entries(&[1 << 1]),
        );
        assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::EINVAL));
    }
}
