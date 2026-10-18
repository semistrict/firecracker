// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent device's worker: a thread that takes the requests off the queue, and threads that
//! serve them, blocking on the store's I/O, several at once: the device applies requests in any
//! order but across barriers (doc-4), so a guest's `MAP` doesn't wait for the writes and durable
//! commits queued before it.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

use fxdax::{Errno, RemoteExtentStore};
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemory, GuestMemoryError};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use super::{
    CommitArgs, ExtentIdLe, Info, IoArgs, MAX_ROOT, MAX_TRANSFER, MapArgs, RequestHeader, Response,
    RootLen, UnmapArgs, VIRTIO_EXTENT_COMMIT_DURABLE, VIRTIO_EXTENT_COMMIT_ROOT,
    VIRTIO_EXTENT_MAP_WRITE, VIRTIO_EXTENT_T_COMMIT, VIRTIO_EXTENT_T_FREE, VIRTIO_EXTENT_T_INFO,
    VIRTIO_EXTENT_T_MAP, VIRTIO_EXTENT_T_READ, VIRTIO_EXTENT_T_ROOT, VIRTIO_EXTENT_T_UNMAP,
    VIRTIO_EXTENT_T_WRITE, write_barriers,
};
use super::{
    Epoch, INFO_LEN_WITHOUT_BRANCH, ResizedArgs, Resizing, VIRTIO_EXTENT_FREEZE_FROZEN,
    VIRTIO_EXTENT_RESIZED_TOOK, VIRTIO_EXTENT_T_ADVANCE, VIRTIO_EXTENT_T_FREEZE,
    VIRTIO_EXTENT_T_LAST, VIRTIO_EXTENT_T_LET_GO, VIRTIO_EXTENT_T_PIN, VIRTIO_EXTENT_T_RESIZED,
    VIRTIO_EXTENT_T_UNPIN,
};
use crate::devices::virtio::queue::{DescriptorChain, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{error, info};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

/// How many requests the worker serves at once: as many as the daemon does for a connection.
const SERVERS: usize = 8;

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

/// What the worker shares with the threads serving requests.
struct Shared {
    queue: Mutex<Queue>,
    interrupt: Arc<dyn VirtioInterrupt>,
    mem: GuestMemoryMmap,
    store: Arc<RemoteExtentStore>,
    resizing: Arc<Resizing>,
    /// Whether the guest's filesystem is frozen (`VIRTIO_EXTENT_T_FREEZE`).
    frozen: Arc<AtomicBool>,
    served: Served,
}

impl Shared {
    /// The type of the request `chain` holds, from its header.
    fn request_type(&self, chain: &DescriptorChain) -> Option<u32> {
        use vm_memory::Bytes;
        self.mem.read_obj::<u32>(chain.addr).ok().map(u32::from_le)
    }

    /// Serves the request in `chain` and returns it to the driver.
    fn serve_one(&self, chain: DescriptorChain) {
        let index = chain.index;
        let type_ = self.request_type(&chain);
        let start = Instant::now();
        let len = handle(&self.store, &self.resizing, &self.frozen, &self.mem, chain);
        #[allow(clippy::cast_possible_truncation)]
        self.served.add(type_, start.elapsed().as_nanos() as u64);
        self.complete(index, len);
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
            && let Err(err) = self.interrupt.trigger(VirtioInterruptType::Queue(0))
        {
            error!("extent worker: signalling the queue: {err}");
        }
    }
}

/// Whether a request of `type_` is quick to serve: the thread taking it off the queue serves it
/// itself when it is alone, rather than handing it to a server, a thread's wake-up more.
fn quick(type_: Option<u32>) -> bool {
    matches!(
        type_,
        Some(
            VIRTIO_EXTENT_T_MAP
                | VIRTIO_EXTENT_T_UNMAP
                | VIRTIO_EXTENT_T_FREE
                | VIRTIO_EXTENT_T_ROOT
                | VIRTIO_EXTENT_T_INFO
                | VIRTIO_EXTENT_T_ADVANCE
                | VIRTIO_EXTENT_T_LET_GO
                | VIRTIO_EXTENT_T_PIN
                | VIRTIO_EXTENT_T_UNPIN
        )
    )
}

/// The worker's thread, once spawned, which stops when told to.
#[derive(Debug)]
pub(super) struct Worker {
    /// Returns the queue, as the worker left it.
    thread: thread::JoinHandle<Queue>,
    stop: EventFd,
}

impl Worker {
    /// Spawns the worker for `queue`, which the driver notifies through `queue_event`, serving
    /// the requests with `store`.
    pub(super) fn spawn(
        queue: Queue,
        queue_event: EventFd,
        interrupt: Arc<dyn VirtioInterrupt>,
        mem: GuestMemoryMmap,
        store: Arc<RemoteExtentStore>,
        resizing: Arc<Resizing>,
        frozen: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let stop = EventFd::new(libc::EFD_NONBLOCK)?;
        let stop_theirs = stop.try_clone()?;
        let shared = Shared {
            queue: Mutex::new(queue),
            interrupt,
            mem,
            store,
            resizing,
            frozen,
            served: Served::default(),
        };
        let thread = thread::Builder::new()
            .name("fc_extent".into())
            .spawn(move || work(shared, queue_event, stop_theirs))?;
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

/// A request taken off the queue, which a server serves.
struct Request(DescriptorChain);

// SAFETY: The chain reads its descriptors from the queue's table in guest memory, which stays
// mapped while the device is active, and so while the worker, which the device stops before it
// goes, runs. Each chain is served by one server at a time.
unsafe impl Send for Request {}

fn work(shared: Shared, queue_event: EventFd, stop: EventFd) -> Queue {
    let (requests, received) = mpsc::channel::<Request>();
    let received = Mutex::new(received);
    thread::scope(|scope| {
        for server in 0..SERVERS {
            let (shared, received) = (&shared, &received);
            let spawned = thread::Builder::new()
                .name(format!("fc_extent_{server}"))
                .spawn_scoped(scope, move || {
                    loop {
                        let chain = received.lock().expect("Poisoned lock").recv();
                        let Ok(Request(chain)) = chain else {
                            return;
                        };
                        shared.serve_one(chain);
                    }
                });
            if let Err(err) = spawned {
                error!("extent worker: spawning a server: {err}");
            }
        }
        // Once stopped, the servers finish what they took and return as the channel closes.
        take_requests(&shared, &queue_event, &stop, requests);
    });
    shared.served.log();
    shared.queue.into_inner().expect("Poisoned lock")
}

/// Takes the requests off the queue as the driver notifies `queue_event`, and sends them to
/// `requests`, until `stop` is written: but serves one quick request alone itself.
fn take_requests(
    shared: &Shared,
    queue_event: &EventFd,
    stop: &EventFd,
    requests: mpsc::Sender<Request>,
) {
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
                loop {
                    match queue.pop() {
                        Ok(Some(chain)) => taken.push(chain),
                        Ok(None) => break,
                        Err(err) => {
                            error!("extent worker: {err}");
                            break;
                        }
                    }
                }
            }
            if taken.len() == 1 && quick(shared.request_type(&taken[0])) {
                shared.serve_one(taken[0]);
                continue;
            }
            for chain in taken {
                // The servers outlive this sender.
                requests
                    .send(Request(chain))
                    .expect("the extent servers stopped");
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

/// A request's buffers: those the driver wrote, and those it gave the device to write, whose last
/// bytes are the response.
struct Buffers {
    readable: Vec<Segment>,
    writable: Vec<Segment>,
}

impl Buffers {
    /// The buffers of the request in `chain`, all in `mem`. The writable ones are marked dirty,
    /// as the device writes them whole.
    fn new(mem: &GuestMemoryMmap, chain: DescriptorChain) -> Result<Self, GuestMemoryError> {
        let mut buffers = Self {
            readable: Vec::new(),
            writable: Vec::new(),
        };
        for descriptor in chain {
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

/// Serves the request in `chain` with `store`, and returns the length of what the device writes
/// to it: its writable buffers, whose last bytes hold the response.
pub(super) fn handle(
    store: &RemoteExtentStore,
    resizing: &Resizing,
    frozen: &AtomicBool,
    mem: &GuestMemoryMmap,
    chain: DescriptorChain,
) -> u32 {
    let buffers = match Buffers::new(mem, chain) {
        Ok(buffers) => buffers,
        Err(err) => {
            error!("extent device: a descriptor chain is not guest memory: {err}");
            return 0;
        }
    };
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
    let (status, written) = match serve(store, resizing, frozen, &mut reader, &writer, room) {
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
    u32::try_from(writable).expect("a descriptor chain's length fits in u32")
}

/// Serves the request `reader` holds, writing what it returns with `writer`, which has `room`
/// bytes for it, and returns how many it wrote.
fn serve(
    store: &RemoteExtentStore,
    resizing: &Resizing,
    frozen: &AtomicBool,
    reader: &mut Reader,
    writer: &Writer,
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
            store.read(args.id.into(), u64::from_le(args.offset), &mut slices)?;
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
            store.write_with_barriers(
                args.id.into(),
                u64::from_le(args.offset),
                &data,
                barriers,
            )?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_FREE => {
            let id: ExtentIdLe = reader.obj()?;
            store.free(id.into())?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_MAP => {
            let args: MapArgs = reader.obj()?;
            if flags & !VIRTIO_EXTENT_MAP_WRITE != 0 {
                return Err(Errno::EINVAL);
            }
            store.map(
                args.id.into(),
                u64::from_le(args.offset),
                u64::from_le(args.len),
                u64::from_le(args.window_offset),
                flags & VIRTIO_EXTENT_MAP_WRITE != 0,
            )?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_UNMAP => {
            let args: UnmapArgs = reader.obj()?;
            store.unmap(u64::from_le(args.window_offset), u64::from_le(args.len))?;
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
            if flags & VIRTIO_EXTENT_COMMIT_DURABLE != 0 {
                store.commit(root.as_deref())?;
            } else {
                store.commit_ordered(root.as_deref())?;
            }
            Ok(0)
        }
        VIRTIO_EXTENT_T_ROOT => {
            let returned = MAX_ROOT as usize + size_of::<RootLen>();
            let root = store.root()?;
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
            let info = store.info()?;
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
            store.resized(capacity, took)?;
            Ok(0)
        }
        // fxdax: a follower's (doc-4's F_READ_ONLY); a writer's store refuses them (EINVAL).
        VIRTIO_EXTENT_T_ADVANCE => {
            if room < size_of::<Epoch>() {
                return Err(Errno::EINVAL);
            }
            let epoch = Epoch {
                epoch: store.advance()?.to_le(),
                reserved: 0,
            };
            writer.write(0, epoch.as_slice());
            Ok(size_of::<Epoch>())
        }
        VIRTIO_EXTENT_T_LET_GO => {
            let epoch: Epoch = reader.obj()?;
            store.let_go(u64::from_le(epoch.epoch))?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_PIN => {
            let id: ExtentIdLe = reader.obj()?;
            store.pin(id.into())?;
            Ok(0)
        }
        VIRTIO_EXTENT_T_UNPIN => {
            let id: ExtentIdLe = reader.obj()?;
            store.unpin(id.into())?;
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
        let dir = TestDir::new();
        let socket = dir.0.join("extentd.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        thread::spawn(move || fxdax::extentd::serve(listener));
        let store = RemoteExtentStore::connect(&socket, dir.0.join("store"), 1 << 20).unwrap();
        (store, dir)
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
        let used = handle(
            store,
            &Resizing::default(),
            &AtomicBool::new(false),
            &mem,
            chain,
        ) as usize;
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
        // Without a DAX window, writable or not; and a MAP flag the device doesn't know.
        for flags in [0, VIRTIO_EXTENT_MAP_WRITE] {
            let map = bytes(VIRTIO_EXTENT_T_MAP, flags, Some(MapArgs::default()), &[]);
            assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::ENOSYS));
        }
        let map = bytes(VIRTIO_EXTENT_T_MAP, 1 << 1, Some(MapArgs::default()), &[]);
        assert_eq!(request(&store, &map, RESPONSE).1, errno(Errno::EINVAL));
    }
}
