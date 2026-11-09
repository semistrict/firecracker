// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The virtio extent-store device: fxdax's backlog doc-4, which specifies it.
//!
//! A guest that runs Fxfs itself stores its filesystem through this device, as extents its Fxfs
//! names: immutable pieces of data, written once and sealed by the next commit, freed whole, and
//! a root naming where the filesystem starts. fxdax's extent daemon, which the device connects
//! to, keeps them in an fxdax extent store on local disk, and maps sealed extents into the
//! device's DAX window, its shared memory region 0, from its cache of their pages, which the
//! host's VMs share.

pub mod device;
pub mod persist;
mod window;
mod worker;

pub use self::device::{Extent, ExtentError};
#[cfg(target_arch = "x86_64")]
pub use self::window::KvmPrefault;
pub use self::window::{DaxWindowError, PrefaultGuestMemory, dax_window_at};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::vstate::memory::ByteValued;

/// fxdax: the device's protocol version, the configuration's first field (TASK-141.3): a change to
/// any of its requests, flags, features, configuration or what they mean makes a new one, which
/// the driver refuses a device of another of at probe, naming both, as AGENTS.md's rule, no
/// migrations, has every format refuse another. Its features are not a negotiation: they say
/// what the device is configured as (a follower, a window), and a driver takes every one offered,
/// or its activation is refused. Where it is, the configuration's first four bytes, no version
/// moves. Its driver's is `VIRTIO_EXTENT_VERSION` (guest/linux/include/linux/virtio_extent.h).
pub const VIRTIO_EXTENT_VERSION: u32 = 1;

/// Shared memory region 0 is a DAX window, and `MAP`/`UNMAP` work. fxdax: the window maps sealed
/// extents and zeros alone, read-only (backlog doc-13): a `MAP` of an open extent fails `EPERM`. A
/// writer's copies on write: a store to a page of it gives the device a private page holding what
/// the page held, mapped writable at the same address, until a `MAP` or `UNMAP` over it; past the
/// configuration's `private_max` private pages a store is refused, and the VM stops. `MAP_ZEROS`
/// maps zeros, and `PRIVATE` makes pages private ahead of stores. A follower's (`READ_ONLY`) maps
/// no zeros, and refuses every store. Bit 1, writable DAX's, is not reused.
pub const VIRTIO_EXTENT_F_DAX: u32 = 0;
/// `WRITE` takes `WRITE_COMMIT`: a commit follows the write, in one request.
pub const VIRTIO_EXTENT_F_WRITE_COMMIT: u32 = 2;
/// fxdax: the configuration holds the store's capacity, which the host changes while the guest
/// runs, telling it with a configuration change; a shrink the guest is asked to take it answers
/// (`VIRTIO_EXTENT_T_RESIZED`).
pub const VIRTIO_EXTENT_F_RESIZE: u32 = 3;
/// fxdax: `VIRTIO_EXTENT_T_FREEZE` tells the device the guest's filesystem is frozen, or thawed: a
/// snapshot of the VM is taken frozen, and a VM restored from it, with a store of its own, learns
/// its branch, which `INFO` says, as its filesystem thaws (TASK-39.1).
pub const VIRTIO_EXTENT_F_FREEZE: u32 = 4;
/// fxdax: the device follows a store another VM writes, read-only (backlog doc-8): `ADVANCE`,
/// `LET_GO`, `PIN` and `UNPIN` work, and the configuration's `committed` changes as the writer
/// commits, telling the guest with a configuration change (TASK-42.3).
pub const VIRTIO_EXTENT_F_READ_ONLY: u32 = 5;
/// fxdax: `FREE` frees, with `FREE_MANY`, the extents its data names too, after the one its
/// arguments do: a flush's dead extents in one request rather than one each (TASK-41).
pub const VIRTIO_EXTENT_F_FREE_MANY: u32 = 6;
/// fxdax: `MAP` maps, with `MAP_MANY`, the maps its data holds too, each a `MapEntry`, after the
/// one its arguments say: the pieces of a file's chunk in one request rather than one each
/// (TASK-91.4).
pub const VIRTIO_EXTENT_F_MAP_MANY: u32 = 7;
/// fxdax: `MAP` takes `MAP_AHEAD`, as each of its further maps does: the guest accesses the pages
/// next, as it maps them to read, and the device maps them for it ahead of its accesses, as it does
/// writable ones, rather than the hypervisor one fault at a time (TASK-112.1).
pub const VIRTIO_EXTENT_F_MAP_AHEAD: u32 = 8;
// fxdax: bits 9 and 10, writable DAX's asks to seal and stage 1's copy on write beside it, are
// not reused (backlog doc-13).
/// fxdax: the host asks the guest for its stats, the configuration's `stats_asked` changing, and
/// telling it with a configuration change; the guest answers with `STATS`, its stats as text: what
/// the extent daemon's snapshots report (TASK-111.4).
pub const VIRTIO_EXTENT_F_STATS: u32 = 11;

pub const VIRTIO_EXTENT_T_READ: u32 = 1;
pub const VIRTIO_EXTENT_T_WRITE: u32 = 2;
pub const VIRTIO_EXTENT_T_FREE: u32 = 3;
pub const VIRTIO_EXTENT_T_MAP: u32 = 4;
pub const VIRTIO_EXTENT_T_UNMAP: u32 = 5;
pub const VIRTIO_EXTENT_T_COMMIT: u32 = 6;
pub const VIRTIO_EXTENT_T_ROOT: u32 = 7;
pub const VIRTIO_EXTENT_T_INFO: u32 = 8;
/// fxdax: the guest's answer to a shrink it was asked to take (`ConfigSpace::asked`): whether it
/// took it, `VIRTIO_EXTENT_RESIZED_TOOK`.
pub const VIRTIO_EXTENT_T_RESIZED: u32 = 9;
pub const VIRTIO_EXTENT_RESIZED_TOOK: u32 = 1 << 0;
/// fxdax: the guest's filesystem is frozen, with `VIRTIO_EXTENT_FREEZE_FROZEN`, nothing open and
/// nothing written until it thaws; or thawed, without.
pub const VIRTIO_EXTENT_T_FREEZE: u32 = 10;
pub const VIRTIO_EXTENT_FREEZE_FROZEN: u32 = 1 << 0;
/// fxdax (`VIRTIO_EXTENT_F_READ_ONLY`): moves the follower's view to its writer's latest commit,
/// holding what the commits between held until `LET_GO`, and writes its epoch (`Epoch`).
pub const VIRTIO_EXTENT_T_ADVANCE: u32 = 11;
/// fxdax: lets go of what the follower's view held of the commits before the one an `Epoch`
/// names, which an `ADVANCE` wrote: served after the next `ADVANCE`, it lets go of no more.
pub const VIRTIO_EXTENT_T_LET_GO: u32 = 12;
/// fxdax: keeps an extent the view holds, whatever commit it advances to, until `UNPIN`.
pub const VIRTIO_EXTENT_T_PIN: u32 = 13;
pub const VIRTIO_EXTENT_T_UNPIN: u32 = 14;
// fxdax: 15 was the guest's answer to an ask to seal, writable DAX's, not reused.
/// fxdax (`VIRTIO_EXTENT_F_DAX`, a writer's): makes the window's `len` bytes at `window_offset`
/// private now, as stores would, mapped for the guest ahead of its accesses: `ENOMEM`, none made
/// private, past `private_max`; `EINVAL` where nothing is mapped, or of a follower's window
/// (`UnmapArgs` are its arguments).
pub const VIRTIO_EXTENT_T_PRIVATE: u32 = 16;
/// fxdax (`VIRTIO_EXTENT_F_STATS`): the guest's answer to the ask its `StatsArgs` name, and those
/// before it: its stats, the request's data, UTF-8 text of `RemoteExtentStore::MAX_STATS` bytes at
/// most (`EINVAL` past it), lines of a name and a value (TASK-111.4).
pub const VIRTIO_EXTENT_T_STATS: u32 = 17;
/// The last request type.
pub const VIRTIO_EXTENT_T_LAST: u32 = VIRTIO_EXTENT_T_STATS;

/// A `WRITE`'s flags: a barrier precedes it, as if a `COMMIT` did; a `COMMIT` follows it (with
/// `WRITE_COMMIT`); that commit completes once durable; fxdax: that commit sets the root, which
/// follows the data, of `IoArgs::root_len` bytes.
pub const VIRTIO_EXTENT_WRITE_BARRIER: u32 = 1 << 0;
pub const VIRTIO_EXTENT_WRITE_COMMIT: u32 = 1 << 1;
pub const VIRTIO_EXTENT_WRITE_DURABLE: u32 = 1 << 2;
pub const VIRTIO_EXTENT_WRITE_ROOT: u32 = 1 << 3;

/// The barriers a `WRITE`'s `flags` order it with, unless they are not a `WRITE`'s; the root that
/// `WRITE_ROOT` sets the caller reads, after the data.
pub fn write_barriers(flags: u32) -> Option<fxdax::WriteBarriers<'static>> {
    let known = VIRTIO_EXTENT_WRITE_BARRIER
        | VIRTIO_EXTENT_WRITE_COMMIT
        | VIRTIO_EXTENT_WRITE_DURABLE
        | VIRTIO_EXTENT_WRITE_ROOT;
    let commit = flags & VIRTIO_EXTENT_WRITE_COMMIT != 0;
    if flags & !known != 0
        || (flags & (VIRTIO_EXTENT_WRITE_DURABLE | VIRTIO_EXTENT_WRITE_ROOT) != 0 && !commit)
    {
        return None;
    }
    let after = (flags & VIRTIO_EXTENT_WRITE_COMMIT != 0).then_some(
        if flags & VIRTIO_EXTENT_WRITE_DURABLE != 0 {
            fxdax::Commit::Durable
        } else {
            fxdax::Commit::Ordered
        },
    );
    Some(fxdax::WriteBarriers {
        before: flags & VIRTIO_EXTENT_WRITE_BARRIER != 0,
        after,
        root: None,
    })
}
/// fxdax: a `FREE`'s flags: its data names more extents to free, each a `virtio_extent_id`
/// (`F_FREE_MANY`), of `MAX_MANY_DATA` bytes at most.
pub const VIRTIO_EXTENT_FREE_MANY: u32 = 1 << 0;

/// A `COMMIT`'s flags: it completes once durable; it sets the root.
pub const VIRTIO_EXTENT_COMMIT_DURABLE: u32 = 1 << 0;
pub const VIRTIO_EXTENT_COMMIT_ROOT: u32 = 1 << 1;
/// A `MAP`'s flags, fxdax: its data holds more maps (`F_MAP_MANY`), of `MAX_MANY_DATA` bytes at
/// most; and the guest accesses the
/// pages next (`F_MAP_AHEAD`); and zeros, its extent and offset ignored, of a writer's window, as
/// each of a `MAP_MANY`'s maps may be. Every map is read-only: bit 0, writable DAX's `MAP_WRITE`,
/// is not reused.
pub const VIRTIO_EXTENT_MAP_MANY: u32 = 1 << 1;
pub const VIRTIO_EXTENT_MAP_AHEAD: u32 = 1 << 2;
pub const VIRTIO_EXTENT_MAP_ZEROS: u32 = 1 << 3;

/// The device's queues, and their size: request queues, interchangeable, which a driver may use one
/// per CPU of (fxdax TASK-26.18.5).
pub const EXTENT_NUM_QUEUES: usize = 4;
pub const EXTENT_QUEUE_SIZE: u16 = 256;

/// The ID of the DAX window's shared memory region.
const DAX_WINDOW_SHM_ID: u8 = 0;

/// The most bytes one `READ` or `WRITE` moves.
const MAX_TRANSFER: u32 = 8 << 20;
/// The most bytes the root holds.
const MAX_ROOT: u32 = 4096;
/// The most bytes one extent holds.
const MAX_EXTENT: u64 = fxdax::ExtentStore::MAX_EXTENT;
/// fxdax: the most bytes of data a `FREE_MANY` or a `MAP_MANY` carries, its further extents or
/// maps: a page of the largest a guest's kernel has, as its drivers send a page's worth at most;
/// past it, the request is refused (`EINVAL`). The device lists what the data names in its own
/// memory, and a chain's descriptors, naming the same guest memory again and again, can name far
/// more than the guest has: unbounded, one request grew the VMM by what they named.
const MAX_MANY_DATA: usize = 64 << 10;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ExtentIdLe {
    pub branch: u64,
    pub sequence: u64,
}

/// Every request's header.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct RequestHeader {
    pub type_: u32,
    pub flags: u32,
    /// The driver's own, for tracing.
    pub unique: u64,
}

/// Every request's response, the last bytes the device writes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Response {
    /// 0, or an errno.
    pub status: u32,
    pub reserved: u32,
}

/// `READ`'s and `WRITE`'s arguments.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct IoArgs {
    pub id: ExtentIdLe,
    pub offset: u64,
    pub len: u32,
    /// fxdax: a `WRITE`'s with `WRITE_ROOT`: the root's bytes, after the data.
    pub root_len: u32,
}

/// `MAP`'s arguments.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct MapArgs {
    pub id: ExtentIdLe,
    pub offset: u64,
    pub len: u64,
    pub window_offset: u64,
}

/// fxdax: one of a `MAP_MANY`'s further maps, its flags `MAP_AHEAD` and `MAP_ZEROS` alone
/// (`F_MAP_MANY`).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct MapEntry {
    pub map: MapArgs,
    pub flags: u32,
    pub reserved: u32,
}

/// `UNMAP`'s arguments.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct UnmapArgs {
    pub window_offset: u64,
    pub len: u64,
}

/// `COMMIT`'s arguments.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct CommitArgs {
    pub root_len: u32,
    pub reserved: u32,
}

/// What follows the root `ROOT` writes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct RootLen {
    pub len: u32,
    pub reserved: u32,
}

/// fxdax: `STATS`'s arguments: the ask it answers (`ConfigSpace::stats_asked`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct StatsArgs {
    pub asked: u64,
}

/// What `INFO` writes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Info {
    pub capacity: u64,
    pub used: u64,
    pub available: u64,
    pub next_sequence: u64,
    /// fxdax: the lowest sequence number the guest may mint from.
    pub sequence_floor: u64,
    /// fxdax: the branch the guest mints extents of.
    pub branch: u64,
}

/// What `ADVANCE` writes, the epoch of the commit the follower's view is as of now, and `LET_GO`
/// reads.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Epoch {
    pub epoch: u64,
    pub reserved: u64,
}

/// `VIRTIO_EXTENT_T_RESIZED`'s arguments: the capacity the guest was asked to shrink to.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ResizedArgs {
    pub capacity: u64,
}

/// fxdax: what the device knows of its store's capacity, which the daemon changes
/// (`RemoteExtentStore::on_capacity`): the capacity, the shrink the guest is asked to take, if any
/// (0 if none), and how the guest is told, once the driver activates the device. The daemon's
/// changes and the guest's answers are made one at a time (`changing`), so that an answer to a
/// shrink no longer asked changes nothing (TASK-79.41); the driver reads the fields as they are.
#[derive(Default)]
pub struct Resizing {
    pub capacity: AtomicU64,
    pub asked: AtomicU64,
    pub interrupt: Mutex<Option<Arc<dyn VirtioInterrupt>>>,
    changing: Mutex<()>,
}

impl std::fmt::Debug for Resizing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resizing")
            .field("capacity", &self.capacity)
            .field("asked", &self.asked)
            .finish_non_exhaustive()
    }
}

impl Resizing {
    /// The daemon set the store's capacity to `capacity` bytes, or, if `ask`, asks the guest to
    /// shrink to it: the guest is told, with a configuration change.
    pub fn changed(&self, capacity: u64, ask: bool) {
        let _changing = self.changing.lock().expect("Poisoned lock");
        if ask {
            self.asked.store(capacity, Ordering::Release);
        } else {
            self.capacity.store(capacity, Ordering::Release);
            self.asked.store(0, Ordering::Release);
        }
        if let Some(interrupt) = &*self.interrupt.lock().expect("Poisoned lock")
            && let Err(err) = interrupt.trigger(VirtioInterruptType::Config)
        {
            crate::logger::error!("extent device: signalling a configuration change: {err:?}");
        }
    }

    /// The guest answered the shrink to `capacity` bytes it was asked to take: it took it, if
    /// `took`. An answer to a shrink no longer asked, the daemon having asked another since, or
    /// told the capacity it kept, changes nothing.
    pub fn answered(&self, capacity: u64, took: bool) {
        let _changing = self.changing.lock().expect("Poisoned lock");
        if self.asked.load(Ordering::Acquire) != capacity {
            return;
        }
        self.asked.store(0, Ordering::Release);
        if took {
            self.capacity.store(capacity, Ordering::Release);
        }
    }
}

/// fxdax: what a follower's device knows of its writer's commits (`VIRTIO_EXTENT_F_READ_ONLY`,
/// `RemoteExtentStore::on_committed`): the latest commit's epoch, and how the guest is told, once
/// the driver activates the device.
#[derive(Default)]
pub struct Following {
    pub committed: AtomicU64,
    pub interrupt: Mutex<Option<Arc<dyn VirtioInterrupt>>>,
}

impl std::fmt::Debug for Following {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Following")
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl Following {
    /// The writer made commit `epoch`: the guest is told, with a configuration change, if it is
    /// after what it was told before.
    pub fn committed(&self, epoch: u64) {
        if self.committed.fetch_max(epoch, Ordering::AcqRel) >= epoch {
            return;
        }
        if let Some(interrupt) = &*self.interrupt.lock().expect("Poisoned lock")
            && let Err(err) = interrupt.trigger(VirtioInterruptType::Config)
        {
            crate::logger::error!("extent device: signalling a configuration change: {err:?}");
        }
    }
}

/// fxdax: the extent daemon's asks for the guest's stats (`VIRTIO_EXTENT_F_STATS`, TASK-111.4):
/// the latest, which the configuration's `stats_asked` says, and how the guest is told, while the
/// driver that activated the device takes asks.
#[derive(Default)]
pub struct StatsAsks {
    pub asked: AtomicU64,
    pub interrupt: Mutex<Option<Arc<dyn VirtioInterrupt>>>,
}

impl std::fmt::Debug for StatsAsks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatsAsks")
            .field("asked", &self.asked)
            .finish_non_exhaustive()
    }
}

impl StatsAsks {
    /// The daemon asks `ask`: whether the guest is asked, with a configuration change, as it is
    /// while the driver takes asks. Its answer, `STATS`, answers the asks before it too.
    pub fn ask(&self, ask: u64) -> bool {
        let interrupt = self.interrupt.lock().expect("Poisoned lock");
        let Some(interrupt) = &*interrupt else {
            return false;
        };
        self.asked.store(ask, Ordering::Release);
        match interrupt.trigger(VirtioInterruptType::Config) {
            Ok(()) => true,
            Err(err) => {
                crate::logger::error!("extent device: signalling a configuration change: {err:?}");
                false
            }
        }
    }
}

/// The device's configuration space.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct ConfigSpace {
    /// fxdax: the device's protocol version, [`VIRTIO_EXTENT_VERSION`], first, where every version
    /// has it (TASK-141.3).
    pub version: u32,
    /// The filesystem's name, NUL-padded: the mount's source.
    pub tag: [u8; 36],
    pub num_request_queues: u32,
    pub block_size: u32,
    pub map_alignment: u32,
    pub max_transfer: u32,
    pub max_segments: u32,
    pub max_root: u32,
    pub branch: u64,
    pub max_extent: u64,
    /// fxdax: the store's capacity, and the shrink the guest is asked to take, if any, 0 if none
    /// (`VIRTIO_EXTENT_F_RESIZE`).
    pub capacity: u64,
    pub asked: u64,
    /// fxdax: the epoch of the latest commit of a follower's writer (`VIRTIO_EXTENT_F_READ_ONLY`).
    pub committed: u64,
    /// fxdax: the most private pages a writer's window holds (`VIRTIO_EXTENT_F_DAX`, backlog
    /// doc-13): 0 of a follower's, which copies nothing.
    pub private_max: u64,
    /// fxdax: the latest of the extent daemon's asks for the guest's stats, 0 before the first
    /// (`VIRTIO_EXTENT_F_STATS`, TASK-111.4).
    pub stats_asked: u64,
}

// SAFETY: They are plain data, with no implicit padding.
unsafe impl ByteValued for ExtentIdLe {}
// SAFETY: As above.
unsafe impl ByteValued for RequestHeader {}
// SAFETY: As above.
unsafe impl ByteValued for Response {}
// SAFETY: As above.
unsafe impl ByteValued for ResizedArgs {}
// SAFETY: As above.
unsafe impl ByteValued for IoArgs {}
// SAFETY: As above.
unsafe impl ByteValued for MapArgs {}
// SAFETY: plain old data, with no padding.
unsafe impl ByteValued for MapEntry {}
// SAFETY: As above.
unsafe impl ByteValued for UnmapArgs {}
// SAFETY: As above.
unsafe impl ByteValued for CommitArgs {}
// SAFETY: As above.
unsafe impl ByteValued for RootLen {}
// SAFETY: As above.
unsafe impl ByteValued for Info {}
// SAFETY: As above.
unsafe impl ByteValued for StatsArgs {}
// SAFETY: As above.
unsafe impl ByteValued for Epoch {}
// SAFETY: As above.
unsafe impl ByteValued for ConfigSpace {}

impl From<ExtentIdLe> for fxdax::ExtentId {
    fn from(id: ExtentIdLe) -> Self {
        Self {
            branch: u64::from_le(id.branch),
            sequence: u64::from_le(id.sequence),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the device knows of its store's capacity: the capacity, and the shrink asked.
    fn known(resizing: &Resizing) -> (u64, u64) {
        (
            resizing.capacity.load(Ordering::Acquire),
            resizing.asked.load(Ordering::Acquire),
        )
    }

    /// fxdax TASK-79.41: the guest's answer to a shrink it was asked to take, once a newer shrink
    /// was asked, is that of a shrink no longer asked: the newer stays asked, and the capacity is
    /// the daemon's; the answer to the shrink asked last takes it.
    #[test]
    fn answers_to_shrinks_no_longer_asked_change_nothing() {
        let resizing = Resizing::default();
        resizing.changed(8, false);
        resizing.changed(6, true);
        resizing.changed(4, true);
        resizing.answered(6, true);
        assert_eq!(known(&resizing), (8, 4));
        resizing.answered(4, true);
        assert_eq!(known(&resizing), (4, 0));
        // The daemon told the capacity it kept, as for a shrink no answer came for in time.
        resizing.changed(2, true);
        resizing.changed(4, false);
        resizing.answered(2, true);
        assert_eq!(known(&resizing), (4, 0));
    }

    /// fxdax TASK-111.4: the daemon's asks for the guest's stats reach the guest, the
    /// configuration's `stats_asked` and a configuration change, while the driver takes asks; while
    /// it doesn't, none is asked, for the store to answer at once.
    #[test]
    fn stats_are_asked_of_guests_that_take_asks() {
        use crate::devices::virtio::test_utils::default_interrupt;
        let asks = StatsAsks::default();
        assert!(!asks.ask(1));
        assert_eq!(asks.asked.load(Ordering::Acquire), 0);
        let interrupt = default_interrupt();
        *asks.interrupt.lock().unwrap() = Some(interrupt.clone());
        assert!(asks.ask(2));
        assert_eq!(asks.asked.load(Ordering::Acquire), 2);
        assert!(interrupt.has_pending_interrupt(VirtioInterruptType::Config));
        *asks.interrupt.lock().unwrap() = None;
        assert!(!asks.ask(3));
        assert_eq!(asks.asked.load(Ordering::Acquire), 2);
    }
}
