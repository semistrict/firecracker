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
pub use self::window::{DaxWindowError, PrefaultGuestMemory};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::vstate::memory::ByteValued;

/// Shared memory region 0 is a DAX window, and `MAP`/`UNMAP` work.
pub const VIRTIO_EXTENT_F_DAX: u32 = 0;
/// `MAP` maps open extents writably.
pub const VIRTIO_EXTENT_F_DAX_WRITE: u32 = 1;
/// `WRITE` takes `WRITE_COMMIT`: a commit follows the write, in one request.
pub const VIRTIO_EXTENT_F_WRITE_COMMIT: u32 = 2;
/// fxdax: the configuration holds the store's capacity, which the host changes while the guest
/// runs, telling it with a configuration change; a shrink the guest is asked to take it answers
/// (`VIRTIO_EXTENT_T_RESIZED`).
pub const VIRTIO_EXTENT_F_RESIZE: u32 = 3;
/// fxdax: `VIRTIO_EXTENT_T_FREEZE` tells the device the guest's filesystem is frozen, or thawed,
/// and `INFO` says the branch: a snapshot of the VM is taken frozen, and a VM restored from it,
/// with a store of its own, learns its branch as its filesystem thaws (TASK-39.1).
pub const VIRTIO_EXTENT_F_FREEZE: u32 = 4;
/// fxdax: the device follows a store another VM writes, read-only (backlog doc-8): `ADVANCE`,
/// `LET_GO`, `PIN` and `UNPIN` work, and the configuration's `committed` changes as the writer
/// commits, telling the guest with a configuration change (TASK-42.3).
pub const VIRTIO_EXTENT_F_READ_ONLY: u32 = 5;

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
/// The last request type.
pub const VIRTIO_EXTENT_T_LAST: u32 = VIRTIO_EXTENT_T_UNPIN;

/// A `WRITE`'s flags: a barrier precedes it, as if a `COMMIT` did; a `COMMIT` follows it (with
/// `WRITE_COMMIT`); that commit completes once durable.
pub const VIRTIO_EXTENT_WRITE_BARRIER: u32 = 1 << 0;
pub const VIRTIO_EXTENT_WRITE_COMMIT: u32 = 1 << 1;
pub const VIRTIO_EXTENT_WRITE_DURABLE: u32 = 1 << 2;

/// The barriers a `WRITE`'s `flags` order it with, unless they are not a `WRITE`'s.
pub fn write_barriers(flags: u32) -> Option<fxdax::WriteBarriers> {
    let known =
        VIRTIO_EXTENT_WRITE_BARRIER | VIRTIO_EXTENT_WRITE_COMMIT | VIRTIO_EXTENT_WRITE_DURABLE;
    if flags & !known != 0
        || (flags & VIRTIO_EXTENT_WRITE_DURABLE != 0 && flags & VIRTIO_EXTENT_WRITE_COMMIT == 0)
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
    })
}
/// A `COMMIT`'s flags: it completes once durable; it sets the root.
pub const VIRTIO_EXTENT_COMMIT_DURABLE: u32 = 1 << 0;
pub const VIRTIO_EXTENT_COMMIT_ROOT: u32 = 1 << 1;
/// A `MAP`'s flag: writable, which needs `DAX_WRITE`.
pub const VIRTIO_EXTENT_MAP_WRITE: u32 = 1 << 0;

/// The device's queues, and their size.
pub const EXTENT_NUM_QUEUES: usize = 1;
pub const EXTENT_QUEUE_SIZE: u16 = 256;

/// The ID of the DAX window's shared memory region.
const DAX_WINDOW_SHM_ID: u8 = 0;

/// The most bytes one `READ` or `WRITE` moves.
const MAX_TRANSFER: u32 = 8 << 20;
/// The most bytes the root holds.
const MAX_ROOT: u32 = 4096;
/// The most bytes one extent holds.
const MAX_EXTENT: u64 = fxdax::ExtentStore::MAX_EXTENT;

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
    pub reserved: u32,
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
    /// fxdax (`VIRTIO_EXTENT_F_FREEZE`): the branch the guest mints extents of.
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

/// The length of what `INFO` writes for a driver without `VIRTIO_EXTENT_F_FREEZE`: the fields
/// before `Info::branch`.
pub const INFO_LEN_WITHOUT_BRANCH: usize = std::mem::offset_of!(Info, branch);

/// `VIRTIO_EXTENT_T_RESIZED`'s arguments: the capacity the guest was asked to shrink to.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ResizedArgs {
    pub capacity: u64,
}

/// fxdax: what the device knows of its store's capacity, which the daemon changes
/// (`RemoteExtentStore::on_capacity`): the capacity, the shrink the guest is asked to take, if any
/// (0 if none), and how the guest is told, once the driver activates the device.
#[derive(Default)]
pub struct Resizing {
    pub capacity: AtomicU64,
    pub asked: AtomicU64,
    pub interrupt: Mutex<Option<Arc<dyn VirtioInterrupt>>>,
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
    /// `took`.
    pub fn answered(&self, capacity: u64, took: bool) {
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

/// The device's configuration space.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct ConfigSpace {
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
// SAFETY: As above.
unsafe impl ByteValued for UnmapArgs {}
// SAFETY: As above.
unsafe impl ByteValued for CommitArgs {}
// SAFETY: As above.
unsafe impl ByteValued for RootLen {}
// SAFETY: As above.
unsafe impl ByteValued for Info {}
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
