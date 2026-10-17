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
mod window;
mod worker;

pub use self::device::{Extent, ExtentError};
#[cfg(target_arch = "x86_64")]
pub use self::window::KvmPrefault;
pub use self::window::{DaxWindowError, PrefaultGuestMemory};

use crate::vstate::memory::ByteValued;

/// Shared memory region 0 is a DAX window, and `MAP`/`UNMAP` work.
pub const VIRTIO_EXTENT_F_DAX: u32 = 0;
/// `MAP` maps open extents writably.
pub const VIRTIO_EXTENT_F_DAX_WRITE: u32 = 1;
/// `WRITE` takes `WRITE_COMMIT`: a commit follows the write, in one request.
pub const VIRTIO_EXTENT_F_WRITE_COMMIT: u32 = 2;

pub const VIRTIO_EXTENT_T_READ: u32 = 1;
pub const VIRTIO_EXTENT_T_WRITE: u32 = 2;
pub const VIRTIO_EXTENT_T_FREE: u32 = 3;
pub const VIRTIO_EXTENT_T_MAP: u32 = 4;
pub const VIRTIO_EXTENT_T_UNMAP: u32 = 5;
pub const VIRTIO_EXTENT_T_COMMIT: u32 = 6;
pub const VIRTIO_EXTENT_T_ROOT: u32 = 7;
pub const VIRTIO_EXTENT_T_INFO: u32 = 8;

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
}

// SAFETY: They are plain data, with no implicit padding.
unsafe impl ByteValued for ExtentIdLe {}
// SAFETY: As above.
unsafe impl ByteValued for RequestHeader {}
// SAFETY: As above.
unsafe impl ByteValued for Response {}
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
unsafe impl ByteValued for ConfigSpace {}

impl From<ExtentIdLe> for fxdax::ExtentId {
    fn from(id: ExtentIdLe) -> Self {
        Self {
            branch: u64::from_le(id.branch),
            sequence: u64::from_le(id.sequence),
        }
    }
}
