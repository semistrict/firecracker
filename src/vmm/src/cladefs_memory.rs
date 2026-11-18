// Copyright 2026 The cladefs Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! cladefs: a VM's memory restored from a memory vdisk of its snapshot's cell (TASK-456.3),
//! rather than from a file or through a userfaultfd handler of another process.
//!
//! Guest memory is one reservation of the whole of it, its regions carved from it in order, as a
//! snapshot's memory file lays them out: so that one window of the extent daemon's covers it,
//! offset for offset the memory vdisk's image. The window, a copy-on-write one
//! (`cladefs::memory_vdisk`), maps the daemon's pages of the image's extents as the guest first
//! touches them, shared with every VM restored from the same snapshot on the host, and gives the
//! guest a private copy of a page it stores to: so no page is in memory more than once but those
//! VMs wrote. The VM's memory vdisk is a fork of the snapshot's memory's copy, its own, which its
//! next snapshot writes its private pages into.
//!
//! The window is made before anything touches guest memory, as restoring its devices does. The
//! vdisk and the reservation live as long as the process, a VM's: kept here, the vdisk going
//! first, which lets go of the window's memory, then the reservation.

use std::path::Path;
use std::ptr::NonNull;
use std::sync::Mutex;

use cladefs::memory_vdisk::MemoryVdisk;
use vm_memory::mmap::NewBitmap;

use crate::vmm_config::snapshot::MemoryVdiskConfig;
use crate::vstate::memory::{AtomicBitmap, GuestAddress, GuestRegionMmap, MmapRegionBuilder};

/// Errors restoring guest memory from a memory vdisk.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VdiskMemoryError {
    /// A `Vdisk` memory backend needs `memory_vdisk`, naming the copy and the daemon.
    NoMemoryVdisk,
    /// Guest memory restored from a memory vdisk can't be of huge pages.
    HugePages,
    /// Reserving {0} bytes for guest memory: {1}
    Reserve(usize, std::io::Error),
    /// Making a guest memory region: {0}
    Region(vm_memory::mmap::MmapRegionError),
    /// A guest memory region at {0:#x} of {1} bytes past what vm-memory allows.
    RegionPlace(u64, usize),
    /// Opening the memory vdisk at {0}: {1}
    Open(String, cladefs::Error),
    /// Making the memory vdisk the guest's memory: {0}
    Window(cladefs::Error),
}

/// The memory a VM was restored with, kept for the process's life: the vdisk first, as it goes
/// first, letting go of the window's memory, then the reservation it is in.
struct Restored {
    _vdisk: MemoryVdisk,
    _reservation: Reservation,
}

// SAFETY: the reservation's memory is the guest's, which the window serves from any thread.
unsafe impl Send for Restored {}

/// The VM's memory restored from a memory vdisk, if it was.
static RESTORED: Mutex<Option<Restored>> = Mutex::new(None);

/// A reservation of memory, unmapped when dropped.
struct Reservation {
    base: NonNull<u8>,
    len: usize,
}

impl Reservation {
    fn new(len: usize) -> Result<Self, VdiskMemoryError> {
        // SAFETY: new anonymous memory, reserving none, which the reservation owns.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(VdiskMemoryError::Reserve(
                len,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            base: NonNull::new(base.cast()).expect("a mapping"),
            len,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: the reservation's memory, which nothing uses with the window gone.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// Guest memory of `regions`, restored from the memory vdisk at `store`, as `config` says, its
/// window made over it.
pub fn guest_memory(
    store: &Path,
    config: Option<&MemoryVdiskConfig>,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: bool,
) -> Result<Vec<GuestRegionMmap>, VdiskMemoryError> {
    let config = config.ok_or(VdiskMemoryError::NoMemoryVdisk)?;
    if huge_pages {
        return Err(VdiskMemoryError::HugePages);
    }
    let regions: Vec<_> = regions.collect();
    let size: usize = regions.iter().map(|(_, size)| size).sum();
    let reservation = Reservation::new(size)?;
    let mut guest = Vec::with_capacity(regions.len());
    let mut offset = 0;
    for (start, len) in regions {
        // SAFETY: within the reservation, which outlives the region (`Restored`).
        let at = unsafe { reservation.base.as_ptr().add(offset) };
        let bitmap = track_dirty_pages.then(|| AtomicBitmap::with_len(len));
        // SAFETY: the region's memory is the reservation's, mapped as the region says it is.
        let builder = unsafe {
            MmapRegionBuilder::new_with_bitmap(len, bitmap)
                .with_raw_mmap_pointer(at)
                .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                .with_mmap_flags(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)
        };
        let region = builder.build().map_err(VdiskMemoryError::Region)?;
        let region = GuestRegionMmap::new(region, start)
            .ok_or(VdiskMemoryError::RegionPlace(start.0, len))?;
        guest.push(region);
        offset += len;
    }
    let vdisk = MemoryVdisk::open_forked(
        &config.cladefsd_socket,
        store,
        &config.copy_on_host,
        size as u64,
    )
    .map_err(|error| VdiskMemoryError::Open(store.display().to_string(), error))?;
    // SAFETY: the reservation is the guest's memory, which nothing else of the process uses, and
    // which outlives the vdisk (`Restored`).
    unsafe { vdisk.window(reservation.base, size as u64, None) }
        .map_err(VdiskMemoryError::Window)?;
    *RESTORED.lock().unwrap() = Some(Restored {
        _vdisk: vdisk,
        _reservation: reservation,
    });
    Ok(guest)
}
