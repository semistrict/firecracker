// Copyright 2026 The cladefs Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! cladefs: a VM's memory restored from a memory cell of its snapshot's cell (TASK-456.3),
//! rather than from a file or through a userfaultfd handler of another process.
//!
//! Guest memory is one reservation of the whole of it, its regions carved from it in order, as a
//! snapshot's memory file lays them out: so that one window of the extent daemon's covers it,
//! offset for offset the memory cell's image. The window, a copy-on-write one
//! (`cladefs::memory_cell`), maps the daemon's pages of the image's extents as the guest first
//! touches them, shared with every VM restored from the same snapshot on the host, and gives the
//! guest a private copy of a page it stores to: so no page is in memory more than once but those
//! VMs wrote. The VM's memory cell is a fork of the snapshot's memory's copy, its own, which its
//! next snapshot writes its private pages into.
//!
//! The window is made before anything touches guest memory, as restoring its devices does. The
//! cell and the reservation live as long as the process, a VM's: kept here, the cell going
//! first, which lets go of the window's memory, then the reservation.
//!
//! What the guest gives back of that memory, a balloon's inflation or a free page report, is
//! reclaimed through the window ([`reclaim`], board 8497): its private pages there end, their
//! memory emptied. The `madvise(MADV_DONTNEED)` that `discard_range` makes of other memory
//! frees nothing of it, the private pages' memory object keeping them.

use std::path::Path;
use std::ptr::NonNull;
use std::sync::Mutex;

use cladefs::CellVersion;
use cladefs::memory_cell::MemoryCell;
use vm_memory::mmap::NewBitmap;

use crate::vmm_config::snapshot::MemoryCellConfig;
use crate::vstate::memory::{AtomicBitmap, GuestAddress, GuestRegionMmap, MmapRegionBuilder};

/// Errors restoring guest memory from a memory cell.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CellMemoryError {
    /// A `Cell` memory backend needs `memory_cell`, naming the copy and the daemon.
    NoMemoryCell,
    /// Guest memory restored from a memory cell can't be of huge pages.
    HugePages,
    /// Reserving {0} bytes for guest memory: {1}
    Reserve(usize, std::io::Error),
    /// Making a guest memory region: {0}
    Region(vm_memory::mmap::MmapRegionError),
    /// A guest memory region at {0:#x} of {1} bytes past what vm-memory allows.
    RegionPlace(u64, usize),
    /// Opening the memory cell at {0}: {1}
    Open(String, cladefs::Error),
    /// Making the memory cell the guest's memory: {0}
    Window(cladefs::Error),
}

/// The memory a VM was restored with, kept for the process's life: the cell first, as it goes
/// first, letting go of the window's memory, then the reservation it is in.
struct Restored {
    memory_cell: MemoryCell,
    reservation: Reservation,
}

// SAFETY: the reservation's memory is the guest's, which the window serves from any thread.
unsafe impl Send for Restored {}

/// The VM's memory restored from a memory cell, if it was.
static RESTORED: Mutex<Option<Restored>> = Mutex::new(None);

/// A reservation of memory, unmapped when dropped.
struct Reservation {
    base: NonNull<u8>,
    len: usize,
}

impl Reservation {
    fn new(len: usize) -> Result<Self, CellMemoryError> {
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
            return Err(CellMemoryError::Reserve(
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

/// Guest memory of `regions`, restored from the memory cell at `store`, as `config` says, its
/// window made over it.
pub fn guest_memory(
    store: &Path,
    config: Option<&MemoryCellConfig>,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: bool,
) -> Result<Vec<GuestRegionMmap>, CellMemoryError> {
    let config = config.ok_or(CellMemoryError::NoMemoryCell)?;
    if huge_pages {
        return Err(CellMemoryError::HugePages);
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
        let region = builder.build().map_err(CellMemoryError::Region)?;
        let region = GuestRegionMmap::new(region, start)
            .ok_or(CellMemoryError::RegionPlace(start.0, len))?;
        guest.push(region);
        offset += len;
    }
    let from = CellVersion {
        tenant: config.tenant,
        cell: config.cell,
        version: config.version,
    };
    let memory_cell = MemoryCell::open_forked(&config.cladefsd_socket, store, from, size as u64)
        .map_err(|error| CellMemoryError::Open(store.display().to_string(), error))?;
    // SAFETY: the reservation is the guest's memory, which nothing else of the process uses, and
    // which outlives the memory_cell (`Restored`).
    unsafe { memory_cell.window(reservation.base, size as u64, None) }
        .map_err(CellMemoryError::Window)?;
    *RESTORED.lock().unwrap() = Some(Restored {
        memory_cell,
        reservation,
    });
    Ok(guest)
}

/// Reclaims the `len` bytes of guest memory at host address `addr`, which the guest gave back,
/// if they are memory restored from a memory cell: through its window, which ends the private
/// pages there, their memory emptied (`MemoryCell::reclaim`); the guest reads the cell's pages
/// there next. None for other memory, which `discard_range` discards as upstream does.
pub(crate) fn reclaim(addr: *const u8, len: usize) -> Option<Result<(), cladefs::Error>> {
    let restored = RESTORED.lock().unwrap();
    let Restored {
        memory_cell,
        reservation,
    } = restored.as_ref()?;
    let offset = (addr as usize).checked_sub(reservation.base.as_ptr() as usize)?;
    if offset >= reservation.len {
        return None;
    }
    // Within the reservation: a region's, carved from it whole.
    Some(memory_cell.reclaim(offset as u64, len as u64))
}
