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
use vm_memory::GuestMemoryBackend;
use vm_memory::mmap::NewBitmap;

use crate::arch::host_page_size;

use crate::vmm_config::snapshot::{CreateMemoryCellConfig, MemoryCellConfig, MemoryCellSnapshot};
use crate::vstate::memory::{
    AtomicBitmap, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegionBuilder,
};

/// Errors restoring or snapshotting guest memory with a memory cell.
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
    /// A VM restored from a memory cell snapshots into its own forked cell: omit `path_on_host` and `cladefsd_socket`.
    RestoredMemoryCellHasConfig,
    /// Snapshotting a VM not restored from a memory cell requires both `path_on_host` and `cladefsd_socket`.
    NoCreateMemoryCellPath,
    /// Querying resident guest pages with mincore: {0}
    Mincore(std::io::Error),
    /// Snapshotting guest memory into its memory cell: {0}
    Snapshot(cladefs::Error),
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
        let region = vm_memory::GuestRegionMmap::new(region, start)
            .ok_or(CellMemoryError::RegionPlace(start.0, len))?;
        guest.push(GuestRegionMmap::from_unowned(region));
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

/// Snapshots guest memory straight into a memory cell (TASK-456.4):
/// - For a VM restored from a memory cell, writes only the window's private pages into its forked
///   memory cell, commits, reclaims them back to the newly committed extents, and makes a version.
/// - For a cold-booted (or non-cell) VM, opens a new memory cell at `config.path_on_host` via
///   `config.cladefsd_socket`, scans resident pages via `mincore` without faulting untouched
///   anonymous pages, writes only non-zero resident pages (zeros discarded as holes), commits, and
///   makes a version.
pub fn snapshot_memory(
    guest_memory: &GuestMemoryMmap,
    config: &CreateMemoryCellConfig,
) -> Result<MemoryCellSnapshot, CellMemoryError> {
    let restored = RESTORED.lock().unwrap();
    if let Some(restored) = restored.as_ref() {
        if config.path_on_host.is_some() || config.cladefsd_socket.is_some() {
            return Err(CellMemoryError::RestoredMemoryCellHasConfig);
        }
        // SAFETY: the VM is paused by Firecracker before creating a snapshot, and
        // `restored.reservation.base` is the base passed to `MemoryCell::window`.
        let version = unsafe {
            restored
                .memory_cell
                .snapshot_window(restored.reservation.base)
        }
        .map_err(CellMemoryError::Snapshot)?;
        return Ok(MemoryCellSnapshot {
            tenant: version.tenant,
            cell: version.cell,
            version: version.version,
        });
    }
    drop(restored);

    let (Some(path), Some(socket)) = (&config.path_on_host, &config.cladefsd_socket) else {
        return Err(CellMemoryError::NoCreateMemoryCellPath);
    };
    let total_size: usize = guest_memory
        .iter()
        .flat_map(|region| region.slots())
        .map(|(slot, _)| slot.slice.len())
        .sum();
    let cell = MemoryCell::open(socket, path, total_size as u64)
        .map_err(|error| CellMemoryError::Open(path.display().to_string(), error))?;

    let host_ps = host_page_size();
    // 64 MiB chunks keep the mincore status vec tiny (16 KiB on 4 KiB hosts).
    const CHUNK_BYTES: usize = 64 << 20;
    let mut mincore_vec = vec![0u8; CHUNK_BYTES / host_ps];
    let mut offset = 0u64;

    for (mem_slot, plugged) in guest_memory.iter().flat_map(|region| region.slots()) {
        let slot_len = mem_slot.slice.len();
        if !plugged {
            offset += slot_len as u64;
            continue;
        }
        let base_ptr = mem_slot.slice.ptr_guard().as_ptr();
        let mut pos = 0usize;
        while pos < slot_len {
            let chunk_len = (slot_len - pos).min(CHUNK_BYTES);
            let pages = chunk_len / host_ps;
            let vec = &mut mincore_vec[..pages];
            // SAFETY: `base_ptr.add(pos)` is a page-aligned guest memory mapping of at least
            // `chunk_len` bytes, and `vec` has one byte per host page.
            let rc = unsafe {
                libc::mincore(
                    base_ptr.add(pos).cast_mut().cast(),
                    chunk_len,
                    vec.as_mut_ptr(),
                )
            };
            if rc != 0 {
                return Err(CellMemoryError::Mincore(std::io::Error::last_os_error()));
            }
            // Write contiguous runs of resident pages; non-resident pages remain zero holes.
            let mut idx = 0usize;
            while idx < pages {
                if vec[idx] & 1 == 0 {
                    idx += 1;
                    continue;
                }
                let run_start = idx;
                while idx < pages && (vec[idx] & 1) != 0 {
                    idx += 1;
                }
                let run_off = pos + run_start * host_ps;
                let run_len = (idx - run_start) * host_ps;
                // SAFETY: within the plugged guest memory slot, and the VM is paused.
                let bytes = unsafe { std::slice::from_raw_parts(base_ptr.add(run_off), run_len) };
                cell.write_sparse(offset + run_off as u64, bytes)
                    .map_err(CellMemoryError::Snapshot)?;
            }
            pos += chunk_len;
        }
        offset += slot_len as u64;
    }

    cell.commit().map_err(CellMemoryError::Snapshot)?;
    let version = cell.make_version().map_err(CellMemoryError::Snapshot)?;
    cell.close().map_err(CellMemoryError::Snapshot)?;
    Ok(MemoryCellSnapshot {
        tenant: version.tenant,
        cell: version.cell,
        version: version.version,
    })
}
