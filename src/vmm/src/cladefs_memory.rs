// Copyright 2026 The cladefs Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! cladefs: a VM's memory, a memory cell's window, whether the VM was freshly booted (board
//! 14415) or restored from a snapshot (TASK-456.3): one path for both, rather than memory from a
//! file, or through a userfaultfd handler of another process, or anonymous memory.
//!
//! Guest memory is one reservation of the whole of it, its regions carved from it in order, as a
//! snapshot's memory file lays them out: so that one window of the extent daemon's covers it,
//! offset for offset the memory cell's image. The window, a copy-on-write one
//! (`cladefs::memory_cell`), maps the daemon's pages of the image's extents as the guest first
//! touches them, shared with every VM restored from the same snapshot on the host, and gives the
//! guest a private copy of a page it stores to: so no page is in memory more than once but those
//! VMs wrote. Where it comes from ([`Source`]):
//!
//! - A freshly booted VM's memory cell is a new one, empty, which `memory-cell` names
//!   (`MemoryCellBootConfig`): its image all holes, each page the guest writes made private. A
//!   boot without one is refused (hotbed question 596).
//! - A restored VM's is a fork of the snapshot's memory's version, its own; or, ephemeral, the
//!   host-local cell it was suspended into, reopened.
//!
//! Either way the VM's snapshots write its private pages into its memory cell, the same way
//! ([`snapshot_memory`]). The window maps 4 KiB pages: memory of huge pages is refused (hotbed
//! question 595).
//!
//! The window is made before anything touches guest memory. The cell and the reservation live as
//! long as the process, a VM's: kept here, the cell going first, which lets go of the window's
//! memory, then the reservation.
//!
//! What the guest gives back of that memory, a balloon's inflation or a free page report, is
//! reclaimed through the window ([`reclaim`], board 8497): its private pages there end, their
//! memory emptied. The `madvise(MADV_DONTNEED)` that `discard_range` makes of other memory
//! frees nothing of it, the private pages' memory object keeping them.

use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Mutex;

use cladefs::CellVersion;
use cladefs::memory_cell::MemoryCell;
use vm_memory::mmap::NewBitmap;

use crate::vmm_config::memory_cell::MemoryCellBootConfig;
use crate::vmm_config::snapshot::{CreateMemoryCellConfig, MemoryCellConfig, MemoryCellSnapshot};
use crate::vstate::memory::{AtomicBitmap, GuestAddress, GuestRegionMmap, MmapRegionBuilder};

/// Errors making or snapshotting guest memory with a memory cell. A `cladefs::Error` is printed
/// with its causes (`{:#}`), as the extent device's errors print it: its own `Display` is its
/// outermost context alone, which leaves out the errno the daemon refused with.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CellMemoryError {
    /// A `Cell` memory backend needs `memory_cell`, naming the copy and the daemon.
    NoMemoryCell,
    /// Booting a VM needs `memory-cell` (`PUT /memory-cell`): its memory is a memory cell's window (hotbed question 596).
    NoBootMemoryCell,
    /// Guest memory that is a memory cell's window can't be of huge pages: set `huge_pages` to `None` (hotbed question 595).
    HugePages,
    /// A vhost-user device can't reach guest memory that is a memory cell's window.
    VhostUser,
    /// Reserving {0} bytes for guest memory: {1}
    Reserve(usize, std::io::Error),
    /// Making a guest memory region: {0}
    Region(vm_memory::mmap::MmapRegionError),
    /// A guest memory region at {0:#x} of {1} bytes past what vm-memory allows.
    RegionPlace(u64, usize),
    /// Opening the memory cell at {0}: {1:#}
    Open(String, cladefs::Error),
    /// Making the memory cell the guest's memory: {0:#}
    Window(cladefs::Error),
    /// The VM's memory is no memory cell's (restored from a `File` or `Uffd` backend): snapshot it to `mem_file_path` (hotbed question 597).
    NotCellMemory,
    /// Snapshotting guest memory into its memory cell: {0:#}
    Snapshot(cladefs::Error),
    /// Invalid ephemeral memory cell configuration: `version` must be 0, and `tenant` requires `cell`.
    InvalidEphemeralConfig,
    /// Snapshot `memory_cell.ephemeral: true` cannot be used on a VM whose memory cell is bucket-backed.
    EphemeralMismatch,
    /// Reading memory diff file {0}: {1}
    DiffFile(String, std::io::Error),
    /// Memory diff file {0} is {1} bytes, expected {2}.
    DiffFileSize(String, u64, u64),
    /// Applying memory diff files to the memory cell: {0:#}
    ApplyDiffs(cladefs::Error),
}

/// What a VM's memory cell is: a fresh boot's, new, or a restore's.
#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    /// A freshly booted VM's: a new memory cell, empty, where `memory-cell` says.
    Boot(&'a MemoryCellBootConfig),
    /// A restored VM's: the memory cell at `store` (the memory backend's path), as `config`
    /// says, a fork of the snapshot's memory's version or an ephemeral cell reopened.
    Restore {
        /// The memory cell's directory, or `TENANT/CELL`.
        store: &'a Path,
        /// Where the snapshot's memory is, and which daemon serves it.
        config: &'a MemoryCellConfig,
    },
}

/// The VM's memory, kept for the process's life: the cell first, as it goes first, letting go of
/// the window's memory, then the reservation it is in; and the configuration it was booted with,
/// if it was.
struct CellMemory {
    memory_cell: MemoryCell,
    reservation: Reservation,
    boot: Option<MemoryCellBootConfig>,
}

// SAFETY: the reservation's memory is the guest's, which the window serves from any thread.
unsafe impl Send for CellMemory {}

/// The VM's memory, once made: none for a VM restored from a `File` or `Uffd` backend.
static MEMORY: Mutex<Option<CellMemory>> = Mutex::new(None);

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

/// Guest memory of `regions`, a fresh boot's or a restore's as `source` says, the window of its
/// memory cell made over it.
pub fn guest_memory(
    source: Source<'_>,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: bool,
) -> Result<Vec<GuestRegionMmap>, CellMemoryError> {
    if huge_pages {
        return Err(CellMemoryError::HugePages);
    }
    let regions: Vec<_> = regions.collect();
    let size: usize = regions.iter().map(|(_, size)| size).sum();
    let reservation = Reservation::new(size)?;
    let mut guest = Vec::with_capacity(regions.len());
    let mut offset = 0;
    for (start, len) in regions {
        // SAFETY: within the reservation, which outlives the region (`CellMemory`).
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
    let memory_cell = open(source, size as u64)?;
    // SAFETY: the reservation is the guest's memory, which nothing else of the process uses, and
    // which outlives the memory_cell (`CellMemory`).
    unsafe { memory_cell.window(reservation.base, size as u64, None) }
        .map_err(CellMemoryError::Window)?;
    let boot = match source {
        Source::Boot(config) => Some(config.clone()),
        Source::Restore { .. } => None,
    };
    *MEMORY.lock().unwrap() = Some(CellMemory {
        memory_cell,
        reservation,
        boot,
    });
    Ok(guest)
}

/// Opens the memory cell of a memory of `size` bytes as `source` says, ready for its window: a
/// restore's diff files applied.
fn open(source: Source<'_>, size: u64) -> Result<MemoryCell, CellMemoryError> {
    let (store, config) = match source {
        Source::Boot(config) => {
            let path = &config.path_on_host;
            let made = match config.ephemeral {
                true => MemoryCell::create_ephemeral(&config.cladefsd_socket, path, size),
                false => MemoryCell::create(&config.cladefsd_socket, path, size),
            };
            return made.map_err(|error| CellMemoryError::Open(path.display().to_string(), error));
        }
        Source::Restore { store, config } => (store, config),
    };
    for path in &config.diff_files {
        let len = std::fs::metadata(path)
            .map_err(|err| CellMemoryError::DiffFile(path.display().to_string(), err))?
            .len();
        if len != size {
            return Err(CellMemoryError::DiffFileSize(
                path.display().to_string(),
                len,
                size,
            ));
        }
    }
    let opened = if config.ephemeral {
        if config.version != 0 || (config.cell == 0 && config.tenant != 0) {
            return Err(CellMemoryError::InvalidEphemeralConfig);
        }
        let expected = (config.cell != 0).then_some(cladefs::CellId {
            tenant: config.tenant,
            id: config.cell,
        });
        MemoryCell::open_ephemeral_existing(&config.cladefsd_socket, store, expected, size)
    } else {
        let from = CellVersion {
            tenant: config.tenant,
            cell: config.cell,
            version: config.version,
        };
        MemoryCell::open_forked(&config.cladefsd_socket, store, from, size)
    };
    let memory_cell =
        opened.map_err(|error| CellMemoryError::Open(store.display().to_string(), error))?;
    if !config.diff_files.is_empty() {
        let diffs: Vec<&Path> = config.diff_files.iter().map(PathBuf::as_path).collect();
        memory_cell
            .apply_diff_files(&diffs)
            .map_err(CellMemoryError::ApplyDiffs)?;
    }
    Ok(memory_cell)
}

/// The memory cell a freshly booted VM's memory is the window of, as its configuration named it:
/// none for a restored VM.
pub fn boot_config() -> Option<MemoryCellBootConfig> {
    let memory = MEMORY.lock().unwrap();
    memory.as_ref().and_then(|memory| memory.boot.clone())
}

/// Reclaims the `len` bytes of guest memory at host address `addr`, which the guest gave back,
/// if they are memory of a memory cell's: through its window, which ends the private pages there,
/// their memory emptied (`MemoryCell::reclaim`); the guest reads the cell's pages there next.
/// None for other memory, which `discard_range` discards as upstream does.
pub(crate) fn reclaim(addr: *const u8, len: usize) -> Option<Result<(), cladefs::Error>> {
    let memory = MEMORY.lock().unwrap();
    let CellMemory {
        memory_cell,
        reservation,
        ..
    } = memory.as_ref()?;
    let offset = (addr as usize).checked_sub(reservation.base.as_ptr() as usize)?;
    if offset >= reservation.len {
        return None;
    }
    // Within the reservation: a region's, carved from it whole.
    Some(memory_cell.reclaim(offset as u64, len as u64))
}

/// Snapshots guest memory straight into its memory cell (TASK-456.4), a freshly booted VM's as a
/// restored one's: writes the window's private pages into it, commits, reclaims them back to the
/// newly committed extents, and makes a version; or, of an ephemeral memory cell, checkpoints it
/// in place. The VM is paused.
pub fn snapshot_memory(
    config: &CreateMemoryCellConfig,
) -> Result<MemoryCellSnapshot, CellMemoryError> {
    let memory = MEMORY.lock().unwrap();
    let memory = memory.as_ref().ok_or(CellMemoryError::NotCellMemory)?;
    if memory.memory_cell.is_ephemeral() {
        // SAFETY: the VM is paused by Firecracker before creating a snapshot, and
        // `memory.reservation.base` is the base passed to `MemoryCell::window`.
        let cell = unsafe {
            memory
                .memory_cell
                .snapshot_window_ephemeral(memory.reservation.base)
        }
        .map_err(CellMemoryError::Snapshot)?;
        return Ok(MemoryCellSnapshot {
            tenant: cell.tenant,
            cell: cell.id,
            version: 0,
            ephemeral: true,
        });
    }
    if config.ephemeral {
        return Err(CellMemoryError::EphemeralMismatch);
    }
    // SAFETY: the VM is paused by Firecracker before creating a snapshot, and
    // `memory.reservation.base` is the base passed to `MemoryCell::window`.
    let version = unsafe { memory.memory_cell.snapshot_window(memory.reservation.base) }
        .map_err(CellMemoryError::Snapshot)?;
    Ok(MemoryCellSnapshot {
        tenant: version.tenant,
        cell: version.cell,
        version: version.version,
        ephemeral: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The errno the extent daemon refused an opening with is in the fault Firecracker reports
    /// (cladefs board 13876): a `cladefs::Error`'s own `Display` is its outermost context alone.
    #[test]
    fn faults_name_the_daemons_errno() {
        let refused =
            cladefs::Error::new(cladefs::Errno::EACCES).context("opening the extent store at 0/0");
        assert_eq!(
            CellMemoryError::Open("0/0".into(), refused).to_string(),
            "Opening the memory cell at 0/0: opening the extent store at 0/0: EACCES (errno 13)"
        );
    }
}
