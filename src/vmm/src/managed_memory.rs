//! Ownership of memory controlled by the host's volume pager.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sproutfs_vm_memory::{Control, Region, RegionKind, RegionSpec, Session};
use vm_memory::GuestAddress;

use crate::resources::ManagedMemoryConfig;
use crate::seccomp::{BpfProgram, BpfThreadMap};
use crate::vstate::memory::{GuestRegionMmap, MemoryError};

static WORKER_POLICY: OnceLock<Arc<BpfProgram>> = OnceLock::new();

/// Selects the explicit memory-worker policy before any attachment is created.
/// Missing filters fail closed, including when a custom policy is supplied.
pub fn configure_worker_policy(filters: &BpfThreadMap) -> io::Result<()> {
    let policy = filters
        .get("memory")
        .ok_or_else(|| io::Error::other("missing memory-worker seccomp filter"))?;
    let selected = WORKER_POLICY.get_or_init(|| policy.clone());
    if selected.as_slice() != policy.as_slice() {
        return Err(io::Error::other("memory-worker seccomp policy changed"));
    }
    Ok(())
}

/// Retains the Session, including after its service thread returns.
///
/// A session maps one volume, so an owner is one volume: guest RAM is one, and
/// so is each PMEM device. Guest RAM's mapping wrappers may be several, one per
/// guest region, and they share this owner. The last owner can drop only after
/// memory users have stopped. Guest RAM owns this through its mapping wrappers;
/// PMEM owns it after its KVM slot.
pub struct Owner {
    socket_path: std::path::PathBuf,
    control: Control,
    region: Region,
    stopping: Arc<AtomicBool>,
    service: Mutex<Option<JoinHandle<Session>>>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedMemoryOwner")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Owner {
    /// Connects before exposing any mapping and starts a dedicated service.
    pub fn connect(path: &std::path::Path, spec: RegionSpec) -> io::Result<Arc<Self>> {
        let service_policy = WORKER_POLICY
            .get()
            .ok_or_else(|| io::Error::other("memory-worker policy not configured"))?
            .clone();
        let mut session = Session::connect(path, spec)?;
        let region = session.region();
        let control = session.control();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let service = thread::Builder::new()
            .name("sproutfs-memory".into())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&service_policy) {
                    eprintln!("Cannot install memory-worker policy: {err}");
                    #[allow(clippy::exit)]
                    std::process::exit(1);
                }
                let result = session.run();
                if !worker_stopping.load(Ordering::Acquire) {
                    eprintln!("Managed memory service ended unexpectedly: {result:?}");
                    // Closing UFFD while KVM keeps running can expose zero-filled
                    // anonymous trap pages. Process termination stops every user.
                    #[allow(clippy::exit)]
                    std::process::exit(1);
                }
                session
            })?;
        Ok(Arc::new(Self {
            socket_path: path.to_owned(),
            control,
            region,
            stopping,
            service: Mutex::new(Some(service)),
        }))
    }

    /// The stable address retained by this owner.
    pub fn region(&self) -> Region {
        self.region
    }

    /// Socket identity used to construct this attachment.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

/// How long a seal request waits here. The host's own deadline is the one that
/// decides a seal: it answers one it could not finish with a failure, which
/// fails the checkpoint, unseals and lets the guest resume. This is far longer,
/// so a slow seal is never answered by a timer here — expiring closes the
/// control session and kills the guest — and it remains only the backstop for a
/// host that has stopped answering at all.
const SEAL_BACKSTOP: Duration = Duration::from_secs(300);

/// Seal independently owned volumes concurrently after guest CPUs and device
/// mutations have stopped for a coordinated capture. Sealing moves no bytes:
/// the host write-protects each volume's dirty set and answers, and its
/// checkpoint uploads those frames once the guest has resumed.
///
/// Callers name owners per guest region, and guest RAM's regions share one
/// owner, so a volume named more than once is sealed once.
///
/// The host's deadline is the only one that decides a seal; see SEAL_BACKSTOP.
pub fn seal_regions(owners: Vec<Arc<Owner>>) -> io::Result<()> {
    let mut sealing: Vec<Arc<Owner>> = Vec::with_capacity(owners.len());
    for owner in owners {
        if !sealing.iter().any(|held| Arc::ptr_eq(held, &owner)) {
            sealing.push(owner);
        }
    }
    seal_all(
        sealing.iter().map(|owner| owner.control.start_seal()),
        |request| request.wait(SEAL_BACKSTOP),
    )
}

/// Starts every seal before waiting on any, so independently owned volumes seal
/// concurrently rather than one after another, and waits out every request it
/// did start even when a later one will not start at all.
///
/// A seal that will not start is one region's failure and the capture fails with
/// it, but the requests already in flight belong to sessions of their own:
/// dropping a PendingSeal without observing its completion closes its control
/// session, which ends that session's service thread and with it this whole
/// process. Returning early would kill the guest over a checkpoint that merely
/// could not be taken.
fn seal_all<H>(
    starts: impl Iterator<Item = io::Result<H>>,
    wait: impl Fn(H) -> io::Result<()>,
) -> io::Result<()> {
    let mut started = Vec::new();
    let mut result = Ok(());
    for start in starts {
        match start {
            Ok(handle) => started.push(handle),
            Err(err) => {
                result = Err(err);
                break;
            }
        }
    }
    for handle in started {
        if let Err(err) = wait(handle)
            && result.is_ok()
        {
            result = Err(err);
        }
    }
    result
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.control.disconnect();
        if let Some(service) = self.service.get_mut().unwrap().take() {
            // The returned Session retains the mappings until this join ends.
            drop(service.join().expect("managed memory service panicked"));
        }
    }
}

/// One guest region's bytes inside the RAM volume: where the guest sees them
/// and the volume offset they start at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VolumeRange {
    guest: GuestAddress,
    offset: usize,
    len: usize,
}

/// Places a memory size's guest regions in the one RAM volume, in ascending
/// guest order.
///
/// A managed VM has one RAM volume, which is one contiguous byte range; the
/// guest's physical address space is not contiguous, because the architecture
/// reserves holes in it for MMIO. On x86_64 the largest is 3 GiB to 4 GiB, so
/// any VM with more than 3 GiB of RAM sees two regions. The volume does not
/// carry those holes: it is the guest's RAM concatenated, so volume offset
/// 3 GiB is guest address 4 GiB, on every path the volume takes -- fault, seal,
/// checkpoint, restore, fork and migration. On aarch64 RAM below 256 GiB is one
/// region and the volume is that region.
///
/// The layout must be exactly the one this architecture gives that size. A
/// snapshot restored onto a different split would otherwise read every byte
/// past the first hole from the wrong volume offset.
fn volume_ranges(layout: &[(GuestAddress, usize)]) -> io::Result<Vec<VolumeRange>> {
    let refuse = |reason: &str| io::Error::new(io::ErrorKind::Unsupported, reason.to_owned());
    let total = layout
        .iter()
        .try_fold(0usize, |total, (_, len)| total.checked_add(*len))
        .filter(|total| *total > 0)
        .ok_or_else(|| refuse("managed RAM is an empty or overlong memory size"))?;
    if layout != crate::arch::arch_memory_regions(total).as_slice() {
        return Err(refuse(
            "managed RAM layout is not this architecture's layout for its size",
        ));
    }
    let mut offset = 0;
    let mut ranges = Vec::with_capacity(layout.len());
    for &(guest, len) in layout {
        if len % sproutfs_vm_memory::PAGE_SIZE != 0
            || guest.0 % sproutfs_vm_memory::PAGE_SIZE as u64 != 0
        {
            return Err(refuse(
                "managed RAM regions must be whole pager pages at page-aligned guest addresses",
            ));
        }
        ranges.push(VolumeRange { guest, offset, len });
        offset += len;
    }
    Ok(ranges)
}

/// Allocates the guest's RAM through the pager, without copying a whole backing
/// image or creating anonymous guest data pages.
///
/// One volume and one session serve every guest region: the session maps the
/// volume once, and each guest region wraps the part of that mapping
/// [`volume_ranges`] gives it.
pub fn ram(
    config: &ManagedMemoryConfig,
    layout: &[(GuestAddress, usize)],
    track_dirty: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let ranges = volume_ranges(layout).map_err(MemoryError::Managed)?;
    let len = ranges.iter().map(|range| range.len).sum();
    let owner = Owner::connect(
        &config.socket_path,
        RegionSpec {
            kind: RegionKind::Ram,
            len,
        },
    )
    .map_err(MemoryError::Managed)?;
    let region = owner.region();
    ranges
        .into_iter()
        .map(|range| {
            GuestRegionMmap::managed(
                range.guest,
                region.address + range.offset,
                range.len,
                owner.clone(),
                track_dirty,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{MMIO64_MEM_SIZE, MMIO64_MEM_START, arch_memory_regions};

    const GIB: usize = 1 << 30;

    /// A seal handle that records whether it was waited on. Dropping a real
    /// PendingSeal without observing its completion closes the control session,
    /// which ends its service thread and with it the whole VMM process.
    struct Handle<'a> {
        id: usize,
        waited: &'a std::cell::RefCell<Vec<usize>>,
        abandoned: &'a std::cell::Cell<usize>,
        finished: bool,
    }

    impl Drop for Handle<'_> {
        fn drop(&mut self) {
            if !self.finished {
                self.abandoned.set(self.abandoned.get() + 1);
            }
        }
    }

    /// A seal that will not start is one region's failure, and the capture
    /// fails with it. The seals already started are requests in flight on their
    /// own sessions: abandoning them closes those sessions and kills the guest
    /// over a checkpoint that merely could not be taken, so every one of them is
    /// waited out first.
    #[test]
    fn a_seal_that_cannot_start_still_waits_out_the_ones_that_did() {
        let waited = std::cell::RefCell::new(Vec::new());
        let abandoned = std::cell::Cell::new(0);
        let refused = || io::Error::other("this session will not start a seal");
        let starts = (0..3).map(|id| {
            if id == 2 {
                Err(refused())
            } else {
                Ok(Handle {
                    id,
                    waited: &waited,
                    abandoned: &abandoned,
                    finished: false,
                })
            }
        });
        let result = seal_all(starts, |mut handle| {
            handle.finished = true;
            handle.waited.borrow_mut().push(handle.id);
            Ok(())
        });
        assert_eq!(result.unwrap_err().to_string(), refused().to_string());
        assert_eq!(*waited.borrow(), vec![0, 1]);
        assert_eq!(abandoned.get(), 0, "an unfinished seal was dropped");
    }

    /// The whole point of starting every seal before waiting on any is that
    /// independently owned volumes seal at the same time.
    #[test]
    fn every_seal_starts_before_any_is_waited_on() {
        let waited = std::cell::RefCell::new(Vec::new());
        let abandoned = std::cell::Cell::new(0);
        let started = std::cell::Cell::new(0);
        let starts = (0..3).map(|id| {
            started.set(started.get() + 1);
            assert!(waited.borrow().is_empty(), "a seal was waited on mid-start");
            Ok(Handle {
                id,
                waited: &waited,
                abandoned: &abandoned,
                finished: false,
            })
        });
        seal_all(starts, |mut handle| {
            handle.finished = true;
            handle.waited.borrow_mut().push(handle.id);
            Ok(())
        })
        .unwrap();
        assert_eq!(started.get(), 3);
        assert_eq!(*waited.borrow(), vec![0, 1, 2]);
        assert_eq!(abandoned.get(), 0);
    }

    /// The guest address the volume's byte at `offset` is read and written at.
    fn guest_of(ranges: &[VolumeRange], offset: usize) -> GuestAddress {
        let range = ranges
            .iter()
            .find(|range| offset >= range.offset && offset - range.offset < range.len)
            .expect("offset is outside the volume");
        GuestAddress(range.guest.0 + (offset - range.offset) as u64)
    }

    /// Every range is whole pages of the volume, they cover it once in
    /// ascending guest order, and they total the memory size.
    fn check_covers(ranges: &[VolumeRange], size: usize) {
        let mut offset = 0;
        let mut guest_end = 0;
        for range in ranges {
            assert_eq!(range.offset, offset);
            assert!(range.len > 0 && range.len % sproutfs_vm_memory::PAGE_SIZE == 0);
            assert!(range.guest.0 >= guest_end);
            offset += range.len;
            guest_end = range.guest.0 + range.len as u64;
        }
        assert_eq!(offset, size);
    }

    #[test]
    fn a_size_below_the_first_hole_is_one_range() {
        let size = GIB;
        let ranges = volume_ranges(&arch_memory_regions(size)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, size);
        check_covers(&ranges, size);
    }

    #[test]
    fn a_size_spanning_the_64_bit_hole_skips_it() {
        let size = usize::try_from(MMIO64_MEM_START).unwrap() + GIB;
        let ranges = volume_ranges(&arch_memory_regions(size)).unwrap();
        check_covers(&ranges, size);
        assert!(ranges.len() > 1, "the hole splits this size");
        let past = *ranges.last().unwrap();
        assert_eq!(past.guest.0, MMIO64_MEM_START + MMIO64_MEM_SIZE);
        assert_eq!(guest_of(&ranges, past.offset).0, past.guest.0);
        assert_eq!(guest_of(&ranges, past.offset + 4096).0, past.guest.0 + 4096);
        assert_eq!(
            guest_of(&ranges, past.offset - 1).0,
            MMIO64_MEM_START - 1,
            "the volume ends the region below the hole where the hole begins"
        );
    }

    #[test]
    fn a_layout_this_architecture_would_not_produce_is_refused() {
        let size = 4 * GIB;
        let mut layout = arch_memory_regions(size);
        let (first, len) = layout[0];
        layout[0] = (first, len - sproutfs_vm_memory::PAGE_SIZE);
        layout.push((
            GuestAddress(first.0 + len as u64 - sproutfs_vm_memory::PAGE_SIZE as u64),
            sproutfs_vm_memory::PAGE_SIZE,
        ));
        assert_eq!(
            volume_ranges(&layout).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn an_empty_layout_is_refused() {
        assert_eq!(
            volume_ranges(&[]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    /// More than 3 GiB of RAM is two guest regions, and the volume is the two
    /// of them joined: volume offset 3 GiB is guest address 4 GiB.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ram_past_the_32_bit_hole_continues_the_volume() {
        use crate::arch::{FIRST_ADDR_PAST_32BITS, MMIO32_MEM_START};

        let size = 4 * GIB;
        let ranges = volume_ranges(&arch_memory_regions(size)).unwrap();
        check_covers(&ranges, size);
        let below = usize::try_from(MMIO32_MEM_START).unwrap();
        assert_eq!(
            ranges,
            vec![
                VolumeRange {
                    guest: GuestAddress(0),
                    offset: 0,
                    len: below,
                },
                VolumeRange {
                    guest: GuestAddress(FIRST_ADDR_PAST_32BITS),
                    offset: below,
                    len: size - below,
                },
            ]
        );
        assert_eq!(guest_of(&ranges, below).0, FIRST_ADDR_PAST_32BITS);
        assert_eq!(
            guest_of(&ranges, below + 12345).0,
            FIRST_ADDR_PAST_32BITS + 12345
        );
        assert_eq!(guest_of(&ranges, below - 1).0, MMIO32_MEM_START - 1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ram_up_to_the_32_bit_hole_is_one_range() {
        let size = usize::try_from(crate::arch::MMIO32_MEM_START).unwrap();
        let ranges = volume_ranges(&arch_memory_regions(size)).unwrap();
        assert_eq!(ranges.len(), 1);
        check_covers(&ranges, size);
    }

    /// aarch64 has no hole below 256 GiB, so RAM is one region beginning at the
    /// start of DRAM and the volume is exactly that region.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn ram_past_4_gib_is_still_one_range() {
        use crate::arch::DRAM_MEM_START;

        let size = 8 * GIB;
        let ranges = volume_ranges(&arch_memory_regions(size)).unwrap();
        assert_eq!(
            ranges,
            vec![VolumeRange {
                guest: GuestAddress(DRAM_MEM_START),
                offset: 0,
                len: size,
            }]
        );
        assert_eq!(guest_of(&ranges, 12345).0, DRAM_MEM_START + 12345);
    }
}
