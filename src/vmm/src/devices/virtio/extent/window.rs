// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent device's DAX window: guest physical addresses in the 64-bit MMIO gap, the PCI host
//! bridge's window, a BAR of the device's own that the PCI transport describes with a shared
//! memory capability, backed by anonymous host memory that KVM follows. fxdax's extent daemon owns
//! the window: the device hands the host memory to the store's connection, which maps the
//! window's pages there from the daemon's memory, and serves the faults KVM takes on the rest.
//!
//! KVM maps a page of the window into its second-stage tables on the guest's first access to it,
//! an exit per page, which nested virtualization makes slow: on x86-64, given a [`KvmPrefault`],
//! the window has KVM map the pages as the daemon maps them.

use std::io;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use vm_allocator::{AllocPolicy, RangeInclusive};

use crate::devices::virtio::transport::pci::device::shm_bar_size;
use crate::utils::u64_to_usize;
use crate::vmm_config::extent::DAX_WINDOW_ALIGNMENT;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::{KvmMemSlot, KvmVm, VmError};

/// The window's guest physical addresses, a BAR's in the 64-bit MMIO gap: a power of two in size,
/// the window's length rounded up, and aligned to it, as BARs are; the guest finds it there, as
/// Firecracker relocates no BAR. Freed on drop.
#[derive(Debug)]
struct GuestRange {
    vm: Arc<KvmVm>,
    start: u64,
    /// The window's length.
    len: u64,
}

impl GuestRange {
    fn allocate(vm: Arc<KvmVm>, len: u64) -> Result<Self, vm_allocator::Error> {
        let start = Self::allocate_bar(&mut vm.resource_allocator(), len)?;
        Ok(Self { vm, start, len })
    }

    /// The range at `start`, which the VM's resource allocator, restored from a snapshot, holds
    /// as allocated already.
    fn restored(vm: Arc<KvmVm>, start: u64, len: u64) -> Self {
        Self { vm, start, len }
    }

    /// Allocates the BAR of a window of `len` bytes from `allocator`'s 64-bit MMIO gap: where it
    /// starts.
    fn allocate_bar(allocator: &mut ResourceAllocator, len: u64) -> Result<u64, vm_allocator::Error> {
        let size = shm_bar_size(len);
        Ok(allocator
            .mmio64_memory
            .allocate(size, size, AllocPolicy::FirstMatch)?
            .start())
    }

    /// Frees the BAR [`GuestRange::allocate_bar`] allocated for the window of `len` bytes at
    /// `start`.
    fn free_bar(allocator: &mut ResourceAllocator, start: u64, len: u64) {
        let range = RangeInclusive::new(start, start + shm_bar_size(len) - 1)
            .expect("Invalid DAX window range");
        _ = allocator.mmio64_memory.free(&range);
    }
}

impl Drop for GuestRange {
    fn drop(&mut self) {
        Self::free_bar(&mut self.vm.resource_allocator(), self.start, self.len);
    }
}

/// Anonymous host memory of the window's size, aligned as the window is, so that KVM maps it
/// for the guest with huge pages where the daemon's are. Unmapped on drop. fxdax: inaccessible
/// until the store's connection takes it over, as once it lets it go (TASK-79.8): a guest's
/// accesses meanwhile, as before it sets DRIVER_OK, fault, rather than growing its VMM's memory by
/// the window's size.
#[derive(Debug)]
struct HostMemory {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: The mapping is only an address range, which the store's connection maps pages into.
unsafe impl Send for HostMemory {}

impl HostMemory {
    fn map(len: usize) -> io::Result<Self> {
        let align = u64_to_usize(DAX_WINDOW_ALIGNMENT);
        let reserved = len + align;
        // SAFETY: A new anonymous mapping, whose result is checked.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                reserved,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // The aligned part, unmapping what is around it.
        let start = ptr as usize;
        let base = start.next_multiple_of(align);
        let head = base - start;
        let tail = reserved - head - len;
        // SAFETY: Both are parts of the mapping just made, outside the part kept.
        unsafe {
            if head > 0 {
                libc::munmap(ptr, head);
            }
            if tail > 0 {
                libc::munmap((base + len) as *mut libc::c_void, tail);
            }
        }
        Ok(Self {
            base: NonNull::new(base as *mut u8).expect("mmap returned a null mapping"),
            len,
        })
    }
}

impl Drop for HostMemory {
    fn drop(&mut self) {
        // SAFETY: The mapping is this one's, which nothing uses once it is dropped.
        unsafe {
            libc::munmap(self.base.as_ptr().cast(), self.len);
        }
    }
}

/// Errors making the DAX window.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DaxWindowError {
    /// The DAX window's size, {0:#x} bytes, is not a nonzero multiple of 2 MiB
    Size(u64),
    /// Cannot allocate guest addresses for the DAX window: {0}
    GuestAddresses(#[from] vm_allocator::Error),
    /// Cannot map host memory for the DAX window: {0}
    HostMemory(#[from] io::Error),
    /// Cannot map the DAX window into the guest: {0}
    KvmMemSlot(#[from] VmError),
}

/// The DAX window: its guest physical addresses, and the host memory KVM maps there.
#[derive(Debug)]
pub(super) struct DaxWindow {
    // In the order they are dropped in: KVM lets go of the host memory before it is unmapped, and
    // the guest addresses are freed last.
    _slot: KvmMemSlot,
    host: HostMemory,
    guest: GuestRange,
}

impl DaxWindow {
    /// A window of `len` bytes, a multiple of 2 MiB, mapped into `vm`'s guest.
    pub(super) fn new(vm: Arc<KvmVm>, len: u64) -> Result<Self, DaxWindowError> {
        if len == 0 || !len.is_multiple_of(DAX_WINDOW_ALIGNMENT) {
            return Err(DaxWindowError::Size(len));
        }
        let guest = GuestRange::allocate(vm.clone(), len)?;
        Self::in_range(vm, guest)
    }

    /// The window of `len` bytes at `guest_addr` in guest memory, where a snapshot the VM is
    /// restored from had it, whose addresses the VM's resource allocator holds already.
    pub(super) fn at(vm: Arc<KvmVm>, guest_addr: u64, len: u64) -> Result<Self, DaxWindowError> {
        if len == 0 || !len.is_multiple_of(DAX_WINDOW_ALIGNMENT) {
            return Err(DaxWindowError::Size(len));
        }
        let guest = GuestRange::restored(vm.clone(), guest_addr, len);
        Self::in_range(vm, guest)
    }

    fn in_range(vm: Arc<KvmVm>, guest: GuestRange) -> Result<Self, DaxWindowError> {
        let host = HostMemory::map(u64_to_usize(guest.len))?;
        let slot = KvmMemSlot::new(vm, guest.start, guest.len, host.base.as_ptr() as u64, 0)?;
        WINDOWS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((guest.start, guest.len, host.base.as_ptr() as usize));
        Ok(Self {
            _slot: slot,
            host,
            guest,
        })
    }

    /// The guest physical address the window starts at.
    pub(super) fn guest_addr(&self) -> u64 {
        self.guest.start
    }

    /// The window's length in bytes.
    pub(super) fn len(&self) -> u64 {
        self.guest.len
    }

    /// The host memory KVM maps into the guest, which the store's connection takes over.
    pub(super) fn host_memory(&self) -> NonNull<u8> {
        self.host.base
    }
}

impl Drop for DaxWindow {
    fn drop(&mut self) {
        let mut windows = WINDOWS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let this = (
            self.guest.start,
            self.guest.len,
            self.host.base.as_ptr() as usize,
        );
        windows.retain(|window| *window != this);
    }
}

/// fxdax: the DAX windows of this process's guest, as their guest physical addresses, lengths
/// and host memory: where a vCPU whose access keeps failing finds what it failed at
/// ([`dax_window_at`]).
static WINDOWS: Mutex<Vec<(u64, u64, usize)>> = Mutex::new(Vec::new());

/// fxdax: the DAX window guest physical address `gpa` is in, if any: its offset there, and the
/// host address KVM maps there, which fxdax's second stage of the window is in
/// (`fxdax::describe_windows`).
pub fn dax_window_at(gpa: u64) -> Option<(u64, usize)> {
    let windows = WINDOWS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let within = |&&(start, len, _): &&(u64, u64, usize)| (start..start + len).contains(&gpa);
    let &(start, _, host) = windows.iter().find(within)?;
    let offset = gpa - start;
    Some((offset, host + u64_to_usize(offset)))
}

/// Maps guest memory for the guest ahead of its accesses, as KVM's `KVM_PRE_FAULT_MEMORY` does,
/// rather than on a fault on each page.
pub trait PrefaultGuestMemory: std::fmt::Debug + Send + Sync {
    /// Maps the `len` bytes of guest memory at `guest_addr`, which the host has mapped, for the
    /// guest. It must not wait for the guest.
    fn prefault(&self, guest_addr: u64, len: u64);
}

/// Has `prefault` map the pages the store maps into the window, at the window's guest address.
pub(super) struct WindowPrefault {
    pub(super) guest_addr: u64,
    pub(super) prefault: Arc<dyn PrefaultGuestMemory>,
}

impl fxdax::Prefault for WindowPrefault {
    fn prefault(&self, offset: u64, len: u64) {
        self.prefault.prefault(self.guest_addr + offset, len);
    }
}

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::KvmPrefault;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    // KVM's mapping of guest memory for the guest ahead of its accesses
    // (`KVM_PRE_FAULT_MEMORY`). It is a vCPU ioctl, which waits for the vCPU to leave `KVM_RUN`,
    // so a vCPU of its own does it, which the guest does not know of and which never runs. vCPUs
    // share the second-stage tables of the guest's memory, while none is in SMM or nested guest
    // mode.

    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};

    use kvm_ioctls::VcpuFd;

    use super::PrefaultGuestMemory;
    use crate::logger::warn;
    use crate::vstate::vm::KvmVm;

    // From `include/uapi/linux/kvm.h`.
    const KVM_CAP_PRE_FAULT_MEMORY: libc::c_ulong = 236;
    #[allow(clippy::cast_possible_truncation)]
    const KVM_PRE_FAULT_MEMORY: libc::c_ulong =
        (3 << 30) | ((size_of::<KvmPreFaultMemory>() as libc::c_ulong) << 16) | (0xae << 8) | 0xd5;

    #[repr(C)]
    struct KvmPreFaultMemory {
        gpa: u64,
        size: u64,
        flags: u64,
        padding: [u64; 5],
    }

    /// Maps guest memory for the guest with a vCPU of its own.
    #[derive(Debug)]
    pub struct KvmPrefault {
        vcpu: VcpuFd,
        /// Whether a failure has been logged, which is logged only once.
        failed: AtomicBool,
    }

    impl KvmPrefault {
        /// A vCPU of `vm`'s, with id `id`, which no vCPU of the guest's has, for mapping guest
        /// memory ahead of the guest; or none if KVM cannot.
        pub fn new(vm: &KvmVm, id: u64) -> io::Result<Option<Self>> {
            if vm.fd().check_extension_raw(KVM_CAP_PRE_FAULT_MEMORY) <= 0 {
                return Ok(None);
            }
            let vcpu = vm.fd().create_vcpu(id).map_err(io::Error::other)?;
            // The second-stage tables' depth follows the guest's physical address width, which
            // the vCPU's CPUID sets.
            vcpu.set_cpuid2(&vm.kvm().supported_cpuid)
                .map_err(io::Error::other)?;
            Ok(Some(Self {
                vcpu,
                failed: AtomicBool::new(false),
            }))
        }
    }

    impl PrefaultGuestMemory for KvmPrefault {
        fn prefault(&self, guest_addr: u64, len: u64) {
            let mut range = KvmPreFaultMemory {
                gpa: guest_addr,
                size: len,
                flags: 0,
                padding: [0; 5],
            };
            // KVM maps what it can and updates the range to what is left, which a signal, or
            // contention, can leave.
            while range.size > 0 {
                // SAFETY: Passes the vCPU's ioctl the structure it takes, which it updates.
                let ret = unsafe {
                    libc::ioctl(
                        self.vcpu.as_raw_fd(),
                        KVM_PRE_FAULT_MEMORY as _,
                        &mut range as *mut KvmPreFaultMemory,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EINTR | libc::EAGAIN) => continue,
                        // The guest faults on what is left as it would have.
                        _ => {
                            if !self.failed.swap(true, Ordering::Relaxed) {
                                warn!(
                                    "pre-faulting guest memory at {:#x}, {:#x} bytes: {err}",
                                    range.gpa, range.size
                                );
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window's addresses are a BAR's, in the 64-bit MMIO gap, its length rounded up to a power
    /// of two and aligned to it, after the BARs allocated before it; freed whole, they are
    /// allocated again where they were.
    #[test]
    fn windows_are_bars_in_the_mmio64_gap() {
        let mut allocator = ResourceAllocator::new();
        // The capability BAR of a device attached before, which takes the gap's first bytes.
        allocator
            .mmio64_memory
            .allocate(0x80000, 0x80000, AllocPolicy::FirstMatch)
            .unwrap();
        let len = (64 << 30) + (2 << 20);

        let bar = GuestRange::allocate_bar(&mut allocator, len).unwrap();
        assert_eq!(bar, allocator.mmio64_memory.base() + (128 << 30));
        assert_eq!(bar % (128 << 30), 0);
        // Another, which the first's rounding up leaves no room for in the gap.
        GuestRange::allocate_bar(&mut allocator, len).unwrap_err();
        // A small one, in what the first left before it.
        let small = GuestRange::allocate_bar(&mut allocator, 2 << 20).unwrap();
        assert_eq!(small, allocator.mmio64_memory.base() + (2 << 20));

        GuestRange::free_bar(&mut allocator, bar, len);
        assert_eq!(GuestRange::allocate_bar(&mut allocator, len).unwrap(), bar);
    }
}
