// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! What only Firecracker can do for the extent device's DAX window (fxdax's
//! `virtio_extent::WindowVm`): its guest physical addresses in the 64-bit MMIO gap, the PCI host
//! bridge's window, a BAR of the device's own that the PCI transport describes with a shared
//! memory capability; and the KVM memory slot mapping the window's host memory there.
//!
//! KVM maps a page of the window into its second-stage tables on the guest's first access to it,
//! an exit per page, which nested virtualization makes slow: on x86-64, given a [`KvmPrefault`],
//! the window has KVM map the pages as the daemon maps them.

use std::ptr::NonNull;
use std::sync::Arc;

use vm_allocator::{AllocPolicy, RangeInclusive};

use crate::devices::virtio::transport::pci::device::shm_bar_size;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

/// A VM's guest physical address space and memory slots, as an extent device's window has them.
#[derive(Debug)]
pub(super) struct ExtentVm {
    vm: Arc<KvmVm>,
}

impl ExtentVm {
    pub(super) fn new(vm: Arc<KvmVm>) -> Self {
        Self { vm }
    }
}

impl virtio_extent::WindowVm for ExtentVm {
    /// The window's BAR, in the 64-bit MMIO gap: a power of two in size, the window's length
    /// rounded up, and aligned to it, as BARs are; the guest finds it there, as Firecracker
    /// relocates no BAR. Restored from a snapshot, where it was, which the VM's resource
    /// allocator, restored too, holds as allocated already.
    fn reserve(&self, len: u64, at: Option<u64>) -> Result<u64, virtio_extent::BoxError> {
        match at {
            Some(start) => Ok(start),
            None => Ok(allocate_bar(&mut self.vm.resource_allocator(), len)?),
        }
    }

    fn release(&self, start: u64, len: u64) {
        free_bar(&mut self.vm.resource_allocator(), start, len);
    }

    fn add_slot(
        &self,
        guest_addr: u64,
        len: u64,
        host: NonNull<u8>,
    ) -> Result<u32, virtio_extent::BoxError> {
        Ok(self
            .vm
            .add_memory_slot(guest_addr, len, host.as_ptr() as u64, 0)?)
    }

    fn remove_slot(&self, slot: u32) {
        self.vm.remove_memory_slot(slot);
    }
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

/// Frees the BAR [`allocate_bar`] allocated for the window of `len` bytes at `start`.
fn free_bar(allocator: &mut ResourceAllocator, start: u64, len: u64) {
    let range = RangeInclusive::new(start, start + shm_bar_size(len) - 1)
        .expect("Invalid DAX window range");
    _ = allocator.mmio64_memory.free(&range);
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
    use virtio_extent::PrefaultGuestMemory;

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

        let bar = allocate_bar(&mut allocator, len).unwrap();
        assert_eq!(bar, allocator.mmio64_memory.base() + (128 << 30));
        assert_eq!(bar % (128 << 30), 0);
        // Another, which the first's rounding up leaves no room for in the gap.
        allocate_bar(&mut allocator, len).unwrap_err();
        // A small one, in what the first left before it.
        let small = allocate_bar(&mut allocator, 2 << 20).unwrap();
        assert_eq!(small, allocator.mmio64_memory.base() + (2 << 20));

        free_bar(&mut allocator, bar, len);
        assert_eq!(allocate_bar(&mut allocator, len).unwrap(), bar);
    }
}
