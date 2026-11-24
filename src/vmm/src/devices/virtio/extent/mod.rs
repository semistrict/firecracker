// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The virtio extent-store device: cladefs's backlog doc-4, which specifies it.
//!
//! A guest that runs Fxfs itself stores its filesystem through this device, as extents its Fxfs
//! names: immutable pieces of data, written once and sealed by the next commit, freed whole, and
//! a root naming where the filesystem starts. cladefs's extent daemon, which the device connects
//! to, keeps them in an cladefs extent store on local disk, and maps sealed extents into the
//! device's DAX window, its shared memory region 0, from its cache of their pages, which the
//! host's VMs share.
//!
//! The device is cladefs's `virtio_extent` crate, which every VMM hosting it shares: its protocol,
//! the handling of its requests, its notices, its window and its snapshots. This is Firecracker's
//! adapter, what the crate's README asks of one: the virtio-PCI transport and its queues, the
//! window's BAR and memory slot ([`window`]), `KVM_PRE_FAULT_MEMORY`, the threads its requests
//! are taken on ([`worker`]), and the device in Firecracker's snapshots ([`persist`]).

pub mod device;
pub mod persist;
mod window;
mod worker;

use std::sync::Arc;

pub use virtio_extent::protocol::QUEUE_SIZE as EXTENT_QUEUE_SIZE;
pub use virtio_extent::{PrefaultGuestMemory, dax_window_at};

pub use self::device::{Extent, ExtentError};
#[cfg(target_arch = "x86_64")]
pub use self::window::KvmPrefault;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};

/// The device's request queues, interchangeable, which a driver may use one per CPU of (cladefs
/// TASK-26.18.5): as many as its VM has vCPUs ([`request_queues`]), each with an MSI-X vector and a
/// worker of its own, so that no two of the guest's CPUs share one; 4, whatever the VM, before
/// (TASK-276). At most as many as a VM has vCPUs at most.
pub const EXTENT_MAX_QUEUES: usize = crate::vstate::vm::MAX_SUPPORTED_KVM_VCPUS as usize;

/// cladefs: the request queues of the device of a VM of `vcpus` vCPUs: one each, one at least, and
/// [`EXTENT_MAX_QUEUES`] at most (TASK-276).
pub fn request_queues(vcpus: u16) -> usize {
    usize::from(vcpus).clamp(1, EXTENT_MAX_QUEUES)
}

/// The device's configuration change interrupt, as its transport raises it: what tells the guest
/// of the extent daemon's notices.
struct ConfigInterrupt(Arc<dyn VirtioInterrupt>);

impl virtio_extent::ConfigInterrupt for ConfigInterrupt {
    fn config_changed(&self) -> Result<(), virtio_extent::BoxError> {
        self.0
            .trigger(VirtioInterruptType::Config)
            .map_err(|err| format!("{err:?}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cladefs TASK-276: a queue per vCPU, one at least, as many as a VM has vCPUs at most.
    #[test]
    fn a_queue_per_vcpu() {
        assert_eq!(request_queues(0), 1);
        assert_eq!(request_queues(1), 1);
        assert_eq!(request_queues(2), 2);
        assert_eq!(request_queues(8), 8);
        assert_eq!(request_queues(32), 32);
        assert_eq!(request_queues(33), EXTENT_MAX_QUEUES);
        assert_eq!(EXTENT_MAX_QUEUES, 32);
    }

    /// cladefs TASK-111.4: the transport's configuration change interrupt is what the device's
    /// notices raise.
    #[test]
    fn notices_raise_the_configuration_interrupt() {
        use virtio_extent::ConfigInterrupt as _;

        use crate::devices::virtio::test_utils::default_interrupt;
        let interrupt = default_interrupt();
        ConfigInterrupt(interrupt.clone()).config_changed().unwrap();
        assert!(interrupt.has_pending_interrupt(VirtioInterruptType::Config));
    }
}
