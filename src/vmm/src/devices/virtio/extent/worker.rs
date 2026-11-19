// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The extent device's queues as cladefs's `virtio_extent` takes requests off them: Firecracker's
//! `Queue`, its chains' descriptors as the request's buffers, in guest memory, and its MSI-X
//! vector. The crate's workers serve them.

use std::sync::Arc;

use virtio_extent::{BoxError, Buffers, BuffersError, Popped};
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemoryBackend, GuestMemoryError};

use crate::devices::virtio::queue::{DescriptorChain, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::vstate::memory::GuestMemoryMmap;

/// A request queue of the device's, in its guest's memory.
#[derive(Debug)]
pub(super) struct ExtentQueue {
    pub(super) queue: Queue,
    mem: GuestMemoryMmap,
}

impl ExtentQueue {
    pub(super) fn new(queue: Queue, mem: GuestMemoryMmap) -> Self {
        Self { queue, mem }
    }
}

impl virtio_extent::RequestQueue for ExtentQueue {
    // cladefs: with EVENT_IDX, the driver notifies again only once the queue is taken empty, which
    // this rechecks after asking to be notified.
    fn pop(&mut self) -> Result<Option<Popped>, BoxError> {
        let Some(chain) = self.queue.pop_or_enable_notification()? else {
            return Ok(None);
        };
        let index = chain.index;
        let buffers = buffers(&self.mem, chain).map_err(BoxError::from);
        Ok(Some(Popped { index, buffers }))
    }

    fn complete(&mut self, index: u16, len: u32) -> Result<bool, BoxError> {
        self.queue.add_used(index, len)?;
        self.queue.advance_used_ring_idx();
        Ok(self.queue.prepare_kick())
    }
}

/// A queue's MSI-X vector.
pub(super) struct QueueVector {
    pub(super) interrupt: Arc<dyn VirtioInterrupt>,
    pub(super) index: u16,
}

impl virtio_extent::QueueInterrupt for QueueVector {
    fn notify(&self) -> Result<(), BoxError> {
        self.interrupt
            .trigger(VirtioInterruptType::Queue(self.index))
            .map_err(|err| format!("{err}").into())
    }
}

/// Why a descriptor chain is no request's buffers.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum ChainError {
    /// a descriptor chain is not guest memory: {0}
    Memory(#[from] GuestMemoryError),
    /// {0}
    Buffers(#[from] BuffersError),
}

/// The buffers of the request in `chain`, all in `mem`, in the descriptors' order. The writable
/// ones are marked dirty, as the device writes them whole.
fn buffers(mem: &GuestMemoryMmap, chain: DescriptorChain) -> Result<Buffers, ChainError> {
    let mut buffers = Buffers::new();
    for descriptor in chain {
        let len = descriptor.len as usize;
        let slice = mem.get_slice(descriptor.addr, len)?;
        let ptr = slice.ptr_guard_mut().as_ptr();
        if descriptor.is_write_only() {
            // SAFETY: Guest memory, mapped while the device is active, and so while the requests
            // its workers took are served (the crate's workers wait for them as they stop), which
            // only the request writes, as the driver gave it the device to write.
            unsafe { buffers.push_writable(ptr, len) }?;
            slice.bitmap().mark_dirty(0, len);
        } else {
            // SAFETY: As above, which the request reads.
            unsafe { buffers.push_readable(ptr, len) };
        }
    }
    Ok(buffers)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    //! The adapter's half of a request: its descriptors as its buffers, and the used ring. What
    //! the device makes of a request is cladefs's `virtio_extent`'s, which tests it apart from any
    //! VMM.

    use virtio_extent::RequestQueue;

    use super::*;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::VirtQueue;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Bytes, GuestAddress};

    /// cladefs TASK-79.25: a chain whose descriptors give the device more bytes to write than a
    /// u32 holds, naming the same memory again and again, is refused, not served: its used
    /// length couldn't say what the device wrote, which aborted the VMM.
    #[test]
    fn chains_writing_past_u32_are_refused() {
        const LEN: u32 = 0x6000_0000;
        let mem = single_region_mem(LEN as usize);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let mut queue = vq.create_queue();
        for i in 0..3 {
            let next = if i < 2 { VIRTQ_DESC_F_NEXT } else { 0 };
            vq.dtable[i].set(0, LEN, VIRTQ_DESC_F_WRITE | next, (i + 1) as u16);
        }
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        let chain = queue.pop().unwrap().unwrap();
        let refused = buffers(&mem, chain).unwrap_err();
        assert!(
            matches!(
                refused,
                ChainError::Buffers(BuffersError::TooLong(0x1_2000_0000))
            ),
            "{refused}"
        );
    }

    /// A chain's descriptors are its buffers, in order, readable and writable as they say: the
    /// request's header is its first bytes, wherever the descriptors split them; returned, it is
    /// on the used ring with the length the device wrote.
    #[test]
    fn chains_are_buffers_in_order_and_returned_used() {
        let mem = single_region_mem(1 << 20);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let mut queue = vq.create_queue();
        let header = [4u8, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0];
        mem.write_slice(&header[..5], GuestAddress(0x1_0000))
            .unwrap();
        mem.write_slice(&header[5..], GuestAddress(0x2_0000))
            .unwrap();
        let descriptors = [
            (0x1_0000, 5, VIRTQ_DESC_F_NEXT),
            (0x2_0000, 11, VIRTQ_DESC_F_NEXT),
            (0x3_0000, 24, VIRTQ_DESC_F_WRITE),
        ];
        for (i, (addr, len, flags)) in descriptors.into_iter().enumerate() {
            vq.dtable[i].set(addr, len, flags, (i + 1) as u16);
        }
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        let mut queue = ExtentQueue::new(queue, mem.clone());
        let popped = queue.pop().unwrap().unwrap();
        let buffers = popped.buffers.unwrap();
        let read = buffers.header().unwrap();
        assert_eq!((popped.index, read.type_, read.unique), (0, 4, 9));
        assert_eq!(buffers.writable_len(), 24);
        assert!(queue.pop().unwrap().is_none());
        queue.complete(popped.index, 24).unwrap();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, 24);
    }
}
