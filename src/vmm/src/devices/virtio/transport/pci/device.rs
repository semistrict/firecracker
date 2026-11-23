// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use kvm_ioctls::{IoEventAddress, NoDatamatch};
use serde::{Deserialize, Serialize};
use vm_allocator::{AddressAllocator, AllocPolicy, RangeInclusive};
use vm_memory::{ByteValued, Le32};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use zerocopy::IntoBytes;

use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType, VirtioShmRegion};
use crate::devices::virtio::transport::pci::common_config::{
    VirtioPciCommonConfig, VirtioPciCommonConfigState,
};
use crate::devices::virtio::transport::pci::device_status::*;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{debug, error, warn};
use crate::pci::configuration::{
    BAR0_REG_IDX, BarPrefetchable, Bars, NUM_BAR_REGS, PciCapability, PciConfiguration,
    PciConfigurationError, PciConfigurationState,
};
use crate::pci::msix::{MsixCap, MsixConfig, MsixConfigState};
use crate::pci::{
    PciCapabilityId, PciClassCode, PciDevice, PciMassStorageSubclass, PciNetworkControllerSubclass,
    PciSBDF,
};
use crate::vstate::bus::BusDevice;
use crate::vstate::interrupts::{InterruptError, MsixVectorGroup};
use crate::vstate::vm::KvmVm;

/// Vector value used to disable MSI for a queue.
pub const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;

/// BAR index we are using for VirtIO configuration
const VIRTIO_BAR_INDEX: u8 = 0;

/// BAR index of a device's shared memory regions (virtio 1.2, section 2.10), which a 64-bit BAR
/// of its own holds, after the configuration's.
const VIRTIO_SHM_BAR_INDEX: u8 = 2;

/// The shared memory regions a device may have over PCI: the configuration space's capabilities
/// end at offset 192 (`PciConfiguration::add_capability`), which leaves room for one
/// `virtio_pci_cap64` after the transport's own capabilities, and no more.
pub const MAX_SHM_REGIONS: usize = 1;

#[derive(Debug, Clone, Copy)]
enum PciCapabilityType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    Pci = 5,
    SharedMemory = 8,
}

// This offset represents the 2 bytes omitted from the VirtioPciCap structure
// as they are already handled through add_capability(). These 2 bytes are the
// fields cap_vndr (1 byte) and cap_next (1 byte) defined in the virtio spec.
const VIRTIO_PCI_CAP_OFFSET: u16 = 2;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VirtioPciCap {
    cap_len: u8,      // Generic PCI field: capability length
    cfg_type: u8,     // Identifies the structure.
    pci_bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type.
    padding: [u8; 2], // Pad to full dword.
    offset: Le32,     // Offset within bar.
    length: Le32,     // Length of the structure, in bytes.
}

// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap {}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

const VIRTIO_PCI_CAP_LEN_OFFSET: u8 = 2;

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_len: u8::try_from(std::mem::size_of::<VirtioPciCap>()).unwrap()
                + VIRTIO_PCI_CAP_LEN_OFFSET,
            cfg_type: cfg_type as u8,
            pci_bar: VIRTIO_BAR_INDEX,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }
}

/// A capability of 64-bit offset and length (virtio 1.2, section 4.1.4, `virtio_pci_cap64`): a
/// shared memory region's, whose `cap.id` is the region's ID.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VirtioPciCap64 {
    cap: VirtioPciCap,
    offset_hi: Le32,
    length_hi: Le32,
}

// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap64 {}

impl PciCapability for VirtioPciCap64 {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCap64 {
    /// The capability of the shared memory region `id`, `length` bytes at `offset` in the BAR
    /// `pci_bar`.
    fn shared_memory(pci_bar: u8, id: u8, offset: u64, length: u64) -> Self {
        // The low and high halves of the offset and length.
        #[allow(clippy::cast_possible_truncation)]
        let (low, high) = (
            |v: u64| Le32::from(v as u32),
            |v: u64| Le32::from((v >> 32) as u32),
        );
        VirtioPciCap64 {
            cap: VirtioPciCap {
                cap_len: u8::try_from(std::mem::size_of::<VirtioPciCap64>()).unwrap()
                    + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: PciCapabilityType::SharedMemory as u8,
                pci_bar,
                id,
                padding: [0; 2],
                offset: low(offset),
                length: low(length),
            },
            offset_hi: high(offset),
            length_hi: high(length),
        }
    }
}

/// The BAR that holds a device's shared memory `regions`, if it has any: the smallest power of two
/// in size from the first region's start that covers them all, its address and size. A BAR is
/// naturally aligned, so whoever places the regions places them so (see [`shm_bar_size`]).
pub fn shm_bar(regions: &[VirtioShmRegion]) -> Option<(u64, u64)> {
    let start = regions.iter().map(|region| region.guest_addr).min()?;
    let end = regions
        .iter()
        .map(|region| region.guest_addr + region.len)
        .max()?;
    Some((start, shm_bar_size(end - start)))
}

/// The size of the BAR holding shared memory regions of `len` bytes from its start: the guest
/// addresses to allocate for them, from the 64-bit MMIO range, aligned to this size.
pub fn shm_bar_size(len: u64) -> u64 {
    len.next_power_of_two()
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: Le32,
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciNotifyCap {}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciNotifyCap {
    pub fn new(cfg_type: PciCapabilityType, offset: u32, length: u32, multiplier: Le32) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_len: u8::try_from(std::mem::size_of::<VirtioPciNotifyCap>()).unwrap()
                    + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar: VIRTIO_BAR_INDEX,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VirtioPciCfgCap {
    cap: VirtioPciCap,
    pci_cfg_data: [u8; 4],
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCfgCap {}

impl PciCapability for VirtioPciCfgCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCfgCap {
    fn new() -> Self {
        VirtioPciCfgCap {
            cap: VirtioPciCap {
                cap_len: u8::try_from(size_of::<Self>()).unwrap() + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: PciCapabilityType::Pci as u8,
                pci_bar: VIRTIO_BAR_INDEX,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(0),
                length: Le32::from(0),
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct VirtioPciCfgCapInfo {
    offset: u16,
    cap: VirtioPciCfgCap,
}

impl VirtioPciCfgCapInfo {
    fn in_range(&self, reg_idx: u16, offset: u8, data_len: usize) -> bool {
        let base = reg_idx * 4;
        let cap_start = self.offset;
        let cap_end = self.offset as usize + self.cap.bytes().len();
        let start = base + u16::from(offset);
        let end = (base + u16::from(offset)) as usize + data_len;
        cap_start <= start && end <= cap_end
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PciVirtioSubclass {
    NonTransitionalBase = 0xff,
}

// Allocate one bar for the structs pointed to by the capability structures.
// As per the PCI specification, because the same BAR shares MSI-X and non
// MSI-X structures, it is recommended to use 8KiB alignment for all those
// structures.
const COMMON_CONFIG_BAR_OFFSET: u32 = 0x0000;
const COMMON_CONFIG_SIZE: u32 = 56;
const ISR_CONFIG_BAR_OFFSET: u32 = 0x2000;
const ISR_CONFIG_SIZE: u32 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u32 = 0x4000;
const DEVICE_CONFIG_SIZE: u32 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u32 = 0x6000;
const NOTIFICATION_SIZE: u32 = 0x1000;
const MSIX_TABLE_BAR_OFFSET: u32 = 0x8000;
// The size is 256KiB because the table can hold up to 2048 entries, with each
// entry being 128 bits (4 DWORDS).
const MSIX_TABLE_SIZE: u32 = 0x40000;
const MSIX_PBA_BAR_OFFSET: u32 = 0x48000;
// The size is 2KiB because the Pending Bit Array has one bit per vector and it
// can support up to 2048 vectors.
const MSIX_PBA_SIZE: u32 = 0x800;
/// The BAR size must be a power of 2.
pub const CAPABILITY_BAR_SIZE: u64 = 0x80000;

/// PCI configuration register index of the Command/Status DWORD.
const COMMAND_REG: u16 = 1;
/// Command register "Memory Space Enable" bit
const COMMAND_MEMORY_SPACE_ENABLE: u32 = 0x0000_0002;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.

/// The PCI device ID of a device whose type is past the 63 the modern IDs, 0x1040 to 0x107f, name:
/// the last transitional ID, whose subsystem device ID says the device's type (virtio 1.2,
/// section 4.1.2.1). Linux's virtio_pci claims PCI device IDs 0x1000 to 0x107f alone, and takes a
/// transitional one's type from its subsystem device ID, which a modern ID's 0x1040 plus the type
/// would have left outside.
const VIRTIO_PCI_TRANSITIONAL_DEVICE_ID: u16 = 0x103f;

/// The PCI device ID and subsystem device ID of a virtio device of type `device_type`.
fn pci_device_ids(device_type: VirtioDeviceType) -> (u16, u16) {
    let device_type = device_type as u16;
    match VIRTIO_PCI_DEVICE_ID_BASE.checked_add(device_type) {
        Some(id) if id <= 0x107f => (id, id),
        _ => (VIRTIO_PCI_TRANSITIONAL_DEVICE_ID, device_type),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioPciDeviceState {
    pub sbdf: PciSBDF,
    pub device_activated: bool,
    pub cap_pci_cfg_offset: u16,
    pub cap_pci_cfg: Vec<u8>,
    pub pci_configuration_state: PciConfigurationState,
    pub pci_dev_state: VirtioPciCommonConfigState,
    pub msix_state: MsixConfigState,
    pub bars: Bars,
    pub msix_config_cap_offset: u16,
    pub bar_address: u64,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioPciDeviceError {
    /// Error creating MSI configuration: {0}
    Msi(#[from] InterruptError),
    /// Invalid PCI configuration state: {0}
    PciConfiguration(#[from] PciConfigurationError),
    /// Invalid restore state: driver_status {0:#x} is inconsistent with device_activated (expected {1:#x})
    InvalidRestoreState(u8, u8),
    /// Restored MSI-X vector count ({0}) does not match the expected count ({1}) for this device
    UnexpectedMsixVectorCount(usize, usize),
    /// Could not activate restored device: {0}
    Activate(#[from] ActivateError),
}

pub struct VirtioPciDevice {
    id: String,

    // The subscriber ID returned by the EventManager
    pub sub_id: Option<event_manager::SubscriberId>,

    // SBDF assigned to the device
    pub sbdf: PciSBDF,

    // PCI configuration registers.
    configuration: PciConfiguration,
    // BARs region from configuration space handled separately
    bars: Bars,

    // virtio PCI common configuration
    common_config: VirtioPciCommonConfig,

    // Virtio device reference and status
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: Arc<AtomicBool>,

    // PCI interrupts.
    virtio_interrupt: Option<Arc<VirtioInterruptMsix>>,

    vm: Arc<KvmVm>,

    // GPA base at which the capability BAR is currently mapped on the
    // mmio bus, and where the notification ioeventfds are registered.
    // 0 means unmapped
    //
    // It is not necessarily equal to `config_bar_addr()`: the latter reflects
    // whatever the guest has last written into the BAR registers, which may be
    // transient (a 64-bit BAR is programmed with two separate writes) or not
    // yet in effect.
    bar_address: u64,

    // GPA base of the shared memory BAR (BAR 2), if the device has shared memory regions.
    // Shared memory regions are backed by fixed KVM memory slots and are not relocated when
    // the guest reprograms BAR 2; `maybe_relocate_bar` reverts any attempt to move BAR 2 so
    // the BAR register always agrees with the backing slot.
    shm_bar_address: Option<u64>,

    // Add a dedicated structure to hold information about the very specific
    // virtio-pci capability VIRTIO_PCI_CAP_PCI_CFG. This is needed to support
    // the legacy/backward compatible mechanism of letting the guest access the
    // other virtio capabilities without mapping the PCI BARs. This can be
    // needed when the guest tries to early access the virtio configuration of
    // a device.
    cap_pci_cfg_info: VirtioPciCfgCapInfo,
    msix_config_cap_offset: u16,
    msix_config: Arc<Mutex<MsixConfig>>,
}

impl Debug for VirtioPciDevice {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("VirtioPciDevice")
            .field("id", &self.id)
            .finish()
    }
}

impl VirtioPciDevice {
    fn pci_configuration(device_type: VirtioDeviceType) -> PciConfiguration {
        let (pci_device_id, subsystem_id) = pci_device_ids(device_type);
        let (class, subclass) = match device_type {
            VirtioDeviceType::Net => (
                PciClassCode::NetworkController,
                PciNetworkControllerSubclass::EthernetController as u8,
            ),
            VirtioDeviceType::Block => (
                PciClassCode::MassStorageController,
                PciMassStorageSubclass::MassStorage as u8,
            ),
            _ => (
                PciClassCode::UnassignedClass,
                PciVirtioSubclass::NonTransitionalBase as u8,
            ),
        };

        PciConfiguration::new_type0(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            0x1, // For modern virtio-PCI devices
            class,
            subclass,
            VIRTIO_PCI_VENDOR_ID,
            subsystem_id,
        )
    }

    /// Allocate the PCI BAR for the VirtIO device and its associated capabilities.
    ///
    /// This must happen only during the creation of a brand new VM. When a VM is restored from a
    /// known state, the BARs are already created with the right content, therefore we don't need
    /// to go through this codepath.
    ///
    /// The device's shared memory regions, if it has any, are where it placed them: a BAR of
    /// their own holds them ([`shm_bar`]). They stay at that address (`maybe_relocate_bar` refuses
    /// guest attempts to relocate BAR 2).
    pub fn allocate_bars(&mut self, mmio64_allocator: &mut AddressAllocator) {
        let shm_regions = self.device.lock().unwrap().shm_regions().to_vec();
        assert!(
            shm_regions.len() <= MAX_SHM_REGIONS,
            "a device of {} shared memory regions: the PCI transport describes {MAX_SHM_REGIONS} \
             at most",
            shm_regions.len()
        );

        // Allocate the virtio-pci capability BAR.
        // See http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-740004
        self.bar_address = mmio64_allocator
            .allocate(
                CAPABILITY_BAR_SIZE,
                CAPABILITY_BAR_SIZE,
                AllocPolicy::FirstMatch,
            )
            .unwrap()
            .start();
        self.bars.set_bar_64(
            VIRTIO_BAR_INDEX,
            self.bar_address,
            CAPABILITY_BAR_SIZE,
            BarPrefetchable::No,
        );
        let shm_bar = shm_bar(&shm_regions);
        if let Some((addr, size)) = shm_bar {
            assert!(
                addr.is_multiple_of(size),
                "shared memory regions at {addr:#x} not aligned to their BAR's {size:#x} bytes"
            );
            self.bars
                .set_bar_64(VIRTIO_SHM_BAR_INDEX, addr, size, BarPrefetchable::Yes);
            self.shm_bar_address = Some(addr);
        }
        self.add_pci_capabilities();
        // After the others', which a driver finds by their types, wherever they are.
        if let Some((addr, _)) = shm_bar {
            for region in &shm_regions {
                let cap = VirtioPciCap64::shared_memory(
                    VIRTIO_SHM_BAR_INDEX,
                    region.id,
                    region.guest_addr - addr,
                    region.len,
                );
                self.configuration.add_capability(&cap);
            }
        }
    }

    fn shm_bar_addr_of(bars: &Bars) -> Option<u64> {
        if !bars.bars[VIRTIO_SHM_BAR_INDEX as usize].is_64bit() {
            return None;
        }
        let bar = bars.get_bar_addr_64(VIRTIO_SHM_BAR_INDEX);
        (bar != 0).then_some(bar)
    }

    /// The address of the BAR holding the device's shared memory regions, if it has any.
    pub fn shm_bar_addr(&self) -> Option<u64> {
        Self::shm_bar_addr_of(&self.bars)
    }

    /// Free the PCI BAR of the VirtIO device.
    pub fn free_bars(&mut self, mmio64_allocator: &mut AddressAllocator) {
        let bar_end = self
            .bar_address
            .checked_add(CAPABILITY_BAR_SIZE - 1)
            .expect("virtio-pci BAR end address overflows");
        let range =
            RangeInclusive::new(self.bar_address, bar_end).expect("Invalid virtio-pci BAR range");
        mmio64_allocator
            .free(&range)
            .expect("virtio-pci BAR is not allocated");
        self.bar_address = 0;
    }

    /// Constructs a new PCI transport for the given virtio device.
    pub fn new(
        id: String,
        vm: &Arc<KvmVm>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        msix_vectors: Arc<MsixVectorGroup>,
        sbdf: PciSBDF,
    ) -> Self {
        let num_queues = device.lock().expect("Poisoned lock").queues().len();
        assert_eq!(msix_vectors.vectors.len(), num_queues + 1);

        let msix_config = Arc::new(Mutex::new(MsixConfig::new(msix_vectors.clone(), sbdf)));
        let pci_config =
            Self::pci_configuration(device.lock().expect("Poisoned lock").device_type());

        let virtio_common_config = VirtioPciCommonConfig::new(VirtioPciCommonConfigState {
            driver_status: 0,
            config_generation: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            queue_select: 0,
            msix_config: VIRTQ_MSI_NO_VECTOR,
            msix_queues: vec![VIRTQ_MSI_NO_VECTOR; num_queues],
        });
        let interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            virtio_common_config.msix_config.clone(),
            virtio_common_config.msix_queues.clone(),
            msix_vectors,
        ));

        VirtioPciDevice {
            id,
            sub_id: None,
            sbdf,
            configuration: pci_config,
            common_config: virtio_common_config,
            device,
            device_activated: Arc::new(AtomicBool::new(false)),
            virtio_interrupt: Some(interrupt),
            vm: vm.clone(),
            bar_address: 0,
            shm_bar_address: None,
            cap_pci_cfg_info: VirtioPciCfgCapInfo::default(),
            bars: Bars::default(),
            msix_config,
            msix_config_cap_offset: 0,
        }
    }

    pub fn new_from_state(
        id: String,
        vm: &Arc<KvmVm>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        state: VirtioPciDeviceState,
    ) -> Result<Self, VirtioPciDeviceError> {
        let msix_config = MsixConfig::from_state(state.msix_state, vm.clone(), state.sbdf)?;
        let vectors = msix_config.vectors.clone();

        // Expecting one vector per queue, plus one for the configuration
        let expected_num_vectors = device.lock().expect("Poisoned lock").queues().len() + 1;
        if vectors.vectors.len() != expected_num_vectors {
            return Err(VirtioPciDeviceError::UnexpectedMsixVectorCount(
                vectors.vectors.len(),
                expected_num_vectors,
            ));
        }

        let msix_config = Arc::new(Mutex::new(msix_config));

        let pci_config = PciConfiguration::type0_from_state(state.pci_configuration_state)?;
        let virtio_common_config = VirtioPciCommonConfig::new(state.pci_dev_state);

        if state.device_activated {
            let driver_ok = ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK;
            // The reset code path leaves the backend active while setting
            // driver_status to 0 (INIT), so INIT is also valid
            let valid = virtio_common_config.driver_status == driver_ok
                || virtio_common_config.driver_status == INIT;
            if !valid {
                return Err(VirtioPciDeviceError::InvalidRestoreState(
                    virtio_common_config.driver_status,
                    driver_ok,
                ));
            }
        }

        let cap_pci_cfg_info = VirtioPciCfgCapInfo {
            offset: state.cap_pci_cfg_offset,
            cap: *VirtioPciCfgCap::from_slice(&state.cap_pci_cfg).ok_or(
                PciConfigurationError::InvalidCapPciCfgLength(state.cap_pci_cfg.len()),
            )?,
        };

        let interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            virtio_common_config.msix_config.clone(),
            virtio_common_config.msix_queues.clone(),
            vectors,
        ));

        if !state.bars.bar_idx_valid(VIRTIO_BAR_INDEX)
            || !state.bars.bars[VIRTIO_BAR_INDEX as usize].is_64bit()
        {
            return Err(PciConfigurationError::InvalidBarIdx(VIRTIO_BAR_INDEX).into());
        }

        let shm_bar_address = Self::shm_bar_addr_of(&state.bars);
        let virtio_pci_device = VirtioPciDevice {
            id,
            sub_id: None,
            sbdf: state.sbdf,
            configuration: pci_config,
            common_config: virtio_common_config,
            device,
            device_activated: Arc::new(AtomicBool::new(state.device_activated)),
            virtio_interrupt: Some(interrupt),
            vm: vm.clone(),
            bar_address: state.bar_address,
            shm_bar_address,
            cap_pci_cfg_info,
            bars: state.bars,
            msix_config,
            msix_config_cap_offset: state.msix_config_cap_offset,
        };

        if state.device_activated {
            virtio_pci_device
                .device
                .lock()
                .expect("Poisoned lock")
                .activate(
                    virtio_pci_device.vm.guest_memory().clone(),
                    virtio_pci_device.virtio_interrupt.as_ref().unwrap().clone(),
                )?;
        }

        Ok(virtio_pci_device)
    }

    /// Enable unmasked MSI-X vectors by registering IRQFDs with KVM.
    ///
    /// Must be called after the GSI routes have been set up (see [KvmVm::set_gsi_routes]).
    pub fn enable_unmasked_vectors(&self) -> Result<(), InterruptError> {
        self.msix_config
            .lock()
            .expect("Poisoned lock")
            .enable_unmasked_vectors()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = ACKNOWLEDGE | DRIVER | DRIVER_OK | FEATURES_OK;
        self.common_config.driver_status == ready_bits
    }

    /// Determines if the driver has requested the device (re)init / reset itself
    fn is_driver_init(&self) -> bool {
        self.common_config.driver_status == INIT
    }

    /// GPA base currently written in the BAR register.
    ///
    /// Might be different from bar_address() during BAR relocation.
    pub fn config_bar_addr(&self) -> u64 {
        self.bars.get_bar_addr_64(VIRTIO_BAR_INDEX)
    }

    /// GPA base at which the capability BAR is currently mapped on the
    /// mmio bus, and where the notification ioeventfds are registered.
    ///
    /// Might be different from config_bar_addr() during BAR relocation.
    pub fn bar_address(&self) -> u64 {
        self.bar_address
    }

    fn add_pci_capabilities(&mut self) {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::Common,
            COMMON_CONFIG_BAR_OFFSET,
            COMMON_CONFIG_SIZE,
        );
        self.configuration.add_capability(&common_cap);

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::Isr,
            ISR_CONFIG_BAR_OFFSET,
            ISR_CONFIG_SIZE,
        );
        self.configuration.add_capability(&isr_cap);

        // TODO(dgreid) - set based on device's configuration size?
        let device_cap = VirtioPciCap::new(
            PciCapabilityType::Device,
            DEVICE_CONFIG_BAR_OFFSET,
            DEVICE_CONFIG_SIZE,
        );
        self.configuration.add_capability(&device_cap);

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::Notify,
            NOTIFICATION_BAR_OFFSET,
            NOTIFICATION_SIZE,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.configuration.add_capability(&notify_cap);

        let configuration_cap = VirtioPciCfgCap::new();
        self.cap_pci_cfg_info.offset =
            u16::from(self.configuration.add_capability(&configuration_cap))
                + VIRTIO_PCI_CAP_OFFSET;
        self.cap_pci_cfg_info.cap = configuration_cap;

        if let Some(interrupt) = &self.virtio_interrupt {
            let msix_cap = MsixCap::new(
                VIRTIO_BAR_INDEX,
                interrupt
                    .msix_config
                    .lock()
                    .expect("Poisoned lock")
                    .vectors
                    .num_vectors(),
                MSIX_TABLE_BAR_OFFSET,
                VIRTIO_BAR_INDEX,
                MSIX_PBA_BAR_OFFSET,
            );
            // The whole Configuration region is 4K, so u16 can address it all
            #[allow(clippy::cast_possible_truncation)]
            let offset = self.configuration.add_capability(&msix_cap) as u16;
            self.msix_config_cap_offset = offset;
        }
    }

    fn read_cap_pci_cfg(&mut self, offset: usize, mut data: &mut [u8]) {
        let cap_slice = self.cap_pci_cfg_info.cap.as_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to read cap_pci_cfg from config space");
            return;
        }

        if offset < std::mem::size_of::<VirtioPciCap>() {
            if let Some(end) = offset.checked_add(data_len) {
                // This write can't fail, offset and end are checked against config_len.
                data.write_all(&cap_slice[offset..cmp::min(end, cap_len)])
                    .unwrap();
            }
        } else {
            let bar_offset: u32 = self.cap_pci_cfg_info.cap.cap.offset.into();
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            // BAR reads expect that the buffer has the exact size of the field that
            // offset is pointing to. So, do some check that the `length` has a meaningful value
            // and only use the part of the buffer we actually need.
            if len <= 4 {
                self.read_bar(0, bar_offset as u64, &mut data[..len]);
            }
        }
    }

    fn write_cap_pci_cfg(&mut self, offset: usize, data: &[u8]) -> Option<Arc<Barrier>> {
        let cap_slice = self.cap_pci_cfg_info.cap.as_mut_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to write cap_pci_cfg to config space");
            return None;
        }

        if offset < std::mem::size_of::<VirtioPciCap>() {
            let (_, right) = cap_slice.split_at_mut(offset);
            right[..data_len].copy_from_slice(data);
            None
        } else {
            let bar_offset: u32 = self.cap_pci_cfg_info.cap.cap.offset.into();
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            // BAR writes expect that the buffer has the exact size of the field that
            // offset is pointing to. So, do some check that the `length` has a meaningful value
            // and only use the part of the buffer we actually need.
            if len <= 4 {
                let len = len.min(data.len());
                self.write_bar(0, bar_offset as u64, &data[..len])
            } else {
                None
            }
        }
    }

    pub fn virtio_device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn needs_activation(&self) -> bool {
        !self.device_activated.load(Ordering::SeqCst) && self.is_driver_ready()
    }

    fn set_notification_ioevents(
        &self,
        vm: &KvmVm,
        bar_addr: u64,
        assign: bool,
    ) -> Result<(), errno::Error> {
        for (i, queue_evt) in self
            .device
            .lock()
            .expect("Poisoned lock")
            .queue_events()
            .iter()
            .enumerate()
        {
            let notify_base = bar_addr + u64::from(NOTIFICATION_BAR_OFFSET);
            let io_addr =
                IoEventAddress::Mmio(notify_base + i as u64 * u64::from(NOTIFY_OFF_MULTIPLIER));
            if assign {
                vm.fd().register_ioevent(queue_evt, &io_addr, NoDatamatch)?;
            } else {
                vm.fd()
                    .unregister_ioevent(queue_evt, &io_addr, NoDatamatch)?;
            }
        }
        Ok(())
    }

    /// Return true if the guest has enabled memory-space decoding for this
    /// device in the command register.
    fn memory_space_enabled(&self) -> bool {
        self.configuration.read_reg(COMMAND_REG) & COMMAND_MEMORY_SPACE_ENABLE != 0
    }

    /// Relocate the PCI bar if a new address was written to the registers
    fn maybe_relocate_bar(&mut self) {
        if let Some(old_shm) = self.shm_bar_address
            && self.shm_bar_addr() != Some(old_shm)
        {
            error!(
                "Refusing to relocate virtio-pci shared memory BAR {old_shm:#x} -> {:?}: \
                 shared memory regions stay at their allocated address",
                self.shm_bar_addr()
            );
            let bar_lo = &mut self.bars.bars[VIRTIO_SHM_BAR_INDEX as usize];
            bar_lo.encoded_addr = ((old_shm & 0xffff_fff0) as u32) | (bar_lo.encoded_addr & 0xf);
            self.bars.bars[VIRTIO_SHM_BAR_INDEX as usize + 1].encoded_addr = (old_shm >> 32) as u32;
        }

        let old_base = self.bar_address;
        let new_base = self.config_bar_addr();
        if new_base == old_base {
            return;
        }

        // Try to allocate the new range from the resource allocator.
        let new_range = match self.vm.resource_allocator().mmio64_memory.allocate(
            CAPABILITY_BAR_SIZE,
            CAPABILITY_BAR_SIZE,
            AllocPolicy::ExactMatch(new_base),
        ) {
            Ok(range) => range,
            Err(err) => {
                error!("Cannot reserve relocated BAR range at {new_base:#x}: {err:?}");
                return;
            }
        };

        // Register the new notification ioeventfds first. If this fails
        // nothing has moved yet, so the device keeps working at its old base.
        if let Err(err) = self.set_notification_ioevents(&self.vm, new_base, true) {
            error!("Failed to add notification ioeventfds at {new_base:#x}: {err:?}");
            // set_notification_ioevents() might leave some ioeventfds
            // registered in case of failure. Do not return the possibly
            // "poisoned" address range to the mmio64_allocator.
            return;
        }

        if let Err(err) =
            self.vm
                .common
                .mmio_bus
                .move_range(old_base, new_base, CAPABILITY_BAR_SIZE)
        {
            error!("Failed to relocate BAR mapping {old_base:#x} -> {new_base:#x}: {err:?}");
            if let Err(err) = self.set_notification_ioevents(&self.vm, new_base, false) {
                error!("Failed to remove notification ioeventfds at {new_base:#x}: {err:?}");
                // As above, only release the old range if it has no ioeventfds left.
            } else {
                let _ = self.vm.resource_allocator().mmio64_memory.free(&new_range);
            }
            return;
        }

        if let Err(err) = self.set_notification_ioevents(&self.vm, old_base, false) {
            // As above, only release the old range if it has no ioeventfds left.
            error!("Failed to remove old notification ioeventfds at {old_base:#x}: {err:?}");
        } else {
            // SAFETY: old_base was allocated from the resource allocator, comes
            // from a previous relocation which validated it, or comes from a
            // snapshot, which is trusted. So the range is always valid.
            let old_end = old_base
                .checked_add(CAPABILITY_BAR_SIZE - 1)
                .expect("BAR end address overflows");
            let old_range = RangeInclusive::new(old_base, old_end).expect("Invalid BAR range");
            let _ = self.vm.resource_allocator().mmio64_memory.free(&old_range);
        }

        self.bar_address = new_base;
        debug!("Relocated virtio-pci BAR mapping {old_base:#x} -> {new_base:#x}");
    }

    /// Register the IoEvent notifications for a VirtIO device.
    pub fn register_notification_ioevents(&self, vm: &KvmVm) -> Result<(), errno::Error> {
        self.set_notification_ioevents(vm, self.bar_address, true)
    }

    /// Unregister the IoEvent notifications for a VirtIO device.
    pub fn unregister_notification_ioevents(&self, vm: &KvmVm) -> Result<(), errno::Error> {
        self.set_notification_ioevents(vm, self.bar_address, false)
    }

    /// Tear down the MSI-X configuration. Used on device reset.
    fn reset_msix(&mut self) {
        let (num_vectors, vm) = {
            let msix_config = self.msix_config.lock().expect("Poisoned lock");
            (
                msix_config.vectors.num_vectors(),
                msix_config.vectors.vm.clone(),
            )
        };

        // Build a fresh MSI-X vector group and configuration.
        let msix_vectors = match KvmVm::create_msix_group(vm.clone(), num_vectors) {
            Ok(vectors) => Arc::new(vectors),
            Err(err) => {
                error!("Failed to recreate MSI-X vector group on reset: {err:?}");
                return;
            }
        };

        self.common_config
            .msix_config
            .store(VIRTQ_MSI_NO_VECTOR, Ordering::Release);
        for vector in self
            .common_config
            .msix_queues
            .lock()
            .expect("Poisoned lock")
            .iter_mut()
        {
            *vector = VIRTQ_MSI_NO_VECTOR;
        }

        let msix_config = Arc::new(Mutex::new(MsixConfig::new(msix_vectors.clone(), self.sbdf)));
        let interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            self.common_config.msix_config.clone(),
            self.common_config.msix_queues.clone(),
            msix_vectors,
        ));

        // Dropping the previous virtio_interrupt and msix_config releases the
        // last references to the old MsixVectorGroup, whose Drop unregisters
        // the irqfds, removes the GSI routes from the routing table and frees
        // the GSIs.
        self.virtio_interrupt = Some(interrupt);
        self.msix_config = msix_config;

        // Flush the updated routing table
        if let Err(err) = vm.set_gsi_routes() {
            error!("Failed to update GSI routes after MSI-X reset: {err:?}");
        }

        // Clear the MSI-X Enable and Function Mask bits in the guest-visible
        // PCI capability so config-space reads stay consistent with the
        // freshly-reset MsixConfig.
        let reg_idx = self.msix_config_cap_offset / 4;
        let msg_ctl = (self.configuration.read_reg(reg_idx) >> 16) as u16;
        let msg_ctl = msg_ctl & !((1 << 15) | (1 << 14)); // clear Enable + Function Mask
        self.configuration
            .write_config_register(reg_idx, 2, &msg_ctl.to_le_bytes());
    }

    pub fn state(&self) -> VirtioPciDeviceState {
        VirtioPciDeviceState {
            sbdf: self.sbdf,
            device_activated: self.device_activated.load(Ordering::Acquire),
            cap_pci_cfg_offset: self.cap_pci_cfg_info.offset,
            cap_pci_cfg: self.cap_pci_cfg_info.cap.bytes().to_vec(),
            pci_configuration_state: self.configuration.state(),
            pci_dev_state: self.common_config.state(),
            msix_state: self
                .virtio_interrupt
                .as_ref()
                .unwrap()
                .msix_config
                .lock()
                .expect("Poisoned lock")
                .state(),
            bars: self.bars,
            msix_config_cap_offset: self.msix_config_cap_offset,
            bar_address: self.bar_address,
        }
    }
}

pub struct VirtioInterruptMsix {
    msix_config: Arc<Mutex<MsixConfig>>,
    config_vector: Arc<AtomicU16>,
    queues_vectors: Arc<Mutex<Vec<u16>>>,
    vectors: Arc<MsixVectorGroup>,
}

impl std::fmt::Debug for VirtioInterruptMsix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioInterruptMsix")
            .field("msix_config", &self.msix_config)
            .field("config_vector", &self.config_vector)
            .field("queues_vectors", &self.queues_vectors)
            .finish()
    }
}

impl VirtioInterruptMsix {
    pub fn new(
        msix_config: Arc<Mutex<MsixConfig>>,
        config_vector: Arc<AtomicU16>,
        queues_vectors: Arc<Mutex<Vec<u16>>>,
        vectors: Arc<MsixVectorGroup>,
    ) -> Self {
        VirtioInterruptMsix {
            msix_config,
            config_vector,
            queues_vectors,
            vectors,
        }
    }
}

impl VirtioInterrupt for VirtioInterruptMsix {
    fn trigger(&self, int_type: VirtioInterruptType) -> Result<(), InterruptError> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => *self
                .queues_vectors
                .lock()
                .unwrap()
                .get(queue_index as usize)
                .ok_or(InterruptError::InvalidVectorIndex(queue_index as usize))?,
        };

        if vector == VIRTQ_MSI_NO_VECTOR {
            return Ok(());
        }

        let config = &mut self.msix_config.lock().unwrap();
        let entry = &config.table_entries[vector as usize];
        // In case the vector control register associated with the entry
        // has its first bit set, this means the vector is masked and the
        // device should not inject the interrupt.
        // Instead, the Pending Bit Array table is updated to reflect there
        // is a pending interrupt for this specific vector.
        if config.masked || entry.masked() {
            config.set_pba_bit(vector, false);
            return Ok(());
        }

        self.vectors.trigger(vector as usize)
    }

    fn notifier(&self, int_type: VirtioInterruptType) -> Option<&EventFd> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => *self
                .queues_vectors
                .lock()
                .unwrap()
                .get(queue_index as usize)?,
        };

        self.vectors.notifier(vector as usize)
    }

    fn status(&self) -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(0))
    }

    #[cfg(test)]
    fn has_pending_interrupt(&self, _interrupt_type: VirtioInterruptType) -> bool {
        false
    }

    #[cfg(test)]
    fn ack_interrupt(&self, _interrupt_type: VirtioInterruptType) {
        // Do nothing here
    }
}

impl PciDevice for VirtioPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let in_bars = BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS);
        let in_msix_cap_header = reg_idx * 4 == self.msix_config_cap_offset;
        let in_pci_cfg = self.cap_pci_cfg_info.in_range(reg_idx, offset, data.len());
        if in_bars {
            // reg_idx is in [BAR0_REG_IDX, BAR0_REG_IDX+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            self.bars.write(bar_idx, offset, data);
            None
        } else if in_msix_cap_header {
            // For the MsixCap structure, we need to capture writes to the second 2 bytes
            // of the capability header where Function Mask and MSI-X Enable bits are present.
            // Everything else can be served from `self.configuration`.
            self.msix_config
                .lock()
                .unwrap()
                .write_msg_ctl_register(offset, data);
            self.configuration
                .write_config_register(reg_idx, offset, data);
            None
        } else if in_pci_cfg {
            let offset = (reg_idx * 4 + u16::from(offset) - self.cap_pci_cfg_info.offset) as usize;
            self.write_cap_pci_cfg(offset, data)
        } else {
            let mem_enabled_before = self.memory_space_enabled();
            self.configuration
                .write_config_register(reg_idx, offset, data);
            if !mem_enabled_before && self.memory_space_enabled() {
                self.maybe_relocate_bar();
            }
            None
        }
    }

    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let in_bars = BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS);
        let in_pci_cfg = self.cap_pci_cfg_info.in_range(reg_idx, 0, 4);

        if in_bars {
            // reg_idx is in [BAR0_REG_IDX, BAR0_REG_IDX+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            let mut value: u32 = 0;
            self.bars.read(bar_idx, 0, value.as_mut_bytes());
            value
        } else if in_pci_cfg {
            // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
            // is accessed. This capability has a special meaning as it allows the
            // guest to access other capabilities without mapping the PCI BAR.
            let offset = (reg_idx * 4 - self.cap_pci_cfg_info.offset) as usize;
            let mut data = [0u8; 4];
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            if len <= 4 {
                self.read_cap_pci_cfg(offset, &mut data[..len]);
                u32::from_le_bytes(data)
            } else {
                0
            }
        } else {
            self.configuration.read_reg(reg_idx)
        }
    }

    fn read_bar(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            o if o < u64::from(COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE) => {
                self.common_config.read(
                    o - u64::from(COMMON_CONFIG_BAR_OFFSET),
                    data,
                    self.device.clone(),
                )
            }
            o if (u64::from(ISR_CONFIG_BAR_OFFSET)
                ..u64::from(ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE))
                .contains(&o) =>
            {
                // We don't actually support legacy INT#x interrupts for VirtIO PCI devices
                warn!("pci: read access to unsupported ISR status field");
                data.fill(0);
            }
            o if (u64::from(DEVICE_CONFIG_BAR_OFFSET)
                ..u64::from(DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE))
                .contains(&o) =>
            {
                let device = self.device.lock().unwrap();
                device.read_config(o - u64::from(DEVICE_CONFIG_BAR_OFFSET), data);
            }
            o if (u64::from(NOTIFICATION_BAR_OFFSET)
                ..u64::from(NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE))
                .contains(&o) =>
            {
                // Handled with ioeventfds.
                warn!("pci: unexpected read to notification BAR. Offset {o:#x}");
            }
            o if (u64::from(MSIX_TABLE_BAR_OFFSET)
                ..u64::from(MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .read_table(o - u64::from(MSIX_TABLE_BAR_OFFSET), data);
                }
            }
            o if (u64::from(MSIX_PBA_BAR_OFFSET)
                ..u64::from(MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .read_pba(o - u64::from(MSIX_PBA_BAR_OFFSET), data);
                }
            }
            _ => (),
        }
    }

    fn write_bar(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            o if o < u64::from(COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE) => {
                self.common_config.write(
                    o - u64::from(COMMON_CONFIG_BAR_OFFSET),
                    data,
                    self.device.clone(),
                    self.device_activated.load(Ordering::SeqCst),
                )
            }
            o if (u64::from(ISR_CONFIG_BAR_OFFSET)
                ..u64::from(ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE))
                .contains(&o) =>
            {
                // We don't actually support legacy INT#x interrupts for VirtIO PCI devices
                warn!("pci: access to unsupported ISR status field");
            }
            o if (u64::from(DEVICE_CONFIG_BAR_OFFSET)
                ..u64::from(DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE))
                .contains(&o) =>
            {
                let mut device = self.device.lock().unwrap();
                device.write_config(o - u64::from(DEVICE_CONFIG_BAR_OFFSET), data);
            }
            o if (u64::from(NOTIFICATION_BAR_OFFSET)
                ..u64::from(NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE))
                .contains(&o) =>
            {
                // Handled with ioeventfds.
                warn!("pci: unexpected write to notification BAR. Offset {o:#x}");
            }
            o if (u64::from(MSIX_TABLE_BAR_OFFSET)
                ..u64::from(MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .write_table(o - u64::from(MSIX_TABLE_BAR_OFFSET), data);
                }
            }
            o if (u64::from(MSIX_PBA_BAR_OFFSET)
                ..u64::from(MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .write_pba(o - u64::from(MSIX_PBA_BAR_OFFSET), data);
                }
            }
            _ => (),
        };

        // Try and activate the device if the driver status has changed
        if self.needs_activation() {
            debug!("Activating device");
            let interrupt = Arc::clone(self.virtio_interrupt.as_ref().unwrap());
            let device = self.virtio_device();
            let mut locked_device = device.lock().unwrap();
            match locked_device.activate(self.vm.guest_memory().clone(), interrupt.clone()) {
                Ok(()) => {
                    self.device_activated.store(true, Ordering::SeqCst);

                    // A queue notification may have arrived after the guest set DRIVER_OK but
                    // before the device finished activating, in which case it was discarded as
                    // spurious. Re-notify the queues so any buffers the guest already made
                    // available get processed.
                    locked_device.notify_queue_events();
                }
                Err(err) => {
                    self.common_config.driver_status |= DEVICE_NEEDS_RESET;
                    error!("Error activating device: {err:?}");

                    // Section 2.1.2 of the specification states that we need to send a device
                    // configuration change interrupt
                    let _ = interrupt.trigger(VirtioInterruptType::Config);
                }
            }
        }

        // Device has been reset by the driver
        if self.device_activated.load(Ordering::SeqCst) && self.is_driver_init() {
            let reset_succeeded = self.device.lock().unwrap().reset();
            if reset_succeeded {
                self.device_activated.store(false, Ordering::SeqCst);

                self.common_config.queue_select = 0;
                self.common_config.device_feature_select = 0;
                self.common_config.driver_feature_select = 0;

                self.reset_msix();
            } else {
                error!("Attempt to reset device when not implemented in underlying device");
                // The virtio spec does not specify what to do if reset fails.
                //
                // Our MMIO transport sets FAILED in this case, but we must NOT do that for PCI.
                // During shutdown, the Linux kernel issues a reset to each virtio device.  The
                // virtio PCI driver then polls device_status until it reads back 0, unlike the
                // virtio MMIO driver which simply writes 0 and returns.  Setting FAILED would
                // cause the poll to spin forever, breaking reboot command and Ctrl-Alt-Del.
                // - PCI: https://elixir.bootlin.com/linux/v6.19.8/source/drivers/virtio/virtio_pci_modern.c#L546-L565
                // - MMIO: https://elixir.bootlin.com/linux/v6.19.8/source/drivers/virtio/virtio_mmio.c#L251-L258
                //
                // Since device_status was already set to INIT by set_device_status(), we don't
                // need to set it again here.  However, the backend device is still active since
                // reset() is unimplemented.  The combination of device_activated == true and
                // device_status == INIT will cause set_device_status() to block any
                // re-initialization attempts.
            }
        }
        None
    }
}

impl BusDevice for VirtioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    use linux_loader::loader::Cmdline;
    use vm_allocator::{AllocPolicy, RangeInclusive};
    use vm_memory::{ByteValued, Le32};

    use super::{
        EventFd, IoEventAddress, KvmVm, NoDatamatch, PciCapabilityType, VirtioPciCap64,
        VirtioPciDevice, pci_device_ids, shm_bar, shm_bar_size,
    };
    use crate::Vmm;
    use crate::arch::{MEM_64BIT_DEVICES_SIZE, MEM_64BIT_DEVICES_START};
    use crate::builder::tests::default_vmm_with_pci;
    use crate::device_manager::tests::pci_devices;
    use crate::devices::virtio::device::{VirtioDeviceType, VirtioShmRegion};
    use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
    use crate::devices::virtio::rng::Entropy;
    use crate::devices::virtio::transport::mmio::tests::DummyDevice;
    use crate::devices::virtio::transport::pci::common_config_offset::*;
    use crate::devices::virtio::transport::pci::device::{
        CAPABILITY_BAR_SIZE, COMMAND_MEMORY_SPACE_ENABLE, COMMAND_REG, COMMON_CONFIG_BAR_OFFSET,
        COMMON_CONFIG_SIZE, DEVICE_CONFIG_BAR_OFFSET, DEVICE_CONFIG_SIZE, ISR_CONFIG_BAR_OFFSET,
        ISR_CONFIG_SIZE, NOTIFICATION_BAR_OFFSET, NOTIFICATION_SIZE, NOTIFY_OFF_MULTIPLIER,
        PciVirtioSubclass, VirtioPciCap, VirtioPciCfgCap, VirtioPciNotifyCap,
    };
    use crate::devices::virtio::transport::pci::device_status::{
        ACKNOWLEDGE, DRIVER, DRIVER_OK, FEATURES_OK,
    };
    use crate::pci::configuration::BAR0_REG_IDX;
    use crate::pci::msix::MsixCap;
    use crate::pci::{PciCapabilityId, PciClassCode, PciDevice};
    use crate::rate_limiter::RateLimiter;

    fn create_vmm_with_virtio_pci_device() -> Vmm {
        let mut vmm = default_vmm_with_pci();
        let entropy = Arc::new(Mutex::new(Entropy::new(RateLimiter::default()).unwrap()));
        let mut event_manager = crate::EventManager::new().unwrap();
        vmm.device_manager
            .attach_boot_virtio_device(
                &vmm.vm,
                "rng".to_string(),
                entropy.clone(),
                &mut Cmdline::new(1024).unwrap(),
                &mut event_manager,
                false,
            )
            .unwrap();
        vmm
    }

    fn get_virtio_device(vmm: &Vmm) -> Arc<Mutex<VirtioPciDevice>> {
        pci_devices(&vmm.device_manager)
            .get_virtio_device(VirtioDeviceType::Rng, "rng")
            .unwrap()
            .clone()
    }

    #[test]
    fn test_pci_device_config() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // For more information for the values we are checking here look into the VirtIO spec here:
        // https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1220007
        // and PCI Header type 0 layout here: https://wiki.osdev.org/PCI#Configuration_Space

        //              |  16 bits  |  16 bits  |
        //              |-----------|-----------|
        // regiger 0x0: | Device ID | Vendor ID |
        //
        // Vendor ID of VirtIO devices is 0x1af4
        let reg0 = locked_virtio_pci_device.read_config_register(0);
        assert_eq!(reg0 & 0xffff, 0x1af4);
        // VirtIO PCI device IDs are in the range [0x1000, 0x107f]. (We are not using transitional
        // device IDs).
        let devid = reg0 >> 16;
        assert!(
            (0x1000..=0x107f).contains(&devid),
            "Device ID check: {:#x} >= 0x1000 && {:#x} <= 0x107f",
            devid,
            devid
        );

        //              |   16 bits  |  16 bits  |
        //              |------------|-----------|
        // regiger 0x1: |   Status   |  Command  |
        // We offer the capabilities list (bit 4 of status register) at offset 0x34
        let reg1 = locked_virtio_pci_device.read_config_register(1);
        assert_eq!(reg1, 0x0010_0000);

        //               |   8 bits   |  8 bits  | 8 bits  |    8 bits   |
        // register 0x2: | Class code | Subclass | Prog IF | Revision ID |
        //
        // Class code: VIRTIO_PCI_VENDOR_ID for all VirtIO devices
        // Subclass: PciClassCode::NetworkController for net, PciClassCode::MassStorageController
        // for block           PciClassCode::UnassignedClass for everything else
        // Prog IF: A register defining some programmable interface register. 0 for VirtIO devices
        // Revision ID: 0x1 for modern VirtIO devices
        let reg2 = locked_virtio_pci_device.read_config_register(2);
        assert_eq!(reg2, 0xffff_0001);
        let class_code = ((reg2 >> 24) & 0xff) as u8;
        assert_eq!(class_code, PciClassCode::UnassignedClass as u8);
        let subclass = ((reg2 >> 16) & 0xff) as u8;
        assert_eq!(subclass, PciVirtioSubclass::NonTransitionalBase as u8);
        let prog_if = ((reg2 >> 8) & 0xff) as u8;
        assert_eq!(prog_if, 0);
        let revision_id = reg2 & 0xff;
        assert_eq!(revision_id, 0x1);

        //               |   8 bits   |    8 bits   |    8 bits     |      8 bits     |
        // register 0x3: |    BIST    | Header Type | Latency timer | Cache line size |
        //
        // BIST: status and control for self test of PCI devices. Always 0 for VirtIO devices
        // HeaderType: 0x0 for general devices
        // LatencyTimer: Latency timer in units of PCI bus clocks, 0 for VirtIO
        // Cache Line size: 0 for VirtIO devices
        let reg3 = locked_virtio_pci_device.read_config_register(3);
        assert_eq!(reg3, 0x0);

        // register 0xa: Cardbus CIS pointer
        //
        // We don't emulate CardBus
        let reg10 = locked_virtio_pci_device.read_config_register(0xa);
        assert_eq!(reg10, 0);

        //              |    16 bits   |       16 bits      |
        // regiger 0xb: | Subsystem ID | Subsystem vendor ID|
        //
        // For us Subsystem ID is same as device ID and subsystem vendor ID is same as vendor ID
        // (reg 0x0)
        let reg11 = locked_virtio_pci_device.read_config_register(0xb);
        assert_eq!(reg11, reg0);

        // register 0xc: Expansion ROM base address: 0x0 for us
        let reg12 = locked_virtio_pci_device.read_config_register(0xc);
        assert_eq!(reg12, 0);

        //               |  24 bits |        8 bits        |
        // register 0xd: | Reserved | Capabilities pointer |
        let reg13 = locked_virtio_pci_device.read_config_register(0xd);
        assert_eq!(reg13 >> 24, 0);

        // register 0xe: Reserved
        let reg14 = locked_virtio_pci_device.read_config_register(0xe);
        assert_eq!(reg14, 0);

        //               |    8 bits   |   8 bits  |    8 bits     |     8 bits     |
        // register 0xf: | max latency | min grant | Interrupt pin | Interrupt line |
        //
        // We don't specify any of those
        let reg15 = locked_virtio_pci_device.read_config_register(0xf);
        assert_eq!(reg15, 0);
    }

    /// Firecracker's PCI configuration space, of an entropy device attached over PCI as the first
    /// device of `create_vmm_with_virtio_pci_device`'s VM: its 64 registers as read, the header,
    /// BARs and capability chain, then its six BARs' sizes as a guest reads them, all ones written
    /// first (cladefs TASK-267).
    const UPSTREAM_RNG_CONFIG_SPACE: [u32; 64] = [
        0x10441af4, 0x00100000, 0xffff0001, 0x00000000, 0x00000004, 0x00000040, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x10441af4, 0x00000000, 0x00000040,
        0x00000000, 0x00000000, 0x01105009, 0x00000000, 0x00000000, 0x00000038, 0x03106009,
        0x00000000, 0x00002000, 0x00000001, 0x04107009, 0x00000000, 0x00004000, 0x00001000,
        0x02148409, 0x00000000, 0x00006000, 0x00001000, 0x00000004, 0x05149809, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x80010011, 0x00008000, 0x00048000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000,
    ];
    const UPSTREAM_RNG_BAR_SIZES: [u32; 6] = [
        0xfff80004, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    ];

    /// A device without shared memory regions is upstream's PCI device: its configuration space,
    /// register by register, and its BARs' sizes are as upstream makes them (cladefs TASK-267): no
    /// BAR 2, no capability more, the chain as it was.
    #[test]
    fn test_config_space_as_upstream() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked = device.lock().unwrap();
        let registers: Vec<u32> = (0..64)
            .map(|reg| locked.read_config_register(reg))
            .collect();
        let sizes: Vec<u32> = (0..6)
            .map(|bar| {
                locked.write_config_register(4 + bar, 0, &[0xff; 4]);
                locked.read_config_register(4 + bar)
            })
            .collect();
        assert_eq!(
            (registers.as_slice(), sizes.as_slice()),
            (
                UPSTREAM_RNG_CONFIG_SPACE.as_slice(),
                UPSTREAM_RNG_BAR_SIZES.as_slice()
            ),
            "\nregisters: {registers:#010x?}\nsizes: {sizes:#010x?}"
        );
    }

    #[test]
    fn test_reading_bars() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // According to OSdev wiki (https://wiki.osdev.org/PCI#Configuration_Space):
        //
        // When you want to retrieve the actual base address of a BAR, be sure to mask the lower
        // bits. For 16-bit Memory Space BARs, you calculate (BAR[x] & 0xFFF0). For 32-bit Memory
        // Space BARs, you calculate (BAR[x] & 0xFFFFFFF0). For 64-bit Memory Space BARs, you
        // calculate ((BAR[x] & 0xFFFFFFF0) + ((BAR[x + 1] & 0xFFFFFFFF) << 32)) For I/O Space
        // BARs, you calculate (BAR[x] & 0xFFFFFFFC).

        // We are allocating a single 64-bit MMIO bar for VirtIO capabilities list. As a result, we
        // are using the first two BAR registers from the configuration space.
        //
        // The BAR address layout is as follows:
        //
        // |          Bits 31-4           |     Bit 3    | Bits 2-1 |   Bit 0  |
        // | 16-Byte Aligned Base Address | Prefetchable |   Type   | Always 0 |
        //
        // For 64-bit addresses though a second BAR is used to hold the upper 32 bits
        // of the address. Prefetchable and type will be help in the lower bits of the
        // first bar along with the lower 32-bits of the address which is always 16-bytes
        // aligned.
        let bar_addr_lo = locked_virtio_pci_device.read_config_register(0x4);
        let bar_addr_hi = locked_virtio_pci_device.read_config_register(0x5);
        let bar_addr = bar_addr_lo as u64 + ((bar_addr_hi as u64) << 32);

        // Bit 0 always 0
        assert_eq!(bar_addr & 0x1, 0);
        // Type is 0x2 meaning 64-bit BAR
        assert_eq!((bar_addr & 0x6) >> 1, 2);
        // The actual address of the BAR should be the first available address of our 64-bit MMIO
        // region
        assert_eq!(bar_addr & 0xffff_ffff_ffff_fff0, MEM_64BIT_DEVICES_START);

        // Reading the BAR size is a bit more convoluted. According to OSDev wiki:
        //
        // To determine the amount of address space needed by a PCI device, you must save the
        // original value of the BAR, write a value of all 1's to the register, then read it back.
        // The amount of memory can then be determined by masking the information bits, performing
        // a bitwise NOT ('~' in C), and incrementing the value by 1.

        locked_virtio_pci_device.write_config_register(0x4, 0, &[0xff, 0xff, 0xff, 0xff]);
        // Read the lower size bits and mask out the last 4 bits include Prefetchable, Type and
        // hardwired-0
        let bar_size_lo = locked_virtio_pci_device.read_config_register(0x4) as u64 & 0xfffffff0;
        locked_virtio_pci_device.write_config_register(0x5, 0, &[0xff, 0xff, 0xff, 0xff]);
        let bar_size_hi = locked_virtio_pci_device.read_config_register(0x5) as u64;
        let bar_size = !((bar_size_hi << 32) | bar_size_lo) + 1;

        // We create a capabilities BAR region of 0x80000 bytes
        assert_eq!(bar_size, 0x80000);
    }

    fn kvm_vm(vmm: &Vmm) -> &Arc<KvmVm> {
        vmm.vm.as_kvm().unwrap()
    }

    fn write_bar_base(device: &mut VirtioPciDevice, base: u64) {
        device.write_config_register(BAR0_REG_IDX, 0, &(base as u32).to_le_bytes());
        device.write_config_register(BAR0_REG_IDX + 1, 0, &((base >> 32) as u32).to_le_bytes());
    }

    fn set_memory_space_enable(device: &mut VirtioPciDevice, enable: bool) {
        let command = if enable {
            COMMAND_MEMORY_SPACE_ENABLE as u16
        } else {
            0
        };
        device.write_config_register(COMMAND_REG, 0, &command.to_le_bytes());
    }

    fn allocate_bar_range(vmm: &Vmm, base: u64) -> Result<RangeInclusive, vm_allocator::Error> {
        kvm_vm(vmm).resource_allocator().mmio64_memory.allocate(
            CAPABILITY_BAR_SIZE,
            CAPABILITY_BAR_SIZE,
            AllocPolicy::ExactMatch(base),
        )
    }

    /// Try to register an ioeventfd at the notification address of a BAR
    /// mapped at `base`. KVM returns EEXIST if a colliding MMIO ioeventfd is
    /// already registered there, which makes the notification ioeventfds of
    /// the device directly observable.
    fn register_probe_ioevent(vmm: &Vmm, base: u64) -> Result<(), kvm_ioctls::Error> {
        let probe = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let notify = IoEventAddress::Mmio(base + u64::from(NOTIFICATION_BAR_OFFSET));
        kvm_vm(vmm)
            .fd()
            .register_ioevent(&probe, &notify, NoDatamatch)
    }

    #[test]
    fn test_bar_relocation() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let old_base = MEM_64BIT_DEVICES_START;
        let new_base = old_base + CAPABILITY_BAR_SIZE;

        {
            let mut device = device.lock().unwrap();
            assert_eq!(device.bar_address(), old_base);

            // Writing the BAR does not move the device on its own. The
            // relocation happens when memory space decoding gets enabled.
            write_bar_base(&mut device, new_base);
            assert_eq!(device.config_bar_addr(), new_base);
            assert_eq!(device.bar_address(), old_base);

            set_memory_space_enable(&mut device, true);
            assert_eq!(device.bar_address(), new_base);
        }

        // The mmio bus mapping followed the BAR.
        let mut data = [0u8; 4];
        kvm_vm(&vmm)
            .common
            .mmio_bus
            .read(new_base, &mut data)
            .unwrap();
        kvm_vm(&vmm)
            .common
            .mmio_bus
            .read(old_base, &mut data)
            .unwrap_err();

        // The old range is free and the new one is taken.
        allocate_bar_range(&vmm, old_base).unwrap();
        allocate_bar_range(&vmm, new_base).unwrap_err();

        // The notification ioeventfds followed the BAR: KVM rejects a second
        // registration at the new notify address and accepts one at the old.
        register_probe_ioevent(&vmm, new_base).unwrap_err();
        register_probe_ioevent(&vmm, old_base).unwrap();
    }

    #[test]
    fn test_bar_relocation_on_memory_space_enable_only() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut device = device.lock().unwrap();
        let old_base = MEM_64BIT_DEVICES_START;
        let new_base = old_base + CAPABILITY_BAR_SIZE;

        // Enabling memory space decoding with an unchanged BAR is a no-op.
        set_memory_space_enable(&mut device, true);
        assert_eq!(device.bar_address(), old_base);

        // A BAR write while memory space decoding is already enabled does not
        // relocate the device.
        write_bar_base(&mut device, new_base);
        assert_eq!(device.bar_address(), old_base);

        // Only the transition from disabled to enabled does.
        set_memory_space_enable(&mut device, false);
        assert_eq!(device.bar_address(), old_base);
        set_memory_space_enable(&mut device, true);
        assert_eq!(device.bar_address(), new_base);
    }

    #[test]
    fn test_bar_relocation_refused() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let old_base = MEM_64BIT_DEVICES_START;

        // A range that is already allocated to someone else.
        let taken_base = old_base + CAPABILITY_BAR_SIZE;
        allocate_bar_range(&vmm, taken_base).unwrap();
        // A range outside the 64-bit MMIO window.
        let outside_base = MEM_64BIT_DEVICES_START + MEM_64BIT_DEVICES_SIZE;

        for base in [taken_base, outside_base] {
            let mut device = device.lock().unwrap();
            set_memory_space_enable(&mut device, false);
            write_bar_base(&mut device, base);
            set_memory_space_enable(&mut device, true);
            assert_eq!(device.bar_address(), old_base);
        }

        // The device is still mapped at its old base.
        let mut data = [0u8; 4];
        kvm_vm(&vmm)
            .common
            .mmio_bus
            .read(old_base, &mut data)
            .unwrap();

        // The notification ioeventfds did not move either: KVM rejects a
        // second registration at the old notify address
        register_probe_ioevent(&vmm, old_base).unwrap_err();
    }

    fn read_virtio_pci_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciCap) {
        let word1 = device.read_config_register((offset >> 2) as u16);
        let word2 = device.read_config_register((offset >> 2) as u16 + 1);
        let word3 = device.read_config_register((offset >> 2) as u16 + 2);
        let word4 = device.read_config_register((offset >> 2) as u16 + 3);

        let id = PciCapabilityId::from((word1 & 0xff) as u8);
        let next = ((word1 >> 8) & 0xff) as u8;

        let cap = VirtioPciCap {
            cap_len: ((word1 >> 16) & 0xff) as u8,
            cfg_type: ((word1 >> 24) & 0xff) as u8,
            pci_bar: (word2 & 0xff) as u8,
            id: ((word2 >> 8) & 0xff) as u8,
            padding: [0u8; 2],
            offset: Le32::from(word3),
            length: Le32::from(word4),
        };

        // We only ever set a single capability of a type. It's ID is 0.
        assert_eq!(cap.id, 0);

        (id, next, cap)
    }

    fn read_virtio_notification_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciNotifyCap) {
        let (id, next, cap) = read_virtio_pci_cap(device, offset);
        let word5 = device.read_config_register((offset >> 2) as u16 + 4);

        let notification_cap = VirtioPciNotifyCap {
            cap,
            notify_off_multiplier: Le32::from(word5),
        };

        (id, next, notification_cap)
    }

    fn read_virtio_pci_config_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciCfgCap) {
        let (id, next, cap) = read_virtio_pci_cap(device, offset);
        let word5 = device.read_config_register((offset >> 2) as u16 + 4);

        let pci_cfg_cap = VirtioPciCfgCap {
            cap,
            pci_cfg_data: word5.as_slice().try_into().unwrap(),
        };

        (id, next, pci_cfg_cap)
    }

    fn read_msix_cap(device: &mut VirtioPciDevice, offset: u32) -> (PciCapabilityId, u8, MsixCap) {
        let word1 = device.read_config_register((offset >> 2) as u16);
        let table = device.read_config_register((offset >> 2) as u16 + 1);
        let pba = device.read_config_register((offset >> 2) as u16 + 2);

        let id = PciCapabilityId::from((word1 & 0xff) as u8);
        let next = ((word1 >> 8) & 0xff) as u8;

        let cap = MsixCap {
            msg_ctl: (word1 & 0xffff) as u16,
            table,
            pba,
        };

        (id, next, cap)
    }

    fn capabilities_start(device: &mut VirtioPciDevice) -> u32 {
        device.read_config_register(0xd) & 0xfc
    }

    #[test]
    fn test_capabilities() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // VirtIO devices need to expose a set of mandatory capabilities:
        // * Common configuration
        // * Notifications
        // * ISR status
        // * PCI configuration access
        //
        // and, optionally, a device-specific configuration area for those devices that need it.
        //
        // We always expose all 5 capabilities, so check that the capabilities are present

        // Common config
        let common_config_cap_offset = capabilities_start(&mut locked_virtio_pci_device);
        let (id, next, cap) =
            read_virtio_pci_cap(&mut locked_virtio_pci_device, common_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Common as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), COMMON_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), COMMON_CONFIG_SIZE);
        assert_eq!(next as u32, common_config_cap_offset + cap.cap_len as u32);

        // ISR
        let isr_cap_offset = next as u32;
        let (id, next, cap) = read_virtio_pci_cap(&mut locked_virtio_pci_device, isr_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Isr as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), ISR_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), ISR_CONFIG_SIZE);
        assert_eq!(next as u32, isr_cap_offset + cap.cap_len as u32);

        // Device config
        let device_config_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_pci_cap(&mut locked_virtio_pci_device, device_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Device as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), DEVICE_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), DEVICE_CONFIG_SIZE);
        assert_eq!(next as u32, device_config_cap_offset + cap.cap_len as u32);

        let notification_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_notification_cap(&mut locked_virtio_pci_device, notification_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(
            cap.cap.cap_len as usize,
            size_of::<VirtioPciNotifyCap>() + 2
        );
        assert_eq!(cap.cap.cfg_type, PciCapabilityType::Notify as u8);
        assert_eq!(cap.cap.pci_bar, 0);
        assert_eq!(u32::from(cap.cap.offset), NOTIFICATION_BAR_OFFSET);
        assert_eq!(u32::from(cap.cap.length), NOTIFICATION_SIZE);
        assert_eq!(
            next as u32,
            notification_cap_offset + cap.cap.cap_len as u32
        );
        assert_eq!(u32::from(cap.notify_off_multiplier), NOTIFY_OFF_MULTIPLIER);

        let pci_config_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_pci_config_cap(&mut locked_virtio_pci_device, pci_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap.cap_len as usize, size_of::<VirtioPciCfgCap>() + 2);
        assert_eq!(cap.cap.cfg_type, PciCapabilityType::Pci as u8);
        assert_eq!(cap.cap.pci_bar, 0);
        assert_eq!(u32::from(cap.cap.offset), 0);
        assert_eq!(u32::from(cap.cap.length), 0);
        assert_eq!(
            locked_virtio_pci_device.cap_pci_cfg_info.offset,
            pci_config_cap_offset as u16 + 2
        );
        assert_eq!(locked_virtio_pci_device.cap_pci_cfg_info.cap, cap);
        assert_eq!(next as u32, pci_config_cap_offset + cap.cap.cap_len as u32);

        let msix_cap_offset = next as u32;
        let (id, next, _cap) = read_msix_cap(&mut locked_virtio_pci_device, msix_cap_offset);
        assert_eq!(id, PciCapabilityId::MsiX);
        assert_eq!(next, 0);
    }

    /// A device with shared memory regions `regions`, of `len` bytes from the start of a range
    /// of the 64-bit MMIO gap allocated as [`shm_bar_size`] says, attached over PCI.
    fn create_vmm_with_shm_regions(
        len: u64,
        regions: impl FnOnce(u64) -> Vec<VirtioShmRegion>,
    ) -> (Vmm, u64) {
        let mut vmm = default_vmm_with_pci();
        let size = shm_bar_size(len);
        let addr = vmm
            .vm
            .as_kvm()
            .unwrap()
            .resource_allocator()
            .mmio64_memory
            .allocate(size, size, AllocPolicy::FirstMatch)
            .unwrap()
            .start();
        let mut dummy = DummyDevice::new();
        dummy.set_shm_regions(regions(addr));
        let mut event_manager = crate::EventManager::new().unwrap();
        vmm.device_manager
            .attach_boot_virtio_device(
                &vmm.vm,
                "dummy".to_string(),
                Arc::new(Mutex::new(dummy)),
                &mut Cmdline::new(1024).unwrap(),
                &mut event_manager,
                false,
            )
            .unwrap();
        (vmm, addr)
    }

    /// The vendor capabilities of `device` of type `cfg_type`, at their offsets.
    fn find_virtio_caps(device: &mut VirtioPciDevice, cfg_type: PciCapabilityType) -> Vec<u32> {
        let mut found = Vec::new();
        let mut offset = capabilities_start(device);
        while offset != 0 {
            let word1 = device.read_config_register((offset >> 2) as u16);
            if PciCapabilityId::from((word1 & 0xff) as u8) == PciCapabilityId::VendorSpecific
                && (word1 >> 24) as u8 == cfg_type as u8
            {
                found.push(offset);
            }
            offset = (word1 >> 8) & 0xff;
        }
        found
    }

    fn read_virtio_pci_cap64(device: &mut VirtioPciDevice, offset: u32) -> VirtioPciCap64 {
        let words: Vec<u32> = (0..6)
            .map(|i| device.read_config_register((offset >> 2) as u16 + i))
            .collect();
        VirtioPciCap64 {
            cap: VirtioPciCap {
                cap_len: ((words[0] >> 16) & 0xff) as u8,
                cfg_type: ((words[0] >> 24) & 0xff) as u8,
                pci_bar: (words[1] & 0xff) as u8,
                id: ((words[1] >> 8) & 0xff) as u8,
                padding: [((words[1] >> 16) & 0xff) as u8, (words[1] >> 24) as u8],
                offset: Le32::from(words[2]),
                length: Le32::from(words[3]),
            },
            offset_hi: Le32::from(words[4]),
            length_hi: Le32::from(words[5]),
        }
    }

    /// The address register's value, and the size, of the 64-bit BAR `bar`, as a guest sizes it,
    /// restoring the BAR registers afterward.
    fn read_bar_64(device: &mut VirtioPciDevice, bar: u16) -> (u64, u64) {
        let (lo, hi) = (0x4 + bar, 0x5 + bar);
        let orig_lo = device.read_config_register(lo);
        let orig_hi = device.read_config_register(hi);
        let addr = u64::from(orig_lo) | (u64::from(orig_hi) << 32);
        device.write_config_register(lo, 0, &[0xff; 4]);
        let size_lo = u64::from(device.read_config_register(lo)) & 0xffff_fff0;
        device.write_config_register(hi, 0, &[0xff; 4]);
        let size_hi = u64::from(device.read_config_register(hi));
        device.write_config_register(lo, 0, &orig_lo.to_le_bytes());
        device.write_config_register(hi, 0, &orig_hi.to_le_bytes());
        (addr, (!((size_hi << 32) | size_lo)).wrapping_add(1))
    }

    /// A device type the modern IDs name has its modern ID as both. (One past them, the last
    /// transitional ID and its type the subsystem device ID, is the cladefs feature's extent device,
    /// which its commit tests here.)
    #[test]
    fn test_pci_device_ids() {
        assert_eq!(pci_device_ids(VirtioDeviceType::Net), (0x1041, 0x1041));
        assert_eq!(pci_device_ids(VirtioDeviceType::Rng), (0x1044, 0x1044));
        assert_eq!(pci_device_ids(VirtioDeviceType::Pmem), (0x105b, 0x105b));
    }

    #[test]
    fn test_shm_bar() {
        assert_eq!(shm_bar(&[]), None);
        let region = |id, guest_addr, len| VirtioShmRegion {
            id,
            guest_addr,
            len,
        };
        assert_eq!(
            shm_bar(&[region(0, 0x40_0000_0000, 3 << 30)]),
            Some((0x40_0000_0000, 4 << 30))
        );
        assert_eq!(
            shm_bar(&[
                region(1, 0x40_4000_0000, 1 << 20),
                region(0, 0x40_0000_0000, 2 << 20)
            ]),
            Some((0x40_0000_0000, 2 << 30))
        );
        assert_eq!(shm_bar_size(64 << 30), 64 << 30);
        assert_eq!(shm_bar_size((64 << 30) + (2 << 20)), 128 << 30);
    }

    /// A device's shared memory region is a 64-bit prefetchable BAR of its own, BAR 2, which a
    /// `virtio_pci_cap64` of type SHARED_MEMORY_CFG describes, after the other capabilities
    /// (virtio 1.2, section 4.1.4.7).
    #[test]
    fn test_shared_memory_capabilities() {
        let (vmm, addr) = create_vmm_with_shm_regions(5 << 30, |addr| {
            vec![VirtioShmRegion {
                id: 3,
                guest_addr: addr,
                len: 5 << 30,
            }]
        });
        let device = pci_devices(&vmm.device_manager)
            .get_virtio_device(VirtioDeviceType::Rng, "dummy")
            .unwrap()
            .clone();
        let mut device = device.lock().unwrap();

        // 64-bit (0b100) and prefetchable (0b1000), naturally aligned, 8 GiB: 5 GiB rounded up.
        let (bar, size) = read_bar_64(&mut device, 2);
        assert_eq!(bar, addr | 0b1100);
        assert_eq!(size, 8 << 30);
        assert_eq!(addr % size, 0);
        assert_eq!(device.shm_bar_addr(), Some(addr));
        // The configuration's BAR is where it was.
        let (bar0, size0) = read_bar_64(&mut device, 0);
        assert_eq!(bar0 & !0xf, device.config_bar_addr());
        assert_eq!(size0, CAPABILITY_BAR_SIZE);

        let offsets = find_virtio_caps(&mut device, PciCapabilityType::SharedMemory);
        let caps: Vec<VirtioPciCap64> = offsets
            .iter()
            .map(|&offset| read_virtio_pci_cap64(&mut device, offset))
            .collect();
        assert_eq!(caps, vec![VirtioPciCap64::shared_memory(2, 3, 0, 5 << 30)]);
        // What Linux's virtio_pci_find_shm_cap takes: cap_len of a virtio_pci_cap64's 24 bytes,
        // and the halves of the offset and length.
        assert_eq!(caps[0].cap.cap_len, 24);
        assert_eq!(caps[0].cap.cfg_type, 8);
        assert_eq!(caps[0].cap.pci_bar, 2);
        assert_eq!(u32::from(caps[0].cap.offset), 0);
        assert_eq!(u32::from(caps[0].offset_hi), 0);
        assert_eq!(u32::from(caps[0].cap.length), 1 << 30);
        assert_eq!(u32::from(caps[0].length_hi), 1);
        // After the MSI-X capability, the last of the others.
        let msix = device.msix_config_cap_offset as u32;
        assert!(offsets.iter().all(|&offset| offset > msix));
    }

    /// Reprogramming the shared memory BAR (BAR 2) and re-enabling memory space decoding reverts
    /// BAR 2 back to its fixed backing slot address so config space never diverges from the slot.
    #[test]
    fn test_shared_memory_bar_relocation_refused() {
        let (vmm, addr) = create_vmm_with_shm_regions(5 << 30, |addr| {
            vec![VirtioShmRegion {
                id: 3,
                guest_addr: addr,
                len: 5 << 30,
            }]
        });
        let device = pci_devices(&vmm.device_manager)
            .get_virtio_device(VirtioDeviceType::Rng, "dummy")
            .unwrap()
            .clone();
        let mut device = device.lock().unwrap();
        let new_addr = addr + (8 << 30);

        set_memory_space_enable(&mut device, false);
        device.write_config_register(BAR0_REG_IDX + 2, 0, &(new_addr as u32).to_le_bytes());
        device.write_config_register(
            BAR0_REG_IDX + 3,
            0,
            &((new_addr >> 32) as u32).to_le_bytes(),
        );
        set_memory_space_enable(&mut device, true);

        assert_eq!(device.shm_bar_addr(), Some(addr));
        let (bar, size) = read_bar_64(&mut device, 2);
        assert_eq!(bar, addr | 0b1100);
        assert_eq!(size, 8 << 30);
    }

    /// A device without shared memory regions has no BAR 2, nor a SHARED_MEMORY_CFG capability.
    #[test]
    fn test_no_shared_memory_capabilities() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut device = device.lock().unwrap();
        assert_eq!(read_bar_64(&mut device, 2), (0, 0));
        assert_eq!(device.shm_bar_addr(), None);
        assert_eq!(
            find_virtio_caps(&mut device, PciCapabilityType::SharedMemory),
            Vec::<u32>::new()
        );
    }

    fn cap_pci_cfg_read(device: &mut VirtioPciDevice, bar_offset: u32, length: u32) -> u32 {
        let pci_config_cap_offset = capabilities_start(device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2)
            + (size_of::<VirtioPciNotifyCap>() + 2);

        // To program the access through the PCI config capability mechanism, we need to write the
        // bar offset and read length in the `VirtioPciCfgCap::cap.offset` and
        // `VirtioPciCfgCap::length` fields. These are the third and fourth word respectively
        // within the capability. The fifth word of the capability should contain the data
        let offset_register = ((pci_config_cap_offset + 8) >> 2) as u16;
        let length_register = ((pci_config_cap_offset + 12) >> 2) as u16;
        let data_register = ((pci_config_cap_offset + 16) >> 2) as u16;

        device.write_config_register(offset_register, 0, bar_offset.as_slice());
        device.write_config_register(length_register, 0, length.as_slice());
        device.read_config_register(data_register)
    }

    fn cap_pci_cfg_write(device: &mut VirtioPciDevice, bar_offset: u32, length: u32, data: &[u8]) {
        let pci_config_cap_offset = capabilities_start(device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2)
            + (size_of::<VirtioPciNotifyCap>() + 2);

        // To program the access through the PCI config capability mechanism, we need to write the
        // bar offset and read length in the `VirtioPciCfgCap::cap.offset` and
        // `VirtioPciCfgCap::length` fields. These are the third and fourth word respectively
        // within the capability. The fifth word of the capability should contain the data
        let offset_register = ((pci_config_cap_offset + 8) >> 2) as u16;
        let length_register = ((pci_config_cap_offset + 12) >> 2) as u16;
        let data_register = ((pci_config_cap_offset + 16) >> 2) as u16;

        device.write_config_register(offset_register, 0, bar_offset.as_slice());
        device.write_config_register(length_register, 0, length.as_slice());
        device.write_config_register(data_register, 0, data);
    }

    #[test]
    fn test_pci_configuration_cap() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // Let's read the number of queues of the entropy device
        // That information is located at NUM_QUEUES offset past the BAR region belonging to the
        // common config capability.
        let bar_offset = COMMON_CONFIG_BAR_OFFSET + u32::try_from(NUM_QUEUES).unwrap();
        let len = 2u32;
        let num_queues = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(num_queues, 1);

        // Use queue_select to test read/write through the PCI Configuration Access Capability.
        // This register is freely read-writable with no side effects, making it ideal for testing
        // the capability mechanism itself.
        let bar_offset = COMMON_CONFIG_BAR_OFFSET + QUEUE_SELECT as u32;
        let len = 2u32;
        let val = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(val, 0);

        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            len,
            0x01u32.as_slice(),
        );
        let val = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(val, 0x01);

        // Reads with out-of-bounds lengths should return 0s
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, 8),
            0
        );
        // Writes with out-of-bounds lengths should have no effect
        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            8,
            0xDEADu32.as_slice(),
        );
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len),
            val
        );

        // When the capability's length is shorter than pci_cfg_data (4 bytes), only that many
        // bytes should be forwarded to the BAR write. Writing 0xDEAD_0000 with length=2 should
        // only write the lower 2 bytes (0x0000).
        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            len,
            0xDEAD_0000u32.as_slice(),
        );
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len),
            0x0000
        );
    }

    fn isr_status_read(device: &mut VirtioPciDevice) -> u32 {
        let mut data = 0u32;
        device.read_bar(0, u64::from(ISR_CONFIG_BAR_OFFSET), data.as_mut_slice());
        data
    }

    fn isr_status_write(device: &mut VirtioPciDevice, data: u32) {
        device.write_bar(0, u64::from(ISR_CONFIG_BAR_OFFSET), data.as_slice());
    }

    #[test]
    fn test_isr_capability() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // We don't support legacy interrupts so reads to ISR BAR should always return 0s and
        // writes to it should not have any effect
        assert_eq!(isr_status_read(&mut locked_virtio_pci_device), 0);
        isr_status_write(&mut locked_virtio_pci_device, 0x1312);
        assert_eq!(isr_status_read(&mut locked_virtio_pci_device), 0);
    }

    #[test]
    fn test_notification_capability() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        let notification_cap_offset = (capabilities_start(&mut locked_virtio_pci_device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2))
            .try_into()
            .unwrap();

        let (_, _, notify_cap) =
            read_virtio_notification_cap(&mut locked_virtio_pci_device, notification_cap_offset);

        // We do not offer `VIRTIO_F_NOTIFICATION_DATA` so:
        // * `cap.offset` MUST by 2-byte aligned
        assert_eq!(u32::from(notify_cap.cap.offset) & 0x3, 0);
        // * The device MUST either present notify_off_multiplier as an even power of 2, or present
        //   notify_off_multiplier as 0.
        let multiplier = u32::from(notify_cap.notify_off_multiplier);
        assert!(multiplier.is_power_of_two() && multiplier.trailing_zeros() % 2 == 0);
        // * For all queues, the value cap.length presented by the device MUST satisfy:
        //
        //   `cap.length >= queue_notify_off * notify_off_multiplier + 2`
        //
        // The spec allows for up to 65536 queues, but in reality the device we are using with most
        // queues is vsock (3). Let's check here for 16, projecting for future devices and
        // use-cases such as multiple queue pairs in network devices
        assert!(u32::from(notify_cap.cap.length) >= 15 * multiplier + 2);

        // Reads and writes to the notification region of the BAR are handled by IoEvent file
        // descriptors. Any such accesses should have no effects.
        let data = [0x42u8; NOTIFICATION_SIZE as usize];
        locked_virtio_pci_device.write_bar(0, u64::from(NOTIFICATION_BAR_OFFSET), &data);
        let mut buffer = [0x0; NOTIFICATION_SIZE as usize];
        locked_virtio_pci_device.read_bar(0, u64::from(NOTIFICATION_BAR_OFFSET), &mut buffer);
        assert_eq!(buffer, [0u8; NOTIFICATION_SIZE as usize]);
    }

    const COMMON_CFG: u64 = COMMON_CONFIG_BAR_OFFSET as u64;

    fn write_driver_status(device: &mut VirtioPciDevice, status: u8) {
        device.write_bar(0, COMMON_CFG + DEVICE_STATUS, status.as_slice());
    }

    fn read_driver_status(device: &mut VirtioPciDevice) -> u8 {
        let mut status = 0u8;
        device.read_bar(0, COMMON_CFG + DEVICE_STATUS, status.as_mut_slice());
        status
    }

    fn read_device_features(device: &mut VirtioPciDevice) -> u64 {
        let mut features_lo = 0u32;
        device.write_bar(0, COMMON_CFG + DEVICE_FEATURE_SELECT, 0u32.as_slice());
        device.read_bar(0, COMMON_CFG + DEVICE_FEATURE, features_lo.as_mut_slice());
        let mut features_hi = 0u32;
        device.write_bar(0, COMMON_CFG + DEVICE_FEATURE_SELECT, 1u32.as_slice());
        device.read_bar(0, COMMON_CFG + DEVICE_FEATURE, features_hi.as_mut_slice());

        features_lo as u64 | ((features_hi as u64) << 32)
    }

    fn write_driver_features(device: &mut VirtioPciDevice, features: u64) {
        device.write_bar(0, COMMON_CFG + DRIVER_FEATURE_SELECT, 0u32.as_slice());
        device.write_bar(
            0,
            COMMON_CFG + DRIVER_FEATURE,
            ((features & 0xffff_ffff) as u32).as_slice(),
        );
        device.write_bar(0, COMMON_CFG + DRIVER_FEATURE_SELECT, 1u32.as_slice());
        device.write_bar(
            0,
            COMMON_CFG + DRIVER_FEATURE,
            (((features >> 32) & 0xffff_ffff) as u32).as_slice(),
        );
    }

    fn setup_queues(device: &mut VirtioPciDevice) {
        device.write_bar(0, COMMON_CFG + QUEUE_DESC_LO, 0x8000_0000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_AVAIL_LO, 0x8000_1000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_USED_LO, 0x8000_2000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_ENABLE, 1u16.as_slice());
    }

    #[test]
    fn test_device_initialization() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        assert!(locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        write_driver_status(&mut locked_virtio_pci_device, ACKNOWLEDGE);
        write_driver_status(&mut locked_virtio_pci_device, ACKNOWLEDGE | DRIVER);
        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        let status = read_driver_status(&mut locked_virtio_pci_device);
        assert_eq!(status, ACKNOWLEDGE | DRIVER);

        // Entropy device just offers VIRTIO_F_VERSION_1
        let offered_features = read_device_features(&mut locked_virtio_pci_device);
        assert_eq!(offered_features, 1 << VIRTIO_F_VERSION_1);
        // ACK features
        write_driver_features(&mut locked_virtio_pci_device, offered_features);
        write_driver_status(
            &mut locked_virtio_pci_device,
            ACKNOWLEDGE | DRIVER | FEATURES_OK,
        );
        let status = read_driver_status(&mut locked_virtio_pci_device);
        assert!((status & FEATURES_OK) != 0);

        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        setup_queues(&mut locked_virtio_pci_device);

        write_driver_status(
            &mut locked_virtio_pci_device,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );

        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(locked_virtio_pci_device.is_driver_ready());
        assert!(
            locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );
    }

    #[test]
    fn test_activate_failure_sets_needs_reset() {
        // Verify that DEVICE_NEEDS_RESET is set in driver_status when device activation fails.
        use crate::devices::virtio::transport::pci::device_status::DEVICE_NEEDS_RESET;

        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked = device.lock().unwrap();

        // Drive through init without setting up queues, so activate() fails.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER);
        let features = read_device_features(&mut locked);
        write_driver_features(&mut locked, features);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        // Skip setup_queues() -- queues are not ready, so activate() will fail.
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);

        assert!(!locked.device_activated.load(Ordering::SeqCst));
        let status = read_driver_status(&mut locked);
        assert_eq!(status & DEVICE_NEEDS_RESET, DEVICE_NEEDS_RESET);
    }

    #[test]
    fn test_reset_and_reinitialization() {
        let vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked = device.lock().unwrap();

        // Full initialization sequence.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER);
        let features = read_device_features(&mut locked);
        write_driver_features(&mut locked, features);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        setup_queues(&mut locked);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
        assert!(locked.device_activated.load(Ordering::SeqCst));

        // Write 0 to device_status to request a reset.
        write_driver_status(&mut locked, 0);
        assert_eq!(read_driver_status(&mut locked), 0);
        // Device should be deactivated after successful reset.
        assert!(!locked.device_activated.load(Ordering::SeqCst));

        // Re-initialization should succeed after a successful reset.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        assert_eq!(read_driver_status(&mut locked), ACKNOWLEDGE);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER);
        let features = read_device_features(&mut locked);
        write_driver_features(&mut locked, features);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        setup_queues(&mut locked);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
        assert!(locked.device_activated.load(Ordering::SeqCst));
    }
}
