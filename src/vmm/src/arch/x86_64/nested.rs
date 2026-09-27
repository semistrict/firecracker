// SPDX-License-Identifier: Apache-2.0

//! Nested virtualization on Intel VMX: the controls a guest hypervisor is
//! offered, and the state KVM keeps for it across a snapshot.

use std::collections::BTreeMap;

use kvm_bindings::{CpuId, Msrs, kvm_msr_entry, kvm_nested_state};
use kvm_ioctls::{KvmNestedStateBuffer, VcpuFd};
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

use crate::arch::x86_64::generated::msr_index::{
    MSR_IA32_VMX_BASIC, MSR_IA32_VMX_CR0_FIXED0, MSR_IA32_VMX_CR4_FIXED0,
    MSR_IA32_VMX_EPT_VPID_CAP, MSR_IA32_VMX_MISC, MSR_IA32_VMX_PROCBASED_CTLS2,
    MSR_IA32_VMX_TRUE_ENTRY_CTLS, MSR_IA32_VMX_TRUE_EXIT_CTLS, MSR_IA32_VMX_TRUE_PINBASED_CTLS,
    MSR_IA32_VMX_TRUE_PROCBASED_CTLS, MSR_IA32_VMX_VMCS_ENUM, MSR_IA32_VMX_VMFUNC,
};
use crate::arch::x86_64::msr::{MsrError, set_msrs};
use crate::utils::u64_to_usize;

/// CPUID.1:ECX bit 5: the processor has VMX.
const CPUID_1_ECX_VMX: u32 = 1 << 5;

/// Pin-based control: process posted interrupts.
const PIN_BASED_POSTED_INTR: u32 = 1 << 7;
/// Primary processor-based control: use TPR shadow (the virtual-APIC page).
const CPU_BASED_TPR_SHADOW: u32 = 1 << 21;
/// Secondary processor-based control: virtualize APIC accesses.
const SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES: u32 = 1 << 0;
/// Secondary processor-based control: virtualize x2APIC mode.
const SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE: u32 = 1 << 4;
/// Secondary processor-based control: APIC-register virtualization.
const SECONDARY_EXEC_APIC_REGISTER_VIRT: u32 = 1 << 8;
/// Secondary processor-based control: virtual-interrupt delivery.
const SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY: u32 = 1 << 9;

/// The controls a guest hypervisor must not be offered when a pager manages
/// guest memory, by the capability MSR that offers them.
///
/// While L2 runs, KVM maps three L1 pages with kvm_vcpu_map in
/// nested_get_vmcs12_pages: the APIC-access page, the virtual-APIC page and
/// the posted-interrupt descriptor. It keeps them mapped until L2 exits to L1.
/// Those maps pin the host page and bypass the host page tables. The pager
/// write-protects guest RAM to seal it, and moves or frees pages to copy,
/// evict and give them back. KVM and the CPU would keep writing the old page
/// through the pin, so the pager would miss those writes.
///
/// Each page is used only when L1 sets a control in its VMCS. KVM refuses a
/// VM entry whose VMCS sets a control the capability MSRs do not allow. So
/// clearing these allowed-1 bits means KVM never maps those pages.
///
/// The APIC-access page needs "virtualize APIC accesses". The virtual-APIC
/// page needs "use TPR shadow"; x2APIC virtualization, APIC-register
/// virtualization and virtual-interrupt delivery all require it too. The
/// posted-interrupt descriptor needs "process posted interrupts".
const PINNING_CONTROLS: [(u32, u32); 3] = [
    (MSR_IA32_VMX_TRUE_PINBASED_CTLS, PIN_BASED_POSTED_INTR),
    (MSR_IA32_VMX_TRUE_PROCBASED_CTLS, CPU_BASED_TPR_SHADOW),
    (
        MSR_IA32_VMX_PROCBASED_CTLS2,
        SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES
            | SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE
            | SECONDARY_EXEC_APIC_REGISTER_VIRT
            | SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY,
    ),
];

/// The VMX capability MSRs KVM lets userspace set (vmx_set_vmx_msr). KVM
/// derives the others, the non-true controls and CR0/CR4 FIXED1, from these
/// and from CPUID, and refuses writes to them.
pub const VMX_CAPABILITY_MSRS: [u32; 12] = [
    MSR_IA32_VMX_BASIC,
    MSR_IA32_VMX_TRUE_PINBASED_CTLS,
    MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
    MSR_IA32_VMX_TRUE_EXIT_CTLS,
    MSR_IA32_VMX_TRUE_ENTRY_CTLS,
    MSR_IA32_VMX_MISC,
    MSR_IA32_VMX_CR0_FIXED0,
    MSR_IA32_VMX_CR4_FIXED0,
    MSR_IA32_VMX_VMCS_ENUM,
    MSR_IA32_VMX_PROCBASED_CTLS2,
    MSR_IA32_VMX_EPT_VPID_CAP,
    MSR_IA32_VMX_VMFUNC,
];

/// Errors of nested virtualization setup, save and restore.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum NestedError {
    /// Failed to build the VMX capability MSR list: {0}
    Fam(#[from] vmm_sys_util::fam::Error),
    /// Failed to read the VMX capability MSRs: {0}
    GetCapabilities(kvm_ioctls::Error),
    /// KVM did not return VMX capability MSR {0:#x}
    MissingCapability(u32),
    /// KVM refused the VMX capability MSRs: {0}
    SetCapabilities(MsrError),
    /// KVM kept VMX capability MSR {index:#x} at {actual:#x} instead of {expected:#x}
    CapabilityNotNarrowed {
        /// The MSR.
        index: u32,
        /// The value written.
        expected: u64,
        /// The value KVM reads back.
        actual: u64,
    },
    /// KVM does not support KVM_CAP_NESTED_STATE
    NoNestedStateCapability,
    /// KVM nested state takes {0} bytes, more than the {1} this build holds
    NestedStateTooLarge(usize, usize),
    /// Failed to get nested state: {0}
    GetNestedState(kvm_ioctls::Error),
    /// Failed to set nested state: {0}
    SetNestedState(kvm_ioctls::Error),
    /// Saved nested state has {0} bytes, which is not one kvm_nested_state
    NestedStateLength(usize),
    /// Saved nested state has {0} bytes but its header says {1}
    NestedStateSize(usize, usize),
}

/// A vCPU's nested virtualization state, saved in a snapshot when its CPUID
/// offers VMX.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedState {
    /// The VMX capability MSRs L1 was offered, by index. They go back before
    /// the nested state, because KVM refuses them once L1 is in VMX operation.
    pub vmx_capabilities: BTreeMap<u32, u64>,
    /// What KVM_GET_NESTED_STATE returned: the `kvm_nested_state` header and
    /// its data, as many bytes as the header's size.
    pub kvm_nested_state: Vec<u8>,
}

/// Whether this CPUID offers VMX to the guest.
pub fn offers_vmx(cpuid: &CpuId) -> bool {
    cpuid
        .as_slice()
        .iter()
        .any(|entry| entry.function == 1 && entry.ecx & CPUID_1_ECX_VMX != 0)
}

/// Clears, in a VMX capability MSR, the allowed-1 bits of the controls that
/// make KVM pin L1 pages (see [`PINNING_CONTROLS`]). The allowed-1 bits are
/// the high 32 bits. Other MSRs and bits are returned unchanged.
pub fn without_pinning_controls(index: u32, value: u64) -> u64 {
    PINNING_CONTROLS
        .iter()
        .filter(|(msr, _)| *msr == index)
        .fold(value, |value, (_, controls)| {
            value & !(u64::from(*controls) << 32)
        })
}

/// Takes the controls that make KVM pin L1 pages away from what this vCPU
/// offers L1, and checks that KVM holds to it.
///
/// The vCPU's CPUID must offer VMX, and L1 must not be in VMX operation:
/// KVM takes these MSRs only then.
pub fn forbid_pinning_controls(fd: &VcpuFd) -> Result<(), NestedError> {
    let indices = PINNING_CONTROLS.map(|(index, _)| index);
    let narrowed = get_msrs(fd, &indices)?
        .into_iter()
        .map(|(index, value)| (index, without_pinning_controls(index, value)))
        .collect();
    set_capabilities(fd, &narrowed)?;
    let actual = get_msrs(fd, &indices)?;
    match narrowed
        .iter()
        .find(|(index, value)| actual.get(index) != Some(value))
    {
        Some((&index, &expected)) => Err(NestedError::CapabilityNotNarrowed {
            index,
            expected,
            actual: actual.get(&index).copied().unwrap_or_default(),
        }),
        None => Ok(()),
    }
}

/// Writes VMX capability MSRs. L1 must not be in VMX operation.
pub fn set_capabilities(fd: &VcpuFd, msrs: &BTreeMap<u32, u64>) -> Result<(), NestedError> {
    let entries = msrs
        .iter()
        .map(|(&index, &data)| kvm_msr_entry {
            index,
            data,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    set_msrs(fd, &entries).map_err(NestedError::SetCapabilities)
}

/// Saves a vCPU's nested state. `state_size` is what KVM_CAP_NESTED_STATE
/// reports.
pub fn save(fd: &VcpuFd, state_size: Option<usize>) -> Result<NestedState, NestedError> {
    let vmx_capabilities = get_msrs(fd, &VMX_CAPABILITY_MSRS)?;
    let state_size = state_size.ok_or(NestedError::NoNestedStateCapability)?;
    let capacity = size_of::<KvmNestedStateBuffer>();
    if state_size > capacity {
        return Err(NestedError::NestedStateTooLarge(state_size, capacity));
    }
    let mut buffer = KvmNestedStateBuffer::empty();
    // This returns no length when KVM wrote only the header. The header still
    // says whether L1 is in VMX operation, so it is kept either way.
    fd.nested_state(&mut buffer)
        .map_err(NestedError::GetNestedState)?;
    let len = u64_to_usize(u64::from(buffer.size));
    let kvm_nested_state = buffer
        .as_bytes()
        .get(..len)
        .ok_or(NestedError::NestedStateTooLarge(len, capacity))?
        .to_vec();
    Ok(NestedState {
        vmx_capabilities,
        kvm_nested_state,
    })
}

/// Restores a vCPU's nested state saved by [`save`]. The VMX capability MSRs
/// must be set first.
pub fn restore(fd: &VcpuFd, state: &NestedState) -> Result<(), NestedError> {
    fd.set_nested_state(&nested_state_buffer(&state.kvm_nested_state)?)
        .map_err(NestedError::SetNestedState)
}

/// Puts saved nested state bytes back in the buffer KVM_SET_NESTED_STATE
/// takes, checking they are one whole `kvm_nested_state`.
fn nested_state_buffer(bytes: &[u8]) -> Result<KvmNestedStateBuffer, NestedError> {
    let mut buffer = KvmNestedStateBuffer::empty();
    if bytes.len() < size_of::<kvm_nested_state>() || bytes.len() > size_of_val(&buffer) {
        return Err(NestedError::NestedStateLength(bytes.len()));
    }
    buffer.as_mut_bytes()[..bytes.len()].copy_from_slice(bytes);
    let len = u64_to_usize(u64::from(buffer.size));
    if len != bytes.len() {
        return Err(NestedError::NestedStateSize(bytes.len(), len));
    }
    Ok(buffer)
}

/// Reads MSRs that KVM must all return.
fn get_msrs(fd: &VcpuFd, indices: &[u32]) -> Result<BTreeMap<u32, u64>, NestedError> {
    let entries = indices
        .iter()
        .map(|&index| kvm_msr_entry {
            index,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let mut msrs = Msrs::from_entries(&entries)?;
    let read = fd
        .get_msrs(&mut msrs)
        .map_err(NestedError::GetCapabilities)?;
    if let Some(&index) = indices.get(read) {
        return Err(NestedError::MissingCapability(index));
    }
    Ok(msrs
        .as_slice()
        .iter()
        .map(|entry| (entry.index, entry.data))
        .collect())
}

#[cfg(test)]
mod tests {
    use kvm_bindings::kvm_cpuid_entry2;

    use super::*;

    #[test]
    fn test_without_pinning_controls() {
        // Must-be-1 bits (low half) stay. Only the named allowed-1 bits go.
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_TRUE_PINBASED_CTLS, 0x0000_00ff_0000_0016),
            0x0000_007f_0000_0016
        );
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, 0xfff9_fffe_0400_6172),
            0xffd9_fffe_0400_6172
        );
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_PROCBASED_CTLS2, 0x0053_7fff_0000_0000),
            0x0053_7cee_0000_0000
        );
        // A control that is not offered stays not offered.
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_TRUE_PINBASED_CTLS, 0x0000_007f_0000_0016),
            0x0000_007f_0000_0016
        );
        // A low-half bit at a pinning control's position is a must-be-1 bit
        // and is not touched.
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_PROCBASED_CTLS2, 0x0000_0000_0000_0001),
            0x0000_0000_0000_0001
        );
        // Other capability MSRs pass through.
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_TRUE_EXIT_CTLS, u64::MAX),
            u64::MAX
        );
        assert_eq!(
            without_pinning_controls(MSR_IA32_VMX_BASIC, u64::MAX),
            u64::MAX
        );
    }

    #[test]
    fn test_pinning_controls_are_restorable() {
        for (index, _) in PINNING_CONTROLS {
            assert!(VMX_CAPABILITY_MSRS.contains(&index), "{index:#x}");
        }
    }

    fn cpuid(entries: &[(u32, u32)]) -> CpuId {
        CpuId::from_entries(
            &entries
                .iter()
                .map(|&(function, ecx)| kvm_cpuid_entry2 {
                    function,
                    ecx,
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn test_offers_vmx() {
        assert!(offers_vmx(&cpuid(&[(0, 0), (1, 0x20)])));
        assert!(!offers_vmx(&cpuid(&[(0, 0), (1, 0xffff_ffdf)])));
        // Bit 5 of another leaf says nothing about VMX.
        assert!(!offers_vmx(&cpuid(&[(0x8000_0001, 0x20)])));
        assert!(!offers_vmx(&cpuid(&[])));
    }

    fn header(size: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; size_of::<kvm_nested_state>()];
        bytes[4..8].copy_from_slice(&size.to_ne_bytes());
        bytes
    }

    #[test]
    fn test_nested_state_buffer() {
        // A header alone: L1 is not in VMX operation, or has no current VMCS.
        let bytes = header(128);
        let buffer = nested_state_buffer(&bytes).unwrap();
        assert_eq!(buffer.size, 128);
        assert_eq!(&buffer.as_bytes()[..128], bytes.as_slice());

        // A header and a vmcs12.
        let mut bytes = header(128 + 4096);
        bytes.extend((0..4096).map(|i| u8::try_from(i % 251).unwrap()));
        let buffer = nested_state_buffer(&bytes).unwrap();
        assert_eq!(&buffer.as_bytes()[..bytes.len()], bytes.as_slice());

        // The largest VMX state: a header, a vmcs12 and a shadow vmcs12.
        let mut bytes = header(128 + 8192);
        bytes.resize(128 + 8192, 0xa5);
        nested_state_buffer(&bytes).unwrap();
    }

    #[test]
    fn test_nested_state_buffer_malformed() {
        assert_eq!(
            nested_state_buffer(&[]).err(),
            Some(NestedError::NestedStateLength(0))
        );
        assert_eq!(
            nested_state_buffer(&[0; 64]).err(),
            Some(NestedError::NestedStateLength(64))
        );
        // The header names more bytes than were saved.
        assert_eq!(
            nested_state_buffer(&header(128 + 4096)).err(),
            Some(NestedError::NestedStateSize(128, 128 + 4096))
        );
        // More bytes than KVM_SET_NESTED_STATE's buffer holds.
        let too_long = size_of::<KvmNestedStateBuffer>() + 1;
        let mut bytes = header(u32::try_from(too_long).unwrap());
        bytes.resize(too_long, 0);
        assert_eq!(
            nested_state_buffer(&bytes).err(),
            Some(NestedError::NestedStateLength(too_long))
        );
    }

    #[test]
    fn test_nested_state_serialization() {
        let mut kvm_nested_state = header(128 + 4096);
        kvm_nested_state.resize(128 + 4096, 7);
        let state = NestedState {
            vmx_capabilities: VMX_CAPABILITY_MSRS
                .iter()
                .map(|&index| (index, u64::from(index) << 20 | 0x16))
                .collect(),
            kvm_nested_state,
        };
        let bytes = bitcode::serialize(&Some(state.clone())).unwrap();
        let restored: Option<NestedState> = bitcode::deserialize(&bytes).unwrap();
        assert_eq!(restored, Some(state));
    }
}
