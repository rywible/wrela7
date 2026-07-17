//! Minimal compiler-owned boundary between laid-out WIR and bundled runtime code.
//!
//! Source programs cannot name this ABI. Most runtime behavior is generated as
//! ordinary `MachineWir`; these intrinsics exist only where firmware, processor,
//! record/replay, or the image-test harness requires a privileged boundary.

#![forbid(unsafe_code)]

use std::fmt;

pub const RUNTIME_ABI_VERSION: u32 = 2;
pub const TEST_ASSERTION_EXPRESSION_BYTES_MAX: usize = 4096;
pub const TEST_ASSERTION_MESSAGE_BYTES_MAX: usize = 4096;

/// Stable PE/COFF entry symbol selected by the only revision-0.1 target.
pub const IMAGE_ENTRY_SYMBOL: &str = "wrela_image_entry";
/// Target-relative path of the digest-checked runtime implementation object.
pub const RUNTIME_OBJECT_PATH: &str = "runtime/wrela-runtime-aarch64.obj";
/// ARM64 PE/COFF machine identifier (`IMAGE_FILE_MACHINE_ARM64`).
pub const ARM64_COFF_MACHINE: u16 = 0xaa64;

/// UEFI's AArch64 binding keeps the stack 16-byte aligned at every public
/// interface.
pub const AARCH64_UEFI_STACK_ALIGNMENT_BYTES: u32 = 16;
/// UEFI reserves the AArch64 platform register X18 as "do not use".
pub const AARCH64_UEFI_RESERVED_PLATFORM_REGISTER: u8 = 18;
/// The image handle is passed in X0.
pub const AARCH64_UEFI_IMAGE_HANDLE_REGISTER: u8 = 0;
/// The system-table pointer is passed in X1.
pub const AARCH64_UEFI_SYSTEM_TABLE_REGISTER: u8 = 1;
/// `EFI_STATUS` is returned in X0.
pub const AARCH64_UEFI_STATUS_REGISTER: u8 = 0;
/// The firmware return address is passed in X30.
pub const AARCH64_UEFI_RETURN_ADDRESS_REGISTER: u8 = 30;

/// Total deterministic record/replay storage owned by the revision-0.1
/// AArch64 target runtime. A build profile's `event_log_bytes` is a reservation
/// ceiling and therefore includes the mandatory overflow marker below.
pub const EVENT_LOG_STORAGE_BYTES: u64 = 64 * 1024;
/// Bytes permanently reserved at the end of the event log for an explicit,
/// deterministic overflow record. The runtime never silently truncates.
pub const EVENT_LOG_OVERFLOW_MARKER_BYTES: u64 = 8;
/// Bytes available for complete ordinary record/replay records before
/// overflow is represented by the reserved marker. This region includes each
/// record's eight-byte kind/length header; it is not a pure payload ceiling.
pub const EVENT_LOG_RECORD_REGION_BYTES: u64 =
    EVENT_LOG_STORAGE_BYTES - EVENT_LOG_OVERFLOW_MARKER_BYTES;
/// Little-endian bytes in every ordinary record header: `u32 kind` followed by
/// `u32 payload_bytes`.
pub const EVENT_LOG_RECORD_HEADER_BYTES: u32 = 8;
/// Reserved record kind written into the terminal overflow marker.
pub const EVENT_LOG_OVERFLOW_KIND: u32 = u32::MAX;

/// Stable read-only COFF subsection containing the interrupt route table.
pub const INTERRUPT_ROUTE_SECTION: &str = ".rdata$wrela_irq";
/// Stable COFF symbol for the interrupt route table header. A header is emitted
/// even when the route count is zero, so the target runtime never depends on a
/// linker-specific zero-length array symbol.
pub const INTERRUPT_ROUTE_TABLE_SYMBOL: &str = "wrela_rt_v2_interrupt_route_table";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiByteOrder {
    LittleEndian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64CoffRelocation {
    Address64,
}

/// Wire layout of one target-runtime interrupt route. This is deliberately a
/// byte-layout contract rather than a Rust `repr(C)` type: runtime objects may
/// be implemented in another language and must not inherit host ABI choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptRouteLayout {
    pub byte_order: AbiByteOrder,
    pub table_alignment: u32,
    pub header_bytes: u32,
    pub route_count_offset: u32,
    pub header_reserved_offset: u32,
    pub record_bytes: u32,
    pub global_id_offset: u32,
    pub reserved_offset: u32,
    pub handler_address_offset: u32,
    pub handler_relocation: Arm64CoffRelocation,
}

/// Runtime ABI v2 table layout. The header is
/// `{ route_count: u32, reserved_zero: u32 }`; it is followed immediately by
/// route records `{ global_id: u32, reserved_zero: u32, handler_address: u64 }`.
/// Integer fields are little-endian, handler addresses use ordinary ARM64 COFF
/// relocations, records are sorted by `global_id`, and all reserved fields are
/// zero. Duplicate IDs are invalid.
pub const INTERRUPT_ROUTE_LAYOUT: InterruptRouteLayout = InterruptRouteLayout {
    byte_order: AbiByteOrder::LittleEndian,
    table_alignment: 8,
    header_bytes: 8,
    route_count_offset: 0,
    header_reserved_offset: 4,
    record_bytes: 16,
    global_id_offset: 0,
    reserved_offset: 4,
    handler_address_offset: 8,
    handler_relocation: Arm64CoffRelocation::Address64,
};

impl InterruptRouteLayout {
    /// Exact encoded table extent for a canonical route count.
    #[must_use]
    pub fn table_bytes(self, route_count: u32) -> u64 {
        u64::from(self.header_bytes) + u64::from(route_count) * u64::from(self.record_bytes)
    }

    /// Validate the complete little-endian scalar portion of one route table.
    /// The object consumer separately checks the section alignment and the
    /// ARM64 address relocation attached to each handler slot.
    pub fn validate_table(self, bytes: &[u8]) -> Result<(), RuntimeAbiError> {
        if self != INTERRUPT_ROUTE_LAYOUT {
            return Err(RuntimeAbiError::InterruptRouteLayoutMismatch);
        }
        if bytes.len() < self.header_bytes as usize {
            return Err(RuntimeAbiError::InterruptRouteTableTruncated);
        }
        let route_count = read_u32_le(bytes, u64::from(self.route_count_offset))?;
        let expected_bytes = self.table_bytes(route_count);
        let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_bytes != expected_bytes {
            return Err(RuntimeAbiError::InterruptRouteTableLength {
                route_count,
                expected_bytes,
                actual_bytes,
            });
        }
        if read_u32_le(bytes, u64::from(self.header_reserved_offset))? != 0 {
            return Err(RuntimeAbiError::InterruptRouteReservedNonZero { record_index: None });
        }

        let mut previous_global_id = None;
        for record_index in 0..route_count {
            let base = u64::from(self.header_bytes)
                + u64::from(record_index) * u64::from(self.record_bytes);
            let global_id = read_u32_le(bytes, base + u64::from(self.global_id_offset))?;
            if previous_global_id.is_some_and(|previous| previous >= global_id) {
                return Err(RuntimeAbiError::NonCanonicalInterruptRoutes { record_index });
            }
            if read_u32_le(bytes, base + u64::from(self.reserved_offset))? != 0 {
                return Err(RuntimeAbiError::InterruptRouteReservedNonZero {
                    record_index: Some(record_index),
                });
            }
            previous_global_id = Some(global_id);
        }
        Ok(())
    }
}

fn read_u32_le(bytes: &[u8], offset: u64) -> Result<u32, RuntimeAbiError> {
    let offset =
        usize::try_from(offset).map_err(|_| RuntimeAbiError::InterruptRouteTableTruncated)?;
    let end = offset
        .checked_add(4)
        .ok_or(RuntimeAbiError::InterruptRouteTableTruncated)?;
    let raw = bytes
        .get(offset..end)
        .ok_or(RuntimeAbiError::InterruptRouteTableTruncated)?;
    let raw: [u8; 4] = raw
        .try_into()
        .map_err(|_| RuntimeAbiError::InterruptRouteTableTruncated)?;
    Ok(u32::from_le_bytes(raw))
}

/// Scalar shapes permitted at the runtime ABI. Aggregate layout never leaks
/// across this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AbiType {
    Unit,
    Bool,
    U8,
    U32,
    U64,
    Usize,
    Address,
    Status,
}

/// Calling conventions that cross the compiler/runtime or firmware boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AbiCallingConvention {
    /// The ordinary scalar AAPCS64 C convention used by runtime intrinsics.
    Aapcs64,
    /// UEFI's constrained AAPCS64 convention for the PE/COFF image entry.
    UefiAarch64,
}

/// Exact public signature and register handoff of the AArch64 UEFI image
/// entry. Aggregate firmware types remain opaque addresses at this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageEntrySignature {
    pub symbol: &'static str,
    pub calling_convention: AbiCallingConvention,
    pub parameters: [AbiType; 2],
    pub result: AbiType,
    pub argument_registers: [u8; 2],
    pub result_register: u8,
    pub return_address_register: u8,
    pub stack_alignment_bytes: u32,
    pub reserved_platform_register: u8,
    pub little_endian: bool,
}

/// Revision-0.1 firmware entry contract:
/// `EFI_STATUS EFIAPI entry(EFI_HANDLE, EFI_SYSTEM_TABLE *)`.
///
/// UEFI's AArch64 binding is AAPCS64 with X0/X1 holding the two parameters,
/// X0 holding the result, X30 holding the return address, a 16-byte-aligned
/// stack, little-endian execution, and X18 unavailable to generated code.
pub const AARCH64_UEFI_IMAGE_ENTRY: ImageEntrySignature = ImageEntrySignature {
    symbol: IMAGE_ENTRY_SYMBOL,
    calling_convention: AbiCallingConvention::UefiAarch64,
    parameters: [AbiType::Address, AbiType::Address],
    result: AbiType::Status,
    argument_registers: [
        AARCH64_UEFI_IMAGE_HANDLE_REGISTER,
        AARCH64_UEFI_SYSTEM_TABLE_REGISTER,
    ],
    result_register: AARCH64_UEFI_STATUS_REGISTER,
    return_address_register: AARCH64_UEFI_RETURN_ADDRESS_REGISTER,
    stack_alignment_bytes: AARCH64_UEFI_STACK_ALIGNMENT_BYTES,
    reserved_platform_register: AARCH64_UEFI_RESERVED_PLATFORM_REGISTER,
    little_endian: true,
};

/// Processor cache-maintenance action required by a proved DMA transition.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CacheOperation {
    Clean = 0,
    Invalidate = 1,
    CleanAndInvalidate = 2,
}

/// Closed semantic effect performed by one privileged runtime call. These
/// labels are validation/reporting facts, not permission to infer LLVM
/// aliasing or memory attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuntimeEffect {
    EnterImage,
    ExitImage,
    FatalTermination,
    CpuIdle,
    MaskInterrupts,
    RestoreInterrupts,
    MaintainCache,
    AppendRecord,
    ConsumeReplay,
    EmitTestFrame,
    FinishTests,
    FailTestAssertion,
}

/// Stable fatal codes crossing [`RuntimeIntrinsic::Fatal`].
///
/// The first four values are the existing scalar/actor failure classes. The
/// shift-specific values deliberately remain distinct all the way through
/// MachineWir and code generation: the target runtime must never infer a
/// language-fatal cause from a source location or a generic arithmetic code.
/// The second ABI argument remains the lossless packed FlowWir
/// function/instruction provenance.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuntimeFatalCode {
    Arithmetic = 1,
    Conversion = 2,
    ActorMailboxFull = 3,
    ActorMailboxMismatch = 4,
    CheckedShiftResultLoss = 5,
    InvalidShiftCount = 6,
}

impl RuntimeFatalCode {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Closed runtime operation set. Adding or changing a signature increments
/// [`RUNTIME_ABI_VERSION`] and the toolchain manifest compatibility tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuntimeIntrinsic {
    /// Enter generated image initialization from the UEFI entry trampoline.
    ImageEnter,
    /// Return an EFI status after deterministic image teardown.
    ImageExit,
    /// Terminate after an unrecoverable language or target contract violation.
    Fatal,
    /// Enter the target-defined low-power state until work may be available.
    CpuIdle,
    /// Save and mask local interrupts, returning an opaque prior-state token.
    InterruptMask,
    /// Restore the exact prior local-interrupt state token.
    InterruptRestore,
    /// Perform target cache maintenance on a proved physical DMA range.
    CacheMaintain,
    /// Append one bounded deterministic record/replay event.
    RecordEvent,
    /// Read and validate the next deterministic replay event.
    ReplayEvent,
    /// Emit one framed event from an image compiled in test mode.
    TestEmit,
    /// Finish a test image with a structured terminal outcome.
    TestFinish,
    /// Compiler-only failure edge for a false assertion in an active selected
    /// generated test. The runtime owns lifecycle identity and sequencing.
    TestAssertionFail,
}

pub const RUNTIME_INTRINSIC_COUNT: usize = 12;

/// Canonical runtime-symbol order used by validators, reports, and object
/// inspectors. This is deliberately independent of source or hash-map order.
pub const ALL_RUNTIME_INTRINSICS: [RuntimeIntrinsic; RUNTIME_INTRINSIC_COUNT] = [
    RuntimeIntrinsic::ImageEnter,
    RuntimeIntrinsic::ImageExit,
    RuntimeIntrinsic::Fatal,
    RuntimeIntrinsic::CpuIdle,
    RuntimeIntrinsic::InterruptMask,
    RuntimeIntrinsic::InterruptRestore,
    RuntimeIntrinsic::CacheMaintain,
    RuntimeIntrinsic::RecordEvent,
    RuntimeIntrinsic::ReplayEvent,
    RuntimeIntrinsic::TestEmit,
    RuntimeIntrinsic::TestFinish,
    RuntimeIntrinsic::TestAssertionFail,
];

/// Exact, reviewable ABI signature for one intrinsic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrinsicSignature {
    pub intrinsic: RuntimeIntrinsic,
    pub calling_convention: AbiCallingConvention,
    pub parameters: Vec<AbiType>,
    pub result: AbiType,
    pub effect: RuntimeEffect,
    pub may_return: bool,
}

impl RuntimeIntrinsic {
    /// Stable COFF symbol implemented by the target runtime object. The ABI
    /// version is deliberately present in the spelling so incompatible runtime
    /// objects cannot satisfy a newer machine module accidentally.
    #[must_use]
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::ImageEnter => "wrela_rt_v2_image_enter",
            Self::ImageExit => "wrela_rt_v2_image_exit",
            Self::Fatal => "wrela_rt_v2_fatal",
            Self::CpuIdle => "wrela_rt_v2_cpu_idle",
            Self::InterruptMask => "wrela_rt_v2_interrupt_mask",
            Self::InterruptRestore => "wrela_rt_v2_interrupt_restore",
            Self::CacheMaintain => "wrela_rt_v2_cache_maintain",
            Self::RecordEvent => "wrela_rt_v2_record_event",
            Self::ReplayEvent => "wrela_rt_v2_replay_event",
            Self::TestEmit => "wrela_rt_v2_test_emit",
            Self::TestFinish => "wrela_rt_v2_test_finish",
            Self::TestAssertionFail => "wrela_rt_v2_test_assertion_fail",
        }
    }

    /// Exact privileged effect owned by the target runtime implementation.
    #[must_use]
    pub const fn effect(self) -> RuntimeEffect {
        match self {
            Self::ImageEnter => RuntimeEffect::EnterImage,
            Self::ImageExit => RuntimeEffect::ExitImage,
            Self::Fatal => RuntimeEffect::FatalTermination,
            Self::CpuIdle => RuntimeEffect::CpuIdle,
            Self::InterruptMask => RuntimeEffect::MaskInterrupts,
            Self::InterruptRestore => RuntimeEffect::RestoreInterrupts,
            Self::CacheMaintain => RuntimeEffect::MaintainCache,
            Self::RecordEvent => RuntimeEffect::AppendRecord,
            Self::ReplayEvent => RuntimeEffect::ConsumeReplay,
            Self::TestEmit => RuntimeEffect::EmitTestFrame,
            Self::TestFinish => RuntimeEffect::FinishTests,
            Self::TestAssertionFail => RuntimeEffect::FailTestAssertion,
        }
    }

    /// Whether control may return normally to generated code.
    #[must_use]
    pub const fn may_return(self) -> bool {
        !matches!(
            self,
            Self::ImageExit | Self::Fatal | Self::TestFinish | Self::TestAssertionFail
        )
    }

    #[must_use]
    pub fn signature(self) -> IntrinsicSignature {
        let (parameters, result) = match self {
            Self::ImageEnter => (vec![AbiType::Address, AbiType::Address], AbiType::Status),
            Self::ImageExit => (vec![AbiType::Status], AbiType::Unit),
            Self::Fatal => (vec![AbiType::U32, AbiType::U64], AbiType::Unit),
            Self::CpuIdle => (Vec::new(), AbiType::Unit),
            Self::InterruptMask => (Vec::new(), AbiType::U64),
            Self::InterruptRestore => (vec![AbiType::U64], AbiType::Unit),
            Self::CacheMaintain => (
                vec![AbiType::Address, AbiType::Usize, AbiType::U8],
                AbiType::Unit,
            ),
            Self::RecordEvent => (
                vec![AbiType::U32, AbiType::Address, AbiType::Usize],
                AbiType::Status,
            ),
            Self::ReplayEvent => (
                vec![AbiType::U32, AbiType::Address, AbiType::Usize],
                AbiType::Usize,
            ),
            Self::TestEmit => (vec![AbiType::Address, AbiType::Usize], AbiType::Status),
            Self::TestFinish => (vec![AbiType::U32], AbiType::Unit),
            Self::TestAssertionFail => (
                vec![
                    AbiType::Address,
                    AbiType::Usize,
                    AbiType::Address,
                    AbiType::Usize,
                    AbiType::U32,
                    AbiType::U32,
                    AbiType::U32,
                ],
                AbiType::Unit,
            ),
        };
        IntrinsicSignature {
            intrinsic: self,
            calling_convention: AbiCallingConvention::Aapcs64,
            parameters,
            result,
            effect: self.effect(),
            may_return: self.may_return(),
        }
    }
}

/// Canonical record/replay storage and wire layout implemented by ABI v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogLayout {
    pub storage_bytes: u64,
    pub record_region_bytes: u64,
    pub overflow_marker_bytes: u64,
    pub record_header_bytes: u32,
    pub kind_offset: u32,
    pub payload_bytes_offset: u32,
    pub overflow_kind: u32,
    pub little_endian: bool,
}

pub const EVENT_LOG_LAYOUT: EventLogLayout = EventLogLayout {
    storage_bytes: EVENT_LOG_STORAGE_BYTES,
    record_region_bytes: EVENT_LOG_RECORD_REGION_BYTES,
    overflow_marker_bytes: EVENT_LOG_OVERFLOW_MARKER_BYTES,
    record_header_bytes: EVENT_LOG_RECORD_HEADER_BYTES,
    kind_offset: 0,
    payload_bytes_offset: 4,
    overflow_kind: EVENT_LOG_OVERFLOW_KIND,
    little_endian: true,
};

/// Whether a pinned runtime-object section has a fixed or compiler-dependent
/// extent. Only `.text` may vary when the authenticated assembler changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionExtent {
    Exact(u64),
    NonEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// One canonical section in the freestanding AArch64 runtime object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeObjectSectionLayout {
    pub name: &'static str,
    pub alignment: u32,
    pub extent: SectionExtent,
    pub permissions: SectionPermissions,
    pub zero_filled: bool,
}

pub const RUNTIME_OBJECT_SECTION_COUNT: usize = 4;
/// The fixed runtime state occupies the 64 KiB event log plus one bounded
/// assertion-frame buffer and 128 bytes of lifecycle/replay/alignment state.
pub const RUNTIME_OBJECT_ZERO_FILL_BYTES: u64 = EVENT_LOG_STORAGE_BYTES + 8_448;
pub const RUNTIME_OBJECT_RELOCATION_ANCHOR_BYTES: u64 = 8;
pub const RUNTIME_OBJECT_READ_ONLY_BYTES: u64 = 24;

pub const RUNTIME_OBJECT_SECTIONS: [RuntimeObjectSectionLayout; RUNTIME_OBJECT_SECTION_COUNT] = [
    RuntimeObjectSectionLayout {
        name: ".text",
        alignment: 16,
        extent: SectionExtent::NonEmpty,
        permissions: SectionPermissions {
            readable: true,
            writable: false,
            executable: true,
        },
        zero_filled: false,
    },
    RuntimeObjectSectionLayout {
        name: ".data",
        alignment: 4,
        extent: SectionExtent::Exact(0),
        permissions: SectionPermissions {
            readable: true,
            writable: true,
            executable: false,
        },
        zero_filled: false,
    },
    RuntimeObjectSectionLayout {
        name: ".bss",
        alignment: 64,
        extent: SectionExtent::Exact(RUNTIME_OBJECT_ZERO_FILL_BYTES),
        permissions: SectionPermissions {
            readable: true,
            writable: true,
            executable: false,
        },
        zero_filled: true,
    },
    RuntimeObjectSectionLayout {
        name: ".rdata",
        alignment: 8,
        extent: SectionExtent::Exact(RUNTIME_OBJECT_READ_ONLY_BYTES),
        permissions: SectionPermissions {
            readable: true,
            writable: false,
            executable: false,
        },
        zero_filled: false,
    },
];

/// Canonical structural facts independently checked on the pinned runtime
/// object before it is shipped or linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeObjectLayout {
    pub coff_machine: u16,
    pub coff_timestamp: u32,
    pub sections: [RuntimeObjectSectionLayout; RUNTIME_OBJECT_SECTION_COUNT],
    pub external_definitions: [RuntimeIntrinsic; RUNTIME_INTRINSIC_COUNT],
    pub relocation_anchor_section: &'static str,
    pub relocation_anchor_bytes: u64,
    pub relocation_anchor_target: RuntimeIntrinsic,
    pub undefined_external_symbols: u32,
}

pub const RUNTIME_OBJECT_LAYOUT: RuntimeObjectLayout = RuntimeObjectLayout {
    coff_machine: ARM64_COFF_MACHINE,
    coff_timestamp: 0,
    sections: RUNTIME_OBJECT_SECTIONS,
    external_definitions: ALL_RUNTIME_INTRINSICS,
    relocation_anchor_section: ".rdata",
    relocation_anchor_bytes: RUNTIME_OBJECT_RELOCATION_ANCHOR_BYTES,
    relocation_anchor_target: RuntimeIntrinsic::ImageEnter,
    undefined_external_symbols: 0,
};

/// Complete canonical ABI snapshot. Object inspectors and backend validators
/// can construct an independently observed snapshot and reject any field that
/// differs before linking or reporting it as ABI v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAbiContract {
    pub version: u32,
    pub image_entry: ImageEntrySignature,
    pub intrinsics: [IntrinsicSignature; RUNTIME_INTRINSIC_COUNT],
    pub interrupt_routes: InterruptRouteLayout,
    pub event_log: EventLogLayout,
    pub runtime_object: RuntimeObjectLayout,
}

impl RuntimeAbiContract {
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            version: RUNTIME_ABI_VERSION,
            image_entry: AARCH64_UEFI_IMAGE_ENTRY,
            intrinsics: ALL_RUNTIME_INTRINSICS.map(RuntimeIntrinsic::signature),
            interrupt_routes: INTERRUPT_ROUTE_LAYOUT,
            event_log: EVENT_LOG_LAYOUT,
            runtime_object: RUNTIME_OBJECT_LAYOUT,
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeAbiError> {
        if self.version != RUNTIME_ABI_VERSION {
            return Err(RuntimeAbiError::UnsupportedVersion(self.version));
        }
        if self.image_entry != AARCH64_UEFI_IMAGE_ENTRY {
            return Err(RuntimeAbiError::ImageEntryContractMismatch);
        }
        for (actual, intrinsic) in self.intrinsics.iter().zip(ALL_RUNTIME_INTRINSICS) {
            if *actual != intrinsic.signature() {
                return Err(RuntimeAbiError::IntrinsicContractMismatch(intrinsic));
            }
        }
        if self.interrupt_routes != INTERRUPT_ROUTE_LAYOUT {
            return Err(RuntimeAbiError::InterruptRouteLayoutMismatch);
        }
        if self.event_log != EVENT_LOG_LAYOUT {
            return Err(RuntimeAbiError::EventLogLayoutMismatch);
        }
        if self.runtime_object != RUNTIME_OBJECT_LAYOUT {
            return Err(RuntimeAbiError::RuntimeObjectLayoutMismatch);
        }
        Ok(())
    }
}

/// Complete runtime ABI required by one machine module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRequirements {
    pub version: u32,
    /// Strictly sorted and duplicate-free.
    pub intrinsics: Vec<RuntimeIntrinsic>,
}

impl RuntimeRequirements {
    pub fn new(mut intrinsics: Vec<RuntimeIntrinsic>) -> Self {
        intrinsics.sort_unstable();
        intrinsics.dedup();
        Self {
            version: RUNTIME_ABI_VERSION,
            intrinsics,
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeAbiError> {
        if self.version != RUNTIME_ABI_VERSION {
            return Err(RuntimeAbiError::UnsupportedVersion(self.version));
        }
        if !self.intrinsics.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(RuntimeAbiError::NonCanonicalRequirements);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeAbiError {
    UnsupportedVersion(u32),
    NonCanonicalRequirements,
    ImageEntryContractMismatch,
    IntrinsicContractMismatch(RuntimeIntrinsic),
    InterruptRouteLayoutMismatch,
    EventLogLayoutMismatch,
    RuntimeObjectLayoutMismatch,
    InterruptRouteTableTruncated,
    InterruptRouteTableLength {
        route_count: u32,
        expected_bytes: u64,
        actual_bytes: u64,
    },
    InterruptRouteReservedNonZero {
        record_index: Option<u32>,
    },
    NonCanonicalInterruptRoutes {
        record_index: u32,
    },
}

impl fmt::Display for RuntimeAbiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported runtime ABI version {version}")
            }
            Self::NonCanonicalRequirements => {
                formatter.write_str("runtime requirements are not sorted and unique")
            }
            Self::ImageEntryContractMismatch => formatter
                .write_str("AArch64 UEFI image-entry contract does not match runtime ABI v2"),
            Self::IntrinsicContractMismatch(intrinsic) => write!(
                formatter,
                "runtime intrinsic contract for {intrinsic:?} does not match ABI v2"
            ),
            Self::InterruptRouteLayoutMismatch => {
                formatter.write_str("interrupt-route layout does not match runtime ABI v2")
            }
            Self::EventLogLayoutMismatch => {
                formatter.write_str("event-log layout does not match runtime ABI v2")
            }
            Self::RuntimeObjectLayoutMismatch => {
                formatter.write_str("runtime-object layout does not match runtime ABI v2")
            }
            Self::InterruptRouteTableTruncated => {
                formatter.write_str("interrupt-route table is truncated")
            }
            Self::InterruptRouteTableLength {
                route_count,
                expected_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "interrupt-route table for {route_count} routes has {actual_bytes} bytes, expected {expected_bytes}"
            ),
            Self::InterruptRouteReservedNonZero { record_index: None } => {
                formatter.write_str("interrupt-route table header has a nonzero reserved field")
            }
            Self::InterruptRouteReservedNonZero {
                record_index: Some(record_index),
            } => write!(
                formatter,
                "interrupt-route record {record_index} has a nonzero reserved field"
            ),
            Self::NonCanonicalInterruptRoutes { record_index } => write!(
                formatter,
                "interrupt-route record {record_index} is not strictly ordered by global ID"
            ),
        }
    }
}

impl std::error::Error for RuntimeAbiError {}

#[cfg(test)]
mod tests {
    use super::{
        AbiByteOrder, Arm64CoffRelocation, EVENT_LOG_OVERFLOW_MARKER_BYTES,
        EVENT_LOG_RECORD_REGION_BYTES, EVENT_LOG_STORAGE_BYTES, INTERRUPT_ROUTE_LAYOUT,
        INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL, RuntimeFatalCode, RuntimeIntrinsic,
        RuntimeRequirements,
    };

    #[test]
    fn requirements_are_canonicalized() {
        let requirements = RuntimeRequirements::new(vec![
            RuntimeIntrinsic::Fatal,
            RuntimeIntrinsic::CpuIdle,
            RuntimeIntrinsic::Fatal,
        ]);
        requirements.validate().expect("valid ABI requirements");
        assert_eq!(requirements.intrinsics.len(), 2);
    }

    #[test]
    fn interrupt_route_wire_layout_is_stable() {
        assert_eq!(INTERRUPT_ROUTE_SECTION, ".rdata$wrela_irq");
        assert_eq!(
            INTERRUPT_ROUTE_TABLE_SYMBOL,
            "wrela_rt_v2_interrupt_route_table"
        );
        assert_eq!(
            INTERRUPT_ROUTE_LAYOUT.byte_order,
            AbiByteOrder::LittleEndian
        );
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.table_alignment, 8);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.header_bytes, 8);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.route_count_offset, 0);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.header_reserved_offset, 4);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.record_bytes, 16);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.global_id_offset, 0);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.reserved_offset, 4);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.handler_address_offset, 8);
        assert_eq!(
            INTERRUPT_ROUTE_LAYOUT.handler_relocation,
            Arm64CoffRelocation::Address64
        );
    }

    #[test]
    fn event_log_reservation_accounts_for_the_overflow_marker() {
        assert_eq!(EVENT_LOG_STORAGE_BYTES, 65_536);
        assert_eq!(EVENT_LOG_OVERFLOW_MARKER_BYTES, 8);
        assert_eq!(EVENT_LOG_RECORD_REGION_BYTES, 65_528);
        assert_eq!(
            EVENT_LOG_RECORD_REGION_BYTES + EVENT_LOG_OVERFLOW_MARKER_BYTES,
            EVENT_LOG_STORAGE_BYTES
        );
    }

    #[test]
    fn fatal_codes_are_stable_and_keep_shift_causes_distinct() {
        assert_eq!(RuntimeFatalCode::Arithmetic.as_u32(), 1);
        assert_eq!(RuntimeFatalCode::Conversion.as_u32(), 2);
        assert_eq!(RuntimeFatalCode::ActorMailboxFull.as_u32(), 3);
        assert_eq!(RuntimeFatalCode::ActorMailboxMismatch.as_u32(), 4);
        assert_eq!(RuntimeFatalCode::CheckedShiftResultLoss.as_u32(), 5);
        assert_eq!(RuntimeFatalCode::InvalidShiftCount.as_u32(), 6);
    }
}
