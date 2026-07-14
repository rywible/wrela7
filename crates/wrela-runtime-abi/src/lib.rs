//! Minimal compiler-owned boundary between laid-out WIR and bundled runtime code.
//!
//! Source programs cannot name this ABI. Most runtime behavior is generated as
//! ordinary `MachineWir`; these intrinsics exist only where firmware, processor,
//! record/replay, or the image-test harness requires a privileged boundary.

#![forbid(unsafe_code)]

use std::fmt;

pub const RUNTIME_ABI_VERSION: u32 = 1;

/// Stable read-only COFF subsection containing the interrupt route table.
pub const INTERRUPT_ROUTE_SECTION: &str = ".rdata$wrela_irq";
/// Stable COFF symbol for the interrupt route table header. A header is emitted
/// even when the route count is zero, so the target runtime never depends on a
/// linker-specific zero-length array symbol.
pub const INTERRUPT_ROUTE_TABLE_SYMBOL: &str = "wrela_rt_v1_interrupt_route_table";

/// Wire layout of one target-runtime interrupt route. This is deliberately a
/// byte-layout contract rather than a Rust `repr(C)` type: runtime objects may
/// be implemented in another language and must not inherit host ABI choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptRouteLayout {
    pub table_alignment: u32,
    pub header_bytes: u32,
    pub route_count_offset: u32,
    pub header_reserved_offset: u32,
    pub record_bytes: u32,
    pub global_id_offset: u32,
    pub reserved_offset: u32,
    pub handler_address_offset: u32,
}

/// Runtime ABI v1 table layout. The header is
/// `{ route_count: u32, reserved_zero: u32 }`; it is followed immediately by
/// route records `{ global_id: u32, reserved_zero: u32, handler_address: u64 }`.
/// Integer fields are little-endian, handler addresses use ordinary ARM64 COFF
/// relocations, records are sorted by `global_id`, and all reserved fields are
/// zero. Duplicate IDs are invalid.
pub const INTERRUPT_ROUTE_LAYOUT: InterruptRouteLayout = InterruptRouteLayout {
    table_alignment: 8,
    header_bytes: 8,
    route_count_offset: 0,
    header_reserved_offset: 4,
    record_bytes: 16,
    global_id_offset: 0,
    reserved_offset: 4,
    handler_address_offset: 8,
};

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

/// Processor cache-maintenance action required by a proved DMA transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CacheOperation {
    Clean,
    Invalidate,
    CleanAndInvalidate,
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
}

/// Exact, reviewable ABI signature for one intrinsic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrinsicSignature {
    pub intrinsic: RuntimeIntrinsic,
    pub parameters: Vec<AbiType>,
    pub result: AbiType,
    pub may_return: bool,
}

impl RuntimeIntrinsic {
    /// Stable COFF symbol implemented by the target runtime object. The ABI
    /// version is deliberately present in the spelling so incompatible runtime
    /// objects cannot satisfy a newer machine module accidentally.
    #[must_use]
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::ImageEnter => "wrela_rt_v1_image_enter",
            Self::ImageExit => "wrela_rt_v1_image_exit",
            Self::Fatal => "wrela_rt_v1_fatal",
            Self::CpuIdle => "wrela_rt_v1_cpu_idle",
            Self::InterruptMask => "wrela_rt_v1_interrupt_mask",
            Self::InterruptRestore => "wrela_rt_v1_interrupt_restore",
            Self::CacheMaintain => "wrela_rt_v1_cache_maintain",
            Self::RecordEvent => "wrela_rt_v1_record_event",
            Self::ReplayEvent => "wrela_rt_v1_replay_event",
            Self::TestEmit => "wrela_rt_v1_test_emit",
            Self::TestFinish => "wrela_rt_v1_test_finish",
        }
    }

    #[must_use]
    pub fn signature(self) -> IntrinsicSignature {
        let (parameters, result, may_return) = match self {
            Self::ImageEnter => (
                vec![AbiType::Address, AbiType::Address],
                AbiType::Status,
                true,
            ),
            Self::ImageExit => (vec![AbiType::Status], AbiType::Unit, false),
            Self::Fatal => (vec![AbiType::U32, AbiType::U64], AbiType::Unit, false),
            Self::CpuIdle => (Vec::new(), AbiType::Unit, true),
            Self::InterruptMask => (Vec::new(), AbiType::U64, true),
            Self::InterruptRestore => (vec![AbiType::U64], AbiType::Unit, true),
            Self::CacheMaintain => (
                vec![AbiType::Address, AbiType::Usize, AbiType::U8],
                AbiType::Unit,
                true,
            ),
            Self::RecordEvent => (
                vec![AbiType::U32, AbiType::Address, AbiType::Usize],
                AbiType::Status,
                true,
            ),
            Self::ReplayEvent => (
                vec![AbiType::U32, AbiType::Address, AbiType::Usize],
                AbiType::Usize,
                true,
            ),
            Self::TestEmit => (
                vec![AbiType::Address, AbiType::Usize],
                AbiType::Status,
                true,
            ),
            Self::TestFinish => (vec![AbiType::U32], AbiType::Unit, false),
        };
        IntrinsicSignature {
            intrinsic: self,
            parameters,
            result,
            may_return,
        }
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
        }
    }
}

impl std::error::Error for RuntimeAbiError {}

#[cfg(test)]
mod tests {
    use super::{
        INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
        RuntimeIntrinsic, RuntimeRequirements,
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
            "wrela_rt_v1_interrupt_route_table"
        );
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.table_alignment, 8);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.header_bytes, 8);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.route_count_offset, 0);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.header_reserved_offset, 4);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.record_bytes, 16);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.global_id_offset, 0);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.reserved_offset, 4);
        assert_eq!(INTERRUPT_ROUTE_LAYOUT.handler_address_offset, 8);
    }
}
