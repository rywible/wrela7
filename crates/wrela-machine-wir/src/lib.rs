//! Target-laid-out, LLVM-independent machine IR.
//!
//! MachineWir fixes ABI, data layout, sections, stack/frame objects, runtime
//! intrinsics, and every undefined-behavior-bearing backend fact. Codegen is a
//! translation of this contract, not another semantic lowering pass.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_runtime_abi::{
    AbiType, INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
    RUNTIME_ABI_VERSION, RuntimeAbiError, RuntimeFatalCode, RuntimeIntrinsic, RuntimeRequirements,
    TEST_ASSERTION_EXPRESSION_BYTES_MAX, TEST_ASSERTION_MESSAGE_BYTES_MAX,
};
use wrela_source::Span;
use wrela_target::{InterruptDomain, TargetError, TargetPackage};
use wrela_test_model::{GuestTestOutcome, TestEvent, TestEventKind, TestId};
use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, TestEventCodec};

pub const MACHINE_WIR_VERSION: u32 = 16;
pub const REGION_STORAGE_SECTION_PREFIX: &str = ".data$wrela$region$";
pub const REGION_STORAGE_SYMBOL_PREFIX: &str = "__wrela_region_storage_";

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(MachineTypeId);
id_type!(FunctionId);
id_type!(BlockId);
id_type!(ValueId);
id_type!(InstructionId);
id_type!(GlobalId);
id_type!(StackSlotId);
id_type!(SectionId);
id_type!(SymbolId);
id_type!(ProofId);
id_type!(InterruptEntryId);
id_type!(MachineTestId);
id_type!(MachineActivationId);
id_type!(MachineRegionStorageId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    Little,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLayout {
    pub pointer_bits: u16,
    pub pointer_alignment: u32,
    pub stack_alignment: u32,
    pub aggregate_alignment: u32,
    pub maximum_object_alignment: u32,
    pub endianness: Endianness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineTypeKind {
    Void,
    Integer {
        bits: u16,
    },
    Float32,
    Float64,
    Pointer {
        address_space: u32,
        pointee: Option<MachineTypeId>,
    },
    Vector {
        element: MachineTypeId,
        lanes: u32,
    },
    Array {
        element: MachineTypeId,
        length: u64,
    },
    Struct {
        fields: Vec<MachineField>,
        packed: bool,
    },
    /// Closed enum represented canonically as `{u8 tag}` for an all-unit
    /// shape or `{u8 tag, payload}` when any variant carries a payload.
    TaggedEnum {
        tag: MachineTypeId,
        payload: Option<MachineTypeId>,
        variants: u16,
        /// One exact payload-presence bit per discriminant, in tag order.
        payload_variants: Vec<bool>,
    },
    Function {
        parameters: Vec<MachineTypeId>,
        result: MachineTypeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineField {
    pub ty: MachineTypeId,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineType {
    pub id: MachineTypeId,
    pub kind: MachineTypeKind,
    pub size: u64,
    pub alignment: u32,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Code,
    ReadOnlyData,
    WritableData,
    ZeroFill,
    Relocations,
    RuntimeMetadata,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: SectionId,
    pub name: String,
    pub kind: SectionKind,
    pub alignment: u32,
    pub reserved_bytes: u64,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolVisibility {
    Private,
    ImageEntry,
    Runtime,
    RuntimeMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolDefinition {
    Function(FunctionId),
    Global(GlobalId),
    SectionOffset {
        section: SectionId,
        offset: u64,
        bytes: u64,
    },
    ExternalRuntime(RuntimeIntrinsic),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub visibility: SymbolVisibility,
    pub definition: SymbolDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Compiler-private convention. It never crosses an object boundary.
    Internal,
    /// AAPCS64 boundary used by target/runtime glue.
    Aapcs64,
    /// The sole UEFI image entry. Codegen maps this marker to the AAPCS64 C
    /// convention only after validating the firmware signature.
    UefiAarch64,
    /// A no-argument, void interrupt body reached only through target-owned
    /// exception entry and dispatch glue. It is not an ordinary call target.
    InterruptHandler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    Private,
    InternalRuntime,
    ExportedEntry,
}

/// One statically sealed interrupt route. The target binding is retained so
/// startup, codegen, and reporting do not have to reconstruct the association
/// from source-level device plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptEntry {
    pub id: InterruptEntryId,
    pub device: u32,
    pub target_binding: String,
    /// GIC SPI number, excluding the architectural offset of 32.
    pub line: u32,
    /// Architectural GIC interrupt ID (INTID).
    pub global_id: u32,
    pub handler: FunctionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcquireRelease,
    Sequential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySemantics {
    Ordinary,
    Volatile,
    Device,
    Atomic(AtomicOrdering),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerPredicate {
    Equal,
    NotEqual,
    UnsignedLess,
    UnsignedLessEqual,
    UnsignedGreater,
    UnsignedGreaterEqual,
    SignedLess,
    SignedLessEqual,
    SignedGreater,
    SignedGreaterEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatPredicate {
    OrderedEqual,
    /// True when either operand is NaN or the ordered operands are unequal.
    /// This is the revision-0.1 language `!=` contract.
    UnorderedNotEqual,
    OrderedLess,
    OrderedLessEqual,
    OrderedGreater,
    OrderedGreaterEqual,
    Unordered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineUnaryOp {
    BoolNot,
    BitNot,
    /// IEEE negation with revision-0.1 canonical-NaN output semantics.
    FloatNegate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticOp {
    IntegerAdd,
    IntegerSubtract,
    IntegerMultiply,
    UnsignedDivide,
    SignedDivide,
    UnsignedRemainder,
    SignedRemainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    FloatAdd,
    FloatSubtract,
    FloatMultiply,
    FloatDivide,
}

/// Exact scalar conversion selected after signedness, widths, and checked/exact
/// source semantics have already been resolved. LLVM must not infer a choice
/// from otherwise signless machine integer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionOp {
    IntegerTruncate,
    ZeroExtend,
    SignExtend,
    FloatTruncate,
    FloatExtend,
    UnsignedIntegerToFloat,
    SignedIntegerToFloat,
    FloatToUnsignedInteger,
    FloatToSignedInteger,
    PointerToInteger,
    IntegerToPointer,
    Bitcast,
}

/// Checked integer operation whose failure behavior remains part of the
/// MachineWir contract. These operations are intentionally distinct from
/// [`ArithmeticOp`]: codegen may not silently replace an abandoning source
/// operation with a wrapping or undefined LLVM operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckedIntegerOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    ShiftLeft,
    /// Left shift whose result wraps while its count remains checked.
    ShiftLeftWrapping,
    ShiftRight,
}

impl CheckedIntegerOp {
    /// Exact runtime cause for an invalid shift count. This is part of the
    /// MachineWir contract so code generation never recovers a language-fatal
    /// cause from generic arithmetic provenance.
    #[must_use]
    pub const fn invalid_shift_count_fatal_code(self) -> Option<RuntimeFatalCode> {
        match self {
            Self::ShiftLeft | Self::ShiftLeftWrapping | Self::ShiftRight => {
                Some(RuntimeFatalCode::InvalidShiftCount)
            }
            Self::Add | Self::Subtract | Self::Multiply | Self::Divide | Self::Remainder => None,
        }
    }

    /// Exact runtime cause for a checked left shift that loses result bits.
    #[must_use]
    pub const fn result_loss_fatal_code(self) -> Option<RuntimeFatalCode> {
        match self {
            Self::ShiftLeft => Some(RuntimeFatalCode::CheckedShiftResultLoss),
            Self::Add
            | Self::Subtract
            | Self::Multiply
            | Self::Divide
            | Self::Remainder
            | Self::ShiftLeftWrapping
            | Self::ShiftRight => None,
        }
    }
}

/// Signed interpretation fixed before signless machine integer types reach
/// codegen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerSignedness {
    Unsigned,
    Signed,
}

/// Numeric interpretation fixed for a checked scalar conversion. Integer
/// widths remain in the referenced machine types; signedness cannot be
/// reconstructed from those signless types and is therefore explicit here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckedNumericKind {
    UnsignedInteger,
    SignedInteger,
    Float32,
    Float64,
}

/// Stable fatal-code classes shared with FlowWir's canonical failure encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarFailureKind {
    Arithmetic,
    Conversion,
    ActorMailboxFull,
    ActorMailboxMismatch,
    ActorReplyStateMismatch,
    ActorReplyDuplicateResolve,
}

impl ScalarFailureKind {
    /// Stable `wrela_rt_v2_fatal` code. These values deliberately match the
    /// canonical FlowWir `FailureKind` encoding without depending on FlowWir at
    /// the target-laid-out boundary.
    #[must_use]
    pub const fn runtime_code(self) -> RuntimeFatalCode {
        match self {
            Self::Arithmetic => RuntimeFatalCode::Arithmetic,
            Self::Conversion => RuntimeFatalCode::Conversion,
            Self::ActorMailboxFull => RuntimeFatalCode::ActorMailboxFull,
            Self::ActorMailboxMismatch => RuntimeFatalCode::ActorMailboxMismatch,
            Self::ActorReplyStateMismatch => RuntimeFatalCode::ActorReplyStateMismatch,
            Self::ActorReplyDuplicateResolve => RuntimeFatalCode::ActorReplyDuplicateResolve,
        }
    }
}

/// Exact producer provenance attached to an abandoning scalar operation.
/// Runtime detail losslessly packs the FlowWir function and instruction IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarFailureProvenance {
    pub kind: ScalarFailureKind,
    pub flow_function: u32,
    pub flow_instruction: u32,
}

impl ScalarFailureProvenance {
    #[must_use]
    pub const fn runtime_detail(self) -> u64 {
        (self.flow_function as u64) << 32 | self.flow_instruction as u64
    }
}

/// Hardware/compiler fence selected by lowering. Load/store semantics remain
/// attached to those operations; a standalone fence can never be "ordinary"
/// or merely "volatile".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFence {
    Acquire,
    Release,
    AcquireRelease,
    Sequential,
    DeviceRead,
    DeviceWrite,
    DeviceFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineImmediate {
    Integer {
        ty: MachineTypeId,
        bytes_le: Vec<u8>,
    },
    Float32(u32),
    Float64(u64),
    Null(MachineTypeId),
    Zero(MachineTypeId),
    SymbolAddress(SymbolId),
    Bytes(Vec<u8>),
}

/// Facts codegen may translate into LLVM attributes or inbounds operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendFacts {
    pub proof: ProofId,
    pub alignment: Option<u32>,
    pub non_null: bool,
    pub no_alias: bool,
    pub in_bounds: bool,
    pub no_unsigned_wrap: bool,
    pub no_signed_wrap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOperation {
    Immediate(MachineImmediate),
    Unary {
        op: MachineUnaryOp,
        value: ValueId,
    },
    Arithmetic {
        op: ArithmeticOp,
        left: ValueId,
        right: ValueId,
    },
    CheckedInteger {
        op: CheckedIntegerOp,
        signedness: IntegerSignedness,
        left: ValueId,
        right: ValueId,
        failure: ScalarFailureProvenance,
    },
    IntegerCompare {
        predicate: IntegerPredicate,
        left: ValueId,
        right: ValueId,
    },
    FloatCompare {
        predicate: FloatPredicate,
        left: ValueId,
        right: ValueId,
    },
    Convert {
        op: ConversionOp,
        value: ValueId,
        destination: MachineTypeId,
    },
    CheckedConvert {
        source: CheckedNumericKind,
        destination_kind: CheckedNumericKind,
        value: ValueId,
        destination: MachineTypeId,
        failure: ScalarFailureProvenance,
    },
    Select {
        condition: ValueId,
        then_value: ValueId,
        else_value: ValueId,
    },
    /// Construct one unpacked, target-laid-out struct value from its fields.
    MakeStruct {
        ty: MachineTypeId,
        fields: Vec<ValueId>,
    },
    /// Replace one field while preserving every other field of an unpacked struct.
    InsertField {
        aggregate: ValueId,
        field: u32,
        value: ValueId,
    },
    /// Project one field from an unpacked struct value.
    ExtractField {
        aggregate: ValueId,
        field: u32,
    },
    /// Preserve one first-class machine value without changing its representation.
    Copy {
        value: ValueId,
    },
    /// Construct the canonical `{u8 tag, payload}` machine enum value.
    MakeEnum {
        ty: MachineTypeId,
        variant: u8,
        payload: Option<ValueId>,
    },
    EnumTag {
        value: ValueId,
    },
    EnumPayload {
        value: ValueId,
    },
    AddressOffset {
        base: ValueId,
        byte_offset: ValueId,
        facts: BackendFacts,
    },
    Load {
        address: ValueId,
        ty: MachineTypeId,
        semantics: MemorySemantics,
        facts: BackendFacts,
    },
    Store {
        address: ValueId,
        value: ValueId,
        semantics: MemorySemantics,
        facts: BackendFacts,
    },
    /// Prove the fixed mailbox slot empty and materialize its strict-linear
    /// reservation as an address. A failed admission abandons through the
    /// target fatal ABI with exact Flow provenance.
    ActorReserve {
        mailbox: GlobalId,
        actor: u32,
        method: FunctionId,
        proof: ProofId,
        failure: ScalarFailureProvenance,
    },
    /// Publish the unit-message tag into the slot obtained from the adjacent
    /// reservation. Release ordering makes the message visible atomically.
    ActorCommit {
        reservation: ValueId,
        mailbox: GlobalId,
        actor: u32,
        method: FunctionId,
    },
    /// Execute the exact single-flight same-core reply protocol using one
    /// statically allocated 16-byte caller-frame slot. The backend performs
    /// Empty→Pending→Writing→Resolved→Consumed, dispatches the exact mailbox
    /// tag once, and returns the u64 outcome.
    ActorReplyRequest {
        slot: StackSlotId,
        mailbox: GlobalId,
        actor: u32,
        method: FunctionId,
        permit: ProofId,
        reply: ProofId,
        failure: ScalarFailureProvenance,
        duplicate_failure: ScalarFailureProvenance,
    },
    /// Callee-side exactly-once resolve marker. The same-core backend fuses
    /// the physical slot write into the direct caller transition after this
    /// result returns, while preserving the authenticated proof and outcome.
    ActorReplyResolve {
        outcome: ValueId,
        reply: ProofId,
    },
    /// Consume the exact unit-message tag at the beginning of its actor turn.
    /// An absent or substituted tag abandons with source-aware provenance.
    MailboxReceive {
        mailbox: GlobalId,
        actor: u32,
        method: FunctionId,
        failure: ScalarFailureProvenance,
    },
    /// Deterministically drain admitted unit messages through exact internal
    /// calls until the mailbox is empty. Each turn's `MailboxReceive` authenticates
    /// the exact method tag and releases the slot before the next scan, permitting
    /// a completed turn to publish recurring work without recursive re-entry.
    MailboxDispatch {
        mailbox: GlobalId,
        actor: u32,
        method: FunctionId,
    },
    MemoryCopy {
        destination: ValueId,
        source: ValueId,
        bytes: ValueId,
        destination_alignment: u32,
        source_alignment: u32,
        non_overlapping: bool,
        proof: ProofId,
    },
    MemorySet {
        destination: ValueId,
        byte: ValueId,
        bytes: ValueId,
        alignment: u32,
    },
    StackAddress(StackSlotId),
    GlobalAddress(GlobalId),
    Call {
        function: FunctionId,
        arguments: Vec<ValueId>,
        convention: CallingConvention,
    },
    RuntimeCall {
        intrinsic: RuntimeIntrinsic,
        arguments: Vec<ValueId>,
    },
    /// Fail the currently active generated source test when `condition` is
    /// false. Codegen emits one conditional call to the compiler-only,
    /// noreturn assertion runtime intrinsic and a normal true continuation.
    TestAssert {
        condition: ValueId,
        failure: MachineAssertionFailure,
    },
    Fence(MachineFence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineInstruction {
    pub id: InstructionId,
    pub results: Vec<ValueId>,
    pub operation: MachineOperation,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineTerminator {
    Jump {
        block: BlockId,
        arguments: Vec<ValueId>,
    },
    Branch {
        condition: ValueId,
        then_block: BlockId,
        then_arguments: Vec<ValueId>,
        else_block: BlockId,
        else_arguments: Vec<ValueId>,
    },
    Switch {
        value: ValueId,
        cases: Vec<(u128, BlockId, Vec<ValueId>)>,
        default: BlockId,
        default_arguments: Vec<ValueId>,
    },
    Return(Vec<ValueId>),
    TailCall {
        function: FunctionId,
        arguments: Vec<ValueId>,
    },
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineBlock {
    pub id: BlockId,
    pub parameters: Vec<ValueId>,
    pub instructions: Vec<MachineInstruction>,
    pub terminator: MachineTerminator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineValue {
    pub id: ValueId,
    pub ty: MachineTypeId,
    pub source_name: Option<String>,
}

/// Exact declared-source assertion descriptor retained for the compiler-only
/// generated-test failure intrinsic. The source database is authoritative;
/// this record preserves its bounded lowering result across MachineWir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAssertionFailure {
    pub expression: String,
    pub expression_global: GlobalId,
    pub message: Option<String>,
    pub message_global: Option<GlobalId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    pub id: StackSlotId,
    pub size: u64,
    pub alignment: u32,
    pub source_name: Option<String>,
    pub live_states: Vec<u32>,
    pub overlay_group: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFunctionRole {
    Ordinary,
    ActorTurn(u32),
    TaskEntry(u32),
    Isr(u32),
    Cleanup,
    ImageEntry,
    Test,
}

/// Exact FlowWir provenance retained through target lowering. Runtime-test
/// intrinsics are compiler-only and may occur solely in a generated test
/// harness, so role alone is intentionally insufficient at this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFunctionOrigin {
    SourceSemantic {
        semantic_function: u32,
    },
    GeneratedImageEntry {
        semantic_function: u32,
        constructor: u32,
    },
    GeneratedTestHarness {
        semantic_function: u32,
        group: u32,
    },
    GeneratedAsyncState {
        semantic_function: u32,
        state: u32,
    },
    GeneratedCleanup {
        semantic_function: u32,
        scope: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFunction {
    pub id: FunctionId,
    /// Exact FlowWir function lowered into this machine function. Revision 0.1
    /// requires a canonical one-to-one function mapping.
    pub flow_function: u32,
    pub origin: MachineFunctionOrigin,
    pub role: MachineFunctionRole,
    pub symbol: SymbolId,
    /// Exact code section selected by machine lowering. Codegen determines the
    /// final section-relative offset and extent, but never section ownership.
    pub section: SectionId,
    pub linkage: Linkage,
    pub convention: CallingConvention,
    pub parameters: Vec<ValueId>,
    pub result: MachineTypeId,
    /// Exact FlowWir proof attachments retained for independently validating
    /// activation capacity and cleanup authority at the machine boundary.
    pub proofs: Vec<ProofId>,
    pub values: Vec<MachineValue>,
    pub stack_slots: Vec<StackSlot>,
    pub blocks: Vec<MachineBlock>,
    pub entry: BlockId,
    pub stack_bytes: u64,
    pub source: Option<Span>,
}

/// The only scheduler ownership admitted by MachineWir v16. An actor turn is
/// compiled but remains dormant until a real mailbox admission operation
/// exists; a single-slot static task is invoked exactly once during startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineActivationOwner {
    Actor {
        actor: u32,
        mailbox_capacity: u32,
    },
    Task {
        task: u32,
        slots: u32,
        supervisor: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineActivationSchedule {
    DormantMailbox,
    /// The image entry invokes this actor turn once, immediately after the
    /// startup task has published its statically admitted mailbox message.
    MailboxOnce,
    /// One per-core capacity-one drain owns all turns for this actor. The
    /// image entry dispatches by sealed mailbox tag and never calls a turn
    /// recursively from another turn.
    SchedulerFifo,
    StartupOnce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineActivationCancellation {
    DropCalleeThenPropagate,
}

/// Exact machine-consumer join for one FlowWir v15 immediate activation.
///
/// The current closed subset lowers an ordinary async helper that is proven
/// to return without another suspension into a private direct call followed
/// by the named resume edge. The source plan and its frame/capacity/cleanup
/// authority remain first-class even though the strict-linear token itself is
/// erased from machine SSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineActivationPlan {
    pub id: MachineActivationId,
    pub owner: MachineActivationOwner,
    pub schedule: MachineActivationSchedule,
    pub caller: FunctionId,
    pub callee: FunctionId,
    pub call_instruction: InstructionId,
    pub state: u32,
    pub resume_block: BlockId,
    pub region: u32,
    pub region_capacity_bytes: u64,
    pub region_alignment: u32,
    pub frame_bytes: u64,
    pub maximum_live: u32,
    pub cancellation: MachineActivationCancellation,
    pub capacity_proof: ProofId,
    pub capacity_bound: u64,
    pub cleanup_proof: ProofId,
    pub source: Span,
}

/// Exact per-core ownership authority retained from FlowWir. This record does
/// not claim a ready queue, dispatch policy, parking, or runtime execution;
/// those remain separate lowering obligations. Keeping the partition at the
/// machine boundary prevents later runtime work from silently recovering a
/// global scheduler after Flow ownership has been authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSchedulerPlan {
    pub core: u32,
    pub actors: Vec<u32>,
    pub tasks: Vec<u32>,
}

/// Closed identity of statically reserved storage in the currently supported
/// actor image. These categories describe allocation only; they do not imply a
/// mailbox producer, scheduler, or runtime dispatch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineRegionStorageKind {
    ActorMailbox {
        actor: u32,
        mailbox_capacity: u32,
    },
    /// Canonical, actor-owned persistent state cell. MachineWir v16 admits
    /// exactly one zero-initialized `u64` cell for a stateful actor; richer
    /// state layouts remain outside this closed representation.
    ActorState {
        actor: u32,
    },
    ActorTurnFrame {
        actor: u32,
        function: FunctionId,
    },
    TaskEntryFrame {
        task: u32,
        function: FunctionId,
        slots: u32,
    },
    ActivationFrame {
        activation: MachineActivationId,
    },
}

/// Exact Flow-region to native zero-initialized writable allocation join.
///
/// Every record owns one distinct type/global/symbol/section tuple. The
/// capacity proof bounds `capacity_units`; the reserved byte extent is the
/// checked product of `capacity_units` and `bytes_per_unit`. The source region
/// name/span remain first-class so codegen and reporting never infer them from
/// actor counts or generated spellings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRegionStorage {
    pub id: MachineRegionStorageId,
    pub flow_region: u32,
    pub name: String,
    pub kind: MachineRegionStorageKind,
    pub global: GlobalId,
    pub symbol: SymbolId,
    pub section: SectionId,
    pub ty: MachineTypeId,
    pub capacity_proof: ProofId,
    pub capacity_units: u64,
    pub bytes_per_unit: u64,
    pub capacity_bytes: u64,
    pub alignment: u32,
    /// Exact Flow region declaration/installation span.
    pub source: Span,
    /// Exact sole source carried by the retained capacity proof. The mailbox
    /// proof names its `mailbox=` argument, which is intentionally distinct
    /// from the enclosing actor-installation region span.
    pub capacity_source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineTestKind {
    Comptime,
    Integration,
    Image,
}

/// Canonical executable test metadata retained from FlowWir without global
/// test-plan IDs. Those IDs live in the already-encoded protocol frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTestEntry {
    pub id: MachineTestId,
    /// Global plan identity encoded into compiler-owned protocol frames.
    pub plan_id: u32,
    pub name: String,
    pub function: FunctionId,
    pub kind: MachineTestKind,
    pub source: Span,
    pub timeout_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineGlobal {
    pub id: GlobalId,
    pub symbol: SymbolId,
    pub ty: MachineTypeId,
    pub section: SectionId,
    pub offset: u64,
    pub alignment: u32,
    pub initializer: MachineImmediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProof {
    pub id: ProofId,
    pub source_proofs: Vec<u32>,
    pub kind: BackendProofKind,
    pub depends_on: Vec<ProofId>,
    pub bound: Option<u64>,
    pub sources: Vec<Span>,
    pub statement: String,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendProofKind {
    TypeChecked,
    EffectsAllowed,
    DefiniteInitialization,
    Ownership,
    AccessExclusive,
    ViewDoesNotEscape,
    RegionBound,
    CapacityBound,
    ActorReplyExactlyOnce,
    WaitGraphAcyclic,
    CleanupAcyclic,
    WorkBound,
    StackBound,
    IsrSafe,
    DmaTransition,
    MmioPartition,
    DeviceValueValidated,
    WireLayout,
    ReceiptLineage,
    ActorAsIf,
    SupervisionComplete,
    ImageClosed,
    FlowControl,
    ValueRange,
    Alignment,
    NoAlias,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTarget {
    pub identity: String,
    pub llvm_triple: String,
    pub data_layout: String,
    pub cpu: String,
    pub features: Vec<String>,
    pub coff_machine: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineWir {
    pub version: u32,
    pub name: String,
    pub build: BuildIdentity,
    pub target: MachineTarget,
    pub layout: DataLayout,
    pub runtime: RuntimeRequirements,
    pub types: Vec<MachineType>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub globals: Vec<MachineGlobal>,
    pub functions: Vec<MachineFunction>,
    pub activations: Vec<MachineActivationPlan>,
    pub schedulers: Vec<MachineSchedulerPlan>,
    pub region_storage: Vec<MachineRegionStorage>,
    pub interrupts: Vec<InterruptEntry>,
    pub tests: Vec<MachineTestEntry>,
    pub proofs: Vec<BackendProof>,
    pub image_entry: FunctionId,
}

/// Finite policy for independently validating an untrusted MachineWir model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum records in any one dense arena or validation scratch table.
    pub arena_records: u64,
    /// Maximum aggregate vector elements and validation scratch entries.
    pub model_edges: u64,
    /// Maximum aggregate retained UTF-8 and immediate byte payload.
    pub payload_bytes: u64,
    /// Conservative upper bound for validation, CFG, and call-graph work.
    pub validation_work: u64,
    /// Maximum number of validation errors retained in memory.
    pub errors: u32,
}

impl ValidationLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            arena_records: 256_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            validation_work: 1_100_000_000_000,
            errors: 100_000,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.arena_records > 0
            && self.arena_records <= u32::MAX as u64
            && self.model_edges > 0
            && self.payload_bytes > 0
            && self.validation_work > 0
            && self.errors > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    InvalidLimits,
    Cancelled,
    ResourceLimit { resource: &'static str, limit: u64 },
    Invalid(ValidationErrors),
}

impl MachineWir {
    /// Seal this module only after matching every target-owned backend field and
    /// interrupt route against the exact content-addressed package selected by
    /// the build. There is intentionally no context-free sealing operation.
    pub fn validate_for_target(
        self,
        target: &TargetPackage,
    ) -> Result<ValidatedMachineWir, ValidationErrors> {
        match self.validate_with_limits(target, ValidationLimits::standard(), &|| false) {
            Ok(wir) => Ok(wir),
            Err(ValidationFailure::Invalid(errors)) => Err(errors),
            Err(ValidationFailure::InvalidLimits) => {
                Err(ValidationErrors(vec![ValidationError::InvalidLimits]))
            }
            Err(ValidationFailure::Cancelled) => {
                Err(ValidationErrors(vec![ValidationError::Cancelled]))
            }
            Err(ValidationFailure::ResourceLimit { resource, limit }) => {
                Err(ValidationErrors(vec![ValidationError::ResourceLimit {
                    resource,
                    limit,
                }]))
            }
        }
    }

    /// Validate against an exact target under caller-owned finite policy and
    /// cancellation. No project-sized scratch allocation occurs before the
    /// resource preflight succeeds.
    pub fn validate_with_limits(
        self,
        target: &TargetPackage,
        limits: ValidationLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedMachineWir, ValidationFailure> {
        if !limits.is_valid() {
            return Err(ValidationFailure::InvalidLimits);
        }
        validate_model_resources(&self, limits, is_cancelled)?;
        let errors = validate_module(&self, target, limits, is_cancelled)?;
        if errors.is_empty() {
            if is_cancelled() {
                Err(ValidationFailure::Cancelled)
            } else {
                Ok(ValidatedMachineWir(self))
            }
        } else {
            Err(ValidationFailure::Invalid(ValidationErrors(errors)))
        }
    }
}

struct ResourceMeter<'a> {
    limits: ValidationLimits,
    arena_records: u64,
    edges: u64,
    payload_bytes: u64,
    work: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> ResourceMeter<'a> {
    fn new(limits: ValidationLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
            arena_records: 0,
            edges: 0,
            payload_bytes: 0,
            work: 0,
            is_cancelled,
        }
    }

    fn poll(&self) -> Result<(), ValidationFailure> {
        if (self.is_cancelled)() {
            Err(ValidationFailure::Cancelled)
        } else {
            Ok(())
        }
    }

    fn length(
        &self,
        resource: &'static str,
        length: usize,
        limit: u64,
    ) -> Result<u64, ValidationFailure> {
        self.poll()?;
        let length = u64::try_from(length)
            .map_err(|_| ValidationFailure::ResourceLimit { resource, limit })?;
        if length > limit {
            Err(ValidationFailure::ResourceLimit { resource, limit })
        } else {
            Ok(length)
        }
    }

    fn arena(&mut self, resource: &'static str, length: usize) -> Result<(), ValidationFailure> {
        let length = self.length(resource, length, self.limits.arena_records)?;
        self.edges(length)?;
        self.arena_records = self.arena_records.max(length);
        Ok(())
    }

    fn edge_slice<T>(&mut self, values: &[T]) -> Result<(), ValidationFailure> {
        let length = self.length("model edges", values.len(), self.limits.model_edges)?;
        self.edges(length)
    }

    fn edges(&mut self, amount: u64) -> Result<(), ValidationFailure> {
        let chunks = amount
            .checked_add(4095)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            })?
            / 4096;
        for _ in 0..chunks {
            self.poll()?;
        }
        self.edges = self
            .edges
            .checked_add(amount)
            .filter(|total| *total <= self.limits.model_edges)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            })?;
        self.work(amount)?;
        Ok(())
    }

    fn payload(&mut self, length: usize) -> Result<(), ValidationFailure> {
        self.poll()?;
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "payload bytes",
            limit: self.limits.payload_bytes,
        })?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(length)
            .filter(|total| *total <= self.limits.payload_bytes)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: self.limits.payload_bytes,
            })?;
        self.work(length)?;
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), ValidationFailure> {
        self.payload(value.len())
    }

    fn work(&mut self, amount: u64) -> Result<(), ValidationFailure> {
        self.poll()?;
        self.work = self
            .work
            .checked_add(amount)
            .filter(|work| *work <= self.limits.validation_work)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })?;
        Ok(())
    }

    fn work_product(&mut self, left: u64, right: u64) -> Result<(), ValidationFailure> {
        self.work(
            left.checked_mul(right)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: self.limits.validation_work,
                })?,
        )
    }

    fn finish(&self) -> Result<(), ValidationFailure> {
        self.poll()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelResourceUsage {
    arena_records: u64,
    model_edges: u64,
    payload_bytes: u64,
    validation_work: u64,
}

fn validate_model_resources(
    module: &MachineWir,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ValidationFailure> {
    model_resource_usage(module, limits, is_cancelled).map(|_| ())
}

fn model_resource_usage(
    module: &MachineWir,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ModelResourceUsage, ValidationFailure> {
    let mut meter = ResourceMeter::new(limits, is_cancelled);
    meter.text(&module.name)?;
    meter.text(module.build.target.as_str())?;
    for text in [
        module.target.identity.as_str(),
        module.target.llvm_triple.as_str(),
        module.target.data_layout.as_str(),
        module.target.cpu.as_str(),
        module.target.coff_machine.as_str(),
    ] {
        meter.text(text)?;
    }
    meter.edge_slice(&module.target.features)?;
    for feature in &module.target.features {
        meter.text(feature)?;
    }
    meter.edge_slice(&module.runtime.intrinsics)?;
    meter.arena("types", module.types.len())?;
    meter.arena("sections", module.sections.len())?;
    meter.arena("symbols", module.symbols.len())?;
    meter.arena("globals", module.globals.len())?;
    meter.arena("functions", module.functions.len())?;
    meter.arena("activations", module.activations.len())?;
    meter.arena("schedulers", module.schedulers.len())?;
    meter.arena("region storage", module.region_storage.len())?;
    meter.arena("interrupts", module.interrupts.len())?;
    meter.arena("tests", module.tests.len())?;
    meter.arena("proofs", module.proofs.len())?;

    for ty in &module.types {
        meter.poll()?;
        if let Some(name) = &ty.source_name {
            meter.text(name)?;
        }
        match &ty.kind {
            MachineTypeKind::Struct { fields, .. } => meter.edge_slice(fields)?,
            MachineTypeKind::TaggedEnum {
                payload,
                payload_variants,
                ..
            } => {
                meter.edges(1 + u64::from(payload.is_some()))?;
                meter.edge_slice(payload_variants)?;
            }
            MachineTypeKind::Function { parameters, .. } => meter.edge_slice(parameters)?,
            MachineTypeKind::Void
            | MachineTypeKind::Integer { .. }
            | MachineTypeKind::Float32
            | MachineTypeKind::Float64
            | MachineTypeKind::Pointer { .. }
            | MachineTypeKind::Vector { .. }
            | MachineTypeKind::Array { .. } => {}
        }
    }
    for section in &module.sections {
        meter.poll()?;
        meter.text(&section.name)?;
        meter.text(&section.owner)?;
    }
    for symbol in &module.symbols {
        meter.poll()?;
        meter.text(&symbol.name)?;
    }
    for global in &module.globals {
        meter.poll()?;
        meter_immediate(&mut meter, &global.initializer)?;
    }

    let mut all_instructions = 0u64;
    let mut all_values = 0u64;
    for function in &module.functions {
        meter.poll()?;
        meter.edge_slice(&function.parameters)?;
        meter.edge_slice(&function.proofs)?;
        meter.arena("function values", function.values.len())?;
        meter.arena("stack slots", function.stack_slots.len())?;
        meter.arena("function blocks", function.blocks.len())?;
        all_values = all_values
            .checked_add(u64::try_from(function.values.len()).map_err(|_| {
                ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                }
            })?)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            })?;
        for value in &function.values {
            meter.poll()?;
            if let Some(name) = &value.source_name {
                meter.text(name)?;
            }
        }
        for stack_slot in &function.stack_slots {
            meter.poll()?;
            if let Some(name) = &stack_slot.source_name {
                meter.text(name)?;
            }
            meter.edge_slice(&stack_slot.live_states)?;
        }
        let mut function_instructions = 0u64;
        let mut cfg_edges = 0u64;
        let mut value_uses = 0u64;
        for block in &function.blocks {
            meter.poll()?;
            meter.edge_slice(&block.parameters)?;
            meter.arena("block instructions", block.instructions.len())?;
            let instructions = u64::try_from(block.instructions.len()).map_err(|_| {
                ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                }
            })?;
            function_instructions = function_instructions.checked_add(instructions).ok_or(
                ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                },
            )?;
            for instruction in &block.instructions {
                meter.poll()?;
                meter.edge_slice(&instruction.results)?;
                value_uses = value_uses
                    .checked_add(meter_operation(&mut meter, &instruction.operation)?)
                    .ok_or(ValidationFailure::ResourceLimit {
                        resource: "validation work",
                        limit: limits.validation_work,
                    })?;
            }
            let (edges, uses) = meter_terminator(&mut meter, &block.terminator)?;
            cfg_edges = cfg_edges
                .checked_add(edges)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                })?;
            value_uses = value_uses
                .checked_add(uses)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                })?;
        }
        all_instructions = all_instructions.checked_add(function_instructions).ok_or(
            ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            },
        )?;
        let blocks =
            u64::try_from(function.blocks.len()).map_err(|_| ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            })?;
        meter.work(function_instructions)?;
        meter.work_product(
            blocks,
            blocks
                .checked_add(cfg_edges)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: limits.validation_work,
                })?,
        )?;
        meter.work_product(value_uses, blocks.max(1))?;
    }

    for _activation in &module.activations {
        meter.poll()?;
        // The record contains only fixed-width facts. Charge one edge for its
        // independently indexed caller/callee join.
        meter.edges(1)?;
    }

    for scheduler in &module.schedulers {
        meter.poll()?;
        meter.edge_slice(&scheduler.actors)?;
        meter.edge_slice(&scheduler.tasks)?;
    }

    for storage in &module.region_storage {
        meter.poll()?;
        meter.text(&storage.name)?;
        // Region, type, global, symbol, section, and proof are independently
        // indexed joins retained by this fixed-size record.
        meter.edges(6)?;
    }

    for interrupt in &module.interrupts {
        meter.poll()?;
        meter.text(&interrupt.target_binding)?;
    }
    for test in &module.tests {
        meter.poll()?;
        meter.text(&test.name)?;
    }
    for proof in &module.proofs {
        meter.poll()?;
        meter.edge_slice(&proof.source_proofs)?;
        meter.edge_slice(&proof.depends_on)?;
        meter.edge_slice(&proof.sources)?;
        meter.text(&proof.statement)?;
    }
    let interrupt_count =
        u64::try_from(module.interrupts.len()).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: limits.validation_work,
        })?;
    let function_count =
        u64::try_from(module.functions.len()).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: limits.validation_work,
        })?;
    meter.work_product(
        interrupt_count,
        function_count
            .checked_add(all_instructions)
            .and_then(|work| work.checked_add(all_values))
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            })?,
    )?;
    let runtime_count = u64::try_from(module.runtime.intrinsics.len()).map_err(|_| {
        ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: limits.validation_work,
        }
    })?;
    let symbol_count =
        u64::try_from(module.symbols.len()).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: limits.validation_work,
        })?;
    meter.work_product(
        runtime_count,
        symbol_count
            .checked_add(function_count)
            .and_then(|work| work.checked_add(all_instructions))
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            })?,
    )?;
    let type_count =
        u64::try_from(module.types.len()).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: limits.validation_work,
        })?;
    meter.work_product(interrupt_count, type_count)?;
    let sort_factor = u64::from(u64::BITS - meter.edges.max(1).leading_zeros()) + 1;
    meter.work_product(meter.edges, sort_factor)?;
    meter.finish()?;
    Ok(ModelResourceUsage {
        arena_records: meter.arena_records,
        model_edges: meter.edges,
        payload_bytes: meter.payload_bytes,
        validation_work: meter.work,
    })
}

fn meter_immediate(
    meter: &mut ResourceMeter<'_>,
    immediate: &MachineImmediate,
) -> Result<(), ValidationFailure> {
    match immediate {
        MachineImmediate::Integer { bytes_le, .. } | MachineImmediate::Bytes(bytes_le) => {
            meter.payload(bytes_le.len())
        }
        MachineImmediate::Float32(_)
        | MachineImmediate::Float64(_)
        | MachineImmediate::Null(_)
        | MachineImmediate::Zero(_)
        | MachineImmediate::SymbolAddress(_) => Ok(()),
    }
}

fn meter_operation(
    meter: &mut ResourceMeter<'_>,
    operation: &MachineOperation,
) -> Result<u64, ValidationFailure> {
    match operation {
        MachineOperation::Immediate(immediate) => {
            meter_immediate(meter, immediate)?;
            Ok(0)
        }
        MachineOperation::Call { arguments, .. }
        | MachineOperation::RuntimeCall { arguments, .. }
        | MachineOperation::MakeStruct {
            fields: arguments, ..
        } => {
            meter.edge_slice(arguments)?;
            u64::try_from(arguments.len()).map_err(|_| ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: meter.limits.validation_work,
            })
        }
        MachineOperation::Unary { .. }
        | MachineOperation::Convert { .. }
        | MachineOperation::CheckedConvert { .. }
        | MachineOperation::Copy { .. }
        | MachineOperation::Load { .. }
        | MachineOperation::GlobalAddress(_)
        | MachineOperation::StackAddress(_) => Ok(1),
        MachineOperation::MakeEnum { .. }
        | MachineOperation::EnumTag { .. }
        | MachineOperation::EnumPayload { .. }
        | MachineOperation::ExtractField { .. } => Ok(1),
        MachineOperation::InsertField { .. } => Ok(2),
        MachineOperation::TestAssert { failure, .. } => {
            meter.payload(failure.expression.len())?;
            if let Some(message) = &failure.message {
                meter.payload(message.len())?;
            }
            Ok(1)
        }
        MachineOperation::ActorCommit { .. } => Ok(1),
        MachineOperation::ActorReplyResolve { .. } => Ok(1),
        MachineOperation::ActorReserve { .. }
        | MachineOperation::ActorReplyRequest { .. }
        | MachineOperation::MailboxReceive { .. }
        | MachineOperation::MailboxDispatch { .. } => Ok(0),
        MachineOperation::Arithmetic { .. }
        | MachineOperation::CheckedInteger { .. }
        | MachineOperation::IntegerCompare { .. }
        | MachineOperation::FloatCompare { .. }
        | MachineOperation::AddressOffset { .. } => Ok(2),
        MachineOperation::Select { .. }
        | MachineOperation::MemoryCopy { .. }
        | MachineOperation::MemorySet { .. } => Ok(3),
        MachineOperation::Store { .. } => Ok(2),
        MachineOperation::Fence(_) => Ok(0),
    }
}

fn meter_terminator(
    meter: &mut ResourceMeter<'_>,
    terminator: &MachineTerminator,
) -> Result<(u64, u64), ValidationFailure> {
    let mut edges = 0u64;
    let mut uses = 0u64;
    match terminator {
        MachineTerminator::Jump { arguments, .. }
        | MachineTerminator::Return(arguments)
        | MachineTerminator::TailCall { arguments, .. } => {
            meter.edge_slice(arguments)?;
            uses =
                u64::try_from(arguments.len()).map_err(|_| ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: meter.limits.validation_work,
                })?;
            edges = u64::from(matches!(terminator, MachineTerminator::Jump { .. }));
        }
        MachineTerminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => {
            meter.edge_slice(then_arguments)?;
            meter.edge_slice(else_arguments)?;
            uses = u64::try_from(then_arguments.len())
                .ok()
                .and_then(|count| count.checked_add(u64::try_from(else_arguments.len()).ok()?))
                .and_then(|count| count.checked_add(1))
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: meter.limits.validation_work,
                })?;
            edges = 2;
        }
        MachineTerminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            meter.edge_slice(cases)?;
            meter.edge_slice(default_arguments)?;
            edges = u64::try_from(cases.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: meter.limits.validation_work,
                })?;
            uses = 1u64
                .checked_add(u64::try_from(default_arguments.len()).map_err(|_| {
                    ValidationFailure::ResourceLimit {
                        resource: "validation work",
                        limit: meter.limits.validation_work,
                    }
                })?)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: meter.limits.validation_work,
                })?;
            for (_, _, arguments) in cases {
                meter.poll()?;
                meter.edge_slice(arguments)?;
                uses = uses
                    .checked_add(u64::try_from(arguments.len()).map_err(|_| {
                        ValidationFailure::ResourceLimit {
                            resource: "validation work",
                            limit: meter.limits.validation_work,
                        }
                    })?)
                    .ok_or(ValidationFailure::ResourceLimit {
                        resource: "validation work",
                        limit: meter.limits.validation_work,
                    })?;
            }
        }
        MachineTerminator::Unreachable => {}
    }
    Ok((edges, uses))
}

struct ValidationContext<'a> {
    errors: Vec<ValidationError>,
    limits: ValidationLimits,
    is_cancelled: &'a dyn Fn() -> bool,
    cancelled: bool,
    allocation_failure: Option<(&'static str, u64)>,
    capped: bool,
    assertion_global_uses: Vec<u32>,
    test_reachable_functions: Vec<bool>,
}

impl<'a> ValidationContext<'a> {
    fn new(limits: ValidationLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            errors: Vec::new(),
            limits,
            is_cancelled,
            cancelled: false,
            allocation_failure: None,
            capped: false,
            assertion_global_uses: Vec::new(),
            test_reachable_functions: Vec::new(),
        }
    }

    fn prepare_assertion_witnesses(&mut self, module: &MachineWir) {
        let Some(mut uses) = self.filled(module.globals.len(), 0u32) else {
            return;
        };
        for function in &module.functions {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    if !self.poll() {
                        return;
                    }
                    let MachineOperation::TestAssert { failure, .. } = &instruction.operation
                    else {
                        continue;
                    };
                    for global in
                        std::iter::once(failure.expression_global).chain(failure.message_global)
                    {
                        if let Some(count) = uses.get_mut(global.0 as usize) {
                            *count = count.saturating_add(1);
                        }
                    }
                }
            }
        }
        let Some(mut reachable) = self.filled(module.functions.len(), false) else {
            return;
        };
        let Some(mut pending) = self.scratch(module.functions.len()) else {
            return;
        };
        if let [test] = module.tests.as_slice()
            && !self.scratch_push(&mut pending, test.function)
        {
            return;
        }
        while let Some(function_id) = pending.pop() {
            if !self.poll() {
                return;
            }
            let Some(slot) = reachable.get_mut(function_id.0 as usize) else {
                continue;
            };
            if *slot {
                continue;
            }
            *slot = true;
            let Some(function) = module.functions.get(function_id.0 as usize) else {
                continue;
            };
            for block in &function.blocks {
                for instruction in &block.instructions {
                    if !self.poll() {
                        return;
                    }
                    if let MachineOperation::Call {
                        function: callee, ..
                    } = instruction.operation
                        && !self.scratch_push(&mut pending, callee)
                    {
                        return;
                    }
                }
            }
        }
        self.assertion_global_uses = uses;
        self.test_reachable_functions = reachable;
    }

    fn assertion_global_is_unique(&self, global: GlobalId) -> bool {
        self.assertion_global_uses.get(global.0 as usize) == Some(&1)
    }

    fn selected_test_reaches(&self, function: FunctionId) -> bool {
        self.test_reachable_functions
            .get(function.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    fn poll(&mut self) -> bool {
        if self.cancelled || (self.is_cancelled)() {
            self.cancelled = true;
            false
        } else {
            !self.capped && self.allocation_failure.is_none()
        }
    }

    fn push(&mut self, error: ValidationError) {
        if !self.poll() {
            return;
        }
        let limit = self.limits.errors as usize;
        if self.errors.len().saturating_add(1) >= limit {
            if self.errors.try_reserve(1).is_err() {
                self.allocation_failure =
                    Some(("validation error scratch", u64::from(self.limits.errors)));
                return;
            }
            if !self.poll() {
                return;
            }
            self.errors.push(ValidationError::TooManyErrors {
                limit: self.limits.errors,
            });
            self.capped = true;
            return;
        }
        if self.errors.try_reserve(1).is_err() {
            self.allocation_failure =
                Some(("validation error scratch", u64::from(self.limits.errors)));
            return;
        }
        if !self.poll() {
            return;
        }
        self.errors.push(error);
    }

    fn scratch<T>(&mut self, capacity: usize) -> Option<Vec<T>> {
        if !self.poll()
            || u64::try_from(capacity).map_or(true, |length| length > self.limits.model_edges)
        {
            if !self.cancelled && !self.capped {
                self.allocation_failure =
                    Some(("validation scratch entries", self.limits.model_edges));
            }
            return None;
        }
        let mut values = Vec::new();
        if values.try_reserve_exact(capacity).is_err() {
            self.allocation_failure = Some(("validation scratch entries", self.limits.model_edges));
            None
        } else if !self.poll() {
            None
        } else {
            Some(values)
        }
    }

    fn filled<T: Clone>(&mut self, length: usize, value: T) -> Option<Vec<T>> {
        let mut values = self.scratch(length)?;
        for _ in 0..length {
            if !self.poll() {
                return None;
            }
            values.push(value.clone());
        }
        Some(values)
    }

    fn scratch_push<T>(&mut self, values: &mut Vec<T>, value: T) -> bool {
        if !self.poll()
            || u64::try_from(values.len()).map_or(true, |length| length >= self.limits.model_edges)
        {
            if !self.cancelled && !self.capped {
                self.allocation_failure =
                    Some(("validation scratch entries", self.limits.model_edges));
            }
            return false;
        }
        if values.try_reserve(1).is_err() {
            self.allocation_failure = Some(("validation scratch entries", self.limits.model_edges));
            false
        } else if !self.poll() {
            false
        } else {
            values.push(value);
            true
        }
    }

    fn finish(mut self) -> Result<Vec<ValidationError>, ValidationFailure> {
        if !self.capped && self.allocation_failure.is_none() {
            self.poll();
        }
        if self.cancelled {
            Err(ValidationFailure::Cancelled)
        } else if let Some((resource, limit)) = self.allocation_failure {
            Err(ValidationFailure::ResourceLimit { resource, limit })
        } else {
            Ok(self.errors)
        }
    }
}

fn sort_scratch<T: Copy + Ord>(values: &mut [T], errors: &mut ValidationContext<'_>) -> bool {
    sort_scratch_by(values, errors, &|left, right, _| Some(left.cmp(right)))
}

fn sort_scratch_by<T: Copy>(
    values: &mut [T],
    errors: &mut ValidationContext<'_>,
    compare: &impl Fn(&T, &T, &mut ValidationContext<'_>) -> Option<std::cmp::Ordering>,
) -> bool {
    let Some(first) = values.first().copied() else {
        return errors.poll();
    };
    let Some(mut buffer) = errors.filled(values.len(), first) else {
        return false;
    };
    let mut width = 1_usize;
    let mut source_is_values = true;
    while width < values.len() {
        let completed = if source_is_values {
            merge_sort_pass(values, &mut buffer, width, errors, compare)
        } else {
            merge_sort_pass(&buffer, values, width, errors, compare)
        };
        if !completed {
            return false;
        }
        source_is_values = !source_is_values;
        width = width.checked_mul(2).unwrap_or(values.len());
    }
    if !source_is_values {
        for (destination, source) in values.iter_mut().zip(buffer) {
            if !errors.poll() {
                return false;
            }
            *destination = source;
        }
    }
    true
}

fn merge_sort_pass<T: Copy>(
    source: &[T],
    destination: &mut [T],
    width: usize,
    errors: &mut ValidationContext<'_>,
    compare: &impl Fn(&T, &T, &mut ValidationContext<'_>) -> Option<std::cmp::Ordering>,
) -> bool {
    let mut start = 0_usize;
    while start < source.len() {
        let middle = start
            .checked_add(width)
            .unwrap_or(source.len())
            .min(source.len());
        let end = middle
            .checked_add(width)
            .unwrap_or(source.len())
            .min(source.len());
        let (mut left, mut right) = (start, middle);
        for output in &mut destination[start..end] {
            if !errors.poll() {
                return false;
            }
            let take_left = if right >= end {
                true
            } else if left >= middle {
                false
            } else {
                let Some(ordering) = compare(&source[left], &source[right], errors) else {
                    return false;
                };
                ordering != std::cmp::Ordering::Greater
            };
            if take_left {
                *output = source[left];
                left += 1;
            } else {
                *output = source[right];
                right += 1;
            }
        }
        start = end;
    }
    true
}

fn validate_module(
    module: &MachineWir,
    target: &TargetPackage,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ValidationError>, ValidationFailure> {
    let mut errors = ValidationContext::new(limits, is_cancelled);
    errors.prepare_assertion_witnesses(module);
    if let Err(error) = target.validate() {
        errors.push(ValidationError::TargetPackage(error));
    }
    if module.version != MACHINE_WIR_VERSION {
        errors.push(ValidationError::UnsupportedVersion(module.version));
    }
    let Some(missing_image_name) = text_is_blank(&module.name, &mut errors) else {
        return errors.finish();
    };
    if missing_image_name {
        errors.push(ValidationError::MissingImageName);
    }
    if module.runtime.version != RUNTIME_ABI_VERSION {
        errors.push(ValidationError::RuntimeAbi(
            RuntimeAbiError::UnsupportedVersion(module.runtime.version),
        ));
    } else {
        for pair in module.runtime.intrinsics.windows(2) {
            if !errors.poll() {
                return errors.finish();
            }
            if pair[0] >= pair[1] {
                errors.push(ValidationError::RuntimeAbi(
                    RuntimeAbiError::NonCanonicalRequirements,
                ));
                break;
            }
        }
    }
    validate_target_and_layout(module, target, &mut errors);
    check_dense(
        "type",
        module.types.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "section",
        module.sections.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "symbol",
        module.symbols.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "global",
        module.globals.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "function",
        module.functions.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "flow function provenance",
        module.functions.iter().map(|item| item.flow_function),
        &mut errors,
    );
    check_dense(
        "activation",
        module.activations.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "region storage",
        module.region_storage.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "interrupt entry",
        module.interrupts.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "test",
        module.tests.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "proof",
        module.proofs.iter().map(|item| item.id.0),
        &mut errors,
    );

    for proof in &module.proofs {
        if !errors.poll() {
            return errors.finish();
        }
        let mut backward_dependencies = true;
        for dependency in &proof.depends_on {
            if !errors.poll() {
                return errors.finish();
            }
            require_id(
                "proof dependency",
                dependency.0,
                module.proofs.len(),
                &mut errors,
            );
            backward_dependencies &= dependency.0 < proof.id.0;
        }
        let Some(blank_statement) = text_is_blank(&proof.statement, &mut errors) else {
            return errors.finish();
        };
        let mut canonical = !proof.source_proofs.is_empty()
            && !blank_statement
            && proof.source == proof.sources.first().copied()
            && backward_dependencies;
        for pair in proof.source_proofs.windows(2) {
            if !errors.poll() {
                return errors.finish();
            }
            canonical &= pair[0] < pair[1];
        }
        for pair in proof.depends_on.windows(2) {
            if !errors.poll() {
                return errors.finish();
            }
            canonical &= pair[0] < pair[1];
        }
        for source in &proof.sources {
            if !errors.poll() {
                return errors.finish();
            }
            canonical &= source.range.start <= source.range.end;
        }
        if !canonical {
            errors.push(ValidationError::InvalidRecord {
                kind: "backend proof",
                id: proof.id.0,
            });
        }
    }

    for ty in &module.types {
        if !errors.poll() {
            return errors.finish();
        }
        validate_type(module, ty, &mut errors);
    }
    for section in &module.sections {
        if !errors.poll() {
            return errors.finish();
        }
        let Some(blank_name) = text_is_blank(&section.name, &mut errors) else {
            return errors.finish();
        };
        if blank_name || !valid_alignment(section.alignment) {
            errors.push(ValidationError::InvalidRecord {
                kind: "section",
                id: section.id.0,
            });
        }
    }
    require_unique_names(
        "section",
        module.sections.iter().map(|item| item.name.as_str()),
        &mut errors,
    );
    let Some(mut function_symbol_counts) = errors.filled(module.functions.len(), 0usize) else {
        return errors.finish();
    };
    let Some(mut global_symbol_counts) = errors.filled(module.globals.len(), 0usize) else {
        return errors.finish();
    };
    for symbol in &module.symbols {
        if !errors.poll() {
            return errors.finish();
        }
        let Some(blank_name) = text_is_blank(&symbol.name, &mut errors) else {
            return errors.finish();
        };
        if blank_name {
            errors.push(ValidationError::InvalidRecord {
                kind: "symbol",
                id: symbol.id.0,
            });
        }
        match symbol.definition {
            SymbolDefinition::Function(id) => {
                require_id("symbol function", id.0, module.functions.len(), &mut errors);
                if let Some(count) = function_symbol_counts.get_mut(id.0 as usize) {
                    *count += 1;
                }
            }
            SymbolDefinition::Global(id) => {
                require_id("symbol global", id.0, module.globals.len(), &mut errors);
                if let Some(count) = global_symbol_counts.get_mut(id.0 as usize) {
                    *count += 1;
                }
            }
            SymbolDefinition::SectionOffset {
                section,
                offset,
                bytes,
            } => {
                require_id(
                    "symbol section",
                    section.0,
                    module.sections.len(),
                    &mut errors,
                );
                if module.sections.get(section.0 as usize).is_some_and(|item| {
                    bytes == 0
                        || offset
                            .checked_add(bytes)
                            .is_none_or(|end| end > item.reserved_bytes)
                }) {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "section symbol",
                        id: symbol.id.0,
                    });
                }
            }
            SymbolDefinition::ExternalRuntime(intrinsic) => {
                if symbol.name != intrinsic.symbol_name() {
                    errors.push(ValidationError::InvalidRuntimeSymbol { intrinsic });
                }
                if !sorted_contains(&module.runtime.intrinsics, &intrinsic, &mut errors) {
                    errors.push(ValidationError::UnexpectedRuntimeSymbol(intrinsic));
                }
            }
        }
        let expected_visibility = match symbol.definition {
            SymbolDefinition::Function(id) if id == module.image_entry => {
                SymbolVisibility::ImageEntry
            }
            SymbolDefinition::ExternalRuntime(_) => SymbolVisibility::Runtime,
            SymbolDefinition::SectionOffset { .. }
                if symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL =>
            {
                SymbolVisibility::RuntimeMetadata
            }
            SymbolDefinition::Function(_)
            | SymbolDefinition::Global(_)
            | SymbolDefinition::SectionOffset { .. } => SymbolVisibility::Private,
        };
        if symbol.visibility != expected_visibility {
            errors.push(ValidationError::InvalidSymbolVisibility(symbol.id));
        }
    }
    require_unique_names(
        "symbol",
        module.symbols.iter().map(|item| item.name.as_str()),
        &mut errors,
    );
    for intrinsic in &module.runtime.intrinsics {
        if !errors.poll() {
            return errors.finish();
        }
        let mut count = 0usize;
        for symbol in &module.symbols {
            if !errors.poll() {
                return errors.finish();
            }
            if symbol.definition == SymbolDefinition::ExternalRuntime(*intrinsic) {
                count = count.saturating_add(1);
            }
        }
        if count != 1 {
            errors.push(ValidationError::RuntimeSymbolCount {
                intrinsic: *intrinsic,
                count,
            });
        }
        let mut call_count = 0usize;
        for function in &module.functions {
            if !errors.poll() {
                return errors.finish();
            }
            for block in &function.blocks {
                if !errors.poll() {
                    return errors.finish();
                }
                for instruction in &block.instructions {
                    if !errors.poll() {
                        return errors.finish();
                    }
                    if matches!(
                        instruction.operation,
                        MachineOperation::RuntimeCall { intrinsic: called, .. }
                            if called == *intrinsic
                    ) || (*intrinsic == RuntimeIntrinsic::Fatal
                        && matches!(
                            instruction.operation,
                            MachineOperation::CheckedInteger { .. }
                                | MachineOperation::CheckedConvert { .. }
                                | MachineOperation::ActorReserve { .. }
                                | MachineOperation::MailboxReceive { .. }
                        ))
                        || (*intrinsic == RuntimeIntrinsic::TestAssertionFail
                            && matches!(instruction.operation, MachineOperation::TestAssert { .. }))
                    {
                        call_count = call_count.saturating_add(1);
                    }
                }
            }
        }
        if call_count == 0 {
            errors.push(ValidationError::UnusedRuntimeIntrinsic(*intrinsic));
        }
    }
    for global in &module.globals {
        if !errors.poll() {
            return errors.finish();
        }
        let symbol_count = global_symbol_counts
            .get(global.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if symbol_count != 1 {
            errors.push(ValidationError::DefinitionSymbolCount {
                kind: "global",
                id: global.id.0,
                count: symbol_count,
            });
        }
        require_id(
            "global symbol",
            global.symbol.0,
            module.symbols.len(),
            &mut errors,
        );
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        require_id(
            "global section",
            global.section.0,
            module.sections.len(),
            &mut errors,
        );
        if !valid_alignment(global.alignment) {
            errors.push(ValidationError::InvalidRecord {
                kind: "global",
                id: global.id.0,
            });
        }
        if module
            .symbols
            .get(global.symbol.0 as usize)
            .is_some_and(|symbol| symbol.definition != SymbolDefinition::Global(global.id))
        {
            errors.push(ValidationError::SymbolDefinitionMismatch(global.symbol));
        }
        if let (Some(ty), Some(section)) = (
            module.types.get(global.ty.0 as usize),
            module.sections.get(global.section.0 as usize),
        ) {
            let end = global.offset.checked_add(ty.size);
            if end.is_none_or(|end| end > section.reserved_bytes)
                || global.offset % u64::from(global.alignment) != 0
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "global placement",
                    id: global.id.0,
                });
            }
        }
        validate_immediate(module, &global.initializer, &mut errors);
        if !immediate_matches_type(module, &global.initializer, global.ty) {
            errors.push(ValidationError::InvalidGlobalInitializer(global.id));
        }
    }
    let Some(mut global_placements) = errors.scratch(module.globals.len()) else {
        return errors.finish();
    };
    for global in &module.globals {
        if !errors.poll() {
            return errors.finish();
        }
        if let Some(end) = module
            .types
            .get(global.ty.0 as usize)
            .and_then(|ty| global.offset.checked_add(ty.size))
        {
            if !errors.scratch_push(
                &mut global_placements,
                (global.section, global.offset, end, global.id),
            ) {
                return errors.finish();
            }
        }
    }
    if !sort_scratch_by(&mut global_placements, &mut errors, &|left, right, _| {
        Some((left.0, left.1, left.2).cmp(&(right.0, right.1, right.2)))
    }) {
        return errors.finish();
    }
    for pair in global_placements.windows(2) {
        if !errors.poll() {
            return errors.finish();
        }
        if pair[0].0 == pair[1].0 && pair[0].2 > pair[1].1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "overlapping global placement",
                id: pair[1].3.0,
            });
        }
    }
    for function in &module.functions {
        if !errors.poll() {
            return errors.finish();
        }
        let symbol_count = function_symbol_counts
            .get(function.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if symbol_count != 1 {
            errors.push(ValidationError::DefinitionSymbolCount {
                kind: "function",
                id: function.id.0,
                count: symbol_count,
            });
        }
        validate_function(module, function, &mut errors);
    }
    validate_activations(module, &mut errors);
    validate_scheduler_ownership(module, &mut errors);
    validate_region_storage(module, &mut errors);
    validate_actor_message_contract(module, &mut errors);
    validate_actor_wait_proof(module, &mut errors);
    validate_static_supervision_proof(module, &mut errors);
    validate_tests(module, &mut errors);
    validate_interrupt_entries(module, target, &mut errors);
    validate_interrupt_metadata(module, &mut errors);
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownImageEntry(module.image_entry));
    } else {
        validate_image_entry(module, target, &mut errors);
        let mut image_entry_roles = 0usize;
        for function in &module.functions {
            if !errors.poll() {
                return errors.finish();
            }
            if function.role == MachineFunctionRole::ImageEntry {
                image_entry_roles = image_entry_roles.saturating_add(1);
            }
        }
        if module.functions[module.image_entry.0 as usize].role != MachineFunctionRole::ImageEntry
            || image_entry_roles != 1
        {
            errors.push(ValidationError::InvalidImageEntry(module.image_entry));
        }
    }
    errors.finish()
}

fn validate_target_and_layout(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut ValidationContext<'_>,
) {
    let backend = target.backend();
    let text_pairs = [
        (
            module.target.identity.as_str(),
            module.build.target.as_str(),
        ),
        (module.target.llvm_triple.as_str(), backend.llvm_triple()),
        (module.target.coff_machine.as_str(), backend.coff_machine()),
        (module.target.cpu.as_str(), backend.llvm_cpu()),
        (
            module.target.data_layout.as_str(),
            backend.llvm_data_layout(),
        ),
    ];
    let mut target_text_matches = true;
    for (actual, expected) in text_pairs {
        let Some(matches) = text_equals(actual, expected, errors) else {
            return;
        };
        target_text_matches &= matches;
    }
    let expected_features = backend.llvm_features();
    let mut features_match = module.target.features.len() == expected_features.len();
    for (actual, expected) in module.target.features.iter().zip(expected_features) {
        let Some(matches) = text_equals(actual, expected, errors) else {
            return;
        };
        features_match &= matches;
    }
    if target.identity() != &module.build.target
        || target.semantic().content_digest() != module.build.target_package
        || !target_text_matches
        || !features_match
    {
        errors.push(ValidationError::InvalidAarch64Target);
    }
    let layout = &module.layout;
    if layout.pointer_bits != 64
        || !valid_alignment(layout.pointer_alignment)
        || !valid_alignment(layout.stack_alignment)
        || !valid_alignment(layout.aggregate_alignment)
        || !valid_alignment(layout.maximum_object_alignment)
        || layout.pointer_alignment > layout.maximum_object_alignment
        || layout.aggregate_alignment > layout.maximum_object_alignment
        || layout.stack_alignment < 16
    {
        errors.push(ValidationError::InvalidDataLayout);
    }
}

fn validate_type(module: &MachineWir, ty: &MachineType, errors: &mut ValidationContext<'_>) {
    if !valid_alignment(ty.alignment)
        || ty.alignment > module.layout.maximum_object_alignment
        || (ty.size != 0 && ty.size % u64::from(ty.alignment) != 0)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "machine type layout",
            id: ty.id.0,
        });
    }
    match &ty.kind {
        MachineTypeKind::Void => {
            if ty.size != 0 {
                errors.push(ValidationError::InvalidRecord {
                    kind: "void type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Integer { bits } => {
            if *bits == 0 || *bits > 128 || u64::from(*bits).div_ceil(8) > ty.size {
                errors.push(ValidationError::InvalidRecord {
                    kind: "integer type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Float32 => require_minimum_size(ty, 4, errors),
        MachineTypeKind::Float64 => require_minimum_size(ty, 8, errors),
        MachineTypeKind::Pointer { pointee, .. } => {
            if ty.size != u64::from(module.layout.pointer_bits / 8) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "pointer type",
                    id: ty.id.0,
                });
            }
            if let Some(pointee) = pointee {
                require_id("pointer pointee", pointee.0, module.types.len(), errors);
            }
        }
        MachineTypeKind::Vector { element, lanes } => {
            require_id("vector element", element.0, module.types.len(), errors);
            if *lanes == 0 {
                errors.push(ValidationError::InvalidRecord {
                    kind: "vector type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Array { element, .. } => {
            require_id("array element", element.0, module.types.len(), errors)
        }
        MachineTypeKind::Struct { fields, packed } => {
            let mut previous_end = 0_u64;
            let mut aggregate_alignment = 1_u32;
            for field in fields {
                if !errors.poll() {
                    return;
                }
                require_id("struct field type", field.ty.0, module.types.len(), errors);
                if let Some(field_ty) = module.types.get(field.ty.0 as usize) {
                    let field_alignment = if *packed { 1 } else { field_ty.alignment };
                    let alignment = u64::from(field_alignment);
                    let expected_offset = previous_end
                        .checked_add(alignment - 1)
                        .map(|offset| offset & !(alignment - 1));
                    let end = field.offset.checked_add(field_ty.size);
                    if expected_offset != Some(field.offset) || end.is_none_or(|end| end > ty.size)
                    {
                        errors.push(ValidationError::InvalidRecord {
                            kind: "struct field",
                            id: ty.id.0,
                        });
                    }
                    previous_end = end.unwrap_or(u64::MAX);
                    aggregate_alignment = aggregate_alignment.max(field_alignment);
                }
            }
            let alignment = u64::from(aggregate_alignment);
            let expected_size = previous_end
                .checked_add(alignment - 1)
                .map(|size| size & !(alignment - 1));
            if ty.alignment != aggregate_alignment || expected_size != Some(ty.size) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "struct layout",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::TaggedEnum {
            tag,
            payload,
            variants,
            payload_variants,
        } => {
            require_id("tagged enum tag type", tag.0, module.types.len(), errors);
            if let Some(payload) = payload {
                require_id(
                    "tagged enum payload type",
                    payload.0,
                    module.types.len(),
                    errors,
                );
            }
            let tag_valid = module.types.get(tag.0 as usize).is_some_and(|tag| {
                tag.kind == MachineTypeKind::Integer { bits: 8 }
                    && tag.size == 1
                    && tag.alignment == 1
            });
            let payload_valid = payload.is_some_and(|payload| {
                module.types.get(payload.0 as usize).is_some_and(|payload| {
                    let expected = match payload.kind {
                        MachineTypeKind::Integer {
                            bits: 8 | 16 | 32 | 64 | 128,
                        } => {
                            let MachineTypeKind::Integer { bits } = payload.kind else {
                                unreachable!();
                            };
                            let bytes = u64::from(bits / 8);
                            Some((bytes, u32::try_from(bytes.min(16)).unwrap_or(0)))
                        }
                        MachineTypeKind::Float32 => Some((4, 4)),
                        MachineTypeKind::Float64 => Some((8, 8)),
                        _ => None,
                    };
                    expected == Some((payload.size, payload.alignment))
                })
            });
            let layout_valid = payload.is_some_and(|payload| {
                module.types.get(payload.0 as usize).is_some_and(|payload| {
                    let alignment = payload.alignment.max(1);
                    let offset = (1_u64 + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
                    offset
                        .checked_add(payload.size)
                        .map(|size| (size + u64::from(alignment) - 1) & !(u64::from(alignment) - 1))
                        == Some(ty.size)
                        && ty.alignment == alignment
                })
            });
            let has_payload = payload_variants.iter().any(|present| *present);
            let representation_valid = if has_payload {
                payload.is_some() && payload_valid && layout_valid
            } else {
                payload.is_none() && ty.size == 1 && ty.alignment == 1
            };
            if *variants == 0
                || *variants > 256
                || usize::from(*variants) != payload_variants.len()
                || !tag_valid
                || !representation_valid
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "tagged enum type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Function { parameters, result } => {
            for parameter in parameters {
                if !errors.poll() {
                    return;
                }
                require_id(
                    "function parameter type",
                    parameter.0,
                    module.types.len(),
                    errors,
                );
            }
            require_id("function result type", result.0, module.types.len(), errors);
        }
    }
}

fn require_minimum_size(ty: &MachineType, minimum: u64, errors: &mut ValidationContext<'_>) {
    if ty.size < minimum {
        errors.push(ValidationError::InvalidRecord {
            kind: "floating type",
            id: ty.id.0,
        });
    }
}

fn validate_immediate(
    module: &MachineWir,
    immediate: &MachineImmediate,
    errors: &mut ValidationContext<'_>,
) {
    match immediate {
        MachineImmediate::Integer { ty, .. }
        | MachineImmediate::Null(ty)
        | MachineImmediate::Zero(ty) => {
            require_id("immediate type", ty.0, module.types.len(), errors);
        }
        MachineImmediate::SymbolAddress(symbol) => {
            require_id("immediate symbol", symbol.0, module.symbols.len(), errors)
        }
        MachineImmediate::Float32(_)
        | MachineImmediate::Float64(_)
        | MachineImmediate::Bytes(_) => {}
    }
}

fn validate_function(
    module: &MachineWir,
    function: &MachineFunction,
    errors: &mut ValidationContext<'_>,
) {
    require_id(
        "function symbol",
        function.symbol.0,
        module.symbols.len(),
        errors,
    );
    require_id(
        "function section",
        function.section.0,
        module.sections.len(),
        errors,
    );
    require_id(
        "function result type",
        function.result.0,
        module.types.len(),
        errors,
    );
    for proof in &function.proofs {
        if !errors.poll() {
            return;
        }
        require_id("function proof", proof.0, module.proofs.len(), errors);
    }
    if function.proofs.windows(2).any(|pair| pair[0] >= pair[1]) {
        errors.push(ValidationError::InvalidRecord {
            kind: "function proof attachments",
            id: function.id.0,
        });
    }
    if module
        .symbols
        .get(function.symbol.0 as usize)
        .is_some_and(|symbol| symbol.definition != SymbolDefinition::Function(function.id))
    {
        errors.push(ValidationError::SymbolDefinitionMismatch(function.symbol));
    }
    let valid_origin = match function.origin {
        MachineFunctionOrigin::SourceSemantic { .. } => {
            function.source.is_some() && function.role != MachineFunctionRole::ImageEntry
        }
        MachineFunctionOrigin::GeneratedImageEntry { .. }
        | MachineFunctionOrigin::GeneratedTestHarness { .. } => {
            function.source.is_none() && function.role == MachineFunctionRole::ImageEntry
        }
        MachineFunctionOrigin::GeneratedAsyncState { .. } => {
            function.role != MachineFunctionRole::ImageEntry
        }
        MachineFunctionOrigin::GeneratedCleanup { .. } => {
            function.role != MachineFunctionRole::ImageEntry
        }
    };
    if !valid_origin {
        errors.push(ValidationError::InvalidFunctionOrigin(function.id));
    }
    if module
        .sections
        .get(function.section.0 as usize)
        .is_some_and(|section| section.kind != SectionKind::Code)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "function code section",
            id: function.id.0,
        });
    }
    if function.id != module.image_entry {
        let valid_abi = match (function.linkage, function.convention) {
            (Linkage::Private, CallingConvention::Internal | CallingConvention::Aapcs64)
            | (Linkage::Private, CallingConvention::InterruptHandler)
            | (Linkage::InternalRuntime, CallingConvention::Aapcs64) => true,
            (Linkage::Private | Linkage::InternalRuntime, CallingConvention::UefiAarch64)
            | (Linkage::InternalRuntime, CallingConvention::Internal)
            | (Linkage::InternalRuntime, CallingConvention::InterruptHandler)
            | (Linkage::ExportedEntry, _) => false,
        };
        if !valid_abi {
            errors.push(ValidationError::InvalidFunctionAbi(function.id));
        }
    }
    check_dense(
        "value",
        function.values.iter().map(|item| item.id.0),
        errors,
    );
    check_dense(
        "stack slot",
        function.stack_slots.iter().map(|item| item.id.0),
        errors,
    );
    check_dense(
        "block",
        function.blocks.iter().map(|item| item.id.0),
        errors,
    );
    for value in &function.values {
        if !errors.poll() {
            return;
        }
        require_id("value type", value.ty.0, module.types.len(), errors);
        if module
            .types
            .get(value.ty.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void))
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "void machine SSA value",
                id: value.id.0,
            });
        }
    }
    for slot in &function.stack_slots {
        if !errors.poll() {
            return;
        }
        if !valid_alignment(slot.alignment)
            || slot.alignment > module.layout.stack_alignment
            || slot.size > function.stack_bytes
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "stack slot",
                id: slot.id.0,
            });
        }
    }
    if function.stack_bytes % u64::from(module.layout.stack_alignment) != 0 {
        errors.push(ValidationError::InvalidRecord {
            kind: "function stack",
            id: function.id.0,
        });
    }
    require_id(
        "function entry block",
        function.entry.0,
        function.blocks.len(),
        errors,
    );
    if function
        .blocks
        .get(function.entry.0 as usize)
        .is_some_and(|entry| !entry.parameters.is_empty())
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "function entry block parameters",
            id: function.id.0,
        });
    }
    let Some(mut definitions) = errors.filled(function.values.len(), 0u8) else {
        return;
    };
    for value in &function.parameters {
        if !errors.poll() {
            return;
        }
        define_value(function.id, *value, &mut definitions, errors);
    }
    let mut instruction_count = 0usize;
    for block in &function.blocks {
        if !errors.poll() {
            return;
        }
        let Some(next) = instruction_count.checked_add(block.instructions.len()) else {
            errors.allocation_failure =
                Some(("validation scratch entries", errors.limits.model_edges));
            return;
        };
        instruction_count = next;
    }
    let Some(mut instruction_ids) = errors.scratch(instruction_count) else {
        return;
    };
    for block in &function.blocks {
        if !errors.poll() {
            return;
        }
        for value in &block.parameters {
            if !errors.poll() {
                return;
            }
            define_value(function.id, *value, &mut definitions, errors);
        }
        for (index, instruction) in block.instructions.iter().enumerate() {
            if !errors.poll() || !errors.scratch_push(&mut instruction_ids, instruction.id.0) {
                return;
            }
            for value in &instruction.results {
                if !errors.poll() {
                    return;
                }
                define_value(function.id, *value, &mut definitions, errors);
            }
            validate_operation(module, function, instruction, errors);
            if matches!(
                instruction.operation,
                MachineOperation::RuntimeCall { intrinsic, .. }
                    if !intrinsic.signature().may_return
            ) && (index + 1 != block.instructions.len()
                || !matches!(block.terminator, MachineTerminator::Unreachable))
            {
                errors.push(ValidationError::NonReturningRuntimeFallthrough {
                    function: function.id,
                    instruction: instruction.id,
                });
            }
        }
        validate_terminator(module, function, &block.terminator, errors);
    }
    check_dense("instruction", instruction_ids, errors);
    for (index, count) in definitions.into_iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if count != 1 {
            errors.push(ValidationError::ValueDefinitionCount {
                function: function.id,
                value: ValueId(index as u32),
                definitions: count,
            });
        }
    }
    validate_control_flow_and_ssa(module, function, errors);
    validate_generated_runtime_contract(module, function, errors);
}

#[derive(Clone, Copy)]
struct ActorReserveRecord {
    function: FunctionId,
    instruction: InstructionId,
    reservation: ValueId,
    mailbox: GlobalId,
    actor: u32,
    method: FunctionId,
    proof: ProofId,
    failure: ScalarFailureProvenance,
    source: Span,
}

#[derive(Clone, Copy)]
struct ActorReceiveRecord {
    function: FunctionId,
    instruction: InstructionId,
    mailbox: GlobalId,
    actor: u32,
    method: FunctionId,
    failure: ScalarFailureProvenance,
}

#[derive(Clone, Copy)]
struct ActorDispatchRecord {
    mailbox: GlobalId,
    actor: u32,
    method: FunctionId,
}

fn validate_actor_wait_proof(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let has_actor = module
        .functions
        .iter()
        .any(|function| matches!(function.role, MachineFunctionRole::ActorTurn(_)))
        || module
            .region_storage
            .iter()
            .any(|storage| matches!(storage.kind, MachineRegionStorageKind::ActorMailbox { .. }));
    if !has_actor {
        return;
    }
    let mut wait_proof = None;
    for proof in &module.proofs {
        if !errors.poll() {
            return;
        }
        if proof.kind == BackendProofKind::WaitGraphAcyclic
            && wait_proof.replace(proof.id).is_some()
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor wait proof",
                id: proof.id.0,
            });
        }
    }
    if wait_proof.is_none() {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor wait proof",
            id: 0,
        });
    }
}

fn validate_static_supervision_proof(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let actor_count = module
        .region_storage
        .iter()
        .filter(|storage| matches!(storage.kind, MachineRegionStorageKind::ActorMailbox { .. }))
        .count();
    if actor_count == 0 {
        return;
    }
    let task_count = module
        .region_storage
        .iter()
        .filter(|storage| {
            matches!(
                storage.kind,
                MachineRegionStorageKind::TaskEntryFrame { .. }
            )
        })
        .count();
    let mut supervision = None;
    let mut image_closed = None;
    for proof in &module.proofs {
        if !errors.poll() {
            return;
        }
        match proof.kind {
            BackendProofKind::SupervisionComplete if supervision.is_some() => {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor supervision proof",
                    id: proof.id.0,
                });
            }
            BackendProofKind::SupervisionComplete => supervision = Some(proof),
            BackendProofKind::ImageClosed => image_closed = Some(proof),
            _ => {}
        }
    }
    let Some(proof) = supervision else {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor supervision proof",
            id: 0,
        });
        return;
    };
    let mut source_index = 0usize;
    let mut topology_matches = true;
    for storage in &module.region_storage {
        if !errors.poll() {
            return;
        }
        if matches!(storage.kind, MachineRegionStorageKind::ActorMailbox { .. }) {
            topology_matches &= proof.sources.get(source_index) == Some(&storage.source);
            source_index = source_index.saturating_add(1);
        }
    }
    for storage in &module.region_storage {
        if !errors.poll() {
            return;
        }
        let MachineRegionStorageKind::TaskEntryFrame { task, .. } = storage.kind else {
            continue;
        };
        topology_matches &= proof.sources.get(source_index) == Some(&storage.source);
        source_index = source_index.saturating_add(1);
        let task_activation = module.activations.iter().find(|activation| {
            matches!(
                activation.owner,
                MachineActivationOwner::Task {
                    task: owner_task,
                    ..
                } if owner_task == task
            )
        });
        let parent_matches = task_activation.map_or_else(
            || {
                module
                    .functions
                    .iter()
                    .filter(|function| function.role == MachineFunctionRole::TaskEntry(task))
                    .count()
                    == 1
            },
            |activation| {
                matches!(
                    activation.owner,
                    MachineActivationOwner::Task {
                        supervisor: Some(actor),
                        ..
                    } if module.region_storage.iter().any(|candidate| {
                        matches!(candidate.kind,
                            MachineRegionStorageKind::ActorMailbox {
                                actor: candidate_actor,
                                ..
                            } if candidate_actor == actor)
                    })
                )
            },
        );
        topology_matches &= parent_matches;
    }
    let exact_bound = actor_count
        .checked_add(task_count)
        .and_then(|count| u64::try_from(count).ok());
    let entry_has_proof = module
        .functions
        .get(module.image_entry.0 as usize)
        .is_some_and(|entry| entry.proofs.contains(&proof.id));
    let closure_reaches = image_closed.is_some_and(|closed| {
        closed.depends_on.contains(&proof.id)
            || closed.depends_on.iter().any(|dependency| {
                module
                    .proofs
                    .get(dependency.0 as usize)
                    .is_some_and(|parent| parent.depends_on.contains(&proof.id))
            })
    });
    let typed_dependency = proof.depends_on.as_slice() == [ProofId(0)]
        && module.proofs.first().is_some_and(|typed| {
            typed.id == ProofId(0) && typed.kind == BackendProofKind::TypeChecked
        });
    if proof.source_proofs.as_slice() != [proof.id.0]
        || proof.bound != exact_bound
        || proof.sources.len() != source_index
        || !topology_matches
        || !typed_dependency
        || !entry_has_proof
        || !closure_reaches
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor supervision proof",
            id: proof.id.0,
        });
    }
}

fn validate_actor_message_contract(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let startup_success = module
        .functions
        .get(module.image_entry.0 as usize)
        .and_then(|entry| entry.blocks.get(entry.entry.0 as usize))
        .and_then(|prologue| match &prologue.terminator {
            MachineTerminator::Switch { cases, .. } => match cases.as_slice() {
                [(0, success, arguments)] if arguments.is_empty() => Some(*success),
                _ => None,
            },
            _ => None,
        });
    let mut reserve_count = 0_u8;
    let mut commit_count = 0_u8;
    let mut receive_count = 0_u8;
    let mut dispatch_count = 0_u8;
    let Some(mut reserves) = errors.scratch(2) else {
        return;
    };
    let Some(mut receives) = errors.scratch(2) else {
        return;
    };
    let mut dispatch = None;
    let mut reply_request = None;
    let mut reply_resolve = None;

    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        for block in &function.blocks {
            if !errors.poll() {
                return;
            }
            for (index, instruction) in block.instructions.iter().enumerate() {
                if !errors.poll() {
                    return;
                }
                match &instruction.operation {
                    MachineOperation::ActorReserve {
                        mailbox,
                        actor,
                        method,
                        proof,
                        failure,
                    } => {
                        reserve_count = reserve_count.saturating_add(1);
                        let source = instruction.source;
                        let result = instruction.results.first().copied();
                        let adjacent_commit = block.instructions.get(index.saturating_add(1));
                        let fixed = instruction.results.len() == 1
                            && match function.role {
                                MachineFunctionRole::TaskEntry(_) => true,
                                MachineFunctionRole::ActorTurn(owner) => owner == *actor,
                                _ => false,
                            }
                            && source.is_some()
                            && failure.kind == ScalarFailureKind::ActorMailboxFull
                            && failure.flow_function == function.flow_function
                            && failure.flow_instruction == instruction.id.0
                            && matches!(
                                (result, adjacent_commit),
                                (
                                    Some(reservation),
                                    Some(MachineInstruction {
                                        results,
                                        operation: MachineOperation::ActorCommit {
                                            reservation: committed,
                                            mailbox: commit_mailbox,
                                            actor: commit_actor,
                                            method: commit_method,
                                        },
                                        source: commit_source,
                                        ..
                                    })
                                ) if results.is_empty()
                                    && *committed == reservation
                                    && *commit_mailbox == *mailbox
                                    && *commit_actor == *actor
                                    && *commit_method == *method
                                    && *commit_source == source
                            );
                        if reserves.len() >= 2 || !fixed {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor mailbox reserve contract",
                                id: instruction.id.0,
                            });
                        } else if let (Some(reservation), Some(source)) = (result, source) {
                            reserves.push(ActorReserveRecord {
                                function: function.id,
                                instruction: instruction.id,
                                reservation,
                                mailbox: *mailbox,
                                actor: *actor,
                                method: *method,
                                proof: *proof,
                                failure: *failure,
                                source,
                            });
                        }
                    }
                    MachineOperation::ActorCommit {
                        reservation,
                        mailbox,
                        actor,
                        method,
                    } => {
                        commit_count = commit_count.saturating_add(1);
                        let prior = index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        if !instruction.results.is_empty()
                            || !matches!(prior,
                                Some(MachineInstruction {
                                    results,
                                    operation: MachineOperation::ActorReserve {
                                        mailbox: reserve_mailbox,
                                        actor: reserve_actor,
                                        method: reserve_method,
                                        ..
                                    },
                                    source: reserve_source,
                                    ..
                                }) if results.as_slice() == [*reservation]
                                    && *reserve_mailbox == *mailbox
                                    && *reserve_actor == *actor
                                    && *reserve_method == *method
                                    && *reserve_source == instruction.source)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor mailbox commit contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    MachineOperation::MailboxReceive {
                        mailbox,
                        actor,
                        method,
                        failure,
                    } => {
                        receive_count = receive_count.saturating_add(1);
                        let fixed = instruction.results.is_empty()
                            && block.id == function.entry
                            && index == 0
                            && function.id == *method
                            && function.role == MachineFunctionRole::ActorTurn(*actor)
                            && instruction.source.is_some()
                            && failure.kind == ScalarFailureKind::ActorMailboxMismatch
                            && failure.flow_function == function.flow_function
                            && failure.flow_instruction == instruction.id.0;
                        if receives.len() >= 2 || !fixed {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor mailbox receive contract",
                                id: instruction.id.0,
                            });
                        } else {
                            receives.push(ActorReceiveRecord {
                                function: function.id,
                                instruction: instruction.id,
                                mailbox: *mailbox,
                                actor: *actor,
                                method: *method,
                                failure: *failure,
                            });
                        }
                    }
                    MachineOperation::MailboxDispatch {
                        mailbox,
                        actor,
                        method,
                    } => {
                        dispatch_count = dispatch_count.saturating_add(1);
                        let prior = index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        let fixed = instruction.results.is_empty()
                            && instruction.source.is_none()
                            && function.id == module.image_entry
                            && Some(block.id) == startup_success
                            && index == 1
                            && matches!(prior,
                                Some(MachineInstruction {
                                    results,
                                    operation: MachineOperation::Call {
                                        arguments,
                                        convention: CallingConvention::Internal,
                                        ..
                                    },
                                    source: None,
                                    ..
                                }) if results.is_empty() && arguments.is_empty());
                        if dispatch.is_some() || !fixed {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor mailbox dispatch contract",
                                id: instruction.id.0,
                            });
                        } else {
                            dispatch = Some(ActorDispatchRecord {
                                mailbox: *mailbox,
                                actor: *actor,
                                method: *method,
                            });
                        }
                    }
                    MachineOperation::ActorReplyRequest {
                        slot,
                        mailbox,
                        actor,
                        method,
                        permit,
                        reply,
                        failure,
                        duplicate_failure,
                    } => {
                        let fixed = instruction.results.len() == 1
                            && matches!(function.role, MachineFunctionRole::TaskEntry(_))
                            && instruction.source.is_some()
                            && failure.kind == ScalarFailureKind::ActorReplyStateMismatch
                            && duplicate_failure.kind
                                == ScalarFailureKind::ActorReplyDuplicateResolve
                            && failure.flow_function == function.flow_function
                            && duplicate_failure.flow_function == function.flow_function
                            && failure.flow_instruction == instruction.id.0
                            && duplicate_failure.flow_instruction == instruction.id.0
                            && function
                                .stack_slots
                                .get(slot.0 as usize)
                                .is_some_and(|slot| slot.size == 16 && slot.alignment == 8);
                        if !fixed
                            || reply_request
                                .replace((
                                    function.id,
                                    *mailbox,
                                    *actor,
                                    *method,
                                    *permit,
                                    *reply,
                                    instruction.source,
                                ))
                                .is_some()
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reply request contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    MachineOperation::ActorReplyResolve { outcome, reply } => {
                        let fixed = instruction.results.is_empty()
                            && matches!(function.role, MachineFunctionRole::ActorTurn(_))
                            && function
                                .values
                                .get(outcome.0 as usize)
                                .is_some_and(|value| {
                                    module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                                        ty.kind == MachineTypeKind::Integer { bits: 64 }
                                    })
                                });
                        if !fixed || reply_resolve.replace((function.id, *reply)).is_some() {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reply resolve contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some((producer, mailbox, actor, method, permit, reply, source)) = reply_request {
        let startup_calls_producer = startup_success
            .and_then(|success| {
                module
                    .functions
                    .get(module.image_entry.0 as usize)
                    .and_then(|entry| entry.blocks.get(success.0 as usize))
            })
            .is_some_and(|block| {
                matches!(block.instructions.first(), Some(MachineInstruction {
                    results,
                    operation: MachineOperation::Call {
                        function,
                        arguments,
                        convention: CallingConvention::Internal,
                    },
                    source: None,
                    ..
                }) if results.is_empty() && arguments.is_empty() && *function == producer)
            });
        let storage_matches = module.region_storage.iter().any(|storage| {
            storage.global == mailbox
                && storage.kind
                    == MachineRegionStorageKind::ActorMailbox {
                        actor,
                        mailbox_capacity: 1,
                    }
                && storage.capacity_bytes == 16
                && storage.alignment == 8
        });
        let permit_matches = module.proofs.get(permit.0 as usize).is_some_and(|proof| {
            proof.kind == BackendProofKind::CapacityBound
                && proof.bound == Some(1)
                && proof.source == source
        });
        let reply_matches = module.proofs.get(reply.0 as usize).is_some_and(|proof| {
            proof.kind == BackendProofKind::ActorReplyExactlyOnce
                && proof.bound == Some(1)
                && proof.depends_on.contains(&permit)
                && proof.source == source
        });
        let target_matches = module
            .functions
            .get(method.0 as usize)
            .is_some_and(|target| {
                target.role == MachineFunctionRole::ActorTurn(actor)
                    && target.parameters.is_empty()
                    && module
                        .types
                        .get(target.result.0 as usize)
                        .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 64 })
            });
        if reserve_count != 0
            || commit_count != 0
            || receive_count != 1
            || dispatch_count != 0
            || receives.first().is_none_or(|receive| {
                receive.mailbox != mailbox || receive.actor != actor || receive.method != method
            })
            || reply_resolve != Some((method, reply))
            || !startup_calls_producer
            || !storage_matches
            || !permit_matches
            || !reply_matches
            || !target_matches
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor reply message contract",
                id: 0,
            });
        }
        return;
    }

    if reserve_count == 0 && commit_count == 0 && receive_count == 0 && dispatch_count == 0 {
        for activation in &module.activations {
            if !errors.poll() {
                return;
            }
            if activation.schedule == MachineActivationSchedule::MailboxOnce {
                errors.push(ValidationError::InvalidActivationPlan(activation.id));
            }
        }
        return;
    }

    let single = matches!(
        (reserves.as_slice(), receives.as_slice(), dispatch),
        ([reserve], [receive], Some(dispatch))
            if reserve_count == 1
                && commit_count == 1
                && receive_count == 1
                && dispatch_count == 1
                && reserve.mailbox == receive.mailbox
                && reserve.mailbox == dispatch.mailbox
                && reserve.actor == receive.actor
                && reserve.actor == dispatch.actor
                && reserve.method == receive.method
                && reserve.method == dispatch.method
                && receive.function == reserve.method
                && receive.instruction.0 == receive.failure.flow_instruction
                && reserve.instruction.0 == reserve.failure.flow_instruction
    );
    let recurring = matches!(
        (reserves.as_slice(), dispatch),
        ([left, right], Some(dispatch))
            if reserve_count == 2
                && commit_count == 2
                && receive_count == 2
                && dispatch_count == 1
                && {
                    let (startup, turn) = if matches!(
                        module.functions.get(left.function.0 as usize).map(|function| function.role),
                        Some(MachineFunctionRole::TaskEntry(_))
                    ) { (left, right) } else { (right, left) };
                    startup.actor == turn.actor
                        && startup.mailbox == turn.mailbox
                        && startup.mailbox == dispatch.mailbox
                        && startup.actor == dispatch.actor
                        && startup.method == dispatch.method
                        && startup.method == turn.function
                        && startup.method != turn.method
                        && receives.iter().all(|receive| {
                            receive.mailbox == startup.mailbox
                                && receive.actor == startup.actor
                                && receive.function == receive.method
                                && receive.instruction.0 == receive.failure.flow_instruction
                        })
                        && receives.iter().any(|receive| receive.method == startup.method)
                        && receives.iter().any(|receive| receive.method == turn.method)
                        && left.instruction.0 == left.failure.flow_instruction
                        && right.instruction.0 == right.failure.flow_instruction
                }
    );
    if !single && !recurring {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            id: 0,
        });
        return;
    }
    let Some(reserve) = reserves.iter().find(|reserve| {
        matches!(
            module
                .functions
                .get(reserve.function.0 as usize)
                .map(|function| function.role),
            Some(MachineFunctionRole::TaskEntry(_))
        )
    }) else {
        return;
    };

    let mut storage = None;
    for candidate in &module.region_storage {
        if !errors.poll() {
            return;
        }
        if candidate.global == reserve.mailbox && storage.replace(candidate).is_some() {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor mailbox storage contract",
                id: reserve.mailbox.0,
            });
        }
    }
    let storage_matches = storage.is_some_and(|storage| {
        storage.kind
            == (MachineRegionStorageKind::ActorMailbox {
                actor: reserve.actor,
                mailbox_capacity: 1,
            })
            && storage.capacity_units == 1
            && storage.bytes_per_unit == 16
            && storage.capacity_bytes == 16
            && storage.alignment == 8
    });
    let mut all_reserves_match = storage_matches;
    for candidate in &reserves {
        if !errors.poll() {
            return;
        }
        let proof_matches = storage
            .and_then(|storage| {
                module
                    .proofs
                    .get(candidate.proof.0 as usize)
                    .map(|proof| (storage, proof))
            })
            .is_some_and(|(storage, proof)| {
                candidate.mailbox == reserve.mailbox
                    && candidate.actor == reserve.actor
                    && proof.kind == BackendProofKind::CapacityBound
                    && proof.source_proofs.as_slice() == [candidate.proof.0]
                    && proof.depends_on.as_slice() == [storage.capacity_proof]
                    && proof.bound == Some(1)
                    && proof.sources.as_slice() == [candidate.source]
                    && proof.source == Some(candidate.source)
            });
        let producer_matches = module
            .functions
            .get(candidate.function.0 as usize)
            .is_some_and(|producer| producer.proofs.contains(&candidate.proof));
        let target_matches = module
            .functions
            .get(candidate.method.0 as usize)
            .is_some_and(|target| {
                target.id == candidate.method
                    && target.role == MachineFunctionRole::ActorTurn(candidate.actor)
                    && target.parameters.is_empty()
                    && module
                        .types
                        .get(target.result.0 as usize)
                        .is_some_and(|ty| ty.kind == MachineTypeKind::Void)
            });
        let mut uses = 0_u8;
        let mut escaped = false;
        if let Some(producer) = module.functions.get(candidate.function.0 as usize) {
            for block in &producer.blocks {
                if !errors.poll() {
                    return;
                }
                for instruction in &block.instructions {
                    if !errors.poll() {
                        return;
                    }
                    let expected_commit = matches!(
                        instruction.operation,
                        MachineOperation::ActorCommit { reservation, .. }
                            if reservation == candidate.reservation
                    );
                    for_each_operation_value(&instruction.operation, |value| {
                        if value == candidate.reservation {
                            uses = uses.saturating_add(1);
                            escaped |= !expected_commit;
                        }
                        true
                    });
                }
                for_each_terminator_value(&block.terminator, |value| {
                    escaped |= value == candidate.reservation;
                    true
                });
            }
        }
        all_reserves_match &=
            proof_matches && producer_matches && target_matches && uses == 1 && !escaped;
    }
    let permit_matches = storage
        .and_then(|storage| {
            module
                .proofs
                .get(reserve.proof.0 as usize)
                .map(|proof| (storage, proof))
        })
        .is_some_and(|(storage, proof)| {
            proof.kind == BackendProofKind::CapacityBound
                && proof.source_proofs.as_slice() == [reserve.proof.0]
                && proof.depends_on.as_slice() == [storage.capacity_proof]
                && proof.bound == Some(1)
                && proof.sources.as_slice() == [reserve.source]
                && proof.source == Some(reserve.source)
        });
    let mut producer_has_permit = false;
    if let Some(producer) = module.functions.get(reserve.function.0 as usize) {
        for proof in &producer.proofs {
            if !errors.poll() {
                return;
            }
            producer_has_permit |= *proof == reserve.proof;
        }
    }
    let target_matches = module
        .functions
        .get(reserve.method.0 as usize)
        .is_some_and(|target| {
            target.id == reserve.method
                && target.role == MachineFunctionRole::ActorTurn(reserve.actor)
                && target.parameters.is_empty()
                && module
                    .types
                    .get(target.result.0 as usize)
                    .is_some_and(|ty| ty.kind == MachineTypeKind::Void)
        });
    let mut actor_activation_count = 0_u8;
    let mut task_activation_count = 0_u8;
    let recurring_methods = recurring.then(|| {
        let continuation = reserves
            .iter()
            .find(|candidate| candidate.function != reserve.function)
            .map(|candidate| candidate.method)
            .unwrap_or(reserve.method);
        (reserve.method, continuation)
    });
    let mut first_fifo = 0_u8;
    let mut second_fifo = 0_u8;
    let mut fifo_callers_match = true;
    for activation in &module.activations {
        if !errors.poll() {
            return;
        }
        if matches!(activation.owner, MachineActivationOwner::Actor { actor, mailbox_capacity: 1 }
                if actor == reserve.actor)
            && ((single
                && activation.caller == reserve.method
                && activation.schedule == MachineActivationSchedule::MailboxOnce)
                || (recurring && activation.schedule == MachineActivationSchedule::SchedulerFifo))
        {
            actor_activation_count = actor_activation_count.saturating_add(1);
            if let Some((first, second)) = recurring_methods {
                if activation.caller == first {
                    first_fifo = first_fifo.saturating_add(1);
                } else if activation.caller == second {
                    second_fifo = second_fifo.saturating_add(1);
                } else {
                    fifo_callers_match = false;
                }
            }
        }
        if activation.caller == reserve.function
            && activation.schedule == MachineActivationSchedule::StartupOnce
            && matches!(activation.owner,
            MachineActivationOwner::Task { supervisor: Some(actor), .. }
                if actor == reserve.actor
                    || (reserve.actor == 0
                        && actor == 1
                        && module.region_storage.iter().any(|storage| {
                            storage.kind == (MachineRegionStorageKind::ActorMailbox {
                                actor: 1,
                                mailbox_capacity: 1,
                            })
                        })))
        {
            task_activation_count = task_activation_count.saturating_add(1);
        }
    }

    let mut reservation_uses = 0_u8;
    if let Some(producer) = module.functions.get(reserve.function.0 as usize) {
        for block in &producer.blocks {
            if !errors.poll() {
                return;
            }
            for instruction in &block.instructions {
                if !errors.poll() {
                    return;
                }
                let expected_commit = matches!(instruction.operation,
                    MachineOperation::ActorCommit { reservation, .. }
                        if reservation == reserve.reservation);
                let mut escaped = false;
                let mut cancelled = false;
                for_each_operation_value(&instruction.operation, |value| {
                    if !cancelled && !errors.poll() {
                        cancelled = true;
                        return false;
                    }
                    if value == reserve.reservation {
                        reservation_uses = reservation_uses.saturating_add(1);
                        escaped |= !expected_commit;
                    }
                    true
                });
                if cancelled {
                    return;
                }
                if escaped {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "actor reservation escape",
                        id: reserve.reservation.0,
                    });
                }
            }
            let mut escaped = false;
            let mut cancelled = false;
            for_each_terminator_value(&block.terminator, |value| {
                if !cancelled && !errors.poll() {
                    cancelled = true;
                    return false;
                }
                escaped |= value == reserve.reservation;
                true
            });
            if cancelled {
                return;
            }
            if escaped {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reservation escape",
                    id: reserve.reservation.0,
                });
            }
        }
    }
    if !all_reserves_match
        || !storage_matches
        || !permit_matches
        || !producer_has_permit
        || !target_matches
        || actor_activation_count != if recurring { 2 } else { 1 }
        || (recurring && (!fifo_callers_match || first_fifo != 1 || second_fifo != 1))
        || task_activation_count != 1
        || reservation_uses != 1
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            id: reserve.method.0,
        });
    }
}

fn validate_activations(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let Some(mut caller_counts) = errors.filled(module.functions.len(), 0usize) else {
        return;
    };
    for activation in &module.activations {
        if !errors.poll() {
            return;
        }
        require_id(
            "activation caller",
            activation.caller.0,
            module.functions.len(),
            errors,
        );
        require_id(
            "activation callee",
            activation.callee.0,
            module.functions.len(),
            errors,
        );
        require_id(
            "activation capacity proof",
            activation.capacity_proof.0,
            module.proofs.len(),
            errors,
        );
        require_id(
            "activation cleanup proof",
            activation.cleanup_proof.0,
            module.proofs.len(),
            errors,
        );
        if let Some(count) = caller_counts.get_mut(activation.caller.0 as usize) {
            *count = count.saturating_add(1);
        }

        let Some(caller) = module.functions.get(activation.caller.0 as usize) else {
            continue;
        };
        let Some(callee) = module.functions.get(activation.callee.0 as usize) else {
            continue;
        };
        let owner_matches = match (activation.owner, caller.role, activation.schedule) {
            (
                MachineActivationOwner::Actor {
                    actor,
                    mailbox_capacity,
                },
                MachineFunctionRole::ActorTurn(role_actor),
                MachineActivationSchedule::DormantMailbox
                | MachineActivationSchedule::MailboxOnce
                | MachineActivationSchedule::SchedulerFifo,
            ) => actor == role_actor && mailbox_capacity != 0,
            (
                MachineActivationOwner::Task {
                    task,
                    slots,
                    supervisor,
                },
                MachineFunctionRole::TaskEntry(role_task),
                MachineActivationSchedule::StartupOnce,
            ) => {
                task == role_task
                    && slots == 1
                    && supervisor.is_none_or(|actor| {
                        actor == 0
                            || (actor == 1
                                && module.region_storage.iter().any(|storage| {
                                    storage.kind
                                        == (MachineRegionStorageKind::ActorMailbox {
                                            actor: 1,
                                            mailbox_capacity: 1,
                                        })
                                }))
                    })
            }
            _ => false,
        };
        let proof_matches = caller.proofs.contains(&activation.capacity_proof)
            && callee.proofs.contains(&activation.cleanup_proof)
            && module
                .proofs
                .get(activation.capacity_proof.0 as usize)
                .is_some_and(|proof| {
                    proof.source_proofs.as_slice() == [activation.capacity_proof.0]
                        && proof.kind == BackendProofKind::CapacityBound
                        && proof.depends_on.as_slice() == [activation.cleanup_proof]
                        && proof.bound == Some(activation.capacity_bound)
                        && proof.sources.as_slice() == [activation.source]
                        && proof.source == Some(activation.source)
                })
            && module
                .proofs
                .get(activation.cleanup_proof.0 as usize)
                .is_some_and(|proof| {
                    proof.source_proofs.as_slice() == [activation.cleanup_proof.0]
                        && proof.kind == BackendProofKind::CleanupAcyclic
                        && callee
                            .source
                            .is_some_and(|source| proof.sources.as_slice() == [source])
                        && proof.source == proof.sources.first().copied()
                });
        let two_await = two_await_activation_shape_matches(module, caller, activation);
        let fixed_facts_match = (activation.state == 0 || (two_await && activation.state == 1))
            && activation.frame_bytes != 0
            && activation.frame_bytes == activation.region_capacity_bytes
            && valid_alignment(activation.region_alignment)
            && activation.region_alignment <= module.layout.maximum_object_alignment
            && activation.maximum_live == 1
            && activation.capacity_bound == u64::from(activation.maximum_live)
            && activation.source.range.start <= activation.source.range.end;

        let call_shape_matches =
            activation_call_shape_matches(module, caller, callee, activation, errors);
        let callee_shape_matches = immediate_activation_callee_matches(module, callee);
        let schedule_matches = activation_schedule_matches(module, activation, errors);
        if !owner_matches
            || !proof_matches
            || !fixed_facts_match
            || !call_shape_matches
            || !callee_shape_matches
            || !schedule_matches
        {
            errors.push(ValidationError::InvalidActivationPlan(activation.id));
        }
    }

    for (index, function) in module.functions.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let activation_role = matches!(
            function.role,
            MachineFunctionRole::ActorTurn(_) | MachineFunctionRole::TaskEntry(_)
        );
        let count = caller_counts.get(index).copied().unwrap_or(0);
        let reply_role = function.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::ActorReplyRequest { .. }
                        | MachineOperation::ActorReplyResolve { .. }
                )
            })
        });
        let two_await_role = count == 2
            && module
                .activations
                .iter()
                .filter(|activation| activation.caller == function.id)
                .all(|activation| two_await_activation_shape_matches(module, function, activation));
        if activation_role != (count == 1 || two_await_role || reply_role) {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation caller set",
                id: function.id.0,
            });
        }
    }
}

fn validate_scheduler_ownership(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let has_owned_work = module.functions.iter().any(|function| {
        matches!(
            function.role,
            MachineFunctionRole::ActorTurn(_) | MachineFunctionRole::TaskEntry(_)
        )
    }) || module
        .region_storage
        .iter()
        .any(|storage| matches!(storage.kind, MachineRegionStorageKind::ActorMailbox { .. }));
    if !has_owned_work {
        if !module.schedulers.is_empty() {
            errors.push(ValidationError::InvalidRecord {
                kind: "scheduler ownership partition",
                id: module
                    .schedulers
                    .first()
                    .map_or(0, |scheduler| scheduler.core),
            });
        }
        return;
    }

    let [scheduler] = module.schedulers.as_slice() else {
        errors.push(ValidationError::InvalidRecord {
            kind: "scheduler ownership partition",
            id: module
                .schedulers
                .first()
                .map_or(0, |scheduler| scheduler.core),
        });
        return;
    };
    let mut valid = scheduler.core == 0
        && scheduler
            .actors
            .iter()
            .enumerate()
            .all(|(index, actor)| usize::try_from(*actor).ok() == Some(index))
        && scheduler
            .tasks
            .iter()
            .enumerate()
            .all(|(index, task)| usize::try_from(*task).ok() == Some(index));
    let Some(mut actor_owners) = errors.filled(scheduler.actors.len(), false) else {
        return;
    };
    let Some(mut task_owners) = errors.filled(scheduler.tasks.len(), false) else {
        return;
    };
    for storage in &module.region_storage {
        if !errors.poll() {
            return;
        }
        if let MachineRegionStorageKind::ActorMailbox { actor, .. } = storage.kind {
            if let Some(owned) = actor_owners.get_mut(actor as usize) {
                *owned = true;
            } else {
                valid = false;
            }
        }
    }
    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        match function.role {
            MachineFunctionRole::ActorTurn(actor) => {
                if actor_owners.get(actor as usize).is_none() {
                    valid = false;
                }
            }
            MachineFunctionRole::TaskEntry(task) => {
                if let Some(owned) = task_owners.get_mut(task as usize) {
                    *owned = true;
                } else {
                    valid = false;
                }
            }
            MachineFunctionRole::Ordinary
            | MachineFunctionRole::Isr(_)
            | MachineFunctionRole::Cleanup
            | MachineFunctionRole::ImageEntry
            | MachineFunctionRole::Test => {}
        }
    }
    valid &=
        actor_owners.into_iter().all(|owned| owned) && task_owners.into_iter().all(|owned| owned);
    if !valid {
        errors.push(ValidationError::InvalidRecord {
            kind: "scheduler ownership partition",
            id: scheduler.core,
        });
    }
}

fn validate_region_storage(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let reply_profile = module.functions.iter().any(|function| {
        function.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::ActorReplyRequest { .. }
                )
            })
        })
    });
    if module.activations.is_empty() && !reply_profile {
        for storage in &module.region_storage {
            if !errors.poll() {
                return;
            }
            errors.push(ValidationError::InvalidRegionStorage(storage.id));
        }
        return;
    }

    let cross_actor = reply_profile
        || module.activations.iter().any(|activation| {
            matches!(
                activation.owner,
                MachineActivationOwner::Task {
                    supervisor: Some(1),
                    ..
                }
            ) && activation.schedule == MachineActivationSchedule::StartupOnce
        });
    let actor_state_count = module
        .region_storage
        .iter()
        .filter(|storage| matches!(storage.kind, MachineRegionStorageKind::ActorState { .. }))
        .count();
    let has_actor_state = actor_state_count == 1;
    let expected = module
        .activations
        .len()
        .checked_add(if cross_actor { 4 } else { 3 })
        .and_then(|count| count.checked_add(usize::from(has_actor_state)));
    if expected != Some(module.region_storage.len()) {
        errors.push(ValidationError::InvalidRecord {
            kind: "region storage set",
            id: u32::try_from(module.region_storage.len()).unwrap_or(u32::MAX),
        });
    }

    let Some(mut global_counts) = errors.filled(module.globals.len(), 0u8) else {
        return;
    };
    let Some(mut symbol_counts) = errors.filled(module.symbols.len(), 0u8) else {
        return;
    };
    let Some(mut section_counts) = errors.filled(module.sections.len(), 0u8) else {
        return;
    };
    let Some(mut type_counts) = errors.filled(module.types.len(), 0u8) else {
        return;
    };
    let Some(mut activation_counts) = errors.filled(module.activations.len(), 0u8) else {
        return;
    };
    let mut mailbox_count = 0u8;
    let mut state_count = 0u8;
    let mut actor_zero_mailbox_name = None;
    let mut actor_frame_count = 0u8;
    let mut task_frame_count = 0u8;
    let mut total_bytes = Some(0u64);

    for storage in &module.region_storage {
        if !errors.poll() {
            return;
        }
        require_id(
            "region storage global",
            storage.global.0,
            module.globals.len(),
            errors,
        );
        require_id(
            "region storage symbol",
            storage.symbol.0,
            module.symbols.len(),
            errors,
        );
        require_id(
            "region storage section",
            storage.section.0,
            module.sections.len(),
            errors,
        );
        require_id(
            "region storage type",
            storage.ty.0,
            module.types.len(),
            errors,
        );
        require_id(
            "region storage capacity proof",
            storage.capacity_proof.0,
            module.proofs.len(),
            errors,
        );
        increment_identity_count(&mut global_counts, storage.global.0);
        increment_identity_count(&mut symbol_counts, storage.symbol.0);
        increment_identity_count(&mut section_counts, storage.section.0);
        increment_identity_count(&mut type_counts, storage.ty.0);

        let name_nonblank = text_is_blank(&storage.name, errors).is_some_and(|blank| !blank);
        let fixed = storage.flow_region == storage.id.0
            && name_nonblank
            && storage.capacity_units != 0
            && storage.bytes_per_unit != 0
            && storage.capacity_units.checked_mul(storage.bytes_per_unit)
                == Some(storage.capacity_bytes)
            && storage.capacity_bytes != 0
            && valid_alignment(storage.alignment)
            && storage.alignment <= module.layout.maximum_object_alignment
            && storage.capacity_bytes % u64::from(storage.alignment) == 0
            && storage.source.range.start <= storage.source.range.end
            && storage.capacity_source.range.start <= storage.capacity_source.range.end;

        let global_matches = module
            .globals
            .get(storage.global.0 as usize)
            .is_some_and(|global| {
                global.symbol == storage.symbol
                    && global.ty == storage.ty
                    && global.section == storage.section
                    && global.offset == 0
                    && global.alignment == storage.alignment
                    && global.initializer == MachineImmediate::Zero(storage.ty)
            });
        let symbol_matches = module
            .symbols
            .get(storage.symbol.0 as usize)
            .is_some_and(|symbol| {
                symbol.visibility == SymbolVisibility::Private
                    && symbol.definition == SymbolDefinition::Global(storage.global)
            })
            && numbered_name_matches(
                module
                    .symbols
                    .get(storage.symbol.0 as usize)
                    .map_or("", |symbol| symbol.name.as_str()),
                REGION_STORAGE_SYMBOL_PREFIX,
                storage.id.0,
                errors,
            );
        let section_matches =
            module
                .sections
                .get(storage.section.0 as usize)
                .is_some_and(|section| {
                    section.kind == SectionKind::WritableData
                        && section.alignment == storage.alignment
                        && section.reserved_bytes == storage.capacity_bytes
                })
                && module
                    .sections
                    .get(storage.section.0 as usize)
                    .is_some_and(|section| {
                        text_equals(&section.owner, &storage.name, errors).unwrap_or(false)
                            && numbered_name_matches(
                                &section.name,
                                REGION_STORAGE_SECTION_PREFIX,
                                storage.id.0,
                                errors,
                            )
                    });
        let type_matches = module.types.get(storage.ty.0 as usize).is_some_and(|ty| {
            matches!(
                ty.kind,
                MachineTypeKind::Array { length, .. }
                    if length == storage.capacity_bytes
            ) && ty.size == storage.capacity_bytes
                && ty.alignment == storage.alignment
                && ty
                    .source_name
                    .as_deref()
                    .is_some_and(|name| text_equals(name, &storage.name, errors).unwrap_or(false))
                && matches!(
                    ty.kind,
                    MachineTypeKind::Array { element, .. }
                        if module.types.get(element.0 as usize).is_some_and(|element| {
                            element.kind == MachineTypeKind::Integer { bits: 8 }
                                && element.size == 1
                                && element.alignment == 1
                        })
                )
        });
        let proof_matches = module
            .proofs
            .get(storage.capacity_proof.0 as usize)
            .is_some_and(|proof| {
                proof.kind == BackendProofKind::CapacityBound
                    && proof.source_proofs.as_slice() == [storage.capacity_proof.0]
                    && proof.bound == Some(storage.capacity_units)
                    && proof.sources.as_slice() == [storage.capacity_source]
                    && proof.source == Some(storage.capacity_source)
            });

        let kind_matches = match storage.kind {
            MachineRegionStorageKind::ActorMailbox {
                actor,
                mailbox_capacity,
            } => {
                mailbox_count = mailbox_count.saturating_add(1);
                if actor == 0 {
                    actor_zero_mailbox_name = Some(storage.name.as_str());
                }
                storage.id.0
                    == if actor == 0 {
                        0
                    } else {
                        2 + u32::from(has_actor_state)
                    }
                    && (!cross_actor || matches!(actor, 0 | 1))
                    && storage.capacity_units == u64::from(mailbox_capacity)
                    && storage.bytes_per_unit == 16
                    && text_ends_with(&storage.name, ".mailbox", errors)
                    && (module.activations.iter().any(|activation| {
                        matches!(
                            activation.schedule,
                            MachineActivationSchedule::DormantMailbox
                                | MachineActivationSchedule::MailboxOnce
                                | MachineActivationSchedule::SchedulerFifo
                        ) && activation.owner
                            == (MachineActivationOwner::Actor {
                                actor,
                                mailbox_capacity,
                            })
                    }) || (cross_actor && actor == 1 && mailbox_capacity == 1)
                        || (reply_profile && matches!(actor, 0 | 1) && mailbox_capacity == 1))
            }
            MachineRegionStorageKind::ActorState { actor } => {
                state_count = state_count.saturating_add(1);
                let proof = module.proofs.get(storage.capacity_proof.0 as usize);
                actor == 0
                    && storage.id.0 == 1
                    && storage.capacity_units == 1
                    && storage.bytes_per_unit == 8
                    && storage.capacity_bytes == 8
                    && storage.alignment == 8
                    && storage.source == storage.capacity_source
                    && text_ends_with(&storage.name, ".state", errors)
                    && actor_zero_mailbox_name.is_some_and(|mailbox_name| {
                        sibling_storage_name_matches(
                            mailbox_name,
                            ".mailbox",
                            &storage.name,
                            ".state",
                            errors,
                        )
                    })
                    && proof.is_some_and(|proof| proof.depends_on.is_empty())
            }
            MachineRegionStorageKind::ActorTurnFrame { actor, function } => {
                actor_frame_count = actor_frame_count.saturating_add(1);
                storage.id.0 == 1 + u32::from(has_actor_state)
                    && storage.capacity_units == 1
                    && storage.bytes_per_unit == storage.capacity_bytes
                    && text_ends_with(&storage.name, ".turn-frame", errors)
                    && module
                        .functions
                        .get(function.0 as usize)
                        .is_some_and(|function| {
                            function.role == MachineFunctionRole::ActorTurn(actor)
                        })
                    && (module.activations.iter().any(|activation| {
                        matches!(
                            activation.schedule,
                            MachineActivationSchedule::DormantMailbox
                                | MachineActivationSchedule::MailboxOnce
                                | MachineActivationSchedule::SchedulerFifo
                        ) && activation.caller == function
                    }) || (reply_profile
                        && module
                            .functions
                            .get(function.0 as usize)
                            .is_some_and(|function| {
                                function.blocks.iter().any(|block| {
                                    block.instructions.iter().any(|instruction| {
                                        matches!(
                                            instruction.operation,
                                            MachineOperation::ActorReplyResolve { .. }
                                        )
                                    })
                                })
                            })))
            }
            MachineRegionStorageKind::TaskEntryFrame {
                task,
                function,
                slots,
            } => {
                task_frame_count = task_frame_count.saturating_add(1);
                storage.id.0 == (if cross_actor { 3 } else { 2 }) + u32::from(has_actor_state)
                    && slots == 1
                    && storage.capacity_units == u64::from(slots)
                    && storage.bytes_per_unit == storage.capacity_bytes
                    && text_ends_with(&storage.name, ".frame", errors)
                    && module
                        .functions
                        .get(function.0 as usize)
                        .is_some_and(|function| {
                            function.role == MachineFunctionRole::TaskEntry(task)
                        })
                    && (module.activations.iter().any(|activation| {
                        activation.schedule == MachineActivationSchedule::StartupOnce
                            && activation.caller == function
                    }) || (reply_profile
                        && module
                            .functions
                            .get(function.0 as usize)
                            .is_some_and(|function| {
                                function.blocks.iter().any(|block| {
                                    block.instructions.iter().any(|instruction| {
                                        matches!(
                                            instruction.operation,
                                            MachineOperation::ActorReplyRequest { .. }
                                        )
                                    })
                                })
                            })))
            }
            MachineRegionStorageKind::ActivationFrame { activation } => {
                if let Some(count) = activation_counts.get_mut(activation.0 as usize) {
                    *count = count.saturating_add(1);
                }
                module
                    .activations
                    .get(activation.0 as usize)
                    .is_some_and(|plan| {
                        storage.id.0 == plan.region
                            && storage.flow_region == plan.region
                            && storage.capacity_proof == plan.capacity_proof
                            && storage.capacity_units == u64::from(plan.maximum_live)
                            && storage.bytes_per_unit == plan.frame_bytes
                            && storage.capacity_bytes == plan.region_capacity_bytes
                            && storage.alignment == plan.region_alignment
                            && storage.source == plan.source
                            && storage.capacity_source == plan.source
                            && text_ends_with(&storage.name, ".async-activation-frame", errors)
                    })
            }
        };
        total_bytes = total_bytes.and_then(|total| total.checked_add(storage.capacity_bytes));
        if !fixed
            || !global_matches
            || !symbol_matches
            || !section_matches
            || !type_matches
            || !proof_matches
            || !kind_matches
        {
            errors.push(ValidationError::InvalidRegionStorage(storage.id));
        }
    }

    if mailbox_count != if cross_actor { 2 } else { 1 }
        || state_count != u8::from(has_actor_state)
        || actor_state_count > 1
        || actor_frame_count != 1
        || task_frame_count != 1
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "region storage owner set",
            id: 0,
        });
    }
    for (index, count) in activation_counts.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if *count != 1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation region storage set",
                id: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
    validate_storage_identity_counts(
        module,
        &global_counts,
        &symbol_counts,
        &section_counts,
        &type_counts,
        errors,
    );

    let image_closed = module
        .proofs
        .last()
        .filter(|proof| proof.kind == BackendProofKind::ImageClosed);
    let entry_references_closure = image_closed.is_some_and(|proof| {
        module
            .functions
            .get(module.image_entry.0 as usize)
            .is_some_and(|entry| entry.proofs.contains(&proof.id))
    });
    if image_closed.and_then(|proof| proof.bound) != total_bytes || !entry_references_closure {
        errors.push(ValidationError::InvalidRecord {
            kind: "region storage image bound",
            id: 0,
        });
    }
}

fn increment_identity_count(counts: &mut [u8], id: u32) {
    if let Some(count) = counts.get_mut(id as usize) {
        *count = count.saturating_add(1);
    }
}

fn sibling_storage_name_matches(
    left: &str,
    left_suffix: &str,
    right: &str,
    right_suffix: &str,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let Some(left_prefix_bytes) = left.len().checked_sub(left_suffix.len()) else {
        return false;
    };
    let Some(right_prefix_bytes) = right.len().checked_sub(right_suffix.len()) else {
        return false;
    };
    if left_prefix_bytes != right_prefix_bytes
        || !left.ends_with(left_suffix)
        || !right.ends_with(right_suffix)
    {
        return false;
    }
    let Some(left_prefix) = left.get(..left_prefix_bytes) else {
        return false;
    };
    let Some(right_prefix) = right.get(..right_prefix_bytes) else {
        return false;
    };
    text_equals(left_prefix, right_prefix, errors).unwrap_or(false)
}

fn validate_storage_identity_counts(
    module: &MachineWir,
    global_counts: &[u8],
    symbol_counts: &[u8],
    section_counts: &[u8],
    type_counts: &[u8],
    errors: &mut ValidationContext<'_>,
) {
    for (index, global) in module.globals.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let region_storage = module
            .sections
            .get(global.section.0 as usize)
            .is_some_and(|section| section.name.starts_with(REGION_STORAGE_SECTION_PREFIX));
        if global_counts.get(index).copied().unwrap_or(0) != u8::from(region_storage) {
            errors.push(ValidationError::InvalidRecord {
                kind: "region storage global identity",
                id: global.id.0,
            });
        }
    }
    for (index, count) in symbol_counts.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if *count > 1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "region storage symbol identity",
                id: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
    for (index, section) in module.sections.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let expected = u8::from(section.name.starts_with(REGION_STORAGE_SECTION_PREFIX));
        if section_counts.get(index).copied().unwrap_or(0) != expected {
            errors.push(ValidationError::InvalidRecord {
                kind: "region storage section identity",
                id: section.id.0,
            });
        }
    }
    for (index, count) in type_counts.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if *count > 1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "region storage type identity",
                id: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
}

fn numbered_name_matches(
    actual: &str,
    prefix: &str,
    number: u32,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let mut digits = [0u8; 10];
    let mut cursor = digits.len();
    let mut remaining = number;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let expected_len = prefix.len().checked_add(digits.len() - cursor);
    if expected_len != Some(actual.len()) {
        return false;
    }
    for (left, right) in actual
        .bytes()
        .zip(prefix.bytes().chain(digits[cursor..].iter().copied()))
    {
        if !errors.poll() || left != right {
            return false;
        }
    }
    true
}

fn text_ends_with(actual: &str, suffix: &str, errors: &mut ValidationContext<'_>) -> bool {
    actual
        .len()
        .checked_sub(suffix.len())
        .and_then(|start| actual.get(start..))
        .is_some_and(|tail| text_equals(tail, suffix, errors).unwrap_or(false))
}

fn activation_call_shape_matches(
    module: &MachineWir,
    caller: &MachineFunction,
    callee: &MachineFunction,
    activation: &MachineActivationPlan,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let two_await = two_await_activation_shape_matches(module, caller, activation);
    let mut matched = 0usize;
    let mut valid = true;
    for block in &caller.blocks {
        if !errors.poll() {
            return false;
        }
        for instruction in &block.instructions {
            if !errors.poll() {
                return false;
            }
            if instruction.id != activation.call_instruction {
                continue;
            }
            matched = matched.saturating_add(1);
            let call_tail =
                exact_machine_activation_call_tail(module, caller, callee, block, instruction);
            let unit_result = module
                .types
                .get(callee.result.0 as usize)
                .is_some_and(|ty| ty.kind == MachineTypeKind::Void)
                && instruction.results.is_empty();
            let u64_result = exact_machine_u64_type(module, callee.result)
                && matches!(instruction.results.as_slice(), [result]
                    if caller.values.get(result.0 as usize)
                        .is_some_and(|value| value.ty == callee.result));
            valid &= (unit_result || u64_result)
                && (call_tail == Some(1) || (two_await && call_tail == Some(2)))
                && instruction.source == Some(activation.source)
                && matches!(
                    &instruction.operation,
                    MachineOperation::Call {
                        function,
                        arguments,
                        convention: CallingConvention::Internal,
                    } if *function == activation.callee
                )
                && matches!(
                    &block.terminator,
                    MachineTerminator::Jump { block, arguments }
                        if *block == activation.resume_block && arguments.is_empty()
                )
                && (block.id == caller.entry
                    || two_await
                    || structured_scope_activation_shape_matches(
                        module, caller, block.id, activation, errors,
                    ));
        }
    }
    let resume_matches = two_await || caller
        .blocks
        .get(activation.resume_block.0 as usize)
        .is_some_and(|resume| {
            resume.parameters.is_empty()
                && resume.instructions.is_empty()
                && matches!(&resume.terminator, MachineTerminator::Return(values) if values.is_empty())
        });
    matched == 1 && valid && resume_matches
}

fn two_await_activation_shape_matches(
    module: &MachineWir,
    caller: &MachineFunction,
    activation: &MachineActivationPlan,
) -> bool {
    if module.activations.len() != 4 || activation.state > 1 {
        return false;
    }
    let [entry, middle, terminal] = caller.blocks.as_slice() else {
        return false;
    };
    let mut state_zero = None;
    let mut state_one = None;
    let mut caller_count = 0usize;
    for candidate in &module.activations {
        if candidate.caller != caller.id {
            continue;
        }
        caller_count = caller_count.saturating_add(1);
        if candidate.callee != activation.callee {
            return false;
        }
        match candidate.state {
            0 if state_zero.replace(candidate).is_none() => {}
            1 if state_one.replace(candidate).is_none() => {}
            _ => return false,
        }
    }
    let (Some(state_zero), Some(state_one)) = (state_zero, state_one) else {
        return false;
    };
    let Some(callee) = module.functions.get(activation.callee.0 as usize) else {
        return false;
    };
    caller_count == 2
        && caller.entry == entry.id
        && entry.id == BlockId(0)
        && middle.id == BlockId(1)
        && terminal.id == BlockId(2)
        && entry.parameters.is_empty()
        && middle.parameters.is_empty()
        && terminal.parameters.is_empty()
        && entry.instructions.last().is_some_and(|call| {
            call.id == state_zero.call_instruction
                && exact_machine_activation_call_tail(module, caller, callee, entry, call)
                    == Some(entry.instructions.len())
        })
        && matches!(&entry.terminator,
            MachineTerminator::Jump { block, arguments }
                if *block == middle.id && arguments.is_empty())
        && middle.instructions.last().is_some_and(|call| {
            call.id == state_one.call_instruction
                && exact_machine_activation_call_tail(module, caller, callee, middle, call)
                    == Some(middle.instructions.len())
        })
        && matches!(&middle.terminator,
            MachineTerminator::Jump { block, arguments }
                if *block == terminal.id && arguments.is_empty())
        && terminal.instructions.is_empty()
        && matches!(&terminal.terminator,
            MachineTerminator::Return(values) if values.is_empty())
        && state_zero.resume_block == middle.id
        && state_one.resume_block == terminal.id
}

fn exact_machine_activation_call_tail(
    module: &MachineWir,
    caller: &MachineFunction,
    callee: &MachineFunction,
    block: &MachineBlock,
    call: &MachineInstruction,
) -> Option<usize> {
    if block.instructions.last() != Some(call) {
        return None;
    }
    let MachineOperation::Call { arguments, .. } = &call.operation else {
        return None;
    };
    match (callee.parameters.as_slice(), arguments.as_slice()) {
        ([], []) => Some(1),
        ([parameter], [argument]) => {
            let argument_instruction = block
                .instructions
                .get(block.instructions.len().checked_sub(2)?)?;
            matches!(argument_instruction.results.as_slice(), [value] if value == argument)
                .then_some(())?;
            matches!(&argument_instruction.operation,
                MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le })
                    if *ty == callee.result && bytes_le.len() == 8)
            .then_some(())?;
            (exact_machine_u64_type(module, callee.result)
                && caller
                    .values
                    .get(argument.0 as usize)
                    .is_some_and(|value| value.ty == callee.result)
                && callee
                    .values
                    .get(parameter.0 as usize)
                    .is_some_and(|value| value.ty == callee.result)
                && argument_instruction.source.is_some())
            .then_some(2)
        }
        _ => None,
    }
}

fn structured_scope_activation_shape_matches(
    module: &MachineWir,
    caller: &MachineFunction,
    call_block: BlockId,
    activation: &MachineActivationPlan,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let [entry, taken, untaken, fallthrough, resume] = caller.blocks.as_slice() else {
        return false;
    };
    if caller.entry != entry.id
        || entry.id != BlockId(0)
        || taken.id != BlockId(1)
        || untaken.id != BlockId(2)
        || fallthrough.id != BlockId(3)
        || resume.id != BlockId(4)
        || call_block != fallthrough.id
        || activation.resume_block != resume.id
        || !entry.parameters.is_empty()
        || !taken.parameters.is_empty()
        || !untaken.parameters.is_empty()
        || !fallthrough.parameters.is_empty()
        || !resume.parameters.is_empty()
    {
        return false;
    }
    let [state_field, state_constructor, predicate] = entry.instructions.as_slice() else {
        return false;
    };
    let [fallthrough_cleanup, activation_call] = fallthrough.instructions.as_slice() else {
        return false;
    };
    let returning_cleanup = match (
        taken.instructions.as_slice(),
        &taken.terminator,
        untaken.instructions.as_slice(),
        &untaken.terminator,
    ) {
        (
            [cleanup],
            MachineTerminator::Return(values),
            [],
            MachineTerminator::Jump { block, arguments },
        ) if values.is_empty() && *block == fallthrough.id && arguments.is_empty() => cleanup,
        (
            [],
            MachineTerminator::Jump { block, arguments },
            [cleanup],
            MachineTerminator::Return(values),
        ) if values.is_empty() && *block == fallthrough.id && arguments.is_empty() => cleanup,
        _ => return false,
    };
    let [state_field_value] = state_field.results.as_slice() else {
        return false;
    };
    let [state] = state_constructor.results.as_slice() else {
        return false;
    };
    let [condition] = predicate.results.as_slice() else {
        return false;
    };
    let predicate_callee = match &predicate.operation {
        MachineOperation::Call {
            function,
            arguments,
            convention: CallingConvention::Internal,
        } if arguments.is_empty() => module.functions.get(function.0 as usize),
        _ => None,
    };
    let cleanup_function = match (&returning_cleanup.operation, &fallthrough_cleanup.operation) {
        (
            MachineOperation::Call {
                function: left,
                arguments: left_arguments,
                convention: CallingConvention::Internal,
            },
            MachineOperation::Call {
                function: right,
                arguments: right_arguments,
                convention: CallingConvention::Internal,
            },
        ) if left == right
            && left_arguments.as_slice() == [*state]
            && right_arguments == left_arguments
            && returning_cleanup.results.is_empty()
            && fallthrough_cleanup.results.is_empty()
            && returning_cleanup.source == fallthrough_cleanup.source =>
        {
            module.functions.get(left.0 as usize)
        }
        _ => None,
    };
    let branch_matches = matches!(
        &entry.terminator,
        MachineTerminator::Branch {
            condition: branch_condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } if branch_condition == condition
            && *then_block == taken.id
            && then_arguments.is_empty()
            && *else_block == untaken.id
            && else_arguments.is_empty()
    );
    let state_matches = matches!(
        state_field.operation,
        MachineOperation::Immediate(MachineImmediate::Integer { .. })
    ) && matches!(
        &state_constructor.operation,
        MachineOperation::MakeStruct { fields, .. }
            if fields.as_slice() == [*state_field_value]
    );
    let predicate_matches = predicate_callee.is_some_and(|callee| {
        callee.role == MachineFunctionRole::Ordinary
            && callee.convention == CallingConvention::Internal
            && callee.parameters.is_empty()
            && module
                .types
                .get(callee.result.0 as usize)
                .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 8 })
    });
    let cleanup_matches = cleanup_function.is_some_and(|cleanup| {
        matches!(
            cleanup.origin,
            MachineFunctionOrigin::GeneratedCleanup { .. }
        ) && cleanup.role == MachineFunctionRole::Cleanup
            && cleanup.convention == CallingConvention::Internal
    });
    let tails_match = activation_call.id == activation.call_instruction
        && resume.instructions.is_empty()
        && matches!(&resume.terminator, MachineTerminator::Return(values) if values.is_empty());
    branch_matches
        && state_matches
        && predicate_matches
        && cleanup_matches
        && tails_match
        && errors.poll()
}

fn immediate_activation_callee_matches(module: &MachineWir, callee: &MachineFunction) -> bool {
    let unit = module
        .types
        .get(callee.result.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void))
        && matches!(callee.blocks.as_slice(), [block]
            if block.id == callee.entry
                && block.parameters.is_empty()
                && block.instructions.is_empty()
                && matches!(&block.terminator, MachineTerminator::Return(values) if values.is_empty()));
    let u64_result = exact_bounded_u64_activation_callee(module, callee);
    callee.role == MachineFunctionRole::Ordinary
        && callee.convention == CallingConvention::Internal
        && (unit || u64_result)
}

fn exact_constant_u64_machine_function(module: &MachineWir, function: &MachineFunction) -> bool {
    exact_machine_u64_type(module, function.result)
        && function.parameters.is_empty()
        && matches!(function.blocks.as_slice(), [block]
            if block.id == function.entry
                && block.parameters.is_empty()
                && matches!(block.instructions.as_slice(), [constant]
                    if constant.source.is_some()
                        && matches!(constant.results.as_slice(), [value]
                            if function.values.get(value.0 as usize)
                                .is_some_and(|value| value.ty == function.result))
                        && matches!(&constant.operation,
                            MachineOperation::Immediate(MachineImmediate::Integer {
                                ty,
                                bytes_le,
                            }) if *ty == function.result && bytes_le.len() == 8)
                        && matches!(&block.terminator,
                            MachineTerminator::Return(values)
                                if values.as_slice() == constant.results.as_slice())))
}

fn exact_bounded_u64_activation_callee(module: &MachineWir, callee: &MachineFunction) -> bool {
    if exact_constant_u64_machine_function(module, callee) {
        return true;
    }
    let [block] = callee.blocks.as_slice() else {
        return false;
    };
    let [initial, constant, first, tail @ ..] = block.instructions.as_slice() else {
        return false;
    };
    let (left, right, parameterized) = match (
        &initial.operation,
        initial.results.as_slice(),
        &constant.operation,
        constant.results.as_slice(),
    ) {
        (
            MachineOperation::Call {
                function,
                arguments,
                convention: CallingConvention::Internal,
            },
            [left],
            MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le }),
            [right],
        ) if arguments.is_empty()
            && *ty == callee.result
            && bytes_le.len() == 8
            && callee
                .values
                .get(left.0 as usize)
                .is_some_and(|value| value.ty == callee.result)
            && callee
                .values
                .get(right.0 as usize)
                .is_some_and(|value| value.ty == callee.result)
            && module
                .functions
                .get(function.0 as usize)
                .is_some_and(|seed| {
                    seed.id == *function
                        && seed.role == MachineFunctionRole::Ordinary
                        && seed.convention == CallingConvention::Internal
                        && seed.result == callee.result
                        && exact_constant_u64_machine_function(module, seed)
                }) =>
        {
            (*left, *right, false)
        }
        (
            MachineOperation::Convert {
                op: ConversionOp::Bitcast,
                value: parameter,
                destination,
            },
            [left],
            MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le }),
            [right],
        ) if *destination == callee.result
            && *ty == callee.result
            && bytes_le.len() == 8
            && callee.parameters.as_slice() == [*parameter]
            && callee
                .values
                .get(parameter.0 as usize)
                .is_some_and(|value| value.ty == callee.result)
            && callee
                .values
                .get(left.0 as usize)
                .is_some_and(|value| value.ty == callee.result)
            && callee
                .values
                .get(right.0 as usize)
                .is_some_and(|value| value.ty == callee.result) =>
        {
            (*left, *right, true)
        }
        _ => return false,
    };
    let checked_add =
        |instruction: &MachineInstruction, expected_left: ValueId| -> Option<ValueId> {
            match (&instruction.operation, instruction.results.as_slice()) {
                (
                    MachineOperation::CheckedInteger {
                        op: CheckedIntegerOp::Add,
                        signedness: IntegerSignedness::Unsigned,
                        left,
                        right: actual_right,
                        failure,
                    },
                    [sum],
                ) if *left == expected_left
                    && *actual_right == right
                    && failure.kind == ScalarFailureKind::Arithmetic
                    && callee
                        .values
                        .get(sum.0 as usize)
                        .is_some_and(|value| value.ty == callee.result)
                    && instruction.source.is_some() =>
                {
                    Some(*sum)
                }
                _ => None,
            }
        };
    let Some(first_sum) = checked_add(first, left) else {
        return false;
    };
    let final_sum = match tail {
        [] => first_sum,
        [second] => match checked_add(second, first_sum) {
            Some(sum) => sum,
            None => return false,
        },
        _ => return false,
    };
    exact_machine_u64_type(module, callee.result)
        && (parameterized || callee.parameters.is_empty())
        && block.id == callee.entry
        && block.parameters.is_empty()
        && initial.source.is_some()
        && constant.source.is_some()
        && matches!(&block.terminator,
            MachineTerminator::Return(values) if values.as_slice() == [final_sum])
}

fn exact_machine_u64_type(module: &MachineWir, ty: MachineTypeId) -> bool {
    module.types.get(ty.0 as usize).is_some_and(|ty| {
        ty.kind == MachineTypeKind::Integer { bits: 64 } && ty.size == 8 && ty.alignment == 8
    })
}

fn activation_schedule_matches(
    module: &MachineWir,
    activation: &MachineActivationPlan,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let startup_success = module
        .functions
        .get(module.image_entry.0 as usize)
        .and_then(|entry| entry.blocks.get(entry.entry.0 as usize))
        .and_then(|prologue| match &prologue.terminator {
            MachineTerminator::Switch { cases, .. } => match cases.as_slice() {
                [(0, success, arguments)] if arguments.is_empty() => Some(*success),
                _ => None,
            },
            _ => None,
        });
    let mut calls = 0usize;
    let mut valid_startup = false;
    let mut valid_mailbox = false;
    let mut valid_fifo = false;
    for function in &module.functions {
        if !errors.poll() {
            return false;
        }
        for block in &function.blocks {
            if !errors.poll() {
                return false;
            }
            for (index, instruction) in block.instructions.iter().enumerate() {
                if !errors.poll() {
                    return false;
                }
                let direct_call = matches!(&instruction.operation,
                    MachineOperation::Call { function, .. } if *function == activation.caller);
                let mailbox_dispatch = matches!(&instruction.operation,
                    MachineOperation::MailboxDispatch { method, .. }
                        if *method == activation.caller);
                valid_fifo |= matches!(
                    (&instruction.operation, activation.owner),
                    (
                        MachineOperation::MailboxDispatch { actor, .. },
                        MachineActivationOwner::Actor { actor: owner, .. },
                    ) if *actor == owner
                        && function.id == module.image_entry
                        && Some(block.id) == startup_success
                        && index == 1
                        && instruction.results.is_empty()
                        && instruction.source.is_none()
                );
                if direct_call || mailbox_dispatch {
                    calls = calls.saturating_add(1);
                    valid_startup |= direct_call
                        && function.id == module.image_entry
                        && Some(block.id) == startup_success
                        && index == 0
                        && instruction.results.is_empty()
                        && instruction.source.is_none()
                        && matches!(&instruction.operation,
                            MachineOperation::Call {
                                arguments,
                                convention: CallingConvention::Internal,
                                ..
                            } if arguments.is_empty());
                    valid_mailbox |= mailbox_dispatch
                        && function.id == module.image_entry
                        && Some(block.id) == startup_success
                        && index == 1
                        && instruction.results.is_empty()
                        && instruction.source.is_none()
                        && matches!(&instruction.operation,
                            MachineOperation::MailboxDispatch { method, .. }
                                if *method == activation.caller);
                }
            }
        }
    }
    match activation.schedule {
        MachineActivationSchedule::DormantMailbox => calls == 0,
        MachineActivationSchedule::MailboxOnce => calls == 1 && valid_mailbox,
        MachineActivationSchedule::SchedulerFifo => {
            calls == usize::from(valid_mailbox) && valid_fifo
        }
        MachineActivationSchedule::StartupOnce => calls == 1 && valid_startup,
    }
}

fn validate_tests(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let Some(mut listed) = errors.scratch(module.tests.len()) else {
        return;
    };
    for test in &module.tests {
        if !errors.poll() {
            return;
        }
        require_id(
            "test function",
            test.function.0,
            module.functions.len(),
            errors,
        );
        let Some(blank_name) = text_is_blank(&test.name, errors) else {
            return;
        };
        if blank_name || test.timeout_ns == 0 || test.source.range.start > test.source.range.end {
            errors.push(ValidationError::InvalidRecord {
                kind: "test",
                id: test.id.0,
            });
        }
        if module
            .functions
            .get(test.function.0 as usize)
            .is_some_and(|function| function.role != MachineFunctionRole::Test)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "test function role",
                id: test.id.0,
            });
        }
        if !errors.scratch_push(&mut listed, test.function) {
            return;
        }
    }
    if !sort_scratch(&mut listed, errors) {
        return;
    }
    let mut invalid = false;
    for pair in listed.windows(2) {
        if !errors.poll() {
            return;
        }
        invalid |= pair[0] == pair[1];
    }
    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        invalid |= function.role == MachineFunctionRole::Test
            && !sorted_contains(&listed, &function.id, errors);
    }
    if invalid {
        errors.push(ValidationError::InvalidRecord {
            kind: "test function set",
            id: 0,
        });
    }
}

fn validate_generated_runtime_contract(
    module: &MachineWir,
    function: &MachineFunction,
    errors: &mut ValidationContext<'_>,
) {
    let generated_image_entry = function.id == module.image_entry
        && matches!(
            function.origin,
            MachineFunctionOrigin::GeneratedImageEntry { .. }
                | MachineFunctionOrigin::GeneratedTestHarness { .. }
        );
    let generated_test_harness = function.id == module.image_entry
        && matches!(
            function.origin,
            MachineFunctionOrigin::GeneratedTestHarness { .. }
        );
    let Some(mut definitions) = errors.filled(function.values.len(), None) else {
        return;
    };
    for block in &function.blocks {
        if !errors.poll() {
            return;
        }
        for instruction in &block.instructions {
            if !errors.poll() {
                return;
            }
            for result in &instruction.results {
                if !errors.poll() {
                    return;
                }
                if let Some(definition) = definitions.get_mut(result.0 as usize) {
                    *definition = Some(instruction);
                }
            }
        }
    }
    let incoming = if generated_test_harness {
        let Some(mut incoming) = errors.filled(function.blocks.len(), 0usize) else {
            return;
        };
        for block in &function.blocks {
            if !errors.poll()
                || !for_each_edge(&block.terminator, |target, _| {
                    if !errors.poll() {
                        return false;
                    }
                    if let Some(count) = incoming.get_mut(target.0 as usize) {
                        *count = count.saturating_add(1);
                    }
                    true
                })
            {
                return;
            }
        }
        Some(incoming)
    } else {
        None
    };
    let expected_static_events = module
        .tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2));
    let mut static_events = if generated_test_harness {
        expected_static_events.and_then(|count| errors.filled(count, None::<TestEvent>))
    } else {
        None
    };
    for block in &function.blocks {
        if !errors.poll() {
            return;
        }
        for (index, instruction) in block.instructions.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            let MachineOperation::RuntimeCall {
                intrinsic,
                arguments,
            } = &instruction.operation
            else {
                continue;
            };
            if *intrinsic == RuntimeIntrinsic::ImageEnter {
                if !generated_image_entry || block.id != function.entry {
                    errors.push(ValidationError::InvalidImageEnterContext {
                        function: function.id,
                        instruction: instruction.id,
                    });
                }
                continue;
            }
            if !matches!(
                intrinsic,
                RuntimeIntrinsic::TestEmit | RuntimeIntrinsic::TestFinish
            ) {
                continue;
            }
            let valid_context = function.id == module.image_entry
                && matches!(
                    function.origin,
                    MachineFunctionOrigin::GeneratedTestHarness { .. }
                );
            if !valid_context {
                errors.push(ValidationError::InvalidTestRuntimeContext {
                    intrinsic: *intrinsic,
                    function: function.id,
                    instruction: instruction.id,
                });
            }
            if *intrinsic == RuntimeIntrinsic::TestEmit {
                let decoded = static_test_payload(module, function, arguments, &definitions)
                    .and_then(|bytes| {
                        CanonicalTestEventCodec
                            .decode(bytes, ProtocolLimits::standard(), errors.is_cancelled)
                            .ok()
                    });
                let Some(event) = decoded else {
                    errors.push(ValidationError::InvalidStaticTestPayload {
                        function: function.id,
                        instruction: instruction.id,
                    });
                    continue;
                };
                if generated_test_harness {
                    let slot = usize::try_from(event.sequence)
                        .ok()
                        .and_then(|index| static_events.as_mut()?.get_mut(index));
                    let Some(slot) = slot else {
                        errors.push(ValidationError::InvalidStaticTestPayload {
                            function: function.id,
                            instruction: instruction.id,
                        });
                        continue;
                    };
                    if slot.is_some() {
                        errors.push(ValidationError::InvalidStaticTestPayload {
                            function: function.id,
                            instruction: instruction.id,
                        });
                        continue;
                    }
                    *slot = Some(event);
                }
            }
            if *intrinsic == RuntimeIntrinsic::TestEmit
                && generated_test_harness
                && !valid_test_emit_status_contract(
                    function,
                    block,
                    index,
                    instruction,
                    incoming.as_deref().unwrap_or(&[]),
                )
            {
                errors.push(ValidationError::InvalidTestEmitStatusContract {
                    function: function.id,
                    instruction: instruction.id,
                });
            }
        }
    }
    if generated_test_harness
        && static_events
            .as_deref()
            .is_none_or(|events| !exact_generated_passing_events(events, &module.tests))
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "generated static passing test lifecycle",
            id: function.id.0,
        });
    }
    if generated_image_entry && !valid_image_enter_prologue(function, errors) {
        errors.push(ValidationError::InvalidImageEnterPrologue(function.id));
    }
}

fn valid_test_emit_status_contract(
    function: &MachineFunction,
    block: &MachineBlock,
    instruction_index: usize,
    instruction: &MachineInstruction,
    incoming: &[usize],
) -> bool {
    if instruction_index + 1 != block.instructions.len() {
        return false;
    }
    let [status] = instruction.results.as_slice() else {
        return false;
    };
    let MachineTerminator::Switch {
        value,
        cases,
        default,
        default_arguments,
    } = &block.terminator
    else {
        return false;
    };
    let [(success_status, success, success_arguments)] = cases.as_slice() else {
        return false;
    };
    if value != status
        || *success_status != 0
        || !success_arguments.is_empty()
        || !default_arguments.is_empty()
        || *success == block.id
        || *default == block.id
        || *success == *default
        || incoming.get(success.0 as usize) != Some(&1)
        || incoming.get(default.0 as usize) != Some(&1)
    {
        return false;
    }
    let Some(success_block) = function.blocks.get(success.0 as usize) else {
        return false;
    };
    if !success_block.parameters.is_empty()
        || matches!(success_block.terminator, MachineTerminator::Return(_))
    {
        return false;
    }
    let Some(failure) = function.blocks.get(default.0 as usize) else {
        return false;
    };
    failure.parameters.is_empty()
        && failure.instructions.is_empty()
        && matches!(&failure.terminator, MachineTerminator::Return(values) if values.as_slice() == [*status])
}

fn valid_image_enter_prologue(
    function: &MachineFunction,
    errors: &mut ValidationContext<'_>,
) -> bool {
    if function.parameters.as_slice() != [ValueId(0), ValueId(1)] {
        return false;
    }
    let Some(entry) = function.blocks.get(function.entry.0 as usize) else {
        return false;
    };
    let [instruction] = entry.instructions.as_slice() else {
        return false;
    };
    let MachineOperation::RuntimeCall {
        intrinsic: RuntimeIntrinsic::ImageEnter,
        arguments,
    } = &instruction.operation
    else {
        return false;
    };
    if arguments.as_slice() != [ValueId(0), ValueId(1)] {
        return false;
    }
    let [status] = instruction.results.as_slice() else {
        return false;
    };
    let MachineTerminator::Switch {
        value,
        cases,
        default,
        default_arguments,
    } = &entry.terminator
    else {
        return false;
    };
    let [(success_status, success, success_arguments)] = cases.as_slice() else {
        return false;
    };
    if value != status
        || *success_status != 0
        || !success_arguments.is_empty()
        || !default_arguments.is_empty()
        || *success == function.entry
        || *default == function.entry
        || *success == *default
    {
        return false;
    }
    let Some(failure) = function.blocks.get(default.0 as usize) else {
        return false;
    };
    if !failure.parameters.is_empty()
        || !failure.instructions.is_empty()
        || !matches!(&failure.terminator, MachineTerminator::Return(values) if values.as_slice() == [*status])
    {
        return false;
    }

    let mut image_enter_calls = 0usize;
    for block in &function.blocks {
        if !errors.poll() {
            return false;
        }
        if block.id != function.entry && terminator_targets_block(&block.terminator, function.entry)
        {
            return false;
        }
        for instruction in &block.instructions {
            if !errors.poll() {
                return false;
            }
            if matches!(
                instruction.operation,
                MachineOperation::RuntimeCall {
                    intrinsic: RuntimeIntrinsic::ImageEnter,
                    ..
                }
            ) {
                image_enter_calls = image_enter_calls.saturating_add(1);
            }
        }
    }
    image_enter_calls == 1
}

fn terminator_targets_block(terminator: &MachineTerminator, target: BlockId) -> bool {
    match terminator {
        MachineTerminator::Jump { block, .. } => *block == target,
        MachineTerminator::Branch {
            then_block,
            else_block,
            ..
        } => *then_block == target || *else_block == target,
        MachineTerminator::Switch { cases, default, .. } => {
            *default == target || cases.iter().any(|(_, block, _)| *block == target)
        }
        MachineTerminator::Return(_)
        | MachineTerminator::TailCall { .. }
        | MachineTerminator::Unreachable => false,
    }
}

fn static_test_payload<'a>(
    module: &'a MachineWir,
    function: &MachineFunction,
    arguments: &[ValueId],
    definitions: &[Option<&MachineInstruction>],
) -> Option<&'a [u8]> {
    let [address, size] = arguments else {
        return None;
    };
    let address_definition = definitions.get(address.0 as usize).and_then(|item| *item)?;
    let MachineOperation::GlobalAddress(global_id) = address_definition.operation else {
        return None;
    };
    let global = module.globals.get(global_id.0 as usize)?;
    let section = module.sections.get(global.section.0 as usize)?;
    let MachineImmediate::Bytes(bytes) = &global.initializer else {
        return None;
    };
    let global_ty = module.types.get(global.ty.0 as usize)?;
    let MachineTypeKind::Array { element, length } = global_ty.kind else {
        return None;
    };
    let element_is_byte = module
        .types
        .get(element.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 8 }) && ty.size == 1);
    let size_definition = definitions.get(size.0 as usize).and_then(|item| *item)?;
    let MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le }) =
        &size_definition.operation
    else {
        return None;
    };
    let exact_size = <[u8; 8]>::try_from(bytes_le.as_slice())
        .ok()
        .map(u64::from_le_bytes)
        == u64::try_from(bytes.len()).ok();
    let size_type_matches = function
        .values
        .get(size.0 as usize)
        .is_some_and(|value| value.ty == *ty)
        && module
            .types
            .get(ty.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 64 }));
    (section.kind == SectionKind::ReadOnlyData
        && element_is_byte
        && length == bytes.len() as u64
        && global_ty.size == length
        && exact_size
        && size_type_matches)
        .then_some(bytes.as_slice())
}

fn exact_generated_passing_events(
    events: &[Option<TestEvent>],
    tests: &[MachineTestEntry],
) -> bool {
    let expected = tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2));
    if expected != Some(events.len()) {
        return false;
    }
    let Some(first) = events.first().and_then(Option::as_ref) else {
        return false;
    };
    if first.sequence != 0
        || !matches!(first.kind, TestEventKind::RunStarted { test_count }
            if usize::try_from(test_count).ok() == Some(tests.len()))
    {
        return false;
    }
    for (index, test) in tests.iter().enumerate() {
        let start_index = index * 2 + 1;
        let finish_index = start_index + 1;
        let protocol_id = TestId(test.plan_id);
        if events.get(start_index).and_then(Option::as_ref).is_none_or(|event| {
            event.sequence != start_index as u64
                || !matches!(event.kind, TestEventKind::TestStarted { test } if test == protocol_id)
        }) || events.get(finish_index).and_then(Option::as_ref).is_none_or(|event| {
            event.sequence != finish_index as u64
                || !matches!(event.kind, TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::Passed,
                } if test == protocol_id)
        }) {
            return false;
        }
    }
    let terminal_index = events.len() - 1;
    events.last().and_then(Option::as_ref).is_some_and(|event| {
        event.sequence == terminal_index as u64
            && matches!(event.kind, TestEventKind::RunFinished { passed, failed }
                if usize::try_from(passed).ok() == Some(tests.len()) && failed == 0)
    })
}

#[derive(Debug, Clone, Copy)]
enum ValueDefinitionSite {
    FunctionParameter,
    BlockParameter(usize),
    Instruction { block: usize, index: usize },
}

fn validate_control_flow_and_ssa(
    module: &MachineWir,
    function: &MachineFunction,
    errors: &mut ValidationContext<'_>,
) {
    let block_count = function.blocks.len();
    let Some(entry) = usize::try_from(function.entry.0)
        .ok()
        .filter(|entry| *entry < block_count)
    else {
        return;
    };

    let Some(mut successors) = errors.filled(block_count, Vec::<usize>::new()) else {
        return;
    };
    let Some(mut predecessors) = errors.filled(block_count, Vec::<usize>::new()) else {
        return;
    };
    for (source, block) in function.blocks.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let Some(mut arguments_by_target) = errors.scratch(0) else {
            return;
        };
        let collected = for_each_edge(&block.terminator, |target, arguments| {
            if !errors.poll() {
                return false;
            }
            let Some(target_index) = usize::try_from(target.0)
                .ok()
                .filter(|target| *target < block_count)
            else {
                return true;
            };
            errors.scratch_push(&mut successors[source], target_index)
                && errors.scratch_push(&mut predecessors[target_index], source)
                && errors.scratch_push(&mut arguments_by_target, (target, arguments))
        });
        if !collected
            || !sort_scratch_by(&mut arguments_by_target, errors, &|left, right, _| {
                Some(left.0.cmp(&right.0))
            })
        {
            return;
        }
        for pair in arguments_by_target.windows(2) {
            if !errors.poll() {
                return;
            }
            let Some(same_arguments) = value_slices_equal(pair[0].1, pair[1].1, errors) else {
                return;
            };
            if pair[0].0 == pair[1].0 && !same_arguments {
                errors.push(ValidationError::ConflictingParallelEdgeArguments {
                    function: function.id,
                    from: block.id,
                    to: pair[1].0,
                });
            }
        }
        if !sort_scratch(&mut successors[source], errors) {
            return;
        }
    }
    for incoming in &mut predecessors {
        if !errors.poll() || !sort_scratch(incoming, errors) {
            return;
        }
    }

    let Some(mut reachable) = errors.filled(block_count, false) else {
        return;
    };
    let Some(mut postorder) = errors.scratch(block_count) else {
        return;
    };
    let Some(mut pending) = errors.scratch(0) else {
        return;
    };
    if !errors.scratch_push(&mut pending, (entry, false)) {
        return;
    }
    while let Some((block, expanded)) = pending.pop() {
        if !errors.poll() {
            return;
        }
        if expanded {
            if !errors.scratch_push(&mut postorder, block) {
                return;
            }
            continue;
        }
        if std::mem::replace(&mut reachable[block], true) {
            continue;
        }
        if !errors.scratch_push(&mut pending, (block, true)) {
            return;
        }
        for successor in successors[block].iter().rev() {
            if !errors.poll() {
                return;
            }
            if !reachable[*successor] && !errors.scratch_push(&mut pending, (*successor, false)) {
                return;
            }
        }
    }
    for (block, is_reachable) in reachable.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if !is_reachable {
            errors.push(ValidationError::UnreachableBlock {
                function: function.id,
                block: BlockId(block as u32),
            });
        }
    }

    for index in 0..postorder.len() / 2 {
        if !errors.poll() {
            return;
        }
        let opposite = postorder.len() - 1 - index;
        postorder.swap(index, opposite);
    }
    let Some(mut reverse_postorder) = errors.filled(block_count, usize::MAX) else {
        return;
    };
    for (position, block) in postorder.iter().copied().enumerate() {
        if !errors.poll() {
            return;
        }
        reverse_postorder[block] = position;
    }
    let Some(mut immediate_dominator) = errors.filled(block_count, None) else {
        return;
    };
    immediate_dominator[entry] = Some(entry);
    loop {
        if !errors.poll() {
            return;
        }
        let mut changed = false;
        for block in postorder.iter().copied().skip(1) {
            if !errors.poll() {
                return;
            }
            let mut candidate = None;
            for predecessor in predecessors[block].iter().copied() {
                if !errors.poll() {
                    return;
                }
                if immediate_dominator[predecessor].is_none() {
                    continue;
                }
                candidate = if let Some(candidate) = candidate {
                    let Some(intersection) = intersect_dominators(
                        candidate,
                        predecessor,
                        &immediate_dominator,
                        &reverse_postorder,
                        errors,
                    ) else {
                        return;
                    };
                    Some(intersection)
                } else {
                    Some(predecessor)
                };
            }
            let Some(candidate) = candidate else {
                continue;
            };
            if immediate_dominator[block] != Some(candidate) {
                immediate_dominator[block] = Some(candidate);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let Some(mut definitions) = errors.filled(function.values.len(), None) else {
        return;
    };
    for parameter in &function.parameters {
        if !errors.poll() {
            return;
        }
        record_definition(
            &mut definitions,
            *parameter,
            ValueDefinitionSite::FunctionParameter,
        );
    }
    for (block_index, block) in function.blocks.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        for parameter in &block.parameters {
            if !errors.poll() {
                return;
            }
            record_definition(
                &mut definitions,
                *parameter,
                ValueDefinitionSite::BlockParameter(block_index),
            );
        }
        for (instruction_index, instruction) in block.instructions.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            for result in &instruction.results {
                if !errors.poll() {
                    return;
                }
                record_definition(
                    &mut definitions,
                    *result,
                    ValueDefinitionSite::Instruction {
                        block: block_index,
                        index: instruction_index,
                    },
                );
            }
        }
    }

    for (block_index, block) in function.blocks.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        for (instruction_index, instruction) in block.instructions.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            if !for_each_operation_value(&instruction.operation, |value| {
                validate_value_dominance(
                    function,
                    value,
                    block_index,
                    Some(instruction_index),
                    &definitions,
                    &immediate_dominator,
                    &reachable,
                    errors,
                );
                errors.poll()
            }) {
                return;
            }
        }
        if !for_each_terminator_value(&block.terminator, |value| {
            validate_value_dominance(
                function,
                value,
                block_index,
                None,
                &definitions,
                &immediate_dominator,
                &reachable,
                errors,
            );
            errors.poll()
        }) {
            return;
        }
        if let MachineTerminator::Switch { value, cases, .. } = &block.terminator {
            let bits = function
                .values
                .get(value.0 as usize)
                .and_then(|value| module.types.get(value.ty.0 as usize))
                .and_then(|ty| match ty.kind {
                    MachineTypeKind::Integer { bits } => Some(bits),
                    _ => None,
                });
            if let Some(bits) = bits {
                for (case, _, _) in cases {
                    if !errors.poll() {
                        return;
                    }
                    if bits < 128 && *case >= (1u128 << u32::from(bits)) {
                        errors.push(ValidationError::SwitchCaseOutOfRange {
                            function: function.id,
                            block: block.id,
                            value: *case,
                            bits,
                        });
                    }
                }
            }
        }
    }
}

fn for_each_edge<'a>(
    terminator: &'a MachineTerminator,
    mut visit: impl FnMut(BlockId, &'a [ValueId]) -> bool,
) -> bool {
    match terminator {
        MachineTerminator::Jump { block, arguments } => visit(*block, arguments),
        MachineTerminator::Branch {
            then_block,
            then_arguments,
            else_block,
            else_arguments,
            ..
        } => visit(*then_block, then_arguments) && visit(*else_block, else_arguments),
        MachineTerminator::Switch {
            cases,
            default,
            default_arguments,
            ..
        } => {
            for (_, block, arguments) in cases {
                if !visit(*block, arguments) {
                    return false;
                }
            }
            visit(*default, default_arguments)
        }
        MachineTerminator::Return(_)
        | MachineTerminator::TailCall { .. }
        | MachineTerminator::Unreachable => true,
    }
}

fn intersect_dominators(
    mut left: usize,
    mut right: usize,
    immediate_dominator: &[Option<usize>],
    reverse_postorder: &[usize],
    errors: &mut ValidationContext<'_>,
) -> Option<usize> {
    while left != right {
        if !errors.poll() {
            return None;
        }
        while reverse_postorder[left] > reverse_postorder[right] {
            if !errors.poll() {
                return None;
            }
            left = immediate_dominator[left].unwrap_or(left);
        }
        while reverse_postorder[right] > reverse_postorder[left] {
            if !errors.poll() {
                return None;
            }
            right = immediate_dominator[right].unwrap_or(right);
        }
    }
    Some(left)
}

fn record_definition(
    definitions: &mut [Option<ValueDefinitionSite>],
    value: ValueId,
    site: ValueDefinitionSite,
) {
    if let Some(definition) = definitions.get_mut(value.0 as usize) {
        if definition.is_none() {
            *definition = Some(site);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_value_dominance(
    function: &MachineFunction,
    value: ValueId,
    use_block: usize,
    use_instruction: Option<usize>,
    definitions: &[Option<ValueDefinitionSite>],
    immediate_dominator: &[Option<usize>],
    reachable: &[bool],
    errors: &mut ValidationContext<'_>,
) {
    if !errors.poll() {
        return;
    }
    let Some(definition) = definitions.get(value.0 as usize).and_then(|site| *site) else {
        return;
    };
    let valid = match definition {
        ValueDefinitionSite::FunctionParameter => true,
        ValueDefinitionSite::BlockParameter(block) => {
            block_dominates(block, use_block, immediate_dominator, reachable, errors)
        }
        ValueDefinitionSite::Instruction { block, index } if block == use_block => {
            use_instruction.is_none_or(|use_index| index < use_index)
        }
        ValueDefinitionSite::Instruction { block, .. } => {
            block_dominates(block, use_block, immediate_dominator, reachable, errors)
        }
    };
    if !valid {
        errors.push(ValidationError::NonDominatingValueUse {
            function: function.id,
            value,
            block: BlockId(use_block as u32),
            instruction: use_instruction
                .map(|index| function.blocks[use_block].instructions[index].id),
        });
    }
}

fn block_dominates(
    dominator: usize,
    block: usize,
    immediate_dominator: &[Option<usize>],
    reachable: &[bool],
    errors: &mut ValidationContext<'_>,
) -> bool {
    if !reachable.get(dominator).copied().unwrap_or(false)
        || !reachable.get(block).copied().unwrap_or(false)
    {
        return false;
    }
    let mut cursor = block;
    loop {
        if !errors.poll() {
            return false;
        }
        if cursor == dominator {
            return true;
        }
        let Some(parent) = immediate_dominator.get(cursor).and_then(|parent| *parent) else {
            return false;
        };
        if parent == cursor {
            return false;
        }
        cursor = parent;
    }
}

fn for_each_operation_value(
    operation: &MachineOperation,
    mut visit: impl FnMut(ValueId) -> bool,
) -> bool {
    match operation {
        MachineOperation::Immediate(_)
        | MachineOperation::StackAddress(_)
        | MachineOperation::GlobalAddress(_)
        | MachineOperation::ActorReserve { .. }
        | MachineOperation::ActorReplyRequest { .. }
        | MachineOperation::MailboxReceive { .. }
        | MachineOperation::MailboxDispatch { .. }
        | MachineOperation::Fence(_) => true,
        MachineOperation::Arithmetic { left, right, .. }
        | MachineOperation::CheckedInteger { left, right, .. }
        | MachineOperation::IntegerCompare { left, right, .. }
        | MachineOperation::FloatCompare { left, right, .. } => visit(*left) && visit(*right),
        MachineOperation::Unary { value, .. }
        | MachineOperation::Convert { value, .. }
        | MachineOperation::CheckedConvert { value, .. }
        | MachineOperation::Copy { value }
        | MachineOperation::TestAssert {
            condition: value, ..
        } => visit(*value),
        MachineOperation::MakeEnum { payload, .. } => payload.is_none_or(&mut visit),
        MachineOperation::EnumTag { value } | MachineOperation::EnumPayload { value } => {
            visit(*value)
        }
        MachineOperation::MakeStruct { fields, .. } => fields.iter().copied().all(&mut visit),
        MachineOperation::InsertField {
            aggregate, value, ..
        } => visit(*aggregate) && visit(*value),
        MachineOperation::ExtractField { aggregate, .. } => visit(*aggregate),
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => visit(*condition) && visit(*then_value) && visit(*else_value),
        MachineOperation::AddressOffset {
            base, byte_offset, ..
        } => visit(*base) && visit(*byte_offset),
        MachineOperation::Load { address, .. } => visit(*address),
        MachineOperation::Store { address, value, .. } => visit(*address) && visit(*value),
        MachineOperation::ActorCommit { reservation, .. } => visit(*reservation),
        MachineOperation::ActorReplyResolve { outcome, .. } => visit(*outcome),
        MachineOperation::MemoryCopy {
            destination,
            source,
            bytes,
            ..
        } => visit(*destination) && visit(*source) && visit(*bytes),
        MachineOperation::MemorySet {
            destination,
            byte,
            bytes,
            ..
        } => visit(*destination) && visit(*byte) && visit(*bytes),
        MachineOperation::Call { arguments, .. }
        | MachineOperation::RuntimeCall { arguments, .. } => {
            for argument in arguments {
                if !visit(*argument) {
                    return false;
                }
            }
            true
        }
    }
}

fn for_each_terminator_value(
    terminator: &MachineTerminator,
    mut visit: impl FnMut(ValueId) -> bool,
) -> bool {
    match terminator {
        MachineTerminator::Jump { arguments, .. } => {
            for value in arguments {
                if !visit(*value) {
                    return false;
                }
            }
            true
        }
        MachineTerminator::Branch {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            if !visit(*condition) {
                return false;
            }
            for value in then_arguments.iter().chain(else_arguments) {
                if !visit(*value) {
                    return false;
                }
            }
            true
        }
        MachineTerminator::Switch {
            value,
            cases,
            default_arguments,
            ..
        } => {
            if !visit(*value) {
                return false;
            }
            for (_, _, arguments) in cases {
                for value in arguments {
                    if !visit(*value) {
                        return false;
                    }
                }
            }
            for value in default_arguments {
                if !visit(*value) {
                    return false;
                }
            }
            true
        }
        MachineTerminator::Return(values) => {
            for value in values {
                if !visit(*value) {
                    return false;
                }
            }
            true
        }
        MachineTerminator::TailCall { arguments, .. } => {
            for value in arguments {
                if !visit(*value) {
                    return false;
                }
            }
            true
        }
        MachineTerminator::Unreachable => true,
    }
}

fn validate_operation(
    module: &MachineWir,
    function: &MachineFunction,
    instruction: &MachineInstruction,
    errors: &mut ValidationContext<'_>,
) {
    macro_rules! value {
        ($id:expr) => {
            require_id("instruction value", ($id).0, function.values.len(), errors)
        };
    }
    macro_rules! proof {
        ($facts:expr) => {{
            require_id(
                "backend proof",
                ($facts).proof.0,
                module.proofs.len(),
                errors,
            );
            if ($facts)
                .alignment
                .is_some_and(|alignment| !valid_alignment(alignment))
            {
                errors.push(ValidationError::InvalidBackendFacts(($facts).proof));
            }
        }};
    }
    macro_rules! checked_failure {
        ($failure:expr, $expected:expr) => {{
            if ($failure).kind != $expected || ($failure).flow_function != function.flow_function {
                errors.push(ValidationError::InvalidRecord {
                    kind: "checked scalar failure provenance",
                    id: instruction.id.0,
                });
            }
            if !sorted_contains(&module.runtime.intrinsics, &RuntimeIntrinsic::Fatal, errors) {
                errors.push(ValidationError::UnrequiredRuntimeCall(
                    RuntimeIntrinsic::Fatal,
                ));
            }
        }};
    }
    match &instruction.operation {
        MachineOperation::Immediate(immediate) => validate_immediate(module, immediate, errors),
        MachineOperation::Unary { value: operand, .. } => value!(*operand),
        MachineOperation::Arithmetic { left, right, .. }
        | MachineOperation::IntegerCompare { left, right, .. }
        | MachineOperation::FloatCompare { left, right, .. } => {
            value!(*left);
            value!(*right);
        }
        MachineOperation::CheckedInteger {
            left,
            right,
            failure,
            ..
        } => {
            value!(*left);
            value!(*right);
            checked_failure!(*failure, ScalarFailureKind::Arithmetic);
        }
        MachineOperation::Convert {
            value: source,
            destination,
            ..
        } => {
            value!(*source);
            require_id("conversion type", destination.0, module.types.len(), errors);
        }
        MachineOperation::CheckedConvert {
            value: source,
            destination,
            failure,
            ..
        } => {
            value!(*source);
            require_id(
                "checked conversion type",
                destination.0,
                module.types.len(),
                errors,
            );
            checked_failure!(*failure, ScalarFailureKind::Conversion);
        }
        MachineOperation::Copy { value } => value!(*value),
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            value!(*condition);
            value!(*then_value);
            value!(*else_value);
        }
        MachineOperation::MakeStruct { ty, fields } => {
            require_id("constructed struct type", ty.0, module.types.len(), errors);
            for field in fields {
                value!(*field);
            }
        }
        MachineOperation::InsertField {
            aggregate, value, ..
        } => {
            value!(*aggregate);
            value!(*value);
        }
        MachineOperation::ExtractField { aggregate, .. } => value!(*aggregate),
        MachineOperation::MakeEnum { ty, payload, .. } => {
            require_id("constructed enum type", ty.0, module.types.len(), errors);
            if let Some(payload) = payload {
                value!(*payload);
            }
        }
        MachineOperation::EnumTag { value } | MachineOperation::EnumPayload { value } => {
            value!(*value)
        }
        MachineOperation::AddressOffset {
            base,
            byte_offset,
            facts,
        } => {
            value!(*base);
            value!(*byte_offset);
            proof!(facts);
        }
        MachineOperation::Load {
            address, ty, facts, ..
        } => {
            value!(*address);
            require_id("load type", ty.0, module.types.len(), errors);
            proof!(facts);
        }
        MachineOperation::Store {
            address,
            value: stored,
            facts,
            ..
        } => {
            value!(*address);
            value!(*stored);
            proof!(facts);
        }
        MachineOperation::ActorReserve {
            mailbox,
            method,
            proof: permit,
            failure,
            ..
        } => {
            require_id(
                "actor mailbox global",
                mailbox.0,
                module.globals.len(),
                errors,
            );
            require_id("actor method", method.0, module.functions.len(), errors);
            require_id("actor permit proof", permit.0, module.proofs.len(), errors);
            checked_failure!(*failure, ScalarFailureKind::ActorMailboxFull);
        }
        MachineOperation::ActorCommit {
            reservation,
            mailbox,
            method,
            ..
        } => {
            value!(*reservation);
            require_id(
                "actor mailbox global",
                mailbox.0,
                module.globals.len(),
                errors,
            );
            require_id("actor method", method.0, module.functions.len(), errors);
        }
        MachineOperation::ActorReplyRequest {
            slot,
            mailbox,
            method,
            permit,
            reply,
            failure,
            duplicate_failure,
            ..
        } => {
            require_id(
                "actor reply slot",
                slot.0,
                function.stack_slots.len(),
                errors,
            );
            require_id(
                "actor mailbox global",
                mailbox.0,
                module.globals.len(),
                errors,
            );
            require_id("actor method", method.0, module.functions.len(), errors);
            require_id("actor permit proof", permit.0, module.proofs.len(), errors);
            require_id("actor reply proof", reply.0, module.proofs.len(), errors);
            checked_failure!(*failure, ScalarFailureKind::ActorReplyStateMismatch);
            checked_failure!(
                *duplicate_failure,
                ScalarFailureKind::ActorReplyDuplicateResolve
            );
        }
        MachineOperation::ActorReplyResolve { outcome, reply } => {
            value!(*outcome);
            require_id("actor reply proof", reply.0, module.proofs.len(), errors);
        }
        MachineOperation::MailboxReceive {
            mailbox,
            method,
            failure,
            ..
        } => {
            require_id(
                "actor mailbox global",
                mailbox.0,
                module.globals.len(),
                errors,
            );
            require_id("actor method", method.0, module.functions.len(), errors);
            checked_failure!(*failure, ScalarFailureKind::ActorMailboxMismatch);
        }
        MachineOperation::MailboxDispatch {
            mailbox, method, ..
        } => {
            require_id(
                "actor mailbox global",
                mailbox.0,
                module.globals.len(),
                errors,
            );
            require_id("actor method", method.0, module.functions.len(), errors);
        }
        MachineOperation::MemoryCopy {
            destination,
            source,
            bytes,
            destination_alignment,
            source_alignment,
            proof,
            ..
        } => {
            value!(*destination);
            value!(*source);
            value!(*bytes);
            require_id("memory copy proof", proof.0, module.proofs.len(), errors);
            if !valid_alignment(*destination_alignment) || !valid_alignment(*source_alignment) {
                errors.push(ValidationError::InvalidBackendFacts(*proof));
            }
        }
        MachineOperation::MemorySet {
            destination,
            byte,
            bytes,
            alignment,
        } => {
            value!(*destination);
            value!(*byte);
            value!(*bytes);
            if !valid_alignment(*alignment) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "memory set",
                    id: instruction.id.0,
                });
            }
        }
        MachineOperation::StackAddress(slot) => {
            require_id("stack slot", slot.0, function.stack_slots.len(), errors)
        }
        MachineOperation::GlobalAddress(global) => {
            require_id("global", global.0, module.globals.len(), errors)
        }
        MachineOperation::Call {
            function: callee,
            arguments,
            convention,
        } => {
            require_id("callee", callee.0, module.functions.len(), errors);
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.convention != *convention)
            {
                errors.push(ValidationError::CallingConventionMismatch {
                    caller: function.id,
                    callee: *callee,
                });
            }
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| {
                    matches!(
                        callee.convention,
                        CallingConvention::UefiAarch64 | CallingConvention::InterruptHandler
                    )
                })
            {
                errors.push(ValidationError::ForbiddenDirectCall {
                    caller: function.id,
                    callee: *callee,
                });
            }
            for argument in arguments {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
            }
            validate_machine_call(module, function, instruction, *callee, arguments, errors);
        }
        MachineOperation::RuntimeCall {
            intrinsic,
            arguments,
        } => {
            if *intrinsic == RuntimeIntrinsic::TestAssertionFail {
                errors.push(ValidationError::InvalidTestRuntimeContext {
                    intrinsic: *intrinsic,
                    function: function.id,
                    instruction: instruction.id,
                });
            }
            if !sorted_contains(&module.runtime.intrinsics, intrinsic, errors) {
                errors.push(ValidationError::UnrequiredRuntimeCall(*intrinsic));
            }
            let signature = intrinsic.signature();
            if arguments.len() != signature.parameters.len() {
                errors.push(ValidationError::RuntimeArity {
                    intrinsic: *intrinsic,
                    expected: signature.parameters.len(),
                    actual: arguments.len(),
                });
            }
            for (argument, abi) in arguments.iter().zip(&signature.parameters) {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
                if let Some(value) = function.values.get(argument.0 as usize) {
                    validate_abi_type(module, value.ty, *abi, *intrinsic, errors);
                }
            }
            let expected_results = usize::from(signature.result != AbiType::Unit);
            if instruction.results.len() != expected_results {
                errors.push(ValidationError::RuntimeResultCount {
                    intrinsic: *intrinsic,
                    expected: expected_results,
                    actual: instruction.results.len(),
                });
            } else if let Some(result) = instruction
                .results
                .first()
                .and_then(|id| function.values.get(id.0 as usize))
            {
                validate_abi_type(module, result.ty, signature.result, *intrinsic, errors);
            }
        }
        MachineOperation::TestAssert { condition, failure } => {
            value!(*condition);
            let expression_blank = text_is_blank(&failure.expression, errors).unwrap_or(true);
            let message_blank = failure
                .message
                .as_ref()
                .is_some_and(|message| text_is_blank(message, errors).unwrap_or(true));
            if !sorted_contains(
                &module.runtime.intrinsics,
                &RuntimeIntrinsic::TestAssertionFail,
                errors,
            ) {
                errors.push(ValidationError::UnrequiredRuntimeCall(
                    RuntimeIntrinsic::TestAssertionFail,
                ));
            }
            let message_is_valid = match (&failure.message, failure.message_global) {
                (None, None) => true,
                (Some(message), Some(global)) => {
                    !message_blank
                        && message.len() <= TEST_ASSERTION_MESSAGE_BYTES_MAX
                        && assertion_global_matches(module, global, message)
                        && errors.assertion_global_is_unique(global)
                }
                _ => false,
            };
            let generated_test_context = matches!(
                module
                    .functions
                    .get(module.image_entry.0 as usize)
                    .map(|entry| entry.origin),
                Some(MachineFunctionOrigin::GeneratedTestHarness { .. })
            ) && errors.selected_test_reaches(function.id);
            if module.tests.len() != 1
                || !generated_test_context
                || expression_blank
                || failure.expression.len() > TEST_ASSERTION_EXPRESSION_BYTES_MAX
                || !assertion_global_matches(module, failure.expression_global, &failure.expression)
                || !errors.assertion_global_is_unique(failure.expression_global)
                || failure.message_global == Some(failure.expression_global)
                || !message_is_valid
                || failure.source.range.start > failure.source.range.end
                || instruction.source != Some(failure.source)
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "generated test assertion",
                    id: instruction.id.0,
                });
            }
        }
        MachineOperation::Fence(_) => {}
    }
    validate_operation_types(module, function, instruction, errors);
}

fn assertion_global_matches(module: &MachineWir, id: GlobalId, text: &str) -> bool {
    let Some(global) = module.globals.get(id.0 as usize) else {
        return false;
    };
    let Some(section) = module.sections.get(global.section.0 as usize) else {
        return false;
    };
    let Some(ty) = module.types.get(global.ty.0 as usize) else {
        return false;
    };
    let MachineTypeKind::Array { element, length } = ty.kind else {
        return false;
    };
    let element_is_byte = module
        .types
        .get(element.0 as usize)
        .is_some_and(|element| element.kind == MachineTypeKind::Integer { bits: 8 });
    let MachineImmediate::Bytes(bytes) = &global.initializer else {
        return false;
    };
    section.kind == SectionKind::ReadOnlyData
        && global.alignment == 1
        && length == TEST_ASSERTION_EXPRESSION_BYTES_MAX as u64
        && element_is_byte
        && bytes.len() == TEST_ASSERTION_EXPRESSION_BYTES_MAX
        && bytes.get(..text.len()) == Some(text.as_bytes())
        && bytes
            .get(text.len()..)
            .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
}

fn validate_operation_types(
    module: &MachineWir,
    function: &MachineFunction,
    instruction: &MachineInstruction,
    errors: &mut ValidationContext<'_>,
) {
    let value_ty = |id: ValueId| function.values.get(id.0 as usize).map(|value| value.ty);
    let result_ty = |index: usize| instruction.results.get(index).and_then(|id| value_ty(*id));
    let result_count = instruction.results.len();
    let same = |left: ValueId, right: ValueId| {
        value_ty(left)
            .zip(value_ty(right))
            .is_some_and(|(left, right)| left == right)
    };
    let valid = match &instruction.operation {
        MachineOperation::Immediate(immediate) => {
            result_count == 1
                && result_ty(0).is_some_and(|ty| immediate_matches_type(module, immediate, ty))
        }
        MachineOperation::Unary { op, value } => {
            let ty = value_ty(*value);
            result_count == 1
                && ty == result_ty(0)
                && ty.is_some_and(|ty| match op {
                    MachineUnaryOp::BoolNot => is_bool(module, ty),
                    MachineUnaryOp::BitNot => is_integer(module, ty),
                    MachineUnaryOp::FloatNegate => is_float(module, ty),
                })
        }
        MachineOperation::Arithmetic { op, left, right } => {
            let ty = value_ty(*left);
            let operands_match = same(*left, *right) && ty == result_ty(0);
            let valid_kind = ty
                .and_then(|ty| module.types.get(ty.0 as usize))
                .is_some_and(|ty| match op {
                    ArithmeticOp::FloatAdd
                    | ArithmeticOp::FloatSubtract
                    | ArithmeticOp::FloatMultiply
                    | ArithmeticOp::FloatDivide => {
                        matches!(ty.kind, MachineTypeKind::Float32 | MachineTypeKind::Float64)
                    }
                    _ => matches!(ty.kind, MachineTypeKind::Integer { .. }),
                });
            result_count == 1 && operands_match && valid_kind
        }
        MachineOperation::CheckedInteger { left, right, .. } => {
            let ty = value_ty(*left);
            result_count == 1
                && same(*left, *right)
                && ty == result_ty(0)
                && ty.is_some_and(|ty| is_integer(module, ty))
        }
        MachineOperation::IntegerCompare { left, right, .. } => {
            result_count == 1
                && same(*left, *right)
                && value_ty(*left).is_some_and(|ty| is_integer(module, ty))
                && result_ty(0).is_some_and(|ty| is_bool(module, ty))
        }
        MachineOperation::FloatCompare { left, right, .. } => {
            result_count == 1
                && same(*left, *right)
                && value_ty(*left).is_some_and(|ty| is_float(module, ty))
                && result_ty(0).is_some_and(|ty| is_bool(module, ty))
        }
        MachineOperation::Convert {
            op,
            value,
            destination,
        } => {
            result_count == 1
                && result_ty(0) == Some(*destination)
                && value_ty(*value)
                    .is_some_and(|source| valid_conversion(module, *op, source, *destination))
        }
        MachineOperation::CheckedConvert {
            source,
            destination_kind,
            value,
            destination,
            ..
        } => {
            result_count == 1
                && result_ty(0) == Some(*destination)
                && value_ty(*value)
                    .is_some_and(|ty| checked_numeric_kind_matches(module, *source, ty))
                && checked_numeric_kind_matches(module, *destination_kind, *destination)
        }
        MachineOperation::Copy { value } => result_count == 1 && value_ty(*value) == result_ty(0),
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            result_count == 1
                && value_ty(*condition).is_some_and(|ty| is_bool(module, ty))
                && same(*then_value, *else_value)
                && value_ty(*then_value) == result_ty(0)
        }
        MachineOperation::MakeStruct { ty, fields } => {
            result_count == 1
                && result_ty(0) == Some(*ty)
                && module.types.get(ty.0 as usize).is_some_and(|record| {
                    matches!(&record.kind, MachineTypeKind::Struct {
                        fields: expected,
                        packed: false,
                    } if !expected.is_empty()
                        && expected.len() == fields.len()
                        && expected.iter().zip(fields).all(|(field, value)| {
                            value_ty(*value) == Some(field.ty)
                        }))
                })
        }
        MachineOperation::InsertField {
            aggregate,
            field,
            value,
        } => {
            result_count == 1
                && value_ty(*aggregate) == result_ty(0)
                && value_ty(*aggregate)
                    .and_then(|ty| module.types.get(ty.0 as usize))
                    .and_then(|record| match &record.kind {
                        MachineTypeKind::Struct {
                            fields,
                            packed: false,
                        } => fields.get(*field as usize).map(|field| field.ty),
                        _ => None,
                    })
                    .is_some_and(|expected| value_ty(*value) == Some(expected))
        }
        MachineOperation::ExtractField { aggregate, field } => {
            result_count == 1
                && value_ty(*aggregate)
                    .and_then(|ty| module.types.get(ty.0 as usize))
                    .and_then(|record| match &record.kind {
                        MachineTypeKind::Struct {
                            fields,
                            packed: false,
                        } => fields.get(*field as usize).map(|field| field.ty),
                        _ => None,
                    })
                    .is_some_and(|expected| result_ty(0) == Some(expected))
        }
        MachineOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => {
            result_count == 1
                && result_ty(0) == Some(*ty)
                && module.types.get(ty.0 as usize).is_some_and(|record| {
                    matches!(&record.kind, MachineTypeKind::TaggedEnum {
                        payload: expected,
                        variants,
                        payload_variants,
                        ..
                    } if u16::from(*variant) < *variants
                        && payload_variants.get(usize::from(*variant)).copied()
                            == Some(payload.is_some())
                            && match payload {
                                None => true,
                                Some(payload) => expected
                                    .is_some_and(|expected| value_ty(*payload) == Some(expected)),
                            })
                })
        }
        MachineOperation::EnumTag { value } => {
            result_count == 1
                && value_ty(*value)
                    .and_then(|ty| module.types.get(ty.0 as usize))
                    .and_then(|record| match &record.kind {
                        MachineTypeKind::TaggedEnum { tag, .. } => Some(*tag),
                        _ => None,
                    })
                    .is_some_and(|expected| result_ty(0) == Some(expected))
        }
        MachineOperation::EnumPayload { value } => {
            result_count == 1
                && value_ty(*value)
                    .and_then(|ty| module.types.get(ty.0 as usize))
                    .and_then(|record| match &record.kind {
                        MachineTypeKind::TaggedEnum {
                            payload: Some(payload),
                            payload_variants,
                            ..
                        } if payload_variants.iter().any(|present| *present) => Some(*payload),
                        _ => None,
                    })
                    .is_some_and(|expected| result_ty(0) == Some(expected))
        }
        MachineOperation::AddressOffset {
            base, byte_offset, ..
        } => {
            result_count == 1
                && value_ty(*base).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*byte_offset).is_some_and(|ty| is_integer(module, ty))
                && value_ty(*base) == result_ty(0)
        }
        MachineOperation::Load { address, ty, .. } => {
            result_count == 1
                && result_ty(0) == Some(*ty)
                && value_ty(*address).is_some_and(|address| pointer_accepts(module, address, *ty))
        }
        MachineOperation::Store { address, value, .. } => {
            result_count == 0
                && value_ty(*address)
                    .zip(value_ty(*value))
                    .is_some_and(|(address, value)| pointer_accepts(module, address, value))
        }
        MachineOperation::ActorReserve { .. } => {
            result_count == 1 && result_ty(0).is_some_and(|ty| is_pointer(module, ty))
        }
        MachineOperation::ActorCommit { reservation, .. } => {
            result_count == 0 && value_ty(*reservation).is_some_and(|ty| is_pointer(module, ty))
        }
        MachineOperation::ActorReplyRequest { slot, method, .. } => {
            let result_is_u64 = result_ty(0)
                .and_then(|ty| module.types.get(ty.0 as usize))
                .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 64 });
            let target_returns_u64 = module
                .functions
                .get(method.0 as usize)
                .and_then(|target| module.types.get(target.result.0 as usize))
                .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 64 });
            let slot_is_exact = function
                .stack_slots
                .get(slot.0 as usize)
                .is_some_and(|slot| slot.size == 16 && slot.alignment == 8);
            result_count == 1 && result_is_u64 && target_returns_u64 && slot_is_exact
        }
        MachineOperation::ActorReplyResolve { outcome, .. } => {
            result_count == 0
                && value_ty(*outcome)
                    .and_then(|ty| module.types.get(ty.0 as usize))
                    .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 64 })
        }
        MachineOperation::MailboxReceive { .. } | MachineOperation::MailboxDispatch { .. } => {
            result_count == 0
        }
        MachineOperation::MemoryCopy {
            destination,
            source,
            bytes,
            ..
        } => {
            result_count == 0
                && value_ty(*destination).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*source).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*bytes).is_some_and(|ty| is_integer(module, ty))
        }
        MachineOperation::MemorySet {
            destination,
            byte,
            bytes,
            ..
        } => {
            result_count == 0
                && value_ty(*destination).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*byte).is_some_and(|ty| is_bool(module, ty))
                && value_ty(*bytes).is_some_and(|ty| is_integer(module, ty))
        }
        MachineOperation::Fence(_) => result_count == 0,
        MachineOperation::TestAssert { condition, .. } => {
            result_count == 0 && value_ty(*condition).is_some_and(|ty| is_bool(module, ty))
        }
        MachineOperation::StackAddress(_) => {
            result_count == 1 && result_ty(0).is_some_and(|ty| is_pointer(module, ty))
        }
        MachineOperation::GlobalAddress(global) => {
            result_count == 1
                && result_ty(0).is_some_and(|pointer| {
                    module
                        .globals
                        .get(global.0 as usize)
                        .is_some_and(|global| pointer_accepts(module, pointer, global.ty))
                })
        }
        // Arity and result types for these operations are validated against
        // their declared callee/runtime signatures by the main validator.
        MachineOperation::Call { .. } | MachineOperation::RuntimeCall { .. } => true,
    };
    if !valid {
        errors.push(ValidationError::OperationTypeMismatch {
            function: function.id,
            instruction: instruction.id,
        });
    }
}

fn immediate_matches_type(
    module: &MachineWir,
    immediate: &MachineImmediate,
    expected: MachineTypeId,
) -> bool {
    let Some(ty) = module.types.get(expected.0 as usize) else {
        return false;
    };
    match immediate {
        MachineImmediate::Integer {
            ty: immediate_ty,
            bytes_le,
        } => {
            *immediate_ty == expected
                && matches!(ty.kind, MachineTypeKind::Integer { .. })
                && integer_bytes_are_canonical(ty, bytes_le)
        }
        MachineImmediate::Float32(_) => matches!(ty.kind, MachineTypeKind::Float32),
        MachineImmediate::Float64(_) => matches!(ty.kind, MachineTypeKind::Float64),
        MachineImmediate::Null(immediate_ty) => {
            *immediate_ty == expected && matches!(ty.kind, MachineTypeKind::Pointer { .. })
        }
        MachineImmediate::Zero(immediate_ty) => {
            *immediate_ty == expected && !matches!(ty.kind, MachineTypeKind::Void)
        }
        MachineImmediate::SymbolAddress(_) => matches!(ty.kind, MachineTypeKind::Pointer { .. }),
        MachineImmediate::Bytes(bytes) => {
            !matches!(ty.kind, MachineTypeKind::Void) && bytes.len() as u64 == ty.size
        }
    }
}

fn integer_bytes_are_canonical(ty: &MachineType, bytes: &[u8]) -> bool {
    let MachineTypeKind::Integer { bits } = ty.kind else {
        return false;
    };
    let expected = usize::from(bits.div_ceil(8));
    if bytes.len() != expected {
        return false;
    }
    let used = bits % 8;
    used == 0
        || bytes
            .last()
            .is_some_and(|last| *last & !((1u8 << used) - 1) == 0)
}

fn is_integer(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { .. }))
}

fn checked_numeric_kind_matches(
    module: &MachineWir,
    kind: CheckedNumericKind,
    ty: MachineTypeId,
) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| match kind {
            CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger => {
                matches!(ty.kind, MachineTypeKind::Integer { .. })
            }
            CheckedNumericKind::Float32 => matches!(ty.kind, MachineTypeKind::Float32),
            CheckedNumericKind::Float64 => matches!(ty.kind, MachineTypeKind::Float64),
        })
}

fn is_bool(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 8 }))
}

fn is_float(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Float32 | MachineTypeKind::Float64))
}

fn is_pointer(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Pointer { .. }))
}

fn pointer_accepts(module: &MachineWir, pointer: MachineTypeId, value: MachineTypeId) -> bool {
    module
        .types
        .get(pointer.0 as usize)
        .is_some_and(|pointer| match pointer.kind {
            MachineTypeKind::Pointer { pointee, .. } => {
                pointee.is_none_or(|pointee| pointee == value)
            }
            _ => false,
        })
}

fn valid_conversion(
    module: &MachineWir,
    op: ConversionOp,
    source: MachineTypeId,
    destination: MachineTypeId,
) -> bool {
    let Some(source_ty) = module.types.get(source.0 as usize) else {
        return false;
    };
    let Some(destination_ty) = module.types.get(destination.0 as usize) else {
        return false;
    };
    let integer_bits = |ty: &MachineType| match ty.kind {
        MachineTypeKind::Integer { bits } => Some(bits),
        _ => None,
    };
    match op {
        ConversionOp::IntegerTruncate => integer_bits(source_ty)
            .zip(integer_bits(destination_ty))
            .is_some_and(|(source, destination)| destination < source),
        ConversionOp::ZeroExtend | ConversionOp::SignExtend => integer_bits(source_ty)
            .zip(integer_bits(destination_ty))
            .is_some_and(|(source, destination)| destination > source),
        ConversionOp::FloatTruncate => {
            matches!(source_ty.kind, MachineTypeKind::Float64)
                && matches!(destination_ty.kind, MachineTypeKind::Float32)
        }
        ConversionOp::FloatExtend => {
            matches!(source_ty.kind, MachineTypeKind::Float32)
                && matches!(destination_ty.kind, MachineTypeKind::Float64)
        }
        ConversionOp::UnsignedIntegerToFloat | ConversionOp::SignedIntegerToFloat => {
            integer_bits(source_ty).is_some()
                && matches!(
                    destination_ty.kind,
                    MachineTypeKind::Float32 | MachineTypeKind::Float64
                )
        }
        ConversionOp::FloatToUnsignedInteger | ConversionOp::FloatToSignedInteger => {
            matches!(
                source_ty.kind,
                MachineTypeKind::Float32 | MachineTypeKind::Float64
            ) && integer_bits(destination_ty).is_some()
        }
        ConversionOp::PointerToInteger => {
            matches!(source_ty.kind, MachineTypeKind::Pointer { .. })
                && integer_bits(destination_ty) == Some(module.layout.pointer_bits)
        }
        ConversionOp::IntegerToPointer => {
            integer_bits(source_ty) == Some(module.layout.pointer_bits)
                && matches!(destination_ty.kind, MachineTypeKind::Pointer { .. })
        }
        ConversionOp::Bitcast => {
            source_ty.size == destination_ty.size
                && scalar_or_vector(source_ty)
                && scalar_or_vector(destination_ty)
        }
    }
}

fn scalar_or_vector(ty: &MachineType) -> bool {
    matches!(
        ty.kind,
        MachineTypeKind::Integer { .. }
            | MachineTypeKind::Float32
            | MachineTypeKind::Float64
            | MachineTypeKind::Pointer { .. }
            | MachineTypeKind::Vector { .. }
    )
}

fn validate_abi_type(
    module: &MachineWir,
    ty: MachineTypeId,
    abi: AbiType,
    intrinsic: RuntimeIntrinsic,
    errors: &mut ValidationContext<'_>,
) {
    let Some(ty) = module.types.get(ty.0 as usize) else {
        return;
    };
    let valid = match abi {
        AbiType::Unit => matches!(ty.kind, MachineTypeKind::Void),
        AbiType::Bool | AbiType::U8 => matches!(ty.kind, MachineTypeKind::Integer { bits: 8 }),
        AbiType::U32 => matches!(ty.kind, MachineTypeKind::Integer { bits: 32 }),
        AbiType::U64 | AbiType::Usize | AbiType::Status => {
            matches!(ty.kind, MachineTypeKind::Integer { bits: 64 })
        }
        AbiType::Address => matches!(ty.kind, MachineTypeKind::Pointer { .. }),
    };
    if !valid {
        errors.push(ValidationError::RuntimeTypeMismatch {
            intrinsic,
            abi,
            ty: ty.id,
        });
    }
}

fn validate_terminator(
    module: &MachineWir,
    function: &MachineFunction,
    terminator: &MachineTerminator,
    errors: &mut ValidationContext<'_>,
) {
    macro_rules! value {
        ($id:expr) => {
            require_id("terminator value", ($id).0, function.values.len(), errors)
        };
    }
    macro_rules! block {
        ($id:expr) => {
            require_id("terminator block", ($id).0, function.blocks.len(), errors)
        };
    }
    match terminator {
        MachineTerminator::Jump {
            block: target,
            arguments,
        } => {
            block!(*target);
            for argument in arguments {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
            }
            if !block_arguments_match(function, *target, arguments, errors) {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => {
            value!(*condition);
            block!(*then_block);
            block!(*else_block);
            for argument in then_arguments.iter().chain(else_arguments) {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
            }
            if function
                .values
                .get(condition.0 as usize)
                .is_none_or(|value| !is_bool(module, value.ty))
                || !block_arguments_match(function, *then_block, then_arguments, errors)
                || !block_arguments_match(function, *else_block, else_arguments, errors)
            {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Switch {
            value: switched,
            cases,
            default,
            default_arguments,
        } => {
            value!(*switched);
            block!(*default);
            for argument in default_arguments {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
            }
            for (_, target, arguments) in cases {
                if !errors.poll() {
                    return;
                }
                block!(*target);
                for argument in arguments {
                    if !errors.poll() {
                        return;
                    }
                    value!(*argument);
                }
            }
            let switched_is_integer = function
                .values
                .get(switched.0 as usize)
                .is_some_and(|value| is_integer(module, value.ty));
            let Some(mut case_values) = errors.scratch(cases.len()) else {
                return;
            };
            for (value, _, _) in cases {
                if !errors.scratch_push(&mut case_values, *value) {
                    return;
                }
            }
            if !sort_scratch(&mut case_values, errors) {
                return;
            }
            let mut unique_cases = true;
            for pair in case_values.windows(2) {
                if !errors.poll() {
                    return;
                }
                unique_cases &= pair[0] != pair[1];
            }
            let mut case_arguments_match = true;
            for (_, target, arguments) in cases {
                if !errors.poll() {
                    return;
                }
                case_arguments_match &= block_arguments_match(function, *target, arguments, errors);
            }
            if !switched_is_integer
                || !unique_cases
                || !block_arguments_match(function, *default, default_arguments, errors)
                || !case_arguments_match
            {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Return(values) => {
            for value in values {
                if !errors.poll() {
                    return;
                }
                value!(*value);
            }
            let expected = usize::from(
                module
                    .types
                    .get(function.result.0 as usize)
                    .is_some_and(|ty| !matches!(ty.kind, MachineTypeKind::Void)),
            );
            if values.len() != expected
                || (expected == 1
                    && function
                        .values
                        .get(values[0].0 as usize)
                        .is_some_and(|value| value.ty != function.result))
            {
                errors.push(ValidationError::ReturnMismatch(function.id));
            }
        }
        MachineTerminator::TailCall {
            function: callee,
            arguments,
        } => {
            require_id("tail callee", callee.0, module.functions.len(), errors);
            for argument in arguments {
                if !errors.poll() {
                    return;
                }
                value!(*argument);
            }
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| {
                    callee.convention != function.convention
                        || matches!(
                            callee.convention,
                            CallingConvention::UefiAarch64 | CallingConvention::InterruptHandler
                        )
                })
            {
                errors.push(ValidationError::ForbiddenTailCall {
                    caller: function.id,
                    callee: *callee,
                });
            }
            validate_machine_call_shape(module, function, *callee, arguments, errors);
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.result != function.result)
            {
                errors.push(ValidationError::CallResultMismatch {
                    caller: function.id,
                    callee: *callee,
                });
            }
        }
        MachineTerminator::Unreachable => {}
    }
}

fn block_arguments_match(
    function: &MachineFunction,
    target: BlockId,
    arguments: &[ValueId],
    errors: &mut ValidationContext<'_>,
) -> bool {
    let Some(block) = function.blocks.get(target.0 as usize) else {
        return false;
    };
    if arguments.len() != block.parameters.len() {
        return false;
    }
    for (argument, parameter) in arguments.iter().zip(&block.parameters) {
        if !errors.poll()
            || function
                .values
                .get(argument.0 as usize)
                .zip(function.values.get(parameter.0 as usize))
                .is_none_or(|(argument, parameter)| argument.ty != parameter.ty)
        {
            return false;
        }
    }
    true
}

fn value_slices_equal(
    left: &[ValueId],
    right: &[ValueId],
    errors: &mut ValidationContext<'_>,
) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (left, right) in left.iter().zip(right) {
        if !errors.poll() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

fn validate_machine_call(
    module: &MachineWir,
    caller: &MachineFunction,
    instruction: &MachineInstruction,
    callee: FunctionId,
    arguments: &[ValueId],
    errors: &mut ValidationContext<'_>,
) {
    validate_machine_call_shape(module, caller, callee, arguments, errors);
    let Some(callee) = module.functions.get(callee.0 as usize) else {
        return;
    };
    let expected = usize::from(
        module
            .types
            .get(callee.result.0 as usize)
            .is_some_and(|ty| !matches!(ty.kind, MachineTypeKind::Void)),
    );
    if instruction.results.len() != expected
        || (expected == 1
            && caller
                .values
                .get(instruction.results[0].0 as usize)
                .is_some_and(|value| value.ty != callee.result))
    {
        errors.push(ValidationError::CallResultMismatch {
            caller: caller.id,
            callee: callee.id,
        });
    }
}

fn validate_machine_call_shape(
    module: &MachineWir,
    caller: &MachineFunction,
    callee: FunctionId,
    arguments: &[ValueId],
    errors: &mut ValidationContext<'_>,
) {
    let Some(callee) = module.functions.get(callee.0 as usize) else {
        return;
    };
    if arguments.len() != callee.parameters.len() {
        errors.push(ValidationError::CallArity {
            caller: caller.id,
            callee: callee.id,
            expected: callee.parameters.len(),
            actual: arguments.len(),
        });
        return;
    }
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        if !errors.poll() {
            return;
        }
        let types = caller
            .values
            .get(argument.0 as usize)
            .zip(callee.values.get(parameter.0 as usize))
            .map(|(argument, parameter)| (argument.ty, parameter.ty));
        if types.is_some_and(|(argument, parameter)| argument != parameter) {
            errors.push(ValidationError::CallTypeMismatch {
                caller: caller.id,
                callee: callee.id,
            });
        }
    }
}

fn validate_image_entry(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut ValidationContext<'_>,
) {
    let entry = &module.functions[module.image_entry.0 as usize];
    let valid_symbol = if let Some(symbol) = module.symbols.get(entry.symbol.0 as usize) {
        let Some(name_matches) = text_equals(&symbol.name, target.backend().entry_symbol(), errors)
        else {
            return;
        };
        symbol.visibility == SymbolVisibility::ImageEntry
            && name_matches
            && symbol.definition == SymbolDefinition::Function(entry.id)
    } else {
        false
    };
    let mut valid_parameters = entry.parameters.len() == 2;
    for parameter in &entry.parameters {
        if !errors.poll() {
            return;
        }
        valid_parameters &= entry
            .values
            .get(parameter.0 as usize)
            .and_then(|value| module.types.get(value.ty.0 as usize))
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Pointer { .. }));
    }
    let valid_signature = valid_parameters
        && module
            .types
            .get(entry.result.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 64 }));
    if entry.linkage != Linkage::ExportedEntry
        || entry.convention != CallingConvention::UefiAarch64
        || !valid_symbol
        || !valid_signature
    {
        errors.push(ValidationError::InvalidImageEntry(module.image_entry));
    }
    let mut image_entries = 0usize;
    for symbol in &module.symbols {
        if !errors.poll() {
            return;
        }
        if symbol.visibility == SymbolVisibility::ImageEntry {
            image_entries = image_entries.saturating_add(1);
        }
    }
    if image_entries != 1 {
        errors.push(ValidationError::ImageEntrySymbolCount(image_entries));
    }
}

fn validate_interrupt_entries(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut ValidationContext<'_>,
) {
    let mut canonical = true;
    for pair in module.interrupts.windows(2) {
        if !errors.poll() {
            return;
        }
        let Some(ordering) = text_compare(&pair[0].target_binding, &pair[1].target_binding, errors)
        else {
            return;
        };
        canonical &= ordering == std::cmp::Ordering::Less;
    }
    if !canonical {
        errors.push(ValidationError::NonCanonicalInterruptEntries);
    }
    let Some(mut global_ids) = errors.scratch(module.interrupts.len()) else {
        return;
    };
    let Some(mut duplicate_global) = errors.filled(module.interrupts.len(), false) else {
        return;
    };
    let Some(mut handler_counts) = errors.filled(module.functions.len(), 0usize) else {
        return;
    };
    for (index, interrupt) in module.interrupts.iter().enumerate() {
        if !errors.scratch_push(&mut global_ids, (interrupt.global_id, index)) {
            return;
        }
        if let Some(count) = handler_counts.get_mut(interrupt.handler.0 as usize) {
            *count = count.saturating_add(1);
        }
    }
    if !sort_scratch(&mut global_ids, errors) {
        return;
    }
    for pair in global_ids.windows(2) {
        if !errors.poll() {
            return;
        }
        if pair[0].0 == pair[1].0 {
            duplicate_global[pair[0].1] = true;
            duplicate_global[pair[1].1] = true;
        }
    }
    for (index, interrupt) in module.interrupts.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let bindings = target.semantic().mmio_bindings();
        let (mut start, mut end) = (0usize, bindings.len());
        let mut found = None;
        while start < end {
            if !errors.poll() {
                return;
            }
            let middle = start + (end - start) / 2;
            let Some(ordering) = text_compare(
                bindings[middle].name.as_str(),
                &interrupt.target_binding,
                errors,
            ) else {
                return;
            };
            match ordering {
                std::cmp::Ordering::Less => start = middle + 1,
                std::cmp::Ordering::Equal => {
                    found = bindings.get(middle);
                    break;
                }
                std::cmp::Ordering::Greater => end = middle,
            }
        }
        let matches_target = found
            .and_then(|binding| binding.interrupt)
            .is_some_and(|binding| {
                binding.domain == InterruptDomain::GicSpi
                    && binding.line == interrupt.line
                    && binding.global_id == interrupt.global_id
            });
        let Some(blank_binding) = text_is_blank(&interrupt.target_binding, errors) else {
            return;
        };
        let unique_route = !blank_binding
            && interrupt.line.checked_add(32) == Some(interrupt.global_id)
            && matches_target
            && !duplicate_global[index]
            && handler_counts.get(interrupt.handler.0 as usize) == Some(&1);
        let valid_handler = module
            .functions
            .get(interrupt.handler.0 as usize)
            .is_some_and(|handler| {
                let private_symbol = module
                    .symbols
                    .get(handler.symbol.0 as usize)
                    .is_some_and(|symbol| symbol.visibility == SymbolVisibility::Private);
                let void_result = module
                    .types
                    .get(handler.result.0 as usize)
                    .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void));
                let isr_safe_proofs = handler
                    .proofs
                    .iter()
                    .filter(|proof| {
                        module
                            .proofs
                            .get(proof.0 as usize)
                            .is_some_and(|proof| proof.kind == BackendProofKind::IsrSafe)
                    })
                    .count();
                handler.linkage == Linkage::Private
                    && handler.convention == CallingConvention::InterruptHandler
                    && handler.role == MachineFunctionRole::Isr(interrupt.device)
                    && handler.parameters.is_empty()
                    && void_result
                    && private_symbol
                    && isr_safe_proofs == 1
            });
        if !unique_route || !valid_handler {
            errors.push(ValidationError::InvalidInterruptEntry(interrupt.id));
        }
    }
    for handler in &module.functions {
        if !errors.poll() {
            return;
        }
        if handler.convention != CallingConvention::InterruptHandler {
            continue;
        }
        let count = handler_counts
            .get(handler.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if count != 1 {
            errors.push(ValidationError::InterruptHandlerRouteCount {
                handler: handler.id,
                count,
            });
        }
        validate_interrupt_call_graph(module, handler.id, errors);
    }
}

fn validate_interrupt_metadata(module: &MachineWir, errors: &mut ValidationContext<'_>) {
    let expected_bytes = u64::try_from(module.interrupts.len())
        .ok()
        .and_then(|count| count.checked_mul(u64::from(INTERRUPT_ROUTE_LAYOUT.record_bytes)))
        .and_then(|records| records.checked_add(u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)));
    let mut section_count = 0usize;
    let mut route_section = None;
    for section in &module.sections {
        if !errors.poll() {
            return;
        }
        if section.name == INTERRUPT_ROUTE_SECTION {
            section_count = section_count.saturating_add(1);
            route_section = Some(section);
        }
    }
    let valid_section = section_count == 1
        && route_section.is_some_and(|section| {
            section.kind == SectionKind::RuntimeMetadata
                && section.alignment == INTERRUPT_ROUTE_LAYOUT.table_alignment
                && Some(section.reserved_bytes) == expected_bytes
        });
    let mut symbol_count = 0usize;
    let mut route_symbol = None;
    for symbol in &module.symbols {
        if !errors.poll() {
            return;
        }
        if symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL {
            symbol_count = symbol_count.saturating_add(1);
            route_symbol = Some(symbol);
        }
    }
    let valid_symbol = section_count == 1
        && symbol_count == 1
        && route_section
            .zip(route_symbol)
            .is_some_and(|(section, symbol)| {
                symbol.visibility == SymbolVisibility::RuntimeMetadata
                    && symbol.definition
                        == SymbolDefinition::SectionOffset {
                            section: section.id,
                            offset: 0,
                            bytes: section.reserved_bytes,
                        }
            });
    if !valid_section || !valid_symbol {
        errors.push(ValidationError::InvalidInterruptMetadata);
    }
}

fn validate_interrupt_call_graph(
    module: &MachineWir,
    handler: FunctionId,
    errors: &mut ValidationContext<'_>,
) {
    let Some(mut pending) = errors.scratch(0) else {
        return;
    };
    if !errors.scratch_push(&mut pending, handler) {
        return;
    }
    let Some(mut visited) = errors.filled(module.functions.len(), false) else {
        return;
    };
    while let Some(function_id) = pending.pop() {
        if !errors.poll() {
            return;
        }
        let Some(function) = module.functions.get(function_id.0 as usize) else {
            continue;
        };
        if std::mem::replace(&mut visited[function_id.0 as usize], true) {
            continue;
        }
        let has_forbidden_type = function_requires_simd(module, function, errors);
        if !errors.poll() {
            return;
        }
        let mut forbidden_operation = false;
        for block in &function.blocks {
            if !errors.poll() {
                return;
            }
            for instruction in &block.instructions {
                if !errors.poll() {
                    return;
                }
                match &instruction.operation {
                    MachineOperation::Arithmetic {
                        op:
                            ArithmeticOp::FloatAdd
                            | ArithmeticOp::FloatSubtract
                            | ArithmeticOp::FloatMultiply
                            | ArithmeticOp::FloatDivide,
                        ..
                    }
                    | MachineOperation::FloatCompare { .. }
                    | MachineOperation::Immediate(
                        MachineImmediate::Float32(_) | MachineImmediate::Float64(_),
                    ) => forbidden_operation = true,
                    MachineOperation::Convert {
                        op:
                            ConversionOp::FloatTruncate
                            | ConversionOp::FloatExtend
                            | ConversionOp::UnsignedIntegerToFloat
                            | ConversionOp::SignedIntegerToFloat
                            | ConversionOp::FloatToUnsignedInteger
                            | ConversionOp::FloatToSignedInteger,
                        ..
                    } => forbidden_operation = true,
                    MachineOperation::RuntimeCall { intrinsic, .. }
                        if *intrinsic != RuntimeIntrinsic::Fatal =>
                    {
                        forbidden_operation = true;
                    }
                    MachineOperation::Call {
                        function: callee, ..
                    } => {
                        let true = errors.scratch_push(&mut pending, *callee) else {
                            return;
                        };
                    }
                    _ => {}
                }
            }
            if let MachineTerminator::TailCall {
                function: callee, ..
            } = block.terminator
            {
                if !errors.scratch_push(&mut pending, callee) {
                    return;
                }
            }
        }
        if has_forbidden_type || forbidden_operation {
            errors.push(ValidationError::InvalidInterruptReachableCode {
                handler,
                function: function_id,
            });
        }
    }
}

fn function_requires_simd(
    module: &MachineWir,
    function: &MachineFunction,
    errors: &mut ValidationContext<'_>,
) -> bool {
    let Some(mut visited) = errors.filled(module.types.len(), false) else {
        return false;
    };
    let Some(mut pending) = errors.scratch(0) else {
        return false;
    };
    if !errors.scratch_push(&mut pending, function.result) {
        return false;
    }
    for value in &function.values {
        if !errors.scratch_push(&mut pending, value.ty) {
            return false;
        }
    }
    while let Some(ty) = pending.pop() {
        if !errors.poll() {
            return false;
        }
        let Some(record) = module.types.get(ty.0 as usize) else {
            continue;
        };
        if std::mem::replace(&mut visited[ty.0 as usize], true) {
            continue;
        }
        match &record.kind {
            MachineTypeKind::Float32
            | MachineTypeKind::Float64
            | MachineTypeKind::Vector { .. } => {
                return true;
            }
            MachineTypeKind::Array { element, .. } => {
                if !errors.scratch_push(&mut pending, *element) {
                    return false;
                }
            }
            MachineTypeKind::Struct { fields, .. } => {
                for field in fields {
                    if !errors.scratch_push(&mut pending, field.ty) {
                        return false;
                    }
                }
            }
            MachineTypeKind::TaggedEnum { tag, payload, .. } => {
                if !errors.scratch_push(&mut pending, *tag)
                    || payload.is_some_and(|payload| !errors.scratch_push(&mut pending, payload))
                {
                    return false;
                }
            }
            MachineTypeKind::Function { parameters, result } => {
                if !errors.scratch_push(&mut pending, *result) {
                    return false;
                }
                for parameter in parameters {
                    if !errors.scratch_push(&mut pending, *parameter) {
                        return false;
                    }
                }
            }
            MachineTypeKind::Void
            | MachineTypeKind::Integer { .. }
            | MachineTypeKind::Pointer { .. } => {}
        }
    }
    false
}

fn text_is_blank(value: &str, errors: &mut ValidationContext<'_>) -> Option<bool> {
    for character in value.chars() {
        if !errors.poll() {
            return None;
        }
        if !character.is_whitespace() {
            return Some(false);
        }
    }
    Some(true)
}

fn text_equals(left: &str, right: &str, errors: &mut ValidationContext<'_>) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (left, right) in left.bytes().zip(right.bytes()) {
        if !errors.poll() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

fn text_compare(
    left: &str,
    right: &str,
    errors: &mut ValidationContext<'_>,
) -> Option<std::cmp::Ordering> {
    for (left, right) in left.bytes().zip(right.bytes()) {
        if !errors.poll() {
            return None;
        }
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Some(ordering),
        }
    }
    Some(left.len().cmp(&right.len()))
}

fn valid_alignment(alignment: u32) -> bool {
    alignment.is_power_of_two()
}

fn sorted_contains<T: Ord>(values: &[T], needle: &T, errors: &mut ValidationContext<'_>) -> bool {
    let (mut start, mut end) = (0usize, values.len());
    while start < end {
        if !errors.poll() {
            return false;
        }
        let middle = start + (end - start) / 2;
        match values[middle].cmp(needle) {
            std::cmp::Ordering::Less => start = middle + 1,
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Greater => end = middle,
        }
    }
    false
}

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut ValidationContext<'_>) {
    if id as usize >= length {
        errors.push(ValidationError::UnknownReference { kind, id });
    }
}

fn define_value(
    function: FunctionId,
    value: ValueId,
    definitions: &mut [u8],
    errors: &mut ValidationContext<'_>,
) {
    let Some(count) = definitions.get_mut(value.0 as usize) else {
        errors.push(ValidationError::UnknownValue { function, value });
        return;
    };
    *count = count.saturating_add(1);
}

fn require_unique_names<'a>(
    kind: &'static str,
    names: impl IntoIterator<Item = &'a str>,
    errors: &mut ValidationContext<'_>,
) {
    let Some(mut scratch) = errors.scratch(0) else {
        return;
    };
    for name in names {
        if !errors.scratch_push(&mut scratch, name) {
            return;
        }
    }
    if !sort_scratch_by(&mut scratch, errors, &|left, right, errors| {
        text_compare(left, right, errors)
    }) {
        return;
    }
    for pair in scratch.windows(2) {
        if !errors.poll() {
            return;
        }
        let Some(equal) = text_equals(pair[0], pair[1], errors) else {
            return;
        };
        if equal {
            errors.push(ValidationError::DuplicateName(kind));
            return;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMachineWir(MachineWir);

impl ValidatedMachineWir {
    #[must_use]
    pub fn as_wir(&self) -> &MachineWir {
        &self.0
    }

    #[must_use]
    pub fn into_wir(self) -> MachineWir {
        self.0
    }
}

fn check_dense(
    kind: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationContext<'_>,
) {
    for (expected, actual) in ids.into_iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if actual as usize != expected {
            errors.push(ValidationError::NonDenseId {
                kind,
                expected,
                actual,
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidLimits,
    Cancelled,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    TooManyErrors {
        limit: u32,
    },
    TargetPackage(TargetError),
    UnsupportedVersion(u32),
    MissingImageName,
    RuntimeAbi(RuntimeAbiError),
    NonDenseId {
        kind: &'static str,
        expected: usize,
        actual: u32,
    },
    UnknownReference {
        kind: &'static str,
        id: u32,
    },
    UnknownValue {
        function: FunctionId,
        value: ValueId,
    },
    ValueDefinitionCount {
        function: FunctionId,
        value: ValueId,
        definitions: u8,
    },
    InvalidRecord {
        kind: &'static str,
        id: u32,
    },
    DuplicateName(&'static str),
    InvalidAarch64Target,
    InvalidDataLayout,
    SymbolDefinitionMismatch(SymbolId),
    DefinitionSymbolCount {
        kind: &'static str,
        id: u32,
        count: usize,
    },
    CallingConventionMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    InvalidFunctionAbi(FunctionId),
    InvalidFunctionOrigin(FunctionId),
    InvalidActivationPlan(MachineActivationId),
    InvalidRegionStorage(MachineRegionStorageId),
    ForbiddenDirectCall {
        caller: FunctionId,
        callee: FunctionId,
    },
    ForbiddenTailCall {
        caller: FunctionId,
        callee: FunctionId,
    },
    CallArity {
        caller: FunctionId,
        callee: FunctionId,
        expected: usize,
        actual: usize,
    },
    CallTypeMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    CallResultMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    OperationTypeMismatch {
        function: FunctionId,
        instruction: InstructionId,
    },
    UnreachableBlock {
        function: FunctionId,
        block: BlockId,
    },
    NonDominatingValueUse {
        function: FunctionId,
        value: ValueId,
        block: BlockId,
        instruction: Option<InstructionId>,
    },
    ConflictingParallelEdgeArguments {
        function: FunctionId,
        from: BlockId,
        to: BlockId,
    },
    SwitchCaseOutOfRange {
        function: FunctionId,
        block: BlockId,
        value: u128,
        bits: u16,
    },
    ControlFlowTypeMismatch(FunctionId),
    ReturnMismatch(FunctionId),
    InvalidGlobalInitializer(GlobalId),
    NonReturningRuntimeFallthrough {
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidTestRuntimeContext {
        intrinsic: RuntimeIntrinsic,
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidImageEnterContext {
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidImageEnterPrologue(FunctionId),
    InvalidStaticTestPayload {
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidTestEmitStatusContract {
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidRuntimeSymbol {
        intrinsic: RuntimeIntrinsic,
    },
    RuntimeSymbolCount {
        intrinsic: RuntimeIntrinsic,
        count: usize,
    },
    UnexpectedRuntimeSymbol(RuntimeIntrinsic),
    UnrequiredRuntimeCall(RuntimeIntrinsic),
    UnusedRuntimeIntrinsic(RuntimeIntrinsic),
    RuntimeArity {
        intrinsic: RuntimeIntrinsic,
        expected: usize,
        actual: usize,
    },
    RuntimeResultCount {
        intrinsic: RuntimeIntrinsic,
        expected: usize,
        actual: usize,
    },
    RuntimeTypeMismatch {
        intrinsic: RuntimeIntrinsic,
        abi: AbiType,
        ty: MachineTypeId,
    },
    InvalidBackendFacts(ProofId),
    UnknownImageEntry(FunctionId),
    InvalidImageEntry(FunctionId),
    ImageEntrySymbolCount(usize),
    InvalidSymbolVisibility(SymbolId),
    NonCanonicalInterruptEntries,
    InvalidInterruptEntry(InterruptEntryId),
    InterruptHandlerRouteCount {
        handler: FunctionId,
        count: usize,
    },
    InvalidInterruptReachableCode {
        handler: FunctionId,
        function: FunctionId,
    },
    InvalidInterruptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MachineWir validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use wrela_build_model::{LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_source::{FileId, TextRange};

    fn fixture() -> (MachineWir, TargetPackage) {
        let digest = Sha256Digest::from_bytes([7; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        let module = MachineWir {
            version: MACHINE_WIR_VERSION,
            name: "fixture".to_owned(),
            build: BuildIdentity {
                compiler: Sha256Digest::from_bytes([1; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: digest,
                standard_library: Sha256Digest::from_bytes([2; 32]),
                source_graph: Sha256Digest::from_bytes([3; 32]),
                request: Sha256Digest::from_bytes([4; 32]),
                profile: Sha256Digest::from_bytes([5; 32]),
            },
            target: MachineTarget {
                identity: target.identity().as_str().to_owned(),
                llvm_triple: target.backend().llvm_triple().to_owned(),
                data_layout: target.backend().llvm_data_layout().to_owned(),
                cpu: target.backend().llvm_cpu().to_owned(),
                features: target.backend().llvm_features().to_vec(),
                coff_machine: target.backend().coff_machine().to_owned(),
            },
            layout: DataLayout {
                pointer_bits: 64,
                pointer_alignment: 8,
                stack_alignment: 16,
                aggregate_alignment: 8,
                maximum_object_alignment: 16,
                endianness: Endianness::Little,
            },
            runtime: RuntimeRequirements::new(vec![RuntimeIntrinsic::ImageEnter]),
            types: vec![
                MachineType {
                    id: MachineTypeId(0),
                    kind: MachineTypeKind::Void,
                    size: 0,
                    alignment: 1,
                    source_name: None,
                },
                MachineType {
                    id: MachineTypeId(1),
                    kind: MachineTypeKind::Pointer {
                        address_space: 0,
                        pointee: None,
                    },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
                MachineType {
                    id: MachineTypeId(2),
                    kind: MachineTypeKind::Integer { bits: 64 },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
            ],
            sections: vec![
                Section {
                    id: SectionId(0),
                    name: ".text".to_owned(),
                    kind: SectionKind::Code,
                    alignment: 16,
                    reserved_bytes: 4096,
                    owner: "image".to_owned(),
                },
                Section {
                    id: SectionId(1),
                    name: INTERRUPT_ROUTE_SECTION.to_owned(),
                    kind: SectionKind::RuntimeMetadata,
                    alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
                    reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    owner: "runtime".to_owned(),
                },
            ],
            symbols: vec![
                Symbol {
                    id: SymbolId(0),
                    name: "wrela_image_entry".to_owned(),
                    visibility: SymbolVisibility::ImageEntry,
                    definition: SymbolDefinition::Function(FunctionId(0)),
                },
                Symbol {
                    id: SymbolId(1),
                    name: RuntimeIntrinsic::ImageEnter.symbol_name().to_owned(),
                    visibility: SymbolVisibility::Runtime,
                    definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter),
                },
                Symbol {
                    id: SymbolId(2),
                    name: INTERRUPT_ROUTE_TABLE_SYMBOL.to_owned(),
                    visibility: SymbolVisibility::RuntimeMetadata,
                    definition: SymbolDefinition::SectionOffset {
                        section: SectionId(1),
                        offset: 0,
                        bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    },
                },
            ],
            globals: Vec::new(),
            functions: vec![MachineFunction {
                id: FunctionId(0),
                flow_function: 0,
                origin: MachineFunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 0,
                },
                role: MachineFunctionRole::ImageEntry,
                symbol: SymbolId(0),
                section: SectionId(0),
                linkage: Linkage::ExportedEntry,
                convention: CallingConvention::UefiAarch64,
                parameters: vec![ValueId(0), ValueId(1)],
                result: MachineTypeId(2),
                proofs: Vec::new(),
                values: vec![
                    MachineValue {
                        id: ValueId(0),
                        ty: MachineTypeId(1),
                        source_name: None,
                    },
                    MachineValue {
                        id: ValueId(1),
                        ty: MachineTypeId(1),
                        source_name: None,
                    },
                    MachineValue {
                        id: ValueId(2),
                        ty: MachineTypeId(2),
                        source_name: None,
                    },
                    MachineValue {
                        id: ValueId(3),
                        ty: MachineTypeId(2),
                        source_name: None,
                    },
                ],
                stack_slots: Vec::new(),
                blocks: vec![
                    MachineBlock {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: vec![MachineInstruction {
                            id: InstructionId(0),
                            results: vec![ValueId(2)],
                            operation: MachineOperation::Immediate(MachineImmediate::Integer {
                                ty: MachineTypeId(2),
                                bytes_le: vec![0; 8],
                            }),
                            source: None,
                        }],
                        terminator: MachineTerminator::Return(vec![ValueId(2)]),
                    },
                    MachineBlock {
                        id: BlockId(1),
                        parameters: Vec::new(),
                        instructions: vec![MachineInstruction {
                            id: InstructionId(1),
                            results: vec![ValueId(3)],
                            operation: MachineOperation::RuntimeCall {
                                intrinsic: RuntimeIntrinsic::ImageEnter,
                                arguments: vec![ValueId(0), ValueId(1)],
                            },
                            source: None,
                        }],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(3),
                            cases: vec![(0, BlockId(0), Vec::new())],
                            default: BlockId(2),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(2),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(3)]),
                    },
                ],
                entry: BlockId(1),
                stack_bytes: 0,
                source: None,
            }],
            activations: Vec::new(),
            schedulers: Vec::new(),
            region_storage: Vec::new(),
            interrupts: Vec::new(),
            tests: Vec::new(),
            proofs: Vec::new(),
            image_entry: FunctionId(0),
        };
        (module, target)
    }

    fn closed_enum_fixture(variants: u16) -> (MachineWir, TargetPackage) {
        let (mut module, target) = fixture();
        module.types.push(MachineType {
            id: MachineTypeId(3),
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: Some("u8".to_owned()),
        });
        module.types.push(MachineType {
            id: MachineTypeId(4),
            kind: MachineTypeKind::TaggedEnum {
                tag: MachineTypeId(3),
                payload: Some(MachineTypeId(3)),
                variants,
                payload_variants: vec![true; usize::from(variants)],
            },
            size: 2,
            alignment: 1,
            source_name: Some("LocalResult".to_owned()),
        });
        module.symbols.push(Symbol {
            id: SymbolId(3),
            name: "__wrela_fn_1".to_owned(),
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Function(FunctionId(1)),
        });
        module.functions.push(MachineFunction {
            id: FunctionId(1),
            flow_function: 1,
            origin: MachineFunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: MachineFunctionRole::Ordinary,
            symbol: SymbolId(3),
            section: SectionId(0),
            linkage: Linkage::Private,
            convention: CallingConvention::Internal,
            parameters: vec![ValueId(0)],
            result: MachineTypeId(3),
            proofs: Vec::new(),
            values: vec![
                MachineValue {
                    id: ValueId(0),
                    ty: MachineTypeId(3),
                    source_name: Some("payload".to_owned()),
                },
                MachineValue {
                    id: ValueId(1),
                    ty: MachineTypeId(4),
                    source_name: Some("result".to_owned()),
                },
                MachineValue {
                    id: ValueId(2),
                    ty: MachineTypeId(3),
                    source_name: Some("tag".to_owned()),
                },
                MachineValue {
                    id: ValueId(3),
                    ty: MachineTypeId(3),
                    source_name: Some("projected".to_owned()),
                },
            ],
            stack_slots: Vec::new(),
            blocks: vec![MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    MachineInstruction {
                        id: InstructionId(0),
                        results: vec![ValueId(1)],
                        operation: MachineOperation::MakeEnum {
                            ty: MachineTypeId(4),
                            variant: u8::try_from(variants.saturating_sub(1).min(255))
                                .expect("bounded variant"),
                            payload: Some(ValueId(0)),
                        },
                        source: None,
                    },
                    MachineInstruction {
                        id: InstructionId(1),
                        results: vec![ValueId(2)],
                        operation: MachineOperation::EnumTag { value: ValueId(1) },
                        source: None,
                    },
                    MachineInstruction {
                        id: InstructionId(2),
                        results: vec![ValueId(3)],
                        operation: MachineOperation::EnumPayload { value: ValueId(1) },
                        source: None,
                    },
                ],
                terminator: MachineTerminator::Return(vec![ValueId(3)]),
            }],
            entry: BlockId(0),
            stack_bytes: 0,
            source: Some(Span {
                file: FileId(0),
                range: TextRange { start: 0, end: 0 },
            }),
        });
        (module, target)
    }

    fn native_struct_fixture() -> (MachineWir, TargetPackage) {
        let (mut module, target) = fixture();
        module.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 32 },
                size: 4,
                alignment: 4,
                source_name: Some("u32".to_owned()),
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Struct {
                    fields: vec![
                        MachineField {
                            ty: MachineTypeId(3),
                            offset: 0,
                        },
                        MachineField {
                            ty: MachineTypeId(2),
                            offset: 8,
                        },
                    ],
                    packed: false,
                },
                size: 16,
                alignment: 8,
                source_name: Some("Pair".to_owned()),
            },
        ]);
        let function = &mut module.functions[0];
        function.values.extend([
            MachineValue {
                id: ValueId(4),
                ty: MachineTypeId(3),
                source_name: None,
            },
            MachineValue {
                id: ValueId(5),
                ty: MachineTypeId(2),
                source_name: None,
            },
            MachineValue {
                id: ValueId(6),
                ty: MachineTypeId(4),
                source_name: None,
            },
            MachineValue {
                id: ValueId(7),
                ty: MachineTypeId(4),
                source_name: None,
            },
            MachineValue {
                id: ValueId(8),
                ty: MachineTypeId(2),
                source_name: None,
            },
        ]);
        function.blocks[0].instructions.extend([
            MachineInstruction {
                id: InstructionId(1),
                results: vec![ValueId(4)],
                operation: MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: MachineTypeId(3),
                    bytes_le: vec![1, 0, 0, 0],
                }),
                source: None,
            },
            MachineInstruction {
                id: InstructionId(2),
                results: vec![ValueId(5)],
                operation: MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: MachineTypeId(2),
                    bytes_le: vec![2, 0, 0, 0, 0, 0, 0, 0],
                }),
                source: None,
            },
            MachineInstruction {
                id: InstructionId(3),
                results: vec![ValueId(6)],
                operation: MachineOperation::MakeStruct {
                    ty: MachineTypeId(4),
                    fields: vec![ValueId(4), ValueId(5)],
                },
                source: None,
            },
            MachineInstruction {
                id: InstructionId(4),
                results: vec![ValueId(7)],
                operation: MachineOperation::InsertField {
                    aggregate: ValueId(6),
                    field: 1,
                    value: ValueId(5),
                },
                source: None,
            },
            MachineInstruction {
                id: InstructionId(5),
                results: vec![ValueId(8)],
                operation: MachineOperation::ExtractField {
                    aggregate: ValueId(7),
                    field: 1,
                },
                source: None,
            },
        ]);
        function.blocks[1].instructions[0].id = InstructionId(6);
        (module, target)
    }

    #[test]
    fn unpacked_struct_operations_validate_exact_field_types_and_layout() {
        let (module, target) = native_struct_fixture();
        module
            .clone()
            .validate_for_target(&target)
            .expect("canonical unpacked struct operations");

        let mut wrong_field = module.clone();
        let MachineOperation::InsertField { field, .. } =
            &mut wrong_field.functions[0].blocks[0].instructions[4].operation
        else {
            panic!("fixture field insertion")
        };
        *field = 0;
        let errors = wrong_field
            .validate_for_target(&target)
            .expect_err("field value type substitution must fail");
        assert!(errors.0.contains(&ValidationError::OperationTypeMismatch {
            function: FunctionId(0),
            instruction: InstructionId(4),
        }));

        let mut packed_module = module;
        let MachineTypeKind::Struct { packed, .. } = &mut packed_module.types[4].kind else {
            panic!("fixture struct type")
        };
        *packed = true;
        assert!(
            packed_module
                .validate_for_target(&target)
                .expect_err("packed struct operations stay unsupported")
                .0
                .contains(&ValidationError::OperationTypeMismatch {
                    function: FunctionId(0),
                    instruction: InstructionId(3),
                })
        );

        let mut empty = native_struct_fixture().0;
        empty.types[4].kind = MachineTypeKind::Struct {
            fields: Vec::new(),
            packed: false,
        };
        empty.types[4].size = 0;
        empty.types[4].alignment = 1;
        let make = &mut empty.functions[0].blocks[0].instructions[3];
        make.operation = MachineOperation::MakeStruct {
            ty: MachineTypeId(4),
            fields: Vec::new(),
        };
        assert!(
            empty
                .validate_for_target(&target)
                .expect_err("empty first-class struct construction must fail")
                .0
                .contains(&ValidationError::OperationTypeMismatch {
                    function: FunctionId(0),
                    instruction: InstructionId(3),
                })
        );

        let mut gapped = native_struct_fixture().0;
        let MachineTypeKind::Struct { fields, .. } = &mut gapped.types[4].kind else {
            panic!("fixture struct type")
        };
        fields[1].ty = MachineTypeId(3);
        fields[1].offset = 8;
        gapped.types[4].alignment = 4;
        let errors = gapped
            .validate_for_target(&target)
            .expect_err("unpacked struct gaps must not diverge from LLVM layout");
        assert!(errors.0.contains(&ValidationError::InvalidRecord {
            kind: "struct field",
            id: 4,
        }));
    }

    fn generated_test_fixture() -> (MachineWir, TargetPackage) {
        let (mut module, target) = fixture();
        module.runtime = RuntimeRequirements::new(vec![
            RuntimeIntrinsic::ImageEnter,
            RuntimeIntrinsic::TestEmit,
            RuntimeIntrinsic::TestFinish,
        ]);
        module.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 8 },
                size: 1,
                alignment: 1,
                source_name: None,
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: 4,
                },
                size: 4,
                alignment: 1,
                source_name: None,
            },
            MachineType {
                id: MachineTypeId(5),
                kind: MachineTypeKind::Integer { bits: 32 },
                size: 4,
                alignment: 4,
                source_name: None,
            },
        ]);
        module.sections.push(Section {
            id: SectionId(2),
            name: ".rdata.wrela.test".to_owned(),
            kind: SectionKind::ReadOnlyData,
            alignment: 1,
            reserved_bytes: 4,
            owner: "generated-test-harness".to_owned(),
        });
        module.symbols.extend([
            Symbol {
                id: SymbolId(3),
                name: "__wrela_test_frame_0".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(0)),
            },
            Symbol {
                id: SymbolId(4),
                name: RuntimeIntrinsic::TestEmit.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::TestEmit),
            },
            Symbol {
                id: SymbolId(5),
                name: RuntimeIntrinsic::TestFinish.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::TestFinish),
            },
        ]);
        module.globals.push(MachineGlobal {
            id: GlobalId(0),
            symbol: SymbolId(3),
            ty: MachineTypeId(4),
            section: SectionId(2),
            offset: 0,
            alignment: 1,
            initializer: MachineImmediate::Bytes(vec![0x5a; 4]),
        });
        module.functions[0].origin = MachineFunctionOrigin::GeneratedTestHarness {
            semantic_function: 0,
            group: 0,
        };
        module.functions[0].values = vec![
            MachineValue {
                id: ValueId(0),
                ty: MachineTypeId(1),
                source_name: None,
            },
            MachineValue {
                id: ValueId(1),
                ty: MachineTypeId(1),
                source_name: None,
            },
            MachineValue {
                id: ValueId(2),
                ty: MachineTypeId(1),
                source_name: None,
            },
            MachineValue {
                id: ValueId(3),
                ty: MachineTypeId(2),
                source_name: None,
            },
            MachineValue {
                id: ValueId(4),
                ty: MachineTypeId(2),
                source_name: None,
            },
            MachineValue {
                id: ValueId(5),
                ty: MachineTypeId(5),
                source_name: None,
            },
            MachineValue {
                id: ValueId(6),
                ty: MachineTypeId(2),
                source_name: None,
            },
        ];
        module.functions[0].blocks = vec![
            MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    MachineInstruction {
                        id: InstructionId(0),
                        results: vec![ValueId(2)],
                        operation: MachineOperation::GlobalAddress(GlobalId(0)),
                        source: None,
                    },
                    MachineInstruction {
                        id: InstructionId(1),
                        results: vec![ValueId(3)],
                        operation: MachineOperation::Immediate(MachineImmediate::Integer {
                            ty: MachineTypeId(2),
                            bytes_le: 4u64.to_le_bytes().to_vec(),
                        }),
                        source: None,
                    },
                    MachineInstruction {
                        id: InstructionId(2),
                        results: vec![ValueId(4)],
                        operation: MachineOperation::RuntimeCall {
                            intrinsic: RuntimeIntrinsic::TestEmit,
                            arguments: vec![ValueId(2), ValueId(3)],
                        },
                        source: None,
                    },
                ],
                terminator: MachineTerminator::Switch {
                    value: ValueId(4),
                    cases: vec![(0, BlockId(2), Vec::new())],
                    default: BlockId(1),
                    default_arguments: Vec::new(),
                },
            },
            MachineBlock {
                id: BlockId(1),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(vec![ValueId(4)]),
            },
            MachineBlock {
                id: BlockId(2),
                parameters: Vec::new(),
                instructions: vec![
                    MachineInstruction {
                        id: InstructionId(3),
                        results: vec![ValueId(5)],
                        operation: MachineOperation::Immediate(MachineImmediate::Integer {
                            ty: MachineTypeId(5),
                            bytes_le: vec![0; 4],
                        }),
                        source: None,
                    },
                    MachineInstruction {
                        id: InstructionId(4),
                        results: Vec::new(),
                        operation: MachineOperation::RuntimeCall {
                            intrinsic: RuntimeIntrinsic::TestFinish,
                            arguments: vec![ValueId(5)],
                        },
                        source: None,
                    },
                ],
                terminator: MachineTerminator::Unreachable,
            },
            MachineBlock {
                id: BlockId(3),
                parameters: Vec::new(),
                instructions: vec![MachineInstruction {
                    id: InstructionId(5),
                    results: vec![ValueId(6)],
                    operation: MachineOperation::RuntimeCall {
                        intrinsic: RuntimeIntrinsic::ImageEnter,
                        arguments: vec![ValueId(0), ValueId(1)],
                    },
                    source: None,
                }],
                terminator: MachineTerminator::Switch {
                    value: ValueId(6),
                    cases: vec![(0, BlockId(0), Vec::new())],
                    default: BlockId(4),
                    default_arguments: Vec::new(),
                },
            },
            MachineBlock {
                id: BlockId(4),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(vec![ValueId(6)]),
            },
        ];
        module.functions[0].entry = BlockId(3);
        (module, target)
    }

    #[test]
    fn minimal_module_seals_against_exact_target() {
        let (module, target) = fixture();
        module
            .validate_for_target(&target)
            .expect("valid MachineWir fixture");
    }

    #[test]
    fn closed_enum_accepts_exact_bounds_and_rejects_layout_and_operation_substitution() {
        let (one, target) = closed_enum_fixture(1);
        one.validate_for_target(&target).expect("one-variant enum");
        let (maximum, target) = closed_enum_fixture(256);
        maximum
            .validate_for_target(&target)
            .expect("256-variant enum");
        for variants in [0, 257] {
            let (module, target) = closed_enum_fixture(variants);
            assert!(module.validate_for_target(&target).is_err());
        }

        let (mut wrong_layout, target) = closed_enum_fixture(2);
        wrong_layout.types[4].size = 1;
        assert!(wrong_layout.validate_for_target(&target).is_err());

        let (mut wrong_variant, target) = closed_enum_fixture(2);
        let MachineOperation::MakeEnum { variant, .. } =
            &mut wrong_variant.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *variant = 2;
        assert!(wrong_variant.validate_for_target(&target).is_err());

        let (mut wrong_tag, target) = closed_enum_fixture(2);
        wrong_tag.functions[1].values[2].ty = MachineTypeId(0);
        assert!(wrong_tag.validate_for_target(&target).is_err());

        let (mut wrong_payload, target) = closed_enum_fixture(2);
        wrong_payload.functions[1].values[3].ty = MachineTypeId(0);
        assert!(wrong_payload.validate_for_target(&target).is_err());

        let (mut mixed_arity, target) = closed_enum_fixture(2);
        let MachineTypeKind::TaggedEnum {
            payload_variants, ..
        } = &mut mixed_arity.types[4].kind
        else {
            unreachable!();
        };
        payload_variants[0] = false;
        mixed_arity
            .clone()
            .validate_for_target(&target)
            .expect("unit plus unary machine enum is canonical");
        let (exact, usage) = exact_validation_policy(&mixed_arity);
        mixed_arity
            .clone()
            .validate_with_limits(&target, exact, &|| false)
            .expect("exact mixed-arity validation bound");
        let one_under = ValidationLimits {
            model_edges: usage.model_edges - 1,
            ..exact
        };
        assert_eq!(
            mixed_arity
                .clone()
                .validate_with_limits(&target, one_under, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: usage.model_edges - 1,
            })
        );
        let polls = Cell::new(0_u64);
        mixed_arity
            .clone()
            .validate_with_limits(&target, exact, &|| {
                polls.set(polls.get() + 1);
                false
            })
            .expect("measure mixed-arity cancellation polls");
        let cancellation_at = polls.get() - 1;
        let polls = Cell::new(0_u64);
        assert_eq!(
            mixed_arity
                .clone()
                .validate_with_limits(&target, exact, &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next >= cancellation_at
                }),
            Err(ValidationFailure::Cancelled)
        );
        let mut wrong_presence = mixed_arity.clone();
        let MachineOperation::MakeEnum { variant, .. } =
            &mut wrong_presence.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *variant = 0;
        assert!(wrong_presence.validate_for_target(&target).is_err());
        let MachineOperation::MakeEnum { payload, .. } =
            &mut mixed_arity.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = None;
        assert!(mixed_arity.validate_for_target(&target).is_err());

        let (mut all_unit, target) = closed_enum_fixture(2);
        all_unit.types[4].size = 1;
        all_unit.types[4].alignment = 1;
        let MachineTypeKind::TaggedEnum {
            payload,
            payload_variants,
            ..
        } = &mut all_unit.types[4].kind
        else {
            unreachable!();
        };
        *payload = None;
        payload_variants.fill(false);
        let MachineOperation::MakeEnum { payload, .. } =
            &mut all_unit.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = None;
        all_unit.functions[1].blocks[0].instructions.remove(2);
        all_unit.functions[1].values.remove(3);
        all_unit.functions[1].blocks[0].terminator = MachineTerminator::Return(vec![ValueId(2)]);
        all_unit
            .clone()
            .validate_for_target(&target)
            .expect("all-unit enum has a one-byte tag-only representation");

        let (exact, usage) = exact_validation_policy(&all_unit);
        all_unit
            .clone()
            .validate_with_limits(&target, exact, &|| false)
            .expect("exact all-unit validation bound");
        let one_under = ValidationLimits {
            model_edges: usage.model_edges - 1,
            ..exact
        };
        assert_eq!(
            all_unit
                .clone()
                .validate_with_limits(&target, one_under, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: usage.model_edges - 1,
            })
        );
        let polls = Cell::new(0_u64);
        all_unit
            .clone()
            .validate_with_limits(&target, exact, &|| {
                polls.set(polls.get() + 1);
                false
            })
            .expect("measure all-unit cancellation polls");
        let cancellation_at = polls.get() - 1;
        let polls = Cell::new(0_u64);
        assert_eq!(
            all_unit.clone().validate_with_limits(&target, exact, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next >= cancellation_at
            }),
            Err(ValidationFailure::Cancelled)
        );

        let mut forged_type_payload = all_unit.clone();
        let MachineTypeKind::TaggedEnum { payload, .. } = &mut forged_type_payload.types[4].kind
        else {
            unreachable!();
        };
        *payload = Some(MachineTypeId(3));
        assert!(forged_type_payload.validate_for_target(&target).is_err());

        let mut forged_constructor_payload = all_unit.clone();
        let MachineOperation::MakeEnum { payload, .. } =
            &mut forged_constructor_payload.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = Some(ValueId(0));
        assert!(
            forged_constructor_payload
                .validate_for_target(&target)
                .is_err()
        );

        let mut forged_projection = all_unit;
        forged_projection.functions[1].values.push(MachineValue {
            id: ValueId(3),
            ty: MachineTypeId(3),
            source_name: Some("forged-projected".to_owned()),
        });
        forged_projection.functions[1].blocks[0]
            .instructions
            .push(MachineInstruction {
                id: InstructionId(2),
                results: vec![ValueId(3)],
                operation: MachineOperation::EnumPayload { value: ValueId(1) },
                source: None,
            });
        assert!(forged_projection.validate_for_target(&target).is_err());
    }

    #[test]
    fn generated_image_entry_runtime_prologue_fails_closed_under_exact_mutations() {
        let (baseline, target) = fixture();
        let rejects_prologue = |module: MachineWir| {
            let errors = module
                .validate_for_target(&target)
                .expect_err("malformed generated image-entry prologue");
            assert!(
                errors
                    .0
                    .contains(&ValidationError::InvalidImageEnterPrologue(FunctionId(0))),
                "missing exact prologue diagnostic: {:?}",
                errors.0
            );
            errors
        };

        let mut omitted = baseline.clone();
        omitted.functions[0].blocks[1].instructions.clear();
        rejects_prologue(omitted);

        let mut duplicate = baseline.clone();
        let mut duplicate_call = duplicate.functions[0].blocks[1].instructions[0].clone();
        duplicate_call.id = InstructionId(2);
        duplicate.functions[0].blocks[2]
            .instructions
            .push(duplicate_call);
        let errors = rejects_prologue(duplicate);
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::InvalidImageEnterContext {
                function: FunctionId(0),
                instruction: InstructionId(2),
            }
        )));

        let mut wrong_context = baseline.clone();
        let mut moved = wrong_context.functions[0].blocks[1].instructions.remove(0);
        moved.id = InstructionId(1);
        wrong_context.functions[0].blocks[0]
            .instructions
            .push(moved);
        let errors = rejects_prologue(wrong_context);
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidImageEnterContext { .. }))
        );

        let mut wrong_function = baseline.clone();
        wrong_function.symbols.push(Symbol {
            id: SymbolId(3),
            name: "__wrong_image_enter_caller".to_owned(),
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Function(FunctionId(1)),
        });
        wrong_function.functions.push(MachineFunction {
            id: FunctionId(1),
            flow_function: 1,
            origin: MachineFunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: MachineFunctionRole::Ordinary,
            symbol: SymbolId(3),
            section: SectionId(0),
            linkage: Linkage::Private,
            convention: CallingConvention::Internal,
            parameters: vec![ValueId(0), ValueId(1)],
            result: MachineTypeId(2),
            proofs: Vec::new(),
            values: vec![
                MachineValue {
                    id: ValueId(0),
                    ty: MachineTypeId(1),
                    source_name: None,
                },
                MachineValue {
                    id: ValueId(1),
                    ty: MachineTypeId(1),
                    source_name: None,
                },
                MachineValue {
                    id: ValueId(2),
                    ty: MachineTypeId(2),
                    source_name: None,
                },
            ],
            stack_slots: Vec::new(),
            blocks: vec![MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![MachineInstruction {
                    id: InstructionId(0),
                    results: vec![ValueId(2)],
                    operation: MachineOperation::RuntimeCall {
                        intrinsic: RuntimeIntrinsic::ImageEnter,
                        arguments: vec![ValueId(0), ValueId(1)],
                    },
                    source: None,
                }],
                terminator: MachineTerminator::Return(vec![ValueId(2)]),
            }],
            entry: BlockId(0),
            stack_bytes: 0,
            source: Some(Span {
                file: FileId(0),
                range: TextRange { start: 0, end: 1 },
            }),
        });
        let errors = wrong_function
            .validate_for_target(&target)
            .expect_err("ImageEnter outside the generated image entry");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidImageEnterContext {
                    function: FunctionId(1),
                    instruction: InstructionId(0),
                })
        );

        let mut swapped_arguments = baseline.clone();
        let MachineOperation::RuntimeCall { arguments, .. } =
            &mut swapped_arguments.functions[0].blocks[1].instructions[0].operation
        else {
            panic!("canonical image-enter call")
        };
        arguments.swap(0, 1);
        rejects_prologue(swapped_arguments);

        let mut bypass = baseline.clone();
        bypass.functions[0].blocks[0].terminator = MachineTerminator::Jump {
            block: BlockId(1),
            arguments: Vec::new(),
        };
        rejects_prologue(bypass);

        let mut wrong_success = baseline.clone();
        let MachineTerminator::Switch { cases, .. } =
            &mut wrong_success.functions[0].blocks[1].terminator
        else {
            panic!("canonical image-enter switch")
        };
        cases[0].0 = 1;
        rejects_prologue(wrong_success);

        let mut remapped_failure = baseline.clone();
        remapped_failure.functions[0].blocks[2].terminator =
            MachineTerminator::Return(vec![ValueId(2)]);
        rejects_prologue(remapped_failure);

        let mut missing_requirement = baseline.clone();
        missing_requirement.runtime.intrinsics.clear();
        let errors = missing_requirement
            .validate_for_target(&target)
            .expect_err("ImageEnter call without its exact runtime requirement");
        assert!(errors.0.contains(&ValidationError::UnrequiredRuntimeCall(
            RuntimeIntrinsic::ImageEnter
        )));
        assert!(errors.0.contains(&ValidationError::UnexpectedRuntimeSymbol(
            RuntimeIntrinsic::ImageEnter
        )));

        let mut missing_symbol = baseline.clone();
        missing_symbol.symbols.remove(1);
        for (id, symbol) in missing_symbol.symbols.iter_mut().enumerate() {
            symbol.id = SymbolId(u32::try_from(id).expect("small symbol fixture"));
        }
        let errors = missing_symbol
            .validate_for_target(&target)
            .expect_err("required ImageEnter symbol omitted");
        assert!(errors.0.contains(&ValidationError::RuntimeSymbolCount {
            intrinsic: RuntimeIntrinsic::ImageEnter,
            count: 0,
        }));

        let polls = Cell::new(0usize);
        baseline
            .clone()
            .validate_with_limits(&target, ValidationLimits::standard(), &|| {
                polls.set(polls.get().saturating_add(1));
                false
            })
            .expect("calibrate prologue validation cancellation");
        let cancel_at = polls.get().saturating_sub(1);
        let observed = Cell::new(0usize);
        assert_eq!(
            baseline.validate_with_limits(&target, ValidationLimits::standard(), &|| {
                let next = observed.get().saturating_add(1);
                observed.set(next);
                next >= cancel_at
            }),
            Err(ValidationFailure::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn generated_test_emit_status_guard_fails_closed_under_exact_mutations() {
        let (baseline, _) = generated_test_fixture();
        let guard_is_valid = |module: &MachineWir| {
            let function = &module.functions[0];
            let mut incoming = vec![0usize; function.blocks.len()];
            for block in &function.blocks {
                assert!(for_each_edge(&block.terminator, |target, _| {
                    incoming[target.0 as usize] = incoming[target.0 as usize].saturating_add(1);
                    true
                }));
            }
            let block = &function.blocks[0];
            valid_test_emit_status_contract(function, block, 2, &block.instructions[2], &incoming)
        };
        assert!(
            guard_is_valid(&baseline),
            "canonical TestEmit EFI_STATUS guard"
        );
        let rejects_guard = |module: MachineWir| {
            assert!(
                !guard_is_valid(&module),
                "malformed TestEmit EFI_STATUS guard"
            );
        };

        let mut omitted_result = baseline.clone();
        omitted_result.functions[0].blocks[0].instructions[2]
            .results
            .clear();
        rejects_guard(omitted_result);

        let mut ignored = baseline.clone();
        ignored.functions[0].blocks[0].terminator = MachineTerminator::Jump {
            block: BlockId(2),
            arguments: Vec::new(),
        };
        rejects_guard(ignored);

        let mut wrong_zero = baseline.clone();
        let MachineTerminator::Switch { cases, .. } =
            &mut wrong_zero.functions[0].blocks[0].terminator
        else {
            panic!("canonical TestEmit switch")
        };
        cases[0].0 = 1;
        rejects_guard(wrong_zero);

        let mut remapped_switch = baseline.clone();
        let MachineTerminator::Switch { value, .. } =
            &mut remapped_switch.functions[0].blocks[0].terminator
        else {
            panic!("canonical TestEmit switch")
        };
        *value = ValueId(6);
        rejects_guard(remapped_switch);

        let mut remapped_failure = baseline.clone();
        remapped_failure.functions[0].blocks[1].terminator =
            MachineTerminator::Return(vec![ValueId(3)]);
        rejects_guard(remapped_failure);

        let mut returning_success = baseline.clone();
        returning_success.functions[0].blocks[2].terminator =
            MachineTerminator::Return(vec![ValueId(4)]);
        rejects_guard(returning_success);

        let mut post_call_operation = baseline.clone();
        let moved = post_call_operation.functions[0].blocks[2]
            .instructions
            .remove(0);
        post_call_operation.functions[0].blocks[0]
            .instructions
            .push(moved);
        rejects_guard(post_call_operation);

        let mut bypass = baseline;
        let MachineTerminator::Switch { cases, .. } = &mut bypass.functions[0].blocks[3].terminator
        else {
            panic!("canonical ImageEnter switch")
        };
        cases.push((1, BlockId(2), Vec::new()));
        rejects_guard(bypass);
    }

    #[test]
    fn void_remains_a_result_type_but_never_an_ssa_value() {
        let (mut module, target) = fixture();
        module.functions[0].values[2].ty = MachineTypeId(0);
        let errors = module
            .validate_for_target(&target)
            .expect_err("void-typed MachineWir SSA value");
        assert!(errors.0.contains(&ValidationError::InvalidRecord {
            kind: "void machine SSA value",
            id: 2,
        }));
    }

    #[test]
    fn current_schema_accepts_only_exact_machine_wir_v16() {
        assert_eq!(MACHINE_WIR_VERSION, 16);
        assert_eq!(
            CheckedIntegerOp::ShiftLeft.invalid_shift_count_fatal_code(),
            Some(RuntimeFatalCode::InvalidShiftCount)
        );
        assert_eq!(
            CheckedIntegerOp::ShiftLeft.result_loss_fatal_code(),
            Some(RuntimeFatalCode::CheckedShiftResultLoss)
        );
        assert_eq!(
            CheckedIntegerOp::ShiftLeftWrapping.invalid_shift_count_fatal_code(),
            Some(RuntimeFatalCode::InvalidShiftCount)
        );
        assert_eq!(
            CheckedIntegerOp::ShiftLeftWrapping.result_loss_fatal_code(),
            None
        );
        assert_eq!(
            CheckedIntegerOp::ShiftRight.invalid_shift_count_fatal_code(),
            Some(RuntimeFatalCode::InvalidShiftCount)
        );
        assert_eq!(CheckedIntegerOp::Add.invalid_shift_count_fatal_code(), None);
        let (module, target) = fixture();
        for rejected in [15, 17] {
            let mut changed = module.clone();
            changed.version = rejected;
            let errors = changed
                .validate_for_target(&target)
                .expect_err("only exact-current MachineWir v16 is accepted");
            assert!(
                errors
                    .0
                    .contains(&ValidationError::UnsupportedVersion(rejected))
            );
        }
    }

    fn exact_validation_policy(module: &MachineWir) -> (ValidationLimits, ModelResourceUsage) {
        let usage = model_resource_usage(module, ValidationLimits::standard(), &|| false)
            .expect("measure fixture validation resources");
        (
            ValidationLimits {
                arena_records: usage.arena_records,
                model_edges: usage.model_edges,
                payload_bytes: usage.payload_bytes,
                validation_work: usage.validation_work,
                errors: 100,
            },
            usage,
        )
    }

    #[test]
    fn finite_validation_policy_accepts_exact_usage_and_rejects_max_plus_one() {
        let (module, target) = fixture();
        let (exact, usage) = exact_validation_policy(&module);
        module
            .clone()
            .validate_with_limits(&target, exact, &|| false)
            .expect("exact validation policy");

        let mut arena_overflow = module.clone();
        arena_overflow.types.push(MachineType {
            id: MachineTypeId(3),
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: None,
        });
        arena_overflow.types.push(MachineType {
            id: MachineTypeId(4),
            kind: MachineTypeKind::Integer { bits: 16 },
            size: 2,
            alignment: 2,
            source_name: None,
        });
        assert_eq!(
            arena_overflow.validate_with_limits(&target, exact, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "types",
                limit: usage.arena_records,
            })
        );

        let mut edge_overflow = module.clone();
        edge_overflow.target.features.push(String::new());
        assert_eq!(
            edge_overflow.validate_with_limits(&target, exact, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: usage.model_edges,
            })
        );

        let mut payload_overflow = module;
        payload_overflow.name.push('x');
        assert_eq!(
            payload_overflow.validate_with_limits(&target, exact, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: usage.payload_bytes,
            })
        );
    }

    #[test]
    fn build_target_and_stack_slot_payloads_are_metered_exactly() {
        let (module, _) = fixture();
        let standard = ValidationLimits::standard();
        let baseline =
            model_resource_usage(&module, standard, &|| false).expect("measure baseline resources");

        let mut changed_target = module.clone();
        let old_target_bytes = changed_target.build.target.as_str().len() as u64;
        changed_target.build.target =
            TargetIdentity::new("meter-target").expect("valid target identity");
        let new_target_bytes = changed_target.build.target.as_str().len() as u64;
        let changed_target_usage = model_resource_usage(&changed_target, standard, &|| false)
            .expect("measure changed build target");
        assert_eq!(
            changed_target_usage.payload_bytes,
            baseline.payload_bytes - old_target_bytes + new_target_bytes
        );

        let mut bare_slot = changed_target;
        bare_slot.functions[0].stack_slots.push(StackSlot {
            id: StackSlotId(0),
            size: 8,
            alignment: 8,
            source_name: None,
            live_states: Vec::new(),
            overlay_group: None,
        });
        let bare_slot_usage =
            model_resource_usage(&bare_slot, standard, &|| false).expect("measure bare stack slot");
        let mut enriched_slot = bare_slot;
        enriched_slot.functions[0].stack_slots[0].source_name = Some("scratch-slot".to_owned());
        enriched_slot.functions[0].stack_slots[0].live_states = vec![2, 5, 8];
        let enriched_usage = model_resource_usage(&enriched_slot, standard, &|| false)
            .expect("measure retained stack slot fields");
        assert_eq!(
            enriched_usage.payload_bytes,
            bare_slot_usage.payload_bytes + "scratch-slot".len() as u64
        );
        assert_eq!(enriched_usage.model_edges, bare_slot_usage.model_edges + 3);

        let exact = ValidationLimits {
            arena_records: enriched_usage.arena_records,
            model_edges: enriched_usage.model_edges,
            payload_bytes: enriched_usage.payload_bytes,
            validation_work: enriched_usage.validation_work,
            errors: 1,
        };
        model_resource_usage(&enriched_slot, exact, &|| false)
            .expect("exact retained-resource policy");
        assert_eq!(
            model_resource_usage(
                &enriched_slot,
                ValidationLimits {
                    payload_bytes: enriched_usage.payload_bytes - 1,
                    ..exact
                },
                &|| false,
            ),
            Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: enriched_usage.payload_bytes - 1,
            })
        );
        assert_eq!(
            model_resource_usage(
                &enriched_slot,
                ValidationLimits {
                    model_edges: enriched_usage.model_edges - 1,
                    ..exact
                },
                &|| false,
            ),
            Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: enriched_usage.model_edges - 1,
            })
        );
    }

    #[test]
    fn aggregate_visitors_stop_at_the_first_cancelled_callback() {
        let arguments = vec![ValueId(7); 4_096];
        let operation = MachineOperation::Call {
            function: FunctionId(0),
            arguments: arguments.clone(),
            convention: CallingConvention::Internal,
        };
        let operation_visits = Cell::new(0usize);
        assert!(!for_each_operation_value(&operation, |_| {
            let next = operation_visits.get() + 1;
            operation_visits.set(next);
            next < 3
        }));
        assert_eq!(operation_visits.get(), 3);

        let terminator = MachineTerminator::Switch {
            value: ValueId(0),
            cases: vec![(0, BlockId(1), arguments)],
            default: BlockId(2),
            default_arguments: vec![ValueId(9); 4_096],
        };
        let value_visits = Cell::new(0usize);
        assert!(!for_each_terminator_value(&terminator, |_| {
            let next = value_visits.get() + 1;
            value_visits.set(next);
            next < 3
        }));
        assert_eq!(value_visits.get(), 3);

        let edges = MachineTerminator::Switch {
            value: ValueId(0),
            cases: vec![(0, BlockId(1), Vec::new()); 4_096],
            default: BlockId(2),
            default_arguments: Vec::new(),
        };
        let edge_visits = Cell::new(0usize);
        assert!(!for_each_edge(&edges, |_, _| {
            let next = edge_visits.get() + 1;
            edge_visits.set(next);
            next < 3
        }));
        assert_eq!(edge_visits.get(), 3);
    }

    #[test]
    fn scratch_fill_and_target_text_scans_stop_at_exact_midpoints() {
        let fill_polls = Cell::new(0usize);
        let cancel_fill = || {
            let next = fill_polls.get() + 1;
            fill_polls.set(next);
            next == 100
        };
        let mut fill_errors = ValidationContext::new(ValidationLimits::standard(), &cancel_fill);
        assert!(fill_errors.filled(4_096, 0u32).is_none());
        assert_eq!(fill_polls.get(), 100);
        assert!(fill_errors.cancelled);

        let error_push_polls = Cell::new(0usize);
        let cancel_error_push = || {
            let next = error_push_polls.get() + 1;
            error_push_polls.set(next);
            next == 2
        };
        let mut error_push =
            ValidationContext::new(ValidationLimits::standard(), &cancel_error_push);
        error_push.push(ValidationError::UnsupportedVersion(0));
        assert!(error_push.errors.is_empty());
        assert_eq!(error_push_polls.get(), 2);

        let scratch_push_polls = Cell::new(0usize);
        let cancel_scratch_push = || {
            let next = scratch_push_polls.get() + 1;
            scratch_push_polls.set(next);
            next == 4
        };
        let mut scratch_push =
            ValidationContext::new(ValidationLimits::standard(), &cancel_scratch_push);
        let mut scratch = scratch_push
            .scratch(1)
            .expect("reserve scratch before cancellation");
        assert!(!scratch_push.scratch_push(&mut scratch, 1u32));
        assert!(scratch.is_empty());
        assert_eq!(scratch_push_polls.get(), 4);

        let long_target_field = "x".repeat(4_096);
        let equality_polls = Cell::new(0usize);
        let cancel_equality = || {
            let next = equality_polls.get() + 1;
            equality_polls.set(next);
            next == 2_048
        };
        let mut equality_errors =
            ValidationContext::new(ValidationLimits::standard(), &cancel_equality);
        assert_eq!(
            text_equals(&long_target_field, &long_target_field, &mut equality_errors,),
            None
        );
        assert_eq!(equality_polls.get(), 2_048);

        let ordering_polls = Cell::new(0usize);
        let cancel_ordering = || {
            let next = ordering_polls.get() + 1;
            ordering_polls.set(next);
            next == 3_072
        };
        let mut ordering_errors =
            ValidationContext::new(ValidationLimits::standard(), &cancel_ordering);
        assert_eq!(
            text_compare(&long_target_field, &long_target_field, &mut ordering_errors,),
            None
        );
        assert_eq!(ordering_polls.get(), 3_072);
    }

    #[test]
    fn invalid_and_work_limited_validation_policies_are_structural_failures() {
        let (module, target) = fixture();
        let (exact, usage) = exact_validation_policy(&module);
        assert!(usage.validation_work > 0);
        assert_eq!(
            module.clone().validate_with_limits(
                &target,
                ValidationLimits { errors: 0, ..exact },
                &|| false,
            ),
            Err(ValidationFailure::InvalidLimits)
        );
        assert_eq!(
            module.validate_with_limits(
                &target,
                ValidationLimits {
                    validation_work: usage.validation_work - 1,
                    ..exact
                },
                &|| false,
            ),
            Err(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: usage.validation_work - 1,
            })
        );
    }

    #[test]
    fn validation_caps_errors_and_scratch_allocations() {
        let (mut module, target) = fixture();
        let (mut limits, _) = exact_validation_policy(&module);
        limits.errors = 2;
        module.version = 0;
        module.name.clear();
        module.layout.pointer_bits = 32;
        let failure = module
            .validate_with_limits(&target, limits, &|| false)
            .expect_err("invalid fixture");
        let ValidationFailure::Invalid(errors) = failure else {
            panic!("expected capped validation errors, got {failure:?}");
        };
        assert_eq!(errors.0.len(), 2);
        assert_eq!(
            errors.0.last(),
            Some(&ValidationError::TooManyErrors { limit: 2 })
        );

        let never_cancelled = || false;
        let mut scratch_limits = ValidationLimits::standard();
        scratch_limits.model_edges = 2;
        let mut context = ValidationContext::new(scratch_limits, &never_cancelled);
        assert!(context.scratch::<u8>(3).is_none());
        assert_eq!(
            context.finish(),
            Err(ValidationFailure::ResourceLimit {
                resource: "validation scratch entries",
                limit: 2,
            })
        );
    }

    #[test]
    fn late_validation_cancellation_is_not_collapsed_into_invalid_output() {
        let (module, target) = fixture();
        let limits = ValidationLimits::standard();
        let preflight_polls = Cell::new(0u64);
        model_resource_usage(&module, limits, &|| {
            preflight_polls.set(preflight_polls.get() + 1);
            false
        })
        .expect("resource preflight");
        let all_polls = Cell::new(0u64);
        module
            .clone()
            .validate_with_limits(&target, limits, &|| {
                all_polls.set(all_polls.get() + 1);
                false
            })
            .expect("count full validation polls");
        let cancel_at = all_polls.get().saturating_sub(1);
        assert!(cancel_at > preflight_polls.get());
        let cancellation_polls = Cell::new(0u64);
        assert_eq!(
            module.validate_with_limits(&target, limits, &|| {
                let next = cancellation_polls.get() + 1;
                cancellation_polls.set(next);
                next >= cancel_at
            }),
            Err(ValidationFailure::Cancelled)
        );
    }

    #[test]
    fn function_section_and_fixed_symbol_extent_are_not_codegen_choices() {
        let (mut module, target) = fixture();
        module.functions[0].section = SectionId(1);
        assert!(module.clone().validate_for_target(&target).is_err());

        module.functions[0].section = SectionId(0);
        if let SymbolDefinition::SectionOffset { bytes, .. } = &mut module.symbols[2].definition {
            *bytes = 0;
        }
        assert!(module.validate_for_target(&target).is_err());
    }

    #[test]
    fn interrupt_route_must_match_target_and_runtime_metadata() {
        let (mut module, target) = fixture();
        module.symbols.push(Symbol {
            id: SymbolId(3),
            name: "virtio_mmio_irq".to_owned(),
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Function(FunctionId(1)),
        });
        let isr_safe_proof = ProofId(module.proofs.len() as u32);
        module.proofs.push(BackendProof {
            id: isr_safe_proof,
            source_proofs: vec![0],
            kind: BackendProofKind::IsrSafe,
            depends_on: Vec::new(),
            bound: Some(0),
            sources: Vec::new(),
            statement: "virtio-mmio-0 interrupt closure is ISR-safe".to_owned(),
            source: None,
        });
        module.functions.push(MachineFunction {
            id: FunctionId(1),
            flow_function: 1,
            origin: MachineFunctionOrigin::GeneratedAsyncState {
                semantic_function: 0,
                state: 0,
            },
            role: MachineFunctionRole::Isr(0),
            symbol: SymbolId(3),
            section: SectionId(0),
            linkage: Linkage::Private,
            convention: CallingConvention::InterruptHandler,
            parameters: Vec::new(),
            result: MachineTypeId(0),
            proofs: vec![isr_safe_proof],
            values: Vec::new(),
            stack_slots: Vec::new(),
            blocks: vec![MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(Vec::new()),
            }],
            entry: BlockId(0),
            stack_bytes: 0,
            source: None,
        });
        module.interrupts.push(InterruptEntry {
            id: InterruptEntryId(0),
            device: 0,
            target_binding: "virtio-mmio-0".to_owned(),
            line: 16,
            global_id: 48,
            handler: FunctionId(1),
        });
        module.sections[1].reserved_bytes = u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)
            + u64::from(INTERRUPT_ROUTE_LAYOUT.record_bytes);
        if let SymbolDefinition::SectionOffset { bytes, .. } = &mut module.symbols[2].definition {
            *bytes = module.sections[1].reserved_bytes;
        }
        module
            .clone()
            .validate_for_target(&target)
            .expect("valid target-owned interrupt route with sealed ISR-safety proof");

        let mut missing_isr_proof = module.clone();
        missing_isr_proof.functions[1].proofs.clear();
        let errors = missing_isr_proof
            .validate_for_target(&target)
            .expect_err("interrupt handler without an ISR-safety proof must fail");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidInterruptEntry(InterruptEntryId(0)))
        );

        module.interrupts[0].global_id = 49;
        let errors = module
            .validate_for_target(&target)
            .expect_err("mismatched target route must fail");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidInterruptEntry(InterruptEntryId(0)))
        );
    }

    fn push_bool_type(module: &mut MachineWir) -> MachineTypeId {
        let id = MachineTypeId(module.types.len() as u32);
        module.types.push(MachineType {
            id,
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: Some("bool".to_owned()),
        });
        id
    }

    fn push_value(function: &mut MachineFunction, ty: MachineTypeId) -> ValueId {
        let id = ValueId(function.values.len() as u32);
        function.values.push(MachineValue {
            id,
            ty,
            source_name: None,
        });
        id
    }

    #[test]
    fn control_flow_sealer_rejects_non_dominating_ssa_use() {
        let (mut module, _) = fixture();
        let bool_ty = push_bool_type(&mut module);
        let function = &mut module.functions[0];
        let condition = push_value(function, bool_ty);
        function.entry = BlockId(0);
        function.blocks = vec![
            MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![MachineInstruction {
                    id: InstructionId(0),
                    results: vec![condition],
                    operation: MachineOperation::Immediate(MachineImmediate::Integer {
                        ty: bool_ty,
                        bytes_le: vec![1],
                    }),
                    source: None,
                }],
                terminator: MachineTerminator::Branch {
                    condition,
                    then_block: BlockId(1),
                    then_arguments: Vec::new(),
                    else_block: BlockId(2),
                    else_arguments: Vec::new(),
                },
            },
            MachineBlock {
                id: BlockId(1),
                parameters: Vec::new(),
                instructions: vec![MachineInstruction {
                    id: InstructionId(1),
                    results: vec![ValueId(2)],
                    operation: MachineOperation::Immediate(MachineImmediate::Integer {
                        ty: MachineTypeId(2),
                        bytes_le: vec![0; 8],
                    }),
                    source: None,
                }],
                terminator: MachineTerminator::Jump {
                    block: BlockId(3),
                    arguments: Vec::new(),
                },
            },
            MachineBlock {
                id: BlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Jump {
                    block: BlockId(3),
                    arguments: Vec::new(),
                },
            },
            MachineBlock {
                id: BlockId(3),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(vec![ValueId(2)]),
            },
        ];

        let never_cancelled = || false;
        let mut context = ValidationContext::new(ValidationLimits::standard(), &never_cancelled);
        validate_control_flow_and_ssa(&module, &module.functions[0], &mut context);
        let errors = context.finish().expect("validation scratch");
        assert!(errors.contains(&ValidationError::NonDominatingValueUse {
            function: FunctionId(0),
            value: ValueId(2),
            block: BlockId(3),
            instruction: None,
        }));
    }

    #[test]
    fn control_flow_sealer_rejects_conflicting_parallel_phi_edges() {
        let (mut module, _) = fixture();
        let bool_ty = push_bool_type(&mut module);
        let function = &mut module.functions[0];
        let mut body = function.blocks[0].clone();
        function.values.truncate(3);
        let condition = push_value(function, bool_ty);
        let alternate = push_value(function, MachineTypeId(2));
        let parameter = push_value(function, MachineTypeId(2));
        body.instructions.push(MachineInstruction {
            id: InstructionId(1),
            results: vec![condition],
            operation: MachineOperation::Immediate(MachineImmediate::Integer {
                ty: bool_ty,
                bytes_le: vec![1],
            }),
            source: None,
        });
        body.instructions.push(MachineInstruction {
            id: InstructionId(2),
            results: vec![alternate],
            operation: MachineOperation::Immediate(MachineImmediate::Integer {
                ty: MachineTypeId(2),
                bytes_le: vec![1; 8],
            }),
            source: None,
        });
        body.terminator = MachineTerminator::Branch {
            condition,
            then_block: BlockId(1),
            then_arguments: vec![ValueId(2)],
            else_block: BlockId(1),
            else_arguments: vec![alternate],
        };
        function.blocks = vec![
            body,
            MachineBlock {
                id: BlockId(1),
                parameters: vec![parameter],
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(vec![parameter]),
            },
        ];
        function.entry = BlockId(0);

        let never_cancelled = || false;
        let mut context = ValidationContext::new(ValidationLimits::standard(), &never_cancelled);
        validate_control_flow_and_ssa(&module, &module.functions[0], &mut context);
        let errors = context.finish().expect("validation scratch");
        assert!(
            errors.contains(&ValidationError::ConflictingParallelEdgeArguments {
                function: FunctionId(0),
                from: BlockId(0),
                to: BlockId(1),
            })
        );
    }

    #[test]
    fn switch_cases_must_fit_the_exact_machine_integer_width() {
        let (mut module, _) = fixture();
        let byte_ty = push_bool_type(&mut module);
        let function = &mut module.functions[0];
        let mut body = function.blocks[0].clone();
        function.values.truncate(3);
        let switched = push_value(function, byte_ty);
        body.instructions.push(MachineInstruction {
            id: InstructionId(1),
            results: vec![switched],
            operation: MachineOperation::Immediate(MachineImmediate::Integer {
                ty: byte_ty,
                bytes_le: vec![0],
            }),
            source: None,
        });
        body.terminator = MachineTerminator::Switch {
            value: switched,
            cases: vec![(256, BlockId(1), Vec::new())],
            default: BlockId(1),
            default_arguments: Vec::new(),
        };
        function.blocks = vec![
            body,
            MachineBlock {
                id: BlockId(1),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(vec![ValueId(2)]),
            },
        ];
        function.entry = BlockId(0);

        let never_cancelled = || false;
        let mut context = ValidationContext::new(ValidationLimits::standard(), &never_cancelled);
        validate_control_flow_and_ssa(&module, &module.functions[0], &mut context);
        let errors = context.finish().expect("validation scratch");
        assert!(errors.contains(&ValidationError::SwitchCaseOutOfRange {
            function: FunctionId(0),
            block: BlockId(0),
            value: 256,
            bits: 8,
        }));
    }
}
