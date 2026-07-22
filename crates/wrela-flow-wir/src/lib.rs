//! Canonical typed SSA IR exchanged between the frontend and private backend.
//!
//! FlowWir makes control flow, state machines, ownership transitions, cleanup,
//! scheduling, and hardware effects explicit. It is target-layout independent
//! and contains no LLVM concepts.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_source::Span;

pub use wrela_test_model::TestPlanLimits;

pub const FLOW_WIR_VERSION: u32 = 17;
pub const ASSERTION_EXPRESSION_BYTES_MAX: usize = 4096;
pub const SUPPORTED_SEMANTIC_WIR_VERSION: u32 = 12;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(TypeId);
id_type!(FunctionId);
id_type!(BlockId);
id_type!(ValueId);
id_type!(InstructionId);
id_type!(GlobalId);
id_type!(ActorId);
id_type!(TaskId);
id_type!(DeviceId);
id_type!(PoolId);
id_type!(RegionId);
id_type!(ActivationId);
id_type!(ProofId);
id_type!(CheckpointId);
id_type!(TestId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarType {
    Bool,
    Character,
    Integer { signed: bool, bits: u16 },
    Float32,
    Float64,
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowTypeKind {
    Unit,
    Scalar(ScalarType),
    /// Compiler-minted immutable UTF-8 value with an authenticated exact byte
    /// extent. This retains semantic identity without choosing a target ABI.
    StaticString {
        bytes: u64,
    },
    /// Compiler-minted owned UTF-8 value with runtime occupancy bounded by the
    /// authenticated capacity. This retains no physical storage layout.
    BoundedString {
        capacity: u64,
    },
    Tuple(Vec<TypeId>),
    Array {
        element: TypeId,
        length: u64,
    },
    Struct {
        fields: Vec<TypeId>,
    },
    Enum {
        variants: Vec<Vec<TypeId>>,
    },
    Function {
        parameters: Vec<TypeId>,
        result: TypeId,
    },
    /// A strict-linear, compiler-created token representing one in-flight
    /// asynchronous call whose eventual value has `result` type. Activations
    /// are consumed only by [`Terminator::Suspend`]; they are not scheduler or
    /// queue handles.
    Activation {
        result: TypeId,
    },
    RegionHandle(RegionId),
    PoolHandle(PoolId),
    ActorHandle(ActorId),
    TaskHandle(TaskId),
    Reservation,
    Receipt {
        payload: TypeId,
        error: TypeId,
    },
    DmaToken {
        pool: PoolId,
        payload: TypeId,
    },
    OpaqueTarget {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowType {
    pub id: TypeId,
    pub kind: FlowTypeKind,
    pub name: Option<String>,
    pub copyable: bool,
    pub strict_linear: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Negate,
    BoolNot,
    BitNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    AddChecked,
    AddWrapping,
    SubChecked,
    SubWrapping,
    MulChecked,
    MulWrapping,
    DivChecked,
    RemChecked,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeftChecked,
    ShiftRightChecked,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    /// Left shift with a wrapping result but a checked shift count. Counts
    /// outside `0..bits` abandon exactly like every other checked shift.
    ShiftLeftWrapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastMode {
    Checked,
    Exact,
    Bitcast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Mutate,
    Take,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaOwnership {
    Cpu,
    Prepared,
    Device,
    Completed,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceKind {
    Acquire,
    Release,
    AcquireRelease,
    DeviceRead,
    DeviceWrite,
    DeviceFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Bounds,
    Arithmetic,
    Conversion,
    Capacity,
    Generation,
    DmaState,
    DeviceValue,
    Cancellation,
    Deadline,
    PeerFailure,
    TaskFailure,
    FatalTarget,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Immediate {
    Unit,
    Bool(bool),
    Character(char),
    Integer { bits: u16, bytes_le: Vec<u8> },
    Float32(u32),
    Float64(u64),
    Bytes(Vec<u8>),
    Zero(TypeId),
    GlobalAddress(GlobalId),
    FunctionAddress(FunctionId),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlowOperation {
    Immediate(Immediate),
    /// Materialize the address of one canonical actor-owned state region.
    /// Machine lowering resolves this authenticated region identity to the
    /// matching `ActorState` storage global; source receiver values stay erased.
    ActorStateAddress {
        actor: ActorId,
        region: RegionId,
        proof: ProofId,
    },
    Unary {
        op: UnaryOp,
        value: ValueId,
    },
    Binary {
        op: BinaryOp,
        left: ValueId,
        right: ValueId,
    },
    Cast {
        value: ValueId,
        to: TypeId,
        mode: CastMode,
    },
    MakeAggregate {
        ty: TypeId,
        fields: Vec<ValueId>,
    },
    /// Preserve one source-ordered bounded formatting construction. Machine
    /// lowering must select and authenticate storage plus a formatting ABI.
    FormatBoundedString {
        ty: TypeId,
        parts: Vec<BoundedStringPart>,
    },
    /// Construct the canonical `{u8 tag, payload}` representation of an enum.
    MakeEnum {
        ty: TypeId,
        variant: u8,
        /// Present exactly when the selected variant has one payload field.
        payload: Option<ValueId>,
    },
    /// Read the canonical u8 discriminant of an enum value.
    EnumTag {
        value: ValueId,
    },
    /// Read the shared scalar payload of an enum value.
    EnumPayload {
        value: ValueId,
    },
    ExtractField {
        aggregate: ValueId,
        field: u32,
    },
    /// Extract one element from an exact fixed array. The capacity proof binds
    /// the generated index protocol to the array's authenticated extent.
    ExtractIndex {
        aggregate: ValueId,
        index: ValueId,
        proof: ProofId,
    },
    InsertField {
        aggregate: ValueId,
        field: u32,
        value: ValueId,
    },
    Select {
        condition: ValueId,
        then_value: ValueId,
        else_value: ValueId,
    },
    BeginAccess {
        place: ValueId,
        kind: AccessKind,
        proof: ProofId,
    },
    EndAccess {
        access: ValueId,
    },
    Load {
        address: ValueId,
        proof: ProofId,
    },
    Store {
        address: ValueId,
        value: ValueId,
        proof: ProofId,
    },
    Move {
        value: ValueId,
    },
    Copy {
        value: ValueId,
    },
    Drop {
        value: ValueId,
    },
    Call {
        function: FunctionId,
        arguments: Vec<ValueId>,
    },
    /// Start one asynchronous function invocation and produce exactly one
    /// strict-linear activation token. Result delivery is represented by the
    /// matching [`Terminator::Suspend`] resume-block parameter.
    AsyncCall {
        function: FunctionId,
        arguments: Vec<ValueId>,
        plan: ActivationId,
    },
    Allocate {
        region: RegionId,
        ty: TypeId,
        count: ValueId,
        proof: ProofId,
    },
    RegionReset {
        region: RegionId,
    },
    /// Authenticate a value lifetime transition into one persistent image
    /// region. The subsequent store performs the runtime write; this marker
    /// preserves the exact escape proof for downstream validation.
    Promote {
        value: ValueId,
        destination: RegionId,
        proof: ProofId,
    },
    /// Immutable image-wired capability for one exact installed actor.
    ActorCapability {
        actor: ActorId,
        proof: ProofId,
    },
    ActorReserve {
        actor: ActorId,
        method: FunctionId,
        proof: ProofId,
    },
    ActorCommit {
        reservation: ValueId,
        arguments: Vec<ValueId>,
    },
    ActorReplyRequest {
        actor: ActorId,
        method: FunctionId,
        permit: ProofId,
        reply: ProofId,
    },
    ActorReplyResolve {
        outcome: ValueId,
        reply: ProofId,
    },
    ActorReject {
        reservation: ValueId,
    },
    MailboxReceive {
        actor: ActorId,
        method: FunctionId,
    },
    ReplyResolve {
        endpoint: ValueId,
        outcome: ValueId,
    },
    ReceiptCommit {
        receipt: ValueId,
        payload: ValueId,
    },
    ReceiptResolve {
        receipt: ValueId,
        outcome: ValueId,
    },
    TaskAcquireSlot {
        task: TaskId,
        proof: ProofId,
    },
    TaskStart {
        slot: ValueId,
        entry: FunctionId,
        arguments: Vec<ValueId>,
    },
    TaskCancel {
        task: ValueId,
    },
    Park {
        wait_set: ValueId,
    },
    Wake {
        target: ValueId,
    },
    Checkpoint {
        id: CheckpointId,
        proof: ProofId,
    },
    DeadlineRead,
    InterruptMask,
    InterruptRestore {
        token: ValueId,
    },
    InterruptPublish {
        cell: ValueId,
        value: ValueId,
    },
    MmioRead {
        device: DeviceId,
        register: u32,
    },
    MmioWrite {
        device: DeviceId,
        register: u32,
        value: ValueId,
    },
    Fence {
        kind: FenceKind,
    },
    DmaTransition {
        token: ValueId,
        device: DeviceId,
        from: DmaOwnership,
        to: DmaOwnership,
        proof: ProofId,
    },
    QueueReserve {
        device: DeviceId,
        descriptors: ValueId,
        proof: ProofId,
    },
    QueuePublish {
        reservation: ValueId,
        payload: ValueId,
    },
    ValidateDeviceValue {
        value: ValueId,
        proof: ProofId,
    },
    Check {
        condition: ValueId,
        failure: FailureKind,
        proof: Option<ProofId>,
    },
    Assert {
        condition: ValueId,
        failure: AssertionFailureDescriptor,
    },
    RecordEvent {
        kind: u32,
        payload: ValueId,
    },
    ReplayEvent {
        kind: u32,
        destination: ValueId,
    },
    /// Emit a canonical encoded test event from a generated test image.
    TestEmit {
        payload: ValueId,
    },
    /// Terminate a generated test image with its protocol outcome code.
    TestFinish {
        outcome: ValueId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedStringPart {
    Text {
        value: String,
        source: Span,
    },
    Bool {
        value: ValueId,
        source: Span,
    },
    Character {
        value: ValueId,
        source: Span,
    },
    Integer {
        value: ValueId,
        maximum_bytes: u64,
        source: Span,
    },
    StaticString {
        value: ValueId,
        bytes: u64,
        source: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionFailureDescriptor {
    pub expression: String,
    pub message: Option<String>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub id: InstructionId,
    pub results: Vec<ValueId>,
    pub operation: FlowOperation,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Terminator {
    Jump {
        target: BlockId,
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
        cases: Vec<SwitchCase>,
        default: BlockId,
        default_arguments: Vec<ValueId>,
    },
    Return(Vec<ValueId>),
    Suspend {
        state: u32,
        activation: ValueId,
        resume: BlockId,
    },
    TailCall {
        function: FunctionId,
        arguments: Vec<ValueId>,
    },
    Trap {
        failure: FailureKind,
        detail: Option<ValueId>,
    },
    Unreachable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwitchCase {
    pub value: u128,
    pub target: BlockId,
    pub arguments: Vec<ValueId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub id: BlockId,
    pub parameters: Vec<ValueId>,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Value {
    pub id: ValueId,
    pub ty: TypeId,
    pub source_name: Option<String>,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionRole {
    Ordinary,
    ActorTurn(ActorId),
    TaskEntry(TaskId),
    Isr(DeviceId),
    Cleanup,
    ImageEntry,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionColor {
    Sync,
    Async,
    Isr,
}

/// Exact provenance for Flow functions. One base function is retained for
/// every SemanticWir function; additional variants are compiler-generated by
/// structured/async lowering and identify their semantic owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionOrigin {
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

#[derive(Debug, Clone, PartialEq)]
pub struct FlowFunction {
    pub id: FunctionId,
    pub name: String,
    pub origin: FunctionOrigin,
    pub role: FunctionRole,
    pub color: FunctionColor,
    pub parameters: Vec<ValueId>,
    pub result_types: Vec<TypeId>,
    pub values: Vec<Value>,
    pub blocks: Vec<Block>,
    pub entry: BlockId,
    pub stack_bound: u64,
    pub frame_bound: u64,
    /// Semantic proof identities retained for this exact function instance.
    pub proofs: Vec<ProofId>,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlowGlobal {
    pub id: GlobalId,
    pub name: String,
    pub ty: TypeId,
    pub initializer: Immediate,
    pub mutable: bool,
    pub owner: PlanOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorPlan {
    pub id: ActorId,
    pub name: String,
    pub state_type: TypeId,
    pub mailbox_capacity: u32,
    pub message_types: Vec<TypeId>,
    pub turn_functions: Vec<FunctionId>,
    pub priority: u8,
    pub supervisor: Option<ActorId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPlan {
    pub id: TaskId,
    pub name: String,
    pub entry: FunctionId,
    pub slots: u32,
    pub priority: u8,
    pub frame_bytes_bound: u64,
    pub supervisor: Option<ActorId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePlan {
    pub id: DeviceId,
    pub name: String,
    pub target_binding: String,
    pub owner: ActorId,
    pub queue_capacity: Option<u32>,
    pub maximum_in_flight: Option<u32>,
    pub required_features: Vec<String>,
    pub optional_features: Vec<String>,
    pub interrupt_functions: Vec<FunctionId>,
    pub reset_timeout_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPlan {
    pub id: PoolId,
    pub name: String,
    pub element_type: TypeId,
    pub capacity: u64,
    pub alignment: u64,
    pub devices: Vec<DeviceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionPlan {
    pub id: RegionId,
    pub name: String,
    pub class: RegionClass,
    pub capacity_bytes: u64,
    pub alignment: u64,
    pub reset_function: Option<FunctionId>,
    pub owner: PlanOwner,
    pub capacity_proof: ProofId,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCancellation {
    DropCalleeThenPropagate,
}

/// Exact source-level admission record for one `AsyncCall` instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationPlan {
    pub id: ActivationId,
    pub caller: FunctionId,
    pub callee: FunctionId,
    pub region: RegionId,
    pub frame_bytes: u64,
    pub maximum_live: u32,
    pub cancellation: ActivationCancellation,
    pub capacity_proof: ProofId,
    pub source: Span,
}

/// Exact ownership of the actor and task plans assigned to one cooperative
/// scheduler core. The current target profile admits only core zero; carrying
/// the partition explicitly prevents later lowering from reconstructing or
/// silently globalizing scheduler ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerPlan {
    pub core: u32,
    pub actors: Vec<ActorId>,
    pub tasks: Vec<TaskId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionClass {
    Image,
    TaskFrame,
    Call,
    Request,
    Pool(PoolId),
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlanOwner {
    Runtime,
    Actor(ActorId),
    Task(TaskId),
    Device(DeviceId),
    Pool(PoolId),
    BakedArtifact(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSummary {
    pub semantic_wir_version: u32,
    pub semantic_functions: u32,
    /// Exact HIR arena bounds retained for source and declaration provenance.
    /// These are distinct from reachability counts because dense IDs need not
    /// be smaller than the number of reachable records.
    pub hir_files: u32,
    pub hir_declarations: u32,
    pub reachable_declarations: u64,
    pub monomorphized_instantiations: u64,
    pub resolved_interface_calls: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofKind {
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
    /// Proof introduced by structured control-flow lowering rather than
    /// copied from SemanticWir.
    FlowControl,
    /// Range fact introduced by SSA construction or later Flow optimization.
    ValueRange,
    /// Layout-independent alignment fact introduced while making accesses
    /// explicit in FlowWir.
    Alignment,
    /// Alias fact introduced while making semantic access paths explicit.
    NoAlias,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub id: ProofId,
    pub kind: ProofKind,
    pub subject: String,
    pub sources: Vec<Span>,
    pub depends_on: Vec<ProofId>,
    pub bound: Option<u64>,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub function: FunctionId,
    pub source: Span,
    pub uninterrupted_bound: u64,
    pub may_observe_cancellation: bool,
    pub may_yield: bool,
}

/// Dense, image-local identity and executable provenance for one test retained
/// from SemanticWir. The global plan ID and function key are carried explicitly
/// so the private backend can reject a substituted compiled-group binding
/// without reconstructing either value from protocol frame immediates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestEntry {
    pub id: TestId,
    pub plan_id: u32,
    pub function_key: wrela_build_model::Sha256Digest,
    pub name: String,
    pub function: FunctionId,
    pub kind: TestKind,
    pub source: Span,
    pub timeout_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestKind {
    Comptime,
    Integration,
    Image,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlowWir {
    pub version: u32,
    pub name: String,
    pub build: BuildIdentity,
    pub source_summary: SourceSummary,
    pub types: Vec<FlowType>,
    pub globals: Vec<FlowGlobal>,
    pub functions: Vec<FlowFunction>,
    pub actors: Vec<ActorPlan>,
    pub tasks: Vec<TaskPlan>,
    pub devices: Vec<DevicePlan>,
    pub pools: Vec<PoolPlan>,
    pub regions: Vec<RegionPlan>,
    pub activations: Vec<ActivationPlan>,
    pub schedulers: Vec<SchedulerPlan>,
    pub proofs: Vec<Proof>,
    pub checkpoints: Vec<Checkpoint>,
    pub tests: Vec<TestEntry>,
    /// Exact sealed-plan group retained without reconstruction across the
    /// frontend/backend process boundary. Ordinary images carry `None`.
    pub compiled_test_group: Option<wrela_test_model::FullImageTestGroup>,
    pub startup_order: Vec<PlanOwner>,
    pub shutdown_order: Vec<PlanOwner>,
    pub image_entry: FunctionId,
    pub static_bytes: u64,
    pub peak_bytes: u64,
}

/// Finite policy for independently validating an untrusted FlowWir model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum records in any one dense arena.
    pub arena_records: u64,
    /// Maximum aggregate vector elements and validation scratch entries.
    pub model_edges: u64,
    /// Maximum aggregate retained UTF-8 and byte-string payload.
    pub payload_bytes: u64,
    /// Conservative upper bound for validation and dominance work.
    pub validation_work: u64,
    /// Maximum number of validation errors retained in memory.
    pub errors: u32,
    /// Exact finite policy for an embedded compiled test-group binding.
    pub test_plan: TestPlanLimits,
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
            test_plan: TestPlanLimits::standard(),
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
            && self.test_plan.is_valid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    InvalidLimits,
    Cancelled,
    ResourceLimit { resource: &'static str, limit: u64 },
    Invalid(ValidationErrors),
}

impl FlowWir {
    pub fn validate(self) -> Result<ValidatedFlowWir, ValidationErrors> {
        match self.validate_with_limits(ValidationLimits::standard(), &|| false) {
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

    /// Validate under an explicit finite resource policy and cancellation hook.
    pub fn validate_with_limits(
        self,
        limits: ValidationLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedFlowWir, ValidationFailure> {
        if !limits.is_valid() {
            return Err(ValidationFailure::InvalidLimits);
        }
        validate_model_resources(&self, limits, is_cancelled)?;
        let errors = validate_module(&self, limits, is_cancelled)?;
        if errors.is_empty() {
            if is_cancelled() {
                Err(ValidationFailure::Cancelled)
            } else {
                Ok(ValidatedFlowWir(self))
            }
        } else {
            Err(ValidationFailure::Invalid(ValidationErrors(errors)))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedFlowWir(FlowWir);

impl ValidatedFlowWir {
    #[must_use]
    pub fn as_wir(&self) -> &FlowWir {
        &self.0
    }

    #[must_use]
    pub fn into_wir(self) -> FlowWir {
        self.0
    }
}

struct ResourceMeter<'a> {
    limits: ValidationLimits,
    edges: u64,
    payload_bytes: u64,
    work: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> ResourceMeter<'a> {
    fn new(limits: ValidationLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
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

    fn arena(&mut self, resource: &'static str, length: usize) -> Result<(), ValidationFailure> {
        let length = self.length(resource, length, self.limits.arena_records)?;
        self.edges(length)
    }

    fn edge_slice<T>(&mut self, values: &[T]) -> Result<(), ValidationFailure> {
        let length = self.length("model edges", values.len(), self.limits.model_edges)?;
        self.edges(length)
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

    fn edges(&mut self, amount: u64) -> Result<(), ValidationFailure> {
        // Poll at bounded intervals even when a vector's scalar elements do not
        // otherwise need inspection during the resource preflight.
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
        let amount = left
            .checked_mul(right)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })?;
        self.work(amount)
    }

    fn finish(&self) -> Result<(), ValidationFailure> {
        self.poll()
    }
}

fn validate_model_resources(
    module: &FlowWir,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ValidationFailure> {
    let mut meter = ResourceMeter::new(limits, is_cancelled);
    meter.text(&module.name)?;
    meter.text(module.build.target.as_str())?;
    meter.arena("types", module.types.len())?;
    meter.arena("globals", module.globals.len())?;
    meter.arena("functions", module.functions.len())?;
    meter.arena("actors", module.actors.len())?;
    meter.arena("tasks", module.tasks.len())?;
    meter.arena("devices", module.devices.len())?;
    meter.arena("pools", module.pools.len())?;
    meter.arena("regions", module.regions.len())?;
    meter.arena("activations", module.activations.len())?;
    meter.arena("schedulers", module.schedulers.len())?;
    meter.arena("proofs", module.proofs.len())?;
    meter.arena("checkpoints", module.checkpoints.len())?;
    meter.arena("tests", module.tests.len())?;
    meter.edge_slice(&module.startup_order)?;
    meter.edge_slice(&module.shutdown_order)?;

    for scheduler in &module.schedulers {
        meter.poll()?;
        meter.edge_slice(&scheduler.actors)?;
        meter.edge_slice(&scheduler.tasks)?;
    }

    if let Some(group) = &module.compiled_test_group {
        meter.edge_slice(&group.tests)?;
        meter.text(&group.name)?;
        match &group.root {
            wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
                meter.text(harness_name)?;
            }
            wrela_test_model::ImageRoot::Declared { image_name, .. } => {
                meter.text(image_name)?;
            }
        }
        for test in &group.tests {
            meter.poll()?;
            meter.text(&test.descriptor.name)?;
            meter.edge_slice(&test.assertions)?;
            for assertion in &test.assertions {
                meter.poll()?;
                meter.text(&assertion.expression)?;
                if let Some(message) = &assertion.message {
                    meter.text(message)?;
                }
            }
        }
    }

    for ty in &module.types {
        meter.poll()?;
        if let Some(name) = &ty.name {
            meter.text(name)?;
        }
        match &ty.kind {
            FlowTypeKind::Tuple(items) | FlowTypeKind::Struct { fields: items } => {
                meter.edge_slice(items)?;
            }
            FlowTypeKind::Enum { variants } => {
                meter.edge_slice(variants)?;
                for variant in variants {
                    meter.poll()?;
                    meter.edge_slice(variant)?;
                }
            }
            FlowTypeKind::Function { parameters, .. } => meter.edge_slice(parameters)?,
            FlowTypeKind::OpaqueTarget { name } => meter.text(name)?,
            FlowTypeKind::Unit
            | FlowTypeKind::Scalar(_)
            | FlowTypeKind::StaticString { .. }
            | FlowTypeKind::BoundedString { .. }
            | FlowTypeKind::Array { .. }
            | FlowTypeKind::Activation { .. }
            | FlowTypeKind::RegionHandle(_)
            | FlowTypeKind::PoolHandle(_)
            | FlowTypeKind::ActorHandle(_)
            | FlowTypeKind::TaskHandle(_)
            | FlowTypeKind::Reservation
            | FlowTypeKind::Receipt { .. }
            | FlowTypeKind::DmaToken { .. } => {}
        }
    }

    for global in &module.globals {
        meter.poll()?;
        meter.text(&global.name)?;
        meter_immediate(&mut meter, &global.initializer)?;
    }

    for function in &module.functions {
        meter.poll()?;
        meter.text(&function.name)?;
        meter.edge_slice(&function.parameters)?;
        meter.edge_slice(&function.result_types)?;
        meter.edge_slice(&function.proofs)?;
        meter.arena("function values", function.values.len())?;
        meter.arena("function blocks", function.blocks.len())?;
        for value in &function.values {
            meter.poll()?;
            if let Some(name) = &value.source_name {
                meter.text(name)?;
            }
        }
        let mut instruction_count = 0_u64;
        let mut cfg_edges = 0_u64;
        let mut value_uses = 0_u64;
        for block in &function.blocks {
            meter.poll()?;
            meter.edge_slice(&block.parameters)?;
            meter.arena("block instructions", block.instructions.len())?;
            instruction_count = instruction_count
                .checked_add(u64::try_from(block.instructions.len()).map_err(|_| {
                    ValidationFailure::ResourceLimit {
                        resource: "model edges",
                        limit: limits.model_edges,
                    }
                })?)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "model edges",
                    limit: limits.model_edges,
                })?;
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
            let (block_edges, block_uses) = meter_terminator(&mut meter, &block.terminator)?;
            cfg_edges =
                cfg_edges
                    .checked_add(block_edges)
                    .ok_or(ValidationFailure::ResourceLimit {
                        resource: "validation work",
                        limit: limits.validation_work,
                    })?;
            value_uses =
                value_uses
                    .checked_add(block_uses)
                    .ok_or(ValidationFailure::ResourceLimit {
                        resource: "validation work",
                        limit: limits.validation_work,
                    })?;
        }
        let blocks =
            u64::try_from(function.blocks.len()).map_err(|_| ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: limits.validation_work,
            })?;
        meter.work(instruction_count)?;
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

    for actor in &module.actors {
        meter.poll()?;
        meter.text(&actor.name)?;
        meter.edge_slice(&actor.message_types)?;
        meter.edge_slice(&actor.turn_functions)?;
    }
    for task in &module.tasks {
        meter.poll()?;
        meter.text(&task.name)?;
    }
    for device in &module.devices {
        meter.poll()?;
        meter.text(&device.name)?;
        meter.text(&device.target_binding)?;
        meter.edge_slice(&device.required_features)?;
        meter.edge_slice(&device.optional_features)?;
        meter.edge_slice(&device.interrupt_functions)?;
        for feature in device
            .required_features
            .iter()
            .chain(&device.optional_features)
        {
            meter.poll()?;
            meter.text(feature)?;
        }
    }
    for pool in &module.pools {
        meter.poll()?;
        meter.text(&pool.name)?;
        meter.edge_slice(&pool.devices)?;
    }
    for region in &module.regions {
        meter.poll()?;
        meter.text(&region.name)?;
    }
    for _activation in &module.activations {
        meter.poll()?;
    }
    for proof in &module.proofs {
        meter.poll()?;
        meter.text(&proof.subject)?;
        meter.edge_slice(&proof.sources)?;
        meter.edge_slice(&proof.depends_on)?;
        meter.edge_slice(&proof.explanation)?;
        for line in &proof.explanation {
            meter.poll()?;
            meter.text(line)?;
        }
    }
    for test in &module.tests {
        meter.poll()?;
        meter.text(&test.name)?;
    }
    meter.finish()
}

fn meter_immediate(
    meter: &mut ResourceMeter<'_>,
    immediate: &Immediate,
) -> Result<(), ValidationFailure> {
    match immediate {
        Immediate::Integer { bytes_le, .. } | Immediate::Bytes(bytes_le) => {
            meter.payload(bytes_le.len())
        }
        Immediate::Unit
        | Immediate::Bool(_)
        | Immediate::Character(_)
        | Immediate::Float32(_)
        | Immediate::Float64(_)
        | Immediate::Zero(_)
        | Immediate::GlobalAddress(_)
        | Immediate::FunctionAddress(_) => meter.poll(),
    }
}

fn meter_operation(
    meter: &mut ResourceMeter<'_>,
    operation: &FlowOperation,
) -> Result<u64, ValidationFailure> {
    meter.poll()?;
    match operation {
        FlowOperation::Immediate(immediate) => {
            meter_immediate(meter, immediate)?;
        }
        FlowOperation::MakeAggregate { fields, .. } => meter.edge_slice(fields)?,
        FlowOperation::FormatBoundedString { parts, .. } => {
            meter.edge_slice(parts)?;
            for part in parts {
                meter.poll()?;
                if let BoundedStringPart::Text { value, .. } = part {
                    meter.text(value)?;
                }
            }
        }
        FlowOperation::Call { arguments, .. }
        | FlowOperation::AsyncCall { arguments, .. }
        | FlowOperation::ActorCommit { arguments, .. } => meter.edge_slice(arguments)?,
        FlowOperation::TaskStart { arguments, .. } => meter.edge_slice(arguments)?,
        FlowOperation::Assert { failure, .. } => {
            meter.text(&failure.expression)?;
            if let Some(message) = &failure.message {
                meter.text(message)?;
            }
        }
        FlowOperation::Unary { .. }
        | FlowOperation::ActorStateAddress { .. }
        | FlowOperation::Binary { .. }
        | FlowOperation::Cast { .. }
        | FlowOperation::MakeEnum { .. }
        | FlowOperation::EnumTag { .. }
        | FlowOperation::EnumPayload { .. }
        | FlowOperation::ExtractField { .. }
        | FlowOperation::ExtractIndex { .. }
        | FlowOperation::InsertField { .. }
        | FlowOperation::Select { .. }
        | FlowOperation::BeginAccess { .. }
        | FlowOperation::EndAccess { .. }
        | FlowOperation::Load { .. }
        | FlowOperation::Store { .. }
        | FlowOperation::Move { .. }
        | FlowOperation::Copy { .. }
        | FlowOperation::Drop { .. }
        | FlowOperation::Allocate { .. }
        | FlowOperation::RegionReset { .. }
        | FlowOperation::Promote { .. }
        | FlowOperation::ActorCapability { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::ActorReplyRequest { .. }
        | FlowOperation::ActorReplyResolve { .. }
        | FlowOperation::ActorReject { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::ReplyResolve { .. }
        | FlowOperation::ReceiptCommit { .. }
        | FlowOperation::ReceiptResolve { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::TaskCancel { .. }
        | FlowOperation::Park { .. }
        | FlowOperation::Wake { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::InterruptRestore { .. }
        | FlowOperation::InterruptPublish { .. }
        | FlowOperation::MmioRead { .. }
        | FlowOperation::MmioWrite { .. }
        | FlowOperation::Fence { .. }
        | FlowOperation::DmaTransition { .. }
        | FlowOperation::QueueReserve { .. }
        | FlowOperation::QueuePublish { .. }
        | FlowOperation::ValidateDeviceValue { .. }
        | FlowOperation::Check { .. }
        | FlowOperation::RecordEvent { .. }
        | FlowOperation::ReplayEvent { .. }
        | FlowOperation::TestEmit { .. }
        | FlowOperation::TestFinish { .. } => {}
    }
    let mut uses = Some(0_u64);
    for_each_flow_operation_value(operation, |_| {
        uses = uses.and_then(|count| count.checked_add(1));
    });
    uses.ok_or(ValidationFailure::ResourceLimit {
        resource: "validation work",
        limit: meter.limits.validation_work,
    })
}

fn meter_terminator(
    meter: &mut ResourceMeter<'_>,
    terminator: &Terminator,
) -> Result<(u64, u64), ValidationFailure> {
    meter.poll()?;
    let cfg_edges = match terminator {
        Terminator::Jump { arguments, .. } => {
            meter.edge_slice(arguments)?;
            1
        }
        Terminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => {
            meter.edge_slice(then_arguments)?;
            meter.edge_slice(else_arguments)?;
            2
        }
        Terminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            meter.edge_slice(cases)?;
            meter.edge_slice(default_arguments)?;
            for case in cases {
                meter.poll()?;
                meter.edge_slice(&case.arguments)?;
            }
            u64::try_from(cases.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "validation work",
                    limit: meter.limits.validation_work,
                })?
        }
        Terminator::Suspend { .. } => 1,
        Terminator::Return(values) => {
            meter.edge_slice(values)?;
            0
        }
        Terminator::TailCall { arguments, .. } => {
            meter.edge_slice(arguments)?;
            0
        }
        Terminator::Trap { .. } | Terminator::Unreachable => 0,
    };
    let mut uses = Some(0_u64);
    for_each_flow_terminator_value(terminator, |_| {
        uses = uses.and_then(|count| count.checked_add(1));
    });
    Ok((
        cfg_edges,
        uses.ok_or(ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: meter.limits.validation_work,
        })?,
    ))
}

struct ValidationContext<'a> {
    errors: Vec<ValidationError>,
    limits: ValidationLimits,
    is_cancelled: &'a dyn Fn() -> bool,
    cancelled: bool,
    allocation_failure: Option<(&'static str, u64)>,
    capped: bool,
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
        }
    }

    fn poll(&mut self) -> bool {
        if self.cancelled || (self.is_cancelled)() {
            self.cancelled = true;
            false
        } else {
            true
        }
    }

    fn push(&mut self, error: ValidationError) {
        if !self.poll() || self.capped || self.allocation_failure.is_some() {
            return;
        }
        let limit = self.limits.errors as usize;
        if self.errors.len().saturating_add(1) >= limit {
            if self.errors.try_reserve(1).is_err() {
                self.allocation_failure =
                    Some(("validation error scratch", u64::from(self.limits.errors)));
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
        self.errors.push(error);
    }

    fn scratch<T>(&mut self, capacity: usize) -> Option<Vec<T>> {
        if !self.poll()
            || u64::try_from(capacity).map_or(true, |length| length > self.limits.model_edges)
        {
            if !self.cancelled {
                self.allocation_failure =
                    Some(("validation scratch entries", self.limits.model_edges));
            }
            return None;
        }
        let mut values = Vec::new();
        if values.try_reserve_exact(capacity).is_err() {
            self.allocation_failure = Some(("validation scratch entries", self.limits.model_edges));
            None
        } else {
            Some(values)
        }
    }

    fn filled<T: Clone>(&mut self, length: usize, value: T) -> Option<Vec<T>> {
        let mut values = self.scratch(length)?;
        values.resize(length, value);
        Some(values)
    }

    fn scratch_push<T>(&mut self, values: &mut Vec<T>, value: T) -> bool {
        if !self.poll()
            || u64::try_from(values.len()).map_or(true, |length| length >= self.limits.model_edges)
        {
            if !self.cancelled {
                self.allocation_failure =
                    Some(("validation scratch entries", self.limits.model_edges));
            }
            return false;
        }
        if values.try_reserve(1).is_err() {
            self.allocation_failure = Some(("validation scratch entries", self.limits.model_edges));
            false
        } else {
            values.push(value);
            true
        }
    }

    fn finish(mut self) -> Result<Vec<ValidationError>, ValidationFailure> {
        self.poll();
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
    sort_scratch_by(values, errors, &T::cmp)
}

fn sort_scratch_by<T: Copy>(
    values: &mut [T],
    errors: &mut ValidationContext<'_>,
    compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
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
    compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
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
            let take_left = right >= end
                || left < middle
                    && compare(&source[left], &source[right]) != std::cmp::Ordering::Greater;
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
    module: &FlowWir,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ValidationError>, ValidationFailure> {
    let mut errors = ValidationContext::new(limits, is_cancelled);
    if module.version != FLOW_WIR_VERSION {
        errors.push(ValidationError::UnsupportedVersion(module.version));
    }
    if module.name.trim().is_empty() {
        errors.push(ValidationError::MissingImageName);
    }
    if module.source_summary.semantic_wir_version != SUPPORTED_SEMANTIC_WIR_VERSION
        || module.source_summary.hir_files == 0
        || module.source_summary.hir_declarations == 0
        || module.source_summary.reachable_declarations
            > u64::from(module.source_summary.hir_declarations)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "source summary",
            id: 0,
        });
    }
    check_dense(
        "type",
        module.types.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "global",
        module.globals.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "function",
        module.functions.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "proof",
        module.proofs.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "actor",
        module.actors.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "task",
        module.tasks.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "device",
        module.devices.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "pool",
        module.pools.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "region",
        module.regions.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "activation",
        module.activations.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "checkpoint",
        module.checkpoints.iter().map(|record| record.id.0),
        &mut errors,
    );
    check_dense(
        "test",
        module.tests.iter().map(|record| record.id.0),
        &mut errors,
    );
    for ty in &module.types {
        if !errors.poll() {
            return errors.finish();
        }
        validate_type(module, ty, &mut errors);
    }
    let mut saw_activation = false;
    let mut prior_activation_result = None;
    for ty in &module.types {
        if !errors.poll() {
            return errors.finish();
        }
        match ty.kind {
            FlowTypeKind::Activation { result } => {
                let canonical = prior_activation_result.is_none_or(|prior| prior < result)
                    && module.types.get(result.0 as usize).is_some_and(|result| {
                        !matches!(result.kind, FlowTypeKind::Activation { .. })
                    });
                if !canonical {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "activation type order",
                        id: ty.id.0,
                    });
                }
                saw_activation = true;
                prior_activation_result = Some(result);
            }
            _ if saw_activation => errors.push(ValidationError::InvalidRecord {
                kind: "activation type order",
                id: ty.id.0,
            }),
            _ => {}
        }
    }
    for global in &module.globals {
        if !errors.poll() {
            return errors.finish();
        }
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        validate_immediate(module, &global.initializer, &mut errors);
        validate_owner(module, global.owner, &mut errors);
    }
    for function in &module.functions {
        if !errors.poll() {
            return errors.finish();
        }
        let (semantic_function, valid_origin) = match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function } => (
                semantic_function,
                function.source.is_some() && function.role != FunctionRole::ImageEntry,
            ),
            FunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            } => (
                semantic_function,
                function.source.is_none()
                    && function.role == FunctionRole::ImageEntry
                    && constructor < module.source_summary.hir_declarations,
            ),
            FunctionOrigin::GeneratedTestHarness {
                semantic_function, ..
            } => (
                semantic_function,
                function.source.is_none() && function.role == FunctionRole::ImageEntry,
            ),
            FunctionOrigin::GeneratedAsyncState {
                semantic_function, ..
            }
            | FunctionOrigin::GeneratedCleanup {
                semantic_function, ..
            } => (semantic_function, function.role != FunctionRole::ImageEntry),
        };
        let role_color_matches = match function.role {
            FunctionRole::ActorTurn(_) | FunctionRole::TaskEntry(_) => {
                function.color == FunctionColor::Async
            }
            FunctionRole::Isr(_) => function.color == FunctionColor::Isr,
            FunctionRole::Ordinary => function.color != FunctionColor::Isr,
            FunctionRole::Cleanup | FunctionRole::ImageEntry | FunctionRole::Test => {
                function.color == FunctionColor::Sync
            }
        };
        if function.name.trim().is_empty()
            || semantic_function >= module.source_summary.semantic_functions
            || !valid_origin
            || !role_color_matches
            || function
                .source
                .is_some_and(|span| !valid_source_span(module, span))
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "function",
                id: function.id.0,
            });
        }
        check_dense(
            "value",
            function.values.iter().map(|record| record.id.0),
            &mut errors,
        );
        check_dense(
            "block",
            function.blocks.iter().map(|record| record.id.0),
            &mut errors,
        );
        for value in &function.values {
            if !errors.poll() {
                return errors.finish();
            }
            require_id("value type", value.ty.0, module.types.len(), &mut errors);
            if value
                .source
                .is_some_and(|span| !valid_source_span(module, span))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "value source",
                    id: value.id.0,
                });
            }
        }
        match function.role {
            FunctionRole::ActorTurn(id) => require_id(
                "function actor role",
                id.0,
                module.actors.len(),
                &mut errors,
            ),
            FunctionRole::TaskEntry(id) => {
                require_id("function task role", id.0, module.tasks.len(), &mut errors)
            }
            FunctionRole::Isr(id) => {
                require_id("function ISR role", id.0, module.devices.len(), &mut errors)
            }
            FunctionRole::Ordinary
            | FunctionRole::Cleanup
            | FunctionRole::ImageEntry
            | FunctionRole::Test => {}
        }
        for result in &function.result_types {
            if !errors.poll() {
                return errors.finish();
            }
            require_id(
                "function result type",
                result.0,
                module.types.len(),
                &mut errors,
            );
            if module
                .types
                .get(result.0 as usize)
                .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::Activation { .. }))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "activation function result",
                    id: function.id.0,
                });
            }
        }
        for proof in &function.proofs {
            if !errors.poll() {
                return errors.finish();
            }
            require_id("function proof", proof.0, module.proofs.len(), &mut errors);
        }
        require_canonical_ids(
            "function proofs",
            function.id.0,
            function.proofs.iter().map(|proof| proof.0),
            &mut errors,
        );
        if function.entry.0 as usize >= function.blocks.len() {
            errors.push(ValidationError::UnknownBlock {
                function: function.id,
                block: function.entry,
            });
        }
        let Some(mut definitions) = errors.filled(function.values.len(), 0_u8) else {
            return errors.finish();
        };
        for value in &function.parameters {
            if !errors.poll() {
                return errors.finish();
            }
            define_value(function.id, *value, &mut definitions, &mut errors);
        }
        let Some(mut instruction_ids) = errors.scratch(0) else {
            return errors.finish();
        };
        for block in &function.blocks {
            if !errors.poll() {
                return errors.finish();
            }
            if block
                .source
                .is_some_and(|span| !valid_source_span(module, span))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "block source",
                    id: block.id.0,
                });
            }
            for value in &block.parameters {
                if !errors.poll() {
                    return errors.finish();
                }
                define_value(function.id, *value, &mut definitions, &mut errors);
            }
            for instruction in &block.instructions {
                if !errors.poll() {
                    return errors.finish();
                }
                if instruction
                    .source
                    .is_some_and(|span| !valid_source_span(module, span))
                {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "instruction source",
                        id: instruction.id.0,
                    });
                }
                if !errors.scratch_push(&mut instruction_ids, instruction.id.0) {
                    return errors.finish();
                }
                for result in &instruction.results {
                    if !errors.poll() {
                        return errors.finish();
                    }
                    define_value(function.id, *result, &mut definitions, &mut errors);
                }
                validate_operation(module, function, instruction, &mut errors);
            }
            validate_terminator(module, function, &block.terminator, &mut errors);
        }
        check_dense("instruction", instruction_ids, &mut errors);
        for (value, definitions) in definitions.into_iter().enumerate() {
            if !errors.poll() {
                return errors.finish();
            }
            if definitions != 1 {
                errors.push(ValidationError::ValueDefinitionCount {
                    function: function.id,
                    value: ValueId(value as u32),
                    definitions,
                });
            }
        }
        validate_activation_contract(module, function, &mut errors);
        validate_control_flow_and_ssa(module, function, &mut errors);
    }
    validate_actor_message_contract(module, &mut errors);
    let mut expected_semantic_function = 0_u32;
    let mut base_semantic_functions_are_dense = true;
    for function in &module.functions {
        if !errors.poll() {
            return errors.finish();
        }
        let semantic_function = match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function }
            | FunctionOrigin::GeneratedImageEntry {
                semantic_function, ..
            }
            | FunctionOrigin::GeneratedTestHarness {
                semantic_function, ..
            } => Some(semantic_function),
            FunctionOrigin::GeneratedAsyncState { .. }
            | FunctionOrigin::GeneratedCleanup { .. } => None,
        };
        if let Some(semantic_function) = semantic_function {
            base_semantic_functions_are_dense &= semantic_function == expected_semantic_function;
            let Some(next) = expected_semantic_function.checked_add(1) else {
                base_semantic_functions_are_dense = false;
                break;
            };
            expected_semantic_function = next;
        }
    }
    base_semantic_functions_are_dense &=
        expected_semantic_function == module.source_summary.semantic_functions;
    if !base_semantic_functions_are_dense {
        errors.push(ValidationError::InvalidRecord {
            kind: "semantic function provenance",
            id: 0,
        });
    }
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownFunction(module.image_entry));
    }
    let Some(mut actor_turns) = errors.filled(module.actors.len(), Vec::new()) else {
        return errors.finish();
    };
    let Some(mut task_entries) = errors.filled(module.tasks.len(), Vec::new()) else {
        return errors.finish();
    };
    let Some(mut device_interrupts) = errors.filled(module.devices.len(), Vec::new()) else {
        return errors.finish();
    };
    let mut image_entry_count = 0usize;
    for function in &module.functions {
        if !errors.poll() {
            return errors.finish();
        }
        match function.role {
            FunctionRole::ActorTurn(actor) => {
                if let Some(turns) = actor_turns.get_mut(actor.0 as usize) {
                    if !errors.scratch_push(turns, function.id) {
                        return errors.finish();
                    }
                }
            }
            FunctionRole::Isr(device) => {
                if let Some(interrupts) = device_interrupts.get_mut(device.0 as usize) {
                    if !errors.scratch_push(interrupts, function.id) {
                        return errors.finish();
                    }
                }
            }
            FunctionRole::TaskEntry(task) => {
                if let Some(entries) = task_entries.get_mut(task.0 as usize) {
                    if !errors.scratch_push(entries, function.id) {
                        return errors.finish();
                    }
                }
            }
            FunctionRole::ImageEntry => image_entry_count += 1,
            FunctionRole::Ordinary | FunctionRole::Cleanup | FunctionRole::Test => {}
        }
    }
    if module
        .functions
        .get(module.image_entry.0 as usize)
        .is_some_and(|function| function.role != FunctionRole::ImageEntry)
        || image_entry_count != 1
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "image entry role",
            id: module.image_entry.0,
        });
    }
    for actor in &module.actors {
        if !errors.poll() {
            return errors.finish();
        }
        if actor.name.trim().is_empty() || actor.mailbox_capacity == 0 {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor",
                id: actor.id.0,
            });
        }
        require_id(
            "actor state type",
            actor.state_type.0,
            module.types.len(),
            &mut errors,
        );
        for ty in &actor.message_types {
            if !errors.poll() {
                return errors.finish();
            }
            require_id("actor message type", ty.0, module.types.len(), &mut errors);
        }
        require_canonical_ids(
            "actor message types",
            actor.id.0,
            actor.message_types.iter().map(|id| id.0),
            &mut errors,
        );
        for function in &actor.turn_functions {
            if !errors.poll() {
                return errors.finish();
            }
            require_id(
                "actor turn function",
                function.0,
                module.functions.len(),
                &mut errors,
            );
        }
        require_canonical_ids(
            "actor turn functions",
            actor.id.0,
            actor.turn_functions.iter().map(|id| id.0),
            &mut errors,
        );
        let mut turn_set_matches = false;
        if let Some(turns) = actor_turns.get(actor.id.0 as usize) {
            turn_set_matches = actor.turn_functions.len() == turns.len();
            if turn_set_matches {
                for (declared, derived) in actor.turn_functions.iter().zip(turns) {
                    if !errors.poll() {
                        return errors.finish();
                    }
                    if declared != derived {
                        turn_set_matches = false;
                        break;
                    }
                }
            }
        }
        if !turn_set_matches {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor turn set",
                id: actor.id.0,
            });
        }
        if let Some(supervisor) = actor.supervisor {
            require_id(
                "actor supervisor",
                supervisor.0,
                module.actors.len(),
                &mut errors,
            );
        }
    }
    for task in &module.tasks {
        if !errors.poll() {
            return errors.finish();
        }
        if task.name.trim().is_empty() || task.slots == 0 {
            errors.push(ValidationError::InvalidRecord {
                kind: "task",
                id: task.id.0,
            });
        }
        require_id(
            "task entry",
            task.entry.0,
            module.functions.len(),
            &mut errors,
        );
        if module
            .functions
            .get(task.entry.0 as usize)
            .is_some_and(|function| function.role != FunctionRole::TaskEntry(task.id))
            || task_entries
                .get(task.id.0 as usize)
                .is_none_or(|entries| entries.as_slice() != [task.entry])
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "task entry role",
                id: task.id.0,
            });
        }
        if let Some(supervisor) = task.supervisor {
            require_id(
                "task supervisor",
                supervisor.0,
                module.actors.len(),
                &mut errors,
            );
        }
    }
    for device in &module.devices {
        if !errors.poll() {
            return errors.finish();
        }
        let required_features_are_canonical =
            sorted_unique_strings(&device.required_features, &mut errors);
        let optional_features_are_canonical =
            sorted_unique_strings(&device.optional_features, &mut errors);
        let mut overlapping_features = false;
        for feature in &device.required_features {
            if !errors.poll() {
                return errors.finish();
            }
            overlapping_features |= device.optional_features.binary_search(feature).is_ok();
        }
        if device.name.trim().is_empty()
            || device.target_binding.trim().is_empty()
            || device.reset_timeout_ns == 0
            || device.interrupt_functions.len() > 1
            || !required_features_are_canonical
            || !optional_features_are_canonical
            || overlapping_features
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "device",
                id: device.id.0,
            });
        }
        require_id(
            "device owner",
            device.owner.0,
            module.actors.len(),
            &mut errors,
        );
        for function in &device.interrupt_functions {
            if !errors.poll() {
                return errors.finish();
            }
            require_id(
                "device interrupt function",
                function.0,
                module.functions.len(),
                &mut errors,
            );
        }
        require_canonical_ids(
            "device interrupt functions",
            device.id.0,
            device.interrupt_functions.iter().map(|id| id.0),
            &mut errors,
        );
        if device_interrupts
            .get(device.id.0 as usize)
            .is_none_or(|interrupts| device.interrupt_functions != *interrupts)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "device interrupt set",
                id: device.id.0,
            });
        }
    }
    for pool in &module.pools {
        if !errors.poll() {
            return errors.finish();
        }
        if pool.name.trim().is_empty() || pool.capacity == 0 || !pool.alignment.is_power_of_two() {
            errors.push(ValidationError::InvalidRecord {
                kind: "pool",
                id: pool.id.0,
            });
        }
        require_id(
            "pool element type",
            pool.element_type.0,
            module.types.len(),
            &mut errors,
        );
        for device in &pool.devices {
            if !errors.poll() {
                return errors.finish();
            }
            require_id("pool device", device.0, module.devices.len(), &mut errors);
        }
    }
    for region in &module.regions {
        if !errors.poll() {
            return errors.finish();
        }
        if region.name.trim().is_empty()
            || region.capacity_bytes == 0
            || !region.alignment.is_power_of_two()
            || !valid_source_span(module, region.source)
            || module
                .proofs
                .get(region.capacity_proof.0 as usize)
                .is_none_or(|proof| proof.kind != ProofKind::CapacityBound)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "region",
                id: region.id.0,
            });
        }
        require_id(
            "region capacity proof",
            region.capacity_proof.0,
            module.proofs.len(),
            &mut errors,
        );
        if let RegionClass::Pool(pool) = region.class {
            require_id("region class pool", pool.0, module.pools.len(), &mut errors);
            if region.owner != PlanOwner::Pool(pool) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "pool region owner",
                    id: region.id.0,
                });
            }
        }
        if let Some(function) = region.reset_function {
            require_id(
                "region reset function",
                function.0,
                module.functions.len(),
                &mut errors,
            );
        }
        validate_owner(module, region.owner, &mut errors);
    }
    validate_activation_plans(module, &mut errors);
    validate_actor_capacity_contract(module, &mut errors);
    validate_static_supervision_contract(module, &mut errors);
    for proof in &module.proofs {
        if !errors.poll() {
            return errors.finish();
        }
        let mut invalid_proof = proof.subject.trim().is_empty() || proof.explanation.is_empty();
        for line in &proof.explanation {
            if !errors.poll() {
                return errors.finish();
            }
            invalid_proof |= line.trim().is_empty();
        }
        for span in &proof.sources {
            if !errors.poll() {
                return errors.finish();
            }
            invalid_proof |= !valid_source_span(module, *span);
        }
        for dependency in &proof.depends_on {
            if !errors.poll() {
                return errors.finish();
            }
            invalid_proof |= dependency.0 >= proof.id.0;
        }
        if invalid_proof {
            errors.push(ValidationError::InvalidRecord {
                kind: "proof",
                id: proof.id.0,
            });
        }
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
        }
        require_canonical_ids(
            "proof dependencies",
            proof.id.0,
            proof.depends_on.iter().map(|id| id.0),
            &mut errors,
        );
    }
    for checkpoint in &module.checkpoints {
        if !errors.poll() {
            return errors.finish();
        }
        require_id(
            "checkpoint function",
            checkpoint.function.0,
            module.functions.len(),
            &mut errors,
        );
        if !valid_source_span(module, checkpoint.source) {
            errors.push(ValidationError::InvalidRecord {
                kind: "checkpoint source",
                id: checkpoint.id.0,
            });
        }
    }
    for test in &module.tests {
        if !errors.poll() {
            return errors.finish();
        }
        require_id(
            "test function",
            test.function.0,
            module.functions.len(),
            &mut errors,
        );
        if test.name.trim().is_empty()
            || test.timeout_ns == 0
            || !valid_source_span(module, test.source)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "test",
                id: test.id.0,
            });
        }
        if module
            .functions
            .get(test.function.0 as usize)
            .is_some_and(|function| function.role != FunctionRole::Test)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "test function role",
                id: test.id.0,
            });
        }
    }
    let Some(mut listed_tests) = errors.scratch(module.tests.len()) else {
        return errors.finish();
    };
    for test in &module.tests {
        if !errors.scratch_push(&mut listed_tests, test.function) {
            return errors.finish();
        }
    }
    if !sort_scratch(&mut listed_tests, &mut errors) {
        return errors.finish();
    }
    let mut invalid_test_function_set = false;
    for pair in listed_tests.windows(2) {
        if !errors.poll() {
            return errors.finish();
        }
        invalid_test_function_set |= pair[0] == pair[1];
    }
    for function in &module.functions {
        if !errors.poll() {
            return errors.finish();
        }
        invalid_test_function_set |= function.role == FunctionRole::Test
            && listed_tests.binary_search(&function.id).is_err();
    }
    if invalid_test_function_set {
        errors.push(ValidationError::InvalidRecord {
            kind: "test function set",
            id: 0,
        });
    }
    if !compiled_test_group_matches(module, limits.test_plan, is_cancelled)? {
        errors.push(ValidationError::InvalidRecord {
            kind: "compiled test-group binding",
            id: module
                .compiled_test_group
                .as_ref()
                .map_or(0, |group| group.id.0),
        });
    }
    validate_scheduler_ownership(module, &mut errors);
    validate_image_order(module, &module.startup_order, true, &mut errors);
    validate_image_order(module, &module.shutdown_order, false, &mut errors);
    if module.peak_bytes < module.static_bytes {
        errors.push(ValidationError::InvalidRecord {
            kind: "image memory plan",
            id: 0,
        });
    }
    errors.finish()
}

fn validate_scheduler_ownership(module: &FlowWir, errors: &mut ValidationContext<'_>) {
    let has_scheduled_work = !module.actors.is_empty() || !module.tasks.is_empty();
    let exact = if has_scheduled_work {
        module.schedulers.len() == 1
            && module.schedulers[0].core == 0
            && module.schedulers[0].actors.len() == module.actors.len()
            && module.schedulers[0]
                .actors
                .iter()
                .copied()
                .eq(module.actors.iter().map(|actor| actor.id))
            && module.schedulers[0].tasks.len() == module.tasks.len()
            && module.schedulers[0]
                .tasks
                .iter()
                .copied()
                .eq(module.tasks.iter().map(|task| task.id))
    } else {
        module.schedulers.is_empty()
    };
    if !exact {
        errors.push(ValidationError::InvalidRecord {
            kind: "scheduler ownership partition",
            id: module.schedulers.first().map_or(0, |plan| plan.core),
        });
    }
}

fn validate_image_order(
    module: &FlowWir,
    order: &[PlanOwner],
    startup: bool,
    errors: &mut ValidationContext<'_>,
) {
    let expected_length = 1_usize
        .checked_add(module.actors.len())
        .and_then(|count| count.checked_add(module.tasks.len()))
        .and_then(|count| count.checked_add(module.devices.len()))
        .and_then(|count| count.checked_add(module.pools.len()));
    let Some(expected_length) = expected_length else {
        errors.push(ValidationError::InvalidRecord {
            kind: "image ownership order",
            id: 0,
        });
        return;
    };
    let Some(mut expected) = errors.scratch(expected_length) else {
        return;
    };
    if !errors.scratch_push(&mut expected, PlanOwner::Runtime) {
        return;
    }
    for actor in &module.actors {
        if !errors.scratch_push(&mut expected, PlanOwner::Actor(actor.id)) {
            return;
        }
    }
    for task in &module.tasks {
        if !errors.scratch_push(&mut expected, PlanOwner::Task(task.id)) {
            return;
        }
    }
    for device in &module.devices {
        if !errors.scratch_push(&mut expected, PlanOwner::Device(device.id)) {
            return;
        }
    }
    for pool in &module.pools {
        if !errors.scratch_push(&mut expected, PlanOwner::Pool(pool.id)) {
            return;
        }
    }
    let mut valid = order.len() == expected.len();
    if startup {
        for (actual, expected) in order.iter().zip(&expected) {
            if !errors.poll() {
                return;
            }
            validate_owner(module, *actual, errors);
            valid &= actual == expected;
        }
    } else {
        for (actual, expected) in order.iter().zip(expected.iter().rev()) {
            if !errors.poll() {
                return;
            }
            validate_owner(module, *actual, errors);
            valid &= actual == expected;
        }
    }
    if !valid {
        errors.push(ValidationError::InvalidRecord {
            kind: if startup {
                "startup ownership order"
            } else {
                "shutdown ownership order"
            },
            id: 0,
        });
    }
}

fn compiled_test_group_matches(
    module: &FlowWir,
    limits: TestPlanLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ValidationFailure> {
    let entry = module.functions.get(module.image_entry.0 as usize);
    let Some(group) = &module.compiled_test_group else {
        return Ok(module.tests.is_empty()
            && !matches!(
                entry.map(|function| function.origin),
                Some(FunctionOrigin::GeneratedTestHarness { .. })
            ));
    };
    if let Err(error) = group.validate_compiled_binding_with_limits(limits, is_cancelled) {
        return match error {
            wrela_test_model::TestModelError::Cancelled => Err(ValidationFailure::Cancelled),
            wrela_test_model::TestModelError::ResourceLimit { resource, limit } => {
                Err(ValidationFailure::ResourceLimit { resource, limit })
            }
            _ => Ok(false),
        };
    }
    Ok(match &group.root {
        wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
            if module.name != *harness_name
                || !matches!(
                    entry.map(|function| function.origin),
                    Some(FunctionOrigin::GeneratedTestHarness { group: actual, .. })
                        if actual == group.id.0
                )
                || module.tests.len() != group.tests.len()
            {
                return Ok(false);
            }
            let mut exact = true;
            for (local, planned) in module.tests.iter().zip(&group.tests) {
                if is_cancelled() {
                    return Err(ValidationFailure::Cancelled);
                }
                let wrela_test_model::ImageTestInvocation::GeneratedFunction { function_key } =
                    planned.invocation
                else {
                    exact = false;
                    continue;
                };
                exact &= local.plan_id == planned.descriptor.id.0
                    && local.function_key == function_key.0
                    && local.name == planned.descriptor.name
                    && local.kind == TestKind::Integration
                    && planned.descriptor.kind == wrela_test_model::TestKind::IntegrationImage
                    && Some(local.source) == planned.descriptor.source
                    && local.timeout_ns == planned.descriptor.timeout_ns;
            }
            exact
        }
        wrela_test_model::ImageRoot::Declared { image_name, .. } => {
            module.name == *image_name
                && module.tests.is_empty()
                && matches!(
                    entry.map(|function| function.origin),
                    Some(FunctionOrigin::GeneratedImageEntry { .. })
                )
        }
    })
}

fn validate_activation_plans(module: &FlowWir, errors: &mut ValidationContext<'_>) {
    let Some(mut uses) = errors.filled(module.activations.len(), 0_u32) else {
        return;
    };
    let mut prior_key = None;
    for plan in &module.activations {
        if !errors.poll() {
            return;
        }
        require_id(
            "activation caller",
            plan.caller.0,
            module.functions.len(),
            errors,
        );
        require_id(
            "activation callee",
            plan.callee.0,
            module.functions.len(),
            errors,
        );
        require_id(
            "activation region",
            plan.region.0,
            module.regions.len(),
            errors,
        );
        require_id(
            "activation capacity proof",
            plan.capacity_proof.0,
            module.proofs.len(),
            errors,
        );
        let key = (
            plan.caller.0,
            plan.source.file.0,
            plan.source.range.start,
            plan.source.range.end,
            plan.callee.0,
        );
        let canonical = prior_key.is_none_or(|prior| prior < key);
        prior_key = Some(key);
        let caller = module.functions.get(plan.caller.0 as usize);
        let callee = module.functions.get(plan.callee.0 as usize);
        let owner = caller.and_then(|function| match function.role {
            FunctionRole::ActorTurn(actor) => Some(PlanOwner::Actor(actor)),
            FunctionRole::TaskEntry(task)
                if module
                    .tasks
                    .get(task.0 as usize)
                    .is_some_and(|task| task.slots == 1) =>
            {
                Some(PlanOwner::Task(task))
            }
            FunctionRole::TaskEntry(_) => None,
            FunctionRole::Ordinary
            | FunctionRole::Isr(_)
            | FunctionRole::Cleanup
            | FunctionRole::ImageEntry
            | FunctionRole::Test => None,
        });
        let region = module.regions.get(plan.region.0 as usize);
        let proof = module.proofs.get(plan.capacity_proof.0 as usize);
        let Some(region_name_matches) =
            caller.zip(region).map_or(Some(false), |(caller, region)| {
                polled_joined_name_matches(
                    &region.name,
                    &caller.name,
                    ".async-activation-frame",
                    errors,
                )
            })
        else {
            return;
        };
        let mut cleanup_proofs = callee
            .into_iter()
            .flat_map(|callee| callee.proofs.iter())
            .filter(|proof| {
                module
                    .proofs
                    .get(proof.0 as usize)
                    .is_some_and(|record| record.kind == ProofKind::CleanupAcyclic)
            });
        let cleanup_proof = cleanup_proofs.next().copied();
        let unique_cleanup = cleanup_proofs.next().is_none();
        let capacity_bytes = plan.frame_bytes.checked_mul(u64::from(plan.maximum_live));
        if !canonical
            || plan.frame_bytes == 0
            || plan.maximum_live != 1
            || !valid_source_span(module, plan.source)
            || caller.is_none_or(|function| {
                function.color != FunctionColor::Async
                    || function.proofs.binary_search(&plan.capacity_proof).is_err()
            })
            || callee.is_none_or(|function| {
                function.color != FunctionColor::Async
                    || function.role != FunctionRole::Ordinary
                    || function.frame_bound.max(1) != plan.frame_bytes
            })
            || owner.is_none()
            || region.is_none_or(|region| {
                region.id != plan.region
                    || !region_name_matches
                    || region.class != RegionClass::TaskFrame
                    || Some(region.capacity_bytes) != capacity_bytes
                    || region.alignment != 8
                    || region.reset_function.is_some()
                    || Some(region.owner) != owner
                    || region.capacity_proof != plan.capacity_proof
                    || region.source != plan.source
            })
            || proof.is_none_or(|proof| {
                proof.id != plan.capacity_proof
                    || proof.kind != ProofKind::CapacityBound
                    || proof.bound != Some(u64::from(plan.maximum_live))
                    || proof.sources.as_slice() != [plan.source]
                    || cleanup_proof.is_none()
                    || !unique_cleanup
                    || proof.depends_on.as_slice() != cleanup_proof.as_slice()
            })
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation plan",
                id: plan.id.0,
            });
        }
    }

    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        for block in &function.blocks {
            if !errors.poll() {
                return;
            }
            for instruction in &block.instructions {
                if !errors.poll() {
                    return;
                }
                let FlowOperation::AsyncCall {
                    function: callee,
                    plan,
                    ..
                } = &instruction.operation
                else {
                    continue;
                };
                let valid = instruction.source.is_some_and(|source| {
                    module
                        .activations
                        .get(plan.0 as usize)
                        .is_some_and(|record| {
                            record.id == *plan
                                && record.caller == function.id
                                && record.callee == *callee
                                && record.source == source
                                && uses.get_mut(plan.0 as usize).is_some_and(|count| {
                                    *count = count.saturating_add(1);
                                    true
                                })
                        })
                });
                if !valid {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "activation call binding",
                        id: instruction.id.0,
                    });
                }
            }
        }
    }
    for (index, uses) in uses.into_iter().enumerate() {
        if uses != 1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation plan use",
                id: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
}

fn polled_joined_name_matches(
    joined: &str,
    base: &str,
    suffix: &str,
    errors: &mut ValidationContext<'_>,
) -> Option<bool> {
    let Some(prefix_bytes) = joined.len().checked_sub(suffix.len()) else {
        return Some(false);
    };
    if prefix_bytes != base.len() {
        return Some(false);
    }
    let (prefix, actual_suffix) = joined.as_bytes().split_at(prefix_bytes);
    if actual_suffix != suffix.as_bytes() {
        return Some(false);
    }
    for (actual, expected) in prefix.chunks(4096).zip(base.as_bytes().chunks(4096)) {
        if !errors.poll() {
            return None;
        }
        if actual != expected {
            return Some(false);
        }
    }
    Some(true)
}

fn validate_actor_capacity_contract(module: &FlowWir, errors: &mut ValidationContext<'_>) {
    if module.actors.is_empty() {
        if !module.tasks.is_empty() || !module.activations.is_empty() {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor capacity closure",
                id: 0,
            });
        }
        return;
    }
    let state_region_count = module
        .actors
        .iter()
        .filter(|actor| {
            module.regions.iter().any(|region| {
                region.owner == PlanOwner::Actor(actor.id)
                    && polled_joined_name_matches(&region.name, &actor.name, ".state", errors)
                        == Some(true)
            })
        })
        .count();
    let base_region_count = module
        .actors
        .len()
        .checked_add(state_region_count)
        .and_then(|count| {
            count.checked_add(
                module
                    .actors
                    .iter()
                    .filter(|actor| !actor.turn_functions.is_empty())
                    .count(),
            )
        })
        .and_then(|count| count.checked_add(module.tasks.len()));
    let expected_regions =
        base_region_count.and_then(|count| count.checked_add(module.activations.len()));
    let mut base_bytes = Some(0_u64);
    let mut valid = expected_regions == Some(module.regions.len());
    let mut region_cursor = 0usize;
    for actor in &module.actors {
        if !errors.poll() {
            return;
        }
        let mailbox_index = Some(region_cursor);
        region_cursor = region_cursor.saturating_add(1);
        let state_index = module.regions.get(region_cursor).and_then(|region| {
            (polled_joined_name_matches(&region.name, &actor.name, ".state", errors) == Some(true))
                .then_some(region_cursor)
        });
        if state_index.is_some() {
            region_cursor = region_cursor.saturating_add(1);
        }
        let turn_index = (!actor.turn_functions.is_empty()).then_some(region_cursor);
        if turn_index.is_some() {
            region_cursor = region_cursor.saturating_add(1);
        }
        let mailbox = mailbox_index.and_then(|index| module.regions.get(index));
        let state = state_index.and_then(|index| module.regions.get(index));
        let turn = turn_index.and_then(|index| module.regions.get(index));
        let mailbox_bytes = u64::from(actor.mailbox_capacity).checked_mul(16);
        let mut turn_bytes = u64::from(!actor.turn_functions.is_empty());
        for function in &actor.turn_functions {
            if !errors.poll() {
                return;
            }
            let Some(function) = module.functions.get(function.0 as usize) else {
                valid = false;
                continue;
            };
            turn_bytes = turn_bytes.max(function.frame_bound.max(1));
        }
        let Some(mailbox_name_matches) = mailbox.map_or(Some(false), |region| {
            polled_joined_name_matches(&region.name, &actor.name, ".mailbox", errors)
        }) else {
            return;
        };
        let Some(turn_name_matches) = turn.map_or(Some(false), |region| {
            polled_joined_name_matches(&region.name, &actor.name, ".turn-frame", errors)
        }) else {
            return;
        };
        let state_matches = state.is_none_or(|region| {
            state_index
                .and_then(|index| u32::try_from(index).ok())
                .is_some_and(|index| region.id == RegionId(index))
                && region.class == RegionClass::Image
                && region.capacity_bytes == 8
                && region.alignment == 8
                && region.owner == PlanOwner::Actor(actor.id)
                && module
                    .proofs
                    .get(region.capacity_proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.id == region.capacity_proof
                            && proof.kind == ProofKind::CapacityBound
                            && proof.bound == Some(1)
                            && proof.sources.as_slice() == [region.source]
                            && proof.depends_on.is_empty()
                    })
        });
        valid &= mailbox_bytes.is_some()
            && mailbox.is_some_and(|region| {
                mailbox_index
                    .and_then(|index| u32::try_from(index).ok())
                    .is_some_and(|index| region.id == RegionId(index))
                    && mailbox_name_matches
                    && region.class == RegionClass::Image
                    && Some(region.capacity_bytes) == mailbox_bytes
                    && region.alignment == 8
                    && region.owner == PlanOwner::Actor(actor.id)
                    && module
                        .proofs
                        .get(region.capacity_proof.0 as usize)
                        .is_some_and(|proof| {
                            proof.id == region.capacity_proof
                                && proof.kind == ProofKind::CapacityBound
                                && proof.bound == Some(u64::from(actor.mailbox_capacity))
                                && proof.sources.len() == 1
                                && proof.sources[0].file == region.source.file
                                && proof.sources[0].range.start >= region.source.range.start
                                && proof.sources[0].range.end <= region.source.range.end
                        })
            })
            && (actor.turn_functions.is_empty()
                || turn.is_some_and(|region| {
                    turn_index
                        .and_then(|index| u32::try_from(index).ok())
                        .is_some_and(|index| region.id == RegionId(index))
                        && turn_name_matches
                        && region.class == RegionClass::TaskFrame
                        && region.capacity_bytes == turn_bytes
                        && region.alignment == 8
                        && region.owner == PlanOwner::Actor(actor.id)
                        && module
                            .proofs
                            .get(region.capacity_proof.0 as usize)
                            .is_some_and(|proof| {
                                proof.id == region.capacity_proof
                                    && proof.kind == ProofKind::CapacityBound
                                    && proof.bound == Some(1)
                                    && proof.sources.as_slice() == [region.source]
                            })
                }))
            && state_matches;
        base_bytes = base_bytes
            .and_then(|bytes| mailbox_bytes.and_then(|mailbox| bytes.checked_add(mailbox)))
            .and_then(|bytes| {
                if state.is_some() {
                    bytes.checked_add(8)
                } else {
                    Some(bytes)
                }
            })
            .and_then(|bytes| bytes.checked_add(turn_bytes));
        valid &= base_bytes.is_some();
    }
    let task_start = Some(region_cursor);
    for (index, task) in module.tasks.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let frame = module
            .functions
            .get(task.entry.0 as usize)
            .map(|function| function.frame_bound.max(1));
        let bytes = frame.and_then(|frame| frame.checked_mul(u64::from(task.slots)));
        let region_index = task_start.and_then(|start| start.checked_add(index));
        let region = region_index.and_then(|index| module.regions.get(index));
        let Some(region_name_matches) = region.map_or(Some(false), |region| {
            polled_joined_name_matches(&region.name, &task.name, ".frame", errors)
        }) else {
            return;
        };
        valid &= bytes.is_some()
            && region.is_some_and(|region| {
                region_index
                    .and_then(|index| u32::try_from(index).ok())
                    .is_some_and(|index| region.id == RegionId(index))
                    && region_name_matches
                    && region.class == RegionClass::TaskFrame
                    && Some(region.capacity_bytes) == bytes
                    && region.alignment == 8
                    && region.owner == PlanOwner::Task(task.id)
                    && module
                        .proofs
                        .get(region.capacity_proof.0 as usize)
                        .is_some_and(|proof| {
                            proof.id == region.capacity_proof
                                && proof.kind == ProofKind::CapacityBound
                                && proof.bound == Some(u64::from(task.slots))
                                && proof.sources.as_slice() == [region.source]
                        })
            });
        base_bytes = base_bytes.and_then(|total| bytes.and_then(|bytes| total.checked_add(bytes)));
        valid &= base_bytes.is_some();
    }
    let mut activation_bytes = Some(0_u64);
    for (index, plan) in module.activations.iter().enumerate() {
        if !errors.poll() {
            return;
        }
        let expected_region = base_region_count
            .and_then(|start| start.checked_add(index))
            .and_then(|index| u32::try_from(index).ok())
            .map(RegionId);
        valid &= expected_region == Some(plan.region);
        let bytes = plan.frame_bytes.checked_mul(u64::from(plan.maximum_live));
        activation_bytes =
            activation_bytes.and_then(|total| bytes.and_then(|bytes| total.checked_add(bytes)));
        valid &= activation_bytes.is_some();
    }
    let total = base_bytes
        .and_then(|base| activation_bytes.and_then(|activation| base.checked_add(activation)));
    valid &= total == Some(module.static_bytes) && total == Some(module.peak_bytes);
    let mut wait_proof = None;
    let mut supervision_proof = None;
    let mut final_proof = None;
    for proof in &module.proofs {
        if !errors.poll() {
            return;
        }
        match proof.kind {
            ProofKind::WaitGraphAcyclic => {
                valid &= wait_proof.is_none();
                wait_proof = Some(proof.id);
            }
            ProofKind::ImageClosed => {
                valid &= final_proof.is_none();
                final_proof = Some(proof);
            }
            ProofKind::SupervisionComplete => {
                valid &= supervision_proof.is_none();
                supervision_proof = Some(proof.id);
            }
            _ => {}
        }
    }
    valid &= module
        .proofs
        .first()
        .is_some_and(|proof| proof.id == ProofId(0) && proof.kind == ProofKind::TypeChecked)
        && module
            .proofs
            .get(1)
            .is_some_and(|proof| proof.id == ProofId(1) && proof.kind == ProofKind::EffectsAllowed)
        && wait_proof.is_some()
        && supervision_proof.is_some();
    let Some(final_proof) = final_proof else {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor capacity closure",
            id: 0,
        });
        return;
    };
    valid &= final_proof.bound == total;
    let base_proof = if module.activations.is_empty() {
        Some(final_proof)
    } else {
        valid &= final_proof.depends_on.len() == module.activations.len().saturating_add(1);
        final_proof
            .depends_on
            .first()
            .and_then(|id| module.proofs.get(id.0 as usize))
            .filter(|proof| proof.kind == ProofKind::CapacityBound && proof.bound == base_bytes)
    };
    valid &= base_proof.is_some();
    if let (Some(base_proof), Some(wait_proof), Some(supervision_proof), Some(base_region_count)) =
        (base_proof, wait_proof, supervision_proof, base_region_count)
    {
        let Some(expected_dependencies) = base_region_count.checked_add(4) else {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor capacity closure",
                id: 0,
            });
            return;
        };
        let Some(mut expected) = errors.scratch(expected_dependencies) else {
            return;
        };
        for proof in [ProofId(0), ProofId(1), wait_proof, supervision_proof] {
            if !errors.scratch_push(&mut expected, proof) {
                return;
            }
        }
        for region in module.regions.iter().take(base_region_count) {
            if !errors.poll() {
                return;
            }
            if !errors.scratch_push(&mut expected, region.capacity_proof) {
                return;
            }
        }
        if !sort_scratch(&mut expected, errors) {
            return;
        }
        valid &= expected.len() == base_proof.depends_on.len();
        for (expected, actual) in expected.iter().zip(&base_proof.depends_on) {
            if !errors.poll() {
                return;
            }
            valid &= expected == actual;
        }
        if let Some(entry) = module.functions.get(module.image_entry.0 as usize) {
            valid &= entry.proofs.binary_search(&final_proof.id).is_ok()
                && entry.proofs.binary_search(&base_proof.id).is_ok()
                && entry.proofs.binary_search(&wait_proof).is_ok()
                && entry.proofs.binary_search(&supervision_proof).is_ok();
            for region in module.regions.iter().take(base_region_count) {
                if !errors.poll() {
                    return;
                }
                valid &= entry.proofs.binary_search(&region.capacity_proof).is_ok();
            }
        } else {
            valid = false;
        }
        let expected_sources = module.actors.len().checked_add(1);
        valid &= expected_sources == Some(base_proof.sources.len());
        if let Some(root_source) = module
            .proofs
            .first()
            .and_then(|proof| proof.sources.first())
        {
            valid &= base_proof.sources.first() == Some(root_source);
        } else {
            valid = false;
        }
        for (index, actor) in module.actors.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            let expected = module.regions.iter().find_map(|region| {
                (region.owner == PlanOwner::Actor(actor.id)
                    && polled_joined_name_matches(&region.name, &actor.name, ".mailbox", errors)
                        == Some(true))
                .then_some(region.source)
            });
            valid &= base_proof.sources.get(index.saturating_add(1)).copied() == expected;
        }
    } else {
        valid = false;
    }
    if !module.activations.is_empty() {
        for (index, plan) in module.activations.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            valid &= final_proof
                .depends_on
                .get(index.saturating_add(1))
                .is_some_and(|dependency| *dependency == plan.capacity_proof)
                && final_proof.sources.get(index).copied() == Some(plan.source);
        }
        valid &= final_proof.sources.len() == module.activations.len();
    }
    if !valid {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor capacity closure",
            id: 0,
        });
    }
}

fn validate_static_supervision_contract(module: &FlowWir, errors: &mut ValidationContext<'_>) {
    if module.actors.is_empty() {
        return;
    }
    let mut supervision = None;
    let mut image_closed = None;
    for proof in &module.proofs {
        if !errors.poll() {
            return;
        }
        match proof.kind {
            ProofKind::SupervisionComplete if supervision.is_some() => {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor supervision proof",
                    id: proof.id.0,
                });
            }
            ProofKind::SupervisionComplete => supervision = Some(proof),
            ProofKind::ImageClosed => image_closed = Some(proof),
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
    let Some(node_count) = module.actors.len().checked_add(module.tasks.len()) else {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor supervision proof",
            id: proof.id.0,
        });
        return;
    };
    let Some(mut expected_sources) = errors.scratch(node_count) else {
        return;
    };
    for actor in &module.actors {
        if !errors.poll() {
            return;
        }
        let source = module
            .regions
            .iter()
            .find(|region| region.owner == PlanOwner::Actor(actor.id))
            .map(|region| region.source);
        let mut cursor = actor.supervisor;
        let mut ancestry_valid = true;
        for _ in 0..module.actors.len() {
            let Some(parent) = cursor else {
                break;
            };
            if parent == actor.id {
                ancestry_valid = false;
                break;
            }
            let Some(parent_record) = module.actors.get(parent.0 as usize) else {
                ancestry_valid = false;
                break;
            };
            cursor = parent_record.supervisor;
        }
        ancestry_valid &= cursor.is_none();
        if !ancestry_valid || source.is_none() {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor supervision topology",
                id: actor.id.0,
            });
        }
        if let Some(source) = source {
            if !errors.scratch_push(&mut expected_sources, source) {
                return;
            }
        }
    }
    for task in &module.tasks {
        if !errors.poll() {
            return;
        }
        let parent_matches = task.supervisor.is_some_and(|actor| {
            module
                .actors
                .get(actor.0 as usize)
                .is_some_and(|candidate| candidate.id == actor)
        });
        let entry_matches = module
            .functions
            .get(task.entry.0 as usize)
            .is_some_and(|function| function.role == FunctionRole::TaskEntry(task.id));
        let source = module
            .regions
            .iter()
            .find(|region| region.owner == PlanOwner::Task(task.id))
            .map(|region| region.source);
        if !parent_matches || !entry_matches || source.is_none() {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor supervision topology",
                id: task.id.0,
            });
        }
        if let Some(source) = source {
            if !errors.scratch_push(&mut expected_sources, source) {
                return;
            }
        }
    }
    let exact_bound = u64::try_from(node_count).ok();
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
    if proof.subject != "complete static actor/task parent topology"
        || proof.bound != exact_bound
        || proof.depends_on.as_slice() != [ProofId(0)]
        || proof.sources.as_slice() != expected_sources.as_slice()
        || proof.explanation.as_slice()
            != [
                "the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed",
            ]
        || !entry_has_proof
        || !closure_reaches
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor supervision proof",
            id: proof.id.0,
        });
    }
}

fn valid_source_span(module: &FlowWir, span: Span) -> bool {
    span.file.0 < module.source_summary.hir_files && span.range.start <= span.range.end
}

fn validate_owner(module: &FlowWir, owner: PlanOwner, errors: &mut ValidationContext<'_>) {
    match owner {
        PlanOwner::Runtime | PlanOwner::BakedArtifact(_) => {}
        PlanOwner::Actor(id) => require_id("owner actor", id.0, module.actors.len(), errors),
        PlanOwner::Task(id) => require_id("owner task", id.0, module.tasks.len(), errors),
        PlanOwner::Device(id) => require_id("owner device", id.0, module.devices.len(), errors),
        PlanOwner::Pool(id) => require_id("owner pool", id.0, module.pools.len(), errors),
    }
}

fn activation_result_matches_function(
    module: &FlowWir,
    activation_result: TypeId,
    callee: &FlowFunction,
) -> bool {
    match callee.result_types.as_slice() {
        [] => module
            .types
            .get(activation_result.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::Unit)),
        [result] => *result == activation_result,
        _ => false,
    }
}

fn is_activation_value(module: &FlowWir, function: &FlowFunction, value: ValueId) -> bool {
    function
        .values
        .get(value.0 as usize)
        .and_then(|value| module.types.get(value.ty.0 as usize))
        .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::Activation { .. }))
}

fn is_reservation_value(module: &FlowWir, function: &FlowFunction, value: ValueId) -> bool {
    function
        .values
        .get(value.0 as usize)
        .and_then(|value| module.types.get(value.ty.0 as usize))
        .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::Reservation))
}

fn is_actor_capability_value(module: &FlowWir, function: &FlowFunction, value: ValueId) -> bool {
    function
        .values
        .get(value.0 as usize)
        .and_then(|value| module.types.get(value.ty.0 as usize))
        .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::ActorHandle(_)))
}

fn actor_mailbox_proof(
    module: &FlowWir,
    actor: ActorId,
    errors: &mut ValidationContext<'_>,
) -> Option<ProofId> {
    let mut proof = None;
    for region in &module.regions {
        if !errors.poll() {
            return None;
        }
        if region.owner == PlanOwner::Actor(actor)
            && region.class == RegionClass::Image
            && proof.replace(region.capacity_proof).is_some()
        {
            return None;
        }
    }
    proof
}

fn flow_value_type(function: &FlowFunction, value: ValueId) -> Option<TypeId> {
    function
        .values
        .get(value.0 as usize)
        .filter(|record| record.id == value)
        .map(|record| record.ty)
}

/// The currently executable actor-message subset is deliberately exact: one
/// startup-once task may reserve and commit one unit message, and the
/// matching actor turn begins by consuming that mailbox entry. Reservations
/// cannot escape through SSA edges or be duplicated.
fn validate_actor_message_contract(module: &FlowWir, errors: &mut ValidationContext<'_>) {
    let Some(mut incoming) = errors.filled(module.functions.len(), 0_u8) else {
        return;
    };
    let Some(mut receives) = errors.filled(module.functions.len(), 0_u8) else {
        return;
    };
    let Some(mut reply_incoming) = errors.filled(module.functions.len(), 0_u8) else {
        return;
    };
    let Some(mut reply_resolves) = errors.filled(module.functions.len(), 0_u8) else {
        return;
    };
    let mut reservation_type_count = 0_u8;
    for ty in &module.types {
        if !errors.poll() {
            return;
        }
        if ty.kind == FlowTypeKind::Reservation {
            reservation_type_count = reservation_type_count.saturating_add(1);
        }
    }
    let mut reserve_count = 0_u8;

    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        let Some(mut definitions) = errors.filled(function.values.len(), 0_u8) else {
            return;
        };
        let Some(mut commits) = errors.filled(function.values.len(), 0_u8) else {
            return;
        };

        for parameter in &function.parameters {
            if !errors.poll() {
                return;
            }
            if is_reservation_value(module, function, *parameter) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reservation function parameter",
                    id: parameter.0,
                });
            }
        }

        for block in &function.blocks {
            if !errors.poll() {
                return;
            }
            for parameter in &block.parameters {
                if !errors.poll() {
                    return;
                }
                if is_reservation_value(module, function, *parameter) {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "actor reservation block parameter",
                        id: parameter.0,
                    });
                }
            }
            for (index, instruction) in block.instructions.iter().enumerate() {
                if !errors.poll() {
                    return;
                }
                let reserve = match &instruction.operation {
                    FlowOperation::ActorReserve {
                        actor,
                        method,
                        proof,
                    } => Some((*actor, *method, *proof)),
                    _ => None,
                };
                for result in &instruction.results {
                    if !errors.poll() {
                        return;
                    }
                    if !is_reservation_value(module, function, *result) {
                        continue;
                    }
                    if reserve.is_some() && instruction.results.len() == 1 {
                        if let Some(count) = definitions.get_mut(result.0 as usize) {
                            *count = count.saturating_add(1);
                        }
                    } else {
                        errors.push(ValidationError::InvalidRecord {
                            kind: "actor reservation definition",
                            id: result.0,
                        });
                    }
                }

                match &instruction.operation {
                    FlowOperation::ActorReserve {
                        actor,
                        method,
                        proof,
                    } => {
                        reserve_count = reserve_count.saturating_add(1);
                        let result = instruction.results.first().copied();
                        let task_actor = match function.role {
                            FunctionRole::TaskEntry(task) => module
                                .tasks
                                .get(task.0 as usize)
                                .filter(|record| record.id == task)
                                .and_then(|record| record.supervisor),
                            FunctionRole::ActorTurn(actor) => Some(actor),
                            _ => None,
                        };
                        let target = module.functions.get(method.0 as usize).filter(|target| {
                            target.id == *method
                                && target.role == FunctionRole::ActorTurn(*actor)
                                && target.color == FunctionColor::Async
                        });
                        let state_parameter_matches = target.is_some_and(|target| {
                            matches!(target.parameters.as_slice(), [state]
                                if flow_value_type(target, *state)
                                    == module
                                        .actors
                                        .get(actor.0 as usize)
                                        .map(|plan| plan.state_type))
                                && target.result_types.is_empty()
                        });
                        let mailbox = actor_mailbox_proof(module, *actor, errors);
                        if !errors.poll() {
                            return;
                        }
                        let mut function_has_permit = false;
                        for listed in &function.proofs {
                            if !errors.poll() {
                                return;
                            }
                            function_has_permit |= listed == proof;
                        }
                        let permit_matches = module.proofs.get(proof.0 as usize).is_some_and(|p| {
                            p.id == *proof
                                && p.kind == ProofKind::CapacityBound
                                && p.bound == Some(1)
                                && instruction
                                    .source
                                    .is_some_and(|source| p.sources.as_slice() == [source])
                                && mailbox
                                    .is_some_and(|mailbox| p.depends_on.as_slice() == [mailbox])
                                && function_has_permit
                        });
                        let immediately_committed = matches!(
                            (result, block.instructions.get(index.saturating_add(1))),
                            (
                                Some(reservation),
                                Some(Instruction {
                                    results,
                                    operation: FlowOperation::ActorCommit {
                                        reservation: committed,
                                        arguments,
                                    },
                                    source,
                                    ..
                                })
                            ) if results.is_empty()
                                && *committed == reservation
                                && arguments.is_empty()
                                && *source == instruction.source
                        );
                        let incoming_count = incoming.get_mut(method.0 as usize).map(|count| {
                            *count = count.saturating_add(1);
                            *count
                        });
                        let cross_actor = module.actors.len() == 2
                            && task_actor == Some(ActorId(1))
                            && *actor == ActorId(0)
                            && matches!(
                                index.checked_sub(1).and_then(|prior| block.instructions.get(prior)),
                                Some(Instruction {
                                    results,
                                    operation: FlowOperation::ActorCapability {
                                        actor: capability_actor,
                                        proof: wiring_proof,
                                    },
                                    ..
                                }) if *capability_actor == *actor
                                    && matches!(results.as_slice(), [capability]
                                        if function.values.get(capability.0 as usize).is_some_and(|value| {
                                            module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                                                ty.kind == FlowTypeKind::ActorHandle(*actor)
                                                    && ty.copyable
                                                    && !ty.strict_linear
                                            })
                                        }))
                                    && module.proofs.get(wiring_proof.0 as usize).is_some_and(|proof| {
                                        proof.kind == ProofKind::ActorAsIf
                                            && proof.bound == Some(1)
                                            && proof.sources.len() == 1
                                            && proof.depends_on.is_empty()
                                    })
                            );
                        if result
                            .is_none_or(|result| !is_reservation_value(module, function, result))
                            || (task_actor != Some(*actor) && !cross_actor)
                            || target.is_none()
                            || !state_parameter_matches
                            || !permit_matches
                            || !immediately_committed
                            || incoming_count != Some(1)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reserve contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    FlowOperation::ActorCommit {
                        reservation,
                        arguments,
                    } => {
                        if let Some(count) = commits.get_mut(reservation.0 as usize) {
                            *count = count.saturating_add(1);
                        }
                        let prior = index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        let target = prior.and_then(|prior| match prior.operation {
                            FlowOperation::ActorReserve { method, .. }
                                if prior.results.as_slice() == [*reservation]
                                    && prior.source == instruction.source =>
                            {
                                module.functions.get(method.0 as usize)
                            }
                            _ => None,
                        });
                        let arguments_match = arguments.is_empty()
                            && target.is_some_and(|target| {
                                target.parameters.len() == 1 && target.result_types.is_empty()
                            });
                        if !instruction.results.is_empty()
                            || !is_reservation_value(module, function, *reservation)
                            || target.is_none()
                            || !arguments_match
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor commit contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    FlowOperation::ActorReplyRequest {
                        actor,
                        method,
                        permit,
                        reply,
                    } => {
                        let task_actor = match function.role {
                            FunctionRole::TaskEntry(task) => module
                                .tasks
                                .get(task.0 as usize)
                                .filter(|record| record.id == task)
                                .and_then(|record| record.supervisor),
                            _ => None,
                        };
                        let target = module.functions.get(method.0 as usize);
                        let result_is_u64 = matches!(instruction.results.as_slice(), [result]
                        if flow_value_type(function, *result).and_then(|ty| {
                            module.types.get(ty.0 as usize)
                        }).is_some_and(|ty| {
                            ty.kind == FlowTypeKind::Scalar(ScalarType::Integer {
                                signed: false,
                                bits: 64,
                            })
                        }));
                        let target_type_proof = target.and_then(|target| {
                            target.proofs.iter().copied().find(|candidate| {
                                module
                                    .proofs
                                    .get(candidate.0 as usize)
                                    .is_some_and(|record| record.kind == ProofKind::TypeChecked)
                            })
                        });
                        let mut expected_dependencies =
                            target_type_proof.map(|type_proof| [type_proof, *permit]);
                        if let Some(expected) = &mut expected_dependencies {
                            expected.sort_unstable();
                        }
                        let exact_target = target.is_some_and(|target| {
                            target.role == FunctionRole::ActorTurn(*actor)
                                && target.color == FunctionColor::Async
                                && matches!(target.parameters.as_slice(), [state]
                                    if flow_value_type(target, *state)
                                        == module.actors.get(actor.0 as usize).map(|plan| plan.state_type))
                                && matches!(target.result_types.as_slice(), [result]
                                    if module.types.get(result.0 as usize).is_some_and(|ty| {
                                        ty.kind == FlowTypeKind::Scalar(ScalarType::Integer {
                                            signed: false,
                                            bits: 64,
                                        })
                                    }))
                        });
                        let exact_capability = matches!(
                            index.checked_sub(1).and_then(|prior| block.instructions.get(prior)),
                            Some(Instruction {
                                operation: FlowOperation::ActorCapability {
                                    actor: capability_actor,
                                    ..
                                },
                                ..
                            }) if capability_actor == actor
                        );
                        let permit_matches =
                            module.proofs.get(permit.0 as usize).is_some_and(|proof| {
                                proof.kind == ProofKind::CapacityBound
                                    && proof.bound == Some(1)
                                    && function.proofs.contains(permit)
                            });
                        let reply_matches =
                            module.proofs.get(reply.0 as usize).is_some_and(|proof| {
                                proof.kind == ProofKind::ActorReplyExactlyOnce
                                    && proof.bound == Some(1)
                                    && expected_dependencies
                                        .is_some_and(|expected| proof.depends_on == expected)
                                    && function.proofs.contains(reply)
                            });
                        let incoming_count = incoming.get_mut(method.0 as usize).map(|count| {
                            *count = count.saturating_add(1);
                            *count
                        });
                        let reply_count = reply_incoming.get_mut(method.0 as usize).map(|count| {
                            *count = count.saturating_add(1);
                            *count
                        });
                        if module.actors.len() != 2
                            || task_actor != Some(ActorId(1))
                            || *actor != ActorId(0)
                            || !result_is_u64
                            || !exact_target
                            || !exact_capability
                            || !permit_matches
                            || !reply_matches
                            || incoming_count != Some(1)
                            || reply_count != Some(1)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reply request contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    FlowOperation::ActorReplyResolve { outcome, reply } => {
                        let resolve_count =
                            reply_resolves.get_mut(function.id.0 as usize).map(|count| {
                                *count = count.saturating_add(1);
                                *count
                            });
                        let exact_outcome = matches!(function.result_types.as_slice(), [result]
                            if flow_value_type(function, *outcome) == Some(*result));
                        if !instruction.results.is_empty()
                            || !matches!(function.role, FunctionRole::ActorTurn(_))
                            || !exact_outcome
                            || module.proofs.get(reply.0 as usize).is_none_or(|proof| {
                                proof.kind != ProofKind::ActorReplyExactlyOnce
                                    || proof.bound != Some(1)
                            })
                            || resolve_count != Some(1)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reply resolve contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    FlowOperation::MailboxReceive { actor, method } => {
                        let receive_count = receives.get_mut(method.0 as usize).map(|count| {
                            *count = count.saturating_add(1);
                            *count
                        });
                        let first_entry_instruction = block.id == function.entry && index == 0;
                        if !instruction.results.is_empty()
                            || function.id != *method
                            || function.role != FunctionRole::ActorTurn(*actor)
                            || !first_entry_instruction
                            || receive_count != Some(1)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "mailbox receive contract",
                                id: instruction.id.0,
                            });
                        }
                    }
                    operation => {
                        let mut escaped = None;
                        let mut cancelled = false;
                        for_each_flow_operation_value(operation, |value| {
                            if !cancelled && !errors.poll() {
                                cancelled = true;
                            } else if escaped.is_none()
                                && (is_reservation_value(module, function, value)
                                    || is_actor_capability_value(module, function, value))
                            {
                                escaped = Some(value);
                            }
                        });
                        if cancelled {
                            return;
                        }
                        if let Some(value) = escaped {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "actor reservation operation escape",
                                id: value.0,
                            });
                        }
                    }
                }
            }

            let mut escaped = None;
            let mut cancelled = false;
            for_each_flow_terminator_value(&block.terminator, |value| {
                if !cancelled && !errors.poll() {
                    cancelled = true;
                } else if escaped.is_none()
                    && (is_reservation_value(module, function, value)
                        || is_actor_capability_value(module, function, value))
                {
                    escaped = Some(value);
                }
            });
            if cancelled {
                return;
            }
            if let Some(value) = escaped {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reservation terminator escape",
                    id: value.0,
                });
            }
        }

        for value in &function.values {
            if !errors.poll() {
                return;
            }
            if is_reservation_value(module, function, value.id)
                && definitions
                    .get(value.id.0 as usize)
                    .zip(commits.get(value.id.0 as usize))
                    .is_none_or(|(definitions, commits)| *definitions != 1 || *commits != 1)
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reservation delivery",
                    id: value.id.0,
                });
            }
        }
    }

    if (reserve_count == 0 && reservation_type_count != 0)
        || (reserve_count != 0
            && (!(reserve_count == 1 || reserve_count == 2) || reservation_type_count != 1))
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor reservation type set",
            id: u32::from(reservation_type_count),
        });
    }

    for function in &module.functions {
        if !errors.poll() {
            return;
        }
        let expected = incoming.get(function.id.0 as usize).copied().unwrap_or(0);
        let actual = receives.get(function.id.0 as usize).copied().unwrap_or(0);
        let expected_replies = reply_incoming
            .get(function.id.0 as usize)
            .copied()
            .unwrap_or(0);
        let actual_replies = reply_resolves
            .get(function.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if matches!(function.role, FunctionRole::ActorTurn(_)) {
            if expected != actual
                || expected > 1
                || expected_replies != actual_replies
                || expected_replies > 1
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor mailbox dispatch contract",
                    id: function.id.0,
                });
            }
        } else if expected != 0 || actual != 0 {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor mailbox dispatch target",
                id: function.id.0,
            });
        }
    }
}

/// Activations are deliberately more constrained than general strict-linear
/// values: each is defined by exactly one `AsyncCall`, consumed by exactly one
/// `Suspend`, and cannot cross an ordinary SSA edge or function boundary.
fn validate_activation_contract(
    module: &FlowWir,
    function: &FlowFunction,
    errors: &mut ValidationContext<'_>,
) {
    let Some(mut definitions) = errors.filled(function.values.len(), 0_u8) else {
        return;
    };
    let Some(mut suspends) = errors.filled(function.values.len(), 0_u8) else {
        return;
    };

    for parameter in &function.parameters {
        if !errors.poll() {
            return;
        }
        if is_activation_value(module, function, *parameter) {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation function parameter",
                id: parameter.0,
            });
        }
    }

    let Some(mut states) = errors.scratch(0) else {
        return;
    };
    for block in &function.blocks {
        if !errors.poll() {
            return;
        }
        for parameter in &block.parameters {
            if is_activation_value(module, function, *parameter) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "activation block parameter",
                    id: parameter.0,
                });
            }
        }
        for (instruction_index, instruction) in block.instructions.iter().enumerate() {
            if !errors.poll() {
                return;
            }
            let async_definition = matches!(instruction.operation, FlowOperation::AsyncCall { .. });
            for result in &instruction.results {
                if !errors.poll() {
                    return;
                }
                if is_activation_value(module, function, *result) {
                    if async_definition && instruction.results.len() == 1 {
                        if let Some(count) = definitions.get_mut(result.0 as usize) {
                            *count = count.saturating_add(1);
                        }
                    } else {
                        errors.push(ValidationError::InvalidRecord {
                            kind: "activation definition",
                            id: result.0,
                        });
                    }
                }
            }
            let mut activation_operand = None;
            for_each_flow_operation_value(&instruction.operation, |value| {
                if activation_operand.is_none() && is_activation_value(module, function, value) {
                    activation_operand = Some(value);
                }
            });
            if let Some(value) = activation_operand {
                errors.push(ValidationError::InvalidRecord {
                    kind: "activation operation operand",
                    id: value.0,
                });
            }
            if async_definition {
                let activation = instruction.results.first().copied();
                let is_immediate_suspend = instruction_index
                    .checked_add(1)
                    .is_some_and(|next| next == block.instructions.len())
                    && matches!(
                        (&block.terminator, activation),
                        (
                            Terminator::Suspend {
                                activation: suspended,
                                ..
                            },
                            Some(activation),
                        ) if *suspended == activation
                    );
                if !is_immediate_suspend {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "activation immediate suspend",
                        id: instruction.id.0,
                    });
                }
            }
        }

        match &block.terminator {
            Terminator::Suspend {
                state, activation, ..
            } => {
                if !errors.scratch_push(&mut states, *state) {
                    return;
                }
                if let Some(count) = suspends.get_mut(activation.0 as usize) {
                    *count = count.saturating_add(1);
                }
                let immediately_defined = block.instructions.last().is_some_and(|instruction| {
                    matches!(instruction.operation, FlowOperation::AsyncCall { .. })
                        && instruction.results.as_slice() == [*activation]
                });
                if !immediately_defined {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "suspend activation definition",
                        id: activation.0,
                    });
                }
            }
            terminator => {
                let mut activation_operand = None;
                for_each_flow_terminator_value(terminator, |value| {
                    if activation_operand.is_none() && is_activation_value(module, function, value)
                    {
                        activation_operand = Some(value);
                    }
                });
                if let Some(value) = activation_operand {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "activation terminator operand",
                        id: value.0,
                    });
                }
            }
        }
    }

    if !sort_scratch(&mut states, errors) {
        return;
    }
    for (expected, actual) in states.into_iter().enumerate() {
        if !errors.poll() {
            return;
        }
        if usize::try_from(actual) != Ok(expected) {
            errors.push(ValidationError::InvalidRecord {
                kind: "async state order",
                id: actual,
            });
        }
    }

    for value in &function.values {
        if !errors.poll() {
            return;
        }
        let counts = definitions
            .get(value.id.0 as usize)
            .zip(suspends.get(value.id.0 as usize));
        if is_activation_value(module, function, value.id)
            && counts.is_none_or(|(definitions, suspends)| *definitions != 1 || *suspends != 1)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "activation delivery",
                id: value.id.0,
            });
        }
    }
}

fn sorted_unique_strings(values: &[String], errors: &mut ValidationContext<'_>) -> bool {
    let mut canonical = true;
    for value in values {
        if !errors.poll() {
            return false;
        }
        canonical &= !value.trim().is_empty();
    }
    for pair in values.windows(2) {
        if !errors.poll() {
            return false;
        }
        canonical &= pair[0] < pair[1];
    }
    canonical
}

fn require_canonical_ids(
    kind: &'static str,
    owner: u32,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationContext<'_>,
) {
    let mut prior = None;
    let mut canonical = true;
    for id in ids {
        if !errors.poll() {
            return;
        }
        canonical &= prior.is_none_or(|prior| prior < id);
        prior = Some(id);
    }
    if !canonical {
        errors.push(ValidationError::NonCanonicalReferences { kind, owner });
    }
}

fn validate_call_arguments(
    module: &FlowWir,
    caller: &FlowFunction,
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

fn validate_edge(
    function: &FlowFunction,
    target: BlockId,
    arguments: &[ValueId],
    errors: &mut ValidationContext<'_>,
) {
    let Some(block) = function.blocks.get(target.0 as usize) else {
        return;
    };
    if arguments.len() != block.parameters.len() {
        errors.push(ValidationError::EdgeArity {
            function: function.id,
            target,
            expected: block.parameters.len(),
            actual: arguments.len(),
        });
        return;
    }
    for (argument, parameter) in arguments.iter().zip(&block.parameters) {
        let types = function
            .values
            .get(argument.0 as usize)
            .zip(function.values.get(parameter.0 as usize))
            .map(|(argument, parameter)| (argument.ty, parameter.ty));
        if types.is_some_and(|(argument, parameter)| argument != parameter) {
            errors.push(ValidationError::EdgeTypeMismatch {
                function: function.id,
                target,
            });
        }
    }
}

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut ValidationContext<'_>) {
    if !errors.poll() {
        return;
    }
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

#[derive(Debug, Clone, Copy)]
enum ValueDefinitionSite {
    FunctionParameter,
    BlockParameter(usize),
    Instruction { block: usize, index: usize },
}

fn validate_control_flow_and_ssa(
    module: &FlowWir,
    function: &FlowFunction,
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
        let mut completed = true;
        let mut edge_index = 0_usize;
        for_each_flow_edge(&block.terminator, |target, arguments| {
            if !completed {
                return;
            }
            let Some(target_index) = usize::try_from(target.0)
                .ok()
                .filter(|target| *target < block_count)
            else {
                return;
            };
            completed = errors.scratch_push(&mut successors[source], target_index)
                && errors.scratch_push(&mut predecessors[target_index], source)
                && errors.scratch_push(&mut arguments_by_target, (target, arguments, edge_index));
            if let Some(next) = edge_index.checked_add(1) {
                edge_index = next;
            } else {
                completed = false;
                errors.allocation_failure =
                    Some(("validation scratch entries", errors.limits.model_edges));
            }
        });
        if !completed
            || !sort_scratch_by(
                &mut arguments_by_target,
                errors,
                &|(left, _, _), (right, _, _)| left.cmp(right),
            )
        {
            return;
        }
        let Some(mut conflicting) = errors.filled(arguments_by_target.len(), false) else {
            return;
        };
        for pair in arguments_by_target.windows(2) {
            if !errors.poll() {
                return;
            }
            if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
                let Some(entry) = conflicting.get_mut(pair[1].2) else {
                    errors.allocation_failure =
                        Some(("validation scratch entries", errors.limits.model_edges));
                    return;
                };
                *entry = true;
            }
        }
        if !sort_scratch_by(
            &mut arguments_by_target,
            errors,
            &|(_, _, left), (_, _, right)| left.cmp(right),
        ) {
            return;
        }
        for (target, _, index) in &arguments_by_target {
            if !errors.poll() {
                return;
            }
            if conflicting[*index] {
                errors.push(ValidationError::ConflictingParallelEdgeArguments {
                    function: function.id,
                    from: block.id,
                    to: *target,
                });
            }
        }
        if !sort_scratch(&mut successors[source], errors) {
            return;
        }
        successors[source].dedup();
    }
    for incoming in &mut predecessors {
        if !sort_scratch(incoming, errors) {
            return;
        }
        incoming.dedup();
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
            let Ok(block) = u32::try_from(block) else {
                errors.allocation_failure =
                    Some(("validation scratch entries", errors.limits.model_edges));
                return;
            };
            errors.push(ValidationError::UnreachableBlock {
                function: function.id,
                block: BlockId(block),
            });
        }
    }

    for index in 0..(postorder.len() / 2) {
        if !errors.poll() {
            return;
        }
        let opposite = postorder.len() - index - 1;
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
                candidate = match candidate {
                    Some(candidate) => {
                        let Some(intersection) = intersect_flow_dominators(
                            candidate,
                            predecessor,
                            &immediate_dominator,
                            &reverse_postorder,
                            errors,
                        ) else {
                            return;
                        };
                        Some(intersection)
                    }
                    None => Some(predecessor),
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
        record_flow_definition(
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
            record_flow_definition(
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
                record_flow_definition(
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
            for_each_flow_operation_value(&instruction.operation, |value| {
                validate_flow_value_dominance(
                    function,
                    value,
                    block_index,
                    Some(instruction_index),
                    &definitions,
                    &immediate_dominator,
                    &reachable,
                    errors,
                );
            });
        }
        for_each_flow_terminator_value(&block.terminator, |value| {
            validate_flow_value_dominance(
                function,
                value,
                block_index,
                None,
                &definitions,
                &immediate_dominator,
                &reachable,
                errors,
            );
        });
        validate_flow_terminator_types(module, function, block, errors);
    }
}

fn for_each_flow_edge<'a>(
    terminator: &'a Terminator,
    mut visit: impl FnMut(BlockId, &'a [ValueId]),
) {
    match terminator {
        Terminator::Jump { target, arguments } => visit(*target, arguments),
        Terminator::Branch {
            then_block,
            then_arguments,
            else_block,
            else_arguments,
            ..
        } => {
            visit(*then_block, then_arguments);
            visit(*else_block, else_arguments);
        }
        Terminator::Switch {
            cases,
            default,
            default_arguments,
            ..
        } => {
            for case in cases {
                visit(case.target, &case.arguments);
            }
            visit(*default, default_arguments);
        }
        Terminator::Suspend { resume, .. } => visit(*resume, &[]),
        Terminator::Return(_)
        | Terminator::TailCall { .. }
        | Terminator::Trap { .. }
        | Terminator::Unreachable => {}
    }
}

fn intersect_flow_dominators(
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

fn record_flow_definition(
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
fn validate_flow_value_dominance(
    function: &FlowFunction,
    value: ValueId,
    use_block: usize,
    use_instruction: Option<usize>,
    definitions: &[Option<ValueDefinitionSite>],
    immediate_dominator: &[Option<usize>],
    reachable: &[bool],
    errors: &mut ValidationContext<'_>,
) {
    let Some(definition) = definitions.get(value.0 as usize).and_then(|site| *site) else {
        return;
    };
    let valid = match definition {
        ValueDefinitionSite::FunctionParameter => true,
        ValueDefinitionSite::BlockParameter(block) => {
            flow_block_dominates(block, use_block, immediate_dominator, reachable, errors)
        }
        ValueDefinitionSite::Instruction { block, index } if block == use_block => {
            use_instruction.is_none_or(|use_index| index < use_index)
        }
        ValueDefinitionSite::Instruction { block, .. } => {
            flow_block_dominates(block, use_block, immediate_dominator, reachable, errors)
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

fn flow_block_dominates(
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

fn for_each_flow_operation_value(operation: &FlowOperation, mut visit: impl FnMut(ValueId)) {
    match operation {
        FlowOperation::Immediate(_)
        | FlowOperation::ActorStateAddress { .. }
        | FlowOperation::RegionReset { .. }
        | FlowOperation::ActorCapability { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::ActorReplyRequest { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::MmioRead { .. }
        | FlowOperation::Fence { .. } => {}
        FlowOperation::Unary { value, .. }
        | FlowOperation::Cast { value, .. }
        | FlowOperation::Promote { value, .. }
        | FlowOperation::EnumTag { value }
        | FlowOperation::EnumPayload { value }
        | FlowOperation::ExtractField {
            aggregate: value, ..
        }
        | FlowOperation::EndAccess { access: value }
        | FlowOperation::Load { address: value, .. }
        | FlowOperation::Move { value }
        | FlowOperation::Copy { value }
        | FlowOperation::Drop { value }
        | FlowOperation::ActorReject { reservation: value }
        | FlowOperation::TaskCancel { task: value }
        | FlowOperation::Park { wait_set: value }
        | FlowOperation::Wake { target: value }
        | FlowOperation::InterruptRestore { token: value }
        | FlowOperation::ValidateDeviceValue { value, .. }
        | FlowOperation::Check {
            condition: value, ..
        }
        | FlowOperation::Assert {
            condition: value, ..
        }
        | FlowOperation::RecordEvent { payload: value, .. }
        | FlowOperation::ReplayEvent {
            destination: value, ..
        }
        | FlowOperation::TestEmit { payload: value }
        | FlowOperation::TestFinish { outcome: value } => visit(*value),
        FlowOperation::ActorReplyResolve { outcome, .. } => visit(*outcome),
        FlowOperation::Binary { left, right, .. } => {
            visit(*left);
            visit(*right);
        }
        FlowOperation::ExtractIndex {
            aggregate, index, ..
        } => {
            visit(*aggregate);
            visit(*index);
        }
        FlowOperation::MakeAggregate { fields, .. } => {
            for field in fields {
                visit(*field);
            }
        }
        FlowOperation::FormatBoundedString { parts, .. } => {
            for part in parts {
                match part {
                    BoundedStringPart::Text { .. } => {}
                    BoundedStringPart::Bool { value, .. }
                    | BoundedStringPart::Character { value, .. }
                    | BoundedStringPart::Integer { value, .. }
                    | BoundedStringPart::StaticString { value, .. } => visit(*value),
                }
            }
        }
        FlowOperation::MakeEnum { payload, .. } => {
            if let Some(payload) = payload {
                visit(*payload);
            }
        }
        FlowOperation::InsertField {
            aggregate, value, ..
        }
        | FlowOperation::Store {
            address: aggregate,
            value,
            ..
        }
        | FlowOperation::ReplyResolve {
            endpoint: aggregate,
            outcome: value,
        }
        | FlowOperation::ReceiptCommit {
            receipt: aggregate,
            payload: value,
        }
        | FlowOperation::ReceiptResolve {
            receipt: aggregate,
            outcome: value,
        }
        | FlowOperation::InterruptPublish {
            cell: aggregate,
            value,
        }
        | FlowOperation::QueuePublish {
            reservation: aggregate,
            payload: value,
        } => {
            visit(*aggregate);
            visit(*value);
        }
        FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            visit(*reservation);
            for argument in arguments {
                visit(*argument);
            }
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            visit(*condition);
            visit(*then_value);
            visit(*else_value);
        }
        FlowOperation::BeginAccess { place, .. } => visit(*place),
        FlowOperation::Call { arguments, .. } | FlowOperation::AsyncCall { arguments, .. } => {
            for argument in arguments {
                visit(*argument);
            }
        }
        FlowOperation::Allocate { count, .. } => visit(*count),
        FlowOperation::TaskStart {
            slot, arguments, ..
        } => {
            visit(*slot);
            for argument in arguments {
                visit(*argument);
            }
        }
        FlowOperation::MmioWrite { value, .. } => visit(*value),
        FlowOperation::DmaTransition { token, .. } => visit(*token),
        FlowOperation::QueueReserve { descriptors, .. } => visit(*descriptors),
    }
}

fn for_each_flow_terminator_value(terminator: &Terminator, mut visit: impl FnMut(ValueId)) {
    match terminator {
        Terminator::Jump { arguments, .. } => {
            for value in arguments {
                visit(*value);
            }
        }
        Terminator::Branch {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            visit(*condition);
            for value in then_arguments.iter().chain(else_arguments) {
                visit(*value);
            }
        }
        Terminator::Switch {
            value,
            cases,
            default_arguments,
            ..
        } => {
            visit(*value);
            for case in cases {
                for value in &case.arguments {
                    visit(*value);
                }
            }
            for value in default_arguments {
                visit(*value);
            }
        }
        Terminator::Return(values) => {
            for value in values {
                visit(*value);
            }
        }
        Terminator::Suspend { activation, .. } => visit(*activation),
        Terminator::TailCall { arguments, .. } => {
            for value in arguments {
                visit(*value);
            }
        }
        Terminator::Trap { detail, .. } => {
            if let Some(value) = detail {
                visit(*value);
            }
        }
        Terminator::Unreachable => {}
    }
}

fn validate_flow_terminator_types(
    module: &FlowWir,
    function: &FlowFunction,
    block: &Block,
    errors: &mut ValidationContext<'_>,
) {
    let value_type = |value: ValueId| function.values.get(value.0 as usize).map(|value| value.ty);
    match &block.terminator {
        Terminator::Branch { condition, .. } => {
            let is_bool = value_type(*condition)
                .and_then(|ty| module.types.get(ty.0 as usize))
                .is_some_and(|ty| matches!(ty.kind, FlowTypeKind::Scalar(ScalarType::Bool)));
            if !is_bool {
                errors.push(ValidationError::TerminatorTypeMismatch {
                    function: function.id,
                    block: block.id,
                });
            }
        }
        Terminator::Switch { value, cases, .. } => {
            let bits = value_type(*value)
                .and_then(|ty| module.types.get(ty.0 as usize))
                .and_then(|ty| match ty.kind {
                    FlowTypeKind::Scalar(ScalarType::Bool) => Some(1),
                    FlowTypeKind::Scalar(ScalarType::Integer { bits, .. }) => Some(bits),
                    _ => None,
                });
            let Some(mut seen) = errors.scratch(cases.len()) else {
                return;
            };
            for (index, case) in cases.iter().enumerate() {
                if !errors.scratch_push(&mut seen, (case.value, index)) {
                    return;
                }
            }
            if !sort_scratch(&mut seen, errors) {
                return;
            }
            let Some(mut duplicate) = errors.filled(cases.len(), false) else {
                return;
            };
            for pair in seen.windows(2) {
                if !errors.poll() {
                    return;
                }
                if pair[0].0 == pair[1].0 {
                    duplicate[pair[1].1] = true;
                }
            }
            for (index, case) in cases.iter().enumerate() {
                if !errors.poll() {
                    return;
                }
                if duplicate[index] {
                    errors.push(ValidationError::DuplicateSwitchCase {
                        function: function.id,
                        block: block.id,
                        value: case.value,
                    });
                }
                if bits.is_none_or(|bits| {
                    bits == 0 || (bits < 128 && case.value >= (1u128 << u32::from(bits)))
                }) {
                    errors.push(ValidationError::SwitchCaseOutOfRange {
                        function: function.id,
                        block: block.id,
                        value: case.value,
                        bits,
                    });
                }
            }
        }
        Terminator::Return(values) => {
            let actual_matches = values
                .iter()
                .filter_map(|value| value_type(*value))
                .eq(function.result_types.iter().copied());
            if !actual_matches {
                errors.push(ValidationError::TerminatorTypeMismatch {
                    function: function.id,
                    block: block.id,
                });
            }
        }
        Terminator::TailCall {
            function: callee, ..
        } => {
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.result_types != function.result_types)
            {
                errors.push(ValidationError::TailCallResultMismatch {
                    caller: function.id,
                    callee: *callee,
                });
            }
        }
        Terminator::Suspend {
            activation, resume, ..
        } => {
            let delivered = value_type(*activation)
                .and_then(|ty| module.types.get(ty.0 as usize))
                .and_then(|ty| match ty.kind {
                    FlowTypeKind::Activation { result } => Some(result),
                    _ => None,
                });
            let resume_parameter = function.blocks.get(resume.0 as usize).and_then(|resume| {
                match resume.parameters.as_slice() {
                    [parameter] => value_type(*parameter),
                    _ => None,
                }
            });
            if delivered.is_none() || delivered != resume_parameter {
                errors.push(ValidationError::TerminatorTypeMismatch {
                    function: function.id,
                    block: block.id,
                });
            }
        }
        Terminator::Jump { .. } | Terminator::Trap { .. } | Terminator::Unreachable => {}
    }
}

fn canonical_enum_payload(module: &FlowWir, variants: &[Vec<TypeId>]) -> Option<TypeId> {
    if variants.is_empty() || variants.len() > 256 {
        return None;
    }
    let mut payload = None;
    for variant in variants {
        match variant.as_slice() {
            [] => {}
            [candidate] if payload.is_none_or(|payload| payload == *candidate) => {
                payload = Some(*candidate);
            }
            _ => return None,
        }
    }
    payload.filter(|payload| {
        module.types.get(payload.0 as usize).is_some_and(|record| {
            record.copyable
                && !record.strict_linear
                && matches!(
                    record.kind,
                    FlowTypeKind::Scalar(
                        ScalarType::Bool
                            | ScalarType::Integer {
                                bits: 8 | 16 | 32 | 64 | 128,
                                ..
                            }
                            | ScalarType::Float32
                            | ScalarType::Float64
                    )
                )
        })
    })
}

fn canonical_enum_shape(module: &FlowWir, variants: &[Vec<TypeId>]) -> bool {
    !variants.is_empty()
        && variants.len() <= 256
        && (variants.iter().all(Vec::is_empty)
            || canonical_enum_payload(module, variants).is_some()
            || exact_fixed_flat_enum_profile(module, variants)
            || exact_heterogeneous_scalar_enum_profile(module, variants))
}

fn exact_heterogeneous_scalar_enum_profile(module: &FlowWir, variants: &[Vec<TypeId>]) -> bool {
    let [left, right] = variants else {
        return false;
    };
    let ([left], [right]) = (left.as_slice(), right.as_slice()) else {
        return false;
    };
    let scalar = |ty: TypeId| {
        module.types.get(ty.0 as usize).is_some_and(|record| {
            record.id == ty
                && record.copyable
                && !record.strict_linear
                && matches!(
                    record.kind,
                    FlowTypeKind::Scalar(
                        ScalarType::Bool
                            | ScalarType::Integer {
                                bits: 8 | 16 | 32 | 64 | 128,
                                ..
                            }
                            | ScalarType::Float32
                            | ScalarType::Float64
                    )
                )
        })
    };
    left != right && scalar(*left) && scalar(*right)
}

fn flat_nominal_enum_payload(module: &FlowWir, ty: TypeId) -> bool {
    module.types.get(ty.0 as usize).is_some_and(|record| {
        record.id == ty
            && record.name.is_some()
            && record.copyable
            && !record.strict_linear
            && matches!(&record.kind, FlowTypeKind::Struct { fields }
            if !fields.is_empty() && fields.iter().all(|field| {
                module.types.get(field.0 as usize).is_some_and(|field| {
                    field.copyable
                        && !field.strict_linear
                        && matches!(field.kind, FlowTypeKind::Scalar(
                            ScalarType::Bool
                                | ScalarType::Integer {
                                    bits: 8 | 16 | 32 | 64 | 128,
                                    ..
                                }
                                | ScalarType::Float32
                                | ScalarType::Float64
                        ))
                })
            }))
    })
}

fn exact_fixed_flat_enum_profile(module: &FlowWir, variants: &[Vec<TypeId>]) -> bool {
    let [left, right] = variants else {
        return false;
    };
    let ([left], [right]) = (left.as_slice(), right.as_slice()) else {
        return false;
    };
    if left == right {
        return false;
    }
    let scalar = |ty: TypeId| {
        module.types.get(ty.0 as usize).is_some_and(|record| {
            record.id == ty
                && record.copyable
                && !record.strict_linear
                && matches!(
                    record.kind,
                    FlowTypeKind::Scalar(
                        ScalarType::Bool
                            | ScalarType::Integer {
                                bits: 8 | 16 | 32 | 64 | 128,
                                ..
                            }
                            | ScalarType::Float32
                            | ScalarType::Float64
                    )
                )
        })
    };
    (flat_nominal_enum_payload(module, *left) && scalar(*right))
        || (scalar(*left) && flat_nominal_enum_payload(module, *right))
}

fn validate_type(module: &FlowWir, ty: &FlowType, errors: &mut ValidationContext<'_>) {
    macro_rules! use_type {
        ($id:expr) => {
            require_id("type reference", ($id).0, module.types.len(), errors)
        };
    }
    match &ty.kind {
        FlowTypeKind::Tuple(types) | FlowTypeKind::Struct { fields: types } => {
            for id in types {
                use_type!(*id);
            }
        }
        FlowTypeKind::Array { element, .. } | FlowTypeKind::Activation { result: element } => {
            use_type!(*element)
        }
        FlowTypeKind::Enum { variants } => {
            for id in variants.iter().flatten() {
                use_type!(*id);
            }
            let canonical =
                ty.copyable && !ty.strict_linear && canonical_enum_shape(module, variants);
            if !canonical {
                errors.push(ValidationError::InvalidRecord {
                    kind: "closed enum type",
                    id: ty.id.0,
                });
            }
        }
        FlowTypeKind::Function { parameters, result } => {
            for id in parameters {
                use_type!(*id);
            }
            use_type!(*result);
        }
        FlowTypeKind::RegionHandle(id) => {
            require_id("region type", id.0, module.regions.len(), errors)
        }
        FlowTypeKind::PoolHandle(id) => require_id("pool type", id.0, module.pools.len(), errors),
        FlowTypeKind::ActorHandle(id) => {
            require_id("actor type", id.0, module.actors.len(), errors)
        }
        FlowTypeKind::TaskHandle(id) => require_id("task type", id.0, module.tasks.len(), errors),
        FlowTypeKind::Receipt { payload, error } => {
            use_type!(*payload);
            use_type!(*error);
        }
        FlowTypeKind::DmaToken { pool, payload } => {
            require_id("DMA pool type", pool.0, module.pools.len(), errors);
            use_type!(*payload);
        }
        FlowTypeKind::Unit
        | FlowTypeKind::Scalar(_)
        | FlowTypeKind::StaticString { .. }
        | FlowTypeKind::BoundedString { .. }
        | FlowTypeKind::Reservation
        | FlowTypeKind::OpaqueTarget { .. } => {}
    }
    if matches!(ty.kind, FlowTypeKind::Activation { .. }) && (ty.copyable || !ty.strict_linear) {
        errors.push(ValidationError::InvalidRecord {
            kind: "activation type",
            id: ty.id.0,
        });
    }
    if matches!(ty.kind, FlowTypeKind::Reservation) && (ty.copyable || !ty.strict_linear) {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor reservation type",
            id: ty.id.0,
        });
    }
    let canonical_text = match ty.kind {
        FlowTypeKind::Scalar(ScalarType::Character) => ty.copyable && !ty.strict_linear,
        FlowTypeKind::StaticString { .. } => ty.copyable && !ty.strict_linear,
        FlowTypeKind::BoundedString { capacity } => {
            capacity > 0 && !ty.copyable && !ty.strict_linear
        }
        _ => true,
    };
    if !canonical_text {
        errors.push(ValidationError::InvalidRecord {
            kind: "bounded text type",
            id: ty.id.0,
        });
    }
}

fn validate_immediate(module: &FlowWir, immediate: &Immediate, errors: &mut ValidationContext<'_>) {
    match immediate {
        Immediate::Zero(ty) => require_id("immediate type", ty.0, module.types.len(), errors),
        Immediate::GlobalAddress(id) => {
            require_id("immediate global", id.0, module.globals.len(), errors)
        }
        Immediate::FunctionAddress(id) => {
            require_id("immediate function", id.0, module.functions.len(), errors)
        }
        Immediate::Unit
        | Immediate::Bool(_)
        | Immediate::Character(_)
        | Immediate::Integer { .. }
        | Immediate::Float32(_)
        | Immediate::Float64(_)
        | Immediate::Bytes(_) => {}
    }
}

fn decimal_digits(value: u128) -> u64 {
    if value == 0 {
        1
    } else {
        u64::from(value.ilog10()) + 1
    }
}

fn integer_maximum_bytes(signed: bool, bits: u16) -> Option<u64> {
    if !matches!(bits, 8 | 16 | 32 | 64 | 128) {
        return None;
    }
    if signed {
        let magnitude = 1_u128.checked_shl(u32::from(bits - 1))?;
        decimal_digits(magnitude).checked_add(1)
    } else {
        let maximum = if bits == 128 {
            u128::MAX
        } else {
            (1_u128 << u32::from(bits)) - 1
        };
        Some(decimal_digits(maximum))
    }
}

fn validate_bounded_string_operation(
    module: &FlowWir,
    function: &FlowFunction,
    instruction: &Instruction,
    ty: TypeId,
    parts: &[BoundedStringPart],
) -> bool {
    let Some(capacity) = module
        .types
        .get(ty.0 as usize)
        .and_then(|record| match record.kind {
            FlowTypeKind::BoundedString { capacity }
                if !record.copyable && !record.strict_linear =>
            {
                Some(capacity)
            }
            _ => None,
        })
    else {
        return false;
    };
    if !matches!(instruction.results.as_slice(), [result]
        if function.values.get(result.0 as usize).is_some_and(|value| value.ty == ty))
    {
        return false;
    }
    let mut total = 0_u64;
    for part in parts {
        let (bytes, valid) = match part {
            BoundedStringPart::Text { value, source } => (
                u64::try_from(value.len()).ok(),
                source.range.start <= source.range.end,
            ),
            BoundedStringPart::Bool { value, source } => (
                Some(5),
                source.range.start <= source.range.end
                    && function.values.get(value.0 as usize).is_some_and(|value| {
                        module.types.get(value.ty.0 as usize).is_some_and(|record| {
                            record.kind == FlowTypeKind::Scalar(ScalarType::Bool)
                        })
                    }),
            ),
            BoundedStringPart::Character { value, source } => (
                Some(4),
                source.range.start <= source.range.end
                    && function.values.get(value.0 as usize).is_some_and(|value| {
                        module.types.get(value.ty.0 as usize).is_some_and(|record| {
                            record.kind == FlowTypeKind::Scalar(ScalarType::Character)
                        })
                    }),
            ),
            BoundedStringPart::Integer {
                value,
                maximum_bytes,
                source,
            } => {
                let expected = function.values.get(value.0 as usize).and_then(|value| {
                    module
                        .types
                        .get(value.ty.0 as usize)
                        .and_then(|record| match record.kind {
                            FlowTypeKind::Scalar(ScalarType::Integer { signed, bits }) => {
                                integer_maximum_bytes(signed, bits)
                            }
                            _ => None,
                        })
                });
                (
                    Some(*maximum_bytes),
                    source.range.start <= source.range.end && expected == Some(*maximum_bytes),
                )
            }
            BoundedStringPart::StaticString {
                value,
                bytes,
                source,
            } => (
                Some(*bytes),
                source.range.start <= source.range.end
                    && function.values.get(value.0 as usize).is_some_and(|value| {
                        module.types.get(value.ty.0 as usize).is_some_and(|record| {
                            matches!(record.kind, FlowTypeKind::StaticString { bytes: extent }
                                if extent == *bytes && record.copyable && !record.strict_linear)
                        })
                    }),
            ),
        };
        let Some(bytes) = bytes else {
            return false;
        };
        if !valid {
            return false;
        }
        let Some(next) = total.checked_add(bytes) else {
            return false;
        };
        total = next;
    }
    !parts.is_empty() && total == capacity
}

fn validate_operation(
    module: &FlowWir,
    function: &FlowFunction,
    instruction: &Instruction,
    errors: &mut ValidationContext<'_>,
) {
    macro_rules! value {
        ($id:expr) => {
            require_id("instruction value", ($id).0, function.values.len(), errors)
        };
    }
    macro_rules! proof {
        ($id:expr) => {
            require_id("instruction proof", ($id).0, module.proofs.len(), errors)
        };
    }
    match &instruction.operation {
        FlowOperation::Immediate(immediate) => {
            validate_immediate(module, immediate, errors);
            let exact_text_or_character = match immediate {
                Immediate::Bytes(bytes) => match instruction.results.as_slice() {
                    [result] => function
                        .values
                        .get(result.0 as usize)
                        .and_then(|value| module.types.get(value.ty.0 as usize))
                        .is_none_or(|record| match record.kind {
                            FlowTypeKind::StaticString { bytes: extent } => {
                                usize::try_from(extent).ok() == Some(bytes.len())
                            }
                            _ => true,
                        }),
                    _ => true,
                },
                Immediate::Character(_) => matches!(instruction.results.as_slice(), [result]
                if function.values.get(result.0 as usize).is_some_and(|value| {
                    module.types.get(value.ty.0 as usize).is_some_and(|record| {
                        record.kind == FlowTypeKind::Scalar(ScalarType::Character)
                    })
                })),
                _ => true,
            };
            if !exact_text_or_character {
                errors.push(ValidationError::InvalidRecord {
                    kind: "bounded text immediate",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::ActorStateAddress {
            actor,
            region,
            proof: capacity,
        } => {
            require_id("actor state actor", actor.0, module.actors.len(), errors);
            require_id("actor state region", region.0, module.regions.len(), errors);
            proof!(*capacity);
            let valid = function.role == FunctionRole::ActorTurn(*actor)
                && module
                    .actors
                    .get(actor.0 as usize)
                    .is_some_and(|actor_plan| {
                        module
                            .regions
                            .get(region.0 as usize)
                            .is_some_and(|region_plan| {
                                region_plan.owner == PlanOwner::Actor(*actor)
                                    && region_plan.class == RegionClass::Image
                                    && region_plan.capacity_bytes == 8
                                    && region_plan.alignment == 8
                                    && region_plan.capacity_proof == *capacity
                                    && region_plan.name.strip_suffix(".state")
                                        == Some(actor_plan.name.as_str())
                                    && module.proofs.get(capacity.0 as usize).is_some_and(|proof| {
                                        proof.kind == ProofKind::CapacityBound
                                            && proof.bound == Some(1)
                                            && proof.sources.as_slice() == [region_plan.source]
                                            && proof.depends_on.is_empty()
                                    })
                            })
                    })
                && matches!(instruction.results.as_slice(), [result]
                if function.values.get(result.0 as usize).is_some_and(|value| {
                    module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                        ty.kind == FlowTypeKind::Scalar(ScalarType::Address)
                    })
                }));
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor state address",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::Unary { value: operand, .. } => value!(*operand),
        FlowOperation::Binary { left, right, .. } => {
            value!(*left);
            value!(*right);
        }
        FlowOperation::Cast {
            value: operand, to, ..
        } => {
            value!(*operand);
            require_id("cast type", to.0, module.types.len(), errors);
        }
        FlowOperation::MakeAggregate { ty, fields } => {
            require_id("aggregate type", ty.0, module.types.len(), errors);
            for id in fields {
                value!(*id);
            }
        }
        FlowOperation::FormatBoundedString { ty, parts } => {
            require_id("bounded string type", ty.0, module.types.len(), errors);
            for part in parts {
                match part {
                    BoundedStringPart::Text { .. } => {}
                    BoundedStringPart::Bool { value: operand, .. }
                    | BoundedStringPart::Character { value: operand, .. }
                    | BoundedStringPart::Integer { value: operand, .. }
                    | BoundedStringPart::StaticString { value: operand, .. } => value!(*operand),
                }
            }
            if !validate_bounded_string_operation(module, function, instruction, *ty, parts) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "bounded string construction",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => {
            require_id("enum type", ty.0, module.types.len(), errors);
            if let Some(payload) = payload {
                value!(*payload);
            }
            if !module.types.get(ty.0 as usize).is_some_and(|record| {
                matches!(&record.kind, FlowTypeKind::Enum { variants }
                    if variants.get(usize::from(*variant)).is_some_and(|fields| {
                        match (fields.as_slice(), payload) {
                            ([], None) => true,
                            ([expected], Some(payload)) => function.values
                                .get(payload.0 as usize)
                                .is_some_and(|value| value.ty == *expected),
                            _ => false,
                        }
                    }))
                    && matches!(instruction.results.as_slice(), [result]
                        if function.values.get(result.0 as usize).is_some_and(|value| value.ty == *ty))
            }) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "enum construction",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::EnumTag { value } => {
            value!(*value);
            let valid_enum = function.values.get(value.0 as usize).is_some_and(|value| {
                module.types.get(value.ty.0 as usize).is_some_and(|record| {
                    matches!(&record.kind, FlowTypeKind::Enum { variants }
                        if canonical_enum_shape(module, variants))
                })
            });
            let valid_result = matches!(instruction.results.as_slice(), [result]
            if function.values.get(result.0 as usize).is_some_and(|value| {
                module.types.get(value.ty.0 as usize).is_some_and(|record| {
                    record.kind == FlowTypeKind::Scalar(ScalarType::Integer {
                        signed: false,
                        bits: 8,
                    })
                })
            }));
            if !valid_enum || !valid_result {
                errors.push(ValidationError::InvalidRecord {
                    kind: "enum projection",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::EnumPayload { value } => {
            value!(*value);
            let payload_ty = function.values.get(value.0 as usize).and_then(|value| {
                module
                    .types
                    .get(value.ty.0 as usize)
                    .and_then(|record| match &record.kind {
                        FlowTypeKind::Enum { variants } => canonical_enum_payload(module, variants),
                        _ => None,
                    })
            });
            if !matches!((payload_ty, instruction.results.as_slice()), (Some(expected), [result])
                if function.values.get(result.0 as usize).is_some_and(|value| value.ty == expected))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "enum payload projection",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::ExtractField { aggregate, .. } => value!(*aggregate),
        FlowOperation::ExtractIndex {
            aggregate,
            index,
            proof: capacity,
        } => {
            value!(*aggregate);
            value!(*index);
            proof!(*capacity);
            let valid = function
                .values
                .get(aggregate.0 as usize)
                .and_then(|aggregate| {
                    module
                        .types
                        .get(aggregate.ty.0 as usize)
                        .and_then(|record| match record.kind {
                            FlowTypeKind::Array { element, length } if length > 0 => {
                                Some((element, length))
                            }
                            _ => None,
                        })
                })
                .is_some_and(|(element, length)| {
                    function.values.get(index.0 as usize).is_some_and(|index| {
                        module.types.get(index.ty.0 as usize).is_some_and(|record| {
                            record.kind
                                == FlowTypeKind::Scalar(ScalarType::Integer {
                                    signed: false,
                                    bits: 64,
                                })
                        })
                    }) && module.proofs.get(capacity.0 as usize).is_some_and(|proof| {
                        proof.id == *capacity
                            && proof.kind == ProofKind::CapacityBound
                            && proof.subject == "inline fixed-array iteration"
                            && proof.bound == Some(length)
                            && proof.depends_on.is_empty()
                            && !proof.sources.is_empty()
                    }) && function.proofs.binary_search(capacity).is_ok()
                        && matches!(instruction.results.as_slice(), [result]
                            if function.values.get(result.0 as usize)
                                .is_some_and(|result| result.ty == element))
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "fixed-array index",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::InsertField {
            aggregate,
            field,
            value: inserted,
        } => {
            value!(*aggregate);
            value!(*inserted);
            let valid = function
                .values
                .get(aggregate.0 as usize)
                .and_then(|aggregate| {
                    let aggregate_ty = aggregate.ty;
                    module
                        .types
                        .get(aggregate_ty.0 as usize)
                        .and_then(|record| match &record.kind {
                            FlowTypeKind::Struct { fields } => fields
                                .get(*field as usize)
                                .copied()
                                .map(|field_ty| (aggregate_ty, field_ty)),
                            _ => None,
                        })
                })
                .is_some_and(|(aggregate_ty, field_ty)| {
                    function
                        .values
                        .get(inserted.0 as usize)
                        .is_some_and(|inserted| inserted.ty == field_ty)
                        && matches!(instruction.results.as_slice(), [result]
                            if function.values.get(result.0 as usize)
                                .is_some_and(|result| result.ty == aggregate_ty))
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "field insertion",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            value!(*condition);
            value!(*then_value);
            value!(*else_value);
        }
        FlowOperation::BeginAccess {
            place, proof: p, ..
        } => {
            value!(*place);
            proof!(*p);
        }
        FlowOperation::EndAccess { access } => value!(*access),
        FlowOperation::Load { address, proof: p } => {
            value!(*address);
            proof!(*p);
        }
        FlowOperation::Store {
            address,
            value: stored,
            proof: p,
        } => {
            value!(*address);
            value!(*stored);
            proof!(*p);
        }
        FlowOperation::Move { value: operand }
        | FlowOperation::Copy { value: operand }
        | FlowOperation::Drop { value: operand } => value!(*operand),
        FlowOperation::Call {
            function: callee,
            arguments,
        } => {
            require_id("callee", callee.0, module.functions.len(), errors);
            for id in arguments {
                value!(*id);
            }
            validate_call_arguments(module, function, *callee, arguments, errors);
            if let Some(callee) = module.functions.get(callee.0 as usize) {
                if callee.color == FunctionColor::Async {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "ordinary call to async function",
                        id: instruction.id.0,
                    });
                }
                let canonical_results = instruction
                    .results
                    .iter()
                    .filter_map(|result| function.values.get(result.0 as usize))
                    .map(|value| value.ty)
                    .eq(callee.result_types.iter().copied());
                let explicit_unit_result = callee.result_types.is_empty()
                    && matches!(instruction.results.as_slice(), [result]
                        if function
                            .values
                            .get(result.0 as usize)
                            .and_then(|value| module.types.get(value.ty.0 as usize))
                            .is_some_and(|ty| ty.kind == FlowTypeKind::Unit));
                if !canonical_results && !explicit_unit_result {
                    errors.push(ValidationError::CallResultMismatch {
                        caller: function.id,
                        callee: callee.id,
                    });
                }
            }
        }
        FlowOperation::AsyncCall {
            function: callee,
            arguments,
            plan,
        } => {
            require_id("async callee", callee.0, module.functions.len(), errors);
            require_id(
                "async activation plan",
                plan.0,
                module.activations.len(),
                errors,
            );
            for id in arguments {
                value!(*id);
            }
            validate_call_arguments(module, function, *callee, arguments, errors);
            if let Some(callee) = module.functions.get(callee.0 as usize) {
                if function.color != FunctionColor::Async || callee.color != FunctionColor::Async {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "async call color",
                        id: instruction.id.0,
                    });
                }
                let result = instruction
                    .results
                    .first()
                    .and_then(|result| function.values.get(result.0 as usize))
                    .and_then(|value| module.types.get(value.ty.0 as usize))
                    .and_then(|ty| match ty.kind {
                        FlowTypeKind::Activation { result } => Some(result),
                        _ => None,
                    });
                if instruction.results.len() != 1
                    || result.is_none_or(|result| {
                        !activation_result_matches_function(module, result, callee)
                    })
                {
                    errors.push(ValidationError::CallResultMismatch {
                        caller: function.id,
                        callee: callee.id,
                    });
                }
            }
        }
        FlowOperation::Allocate {
            region,
            ty,
            count,
            proof: p,
        } => {
            require_id("allocation region", region.0, module.regions.len(), errors);
            require_id("allocation type", ty.0, module.types.len(), errors);
            value!(*count);
            proof!(*p);
        }
        FlowOperation::RegionReset { region } => {
            require_id("reset region", region.0, module.regions.len(), errors)
        }
        FlowOperation::Promote {
            value: promoted,
            destination,
            proof: promotion_proof,
        } => {
            value!(*promoted);
            require_id(
                "promotion region",
                destination.0,
                module.regions.len(),
                errors,
            );
            proof!(*promotion_proof);
            let valid = matches!(function.role, FunctionRole::ActorTurn(actor)
            if module.actors.get(actor.0 as usize).is_some_and(|actor_plan| {
                module.regions.get(destination.0 as usize).is_some_and(|region| {
                    region.owner == PlanOwner::Actor(actor)
                        && region.class == RegionClass::Image
                        && region.capacity_bytes == 8
                        && region.alignment == 8
                        && region.name.strip_suffix(".state") == Some(actor_plan.name.as_str())
                })
            })) && function
                .values
                .get(promoted.0 as usize)
                .is_some_and(|value| {
                    module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                        ty.kind
                            == FlowTypeKind::Scalar(ScalarType::Integer {
                                signed: false,
                                bits: 64,
                            })
                    })
                })
                && module
                    .proofs
                    .get(promotion_proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.kind == ProofKind::RegionBound
                            && proof.subject.starts_with("alloc:")
                            && proof.bound == Some(8)
                            && instruction
                                .source
                                .is_some_and(|source| proof.sources.as_slice() == [source])
                            && proof.depends_on.is_empty()
                            && proof.explanation.as_slice()
                                == ["actor state store outlives its non-reentrant turn frame"]
                    })
                && function.proofs.binary_search(promotion_proof).is_ok()
                && instruction.results.is_empty();
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "promotion",
                    id: promotion_proof.0,
                });
            }
        }
        FlowOperation::ActorCapability { actor, proof: p } => {
            require_id("actor capability", actor.0, module.actors.len(), errors);
            proof!(*p);
            let valid = matches!(instruction.results.as_slice(), [result]
            if function.values.get(result.0 as usize).is_some_and(|value| {
                module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                    ty.kind == FlowTypeKind::ActorHandle(*actor)
                        && ty.copyable
                        && !ty.strict_linear
                })
            })
            && module.proofs.get(p.0 as usize).is_some_and(|proof| {
                proof.kind == ProofKind::ActorAsIf
                    && proof.bound == Some(1)
                    && proof.sources.len() == 1
                    && proof.depends_on.is_empty()
            }));
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor capability",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::ActorReserve {
            actor, proof: p, ..
        } => {
            require_id("actor reserve", actor.0, module.actors.len(), errors);
            proof!(*p);
        }
        FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            value!(*reservation);
            for argument in arguments {
                value!(*argument);
            }
        }
        FlowOperation::ActorReplyRequest {
            actor,
            method,
            permit,
            reply,
        } => {
            require_id("actor reply target", actor.0, module.actors.len(), errors);
            require_id(
                "actor reply method",
                method.0,
                module.functions.len(),
                errors,
            );
            proof!(*permit);
            proof!(*reply);
            let valid = matches!(instruction.results.as_slice(), [result]
            if function.values.get(result.0 as usize).is_some_and(|value| {
                module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                    ty.kind == FlowTypeKind::Scalar(ScalarType::Integer {
                        signed: false,
                        bits: 64,
                    }) && ty.copyable && !ty.strict_linear
                })
            })) && module
                .functions
                .get(method.0 as usize)
                .is_some_and(|target| {
                    target.role == FunctionRole::ActorTurn(*actor)
                        && target.color == FunctionColor::Async
                        && target.result_types.len() == 1
                })
                && module.proofs.get(permit.0 as usize).is_some_and(|proof| {
                    proof.kind == ProofKind::CapacityBound && proof.bound == Some(1)
                })
                && module.proofs.get(reply.0 as usize).is_some_and(|proof| {
                    let target_type_proof =
                        module.functions.get(method.0 as usize).and_then(|target| {
                            target.proofs.iter().copied().find(|candidate| {
                                module
                                    .proofs
                                    .get(candidate.0 as usize)
                                    .is_some_and(|record| record.kind == ProofKind::TypeChecked)
                            })
                        });
                    let mut expected = target_type_proof.map(|type_proof| [type_proof, *permit]);
                    if let Some(expected) = &mut expected {
                        expected.sort_unstable();
                    }
                    proof.kind == ProofKind::ActorReplyExactlyOnce
                        && proof.bound == Some(1)
                        && expected.is_some_and(|expected| proof.depends_on == expected)
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reply request",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::ActorReplyResolve { outcome, reply } => {
            value!(*outcome);
            proof!(*reply);
            let valid = instruction.results.is_empty()
                && module.proofs.get(reply.0 as usize).is_some_and(|proof| {
                    proof.kind == ProofKind::ActorReplyExactlyOnce && proof.bound == Some(1)
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reply resolve",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::ActorReject { reservation } => value!(*reservation),
        FlowOperation::MailboxReceive { actor, .. } => {
            require_id("mailbox actor", actor.0, module.actors.len(), errors)
        }
        FlowOperation::ReplyResolve { endpoint, outcome } => {
            value!(*endpoint);
            value!(*outcome);
        }
        FlowOperation::ReceiptCommit { receipt, payload } => {
            value!(*receipt);
            value!(*payload);
        }
        FlowOperation::ReceiptResolve { receipt, outcome } => {
            value!(*receipt);
            value!(*outcome);
        }
        FlowOperation::TaskAcquireSlot { task, proof: p } => {
            require_id("task slot", task.0, module.tasks.len(), errors);
            proof!(*p);
        }
        FlowOperation::TaskStart {
            slot,
            entry,
            arguments,
        } => {
            value!(*slot);
            require_id("task start", entry.0, module.functions.len(), errors);
            for id in arguments {
                value!(*id);
            }
            validate_call_arguments(module, function, *entry, arguments, errors);
            errors.push(ValidationError::InvalidRecord {
                kind: "task start slot provenance is not sealed",
                id: instruction.id.0,
            });
        }
        FlowOperation::TaskCancel { task } => value!(*task),
        FlowOperation::Park { wait_set } => value!(*wait_set),
        FlowOperation::Wake { target } => value!(*target),
        FlowOperation::Checkpoint { id, proof: p } => {
            require_id("checkpoint", id.0, module.checkpoints.len(), errors);
            proof!(*p);
        }
        FlowOperation::InterruptRestore { token } => value!(*token),
        FlowOperation::InterruptPublish {
            cell,
            value: published,
        } => {
            value!(*cell);
            value!(*published);
        }
        FlowOperation::MmioRead { device, .. } => {
            require_id("MMIO device", device.0, module.devices.len(), errors)
        }
        FlowOperation::MmioWrite {
            device,
            value: written,
            ..
        } => {
            require_id("MMIO device", device.0, module.devices.len(), errors);
            value!(*written);
        }
        FlowOperation::DmaTransition {
            token,
            device,
            proof: p,
            ..
        } => {
            value!(*token);
            require_id("DMA device", device.0, module.devices.len(), errors);
            proof!(*p);
        }
        FlowOperation::QueueReserve {
            device,
            descriptors,
            proof: p,
        } => {
            require_id("queue device", device.0, module.devices.len(), errors);
            value!(*descriptors);
            proof!(*p);
        }
        FlowOperation::QueuePublish {
            reservation,
            payload,
        } => {
            value!(*reservation);
            value!(*payload);
        }
        FlowOperation::ValidateDeviceValue {
            value: checked,
            proof: p,
        } => {
            value!(*checked);
            proof!(*p);
        }
        FlowOperation::Check {
            condition,
            proof: p,
            ..
        } => {
            value!(*condition);
            if let Some(p) = p {
                proof!(*p);
            }
        }
        FlowOperation::Assert { condition, failure } => {
            value!(*condition);
            if failure.expression.chars().all(char::is_whitespace)
                || failure.expression.len() > ASSERTION_EXPRESSION_BYTES_MAX
                || failure.message.as_ref().is_some_and(|message| {
                    message.chars().all(char::is_whitespace)
                        || message.len() > ASSERTION_EXPRESSION_BYTES_MAX
                })
                || failure.source.range.start > failure.source.range.end
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "runtime assertion descriptor",
                    id: instruction.id.0,
                });
            }
        }
        FlowOperation::RecordEvent { payload, .. } => value!(*payload),
        FlowOperation::ReplayEvent { destination, .. } => value!(*destination),
        FlowOperation::TestEmit { payload } => value!(*payload),
        FlowOperation::TestFinish { outcome } => value!(*outcome),
        FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::Fence { .. } => {}
    }
}

fn validate_terminator(
    module: &FlowWir,
    function: &FlowFunction,
    terminator: &Terminator,
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
        Terminator::Jump { target, arguments } => {
            block!(*target);
            for id in arguments {
                value!(*id);
            }
            validate_edge(function, *target, arguments, errors);
        }
        Terminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => {
            value!(*condition);
            block!(*then_block);
            block!(*else_block);
            for id in then_arguments.iter().chain(else_arguments) {
                value!(*id);
            }
            validate_edge(function, *then_block, then_arguments, errors);
            validate_edge(function, *else_block, else_arguments, errors);
        }
        Terminator::Switch {
            value: switched,
            cases,
            default,
            default_arguments,
        } => {
            value!(*switched);
            block!(*default);
            for id in default_arguments {
                value!(*id);
            }
            validate_edge(function, *default, default_arguments, errors);
            for case in cases {
                block!(case.target);
                for id in &case.arguments {
                    value!(*id);
                }
                validate_edge(function, case.target, &case.arguments, errors);
            }
        }
        Terminator::Return(values) => {
            for id in values {
                value!(*id);
            }
            if values.len() != function.result_types.len() {
                errors.push(ValidationError::ReturnArity {
                    function: function.id,
                    expected: function.result_types.len(),
                    actual: values.len(),
                });
            }
        }
        Terminator::Suspend {
            activation, resume, ..
        } => {
            block!(*resume);
            value!(*activation);
            if function.color != FunctionColor::Async {
                errors.push(ValidationError::InvalidRecord {
                    kind: "suspend in non-async function",
                    id: function.id.0,
                });
            }
        }
        Terminator::TailCall {
            function: callee,
            arguments,
        } => {
            require_id("tail callee", callee.0, module.functions.len(), errors);
            for id in arguments {
                value!(*id);
            }
            validate_call_arguments(module, function, *callee, arguments, errors);
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.color == FunctionColor::Async)
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "tail call to async function",
                    id: function.id.0,
                });
            }
        }
        Terminator::Trap { detail, .. } => {
            if let Some(detail) = detail {
                value!(*detail);
            }
        }
        Terminator::Unreachable => {}
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
    UnsupportedVersion(u32),
    MissingImageName,
    NonDenseId {
        kind: &'static str,
        expected: usize,
        actual: u32,
    },
    UnknownFunction(FunctionId),
    UnknownBlock {
        function: FunctionId,
        block: BlockId,
    },
    UnknownValue {
        function: FunctionId,
        value: ValueId,
    },
    UnknownReference {
        kind: &'static str,
        id: u32,
    },
    ValueDefinitionCount {
        function: FunctionId,
        value: ValueId,
        definitions: u8,
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
    TerminatorTypeMismatch {
        function: FunctionId,
        block: BlockId,
    },
    DuplicateSwitchCase {
        function: FunctionId,
        block: BlockId,
        value: u128,
    },
    SwitchCaseOutOfRange {
        function: FunctionId,
        block: BlockId,
        value: u128,
        bits: Option<u16>,
    },
    TailCallResultMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    InvalidRecord {
        kind: &'static str,
        id: u32,
    },
    NonCanonicalReferences {
        kind: &'static str,
        owner: u32,
    },
    CyclicReferences(&'static str),
    DuplicatePlanOwner(&'static str),
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
    EdgeArity {
        function: FunctionId,
        target: BlockId,
        expected: usize,
        actual: usize,
    },
    EdgeTypeMismatch {
        function: FunctionId,
        target: BlockId,
    },
    ReturnArity {
        function: FunctionId,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FlowWir validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_source::{FileId, TextRange};

    fn fixture() -> FlowWir {
        let digest = Sha256Digest::from_bytes([1; 32]);
        FlowWir {
            version: FLOW_WIR_VERSION,
            name: "image".to_owned(),
            build: BuildIdentity {
                compiler: digest,
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: digest,
                standard_library: digest,
                source_graph: digest,
                request: digest,
                profile: digest,
            },
            source_summary: SourceSummary {
                semantic_wir_version: SUPPORTED_SEMANTIC_WIR_VERSION,
                semantic_functions: 1,
                hir_files: 1,
                hir_declarations: 1,
                reachable_declarations: 1,
                monomorphized_instantiations: 1,
                resolved_interface_calls: 0,
            },
            types: vec![FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            }],
            globals: Vec::new(),
            functions: vec![FlowFunction {
                id: FunctionId(0),
                name: "entry".to_owned(),
                origin: FunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 0,
                },
                role: FunctionRole::ImageEntry,
                color: FunctionColor::Sync,
                parameters: Vec::new(),
                result_types: Vec::new(),
                values: Vec::new(),
                blocks: vec![Block {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: Vec::new(),
                    terminator: Terminator::Return(Vec::new()),
                    source: None,
                }],
                entry: BlockId(0),
                stack_bound: 0,
                frame_bound: 0,
                proofs: Vec::new(),
                source: None,
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            activations: Vec::new(),
            schedulers: Vec::new(),
            proofs: Vec::new(),
            checkpoints: Vec::new(),
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![PlanOwner::Runtime],
            shutdown_order: vec![PlanOwner::Runtime],
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
    }

    fn bounded_string_fixture() -> FlowWir {
        let mut module = fixture();
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 10, end: 20 },
        };
        module.types.extend([
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 8,
                }),
                name: Some("u8".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::StaticString { bytes: 5 },
                name: Some("Static[Str]".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(3),
                kind: FlowTypeKind::BoundedString { capacity: 10 },
                name: Some("BoundedString".to_owned()),
                copyable: false,
                strict_linear: false,
            },
        ]);
        let function = &mut module.functions[0];
        function.values = vec![
            Value {
                id: ValueId(0),
                ty: TypeId(1),
                source_name: Some("count".to_owned()),
                source: Some(source),
            },
            Value {
                id: ValueId(1),
                ty: TypeId(2),
                source_name: Some("label".to_owned()),
                source: Some(source),
            },
            Value {
                id: ValueId(2),
                ty: TypeId(3),
                source_name: Some("rendered".to_owned()),
                source: Some(source),
            },
        ];
        function.blocks[0].instructions = vec![
            Instruction {
                id: InstructionId(0),
                results: vec![ValueId(0)],
                operation: FlowOperation::Immediate(Immediate::Integer {
                    bits: 8,
                    bytes_le: vec![7],
                }),
                source: Some(source),
            },
            Instruction {
                id: InstructionId(1),
                results: vec![ValueId(1)],
                operation: FlowOperation::Immediate(Immediate::Bytes(b"ready".to_vec())),
                source: Some(source),
            },
            Instruction {
                id: InstructionId(2),
                results: vec![ValueId(2)],
                operation: FlowOperation::FormatBoundedString {
                    ty: TypeId(3),
                    parts: vec![
                        BoundedStringPart::Text {
                            value: "n=".to_owned(),
                            source,
                        },
                        BoundedStringPart::Integer {
                            value: ValueId(0),
                            maximum_bytes: 3,
                            source,
                        },
                        BoundedStringPart::StaticString {
                            value: ValueId(1),
                            bytes: 5,
                            source,
                        },
                    ],
                },
                source: Some(source),
            },
        ];
        module
    }

    #[test]
    fn bounded_string_construction_authenticates_flow_parts_capacity_and_identity() {
        bounded_string_fixture()
            .validate()
            .expect("exact bounded string FlowWir");

        let mutate = |module: &mut FlowWir, mutation: u8| {
            let FlowOperation::FormatBoundedString { ty, parts } =
                &mut module.functions[0].blocks[0].instructions[2].operation
            else {
                panic!("bounded fixture operation")
            };
            match mutation {
                0 => *ty = TypeId(2),
                1 => {
                    let BoundedStringPart::Integer { maximum_bytes, .. } = &mut parts[1] else {
                        panic!("integer part")
                    };
                    *maximum_bytes = 4;
                }
                2 => {
                    let BoundedStringPart::StaticString { bytes, .. } = &mut parts[2] else {
                        panic!("static part")
                    };
                    *bytes = 4;
                }
                3 => module.types[3].kind = FlowTypeKind::BoundedString { capacity: 11 },
                _ => unreachable!(),
            }
        };
        for mutation in 0..4 {
            let mut forged = bounded_string_fixture();
            mutate(&mut forged, mutation);
            let errors = forged.validate().expect_err("forged bounded string").0;
            assert!(errors.iter().any(|error| matches!(
                error,
                ValidationError::InvalidRecord {
                    kind: "bounded string construction",
                    id: 2
                }
            )));
        }

        let calls = Cell::new(0_u64);
        bounded_string_fixture()
            .validate_with_limits(ValidationLimits::standard(), &|| {
                calls.set(calls.get() + 1);
                false
            })
            .expect("bounded string validation baseline");
        let final_poll = calls.get();
        calls.set(0);
        assert_eq!(
            bounded_string_fixture().validate_with_limits(ValidationLimits::standard(), &|| {
                let next = calls.get() + 1;
                calls.set(next);
                next >= final_poll
            }),
            Err(ValidationFailure::Cancelled)
        );
    }

    fn closed_enum_fixture(variants: usize) -> FlowWir {
        let mut module = fixture();
        module.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 8,
            }),
            name: Some("u8".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        module.types.push(FlowType {
            id: TypeId(2),
            kind: FlowTypeKind::Enum {
                variants: (0..variants).map(|_| vec![TypeId(1)]).collect(),
            },
            name: Some("LocalResult".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "construct-and-project".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: vec![ValueId(0)],
            result_types: vec![TypeId(1)],
            values: vec![
                Value {
                    id: ValueId(0),
                    ty: TypeId(1),
                    source_name: Some("payload".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(1),
                    ty: TypeId(2),
                    source_name: Some("result".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(2),
                    ty: TypeId(1),
                    source_name: Some("tag".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(3),
                    ty: TypeId(1),
                    source_name: Some("projected".to_owned()),
                    source: Some(source),
                },
            ],
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    Instruction {
                        id: InstructionId(0),
                        results: vec![ValueId(1)],
                        operation: FlowOperation::MakeEnum {
                            ty: TypeId(2),
                            variant: u8::try_from(variants.saturating_sub(1).min(255))
                                .expect("bounded variant"),
                            payload: Some(ValueId(0)),
                        },
                        source: Some(source),
                    },
                    Instruction {
                        id: InstructionId(1),
                        results: vec![ValueId(2)],
                        operation: FlowOperation::EnumTag { value: ValueId(1) },
                        source: Some(source),
                    },
                    Instruction {
                        id: InstructionId(2),
                        results: vec![ValueId(3)],
                        operation: FlowOperation::EnumPayload { value: ValueId(1) },
                        source: Some(source),
                    },
                ],
                terminator: Terminator::Return(vec![ValueId(3)]),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(source),
        });
        module.source_summary.semantic_functions = 2;
        module.source_summary.hir_declarations = 2;
        module.source_summary.reachable_declarations = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    fn insert_field_fixture() -> FlowWir {
        let mut module = fixture();
        module.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 64,
            }),
            name: Some("u64".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        module.types.push(FlowType {
            id: TypeId(2),
            kind: FlowTypeKind::Struct {
                fields: vec![TypeId(1)],
            },
            name: Some("Cell".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "replace-cell-value".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: vec![ValueId(0), ValueId(1)],
            result_types: vec![TypeId(2)],
            values: vec![
                Value {
                    id: ValueId(0),
                    ty: TypeId(2),
                    source_name: Some("cell".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(1),
                    ty: TypeId(1),
                    source_name: Some("value".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(2),
                    ty: TypeId(2),
                    source_name: Some("updated".to_owned()),
                    source: Some(source),
                },
            ],
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![Instruction {
                    id: InstructionId(0),
                    results: vec![ValueId(2)],
                    operation: FlowOperation::InsertField {
                        aggregate: ValueId(0),
                        field: 0,
                        value: ValueId(1),
                    },
                    source: Some(source),
                }],
                terminator: Terminator::Return(vec![ValueId(2)]),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(source),
        });
        module.source_summary.semantic_functions = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    #[test]
    fn insert_field_authenticates_aggregate_field_value_and_result_types() {
        let module = insert_field_fixture();
        module.clone().validate().expect("exact field insertion");

        let cases: &[(ValueId, u32, ValueId, TypeId)] = &[
            (ValueId(1), 0, ValueId(1), TypeId(2)),
            (ValueId(0), 1, ValueId(1), TypeId(2)),
            (ValueId(0), 0, ValueId(0), TypeId(2)),
            (ValueId(0), 0, ValueId(1), TypeId(1)),
        ];
        for &(aggregate, field, value, result_ty) in cases {
            let mut forged = module.clone();
            let instruction = &mut forged.functions[1].blocks[0].instructions[0];
            instruction.operation = FlowOperation::InsertField {
                aggregate,
                field,
                value,
            };
            forged.functions[1].values[2].ty = result_ty;
            let errors = forged
                .validate()
                .expect_err("forged field insertion must fail")
                .0;
            assert!(errors.iter().any(|error| matches!(
                error,
                ValidationError::InvalidRecord {
                    kind: "field insertion",
                    id: 0
                }
            )));
        }

        for results in [Vec::new(), vec![ValueId(2), ValueId(2)]] {
            let mut forged = module.clone();
            forged.functions[1].blocks[0].instructions[0].results = results;
            let errors = forged
                .validate()
                .expect_err("non-singleton insertion result must fail")
                .0;
            assert!(errors.iter().any(|error| matches!(
                error,
                ValidationError::InvalidRecord {
                    kind: "field insertion",
                    id: 0
                }
            )));
        }
    }

    #[test]
    fn seals_exact_function_provenance_and_image_role() {
        fixture().validate().expect("valid FlowWir");

        let mut stale_semantic_schema = fixture();
        stale_semantic_schema.source_summary.semantic_wir_version = 5;
        assert!(stale_semantic_schema.validate().is_err());

        let mut wrong_role = fixture();
        wrong_role.functions[0].role = FunctionRole::Ordinary;
        assert!(wrong_role.validate().is_err());

        let mut wrong_origin = fixture();
        wrong_origin.functions[0].origin = FunctionOrigin::GeneratedImageEntry {
            semantic_function: 0,
            constructor: 1,
        };
        assert!(wrong_origin.validate().is_err());

        let mut source_runtime_entry = fixture();
        source_runtime_entry.functions[0].origin = FunctionOrigin::SourceSemantic {
            semantic_function: 0,
        };
        source_runtime_entry.functions[0].source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        });
        assert!(source_runtime_entry.validate().is_err());
    }

    #[test]
    fn closed_enum_accepts_exact_bounds_and_rejects_type_and_operation_substitution() {
        closed_enum_fixture(1).validate().expect("one-variant enum");
        closed_enum_fixture(256)
            .validate()
            .expect("256-variant enum");
        for rejected in [11, FLOW_WIR_VERSION - 1, FLOW_WIR_VERSION + 1] {
            let mut wrong_version = closed_enum_fixture(2);
            wrong_version.version = rejected;
            assert!(wrong_version.validate().is_err());
        }
        assert!(closed_enum_fixture(0).validate().is_err());
        assert!(closed_enum_fixture(257).validate().is_err());

        let mut mixed_payload = closed_enum_fixture(2);
        let FlowTypeKind::Enum { variants } = &mut mixed_payload.types[2].kind else {
            unreachable!();
        };
        variants[1][0] = TypeId(0);
        assert!(mixed_payload.validate().is_err());

        let mut wrong_variant = closed_enum_fixture(2);
        let FlowOperation::MakeEnum { variant, .. } =
            &mut wrong_variant.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *variant = 2;
        assert!(wrong_variant.validate().is_err());

        let mut wrong_tag = closed_enum_fixture(2);
        wrong_tag.functions[1].values[2].ty = TypeId(0);
        assert!(wrong_tag.validate().is_err());

        let mut wrong_payload = closed_enum_fixture(2);
        wrong_payload.functions[1].values[3].ty = TypeId(0);
        assert!(wrong_payload.validate().is_err());

        let mut mixed_arity = closed_enum_fixture(2);
        let FlowTypeKind::Enum { variants } = &mut mixed_arity.types[2].kind else {
            unreachable!();
        };
        variants[0].clear();
        mixed_arity
            .clone()
            .validate()
            .expect("unit plus unary enum is canonical");
        let mut wrong_presence = mixed_arity.clone();
        let FlowOperation::MakeEnum { variant, .. } =
            &mut wrong_presence.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *variant = 0;
        assert!(wrong_presence.validate().is_err());
        let FlowOperation::MakeEnum { payload, .. } =
            &mut mixed_arity.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = None;
        assert!(mixed_arity.validate().is_err());

        let mut all_unit = closed_enum_fixture(2);
        let FlowTypeKind::Enum { variants } = &mut all_unit.types[2].kind else {
            unreachable!();
        };
        for variant in variants {
            variant.clear();
        }
        let FlowOperation::MakeEnum { payload, .. } =
            &mut all_unit.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = None;
        all_unit.functions[1].blocks[0].instructions.remove(2);
        all_unit.functions[1].values.remove(3);
        all_unit.functions[1].blocks[0].terminator = Terminator::Return(vec![ValueId(2)]);
        all_unit
            .clone()
            .validate()
            .expect("all-unit enum has a tag-only FlowWir representation");

        let mut forged_payload = all_unit.clone();
        let FlowOperation::MakeEnum { payload, .. } =
            &mut forged_payload.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!();
        };
        *payload = Some(ValueId(0));
        assert!(forged_payload.validate().is_err());

        let mut forged_projection = all_unit;
        forged_projection.functions[1].values.push(Value {
            id: ValueId(3),
            ty: TypeId(1),
            source_name: Some("forged-projected".to_owned()),
            source: None,
        });
        forged_projection.functions[1].blocks[0]
            .instructions
            .push(Instruction {
                id: InstructionId(2),
                results: vec![ValueId(3)],
                operation: FlowOperation::EnumPayload { value: ValueId(1) },
                source: None,
            });
        assert!(forged_projection.validate().is_err());
    }

    #[test]
    fn fixed_flat_enum_payload_accepts_exact_nominal_operations_and_rejects_substitution() {
        let mut module = fixture();
        module.types.extend([
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 8,
                }),
                name: Some("u8".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::Struct {
                    fields: vec![TypeId(1)],
                },
                name: Some("Detail".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(3),
                kind: FlowTypeKind::Enum {
                    variants: vec![vec![TypeId(2)], vec![TypeId(1)]],
                },
                name: Some("Envelope".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ]);
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "construct-fixed-payload".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: vec![ValueId(0)],
            result_types: vec![TypeId(3)],
            values: vec![
                Value {
                    id: ValueId(0),
                    ty: TypeId(1),
                    source_name: Some("word".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(1),
                    ty: TypeId(2),
                    source_name: Some("detail".to_owned()),
                    source: Some(source),
                },
                Value {
                    id: ValueId(2),
                    ty: TypeId(3),
                    source_name: Some("envelope".to_owned()),
                    source: Some(source),
                },
            ],
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    Instruction {
                        id: InstructionId(0),
                        results: vec![ValueId(1)],
                        operation: FlowOperation::MakeAggregate {
                            ty: TypeId(2),
                            fields: vec![ValueId(0)],
                        },
                        source: Some(source),
                    },
                    Instruction {
                        id: InstructionId(1),
                        results: vec![ValueId(2)],
                        operation: FlowOperation::MakeEnum {
                            ty: TypeId(3),
                            variant: 0,
                            payload: Some(ValueId(1)),
                        },
                        source: Some(source),
                    },
                ],
                terminator: Terminator::Return(vec![ValueId(2)]),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(source),
        });
        module.source_summary.semantic_functions = 2;
        module.source_summary.hir_declarations = 2;
        module.source_summary.reachable_declarations = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module
            .clone()
            .validate()
            .expect("exact fixed flat payload and construction are canonical");

        let mut wrong_variant_payload = module.clone();
        let FlowOperation::MakeEnum {
            variant, payload, ..
        } = &mut wrong_variant_payload.functions[1].blocks[0].instructions[1].operation
        else {
            unreachable!();
        };
        *variant = 1;
        *payload = Some(ValueId(1));
        assert!(wrong_variant_payload.validate().is_err());

        let mut wrong_nominal_value = module;
        let FlowOperation::MakeEnum { payload, .. } =
            &mut wrong_nominal_value.functions[1].blocks[0].instructions[1].operation
        else {
            unreachable!();
        };
        *payload = Some(ValueId(0));
        assert!(wrong_nominal_value.validate().is_err());
    }

    #[test]
    fn explicit_validation_policy_bounds_resources_errors_and_cancellation() {
        let payload_limited = ValidationLimits {
            payload_bytes: 4,
            ..ValidationLimits::standard()
        };
        assert!(matches!(
            fixture().validate_with_limits(payload_limited, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: 4,
            })
        ));

        let invalid_limits = ValidationLimits {
            errors: 0,
            ..ValidationLimits::standard()
        };
        assert_eq!(
            fixture().validate_with_limits(invalid_limits, &|| false),
            Err(ValidationFailure::InvalidLimits)
        );
        assert_eq!(
            fixture().validate_with_limits(ValidationLimits::standard(), &|| true),
            Err(ValidationFailure::Cancelled)
        );

        let mut malformed = fixture();
        malformed.version = 0;
        malformed.name.clear();
        malformed.source_summary.reachable_declarations = 2;
        malformed.static_bytes = 1;
        malformed.peak_bytes = 0;
        let bounded_errors = ValidationLimits {
            errors: 2,
            ..ValidationLimits::standard()
        };
        let Err(ValidationFailure::Invalid(ValidationErrors(errors))) =
            malformed.validate_with_limits(bounded_errors, &|| false)
        else {
            panic!("malformed FlowWir must fail");
        };
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors.last(),
            Some(&ValidationError::TooManyErrors { limit: 2 })
        );
    }

    #[test]
    fn validation_rejects_arena_maximum_plus_one_before_scratch_allocation() {
        let mut module = fixture();
        module.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Unit,
            name: Some("unit-duplicate".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let limits = ValidationLimits {
            arena_records: 1,
            ..ValidationLimits::standard()
        };
        assert_eq!(
            module.validate_with_limits(limits, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "types",
                limit: 1,
            })
        );
    }

    #[test]
    fn scratch_allocation_policy_and_sort_cancellation_are_contained() {
        let limits = ValidationLimits {
            model_edges: 1,
            ..ValidationLimits::standard()
        };
        let mut bounded = ValidationContext::new(limits, &|| false);
        assert!(bounded.scratch::<u8>(2).is_none());
        assert_eq!(
            bounded.finish(),
            Err(ValidationFailure::ResourceLimit {
                resource: "validation scratch entries",
                limit: 1,
            })
        );

        let calls = Cell::new(0_u64);
        let mut values: Vec<_> = (0_u32..4096).rev().collect();
        let cancellation = || {
            let next = calls.get() + 1;
            calls.set(next);
            next > 64
        };
        let mut cancelled = ValidationContext::new(ValidationLimits::standard(), &cancellation);
        assert!(!sort_scratch(&mut values, &mut cancelled));
        assert_eq!(cancelled.finish(), Err(ValidationFailure::Cancelled));
        assert!(calls.get() > 64);
    }

    #[test]
    fn cancellation_prevents_late_validated_flow_publication() {
        let calls = Cell::new(0_u64);
        fixture()
            .validate_with_limits(ValidationLimits::standard(), &|| {
                calls.set(calls.get() + 1);
                false
            })
            .expect("validation baseline");
        let baseline = calls.get();
        calls.set(0);
        let result = fixture().validate_with_limits(ValidationLimits::standard(), &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next >= baseline
        });
        assert_eq!(result, Err(ValidationFailure::Cancelled));
        assert!(calls.get() >= baseline);
    }

    #[test]
    fn rejects_out_of_graph_spans_and_noncanonical_proofs() {
        let mut invalid_block_source = fixture();
        invalid_block_source.functions[0].blocks[0].source = Some(Span {
            file: FileId(1),
            range: TextRange { start: 0, end: 0 },
        });
        assert!(invalid_block_source.validate().is_err());

        let mut valid_proof = fixture();
        valid_proof.proofs.push(Proof {
            id: ProofId(0),
            kind: ProofKind::TypeChecked,
            subject: "generated entry".to_owned(),
            sources: vec![Span {
                file: FileId(0),
                range: TextRange { start: 0, end: 1 },
            }],
            depends_on: Vec::new(),
            bound: None,
            explanation: vec!["semantic type proof retained exactly".to_owned()],
        });
        valid_proof
            .clone()
            .validate()
            .expect("valid canonical proof");

        let mut forward_dependency = valid_proof.clone();
        forward_dependency.proofs[0].depends_on = vec![ProofId(0)];
        assert!(forward_dependency.validate().is_err());

        let mut missing_explanation = valid_proof;
        missing_explanation.proofs[0].explanation.clear();
        assert!(missing_explanation.validate().is_err());
    }

    fn fixture_with_test() -> FlowWir {
        let mut module = fixture();
        module.source_summary.semantic_functions = 2;
        module.source_summary.hir_declarations = 2;
        module.source_summary.reachable_declarations = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module.functions[0].origin = FunctionOrigin::GeneratedTestHarness {
            semantic_function: 0,
            group: 0,
        };
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "integration-test".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Test,
            color: FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: Some(Span {
                    file: FileId(0),
                    range: TextRange { start: 10, end: 20 },
                }),
            }],
            entry: BlockId(0),
            stack_bound: 64,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(Span {
                file: FileId(0),
                range: TextRange { start: 10, end: 20 },
            }),
        });
        module.tests.push(TestEntry {
            id: TestId(0),
            plan_id: 0,
            function_key: Sha256Digest::from_bytes([1; 32]),
            name: "integration-test".to_owned(),
            function: FunctionId(1),
            kind: TestKind::Integration,
            source: Span {
                file: FileId(0),
                range: TextRange { start: 10, end: 20 },
            },
            timeout_ns: 5_000_000_000,
        });
        module.compiled_test_group = Some(wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(0),
            name: "integration".to_owned(),
            root: wrela_test_model::ImageRoot::GeneratedHarness {
                harness_name: "image".to_owned(),
            },
            tests: vec![wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(0),
                    name: "integration-test".to_owned(),
                    kind: wrela_test_model::TestKind::IntegrationImage,
                    source: Some(Span {
                        file: FileId(0),
                        range: TextRange { start: 10, end: 20 },
                    }),
                    timeout_ns: 5_000_000_000,
                },
                invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                    function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes([1; 32])),
                },
                assertions: Vec::new(),
            }],
            deterministic_seed: None,
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: 5,
            maximum_output_bytes: 1,
        });
        module
    }

    #[test]
    fn seals_dense_exact_test_function_table() {
        fixture_with_test()
            .validate()
            .expect("valid canonical test table");

        let mut non_dense = fixture_with_test();
        non_dense.tests[0].id = TestId(1);
        assert!(non_dense.validate().is_err());

        let mut wrong_role = fixture_with_test();
        wrong_role.functions[1].role = FunctionRole::Ordinary;
        assert!(wrong_role.validate().is_err());

        let mut missing = fixture_with_test();
        missing.tests.clear();
        assert!(missing.validate().is_err());

        let mut duplicate = fixture_with_test();
        duplicate.tests.push(TestEntry {
            id: TestId(1),
            ..duplicate.tests[0].clone()
        });
        assert!(duplicate.validate().is_err());

        let mut invalid_source = fixture_with_test();
        invalid_source.tests[0].source.file = FileId(1);
        assert!(invalid_source.validate().is_err());

        let mut zero_timeout = fixture_with_test();
        zero_timeout.tests[0].timeout_ns = 0;
        assert!(zero_timeout.validate().is_err());

        let mut substituted_key = fixture_with_test();
        let Some(group) = &mut substituted_key.compiled_test_group else {
            panic!("compiled test-group binding");
        };
        group.tests[0].invocation = wrela_test_model::ImageTestInvocation::GeneratedFunction {
            function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes([9; 32])),
        };
        assert!(substituted_key.validate().is_err());

        let mut substituted_plan_id = fixture_with_test();
        substituted_plan_id.tests[0].plan_id = 7;
        assert!(substituted_plan_id.validate().is_err());
    }

    fn push_scalar_type(module: &mut FlowWir, scalar: ScalarType) -> TypeId {
        let id = TypeId(module.types.len() as u32);
        module.types.push(FlowType {
            id,
            kind: FlowTypeKind::Scalar(scalar),
            name: None,
            copyable: true,
            strict_linear: false,
        });
        id
    }

    fn push_value(function: &mut FlowFunction, ty: TypeId) -> ValueId {
        let id = ValueId(function.values.len() as u32);
        function.values.push(Value {
            id,
            ty,
            source_name: None,
            source: None,
        });
        id
    }

    fn explicit_unit_call_fixture() -> FlowWir {
        let mut module = fixture();
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 10, end: 20 },
        };
        module.source_summary.semantic_functions = 2;
        module.source_summary.hir_declarations = 2;
        module.source_summary.reachable_declarations = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module.functions[0].values.push(Value {
            id: ValueId(0),
            ty: TypeId(0),
            source_name: None,
            source: Some(source),
        });
        module.functions[0].blocks[0]
            .instructions
            .push(Instruction {
                id: InstructionId(0),
                results: vec![ValueId(0)],
                operation: FlowOperation::Call {
                    function: FunctionId(1),
                    arguments: Vec::new(),
                },
                source: Some(source),
            });
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "unit-helper".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(source),
        });
        module
    }

    fn assert_call_result_mismatch(module: FlowWir) {
        let errors = module
            .validate()
            .expect_err("malformed call result contract must fail")
            .0;
        assert!(errors.contains(&ValidationError::CallResultMismatch {
            caller: FunctionId(0),
            callee: FunctionId(1),
        }));
    }

    #[test]
    fn unit_call_result_contract_round_trips_and_rejects_malformed_vectors() {
        let explicit = explicit_unit_call_fixture();
        let validated = explicit
            .clone()
            .validate()
            .expect("one explicit unit SSA result is canonical");
        assert_eq!(validated.into_wir(), explicit);

        let mut ignored = explicit_unit_call_fixture();
        ignored.functions[0].blocks[0].instructions[0]
            .results
            .clear();
        ignored.functions[0].values.clear();
        ignored
            .validate()
            .expect("an ignored unit result remains canonical");

        let mut two = explicit_unit_call_fixture();
        let second = push_value(&mut two.functions[0], TypeId(0));
        two.functions[0].blocks[0].instructions[0]
            .results
            .push(second);
        assert_call_result_mismatch(two);

        let mut wrong_type = explicit_unit_call_fixture();
        let integer = push_scalar_type(
            &mut wrong_type,
            ScalarType::Integer {
                signed: false,
                bits: 32,
            },
        );
        wrong_type.functions[0].values[0].ty = integer;
        assert_call_result_mismatch(wrong_type);

        let mut forged_callee = explicit_unit_call_fixture();
        let integer = push_scalar_type(
            &mut forged_callee,
            ScalarType::Integer {
                signed: false,
                bits: 32,
            },
        );
        let result = push_value(&mut forged_callee.functions[1], integer);
        forged_callee.functions[1].result_types = vec![integer];
        forged_callee.functions[1].blocks[0]
            .instructions
            .push(Instruction {
                id: InstructionId(0),
                results: vec![result],
                operation: FlowOperation::Immediate(Immediate::Integer {
                    bits: 32,
                    bytes_le: vec![0; 4],
                }),
                source: None,
            });
        forged_callee.functions[1].blocks[0].terminator = Terminator::Return(vec![result]);
        assert_call_result_mismatch(forged_callee);
    }

    fn async_fixture() -> FlowWir {
        let mut module = fixture();
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 10, end: 20 },
        };
        module.source_summary.semantic_functions = 3;
        module.source_summary.hir_declarations = 3;
        module.source_summary.reachable_declarations = 3;
        module.source_summary.monomorphized_instantiations = 3;
        module.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Activation { result: TypeId(0) },
            name: Some("__wrela_activation_0".to_owned()),
            copyable: false,
            strict_linear: true,
        });
        module.functions.push(FlowFunction {
            id: FunctionId(1),
            name: "async-unit".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::ActorTurn(ActorId(0)),
            color: FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: vec![
                Value {
                    id: ValueId(0),
                    ty: TypeId(1),
                    source_name: None,
                    source: Some(source),
                },
                Value {
                    id: ValueId(1),
                    ty: TypeId(0),
                    source_name: None,
                    source: Some(source),
                },
            ],
            blocks: vec![
                Block {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![Instruction {
                        id: InstructionId(0),
                        results: vec![ValueId(0)],
                        operation: FlowOperation::AsyncCall {
                            function: FunctionId(2),
                            arguments: Vec::new(),
                            plan: ActivationId(0),
                        },
                        source: Some(source),
                    }],
                    terminator: Terminator::Suspend {
                        state: 0,
                        activation: ValueId(0),
                        resume: BlockId(1),
                    },
                    source: Some(source),
                },
                Block {
                    id: BlockId(1),
                    parameters: vec![ValueId(1)],
                    instructions: Vec::new(),
                    terminator: Terminator::Return(Vec::new()),
                    source: Some(source),
                },
            ],
            entry: BlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![ProofId(8)],
            source: Some(source),
        });
        module.functions.push(FlowFunction {
            id: FunctionId(2),
            name: "async-helper".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![ProofId(2)],
            source: Some(source),
        });
        module.functions[0].proofs = vec![
            ProofId(3),
            ProofId(4),
            ProofId(5),
            ProofId(6),
            ProofId(7),
            ProofId(9),
        ];
        module.actors.push(ActorPlan {
            id: ActorId(0),
            name: "actor".to_owned(),
            state_type: TypeId(0),
            mailbox_capacity: 1,
            message_types: Vec::new(),
            turn_functions: vec![FunctionId(1)],
            priority: 1,
            supervisor: None,
        });
        module.proofs = vec![
            Proof {
                id: ProofId(0),
                kind: ProofKind::TypeChecked,
                subject: "actor image types".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: None,
                explanation: vec!["actor image is typed".to_owned()],
            },
            Proof {
                id: ProofId(1),
                kind: ProofKind::EffectsAllowed,
                subject: "actor image effects".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(0)],
                bound: None,
                explanation: vec!["actor image effects are closed".to_owned()],
            },
            Proof {
                id: ProofId(2),
                kind: ProofKind::CleanupAcyclic,
                subject: "helper cleanup".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["drop helper frame".to_owned()],
            },
            Proof {
                id: ProofId(3),
                kind: ProofKind::CapacityBound,
                subject: "mailbox capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one mailbox slot".to_owned()],
            },
            Proof {
                id: ProofId(4),
                kind: ProofKind::CapacityBound,
                subject: "turn capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one turn frame".to_owned()],
            },
            Proof {
                id: ProofId(5),
                kind: ProofKind::WaitGraphAcyclic,
                subject: "closed actor wait graph".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(1)],
                bound: Some(1),
                explanation: vec!["one acyclic await edge".to_owned()],
            },
            Proof {
                id: ProofId(6),
                kind: ProofKind::SupervisionComplete,
                subject: "complete static actor/task parent topology".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(0)],
                bound: Some(1),
                explanation: vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()],
            },
            Proof {
                id: ProofId(7),
                kind: ProofKind::CapacityBound,
                subject: "base actor allocation".to_owned(),
                sources: vec![source, source],
                depends_on: vec![
                    ProofId(0),
                    ProofId(1),
                    ProofId(3),
                    ProofId(4),
                    ProofId(5),
                    ProofId(6),
                ],
                bound: Some(24),
                explanation: vec!["mailbox plus root turn frame".to_owned()],
            },
            Proof {
                id: ProofId(8),
                kind: ProofKind::CapacityBound,
                subject: "call activation".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(2)],
                bound: Some(1),
                explanation: vec!["one helper frame".to_owned()],
            },
            Proof {
                id: ProofId(9),
                kind: ProofKind::ImageClosed,
                subject: "closed actor image".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(7), ProofId(8)],
                bound: Some(32),
                explanation: vec!["base plus helper activation".to_owned()],
            },
        ];
        module.regions = vec![
            RegionPlan {
                id: RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(3),
                source,
            },
            RegionPlan {
                id: RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(4),
                source,
            },
            RegionPlan {
                id: RegionId(2),
                name: "async-unit.async-activation-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(8),
                source,
            },
        ];
        module.activations.push(ActivationPlan {
            id: ActivationId(0),
            caller: FunctionId(1),
            callee: FunctionId(2),
            region: RegionId(2),
            frame_bytes: 8,
            maximum_live: 1,
            cancellation: ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: ProofId(8),
            source,
        });
        module.schedulers = vec![SchedulerPlan {
            core: 0,
            actors: vec![ActorId(0)],
            tasks: Vec::new(),
        }];
        module.startup_order = vec![PlanOwner::Runtime, PlanOwner::Actor(ActorId(0))];
        module.shutdown_order = vec![PlanOwner::Actor(ActorId(0)), PlanOwner::Runtime];
        module.static_bytes = 32;
        module.peak_bytes = 32;
        module
    }

    #[test]
    fn async_activation_delivery_is_strict_linear_typed_and_dense() {
        async_fixture()
            .validate()
            .expect("valid explicit unit async delivery");

        let mut copyable = async_fixture();
        copyable.types[1].copyable = true;
        assert!(copyable.validate().is_err());

        let mut wrong_color = async_fixture();
        wrong_color.functions[1].color = FunctionColor::Sync;
        assert!(wrong_color.validate().is_err());

        let mut missing_delivery = async_fixture();
        missing_delivery.functions[1].blocks[1].parameters.clear();
        assert!(missing_delivery.validate().is_err());

        let mut non_dense_state = async_fixture();
        let Terminator::Suspend { state, .. } =
            &mut non_dense_state.functions[1].blocks[0].terminator
        else {
            panic!("async fixture suspend")
        };
        *state = 1;
        assert!(non_dense_state.validate().is_err());

        let mut activation_crosses_edge = async_fixture();
        let suspend = activation_crosses_edge.functions[1].blocks[0]
            .terminator
            .clone();
        activation_crosses_edge.functions[1].blocks[0].terminator = Terminator::Jump {
            target: BlockId(2),
            arguments: Vec::new(),
        };
        let function_source = activation_crosses_edge.functions[1].source;
        activation_crosses_edge.functions[1].blocks.push(Block {
            id: BlockId(2),
            parameters: Vec::new(),
            instructions: Vec::new(),
            terminator: suspend,
            source: function_source,
        });
        assert!(activation_crosses_edge.validate().is_err());

        let mut ordinary_call = async_fixture();
        ordinary_call.functions[1].blocks[0].instructions[0].operation = FlowOperation::Call {
            function: FunctionId(1),
            arguments: Vec::new(),
        };
        assert!(ordinary_call.validate().is_err());

        let mut overprovisioned = async_fixture();
        overprovisioned.activations[0].maximum_live = 2;
        overprovisioned.regions[2].capacity_bytes = 16;
        overprovisioned.proofs[8].bound = Some(2);
        overprovisioned.proofs[9].bound = Some(40);
        overprovisioned.static_bytes = 40;
        overprovisioned.peak_bytes = 40;
        assert!(overprovisioned.validate().is_err());

        let mut stale_static = async_fixture();
        stale_static.static_bytes = 24;
        stale_static.peak_bytes = 24;
        assert!(stale_static.validate().is_err());

        let mut omitted_region = async_fixture();
        omitted_region.regions.pop();
        assert!(omitted_region.validate().is_err());

        let mut omitted_startup_actor = async_fixture();
        omitted_startup_actor.startup_order.pop();
        assert!(omitted_startup_actor.validate().is_err());

        let mut omitted_startup_runtime = async_fixture();
        omitted_startup_runtime.startup_order.remove(0);
        assert!(omitted_startup_runtime.validate().is_err());

        let mut mismatched_shutdown = async_fixture();
        mismatched_shutdown.shutdown_order = vec![PlanOwner::Runtime];
        assert!(mismatched_shutdown.validate().is_err());

        let mut wrong_caller = async_fixture();
        wrong_caller.activations[0].caller = FunctionId(2);
        assert!(wrong_caller.validate().is_err());

        let mut wrong_call_link = async_fixture();
        let FlowOperation::AsyncCall { plan, .. } =
            &mut wrong_call_link.functions[1].blocks[0].instructions[0].operation
        else {
            panic!("async call")
        };
        *plan = ActivationId(1);
        assert!(wrong_call_link.validate().is_err());

        let mut omitted_cleanup = async_fixture();
        omitted_cleanup.proofs[8].depends_on.clear();
        assert!(omitted_cleanup.validate().is_err());

        let mut omitted_caller_attachment = async_fixture();
        omitted_caller_attachment.functions[1].proofs.clear();
        assert!(omitted_caller_attachment.validate().is_err());

        let mut substituted_caller_attachment = async_fixture();
        substituted_caller_attachment.functions[1].proofs[0] = ProofId(3);
        assert!(substituted_caller_attachment.validate().is_err());

        let mut substituted_cleanup = async_fixture();
        substituted_cleanup.proofs[8].depends_on[0] = ProofId(3);
        assert!(substituted_cleanup.validate().is_err());

        let mut duplicate_cleanup = async_fixture();
        duplicate_cleanup.proofs.push(Proof {
            id: ProofId(10),
            kind: ProofKind::CleanupAcyclic,
            subject: "substituted helper cleanup".to_owned(),
            sources: duplicate_cleanup.proofs[2].sources.clone(),
            depends_on: Vec::new(),
            bound: Some(0),
            explanation: vec!["duplicate helper cleanup".to_owned()],
        });
        duplicate_cleanup.functions[2].proofs.push(ProofId(10));
        assert!(duplicate_cleanup.validate().is_err());

        let mut omitted_closure_link = async_fixture();
        omitted_closure_link.proofs[9].depends_on.pop();
        assert!(omitted_closure_link.validate().is_err());

        for attachment in [
            ProofId(3),
            ProofId(4),
            ProofId(5),
            ProofId(6),
            ProofId(7),
            ProofId(9),
        ] {
            let mut omitted_entry_attachment = async_fixture();
            omitted_entry_attachment.functions[0]
                .proofs
                .retain(|proof| *proof != attachment);
            assert!(omitted_entry_attachment.validate().is_err());
        }

        let mut omitted_base_dependency = async_fixture();
        omitted_base_dependency.proofs[7].depends_on.remove(3);
        assert!(omitted_base_dependency.validate().is_err());

        let mut substituted_base_dependency = async_fixture();
        substituted_base_dependency.proofs[7].depends_on[3] = ProofId(2);
        assert!(substituted_base_dependency.validate().is_err());

        let mut substituted_base_source = async_fixture();
        substituted_base_source.proofs[7].sources[1].range.start += 1;
        assert!(substituted_base_source.validate().is_err());

        let mut substituted_region = async_fixture();
        substituted_region.activations[0].region = RegionId(1);
        assert!(substituted_region.validate().is_err());

        let mut renamed_region = async_fixture();
        renamed_region.regions[2].name = "actor.forged-frame".to_owned();
        assert!(renamed_region.validate().is_err());

        let mut overflowing = async_fixture();
        overflowing.functions[2].frame_bound = u64::MAX;
        overflowing.activations[0].frame_bytes = u64::MAX;
        overflowing.regions[2].capacity_bytes = u64::MAX;
        assert!(overflowing.validate().is_err());

        let mut long_name = async_fixture();
        long_name.actors[0].name = "a".repeat(32 * 1024);
        long_name.regions[0].name = format!("{}.mailbox", long_name.actors[0].name);
        long_name.regions[1].name = format!("{}.turn-frame", long_name.actors[0].name);
        let polls = Cell::new(0_u32);
        let cancellation = || {
            let next = polls.get() + 1;
            polls.set(next);
            next > 5
        };
        let mut errors = ValidationContext::new(ValidationLimits::standard(), &cancellation);
        validate_actor_capacity_contract(&long_name, &mut errors);
        assert_eq!(errors.finish(), Err(ValidationFailure::Cancelled));
        assert!(polls.get() > 5);
    }

    #[test]
    fn one_core_scheduler_plan_exactly_partitions_actor_and_task_ownership() {
        let mut module = async_fixture();
        module.schedulers = vec![SchedulerPlan {
            core: 0,
            actors: vec![ActorId(0)],
            tasks: Vec::new(),
        }];
        module
            .clone()
            .validate()
            .expect("exact core-zero ownership");

        let mut wrong_core = module.clone();
        wrong_core.schedulers[0].core = 1;
        assert!(wrong_core.validate().is_err());

        let mut omitted_actor = module.clone();
        omitted_actor.schedulers[0].actors.clear();
        assert!(omitted_actor.validate().is_err());

        let mut duplicated_actor = module;
        duplicated_actor.schedulers[0].actors.push(ActorId(0));
        assert!(duplicated_actor.validate().is_err());
    }

    #[test]
    fn cfg_validation_rejects_non_dominating_ssa_uses() {
        let mut module = fixture();
        let bool_ty = push_scalar_type(&mut module, ScalarType::Bool);
        let integer_ty = push_scalar_type(
            &mut module,
            ScalarType::Integer {
                signed: false,
                bits: 64,
            },
        );
        let function = &mut module.functions[0];
        let condition = push_value(function, bool_ty);
        let branch_value = push_value(function, integer_ty);
        function.result_types = vec![integer_ty];
        function.blocks = vec![
            Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![Instruction {
                    id: InstructionId(0),
                    results: vec![condition],
                    operation: FlowOperation::Immediate(Immediate::Bool(true)),
                    source: None,
                }],
                terminator: Terminator::Branch {
                    condition,
                    then_block: BlockId(1),
                    then_arguments: Vec::new(),
                    else_block: BlockId(2),
                    else_arguments: Vec::new(),
                },
                source: None,
            },
            Block {
                id: BlockId(1),
                parameters: Vec::new(),
                instructions: vec![Instruction {
                    id: InstructionId(1),
                    results: vec![branch_value],
                    operation: FlowOperation::Immediate(Immediate::Integer {
                        bits: 64,
                        bytes_le: vec![0; 8],
                    }),
                    source: None,
                }],
                terminator: Terminator::Jump {
                    target: BlockId(3),
                    arguments: Vec::new(),
                },
                source: None,
            },
            Block {
                id: BlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Jump {
                    target: BlockId(3),
                    arguments: Vec::new(),
                },
                source: None,
            },
            Block {
                id: BlockId(3),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(vec![branch_value]),
                source: None,
            },
        ];

        let mut errors = ValidationContext::new(ValidationLimits::standard(), &|| false);
        validate_control_flow_and_ssa(&module, &module.functions[0], &mut errors);
        assert!(
            errors
                .errors
                .contains(&ValidationError::NonDominatingValueUse {
                    function: FunctionId(0),
                    value: branch_value,
                    block: BlockId(3),
                    instruction: None,
                })
        );
    }

    #[test]
    fn cfg_validation_rejects_parallel_phi_conflicts_and_invalid_switch_values() {
        let mut module = fixture();
        let bool_ty = push_scalar_type(&mut module, ScalarType::Bool);
        let byte_ty = push_scalar_type(
            &mut module,
            ScalarType::Integer {
                signed: false,
                bits: 8,
            },
        );
        let function = &mut module.functions[0];
        let condition = push_value(function, bool_ty);
        let left = push_value(function, byte_ty);
        let right = push_value(function, byte_ty);
        let parameter = push_value(function, byte_ty);
        function.result_types = vec![byte_ty];
        function.blocks[0].instructions = vec![
            Instruction {
                id: InstructionId(0),
                results: vec![condition],
                operation: FlowOperation::Immediate(Immediate::Bool(true)),
                source: None,
            },
            Instruction {
                id: InstructionId(1),
                results: vec![left],
                operation: FlowOperation::Immediate(Immediate::Integer {
                    bits: 8,
                    bytes_le: vec![0],
                }),
                source: None,
            },
            Instruction {
                id: InstructionId(2),
                results: vec![right],
                operation: FlowOperation::Immediate(Immediate::Integer {
                    bits: 8,
                    bytes_le: vec![1],
                }),
                source: None,
            },
        ];
        function.blocks[0].terminator = Terminator::Branch {
            condition,
            then_block: BlockId(1),
            then_arguments: vec![left],
            else_block: BlockId(1),
            else_arguments: vec![right],
        };
        function.blocks.push(Block {
            id: BlockId(1),
            parameters: vec![parameter],
            instructions: Vec::new(),
            terminator: Terminator::Switch {
                value: parameter,
                cases: vec![
                    SwitchCase {
                        value: 256,
                        target: BlockId(2),
                        arguments: Vec::new(),
                    },
                    SwitchCase {
                        value: 256,
                        target: BlockId(2),
                        arguments: Vec::new(),
                    },
                ],
                default: BlockId(2),
                default_arguments: Vec::new(),
            },
            source: None,
        });
        function.blocks.push(Block {
            id: BlockId(2),
            parameters: Vec::new(),
            instructions: Vec::new(),
            terminator: Terminator::Return(vec![parameter]),
            source: None,
        });

        let mut errors = ValidationContext::new(ValidationLimits::standard(), &|| false);
        validate_control_flow_and_ssa(&module, &module.functions[0], &mut errors);
        assert!(
            errors
                .errors
                .contains(&ValidationError::ConflictingParallelEdgeArguments {
                    function: FunctionId(0),
                    from: BlockId(0),
                    to: BlockId(1),
                })
        );
        assert!(
            errors
                .errors
                .contains(&ValidationError::DuplicateSwitchCase {
                    function: FunctionId(0),
                    block: BlockId(1),
                    value: 256,
                })
        );
        assert!(
            errors
                .errors
                .contains(&ValidationError::SwitchCaseOutOfRange {
                    function: FunctionId(0),
                    block: BlockId(1),
                    value: 256,
                    bits: Some(8),
                })
        );
    }
}
