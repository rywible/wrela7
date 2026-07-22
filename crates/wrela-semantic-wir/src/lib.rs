//! Structured, fully specialized whole-image semantic IR.
//!
//! `SemanticWir` is the first IR after successful semantic analysis. It retains
//! language operations whose ordering and failure behavior matter—actors,
//! async, regions, ownership, DMA, cleanup, and supervision—without syntax,
//! unresolved names, generics, interfaces, or target layout.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{BuildIdentity, Sha256Digest};
pub use wrela_source::Span;
pub use wrela_test_model::{
    FullImageTestGroup, FunctionKey, ImageGroupId, ImageRoot, ImageTest, ImageTestInvocation,
    TestDescriptor, TestId as ModelTestId, TestKind as ModelTestKind,
};

pub const SEMANTIC_WIR_VERSION: u32 = 14;
pub const ASSERTION_EXPRESSION_BYTES_MAX: usize = 4096;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(TypeId);
id_type!(FunctionId);
id_type!(ValueId);
id_type!(GlobalId);
id_type!(ActorId);
id_type!(TaskId);
id_type!(DeviceId);
id_type!(PoolId);
id_type!(RegionId);
id_type!(ActivationId);
id_type!(ScopeId);
id_type!(ProofId);
id_type!(TestId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveType {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    F32,
    F64,
    Char,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    Mutate,
    Take,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionColor {
    Sync,
    Async,
    Isr,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Linearity {
    CopyScalar,
    ExplicitCopy,
    Reclaimable,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Primitive(PrimitiveType),
    /// Compiler-minted immutable UTF-8 handle with an authenticated exact
    /// byte extent. This is a semantic identity, not a runtime ABI layout.
    StaticString {
        bytes: u64,
    },
    /// Compiler-minted immutable byte-slice handle with an authenticated exact
    /// decoded extent. This is a semantic identity, not a runtime ABI layout.
    StaticBytes {
        bytes: u64,
    },
    /// Compiler-minted owned result of one bounded interpolation. Capacity is
    /// semantic proof data; no storage layout is implied at this tier.
    BoundedString {
        capacity: u64,
    },
    Tuple(Vec<TypeId>),
    Array {
        element: TypeId,
        length: u64,
    },
    Struct {
        fields: Vec<FieldType>,
    },
    Enum {
        variants: Vec<VariantType>,
    },
    /// Compiler-authenticated `core.actor.AsyncExit[u64]`. Keeping this
    /// distinct from a source-constructible enum prevents a structurally
    /// similar nominal type from acquiring privileged async-outcome authority.
    AsyncExit {
        operation_error: TypeId,
        cancelled: TypeId,
        deadline_rejected: TypeId,
        deadline_exceeded: TypeId,
    },
    /// The ephemeral result produced only by one authenticated fallible await.
    /// `declared_error` records the direct callee's pre-widening error type.
    AsyncOutcome {
        value: TypeId,
        declared_error: TypeId,
        exit: TypeId,
    },
    Function(FunctionType),
    Iso {
        pool: PoolId,
        payload: TypeId,
    },
    ActorHandle {
        actor_type: TypeId,
    },
    /// Strict-linear compiler-created token for one proved mailbox slot.
    Reservation,
    Receipt {
        payload: TypeId,
        error: TypeId,
    },
    DmaPayload {
        pool: PoolId,
        payload: TypeId,
    },
    DmaShared {
        pool: PoolId,
        layout: TypeId,
    },
    Mmio {
        layout: TypeId,
    },
    Validated {
        format: TypeId,
        payload: TypeId,
    },
    OpaqueTarget {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldType {
    pub name: String,
    pub ty: TypeId,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantType {
    pub name: String,
    pub fields: Vec<FieldType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionType {
    pub color: FunctionColor,
    pub parameters: Vec<ParameterType>,
    pub result: TypeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterType {
    pub access: AccessMode,
    pub ty: TypeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRecord {
    pub id: TypeId,
    pub source_name: String,
    pub kind: TypeKind,
    pub linearity: Linearity,
    pub source: Option<Span>,
}

/// Language effects remain explicit until FlowWir proves their lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EffectSet(pub u64);

impl EffectSet {
    pub const ALLOCATE: u64 = 1 << 0;
    pub const SUSPEND: u64 = 1 << 1;
    pub const ACTOR_CALL: u64 = 1 << 2;
    pub const TASK_SPAWN: u64 = 1 << 3;
    pub const MMIO: u64 = 1 << 4;
    pub const DMA: u64 = 1 << 5;
    pub const INTERRUPT: u64 = 1 << 6;
    pub const FIRMWARE: u64 = 1 << 7;
    pub const RECORD_REPLAY: u64 = 1 << 8;
    pub const MAY_FAIL: u64 = 1 << 9;
    pub const DROP_EFFECT: u64 = 1 << 10;
    pub const ALL: u64 = Self::ALLOCATE
        | Self::SUSPEND
        | Self::ACTOR_CALL
        | Self::TASK_SPAWN
        | Self::MMIO
        | Self::DMA
        | Self::INTERRUPT
        | Self::FIRMWARE
        | Self::RECORD_REPLAY
        | Self::MAY_FAIL
        | Self::DROP_EFFECT;

    #[must_use]
    pub const fn contains(self, effect: u64) -> bool {
        self.0 & effect != 0
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 & !Self::ALL == 0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Unit,
    Bool(bool),
    Unsigned { bits: u8, value: u128 },
    Signed { bits: u8, value: i128 },
    Float32(u32),
    Float64(u64),
    Char(char),
    Bytes(Vec<u8>),
    String(String),
    Enum { variant: u32, fields: Vec<Constant> },
    Aggregate(Vec<Constant>),
    Zeroed(TypeId),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticValue {
    pub id: ValueId,
    pub ty: TypeId,
    pub origin: Option<Span>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticMode {
    Checked,
    Wrapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Negate,
    BitNot,
    BoolNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Bounds,
    Arithmetic,
    Conversion,
    Generation,
    Capacity,
    DeviceValue,
    WireValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaState {
    CpuOwned,
    PreparedForDevice,
    DeviceOwned,
    Completed,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOrdering {
    Compiler,
    Acquire,
    Release,
    AcqRel,
    Sequential,
    Device,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SemanticOperation {
    Constant(Constant),
    Unary {
        operator: UnaryOperator,
        operand: ValueId,
        arithmetic: ArithmeticMode,
    },
    Binary {
        operator: BinaryOperator,
        left: ValueId,
        right: ValueId,
        arithmetic: ArithmeticMode,
    },
    Convert {
        value: ValueId,
        destination: TypeId,
        checked: bool,
    },
    Aggregate {
        ty: TypeId,
        fields: Vec<ValueId>,
    },
    /// Construct one compiler-minted bounded string from exact source-order
    /// parts. Flow lowering must choose storage and an ABI before execution.
    FormatBoundedString {
        ty: TypeId,
        parts: Vec<BoundedStringPart>,
    },
    /// Produce a fresh aggregate value by replacing one exact struct field.
    InsertField {
        aggregate: ValueId,
        field: u32,
        value: ValueId,
    },
    /// Construct one closed enum variant from its exact positional payload.
    ConstructEnum {
        ty: TypeId,
        variant: u32,
        /// Present exactly when the selected variant has one payload field.
        payload: Option<ValueId>,
    },
    Project {
        base: ValueId,
        field: u32,
        access: AccessMode,
    },
    /// Load the one canonical actor-owned state cell. The region and capacity
    /// proof authenticate storage independently of the erased receiver value.
    ActorStateLoad {
        actor: ActorId,
        region: RegionId,
        proof: ProofId,
    },
    /// Store the one canonical actor-owned state cell.
    ActorStateStore {
        actor: ActorId,
        region: RegionId,
        value: ValueId,
        proof: ProofId,
    },
    Index {
        base: ValueId,
        index: ValueId,
        proof: ProofId,
    },
    BeginAccess {
        place: ValueId,
        access: AccessMode,
        region: RegionId,
    },
    EndAccess {
        value: ValueId,
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
        arguments: Vec<Argument>,
        /// Exact static activation plan for an asynchronous call. Synchronous
        /// calls carry `None`; asynchronous calls must carry `Some` and are
        /// independently cross-checked against the containing function and
        /// source location.
        activation: Option<ActivationId>,
    },
    /// Materialize one immutable image-wired actor capability. The proof binds
    /// the capability to the exact installed target; source code cannot store
    /// or return this compiler-created value.
    ActorCapability {
        actor: ActorId,
        wiring_proof: ProofId,
    },
    ActorReserve {
        actor: ActorId,
        method: FunctionId,
        permit_proof: ProofId,
    },
    ActorCommit {
        reservation: ValueId,
        arguments: Vec<Argument>,
    },
    /// Execute the exact single-flight same-core request protocol and produce
    /// its typed u64 outcome. The reply proof authenticates one caller/callee
    /// pair and one finite reply slot; broader payloads and concurrency stay
    /// fail-closed in lowering.
    ActorReplyRequest {
        actor: ActorId,
        method: FunctionId,
        permit_proof: ProofId,
        reply_proof: ProofId,
    },
    /// Resolve the sole reply from the actor turn before its normal return.
    /// The backend may fuse this with the direct same-core caller transition,
    /// but must preserve exactly-once state ordering.
    ActorReplyResolve {
        outcome: ValueId,
        reply_proof: ProofId,
    },
    /// Dequeue the next message for an actor turn. Unit messages produce no
    /// value; the concrete method identity prevents dispatch substitution.
    MailboxReceive {
        actor: ActorId,
        method: FunctionId,
    },
    ActorSend {
        message: ValueId,
    },
    ActorTrySend {
        message: ValueId,
    },
    Await {
        awaitable: ValueId,
    },
    /// Await one direct non-actor `Result[u64,u64]` activation and widen its
    /// error to the authenticated `AsyncExit[u64]` taxonomy.
    AwaitAsyncOutcome {
        awaitable: ValueId,
        exit: TypeId,
        proof: ProofId,
    },
    SpawnTask {
        task: TaskId,
        arguments: Vec<Argument>,
        slot_proof: ProofId,
    },
    Cancel {
        target: ValueId,
    },
    Checkpoint {
        budget_proof: ProofId,
    },
    Select {
        awaitables: Vec<ValueId>,
    },
    Race {
        awaitables: Vec<ValueId>,
    },
    Allocate {
        region: RegionId,
        ty: TypeId,
        count: ValueId,
        capacity_proof: ProofId,
    },
    ResetRegion {
        region: RegionId,
    },
    Promote {
        value: ValueId,
        destination: RegionId,
        proof: ProofId,
    },
    EnterScope {
        scope: ScopeId,
        state: ValueId,
    },
    CommitScope {
        scope: ScopeId,
        value: ValueId,
    },
    AbortScope {
        scope: ScopeId,
        error: Option<ValueId>,
    },
    ExitScope {
        scope: ScopeId,
    },
    DmaTransition {
        value: ValueId,
        from: DmaState,
        to: DmaState,
        device: DeviceId,
        proof: ProofId,
    },
    MmioRead {
        device: DeviceId,
        register: u32,
        ordering: MemoryOrdering,
    },
    MmioWrite {
        device: DeviceId,
        register: u32,
        value: ValueId,
        ordering: MemoryOrdering,
    },
    InterruptPublish {
        device: DeviceId,
        value: ValueId,
        ordering: MemoryOrdering,
    },
    QueueReserve {
        device: DeviceId,
        descriptors: ValueId,
        proof: ProofId,
    },
    QueuePublish {
        reservation: ValueId,
        payloads: Vec<ValueId>,
    },
    Check {
        kind: CheckKind,
        condition: ValueId,
        proof: Option<ProofId>,
    },
    /// Fail the active selected test if `condition` is false. The descriptor
    /// is exact declared-source provenance and is never user-supplied wire.
    Assert {
        condition: ValueId,
        failure: AssertionFailureDescriptor,
    },
    RecordEvent {
        kind: u32,
        payload: ValueId,
    },
    TestEmit {
        payload: ValueId,
    },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argument {
    pub access: AccessMode,
    pub value: ValueId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LetStatement {
    pub results: Vec<ValueId>,
    pub operation: SemanticOperation,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SemanticStatement {
    Let(LetStatement),
    If {
        condition: ValueId,
        then_region: SemanticRegion,
        else_region: SemanticRegion,
        results: Vec<ValueId>,
        source: Option<Span>,
    },
    Match {
        scrutinee: ValueId,
        arms: Vec<SemanticMatchArm>,
        results: Vec<ValueId>,
        source: Option<Span>,
    },
    Loop {
        body: SemanticRegion,
        carried: Vec<ValueId>,
        uninterrupted_bound: Option<u64>,
        source: Option<Span>,
    },
    Return(Vec<ValueId>),
    Yield(Vec<ValueId>),
    Break(Vec<ValueId>),
    Continue(Vec<ValueId>),
    Unreachable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticMatchArm {
    pub variant: Option<u32>,
    pub bindings: Vec<ValueId>,
    pub guard: Option<ValueId>,
    pub body: SemanticRegion,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SemanticRegion {
    pub parameters: Vec<ValueId>,
    pub statements: Vec<SemanticStatement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionOrigin {
    Source,
    /// Runtime entry synthesized from the declared source `@image` comptime
    /// constructor. The constructor declaration is provenance only and is not
    /// emitted as runtime code.
    GeneratedImageEntry {
        constructor: u32,
    },
    GeneratedTestHarness {
        group: u32,
    },
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

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticFunction {
    pub id: FunctionId,
    /// Stable monomorphized-instance identity assigned by semantic analysis.
    pub instance_key: Sha256Digest,
    pub name: String,
    pub origin: FunctionOrigin,
    pub role: FunctionRole,
    pub color: FunctionColor,
    pub parameters: Vec<ValueId>,
    pub result: TypeId,
    pub values: Vec<SemanticValue>,
    pub body: SemanticRegion,
    pub effects: EffectSet,
    /// Proofs attached to this exact function instance by semantic analysis.
    pub proofs: Vec<ProofId>,
    pub source: Option<Span>,
    pub stack_bound: u64,
    pub frame_bound: u64,
    pub uninterrupted_bound: Option<u64>,
    pub recursive_depth_bound: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Global {
    pub id: GlobalId,
    pub name: String,
    pub ty: TypeId,
    pub initializer: Constant,
    pub owner: ImageOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ImageOwner {
    Runtime,
    Actor(ActorId),
    Task(TaskId),
    Device(DeviceId),
    Pool(PoolId),
    BakedArtifact(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorInstance {
    pub id: ActorId,
    pub name: String,
    pub ty: TypeId,
    pub priority: u8,
    pub mailbox_capacity: u32,
    pub message_types: Vec<TypeId>,
    pub turn_functions: Vec<FunctionId>,
    pub supervisor: Option<ActorId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInstance {
    pub id: TaskId,
    pub name: String,
    pub entry: FunctionId,
    pub slots: u32,
    pub priority: u8,
    pub supervisor: Option<ActorId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInstance {
    pub id: DeviceId,
    pub name: String,
    pub target_binding: String,
    pub owner: ActorId,
    pub required_features: Vec<String>,
    pub optional_features: Vec<String>,
    pub interrupt_functions: Vec<FunctionId>,
    pub queue_capacity: Option<u32>,
    pub maximum_in_flight: Option<u32>,
    pub reset_timeout_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolInstance {
    pub id: PoolId,
    pub name: String,
    pub payload: TypeId,
    pub capacity: u64,
    pub alignment: u64,
    pub reachable_devices: Vec<DeviceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionRecord {
    pub id: RegionId,
    pub name: String,
    pub class: RegionClass,
    pub capacity_bytes: u64,
    pub alignment: u64,
    pub owner: ImageOwner,
    pub proof: ProofId,
    pub source: Span,
}

/// Cancellation behavior proved for one statically admitted async call site.
///
/// The current actor slice supports only immediate awaits of scalar helpers,
/// so cancellation destroys the complete callee frame before propagating to
/// the retained caller activation. More dispositions require a schema bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCancellation {
    DropCalleeThenPropagate,
}

/// Exact, source-aware storage admission for one asynchronous call site.
/// Every record owns one activation-linked `RegionClass::TaskFrame` region and
/// one capacity proof. `RegionClass::Call` remains reserved for synchronous
/// temporaries that cannot survive suspension.
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

/// Lowered contract for one `with` activation site. Helper functions contain
/// the specialized non-suspending abort/exit bodies. Dependencies form the
/// proved cleanup DAG used by Flow lowering during every abnormal exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePlan {
    pub id: ScopeId,
    pub name: String,
    pub state_type: TypeId,
    pub abort: Option<FunctionId>,
    pub exit: FunctionId,
    pub suspend_safe: bool,
    pub dependencies: Vec<ScopeId>,
    pub reverse_source_order: u32,
    pub cleanup_proof: ProofId,
    pub source: Span,
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
    AsyncOutcomeAuthenticated,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRecord {
    pub id: ProofId,
    pub kind: ProofKind,
    pub subject: String,
    pub bound: Option<u64>,
    /// Every source location retained by semantic analysis, in its original
    /// canonical order. Proofs may span declarations or files and must not be
    /// collapsed to an arbitrary representative location.
    pub sources: Vec<Span>,
    pub depends_on: Vec<ProofId>,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestEntry {
    pub id: TestId,
    /// Global ID assigned by the sealed test plan and emitted by the guest
    /// protocol. `id` remains the dense image-local table identity.
    pub plan_id: u32,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSummary {
    /// Dense HIR arena bounds retained so source provenance can be validated
    /// without treating a reachability count as a declaration ID bound.
    pub hir_files: u32,
    pub hir_declarations: u32,
    /// Number of distinct HIR declaration IDs retained by the closed runtime
    /// semantic model, including image-constructor provenance and every source
    /// function, scope, type, and brand origin. This is provenance reachability,
    /// not an inferred source call-graph metric.
    pub reachable_declarations: u64,
    pub monomorphized_instantiations: u64,
    pub resolved_interface_calls: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticWir {
    pub version: u32,
    pub name: String,
    pub build: BuildIdentity,
    pub source_summary: SourceSummary,
    pub types: Vec<TypeRecord>,
    pub globals: Vec<Global>,
    pub functions: Vec<SemanticFunction>,
    pub actors: Vec<ActorInstance>,
    pub tasks: Vec<TaskInstance>,
    pub devices: Vec<DeviceInstance>,
    pub pools: Vec<PoolInstance>,
    pub regions: Vec<RegionRecord>,
    pub activations: Vec<ActivationPlan>,
    pub scopes: Vec<ScopePlan>,
    pub proofs: Vec<ProofRecord>,
    pub tests: Vec<TestEntry>,
    /// Exact group selected from the sealed test plan for this compilation.
    /// This is `None` for ordinary image builds and preserves the complete
    /// plan-scoped identity for both generated and declared test images.
    pub compiled_test_group: Option<FullImageTestGroup>,
    pub startup_order: Vec<ImageOwner>,
    pub shutdown_order: Vec<ImageOwner>,
    pub image_entry: FunctionId,
    pub static_bytes: u64,
    pub peak_bytes: u64,
}

/// Finite policy for independently validating an untrusted SemanticWir model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum records in any one dense arena.
    pub arena_records: u64,
    /// Maximum aggregate vector elements and recursively visited model nodes.
    pub model_edges: u64,
    /// Maximum aggregate retained UTF-8 and byte-string payload.
    pub payload_bytes: u64,
    /// Conservative upper bound for validation work.
    pub validation_work: u64,
    /// Maximum constant and structured-region nesting.
    pub nesting: u32,
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
            nesting: 1024,
            errors: 100_000,
        }
    }

    fn is_valid(self) -> bool {
        self.arena_records > 0
            && self.arena_records <= u64::from(u32::MAX)
            && self.model_edges > 0
            && self.payload_bytes > 0
            && self.validation_work > 0
            && self.nesting > 0
            && self.nesting <= 1024
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

impl SemanticWir {
    pub fn validate(self) -> Result<ValidatedSemanticWir, ValidationErrors> {
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
    ) -> Result<ValidatedSemanticWir, ValidationFailure> {
        if !limits.is_valid() {
            return Err(ValidationFailure::InvalidLimits);
        }
        validate_model_resources(&self, limits, is_cancelled)?;
        let errors = validate_module(&self, limits.errors, is_cancelled)?;
        if errors.is_empty() {
            Ok(ValidatedSemanticWir(self))
        } else {
            Err(ValidationFailure::Invalid(ValidationErrors(errors)))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedSemanticWir(SemanticWir);

impl ValidatedSemanticWir {
    #[must_use]
    pub fn as_wir(&self) -> &SemanticWir {
        &self.0
    }

    #[must_use]
    pub fn into_wir(self) -> SemanticWir {
        self.0
    }
}

struct ResourceMeter<'a> {
    limits: ValidationLimits,
    edges: u64,
    payload_bytes: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> ResourceMeter<'a> {
    fn new(limits: ValidationLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
            edges: 0,
            payload_bytes: 0,
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
        self.poll()?;
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource,
            limit: self.limits.arena_records,
        })?;
        if length > self.limits.arena_records {
            return Err(ValidationFailure::ResourceLimit {
                resource,
                limit: self.limits.arena_records,
            });
        }
        self.edges(length)
    }

    fn edge_slice<T>(&mut self, values: &[T]) -> Result<(), ValidationFailure> {
        let length = u64::try_from(values.len()).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "model edges",
            limit: self.limits.model_edges,
        })?;
        self.edges(length)
    }

    fn edges(&mut self, amount: u64) -> Result<(), ValidationFailure> {
        self.poll()?;
        self.edges = self
            .edges
            .checked_add(amount)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            })?;
        if self.edges > self.limits.model_edges {
            return Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            });
        }
        Ok(())
    }

    fn payload(&mut self, length: usize) -> Result<(), ValidationFailure> {
        self.poll()?;
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "payload bytes",
            limit: self.limits.payload_bytes,
        })?;
        self.payload_bytes =
            self.payload_bytes
                .checked_add(length)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "payload bytes",
                    limit: self.limits.payload_bytes,
                })?;
        if self.payload_bytes > self.limits.payload_bytes {
            return Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: self.limits.payload_bytes,
            });
        }
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), ValidationFailure> {
        self.payload(value.len())
    }

    fn depth(&self, depth: u32) -> Result<(), ValidationFailure> {
        self.poll()?;
        if depth > self.limits.nesting {
            Err(ValidationFailure::ResourceLimit {
                resource: "model nesting",
                limit: u64::from(self.limits.nesting),
            })
        } else {
            Ok(())
        }
    }

    fn finish(&self) -> Result<(), ValidationFailure> {
        self.poll()?;
        let multiplier = u64::from(self.limits.nesting).checked_add(64).ok_or(
            ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            },
        )?;
        let work = self
            .edges
            .checked_mul(multiplier)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })?;
        if work > self.limits.validation_work {
            Err(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })
        } else {
            Ok(())
        }
    }
}

fn try_push_scratch<T>(values: &mut Vec<T>, value: T, limit: u64) -> Result<(), ValidationFailure> {
    if u64::try_from(values.len()).map_or(true, |length| length >= limit) {
        return Err(ValidationFailure::ResourceLimit {
            resource: "validation scratch entries",
            limit,
        });
    }
    values
        .try_reserve(1)
        .map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation scratch entries",
            limit,
        })?;
    values.push(value);
    Ok(())
}

fn validate_model_resources(
    module: &SemanticWir,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ValidationFailure> {
    let mut meter = ResourceMeter::new(limits, is_cancelled);
    meter.text(&module.name)?;
    meter.arena("types", module.types.len())?;
    meter.arena("globals", module.globals.len())?;
    meter.arena("functions", module.functions.len())?;
    meter.arena("actors", module.actors.len())?;
    meter.arena("tasks", module.tasks.len())?;
    meter.arena("devices", module.devices.len())?;
    meter.arena("pools", module.pools.len())?;
    meter.arena("regions", module.regions.len())?;
    meter.arena("activations", module.activations.len())?;
    meter.arena("scopes", module.scopes.len())?;
    meter.arena("proofs", module.proofs.len())?;
    meter.arena("tests", module.tests.len())?;
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
            meter.text(&test.descriptor.name)?;
        }
    }
    meter.edge_slice(&module.startup_order)?;
    meter.edge_slice(&module.shutdown_order)?;

    for ty in &module.types {
        meter.poll()?;
        meter.text(&ty.source_name)?;
        match &ty.kind {
            TypeKind::Tuple(items) => meter.edge_slice(items)?,
            TypeKind::Struct { fields } => {
                meter.edge_slice(fields)?;
                for field in fields {
                    meter.text(&field.name)?;
                }
            }
            TypeKind::Enum { variants } => {
                meter.edge_slice(variants)?;
                for variant in variants {
                    meter.text(&variant.name)?;
                    meter.edge_slice(&variant.fields)?;
                    for field in &variant.fields {
                        meter.text(&field.name)?;
                    }
                }
            }
            TypeKind::Function(function) => meter.edge_slice(&function.parameters)?,
            TypeKind::OpaqueTarget { name } => meter.text(name)?,
            TypeKind::Primitive(_)
            | TypeKind::StaticString { .. }
            | TypeKind::StaticBytes { .. }
            | TypeKind::BoundedString { .. }
            | TypeKind::AsyncExit { .. }
            | TypeKind::AsyncOutcome { .. }
            | TypeKind::Array { .. }
            | TypeKind::Iso { .. }
            | TypeKind::ActorHandle { .. }
            | TypeKind::Reservation
            | TypeKind::Receipt { .. }
            | TypeKind::DmaPayload { .. }
            | TypeKind::DmaShared { .. }
            | TypeKind::Mmio { .. }
            | TypeKind::Validated { .. } => {}
        }
    }

    let mut constants = Vec::new();
    for global in &module.globals {
        meter.poll()?;
        meter.text(&global.name)?;
        try_push_scratch(
            &mut constants,
            (&global.initializer, 1_u32),
            limits.model_edges,
        )?;
    }
    for function in &module.functions {
        meter.poll()?;
        meter.text(&function.name)?;
        meter.edge_slice(&function.parameters)?;
        meter.arena("function values", function.values.len())?;
        meter.edge_slice(&function.proofs)?;
        for value in &function.values {
            meter.poll()?;
            if let Some(name) = &value.name {
                meter.text(name)?;
            }
        }
        let mut regions = Vec::new();
        try_push_scratch(&mut regions, (&function.body, 1_u32), limits.model_edges)?;
        while let Some((region, depth)) = regions.pop() {
            meter.depth(depth)?;
            meter.edges(1)?;
            meter.edge_slice(&region.parameters)?;
            meter.edge_slice(&region.statements)?;
            for statement in &region.statements {
                meter.poll()?;
                match statement {
                    SemanticStatement::Let(statement) => {
                        meter.edge_slice(&statement.results)?;
                        match &statement.operation {
                            SemanticOperation::Constant(value) => try_push_scratch(
                                &mut constants,
                                (value, 1_u32),
                                limits.model_edges,
                            )?,
                            SemanticOperation::Aggregate { fields, .. } => {
                                meter.edge_slice(fields)?
                            }
                            SemanticOperation::FormatBoundedString { parts, .. } => {
                                meter.edge_slice(parts)?;
                                for part in parts {
                                    if let BoundedStringPart::Text { value, .. } = part {
                                        meter.text(value)?;
                                    }
                                }
                            }
                            SemanticOperation::ConstructEnum { .. } => {}
                            SemanticOperation::Call { arguments, .. }
                            | SemanticOperation::ActorCommit { arguments, .. }
                            | SemanticOperation::SpawnTask { arguments, .. } => {
                                meter.edge_slice(arguments)?
                            }
                            SemanticOperation::Select { awaitables }
                            | SemanticOperation::Race { awaitables }
                            | SemanticOperation::QueuePublish {
                                payloads: awaitables,
                                ..
                            } => meter.edge_slice(awaitables)?,
                            SemanticOperation::Unary { .. }
                            | SemanticOperation::Binary { .. }
                            | SemanticOperation::Convert { .. }
                            | SemanticOperation::InsertField { .. }
                            | SemanticOperation::Project { .. }
                            | SemanticOperation::ActorStateLoad { .. }
                            | SemanticOperation::ActorStateStore { .. }
                            | SemanticOperation::Index { .. }
                            | SemanticOperation::BeginAccess { .. }
                            | SemanticOperation::EndAccess { .. }
                            | SemanticOperation::Move { .. }
                            | SemanticOperation::Copy { .. }
                            | SemanticOperation::Drop { .. }
                            | SemanticOperation::ActorCapability { .. }
                            | SemanticOperation::ActorReserve { .. }
                            | SemanticOperation::ActorReplyRequest { .. }
                            | SemanticOperation::ActorReplyResolve { .. }
                            | SemanticOperation::MailboxReceive { .. }
                            | SemanticOperation::ActorSend { .. }
                            | SemanticOperation::ActorTrySend { .. }
                            | SemanticOperation::Await { .. }
                            | SemanticOperation::AwaitAsyncOutcome { .. }
                            | SemanticOperation::Cancel { .. }
                            | SemanticOperation::Checkpoint { .. }
                            | SemanticOperation::Allocate { .. }
                            | SemanticOperation::ResetRegion { .. }
                            | SemanticOperation::Promote { .. }
                            | SemanticOperation::EnterScope { .. }
                            | SemanticOperation::CommitScope { .. }
                            | SemanticOperation::AbortScope { .. }
                            | SemanticOperation::ExitScope { .. }
                            | SemanticOperation::DmaTransition { .. }
                            | SemanticOperation::MmioRead { .. }
                            | SemanticOperation::MmioWrite { .. }
                            | SemanticOperation::InterruptPublish { .. }
                            | SemanticOperation::QueueReserve { .. }
                            | SemanticOperation::Check { .. }
                            | SemanticOperation::RecordEvent { .. }
                            | SemanticOperation::TestEmit { .. }
                            | SemanticOperation::TestFinish { .. } => {}
                            SemanticOperation::Assert { failure, .. } => {
                                meter.text(&failure.expression)?;
                                if let Some(message) = &failure.message {
                                    meter.text(message)?;
                                }
                            }
                        }
                    }
                    SemanticStatement::If {
                        then_region,
                        else_region,
                        results,
                        ..
                    } => {
                        meter.edge_slice(results)?;
                        let next =
                            depth
                                .checked_add(1)
                                .ok_or(ValidationFailure::ResourceLimit {
                                    resource: "model nesting",
                                    limit: u64::from(limits.nesting),
                                })?;
                        try_push_scratch(&mut regions, (then_region, next), limits.model_edges)?;
                        try_push_scratch(&mut regions, (else_region, next), limits.model_edges)?;
                    }
                    SemanticStatement::Match { arms, results, .. } => {
                        meter.edge_slice(arms)?;
                        meter.edge_slice(results)?;
                        let next =
                            depth
                                .checked_add(1)
                                .ok_or(ValidationFailure::ResourceLimit {
                                    resource: "model nesting",
                                    limit: u64::from(limits.nesting),
                                })?;
                        for arm in arms {
                            meter.edge_slice(&arm.bindings)?;
                            try_push_scratch(&mut regions, (&arm.body, next), limits.model_edges)?;
                        }
                    }
                    SemanticStatement::Loop { body, carried, .. } => {
                        meter.edge_slice(carried)?;
                        let next =
                            depth
                                .checked_add(1)
                                .ok_or(ValidationFailure::ResourceLimit {
                                    resource: "model nesting",
                                    limit: u64::from(limits.nesting),
                                })?;
                        try_push_scratch(&mut regions, (body, next), limits.model_edges)?;
                    }
                    SemanticStatement::Return(values)
                    | SemanticStatement::Yield(values)
                    | SemanticStatement::Break(values)
                    | SemanticStatement::Continue(values) => meter.edge_slice(values)?,
                    SemanticStatement::Unreachable => {}
                }
            }
        }
    }

    while let Some((constant, depth)) = constants.pop() {
        meter.depth(depth)?;
        meter.edges(1)?;
        match constant {
            Constant::Bytes(bytes) => meter.payload(bytes.len())?,
            Constant::String(value) => meter.text(value)?,
            Constant::Enum { fields, .. } | Constant::Aggregate(fields) => {
                meter.edge_slice(fields)?;
                let next = depth
                    .checked_add(1)
                    .ok_or(ValidationFailure::ResourceLimit {
                        resource: "model nesting",
                        limit: u64::from(limits.nesting),
                    })?;
                for field in fields {
                    try_push_scratch(&mut constants, (field, next), limits.model_edges)?;
                }
            }
            Constant::Unit
            | Constant::Bool(_)
            | Constant::Unsigned { .. }
            | Constant::Signed { .. }
            | Constant::Float32(_)
            | Constant::Float64(_)
            | Constant::Char(_)
            | Constant::Zeroed(_) => {}
        }
    }

    for actor in &module.actors {
        meter.text(&actor.name)?;
        meter.edge_slice(&actor.message_types)?;
        meter.edge_slice(&actor.turn_functions)?;
    }
    for task in &module.tasks {
        meter.text(&task.name)?;
    }
    for device in &module.devices {
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
            meter.text(feature)?;
        }
    }
    for pool in &module.pools {
        meter.text(&pool.name)?;
        meter.edge_slice(&pool.reachable_devices)?;
    }
    for region in &module.regions {
        meter.text(&region.name)?;
    }
    for _activation in &module.activations {
        meter.poll()?;
    }
    for scope in &module.scopes {
        meter.text(&scope.name)?;
        meter.edge_slice(&scope.dependencies)?;
    }
    for proof in &module.proofs {
        meter.text(&proof.subject)?;
        meter.edge_slice(&proof.sources)?;
        meter.edge_slice(&proof.depends_on)?;
        meter.edge_slice(&proof.explanation)?;
        for line in &proof.explanation {
            meter.text(line)?;
        }
    }
    for test in &module.tests {
        meter.text(&test.name)?;
    }
    meter.finish()
}

struct ValidationErrorSink<'a> {
    errors: Vec<ValidationError>,
    limit: u32,
    truncated: bool,
    allocation_failed: bool,
    is_cancelled: &'a dyn Fn() -> bool,
    cancelled: bool,
}

impl<'a> ValidationErrorSink<'a> {
    fn new(limit: u32, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            errors: Vec::new(),
            limit,
            truncated: false,
            allocation_failed: false,
            is_cancelled,
            cancelled: false,
        }
    }

    fn poll(&mut self) -> bool {
        if !self.cancelled && (self.is_cancelled)() {
            self.cancelled = true;
        }
        self.cancelled
    }

    fn push(&mut self, error: ValidationError) {
        if self.poll() {
            return;
        }
        if self.errors.len() >= self.limit as usize {
            self.truncated = true;
            return;
        }
        if self.errors.try_reserve(1).is_err() {
            self.allocation_failed = true;
            return;
        }
        self.errors.push(error);
    }

    fn scratch_allocation_failed(&mut self) {
        self.allocation_failed = true;
    }

    fn finish(mut self) -> Result<Vec<ValidationError>, ValidationFailure> {
        if self.cancelled || (self.is_cancelled)() {
            return Err(ValidationFailure::Cancelled);
        }
        if self.allocation_failed {
            return Err(ValidationFailure::ResourceLimit {
                resource: "validation scratch memory",
                limit: self.limit.into(),
            });
        }
        if self.truncated {
            let marker = ValidationError::TooManyErrors { limit: self.limit };
            if let Some(last) = self.errors.last_mut() {
                *last = marker;
            } else if self.errors.try_reserve(1).is_ok() {
                self.errors.push(marker);
            } else {
                return Err(ValidationFailure::ResourceLimit {
                    resource: "validation error storage",
                    limit: self.limit.into(),
                });
            }
        }
        Ok(self.errors)
    }
}

fn sort_validation_scratch<T: Copy + Ord>(
    values: &mut [T],
    errors: &mut ValidationErrorSink<'_>,
) -> bool {
    let Some(first) = values.first().copied() else {
        return !errors.poll();
    };
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(values.len()).is_err() {
        errors.scratch_allocation_failed();
        return false;
    }
    buffer.resize(values.len(), first);
    let mut width = 1_usize;
    let mut source_is_values = true;
    while width < values.len() {
        let completed = if source_is_values {
            merge_validation_sort_pass(values, &mut buffer, width, errors)
        } else {
            merge_validation_sort_pass(&buffer, values, width, errors)
        };
        if !completed {
            return false;
        }
        source_is_values = !source_is_values;
        width = match width.checked_mul(2) {
            Some(next) => next,
            None => values.len(),
        };
    }
    if !source_is_values {
        for (destination, source) in values.iter_mut().zip(buffer) {
            if errors.poll() {
                return false;
            }
            *destination = source;
        }
    }
    true
}

fn merge_validation_sort_pass<T: Copy + Ord>(
    source: &[T],
    destination: &mut [T],
    width: usize,
    errors: &mut ValidationErrorSink<'_>,
) -> bool {
    let mut start = 0_usize;
    while start < source.len() {
        let middle = match start.checked_add(width) {
            Some(value) => value.min(source.len()),
            None => source.len(),
        };
        let end = match middle.checked_add(width) {
            Some(value) => value.min(source.len()),
            None => source.len(),
        };
        let (mut left, mut right) = (start, middle);
        for output in &mut destination[start..end] {
            if errors.poll() {
                return false;
            }
            let take_left = right >= end || left < middle && source[left] <= source[right];
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
    module: &SemanticWir,
    error_limit: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ValidationError>, ValidationFailure> {
    let mut errors = ValidationErrorSink::new(error_limit, is_cancelled);
    if module.version != SEMANTIC_WIR_VERSION {
        errors.push(ValidationError::UnsupportedVersion(module.version));
    }
    if module.name.trim().is_empty() {
        errors.push(ValidationError::MissingImageName);
    }
    check_dense(
        "type",
        module.types.iter().map(|item| item.id.0),
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
        "actor",
        module.actors.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "task",
        module.tasks.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "device",
        module.devices.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "pool",
        module.pools.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "region",
        module.regions.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "activation",
        module.activations.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "scope",
        module.scopes.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "proof",
        module.proofs.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "test",
        module.tests.iter().map(|item| item.id.0),
        &mut errors,
    );

    for ty in &module.types {
        if errors.poll() {
            break;
        }
        validate_type(module, ty, &mut errors);
    }
    for global in &module.globals {
        if errors.poll() {
            break;
        }
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        validate_constant(module, &global.initializer, &mut errors);
        validate_owner(module, global.owner, &mut errors);
    }
    let mut instance_keys = Vec::new();
    if instance_keys
        .try_reserve_exact(module.functions.len())
        .is_err()
    {
        errors.scratch_allocation_failed();
    } else {
        for function in &module.functions {
            if errors.poll() {
                break;
            }
            instance_keys.push((function.instance_key, function.id));
        }
        if sort_validation_scratch(&mut instance_keys, &mut errors) {
            let mut prior = None;
            for (key, function) in &instance_keys {
                if errors.poll() {
                    break;
                }
                if prior == Some(*key) {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "function instance key",
                        id: function.0,
                    });
                }
                prior = Some(*key);
            }
        }
    }
    for function in &module.functions {
        if errors.poll() {
            break;
        }
        validate_function(module, function, &mut errors);
    }
    for actor in &module.actors {
        if errors.poll() {
            break;
        }
        require_id("actor type", actor.ty.0, module.types.len(), &mut errors);
        for ty in &actor.message_types {
            require_id("actor message type", ty.0, module.types.len(), &mut errors);
        }
        require_canonical_ids(
            "actor message types",
            actor.id.0,
            actor.message_types.iter().map(|id| id.0),
            &mut errors,
        );
        for function in &actor.turn_functions {
            require_id(
                "actor turn function",
                function.0,
                module.functions.len(),
                &mut errors,
            );
            if module
                .functions
                .get(function.0 as usize)
                .is_some_and(|function| function.role != FunctionRole::ActorTurn(actor.id))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor turn role",
                    id: actor.id.0,
                });
            }
        }
        require_canonical_ids(
            "actor turn functions",
            actor.id.0,
            actor.turn_functions.iter().map(|id| id.0),
            &mut errors,
        );
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
        if errors.poll() {
            break;
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
        if errors.poll() {
            break;
        }
        if device.name.trim().is_empty()
            || device.target_binding.trim().is_empty()
            || device.reset_timeout_ns == 0
            || device.queue_capacity == Some(0)
            || device.maximum_in_flight == Some(0)
            || device.interrupt_functions.len() > 1
            || matches!(
                (device.maximum_in_flight, device.queue_capacity),
                (Some(in_flight), Some(queue)) if in_flight > queue
            )
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
            require_id(
                "device interrupt function",
                function.0,
                module.functions.len(),
                &mut errors,
            );
            if module
                .functions
                .get(function.0 as usize)
                .is_some_and(|function| function.role != FunctionRole::Isr(device.id))
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "device interrupt role",
                    id: device.id.0,
                });
            }
        }
        require_canonical_ids(
            "device interrupt functions",
            device.id.0,
            device.interrupt_functions.iter().map(|id| id.0),
            &mut errors,
        );
    }
    for function in &module.functions {
        if errors.poll() {
            break;
        }
        let listed = match function.role {
            FunctionRole::ActorTurn(actor) => module
                .actors
                .get(actor.0 as usize)
                .is_some_and(|record| record.turn_functions.binary_search(&function.id).is_ok()),
            FunctionRole::Isr(device) => {
                module.devices.get(device.0 as usize).is_some_and(|record| {
                    record
                        .interrupt_functions
                        .binary_search(&function.id)
                        .is_ok()
                })
            }
            FunctionRole::TaskEntry(task) => module
                .tasks
                .get(task.0 as usize)
                .is_some_and(|record| record.entry == function.id),
            FunctionRole::Ordinary
            | FunctionRole::Cleanup
            | FunctionRole::ImageEntry
            | FunctionRole::Test => true,
        };
        if !listed {
            errors.push(ValidationError::InvalidRecord {
                kind: "function role graph relation",
                id: function.id.0,
            });
        }
    }
    for pool in &module.pools {
        if errors.poll() {
            break;
        }
        require_id(
            "pool payload",
            pool.payload.0,
            module.types.len(),
            &mut errors,
        );
        for device in &pool.reachable_devices {
            require_id("pool device", device.0, module.devices.len(), &mut errors);
        }
        require_canonical_ids(
            "pool devices",
            pool.id.0,
            pool.reachable_devices.iter().map(|id| id.0),
            &mut errors,
        );
    }
    for region in &module.regions {
        if errors.poll() {
            break;
        }
        validate_owner(module, region.owner, &mut errors);
        require_id(
            "region proof",
            region.proof.0,
            module.proofs.len(),
            &mut errors,
        );
        if region.name.trim().is_empty()
            || region.capacity_bytes == 0
            || !region.alignment.is_power_of_two()
            || !valid_span(module, region.source)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "region",
                id: region.id.0,
            });
        }
        if let RegionClass::Pool(pool) = region.class {
            require_id("region pool", pool.0, module.pools.len(), &mut errors);
        }
    }
    validate_activation_plans(module, &mut errors);
    validate_actor_capacity_contract(module, &mut errors);
    validate_static_supervision_contract(module, &mut errors);
    for scope in &module.scopes {
        if errors.poll() {
            break;
        }
        require_id(
            "scope state type",
            scope.state_type.0,
            module.types.len(),
            &mut errors,
        );
        if let Some(abort) = scope.abort {
            require_id(
                "scope abort function",
                abort.0,
                module.functions.len(),
                &mut errors,
            );
            if module
                .functions
                .get(abort.0 as usize)
                .is_some_and(|function| function.role != FunctionRole::Cleanup)
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "scope abort role",
                    id: scope.id.0,
                });
            }
        }
        require_id(
            "scope exit function",
            scope.exit.0,
            module.functions.len(),
            &mut errors,
        );
        if module
            .functions
            .get(scope.exit.0 as usize)
            .is_some_and(|function| function.role != FunctionRole::Cleanup)
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "scope exit role",
                id: scope.id.0,
            });
        }
        require_id(
            "scope cleanup proof",
            scope.cleanup_proof.0,
            module.proofs.len(),
            &mut errors,
        );
        for dependency in &scope.dependencies {
            require_id(
                "scope dependency",
                dependency.0,
                module.scopes.len(),
                &mut errors,
            );
        }
        require_canonical_ids(
            "scope dependencies",
            scope.id.0,
            scope.dependencies.iter().map(|id| id.0),
            &mut errors,
        );
        if !valid_span(module, scope.source) {
            errors.push(ValidationError::InvalidRecord {
                kind: "scope source",
                id: scope.id.0,
            });
        }
    }
    validate_acyclic(
        "scope dependency",
        module.scopes.len(),
        |index| module.scopes[index].dependencies.as_slice(),
        |id| id.0,
        &mut errors,
    );
    for proof in &module.proofs {
        if errors.poll() {
            break;
        }
        let mut invalid = proof.subject.trim().is_empty() || proof.explanation.is_empty();
        for line in &proof.explanation {
            if errors.poll() {
                break;
            }
            invalid |= line.trim().is_empty();
        }
        for source in &proof.sources {
            if errors.poll() {
                break;
            }
            invalid |= !valid_span(module, *source);
        }
        for dependency in &proof.depends_on {
            if errors.poll() {
                break;
            }
            invalid |= dependency.0 >= proof.id.0;
        }
        if invalid {
            errors.push(ValidationError::InvalidRecord {
                kind: "proof",
                id: proof.id.0,
            });
        }
        for dependency in &proof.depends_on {
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
    validate_acyclic(
        "proof dependency",
        module.proofs.len(),
        |index| module.proofs[index].depends_on.as_slice(),
        |id| id.0,
        &mut errors,
    );
    for test in &module.tests {
        if errors.poll() {
            break;
        }
        require_id(
            "test function",
            test.function.0,
            module.functions.len(),
            &mut errors,
        );
        if test.name.trim().is_empty() || test.timeout_ns == 0 || !valid_span(module, test.source) {
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
    let mut listed_tests = Vec::new();
    if listed_tests.try_reserve_exact(module.tests.len()).is_err() {
        errors.scratch_allocation_failed();
    } else {
        for test in &module.tests {
            if errors.poll() {
                break;
            }
            listed_tests.push(test.function);
        }
        if sort_validation_scratch(&mut listed_tests, &mut errors) {
            let mut prior = None;
            for function in &listed_tests {
                if errors.poll() {
                    break;
                }
                if prior == Some(*function) {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "test function set",
                        id: 0,
                    });
                }
                prior = Some(*function);
            }
        }
        let mut missing_test = false;
        for function in &module.functions {
            if errors.poll() {
                break;
            }
            missing_test |= function.role == FunctionRole::Test
                && listed_tests.binary_search(&function.id).is_err();
        }
        if missing_test {
            errors.push(ValidationError::InvalidRecord {
                kind: "test function set",
                id: 0,
            });
        }
    }
    if !compiled_test_group_matches(module) {
        errors.push(ValidationError::InvalidRecord {
            kind: "compiled test-group binding",
            id: module
                .compiled_test_group
                .as_ref()
                .map_or(0, |group| group.id.0),
        });
    }
    validate_image_order(module, &module.startup_order, "startup order", &mut errors);
    validate_image_order(
        module,
        &module.shutdown_order,
        "shutdown order",
        &mut errors,
    );
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownImageEntry(module.image_entry));
    } else {
        let mut image_entries = 0_u64;
        for function in &module.functions {
            if errors.poll() {
                break;
            }
            if function.role == FunctionRole::ImageEntry {
                image_entries = image_entries.saturating_add(1);
            }
        }
        if module.functions[module.image_entry.0 as usize].role != FunctionRole::ImageEntry
            || image_entries != 1
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "image entry role",
                id: module.image_entry.0,
            });
        }
    }
    if module.peak_bytes < module.static_bytes {
        errors.push(ValidationError::InvalidRecord {
            kind: "image memory plan",
            id: 0,
        });
    }
    if module.source_summary.reachable_declarations
        > u64::from(module.source_summary.hir_declarations)
        || module.source_summary.monomorphized_instantiations
            != u64::try_from(module.functions.len()).unwrap_or(u64::MAX)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "source summary",
            id: 0,
        });
    }
    errors.finish()
}

fn compiled_test_group_matches(module: &SemanticWir) -> bool {
    let entry = module.functions.get(module.image_entry.0 as usize);
    let Some(group) = &module.compiled_test_group else {
        return module.tests.is_empty()
            && !matches!(
                entry.map(|function| function.origin),
                Some(FunctionOrigin::GeneratedTestHarness { .. })
            );
    };
    if group.validate_compiled_binding().is_err() {
        return false;
    }
    match &group.root {
        wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
            if module.name != *harness_name
                || !matches!(
                    entry.map(|function| function.origin),
                    Some(FunctionOrigin::GeneratedTestHarness { group: actual })
                        if actual == group.id.0
                )
                || module.tests.len() != group.tests.len()
            {
                return false;
            }
            module
                .tests
                .iter()
                .zip(&group.tests)
                .all(|(local, planned)| {
                    let wrela_test_model::ImageTestInvocation::GeneratedFunction { function_key } =
                        planned.invocation
                    else {
                        return false;
                    };
                    local.plan_id == planned.descriptor.id.0
                        && local.name == planned.descriptor.name
                        && local.kind == TestKind::Integration
                        && planned.descriptor.kind == wrela_test_model::TestKind::IntegrationImage
                        && Some(local.source) == planned.descriptor.source
                        && local.timeout_ns == planned.descriptor.timeout_ns
                        && module
                            .functions
                            .get(local.function.0 as usize)
                            .is_some_and(|function| function.instance_key == function_key.0)
                })
        }
        wrela_test_model::ImageRoot::Declared { image_name, .. } => {
            module.name == *image_name
                && module.tests.is_empty()
                && matches!(
                    entry.map(|function| function.origin),
                    Some(FunctionOrigin::GeneratedImageEntry { .. })
                )
        }
    }
}

fn validate_type(module: &SemanticWir, ty: &TypeRecord, errors: &mut ValidationErrorSink<'_>) {
    if errors.poll() {
        return;
    }
    macro_rules! use_type {
        ($id:expr) => {
            require_id("type reference", ($id).0, module.types.len(), errors)
        };
    }
    if ty.source.is_some_and(|source| !valid_span(module, source)) {
        errors.push(ValidationError::InvalidRecord {
            kind: "type source",
            id: ty.id.0,
        });
    }
    match &ty.kind {
        TypeKind::Primitive(_) | TypeKind::OpaqueTarget { .. } => {}
        TypeKind::StaticString { .. } => {
            if ty.source_name != "Static[Str]"
                || ty.linearity != Linearity::ExplicitCopy
                || ty.source.is_some()
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "static string type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::StaticBytes { bytes } => {
            let extent = ty
                .source_name
                .strip_prefix("Static[Bytes[")
                .and_then(|name| name.strip_suffix("]]"));
            if extent.and_then(|extent| extent.parse::<u64>().ok()) != Some(*bytes)
                || extent.is_none_or(|extent| extent.len() > 1 && extent.starts_with('0'))
                || ty.linearity != Linearity::ExplicitCopy
                || ty.source.is_some()
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "static bytes type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::BoundedString { capacity } => {
            if *capacity == 0
                || ty.source_name != "BoundedString"
                || ty.linearity != Linearity::Reclaimable
                || ty.source.is_some()
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "bounded string type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::Tuple(types) => {
            for ty in types {
                use_type!(*ty);
            }
        }
        TypeKind::Array { element, .. } => use_type!(*element),
        TypeKind::Struct { fields } => {
            for field in fields {
                use_type!(field.ty);
            }
        }
        TypeKind::Enum { variants } => {
            for field in variants.iter().flat_map(|variant| &variant.fields) {
                use_type!(field.ty);
            }
            let canonical = !variants.is_empty()
                && variants.len() <= 256
                && ty.linearity == Linearity::ExplicitCopy
                && variants.iter().enumerate().all(|(index, variant)| {
                    let supported_shape = variant.fields.is_empty()
                        || matches!(variant.fields.as_slice(), [field]
                        if field.name.is_empty()
                            && field.public
                            && canonical_closed_enum_payload(module, field.ty));
                    supported_shape
                        && !variant.name.is_empty()
                        && !variants[..index]
                            .iter()
                            .any(|prior| prior.name == variant.name)
                });
            if !canonical {
                errors.push(ValidationError::InvalidRecord {
                    kind: "closed enum type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::AsyncExit {
            operation_error,
            cancelled,
            deadline_rejected,
            deadline_exceeded,
        } => {
            use_type!(*operation_error);
            use_type!(*cancelled);
            use_type!(*deadline_rejected);
            use_type!(*deadline_exceeded);
            let valid = ty.source_name == "AsyncExit"
                && ty.linearity == Linearity::ExplicitCopy
                && ty.source.is_some()
                && canonical_u64(module, *operation_error)
                && canonical_empty_cause(module, *cancelled, "Cancelled")
                && canonical_empty_cause(module, *deadline_rejected, "DeadlineRejected")
                && canonical_empty_cause(module, *deadline_exceeded, "DeadlineExceeded")
                && cancelled != deadline_rejected
                && cancelled != deadline_exceeded
                && deadline_rejected != deadline_exceeded;
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "async exit type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::AsyncOutcome {
            value,
            declared_error,
            exit,
        } => {
            use_type!(*value);
            use_type!(*declared_error);
            use_type!(*exit);
            let valid = ty.source_name == "Result"
                && ty.linearity == Linearity::ExplicitCopy
                && ty.source.is_some()
                && canonical_u64(module, *value)
                && canonical_u64(module, *declared_error)
                && module.types.get(exit.0 as usize).is_some_and(|record| {
                    record.id == *exit
                        && matches!(record.kind, TypeKind::AsyncExit { operation_error, .. }
                            if operation_error == *declared_error)
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "async outcome type",
                    id: ty.id.0,
                });
            }
        }
        TypeKind::Function(function) => {
            for parameter in &function.parameters {
                use_type!(parameter.ty);
            }
            use_type!(function.result);
        }
        TypeKind::Iso { pool, payload } | TypeKind::DmaPayload { pool, payload } => {
            require_id("type pool", pool.0, module.pools.len(), errors);
            use_type!(*payload);
        }
        TypeKind::ActorHandle { actor_type } => use_type!(*actor_type),
        TypeKind::Reservation => {}
        TypeKind::Receipt { payload, error } => {
            use_type!(*payload);
            use_type!(*error);
        }
        TypeKind::DmaShared { pool, layout } => {
            require_id("type pool", pool.0, module.pools.len(), errors);
            use_type!(*layout);
        }
        TypeKind::Mmio { layout } => use_type!(*layout),
        TypeKind::Validated { format, payload } => {
            use_type!(*format);
            use_type!(*payload);
        }
    }
}

fn canonical_u64(module: &SemanticWir, ty: TypeId) -> bool {
    module.types.get(ty.0 as usize).is_some_and(|record| {
        record.id == ty
            && record.source_name == "u64"
            && record.linearity == Linearity::CopyScalar
            && record.source.is_none()
            && record.kind == TypeKind::Primitive(PrimitiveType::U64)
    })
}

fn canonical_empty_cause(module: &SemanticWir, ty: TypeId, name: &str) -> bool {
    module.types.get(ty.0 as usize).is_some_and(|record| {
        record.id == ty
            && record.source_name == name
            && record.linearity == Linearity::ExplicitCopy
            && record.source.is_some()
            && matches!(&record.kind, TypeKind::Struct { fields } if fields.is_empty())
    })
}

fn canonical_closed_enum_payload(module: &SemanticWir, ty: TypeId) -> bool {
    let Some(record) = module
        .types
        .get(ty.0 as usize)
        .filter(|record| record.id == ty)
    else {
        return false;
    };
    if canonical_closed_enum_scalar_payload(record) {
        return true;
    }
    record.linearity == Linearity::ExplicitCopy
        && matches!(&record.kind, TypeKind::Struct { fields }
        if fields.iter().all(|field| {
            module.types.get(field.ty.0 as usize).is_some_and(|field_ty|
                field_ty.id == field.ty && canonical_closed_enum_scalar_payload(field_ty))
        }))
}

fn canonical_closed_enum_scalar_payload(record: &TypeRecord) -> bool {
    record.linearity == Linearity::CopyScalar
        && matches!(
            record.kind,
            TypeKind::Primitive(
                PrimitiveType::Bool
                    | PrimitiveType::I8
                    | PrimitiveType::I16
                    | PrimitiveType::I32
                    | PrimitiveType::I64
                    | PrimitiveType::I128
                    | PrimitiveType::U8
                    | PrimitiveType::U16
                    | PrimitiveType::U32
                    | PrimitiveType::U64
                    | PrimitiveType::U128
                    | PrimitiveType::F32
                    | PrimitiveType::F64
            )
        )
}

fn validate_constant(
    module: &SemanticWir,
    constant: &Constant,
    errors: &mut ValidationErrorSink<'_>,
) {
    let mut work = Vec::new();
    if work.try_reserve(1).is_err() {
        errors.scratch_allocation_failed();
        return;
    }
    work.push(constant);
    while let Some(constant) = work.pop() {
        if errors.poll() {
            return;
        }
        match constant {
            Constant::Enum { fields, .. } | Constant::Aggregate(fields) => {
                if work.try_reserve(fields.len()).is_err() {
                    errors.scratch_allocation_failed();
                    return;
                }
                work.extend(fields);
            }
            Constant::Zeroed(ty) => {
                require_id("constant type", ty.0, module.types.len(), errors);
            }
            Constant::Unit
            | Constant::Bool(_)
            | Constant::Unsigned { .. }
            | Constant::Signed { .. }
            | Constant::Float32(_)
            | Constant::Float64(_)
            | Constant::Char(_)
            | Constant::Bytes(_)
            | Constant::String(_) => {}
        }
    }
}

fn validate_owner(module: &SemanticWir, owner: ImageOwner, errors: &mut ValidationErrorSink<'_>) {
    if errors.poll() {
        return;
    }
    match owner {
        ImageOwner::Runtime | ImageOwner::BakedArtifact(_) => {}
        ImageOwner::Actor(id) => require_id("owner actor", id.0, module.actors.len(), errors),
        ImageOwner::Task(id) => require_id("owner task", id.0, module.tasks.len(), errors),
        ImageOwner::Device(id) => require_id("owner device", id.0, module.devices.len(), errors),
        ImageOwner::Pool(id) => require_id("owner pool", id.0, module.pools.len(), errors),
    }
}

fn validate_image_order(
    module: &SemanticWir,
    order: &[ImageOwner],
    kind: &'static str,
    errors: &mut ValidationErrorSink<'_>,
) {
    let expected = 1_usize
        .checked_add(module.actors.len())
        .and_then(|count| count.checked_add(module.tasks.len()))
        .and_then(|count| count.checked_add(module.devices.len()))
        .and_then(|count| count.checked_add(module.pools.len()));
    let mut seen = Vec::new();
    if seen.try_reserve_exact(order.len()).is_err() {
        errors.scratch_allocation_failed();
        return;
    }
    let mut valid = expected == Some(order.len());
    for owner in order {
        if errors.poll() {
            return;
        }
        validate_owner(module, *owner, errors);
        valid &= !matches!(*owner, ImageOwner::BakedArtifact(_));
        seen.push(*owner);
    }
    if !sort_validation_scratch(&mut seen, errors) {
        return;
    }
    let mut prior = None;
    let mut has_runtime = false;
    for owner in &seen {
        if errors.poll() {
            return;
        }
        valid &= prior != Some(*owner);
        has_runtime |= *owner == ImageOwner::Runtime;
        prior = Some(*owner);
    }
    valid &= has_runtime;
    if !valid {
        errors.push(ValidationError::InvalidRecord { kind, id: 0 });
    }
}

fn validate_activation_plans(module: &SemanticWir, errors: &mut ValidationErrorSink<'_>) {
    let mut uses = Vec::new();
    if uses.try_reserve_exact(module.activations.len()).is_err() {
        errors.scratch_allocation_failed();
        return;
    }
    uses.resize(module.activations.len(), 0_u32);

    let mut prior_key = None;
    for plan in &module.activations {
        if errors.poll() {
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
            FunctionRole::ActorTurn(actor) => Some(ImageOwner::Actor(actor)),
            FunctionRole::TaskEntry(task)
                if module
                    .tasks
                    .get(task.0 as usize)
                    .is_some_and(|task| task.slots == 1) =>
            {
                Some(ImageOwner::Task(task))
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
            || !valid_span(module, plan.source)
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
                    || Some(region.owner) != owner
                    || region.proof != plan.capacity_proof
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
        if errors.poll() {
            return;
        }
        let mut regions = Vec::new();
        if regions.try_reserve(1).is_err() {
            errors.scratch_allocation_failed();
            return;
        }
        regions.push(&function.body);
        while let Some(region) = regions.pop() {
            for statement in &region.statements {
                if errors.poll() {
                    return;
                }
                match statement {
                    SemanticStatement::Let(LetStatement {
                        operation:
                            SemanticOperation::Call {
                                function: callee,
                                activation,
                                ..
                            },
                        source,
                        ..
                    }) => {
                        let is_async = module
                            .functions
                            .get(callee.0 as usize)
                            .is_some_and(|callee| callee.color == FunctionColor::Async);
                        let valid = match (*activation, *source, is_async) {
                            (Some(id), Some(source), true) => {
                                module.activations.get(id.0 as usize).is_some_and(|plan| {
                                    plan.id == id
                                        && plan.caller == function.id
                                        && plan.callee == *callee
                                        && plan.source == source
                                        && uses.get_mut(id.0 as usize).is_some_and(|count| {
                                            *count = count.saturating_add(1);
                                            true
                                        })
                                })
                            }
                            (None, _, false) => true,
                            _ => false,
                        };
                        if !valid {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "activation call binding",
                                id: function.id.0,
                            });
                        }
                    }
                    SemanticStatement::If {
                        then_region,
                        else_region,
                        ..
                    } => {
                        if regions.try_reserve(2).is_err() {
                            errors.scratch_allocation_failed();
                            return;
                        }
                        regions.push(else_region);
                        regions.push(then_region);
                    }
                    SemanticStatement::Match { arms, .. } => {
                        if regions.try_reserve(arms.len()).is_err() {
                            errors.scratch_allocation_failed();
                            return;
                        }
                        for arm in arms.iter().rev() {
                            regions.push(&arm.body);
                        }
                    }
                    SemanticStatement::Loop { body, .. } => {
                        if regions.try_reserve(1).is_err() {
                            errors.scratch_allocation_failed();
                            return;
                        }
                        regions.push(body);
                    }
                    SemanticStatement::Let(_)
                    | SemanticStatement::Return(_)
                    | SemanticStatement::Yield(_)
                    | SemanticStatement::Break(_)
                    | SemanticStatement::Continue(_)
                    | SemanticStatement::Unreachable => {}
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
    errors: &mut ValidationErrorSink<'_>,
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
        if errors.poll() {
            return None;
        }
        if actual != expected {
            return Some(false);
        }
    }
    Some(true)
}

fn validate_actor_capacity_contract(module: &SemanticWir, errors: &mut ValidationErrorSink<'_>) {
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
                region.owner == ImageOwner::Actor(actor.id)
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
        if errors.poll() {
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
            if errors.poll() {
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
                && region.owner == ImageOwner::Actor(actor.id)
                && module
                    .proofs
                    .get(region.proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.id == region.proof
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
                    && region.owner == ImageOwner::Actor(actor.id)
                    && module
                        .proofs
                        .get(region.proof.0 as usize)
                        .is_some_and(|proof| {
                            proof.id == region.proof
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
                        && region.owner == ImageOwner::Actor(actor.id)
                        && module
                            .proofs
                            .get(region.proof.0 as usize)
                            .is_some_and(|proof| {
                                proof.id == region.proof
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
        if errors.poll() {
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
                    && region.owner == ImageOwner::Task(task.id)
                    && module
                        .proofs
                        .get(region.proof.0 as usize)
                        .is_some_and(|proof| {
                            proof.id == region.proof
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
        if errors.poll() {
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
        if errors.poll() {
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
        valid = false;
        if !valid {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor capacity closure",
                id: 0,
            });
        }
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
        let mut expected = Vec::new();
        if expected.try_reserve_exact(expected_dependencies).is_err() {
            errors.scratch_allocation_failed();
            return;
        }
        expected.extend([ProofId(0), ProofId(1), wait_proof, supervision_proof]);
        for region in module.regions.iter().take(base_region_count) {
            if errors.poll() {
                return;
            }
            expected.push(region.proof);
        }
        if !sort_validation_scratch(&mut expected, errors) {
            return;
        }
        valid &= expected.len() == base_proof.depends_on.len();
        for (expected, actual) in expected.iter().zip(&base_proof.depends_on) {
            if errors.poll() {
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
                if errors.poll() {
                    return;
                }
                valid &= entry.proofs.binary_search(&region.proof).is_ok();
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
            if errors.poll() {
                return;
            }
            let expected = module.regions.iter().find_map(|region| {
                (region.owner == ImageOwner::Actor(actor.id)
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
            if errors.poll() {
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

fn validate_static_supervision_contract(
    module: &SemanticWir,
    errors: &mut ValidationErrorSink<'_>,
) {
    if module.actors.is_empty() {
        return;
    }
    let mut supervision = None;
    let mut image_closed = None;
    for proof in &module.proofs {
        if errors.poll() {
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
    let node_count = module.actors.len().checked_add(module.tasks.len());
    let mut expected_sources = Vec::new();
    let Some(node_count_usize) = node_count else {
        errors.push(ValidationError::InvalidRecord {
            kind: "actor supervision proof",
            id: proof.id.0,
        });
        return;
    };
    if expected_sources
        .try_reserve_exact(node_count_usize)
        .is_err()
    {
        errors.scratch_allocation_failed();
        return;
    }
    for actor in &module.actors {
        if errors.poll() {
            return;
        }
        let source = module
            .regions
            .iter()
            .find(|region| region.owner == ImageOwner::Actor(actor.id))
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
            expected_sources.push(source);
        }
    }
    for task in &module.tasks {
        if errors.poll() {
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
            .find(|region| region.owner == ImageOwner::Task(task.id))
            .map(|region| region.source);
        if !parent_matches || !entry_matches || source.is_none() {
            errors.push(ValidationError::InvalidRecord {
                kind: "actor supervision topology",
                id: task.id.0,
            });
        }
        if let Some(source) = source {
            expected_sources.push(source);
        }
    }
    let exact = u64::try_from(node_count_usize).ok();
    let entry_has_proof = module
        .functions
        .get(module.image_entry.0 as usize)
        .is_some_and(|entry| entry.proofs.contains(&proof.id));
    let closure_reaches = image_closed.is_some_and(|closed| {
        closed.id == proof.id
            || closed.depends_on.contains(&proof.id)
            || closed.depends_on.iter().any(|dependency| {
                module
                    .proofs
                    .get(dependency.0 as usize)
                    .is_some_and(|parent| parent.depends_on.contains(&proof.id))
            })
    });
    if proof.subject != "complete static actor/task parent topology"
        || proof.bound != exact
        || proof.depends_on.as_slice() != [ProofId(0)]
        || proof.sources != expected_sources
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

fn valid_span(module: &SemanticWir, span: Span) -> bool {
    span.file.0 < module.source_summary.hir_files && span.range.start <= span.range.end
}

fn validate_function(
    module: &SemanticWir,
    function: &SemanticFunction,
    errors: &mut ValidationErrorSink<'_>,
) {
    if errors.poll() {
        return;
    }
    let valid_origin = match function.origin {
        FunctionOrigin::Source => {
            function.source.is_some() && function.role != FunctionRole::ImageEntry
        }
        FunctionOrigin::GeneratedImageEntry { constructor } => {
            function.source.is_none()
                && function.role == FunctionRole::ImageEntry
                && constructor < module.source_summary.hir_declarations
                && module.source_summary.reachable_declarations > 0
        }
        FunctionOrigin::GeneratedTestHarness { .. } => {
            function.source.is_none() && function.role == FunctionRole::ImageEntry
        }
    };
    let valid_role = match function.role {
        FunctionRole::ActorTurn(actor) => (actor.0 as usize) < module.actors.len(),
        FunctionRole::TaskEntry(task) => (task.0 as usize) < module.tasks.len(),
        FunctionRole::Isr(device) => (device.0 as usize) < module.devices.len(),
        FunctionRole::Ordinary
        | FunctionRole::Cleanup
        | FunctionRole::ImageEntry
        | FunctionRole::Test => true,
    };
    let valid_color_role = match (function.color, function.role) {
        (FunctionColor::Isr, FunctionRole::Isr(_)) => true,
        (FunctionColor::Isr, _) | (_, FunctionRole::Isr(_)) => false,
        (FunctionColor::Sync, FunctionRole::ImageEntry) => true,
        (FunctionColor::Async, FunctionRole::ImageEntry) => false,
        (FunctionColor::Sync | FunctionColor::Async, _) => true,
    };
    if function.name.trim().is_empty()
        || function
            .instance_key
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || !function.effects.is_valid()
        || !valid_origin
        || !valid_role
        || !valid_color_role
        || function
            .source
            .is_some_and(|source| !valid_span(module, source))
        || function.recursive_depth_bound == Some(0)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "function",
            id: function.id.0,
        });
    }
    check_dense(
        "value",
        function.values.iter().map(|item| item.id.0),
        errors,
    );
    require_id(
        "function result type",
        function.result.0,
        module.types.len(),
        errors,
    );
    for value in &function.values {
        require_id("value type", value.ty.0, module.types.len(), errors);
        if value
            .origin
            .is_some_and(|source| !valid_span(module, source))
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "value source",
                id: value.id.0,
            });
        }
    }
    for proof in &function.proofs {
        require_id("function proof", proof.0, module.proofs.len(), errors);
    }
    require_canonical_ids(
        "function proofs",
        function.id.0,
        function.proofs.iter().map(|proof| proof.0),
        errors,
    );
    if function.body.parameters != function.parameters {
        errors.push(ValidationError::RootParameterMismatch(function.id));
    }
    let mut definitions = Vec::new();
    if definitions
        .try_reserve_exact(function.values.len())
        .is_err()
    {
        errors.scratch_allocation_failed();
        return;
    }
    definitions.resize(function.values.len(), 0_u8);
    for parameter in &function.parameters {
        define_value(function.id, *parameter, &mut definitions, errors);
    }
    validate_region(
        module,
        function,
        &function.body,
        true,
        &mut definitions,
        errors,
    );
    for (index, count) in definitions.into_iter().enumerate() {
        if errors.poll() {
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
}

fn validate_region(
    module: &SemanticWir,
    function: &SemanticFunction,
    region: &SemanticRegion,
    is_root: bool,
    definitions: &mut [u8],
    errors: &mut ValidationErrorSink<'_>,
) {
    let mut regions = Vec::new();
    if regions.try_reserve(1).is_err() {
        errors.scratch_allocation_failed();
        return;
    }
    regions.push((region, is_root));
    while let Some((region, is_root)) = regions.pop() {
        if errors.poll() {
            return;
        }
        if !is_root {
            for parameter in &region.parameters {
                define_value(function.id, *parameter, definitions, errors);
            }
        }
        for statement in &region.statements {
            if errors.poll() {
                return;
            }
            let source = match statement {
                SemanticStatement::Let(statement) => statement.source,
                SemanticStatement::If { source, .. }
                | SemanticStatement::Match { source, .. }
                | SemanticStatement::Loop { source, .. } => *source,
                SemanticStatement::Return(_)
                | SemanticStatement::Yield(_)
                | SemanticStatement::Break(_)
                | SemanticStatement::Continue(_)
                | SemanticStatement::Unreachable => None,
            };
            if source.is_some_and(|source| !valid_span(module, source)) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "statement source",
                    id: function.id.0,
                });
            }
            match statement {
                SemanticStatement::Let(statement) => {
                    for result in &statement.results {
                        define_value(function.id, *result, definitions, errors);
                    }
                    validate_operation(
                        module,
                        function,
                        &statement.results,
                        &statement.operation,
                        errors,
                    );
                }
                SemanticStatement::If {
                    condition,
                    then_region,
                    else_region,
                    results,
                    ..
                } => {
                    use_value(function, *condition, errors);
                    for result in results {
                        define_value(function.id, *result, definitions, errors);
                    }
                    if regions.try_reserve(2).is_err() {
                        errors.scratch_allocation_failed();
                        return;
                    }
                    regions.push((else_region, false));
                    regions.push((then_region, false));
                }
                SemanticStatement::Match {
                    scrutinee,
                    arms,
                    results,
                    ..
                } => {
                    use_value(function, *scrutinee, errors);
                    for result in results {
                        define_value(function.id, *result, definitions, errors);
                    }
                    if regions.try_reserve(arms.len()).is_err() {
                        errors.scratch_allocation_failed();
                        return;
                    }
                    for arm in arms.iter().rev() {
                        if arm.body.parameters != arm.bindings {
                            errors.push(ValidationError::InvalidRecord {
                                kind: "match arm bracket",
                                id: function.id.0,
                            });
                        }
                        if let Some(guard) = arm.guard {
                            use_value(function, guard, errors);
                        }
                        regions.push((&arm.body, false));
                    }
                }
                SemanticStatement::Loop { body, carried, .. } => {
                    let arity = body.parameters.len();
                    let valid_carried = carried.len() == arity.saturating_mul(3)
                        && body.parameters == carried[arity..2 * arity]
                        && (0..arity).all(|index| {
                            let ty = |value: ValueId| {
                                function.values.get(value.0 as usize).map(|value| value.ty)
                            };
                            let initial = ty(carried[index]);
                            initial.is_some()
                                && initial == ty(carried[arity + index])
                                && initial == ty(carried[2 * arity + index])
                        });
                    if !valid_carried {
                        errors.push(ValidationError::InvalidRecord {
                            kind: "loop carried bracket",
                            id: function.id.0,
                        });
                    } else {
                        for value in &carried[..arity] {
                            use_value(function, *value, errors);
                        }
                        for value in &carried[2 * arity..] {
                            define_value(function.id, *value, definitions, errors);
                        }
                    }
                    if regions.try_reserve(1).is_err() {
                        errors.scratch_allocation_failed();
                        return;
                    }
                    regions.push((body, false));
                }
                SemanticStatement::Return(values)
                | SemanticStatement::Yield(values)
                | SemanticStatement::Break(values)
                | SemanticStatement::Continue(values) => {
                    for value in values {
                        use_value(function, *value, errors);
                    }
                }
                SemanticStatement::Unreachable => {}
            }
        }
    }
}

fn validate_operation(
    module: &SemanticWir,
    function: &SemanticFunction,
    results: &[ValueId],
    operation: &SemanticOperation,
    errors: &mut ValidationErrorSink<'_>,
) {
    macro_rules! value {
        ($id:expr) => {
            use_value(function, $id, errors)
        };
    }
    macro_rules! argument {
        ($argument:expr) => {
            value!(($argument).value)
        };
    }
    match operation {
        SemanticOperation::Constant(constant) => {
            validate_constant(module, constant, errors);
            if let Constant::String(value) = constant {
                let valid = matches!(results, [result]
                if function.values.get(result.0 as usize).is_some_and(|result| {
                    module.types.get(result.ty.0 as usize).is_some_and(|ty| {
                        matches!(ty.kind, TypeKind::StaticString { bytes }
                            if u64::try_from(value.len()) == Ok(bytes))
                    })
                }));
                if !valid {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "static string constant",
                        id: results.first().map_or(u32::MAX, |result| result.0),
                    });
                }
            }
            if let Constant::Bytes(value) = constant {
                let valid = matches!(results, [result]
                if function.values.get(result.0 as usize).is_some_and(|result| {
                    module.types.get(result.ty.0 as usize).is_some_and(|ty| match ty.kind {
                        TypeKind::StaticBytes { bytes } => {
                            u64::try_from(value.len()) == Ok(bytes)
                        }
                        TypeKind::Array { element, length } => {
                            u64::try_from(value.len()) == Ok(length)
                                && module.types.get(element.0 as usize).is_some_and(|element| {
                                    element.kind == TypeKind::Primitive(PrimitiveType::U8)
                                        && element.linearity == Linearity::CopyScalar
                                })
                        }
                        _ => false,
                    })
                }));
                if !valid {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "byte constant",
                        id: results.first().map_or(u32::MAX, |result| result.0),
                    });
                }
            }
        }
        SemanticOperation::Unary { operand, .. } => value!(*operand),
        SemanticOperation::Binary { left, right, .. } => {
            value!(*left);
            value!(*right);
        }
        SemanticOperation::Convert {
            value: operand,
            destination,
            ..
        } => {
            value!(*operand);
            require_id("conversion type", destination.0, module.types.len(), errors);
        }
        SemanticOperation::Aggregate { ty, fields } => {
            require_id("aggregate type", ty.0, module.types.len(), errors);
            for field in fields {
                value!(*field);
            }
        }
        SemanticOperation::FormatBoundedString { ty, parts } => {
            require_id("bounded string type", ty.0, module.types.len(), errors);
            let expected_capacity = module
                .types
                .get(ty.0 as usize)
                .and_then(|record| match record.kind {
                    TypeKind::BoundedString { capacity } => Some(capacity),
                    _ => None,
                });
            let mut capacity = Some(0_u64);
            let mut value_parts = 0_u64;
            let mut previous_source = None;
            for part in parts {
                if errors.poll() {
                    return;
                }
                let (source, width) = match part {
                    BoundedStringPart::Text { value, source } => {
                        (*source, u64::try_from(value.len()).ok())
                    }
                    BoundedStringPart::Bool { value, source } => {
                        value!(*value);
                        value_parts = value_parts.saturating_add(1);
                        let width = function.values.get(value.0 as usize).and_then(|value| {
                            module.types.get(value.ty.0 as usize).and_then(|ty| {
                                (ty.kind == TypeKind::Primitive(PrimitiveType::Bool)).then_some(5)
                            })
                        });
                        (*source, width)
                    }
                    BoundedStringPart::Character { value, source } => {
                        value!(*value);
                        value_parts = value_parts.saturating_add(1);
                        let width = function.values.get(value.0 as usize).and_then(|value| {
                            module.types.get(value.ty.0 as usize).and_then(|ty| {
                                (ty.kind == TypeKind::Primitive(PrimitiveType::Char)).then_some(4)
                            })
                        });
                        (*source, width)
                    }
                    BoundedStringPart::Integer {
                        value,
                        maximum_bytes,
                        source,
                    } => {
                        value!(*value);
                        value_parts = value_parts.saturating_add(1);
                        let width = function.values.get(value.0 as usize).and_then(|value| {
                            module.types.get(value.ty.0 as usize).and_then(|ty| {
                                bounded_integer_maximum(&ty.kind)
                                    .filter(|expected| expected == maximum_bytes)
                            })
                        });
                        (*source, width)
                    }
                    BoundedStringPart::StaticString {
                        value,
                        bytes,
                        source,
                    } => {
                        value!(*value);
                        value_parts = value_parts.saturating_add(1);
                        let width = function.values.get(value.0 as usize).and_then(|value| {
                            module.types.get(value.ty.0 as usize).and_then(|ty| {
                                matches!(ty.kind, TypeKind::StaticString { bytes: extent }
                                    if extent == *bytes)
                                .then_some(*bytes)
                            })
                        });
                        (*source, width)
                    }
                };
                let ordered = valid_span(module, source)
                    && previous_source.is_none_or(|previous: Span| {
                        previous.file == source.file && previous.range.end <= source.range.start
                    });
                if !ordered {
                    capacity = None;
                }
                previous_source = Some(source);
                capacity =
                    capacity.and_then(|total| width.and_then(|width| total.checked_add(width)));
            }
            let valid_result = matches!(results, [result]
                if function.values.get(result.0 as usize).is_some_and(|result| result.ty == *ty));
            if parts.is_empty()
                || value_parts == 0
                || expected_capacity.is_none()
                || capacity != expected_capacity
                || !valid_result
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "bounded string construction",
                    id: results.first().map_or(u32::MAX, |result| result.0),
                });
            }
        }
        SemanticOperation::InsertField {
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
                            TypeKind::Struct { fields } => fields
                                .get(*field as usize)
                                .map(|selected| (aggregate_ty, selected.ty)),
                            _ => None,
                        })
                })
                .is_some_and(|(aggregate_ty, field_ty)| {
                    function
                        .values
                        .get(inserted.0 as usize)
                        .is_some_and(|inserted| inserted.ty == field_ty)
                        && matches!(results, [result]
                            if function.values.get(result.0 as usize)
                                .is_some_and(|result| result.ty == aggregate_ty))
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "field insertion",
                    id: results.first().map_or(u32::MAX, |result| result.0),
                });
            }
        }
        SemanticOperation::ConstructEnum {
            ty,
            variant,
            payload,
        } => {
            require_id("enum type", ty.0, module.types.len(), errors);
            if let Some(payload) = payload {
                value!(*payload);
            }
            if !module.types.get(ty.0 as usize).is_some_and(|record| {
                matches!(&record.kind, TypeKind::Enum { variants }
                    if variants.get(*variant as usize).is_some_and(|item| {
                        match (item.fields.as_slice(), payload) {
                            ([], None) => true,
                            ([field], Some(payload)) => function.values
                                .get(payload.0 as usize)
                                .is_some_and(|value| value.ty == field.ty),
                            _ => false,
                        }
                    }))
                    && matches!(results, [result]
                        if function.values.get(result.0 as usize).is_some_and(|value| value.ty == *ty))
            }) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "enum construction",
                    id: ty.0,
                });
            }
        }
        SemanticOperation::Project { base, .. } => value!(*base),
        SemanticOperation::ActorStateLoad {
            actor,
            region,
            proof,
        } => {
            require_id("actor state actor", actor.0, module.actors.len(), errors);
            require_id("actor state region", region.0, module.regions.len(), errors);
            require_id("actor state proof", proof.0, module.proofs.len(), errors);
            if !valid_actor_state_operation(
                module, function, results, *actor, *region, *proof, None,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor state load",
                    id: region.0,
                });
            }
        }
        SemanticOperation::ActorStateStore {
            actor,
            region,
            value: stored,
            proof,
        } => {
            value!(*stored);
            require_id("actor state actor", actor.0, module.actors.len(), errors);
            require_id("actor state region", region.0, module.regions.len(), errors);
            require_id("actor state proof", proof.0, module.proofs.len(), errors);
            if !valid_actor_state_operation(
                module,
                function,
                results,
                *actor,
                *region,
                *proof,
                Some(*stored),
            ) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor state store",
                    id: region.0,
                });
            }
        }
        SemanticOperation::Index { base, index, proof } => {
            value!(*base);
            value!(*index);
            require_id("index proof", proof.0, module.proofs.len(), errors);
        }
        SemanticOperation::BeginAccess { place, region, .. } => {
            value!(*place);
            require_id("access region", region.0, module.regions.len(), errors);
        }
        SemanticOperation::EndAccess { value: operand }
        | SemanticOperation::Move { value: operand }
        | SemanticOperation::Copy { value: operand }
        | SemanticOperation::Drop { value: operand }
        | SemanticOperation::ActorSend { message: operand }
        | SemanticOperation::ActorTrySend { message: operand }
        | SemanticOperation::Await { awaitable: operand }
        | SemanticOperation::Cancel { target: operand }
        | SemanticOperation::RecordEvent {
            payload: operand, ..
        }
        | SemanticOperation::TestEmit { payload: operand }
        | SemanticOperation::TestFinish { outcome: operand } => value!(*operand),
        SemanticOperation::AwaitAsyncOutcome {
            awaitable,
            exit,
            proof,
        } => {
            value!(*awaitable);
            require_id(
                "async outcome exit type",
                exit.0,
                module.types.len(),
                errors,
            );
            require_id("async outcome proof", proof.0, module.proofs.len(), errors);
            let outcome = match results {
                [result] => function.values.get(result.0 as usize).and_then(|result| {
                    module
                        .types
                        .get(result.ty.0 as usize)
                        .and_then(|outcome| match outcome.kind {
                            TypeKind::AsyncOutcome {
                                value,
                                declared_error,
                                exit: outcome_exit,
                            } => Some((result, value, declared_error, outcome_exit)),
                            _ => None,
                        })
                }),
                _ => None,
            };
            let valid = function.color == FunctionColor::Async
                && outcome.is_some_and(|(result, value, declared_error, outcome_exit)| {
                    outcome_exit == *exit
                        && canonical_u64(module, value)
                        && canonical_u64(module, declared_error)
                        && function.values.get(awaitable.0 as usize).is_some_and(|awaitable| {
                            canonical_declared_async_result(
                                module,
                                awaitable.ty,
                                value,
                                declared_error,
                            )
                        })
                        && module.proofs.get(proof.0 as usize).is_some_and(|record| {
                            let source = result.origin;
                            record.id == *proof
                                && record.kind == ProofKind::AsyncOutcomeAuthenticated
                                && record.subject
                                    == "direct fallible await widens to AsyncExit[u64]"
                                && record.bound == Some(1)
                                && source.is_some_and(|source| {
                                    record.sources.as_slice() == [source]
                                })
                                && record.depends_on.as_slice() == [ProofId(0), ProofId(1)]
                                && record.explanation.as_slice() == [
                                    "the direct non-actor async callee returns Result[u64,u64]; this await alone widens the error to compiler-authenticated AsyncExit[u64] for immediate match or is consumption",
                                ]
                                && function.proofs.binary_search(proof).is_ok()
                        })
                });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "authenticated async outcome await",
                    id: results.first().map_or(u32::MAX, |result| result.0),
                });
            }
        }
        SemanticOperation::Assert { condition, failure } => {
            value!(*condition);
            if failure.expression.chars().all(char::is_whitespace)
                || failure.expression.len() > ASSERTION_EXPRESSION_BYTES_MAX
                || failure.message.as_ref().is_some_and(|message| {
                    message.chars().all(char::is_whitespace)
                        || message.len() > ASSERTION_EXPRESSION_BYTES_MAX
                })
                || failure.source.range.start > failure.source.range.end
            {
                errors.push(ValidationError::InvalidAssertionDescriptor {
                    function: function.id,
                });
            }
        }
        SemanticOperation::Call {
            function: callee,
            arguments,
            activation,
        } => {
            require_id("callee", callee.0, module.functions.len(), errors);
            if let Some(activation) = activation {
                require_id(
                    "call activation",
                    activation.0,
                    module.activations.len(),
                    errors,
                );
            }
            for item in arguments {
                argument!(item);
            }
        }
        SemanticOperation::ActorCapability {
            actor,
            wiring_proof,
        } => {
            require_id(
                "actor capability target",
                actor.0,
                module.actors.len(),
                errors,
            );
            require_id(
                "actor capability wiring proof",
                wiring_proof.0,
                module.proofs.len(),
                errors,
            );
            let valid = matches!(results, [result]
            if module.actors.get(actor.0 as usize).is_some_and(|target| {
                function.values.get(result.0 as usize).is_some_and(|value| {
                    module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                        ty.linearity == Linearity::ExplicitCopy
                            && matches!(ty.kind, TypeKind::ActorHandle { actor_type }
                                if actor_type == target.ty)
                    })
                })
            })
            && module.proofs.get(wiring_proof.0 as usize).is_some_and(|proof| {
                proof.kind == ProofKind::ActorAsIf
                    && proof.bound == Some(1)
                    && proof.sources.len() == 1
                    && proof.depends_on.is_empty()
            }));
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor capability",
                    id: actor.0,
                });
            }
        }
        SemanticOperation::ActorReserve {
            actor,
            method,
            permit_proof,
        } => {
            require_id("actor reservation", actor.0, module.actors.len(), errors);
            require_id("actor method", method.0, module.functions.len(), errors);
            require_id(
                "actor permit proof",
                permit_proof.0,
                module.proofs.len(),
                errors,
            );
        }
        SemanticOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            value!(*reservation);
            for item in arguments {
                argument!(item);
            }
        }
        SemanticOperation::ActorReplyRequest {
            actor,
            method,
            permit_proof,
            reply_proof,
        } => {
            require_id("actor reply target", actor.0, module.actors.len(), errors);
            require_id(
                "actor reply method",
                method.0,
                module.functions.len(),
                errors,
            );
            require_id(
                "actor reply permit",
                permit_proof.0,
                module.proofs.len(),
                errors,
            );
            require_id(
                "actor reply proof",
                reply_proof.0,
                module.proofs.len(),
                errors,
            );
            let valid = matches!(results, [result]
            if function.values.get(result.0 as usize).is_some_and(|value| {
                module.types.get(value.ty.0 as usize).is_some_and(|ty| {
                    ty.kind == TypeKind::Primitive(PrimitiveType::U64)
                        && ty.linearity == Linearity::CopyScalar
                })
            })) && module
                .functions
                .get(method.0 as usize)
                .is_some_and(|target| {
                    target.role == FunctionRole::ActorTurn(*actor)
                        && target.color == FunctionColor::Async
                        && module
                            .types
                            .get(target.result.0 as usize)
                            .is_some_and(|ty| ty.kind == TypeKind::Primitive(PrimitiveType::U64))
                })
                && module
                    .proofs
                    .get(permit_proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.kind == ProofKind::CapacityBound && proof.bound == Some(1)
                    })
                && module
                    .proofs
                    .get(reply_proof.0 as usize)
                    .is_some_and(|proof| {
                        let target_type_proof =
                            module.functions.get(method.0 as usize).and_then(|target| {
                                target.proofs.iter().copied().find(|candidate| {
                                    module
                                        .proofs
                                        .get(candidate.0 as usize)
                                        .is_some_and(|record| record.kind == ProofKind::TypeChecked)
                                })
                            });
                        let mut expected =
                            target_type_proof.map(|type_proof| [type_proof, *permit_proof]);
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
                    id: method.0,
                });
            }
        }
        SemanticOperation::ActorReplyResolve {
            outcome,
            reply_proof,
        } => {
            value!(*outcome);
            require_id(
                "actor reply resolve proof",
                reply_proof.0,
                module.proofs.len(),
                errors,
            );
            let valid = results.is_empty()
                && function
                    .values
                    .get(outcome.0 as usize)
                    .is_some_and(|value| {
                        module
                            .types
                            .get(value.ty.0 as usize)
                            .is_some_and(|ty| ty.kind == TypeKind::Primitive(PrimitiveType::U64))
                    })
                && module
                    .proofs
                    .get(reply_proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.kind == ProofKind::ActorReplyExactlyOnce && proof.bound == Some(1)
                    });
            if !valid {
                errors.push(ValidationError::InvalidRecord {
                    kind: "actor reply resolve",
                    id: reply_proof.0,
                });
            }
        }
        SemanticOperation::MailboxReceive { actor, method } => {
            require_id(
                "mailbox receive actor",
                actor.0,
                module.actors.len(),
                errors,
            );
            require_id(
                "mailbox receive method",
                method.0,
                module.functions.len(),
                errors,
            );
        }
        SemanticOperation::SpawnTask {
            task,
            arguments,
            slot_proof,
        } => {
            require_id("spawn task", task.0, module.tasks.len(), errors);
            require_id("task slot proof", slot_proof.0, module.proofs.len(), errors);
            for item in arguments {
                argument!(item);
            }
        }
        SemanticOperation::Checkpoint { budget_proof } => {
            require_id(
                "checkpoint proof",
                budget_proof.0,
                module.proofs.len(),
                errors,
            );
        }
        SemanticOperation::Select { awaitables } | SemanticOperation::Race { awaitables } => {
            for awaitable in awaitables {
                value!(*awaitable);
            }
        }
        SemanticOperation::Allocate {
            region,
            ty,
            count,
            capacity_proof,
        } => {
            require_id("allocation region", region.0, module.regions.len(), errors);
            require_id("allocation type", ty.0, module.types.len(), errors);
            require_id(
                "allocation proof",
                capacity_proof.0,
                module.proofs.len(),
                errors,
            );
            value!(*count);
        }
        SemanticOperation::ResetRegion { region } => {
            require_id("reset region", region.0, module.regions.len(), errors);
        }
        SemanticOperation::Promote {
            value: promoted,
            destination,
            proof,
        } => {
            value!(*promoted);
            require_id(
                "promotion region",
                destination.0,
                module.regions.len(),
                errors,
            );
            require_id("promotion proof", proof.0, module.proofs.len(), errors);
            if !valid_promotion_operation(
                module,
                function,
                results,
                *promoted,
                *destination,
                *proof,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "promotion",
                    id: proof.0,
                });
            }
        }
        SemanticOperation::EnterScope { scope, state } => {
            require_id("entered scope", scope.0, module.scopes.len(), errors);
            value!(*state);
        }
        SemanticOperation::CommitScope {
            scope,
            value: committed,
        } => {
            require_id("committed scope", scope.0, module.scopes.len(), errors);
            value!(*committed);
        }
        SemanticOperation::AbortScope { scope, error } => {
            require_id("aborted scope", scope.0, module.scopes.len(), errors);
            if let Some(error) = error {
                value!(*error);
            }
        }
        SemanticOperation::ExitScope { scope } => {
            require_id("exited scope", scope.0, module.scopes.len(), errors);
        }
        SemanticOperation::DmaTransition {
            value: token,
            device,
            proof,
            ..
        } => {
            value!(*token);
            require_id("DMA device", device.0, module.devices.len(), errors);
            require_id("DMA proof", proof.0, module.proofs.len(), errors);
        }
        SemanticOperation::MmioRead { device, .. } => {
            require_id("MMIO device", device.0, module.devices.len(), errors);
        }
        SemanticOperation::MmioWrite {
            device,
            value: written,
            ..
        }
        | SemanticOperation::InterruptPublish {
            device,
            value: written,
            ..
        } => {
            require_id("hardware device", device.0, module.devices.len(), errors);
            value!(*written);
        }
        SemanticOperation::QueueReserve {
            device,
            descriptors,
            proof,
        } => {
            require_id("queue device", device.0, module.devices.len(), errors);
            require_id("queue proof", proof.0, module.proofs.len(), errors);
            value!(*descriptors);
        }
        SemanticOperation::QueuePublish {
            reservation,
            payloads,
        } => {
            value!(*reservation);
            for payload in payloads {
                value!(*payload);
            }
        }
        SemanticOperation::Check {
            condition, proof, ..
        } => {
            value!(*condition);
            if let Some(proof) = proof {
                require_id("check proof", proof.0, module.proofs.len(), errors);
            }
        }
    }
}

fn canonical_declared_async_result(
    module: &SemanticWir,
    ty: TypeId,
    value: TypeId,
    error: TypeId,
) -> bool {
    module.types.get(ty.0 as usize).is_some_and(|record| {
        record.id == ty
            && record.source_name == "Result"
            && record.linearity == Linearity::ExplicitCopy
            && record.source.is_some()
            && matches!(&record.kind, TypeKind::Enum { variants }
                if matches!(variants.as_slice(), [ok, err]
                    if ok.name == "Ok"
                        && matches!(ok.fields.as_slice(), [field]
                            if field.name.is_empty() && field.public && field.ty == value)
                        && err.name == "Err"
                        && matches!(err.fields.as_slice(), [field]
                            if field.name.is_empty() && field.public && field.ty == error)))
    })
}

fn bounded_integer_maximum(kind: &TypeKind) -> Option<u64> {
    let decimal_digits = |mut value: u128| {
        let mut digits = 1_u64;
        while value >= 10 {
            value /= 10;
            digits = digits.saturating_add(1);
        }
        digits
    };
    match kind {
        TypeKind::Primitive(
            PrimitiveType::U8
            | PrimitiveType::U16
            | PrimitiveType::U32
            | PrimitiveType::U64
            | PrimitiveType::U128
            | PrimitiveType::Usize,
        ) => {
            let bits = match kind {
                TypeKind::Primitive(PrimitiveType::U8) => 8,
                TypeKind::Primitive(PrimitiveType::U16) => 16,
                TypeKind::Primitive(PrimitiveType::U32) => 32,
                TypeKind::Primitive(PrimitiveType::U64 | PrimitiveType::Usize) => 64,
                TypeKind::Primitive(PrimitiveType::U128) => 128,
                _ => return None,
            };
            Some(decimal_digits(if bits == 128 {
                u128::MAX
            } else {
                (1_u128 << bits) - 1
            }))
        }
        TypeKind::Primitive(
            PrimitiveType::I8
            | PrimitiveType::I16
            | PrimitiveType::I32
            | PrimitiveType::I64
            | PrimitiveType::I128
            | PrimitiveType::Isize,
        ) => {
            let bits = match kind {
                TypeKind::Primitive(PrimitiveType::I8) => 8,
                TypeKind::Primitive(PrimitiveType::I16) => 16,
                TypeKind::Primitive(PrimitiveType::I32) => 32,
                TypeKind::Primitive(PrimitiveType::I64 | PrimitiveType::Isize) => 64,
                TypeKind::Primitive(PrimitiveType::I128) => 128,
                _ => return None,
            };
            Some(1 + decimal_digits((1_u128 << (bits - 1)) - 1))
        }
        _ => None,
    }
}

fn valid_actor_state_operation(
    module: &SemanticWir,
    function: &SemanticFunction,
    results: &[ValueId],
    actor: ActorId,
    region: RegionId,
    proof: ProofId,
    stored: Option<ValueId>,
) -> bool {
    let Some(actor_record) = module.actors.get(actor.0 as usize) else {
        return false;
    };
    let Some(region_record) = module.regions.get(region.0 as usize) else {
        return false;
    };
    let Some(proof_record) = module.proofs.get(proof.0 as usize) else {
        return false;
    };
    let u64_value = |value: ValueId| {
        function.values.get(value.0 as usize).is_some_and(|value| {
            module
                .types
                .get(value.ty.0 as usize)
                .is_some_and(|ty| ty.kind == TypeKind::Primitive(PrimitiveType::U64))
        })
    };
    function.role == FunctionRole::ActorTurn(actor)
        && region_record.owner == ImageOwner::Actor(actor)
        && region_record.class == RegionClass::Image
        && region_record.capacity_bytes == 8
        && region_record.alignment == 8
        && region_record.proof == proof
        && region_record.name.strip_suffix(".state") == Some(actor_record.name.as_str())
        && proof_record.kind == ProofKind::CapacityBound
        && proof_record.bound == Some(1)
        && proof_record.sources.as_slice() == [region_record.source]
        && proof_record.depends_on.is_empty()
        && match stored {
            None => matches!(results, [result] if u64_value(*result)),
            Some(value) => results.is_empty() && u64_value(value),
        }
}

fn valid_promotion_operation(
    module: &SemanticWir,
    function: &SemanticFunction,
    results: &[ValueId],
    value: ValueId,
    destination: RegionId,
    proof: ProofId,
) -> bool {
    let FunctionRole::ActorTurn(actor) = function.role else {
        return false;
    };
    let Some(value) = function.values.get(value.0 as usize) else {
        return false;
    };
    let Some(ty) = module.types.get(value.ty.0 as usize) else {
        return false;
    };
    let Some(region) = module.regions.get(destination.0 as usize) else {
        return false;
    };
    let Some(proof) = module.proofs.get(proof.0 as usize) else {
        return false;
    };
    results.is_empty()
        && ty.kind == TypeKind::Primitive(PrimitiveType::U64)
        && region.owner == ImageOwner::Actor(actor)
        && region.class == RegionClass::Image
        && region.capacity_bytes == 8
        && region.alignment == 8
        && proof.kind == ProofKind::RegionBound
        && proof.subject.starts_with("alloc:")
        && proof.bound == Some(8)
        && proof.sources.len() == 1
        && proof.depends_on.is_empty()
        && proof.explanation.as_slice()
            == ["actor state store outlives its non-reentrant turn frame"]
}

fn use_value(function: &SemanticFunction, value: ValueId, errors: &mut ValidationErrorSink<'_>) {
    if errors.poll() {
        return;
    }
    if value.0 as usize >= function.values.len() {
        errors.push(ValidationError::UnknownValue {
            function: function.id,
            value,
        });
    }
}

fn define_value(
    function: FunctionId,
    value: ValueId,
    definitions: &mut [u8],
    errors: &mut ValidationErrorSink<'_>,
) {
    if errors.poll() {
        return;
    }
    let Some(count) = definitions.get_mut(value.0 as usize) else {
        errors.push(ValidationError::UnknownValue { function, value });
        return;
    };
    *count = count.saturating_add(1);
}

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut ValidationErrorSink<'_>) {
    if errors.poll() {
        return;
    }
    if id as usize >= length {
        errors.push(ValidationError::UnknownReference { kind, id });
    }
}

fn require_canonical_ids(
    kind: &'static str,
    owner: u32,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationErrorSink<'_>,
) {
    let mut previous = None;
    for id in ids {
        if errors.poll() {
            return;
        }
        if previous.is_some_and(|previous| previous >= id) {
            errors.push(ValidationError::NonCanonicalReferences { kind, owner });
            return;
        }
        previous = Some(id);
    }
}

fn validate_acyclic<'a, T: 'a>(
    kind: &'static str,
    node_count: usize,
    edges: impl Fn(usize) -> &'a [T],
    edge_id: impl Fn(&T) -> u32,
    errors: &mut ValidationErrorSink<'_>,
) {
    let mut colors = Vec::new();
    if colors.try_reserve_exact(node_count).is_err() {
        errors.scratch_allocation_failed();
        return;
    }
    colors.resize(node_count, 0_u8);
    let mut work = Vec::new();
    for root in 0..node_count {
        if errors.poll() {
            return;
        }
        if colors[root] != 0 {
            continue;
        }
        colors[root] = 1;
        if work.try_reserve(1).is_err() {
            errors.scratch_allocation_failed();
            return;
        }
        work.push((root, 0_usize));
        while let Some((node, next_edge)) = work.pop() {
            if errors.poll() {
                return;
            }
            let adjacent = edges(node);
            let Some(edge) = adjacent.get(next_edge) else {
                colors[node] = 2;
                continue;
            };
            if work.try_reserve(1).is_err() {
                errors.scratch_allocation_failed();
                return;
            }
            work.push((node, next_edge + 1));
            let edge = edge_id(edge) as usize;
            if edge >= node_count || colors[edge] == 2 {
                continue;
            }
            if colors[edge] == 1 {
                errors.push(ValidationError::CyclicReferences(kind));
                return;
            }
            colors[edge] = 1;
            if work.try_reserve(1).is_err() {
                errors.scratch_allocation_failed();
                return;
            }
            work.push((edge, 0));
        }
    }
}

fn check_dense(
    kind: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationErrorSink<'_>,
) {
    for (expected, actual) in ids.into_iter().enumerate() {
        if errors.poll() {
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
    UnknownReference {
        kind: &'static str,
        id: u32,
    },
    UnknownValue {
        function: FunctionId,
        value: ValueId,
    },
    InvalidAssertionDescriptor {
        function: FunctionId,
    },
    RootParameterMismatch(FunctionId),
    ValueDefinitionCount {
        function: FunctionId,
        value: ValueId,
        definitions: u8,
    },
    NonCanonicalReferences {
        kind: &'static str,
        owner: u32,
    },
    CyclicReferences(&'static str),
    InvalidRecord {
        kind: &'static str,
        id: u32,
    },
    UnknownImageEntry(FunctionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid SemanticWir validation limits"),
            Self::Cancelled => formatter.write_str("SemanticWir validation cancelled"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "SemanticWir {resource} exceeds limit {limit}")
            }
            Self::TooManyErrors { limit } => {
                write!(
                    formatter,
                    "SemanticWir validation exceeded error limit {limit}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported SemanticWir version {version}")
            }
            Self::MissingImageName => formatter.write_str("SemanticWir has no image name"),
            Self::NonDenseId {
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "{kind} IDs must be dense: expected {expected}, found {actual}"
            ),
            Self::UnknownReference { kind, id } => write!(formatter, "unknown {kind} ID {id}"),
            Self::UnknownValue { function, value } => write!(
                formatter,
                "function {} references unknown value {}",
                function.0, value.0
            ),
            Self::InvalidAssertionDescriptor { function } => write!(
                formatter,
                "function {} has an invalid runtime assertion descriptor",
                function.0
            ),
            Self::RootParameterMismatch(function) => write!(
                formatter,
                "function {} root-region parameters do not match its signature",
                function.0
            ),
            Self::ValueDefinitionCount {
                function,
                value,
                definitions,
            } => write!(
                formatter,
                "function {} value {} has {definitions} definitions; expected exactly one",
                function.0, value.0
            ),
            Self::NonCanonicalReferences { kind, owner } => {
                write!(
                    formatter,
                    "{kind} for record {owner} are not sorted and unique"
                )
            }
            Self::CyclicReferences(kind) => write!(formatter, "{kind} graph contains a cycle"),
            Self::InvalidRecord { kind, id } => write!(formatter, "invalid {kind} record {id}"),
            Self::UnknownImageEntry(id) => {
                write!(formatter, "SemanticWir image entry {} is unknown", id.0)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SemanticWir validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

impl fmt::Display for ValidationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid SemanticWir validation limits"),
            Self::Cancelled => formatter.write_str("SemanticWir validation cancelled"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "SemanticWir {resource} exceeds limit {limit}")
            }
            Self::Invalid(errors) => errors.fmt(formatter),
        }
    }
}

impl std::error::Error for ValidationFailure {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_source::{FileId, TextRange};

    fn fixture() -> SemanticWir {
        let digest = Sha256Digest::from_bytes([2; 32]);
        SemanticWir {
            version: SEMANTIC_WIR_VERSION,
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
                hir_files: 1,
                hir_declarations: 1,
                reachable_declarations: 1,
                monomorphized_instantiations: 1,
                resolved_interface_calls: 0,
            },
            types: vec![TypeRecord {
                id: TypeId(0),
                source_name: "unit".to_owned(),
                kind: TypeKind::Primitive(PrimitiveType::Unit),
                linearity: Linearity::CopyScalar,
                source: None,
            }],
            globals: Vec::new(),
            functions: vec![SemanticFunction {
                id: FunctionId(0),
                instance_key: digest,
                name: "entry".to_owned(),
                origin: FunctionOrigin::GeneratedImageEntry { constructor: 0 },
                role: FunctionRole::ImageEntry,
                color: FunctionColor::Sync,
                parameters: Vec::new(),
                result: TypeId(0),
                values: Vec::new(),
                body: SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![SemanticStatement::Return(Vec::new())],
                },
                effects: EffectSet(0),
                proofs: Vec::new(),
                source: None,
                stack_bound: 0,
                frame_bound: 0,
                uninterrupted_bound: None,
                recursive_depth_bound: Some(1),
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            activations: Vec::new(),
            scopes: Vec::new(),
            proofs: Vec::new(),
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![ImageOwner::Runtime],
            shutdown_order: vec![ImageOwner::Runtime],
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
    }

    fn span(file: u32) -> Span {
        Span {
            file: FileId(file),
            range: TextRange { start: 0, end: 0 },
        }
    }

    fn source_function(id: u32, key_byte: u8) -> SemanticFunction {
        SemanticFunction {
            id: FunctionId(id),
            instance_key: Sha256Digest::from_bytes([key_byte; 32]),
            name: format!("source-{id}"),
            origin: FunctionOrigin::Source,
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: Vec::new(),
            result: TypeId(0),
            values: Vec::new(),
            body: SemanticRegion {
                parameters: Vec::new(),
                statements: vec![SemanticStatement::Return(Vec::new())],
            },
            effects: EffectSet(0),
            proofs: Vec::new(),
            source: Some(span(0)),
            stack_bound: 0,
            frame_bound: 0,
            uninterrupted_bound: None,
            recursive_depth_bound: Some(1),
        }
    }

    fn bounded_string_fixture() -> SemanticWir {
        let mut module = fixture();
        module.types.extend([
            TypeRecord {
                id: TypeId(1),
                source_name: "bool".to_owned(),
                kind: TypeKind::Primitive(PrimitiveType::Bool),
                linearity: Linearity::CopyScalar,
                source: None,
            },
            TypeRecord {
                id: TypeId(2),
                source_name: "Static[Str]".to_owned(),
                kind: TypeKind::StaticString { bytes: 2 },
                linearity: Linearity::ExplicitCopy,
                source: None,
            },
            TypeRecord {
                id: TypeId(3),
                source_name: "BoundedString".to_owned(),
                kind: TypeKind::BoundedString { capacity: 10 },
                linearity: Linearity::Reclaimable,
                source: None,
            },
        ]);
        let source = |start, end| Span {
            file: FileId(0),
            range: TextRange { start, end },
        };
        let mut function = source_function(1, 3);
        function.values = vec![
            SemanticValue {
                id: ValueId(0),
                ty: TypeId(2),
                origin: Some(source(1, 3)),
                name: Some("label".to_owned()),
            },
            SemanticValue {
                id: ValueId(1),
                ty: TypeId(1),
                origin: Some(source(4, 5)),
                name: Some("ready".to_owned()),
            },
            SemanticValue {
                id: ValueId(2),
                ty: TypeId(3),
                origin: Some(source(10, 15)),
                name: Some("rendered".to_owned()),
            },
        ];
        function.body.statements = vec![
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(0)],
                operation: SemanticOperation::Constant(Constant::String("ok".to_owned())),
                source: Some(source(1, 3)),
            }),
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(1)],
                operation: SemanticOperation::Constant(Constant::Bool(true)),
                source: Some(source(4, 5)),
            }),
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(2)],
                operation: SemanticOperation::FormatBoundedString {
                    ty: TypeId(3),
                    parts: vec![
                        BoundedStringPart::Text {
                            value: "x=".to_owned(),
                            source: source(10, 12),
                        },
                        BoundedStringPart::Bool {
                            value: ValueId(1),
                            source: source(12, 13),
                        },
                        BoundedStringPart::Text {
                            value: "/".to_owned(),
                            source: source(13, 14),
                        },
                        BoundedStringPart::StaticString {
                            value: ValueId(0),
                            bytes: 2,
                            source: source(14, 15),
                        },
                    ],
                },
                source: Some(source(10, 15)),
            }),
            SemanticStatement::Return(Vec::new()),
        ];
        module.functions.push(function);
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    fn static_bytes_fixture() -> SemanticWir {
        let mut module = fixture();
        module.types.push(TypeRecord {
            id: TypeId(1),
            source_name: "Static[Bytes[3]]".to_owned(),
            kind: TypeKind::StaticBytes { bytes: 3 },
            linearity: Linearity::ExplicitCopy,
            source: None,
        });
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 1, end: 8 },
        };
        let mut function = source_function(1, 4);
        function.values.push(SemanticValue {
            id: ValueId(0),
            ty: TypeId(1),
            origin: Some(source),
            name: Some("payload".to_owned()),
        });
        function.body.statements = vec![
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(0)],
                operation: SemanticOperation::Constant(Constant::Bytes(vec![b'A', b'B', 0])),
                source: Some(source),
            }),
            SemanticStatement::Return(Vec::new()),
        ];
        module.functions.push(function);
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    fn insert_field_fixture() -> SemanticWir {
        let mut module = fixture();
        module.types.push(TypeRecord {
            id: TypeId(1),
            source_name: "u64".to_owned(),
            kind: TypeKind::Primitive(PrimitiveType::U64),
            linearity: Linearity::CopyScalar,
            source: None,
        });
        module.types.push(TypeRecord {
            id: TypeId(2),
            source_name: "Cell".to_owned(),
            kind: TypeKind::Struct {
                fields: vec![FieldType {
                    name: "value".to_owned(),
                    ty: TypeId(1),
                    public: false,
                }],
            },
            linearity: Linearity::ExplicitCopy,
            source: None,
        });
        let source = span(0);
        module.functions.push(SemanticFunction {
            id: FunctionId(1),
            instance_key: Sha256Digest::from_bytes([3; 32]),
            name: "replace-cell-value".to_owned(),
            origin: FunctionOrigin::Source,
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: vec![ValueId(0), ValueId(1)],
            result: TypeId(2),
            values: vec![
                SemanticValue {
                    id: ValueId(0),
                    ty: TypeId(2),
                    origin: Some(source),
                    name: Some("cell".to_owned()),
                },
                SemanticValue {
                    id: ValueId(1),
                    ty: TypeId(1),
                    origin: Some(source),
                    name: Some("value".to_owned()),
                },
                SemanticValue {
                    id: ValueId(2),
                    ty: TypeId(2),
                    origin: Some(source),
                    name: Some("updated".to_owned()),
                },
            ],
            body: SemanticRegion {
                parameters: vec![ValueId(0), ValueId(1)],
                statements: vec![
                    SemanticStatement::Let(LetStatement {
                        results: vec![ValueId(2)],
                        operation: SemanticOperation::InsertField {
                            aggregate: ValueId(0),
                            field: 0,
                            value: ValueId(1),
                        },
                        source: Some(source),
                    }),
                    SemanticStatement::Return(vec![ValueId(2)]),
                ],
            },
            effects: EffectSet(0),
            proofs: Vec::new(),
            source: Some(source),
            stack_bound: 0,
            frame_bound: 0,
            uninterrupted_bound: None,
            recursive_depth_bound: Some(1),
        });
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    #[test]
    fn bounded_string_construction_authenticates_parts_extents_capacity_and_result() {
        bounded_string_fixture()
            .validate()
            .expect("canonical bounded string construction");

        let mut empty_static = bounded_string_fixture();
        empty_static.types[2].kind = TypeKind::StaticString { bytes: 0 };
        empty_static.types[3].kind = TypeKind::BoundedString { capacity: 8 };
        let SemanticStatement::Let(LetStatement {
            operation: SemanticOperation::Constant(Constant::String(value)),
            ..
        }) = &mut empty_static.functions[1].body.statements[0]
        else {
            panic!("static string constant")
        };
        value.clear();
        let SemanticStatement::Let(LetStatement {
            operation: SemanticOperation::FormatBoundedString { parts, .. },
            ..
        }) = &mut empty_static.functions[1].body.statements[2]
        else {
            panic!("bounded string operation")
        };
        let BoundedStringPart::StaticString { bytes, .. } = &mut parts[3] else {
            panic!("static string part")
        };
        *bytes = 0;
        empty_static
            .validate()
            .expect("empty Static[Str] retains exact zero extent");

        let mutate_operation =
            |module: &mut SemanticWir,
             mutate: &dyn Fn(&mut TypeId, &mut Vec<BoundedStringPart>)| {
                let SemanticStatement::Let(LetStatement {
                    operation: SemanticOperation::FormatBoundedString { ty, parts },
                    ..
                }) = &mut module.functions[1].body.statements[2]
                else {
                    panic!("bounded string operation")
                };
                mutate(ty, parts);
            };

        let mut forged_capacity = bounded_string_fixture();
        forged_capacity.types[3].kind = TypeKind::BoundedString { capacity: 11 };
        assert!(forged_capacity.validate().is_err());

        let mut forged_extent = bounded_string_fixture();
        mutate_operation(&mut forged_extent, &|_, parts| {
            let BoundedStringPart::StaticString { bytes, .. } = &mut parts[3] else {
                panic!("static string part")
            };
            *bytes = 3;
        });
        assert!(forged_extent.validate().is_err());

        let mut reordered = bounded_string_fixture();
        mutate_operation(&mut reordered, &|_, parts| parts.swap(0, 1));
        assert!(reordered.validate().is_err());

        let mut wrong_result = bounded_string_fixture();
        wrong_result.functions[1].values[2].ty = TypeId(1);
        assert!(wrong_result.validate().is_err());

        let mut wrong_value_kind = bounded_string_fixture();
        mutate_operation(&mut wrong_value_kind, &|_, parts| {
            let BoundedStringPart::Bool { value, .. } = &mut parts[1] else {
                panic!("bool part")
            };
            *value = ValueId(0);
        });
        assert!(wrong_value_kind.validate().is_err());
    }

    #[test]
    fn static_bytes_constant_authenticates_canonical_identity_and_exact_extent() {
        static_bytes_fixture()
            .validate()
            .expect("canonical static bytes constant");

        let mut forged_extent = static_bytes_fixture();
        let SemanticStatement::Let(LetStatement {
            operation: SemanticOperation::Constant(Constant::Bytes(bytes)),
            ..
        }) = &mut forged_extent.functions[1].body.statements[0]
        else {
            panic!("static bytes constant")
        };
        bytes.push(1);
        assert!(forged_extent.validate().is_err());

        let mut forged_name = static_bytes_fixture();
        forged_name.types[1].source_name = "Static[Bytes[03]]".to_owned();
        assert!(forged_name.validate().is_err());

        let mut forged_kind = static_bytes_fixture();
        let SemanticStatement::Let(LetStatement { operation, .. }) =
            &mut forged_kind.functions[1].body.statements[0]
        else {
            panic!("static bytes constant")
        };
        *operation = SemanticOperation::Constant(Constant::String("AB\0".to_owned()));
        assert!(forged_kind.validate().is_err());

        let mut forged_linearity = static_bytes_fixture();
        forged_linearity.types[1].linearity = Linearity::CopyScalar;
        assert!(forged_linearity.validate().is_err());
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
            let SemanticStatement::Let(statement) = &mut forged.functions[1].body.statements[0]
            else {
                panic!("fixture insertion statement")
            };
            statement.operation = SemanticOperation::InsertField {
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
                    id: 2
                }
            )));
        }

        for results in [Vec::new(), vec![ValueId(2), ValueId(2)]] {
            let mut forged = module.clone();
            let SemanticStatement::Let(statement) = &mut forged.functions[1].body.statements[0]
            else {
                panic!("fixture insertion statement")
            };
            statement.results = results;
            let errors = forged
                .validate()
                .expect_err("non-singleton insertion result must fail")
                .0;
            assert!(errors.iter().any(|error| matches!(
                error,
                ValidationError::InvalidRecord {
                    kind: "field insertion",
                    ..
                }
            )));
        }
    }

    fn closed_enum_fixture(variants: usize) -> SemanticWir {
        let mut module = fixture();
        module.types.push(TypeRecord {
            id: TypeId(1),
            source_name: "u8".to_owned(),
            kind: TypeKind::Primitive(PrimitiveType::U8),
            linearity: Linearity::CopyScalar,
            source: None,
        });
        module.types.push(TypeRecord {
            id: TypeId(2),
            source_name: "LocalResult".to_owned(),
            kind: TypeKind::Enum {
                variants: (0..variants)
                    .map(|index| VariantType {
                        name: format!("V{index}"),
                        fields: vec![FieldType {
                            name: String::new(),
                            ty: TypeId(1),
                            public: true,
                        }],
                    })
                    .collect(),
            },
            linearity: Linearity::ExplicitCopy,
            source: None,
        });
        let mut function = source_function(1, 3);
        function.result = TypeId(2);
        function.parameters = vec![ValueId(0)];
        function.values = vec![
            SemanticValue {
                id: ValueId(0),
                ty: TypeId(1),
                origin: Some(span(0)),
                name: Some("payload".to_owned()),
            },
            SemanticValue {
                id: ValueId(1),
                ty: TypeId(2),
                origin: Some(span(0)),
                name: Some("result".to_owned()),
            },
        ];
        function.body = SemanticRegion {
            parameters: vec![ValueId(0)],
            statements: vec![
                SemanticStatement::Let(LetStatement {
                    results: vec![ValueId(1)],
                    operation: SemanticOperation::ConstructEnum {
                        ty: TypeId(2),
                        variant: u32::try_from(variants.saturating_sub(1).min(255))
                            .expect("bounded variant"),
                        payload: Some(ValueId(0)),
                    },
                    source: Some(span(0)),
                }),
                SemanticStatement::Return(vec![ValueId(1)]),
            ],
        };
        module.functions.push(function);
        module.source_summary.hir_declarations = 2;
        module.source_summary.reachable_declarations = 2;
        module.source_summary.monomorphized_instantiations = 2;
        module
    }

    fn async_actor_fixture() -> SemanticWir {
        let mut module = fixture();
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 10, end: 20 },
        };
        module.source_summary.hir_declarations = 3;
        module.source_summary.reachable_declarations = 3;
        module.source_summary.monomorphized_instantiations = 3;
        module.functions[0].proofs = vec![
            ProofId(3),
            ProofId(4),
            ProofId(5),
            ProofId(6),
            ProofId(7),
            ProofId(9),
        ];
        let mut caller = source_function(1, 3);
        caller.name = "actor-turn".to_owned();
        caller.role = FunctionRole::ActorTurn(ActorId(0));
        caller.color = FunctionColor::Async;
        caller.effects = EffectSet(EffectSet::ACTOR_CALL | EffectSet::SUSPEND);
        caller.values = vec![
            SemanticValue {
                id: ValueId(0),
                ty: TypeId(0),
                origin: Some(source),
                name: None,
            },
            SemanticValue {
                id: ValueId(1),
                ty: TypeId(0),
                origin: Some(source),
                name: None,
            },
        ];
        caller.body.statements = vec![
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(0)],
                operation: SemanticOperation::Call {
                    function: FunctionId(2),
                    arguments: Vec::new(),
                    activation: Some(ActivationId(0)),
                },
                source: Some(source),
            }),
            SemanticStatement::Let(LetStatement {
                results: vec![ValueId(1)],
                operation: SemanticOperation::Await {
                    awaitable: ValueId(0),
                },
                source: Some(source),
            }),
            SemanticStatement::Return(Vec::new()),
        ];
        caller.stack_bound = 8;
        caller.frame_bound = 8;
        caller.proofs = vec![ProofId(8)];
        let mut callee = source_function(2, 4);
        callee.name = "async-helper".to_owned();
        callee.color = FunctionColor::Async;
        callee.effects = EffectSet(EffectSet::SUSPEND);
        callee.stack_bound = 8;
        callee.frame_bound = 8;
        callee.proofs = vec![ProofId(2)];
        module.functions.extend([caller, callee]);
        module.actors = vec![ActorInstance {
            id: ActorId(0),
            name: "actor".to_owned(),
            ty: TypeId(0),
            priority: 1,
            mailbox_capacity: 1,
            message_types: Vec::new(),
            turn_functions: vec![FunctionId(1)],
            supervisor: None,
        }];
        let proof = |id, kind, subject: &str, sources, depends_on, bound| ProofRecord {
            id: ProofId(id),
            kind,
            subject: subject.to_owned(),
            bound,
            sources,
            depends_on,
            explanation: vec![format!("proof {id} is sealed")],
        };
        module.proofs = vec![
            proof(
                0,
                ProofKind::TypeChecked,
                "actor image types",
                vec![source],
                Vec::new(),
                None,
            ),
            proof(
                1,
                ProofKind::EffectsAllowed,
                "actor image effects",
                vec![source],
                vec![ProofId(0)],
                None,
            ),
            proof(
                2,
                ProofKind::CleanupAcyclic,
                "helper cleanup",
                vec![source],
                Vec::new(),
                Some(0),
            ),
            proof(
                3,
                ProofKind::CapacityBound,
                "mailbox capacity",
                vec![source],
                Vec::new(),
                Some(1),
            ),
            proof(
                4,
                ProofKind::CapacityBound,
                "turn capacity",
                vec![source],
                Vec::new(),
                Some(1),
            ),
            proof(
                5,
                ProofKind::WaitGraphAcyclic,
                "closed wait graph",
                vec![source],
                vec![ProofId(1)],
                Some(1),
            ),
            proof(
                6,
                ProofKind::SupervisionComplete,
                "complete static actor/task parent topology",
                vec![source],
                vec![ProofId(0)],
                Some(1),
            ),
            proof(
                7,
                ProofKind::CapacityBound,
                "base actor allocation",
                vec![source, source],
                vec![
                    ProofId(0),
                    ProofId(1),
                    ProofId(3),
                    ProofId(4),
                    ProofId(5),
                    ProofId(6),
                ],
                Some(24),
            ),
            proof(
                8,
                ProofKind::CapacityBound,
                "call activation",
                vec![source],
                vec![ProofId(2)],
                Some(1),
            ),
            proof(
                9,
                ProofKind::ImageClosed,
                "closed actor image",
                vec![source],
                vec![ProofId(7), ProofId(8)],
                Some(32),
            ),
        ];
        module.proofs[6].explanation = vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()];
        module.regions = vec![
            RegionRecord {
                id: RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                owner: ImageOwner::Actor(ActorId(0)),
                proof: ProofId(3),
                source,
            },
            RegionRecord {
                id: RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                owner: ImageOwner::Actor(ActorId(0)),
                proof: ProofId(4),
                source,
            },
            RegionRecord {
                id: RegionId(2),
                name: "actor-turn.async-activation-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                owner: ImageOwner::Actor(ActorId(0)),
                proof: ProofId(8),
                source,
            },
        ];
        module.activations = vec![ActivationPlan {
            id: ActivationId(0),
            caller: FunctionId(1),
            callee: FunctionId(2),
            region: RegionId(2),
            frame_bytes: 8,
            maximum_live: 1,
            cancellation: ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: ProofId(8),
            source,
        }];
        module.startup_order = vec![ImageOwner::Runtime, ImageOwner::Actor(ActorId(0))];
        module.shutdown_order = vec![ImageOwner::Actor(ActorId(0)), ImageOwner::Runtime];
        module.static_bytes = 32;
        module.peak_bytes = 32;
        module
    }

    #[test]
    fn v6_actor_activation_capacity_contract_rejects_substitution_and_overflow() {
        async_actor_fixture()
            .validate()
            .expect("valid source-level actor activation contract");

        let mut substituted_supervision = async_actor_fixture();
        substituted_supervision.proofs[6].kind = ProofKind::Ownership;
        assert!(substituted_supervision.validate().is_err());

        let mut detached_supervision = async_actor_fixture();
        detached_supervision.proofs[7]
            .depends_on
            .retain(|dependency| *dependency != ProofId(6));
        assert!(detached_supervision.validate().is_err());

        let mut nested_actor_parent = async_actor_fixture();
        nested_actor_parent.actors[0].supervisor = Some(ActorId(0));
        assert!(nested_actor_parent.validate().is_err());

        let mut missing_caller_attachment = async_actor_fixture();
        missing_caller_attachment.functions[1].proofs.clear();
        assert!(missing_caller_attachment.validate().is_err());

        let mut substituted_source = async_actor_fixture();
        substituted_source.activations[0].source.range.start += 1;
        assert!(substituted_source.validate().is_err());

        let mut substituted_base_source = async_actor_fixture();
        substituted_base_source.proofs[7].sources[1].range.start += 1;
        assert!(substituted_base_source.validate().is_err());

        let mut omitted_cleanup = async_actor_fixture();
        omitted_cleanup.functions[2].proofs.clear();
        assert!(omitted_cleanup.validate().is_err());

        let mut over_live = async_actor_fixture();
        over_live.activations[0].maximum_live = 2;
        over_live.regions[2].capacity_bytes = 16;
        over_live.proofs[8].bound = Some(2);
        over_live.proofs[9].bound = Some(40);
        over_live.static_bytes = 40;
        over_live.peak_bytes = 40;
        assert!(over_live.validate().is_err());

        let mut renamed_region = async_actor_fixture();
        renamed_region.regions[2].name = "forged.async-activation-frame".to_owned();
        assert!(renamed_region.validate().is_err());

        let mut overflow = async_actor_fixture();
        overflow.functions[2].frame_bound = u64::MAX;
        overflow.activations[0].frame_bytes = u64::MAX;
        overflow.regions[2].capacity_bytes = u64::MAX;
        assert!(overflow.validate().is_err());

        let mut orphan_role = async_actor_fixture();
        orphan_role.actors[0].turn_functions.clear();
        assert!(orphan_role.validate().is_err());

        let mut long_name = async_actor_fixture();
        long_name.actors[0].name = "a".repeat(32 * 1024);
        long_name.regions[0].name = format!("{}.mailbox", long_name.actors[0].name);
        long_name.regions[1].name = format!("{}.turn-frame", long_name.actors[0].name);
        let polls = Cell::new(0_u32);
        let cancellation = || {
            let next = polls.get() + 1;
            polls.set(next);
            next > 5
        };
        let mut errors = ValidationErrorSink::new(100, &cancellation);
        validate_actor_capacity_contract(&long_name, &mut errors);
        assert_eq!(errors.finish(), Err(ValidationFailure::Cancelled));
        assert!(polls.get() > 5);
    }

    #[test]
    fn seals_exact_generated_image_entry_contract() {
        fixture().validate().expect("valid SemanticWir");

        let mut forged = fixture();
        forged.functions[0].origin = FunctionOrigin::Source;
        assert!(forged.validate().is_err());

        let mut stale_constructor = fixture();
        stale_constructor.functions[0].origin =
            FunctionOrigin::GeneratedImageEntry { constructor: 1 };
        assert!(stale_constructor.validate().is_err());

        let mut runtime_source = fixture();
        runtime_source.functions[0].source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        });
        assert!(runtime_source.validate().is_err());

        let mut wrong_role = fixture();
        wrong_role.functions[0].role = FunctionRole::Ordinary;
        assert!(wrong_role.validate().is_err());

        let mut harness = fixture();
        harness.functions[0].origin = FunctionOrigin::GeneratedTestHarness { group: 0 };
        assert!(harness.validate().is_err());

        let mut source = fixture();
        source.functions[0].origin = FunctionOrigin::Source;
        source.functions[0].role = FunctionRole::Ordinary;
        source.functions[0].source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        });
        assert!(source.validate().is_err());

        let mut invalid_effect = fixture();
        invalid_effect.functions[0].effects = EffectSet(1 << 63);
        assert!(invalid_effect.validate().is_err());
    }

    #[test]
    fn v6_rejects_color_key_proof_order_and_span_substitution() {
        let mut v5 = fixture();
        v5.version = 5;
        let errors = v5.validate().expect_err("SemanticWir v5 is stale").0;
        assert!(errors.contains(&ValidationError::UnsupportedVersion(5)));

        let mut async_entry = fixture();
        async_entry.functions[0].color = FunctionColor::Async;
        assert!(async_entry.validate().is_err());

        let mut zero_key = fixture();
        zero_key.functions[0].instance_key = Sha256Digest::from_bytes([0; 32]);
        assert!(zero_key.validate().is_err());

        let mut duplicate_key = fixture();
        let mut duplicate = source_function(1, 3);
        duplicate.instance_key = duplicate_key.functions[0].instance_key;
        duplicate_key.functions.push(duplicate);
        duplicate_key.source_summary.monomorphized_instantiations = 2;
        let errors = duplicate_key
            .validate()
            .expect_err("duplicate instance key")
            .0;
        assert!(errors.iter().any(|error| matches!(
            error,
            ValidationError::InvalidRecord {
                kind: "function instance key",
                id: 1
            }
        )));

        let mut forward_proof = fixture();
        forward_proof.proofs = vec![
            ProofRecord {
                id: ProofId(0),
                kind: ProofKind::TypeChecked,
                subject: "first".to_owned(),
                bound: None,
                sources: Vec::new(),
                depends_on: vec![ProofId(1)],
                explanation: vec!["first proof".to_owned()],
            },
            ProofRecord {
                id: ProofId(1),
                kind: ProofKind::EffectsAllowed,
                subject: "second".to_owned(),
                bound: None,
                sources: Vec::new(),
                depends_on: Vec::new(),
                explanation: vec!["second proof".to_owned()],
            },
        ];
        assert!(forward_proof.validate().is_err());

        let mut invalid_type_span = fixture();
        invalid_type_span.types[0].source = Some(span(1));
        assert!(invalid_type_span.validate().is_err());

        let mut invalid_function_span = fixture();
        let mut function = source_function(1, 3);
        function.source = Some(span(1));
        invalid_function_span.functions.push(function);
        invalid_function_span
            .source_summary
            .monomorphized_instantiations = 2;
        assert!(invalid_function_span.validate().is_err());

        let mut invalid_value_span = fixture();
        let mut function = source_function(1, 3);
        function.parameters.push(ValueId(0));
        function.body.parameters.push(ValueId(0));
        function.values.push(SemanticValue {
            id: ValueId(0),
            ty: TypeId(0),
            origin: Some(span(1)),
            name: None,
        });
        invalid_value_span.functions.push(function);
        invalid_value_span
            .source_summary
            .monomorphized_instantiations = 2;
        assert!(invalid_value_span.validate().is_err());

        let mut invalid_statement_span = fixture();
        invalid_statement_span.functions[0].body.statements.insert(
            0,
            SemanticStatement::Let(LetStatement {
                results: Vec::new(),
                operation: SemanticOperation::Constant(Constant::Unit),
                source: Some(span(1)),
            }),
        );
        assert!(invalid_statement_span.validate().is_err());

        let mut missing_runtime_order = fixture();
        missing_runtime_order.startup_order.clear();
        assert!(missing_runtime_order.validate().is_err());
    }

    #[test]
    fn explicit_validation_policy_bounds_work_errors_and_cancellation() {
        let mut limits = ValidationLimits::standard();
        limits.payload_bytes = 1;
        assert!(matches!(
            fixture().validate_with_limits(limits, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: 1
            })
        ));

        let insufficient_work = ValidationLimits {
            validation_work: 1,
            ..ValidationLimits::standard()
        };
        assert!(matches!(
            fixture().validate_with_limits(insufficient_work, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: 1
            })
        ));

        let mut nested = Constant::Unit;
        for _ in 0..9 {
            nested = Constant::Aggregate(vec![nested]);
        }
        let mut deep_constant = fixture();
        deep_constant.globals.push(Global {
            id: GlobalId(0),
            name: "deep".to_owned(),
            ty: TypeId(0),
            initializer: nested,
            owner: ImageOwner::Runtime,
        });
        let shallow = ValidationLimits {
            nesting: 8,
            ..ValidationLimits::standard()
        };
        assert!(matches!(
            deep_constant.validate_with_limits(shallow, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "model nesting",
                limit: 8
            })
        ));

        assert_eq!(
            fixture().validate_with_limits(ValidationLimits::standard(), &|| true),
            Err(ValidationFailure::Cancelled)
        );

        let mut malformed = fixture();
        malformed.version = 0;
        malformed.name.clear();
        malformed.source_summary.reachable_declarations = 2;
        malformed.peak_bytes = 0;
        malformed.static_bytes = 1;
        let bounded_errors = ValidationLimits {
            errors: 2,
            ..ValidationLimits::standard()
        };
        let Err(ValidationFailure::Invalid(ValidationErrors(errors))) =
            malformed.validate_with_limits(bounded_errors, &|| false)
        else {
            panic!("malformed model must fail");
        };
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors.last(),
            Some(&ValidationError::TooManyErrors { limit: 2 })
        );

        let calls = Cell::new(0_u64);
        validate_model_resources(&fixture(), ValidationLimits::standard(), &|| {
            calls.set(calls.get() + 1);
            false
        })
        .expect("resource preflight");
        let preflight_calls = calls.get();
        calls.set(0);
        let result = fixture().validate_with_limits(ValidationLimits::standard(), &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next > preflight_calls + 3
        });
        assert_eq!(result, Err(ValidationFailure::Cancelled));
        assert!(calls.get() > preflight_calls);
    }

    #[test]
    fn closed_enum_accepts_exact_bounds_and_rejects_type_and_constructor_substitution() {
        closed_enum_fixture(1).validate().expect("one-variant enum");
        closed_enum_fixture(256)
            .validate()
            .expect("256-variant enum");
        for rejected in [13, 15] {
            let mut wrong_version = closed_enum_fixture(2);
            wrong_version.version = rejected;
            assert!(wrong_version.validate().is_err());
        }
        assert!(closed_enum_fixture(0).validate().is_err());
        assert!(closed_enum_fixture(257).validate().is_err());

        let mut heterogeneous = closed_enum_fixture(2);
        heterogeneous.types.push(TypeRecord {
            id: TypeId(3),
            source_name: "u16".to_owned(),
            kind: TypeKind::Primitive(PrimitiveType::U16),
            linearity: Linearity::CopyScalar,
            source: None,
        });
        let TypeKind::Enum { variants } = &mut heterogeneous.types[2].kind else {
            unreachable!();
        };
        variants[1].fields[0].ty = TypeId(3);
        let SemanticStatement::Let(statement) = &mut heterogeneous.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let SemanticOperation::ConstructEnum { variant, .. } = &mut statement.operation else {
            unreachable!();
        };
        *variant = 0;
        heterogeneous
            .clone()
            .validate()
            .expect("distinct scalar payload types remain a closed enum");
        let SemanticStatement::Let(statement) = &mut heterogeneous.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let SemanticOperation::ConstructEnum { variant, .. } = &mut statement.operation else {
            unreachable!();
        };
        *variant = 1;
        assert!(heterogeneous.validate().is_err());

        let mut blank = closed_enum_fixture(2);
        let TypeKind::Enum { variants } = &mut blank.types[2].kind else {
            unreachable!();
        };
        variants[0].name.clear();
        assert!(blank.validate().is_err());

        let mut duplicate = closed_enum_fixture(2);
        let TypeKind::Enum { variants } = &mut duplicate.types[2].kind else {
            unreachable!();
        };
        variants[1].name = variants[0].name.clone();
        assert!(duplicate.validate().is_err());

        let mut private_payload = closed_enum_fixture(2);
        let TypeKind::Enum { variants } = &mut private_payload.types[2].kind else {
            unreachable!();
        };
        variants[0].fields[0].public = false;
        assert!(private_payload.validate().is_err());

        let mut wrong_payload = closed_enum_fixture(2);
        wrong_payload.functions[1].values[0].ty = TypeId(0);
        assert!(wrong_payload.validate().is_err());

        let mut wrong_variant = closed_enum_fixture(2);
        let SemanticStatement::Let(statement) = &mut wrong_variant.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let SemanticOperation::ConstructEnum { variant, .. } = &mut statement.operation else {
            unreachable!();
        };
        *variant = 2;
        assert!(wrong_variant.validate().is_err());

        let mut mixed_arity = closed_enum_fixture(2);
        let TypeKind::Enum { variants } = &mut mixed_arity.types[2].kind else {
            unreachable!();
        };
        variants[0].fields.clear();
        mixed_arity
            .clone()
            .validate()
            .expect("unit plus unary enum is canonical");
        let mut wrong_presence = mixed_arity.clone();
        let SemanticStatement::Let(statement) = &mut wrong_presence.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let SemanticOperation::ConstructEnum { variant, .. } = &mut statement.operation else {
            unreachable!();
        };
        *variant = 0;
        assert!(wrong_presence.validate().is_err());
        let SemanticStatement::Let(statement) = &mut mixed_arity.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let SemanticOperation::ConstructEnum { payload, .. } = &mut statement.operation else {
            unreachable!();
        };
        *payload = None;
        assert!(mixed_arity.validate().is_err());
    }

    #[test]
    fn closed_enum_accepts_exact_flat_structure_payload_and_rejects_nominal_forgery() {
        let mut module = closed_enum_fixture(1);
        module.types.push(TypeRecord {
            id: TypeId(3),
            source_name: "u16".to_owned(),
            kind: TypeKind::Primitive(PrimitiveType::U16),
            linearity: Linearity::CopyScalar,
            source: None,
        });
        module.types[1] = TypeRecord {
            id: TypeId(1),
            source_name: "Detail".to_owned(),
            kind: TypeKind::Struct {
                fields: vec![FieldType {
                    name: "word".to_owned(),
                    ty: TypeId(3),
                    public: true,
                }],
            },
            linearity: Linearity::ExplicitCopy,
            source: None,
        };
        module
            .clone()
            .validate()
            .expect("flat-structure enum payload");

        let TypeKind::Struct { fields } = &mut module.types[1].kind else {
            panic!("fixture structure payload")
        };
        fields[0].ty = TypeId(2);
        let errors = module
            .validate()
            .expect_err("enum-valued nominal field forgery must fail")
            .0;
        assert!(errors.iter().any(|error| matches!(
            error,
            ValidationError::InvalidRecord {
                kind: "closed enum type",
                id: 2
            }
        )));
    }

    #[test]
    fn loop_carried_values_have_distinct_entry_header_and_exit_definitions() {
        let mut wir = fixture();
        let function = &mut wir.functions[0];
        function.parameters = vec![ValueId(0)];
        function.values = (0..3)
            .map(|id| SemanticValue {
                id: ValueId(id),
                ty: TypeId(0),
                origin: None,
                name: None,
            })
            .collect();
        function.body.parameters = vec![ValueId(0)];
        function.body.statements = vec![
            SemanticStatement::Loop {
                body: SemanticRegion {
                    parameters: vec![ValueId(1)],
                    statements: vec![SemanticStatement::Continue(vec![ValueId(1)])],
                },
                carried: vec![ValueId(0), ValueId(1), ValueId(2)],
                uninterrupted_bound: Some(1),
                source: None,
            },
            SemanticStatement::Return(vec![ValueId(2)]),
        ];
        wir.clone()
            .validate()
            .expect("canonical cyclic SSA loop bracket");

        let SemanticStatement::Loop { carried, .. } = &mut wir.functions[0].body.statements[0]
        else {
            unreachable!();
        };
        carried[1] = ValueId(0);
        assert!(
            wir.validate().is_err(),
            "header must be the loop body's unique parameter definition"
        );
    }

    #[test]
    fn deep_proof_dag_is_validated_iteratively() {
        let mut wir = fixture();
        for id in 0..4_096_u32 {
            wir.proofs.push(ProofRecord {
                id: ProofId(id),
                kind: ProofKind::TypeChecked,
                subject: format!("proof-{id}"),
                bound: None,
                sources: Vec::new(),
                depends_on: id.checked_sub(1).map(ProofId).into_iter().collect(),
                explanation: vec!["validated".to_owned()],
            });
        }
        wir.validate().expect("deep prior-only proof DAG");
    }
}
