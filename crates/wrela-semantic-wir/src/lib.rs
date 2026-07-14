//! Structured, fully specialized whole-image semantic IR.
//!
//! `SemanticWir` is the first IR after successful semantic analysis. It retains
//! language operations whose ordering and failure behavior matter—actors,
//! async, regions, ownership, DMA, cleanup, and supervision—without syntax,
//! unresolved names, generics, interfaces, or target layout.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_source::Span;

pub const SEMANTIC_WIR_VERSION: u32 = 1;

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
    Tuple(Vec<TypeId>),
    Array { element: TypeId, length: u64 },
    Struct { fields: Vec<FieldType> },
    Enum { variants: Vec<VariantType> },
    Function(FunctionType),
    Iso { pool: PoolId, payload: TypeId },
    ActorHandle { actor_type: TypeId },
    Receipt { payload: TypeId, error: TypeId },
    DmaPayload { pool: PoolId, payload: TypeId },
    DmaShared { pool: PoolId, layout: TypeId },
    Mmio { layout: TypeId },
    Validated { format: TypeId, payload: TypeId },
    OpaqueTarget { name: String },
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
    Project {
        base: ValueId,
        field: u32,
        access: AccessMode,
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
    ActorSend {
        message: ValueId,
    },
    ActorTrySend {
        message: ValueId,
    },
    Await {
        awaitable: ValueId,
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
    GeneratedTestHarness { group: u32 },
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
    pub name: String,
    pub origin: FunctionOrigin,
    pub role: FunctionRole,
    pub color: FunctionColor,
    pub parameters: Vec<ValueId>,
    pub result: TypeId,
    pub values: Vec<SemanticValue>,
    pub body: SemanticRegion,
    pub effects: EffectSet,
    pub source: Option<Span>,
    pub stack_bound: u64,
    pub frame_bound: u64,
    pub uninterrupted_bound: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Global {
    pub id: GlobalId,
    pub name: String,
    pub ty: TypeId,
    pub initializer: Constant,
    pub owner: ImageOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    DefiniteInitialization,
    AccessExclusive,
    ViewDoesNotEscape,
    RegionBound,
    CapacityBound,
    WaitGraphAcyclic,
    CleanupAcyclic,
    IsrEffectSafe,
    DmaTransition,
    MmioPartition,
    DeviceValueValidated,
    WorkBound,
    StackBound,
    ReceiptLineage,
    ActorAsIf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRecord {
    pub id: ProofId,
    pub kind: ProofKind,
    pub subject: String,
    pub bound: Option<u64>,
    pub source: Option<Span>,
    pub depends_on: Vec<ProofId>,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestEntry {
    pub id: TestId,
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
    pub scopes: Vec<ScopePlan>,
    pub proofs: Vec<ProofRecord>,
    pub tests: Vec<TestEntry>,
    pub startup_order: Vec<ImageOwner>,
    pub shutdown_order: Vec<ImageOwner>,
    pub image_entry: FunctionId,
    pub static_bytes: u64,
    pub peak_bytes: u64,
}

impl SemanticWir {
    pub fn validate(self) -> Result<ValidatedSemanticWir, ValidationErrors> {
        let errors = validate_module(&self);
        if errors.is_empty() {
            Ok(ValidatedSemanticWir(self))
        } else {
            Err(ValidationErrors(errors))
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

fn validate_module(module: &SemanticWir) -> Vec<ValidationError> {
    let mut errors = Vec::new();
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
        validate_type(module, ty, &mut errors);
    }
    for global in &module.globals {
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        validate_constant(module, &global.initializer, &mut errors);
        validate_owner(module, global.owner, &mut errors);
    }
    for function in &module.functions {
        validate_function(module, function, &mut errors);
    }
    let mut actor_turns = vec![Vec::new(); module.actors.len()];
    let mut device_interrupts = vec![Vec::new(); module.devices.len()];
    for function in &module.functions {
        match function.role {
            FunctionRole::ActorTurn(actor) => {
                if let Some(turns) = actor_turns.get_mut(actor.0 as usize) {
                    turns.push(function.id);
                }
            }
            FunctionRole::Isr(device) => {
                if let Some(interrupts) = device_interrupts.get_mut(device.0 as usize) {
                    interrupts.push(function.id);
                }
            }
            FunctionRole::Ordinary
            | FunctionRole::TaskEntry(_)
            | FunctionRole::Cleanup
            | FunctionRole::ImageEntry
            | FunctionRole::Test => {}
        }
    }
    for actor in &module.actors {
        require_id("actor type", actor.ty.0, module.types.len(), &mut errors);
        for ty in &actor.message_types {
            require_id("actor message type", ty.0, module.types.len(), &mut errors);
        }
        for function in &actor.turn_functions {
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
        if actor_turns
            .get(actor.id.0 as usize)
            .is_none_or(|turns| actor.turn_functions != *turns)
        {
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
    for scope in &module.scopes {
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
    }
    validate_acyclic(
        "scope dependency",
        module.scopes.len(),
        |index| {
            module.scopes[index]
                .dependencies
                .iter()
                .map(|id| id.0)
                .collect()
        },
        &mut errors,
    );
    for proof in &module.proofs {
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
        |index| {
            module.proofs[index]
                .depends_on
                .iter()
                .map(|id| id.0)
                .collect()
        },
        &mut errors,
    );
    for test in &module.tests {
        require_id(
            "test function",
            test.function.0,
            module.functions.len(),
            &mut errors,
        );
        if test.name.trim().is_empty() || test.timeout_ns == 0 {
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
    let role_tests: std::collections::BTreeSet<_> = module
        .functions
        .iter()
        .filter(|function| function.role == FunctionRole::Test)
        .map(|function| function.id)
        .collect();
    let listed_tests: std::collections::BTreeSet<_> =
        module.tests.iter().map(|test| test.function).collect();
    if role_tests != listed_tests || listed_tests.len() != module.tests.len() {
        errors.push(ValidationError::InvalidRecord {
            kind: "test function set",
            id: 0,
        });
    }
    for owner in &module.startup_order {
        validate_owner(module, *owner, &mut errors);
    }
    for owner in &module.shutdown_order {
        validate_owner(module, *owner, &mut errors);
    }
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownImageEntry(module.image_entry));
    } else if module.functions[module.image_entry.0 as usize].role != FunctionRole::ImageEntry
        || module
            .functions
            .iter()
            .filter(|function| function.role == FunctionRole::ImageEntry)
            .count()
            != 1
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "image entry role",
            id: module.image_entry.0,
        });
    }
    if module.peak_bytes < module.static_bytes {
        errors.push(ValidationError::InvalidRecord {
            kind: "image memory plan",
            id: 0,
        });
    }
    errors
}

fn validate_type(module: &SemanticWir, ty: &TypeRecord, errors: &mut Vec<ValidationError>) {
    macro_rules! use_type {
        ($id:expr) => {
            require_id("type reference", ($id).0, module.types.len(), errors)
        };
    }
    match &ty.kind {
        TypeKind::Primitive(_) | TypeKind::OpaqueTarget { .. } => {}
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

fn validate_constant(module: &SemanticWir, constant: &Constant, errors: &mut Vec<ValidationError>) {
    match constant {
        Constant::Enum { fields, .. } | Constant::Aggregate(fields) => {
            for field in fields {
                validate_constant(module, field, errors);
            }
        }
        Constant::Zeroed(ty) => require_id("constant type", ty.0, module.types.len(), errors),
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

fn validate_owner(module: &SemanticWir, owner: ImageOwner, errors: &mut Vec<ValidationError>) {
    match owner {
        ImageOwner::Runtime | ImageOwner::BakedArtifact(_) => {}
        ImageOwner::Actor(id) => require_id("owner actor", id.0, module.actors.len(), errors),
        ImageOwner::Task(id) => require_id("owner task", id.0, module.tasks.len(), errors),
        ImageOwner::Device(id) => require_id("owner device", id.0, module.devices.len(), errors),
        ImageOwner::Pool(id) => require_id("owner pool", id.0, module.pools.len(), errors),
    }
}

fn validate_function(
    module: &SemanticWir,
    function: &SemanticFunction,
    errors: &mut Vec<ValidationError>,
) {
    let valid_origin = match function.origin {
        FunctionOrigin::Source => function.source.is_some(),
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
    if function.name.trim().is_empty()
        || !function.effects.is_valid()
        || !valid_origin
        || !valid_role
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
    }
    if function.body.parameters != function.parameters {
        errors.push(ValidationError::RootParameterMismatch(function.id));
    }
    let mut definitions = vec![0u8; function.values.len()];
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
    errors: &mut Vec<ValidationError>,
) {
    if !is_root {
        for parameter in &region.parameters {
            define_value(function.id, *parameter, definitions, errors);
        }
    }
    for statement in &region.statements {
        match statement {
            SemanticStatement::Let(statement) => {
                for result in &statement.results {
                    define_value(function.id, *result, definitions, errors);
                }
                validate_operation(module, function, &statement.operation, errors);
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
                validate_region(module, function, then_region, false, definitions, errors);
                validate_region(module, function, else_region, false, definitions, errors);
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
                for arm in arms {
                    for binding in &arm.bindings {
                        define_value(function.id, *binding, definitions, errors);
                    }
                    if let Some(guard) = arm.guard {
                        use_value(function, guard, errors);
                    }
                    validate_region(module, function, &arm.body, false, definitions, errors);
                }
            }
            SemanticStatement::Loop { body, carried, .. } => {
                for value in carried {
                    use_value(function, *value, errors);
                }
                validate_region(module, function, body, false, definitions, errors);
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

fn validate_operation(
    module: &SemanticWir,
    function: &SemanticFunction,
    operation: &SemanticOperation,
    errors: &mut Vec<ValidationError>,
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
        SemanticOperation::Constant(constant) => validate_constant(module, constant, errors),
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
        SemanticOperation::Project { base, .. } => value!(*base),
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
        SemanticOperation::Call {
            function: callee,
            arguments,
        } => {
            require_id("callee", callee.0, module.functions.len(), errors);
            for item in arguments {
                argument!(item);
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

fn use_value(function: &SemanticFunction, value: ValueId, errors: &mut Vec<ValidationError>) {
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
    errors: &mut Vec<ValidationError>,
) {
    let Some(count) = definitions.get_mut(value.0 as usize) else {
        errors.push(ValidationError::UnknownValue { function, value });
        return;
    };
    *count = count.saturating_add(1);
}

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut Vec<ValidationError>) {
    if id as usize >= length {
        errors.push(ValidationError::UnknownReference { kind, id });
    }
}

fn require_canonical_ids(
    kind: &'static str,
    owner: u32,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut Vec<ValidationError>,
) {
    let ids: Vec<_> = ids.into_iter().collect();
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        errors.push(ValidationError::NonCanonicalReferences { kind, owner });
    }
}

fn validate_acyclic(
    kind: &'static str,
    node_count: usize,
    edges: impl Fn(usize) -> Vec<u32>,
    errors: &mut Vec<ValidationError>,
) {
    fn visit(
        node: usize,
        node_count: usize,
        edges: &impl Fn(usize) -> Vec<u32>,
        colors: &mut [u8],
    ) -> bool {
        if colors[node] == 1 {
            return false;
        }
        if colors[node] == 2 {
            return true;
        }
        colors[node] = 1;
        for edge in edges(node) {
            let edge = edge as usize;
            if edge < node_count && !visit(edge, node_count, edges, colors) {
                return false;
            }
        }
        colors[node] = 2;
        true
    }

    let mut colors = vec![0; node_count];
    if (0..node_count).any(|node| !visit(node, node_count, &edges, &mut colors)) {
        errors.push(ValidationError::CyclicReferences(kind));
    }
}

fn check_dense(
    kind: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut Vec<ValidationError>,
) {
    for (expected, actual) in ids.into_iter().enumerate() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_source::{FileId, TextRange};

    fn fixture() -> SemanticWir {
        let digest = Sha256Digest::from_bytes([2; 32]);
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
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
                name: "entry".to_owned(),
                origin: FunctionOrigin::Source,
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
                source: Some(source),
                stack_bound: 0,
                frame_bound: 0,
                uninterrupted_bound: None,
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            scopes: Vec::new(),
            proofs: Vec::new(),
            tests: Vec::new(),
            startup_order: Vec::new(),
            shutdown_order: Vec::new(),
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
    }

    #[test]
    fn seals_exact_source_and_generated_entry_contracts() {
        fixture().validate().expect("valid SemanticWir");

        let mut forged = fixture();
        forged.functions[0].origin = FunctionOrigin::GeneratedTestHarness { group: 0 };
        assert!(forged.validate().is_err());

        let mut invalid_effect = fixture();
        invalid_effect.functions[0].effects = EffectSet(1 << 63);
        assert!(invalid_effect.validate().is_err());
    }
}
