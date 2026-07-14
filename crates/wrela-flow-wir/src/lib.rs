//! Canonical typed SSA IR exchanged between the frontend and private backend.
//!
//! FlowWir makes control flow, state machines, ownership transitions, cleanup,
//! scheduling, and hardware effects explicit. It is target-layout independent
//! and contains no LLVM concepts.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_source::Span;

pub const FLOW_WIR_VERSION: u32 = 1;

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
id_type!(ProofId);
id_type!(CheckpointId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarType {
    Bool,
    Integer { signed: bool, bits: u16 },
    Float32,
    Float64,
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowTypeKind {
    Unit,
    Scalar(ScalarType),
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
    ExtractField {
        aggregate: ValueId,
        field: u32,
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
    Allocate {
        region: RegionId,
        ty: TypeId,
        count: ValueId,
        proof: ProofId,
    },
    RegionReset {
        region: RegionId,
    },
    ActorReserve {
        actor: ActorId,
        message_kind: u32,
        proof: ProofId,
    },
    ActorCommit {
        reservation: ValueId,
        payload: ValueId,
    },
    ActorReject {
        reservation: ValueId,
    },
    MailboxReceive {
        actor: ActorId,
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
        resume: BlockId,
        frame: ValueId,
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

/// Exact provenance for Flow functions. One base function is retained for
/// every SemanticWir function; additional variants are compiler-generated by
/// structured/async lowering and identify their semantic owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionOrigin {
    SourceSemantic { semantic_function: u32 },
    GeneratedTestHarness { semantic_function: u32, group: u32 },
    GeneratedAsyncState { semantic_function: u32, state: u32 },
    GeneratedCleanup { semantic_function: u32, scope: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlowFunction {
    pub id: FunctionId,
    pub name: String,
    pub origin: FunctionOrigin,
    pub role: FunctionRole,
    pub parameters: Vec<ValueId>,
    pub result_types: Vec<TypeId>,
    pub values: Vec<Value>,
    pub blocks: Vec<Block>,
    pub entry: BlockId,
    pub stack_bound: u64,
    pub frame_bound: u64,
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
    pub capacity_bytes: u64,
    pub alignment: u64,
    pub reset_function: Option<FunctionId>,
    pub owner: PlanOwner,
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
    pub reachable_declarations: u64,
    pub monomorphized_instantiations: u64,
    pub resolved_interface_calls: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofKind {
    Type,
    ControlFlow,
    Ownership,
    Access,
    Region,
    Capacity,
    WaitGraph,
    Cleanup,
    Work,
    Stack,
    Dma,
    Mmio,
    Isr,
    ActorAsIf,
    ValueRange,
    Alignment,
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
    pub proofs: Vec<Proof>,
    pub checkpoints: Vec<Checkpoint>,
    pub startup_order: Vec<PlanOwner>,
    pub shutdown_order: Vec<PlanOwner>,
    pub image_entry: FunctionId,
    pub static_bytes: u64,
    pub peak_bytes: u64,
}

impl FlowWir {
    pub fn validate(self) -> Result<ValidatedFlowWir, ValidationErrors> {
        let errors = validate_module(&self);
        if errors.is_empty() {
            Ok(ValidatedFlowWir(self))
        } else {
            Err(ValidationErrors(errors))
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

fn validate_module(module: &FlowWir) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    if module.version != FLOW_WIR_VERSION {
        errors.push(ValidationError::UnsupportedVersion(module.version));
    }
    if module.name.trim().is_empty() {
        errors.push(ValidationError::MissingImageName);
    }
    if module.source_summary.semantic_wir_version == 0 {
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
        "checkpoint",
        module.checkpoints.iter().map(|record| record.id.0),
        &mut errors,
    );
    for ty in &module.types {
        validate_type(module, ty, &mut errors);
    }
    for global in &module.globals {
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        validate_immediate(module, &global.initializer, &mut errors);
        validate_owner(module, global.owner, &mut errors);
    }
    for function in &module.functions {
        let (semantic_function, valid_origin) = match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function } => {
                (semantic_function, function.source.is_some())
            }
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
            } => (semantic_function, true),
        };
        if function.name.trim().is_empty()
            || semantic_function >= module.source_summary.semantic_functions
            || !valid_origin
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
            require_id("value type", value.ty.0, module.types.len(), &mut errors);
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
            require_id(
                "function result type",
                result.0,
                module.types.len(),
                &mut errors,
            );
        }
        if function.entry.0 as usize >= function.blocks.len() {
            errors.push(ValidationError::UnknownBlock {
                function: function.id,
                block: function.entry,
            });
        }
        let mut definitions = vec![0u8; function.values.len()];
        for value in &function.parameters {
            define_value(function.id, *value, &mut definitions, &mut errors);
        }
        let mut instruction_ids = Vec::new();
        for block in &function.blocks {
            for value in &block.parameters {
                define_value(function.id, *value, &mut definitions, &mut errors);
            }
            for instruction in &block.instructions {
                instruction_ids.push(instruction.id.0);
                for result in &instruction.results {
                    define_value(function.id, *result, &mut definitions, &mut errors);
                }
                validate_operation(module, function, instruction, &mut errors);
            }
            validate_terminator(module, function, &block.terminator, &mut errors);
        }
        check_dense("instruction", instruction_ids, &mut errors);
        for (value, definitions) in definitions.into_iter().enumerate() {
            if definitions != 1 {
                errors.push(ValidationError::ValueDefinitionCount {
                    function: function.id,
                    value: ValueId(value as u32),
                    definitions,
                });
            }
        }
    }
    let base_semantic_functions: Vec<_> = module
        .functions
        .iter()
        .filter_map(|function| match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function }
            | FunctionOrigin::GeneratedTestHarness {
                semantic_function, ..
            } => Some(semantic_function),
            FunctionOrigin::GeneratedAsyncState { .. }
            | FunctionOrigin::GeneratedCleanup { .. } => None,
        })
        .collect();
    if base_semantic_functions != (0..module.source_summary.semantic_functions).collect::<Vec<_>>()
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "semantic function provenance",
            id: 0,
        });
    }
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownFunction(module.image_entry));
    }
    let mut actor_turns = vec![Vec::new(); module.actors.len()];
    let mut device_interrupts = vec![Vec::new(); module.devices.len()];
    let mut image_entry_count = 0usize;
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
            FunctionRole::ImageEntry => image_entry_count += 1,
            FunctionRole::Ordinary
            | FunctionRole::TaskEntry(_)
            | FunctionRole::Cleanup
            | FunctionRole::Test => {}
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
            || device.interrupt_functions.len() > 1
            || !sorted_unique_strings(&device.required_features)
            || !sorted_unique_strings(&device.optional_features)
            || device
                .required_features
                .iter()
                .any(|feature| device.optional_features.binary_search(feature).is_ok())
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
            require_id("pool device", device.0, module.devices.len(), &mut errors);
        }
    }
    for region in &module.regions {
        if region.name.trim().is_empty()
            || region.capacity_bytes == 0
            || !region.alignment.is_power_of_two()
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "region",
                id: region.id.0,
            });
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
    validate_acyclic_proofs(module, &mut errors);
    for checkpoint in &module.checkpoints {
        require_id(
            "checkpoint function",
            checkpoint.function.0,
            module.functions.len(),
            &mut errors,
        );
    }
    for owner in &module.startup_order {
        validate_owner(module, *owner, &mut errors);
    }
    for owner in &module.shutdown_order {
        validate_owner(module, *owner, &mut errors);
    }
    require_unique_owners("startup", &module.startup_order, &mut errors);
    require_unique_owners("shutdown", &module.shutdown_order, &mut errors);
    if module.peak_bytes < module.static_bytes {
        errors.push(ValidationError::InvalidRecord {
            kind: "image memory plan",
            id: 0,
        });
    }
    errors
}

fn validate_owner(module: &FlowWir, owner: PlanOwner, errors: &mut Vec<ValidationError>) {
    match owner {
        PlanOwner::Runtime | PlanOwner::BakedArtifact(_) => {}
        PlanOwner::Actor(id) => require_id("owner actor", id.0, module.actors.len(), errors),
        PlanOwner::Task(id) => require_id("owner task", id.0, module.tasks.len(), errors),
        PlanOwner::Device(id) => require_id("owner device", id.0, module.devices.len(), errors),
        PlanOwner::Pool(id) => require_id("owner pool", id.0, module.pools.len(), errors),
    }
}

fn sorted_unique_strings(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
        && values.windows(2).all(|pair| pair[0] < pair[1])
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

fn validate_acyclic_proofs(module: &FlowWir, errors: &mut Vec<ValidationError>) {
    fn visit(module: &FlowWir, node: usize, colors: &mut [u8]) -> bool {
        if colors[node] == 1 {
            return false;
        }
        if colors[node] == 2 {
            return true;
        }
        colors[node] = 1;
        for dependency in &module.proofs[node].depends_on {
            let dependency = dependency.0 as usize;
            if dependency < module.proofs.len() && !visit(module, dependency, colors) {
                return false;
            }
        }
        colors[node] = 2;
        true
    }

    let mut colors = vec![0; module.proofs.len()];
    if (0..module.proofs.len()).any(|node| !visit(module, node, &mut colors)) {
        errors.push(ValidationError::CyclicReferences("proof dependency"));
    }
}

fn require_unique_owners(
    phase: &'static str,
    owners: &[PlanOwner],
    errors: &mut Vec<ValidationError>,
) {
    let mut owners = owners.to_vec();
    owners.sort_unstable();
    if owners.windows(2).any(|pair| pair[0] == pair[1]) {
        errors.push(ValidationError::DuplicatePlanOwner(phase));
    }
}

fn validate_call_arguments(
    module: &FlowWir,
    caller: &FlowFunction,
    callee: FunctionId,
    arguments: &[ValueId],
    errors: &mut Vec<ValidationError>,
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
    errors: &mut Vec<ValidationError>,
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

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut Vec<ValidationError>) {
    if id as usize >= length {
        errors.push(ValidationError::UnknownReference { kind, id });
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

fn validate_type(module: &FlowWir, ty: &FlowType, errors: &mut Vec<ValidationError>) {
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
        FlowTypeKind::Array { element, .. } => use_type!(*element),
        FlowTypeKind::Enum { variants } => {
            for id in variants.iter().flatten() {
                use_type!(*id);
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
        | FlowTypeKind::Reservation
        | FlowTypeKind::OpaqueTarget { .. } => {}
    }
}

fn validate_immediate(module: &FlowWir, immediate: &Immediate, errors: &mut Vec<ValidationError>) {
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
        | Immediate::Integer { .. }
        | Immediate::Float32(_)
        | Immediate::Float64(_)
        | Immediate::Bytes(_) => {}
    }
}

fn validate_operation(
    module: &FlowWir,
    function: &FlowFunction,
    instruction: &Instruction,
    errors: &mut Vec<ValidationError>,
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
        FlowOperation::Immediate(immediate) => validate_immediate(module, immediate, errors),
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
        FlowOperation::ExtractField { aggregate, .. } => value!(*aggregate),
        FlowOperation::InsertField {
            aggregate,
            value: inserted,
            ..
        } => {
            value!(*aggregate);
            value!(*inserted);
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
                let actual: Vec<_> = instruction
                    .results
                    .iter()
                    .filter_map(|result| function.values.get(result.0 as usize))
                    .map(|value| value.ty)
                    .collect();
                if actual != callee.result_types {
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
        FlowOperation::ActorReserve {
            actor, proof: p, ..
        } => {
            require_id("actor reserve", actor.0, module.actors.len(), errors);
            proof!(*p);
        }
        FlowOperation::ActorCommit {
            reservation,
            payload,
        } => {
            value!(*reservation);
            value!(*payload);
        }
        FlowOperation::ActorReject { reservation } => value!(*reservation),
        FlowOperation::MailboxReceive { actor } => {
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
    errors: &mut Vec<ValidationError>,
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
        Terminator::Suspend { resume, frame, .. } => {
            block!(*resume);
            value!(*frame);
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
                semantic_wir_version: 1,
                semantic_functions: 1,
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
                origin: FunctionOrigin::SourceSemantic {
                    semantic_function: 0,
                },
                role: FunctionRole::ImageEntry,
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
                source: Some(Span {
                    file: FileId(0),
                    range: TextRange { start: 0, end: 0 },
                }),
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            proofs: Vec::new(),
            checkpoints: Vec::new(),
            startup_order: Vec::new(),
            shutdown_order: Vec::new(),
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
    }

    #[test]
    fn seals_exact_function_provenance_and_image_role() {
        fixture().validate().expect("valid FlowWir");

        let mut wrong_role = fixture();
        wrong_role.functions[0].role = FunctionRole::Ordinary;
        assert!(wrong_role.validate().is_err());

        let mut wrong_origin = fixture();
        wrong_origin.functions[0].origin = FunctionOrigin::SourceSemantic {
            semantic_function: 1,
        };
        assert!(wrong_origin.validate().is_err());
    }
}
