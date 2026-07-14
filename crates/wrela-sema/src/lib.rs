//! Mutually dependent whole-image semantic analyses over normalized HIR.
//!
//! Types, effects, ownership, views, regions, comptime, image construction,
//! actors, async state, capacities, scheduling, hardware, and proof production
//! converge here. The public output is a consumer-complete semantic database;
//! the internal query engine and caches never cross the crate boundary.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{BuildIdentity, Sha256Digest, ValidatedBuildConfiguration};
use wrela_diagnostics::{Diagnostic, WithDiagnostics};
use wrela_hir::{
    BodyId, DeclarationId, ExpressionId, FunctionColor, StatementId, ValidatedProgram,
};
use wrela_source::Span;
use wrela_target::TargetSemanticContract;
use wrela_test_model::{
    DeclaredImageTest, FunctionKey, ImageGroupId, ImageRoot as TestImageRoot, TestCaseResult,
    ValidatedTestPlan,
};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(SemanticTypeId);
id_type!(FunctionInstanceId);
id_type!(ValueId);
id_type!(ActorId);
id_type!(TaskId);
id_type!(DeviceId);
id_type!(PoolId);
id_type!(RegionId);
id_type!(ScopeProtocolId);
id_type!(BrandId);
id_type!(ProofId);
id_type!(ArtifactId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisIntent {
    Build,
    TestDiscovery,
    TestExecution,
}

/// Selects both the semantic fixed point and the exact root that must be
/// closed. Invalid combinations such as "build with a test plan" are not
/// represented by a bag of unrelated request fields.
#[derive(Debug)]
pub enum AnalysisMode<'a> {
    Image {
        name: &'a str,
        entry: DeclarationId,
    },
    DiscoverTests {
        image_name: &'a str,
        image_entry: DeclarationId,
        declared_image_tests: &'a [DeclaredImageTest],
    },
    CompileTestGroup {
        plan: &'a ValidatedTestPlan,
        group: ImageGroupId,
        /// Present exactly for a declared-image group; resolved from that
        /// group's manifest-selected image name by the frontend.
        declared_entry: Option<DeclarationId>,
    },
}

impl AnalysisMode<'_> {
    #[must_use]
    pub const fn intent(&self) -> AnalysisIntent {
        match self {
            Self::Image { .. } => AnalysisIntent::Build,
            Self::DiscoverTests { .. } => AnalysisIntent::TestDiscovery,
            Self::CompileTestGroup { .. } => AnalysisIntent::TestExecution,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisLimits {
    pub types: u32,
    pub monomorphizations: u32,
    pub values: u32,
    pub expression_facts: u32,
    pub statement_facts: u32,
    pub scope_protocols: u32,
    pub scope_activations: u32,
    pub image_nodes: u32,
    pub proofs: u32,
    /// Total elements across all variable-length semantic fact collections.
    pub fact_edges: u64,
    /// Total UTF-8 and constant byte payload retained in semantic facts.
    pub fact_bytes: u64,
    pub constant_depth: u32,
    pub evaluator_steps: u64,
    pub evaluator_bytes: u64,
    pub fixed_point_iterations: u32,
    pub proof_edges: u64,
    pub baked_artifacts: u32,
    pub baked_artifact_bytes: u64,
    pub tests: u32,
    pub test_groups: u32,
    pub test_scenarios: u32,
    pub test_scenario_steps: u32,
    pub test_bytes: u64,
    pub test_report_bytes: u64,
    pub test_events_per_group: u32,
    pub test_output_bytes_per_group: u64,
    pub test_timeout_ns_per_group: u64,
    pub diagnostic_count: u32,
    pub diagnostic_bytes: u64,
}

impl AnalysisLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            types: 16_000_000,
            monomorphizations: 16_000_000,
            values: 64_000_000,
            expression_facts: 64_000_000,
            statement_facts: 64_000_000,
            scope_protocols: 4_000_000,
            scope_activations: 16_000_000,
            image_nodes: 16_000_000,
            proofs: 64_000_000,
            fact_edges: 1_000_000_000,
            fact_bytes: 4 * 1024 * 1024 * 1024,
            constant_depth: 1024,
            evaluator_steps: 1_000_000_000,
            evaluator_bytes: 4 * 1024 * 1024 * 1024,
            fixed_point_iterations: 1_000_000,
            proof_edges: 256_000_000,
            baked_artifacts: 1_000_000,
            baked_artifact_bytes: 4 * 1024 * 1024 * 1024,
            tests: 1_000_000,
            test_groups: 100_000,
            test_scenarios: 100_000,
            test_scenario_steps: 1_000_000,
            test_bytes: 64 * 1024 * 1024,
            test_report_bytes: 1024 * 1024 * 1024,
            test_events_per_group: 10_000_000,
            test_output_bytes_per_group: 1024 * 1024 * 1024,
            test_timeout_ns_per_group: 24 * 60 * 60 * 1_000_000_000,
            diagnostic_count: 100_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), AnalysisFailure> {
        if self.types == 0
            || self.monomorphizations == 0
            || self.values == 0
            || self.expression_facts == 0
            || self.statement_facts == 0
            || self.scope_protocols == 0
            || self.scope_activations == 0
            || self.image_nodes == 0
            || self.proofs == 0
            || self.fact_edges == 0
            || self.fact_bytes == 0
            || self.constant_depth == 0
            || self.constant_depth > 1024
            || self.evaluator_steps == 0
            || self.evaluator_bytes == 0
            || self.fixed_point_iterations == 0
            || self.proof_edges == 0
            || self.baked_artifacts == 0
            || self.baked_artifact_bytes == 0
            || self.tests == 0
            || self.test_groups == 0
            || self.test_scenarios == 0
            || self.test_scenario_steps == 0
            || self.test_bytes == 0
            || self.test_report_bytes == 0
            || self.test_events_per_group == 0
            || self.test_output_bytes_per_group == 0
            || self.test_timeout_ns_per_group == 0
            || self.diagnostic_count == 0
            || self.diagnostic_bytes == 0
        {
            Err(AnalysisFailure::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisChangeSet {
    pub previous_source_graph: Option<Sha256Digest>,
    pub changed_declarations: Vec<DeclarationId>,
}

#[derive(Debug)]
pub struct AnalysisRequest<'a> {
    pub hir: &'a ValidatedProgram,
    pub target: &'a TargetSemanticContract,
    pub build: &'a ValidatedBuildConfiguration,
    pub mode: AnalysisMode<'a>,
    pub changes: &'a AnalysisChangeSet,
    pub limits: AnalysisLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Linearity {
    ScalarCopy,
    ExplicitCopy,
    ReclaimableLinear,
    StrictLinear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticTypeKind {
    Error,
    Never,
    Unit,
    Bool,
    Integer {
        signed: bool,
        bits: u16,
    },
    Float {
        bits: u16,
    },
    Character,
    StaticString {
        bytes: u64,
    },
    StaticBytes {
        bytes: u64,
    },
    Tuple(Vec<SemanticTypeId>),
    Array {
        element: SemanticTypeId,
        length: u64,
    },
    Structure {
        declaration: DeclarationId,
        arguments: Vec<SemanticArgument>,
        fields: Vec<SemanticField>,
    },
    Class {
        declaration: DeclarationId,
        arguments: Vec<SemanticArgument>,
        fields: Vec<SemanticField>,
    },
    Enumeration {
        declaration: DeclarationId,
        arguments: Vec<SemanticArgument>,
        variants: Vec<SemanticVariant>,
    },
    Function {
        color: FunctionColor,
        parameters: Vec<SemanticParameter>,
        result: SemanticTypeId,
    },
    View {
        mutable: bool,
        target: SemanticTypeId,
        provenance: Vec<RegionId>,
    },
    Iso {
        brand: BrandId,
        payload: SemanticTypeId,
    },
    Actor {
        class: SemanticTypeId,
    },
    Receipt {
        payload: SemanticTypeId,
        error: SemanticTypeId,
    },
    Dma {
        brand: BrandId,
        payload: SemanticTypeId,
    },
    Mmio {
        layout: SemanticTypeId,
    },
    Validated {
        format: SemanticTypeId,
        payload: SemanticTypeId,
    },
    TargetOpaque {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticArgument {
    Type(SemanticTypeId),
    Constant(ConstantValue),
    Region(RegionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticField {
    pub name: String,
    pub ty: SemanticTypeId,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticVariant {
    pub name: String,
    pub fields: Vec<SemanticField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticParameter {
    pub access: AccessMode,
    pub ty: SemanticTypeId,
}

/// One concrete parameter in a monomorphized function body. Signature types
/// use `SemanticParameter`; executable instances additionally bind each
/// parameter to its image-wide semantic value ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionParameter {
    pub value: ValueId,
    pub access: AccessMode,
    pub ty: SemanticTypeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Value,
    Read,
    Mutate,
    Take,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticType {
    pub id: SemanticTypeId,
    pub kind: SemanticTypeKind,
    pub linearity: Linearity,
    pub size_upper_bound: Option<u64>,
    pub alignment_lower_bound: u32,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstantValue {
    Unit,
    Bool(bool),
    Unsigned {
        bits: u16,
        value: u128,
    },
    Signed {
        bits: u16,
        value: i128,
    },
    Float32(u32),
    Float64(u64),
    Character(char),
    Bytes(Vec<u8>),
    String(String),
    Tuple(Vec<ConstantValue>),
    Array(Vec<ConstantValue>),
    Structure {
        ty: SemanticTypeId,
        fields: Vec<ConstantValue>,
    },
    Enumeration {
        ty: SemanticTypeId,
        variant: u32,
        fields: Vec<ConstantValue>,
    },
    Type(SemanticTypeId),
    Brand(BrandId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EffectSet(pub u64);

impl EffectSet {
    pub const ALLOCATE: u64 = 1 << 0;
    pub const SUSPEND: u64 = 1 << 1;
    pub const ACTOR: u64 = 1 << 2;
    pub const TASK: u64 = 1 << 3;
    pub const MMIO: u64 = 1 << 4;
    pub const DMA: u64 = 1 << 5;
    pub const INTERRUPT: u64 = 1 << 6;
    pub const FIRMWARE: u64 = 1 << 7;
    pub const RECORD_REPLAY: u64 = 1 << 8;
    pub const MAY_FAIL: u64 = 1 << 9;
    pub const DROP_EFFECT: u64 = 1 << 10;
    pub const ALL: u64 = Self::ALLOCATE
        | Self::SUSPEND
        | Self::ACTOR
        | Self::TASK
        | Self::MMIO
        | Self::DMA
        | Self::INTERRUPT
        | Self::FIRMWARE
        | Self::RECORD_REPLAY
        | Self::MAY_FAIL
        | Self::DROP_EFFECT;

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 & !Self::ALL == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionOrigin {
    Source {
        declaration: DeclarationId,
        body: BodyId,
    },
    /// Synthetic entry emitted only when compiling the named sealed test
    /// group. Its body is compiler-owned and therefore has no forged HIR ID.
    GeneratedTestHarness { group: ImageGroupId },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInstance {
    pub id: FunctionInstanceId,
    pub key: FunctionKey,
    pub name: String,
    pub origin: FunctionOrigin,
    pub role: FunctionRole,
    pub generic_arguments: Vec<SemanticArgument>,
    pub parameters: Vec<FunctionParameter>,
    pub result: SemanticTypeId,
    pub effects: EffectSet,
    pub stack_bytes_bound: u64,
    pub frame_bytes_bound: u64,
    pub uninterrupted_work_bound: Option<u64>,
    pub recursive_depth_bound: Option<u32>,
    pub proofs: Vec<ProofId>,
    pub source: Option<Span>,
}

/// One typed semantic value in the whole-image database. Value IDs are dense
/// across the image; `function` supplies the ownership namespace required when
/// the same HIR body is monomorphized more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticValue {
    pub id: ValueId,
    pub function: FunctionInstanceId,
    pub ty: SemanticTypeId,
    pub category: ValueCategory,
    pub source: Option<Span>,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueCategory {
    Value,
    Place,
    SharedView,
    MutableView,
    TypeValue,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipState {
    Uninitialized,
    Owned,
    BorrowedRead,
    BorrowedMut,
    Moved,
    Taken,
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionResolution {
    Error,
    Constant(ConstantValue),
    Value(ValueId),
    Function(FunctionInstanceId),
    Constructor {
        ty: SemanticTypeId,
        variant: Option<u32>,
    },
    DirectCall {
        function: FunctionInstanceId,
        argument_access: Vec<AccessMode>,
    },
    ActorRequest {
        actor: ActorId,
        method: FunctionInstanceId,
        permit: ProofId,
    },
    Closure {
        function: FunctionInstanceId,
        captures: Vec<ValueId>,
    },
    Field {
        index: u32,
    },
    Index {
        bounds: ProofId,
    },
    Builtin(IntrinsicOperation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrinsicOperation {
    RegionAllocate {
        region: RegionId,
        capacity: ProofId,
    },
    RegionReset {
        region: RegionId,
    },
    ActorSend {
        actor: ActorId,
    },
    ActorTrySend {
        actor: ActorId,
    },
    Await,
    Race,
    Select,
    TaskSpawn {
        task: TaskId,
        slots: ProofId,
    },
    Cancel,
    Checkpoint,
    DmaPrepare {
        device: DeviceId,
        pool: PoolId,
        proof: ProofId,
    },
    DmaComplete {
        device: DeviceId,
        pool: PoolId,
        proof: ProofId,
    },
    DmaQuarantine {
        device: DeviceId,
        pool: PoolId,
        proof: ProofId,
    },
    MmioRead {
        device: DeviceId,
        register: u32,
        proof: ProofId,
    },
    MmioWrite {
        device: DeviceId,
        register: u32,
        proof: ProofId,
    },
    QueueReserve {
        device: DeviceId,
        proof: ProofId,
    },
    DeviceValidate {
        device: DeviceId,
        proof: ProofId,
    },
    RecordEvent {
        kind: u32,
    },
    ReplayEvent {
        kind: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionFact {
    pub function: FunctionInstanceId,
    pub expression: ExpressionId,
    pub ty: SemanticTypeId,
    pub category: ValueCategory,
    pub region: RegionId,
    pub effects: EffectSet,
    pub resolution: ExpressionResolution,
    pub ownership_before: OwnershipState,
    pub ownership_after: OwnershipState,
    pub proofs: Vec<ProofId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementFact {
    pub function: FunctionInstanceId,
    pub statement: StatementId,
    pub effects: EffectSet,
    pub initialized_after: Vec<ValueId>,
    pub moved_after: Vec<ValueId>,
    pub live_loans_after: Vec<Loan>,
    pub proofs: Vec<ProofId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loan {
    pub value: ValueId,
    pub access: AccessMode,
    pub region: RegionId,
    pub source: Span,
}

/// Fully resolved contract for one source `scope` declaration. Lowering uses
/// these facts instead of reinterpreting attributes, types, or effects in HIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeProtocol {
    pub id: ScopeProtocolId,
    pub declaration: DeclarationId,
    pub name: String,
    pub parameters: Vec<SemanticParameter>,
    pub result: SemanticTypeId,
    pub setup: BodyId,
    pub enter: ExpressionId,
    pub abort: Option<BodyId>,
    pub exit: BodyId,
    pub suspend_safe: bool,
    pub abort_effects: EffectSet,
    pub exit_effects: EffectSet,
    pub proof: ProofId,
}

/// One statically shaped dynamic activation site. Dependencies point to other
/// `with` statements in the same monomorphized function and are ordered
/// canonically. The proof establishes acyclicity and restoration obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeActivation {
    pub statement: StatementId,
    pub function: FunctionInstanceId,
    pub protocol: ScopeProtocolId,
    pub state_type: SemanticTypeId,
    pub cleanup_dependencies: Vec<StatementId>,
    pub reverse_source_order: u32,
    pub proof: ProofId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionClass {
    Image,
    Call,
    TaskFrame,
    Request,
    Pool(PoolId),
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub id: RegionId,
    pub name: String,
    pub class: RegionClass,
    pub capacity_bytes: u64,
    pub alignment: u32,
    pub owner: ImageOwner,
    pub proof: ProofId,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImageOwner {
    Runtime,
    Actor(ActorId),
    Task(TaskId),
    Device(DeviceId),
    Pool(PoolId),
    Artifact(ArtifactId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorNode {
    pub id: ActorId,
    pub name: String,
    pub class: SemanticTypeId,
    pub mailbox_capacity: u32,
    pub message_types: Vec<SemanticTypeId>,
    pub turn_functions: Vec<FunctionInstanceId>,
    pub priority: u8,
    pub supervisor: Option<ActorId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskNode {
    pub id: TaskId,
    pub name: String,
    pub entry: FunctionInstanceId,
    pub slots: u32,
    pub priority: u8,
    pub supervisor: Option<ActorId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNode {
    pub id: DeviceId,
    pub name: String,
    pub target_binding: String,
    pub owner: ActorId,
    pub required_features: Vec<String>,
    pub optional_features: Vec<String>,
    pub queue_capacity: Option<u32>,
    pub maximum_in_flight: Option<u32>,
    pub interrupt_functions: Vec<FunctionInstanceId>,
    pub reset_timeout_ns: u64,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolNode {
    pub id: PoolId,
    pub name: String,
    pub brand: BrandId,
    pub payload: SemanticTypeId,
    pub capacity: u64,
    pub alignment: u32,
    pub reachable_devices: Vec<DeviceId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandBinding {
    pub id: BrandId,
    pub declaration: DeclarationId,
    pub owner: ImageOwner,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGraph {
    pub name: String,
    pub entry: FunctionInstanceId,
    pub actors: Vec<ActorNode>,
    pub tasks: Vec<TaskNode>,
    pub devices: Vec<DeviceNode>,
    pub pools: Vec<PoolNode>,
    pub regions: Vec<Region>,
    pub brands: Vec<BrandBinding>,
    pub static_bytes: u64,
    pub peak_bytes: u64,
    pub startup_order: Vec<ImageOwner>,
    pub shutdown_order: Vec<ImageOwner>,
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
pub struct BakedArtifact {
    pub id: ArtifactId,
    pub name: String,
    pub media_type: String,
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
    pub owner: ImageOwner,
}

/// Stable HIR arena bounds retained for semantic provenance without cloning
/// the image-sized validated HIR into every analysis result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HirSummary {
    pub files: u32,
    pub declarations: u32,
    pub bodies: u32,
    pub expressions: u32,
    pub statements: u32,
}

impl HirSummary {
    pub fn from_validated(hir: &ValidatedProgram) -> Result<Self, AnalysisFailure> {
        let program = hir.as_program();
        Ok(Self {
            files: program.packages.modules().len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR files",
                    limit: u64::from(u32::MAX),
                }
            })?,
            declarations: program.declarations.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR declarations",
                    limit: u64::from(u32::MAX),
                }
            })?,
            bodies: program.bodies.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR bodies",
                    limit: u64::from(u32::MAX),
                }
            })?,
            expressions: program.expressions.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR expressions",
                    limit: u64::from(u32::MAX),
                }
            })?,
            statements: program.statements.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR statements",
                    limit: u64::from(u32::MAX),
                }
            })?,
        })
    }
}

/// Best-effort facts are always returned when analysis starts, including for a
/// rejected image. Consumers may inspect them for diagnostics but cannot lower
/// them to WIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisRoot {
    DeclaredImage {
        image_name: String,
        declaration: DeclarationId,
        /// Set only when this image is being compiled for one sealed declared
        /// scenario group.
        test_group: Option<ImageGroupId>,
    },
    GeneratedTestHarness {
        group: ImageGroupId,
        harness_name: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartialAnalysis {
    pub hir: HirSummary,
    pub build: BuildIdentity,
    pub target_digest: Sha256Digest,
    /// Exact source or compiler-generated root whose monomorphized instance is
    /// `ImageGraph::entry`.
    pub root: AnalysisRoot,
    pub types: Vec<SemanticType>,
    pub functions: Vec<FunctionInstance>,
    pub values: Vec<SemanticValue>,
    pub expressions: Vec<ExpressionFact>,
    pub statements: Vec<StatementFact>,
    pub scope_protocols: Vec<ScopeProtocol>,
    pub scope_activations: Vec<ScopeActivation>,
    pub graph: Option<ImageGraph>,
    pub proofs: Vec<Proof>,
    pub baked_artifacts: Vec<BakedArtifact>,
    pub test_plan: Option<ValidatedTestPlan>,
    pub comptime_test_results: Vec<TestCaseResult>,
}

impl PartialAnalysis {
    /// Validate the safety contract shared by successful and rejected
    /// analyses. A partial database is prefix-closed: it may omit facts, but
    /// every fact it exposes is canonical and every exposed ID resolves.
    /// `Error` semantic placeholders are permitted only on this path.
    pub fn validate_partial_structure(&self) -> Result<(), AnalysisFailure> {
        let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
        if self.build.target_package != self.target_digest {
            return Err(invalid(
                "semantic target digest differs from build identity",
            ));
        }
        if !dense(self.types.iter().map(|item| item.id.0))
            || !dense(self.functions.iter().map(|item| item.id.0))
            || !dense(self.values.iter().map(|item| item.id.0))
            || !dense(self.scope_protocols.iter().map(|item| item.id.0))
            || !dense(self.proofs.iter().map(|item| item.id.0))
            || !dense(self.baked_artifacts.iter().map(|item| item.id.0))
        {
            return Err(invalid("partial semantic database IDs are not dense"));
        }

        let empty_graph = ImageGraph {
            name: String::new(),
            entry: FunctionInstanceId(0),
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            brands: Vec::new(),
            static_bytes: 0,
            peak_bytes: 0,
            startup_order: Vec::new(),
            shutdown_order: Vec::new(),
        };
        let graph = self.graph.as_ref().unwrap_or(&empty_graph);

        for ty in &self.types {
            if !matches!(ty.kind, SemanticTypeKind::Error) && !valid_semantic_type(ty, self, graph)
            {
                return Err(invalid(
                    "partial semantic type contains a dangling or invalid reference",
                ));
            }
            if ty
                .source
                .is_some_and(|span| !valid_span(span, self.hir.files))
            {
                return Err(invalid("partial semantic type has an invalid source span"));
            }
        }
        for value in &self.values {
            if value.function.0 as usize >= self.functions.len()
                || value.ty.0 as usize >= self.types.len()
                || value
                    .source_name
                    .as_ref()
                    .is_some_and(|name| name.trim().is_empty())
                || value
                    .source
                    .is_some_and(|span| !valid_span(span, self.hir.files))
            {
                return Err(invalid("partial semantic value contains an invalid fact"));
            }
        }

        let mut function_keys = std::collections::BTreeSet::new();
        for function in &self.functions {
            let valid_origin = match function.origin {
                FunctionOrigin::Source { declaration, body } => {
                    declaration.0 < self.hir.declarations
                        && body.0 < self.hir.bodies
                        && function.source.is_some()
                }
                FunctionOrigin::GeneratedTestHarness { .. } => {
                    function.role == FunctionRole::ImageEntry
                        && function.generic_arguments.is_empty()
                        && function.source.is_none()
                }
            };
            let valid_role = match function.role {
                FunctionRole::ActorTurn(id) => (id.0 as usize) < graph.actors.len(),
                FunctionRole::TaskEntry(id) => (id.0 as usize) < graph.tasks.len(),
                FunctionRole::Isr(id) => (id.0 as usize) < graph.devices.len(),
                FunctionRole::Ordinary
                | FunctionRole::Cleanup
                | FunctionRole::ImageEntry
                | FunctionRole::Test => true,
            };
            if !function.key.is_valid()
                || !function_keys.insert(function.key)
                || function.name.trim().is_empty()
                || !valid_origin
                || !valid_role
                || function.result.0 as usize >= self.types.len()
                || !function.effects.is_valid()
                || function
                    .generic_arguments
                    .iter()
                    .any(|argument| !valid_semantic_argument(argument, self, graph))
                || !valid_proof_set(&function.proofs, self.proofs.len())
                || function.parameters.iter().any(|parameter| {
                    parameter.ty.0 as usize >= self.types.len()
                        || self
                            .values
                            .get(parameter.value.0 as usize)
                            .is_none_or(|value| {
                                value.function != function.id || value.ty != parameter.ty
                            })
                })
                || has_duplicate_ids(
                    function
                        .parameters
                        .iter()
                        .map(|parameter| parameter.value.0),
                )
                || function
                    .source
                    .is_some_and(|span| !valid_span(span, self.hir.files))
            {
                return Err(invalid(
                    "partial function contains a dangling or invalid fact",
                ));
            }
        }

        if !self.expressions.windows(2).all(|pair| {
            (pair[0].function, pair[0].expression) < (pair[1].function, pair[1].expression)
        }) || self.expressions.iter().any(|fact| {
            fact.function.0 as usize >= self.functions.len()
                || fact.expression.0 >= self.hir.expressions
                || fact.ty.0 as usize >= self.types.len()
                || fact.region.0 as usize >= graph.regions.len()
                || !fact.effects.is_valid()
                || !valid_proof_set(&fact.proofs, self.proofs.len())
                || (!matches!(fact.resolution, ExpressionResolution::Error)
                    && !valid_expression_resolution(&fact.resolution, fact.function, self, graph))
        }) {
            return Err(invalid("partial expression facts are not prefix-safe"));
        }
        if !self.statements.windows(2).all(|pair| {
            (pair[0].function, pair[0].statement) < (pair[1].function, pair[1].statement)
        }) || self
            .statements
            .iter()
            .any(|fact| !valid_statement_fact(fact, self, graph))
        {
            return Err(invalid("partial statement facts are not prefix-safe"));
        }

        for protocol in &self.scope_protocols {
            if protocol.declaration.0 >= self.hir.declarations
                || protocol.result.0 as usize >= self.types.len()
                || protocol.setup.0 >= self.hir.bodies
                || protocol.enter.0 >= self.hir.expressions
                || protocol.abort.is_some_and(|body| body.0 >= self.hir.bodies)
                || protocol.exit.0 >= self.hir.bodies
                || protocol.name.trim().is_empty()
                || !protocol.abort_effects.is_valid()
                || !protocol.exit_effects.is_valid()
                || protocol.proof.0 as usize >= self.proofs.len()
                || protocol
                    .parameters
                    .iter()
                    .any(|parameter| parameter.ty.0 as usize >= self.types.len())
            {
                return Err(invalid("partial scope protocol contains a dangling fact"));
            }
        }
        if !self.scope_activations.windows(2).all(|pair| {
            (
                pair[0].function,
                pair[0].reverse_source_order,
                pair[0].statement,
            ) < (
                pair[1].function,
                pair[1].reverse_source_order,
                pair[1].statement,
            )
        }) || self.scope_activations.iter().any(|activation| {
            activation.statement.0 >= self.hir.statements
                || activation.function.0 as usize >= self.functions.len()
                || activation.protocol.0 as usize >= self.scope_protocols.len()
                || activation.state_type.0 as usize >= self.types.len()
                || activation.proof.0 as usize >= self.proofs.len()
                || !strict_ids(&activation.cleanup_dependencies)
                || activation
                    .cleanup_dependencies
                    .iter()
                    .any(|statement| statement.0 >= self.hir.statements)
        }) {
            return Err(invalid("partial scope activations are not prefix-safe"));
        }
        for proof in &self.proofs {
            if proof.subject.trim().is_empty()
                || proof.explanation.is_empty()
                || proof.explanation.iter().any(|line| line.trim().is_empty())
                || !proof.depends_on.windows(2).all(|pair| pair[0] < pair[1])
                || proof
                    .depends_on
                    .iter()
                    .any(|dependency| dependency.0 >= proof.id.0)
                || proof
                    .sources
                    .iter()
                    .any(|span| !valid_span(*span, self.hir.files))
            {
                return Err(invalid("partial proof is not prefix-safe"));
            }
        }
        if self.baked_artifacts.iter().any(|artifact| {
            artifact.name.trim().is_empty()
                || artifact.media_type.trim().is_empty()
                || !valid_owner(artifact.owner, graph, self.baked_artifacts.len())
        }) {
            return Err(invalid("partial baked artifact contains an invalid fact"));
        }
        if let Some(graph) = &self.graph {
            if graph.name.trim().is_empty()
                || graph.entry.0 as usize >= self.functions.len()
                || !dense(graph.actors.iter().map(|item| item.id.0))
                || !dense(graph.tasks.iter().map(|item| item.id.0))
                || !dense(graph.devices.iter().map(|item| item.id.0))
                || !dense(graph.pools.iter().map(|item| item.id.0))
                || !dense(graph.regions.iter().map(|item| item.id.0))
                || !dense(graph.brands.iter().map(|item| item.id.0))
                || !root_matches_entry(self, graph)
                || !valid_function_roles(self, graph)
                || !valid_image_graph(graph, self)
            {
                return Err(invalid("partial image graph is present but not complete"));
            }
        }
        if let Some(plan) = &self.test_plan {
            let plan = plan.as_plan();
            if plan.build != self.build
                || self.comptime_test_results.len() > plan.unit_tests.len()
                || !self
                    .comptime_test_results
                    .iter()
                    .zip(&plan.unit_tests)
                    .all(|(result, planned)| result.descriptor == planned.descriptor)
            {
                return Err(invalid("partial test results are not a plan prefix"));
            }
        } else if !self.comptime_test_results.is_empty() {
            return Err(invalid(
                "partial comptime results exist without a test plan",
            ));
        }
        Ok(())
    }

    /// Validate the complete consumer-facing database before sealing it as an
    /// `AnalyzedImage`. Rejected analyses may remain partial; successful ones
    /// may not contain dangling IDs or mismatched build/test identities.
    pub fn validate_for_seal(&self) -> Result<(), AnalysisFailure> {
        let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
        if self.build.target_package != self.target_digest {
            return Err(invalid(
                "semantic target digest differs from build identity",
            ));
        }
        if !dense(self.types.iter().map(|item| item.id.0))
            || !dense(self.functions.iter().map(|item| item.id.0))
            || !dense(self.values.iter().map(|item| item.id.0))
            || !dense(self.scope_protocols.iter().map(|item| item.id.0))
            || !dense(self.proofs.iter().map(|item| item.id.0))
            || !dense(self.baked_artifacts.iter().map(|item| item.id.0))
        {
            return Err(invalid("semantic database IDs are not dense"));
        }
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| invalid("successful analysis has no image graph"))?;
        for ty in &self.types {
            if !valid_semantic_type(ty, self, graph) {
                return Err(invalid(
                    "semantic type is invalid or contains a dangling reference",
                ));
            }
        }
        for value in &self.values {
            if value.function.0 as usize >= self.functions.len()
                || value.ty.0 as usize >= self.types.len()
                || value
                    .source_name
                    .as_ref()
                    .is_some_and(|name| name.trim().is_empty())
            {
                return Err(invalid(
                    "semantic value contains a dangling or invalid fact",
                ));
            }
        }
        let mut function_keys = std::collections::BTreeSet::new();
        for function in &self.functions {
            let valid_origin = match function.origin {
                FunctionOrigin::Source { declaration, body } => {
                    declaration.0 < self.hir.declarations
                        && body.0 < self.hir.bodies
                        && function.source.is_some()
                }
                FunctionOrigin::GeneratedTestHarness { .. } => {
                    function.role == FunctionRole::ImageEntry
                        && function.generic_arguments.is_empty()
                        && function.source.is_none()
                }
            };
            if !function.key.is_valid()
                || !function_keys.insert(function.key)
                || function.name.trim().is_empty()
                || !valid_origin
                || function.result.0 as usize >= self.types.len()
                || !function.effects.is_valid()
                || function
                    .generic_arguments
                    .iter()
                    .any(|argument| !valid_semantic_argument(argument, self, graph))
                || function.proofs.windows(2).any(|pair| pair[0] >= pair[1])
                || function
                    .proofs
                    .iter()
                    .any(|proof| proof.0 as usize >= self.proofs.len())
                || function.parameters.iter().any(|parameter| {
                    parameter.ty.0 as usize >= self.types.len()
                        || self
                            .values
                            .get(parameter.value.0 as usize)
                            .is_none_or(|value| {
                                value.function != function.id || value.ty != parameter.ty
                            })
                })
                || has_duplicate_ids(
                    function
                        .parameters
                        .iter()
                        .map(|parameter| parameter.value.0),
                )
            {
                return Err(invalid("function instance contains a dangling reference"));
            }
        }
        if !self.expressions.windows(2).all(|pair| {
            (pair[0].function, pair[0].expression) < (pair[1].function, pair[1].expression)
        }) || self
            .expressions
            .iter()
            .any(|fact| !valid_expression_fact(fact, self, graph))
        {
            return Err(invalid("expression facts are incomplete or noncanonical"));
        }
        if !self.statements.windows(2).all(|pair| {
            (pair[0].function, pair[0].statement) < (pair[1].function, pair[1].statement)
        }) || self
            .statements
            .iter()
            .any(|fact| !valid_statement_fact(fact, self, graph))
        {
            return Err(invalid("statement facts are incomplete or noncanonical"));
        }
        for protocol in &self.scope_protocols {
            if protocol.declaration.0 >= self.hir.declarations
                || protocol.result.0 as usize >= self.types.len()
                || protocol.setup.0 >= self.hir.bodies
                || protocol.enter.0 >= self.hir.expressions
                || protocol.abort.is_some_and(|body| body.0 >= self.hir.bodies)
                || protocol.exit.0 >= self.hir.bodies
                || protocol.name.trim().is_empty()
                || !protocol.abort_effects.is_valid()
                || !protocol.exit_effects.is_valid()
                || protocol.proof.0 as usize >= self.proofs.len()
                || protocol
                    .parameters
                    .iter()
                    .any(|parameter| parameter.ty.0 as usize >= self.types.len())
            {
                return Err(invalid("scope protocol contains a dangling reference"));
            }
        }
        if !self.scope_activations.windows(2).all(|pair| {
            (
                pair[0].function,
                pair[0].reverse_source_order,
                pair[0].statement,
            ) < (
                pair[1].function,
                pair[1].reverse_source_order,
                pair[1].statement,
            )
        }) {
            return Err(invalid("scope activations are not canonical"));
        }
        for activation in &self.scope_activations {
            if activation.statement.0 >= self.hir.statements
                || activation.function.0 as usize >= self.functions.len()
                || activation.protocol.0 as usize >= self.scope_protocols.len()
                || activation.state_type.0 as usize >= self.types.len()
                || activation.proof.0 as usize >= self.proofs.len()
                || activation
                    .cleanup_dependencies
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || activation
                    .cleanup_dependencies
                    .iter()
                    .any(|statement| statement.0 >= self.hir.statements)
            {
                return Err(invalid("scope activation contains a dangling reference"));
            }
        }
        for proof in &self.proofs {
            if proof.subject.trim().is_empty()
                || proof.explanation.is_empty()
                || proof.explanation.iter().any(|line| line.trim().is_empty())
                || !proof.depends_on.windows(2).all(|pair| pair[0] < pair[1])
                || proof
                    .depends_on
                    .iter()
                    .any(|dependency| dependency.0 >= proof.id.0)
            {
                return Err(invalid("proof dependencies are invalid or noncanonical"));
            }
        }
        if graph.name.trim().is_empty()
            || graph.entry.0 as usize >= self.functions.len()
            || !dense(graph.actors.iter().map(|item| item.id.0))
            || !dense(graph.tasks.iter().map(|item| item.id.0))
            || !dense(graph.devices.iter().map(|item| item.id.0))
            || !dense(graph.pools.iter().map(|item| item.id.0))
            || !dense(graph.regions.iter().map(|item| item.id.0))
            || !dense(graph.brands.iter().map(|item| item.id.0))
        {
            return Err(invalid("image graph is incomplete or noncanonical"));
        }
        if !root_matches_entry(self, graph) || !valid_function_roles(self, graph) {
            return Err(invalid(
                "image root or function roles do not match the closed image graph",
            ));
        }
        if !valid_image_graph(graph, self) {
            return Err(invalid(
                "image graph contains invalid references, bounds, or order",
            ));
        }
        if self.baked_artifacts.iter().any(|artifact| {
            artifact.name.trim().is_empty()
                || artifact.media_type.trim().is_empty()
                || !valid_owner(artifact.owner, graph, self.baked_artifacts.len())
        }) {
            return Err(invalid(
                "baked artifact is incomplete or has an invalid owner",
            ));
        }
        if let Some(plan) = &self.test_plan {
            let plan = plan.as_plan();
            if plan.build != self.build
                || self.comptime_test_results.len() != plan.unit_tests.len()
                || !self
                    .comptime_test_results
                    .iter()
                    .zip(&plan.unit_tests)
                    .all(|(result, planned)| result.descriptor == planned.descriptor)
            {
                return Err(invalid("test plan/results do not match semantic build"));
            }
            let planned_keys = plan.unit_tests.iter().map(|test| test.function_key).chain(
                plan.image_groups.iter().flat_map(|group| {
                    group.tests.iter().filter_map(|test| match test.invocation {
                        wrela_test_model::ImageTestInvocation::GeneratedFunction {
                            function_key,
                        } => Some(function_key),
                        wrela_test_model::ImageTestInvocation::DeclaredScenario => None,
                    })
                }),
            );
            let mut semantic_test_keys = std::collections::BTreeMap::new();
            for function in self
                .functions
                .iter()
                .filter(|function| function.role == FunctionRole::Test)
            {
                *semantic_test_keys.entry(function.key).or_insert(0u32) += 1;
            }
            if planned_keys
                .into_iter()
                .any(|key| semantic_test_keys.get(&key) != Some(&1))
            {
                return Err(invalid(
                    "test plan function key does not name exactly one semantic test instance",
                ));
            }
        } else if !self.comptime_test_results.is_empty() {
            return Err(invalid("comptime results exist without a test plan"));
        }
        Ok(())
    }
}

fn root_matches_entry(analysis: &PartialAnalysis, graph: &ImageGraph) -> bool {
    let Some(entry) = analysis.functions.get(graph.entry.0 as usize) else {
        return false;
    };
    if entry.role != FunctionRole::ImageEntry {
        return false;
    }
    match (&analysis.root, &entry.origin) {
        (
            AnalysisRoot::DeclaredImage {
                image_name,
                declaration,
                ..
            },
            FunctionOrigin::Source {
                declaration: entry_declaration,
                ..
            },
        ) => graph.name == *image_name && declaration == entry_declaration,
        (
            AnalysisRoot::GeneratedTestHarness {
                group,
                harness_name,
            },
            FunctionOrigin::GeneratedTestHarness { group: entry_group },
        ) => graph.name == *harness_name && group == entry_group,
        _ => false,
    }
}

fn valid_function_roles(analysis: &PartialAnalysis, graph: &ImageGraph) -> bool {
    let mut image_entries = Vec::new();
    let mut actor_turns = vec![Vec::new(); graph.actors.len()];
    let mut device_interrupts = vec![Vec::new(); graph.devices.len()];
    let mut roles_valid = true;
    for function in &analysis.functions {
        match function.role {
            FunctionRole::ImageEntry => image_entries.push(function.id),
            FunctionRole::ActorTurn(actor) => {
                if let Some(turns) = actor_turns.get_mut(actor.0 as usize) {
                    turns.push(function.id);
                } else {
                    roles_valid = false;
                }
            }
            FunctionRole::TaskEntry(task) => {
                roles_valid &= graph
                    .tasks
                    .get(task.0 as usize)
                    .is_some_and(|node| node.entry == function.id);
            }
            FunctionRole::Isr(device) => {
                if let Some(interrupts) = device_interrupts.get_mut(device.0 as usize) {
                    interrupts.push(function.id);
                } else {
                    roles_valid = false;
                }
            }
            FunctionRole::Ordinary | FunctionRole::Cleanup | FunctionRole::Test => {}
        }
    }
    roles_valid
        && image_entries == [graph.entry]
        && graph.actors.iter().all(|actor| {
            actor_turns
                .get(actor.id.0 as usize)
                .is_some_and(|turns| actor.turn_functions == *turns)
        })
        && graph.devices.iter().all(|device| {
            device_interrupts
                .get(device.id.0 as usize)
                .is_some_and(|interrupts| device.interrupt_functions == *interrupts)
        })
        && graph.tasks.iter().all(|task| {
            analysis
                .functions
                .get(task.entry.0 as usize)
                .is_some_and(|function| function.role == FunctionRole::TaskEntry(task.id))
        })
}

fn valid_semantic_type(ty: &SemanticType, analysis: &PartialAnalysis, graph: &ImageGraph) -> bool {
    let type_id = |id: SemanticTypeId| (id.0 as usize) < analysis.types.len();
    let region_id = |id: RegionId| (id.0 as usize) < graph.regions.len();
    let brand_id = |id: BrandId| (id.0 as usize) < graph.brands.len();
    if !ty.alignment_lower_bound.is_power_of_two() {
        return false;
    }
    match &ty.kind {
        SemanticTypeKind::Error => false,
        SemanticTypeKind::Never
        | SemanticTypeKind::Unit
        | SemanticTypeKind::Bool
        | SemanticTypeKind::Character
        | SemanticTypeKind::StaticString { .. }
        | SemanticTypeKind::StaticBytes { .. } => true,
        SemanticTypeKind::Integer { bits, .. } => (1..=128).contains(bits),
        SemanticTypeKind::Float { bits } => matches!(bits, 32 | 64),
        SemanticTypeKind::Tuple(items) => items.iter().copied().all(type_id),
        SemanticTypeKind::Array { element, .. } => type_id(*element),
        SemanticTypeKind::Structure {
            declaration,
            arguments,
            fields,
        }
        | SemanticTypeKind::Class {
            declaration,
            arguments,
            fields,
        } => {
            declaration.0 < analysis.hir.declarations
                && arguments
                    .iter()
                    .all(|argument| valid_semantic_argument(argument, analysis, graph))
                && valid_fields(fields, analysis.types.len())
        }
        SemanticTypeKind::Enumeration {
            declaration,
            arguments,
            variants,
        } => {
            declaration.0 < analysis.hir.declarations
                && arguments
                    .iter()
                    .all(|argument| valid_semantic_argument(argument, analysis, graph))
                && !variants.is_empty()
                && unique_nonempty(variants.iter().map(|variant| variant.name.as_str()))
                && variants
                    .iter()
                    .all(|variant| valid_fields(&variant.fields, analysis.types.len()))
        }
        SemanticTypeKind::Function {
            parameters, result, ..
        } => type_id(*result) && parameters.iter().all(|parameter| type_id(parameter.ty)),
        SemanticTypeKind::View {
            target, provenance, ..
        } => {
            type_id(*target)
                && provenance.windows(2).all(|pair| pair[0] < pair[1])
                && provenance.iter().copied().all(region_id)
        }
        SemanticTypeKind::Iso { brand, payload } | SemanticTypeKind::Dma { brand, payload } => {
            brand_id(*brand) && type_id(*payload)
        }
        SemanticTypeKind::Actor { class } => type_id(*class),
        SemanticTypeKind::Receipt { payload, error }
        | SemanticTypeKind::Validated {
            format: payload,
            payload: error,
        } => type_id(*payload) && type_id(*error),
        SemanticTypeKind::Mmio { layout } => type_id(*layout),
        SemanticTypeKind::TargetOpaque { name } => !name.trim().is_empty(),
    }
}

fn valid_fields(fields: &[SemanticField], type_count: usize) -> bool {
    unique_nonempty(fields.iter().map(|field| field.name.as_str()))
        && fields
            .iter()
            .all(|field| (field.ty.0 as usize) < type_count)
}

fn valid_semantic_argument(
    argument: &SemanticArgument,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    match argument {
        SemanticArgument::Type(ty) => (ty.0 as usize) < analysis.types.len(),
        SemanticArgument::Constant(value) => valid_constant(value, analysis, graph),
        SemanticArgument::Region(region) => (region.0 as usize) < graph.regions.len(),
    }
}

fn valid_constant(root: &ConstantValue, analysis: &PartialAnalysis, graph: &ImageGraph) -> bool {
    let mut pending = vec![root];
    while let Some(value) = pending.pop() {
        match value {
            ConstantValue::Unsigned { bits, value } => {
                if *bits == 0
                    || *bits > 128
                    || (*bits < 128 && *value >= (1u128 << u32::from(*bits)))
                {
                    return false;
                }
            }
            ConstantValue::Signed { bits, value } => {
                if *bits == 0 || *bits > 128 {
                    return false;
                }
                if *bits < 128 {
                    let shift = u32::from(*bits - 1);
                    let minimum = -(1i128 << shift);
                    let maximum = (1i128 << shift) - 1;
                    if *value < minimum || *value > maximum {
                        return false;
                    }
                }
            }
            ConstantValue::Tuple(values) | ConstantValue::Array(values) => {
                pending.extend(values);
            }
            ConstantValue::Structure { ty, fields }
            | ConstantValue::Enumeration { ty, fields, .. } => {
                if ty.0 as usize >= analysis.types.len() {
                    return false;
                }
                pending.extend(fields);
            }
            ConstantValue::Type(ty) if ty.0 as usize >= analysis.types.len() => return false,
            ConstantValue::Brand(brand) if brand.0 as usize >= graph.brands.len() => return false,
            ConstantValue::Unit
            | ConstantValue::Bool(_)
            | ConstantValue::Float32(_)
            | ConstantValue::Float64(_)
            | ConstantValue::Character(_)
            | ConstantValue::Bytes(_)
            | ConstantValue::String(_)
            | ConstantValue::Type(_)
            | ConstantValue::Brand(_) => {}
        }
    }
    true
}

fn valid_expression_fact(
    fact: &ExpressionFact,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    (fact.function.0 as usize) < analysis.functions.len()
        && fact.expression.0 < analysis.hir.expressions
        && (fact.ty.0 as usize) < analysis.types.len()
        && (fact.region.0 as usize) < graph.regions.len()
        && fact.effects.is_valid()
        && valid_proof_set(&fact.proofs, analysis.proofs.len())
        && valid_expression_resolution(&fact.resolution, fact.function, analysis, graph)
}

fn valid_expression_resolution(
    resolution: &ExpressionResolution,
    function: FunctionInstanceId,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    let function_id = |id: FunctionInstanceId| (id.0 as usize) < analysis.functions.len();
    let proof_id = |id: ProofId| (id.0 as usize) < analysis.proofs.len();
    let value_id = |id: ValueId| {
        analysis
            .values
            .get(id.0 as usize)
            .is_some_and(|value| value.function == function)
    };
    match resolution {
        ExpressionResolution::Error => false,
        ExpressionResolution::Constant(value) => valid_constant(value, analysis, graph),
        ExpressionResolution::Value(value) => value_id(*value),
        ExpressionResolution::Function(target) => function_id(*target),
        ExpressionResolution::Constructor { ty, .. } => (ty.0 as usize) < analysis.types.len(),
        ExpressionResolution::DirectCall {
            function: target,
            argument_access,
        } => analysis
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| {
                argument_access.len() == target.parameters.len()
                    && argument_access
                        .iter()
                        .zip(&target.parameters)
                        .all(|(actual, expected)| *actual == expected.access)
            }),
        ExpressionResolution::ActorRequest {
            actor,
            method,
            permit,
        } => (actor.0 as usize) < graph.actors.len() && function_id(*method) && proof_id(*permit),
        ExpressionResolution::Closure {
            function: target,
            captures,
        } => {
            function_id(*target)
                && captures.windows(2).all(|pair| pair[0] < pair[1])
                && captures.iter().copied().all(value_id)
        }
        ExpressionResolution::Field { .. } => true,
        ExpressionResolution::Index { bounds } => proof_id(*bounds),
        ExpressionResolution::Builtin(operation) => valid_intrinsic(operation, analysis, graph),
    }
}

fn valid_intrinsic(
    operation: &IntrinsicOperation,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    let proof = |id: ProofId| (id.0 as usize) < analysis.proofs.len();
    let actor = |id: ActorId| (id.0 as usize) < graph.actors.len();
    let task = |id: TaskId| (id.0 as usize) < graph.tasks.len();
    let device = |id: DeviceId| (id.0 as usize) < graph.devices.len();
    let pool = |id: PoolId| (id.0 as usize) < graph.pools.len();
    let region = |id: RegionId| (id.0 as usize) < graph.regions.len();
    match operation {
        IntrinsicOperation::RegionAllocate {
            region: id,
            capacity,
        } => region(*id) && proof(*capacity),
        IntrinsicOperation::RegionReset { region: id } => region(*id),
        IntrinsicOperation::ActorSend { actor: id }
        | IntrinsicOperation::ActorTrySend { actor: id } => actor(*id),
        IntrinsicOperation::TaskSpawn { task: id, slots } => task(*id) && proof(*slots),
        IntrinsicOperation::DmaPrepare {
            device: device_id,
            pool: pool_id,
            proof: proof_id,
        }
        | IntrinsicOperation::DmaComplete {
            device: device_id,
            pool: pool_id,
            proof: proof_id,
        }
        | IntrinsicOperation::DmaQuarantine {
            device: device_id,
            pool: pool_id,
            proof: proof_id,
        } => device(*device_id) && pool(*pool_id) && proof(*proof_id),
        IntrinsicOperation::MmioRead {
            device: device_id,
            proof: proof_id,
            ..
        }
        | IntrinsicOperation::MmioWrite {
            device: device_id,
            proof: proof_id,
            ..
        }
        | IntrinsicOperation::QueueReserve {
            device: device_id,
            proof: proof_id,
        }
        | IntrinsicOperation::DeviceValidate {
            device: device_id,
            proof: proof_id,
        } => device(*device_id) && proof(*proof_id),
        IntrinsicOperation::Await
        | IntrinsicOperation::Race
        | IntrinsicOperation::Select
        | IntrinsicOperation::Cancel
        | IntrinsicOperation::Checkpoint
        | IntrinsicOperation::RecordEvent { .. }
        | IntrinsicOperation::ReplayEvent { .. } => true,
    }
}

fn valid_statement_fact(
    fact: &StatementFact,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    let value = |id: ValueId| {
        analysis
            .values
            .get(id.0 as usize)
            .is_some_and(|value| value.function == fact.function)
    };
    (fact.function.0 as usize) < analysis.functions.len()
        && fact.statement.0 < analysis.hir.statements
        && fact.effects.is_valid()
        && strict_ids(&fact.initialized_after)
        && strict_ids(&fact.moved_after)
        && fact.initialized_after.iter().copied().all(value)
        && fact.moved_after.iter().copied().all(value)
        && valid_proof_set(&fact.proofs, analysis.proofs.len())
        && {
            let mut seen = std::collections::BTreeSet::new();
            fact.live_loans_after.iter().all(|loan| {
                seen.insert(loan.value)
                    && value(loan.value)
                    && (loan.region.0 as usize) < graph.regions.len()
            })
        }
}

fn valid_image_graph(graph: &ImageGraph, analysis: &PartialAnalysis) -> bool {
    if graph.peak_bytes < graph.static_bytes
        || !unique_nonempty(graph.actors.iter().map(|item| item.name.as_str()))
        || !unique_nonempty(graph.tasks.iter().map(|item| item.name.as_str()))
        || !unique_nonempty(graph.devices.iter().map(|item| item.name.as_str()))
        || !unique_nonempty(graph.pools.iter().map(|item| item.name.as_str()))
        || !unique_nonempty(graph.regions.iter().map(|item| item.name.as_str()))
    {
        return false;
    }
    let proof = |id: ProofId| (id.0 as usize) < analysis.proofs.len();
    let owner = |value: ImageOwner| valid_owner(value, graph, analysis.baked_artifacts.len());
    if graph.actors.iter().any(|actor| {
        actor.class.0 as usize >= analysis.types.len()
            || actor
                .message_types
                .iter()
                .any(|ty| ty.0 as usize >= analysis.types.len())
            || !strict_ids(&actor.turn_functions)
            || actor
                .turn_functions
                .iter()
                .any(|function| function.0 as usize >= analysis.functions.len())
            || actor
                .supervisor
                .is_some_and(|id| id == actor.id || id.0 as usize >= graph.actors.len())
    }) || graph.tasks.iter().any(|task| {
        task.entry.0 as usize >= analysis.functions.len()
            || task.slots == 0
            || task
                .supervisor
                .is_some_and(|id| id.0 as usize >= graph.actors.len())
    }) || graph.devices.iter().any(|device| {
        device.name.trim().is_empty()
            || device.target_binding.trim().is_empty()
            || device.owner.0 as usize >= graph.actors.len()
            || device.reset_timeout_ns == 0
            || device.interrupt_functions.len() > 1
            || !strict_ids(&device.interrupt_functions)
            || device
                .interrupt_functions
                .iter()
                .any(|function| function.0 as usize >= analysis.functions.len())
            || !strict_strings(&device.required_features)
            || !strict_strings(&device.optional_features)
            || device.required_features.iter().any(|feature| {
                device.optional_features.binary_search(feature).is_ok()
            })
    }) || graph.pools.iter().any(|pool| {
        pool.brand.0 as usize >= graph.brands.len()
            || pool.payload.0 as usize >= analysis.types.len()
            || pool.capacity == 0
            || !pool.alignment.is_power_of_two()
            || !strict_ids(&pool.reachable_devices)
            || pool
                .reachable_devices
                .iter()
                .any(|device| device.0 as usize >= graph.devices.len())
    }) || graph.regions.iter().any(|region| {
        region.capacity_bytes == 0
            || !region.alignment.is_power_of_two()
            || !owner(region.owner)
            || !proof(region.proof)
            || matches!(region.class, RegionClass::Pool(pool) if pool.0 as usize >= graph.pools.len())
    }) || graph.brands.iter().any(|brand| {
        brand.declaration.0 >= analysis.hir.declarations || !owner(brand.owner)
    }) {
        return false;
    }
    let mut required = std::collections::BTreeSet::from([ImageOwner::Runtime]);
    required.extend(graph.actors.iter().map(|node| ImageOwner::Actor(node.id)));
    required.extend(graph.tasks.iter().map(|node| ImageOwner::Task(node.id)));
    required.extend(graph.devices.iter().map(|node| ImageOwner::Device(node.id)));
    required.extend(graph.pools.iter().map(|node| ImageOwner::Pool(node.id)));
    let startup: std::collections::BTreeSet<_> = graph.startup_order.iter().copied().collect();
    let shutdown: std::collections::BTreeSet<_> = graph.shutdown_order.iter().copied().collect();
    graph.startup_order.len() == startup.len()
        && graph.shutdown_order.len() == shutdown.len()
        && startup == required
        && shutdown == required
}

fn valid_owner(owner: ImageOwner, graph: &ImageGraph, artifacts: usize) -> bool {
    match owner {
        ImageOwner::Runtime => true,
        ImageOwner::Actor(id) => (id.0 as usize) < graph.actors.len(),
        ImageOwner::Task(id) => (id.0 as usize) < graph.tasks.len(),
        ImageOwner::Device(id) => (id.0 as usize) < graph.devices.len(),
        ImageOwner::Pool(id) => (id.0 as usize) < graph.pools.len(),
        ImageOwner::Artifact(id) => (id.0 as usize) < artifacts,
    }
}

fn valid_proof_set(proofs: &[ProofId], proof_count: usize) -> bool {
    proofs.windows(2).all(|pair| pair[0] < pair[1])
        && proofs.iter().all(|proof| (proof.0 as usize) < proof_count)
}

fn strict_ids<T>(values: &[T]) -> bool
where
    T: Copy + Ord,
{
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn has_duplicate_ids(values: impl IntoIterator<Item = u32>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

fn strict_strings(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn unique_nonempty<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .all(|value| !value.trim().is_empty() && seen.insert(value))
}

fn dense(ids: impl IntoIterator<Item = u32>) -> bool {
    ids.into_iter()
        .enumerate()
        .all(|(expected, actual)| expected == actual as usize)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzedImage(PartialAnalysis);

impl AnalyzedImage {
    #[must_use]
    pub fn facts(&self) -> &PartialAnalysis {
        &self.0
    }
    #[must_use]
    pub fn into_facts(self) -> PartialAnalysis {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisOutput {
    product: AnalysisProduct,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq)]
enum AnalysisProduct {
    Partial(PartialAnalysis),
    Complete(AnalyzedImage),
}

impl AnalysisOutput {
    #[must_use]
    pub fn partial(&self) -> &PartialAnalysis {
        match &self.product {
            AnalysisProduct::Partial(partial) => partial,
            AnalysisProduct::Complete(image) => image.facts(),
        }
    }

    #[must_use]
    pub fn successful(&self) -> Option<&AnalyzedImage> {
        match &self.product {
            AnalysisProduct::Partial(_) => None,
            AnalysisProduct::Complete(image) => Some(image),
        }
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn into_parts(self) -> (Result<AnalyzedImage, PartialAnalysis>, Vec<Diagnostic>) {
        let product = match self.product {
            AnalysisProduct::Partial(partial) => Err(partial),
            AnalysisProduct::Complete(image) => Ok(image),
        };
        (product, self.diagnostics)
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error)
    }
}

pub trait SemanticAnalyzer {
    fn analyze(
        &self,
        request: AnalysisRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AnalysisOutput, AnalysisFailure>;
}

/// Finish one analysis without duplicating the image-sized fact database.
/// Error diagnostics retain a partial database; an error-free result is the
/// sole public route to `AnalyzedImage`.
pub fn finish_analysis(
    request: &AnalysisRequest<'_>,
    partial: PartialAnalysis,
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisOutput, AnalysisFailure> {
    if is_cancelled() {
        return Err(AnalysisFailure::Cancelled);
    }
    validate_analysis_request(request, &partial, &diagnostics)?;
    partial.validate_partial_structure()?;
    let mut diagnostics = WithDiagnostics {
        value: (),
        diagnostics,
    };
    diagnostics.sort_diagnostics();
    let product = if diagnostics.has_errors() {
        AnalysisProduct::Partial(partial)
    } else {
        partial.validate_for_seal()?;
        AnalysisProduct::Complete(AnalyzedImage(partial))
    };
    if is_cancelled() {
        return Err(AnalysisFailure::Cancelled);
    }
    Ok(AnalysisOutput {
        product,
        diagnostics: diagnostics.diagnostics,
    })
}

fn valid_declared_test_inputs(tests: &[DeclaredImageTest]) -> bool {
    tests.windows(2).all(|pair| pair[0].name < pair[1].name)
        && tests.iter().all(|test| {
            !test.name.trim().is_empty()
                && !test.image_name.trim().is_empty()
                && test.boot_timeout_ns > 0
                && test.shutdown_timeout_ns > 0
                && test.maximum_events > 0
                && test.maximum_output_bytes > 0
                && test.scenario.validate_shape().is_ok()
        })
}

fn test_plan_matches_declarations(
    validated: &ValidatedTestPlan,
    declared: &[DeclaredImageTest],
) -> bool {
    let plan = validated.as_plan();
    let declared_groups: Vec<_> = plan
        .image_groups
        .iter()
        .filter(|group| matches!(group.root, TestImageRoot::Declared { .. }))
        .collect();
    declared_groups.len() == declared.len()
        && declared_groups
            .into_iter()
            .zip(declared)
            .all(|(group, expected)| {
                let (image_name, scenario_id) = match &group.root {
                    TestImageRoot::Declared {
                        image_name,
                        scenario,
                    } => (image_name, *scenario),
                    TestImageRoot::GeneratedHarness { .. } => return false,
                };
                let Some(scenario) = plan.scenarios.get(scenario_id.0 as usize) else {
                    return false;
                };
                let expected_timeout = group.execution_timeout_ns(Some(scenario));
                group.name == expected.name
                    && image_name == &expected.image_name
                    && scenario == &expected.scenario
                    && group.tests.len() == 1
                    && group.tests[0].descriptor.name == expected.name
                    && group.tests[0].descriptor.timeout_ns == expected_timeout.unwrap_or(0)
                    && matches!(
                        group.tests[0].invocation,
                        wrela_test_model::ImageTestInvocation::DeclaredScenario
                    )
                    && group.deterministic_seed == expected.deterministic_seed
                    && group.boot_timeout_ns == expected.boot_timeout_ns
                    && group.shutdown_timeout_ns == expected.shutdown_timeout_ns
                    && group.maximum_events == expected.maximum_events
                    && group.maximum_output_bytes == expected.maximum_output_bytes
            })
}

fn validate_analysis_request(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    diagnostics: &[Diagnostic],
) -> Result<(), AnalysisFailure> {
    request.limits.validate()?;
    request
        .build
        .validate()
        .map_err(|error| AnalysisFailure::InvalidBuild(error.to_string()))?;
    let hir = HirSummary::from_validated(request.hir)?;
    let expected_root = match &request.mode {
        AnalysisMode::Image { name, entry } => {
            if name.trim().is_empty() || entry.0 >= hir.declarations {
                return Err(AnalysisFailure::RequestMismatch);
            }
            AnalysisRoot::DeclaredImage {
                image_name: (*name).to_owned(),
                declaration: *entry,
                test_group: None,
            }
        }
        AnalysisMode::DiscoverTests {
            image_name,
            image_entry,
            declared_image_tests,
        } => {
            if image_name.trim().is_empty()
                || image_entry.0 >= hir.declarations
                || !valid_declared_test_inputs(declared_image_tests)
            {
                return Err(AnalysisFailure::RequestMismatch);
            }
            if let Some(plan) = &partial.test_plan {
                if !test_plan_matches_declarations(plan, declared_image_tests) {
                    return Err(AnalysisFailure::RequestMismatch);
                }
            }
            AnalysisRoot::DeclaredImage {
                image_name: (*image_name).to_owned(),
                declaration: *image_entry,
                test_group: None,
            }
        }
        AnalysisMode::CompileTestGroup {
            plan,
            group,
            declared_entry,
        } => {
            if plan.build() != &request.build.identity
                || plan.target() != request.target.identity()
                || !test_plan_policy_within_analysis_limits(plan, request.limits)
                || partial.test_plan.is_some()
                || !partial.comptime_test_results.is_empty()
            {
                return Err(AnalysisFailure::RequestMismatch);
            }
            let group_record = plan.group(*group).ok_or(AnalysisFailure::RequestMismatch)?;
            match (&group_record.root, declared_entry) {
                (TestImageRoot::GeneratedHarness { harness_name }, None) => {
                    AnalysisRoot::GeneratedTestHarness {
                        group: *group,
                        harness_name: harness_name.clone(),
                    }
                }
                (TestImageRoot::Declared { image_name, .. }, Some(declaration))
                    if declaration.0 < hir.declarations =>
                {
                    AnalysisRoot::DeclaredImage {
                        image_name: image_name.clone(),
                        declaration: *declaration,
                        test_group: Some(*group),
                    }
                }
                _ => return Err(AnalysisFailure::RequestMismatch),
            }
        }
    };
    if partial.hir != hir
        || partial.build != request.build.identity
        || partial.target_digest != request.target.content_digest()
        || partial.target_digest != request.build.identity.target_package
        || request.target.identity() != &request.build.identity.target
        || partial.root != expected_root
        || request
            .changes
            .changed_declarations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || request
            .changes
            .changed_declarations
            .iter()
            .any(|declaration| declaration.0 >= hir.declarations)
        || (request.changes.previous_source_graph == Some(request.build.identity.source_graph)
            && !request.changes.changed_declarations.is_empty())
        || partial
            .graph
            .as_ref()
            .is_some_and(|graph| !graph_matches_target(graph, request.target))
    {
        return Err(AnalysisFailure::RequestMismatch);
    }
    let has_error = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error);
    match request.mode.intent() {
        AnalysisIntent::Build | AnalysisIntent::TestExecution
            if partial.test_plan.is_some() || !partial.comptime_test_results.is_empty() =>
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        AnalysisIntent::TestDiscovery if !has_error && partial.test_plan.is_none() => {
            return Err(AnalysisFailure::RequestMismatch);
        }
        AnalysisIntent::Build | AnalysisIntent::TestDiscovery | AnalysisIntent::TestExecution => {}
    }
    if !has_error && !successful_mode_matches_functions(&request.mode, partial) {
        return Err(AnalysisFailure::RequestMismatch);
    }
    let bounded_counts = [
        ("semantic types", partial.types.len(), request.limits.types),
        (
            "monomorphizations",
            partial.functions.len(),
            request.limits.monomorphizations,
        ),
        (
            "semantic values",
            partial.values.len(),
            request.limits.values,
        ),
        (
            "expression facts",
            partial.expressions.len(),
            request.limits.expression_facts,
        ),
        (
            "statement facts",
            partial.statements.len(),
            request.limits.statement_facts,
        ),
        (
            "scope protocols",
            partial.scope_protocols.len(),
            request.limits.scope_protocols,
        ),
        (
            "scope activations",
            partial.scope_activations.len(),
            request.limits.scope_activations,
        ),
        ("proofs", partial.proofs.len(), request.limits.proofs),
        (
            "baked artifacts",
            partial.baked_artifacts.len(),
            request.limits.baked_artifacts,
        ),
    ];
    if let Some((resource, _, limit)) = bounded_counts
        .into_iter()
        .find(|(_, count, limit)| *count > *limit as usize)
    {
        return Err(AnalysisFailure::ResourceLimit {
            resource,
            limit: u64::from(limit),
        });
    }
    validate_fact_resources(partial, request.limits)?;
    let image_nodes = partial.graph.as_ref().map_or(0usize, |graph| {
        graph.actors.len()
            + graph.tasks.len()
            + graph.devices.len()
            + graph.pools.len()
            + graph.regions.len()
            + graph.brands.len()
    });
    if image_nodes > request.limits.image_nodes as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "image nodes",
            limit: u64::from(request.limits.image_nodes),
        });
    }
    let proof_edges = partial.proofs.iter().try_fold(0u64, |total, proof| {
        total.checked_add(u64::try_from(proof.depends_on.len()).ok()?)
    });
    if proof_edges.is_none_or(|count| count > request.limits.proof_edges) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "proof edges",
            limit: request.limits.proof_edges,
        });
    }
    let artifact_bytes = partial
        .baked_artifacts
        .iter()
        .try_fold(0u64, |total, artifact| {
            total.checked_add(u64::try_from(artifact.bytes.len()).ok()?)
        });
    if artifact_bytes.is_none_or(|count| count > request.limits.baked_artifact_bytes) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "baked artifact bytes",
            limit: request.limits.baked_artifact_bytes,
        });
    }
    let test_count = partial.test_plan.as_ref().map_or(0usize, |plan| {
        let plan = plan.as_plan();
        plan.unit_tests.len()
            + plan
                .image_groups
                .iter()
                .map(|group| group.tests.len())
                .sum::<usize>()
    });
    let test_groups = partial
        .test_plan
        .as_ref()
        .map_or(0usize, |plan| plan.image_groups().len());
    let test_scenarios = partial
        .test_plan
        .as_ref()
        .map_or(0usize, |plan| plan.scenarios().len());
    let test_scenario_steps = partial
        .test_plan
        .as_ref()
        .map_or(0usize, ValidatedTestPlan::scenario_step_count);
    let test_bytes = partial
        .test_plan
        .as_ref()
        .map_or(Some(0u64), |plan| Some(plan.payload_bytes()))
        .and_then(|initial| test_result_payload_bytes(&partial.comptime_test_results, initial));
    let test_group_limits_hold = partial.test_plan.as_ref().is_none_or(|plan| {
        test_plan_policy_within_analysis_limits(plan, request.limits)
            && plan.image_groups().iter().all(|group| {
                let scenario = match &group.root {
                    TestImageRoot::GeneratedHarness { .. } => None,
                    TestImageRoot::Declared { scenario, .. } => {
                        plan.scenarios().get(scenario.0 as usize)
                    }
                };
                group.maximum_events <= request.limits.test_events_per_group
                    && group.maximum_output_bytes <= request.limits.test_output_bytes_per_group
                    && group
                        .execution_timeout_ns(scenario)
                        .is_some_and(|timeout| timeout <= request.limits.test_timeout_ns_per_group)
            })
    });
    if test_count > request.limits.tests as usize
        || test_groups > request.limits.test_groups as usize
        || test_scenarios > request.limits.test_scenarios as usize
        || test_scenario_steps > request.limits.test_scenario_steps as usize
        || test_bytes.is_none_or(|bytes| bytes > request.limits.test_bytes)
        || partial.comptime_test_results.len() > request.limits.tests as usize
        || !test_group_limits_hold
    {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        });
    }
    if diagnostics.len() > request.limits.diagnostic_count as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "diagnostics",
            limit: u64::from(request.limits.diagnostic_count),
        });
    }
    let mut diagnostic_bytes = 0u64;
    for diagnostic in diagnostics {
        if !valid_analysis_diagnostic(diagnostic, hir.files) {
            return Err(AnalysisFailure::InternalInvariant(
                "semantic diagnostic is malformed or outside the HIR source graph".to_owned(),
            ));
        }
        for value in std::iter::once(diagnostic.message.as_str())
            .chain(diagnostic.code.iter().map(String::as_str))
            .chain(diagnostic.labels.iter().map(|value| value.message.as_str()))
            .chain(diagnostic.notes.iter().map(String::as_str))
            .chain(diagnostic.help.iter().map(String::as_str))
            .chain(
                diagnostic
                    .related
                    .iter()
                    .map(|value| value.message.as_str()),
            )
            .chain(
                diagnostic
                    .repairs
                    .iter()
                    .map(|value| value.message.as_str()),
            )
            .chain(
                diagnostic
                    .repairs
                    .iter()
                    .flat_map(|repair| repair.edits.iter())
                    .map(|edit| edit.replacement.as_str()),
            )
        {
            diagnostic_bytes = diagnostic_bytes
                .checked_add(u64::try_from(value.len()).map_err(|_| {
                    AnalysisFailure::ResourceLimit {
                        resource: "diagnostic bytes",
                        limit: request.limits.diagnostic_bytes,
                    }
                })?)
                .ok_or(AnalysisFailure::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: request.limits.diagnostic_bytes,
                })?;
        }
    }
    if diagnostic_bytes > request.limits.diagnostic_bytes {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "diagnostic bytes",
            limit: request.limits.diagnostic_bytes,
        });
    }
    Ok(())
}

fn test_plan_policy_within_analysis_limits(
    plan: &ValidatedTestPlan,
    limits: AnalysisLimits,
) -> bool {
    let plan_limits = plan.limits();
    plan_limits.tests <= limits.tests
        && plan_limits.groups <= limits.test_groups
        && plan_limits.scenarios <= limits.test_scenarios
        && plan_limits.scenario_steps <= limits.test_scenario_steps
        && plan_limits.payload_bytes <= limits.test_bytes
        && plan_limits.report_bytes <= limits.test_report_bytes
        && plan_limits.events_per_group <= limits.test_events_per_group
        && plan_limits.output_bytes_per_group <= limits.test_output_bytes_per_group
        && plan_limits.execution_timeout_ns_per_group <= limits.test_timeout_ns_per_group
}

#[derive(Default)]
struct FactResourceMeter {
    edges: u64,
    bytes: u64,
    maximum_constant_depth: u32,
    overflowed: bool,
}

impl FactResourceMeter {
    fn edges<T>(&mut self, values: &[T]) {
        self.add_edges(values.len());
    }

    fn add_edges(&mut self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.edges.checked_add(count) {
            self.edges = total;
        } else {
            self.overflowed = true;
        }
    }

    fn text(&mut self, value: &str) {
        self.add_bytes(value.len());
    }

    fn byte_string(&mut self, value: &[u8]) {
        self.add_bytes(value.len());
    }

    fn add_bytes(&mut self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.bytes.checked_add(count) {
            self.bytes = total;
        } else {
            self.overflowed = true;
        }
    }
}

fn validate_fact_resources(
    partial: &PartialAnalysis,
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    let mut meter = FactResourceMeter::default();
    for count in [
        partial.types.len(),
        partial.functions.len(),
        partial.values.len(),
        partial.expressions.len(),
        partial.statements.len(),
        partial.scope_protocols.len(),
        partial.scope_activations.len(),
        partial.proofs.len(),
        partial.baked_artifacts.len(),
    ] {
        meter.add_edges(count);
    }
    match &partial.root {
        AnalysisRoot::DeclaredImage { image_name, .. } => meter.text(image_name),
        AnalysisRoot::GeneratedTestHarness { harness_name, .. } => meter.text(harness_name),
    }

    let mut constants: Vec<(&ConstantValue, u32)> = Vec::new();
    for ty in &partial.types {
        match &ty.kind {
            SemanticTypeKind::Tuple(items) => meter.edges(items),
            SemanticTypeKind::Structure {
                arguments, fields, ..
            }
            | SemanticTypeKind::Class {
                arguments, fields, ..
            } => {
                meter.edges(arguments);
                meter.edges(fields);
                for item in arguments {
                    queue_constant_argument(item, &mut constants);
                }
                for field in fields {
                    meter.text(&field.name);
                }
            }
            SemanticTypeKind::Enumeration {
                arguments,
                variants,
                ..
            } => {
                meter.edges(arguments);
                meter.edges(variants);
                for item in arguments {
                    queue_constant_argument(item, &mut constants);
                }
                for variant in variants {
                    meter.text(&variant.name);
                    meter.edges(&variant.fields);
                    for field in &variant.fields {
                        meter.text(&field.name);
                    }
                }
            }
            SemanticTypeKind::Function { parameters, .. } => meter.edges(parameters),
            SemanticTypeKind::View { provenance, .. } => meter.edges(provenance),
            SemanticTypeKind::TargetOpaque { name } => meter.text(name),
            SemanticTypeKind::Error
            | SemanticTypeKind::Never
            | SemanticTypeKind::Unit
            | SemanticTypeKind::Bool
            | SemanticTypeKind::Integer { .. }
            | SemanticTypeKind::Float { .. }
            | SemanticTypeKind::Character
            | SemanticTypeKind::StaticString { .. }
            | SemanticTypeKind::StaticBytes { .. }
            | SemanticTypeKind::Array { .. }
            | SemanticTypeKind::Iso { .. }
            | SemanticTypeKind::Actor { .. }
            | SemanticTypeKind::Receipt { .. }
            | SemanticTypeKind::Dma { .. }
            | SemanticTypeKind::Mmio { .. }
            | SemanticTypeKind::Validated { .. } => {}
        }
    }
    for function in &partial.functions {
        meter.text(&function.name);
        meter.edges(&function.generic_arguments);
        meter.edges(&function.parameters);
        meter.edges(&function.proofs);
        for item in &function.generic_arguments {
            queue_constant_argument(item, &mut constants);
        }
    }
    for value in &partial.values {
        if let Some(name) = &value.source_name {
            meter.text(name);
        }
    }
    for fact in &partial.expressions {
        meter.edges(&fact.proofs);
        match &fact.resolution {
            ExpressionResolution::Constant(value) => constants.push((value, 1)),
            ExpressionResolution::DirectCall {
                argument_access, ..
            } => meter.edges(argument_access),
            ExpressionResolution::Closure { captures, .. } => meter.edges(captures),
            ExpressionResolution::Error
            | ExpressionResolution::Value(_)
            | ExpressionResolution::Function(_)
            | ExpressionResolution::Constructor { .. }
            | ExpressionResolution::ActorRequest { .. }
            | ExpressionResolution::Field { .. }
            | ExpressionResolution::Index { .. }
            | ExpressionResolution::Builtin(_) => {}
        }
    }
    for fact in &partial.statements {
        meter.edges(&fact.initialized_after);
        meter.edges(&fact.moved_after);
        meter.edges(&fact.live_loans_after);
        meter.edges(&fact.proofs);
    }
    for protocol in &partial.scope_protocols {
        meter.text(&protocol.name);
        meter.edges(&protocol.parameters);
    }
    for activation in &partial.scope_activations {
        meter.edges(&activation.cleanup_dependencies);
    }
    if let Some(graph) = &partial.graph {
        meter.text(&graph.name);
        for count in [
            graph.actors.len(),
            graph.tasks.len(),
            graph.devices.len(),
            graph.pools.len(),
            graph.regions.len(),
            graph.brands.len(),
            graph.startup_order.len(),
            graph.shutdown_order.len(),
        ] {
            meter.add_edges(count);
        }
        for actor in &graph.actors {
            meter.text(&actor.name);
            meter.edges(&actor.message_types);
            meter.edges(&actor.turn_functions);
        }
        for task in &graph.tasks {
            meter.text(&task.name);
        }
        for device in &graph.devices {
            meter.text(&device.name);
            meter.text(&device.target_binding);
            meter.edges(&device.required_features);
            meter.edges(&device.optional_features);
            meter.edges(&device.interrupt_functions);
            for feature in device
                .required_features
                .iter()
                .chain(&device.optional_features)
            {
                meter.text(feature);
            }
        }
        for pool in &graph.pools {
            meter.text(&pool.name);
            meter.edges(&pool.reachable_devices);
        }
        for region in &graph.regions {
            meter.text(&region.name);
        }
    }
    for proof in &partial.proofs {
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            meter.text(line);
        }
    }
    for artifact in &partial.baked_artifacts {
        meter.text(&artifact.name);
        meter.text(&artifact.media_type);
    }
    while let Some((constant, depth)) = constants.pop() {
        meter.add_edges(1);
        meter.maximum_constant_depth = meter.maximum_constant_depth.max(depth);
        match constant {
            ConstantValue::Bytes(bytes) => meter.byte_string(bytes),
            ConstantValue::String(value) => meter.text(value),
            ConstantValue::Tuple(values)
            | ConstantValue::Array(values)
            | ConstantValue::Structure { fields: values, .. }
            | ConstantValue::Enumeration { fields: values, .. } => {
                meter.edges(values);
                let Some(next) = depth.checked_add(1) else {
                    meter.overflowed = true;
                    continue;
                };
                constants.extend(values.iter().map(|value| (value, next)));
            }
            ConstantValue::Unit
            | ConstantValue::Bool(_)
            | ConstantValue::Unsigned { .. }
            | ConstantValue::Signed { .. }
            | ConstantValue::Float32(_)
            | ConstantValue::Float64(_)
            | ConstantValue::Character(_)
            | ConstantValue::Type(_)
            | ConstantValue::Brand(_) => {}
        }
    }
    if meter.overflowed
        || meter.edges > limits.fact_edges
        || meter.bytes > limits.fact_bytes
        || meter.maximum_constant_depth > limits.constant_depth
    {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic fact edges, payload bytes, or constant depth",
            limit: limits.fact_bytes,
        });
    }
    Ok(())
}

fn queue_constant_argument<'a>(
    argument: &'a SemanticArgument,
    constants: &mut Vec<(&'a ConstantValue, u32)>,
) {
    if let SemanticArgument::Constant(value) = argument {
        constants.push((value, 1));
    }
}

fn graph_matches_target(graph: &ImageGraph, target: &TargetSemanticContract) -> bool {
    let mut claimed = std::collections::BTreeSet::new();
    graph.devices.iter().all(|device| {
        claimed.insert(device.target_binding.as_str())
            && device.interrupt_functions.len() <= 1
            && target
                .mmio_bindings()
                .binary_search_by(|binding| binding.name.cmp(&device.target_binding))
                .ok()
                .and_then(|index| target.mmio_bindings().get(index))
                .is_some_and(|binding| {
                    device.interrupt_functions.is_empty() || binding.interrupt.is_some()
                })
    })
}

fn test_result_payload_bytes(results: &[TestCaseResult], initial: u64) -> Option<u64> {
    results.iter().try_fold(initial, |total, result| {
        let message = match &result.outcome {
            wrela_test_model::TestOutcome::Failed { message, .. }
            | wrela_test_model::TestOutcome::Crashed { message, .. } => message.len(),
            wrela_test_model::TestOutcome::Passed
            | wrela_test_model::TestOutcome::TimedOut { .. } => 0,
        };
        total
            .checked_add(u64::try_from(result.descriptor.name.len()).ok()?)?
            .checked_add(u64::try_from(message).ok()?)
    })
}

fn successful_mode_matches_functions(mode: &AnalysisMode<'_>, partial: &PartialAnalysis) -> bool {
    let actual_tests: std::collections::BTreeSet<_> = partial
        .functions
        .iter()
        .filter(|function| function.role == FunctionRole::Test)
        .map(|function| function.key)
        .collect();
    let generated: Vec<_> = partial
        .functions
        .iter()
        .filter_map(|function| match function.origin {
            FunctionOrigin::GeneratedTestHarness { group } => Some((function.id, group)),
            FunctionOrigin::Source { .. } => None,
        })
        .collect();
    match mode {
        AnalysisMode::Image { .. } => actual_tests.is_empty() && generated.is_empty(),
        AnalysisMode::DiscoverTests { .. } => {
            let Some(plan) = partial.test_plan.as_ref().map(ValidatedTestPlan::as_plan) else {
                return false;
            };
            let planned: std::collections::BTreeSet<_> = plan
                .unit_tests
                .iter()
                .map(|test| test.function_key)
                .chain(plan.image_groups.iter().flat_map(|group| {
                    group.tests.iter().filter_map(|test| match test.invocation {
                        wrela_test_model::ImageTestInvocation::GeneratedFunction {
                            function_key,
                        } => Some(function_key),
                        wrela_test_model::ImageTestInvocation::DeclaredScenario => None,
                    })
                }))
                .collect();
            actual_tests == planned && generated.is_empty()
        }
        AnalysisMode::CompileTestGroup { plan, group, .. } => {
            let Some(group_record) = plan.group(*group) else {
                return false;
            };
            match group_record.root {
                TestImageRoot::GeneratedHarness { .. } => {
                    let planned: std::collections::BTreeSet<_> = group_record
                        .tests
                        .iter()
                        .filter_map(|test| match test.invocation {
                            wrela_test_model::ImageTestInvocation::GeneratedFunction {
                                function_key,
                            } => Some(function_key),
                            wrela_test_model::ImageTestInvocation::DeclaredScenario => None,
                        })
                        .collect();
                    actual_tests == planned
                        && generated
                            == vec![(
                                partial
                                    .graph
                                    .as_ref()
                                    .map_or(FunctionInstanceId(u32::MAX), |graph| graph.entry),
                                *group,
                            )]
                }
                TestImageRoot::Declared { .. } => actual_tests.is_empty() && generated.is_empty(),
            }
        }
    }
}

fn valid_analysis_diagnostic(diagnostic: &Diagnostic, files: u32) -> bool {
    !diagnostic.message.trim().is_empty()
        && valid_span(diagnostic.primary, files)
        && diagnostic
            .labels
            .iter()
            .all(|label| !label.message.trim().is_empty() && valid_span(label.span, files))
        && diagnostic
            .related
            .iter()
            .all(|related| !related.message.trim().is_empty() && valid_span(related.span, files))
        && diagnostic.repairs.iter().all(|repair| {
            !repair.message.trim().is_empty()
                && !repair.edits.is_empty()
                && repair.edits.iter().all(|edit| valid_span(edit.span, files))
                && repair.edits.windows(2).all(|pair| {
                    (pair[0].span.file, pair[0].span.range.start)
                        < (pair[1].span.file, pair[1].span.range.start)
                        && (pair[0].span.file != pair[1].span.file
                            || pair[0].span.range.end <= pair[1].span.range.start)
                })
        })
}

fn valid_span(span: Span, files: u32) -> bool {
    span.file.0 < files && span.range.start <= span.range.end
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisFailure {
    Cancelled,
    InvalidLimits,
    InvalidBuild(String),
    TargetMismatch,
    RequestMismatch,
    ResourceLimit { resource: &'static str, limit: u64 },
    InternalInvariant(String),
}

impl fmt::Display for AnalysisFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("semantic analysis was cancelled"),
            Self::InvalidLimits => formatter.write_str("semantic analysis limits must be nonzero"),
            Self::InvalidBuild(message) => {
                write!(formatter, "invalid build configuration: {message}")
            }
            Self::TargetMismatch => {
                formatter.write_str("semantic target does not match the build identity")
            }
            Self::RequestMismatch => {
                formatter.write_str("semantic request and produced facts disagree")
            }
            Self::ResourceLimit { resource, limit } => write!(
                formatter,
                "semantic analysis exceeded {resource} limit {limit}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "semantic analysis invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for AnalysisFailure {}

#[cfg(test)]
mod contract_tests {
    use super::{AnalysisFailure, AnalysisLimits};

    #[test]
    fn semantic_policy_rejects_zero_capacity() {
        AnalysisLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = AnalysisLimits::standard();
        limits.types = 0;
        assert!(matches!(
            limits.validate(),
            Err(AnalysisFailure::InvalidLimits)
        ));
    }
}
