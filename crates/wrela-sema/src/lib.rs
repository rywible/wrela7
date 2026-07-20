//! Mutually dependent whole-image semantic analyses over normalized HIR.
//!
//! Types, effects, ownership, views, regions, comptime, image construction,
//! actors, async state, capacities, scheduling, hardware, and proof production
//! converge here. The public output is a consumer-complete semantic database;
//! the internal query engine and caches never cross the crate boundary.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use wrela_build_model::{BuildIdentity, Sha256Digest, ValidatedBuildConfiguration};
use wrela_diagnostics::{Diagnostic, WithDiagnostics};
use wrela_hir::{
    BodyId, DeclarationId, DeclarationKind, Definition, ExpressionId, FunctionColor, StatementId,
    TypeExpression, TypeExpressionKind, ValidatedProgram,
};
use wrela_package::PackageId;
use wrela_source::Span;
use wrela_target::TargetSemanticContract;
use wrela_test_model::{
    DeclaredImageTest, FullImageTestGroup, FunctionKey, ImageGroupId, ImageRoot as TestImageRoot,
    MAX_RUNTIME_TEST_EVENTS, TestCaseResult, ValidatedTestPlan,
};

mod analyzer;
mod comptime_check;
mod interfaces;

pub use analyzer::CanonicalSemanticAnalyzer;

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

/// Source-test subset chosen by the public driver before dense plan IDs are
/// assigned. Declared image tests are filtered independently by the driver and
/// supplied through `declared_image_tests`, so scenario files never need their
/// digest-bound TestIds rewritten after discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestDiscoverySelection<'a> {
    All,
    Comptime,
    Integration,
    None,
    NameContains(&'a str),
}

/// Selects both the semantic fixed point and the exact root that must be
/// closed. Invalid combinations such as "build with a test plan" are not
/// represented by a bag of unrelated request fields.
#[derive(Debug, Clone, Copy)]
pub enum AnalysisMode<'a> {
    Image {
        name: &'a str,
        entry: DeclarationId,
    },
    DiscoverTests {
        image_name: &'a str,
        image_entry: DeclarationId,
        declared_image_tests: &'a [DeclaredImageTest],
        source_selection: TestDiscoverySelection<'a>,
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
    /// Total comparisons across runtime type interning and aggregate field lookup.
    pub runtime_aggregate_lookup_work: u64,
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
            runtime_aggregate_lookup_work: 1_000_000_000,
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
            test_events_per_group: MAX_RUNTIME_TEST_EVENTS,
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
            || self.runtime_aggregate_lookup_work == 0
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

/// Complete declaration invalidation derived from one sealed prior semantic
/// product. Persistent consumers use this instead of accepting a caller's
/// potentially underreported declaration list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAnalysisChangeSet {
    changes: AnalysisChangeSet,
    comparisons: u64,
}

impl DerivedAnalysisChangeSet {
    #[must_use]
    pub fn changes(&self) -> &AnalysisChangeSet {
        &self.changes
    }

    #[must_use]
    pub const fn comparisons(&self) -> u64 {
        self.comparisons
    }

    #[must_use]
    pub fn into_parts(self) -> (AnalysisChangeSet, u64) {
        (self.changes, self.comparisons)
    }
}

/// Version of the sealed semantic-analysis reuse contract.
pub const ANALYSIS_CHANGE_SET_REUSE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisReuseLimits {
    pub comparisons: u64,
}

impl AnalysisReuseLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            comparisons: 256_000_000,
        }
    }

    fn validate(self) -> Result<(), AnalysisFailure> {
        if self.comparisons == 0 {
            Err(AnalysisFailure::InvalidReuseLimits)
        } else {
            Ok(())
        }
    }
}

/// A prior semantic product must be a sealed output, not a caller-asserted
/// source digest or an analyzer-private cache entry.
#[derive(Debug, Clone, Copy)]
pub struct PreviousAnalysisProduct<'a> {
    pub contract_version: u32,
    pub output: &'a AnalysisOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisReuseReport {
    pub reused_declarations: Vec<DeclarationId>,
    pub reused_functions: Vec<FunctionInstanceId>,
    pub recomputed_declarations: Vec<DeclarationId>,
    /// Semantic function producers actually executed for this invocation.
    pub producer_functions_executed: u64,
    pub comparisons: u64,
}

impl AnalysisReuseReport {
    #[must_use]
    pub const fn cold(producer_functions_executed: u64) -> Self {
        Self {
            reused_declarations: Vec::new(),
            reused_functions: Vec::new(),
            recomputed_declarations: Vec::new(),
            producer_functions_executed,
            comparisons: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisRequest<'a> {
    /// Exact shared HIR instance retained by a successful [`AnalyzedImage`].
    /// Ownership is explicit so semantic lowering never needs to clone or
    /// reconstruct the image-sized executable body graph.
    pub hir: Arc<ValidatedProgram>,
    /// Exact package selected by the root package's reserved `core`
    /// dependency. `BuildIdentity::standard_library` is the digest of the
    /// complete installed toolchain component, not a package content digest.
    pub standard_library_package: PackageId,
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
        /// Distinguishes fixed-width `uN`/`iN` from target-width
        /// `usize`/`isize`, even when both have the same selected width.
        pointer_sized: bool,
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
    /// Compiler-created strict-linear permit for one statically proved actor
    /// mailbox admission. Source code cannot name or store this type.
    Reservation,
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
    /// Exact HIR parameter bound by this specialized instance.
    pub parameter: wrela_hir::ParameterId,
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
    /// Source closure expression whose typed body is monomorphized as a
    /// function instance. The exact expression retains capture and body
    /// provenance without forging a declaration ID.
    SourceClosure { expression: ExpressionId },
    /// Runtime entry synthesized from a successfully evaluated source
    /// `@image fn`. The constructor itself never becomes runtime code;
    /// retaining its declaration ID preserves exact provenance.
    GeneratedImageEntry { constructor: DeclarationId },
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
    pub color: FunctionColor,
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
    /// Exact source construct which introduces this runtime value.
    pub origin: SemanticValueOrigin,
    pub source: Option<Span>,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticValueOrigin {
    Parameter(wrela_hir::ParameterId),
    Local(wrela_hir::LocalId),
    Expression(ExpressionId),
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
    ResultTry {
        result_type: SemanticTypeId,
        ok_variant: u32,
        err_variant: u32,
        ok_payload: ValueId,
        err_payload: ValueId,
        propagated: ValueId,
    },
    DirectCall {
        function: FunctionInstanceId,
        /// Exact source-to-parameter permutation. Records are canonical by
        /// `parameter_index`; `source_index` indexes the HIR call arguments.
        arguments: Vec<ResolvedCallArgument>,
    },
    /// A binary/comparison operator desugared to a direct call on a
    /// `core.ops` interface impl method (chapter 10 §12). `source_index` 0
    /// names the expression's `left` operand and 1 its `right` operand,
    /// evaluated in that order regardless of `parameter_index` mapping.
    /// `raw_result` is the value the call itself writes; when `negate` is
    /// false (every operator but `<=`/`>=`) it is exactly the expression's
    /// own recorded result, and the call writes that value directly. `<=`
    /// and `>=` call `Ord::less_than` with swapped operands and negate: the
    /// call instead writes a distinct intermediate `raw_result`, and the
    /// expression's own result is a further logical NOT of it.
    OperatorCall {
        function: FunctionInstanceId,
        arguments: Vec<ResolvedCallArgument>,
        raw_result: ValueId,
        negate: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedCallArgument {
    pub source_index: u32,
    pub parameter_index: u32,
    pub access: AccessMode,
    /// Exact semantic value supplied by this source argument. Exclusive-place
    /// arguments do not manufacture an expression fact, so the binding owns
    /// this producer-to-consumer identity directly.
    pub value: ValueId,
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
    /// Scalar expressions and direct calls do not require an allocation
    /// region. Place/view and region intrinsics retain the exact region.
    pub region: Option<RegionId>,
    pub effects: EffectSet,
    pub resolution: ExpressionResolution,
    /// Exact runtime value defined by this expression, when it defines one.
    /// References and callee-name expressions use `None`.
    pub result: Option<ValueId>,
    pub ownership_before: OwnershipState,
    pub ownership_after: OwnershipState,
    pub proofs: Vec<ProofId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementFact {
    pub function: FunctionInstanceId,
    pub statement: StatementId,
    pub effects: EffectSet,
    /// Exact source-local definitions introduced by this statement.
    pub definitions: Vec<LocalDefinition>,
    pub initialized_after: Vec<ValueId>,
    pub moved_after: Vec<ValueId>,
    pub live_loans_after: Vec<Loan>,
    pub proofs: Vec<ProofId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDefinition {
    pub local: wrela_hir::LocalId,
    pub value: ValueId,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub parameters: u32,
    pub locals: u32,
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
            parameters: program.parameters.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR parameters",
                    limit: u64::from(u32::MAX),
                }
            })?,
            locals: program.locals.len().try_into().map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "HIR locals",
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
    /// Exact source image constructor, or compiler-generated test root, that
    /// produced the closed image graph. A declared image's graph entry is a
    /// distinct compiler-generated runtime function and never the comptime
    /// constructor itself.
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
    /// Exact plan group bound by `CompileTestGroup`. Discovery retains the
    /// complete plan instead; ordinary images retain neither. This prevents
    /// downstream lowering from reconstructing global test IDs or timeouts
    /// from display names and analyzer-private constants.
    pub compiled_test_group: Option<FullImageTestGroup>,
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
                || !valid_value_origin(value.origin, self.hir)
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

        let mut function_keys = std::collections::HashSet::new();
        function_keys
            .try_reserve(self.functions.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "semantic validation function keys",
                limit: self.functions.len() as u64,
            })?;
        for function in &self.functions {
            let valid_origin = match function.origin {
                FunctionOrigin::Source { declaration, body } => {
                    declaration.0 < self.hir.declarations
                        && body.0 < self.hir.bodies
                        && function.role != FunctionRole::ImageEntry
                        && function.source.is_some()
                }
                FunctionOrigin::SourceClosure { expression } => {
                    expression.0 < self.hir.expressions
                        && function.role == FunctionRole::Ordinary
                        && function.source.is_some()
                }
                FunctionOrigin::GeneratedImageEntry { constructor } => {
                    constructor.0 < self.hir.declarations
                        && function.role == FunctionRole::ImageEntry
                        && function.color == FunctionColor::Sync
                        && function.generic_arguments.is_empty()
                        && function.parameters.is_empty()
                        && function.source.is_none()
                }
                FunctionOrigin::GeneratedTestHarness { .. } => {
                    function.role == FunctionRole::ImageEntry
                        && function.color == FunctionColor::Sync
                        && function.generic_arguments.is_empty()
                        && function.parameters.is_empty()
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
                || !valid_function_color_role(function)
                || function.result.0 as usize >= self.types.len()
                || !function.effects.is_valid()
                || function
                    .generic_arguments
                    .iter()
                    .any(|argument| !valid_semantic_argument(argument, self, graph))
                || !valid_proof_set(&function.proofs, self.proofs.len())
                || function.parameters.iter().any(|parameter| {
                    parameter.parameter.0 >= self.hir.parameters
                        || parameter.ty.0 as usize >= self.types.len()
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
                || fact
                    .region
                    .is_some_and(|region| region.0 as usize >= graph.regions.len())
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
        if self
            .compiled_test_group
            .as_ref()
            .is_some_and(|group| !compiled_test_group_matches_facts(self, group))
            || (self.test_plan.is_some() && self.compiled_test_group.is_some())
        {
            return Err(invalid(
                "partial compiled test-group metadata does not match semantic facts",
            ));
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
    pub fn validate_for_seal(
        &self,
        hir: &ValidatedProgram,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisFailure> {
        let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
        if self.hir != HirSummary::from_validated(hir)? {
            return Err(invalid(
                "semantic HIR summary differs from the retained validated HIR",
            ));
        }
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
                || !valid_value_origin(value.origin, self.hir)
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
        let mut function_keys = std::collections::HashSet::new();
        function_keys
            .try_reserve(self.functions.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "semantic validation function keys",
                limit: self.functions.len() as u64,
            })?;
        for function in &self.functions {
            let valid_origin = match function.origin {
                FunctionOrigin::Source { declaration, body } => {
                    declaration.0 < self.hir.declarations
                        && body.0 < self.hir.bodies
                        && function.role != FunctionRole::ImageEntry
                        && function.source.is_some()
                }
                FunctionOrigin::SourceClosure { expression } => {
                    expression.0 < self.hir.expressions
                        && function.role == FunctionRole::Ordinary
                        && function.source.is_some()
                }
                FunctionOrigin::GeneratedImageEntry { constructor } => {
                    constructor.0 < self.hir.declarations
                        && function.role == FunctionRole::ImageEntry
                        && function.color == FunctionColor::Sync
                        && function.generic_arguments.is_empty()
                        && function.parameters.is_empty()
                        && function.source.is_none()
                }
                FunctionOrigin::GeneratedTestHarness { .. } => {
                    function.role == FunctionRole::ImageEntry
                        && function.color == FunctionColor::Sync
                        && function.generic_arguments.is_empty()
                        && function.parameters.is_empty()
                        && function.source.is_none()
                }
            };
            if !function.key.is_valid()
                || !function_keys.insert(function.key)
                || function.name.trim().is_empty()
                || !valid_origin
                || !valid_function_color_role(function)
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
                    parameter.parameter.0 >= self.hir.parameters
                        || parameter.ty.0 as usize >= self.types.len()
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
        if self
            .compiled_test_group
            .as_ref()
            .is_some_and(|group| !compiled_test_group_matches_facts(self, group))
            || (self.test_plan.is_some() && self.compiled_test_group.is_some())
        {
            return Err(invalid(
                "compiled test-group metadata does not match semantic facts",
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
            let mut semantic_test_keys = std::collections::HashMap::new();
            semantic_test_keys
                .try_reserve(self.functions.len())
                .map_err(|_| AnalysisFailure::ResourceLimit {
                    resource: "semantic validation test keys",
                    limit: self.functions.len() as u64,
                })?;
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
        validate_exact_source_facts(self, hir, is_cancelled)
    }
}

fn validate_exact_source_facts(
    analysis: &PartialAnalysis,
    hir: &ValidatedProgram,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let program = hir.as_program();
    let mut definitions = Vec::new();
    definitions
        .try_reserve_exact(analysis.values.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic value-definition validation",
            limit: analysis.values.len() as u64,
        })?;
    definitions.resize(analysis.values.len(), 0u8);
    let mut exactly_taken = Vec::new();
    exactly_taken
        .try_reserve_exact(analysis.values.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic ownership-transition validation",
            limit: analysis.values.len() as u64,
        })?;
    exactly_taken.resize(analysis.values.len(), false);

    for function in &analysis.functions {
        check_analysis_cancelled(is_cancelled)?;
        let FunctionOrigin::Source { declaration, body } = function.origin else {
            if analysis
                .expressions
                .iter()
                .any(|fact| fact.function == function.id)
                || analysis
                    .statements
                    .iter()
                    .any(|fact| fact.function == function.id)
                || analysis
                    .values
                    .iter()
                    .any(|value| value.function == function.id)
            {
                return Err(invalid("generated function owns source body facts"));
            }
            continue;
        };
        let declaration_record = program
            .declaration(declaration)
            .ok_or_else(|| invalid("source function declaration is missing"))?;
        let wrela_hir::DeclarationKind::Function(source_function) = &declaration_record.kind else {
            return Err(invalid("source function origin is not a HIR function"));
        };
        if source_function.body != Some(body)
            || source_function.color != function.color
            || function.source != Some(declaration_record.source)
        {
            return Err(invalid("source function provenance differs from HIR"));
        }
        // There is no comptime function color: a comptime-tier test is
        // evaluated directly from HIR by the comptime evaluator and never
        // populates a runtime body, so it is the only `FunctionOrigin::Source`
        // instance that can legitimately have zero runtime facts. Every
        // populated body appends at least one statement fact (even a lone
        // `pass`), so "no facts at all" reliably identifies this case without
        // relying on a declared color.
        let has_runtime_facts = analysis
            .expressions
            .iter()
            .any(|fact| fact.function == function.id)
            || analysis
                .statements
                .iter()
                .any(|fact| fact.function == function.id)
            || analysis
                .values
                .iter()
                .any(|value| value.function == function.id);
        if !has_runtime_facts {
            if function.role != FunctionRole::Test || !function.parameters.is_empty() {
                return Err(invalid(
                    "source function is missing its expected runtime body facts",
                ));
            }
            continue;
        }

        validate_exact_parameters(
            analysis,
            program,
            function,
            declaration,
            source_function,
            &mut definitions,
        )?;
        let closure = collect_source_body_closure(program, body, is_cancelled)?;
        let actual_statements = analysis
            .statements
            .iter()
            .filter(|fact| fact.function == function.id)
            .map(|fact| fact.statement);
        if !actual_statements.eq(closure.statements.iter().copied()) {
            return Err(invalid(
                "source statement facts are not the exact HIR body closure",
            ));
        }
        let actual_expressions = analysis
            .expressions
            .iter()
            .filter(|fact| fact.function == function.id)
            .map(|fact| fact.expression);
        if !actual_expressions.eq(closure.expressions.iter().copied()) {
            return Err(invalid(
                "source expression facts are not the exact HIR body closure",
            ));
        }

        for fact in analysis
            .expressions
            .iter()
            .filter(|fact| fact.function == function.id)
        {
            check_analysis_cancelled(is_cancelled)?;
            validate_exact_expression_fact(
                analysis,
                program,
                function,
                fact,
                &mut definitions,
                is_cancelled,
            )?;
            if fact.ownership_after == OwnershipState::Taken {
                let value = match (&fact.resolution, fact.result) {
                    (ExpressionResolution::Value(value), _) => *value,
                    (ExpressionResolution::ActorRequest { .. }, Some(reservation)) => reservation,
                    _ => {
                        return Err(invalid(
                            "taken expression does not resolve to one source value or reservation",
                        ));
                    }
                };
                *exactly_taken
                    .get_mut(value.0 as usize)
                    .ok_or_else(|| invalid("taken expression value is invalid"))? = true;
            }
            if let ExpressionResolution::DirectCall { arguments, .. } = &fact.resolution {
                for argument in arguments {
                    check_analysis_cancelled(is_cancelled)?;
                    if argument.access == AccessMode::Take {
                        *exactly_taken
                            .get_mut(argument.value.0 as usize)
                            .ok_or_else(|| invalid("taken call argument value is invalid"))? = true;
                    }
                }
            }
        }
        for fact in analysis
            .statements
            .iter()
            .filter(|fact| fact.function == function.id)
        {
            check_analysis_cancelled(is_cancelled)?;
            validate_exact_statement_fact(
                analysis,
                program,
                function,
                fact,
                ExactStatementValidation {
                    bodies: &closure.bodies,
                    exactly_taken: &exactly_taken,
                    definitions: &mut definitions,
                },
                is_cancelled,
            )?;
        }
        validate_exact_local_value_flow(analysis, program, function, body, is_cancelled)?;
    }

    for value in &analysis.values {
        check_analysis_cancelled(is_cancelled)?;
        if definitions.get(value.id.0 as usize).copied() != Some(1) {
            return Err(invalid(
                "semantic runtime value does not have exactly one definition",
            ));
        }
        match value.origin {
            SemanticValueOrigin::Local(local) => {
                let mut bindings = analysis
                    .statements
                    .iter()
                    .filter(|fact| fact.function == value.function)
                    .flat_map(|fact| &fact.definitions)
                    .filter(|definition| definition.local == local && definition.value == value.id);
                if bindings.next().is_none() || bindings.next().is_some() {
                    return Err(invalid(
                        "local semantic value lacks one exact statement binding",
                    ));
                }
            }
            SemanticValueOrigin::Parameter(_) | SemanticValueOrigin::Expression(_) => {}
        }
    }
    Ok(())
}

fn exact_statement_fact(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    statement: StatementId,
) -> Option<&StatementFact> {
    analysis
        .statements
        .binary_search_by_key(&(function, statement), |fact| {
            (fact.function, fact.statement)
        })
        .ok()
        .and_then(|index| analysis.statements.get(index))
}

fn copy_exact_local_values(
    source: &[Option<ValueId>],
) -> Result<Vec<Option<ValueId>>, AnalysisFailure> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(source.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic local-value flow validation",
            limit: source.len() as u64,
        })?;
    copied.extend_from_slice(source);
    Ok(copied)
}

fn validate_exact_expression_local_values(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    expression: ExpressionId,
    locals: &[Option<ValueId>],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let mut pending = Vec::new();
    reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
    pending.push(expression);
    while let Some(expression) = pending.pop() {
        check_analysis_cancelled(is_cancelled)?;
        let source = program
            .expression(expression)
            .ok_or_else(|| invalid("local-value flow expression is missing"))?;
        let fact = exact_child_expression(analysis, function, expression)
            .ok_or_else(|| invalid("local-value flow expression fact is missing"))?;
        match &source.kind {
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(local)) => {
                let current = locals
                    .get(local.0 as usize)
                    .copied()
                    .flatten()
                    .ok_or_else(|| invalid("local reference has no reaching definition"))?;
                if fact.resolution != ExpressionResolution::Value(current) {
                    return Err(invalid(
                        "local reference does not resolve to its exact reaching definition",
                    ));
                }
            }
            wrela_hir::ExpressionKind::Call { callee, arguments } => {
                reserve_validation_scratch(
                    &mut pending,
                    arguments
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| invalid("expression child count overflow"))?,
                    program.expressions.len() as u64,
                )?;
                pending.push(*callee);
                for (source_index, argument) in arguments.iter().enumerate() {
                    match &argument.value {
                        wrela_hir::CallArgumentValue::Value(value) => pending.push(*value),
                        wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                            let expected = match place.root {
                                wrela_hir::Definition::Local(local) => locals
                                    .get(local.0 as usize)
                                    .copied()
                                    .flatten()
                                    .ok_or_else(|| {
                                        invalid("exclusive local place has no reaching definition")
                                    })?,
                                wrela_hir::Definition::Parameter(parameter) => analysis
                                    .functions
                                    .get(function.0 as usize)
                                    .and_then(|function| {
                                        function
                                            .parameters
                                            .iter()
                                            .find(|binding| binding.parameter == parameter)
                                    })
                                    .map(|binding| binding.value)
                                    .ok_or_else(|| {
                                        invalid("exclusive parameter place has no exact binding")
                                    })?,
                                _ => {
                                    return Err(invalid(
                                        "exclusive call place root is not a local or parameter",
                                    ));
                                }
                            };
                            let resolved = match &fact.resolution {
                                ExpressionResolution::DirectCall { arguments, .. } => arguments
                                    .iter()
                                    .find(|binding| binding.source_index as usize == source_index)
                                    .map(|binding| binding.value),
                                _ => None,
                            };
                            if resolved != Some(expected) {
                                return Err(invalid(
                                    "exclusive call place does not resolve to its exact reaching value",
                                ));
                            }
                            pending.extend(place.projections.iter().filter_map(|projection| {
                                match projection {
                                    wrela_hir::PlaceProjection::Index(index) => Some(*index),
                                    _ => None,
                                }
                            }))
                        }
                    }
                }
            }
            wrela_hir::ExpressionKind::Unary { operand, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::Try(operand) => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::Binary { left, right, .. }
            | wrela_hir::ExpressionKind::Compare { left, right, .. } => {
                reserve_validation_scratch(&mut pending, 2, program.expressions.len() as u64)?;
                pending.push(*right);
                pending.push(*left);
            }
            wrela_hir::ExpressionKind::Cast { value, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*value);
            }
            wrela_hir::ExpressionKind::Field { base, .. } => {
                if exact_resolved_enum_constructor(program, expression, is_cancelled)?.is_none() {
                    reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                    pending.push(*base);
                }
            }
            wrela_hir::ExpressionKind::Literal(_) | wrela_hir::ExpressionKind::Reference(_) => {}
            _ => {
                return Err(invalid(
                    "local-value flow encountered an unsupported expression",
                ));
            }
        }
    }
    Ok(())
}

fn expression_references_local(
    program: &wrela_hir::Program,
    expression: ExpressionId,
    local: wrela_hir::LocalId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let mut pending = Vec::new();
    reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
    pending.push(expression);
    let mut visited = 0_usize;
    while let Some(expression) = pending.pop() {
        check_analysis_cancelled(is_cancelled)?;
        visited = visited
            .checked_add(1)
            .ok_or_else(|| invalid("compound-assignment expression traversal overflowed"))?;
        if visited > program.expressions.len() {
            return Err(invalid(
                "compound-assignment expression is cyclic or duplicated",
            ));
        }
        let source = program
            .expression(expression)
            .ok_or_else(|| invalid("compound-assignment expression is missing"))?;
        match &source.kind {
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(candidate))
                if *candidate == local =>
            {
                return Ok(true);
            }
            wrela_hir::ExpressionKind::Call { callee, arguments } => {
                reserve_validation_scratch(
                    &mut pending,
                    arguments
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| invalid("expression child count overflow"))?,
                    program.expressions.len() as u64,
                )?;
                pending.push(*callee);
                for argument in arguments {
                    match &argument.value {
                        wrela_hir::CallArgumentValue::Value(value) => pending.push(*value),
                        wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                            pending.extend(place.projections.iter().filter_map(|projection| {
                                match projection {
                                    wrela_hir::PlaceProjection::Index(index) => Some(*index),
                                    _ => None,
                                }
                            }))
                        }
                    }
                }
            }
            wrela_hir::ExpressionKind::Unary { operand, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::Try(operand) => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::Binary { left, right, .. }
            | wrela_hir::ExpressionKind::Compare { left, right, .. } => {
                reserve_validation_scratch(&mut pending, 2, program.expressions.len() as u64)?;
                pending.push(*right);
                pending.push(*left);
            }
            wrela_hir::ExpressionKind::Cast { value, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*value);
            }
            wrela_hir::ExpressionKind::Field { base, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*base);
            }
            wrela_hir::ExpressionKind::Literal(_) | wrela_hir::ExpressionKind::Reference(_) => {}
            _ => {
                return Err(invalid(
                    "compound-assignment traversal encountered an unsupported expression",
                ));
            }
        }
    }
    Ok(false)
}

fn validate_exact_body_local_value_flow(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    body: BodyId,
    locals: &mut [Option<ValueId>],
    depth: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EffectSet, AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    if depth > program.bodies.len() {
        return Err(invalid("source body nesting is cyclic or unbounded"));
    }
    let body = program
        .body(body)
        .ok_or_else(|| invalid("local-value flow body is missing"))?;
    let mut body_effects = EffectSet(0);
    for statement_id in &body.statements {
        check_analysis_cancelled(is_cancelled)?;
        let statement = program
            .statement(*statement_id)
            .filter(|statement| statement.body == body.id)
            .ok_or_else(|| invalid("local-value flow statement is missing"))?;
        let fact = exact_statement_fact(analysis, function.id, *statement_id)
            .ok_or_else(|| invalid("local-value flow statement fact is missing"))?;
        let expected_effects = match &statement.kind {
            wrela_hir::StatementKind::Pass => EffectSet(0),
            wrela_hir::StatementKind::Initialize { local, value } => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *value,
                    locals,
                    is_cancelled,
                )?;
                let [definition] = fact.definitions.as_slice() else {
                    return Err(invalid(
                        "initializer local-value flow definition is missing",
                    ));
                };
                let slot = locals
                    .get_mut(local.0 as usize)
                    .ok_or_else(|| invalid("initializer local-value flow target is invalid"))?;
                if slot.is_some() || definition.local != *local {
                    return Err(invalid("initializer local-value flow is not exact"));
                }
                *slot = Some(definition.value);
                exact_child_expression(analysis, function.id, *value)
                    .ok_or_else(|| invalid("initializer expression fact is missing"))?
                    .effects
            }
            wrela_hir::StatementKind::Assign {
                targets,
                operator,
                value,
            } => {
                let [target] = targets.as_slice() else {
                    return Err(invalid("assignment local-value flow target is invalid"));
                };
                let wrela_hir::Definition::Local(local) = target.root else {
                    return Err(invalid("assignment local-value flow target is not local"));
                };
                if !target.projections.is_empty() {
                    return Err(invalid(
                        "assignment local-value flow target contains a projection",
                    ));
                }
                if *operator != wrela_hir::AssignmentOperator::Assign
                    && expression_references_local(program, *value, local, is_cancelled)?
                {
                    return Err(invalid(
                        "compound-assignment right-hand side overlaps its destination",
                    ));
                }
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *value,
                    locals,
                    is_cancelled,
                )?;
                let [definition] = fact.definitions.as_slice() else {
                    return Err(invalid("assignment local-value flow definition is missing"));
                };
                let slot = locals
                    .get_mut(local.0 as usize)
                    .ok_or_else(|| invalid("assignment local-value flow target is invalid"))?;
                let previous = slot.ok_or_else(|| {
                    invalid("assignment local-value flow target is uninitialized")
                })?;
                if definition.local != local || definition.value == previous {
                    return Err(invalid("assignment local-value flow is not exact"));
                }
                *slot = Some(definition.value);
                exact_child_expression(analysis, function.id, *value)
                    .ok_or_else(|| invalid("assignment expression fact is missing"))?
                    .effects
            }
            wrela_hir::StatementKind::Expression(expression)
            | wrela_hir::StatementKind::Send(expression) => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *expression,
                    locals,
                    is_cancelled,
                )?;
                exact_child_expression(analysis, function.id, *expression)
                    .ok_or_else(|| invalid("expression statement fact is missing"))?
                    .effects
            }
            wrela_hir::StatementKind::Assert {
                condition,
                comptime: false,
                ..
            } => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *condition,
                    locals,
                    is_cancelled,
                )?;
                let effects = exact_child_expression(analysis, function.id, *condition)
                    .ok_or_else(|| invalid("assertion condition fact is missing"))?
                    .effects;
                EffectSet(effects.0 | EffectSet::MAY_FAIL)
            }
            wrela_hir::StatementKind::Return(expression) => {
                if let Some(expression) = expression {
                    validate_exact_expression_local_values(
                        analysis,
                        program,
                        function.id,
                        *expression,
                        locals,
                        is_cancelled,
                    )?;
                    exact_child_expression(analysis, function.id, *expression)
                        .ok_or_else(|| invalid("return expression fact is missing"))?
                        .effects
                } else {
                    EffectSet(0)
                }
            }
            wrela_hir::StatementKind::If {
                branches,
                else_body,
            } => {
                let [(condition, then_body)] = branches.as_slice() else {
                    return Err(invalid("local-value flow branch shape is not exact"));
                };
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *condition,
                    locals,
                    is_cancelled,
                )?;
                let condition_effects = exact_child_expression(analysis, function.id, *condition)
                    .ok_or_else(|| invalid("branch condition fact is missing"))?
                    .effects;
                let mut then_locals = copy_exact_local_values(locals)?;
                let then_effects = validate_exact_body_local_value_flow(
                    analysis,
                    program,
                    function,
                    *then_body,
                    &mut then_locals,
                    depth + 1,
                    is_cancelled,
                )?;
                let mut else_locals = copy_exact_local_values(locals)?;
                let else_effects = if let Some(else_body) = else_body {
                    validate_exact_body_local_value_flow(
                        analysis,
                        program,
                        function,
                        *else_body,
                        &mut else_locals,
                        depth + 1,
                        is_cancelled,
                    )?
                } else {
                    EffectSet(0)
                };
                let mut definition_index = 0usize;
                for index in 0..locals.len() {
                    check_analysis_cancelled(is_cancelled)?;
                    let Some(original) = locals[index] else {
                        continue;
                    };
                    let then_value = then_locals[index]
                        .ok_or_else(|| invalid("then branch loses a reaching local definition"))?;
                    let else_value = else_locals[index]
                        .ok_or_else(|| invalid("else branch loses a reaching local definition"))?;
                    if then_value == else_value {
                        if then_value != original {
                            return Err(invalid("unchanged branch local flow is inconsistent"));
                        }
                        locals[index] = Some(then_value);
                        continue;
                    }
                    let definition = fact
                        .definitions
                        .get(definition_index)
                        .ok_or_else(|| invalid("branch local-value join definition is missing"))?;
                    if definition.local.0 as usize != index {
                        return Err(invalid("branch local-value join order is not exact"));
                    }
                    locals[index] = Some(definition.value);
                    definition_index += 1;
                }
                if definition_index != fact.definitions.len() {
                    return Err(invalid("branch has a spurious local-value join definition"));
                }
                EffectSet(condition_effects.0 | then_effects.0 | else_effects.0)
            }
            wrela_hir::StatementKind::While { condition, body } => {
                if fact.definitions.len() % 2 != 0 {
                    return Err(invalid("loop carried definitions are not paired"));
                }
                let arity = fact.definitions.len() / 2;
                for definition in &fact.definitions[..arity] {
                    let slot = locals
                        .get_mut(definition.local.0 as usize)
                        .ok_or_else(|| invalid("loop carried local is invalid"))?;
                    if slot.is_none() {
                        return Err(invalid("loop carries an uninitialized local"));
                    }
                    *slot = Some(definition.value);
                }
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *condition,
                    locals,
                    is_cancelled,
                )?;
                let condition_effects = exact_child_expression(analysis, function.id, *condition)
                    .ok_or_else(|| invalid("while condition fact is missing"))?
                    .effects;
                let mut body_locals = copy_exact_local_values(locals)?;
                let body_effects = validate_exact_body_local_value_flow(
                    analysis,
                    program,
                    function,
                    *body,
                    &mut body_locals,
                    depth + 1,
                    is_cancelled,
                )?;
                for definition in &fact.definitions[arity..] {
                    locals[definition.local.0 as usize] = Some(definition.value);
                }
                EffectSet(condition_effects.0 | body_effects.0)
            }
            wrela_hir::StatementKind::Break | wrela_hir::StatementKind::Continue => EffectSet(0),
            wrela_hir::StatementKind::Match { scrutinee, arms } => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *scrutinee,
                    locals,
                    is_cancelled,
                )?;
                let mut effects = exact_child_expression(analysis, function.id, *scrutinee)
                    .ok_or_else(|| invalid("enum match scrutinee fact is missing"))?
                    .effects;
                if fact.definitions.len() != arms.len() {
                    return Err(invalid("enum match local-value bindings are incomplete"));
                }
                for (arm, definition) in arms.iter().zip(&fact.definitions) {
                    check_analysis_cancelled(is_cancelled)?;
                    let local = exact_match_payload_local(program, arm)
                        .ok_or_else(|| invalid("enum match payload binding differs from HIR"))?;
                    if definition.local != local {
                        return Err(invalid("enum match payload definition order is not exact"));
                    }
                    let mut arm_locals = copy_exact_local_values(locals)?;
                    let slot = arm_locals
                        .get_mut(local.0 as usize)
                        .ok_or_else(|| invalid("enum match payload local is invalid"))?;
                    if slot.replace(definition.value).is_some() {
                        return Err(invalid("enum match payload shadows reaching local state"));
                    }
                    let arm_effects = validate_exact_body_local_value_flow(
                        analysis,
                        program,
                        function,
                        arm.body,
                        &mut arm_locals,
                        depth + 1,
                        is_cancelled,
                    )?;
                    for (index, (before, after)) in locals.iter().zip(&arm_locals).enumerate() {
                        check_analysis_cancelled(is_cancelled)?;
                        if index != local.0 as usize && before != after {
                            return Err(invalid("enum match arm mutates outer local state"));
                        }
                    }
                    effects.0 |= arm_effects.0;
                }
                effects
            }
            _ => {
                return Err(invalid(
                    "local-value flow encountered an unsupported statement",
                ));
            }
        };
        if fact.effects != expected_effects {
            return Err(invalid(
                "statement effects differ from exact expression and branch effects",
            ));
        }
        body_effects.0 |= fact.effects.0;
    }
    Ok(body_effects)
}

fn validate_exact_local_value_flow(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    body: BodyId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let mut locals = Vec::new();
    locals
        .try_reserve_exact(program.locals.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic local-value flow validation",
            limit: program.locals.len() as u64,
        })?;
    locals.resize(program.locals.len(), None);
    validate_exact_body_local_value_flow(
        analysis,
        program,
        function,
        body,
        &mut locals,
        1,
        is_cancelled,
    )?;
    Ok(())
}

fn validate_exact_parameters(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    declaration: DeclarationId,
    source: &wrela_hir::FunctionDeclaration,
    definitions: &mut [u8],
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    if source.parameters.len() != function.parameters.len() {
        return Err(invalid("source function parameter count differs from HIR"));
    }
    for (parameter_id, semantic) in source.parameters.iter().zip(&function.parameters) {
        let parameter = program
            .parameters
            .get(parameter_id.0 as usize)
            .filter(|parameter| {
                parameter.id == *parameter_id
                    && parameter.owner == wrela_hir::CallableOwner::Declaration(declaration)
            })
            .ok_or_else(|| invalid("source function parameter provenance is invalid"))?;
        let value = analysis
            .values
            .get(semantic.value.0 as usize)
            .filter(|value| value.function == function.id && value.ty == semantic.ty)
            .ok_or_else(|| invalid("source parameter value is invalid"))?;
        let access_matches = matches!(
            (parameter.access, semantic.access),
            (wrela_hir::AccessMode::Value, AccessMode::Value)
                | (wrela_hir::AccessMode::Read, AccessMode::Read)
                | (wrela_hir::AccessMode::Mutate, AccessMode::Mutate)
                | (wrela_hir::AccessMode::Take, AccessMode::Take)
        );
        let expected_name = parameter
            .name
            .as_ref()
            .map_or("self", wrela_hir::Name::as_str);
        if semantic.parameter != *parameter_id
            || value.origin != SemanticValueOrigin::Parameter(*parameter_id)
            || value.source != Some(parameter.source)
            || value.source_name.as_deref() != Some(expected_name)
            || !access_matches
        {
            return Err(invalid("source parameter binding differs from HIR"));
        }
        increment_definition(definitions, semantic.value)?;
    }
    Ok(())
}

struct SourceBodyClosure {
    bodies: Vec<BodyId>,
    statements: Vec<StatementId>,
    expressions: Vec<ExpressionId>,
}

fn collect_source_body_closure(
    program: &wrela_hir::Program,
    root: BodyId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SourceBodyClosure, AnalysisFailure> {
    let invalid = || {
        AnalysisFailure::InternalInvariant(
            "unsupported or malformed source body closure".to_owned(),
        )
    };
    let mut pending_bodies = fallible_scratch(1, program.bodies.len() as u64)?;
    let mut bodies = fallible_scratch(1, program.bodies.len() as u64)?;
    let mut statements = fallible_scratch(0, program.statements.len() as u64)?;
    let mut pending_expressions = fallible_scratch(0, program.expressions.len() as u64)?;
    let mut expressions = fallible_scratch(0, program.expressions.len() as u64)?;
    pending_bodies.push(root);
    while let Some(body_id) = pending_bodies.pop() {
        check_analysis_cancelled(is_cancelled)?;
        let body = program.body(body_id).ok_or_else(invalid)?;
        reserve_validation_scratch(&mut bodies, 1, program.bodies.len() as u64)?;
        bodies.push(body_id);
        reserve_validation_scratch(
            &mut statements,
            body.statements.len(),
            program.statements.len() as u64,
        )?;
        for statement_id in &body.statements {
            let statement = program.statement(*statement_id).ok_or_else(invalid)?;
            if statement.body != body_id || !statement.attributes.is_empty() {
                return Err(invalid());
            }
            statements.push(*statement_id);
            match &statement.kind {
                wrela_hir::StatementKind::Pass => {}
                wrela_hir::StatementKind::Initialize { value, .. }
                | wrela_hir::StatementKind::Assign { value, .. }
                | wrela_hir::StatementKind::Assert {
                    condition: value, ..
                }
                | wrela_hir::StatementKind::Expression(value)
                | wrela_hir::StatementKind::Send(value) => {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*value);
                }
                wrela_hir::StatementKind::Return(value) => {
                    if let Some(value) = value {
                        reserve_validation_scratch(
                            &mut pending_expressions,
                            1,
                            program.expressions.len() as u64,
                        )?;
                        pending_expressions.push(*value);
                    }
                }
                wrela_hir::StatementKind::If {
                    branches,
                    else_body,
                } => {
                    let [(condition, then_body)] = branches.as_slice() else {
                        return Err(invalid());
                    };
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*condition);
                    reserve_validation_scratch(
                        &mut pending_bodies,
                        1 + usize::from(else_body.is_some()),
                        program.bodies.len() as u64,
                    )?;
                    pending_bodies.push(*then_body);
                    if let Some(otherwise) = else_body {
                        pending_bodies.push(*otherwise);
                    }
                }
                wrela_hir::StatementKind::While { condition, body } => {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*condition);
                    reserve_validation_scratch(
                        &mut pending_bodies,
                        1,
                        program.bodies.len() as u64,
                    )?;
                    pending_bodies.push(*body);
                }
                wrela_hir::StatementKind::Break | wrela_hir::StatementKind::Continue => {}
                wrela_hir::StatementKind::Match { scrutinee, arms } => {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*scrutinee);
                    reserve_validation_scratch(
                        &mut pending_bodies,
                        arms.len(),
                        program.bodies.len() as u64,
                    )?;
                    for arm in arms {
                        pending_bodies.push(arm.body);
                    }
                }
                _ => return Err(invalid()),
            }
        }
    }
    while let Some(expression_id) = pending_expressions.pop() {
        check_analysis_cancelled(is_cancelled)?;
        let expression = program.expression(expression_id).ok_or_else(invalid)?;
        reserve_validation_scratch(&mut expressions, 1, program.expressions.len() as u64)?;
        expressions.push(expression_id);
        match &expression.kind {
            wrela_hir::ExpressionKind::Literal(
                wrela_hir::Literal::Unit
                | wrela_hir::Literal::Boolean(_)
                | wrela_hir::Literal::Integer(_)
                | wrela_hir::Literal::Float(_),
            )
            | wrela_hir::ExpressionKind::Reference(
                wrela_hir::Definition::Local(_)
                | wrela_hir::Definition::Parameter(_)
                | wrela_hir::Definition::Declaration(_)
                | wrela_hir::Definition::Variant(_),
            ) => {}
            wrela_hir::ExpressionKind::Call { callee, arguments } => {
                let additional = arguments.len().checked_add(1).ok_or_else(invalid)?;
                reserve_validation_scratch(
                    &mut pending_expressions,
                    additional,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*callee);
                for argument in arguments {
                    match &argument.value {
                        wrela_hir::CallArgumentValue::Value(value) => {
                            pending_expressions.push(*value);
                        }
                        wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                            pending_expressions.extend(place.projections.iter().filter_map(
                                |projection| match projection {
                                    wrela_hir::PlaceProjection::Index(index) => Some(*index),
                                    _ => None,
                                },
                            ));
                        }
                    }
                }
            }
            wrela_hir::ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Await,
                operand,
            } => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    1,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*operand);
            }
            wrela_hir::ExpressionKind::Try(operand) => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    1,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*operand);
            }
            wrela_hir::ExpressionKind::Unary { operand, .. }
            | wrela_hir::ExpressionKind::Cast { value: operand, .. } => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    1,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*operand);
            }
            wrela_hir::ExpressionKind::Binary { left, right, .. }
            | wrela_hir::ExpressionKind::Compare { left, right, .. } => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    2,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*right);
                pending_expressions.push(*left);
            }
            wrela_hir::ExpressionKind::Field { base, .. } => {
                if exact_resolved_enum_constructor(program, expression_id, is_cancelled)?.is_none()
                {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*base);
                }
            }
            _ => return Err(invalid()),
        }
    }
    bodies.sort_unstable();
    statements.sort_unstable();
    expressions.sort_unstable();
    if bodies.windows(2).any(|pair| pair[0] == pair[1])
        || statements.windows(2).any(|pair| pair[0] == pair[1])
        || expressions.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(invalid());
    }
    Ok(SourceBodyClosure {
        bodies,
        statements,
        expressions,
    })
}

fn exact_match_payload_local(
    program: &wrela_hir::Program,
    arm: &wrela_hir::MatchArm,
) -> Option<wrela_hir::LocalId> {
    if arm.guard.is_some() {
        return None;
    }
    let pattern = program.patterns.get(arm.pattern.0 as usize)?;
    let [alternative] = pattern.alternatives.as_slice() else {
        return None;
    };
    let wrela_hir::PrimaryPattern::Constructor { arguments, .. } = &alternative.kind else {
        return None;
    };
    let [argument] = arguments.as_slice() else {
        return None;
    };
    if argument.take {
        return None;
    }
    let payload = program.patterns.get(argument.pattern.0 as usize)?;
    let [alternative] = payload.alternatives.as_slice() else {
        return None;
    };
    let wrela_hir::PrimaryPattern::Bind(local) = alternative.kind else {
        return None;
    };
    Some(local)
}

fn validate_exact_expression_fact(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    fact: &ExpressionFact,
    definitions: &mut [u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let expression = program
        .expression(fact.expression)
        .ok_or_else(|| invalid("expression fact HIR node is missing"))?;
    let ownership_matches = if matches!(fact.resolution, ExpressionResolution::ActorRequest { .. })
    {
        fact.ownership_before == OwnershipState::Owned
            && fact.ownership_after == OwnershipState::Taken
    } else {
        exact_expression_ownership_matches(program, fact, is_cancelled)?
    };
    if !ownership_matches {
        return Err(invalid(
            "expression ownership transition differs from exact HIR access",
        ));
    }
    if let Some(result) = fact.result {
        let value = analysis
            .values
            .get(result.0 as usize)
            .filter(|value| {
                value.function == function.id
                    && value.ty == fact.ty
                    && value.category == fact.category
            })
            .ok_or_else(|| invalid("expression result value is invalid"))?;
        match value.origin {
            SemanticValueOrigin::Expression(source) if source == fact.expression => {}
            SemanticValueOrigin::Local(_) => {}
            _ => return Err(invalid("expression result has the wrong source origin")),
        }
        increment_definition(definitions, result)?;
    }
    match (&expression.kind, &fact.resolution, fact.result) {
        (
            wrela_hir::ExpressionKind::Literal(literal),
            ExpressionResolution::Constant(constant),
            Some(_),
        ) if constant_matches_literal(analysis, fact.ty, literal, constant) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(local)),
            ExpressionResolution::Value(value),
            _,
        ) if analysis.values.get(value.0 as usize).is_some_and(|record| {
            record.function == function.id
                && record.ty == fact.ty
                && record.origin == SemanticValueOrigin::Local(*local)
        }) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(parameter)),
            ExpressionResolution::Value(value),
            _,
        ) if analysis.values.get(value.0 as usize).is_some_and(|record| {
            record.function == function.id
                && record.ty == fact.ty
                && record.origin == SemanticValueOrigin::Parameter(*parameter)
        }) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(source)),
            ExpressionResolution::Function(target),
            None,
        ) if analysis
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| {
                matches!(
                    target.origin,
                    FunctionOrigin::Source { declaration, .. } if declaration == source.declaration
                )
            }) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(source)),
            ExpressionResolution::Constructor { ty, variant: None },
            None,
        ) if *ty == fact.ty
            && analysis.types.get(ty.0 as usize).is_some_and(|record| {
                matches!(
                    &record.kind,
                    SemanticTypeKind::Structure {
                        declaration,
                        arguments,
                        ..
                    } if *declaration == source.declaration && arguments.is_empty()
                )
            }) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Variant(source)),
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            None,
        ) if *ty == fact.ty
            && exact_enum_constructor_reference_matches(
                analysis, program, source, *ty, *variant,
            ) => {}
        (
            wrela_hir::ExpressionKind::Field { .. },
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            None,
        ) if *ty == fact.ty
            && exact_resolved_enum_constructor(program, fact.expression, is_cancelled)?
                .is_some_and(|source| {
                    exact_enum_constructor_reference_matches(
                        analysis, program, &source, *ty, *variant,
                    )
                }) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::Constructor { ty, variant: None },
            Some(_),
        ) if *ty == fact.ty
            && exact_flat_constructor_matches(
                analysis,
                program,
                function.id,
                *callee,
                arguments,
                *ty,
                is_cancelled,
            )? => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            Some(_),
        ) if *ty == fact.ty
            && exact_enum_constructor_matches(
                analysis,
                program,
                function.id,
                fact,
                *callee,
                arguments,
                *ty,
                *variant,
                is_cancelled,
            )? => {}
        (
            wrela_hir::ExpressionKind::Field { base, name },
            ExpressionResolution::Field { index },
            Some(_),
        ) if exact_flat_field_matches(
            analysis,
            program,
            function.id,
            *base,
            name,
            *index,
            fact.ty,
            is_cancelled,
        )? => {}
        (
            wrela_hir::ExpressionKind::Field { base, name },
            ExpressionResolution::Function(target),
            None,
        ) if exact_actor_method_reference_matches(
            analysis,
            program,
            function.id,
            fact,
            *base,
            name,
            *target,
        ) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::DirectCall {
                function: target,
                arguments: bindings,
            },
            Some(_),
        ) if exact_call_bindings_match(
            analysis,
            program,
            function.id,
            *callee,
            arguments,
            *target,
            bindings,
        ) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::ActorRequest {
                actor,
                method,
                permit,
            },
            Some(_),
        ) if exact_actor_request_matches(
            analysis,
            program,
            function.id,
            fact,
            *callee,
            arguments,
            *actor,
            *method,
            *permit,
        ) => {}
        (
            wrela_hir::ExpressionKind::Unary { operator, operand },
            ExpressionResolution::Value(value),
            Some(result),
        ) if *value == result
            && exact_scalar_unary_matches(analysis, function.id, *operator, *operand, fact) => {}
        (
            wrela_hir::ExpressionKind::Binary {
                operator,
                left,
                right,
            },
            ExpressionResolution::Value(value),
            Some(result),
        ) if *value == result
            && exact_scalar_binary_matches(
                analysis,
                function.id,
                *operator,
                *left,
                *right,
                fact,
            ) => {}
        (
            wrela_hir::ExpressionKind::Compare {
                left,
                operator,
                right,
            },
            ExpressionResolution::Value(value),
            Some(result),
        ) if *value == result
            && exact_scalar_comparison_matches(
                analysis,
                function.id,
                *operator,
                *left,
                *right,
                fact,
            ) => {}
        (
            wrela_hir::ExpressionKind::Cast { value: source, ty },
            ExpressionResolution::Value(value),
            Some(result),
        ) if *value == result
            && exact_scalar_cast_matches(analysis, function.id, *source, ty, fact) => {}
        (
            wrela_hir::ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Await,
                operand,
            },
            ExpressionResolution::Builtin(IntrinsicOperation::Await),
            Some(_),
        ) if exact_await_operand_matches(analysis, function.id, *operand, fact.ty) => {}
        (
            wrela_hir::ExpressionKind::Try(operand),
            ExpressionResolution::ResultTry {
                result_type,
                ok_variant,
                err_variant,
                ok_payload,
                err_payload,
                propagated,
            },
            Some(_),
        ) => {
            if !exact_result_try_matches(
                analysis,
                program,
                function,
                *operand,
                fact,
                *result_type,
                *ok_variant,
                *err_variant,
                *ok_payload,
                *err_payload,
                *propagated,
            ) {
                return Err(invalid("postfix question semantic facts differ from HIR"));
            }
            increment_definition(definitions, *ok_payload)?;
            increment_definition(definitions, *err_payload)?;
            increment_definition(definitions, *propagated)?;
        }
        _ => {
            return Err(invalid(&format!(
                "expression semantic fact differs from exact HIR meaning: function {:?}, expression {:?}, HIR {:?}, resolution {:?}, result {:?}",
                function.id, fact.expression, expression.kind, fact.resolution, fact.result
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn exact_result_try_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    operand: ExpressionId,
    fact: &ExpressionFact,
    result_type: SemanticTypeId,
    ok_variant: u32,
    err_variant: u32,
    ok_payload: ValueId,
    err_payload: ValueId,
    propagated: ValueId,
) -> bool {
    let Some(operand_fact) = exact_child_expression(analysis, function.id, operand) else {
        return false;
    };
    if program.expression(operand).is_none_or(|operand| {
        matches!(
            operand.kind,
            wrela_hir::ExpressionKind::Reference(
                wrela_hir::Definition::Local(_) | wrela_hir::Definition::Parameter(_)
            ) | wrela_hir::ExpressionKind::Field { .. }
        )
    }) {
        return false;
    }
    let Some(result) = fact.result else {
        return false;
    };
    if operand_fact.ty != result_type
        || operand_fact.result.is_none()
        || matches!(operand_fact.resolution, ExpressionResolution::Value(_))
        || function.result != result_type
        || fact.effects != operand_fact.effects
        || [result, ok_payload, err_payload, propagated]
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || result == err_payload
        || result == propagated
        || ok_payload == propagated
    {
        return false;
    }
    let Some(SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    }) = analysis
        .types
        .get(result_type.0 as usize)
        .map(|record| &record.kind)
    else {
        return false;
    };
    let Some(payload_type) = variants
        .first()
        .and_then(|variant| variant.fields.first())
        .map(|field| field.ty)
    else {
        return false;
    };
    let internal_value = |value: ValueId, ty: SemanticTypeId| {
        analysis.values.get(value.0 as usize).is_some_and(|value| {
            value.function == function.id
                && value.ty == ty
                && value.category == ValueCategory::Value
                && value.origin == SemanticValueOrigin::Expression(fact.expression)
                && value.source_name.is_none()
        })
    };
    ok_variant == 0
        && err_variant == 1
        && exact_core_result_declaration_matches(program, *declaration)
        && runtime_enum_arguments_supported(arguments, variants)
        && fact.ty == payload_type
        && internal_value(ok_payload, payload_type)
        && internal_value(err_payload, payload_type)
        && internal_value(propagated, result_type)
}

fn exact_core_result_declaration_matches(
    program: &wrela_hir::Program,
    declaration: DeclarationId,
) -> bool {
    let Some(core_package) = program
        .packages
        .package(program.packages.root())
        .and_then(|root| {
            root.dependencies
                .iter()
                .find(|dependency| dependency.alias.as_str() == "core")
                .map(|dependency| dependency.package)
        })
    else {
        return false;
    };
    let Some(record) = program.declaration(declaration) else {
        return false;
    };
    if record.visibility != wrela_hir::Visibility::Public
        || record.name.as_ref().map(wrela_hir::Name::as_str) != Some("Result")
        || program
            .modules
            .get(record.module.0 as usize)
            .is_none_or(|module| module.package != core_package || module.path.dotted() != "result")
    {
        return false;
    }
    let wrela_hir::DeclarationKind::Enumeration(source) = &record.kind else {
        return false;
    };
    let [ok_generic, err_generic] = source.generics.as_slice() else {
        return false;
    };
    let generic_is_type = |generic| {
        program.generic_parameter(generic).is_some_and(|record| {
            matches!(record.kind, wrela_hir::GenericParameterKind::Type { .. })
        })
    };
    let [ok, err] = source.variants.as_slice() else {
        return false;
    };
    let exact_variant =
        |variant: &wrela_hir::EnumVariant, name: &str, generic: wrela_hir::GenericParameterId| {
            variant.name.as_str() == name
                && matches!(variant.fields.as_slice(), [field]
                    if field.name.is_none()
                        && matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                            definition: wrela_hir::Definition::Generic(candidate),
                            arguments,
                        } if *candidate == generic && arguments.is_empty()))
        };
    generic_is_type(*ok_generic)
        && generic_is_type(*err_generic)
        && exact_variant(ok, "Ok", *ok_generic)
        && exact_variant(err, "Err", *err_generic)
}

fn exact_enum_constructor_reference_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    source: &wrela_hir::ResolvedVariant,
    ty: SemanticTypeId,
    variant: u32,
) -> bool {
    if source.variant != variant {
        return false;
    }
    let Some(record) = program.declaration(source.enumeration.declaration) else {
        return false;
    };
    if record.id != source.enumeration.declaration
        || record.module != source.enumeration.module
        || program
            .modules
            .get(source.enumeration.module.0 as usize)
            .is_none_or(|module| module.package != source.enumeration.package)
    {
        return false;
    }
    analysis.types.get(ty.0 as usize).is_some_and(|record| {
        matches!(
            &record.kind,
            SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                variants,
            } if *declaration == source.enumeration.declaration
                && runtime_enum_arguments_supported(arguments, variants)
                && (variant as usize) < variants.len()
        )
    })
}

fn runtime_enum_arguments_supported(
    arguments: &[SemanticArgument],
    variants: &[SemanticVariant],
) -> bool {
    if arguments.is_empty() {
        return true;
    }
    matches!(arguments, [SemanticArgument::Type(ok), SemanticArgument::Type(err)] if ok == err)
        && matches!(variants, [ok, err]
            if ok.name == "Ok"
                && err.name == "Err"
                && matches!((ok.fields.as_slice(), err.fields.as_slice()), ([ok_field], [err_field])
                    if ok_field.name.is_empty()
                        && err_field.name.is_empty()
                        && ok_field.public
                        && err_field.public
                        && ok_field.ty == err_field.ty
                        && matches!(arguments, [SemanticArgument::Type(payload), _]
                            if *payload == ok_field.ty)))
}

#[allow(clippy::too_many_arguments)]
fn exact_enum_constructor_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    fact: &ExpressionFact,
    callee: ExpressionId,
    arguments: &[wrela_hir::CallArgument],
    ty: SemanticTypeId,
    variant: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let Some(SemanticTypeKind::Enumeration {
        arguments: type_arguments,
        variants,
        ..
    }) = analysis.types.get(ty.0 as usize).map(|record| &record.kind)
    else {
        return Ok(false);
    };
    let Some(payload_ty) = variants
        .get(variant as usize)
        .and_then(|variant| variant.fields.first())
        .map(|field| field.ty)
    else {
        return Ok(false);
    };
    if !runtime_enum_arguments_supported(type_arguments, variants) {
        return Ok(false);
    }
    let [argument] = arguments else {
        return Ok(false);
    };
    let wrela_hir::CallArgumentValue::Value(payload) = argument.value else {
        return Ok(false);
    };
    if argument.name.is_some() {
        return Ok(false);
    }
    let Some(source) = exact_resolved_enum_constructor(program, callee, is_cancelled)? else {
        return Ok(false);
    };
    if !exact_enum_constructor_reference_matches(analysis, program, &source, ty, variant) {
        return Ok(false);
    }
    let callee_matches = exact_child_expression(analysis, function, callee).is_some_and(|fact| {
        fact.ty == ty
            && fact.result.is_none()
            && fact.effects == EffectSet(0)
            && fact.resolution
                == (ExpressionResolution::Constructor {
                    ty,
                    variant: Some(variant),
                })
    });
    let payload_matches =
        exact_child_expression(analysis, function, payload).is_some_and(|value| {
            value.ty == payload_ty
                && exact_expression_produces_value(value)
                && value.effects == fact.effects
        });
    Ok(callee_matches && payload_matches)
}

fn exact_flat_constructor_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    callee: ExpressionId,
    arguments: &[wrela_hir::CallArgument],
    ty: SemanticTypeId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let Some(SemanticTypeKind::Structure {
        declaration,
        arguments: type_arguments,
        fields,
    }) = analysis.types.get(ty.0 as usize).map(|record| &record.kind)
    else {
        return Ok(false);
    };
    if !type_arguments.is_empty() || arguments.len() != fields.len() {
        return Ok(false);
    }
    let callee_matches = program.expression(callee).is_some_and(|expression| {
        matches!(
            &expression.kind,
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(source))
                if source.declaration == *declaration
        )
    }) && analysis
        .expressions
        .binary_search_by_key(&(function, callee), |fact| (fact.function, fact.expression))
        .ok()
        .and_then(|index| analysis.expressions.get(index))
        .is_some_and(|fact| {
            fact.ty == ty
                && fact.result.is_none()
                && fact.resolution == (ExpressionResolution::Constructor { ty, variant: None })
        });
    if !callee_matches {
        return Ok(false);
    }
    let mut initialized = Vec::new();
    initialized
        .try_reserve_exact(fields.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "flat constructor validation fields",
            limit: fields.len() as u64,
        })?;
    initialized.resize(fields.len(), false);
    for (source_index, argument) in arguments.iter().enumerate() {
        check_analysis_cancelled(is_cancelled)?;
        let wrela_hir::CallArgumentValue::Value(argument_value) = &argument.value else {
            return Ok(false);
        };
        let field_index = if let Some(name) = &argument.name {
            let mut selected = None;
            for (index, field) in fields.iter().enumerate() {
                check_analysis_cancelled(is_cancelled)?;
                if field.name == name.as_str() && selected.replace(index).is_some() {
                    return Ok(false);
                }
            }
            let Some(selected) = selected else {
                return Ok(false);
            };
            selected
        } else {
            source_index
        };
        let Some(field) = fields.get(field_index) else {
            return Ok(false);
        };
        let Some(slot) = initialized.get_mut(field_index) else {
            return Ok(false);
        };
        if std::mem::replace(slot, true) {
            return Ok(false);
        }
        let argument_matches = analysis
            .expressions
            .binary_search_by_key(&(function, *argument_value), |fact| {
                (fact.function, fact.expression)
            })
            .ok()
            .and_then(|index| analysis.expressions.get(index))
            .is_some_and(|fact| fact.ty == field.ty);
        if !argument_matches {
            return Ok(false);
        }
    }
    for initialized in initialized {
        check_analysis_cancelled(is_cancelled)?;
        if !initialized {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn exact_flat_field_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    base: ExpressionId,
    name: &wrela_hir::Name,
    index: u32,
    result: SemanticTypeId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    check_analysis_cancelled(is_cancelled)?;
    let Some(base_fact) = analysis
        .expressions
        .binary_search_by_key(&(function, base), |fact| (fact.function, fact.expression))
        .ok()
        .and_then(|position| analysis.expressions.get(position))
    else {
        return Ok(false);
    };
    let Some(base_type) = analysis.types.get(base_fact.ty.0 as usize) else {
        return Ok(false);
    };
    match &base_type.kind {
        SemanticTypeKind::Structure {
            arguments, fields, ..
        } => {
            if !arguments.is_empty() {
                return Ok(false);
            }
            let Some(field) = fields.get(index as usize) else {
                return Ok(false);
            };
            check_analysis_cancelled(is_cancelled)?;
            Ok(field.name == name.as_str() && field.ty == result)
        }
        SemanticTypeKind::Class {
            declaration,
            arguments,
            fields,
        } if arguments.is_empty() && fields.is_empty() && index == 0 => {
            let Some(wrela_hir::Declaration {
                kind: wrela_hir::DeclarationKind::Structure(class),
                ..
            }) = program.declaration(*declaration)
            else {
                return Ok(false);
            };
            let [field] = class.fields.as_slice() else {
                return Ok(false);
            };
            let wrela_hir::TypeExpressionKind::Named {
                definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::Actor),
                arguments,
            } = &field.ty.kind
            else {
                return Ok(false);
            };
            let [argument] = arguments.as_slice() else {
                return Ok(false);
            };
            let wrela_hir::GenericArgumentKind::Type(wrela_hir::TypeExpression {
                kind:
                    wrela_hir::TypeExpressionKind::Named {
                        definition: wrela_hir::Definition::Declaration(target),
                        arguments,
                    },
                ..
            }) = &argument.kind
            else {
                return Ok(false);
            };
            Ok(arguments.is_empty()
                && field.name == *name
                && analysis.types.get(result.0 as usize).is_some_and(|ty| {
                    matches!(ty.kind, SemanticTypeKind::Actor { class }
                    if analysis.types.get(class.0 as usize).is_some_and(|class| {
                        matches!(class.kind, SemanticTypeKind::Class { declaration, .. }
                            if declaration == target.declaration)
                    }))
                }))
        }
        _ => Ok(false),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactScalarType {
    Bool,
    Integer { signed: bool, bits: u16 },
    Float { bits: u16 },
}

fn exact_scalar_type(analysis: &PartialAnalysis, ty: SemanticTypeId) -> Option<ExactScalarType> {
    match analysis.types.get(ty.0 as usize)?.kind {
        SemanticTypeKind::Bool => Some(ExactScalarType::Bool),
        SemanticTypeKind::Integer { signed, bits, .. } => {
            Some(ExactScalarType::Integer { signed, bits })
        }
        SemanticTypeKind::Float { bits } => Some(ExactScalarType::Float { bits }),
        _ => None,
    }
}

fn exact_child_expression(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    expression: ExpressionId,
) -> Option<&ExpressionFact> {
    analysis
        .expressions
        .binary_search_by_key(&(function, expression), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| analysis.expressions.get(index))
}

fn exact_resolved_enum_constructor(
    program: &wrela_hir::Program,
    callee: ExpressionId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<wrela_hir::ResolvedVariant>, AnalysisFailure> {
    let Some(expression) = program.expression(callee) else {
        return Ok(None);
    };
    match &expression.kind {
        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Variant(resolved)) => {
            Ok(Some(resolved.clone()))
        }
        wrela_hir::ExpressionKind::Field { base, name } => {
            let Some(wrela_hir::Expression {
                kind:
                    wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(resolved)),
                ..
            }) = program.expression(*base)
            else {
                return Ok(None);
            };
            let Some(declaration) = program.declaration(resolved.declaration).filter(|record| {
                record.module == resolved.module
                    && program
                        .modules
                        .get(resolved.module.0 as usize)
                        .is_some_and(|module| module.package == resolved.package)
            }) else {
                return Ok(None);
            };
            let wrela_hir::DeclarationKind::Enumeration(enumeration) = &declaration.kind else {
                return Ok(None);
            };
            if enumeration.variants.len() > 256 {
                return Ok(None);
            }
            let mut selected = None;
            for (index, variant) in enumeration.variants.iter().enumerate() {
                check_analysis_cancelled(is_cancelled)?;
                if variant.name == *name {
                    if selected.is_some() {
                        return Ok(None);
                    }
                    selected = Some(u32::try_from(index).map_err(|_| {
                        AnalysisFailure::InternalInvariant(
                            "enum constructor variant index is not representable".to_owned(),
                        )
                    })?);
                }
            }
            Ok(selected.map(|variant| wrela_hir::ResolvedVariant {
                enumeration: resolved.clone(),
                variant,
            }))
        }
        _ => Ok(None),
    }
}

fn exact_expression_produces_value(fact: &ExpressionFact) -> bool {
    fact.result.is_some() || matches!(fact.resolution, ExpressionResolution::Value(_))
}

fn exact_scalar_unary_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    operator: wrela_hir::UnaryOperator,
    operand: ExpressionId,
    fact: &ExpressionFact,
) -> bool {
    let Some(operand) = exact_child_expression(analysis, function, operand) else {
        return false;
    };
    if !exact_expression_produces_value(operand)
        || operand.ty != fact.ty
        || operand.effects != fact.effects
    {
        return false;
    }
    matches!(
        (operator, exact_scalar_type(analysis, fact.ty)),
        (
            wrela_hir::UnaryOperator::Negate,
            Some(ExactScalarType::Integer { signed: true, .. } | ExactScalarType::Float { .. }),
        ) | (
            wrela_hir::UnaryOperator::BitNot,
            Some(ExactScalarType::Integer { .. })
        ) | (
            wrela_hir::UnaryOperator::BoolNot,
            Some(ExactScalarType::Bool)
        )
    ) || operator == wrela_hir::UnaryOperator::Copy
        && analysis
            .types
            .get(fact.ty.0 as usize)
            .is_some_and(|ty| ty.linearity == Linearity::ExplicitCopy)
}

fn exact_scalar_binary_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    operator: wrela_hir::BinaryOperator,
    left: ExpressionId,
    right: ExpressionId,
    fact: &ExpressionFact,
) -> bool {
    let (Some(left), Some(right)) = (
        exact_child_expression(analysis, function, left),
        exact_child_expression(analysis, function, right),
    ) else {
        return false;
    };
    exact_expression_produces_value(left)
        && exact_expression_produces_value(right)
        && left.ty == right.ty
        && fact.ty == left.ty
        && fact.effects.0 == left.effects.0 | right.effects.0
        && matches!(
            exact_scalar_type(analysis, left.ty),
            Some(ExactScalarType::Integer { .. })
        )
        && matches!(
            operator,
            wrela_hir::BinaryOperator::Add
                | wrela_hir::BinaryOperator::AddWrapping
                | wrela_hir::BinaryOperator::Subtract
                | wrela_hir::BinaryOperator::SubtractWrapping
                | wrela_hir::BinaryOperator::Multiply
                | wrela_hir::BinaryOperator::MultiplyWrapping
                | wrela_hir::BinaryOperator::Divide
                | wrela_hir::BinaryOperator::Remainder
                | wrela_hir::BinaryOperator::BitOr
                | wrela_hir::BinaryOperator::BitXor
                | wrela_hir::BinaryOperator::BitAnd
                | wrela_hir::BinaryOperator::ShiftLeft
                | wrela_hir::BinaryOperator::ShiftRight
        )
}

fn exact_scalar_comparison_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    operator: wrela_hir::ComparisonOperator,
    left: ExpressionId,
    right: ExpressionId,
    fact: &ExpressionFact,
) -> bool {
    let (Some(left), Some(right)) = (
        exact_child_expression(analysis, function, left),
        exact_child_expression(analysis, function, right),
    ) else {
        return false;
    };
    let bool_result = matches!(
        exact_scalar_type(analysis, fact.ty),
        Some(ExactScalarType::Bool)
    );
    let operator_matches = match exact_scalar_type(analysis, left.ty) {
        Some(ExactScalarType::Bool) => matches!(
            operator,
            wrela_hir::ComparisonOperator::Equal | wrela_hir::ComparisonOperator::NotEqual
        ),
        Some(ExactScalarType::Integer { .. } | ExactScalarType::Float { .. }) => matches!(
            operator,
            wrela_hir::ComparisonOperator::Equal
                | wrela_hir::ComparisonOperator::NotEqual
                | wrela_hir::ComparisonOperator::Less
                | wrela_hir::ComparisonOperator::LessEqual
                | wrela_hir::ComparisonOperator::Greater
                | wrela_hir::ComparisonOperator::GreaterEqual
        ),
        None => false,
    };
    exact_expression_produces_value(left)
        && exact_expression_produces_value(right)
        && left.ty == right.ty
        && bool_result
        && operator_matches
        && fact.effects.0 == left.effects.0 | right.effects.0
}

fn exact_scalar_cast_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    source: ExpressionId,
    destination: &wrela_hir::TypeExpression,
    fact: &ExpressionFact,
) -> bool {
    let Some(source) = exact_child_expression(analysis, function, source) else {
        return false;
    };
    exact_expression_produces_value(source)
        && source.effects == fact.effects
        && exact_scalar_source_type(analysis, destination) == Some(fact.ty)
        && matches!(
            exact_scalar_type(analysis, source.ty),
            Some(ExactScalarType::Integer { .. } | ExactScalarType::Float { .. })
        )
        && matches!(
            exact_scalar_type(analysis, fact.ty),
            Some(ExactScalarType::Integer { .. } | ExactScalarType::Float { .. })
        )
}

fn exact_scalar_source_type(
    analysis: &PartialAnalysis,
    source: &wrela_hir::TypeExpression,
) -> Option<SemanticTypeId> {
    let wrela_hir::TypeExpressionKind::Named {
        definition: wrela_hir::Definition::Builtin(builtin),
        arguments,
    } = &source.kind
    else {
        return None;
    };
    if !arguments.is_empty() {
        return None;
    }
    let matches = |kind: &SemanticTypeKind| match builtin {
        wrela_hir::Builtin::Unit => matches!(kind, SemanticTypeKind::Unit),
        wrela_hir::Builtin::Bool => matches!(kind, SemanticTypeKind::Bool),
        wrela_hir::Builtin::U8 => exact_integer_kind(kind, false, 8, false),
        wrela_hir::Builtin::U16 => exact_integer_kind(kind, false, 16, false),
        wrela_hir::Builtin::U32 => exact_integer_kind(kind, false, 32, false),
        wrela_hir::Builtin::U64 => exact_integer_kind(kind, false, 64, false),
        wrela_hir::Builtin::U128 => exact_integer_kind(kind, false, 128, false),
        wrela_hir::Builtin::Usize => exact_pointer_integer_kind(kind, false),
        wrela_hir::Builtin::I8 => exact_integer_kind(kind, true, 8, false),
        wrela_hir::Builtin::I16 => exact_integer_kind(kind, true, 16, false),
        wrela_hir::Builtin::I32 => exact_integer_kind(kind, true, 32, false),
        wrela_hir::Builtin::I64 => exact_integer_kind(kind, true, 64, false),
        wrela_hir::Builtin::I128 => exact_integer_kind(kind, true, 128, false),
        wrela_hir::Builtin::Isize => exact_pointer_integer_kind(kind, true),
        wrela_hir::Builtin::F32 => matches!(kind, SemanticTypeKind::Float { bits: 32 }),
        wrela_hir::Builtin::F64 => matches!(kind, SemanticTypeKind::Float { bits: 64 }),
        wrela_hir::Builtin::Never
        | wrela_hir::Builtin::Char
        | wrela_hir::Builtin::Static
        | wrela_hir::Builtin::Str
        | wrela_hir::Builtin::Bytes
        | wrela_hir::Builtin::String
        | wrela_hir::Builtin::Option
        | wrela_hir::Builtin::Result
        | wrela_hir::Builtin::Actor
        | wrela_hir::Builtin::Receipt
        | wrela_hir::Builtin::Dma
        | wrela_hir::Builtin::Mmio
        | wrela_hir::Builtin::Validated => false,
    };
    let mut found = None;
    for ty in &analysis.types {
        if matches(&ty.kind) && found.replace(ty.id).is_some() {
            return None;
        }
    }
    found
}

fn exact_runtime_source_type(
    analysis: &PartialAnalysis,
    source: &wrela_hir::TypeExpression,
) -> Option<SemanticTypeId> {
    if let Some(scalar) = exact_scalar_source_type(analysis, source) {
        return Some(scalar);
    }
    let wrela_hir::TypeExpressionKind::Named {
        definition: wrela_hir::Definition::Declaration(declaration),
        arguments: source_arguments,
    } = &source.kind
    else {
        return None;
    };
    let mut argument_types = Vec::new();
    argument_types
        .try_reserve_exact(source_arguments.len())
        .ok()?;
    for argument in source_arguments {
        let wrela_hir::GenericArgumentKind::Type(source) = &argument.kind else {
            return None;
        };
        argument_types.push(exact_scalar_source_type(analysis, source)?);
    }
    let mut matches = analysis.types.iter().filter(|candidate| {
        matches!(&candidate.kind, SemanticTypeKind::Enumeration {
            declaration: candidate_declaration,
            arguments,
            variants,
        } if *candidate_declaration == declaration.declaration
            && runtime_enum_arguments_supported(arguments, variants)
            && arguments.iter().zip(&argument_types).all(|(argument, expected)| {
                matches!(argument, SemanticArgument::Type(actual) if actual == expected)
            })
            && arguments.len() == argument_types.len())
    });
    let result = matches.next()?.id;
    matches.next().is_none().then_some(result)
}

fn exact_integer_kind(
    kind: &SemanticTypeKind,
    expected_signed: bool,
    expected_bits: u16,
    expected_pointer_sized: bool,
) -> bool {
    matches!(
        kind,
        SemanticTypeKind::Integer {
            signed,
            bits,
            pointer_sized,
        } if *signed == expected_signed
            && *bits == expected_bits
            && *pointer_sized == expected_pointer_sized
    )
}

fn exact_pointer_integer_kind(kind: &SemanticTypeKind, expected_signed: bool) -> bool {
    matches!(
        kind,
        SemanticTypeKind::Integer {
            signed,
            bits,
            pointer_sized: true,
        } if *signed == expected_signed && matches!(*bits, 32 | 64)
    )
}

fn exact_await_operand_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    operand: ExpressionId,
    result: SemanticTypeId,
) -> bool {
    analysis
        .expressions
        .binary_search_by_key(&(function, operand), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| analysis.expressions.get(index))
        .is_some_and(|operand| {
            operand.ty == result
                && operand.result.is_some()
                && match operand.resolution {
                    ExpressionResolution::DirectCall {
                        function: target, ..
                    } => analysis
                        .functions
                        .get(target.0 as usize)
                        .is_some_and(|target| target.color == FunctionColor::Async),
                    _ => false,
                }
        })
}

fn exact_expression_ownership_matches(
    program: &wrela_hir::Program,
    fact: &ExpressionFact,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    if fact.ownership_before != OwnershipState::Owned {
        return Ok(false);
    }
    let mut source_access = None;
    for parent in &program.expressions {
        check_analysis_cancelled(is_cancelled)?;
        let wrela_hir::ExpressionKind::Call { arguments, .. } = &parent.kind else {
            continue;
        };
        for argument in arguments {
            check_analysis_cancelled(is_cancelled)?;
            if let wrela_hir::CallArgumentValue::Value(value) = &argument.value {
                if *value == fact.expression && source_access.replace(argument.access()).is_some() {
                    return Ok(false);
                }
            }
        }
    }
    let expected_after = if source_access == Some(wrela_hir::AccessMode::Take) {
        OwnershipState::Taken
    } else {
        OwnershipState::Owned
    };
    Ok(fact.ownership_after == expected_after)
}

struct ExactStatementValidation<'a> {
    bodies: &'a [BodyId],
    exactly_taken: &'a [bool],
    definitions: &'a mut [u8],
}

fn validate_exact_statement_fact(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    fact: &StatementFact,
    validation: ExactStatementValidation<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let ExactStatementValidation {
        bodies,
        exactly_taken,
        definitions,
    } = validation;
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let statement = program
        .statement(fact.statement)
        .ok_or_else(|| invalid("statement fact HIR node is missing"))?;
    if bodies.binary_search(&statement.body).is_err() {
        return Err(invalid("statement fact belongs to a different source body"));
    }
    match &statement.kind {
        wrela_hir::StatementKind::Initialize { local, value } => {
            let [definition] = fact.definitions.as_slice() else {
                return Err(invalid("local initializer lacks one exact definition"));
            };
            let expression = analysis
                .expressions
                .binary_search_by_key(&(function.id, *value), |fact| {
                    (fact.function, fact.expression)
                })
                .ok()
                .and_then(|index| analysis.expressions.get(index))
                .ok_or_else(|| invalid("local initializer expression fact is missing"))?;
            let local_record = program
                .locals
                .get(local.0 as usize)
                .filter(|record| record.id == *local && record.body == statement.body)
                .ok_or_else(|| invalid("local initializer target is invalid"))?;
            let value_record = analysis
                .values
                .get(definition.value.0 as usize)
                .ok_or_else(|| invalid("local initializer value is invalid"))?;
            if definition.local != *local
                || expression.result != Some(definition.value)
                || value_record.function != function.id
                || value_record.origin != SemanticValueOrigin::Local(*local)
                || value_record.source != Some(local_record.source)
                || value_record.source_name.as_deref() != Some(local_record.name.as_str())
            {
                return Err(invalid("local initializer binding differs from HIR"));
            }
        }
        wrela_hir::StatementKind::Assign {
            targets,
            operator,
            value,
        } => {
            let [target] = targets.as_slice() else {
                return Err(invalid("scalar assignment target arity differs from HIR"));
            };
            let wrela_hir::Definition::Local(local) = &target.root else {
                return Err(invalid("scalar assignment target is not a local"));
            };
            if !target.projections.is_empty() {
                return Err(invalid("scalar assignment target contains a projection"));
            }
            let [definition] = fact.definitions.as_slice() else {
                return Err(invalid("scalar assignment lacks one exact definition"));
            };
            let expression = analysis
                .expressions
                .binary_search_by_key(&(function.id, *value), |fact| {
                    (fact.function, fact.expression)
                })
                .ok()
                .and_then(|index| analysis.expressions.get(index))
                .ok_or_else(|| invalid("scalar assignment expression fact is missing"))?;
            let local_record = program
                .locals
                .get(local.0 as usize)
                .filter(|record| record.id == *local)
                .ok_or_else(|| invalid("scalar assignment local is invalid"))?;
            let value_record = analysis
                .values
                .get(definition.value.0 as usize)
                .ok_or_else(|| invalid("scalar assignment value is invalid"))?;
            let compound = *operator != wrela_hir::AssignmentOperator::Assign;
            let expression_binding_matches = if compound {
                expression.result != Some(definition.value)
                    && expression.ty == value_record.ty
                    && analysis
                        .types
                        .get(value_record.ty.0 as usize)
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Integer { .. }))
                    && !analysis.expressions.iter().any(|expression| {
                        expression.function == function.id
                            && expression.result == Some(definition.value)
                    })
                    && !expression_references_local(program, *value, *local, is_cancelled)?
            } else {
                expression.result == Some(definition.value)
            };
            if definition.local != *local
                || !expression_binding_matches
                || value_record.function != function.id
                || value_record.origin != SemanticValueOrigin::Local(*local)
                || value_record.source != Some(local_record.source)
                || value_record.source_name.as_deref() != Some(local_record.name.as_str())
                || exact_runtime_source_type(
                    analysis,
                    local_record
                        .ty
                        .as_ref()
                        .ok_or_else(|| invalid("scalar assignment local lacks a type"))?,
                ) != Some(value_record.ty)
            {
                return Err(invalid("scalar assignment binding differs from HIR"));
            }
            if compound {
                increment_definition(definitions, definition.value)?;
            }
        }
        wrela_hir::StatementKind::Match { scrutinee, arms } => {
            let scrutinee_fact = analysis
                .expressions
                .binary_search_by_key(&(function.id, *scrutinee), |fact| {
                    (fact.function, fact.expression)
                })
                .ok()
                .and_then(|index| analysis.expressions.get(index))
                .ok_or_else(|| invalid("enum match scrutinee expression fact is missing"))?;
            let (enumeration, variant_count, payload_ty) = analysis
                .types
                .get(scrutinee_fact.ty.0 as usize)
                .and_then(|record| match &record.kind {
                    SemanticTypeKind::Enumeration {
                        declaration,
                        arguments,
                        variants,
                    } if runtime_enum_arguments_supported(arguments, variants) => variants
                        .first()
                        .and_then(|variant| variant.fields.first())
                        .map(|field| (*declaration, variants.len(), field.ty)),
                    _ => None,
                })
                .ok_or_else(|| invalid("enum match scrutinee type is not canonical"))?;
            if arms.len() != variant_count || fact.definitions.len() != arms.len() {
                return Err(invalid(
                    "enum match bindings do not cover every variant arm",
                ));
            }
            let mut covered = fallible_scratch::<bool>(variant_count, 256)?;
            covered.resize(variant_count, false);
            for (arm, definition) in arms.iter().zip(&fact.definitions) {
                check_analysis_cancelled(is_cancelled)?;
                if arm.guard.is_some() {
                    return Err(invalid("sealed enum match contains a guarded arm"));
                }
                let pattern = program
                    .patterns
                    .get(arm.pattern.0 as usize)
                    .filter(|pattern| {
                        pattern.id == arm.pattern
                            && pattern
                                .binding_scope
                                .and_then(|scope| program.scopes.get(scope.0 as usize))
                                .is_some_and(|scope| scope.body == arm.body)
                    })
                    .ok_or_else(|| invalid("enum match arm pattern scope differs from HIR"))?;
                let [alternative] = pattern.alternatives.as_slice() else {
                    return Err(invalid("enum match arm is not one constructor pattern"));
                };
                let wrela_hir::PrimaryPattern::Constructor {
                    candidates,
                    arguments,
                    ..
                } = &alternative.kind
                else {
                    return Err(invalid("enum match arm is not a constructor"));
                };
                let [candidate] = candidates.as_slice() else {
                    return Err(invalid("enum match constructor is not exact"));
                };
                let variant = usize::try_from(candidate.variant)
                    .map_err(|_| invalid("enum match variant index is invalid"))?;
                if program
                    .declaration(candidate.enumeration.declaration)
                    .filter(|record| {
                        record.id == enumeration
                            && record.module == candidate.enumeration.module
                            && program
                                .modules
                                .get(candidate.enumeration.module.0 as usize)
                                .is_some_and(|module| {
                                    module.package == candidate.enumeration.package
                                })
                    })
                    .is_none()
                    || variant >= variant_count
                    || covered[variant]
                {
                    return Err(invalid("enum match constructor coverage differs from HIR"));
                }
                covered[variant] = true;
                let [argument] = arguments.as_slice() else {
                    return Err(invalid("enum match constructor payload arity differs"));
                };
                if argument.take {
                    return Err(invalid("enum match payload unexpectedly takes ownership"));
                }
                let payload_pattern = program
                    .patterns
                    .get(argument.pattern.0 as usize)
                    .filter(|pattern| pattern.id == argument.pattern)
                    .ok_or_else(|| invalid("enum match payload pattern is missing"))?;
                let [payload_alternative] = payload_pattern.alternatives.as_slice() else {
                    return Err(invalid("enum match payload is not one binding pattern"));
                };
                let wrela_hir::PrimaryPattern::Bind(local) = payload_alternative.kind else {
                    return Err(invalid("enum match payload is not a local binding"));
                };
                let local_record = program
                    .locals
                    .get(local.0 as usize)
                    .filter(|record| record.id == local && record.body == arm.body)
                    .ok_or_else(|| invalid("enum match payload local differs from arm body"))?;
                let value_record = analysis
                    .values
                    .get(definition.value.0 as usize)
                    .filter(|record| {
                        definition.local == local
                            && record.function == function.id
                            && record.ty == payload_ty
                            && record.origin == SemanticValueOrigin::Local(local)
                            && record.source == Some(local_record.source)
                            && record.source_name.as_deref() == Some(local_record.name.as_str())
                    })
                    .ok_or_else(|| invalid("enum match payload value provenance is invalid"))?;
                if analysis.expressions.iter().any(|expression| {
                    expression.function == function.id && expression.result == Some(value_record.id)
                }) {
                    return Err(invalid(
                        "enum match payload binding is an expression result",
                    ));
                }
                increment_definition(definitions, definition.value)?;
            }
            if covered.iter().any(|covered| !covered) {
                return Err(invalid("enum match omits a constructor variant"));
            }
        }
        wrela_hir::StatementKind::If { .. } | wrela_hir::StatementKind::While { .. } => {
            for definition in &fact.definitions {
                check_analysis_cancelled(is_cancelled)?;
                let local_record = program
                    .locals
                    .get(definition.local.0 as usize)
                    .filter(|record| {
                        record.id == definition.local
                            && body_is_ancestor(program, record.body, statement.body)
                    })
                    .ok_or_else(|| invalid("branch join local is outside the conditional"))?;
                let value_record = analysis
                    .values
                    .get(definition.value.0 as usize)
                    .filter(|record| {
                        record.function == function.id
                            && record.origin == SemanticValueOrigin::Local(definition.local)
                            && record.source == Some(local_record.source)
                            && record.source_name.as_deref() == Some(local_record.name.as_str())
                    })
                    .ok_or_else(|| invalid("branch join value provenance is invalid"))?;
                if exact_runtime_source_type(
                    analysis,
                    local_record
                        .ty
                        .as_ref()
                        .ok_or_else(|| invalid("branch join local lacks a type"))?,
                ) != Some(value_record.ty)
                    || analysis.expressions.iter().any(|expression| {
                        expression.function == function.id
                            && expression.result == Some(definition.value)
                    })
                {
                    return Err(invalid(
                        "branch join value is not an exact statement result",
                    ));
                }
                increment_definition(definitions, definition.value)?;
            }
        }
        _ if fact.definitions.is_empty() => {}
        _ => {
            return Err(invalid(
                "statement has unsupported source-local definitions",
            ));
        }
    }
    for value in &fact.initialized_after {
        let record = analysis
            .values
            .get(value.0 as usize)
            .filter(|record| record.function == function.id)
            .ok_or_else(|| invalid("statement post-state contains a foreign value"))?;
        if let SemanticValueOrigin::Local(local) = record.origin {
            let local_body = program
                .locals
                .get(local.0 as usize)
                .map(|local| local.body)
                .ok_or_else(|| invalid("statement post-state local is missing"))?;
            if !body_is_ancestor(program, local_body, statement.body) {
                return Err(invalid(
                    "branch-local value escapes without an explicit merge",
                ));
            }
        }
    }
    for value in &fact.moved_after {
        check_analysis_cancelled(is_cancelled)?;
        if exactly_taken.get(value.0 as usize) != Some(&true) {
            return Err(invalid(
                "statement moved state does not name an exactly taken source value",
            ));
        }
    }
    Ok(())
}

fn exact_call_bindings_match(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: FunctionInstanceId,
    callee_expression: ExpressionId,
    source_arguments: &[wrela_hir::CallArgument],
    target: FunctionInstanceId,
    bindings: &[ResolvedCallArgument],
) -> bool {
    let Some(target_function) = analysis.functions.get(target.0 as usize) else {
        return false;
    };
    let callee_matches = analysis
        .expressions
        .binary_search_by_key(&(caller, callee_expression), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| analysis.expressions.get(index))
        .is_some_and(|fact| {
            fact.result.is_none() && fact.resolution == ExpressionResolution::Function(target)
        });
    if !callee_matches
        || bindings.len() != source_arguments.len()
        || bindings.len() != target_function.parameters.len()
    {
        return false;
    }
    bindings
        .iter()
        .enumerate()
        .all(|(parameter_index, binding)| {
            let Some(source) = source_arguments.get(binding.source_index as usize) else {
                return false;
            };
            let Some(parameter) = target_function.parameters.get(parameter_index) else {
                return false;
            };
            let name_matches = match &source.name {
                Some(name) => {
                    program
                        .parameters
                        .get(parameter.parameter.0 as usize)
                        .and_then(|parameter| parameter.name.as_ref())
                        == Some(name)
                }
                None => binding.source_index as usize == parameter_index,
            };
            let access_matches = matches!(
                (&source.value, binding.access),
                (
                    wrela_hir::CallArgumentValue::Value(_),
                    AccessMode::Value | AccessMode::Read
                ) | (
                    wrela_hir::CallArgumentValue::Exclusive {
                        access: wrela_hir::ExclusiveAccess::Mutate,
                        ..
                    },
                    AccessMode::Mutate,
                ) | (
                    wrela_hir::CallArgumentValue::Exclusive {
                        access: wrela_hir::ExclusiveAccess::Take,
                        ..
                    },
                    AccessMode::Take,
                )
            );
            binding.parameter_index as usize == parameter_index
                && name_matches
                && access_matches
                && binding.access == parameter.access
                && analysis
                    .values
                    .get(binding.value.0 as usize)
                    .is_some_and(|value| value.function == caller && value.ty == parameter.ty)
                && match &source.value {
                    wrela_hir::CallArgumentValue::Value(expression) => analysis
                        .expressions
                        .binary_search_by_key(&(caller, *expression), |fact| {
                            (fact.function, fact.expression)
                        })
                        .ok()
                        .and_then(|index| analysis.expressions.get(index))
                        .is_some_and(|fact| {
                            fact.result == Some(binding.value)
                                || fact.resolution == ExpressionResolution::Value(binding.value)
                        }),
                    wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                        place.projections.is_empty()
                            && analysis
                                .values
                                .get(binding.value.0 as usize)
                                .is_some_and(|value| {
                                    matches!(
                                        (&place.root, &value.origin),
                                        (
                                            wrela_hir::Definition::Local(source),
                                            SemanticValueOrigin::Local(candidate)
                                        ) if source == candidate
                                    ) || matches!(
                                        (&place.root, &value.origin),
                                        (
                                            wrela_hir::Definition::Parameter(source),
                                            SemanticValueOrigin::Parameter(candidate)
                                        ) if source == candidate
                                    )
                                })
                    }
                }
        })
}

fn exact_actor_method_reference_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: FunctionInstanceId,
    fact: &ExpressionFact,
    base: ExpressionId,
    name: &wrela_hir::Name,
    target: FunctionInstanceId,
) -> bool {
    if fact.effects != EffectSet(0)
        || fact.result.is_some()
        || fact.ownership_before != OwnershipState::Owned
        || fact.ownership_after != OwnershipState::Owned
    {
        return false;
    }
    let Some(graph) = analysis.graph.as_ref() else {
        return false;
    };
    let Some(caller_record) = analysis.functions.get(caller.0 as usize) else {
        return false;
    };
    let FunctionRole::TaskEntry(task) = caller_record.role else {
        return false;
    };
    let Some(source_actor) = graph
        .tasks
        .get(task.0 as usize)
        .filter(|record| record.id == task)
        .and_then(|record| record.supervisor)
    else {
        return false;
    };
    let Some(target_record) = analysis.functions.get(target.0 as usize) else {
        return false;
    };
    let target_name_matches = match target_record.origin {
        FunctionOrigin::Source { declaration, .. } => {
            program
                .declaration(declaration)
                .and_then(|declaration| declaration.name.as_ref())
                == Some(name)
        }
        _ => false,
    };
    let Some(base_fact) = exact_child_expression(analysis, caller, base) else {
        return false;
    };
    let base_is_receiver = program.expression(base).is_some_and(|expression| {
        matches!(
            expression.kind,
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(parameter))
                if caller_record.parameters.first().map(|record| record.parameter)
                    == Some(parameter)
        )
    });
    let method_type_matches = analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
        matches!(
            &ty.kind,
            SemanticTypeKind::Function {
                color: FunctionColor::Async,
                parameters,
                result,
            } if parameters.is_empty() && *result == SemanticTypeId(0)
        )
    });
    let target_actor = match target_record.role {
        FunctionRole::ActorTurn(actor) => actor,
        _ => return false,
    };
    let cross_actor_handle = graph.actors.len() == 2
        && source_actor == ActorId(1)
        && target_actor == ActorId(0)
        && matches!(
            base_fact.resolution,
            ExpressionResolution::Field { index: 0 }
        )
        && base_fact.result.is_some();
    target_name_matches
        && ((base_is_receiver
            && source_actor == target_actor
            && matches!(base_fact.resolution, ExpressionResolution::Value(_))
            && base_fact.result.is_none())
            || cross_actor_handle)
        && base_fact.effects == EffectSet(0)
        && target_record.id == target
        && target_record.color == FunctionColor::Async
        && target_record.parameters.len() == 1
        && target_record.result == SemanticTypeId(0)
        && method_type_matches
}

#[allow(clippy::too_many_arguments)]
fn exact_actor_request_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: FunctionInstanceId,
    fact: &ExpressionFact,
    callee: ExpressionId,
    arguments: &[wrela_hir::CallArgument],
    actor: ActorId,
    method: FunctionInstanceId,
    permit: ProofId,
) -> bool {
    if !arguments.is_empty()
        || fact.effects != EffectSet(EffectSet::ACTOR)
        || fact.ownership_before != OwnershipState::Owned
        || fact.ownership_after != OwnershipState::Taken
    {
        return false;
    }
    let Some(graph) = analysis.graph.as_ref() else {
        return false;
    };
    let Some(producer) = analysis.functions.get(caller.0 as usize) else {
        return false;
    };
    let FunctionRole::TaskEntry(task) = producer.role else {
        return false;
    };
    let Some(source_actor) = graph
        .tasks
        .get(task.0 as usize)
        .filter(|record| record.id == task)
        .and_then(|record| record.supervisor)
    else {
        return false;
    };
    if source_actor != actor
        && !(graph.actors.len() == 2 && source_actor == ActorId(1) && actor == ActorId(0))
    {
        return false;
    }
    let Some(target) = analysis.functions.get(method.0 as usize) else {
        return false;
    };
    if target.id != method
        || target.role != FunctionRole::ActorTurn(actor)
        || target.color != FunctionColor::Async
        || target.parameters.len() != 1
        || target.result != SemanticTypeId(0)
    {
        return false;
    }
    let Some(reservation) = analysis.types.get(fact.ty.0 as usize) else {
        return false;
    };
    if reservation.kind != SemanticTypeKind::Reservation
        || reservation.linearity != Linearity::StrictLinear
        || reservation.size_upper_bound != Some(8)
        || reservation.alignment_lower_bound != 8
        || reservation.source.is_some()
    {
        return false;
    }
    let Some(callee_source) = program.expression(callee) else {
        return false;
    };
    let wrela_hir::ExpressionKind::Field { base, name } = &callee_source.kind else {
        return false;
    };
    let Some(base_source) = program.expression(*base) else {
        return false;
    };
    let receiver = match &base_source.kind {
        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(receiver)) => {
            *receiver
        }
        wrela_hir::ExpressionKind::Field { base, .. }
            if source_actor == ActorId(1) && actor == ActorId(0) =>
        {
            let Some(wrela_hir::Expression {
                kind:
                    wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(receiver)),
                ..
            }) = program.expression(*base)
            else {
                return false;
            };
            *receiver
        }
        _ => return false,
    };
    if producer
        .parameters
        .first()
        .map(|parameter| parameter.parameter)
        != Some(receiver)
    {
        return false;
    }
    let Some(base_fact) = exact_child_expression(analysis, caller, *base) else {
        return false;
    };
    let Some(callee_fact) = exact_child_expression(analysis, caller, callee) else {
        return false;
    };
    let base_matches = (source_actor == actor
        && matches!(base_fact.resolution, ExpressionResolution::Value(_))
        && base_fact.result.is_none())
        || (source_actor == ActorId(1)
            && actor == ActorId(0)
            && matches!(
                base_fact.resolution,
                ExpressionResolution::Field { index: 0 }
            )
            && base_fact.result.is_some());
    if !base_matches
        || base_fact.effects != EffectSet(0)
        || callee_fact.resolution != ExpressionResolution::Function(method)
        || callee_fact.result.is_some()
        || callee_fact.effects != EffectSet(0)
    {
        return false;
    }
    let method_name_matches = match target.origin {
        FunctionOrigin::Source { declaration, .. } => {
            program
                .declaration(declaration)
                .and_then(|declaration| declaration.name.as_ref())
                == Some(name)
        }
        _ => false,
    };
    if !method_name_matches {
        return false;
    }
    let mut mailbox_proof = None;
    for region in &graph.regions {
        if region.owner == ImageOwner::Actor(actor)
            && region.class == RegionClass::Image
            && mailbox_proof.replace(region.proof).is_some()
        {
            return false;
        }
    }
    let Some(mailbox_proof) = mailbox_proof else {
        return false;
    };
    let Some(request_source) = program
        .expression(fact.expression)
        .map(|expression| expression.source)
    else {
        return false;
    };
    analysis.proofs.get(permit.0 as usize).is_some_and(|proof| {
        proof.id == permit
            && proof.kind == ProofKind::CapacityBound
            && proof.bound == Some(1)
            && proof.sources.as_slice() == [request_source]
            && proof.depends_on.as_slice() == [mailbox_proof]
            && producer.proofs.contains(&permit)
    })
}

fn constant_matches_literal(
    analysis: &PartialAnalysis,
    ty: SemanticTypeId,
    literal: &wrela_hir::Literal,
    constant: &ConstantValue,
) -> bool {
    let Some(kind) = analysis.types.get(ty.0 as usize).map(|record| &record.kind) else {
        return false;
    };
    match (literal, constant, kind) {
        (wrela_hir::Literal::Unit, ConstantValue::Unit, SemanticTypeKind::Unit) => true,
        (
            wrela_hir::Literal::Boolean(source),
            ConstantValue::Bool(value),
            SemanticTypeKind::Bool,
        ) => source == value,
        (
            wrela_hir::Literal::Integer(source),
            ConstantValue::Unsigned {
                bits: value_bits,
                value,
            },
            SemanticTypeKind::Integer {
                signed: false,
                bits,
                ..
            },
        ) => bits == value_bits && parse_hir_integer(source) == Some(*value),
        (
            wrela_hir::Literal::Integer(source),
            ConstantValue::Signed {
                bits: value_bits,
                value,
            },
            SemanticTypeKind::Integer {
                signed: true, bits, ..
            },
        ) => {
            bits == value_bits
                && parse_hir_integer(source).and_then(|value| i128::try_from(value).ok())
                    == Some(*value)
        }
        (
            wrela_hir::Literal::Float(source),
            ConstantValue::Float32(value),
            SemanticTypeKind::Float { bits: 32 },
        ) => parse_hir_float(source)
            .and_then(|source| source.parse::<f32>().ok())
            .filter(|source| source.is_finite())
            .is_some_and(|source| source.to_bits() == *value),
        (
            wrela_hir::Literal::Float(source),
            ConstantValue::Float64(value),
            SemanticTypeKind::Float { bits: 64 },
        ) => parse_hir_float(source)
            .and_then(|source| source.parse::<f64>().ok())
            .filter(|source| source.is_finite())
            .is_some_and(|source| source.to_bits() == *value),
        _ => false,
    }
}

fn parse_hir_float(value: &str) -> Option<String> {
    let mut spelling = String::new();
    spelling.try_reserve_exact(value.len()).ok()?;
    spelling.extend(value.chars().filter(|character| *character != '_'));
    Some(spelling)
}

fn parse_hir_integer(value: &str) -> Option<u128> {
    let (digits, radix) = if let Some(digits) = value.strip_prefix("0x") {
        (digits, 16)
    } else if let Some(digits) = value.strip_prefix("0o") {
        (digits, 8)
    } else if let Some(digits) = value.strip_prefix("0b") {
        (digits, 2)
    } else {
        (value, 10)
    };
    let mut output = 0u128;
    for byte in digits.bytes().filter(|byte| *byte != b'_') {
        let digit = match byte {
            b'0'..=b'9' => u128::from(byte - b'0'),
            b'a'..=b'f' => u128::from(byte - b'a' + 10),
            b'A'..=b'F' => u128::from(byte - b'A' + 10),
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        output = output.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(output)
}

fn body_is_ancestor(program: &wrela_hir::Program, ancestor: BodyId, body: BodyId) -> bool {
    let Some(mut scope) = program.body(body).map(|body| body.scope) else {
        return false;
    };
    loop {
        let Some(record) = program.scopes.get(scope.0 as usize) else {
            return false;
        };
        if record.body == ancestor {
            return true;
        }
        let Some(parent) = record.parent else {
            return false;
        };
        scope = parent;
    }
}

fn increment_definition(definitions: &mut [u8], value: ValueId) -> Result<(), AnalysisFailure> {
    let count = definitions.get_mut(value.0 as usize).ok_or_else(|| {
        AnalysisFailure::InternalInvariant("value definition is dangling".to_owned())
    })?;
    *count = count.checked_add(1).ok_or_else(|| {
        AnalysisFailure::InternalInvariant("value definition count overflowed".to_owned())
    })?;
    Ok(())
}

fn fallible_scratch<T>(capacity: usize, limit: u64) -> Result<Vec<T>, AnalysisFailure> {
    if u64::try_from(capacity).map_or(true, |capacity| capacity > limit) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "source body validation scratch",
            limit,
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "source body validation scratch",
            limit,
        })?;
    Ok(output)
}

fn reserve_validation_scratch<T>(
    output: &mut Vec<T>,
    additional: usize,
    limit: u64,
) -> Result<(), AnalysisFailure> {
    let required = output
        .len()
        .checked_add(additional)
        .and_then(|required| u64::try_from(required).ok())
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "source body validation scratch",
            limit,
        })?;
    if required > limit {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "source body validation scratch",
            limit,
        });
    }
    output
        .try_reserve_exact(additional)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "source body validation scratch",
            limit,
        })
}

fn compiled_test_group_matches_facts(
    analysis: &PartialAnalysis,
    group: &FullImageTestGroup,
) -> bool {
    if group.name.trim().is_empty()
        || group.tests.is_empty()
        || group.boot_timeout_ns == 0
        || group.shutdown_timeout_ns == 0
        || group.maximum_events == 0
        || group.maximum_output_bytes == 0
    {
        return false;
    }
    let root_matches = match (&analysis.root, &group.root) {
        (
            AnalysisRoot::GeneratedTestHarness {
                group: actual_group,
                harness_name: actual_name,
            },
            TestImageRoot::GeneratedHarness { harness_name },
        ) => actual_group == &group.id && actual_name == harness_name,
        (
            AnalysisRoot::DeclaredImage {
                image_name: actual_name,
                test_group: Some(actual_group),
                ..
            },
            TestImageRoot::Declared { image_name, .. },
        ) => actual_group == &group.id && actual_name == image_name,
        _ => false,
    };
    if !root_matches {
        return false;
    }
    let mut semantic_keys = Vec::new();
    if semantic_keys
        .try_reserve_exact(analysis.functions.len())
        .is_err()
    {
        return false;
    }
    semantic_keys.extend(
        analysis
            .functions
            .iter()
            .filter(|function| function.role == FunctionRole::Test)
            .map(|function| function.key),
    );
    semantic_keys.sort_unstable();
    if semantic_keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    match &group.root {
        TestImageRoot::GeneratedHarness { .. } => {
            let mut planned_keys = Vec::new();
            if planned_keys.try_reserve_exact(group.tests.len()).is_err() {
                return false;
            }
            for test in &group.tests {
                let wrela_test_model::ImageTestInvocation::GeneratedFunction { function_key } =
                    test.invocation
                else {
                    return false;
                };
                planned_keys.push(function_key);
            }
            planned_keys.sort_unstable();
            !planned_keys.windows(2).any(|pair| pair[0] == pair[1]) && semantic_keys == planned_keys
        }
        TestImageRoot::Declared { .. } => {
            semantic_keys.is_empty()
                && group.tests.len() == 1
                && matches!(
                    group.tests[0].invocation,
                    wrela_test_model::ImageTestInvocation::DeclaredScenario
                )
        }
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
            AnalysisRoot::DeclaredImage { declaration, .. },
            FunctionOrigin::GeneratedImageEntry { constructor },
        ) => declaration == constructor,
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

fn valid_function_color_role(function: &FunctionInstance) -> bool {
    match (function.color, function.role) {
        (FunctionColor::Isr, FunctionRole::Isr(_)) => true,
        (FunctionColor::Isr, _) | (_, FunctionRole::Isr(_)) => false,
        (FunctionColor::Sync, FunctionRole::ImageEntry) => true,
        (FunctionColor::Async, FunctionRole::ImageEntry) => false,
        (FunctionColor::Sync | FunctionColor::Async, _) => true,
    }
}

fn valid_function_roles(analysis: &PartialAnalysis, graph: &ImageGraph) -> bool {
    let mut actor_turns = Vec::new();
    let mut device_interrupts = Vec::new();
    if actor_turns.try_reserve_exact(graph.actors.len()).is_err()
        || device_interrupts
            .try_reserve_exact(graph.devices.len())
            .is_err()
    {
        return false;
    }
    actor_turns.resize(graph.actors.len(), 0usize);
    device_interrupts.resize(graph.devices.len(), 0usize);
    let mut image_entry = None;
    let mut roles_valid = true;
    for function in &analysis.functions {
        match function.role {
            FunctionRole::ImageEntry => {
                roles_valid &= image_entry.replace(function.id).is_none();
            }
            FunctionRole::ActorTurn(actor) => {
                let Some(next) = actor_turns.get_mut(actor.0 as usize) else {
                    roles_valid = false;
                    continue;
                };
                let Some(expected) = graph
                    .actors
                    .get(actor.0 as usize)
                    .and_then(|record| record.turn_functions.get(*next))
                else {
                    roles_valid = false;
                    continue;
                };
                roles_valid &= *expected == function.id;
                *next += 1;
            }
            FunctionRole::TaskEntry(task) => {
                roles_valid &= graph
                    .tasks
                    .get(task.0 as usize)
                    .is_some_and(|node| node.entry == function.id);
            }
            FunctionRole::Isr(device) => {
                let Some(next) = device_interrupts.get_mut(device.0 as usize) else {
                    roles_valid = false;
                    continue;
                };
                let Some(expected) = graph
                    .devices
                    .get(device.0 as usize)
                    .and_then(|record| record.interrupt_functions.get(*next))
                else {
                    roles_valid = false;
                    continue;
                };
                roles_valid &= *expected == function.id;
                *next += 1;
            }
            FunctionRole::Ordinary | FunctionRole::Cleanup | FunctionRole::Test => {}
        }
    }
    roles_valid
        && image_entry == Some(graph.entry)
        && graph.actors.iter().all(|actor| {
            actor_turns.get(actor.id.0 as usize).copied() == Some(actor.turn_functions.len())
        })
        && graph.devices.iter().all(|device| {
            device_interrupts.get(device.id.0 as usize).copied()
                == Some(device.interrupt_functions.len())
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
        SemanticTypeKind::Integer {
            bits,
            pointer_sized,
            ..
        } => {
            matches!(*bits, 8 | 16 | 32 | 64 | 128)
                && (!pointer_sized || matches!(*bits, 16 | 32 | 64 | 128))
        }
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
                    .all(|variant| valid_variant_fields(&variant.fields, analysis.types.len()))
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
        SemanticTypeKind::Reservation => true,
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

fn valid_variant_fields(fields: &[SemanticField], type_count: usize) -> bool {
    fields
        .iter()
        .all(|field| (field.ty.0 as usize) < type_count)
        && (fields.iter().all(|field| field.name.is_empty())
            || unique_nonempty(fields.iter().map(|field| field.name.as_str())))
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
    let mut pending = Vec::new();
    if pending.try_reserve_exact(1).is_err() {
        return false;
    }
    pending.push(root);
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
                if pending.try_reserve(values.len()).is_err() {
                    return false;
                }
                pending.extend(values);
            }
            ConstantValue::Structure { ty, fields }
            | ConstantValue::Enumeration { ty, fields, .. } => {
                if ty.0 as usize >= analysis.types.len() {
                    return false;
                }
                if pending.try_reserve(fields.len()).is_err() {
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
    let result_valid = fact.result.is_none_or(|result| {
        analysis.values.get(result.0 as usize).is_some_and(|value| {
            value.function == fact.function
                && value.ty == fact.ty
                && value.category == fact.category
        })
    });
    // A non-negating operator call writes the expression's own result
    // directly; only `<= >=` write a distinct intermediate `raw_result`
    // ahead of a further logical NOT.
    let operator_call_result_valid = match &fact.resolution {
        ExpressionResolution::OperatorCall {
            raw_result,
            negate: false,
            ..
        } => fact.result == Some(*raw_result),
        _ => true,
    };
    (fact.function.0 as usize) < analysis.functions.len()
        && fact.expression.0 < analysis.hir.expressions
        && (fact.ty.0 as usize) < analysis.types.len()
        && valid_expression_region(fact, graph)
        && fact.effects.is_valid()
        && valid_proof_set(&fact.proofs, analysis.proofs.len())
        && result_valid
        && operator_call_result_valid
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
        ExpressionResolution::Constructor { ty, variant } => analysis
            .types
            .get(ty.0 as usize)
            .is_some_and(|record| match (&record.kind, variant) {
                (SemanticTypeKind::Structure { arguments, .. }, None) => arguments.is_empty(),
                (
                    SemanticTypeKind::Enumeration {
                        arguments,
                        variants,
                        ..
                    },
                    Some(variant),
                ) => {
                    runtime_enum_arguments_supported(arguments, variants)
                        && (*variant as usize) < variants.len()
                }
                _ => false,
            }),
        ExpressionResolution::ResultTry {
            result_type,
            ok_variant,
            err_variant,
            ok_payload,
            err_payload,
            propagated,
        } => valid_result_try_resolution(
            analysis,
            function,
            *result_type,
            *ok_variant,
            *err_variant,
            *ok_payload,
            *err_payload,
            *propagated,
        ),
        ExpressionResolution::DirectCall {
            function: target,
            arguments,
        } => analysis
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| {
                arguments.len() == target.parameters.len()
                    && arguments.iter().zip(&target.parameters).enumerate().all(
                        |(parameter_index, (actual, expected))| {
                            usize::try_from(actual.parameter_index) == Ok(parameter_index)
                                && actual.access == expected.access
                        },
                    )
            }),
        ExpressionResolution::OperatorCall {
            function: target,
            arguments,
            raw_result,
            negate: _,
        } => {
            value_id(*raw_result)
                && analysis
                    .functions
                    .get(target.0 as usize)
                    .is_some_and(|target| {
                        arguments.len() == 2
                            && target.parameters.len() == 2
                            && arguments.iter().zip(&target.parameters).enumerate().all(
                                |(parameter_index, (actual, expected))| {
                                    usize::try_from(actual.parameter_index) == Ok(parameter_index)
                                        && actual.access == expected.access
                                },
                            )
                    })
        }
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

#[allow(clippy::too_many_arguments)]
fn valid_result_try_resolution(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    result_type: SemanticTypeId,
    ok_variant: u32,
    err_variant: u32,
    ok_payload: ValueId,
    err_payload: ValueId,
    propagated: ValueId,
) -> bool {
    let Some(SemanticTypeKind::Enumeration {
        arguments,
        variants,
        ..
    }) = analysis
        .types
        .get(result_type.0 as usize)
        .map(|record| &record.kind)
    else {
        return false;
    };
    if ok_variant != 0 || err_variant != 1 || !runtime_enum_arguments_supported(arguments, variants)
    {
        return false;
    }
    let Some(payload_type) = variants
        .first()
        .and_then(|variant| variant.fields.first())
        .map(|field| field.ty)
    else {
        return false;
    };
    let value_matches = |value: ValueId, ty: SemanticTypeId| {
        analysis.values.get(value.0 as usize).is_some_and(|value| {
            value.function == function && value.ty == ty && value.category == ValueCategory::Value
        })
    };
    let distinct = [ok_payload, err_payload, propagated]
        .iter()
        .enumerate()
        .all(|(index, value)| {
            [ok_payload, err_payload, propagated][index + 1..]
                .iter()
                .all(|candidate| candidate != value)
        });
    distinct
        && value_matches(ok_payload, payload_type)
        && value_matches(err_payload, payload_type)
        && value_matches(propagated, result_type)
}

fn valid_expression_region(fact: &ExpressionFact, graph: &ImageGraph) -> bool {
    let resolves = |region: RegionId| (region.0 as usize) < graph.regions.len();
    match fact.category {
        ValueCategory::Place | ValueCategory::SharedView | ValueCategory::MutableView => {
            fact.region.is_some_and(resolves)
        }
        ValueCategory::Value | ValueCategory::TypeValue => match &fact.resolution {
            ExpressionResolution::Field { .. } => fact.region.is_none(),
            ExpressionResolution::Index { .. } => fact.region.is_some_and(resolves),
            ExpressionResolution::Builtin(IntrinsicOperation::RegionAllocate {
                region, ..
            })
            | ExpressionResolution::Builtin(IntrinsicOperation::RegionReset { region }) => {
                fact.region == Some(*region) && resolves(*region)
            }
            ExpressionResolution::Error => false,
            ExpressionResolution::Constant(_)
            | ExpressionResolution::Value(_)
            | ExpressionResolution::Function(_)
            | ExpressionResolution::Constructor { .. }
            | ExpressionResolution::ResultTry { .. }
            | ExpressionResolution::DirectCall { .. }
            | ExpressionResolution::OperatorCall { .. }
            | ExpressionResolution::ActorRequest { .. }
            | ExpressionResolution::Closure { .. }
            | ExpressionResolution::Builtin(_) => fact.region.is_none(),
        },
        ValueCategory::Error => false,
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
        && (fact
            .definitions
            .windows(2)
            .all(|pair| pair[0].local < pair[1].local)
            || (fact.definitions.len() % 2 == 0 && {
                let arity = fact.definitions.len() / 2;
                fact.definitions[..arity]
                    .windows(2)
                    .all(|pair| pair[0].local < pair[1].local)
                    && fact.definitions[arity..]
                        .windows(2)
                        .all(|pair| pair[0].local < pair[1].local)
                    && fact.definitions[..arity]
                        .iter()
                        .zip(&fact.definitions[arity..])
                        .all(|(header, exit)| header.local == exit.local)
            }))
        && fact
            .definitions
            .iter()
            .all(|definition| definition.local.0 < analysis.hir.locals && value(definition.value))
        && strict_ids(&fact.initialized_after)
        && strict_ids(&fact.moved_after)
        && fact
            .initialized_after
            .iter()
            .all(|value| fact.moved_after.binary_search(value).is_err())
        && fact.initialized_after.iter().copied().all(value)
        && fact.moved_after.iter().copied().all(value)
        && valid_proof_set(&fact.proofs, analysis.proofs.len())
        && {
            let mut seen = std::collections::HashSet::new();
            seen.try_reserve(fact.live_loans_after.len()).is_ok()
                && fact.live_loans_after.iter().all(|loan| {
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
        actor.mailbox_capacity == 0
            || actor.class.0 as usize >= analysis.types.len()
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
    let Some(required_capacity) = 1usize
        .checked_add(graph.actors.len())
        .and_then(|count| count.checked_add(graph.tasks.len()))
        .and_then(|count| count.checked_add(graph.devices.len()))
        .and_then(|count| count.checked_add(graph.pools.len()))
    else {
        return false;
    };
    let mut required = std::collections::HashSet::new();
    if required.try_reserve(required_capacity).is_err() {
        return false;
    }
    required.insert(ImageOwner::Runtime);
    required.extend(graph.actors.iter().map(|node| ImageOwner::Actor(node.id)));
    required.extend(graph.tasks.iter().map(|node| ImageOwner::Task(node.id)));
    required.extend(graph.devices.iter().map(|node| ImageOwner::Device(node.id)));
    required.extend(graph.pools.iter().map(|node| ImageOwner::Pool(node.id)));
    let Some(startup) = fallible_set(&graph.startup_order) else {
        return false;
    };
    let Some(shutdown) = fallible_set(&graph.shutdown_order) else {
        return false;
    };
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
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .any(|value| seen.try_reserve(1).is_err() || !seen.insert(value))
}

fn strict_strings(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn unique_nonempty<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .all(|value| !value.trim().is_empty() && seen.try_reserve(1).is_ok() && seen.insert(value))
}

fn fallible_set<T>(values: &[T]) -> Option<std::collections::HashSet<T>>
where
    T: Copy + Eq + std::hash::Hash,
{
    let mut set = std::collections::HashSet::new();
    set.try_reserve(values.len()).ok()?;
    set.extend(values.iter().copied());
    Some(set)
}

fn dense(ids: impl IntoIterator<Item = u32>) -> bool {
    ids.into_iter()
        .enumerate()
        .all(|(expected, actual)| expected == actual as usize)
}

fn valid_value_origin(origin: SemanticValueOrigin, hir: HirSummary) -> bool {
    match origin {
        SemanticValueOrigin::Parameter(parameter) => parameter.0 < hir.parameters,
        SemanticValueOrigin::Local(local) => local.0 < hir.locals,
        SemanticValueOrigin::Expression(expression) => expression.0 < hir.expressions,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzedImage {
    hir: Arc<ValidatedProgram>,
    facts: PartialAnalysis,
}

impl AnalyzedImage {
    #[must_use]
    pub fn facts(&self) -> &PartialAnalysis {
        &self.facts
    }

    #[must_use]
    pub fn hir(&self) -> &ValidatedProgram {
        &self.hir
    }

    #[must_use]
    pub fn shared_hir(&self) -> &Arc<ValidatedProgram> {
        &self.hir
    }

    #[must_use]
    pub fn into_facts(self) -> PartialAnalysis {
        self.facts
    }

    #[must_use]
    pub fn into_parts(self) -> (Arc<ValidatedProgram>, PartialAnalysis) {
        (self.hir, self.facts)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisOutput {
    product: AnalysisProduct,
    diagnostics: Vec<Diagnostic>,
}

/// Analysis output paired with non-semantic execution evidence. Reuse history
/// never enters the sealed fact database, preserving exact cold/incremental
/// structural equality.
#[derive(Debug, Clone, PartialEq)]
pub struct TrackedAnalysisOutput {
    output: AnalysisOutput,
    reuse: AnalysisReuseReport,
}

impl TrackedAnalysisOutput {
    #[must_use]
    pub fn output(&self) -> &AnalysisOutput {
        &self.output
    }

    #[must_use]
    pub fn reuse(&self) -> &AnalysisReuseReport {
        &self.reuse
    }

    #[must_use]
    pub fn into_parts(self) -> (AnalysisOutput, AnalysisReuseReport) {
        (self.output, self.reuse)
    }
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
    validate_analysis_request(request, &partial, &diagnostics, is_cancelled)?;
    check_analysis_cancelled(is_cancelled)?;
    partial.validate_partial_structure()?;
    check_analysis_cancelled(is_cancelled)?;
    let mut diagnostics = WithDiagnostics {
        value: (),
        diagnostics,
    };
    diagnostics.sort_diagnostics();
    let product = if diagnostics.has_errors() {
        AnalysisProduct::Partial(partial)
    } else {
        partial.validate_for_seal(request.hir.as_ref(), is_cancelled)?;
        check_analysis_cancelled(is_cancelled)?;
        AnalysisProduct::Complete(AnalyzedImage {
            hir: Arc::clone(&request.hir),
            facts: partial,
        })
    };
    if is_cancelled() {
        return Err(AnalysisFailure::Cancelled);
    }
    Ok(AnalysisOutput {
        product,
        diagnostics: diagnostics.diagnostics,
    })
}

fn check_analysis_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), AnalysisFailure> {
    if is_cancelled() {
        Err(AnalysisFailure::Cancelled)
    } else {
        Ok(())
    }
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
    let mut expected = declared.iter();
    for group in plan
        .image_groups
        .iter()
        .filter(|group| matches!(group.root, TestImageRoot::Declared { .. }))
    {
        let Some(expected) = expected.next() else {
            return false;
        };
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
        if group.name != expected.name
            || image_name != &expected.image_name
            || scenario != &expected.scenario
            || group.tests.len() != 1
            || group.tests[0].descriptor.name != expected.name
            || group.tests[0].descriptor.timeout_ns != expected_timeout.unwrap_or(0)
            || !matches!(
                group.tests[0].invocation,
                wrela_test_model::ImageTestInvocation::DeclaredScenario
            )
            || group.deterministic_seed != expected.deterministic_seed
            || group.boot_timeout_ns != expected.boot_timeout_ns
            || group.shutdown_timeout_ns != expected.shutdown_timeout_ns
            || group.maximum_events != expected.maximum_events
            || group.maximum_output_bytes != expected.maximum_output_bytes
        {
            return false;
        }
    }
    expected.next().is_none()
}

fn validate_analysis_top_level_counts(
    partial: &PartialAnalysis,
    diagnostic_count: usize,
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    let bounded_counts = [
        ("semantic types", partial.types.len(), limits.types),
        (
            "monomorphizations",
            partial.functions.len(),
            limits.monomorphizations,
        ),
        ("semantic values", partial.values.len(), limits.values),
        (
            "expression facts",
            partial.expressions.len(),
            limits.expression_facts,
        ),
        (
            "statement facts",
            partial.statements.len(),
            limits.statement_facts,
        ),
        (
            "scope protocols",
            partial.scope_protocols.len(),
            limits.scope_protocols,
        ),
        (
            "scope activations",
            partial.scope_activations.len(),
            limits.scope_activations,
        ),
        ("proofs", partial.proofs.len(), limits.proofs),
        (
            "baked artifacts",
            partial.baked_artifacts.len(),
            limits.baked_artifacts,
        ),
        ("diagnostics", diagnostic_count, limits.diagnostic_count),
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
    let image_nodes = partial.graph.as_ref().map_or(Some(0usize), |graph| {
        graph
            .actors
            .len()
            .checked_add(graph.tasks.len())?
            .checked_add(graph.devices.len())?
            .checked_add(graph.pools.len())?
            .checked_add(graph.regions.len())?
            .checked_add(graph.brands.len())
    });
    if image_nodes.is_none_or(|count| count > limits.image_nodes as usize) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "image nodes",
            limit: u64::from(limits.image_nodes),
        });
    }
    Ok(())
}

fn validate_analysis_request(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    diagnostics: &[Diagnostic],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    check_analysis_cancelled(is_cancelled)?;
    request.limits.validate()?;
    request
        .build
        .validate()
        .map_err(|error| AnalysisFailure::InvalidBuild(error.to_string()))?;
    let hir = HirSummary::from_validated(request.hir.as_ref())?;
    if !valid_standard_library_selection(request.hir.as_ref(), request.standard_library_package) {
        return Err(AnalysisFailure::RequestMismatch);
    }
    validate_analysis_top_level_counts(partial, diagnostics.len(), request.limits)?;
    check_analysis_cancelled(is_cancelled)?;
    let root_matches = match &request.mode {
        AnalysisMode::Image { name, entry } => {
            if name.trim().is_empty()
                || partial.compiled_test_group.is_some()
                || !valid_image_constructor(request.hir.as_ref(), *entry)
                || !image_constructor_returns_standard_image(
                    request.hir.as_ref(),
                    *entry,
                    request.standard_library_package,
                )
            {
                return Err(AnalysisFailure::RequestMismatch);
            }
            matches!(
                &partial.root,
                AnalysisRoot::DeclaredImage {
                    image_name,
                    declaration,
                    test_group: None,
                } if image_name == name && declaration == entry
            )
        }
        AnalysisMode::DiscoverTests {
            image_name,
            image_entry,
            declared_image_tests,
            source_selection,
        } => {
            if image_name.trim().is_empty()
                || partial.compiled_test_group.is_some()
                || !valid_image_constructor(request.hir.as_ref(), *image_entry)
                || !image_constructor_returns_standard_image(
                    request.hir.as_ref(),
                    *image_entry,
                    request.standard_library_package,
                )
                || !valid_declared_test_inputs(declared_image_tests)
                || matches!(
                    source_selection,
                    TestDiscoverySelection::NameContains(filter)
                        if filter.trim().is_empty()
                            || filter.trim() != *filter
                            || filter.len() as u64 > request.limits.test_bytes
                )
            {
                return Err(AnalysisFailure::RequestMismatch);
            }
            if let Some(plan) = &partial.test_plan {
                if !test_plan_matches_declarations(plan, declared_image_tests) {
                    return Err(AnalysisFailure::RequestMismatch);
                }
            }
            matches!(
                &partial.root,
                AnalysisRoot::DeclaredImage {
                    image_name: actual_name,
                    declaration,
                    test_group: None,
                } if actual_name == image_name && declaration == image_entry
            )
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
            if partial.compiled_test_group.as_ref() != Some(group_record) {
                return Err(AnalysisFailure::RequestMismatch);
            }
            match (&group_record.root, declared_entry) {
                (TestImageRoot::GeneratedHarness { harness_name }, None) => {
                    matches!(
                        &partial.root,
                        AnalysisRoot::GeneratedTestHarness {
                            group: actual_group,
                            harness_name: actual_name,
                        } if actual_group == group && actual_name == harness_name
                    )
                }
                (TestImageRoot::Declared { image_name, .. }, Some(declaration))
                    if valid_image_constructor(request.hir.as_ref(), *declaration)
                        && image_constructor_returns_standard_image(
                            request.hir.as_ref(),
                            *declaration,
                            request.standard_library_package,
                        ) =>
                {
                    matches!(
                        &partial.root,
                        AnalysisRoot::DeclaredImage {
                            image_name: actual_name,
                            declaration: actual_declaration,
                            test_group: Some(actual_group),
                        } if actual_name == image_name
                            && actual_declaration == declaration
                            && actual_group == group
                    )
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
        || partial.types.iter().any(|ty| {
            matches!(
                ty.kind,
                SemanticTypeKind::Integer {
                    bits,
                    pointer_sized: true,
                    ..
                } if bits != u16::from(request.target.pointer_width())
            )
        })
        || !root_matches
        || partial.functions.iter().any(|function| {
            !function_origin_matches_hir(
                request.hir.as_ref(),
                request.standard_library_package,
                function,
                partial,
            )
        })
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
        AnalysisIntent::Build
            if partial.test_plan.is_some()
                || !partial.comptime_test_results.is_empty()
                || partial.compiled_test_group.is_some() =>
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        AnalysisIntent::TestDiscovery
            if partial.compiled_test_group.is_some()
                || (!has_error && partial.test_plan.is_none()) =>
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        AnalysisIntent::TestExecution
            if partial.test_plan.is_some()
                || !partial.comptime_test_results.is_empty()
                || (!has_error && partial.compiled_test_group.is_none()) =>
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        AnalysisIntent::Build | AnalysisIntent::TestDiscovery | AnalysisIntent::TestExecution => {}
    }
    if !has_error && !successful_mode_matches_functions(&request.mode, partial) {
        return Err(AnalysisFailure::RequestMismatch);
    }
    check_analysis_cancelled(is_cancelled)?;
    validate_fact_resources(partial, request.limits, is_cancelled)?;
    let mut proof_edges = 0u64;
    for proof in &partial.proofs {
        check_analysis_cancelled(is_cancelled)?;
        proof_edges = proof_edges
            .checked_add(u64::try_from(proof.depends_on.len()).map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "proof edges",
                    limit: request.limits.proof_edges,
                }
            })?)
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "proof edges",
                limit: request.limits.proof_edges,
            })?;
        if proof_edges > request.limits.proof_edges {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "proof edges",
                limit: request.limits.proof_edges,
            });
        }
    }
    let mut artifact_bytes = 0u64;
    for artifact in &partial.baked_artifacts {
        check_analysis_cancelled(is_cancelled)?;
        artifact_bytes = artifact_bytes
            .checked_add(u64::try_from(artifact.bytes.len()).map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "baked artifact bytes",
                    limit: request.limits.baked_artifact_bytes,
                }
            })?)
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "baked artifact bytes",
                limit: request.limits.baked_artifact_bytes,
            })?;
        if artifact_bytes > request.limits.baked_artifact_bytes {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "baked artifact bytes",
                limit: request.limits.baked_artifact_bytes,
            });
        }
    }
    let test_count = partial.test_plan.as_ref().map_or_else(
        || {
            partial
                .compiled_test_group
                .as_ref()
                .map_or(0, |group| group.tests.len())
        },
        |plan| {
            let plan = plan.as_plan();
            plan.unit_tests.len()
                + plan
                    .image_groups
                    .iter()
                    .map(|group| group.tests.len())
                    .sum::<usize>()
        },
    );
    let test_groups = partial.test_plan.as_ref().map_or_else(
        || usize::from(partial.compiled_test_group.is_some()),
        |plan| plan.image_groups().len(),
    );
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
        .map_or_else(
            || {
                partial
                    .compiled_test_group
                    .as_ref()
                    .map_or(Some(0), compiled_test_group_payload_bytes)
            },
            |plan| Some(plan.payload_bytes()),
        )
        .and_then(|initial| test_result_payload_bytes(&partial.comptime_test_results, initial));
    let test_group_limits_hold = partial.test_plan.as_ref().map_or_else(
        || {
            partial.compiled_test_group.as_ref().is_none_or(|group| {
                group.maximum_events <= request.limits.test_events_per_group
                    && group.maximum_output_bytes <= request.limits.test_output_bytes_per_group
                    && match &group.root {
                        TestImageRoot::GeneratedHarness { .. } => {
                            group.execution_timeout_ns(None).is_some_and(|timeout| {
                                timeout <= request.limits.test_timeout_ns_per_group
                            })
                        }
                        TestImageRoot::Declared { .. } => {
                            group.tests[0].descriptor.timeout_ns
                                <= request.limits.test_timeout_ns_per_group
                        }
                    }
            })
        },
        |plan| {
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
                        && group.execution_timeout_ns(scenario).is_some_and(|timeout| {
                            timeout <= request.limits.test_timeout_ns_per_group
                        })
                })
        },
    );
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
    let mut diagnostic_bytes = 0u64;
    for diagnostic in diagnostics {
        check_analysis_cancelled(is_cancelled)?;
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
    check_analysis_cancelled(is_cancelled)?;
    Ok(())
}

fn valid_image_constructor(hir: &ValidatedProgram, id: DeclarationId) -> bool {
    let program = hir.as_program();
    let Some(declaration) = program.declaration(id) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Function(function) = &declaration.kind else {
        return false;
    };
    declaration.visibility == wrela_hir::Visibility::Public
        && declaration.name.is_some()
        && matches!(
            declaration.owner,
            wrela_hir::DeclarationOwner::Module(module) if module == declaration.module
        )
        && function.color == FunctionColor::Sync
        && function.generics.is_empty()
        && function.parameters.is_empty()
        && function.body.is_some()
        && function
            .result
            .as_ref()
            .is_some_and(|result| !matches!(result.kind, wrela_hir::TypeExpressionKind::Error))
        && declaration
            .attributes
            .iter()
            .filter(|attribute| {
                matches!(
                    attribute.identity,
                    wrela_hir::AttributeIdentity::Builtin(wrela_hir::BuiltinAttribute::Image)
                )
            })
            .count()
            == 1
        && program.image_candidates.binary_search(&id).is_ok()
}

fn image_constructor_returns_standard_image(
    hir: &ValidatedProgram,
    id: DeclarationId,
    standard_library: PackageId,
) -> bool {
    let program = hir.as_program();
    let Some(DeclarationKind::Function(function)) =
        program.declaration(id).map(|declaration| &declaration.kind)
    else {
        return false;
    };
    let Some(TypeExpression {
        kind:
            TypeExpressionKind::Named {
                definition: Definition::Declaration(resolved),
                arguments,
            },
        ..
    }) = function.result.as_ref()
    else {
        return false;
    };
    arguments.is_empty()
        && resolved.package == standard_library
        && program
            .declaration(resolved.declaration)
            .and_then(|declaration| declaration.name.as_ref())
            .is_some_and(|name| name.as_str() == "Image")
}

fn valid_standard_library_selection(hir: &ValidatedProgram, standard_library: PackageId) -> bool {
    let graph = &hir.as_program().packages;
    graph.package(standard_library).is_some()
        && graph.package(graph.root()).is_some_and(|root| {
            root.dependencies.iter().any(|dependency| {
                dependency.alias.as_str() == "core" && dependency.package == standard_library
            })
        })
}

fn function_origin_matches_hir(
    hir: &ValidatedProgram,
    standard_library_package: PackageId,
    function: &FunctionInstance,
    analysis: &PartialAnalysis,
) -> bool {
    let program = hir.as_program();
    match function.origin {
        FunctionOrigin::Source { declaration, body } => {
            let Some(declaration) = program.declaration(declaration) else {
                return false;
            };
            if function.source != Some(declaration.source) {
                return false;
            }
            match &declaration.kind {
                wrela_hir::DeclarationKind::Function(source) => {
                    source.body == Some(body)
                        && source.color == function.color
                        && semantic_parameters_match_hir(
                            program,
                            &source.parameters,
                            function,
                            analysis,
                        )
                }
                wrela_hir::DeclarationKind::Initializer(_) => false,
                wrela_hir::DeclarationKind::Projection(source) => {
                    source.body == Some(body)
                        && function.color == FunctionColor::Sync
                        && function.role == FunctionRole::Ordinary
                        && semantic_parameters_match_hir(
                            program,
                            &source.parameters,
                            function,
                            analysis,
                        )
                }
                wrela_hir::DeclarationKind::Scope(source) => {
                    (source.setup == body || source.abort == Some(body) || source.exit == body)
                        && function.color == FunctionColor::Sync
                        && function.role == FunctionRole::Cleanup
                }
                wrela_hir::DeclarationKind::Constant(_)
                | wrela_hir::DeclarationKind::Brand
                | wrela_hir::DeclarationKind::Structure(_)
                | wrela_hir::DeclarationKind::Enumeration(_)
                | wrela_hir::DeclarationKind::Interface(_)
                | wrela_hir::DeclarationKind::Implementation(_)
                | wrela_hir::DeclarationKind::ComptimeSelection(_)
                | wrela_hir::DeclarationKind::Error => false,
            }
        }
        FunctionOrigin::SourceClosure { expression } => {
            let Some(source) = program.expression(expression) else {
                return false;
            };
            let wrela_hir::ExpressionKind::Closure {
                color, parameters, ..
            } = &source.kind
            else {
                return false;
            };
            function.source == Some(source.source)
                && *color == function.color
                && function.role == FunctionRole::Ordinary
                && semantic_parameters_match_hir(program, parameters, function, analysis)
        }
        FunctionOrigin::GeneratedImageEntry { constructor } => {
            valid_image_constructor(hir, constructor)
                && image_constructor_returns_standard_image(
                    hir,
                    constructor,
                    standard_library_package,
                )
                && function.source.is_none()
                && function.color == FunctionColor::Sync
                && function.role == FunctionRole::ImageEntry
                && function.parameters.is_empty()
                && analysis
                    .types
                    .get(function.result.0 as usize)
                    .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Unit))
        }
        FunctionOrigin::GeneratedTestHarness { .. } => {
            function.source.is_none()
                && function.color == FunctionColor::Sync
                && function.role == FunctionRole::ImageEntry
                && function.parameters.is_empty()
                && analysis
                    .types
                    .get(function.result.0 as usize)
                    .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Unit))
        }
    }
}

fn semantic_parameters_match_hir(
    program: &wrela_hir::Program,
    source_parameters: &[wrela_hir::ParameterId],
    function: &FunctionInstance,
    analysis: &PartialAnalysis,
) -> bool {
    source_parameters.len() == function.parameters.len()
        && source_parameters
            .iter()
            .zip(&function.parameters)
            .all(|(source_id, semantic)| {
                let Some(source) = program.parameter(*source_id) else {
                    return false;
                };
                let Some(value) = analysis.values.get(semantic.value.0 as usize) else {
                    return false;
                };
                let expected_name = source.name.as_ref().map_or("self", wrela_hir::Name::as_str);
                semantic_access_matches_hir(semantic.access, source.access)
                    && value.source == Some(source.source)
                    && value.source_name.as_deref() == Some(expected_name)
            })
}

fn semantic_access_matches_hir(semantic: AccessMode, source: wrela_hir::AccessMode) -> bool {
    matches!(
        (semantic, source),
        (AccessMode::Value, wrela_hir::AccessMode::Value)
            | (AccessMode::Read, wrela_hir::AccessMode::Read)
            | (AccessMode::Mutate, wrela_hir::AccessMode::Mutate)
            | (AccessMode::Take, wrela_hir::AccessMode::Take)
    )
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

    fn enforce(&self, limits: AnalysisLimits) -> Result<(), AnalysisFailure> {
        if self.overflowed || self.edges > limits.fact_edges || self.bytes > limits.fact_bytes {
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic fact edges or payload bytes",
                limit: limits.fact_bytes,
            })
        } else {
            Ok(())
        }
    }
}

fn validate_fact_resources(
    partial: &PartialAnalysis,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    check_analysis_cancelled(is_cancelled)?;
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
    meter.enforce(limits)?;
    match &partial.root {
        AnalysisRoot::DeclaredImage { image_name, .. } => meter.text(image_name),
        AnalysisRoot::GeneratedTestHarness { harness_name, .. } => meter.text(harness_name),
    }

    let mut constants: Vec<(&ConstantValue, u32)> = Vec::new();
    for ty in &partial.types {
        check_analysis_cancelled(is_cancelled)?;
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
                meter.enforce(limits)?;
                for item in arguments {
                    check_analysis_cancelled(is_cancelled)?;
                    queue_constant_argument(item, &mut constants, limits)?;
                }
                for field in fields {
                    check_analysis_cancelled(is_cancelled)?;
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
                meter.enforce(limits)?;
                for item in arguments {
                    check_analysis_cancelled(is_cancelled)?;
                    queue_constant_argument(item, &mut constants, limits)?;
                }
                for variant in variants {
                    check_analysis_cancelled(is_cancelled)?;
                    meter.text(&variant.name);
                    meter.edges(&variant.fields);
                    meter.enforce(limits)?;
                    for field in &variant.fields {
                        check_analysis_cancelled(is_cancelled)?;
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
            | SemanticTypeKind::Reservation
            | SemanticTypeKind::Receipt { .. }
            | SemanticTypeKind::Dma { .. }
            | SemanticTypeKind::Mmio { .. }
            | SemanticTypeKind::Validated { .. } => {}
        }
        meter.enforce(limits)?;
    }
    if let Some(group) = &partial.compiled_test_group {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&group.name);
        meter.edges(&group.tests);
        match &group.root {
            TestImageRoot::GeneratedHarness { harness_name } => meter.text(harness_name),
            TestImageRoot::Declared { image_name, .. } => meter.text(image_name),
        }
        for test in &group.tests {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&test.descriptor.name);
            meter.edges(&test.assertions);
            for assertion in &test.assertions {
                check_analysis_cancelled(is_cancelled)?;
                meter.text(&assertion.expression);
                if let Some(message) = &assertion.message {
                    meter.text(message);
                }
            }
        }
        meter.enforce(limits)?;
    }
    for function in &partial.functions {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&function.name);
        meter.edges(&function.generic_arguments);
        meter.edges(&function.parameters);
        meter.edges(&function.proofs);
        meter.enforce(limits)?;
        for item in &function.generic_arguments {
            check_analysis_cancelled(is_cancelled)?;
            queue_constant_argument(item, &mut constants, limits)?;
        }
    }
    for value in &partial.values {
        check_analysis_cancelled(is_cancelled)?;
        if let Some(name) = &value.source_name {
            meter.text(name);
        }
        meter.enforce(limits)?;
    }
    for fact in &partial.expressions {
        check_analysis_cancelled(is_cancelled)?;
        meter.edges(&fact.proofs);
        match &fact.resolution {
            ExpressionResolution::Constant(value) => {
                push_fact_constant(&mut constants, (value, 1), limits)?;
            }
            ExpressionResolution::DirectCall { arguments, .. }
            | ExpressionResolution::OperatorCall { arguments, .. } => meter.edges(arguments),
            ExpressionResolution::Closure { captures, .. } => meter.edges(captures),
            ExpressionResolution::Error
            | ExpressionResolution::Value(_)
            | ExpressionResolution::Function(_)
            | ExpressionResolution::Constructor { .. }
            | ExpressionResolution::ResultTry { .. }
            | ExpressionResolution::ActorRequest { .. }
            | ExpressionResolution::Field { .. }
            | ExpressionResolution::Index { .. }
            | ExpressionResolution::Builtin(_) => {}
        }
        meter.enforce(limits)?;
    }
    for fact in &partial.statements {
        check_analysis_cancelled(is_cancelled)?;
        meter.edges(&fact.definitions);
        meter.edges(&fact.initialized_after);
        meter.edges(&fact.moved_after);
        meter.edges(&fact.live_loans_after);
        meter.edges(&fact.proofs);
        meter.enforce(limits)?;
    }
    for protocol in &partial.scope_protocols {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&protocol.name);
        meter.edges(&protocol.parameters);
        meter.enforce(limits)?;
    }
    for activation in &partial.scope_activations {
        check_analysis_cancelled(is_cancelled)?;
        meter.edges(&activation.cleanup_dependencies);
        meter.enforce(limits)?;
    }
    if let Some(graph) = &partial.graph {
        check_analysis_cancelled(is_cancelled)?;
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
        meter.enforce(limits)?;
        for actor in &graph.actors {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&actor.name);
            meter.edges(&actor.message_types);
            meter.edges(&actor.turn_functions);
            meter.enforce(limits)?;
        }
        for task in &graph.tasks {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&task.name);
            meter.enforce(limits)?;
        }
        for device in &graph.devices {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&device.name);
            meter.text(&device.target_binding);
            meter.edges(&device.required_features);
            meter.edges(&device.optional_features);
            meter.edges(&device.interrupt_functions);
            meter.enforce(limits)?;
            for feature in device
                .required_features
                .iter()
                .chain(&device.optional_features)
            {
                check_analysis_cancelled(is_cancelled)?;
                meter.text(feature);
            }
        }
        for pool in &graph.pools {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&pool.name);
            meter.edges(&pool.reachable_devices);
            meter.enforce(limits)?;
        }
        for region in &graph.regions {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(&region.name);
            meter.enforce(limits)?;
        }
    }
    for proof in &partial.proofs {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        meter.enforce(limits)?;
        for line in &proof.explanation {
            check_analysis_cancelled(is_cancelled)?;
            meter.text(line);
        }
    }
    for artifact in &partial.baked_artifacts {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&artifact.name);
        meter.text(&artifact.media_type);
        meter.enforce(limits)?;
    }
    while let Some((constant, depth)) = constants.pop() {
        check_analysis_cancelled(is_cancelled)?;
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
                meter.enforce(limits)?;
                let Some(next) = depth.checked_add(1) else {
                    meter.overflowed = true;
                    continue;
                };
                try_reserve_fact_constants(&mut constants, values.len(), limits)?;
                for value in values {
                    check_analysis_cancelled(is_cancelled)?;
                    constants.push((value, next));
                }
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
        meter.enforce(limits)?;
    }
    check_analysis_cancelled(is_cancelled)?;
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
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    if let SemanticArgument::Constant(value) = argument {
        push_fact_constant(constants, (value, 1), limits)?;
    }
    Ok(())
}

fn push_fact_constant<'a>(
    constants: &mut Vec<(&'a ConstantValue, u32)>,
    value: (&'a ConstantValue, u32),
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    try_reserve_fact_constants(constants, 1, limits)?;
    constants.push(value);
    Ok(())
}

fn try_reserve_fact_constants(
    constants: &mut Vec<(&ConstantValue, u32)>,
    additional: usize,
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    let required = constants
        .len()
        .checked_add(additional)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "semantic constant validation stack",
            limit: limits.fact_edges,
        })?;
    if required > limits.fact_edges {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic constant validation stack",
            limit: limits.fact_edges,
        });
    }
    constants
        .try_reserve(additional)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic constant validation stack",
            limit: limits.fact_edges,
        })
}

fn graph_matches_target(graph: &ImageGraph, target: &TargetSemanticContract) -> bool {
    let mut claimed = std::collections::HashSet::new();
    if claimed.try_reserve(graph.devices.len()).is_err() {
        return false;
    }
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
            | wrela_test_model::TestOutcome::TimedOut { .. }
            | wrela_test_model::TestOutcome::LanguageFatal { .. } => 0,
        };
        total
            .checked_add(u64::try_from(result.descriptor.name.len()).ok()?)?
            .checked_add(u64::try_from(message).ok()?)
    })
}

fn compiled_test_group_payload_bytes(group: &FullImageTestGroup) -> Option<u64> {
    let root = match &group.root {
        TestImageRoot::GeneratedHarness { harness_name } => harness_name.len(),
        TestImageRoot::Declared { image_name, .. } => image_name.len(),
    };
    group.tests.iter().try_fold(
        u64::try_from(group.name.len().checked_add(root)?).ok()?,
        |total, test| {
            test.assertions.iter().try_fold(
                total.checked_add(u64::try_from(test.descriptor.name.len()).ok()?)?,
                |total, assertion| {
                    total
                        .checked_add(u64::try_from(assertion.expression.len()).ok()?)?
                        .checked_add(
                            u64::try_from(assertion.message.as_ref().map_or(0, String::len))
                                .ok()?,
                        )
                },
            )
        },
    )
}

fn successful_mode_matches_functions(mode: &AnalysisMode<'_>, partial: &PartialAnalysis) -> bool {
    let mut actual_tests = std::collections::HashSet::new();
    let mut generated_image_entries = Vec::new();
    let mut generated_test_harnesses = Vec::new();
    for function in &partial.functions {
        if function.role == FunctionRole::Test
            && (actual_tests.try_reserve(1).is_err() || !actual_tests.insert(function.key))
        {
            return false;
        }
        match function.origin {
            FunctionOrigin::GeneratedImageEntry { constructor } => {
                if generated_image_entries.try_reserve(1).is_err() {
                    return false;
                }
                generated_image_entries.push((function.id, constructor));
            }
            FunctionOrigin::GeneratedTestHarness { group } => {
                if generated_test_harnesses.try_reserve(1).is_err() {
                    return false;
                }
                generated_test_harnesses.push((function.id, group));
            }
            FunctionOrigin::Source { .. } | FunctionOrigin::SourceClosure { .. } => {}
        }
    }
    match mode {
        AnalysisMode::Image { entry, .. } => {
            actual_tests.is_empty()
                && generated_test_harnesses.is_empty()
                && generated_image_entries
                    == vec![(
                        partial
                            .graph
                            .as_ref()
                            .map_or(FunctionInstanceId(u32::MAX), |graph| graph.entry),
                        *entry,
                    )]
        }
        AnalysisMode::DiscoverTests { .. } => {
            let Some(plan) = partial.test_plan.as_ref().map(ValidatedTestPlan::as_plan) else {
                return false;
            };
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
            let mut planned = std::collections::HashSet::new();
            if planned.try_reserve(plan.unit_tests.len()).is_err() {
                return false;
            }
            for key in planned_keys {
                if planned.try_reserve(1).is_err() || !planned.insert(key) {
                    return false;
                }
            }
            let constructor = match partial.root {
                AnalysisRoot::DeclaredImage { declaration, .. } => declaration,
                AnalysisRoot::GeneratedTestHarness { .. } => return false,
            };
            actual_tests == planned
                && generated_test_harnesses.is_empty()
                && generated_image_entries
                    == vec![(
                        partial
                            .graph
                            .as_ref()
                            .map_or(FunctionInstanceId(u32::MAX), |graph| graph.entry),
                        constructor,
                    )]
        }
        AnalysisMode::CompileTestGroup { plan, group, .. } => {
            let Some(group_record) = plan.group(*group) else {
                return false;
            };
            match group_record.root {
                TestImageRoot::GeneratedHarness { .. } => {
                    let mut planned = std::collections::HashSet::new();
                    if planned.try_reserve(group_record.tests.len()).is_err() {
                        return false;
                    }
                    for key in group_record
                        .tests
                        .iter()
                        .filter_map(|test| match test.invocation {
                            wrela_test_model::ImageTestInvocation::GeneratedFunction {
                                function_key,
                            } => Some(function_key),
                            wrela_test_model::ImageTestInvocation::DeclaredScenario => None,
                        })
                    {
                        if !planned.insert(key) {
                            return false;
                        }
                    }
                    actual_tests == planned
                        && generated_image_entries.is_empty()
                        && generated_test_harnesses
                            == vec![(
                                partial
                                    .graph
                                    .as_ref()
                                    .map_or(FunctionInstanceId(u32::MAX), |graph| graph.entry),
                                *group,
                            )]
                }
                TestImageRoot::Declared { .. } => {
                    let constructor = match partial.root {
                        AnalysisRoot::DeclaredImage { declaration, .. } => declaration,
                        AnalysisRoot::GeneratedTestHarness { .. } => return false,
                    };
                    actual_tests.is_empty()
                        && generated_test_harnesses.is_empty()
                        && generated_image_entries
                            == vec![(
                                partial
                                    .graph
                                    .as_ref()
                                    .map_or(FunctionInstanceId(u32::MAX), |graph| graph.entry),
                                constructor,
                            )]
                }
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
    InvalidReuseLimits,
    UnsupportedReuseVersion { observed: u32 },
    UnsupportedReuseShape(&'static str),
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
            Self::InvalidReuseLimits => {
                formatter.write_str("semantic reuse comparison limits must be nonzero")
            }
            Self::UnsupportedReuseVersion { observed } => write!(
                formatter,
                "semantic reuse contract version {observed} is unsupported"
            ),
            Self::UnsupportedReuseShape(reason) => {
                write!(formatter, "semantic reuse shape is unsupported: {reason}")
            }
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
