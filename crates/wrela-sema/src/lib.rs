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
    BodyId, DeclarationId, DeclarationKind, Definition, ExpressionId, FunctionColor, LocalId,
    StatementId, TypeExpression, TypeExpressionKind, ValidatedProgram,
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
id_type!(AllocationId);
id_type!(ProjectionProtocolId);
id_type!(LexicalViewId);
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
    pub projection_protocols: u32,
    pub lexical_views: u32,
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
            projection_protocols: 4_000_000,
            lexical_views: 64_000_000,
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
            || self.projection_protocols == 0
            || self.lexical_views == 0
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
    /// Analysis-only owned destination for one exactly bounded interpolation.
    /// `capacity` includes decoded literal UTF-8 bytes and the maximum encoded
    /// width of every admitted formatted value.
    BoundedString {
        capacity: u64,
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
    /// Storage/consumption class of this typed value. Producer-dependent
    /// carriers live here rather than on the nominal type record: a lexical
    /// view intentionally shares its target `SemanticTypeId` while remaining
    /// second-class.
    pub class: SemanticValueClass,
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
    /// The old value loaded by one authenticated compound actor-state write.
    ActorStateLoad(StatementId),
    /// The checked arithmetic result stored by one authenticated compound
    /// actor-state write.
    ActorStateCompoundResult(StatementId),
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
pub enum SemanticValueClass {
    FirstClass,
    Ephemeral(EphemeralKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralKind {
    View,
    ProjectionCarrier,
    AdmissionResult,
    AsyncOutcome,
    OwnershipConditionedActorCallOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralUse {
    DirectBinding,
    PatternMatch,
    TypeTest,
    Question,
    ImmediateRead,
}

impl EphemeralKind {
    #[must_use]
    pub const fn permits(self, usage: EphemeralUse) -> bool {
        match usage {
            EphemeralUse::DirectBinding | EphemeralUse::PatternMatch | EphemeralUse::TypeTest => {
                true
            }
            EphemeralUse::Question => matches!(
                self,
                Self::ProjectionCarrier | Self::OwnershipConditionedActorCallOutcome
            ),
            EphemeralUse::ImmediateRead => matches!(self, Self::View),
        }
    }
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
    /// A source `scope` declaration is callable only as the acquisition of a
    /// `with` statement. It is deliberately not represented by a synthetic
    /// [`FunctionInstance`]: scope phases have their own protocol contract.
    Scope(ScopeProtocolId),
    /// A source `projection` declaration. Projections are callable only to
    /// introduce a regionless lexical view; they are not synthetic functions.
    Projection(ProjectionProtocolId),
    Constructor {
        ty: SemanticTypeId,
        variant: Option<u32>,
    },
    /// A structure value produced by one exact, infallible `init` protocol.
    /// The initializer declaration identity is retained so validation and
    /// lowering can replay the source protocol instead of trusting layout
    /// compatibility or treating the call as direct field construction.
    InitializerConstruction {
        ty: SemanticTypeId,
        initializer: DeclarationId,
    },
    ResultTry {
        result_type: SemanticTypeId,
        ok_variant: u32,
        err_variant: u32,
        ok_payload: ValueId,
        err_payload: ValueId,
        propagated: ValueId,
    },
    /// Postfix `?` over the exact core `Option[S]` scalar specialization.
    /// `Some` yields `some_payload`; `None` reconstructs `propagated` and
    /// returns it from the enclosing function.
    OptionTry {
        option_type: SemanticTypeId,
        some_variant: u32,
        none_variant: u32,
        some_payload: ValueId,
        propagated: ValueId,
    },
    /// Analysis-only closed iterator. `ExpressionFact::ty` is the yielded
    /// integer type rather than a first-class range value type; ranges are
    /// consumable only by the enclosing `for` statement in this slice.
    ClosedRange {
        start: ValueId,
        end: ValueId,
        inclusive: bool,
        maximum_iterations: u64,
    },
    /// Analysis-only fixed-array witness. The HIR array literal is retained as
    /// an exact source-ordered element-value sequence and is consumable only by
    /// its enclosing `for` or bounded fixed-array `match` statement.
    ClosedArray {
        elements: Vec<ValueId>,
        maximum_iterations: u64,
        bounds: ProofId,
        /// Absent for an inline consumer. Present only for the bounded stored
        /// form: one immutable local initialized by this expression and one
        /// later direct `for` reference in the same synchronous body.
        storage: Option<ClosedArrayStorage>,
    },
    DirectCall {
        function: FunctionInstanceId,
        /// Exact source-to-parameter permutation. Records are canonical by
        /// `parameter_index`; `source_index` indexes the HIR call arguments.
        arguments: Vec<ResolvedCallArgument>,
    },
    /// A concrete, non-generic method selected from a named local or
    /// parameter receiver. The receiver is implicit in source argument
    /// syntax and therefore has its own exact identity/access fields;
    /// `arguments` contains only the explicitly written arguments and is
    /// canonical by the target parameter index after the receiver.
    MethodCall {
        function: FunctionInstanceId,
        receiver: ValueId,
        receiver_access: AccessMode,
        arguments: Vec<ResolvedCallArgument>,
    },
    ScopeCall {
        protocol: ScopeProtocolId,
        /// Exact source-to-scope-parameter permutation, canonical by
        /// `parameter_index` just like an ordinary direct call.
        arguments: Vec<ResolvedCallArgument>,
    },
    /// One call to a projection protocol and the exact lexical view it
    /// introduces. `arguments` remains canonical by `parameter_index`.
    ProjectionCall {
        protocol: ProjectionProtocolId,
        arguments: Vec<ResolvedCallArgument>,
        view: LexicalViewId,
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
    /// Compiler-derived structural equality for a nonempty flat stored-copy-
    /// scalar structure. Fields and fold results are canonical in declaration
    /// order and every generated value is authenticated by the full seal.
    DerivedEquality {
        aggregate: SemanticTypeId,
        left: ValueId,
        right: ValueId,
        fields: Vec<DerivedEqualityField>,
        conjunctions: Vec<ValueId>,
    },
    /// Compiler-derived `Destination.from(value)` for the exact
    /// single-variant, single-positional-field enum profile. The destination
    /// type, variant tag, and evaluated payload identity are retained so the
    /// full seal can re-derive the clause and nominal source declaration.
    DerivedFrom {
        enumeration: SemanticTypeId,
        variant: u32,
        payload: ValueId,
    },
    /// Exact destination-type witness in the associated derived conversion
    /// spelling. This is not a first-class runtime type value.
    DerivedFromType {
        enumeration: SemanticTypeId,
    },
    /// Exact generated associated conversion member witness.
    DerivedFromFunction {
        enumeration: SemanticTypeId,
        variant: u32,
    },
    /// Exact source-order witness for an analysis-only bounded interpolation.
    BoundedInterpolation {
        capacity: u64,
        parts: Vec<BoundedInterpolationPart>,
    },
    /// One exact closed-enum tag test. The scrutinee remains a borrowed value;
    /// the expression result is the separately recorded boolean value.
    EnumTypeTest {
        enumeration: SemanticTypeId,
        variant: u32,
        scrutinee: ValueId,
    },
    ActorRequest {
        actor: ActorId,
        method: FunctionInstanceId,
        permit: ProofId,
        /// Exact single-flight reply authority for an awaited typed request.
        /// One-way sends carry `None` and retain the strict-linear reservation
        /// result; the bounded reply slice carries `Some` and produces the
        /// method's scalar result directly.
        reply: Option<ProofId>,
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
pub struct ClosedArrayStorage {
    pub local: LocalId,
    pub value: ValueId,
    pub iterable: ExpressionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedEqualityField {
    pub field: u32,
    pub left: ValueId,
    pub right: ValueId,
    pub comparison: ValueId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedInterpolationPart {
    Text {
        value: String,
        source: Span,
    },
    Integer {
        expression: ExpressionId,
        value: ValueId,
        ty: SemanticTypeId,
        maximum_bytes: u64,
    },
    /// An exact immutable UTF-8 value. `ty` retains its compiler-minted
    /// `StaticString { bytes }` extent so the seal can authenticate the
    /// formatted bound without trusting this witness.
    StaticString {
        expression: ExpressionId,
        value: ValueId,
        ty: SemanticTypeId,
    },
    Character {
        expression: ExpressionId,
        value: ValueId,
    },
    Bool {
        expression: ExpressionId,
        value: ValueId,
    },
}

fn bounded_interpolation_maximum_bytes(kind: &SemanticTypeKind) -> Option<u64> {
    let decimal_digits = |mut value: u128| {
        let mut digits = 1_u64;
        while value >= 10 {
            value /= 10;
            digits = digits.saturating_add(1);
        }
        digits
    };
    match kind {
        SemanticTypeKind::Bool => Some(5),
        SemanticTypeKind::Character => Some(4),
        SemanticTypeKind::StaticString { bytes } => Some(*bytes),
        SemanticTypeKind::Integer { signed, bits, .. } if (1..=128).contains(bits) => {
            let magnitude = if *signed {
                1_u128 << u32::from(bits - 1)
            } else if *bits == 128 {
                u128::MAX
            } else {
                (1_u128 << u32::from(*bits)) - 1
            };
            Some(decimal_digits(magnitude) + u64::from(*signed))
        }
        _ => None,
    }
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
    /// Regionless projection views live immediately after this statement.
    /// IDs are strictly increasing and every record belongs to `function`.
    pub live_lexical_views_after: Vec<LexicalViewId>,
    pub proofs: Vec<ProofId>,
}

/// One authenticated access to the canonical actor-owned state cell.  Actor
/// instances remain erased language values: this record binds the source
/// receiver and declared field to the independently planned image region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorStateAccess {
    pub function: FunctionInstanceId,
    pub actor: ActorId,
    pub receiver: wrela_hir::ParameterId,
    pub class: DeclarationId,
    pub field: u32,
    pub region: RegionId,
    pub capacity: ProofId,
    pub source: Span,
    pub kind: ActorStateAccessKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorStateAccessKind {
    Read {
        expression: ExpressionId,
        result: ValueId,
    },
    Write {
        statement: StatementId,
        value_expression: ExpressionId,
        value: ValueId,
    },
    CompoundAssign {
        statement: StatementId,
        operator: wrela_hir::AssignmentOperator,
        value_expression: ExpressionId,
        value: ValueId,
        current: ValueId,
        result: ValueId,
    },
}

/// One runtime value whose required lifetime has been classified by the
/// whole-image escape analysis. IDs are dense in deterministic source order;
/// `name` is the stable suffix used by public analysis reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionAssignment {
    pub id: AllocationId,
    pub name: String,
    pub function: FunctionInstanceId,
    pub statement: StatementId,
    pub value: ValueId,
    pub region: RegionId,
    pub source: Span,
}

/// Authenticated widening of one allocation from a turn-local region into a
/// longer-lived destination region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    pub allocation: AllocationId,
    pub value: ValueId,
    pub source_region: RegionId,
    pub destination: RegionId,
    pub proof: ProofId,
    pub reason: String,
    pub source: Span,
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

/// Analysis-tier contract for one source `projection`. Provenance uses exact
/// HIR parameter identities and is intentionally distinct from allocation
/// [`RegionId`]s: lexical view analysis must not forge a runtime region before
/// the region/escape producer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionProtocol {
    pub id: ProjectionProtocolId,
    pub declaration: DeclarationId,
    pub name: String,
    pub parameters: Vec<ProjectionParameter>,
    pub mutable: bool,
    pub target: SemanticTypeId,
    pub provenance: Vec<wrela_hir::ParameterId>,
    pub body: BodyId,
    pub proof: ProofId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionParameter {
    pub parameter: wrela_hir::ParameterId,
    pub access: AccessMode,
    pub ty: SemanticTypeId,
}

/// One activation of a projection protocol inside a source function. This is
/// deliberately a lexical model: its sources are semantic values, not forged
/// allocation regions or loans. Statement post-states carry the exact liveness
/// snapshots consumed by escape and mutation checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalView {
    pub id: LexicalViewId,
    pub function: FunctionInstanceId,
    pub protocol: ProjectionProtocolId,
    pub expression: ExpressionId,
    pub initialization: StatementId,
    pub binding: wrela_hir::LocalId,
    pub value: ValueId,
    /// Conservative provenance in the protocol's canonical provenance order.
    pub sources: Vec<LexicalViewSource>,
    /// Final local-reference uses on all admitted control-flow paths.
    pub terminal_uses: Vec<ExpressionId>,
    /// Statements after which the activation remains live. This structured
    /// witness is independent of source-span ordering and therefore preserves
    /// branch-local lifetimes exactly.
    pub live_after_statements: Vec<StatementId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LexicalViewSource {
    pub parameter: wrela_hir::ParameterId,
    pub value: ValueId,
    pub access: AccessMode,
    pub argument_source: Span,
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
    pub actor_state_accesses: Vec<ActorStateAccess>,
    pub region_assignments: Vec<RegionAssignment>,
    pub promotions: Vec<Promotion>,
    pub projection_protocols: Vec<ProjectionProtocol>,
    pub lexical_views: Vec<LexicalView>,
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
            || !dense(self.region_assignments.iter().map(|item| item.id.0))
            || !dense(self.projection_protocols.iter().map(|item| item.id.0))
            || !dense(self.lexical_views.iter().map(|item| item.id.0))
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

        if self.region_assignments.iter().any(|assignment| {
            assignment.name.trim().is_empty()
                || assignment.function.0 as usize >= self.functions.len()
                || assignment.statement.0 >= self.hir.statements
                || assignment.value.0 as usize >= self.values.len()
                || assignment.region.0 as usize >= graph.regions.len()
                || !valid_span(assignment.source, self.hir.files)
        }) || !self
            .promotions
            .windows(2)
            .all(|pair| pair[0].allocation < pair[1].allocation)
            || self.promotions.iter().any(|promotion| {
                promotion.allocation.0 as usize >= self.region_assignments.len()
                    || self.region_assignments[promotion.allocation.0 as usize].id
                        != promotion.allocation
                    || promotion.value.0 as usize >= self.values.len()
                    || promotion.source_region.0 as usize >= graph.regions.len()
                    || promotion.destination.0 as usize >= graph.regions.len()
                    || promotion.proof.0 as usize >= self.proofs.len()
                    || promotion.reason.trim().is_empty()
                    || !valid_span(promotion.source, self.hir.files)
            })
        {
            return Err(invalid(
                "partial region inference contains a dangling or invalid reference",
            ));
        }

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
                || !valid_semantic_value_class(value, self)
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
                || (!matches!(fact.resolution, ExpressionResolution::Error)
                    && !valid_expression_region(fact, self, graph))
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

        for protocol in &self.projection_protocols {
            if !valid_projection_protocol_prefix(protocol, self) {
                return Err(invalid(
                    "partial projection protocol contains a dangling or inexact fact",
                ));
            }
        }
        for view in &self.lexical_views {
            if !valid_lexical_view_prefix(view, self) {
                return Err(invalid(
                    "partial lexical view contains a dangling or inexact fact",
                ));
            }
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
            || !dense(self.region_assignments.iter().map(|item| item.id.0))
            || !dense(self.projection_protocols.iter().map(|item| item.id.0))
            || !dense(self.lexical_views.iter().map(|item| item.id.0))
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
            if matches!(ty.kind, SemanticTypeKind::Structure { .. })
                && !exact_flat_structure_type_matches(self, hir.as_program(), ty)
            {
                return Err(invalid(
                    "semantic structure type differs from its exact HIR specialization",
                ));
            }
            if matches!(&ty.kind, SemanticTypeKind::Enumeration { arguments, .. } if !arguments.is_empty())
                && !exact_generic_enum_type_matches(self, hir.as_program(), ty)
                && !exact_core_async_exit_type_matches(self, hir.as_program(), ty)
                && !exact_core_async_result_type_matches(self, hir.as_program(), ty)
            {
                return Err(invalid(
                    "semantic enumeration type differs from its exact HIR specialization",
                ));
            }
        }
        for value in &self.values {
            if value.function.0 as usize >= self.functions.len()
                || value.ty.0 as usize >= self.types.len()
                || !valid_value_origin(value.origin, self.hir)
                || !valid_semantic_value_class(value, self)
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
        for protocol in &self.projection_protocols {
            if !valid_projection_protocol_record(protocol, self, hir.as_program()) {
                return Err(invalid(
                    "projection protocol differs from exact HIR semantics",
                ));
            }
        }
        for view in &self.lexical_views {
            if !valid_lexical_view_record(view, self, hir.as_program(), is_cancelled)? {
                return Err(invalid(
                    "lexical view differs from exact HIR projection semantics",
                ));
            }
        }
        if !lexical_view_accesses_are_disjoint(self, hir.as_program(), is_cancelled)? {
            return Err(invalid(
                "lexical view source accesses overlap exclusive authority",
            ));
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
        if !valid_scope_contracts(self, hir.as_program()) {
            return Err(invalid(
                "scope protocols or activations differ from exact HIR cleanup semantics",
            ));
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
        if !valid_iso_pool_contracts(self, hir.as_program(), graph) {
            return Err(invalid(
                "branded iso pool facts differ from the exact image-builder source",
            ));
        }
        if !valid_static_supervision_contract(self, hir.as_program(), graph, is_cancelled)? {
            return Err(invalid(
                "static supervision topology or proof closure differs from the exact actor image",
            ));
        }
        if !valid_actor_state_contracts(self, hir.as_program(), graph) {
            return Err(invalid(
                "actor state storage differs from its exact HIR declaration",
            ));
        }
        if !valid_actor_state_accesses(self, hir.as_program(), graph) {
            return Err(invalid(
                "actor state accesses differ from their exact HIR receiver, field, region, or capacity proof",
            ));
        }
        if !valid_region_inference(self, hir.as_program(), graph) {
            return Err(invalid(
                "region assignments or promotions differ from exact actor-state escapes",
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
    let mut static_types = std::collections::BTreeSet::new();
    for ty in &analysis.types {
        check_analysis_cancelled(is_cancelled)?;
        let identity = match ty.kind {
            SemanticTypeKind::StaticString { bytes } => Some((0_u8, bytes)),
            SemanticTypeKind::StaticBytes { bytes } => Some((1_u8, bytes)),
            SemanticTypeKind::BoundedString { capacity } => Some((2_u8, capacity)),
            _ => None,
        };
        if identity.is_some_and(|identity| !static_types.insert(identity)) {
            return Err(invalid("compiler-minted data type is duplicated"));
        }
    }
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
        if !exact_source_function_specialization_matches(
            analysis,
            program,
            function,
            declaration,
            declaration_record,
            source_function,
        ) {
            return Err(invalid(
                "source function specialization differs from its exact HIR signature",
            ));
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
            if let ExpressionResolution::DirectCall { arguments, .. }
            | ExpressionResolution::ScopeCall { arguments, .. }
            | ExpressionResolution::ProjectionCall { arguments, .. } = &fact.resolution
            {
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
        let has_typed_actor_reply = analysis.expressions.iter().any(|fact| {
            fact.function == function.id
                && matches!(
                    fact.resolution,
                    ExpressionResolution::ActorRequest { reply: Some(_), .. }
                )
        });
        if has_typed_actor_reply
            && (!matches!(function.role, FunctionRole::TaskEntry(_))
                || function.effects
                    != EffectSet(EffectSet::TASK | EffectSet::ACTOR | EffectSet::SUSPEND))
        {
            return Err(invalid(
                "typed actor reply producer effects differ from the exact startup-task contract",
            ));
        }
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
            SemanticValueOrigin::Parameter(_)
            | SemanticValueOrigin::Expression(_)
            | SemanticValueOrigin::ActorStateLoad(_)
            | SemanticValueOrigin::ActorStateCompoundResult(_) => {}
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
                                ExpressionResolution::DirectCall { arguments, .. }
                                | ExpressionResolution::ScopeCall { arguments, .. }
                                | ExpressionResolution::ProjectionCall { arguments, .. } => {
                                    arguments
                                        .iter()
                                        .find(|binding| {
                                            binding.source_index as usize == source_index
                                        })
                                        .map(|binding| binding.value)
                                }
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
            wrela_hir::ExpressionKind::Try(operand)
            | wrela_hir::ExpressionKind::TrySend(operand) => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::IsPattern { value, .. } => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*value);
            }
            wrela_hir::ExpressionKind::Binary { left, right, .. }
            | wrela_hir::ExpressionKind::Compare { left, right, .. }
            | wrela_hir::ExpressionKind::Range {
                start: left,
                end: right,
                ..
            } => {
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
            wrela_hir::ExpressionKind::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let additional = elif_branches
                    .len()
                    .checked_mul(2)
                    .and_then(|elif| elif.checked_add(3))
                    .ok_or_else(|| invalid("expression child count overflow"))?;
                reserve_validation_scratch(
                    &mut pending,
                    additional,
                    program.expressions.len() as u64,
                )?;
                pending.push(*else_branch);
                for (elif_condition, elif_branch) in elif_branches.iter().rev() {
                    pending.push(*elif_branch);
                    pending.push(*elif_condition);
                }
                pending.push(*then_branch);
                pending.push(*condition);
            }
            wrela_hir::ExpressionKind::Interpolate(parts) => {
                let values = parts
                    .iter()
                    .filter(|part| matches!(part, wrela_hir::InterpolationPart::Value { .. }))
                    .count();
                reserve_validation_scratch(&mut pending, values, program.expressions.len() as u64)?;
                for part in parts.iter().rev() {
                    if let wrela_hir::InterpolationPart::Value { expression, .. } = part {
                        pending.push(*expression);
                    }
                }
            }
            wrela_hir::ExpressionKind::Array(elements) => {
                reserve_validation_scratch(
                    &mut pending,
                    elements.len(),
                    program.expressions.len() as u64,
                )?;
                pending.extend(elements.iter().rev().copied());
            }
            wrela_hir::ExpressionKind::Literal(_)
            | wrela_hir::ExpressionKind::Reference(_)
            | wrela_hir::ExpressionKind::DotName { .. } => {}
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
            wrela_hir::ExpressionKind::Try(operand)
            | wrela_hir::ExpressionKind::TrySend(operand) => {
                reserve_validation_scratch(&mut pending, 1, program.expressions.len() as u64)?;
                pending.push(*operand);
            }
            wrela_hir::ExpressionKind::Binary { left, right, .. }
            | wrela_hir::ExpressionKind::Compare { left, right, .. }
            | wrela_hir::ExpressionKind::Range {
                start: left,
                end: right,
                ..
            } => {
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
            wrela_hir::ExpressionKind::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let additional = elif_branches
                    .len()
                    .checked_mul(2)
                    .and_then(|elif| elif.checked_add(3))
                    .ok_or_else(|| invalid("expression child count overflow"))?;
                reserve_validation_scratch(
                    &mut pending,
                    additional,
                    program.expressions.len() as u64,
                )?;
                pending.push(*else_branch);
                for (elif_condition, elif_branch) in elif_branches.iter().rev() {
                    pending.push(*elif_branch);
                    pending.push(*elif_condition);
                }
                pending.push(*then_branch);
                pending.push(*condition);
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
                if let wrela_hir::Definition::Parameter(receiver) = target.root {
                    validate_exact_expression_local_values(
                        analysis,
                        program,
                        function.id,
                        *value,
                        locals,
                        is_cancelled,
                    )?;
                    let expression = exact_child_expression(analysis, function.id, *value)
                        .ok_or_else(|| {
                            invalid("actor state assignment expression fact is missing")
                        })?;
                    if !fact.definitions.is_empty()
                        || !exact_actor_state_write_matches(
                            analysis,
                            function.id,
                            *statement_id,
                            receiver,
                            *value,
                            expression.result,
                        )
                    {
                        return Err(invalid(
                            "actor state assignment local-value flow is not exact",
                        ));
                    }
                    EffectSet(expression.effects.0 | EffectSet::ACTOR)
                } else {
                    let wrela_hir::Definition::Local(local) = target.root else {
                        return Err(invalid("assignment local-value flow target is not local"));
                    };
                    let projected_field = match target.projections.as_slice() {
                        [] => None,
                        [wrela_hir::PlaceProjection::Field(name)]
                            if *operator == wrela_hir::AssignmentOperator::Assign =>
                        {
                            Some(name)
                        }
                        _ => {
                            return Err(invalid(
                                "assignment local-value flow projection is unsupported",
                            ));
                        }
                    };
                    if projected_field.is_none()
                        && *operator != wrela_hir::AssignmentOperator::Assign
                        && expression_references_local(program, *value, local, is_cancelled)?
                    {
                        return Err(invalid(
                            "compound-assignment right-hand side overlaps its destination",
                        ));
                    }
                    if projected_field.is_some()
                        && expression_references_local(program, *value, local, is_cancelled)?
                    {
                        return Err(invalid(
                            "projected-assignment right-hand side overlaps its reserved aggregate",
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
                    if let Some(field_name) = projected_field {
                        let previous_record = analysis
                            .values
                            .get(previous.0 as usize)
                            .filter(|record| record.function == function.id)
                            .ok_or_else(|| {
                                invalid("projected assignment previous value is invalid")
                            })?;
                        let replacement = analysis
                            .values
                            .get(definition.value.0 as usize)
                            .filter(|record| record.function == function.id)
                            .ok_or_else(|| {
                                invalid("projected assignment replacement is invalid")
                            })?;
                        let Some(SemanticTypeKind::Structure {
                            arguments, fields, ..
                        }) = analysis
                            .types
                            .get(previous_record.ty.0 as usize)
                            .map(|record| &record.kind)
                        else {
                            return Err(invalid(
                                "projected assignment previous value is not a structure",
                            ));
                        };
                        let rhs = exact_child_expression(analysis, function.id, *value)
                            .ok_or_else(|| invalid("projected assignment RHS is missing"))?;
                        let mut selected = None;
                        for field in fields {
                            check_analysis_cancelled(is_cancelled)?;
                            if field.name == field_name.as_str()
                                && selected.replace(field).is_some()
                            {
                                return Err(invalid("projected assignment field is ambiguous"));
                            }
                        }
                        let field = selected
                            .ok_or_else(|| invalid("projected assignment field is not exact"))?;
                        if !runtime_structure_arguments_supported(analysis, arguments, fields)
                            || replacement.ty != previous_record.ty
                            || rhs.ty != field.ty
                        {
                            return Err(invalid(
                                "projected assignment local-value flow type is not exact",
                            ));
                        }
                    }
                    *slot = Some(definition.value);
                    exact_child_expression(analysis, function.id, *value)
                        .ok_or_else(|| invalid("assignment expression fact is missing"))?
                        .effects
                }
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
            wrela_hir::StatementKind::For {
                binding,
                iterable,
                body,
                ..
            } => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *iterable,
                    locals,
                    is_cancelled,
                )?;
                let iterable_fact = exact_child_expression(analysis, function.id, *iterable)
                    .ok_or_else(|| invalid("for iterable fact is not a closed iterator"))?;
                exact_closed_for_element_type(analysis, function.id, *iterable, iterable_fact)
                    .ok_or_else(|| invalid("for iterable fact is not a closed iterator"))?;
                let iterable_effects = iterable_fact.effects;
                let [definition] = fact.definitions.as_slice() else {
                    return Err(invalid("for local-value binding is missing"));
                };
                if definition.local != *binding {
                    return Err(invalid("for local-value binding differs from HIR"));
                }
                let mut body_locals = copy_exact_local_values(locals)?;
                let slot = body_locals
                    .get_mut(binding.0 as usize)
                    .ok_or_else(|| invalid("for local-value binding is invalid"))?;
                if slot.replace(definition.value).is_some() {
                    return Err(invalid("for local-value binding shadows live state"));
                }
                let body_effects = validate_exact_body_local_value_flow(
                    analysis,
                    program,
                    function,
                    *body,
                    &mut body_locals,
                    depth + 1,
                    is_cancelled,
                )?;
                if body_locals.get(binding.0 as usize).copied().flatten() != Some(definition.value)
                {
                    return Err(invalid("for body changes its generated binding"));
                }
                for (index, (before, after)) in locals.iter().zip(&body_locals).enumerate() {
                    check_analysis_cancelled(is_cancelled)?;
                    let local_is_nested = program
                        .locals
                        .get(index)
                        .is_some_and(|local| body_is_ancestor(program, *body, local.body));
                    if !local_is_nested && before != after {
                        return Err(invalid("for body changes outer local-value flow"));
                    }
                }
                EffectSet(iterable_effects.0 | body_effects.0)
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
                let mut definition_index = 0usize;
                for arm in arms {
                    check_analysis_cancelled(is_cancelled)?;
                    let mut arm_locals = copy_exact_local_values(locals)?;
                    let binding_locals = exact_match_binding_locals(program, arm)?;
                    for local in &binding_locals {
                        let definition = fact
                            .definitions
                            .get(definition_index)
                            .ok_or_else(|| invalid("match pattern binding is missing"))?;
                        definition_index += 1;
                        if definition.local != *local {
                            return Err(invalid("match binding definition order is not exact"));
                        }
                        let slot = arm_locals
                            .get_mut(local.0 as usize)
                            .ok_or_else(|| invalid("match pattern local is invalid"))?;
                        if slot.replace(definition.value).is_some() {
                            return Err(invalid("match pattern shadows reaching local state"));
                        }
                    }
                    if let Some(guard) = arm.guard {
                        validate_exact_expression_local_values(
                            analysis,
                            program,
                            function.id,
                            guard,
                            &arm_locals,
                            is_cancelled,
                        )?;
                        effects.0 |= exact_child_expression(analysis, function.id, guard)
                            .ok_or_else(|| invalid("enum match guard fact is missing"))?
                            .effects
                            .0;
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
                        if !binding_locals.iter().any(|local| index == local.0 as usize)
                            && before != after
                        {
                            return Err(invalid("match arm mutates outer local state"));
                        }
                    }
                    effects.0 |= arm_effects.0;
                }
                if definition_index != fact.definitions.len() {
                    return Err(invalid("enum match has extraneous payload bindings"));
                }
                effects
            }
            wrela_hir::StatementKind::With {
                value,
                binding,
                body,
                ..
            } => {
                validate_exact_expression_local_values(
                    analysis,
                    program,
                    function.id,
                    *value,
                    locals,
                    is_cancelled,
                )?;
                let value_effects = exact_child_expression(analysis, function.id, *value)
                    .ok_or_else(|| invalid("with acquisition expression fact is missing"))?
                    .effects;
                let mut body_locals = copy_exact_local_values(locals)?;
                if let Some(local) = binding {
                    let [definition] = fact.definitions.as_slice() else {
                        return Err(invalid("with binding flow definition is missing"));
                    };
                    let slot = body_locals
                        .get_mut(local.0 as usize)
                        .ok_or_else(|| invalid("with binding flow local is invalid"))?;
                    if slot.replace(definition.value).is_some() || definition.local != *local {
                        return Err(invalid("with binding flow shadows a live local"));
                    }
                } else if !fact.definitions.is_empty() {
                    return Err(invalid("unbound with flow defines a local"));
                }
                let body_effects = validate_exact_body_local_value_flow(
                    analysis,
                    program,
                    function,
                    *body,
                    &mut body_locals,
                    depth + 1,
                    is_cancelled,
                )?;
                for index in 0..locals.len() {
                    check_analysis_cancelled(is_cancelled)?;
                    if binding.is_some_and(|local| index == local.0 as usize) {
                        continue;
                    }
                    locals[index] = body_locals[index];
                }
                EffectSet(value_effects.0 | body_effects.0)
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

fn exact_generic_signature_source_type(
    analysis: &PartialAnalysis,
    source: &wrela_hir::TypeExpression,
    generics: &[wrela_hir::GenericParameterId],
    arguments: &[SemanticArgument],
) -> Option<SemanticTypeId> {
    if let Some(scalar) = exact_scalar_source_type(analysis, source) {
        return Some(scalar);
    }
    let wrela_hir::TypeExpressionKind::Named {
        definition: wrela_hir::Definition::Generic(generic),
        arguments: source_arguments,
    } = &source.kind
    else {
        return None;
    };
    if !source_arguments.is_empty() {
        return None;
    }
    let position = generics.iter().position(|candidate| candidate == generic)?;
    match arguments.get(position)? {
        SemanticArgument::Type(ty) => Some(*ty),
        SemanticArgument::Constant(_) | SemanticArgument::Region(_) => None,
    }
}

fn exact_source_function_specialization_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    declaration: DeclarationId,
    declaration_record: &wrela_hir::Declaration,
    source: &wrela_hir::FunctionDeclaration,
) -> bool {
    if source.generics.is_empty() {
        return function.generic_arguments.is_empty();
    }
    let receiver_declaration = crate::interfaces::receiver_concrete_struct(program, declaration);
    let is_free_function = matches!(
        declaration_record.owner,
        wrela_hir::DeclarationOwner::Module(_)
    ) && source.parameters.iter().all(|parameter| {
        program
            .parameter(*parameter)
            .is_some_and(|parameter| !parameter.receiver)
    });
    let is_concrete_method = receiver_declaration.is_some()
        && source
            .parameters
            .first()
            .and_then(|parameter| program.parameter(*parameter))
            .is_some_and(|parameter| {
                parameter.receiver && parameter.access == wrela_hir::AccessMode::Read
            })
        && source.parameters.iter().skip(1).all(|parameter| {
            program
                .parameter(*parameter)
                .is_some_and(|parameter| !parameter.receiver)
        });
    if source.color != FunctionColor::Sync
        || function.role != FunctionRole::Ordinary
        || !(is_free_function || is_concrete_method)
        || source.generics.len() != function.generic_arguments.len()
        || source.generics.len() > 26
        || source.parameters.len() != function.parameters.len()
    {
        return false;
    }
    for (generic_id, argument) in source.generics.iter().zip(&function.generic_arguments) {
        let Some(generic) = program.generic_parameter(*generic_id) else {
            return false;
        };
        if generic.owner != declaration
            || !matches!(
                generic.kind,
                wrela_hir::GenericParameterKind::Type { bound: None }
            )
            || !matches!(argument, SemanticArgument::Type(ty)
                if exact_stored_copy_scalar_layout(analysis, *ty).is_some()
                    || (is_free_function
                        && source.generics.len() == 1
                        && exact_generic_function_flat_argument(analysis, *ty).is_some()))
        {
            return false;
        }
    }
    if source_function_specialization_key(
        analysis.build.request,
        declaration,
        &function.generic_arguments,
        analysis,
    ) != Some(function.key)
    {
        return false;
    }
    let expected_result = source
        .result
        .as_ref()
        .map_or(Some(SemanticTypeId(0)), |result| {
            exact_generic_signature_source_type(
                analysis,
                result,
                &source.generics,
                &function.generic_arguments,
            )
        });
    if expected_result != Some(function.result) {
        return false;
    }
    source
        .parameters
        .iter()
        .zip(&function.parameters)
        .all(|(parameter_id, semantic)| {
            let Some(parameter) = program.parameter(*parameter_id) else {
                return false;
            };
            if parameter.receiver {
                let Some(receiver_declaration) = receiver_declaration else {
                    return false;
                };
                return semantic.access == AccessMode::Read
                    && analysis.types.get(semantic.ty.0 as usize).is_some_and(|ty| {
                        exact_flat_structure_type_matches(analysis, program, ty)
                            && matches!(
                                &ty.kind,
                                SemanticTypeKind::Structure {
                                    declaration,
                                    arguments,
                                    ..
                                } if *declaration == receiver_declaration && arguments.is_empty()
                            )
                    });
            }
            parameter.ty.as_ref().is_some_and(|ty| {
                exact_generic_signature_source_type(
                    analysis,
                    ty,
                    &source.generics,
                    &function.generic_arguments,
                ) == Some(semantic.ty)
            })
        })
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
                wrela_hir::StatementKind::For { iterable, body, .. } => {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*iterable);
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
                        if let Some(guard) = arm.guard {
                            reserve_validation_scratch(
                                &mut pending_expressions,
                                1,
                                program.expressions.len() as u64,
                            )?;
                            pending_expressions.push(guard);
                        }
                        pending_bodies.push(arm.body);
                    }
                }
                wrela_hir::StatementKind::With { value, body, .. } => {
                    reserve_validation_scratch(
                        &mut pending_expressions,
                        1,
                        program.expressions.len() as u64,
                    )?;
                    pending_expressions.push(*value);
                    reserve_validation_scratch(
                        &mut pending_bodies,
                        1,
                        program.bodies.len() as u64,
                    )?;
                    pending_bodies.push(*body);
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
                | wrela_hir::Literal::Float(_)
                | wrela_hir::Literal::Character(_)
                | wrela_hir::Literal::String(_)
                | wrela_hir::Literal::Bytes(_),
            )
            | wrela_hir::ExpressionKind::Reference(
                wrela_hir::Definition::Local(_)
                | wrela_hir::Definition::Parameter(_)
                | wrela_hir::Definition::Declaration(_)
                | wrela_hir::Definition::Variant(_),
            )
            // A leading-dot variant is a resolved-candidate leaf: its
            // `candidates` are HIR-lowering metadata, not sub-expressions.
            | wrela_hir::ExpressionKind::DotName { .. } => {}
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
            wrela_hir::ExpressionKind::Try(operand)
            | wrela_hir::ExpressionKind::TrySend(operand) => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    1,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*operand);
            }
            wrela_hir::ExpressionKind::IsPattern { value, .. } => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    1,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*value);
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
            | wrela_hir::ExpressionKind::Compare { left, right, .. }
            | wrela_hir::ExpressionKind::Range {
                start: left,
                end: right,
                ..
            } => {
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
            wrela_hir::ExpressionKind::Array(elements) => {
                reserve_validation_scratch(
                    &mut pending_expressions,
                    elements.len(),
                    program.expressions.len() as u64,
                )?;
                pending_expressions.extend(elements.iter().rev().copied());
            }
            wrela_hir::ExpressionKind::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let additional = elif_branches
                    .len()
                    .checked_mul(2)
                    .and_then(|elif| elif.checked_add(3))
                    .ok_or_else(invalid)?;
                reserve_validation_scratch(
                    &mut pending_expressions,
                    additional,
                    program.expressions.len() as u64,
                )?;
                pending_expressions.push(*else_branch);
                for (elif_condition, elif_branch) in elif_branches.iter().rev() {
                    pending_expressions.push(*elif_branch);
                    pending_expressions.push(*elif_condition);
                }
                pending_expressions.push(*then_branch);
                pending_expressions.push(*condition);
            }
            wrela_hir::ExpressionKind::Interpolate(parts) => {
                let values = parts
                    .iter()
                    .filter(|part| matches!(part, wrela_hir::InterpolationPart::Value { .. }))
                    .count();
                reserve_validation_scratch(
                    &mut pending_expressions,
                    values,
                    program.expressions.len() as u64,
                )?;
                for part in parts.iter().rev() {
                    if let wrela_hir::InterpolationPart::Value { expression, .. } = part {
                        pending_expressions.push(*expression);
                    }
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

fn exact_match_binding_locals(
    program: &wrela_hir::Program,
    arm: &wrela_hir::MatchArm,
) -> Result<Vec<wrela_hir::LocalId>, AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let pattern = program
        .patterns
        .get(arm.pattern.0 as usize)
        .ok_or_else(|| invalid("match pattern is missing"))?;
    if let [alternative] = pattern.alternatives.as_slice() {
        if let wrela_hir::PrimaryPattern::Array(arguments) = &alternative.kind {
            let mut bindings = fallible_scratch(arguments.len(), 256)?;
            for argument in arguments {
                let child = program
                    .patterns
                    .get(argument.pattern.0 as usize)
                    .ok_or_else(|| invalid("array element pattern is missing"))?;
                let [child] = child.alternatives.as_slice() else {
                    return Err(invalid("array element pattern is not exact"));
                };
                if let wrela_hir::PrimaryPattern::Bind(local) = child.kind {
                    bindings.push(local);
                }
            }
            return Ok(bindings);
        }
    }
    let mut shared = None;
    for alternative in &pattern.alternatives {
        let wrela_hir::PrimaryPattern::Constructor { arguments, .. } = &alternative.kind else {
            return Ok(Vec::new());
        };
        if arguments.is_empty() {
            continue;
        }
        let [argument] = arguments.as_slice() else {
            return Ok(Vec::new());
        };
        if argument.take {
            return Ok(Vec::new());
        }
        let payload = program
            .patterns
            .get(argument.pattern.0 as usize)
            .ok_or_else(|| invalid("constructor payload pattern is missing"))?;
        let [alternative] = payload.alternatives.as_slice() else {
            return Ok(Vec::new());
        };
        let wrela_hir::PrimaryPattern::Bind(local) = alternative.kind else {
            return Ok(Vec::new());
        };
        if shared.is_some_and(|existing| existing != local) {
            return Ok(Vec::new());
        }
        shared = Some(local);
    }
    let mut bindings = Vec::new();
    if let Some(local) = shared {
        bindings
            .try_reserve_exact(1)
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "match binding validation",
                limit: 1,
            })?;
        bindings.push(local);
    }
    Ok(bindings)
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
    let ownership_matches =
        if let ExpressionResolution::ActorRequest { reply, .. } = fact.resolution {
            fact.ownership_before == OwnershipState::Owned
                && fact.ownership_after
                    == if reply.is_some() {
                        OwnershipState::Owned
                    } else {
                        OwnershipState::Taken
                    }
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
            wrela_hir::ExpressionKind::Interpolate(parts),
            ExpressionResolution::BoundedInterpolation {
                capacity,
                parts: resolved,
            },
            Some(_),
        ) if exact_bounded_interpolation_matches(
            analysis,
            function.id,
            fact,
            parts,
            *capacity,
            resolved,
        ) => {}
        (
            wrela_hir::ExpressionKind::Range {
                start,
                end,
                inclusive,
            },
            ExpressionResolution::ClosedRange {
                start: start_value,
                end: end_value,
                inclusive: resolved_inclusive,
                maximum_iterations,
            },
            None,
        ) if exact_closed_literal_range_matches(
            analysis,
            function.id,
            fact,
            *start,
            *end,
            *inclusive,
            *start_value,
            *end_value,
            *resolved_inclusive,
            *maximum_iterations,
        ) => {}
        (
            wrela_hir::ExpressionKind::Array(source_elements),
            resolution @ ExpressionResolution::ClosedArray { .. },
            _,
        ) if exact_closed_fixed_array_matches(
            analysis,
            program,
            function.id,
            fact,
            source_elements,
            resolution,
        ) => {}
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
            ExpressionResolution::Scope(protocol),
            None,
        ) if analysis
            .scope_protocols
            .get(protocol.0 as usize)
            .is_some_and(|protocol| {
                protocol.declaration == source.declaration
                    && analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
                        matches!(
                            &ty.kind,
                            SemanticTypeKind::Function {
                                color: wrela_hir::FunctionColor::Sync,
                                parameters,
                                result,
                            } if parameters == &protocol.parameters && *result == protocol.result
                        )
                    })
            }) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(source)),
            ExpressionResolution::Projection(protocol),
            None,
        ) if analysis
            .projection_protocols
            .get(protocol.0 as usize)
            .is_some_and(|protocol| {
                protocol.declaration == source.declaration
                    && analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
                        matches!(
                            &ty.kind,
                            SemanticTypeKind::Function {
                                color: wrela_hir::FunctionColor::Sync,
                                parameters,
                                result,
                            } if parameters.len() == protocol.parameters.len()
                                && parameters.iter().zip(&protocol.parameters).all(
                                    |(actual, expected)| actual.access == expected.access
                                        && actual.ty == expected.ty
                                )
                                && *result == protocol.target
                        )
                    })
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
                        fields,
                        ..
                    } if *declaration == source.declaration
                        && runtime_structure_arguments_supported(analysis, arguments, fields)
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
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Variant(source)),
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            Some(_),
        ) if *ty == fact.ty
            && exact_unit_enum_constructor_reference_matches(
                analysis, program, source, *ty, *variant,
            ) => {}
        (
            wrela_hir::ExpressionKind::Field { .. },
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            Some(_),
        ) if *ty == fact.ty
            && exact_resolved_enum_constructor(program, fact.expression, is_cancelled)?
                .is_some_and(|source| {
                    exact_unit_enum_constructor_reference_matches(
                        analysis, program, &source, *ty, *variant,
                    )
                }) => {}
        (
            wrela_hir::ExpressionKind::DotName { candidates, .. },
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            None,
        ) if *ty == fact.ty
            && candidates.iter().any(|candidate| {
                exact_enum_constructor_reference_matches(
                    analysis, program, candidate, *ty, *variant,
                )
            }) => {}
        (
            wrela_hir::ExpressionKind::DotName { candidates, .. },
            ExpressionResolution::Constructor {
                ty,
                variant: Some(variant),
            },
            Some(_),
        ) if *ty == fact.ty
            && candidates.iter().any(|candidate| {
                exact_unit_enum_constructor_reference_matches(
                    analysis, program, candidate, *ty, *variant,
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
            ExpressionResolution::InitializerConstruction { ty, initializer },
            Some(_),
        ) if *ty == fact.ty
            && exact_initializer_constructor_matches(
                analysis,
                program,
                function.id,
                *callee,
                arguments,
                *ty,
                *initializer,
                is_cancelled,
            )? => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::DerivedFrom {
                enumeration,
                variant,
                payload,
            },
            Some(_),
        ) if exact_derived_from_matches(
            analysis,
            program,
            function.id,
            fact,
            *callee,
            arguments,
            *enumeration,
            *variant,
            *payload,
        ) => {}
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
        )? || exact_actor_state_field_matches(
            analysis,
            function.id,
            fact.expression,
            fact.result,
            fact.region,
        ) => {}
        (
            wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(destination)),
            ExpressionResolution::DerivedFromType { enumeration },
            None,
        ) if fact.ty == *enumeration
            && exact_derived_from_destination_matches(
                analysis,
                program,
                destination,
                *enumeration,
            ) => {}
        (
            wrela_hir::ExpressionKind::Field { base, name },
            ExpressionResolution::DerivedFromFunction {
                enumeration,
                variant,
            },
            None,
        ) if fact.ty == *enumeration
            && *variant == 0
            && name.as_str() == "from"
            && exact_child_expression(analysis, function.id, *base).is_some_and(|base| {
                base.ty == *enumeration
                    && base.result.is_none()
                    && base.effects == EffectSet(0)
                    && base.resolution
                        == ExpressionResolution::DerivedFromType {
                            enumeration: *enumeration,
                        }
            }) => {}
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
        ) || exact_concrete_method_reference_matches(
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
            ExpressionResolution::MethodCall {
                function: target,
                receiver,
                receiver_access,
                arguments: bindings,
            },
            Some(_),
        ) if exact_method_call_bindings_match(
            analysis,
            program,
            function,
            *callee,
            arguments,
            *target,
            *receiver,
            *receiver_access,
            bindings,
        ) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::ScopeCall {
                protocol,
                arguments: bindings,
            },
            Some(_),
        ) if exact_scope_call_bindings_match(
            analysis,
            program,
            function.id,
            *callee,
            arguments,
            *protocol,
            bindings,
        ) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::ProjectionCall {
                protocol,
                arguments: bindings,
                view,
            },
            Some(result),
        ) if exact_projection_call_bindings_match(
            analysis,
            program,
            function.id,
            fact,
            *callee,
            arguments,
            *protocol,
            bindings,
            *view,
            result,
        ) => {}
        (
            wrela_hir::ExpressionKind::Call { callee, arguments },
            ExpressionResolution::ActorRequest {
                actor,
                method,
                permit,
                reply,
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
            *reply,
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
            ExpressionResolution::DerivedEquality {
                aggregate,
                left: left_value,
                right: right_value,
                fields,
                conjunctions,
            },
            Some(result),
        ) if exact_derived_equality_matches(
            analysis,
            program,
            function.id,
            *operator,
            *left,
            *right,
            fact,
            *aggregate,
            *left_value,
            *right_value,
            fields,
            conjunctions,
        ) =>
        {
            for field in fields {
                increment_definition(definitions, field.left)?;
                increment_definition(definitions, field.right)?;
                if field.comparison != result {
                    increment_definition(definitions, field.comparison)?;
                }
            }
            for conjunction in conjunctions {
                if *conjunction != result {
                    increment_definition(definitions, *conjunction)?;
                }
            }
        }
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
            wrela_hir::ExpressionKind::IsPattern { value, pattern, .. },
            ExpressionResolution::EnumTypeTest {
                enumeration,
                variant,
                scrutinee,
            },
            Some(_),
        ) if exact_enum_is_matches(
            analysis,
            program,
            fact,
            ExactEnumTypeTest {
                function: function.id,
                value: *value,
                pattern: *pattern,
                enumeration: *enumeration,
                variant: *variant,
                scrutinee: *scrutinee,
            },
            is_cancelled,
        )? => {}
        (
            wrela_hir::ExpressionKind::Binary {
                operator,
                left,
                right,
            },
            ExpressionResolution::OperatorCall {
                function: callee,
                arguments,
                raw_result,
                negate,
            },
            Some(result),
        ) if exact_operator_call_matches(
            analysis,
            program,
            function.id,
            desugar_binary_operator(*operator),
            *left,
            *right,
            fact,
            *callee,
            arguments,
            *raw_result,
            *negate,
            result,
        ) =>
        {
            // `<=`/`>=` define a distinct intermediate raw call result ahead
            // of the logical NOT that defines the expression's own result.
            if *negate {
                increment_definition(definitions, *raw_result)?;
            }
        }
        (
            wrela_hir::ExpressionKind::Compare {
                left,
                operator,
                right,
            },
            ExpressionResolution::OperatorCall {
                function: callee,
                arguments,
                raw_result,
                negate,
            },
            Some(result),
        ) if exact_operator_call_matches(
            analysis,
            program,
            function.id,
            desugar_comparison_operator(*operator),
            *left,
            *right,
            fact,
            *callee,
            arguments,
            *raw_result,
            *negate,
            result,
        ) =>
        {
            // `<=`/`>=` define a distinct intermediate raw call result ahead
            // of the logical NOT that defines the expression's own result.
            if *negate {
                increment_definition(definitions, *raw_result)?;
            }
        }
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
        ) if exact_await_operand_matches(analysis, program, function.id, *operand, fact) => {}
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
        (
            wrela_hir::ExpressionKind::Try(operand),
            ExpressionResolution::OptionTry {
                option_type,
                some_variant,
                none_variant,
                some_payload,
                propagated,
            },
            Some(_),
        ) => {
            if !exact_option_try_matches(
                analysis,
                program,
                function,
                *operand,
                fact,
                *option_type,
                *some_variant,
                *none_variant,
                *some_payload,
                *propagated,
            ) {
                return Err(invalid(
                    "Option postfix question semantic facts differ from HIR",
                ));
            }
            increment_definition(definitions, *some_payload)?;
            increment_definition(definitions, *propagated)?;
        }
        (
            wrela_hir::ExpressionKind::TrySend(operand),
            ExpressionResolution::Builtin(IntrinsicOperation::ActorTrySend { actor }),
            Some(result),
        ) if exact_admission_try_send_matches(
            analysis, program, function, *operand, fact, *actor, result,
        ) => {}
        (
            wrela_hir::ExpressionKind::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            },
            ExpressionResolution::Value(value),
            Some(result),
        ) if *value == result
            && exact_inline_if_matches(
                analysis,
                function.id,
                *condition,
                *then_branch,
                elif_branches,
                *else_branch,
                fact,
            ) => {}
        _ => {
            return Err(invalid(&format!(
                "expression semantic fact differs from exact HIR meaning: function {:?}, expression {:?}, HIR {:?}, resolution {:?}, result {:?}",
                function.id, fact.expression, expression.kind, fact.resolution, fact.result
            )));
        }
    }
    Ok(())
}

fn exact_inline_if_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    condition: ExpressionId,
    then_branch: ExpressionId,
    elif_branches: &[(ExpressionId, ExpressionId)],
    else_branch: ExpressionId,
    fact: &ExpressionFact,
) -> bool {
    let Some(condition_fact) = exact_child_expression(analysis, function, condition) else {
        return false;
    };
    let Some(then_fact) = exact_child_expression(analysis, function, then_branch) else {
        return false;
    };
    let Some(else_fact) = exact_child_expression(analysis, function, else_branch) else {
        return false;
    };
    if then_fact.ty != fact.ty || else_fact.ty != fact.ty {
        return false;
    }
    let mut effects = condition_fact.effects;
    effects.0 |= then_fact.effects.0;
    for (elif_condition, elif_branch) in elif_branches {
        let Some(elif_condition_fact) = exact_child_expression(analysis, function, *elif_condition)
        else {
            return false;
        };
        let Some(elif_fact) = exact_child_expression(analysis, function, *elif_branch) else {
            return false;
        };
        if elif_fact.ty != fact.ty {
            return false;
        }
        effects.0 |= elif_condition_fact.effects.0;
        effects.0 |= elif_fact.effects.0;
    }
    effects.0 |= else_fact.effects.0;
    effects.0 == fact.effects.0
}

#[derive(Clone, Copy)]
struct ExactEnumTypeTest {
    function: FunctionInstanceId,
    value: ExpressionId,
    pattern: wrela_hir::PatternId,
    enumeration: SemanticTypeId,
    variant: u32,
    scrutinee: ValueId,
}

fn exact_enum_is_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    fact: &ExpressionFact,
    identity: ExactEnumTypeTest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let Some(value_fact) = exact_child_expression(analysis, identity.function, identity.value)
    else {
        return Ok(false);
    };
    let exact_scrutinee = value_fact.result == Some(identity.scrutinee)
        || matches!(value_fact.resolution, ExpressionResolution::Value(value) if value == identity.scrutinee);
    if value_fact.ty != identity.enumeration
        || !exact_scrutinee
        || fact.effects != value_fact.effects
        || !matches!(
            exact_scalar_type(analysis, fact.ty),
            Some(ExactScalarType::Bool)
        )
    {
        return Ok(false);
    }
    let Some(pattern) = program.patterns.get(identity.pattern.0 as usize) else {
        return Ok(false);
    };
    let [alternative] = pattern.alternatives.as_slice() else {
        return Ok(false);
    };
    let wrela_hir::PrimaryPattern::Constructor {
        candidates,
        arguments,
        ..
    } = &alternative.kind
    else {
        return Ok(false);
    };
    let [candidate] = candidates.as_slice() else {
        return Ok(false);
    };
    if candidate.variant != identity.variant
        || !exact_enum_constructor_reference_matches(
            analysis,
            program,
            candidate,
            value_fact.ty,
            identity.variant,
        )
    {
        return Ok(false);
    }
    let Some(payload_ty) = analysis
        .types
        .get(value_fact.ty.0 as usize)
        .and_then(|record| match &record.kind {
            SemanticTypeKind::Enumeration { variants, .. } => variants
                .get(candidate.variant as usize)
                .map(|variant| variant.fields.first().map(|field| field.ty)),
            _ => None,
        })
    else {
        return Ok(false);
    };
    match payload_ty {
        None => Ok(arguments.is_empty()),
        Some(_) => {
            let [argument] = arguments.as_slice() else {
                return Ok(false);
            };
            if argument.take {
                return Ok(false);
            }
            let Some(payload) = program.patterns.get(argument.pattern.0 as usize) else {
                return Ok(false);
            };
            check_analysis_cancelled(is_cancelled)?;
            Ok(matches!(
                payload.alternatives.as_slice(),
                [alternative] if matches!(alternative.kind, wrela_hir::PrimaryPattern::Wildcard)
            ))
        }
    }
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
    let Some(ok_payload_type) = variants
        .first()
        .and_then(|variant| variant.fields.first())
        .map(|field| field.ty)
    else {
        return false;
    };
    let Some(err_payload_type) = variants
        .get(1)
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
        && fact.ty == ok_payload_type
        && internal_value(ok_payload, ok_payload_type)
        && internal_value(err_payload, err_payload_type)
        && internal_value(propagated, result_type)
}

#[allow(clippy::too_many_arguments)]
fn exact_option_try_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    operand: ExpressionId,
    fact: &ExpressionFact,
    option_type: SemanticTypeId,
    some_variant: u32,
    none_variant: u32,
    some_payload: ValueId,
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
    if operand_fact.ty != option_type
        || operand_fact.result.is_none()
        || matches!(operand_fact.resolution, ExpressionResolution::Value(_))
        || function.result != option_type
        || fact.effects != operand_fact.effects
        || result == some_payload
        || result == propagated
        || some_payload == propagated
    {
        return false;
    }
    let Some(SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    }) = analysis
        .types
        .get(option_type.0 as usize)
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
    some_variant == 0
        && none_variant == 1
        && exact_core_option_declaration_matches(program, *declaration)
        && runtime_enum_arguments_supported(arguments, variants)
        && matches!(variants.as_slice(), [some, none]
            if matches!(some.fields.as_slice(), [field] if field.ty == payload_type)
                && none.fields.is_empty())
        && fact.ty == payload_type
        && internal_value(some_payload, payload_type)
        && internal_value(propagated, option_type)
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
            record.owner == declaration
                && matches!(
                    record.kind,
                    wrela_hir::GenericParameterKind::Type { bound: None }
                )
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
    source.members.is_empty()
        && source.deriving.is_empty()
        && generic_is_type(*ok_generic)
        && generic_is_type(*err_generic)
        && exact_variant(ok, "Ok", *ok_generic)
        && exact_variant(err, "Err", *err_generic)
}

fn exact_core_option_declaration_matches(
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
        || record.name.as_ref().map(wrela_hir::Name::as_str) != Some("Option")
        || program
            .modules
            .get(record.module.0 as usize)
            .is_none_or(|module| module.package != core_package || module.path.dotted() != "option")
    {
        return false;
    }
    let wrela_hir::DeclarationKind::Enumeration(source) = &record.kind else {
        return false;
    };
    let [generic] = source.generics.as_slice() else {
        return false;
    };
    let Some(generic_record) = program.generic_parameter(*generic) else {
        return false;
    };
    generic_record.owner == declaration
        && matches!(
            generic_record.kind,
            wrela_hir::GenericParameterKind::Type { bound: None }
        )
        && source.members.is_empty()
        && source.deriving.is_empty()
        && matches!(source.variants.as_slice(), [some, none]
            if some.name.as_str() == "Some"
                && matches!(some.fields.as_slice(), [field]
                    if field.name.is_none()
                        && matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                            definition: wrela_hir::Definition::Generic(candidate),
                            arguments,
                        } if *candidate == *generic && arguments.is_empty()))
                && none.name.as_str() == "None"
                && none.fields.is_empty())
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

fn exact_unit_enum_constructor_reference_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    source: &wrela_hir::ResolvedVariant,
    ty: SemanticTypeId,
    variant: u32,
) -> bool {
    exact_enum_constructor_reference_matches(analysis, program, source, ty, variant)
        && analysis.types.get(ty.0 as usize).is_some_and(|record| {
            matches!(
                &record.kind,
                SemanticTypeKind::Enumeration { variants, .. }
                    if variants
                        .get(variant as usize)
                        .is_some_and(|variant| variant.fields.is_empty())
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
    let core_result_shape = matches!(arguments, [SemanticArgument::Type(ok), SemanticArgument::Type(err)] if ok == err)
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
                                if *payload == ok_field.ty)));
    core_result_shape
        || (arguments
            .iter()
            .all(|argument| matches!(argument, SemanticArgument::Type(_)))
            && variants
                .iter()
                .all(|variant| match variant.fields.as_slice() {
                    [] => true,
                    [field] => field.name.is_empty() && field.public,
                    _ => false,
                }))
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
    // A leading-dot variant callee (`.name(args)`) carries a candidate set
    // rather than one structurally-fixed reference: it is legitimate here
    // exactly when the recorded resolution's variant is among those HIR
    // candidates, which is the same check expected-type intersection would
    // have made. Every other callee shape keeps the purely structural
    // re-derivation.
    let source_matches = match program
        .expression(callee)
        .map(|expression| &expression.kind)
    {
        Some(wrela_hir::ExpressionKind::DotName { candidates, .. }) => {
            candidates.iter().any(|candidate| {
                exact_enum_constructor_reference_matches(analysis, program, candidate, ty, variant)
            })
        }
        _ => {
            let Some(source) = exact_resolved_enum_constructor(program, callee, is_cancelled)?
            else {
                return Ok(false);
            };
            exact_enum_constructor_reference_matches(analysis, program, &source, ty, variant)
        }
    };
    if !source_matches {
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

#[allow(clippy::too_many_arguments)]
fn exact_derived_from_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    fact: &ExpressionFact,
    callee: ExpressionId,
    arguments: &[wrela_hir::CallArgument],
    enumeration: SemanticTypeId,
    variant: u32,
    payload: ValueId,
) -> bool {
    if fact.ty != enumeration || variant != 0 {
        return false;
    }
    let Some(wrela_hir::ExpressionKind::Field { base, name }) = program
        .expression(callee)
        .map(|expression| &expression.kind)
    else {
        return false;
    };
    let Some(wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(destination))) =
        program.expression(*base).map(|expression| &expression.kind)
    else {
        return false;
    };
    let Some(declaration) = program.declaration(destination.declaration) else {
        return false;
    };
    let source_identity = name.as_str() == "from"
        && declaration.module == destination.module
        && program
            .modules
            .get(destination.module.0 as usize)
            .is_some_and(|module| module.package == destination.package);
    let wrela_hir::DeclarationKind::Enumeration(source) = &declaration.kind else {
        return false;
    };
    let source_shape = source.generics.is_empty()
        && source.deriving.iter().any(|name| name.as_str() == "From")
        && matches!(source.variants.as_slice(), [variant]
            if matches!(variant.fields.as_slice(), [field] if field.name.is_none()));
    let Some(payload_ty) = analysis
        .types
        .get(enumeration.0 as usize)
        .and_then(|record| match &record.kind {
            SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                variants,
            } if *declaration == destination.declaration && arguments.is_empty() => {
                match variants.as_slice() {
                    [variant] => match variant.fields.as_slice() {
                        [field] => Some(field.ty),
                        _ => None,
                    },
                    _ => None,
                }
            }
            _ => None,
        })
    else {
        return false;
    };
    let [argument] = arguments else {
        return false;
    };
    let wrela_hir::CallArgumentValue::Value(payload_expression) = argument.value else {
        return false;
    };
    let Some(payload_fact) = exact_child_expression(analysis, function, payload_expression) else {
        return false;
    };
    let produced = match payload_fact.resolution {
        ExpressionResolution::Value(value) => Some(value),
        _ => payload_fact.result,
    };
    source_identity
        && source_shape
        && argument.name.is_none()
        && exact_stored_copy_scalar_layout(analysis, payload_ty).is_some()
        && payload_fact.ty == payload_ty
        && produced == Some(payload)
        && payload_fact.effects == fact.effects
        && analysis
            .values
            .get(payload.0 as usize)
            .is_some_and(|value| {
                value.function == function
                    && value.ty == payload_ty
                    && value.category == ValueCategory::Value
            })
}

fn exact_derived_from_destination_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    destination: &wrela_hir::ResolvedDeclaration,
    enumeration: SemanticTypeId,
) -> bool {
    let Some(declaration) = program.declaration(destination.declaration) else {
        return false;
    };
    let exact_identity = declaration.module == destination.module
        && program
            .modules
            .get(destination.module.0 as usize)
            .is_some_and(|module| module.package == destination.package);
    let wrela_hir::DeclarationKind::Enumeration(source) = &declaration.kind else {
        return false;
    };
    exact_identity
        && source.generics.is_empty()
        && source.deriving.iter().any(|name| name.as_str() == "From")
        && matches!(source.variants.as_slice(), [variant]
            if matches!(variant.fields.as_slice(), [field] if field.name.is_none()))
        && analysis
            .types
            .get(enumeration.0 as usize)
            .is_some_and(|record| {
                matches!(&record.kind,
                SemanticTypeKind::Enumeration {
                    declaration,
                    arguments,
                    variants,
                } if *declaration == destination.declaration
                    && arguments.is_empty()
                    && matches!(variants.as_slice(), [variant]
                        if matches!(variant.fields.as_slice(), [field]
                            if exact_stored_copy_scalar_layout(analysis, field.ty).is_some())))
            })
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
    if !runtime_structure_arguments_supported(analysis, type_arguments, fields)
        || arguments.len() != fields.len()
    {
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
fn exact_initializer_constructor_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    callee: ExpressionId,
    arguments: &[wrela_hir::CallArgument],
    ty: SemanticTypeId,
    initializer_id: DeclarationId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    if !exact_flat_constructor_matches(
        analysis,
        program,
        function,
        callee,
        arguments,
        ty,
        is_cancelled,
    )? {
        return Ok(false);
    }
    let Some(SemanticTypeKind::Structure {
        declaration,
        arguments: type_arguments,
        fields,
    }) = analysis.types.get(ty.0 as usize).map(|record| &record.kind)
    else {
        return Ok(false);
    };
    if !type_arguments.is_empty() || fields.is_empty() {
        return Ok(false);
    }
    let Some(wrela_hir::Declaration {
        kind: wrela_hir::DeclarationKind::Structure(source_structure),
        ..
    }) = program.declaration(*declaration)
    else {
        return Ok(false);
    };
    if !source_structure.generics.is_empty()
        || source_structure.linear
        || source_structure.copy
        || source_structure.fields.len() != fields.len()
        || !source_structure.members.contains(&initializer_id)
        || source_structure.fields.iter().any(|field| {
            field.visibility != wrela_hir::Visibility::Public
                || !field.attributes.is_empty()
                || field.default.is_some()
        })
    {
        return Ok(false);
    }
    let Some(wrela_hir::Declaration {
        kind: wrela_hir::DeclarationKind::Initializer(initializer),
        ..
    }) = program.declaration(initializer_id)
    else {
        return Ok(false);
    };
    if initializer.result.is_some()
        || initializer.parameters.len() != fields.len().saturating_add(1)
    {
        return Ok(false);
    }
    let Some(receiver) = initializer
        .parameters
        .first()
        .and_then(|parameter| program.parameters.get(parameter.0 as usize))
    else {
        return Ok(false);
    };
    if !receiver.receiver
        || receiver.access != wrela_hir::AccessMode::Mutate
        || receiver.name.is_some()
        || receiver.ty.is_some()
    {
        return Ok(false);
    }
    for ((source_field, field), parameter_id) in source_structure
        .fields
        .iter()
        .zip(fields)
        .zip(initializer.parameters.iter().skip(1))
    {
        check_analysis_cancelled(is_cancelled)?;
        let Some(parameter) = program
            .parameters
            .get(parameter_id.0 as usize)
            .filter(|parameter| parameter.id == *parameter_id)
        else {
            return Ok(false);
        };
        if parameter.receiver
            || parameter.access != wrela_hir::AccessMode::Value
            || parameter.positional_only
            || parameter.name.as_ref() != Some(&source_field.name)
            || parameter
                .ty
                .as_ref()
                .and_then(|source| exact_scalar_source_type(analysis, source))
                != Some(field.ty)
        {
            return Ok(false);
        }
    }
    let Some(body) = program.body(initializer.body) else {
        return Ok(false);
    };
    let mut initialized = Vec::new();
    initialized
        .try_reserve_exact(fields.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "initializer validation fields",
            limit: fields.len() as u64,
        })?;
    initialized.resize(fields.len(), false);
    for statement_id in &body.statements {
        check_analysis_cancelled(is_cancelled)?;
        let Some(wrela_hir::Statement {
            kind:
                wrela_hir::StatementKind::Assign {
                    targets,
                    operator: wrela_hir::AssignmentOperator::Assign,
                    value,
                },
            ..
        }) = program.statement(*statement_id)
        else {
            return Ok(false);
        };
        let [target] = targets.as_slice() else {
            return Ok(false);
        };
        let [wrela_hir::PlaceProjection::Field(name)] = target.projections.as_slice() else {
            return Ok(false);
        };
        if !matches!(target.root, wrela_hir::Definition::Parameter(parameter) if parameter == receiver.id)
        {
            return Ok(false);
        }
        let Some(field_index) = source_structure
            .fields
            .iter()
            .position(|field| field.name == *name)
        else {
            return Ok(false);
        };
        let rhs_matches = program.expression(*value).is_some_and(|expression| {
            matches!(expression.kind,
                wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(parameter))
                    if initializer.parameters.get(field_index.saturating_add(1)) == Some(&parameter))
        });
        let Some(slot) = initialized.get_mut(field_index) else {
            return Ok(false);
        };
        if !rhs_matches || std::mem::replace(slot, true) {
            return Ok(false);
        }
    }
    Ok(initialized.into_iter().all(|field| field))
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
            if !runtime_structure_arguments_supported(analysis, arguments, fields) {
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

const fn desugar_binary_operator(
    operator: wrela_hir::BinaryOperator,
) -> Option<crate::interfaces::DesugarOperator> {
    match operator {
        wrela_hir::BinaryOperator::Add => Some(crate::interfaces::DesugarOperator::Add),
        wrela_hir::BinaryOperator::Subtract => Some(crate::interfaces::DesugarOperator::Subtract),
        _ => None,
    }
}

const fn desugar_comparison_operator(
    operator: wrela_hir::ComparisonOperator,
) -> Option<crate::interfaces::DesugarOperator> {
    match operator {
        wrela_hir::ComparisonOperator::Less => Some(crate::interfaces::DesugarOperator::LessThan),
        wrela_hir::ComparisonOperator::Greater => {
            Some(crate::interfaces::DesugarOperator::GreaterThan)
        }
        wrela_hir::ComparisonOperator::LessEqual => {
            Some(crate::interfaces::DesugarOperator::LessEqual)
        }
        wrela_hir::ComparisonOperator::GreaterEqual => {
            Some(crate::interfaces::DesugarOperator::GreaterEqual)
        }
        _ => None,
    }
}

/// Recompute the expected `core.ops` operator desugaring for one HIR binary or
/// comparison expression and require the recorded [`ExpressionResolution::OperatorCall`]
/// to match it exactly: the callee must be the operator's impl method declared
/// for exactly the operand struct, the argument binding must follow the
/// operator's swap mapping with operand values in source order, argument
/// access modes must equal the callee's declared parameter modes, and the
/// `raw_result`/`negate`/result relation must follow the resolution contract
/// (`negate` only for `<=`/`>=`, where the expression result is a distinct
/// logical NOT of the raw call result).
#[allow(clippy::too_many_arguments)]
fn exact_operator_call_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    operator: Option<crate::interfaces::DesugarOperator>,
    left: ExpressionId,
    right: ExpressionId,
    fact: &ExpressionFact,
    callee: FunctionInstanceId,
    arguments: &[ResolvedCallArgument],
    raw_result: ValueId,
    negate: bool,
    result: ValueId,
) -> bool {
    let Some(operator) = operator else {
        return false;
    };
    let (expected_swap, expected_negate) = operator.mapping();
    if negate != expected_negate {
        return false;
    }
    let (Some(left_fact), Some(right_fact)) = (
        exact_child_expression(analysis, function, left),
        exact_child_expression(analysis, function, right),
    ) else {
        return false;
    };
    // A reference operand carries its value in its `Value` resolution rather
    // than a materialized expression result, matching the analyzer's
    // `referenced.or(result)` argument rule.
    let operand_value = |fact: &ExpressionFact| match fact.resolution {
        ExpressionResolution::Value(value) => Some(value),
        _ => fact.result,
    };
    let (Some(left_value), Some(right_value)) =
        (operand_value(left_fact), operand_value(right_fact))
    else {
        return false;
    };
    if left_fact.ty != right_fact.ty {
        return false;
    }
    let Some(SemanticTypeKind::Structure {
        declaration: struct_declaration,
        ..
    }) = analysis
        .types
        .get(left_fact.ty.0 as usize)
        .map(|record| &record.kind)
    else {
        return false;
    };
    let Some(instance) = analysis.functions.get(callee.0 as usize) else {
        return false;
    };
    let FunctionOrigin::Source {
        declaration: callee_declaration,
        ..
    } = instance.origin
    else {
        return false;
    };
    if crate::interfaces::receiver_concrete_struct(program, callee_declaration)
        != Some(*struct_declaration)
        || crate::interfaces::declaration_name(program, callee_declaration)
            != Some(operator.method_name())
        || instance.parameters.len() != 2
        || arguments.len() != 2
    {
        return false;
    }
    let (self_source, self_value, other_source, other_value) = if expected_swap {
        (1u32, right_value, 0u32, left_value)
    } else {
        (0u32, left_value, 1u32, right_value)
    };
    let expected = [
        (self_source, 0u32, self_value),
        (other_source, 1u32, other_value),
    ];
    for (argument, (source_index, parameter_index, value)) in arguments.iter().zip(expected) {
        let Some(parameter) = instance.parameters.get(parameter_index as usize) else {
            return false;
        };
        if argument.source_index != source_index
            || argument.parameter_index != parameter_index
            || argument.value != value
            || argument.access != parameter.access
        {
            return false;
        }
    }
    // Operand effects must be contained in the expression's recorded effects.
    if fact.effects.0 & (left_fact.effects.0 | right_fact.effects.0)
        != (left_fact.effects.0 | right_fact.effects.0)
    {
        return false;
    }
    let raw_value_valid = analysis
        .values
        .get(raw_result.0 as usize)
        .is_some_and(|value| value.function == function && value.ty == instance.result);
    if !raw_value_valid {
        return false;
    }
    if negate {
        // `<=`/`>=` write a distinct intermediate raw result and record the
        // logical NOT as the expression's own result.
        result != raw_result && fact.ty == instance.result
    } else {
        result == raw_result && fact.ty == instance.result
    }
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

#[allow(clippy::too_many_arguments)]
fn exact_derived_equality_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    operator: wrela_hir::ComparisonOperator,
    left_expression: ExpressionId,
    right_expression: ExpressionId,
    fact: &ExpressionFact,
    aggregate: SemanticTypeId,
    left: ValueId,
    right: ValueId,
    derived_fields: &[DerivedEqualityField],
    conjunctions: &[ValueId],
) -> bool {
    if !matches!(
        operator,
        wrela_hir::ComparisonOperator::Equal | wrela_hir::ComparisonOperator::NotEqual
    ) || aggregate.0 as usize >= analysis.types.len()
    {
        return false;
    }
    let (Some(left_fact), Some(right_fact)) = (
        exact_child_expression(analysis, function, left_expression),
        exact_child_expression(analysis, function, right_expression),
    ) else {
        return false;
    };
    let resolved_value = |child: &ExpressionFact| match child.resolution {
        ExpressionResolution::Value(value) => Some(value),
        _ => child.result,
    };
    let (Some(left_result), Some(right_result)) =
        (resolved_value(left_fact), resolved_value(right_fact))
    else {
        return false;
    };
    if left != left_result
        || right != right_result
        || left_fact.ty != aggregate
        || right_fact.ty != aggregate
        || fact.effects.0 != left_fact.effects.0 | right_fact.effects.0
        || !matches!(
            exact_scalar_type(analysis, fact.ty),
            Some(ExactScalarType::Bool)
        )
    {
        return false;
    }
    let Some(SemanticTypeKind::Structure {
        declaration,
        arguments,
        fields,
    }) = analysis
        .types
        .get(aggregate.0 as usize)
        .map(|record| &record.kind)
    else {
        return false;
    };
    if fields.is_empty()
        || derived_fields.len() != fields.len()
        || conjunctions.len() != fields.len().saturating_sub(1)
    {
        return false;
    }
    let source_matches = program
        .declaration(*declaration)
        .and_then(|record| match &record.kind {
            wrela_hir::DeclarationKind::Structure(source) => Some(source),
            _ => None,
        })
        .is_some_and(|source| {
            source.generics.is_empty()
                && source.fields.len() == fields.len()
                && source.deriving.iter().any(|name| name.as_str() == "Eq")
                && source.fields.iter().zip(fields).all(|(source, semantic)| {
                    source.name.as_str() == semantic.name
                        && exact_runtime_source_type(analysis, &source.ty) == Some(semantic.ty)
                })
        });
    let fact_source = program
        .expression(fact.expression)
        .map(|record| record.source);
    let value_matches = |value: ValueId, ty: SemanticTypeId| {
        analysis.values.get(value.0 as usize).is_some_and(|record| {
            record.function == function
                && record.ty == ty
                && record.category == ValueCategory::Value
                && record.class == SemanticValueClass::FirstClass
                && record.origin == SemanticValueOrigin::Expression(fact.expression)
                && record.source == fact_source
                && record.source_name.is_none()
        })
    };
    let result = match fact.result {
        Some(result) => result,
        None => return false,
    };
    let mut generated = Vec::new();
    if generated
        .try_reserve(
            derived_fields
                .len()
                .saturating_mul(3)
                .saturating_add(conjunctions.len()),
        )
        .is_err()
    {
        return false;
    }
    let fields_match =
        derived_fields
            .iter()
            .zip(fields)
            .enumerate()
            .all(|(index, (derived, semantic))| {
                let Ok(expected_index) = u32::try_from(index) else {
                    return false;
                };
                let comparison_is_result = fields.len() == 1
                    && operator == wrela_hir::ComparisonOperator::Equal
                    && derived.comparison == result;
                let matches = derived.field == expected_index
                    && value_matches(derived.left, semantic.ty)
                    && value_matches(derived.right, semantic.ty)
                    && (comparison_is_result || value_matches(derived.comparison, fact.ty));
                generated.extend([derived.left, derived.right, derived.comparison]);
                matches
            });
    let conjunctions_match = conjunctions.iter().enumerate().all(|(index, value)| {
        let final_equal_result = operator == wrela_hir::ComparisonOperator::Equal
            && index + 1 == conjunctions.len()
            && *value == result;
        generated.push(*value);
        final_equal_result || value_matches(*value, fact.ty)
    });
    let generated_are_distinct = generated.iter().enumerate().all(|(index, value)| {
        generated[index + 1..]
            .iter()
            .all(|candidate| candidate != value)
    });
    arguments.is_empty()
        && source_matches
        && fields
            .iter()
            .all(|field| exact_scalar_type(analysis, field.ty).is_some())
        && fields_match
        && conjunctions_match
        && generated_are_distinct
        && match operator {
            wrela_hir::ComparisonOperator::Equal => {
                conjunctions
                    .last()
                    .copied()
                    .unwrap_or(derived_fields[0].comparison)
                    == result
            }
            wrela_hir::ComparisonOperator::NotEqual => !generated.contains(&result),
            _ => false,
        }
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
    let arguments_match = |arguments: &[SemanticArgument]| {
        arguments.len() == argument_types.len()
            && arguments.iter().zip(&argument_types).all(|(argument, expected)| {
                matches!(argument, SemanticArgument::Type(actual) if actual == expected)
            })
    };
    let mut matches = analysis
        .types
        .iter()
        .filter(|candidate| match &candidate.kind {
            SemanticTypeKind::Enumeration {
                declaration: candidate_declaration,
                arguments,
                variants,
            } => {
                *candidate_declaration == declaration.declaration
                    && runtime_enum_arguments_supported(arguments, variants)
                    && arguments_match(arguments)
            }
            SemanticTypeKind::Structure {
                declaration: candidate_declaration,
                arguments,
                ..
            } => *candidate_declaration == declaration.declaration && arguments_match(arguments),
            _ => false,
        });
    let result = matches.next()?.id;
    matches.next().is_none().then_some(result)
}

fn exact_flat_structure_type_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    semantic: &SemanticType,
) -> bool {
    let SemanticTypeKind::Structure {
        declaration,
        arguments,
        fields,
    } = &semantic.kind
    else {
        return false;
    };
    let Some(source) = program.declaration(*declaration) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Structure(aggregate) = &source.kind else {
        return false;
    };
    if semantic.source != Some(source.source)
        || !aggregate.implements.is_empty()
        || aggregate.generics.len() != arguments.len()
        || aggregate.fields.len() != fields.len()
        || !runtime_structure_arguments_supported(analysis, arguments, fields)
    {
        return false;
    }
    for (generic_id, argument) in aggregate.generics.iter().zip(arguments) {
        let Some(generic) = program.generic_parameter(*generic_id) else {
            return false;
        };
        if generic.owner != *declaration
            || !matches!(
                generic.kind,
                wrela_hir::GenericParameterKind::Type { bound: None }
            )
            || !matches!(argument, SemanticArgument::Type(ty)
                if exact_stored_copy_scalar_layout(analysis, *ty).is_some())
        {
            return false;
        }
    }

    let mut size = 0_u64;
    let mut alignment = 1_u32;
    for (source_field, semantic_field) in aggregate.fields.iter().zip(fields) {
        if source_field.default.is_some()
            || !source_field.attributes.is_empty()
            || semantic_field.name != source_field.name.as_str()
            || semantic_field.public != (source_field.visibility != wrela_hir::Visibility::Private)
        {
            return false;
        }
        let expected = match &source_field.ty.kind {
            wrela_hir::TypeExpressionKind::Named {
                definition: wrela_hir::Definition::Builtin(_),
                arguments,
            } if arguments.is_empty() => exact_scalar_source_type(analysis, &source_field.ty),
            wrela_hir::TypeExpressionKind::Named {
                definition: wrela_hir::Definition::Generic(generic),
                arguments: source_arguments,
            } if source_arguments.is_empty() => aggregate
                .generics
                .iter()
                .position(|candidate| candidate == generic)
                .and_then(|position| arguments.get(position))
                .and_then(|argument| match argument {
                    SemanticArgument::Type(ty) => Some(*ty),
                    SemanticArgument::Constant(_) | SemanticArgument::Region(_) => None,
                }),
            _ => None,
        };
        if expected != Some(semantic_field.ty) {
            return false;
        }
        let Some((field_size, field_alignment)) =
            exact_stored_copy_scalar_layout(analysis, semantic_field.ty)
        else {
            return false;
        };
        let Some(mask) = u64::from(field_alignment).checked_sub(1) else {
            return false;
        };
        let Some(aligned) = size.checked_add(mask).map(|value| value & !mask) else {
            return false;
        };
        let Some(next) = aligned.checked_add(field_size) else {
            return false;
        };
        size = next;
        alignment = alignment.max(field_alignment);
    }
    let Some(mask) = u64::from(alignment).checked_sub(1) else {
        return false;
    };
    let Some(size) = size.checked_add(mask).map(|value| value & !mask) else {
        return false;
    };
    semantic.linearity
        == if aggregate.copy {
            Linearity::ScalarCopy
        } else {
            Linearity::ExplicitCopy
        }
        && semantic.size_upper_bound == Some(size)
        && semantic.alignment_lower_bound == alignment
}

fn exact_fixed_flat_structure_payload_type(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    source: &wrela_hir::TypeExpression,
) -> Option<SemanticTypeId> {
    let wrela_hir::TypeExpressionKind::Named {
        definition: wrela_hir::Definition::Declaration(resolved),
        arguments,
    } = &source.kind
    else {
        return None;
    };
    if !arguments.is_empty() {
        return None;
    }
    let mut matches = analysis.types.iter().filter(|semantic| {
        matches!(&semantic.kind, SemanticTypeKind::Structure {
            declaration,
            arguments,
            ..
        } if *declaration == resolved.declaration && arguments.is_empty())
            && exact_flat_structure_type_matches(analysis, program, semantic)
    });
    let ty = matches.next()?.id;
    matches.next().is_none().then_some(ty)
}

fn exact_generic_enum_payload_layout(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    ty: SemanticTypeId,
) -> Option<(u64, u32)> {
    exact_stored_copy_scalar_layout(analysis, ty).or_else(|| {
        let semantic = analysis.types.get(ty.0 as usize)?;
        matches!(&semantic.kind, SemanticTypeKind::Structure { arguments, .. } if arguments.is_empty())
            .then_some(())?;
        exact_flat_structure_type_matches(analysis, program, semantic).then_some((
            semantic.size_upper_bound?,
            semantic.alignment_lower_bound,
        ))
    })
}

fn exact_generic_enum_type_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    semantic: &SemanticType,
) -> bool {
    let SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    } = &semantic.kind
    else {
        return false;
    };
    let Some(source) = program.declaration(*declaration) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Enumeration(enumeration) = &source.kind else {
        return false;
    };
    if arguments.is_empty()
        || semantic.source != Some(source.source)
        || enumeration.generics.len() != arguments.len()
        || enumeration.variants.len() != variants.len()
        || enumeration.variants.is_empty()
        || enumeration.variants.len() > 256
        || semantic.linearity != Linearity::ExplicitCopy
    {
        return false;
    }
    for (generic_id, argument) in enumeration.generics.iter().zip(arguments) {
        let Some(generic) = program.generic_parameter(*generic_id) else {
            return false;
        };
        if generic.owner != *declaration
            || !matches!(
                generic.kind,
                wrela_hir::GenericParameterKind::Type { bound: None }
            )
            || !matches!(argument, SemanticArgument::Type(ty)
                if exact_stored_copy_scalar_layout(analysis, *ty).is_some())
        {
            return false;
        }
    }
    let mut payload_slot: Option<(u64, u32)> = None;
    for (source_variant, semantic_variant) in enumeration.variants.iter().zip(variants) {
        if semantic_variant.name != source_variant.name.as_str() {
            return false;
        }
        let expected = match source_variant.fields.as_slice() {
            [] => None,
            [field] if field.name.is_none() => match &field.ty.kind {
                wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(_),
                    arguments: source_arguments,
                } if source_arguments.is_empty() => exact_scalar_source_type(analysis, &field.ty),
                wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Generic(generic),
                    arguments: source_arguments,
                } if source_arguments.is_empty() => enumeration
                    .generics
                    .iter()
                    .position(|candidate| candidate == generic)
                    .and_then(|position| arguments.get(position))
                    .and_then(|argument| match argument {
                        SemanticArgument::Type(ty) => Some(*ty),
                        SemanticArgument::Constant(_) | SemanticArgument::Region(_) => None,
                    }),
                wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Declaration(_),
                    arguments: source_arguments,
                } if source_arguments.is_empty() => {
                    exact_fixed_flat_structure_payload_type(analysis, program, &field.ty)
                }
                _ => None,
            },
            _ => return false,
        };
        match (expected, semantic_variant.fields.as_slice()) {
            (None, []) if source_variant.fields.is_empty() => {}
            (Some(expected), [field])
                if field.name.is_empty() && field.public && field.ty == expected =>
            {
                let Some((size, alignment)) =
                    exact_generic_enum_payload_layout(analysis, program, expected)
                else {
                    return false;
                };
                payload_slot = Some(match payload_slot {
                    None => (size, alignment),
                    Some((current_size, current_alignment)) => {
                        (current_size.max(size), current_alignment.max(alignment))
                    }
                });
            }
            _ => return false,
        }
    }
    let (size, alignment) = match payload_slot {
        None => (1_u64, 1_u32),
        Some((payload_size, alignment)) => {
            let mask = u64::from(alignment).checked_sub(1);
            let Some(offset) = mask.and_then(|mask| 1_u64.checked_add(mask).map(|v| v & !mask))
            else {
                return false;
            };
            let Some(size) = offset
                .checked_add(payload_size)
                .and_then(|value| value.checked_add(u64::from(alignment) - 1))
                .map(|value| value & !(u64::from(alignment) - 1))
            else {
                return false;
            };
            (size, alignment)
        }
    };
    semantic.size_upper_bound == Some(size) && semantic.alignment_lower_bound == alignment
}

fn exact_core_async_exit_declarations(
    program: &wrela_hir::Program,
) -> Option<(DeclarationId, [DeclarationId; 3])> {
    let core_package = program
        .packages
        .package(program.packages.root())?
        .dependencies
        .iter()
        .find(|dependency| dependency.alias.as_str() == "core")?
        .package;
    let mut outcome = None;
    let mut causes = [None, None, None];
    for declaration in &program.declarations {
        let module = program.modules.get(declaration.module.0 as usize)?;
        if module.package != core_package || module.path.dotted() != "actor" {
            continue;
        }
        let slot = match declaration.name.as_ref().map(wrela_hir::Name::as_str) {
            Some("AsyncExit") => &mut outcome,
            Some("Cancelled") => &mut causes[0],
            Some("DeadlineRejected") => &mut causes[1],
            Some("DeadlineExceeded") => &mut causes[2],
            _ => continue,
        };
        if slot.replace(declaration.id).is_some() {
            return None;
        }
    }
    Some((outcome?, [causes[0]?, causes[1]?, causes[2]?]))
}

fn exact_core_async_exit_type_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    semantic: &SemanticType,
) -> bool {
    let Some((outcome_id, cause_ids)) = exact_core_async_exit_declarations(program) else {
        return false;
    };
    let exact_cause_source = |id| {
        program.declaration(id).is_some_and(|record| {
            record.visibility == wrela_hir::Visibility::Public
                && matches!(&record.kind, wrela_hir::DeclarationKind::Structure(aggregate)
                    if aggregate.generics.is_empty()
                        && aggregate.implements.is_empty()
                        && aggregate.fields.is_empty()
                        && aggregate.members.is_empty()
                        && !aggregate.linear
                        && !aggregate.copy
                        && aggregate.deriving.is_empty())
        })
    };
    if !cause_ids.iter().copied().all(exact_cause_source) {
        return false;
    }
    let Some(source) = program.declaration(outcome_id) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Enumeration(enumeration) = &source.kind else {
        return false;
    };
    let [generic] = enumeration.generics.as_slice() else {
        return false;
    };
    let Some(parameter) = program.generic_parameter(*generic) else {
        return false;
    };
    let exact_source_field = |variant: &wrela_hir::EnumVariant,
                              name: &str,
                              expected_generic: bool,
                              expected_cause: DeclarationId| {
        variant.name.as_str() == name
            && matches!(variant.fields.as_slice(), [field]
            if field.name.is_none()
                && if expected_generic {
                    matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                        definition: wrela_hir::Definition::Generic(candidate),
                        arguments,
                    } if *candidate == *generic && arguments.is_empty())
                } else {
                    matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                        definition: wrela_hir::Definition::Declaration(candidate),
                        arguments,
                    } if candidate.declaration == expected_cause && arguments.is_empty())
                })
    };
    let exact_source = source.visibility == wrela_hir::Visibility::Public
        && parameter.owner == outcome_id
        && matches!(
            parameter.kind,
            wrela_hir::GenericParameterKind::Type { bound: None }
        )
        && enumeration.members.is_empty()
        && enumeration.deriving.is_empty()
        && matches!(enumeration.variants.as_slice(), [operation, cancelled, rejected, exceeded]
            if exact_source_field(operation, "Operation", true, cause_ids[0])
                && exact_source_field(cancelled, "Cancelled", false, cause_ids[0])
                && exact_source_field(rejected, "DeadlineRejected", false, cause_ids[1])
                && exact_source_field(exceeded, "DeadlineExceeded", false, cause_ids[2]));
    if !exact_source {
        return false;
    }
    let SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    } = &semantic.kind
    else {
        return false;
    };
    let [SemanticArgument::Type(error)] = arguments.as_slice() else {
        return false;
    };
    let cause_type = |declaration| {
        let mut matches = analysis.types.iter().filter(|ty| {
            ty.kind
                == (SemanticTypeKind::Structure {
                    declaration,
                    arguments: Vec::new(),
                    fields: Vec::new(),
                })
                && ty.linearity == Linearity::ExplicitCopy
                && ty.size_upper_bound == Some(0)
                && ty.alignment_lower_bound == 1
                && ty.source == program.declaration(declaration).map(|record| record.source)
        });
        let id = matches.next().map(|ty| ty.id)?;
        matches.next().is_none().then_some(id)
    };
    let Some(cause_types) = cause_type(cause_ids[0])
        .zip(cause_type(cause_ids[1]))
        .zip(cause_type(cause_ids[2]))
        .map(|((left, middle), right)| [left, middle, right])
    else {
        return false;
    };
    *declaration == outcome_id
        && exact_stored_copy_scalar_layout(analysis, *error) == Some((8, 8))
        && semantic.linearity == Linearity::ExplicitCopy
        && semantic.size_upper_bound == Some(16)
        && semantic.alignment_lower_bound == 8
        && semantic.source == Some(source.source)
        && matches!(variants.as_slice(), [operation, cancelled, rejected, exceeded]
            if operation.name == "Operation"
                && matches!(operation.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == *error)
                && cancelled.name == "Cancelled"
                && matches!(cancelled.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == cause_types[0])
                && rejected.name == "DeadlineRejected"
                && matches!(rejected.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == cause_types[1])
                && exceeded.name == "DeadlineExceeded"
                && matches!(exceeded.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == cause_types[2]))
}

fn exact_core_async_result_type_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    semantic: &SemanticType,
) -> bool {
    let SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    } = &semantic.kind
    else {
        return false;
    };
    let [SemanticArgument::Type(ok), SemanticArgument::Type(err)] = arguments.as_slice() else {
        return false;
    };
    exact_core_result_declaration_matches(program, *declaration)
        && exact_stored_copy_scalar_layout(analysis, *ok) == Some((8, 8))
        && analysis.types.get(err.0 as usize).is_some_and(|ty| {
            exact_core_async_exit_type_matches(analysis, program, ty)
                && matches!(&ty.kind, SemanticTypeKind::Enumeration { arguments, .. }
                    if arguments.as_slice() == [SemanticArgument::Type(*ok)])
        })
        && semantic.linearity == Linearity::ExplicitCopy
        && semantic.size_upper_bound == Some(24)
        && semantic.alignment_lower_bound == 8
        && semantic.source
            == program
                .declaration(*declaration)
                .map(|record| record.source)
        && matches!(variants.as_slice(), [ok_variant, err_variant]
            if ok_variant.name == "Ok"
                && matches!(ok_variant.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == *ok)
                && err_variant.name == "Err"
                && matches!(err_variant.fields.as_slice(), [field]
                    if field.name.is_empty() && field.public && field.ty == *err))
}

fn exact_stored_copy_scalar_layout(
    analysis: &PartialAnalysis,
    ty: SemanticTypeId,
) -> Option<(u64, u32)> {
    let record = analysis.types.get(ty.0 as usize)?;
    if record.linearity != Linearity::ScalarCopy || record.source.is_some() {
        return None;
    }
    let bytes = match record.kind {
        SemanticTypeKind::Bool => 1_u64,
        SemanticTypeKind::Integer { bits, .. } => u64::from(bits.div_ceil(8)),
        SemanticTypeKind::Float { bits: 32 } => 4,
        SemanticTypeKind::Float { bits: 64 } => 8,
        _ => return None,
    };
    let alignment = u32::try_from(bytes).ok()?;
    (record.size_upper_bound == Some(bytes) && record.alignment_lower_bound == alignment)
        .then_some((bytes, alignment))
}

fn stored_copy_scalar_specialization_code(
    analysis: &PartialAnalysis,
    ty: SemanticTypeId,
) -> Option<u8> {
    exact_stored_copy_scalar_layout(analysis, ty)?;
    Some(match analysis.types.get(ty.0 as usize)?.kind {
        SemanticTypeKind::Bool => 1,
        SemanticTypeKind::Integer {
            signed: false,
            bits: 8,
            pointer_sized: false,
        } => 2,
        SemanticTypeKind::Integer {
            signed: false,
            bits: 16,
            pointer_sized: false,
        } => 3,
        SemanticTypeKind::Integer {
            signed: false,
            bits: 32,
            pointer_sized: false,
        } => 4,
        SemanticTypeKind::Integer {
            signed: false,
            bits: 64,
            pointer_sized: false,
        } => 5,
        SemanticTypeKind::Integer {
            signed: false,
            bits: 128,
            pointer_sized: false,
        } => 6,
        SemanticTypeKind::Integer {
            signed: false,
            pointer_sized: true,
            ..
        } => 7,
        SemanticTypeKind::Integer {
            signed: true,
            bits: 8,
            pointer_sized: false,
        } => 8,
        SemanticTypeKind::Integer {
            signed: true,
            bits: 16,
            pointer_sized: false,
        } => 9,
        SemanticTypeKind::Integer {
            signed: true,
            bits: 32,
            pointer_sized: false,
        } => 10,
        SemanticTypeKind::Integer {
            signed: true,
            bits: 64,
            pointer_sized: false,
        } => 11,
        SemanticTypeKind::Integer {
            signed: true,
            bits: 128,
            pointer_sized: false,
        } => 12,
        SemanticTypeKind::Integer {
            signed: true,
            pointer_sized: true,
            ..
        } => 13,
        SemanticTypeKind::Float { bits: 32 } => 14,
        SemanticTypeKind::Float { bits: 64 } => 15,
        _ => return None,
    })
}

fn source_function_specialization_key(
    request: Sha256Digest,
    declaration: DeclarationId,
    arguments: &[SemanticArgument],
    analysis: &PartialAnalysis,
) -> Option<FunctionKey> {
    const HEADER_BYTES: usize = 6;
    let mut bytes = *request.as_bytes();
    if arguments.is_empty() || arguments.len() > bytes.len().checked_sub(HEADER_BYTES)? {
        return None;
    }
    bytes[0] ^= 0x47;
    for (destination, source) in bytes[1..5].iter_mut().zip(declaration.0.to_be_bytes()) {
        *destination ^= source;
    }
    bytes[5] ^= u8::try_from(arguments.len()).ok()?;
    for (index, argument) in arguments.iter().enumerate() {
        let SemanticArgument::Type(ty) = argument else {
            return None;
        };
        if let Some(code) = stored_copy_scalar_specialization_code(analysis, *ty) {
            bytes[HEADER_BYTES + index] ^= code;
        } else if arguments.len() == 1 {
            let declaration = exact_generic_function_flat_argument(analysis, *ty)?;
            bytes[HEADER_BYTES] ^= 0x80;
            for (destination, source) in bytes[HEADER_BYTES + 1..HEADER_BYTES + 5]
                .iter_mut()
                .zip(declaration.0.to_be_bytes())
            {
                *destination ^= source;
            }
        } else {
            return None;
        }
    }
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 0x47;
    }
    Some(FunctionKey(Sha256Digest::from_bytes(bytes)))
}

pub(crate) fn exact_generic_function_flat_argument(
    analysis: &PartialAnalysis,
    ty: SemanticTypeId,
) -> Option<DeclarationId> {
    let record = analysis.types.get(ty.0 as usize)?;
    let SemanticTypeKind::Structure {
        declaration,
        arguments,
        fields,
    } = &record.kind
    else {
        return None;
    };
    if !arguments.is_empty()
        || fields.len() != 2
        || record.linearity != Linearity::ExplicitCopy
        || record.size_upper_bound.is_none()
        || record.alignment_lower_bound == 0
        || !record.alignment_lower_bound.is_power_of_two()
        || fields
            .iter()
            .any(|field| exact_stored_copy_scalar_layout(analysis, field.ty).is_none())
    {
        return None;
    }
    Some(*declaration)
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
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    operand: ExpressionId,
    await_fact: &ExpressionFact,
) -> bool {
    analysis
        .expressions
        .binary_search_by_key(&(function, operand), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| analysis.expressions.get(index))
        .is_some_and(|operand| {
            operand.result.is_some()
                && await_fact.effects == EffectSet(operand.effects.0 | EffectSet::SUSPEND)
                && await_fact.ownership_before == OwnershipState::Owned
                && await_fact.ownership_after == OwnershipState::Owned
                && match operand.resolution {
                    ExpressionResolution::DirectCall {
                        function: target, ..
                    } => {
                        analysis
                            .functions
                            .get(target.0 as usize)
                            .is_some_and(|target| {
                                target.color == FunctionColor::Async
                                    && target.result == operand.ty
                                    && if exact_declared_fallible_u64_result(
                                        analysis,
                                        program,
                                        target.result,
                                    ) {
                                        analysis.types.get(await_fact.ty.0 as usize).is_some_and(
                                            |ty| {
                                                exact_core_async_result_type_matches(
                                                    analysis, program, ty,
                                                )
                                            },
                                        ) && await_fact.result.is_some_and(|result| {
                                            analysis.values.get(result.0 as usize).is_some_and(
                                                |value| {
                                                    value.class
                                                        == SemanticValueClass::Ephemeral(
                                                            EphemeralKind::AsyncOutcome,
                                                        )
                                                },
                                            )
                                        }) && exact_async_outcome_hir_use(
                                            program,
                                            await_fact.expression,
                                        )
                                    } else {
                                        operand.ty == await_fact.ty
                                    }
                            })
                    }
                    ExpressionResolution::ActorRequest {
                        method: target,
                        reply: Some(_),
                        ..
                    } => {
                        operand.ty == await_fact.ty
                            && analysis
                                .functions
                                .get(target.0 as usize)
                                .is_some_and(|target| target.color == FunctionColor::Async)
                    }
                    _ => false,
                }
        })
}

fn exact_declared_fallible_u64_result(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    ty: SemanticTypeId,
) -> bool {
    analysis.types.get(ty.0 as usize).is_some_and(|record| {
        matches!(&record.kind, SemanticTypeKind::Enumeration {
            declaration,
            arguments,
            variants,
        } if exact_core_result_declaration_matches(program, *declaration)
            && matches!(arguments.as_slice(), [SemanticArgument::Type(ok), SemanticArgument::Type(err)]
                if ok == err && exact_stored_copy_scalar_layout(analysis, *ok) == Some((8, 8)))
            && matches!(variants.as_slice(), [ok, err]
                if ok.name == "Ok" && err.name == "Err"
                    && matches!((ok.fields.as_slice(), err.fields.as_slice()), ([ok], [err])
                        if ok.ty == err.ty)))
    })
}

fn exact_async_outcome_hir_use(program: &wrela_hir::Program, expression: ExpressionId) -> bool {
    let matches = program
        .statements
        .iter()
        .filter(|statement| {
            matches!(statement.kind, wrela_hir::StatementKind::Match { scrutinee, .. }
            if scrutinee == expression)
        })
        .count();
    let tests = program
        .expressions
        .iter()
        .filter(|parent| {
            matches!(parent.kind, wrela_hir::ExpressionKind::IsPattern { value, .. }
            if value == expression)
        })
        .count();
    matches + tests == 1
        && (tests == 1 || exact_async_outcome_nested_match_hir(program, expression))
        && !program.expressions.iter().any(|parent| {
            matches!(parent.kind, wrela_hir::ExpressionKind::Try(operand) if operand == expression)
        })
}

fn exact_async_outcome_nested_match_hir(
    program: &wrela_hir::Program,
    expression: ExpressionId,
) -> bool {
    let mut outer = program
        .statements
        .iter()
        .filter_map(|statement| match &statement.kind {
            wrela_hir::StatementKind::Match { scrutinee, arms } if *scrutinee == expression => {
                Some(arms)
            }
            _ => None,
        });
    let Some(arms) = outer.next() else {
        return false;
    };
    if outer.next().is_some() || arms.len() != 2 {
        return false;
    }
    let mut ok_seen = false;
    let mut err = None;
    for arm in arms {
        if arm.guard.is_some() {
            return false;
        }
        let Some((candidate, arguments)) = exact_async_constructor_pattern(program, arm.pattern)
        else {
            return false;
        };
        if program
            .declaration(candidate.enumeration.declaration)
            .and_then(|declaration| declaration.name.as_ref())
            .map(wrela_hir::Name::as_str)
            != Some("Result")
            || arguments.len() != 1
        {
            return false;
        }
        match candidate.variant {
            0 if !ok_seen => ok_seen = true,
            1 if err.is_none() => {
                let Some(binding) = exact_async_constructor_binding(program, &arguments[0]) else {
                    return false;
                };
                err = Some((binding, arm.body));
            }
            _ => return false,
        }
    }
    let Some((binding, body)) = err else {
        return false;
    };
    let Some(body) = program.body(body) else {
        return false;
    };
    let [statement] = body.statements.as_slice() else {
        return false;
    };
    let Some(wrela_hir::StatementKind::Match { scrutinee, arms }) = program
        .statement(*statement)
        .map(|statement| &statement.kind)
    else {
        return false;
    };
    if !program.expression(*scrutinee).is_some_and(|expression| {
        expression.kind
            == wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(binding))
    }) || arms.len() != 4
    {
        return false;
    }
    arms.iter().enumerate().all(|(index, arm)| {
        if arm.guard.is_some() {
            return false;
        }
        exact_async_constructor_pattern(program, arm.pattern).is_some_and(
            |(candidate, arguments)| {
                candidate.variant as usize == index
                    && arguments.len() == 1
                    && program
                        .declaration(candidate.enumeration.declaration)
                        .and_then(|declaration| declaration.name.as_ref())
                        .map(wrela_hir::Name::as_str)
                        == Some("AsyncExit")
            },
        )
    })
}

fn exact_async_constructor_pattern(
    program: &wrela_hir::Program,
    pattern: wrela_hir::PatternId,
) -> Option<(&wrela_hir::ResolvedVariant, &[wrela_hir::PatternArgument])> {
    let pattern = program.patterns.get(pattern.0 as usize)?;
    let [alternative] = pattern.alternatives.as_slice() else {
        return None;
    };
    let wrela_hir::PrimaryPattern::Constructor {
        candidates,
        arguments,
        ..
    } = &alternative.kind
    else {
        return None;
    };
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some((candidate, arguments))
}

fn exact_async_constructor_binding(
    program: &wrela_hir::Program,
    argument: &wrela_hir::PatternArgument,
) -> Option<wrela_hir::LocalId> {
    if argument.take {
        return None;
    }
    let pattern = program.patterns.get(argument.pattern.0 as usize)?;
    let [alternative] = pattern.alternatives.as_slice() else {
        return None;
    };
    match alternative.kind {
        wrela_hir::PrimaryPattern::Bind(local) => Some(local),
        _ => None,
    }
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

#[allow(clippy::too_many_arguments)]
fn validate_exact_fixed_array_match_statement(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    fact: &StatementFact,
    arms: &[wrela_hir::MatchArm],
    element_ty: SemanticTypeId,
    length: u64,
    definitions: &mut [u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
    let element_kind = analysis
        .types
        .get(element_ty.0 as usize)
        .filter(|record| record.linearity == Linearity::ScalarCopy)
        .map(|record| &record.kind)
        .ok_or_else(|| invalid("fixed-array match element type is missing"))?;
    if !matches!(
        element_kind,
        SemanticTypeKind::Bool
            | SemanticTypeKind::Integer {
                signed: true,
                bits: 64,
                pointer_sized: false,
            }
    ) {
        return Err(invalid("fixed-array match element type is not canonical"));
    }
    let arity = usize::try_from(length)
        .map_err(|_| invalid("fixed-array match length is not representable"))?;
    let mut definition_index = 0usize;
    let mut exhaustive = false;
    for arm in arms {
        check_analysis_cancelled(is_cancelled)?;
        if exhaustive || arm.guard.is_some() {
            return Err(invalid("fixed-array match coverage differs from HIR"));
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
            .ok_or_else(|| invalid("fixed-array match arm pattern scope differs from HIR"))?;
        let [alternative] = pattern.alternatives.as_slice() else {
            return Err(invalid("fixed-array match arm is not one exact pattern"));
        };
        match &alternative.kind {
            wrela_hir::PrimaryPattern::Wildcard => exhaustive = true,
            wrela_hir::PrimaryPattern::Array(arguments) => {
                if arguments.len() != arity {
                    return Err(invalid("fixed-array match pattern arity differs from type"));
                }
                let mut irrefutable = true;
                let mut arm_bindings = fallible_scratch::<wrela_hir::LocalId>(arity, 256)?;
                for argument in arguments {
                    check_analysis_cancelled(is_cancelled)?;
                    if argument.take {
                        return Err(invalid("fixed-array match element unexpectedly takes"));
                    }
                    let child = program
                        .patterns
                        .get(argument.pattern.0 as usize)
                        .filter(|pattern| pattern.id == argument.pattern)
                        .ok_or_else(|| invalid("fixed-array element pattern is missing"))?;
                    let [child] = child.alternatives.as_slice() else {
                        return Err(invalid("fixed-array element pattern is not exact"));
                    };
                    match &child.kind {
                        wrela_hir::PrimaryPattern::Wildcard => {}
                        wrela_hir::PrimaryPattern::Bind(local) => {
                            if arm_bindings.contains(local) {
                                return Err(invalid("fixed-array element binding is duplicated"));
                            }
                            arm_bindings.push(*local);
                            let definition =
                                fact.definitions.get(definition_index).ok_or_else(|| {
                                    invalid("fixed-array element binding definition is missing")
                                })?;
                            definition_index += 1;
                            let local_record = program
                                .locals
                                .get(local.0 as usize)
                                .filter(|record| record.id == *local && record.body == arm.body)
                                .ok_or_else(|| {
                                    invalid("fixed-array element binding differs from arm body")
                                })?;
                            let value_record = analysis
                                .values
                                .get(definition.value.0 as usize)
                                .filter(|record| {
                                    definition.local == *local
                                        && record.function == function.id
                                        && record.ty == element_ty
                                        && record.category == ValueCategory::Value
                                        && record.class == SemanticValueClass::FirstClass
                                        && record.origin == SemanticValueOrigin::Local(*local)
                                        && record.source == Some(local_record.source)
                                        && record.source_name.as_deref()
                                            == Some(local_record.name.as_str())
                                })
                                .ok_or_else(|| {
                                    invalid("fixed-array element binding provenance is invalid")
                                })?;
                            if analysis.expressions.iter().any(|expression| {
                                expression.function == function.id
                                    && expression.result == Some(value_record.id)
                            }) {
                                return Err(invalid(
                                    "fixed-array element binding is an expression result",
                                ));
                            }
                            increment_definition(definitions, definition.value)?;
                        }
                        wrela_hir::PrimaryPattern::Literal { negative, literal } => {
                            irrefutable = false;
                            let exact = match (element_kind, literal) {
                                (SemanticTypeKind::Bool, wrela_hir::Literal::Boolean(_)) => {
                                    !*negative
                                }
                                (
                                    SemanticTypeKind::Integer {
                                        signed: true,
                                        bits: 64,
                                        pointer_sized: false,
                                    },
                                    wrela_hir::Literal::Integer(spelling),
                                ) => {
                                    !*negative
                                        && parse_hir_integer(spelling)
                                            .is_some_and(|value| value <= i64::MAX as u128)
                                }
                                _ => false,
                            };
                            if !exact {
                                return Err(invalid(
                                    "fixed-array pattern literal differs from element type",
                                ));
                            }
                        }
                        _ => {
                            return Err(invalid(
                                "fixed-array element pattern is outside the exact scalar subset",
                            ));
                        }
                    }
                }
                exhaustive = irrefutable;
            }
            _ => return Err(invalid("fixed-array match arm shape differs from HIR")),
        }
    }
    if !exhaustive || definition_index != fact.definitions.len() {
        return Err(invalid(
            "fixed-array match coverage or binding definitions are incomplete",
        ));
    }
    Ok(())
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
            if let wrela_hir::Definition::Parameter(receiver) = target.root {
                let expression = exact_child_expression(analysis, function.id, *value)
                    .ok_or_else(|| invalid("actor state assignment expression fact is missing"))?;
                if !fact.definitions.is_empty()
                    || !exact_actor_state_write_matches(
                        analysis,
                        function.id,
                        fact.statement,
                        receiver,
                        *value,
                        expression.result,
                    )
                {
                    return Err(invalid(
                        "actor state assignment differs from exact HIR storage access",
                    ));
                }
                if let Some((current, result)) =
                    exact_actor_state_compound_results(analysis, function.id, fact.statement)
                {
                    increment_definition(definitions, current)?;
                    increment_definition(definitions, result)?;
                }
            } else {
                let wrela_hir::Definition::Local(local) = &target.root else {
                    return Err(invalid("scalar assignment target is not a local"));
                };
                let [definition] = fact.definitions.as_slice() else {
                    return Err(invalid("assignment lacks one exact definition"));
                };
                let expression = analysis
                    .expressions
                    .binary_search_by_key(&(function.id, *value), |fact| {
                        (fact.function, fact.expression)
                    })
                    .ok()
                    .and_then(|index| analysis.expressions.get(index))
                    .ok_or_else(|| invalid("assignment expression fact is missing"))?;
                let local_record = program
                    .locals
                    .get(local.0 as usize)
                    .filter(|record| record.id == *local)
                    .ok_or_else(|| invalid("assignment local is invalid"))?;
                let value_record = analysis
                    .values
                    .get(definition.value.0 as usize)
                    .ok_or_else(|| invalid("assignment value is invalid"))?;
                if !target.projections.is_empty() {
                    let [wrela_hir::PlaceProjection::Field(field_name)] =
                        target.projections.as_slice()
                    else {
                        return Err(invalid(
                            "projected assignment target is not one direct field",
                        ));
                    };
                    if *operator != wrela_hir::AssignmentOperator::Assign {
                        return Err(invalid("projected assignment operator is not plain assign"));
                    }
                    let Some(SemanticTypeKind::Structure {
                        arguments, fields, ..
                    }) = analysis
                        .types
                        .get(value_record.ty.0 as usize)
                        .map(|record| &record.kind)
                    else {
                        return Err(invalid(
                            "projected assignment value is not a flat structure",
                        ));
                    };
                    if !runtime_structure_arguments_supported(analysis, arguments, fields) {
                        return Err(invalid(
                            "projected assignment structure is not the supported flat scalar shape",
                        ));
                    }
                    let mut selected = None;
                    for (index, field) in fields.iter().enumerate() {
                        check_analysis_cancelled(is_cancelled)?;
                        if field.name == field_name.as_str() && selected.replace(index).is_some() {
                            return Err(invalid("projected assignment field is ambiguous"));
                        }
                    }
                    let field = selected
                        .and_then(|index| fields.get(index))
                        .ok_or_else(|| invalid("projected assignment field is missing"))?;
                    if definition.local != *local
                        || expression.ty != field.ty
                        || !exact_expression_produces_value(expression)
                        || expression.result == Some(definition.value)
                        || analysis.expressions.iter().any(|expression| {
                            expression.function == function.id
                                && expression.result == Some(definition.value)
                        })
                        || value_record.function != function.id
                        || value_record.origin != SemanticValueOrigin::Local(*local)
                        || value_record.source != Some(local_record.source)
                        || value_record.source_name.as_deref() != Some(local_record.name.as_str())
                        || exact_runtime_source_type(
                            analysis,
                            local_record.ty.as_ref().ok_or_else(|| {
                                invalid("projected assignment local lacks a type")
                            })?,
                        ) != Some(value_record.ty)
                    {
                        return Err(invalid("projected assignment binding differs from HIR"));
                    }
                    increment_definition(definitions, definition.value)?;
                } else {
                    let compound = *operator != wrela_hir::AssignmentOperator::Assign;
                    let expression_binding_matches = if compound {
                        expression.result != Some(definition.value)
                            && expression.ty == value_record.ty
                            && analysis
                                .types
                                .get(value_record.ty.0 as usize)
                                .is_some_and(|ty| {
                                    matches!(ty.kind, SemanticTypeKind::Integer { .. })
                                })
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
            if let Some((element, length)) = analysis
                .types
                .get(scrutinee_fact.ty.0 as usize)
                .and_then(|record| match record.kind {
                    SemanticTypeKind::Array { element, length } => Some((element, length)),
                    _ => None,
                })
            {
                validate_exact_fixed_array_match_statement(
                    analysis,
                    program,
                    function,
                    fact,
                    arms,
                    element,
                    length,
                    definitions,
                    is_cancelled,
                )?;
                return validate_exact_statement_post_state(
                    analysis,
                    program,
                    function,
                    fact,
                    exactly_taken,
                    statement.body,
                    is_cancelled,
                );
            }
            let (enumeration, variant_count) = analysis
                .types
                .get(scrutinee_fact.ty.0 as usize)
                .and_then(|record| match &record.kind {
                    SemanticTypeKind::Enumeration {
                        declaration,
                        arguments,
                        variants,
                    } if runtime_enum_arguments_supported(arguments, variants)
                        && !variants.is_empty() =>
                    {
                        Some((*declaration, variants.len()))
                    }
                    _ => None,
                })
                .ok_or_else(|| invalid("enum match scrutinee type is not canonical"))?;
            let mut covered = fallible_scratch::<bool>(variant_count, 256)?;
            covered.resize(variant_count, false);
            let mut definition_index = 0usize;
            let mut seen_wildcard = false;
            for (arm_index, arm) in arms.iter().enumerate() {
                check_analysis_cancelled(is_cancelled)?;
                if seen_wildcard {
                    return Err(invalid("enum match arm follows a catch-all wildcard"));
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
                if pattern.alternatives.len() > 1 {
                    if arm.guard.is_some() {
                        return Err(invalid("guarded enum match alternatives are not canonical"));
                    }
                    let mut shared_binding: Option<(wrela_hir::LocalId, SemanticTypeId)> = None;
                    let mut saw_unit_variant = false;
                    for alternative in &pattern.alternatives {
                        check_analysis_cancelled(is_cancelled)?;
                        let wrela_hir::PrimaryPattern::Constructor {
                            candidates,
                            arguments,
                            ..
                        } = &alternative.kind
                        else {
                            return Err(invalid(
                                "enum match alternative is not a unit constructor",
                            ));
                        };
                        let [candidate] = candidates.as_slice() else {
                            return Err(invalid("enum match alternative constructor is not exact"));
                        };
                        let variant = usize::try_from(candidate.variant)
                            .map_err(|_| invalid("enum match alternative variant is invalid"))?;
                        let exact_constructor = program
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
                            .is_some();
                        let payload_ty = analysis
                            .types
                            .get(scrutinee_fact.ty.0 as usize)
                            .and_then(|record| match &record.kind {
                                SemanticTypeKind::Enumeration { variants, .. } => variants
                                    .get(variant)
                                    .map(|variant| variant.fields.first().map(|field| field.ty)),
                                _ => None,
                            })
                            .ok_or_else(|| {
                                invalid("enum match alternative payload type is missing")
                            })?;
                        if !exact_constructor || variant >= variant_count || covered[variant] {
                            return Err(invalid(
                                "enum match alternative coverage differs from HIR",
                            ));
                        }
                        match payload_ty {
                            None => {
                                if !arguments.is_empty() || shared_binding.is_some() {
                                    return Err(invalid(
                                        "enum match unit alternative binding differs from HIR",
                                    ));
                                }
                                saw_unit_variant = true;
                            }
                            Some(payload_ty) => {
                                if saw_unit_variant {
                                    return Err(invalid(
                                        "enum match alternatives mix unit and payload variants",
                                    ));
                                }
                                let [argument] = arguments.as_slice() else {
                                    return Err(invalid(
                                        "enum match alternative payload arity differs",
                                    ));
                                };
                                if argument.take {
                                    return Err(invalid(
                                        "enum match alternative payload unexpectedly takes ownership",
                                    ));
                                }
                                let payload_pattern = program
                                    .patterns
                                    .get(argument.pattern.0 as usize)
                                    .filter(|pattern| pattern.id == argument.pattern)
                                    .ok_or_else(|| {
                                        invalid("enum match alternative payload pattern is missing")
                                    })?;
                                let [payload_alternative] = payload_pattern.alternatives.as_slice()
                                else {
                                    return Err(invalid(
                                        "enum match alternative payload is not one binding",
                                    ));
                                };
                                let wrela_hir::PrimaryPattern::Bind(local) =
                                    payload_alternative.kind
                                else {
                                    return Err(invalid(
                                        "enum match alternative payload is not a shared local",
                                    ));
                                };
                                if shared_binding.is_some_and(|(existing, ty)| {
                                    existing != local || ty != payload_ty
                                }) {
                                    return Err(invalid(
                                        "enum match alternative shared payload differs from HIR",
                                    ));
                                }
                                shared_binding = Some((local, payload_ty));
                            }
                        }
                        covered[variant] = true;
                    }
                    if let Some((local, payload_ty)) = shared_binding {
                        let definition =
                            fact.definitions.get(definition_index).ok_or_else(|| {
                                invalid("enum match alternative payload definition is missing")
                            })?;
                        definition_index += 1;
                        let local_record = program
                            .locals
                            .get(local.0 as usize)
                            .filter(|record| record.id == local && record.body == arm.body)
                            .ok_or_else(|| {
                                invalid("enum match alternative payload local differs from body")
                            })?;
                        let value_record = analysis
                            .values
                            .get(definition.value.0 as usize)
                            .filter(|record| {
                                definition.local == local
                                    && record.function == function.id
                                    && record.ty == payload_ty
                                    && record.origin == SemanticValueOrigin::Local(local)
                                    && record.source == Some(local_record.source)
                                    && record.source_name.as_deref()
                                        == Some(local_record.name.as_str())
                            })
                            .ok_or_else(|| {
                                invalid("enum match alternative payload provenance is invalid")
                            })?;
                        if analysis.expressions.iter().any(|expression| {
                            expression.function == function.id
                                && expression.result == Some(value_record.id)
                        }) {
                            return Err(invalid(
                                "enum match alternative payload is an expression result",
                            ));
                        }
                        increment_definition(definitions, definition.value)?;
                    }
                    continue;
                }
                let [alternative] = pattern.alternatives.as_slice() else {
                    return Err(invalid("enum match arm is not one constructor pattern"));
                };
                if matches!(alternative.kind, wrela_hir::PrimaryPattern::Wildcard) {
                    if arm.guard.is_some() || arm_index + 1 != arms.len() {
                        return Err(invalid("enum match catch-all wildcard is not canonical"));
                    }
                    let mut remaining = false;
                    for slot in &mut covered {
                        check_analysis_cancelled(is_cancelled)?;
                        if !*slot {
                            *slot = true;
                            remaining = true;
                        }
                    }
                    if !remaining {
                        return Err(invalid("enum match catch-all wildcard is unreachable"));
                    }
                    seen_wildcard = true;
                    continue;
                }
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
                {
                    return Err(invalid("enum match constructor coverage differs from HIR"));
                }
                if covered[variant] {
                    return Err(invalid("enum match constructor arm is unreachable"));
                }
                let payload_ty = analysis
                    .types
                    .get(scrutinee_fact.ty.0 as usize)
                    .and_then(|record| match &record.kind {
                        SemanticTypeKind::Enumeration { variants, .. } => variants
                            .get(variant)
                            .map(|variant| variant.fields.first().map(|field| field.ty)),
                        _ => None,
                    })
                    .ok_or_else(|| invalid("enum match variant payload type is missing"))?;
                match payload_ty {
                    None => {
                        if !arguments.is_empty() {
                            return Err(invalid("unit enum match arm binds a payload"));
                        }
                    }
                    Some(payload_ty) => {
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
                        match payload_alternative.kind {
                            wrela_hir::PrimaryPattern::Bind(local) => {
                                let definition =
                                    fact.definitions.get(definition_index).ok_or_else(|| {
                                        invalid("enum match payload definition is missing")
                                    })?;
                                definition_index += 1;
                                let local_record = program
                                    .locals
                                    .get(local.0 as usize)
                                    .filter(|record| record.id == local && record.body == arm.body)
                                    .ok_or_else(|| {
                                        invalid("enum match payload local differs from arm body")
                                    })?;
                                let value_record = analysis
                                    .values
                                    .get(definition.value.0 as usize)
                                    .filter(|record| {
                                        definition.local == local
                                            && record.function == function.id
                                            && record.ty == payload_ty
                                            && record.origin == SemanticValueOrigin::Local(local)
                                            && record.source == Some(local_record.source)
                                            && record.source_name.as_deref()
                                                == Some(local_record.name.as_str())
                                    })
                                    .ok_or_else(|| {
                                        invalid("enum match payload value provenance is invalid")
                                    })?;
                                if analysis.expressions.iter().any(|expression| {
                                    expression.function == function.id
                                        && expression.result == Some(value_record.id)
                                }) {
                                    return Err(invalid(
                                        "enum match payload binding is an expression result",
                                    ));
                                }
                                increment_definition(definitions, definition.value)?;
                            }
                            wrela_hir::PrimaryPattern::Wildcard => {}
                            _ => {
                                return Err(invalid(
                                    "enum match payload is not a local binding or wildcard",
                                ));
                            }
                        }
                    }
                }
                if let Some(guard) = arm.guard {
                    let guard_fact = analysis
                        .expressions
                        .binary_search_by_key(&(function.id, guard), |fact| {
                            (fact.function, fact.expression)
                        })
                        .ok()
                        .and_then(|index| analysis.expressions.get(index))
                        .ok_or_else(|| invalid("enum match guard expression fact is missing"))?;
                    let bool_ty = analysis.types.iter().find_map(|record| match record.kind {
                        SemanticTypeKind::Bool => Some(record.id),
                        _ => None,
                    });
                    if Some(guard_fact.ty) != bool_ty {
                        return Err(invalid("enum match guard is not bool"));
                    }
                } else {
                    covered[variant] = true;
                }
            }
            if definition_index != fact.definitions.len() {
                return Err(invalid("enum match has extraneous payload definitions"));
            }
            if covered.iter().any(|covered| !covered) {
                return Err(invalid("enum match omits a constructor variant"));
            }
        }
        wrela_hir::StatementKind::For {
            take_binding,
            binding,
            take_iterable,
            iterable,
            body,
        } => {
            let [definition] = fact.definitions.as_slice() else {
                return Err(invalid("closed iterator loop lacks one exact binding"));
            };
            let iterable_fact = exact_child_expression(analysis, function.id, *iterable)
                .filter(|fact| fact.result.is_none())
                .ok_or_else(|| invalid("for iterable is not an exact closed iterator"))?;
            let element_ty =
                exact_closed_for_element_type(analysis, function.id, *iterable, iterable_fact)
                    .ok_or_else(|| invalid("for iterable is not an exact closed iterator"))?;
            let local_record = program
                .locals
                .get(binding.0 as usize)
                .filter(|record| {
                    record.id == *binding && record.body == *body && record.ty.is_none()
                })
                .ok_or_else(|| invalid("for binding local differs from its child body"))?;
            let value_record = analysis
                .values
                .get(definition.value.0 as usize)
                .filter(|record| {
                    definition.local == *binding
                        && record.function == function.id
                        && record.ty == element_ty
                        && record.origin == SemanticValueOrigin::Local(*binding)
                        && record.source == Some(local_record.source)
                        && record.source_name.as_deref() == Some(local_record.name.as_str())
                        && record.category == ValueCategory::Value
                        && record.class == SemanticValueClass::FirstClass
                })
                .ok_or_else(|| invalid("for binding value provenance is invalid"))?;
            if *take_binding
                || *take_iterable
                || analysis.expressions.iter().any(|expression| {
                    expression.function == function.id && expression.result == Some(value_record.id)
                })
            {
                return Err(invalid("for binding differs from the closed iterator HIR"));
            }
            increment_definition(definitions, definition.value)?;
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
        wrela_hir::StatementKind::With {
            value,
            binding,
            body,
            ..
        } => match binding {
            Some(local) => {
                let [definition] = fact.definitions.as_slice() else {
                    return Err(invalid("with binding lacks one exact definition"));
                };
                let local_record = program
                    .locals
                    .get(local.0 as usize)
                    .filter(|record| record.id == *local && record.body == *body)
                    .ok_or_else(|| invalid("with binding local differs from its child body"))?;
                let value_fact = exact_child_expression(analysis, function.id, *value)
                    .ok_or_else(|| invalid("with acquisition expression fact is missing"))?;
                let value_record = analysis
                    .values
                    .get(definition.value.0 as usize)
                    .filter(|record| {
                        definition.local == *local
                            && record.function == function.id
                            && record.origin == SemanticValueOrigin::Local(*local)
                            && record.source == Some(local_record.source)
                            && record.source_name.as_deref() == Some(local_record.name.as_str())
                            && value_fact.result == Some(record.id)
                    })
                    .ok_or_else(|| invalid("with binding value provenance is invalid"))?;
                if value_fact.ty != value_record.ty {
                    return Err(invalid("with binding type differs from acquisition result"));
                }
            }
            None if fact.definitions.is_empty() => {}
            None => return Err(invalid("unbound with statement defines a source local")),
        },
        _ if fact.definitions.is_empty() => {}
        _ => {
            return Err(invalid(
                "statement has unsupported source-local definitions",
            ));
        }
    }
    validate_exact_statement_post_state(
        analysis,
        program,
        function,
        fact,
        exactly_taken,
        statement.body,
        is_cancelled,
    )
}

fn validate_exact_statement_post_state(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    fact: &StatementFact,
    exactly_taken: &[bool],
    statement_body: wrela_hir::BodyId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let invalid = |message: &str| AnalysisFailure::InternalInvariant(message.to_owned());
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
            if !body_is_ancestor(program, local_body, statement_body) {
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

fn exact_method_is_visible_from(
    program: &wrela_hir::Program,
    method: DeclarationId,
    caller_module: wrela_package::ModuleId,
) -> bool {
    let Some(record) = program.declaration(method) else {
        return false;
    };
    if record.module == caller_module {
        return true;
    }
    let wrela_hir::DeclarationOwner::Declaration(owner) = record.owner else {
        return false;
    };
    match program.declaration(owner).map(|record| &record.kind) {
        Some(wrela_hir::DeclarationKind::Structure(_)) => {
            record.visibility == wrela_hir::Visibility::Public
        }
        Some(wrela_hir::DeclarationKind::Implementation(implementation)) => {
            let visible_nominal = |ty: &wrela_hir::TypeExpression, applied: bool| {
                let wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Declaration(resolved),
                    arguments,
                } = &ty.kind
                else {
                    return false;
                };
                (applied || arguments.is_empty())
                    && program
                        .declaration(resolved.declaration)
                        .is_some_and(|record| record.visibility == wrela_hir::Visibility::Public)
            };
            visible_nominal(&implementation.interface, true)
                && visible_nominal(&implementation.implementing_type, false)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn exact_method_call_bindings_match(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: &FunctionInstance,
    callee_expression: ExpressionId,
    source_arguments: &[wrela_hir::CallArgument],
    target: FunctionInstanceId,
    receiver: ValueId,
    receiver_access: AccessMode,
    bindings: &[ResolvedCallArgument],
) -> bool {
    let Some(wrela_hir::Expression {
        kind: wrela_hir::ExpressionKind::Field { base, name },
        ..
    }) = program.expression(callee_expression)
    else {
        return false;
    };
    let Some(receiver_fact) = exact_child_expression(analysis, caller.id, *base) else {
        return false;
    };
    if receiver_fact.resolution != ExpressionResolution::Value(receiver) {
        return false;
    }
    let Some(SemanticTypeKind::Structure {
        declaration: receiver_declaration,
        arguments: receiver_arguments,
        fields: receiver_fields,
    }) = analysis
        .types
        .get(receiver_fact.ty.0 as usize)
        .map(|record| &record.kind)
    else {
        return false;
    };
    if !receiver_arguments.is_empty()
        || !runtime_structure_arguments_supported(analysis, receiver_arguments, receiver_fields)
    {
        return false;
    }
    let Some(target_function) = analysis.functions.get(target.0 as usize) else {
        return false;
    };
    let FunctionOrigin::Source {
        declaration: target_declaration,
        ..
    } = target_function.origin
    else {
        return false;
    };
    let FunctionOrigin::Source {
        declaration: caller_declaration,
        ..
    } = caller.origin
    else {
        return false;
    };
    let Some(caller_module) = program
        .declaration(caller_declaration)
        .map(|record| record.module)
    else {
        return false;
    };
    let unique_visible_target = program
        .declarations
        .iter()
        .filter(|candidate| {
            candidate.name.as_ref() == Some(name)
                && matches!(candidate.kind, wrela_hir::DeclarationKind::Function(_))
                && crate::interfaces::receiver_concrete_struct(program, candidate.id)
                    == Some(*receiver_declaration)
                && exact_method_is_visible_from(program, candidate.id, caller_module)
        })
        .try_fold(None, |selected, candidate| match selected {
            None => Ok(Some(candidate.id)),
            Some(_) => Err(()),
        });
    if unique_visible_target != Ok(Some(target_declaration))
        || target_function.color != wrela_hir::FunctionColor::Sync
        || receiver_access != AccessMode::Read
        || target_function.parameters.len() != bindings.len().saturating_add(1)
        || source_arguments.len() != bindings.len()
    {
        return false;
    }
    let Some(receiver_parameter) = target_function.parameters.first() else {
        return false;
    };
    if receiver_parameter.access != receiver_access
        || receiver_parameter.ty != receiver_fact.ty
        || analysis
            .values
            .get(receiver.0 as usize)
            .is_none_or(|value| value.function != caller.id || value.ty != receiver_parameter.ty)
    {
        return false;
    }
    bindings
        .iter()
        .enumerate()
        .all(|(relative_index, binding)| {
            let parameter_index = relative_index + 1;
            let Some(source) = source_arguments.get(binding.source_index as usize) else {
                return false;
            };
            let Some(parameter) = target_function.parameters.get(parameter_index) else {
                return false;
            };
            let name_matches = match &source.name {
                Some(name) => {
                    program
                        .parameter(parameter.parameter)
                        .and_then(|parameter| parameter.name.as_ref())
                        == Some(name)
                }
                None => binding.source_index as usize == relative_index,
            };
            binding.parameter_index as usize == parameter_index
                && name_matches
                && exact_call_argument_access(source, binding.access)
                && binding.access == parameter.access
                && analysis
                    .values
                    .get(binding.value.0 as usize)
                    .is_some_and(|value| value.function == caller.id && value.ty == parameter.ty)
                && match &source.value {
                    wrela_hir::CallArgumentValue::Value(expression) => {
                        exact_child_expression(analysis, caller.id, *expression).is_some_and(
                            |fact| {
                                fact.result == Some(binding.value)
                                    || fact.resolution == ExpressionResolution::Value(binding.value)
                            },
                        )
                    }
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

fn exact_call_argument_access(argument: &wrela_hir::CallArgument, access: AccessMode) -> bool {
    matches!(
        (&argument.value, access),
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
    )
}

fn exact_scope_call_bindings_match(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: FunctionInstanceId,
    callee_expression: ExpressionId,
    source_arguments: &[wrela_hir::CallArgument],
    protocol: ScopeProtocolId,
    bindings: &[ResolvedCallArgument],
) -> bool {
    let Some(protocol_record) = analysis.scope_protocols.get(protocol.0 as usize) else {
        return false;
    };
    let Some(wrela_hir::DeclarationKind::Scope(source_scope)) = program
        .declaration(protocol_record.declaration)
        .map(|declaration| &declaration.kind)
    else {
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
            fact.result.is_none() && fact.resolution == ExpressionResolution::Scope(protocol)
        });
    if !callee_matches
        || bindings.len() != source_arguments.len()
        || bindings.len()
            != source_scope
                .parameters
                .iter()
                .filter(|parameter| **parameter != source_scope.exit_parameter)
                .count()
        || bindings.len() != protocol_record.parameters.len()
    {
        return false;
    }
    bindings
        .iter()
        .zip(&protocol_record.parameters)
        .enumerate()
        .all(|(parameter_index, (binding, parameter))| {
            let Some(source) = source_arguments.get(binding.source_index as usize) else {
                return false;
            };
            let Some(parameter_id) = source_scope
                .parameters
                .iter()
                .filter(|parameter| **parameter != source_scope.exit_parameter)
                .nth(parameter_index)
            else {
                return false;
            };
            let Some(hir_parameter) = program.parameters.get(parameter_id.0 as usize) else {
                return false;
            };
            let name_matches = match &source.name {
                Some(name) => hir_parameter.name.as_ref() == Some(name),
                None => binding.source_index as usize == parameter_index,
            };
            binding.parameter_index as usize == parameter_index
                && binding.access == parameter.access
                && name_matches
                && matches!(
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
                )
                && analysis
                    .values
                    .get(binding.value.0 as usize)
                    .is_some_and(|value| value.function == caller && value.ty == parameter.ty)
        })
}

#[allow(clippy::too_many_arguments)]
fn exact_projection_call_bindings_match(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    caller: FunctionInstanceId,
    fact: &ExpressionFact,
    callee_expression: ExpressionId,
    source_arguments: &[wrela_hir::CallArgument],
    protocol: ProjectionProtocolId,
    bindings: &[ResolvedCallArgument],
    view: LexicalViewId,
    result: ValueId,
) -> bool {
    let Some(protocol_record) = analysis.projection_protocols.get(protocol.0 as usize) else {
        return false;
    };
    let Some(wrela_hir::DeclarationKind::Projection(source_projection)) = program
        .declaration(protocol_record.declaration)
        .map(|declaration| &declaration.kind)
    else {
        return false;
    };
    let callee_matches =
        exact_child_expression(analysis, caller, callee_expression).is_some_and(|callee| {
            callee.result.is_none()
                && callee.resolution == ExpressionResolution::Projection(protocol)
        });
    let expected_category = if protocol_record.mutable {
        ValueCategory::MutableView
    } else {
        ValueCategory::SharedView
    };
    if !callee_matches
        || fact.ty != protocol_record.target
        || fact.category != expected_category
        || fact.region.is_some()
        || bindings.len() != source_arguments.len()
        || bindings.len() != source_projection.parameters.len()
        || bindings.len() != protocol_record.parameters.len()
    {
        return false;
    }
    let bindings_match = bindings
        .iter()
        .zip(&protocol_record.parameters)
        .enumerate()
        .all(|(parameter_index, (binding, parameter))| {
            let Some(source) = source_arguments.get(binding.source_index as usize) else {
                return false;
            };
            let Some(parameter_id) = source_projection.parameters.get(parameter_index) else {
                return false;
            };
            let Some(hir_parameter) = program.parameters.get(parameter_id.0 as usize) else {
                return false;
            };
            let name_matches = match &source.name {
                Some(name) => hir_parameter.name.as_ref() == Some(name),
                None => binding.source_index as usize == parameter_index,
            };
            binding.parameter_index as usize == parameter_index
                && binding.access == parameter.access
                && name_matches
                && matches!(
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
                    )
                )
                && analysis
                    .values
                    .get(binding.value.0 as usize)
                    .is_some_and(|value| value.function == caller && value.ty == parameter.ty)
        });
    bindings_match
        && analysis
            .lexical_views
            .get(view.0 as usize)
            .is_some_and(|record| {
                record.function == caller
                    && record.protocol == protocol
                    && record.expression == fact.expression
                    && record.value == result
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
    let source_actor = match caller_record.role {
        FunctionRole::TaskEntry(task) => {
            let Some(actor) = graph
                .tasks
                .get(task.0 as usize)
                .filter(|record| record.id == task)
                .and_then(|record| record.supervisor)
            else {
                return false;
            };
            actor
        }
        FunctionRole::ActorTurn(actor) => actor,
        _ => return false,
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
            } if parameters.is_empty() && *result == target_record.result
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
        && analysis
            .types
            .get(target_record.result.0 as usize)
            .is_some_and(|ty| {
                ty.kind == SemanticTypeKind::Unit
                    || matches!(
                        ty.kind,
                        SemanticTypeKind::Integer {
                            signed: false,
                            bits: 64,
                            ..
                        }
                    )
            })
        && method_type_matches
}

fn exact_concrete_method_reference_matches(
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
    let Some(base_fact) = exact_child_expression(analysis, caller, base) else {
        return false;
    };
    if !matches!(base_fact.resolution, ExpressionResolution::Value(_)) {
        return false;
    }
    let Some(SemanticTypeKind::Structure {
        declaration: receiver_declaration,
        arguments,
        fields,
    }) = analysis
        .types
        .get(base_fact.ty.0 as usize)
        .map(|ty| &ty.kind)
    else {
        return false;
    };
    if !arguments.is_empty() || !runtime_structure_arguments_supported(analysis, arguments, fields)
    {
        return false;
    }
    let Some(target_record) = analysis.functions.get(target.0 as usize) else {
        return false;
    };
    let FunctionOrigin::Source { declaration, .. } = target_record.origin else {
        return false;
    };
    if crate::interfaces::receiver_concrete_struct(program, declaration)
        != Some(*receiver_declaration)
        || crate::interfaces::declaration_name(program, declaration) != Some(name.as_str())
        || target_record.color != FunctionColor::Sync
        || target_record.parameters.first().is_none_or(|parameter| {
            parameter.access != AccessMode::Read || parameter.ty != base_fact.ty
        })
    {
        return false;
    }
    analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
        matches!(
            &ty.kind,
            SemanticTypeKind::Function {
                color: FunctionColor::Sync,
                parameters,
                result,
            } if parameters.len() == target_record.parameters.len().saturating_sub(1)
                && parameters.iter().zip(&target_record.parameters[1..]).all(
                    |(actual, expected)| actual.access == expected.access && actual.ty == expected.ty
                )
                && *result == target_record.result
        )
    })
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
    reply: Option<ProofId>,
) -> bool {
    if !arguments.is_empty()
        || fact.effects != EffectSet(EffectSet::ACTOR)
        || fact.ownership_before != OwnershipState::Owned
        || fact.ownership_after
            != if reply.is_some() {
                OwnershipState::Owned
            } else {
                OwnershipState::Taken
            }
    {
        return false;
    }
    let Some(graph) = analysis.graph.as_ref() else {
        return false;
    };
    let Some(producer) = analysis.functions.get(caller.0 as usize) else {
        return false;
    };
    if fact.proofs != producer.proofs
        || !fact.proofs.contains(&permit)
        || reply.is_some_and(|reply| !fact.proofs.contains(&reply))
    {
        return false;
    }
    let source_actor = match producer.role {
        FunctionRole::TaskEntry(task) => {
            let Some(actor) = graph
                .tasks
                .get(task.0 as usize)
                .filter(|record| record.id == task)
                .and_then(|record| record.supervisor)
            else {
                return false;
            };
            actor
        }
        FunctionRole::ActorTurn(actor) => actor,
        _ => return false,
    };
    if source_actor != actor
        && !(graph.actors.len() == 2 && source_actor == ActorId(1) && actor == ActorId(0))
    {
        return false;
    }
    let Some(target) = analysis.functions.get(method.0 as usize) else {
        return false;
    };
    let target_type_proof = target.proofs.iter().copied().find(|proof| {
        analysis
            .proofs
            .get(proof.0 as usize)
            .is_some_and(|record| record.kind == ProofKind::TypeChecked)
    });
    if target.id != method
        || target.role != FunctionRole::ActorTurn(actor)
        || target.color != FunctionColor::Async
        || target.parameters.len() != 1
        || (reply.is_none()
            && analysis
                .types
                .get(target.result.0 as usize)
                .is_none_or(|ty| ty.kind != SemanticTypeKind::Unit))
    {
        return false;
    }
    let Some(result_type) = analysis.types.get(fact.ty.0 as usize) else {
        return false;
    };
    let result_matches = if reply.is_some() {
        fact.ty == target.result
            && matches!(
                result_type.kind,
                SemanticTypeKind::Integer {
                    signed: false,
                    bits: 64,
                    ..
                }
            )
            && result_type.linearity == Linearity::ScalarCopy
            && result_type.size_upper_bound == Some(8)
            && result_type.alignment_lower_bound == 8
    } else {
        result_type.kind == SemanticTypeKind::Reservation
            && result_type.linearity == Linearity::StrictLinear
            && result_type.size_upper_bound == Some(8)
            && result_type.alignment_lower_bound == 8
            && result_type.source.is_none()
    };
    if !result_matches {
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
    let permit_matches = analysis.proofs.get(permit.0 as usize).is_some_and(|proof| {
        proof.id == permit
            && proof.kind == ProofKind::CapacityBound
            && proof.bound == Some(1)
            && proof.sources.as_slice() == [request_source]
            && proof.depends_on.as_slice() == [mailbox_proof]
            && producer.proofs.contains(&permit)
    });
    permit_matches
        && reply.is_none_or(|reply| {
            let Some(target_type_proof) = target_type_proof else {
                return false;
            };
            let mut expected_dependencies = [target_type_proof, permit];
            expected_dependencies.sort_unstable();
            analysis.proofs.get(reply.0 as usize).is_some_and(|proof| {
                proof.id == reply
                    && proof.kind == ProofKind::ActorReplyExactlyOnce
                    && proof.bound == Some(1)
                    && proof.sources.as_slice() == [request_source]
                    && proof.depends_on.as_slice() == expected_dependencies
                    && producer.proofs.contains(&reply)
            })
        })
}

fn exact_admission_try_send_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: &FunctionInstance,
    operand: ExpressionId,
    fact: &ExpressionFact,
    actor: ActorId,
    result: ValueId,
) -> bool {
    let Some(request) = exact_child_expression(analysis, function.id, operand) else {
        return false;
    };
    let ExpressionResolution::ActorRequest {
        actor: request_actor,
        method: _,
        permit,
        reply: None,
    } = request.resolution
    else {
        return false;
    };
    if request_actor != actor
        || request.effects != EffectSet(EffectSet::ACTOR)
        || request.ownership_before != OwnershipState::Owned
        || request.ownership_after != OwnershipState::Taken
        || fact.effects != request.effects
        || fact.ownership_before != OwnershipState::Owned
        || fact.ownership_after != OwnershipState::Owned
        || fact.proofs != request.proofs
        || !fact.proofs.contains(&permit)
    {
        return false;
    }
    let Some(value) = analysis.values.get(result.0 as usize) else {
        return false;
    };
    if value.function != function.id
        || value.ty != fact.ty
        || value.category != ValueCategory::Value
        || value.class != SemanticValueClass::Ephemeral(EphemeralKind::AdmissionResult)
        || value.origin != SemanticValueOrigin::Expression(fact.expression)
        || value.source
            != program
                .expression(fact.expression)
                .map(|expression| expression.source)
    {
        return false;
    }
    let direct_match = program.statements.iter().any(|statement| {
        matches!(statement.kind, wrela_hir::StatementKind::Match { scrutinee, .. }
            if scrutinee == fact.expression)
    });
    let direct_is = program.expressions.iter().any(|expression| {
        matches!(expression.kind, wrela_hir::ExpressionKind::IsPattern { value, .. }
            if value == fact.expression)
    });
    if direct_match == direct_is
        || program.expressions.iter().any(|expression| {
            matches!(expression.kind, wrela_hir::ExpressionKind::Try(operand)
            if operand == fact.expression)
        })
    {
        return false;
    }
    exact_core_admission_result_type_matches(analysis, program, fact.ty)
}

fn exact_core_admission_result_type_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    result_ty: SemanticTypeId,
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
    let mut error = None;
    let mut result = None;
    for declaration in &program.declarations {
        let Some(module) = program.modules.get(declaration.module.0 as usize) else {
            return false;
        };
        if module.package != core_package || module.path.dotted() != "actor" {
            continue;
        }
        match declaration.name.as_ref().map(wrela_hir::Name::as_str) {
            Some("AdmissionError") if error.replace(declaration).is_some() => return false,
            Some("AdmissionResult") if result.replace(declaration).is_some() => return false,
            _ => {}
        }
    }
    let (Some(error), Some(result)) = (error, result) else {
        return false;
    };
    let unit = |variant: &wrela_hir::EnumVariant, name: &str| {
        variant.name.as_str() == name && variant.fields.is_empty()
    };
    let exact_error = error.visibility == wrela_hir::Visibility::Public
        && matches!(&error.kind, wrela_hir::DeclarationKind::Enumeration(enumeration)
            if enumeration.generics.is_empty()
                && enumeration.members.is_empty()
                && enumeration.deriving.is_empty()
                && matches!(enumeration.variants.as_slice(), [full, restarting, stale, cancelled, deadline]
                    if unit(full, "Full")
                        && unit(restarting, "Restarting")
                        && unit(stale, "StaleRequest")
                        && unit(cancelled, "Cancelled")
                        && unit(deadline, "DeadlineRejected")));
    let exact_result = result.visibility == wrela_hir::Visibility::Public
        && matches!(&result.kind, wrela_hir::DeclarationKind::Enumeration(enumeration)
            if enumeration.generics.is_empty()
                && enumeration.members.is_empty()
                && enumeration.deriving.is_empty()
                && matches!(enumeration.variants.as_slice(), [admitted, rejected]
                    if unit(admitted, "Admitted")
                        && rejected.name.as_str() == "Rejected"
                        && matches!(rejected.fields.as_slice(), [field]
                            if field.name.is_none()
                                && matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                                    definition: wrela_hir::Definition::Declaration(resolved),
                                    arguments,
                                } if arguments.is_empty()
                                    && resolved.package == core_package
                                    && resolved.module == error.module
                                    && resolved.declaration == error.id))));
    if !exact_error || !exact_result {
        return false;
    }
    let mut error_types = analysis.types.iter().filter(|ty| {
        matches!(&ty.kind, SemanticTypeKind::Enumeration { declaration, arguments, variants }
            if *declaration == error.id
                && arguments.is_empty()
                && variants.len() == 5
                && variants.iter().zip(["Full", "Restarting", "StaleRequest", "Cancelled", "DeadlineRejected"])
                    .all(|(variant, name)| variant.name == name && variant.fields.is_empty()))
    });
    let Some(error_ty) = error_types.next() else {
        return false;
    };
    if error_types.next().is_some() {
        return false;
    }
    analysis.types.get(result_ty.0 as usize).is_some_and(|ty| {
        ty.linearity == Linearity::ExplicitCopy
            && matches!(&ty.kind, SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                variants,
            } if *declaration == result.id
                && arguments.is_empty()
                && matches!(variants.as_slice(), [admitted, rejected]
                    if admitted.name == "Admitted"
                        && admitted.fields.is_empty()
                        && rejected.name == "Rejected"
                        && matches!(rejected.fields.as_slice(), [field]
                            if field.name.is_empty()
                                && field.public
                                && field.ty == error_ty.id)))
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
        (
            wrela_hir::Literal::Character(source),
            ConstantValue::Character(value),
            SemanticTypeKind::Character,
        ) => source == value,
        (
            wrela_hir::Literal::String(source),
            ConstantValue::String(value),
            SemanticTypeKind::StaticString { bytes },
        ) => source == value && u64::try_from(source.len()) == Ok(*bytes),
        (
            wrela_hir::Literal::Bytes(source),
            ConstantValue::Bytes(value),
            SemanticTypeKind::StaticBytes { bytes },
        ) => source == value && u64::try_from(source.len()) == Ok(*bytes),
        _ => false,
    }
}

fn exact_bounded_interpolation_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    fact: &ExpressionFact,
    source_parts: &[wrela_hir::InterpolationPart],
    capacity: u64,
    resolved_parts: &[BoundedInterpolationPart],
) -> bool {
    if source_parts.len() != resolved_parts.len()
        || !analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
            matches!(ty.kind, SemanticTypeKind::BoundedString { capacity: bound } if bound == capacity)
        })
    {
        return false;
    }
    let mut expected_capacity = 0_u64;
    let mut value_count = 0_usize;
    let mut effects = 0_u64;
    for (source, resolved) in source_parts.iter().zip(resolved_parts) {
        match (source, resolved) {
            (
                wrela_hir::InterpolationPart::Text {
                    value: source_value,
                    source: source_span,
                },
                BoundedInterpolationPart::Text {
                    value,
                    source: span,
                },
            ) if source_value == value && source_span == span => {
                let Ok(bytes) = u64::try_from(source_value.len()) else {
                    return false;
                };
                let Some(next) = expected_capacity.checked_add(bytes) else {
                    return false;
                };
                expected_capacity = next;
            }
            (
                wrela_hir::InterpolationPart::Value {
                    expression,
                    format: None,
                    format_source: None,
                },
                BoundedInterpolationPart::Bool {
                    expression: resolved_expression,
                    value,
                },
            ) if expression == resolved_expression => {
                let Some(child) = exact_child_expression(analysis, function, *expression) else {
                    return false;
                };
                let resolved_value = match child.resolution {
                    ExpressionResolution::Value(value) => Some(value),
                    _ => child.result,
                };
                if resolved_value != Some(*value)
                    || !analysis
                        .types
                        .get(child.ty.0 as usize)
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Bool))
                {
                    return false;
                }
                let Some(next) = expected_capacity.checked_add(5) else {
                    return false;
                };
                expected_capacity = next;
                value_count = value_count.saturating_add(1);
                effects |= child.effects.0;
            }
            (
                wrela_hir::InterpolationPart::Value {
                    expression,
                    format: None,
                    format_source: None,
                },
                BoundedInterpolationPart::Character {
                    expression: resolved_expression,
                    value,
                },
            ) if expression == resolved_expression => {
                let Some(child) = exact_child_expression(analysis, function, *expression) else {
                    return false;
                };
                let resolved_value = match child.resolution {
                    ExpressionResolution::Value(value) => Some(value),
                    _ => child.result,
                };
                if resolved_value != Some(*value)
                    || !analysis
                        .values
                        .get(value.0 as usize)
                        .filter(|record| record.function == function && record.ty == child.ty)
                        .and_then(|_| analysis.types.get(child.ty.0 as usize))
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Character))
                {
                    return false;
                }
                let Some(next) = expected_capacity.checked_add(4) else {
                    return false;
                };
                expected_capacity = next;
                value_count = value_count.saturating_add(1);
                effects |= child.effects.0;
            }
            (
                wrela_hir::InterpolationPart::Value {
                    expression,
                    format: None,
                    format_source: None,
                },
                BoundedInterpolationPart::StaticString {
                    expression: resolved_expression,
                    value,
                    ty,
                },
            ) if expression == resolved_expression => {
                let Some(child) = exact_child_expression(analysis, function, *expression) else {
                    return false;
                };
                let resolved_value = match child.resolution {
                    ExpressionResolution::Value(value) => Some(value),
                    _ => child.result,
                };
                let Some(bytes) = analysis
                    .values
                    .get(value.0 as usize)
                    .filter(|record| {
                        record.function == function && record.ty == *ty && child.ty == *ty
                    })
                    .and_then(|_| analysis.types.get(ty.0 as usize))
                    .and_then(|record| match record.kind {
                        SemanticTypeKind::StaticString { bytes } => Some(bytes),
                        _ => None,
                    })
                else {
                    return false;
                };
                if resolved_value != Some(*value) {
                    return false;
                }
                let Some(next) = expected_capacity.checked_add(bytes) else {
                    return false;
                };
                expected_capacity = next;
                value_count = value_count.saturating_add(1);
                effects |= child.effects.0;
            }
            (
                wrela_hir::InterpolationPart::Value {
                    expression,
                    format: None,
                    format_source: None,
                },
                BoundedInterpolationPart::Integer {
                    expression: resolved_expression,
                    value,
                    ty,
                    maximum_bytes,
                },
            ) if expression == resolved_expression => {
                let Some(child) = exact_child_expression(analysis, function, *expression) else {
                    return false;
                };
                let resolved_value = match child.resolution {
                    ExpressionResolution::Value(value) => Some(value),
                    _ => child.result,
                };
                if resolved_value != Some(*value)
                    || child.ty != *ty
                    || analysis
                        .values
                        .get(value.0 as usize)
                        .is_none_or(|record| record.function != function || record.ty != *ty)
                {
                    return false;
                }
                let Some(expected_maximum) = analysis
                    .types
                    .get(ty.0 as usize)
                    .filter(|ty| matches!(ty.kind, SemanticTypeKind::Integer { .. }))
                    .and_then(|ty| bounded_interpolation_maximum_bytes(&ty.kind))
                else {
                    return false;
                };
                if expected_maximum != *maximum_bytes {
                    return false;
                }
                let Some(next) = expected_capacity.checked_add(expected_maximum) else {
                    return false;
                };
                expected_capacity = next;
                value_count = value_count.saturating_add(1);
                effects |= child.effects.0;
            }
            _ => return false,
        }
    }
    value_count > 0 && capacity == expected_capacity && fact.effects.0 == effects
}

#[allow(clippy::too_many_arguments)]
fn exact_closed_literal_range_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    range: &ExpressionFact,
    start: ExpressionId,
    end: ExpressionId,
    source_inclusive: bool,
    start_value: ValueId,
    end_value: ValueId,
    resolved_inclusive: bool,
    maximum_iterations: u64,
) -> bool {
    if source_inclusive != resolved_inclusive || range.result.is_some() {
        return false;
    }
    let endpoint = |expression, value| {
        analysis
            .expressions
            .binary_search_by_key(&(function, expression), |fact| {
                (fact.function, fact.expression)
            })
            .ok()
            .and_then(|index| analysis.expressions.get(index))
            .filter(|fact| {
                fact.ty == range.ty
                    && fact.result == Some(value)
                    && matches!(fact.resolution, ExpressionResolution::Constant(_))
            })
    };
    let (Some(start_fact), Some(end_fact)) =
        (endpoint(start, start_value), endpoint(end, end_value))
    else {
        return false;
    };
    let parse = |fact: &ExpressionFact| match fact.resolution {
        ExpressionResolution::Constant(ConstantValue::Unsigned { bits: 64, value }) => {
            u64::try_from(value).ok()
        }
        _ => None,
    };
    let (Some(start_constant), Some(end_constant)) = (parse(start_fact), parse(end_fact)) else {
        return false;
    };
    analysis.types.get(range.ty.0 as usize).is_some_and(|ty| {
        matches!(
            ty.kind,
            SemanticTypeKind::Integer {
                signed: false,
                bits: 64,
                pointer_sized: false,
            }
        )
    }) && Some(maximum_iterations)
        == if source_inclusive {
            inclusive_trip_count(start_constant, end_constant)
        } else {
            Some(half_open_trip_count(start_constant, end_constant))
        }
        && range.effects == EffectSet(start_fact.effects.0 | end_fact.effects.0)
}

fn exact_closed_for_element_type(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    iterable: ExpressionId,
    iterable_fact: &ExpressionFact,
) -> Option<SemanticTypeId> {
    if iterable_fact.function != function || iterable_fact.result.is_some() {
        return None;
    }
    match iterable_fact.resolution {
        ExpressionResolution::ClosedRange { .. } => Some(iterable_fact.ty),
        ExpressionResolution::ClosedArray { storage: None, .. } => analysis
            .types
            .get(iterable_fact.ty.0 as usize)
            .and_then(|record| match record.kind {
                SemanticTypeKind::Array { element, .. } => Some(element),
                _ => None,
            }),
        ExpressionResolution::Value(value) => analysis.expressions.iter().find_map(|fact| {
            if fact.function != function || fact.result != Some(value) {
                return None;
            }
            let ExpressionResolution::ClosedArray {
                storage:
                    Some(ClosedArrayStorage {
                        value: stored,
                        iterable: stored_iterable,
                        ..
                    }),
                ..
            } = fact.resolution
            else {
                return None;
            };
            if stored != value || stored_iterable != iterable || fact.ty != iterable_fact.ty {
                return None;
            }
            analysis
                .types
                .get(fact.ty.0 as usize)
                .and_then(|record| match record.kind {
                    SemanticTypeKind::Array { element, .. } => Some(element),
                    _ => None,
                })
        }),
        _ => None,
    }
}

fn exact_closed_fixed_array_matches(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    function: FunctionInstanceId,
    array: &ExpressionFact,
    source_elements: &[ExpressionId],
    resolution: &ExpressionResolution,
) -> bool {
    let ExpressionResolution::ClosedArray {
        elements,
        maximum_iterations,
        bounds,
        storage,
    } = resolution
    else {
        return false;
    };
    let Ok(length) = u64::try_from(source_elements.len()) else {
        return false;
    };
    if length == 0 || *maximum_iterations != length || source_elements.len() != elements.len() {
        return false;
    }
    let Some(source) = program
        .expression(array.expression)
        .map(|expression| expression.source)
    else {
        return false;
    };
    let Some(proof) = analysis
        .proofs
        .get(bounds.0 as usize)
        .filter(|proof| proof.id == *bounds)
    else {
        return false;
    };
    let (subject, explanation, second_source) = match storage {
        None => {
            if array.result.is_some() {
                return false;
            }
            let iteration_uses = program
                .statements
                .iter()
                .filter(|statement| {
                    matches!(
                        statement.kind,
                        wrela_hir::StatementKind::For { iterable, .. }
                            if iterable == array.expression
                    )
                })
                .count();
            let match_uses = program
                .statements
                .iter()
                .filter(|statement| {
                    matches!(
                        statement.kind,
                        wrela_hir::StatementKind::Match { scrutinee, .. }
                            if scrutinee == array.expression
                    )
                })
                .count();
            match (iteration_uses, match_uses) {
                (1, 0) => (
                    "inline fixed-array iteration",
                    "every generated index is strictly below the exact inline array length",
                    None,
                ),
                (0, 1) => (
                    "inline fixed-array pattern match",
                    "every array-pattern position is authenticated against the exact inline array length",
                    None,
                ),
                _ => return false,
            }
        }
        Some(storage) => {
            if array.result != Some(storage.value) {
                return false;
            }
            let Some(value) = analysis
                .values
                .get(storage.value.0 as usize)
                .filter(|value| {
                    value.function == function
                        && value.ty == array.ty
                        && value.origin == SemanticValueOrigin::Local(storage.local)
                        && value.category == ValueCategory::Value
                        && value.class == SemanticValueClass::FirstClass
                })
            else {
                return false;
            };
            let Some(local) = program
                .locals
                .get(storage.local.0 as usize)
                .filter(|local| {
                    local.id == storage.local
                        && local.ty.is_none()
                        && value.source == Some(local.source)
                        && value.source_name.as_deref() == Some(local.name.as_str())
                })
            else {
                return false;
            };
            let Some(initialization) = program.statements.iter().find(|statement| {
                statement.body == local.body
                    && matches!(
                        statement.kind,
                        wrela_hir::StatementKind::Initialize {
                            local: initialized,
                            value,
                        } if initialized == storage.local && value == array.expression
                    )
            }) else {
                return false;
            };
            let Some(iterable) = program.expression(storage.iterable).filter(|expression| {
                expression.kind
                    == wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(
                        storage.local,
                    ))
                    && expression.owner == wrela_hir::ExpressionOwner::Body(local.body)
            }) else {
                return false;
            };
            let references = program
                .expressions
                .iter()
                .filter(|expression| {
                    expression.kind
                        == wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(
                            storage.local,
                        ))
                })
                .count();
            let Some(iteration) = program.statements.iter().find(|statement| {
                statement.body == local.body
                    && matches!(
                        statement.kind,
                        wrela_hir::StatementKind::For {
                            take_binding: false,
                            take_iterable: false,
                            iterable: candidate,
                            ..
                        } if candidate == storage.iterable
                    )
            }) else {
                return false;
            };
            let Some(body) = program.body(local.body) else {
                return false;
            };
            let initializer_index = body
                .statements
                .iter()
                .position(|statement| *statement == initialization.id);
            let iteration_index = body
                .statements
                .iter()
                .position(|statement| *statement == iteration.id);
            if references != 1
                || initializer_index
                    .zip(iteration_index)
                    .is_none_or(|(init, use_)| init >= use_)
                || program.statements.iter().any(|statement| {
                    matches!(
                        &statement.kind,
                        wrela_hir::StatementKind::Assign { targets, .. }
                            if targets.iter().any(|target| {
                                target.root
                                    == wrela_hir::Definition::Local(storage.local)
                            })
                    )
                })
            {
                return false;
            }
            let Some(iterable_fact) = exact_child_expression(analysis, function, storage.iterable)
            else {
                return false;
            };
            if iterable_fact.ty != array.ty
                || iterable_fact.result.is_some()
                || iterable_fact.resolution != ExpressionResolution::Value(storage.value)
                || iterable_fact.effects != EffectSet(0)
                || iterable_fact.ownership_before != OwnershipState::Owned
                || iterable_fact.ownership_after != OwnershipState::Owned
            {
                return false;
            }
            (
                "stored fixed-array iteration",
                "the immutable local retains the initializer's exact extent and every generated index is strictly below it",
                Some(iterable.source),
            )
        }
    };
    if proof.kind != ProofKind::CapacityBound
        || proof.subject != subject
        || proof.explanation.as_slice() != [explanation]
        || match second_source {
            Some(iterable) => proof.sources.as_slice() != [source, iterable],
            None => proof.sources.as_slice() != [source],
        }
        || !proof.depends_on.is_empty()
        || proof.bound != Some(length)
    {
        return false;
    }
    let mut element_ty = None;
    let mut effects = 0_u64;
    for (source_element, element) in source_elements.iter().zip(elements) {
        let Some(source_record) = program.expression(*source_element) else {
            return false;
        };
        if !matches!(
            source_record.kind,
            wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Boolean(_))
                | wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(_))
        ) {
            return false;
        }
        let Some(child) = exact_child_expression(analysis, function, *source_element) else {
            return false;
        };
        if child.result != Some(*element)
            || !matches!(child.resolution, ExpressionResolution::Constant(_))
            || analysis
                .values
                .get(element.0 as usize)
                .is_none_or(|record| {
                    record.function != function
                        || record.ty != child.ty
                        || record.origin != SemanticValueOrigin::Expression(*source_element)
                })
        {
            return false;
        }
        if let Some(expected) = element_ty {
            if child.ty != expected {
                return false;
            }
        } else {
            element_ty = Some(child.ty);
        }
        effects |= child.effects.0;
    }
    let Some(element_ty) = element_ty else {
        return false;
    };
    let Some(element_record) = analysis.types.get(element_ty.0 as usize) else {
        return false;
    };
    if element_record.linearity != Linearity::ScalarCopy
        || !matches!(
            element_record.kind,
            SemanticTypeKind::Bool | SemanticTypeKind::Integer { .. }
        )
    {
        return false;
    }
    analysis
        .types
        .get(array.ty.0 as usize)
        .is_some_and(|record| {
            record.kind
                == (SemanticTypeKind::Array {
                    element: element_ty,
                    length,
                })
                && record.linearity == Linearity::ExplicitCopy
                && record.size_upper_bound
                    == element_record
                        .size_upper_bound
                        .and_then(|size| size.checked_mul(length))
                && record.alignment_lower_bound == element_record.alignment_lower_bound
                && record.source.is_none()
        })
        && array.effects == EffectSet(effects)
}

// Keep the subtraction explicit: the sealed proof is defined in terms of a
// checked difference, with an empty range on underflow.
#[allow(clippy::manual_unwrap_or, clippy::manual_unwrap_or_default)]
fn half_open_trip_count(start: u64, end: u64) -> u64 {
    match end.checked_sub(start) {
        Some(iterations) => iterations,
        None => 0,
    }
}

fn inclusive_trip_count(start: u64, end: u64) -> Option<u64> {
    if end < start {
        Some(0)
    } else {
        end.checked_sub(start)?.checked_add(1)
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
        | SemanticTypeKind::Character => true,
        SemanticTypeKind::StaticString { .. } | SemanticTypeKind::StaticBytes { .. } => {
            ty.linearity == Linearity::ExplicitCopy
                && ty.size_upper_bound.is_none()
                && ty.alignment_lower_bound == 1
                && ty.source.is_none()
        }
        SemanticTypeKind::BoundedString { capacity } => {
            *capacity > 0
                && ty.linearity == Linearity::ReclaimableLinear
                && ty.size_upper_bound.is_none()
                && ty.alignment_lower_bound == 1
                && ty.source.is_none()
        }
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

fn stored_copy_scalar_type(analysis: &PartialAnalysis, ty: SemanticTypeId) -> bool {
    analysis.types.get(ty.0 as usize).is_some_and(|record| {
        record.linearity == Linearity::ScalarCopy
            && matches!(
                record.kind,
                SemanticTypeKind::Bool
                    | SemanticTypeKind::Integer { .. }
                    | SemanticTypeKind::Float { bits: 32 | 64 }
            )
    })
}

fn runtime_structure_arguments_supported(
    analysis: &PartialAnalysis,
    arguments: &[SemanticArgument],
    fields: &[SemanticField],
) -> bool {
    arguments.iter().all(|argument| {
        matches!(argument, SemanticArgument::Type(ty) if stored_copy_scalar_type(analysis, *ty))
    }) && fields
        .iter()
        .all(|field| stored_copy_scalar_type(analysis, field.ty))
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
        && valid_expression_region(fact, analysis, graph)
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
        ExpressionResolution::Scope(protocol) => {
            (protocol.0 as usize) < analysis.scope_protocols.len()
        }
        ExpressionResolution::Projection(protocol) => {
            (protocol.0 as usize) < analysis.projection_protocols.len()
        }
        ExpressionResolution::Constructor { ty, variant } => analysis
            .types
            .get(ty.0 as usize)
            .is_some_and(|record| match (&record.kind, variant) {
                (
                    SemanticTypeKind::Structure {
                        arguments, fields, ..
                    },
                    None,
                ) => runtime_structure_arguments_supported(analysis, arguments, fields),
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
        ExpressionResolution::InitializerConstruction { ty, initializer } => {
            analysis
                .types
                .get(ty.0 as usize)
                .is_some_and(|record| matches!(record.kind, SemanticTypeKind::Structure { .. }))
                && (initializer.0 as usize) < analysis.hir.declarations as usize
        }
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
        ExpressionResolution::OptionTry {
            option_type,
            some_variant,
            none_variant,
            some_payload,
            propagated,
        } => valid_option_try_resolution(
            analysis,
            function,
            *option_type,
            *some_variant,
            *none_variant,
            *some_payload,
            *propagated,
        ),
        ExpressionResolution::ClosedRange { start, end, .. } => {
            start != end && value_id(*start) && value_id(*end)
        }
        ExpressionResolution::ClosedArray {
            elements,
            maximum_iterations,
            bounds,
            storage: _,
        } => elements
            .first()
            .and_then(|first| analysis.values.get(first.0 as usize))
            .is_some_and(|first| {
                first.function == function
                    && !elements.is_empty()
                    && u64::try_from(elements.len()) == Ok(*maximum_iterations)
                    && proof_id(*bounds)
                    && elements.iter().all(|value| {
                        analysis.values.get(value.0 as usize).is_some_and(|record| {
                            record.function == function && record.ty == first.ty
                        })
                    })
            }),
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
        ExpressionResolution::MethodCall {
            function: target,
            receiver,
            receiver_access,
            arguments,
        } => analysis
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| {
                let Some(receiver_parameter) = target.parameters.first() else {
                    return false;
                };
                *receiver_access == AccessMode::Read
                    && receiver_parameter.access == *receiver_access
                    && analysis
                        .values
                        .get(receiver.0 as usize)
                        .is_some_and(|value| {
                            value.function == function && value.ty == receiver_parameter.ty
                        })
                    && arguments.len().saturating_add(1) == target.parameters.len()
                    && arguments.iter().enumerate().all(|(relative, actual)| {
                        let parameter_index = relative.saturating_add(1);
                        target
                            .parameters
                            .get(parameter_index)
                            .is_some_and(|expected| {
                                usize::try_from(actual.parameter_index) == Ok(parameter_index)
                                    && actual.access == expected.access
                                    && value_id(actual.value)
                            })
                    })
            }),
        ExpressionResolution::ScopeCall {
            protocol,
            arguments,
        } => analysis
            .scope_protocols
            .get(protocol.0 as usize)
            .is_some_and(|protocol| {
                arguments.len() == protocol.parameters.len()
                    && arguments.iter().zip(&protocol.parameters).enumerate().all(
                        |(parameter_index, (actual, expected))| {
                            usize::try_from(actual.parameter_index) == Ok(parameter_index)
                                && actual.access == expected.access
                                && value_id(actual.value)
                        },
                    )
            }),
        ExpressionResolution::ProjectionCall {
            protocol,
            arguments,
            view,
        } => analysis
            .projection_protocols
            .get(protocol.0 as usize)
            .is_some_and(|protocol| {
                arguments.len() == protocol.parameters.len()
                    && arguments.iter().zip(&protocol.parameters).enumerate().all(
                        |(parameter_index, (actual, expected))| {
                            usize::try_from(actual.parameter_index) == Ok(parameter_index)
                                && actual.access == expected.access
                                && value_id(actual.value)
                        },
                    )
                    && analysis
                        .lexical_views
                        .get(view.0 as usize)
                        .is_some_and(|record| {
                            record.function == function && record.protocol == protocol.id
                        })
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
        ExpressionResolution::DerivedEquality {
            aggregate,
            left,
            right,
            fields: derived_fields,
            conjunctions,
        } => analysis
            .types
            .get(aggregate.0 as usize)
            .and_then(|record| match &record.kind {
                SemanticTypeKind::Structure { fields, .. } if !fields.is_empty() => Some(fields),
                _ => None,
            })
            .is_some_and(|fields| {
                let value_has_type = |value: ValueId, ty: SemanticTypeId| {
                    analysis
                        .values
                        .get(value.0 as usize)
                        .is_some_and(|record| record.function == function && record.ty == ty)
                };
                let value_is_bool = |value: ValueId| {
                    analysis
                        .values
                        .get(value.0 as usize)
                        .filter(|record| record.function == function)
                        .and_then(|record| analysis.types.get(record.ty.0 as usize))
                        .is_some_and(|record| matches!(record.kind, SemanticTypeKind::Bool))
                };
                value_has_type(*left, *aggregate)
                    && value_has_type(*right, *aggregate)
                    && derived_fields.len() == fields.len()
                    && conjunctions.len() == fields.len().saturating_sub(1)
                    && derived_fields.iter().zip(fields).enumerate().all(
                        |(index, (derived, field))| {
                            u32::try_from(index) == Ok(derived.field)
                                && value_has_type(derived.left, field.ty)
                                && value_has_type(derived.right, field.ty)
                                && value_is_bool(derived.comparison)
                        },
                    )
                    && conjunctions.iter().all(|value| value_is_bool(*value))
            }),
        ExpressionResolution::DerivedFrom {
            enumeration,
            variant,
            payload,
        } => analysis
            .types
            .get(enumeration.0 as usize)
            .and_then(|record| match &record.kind {
                SemanticTypeKind::Enumeration { variants, .. } => variants.get(*variant as usize),
                _ => None,
            })
            .and_then(|variant| match variant.fields.as_slice() {
                [field] => Some(field.ty),
                _ => None,
            })
            .is_some_and(|payload_ty| {
                exact_stored_copy_scalar_layout(analysis, payload_ty).is_some()
                    && analysis
                        .values
                        .get(payload.0 as usize)
                        .is_some_and(|value| {
                            value.function == function
                                && value.ty == payload_ty
                                && value.category == ValueCategory::Value
                        })
            }),
        ExpressionResolution::DerivedFromType { enumeration }
        | ExpressionResolution::DerivedFromFunction { enumeration, .. } => analysis
            .types
            .get(enumeration.0 as usize)
            .is_some_and(|record| matches!(record.kind, SemanticTypeKind::Enumeration { .. })),
        ExpressionResolution::BoundedInterpolation { capacity, parts } => {
            *capacity > 0
                && !parts.is_empty()
                && parts.iter().all(|part| match part {
                    BoundedInterpolationPart::Text { .. } => true,
                    BoundedInterpolationPart::Integer {
                        value,
                        ty,
                        maximum_bytes,
                        ..
                    } => {
                        analysis
                            .values
                            .get(value.0 as usize)
                            .filter(|record| record.function == function && record.ty == *ty)
                            .and_then(|_| analysis.types.get(ty.0 as usize))
                            .filter(|ty| matches!(ty.kind, SemanticTypeKind::Integer { .. }))
                            .and_then(|ty| bounded_interpolation_maximum_bytes(&ty.kind))
                            == Some(*maximum_bytes)
                    }
                    BoundedInterpolationPart::StaticString { value, ty, .. } => analysis
                        .values
                        .get(value.0 as usize)
                        .filter(|record| record.function == function && record.ty == *ty)
                        .and_then(|_| analysis.types.get(ty.0 as usize))
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::StaticString { .. })),
                    BoundedInterpolationPart::Bool { value, .. } => analysis
                        .values
                        .get(value.0 as usize)
                        .filter(|record| record.function == function)
                        .and_then(|record| analysis.types.get(record.ty.0 as usize))
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Bool)),
                    BoundedInterpolationPart::Character { value, .. } => analysis
                        .values
                        .get(value.0 as usize)
                        .filter(|record| record.function == function)
                        .and_then(|record| analysis.types.get(record.ty.0 as usize))
                        .is_some_and(|ty| matches!(ty.kind, SemanticTypeKind::Character)),
                })
        }
        ExpressionResolution::EnumTypeTest {
            enumeration,
            variant,
            scrutinee,
        } => {
            analysis
                .types
                .get(enumeration.0 as usize)
                .and_then(|record| match &record.kind {
                    SemanticTypeKind::Enumeration { variants, .. } => {
                        variants.get(*variant as usize)
                    }
                    _ => None,
                })
                .is_some()
                && analysis
                    .values
                    .get(scrutinee.0 as usize)
                    .is_some_and(|record| record.function == function && record.ty == *enumeration)
        }
        ExpressionResolution::ActorRequest {
            actor,
            method,
            permit,
            reply,
        } => {
            (actor.0 as usize) < graph.actors.len()
                && function_id(*method)
                && proof_id(*permit)
                && reply.is_none_or(&proof_id)
        }
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

fn valid_projection_protocol_record(
    protocol: &ProjectionProtocol,
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
) -> bool {
    let Some(declaration) = program.declaration(protocol.declaration) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Projection(source) = &declaration.kind else {
        return false;
    };
    let wrela_hir::ProjectionCarrierKind::View { mutable, ty } = &source.carrier.kind else {
        return false;
    };
    declaration.name.as_ref().map(wrela_hir::Name::as_str) == Some(protocol.name.as_str())
        && source.generics.is_empty()
        && source.body == Some(protocol.body)
        && *mutable == protocol.mutable
        && exact_runtime_source_type(analysis, ty) == Some(protocol.target)
        && protocol.provenance == source.provenance
        && source.provenance == source.parameters
        && protocol.provenance.windows(2).all(|pair| pair[0] < pair[1])
        && protocol.parameters.len() == source.parameters.len()
        && protocol
            .parameters
            .iter()
            .zip(&source.parameters)
            .all(|(semantic, parameter_id)| {
                semantic.parameter == *parameter_id
                    && program
                        .parameters
                        .get(parameter_id.0 as usize)
                        .is_some_and(|parameter| {
                            !parameter.receiver
                                && parameter.access != wrela_hir::AccessMode::Take
                                && parameter.ty.as_ref().is_some_and(|ty| {
                                    exact_runtime_source_type(analysis, ty) == Some(semantic.ty)
                                })
                                && matches!(
                                    (parameter.access, semantic.access),
                                    (wrela_hir::AccessMode::Value, AccessMode::Value)
                                        | (wrela_hir::AccessMode::Read, AccessMode::Read)
                                        | (wrela_hir::AccessMode::Mutate, AccessMode::Mutate)
                                        | (wrela_hir::AccessMode::Take, AccessMode::Take)
                                )
                        })
            })
        && analysis
            .proofs
            .get(protocol.proof.0 as usize)
            .is_some_and(|proof| {
                proof.kind == ProofKind::ViewDoesNotEscape
                    && proof.sources.as_slice() == [declaration.source]
                    && proof.bound == Some(1)
            })
}

fn valid_projection_protocol_prefix(
    protocol: &ProjectionProtocol,
    analysis: &PartialAnalysis,
) -> bool {
    protocol.declaration.0 < analysis.hir.declarations
        && !protocol.name.trim().is_empty()
        && protocol.body.0 < analysis.hir.bodies
        && (protocol.target.0 as usize) < analysis.types.len()
        && (protocol.proof.0 as usize) < analysis.proofs.len()
        && protocol.provenance.windows(2).all(|pair| pair[0] < pair[1])
        && protocol
            .provenance
            .iter()
            .all(|parameter| parameter.0 < analysis.hir.parameters)
        && protocol.parameters.iter().all(|parameter| {
            parameter.parameter.0 < analysis.hir.parameters
                && (parameter.ty.0 as usize) < analysis.types.len()
        })
        && !has_duplicate_ids(
            protocol
                .parameters
                .iter()
                .map(|parameter| parameter.parameter.0),
        )
        && analysis
            .proofs
            .get(protocol.proof.0 as usize)
            .is_some_and(|proof| {
                proof.kind == ProofKind::ViewDoesNotEscape && proof.bound == Some(1)
            })
}

fn valid_lexical_view_prefix(view: &LexicalView, analysis: &PartialAnalysis) -> bool {
    let Some(protocol) = analysis
        .projection_protocols
        .get(view.protocol.0 as usize)
        .filter(|protocol| protocol.id == view.protocol)
    else {
        return false;
    };
    let expected_category = if protocol.mutable {
        ValueCategory::MutableView
    } else {
        ValueCategory::SharedView
    };
    let value_matches = analysis
        .values
        .get(view.value.0 as usize)
        .is_some_and(|value| {
            value.function == view.function
                && value.ty == protocol.target
                && value.category == expected_category
                && value.class == SemanticValueClass::Ephemeral(EphemeralKind::View)
                && value.origin == SemanticValueOrigin::Local(view.binding)
        });
    let initialization_matches = analysis
        .statements
        .binary_search_by_key(&(view.function, view.initialization), |fact| {
            (fact.function, fact.statement)
        })
        .ok()
        .and_then(|index| analysis.statements.get(index))
        .is_some_and(|statement| {
            statement.definitions.as_slice()
                == [LocalDefinition {
                    local: view.binding,
                    value: view.value,
                }]
                && statement
                    .live_lexical_views_after
                    .binary_search(&view.id)
                    .is_ok()
                    != view.terminal_uses.is_empty()
        });
    let Some(expression) = analysis
        .expressions
        .binary_search_by_key(&(view.function, view.expression), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| analysis.expressions.get(index))
    else {
        return false;
    };
    let ExpressionResolution::ProjectionCall {
        protocol: call_protocol,
        arguments,
        view: call_view,
    } = &expression.resolution
    else {
        return false;
    };
    let sources_match = view.sources.len() == protocol.provenance.len()
        && view
            .sources
            .iter()
            .zip(&protocol.provenance)
            .all(|(source, parameter)| {
                source.parameter == *parameter
                    && protocol
                        .parameters
                        .iter()
                        .position(|candidate| candidate.parameter == *parameter)
                        .and_then(|index| arguments.get(index))
                        .is_some_and(|argument| {
                            argument.value == source.value
                                && argument.access == source.access
                                && protocol
                                    .parameters
                                    .iter()
                                    .find(|candidate| candidate.parameter == *parameter)
                                    .is_some_and(|parameter| {
                                        analysis.values.get(source.value.0 as usize).is_some_and(
                                            |value| {
                                                value.function == view.function
                                                    && value.ty == parameter.ty
                                            },
                                        )
                                    })
                        })
                    && valid_span(source.argument_source, analysis.hir.files)
            });
    let terminal_uses_match = strict_ids(&view.terminal_uses)
        && view.terminal_uses.iter().all(|terminal| {
            analysis
                .expressions
                .binary_search_by_key(&(view.function, *terminal), |fact| {
                    (fact.function, fact.expression)
                })
                .ok()
                .and_then(|index| analysis.expressions.get(index))
                .is_some_and(|fact| {
                    fact.ty == protocol.target
                        && fact.category == expected_category
                        && fact.region.is_none()
                        && fact.resolution == ExpressionResolution::Value(view.value)
                })
        });
    let live_statements_match = strict_ids(&view.live_after_statements)
        && view
            .live_after_statements
            .iter()
            .all(|statement| statement.0 < analysis.hir.statements);
    (view.function.0 as usize) < analysis.functions.len()
        && view.expression.0 < analysis.hir.expressions
        && view.initialization.0 < analysis.hir.statements
        && view.binding.0 < analysis.hir.locals
        && value_matches
        && initialization_matches
        && expression.result == Some(view.value)
        && expression.ty == protocol.target
        && expression.category == expected_category
        && expression.region.is_none()
        && *call_protocol == view.protocol
        && *call_view == view.id
        && sources_match
        && terminal_uses_match
        && live_statements_match
}

fn valid_lexical_view_record(
    view: &LexicalView,
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    check_analysis_cancelled(is_cancelled)?;
    if !valid_lexical_view_prefix(view, analysis) {
        return Ok(false);
    }
    let Some(expression) = program.expression(view.expression) else {
        return Ok(false);
    };
    let wrela_hir::ExpressionKind::Call { callee, arguments } = &expression.kind else {
        return Ok(false);
    };
    let Some(statement) = program.statement(view.initialization) else {
        return Ok(false);
    };
    if !matches!(
        statement.kind,
        wrela_hir::StatementKind::Initialize { local, value }
            if local == view.binding && value == view.expression
    ) || program
        .locals
        .get(view.binding.0 as usize)
        .is_none_or(|local| local.id != view.binding || local.body != statement.body)
    {
        return Ok(false);
    }
    let Some(fact) = exact_child_expression(analysis, view.function, view.expression) else {
        return Ok(false);
    };
    let ExpressionResolution::ProjectionCall {
        protocol,
        arguments: bindings,
        view: call_view,
    } = &fact.resolution
    else {
        return Ok(false);
    };
    let call_matches = exact_projection_call_bindings_match(
        analysis,
        program,
        view.function,
        fact,
        *callee,
        arguments,
        *protocol,
        bindings,
        *call_view,
        view.value,
    );
    let sources_match = analysis
        .projection_protocols
        .get(protocol.0 as usize)
        .is_some_and(|protocol| {
            view.sources.iter().all(|source| {
                protocol
                    .parameters
                    .iter()
                    .position(|parameter| parameter.parameter == source.parameter)
                    .and_then(|index| bindings.get(index))
                    .and_then(|binding| arguments.get(binding.source_index as usize))
                    .is_some_and(|argument| {
                        argument.source == source.argument_source
                            && exact_call_argument_access(argument, source.access)
                    })
            })
        });
    let Ok(structured) = analyzer::derive_structured_view_liveness(
        program,
        view.initialization,
        view.binding,
        is_cancelled,
    )?
    else {
        return Ok(false);
    };
    let structured_matches = view.terminal_uses == structured.terminal_uses
        && view.live_after_statements == structured.live_after_statements;
    let statement_is_live_before = |candidate: &wrela_hir::Statement| {
        view.live_after_statements
            .binary_search(&candidate.id)
            .is_ok()
            || view.terminal_uses.iter().any(|terminal| {
                program.expression(*terminal).is_some_and(|terminal| {
                    candidate.source.file == terminal.source.file
                        && candidate.source.range.start <= terminal.source.range.start
                        && terminal.source.range.end <= candidate.source.range.end
                })
            })
    };
    for candidate in &program.statements {
        check_analysis_cancelled(is_cancelled)?;
        if !statement_is_live_before(candidate) {
            continue;
        }
        if let wrela_hir::StatementKind::Assign { targets, .. } = &candidate.kind {
            let rebinds_retained = targets.iter().any(|target| match target.root {
                wrela_hir::Definition::Local(local) if local == view.binding => true,
                wrela_hir::Definition::Local(local) => view.sources.iter().any(|source| {
                    analysis
                        .values
                        .get(source.value.0 as usize)
                        .is_some_and(|value| value.origin == SemanticValueOrigin::Local(local))
                }),
                _ => false,
            });
            if rebinds_retained {
                return Ok(false);
            }
        }
    }
    for candidate in &program.expressions {
        check_analysis_cancelled(is_cancelled)?;
        let Some(containing) = analyzer::containing_statement_for_expression(program, candidate)
            .and_then(|statement| program.statement(statement))
        else {
            continue;
        };
        if !statement_is_live_before(containing) {
            continue;
        }
        if matches!(
            candidate.kind,
            wrela_hir::ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Await,
                ..
            }
        ) {
            return Ok(false);
        }
        let wrela_hir::ExpressionKind::Call { arguments, .. } = &candidate.kind else {
            continue;
        };
        for argument in arguments {
            check_analysis_cancelled(is_cancelled)?;
            let wrela_hir::CallArgumentValue::Exclusive { place, .. } = &argument.value else {
                continue;
            };
            let mutates_retained = view.sources.iter().any(|source| {
                analysis
                    .values
                    .get(source.value.0 as usize)
                    .is_some_and(|value| match (value.origin, &place.root) {
                        (
                            SemanticValueOrigin::Local(expected),
                            wrela_hir::Definition::Local(actual),
                        ) => expected == *actual,
                        (
                            SemanticValueOrigin::Parameter(expected),
                            wrela_hir::Definition::Parameter(actual),
                        ) => expected == *actual,
                        _ => false,
                    })
            });
            if mutates_retained {
                return Ok(false);
            }
        }
    }
    let mut liveness_is_exact = true;
    for fact in analysis
        .statements
        .iter()
        .filter(|fact| fact.function == view.function)
    {
        check_analysis_cancelled(is_cancelled)?;
        let expected_live = (fact.statement == view.initialization
            && !view.terminal_uses.is_empty())
            || view
                .live_after_statements
                .binary_search(&fact.statement)
                .is_ok();
        liveness_is_exact &= fact
            .live_lexical_views_after
            .binary_search(&view.id)
            .is_ok()
            == expected_live;
    }
    Ok(call_matches && sources_match && structured_matches && liveness_is_exact)
}

fn lexical_view_accesses_are_disjoint(
    analysis: &PartialAnalysis,
    _program: &wrela_hir::Program,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    for (index, left) in analysis.lexical_views.iter().enumerate() {
        check_analysis_cancelled(is_cancelled)?;
        for right in &analysis.lexical_views[index + 1..] {
            check_analysis_cancelled(is_cancelled)?;
            if left.function != right.function {
                continue;
            }
            let mut conflicting_source = false;
            for left_source in &left.sources {
                check_analysis_cancelled(is_cancelled)?;
                for right_source in &right.sources {
                    check_analysis_cancelled(is_cancelled)?;
                    conflicting_source |= left_source.value == right_source.value
                        && semantic_accesses_conflict(left_source.access, right_source.access);
                }
            }
            if !conflicting_source {
                continue;
            }
            if left
                .live_after_statements
                .binary_search(&right.initialization)
                .is_ok()
                || right
                    .live_after_statements
                    .binary_search(&left.initialization)
                    .is_ok()
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn semantic_accesses_conflict(first: AccessMode, second: AccessMode) -> bool {
    !matches!(
        (first, second),
        (
            AccessMode::Value | AccessMode::Read,
            AccessMode::Value | AccessMode::Read
        )
    )
}

fn valid_scope_protocol_record(
    protocol: &ScopeProtocol,
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
) -> bool {
    let Some(declaration) = program.declaration(protocol.declaration) else {
        return false;
    };
    let wrela_hir::DeclarationKind::Scope(source) = &declaration.kind else {
        return false;
    };
    let exact_name = declaration.name.as_ref().map(wrela_hir::Name::as_str);
    let acquisition_parameters = source
        .parameters
        .iter()
        .filter(|parameter| **parameter != source.exit_parameter)
        .collect::<Vec<_>>();
    exact_name == Some(protocol.name.as_str())
        && protocol.setup == source.setup
        && protocol.enter == source.enter
        && protocol.abort == source.abort
        && protocol.exit == source.exit
        && exact_runtime_source_type(analysis, &source.result) == Some(protocol.result)
        && protocol.parameters.len() == acquisition_parameters.len()
        && protocol
            .parameters
            .iter()
            .zip(acquisition_parameters)
            .all(|(semantic, parameter)| {
                program
                    .parameters
                    .get(parameter.0 as usize)
                    .is_some_and(|parameter| {
                        !parameter.receiver
                            && parameter.ty.as_ref().is_some_and(|ty| {
                                exact_runtime_source_type(analysis, ty) == Some(semantic.ty)
                            })
                            && matches!(
                                (parameter.access, semantic.access),
                                (wrela_hir::AccessMode::Value, AccessMode::Value)
                                    | (wrela_hir::AccessMode::Read, AccessMode::Read)
                                    | (wrela_hir::AccessMode::Mutate, AccessMode::Mutate)
                                    | (wrela_hir::AccessMode::Take, AccessMode::Take)
                            )
                    })
            })
        && !protocol.suspend_safe
        && protocol.abort_effects == EffectSet(0)
        && protocol.exit_effects == EffectSet(0)
        && analysis
            .proofs
            .get(protocol.proof.0 as usize)
            .is_some_and(|proof| proof.kind == ProofKind::CleanupAcyclic)
}

fn valid_scope_contracts(analysis: &PartialAnalysis, program: &wrela_hir::Program) -> bool {
    if analysis
        .scope_protocols
        .iter()
        .any(|protocol| !valid_scope_protocol_record(protocol, analysis, program))
    {
        return false;
    }
    for activation in &analysis.scope_activations {
        let Some(statement) = program.statement(activation.statement) else {
            return false;
        };
        let wrela_hir::StatementKind::With { value, .. } = statement.kind else {
            return false;
        };
        let Some(value_fact) = exact_child_expression(analysis, activation.function, value) else {
            return false;
        };
        if !matches!(
            value_fact.resolution,
            ExpressionResolution::ScopeCall { protocol, .. } if protocol == activation.protocol
        ) || analysis
            .scope_protocols
            .get(activation.protocol.0 as usize)
            .is_none_or(|protocol| protocol.result != activation.state_type)
            || analysis
                .proofs
                .get(activation.proof.0 as usize)
                .is_none_or(|proof| proof.kind != ProofKind::CleanupAcyclic)
            || activation.cleanup_dependencies.iter().any(|dependency| {
                *dependency == activation.statement
                    || !analysis.scope_activations.iter().any(|candidate| {
                        candidate.function == activation.function
                            && candidate.statement == *dependency
                    })
            })
        {
            return false;
        }
    }
    let mut functions = analysis
        .scope_activations
        .iter()
        .map(|activation| activation.function)
        .collect::<Vec<_>>();
    functions.sort_unstable();
    functions.dedup();
    for function in functions {
        let mut activations = analysis
            .scope_activations
            .iter()
            .filter(|activation| activation.function == function)
            .collect::<Vec<_>>();
        activations.sort_by_key(|activation| activation.statement);
        let count = activations.len();
        if activations.iter().enumerate().any(|(index, activation)| {
            usize::try_from(activation.reverse_source_order) != Ok(count.saturating_sub(index + 1))
        }) {
            return false;
        }
        let mut colors = vec![0u8; count];
        let mut stack = Vec::<(usize, usize)>::new();
        for root in 0..count {
            if colors[root] != 0 {
                continue;
            }
            colors[root] = 1;
            stack.push((root, 0));
            while let Some((node, next)) = stack.last_mut() {
                if *next >= activations[*node].cleanup_dependencies.len() {
                    colors[*node] = 2;
                    stack.pop();
                    continue;
                }
                let dependency = activations[*node].cleanup_dependencies[*next];
                *next += 1;
                let Some(target) = activations
                    .iter()
                    .position(|activation| activation.statement == dependency)
                else {
                    return false;
                };
                match colors[target] {
                    0 => {
                        colors[target] = 1;
                        stack.push((target, 0));
                    }
                    1 => return false,
                    2 => {}
                    _ => return false,
                }
            }
        }
        let edge_count = activations.iter().try_fold(0u64, |total, activation| {
            total.checked_add(u64::try_from(activation.cleanup_dependencies.len()).ok()?)
        });
        let Some(proof) = activations
            .first()
            .and_then(|activation| analysis.proofs.get(activation.proof.0 as usize))
        else {
            return false;
        };
        if activations
            .iter()
            .any(|activation| activation.proof != proof.id)
            || proof.bound != edge_count
        {
            return false;
        }
    }
    true
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
    let Some(ok_payload_type) = variants
        .first()
        .and_then(|variant| variant.fields.first())
        .map(|field| field.ty)
    else {
        return false;
    };
    let Some(err_payload_type) = variants
        .get(1)
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
        && value_matches(ok_payload, ok_payload_type)
        && value_matches(err_payload, err_payload_type)
        && value_matches(propagated, result_type)
}

fn valid_option_try_resolution(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    option_type: SemanticTypeId,
    some_variant: u32,
    none_variant: u32,
    some_payload: ValueId,
    propagated: ValueId,
) -> bool {
    let Some(SemanticTypeKind::Enumeration {
        arguments,
        variants,
        ..
    }) = analysis
        .types
        .get(option_type.0 as usize)
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
    let value_matches = |value: ValueId, ty: SemanticTypeId| {
        analysis.values.get(value.0 as usize).is_some_and(|value| {
            value.function == function && value.ty == ty && value.category == ValueCategory::Value
        })
    };
    some_variant == 0
        && none_variant == 1
        && some_payload != propagated
        && runtime_enum_arguments_supported(arguments, variants)
        && matches!(variants.as_slice(), [some, none]
            if some.name == "Some"
                && matches!(some.fields.as_slice(), [field] if field.ty == payload_type)
                && none.name == "None"
                && none.fields.is_empty())
        && value_matches(some_payload, payload_type)
        && value_matches(propagated, option_type)
}

fn valid_expression_region(
    fact: &ExpressionFact,
    analysis: &PartialAnalysis,
    graph: &ImageGraph,
) -> bool {
    let resolves = |region: RegionId| (region.0 as usize) < graph.regions.len();
    match fact.category {
        ValueCategory::Place => fact.region.is_some_and(resolves),
        ValueCategory::SharedView | ValueCategory::MutableView => match fact.region {
            Some(region) => resolves(region),
            None => exact_regionless_lexical_view_witness(fact, analysis),
        },
        ValueCategory::Value | ValueCategory::TypeValue => match &fact.resolution {
            ExpressionResolution::Field { .. } => {
                fact.region.is_none()
                    || exact_actor_state_field_matches(
                        analysis,
                        fact.function,
                        fact.expression,
                        fact.result,
                        fact.region,
                    )
            }
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
            | ExpressionResolution::Scope(_)
            | ExpressionResolution::Projection(_)
            | ExpressionResolution::Constructor { .. }
            | ExpressionResolution::InitializerConstruction { .. }
            | ExpressionResolution::ResultTry { .. }
            | ExpressionResolution::OptionTry { .. }
            | ExpressionResolution::ClosedRange { .. }
            | ExpressionResolution::ClosedArray { .. }
            | ExpressionResolution::DirectCall { .. }
            | ExpressionResolution::MethodCall { .. }
            | ExpressionResolution::ScopeCall { .. }
            | ExpressionResolution::ProjectionCall { .. }
            | ExpressionResolution::OperatorCall { .. }
            | ExpressionResolution::DerivedEquality { .. }
            | ExpressionResolution::DerivedFrom { .. }
            | ExpressionResolution::DerivedFromType { .. }
            | ExpressionResolution::DerivedFromFunction { .. }
            | ExpressionResolution::BoundedInterpolation { .. }
            | ExpressionResolution::EnumTypeTest { .. }
            | ExpressionResolution::ActorRequest { .. }
            | ExpressionResolution::Closure { .. }
            | ExpressionResolution::Builtin(_) => fact.region.is_none(),
        },
        ValueCategory::Error => false,
    }
}

fn exact_actor_state_field_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    expression: ExpressionId,
    result: Option<ValueId>,
    region: Option<RegionId>,
) -> bool {
    analysis.actor_state_accesses.iter().any(|access| {
        access.function == function
            && region == Some(access.region)
            && matches!(
                access.kind,
                ActorStateAccessKind::Read {
                    expression: candidate,
                    result: candidate_result,
                } if candidate == expression && result == Some(candidate_result)
            )
    })
}

fn exact_actor_state_write_matches(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    statement: StatementId,
    receiver: wrela_hir::ParameterId,
    value_expression: ExpressionId,
    value: Option<ValueId>,
) -> bool {
    analysis.actor_state_accesses.iter().any(|access| {
        access.function == function
            && access.receiver == receiver
            && matches!(
                access.kind,
                ActorStateAccessKind::Write {
                    statement: candidate,
                    value_expression: candidate_expression,
                    value: candidate_value,
                }
                | ActorStateAccessKind::CompoundAssign {
                    statement: candidate,
                    value_expression: candidate_expression,
                    value: candidate_value,
                    ..
                } if candidate == statement
                    && candidate_expression == value_expression
                    && value == Some(candidate_value)
            )
    })
}

fn exact_actor_state_compound_results(
    analysis: &PartialAnalysis,
    function: FunctionInstanceId,
    statement: StatementId,
) -> Option<(ValueId, ValueId)> {
    analysis.actor_state_accesses.iter().find_map(|access| {
        if access.function != function {
            return None;
        }
        match access.kind {
            ActorStateAccessKind::CompoundAssign {
                statement: candidate,
                current,
                result,
                ..
            } if candidate == statement => Some((current, result)),
            _ => None,
        }
    })
}

fn exact_regionless_lexical_view_witness(
    fact: &ExpressionFact,
    analysis: &PartialAnalysis,
) -> bool {
    let expected_mutable = match fact.category {
        ValueCategory::SharedView => false,
        ValueCategory::MutableView => true,
        _ => return false,
    };
    let (view, value) = match &fact.resolution {
        ExpressionResolution::ProjectionCall { view, .. } => (*view, fact.result),
        ExpressionResolution::Value(value) => {
            let Some(view) = analysis.lexical_views.iter().find(|view| {
                view.function == fact.function
                    && view.value == *value
                    && analysis
                        .projection_protocols
                        .get(view.protocol.0 as usize)
                        .is_some_and(|protocol| {
                            protocol.mutable == expected_mutable && protocol.target == fact.ty
                        })
            }) else {
                return false;
            };
            (view.id, Some(*value))
        }
        _ => return false,
    };
    let Some(value) = value else {
        return false;
    };
    analysis
        .lexical_views
        .get(view.0 as usize)
        .is_some_and(|record| {
            record.id == view
                && record.function == fact.function
                && record.value == value
                && analysis
                    .projection_protocols
                    .get(record.protocol.0 as usize)
                    .is_some_and(|protocol| {
                        protocol.mutable == expected_mutable && protocol.target == fact.ty
                    })
        })
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
        && strict_ids(&fact.live_lexical_views_after)
        && fact.live_lexical_views_after.iter().all(|view| {
            analysis
                .lexical_views
                .get(view.0 as usize)
                .is_some_and(|view| {
                    view.function == fact.function
                        && fact.initialized_after.binary_search(&view.value).is_ok()
                        && fact.moved_after.binary_search(&view.value).is_err()
                        && valid_lexical_view_prefix(view, analysis)
                })
        })
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

fn valid_iso_pool_contracts(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    graph: &ImageGraph,
) -> bool {
    if graph.pools.is_empty() {
        return graph.brands.is_empty()
            && !analysis
                .types
                .iter()
                .any(|ty| matches!(ty.kind, SemanticTypeKind::Iso { .. }));
    }
    // This first source-authenticated increment is deliberately pool-only.
    // Actor constructor injection and runtime pool handles remain sealed.
    if !graph.actors.is_empty()
        || !graph.tasks.is_empty()
        || !graph.devices.is_empty()
        || graph.pools.len() != graph.brands.len()
        || graph.pools.len() != graph.regions.len()
    {
        return false;
    }
    let iso_call_count = program
        .expressions
        .iter()
        .filter(|expression| {
            let wrela_hir::ExpressionKind::Call { callee, .. } = expression.kind else {
                return false;
            };
            let Some(wrela_hir::Expression {
                kind: wrela_hir::ExpressionKind::Index { base, .. },
                ..
            }) = program.expression(callee)
            else {
                return false;
            };
            matches!(
                program.expression(*base).map(|value| &value.kind),
                Some(wrela_hir::ExpressionKind::Field { name, .. })
                    if name.as_str() == "iso_pool"
            )
        })
        .count();
    if iso_call_count != graph.pools.len() {
        return false;
    }

    let mut static_bytes = 0u64;
    let mut expected_capacity_proofs = Vec::new();
    if expected_capacity_proofs
        .try_reserve_exact(graph.pools.len())
        .is_err()
    {
        return false;
    }
    for (index, pool) in graph.pools.iter().enumerate() {
        let Ok(index_u32) = u32::try_from(index) else {
            return false;
        };
        let expected_pool = PoolId(index_u32);
        let expected_brand = BrandId(index_u32);
        if pool.id != expected_pool || pool.brand != expected_brand {
            return false;
        }
        let Some(call) = program.expressions.iter().find(|expression| {
            expression.source == pool.source
                && matches!(expression.kind, wrela_hir::ExpressionKind::Call { .. })
        }) else {
            return false;
        };
        let wrela_hir::ExpressionKind::Call { callee, arguments } = &call.kind else {
            return false;
        };
        let Some(wrela_hir::Expression {
            kind:
                wrela_hir::ExpressionKind::Index {
                    base,
                    index: payload_index,
                },
            ..
        }) = program.expression(*callee)
        else {
            return false;
        };
        let Some(wrela_hir::Expression {
            kind: wrela_hir::ExpressionKind::Field { name, .. },
            ..
        }) = program.expression(*base)
        else {
            return false;
        };
        if name.as_str() != "iso_pool" {
            return false;
        }
        let Some(wrela_hir::Expression {
            kind: wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(payload)),
            source: _,
            ..
        }) = program.expression(*payload_index)
        else {
            return false;
        };
        if payload.declaration
            != analysis
                .types
                .get(pool.payload.0 as usize)
                .and_then(|ty| match ty.kind {
                    SemanticTypeKind::Structure { declaration, .. } => Some(declaration),
                    _ => None,
                })
                .unwrap_or(DeclarationId(u32::MAX))
        {
            return false;
        }
        let mut brand_source = None;
        let mut brand_declaration = None;
        let mut slots_source = None;
        let mut slots = None;
        let mut maximum_source = None;
        let mut maximum = None;
        for argument in arguments {
            let Some(value) = argument.expression().and_then(|id| program.expression(id)) else {
                return false;
            };
            match argument.name.as_ref().map(wrela_hir::Name::as_str) {
                Some("brand") if brand_source.is_none() => {
                    let wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                        declaration,
                    )) = &value.kind
                    else {
                        return false;
                    };
                    brand_source = Some(value.source);
                    brand_declaration = Some(declaration.declaration);
                }
                Some("slots") if slots_source.is_none() => {
                    let wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(value_text)) =
                        &value.kind
                    else {
                        return false;
                    };
                    slots_source = Some(value.source);
                    slots =
                        parse_hir_integer(value_text).and_then(|value| u64::try_from(value).ok());
                }
                Some("max_payload") if maximum_source.is_none() => {
                    let wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(value_text)) =
                        &value.kind
                    else {
                        return false;
                    };
                    maximum_source = Some(value.source);
                    maximum =
                        parse_hir_integer(value_text).and_then(|value| u64::try_from(value).ok());
                }
                _ => return false,
            }
        }
        let (
            Some(brand_source),
            Some(brand_declaration),
            Some(slots_source),
            Some(slots),
            Some(maximum_source),
            Some(maximum),
        ) = (
            brand_source,
            brand_declaration,
            slots_source,
            slots,
            maximum_source,
            maximum,
        )
        else {
            return false;
        };
        let Some(brand) = graph.brands.get(index) else {
            return false;
        };
        let Some(brand_record) = program.declaration(brand_declaration) else {
            return false;
        };
        if brand.id != expected_brand
            || brand.declaration != brand_declaration
            || brand.owner != ImageOwner::Pool(expected_pool)
            || brand.source != brand_source
            || !matches!(brand_record.kind, wrela_hir::DeclarationKind::Brand)
            || brand_record.name.as_ref().map(wrela_hir::Name::as_str) != Some(pool.name.as_str())
            || pool.capacity != slots
        {
            return false;
        }
        let Some(payload_record) = analysis.types.get(pool.payload.0 as usize) else {
            return false;
        };
        if payload_record
            .size_upper_bound
            .is_none_or(|size| size == 0 || size > maximum)
            || pool.alignment != payload_record.alignment_lower_bound
        {
            return false;
        }
        let Some(capacity_bytes) = slots.checked_mul(maximum) else {
            return false;
        };
        static_bytes = match static_bytes.checked_add(capacity_bytes) {
            Some(value) => value,
            None => return false,
        };
        let Some(region) = graph.regions.get(index) else {
            return false;
        };
        let Some(proof) = analysis.proofs.get(region.proof.0 as usize) else {
            return false;
        };
        if region.id != RegionId(index_u32)
            || region.name != pool.name
            || region.class != RegionClass::Pool(expected_pool)
            || region.capacity_bytes != capacity_bytes
            || region.alignment != pool.alignment
            || region.owner != ImageOwner::Pool(expected_pool)
            || region.source != pool.source
            || proof.kind != ProofKind::CapacityBound
            || proof.bound != Some(slots)
            || proof.sources.as_slice() != [pool.source, brand_source, slots_source, maximum_source]
        {
            return false;
        }
        expected_capacity_proofs.push(region.proof);
        let iso_matches = analysis
            .types
            .iter()
            .filter(|ty| {
                matches!(
                    ty,
                    SemanticType {
                        kind: SemanticTypeKind::Iso { brand, payload },
                        linearity: Linearity::StrictLinear,
                        size_upper_bound: None,
                        alignment_lower_bound: 1,
                        source: Some(source),
                        ..
                    } if *brand == expected_brand
                        && *payload == pool.payload
                        && *source == pool.source
                )
            })
            .count();
        if iso_matches != 1 {
            return false;
        }
    }
    if graph.static_bytes != static_bytes || graph.peak_bytes != static_bytes {
        return false;
    }
    let Some(entry) = analysis.functions.get(graph.entry.0 as usize) else {
        return false;
    };
    let mut closed_proofs = entry.proofs.iter().filter_map(|id| {
        analysis
            .proofs
            .get(id.0 as usize)
            .filter(|proof| proof.kind == ProofKind::ImageClosed)
    });
    let Some(closed) = closed_proofs.next() else {
        return false;
    };
    if closed_proofs.next().is_some() {
        return false;
    }
    let mut expected_dependencies = Vec::new();
    if expected_dependencies
        .try_reserve_exact(expected_capacity_proofs.len().saturating_add(2))
        .is_err()
    {
        return false;
    }
    expected_dependencies.extend([ProofId(0), ProofId(1)]);
    expected_dependencies.extend_from_slice(&expected_capacity_proofs);
    closed.bound == Some(static_bytes)
        && closed.depends_on == expected_dependencies
        && expected_capacity_proofs
            .iter()
            .all(|proof| entry.proofs.binary_search(proof).is_ok())
}

fn valid_static_supervision_contract(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    graph: &ImageGraph,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let mut supervision = analysis
        .proofs
        .iter()
        .filter(|proof| proof.kind == ProofKind::SupervisionComplete);
    if graph.actors.is_empty() {
        return Ok(supervision.next().is_none());
    }
    let Some(proof) = supervision.next() else {
        return Ok(false);
    };
    if supervision.next().is_some() {
        return Ok(false);
    }
    let Some(node_count) = graph.actors.len().checked_add(graph.tasks.len()) else {
        return Ok(false);
    };
    if proof.sources.len() != node_count
        || proof.subject != "complete static actor/task parent topology"
        || proof.bound != u64::try_from(node_count).ok()
        || proof.depends_on.as_slice() != [ProofId(0)]
        || proof.explanation.as_slice()
            != [
                "the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed",
            ]
        || analysis
            .proofs
            .first()
            .is_none_or(|type_checked| type_checked.kind != ProofKind::TypeChecked)
    {
        return Ok(false);
    }

    let mut source_index = 0usize;
    for actor in &graph.actors {
        check_analysis_cancelled(is_cancelled)?;
        if proof.sources.get(source_index) != Some(&actor.source) {
            return Ok(false);
        }
        source_index += 1;
        let mut cursor = actor.supervisor;
        for _ in 0..graph.actors.len() {
            let Some(parent) = cursor else {
                break;
            };
            if parent == actor.id {
                return Ok(false);
            }
            let Some(parent_record) = graph
                .actors
                .get(parent.0 as usize)
                .filter(|candidate| candidate.id == parent)
            else {
                return Ok(false);
            };
            cursor = parent_record.supervisor;
        }
        if cursor.is_some() {
            return Ok(false);
        }
    }
    for task in &graph.tasks {
        check_analysis_cancelled(is_cancelled)?;
        if proof.sources.get(source_index) != Some(&task.source) {
            return Ok(false);
        }
        source_index += 1;
        let parent_matches = task.supervisor.is_some_and(|parent| {
            graph
                .actors
                .get(parent.0 as usize)
                .is_some_and(|candidate| candidate.id == parent)
        });
        let entry = analysis
            .functions
            .get(task.entry.0 as usize)
            .filter(|function| {
                function.role == FunctionRole::TaskEntry(task.id)
                    && function.source == Some(task.source)
            });
        let declared_owner = entry
            .and_then(|function| match function.origin {
                FunctionOrigin::Source { declaration, .. } => program.declaration(declaration),
                _ => None,
            })
            .and_then(|declaration| match declaration.owner {
                wrela_hir::DeclarationOwner::Declaration(owner) => Some(owner),
                wrela_hir::DeclarationOwner::Module(_) => None,
            });
        let declared_supervisor = declared_owner.and_then(|owner| {
            graph.actors.iter().find_map(|actor| {
                analysis
                    .types
                    .get(actor.class.0 as usize)
                    .and_then(|ty| match ty.kind {
                        SemanticTypeKind::Class { declaration, .. } if declaration == owner => {
                            Some(actor.id)
                        }
                        _ => None,
                    })
            })
        });
        if !parent_matches || entry.is_none() || task.supervisor != declared_supervisor {
            return Ok(false);
        }
    }

    let entry_has_proof = analysis
        .functions
        .get(graph.entry.0 as usize)
        .is_some_and(|entry| entry.proofs.binary_search(&proof.id).is_ok());
    let mut image_closed = analysis
        .proofs
        .iter()
        .filter(|candidate| candidate.kind == ProofKind::ImageClosed);
    let closure_reaches = image_closed.next().is_some_and(|closed| {
        closed.depends_on.binary_search(&proof.id).is_ok()
            || closed.depends_on.iter().any(|dependency| {
                analysis
                    .proofs
                    .get(dependency.0 as usize)
                    .is_some_and(|parent| parent.depends_on.binary_search(&proof.id).is_ok())
            })
    });
    Ok(entry_has_proof && closure_reaches && image_closed.next().is_none())
}

fn valid_actor_state_contracts(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    graph: &ImageGraph,
) -> bool {
    for actor in &graph.actors {
        let Some(SemanticType {
            kind:
                SemanticTypeKind::Class {
                    declaration,
                    arguments,
                    fields,
                },
            linearity,
            size_upper_bound,
            alignment_lower_bound,
            source,
            ..
        }) = analysis.types.get(actor.class.0 as usize)
        else {
            return false;
        };
        let Some(declaration_record) = program.declaration(*declaration) else {
            return false;
        };
        let wrela_hir::DeclarationKind::Structure(class) = &declaration_record.kind else {
            return false;
        };
        if !arguments.is_empty()
            || !fields.is_empty()
            || *linearity != Linearity::ReclaimableLinear
            || *size_upper_bound != Some(0)
            || *alignment_lower_bound != 1
            || *source != Some(declaration_record.source)
        {
            return false;
        }
        let state_source = match class.fields.as_slice() {
            [] => None,
            [field]
                if matches!(
                    field.ty.kind,
                    wrela_hir::TypeExpressionKind::Named {
                        definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::Actor),
                        ..
                    }
                ) =>
            {
                None
            }
            [field]
                if field.name.as_str() == "value"
                    && matches!(
                        field.ty.kind,
                        wrela_hir::TypeExpressionKind::Named {
                            definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::U64),
                            ref arguments,
                        } if arguments.is_empty()
                    ) =>
            {
                let Some(default) = field.default else {
                    return false;
                };
                let Some(expression) = program.expression(default) else {
                    return false;
                };
                if !matches!(
                    &expression.kind,
                    wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(value))
                        if value == "0"
                ) {
                    return false;
                }
                Some(field.source)
            }
            _ => return false,
        };
        let mut state_regions = graph.regions.iter().filter(|region| {
            region
                .name
                .strip_suffix(".state")
                .is_some_and(|prefix| prefix == actor.name)
        });
        match (state_source, state_regions.next(), state_regions.next()) {
            (None, None, None) => {}
            (Some(source), Some(region), None) => {
                let proof_matches =
                    analysis
                        .proofs
                        .get(region.proof.0 as usize)
                        .is_some_and(|proof| {
                            proof.id == region.proof
                                && proof.kind == ProofKind::CapacityBound
                                && proof.bound == Some(1)
                                && proof.sources.as_slice() == [source]
                                && proof.depends_on.is_empty()
                        });
                if region.class != RegionClass::Image
                    || region.capacity_bytes != 8
                    || region.alignment != 8
                    || region.owner != ImageOwner::Actor(actor.id)
                    || region.source != source
                    || !proof_matches
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn valid_actor_state_accesses(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    graph: &ImageGraph,
) -> bool {
    for (index, access) in analysis.actor_state_accesses.iter().enumerate() {
        if analysis.actor_state_accesses[index + 1..]
            .iter()
            .any(|candidate| candidate.function == access.function && candidate.kind == access.kind)
        {
            return false;
        }
        let Some(function) = analysis.functions.get(access.function.0 as usize) else {
            return false;
        };
        let FunctionOrigin::Source { declaration, body } = function.origin else {
            return false;
        };
        if function.role != FunctionRole::ActorTurn(access.actor)
            || graph.actors.get(access.actor.0 as usize).is_none_or(|actor| {
                analysis.types.get(actor.class.0 as usize).is_none_or(|ty| {
                    !matches!(
                        ty.kind,
                        SemanticTypeKind::Class { declaration, ref arguments, ref fields }
                            if declaration == access.class && arguments.is_empty() && fields.is_empty()
                    )
                })
            })
            || function.parameters.first().is_none_or(|parameter| {
                parameter.parameter != access.receiver || parameter.access != AccessMode::Mutate
            })
        {
            return false;
        }
        let Some(receiver) = program.parameter(access.receiver) else {
            return false;
        };
        if !receiver.receiver
            || receiver.owner != wrela_hir::CallableOwner::Declaration(declaration)
            || receiver.access != wrela_hir::AccessMode::Mutate
        {
            return false;
        }
        let Some(class) = program.declaration(access.class) else {
            return false;
        };
        let wrela_hir::DeclarationKind::Structure(class) = &class.kind else {
            return false;
        };
        let Some(field) = class.fields.get(access.field as usize) else {
            return false;
        };
        if access.field != 0
            || field.name.as_str() != "value"
            || !matches!(
                field.ty.kind,
                wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::U64),
                    ref arguments,
                } if arguments.is_empty()
            )
        {
            return false;
        }
        let Some(region) = graph.regions.get(access.region.0 as usize) else {
            return false;
        };
        if region.owner != ImageOwner::Actor(access.actor)
            || region.class != RegionClass::Image
            || region.capacity_bytes != 8
            || region.alignment != 8
            || region.proof != access.capacity
            || graph
                .actors
                .get(access.actor.0 as usize)
                .is_none_or(|actor| region.name.strip_suffix(".state") != Some(actor.name.as_str()))
            || analysis
                .proofs
                .get(access.capacity.0 as usize)
                .is_none_or(|proof| {
                    proof.kind != ProofKind::CapacityBound
                        || proof.bound != Some(1)
                        || proof.sources.as_slice() != [region.source]
                })
        {
            return false;
        }
        match access.kind {
            ActorStateAccessKind::Read { expression, result } => {
                let Some(record) = program.expression(expression) else {
                    return false;
                };
                let wrela_hir::ExpressionKind::Field { base, ref name } = record.kind else {
                    return false;
                };
                if record.source != access.source || name.as_str() != field.name.as_str() {
                    return false;
                }
                let Some(base) = program.expression(base) else {
                    return false;
                };
                if !matches!(base.kind, wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(parameter)) if parameter == access.receiver)
                    || analysis
                        .expressions
                        .iter()
                        .find(|fact| {
                            fact.function == access.function && fact.expression == expression
                        })
                        .is_none_or(|fact| {
                            fact.result != Some(result)
                                || fact.region != Some(access.region)
                                || fact.resolution
                                    != ExpressionResolution::Field {
                                        index: access.field,
                                    }
                                || !fact.proofs.contains(&access.capacity)
                        })
                {
                    return false;
                }
            }
            ActorStateAccessKind::Write {
                statement,
                value_expression,
                value,
            } => {
                let Some(record) = program.statement(statement) else {
                    return false;
                };
                let wrela_hir::StatementKind::Assign {
                    ref targets,
                    operator,
                    value: source_value,
                } = record.kind
                else {
                    return false;
                };
                let [target] = targets.as_slice() else {
                    return false;
                };
                if record.source != access.source
                    || operator != wrela_hir::AssignmentOperator::Assign
                    || source_value != value_expression
                    || target.root != wrela_hir::Definition::Parameter(access.receiver)
                    || !matches!(target.projections.as_slice(), [wrela_hir::PlaceProjection::Field(name)] if name.as_str() == field.name.as_str())
                    || analysis
                        .expressions
                        .iter()
                        .find(|fact| {
                            fact.function == access.function && fact.expression == value_expression
                        })
                        .is_none_or(|fact| fact.result != Some(value))
                {
                    return false;
                }
                if program.body(body).is_none()
                    || !analysis
                        .statements
                        .iter()
                        .any(|fact| fact.function == access.function && fact.statement == statement)
                {
                    return false;
                }
            }
            ActorStateAccessKind::CompoundAssign {
                statement,
                operator: access_operator,
                value_expression,
                value,
                current,
                result,
            } => {
                let Some(record) = program.statement(statement) else {
                    return false;
                };
                let wrela_hir::StatementKind::Assign {
                    ref targets,
                    operator,
                    value: source_value,
                } = record.kind
                else {
                    return false;
                };
                let [target] = targets.as_slice() else {
                    return false;
                };
                let rhs_matches = analysis.expressions.iter().any(|fact| {
                    fact.function == access.function
                        && fact.expression == value_expression
                        && fact.result == Some(value)
                        && analysis.types.get(fact.ty.0 as usize).is_some_and(|ty| {
                            matches!(
                                ty.kind,
                                SemanticTypeKind::Integer {
                                    signed: false,
                                    bits: 64,
                                    pointer_sized: false,
                                }
                            )
                        })
                });
                let synthetic_matches = [
                    (current, SemanticValueOrigin::ActorStateLoad(statement)),
                    (
                        result,
                        SemanticValueOrigin::ActorStateCompoundResult(statement),
                    ),
                ]
                .into_iter()
                .all(|(id, origin)| {
                    id != value
                        && analysis.values.get(id.0 as usize).is_some_and(|semantic| {
                            semantic.function == access.function
                                && semantic.origin == origin
                                && semantic.category == ValueCategory::Value
                                && semantic.class == SemanticValueClass::FirstClass
                                && semantic.source == Some(record.source)
                                && semantic.source_name.is_none()
                                && analysis
                                    .types
                                    .get(semantic.ty.0 as usize)
                                    .is_some_and(|ty| {
                                        matches!(
                                            ty.kind,
                                            SemanticTypeKind::Integer {
                                                signed: false,
                                                bits: 64,
                                                pointer_sized: false,
                                            }
                                        )
                                    })
                                && !analysis.expressions.iter().any(|fact| {
                                    fact.function == access.function && fact.result == Some(id)
                                })
                        })
                });
                if record.source != access.source
                    || !matches!(
                        operator,
                        wrela_hir::AssignmentOperator::Add
                            | wrela_hir::AssignmentOperator::Subtract
                    )
                    || operator != access_operator
                    || source_value != value_expression
                    || target.root != wrela_hir::Definition::Parameter(access.receiver)
                    || !matches!(target.projections.as_slice(), [wrela_hir::PlaceProjection::Field(name)] if name.as_str() == field.name.as_str())
                    || current == result
                    || !rhs_matches
                    || !synthetic_matches
                    || program.body(body).is_none()
                    || !analysis
                        .statements
                        .iter()
                        .any(|fact| fact.function == access.function && fact.statement == statement)
                {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) const ACTOR_STATE_PROMOTION_REASON: &str =
    "actor state store outlives its non-reentrant turn frame";

fn actor_state_region_inference_candidate(
    kind: ActorStateAccessKind,
) -> Option<(StatementId, ValueId, &'static str)> {
    match kind {
        ActorStateAccessKind::Write {
            statement, value, ..
        } => Some((statement, value, "actor-state-store")),
        ActorStateAccessKind::CompoundAssign {
            statement, result, ..
        } => Some((statement, result, "actor-state-compound-store")),
        ActorStateAccessKind::Read { .. } => None,
    }
}

fn valid_region_inference(
    analysis: &PartialAnalysis,
    program: &wrela_hir::Program,
    graph: &ImageGraph,
) -> bool {
    let promotion_count = analysis
        .actor_state_accesses
        .iter()
        .filter(|access| actor_state_region_inference_candidate(access.kind).is_some())
        .count();
    if analysis.region_assignments.len() != promotion_count
        || analysis.promotions.len() != promotion_count
    {
        return false;
    }
    for (index, ((assignment, promotion), access)) in analysis
        .region_assignments
        .iter()
        .zip(&analysis.promotions)
        .zip(
            analysis
                .actor_state_accesses
                .iter()
                .filter(|access| actor_state_region_inference_candidate(access.kind).is_some()),
        )
        .enumerate()
    {
        let Some((statement, value, name)) = actor_state_region_inference_candidate(access.kind)
        else {
            return false;
        };
        let Some(source_region) = graph.regions.get(promotion.source_region.0 as usize) else {
            return false;
        };
        let Some(destination) = graph.regions.get(assignment.region.0 as usize) else {
            return false;
        };
        let allocation = format!("alloc:{}:{}", assignment.id.0, assignment.name);
        let source_statement = program.statement(statement);
        if assignment.id.0 as usize != index
            || assignment.name != name
            || assignment.function != access.function
            || assignment.statement != statement
            || assignment.value != value
            || assignment.region != access.region
            || assignment.source != access.source
            || promotion.allocation != assignment.id
            || promotion.value != value
            || promotion.destination != assignment.region
            || promotion.reason != ACTOR_STATE_PROMOTION_REASON
            || promotion.source != access.source
            || source_region.class != RegionClass::TaskFrame
            || source_region.owner != ImageOwner::Actor(access.actor)
            || !source_region.name.ends_with(".turn-frame")
            || destination.class != RegionClass::Image
            || destination.owner != ImageOwner::Actor(access.actor)
            || source_statement.is_none_or(|statement| {
                statement.attributes.iter().any(|attribute| {
                    matches!(
                        attribute.identity,
                        wrela_hir::AttributeIdentity::Builtin(
                            wrela_hir::BuiltinAttribute::NoPromote
                        )
                    )
                })
            })
            || analysis
                .proofs
                .get(promotion.proof.0 as usize)
                .is_none_or(|proof| {
                    proof.id != promotion.proof
                        || proof.kind != ProofKind::RegionBound
                        || proof.subject != allocation
                        || proof.sources.as_slice() != [access.source]
                        || !proof.depends_on.is_empty()
                        || proof.bound != Some(8)
                        || proof.explanation.as_slice() != [ACTOR_STATE_PROMOTION_REASON]
                })
        {
            return false;
        }
    }
    true
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
        SemanticValueOrigin::ActorStateLoad(statement)
        | SemanticValueOrigin::ActorStateCompoundResult(statement) => statement.0 < hir.statements,
    }
}

fn valid_semantic_value_class(value: &SemanticValue, analysis: &PartialAnalysis) -> bool {
    if matches!(
        (value.category, value.class),
        (
            ValueCategory::SharedView | ValueCategory::MutableView,
            SemanticValueClass::Ephemeral(EphemeralKind::View)
        ) | (
            ValueCategory::Value
                | ValueCategory::Place
                | ValueCategory::TypeValue
                | ValueCategory::Error,
            SemanticValueClass::FirstClass
        )
    ) {
        return true;
    }
    matches!(
        (value.category, value.class, value.origin),
        (
            ValueCategory::Value,
            SemanticValueClass::Ephemeral(EphemeralKind::AdmissionResult),
            SemanticValueOrigin::Expression(expression),
        ) if analysis.expressions.iter().any(|fact| {
            fact.function == value.function
                && fact.expression == expression
                && fact.ty == value.ty
                && fact.category == ValueCategory::Value
                && fact.result == Some(value.id)
                && matches!(
                    fact.resolution,
                    ExpressionResolution::Builtin(IntrinsicOperation::ActorTrySend { .. })
                )
        })
    ) || matches!(
        (value.category, value.class, value.origin),
        (
            ValueCategory::Value,
            SemanticValueClass::Ephemeral(EphemeralKind::AsyncOutcome),
            SemanticValueOrigin::Expression(expression),
        ) if analysis.expressions.iter().any(|fact| {
            fact.function == value.function
                && fact.expression == expression
                && fact.ty == value.ty
                && fact.category == ValueCategory::Value
                && fact.result == Some(value.id)
                && fact.resolution == ExpressionResolution::Builtin(IntrinsicOperation::Await)
        })
    )
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
            "projection protocols",
            partial.projection_protocols.len(),
            limits.projection_protocols,
        ),
        (
            "lexical views",
            partial.lexical_views.len(),
            limits.lexical_views,
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
        partial.projection_protocols.len(),
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
            | SemanticTypeKind::BoundedString { .. }
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
            | ExpressionResolution::MethodCall { arguments, .. }
            | ExpressionResolution::ScopeCall { arguments, .. }
            | ExpressionResolution::ProjectionCall { arguments, .. }
            | ExpressionResolution::OperatorCall { arguments, .. } => meter.edges(arguments),
            ExpressionResolution::Closure { captures, .. } => meter.edges(captures),
            ExpressionResolution::DerivedEquality {
                fields,
                conjunctions,
                ..
            } => {
                meter.edges(fields);
                meter.edges(conjunctions);
            }
            ExpressionResolution::BoundedInterpolation { parts, .. } => {
                meter.edges(parts);
                for part in parts {
                    check_analysis_cancelled(is_cancelled)?;
                    if let BoundedInterpolationPart::Text { value, .. } = part {
                        meter.text(value);
                    }
                }
            }
            ExpressionResolution::ClosedArray { elements, .. } => meter.edges(elements),
            ExpressionResolution::Error
            | ExpressionResolution::Value(_)
            | ExpressionResolution::Function(_)
            | ExpressionResolution::Scope(_)
            | ExpressionResolution::Projection(_)
            | ExpressionResolution::Constructor { .. }
            | ExpressionResolution::InitializerConstruction { .. }
            | ExpressionResolution::DerivedFrom { .. }
            | ExpressionResolution::DerivedFromType { .. }
            | ExpressionResolution::DerivedFromFunction { .. }
            | ExpressionResolution::ResultTry { .. }
            | ExpressionResolution::OptionTry { .. }
            | ExpressionResolution::ClosedRange { .. }
            | ExpressionResolution::EnumTypeTest { .. }
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
        meter.edges(&fact.live_lexical_views_after);
        meter.edges(&fact.proofs);
        meter.enforce(limits)?;
    }
    for protocol in &partial.projection_protocols {
        check_analysis_cancelled(is_cancelled)?;
        meter.text(&protocol.name);
        meter.edges(&protocol.parameters);
        meter.edges(&protocol.provenance);
        meter.enforce(limits)?;
    }
    for view in &partial.lexical_views {
        check_analysis_cancelled(is_cancelled)?;
        meter.edges(&view.sources);
        meter.edges(&view.terminal_uses);
        meter.edges(&view.live_after_statements);
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

        let mut limits = AnalysisLimits::standard();
        limits.lexical_views = 0;
        assert!(matches!(
            limits.validate(),
            Err(AnalysisFailure::InvalidLimits)
        ));
    }
}
