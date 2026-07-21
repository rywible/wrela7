//! Bounded, exact conversion from a sealed semantic analysis result to
//! specialized, syntax-free SemanticWir.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_sema::{self as sema, AnalyzedImage};
pub use wrela_semantic_wir as semantic_wir;
use wrela_semantic_wir::{
    self as wir, SemanticRegion, SemanticStatement, SemanticWir, Span, ValidatedSemanticWir,
    ValidationErrors,
};
pub use wrela_semantic_wir::{
    AccessMode as SemanticAccessMode, ArithmeticMode as SemanticArithmeticMode, SemanticOperation,
    SemanticStatement as LoweredSemanticStatement, TypeId as SemanticTypeId,
    TypeKind as SemanticTypeKind,
};
use wrela_test_model::{
    FullImageTestGroup, GuestTestOutcome, ImageRoot, ImageTestInvocation, TEST_PROTOCOL_VERSION,
    TestEvent, TestEventKind, TestKind as PlannedTestKind,
};
use wrela_test_protocol::{
    CanonicalTestEventCodec, ProtocolError, ProtocolLimits, seal_encoded_event,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweringLimits {
    pub types: u32,
    pub functions: u32,
    pub values: u64,
    pub operations: u64,
    /// Total elements across all variable-length model collections.
    pub model_edges: u64,
    /// Total UTF-8 and byte-string payload retained in SemanticWir.
    pub payload_bytes: u64,
    pub constant_depth: u32,
    pub structured_region_depth: u32,
}

impl LoweringLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            types: 16_000_000,
            functions: 16_000_000,
            values: 256_000_000,
            operations: 256_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            constant_depth: 1024,
            structured_region_depth: 1024,
        }
    }

    pub fn validate(self) -> Result<(), LowerError> {
        if self.types == 0
            || self.functions == 0
            || self.values == 0
            || self.operations == 0
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.constant_depth == 0
            || self.constant_depth > 1024
            || self.structured_region_depth == 0
            || self.structured_region_depth > 1024
        {
            Err(LowerError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct LowerRequest {
    pub input: AnalyzedImage,
    pub limits: LoweringLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringReport {
    pub semantic_types: u32,
    pub function_instances: u32,
    /// Number of `Let` operations across all nested semantic regions.
    pub operations: u64,
    pub proofs: u32,
    /// Actors + tasks + devices + pools + regions in the specialized image.
    pub image_nodes: u32,
    pub tests: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LowerOutput {
    wir: ValidatedSemanticWir,
    report: LoweringReport,
}

impl LowerOutput {
    #[must_use]
    pub fn wir(&self) -> &ValidatedSemanticWir {
        &self.wir
    }

    #[must_use]
    pub fn report(&self) -> &LoweringReport {
        &self.report
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedSemanticWir, LoweringReport) {
        (self.wir, self.report)
    }
}

pub trait SemanticLowerer {
    fn lower(
        &self,
        request: LowerRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerError>;
}

/// Production lowering for the executable semantic surface currently emitted
/// by [`sema::CanonicalSemanticAnalyzer`]. It accepts the minimum declared
/// image, that same real root compiled for a declared scenario, and a compiled
/// synchronous integration-test group. Generated groups retain their exact
/// descriptor identities and emit codec-sealed guest protocol frames around
/// real source test calls. Bounded stateless app/service graphs retain exact
/// actor turns, static task entries, mailbox/frame regions, direct async waits,
/// and their ownership/capacity/cleanup proofs. Pass-only free-call scopes are
/// retained through exact normal-exit SemanticWir cleanup markers. Other actor messaging, async
/// test scheduling, scope abnormal exits, devices, pools, and artifacts remain explicit
/// rejections until their operation-level lowering exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalSemanticLowerer;

impl CanonicalSemanticLowerer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SemanticLowerer for CanonicalSemanticLowerer {
    fn lower(
        &self,
        request: LowerRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        preflight_input(request.input.facts(), request.limits, is_cancelled)?;
        let (wir, report) = match supported_input(&request.input, request.limits, is_cancelled)? {
            SupportedInput::Minimum(minimum) => {
                let wir = lower_minimum(&minimum, request.limits, is_cancelled)?;
                let report = LoweringReport {
                    semantic_types: 1,
                    function_instances: 1,
                    operations: 0,
                    proofs: count_u32(
                        minimum.facts.proofs.len(),
                        "semantic proofs",
                        request.limits.model_edges,
                    )?,
                    image_nodes: 0,
                    tests: 0,
                };
                (wir, report)
            }
            SupportedInput::ActorImage(actor) => {
                lower_actor_image(&actor, request.limits, is_cancelled)?
            }
            SupportedInput::GeneratedTests(generated) => {
                lower_generated_tests(&generated, request.limits, is_cancelled)?
            }
        };
        check_cancelled(is_cancelled)?;
        seal(&request, wir, report, is_cancelled)
    }
}

enum SupportedInput<'a> {
    Minimum(MinimumFacts<'a>),
    ActorImage(ActorImageFacts<'a>),
    GeneratedTests(GeneratedTestFacts<'a>),
}

struct MinimumFacts<'a> {
    facts: &'a sema::PartialAnalysis,
    graph: &'a sema::ImageGraph,
    ty: &'a sema::SemanticType,
    function: &'a sema::FunctionInstance,
    constructor: wrela_hir::DeclarationId,
    compiled_test_group: Option<&'a FullImageTestGroup>,
}

struct GeneratedTestFacts<'a> {
    input: &'a AnalyzedImage,
    facts: &'a sema::PartialAnalysis,
    graph: &'a sema::ImageGraph,
    group: &'a FullImageTestGroup,
    harness: &'a sema::FunctionInstance,
    test_functions: Vec<sema::FunctionInstanceId>,
}

struct ActorImageFacts<'a> {
    input: &'a AnalyzedImage,
    facts: &'a sema::PartialAnalysis,
    graph: &'a sema::ImageGraph,
    entry: &'a sema::FunctionInstance,
    constructor: wrela_hir::DeclarationId,
    wait_proof: sema::ProofId,
}

#[derive(Debug, Clone, Copy)]
struct ScopeActivationLowering {
    statement: wrela_hir::StatementId,
    protocol: sema::ScopeProtocolId,
    scope: wir::ScopeId,
}

#[derive(Debug)]
struct ScopeLoweringContext {
    activations: Vec<ScopeActivationLowering>,
}

impl ScopeLoweringContext {
    fn activation(&self, statement: wrela_hir::StatementId) -> Option<ScopeActivationLowering> {
        self.activations
            .iter()
            .find(|activation| activation.statement == statement)
            .copied()
    }
}

fn supported_input<'a>(
    input: &'a AnalyzedImage,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SupportedInput<'a>, LowerError> {
    validate_admission_result_lowering_boundary(input.facts())?;
    validate_generic_function_lowering_boundary(input)?;
    validate_method_call_lowering_boundary(input.facts())?;
    match input.facts().root {
        sema::AnalysisRoot::DeclaredImage { .. } => {
            if input
                .facts()
                .graph
                .as_ref()
                .is_some_and(|graph| !graph.actors.is_empty())
            {
                supported_actor_image(input, limits, is_cancelled).map(SupportedInput::ActorImage)
            } else {
                supported_minimum(input.facts()).map(SupportedInput::Minimum)
            }
        }
        sema::AnalysisRoot::GeneratedTestHarness { .. } => {
            supported_generated_tests(input, limits, is_cancelled)
                .map(SupportedInput::GeneratedTests)
        }
    }
}

fn validate_admission_result_lowering_boundary(
    facts: &sema::PartialAnalysis,
) -> Result<(), LowerError> {
    if facts.expressions.iter().any(|fact| {
        matches!(
            fact.resolution,
            sema::ExpressionResolution::Builtin(sema::IntrinsicOperation::ActorTrySend { .. })
        )
    }) {
        Err(unsupported(
            "semantic-admission-result-lowering-pending (try-send outcome dispatch)",
        ))
    } else {
        Ok(())
    }
}

fn validate_method_call_lowering_boundary(facts: &sema::PartialAnalysis) -> Result<(), LowerError> {
    if facts.expressions.iter().any(|fact| {
        matches!(
            fact.resolution,
            sema::ExpressionResolution::MethodCall { .. }
        )
    }) {
        Err(unsupported(
            "semantic-method-call-lowering-pending (concrete receiver method calls)",
        ))
    } else {
        Ok(())
    }
}

fn validate_generic_function_lowering_boundary(input: &AnalyzedImage) -> Result<(), LowerError> {
    validate_generic_function_lowering_boundary_parts(input.facts(), input.hir().as_program())
}

fn validate_generic_function_lowering_boundary_parts(
    facts: &sema::PartialAnalysis,
    program: &wrela_hir::Program,
) -> Result<(), LowerError> {
    for function in &facts.functions {
        if function.generic_arguments.is_empty() {
            continue;
        }
        let sema::FunctionOrigin::Source { declaration, body } = function.origin else {
            return Err(unsupported(
                "semantic-generic-function-kind-lowering-pending (methods, interfaces, async, or generated specialization)",
            ));
        };
        let Some(declaration_record) = program.declaration(declaration) else {
            return Err(LowerError::MissingSemanticFact {
                subject: function.name.clone(),
                fact: "generic source function declaration",
            });
        };
        let wrela_hir::DeclarationKind::Function(source) = &declaration_record.kind else {
            return Err(unsupported(
                "semantic-generic-function-kind-lowering-pending (methods, interfaces, async, or generated specialization)",
            ));
        };
        if !matches!(
            declaration_record.owner,
            wrela_hir::DeclarationOwner::Module(_)
        ) || source.color != wrela_hir::FunctionColor::Sync
            || function.color != wrela_hir::FunctionColor::Sync
            || function.role != sema::FunctionRole::Ordinary
            || source.body != Some(body)
            || function.source != Some(declaration_record.source)
        {
            return Err(unsupported(
                "semantic-generic-function-kind-lowering-pending (methods, interfaces, async, or generated specialization)",
            ));
        }
        if source.generics.is_empty()
            || source.generics.len() != function.generic_arguments.len()
            || source.parameters.len() != function.parameters.len()
        {
            return Err(unsupported(
                "semantic-generic-function-parameter-lowering-pending (const, region, bounded, or unauthenticated specialization)",
            ));
        }
        for (generic, argument) in source.generics.iter().zip(&function.generic_arguments) {
            let Some(record) = program.generic_parameter(*generic) else {
                return Err(unsupported(
                    "semantic-generic-function-parameter-lowering-pending (const, region, bounded, or unauthenticated specialization)",
                ));
            };
            if record.owner != declaration
                || !matches!(
                    record.kind,
                    wrela_hir::GenericParameterKind::Type { bound: None }
                )
            {
                return Err(unsupported(
                    "semantic-generic-function-parameter-lowering-pending (const, region, bounded, or unauthenticated specialization)",
                ));
            }
            let sema::SemanticArgument::Type(argument) = argument else {
                return Err(unsupported(
                    "semantic-generic-function-argument-lowering-pending (non-type or non-scalar specialization)",
                ));
            };
            if !is_stored_copy_scalar(facts, *argument) {
                return Err(unsupported(
                    "semantic-generic-function-argument-lowering-pending (non-type or non-scalar specialization)",
                ));
            }
        }
        let expected_result = source.result.as_ref().map_or_else(
            || Some(sema::SemanticTypeId(0)),
            |result| {
                generic_function_source_type_matches(
                    facts,
                    source,
                    &function.generic_arguments,
                    result,
                )
            },
        );
        if expected_result != Some(function.result) {
            return Err(unsupported(
                "semantic-generic-function-signature-lowering-pending (unsupported or unauthenticated substitution)",
            ));
        }
        for (source_parameter, semantic_parameter) in
            source.parameters.iter().zip(&function.parameters)
        {
            let Some(parameter) = program.parameter(*source_parameter) else {
                return Err(unsupported(
                    "semantic-generic-function-signature-lowering-pending (unsupported or unauthenticated substitution)",
                ));
            };
            if parameter.owner != wrela_hir::CallableOwner::Declaration(declaration)
                || parameter.receiver
                || semantic_parameter.parameter != *source_parameter
                || parameter.ty.as_ref().and_then(|ty| {
                    generic_function_source_type_matches(
                        facts,
                        source,
                        &function.generic_arguments,
                        ty,
                    )
                }) != Some(semantic_parameter.ty)
            {
                return Err(unsupported(
                    "semantic-generic-function-signature-lowering-pending (unsupported or unauthenticated substitution)",
                ));
            }
        }
    }
    Ok(())
}

fn supported_minimum(facts: &sema::PartialAnalysis) -> Result<MinimumFacts<'_>, LowerError> {
    let (root_declaration, test_group) = match &facts.root {
        sema::AnalysisRoot::DeclaredImage {
            declaration,
            test_group,
            ..
        } => (*declaration, *test_group),
        sema::AnalysisRoot::GeneratedTestHarness { .. } => {
            return Err(unsupported("generated test harnesses"));
        }
    };
    if facts.test_plan.is_some() || !facts.comptime_test_results.is_empty() {
        return Err(unsupported("test discovery images"));
    }
    match (test_group, facts.compiled_test_group.as_ref()) {
        (None, None) => {}
        (Some(group), Some(record))
            if record.id == group
                && matches!(
                    &record.root,
                    ImageRoot::Declared { image_name, .. }
                        if image_name == facts.graph.as_ref().map_or("", |graph| graph.name.as_str())
                ) =>
        {
            if !matches!(
                record.tests.as_slice(),
                [test]
                    if test.descriptor.kind == PlannedTestKind::DeclaredImage
                        && test.descriptor.source.is_none()
                        && matches!(test.invocation, ImageTestInvocation::DeclaredScenario)
            ) {
                return Err(LowerError::InternalInvariant(
                    "declared compiled group does not contain its one scenario invocation"
                        .to_owned(),
                ));
            }
        }
        _ => {
            return Err(LowerError::MissingSemanticFact {
                subject: "declared test-group image".to_owned(),
                fact: "matching compiled test-group metadata",
            });
        }
    }
    if !facts.scope_protocols.is_empty() || !facts.scope_activations.is_empty() {
        return Err(unsupported(
            "semantic-with-cleanup-lowering-pending (scope protocols and activations)",
        ));
    }
    if !facts.projection_protocols.is_empty() || !facts.lexical_views.is_empty() {
        return Err(unsupported(
            "semantic-projection-lowering-pending (projection protocols)",
        ));
    }
    if !facts.baked_artifacts.is_empty() {
        return Err(unsupported("baked artifacts"));
    }
    if !facts.values.is_empty() || !facts.expressions.is_empty() || !facts.statements.is_empty() {
        return Err(unsupported("source executable bodies"));
    }
    let graph = facts
        .graph
        .as_ref()
        .ok_or(LowerError::MissingSemanticFact {
            subject: "analyzed image".to_owned(),
            fact: "closed image graph",
        })?;
    if !graph.actors.is_empty()
        || !graph.tasks.is_empty()
        || !graph.devices.is_empty()
        || !graph.pools.is_empty()
        || !graph.regions.is_empty()
        || !graph.brands.is_empty()
        || graph.static_bytes != 0
        || graph.peak_bytes != 0
        || graph.startup_order.as_slice() != [sema::ImageOwner::Runtime]
        || graph.shutdown_order.as_slice() != [sema::ImageOwner::Runtime]
    {
        return Err(unsupported("nonempty runtime image graphs"));
    }
    let [ty] = facts.types.as_slice() else {
        return Err(unsupported(
            "semantic type sets other than the minimum unit type",
        ));
    };
    if ty.id != sema::SemanticTypeId(0)
        || ty.kind != sema::SemanticTypeKind::Unit
        || ty.linearity != sema::Linearity::ScalarCopy
        || ty.size_upper_bound != Some(0)
        || ty.alignment_lower_bound != 1
        || ty.source.is_some()
    {
        return Err(unsupported(
            "semantic types other than the canonical unit type",
        ));
    }
    let [function] = facts.functions.as_slice() else {
        return Err(unsupported("multiple runtime function instances"));
    };
    let constructor = match function.origin {
        sema::FunctionOrigin::GeneratedImageEntry { constructor } => constructor,
        sema::FunctionOrigin::Source { .. } | sema::FunctionOrigin::SourceClosure { .. } => {
            return Err(unsupported("source function bodies"));
        }
        sema::FunctionOrigin::GeneratedTestHarness { .. } => {
            return Err(unsupported("generated test functions"));
        }
    };
    if constructor != root_declaration
        || function.id != sema::FunctionInstanceId(0)
        || graph.entry != function.id
        || function.role != sema::FunctionRole::ImageEntry
        || function.color != wrela_hir::FunctionColor::Sync
        || !function.generic_arguments.is_empty()
        || !function.parameters.is_empty()
        || function.result != sema::SemanticTypeId(0)
    {
        return Err(unsupported("noncanonical generated image entries"));
    }
    if facts.proofs.len() != 3
        || !matches!(facts.proofs[0].kind, sema::ProofKind::TypeChecked)
        || !matches!(facts.proofs[1].kind, sema::ProofKind::EffectsAllowed)
        || !matches!(facts.proofs[2].kind, sema::ProofKind::ImageClosed)
        || function.proofs.as_slice() != [sema::ProofId(0), sema::ProofId(1), sema::ProofId(2)]
    {
        return Err(unsupported("noncanonical minimum-image proof sets"));
    }
    Ok(MinimumFacts {
        facts,
        graph,
        ty,
        function,
        constructor,
        compiled_test_group: facts.compiled_test_group.as_ref(),
    })
}

fn supported_actor_image<'a>(
    input: &'a AnalyzedImage,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ActorImageFacts<'a>, LowerError> {
    check_cancelled(is_cancelled)?;
    let facts = input.facts();
    let constructor = match facts.root {
        sema::AnalysisRoot::DeclaredImage {
            declaration,
            test_group: None,
            ..
        } => declaration,
        sema::AnalysisRoot::DeclaredImage {
            test_group: Some(_),
            ..
        } => return Err(unsupported("actor images compiled as declared scenarios")),
        sema::AnalysisRoot::GeneratedTestHarness { .. } => {
            return Err(unsupported("actor images with generated test harnesses"));
        }
    };
    if facts.test_plan.is_some()
        || facts.compiled_test_group.is_some()
        || !facts.comptime_test_results.is_empty()
    {
        return Err(unsupported("test metadata in actor images"));
    }
    validate_actor_scope_subset(input, is_cancelled)?;
    if !facts.projection_protocols.is_empty() || !facts.lexical_views.is_empty() {
        return Err(unsupported(
            "semantic-projection-lowering-pending (projection protocols in actor images)",
        ));
    }
    if !facts.baked_artifacts.is_empty() {
        return Err(unsupported("baked artifacts in actor images"));
    }
    let graph = facts
        .graph
        .as_ref()
        .ok_or(LowerError::MissingSemanticFact {
            subject: "actor image".to_owned(),
            fact: "closed image graph",
        })?;
    if graph.actors.is_empty()
        || !graph.devices.is_empty()
        || !graph.pools.is_empty()
        || !graph.brands.is_empty()
    {
        return Err(unsupported(
            "actor graphs outside the stateless app/service and static-task slice",
        ));
    }
    let unit = facts
        .types
        .first()
        .ok_or_else(|| unsupported("actor images without the canonical unit type"))?;
    require_unit_type(unit)?;
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        validate_actor_source_type(input, ty)?;
    }
    let entry = facts
        .functions
        .get(graph.entry.0 as usize)
        .filter(|function| function.id == graph.entry)
        .ok_or(LowerError::MissingSemanticFact {
            subject: "actor image".to_owned(),
            fact: "generated image entry",
        })?;
    if entry.origin != (sema::FunctionOrigin::GeneratedImageEntry { constructor })
        || entry.role != sema::FunctionRole::ImageEntry
        || entry.color != wrela_hir::FunctionColor::Sync
        || !entry.generic_arguments.is_empty()
        || !entry.parameters.is_empty()
        || entry.result != sema::SemanticTypeId(0)
        || entry.source.is_some()
        || facts.values.iter().any(|value| value.function == entry.id)
        || facts
            .expressions
            .iter()
            .any(|fact| fact.function == entry.id)
        || facts
            .statements
            .iter()
            .any(|fact| fact.function == entry.id)
    {
        return Err(unsupported("noncanonical generated actor image entry"));
    }
    validate_actor_graph_contract(input, facts, graph, limits, is_cancelled)?;
    validate_actor_source_functions(input, graph, entry.id, limits, is_cancelled)?;
    let wait_proof = validate_actor_wait_contract(input, graph, entry, limits, is_cancelled)?;
    validate_actor_proof_contract(facts, graph, entry, wait_proof, is_cancelled)?;
    Ok(ActorImageFacts {
        input,
        facts,
        graph,
        entry,
        constructor,
        wait_proof,
    })
}

fn validate_actor_scope_subset(
    input: &AnalyzedImage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let facts = input.facts();
    if facts.scope_protocols.is_empty() && facts.scope_activations.is_empty() {
        return Ok(());
    }
    if facts.scope_protocols.is_empty() || facts.scope_activations.is_empty() {
        return Err(LowerError::InternalInvariant(
            "scope protocols and activations are not a closed pair".to_owned(),
        ));
    }
    if facts.scope_protocols.len() != 1 {
        return Err(unsupported(
            "semantic-scope-protocol-lowering-pending (multiple scope protocols)",
        ));
    }
    let program = input.hir().as_program();
    for protocol in &facts.scope_protocols {
        check_cancelled(is_cancelled)?;
        let source = program
            .declaration(protocol.declaration)
            .and_then(|declaration| match &declaration.kind {
                wrela_hir::DeclarationKind::Scope(scope) => Some(scope),
                _ => None,
            })
            .ok_or(LowerError::MissingSemanticFact {
                subject: protocol.name.clone(),
                fact: "free-call scope declaration",
            })?;
        if !protocol.parameters.is_empty() || source.parameters.len() != 1 {
            return Err(unsupported(
                "semantic-scope-parameter-lowering-pending (parameterized acquisition)",
            ));
        }
        if protocol.abort.is_some() {
            return Err(unsupported(
                "semantic-with-abnormal-cleanup-lowering-pending (scope abort phase)",
            ));
        }
        if protocol.suspend_safe
            || protocol.abort_effects.0 != 0
            || protocol.exit_effects.0 != 0
            || !scope_body_is_pass_only(program, protocol.setup)
            || !scope_body_is_pass_only(program, protocol.exit)
        {
            return Err(unsupported(
                "semantic-scope-cleanup-form-lowering-pending (non-pass scope phase)",
            ));
        }
    }
    for activation in &facts.scope_activations {
        check_cancelled(is_cancelled)?;
        let statement =
            program
                .statement(activation.statement)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: "scope activation".to_owned(),
                    fact: "with statement",
                })?;
        let wrela_hir::StatementKind::With { body, region, .. } = statement.kind else {
            return Err(LowerError::InternalInvariant(
                "scope activation no longer names a with statement".to_owned(),
            ));
        };
        if region.is_some() {
            return Err(unsupported(
                "semantic-with-region-lowering-pending (branded scope region)",
            ));
        }
        let function = facts
            .functions
            .get(activation.function.0 as usize)
            .filter(|function| function.id == activation.function)
            .ok_or(LowerError::MissingSemanticFact {
                subject: "scope activation".to_owned(),
                fact: "owning function",
            })?;
        if !matches!(function.role, sema::FunctionRole::ActorTurn(_)) {
            return Err(unsupported(
                "semantic-with-owner-lowering-pending (non-actor source function)",
            ));
        }
        validate_scope_normal_body(facts, program, activation.function, body, is_cancelled)?;
    }
    Ok(())
}

fn scope_body_is_pass_only(program: &wrela_hir::Program, body: wrela_hir::BodyId) -> bool {
    program.body(body).is_some_and(|body| {
        body.statements.iter().all(|statement| {
            program
                .statement(*statement)
                .is_some_and(|statement| matches!(statement.kind, wrela_hir::StatementKind::Pass))
        })
    })
}

fn validate_scope_normal_body(
    facts: &sema::PartialAnalysis,
    program: &wrela_hir::Program,
    function: sema::FunctionInstanceId,
    root: wrela_hir::BodyId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut pending = vec![root];
    while let Some(body) = pending.pop() {
        check_cancelled(is_cancelled)?;
        let body = program.body(body).ok_or(LowerError::MissingSemanticFact {
            subject: "scope activation".to_owned(),
            fact: "with body",
        })?;
        for statement in &body.statements {
            check_cancelled(is_cancelled)?;
            let effects = facts
                .statements
                .binary_search_by_key(&(function, *statement), |fact| {
                    (fact.function, fact.statement)
                })
                .ok()
                .and_then(|index| facts.statements.get(index))
                .map(|fact| fact.effects)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: "scope activation".to_owned(),
                    fact: "with body statement effects",
                })?;
            if effects.0 & (sema::EffectSet::SUSPEND | sema::EffectSet::MAY_FAIL) != 0 {
                return Err(unsupported(
                    "semantic-with-abnormal-cleanup-lowering-pending (await, failure, or question exit)",
                ));
            }
            match &program
                .statement(*statement)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: "scope activation".to_owned(),
                    fact: "with body statement",
                })?
                .kind
            {
                wrela_hir::StatementKind::Return(_)
                | wrela_hir::StatementKind::Break
                | wrela_hir::StatementKind::Continue => {
                    return Err(unsupported(
                        "semantic-with-abnormal-cleanup-lowering-pending (early control-flow exit)",
                    ));
                }
                wrela_hir::StatementKind::With { body, .. }
                | wrela_hir::StatementKind::While { body, .. }
                | wrela_hir::StatementKind::Loop { body }
                | wrela_hir::StatementKind::For { body, .. } => pending.push(*body),
                wrela_hir::StatementKind::If {
                    branches,
                    else_body,
                } => {
                    pending.extend(branches.iter().map(|(_, body)| *body));
                    pending.extend(*else_body);
                }
                wrela_hir::StatementKind::Match { arms, .. } => {
                    pending.extend(arms.iter().map(|arm| arm.body));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_actor_source_type(
    input: &AnalyzedImage,
    ty: &sema::SemanticType,
) -> Result<(), LowerError> {
    let facts = input.facts();
    let scalar = match &ty.kind {
        sema::SemanticTypeKind::Unit | sema::SemanticTypeKind::Bool => true,
        sema::SemanticTypeKind::Integer {
            bits,
            pointer_sized,
            ..
        } => {
            if *pointer_sized {
                *bits == 64
            } else {
                matches!(*bits, 8 | 16 | 32 | 64 | 128)
            }
        }
        sema::SemanticTypeKind::Float { bits } => matches!(*bits, 32 | 64),
        sema::SemanticTypeKind::Function {
            color,
            parameters,
            result,
        } => {
            matches!(
                color,
                wrela_hir::FunctionColor::Sync | wrela_hir::FunctionColor::Async
            ) && (result.0 as usize) < facts.types.len()
                && parameters
                    .iter()
                    .all(|parameter| (parameter.ty.0 as usize) < facts.types.len())
        }
        sema::SemanticTypeKind::Class {
            declaration,
            arguments,
            fields,
        } => {
            let source_matches = input
                .hir()
                .as_program()
                .declaration(*declaration)
                .is_some_and(|declaration| {
                    matches!(declaration.kind, wrela_hir::DeclarationKind::Structure(_))
                        && ty.source == Some(declaration.source)
                });
            if !source_matches
                || !arguments.is_empty()
                || !fields.is_empty()
                || ty.linearity != sema::Linearity::ReclaimableLinear
                || ty.size_upper_bound != Some(0)
                || ty.alignment_lower_bound != 1
            {
                return Err(unsupported("noncanonical actor class types"));
            }
            return Ok(());
        }
        sema::SemanticTypeKind::Actor { class } => {
            if (class.0 as usize) >= facts.types.len()
                || ty.linearity != sema::Linearity::ExplicitCopy
                || ty.size_upper_bound != Some(8)
                || ty.alignment_lower_bound != 8
                || ty.source.is_some()
            {
                return Err(unsupported(
                    "noncanonical image-wired actor capability type",
                ));
            }
            return Ok(());
        }
        sema::SemanticTypeKind::Reservation => {
            if ty.linearity != sema::Linearity::StrictLinear
                || ty.size_upper_bound != Some(8)
                || ty.alignment_lower_bound != 8
                || ty.source.is_some()
            {
                return Err(unsupported("noncanonical actor reservation type"));
            }
            return Ok(());
        }
        sema::SemanticTypeKind::Structure { .. } | sema::SemanticTypeKind::Enumeration { .. } => {
            return validate_supported_source_type(ty, facts);
        }
        _ => false,
    };
    if !scalar || ty.linearity != sema::Linearity::ScalarCopy {
        Err(unsupported(
            "semantic types outside the bounded actor scalar subset",
        ))
    } else {
        Ok(())
    }
}

fn validate_actor_graph_contract(
    input: &AnalyzedImage,
    facts: &sema::PartialAnalysis,
    graph: &sema::ImageGraph,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut state_actor_count = 0usize;
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        state_actor_count = state_actor_count
            .checked_add(usize::from(
                actor_state_source(input, facts, actor)?.is_some(),
            ))
            .ok_or(LowerError::ResourceLimit {
                resource: "actor graph regions",
                limit: limits.model_edges,
            })?;
    }
    let expected_regions = graph
        .actors
        .len()
        .checked_add(state_actor_count)
        .and_then(|count| {
            count.checked_add(
                graph
                    .actors
                    .iter()
                    .filter(|actor| !actor.turn_functions.is_empty())
                    .count(),
            )
        })
        .and_then(|count| count.checked_add(graph.tasks.len()))
        .ok_or(LowerError::ResourceLimit {
            resource: "actor graph regions",
            limit: limits.model_edges,
        })?;
    if graph.regions.len() != expected_regions || graph.static_bytes == 0 {
        return Err(unsupported("noncanonical actor capacity regions"));
    }
    let expected_owners = graph
        .actors
        .len()
        .checked_add(graph.tasks.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(LowerError::ResourceLimit {
            resource: "actor image owner order",
            limit: limits.model_edges,
        })?;
    if graph.startup_order.len() != expected_owners
        || graph.shutdown_order.len() != expected_owners
        || graph.startup_order.first() != Some(&sema::ImageOwner::Runtime)
        || graph.shutdown_order.last() != Some(&sema::ImageOwner::Runtime)
    {
        return Err(unsupported("noncanonical actor startup or shutdown order"));
    }
    let mut static_bytes = 0u64;
    let mut region_cursor = 0usize;
    for (index, actor) in graph.actors.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if actor.id.0 as usize != index
            || actor.name.trim().is_empty()
            || actor.mailbox_capacity == 0
            || actor.priority != 1
            || actor.supervisor.is_some()
            || actor.class.0 as usize >= facts.types.len()
            || !actor
                .turn_functions
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || !actor.message_types.windows(2).all(|pair| pair[0] < pair[1])
            || graph.startup_order.get(index + 1) != Some(&sema::ImageOwner::Actor(actor.id))
            || graph.shutdown_order.get(
                graph
                    .tasks
                    .len()
                    .checked_add(graph.actors.len() - index - 1)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "actor shutdown order",
                        limit: limits.model_edges,
                    })?,
            ) != Some(&sema::ImageOwner::Actor(actor.id))
        {
            return Err(unsupported("noncanonical actor node identity or ordering"));
        }
        for function in &actor.turn_functions {
            if facts
                .functions
                .get(function.0 as usize)
                .is_none_or(|function| function.role != sema::FunctionRole::ActorTurn(actor.id))
            {
                return Err(unsupported("actor turn relation substitution"));
            }
        }
        for message in &actor.message_types {
            if message.0 as usize >= facts.types.len() {
                return Err(unsupported("actor message type substitution"));
            }
        }
        let mailbox = graph
            .regions
            .get(region_cursor)
            .ok_or_else(|| unsupported("missing actor mailbox region"))?;
        let mailbox_id = region_cursor;
        region_cursor = region_cursor
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "actor region identity",
                limit: limits.model_edges,
            })?;
        let mailbox_bytes =
            u64::from(actor.mailbox_capacity)
                .checked_mul(16)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor mailbox bytes",
                    limit: limits.payload_bytes,
                })?;
        let mailbox_name_matches =
            joined_name_matches(&mailbox.name, &actor.name, ".mailbox", is_cancelled)?;
        if mailbox.id.0 as usize != mailbox_id
            || mailbox.class != sema::RegionClass::Image
            || mailbox.owner != sema::ImageOwner::Actor(actor.id)
            || mailbox.capacity_bytes != mailbox_bytes
            || mailbox.alignment != 8
            || mailbox.source != actor.source
            || !mailbox_name_matches
            || !capacity_proof_matches(facts, mailbox.proof, u64::from(actor.mailbox_capacity))
        {
            return Err(unsupported("actor capacity proof or region substitution"));
        }
        static_bytes =
            static_bytes
                .checked_add(mailbox_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.payload_bytes,
                })?;
        if let Some(state_source) = actor_state_source(input, facts, actor)? {
            let state = graph
                .regions
                .get(region_cursor)
                .ok_or_else(|| unsupported("missing actor state region"))?;
            let state_id = region_cursor;
            region_cursor = region_cursor
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.model_edges,
                })?;
            let state_name_matches =
                joined_name_matches(&state.name, &actor.name, ".state", is_cancelled)?;
            let state_proof_matches =
                facts
                    .proofs
                    .get(state.proof.0 as usize)
                    .is_some_and(|proof| {
                        proof.id == state.proof
                            && proof.kind == sema::ProofKind::CapacityBound
                            && proof.bound == Some(1)
                            && proof.sources.as_slice() == [state_source]
                            && proof.depends_on.is_empty()
                    });
            if state.id.0 as usize != state_id
                || state.class != sema::RegionClass::Image
                || state.owner != sema::ImageOwner::Actor(actor.id)
                || state.capacity_bytes != 8
                || state.alignment != 8
                || state.source != state_source
                || !state_name_matches
                || !state_proof_matches
            {
                return Err(unsupported("actor state region substitution"));
            }
            static_bytes = static_bytes
                .checked_add(8)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.payload_bytes,
                })?;
        }
        if !actor.turn_functions.is_empty() {
            let turn = graph
                .regions
                .get(region_cursor)
                .ok_or_else(|| unsupported("missing actor turn-frame region"))?;
            let turn_id = region_cursor;
            region_cursor = region_cursor
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.model_edges,
                })?;
            let mut turn_bytes = 1_u64;
            for function in &actor.turn_functions {
                check_cancelled(is_cancelled)?;
                let function = facts
                    .functions
                    .get(function.0 as usize)
                    .ok_or_else(|| unsupported("actor turn frame identity"))?;
                turn_bytes = turn_bytes.max(function.frame_bytes_bound.max(1));
            }
            let turn_name_matches =
                joined_name_matches(&turn.name, &actor.name, ".turn-frame", is_cancelled)?;
            if turn.id.0 as usize != turn_id
                || turn.class != sema::RegionClass::TaskFrame
                || turn.owner != sema::ImageOwner::Actor(actor.id)
                || turn.capacity_bytes != turn_bytes
                || turn.alignment != 8
                || turn.source != actor.source
                || !turn_name_matches
                || !capacity_proof_matches(facts, turn.proof, 1)
            {
                return Err(unsupported("actor capacity proof or region substitution"));
            }
            static_bytes =
                static_bytes
                    .checked_add(turn_bytes)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "actor static bytes",
                        limit: limits.payload_bytes,
                    })?;
        }
    }
    let task_region_start = region_cursor;
    for (index, task) in graph.tasks.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let entry = facts
            .functions
            .get(task.entry.0 as usize)
            .filter(|function| function.role == sema::FunctionRole::TaskEntry(task.id))
            .ok_or_else(|| unsupported("task entry relation substitution"))?;
        let expected_startup = graph
            .actors
            .len()
            .checked_add(index)
            .and_then(|index| index.checked_add(1))
            .ok_or(LowerError::ResourceLimit {
                resource: "task startup order",
                limit: limits.model_edges,
            })?;
        let expected_shutdown = graph.tasks.len() - index - 1;
        let region = graph
            .regions
            .get(task_region_start + index)
            .ok_or_else(|| unsupported("missing task frame region"))?;
        let frame_bytes = entry
            .frame_bytes_bound
            .max(1)
            .checked_mul(u64::from(task.slots))
            .ok_or(LowerError::ResourceLimit {
                resource: "task frame bytes",
                limit: limits.payload_bytes,
            })?;
        let region_name_matches =
            joined_name_matches(&region.name, &task.name, ".frame", is_cancelled)?;
        if task.id.0 as usize != index
            || task.name.trim().is_empty()
            || task.slots != 1
            || task.priority != 1
            || task
                .supervisor
                .is_none_or(|actor| actor.0 as usize >= graph.actors.len())
            || graph.startup_order.get(expected_startup) != Some(&sema::ImageOwner::Task(task.id))
            || graph.shutdown_order.get(expected_shutdown) != Some(&sema::ImageOwner::Task(task.id))
            || region.id.0 as usize != task_region_start + index
            || region.class != sema::RegionClass::TaskFrame
            || region.owner != sema::ImageOwner::Task(task.id)
            || region.capacity_bytes != frame_bytes
            || region.alignment != 8
            || region.source != task.source
            || !region_name_matches
            || !capacity_proof_matches(facts, region.proof, u64::from(task.slots))
        {
            return Err(unsupported("task capacity proof or identity substitution"));
        }
        static_bytes = static_bytes
            .checked_add(frame_bytes)
            .ok_or(LowerError::ResourceLimit {
                resource: "actor static bytes",
                limit: limits.payload_bytes,
            })?;
    }
    if static_bytes != graph.static_bytes || graph.peak_bytes != graph.static_bytes {
        return Err(unsupported(
            "actor image static or peak capacity substitution",
        ));
    }
    Ok(())
}

fn actor_state_source(
    input: &AnalyzedImage,
    facts: &sema::PartialAnalysis,
    actor: &sema::ActorNode,
) -> Result<Option<Span>, LowerError> {
    let declaration = facts
        .types
        .get(actor.class.0 as usize)
        .and_then(|ty| match ty.kind {
            sema::SemanticTypeKind::Class { declaration, .. } => Some(declaration),
            _ => None,
        })
        .ok_or_else(|| unsupported("actor class state identity"))?;
    let class = input
        .hir()
        .as_program()
        .declaration(declaration)
        .and_then(|declaration| match &declaration.kind {
            wrela_hir::DeclarationKind::Structure(class) => Some(class),
            _ => None,
        })
        .ok_or_else(|| unsupported("actor class state declaration"))?;
    match class.fields.as_slice() {
        [] => Ok(None),
        [field]
            if matches!(
                field.ty.kind,
                wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::Actor),
                    ..
                }
            ) =>
        {
            Ok(None)
        }
        [field]
            if field.name.as_str() == "value"
                && matches!(
                    field.ty.kind,
                    wrela_hir::TypeExpressionKind::Named {
                        definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::U64),
                        ref arguments,
                    } if arguments.is_empty()
                )
                && field.default.is_some_and(|default| {
                    input.hir().as_program().expression(default).is_some_and(|expression| {
                        matches!(
                            &expression.kind,
                            wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(value))
                                if value == "0"
                        )
                    })
                }) =>
        {
            Ok(Some(field.source))
        }
        _ => Err(unsupported(
            "actor state declaration outside the sealed zero-u64 subset",
        )),
    }
}

fn capacity_proof_matches(facts: &sema::PartialAnalysis, id: sema::ProofId, bound: u64) -> bool {
    facts.proofs.get(id.0 as usize).is_some_and(|proof| {
        proof.id == id && proof.kind == sema::ProofKind::CapacityBound && proof.bound == Some(bound)
    })
}

fn joined_name_matches(
    value: &str,
    prefix: &str,
    suffix: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let Some(prefix_bytes) = value.len().checked_sub(suffix.len()) else {
        return Ok(false);
    };
    if prefix_bytes != prefix.len() {
        return Ok(false);
    }
    let (actual_prefix, actual_suffix) = value.as_bytes().split_at(prefix_bytes);
    if actual_suffix != suffix.as_bytes() {
        return Ok(false);
    }
    for (actual, expected) in actual_prefix
        .chunks(4096)
        .zip(prefix.as_bytes().chunks(4096))
    {
        check_cancelled(is_cancelled)?;
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_actor_source_functions(
    input: &AnalyzedImage,
    graph: &sema::ImageGraph,
    entry: sema::FunctionInstanceId,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let facts = input.facts();
    let program = input.hir().as_program();
    let mut edges = try_vec(
        facts.functions.len(),
        "actor source call graph",
        limits.model_edges,
    )?;
    for _ in &facts.functions {
        edges.push(Vec::<sema::FunctionInstanceId>::new());
    }
    let mut roots = try_vec(
        graph
            .actors
            .iter()
            .try_fold(0usize, |count, actor| {
                count.checked_add(actor.turn_functions.len())
            })
            .and_then(|count| count.checked_add(graph.tasks.len()))
            .ok_or(LowerError::ResourceLimit {
                resource: "actor source roots",
                limit: limits.model_edges,
            })?,
        "actor source roots",
        limits.model_edges,
    )?;
    for actor in &graph.actors {
        roots.extend_from_slice(&actor.turn_functions);
    }
    roots.extend(graph.tasks.iter().map(|task| task.entry));
    cancellable_sort(
        &mut roots,
        "actor source roots",
        limits.model_edges,
        is_cancelled,
    )?;
    reject_adjacent_duplicates(
        &roots,
        "actor and task entry identity aliasing",
        is_cancelled,
    )?;
    let mut edge_count = 0u64;
    for fact in &facts.expressions {
        check_cancelled(is_cancelled)?;
        let target = match fact.resolution {
            sema::ExpressionResolution::DirectCall {
                function: target, ..
            }
            | sema::ExpressionResolution::OperatorCall {
                function: target, ..
            } => target,
            _ => continue,
        };
        let caller = facts
            .functions
            .get(fact.function.0 as usize)
            .filter(|function| function.id == fact.function)
            .ok_or_else(|| {
                LowerError::InternalInvariant("actor call has a foreign caller".to_owned())
            })?;
        let target_function = facts
            .functions
            .get(target.0 as usize)
            .filter(|function| function.id == target)
            .ok_or_else(|| {
                LowerError::InternalInvariant("actor call has a foreign target".to_owned())
            })?;
        if !matches!(caller.origin, sema::FunctionOrigin::Source { .. })
            || !matches!(target_function.origin, sema::FunctionOrigin::Source { .. })
            || target_function.role != sema::FunctionRole::Ordinary
        {
            return Err(unsupported(
                "actor calls outside closed ordinary helper functions",
            ));
        }
        edge_count = edge_count.checked_add(1).ok_or(LowerError::ResourceLimit {
            resource: "actor source call graph",
            limit: limits.model_edges,
        })?;
        if edge_count > limits.model_edges {
            return Err(LowerError::ResourceLimit {
                resource: "actor source call graph",
                limit: limits.model_edges,
            });
        }
        let outgoing = edges
            .get_mut(fact.function.0 as usize)
            .ok_or_else(|| LowerError::InternalInvariant("actor caller is not dense".to_owned()))?;
        outgoing
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "actor source call graph",
                limit: limits.model_edges,
            })?;
        outgoing.push(target);
    }
    for outgoing in &mut edges {
        check_cancelled(is_cancelled)?;
        cancellable_sort(
            outgoing,
            "actor source call graph",
            limits.model_edges,
            is_cancelled,
        )?;
        cancellable_dedup(outgoing, is_cancelled)?;
    }
    let mut colors = try_vec(
        facts.functions.len(),
        "actor source reachability",
        limits.model_edges,
    )?;
    colors.resize(facts.functions.len(), 0u8);
    if let Some(color) = colors.get_mut(entry.0 as usize) {
        *color = 2;
    } else {
        return Err(LowerError::InternalInvariant(
            "actor image entry is dangling".to_owned(),
        ));
    }
    for root in &roots {
        check_cancelled(is_cancelled)?;
        let root_index = root.0 as usize;
        if colors.get(root_index).copied() == Some(2) {
            continue;
        }
        let mut stack = try_vec(
            facts.functions.len(),
            "actor source reachability",
            limits.model_edges,
        )?;
        let color = colors
            .get_mut(root_index)
            .ok_or_else(|| LowerError::InternalInvariant("actor root is dangling".to_owned()))?;
        *color = 1;
        stack.push((root_index, 0usize));
        while let Some((function, next_edge)) = stack.last_mut() {
            check_cancelled(is_cancelled)?;
            let outgoing = edges.get(*function).ok_or_else(|| {
                LowerError::InternalInvariant("actor call graph function is dangling".to_owned())
            })?;
            if let Some(target) = outgoing.get(*next_edge) {
                *next_edge = next_edge.checked_add(1).ok_or(LowerError::ResourceLimit {
                    resource: "actor source reachability",
                    limit: limits.model_edges,
                })?;
                let target = target.0 as usize;
                match colors.get(target).copied() {
                    Some(0) => {
                        *colors.get_mut(target).ok_or_else(|| {
                            LowerError::InternalInvariant(
                                "actor call target is dangling".to_owned(),
                            )
                        })? = 1;
                        stack.push((target, 0));
                    }
                    Some(1) => return Err(unsupported("recursive actor helper calls")),
                    Some(2) => {}
                    _ => {
                        return Err(LowerError::InternalInvariant(
                            "actor call target is dangling".to_owned(),
                        ));
                    }
                }
            } else {
                let completed = stack
                    .pop()
                    .ok_or_else(|| LowerError::InternalInvariant("empty actor DFS".to_owned()))?
                    .0;
                *colors.get_mut(completed).ok_or_else(|| {
                    LowerError::InternalInvariant("completed actor function is dangling".to_owned())
                })? = 2;
            }
        }
    }
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == entry {
            continue;
        }
        let sema::FunctionOrigin::Source { declaration, body } = function.origin else {
            return Err(unsupported("non-source functions in actor runtime closure"));
        };
        let declaration_record =
            program
                .declaration(declaration)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: function.name.clone(),
                    fact: "actor source function declaration",
                })?;
        let wrela_hir::DeclarationKind::Function(source) = &declaration_record.kind else {
            return Err(unsupported("non-function actor source origins"));
        };
        let role_matches = match function.role {
            sema::FunctionRole::ActorTurn(actor) => graph
                .actors
                .get(actor.0 as usize)
                .is_some_and(|actor| actor.turn_functions.binary_search(&function.id).is_ok()),
            sema::FunctionRole::TaskEntry(task) => graph
                .tasks
                .get(task.0 as usize)
                .is_some_and(|task| task.entry == function.id),
            sema::FunctionRole::Ordinary => true,
            sema::FunctionRole::Isr(_)
            | sema::FunctionRole::Cleanup
            | sema::FunctionRole::ImageEntry
            | sema::FunctionRole::Test => false,
        };
        let role_effect = match function.role {
            sema::FunctionRole::ActorTurn(_) => sema::EffectSet::ACTOR,
            sema::FunctionRole::TaskEntry(_) => sema::EffectSet::TASK,
            sema::FunctionRole::Ordinary => 0,
            _ => u64::MAX,
        };
        let mut has_one_way_send = false;
        for fact in &facts.expressions {
            check_cancelled(is_cancelled)?;
            if fact.function == function.id
                && matches!(
                    fact.resolution,
                    sema::ExpressionResolution::ActorRequest { .. }
                )
            {
                has_one_way_send = true;
                break;
            }
        }
        let expected_effects = role_effect
            | if has_one_way_send {
                sema::EffectSet::ACTOR
            } else {
                0
            }
            | if function.color == wrela_hir::FunctionColor::Async {
                sema::EffectSet::SUSPEND
            } else {
                0
            };
        if source.body != Some(body)
            || source.color != function.color
            || function.source != Some(declaration_record.source)
            || !matches!(
                function.color,
                wrela_hir::FunctionColor::Sync | wrela_hir::FunctionColor::Async
            )
            || !role_matches
            || function.effects.0 != expected_effects
            || function.recursive_depth_bound != Some(1)
            || function.uninterrupted_work_bound.is_none()
            || (function.color == wrela_hir::FunctionColor::Async
                && function.frame_bytes_bound < 16)
            || (function.color == wrela_hir::FunctionColor::Sync && function.frame_bytes_bound != 0)
            || colors.get(function.id.0 as usize).copied() != Some(2)
        {
            return Err(unsupported(
                "unreachable or noncanonical actor source functions",
            ));
        }
        if matches!(
            function.role,
            sema::FunctionRole::ActorTurn(_) | sema::FunctionRole::TaskEntry(_)
        ) {
            let Some(first_parameter) = source.parameters.first() else {
                return Err(unsupported("actor entry without its receiver"));
            };
            let receiver =
                program
                    .parameter(*first_parameter)
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: function.name.clone(),
                        fact: "actor receiver parameter",
                    })?;
            if !receiver.receiver
                || receiver.access != wrela_hir::AccessMode::Mutate
                || function.result != sema::SemanticTypeId(0)
            {
                return Err(unsupported("noncanonical actor-owned receiver authority"));
            }
        }
    }
    check_cancelled(is_cancelled)
}

#[derive(Clone, Copy)]
struct ActorWaitEdge {
    from: sema::FunctionInstanceId,
    to: sema::FunctionInstanceId,
    source: Span,
}

fn validate_actor_wait_contract(
    input: &AnalyzedImage,
    graph: &sema::ImageGraph,
    entry: &sema::FunctionInstance,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<sema::ProofId, LowerError> {
    let facts = input.facts();
    let program = input.hir().as_program();
    let mut awaited = try_vec(
        facts.expressions.len(),
        "actor awaited activations",
        limits.model_edges,
    )?;
    let mut edges = try_vec(
        facts.expressions.len(),
        "actor wait graph",
        limits.model_edges,
    )?;
    for fact in &facts.expressions {
        check_cancelled(is_cancelled)?;
        if fact.resolution != sema::ExpressionResolution::Builtin(sema::IntrinsicOperation::Await) {
            continue;
        }
        let function = facts
            .functions
            .get(fact.function.0 as usize)
            .filter(|function| function.color == wrela_hir::FunctionColor::Async)
            .ok_or_else(|| unsupported("await facts outside async actor functions"))?;
        let expression =
            program
                .expression(fact.expression)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: function.name.clone(),
                    fact: "await source expression",
                })?;
        let wrela_hir::ExpressionKind::Unary {
            operator: wrela_hir::UnaryOperator::Await,
            operand,
        } = expression.kind
        else {
            return Err(unsupported("await fact substitution"));
        };
        let operand_fact = semantic_expression_fact(facts, fact.function, operand)?;
        let target = match operand_fact.resolution {
            sema::ExpressionResolution::DirectCall {
                function: target, ..
            } => target,
            _ => return Err(unsupported("non-direct actor await operands")),
        };
        let proofs_match = cancellable_slices_equal(&fact.proofs, &function.proofs, is_cancelled)?;
        if facts
            .functions
            .get(target.0 as usize)
            .is_none_or(|target| target.color != wrela_hir::FunctionColor::Async)
            || fact.result.is_none()
            || fact.ty != operand_fact.ty
            || fact.effects.0 != operand_fact.effects.0 | sema::EffectSet::SUSPEND
            || !proofs_match
        {
            return Err(unsupported(
                "actor await type, effect, or proof substitution",
            ));
        }
        awaited.push((fact.function, operand));
        edges.push(ActorWaitEdge {
            from: fact.function,
            to: target,
            source: expression.source,
        });
    }
    cancellable_sort(
        &mut awaited,
        "actor awaited activations",
        limits.model_edges,
        is_cancelled,
    )?;
    reject_adjacent_duplicates(&awaited, "duplicated actor await activation", is_cancelled)?;
    let mut admitted = try_vec(
        graph.actors.len(),
        "one-way actor admission counts",
        limits.model_edges,
    )?;
    admitted.resize(graph.actors.len(), 0_u32);
    for fact in &facts.expressions {
        check_cancelled(is_cancelled)?;
        if let sema::ExpressionResolution::ActorRequest {
            actor,
            method,
            permit,
        } = fact.resolution
        {
            let producer = facts
                .functions
                .get(fact.function.0 as usize)
                .filter(|producer| producer.id == fact.function)
                .ok_or_else(|| unsupported("one-way actor producer identity"))?;
            let sema::FunctionRole::TaskEntry(task) = producer.role else {
                return Err(unsupported("one-way sends outside startup-once tasks"));
            };
            let owner = graph
                .tasks
                .get(task.0 as usize)
                .filter(|record| record.id == task)
                .and_then(|record| record.supervisor)
                .ok_or_else(|| unsupported("one-way task actor ownership"))?;
            let target = facts
                .functions
                .get(method.0 as usize)
                .filter(|target| {
                    target.id == method
                        && target.role == sema::FunctionRole::ActorTurn(actor)
                        && target.color == wrela_hir::FunctionColor::Async
                        && target.parameters.len() == 1
                        && target.result == sema::SemanticTypeId(0)
                })
                .ok_or_else(|| unsupported("one-way actor turn target"))?;
            let reservation = fact
                .result
                .and_then(|value| facts.values.get(value.0 as usize))
                .filter(|value| value.function == fact.function && value.ty == fact.ty)
                .ok_or_else(|| unsupported("one-way actor reservation value"))?;
            let reservation_ty = facts
                .types
                .get(reservation.ty.0 as usize)
                .filter(|ty| {
                    ty.kind == sema::SemanticTypeKind::Reservation
                        && ty.linearity == sema::Linearity::StrictLinear
                        && ty.size_upper_bound == Some(8)
                        && ty.alignment_lower_bound == 8
                })
                .ok_or_else(|| unsupported("one-way actor reservation type"))?;
            let mailbox_proof = graph
                .regions
                .iter()
                .filter(|region| {
                    region.owner == sema::ImageOwner::Actor(actor)
                        && region.class == sema::RegionClass::Image
                })
                .map(|region| region.proof)
                .next()
                .ok_or_else(|| unsupported("one-way actor mailbox capacity proof"))?;
            let request_source = program
                .expression(fact.expression)
                .map(|expression| expression.source)
                .ok_or_else(|| unsupported("one-way actor request source"))?;
            let permit_record = facts
                .proofs
                .get(permit.0 as usize)
                .filter(|proof| {
                    proof.id == permit
                        && proof.kind == sema::ProofKind::CapacityBound
                        && proof.bound == Some(1)
                        && proof.sources.as_slice() == [request_source]
                        && proof.depends_on.as_slice() == [mailbox_proof]
                })
                .ok_or_else(|| unsupported("one-way actor admission proof"))?;
            let count = admitted
                .get_mut(actor.0 as usize)
                .ok_or_else(|| unsupported("one-way actor identity"))?;
            *count = count.checked_add(1).ok_or(LowerError::ResourceLimit {
                resource: "one-way actor admission counts",
                limit: limits.model_edges,
            })?;
            let cross_actor = graph.actors.len() == 2
                && owner == sema::ActorId(1)
                && actor == sema::ActorId(0)
                && facts
                    .proofs
                    .iter()
                    .filter(|proof| proof.kind == sema::ProofKind::ActorAsIf)
                    .count()
                    == 1
                && facts.proofs.iter().any(|proof| {
                    proof.kind == sema::ProofKind::ActorAsIf
                        && proof.bound == Some(1)
                        && proof.sources.len() == 1
                        && proof.depends_on.is_empty()
                });
            if (owner != actor && !cross_actor)
                || *count != 1
                || fact.effects.0 != sema::EffectSet::ACTOR
                || fact.ownership_before != sema::OwnershipState::Owned
                || fact.ownership_after != sema::OwnershipState::Taken
                || reservation_ty.source.is_some()
                || !producer.proofs.contains(&permit_record.id)
                || target.source.is_none()
            {
                return Err(unsupported("noncanonical one-way actor admission"));
            }
            continue;
        }
        let sema::ExpressionResolution::DirectCall {
            function: target, ..
        } = fact.resolution
        else {
            continue;
        };
        if facts
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| target.color == wrela_hir::FunctionColor::Async)
            && awaited
                .binary_search(&(fact.function, fact.expression))
                .is_err()
        {
            return Err(unsupported("async actor calls without an immediate await"));
        }
    }
    cancellable_sort_by(
        &mut edges,
        "actor wait edges",
        limits.model_edges,
        is_cancelled,
        &|left, right| {
            (
                left.from,
                left.to,
                left.source.file,
                left.source.range.start,
                left.source.range.end,
            )
                .cmp(&(
                    right.from,
                    right.to,
                    right.source.file,
                    right.source.range.start,
                    right.source.range.end,
                ))
        },
    )?;
    if actor_wait_graph_has_cycle(facts.functions.len(), &edges, limits, is_cancelled)? {
        return Err(unsupported(
            "cyclic actor wait graph with an acyclicity proof",
        ));
    }
    let mut proof = None;
    for candidate in &facts.proofs {
        check_cancelled(is_cancelled)?;
        if candidate.kind == sema::ProofKind::WaitGraphAcyclic {
            if proof.is_some() {
                return Err(unsupported("multiple actor wait-graph proofs"));
            }
            proof = Some(candidate);
        }
    }
    let proof = proof.ok_or(LowerError::MissingSemanticFact {
        subject: "actor image".to_owned(),
        fact: "wait-graph acyclicity proof",
    })?;
    let mut sources = try_vec(edges.len(), "actor wait proof sources", limits.model_edges)?;
    sources.extend(edges.iter().map(|edge| edge.source));
    cancellable_sort_by(
        &mut sources,
        "actor wait proof sources",
        limits.model_edges,
        is_cancelled,
        &|left, right| {
            (left.file, left.range.start, left.range.end).cmp(&(
                right.file,
                right.range.start,
                right.range.end,
            ))
        },
    )?;
    cancellable_dedup(&mut sources, is_cancelled)?;
    let mut dependencies = try_vec(
        facts.functions.len(),
        "actor wait proof dependencies",
        limits.model_edges,
    )?;
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if function.color == wrela_hir::FunctionColor::Async {
            dependencies.push(
                *function
                    .proofs
                    .get(1)
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: function.name.clone(),
                        fact: "async effect proof",
                    })?,
            );
        }
    }
    cancellable_sort(
        &mut dependencies,
        "actor wait proof dependencies",
        limits.model_edges,
        is_cancelled,
    )?;
    cancellable_dedup(&mut dependencies, is_cancelled)?;
    let sources_match = cancellable_slices_equal(&proof.sources, &sources, is_cancelled)?;
    let dependencies_match =
        cancellable_slices_equal(&proof.depends_on, &dependencies, is_cancelled)?;
    if proof.bound != u64::try_from(edges.len()).ok()
        || !sources_match
        || !dependencies_match
        || entry.proofs.binary_search(&proof.id).is_err()
    {
        return Err(unsupported("actor wait-graph proof substitution"));
    }
    Ok(proof.id)
}

fn semantic_expression_fact(
    facts: &sema::PartialAnalysis,
    function: sema::FunctionInstanceId,
    expression: wrela_hir::ExpressionId,
) -> Result<&sema::ExpressionFact, LowerError> {
    facts
        .expressions
        .binary_search_by_key(&(function, expression), |fact| {
            (fact.function, fact.expression)
        })
        .ok()
        .and_then(|index| facts.expressions.get(index))
        .ok_or(LowerError::MissingSemanticFact {
            subject: "actor expression".to_owned(),
            fact: "exact expression semantic fact",
        })
}

fn actor_wait_graph_has_cycle(
    node_count: usize,
    edges: &[ActorWaitEdge],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let mut colors = try_vec(node_count, "actor wait graph scratch", limits.model_edges)?;
    let mut stack = try_vec(node_count, "actor wait graph scratch", limits.model_edges)?;
    colors.resize(node_count, 0u8);
    for root in 0..node_count {
        check_cancelled(is_cancelled)?;
        if colors[root] != 0 {
            continue;
        }
        colors[root] = 1;
        let start = edges.partition_point(|edge| (edge.from.0 as usize) < root);
        stack.push((root, start));
        while let Some((node, next)) = stack.last_mut() {
            check_cancelled(is_cancelled)?;
            let end = edges.partition_point(|edge| edge.from.0 as usize <= *node);
            if *next >= end {
                colors[*node] = 2;
                stack.pop();
                continue;
            }
            let edge = edges[*next];
            *next = next.checked_add(1).ok_or(LowerError::ResourceLimit {
                resource: "actor wait graph scratch",
                limit: limits.model_edges,
            })?;
            let target = edge.to.0 as usize;
            match colors.get(target).copied() {
                Some(0) => {
                    *colors.get_mut(target).ok_or_else(|| {
                        LowerError::InternalInvariant("actor wait target is dangling".to_owned())
                    })? = 1;
                    let target_start =
                        edges.partition_point(|candidate| (candidate.from.0 as usize) < target);
                    stack.push((target, target_start));
                }
                Some(1) => return Ok(true),
                Some(2) => {}
                _ => {
                    return Err(LowerError::InternalInvariant(
                        "actor wait target is dangling".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(false)
}

fn validate_actor_proof_contract(
    facts: &sema::PartialAnalysis,
    graph: &sema::ImageGraph,
    entry: &sema::FunctionInstance,
    wait_proof: sema::ProofId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    if entry.effects.0 != sema::EffectSet::FIRMWARE | sema::EffectSet::ACTOR | sema::EffectSet::TASK
        || !entry.proofs.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(unsupported(
            "actor image entry effect or proof substitution",
        ));
    }
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == entry.id {
            continue;
        }
        if matches!(
            function.role,
            sema::FunctionRole::ActorTurn(_) | sema::FunctionRole::TaskEntry(_)
        ) && !function_proof_kind(facts, function, sema::ProofKind::Ownership, Some(1))
        {
            return Err(unsupported("actor function ownership proof substitution"));
        }
        if function.color == wrela_hir::FunctionColor::Async {
            let cleanup_bound = u64::try_from(function.parameters.len()).map_err(|_| {
                LowerError::InternalInvariant(
                    "async cleanup parameter bound does not fit u64".to_owned(),
                )
            })?;
            if !function_proof_kind(facts, function, sema::ProofKind::ViewDoesNotEscape, Some(0))
                || !function_proof_kind(
                    facts,
                    function,
                    sema::ProofKind::CleanupAcyclic,
                    Some(cleanup_bound),
                )
            {
                return Err(unsupported(
                    "async actor suspension or cleanup proof substitution",
                ));
            }
        }
    }
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        if entry.proofs.binary_search(&region.proof).is_err() {
            return Err(unsupported("actor entry omits a capacity proof"));
        }
    }
    let mut closed_proofs = facts
        .proofs
        .iter()
        .filter(|proof| proof.kind == sema::ProofKind::ImageClosed);
    let closed = closed_proofs
        .next()
        .ok_or(LowerError::MissingSemanticFact {
            subject: "actor image".to_owned(),
            fact: "closed-image proof",
        })?;
    if closed.bound != Some(graph.static_bytes)
        || closed.depends_on.binary_search(&wait_proof).is_err()
        || entry.proofs.binary_search(&closed.id).is_err()
        || closed.depends_on.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(unsupported("actor closed-image proof substitution"));
    }
    if closed_proofs.next().is_some() {
        return Err(unsupported("multiple actor closed-image proofs"));
    }
    Ok(())
}

fn function_proof_kind(
    facts: &sema::PartialAnalysis,
    function: &sema::FunctionInstance,
    kind: sema::ProofKind,
    exact_bound: Option<u64>,
) -> bool {
    function.proofs.iter().any(|id| {
        facts.proofs.get(id.0 as usize).is_some_and(|proof| {
            proof.id == *id
                && proof.kind == kind
                && exact_bound.is_none_or(|bound| proof.bound == Some(bound))
        })
    })
}

fn supported_generated_tests<'a>(
    input: &'a AnalyzedImage,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<GeneratedTestFacts<'a>, LowerError> {
    check_cancelled(is_cancelled)?;
    let facts = input.facts();
    let (root_group, harness_name) = match &facts.root {
        sema::AnalysisRoot::GeneratedTestHarness {
            group,
            harness_name,
        } => (*group, harness_name),
        sema::AnalysisRoot::DeclaredImage { .. } => {
            return Err(unsupported("declared images as generated test harnesses"));
        }
    };
    if facts.test_plan.is_some() || !facts.comptime_test_results.is_empty() {
        return Err(unsupported("test discovery facts in compiled test images"));
    }
    if !facts.scope_protocols.is_empty() || !facts.scope_activations.is_empty() {
        return Err(unsupported(
            "semantic-with-cleanup-lowering-pending (scope protocols and activations in generated tests)",
        ));
    }
    if !facts.projection_protocols.is_empty() || !facts.lexical_views.is_empty() {
        return Err(unsupported(
            "semantic-projection-lowering-pending (projection protocols in generated tests)",
        ));
    }
    if !facts.baked_artifacts.is_empty() {
        return Err(unsupported("baked artifacts in generated tests"));
    }
    let graph = facts
        .graph
        .as_ref()
        .ok_or(LowerError::MissingSemanticFact {
            subject: "generated test harness".to_owned(),
            fact: "closed image graph",
        })?;
    require_empty_runtime_graph(graph)?;
    if graph.name != *harness_name {
        return Err(LowerError::InternalInvariant(
            "generated test root name differs from its closed graph".to_owned(),
        ));
    }
    let Some(unit) = facts.types.first() else {
        return Err(unsupported("generated tests without the unit type"));
    };
    require_unit_type(unit)?;
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        validate_supported_source_type(ty, facts)?;
    }
    let group = facts
        .compiled_test_group
        .as_ref()
        .filter(|record| record.id == root_group)
        .ok_or(LowerError::MissingSemanticFact {
            subject: "generated test harness".to_owned(),
            fact: "matching compiled test-group metadata",
        })?;
    if !matches!(
        &group.root,
        ImageRoot::GeneratedHarness { harness_name: planned } if planned == harness_name
    ) {
        return Err(LowerError::InternalInvariant(
            "compiled test group does not describe the generated root".to_owned(),
        ));
    }
    let harness = facts
        .functions
        .get(graph.entry.0 as usize)
        .filter(|function| function.id == graph.entry)
        .ok_or(LowerError::MissingSemanticFact {
            subject: "generated test harness".to_owned(),
            fact: "generated image entry",
        })?;
    if harness.origin != (sema::FunctionOrigin::GeneratedTestHarness { group: root_group })
        || harness.role != sema::FunctionRole::ImageEntry
        || harness.color != wrela_hir::FunctionColor::Sync
        || !harness.generic_arguments.is_empty()
        || !harness.parameters.is_empty()
        || harness.result != sema::SemanticTypeId(0)
        || harness.source.is_some()
        || facts
            .values
            .iter()
            .any(|value| value.function == harness.id)
        || facts
            .expressions
            .iter()
            .any(|fact| fact.function == harness.id)
        || facts
            .statements
            .iter()
            .any(|fact| fact.function == harness.id)
    {
        return Err(unsupported("noncanonical generated test harness entry"));
    }

    let mut test_functions = try_vec(
        group.tests.len(),
        "selected semantic test functions",
        limits.model_edges,
    )?;
    for planned in &group.tests {
        check_cancelled(is_cancelled)?;
        let ImageTestInvocation::GeneratedFunction { function_key } = planned.invocation else {
            return Err(unsupported(
                "declared scenarios in a generated test harness",
            ));
        };
        let mut matches = facts.functions.iter().filter(|function| {
            function.role == sema::FunctionRole::Test && function.key == function_key
        });
        let function = matches.next().ok_or(LowerError::MissingSemanticFact {
            subject: planned.descriptor.name.clone(),
            fact: "selected semantic test function",
        })?;
        if matches.next().is_some()
            || function.name != planned.descriptor.name
            || function.role != sema::FunctionRole::Test
            || function.color != wrela_hir::FunctionColor::Sync
            || function.source != planned.descriptor.source
            || planned.descriptor.kind != PlannedTestKind::IntegrationImage
            || planned.descriptor.source.is_none()
            || !function.generic_arguments.is_empty()
            || !function.parameters.is_empty()
            || function.result != sema::SemanticTypeId(0)
        {
            return Err(unsupported(
                "generated test functions outside the synchronous zero-argument unit subset",
            ));
        }
        if !matches!(function.origin, sema::FunctionOrigin::Source { .. }) {
            return Err(unsupported(
                "non-source functions selected as integration tests",
            ));
        }
        test_functions.push(function.id);
    }
    validate_reachable_source_functions(input, &test_functions, harness.id, limits, is_cancelled)?;
    let expected_events = u32::try_from(group.tests.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(3));
    if expected_events != Some(group.maximum_events) {
        return Err(LowerError::InternalInvariant(
            "generated test group event bound omits the reserved assertion-failure terminal frames"
                .to_owned(),
        ));
    }
    Ok(GeneratedTestFacts {
        input,
        facts,
        graph,
        group,
        harness,
        test_functions,
    })
}

fn validate_supported_source_type(
    ty: &sema::SemanticType,
    facts: &sema::PartialAnalysis,
) -> Result<(), LowerError> {
    let valid = match &ty.kind {
        sema::SemanticTypeKind::Unit | sema::SemanticTypeKind::Bool => {
            ty.linearity == sema::Linearity::ScalarCopy
        }
        sema::SemanticTypeKind::Integer {
            bits,
            pointer_sized,
            ..
        } => {
            ty.linearity == sema::Linearity::ScalarCopy
                && if *pointer_sized {
                    *bits == 64
                } else {
                    matches!(*bits, 8 | 16 | 32 | 64 | 128)
                }
        }
        sema::SemanticTypeKind::Float { bits } => {
            ty.linearity == sema::Linearity::ScalarCopy && matches!(*bits, 32 | 64)
        }
        sema::SemanticTypeKind::Structure {
            declaration,
            arguments,
            fields,
        } => {
            if !arguments.iter().all(|argument| {
                matches!(argument, sema::SemanticArgument::Type(ty)
                    if is_stored_copy_scalar(facts, *ty))
            }) {
                return Err(unsupported(
                    "semantic-generic-structure-argument-lowering-pending (non-type or non-scalar specialization)",
                ));
            }
            matches!(
                ty.linearity,
                sema::Linearity::ExplicitCopy | sema::Linearity::ScalarCopy
            ) && ty.source.is_some()
                && declaration.0 < facts.hir.declarations
                && fields
                    .iter()
                    .all(|field| !field.name.is_empty() && is_stored_copy_scalar(facts, field.ty))
                && canonical_flat_structure_layout(facts, fields).is_some_and(
                    |(size, alignment)| {
                        ty.size_upper_bound == Some(size) && ty.alignment_lower_bound == alignment
                    },
                )
        }
        sema::SemanticTypeKind::Enumeration {
            declaration,
            arguments,
            variants,
        } => {
            if !arguments.is_empty()
                && variants
                    .iter()
                    .any(|variant| !matches!(variant.fields.as_slice(), [_]))
            {
                return Err(unsupported(
                    "semantic-generic-enum-mixed-arity-lowering-pending (unit or non-unary generic enum variants)",
                ));
            }
            // Every variant is exactly one supported copy scalar (no unit
            // variants); this is the payload-bearing runtime enum shape the
            // machine lowering below packs into one shared tagged-union slot.
            let all_single_scalar_payload = !variants.is_empty()
                && variants.iter().all(|variant| {
                    matches!(variant.fields.as_slice(), [field]
                    if field.name.is_empty()
                        && field.public
                        && facts.types.get(field.ty.0 as usize).is_some_and(|field_ty| {
                        field_ty.linearity == sema::Linearity::ScalarCopy
                            && matches!(field_ty.kind, sema::SemanticTypeKind::Bool
                                | sema::SemanticTypeKind::Integer { .. }
                                | sema::SemanticTypeKind::Float { bits: 32 | 64 })
                    }))
                });
            // Heterogeneous per-variant scalar payloads resolve at the sema
            // tier (T0.1b), but the tagged-union machine lowering that packs
            // differing payload types into the shared slot is a later slice.
            // Fail closed with a named diagnostic here rather than
            // miscompiling against the first-variant layout assumed below.
            // (`all_single_scalar_payload` guarantees each `fields[0]` exists;
            // `arguments.is_empty()` excludes the generic Result path.)
            if arguments.is_empty()
                && all_single_scalar_payload
                && !variants
                    .windows(2)
                    .all(|pair| pair[0].fields[0].ty == pair[1].fields[0].ty)
            {
                return Err(unsupported(
                    "semantic-enum-heterogeneous-lowering-pending (per-variant differing scalar enum payloads)",
                ));
            }
            // A nominal payload — a flat struct (T0.1c) OR a nongeneric closed
            // enum (T0.1d) — resolves at the sema tier, but the machine lowering
            // that packs it into the shared tagged-union slot is a later slice.
            // Any variant carrying a single NON-scalar payload field trips this
            // guard: sema admits only flat-struct and nongeneric-enum nominal
            // payloads (rejecting every view/generic/recursive payload), so a
            // non-scalar field here is exactly one of those two nominal shapes.
            // Fail closed with a named diagnostic rather than falling through to
            // the generic scalar/flat-structure rejection below or miscompiling
            // against the scalar-slot layout assumed there. (`arguments.is_empty()`
            // excludes the generic core Result path.)
            if arguments.is_empty()
                && variants.iter().any(|variant| {
                    matches!(variant.fields.as_slice(), [field]
                    if facts.types.get(field.ty.0 as usize).is_some_and(|field_ty| {
                        !(field_ty.linearity == sema::Linearity::ScalarCopy
                            && matches!(field_ty.kind, sema::SemanticTypeKind::Bool
                                | sema::SemanticTypeKind::Integer { .. }
                                | sema::SemanticTypeKind::Float { bits: 32 | 64 }))
                    }))
                })
            {
                return Err(unsupported(
                    "semantic-enum-nominal-payload-lowering-pending (flat-struct or nongeneric-enum nominal enum payloads)",
                ));
            }
            let layout = canonical_runtime_enum_layout(facts, variants);
            ty.linearity == sema::Linearity::ExplicitCopy
                && ty.source.is_some()
                && declaration.0 < facts.hir.declarations
                && supported_runtime_enum_type_arguments(arguments)
                && !variants.is_empty()
                && variants.len() <= 256
                && variants.iter().all(|variant| {
                    matches!(variant.fields.as_slice(), [field]
                    if field.name.is_empty()
                        && field.public
                        && facts.types.get(field.ty.0 as usize).is_some_and(|field_ty| {
                        field_ty.linearity == sema::Linearity::ScalarCopy
                            && matches!(field_ty.kind, sema::SemanticTypeKind::Bool
                                | sema::SemanticTypeKind::Integer { .. }
                                | sema::SemanticTypeKind::Float { bits: 32 | 64 })
                    }))
                })
                && layout.is_some_and(|(size, alignment)| {
                    ty.size_upper_bound == Some(size) && ty.alignment_lower_bound == alignment
                })
        }
        sema::SemanticTypeKind::Function {
            color,
            parameters,
            result,
        } => {
            ty.linearity == sema::Linearity::ScalarCopy
                && *color == wrela_hir::FunctionColor::Sync
                && (result.0 as usize) < facts.types.len()
                && parameters
                    .iter()
                    .all(|parameter| (parameter.ty.0 as usize) < facts.types.len())
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(unsupported(
            "source semantic types outside the scalar or flat-structure subset",
        ))
    }
}

fn supported_runtime_enum_type_arguments(arguments: &[sema::SemanticArgument]) -> bool {
    arguments
        .iter()
        .all(|argument| matches!(argument, sema::SemanticArgument::Type(_)))
}

fn supported_core_result_arguments(
    arguments: &[sema::SemanticArgument],
    variants: &[sema::SemanticVariant],
) -> bool {
    matches!(arguments, [sema::SemanticArgument::Type(ok), sema::SemanticArgument::Type(err)] if ok == err)
        && matches!(variants, [ok, err]
            if ok.name == "Ok"
                && err.name == "Err"
                && matches!((ok.fields.as_slice(), err.fields.as_slice()), ([ok_field], [err_field])
                    if ok_field.ty == err_field.ty
                        && matches!(arguments, [sema::SemanticArgument::Type(payload), _]
                            if *payload == ok_field.ty)))
}

fn canonical_tagged_enum_layout(payload: &sema::SemanticType) -> Option<(u64, u32)> {
    let (payload_size, payload_alignment) = match payload.kind {
        sema::SemanticTypeKind::Bool => (1_u64, 1_u32),
        sema::SemanticTypeKind::Integer {
            bits: 8 | 16 | 32 | 64 | 128,
            ..
        }
        | sema::SemanticTypeKind::Float { bits: 32 | 64 } => {
            let bits = match payload.kind {
                sema::SemanticTypeKind::Integer { bits, .. }
                | sema::SemanticTypeKind::Float { bits } => bits,
                _ => unreachable!(),
            };
            let bytes = u64::from(bits.div_ceil(8));
            (bytes, u32::try_from(bytes).ok()?)
        }
        _ => return None,
    };
    let alignment = u64::from(payload_alignment);
    let payload_offset =
        1_u64.checked_add(alignment.checked_sub(1)?)? & !alignment.checked_sub(1)?;
    let unpadded = payload_offset.checked_add(payload_size)?;
    let size = unpadded.checked_add(alignment.checked_sub(1)?)? & !alignment.checked_sub(1)?;
    Some((size, payload_alignment))
}

fn canonical_runtime_enum_layout(
    facts: &sema::PartialAnalysis,
    variants: &[sema::SemanticVariant],
) -> Option<(u64, u32)> {
    let mut payload_size = 0_u64;
    let mut payload_alignment = 1_u32;
    for variant in variants {
        let [field] = variant.fields.as_slice() else {
            return None;
        };
        let payload = facts.types.get(field.ty.0 as usize)?;
        let size = payload.size_upper_bound?;
        canonical_tagged_enum_layout(payload)?;
        payload_size = payload_size.max(size);
        payload_alignment = payload_alignment.max(payload.alignment_lower_bound);
    }
    let alignment = u64::from(payload_alignment);
    let mask = alignment.checked_sub(1)?;
    let payload_offset = 1_u64.checked_add(mask)? & !mask;
    let unpadded = payload_offset.checked_add(payload_size)?;
    let size = unpadded.checked_add(mask)? & !mask;
    Some((size, payload_alignment))
}

fn validate_reachable_source_functions(
    input: &AnalyzedImage,
    roots: &[sema::FunctionInstanceId],
    harness: sema::FunctionInstanceId,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let facts = input.facts();
    let program = input.hir().as_program();
    let mut edges = try_vec(
        facts.functions.len(),
        "semantic source call graph",
        limits.model_edges,
    )?;
    for _ in &facts.functions {
        edges.push(Vec::<sema::FunctionInstanceId>::new());
    }
    let mut edge_count = 0u64;
    for fact in &facts.expressions {
        check_cancelled(is_cancelled)?;
        let target = match &fact.resolution {
            sema::ExpressionResolution::DirectCall {
                function: target, ..
            }
            | sema::ExpressionResolution::OperatorCall {
                function: target, ..
            } => target,
            _ => continue,
        };
        let caller = facts
            .functions
            .get(fact.function.0 as usize)
            .filter(|function| function.id == fact.function)
            .ok_or_else(|| {
                LowerError::InternalInvariant("direct call has a foreign caller".to_owned())
            })?;
        let target_function = facts
            .functions
            .get(target.0 as usize)
            .filter(|function| function.id == *target)
            .ok_or_else(|| {
                LowerError::InternalInvariant("direct call has a foreign target".to_owned())
            })?;
        if !matches!(caller.origin, sema::FunctionOrigin::Source { .. })
            || !matches!(target_function.origin, sema::FunctionOrigin::Source { .. })
            || target_function.role != sema::FunctionRole::Ordinary
        {
            return Err(unsupported(
                "calls outside reachable ordinary scalar helpers",
            ));
        }
        edge_count = edge_count.checked_add(1).ok_or(LowerError::ResourceLimit {
            resource: "semantic source call graph",
            limit: limits.model_edges,
        })?;
        if edge_count > limits.model_edges {
            return Err(LowerError::ResourceLimit {
                resource: "semantic source call graph",
                limit: limits.model_edges,
            });
        }
        let outgoing = edges
            .get_mut(fact.function.0 as usize)
            .ok_or_else(|| LowerError::InternalInvariant("caller is not dense".to_owned()))?;
        outgoing
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "semantic source call graph",
                limit: limits.model_edges,
            })?;
        outgoing.push(*target);
    }

    let mut colors = try_vec(
        facts.functions.len(),
        "semantic source reachability",
        limits.model_edges,
    )?;
    colors.resize(facts.functions.len(), 0u8);
    for root in roots {
        check_cancelled(is_cancelled)?;
        let root_index = root.0 as usize;
        if colors.get(root_index).copied() == Some(2) {
            continue;
        }
        let mut stack = try_vec(
            facts.functions.len(),
            "semantic source reachability",
            limits.model_edges,
        )?;
        let color = colors
            .get_mut(root_index)
            .ok_or_else(|| LowerError::InternalInvariant("test root is dangling".to_owned()))?;
        *color = 1;
        stack.push((root_index, 0usize));
        while let Some((function, next_edge)) = stack.last_mut() {
            check_cancelled(is_cancelled)?;
            let Some(outgoing) = edges.get(*function) else {
                return Err(LowerError::InternalInvariant(
                    "call graph function is dangling".to_owned(),
                ));
            };
            if let Some(target) = outgoing.get(*next_edge) {
                *next_edge = next_edge.checked_add(1).ok_or(LowerError::ResourceLimit {
                    resource: "semantic source reachability",
                    limit: limits.model_edges,
                })?;
                let target = target.0 as usize;
                match colors.get(target).copied() {
                    Some(0) => {
                        let color = colors.get_mut(target).ok_or_else(|| {
                            LowerError::InternalInvariant("call target is dangling".to_owned())
                        })?;
                        *color = 1;
                        stack.push((target, 0));
                    }
                    Some(1) => return Err(unsupported("recursive scalar helper calls")),
                    Some(2) => {}
                    _ => {
                        return Err(LowerError::InternalInvariant(
                            "call target is dangling".to_owned(),
                        ));
                    }
                }
            } else {
                let completed = stack
                    .pop()
                    .ok_or_else(|| LowerError::InternalInvariant("empty DFS stack".to_owned()))?
                    .0;
                let color = colors.get_mut(completed).ok_or_else(|| {
                    LowerError::InternalInvariant("completed function is dangling".to_owned())
                })?;
                *color = 2;
            }
        }
    }

    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == harness {
            continue;
        }
        let sema::FunctionOrigin::Source { declaration, body } = function.origin else {
            return Err(unsupported("generated functions outside the test harness"));
        };
        let declaration_record =
            program
                .declaration(declaration)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: function.name.clone(),
                    fact: "source function declaration",
                })?;
        let wrela_hir::DeclarationKind::Function(source) = &declaration_record.kind else {
            return Err(unsupported("non-function source origins"));
        };
        if source.body != Some(body)
            || source.color != function.color
            || function.source != Some(declaration_record.source)
            || function.color != wrela_hir::FunctionColor::Sync
            || !matches!(
                function.role,
                sema::FunctionRole::Test | sema::FunctionRole::Ordinary
            )
            || colors.get(function.id.0 as usize).copied() != Some(2)
        {
            return Err(unsupported(
                "unreachable or noncanonical scalar source functions",
            ));
        }
    }
    check_cancelled(is_cancelled)
}

fn require_unit_type(ty: &sema::SemanticType) -> Result<(), LowerError> {
    if ty.id != sema::SemanticTypeId(0)
        || ty.kind != sema::SemanticTypeKind::Unit
        || ty.linearity != sema::Linearity::ScalarCopy
        || ty.size_upper_bound != Some(0)
        || ty.alignment_lower_bound != 1
        || ty.source.is_some()
    {
        Err(unsupported("semantic types other than canonical unit"))
    } else {
        Ok(())
    }
}

fn require_empty_runtime_graph(graph: &sema::ImageGraph) -> Result<(), LowerError> {
    if !graph.actors.is_empty()
        || !graph.tasks.is_empty()
        || !graph.devices.is_empty()
        || !graph.pools.is_empty()
        || !graph.regions.is_empty()
        || !graph.brands.is_empty()
        || graph.static_bytes != 0
        || graph.peak_bytes != 0
        || graph.startup_order.as_slice() != [sema::ImageOwner::Runtime]
        || graph.shutdown_order.as_slice() != [sema::ImageOwner::Runtime]
    {
        Err(unsupported("nonempty runtime image graphs"))
    } else {
        Ok(())
    }
}

fn lower_minimum(
    minimum: &MinimumFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SemanticWir, LowerError> {
    check_cancelled(is_cancelled)?;
    let mut types = try_vec(1, "SemanticWir types", u64::from(limits.types))?;
    types.push(wir::TypeRecord {
        id: wir::TypeId(minimum.ty.id.0),
        source_name: copy_text("unit", limits.payload_bytes)?,
        kind: wir::TypeKind::Primitive(wir::PrimitiveType::Unit),
        linearity: wir::Linearity::CopyScalar,
        source: minimum.ty.source,
    });

    let mut proofs = try_vec(
        minimum.facts.proofs.len(),
        "SemanticWir proofs",
        limits.model_edges,
    )?;
    for proof in &minimum.facts.proofs {
        check_cancelled(is_cancelled)?;
        let mut sources = try_vec(
            proof.sources.len(),
            "SemanticWir proof sources",
            limits.model_edges,
        )?;
        sources.extend_from_slice(&proof.sources);
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "SemanticWir proof dependencies",
            limits.model_edges,
        )?;
        depends_on.extend(proof.depends_on.iter().map(|id| wir::ProofId(id.0)));
        let mut explanation = try_vec(
            proof.explanation.len(),
            "SemanticWir proof explanations",
            limits.model_edges,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            explanation.push(copy_text(line, limits.payload_bytes)?);
        }
        proofs.push(wir::ProofRecord {
            id: wir::ProofId(proof.id.0),
            kind: lower_proof_kind(&proof.kind),
            subject: copy_text(&proof.subject, limits.payload_bytes)?,
            bound: proof.bound,
            sources,
            depends_on,
            explanation,
        });
    }

    let mut function_proofs = try_vec(
        minimum.function.proofs.len(),
        "SemanticWir function proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(
        minimum
            .function
            .proofs
            .iter()
            .map(|proof| wir::ProofId(proof.0)),
    );
    let mut statements = try_vec(1, "generated entry statements", limits.operations)?;
    statements.push(wir::SemanticStatement::Return(Vec::new()));
    let mut functions = try_vec(1, "SemanticWir functions", u64::from(limits.functions))?;
    functions.push(wir::SemanticFunction {
        id: wir::FunctionId(minimum.function.id.0),
        instance_key: minimum.function.key.0,
        name: copy_text(&minimum.function.name, limits.payload_bytes)?,
        origin: wir::FunctionOrigin::GeneratedImageEntry {
            constructor: minimum.constructor.0,
        },
        role: wir::FunctionRole::ImageEntry,
        color: wir::FunctionColor::Sync,
        parameters: Vec::new(),
        result: wir::TypeId(minimum.function.result.0),
        values: Vec::new(),
        body: wir::SemanticRegion {
            parameters: Vec::new(),
            statements,
        },
        effects: wir::EffectSet(minimum.function.effects.0),
        proofs: function_proofs,
        source: minimum.function.source,
        stack_bound: minimum.function.stack_bytes_bound,
        frame_bound: minimum.function.frame_bytes_bound,
        uninterrupted_bound: minimum.function.uninterrupted_work_bound,
        recursive_depth_bound: minimum.function.recursive_depth_bound,
    });

    let startup_order = lower_owners(
        &minimum.graph.startup_order,
        limits.model_edges,
        is_cancelled,
    )?;
    let shutdown_order = lower_owners(
        &minimum.graph.shutdown_order,
        limits.model_edges,
        is_cancelled,
    )?;
    check_cancelled(is_cancelled)?;
    let reachable_declarations = minimum_provenance_declaration_count(minimum.constructor);
    Ok(SemanticWir {
        version: wir::SEMANTIC_WIR_VERSION,
        name: copy_text(&minimum.graph.name, limits.payload_bytes)?,
        build: minimum.facts.build.clone(),
        source_summary: wir::SourceSummary {
            hir_files: minimum.facts.hir.files,
            hir_declarations: minimum.facts.hir.declarations,
            reachable_declarations,
            monomorphized_instantiations: 1,
            resolved_interface_calls: 0,
        },
        types,
        globals: Vec::new(),
        functions,
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        scopes: Vec::new(),
        proofs,
        tests: Vec::new(),
        compiled_test_group: minimum.compiled_test_group.cloned(),
        startup_order,
        shutdown_order,
        image_entry: wir::FunctionId(minimum.graph.entry.0),
        static_bytes: minimum.graph.static_bytes,
        peak_bytes: minimum.graph.peak_bytes,
    })
}

fn lower_scope_context(
    actor: &ActorImageFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScopeLoweringContext, LowerError> {
    let mut activations = try_vec(
        actor.facts.scope_activations.len(),
        "SemanticWir scope activations",
        limits.model_edges,
    )?;
    for (index, activation) in actor.facts.scope_activations.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if activation.statement.0 as usize >= actor.input.hir().as_program().statements.len() {
            return Err(LowerError::MissingSemanticFact {
                subject: "scope activation".to_owned(),
                fact: "with statement",
            });
        }
        activations.push(ScopeActivationLowering {
            statement: activation.statement,
            protocol: activation.protocol,
            scope: wir::ScopeId(u32::try_from(index).map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir scope activations",
                limit: limits.model_edges,
            })?),
        });
    }
    Ok(ScopeLoweringContext { activations })
}

fn lower_scope_plans_and_helpers(
    actor: &ActorImageFacts<'_>,
    context: &ScopeLoweringContext,
    functions: &mut Vec<wir::SemanticFunction>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::ScopePlan>, LowerError> {
    let mut exit_functions = try_vec(
        actor.facts.scope_protocols.len(),
        "SemanticWir scope exit functions",
        limits.model_edges,
    )?;
    for protocol in &actor.facts.scope_protocols {
        check_cancelled(is_cancelled)?;
        let source = actor
            .input
            .hir()
            .as_program()
            .body(protocol.exit)
            .map(|body| body.source)
            .ok_or(LowerError::MissingSemanticFact {
                subject: protocol.name.clone(),
                fact: "scope exit body",
            })?;
        let function_id = wir::FunctionId(u32::try_from(functions.len()).map_err(|_| {
            LowerError::ResourceLimit {
                resource: "SemanticWir functions",
                limit: u64::from(limits.functions),
            }
        })?);
        let parameter = wir::ValueId(0);
        let helper = wir::SemanticFunction {
            id: function_id,
            // This bounded slice admits exactly one scope protocol. Reuse the
            // already authenticated build-profile SHA-256 as its synthetic
            // helper identity, and fail closed below on any function-key
            // collision instead of inventing an unauthenticated digest.
            instance_key: actor.facts.build.profile,
            name: copy_text(
                &format!("{}.__scope_exit", protocol.name),
                limits.payload_bytes,
            )?,
            origin: wir::FunctionOrigin::Source,
            role: wir::FunctionRole::Cleanup,
            color: wir::FunctionColor::Sync,
            parameters: vec![parameter],
            result: wir::TypeId(0),
            values: vec![wir::SemanticValue {
                id: parameter,
                ty: wir::TypeId(protocol.result.0),
                origin: Some(source),
                name: Some("state".to_owned()),
            }],
            body: wir::SemanticRegion {
                parameters: vec![parameter],
                statements: vec![wir::SemanticStatement::Return(Vec::new())],
            },
            effects: wir::EffectSet(0),
            proofs: vec![wir::ProofId(protocol.proof.0)],
            source: Some(source),
            stack_bound: 0,
            frame_bound: 0,
            uninterrupted_bound: Some(1),
            recursive_depth_bound: Some(1),
        };
        if functions
            .iter()
            .any(|function| function.instance_key == helper.instance_key)
        {
            return Err(unsupported("semantic-scope-cleanup-helper-key-collision"));
        }
        push_bounded_id(
            functions,
            helper,
            "SemanticWir functions",
            u64::from(limits.functions),
        )?;
        exit_functions.push(function_id);
    }

    let mut scopes = try_vec(
        actor.facts.scope_activations.len(),
        "SemanticWir scope plans",
        limits.model_edges,
    )?;
    for (index, activation) in actor.facts.scope_activations.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let lowered = context
            .activation(activation.statement)
            .filter(|lowered| lowered.scope.0 as usize == index)
            .ok_or_else(|| {
                LowerError::InternalInvariant(
                    "scope activation lowering identity changed".to_owned(),
                )
            })?;
        let protocol = actor
            .facts
            .scope_protocols
            .get(activation.protocol.0 as usize)
            .filter(|protocol| protocol.id == activation.protocol)
            .ok_or(LowerError::MissingSemanticFact {
                subject: "scope activation".to_owned(),
                fact: "scope protocol",
            })?;
        let mut dependencies = try_vec(
            activation.cleanup_dependencies.len(),
            "SemanticWir scope dependencies",
            limits.model_edges,
        )?;
        for dependency in &activation.cleanup_dependencies {
            check_cancelled(is_cancelled)?;
            dependencies.push(
                context
                    .activation(*dependency)
                    .map(|activation| activation.scope)
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: protocol.name.clone(),
                        fact: "scope cleanup dependency",
                    })?,
            );
        }
        scopes.push(wir::ScopePlan {
            id: lowered.scope,
            name: copy_text(&protocol.name, limits.payload_bytes)?,
            state_type: wir::TypeId(activation.state_type.0),
            abort: None,
            exit: *exit_functions.get(activation.protocol.0 as usize).ok_or(
                LowerError::MissingSemanticFact {
                    subject: protocol.name.clone(),
                    fact: "scope exit helper",
                },
            )?,
            suspend_safe: false,
            dependencies,
            reverse_source_order: activation.reverse_source_order,
            cleanup_proof: wir::ProofId(activation.proof.0),
            source: actor
                .input
                .hir()
                .as_program()
                .statement(activation.statement)
                .map(|statement| statement.source)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: protocol.name.clone(),
                    fact: "with statement source",
                })?,
        });
    }
    Ok(scopes)
}

fn lower_actor_image(
    actor: &ActorImageFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(SemanticWir, LoweringReport), LowerError> {
    check_cancelled(is_cancelled)?;
    let scope_context = lower_scope_context(actor, limits, is_cancelled)?;
    let types = lower_actor_types(actor.input, limits, is_cancelled)?;
    let mut proofs = lower_proofs(actor.facts, limits, is_cancelled)?;
    if proofs.get(actor.wait_proof.0 as usize).is_none_or(|proof| {
        proof.id != wir::ProofId(actor.wait_proof.0)
            || proof.kind != wir::ProofKind::WaitGraphAcyclic
    }) {
        return Err(LowerError::InternalInvariant(
            "lowered actor wait proof lost its exact identity".to_owned(),
        ));
    }
    let mut functions = try_vec(
        actor.facts.functions.len(),
        "SemanticWir actor functions",
        u64::from(limits.functions),
    )?;
    let mut operations = 0u64;
    let mut values = 0u64;
    for function in &actor.facts.functions {
        check_cancelled(is_cancelled)?;
        let (lowered, function_operations) = if function.id == actor.entry.id {
            (lower_actor_entry_function(actor, limits, is_cancelled)?, 0)
        } else {
            lower_source_function(
                actor.input,
                function,
                Some(&scope_context),
                limits,
                is_cancelled,
            )?
        };
        if lowered.id.0 as usize != functions.len() {
            return Err(unsupported("noncanonical actor function identity order"));
        }
        operations =
            operations
                .checked_add(function_operations)
                .ok_or(LowerError::ResourceLimit {
                    resource: "SemanticWir operations",
                    limit: limits.operations,
                })?;
        if operations > limits.operations {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: limits.operations,
            });
        }
        values = values
            .checked_add(u64::try_from(lowered.values.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "SemanticWir values",
                    limit: limits.values,
                }
            })?)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            })?;
        if values > limits.values {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            });
        }
        functions.push(lowered);
    }
    let scopes =
        lower_scope_plans_and_helpers(actor, &scope_context, &mut functions, limits, is_cancelled)?;
    let actors = lower_actor_instances(actor.graph, limits, is_cancelled)?;
    let tasks = lower_task_instances(actor.graph, limits, is_cancelled)?;
    let mut regions = lower_actor_regions(actor.graph, limits, is_cancelled)?;
    let (activations, activation_bytes, image_closed_proof) = lower_actor_activations(
        ActorActivationOutput {
            types: &types,
            functions: &mut functions,
            actors: &actors,
            tasks: &tasks,
            regions: &mut regions,
            proofs: &mut proofs,
            image_name: &actor.graph.name,
            startup_order: actor.graph.startup_order.len(),
            shutdown_order: actor.graph.shutdown_order.len(),
        },
        actor.graph.static_bytes,
        limits,
        is_cancelled,
    )?;
    let static_bytes = actor
        .graph
        .static_bytes
        .checked_add(activation_bytes)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor static bytes",
            limit: limits.model_edges,
        })?;
    let entry = functions
        .get_mut(actor.graph.entry.0 as usize)
        .filter(|function| function.id.0 == actor.graph.entry.0)
        .ok_or(unsupported("actor image entry identity"))?;
    if let Some(image_closed_proof) = image_closed_proof {
        push_bounded_proof(&mut entry.proofs, image_closed_proof, limits.model_edges)?;
    }
    let startup_order = lower_owners(&actor.graph.startup_order, limits.model_edges, is_cancelled)?;
    let shutdown_order = lower_owners(
        &actor.graph.shutdown_order,
        limits.model_edges,
        is_cancelled,
    )?;
    let reachable_declarations = actor_reachable_declarations(actor, limits, is_cancelled)?;
    let image_nodes = actors
        .len()
        .checked_add(tasks.len())
        .and_then(|count| count.checked_add(regions.len()))
        .and_then(|count| count.checked_add(activations.len()))
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor image nodes",
            limit: limits.model_edges,
        })?;
    let wir = SemanticWir {
        version: wir::SEMANTIC_WIR_VERSION,
        name: copy_text(&actor.graph.name, limits.payload_bytes)?,
        build: actor.facts.build.clone(),
        source_summary: wir::SourceSummary {
            hir_files: actor.facts.hir.files,
            hir_declarations: actor.facts.hir.declarations,
            reachable_declarations,
            monomorphized_instantiations: u64::try_from(functions.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "SemanticWir actor functions",
                    limit: u64::from(limits.functions),
                }
            })?,
            resolved_interface_calls: 0,
        },
        types,
        globals: Vec::new(),
        functions,
        actors,
        tasks,
        devices: Vec::new(),
        pools: Vec::new(),
        regions,
        activations,
        scopes,
        proofs,
        tests: Vec::new(),
        compiled_test_group: None,
        startup_order,
        shutdown_order,
        image_entry: wir::FunctionId(actor.graph.entry.0),
        static_bytes,
        peak_bytes: static_bytes,
    };
    let report = LoweringReport {
        semantic_types: count_u32(
            wir.types.len(),
            "SemanticWir types",
            u64::from(limits.types),
        )?,
        function_instances: count_u32(
            wir.functions.len(),
            "SemanticWir functions",
            u64::from(limits.functions),
        )?,
        operations,
        proofs: count_u32(wir.proofs.len(), "SemanticWir proofs", limits.model_edges)?,
        image_nodes: count_u32(
            image_nodes,
            "SemanticWir actor image nodes",
            limits.model_edges,
        )?,
        tests: 0,
    };
    check_cancelled(is_cancelled)?;
    Ok((wir, report))
}

fn lower_actor_types(
    input: &AnalyzedImage,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::TypeRecord>, LowerError> {
    let facts = input.facts();
    let mut output = try_vec(
        facts.types.len(),
        "SemanticWir actor types",
        u64::from(limits.types),
    )?;
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        let (source_name, kind) = match &ty.kind {
            sema::SemanticTypeKind::Unit => (
                copy_text("unit", limits.payload_bytes)?,
                wir::TypeKind::Primitive(wir::PrimitiveType::Unit),
            ),
            sema::SemanticTypeKind::Bool => (
                copy_text("bool", limits.payload_bytes)?,
                wir::TypeKind::Primitive(wir::PrimitiveType::Bool),
            ),
            sema::SemanticTypeKind::Integer {
                signed,
                bits,
                pointer_sized,
            } => {
                let (name, kind) = lower_integer_type(*signed, *bits, *pointer_sized)?;
                (copy_text(name, limits.payload_bytes)?, kind)
            }
            sema::SemanticTypeKind::Float { bits: 32 } => (
                copy_text("f32", limits.payload_bytes)?,
                wir::TypeKind::Primitive(wir::PrimitiveType::F32),
            ),
            sema::SemanticTypeKind::Float { bits: 64 } => (
                copy_text("f64", limits.payload_bytes)?,
                wir::TypeKind::Primitive(wir::PrimitiveType::F64),
            ),
            sema::SemanticTypeKind::Structure {
                declaration,
                arguments,
                fields,
            } => {
                let declaration = input
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .filter(|record| {
                        ty.source == Some(record.source)
                            && matches!(record.kind, wrela_hir::DeclarationKind::Structure(_))
                    })
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: "flat actor runtime structure".to_owned(),
                        fact: "source declaration",
                    })?;
                let wrela_hir::DeclarationKind::Structure(source_structure) = &declaration.kind
                else {
                    return Err(unsupported(
                        "non-structure source declaration for actor runtime structure",
                    ));
                };
                if !generic_structure_source_generics_match(
                    input.hir().as_program(),
                    declaration,
                    source_structure,
                    arguments,
                ) {
                    return Err(unsupported(
                        "semantic-generic-structure-parameter-lowering-pending (const, bounded, or unauthenticated specialization)",
                    ));
                }
                if !source_structure.implements.is_empty()
                    || source_structure.fields.len() != fields.len()
                {
                    return Err(unsupported(
                        "noncanonical actor runtime structure semantic facts",
                    ));
                }
                let name = declaration
                    .name
                    .as_ref()
                    .ok_or_else(|| unsupported("anonymous flat actor runtime structures"))?
                    .as_str();
                let mut lowered = try_vec(
                    fields.len(),
                    "SemanticWir actor structure fields",
                    limits.model_edges,
                )?;
                for (field, source_field) in fields.iter().zip(&source_structure.fields) {
                    check_cancelled(is_cancelled)?;
                    if field.name != source_field.name.as_str()
                        || field.public
                            != (source_field.visibility != wrela_hir::Visibility::Private)
                        || source_field.default.is_some()
                        || !source_field.attributes.is_empty()
                        || !generic_structure_source_field_matches(
                            facts,
                            source_structure,
                            arguments,
                            &source_field.ty,
                            field.ty,
                        )
                    {
                        return Err(unsupported(
                            "actor runtime structure semantic facts differ from source",
                        ));
                    }
                    lowered.push(wir::FieldType {
                        name: copy_text(&field.name, limits.payload_bytes)?,
                        ty: wir::TypeId(field.ty.0),
                        public: field.public,
                    });
                }
                (
                    copy_text(name, limits.payload_bytes)?,
                    wir::TypeKind::Struct { fields: lowered },
                )
            }
            sema::SemanticTypeKind::Function {
                color,
                parameters,
                result,
            } => {
                let mut lowered = try_vec(
                    parameters.len(),
                    "SemanticWir actor function type parameters",
                    limits.model_edges,
                )?;
                for parameter in parameters {
                    check_cancelled(is_cancelled)?;
                    lowered.push(wir::ParameterType {
                        access: lower_access(parameter.access),
                        ty: wir::TypeId(parameter.ty.0),
                    });
                }
                (
                    copy_text("fn", limits.payload_bytes)?,
                    wir::TypeKind::Function(wir::FunctionType {
                        color: lower_function_color(*color)?,
                        parameters: lowered,
                        result: wir::TypeId(result.0),
                    }),
                )
            }
            sema::SemanticTypeKind::Actor { class } => {
                let _actor = facts
                    .graph
                    .as_ref()
                    .and_then(|graph| {
                        let mut actors = graph.actors.iter().filter(|actor| actor.class == *class);
                        let actor = actors.next()?;
                        actors.next().is_none().then_some(actor.id)
                    })
                    .ok_or_else(|| unsupported("ambiguous image-wired actor capability type"))?;
                (
                    copy_text("__wrela_actor_capability", limits.payload_bytes)?,
                    wir::TypeKind::ActorHandle {
                        actor_type: wir::TypeId(class.0),
                    },
                )
            }
            sema::SemanticTypeKind::Reservation => (
                copy_text("__wrela_actor_reservation", limits.payload_bytes)?,
                wir::TypeKind::Reservation,
            ),
            sema::SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                variants,
            } => {
                let declaration = input
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .filter(|record| {
                        ty.source == Some(record.source)
                            && matches!(record.kind, wrela_hir::DeclarationKind::Enumeration(_))
                    })
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: "closed actor runtime enum".to_owned(),
                        fact: "source declaration",
                    })?;
                let wrela_hir::DeclarationKind::Enumeration(source_enum) = &declaration.kind else {
                    return Err(unsupported(
                        "non-enum source declaration for actor runtime enum",
                    ));
                };
                let specialized_result = !arguments.is_empty()
                    && core_result_source_matches_semantic(
                        input.hir().as_program(),
                        declaration,
                        source_enum,
                        arguments,
                        variants,
                    );
                let specialized_generic_enum = !arguments.is_empty()
                    && generic_enum_source_generics_match(
                        input.hir().as_program(),
                        declaration,
                        source_enum,
                        arguments,
                    );
                if source_enum.variants.len() != variants.len()
                    || if arguments.is_empty() {
                        !source_enum.generics.is_empty()
                    } else {
                        !specialized_result && !specialized_generic_enum
                    }
                {
                    return Err(unsupported(
                        "noncanonical actor runtime enum semantic facts",
                    ));
                }
                let name = declaration
                    .name
                    .as_ref()
                    .ok_or_else(|| unsupported("anonymous actor runtime enums"))?
                    .as_str();
                let mut lowered = try_vec(
                    variants.len(),
                    "SemanticWir actor enum variants",
                    limits.model_edges,
                )?;
                for (variant_index, (variant, source_variant)) in
                    variants.iter().zip(&source_enum.variants).enumerate()
                {
                    check_cancelled(is_cancelled)?;
                    let [field] = variant.fields.as_slice() else {
                        return Err(unsupported("noncanonical actor enum payload shape"));
                    };
                    let [source_field] = source_variant.fields.as_slice() else {
                        return Err(unsupported("noncanonical actor enum source payload shape"));
                    };
                    let source_payload_matches = if specialized_result {
                        source_enum.generics.get(variant_index).is_some_and(|generic| {
                            matches!(&source_field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                                definition: wrela_hir::Definition::Generic(candidate),
                                arguments,
                            } if candidate == generic && arguments.is_empty())
                                && matches!(arguments.as_slice(), [sema::SemanticArgument::Type(payload), _]
                                    if *payload == field.ty)
                        })
                    } else if specialized_generic_enum {
                        generic_enum_source_payload_matches(
                            facts,
                            source_enum,
                            arguments,
                            &source_field.ty,
                            field.ty,
                        )
                    } else {
                        source_type_matches_semantic(facts, &source_field.ty, field.ty)
                    };
                    if variant.name != source_variant.name.as_str()
                        || source_field.name.is_some()
                        || !field.name.is_empty()
                        || !field.public
                        || !source_payload_matches
                    {
                        return Err(unsupported(
                            "actor runtime enum semantic facts differ from source",
                        ));
                    }
                    let mut fields = try_vec(
                        1,
                        "SemanticWir actor enum payload field",
                        limits.model_edges,
                    )?;
                    fields.push(wir::FieldType {
                        name: copy_text(&field.name, limits.payload_bytes)?,
                        ty: wir::TypeId(field.ty.0),
                        public: field.public,
                    });
                    lowered.push(wir::VariantType {
                        name: copy_text(&variant.name, limits.payload_bytes)?,
                        fields,
                    });
                }
                (
                    copy_text(name, limits.payload_bytes)?,
                    wir::TypeKind::Enum { variants: lowered },
                )
            }
            sema::SemanticTypeKind::Class {
                declaration,
                arguments,
                fields,
            } if arguments.is_empty() && fields.is_empty() => {
                let name = input
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .and_then(|declaration| declaration.name.as_ref())
                    .map(wrela_hir::Name::as_str)
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: "actor class type".to_owned(),
                        fact: "source class name",
                    })?;
                (
                    copy_text(name, limits.payload_bytes)?,
                    wir::TypeKind::Struct { fields: Vec::new() },
                )
            }
            _ => {
                return Err(unsupported(
                    "actor types outside the validated scalar subset",
                ));
            }
        };
        output.push(wir::TypeRecord {
            id: wir::TypeId(ty.id.0),
            source_name,
            kind,
            linearity: lower_linearity(ty.linearity),
            source: ty.source,
        });
    }
    Ok(output)
}

fn lower_actor_entry_function(
    actor: &ActorImageFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<wir::SemanticFunction, LowerError> {
    check_cancelled(is_cancelled)?;
    let mut function_proofs = try_vec(
        actor.entry.proofs.len(),
        "SemanticWir actor entry proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(actor.entry.proofs.iter().map(|proof| wir::ProofId(proof.0)));
    let mut statements = try_vec(1, "actor entry statements", limits.operations)?;
    statements.push(wir::SemanticStatement::Return(Vec::new()));
    Ok(wir::SemanticFunction {
        id: wir::FunctionId(actor.entry.id.0),
        instance_key: actor.entry.key.0,
        name: copy_text(&actor.entry.name, limits.payload_bytes)?,
        origin: wir::FunctionOrigin::GeneratedImageEntry {
            constructor: actor.constructor.0,
        },
        role: wir::FunctionRole::ImageEntry,
        color: wir::FunctionColor::Sync,
        parameters: Vec::new(),
        result: wir::TypeId(actor.entry.result.0),
        values: Vec::new(),
        body: wir::SemanticRegion {
            parameters: Vec::new(),
            statements,
        },
        effects: wir::EffectSet(actor.entry.effects.0),
        proofs: function_proofs,
        source: None,
        stack_bound: actor.entry.stack_bytes_bound,
        frame_bound: actor.entry.frame_bytes_bound,
        uninterrupted_bound: actor.entry.uninterrupted_work_bound,
        recursive_depth_bound: actor.entry.recursive_depth_bound,
    })
}

fn lower_actor_instances(
    graph: &sema::ImageGraph,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::ActorInstance>, LowerError> {
    let mut output = try_vec(
        graph.actors.len(),
        "SemanticWir actor instances",
        limits.model_edges,
    )?;
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        let mut message_types = try_vec(
            actor.message_types.len(),
            "SemanticWir actor message types",
            limits.model_edges,
        )?;
        message_types.extend(actor.message_types.iter().map(|ty| wir::TypeId(ty.0)));
        let mut turn_functions = try_vec(
            actor.turn_functions.len(),
            "SemanticWir actor turn functions",
            limits.model_edges,
        )?;
        turn_functions.extend(
            actor
                .turn_functions
                .iter()
                .map(|function| wir::FunctionId(function.0)),
        );
        output.push(wir::ActorInstance {
            id: wir::ActorId(actor.id.0),
            name: copy_text(&actor.name, limits.payload_bytes)?,
            ty: wir::TypeId(actor.class.0),
            priority: actor.priority,
            mailbox_capacity: actor.mailbox_capacity,
            message_types,
            turn_functions,
            supervisor: actor.supervisor.map(|actor| wir::ActorId(actor.0)),
        });
    }
    Ok(output)
}

fn lower_task_instances(
    graph: &sema::ImageGraph,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::TaskInstance>, LowerError> {
    let mut output = try_vec(
        graph.tasks.len(),
        "SemanticWir task instances",
        limits.model_edges,
    )?;
    for task in &graph.tasks {
        check_cancelled(is_cancelled)?;
        output.push(wir::TaskInstance {
            id: wir::TaskId(task.id.0),
            name: copy_text(&task.name, limits.payload_bytes)?,
            entry: wir::FunctionId(task.entry.0),
            slots: task.slots,
            priority: task.priority,
            supervisor: task.supervisor.map(|actor| wir::ActorId(actor.0)),
        });
    }
    Ok(output)
}

fn lower_actor_regions(
    graph: &sema::ImageGraph,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::RegionRecord>, LowerError> {
    let mut output = try_vec(
        graph.regions.len(),
        "SemanticWir actor regions",
        limits.model_edges,
    )?;
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        output.push(wir::RegionRecord {
            id: wir::RegionId(region.id.0),
            name: copy_text(&region.name, limits.payload_bytes)?,
            class: lower_region_class(region.class),
            capacity_bytes: region.capacity_bytes,
            alignment: u64::from(region.alignment),
            owner: lower_owner(region.owner),
            proof: wir::ProofId(region.proof.0),
            source: region.source,
        });
    }
    Ok(output)
}

#[derive(Debug, Clone)]
struct PendingActivation {
    caller: wir::FunctionId,
    callee: wir::FunctionId,
    statement: usize,
    owner: wir::ImageOwner,
    frame_bytes: u64,
    cleanup_proof: wir::ProofId,
    source: Span,
}

const ACTIVATION_REGION_SUFFIX: &str = ".async-activation-frame";
const BASE_CAPACITY_SUBJECT: &str = "closed actor base allocation";
const BASE_CAPACITY_EXPLANATION: &str = "the analyzer-provided bound covers mailboxes and root actor/task frames; call-site helper frames are admitted by the following activation proofs";
const ACTIVATION_CAPACITY_SUBJECT: &str = "statically admitted async helper activation";
const ACTIVATION_CAPACITY_EXPLANATION: &str = "the immediate await owns exactly one complete callee frame; cancellation drops that frame before propagating to the retained caller";
const ACTIVATION_IMAGE_SUBJECT: &str = "closed actor image with async activations";
const ACTIVATION_IMAGE_EXPLANATION: &str = "the complete static bound includes every mailbox, root frame, and source-linked async helper activation region";

struct ActorActivationOutput<'a> {
    types: &'a [wir::TypeRecord],
    functions: &'a mut [wir::SemanticFunction],
    actors: &'a [wir::ActorInstance],
    tasks: &'a [wir::TaskInstance],
    regions: &'a mut Vec<wir::RegionRecord>,
    proofs: &'a mut Vec<wir::ProofRecord>,
    image_name: &'a str,
    startup_order: usize,
    shutdown_order: usize,
}

fn lower_actor_activations(
    output: ActorActivationOutput<'_>,
    base_static_bytes: u64,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<wir::ActivationPlan>, u64, Option<wir::ProofId>), LowerError> {
    let ActorActivationOutput {
        types,
        functions,
        actors,
        tasks,
        regions,
        proofs,
        image_name,
        startup_order,
        shutdown_order,
    } = output;
    let mut pending = try_vec(
        functions.len(),
        "SemanticWir actor activation sites",
        limits.model_edges,
    )?;
    for function in functions.iter() {
        check_cancelled(is_cancelled)?;
        let owner = match function.role {
            wir::FunctionRole::ActorTurn(actor) => Some(wir::ImageOwner::Actor(actor)),
            wir::FunctionRole::TaskEntry(task)
                if tasks
                    .get(task.0 as usize)
                    .is_some_and(|task| task.slots == 1) =>
            {
                Some(wir::ImageOwner::Task(task))
            }
            wir::FunctionRole::TaskEntry(_) => None,
            wir::FunctionRole::Ordinary
            | wir::FunctionRole::Isr(_)
            | wir::FunctionRole::Cleanup
            | wir::FunctionRole::ImageEntry
            | wir::FunctionRole::Test => None,
        };
        let mut nested = try_vec(1, "SemanticWir actor activation scan", limits.model_edges)?;
        nested.push((&function.body, true));
        while let Some((region, is_root)) = nested.pop() {
            check_cancelled(is_cancelled)?;
            for (statement_index, statement) in region.statements.iter().enumerate() {
                check_cancelled(is_cancelled)?;
                match statement {
                    wir::SemanticStatement::Let(wir::LetStatement {
                        operation:
                            wir::SemanticOperation::Call {
                                function: callee,
                                activation,
                                ..
                            },
                        source,
                        ..
                    }) if functions
                        .get(callee.0 as usize)
                        .is_some_and(|callee| callee.color == wir::FunctionColor::Async) =>
                    {
                        if !is_root || activation.is_some() {
                            return Err(unsupported(
                                "nested or preplanned async actor activation sites",
                            ));
                        }
                        let source = source.ok_or(unsupported(
                            "async actor activation without source provenance",
                        ))?;
                        let owner = owner.ok_or(unsupported(
                            "async helper calls outside actor turns and static tasks",
                        ))?;
                        let callee_function = functions
                            .get(callee.0 as usize)
                            .filter(|callee| {
                                callee.role == wir::FunctionRole::Ordinary
                                    && callee.color == wir::FunctionColor::Async
                            })
                            .ok_or(unsupported("async actor activation callee"))?;
                        let mut cleanup = callee_function.proofs.iter().filter(|proof| {
                            proofs.get(proof.0 as usize).is_some_and(|record| {
                                record.id == **proof
                                    && record.kind == wir::ProofKind::CleanupAcyclic
                            })
                        });
                        let cleanup_proof = *cleanup
                            .next()
                            .ok_or(unsupported("async actor activation cleanup proof"))?;
                        if cleanup.next().is_some() {
                            return Err(unsupported(
                                "multiple async actor activation cleanup proofs",
                            ));
                        }
                        if pending
                            .last()
                            .is_some_and(|prior: &PendingActivation| prior.caller == function.id)
                        {
                            return Err(unsupported(
                                "multiple async helper activations in one actor function",
                            ));
                        }
                        push_pending_activation(
                            &mut pending,
                            PendingActivation {
                                caller: function.id,
                                callee: *callee,
                                statement: statement_index,
                                owner,
                                frame_bytes: callee_function.frame_bound.max(1),
                                cleanup_proof,
                                source,
                            },
                            limits.model_edges,
                        )?;
                    }
                    wir::SemanticStatement::If {
                        then_region,
                        else_region,
                        ..
                    } => {
                        push_region_scan(&mut nested, (else_region, false), limits.model_edges)?;
                        push_region_scan(&mut nested, (then_region, false), limits.model_edges)?;
                    }
                    wir::SemanticStatement::Match { arms, .. } => {
                        for arm in arms.iter().rev() {
                            check_cancelled(is_cancelled)?;
                            push_region_scan(&mut nested, (&arm.body, false), limits.model_edges)?;
                        }
                    }
                    wir::SemanticStatement::Loop { body, .. } => {
                        push_region_scan(&mut nested, (body, false), limits.model_edges)?
                    }
                    wir::SemanticStatement::Let(_)
                    | wir::SemanticStatement::Return(_)
                    | wir::SemanticStatement::Yield(_)
                    | wir::SemanticStatement::Break(_)
                    | wir::SemanticStatement::Continue(_)
                    | wir::SemanticStatement::Unreachable => {}
                }
            }
        }
    }
    if pending.is_empty() {
        return Ok((Vec::new(), 0, None));
    }

    let activation_count = pending.len();
    let activation_proof_count =
        activation_count
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation expansion",
                limit: limits.model_edges,
            })?;
    let final_dependency_count =
        activation_count
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation expansion",
                limit: limits.model_edges,
            })?;
    let future_proofs =
        proofs
            .len()
            .checked_add(activation_proof_count)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation proofs",
                limit: limits.model_edges,
            })?;
    let future_regions =
        regions
            .len()
            .checked_add(activation_count)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation regions",
                limit: limits.model_edges,
            })?;
    check_count(
        "SemanticWir actor activation proofs",
        future_proofs,
        limits.model_edges,
    )?;
    check_count(
        "SemanticWir actor activation regions",
        future_regions,
        limits.model_edges,
    )?;
    let mut base_closed_index = None;
    for (index, proof) in proofs.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if proof.kind == wir::ProofKind::ImageClosed {
            if base_closed_index.is_some() {
                return Err(unsupported("actor base closed-image proof substitution"));
            }
            base_closed_index = Some(index);
        }
    }
    let base_closed_index =
        base_closed_index.ok_or(unsupported("actor base closed-image proof"))?;
    let base_closed = proofs
        .get(base_closed_index)
        .ok_or(unsupported("actor base closed-image proof"))?;
    if base_closed.bound != Some(base_static_bytes) {
        return Err(unsupported("actor base closed-image proof substitution"));
    }
    let base_closed_id = base_closed.id;
    validate_actor_activation_expansion_resources(
        SemanticResourceView {
            name: image_name,
            types,
            globals: &[],
            functions,
            actors,
            tasks,
            devices: &[],
            pools: &[],
            regions,
            activations: &[],
            scopes: &[],
            proofs,
            tests: &[],
            compiled_test_group: None,
            startup_order,
            shutdown_order,
        },
        &pending,
        base_closed,
        limits,
        is_cancelled,
    )?;
    let base_closed = proofs
        .get_mut(base_closed_index)
        .ok_or(unsupported("actor base closed-image proof"))?;
    base_closed.kind = wir::ProofKind::CapacityBound;
    base_closed.subject = copy_text(BASE_CAPACITY_SUBJECT, limits.payload_bytes)?;
    base_closed.explanation = bounded_singleton_text(BASE_CAPACITY_EXPLANATION, limits)?;

    let mut activations = try_vec(
        activation_count,
        "SemanticWir actor activation plans",
        limits.model_edges,
    )?;
    let mut activation_bytes = 0_u64;
    let mut final_dependencies = try_vec(
        final_dependency_count,
        "SemanticWir actor activation proof dependencies",
        limits.model_edges,
    )?;
    final_dependencies.push(base_closed_id);
    let mut final_sources = try_vec(
        activation_count,
        "SemanticWir actor activation proof sources",
        limits.model_edges,
    )?;
    let mut prior_key = None;
    for site in pending {
        check_cancelled(is_cancelled)?;
        let key = (
            site.caller.0,
            site.source.file.0,
            site.source.range.start,
            site.source.range.end,
            site.callee.0,
        );
        if prior_key.is_some_and(|prior| prior >= key) {
            return Err(unsupported("noncanonical actor activation source order"));
        }
        prior_key = Some(key);
        let id = wir::ActivationId(u32::try_from(activations.len()).map_err(|_| {
            LowerError::ResourceLimit {
                resource: "SemanticWir actor activation plans",
                limit: limits.model_edges,
            }
        })?);
        let proof =
            wir::ProofId(
                u32::try_from(proofs.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "SemanticWir actor activation proofs",
                    limit: limits.model_edges,
                })?,
            );
        let region =
            wir::RegionId(
                u32::try_from(regions.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "SemanticWir actor activation regions",
                    limit: limits.model_edges,
                })?,
            );
        let caller_name = functions
            .get(site.caller.0 as usize)
            .filter(|function| function.id == site.caller)
            .ok_or(unsupported("actor activation caller identity"))?
            .name
            .as_str();
        let region_name = bounded_text_pair(
            caller_name,
            ACTIVATION_REGION_SUFFIX,
            limits.payload_bytes,
            is_cancelled,
        )?;
        let caller = functions
            .get_mut(site.caller.0 as usize)
            .filter(|function| function.id == site.caller)
            .ok_or(unsupported("actor activation caller identity"))?;
        let call = caller
            .body
            .statements
            .get_mut(site.statement)
            .and_then(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation:
                        wir::SemanticOperation::Call {
                            function,
                            activation,
                            ..
                        },
                    source: Some(source),
                    ..
                }) if *function == site.callee && *source == site.source => Some(activation),
                _ => None,
            })
            .ok_or(unsupported("actor activation call-site substitution"))?;
        *call = Some(id);
        push_bounded_proof(&mut caller.proofs, proof, limits.model_edges)?;

        let mut proof_sources = try_vec(
            1,
            "SemanticWir actor activation proof sources",
            limits.model_edges,
        )?;
        proof_sources.push(site.source);
        let mut proof_dependencies = try_vec(
            1,
            "SemanticWir actor activation proof dependencies",
            limits.model_edges,
        )?;
        proof_dependencies.push(site.cleanup_proof);
        proofs
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir actor activation proofs",
                limit: limits.model_edges,
            })?;
        proofs.push(wir::ProofRecord {
            id: proof,
            kind: wir::ProofKind::CapacityBound,
            subject: copy_text(ACTIVATION_CAPACITY_SUBJECT, limits.payload_bytes)?,
            bound: Some(1),
            sources: proof_sources,
            depends_on: proof_dependencies,
            explanation: bounded_singleton_text(ACTIVATION_CAPACITY_EXPLANATION, limits)?,
        });
        regions
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir actor activation regions",
                limit: limits.model_edges,
            })?;
        regions.push(wir::RegionRecord {
            id: region,
            name: region_name,
            class: wir::RegionClass::TaskFrame,
            capacity_bytes: site.frame_bytes,
            alignment: 8,
            owner: site.owner,
            proof,
            source: site.source,
        });
        activations.push(wir::ActivationPlan {
            id,
            caller: site.caller,
            callee: site.callee,
            region,
            frame_bytes: site.frame_bytes,
            maximum_live: 1,
            cancellation: wir::ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: proof,
            source: site.source,
        });
        activation_bytes =
            activation_bytes
                .checked_add(site.frame_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "SemanticWir actor activation bytes",
                    limit: limits.model_edges,
                })?;
        final_dependencies.push(proof);
        final_sources.push(site.source);
    }

    let total_static =
        base_static_bytes
            .checked_add(activation_bytes)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor static bytes",
                limit: limits.model_edges,
            })?;
    let image_closed =
        wir::ProofId(
            u32::try_from(proofs.len()).map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir actor activation proofs",
                limit: limits.model_edges,
            })?,
        );
    proofs
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir actor activation proofs",
            limit: limits.model_edges,
        })?;
    proofs.push(wir::ProofRecord {
        id: image_closed,
        kind: wir::ProofKind::ImageClosed,
        subject: copy_text(ACTIVATION_IMAGE_SUBJECT, limits.payload_bytes)?,
        bound: Some(total_static),
        sources: final_sources,
        depends_on: final_dependencies,
        explanation: bounded_singleton_text(ACTIVATION_IMAGE_EXPLANATION, limits)?,
    });
    Ok((activations, activation_bytes, Some(image_closed)))
}

fn validate_actor_activation_expansion_resources(
    base: SemanticResourceView<'_>,
    pending: &[PendingActivation],
    base_closed: &wir::ProofRecord,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut meter = measure_model_resources(base, limits, is_cancelled)?;
    let old_explanation_edges =
        u64::try_from(base_closed.explanation.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir actor activation expansion",
            limit: limits.model_edges,
        })?;
    meter.edges =
        meter
            .edges
            .checked_sub(old_explanation_edges)
            .ok_or(LowerError::InternalInvariant(
                "base proof explanation was absent from its resource meter".to_owned(),
            ))?;
    meter.add_edges(1);
    let mut old_payload = base_closed.subject.len();
    for line in &base_closed.explanation {
        check_cancelled(is_cancelled)?;
        old_payload = old_payload
            .checked_add(line.len())
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation expansion",
                limit: limits.payload_bytes,
            })?;
    }
    meter.payload_bytes = meter
        .payload_bytes
        .checked_sub(
            u64::try_from(old_payload).map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir actor activation expansion",
                limit: limits.payload_bytes,
            })?,
        )
        .ok_or(LowerError::InternalInvariant(
            "base proof text was absent from its resource meter".to_owned(),
        ))?;
    meter.add_payload(BASE_CAPACITY_SUBJECT.len());
    meter.add_payload(BASE_CAPACITY_EXPLANATION.len());

    let activation_count = pending.len();
    let proof_count = activation_count
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation expansion",
            limit: limits.model_edges,
        })?;
    let final_dependencies = activation_count
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation expansion",
            limit: limits.model_edges,
        })?;
    for count in [
        activation_count, // regions
        activation_count, // activation plans
        proof_count,      // capacity proofs plus final closure
        activation_count, // caller proof attachments
        1,                // final closure attachment on the image entry
        activation_count, // capacity-proof sources
        activation_count, // capacity-proof cleanup dependencies
        activation_count, // capacity-proof explanations
        activation_count, // final-closure sources
        final_dependencies,
        1, // final-closure explanation
    ] {
        meter.add_edges(count);
    }
    for site in pending {
        check_cancelled(is_cancelled)?;
        let caller = base
            .functions
            .get(site.caller.0 as usize)
            .filter(|function| function.id == site.caller)
            .ok_or(unsupported("actor activation caller identity"))?;
        let region_name_bytes = caller
            .name
            .len()
            .checked_add(ACTIVATION_REGION_SUFFIX.len())
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir actor activation expansion",
                limit: limits.payload_bytes,
            })?;
        meter.add_payload(region_name_bytes);
        meter.add_payload(ACTIVATION_CAPACITY_SUBJECT.len());
        meter.add_payload(ACTIVATION_CAPACITY_EXPLANATION.len());
    }
    meter.add_payload(ACTIVATION_IMAGE_SUBJECT.len());
    meter.add_payload(ACTIVATION_IMAGE_EXPLANATION.len());

    if meter.overflowed || meter.edges > limits.model_edges {
        return Err(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation expansion",
            limit: limits.model_edges,
        });
    }
    if meter.payload_bytes > limits.payload_bytes {
        return Err(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation expansion",
            limit: limits.payload_bytes,
        });
    }
    check_cancelled(is_cancelled)
}

fn push_pending_activation(
    output: &mut Vec<PendingActivation>,
    value: PendingActivation,
    limit: u64,
) -> Result<(), LowerError> {
    let count = output
        .len()
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation sites",
            limit,
        })?;
    check_count("SemanticWir actor activation sites", count, limit)?;
    output
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir actor activation sites",
            limit,
        })?;
    output.push(value);
    Ok(())
}

fn push_region_scan<'a>(
    output: &mut Vec<(&'a wir::SemanticRegion, bool)>,
    value: (&'a wir::SemanticRegion, bool),
    limit: u64,
) -> Result<(), LowerError> {
    let count = output
        .len()
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir actor activation scan",
            limit,
        })?;
    check_count("SemanticWir actor activation scan", count, limit)?;
    output
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir actor activation scan",
            limit,
        })?;
    output.push(value);
    Ok(())
}

fn push_bounded_proof(
    output: &mut Vec<wir::ProofId>,
    value: wir::ProofId,
    limit: u64,
) -> Result<(), LowerError> {
    let count = output
        .len()
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir function proofs",
            limit,
        })?;
    check_count("SemanticWir function proofs", count, limit)?;
    output
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir function proofs",
            limit,
        })?;
    output.push(value);
    Ok(())
}

fn bounded_singleton_text(value: &str, limits: LoweringLimits) -> Result<Vec<String>, LowerError> {
    let mut output = try_vec(1, "SemanticWir proof explanations", limits.model_edges)?;
    output.push(copy_text(value, limits.payload_bytes)?);
    Ok(output)
}

fn bounded_text_pair(
    left: &str,
    right: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, LowerError> {
    let length = left
        .len()
        .checked_add(right.len())
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir payload bytes",
            limit,
        })?;
    check_count("SemanticWir payload bytes", length, limit)?;
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir payload bytes",
            limit,
        })?;
    let mut bytes_since_poll = 0_usize;
    for character in left.chars() {
        if bytes_since_poll >= 4096 {
            check_cancelled(is_cancelled)?;
            bytes_since_poll = 0;
        }
        output.push(character);
        bytes_since_poll = bytes_since_poll.saturating_add(character.len_utf8());
    }
    check_cancelled(is_cancelled)?;
    output.push_str(right);
    Ok(output)
}

fn lower_region_class(class: sema::RegionClass) -> wir::RegionClass {
    match class {
        sema::RegionClass::Image => wir::RegionClass::Image,
        sema::RegionClass::Call => wir::RegionClass::Call,
        sema::RegionClass::TaskFrame => wir::RegionClass::TaskFrame,
        sema::RegionClass::Request => wir::RegionClass::Request,
        sema::RegionClass::Pool(pool) => wir::RegionClass::Pool(wir::PoolId(pool.0)),
        sema::RegionClass::Static => wir::RegionClass::Static,
    }
}

fn actor_reachable_declarations(
    actor: &ActorImageFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, LowerError> {
    let capacity = actor
        .facts
        .functions
        .len()
        .checked_add(actor.facts.types.len())
        .and_then(|count| count.checked_add(actor.facts.scope_protocols.len()))
        .and_then(|count| count.checked_add(1))
        .ok_or(LowerError::ResourceLimit {
            resource: "actor reachable declarations",
            limit: limits.model_edges,
        })?;
    let mut declarations = try_vec(capacity, "actor reachable declarations", limits.model_edges)?;
    declarations.push(actor.constructor);
    for function in &actor.facts.functions {
        check_cancelled(is_cancelled)?;
        if let sema::FunctionOrigin::Source { declaration, .. } = function.origin {
            declarations.push(declaration);
        }
    }
    for ty in &actor.facts.types {
        check_cancelled(is_cancelled)?;
        if let sema::SemanticTypeKind::Class { declaration, .. } = ty.kind {
            declarations.push(declaration);
        }
    }
    for protocol in &actor.facts.scope_protocols {
        check_cancelled(is_cancelled)?;
        declarations.push(protocol.declaration);
    }
    cancellable_sort(
        &mut declarations,
        "actor reachable declarations",
        limits.model_edges,
        is_cancelled,
    )?;
    cancellable_dedup(&mut declarations, is_cancelled)?;
    u64::try_from(declarations.len()).map_err(|_| LowerError::ResourceLimit {
        resource: "actor reachable declarations",
        limit: limits.model_edges,
    })
}

struct EncodedHarness {
    frames: Vec<Vec<u8>>,
    frame_types: Vec<(usize, wir::TypeId)>,
    outcome_type: wir::TypeId,
}

fn lower_source_types(
    input: &AnalyzedImage,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::TypeRecord>, LowerError> {
    let facts = input.facts();
    let mut output = try_vec(
        facts.types.len(),
        "SemanticWir types",
        u64::from(limits.types),
    )?;
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        let (source_name, kind) = match &ty.kind {
            sema::SemanticTypeKind::Unit => {
                ("unit", wir::TypeKind::Primitive(wir::PrimitiveType::Unit))
            }
            sema::SemanticTypeKind::Bool => {
                ("bool", wir::TypeKind::Primitive(wir::PrimitiveType::Bool))
            }
            sema::SemanticTypeKind::Integer {
                signed,
                bits,
                pointer_sized,
            } => lower_integer_type(*signed, *bits, *pointer_sized)?,
            sema::SemanticTypeKind::Float { bits: 32 } => {
                ("f32", wir::TypeKind::Primitive(wir::PrimitiveType::F32))
            }
            sema::SemanticTypeKind::Float { bits: 64 } => {
                ("f64", wir::TypeKind::Primitive(wir::PrimitiveType::F64))
            }
            sema::SemanticTypeKind::Structure {
                declaration,
                arguments,
                fields,
            } => {
                let declaration = input
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .filter(|record| {
                        ty.source == Some(record.source)
                            && matches!(record.kind, wrela_hir::DeclarationKind::Structure(_))
                    })
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: "flat runtime structure".to_owned(),
                        fact: "source declaration",
                    })?;
                let wrela_hir::DeclarationKind::Structure(source_structure) = &declaration.kind
                else {
                    return Err(unsupported(
                        "non-structure source declaration for runtime structure",
                    ));
                };
                if !generic_structure_source_generics_match(
                    input.hir().as_program(),
                    declaration,
                    source_structure,
                    arguments,
                ) {
                    return Err(unsupported(
                        "semantic-generic-structure-parameter-lowering-pending (const, bounded, or unauthenticated specialization)",
                    ));
                }
                if !source_structure.implements.is_empty()
                    || source_structure.fields.len() != fields.len()
                {
                    return Err(unsupported("noncanonical runtime structure semantic facts"));
                }
                let name = declaration
                    .name
                    .as_ref()
                    .ok_or_else(|| unsupported("anonymous flat runtime structures"))?
                    .as_str();
                let mut lowered = try_vec(
                    fields.len(),
                    "SemanticWir structure fields",
                    limits.model_edges,
                )?;
                for (field, source_field) in fields.iter().zip(&source_structure.fields) {
                    check_cancelled(is_cancelled)?;
                    if field.name != source_field.name.as_str()
                        || field.public
                            != (source_field.visibility != wrela_hir::Visibility::Private)
                        || source_field.default.is_some()
                        || !source_field.attributes.is_empty()
                        || !generic_structure_source_field_matches(
                            facts,
                            source_structure,
                            arguments,
                            &source_field.ty,
                            field.ty,
                        )
                    {
                        return Err(unsupported(
                            "runtime structure semantic facts differ from source",
                        ));
                    }
                    lowered.push(wir::FieldType {
                        name: copy_text(&field.name, limits.payload_bytes)?,
                        ty: wir::TypeId(field.ty.0),
                        public: field.public,
                    });
                }
                (name, wir::TypeKind::Struct { fields: lowered })
            }
            sema::SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                variants,
            } => {
                let declaration = input
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .filter(|record| {
                        ty.source == Some(record.source)
                            && matches!(record.kind, wrela_hir::DeclarationKind::Enumeration(_))
                    })
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: "closed runtime enum".to_owned(),
                        fact: "source declaration",
                    })?;
                let wrela_hir::DeclarationKind::Enumeration(source_enum) = &declaration.kind else {
                    return Err(unsupported("non-enum source declaration for runtime enum"));
                };
                let specialized_result = !arguments.is_empty()
                    && core_result_source_matches_semantic(
                        input.hir().as_program(),
                        declaration,
                        source_enum,
                        arguments,
                        variants,
                    );
                let specialized_generic_enum = !arguments.is_empty()
                    && generic_enum_source_generics_match(
                        input.hir().as_program(),
                        declaration,
                        source_enum,
                        arguments,
                    );
                if source_enum.variants.len() != variants.len()
                    || ty.source != Some(declaration.source)
                    || if arguments.is_empty() {
                        !source_enum.generics.is_empty()
                    } else {
                        !specialized_result && !specialized_generic_enum
                    }
                {
                    return Err(unsupported("noncanonical runtime enum semantic facts"));
                }
                let name = declaration
                    .name
                    .as_ref()
                    .ok_or_else(|| unsupported("anonymous closed runtime enums"))?
                    .as_str();
                let mut lowered = try_vec(
                    variants.len(),
                    "SemanticWir enum variants",
                    limits.model_edges,
                )?;
                for (variant_index, (variant, source_variant)) in
                    variants.iter().zip(&source_enum.variants).enumerate()
                {
                    check_cancelled(is_cancelled)?;
                    let [field] = variant.fields.as_slice() else {
                        return Err(unsupported("noncanonical enum payload shape"));
                    };
                    let [source_field] = source_variant.fields.as_slice() else {
                        return Err(unsupported("noncanonical enum source payload shape"));
                    };
                    let source_payload_matches = if specialized_result {
                        source_enum.generics.get(variant_index).is_some_and(|generic| {
                            matches!(&source_field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                                definition: wrela_hir::Definition::Generic(candidate),
                                arguments,
                            } if candidate == generic && arguments.is_empty())
                                && matches!(arguments.as_slice(), [sema::SemanticArgument::Type(payload), _]
                                    if *payload == field.ty)
                        })
                    } else if specialized_generic_enum {
                        generic_enum_source_payload_matches(
                            facts,
                            source_enum,
                            arguments,
                            &source_field.ty,
                            field.ty,
                        )
                    } else {
                        source_type_matches_semantic(facts, &source_field.ty, field.ty)
                    };
                    if variant.name != source_variant.name.as_str()
                        || source_field.name.is_some()
                        || !field.name.is_empty()
                        || !field.public
                        || !source_payload_matches
                    {
                        return Err(unsupported(
                            "runtime enum semantic facts differ from source",
                        ));
                    }
                    let mut fields =
                        try_vec(1, "SemanticWir enum payload field", limits.model_edges)?;
                    fields.push(wir::FieldType {
                        name: copy_text(&field.name, limits.payload_bytes)?,
                        ty: wir::TypeId(field.ty.0),
                        public: field.public,
                    });
                    lowered.push(wir::VariantType {
                        name: copy_text(&variant.name, limits.payload_bytes)?,
                        fields,
                    });
                }
                (name, wir::TypeKind::Enum { variants: lowered })
            }
            sema::SemanticTypeKind::Function {
                color,
                parameters,
                result,
            } => {
                let mut lowered = try_vec(
                    parameters.len(),
                    "SemanticWir function type parameters",
                    limits.model_edges,
                )?;
                for parameter in parameters {
                    check_cancelled(is_cancelled)?;
                    lowered.push(wir::ParameterType {
                        access: lower_access(parameter.access),
                        ty: wir::TypeId(parameter.ty.0),
                    });
                }
                (
                    "fn",
                    wir::TypeKind::Function(wir::FunctionType {
                        color: lower_function_color(*color)?,
                        parameters: lowered,
                        result: wir::TypeId(result.0),
                    }),
                )
            }
            _ => {
                return Err(unsupported(
                    "source semantic types outside the scalar or flat-structure subset",
                ));
            }
        };
        output.push(wir::TypeRecord {
            id: wir::TypeId(ty.id.0),
            source_name: copy_text(source_name, limits.payload_bytes)?,
            kind,
            linearity: lower_linearity(ty.linearity),
            source: ty.source,
        });
    }
    Ok(output)
}

fn core_result_source_matches_semantic(
    program: &wrela_hir::Program,
    declaration: &wrela_hir::Declaration,
    source_enum: &wrela_hir::EnumDeclaration,
    arguments: &[sema::SemanticArgument],
    variants: &[sema::SemanticVariant],
) -> bool {
    let core_package = program
        .packages
        .package(program.packages.root())
        .and_then(|root| {
            root.dependencies
                .iter()
                .find(|dependency| dependency.alias.as_str() == "core")
                .map(|dependency| dependency.package)
        });
    declaration.visibility == wrela_hir::Visibility::Public
        && declaration
            .name
            .as_ref()
            .is_some_and(|name| name.as_str() == "Result")
        && program
            .modules
            .get(declaration.module.0 as usize)
            .is_some_and(|module| {
                Some(module.package) == core_package && module.path.dotted() == "result"
            })
        && matches!(source_enum.generics.as_slice(), [ok_generic, err_generic]
        if program.generic_parameter(*ok_generic).is_some_and(|generic| {
            matches!(generic.kind, wrela_hir::GenericParameterKind::Type { .. })
        }) && program.generic_parameter(*err_generic).is_some_and(|generic| {
            matches!(generic.kind, wrela_hir::GenericParameterKind::Type { .. })
        }))
        && matches!(source_enum.variants.as_slice(), [ok, err]
            if exact_core_result_source_variant(ok, "Ok", source_enum.generics[0])
                && exact_core_result_source_variant(err, "Err", source_enum.generics[1]))
        && supported_core_result_arguments(arguments, variants)
}

fn generic_enum_source_generics_match(
    program: &wrela_hir::Program,
    declaration: &wrela_hir::Declaration,
    source_enum: &wrela_hir::EnumDeclaration,
    arguments: &[sema::SemanticArgument],
) -> bool {
    !arguments.is_empty()
        && source_enum.generics.len() == arguments.len()
        && source_enum
            .generics
            .iter()
            .zip(arguments)
            .all(|(generic, argument)| {
                matches!(argument, sema::SemanticArgument::Type(_))
                    && program.generic_parameter(*generic).is_some_and(|record| {
                        record.owner == declaration.id
                            && matches!(
                                record.kind,
                                wrela_hir::GenericParameterKind::Type { bound: None }
                            )
                    })
            })
}

fn generic_structure_source_generics_match(
    program: &wrela_hir::Program,
    declaration: &wrela_hir::Declaration,
    source: &wrela_hir::AggregateDeclaration,
    arguments: &[sema::SemanticArgument],
) -> bool {
    source.generics.len() == arguments.len()
        && source
            .generics
            .iter()
            .zip(arguments)
            .all(|(generic, argument)| {
                matches!(argument, sema::SemanticArgument::Type(_))
                    && program.generic_parameter(*generic).is_some_and(|record| {
                        record.owner == declaration.id
                            && matches!(
                                record.kind,
                                wrela_hir::GenericParameterKind::Type { bound: None }
                            )
                    })
            })
}

fn generic_structure_source_field_matches(
    facts: &sema::PartialAnalysis,
    source_structure: &wrela_hir::AggregateDeclaration,
    arguments: &[sema::SemanticArgument],
    source: &wrela_hir::TypeExpression,
    ty: sema::SemanticTypeId,
) -> bool {
    match &source.kind {
        wrela_hir::TypeExpressionKind::Named {
            definition: wrela_hir::Definition::Generic(candidate),
            arguments: nested,
        } if nested.is_empty() => source_structure
            .generics
            .iter()
            .position(|generic| generic == candidate)
            .and_then(|index| arguments.get(index))
            .is_some_and(|argument| {
                matches!(argument, sema::SemanticArgument::Type(argument) if *argument == ty)
            }),
        _ => source_type_matches_semantic(facts, source, ty),
    }
}

fn generic_function_source_type_matches(
    facts: &sema::PartialAnalysis,
    source_function: &wrela_hir::FunctionDeclaration,
    arguments: &[sema::SemanticArgument],
    source: &wrela_hir::TypeExpression,
) -> Option<sema::SemanticTypeId> {
    match &source.kind {
        wrela_hir::TypeExpressionKind::Named {
            definition: wrela_hir::Definition::Generic(candidate),
            arguments: nested,
        } if nested.is_empty() => source_function
            .generics
            .iter()
            .position(|generic| generic == candidate)
            .and_then(|index| arguments.get(index))
            .and_then(|argument| match argument {
                sema::SemanticArgument::Type(argument) => Some(*argument),
                sema::SemanticArgument::Constant(_) | sema::SemanticArgument::Region(_) => None,
            }),
        _ => facts
            .types
            .iter()
            .find(|semantic| source_type_matches_semantic(facts, source, semantic.id))
            .map(|semantic| semantic.id),
    }
}

fn is_stored_copy_scalar(facts: &sema::PartialAnalysis, ty: sema::SemanticTypeId) -> bool {
    facts.types.get(ty.0 as usize).is_some_and(|record| {
        record.linearity == sema::Linearity::ScalarCopy
            && matches!(
                record.kind,
                sema::SemanticTypeKind::Bool
                    | sema::SemanticTypeKind::Integer { .. }
                    | sema::SemanticTypeKind::Float { bits: 32 | 64 }
            )
    })
}

fn canonical_flat_structure_layout(
    facts: &sema::PartialAnalysis,
    fields: &[sema::SemanticField],
) -> Option<(u64, u32)> {
    let mut size = 0_u64;
    let mut alignment = 1_u32;
    for field in fields {
        let record = facts.types.get(field.ty.0 as usize)?;
        if !is_stored_copy_scalar(facts, field.ty) {
            return None;
        }
        let field_size = record.size_upper_bound?;
        let field_alignment = record.alignment_lower_bound;
        let mask = u64::from(field_alignment).checked_sub(1)?;
        size = size
            .checked_add(mask)
            .map(|value| value & !mask)?
            .checked_add(field_size)?;
        alignment = alignment.max(field_alignment);
    }
    let mask = u64::from(alignment).checked_sub(1)?;
    size = size.checked_add(mask).map(|value| value & !mask)?;
    Some((size, alignment))
}

fn generic_enum_source_payload_matches(
    facts: &sema::PartialAnalysis,
    source_enum: &wrela_hir::EnumDeclaration,
    arguments: &[sema::SemanticArgument],
    source: &wrela_hir::TypeExpression,
    ty: sema::SemanticTypeId,
) -> bool {
    match &source.kind {
        wrela_hir::TypeExpressionKind::Named {
            definition: wrela_hir::Definition::Generic(candidate),
            arguments: nested,
        } if nested.is_empty() => source_enum
            .generics
            .iter()
            .position(|generic| generic == candidate)
            .and_then(|index| arguments.get(index))
            .is_some_and(|argument| {
                matches!(argument, sema::SemanticArgument::Type(argument) if *argument == ty)
            }),
        _ => source_type_matches_semantic(facts, source, ty),
    }
}

fn exact_core_result_source_variant(
    variant: &wrela_hir::EnumVariant,
    name: &str,
    generic: wrela_hir::GenericParameterId,
) -> bool {
    variant.name.as_str() == name
        && matches!(variant.fields.as_slice(), [field]
            if field.name.is_none()
                && matches!(&field.ty.kind, wrela_hir::TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Generic(candidate),
                    arguments,
                } if *candidate == generic && arguments.is_empty()))
}

fn lower_integer_type(
    signed: bool,
    bits: u16,
    pointer_sized: bool,
) -> Result<(&'static str, wir::TypeKind), LowerError> {
    let (name, primitive) = match (signed, bits, pointer_sized) {
        (false, 64, true) => ("usize", wir::PrimitiveType::Usize),
        (true, 64, true) => ("isize", wir::PrimitiveType::Isize),
        (false, 8, false) => ("u8", wir::PrimitiveType::U8),
        (false, 16, false) => ("u16", wir::PrimitiveType::U16),
        (false, 32, false) => ("u32", wir::PrimitiveType::U32),
        (false, 64, false) => ("u64", wir::PrimitiveType::U64),
        (false, 128, false) => ("u128", wir::PrimitiveType::U128),
        (true, 8, false) => ("i8", wir::PrimitiveType::I8),
        (true, 16, false) => ("i16", wir::PrimitiveType::I16),
        (true, 32, false) => ("i32", wir::PrimitiveType::I32),
        (true, 64, false) => ("i64", wir::PrimitiveType::I64),
        (true, 128, false) => ("i128", wir::PrimitiveType::I128),
        _ => return Err(unsupported("noncanonical scalar integer identity")),
    };
    Ok((name, wir::TypeKind::Primitive(primitive)))
}

fn lower_linearity(linearity: sema::Linearity) -> wir::Linearity {
    match linearity {
        sema::Linearity::ScalarCopy => wir::Linearity::CopyScalar,
        sema::Linearity::ExplicitCopy => wir::Linearity::ExplicitCopy,
        sema::Linearity::ReclaimableLinear => wir::Linearity::Reclaimable,
        sema::Linearity::StrictLinear => wir::Linearity::Strict,
    }
}

fn lower_access(access: sema::AccessMode) -> wir::AccessMode {
    match access {
        sema::AccessMode::Value | sema::AccessMode::Read => wir::AccessMode::Read,
        sema::AccessMode::Mutate => wir::AccessMode::Mutate,
        sema::AccessMode::Take => wir::AccessMode::Take,
    }
}

fn lower_function_color(color: wrela_hir::FunctionColor) -> Result<wir::FunctionColor, LowerError> {
    match color {
        wrela_hir::FunctionColor::Sync => Ok(wir::FunctionColor::Sync),
        wrela_hir::FunctionColor::Async => Ok(wir::FunctionColor::Async),
        wrela_hir::FunctionColor::Isr => Ok(wir::FunctionColor::Isr),
    }
}

fn lower_generated_tests(
    generated: &GeneratedTestFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(SemanticWir, LoweringReport), LowerError> {
    check_cancelled(is_cancelled)?;
    let mut types = lower_source_types(generated.input, limits, is_cancelled)?;
    let encoded = encode_generated_harness(generated.group, &mut types, limits, is_cancelled)?;

    let proofs = lower_proofs(generated.facts, limits, is_cancelled)?;
    let function_count = generated.facts.functions.len();
    let mut functions = try_vec(
        function_count,
        "SemanticWir functions",
        u64::from(limits.functions),
    )?;
    let mut source_operations = 0u64;
    let mut output_values = 0u64;
    for function in &generated.facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == generated.harness.id {
            continue;
        }
        let (lowered, operations) =
            lower_source_function(generated.input, function, None, limits, is_cancelled)?;
        source_operations =
            source_operations
                .checked_add(operations)
                .ok_or(LowerError::ResourceLimit {
                    resource: "SemanticWir operations",
                    limit: limits.operations,
                })?;
        if source_operations > limits.operations {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: limits.operations,
            });
        }
        if lowered.id.0 as usize != functions.len() {
            return Err(unsupported("noncanonical source function identity order"));
        }
        output_values = output_values
            .checked_add(u64::try_from(lowered.values.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "SemanticWir values",
                    limit: limits.values,
                }
            })?)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            })?;
        functions.push(lowered);
    }
    let (harness, harness_operations) =
        lower_generated_harness_function(generated, encoded, limits, is_cancelled)?;
    if harness.id.0 as usize != functions.len() {
        return Err(unsupported("nonterminal generated test harness identity"));
    }
    output_values = output_values
        .checked_add(u64::try_from(harness.values.len()).map_err(|_| {
            LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            }
        })?)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir values",
            limit: limits.values,
        })?;
    if output_values > limits.values {
        return Err(LowerError::ResourceLimit {
            resource: "SemanticWir values",
            limit: limits.values,
        });
    }
    let operations =
        source_operations
            .checked_add(harness_operations)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: limits.operations,
            })?;
    if operations > limits.operations {
        return Err(LowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit: limits.operations,
        });
    }
    functions.push(harness);

    let mut tests = try_vec(
        generated.group.tests.len(),
        "SemanticWir tests",
        limits.model_edges,
    )?;
    for (local_id, (planned, function_id)) in generated
        .group
        .tests
        .iter()
        .zip(&generated.test_functions)
        .enumerate()
    {
        check_cancelled(is_cancelled)?;
        let source = planned
            .descriptor
            .source
            .ok_or(LowerError::MissingSemanticFact {
                subject: planned.descriptor.name.clone(),
                fact: "integration-test source span",
            })?;
        tests.push(wir::TestEntry {
            id: wir::TestId(
                u32::try_from(local_id).map_err(|_| LowerError::ResourceLimit {
                    resource: "SemanticWir tests",
                    limit: limits.model_edges,
                })?,
            ),
            plan_id: planned.descriptor.id.0,
            name: copy_text(&planned.descriptor.name, limits.payload_bytes)?,
            function: wir::FunctionId(function_id.0),
            kind: wir::TestKind::Integration,
            source,
            timeout_ns: planned.descriptor.timeout_ns,
        });
    }
    let reachable_declarations = generated_reachable_declarations(generated, limits, is_cancelled)?;
    let startup_order = lower_owners(
        &generated.graph.startup_order,
        limits.model_edges,
        is_cancelled,
    )?;
    let shutdown_order = lower_owners(
        &generated.graph.shutdown_order,
        limits.model_edges,
        is_cancelled,
    )?;
    let wir = SemanticWir {
        version: wir::SEMANTIC_WIR_VERSION,
        name: copy_text(&generated.graph.name, limits.payload_bytes)?,
        build: generated.facts.build.clone(),
        source_summary: wir::SourceSummary {
            hir_files: generated.facts.hir.files,
            hir_declarations: generated.facts.hir.declarations,
            reachable_declarations,
            monomorphized_instantiations: u64::try_from(function_count).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "SemanticWir functions",
                    limit: u64::from(limits.functions),
                }
            })?,
            resolved_interface_calls: 0,
        },
        types,
        globals: Vec::new(),
        functions,
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        scopes: Vec::new(),
        proofs,
        tests,
        compiled_test_group: Some(generated.group.clone()),
        startup_order,
        shutdown_order,
        image_entry: wir::FunctionId(generated.graph.entry.0),
        static_bytes: generated.graph.static_bytes,
        peak_bytes: generated.graph.peak_bytes,
    };
    let report = LoweringReport {
        semantic_types: count_u32(
            wir.types.len(),
            "SemanticWir types",
            u64::from(limits.types),
        )?,
        function_instances: count_u32(
            wir.functions.len(),
            "SemanticWir functions",
            u64::from(limits.functions),
        )?,
        operations,
        proofs: count_u32(wir.proofs.len(), "SemanticWir proofs", limits.model_edges)?,
        image_nodes: 0,
        tests: count_u32(wir.tests.len(), "SemanticWir tests", limits.model_edges)?,
    };
    check_cancelled(is_cancelled)?;
    Ok((wir, report))
}

fn lower_proofs(
    facts: &sema::PartialAnalysis,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::ProofRecord>, LowerError> {
    let mut proofs = try_vec(facts.proofs.len(), "SemanticWir proofs", limits.model_edges)?;
    for proof in &facts.proofs {
        check_cancelled(is_cancelled)?;
        let mut sources = try_vec(
            proof.sources.len(),
            "SemanticWir proof sources",
            limits.model_edges,
        )?;
        sources.extend_from_slice(&proof.sources);
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "SemanticWir proof dependencies",
            limits.model_edges,
        )?;
        depends_on.extend(proof.depends_on.iter().map(|id| wir::ProofId(id.0)));
        let mut explanation = try_vec(
            proof.explanation.len(),
            "SemanticWir proof explanations",
            limits.model_edges,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            explanation.push(copy_text(line, limits.payload_bytes)?);
        }
        proofs.push(wir::ProofRecord {
            id: wir::ProofId(proof.id.0),
            kind: lower_proof_kind(&proof.kind),
            subject: copy_text(&proof.subject, limits.payload_bytes)?,
            bound: proof.bound,
            sources,
            depends_on,
            explanation,
        });
    }
    Ok(proofs)
}

fn lower_source_function(
    input: &AnalyzedImage,
    function: &sema::FunctionInstance,
    scope_context: Option<&ScopeLoweringContext>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(wir::SemanticFunction, u64), LowerError> {
    let sema::FunctionOrigin::Source { declaration, body } = function.origin else {
        return Err(unsupported("non-source integration test bodies"));
    };
    let program = input.hir().as_program();
    let declaration_record =
        program
            .declaration(declaration)
            .ok_or(LowerError::MissingSemanticFact {
                subject: function.name.clone(),
                fact: "source function declaration",
            })?;
    let wrela_hir::DeclarationKind::Function(source_function) = &declaration_record.kind else {
        return Err(unsupported("non-function source provenance"));
    };
    if source_function.body != Some(body)
        || source_function.color != function.color
        || function.source != Some(declaration_record.source)
        || source_function.parameters.len() != function.parameters.len()
    {
        return Err(LowerError::InternalInvariant(
            "source function provenance differs from retained HIR".to_owned(),
        ));
    }

    let (mut values, value_map) =
        lower_source_values(input.facts(), function, limits, is_cancelled)?;
    let mut parameters = try_vec(
        function.parameters.len(),
        "SemanticWir function parameters",
        limits.model_edges,
    )?;
    for (source_parameter, parameter) in source_function.parameters.iter().zip(&function.parameters)
    {
        check_cancelled(is_cancelled)?;
        let hir_parameter = program
            .parameters
            .get(source_parameter.0 as usize)
            .filter(|record| {
                record.id == *source_parameter
                    && record.owner == wrela_hir::CallableOwner::Declaration(declaration)
            })
            .ok_or(LowerError::MissingSemanticFact {
                subject: function.name.clone(),
                fact: "source function parameter",
            })?;
        let semantic_value = input
            .facts()
            .values
            .get(parameter.value.0 as usize)
            .filter(|value| {
                value.function == function.id
                    && value.ty == parameter.ty
                    && value.origin == sema::SemanticValueOrigin::Parameter(*source_parameter)
                    && value.source == Some(hir_parameter.source)
            })
            .ok_or_else(|| {
                LowerError::InternalInvariant(
                    "semantic parameter value differs from retained HIR".to_owned(),
                )
            })?;
        let expected_name = if hir_parameter.receiver {
            Some("self")
        } else {
            hir_parameter.name.as_ref().map(wrela_hir::Name::as_str)
        };
        if parameter.parameter != *source_parameter
            || parameter.access != lower_hir_access(hir_parameter.access)
            || semantic_value.source_name.as_deref() != expected_name
        {
            return Err(LowerError::InternalInvariant(
                "semantic parameter binding differs from retained HIR".to_owned(),
            ));
        }
        parameters.push(value_map.get(parameter.value)?);
    }

    let mut lowerer = SourceFunctionLowerer {
        input,
        function,
        scope_context,
        root_body: body,
        value_map: &value_map,
        limits,
        is_cancelled,
        seen_bodies: try_vec(0, "source body closure", limits.model_edges)?,
        seen_statements: try_vec(0, "source statement closure", limits.model_edges)?,
        seen_expressions: try_vec(0, "source expression closure", limits.model_edges)?,
        operations: 0,
        statement_edges: 0,
        aggregate_name_work: 0,
        next_value: u32::try_from(values.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir source values",
            limit: limits.values,
        })?,
        synthetic_values: Vec::new(),
    };
    let mut local_state = SourceLocalState::empty(input.hir().as_program().locals.len(), limits)?;
    let mut lowered_body = lowerer.lower_body(body, 1, &mut local_state)?;
    let structurally_returns = lowerer.body_definitely_returns(body)?;
    let mut mailbox_receive = None;
    for fact in &input.facts().expressions {
        check_cancelled(is_cancelled)?;
        let sema::ExpressionResolution::ActorRequest { actor, method, .. } = fact.resolution else {
            continue;
        };
        if method == function.id && mailbox_receive.replace(actor).is_some() {
            return Err(unsupported(
                "more than one admitted startup message for one actor turn",
            ));
        }
    }
    if let Some(actor) = mailbox_receive {
        if function.role != sema::FunctionRole::ActorTurn(actor) {
            return Err(unsupported("mailbox receive outside its actor turn"));
        }
        let capacity =
            lowered_body
                .statements
                .len()
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "SemanticWir source statements",
                    limit: limits.model_edges,
                })?;
        let mut statements = try_vec(
            capacity,
            "SemanticWir source statements",
            limits.model_edges,
        )?;
        lowerer.push_effect(
            &mut statements,
            wir::SemanticOperation::MailboxReceive {
                actor: wir::ActorId(actor.0),
                method: wir::FunctionId(function.id.0),
            },
            function.source,
        )?;
        statements.append(&mut lowered_body.statements);
        lowered_body.statements = statements;
    }
    if !structurally_returns
        && !lowered_body
            .statements
            .iter()
            .any(|statement| matches!(statement, wir::SemanticStatement::Return(_)))
    {
        if function.result != sema::SemanticTypeId(0) {
            return Err(unsupported(
                "non-unit source functions without an exact return",
            ));
        }
        lowerer.push_statement(
            &mut lowered_body.statements,
            wir::SemanticStatement::Return(Vec::new()),
        )?;
    }
    let mut body_parameters = try_vec(
        parameters.len(),
        "SemanticWir function body parameters",
        limits.model_edges,
    )?;
    body_parameters.extend_from_slice(&parameters);
    lowered_body.parameters = body_parameters;
    lowerer.validate_exact_closure()?;
    values.append(&mut lowerer.synthetic_values);

    let mut function_proofs = try_vec(
        function.proofs.len(),
        "SemanticWir function proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(function.proofs.iter().map(|proof| wir::ProofId(proof.0)));
    let lowered = wir::SemanticFunction {
        id: wir::FunctionId(function.id.0),
        instance_key: function.key.0,
        name: copy_text(&function.name, limits.payload_bytes)?,
        origin: wir::FunctionOrigin::Source,
        role: match function.role {
            sema::FunctionRole::Test => wir::FunctionRole::Test,
            sema::FunctionRole::Ordinary => wir::FunctionRole::Ordinary,
            sema::FunctionRole::ActorTurn(actor) => {
                wir::FunctionRole::ActorTurn(wir::ActorId(actor.0))
            }
            sema::FunctionRole::TaskEntry(task) => {
                wir::FunctionRole::TaskEntry(wir::TaskId(task.0))
            }
            sema::FunctionRole::Isr(_)
            | sema::FunctionRole::Cleanup
            | sema::FunctionRole::ImageEntry => {
                return Err(unsupported(
                    "source function roles outside scalar, actor-turn, and static-task entries",
                ));
            }
        },
        color: lower_function_color(function.color)?,
        parameters,
        result: wir::TypeId(function.result.0),
        values,
        body: lowered_body,
        effects: wir::EffectSet(function.effects.0),
        proofs: function_proofs,
        source: function.source,
        stack_bound: function.stack_bytes_bound,
        frame_bound: function.frame_bytes_bound,
        uninterrupted_bound: function.uninterrupted_work_bound,
        recursive_depth_bound: function.recursive_depth_bound,
    };
    Ok((lowered, lowerer.operations))
}

struct SourceValueMap {
    entries: Vec<(sema::ValueId, wir::ValueId)>,
}

impl SourceValueMap {
    fn get(&self, value: sema::ValueId) -> Result<wir::ValueId, LowerError> {
        self.entries
            .binary_search_by_key(&value, |(source, _)| *source)
            .ok()
            .and_then(|index| self.entries.get(index).map(|(_, lowered)| *lowered))
            .ok_or_else(|| {
                LowerError::InternalInvariant(
                    "semantic value is not owned by its source function".to_owned(),
                )
            })
    }
}

fn lower_source_values(
    facts: &sema::PartialAnalysis,
    function: &sema::FunctionInstance,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<wir::SemanticValue>, SourceValueMap), LowerError> {
    let count = facts
        .values
        .iter()
        .filter(|value| value.function == function.id)
        .count();
    let mut values = try_vec(count, "SemanticWir function values", limits.values)?;
    let mut entries = try_vec(count, "semantic value identity map", limits.model_edges)?;
    for value in facts
        .values
        .iter()
        .filter(|value| value.function == function.id)
    {
        check_cancelled(is_cancelled)?;
        if value.category != sema::ValueCategory::Value {
            return Err(unsupported("non-value scalar semantic values"));
        }
        let id =
            wir::ValueId(
                u32::try_from(values.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "SemanticWir function values",
                    limit: limits.values,
                })?,
            );
        let name = value
            .source_name
            .as_deref()
            .map(|name| copy_text(name, limits.payload_bytes))
            .transpose()?;
        values.push(wir::SemanticValue {
            id,
            ty: wir::TypeId(value.ty.0),
            origin: value.source,
            name,
        });
        entries.push((value.id, id));
    }
    Ok((values, SourceValueMap { entries }))
}

enum LoweredExpression {
    Value(wir::ValueId),
    Function(sema::FunctionInstanceId),
    Constructor(sema::SemanticTypeId),
    EnumConstructor(sema::SemanticTypeId, u32),
}

struct DirectCallInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    callee: wrela_hir::ExpressionId,
    source_argument_count: usize,
    target: sema::FunctionInstanceId,
    bindings: Vec<sema::ResolvedCallArgument>,
    result_type: sema::SemanticTypeId,
    result: Option<sema::ValueId>,
    effects: sema::EffectSet,
}

/// A binary/comparison operator desugared to a direct call on a `core.ops`
/// interface impl method (chapter 10 §12). Unlike `DirectCallInput`, there is
/// no source `Call` expression: `left`/`right` are the original operator's
/// own operand expressions, evaluated in that order regardless of the
/// argument-to-parameter binding recorded in `bindings`.
struct OperatorCallInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    left: wrela_hir::ExpressionId,
    right: wrela_hir::ExpressionId,
    target: sema::FunctionInstanceId,
    bindings: Vec<sema::ResolvedCallArgument>,
    raw_result: sema::ValueId,
    negate: bool,
    result_type: sema::SemanticTypeId,
    result: Option<sema::ValueId>,
    effects: sema::EffectSet,
}

struct AggregateInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    callee: wrela_hir::ExpressionId,
    source_argument_count: usize,
    ty: sema::SemanticTypeId,
    result: Option<sema::ValueId>,
    effects: sema::EffectSet,
}

struct EnumAggregateInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    callee: wrela_hir::ExpressionId,
    ty: sema::SemanticTypeId,
    variant: u32,
    result: Option<sema::ValueId>,
    effects: sema::EffectSet,
}

struct ProjectInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    base: wrela_hir::ExpressionId,
    field: u32,
    ty: sema::SemanticTypeId,
    result: Option<sema::ValueId>,
    effects: sema::EffectSet,
}

struct ValueReferenceInput {
    expression: wrela_hir::ExpressionId,
    local: wrela_hir::LocalId,
    value: sema::ValueId,
    ty: sema::SemanticTypeId,
    effects: sema::EffectSet,
    result: Option<sema::ValueId>,
    source: Span,
}

struct ScalarUnaryInput {
    expression: wrela_hir::ExpressionId,
    operator: wrela_hir::UnaryOperator,
    operand: wrela_hir::ExpressionId,
    ty: sema::SemanticTypeId,
    result: sema::ValueId,
    effects: sema::EffectSet,
}

enum ScalarBinaryOperator {
    Arithmetic(wrela_hir::BinaryOperator),
    Compare(wrela_hir::ComparisonOperator),
}

struct ScalarBinaryInput {
    expression: wrela_hir::ExpressionId,
    operator: ScalarBinaryOperator,
    left: wrela_hir::ExpressionId,
    right: wrela_hir::ExpressionId,
    ty: sema::SemanticTypeId,
    result: sema::ValueId,
    effects: sema::EffectSet,
}

struct ScalarConvertInput {
    expression: wrela_hir::ExpressionId,
    value: wrela_hir::ExpressionId,
    destination: sema::SemanticTypeId,
    result: sema::ValueId,
    effects: sema::EffectSet,
}

struct ResultTryInput {
    expression: wrela_hir::ExpressionId,
    source: Span,
    operand: wrela_hir::ExpressionId,
    payload_type: sema::SemanticTypeId,
    result_type: sema::SemanticTypeId,
    ok_variant: u32,
    err_variant: u32,
    ok_payload: sema::ValueId,
    err_payload: sema::ValueId,
    propagated: sema::ValueId,
    result: sema::ValueId,
    effects: sema::EffectSet,
}

enum SourceStatementPlan {
    Pass,
    Initialize {
        local: wrela_hir::LocalId,
        value: wrela_hir::ExpressionId,
    },
    Assign {
        local: wrela_hir::LocalId,
        value: wrela_hir::ExpressionId,
    },
    AssignField {
        local: wrela_hir::LocalId,
        field: wrela_hir::Name,
        value: wrela_hir::ExpressionId,
    },
    CompoundAssign {
        local: wrela_hir::LocalId,
        operator: wrela_hir::BinaryOperator,
        value: wrela_hir::ExpressionId,
    },
    ActorStateStore {
        access: sema::ActorStateAccess,
        value: wrela_hir::ExpressionId,
    },
    ActorStateCompoundAssign {
        access: sema::ActorStateAccess,
        value: wrela_hir::ExpressionId,
    },
    Expression(wrela_hir::ExpressionId),
    Send(wrela_hir::ExpressionId),
    Return(Option<wrela_hir::ExpressionId>),
    Assert {
        condition: wrela_hir::ExpressionId,
        expression: String,
        message: Option<String>,
    },
    If {
        condition: wrela_hir::ExpressionId,
        then_body: wrela_hir::BodyId,
        else_body: Option<wrela_hir::BodyId>,
    },
    Match {
        scrutinee: wrela_hir::ExpressionId,
        arms: Vec<wrela_hir::MatchArm>,
    },
    While {
        condition: wrela_hir::ExpressionId,
        body: wrela_hir::BodyId,
    },
    With {
        value: wrela_hir::ExpressionId,
        binding: Option<wrela_hir::LocalId>,
        body: wrela_hir::BodyId,
        activation: ScopeActivationLowering,
    },
    Break,
    Continue,
}

enum SourceExpressionPlan {
    Constant {
        value: wir::Constant,
        ty: sema::SemanticTypeId,
        result: sema::ValueId,
    },
    Local(ValueReferenceInput),
    Parameter {
        parameter: wrela_hir::ParameterId,
        value: sema::ValueId,
        ty: sema::SemanticTypeId,
        effects: sema::EffectSet,
        result: Option<sema::ValueId>,
    },
    Function {
        source: wrela_hir::ResolvedDeclaration,
        target: sema::FunctionInstanceId,
        ty: sema::SemanticTypeId,
        effects: sema::EffectSet,
        result: Option<sema::ValueId>,
    },
    Constructor {
        source: wrela_hir::ResolvedDeclaration,
        ty: sema::SemanticTypeId,
        effects: sema::EffectSet,
        result: Option<sema::ValueId>,
    },
    EnumConstructor {
        source: wrela_hir::ResolvedVariant,
        ty: sema::SemanticTypeId,
        variant: u32,
        effects: sema::EffectSet,
        result: Option<sema::ValueId>,
    },
    Aggregate(AggregateInput),
    EnumAggregate(EnumAggregateInput),
    Project(ProjectInput),
    ActorStateLoad(sema::ActorStateAccess),
    DirectCall(DirectCallInput),
    OperatorCall(OperatorCallInput),
    Unary(ScalarUnaryInput),
    Binary(ScalarBinaryInput),
    Convert(ScalarConvertInput),
    ResultTry(ResultTryInput),
    InlineIf(InlineIfInput),
    Await {
        expression: wrela_hir::ExpressionId,
        operand: wrela_hir::ExpressionId,
        ty: sema::SemanticTypeId,
        result: sema::ValueId,
        effects: sema::EffectSet,
    },
}

struct InlineIfInput {
    expression: wrela_hir::ExpressionId,
    condition: wrela_hir::ExpressionId,
    then_branch: wrela_hir::ExpressionId,
    elif_branches: Vec<(wrela_hir::ExpressionId, wrela_hir::ExpressionId)>,
    else_branch: wrela_hir::ExpressionId,
    ty: sema::SemanticTypeId,
    result: sema::ValueId,
    effects: sema::EffectSet,
}

struct SourceFunctionLowerer<'a> {
    input: &'a AnalyzedImage,
    function: &'a sema::FunctionInstance,
    scope_context: Option<&'a ScopeLoweringContext>,
    root_body: wrela_hir::BodyId,
    value_map: &'a SourceValueMap,
    limits: LoweringLimits,
    is_cancelled: &'a dyn Fn() -> bool,
    seen_bodies: Vec<wrela_hir::BodyId>,
    seen_statements: Vec<wrela_hir::StatementId>,
    seen_expressions: Vec<wrela_hir::ExpressionId>,
    operations: u64,
    statement_edges: u64,
    aggregate_name_work: u64,
    next_value: u32,
    synthetic_values: Vec<wir::SemanticValue>,
}

struct SourceLocalState {
    values: Vec<Option<sema::ValueId>>,
}

impl SourceLocalState {
    fn empty(count: usize, limits: LoweringLimits) -> Result<Self, LowerError> {
        let mut values = try_vec(count, "source local SSA state", limits.model_edges)?;
        values.resize(count, None);
        Ok(Self { values })
    }

    fn copy(&self, limits: LoweringLimits) -> Result<Self, LowerError> {
        let mut values = try_vec(
            self.values.len(),
            "source branch SSA state",
            limits.model_edges,
        )?;
        values.extend_from_slice(&self.values);
        Ok(Self { values })
    }

    fn get(&self, local: wrela_hir::LocalId) -> Option<sema::ValueId> {
        self.values.get(local.0 as usize).copied().flatten()
    }

    fn set(&mut self, local: wrela_hir::LocalId, value: sema::ValueId) -> Result<(), LowerError> {
        let slot = self.values.get_mut(local.0 as usize).ok_or_else(|| {
            LowerError::InternalInvariant("source local SSA slot is missing".to_owned())
        })?;
        *slot = Some(value);
        Ok(())
    }

    fn set_empty(&mut self, local: wrela_hir::LocalId) -> Result<(), LowerError> {
        let slot = self.values.get_mut(local.0 as usize).ok_or_else(|| {
            LowerError::InternalInvariant("source local SSA slot is missing".to_owned())
        })?;
        *slot = None;
        Ok(())
    }
}

impl SourceFunctionLowerer<'_> {
    fn lower_body(
        &mut self,
        body_id: wrela_hir::BodyId,
        depth: u32,
        local_state: &mut SourceLocalState,
    ) -> Result<wir::SemanticRegion, LowerError> {
        check_cancelled(self.is_cancelled)?;
        if depth > self.limits.structured_region_depth {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir structured region depth",
                limit: u64::from(self.limits.structured_region_depth),
            });
        }
        if !body_is_ancestor(self.input.hir().as_program(), self.root_body, body_id) {
            return Err(LowerError::InternalInvariant(
                "nested source body escaped its function root".to_owned(),
            ));
        }
        self.push_seen_body(body_id)?;
        let statement_count = self
            .input
            .hir()
            .as_program()
            .body(body_id)
            .map(|body| body.statements.len())
            .ok_or(LowerError::MissingSemanticFact {
                subject: self.function.name.clone(),
                fact: "source function body",
            })?;
        let mut statements = try_vec(
            statement_count,
            "SemanticWir source statements",
            self.limits.model_edges,
        )?;
        let mut returned = false;
        for statement_index in 0..statement_count {
            check_cancelled(self.is_cancelled)?;
            if returned {
                return Err(unsupported("source statements after return"));
            }
            let statement_id = self
                .input
                .hir()
                .as_program()
                .body(body_id)
                .and_then(|body| body.statements.get(statement_index))
                .copied()
                .ok_or_else(|| {
                    LowerError::InternalInvariant(
                        "source body changed while it was being lowered".to_owned(),
                    )
                })?;
            self.push_seen_statement(statement_id)?;
            let (statement, statement_source) = {
                let statement = self
                    .input
                    .hir()
                    .as_program()
                    .statement(statement_id)
                    .filter(|statement| {
                        statement.body == body_id && statement.attributes.is_empty()
                    })
                    .ok_or(LowerError::MissingSemanticFact {
                        subject: self.function.name.clone(),
                        fact: "source statement",
                    })?;
                let plan = match &statement.kind {
                    wrela_hir::StatementKind::Pass => SourceStatementPlan::Pass,
                    wrela_hir::StatementKind::Initialize { local, value } => {
                        SourceStatementPlan::Initialize {
                            local: *local,
                            value: *value,
                        }
                    }
                    wrela_hir::StatementKind::Assign {
                        targets,
                        operator,
                        value,
                    } => {
                        if let Some(access) = self
                            .input
                            .facts()
                            .actor_state_accesses
                            .iter()
                            .find(|access| {
                                access.function == self.function.id
                                    && matches!(access.kind,
                                        sema::ActorStateAccessKind::Write { statement, .. }
                                        | sema::ActorStateAccessKind::CompoundAssign { statement, .. }
                                            if statement == statement_id)
                            })
                            .cloned()
                        {
                            match access.kind {
                                sema::ActorStateAccessKind::Write { .. } => {
                                    SourceStatementPlan::ActorStateStore {
                                        access,
                                        value: *value,
                                    }
                                }
                                sema::ActorStateAccessKind::CompoundAssign { .. } => {
                                    SourceStatementPlan::ActorStateCompoundAssign {
                                        access,
                                        value: *value,
                                    }
                                }
                                sema::ActorStateAccessKind::Read { .. } => {
                                    return Err(self.fact_mismatch("actor state statement access"));
                                }
                            }
                        } else {
                            let [target] = targets.as_slice() else {
                                return Err(unsupported("multi-target scalar assignment"));
                            };
                            let wrela_hir::Definition::Local(local) = target.root else {
                                return Err(unsupported("non-local scalar assignment"));
                            };
                            if let [wrela_hir::PlaceProjection::Field(field)] =
                                target.projections.as_slice()
                            {
                                if compound_assignment_binary_operator(*operator).is_some() {
                                    return Err(unsupported(
                                        "semantic-runtime-field-compound-assignment-pending",
                                    ));
                                }
                                SourceStatementPlan::AssignField {
                                    local,
                                    field: field.clone(),
                                    value: *value,
                                }
                            } else if target.projections.is_empty() {
                                match compound_assignment_binary_operator(*operator) {
                                    Some(operator) => SourceStatementPlan::CompoundAssign {
                                        local,
                                        operator,
                                        value: *value,
                                    },
                                    None => SourceStatementPlan::Assign {
                                        local,
                                        value: *value,
                                    },
                                }
                            } else {
                                return Err(unsupported(
                                    "semantic-runtime-field-assignment-projection-pending",
                                ));
                            }
                        }
                    }
                    wrela_hir::StatementKind::Expression(expression) => {
                        SourceStatementPlan::Expression(*expression)
                    }
                    wrela_hir::StatementKind::Send(expression) => {
                        SourceStatementPlan::Send(*expression)
                    }
                    wrela_hir::StatementKind::Return(expression) => {
                        SourceStatementPlan::Return(*expression)
                    }
                    wrela_hir::StatementKind::Assert {
                        condition,
                        expression,
                        witness,
                        message,
                        comptime: false,
                    } if witness.source
                        == self
                            .input
                            .hir()
                            .as_program()
                            .expression(*condition)
                            .map(|record| record.source)
                            .ok_or_else(|| self.fact_mismatch("runtime assertion witness"))?
                        && witness.expression == *expression =>
                    {
                        SourceStatementPlan::Assert {
                            condition: *condition,
                            expression: expression.clone(),
                            message: message.clone(),
                        }
                    }
                    wrela_hir::StatementKind::If {
                        branches,
                        else_body,
                    } => {
                        let [(condition, then_body)] = branches.as_slice() else {
                            return Err(unsupported("multi-branch source if statements"));
                        };
                        SourceStatementPlan::If {
                            condition: *condition,
                            then_body: *then_body,
                            else_body: *else_body,
                        }
                    }
                    wrela_hir::StatementKind::Match { scrutinee, arms } => {
                        let mut copied =
                            try_vec(arms.len(), "source match arms", self.limits.model_edges)?;
                        copied.extend(arms.iter().cloned());
                        SourceStatementPlan::Match {
                            scrutinee: *scrutinee,
                            arms: copied,
                        }
                    }
                    wrela_hir::StatementKind::While { condition, body } => {
                        SourceStatementPlan::While {
                            condition: *condition,
                            body: *body,
                        }
                    }
                    wrela_hir::StatementKind::With {
                        value,
                        binding,
                        region: None,
                        body,
                    } => SourceStatementPlan::With {
                        value: *value,
                        binding: *binding,
                        body: *body,
                        activation: self
                            .scope_context
                            .and_then(|context| context.activation(statement_id))
                            .ok_or_else(|| self.fact_mismatch("scope activation plan"))?,
                    },
                    wrela_hir::StatementKind::Break => SourceStatementPlan::Break,
                    wrela_hir::StatementKind::Continue => SourceStatementPlan::Continue,
                    _ => {
                        return Err(unsupported(
                            "ordinary source operations outside scalar bodies",
                        ));
                    }
                };
                (plan, statement.source)
            };
            let expected_effects = match &statement {
                SourceStatementPlan::Pass => sema::EffectSet::default(),
                SourceStatementPlan::Initialize { value, .. }
                | SourceStatementPlan::Assign { value, .. }
                | SourceStatementPlan::AssignField { value, .. }
                | SourceStatementPlan::CompoundAssign { value, .. }
                | SourceStatementPlan::Expression(value)
                | SourceStatementPlan::Send(value) => self.expression_fact(*value)?.effects,
                SourceStatementPlan::ActorStateStore { value, .. }
                | SourceStatementPlan::ActorStateCompoundAssign { value, .. } => {
                    let mut effects = self.expression_fact(*value)?.effects;
                    effects.0 |= sema::EffectSet::ACTOR;
                    effects
                }
                SourceStatementPlan::Return(Some(value)) => self.expression_fact(*value)?.effects,
                SourceStatementPlan::Return(None) => sema::EffectSet::default(),
                SourceStatementPlan::Assert { condition, .. } => {
                    let mut effects = self.expression_fact(*condition)?.effects;
                    effects.0 |= sema::EffectSet::MAY_FAIL;
                    effects
                }
                SourceStatementPlan::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let mut effects = self.expression_fact(*condition)?.effects;
                    effects.0 |= self.body_statement_effects(*then_body)?.0;
                    if let Some(otherwise) = *else_body {
                        effects.0 |= self.body_statement_effects(otherwise)?.0;
                    }
                    effects
                }
                SourceStatementPlan::Match { scrutinee, arms } => {
                    let mut effects = self.expression_fact(*scrutinee)?.effects;
                    for arm in arms {
                        check_cancelled(self.is_cancelled)?;
                        effects.0 |= self.body_statement_effects(arm.body)?.0;
                    }
                    effects
                }
                SourceStatementPlan::While { condition, body } => {
                    let mut effects = self.expression_fact(*condition)?.effects;
                    effects.0 |= self.body_statement_effects(*body)?.0;
                    effects
                }
                SourceStatementPlan::With { value, body, .. } => {
                    let mut effects = self.expression_fact(*value)?.effects;
                    effects.0 |= self.body_statement_effects(*body)?.0;
                    effects
                }
                SourceStatementPlan::Break | SourceStatementPlan::Continue => {
                    sema::EffectSet::default()
                }
            };
            let statement_definitions = {
                let fact = self.statement_fact(statement_id)?;
                self.validate_statement_post_state(fact, body_id, expected_effects)?;
                let mut definitions = try_vec(
                    fact.definitions.len(),
                    "source statement definitions",
                    self.limits.model_edges,
                )?;
                definitions.extend_from_slice(&fact.definitions);
                definitions
            };
            match statement {
                SourceStatementPlan::Pass => {
                    if !statement_definitions.is_empty() {
                        return Err(self.fact_mismatch("pass statement defines a local"));
                    }
                }
                SourceStatementPlan::Initialize { local, value } => {
                    let [definition] = statement_definitions.as_slice() else {
                        return Err(self.fact_mismatch("local initializer definition"));
                    };
                    let definition = *definition;
                    if definition.local != local {
                        return Err(self.fact_mismatch("local initializer target"));
                    }
                    let expression = self.expression_fact(value)?;
                    if expression.result != Some(definition.value) {
                        return Err(self.fact_mismatch("local initializer result"));
                    }
                    let semantic_value = self
                        .input
                        .facts()
                        .values
                        .get(definition.value.0 as usize)
                        .filter(|record| {
                            record.function == self.function.id
                                && record.origin == sema::SemanticValueOrigin::Local(local)
                        })
                        .ok_or_else(|| self.fact_mismatch("local initializer value"))?;
                    let local_record = self
                        .input
                        .hir()
                        .as_program()
                        .locals
                        .get(local.0 as usize)
                        .filter(|record| record.id == local && record.body == body_id)
                        .ok_or(LowerError::MissingSemanticFact {
                            subject: self.function.name.clone(),
                            fact: "source local",
                        })?;
                    if semantic_value.source != Some(local_record.source)
                        || semantic_value.source_name.as_deref() != Some(local_record.name.as_str())
                    {
                        return Err(self.fact_mismatch("local value provenance"));
                    }
                    let lowered =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?;
                    if !matches!(
                        lowered,
                        LoweredExpression::Value(value)
                            if value == self.value_map.get(definition.value)?
                    ) {
                        return Err(self.fact_mismatch("lowered local initializer identity"));
                    }
                    if local_state.get(local).is_some() {
                        return Err(self.fact_mismatch("duplicate local initialization"));
                    }
                    local_state.set(local, definition.value)?;
                }
                SourceStatementPlan::Assign { local, value } => {
                    let previous = local_state
                        .get(local)
                        .ok_or_else(|| self.fact_mismatch("uninitialized scalar assignment"))?;
                    let [definition] = statement_definitions.as_slice() else {
                        return Err(self.fact_mismatch("scalar assignment definition"));
                    };
                    if definition.local != local || definition.value == previous {
                        return Err(self.fact_mismatch("scalar assignment target"));
                    }
                    let previous_record = self
                        .input
                        .facts()
                        .values
                        .get(previous.0 as usize)
                        .filter(|record| record.function == self.function.id)
                        .ok_or_else(|| self.fact_mismatch("scalar assignment previous value"))?;
                    let semantic_value = self
                        .input
                        .facts()
                        .values
                        .get(definition.value.0 as usize)
                        .filter(|record| {
                            record.function == self.function.id
                                && record.ty == previous_record.ty
                                && record.origin == sema::SemanticValueOrigin::Local(local)
                        })
                        .ok_or_else(|| self.fact_mismatch("scalar assignment value"))?;
                    let local_record = self
                        .input
                        .hir()
                        .as_program()
                        .locals
                        .get(local.0 as usize)
                        .filter(|record| {
                            record.id == local
                                && body_is_ancestor(
                                    self.input.hir().as_program(),
                                    record.body,
                                    body_id,
                                )
                        })
                        .ok_or_else(|| self.fact_mismatch("scalar assignment provenance"))?;
                    if semantic_value.source != Some(local_record.source)
                        || semantic_value.source_name.as_deref() != Some(local_record.name.as_str())
                        || self.expression_fact(value)?.result != Some(definition.value)
                    {
                        return Err(self.fact_mismatch("scalar assignment provenance"));
                    }
                    let lowered =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?;
                    if !matches!(
                        lowered,
                        LoweredExpression::Value(value)
                            if value == self.value_map.get(definition.value)?
                    ) {
                        return Err(self.fact_mismatch("lowered scalar assignment identity"));
                    }
                    local_state.set(local, definition.value)?;
                }
                SourceStatementPlan::AssignField {
                    local,
                    field,
                    value,
                } => {
                    let previous = local_state
                        .get(local)
                        .ok_or_else(|| self.fact_mismatch("uninitialized field assignment"))?;
                    let [definition] = statement_definitions.as_slice() else {
                        return Err(self.fact_mismatch("field assignment definition"));
                    };
                    if definition.local != local || definition.value == previous {
                        return Err(self.fact_mismatch("field assignment target"));
                    }
                    let previous_record = self
                        .input
                        .facts()
                        .values
                        .get(previous.0 as usize)
                        .filter(|record| record.function == self.function.id)
                        .ok_or_else(|| self.fact_mismatch("field assignment previous value"))?;
                    let semantic_value = self
                        .input
                        .facts()
                        .values
                        .get(definition.value.0 as usize)
                        .filter(|record| {
                            record.function == self.function.id
                                && record.ty == previous_record.ty
                                && record.origin == sema::SemanticValueOrigin::Local(local)
                        })
                        .ok_or_else(|| self.fact_mismatch("field assignment aggregate value"))?;
                    let local_record = self
                        .input
                        .hir()
                        .as_program()
                        .locals
                        .get(local.0 as usize)
                        .filter(|record| {
                            record.id == local
                                && body_is_ancestor(
                                    self.input.hir().as_program(),
                                    record.body,
                                    body_id,
                                )
                        })
                        .ok_or_else(|| self.fact_mismatch("field assignment provenance"))?;
                    if semantic_value.source != Some(local_record.source)
                        || semantic_value.source_name.as_deref() != Some(local_record.name.as_str())
                    {
                        return Err(self.fact_mismatch("field assignment provenance"));
                    }
                    let fields = match self
                        .input
                        .facts()
                        .types
                        .get(previous_record.ty.0 as usize)
                        .map(|record| &record.kind)
                    {
                        Some(sema::SemanticTypeKind::Structure { fields, .. }) => fields,
                        _ => return Err(self.fact_mismatch("field assignment aggregate type")),
                    };
                    let mut selected = None;
                    for (index, candidate) in fields.iter().enumerate() {
                        check_cancelled(self.is_cancelled)?;
                        self.aggregate_name_work = self.aggregate_name_work.checked_add(1).ok_or(
                            LowerError::ResourceLimit {
                                resource: "SemanticWir aggregate name lookup work",
                                limit: self.limits.model_edges,
                            },
                        )?;
                        if self.aggregate_name_work > self.limits.model_edges {
                            return Err(LowerError::ResourceLimit {
                                resource: "SemanticWir aggregate name lookup work",
                                limit: self.limits.model_edges,
                            });
                        }
                        if candidate.name == field.as_str() {
                            selected = Some((index, candidate));
                            break;
                        }
                    }
                    let (field_index, selected_field) = selected
                        .ok_or_else(|| self.fact_mismatch("field assignment semantic field"))?;
                    let rhs_fact = self.expression_fact(value)?;
                    if rhs_fact.ty != selected_field.ty {
                        return Err(self.fact_mismatch("field assignment RHS type"));
                    }
                    let LoweredExpression::Value(lowered_rhs) =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("field assignment RHS value"));
                    };
                    let result = self.value_map.get(definition.value)?;
                    if lowered_rhs == result {
                        return Err(self.fact_mismatch("field assignment replacement identity"));
                    }
                    self.push_let(
                        &mut statements,
                        result,
                        wir::SemanticOperation::InsertField {
                            aggregate: self.value_map.get(previous)?,
                            field: u32::try_from(field_index)
                                .map_err(|_| self.fact_mismatch("field assignment index"))?,
                            value: lowered_rhs,
                        },
                        Some(statement_source),
                    )?;
                    local_state.set(local, definition.value)?;
                }
                SourceStatementPlan::CompoundAssign {
                    local,
                    operator,
                    value,
                } => {
                    let previous = local_state
                        .get(local)
                        .ok_or_else(|| self.fact_mismatch("uninitialized compound assignment"))?;
                    let [definition] = statement_definitions.as_slice() else {
                        return Err(self.fact_mismatch("compound assignment definition"));
                    };
                    if definition.local != local || definition.value == previous {
                        return Err(self.fact_mismatch("compound assignment target"));
                    }
                    let previous_record = self
                        .input
                        .facts()
                        .values
                        .get(previous.0 as usize)
                        .filter(|record| record.function == self.function.id)
                        .ok_or_else(|| self.fact_mismatch("compound assignment previous value"))?;
                    let semantic_value = self
                        .input
                        .facts()
                        .values
                        .get(definition.value.0 as usize)
                        .filter(|record| {
                            record.function == self.function.id
                                && record.ty == previous_record.ty
                                && record.origin == sema::SemanticValueOrigin::Local(local)
                        })
                        .ok_or_else(|| self.fact_mismatch("compound assignment value"))?;
                    let local_record = self
                        .input
                        .hir()
                        .as_program()
                        .locals
                        .get(local.0 as usize)
                        .filter(|record| {
                            record.id == local
                                && body_is_ancestor(
                                    self.input.hir().as_program(),
                                    record.body,
                                    body_id,
                                )
                        })
                        .ok_or_else(|| self.fact_mismatch("compound assignment provenance"))?;
                    let expression = self.expression_fact(value)?;
                    if semantic_value.source != Some(local_record.source)
                        || semantic_value.source_name.as_deref() != Some(local_record.name.as_str())
                        || expression.ty != semantic_value.ty
                        || expression.result == Some(definition.value)
                        || !matches!(
                            source_scalar_kind(self.input.facts(), semantic_value.ty),
                            Some(SourceScalarKind::Integer { .. })
                        )
                        || self.input.facts().expressions.iter().any(|expression| {
                            expression.function == self.function.id
                                && expression.result == Some(definition.value)
                        })
                    {
                        return Err(self.fact_mismatch("compound assignment provenance"));
                    }
                    let (operator, arithmetic) = lower_source_arithmetic_operator(operator)
                        .filter(|(_, arithmetic)| *arithmetic == wir::ArithmeticMode::Checked)
                        .ok_or_else(|| self.fact_mismatch("compound assignment operator"))?;
                    let left = self.value_map.get(previous)?;
                    let LoweredExpression::Value(right) =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("compound assignment right-hand side"));
                    };
                    let result = self.value_map.get(definition.value)?;
                    self.push_let(
                        &mut statements,
                        result,
                        wir::SemanticOperation::Binary {
                            operator,
                            left,
                            right,
                            arithmetic,
                        },
                        Some(statement_source),
                    )?;
                    local_state.set(local, definition.value)?;
                }
                SourceStatementPlan::ActorStateCompoundAssign { access, value } => {
                    let (value_fact, current, result) = match access.kind {
                        sema::ActorStateAccessKind::CompoundAssign {
                            statement,
                            value_expression,
                            value: semantic_value,
                            current,
                            result,
                        } if statement == statement_id && value_expression == value => {
                            let value_fact = self.expression_fact(value)?;
                            if value_fact.result != Some(semantic_value) {
                                return Err(self.fact_mismatch("actor state compound RHS"));
                            }
                            (value_fact, current, result)
                        }
                        _ => return Err(self.fact_mismatch("actor state compound fact")),
                    };
                    if !statement_definitions.is_empty()
                        || access.function != self.function.id
                        || access.source != statement_source
                        || !matches!(
                            self.input
                                .facts()
                                .types
                                .get(value_fact.ty.0 as usize)
                                .map(|ty| &ty.kind),
                            Some(sema::SemanticTypeKind::Integer {
                                signed: false,
                                bits: 64,
                                pointer_sized: false,
                            })
                        )
                    {
                        return Err(self.fact_mismatch("actor state compound statement"));
                    }
                    for (id, origin) in [
                        (
                            current,
                            sema::SemanticValueOrigin::ActorStateLoad(statement_id),
                        ),
                        (
                            result,
                            sema::SemanticValueOrigin::ActorStateCompoundResult(statement_id),
                        ),
                    ] {
                        if self
                            .input
                            .facts()
                            .values
                            .get(id.0 as usize)
                            .is_none_or(|semantic| {
                                semantic.function != self.function.id
                                    || semantic.ty != value_fact.ty
                                    || semantic.category != sema::ValueCategory::Value
                                    || semantic.class != sema::SemanticValueClass::FirstClass
                                    || semantic.origin != origin
                                    || semantic.source != Some(statement_source)
                                    || semantic.source_name.is_some()
                            })
                        {
                            return Err(self.fact_mismatch("actor state compound value"));
                        }
                    }
                    let current = self.value_map.get(current)?;
                    self.push_let(
                        &mut statements,
                        current,
                        wir::SemanticOperation::ActorStateLoad {
                            actor: wir::ActorId(access.actor.0),
                            region: wir::RegionId(access.region.0),
                            proof: wir::ProofId(access.capacity.0),
                        },
                        Some(statement_source),
                    )?;
                    let LoweredExpression::Value(right) =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("actor state compound RHS value"));
                    };
                    let result = self.value_map.get(result)?;
                    self.push_let(
                        &mut statements,
                        result,
                        wir::SemanticOperation::Binary {
                            operator: wir::BinaryOperator::Add,
                            left: current,
                            right,
                            arithmetic: wir::ArithmeticMode::Checked,
                        },
                        Some(statement_source),
                    )?;
                    self.push_statement(
                        &mut statements,
                        wir::SemanticStatement::Let(wir::LetStatement {
                            results: Vec::new(),
                            operation: wir::SemanticOperation::ActorStateStore {
                                actor: wir::ActorId(access.actor.0),
                                region: wir::RegionId(access.region.0),
                                value: result,
                                proof: wir::ProofId(access.capacity.0),
                            },
                            source: Some(statement_source),
                        }),
                    )?;
                }
                SourceStatementPlan::ActorStateStore { access, value } => {
                    if !statement_definitions.is_empty()
                        || access.function != self.function.id
                        || access.source != statement_source
                        || !matches!(
                            access.kind,
                            sema::ActorStateAccessKind::Write {
                                statement,
                                value_expression,
                                ..
                            } if statement == statement_id && value_expression == value
                        )
                    {
                        return Err(self.fact_mismatch("actor state store fact"));
                    }
                    let LoweredExpression::Value(value) =
                        self.lower_expression(value, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("actor state store value"));
                    };
                    self.push_statement(
                        &mut statements,
                        wir::SemanticStatement::Let(wir::LetStatement {
                            results: Vec::new(),
                            operation: wir::SemanticOperation::ActorStateStore {
                                actor: wir::ActorId(access.actor.0),
                                region: wir::RegionId(access.region.0),
                                value,
                                proof: wir::ProofId(access.capacity.0),
                            },
                            source: Some(statement_source),
                        }),
                    )?;
                }
                SourceStatementPlan::Expression(expression) => {
                    if !statement_definitions.is_empty() {
                        return Err(self.fact_mismatch("expression statement definitions"));
                    }
                    let _ = self.lower_expression(
                        expression,
                        sema::AccessMode::Value,
                        &mut statements,
                    )?;
                }
                SourceStatementPlan::Send(expression) => {
                    if !statement_definitions.is_empty() {
                        return Err(self.fact_mismatch("one-way send definitions"));
                    }
                    self.lower_actor_send(expression, &mut statements)?;
                }
                SourceStatementPlan::Return(expression) => {
                    if !statement_definitions.is_empty() {
                        return Err(self.fact_mismatch("return statement definitions"));
                    }
                    let values = match expression {
                        Some(expression) => {
                            let fact = self.expression_fact(expression)?;
                            if fact.ty != self.function.result {
                                return Err(self.fact_mismatch("return expression type"));
                            }
                            let LoweredExpression::Value(value) = self.lower_expression(
                                expression,
                                sema::AccessMode::Value,
                                &mut statements,
                            )?
                            else {
                                return Err(self.fact_mismatch("return expression value"));
                            };
                            one_value_vec(value, self.limits.model_edges)?
                        }
                        None if self.function.result == sema::SemanticTypeId(0) => Vec::new(),
                        None => return Err(unsupported("missing non-unit return value")),
                    };
                    self.push_statement(&mut statements, wir::SemanticStatement::Return(values))?;
                    returned = true;
                }
                SourceStatementPlan::Assert {
                    condition,
                    expression,
                    message,
                } => {
                    if !statement_definitions.is_empty()
                        || self.function.role != sema::FunctionRole::Test
                            && !matches!(
                                self.input.facts().root,
                                sema::AnalysisRoot::GeneratedTestHarness { .. }
                            )
                        || expression.is_empty()
                        || expression.len() > wir::ASSERTION_EXPRESSION_BYTES_MAX
                        || message.as_ref().is_some_and(|message| {
                            message.is_empty()
                                || message.len() > wir::ASSERTION_EXPRESSION_BYTES_MAX
                        })
                    {
                        return Err(self.fact_mismatch("runtime assertion descriptor"));
                    }
                    let condition_source = self
                        .input
                        .hir()
                        .as_program()
                        .expression(condition)
                        .map(|record| record.source)
                        .ok_or_else(|| self.fact_mismatch("runtime assertion condition"))?;
                    let condition_fact = self.expression_fact(condition)?;
                    if !matches!(
                        self.input
                            .facts()
                            .types
                            .get(condition_fact.ty.0 as usize)
                            .map(|ty| &ty.kind),
                        Some(sema::SemanticTypeKind::Bool)
                    ) {
                        return Err(self.fact_mismatch("runtime assertion condition type"));
                    }
                    let LoweredExpression::Value(condition) =
                        self.lower_expression(condition, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("runtime assertion condition value"));
                    };
                    self.push_effect(
                        &mut statements,
                        wir::SemanticOperation::Assert {
                            condition,
                            failure: wir::AssertionFailureDescriptor {
                                expression,
                                message,
                                source: condition_source,
                            },
                        },
                        Some(condition_source),
                    )?;
                }
                SourceStatementPlan::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let condition_fact = self.expression_fact(condition)?;
                    if !matches!(
                        self.input
                            .facts()
                            .types
                            .get(condition_fact.ty.0 as usize)
                            .map(|ty| &ty.kind),
                        Some(sema::SemanticTypeKind::Bool)
                    ) {
                        return Err(self.fact_mismatch("if condition type"));
                    }
                    let LoweredExpression::Value(condition) =
                        self.lower_expression(condition, sema::AccessMode::Value, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("if condition value"));
                    };
                    let before = local_state.copy(self.limits)?;
                    let mut then_state = before.copy(self.limits)?;
                    let mut then_region = self.lower_body(then_body, depth + 1, &mut then_state)?;
                    let mut else_state = before.copy(self.limits)?;
                    let mut else_region = match else_body {
                        Some(body) => self.lower_body(body, depth + 1, &mut else_state)?,
                        None => wir::SemanticRegion::default(),
                    };
                    let mut results = try_vec(
                        statement_definitions.len(),
                        "SemanticWir branch results",
                        self.limits.model_edges,
                    )?;
                    let mut then_values = try_vec(
                        statement_definitions.len(),
                        "SemanticWir then yield values",
                        self.limits.model_edges,
                    )?;
                    let mut else_values = try_vec(
                        statement_definitions.len(),
                        "SemanticWir else yield values",
                        self.limits.model_edges,
                    )?;
                    let mut definition_index = 0usize;
                    for (index, original) in before.values.iter().copied().enumerate() {
                        check_cancelled(self.is_cancelled)?;
                        let Some(original) = original else {
                            continue;
                        };
                        let then_value = then_state.values.get(index).copied().flatten();
                        let else_value = else_state.values.get(index).copied().flatten();
                        let (Some(then_value), Some(else_value)) = (then_value, else_value) else {
                            return Err(self.fact_mismatch("branch local initialization state"));
                        };
                        if then_value == else_value {
                            if statement_definitions
                                .get(definition_index)
                                .is_some_and(|definition| definition.local.0 as usize == index)
                            {
                                return Err(self.fact_mismatch("spurious branch result"));
                            }
                            local_state.values[index] = Some(then_value);
                            continue;
                        }
                        let definition = statement_definitions
                            .get(definition_index)
                            .filter(|definition| definition.local.0 as usize == index)
                            .ok_or_else(|| self.fact_mismatch("missing branch result"))?;
                        definition_index += 1;
                        let original_ty = self
                            .input
                            .facts()
                            .values
                            .get(original.0 as usize)
                            .map(|record| record.ty)
                            .ok_or_else(|| self.fact_mismatch("branch original value"))?;
                        for incoming in [then_value, else_value] {
                            if self
                                .input
                                .facts()
                                .values
                                .get(incoming.0 as usize)
                                .is_none_or(|record| {
                                    record.function != self.function.id
                                        || record.ty != original_ty
                                        || record.origin
                                            != sema::SemanticValueOrigin::Local(definition.local)
                                })
                            {
                                return Err(self.fact_mismatch("branch incoming value type"));
                            }
                        }
                        let result_record = self
                            .input
                            .facts()
                            .values
                            .get(definition.value.0 as usize)
                            .filter(|record| {
                                record.function == self.function.id
                                    && record.ty == original_ty
                                    && record.origin
                                        == sema::SemanticValueOrigin::Local(definition.local)
                            })
                            .ok_or_else(|| self.fact_mismatch("branch result value"))?;
                        let local_record = self
                            .input
                            .hir()
                            .as_program()
                            .locals
                            .get(definition.local.0 as usize)
                            .ok_or_else(|| self.fact_mismatch("branch result local"))?;
                        if result_record.source != Some(local_record.source)
                            || result_record.source_name.as_deref()
                                != Some(local_record.name.as_str())
                        {
                            return Err(self.fact_mismatch("branch result provenance"));
                        }
                        results.push(self.value_map.get(definition.value)?);
                        then_values.push(self.value_map.get(then_value)?);
                        else_values.push(self.value_map.get(else_value)?);
                        local_state.values[index] = Some(definition.value);
                    }
                    if definition_index != statement_definitions.len() {
                        return Err(self.fact_mismatch("extra branch results"));
                    }
                    if !results.is_empty() {
                        self.push_statement(
                            &mut then_region.statements,
                            wir::SemanticStatement::Yield(then_values),
                        )?;
                        self.push_statement(
                            &mut else_region.statements,
                            wir::SemanticStatement::Yield(else_values),
                        )?;
                    }
                    self.push_statement(
                        &mut statements,
                        wir::SemanticStatement::If {
                            condition,
                            then_region,
                            else_region,
                            results,
                            source: Some(statement_source),
                        },
                    )?;
                }
                SourceStatementPlan::While { condition, body } => {
                    let before = local_state.copy(self.limits)?;
                    if statement_definitions.len() % 2 != 0 {
                        return Err(self.fact_mismatch("loop carried local state"));
                    }
                    let arity = statement_definitions.len() / 2;
                    let mut headers = try_vec(
                        arity,
                        "SemanticWir loop header values",
                        self.limits.model_edges,
                    )?;
                    let mut exits = try_vec(
                        arity,
                        "SemanticWir loop exit values",
                        self.limits.model_edges,
                    )?;
                    let mut carried = try_vec(
                        arity.saturating_mul(3),
                        "SemanticWir loop carried values",
                        self.limits.model_edges,
                    )?;
                    for original in before.values.iter().copied().flatten() {
                        carried.push(self.value_map.get(original)?);
                    }
                    let mut header_state = before.copy(self.limits)?;
                    for definition in &statement_definitions[..arity] {
                        headers.push(self.value_map.get(definition.value)?);
                        header_state.set(definition.local, definition.value)?;
                    }
                    for definition in &statement_definitions[arity..] {
                        exits.push(self.value_map.get(definition.value)?);
                        local_state.set(definition.local, definition.value)?;
                    }
                    if carried.len() != arity {
                        return Err(self.fact_mismatch("loop carried local state"));
                    }
                    carried.extend_from_slice(&headers);
                    carried.extend_from_slice(&exits);
                    let mut header_statements = Vec::new();
                    let condition_fact = self.expression_fact(condition)?;
                    if !matches!(
                        self.input
                            .facts()
                            .types
                            .get(condition_fact.ty.0 as usize)
                            .map(|ty| &ty.kind),
                        Some(sema::SemanticTypeKind::Bool)
                    ) {
                        return Err(self.fact_mismatch("while condition type"));
                    }
                    let LoweredExpression::Value(condition_value) = self.lower_expression(
                        condition,
                        sema::AccessMode::Value,
                        &mut header_statements,
                    )?
                    else {
                        return Err(self.fact_mismatch("while condition value"));
                    };
                    let mut body_state = header_state.copy(self.limits)?;
                    let mut then_region = self.lower_body(body, depth + 2, &mut body_state)?;
                    if !matches!(
                        then_region.statements.last(),
                        Some(
                            wir::SemanticStatement::Break(_)
                                | wir::SemanticStatement::Continue(_)
                                | wir::SemanticStatement::Return(_)
                        )
                    ) {
                        let values = body_state
                            .values
                            .iter()
                            .copied()
                            .flatten()
                            .map(|value| self.value_map.get(value))
                            .collect::<Result<Vec<_>, _>>()?;
                        self.push_statement(
                            &mut then_region.statements,
                            wir::SemanticStatement::Continue(values),
                        )?;
                    }
                    let false_values = header_state
                        .values
                        .iter()
                        .copied()
                        .flatten()
                        .map(|value| self.value_map.get(value))
                        .collect::<Result<Vec<_>, _>>()?;
                    let else_region = wir::SemanticRegion {
                        parameters: Vec::new(),
                        statements: vec![wir::SemanticStatement::Break(false_values)],
                    };
                    self.push_statement(
                        &mut header_statements,
                        wir::SemanticStatement::If {
                            condition: condition_value,
                            then_region,
                            else_region,
                            results: Vec::new(),
                            source: Some(statement_source),
                        },
                    )?;
                    let bound = self
                        .input
                        .hir()
                        .as_program()
                        .expression(condition)
                        .and_then(|expression| match &expression.kind {
                            wrela_hir::ExpressionKind::Compare {
                                right,
                                operator: wrela_hir::ComparisonOperator::Less,
                                ..
                            } => self.input.hir().as_program().expression(*right),
                            _ => None,
                        })
                        .and_then(|expression| match &expression.kind {
                            wrela_hir::ExpressionKind::Literal(wrela_hir::Literal::Integer(
                                value,
                            )) => value.replace('_', "").parse::<u64>().ok(),
                            _ => None,
                        })
                        .ok_or_else(|| self.fact_mismatch("synchronous while bound"))?;
                    self.push_statement(
                        &mut statements,
                        wir::SemanticStatement::Loop {
                            body: wir::SemanticRegion {
                                parameters: headers,
                                statements: header_statements,
                            },
                            carried,
                            uninterrupted_bound: Some(bound),
                            source: Some(statement_source),
                        },
                    )?;
                }
                SourceStatementPlan::With {
                    value,
                    binding,
                    body,
                    activation,
                } => {
                    let state = match binding {
                        Some(local) => {
                            let [definition] = statement_definitions.as_slice() else {
                                return Err(self.fact_mismatch("with binding definition"));
                            };
                            if definition.local != local
                                || self.expression_fact(value)?.result != Some(definition.value)
                                || local_state.get(local).is_some()
                            {
                                return Err(self.fact_mismatch("with binding identity"));
                            }
                            local_state.set(local, definition.value)?;
                            self.lower_scope_acquisition(
                                value,
                                activation,
                                self.value_map.get(definition.value)?,
                                &mut statements,
                            )?
                        }
                        None => {
                            if !statement_definitions.is_empty() {
                                return Err(self.fact_mismatch("unbound with definitions"));
                            }
                            let result = self
                                .expression_fact(value)?
                                .result
                                .ok_or_else(|| self.fact_mismatch("with acquisition result"))?;
                            self.lower_scope_acquisition(
                                value,
                                activation,
                                self.value_map.get(result)?,
                                &mut statements,
                            )?
                        }
                    };
                    let mut lowered_body = self.lower_body(body, depth + 1, local_state)?;
                    if lowered_body.statements.iter().any(|statement| {
                        matches!(
                            statement,
                            wir::SemanticStatement::Return(_)
                                | wir::SemanticStatement::Break(_)
                                | wir::SemanticStatement::Continue(_)
                        )
                    }) {
                        return Err(unsupported(
                            "semantic-with-abnormal-cleanup-lowering-pending (lowered early exit)",
                        ));
                    }
                    for nested in lowered_body.statements.drain(..) {
                        self.push_statement(&mut statements, nested)?;
                    }
                    self.push_effect(
                        &mut statements,
                        wir::SemanticOperation::CommitScope {
                            scope: activation.scope,
                            value: state,
                        },
                        Some(statement_source),
                    )?;
                    self.push_effect(
                        &mut statements,
                        wir::SemanticOperation::ExitScope {
                            scope: activation.scope,
                        },
                        Some(statement_source),
                    )?;
                    if let Some(local) = binding {
                        local_state.set_empty(local)?;
                    }
                }
                SourceStatementPlan::Break | SourceStatementPlan::Continue => {
                    if !statement_definitions.is_empty() {
                        return Err(self.fact_mismatch("loop control definitions"));
                    }
                    let values = local_state
                        .values
                        .iter()
                        .copied()
                        .flatten()
                        .map(|value| self.value_map.get(value))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.push_statement(
                        &mut statements,
                        match statement {
                            SourceStatementPlan::Break => wir::SemanticStatement::Break(values),
                            SourceStatementPlan::Continue => {
                                wir::SemanticStatement::Continue(values)
                            }
                            _ => unreachable!(),
                        },
                    )?;
                    returned = true;
                }
                SourceStatementPlan::Match { scrutinee, arms } => {
                    let scrutinee_fact = self.expression_fact(scrutinee)?;
                    let (declaration, semantic_variants) = self
                        .input
                        .facts()
                        .types
                        .get(scrutinee_fact.ty.0 as usize)
                        .and_then(|record| match &record.kind {
                            sema::SemanticTypeKind::Enumeration {
                                declaration,
                                arguments,
                                variants,
                            } if supported_runtime_enum_type_arguments(arguments)
                                && variants
                                    .iter()
                                    .all(|variant| matches!(variant.fields.as_slice(), [_])) =>
                            {
                                Some((*declaration, variants))
                            }
                            _ => None,
                        })
                        .ok_or_else(|| self.fact_mismatch("match scrutinee enum type"))?;
                    let variant_count = semantic_variants.len();
                    let LoweredExpression::Value(scrutinee) =
                        self.lower_expression(scrutinee, sema::AccessMode::Read, &mut statements)?
                    else {
                        return Err(self.fact_mismatch("match scrutinee value"));
                    };
                    if arms.len() != variant_count {
                        return Err(self.fact_mismatch("match exhaustiveness"));
                    }
                    let mut lowered_arms = try_vec(
                        arms.len(),
                        "SemanticWir match arms",
                        self.limits.model_edges,
                    )?;
                    let mut used_definitions = 0usize;
                    let mut seen_variants = try_vec(
                        variant_count,
                        "SemanticWir match coverage",
                        self.limits.model_edges,
                    )?;
                    seen_variants.resize(variant_count, false);
                    let mut used_values = try_vec(
                        statement_definitions.len(),
                        "SemanticWir match binding identities",
                        self.limits.model_edges,
                    )?;
                    let mut all_return = true;
                    for arm in arms {
                        check_cancelled(self.is_cancelled)?;
                        if arm.guard.is_some() {
                            return Err(self.fact_mismatch("guarded runtime match arm"));
                        }
                        let pattern = self
                            .input
                            .hir()
                            .as_program()
                            .patterns
                            .get(arm.pattern.0 as usize)
                            .ok_or_else(|| self.fact_mismatch("match constructor pattern"))?;
                        let [alternative] = pattern.alternatives.as_slice() else {
                            return Err(self.fact_mismatch("match pattern alternatives"));
                        };
                        let wrela_hir::PrimaryPattern::Constructor {
                            candidates,
                            arguments,
                            ..
                        } = &alternative.kind
                        else {
                            return Err(self.fact_mismatch("constructor-only runtime match"));
                        };
                        let ([candidate], [argument]) =
                            (candidates.as_slice(), arguments.as_slice())
                        else {
                            return Err(self.fact_mismatch("match constructor identity"));
                        };
                        if candidate.enumeration.declaration != declaration || argument.take {
                            return Err(self.fact_mismatch("match constructor payload access"));
                        }
                        let payload_ty = semantic_variants
                            .get(candidate.variant as usize)
                            .and_then(|variant| variant.fields.first())
                            .map(|field| field.ty)
                            .ok_or_else(|| self.fact_mismatch("match variant payload type"))?;
                        let covered = seen_variants
                            .get_mut(candidate.variant as usize)
                            .ok_or_else(|| self.fact_mismatch("match variant range"))?;
                        if std::mem::replace(covered, true) {
                            return Err(self.fact_mismatch("duplicate match variant"));
                        }
                        let payload_pattern = self
                            .input
                            .hir()
                            .as_program()
                            .patterns
                            .get(argument.pattern.0 as usize)
                            .ok_or_else(|| self.fact_mismatch("match payload pattern"))?;
                        let [payload_alternative] = payload_pattern.alternatives.as_slice() else {
                            return Err(self.fact_mismatch("match payload alternatives"));
                        };
                        let wrela_hir::PrimaryPattern::Bind(local) = &payload_alternative.kind
                        else {
                            return Err(self.fact_mismatch("match payload binding"));
                        };
                        let mut matching = statement_definitions
                            .iter()
                            .filter(|definition| definition.local == *local);
                        let definition = matching
                            .next()
                            .ok_or_else(|| self.fact_mismatch("match binding definition"))?;
                        if matching.next().is_some() || used_values.contains(&definition.value) {
                            return Err(self.fact_mismatch("unique match binding definition"));
                        }
                        used_values.push(definition.value);
                        let local_record = self
                            .input
                            .hir()
                            .as_program()
                            .locals
                            .get(local.0 as usize)
                            .filter(|record| record.id == *local && record.body == arm.body)
                            .ok_or_else(|| self.fact_mismatch("match binding local ownership"))?;
                        let binding_record = self
                            .input
                            .facts()
                            .values
                            .get(definition.value.0 as usize)
                            .filter(|record| {
                                record.function == self.function.id
                                    && record.ty == payload_ty
                                    && record.origin == sema::SemanticValueOrigin::Local(*local)
                                    && record.source == Some(local_record.source)
                                    && record.source_name.as_deref()
                                        == Some(local_record.name.as_str())
                            })
                            .ok_or_else(|| self.fact_mismatch("match binding value provenance"))?;
                        let _ = binding_record;
                        used_definitions += 1;
                        let mut arm_state = local_state.copy(self.limits)?;
                        if arm_state.get(*local).is_some() {
                            return Err(self.fact_mismatch("match binding shadows live local"));
                        }
                        arm_state.set(*local, definition.value)?;
                        let mut body = self.lower_body(arm.body, depth + 1, &mut arm_state)?;
                        let binding = self.value_map.get(definition.value)?;
                        body.parameters = one_value_vec(binding, self.limits.model_edges)?;
                        let returns = self.body_definitely_returns(arm.body)?;
                        if !returns {
                            all_return = false;
                            self.push_statement(
                                &mut body.statements,
                                wir::SemanticStatement::Yield(Vec::new()),
                            )?;
                        }
                        lowered_arms.push(wir::SemanticMatchArm {
                            variant: Some(candidate.variant),
                            bindings: one_value_vec(binding, self.limits.model_edges)?,
                            guard: None,
                            body,
                        });
                    }
                    if used_definitions != statement_definitions.len() {
                        return Err(self.fact_mismatch("extra match definitions"));
                    }
                    if seen_variants.iter().any(|seen| !seen) {
                        return Err(self.fact_mismatch("missing match variant"));
                    }
                    self.push_statement(
                        &mut statements,
                        wir::SemanticStatement::Match {
                            scrutinee,
                            arms: lowered_arms,
                            results: Vec::new(),
                            source: Some(statement_source),
                        },
                    )?;
                    returned = all_return;
                }
            }
        }
        Ok(wir::SemanticRegion {
            parameters: Vec::new(),
            statements,
        })
    }

    fn lower_scope_acquisition(
        &mut self,
        expression_id: wrela_hir::ExpressionId,
        activation: ScopeActivationLowering,
        result: wir::ValueId,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<wir::ValueId, LowerError> {
        check_cancelled(self.is_cancelled)?;
        self.push_seen_expression(expression_id)?;
        let program = self.input.hir().as_program();
        let expression = program
            .expression(expression_id)
            .ok_or_else(|| self.fact_mismatch("scope acquisition expression"))?;
        let wrela_hir::ExpressionKind::Call { callee, arguments } = &expression.kind else {
            return Err(self.fact_mismatch("scope acquisition call"));
        };
        if !arguments.is_empty() {
            return Err(unsupported(
                "semantic-scope-parameter-lowering-pending (parameterized acquisition)",
            ));
        }
        let (fact_ty, fact_result, fact_protocol, bindings_empty) = {
            let fact = self.expression_fact(expression_id)?;
            let sema::ExpressionResolution::ScopeCall {
                protocol,
                arguments: bindings,
            } = &fact.resolution
            else {
                return Err(self.fact_mismatch("scope call resolution"));
            };
            (fact.ty, fact.result, *protocol, bindings.is_empty())
        };
        if fact_protocol != activation.protocol
            || !bindings_empty
            || fact_result
                .map(|value| self.value_map.get(value))
                .transpose()?
                != Some(result)
        {
            return Err(self.fact_mismatch("scope call activation identity"));
        }
        self.push_seen_expression(*callee)?;
        if !matches!(
            self.expression_fact(*callee)?.resolution,
            sema::ExpressionResolution::Scope(protocol) if protocol == activation.protocol
        ) {
            return Err(self.fact_mismatch("scope callee identity"));
        }
        let protocol = self
            .input
            .facts()
            .scope_protocols
            .get(activation.protocol.0 as usize)
            .filter(|protocol| protocol.id == activation.protocol && protocol.result == fact_ty)
            .ok_or_else(|| self.fact_mismatch("scope protocol result"))?;
        let enter = program
            .expression(protocol.enter)
            .ok_or_else(|| self.fact_mismatch("scope enter expression"))?;
        let wrela_hir::ExpressionKind::Call {
            callee: constructor,
            arguments: initializers,
        } = &enter.kind
        else {
            return Err(unsupported(
                "semantic-scope-enter-lowering-pending (non-aggregate state)",
            ));
        };
        let declaration = program
            .expression(*constructor)
            .and_then(|constructor| match &constructor.kind {
                wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                    declaration,
                )) => program.declaration(declaration.declaration),
                _ => None,
            })
            .ok_or_else(|| self.fact_mismatch("scope state constructor"))?;
        let wrela_hir::DeclarationKind::Structure(source_structure) = &declaration.kind else {
            return Err(self.fact_mismatch("scope state structure"));
        };
        let semantic_fields = self
            .input
            .facts()
            .types
            .get(fact_ty.0 as usize)
            .and_then(|ty| match &ty.kind {
                sema::SemanticTypeKind::Structure {
                    declaration: candidate,
                    arguments,
                    fields,
                } if *candidate == declaration.id && arguments.is_empty() => Some(fields),
                _ => None,
            })
            .ok_or_else(|| self.fact_mismatch("scope state semantic structure"))?;
        if semantic_fields.len() != source_structure.fields.len()
            || initializers.len() != semantic_fields.len()
        {
            return Err(self.fact_mismatch("scope state field arity"));
        }
        let mut fields = try_vec(
            semantic_fields.len(),
            "SemanticWir scope state fields",
            self.limits.model_edges,
        )?;
        for (source_index, initializer) in initializers.iter().enumerate() {
            check_cancelled(self.is_cancelled)?;
            let field_index = initializer
                .name
                .as_ref()
                .and_then(|name| {
                    source_structure
                        .fields
                        .iter()
                        .position(|field| field.name == *name)
                })
                .unwrap_or(source_index);
            let semantic_field = semantic_fields
                .get(field_index)
                .ok_or_else(|| self.fact_mismatch("scope state field index"))?;
            let wrela_hir::CallArgumentValue::Value(value) = initializer.value else {
                return Err(self.fact_mismatch("scope state field access"));
            };
            let literal = program
                .expression(value)
                .and_then(|expression| match &expression.kind {
                    wrela_hir::ExpressionKind::Literal(literal) => {
                        Some((literal, expression.source))
                    }
                    _ => None,
                })
                .ok_or_else(|| {
                    unsupported(
                        "semantic-scope-enter-lowering-pending (nested or parameter state field)",
                    )
                })?;
            let constant = lower_scope_literal(self.input.facts(), semantic_field.ty, literal.0)?;
            let field_value = self.allocate_synthetic_value(semantic_field.ty, literal.1)?;
            self.push_let(
                statements,
                field_value,
                wir::SemanticOperation::Constant(constant),
                Some(literal.1),
            )?;
            fields.push(field_value);
        }
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Aggregate {
                ty: wir::TypeId(fact_ty.0),
                fields,
            },
            Some(enter.source),
        )?;
        self.push_effect(
            statements,
            wir::SemanticOperation::EnterScope {
                scope: activation.scope,
                state: result,
            },
            Some(expression.source),
        )?;
        Ok(result)
    }

    fn allocate_synthetic_value(
        &mut self,
        ty: sema::SemanticTypeId,
        source: Span,
    ) -> Result<wir::ValueId, LowerError> {
        if u64::from(self.next_value) >= self.limits.values {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir scope state values",
                limit: self.limits.values,
            });
        }
        let id = wir::ValueId(self.next_value);
        self.next_value = self
            .next_value
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir scope state values",
                limit: self.limits.values,
            })?;
        push_bounded_id(
            &mut self.synthetic_values,
            wir::SemanticValue {
                id,
                ty: wir::TypeId(ty.0),
                origin: Some(source),
                name: None,
            },
            "SemanticWir scope state values",
            self.limits.values,
        )?;
        Ok(id)
    }

    fn lower_expression(
        &mut self,
        expression_id: wrela_hir::ExpressionId,
        requested_access: sema::AccessMode,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        check_cancelled(self.is_cancelled)?;
        self.push_seen_expression(expression_id)?;
        let (source, plan) = {
            let expression = self
                .input
                .hir()
                .as_program()
                .expression(expression_id)
                .ok_or(LowerError::MissingSemanticFact {
                    subject: self.function.name.clone(),
                    fact: "source expression",
                })?;
            let fact = self.expression_fact(expression_id)?;
            let actor_state_access = self
                .input
                .facts()
                .actor_state_accesses
                .iter()
                .find(|access| {
                    access.function == self.function.id
                        && matches!(
                            access.kind,
                            sema::ActorStateAccessKind::Read { expression, .. }
                                if expression == expression_id
                        )
                })
                .cloned();
            let expected_after = if requested_access == sema::AccessMode::Take {
                sema::OwnershipState::Taken
            } else {
                sema::OwnershipState::Owned
            };
            let expected_proofs = actor_state_access.as_ref().map(|access| {
                let mut proofs = self.function.proofs.clone();
                if !proofs.contains(&access.capacity) {
                    proofs.push(access.capacity);
                    proofs.sort_unstable();
                }
                proofs
            });
            if fact.category != sema::ValueCategory::Value
                || actor_state_access.as_ref().map_or_else(
                    || fact.region.is_some() || fact.proofs != self.function.proofs,
                    |access| {
                        fact.region != Some(access.region)
                            || expected_proofs.as_ref() != Some(&fact.proofs)
                            || fact.effects.0 != sema::EffectSet::ACTOR
                    },
                )
                || fact.ownership_before != sema::OwnershipState::Owned
                || fact.ownership_after != expected_after
            {
                return Err(self.fact_mismatch("scalar expression state"));
            }
            if matches!(
                requested_access,
                sema::AccessMode::Mutate | sema::AccessMode::Take
            ) && !matches!(
                expression.kind,
                wrela_hir::ExpressionKind::Reference(
                    wrela_hir::Definition::Local(_) | wrela_hir::Definition::Parameter(_)
                )
            ) {
                return Err(self.fact_mismatch("exclusive scalar operand"));
            }
            let plan = if let Some(access) = actor_state_access {
                if !matches!(
                    (&expression.kind, &fact.resolution, access.kind),
                    (
                        wrela_hir::ExpressionKind::Field { .. },
                        sema::ExpressionResolution::Field { index },
                        sema::ActorStateAccessKind::Read {
                            expression,
                            result,
                        },
                    ) if *index == access.field
                        && expression == expression_id
                        && fact.result == Some(result)
                ) {
                    return Err(self.fact_mismatch("actor state load fact"));
                }
                SourceExpressionPlan::ActorStateLoad(access)
            } else {
                match (&expression.kind, &fact.resolution) {
                    (
                        wrela_hir::ExpressionKind::Literal(literal),
                        sema::ExpressionResolution::Constant(constant),
                    ) => {
                        if fact.effects.0 != 0
                            || !constant_matches_literal(
                                self.input.facts(),
                                fact.ty,
                                literal,
                                constant,
                            )
                        {
                            return Err(self.fact_mismatch("scalar literal"));
                        }
                        SourceExpressionPlan::Constant {
                            value: lower_constant(constant)?,
                            ty: fact.ty,
                            result: fact
                                .result
                                .ok_or_else(|| self.fact_mismatch("literal result"))?,
                        }
                    }
                    (
                        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Local(local)),
                        sema::ExpressionResolution::Value(value),
                    ) => SourceExpressionPlan::Local(ValueReferenceInput {
                        expression: expression_id,
                        local: *local,
                        value: *value,
                        ty: fact.ty,
                        effects: fact.effects,
                        result: fact.result,
                        source: expression.source,
                    }),
                    (
                        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Parameter(
                            parameter,
                        )),
                        sema::ExpressionResolution::Value(value),
                    ) => SourceExpressionPlan::Parameter {
                        parameter: *parameter,
                        value: *value,
                        ty: fact.ty,
                        effects: fact.effects,
                        result: fact.result,
                    },
                    (
                        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                            source,
                        )),
                        sema::ExpressionResolution::Function(target),
                    ) => SourceExpressionPlan::Function {
                        source: wrela_hir::ResolvedDeclaration {
                            package: source.package,
                            module: source.module,
                            declaration: source.declaration,
                        },
                        target: *target,
                        ty: fact.ty,
                        effects: fact.effects,
                        result: fact.result,
                    },
                    (
                        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                            source,
                        )),
                        sema::ExpressionResolution::Constructor { ty, variant: None },
                    ) => SourceExpressionPlan::Constructor {
                        source: wrela_hir::ResolvedDeclaration {
                            package: source.package,
                            module: source.module,
                            declaration: source.declaration,
                        },
                        ty: *ty,
                        effects: fact.effects,
                        result: fact.result,
                    },
                    (
                        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Variant(
                            source,
                        )),
                        sema::ExpressionResolution::Constructor {
                            ty,
                            variant: Some(variant),
                        },
                    ) => SourceExpressionPlan::EnumConstructor {
                        source: source.clone(),
                        ty: *ty,
                        variant: *variant,
                        effects: fact.effects,
                        result: fact.result,
                    },
                    (
                        wrela_hir::ExpressionKind::Field { .. },
                        sema::ExpressionResolution::Constructor {
                            ty,
                            variant: Some(variant),
                        },
                    ) if resolved_enum_constructor_from_hir(
                        self.input.hir().as_program(),
                        expression_id,
                    )
                    .is_some_and(|source| source.variant == *variant) =>
                    {
                        let source = resolved_enum_constructor_from_hir(
                            self.input.hir().as_program(),
                            expression_id,
                        )
                        .ok_or_else(|| self.fact_mismatch("enum constructor source identity"))?;
                        SourceExpressionPlan::EnumConstructor {
                            source,
                            ty: *ty,
                            variant: *variant,
                            effects: fact.effects,
                            result: fact.result,
                        }
                    }
                    (
                        wrela_hir::ExpressionKind::Call { callee, arguments },
                        sema::ExpressionResolution::Constructor { ty, variant: None },
                    ) => SourceExpressionPlan::Aggregate(AggregateInput {
                        expression: expression_id,
                        source: expression.source,
                        callee: *callee,
                        source_argument_count: arguments.len(),
                        ty: *ty,
                        result: fact.result,
                        effects: fact.effects,
                    }),
                    (
                        wrela_hir::ExpressionKind::Call { callee, arguments },
                        sema::ExpressionResolution::Constructor {
                            ty,
                            variant: Some(variant),
                        },
                    ) if arguments.len() == 1 => {
                        SourceExpressionPlan::EnumAggregate(EnumAggregateInput {
                            expression: expression_id,
                            source: expression.source,
                            callee: *callee,
                            ty: *ty,
                            variant: *variant,
                            result: fact.result,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Field { base, .. },
                        sema::ExpressionResolution::Field { index },
                    ) => SourceExpressionPlan::Project(ProjectInput {
                        expression: expression_id,
                        source: expression.source,
                        base: *base,
                        field: *index,
                        ty: fact.ty,
                        result: fact.result,
                        effects: fact.effects,
                    }),
                    (
                        wrela_hir::ExpressionKind::Call { callee, arguments },
                        sema::ExpressionResolution::DirectCall {
                            function,
                            arguments: bindings,
                        },
                    ) => {
                        let mut copied_bindings = try_vec(
                            bindings.len(),
                            "direct-call semantic bindings",
                            self.limits.model_edges,
                        )?;
                        for binding in bindings {
                            check_cancelled(self.is_cancelled)?;
                            copied_bindings.push(*binding);
                        }
                        SourceExpressionPlan::DirectCall(DirectCallInput {
                            expression: expression_id,
                            source: expression.source,
                            callee: *callee,
                            source_argument_count: arguments.len(),
                            target: *function,
                            bindings: copied_bindings,
                            result_type: fact.ty,
                            result: fact.result,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Unary {
                            operator:
                                operator @ (wrela_hir::UnaryOperator::Negate
                                | wrela_hir::UnaryOperator::BitNot
                                | wrela_hir::UnaryOperator::BoolNot
                                | wrela_hir::UnaryOperator::Copy),
                            operand,
                        },
                        sema::ExpressionResolution::Value(value),
                    ) if fact.result == Some(*value) => {
                        SourceExpressionPlan::Unary(ScalarUnaryInput {
                            expression: expression_id,
                            operator: *operator,
                            operand: *operand,
                            ty: fact.ty,
                            result: *value,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Binary {
                            operator,
                            left,
                            right,
                        },
                        sema::ExpressionResolution::Value(value),
                    ) if !matches!(
                        operator,
                        wrela_hir::BinaryOperator::LogicalOr
                            | wrela_hir::BinaryOperator::LogicalAnd
                    ) && fact.result == Some(*value) =>
                    {
                        SourceExpressionPlan::Binary(ScalarBinaryInput {
                            expression: expression_id,
                            operator: ScalarBinaryOperator::Arithmetic(*operator),
                            left: *left,
                            right: *right,
                            ty: fact.ty,
                            result: *value,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Compare {
                            left,
                            operator,
                            right,
                        },
                        sema::ExpressionResolution::Value(value),
                    ) if !matches!(
                        operator,
                        wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn
                    ) && fact.result == Some(*value) =>
                    {
                        SourceExpressionPlan::Binary(ScalarBinaryInput {
                            expression: expression_id,
                            operator: ScalarBinaryOperator::Compare(*operator),
                            left: *left,
                            right: *right,
                            ty: fact.ty,
                            result: *value,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Binary {
                            operator,
                            left,
                            right,
                        },
                        sema::ExpressionResolution::OperatorCall {
                            function,
                            arguments,
                            raw_result,
                            negate,
                        },
                    ) if !matches!(
                        operator,
                        wrela_hir::BinaryOperator::LogicalOr
                            | wrela_hir::BinaryOperator::LogicalAnd
                    ) =>
                    {
                        let mut copied_bindings = try_vec(
                            arguments.len(),
                            "operator-call semantic bindings",
                            self.limits.model_edges,
                        )?;
                        for binding in arguments {
                            check_cancelled(self.is_cancelled)?;
                            copied_bindings.push(*binding);
                        }
                        SourceExpressionPlan::OperatorCall(OperatorCallInput {
                            expression: expression_id,
                            source: expression.source,
                            left: *left,
                            right: *right,
                            target: *function,
                            bindings: copied_bindings,
                            raw_result: *raw_result,
                            negate: *negate,
                            result_type: fact.ty,
                            result: fact.result,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Compare {
                            left,
                            operator,
                            right,
                        },
                        sema::ExpressionResolution::OperatorCall {
                            function,
                            arguments,
                            raw_result,
                            negate,
                        },
                    ) if !matches!(
                        operator,
                        wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn
                    ) =>
                    {
                        let mut copied_bindings = try_vec(
                            arguments.len(),
                            "operator-call semantic bindings",
                            self.limits.model_edges,
                        )?;
                        for binding in arguments {
                            check_cancelled(self.is_cancelled)?;
                            copied_bindings.push(*binding);
                        }
                        SourceExpressionPlan::OperatorCall(OperatorCallInput {
                            expression: expression_id,
                            source: expression.source,
                            left: *left,
                            right: *right,
                            target: *function,
                            bindings: copied_bindings,
                            raw_result: *raw_result,
                            negate: *negate,
                            result_type: fact.ty,
                            result: fact.result,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Cast { value: source, ty },
                        sema::ExpressionResolution::Value(value),
                    ) if fact.result == Some(*value)
                        && source_type_matches_semantic(self.input.facts(), ty, fact.ty) =>
                    {
                        SourceExpressionPlan::Convert(ScalarConvertInput {
                            expression: expression_id,
                            value: *source,
                            destination: fact.ty,
                            result: *value,
                            effects: fact.effects,
                        })
                    }
                    (
                        wrela_hir::ExpressionKind::Try(operand),
                        sema::ExpressionResolution::ResultTry {
                            result_type,
                            ok_variant,
                            err_variant,
                            ok_payload,
                            err_payload,
                            propagated,
                        },
                    ) => SourceExpressionPlan::ResultTry(ResultTryInput {
                        expression: expression_id,
                        source: expression.source,
                        operand: *operand,
                        payload_type: fact.ty,
                        result_type: *result_type,
                        ok_variant: *ok_variant,
                        err_variant: *err_variant,
                        ok_payload: *ok_payload,
                        err_payload: *err_payload,
                        propagated: *propagated,
                        result: fact
                            .result
                            .ok_or_else(|| self.fact_mismatch("postfix question result"))?,
                        effects: fact.effects,
                    }),
                    (
                        wrela_hir::ExpressionKind::Unary {
                            operator: wrela_hir::UnaryOperator::Await,
                            operand,
                        },
                        sema::ExpressionResolution::Builtin(sema::IntrinsicOperation::Await),
                    ) => SourceExpressionPlan::Await {
                        expression: expression_id,
                        operand: *operand,
                        ty: fact.ty,
                        result: fact
                            .result
                            .ok_or_else(|| self.fact_mismatch("await result"))?,
                        effects: fact.effects,
                    },
                    (
                        wrela_hir::ExpressionKind::If {
                            condition,
                            then_branch,
                            elif_branches,
                            else_branch,
                        },
                        sema::ExpressionResolution::Value(value),
                    ) if fact.result == Some(*value) => {
                        let mut copied_elifs = try_vec(
                            elif_branches.len(),
                            "inline if elif branches",
                            self.limits.model_edges,
                        )?;
                        copied_elifs.extend_from_slice(elif_branches);
                        SourceExpressionPlan::InlineIf(InlineIfInput {
                            expression: expression_id,
                            condition: *condition,
                            then_branch: *then_branch,
                            elif_branches: copied_elifs,
                            else_branch: *else_branch,
                            ty: fact.ty,
                            result: *value,
                            effects: fact.effects,
                        })
                    }
                    _ => {
                        return Err(unsupported(
                            "ordinary source expressions outside scalar bodies",
                        ));
                    }
                }
            };
            (expression.source, plan)
        };
        match plan {
            SourceExpressionPlan::Constant { value, ty, result } => {
                let result = self.lowered_expression_result(expression_id, result, ty, source)?;
                self.push_let(
                    statements,
                    result,
                    wir::SemanticOperation::Constant(value),
                    Some(source),
                )?;
                Ok(LoweredExpression::Value(result))
            }
            SourceExpressionPlan::Local(reference) => {
                self.lower_value_reference(reference, statements)
            }
            SourceExpressionPlan::Parameter {
                parameter,
                value,
                ty,
                effects,
                result,
            } => {
                let record = self
                    .input
                    .facts()
                    .values
                    .get(value.0 as usize)
                    .filter(|record| {
                        record.origin == sema::SemanticValueOrigin::Parameter(parameter)
                    })
                    .ok_or_else(|| self.fact_mismatch("parameter reference"))?;
                if record.function != self.function.id
                    || record.ty != ty
                    || record.category != sema::ValueCategory::Value
                    || effects.0 != 0
                {
                    return Err(self.fact_mismatch("parameter reference value"));
                }
                self.materialize_reference(expression_id, value, ty, result, source, statements)
            }
            SourceExpressionPlan::Function {
                source: source_declaration,
                target,
                ty,
                effects,
                result,
            } => {
                let target_record = self
                    .input
                    .facts()
                    .functions
                    .get(target.0 as usize)
                    .filter(|function| {
                        matches!(
                            function.origin,
                            sema::FunctionOrigin::Source {
                                declaration: origin_declaration,
                                ..
                            } if origin_declaration == source_declaration.declaration
                        )
                    })
                    .ok_or_else(|| self.fact_mismatch("function reference"))?;
                if result.is_some()
                    || effects.0 != 0
                    || target_record.role != sema::FunctionRole::Ordinary
                    || !resolved_declaration_matches_program(
                        self.input.hir().as_program(),
                        &source_declaration,
                    )
                    || !function_reference_type_matches(self.input.facts(), ty, target_record)
                {
                    return Err(self.fact_mismatch("function reference state"));
                }
                Ok(LoweredExpression::Function(target))
            }
            SourceExpressionPlan::Constructor {
                source: source_declaration,
                ty,
                effects,
                result,
            } => {
                let declaration = self
                    .input
                    .hir()
                    .resolved_declaration(&source_declaration)
                    .filter(|record| {
                        matches!(record.kind, wrela_hir::DeclarationKind::Structure(_))
                    })
                    .ok_or_else(|| self.fact_mismatch("structure constructor declaration"))?;
                let nominal_matches =
                    self.input
                        .facts()
                        .types
                        .get(ty.0 as usize)
                        .is_some_and(|record| {
                            matches!(
                                &record.kind,
                                sema::SemanticTypeKind::Structure {
                                    declaration: candidate,
                                    ..
                                } if *candidate == declaration.id
                            )
                        });
                if !nominal_matches || result.is_some() || effects.0 != 0 {
                    return Err(self.fact_mismatch("structure constructor reference state"));
                }
                Ok(LoweredExpression::Constructor(ty))
            }
            SourceExpressionPlan::EnumConstructor {
                source,
                ty,
                variant,
                effects,
                result,
            } => {
                let source_variant = self
                    .input
                    .hir()
                    .resolved_variant(&source)
                    .ok_or_else(|| self.fact_mismatch("enum constructor declaration"))?;
                let nominal_matches = self
                    .input
                    .facts()
                    .types
                    .get(ty.0 as usize)
                    .is_some_and(|record| {
                        matches!(&record.kind, sema::SemanticTypeKind::Enumeration {
                            declaration,
                            arguments,
                            variants,
                        } if *declaration == source.enumeration.declaration
                            && supported_runtime_enum_type_arguments(arguments)
                            && variants.get(variant as usize)
                                .is_some_and(|candidate| candidate.name == source_variant.name.as_str()))
                    });
                if !nominal_matches
                    || variant != source.variant
                    || result.is_some()
                    || effects.0 != 0
                {
                    return Err(self.fact_mismatch("enum constructor reference state"));
                }
                Ok(LoweredExpression::EnumConstructor(ty, variant))
            }
            SourceExpressionPlan::Aggregate(aggregate) => {
                self.lower_flat_aggregate(aggregate, statements)
            }
            SourceExpressionPlan::EnumAggregate(aggregate) => {
                self.lower_enum_aggregate(aggregate, statements)
            }
            SourceExpressionPlan::Project(project) => {
                self.lower_flat_projection(project, statements)
            }
            SourceExpressionPlan::ActorStateLoad(access) => {
                let expression = self
                    .input
                    .hir()
                    .as_program()
                    .expression(expression_id)
                    .ok_or_else(|| self.fact_mismatch("actor state load expression"))?;
                let wrela_hir::ExpressionKind::Field { base, .. } = expression.kind else {
                    return Err(self.fact_mismatch("actor state load expression kind"));
                };
                let base_fact = self.expression_fact(base)?;
                if !matches!(
                    self.input.hir().as_program().expression(base).map(|record| &record.kind),
                    Some(wrela_hir::ExpressionKind::Reference(
                        wrela_hir::Definition::Parameter(parameter)
                    )) if *parameter == access.receiver
                ) || base_fact.result.is_some()
                    || base_fact.region.is_some()
                    || base_fact.effects.0 != 0
                    || base_fact.proofs != self.function.proofs
                {
                    return Err(self.fact_mismatch("actor state receiver witness"));
                }
                self.push_seen_expression(base)?;
                let result = match access.kind {
                    sema::ActorStateAccessKind::Read { result, .. } => result,
                    sema::ActorStateAccessKind::Write { .. }
                    | sema::ActorStateAccessKind::CompoundAssign { .. } => {
                        return Err(self.fact_mismatch("actor state load kind"));
                    }
                };
                let ty = self.expression_fact(expression_id)?.ty;
                let result = self.lowered_expression_result(expression_id, result, ty, source)?;
                self.push_let(
                    statements,
                    result,
                    wir::SemanticOperation::ActorStateLoad {
                        actor: wir::ActorId(access.actor.0),
                        region: wir::RegionId(access.region.0),
                        proof: wir::ProofId(access.capacity.0),
                    },
                    Some(source),
                )?;
                Ok(LoweredExpression::Value(result))
            }
            SourceExpressionPlan::DirectCall(call) => self.lower_direct_call(call, statements),
            SourceExpressionPlan::OperatorCall(call) => self.lower_operator_call(call, statements),
            SourceExpressionPlan::Unary(unary) => {
                self.lower_scalar_unary(unary, source, statements)
            }
            SourceExpressionPlan::Binary(binary) => {
                self.lower_scalar_binary(binary, source, statements)
            }
            SourceExpressionPlan::Convert(convert) => {
                self.lower_scalar_convert(convert, source, statements)
            }
            SourceExpressionPlan::ResultTry(result_try) => {
                self.lower_result_try(result_try, statements)
            }
            SourceExpressionPlan::InlineIf(inline_if) => {
                self.lower_inline_if(inline_if, source, statements)
            }
            SourceExpressionPlan::Await {
                expression,
                operand,
                ty,
                result,
                effects,
            } => {
                if self.function.color != wrela_hir::FunctionColor::Async
                    || !matches!(
                        requested_access,
                        sema::AccessMode::Value | sema::AccessMode::Read
                    )
                {
                    return Err(self.fact_mismatch("await function color or access"));
                }
                let operand_fact = self.expression_fact(operand)?;
                let target = match operand_fact.resolution {
                    sema::ExpressionResolution::DirectCall {
                        function: target, ..
                    } => target,
                    _ => return Err(self.fact_mismatch("await direct activation")),
                };
                if self
                    .input
                    .facts()
                    .functions
                    .get(target.0 as usize)
                    .is_none_or(|target| target.color != wrela_hir::FunctionColor::Async)
                    || operand_fact.ty != ty
                    || effects.0 != operand_fact.effects.0 | sema::EffectSet::SUSPEND
                {
                    return Err(self.fact_mismatch("await semantic state"));
                }
                let LoweredExpression::Value(awaitable) =
                    self.lower_expression(operand, sema::AccessMode::Value, statements)?
                else {
                    return Err(self.fact_mismatch("await activation value"));
                };
                let result = self.lowered_expression_result(expression, result, ty, source)?;
                self.push_let(
                    statements,
                    result,
                    wir::SemanticOperation::Await { awaitable },
                    Some(source),
                )?;
                Ok(LoweredExpression::Value(result))
            }
        }
    }

    fn lower_actor_send(
        &mut self,
        expression_id: wrela_hir::ExpressionId,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<(), LowerError> {
        check_cancelled(self.is_cancelled)?;
        let expression = self
            .input
            .hir()
            .as_program()
            .expression(expression_id)
            .ok_or_else(|| self.fact_mismatch("one-way send source expression"))?;
        let wrela_hir::ExpressionKind::Call { callee, arguments } = &expression.kind else {
            return Err(self.fact_mismatch("one-way send call"));
        };
        if !arguments.is_empty() {
            return Err(unsupported("one-way send payloads outside unit messages"));
        }
        let callee_expression = self
            .input
            .hir()
            .as_program()
            .expression(*callee)
            .ok_or_else(|| self.fact_mismatch("one-way send callee"))?;
        let wrela_hir::ExpressionKind::Field { base, .. } = callee_expression.kind else {
            return Err(self.fact_mismatch("one-way send self method"));
        };
        let base_fact = self.expression_fact(base)?;
        let callee_fact = self.expression_fact(*callee)?;
        let send_fact = self.expression_fact(expression_id)?;
        let (actor, method, permit) = match send_fact.resolution {
            sema::ExpressionResolution::ActorRequest {
                actor,
                method,
                permit,
            } => (actor, method, permit),
            _ => return Err(self.fact_mismatch("one-way actor request")),
        };
        let reservation = send_fact
            .result
            .ok_or_else(|| self.fact_mismatch("one-way reservation value"))?;
        let reservation_type = self
            .input
            .facts()
            .types
            .get(send_fact.ty.0 as usize)
            .ok_or_else(|| self.fact_mismatch("one-way reservation type"))?;
        let target = self
            .input
            .facts()
            .functions
            .get(method.0 as usize)
            .ok_or_else(|| self.fact_mismatch("one-way target function"))?;
        let caller_task = match self.function.role {
            sema::FunctionRole::TaskEntry(task) => task,
            _ => return Err(self.fact_mismatch("one-way startup producer")),
        };
        let graph = self
            .input
            .facts()
            .graph
            .as_ref()
            .ok_or_else(|| self.fact_mismatch("one-way actor graph"))?;
        let owner = graph
            .tasks
            .get(caller_task.0 as usize)
            .and_then(|task| task.supervisor)
            .ok_or_else(|| self.fact_mismatch("one-way task owner"))?;
        let permit_record = self
            .input
            .facts()
            .proofs
            .get(permit.0 as usize)
            .ok_or_else(|| self.fact_mismatch("one-way admission proof"))?;
        let wiring_proof = self
            .input
            .facts()
            .proofs
            .iter()
            .find(|proof| proof.kind == sema::ProofKind::ActorAsIf)
            .map(|proof| proof.id);
        let cross_actor = graph.actors.len() == 2
            && owner == sema::ActorId(1)
            && actor == sema::ActorId(0)
            && wiring_proof.is_some()
            && self
                .input
                .facts()
                .proofs
                .iter()
                .filter(|proof| proof.kind == sema::ProofKind::ActorAsIf)
                .count()
                == 1;
        let base_is_wired_handle = cross_actor
            && matches!(
                base_fact.resolution,
                sema::ExpressionResolution::Field { index: 0 }
            )
            && base_fact.result.is_some();
        let capability_value = base_fact.result;
        if (owner != actor && !cross_actor)
            || target.role != sema::FunctionRole::ActorTurn(actor)
            || target.parameters.len() != 1
            || target.result != sema::SemanticTypeId(0)
            || reservation_type.kind != sema::SemanticTypeKind::Reservation
            || reservation_type.linearity != sema::Linearity::StrictLinear
            || send_fact.effects.0 != sema::EffectSet::ACTOR
            || send_fact.ownership_before != sema::OwnershipState::Owned
            || send_fact.ownership_after != sema::OwnershipState::Taken
            || permit_record.kind != sema::ProofKind::CapacityBound
            || permit_record.bound != Some(1)
            || permit_record.sources.as_slice() != [expression.source]
            || permit_record.depends_on.len() != 1
            || !matches!(
                callee_fact.resolution,
                sema::ExpressionResolution::Function(candidate) if candidate == method
            )
            || callee_fact.effects.0 != 0
            || callee_fact.result.is_some()
            || (!base_is_wired_handle
                && !matches!(base_fact.resolution, sema::ExpressionResolution::Value(_)))
            || base_fact.effects.0 != 0
            || (!base_is_wired_handle && base_fact.result.is_some())
        {
            return Err(self.fact_mismatch("one-way send semantic contract"));
        }
        if base_is_wired_handle {
            let receiver = self
                .input
                .hir()
                .as_program()
                .expression(base)
                .and_then(|expression| match expression.kind {
                    wrela_hir::ExpressionKind::Field { base, .. } => Some(base),
                    _ => None,
                })
                .ok_or_else(|| self.fact_mismatch("image-wired actor handle receiver"))?;
            self.push_seen_expression(receiver)?;
        }
        self.push_seen_expression(base)?;
        self.push_seen_expression(*callee)?;
        self.push_seen_expression(expression_id)?;
        if base_is_wired_handle {
            let capability = capability_value
                .ok_or_else(|| self.fact_mismatch("image-wired actor capability value"))?;
            let capability = self.value_map.get(capability)?;
            let wiring_proof = wiring_proof
                .ok_or_else(|| self.fact_mismatch("image-wired actor capability proof"))?;
            self.push_let(
                statements,
                capability,
                wir::SemanticOperation::ActorCapability {
                    actor: wir::ActorId(actor.0),
                    wiring_proof: wir::ProofId(wiring_proof.0),
                },
                Some(expression.source),
            )?;
        }
        let reservation = self.value_map.get(reservation)?;
        self.push_let(
            statements,
            reservation,
            wir::SemanticOperation::ActorReserve {
                actor: wir::ActorId(actor.0),
                method: wir::FunctionId(method.0),
                permit_proof: wir::ProofId(permit.0),
            },
            Some(expression.source),
        )?;
        self.push_effect(
            statements,
            wir::SemanticOperation::ActorCommit {
                reservation,
                arguments: Vec::new(),
            },
            Some(expression.source),
        )
    }

    fn lower_scalar_unary(
        &mut self,
        unary: ScalarUnaryInput,
        source: Span,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let operand_fact = self.expression_fact(unary.operand)?;
        if operand_fact.ty != unary.ty || operand_fact.effects != unary.effects {
            return Err(self.fact_mismatch("scalar unary operand facts"));
        }
        if unary.operator == wrela_hir::UnaryOperator::Copy {
            if !self
                .input
                .facts()
                .types
                .get(unary.ty.0 as usize)
                .is_some_and(|ty| {
                    matches!(
                        ty.linearity,
                        sema::Linearity::ExplicitCopy | sema::Linearity::ScalarCopy
                    )
                })
            {
                return Err(self.fact_mismatch("explicit-copy unary type"));
            }
            let LoweredExpression::Value(operand) =
                self.lower_expression(unary.operand, sema::AccessMode::Value, statements)?
            else {
                return Err(self.fact_mismatch("explicit-copy unary operand value"));
            };
            let result =
                self.lowered_expression_result(unary.expression, unary.result, unary.ty, source)?;
            self.push_let(
                statements,
                result,
                wir::SemanticOperation::Copy { value: operand },
                Some(source),
            )?;
            return Ok(LoweredExpression::Value(result));
        }
        let kind = source_scalar_kind(self.input.facts(), unary.ty)
            .ok_or_else(|| self.fact_mismatch("scalar unary type"))?;
        let operator = match (unary.operator, kind) {
            (
                wrela_hir::UnaryOperator::Negate,
                SourceScalarKind::Integer { signed: true } | SourceScalarKind::Float,
            ) => wir::UnaryOperator::Negate,
            (wrela_hir::UnaryOperator::BitNot, SourceScalarKind::Integer { .. }) => {
                wir::UnaryOperator::BitNot
            }
            (wrela_hir::UnaryOperator::BoolNot, SourceScalarKind::Bool) => {
                wir::UnaryOperator::BoolNot
            }
            _ => return Err(self.fact_mismatch("scalar unary operator type")),
        };
        let LoweredExpression::Value(operand) =
            self.lower_expression(unary.operand, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("scalar unary operand value"));
        };
        let result =
            self.lowered_expression_result(unary.expression, unary.result, unary.ty, source)?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Unary {
                operator,
                operand,
                arithmetic: wir::ArithmeticMode::Checked,
            },
            Some(source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_scalar_binary(
        &mut self,
        binary: ScalarBinaryInput,
        source: Span,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let left_fact = self.expression_fact(binary.left)?;
        let right_fact = self.expression_fact(binary.right)?;
        let left_ty = left_fact.ty;
        let right_ty = right_fact.ty;
        let effects = sema::EffectSet(left_fact.effects.0 | right_fact.effects.0);
        if left_ty != right_ty || effects != binary.effects {
            return Err(self.fact_mismatch("scalar binary operand facts"));
        }
        let operand_kind = source_scalar_kind(self.input.facts(), left_ty)
            .ok_or_else(|| self.fact_mismatch("scalar binary operand type"))?;
        let (operator, arithmetic, result_matches) = match binary.operator {
            ScalarBinaryOperator::Arithmetic(operator) => {
                let (operator, arithmetic) = lower_source_arithmetic_operator(operator)
                    .ok_or_else(|| self.fact_mismatch("scalar binary operator"))?;
                (
                    operator,
                    arithmetic,
                    matches!(operand_kind, SourceScalarKind::Integer { .. })
                        && binary.ty == left_ty,
                )
            }
            ScalarBinaryOperator::Compare(operator) => (
                lower_source_comparison_operator(operator)
                    .ok_or_else(|| self.fact_mismatch("scalar comparison operator"))?,
                wir::ArithmeticMode::Checked,
                source_scalar_kind(self.input.facts(), binary.ty) == Some(SourceScalarKind::Bool)
                    && match operand_kind {
                        SourceScalarKind::Bool => matches!(
                            operator,
                            wrela_hir::ComparisonOperator::Equal
                                | wrela_hir::ComparisonOperator::NotEqual
                        ),
                        SourceScalarKind::Integer { .. } | SourceScalarKind::Float => true,
                    },
            ),
        };
        if !result_matches {
            return Err(self.fact_mismatch("scalar binary result type"));
        }
        let LoweredExpression::Value(left) =
            self.lower_expression(binary.left, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("scalar binary left value"));
        };
        let LoweredExpression::Value(right) =
            self.lower_expression(binary.right, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("scalar binary right value"));
        };
        let result =
            self.lowered_expression_result(binary.expression, binary.result, binary.ty, source)?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Binary {
                operator,
                left,
                right,
                arithmetic,
            },
            Some(source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_scalar_convert(
        &mut self,
        convert: ScalarConvertInput,
        source: Span,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let source_fact = self.expression_fact(convert.value)?;
        if source_fact.effects != convert.effects
            || !matches!(
                source_scalar_kind(self.input.facts(), source_fact.ty),
                Some(SourceScalarKind::Integer { .. } | SourceScalarKind::Float)
            )
            || !matches!(
                source_scalar_kind(self.input.facts(), convert.destination),
                Some(SourceScalarKind::Integer { .. } | SourceScalarKind::Float)
            )
        {
            return Err(self.fact_mismatch("checked scalar conversion facts"));
        }
        let LoweredExpression::Value(value) =
            self.lower_expression(convert.value, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("checked scalar conversion value"));
        };
        let result = self.lowered_expression_result(
            convert.expression,
            convert.result,
            convert.destination,
            source,
        )?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Convert {
                value,
                destination: wir::TypeId(convert.destination.0),
                checked: true,
            },
            Some(source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_result_try(
        &mut self,
        result_try: ResultTryInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let operand_fact = self.expression_fact(result_try.operand)?;
        if operand_fact.ty != result_try.result_type
            || operand_fact.result.is_none()
            || matches!(
                operand_fact.resolution,
                sema::ExpressionResolution::Value(_)
            )
            || operand_fact.effects != result_try.effects
            || self.function.result != result_try.result_type
        {
            return Err(self.fact_mismatch("postfix question operand and enclosing result"));
        }
        let (declaration, variants) = self
            .input
            .facts()
            .types
            .get(result_try.result_type.0 as usize)
            .and_then(|record| match &record.kind {
                sema::SemanticTypeKind::Enumeration {
                    declaration,
                    arguments,
                    variants,
                } if supported_core_result_arguments(arguments, variants) => {
                    Some((*declaration, variants))
                }
                _ => None,
            })
            .ok_or_else(|| self.fact_mismatch("postfix question Result type"))?;
        let declaration_record = self
            .input
            .hir()
            .as_program()
            .declaration(declaration)
            .ok_or_else(|| self.fact_mismatch("postfix question Result declaration"))?;
        let module = self
            .input
            .hir()
            .as_program()
            .modules
            .get(declaration_record.module.0 as usize)
            .ok_or_else(|| self.fact_mismatch("postfix question Result module"))?;
        if declaration_record.visibility != wrela_hir::Visibility::Public
            || declaration_record
                .name
                .as_ref()
                .is_none_or(|name| name.as_str() != "Result")
            || module.path.dotted() != "result"
            || result_try.ok_variant != 0
            || result_try.err_variant != 1
            || variants.len() != 2
            || variants[0].name != "Ok"
            || variants[1].name != "Err"
            || variants[0]
                .fields
                .first()
                .is_none_or(|field| field.ty != result_try.payload_type)
            || variants[1]
                .fields
                .first()
                .is_none_or(|field| field.ty != result_try.payload_type)
        {
            return Err(self.fact_mismatch("postfix question canonical Result identity"));
        }
        let internal = |value: sema::ValueId, ty: sema::SemanticTypeId| {
            self.input
                .facts()
                .values
                .get(value.0 as usize)
                .filter(|record| {
                    record.function == self.function.id
                        && record.ty == ty
                        && record.category == sema::ValueCategory::Value
                        && record.origin
                            == sema::SemanticValueOrigin::Expression(result_try.expression)
                        && record.source == Some(result_try.source)
                        && record.source_name.is_none()
                })
                .map(|_| self.value_map.get(value))
                .transpose()
                .ok()
                .flatten()
        };
        let ok_payload = internal(result_try.ok_payload, result_try.payload_type)
            .ok_or_else(|| self.fact_mismatch("postfix question Ok payload"))?;
        let err_payload = internal(result_try.err_payload, result_try.payload_type)
            .ok_or_else(|| self.fact_mismatch("postfix question Err payload"))?;
        let propagated = internal(result_try.propagated, result_try.result_type)
            .ok_or_else(|| self.fact_mismatch("postfix question propagated Err"))?;
        let result = self.lowered_expression_result(
            result_try.expression,
            result_try.result,
            result_try.payload_type,
            result_try.source,
        )?;
        let LoweredExpression::Value(operand) =
            self.lower_expression(result_try.operand, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("postfix question operand value"));
        };
        let mut ok_statements = try_vec(1, "postfix question Ok arm", self.limits.model_edges)?;
        self.push_statement(
            &mut ok_statements,
            wir::SemanticStatement::Yield(one_value_vec(ok_payload, self.limits.model_edges)?),
        )?;
        let mut err_statements = try_vec(2, "postfix question Err arm", self.limits.model_edges)?;
        self.push_let(
            &mut err_statements,
            propagated,
            wir::SemanticOperation::ConstructEnum {
                ty: wir::TypeId(result_try.result_type.0),
                variant: result_try.err_variant,
                payload: err_payload,
            },
            Some(result_try.source),
        )?;
        self.push_statement(
            &mut err_statements,
            wir::SemanticStatement::Return(one_value_vec(propagated, self.limits.model_edges)?),
        )?;
        let mut arms = try_vec(2, "postfix question match arms", self.limits.model_edges)?;
        arms.push(wir::SemanticMatchArm {
            variant: Some(result_try.ok_variant),
            bindings: one_value_vec(ok_payload, self.limits.model_edges)?,
            guard: None,
            body: wir::SemanticRegion {
                parameters: one_value_vec(ok_payload, self.limits.model_edges)?,
                statements: ok_statements,
            },
        });
        arms.push(wir::SemanticMatchArm {
            variant: Some(result_try.err_variant),
            bindings: one_value_vec(err_payload, self.limits.model_edges)?,
            guard: None,
            body: wir::SemanticRegion {
                parameters: one_value_vec(err_payload, self.limits.model_edges)?,
                statements: err_statements,
            },
        });
        self.push_statement(
            statements,
            wir::SemanticStatement::Match {
                scrutinee: operand,
                arms,
                results: one_value_vec(result, self.limits.model_edges)?,
                source: Some(result_try.source),
            },
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_inline_if(
        &mut self,
        inline_if: InlineIfInput,
        source: Span,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        if !inline_if.elif_branches.is_empty() {
            return Err(unsupported(
                "inline `if` elif chains in ordinary source lowering",
            ));
        }
        let result = self.lowered_expression_result(
            inline_if.expression,
            inline_if.result,
            inline_if.ty,
            source,
        )?;
        let condition_fact = self.expression_fact(inline_if.condition)?;
        let then_fact = self.expression_fact(inline_if.then_branch)?;
        let else_fact = self.expression_fact(inline_if.else_branch)?;
        let mut expected_effects = condition_fact.effects;
        expected_effects.0 |= then_fact.effects.0;
        expected_effects.0 |= else_fact.effects.0;
        if then_fact.ty != inline_if.ty
            || else_fact.ty != inline_if.ty
            || expected_effects.0 != inline_if.effects.0
        {
            return Err(self.fact_mismatch("inline if arm types or effects"));
        }
        let LoweredExpression::Value(condition) =
            self.lower_expression(inline_if.condition, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("inline if condition value"));
        };
        let mut then_statements = try_vec(2, "inline if then region", self.limits.model_edges)?;
        let LoweredExpression::Value(then_value) = self.lower_expression(
            inline_if.then_branch,
            sema::AccessMode::Value,
            &mut then_statements,
        )?
        else {
            return Err(self.fact_mismatch("inline if then value"));
        };
        self.push_statement(
            &mut then_statements,
            wir::SemanticStatement::Yield(one_value_vec(then_value, self.limits.model_edges)?),
        )?;
        let mut else_statements = try_vec(2, "inline if else region", self.limits.model_edges)?;
        let LoweredExpression::Value(else_value) = self.lower_expression(
            inline_if.else_branch,
            sema::AccessMode::Value,
            &mut else_statements,
        )?
        else {
            return Err(self.fact_mismatch("inline if else value"));
        };
        self.push_statement(
            &mut else_statements,
            wir::SemanticStatement::Yield(one_value_vec(else_value, self.limits.model_edges)?),
        )?;
        self.push_statement(
            statements,
            wir::SemanticStatement::If {
                condition,
                then_region: wir::SemanticRegion {
                    parameters: Vec::new(),
                    statements: then_statements,
                },
                else_region: wir::SemanticRegion {
                    parameters: Vec::new(),
                    statements: else_statements,
                },
                results: one_value_vec(result, self.limits.model_edges)?,
                source: Some(source),
            },
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_value_reference(
        &mut self,
        reference: ValueReferenceInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let record = self
            .input
            .facts()
            .values
            .get(reference.value.0 as usize)
            .filter(|record| record.origin == sema::SemanticValueOrigin::Local(reference.local))
            .ok_or_else(|| self.fact_mismatch("local reference"))?;
        if record.function != self.function.id
            || record.ty != reference.ty
            || record.category != sema::ValueCategory::Value
            || reference.effects.0 != 0
        {
            return Err(self.fact_mismatch("local reference value"));
        }
        let local_record = self
            .input
            .hir()
            .as_program()
            .locals
            .get(reference.local.0 as usize)
            .filter(|local_record| local_record.id == reference.local)
            .ok_or_else(|| self.fact_mismatch("local reference provenance"))?;
        if record.source != Some(local_record.source)
            || record.source_name.as_deref() != Some(local_record.name.as_str())
        {
            return Err(self.fact_mismatch("local reference provenance"));
        }
        self.materialize_reference(
            reference.expression,
            reference.value,
            reference.ty,
            reference.result,
            reference.source,
            statements,
        )
    }

    fn materialize_reference(
        &mut self,
        expression: wrela_hir::ExpressionId,
        value: sema::ValueId,
        ty: sema::SemanticTypeId,
        result: Option<sema::ValueId>,
        source: Span,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let source_value = self.value_map.get(value)?;
        if let Some(result) = result {
            let result = self.lowered_expression_result(expression, result, ty, source)?;
            self.push_let(
                statements,
                result,
                wir::SemanticOperation::Copy {
                    value: source_value,
                },
                Some(source),
            )?;
            Ok(LoweredExpression::Value(result))
        } else {
            Ok(LoweredExpression::Value(source_value))
        }
    }

    fn lowered_expression_result(
        &self,
        expression: wrela_hir::ExpressionId,
        result: sema::ValueId,
        ty: sema::SemanticTypeId,
        source: Span,
    ) -> Result<wir::ValueId, LowerError> {
        let record = self
            .input
            .facts()
            .values
            .get(result.0 as usize)
            .filter(|record| {
                record.function == self.function.id
                    && record.ty == ty
                    && record.category == sema::ValueCategory::Value
            })
            .ok_or_else(|| self.fact_mismatch("expression result value"))?;
        let provenance_matches = match record.origin {
            sema::SemanticValueOrigin::Expression(origin) => {
                origin == expression
                    && record.source == Some(source)
                    && record.source_name.is_none()
            }
            sema::SemanticValueOrigin::Local(local) => self
                .input
                .hir()
                .as_program()
                .locals
                .get(local.0 as usize)
                .is_some_and(|local_record| {
                    local_record.id == local
                        && record.source == Some(local_record.source)
                        && record.source_name.as_deref() == Some(local_record.name.as_str())
                }),
            sema::SemanticValueOrigin::Parameter(_)
            | sema::SemanticValueOrigin::ActorStateLoad(_)
            | sema::SemanticValueOrigin::ActorStateCompoundResult(_) => false,
        };
        if !provenance_matches {
            return Err(self.fact_mismatch("expression result provenance"));
        }
        self.value_map.get(result)
    }

    fn lower_flat_aggregate(
        &mut self,
        aggregate: AggregateInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let LoweredExpression::Constructor(callee_ty) =
            self.lower_expression(aggregate.callee, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("structure constructor callee"));
        };
        if callee_ty != aggregate.ty {
            return Err(self.fact_mismatch("structure constructor nominal type"));
        }
        let (declaration, arguments, semantic_fields) = match self
            .input
            .facts()
            .types
            .get(aggregate.ty.0 as usize)
            .map(|record| &record.kind)
        {
            Some(sema::SemanticTypeKind::Structure {
                declaration,
                arguments,
                fields,
            }) => (*declaration, arguments, fields),
            _ => return Err(self.fact_mismatch("flat structure semantic type")),
        };
        let declaration_record = self
            .input
            .hir()
            .as_program()
            .declaration(declaration)
            .ok_or_else(|| self.fact_mismatch("flat structure declaration"))?;
        let wrela_hir::DeclarationKind::Structure(source_structure) = &declaration_record.kind
        else {
            return Err(self.fact_mismatch("flat structure declaration kind"));
        };
        if aggregate.source_argument_count != semantic_fields.len()
            || source_structure.fields.len() != semantic_fields.len()
            || !generic_structure_source_generics_match(
                self.input.hir().as_program(),
                declaration_record,
                source_structure,
                arguments,
            )
        {
            return Err(self.fact_mismatch("structure constructor field arity"));
        }
        for (source, semantic) in source_structure.fields.iter().zip(semantic_fields) {
            check_cancelled(self.is_cancelled)?;
            if source.name.as_str() != semantic.name
                || (source.visibility != wrela_hir::Visibility::Private) != semantic.public
                || source.default.is_some()
                || !source.attributes.is_empty()
                || !generic_structure_source_field_matches(
                    self.input.facts(),
                    source_structure,
                    arguments,
                    &source.ty,
                    semantic.ty,
                )
            {
                return Err(self.fact_mismatch("structure field semantic identity"));
            }
        }

        let mut operands = try_vec(
            aggregate.source_argument_count,
            "structure constructor source operands",
            self.limits.model_edges,
        )?;
        let mut effects = sema::EffectSet(0);
        for source_index in 0..aggregate.source_argument_count {
            check_cancelled(self.is_cancelled)?;
            let argument = self.call_argument(aggregate.expression, source_index)?;
            let Some(argument_value) = argument.expression() else {
                return Err(self.fact_mismatch("structure constructor field access"));
            };
            let LoweredExpression::Value(value) =
                self.lower_expression(argument_value, sema::AccessMode::Value, statements)?
            else {
                return Err(self.fact_mismatch("structure constructor field value"));
            };
            effects.0 |= self.expression_fact(argument_value)?.effects.0;
            operands.push(value);
        }
        if effects != aggregate.effects {
            return Err(self.fact_mismatch("structure constructor effects"));
        }
        let mut ordered = try_vec(
            semantic_fields.len(),
            "SemanticWir structure fields",
            self.limits.model_edges,
        )?;
        for _ in semantic_fields {
            check_cancelled(self.is_cancelled)?;
            ordered.push(None);
        }
        for source_index in 0..aggregate.source_argument_count {
            check_cancelled(self.is_cancelled)?;
            let argument = self
                .input
                .hir()
                .as_program()
                .expression(aggregate.expression)
                .and_then(|expression| match &expression.kind {
                    wrela_hir::ExpressionKind::Call { arguments, .. } => {
                        arguments.get(source_index)
                    }
                    _ => None,
                })
                .ok_or_else(|| self.fact_mismatch("structure constructor source argument"))?;
            let Some(argument_value) = argument.expression() else {
                return Err(self.fact_mismatch("structure constructor field access"));
            };
            let field_index = if let Some(name) = &argument.name {
                let mut selected = None;
                for (index, field) in semantic_fields.iter().enumerate() {
                    check_cancelled(self.is_cancelled)?;
                    self.aggregate_name_work = self.aggregate_name_work.checked_add(1).ok_or(
                        LowerError::ResourceLimit {
                            resource: "structure constructor name lookup work",
                            limit: self.limits.model_edges,
                        },
                    )?;
                    if self.aggregate_name_work > self.limits.model_edges {
                        return Err(LowerError::ResourceLimit {
                            resource: "structure constructor name lookup work",
                            limit: self.limits.model_edges,
                        });
                    }
                    if field.name == name.as_str() && selected.replace(index).is_some() {
                        return Err(self.fact_mismatch("ambiguous structure constructor field"));
                    }
                }
                selected.ok_or_else(|| self.fact_mismatch("structure constructor field name"))?
            } else {
                source_index
            };
            let field = semantic_fields
                .get(field_index)
                .ok_or_else(|| self.fact_mismatch("structure constructor field index"))?;
            if self.expression_fact(argument_value)?.ty != field.ty {
                return Err(self.fact_mismatch("structure constructor field type"));
            }
            let slot = ordered
                .get_mut(field_index)
                .ok_or_else(|| self.fact_mismatch("structure constructor field slot"))?;
            if slot
                .replace(
                    *operands
                        .get(source_index)
                        .ok_or_else(|| self.fact_mismatch("structure constructor operand"))?,
                )
                .is_some()
            {
                return Err(self.fact_mismatch("duplicate structure constructor field"));
            }
        }
        let mut fields = try_vec(
            ordered.len(),
            "SemanticWir structure fields",
            self.limits.model_edges,
        )?;
        for value in ordered {
            check_cancelled(self.is_cancelled)?;
            fields.push(
                value.ok_or_else(|| self.fact_mismatch("missing structure constructor field"))?,
            );
        }
        let result = aggregate
            .result
            .ok_or_else(|| self.fact_mismatch("structure constructor result"))?;
        let result = self.lowered_expression_result(
            aggregate.expression,
            result,
            aggregate.ty,
            aggregate.source,
        )?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Aggregate {
                ty: wir::TypeId(aggregate.ty.0),
                fields,
            },
            Some(aggregate.source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_enum_aggregate(
        &mut self,
        aggregate: EnumAggregateInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let LoweredExpression::EnumConstructor(callee_ty, callee_variant) =
            self.lower_expression(aggregate.callee, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("enum constructor callee"));
        };
        if callee_ty != aggregate.ty || callee_variant != aggregate.variant {
            return Err(self.fact_mismatch("enum constructor nominal identity"));
        }
        let payload_ty = self
            .input
            .facts()
            .types
            .get(aggregate.ty.0 as usize)
            .and_then(|record| match &record.kind {
                sema::SemanticTypeKind::Enumeration {
                    arguments,
                    variants,
                    ..
                } if supported_runtime_enum_type_arguments(arguments) => variants
                    .get(aggregate.variant as usize)
                    .and_then(|variant| variant.fields.first())
                    .map(|field| field.ty),
                _ => None,
            })
            .ok_or_else(|| self.fact_mismatch("closed enum semantic type"))?;
        let argument = self.call_argument(aggregate.expression, 0)?;
        if argument.name.is_some() {
            return Err(self.fact_mismatch("enum constructor positional payload"));
        }
        let Some(argument_value) = argument.expression() else {
            return Err(self.fact_mismatch("enum constructor payload access"));
        };
        let argument_fact = self.expression_fact(argument_value)?;
        if argument_fact.ty != payload_ty || argument_fact.effects != aggregate.effects {
            return Err(self.fact_mismatch("enum constructor payload facts"));
        }
        let LoweredExpression::Value(payload) =
            self.lower_expression(argument_value, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("enum constructor payload value"));
        };
        let result = aggregate
            .result
            .ok_or_else(|| self.fact_mismatch("enum constructor result"))?;
        let result = self.lowered_expression_result(
            aggregate.expression,
            result,
            aggregate.ty,
            aggregate.source,
        )?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::ConstructEnum {
                ty: wir::TypeId(aggregate.ty.0),
                variant: aggregate.variant,
                payload,
            },
            Some(aggregate.source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_flat_projection(
        &mut self,
        project: ProjectInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let base_fact = self.expression_fact(project.base)?;
        let fields = match self
            .input
            .facts()
            .types
            .get(base_fact.ty.0 as usize)
            .map(|record| &record.kind)
        {
            Some(sema::SemanticTypeKind::Structure { fields, .. }) => fields,
            _ => return Err(self.fact_mismatch("flat structure projection base")),
        };
        let index = usize::try_from(project.field)
            .map_err(|_| self.fact_mismatch("structure projection field index"))?;
        let field = fields
            .get(index)
            .ok_or_else(|| self.fact_mismatch("structure projection field index"))?;
        let expression = self
            .input
            .hir()
            .as_program()
            .expression(project.expression)
            .ok_or_else(|| self.fact_mismatch("structure projection expression"))?;
        let wrela_hir::ExpressionKind::Field { name, .. } = &expression.kind else {
            return Err(self.fact_mismatch("structure projection expression kind"));
        };
        if name.as_str() != field.name
            || field.ty != project.ty
            || project.effects != base_fact.effects
        {
            return Err(self.fact_mismatch("structure projection semantic field"));
        }
        let LoweredExpression::Value(base) =
            self.lower_expression(project.base, sema::AccessMode::Read, statements)?
        else {
            return Err(self.fact_mismatch("structure projection base value"));
        };
        let result = project
            .result
            .ok_or_else(|| self.fact_mismatch("structure projection result"))?;
        let result =
            self.lowered_expression_result(project.expression, result, project.ty, project.source)?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Project {
                base,
                field: project.field,
                access: wir::AccessMode::Read,
            },
            Some(project.source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    fn lower_direct_call(
        &mut self,
        call: DirectCallInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let LoweredExpression::Function(callee_target) =
            self.lower_expression(call.callee, sema::AccessMode::Value, statements)?
        else {
            return Err(self.fact_mismatch("direct-call callee"));
        };
        if callee_target != call.target {
            return Err(self.fact_mismatch("direct-call target"));
        }
        let mut operands = try_vec(
            call.source_argument_count,
            "direct-call source operands",
            self.limits.model_edges,
        )?;
        for source_index in 0..call.source_argument_count {
            check_cancelled(self.is_cancelled)?;
            let source_argument = self.call_argument(call.expression, source_index)?;
            let binding = call
                .bindings
                .iter()
                .find(|binding| binding.source_index as usize == source_index)
                .ok_or_else(|| self.fact_mismatch("direct-call source binding"))?;
            let value = match &source_argument.value {
                wrela_hir::CallArgumentValue::Value(argument) => {
                    let LoweredExpression::Value(value) =
                        self.lower_expression(*argument, binding.access, statements)?
                    else {
                        return Err(self.fact_mismatch("direct-call argument value"));
                    };
                    value
                }
                wrela_hir::CallArgumentValue::Exclusive { .. } => {
                    self.value_map.get(binding.value)?
                }
            };
            operands.push(value);
        }
        let target_function = self
            .input
            .facts()
            .functions
            .get(call.target.0 as usize)
            .filter(|function| {
                function.id == call.target && function.role == sema::FunctionRole::Ordinary
            })
            .ok_or_else(|| self.fact_mismatch("direct-call target function"))?;
        if target_function.result != call.result_type
            || target_function.effects != call.effects
            || call.source_argument_count != target_function.parameters.len()
            || call.bindings.len() != target_function.parameters.len()
        {
            return Err(self.fact_mismatch("direct-call signature"));
        }
        let mut lowered_arguments = try_vec(
            call.bindings.len(),
            "SemanticWir direct-call arguments",
            self.limits.model_edges,
        )?;
        let mut source_used = try_vec(
            call.source_argument_count,
            "direct-call source permutation",
            self.limits.model_edges,
        )?;
        source_used.resize(call.source_argument_count, false);
        let target_declaration = match target_function.origin {
            sema::FunctionOrigin::Source { declaration, .. } => declaration,
            _ => return Err(self.fact_mismatch("direct-call source target")),
        };
        for (parameter_index, binding) in call.bindings.iter().enumerate() {
            check_cancelled(self.is_cancelled)?;
            let source_index = usize::try_from(binding.source_index)
                .map_err(|_| self.fact_mismatch("direct-call source index"))?;
            let source_argument = self.call_argument(call.expression, source_index)?;
            let used = source_used
                .get_mut(source_index)
                .ok_or_else(|| self.fact_mismatch("direct-call source permutation"))?;
            if *used {
                return Err(self.fact_mismatch("direct-call source permutation"));
            }
            *used = true;
            let parameter = target_function
                .parameters
                .get(parameter_index)
                .ok_or_else(|| self.fact_mismatch("direct-call parameter index"))?;
            let hir_parameter = self
                .input
                .hir()
                .as_program()
                .parameters
                .get(parameter.parameter.0 as usize)
                .filter(|record| {
                    record.id == parameter.parameter
                        && record.owner == wrela_hir::CallableOwner::Declaration(target_declaration)
                })
                .ok_or_else(|| self.fact_mismatch("direct-call HIR parameter"))?;
            let name_matches = match &source_argument.name {
                Some(name) => hir_parameter.name.as_ref() == Some(name),
                None => source_index == parameter_index,
            };
            let value_record = self
                .input
                .facts()
                .values
                .get(binding.value.0 as usize)
                .filter(|value| value.function == self.function.id)
                .ok_or_else(|| self.fact_mismatch("direct-call argument semantic value"))?;
            if binding.parameter_index as usize != parameter_index
                || !name_matches
                || binding.access != parameter.access
                || !matches!(
                    (&source_argument.value, binding.access),
                    (
                        wrela_hir::CallArgumentValue::Value(_),
                        sema::AccessMode::Value | sema::AccessMode::Read,
                    ) | (
                        wrela_hir::CallArgumentValue::Exclusive {
                            access: wrela_hir::ExclusiveAccess::Mutate,
                            ..
                        },
                        sema::AccessMode::Mutate,
                    ) | (
                        wrela_hir::CallArgumentValue::Exclusive {
                            access: wrela_hir::ExclusiveAccess::Take,
                            ..
                        },
                        sema::AccessMode::Take,
                    )
                )
                || value_record.ty != parameter.ty
            {
                return Err(self.fact_mismatch("direct-call argument permutation"));
            }
            match &source_argument.value {
                wrela_hir::CallArgumentValue::Value(expression) => {
                    let argument_fact = self.expression_fact(*expression)?;
                    if argument_fact.result != Some(binding.value)
                        && argument_fact.resolution
                            != sema::ExpressionResolution::Value(binding.value)
                    {
                        return Err(self.fact_mismatch("direct-call argument value identity"));
                    }
                }
                wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                    let origin_matches = matches!(
                        (&place.root, value_record.origin),
                        (
                            wrela_hir::Definition::Local(source),
                            sema::SemanticValueOrigin::Local(candidate)
                        ) if *source == candidate
                    ) || matches!(
                        (&place.root, value_record.origin),
                        (
                            wrela_hir::Definition::Parameter(source),
                            sema::SemanticValueOrigin::Parameter(candidate)
                        ) if *source == candidate
                    );
                    if !place.projections.is_empty() || !origin_matches {
                        return Err(self.fact_mismatch("direct-call exclusive place identity"));
                    }
                }
            }
            lowered_arguments.push(wir::Argument {
                access: lower_access(binding.access),
                value: *operands
                    .get(source_index)
                    .ok_or_else(|| self.fact_mismatch("direct-call lowered operand"))?,
            });
        }
        if source_used.iter().any(|used| !used) {
            return Err(self.fact_mismatch("direct-call source permutation"));
        }
        let result = call
            .result
            .ok_or_else(|| self.fact_mismatch("direct-call result"))?;
        let result =
            self.lowered_expression_result(call.expression, result, call.result_type, call.source)?;
        self.push_let(
            statements,
            result,
            wir::SemanticOperation::Call {
                function: wir::FunctionId(call.target.0),
                arguments: lowered_arguments,
                activation: None,
            },
            Some(call.source),
        )?;
        Ok(LoweredExpression::Value(result))
    }

    /// Lower a binary/comparison operator desugared to a `core.ops` impl
    /// method call (chapter 10 §12). There is no source `Call` expression:
    /// `left`/`right` are the operator's own operand expressions and are
    /// lowered in that exact order so their statements are emitted
    /// left-to-right as written, regardless of the argument-to-parameter
    /// binding recorded in `call.bindings`.
    fn lower_operator_call(
        &mut self,
        call: OperatorCallInput,
        statements: &mut Vec<wir::SemanticStatement>,
    ) -> Result<LoweredExpression, LowerError> {
        let target_function = self
            .input
            .facts()
            .functions
            .get(call.target.0 as usize)
            .filter(|function| {
                function.id == call.target && function.role == sema::FunctionRole::Ordinary
            })
            .ok_or_else(|| self.fact_mismatch("operator-call target function"))?;
        if call.bindings.len() != 2
            || target_function.parameters.len() != 2
            || target_function.effects != call.effects
        {
            return Err(self.fact_mismatch("operator-call signature"));
        }
        if call.negate {
            if source_scalar_kind(self.input.facts(), target_function.result)
                != Some(SourceScalarKind::Bool)
                || source_scalar_kind(self.input.facts(), call.result_type)
                    != Some(SourceScalarKind::Bool)
            {
                return Err(self.fact_mismatch("operator-call negated result type"));
            }
        } else if target_function.result != call.result_type
            || call.raw_result
                != call
                    .result
                    .ok_or_else(|| self.fact_mismatch("operator-call result"))?
        {
            return Err(self.fact_mismatch("operator-call result type"));
        }
        let raw_result_record = self
            .input
            .facts()
            .values
            .get(call.raw_result.0 as usize)
            .filter(|value| {
                value.function == self.function.id && value.ty == target_function.result
            })
            .ok_or_else(|| self.fact_mismatch("operator-call raw result value"))?;
        let _ = raw_result_record;

        let left_binding = call
            .bindings
            .iter()
            .find(|binding| binding.source_index == 0)
            .ok_or_else(|| self.fact_mismatch("operator-call left binding"))?;
        let LoweredExpression::Value(left_value) =
            self.lower_expression(call.left, left_binding.access, statements)?
        else {
            return Err(self.fact_mismatch("operator-call left operand value"));
        };
        let right_binding = call
            .bindings
            .iter()
            .find(|binding| binding.source_index == 1)
            .ok_or_else(|| self.fact_mismatch("operator-call right binding"))?;
        let LoweredExpression::Value(right_value) =
            self.lower_expression(call.right, right_binding.access, statements)?
        else {
            return Err(self.fact_mismatch("operator-call right operand value"));
        };
        let operands = [left_value, right_value];

        let mut lowered_arguments = try_vec(
            call.bindings.len(),
            "SemanticWir operator-call arguments",
            self.limits.model_edges,
        )?;
        for (parameter_index, binding) in call.bindings.iter().enumerate() {
            check_cancelled(self.is_cancelled)?;
            let parameter = target_function
                .parameters
                .get(parameter_index)
                .ok_or_else(|| self.fact_mismatch("operator-call parameter index"))?;
            let value_record = self
                .input
                .facts()
                .values
                .get(binding.value.0 as usize)
                .filter(|value| value.function == self.function.id && value.ty == parameter.ty)
                .ok_or_else(|| self.fact_mismatch("operator-call argument semantic value"))?;
            let _ = value_record;
            if binding.parameter_index as usize != parameter_index
                || binding.access != parameter.access
            {
                return Err(self.fact_mismatch("operator-call argument permutation"));
            }
            let source_index = binding.source_index as usize;
            let operand_value = *operands
                .get(source_index)
                .ok_or_else(|| self.fact_mismatch("operator-call source index"))?;
            lowered_arguments.push(wir::Argument {
                access: lower_access(binding.access),
                value: operand_value,
            });
        }

        let raw_result_wir = self.value_map.get(call.raw_result)?;
        self.push_let(
            statements,
            raw_result_wir,
            wir::SemanticOperation::Call {
                function: wir::FunctionId(call.target.0),
                arguments: lowered_arguments,
                activation: None,
            },
            Some(call.source),
        )?;
        if !call.negate {
            return Ok(LoweredExpression::Value(raw_result_wir));
        }
        let final_result = call
            .result
            .ok_or_else(|| self.fact_mismatch("operator-call negated result"))?;
        let final_wir = self.lowered_expression_result(
            call.expression,
            final_result,
            call.result_type,
            call.source,
        )?;
        self.push_let(
            statements,
            final_wir,
            wir::SemanticOperation::Unary {
                operator: wir::UnaryOperator::BoolNot,
                operand: raw_result_wir,
                arithmetic: wir::ArithmeticMode::Checked,
            },
            Some(call.source),
        )?;
        Ok(LoweredExpression::Value(final_wir))
    }

    fn call_argument(
        &self,
        expression: wrela_hir::ExpressionId,
        index: usize,
    ) -> Result<&wrela_hir::CallArgument, LowerError> {
        let expression = self
            .input
            .hir()
            .as_program()
            .expression(expression)
            .ok_or_else(|| self.fact_mismatch("direct-call source expression"))?;
        let wrela_hir::ExpressionKind::Call { arguments, .. } = &expression.kind else {
            return Err(self.fact_mismatch("direct-call source expression"));
        };
        arguments
            .get(index)
            .ok_or_else(|| self.fact_mismatch("direct-call source index"))
    }

    fn push_let(
        &mut self,
        statements: &mut Vec<wir::SemanticStatement>,
        result: wir::ValueId,
        operation: wir::SemanticOperation,
        source: Option<Span>,
    ) -> Result<(), LowerError> {
        self.operations = self
            .operations
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: self.limits.operations,
            })?;
        if self.operations > self.limits.operations {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: self.limits.operations,
            });
        }
        self.push_statement(
            statements,
            wir::SemanticStatement::Let(wir::LetStatement {
                results: one_value_vec(result, self.limits.model_edges)?,
                operation,
                source,
            }),
        )
    }

    fn push_effect(
        &mut self,
        statements: &mut Vec<wir::SemanticStatement>,
        operation: wir::SemanticOperation,
        source: Option<Span>,
    ) -> Result<(), LowerError> {
        self.operations = self
            .operations
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: self.limits.operations,
            })?;
        if self.operations > self.limits.operations {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: self.limits.operations,
            });
        }
        self.push_statement(
            statements,
            wir::SemanticStatement::Let(wir::LetStatement {
                results: Vec::new(),
                operation,
                source,
            }),
        )
    }

    fn push_statement(
        &mut self,
        statements: &mut Vec<wir::SemanticStatement>,
        statement: wir::SemanticStatement,
    ) -> Result<(), LowerError> {
        self.statement_edges =
            self.statement_edges
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "SemanticWir source statement edges",
                    limit: self.limits.model_edges,
                })?;
        if self.statement_edges > self.limits.model_edges {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir source statement edges",
                limit: self.limits.model_edges,
            });
        }
        statements
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir source statements",
                limit: self.limits.model_edges,
            })?;
        statements.push(statement);
        Ok(())
    }

    fn statement_fact(
        &self,
        statement: wrela_hir::StatementId,
    ) -> Result<&sema::StatementFact, LowerError> {
        self.input
            .facts()
            .statements
            .binary_search_by_key(&(self.function.id, statement), |fact| {
                (fact.function, fact.statement)
            })
            .ok()
            .and_then(|index| self.input.facts().statements.get(index))
            .ok_or(LowerError::MissingSemanticFact {
                subject: self.function.name.clone(),
                fact: "statement semantic fact",
            })
    }

    fn expression_fact(
        &self,
        expression: wrela_hir::ExpressionId,
    ) -> Result<&sema::ExpressionFact, LowerError> {
        self.input
            .facts()
            .expressions
            .binary_search_by_key(&(self.function.id, expression), |fact| {
                (fact.function, fact.expression)
            })
            .ok()
            .and_then(|index| self.input.facts().expressions.get(index))
            .ok_or(LowerError::MissingSemanticFact {
                subject: self.function.name.clone(),
                fact: "expression semantic fact",
            })
    }

    fn validate_statement_post_state(
        &self,
        fact: &sema::StatementFact,
        body: wrela_hir::BodyId,
        expected_effects: sema::EffectSet,
    ) -> Result<(), LowerError> {
        if fact.effects != expected_effects
            || fact.effects.0 & !self.function.effects.0 != 0
            || !fact.live_loans_after.is_empty()
            || fact.proofs != self.function.proofs
            || !fact
                .initialized_after
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || !fact.moved_after.windows(2).all(|pair| pair[0] < pair[1])
            || fact
                .initialized_after
                .iter()
                .any(|value| fact.moved_after.binary_search(value).is_ok())
        {
            return Err(self.fact_mismatch("statement semantic state"));
        }
        for value in fact.initialized_after.iter().chain(&fact.moved_after) {
            check_cancelled(self.is_cancelled)?;
            let record = self
                .input
                .facts()
                .values
                .get(value.0 as usize)
                .filter(|record| record.function == self.function.id)
                .ok_or_else(|| self.fact_mismatch("statement initialized value"))?;
            let _ = self.value_map.get(*value)?;
            if let sema::SemanticValueOrigin::Local(local) = record.origin {
                let local_body = self
                    .input
                    .hir()
                    .as_program()
                    .locals
                    .get(local.0 as usize)
                    .map(|local| local.body)
                    .ok_or_else(|| self.fact_mismatch("statement local provenance"))?;
                if !body_is_ancestor(self.input.hir().as_program(), local_body, body) {
                    return Err(unsupported("branch-local semantic value escape"));
                }
            }
        }
        Ok(())
    }

    fn body_statement_effects(
        &self,
        body: wrela_hir::BodyId,
    ) -> Result<sema::EffectSet, LowerError> {
        let statements = self
            .input
            .hir()
            .as_program()
            .body(body)
            .map(|body| body.statements.as_slice())
            .ok_or(LowerError::MissingSemanticFact {
                subject: self.function.name.clone(),
                fact: "nested source body effects",
            })?;
        let mut effects = sema::EffectSet::default();
        for statement in statements {
            check_cancelled(self.is_cancelled)?;
            effects.0 |= self.statement_fact(*statement)?.effects.0;
        }
        Ok(effects)
    }

    fn body_definitely_returns(&self, root: wrela_hir::BodyId) -> Result<bool, LowerError> {
        let mut pending = try_vec(1, "source termination work", self.limits.model_edges)?;
        pending.push((root, 1_u32));
        while let Some((body, depth)) = pending.pop() {
            check_cancelled(self.is_cancelled)?;
            if depth > self.limits.structured_region_depth {
                return Err(LowerError::ResourceLimit {
                    resource: "source termination depth",
                    limit: u64::from(self.limits.structured_region_depth),
                });
            }
            let last = self
                .input
                .hir()
                .as_program()
                .body(body)
                .and_then(|body| body.statements.last())
                .and_then(|id| self.input.hir().as_program().statement(*id));
            match last.map(|statement| &statement.kind) {
                Some(wrela_hir::StatementKind::Return(_)) => {}
                Some(wrela_hir::StatementKind::If {
                    branches,
                    else_body: Some(otherwise),
                }) if !branches.is_empty() => {
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "source termination depth",
                        limit: u64::from(self.limits.structured_region_depth),
                    })?;
                    push_bounded_id(
                        &mut pending,
                        (*otherwise, next),
                        "source termination work",
                        self.limits.model_edges,
                    )?;
                    for (_, branch) in branches {
                        push_bounded_id(
                            &mut pending,
                            (*branch, next),
                            "source termination work",
                            self.limits.model_edges,
                        )?;
                    }
                }
                Some(wrela_hir::StatementKind::Match { arms, .. }) if !arms.is_empty() => {
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "source termination depth",
                        limit: u64::from(self.limits.structured_region_depth),
                    })?;
                    for arm in arms {
                        push_bounded_id(
                            &mut pending,
                            (arm.body, next),
                            "source termination work",
                            self.limits.model_edges,
                        )?;
                    }
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn validate_exact_closure(&mut self) -> Result<(), LowerError> {
        self.seen_bodies.sort_unstable();
        self.seen_statements.sort_unstable();
        self.seen_expressions.sort_unstable();
        if self.seen_bodies.windows(2).any(|pair| pair[0] == pair[1])
            || self
                .seen_statements
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || self
                .seen_expressions
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(self.fact_mismatch("duplicated source body closure"));
        }
        let statements_match = self
            .input
            .facts()
            .statements
            .iter()
            .filter(|fact| fact.function == self.function.id)
            .map(|fact| fact.statement)
            .eq(self.seen_statements.iter().copied());
        let expressions_match = self
            .input
            .facts()
            .expressions
            .iter()
            .filter(|fact| fact.function == self.function.id)
            .map(|fact| fact.expression)
            .eq(self.seen_expressions.iter().copied());
        if !statements_match || !expressions_match {
            return Err(self.fact_mismatch("exact source fact closure"));
        }
        Ok(())
    }

    fn push_seen_body(&mut self, body: wrela_hir::BodyId) -> Result<(), LowerError> {
        push_bounded_id(
            &mut self.seen_bodies,
            body,
            "source body closure",
            self.limits.model_edges,
        )
    }

    fn push_seen_statement(&mut self, statement: wrela_hir::StatementId) -> Result<(), LowerError> {
        push_bounded_id(
            &mut self.seen_statements,
            statement,
            "source statement closure",
            self.limits.model_edges,
        )
    }

    fn push_seen_expression(
        &mut self,
        expression: wrela_hir::ExpressionId,
    ) -> Result<(), LowerError> {
        push_bounded_id(
            &mut self.seen_expressions,
            expression,
            "source expression closure",
            self.limits.model_edges,
        )
    }

    fn fact_mismatch(&self, fact: &'static str) -> LowerError {
        LowerError::MissingSemanticFact {
            subject: self.function.name.clone(),
            fact,
        }
    }
}

fn push_bounded_id<T>(
    output: &mut Vec<T>,
    value: T,
    resource: &'static str,
    limit: u64,
) -> Result<(), LowerError> {
    if u64::try_from(output.len()).map_or(true, |count| count >= limit) {
        return Err(LowerError::ResourceLimit { resource, limit });
    }
    output
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    output.push(value);
    Ok(())
}

fn one_value_vec(value: wir::ValueId, limit: u64) -> Result<Vec<wir::ValueId>, LowerError> {
    let mut output = try_vec(1, "SemanticWir value edges", limit)?;
    output.push(value);
    Ok(output)
}

fn lower_hir_access(access: wrela_hir::AccessMode) -> sema::AccessMode {
    match access {
        wrela_hir::AccessMode::Value => sema::AccessMode::Value,
        wrela_hir::AccessMode::Read => sema::AccessMode::Read,
        wrela_hir::AccessMode::Mutate => sema::AccessMode::Mutate,
        wrela_hir::AccessMode::Take => sema::AccessMode::Take,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceScalarKind {
    Bool,
    Integer { signed: bool },
    Float,
}

fn source_scalar_kind(
    facts: &sema::PartialAnalysis,
    ty: sema::SemanticTypeId,
) -> Option<SourceScalarKind> {
    match facts.types.get(ty.0 as usize)?.kind {
        sema::SemanticTypeKind::Bool => Some(SourceScalarKind::Bool),
        sema::SemanticTypeKind::Integer { signed, .. } => {
            Some(SourceScalarKind::Integer { signed })
        }
        sema::SemanticTypeKind::Float { bits: 32 | 64 } => Some(SourceScalarKind::Float),
        _ => None,
    }
}

fn source_type_matches_semantic(
    facts: &sema::PartialAnalysis,
    source: &wrela_hir::TypeExpression,
    ty: sema::SemanticTypeId,
) -> bool {
    let Some(record) = facts.types.get(ty.0 as usize) else {
        return false;
    };
    let wrela_hir::TypeExpressionKind::Named {
        definition: wrela_hir::Definition::Builtin(builtin),
        arguments,
    } = &source.kind
    else {
        return false;
    };
    if !arguments.is_empty() {
        return false;
    }
    match builtin {
        wrela_hir::Builtin::Bool => matches!(record.kind, sema::SemanticTypeKind::Bool),
        wrela_hir::Builtin::U8 => source_integer_type_matches(record, false, 8, false),
        wrela_hir::Builtin::U16 => source_integer_type_matches(record, false, 16, false),
        wrela_hir::Builtin::U32 => source_integer_type_matches(record, false, 32, false),
        wrela_hir::Builtin::U64 => source_integer_type_matches(record, false, 64, false),
        wrela_hir::Builtin::U128 => source_integer_type_matches(record, false, 128, false),
        wrela_hir::Builtin::Usize => source_pointer_type_matches(record, false),
        wrela_hir::Builtin::I8 => source_integer_type_matches(record, true, 8, false),
        wrela_hir::Builtin::I16 => source_integer_type_matches(record, true, 16, false),
        wrela_hir::Builtin::I32 => source_integer_type_matches(record, true, 32, false),
        wrela_hir::Builtin::I64 => source_integer_type_matches(record, true, 64, false),
        wrela_hir::Builtin::I128 => source_integer_type_matches(record, true, 128, false),
        wrela_hir::Builtin::Isize => source_pointer_type_matches(record, true),
        wrela_hir::Builtin::F32 => {
            matches!(record.kind, sema::SemanticTypeKind::Float { bits: 32 })
        }
        wrela_hir::Builtin::F64 => {
            matches!(record.kind, sema::SemanticTypeKind::Float { bits: 64 })
        }
        wrela_hir::Builtin::Never
        | wrela_hir::Builtin::Unit
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
    }
}

fn resolved_enum_constructor_from_hir(
    program: &wrela_hir::Program,
    expression: wrela_hir::ExpressionId,
) -> Option<wrela_hir::ResolvedVariant> {
    let expression = program.expression(expression)?;
    match &expression.kind {
        wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Variant(source)) => {
            Some(source.clone())
        }
        wrela_hir::ExpressionKind::Field { base, name } => {
            let wrela_hir::ExpressionKind::Reference(wrela_hir::Definition::Declaration(source)) =
                &program.expression(*base)?.kind
            else {
                return None;
            };
            let declaration = program.declaration(source.declaration).filter(|record| {
                record.module == source.module
                    && program
                        .modules
                        .get(source.module.0 as usize)
                        .is_some_and(|module| module.package == source.package)
            })?;
            let wrela_hir::DeclarationKind::Enumeration(enumeration) = &declaration.kind else {
                return None;
            };
            if enumeration.variants.len() > 256 {
                return None;
            }
            let mut selected = None;
            for (index, variant) in enumeration.variants.iter().enumerate() {
                if variant.name == *name {
                    if selected.is_some() {
                        return None;
                    }
                    selected = u32::try_from(index).ok();
                }
            }
            selected.map(|variant| wrela_hir::ResolvedVariant {
                enumeration: source.clone(),
                variant,
            })
        }
        _ => None,
    }
}

fn source_integer_type_matches(
    record: &sema::SemanticType,
    expected_signed: bool,
    expected_bits: u16,
    expected_pointer_sized: bool,
) -> bool {
    matches!(
        record.kind,
        sema::SemanticTypeKind::Integer {
            signed,
            bits,
            pointer_sized,
        } if signed == expected_signed
            && bits == expected_bits
            && pointer_sized == expected_pointer_sized
    )
}

fn source_pointer_type_matches(record: &sema::SemanticType, expected_signed: bool) -> bool {
    matches!(
        record.kind,
        sema::SemanticTypeKind::Integer {
            signed,
            bits: 32 | 64,
            pointer_sized: true,
        } if signed == expected_signed
    )
}

fn compound_assignment_binary_operator(
    operator: wrela_hir::AssignmentOperator,
) -> Option<wrela_hir::BinaryOperator> {
    Some(match operator {
        wrela_hir::AssignmentOperator::Assign => return None,
        wrela_hir::AssignmentOperator::Add => wrela_hir::BinaryOperator::Add,
        wrela_hir::AssignmentOperator::Subtract => wrela_hir::BinaryOperator::Subtract,
        wrela_hir::AssignmentOperator::Multiply => wrela_hir::BinaryOperator::Multiply,
        wrela_hir::AssignmentOperator::Divide => wrela_hir::BinaryOperator::Divide,
        wrela_hir::AssignmentOperator::Remainder => wrela_hir::BinaryOperator::Remainder,
        wrela_hir::AssignmentOperator::BitAnd => wrela_hir::BinaryOperator::BitAnd,
        wrela_hir::AssignmentOperator::BitOr => wrela_hir::BinaryOperator::BitOr,
        wrela_hir::AssignmentOperator::BitXor => wrela_hir::BinaryOperator::BitXor,
        wrela_hir::AssignmentOperator::ShiftLeft => wrela_hir::BinaryOperator::ShiftLeft,
        wrela_hir::AssignmentOperator::ShiftRight => wrela_hir::BinaryOperator::ShiftRight,
    })
}

fn lower_source_arithmetic_operator(
    operator: wrela_hir::BinaryOperator,
) -> Option<(wir::BinaryOperator, wir::ArithmeticMode)> {
    Some(match operator {
        wrela_hir::BinaryOperator::Add => (wir::BinaryOperator::Add, wir::ArithmeticMode::Checked),
        wrela_hir::BinaryOperator::AddWrapping => {
            (wir::BinaryOperator::Add, wir::ArithmeticMode::Wrapping)
        }
        wrela_hir::BinaryOperator::Subtract => {
            (wir::BinaryOperator::Subtract, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::SubtractWrapping => {
            (wir::BinaryOperator::Subtract, wir::ArithmeticMode::Wrapping)
        }
        wrela_hir::BinaryOperator::Multiply => {
            (wir::BinaryOperator::Multiply, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::MultiplyWrapping => {
            (wir::BinaryOperator::Multiply, wir::ArithmeticMode::Wrapping)
        }
        wrela_hir::BinaryOperator::Divide => {
            (wir::BinaryOperator::Divide, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::Remainder => {
            (wir::BinaryOperator::Remainder, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::BitOr => {
            (wir::BinaryOperator::BitOr, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::BitXor => {
            (wir::BinaryOperator::BitXor, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::BitAnd => {
            (wir::BinaryOperator::BitAnd, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::ShiftLeft => {
            (wir::BinaryOperator::ShiftLeft, wir::ArithmeticMode::Checked)
        }
        wrela_hir::BinaryOperator::ShiftRight => (
            wir::BinaryOperator::ShiftRight,
            wir::ArithmeticMode::Checked,
        ),
        wrela_hir::BinaryOperator::LogicalOr | wrela_hir::BinaryOperator::LogicalAnd => {
            return None;
        }
    })
}

fn lower_source_comparison_operator(
    operator: wrela_hir::ComparisonOperator,
) -> Option<wir::BinaryOperator> {
    Some(match operator {
        wrela_hir::ComparisonOperator::Equal => wir::BinaryOperator::Equal,
        wrela_hir::ComparisonOperator::NotEqual => wir::BinaryOperator::NotEqual,
        wrela_hir::ComparisonOperator::Less => wir::BinaryOperator::Less,
        wrela_hir::ComparisonOperator::LessEqual => wir::BinaryOperator::LessEqual,
        wrela_hir::ComparisonOperator::Greater => wir::BinaryOperator::Greater,
        wrela_hir::ComparisonOperator::GreaterEqual => wir::BinaryOperator::GreaterEqual,
        wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn => return None,
    })
}

fn lower_constant(constant: &sema::ConstantValue) -> Result<wir::Constant, LowerError> {
    match constant {
        sema::ConstantValue::Unit => Ok(wir::Constant::Unit),
        sema::ConstantValue::Bool(value) => Ok(wir::Constant::Bool(*value)),
        sema::ConstantValue::Unsigned { bits, value } => Ok(wir::Constant::Unsigned {
            bits: u8::try_from(*bits)
                .map_err(|_| unsupported("integer constants wider than SemanticWir"))?,
            value: *value,
        }),
        sema::ConstantValue::Signed { bits, value } => Ok(wir::Constant::Signed {
            bits: u8::try_from(*bits)
                .map_err(|_| unsupported("integer constants wider than SemanticWir"))?,
            value: *value,
        }),
        sema::ConstantValue::Float32(bits) => Ok(wir::Constant::Float32(*bits)),
        sema::ConstantValue::Float64(bits) => Ok(wir::Constant::Float64(*bits)),
        _ => Err(unsupported("non-scalar source constants")),
    }
}

fn lower_scope_literal(
    facts: &sema::PartialAnalysis,
    ty: sema::SemanticTypeId,
    literal: &wrela_hir::Literal,
) -> Result<wir::Constant, LowerError> {
    let kind = facts
        .types
        .get(ty.0 as usize)
        .map(|ty| &ty.kind)
        .ok_or_else(|| unsupported("scope state literal type"))?;
    match (literal, kind) {
        (wrela_hir::Literal::Unit, sema::SemanticTypeKind::Unit) => Ok(wir::Constant::Unit),
        (wrela_hir::Literal::Boolean(value), sema::SemanticTypeKind::Bool) => {
            Ok(wir::Constant::Bool(*value))
        }
        (
            wrela_hir::Literal::Integer(source),
            sema::SemanticTypeKind::Integer {
                signed: false,
                bits,
                ..
            },
        ) => Ok(wir::Constant::Unsigned {
            bits: u8::try_from(*bits).map_err(|_| unsupported("scope integer constant width"))?,
            value: parse_integer(source)
                .ok_or_else(|| unsupported("scope unsigned integer constant"))?,
        }),
        (
            wrela_hir::Literal::Integer(source),
            sema::SemanticTypeKind::Integer {
                signed: true, bits, ..
            },
        ) => Ok(wir::Constant::Signed {
            bits: u8::try_from(*bits).map_err(|_| unsupported("scope integer constant width"))?,
            value: parse_integer(source)
                .and_then(|value| i128::try_from(value).ok())
                .ok_or_else(|| unsupported("scope signed integer constant"))?,
        }),
        (wrela_hir::Literal::Float(source), sema::SemanticTypeKind::Float { bits: 32 }) => {
            let value = parse_source_float(source)
                .and_then(|source| source.parse::<f32>().ok())
                .filter(|value| value.is_finite())
                .ok_or_else(|| unsupported("scope finite f32 constant"))?;
            Ok(wir::Constant::Float32(value.to_bits()))
        }
        (wrela_hir::Literal::Float(source), sema::SemanticTypeKind::Float { bits: 64 }) => {
            let value = parse_source_float(source)
                .and_then(|source| source.parse::<f64>().ok())
                .filter(|value| value.is_finite())
                .ok_or_else(|| unsupported("scope finite f64 constant"))?;
            Ok(wir::Constant::Float64(value.to_bits()))
        }
        _ => Err(unsupported(
            "semantic-scope-enter-lowering-pending (non-scalar state field)",
        )),
    }
}

fn constant_matches_literal(
    facts: &sema::PartialAnalysis,
    ty: sema::SemanticTypeId,
    literal: &wrela_hir::Literal,
    constant: &sema::ConstantValue,
) -> bool {
    let Some(kind) = facts.types.get(ty.0 as usize).map(|record| &record.kind) else {
        return false;
    };
    match (literal, constant, kind) {
        (wrela_hir::Literal::Unit, sema::ConstantValue::Unit, sema::SemanticTypeKind::Unit) => true,
        (
            wrela_hir::Literal::Boolean(source),
            sema::ConstantValue::Bool(value),
            sema::SemanticTypeKind::Bool,
        ) => source == value,
        (
            wrela_hir::Literal::Integer(source),
            sema::ConstantValue::Unsigned {
                bits: value_bits,
                value,
            },
            sema::SemanticTypeKind::Integer {
                signed: false,
                bits,
                ..
            },
        ) => bits == value_bits && parse_integer(source) == Some(*value),
        (
            wrela_hir::Literal::Integer(source),
            sema::ConstantValue::Signed {
                bits: value_bits,
                value,
            },
            sema::SemanticTypeKind::Integer {
                signed: true, bits, ..
            },
        ) => {
            bits == value_bits
                && parse_integer(source).and_then(|value| i128::try_from(value).ok())
                    == Some(*value)
        }
        (
            wrela_hir::Literal::Float(source),
            sema::ConstantValue::Float32(value),
            sema::SemanticTypeKind::Float { bits: 32 },
        ) => parse_source_float(source)
            .and_then(|source| source.parse::<f32>().ok())
            .filter(|source| source.is_finite())
            .is_some_and(|source| source.to_bits() == *value),
        (
            wrela_hir::Literal::Float(source),
            sema::ConstantValue::Float64(value),
            sema::SemanticTypeKind::Float { bits: 64 },
        ) => parse_source_float(source)
            .and_then(|source| source.parse::<f64>().ok())
            .filter(|source| source.is_finite())
            .is_some_and(|source| source.to_bits() == *value),
        _ => false,
    }
}

fn parse_source_float(value: &str) -> Option<String> {
    let mut spelling = String::new();
    spelling.try_reserve_exact(value.len()).ok()?;
    spelling.extend(value.chars().filter(|character| *character != '_'));
    Some(spelling)
}

fn function_reference_type_matches(
    facts: &sema::PartialAnalysis,
    ty: sema::SemanticTypeId,
    function: &sema::FunctionInstance,
) -> bool {
    let Some(sema::SemanticTypeKind::Function {
        color,
        parameters,
        result,
    }) = facts.types.get(ty.0 as usize).map(|record| &record.kind)
    else {
        return false;
    };
    *color == function.color
        && *result == function.result
        && parameters.len() == function.parameters.len()
        && parameters
            .iter()
            .zip(&function.parameters)
            .all(|(ty, parameter)| ty.access == parameter.access && ty.ty == parameter.ty)
}

fn resolved_declaration_matches_program(
    program: &wrela_hir::Program,
    source: &wrela_hir::ResolvedDeclaration,
) -> bool {
    program
        .declaration(source.declaration)
        .is_some_and(|declaration| declaration.module == source.module)
        && program
            .modules
            .get(source.module.0 as usize)
            .is_some_and(|module| module.id == source.module && module.package == source.package)
}

fn parse_integer(value: &str) -> Option<u128> {
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

fn body_is_ancestor(
    program: &wrela_hir::Program,
    ancestor: wrela_hir::BodyId,
    body: wrela_hir::BodyId,
) -> bool {
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

fn lower_generated_harness_function(
    generated: &GeneratedTestFacts<'_>,
    encoded: EncodedHarness,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(wir::SemanticFunction, u64), LowerError> {
    let test_count = generated.group.tests.len();
    let expected_frames = test_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(LowerError::ResourceLimit {
            resource: "generated test events",
            limit: limits.operations,
        })?;
    if encoded.frames.len() != expected_frames {
        return Err(LowerError::InternalInvariant(
            "encoded harness frame count differs from the compiled group".to_owned(),
        ));
    }
    let value_count = encoded
        .frames
        .len()
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir values",
            limit: limits.values,
        })?;
    check_count("SemanticWir values", value_count, limits.values)?;
    let operation_count = encoded
        .frames
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(test_count))
        .and_then(|count| count.checked_add(2))
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit: limits.operations,
        })?;
    check_count("SemanticWir operations", operation_count, limits.operations)?;
    let statement_count = operation_count
        .checked_add(1)
        .ok_or(LowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit: limits.operations,
        })?;
    let mut values = try_vec(value_count, "SemanticWir values", limits.values)?;
    let mut statements = try_vec(
        statement_count,
        "SemanticWir harness statements",
        limits.model_edges,
    )?;
    let mut frames = encoded.frames.into_iter();
    append_test_emit(
        frames
            .next()
            .ok_or_else(|| LowerError::InternalInvariant("missing run-started frame".to_owned()))?,
        &encoded.frame_types,
        &mut values,
        &mut statements,
        limits,
    )?;
    for function_id in &generated.test_functions {
        check_cancelled(is_cancelled)?;
        let function = generated
            .facts
            .functions
            .get(function_id.0 as usize)
            .filter(|function| function.id == *function_id)
            .ok_or_else(|| {
                LowerError::InternalInvariant("selected test function is dangling".to_owned())
            })?;
        append_test_emit(
            frames.next().ok_or_else(|| {
                LowerError::InternalInvariant("missing test-started frame".to_owned())
            })?,
            &encoded.frame_types,
            &mut values,
            &mut statements,
            limits,
        )?;
        statements.push(wir::SemanticStatement::Let(wir::LetStatement {
            results: Vec::new(),
            operation: wir::SemanticOperation::Call {
                function: wir::FunctionId(function.id.0),
                arguments: Vec::new(),
                activation: None,
            },
            source: function.source,
        }));
        append_test_emit(
            frames.next().ok_or_else(|| {
                LowerError::InternalInvariant("missing test-finished frame".to_owned())
            })?,
            &encoded.frame_types,
            &mut values,
            &mut statements,
            limits,
        )?;
    }
    append_test_emit(
        frames.next().ok_or_else(|| {
            LowerError::InternalInvariant("missing run-finished frame".to_owned())
        })?,
        &encoded.frame_types,
        &mut values,
        &mut statements,
        limits,
    )?;
    if frames.next().is_some() {
        return Err(LowerError::InternalInvariant(
            "generated harness retained trailing event frames".to_owned(),
        ));
    }
    let outcome =
        wir::ValueId(
            u32::try_from(values.len()).map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            })?,
        );
    values.push(wir::SemanticValue {
        id: outcome,
        ty: encoded.outcome_type,
        origin: None,
        name: None,
    });
    statements.push(wir::SemanticStatement::Let(wir::LetStatement {
        results: vec![outcome],
        operation: wir::SemanticOperation::Constant(wir::Constant::Unsigned { bits: 32, value: 0 }),
        source: None,
    }));
    statements.push(wir::SemanticStatement::Let(wir::LetStatement {
        results: Vec::new(),
        operation: wir::SemanticOperation::TestFinish { outcome },
        source: None,
    }));
    statements.push(wir::SemanticStatement::Unreachable);
    let mut function_proofs = try_vec(
        generated.harness.proofs.len(),
        "SemanticWir function proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(
        generated
            .harness
            .proofs
            .iter()
            .map(|proof| wir::ProofId(proof.0)),
    );
    let function = wir::SemanticFunction {
        id: wir::FunctionId(generated.harness.id.0),
        instance_key: generated.harness.key.0,
        name: copy_text(&generated.harness.name, limits.payload_bytes)?,
        origin: wir::FunctionOrigin::GeneratedTestHarness {
            group: generated.group.id.0,
        },
        role: wir::FunctionRole::ImageEntry,
        color: wir::FunctionColor::Sync,
        parameters: Vec::new(),
        result: wir::TypeId(generated.harness.result.0),
        values,
        body: wir::SemanticRegion {
            parameters: Vec::new(),
            statements,
        },
        effects: wir::EffectSet(generated.harness.effects.0),
        proofs: function_proofs,
        source: generated.harness.source,
        stack_bound: generated.harness.stack_bytes_bound,
        frame_bound: generated.harness.frame_bytes_bound,
        uninterrupted_bound: generated.harness.uninterrupted_work_bound,
        recursive_depth_bound: generated.harness.recursive_depth_bound,
    };
    Ok((
        function,
        u64::try_from(operation_count).map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit: limits.operations,
        })?,
    ))
}

fn append_test_emit(
    frame: Vec<u8>,
    frame_types: &[(usize, wir::TypeId)],
    values: &mut Vec<wir::SemanticValue>,
    statements: &mut Vec<wir::SemanticStatement>,
    limits: LoweringLimits,
) -> Result<(), LowerError> {
    let ty = frame_types
        .iter()
        .find_map(|(length, ty)| (*length == frame.len()).then_some(*ty))
        .ok_or_else(|| LowerError::InternalInvariant("test frame type is missing".to_owned()))?;
    let value =
        wir::ValueId(
            u32::try_from(values.len()).map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: limits.values,
            })?,
        );
    values.push(wir::SemanticValue {
        id: value,
        ty,
        origin: None,
        name: None,
    });
    statements.push(wir::SemanticStatement::Let(wir::LetStatement {
        results: vec![value],
        operation: wir::SemanticOperation::Constant(wir::Constant::Bytes(frame)),
        source: None,
    }));
    statements.push(wir::SemanticStatement::Let(wir::LetStatement {
        results: Vec::new(),
        operation: wir::SemanticOperation::TestEmit { payload: value },
        source: None,
    }));
    Ok(())
}

fn encode_generated_harness(
    group: &FullImageTestGroup,
    types: &mut Vec<wir::TypeRecord>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EncodedHarness, LowerError> {
    let test_count = u32::try_from(group.tests.len()).map_err(|_| LowerError::ResourceLimit {
        resource: "generated test count",
        limit: limits.model_edges,
    })?;
    let events = group
        .tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(LowerError::ResourceLimit {
            resource: "generated test events",
            limit: limits.model_edges,
        })?;
    let maximum_events = test_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(3))
        .ok_or(LowerError::ResourceLimit {
            resource: "generated test events",
            limit: limits.model_edges,
        })?;
    if group.maximum_events != maximum_events {
        return Err(LowerError::InternalInvariant(
            "compiled group maximum-events omits its assertion-failure ceiling".to_owned(),
        ));
    }
    let mut event_stream = try_vec(events, "generated test events", limits.model_edges)?;
    event_stream.push(TestEvent {
        protocol: TEST_PROTOCOL_VERSION,
        sequence: 0,
        kind: TestEventKind::RunStarted { test_count },
    });
    let mut sequence = 1u64;
    for test in &group.tests {
        check_cancelled(is_cancelled)?;
        event_stream.push(TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence,
            kind: TestEventKind::TestStarted {
                test: test.descriptor.id,
            },
        });
        sequence = sequence.checked_add(1).ok_or(LowerError::ResourceLimit {
            resource: "generated test sequence",
            limit: limits.model_edges,
        })?;
        event_stream.push(TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence,
            kind: TestEventKind::TestFinished {
                test: test.descriptor.id,
                outcome: GuestTestOutcome::Passed,
            },
        });
        sequence = sequence.checked_add(1).ok_or(LowerError::ResourceLimit {
            resource: "generated test sequence",
            limit: limits.model_edges,
        })?;
    }
    event_stream.push(TestEvent {
        protocol: TEST_PROTOCOL_VERSION,
        sequence,
        kind: TestEventKind::RunFinished {
            passed: test_count,
            failed: 0,
        },
    });
    if event_stream.len() != events {
        return Err(LowerError::InternalInvariant(
            "generated passing event stream differs from its exact static frame count".to_owned(),
        ));
    }
    let protocol_limits = ProtocolLimits::standard();
    if group.maximum_events > protocol_limits.events {
        return Err(LowerError::ResourceLimit {
            resource: "test protocol events",
            limit: u64::from(protocol_limits.events),
        });
    }
    let mut frames = try_vec(events, "generated test frames", limits.model_edges)?;
    let mut payload_bytes = 0u64;
    let mut lengths = Vec::new();
    lengths
        .try_reserve_exact(events)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "generated test frame types",
            limit: limits.model_edges,
        })?;
    for event in &event_stream {
        check_cancelled(is_cancelled)?;
        let frame = seal_encoded_event(
            &CanonicalTestEventCodec,
            event,
            protocol_limits,
            is_cancelled,
        )
        .map_err(map_protocol_error)?
        .into_bytes();
        let frame_bytes = u64::try_from(frame.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "generated test frame bytes",
            limit: limits.payload_bytes,
        })?;
        payload_bytes =
            payload_bytes
                .checked_add(frame_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "generated test frame bytes",
                    limit: limits.payload_bytes,
                })?;
        if payload_bytes > limits.payload_bytes || payload_bytes > group.maximum_output_bytes {
            return Err(LowerError::ResourceLimit {
                resource: "generated test frame bytes",
                limit: limits.payload_bytes.min(group.maximum_output_bytes),
            });
        }
        lengths.push(frame.len());
        frames.push(frame);
    }
    lengths.sort_unstable();
    lengths.dedup();
    let byte_type =
        ensure_harness_primitive(types, wir::PrimitiveType::U8, "__wrela_test_byte", limits)?;
    let outcome_type = ensure_harness_primitive(
        types,
        wir::PrimitiveType::U32,
        "__wrela_test_outcome",
        limits,
    )?;
    let mut frame_types = try_vec(
        lengths.len(),
        "generated test frame types",
        limits.model_edges,
    )?;
    for length in lengths {
        check_cancelled(is_cancelled)?;
        if types.len() >= limits.types as usize {
            return Err(LowerError::ResourceLimit {
                resource: "SemanticWir types",
                limit: u64::from(limits.types),
            });
        }
        let id =
            wir::TypeId(
                u32::try_from(types.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "SemanticWir types",
                    limit: u64::from(limits.types),
                })?,
            );
        types
            .try_reserve(1)
            .map_err(|_| LowerError::ResourceLimit {
                resource: "SemanticWir types",
                limit: u64::from(limits.types),
            })?;
        types.push(wir::TypeRecord {
            id,
            source_name: copy_text(
                &format!("__wrela_test_frame_{length}"),
                limits.payload_bytes,
            )?,
            kind: wir::TypeKind::Array {
                element: byte_type,
                length: u64::try_from(length).map_err(|_| LowerError::ResourceLimit {
                    resource: "test frame bytes",
                    limit: limits.payload_bytes,
                })?,
            },
            linearity: wir::Linearity::ExplicitCopy,
            source: None,
        });
        frame_types.push((length, id));
    }
    Ok(EncodedHarness {
        frames,
        frame_types,
        outcome_type,
    })
}

fn ensure_harness_primitive(
    types: &mut Vec<wir::TypeRecord>,
    primitive: wir::PrimitiveType,
    synthetic_name: &'static str,
    limits: LoweringLimits,
) -> Result<wir::TypeId, LowerError> {
    if let Some(existing) = types.iter().find(|ty| {
        ty.kind == wir::TypeKind::Primitive(primitive) && ty.linearity == wir::Linearity::CopyScalar
    }) {
        return Ok(existing.id);
    }
    if types.len() >= limits.types as usize {
        return Err(LowerError::ResourceLimit {
            resource: "SemanticWir types",
            limit: u64::from(limits.types),
        });
    }
    let id = wir::TypeId(
        u32::try_from(types.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir types",
            limit: u64::from(limits.types),
        })?,
    );
    types
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir types",
            limit: u64::from(limits.types),
        })?;
    types.push(wir::TypeRecord {
        id,
        source_name: copy_text(synthetic_name, limits.payload_bytes)?,
        kind: wir::TypeKind::Primitive(primitive),
        linearity: wir::Linearity::CopyScalar,
        source: None,
    });
    Ok(id)
}

fn map_protocol_error(error: ProtocolError) -> LowerError {
    match error {
        ProtocolError::Cancelled => LowerError::Cancelled,
        error => LowerError::InternalInvariant(format!(
            "canonical generated test event could not be encoded: {error}"
        )),
    }
}

fn generated_reachable_declarations(
    generated: &GeneratedTestFacts<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, LowerError> {
    let capacity = generated
        .facts
        .functions
        .len()
        .checked_add(generated.facts.types.len())
        .ok_or(LowerError::ResourceLimit {
            resource: "generated reachable declarations",
            limit: limits.model_edges,
        })?;
    let mut declarations = try_vec(
        capacity,
        "generated reachable declarations",
        limits.model_edges,
    )?;
    for function in &generated.facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == generated.harness.id {
            continue;
        }
        let sema::FunctionOrigin::Source { declaration, .. } = function.origin else {
            return Err(unsupported("non-source integration tests"));
        };
        declarations.push(declaration);
    }
    for ty in &generated.facts.types {
        check_cancelled(is_cancelled)?;
        if let sema::SemanticTypeKind::Structure { declaration, .. } = ty.kind {
            declarations.push(declaration);
        }
    }
    cancellable_sort(
        &mut declarations,
        "generated reachable declarations",
        limits.model_edges,
        is_cancelled,
    )?;
    cancellable_dedup(&mut declarations, is_cancelled)?;
    u64::try_from(declarations.len()).map_err(|_| LowerError::ResourceLimit {
        resource: "generated reachable declarations",
        limit: limits.model_edges,
    })
}

fn count_u32(count: usize, resource: &'static str, limit: u64) -> Result<u32, LowerError> {
    u32::try_from(count).map_err(|_| LowerError::ResourceLimit { resource, limit })
}

/// The current runtime model retains exactly one HIR declaration identity:
/// the generated entry's source image constructor. The constructor declaration
/// and generated function are distinct entities, so this is the cardinality of
/// the provenance set `{constructor}`, not a call-graph estimate.
const fn minimum_provenance_declaration_count(_constructor: wrela_hir::DeclarationId) -> u64 {
    1
}

fn lower_owners(
    source: &[sema::ImageOwner],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wir::ImageOwner>, LowerError> {
    let mut output = try_vec(source.len(), "SemanticWir image order", limit)?;
    for owner in source {
        check_cancelled(is_cancelled)?;
        output.push(lower_owner(*owner));
    }
    Ok(output)
}

fn lower_owner(source: sema::ImageOwner) -> wir::ImageOwner {
    match source {
        sema::ImageOwner::Runtime => wir::ImageOwner::Runtime,
        sema::ImageOwner::Actor(id) => wir::ImageOwner::Actor(wir::ActorId(id.0)),
        sema::ImageOwner::Task(id) => wir::ImageOwner::Task(wir::TaskId(id.0)),
        sema::ImageOwner::Device(id) => wir::ImageOwner::Device(wir::DeviceId(id.0)),
        sema::ImageOwner::Pool(id) => wir::ImageOwner::Pool(wir::PoolId(id.0)),
        sema::ImageOwner::Artifact(id) => wir::ImageOwner::BakedArtifact(id.0),
    }
}

fn lower_proof_kind(source: &sema::ProofKind) -> wir::ProofKind {
    match source {
        sema::ProofKind::TypeChecked => wir::ProofKind::TypeChecked,
        sema::ProofKind::EffectsAllowed => wir::ProofKind::EffectsAllowed,
        sema::ProofKind::DefiniteInitialization => wir::ProofKind::DefiniteInitialization,
        sema::ProofKind::Ownership => wir::ProofKind::Ownership,
        sema::ProofKind::AccessExclusive => wir::ProofKind::AccessExclusive,
        sema::ProofKind::ViewDoesNotEscape => wir::ProofKind::ViewDoesNotEscape,
        sema::ProofKind::RegionBound => wir::ProofKind::RegionBound,
        sema::ProofKind::CapacityBound => wir::ProofKind::CapacityBound,
        sema::ProofKind::WaitGraphAcyclic => wir::ProofKind::WaitGraphAcyclic,
        sema::ProofKind::CleanupAcyclic => wir::ProofKind::CleanupAcyclic,
        sema::ProofKind::WorkBound => wir::ProofKind::WorkBound,
        sema::ProofKind::StackBound => wir::ProofKind::StackBound,
        sema::ProofKind::IsrSafe => wir::ProofKind::IsrSafe,
        sema::ProofKind::DmaTransition => wir::ProofKind::DmaTransition,
        sema::ProofKind::MmioPartition => wir::ProofKind::MmioPartition,
        sema::ProofKind::DeviceValueValidated => wir::ProofKind::DeviceValueValidated,
        sema::ProofKind::WireLayout => wir::ProofKind::WireLayout,
        sema::ProofKind::ReceiptLineage => wir::ProofKind::ReceiptLineage,
        sema::ProofKind::ActorAsIf => wir::ProofKind::ActorAsIf,
        sema::ProofKind::SupervisionComplete => wir::ProofKind::SupervisionComplete,
        sema::ProofKind::ImageClosed => wir::ProofKind::ImageClosed,
    }
}

fn preflight_input(
    facts: &sema::PartialAnalysis,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64), LowerError> {
    check_count("semantic types", facts.types.len(), u64::from(limits.types))?;
    check_count(
        "semantic functions",
        facts.functions.len(),
        u64::from(limits.functions),
    )?;
    check_count("semantic values", facts.values.len(), limits.values)?;
    let mut edges = 0u64;
    let mut payload = 0u64;
    add_bounded(
        &mut payload,
        "unit".len(),
        "semantic payload bytes",
        limits.payload_bytes,
    )?;
    for count in [
        facts.types.len(),
        facts.functions.len(),
        facts.values.len(),
        facts.expressions.len(),
        facts.statements.len(),
        facts.scope_protocols.len(),
        facts.scope_activations.len(),
        facts.proofs.len(),
        facts.baked_artifacts.len(),
        facts.comptime_test_results.len(),
    ] {
        add_bounded(
            &mut edges,
            count,
            "semantic model edges",
            limits.model_edges,
        )?;
    }
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut edges,
            function.generic_arguments.len(),
            "semantic model edges",
            limits.model_edges,
        )?;
        add_bounded(
            &mut edges,
            function.parameters.len(),
            "semantic model edges",
            limits.model_edges,
        )?;
        add_bounded(
            &mut edges,
            function.proofs.len(),
            "semantic model edges",
            limits.model_edges,
        )?;
        add_bounded(
            &mut payload,
            function.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
    }
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        match &ty.kind {
            sema::SemanticTypeKind::Function { parameters, .. } => {
                add_bounded(
                    &mut edges,
                    parameters.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
            }
            sema::SemanticTypeKind::Structure {
                arguments, fields, ..
            }
            | sema::SemanticTypeKind::Class {
                arguments, fields, ..
            } => {
                add_bounded(
                    &mut edges,
                    arguments.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                add_bounded(
                    &mut edges,
                    fields.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                for field in fields {
                    check_cancelled(is_cancelled)?;
                    add_bounded(
                        &mut payload,
                        field.name.len(),
                        "semantic payload bytes",
                        limits.payload_bytes,
                    )?;
                }
            }
            sema::SemanticTypeKind::Enumeration {
                arguments,
                variants,
                ..
            } => {
                add_bounded(
                    &mut edges,
                    arguments.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                add_bounded(
                    &mut edges,
                    variants.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                for variant in variants {
                    check_cancelled(is_cancelled)?;
                    add_bounded(
                        &mut payload,
                        variant.name.len(),
                        "semantic payload bytes",
                        limits.payload_bytes,
                    )?;
                    add_bounded(
                        &mut edges,
                        variant.fields.len(),
                        "semantic model edges",
                        limits.model_edges,
                    )?;
                }
            }
            _ => {}
        }
    }
    for value in &facts.values {
        check_cancelled(is_cancelled)?;
        if let Some(name) = &value.source_name {
            add_bounded(
                &mut payload,
                name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
        }
    }
    for expression in &facts.expressions {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut edges,
            expression.proofs.len(),
            "semantic model edges",
            limits.model_edges,
        )?;
        if let sema::ExpressionResolution::DirectCall { arguments, .. }
        | sema::ExpressionResolution::OperatorCall { arguments, .. } = &expression.resolution
        {
            add_bounded(
                &mut edges,
                arguments.len(),
                "semantic model edges",
                limits.model_edges,
            )?;
        }
    }
    for proof in &facts.proofs {
        check_cancelled(is_cancelled)?;
        for count in [
            proof.sources.len(),
            proof.depends_on.len(),
            proof.explanation.len(),
        ] {
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
        add_bounded(
            &mut payload,
            proof.subject.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut payload,
                line.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
        }
    }
    for statement in &facts.statements {
        check_cancelled(is_cancelled)?;
        for count in [
            statement.definitions.len(),
            statement.initialized_after.len(),
            statement.moved_after.len(),
            statement.live_loans_after.len(),
            statement.proofs.len(),
        ] {
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
    }
    if let Some(group) = &facts.compiled_test_group {
        add_bounded(
            &mut edges,
            group.tests.len(),
            "semantic model edges",
            limits.model_edges,
        )?;
        add_bounded(
            &mut payload,
            group.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        let root_name = match &group.root {
            ImageRoot::GeneratedHarness { harness_name } => harness_name,
            ImageRoot::Declared { image_name, .. } => image_name,
        };
        add_bounded(
            &mut payload,
            root_name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        for test in &group.tests {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut edges,
                test.assertions.len(),
                "semantic model edges",
                limits.model_edges,
            )?;
            add_bounded(
                &mut payload,
                test.descriptor.name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
            for assertion in &test.assertions {
                check_cancelled(is_cancelled)?;
                add_bounded(
                    &mut payload,
                    assertion.expression.len(),
                    "semantic payload bytes",
                    limits.payload_bytes,
                )?;
                if let Some(message) = &assertion.message {
                    add_bounded(
                        &mut payload,
                        message.len(),
                        "semantic payload bytes",
                        limits.payload_bytes,
                    )?;
                }
            }
        }
    }
    if let Some(graph) = &facts.graph {
        add_bounded(
            &mut payload,
            graph.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
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
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
        for actor in &graph.actors {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut payload,
                actor.name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
            add_bounded(
                &mut edges,
                actor.message_types.len(),
                "semantic model edges",
                limits.model_edges,
            )?;
            add_bounded(
                &mut edges,
                actor.turn_functions.len(),
                "semantic model edges",
                limits.model_edges,
            )?;
        }
        for task in &graph.tasks {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut payload,
                task.name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
        }
        for region in &graph.regions {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut payload,
                region.name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
        }
    }
    check_cancelled(is_cancelled)?;
    Ok((edges, payload))
}

fn check_count(resource: &'static str, count: usize, limit: u64) -> Result<(), LowerError> {
    if u64::try_from(count).map_or(true, |count| count > limit) {
        Err(LowerError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

fn add_bounded(
    total: &mut u64,
    count: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), LowerError> {
    let count = u64::try_from(count).map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    *total = total
        .checked_add(count)
        .ok_or(LowerError::ResourceLimit { resource, limit })?;
    if *total > limit {
        Err(LowerError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

fn try_vec<T>(capacity: usize, resource: &'static str, limit: u64) -> Result<Vec<T>, LowerError> {
    check_count(resource, capacity, limit)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    Ok(output)
}

fn cancellable_sort<T: Copy + Ord>(
    values: &mut [T],
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    cancellable_sort_by(values, resource, limit, is_cancelled, &T::cmp)
}

fn cancellable_sort_by<T: Copy>(
    values: &mut [T],
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
    compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<(), LowerError> {
    let Some(first) = values.first().copied() else {
        return check_cancelled(is_cancelled);
    };
    let mut buffer = try_vec(values.len(), resource, limit)?;
    buffer.resize(values.len(), first);
    let mut width = 1_usize;
    let mut source_is_values = true;
    while width < values.len() {
        if source_is_values {
            cancellable_merge_pass(values, &mut buffer, width, is_cancelled, compare)?;
        } else {
            cancellable_merge_pass(&buffer, values, width, is_cancelled, compare)?;
        }
        source_is_values = !source_is_values;
        width = match width.checked_mul(2) {
            Some(next) => next,
            None => values.len(),
        };
    }
    if !source_is_values {
        for (destination, source) in values.iter_mut().zip(buffer) {
            check_cancelled(is_cancelled)?;
            *destination = source;
        }
    }
    Ok(())
}

fn cancellable_merge_pass<T: Copy>(
    source: &[T],
    destination: &mut [T],
    width: usize,
    is_cancelled: &dyn Fn() -> bool,
    compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<(), LowerError> {
    let mut start = 0_usize;
    while start < source.len() {
        let middle = match start.checked_add(width) {
            Some(index) => index.min(source.len()),
            None => source.len(),
        };
        let end = match middle.checked_add(width) {
            Some(index) => index.min(source.len()),
            None => source.len(),
        };
        let (mut left, mut right) = (start, middle);
        for output in &mut destination[start..end] {
            check_cancelled(is_cancelled)?;
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
    Ok(())
}

fn cancellable_dedup<T: Copy + Eq>(
    values: &mut Vec<T>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut write = 0_usize;
    for read in 0..values.len() {
        check_cancelled(is_cancelled)?;
        if write == 0 || values[read] != values[write - 1] {
            values[write] = values[read];
            write += 1;
        }
    }
    values.truncate(write);
    Ok(())
}

fn reject_adjacent_duplicates<T: Eq>(
    values: &[T],
    feature: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut prior = None;
    for value in values {
        check_cancelled(is_cancelled)?;
        if prior == Some(value) {
            return Err(unsupported(feature));
        }
        prior = Some(value);
    }
    Ok(())
}

fn cancellable_slices_equal<T: Eq>(
    left: &[T],
    right: &[T],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn copy_text(value: &str, limit: u64) -> Result<String, LowerError> {
    check_count("SemanticWir payload bytes", value.len(), limit)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| LowerError::ResourceLimit {
            resource: "SemanticWir payload bytes",
            limit,
        })?;
    output.push_str(value);
    Ok(output)
}

fn unsupported(feature: &'static str) -> LowerError {
    LowerError::UnsupportedInput { feature }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LowerError> {
    if is_cancelled() {
        Err(LowerError::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    UnsupportedInput { feature: &'static str },
    MissingSemanticFact { subject: String, fact: &'static str },
    InvalidReport(&'static str),
    InvalidOutput(ValidationErrors),
    InternalInvariant(String),
}

impl fmt::Display for LowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("SemanticWir lowering was cancelled"),
            Self::InvalidLimits => {
                formatter.write_str("SemanticWir lowering limits must be nonzero")
            }
            Self::ResourceLimit { resource, limit } => write!(
                formatter,
                "SemanticWir lowering exceeded {resource} limit {limit}"
            ),
            Self::UnsupportedInput { feature } => {
                write!(
                    formatter,
                    "SemanticWir lowering does not yet support {feature}"
                )
            }
            Self::MissingSemanticFact { subject, fact } => {
                write!(formatter, "semantic analysis omitted {fact} for {subject}")
            }
            Self::InvalidReport(reason) => {
                write!(formatter, "invalid SemanticWir lowering report: {reason}")
            }
            Self::InvalidOutput(error) => error.fmt(formatter),
            Self::InternalInvariant(message) => write!(
                formatter,
                "SemanticWir lowering invariant failed: {message}"
            ),
        }
    }
}

impl std::error::Error for LowerError {}

pub fn seal(
    request: &LowerRequest,
    wir: SemanticWir,
    report: LoweringReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LowerOutput, LowerError> {
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    request.limits.validate()?;
    preflight_input(request.input.facts(), request.limits, is_cancelled)?;
    if matches!(
        supported_input(&request.input, request.limits, is_cancelled)?,
        SupportedInput::Minimum(_)
    ) {
        validate_candidate_minimum_shape(&wir)?;
    }
    validate_model_resources(&wir, request.limits, is_cancelled)?;
    let validation_limits = semantic_validation_limits(request.limits)?;
    let wir = wir
        .validate_with_limits(validation_limits, is_cancelled)
        .map_err(map_validation_failure)?;
    validate_report(&request.input, &wir, &report, request.limits, is_cancelled)?;
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    Ok(LowerOutput { wir, report })
}

fn semantic_validation_limits(limits: LoweringLimits) -> Result<wir::ValidationLimits, LowerError> {
    let nesting = limits.constant_depth.max(limits.structured_region_depth);
    let multiplier = u64::from(nesting)
        .checked_add(64)
        .ok_or_else(|| resource_error(limits))?;
    let validation_work = limits
        .model_edges
        .checked_mul(multiplier)
        .ok_or_else(|| resource_error(limits))?;
    let arena_records = u64::from(limits.types)
        .max(u64::from(limits.functions))
        .max(limits.values.min(u64::from(u32::MAX)))
        .max(limits.operations.min(u64::from(u32::MAX)));
    Ok(wir::ValidationLimits {
        arena_records,
        model_edges: limits.model_edges,
        payload_bytes: limits.payload_bytes,
        validation_work,
        nesting,
        errors: u32::try_from(limits.model_edges.min(100_000)).unwrap_or(100_000),
    })
}

fn map_validation_failure(error: wir::ValidationFailure) -> LowerError {
    match error {
        wir::ValidationFailure::InvalidLimits => LowerError::InvalidLimits,
        wir::ValidationFailure::Cancelled => LowerError::Cancelled,
        wir::ValidationFailure::ResourceLimit { resource, limit } => {
            LowerError::ResourceLimit { resource, limit }
        }
        wir::ValidationFailure::Invalid(errors) => LowerError::InvalidOutput(errors),
    }
}

#[derive(Default)]
struct ResourceMeter {
    edges: u64,
    payload_bytes: u64,
    maximum_constant_depth: u32,
    overflowed: bool,
}

impl ResourceMeter {
    fn edges<T>(&mut self, values: &[T]) {
        self.add_edges(values.len());
    }

    fn add_edges(&mut self, count: usize) {
        let Some(count) = u64::try_from(count).ok() else {
            self.overflowed = true;
            return;
        };
        let Some(total) = self.edges.checked_add(count) else {
            self.overflowed = true;
            return;
        };
        self.edges = total;
    }

    fn text(&mut self, value: &str) {
        self.add_payload(value.len());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.add_payload(value.len());
    }

    fn add_payload(&mut self, count: usize) {
        let Some(count) = u64::try_from(count).ok() else {
            self.overflowed = true;
            return;
        };
        let Some(total) = self.payload_bytes.checked_add(count) else {
            self.overflowed = true;
            return;
        };
        self.payload_bytes = total;
    }
}

#[derive(Clone, Copy)]
struct SemanticResourceView<'a> {
    name: &'a str,
    types: &'a [wir::TypeRecord],
    globals: &'a [wir::Global],
    functions: &'a [wir::SemanticFunction],
    actors: &'a [wir::ActorInstance],
    tasks: &'a [wir::TaskInstance],
    devices: &'a [wir::DeviceInstance],
    pools: &'a [wir::PoolInstance],
    regions: &'a [wir::RegionRecord],
    activations: &'a [wir::ActivationPlan],
    scopes: &'a [wir::ScopePlan],
    proofs: &'a [wir::ProofRecord],
    tests: &'a [wir::TestEntry],
    compiled_test_group: Option<&'a wrela_test_model::FullImageTestGroup>,
    startup_order: usize,
    shutdown_order: usize,
}

impl<'a> From<&'a SemanticWir> for SemanticResourceView<'a> {
    fn from(wir: &'a SemanticWir) -> Self {
        Self {
            name: &wir.name,
            types: &wir.types,
            globals: &wir.globals,
            functions: &wir.functions,
            actors: &wir.actors,
            tasks: &wir.tasks,
            devices: &wir.devices,
            pools: &wir.pools,
            regions: &wir.regions,
            activations: &wir.activations,
            scopes: &wir.scopes,
            proofs: &wir.proofs,
            tests: &wir.tests,
            compiled_test_group: wir.compiled_test_group.as_ref(),
            startup_order: wir.startup_order.len(),
            shutdown_order: wir.shutdown_order.len(),
        }
    }
}

fn validate_model_resources(
    wir: &SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let meter = measure_model_resources(wir.into(), limits, is_cancelled)?;
    if meter.overflowed
        || meter.edges > limits.model_edges
        || meter.payload_bytes > limits.payload_bytes
        || meter.maximum_constant_depth > limits.constant_depth
    {
        return Err(resource_error(limits));
    }
    check_cancelled(is_cancelled)
}

fn measure_model_resources(
    wir: SemanticResourceView<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ResourceMeter, LowerError> {
    use wrela_semantic_wir::{Constant, SemanticOperation, SemanticStatement, TypeKind};

    let mut meter = ResourceMeter::default();
    check_cancelled(is_cancelled)?;
    meter.text(wir.name);
    for count in [
        wir.types.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.actors.len(),
        wir.tasks.len(),
        wir.devices.len(),
        wir.pools.len(),
        wir.regions.len(),
        wir.activations.len(),
        wir.scopes.len(),
        wir.proofs.len(),
        wir.tests.len(),
        wir.startup_order,
        wir.shutdown_order,
    ] {
        meter.add_edges(count);
    }

    if let Some(group) = wir.compiled_test_group {
        meter.add_edges(group.tests.len());
        meter.text(&group.name);
        match &group.root {
            wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
                meter.text(harness_name);
            }
            wrela_test_model::ImageRoot::Declared { image_name, .. } => {
                meter.text(image_name);
            }
        }
        for test in &group.tests {
            check_cancelled(is_cancelled)?;
            meter.text(&test.descriptor.name);
            meter.add_edges(test.assertions.len());
            for assertion in &test.assertions {
                check_cancelled(is_cancelled)?;
                meter.text(&assertion.expression);
                if let Some(message) = &assertion.message {
                    meter.text(message);
                }
            }
        }
    }

    for ty in wir.types {
        check_cancelled(is_cancelled)?;
        meter.text(&ty.source_name);
        match &ty.kind {
            TypeKind::Tuple(items) => meter.edges(items),
            TypeKind::Struct { fields } => {
                meter.edges(fields);
                for field in fields {
                    meter.text(&field.name);
                }
            }
            TypeKind::Enum { variants } => {
                meter.edges(variants);
                for variant in variants {
                    meter.text(&variant.name);
                    meter.edges(&variant.fields);
                    for field in &variant.fields {
                        meter.text(&field.name);
                    }
                }
            }
            TypeKind::Function(function) => meter.edges(&function.parameters),
            TypeKind::OpaqueTarget { name } => meter.text(name),
            TypeKind::Primitive(_)
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

    let mut constants: Vec<(&Constant, u32)> = Vec::new();
    for global in wir.globals {
        check_cancelled(is_cancelled)?;
        meter.text(&global.name);
        constants.push((&global.initializer, 1));
    }
    for function in wir.functions {
        check_cancelled(is_cancelled)?;
        meter.text(&function.name);
        meter.edges(&function.parameters);
        meter.edges(&function.values);
        meter.edges(&function.proofs);
        for value in &function.values {
            if let Some(name) = &value.name {
                meter.text(name);
            }
        }
        let mut regions = vec![&function.body];
        while let Some(region) = regions.pop() {
            check_cancelled(is_cancelled)?;
            meter.edges(&region.parameters);
            meter.edges(&region.statements);
            for statement in &region.statements {
                match statement {
                    SemanticStatement::Let(statement) => {
                        meter.edges(&statement.results);
                        match &statement.operation {
                            SemanticOperation::Constant(value) => constants.push((value, 1)),
                            SemanticOperation::Aggregate { fields, .. } => meter.edges(fields),
                            SemanticOperation::Call { arguments, .. }
                            | SemanticOperation::ActorCommit { arguments, .. }
                            | SemanticOperation::SpawnTask { arguments, .. } => {
                                meter.edges(arguments)
                            }
                            SemanticOperation::Select { awaitables }
                            | SemanticOperation::Race { awaitables }
                            | SemanticOperation::QueuePublish {
                                payloads: awaitables,
                                ..
                            } => meter.edges(awaitables),
                            SemanticOperation::Assert { failure, .. } => {
                                meter.text(&failure.expression);
                                if let Some(message) = &failure.message {
                                    meter.text(message);
                                }
                            }
                            SemanticOperation::Unary { .. }
                            | SemanticOperation::Binary { .. }
                            | SemanticOperation::Convert { .. }
                            | SemanticOperation::ConstructEnum { .. }
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
                            | SemanticOperation::MailboxReceive { .. }
                            | SemanticOperation::ActorSend { .. }
                            | SemanticOperation::ActorTrySend { .. }
                            | SemanticOperation::Await { .. }
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
                        }
                    }
                    SemanticStatement::If {
                        then_region,
                        else_region,
                        results,
                        ..
                    } => {
                        meter.edges(results);
                        regions.push(then_region);
                        regions.push(else_region);
                    }
                    SemanticStatement::Match { arms, results, .. } => {
                        meter.edges(arms);
                        meter.edges(results);
                        for arm in arms {
                            meter.edges(&arm.bindings);
                            regions.push(&arm.body);
                        }
                    }
                    SemanticStatement::Loop { body, carried, .. } => {
                        meter.edges(carried);
                        regions.push(body);
                    }
                    SemanticStatement::Return(values)
                    | SemanticStatement::Yield(values)
                    | SemanticStatement::Break(values)
                    | SemanticStatement::Continue(values) => {
                        meter.edges(values);
                    }
                    SemanticStatement::Unreachable => {}
                }
            }
        }
    }
    while let Some((constant, depth)) = constants.pop() {
        check_cancelled(is_cancelled)?;
        meter.add_edges(1);
        meter.maximum_constant_depth = meter.maximum_constant_depth.max(depth);
        match constant {
            Constant::Bytes(bytes) => meter.bytes(bytes),
            Constant::String(value) => meter.text(value),
            Constant::Enum { fields, .. } | Constant::Aggregate(fields) => {
                meter.edges(fields);
                let next = depth.checked_add(1).ok_or_else(|| resource_error(limits))?;
                constants.extend(fields.iter().map(|field| (field, next)));
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

    for actor in wir.actors {
        check_cancelled(is_cancelled)?;
        meter.text(&actor.name);
        meter.edges(&actor.message_types);
        meter.edges(&actor.turn_functions);
    }
    for task in wir.tasks {
        check_cancelled(is_cancelled)?;
        meter.text(&task.name);
    }
    for device in wir.devices {
        check_cancelled(is_cancelled)?;
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
    for pool in wir.pools {
        check_cancelled(is_cancelled)?;
        meter.text(&pool.name);
        meter.edges(&pool.reachable_devices);
    }
    for region in wir.regions {
        check_cancelled(is_cancelled)?;
        meter.text(&region.name);
    }
    for _activation in wir.activations {
        check_cancelled(is_cancelled)?;
    }
    for scope in wir.scopes {
        check_cancelled(is_cancelled)?;
        meter.text(&scope.name);
        meter.edges(&scope.dependencies);
    }
    for proof in wir.proofs {
        check_cancelled(is_cancelled)?;
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            meter.text(line);
        }
    }
    for test in wir.tests {
        check_cancelled(is_cancelled)?;
        meter.text(&test.name);
    }

    check_cancelled(is_cancelled)?;
    Ok(meter)
}

fn validate_candidate_minimum_shape(wir: &SemanticWir) -> Result<(), LowerError> {
    let generated_body = wir.functions.as_slice().first().is_some_and(|function| {
        function.parameters.is_empty()
            && function.values.is_empty()
            && function.body.parameters.is_empty()
            && matches!(
                function.body.statements.as_slice(),
                [wir::SemanticStatement::Return(values)] if values.is_empty()
            )
    });
    if wir.types.len() != 1
        || wir.functions.len() != 1
        || wir.proofs.len() != 3
        || !wir.globals.is_empty()
        || !wir.actors.is_empty()
        || !wir.tasks.is_empty()
        || !wir.devices.is_empty()
        || !wir.pools.is_empty()
        || !wir.regions.is_empty()
        || !wir.activations.is_empty()
        || !wir.scopes.is_empty()
        || !wir.tests.is_empty()
        || wir.startup_order.as_slice() != [wir::ImageOwner::Runtime]
        || wir.shutdown_order.as_slice() != [wir::ImageOwner::Runtime]
        || !generated_body
    {
        Err(LowerError::InvalidReport(
            "candidate is not the supported minimum generated image",
        ))
    } else {
        Ok(())
    }
}

fn resource_error(limits: LoweringLimits) -> LowerError {
    LowerError::ResourceLimit {
        resource: "SemanticWir model edges, payload bytes, or constant depth",
        limit: limits.payload_bytes,
    }
}

fn validate_report(
    input: &AnalyzedImage,
    validated: &ValidatedSemanticWir,
    report: &LoweringReport,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    check_cancelled(is_cancelled)?;
    match supported_input(input, limits, is_cancelled)? {
        SupportedInput::GeneratedTests(generated) => {
            let (expected_wir, expected_report) =
                lower_generated_tests(&generated, limits, is_cancelled)?;
            if validated.as_wir() != &expected_wir || *report != expected_report {
                return Err(LowerError::InvalidReport(
                    "generated test SemanticWir differs from its exact semantic group and protocol frames",
                ));
            }
            return check_cancelled(is_cancelled);
        }
        SupportedInput::ActorImage(actor) => {
            let (expected_wir, expected_report) = lower_actor_image(&actor, limits, is_cancelled)?;
            if !semantic_actor_wir_matches(validated.as_wir(), &expected_wir, limits, is_cancelled)?
                || *report != expected_report
            {
                return Err(LowerError::InvalidReport(
                    "actor SemanticWir differs from its exact semantic graph, bodies, capacities, or proofs",
                ));
            }
            return check_cancelled(is_cancelled);
        }
        SupportedInput::Minimum(_) => {}
    }
    let wir = validated.as_wir();
    let facts = input.facts();
    if wir.build != facts.build
        || match facts.graph.as_ref() {
            Some(graph) => !text_matches(&graph.name, &wir.name, is_cancelled)?,
            None => true,
        }
    {
        return Err(LowerError::InvalidReport(
            "SemanticWir image or build differs from analyzed input",
        ));
    }
    let semantic_types = u32::try_from(wir.types.len()).ok();
    let function_instances = u32::try_from(wir.functions.len()).ok();
    let proofs = u32::try_from(wir.proofs.len()).ok();
    let tests = u32::try_from(wir.tests.len()).ok();
    let image_nodes = wir
        .actors
        .len()
        .checked_add(wir.tasks.len())
        .and_then(|count| count.checked_add(wir.devices.len()))
        .and_then(|count| count.checked_add(wir.pools.len()))
        .and_then(|count| count.checked_add(wir.regions.len()))
        .and_then(|count| count.checked_add(wir.activations.len()))
        .and_then(|count| u32::try_from(count).ok());
    let mut maximum_depth = 0u32;
    let operations = wir.functions.iter().try_fold(0u64, |total, function| {
        let (count, depth) = count_operations(&function.body, 1, limits.structured_region_depth)?;
        maximum_depth = maximum_depth.max(depth);
        total.checked_add(count)
    });
    let values = wir.functions.iter().try_fold(0u64, |total, function| {
        total.checked_add(u64::try_from(function.values.len()).ok()?)
    });
    let mut functions_match = facts.functions.len() == wir.functions.len();
    for (source, output) in facts.functions.iter().zip(&wir.functions) {
        check_cancelled(is_cancelled)?;
        functions_match &= semantic_function_matches(source, output, is_cancelled)?;
    }
    let graph_matches = match facts.graph.as_ref() {
        Some(graph) => semantic_graph_matches(graph, wir, is_cancelled)?,
        None => false,
    };
    let minimum = supported_minimum(facts)?;
    let source_summary_matches = wir.source_summary.hir_files == facts.hir.files
        && wir.source_summary.hir_declarations == facts.hir.declarations
        && wir.source_summary.reachable_declarations
            == minimum_provenance_declaration_count(minimum.constructor)
        && wir.source_summary.monomorphized_instantiations == 1
        && wir.source_summary.resolved_interface_calls == 0;
    let types_match = matches!(
        wir.types.as_slice(),
        [wir::TypeRecord {
            id: wir::TypeId(0),
            source_name,
            kind: wir::TypeKind::Primitive(wir::PrimitiveType::Unit),
            linearity: wir::Linearity::CopyScalar,
            source: None,
        }] if source_name == "unit"
    );
    let mut proofs_match = facts.proofs.len() == wir.proofs.len();
    for (source, output) in facts.proofs.iter().zip(&wir.proofs) {
        check_cancelled(is_cancelled)?;
        proofs_match &= semantic_proof_matches(source, output, is_cancelled)?;
    }
    let generated_body_matches = wir.functions.first().is_some_and(|function| {
        function.values.is_empty()
            && function.parameters.is_empty()
            && function.body.parameters.is_empty()
            && matches!(
                function.body.statements.as_slice(),
                [wir::SemanticStatement::Return(values)] if values.is_empty()
            )
            && function.id.0 == minimum.function.id.0
    });
    if semantic_types != Some(report.semantic_types)
        || function_instances != Some(report.function_instances)
        || operations != Some(report.operations)
        || proofs != Some(report.proofs)
        || image_nodes != Some(report.image_nodes)
        || tests != Some(report.tests)
        || semantic_types.is_none_or(|count| count > limits.types)
        || function_instances.is_none_or(|count| count > limits.functions)
        || values.is_none_or(|count| count > limits.values)
        || operations.is_none_or(|count| count > limits.operations)
        || maximum_depth > limits.structured_region_depth
        || !functions_match
        || !graph_matches
        || !source_summary_matches
        || !types_match
        || !proofs_match
        || !generated_body_matches
        || !wir.globals.is_empty()
        || !wir.scopes.is_empty()
    {
        Err(LowerError::InvalidReport(
            "reported counts do not match validated SemanticWir",
        ))
    } else {
        Ok(())
    }
}

fn semantic_function_matches(
    source: &wrela_sema::FunctionInstance,
    output: &wrela_semantic_wir::SemanticFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let origin = match source.origin {
        wrela_sema::FunctionOrigin::Source { .. }
        | wrela_sema::FunctionOrigin::SourceClosure { .. } => {
            wrela_semantic_wir::FunctionOrigin::Source
        }
        wrela_sema::FunctionOrigin::GeneratedImageEntry { constructor } => {
            wrela_semantic_wir::FunctionOrigin::GeneratedImageEntry {
                constructor: constructor.0,
            }
        }
        wrela_sema::FunctionOrigin::GeneratedTestHarness { group } => {
            wrela_semantic_wir::FunctionOrigin::GeneratedTestHarness { group: group.0 }
        }
    };
    let role = match source.role {
        wrela_sema::FunctionRole::Ordinary => wrela_semantic_wir::FunctionRole::Ordinary,
        wrela_sema::FunctionRole::ActorTurn(id) => {
            wrela_semantic_wir::FunctionRole::ActorTurn(wrela_semantic_wir::ActorId(id.0))
        }
        wrela_sema::FunctionRole::TaskEntry(id) => {
            wrela_semantic_wir::FunctionRole::TaskEntry(wrela_semantic_wir::TaskId(id.0))
        }
        wrela_sema::FunctionRole::Isr(id) => {
            wrela_semantic_wir::FunctionRole::Isr(wrela_semantic_wir::DeviceId(id.0))
        }
        wrela_sema::FunctionRole::Cleanup => wrela_semantic_wir::FunctionRole::Cleanup,
        wrela_sema::FunctionRole::ImageEntry => wrela_semantic_wir::FunctionRole::ImageEntry,
        wrela_sema::FunctionRole::Test => wrela_semantic_wir::FunctionRole::Test,
    };
    let color = match source.color {
        wrela_hir::FunctionColor::Sync => wrela_semantic_wir::FunctionColor::Sync,
        wrela_hir::FunctionColor::Async => wrela_semantic_wir::FunctionColor::Async,
        wrela_hir::FunctionColor::Isr => wrela_semantic_wir::FunctionColor::Isr,
    };
    let mut proofs_match = output.proofs.len() == source.proofs.len();
    for (output, source) in output.proofs.iter().zip(&source.proofs) {
        check_cancelled(is_cancelled)?;
        proofs_match &= output.0 == source.0;
    }
    Ok(output.id.0 == source.id.0
        && output.instance_key == source.key.0
        && text_matches(&output.name, &source.name, is_cancelled)?
        && output.origin == origin
        && output.role == role
        && output.color == color
        && output.result.0 == source.result.0
        && output.effects.0 == source.effects.0
        && proofs_match
        && output.source == source.source
        && output.stack_bound == source.stack_bytes_bound
        && output.frame_bound == source.frame_bytes_bound
        && output.uninterrupted_bound == source.uninterrupted_work_bound
        && output.recursive_depth_bound == source.recursive_depth_bound)
}

fn semantic_proof_matches(
    source: &sema::Proof,
    output: &wir::ProofRecord,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if output.sources.len() != source.sources.len()
        || output.depends_on.len() != source.depends_on.len()
        || output.explanation.len() != source.explanation.len()
    {
        return Ok(false);
    }
    for (output, source) in output.sources.iter().zip(&source.sources) {
        check_cancelled(is_cancelled)?;
        if output != source {
            return Ok(false);
        }
    }
    for (output, source) in output.depends_on.iter().zip(&source.depends_on) {
        check_cancelled(is_cancelled)?;
        if output.0 != source.0 {
            return Ok(false);
        }
    }
    for (output, source) in output.explanation.iter().zip(&source.explanation) {
        if !text_matches(output, source, is_cancelled)? {
            return Ok(false);
        }
    }
    Ok(output.id.0 == source.id.0
        && output.kind == lower_proof_kind(&source.kind)
        && text_matches(&output.subject, &source.subject, is_cancelled)?
        && output.bound == source.bound
        && output.sources.len() == source.sources.len())
}

fn text_matches(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .as_bytes()
        .chunks(64 * 1024)
        .zip(right.as_bytes().chunks(64 * 1024))
    {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn semantic_actor_wir_matches(
    left: &SemanticWir,
    right: &SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.version != right.version
        || !text_matches(&left.name, &right.name, is_cancelled)?
        || left.build != right.build
        || left.source_summary != right.source_summary
        || left.image_entry != right.image_entry
        || left.static_bytes != right.static_bytes
        || left.peak_bytes != right.peak_bytes
        || left.types.len() != right.types.len()
        || left.functions.len() != right.functions.len()
        || left.actors.len() != right.actors.len()
        || left.tasks.len() != right.tasks.len()
        || left.regions.len() != right.regions.len()
        || left.activations.len() != right.activations.len()
        || left.scopes.len() != right.scopes.len()
        || left.proofs.len() != right.proofs.len()
        || left.startup_order.len() != right.startup_order.len()
        || left.shutdown_order.len() != right.shutdown_order.len()
        || !left.globals.is_empty()
        || !right.globals.is_empty()
        || !left.devices.is_empty()
        || !right.devices.is_empty()
        || !left.pools.is_empty()
        || !right.pools.is_empty()
        || !left.tests.is_empty()
        || !right.tests.is_empty()
        || left.compiled_test_group.is_some()
        || right.compiled_test_group.is_some()
    {
        return Ok(false);
    }
    for (left, right) in left.scopes.iter().zip(&right.scopes) {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    for (left, right) in left.types.iter().zip(&right.types) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || !text_matches(&left.source_name, &right.source_name, is_cancelled)?
            || left.linearity != right.linearity
            || left.source != right.source
            || !actor_type_kind_matches(&left.kind, &right.kind, is_cancelled)?
        {
            return Ok(false);
        }
    }
    for (left, right) in left.functions.iter().zip(&right.functions) {
        check_cancelled(is_cancelled)?;
        if !actor_function_matches(left, right, limits, is_cancelled)? {
            return Ok(false);
        }
    }
    for (left, right) in left.actors.iter().zip(&right.actors) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || !text_matches(&left.name, &right.name, is_cancelled)?
            || left.ty != right.ty
            || left.priority != right.priority
            || left.mailbox_capacity != right.mailbox_capacity
            || !cancellable_slices_equal(&left.message_types, &right.message_types, is_cancelled)?
            || !cancellable_slices_equal(&left.turn_functions, &right.turn_functions, is_cancelled)?
            || left.supervisor != right.supervisor
        {
            return Ok(false);
        }
    }
    for (left, right) in left.tasks.iter().zip(&right.tasks) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || !text_matches(&left.name, &right.name, is_cancelled)?
            || left.entry != right.entry
            || left.slots != right.slots
            || left.priority != right.priority
            || left.supervisor != right.supervisor
        {
            return Ok(false);
        }
    }
    for (left, right) in left.regions.iter().zip(&right.regions) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || !text_matches(&left.name, &right.name, is_cancelled)?
            || left.class != right.class
            || left.capacity_bytes != right.capacity_bytes
            || left.alignment != right.alignment
            || left.owner != right.owner
            || left.proof != right.proof
            || left.source != right.source
        {
            return Ok(false);
        }
    }
    for (left, right) in left.activations.iter().zip(&right.activations) {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    for (left, right) in left.proofs.iter().zip(&right.proofs) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || left.kind != right.kind
            || !text_matches(&left.subject, &right.subject, is_cancelled)?
            || left.bound != right.bound
            || !cancellable_slices_equal(&left.sources, &right.sources, is_cancelled)?
            || !cancellable_slices_equal(&left.depends_on, &right.depends_on, is_cancelled)?
            || left.explanation.len() != right.explanation.len()
        {
            return Ok(false);
        }
        for (left, right) in left.explanation.iter().zip(&right.explanation) {
            if !text_matches(left, right, is_cancelled)? {
                return Ok(false);
            }
        }
    }
    Ok(
        cancellable_slices_equal(&left.startup_order, &right.startup_order, is_cancelled)?
            && cancellable_slices_equal(&left.shutdown_order, &right.shutdown_order, is_cancelled)?,
    )
}

fn actor_type_kind_matches(
    left: &wir::TypeKind,
    right: &wir::TypeKind,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (left, right) {
        (wir::TypeKind::Primitive(left), wir::TypeKind::Primitive(right)) => left == right,
        (
            wir::TypeKind::Array {
                element: left_element,
                length: left_length,
            },
            wir::TypeKind::Array {
                element: right_element,
                length: right_length,
            },
        ) => left_element == right_element && left_length == right_length,
        (wir::TypeKind::Struct { fields: left }, wir::TypeKind::Struct { fields: right }) => {
            actor_structure_fields_match(left, right, is_cancelled)?
        }
        (wir::TypeKind::Enum { variants: left }, wir::TypeKind::Enum { variants: right }) => {
            actor_enum_variants_match(left, right, is_cancelled)?
        }
        (wir::TypeKind::Function(left), wir::TypeKind::Function(right)) => {
            left.color == right.color
                && left.result == right.result
                && cancellable_slices_equal(&left.parameters, &right.parameters, is_cancelled)?
        }
        (
            wir::TypeKind::ActorHandle { actor_type: left },
            wir::TypeKind::ActorHandle { actor_type: right },
        ) => left == right,
        (wir::TypeKind::Reservation, wir::TypeKind::Reservation) => true,
        _ => false,
    })
}

fn actor_structure_fields_match(
    left: &[wir::FieldType],
    right: &[wir::FieldType],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if left.ty != right.ty
            || left.public != right.public
            || !text_matches(&left.name, &right.name, is_cancelled)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn actor_enum_variants_match(
    left: &[wir::VariantType],
    right: &[wir::VariantType],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if !text_matches(&left.name, &right.name, is_cancelled)?
            || left.fields.len() != right.fields.len()
        {
            return Ok(false);
        }
        for (left, right) in left.fields.iter().zip(&right.fields) {
            check_cancelled(is_cancelled)?;
            if left.ty != right.ty
                || left.public != right.public
                || !text_matches(&left.name, &right.name, is_cancelled)?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn actor_function_matches(
    left: &wir::SemanticFunction,
    right: &wir::SemanticFunction,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.id != right.id
        || left.instance_key != right.instance_key
        || !text_matches(&left.name, &right.name, is_cancelled)?
        || left.origin != right.origin
        || left.role != right.role
        || left.color != right.color
        || !cancellable_slices_equal(&left.parameters, &right.parameters, is_cancelled)?
        || left.result != right.result
        || left.values.len() != right.values.len()
        || left.effects != right.effects
        || !cancellable_slices_equal(&left.proofs, &right.proofs, is_cancelled)?
        || left.source != right.source
        || left.stack_bound != right.stack_bound
        || left.frame_bound != right.frame_bound
        || left.uninterrupted_bound != right.uninterrupted_bound
        || left.recursive_depth_bound != right.recursive_depth_bound
    {
        return Ok(false);
    }
    for (left, right) in left.values.iter().zip(&right.values) {
        check_cancelled(is_cancelled)?;
        if left.id != right.id
            || left.ty != right.ty
            || left.origin != right.origin
            || match (&left.name, &right.name) {
                (Some(left), Some(right)) => !text_matches(left, right, is_cancelled)?,
                (None, None) => false,
                _ => true,
            }
        {
            return Ok(false);
        }
    }
    actor_regions_match(&left.body, &right.body, limits, is_cancelled)
}

fn actor_regions_match(
    left: &wir::SemanticRegion,
    right: &wir::SemanticRegion,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let mut work = try_vec(1, "actor SemanticWir comparison", limits.model_edges)?;
    work.push((left, right));
    while let Some((left, right)) = work.pop() {
        check_cancelled(is_cancelled)?;
        if !cancellable_slices_equal(&left.parameters, &right.parameters, is_cancelled)?
            || left.statements.len() != right.statements.len()
        {
            return Ok(false);
        }
        for (left, right) in left.statements.iter().zip(&right.statements) {
            check_cancelled(is_cancelled)?;
            match (left, right) {
                (wir::SemanticStatement::Let(left), wir::SemanticStatement::Let(right)) => {
                    if left.source != right.source
                        || !cancellable_slices_equal(&left.results, &right.results, is_cancelled)?
                        || !actor_operations_match(&left.operation, &right.operation, is_cancelled)?
                    {
                        return Ok(false);
                    }
                }
                (
                    wir::SemanticStatement::If {
                        condition: left_condition,
                        then_region: left_then,
                        else_region: left_else,
                        results: left_results,
                        source: left_source,
                    },
                    wir::SemanticStatement::If {
                        condition: right_condition,
                        then_region: right_then,
                        else_region: right_else,
                        results: right_results,
                        source: right_source,
                    },
                ) => {
                    if left_condition != right_condition
                        || left_source != right_source
                        || !cancellable_slices_equal(left_results, right_results, is_cancelled)?
                    {
                        return Ok(false);
                    }
                    push_bounded_id(
                        &mut work,
                        (left_else, right_else),
                        "actor SemanticWir comparison",
                        limits.model_edges,
                    )?;
                    push_bounded_id(
                        &mut work,
                        (left_then, right_then),
                        "actor SemanticWir comparison",
                        limits.model_edges,
                    )?;
                }
                (
                    wir::SemanticStatement::Match {
                        scrutinee: left_scrutinee,
                        arms: left_arms,
                        results: left_results,
                        source: left_source,
                    },
                    wir::SemanticStatement::Match {
                        scrutinee: right_scrutinee,
                        arms: right_arms,
                        results: right_results,
                        source: right_source,
                    },
                ) => {
                    if left_scrutinee != right_scrutinee
                        || left_source != right_source
                        || left_arms.len() != right_arms.len()
                        || !cancellable_slices_equal(left_results, right_results, is_cancelled)?
                    {
                        return Ok(false);
                    }
                    for (left_arm, right_arm) in left_arms.iter().zip(right_arms) {
                        check_cancelled(is_cancelled)?;
                        if left_arm.variant != right_arm.variant
                            || left_arm.guard != right_arm.guard
                            || !cancellable_slices_equal(
                                &left_arm.bindings,
                                &right_arm.bindings,
                                is_cancelled,
                            )?
                        {
                            return Ok(false);
                        }
                        push_bounded_id(
                            &mut work,
                            (&left_arm.body, &right_arm.body),
                            "actor SemanticWir comparison",
                            limits.model_edges,
                        )?;
                    }
                }
                (wir::SemanticStatement::Return(left), wir::SemanticStatement::Return(right))
                | (wir::SemanticStatement::Yield(left), wir::SemanticStatement::Yield(right))
                | (wir::SemanticStatement::Break(left), wir::SemanticStatement::Break(right))
                | (
                    wir::SemanticStatement::Continue(left),
                    wir::SemanticStatement::Continue(right),
                ) => {
                    if !cancellable_slices_equal(left, right, is_cancelled)? {
                        return Ok(false);
                    }
                }
                (wir::SemanticStatement::Unreachable, wir::SemanticStatement::Unreachable) => {}
                _ => return Ok(false),
            }
        }
    }
    Ok(true)
}

fn actor_operations_match(
    left: &wir::SemanticOperation,
    right: &wir::SemanticOperation,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (left, right) {
        (wir::SemanticOperation::Constant(left), wir::SemanticOperation::Constant(right)) => {
            actor_constants_match(left, right, is_cancelled)?
        }
        (
            wir::SemanticOperation::Unary {
                operator: lo,
                operand: lv,
                arithmetic: la,
            },
            wir::SemanticOperation::Unary {
                operator: ro,
                operand: rv,
                arithmetic: ra,
            },
        ) => lo == ro && lv == rv && la == ra,
        (
            wir::SemanticOperation::Binary {
                operator: lo,
                left: ll,
                right: lr,
                arithmetic: la,
            },
            wir::SemanticOperation::Binary {
                operator: ro,
                left: rl,
                right: rr,
                arithmetic: ra,
            },
        ) => lo == ro && ll == rl && lr == rr && la == ra,
        (
            wir::SemanticOperation::Convert {
                value: lv,
                destination: ld,
                checked: lc,
            },
            wir::SemanticOperation::Convert {
                value: rv,
                destination: rd,
                checked: rc,
            },
        ) => lv == rv && ld == rd && lc == rc,
        (
            wir::SemanticOperation::Aggregate {
                ty: left_ty,
                fields: left_fields,
            },
            wir::SemanticOperation::Aggregate {
                ty: right_ty,
                fields: right_fields,
            },
        ) => {
            left_ty == right_ty
                && cancellable_slices_equal(left_fields, right_fields, is_cancelled)?
        }
        (
            wir::SemanticOperation::InsertField {
                aggregate: left_aggregate,
                field: left_field,
                value: left_value,
            },
            wir::SemanticOperation::InsertField {
                aggregate: right_aggregate,
                field: right_field,
                value: right_value,
            },
        ) => {
            left_aggregate == right_aggregate
                && left_field == right_field
                && left_value == right_value
        }
        (
            wir::SemanticOperation::Project {
                base: left_base,
                field: left_field,
                access: left_access,
            },
            wir::SemanticOperation::Project {
                base: right_base,
                field: right_field,
                access: right_access,
            },
        ) => left_base == right_base && left_field == right_field && left_access == right_access,
        (
            wir::SemanticOperation::ConstructEnum {
                ty: left_ty,
                variant: left_variant,
                payload: left_payload,
            },
            wir::SemanticOperation::ConstructEnum {
                ty: right_ty,
                variant: right_variant,
                payload: right_payload,
            },
        ) => left_ty == right_ty && left_variant == right_variant && left_payload == right_payload,
        (
            wir::SemanticOperation::Copy { value: left },
            wir::SemanticOperation::Copy { value: right },
        )
        | (
            wir::SemanticOperation::Await { awaitable: left },
            wir::SemanticOperation::Await { awaitable: right },
        ) => left == right,
        (
            wir::SemanticOperation::Call {
                function: lf,
                arguments: la,
                activation: lp,
            },
            wir::SemanticOperation::Call {
                function: rf,
                arguments: ra,
                activation: rp,
            },
        ) => lf == rf && lp == rp && cancellable_slices_equal(la, ra, is_cancelled)?,
        (
            wir::SemanticOperation::ActorCapability {
                actor: la,
                wiring_proof: lp,
            },
            wir::SemanticOperation::ActorCapability {
                actor: ra,
                wiring_proof: rp,
            },
        ) => la == ra && lp == rp,
        (
            wir::SemanticOperation::ActorReserve {
                actor: la,
                method: lm,
                permit_proof: lp,
            },
            wir::SemanticOperation::ActorReserve {
                actor: ra,
                method: rm,
                permit_proof: rp,
            },
        ) => la == ra && lm == rm && lp == rp,
        (
            wir::SemanticOperation::ActorCommit {
                reservation: lr,
                arguments: la,
            },
            wir::SemanticOperation::ActorCommit {
                reservation: rr,
                arguments: ra,
            },
        ) => lr == rr && cancellable_slices_equal(la, ra, is_cancelled)?,
        (
            wir::SemanticOperation::MailboxReceive {
                actor: la,
                method: lm,
            },
            wir::SemanticOperation::MailboxReceive {
                actor: ra,
                method: rm,
            },
        ) => la == ra && lm == rm,
        (
            wir::SemanticOperation::ActorStateLoad {
                actor: la,
                region: lr,
                proof: lp,
            },
            wir::SemanticOperation::ActorStateLoad {
                actor: ra,
                region: rr,
                proof: rp,
            },
        ) => la == ra && lr == rr && lp == rp,
        (
            wir::SemanticOperation::ActorStateStore {
                actor: la,
                region: lr,
                value: lv,
                proof: lp,
            },
            wir::SemanticOperation::ActorStateStore {
                actor: ra,
                region: rr,
                value: rv,
                proof: rp,
            },
        ) => la == ra && lr == rr && lv == rv && lp == rp,
        (
            wir::SemanticOperation::EnterScope {
                scope: left_scope,
                state: left_state,
            },
            wir::SemanticOperation::EnterScope {
                scope: right_scope,
                state: right_state,
            },
        ) => left_scope == right_scope && left_state == right_state,
        (
            wir::SemanticOperation::CommitScope {
                scope: left_scope,
                value: left_value,
            },
            wir::SemanticOperation::CommitScope {
                scope: right_scope,
                value: right_value,
            },
        ) => left_scope == right_scope && left_value == right_value,
        (
            wir::SemanticOperation::ExitScope { scope: left },
            wir::SemanticOperation::ExitScope { scope: right },
        ) => left == right,
        _ => false,
    })
}

fn actor_constants_match(
    left: &wir::Constant,
    right: &wir::Constant,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (left, right) {
        (wir::Constant::Bytes(left), wir::Constant::Bytes(right)) => {
            cancellable_slices_equal(left, right, is_cancelled)?
        }
        (wir::Constant::String(left), wir::Constant::String(right)) => {
            text_matches(left, right, is_cancelled)?
        }
        (wir::Constant::Unit, wir::Constant::Unit) => true,
        (wir::Constant::Bool(left), wir::Constant::Bool(right)) => left == right,
        (
            wir::Constant::Unsigned {
                bits: lb,
                value: lv,
            },
            wir::Constant::Unsigned {
                bits: rb,
                value: rv,
            },
        ) => lb == rb && lv == rv,
        (
            wir::Constant::Signed {
                bits: lb,
                value: lv,
            },
            wir::Constant::Signed {
                bits: rb,
                value: rv,
            },
        ) => lb == rb && lv == rv,
        (wir::Constant::Float32(left), wir::Constant::Float32(right)) => left == right,
        (wir::Constant::Float64(left), wir::Constant::Float64(right)) => left == right,
        (wir::Constant::Char(left), wir::Constant::Char(right)) => left == right,
        (wir::Constant::Zeroed(left), wir::Constant::Zeroed(right)) => left == right,
        _ => false,
    })
}

fn semantic_graph_matches(
    graph: &wrela_sema::ImageGraph,
    output: &wrela_semantic_wir::SemanticWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let mut activation_bytes = Some(0_u64);
    for plan in &output.activations {
        check_cancelled(is_cancelled)?;
        activation_bytes = activation_bytes.and_then(|total| {
            plan.frame_bytes
                .checked_mul(u64::from(plan.maximum_live))
                .and_then(|bytes| total.checked_add(bytes))
        });
    }
    if output.image_entry.0 != graph.entry.0
        || activation_bytes.and_then(|bytes| graph.static_bytes.checked_add(bytes))
            != Some(output.static_bytes)
        || activation_bytes.and_then(|bytes| graph.peak_bytes.checked_add(bytes))
            != Some(output.peak_bytes)
        || graph.actors.len() != output.actors.len()
        || graph.tasks.len() != output.tasks.len()
        || graph.devices.len() != output.devices.len()
        || graph.pools.len() != output.pools.len()
        || graph.regions.len().checked_add(output.activations.len()) != Some(output.regions.len())
        || output.startup_order.len() != graph.startup_order.len()
        || output.shutdown_order.len() != graph.shutdown_order.len()
    {
        return Ok(false);
    }
    for (source, out) in graph.actors.iter().zip(&output.actors) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !text_matches(&out.name, &source.name, is_cancelled)?
            || out.ty.0 != source.class.0
            || out.priority != source.priority
            || out.mailbox_capacity != source.mailbox_capacity
            || out.message_types.len() != source.message_types.len()
            || out.turn_functions.len() != source.turn_functions.len()
            || out.supervisor.map(|id| id.0) != source.supervisor.map(|id| id.0)
        {
            return Ok(false);
        }
        for (out, source) in out.message_types.iter().zip(&source.message_types) {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
        for (out, source) in out.turn_functions.iter().zip(&source.turn_functions) {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
    }
    for (source, out) in graph.tasks.iter().zip(&output.tasks) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !text_matches(&out.name, &source.name, is_cancelled)?
            || out.entry.0 != source.entry.0
            || out.slots != source.slots
            || out.priority != source.priority
            || out.supervisor.map(|id| id.0) != source.supervisor.map(|id| id.0)
        {
            return Ok(false);
        }
    }
    for (source, out) in graph.devices.iter().zip(&output.devices) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !text_matches(&out.name, &source.name, is_cancelled)?
            || !text_matches(&out.target_binding, &source.target_binding, is_cancelled)?
            || out.owner.0 != source.owner.0
            || !text_slices_match(
                &out.required_features,
                &source.required_features,
                is_cancelled,
            )?
            || !text_slices_match(
                &out.optional_features,
                &source.optional_features,
                is_cancelled,
            )?
            || out.interrupt_functions.len() != source.interrupt_functions.len()
            || out.queue_capacity != source.queue_capacity
            || out.maximum_in_flight != source.maximum_in_flight
            || out.reset_timeout_ns != source.reset_timeout_ns
        {
            return Ok(false);
        }
        for (out, source) in out
            .interrupt_functions
            .iter()
            .zip(&source.interrupt_functions)
        {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
    }
    for (source, out) in graph.pools.iter().zip(&output.pools) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !text_matches(&out.name, &source.name, is_cancelled)?
            || out.payload.0 != source.payload.0
            || out.capacity != source.capacity
            || out.alignment != u64::from(source.alignment)
            || out.reachable_devices.len() != source.reachable_devices.len()
        {
            return Ok(false);
        }
        for (out, source) in out.reachable_devices.iter().zip(&source.reachable_devices) {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
    }
    for (source, out) in graph.regions.iter().zip(&output.regions) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !text_matches(&out.name, &source.name, is_cancelled)?
            || !semantic_region_class(out.class, source.class)
            || out.capacity_bytes != source.capacity_bytes
            || out.alignment != u64::from(source.alignment)
            || !semantic_owner(out.owner, source.owner)
            || out.proof.0 != source.proof.0
            || out.source != source.source
        {
            return Ok(false);
        }
    }
    for (out, source) in output.startup_order.iter().zip(&graph.startup_order) {
        check_cancelled(is_cancelled)?;
        if !semantic_owner(*out, *source) {
            return Ok(false);
        }
    }
    for (out, source) in output.shutdown_order.iter().zip(&graph.shutdown_order) {
        check_cancelled(is_cancelled)?;
        if !semantic_owner(*out, *source) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn text_slices_match(
    left: &[String],
    right: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        if !text_matches(left, right, is_cancelled)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn semantic_region_class(
    output: wrela_semantic_wir::RegionClass,
    source: wrela_sema::RegionClass,
) -> bool {
    match (output, source) {
        (wrela_semantic_wir::RegionClass::Image, wrela_sema::RegionClass::Image)
        | (wrela_semantic_wir::RegionClass::Call, wrela_sema::RegionClass::Call)
        | (wrela_semantic_wir::RegionClass::TaskFrame, wrela_sema::RegionClass::TaskFrame)
        | (wrela_semantic_wir::RegionClass::Request, wrela_sema::RegionClass::Request)
        | (wrela_semantic_wir::RegionClass::Static, wrela_sema::RegionClass::Static) => true,
        (wrela_semantic_wir::RegionClass::Pool(out), wrela_sema::RegionClass::Pool(source)) => {
            out.0 == source.0
        }
        _ => false,
    }
}

fn semantic_owner(output: wrela_semantic_wir::ImageOwner, source: wrela_sema::ImageOwner) -> bool {
    match (output, source) {
        (wrela_semantic_wir::ImageOwner::Runtime, wrela_sema::ImageOwner::Runtime) => true,
        (wrela_semantic_wir::ImageOwner::Actor(out), wrela_sema::ImageOwner::Actor(source)) => {
            out.0 == source.0
        }
        (wrela_semantic_wir::ImageOwner::Task(out), wrela_sema::ImageOwner::Task(source)) => {
            out.0 == source.0
        }
        (wrela_semantic_wir::ImageOwner::Device(out), wrela_sema::ImageOwner::Device(source)) => {
            out.0 == source.0
        }
        (wrela_semantic_wir::ImageOwner::Pool(out), wrela_sema::ImageOwner::Pool(source)) => {
            out.0 == source.0
        }
        (
            wrela_semantic_wir::ImageOwner::BakedArtifact(out),
            wrela_sema::ImageOwner::Artifact(source),
        ) => out == source.0,
        _ => false,
    }
}

fn count_operations(region: &SemanticRegion, depth: u32, maximum_depth: u32) -> Option<(u64, u32)> {
    if depth > maximum_depth {
        return None;
    }
    region
        .statements
        .iter()
        .try_fold((0u64, depth), |(count, seen_depth), statement| {
            let nested = match statement {
                SemanticStatement::Let(_) => (1, depth),
                SemanticStatement::If {
                    then_region,
                    else_region,
                    ..
                } => {
                    let then = count_operations(then_region, depth + 1, maximum_depth)?;
                    let otherwise = count_operations(else_region, depth + 1, maximum_depth)?;
                    (then.0.checked_add(otherwise.0)?, then.1.max(otherwise.1))
                }
                SemanticStatement::Match { arms, .. } => {
                    arms.iter().try_fold((0u64, depth), |(sum, seen), arm| {
                        let arm = count_operations(&arm.body, depth + 1, maximum_depth)?;
                        Some((sum.checked_add(arm.0)?, seen.max(arm.1)))
                    })?
                }
                SemanticStatement::Loop { body, .. } => {
                    count_operations(body, depth + 1, maximum_depth)?
                }
                SemanticStatement::Return(_)
                | SemanticStatement::Yield(_)
                | SemanticStatement::Break(_)
                | SemanticStatement::Continue(_)
                | SemanticStatement::Unreachable => (0, depth),
            };
            Some((count.checked_add(nested.0)?, seen_depth.max(nested.1)))
        })
}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use wrela_build_model::{
        BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
        TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
    };
    use wrela_hir::{
        AccessMode, AggregateDeclaration, Attribute, AttributeIdentity, Body, BodyId, BodyOwner,
        Builtin, BuiltinAttribute, CallArgument, CallableOwner, Declaration, DeclarationId,
        DeclarationKind, DeclarationOwner, EnumDeclaration, EnumVariant, Expression, ExpressionId,
        ExpressionKind, ExpressionOwner, FunctionColor, FunctionDeclaration, LexicalScope, Literal,
        Local, LocalId, Module, Name, Parameter, Program, ResolvedDeclaration, ResolvedVariant,
        Statement, StatementId, StatementKind, TypeExpression, TypeExpressionKind,
        ValidatedProgram, Visibility,
    };
    use wrela_hir_lower::{
        CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer,
        LowerRequest as HirLowerRequest, LoweringLimits as HirLoweringLimits,
    };
    use wrela_package::{
        DependencyAlias, ModuleId, ModulePath, PackageGraphBuilder, PackageId, PackageIdentity,
        PackageName, PackageVersion,
    };
    use wrela_sema::{
        AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest,
        CanonicalSemanticAnalyzer, SemanticAnalyzer, TestDiscoverySelection,
    };
    use wrela_source::{FileId, SourceDatabase, SourceInput, Span, TextRange};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
    use wrela_target::{TargetPackage, TargetSemanticContract};
    use wrela_test_model::{
        DeclaredImageTest, IMAGE_SCENARIO_SCHEMA, ImageGroupId, ImageScenario, ImageScenarioStep,
    };
    use wrela_test_protocol::{ProtocolLimits, decode_and_verify_event};

    use super::*;

    const STANDARD_LIBRARY_PACKAGE_DIGEST: Sha256Digest = Sha256Digest::from_bytes([2; 32]);
    const STANDARD_LIBRARY_COMPONENT_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0x22; 32]);
    const TARGET_DIGEST: Sha256Digest = Sha256Digest::from_bytes([3; 32]);
    const PARSED_CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
    const PARSED_CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");
    const PARSED_CORE_OPS_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/ops.wr");
    const PARSED_STDLIB_TIME_RUNTIME_SOURCE: &str =
        include_str!("../../../std/examples/stdlib-time-runtime/src/runtime/time_test.wr");
    const BOUNDED_ACTOR_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        await checkpoint()

    @task
    async fn pulse(mut self):
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;
    const ZERO_STATE_ACTOR_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    value: u64 = 0

    pub async fn ping(mut self):
        await checkpoint()

    @task
    async fn pulse(mut self):
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;
    const PASS_ONLY_SCOPE_ACTOR_SOURCE: &str = r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked() -> Masked:
    enter Masked(token=1)
    exit state:
        pass

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        with irqs_masked() as mask:
            pass
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;

    struct Fixture {
        hir: Arc<ValidatedProgram>,
        target: TargetPackage,
        build: ValidatedBuildConfiguration,
    }

    fn analyze_parsed_actor() -> wrela_sema::AnalyzedImage {
        analyze_parsed_actor_source(BOUNDED_ACTOR_SOURCE)
    }

    fn analyze_pass_only_scope_actor() -> wrela_sema::AnalyzedImage {
        analyze_parsed_actor_source(PASS_ONLY_SCOPE_ACTOR_SOURCE)
    }

    fn analyze_parsed_actor_source(application_source: &str) -> wrela_sema::AnalyzedImage {
        let base = fixture();
        let mut sources = SourceDatabase::default();
        let application_file = sources
            .add(SourceInput {
                path: "app.wr".to_owned(),
                text: application_source.to_owned(),
                digest: Sha256Digest::from_bytes([0xa1; 32]),
            })
            .expect("actor application source");
        let core_file = sources
            .add(SourceInput {
                path: "image.wr".to_owned(),
                text: PARSED_CORE_IMAGE_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xc1; 32]),
            })
            .expect("core image source");
        let mut parsed_files = Vec::new();
        parsed_files
            .try_reserve_exact(2)
            .expect("two parsed actor files");
        for file in [application_file, core_file] {
            let output = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("actor fixture parses");
            assert!(
                output.diagnostics().is_empty(),
                "actor fixture must parse without recovery: {:?}",
                output.diagnostics()
            );
            parsed_files.push(output.into_parts().0);
        }
        let mut packages = PackageGraphBuilder::new(identity(
            "actor-image",
            Sha256Digest::from_bytes([0xb0; 32]),
        ));
        let core = packages
            .add_package(identity("wrela-core", STANDARD_LIBRARY_PACKAGE_DIGEST))
            .expect("core package");
        packages
            .add_dependency(
                packages.root(),
                DependencyAlias::new("core").expect("core alias"),
                core,
            )
            .expect("core dependency");
        packages
            .add_module(
                packages.root(),
                ModulePath::new(["app".to_owned()]).expect("app module path"),
                application_file,
            )
            .expect("app module");
        packages
            .add_module(
                core,
                ModulePath::new(["image".to_owned()]).expect("core module path"),
                core_file,
            )
            .expect("core module");
        let changes = HirChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let lowered = CanonicalHirLowerer::new()
            .lower(
                HirLowerRequest {
                    packages: Arc::new(packages.finish().expect("actor package graph")),
                    source_graph_digest: Sha256Digest::from_bytes([0xd0; 32]),
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &changes,
                    limits: HirLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("actor fixture lowers");
        assert!(
            lowered.diagnostics().is_empty(),
            "actor fixture must lower without recovery: {:?}",
            lowered.diagnostics()
        );
        let hir = Arc::new(lowered.into_parts().0.into_program());
        let entry = *hir
            .as_program()
            .image_candidates
            .first()
            .expect("actor image entry");
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let analyzed = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir,
                    standard_library_package: PackageId(1),
                    target: base.target.semantic(),
                    build: &base.build,
                    mode: AnalysisMode::Image {
                        name: "actor-image",
                        entry,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("actor semantic analysis");
        assert!(
            analyzed.diagnostics().is_empty(),
            "actor semantic analysis must succeed: {:?}",
            analyzed.diagnostics()
        );
        analyzed
            .successful()
            .expect("sealed parsed actor image")
            .clone()
    }

    fn analyze_installed_core_time_generated_group() -> wrela_sema::AnalyzedImage {
        let base = fixture();
        let mut sources = SourceDatabase::default();
        let core_image_file = sources
            .add(SourceInput {
                path: "core/image.wr".to_owned(),
                text: PARSED_CORE_IMAGE_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xc2; 32]),
            })
            .expect("core image source");
        let core_ops_file = sources
            .add(SourceInput {
                path: "core/ops.wr".to_owned(),
                text: PARSED_CORE_OPS_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xc7; 32]),
            })
            .expect("core ops source");
        let core_time_file = sources
            .add(SourceInput {
                path: "core/time.wr".to_owned(),
                text: PARSED_CORE_TIME_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xc3; 32]),
            })
            .expect("core time source");
        let application_file = sources
            .add(SourceInput {
                path: "runtime/time_test.wr".to_owned(),
                text: PARSED_STDLIB_TIME_RUNTIME_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xa2; 32]),
            })
            .expect("stdlib time runtime application source");
        let mut parsed_files = Vec::new();
        parsed_files
            .try_reserve_exact(4)
            .expect("four parsed stdlib time files");
        for file in [
            core_image_file,
            core_ops_file,
            core_time_file,
            application_file,
        ] {
            let output = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("stdlib time runtime fixture parses");
            assert!(
                output.diagnostics().is_empty(),
                "stdlib time runtime fixture must parse without recovery: {:?}",
                output.diagnostics()
            );
            parsed_files.push(output.into_parts().0);
        }

        let mut packages = PackageGraphBuilder::new(identity(
            "stdlib-time-runtime",
            Sha256Digest::from_bytes([0xb2; 32]),
        ));
        let core = packages
            .add_package(identity("wrela-core", STANDARD_LIBRARY_PACKAGE_DIGEST))
            .expect("core package");
        packages
            .add_dependency(
                packages.root(),
                DependencyAlias::new("core").expect("core alias"),
                core,
            )
            .expect("core dependency");
        packages
            .add_module(
                packages.root(),
                ModulePath::new(["runtime".to_owned(), "time_test".to_owned()])
                    .expect("runtime test module path"),
                application_file,
            )
            .expect("runtime test module");
        packages
            .add_module(
                core,
                ModulePath::new(["image".to_owned()]).expect("core image module path"),
                core_image_file,
            )
            .expect("core image module");
        packages
            .add_module(
                core,
                ModulePath::new(["ops".to_owned()]).expect("core ops module path"),
                core_ops_file,
            )
            .expect("core ops module");
        packages
            .add_module(
                core,
                ModulePath::new(["time".to_owned()]).expect("core time module path"),
                core_time_file,
            )
            .expect("core time module");
        let lowered = CanonicalHirLowerer::new()
            .lower(
                HirLowerRequest {
                    packages: Arc::new(packages.finish().expect("stdlib time package graph")),
                    source_graph_digest: Sha256Digest::from_bytes([0xd2; 32]),
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &HirChangeSet {
                        previous_source_graph: None,
                        changed_files: Vec::new(),
                    },
                    limits: HirLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("stdlib time runtime fixture lowers to HIR");
        assert!(
            lowered.diagnostics().is_empty(),
            "stdlib time runtime fixture must lower without recovery: {:?}",
            lowered.diagnostics()
        );
        let hir = Arc::new(lowered.into_parts().0.into_program());
        let entry = *hir
            .as_program()
            .image_candidates
            .first()
            .expect("stdlib time runtime image entry");
        let target = base.target.semantic().clone();
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: Arc::clone(&hir),
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &base.build,
                    mode: AnalysisMode::DiscoverTests {
                        image_name: "stdlib-time-runtime",
                        image_entry: entry,
                        declared_image_tests: &[],
                        source_selection: TestDiscoverySelection::All,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("stdlib time runtime test discovery");
        assert!(
            discovery.diagnostics().is_empty(),
            "stdlib time runtime discovery diagnostics: {:?}",
            discovery.diagnostics()
        );
        let plan = discovery
            .successful()
            .expect("sealed stdlib time runtime discovery")
            .facts()
            .test_plan
            .as_ref()
            .expect("stdlib time runtime test plan")
            .clone();
        let group = plan
            .image_groups()
            .iter()
            .find(|group| {
                group.tests.iter().any(|test| {
                    test.descriptor
                        .name
                        .ends_with("::installed_core_time_executes_in_qemu")
                })
            })
            .expect("generated group containing the installed core.time runtime test");
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir,
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &base.build,
                    mode: AnalysisMode::CompileTestGroup {
                        plan: &plan,
                        group: group.id,
                        declared_entry: None,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("stdlib time runtime group compilation");
        assert!(
            output.diagnostics().is_empty(),
            "stdlib time runtime compilation diagnostics: {:?}",
            output.diagnostics()
        );
        output
            .successful()
            .expect("sealed stdlib time runtime generated image")
            .clone()
    }

    fn span(file: u32, start: u32, end: u32) -> Span {
        Span {
            file: FileId(file),
            range: TextRange { start, end },
        }
    }

    fn name(value: &str) -> Name {
        Name::new(value.to_owned()).expect("valid test name")
    }

    fn identity(name: &str, source_digest: Sha256Digest) -> PackageIdentity {
        PackageIdentity {
            name: PackageName::new(name).expect("package name"),
            version: PackageVersion::new("1.0.0").expect("package version"),
            source_digest,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_runtime_test(false, false)
    }

    fn fixture_with_runtime_test(include_runtime_test: bool, scalar: bool) -> Fixture {
        let root_path = ModulePath::new(["app".to_owned()]).expect("root module path");
        let standard_path = ModulePath::new(["prelude".to_owned()]).expect("standard module path");
        let mut packages =
            PackageGraphBuilder::new(identity("root", Sha256Digest::from_bytes([1; 32])));
        let standard = packages
            .add_package(identity("wrela-std", STANDARD_LIBRARY_PACKAGE_DIGEST))
            .expect("standard package");
        packages
            .add_dependency(
                packages.root(),
                DependencyAlias::new("core").expect("standard alias"),
                standard,
            )
            .expect("standard dependency");
        packages
            .add_module(packages.root(), root_path.clone(), FileId(0))
            .expect("root module");
        packages
            .add_module(standard, standard_path.clone(), FileId(1))
            .expect("standard module");
        let packages = Arc::new(packages.finish().expect("package graph"));

        let root_source = span(0, 0, 500);
        let standard_source = span(1, 0, 200);
        let image_declaration = ResolvedDeclaration {
            package: PackageId(1),
            module: ModuleId(1),
            declaration: DeclarationId(1),
        };
        let target_declaration = ResolvedDeclaration {
            package: PackageId(1),
            module: ModuleId(1),
            declaration: DeclarationId(2),
        };
        let mut program = Program {
            packages,
            modules: vec![
                Module {
                    id: ModuleId(0),
                    package: PackageId(0),
                    path: root_path,
                    declarations: vec![DeclarationId(0)],
                    reexports: Vec::new(),
                    source: root_source,
                },
                Module {
                    id: ModuleId(1),
                    package: PackageId(1),
                    path: standard_path,
                    declarations: vec![DeclarationId(1), DeclarationId(2)],
                    reexports: Vec::new(),
                    source: standard_source,
                },
            ],
            declarations: vec![
                Declaration {
                    id: DeclarationId(0),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(name("boot")),
                    visibility: Visibility::Public,
                    attributes: vec![Attribute {
                        identity: AttributeIdentity::Builtin(BuiltinAttribute::Image),
                        arguments: Vec::new(),
                        source: span(0, 0, 6),
                    }],
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Sync,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: Some(TypeExpression {
                            kind: TypeExpressionKind::Named {
                                definition: wrela_hir::Definition::Declaration(
                                    image_declaration.clone(),
                                ),
                                arguments: Vec::new(),
                            },
                            source: span(0, 7, 12),
                        }),
                        body: Some(BodyId(0)),
                    }),
                    source: root_source,
                },
                Declaration {
                    id: DeclarationId(1),
                    module: ModuleId(1),
                    owner: DeclarationOwner::Module(ModuleId(1)),
                    name: Some(name("Image")),
                    visibility: Visibility::Public,
                    attributes: Vec::new(),
                    kind: DeclarationKind::Structure(AggregateDeclaration {
                        generics: Vec::new(),
                        implements: Vec::new(),
                        fields: Vec::new(),
                        members: Vec::new(),
                        linear: false,
                        copy: false,
                        deriving: Vec::new(),
                    }),
                    source: span(1, 10, 60),
                },
                Declaration {
                    id: DeclarationId(2),
                    module: ModuleId(1),
                    owner: DeclarationOwner::Module(ModuleId(1)),
                    name: Some(name("Target")),
                    visibility: Visibility::Public,
                    attributes: Vec::new(),
                    kind: DeclarationKind::Enumeration(EnumDeclaration {
                        generics: Vec::new(),
                        variants: vec![EnumVariant {
                            name: name("aarch64_qemu_virt_uefi"),
                            fields: Vec::new(),
                            source: span(1, 80, 110),
                        }],
                        members: Vec::new(),
                        deriving: Vec::new(),
                    }),
                    source: span(1, 70, 120),
                },
            ],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![Body {
                id: BodyId(0),
                owner: BodyOwner::Declaration(DeclarationId(0)),
                scope: wrela_hir::ScopeId(0),
                locals: Vec::new(),
                statements: vec![StatementId(0)],
                source: span(0, 20, 180),
            }],
            scopes: vec![LexicalScope {
                id: wrela_hir::ScopeId(0),
                body: BodyId(0),
                parent: None,
                source: span(0, 20, 180),
            }],
            locals: Vec::new(),
            statements: vec![Statement {
                id: StatementId(0),
                body: BodyId(0),
                attributes: Vec::new(),
                kind: StatementKind::Return(Some(ExpressionId(0))),
                source: span(0, 30, 170),
            }],
            expressions: vec![
                Expression {
                    id: ExpressionId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(wrela_hir::ScopeId(0)),
                    kind: ExpressionKind::Call {
                        callee: ExpressionId(1),
                        arguments: vec![
                            CallArgument {
                                name: Some(name("name")),
                                value: wrela_hir::CallArgumentValue::Value(ExpressionId(2)),
                                source: span(0, 48, 65),
                            },
                            CallArgument {
                                name: Some(name("target")),
                                value: wrela_hir::CallArgumentValue::Value(ExpressionId(3)),
                                source: span(0, 68, 92),
                            },
                        ],
                    },
                    source: span(0, 40, 100),
                },
                Expression {
                    id: ExpressionId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(wrela_hir::ScopeId(0)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                        image_declaration,
                    )),
                    source: span(0, 40, 45),
                },
                Expression {
                    id: ExpressionId(2),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(wrela_hir::ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::String("runtime-image".to_owned())),
                    source: span(0, 50, 63),
                },
                Expression {
                    id: ExpressionId(3),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(wrela_hir::ScopeId(0)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Variant(
                        ResolvedVariant {
                            enumeration: target_declaration,
                            variant: 0,
                        },
                    )),
                    source: span(0, 70, 90),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: vec![DeclarationId(0)],
            test_candidates: Vec::new(),
        };
        if include_runtime_test {
            program.modules[0]
                .declarations
                .extend([DeclarationId(3), DeclarationId(4)]);
            program.declarations.extend([
                Declaration {
                    id: DeclarationId(3),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(name("runtime_case")),
                    visibility: Visibility::Private,
                    attributes: vec![Attribute {
                        identity: AttributeIdentity::Builtin(BuiltinAttribute::Test),
                        arguments: Vec::new(),
                        source: span(0, 210, 215),
                    }],
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Sync,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: None,
                        body: Some(BodyId(1)),
                    }),
                    source: span(0, 210, 400),
                },
                Declaration {
                    id: DeclarationId(4),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(name("comptime_case")),
                    visibility: Visibility::Private,
                    attributes: vec![Attribute {
                        identity: AttributeIdentity::Builtin(BuiltinAttribute::Test),
                        arguments: Vec::new(),
                        source: span(0, 410, 415),
                    }],
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Sync,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: None,
                        body: Some(BodyId(2)),
                    }),
                    source: span(0, 410, 490),
                },
            ]);
            program.bodies.extend([
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(3)),
                    scope: wrela_hir::ScopeId(1),
                    locals: Vec::new(),
                    statements: vec![StatementId(1), StatementId(2)],
                    source: span(0, 220, 390),
                },
                Body {
                    id: BodyId(2),
                    owner: BodyOwner::Declaration(DeclarationId(4)),
                    scope: wrela_hir::ScopeId(2),
                    locals: Vec::new(),
                    statements: vec![StatementId(3)],
                    source: span(0, 420, 480),
                },
            ]);
            program.scopes.extend([
                LexicalScope {
                    id: wrela_hir::ScopeId(1),
                    body: BodyId(1),
                    parent: None,
                    source: span(0, 220, 390),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(2),
                    body: BodyId(2),
                    parent: None,
                    source: span(0, 420, 480),
                },
            ]);
            program.statements.extend([
                Statement {
                    id: StatementId(1),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Pass,
                    source: span(0, 230, 234),
                },
                Statement {
                    id: StatementId(2),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(None),
                    source: span(0, 240, 246),
                },
                Statement {
                    id: StatementId(3),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Pass,
                    source: span(0, 430, 434),
                },
            ]);
            program
                .test_candidates
                .extend([DeclarationId(3), DeclarationId(4)]);
        }
        if include_runtime_test && !scalar {
            // A bounded `while` is outside the comptime evaluator's supported
            // subset, so this (inserted before the final `return`) keeps
            // `runtime_case` reachable through the runtime/image tier
            // deterministically: with every function color now
            // phase-neutral, its previous trivial `pass; return` body would
            // otherwise be comptime-legal on its own and collide with
            // `comptime_case`. The `scalar` fixture variant gets its own
            // guard through `helper`'s body instead, so this only applies
            // when that variant isn't in play.
            let u32_ty = |source| TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(Builtin::U32),
                    arguments: Vec::new(),
                },
                source,
            };
            program.locals.push(Local {
                id: LocalId(0),
                body: BodyId(1),
                scope: wrela_hir::ScopeId(1),
                name: name("guard"),
                ty: Some(u32_ty(span(0, 236, 239))),
                shadowed: None,
                source: span(0, 236, 239),
            });
            program.bodies.push(Body {
                id: BodyId(3),
                owner: BodyOwner::Declaration(DeclarationId(3)),
                scope: wrela_hir::ScopeId(3),
                locals: Vec::new(),
                statements: vec![StatementId(6)],
                source: span(0, 236, 239),
            });
            program.scopes.push(LexicalScope {
                id: wrela_hir::ScopeId(3),
                body: BodyId(3),
                parent: Some(wrela_hir::ScopeId(1)),
                source: span(0, 236, 239),
            });
            program.bodies[1].locals = vec![LocalId(0)];
            program.bodies[1].statements = vec![
                StatementId(1),
                StatementId(2),
                StatementId(4),
                StatementId(5),
            ];
            program.statements[2] = Statement {
                id: StatementId(2),
                body: BodyId(1),
                attributes: Vec::new(),
                kind: StatementKind::Initialize {
                    local: LocalId(0),
                    value: ExpressionId(4),
                },
                source: span(0, 236, 239),
            };
            program.statements.extend([
                Statement {
                    id: StatementId(4),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::While {
                        condition: ExpressionId(5),
                        body: BodyId(3),
                    },
                    source: span(0, 236, 239),
                },
                Statement {
                    id: StatementId(5),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(None),
                    source: span(0, 240, 246),
                },
                Statement {
                    id: StatementId(6),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Assign {
                        targets: vec![wrela_hir::PlaceTarget {
                            root: wrela_hir::Definition::Local(LocalId(0)),
                            projections: Vec::new(),
                            source: span(0, 236, 239),
                        }],
                        operator: wrela_hir::AssignmentOperator::Add,
                        value: ExpressionId(8),
                    },
                    source: span(0, 236, 239),
                },
            ]);
            program.expressions.extend([
                Expression {
                    id: ExpressionId(4),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("0".to_owned())),
                    source: span(0, 236, 239),
                },
                Expression {
                    id: ExpressionId(5),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Compare {
                        left: ExpressionId(6),
                        operator: wrela_hir::ComparisonOperator::Less,
                        right: ExpressionId(7),
                    },
                    source: span(0, 236, 239),
                },
                Expression {
                    id: ExpressionId(6),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(0))),
                    source: span(0, 236, 239),
                },
                Expression {
                    id: ExpressionId(7),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 236, 239),
                },
                Expression {
                    id: ExpressionId(8),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 236, 239),
                },
            ]);
        }
        if scalar {
            let bool_ty = |source| TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(Builtin::Bool),
                    arguments: Vec::new(),
                },
                source,
            };
            let u32_ty = |source| TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: wrela_hir::Definition::Builtin(Builtin::U32),
                    arguments: Vec::new(),
                },
                source,
            };
            program.modules[0].declarations.push(DeclarationId(5));
            program.declarations.push(Declaration {
                id: DeclarationId(5),
                module: ModuleId(0),
                owner: DeclarationOwner::Module(ModuleId(0)),
                name: Some(name("helper")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Function(FunctionDeclaration {
                    color: FunctionColor::Sync,
                    generics: Vec::new(),
                    parameters: vec![wrela_hir::ParameterId(0), wrela_hir::ParameterId(1)],
                    result: Some(u32_ty(span(0, 188, 191))),
                    body: Some(BodyId(3)),
                }),
                source: span(0, 170, 209),
            });
            program.parameters.extend([
                Parameter {
                    id: wrela_hir::ParameterId(0),
                    owner: CallableOwner::Declaration(DeclarationId(5)),
                    name: Some(name("x")),
                    access: AccessMode::Value,
                    ty: Some(u32_ty(span(0, 176, 179))),
                    receiver: false,
                    positional_only: false,
                    source: span(0, 174, 179),
                },
                Parameter {
                    id: wrela_hir::ParameterId(1),
                    owner: CallableOwner::Declaration(DeclarationId(5)),
                    name: Some(name("y")),
                    access: AccessMode::Value,
                    ty: Some(u32_ty(span(0, 182, 185))),
                    receiver: false,
                    positional_only: false,
                    source: span(0, 180, 185),
                },
            ]);
            program.bodies[1].locals = vec![LocalId(0), LocalId(1), LocalId(3)];
            program.bodies[1].statements = vec![
                StatementId(1),
                StatementId(2),
                StatementId(4),
                StatementId(5),
                StatementId(6),
            ];
            program.bodies.extend([
                Body {
                    id: BodyId(3),
                    owner: BodyOwner::Declaration(DeclarationId(5)),
                    scope: wrela_hir::ScopeId(3),
                    locals: vec![LocalId(2), LocalId(4)],
                    // A bounded `while` is outside the comptime evaluator's
                    // supported subset, so this (inserted before the final
                    // `return`) keeps every test built on this `helper`
                    // reachable through `runtime_case` in the runtime/image
                    // tier deterministically, since every color is
                    // otherwise phase-neutral and this body would be
                    // comptime-legal on its own.
                    statements: vec![
                        StatementId(7),
                        StatementId(10),
                        StatementId(11),
                        StatementId(12),
                    ],
                    source: span(0, 180, 209),
                },
                Body {
                    id: BodyId(4),
                    owner: BodyOwner::Declaration(DeclarationId(3)),
                    scope: wrela_hir::ScopeId(4),
                    locals: Vec::new(),
                    statements: vec![StatementId(8)],
                    source: span(0, 300, 350),
                },
                Body {
                    id: BodyId(5),
                    owner: BodyOwner::Declaration(DeclarationId(5)),
                    scope: wrela_hir::ScopeId(5),
                    locals: Vec::new(),
                    statements: vec![StatementId(9)],
                    source: span(0, 200, 203),
                },
            ]);
            program.scopes.extend([
                LexicalScope {
                    id: wrela_hir::ScopeId(3),
                    body: BodyId(3),
                    parent: None,
                    source: span(0, 180, 209),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(4),
                    body: BodyId(4),
                    parent: Some(wrela_hir::ScopeId(1)),
                    source: span(0, 300, 350),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(5),
                    body: BodyId(5),
                    parent: Some(wrela_hir::ScopeId(3)),
                    source: span(0, 200, 203),
                },
            ]);
            program.locals.extend([
                Local {
                    id: LocalId(0),
                    body: BodyId(1),
                    scope: wrela_hir::ScopeId(1),
                    name: name("flag"),
                    ty: Some(bool_ty(span(0, 230, 234))),
                    shadowed: None,
                    source: span(0, 230, 234),
                },
                Local {
                    id: LocalId(1),
                    body: BodyId(1),
                    scope: wrela_hir::ScopeId(1),
                    name: name("number"),
                    ty: Some(u32_ty(span(0, 250, 253))),
                    shadowed: None,
                    source: span(0, 244, 253),
                },
                Local {
                    id: LocalId(2),
                    body: BodyId(3),
                    scope: wrela_hir::ScopeId(3),
                    name: name("copied"),
                    ty: Some(u32_ty(span(0, 195, 198))),
                    shadowed: None,
                    source: span(0, 194, 201),
                },
                Local {
                    id: LocalId(3),
                    body: BodyId(1),
                    scope: wrela_hir::ScopeId(1),
                    name: name("other"),
                    ty: Some(u32_ty(span(0, 266, 269))),
                    shadowed: None,
                    source: span(0, 262, 269),
                },
                Local {
                    id: LocalId(4),
                    body: BodyId(3),
                    scope: wrela_hir::ScopeId(3),
                    name: name("guard"),
                    ty: Some(u32_ty(span(0, 200, 203))),
                    shadowed: None,
                    source: span(0, 200, 203),
                },
            ]);
            program.statements[1] = Statement {
                id: StatementId(1),
                body: BodyId(1),
                attributes: Vec::new(),
                kind: StatementKind::Initialize {
                    local: LocalId(0),
                    value: ExpressionId(4),
                },
                source: span(0, 230, 242),
            };
            program.statements[2] = Statement {
                id: StatementId(2),
                body: BodyId(1),
                attributes: Vec::new(),
                kind: StatementKind::Initialize {
                    local: LocalId(1),
                    value: ExpressionId(5),
                },
                source: span(0, 244, 260),
            };
            program.statements.extend([
                Statement {
                    id: StatementId(5),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::If {
                        branches: vec![(ExpressionId(6), BodyId(4))],
                        else_body: None,
                    },
                    source: span(0, 270, 350),
                },
                Statement {
                    id: StatementId(6),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(None),
                    source: span(0, 360, 370),
                },
                Statement {
                    id: StatementId(7),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(2),
                        value: ExpressionId(10),
                    },
                    source: span(0, 194, 202),
                },
                Statement {
                    id: StatementId(8),
                    body: BodyId(4),
                    attributes: Vec::new(),
                    kind: StatementKind::Expression(ExpressionId(7)),
                    source: span(0, 310, 350),
                },
                Statement {
                    id: StatementId(12),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(Some(ExpressionId(11))),
                    source: span(0, 203, 208),
                },
                Statement {
                    id: StatementId(4),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(3),
                        value: ExpressionId(12),
                    },
                    source: span(0, 262, 280),
                },
                Statement {
                    id: StatementId(10),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(4),
                        value: ExpressionId(14),
                    },
                    source: span(0, 200, 203),
                },
                Statement {
                    id: StatementId(11),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::While {
                        condition: ExpressionId(15),
                        body: BodyId(5),
                    },
                    source: span(0, 200, 203),
                },
                Statement {
                    id: StatementId(9),
                    body: BodyId(5),
                    attributes: Vec::new(),
                    kind: StatementKind::Assign {
                        targets: vec![wrela_hir::PlaceTarget {
                            root: wrela_hir::Definition::Local(LocalId(4)),
                            projections: Vec::new(),
                            source: span(0, 200, 203),
                        }],
                        operator: wrela_hir::AssignmentOperator::Add,
                        value: ExpressionId(18),
                    },
                    source: span(0, 200, 203),
                },
            ]);
            program
                .statements
                .sort_unstable_by_key(|statement| statement.id);
            program.expressions.extend([
                Expression {
                    id: ExpressionId(4),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Boolean(true)),
                    source: span(0, 238, 242),
                },
                Expression {
                    id: ExpressionId(5),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("7".to_owned())),
                    source: span(0, 256, 257),
                },
                Expression {
                    id: ExpressionId(6),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(0))),
                    source: span(0, 273, 277),
                },
                Expression {
                    id: ExpressionId(7),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Call {
                        callee: ExpressionId(8),
                        arguments: vec![
                            CallArgument {
                                name: Some(name("y")),
                                value: wrela_hir::CallArgumentValue::Value(ExpressionId(9)),
                                source: span(0, 323, 333),
                            },
                            CallArgument {
                                name: Some(name("x")),
                                value: wrela_hir::CallArgumentValue::Value(ExpressionId(13)),
                                source: span(0, 334, 345),
                            },
                        ],
                    },
                    source: span(0, 315, 345),
                },
                Expression {
                    id: ExpressionId(8),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                        ResolvedDeclaration {
                            package: PackageId(0),
                            module: ModuleId(0),
                            declaration: DeclarationId(5),
                        },
                    )),
                    source: span(0, 315, 321),
                },
                Expression {
                    id: ExpressionId(9),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(3))),
                    source: span(0, 327, 332),
                },
                Expression {
                    id: ExpressionId(10),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Parameter(
                        wrela_hir::ParameterId(0),
                    )),
                    source: span(0, 200, 201),
                },
                Expression {
                    id: ExpressionId(11),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(2))),
                    source: span(0, 207, 208),
                },
                Expression {
                    id: ExpressionId(12),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("9".to_owned())),
                    source: span(0, 276, 277),
                },
                Expression {
                    id: ExpressionId(13),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(1))),
                    source: span(0, 338, 344),
                },
                Expression {
                    id: ExpressionId(14),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Literal(Literal::Integer("0".to_owned())),
                    source: span(0, 200, 201),
                },
                Expression {
                    id: ExpressionId(15),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Compare {
                        left: ExpressionId(16),
                        operator: wrela_hir::ComparisonOperator::Less,
                        right: ExpressionId(17),
                    },
                    source: span(0, 200, 203),
                },
                Expression {
                    id: ExpressionId(16),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(4))),
                    source: span(0, 200, 201),
                },
                Expression {
                    id: ExpressionId(17),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 202, 203),
                },
                Expression {
                    id: ExpressionId(18),
                    owner: ExpressionOwner::Body(BodyId(5)),
                    scope: Some(wrela_hir::ScopeId(5)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 202, 203),
                },
            ]);
        }
        let program = program
            .validate()
            .expect("valid semantic-lowering test HIR");

        let profile = BuildProfile::development();
        let profile_digest = Sha256Digest::from_bytes([6; 32]);
        let build = seal_build_configuration(
            BuildConfiguration {
                identity: BuildIdentity {
                    compiler: Sha256Digest::from_bytes([7; 32]),
                    language: LanguageRevision::Design0_1,
                    target: TargetIdentity::aarch64_qemu_virt_uefi(),
                    target_package: TARGET_DIGEST,
                    standard_library: STANDARD_LIBRARY_COMPONENT_DIGEST,
                    source_graph: Sha256Digest::from_bytes([8; 32]),
                    request: Sha256Digest::from_bytes([9; 32]),
                    profile: profile_digest,
                },
                profile,
            },
            profile_digest,
        )
        .expect("sealed build");
        Fixture {
            hir: Arc::new(program),
            target: TargetPackage::aarch64_qemu_virt_uefi(TARGET_DIGEST),
            build,
        }
    }

    fn analyze_minimum() -> (wrela_sema::AnalyzedImage, TargetSemanticContract) {
        let fixture = fixture();
        let target = fixture.target.semantic().clone();
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: fixture.hir,
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &fixture.build,
                    mode: AnalysisMode::Image {
                        name: "runtime-image",
                        entry: DeclarationId(0),
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("semantic analysis");
        assert!(
            output.diagnostics().is_empty(),
            "unexpected semantic diagnostics: {:?}",
            output.diagnostics()
        );
        let (image, _) = output.into_parts();
        (image.expect("sealed analyzed image"), target)
    }

    fn analyze_generated_test_group() -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(fixture_with_runtime_test(true, false))
    }

    fn analyze_scalar_generated_test_group() -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(fixture_with_runtime_test(true, true))
    }

    fn analyze_scalar_join_generated_test_group() -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(scalar_join_fixture())
    }

    fn scalar_type(builtin: Builtin, source: Span) -> TypeExpression {
        TypeExpression {
            kind: TypeExpressionKind::Named {
                definition: wrela_hir::Definition::Builtin(builtin),
                arguments: Vec::new(),
            },
            source,
        }
    }

    fn scalar_operation_fixture(
        input: Builtin,
        result: Builtin,
        argument: Literal,
        operation: impl FnOnce(&mut Program),
    ) -> Fixture {
        let Fixture { hir, target, build } = fixture_with_runtime_test(true, true);
        let mut program = Arc::try_unwrap(hir)
            .expect("scalar operation fixture owns its HIR")
            .into_program();
        let DeclarationKind::Function(helper) = &mut program.declarations[5].kind else {
            unreachable!();
        };
        helper.result = Some(scalar_type(result, span(0, 188, 191)));
        program.parameters[0].ty = Some(scalar_type(input, span(0, 176, 179)));
        program.locals[1].ty = Some(scalar_type(input, span(0, 250, 253)));
        program.locals[2].ty = Some(scalar_type(result, span(0, 195, 198)));
        program.expressions[5].kind = ExpressionKind::Literal(argument);
        program.expressions[10].source = span(0, 199, 205);
        program.statements[7].source = span(0, 194, 205);
        operation(&mut program);
        Fixture {
            hir: Arc::new(
                program
                    .validate()
                    .expect("valid scalar operation producer HIR"),
            ),
            target,
            build,
        }
    }

    fn compound_assignment_fixture(operator: wrela_hir::AssignmentOperator) -> Fixture {
        let Fixture { hir, target, build } = fixture_with_runtime_test(true, true);
        let mut program = Arc::try_unwrap(hir)
            .expect("compound assignment fixture owns its HIR")
            .into_program();
        program.statements[8].kind = StatementKind::Assign {
            targets: vec![wrela_hir::PlaceTarget {
                root: wrela_hir::Definition::Local(LocalId(1)),
                projections: Vec::new(),
                source: span(0, 310, 316),
            }],
            operator,
            value: ExpressionId(7),
        };
        program.statements[8].source = span(0, 310, 350);
        program.expressions[13].kind =
            ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(3)));
        Fixture {
            hir: Arc::new(
                program
                    .validate()
                    .expect("valid compound assignment producer HIR"),
            ),
            target,
            build,
        }
    }

    fn scalar_join_fixture() -> Fixture {
        scalar_join_fixture_for(
            Builtin::U32,
            Literal::Integer("7".to_owned()),
            Literal::Integer("9".to_owned()),
            Literal::Integer("11".to_owned()),
            Literal::Integer("13".to_owned()),
        )
    }

    fn scalar_join_fixture_for(
        ty: Builtin,
        initial: Literal,
        other: Literal,
        then_value: Literal,
        else_value: Literal,
    ) -> Fixture {
        let Fixture { hir, target, build } = fixture_with_runtime_test(true, true);
        let mut program = Arc::try_unwrap(hir)
            .expect("scalar join fixture owns its HIR")
            .into_program();
        let DeclarationKind::Function(helper) = &mut program.declarations[5].kind else {
            unreachable!();
        };
        helper.result = Some(scalar_type(ty, span(0, 188, 191)));
        program.parameters[0].ty = Some(scalar_type(ty, span(0, 176, 179)));
        program.parameters[1].ty = Some(scalar_type(ty, span(0, 182, 185)));
        program.locals[1].ty = Some(scalar_type(ty, span(0, 250, 253)));
        program.locals[2].ty = Some(scalar_type(ty, span(0, 195, 198)));
        program.locals[3].ty = Some(scalar_type(ty, span(0, 266, 269)));
        program.expressions[5].kind = ExpressionKind::Literal(initial);
        program.expressions[12].kind = ExpressionKind::Literal(other);
        let StatementKind::If { else_body, .. } = &mut program.statements[5].kind else {
            unreachable!();
        };
        *else_body = Some(BodyId(6));
        program.bodies[1].statements = vec![
            StatementId(1),
            StatementId(2),
            StatementId(4),
            StatementId(5),
            StatementId(6),
            StatementId(14),
        ];
        program.bodies.push(Body {
            id: BodyId(6),
            owner: BodyOwner::Declaration(DeclarationId(3)),
            scope: wrela_hir::ScopeId(6),
            locals: Vec::new(),
            statements: vec![StatementId(13)],
            source: span(0, 346, 350),
        });
        program.scopes.push(LexicalScope {
            id: wrela_hir::ScopeId(6),
            body: BodyId(6),
            parent: Some(wrela_hir::ScopeId(1)),
            source: span(0, 346, 350),
        });
        program.statements[8] = Statement {
            id: StatementId(8),
            body: BodyId(4),
            attributes: Vec::new(),
            kind: StatementKind::Assign {
                targets: vec![wrela_hir::PlaceTarget {
                    root: wrela_hir::Definition::Local(LocalId(1)),
                    projections: Vec::new(),
                    source: span(0, 310, 316),
                }],
                operator: wrela_hir::AssignmentOperator::Assign,
                value: ExpressionId(19),
            },
            source: span(0, 310, 320),
        };
        program.statements[6] = Statement {
            id: StatementId(6),
            body: BodyId(1),
            attributes: Vec::new(),
            kind: StatementKind::Expression(ExpressionId(7)),
            source: span(0, 355, 380),
        };
        program.statements.extend([
            Statement {
                id: StatementId(13),
                body: BodyId(6),
                attributes: Vec::new(),
                kind: StatementKind::Assign {
                    targets: vec![wrela_hir::PlaceTarget {
                        root: wrela_hir::Definition::Local(LocalId(1)),
                        projections: Vec::new(),
                        source: span(0, 346, 348),
                    }],
                    operator: wrela_hir::AssignmentOperator::Assign,
                    value: ExpressionId(20),
                },
                source: span(0, 346, 350),
            },
            Statement {
                id: StatementId(14),
                body: BodyId(1),
                attributes: Vec::new(),
                kind: StatementKind::Return(None),
                source: span(0, 385, 390),
            },
        ]);
        for expression in [
            ExpressionId(7),
            ExpressionId(8),
            ExpressionId(9),
            ExpressionId(13),
        ] {
            let expression = &mut program.expressions[expression.0 as usize];
            expression.owner = ExpressionOwner::Body(BodyId(1));
            expression.scope = Some(wrela_hir::ScopeId(1));
        }
        program.expressions[7].source = span(0, 355, 380);
        let ExpressionKind::Call { arguments, .. } = &mut program.expressions[7].kind else {
            unreachable!();
        };
        arguments[0].source = span(0, 365, 370);
        arguments[1].source = span(0, 371, 378);
        program.expressions[8].source = span(0, 355, 361);
        program.expressions[9].source = span(0, 367, 369);
        program.expressions[13].source = span(0, 374, 377);
        program.expressions.extend([
            Expression {
                id: ExpressionId(19),
                owner: ExpressionOwner::Body(BodyId(4)),
                scope: Some(wrela_hir::ScopeId(4)),
                kind: ExpressionKind::Literal(then_value),
                source: span(0, 317, 319),
            },
            Expression {
                id: ExpressionId(20),
                owner: ExpressionOwner::Body(BodyId(6)),
                scope: Some(wrela_hir::ScopeId(6)),
                kind: ExpressionKind::Literal(else_value),
                source: span(0, 348, 350),
            },
        ]);
        Fixture {
            hir: Arc::new(program.validate().expect("valid scalar join producer HIR")),
            target,
            build,
        }
    }

    // Base ids 14..=18 are claimed by `fixture_with_runtime_test`'s bounded
    // `while` tier guard, so operand references synthesized for a particular
    // operation start at 19, the first id free of that guard.
    fn helper_operand_expression(id: u32) -> Expression {
        Expression {
            id: ExpressionId(id),
            owner: ExpressionOwner::Body(BodyId(3)),
            scope: Some(wrela_hir::ScopeId(3)),
            kind: ExpressionKind::Reference(wrela_hir::Definition::Parameter(
                wrela_hir::ParameterId(0),
            )),
            source: span(0, 200 + id - 19, 201 + id - 19),
        }
    }

    fn analyze_scalar_unary_operation(
        operator: wrela_hir::UnaryOperator,
        ty: Builtin,
        argument: Literal,
    ) -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(scalar_operation_fixture(ty, ty, argument, |program| {
            program.expressions[10].kind = ExpressionKind::Unary {
                operator,
                operand: ExpressionId(19),
            };
            program.expressions.push(helper_operand_expression(19));
        }))
    }

    fn analyze_scalar_binary_operation(
        operator: wrela_hir::BinaryOperator,
    ) -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(scalar_operation_fixture(
            Builtin::U32,
            Builtin::U32,
            Literal::Integer("7".to_owned()),
            |program| {
                program.expressions[10].kind = ExpressionKind::Binary {
                    operator,
                    left: ExpressionId(19),
                    right: ExpressionId(20),
                };
                program
                    .expressions
                    .extend([helper_operand_expression(19), helper_operand_expression(20)]);
            },
        ))
    }

    fn analyze_scalar_comparison_operation(
        operator: wrela_hir::ComparisonOperator,
    ) -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(scalar_operation_fixture(
            Builtin::U32,
            Builtin::Bool,
            Literal::Integer("7".to_owned()),
            |program| {
                program.expressions[10].kind = ExpressionKind::Compare {
                    left: ExpressionId(19),
                    operator,
                    right: ExpressionId(20),
                };
                program
                    .expressions
                    .extend([helper_operand_expression(19), helper_operand_expression(20)]);
            },
        ))
    }

    fn analyze_scalar_cast_operation() -> wrela_sema::AnalyzedImage {
        analyze_generated_test_group_from(scalar_operation_fixture(
            Builtin::U32,
            Builtin::U64,
            Literal::Integer("7".to_owned()),
            |program| {
                program.expressions[10].kind = ExpressionKind::Cast {
                    value: ExpressionId(19),
                    ty: scalar_type(Builtin::U64, span(0, 202, 205)),
                };
                program.expressions.push(helper_operand_expression(19));
            },
        ))
    }

    /// Removes the expression at `id` (which the caller has just made
    /// unreachable) and shifts every higher expression id down by one, so
    /// the arena stays dense. Only handles the narrow set of
    /// `ExpressionKind`/`StatementKind` variants these HIR test fixtures
    /// actually construct; panics loudly if it meets anything else, since a
    /// silently-missed reference would reintroduce exactly the coverage gap
    /// this exists to close.
    fn drop_and_renumber_expression(program: &mut Program, id: ExpressionId) {
        fn shift(candidate: &mut ExpressionId, removed: u32) {
            if candidate.0 > removed {
                candidate.0 -= 1;
            }
        }
        let position = program
            .expressions
            .iter()
            .position(|expression| expression.id == id)
            .expect("expression id present");
        program.expressions.remove(position);
        for expression in &mut program.expressions {
            shift(&mut expression.id, id.0);
            match &mut expression.kind {
                ExpressionKind::Literal(_) | ExpressionKind::Reference(_) => {}
                ExpressionKind::Compare { left, right, .. }
                | ExpressionKind::Binary { left, right, .. } => {
                    shift(left, id.0);
                    shift(right, id.0);
                }
                ExpressionKind::Unary { operand, .. } => shift(operand, id.0),
                ExpressionKind::Cast { value, .. } => shift(value, id.0),
                ExpressionKind::Call { callee, arguments } => {
                    shift(callee, id.0);
                    for argument in arguments {
                        if let wrela_hir::CallArgumentValue::Value(value) = &mut argument.value {
                            shift(value, id.0);
                        }
                    }
                }
                other => unreachable!("unexpected expression kind in test fixture: {other:?}"),
            }
        }
        for statement in &mut program.statements {
            match &mut statement.kind {
                StatementKind::Pass | StatementKind::Return(None) => {}
                StatementKind::Initialize { value, .. } | StatementKind::Assign { value, .. } => {
                    shift(value, id.0);
                }
                StatementKind::Return(Some(value)) => shift(value, id.0),
                StatementKind::Expression(value) => shift(value, id.0),
                StatementKind::If { branches, .. } => {
                    for (condition, _) in branches {
                        shift(condition, id.0);
                    }
                }
                StatementKind::While { condition, .. } => shift(condition, id.0),
                other => unreachable!("unexpected statement kind in test fixture: {other:?}"),
            }
        }
    }

    fn analyze_scalar_generated_test_group_with_access(
        access: AccessMode,
    ) -> wrela_sema::AnalyzedImage {
        let Fixture { hir, target, build } = fixture_with_runtime_test(true, true);
        let mut program = Arc::try_unwrap(hir)
            .expect("scalar fixture owns its HIR")
            .into_program();
        program.parameters[0].access = access;
        let ExpressionKind::Call { arguments, .. } = &mut program.expressions[7].kind else {
            unreachable!();
        };
        arguments[1].value = wrela_hir::CallArgumentValue::Exclusive {
            access: match access {
                AccessMode::Mutate => wrela_hir::ExclusiveAccess::Mutate,
                AccessMode::Take => wrela_hir::ExclusiveAccess::Take,
                _ => unreachable!("exclusive test access"),
            },
            place: wrela_hir::PlaceTarget {
                root: wrela_hir::Definition::Local(LocalId(1)),
                projections: Vec::new(),
                source: span(0, 334, 345),
            },
        };
        // The exclusive-access argument above now references `LocalId(1)`
        // through a `PlaceTarget` instead of an owned expression, so the
        // `ExpressionId(13)` it used to reference (`Reference(Local(1))`)
        // is orphaned. Drop it and shift the ids above it down by one to
        // keep the arena dense before adding anything further.
        drop_and_renumber_expression(&mut program, ExpressionId(13));
        if access == AccessMode::Take {
            let StatementKind::If { else_body, .. } = &mut program.statements[5].kind else {
                unreachable!();
            };
            *else_body = Some(BodyId(6));
            program.bodies.push(Body {
                id: BodyId(6),
                owner: BodyOwner::Declaration(DeclarationId(3)),
                scope: wrela_hir::ScopeId(6),
                locals: Vec::new(),
                statements: vec![StatementId(13)],
                source: span(0, 346, 350),
            });
            program.scopes.push(LexicalScope {
                id: wrela_hir::ScopeId(6),
                body: BodyId(6),
                parent: Some(wrela_hir::ScopeId(1)),
                source: span(0, 346, 350),
            });
            program.statements.push(Statement {
                id: StatementId(13),
                body: BodyId(6),
                attributes: Vec::new(),
                kind: StatementKind::Expression(ExpressionId(18)),
                source: span(0, 346, 350),
            });
            program.expressions.extend([
                Expression {
                    id: ExpressionId(18),
                    owner: ExpressionOwner::Body(BodyId(6)),
                    scope: Some(wrela_hir::ScopeId(6)),
                    kind: ExpressionKind::Call {
                        callee: ExpressionId(19),
                        arguments: vec![
                            CallArgument {
                                name: Some(name("y")),
                                value: wrela_hir::CallArgumentValue::Value(ExpressionId(20)),
                                source: span(0, 347, 348),
                            },
                            CallArgument {
                                name: Some(name("x")),
                                value: wrela_hir::CallArgumentValue::Exclusive {
                                    access: wrela_hir::ExclusiveAccess::Take,
                                    place: wrela_hir::PlaceTarget {
                                        root: wrela_hir::Definition::Local(LocalId(1)),
                                        projections: Vec::new(),
                                        source: span(0, 348, 349),
                                    },
                                },
                                source: span(0, 348, 349),
                            },
                        ],
                    },
                    source: span(0, 346, 350),
                },
                Expression {
                    id: ExpressionId(19),
                    owner: ExpressionOwner::Body(BodyId(6)),
                    scope: Some(wrela_hir::ScopeId(6)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Declaration(
                        ResolvedDeclaration {
                            package: PackageId(0),
                            module: ModuleId(0),
                            declaration: DeclarationId(5),
                        },
                    )),
                    source: span(0, 346, 347),
                },
                Expression {
                    id: ExpressionId(20),
                    owner: ExpressionOwner::Body(BodyId(6)),
                    scope: Some(wrela_hir::ScopeId(6)),
                    kind: ExpressionKind::Reference(wrela_hir::Definition::Local(LocalId(3))),
                    source: span(0, 347, 348),
                },
            ]);
        }
        analyze_generated_test_group_from(Fixture {
            hir: Arc::new(
                program
                    .validate()
                    .expect("valid access-mode scalar producer HIR"),
            ),
            target,
            build,
        })
    }

    fn analyze_generated_test_group_from(fixture: Fixture) -> wrela_sema::AnalyzedImage {
        let target = fixture.target.semantic().clone();
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: Arc::clone(&fixture.hir),
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &fixture.build,
                    mode: AnalysisMode::DiscoverTests {
                        image_name: "runtime-image",
                        image_entry: DeclarationId(0),
                        declared_image_tests: &[],
                        source_selection: TestDiscoverySelection::All,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("test discovery");
        assert!(
            discovery.diagnostics().is_empty(),
            "discovery diagnostics: {:?}",
            discovery.diagnostics()
        );
        let discovered = discovery.successful().expect("sealed discovery");
        let plan = discovered
            .facts()
            .test_plan
            .as_ref()
            .expect("discovered plan")
            .clone();
        assert_eq!(plan.unit_tests().len(), 1);
        assert_eq!(plan.image_groups().len(), 1);
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: fixture.hir,
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &fixture.build,
                    mode: AnalysisMode::CompileTestGroup {
                        plan: &plan,
                        group: ImageGroupId(0),
                        declared_entry: None,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("generated group compilation");
        assert!(output.diagnostics().is_empty());
        output
            .successful()
            .expect("sealed generated test image")
            .clone()
    }

    fn analyze_declared_test_group() -> wrela_sema::AnalyzedImage {
        let fixture = fixture();
        let target = fixture.target.semantic().clone();
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let declared = [DeclaredImageTest {
            name: "boots".to_owned(),
            image_name: "runtime-image".to_owned(),
            scenario: ImageScenario {
                id: wrela_test_model::ScenarioId(0),
                schema: IMAGE_SCENARIO_SCHEMA,
                name: "boots".to_owned(),
                source_path: "tests/boots.toml".to_owned(),
                digest: Sha256Digest::from_bytes([0x44; 32]),
                steps: vec![ImageScenarioStep::ExpectExit {
                    code: Some(0),
                    timeout_ns: 10,
                }],
            },
            boot_timeout_ns: 20,
            shutdown_timeout_ns: 30,
            maximum_events: 16,
            maximum_output_bytes: 1024,
            deterministic_seed: Some(7),
        }];
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: Arc::clone(&fixture.hir),
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &fixture.build,
                    mode: AnalysisMode::DiscoverTests {
                        image_name: "runtime-image",
                        image_entry: DeclarationId(0),
                        declared_image_tests: &declared,
                        source_selection: TestDiscoverySelection::All,
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("declared test discovery");
        assert!(discovery.diagnostics().is_empty());
        let plan = discovery
            .successful()
            .expect("sealed declared discovery")
            .facts()
            .test_plan
            .as_ref()
            .expect("declared plan")
            .clone();
        let group = plan.image_groups()[0].id;
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: fixture.hir,
                    standard_library_package: PackageId(1),
                    target: &target,
                    build: &fixture.build,
                    mode: AnalysisMode::CompileTestGroup {
                        plan: &plan,
                        group,
                        declared_entry: Some(DeclarationId(0)),
                    },
                    changes: &changes,
                    limits: AnalysisLimits::standard(),
                },
                &|| false,
            )
            .expect("declared group compilation");
        assert!(output.diagnostics().is_empty());
        output
            .successful()
            .expect("sealed declared test image")
            .clone()
    }

    #[test]
    fn semantic_wir_policy_rejects_zero_capacity() {
        LoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = LoweringLimits::standard();
        limits.types = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
    }

    #[test]
    fn real_parsed_actor_image_lowers_exact_graph_waits_frames_and_proofs() {
        let image = analyze_parsed_actor();
        let semantic_facts = image.facts().clone();
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("parsed actor SemanticWir lowering");
        let lowered = output.wir().as_wir();
        let graph = semantic_facts.graph.as_ref().expect("semantic actor graph");
        assert_eq!(lowered.version, wir::SEMANTIC_WIR_VERSION);
        assert!(semantic_graph_matches(graph, lowered, &|| false).expect("compare actor graph"));
        assert_eq!(lowered.actors.len(), 1);
        assert_eq!(lowered.tasks.len(), 1);
        assert_eq!(lowered.regions.len(), 5);
        assert_eq!(lowered.activations.len(), 2);
        assert_eq!(lowered.actors[0].id, wir::ActorId(graph.actors[0].id.0));
        assert_eq!(lowered.actors[0].mailbox_capacity, 2);
        assert_eq!(lowered.tasks[0].id, wir::TaskId(graph.tasks[0].id.0));
        assert_eq!(lowered.tasks[0].slots, 1);
        assert_eq!(lowered.static_bytes, 96);
        assert_eq!(lowered.peak_bytes, lowered.static_bytes);
        assert_eq!(output.report().image_nodes, 9);
        assert_eq!(output.report().operations, 4);
        for (index, activation) in lowered.activations.iter().enumerate() {
            assert_eq!(activation.id, wir::ActivationId(index as u32));
            assert_eq!(activation.region, wir::RegionId(3 + index as u32));
            assert_eq!(activation.frame_bytes, 16);
            assert_eq!(activation.maximum_live, 1);
            assert_eq!(
                activation.cancellation,
                wir::ActivationCancellation::DropCalleeThenPropagate
            );
            let caller = &lowered.functions[activation.caller.0 as usize];
            assert!(matches!(
                caller.role,
                wir::FunctionRole::ActorTurn(wir::ActorId(0))
                    | wir::FunctionRole::TaskEntry(wir::TaskId(0))
            ));
            assert!(caller.proofs.contains(&activation.capacity_proof));
            assert!(caller.body.statements.iter().any(|statement| matches!(
                statement,
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::Call {
                        function,
                        activation: Some(plan),
                        ..
                    },
                    source: Some(source),
                    ..
                }) if *function == activation.callee
                    && *plan == activation.id
                    && *source == activation.source
            )));
            let callee = &lowered.functions[activation.callee.0 as usize];
            assert_eq!(callee.role, wir::FunctionRole::Ordinary);
            assert_eq!(callee.color, wir::FunctionColor::Async);
            assert_eq!(callee.frame_bound, activation.frame_bytes);
            let cleanup = callee
                .proofs
                .iter()
                .find(|proof| {
                    lowered.proofs[proof.0 as usize].kind == wir::ProofKind::CleanupAcyclic
                })
                .expect("activation callee cleanup proof");
            let proof = &lowered.proofs[activation.capacity_proof.0 as usize];
            assert_eq!(proof.kind, wir::ProofKind::CapacityBound);
            assert_eq!(proof.bound, Some(1));
            assert_eq!(proof.sources, [activation.source]);
            assert_eq!(proof.depends_on, [*cleanup]);
            let region = &lowered.regions[activation.region.0 as usize];
            assert_eq!(region.class, wir::RegionClass::TaskFrame);
            assert_eq!(region.capacity_bytes, activation.frame_bytes);
            assert_eq!(region.proof, activation.capacity_proof);
            assert_eq!(region.source, activation.source);
        }
        let closed = lowered
            .proofs
            .iter()
            .find(|proof| proof.kind == wir::ProofKind::ImageClosed)
            .expect("activation-aware closed image proof");
        assert_eq!(closed.bound, Some(96));
        assert_eq!(
            &closed.depends_on[1..],
            lowered
                .activations
                .iter()
                .map(|activation| activation.capacity_proof)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            lowered
                .functions
                .iter()
                .flat_map(|function| function.body.statements.iter())
                .filter(|statement| {
                    matches!(
                        statement,
                        wir::SemanticStatement::Let(wir::LetStatement {
                            operation: wir::SemanticOperation::Await { .. },
                            ..
                        })
                    )
                })
                .count(),
            2
        );
        assert!(lowered.functions.iter().any(|function| {
            function.role == wir::FunctionRole::ActorTurn(wir::ActorId(0))
                && function.color == wir::FunctionColor::Async
                && function.frame_bound == 16
                && function.effects.contains(wir::EffectSet::SUSPEND)
        }));
        assert!(lowered.functions.iter().any(|function| {
            function.role == wir::FunctionRole::TaskEntry(wir::TaskId(0))
                && function.frame_bound == 16
        }));
        let semantic_wait = semantic_facts
            .proofs
            .iter()
            .find(|proof| proof.kind == sema::ProofKind::WaitGraphAcyclic)
            .expect("semantic wait proof");
        let lowered_wait = lowered
            .proofs
            .get(semantic_wait.id.0 as usize)
            .expect("lowered wait proof");
        assert_eq!(lowered_wait.id, wir::ProofId(semantic_wait.id.0));
        assert_eq!(lowered_wait.kind, wir::ProofKind::WaitGraphAcyclic);
        assert_eq!(lowered_wait.bound, Some(2));
        assert_eq!(lowered_wait.sources, semantic_wait.sources);
        let mut wait_sources = Vec::new();
        for function in &lowered.functions {
            for pair in function.body.statements.windows(2) {
                let [
                    wir::SemanticStatement::Let(wir::LetStatement {
                        results: call_results,
                        operation:
                            wir::SemanticOperation::Call {
                                function: target, ..
                            },
                        ..
                    }),
                    wir::SemanticStatement::Let(wir::LetStatement {
                        operation: wir::SemanticOperation::Await { awaitable },
                        source: Some(source),
                        ..
                    }),
                ] = pair
                else {
                    continue;
                };
                assert_eq!(call_results.as_slice(), [*awaitable]);
                assert_eq!(
                    lowered.functions[target.0 as usize].color,
                    wir::FunctionColor::Async
                );
                wait_sources.push(*source);
            }
        }
        wait_sources
            .sort_unstable_by_key(|source| (source.file, source.range.start, source.range.end));
        wait_sources.dedup();
        assert_eq!(wait_sources, semantic_wait.sources);
        assert!(
            lowered
                .proofs
                .iter()
                .any(|proof| { proof.kind == wir::ProofKind::Ownership && proof.bound == Some(1) })
        );
        assert!(lowered.proofs.iter().any(|proof| {
            proof.kind == wir::ProofKind::CleanupAcyclic
                && proof
                    .explanation
                    .iter()
                    .any(|line| line.contains("reverse source order"))
        }));
    }

    #[test]
    fn real_actor_activation_expansion_accepts_exact_aggregate_resources_and_rejects_one_under() {
        let measured_input = analyze_parsed_actor();
        let (input_edges, input_payload) =
            preflight_input(measured_input.facts(), LoweringLimits::standard(), &|| {
                false
            })
            .expect("measure complete semantic actor input");
        let baseline = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: measured_input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline actor activation lowering");
        let meter = measure_model_resources(
            baseline.wir().as_wir().into(),
            LoweringLimits::standard(),
            &|| false,
        )
        .expect("measure complete actor SemanticWir");
        assert!(!meter.overflowed);
        let mut long_comparison = baseline.wir().as_wir().clone();
        long_comparison.name = "actor-image".repeat(32 * 1024);
        let comparison_polls = Cell::new(0_u32);
        assert!(matches!(
            semantic_actor_wir_matches(
                &long_comparison,
                &long_comparison,
                LoweringLimits::standard(),
                &|| {
                    let next = comparison_polls.get().saturating_add(1);
                    comparison_polls.set(next);
                    next > 8
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(comparison_polls.get(), 9);

        let mut exact = LoweringLimits::standard();
        exact.model_edges = meter.edges.max(input_edges);
        exact.payload_bytes = meter.payload_bytes.max(input_payload);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: analyze_parsed_actor(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact aggregate actor output budget");

        let mut one_edge_under = exact;
        one_edge_under.model_edges = one_edge_under
            .model_edges
            .checked_sub(1)
            .expect("nonzero actor edge count");
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: analyze_parsed_actor(),
                    limits: one_edge_under,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit { limit, .. }) if limit == one_edge_under.model_edges
        ));

        let mut one_byte_under = exact;
        one_byte_under.payload_bytes = one_byte_under
            .payload_bytes
            .checked_sub(1)
            .expect("nonzero actor payload count");
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: analyze_parsed_actor(),
                    limits: one_byte_under,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit { limit, .. }) if limit == one_byte_under.payload_bytes
        ));
    }

    #[test]
    fn actor_zero_state_region_lowers_and_is_exactly_sealed() {
        let image = analyze_parsed_actor_source(ZERO_STATE_ACTOR_SOURCE);
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical actor state region lowers");
        let baseline = output.wir().as_wir().clone();
        let state = baseline
            .regions
            .iter()
            .find(|region| region.name.ends_with(".state"))
            .expect("SemanticWir actor state region");
        assert_eq!(state.class, wir::RegionClass::Image);
        assert_eq!(state.owner, wir::ImageOwner::Actor(wir::ActorId(0)));
        assert_eq!(state.capacity_bytes, 8);
        assert_eq!(state.alignment, 8);
        assert_eq!(baseline.static_bytes, 104);
        assert_eq!(baseline.peak_bytes, 104);

        let request = LowerRequest {
            input: image,
            limits: LoweringLimits::standard(),
        };
        let report = output.report().clone();
        let mut wrong_size = baseline.clone();
        wrong_size
            .regions
            .iter_mut()
            .find(|region| region.name.ends_with(".state"))
            .expect("state region")
            .capacity_bytes = 16;
        wrong_size.static_bytes = 112;
        wrong_size.peak_bytes = 112;
        assert!(matches!(
            seal(&request, wrong_size, report.clone(), &|| false),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_owner = baseline.clone();
        wrong_owner
            .regions
            .iter_mut()
            .find(|region| region.name.ends_with(".state"))
            .expect("state region")
            .owner = wir::ImageOwner::Runtime;
        assert!(matches!(
            seal(&request, wrong_owner, report, &|| false),
            Err(LowerError::InvalidOutput(_))
        ));
    }

    #[test]
    fn actor_sealer_rejects_capacity_identity_cycle_and_proof_substitution() {
        let image = analyze_parsed_actor();
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline actor lowering");
        let baseline = output.wir().as_wir().clone();
        let report = output.report().clone();
        let request = LowerRequest {
            input: image,
            limits: LoweringLimits::standard(),
        };

        let mut wrong_mailbox = baseline.clone();
        wrong_mailbox.actors[0].mailbox_capacity += 1;
        assert!(matches!(
            seal(&request, wrong_mailbox, report.clone(), &|| false),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_task_slot = baseline.clone();
        wrong_task_slot.tasks[0].slots += 1;
        assert!(matches!(
            seal(&request, wrong_task_slot, report.clone(), &|| false),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_region = baseline.clone();
        wrong_region.regions[0].capacity_bytes += 16;
        assert!(matches!(
            seal(&request, wrong_region, report.clone(), &|| false),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut cyclic_wait = baseline.clone();
        let actor_turn = cyclic_wait
            .functions
            .iter()
            .find(|function| function.role == wir::FunctionRole::ActorTurn(wir::ActorId(0)))
            .map(|function| function.id)
            .expect("actor turn");
        let call_target = cyclic_wait
            .functions
            .get_mut(actor_turn.0 as usize)
            .and_then(|function| {
                function
                    .body
                    .statements
                    .iter_mut()
                    .find_map(|statement| match statement {
                        wir::SemanticStatement::Let(wir::LetStatement {
                            operation: wir::SemanticOperation::Call { function, .. },
                            ..
                        }) => Some(function),
                        _ => None,
                    })
            })
            .expect("wait call target");
        *call_target = actor_turn;
        assert!(matches!(
            seal(&request, cyclic_wait, report.clone(), &|| false),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_wait_proof = baseline.clone();
        let wait = wrong_wait_proof
            .proofs
            .iter_mut()
            .find(|proof| proof.kind == wir::ProofKind::WaitGraphAcyclic)
            .expect("wait proof");
        wait.bound = wait.bound.and_then(|bound| bound.checked_add(1));
        assert!(matches!(
            seal(&request, wrong_wait_proof, report.clone(), &|| false),
            Err(LowerError::InvalidReport(_))
        ));

        let mut missing_cleanup = baseline;
        let activation_callee = missing_cleanup.activations[0].callee;
        let cleanup = missing_cleanup
            .proofs
            .iter()
            .find(|proof| {
                proof.kind == wir::ProofKind::CleanupAcyclic
                    && missing_cleanup.functions[activation_callee.0 as usize]
                        .proofs
                        .contains(&proof.id)
            })
            .map(|proof| proof.id)
            .expect("cleanup proof");
        let function = &mut missing_cleanup.functions[activation_callee.0 as usize];
        function.proofs.retain(|proof| *proof != cleanup);
        assert!(matches!(
            seal(&request, missing_cleanup, report, &|| false),
            Err(LowerError::InvalidOutput(_))
        ));
    }

    #[test]
    fn actor_lowering_enforces_exact_operation_limit_and_midflight_cancellation() {
        let image = analyze_parsed_actor();
        let baseline = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline actor lowering");
        let exact_operations = baseline.report().operations;
        assert!(exact_operations > 1);

        let mut exact = LoweringLimits::standard();
        exact.operations = exact_operations;
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact actor operation limit");

        let mut one_too_many = exact;
        one_too_many.operations = exact_operations - 1;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: one_too_many,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit,
            }) if limit == exact_operations - 1
        ));

        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 12
        };
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &cancelled,
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() >= 12);
    }

    #[test]
    fn real_analyzer_minimum_lowers_without_losing_identity_or_proofs() {
        let (image, _target) = analyze_minimum();
        let expected_facts = image.facts().clone();
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("minimum SemanticWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.version, wir::SEMANTIC_WIR_VERSION);
        assert_eq!(wir.build, expected_facts.build);
        assert_eq!(wir.name, "runtime-image");
        assert_eq!(wir.source_summary.hir_files, expected_facts.hir.files);
        assert_eq!(
            wir.source_summary.hir_declarations,
            expected_facts.hir.declarations
        );
        assert_eq!(wir.source_summary.reachable_declarations, 1);
        assert_eq!(wir.types.len(), 1);
        assert_eq!(wir.functions.len(), 1);
        let function = &wir.functions[0];
        assert_eq!(function.instance_key, expected_facts.functions[0].key.0);
        assert_eq!(function.color, wir::FunctionColor::Sync);
        assert_eq!(function.effects.0, expected_facts.functions[0].effects.0);
        assert_eq!(
            function.origin,
            wir::FunctionOrigin::GeneratedImageEntry { constructor: 0 }
        );
        assert_eq!(function.recursive_depth_bound, Some(1));
        assert!(matches!(
            function.body.statements.as_slice(),
            [wir::SemanticStatement::Return(values)] if values.is_empty()
        ));
        assert_eq!(wir.proofs.len(), expected_facts.proofs.len());
        for (source, lowered) in expected_facts.proofs.iter().zip(&wir.proofs) {
            assert!(semantic_proof_matches(source, lowered, &|| false).expect("proof comparison"));
        }
        assert_eq!(wir.startup_order, [wir::ImageOwner::Runtime]);
        assert_eq!(wir.shutdown_order, [wir::ImageOwner::Runtime]);
        assert_eq!(
            output.report(),
            &LoweringReport {
                semantic_types: 1,
                function_instances: 1,
                operations: 0,
                proofs: 3,
                image_nodes: 0,
                tests: 0,
            }
        );
    }

    #[test]
    fn installed_core_time_generated_reachability_is_exact_bounded_and_cancellable() {
        let image = analyze_installed_core_time_generated_group();
        let facts = image.facts();
        let structure_declarations = facts
            .types
            .iter()
            .filter_map(|ty| match &ty.kind {
                sema::SemanticTypeKind::Structure { declaration, .. } => Some(*declaration),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            structure_declarations.iter().any(|declaration| {
                image
                    .hir()
                    .as_program()
                    .declaration(*declaration)
                    .and_then(|record| record.name.as_ref())
                    .is_some_and(|name| name.as_str() == "Duration")
            }),
            "the installed core.time Duration declaration must be retained"
        );

        let mut expected_declarations = facts
            .functions
            .iter()
            .filter_map(|function| match function.origin {
                sema::FunctionOrigin::Source { declaration, .. } => Some(declaration),
                _ => None,
            })
            .chain(structure_declarations.iter().copied())
            .collect::<Vec<_>>();
        expected_declarations.sort_unstable();
        expected_declarations.dedup();
        let expected = u64::try_from(expected_declarations.len())
            .expect("bounded expected reachable declaration count");
        let scratch_capacity = facts
            .functions
            .len()
            .checked_add(facts.types.len())
            .expect("bounded generated reachability scratch capacity");

        {
            let generated =
                supported_generated_tests(&image, LoweringLimits::standard(), &|| false)
                    .expect("supported installed core.time generated image");
            assert_eq!(
                generated_reachable_declarations(
                    &generated,
                    LoweringLimits::standard(),
                    &|| false,
                )
                .expect("installed core.time reachable declarations"),
                expected
            );

            let mut exact_limits = LoweringLimits::standard();
            exact_limits.model_edges =
                u64::try_from(scratch_capacity).expect("bounded reachability scratch capacity");
            assert_eq!(
                generated_reachable_declarations(&generated, exact_limits, &|| false)
                    .expect("exact generated reachability scratch limit"),
                expected
            );
            let mut one_under = exact_limits;
            one_under.model_edges -= 1;
            assert!(matches!(
                generated_reachable_declarations(&generated, one_under, &|| false),
                Err(LowerError::ResourceLimit {
                    resource: "generated reachable declarations",
                    limit,
                }) if limit == one_under.model_edges
            ));

            let successful_polls = Cell::new(0_u32);
            generated_reachable_declarations(&generated, LoweringLimits::standard(), &|| {
                successful_polls.set(successful_polls.get().saturating_add(1));
                false
            })
            .expect("count installed core.time reachability cancellation polls");
            let cancel_at = successful_polls.get().saturating_sub(1);
            assert!(cancel_at > 1);
            let cancelled_polls = Cell::new(0_u32);
            assert_eq!(
                generated_reachable_declarations(&generated, LoweringLimits::standard(), &|| {
                    let next = cancelled_polls.get().saturating_add(1);
                    cancelled_polls.set(next);
                    next == cancel_at
                },),
                Err(LowerError::Cancelled)
            );
            assert_eq!(cancelled_polls.get(), cancel_at);
        }

        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("installed core.time SemanticWir lowering");
        assert_eq!(
            output.wir().as_wir().source_summary.reachable_declarations,
            expected
        );
    }

    #[test]
    fn generated_group_lowers_exact_test_functions_protocol_frames_and_terminal_finish() {
        let image = analyze_generated_test_group();
        let group = image
            .facts()
            .compiled_test_group
            .as_ref()
            .expect("compiled group")
            .clone();
        assert_eq!(group.tests[0].descriptor.id, wrela_test_model::TestId(1));
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("generated SemanticWir");
        let module = output.wir().as_wir();
        assert_eq!(module.functions.len(), 2);
        assert_eq!(module.tests.len(), 1);
        assert_eq!(module.compiled_test_group.as_ref(), Some(&group));
        assert_eq!(module.tests[0].id, wir::TestId(0));
        assert_eq!(module.tests[0].plan_id, group.tests[0].descriptor.id.0);
        assert_eq!(module.tests[0].function, wir::FunctionId(0));
        assert_eq!(
            module.tests[0].timeout_ns,
            group.tests[0].descriptor.timeout_ns
        );
        // `runtime_case`'s body carries the bounded-`while` tier guard
        // (see `fixture_with_runtime_test`'s `!scalar` branch): an
        // initializing `Let`, the guard `Loop`, then the implicit unit
        // `Return`.
        assert!(matches!(
            module.functions[0].body.statements.as_slice(),
            [
                wir::SemanticStatement::Let(_),
                wir::SemanticStatement::Loop { .. },
                wir::SemanticStatement::Return(values)
            ] if values.is_empty()
        ));
        let harness = &module.functions[1];
        assert_eq!(
            harness.origin,
            wir::FunctionOrigin::GeneratedTestHarness { group: group.id.0 }
        );
        assert_eq!(module.image_entry, harness.id);
        let frames: Vec<_> = harness
            .body
            .statements
            .iter()
            .filter_map(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::Constant(wir::Constant::Bytes(bytes)),
                    ..
                }) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(frames.len(), 4);
        let decoded: Vec<_> = frames
            .iter()
            .map(|frame| {
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    frame,
                    ProtocolLimits::standard(),
                    &|| false,
                )
                .expect("canonical embedded test frame")
            })
            .collect();
        assert!(matches!(
            decoded[0].kind,
            TestEventKind::RunStarted { test_count: 1 }
        ));
        assert!(matches!(
            decoded[1].kind,
            TestEventKind::TestStarted {
                test: wrela_test_model::TestId(1)
            }
        ));
        assert!(matches!(
            decoded[2].kind,
            TestEventKind::TestFinished {
                test: wrela_test_model::TestId(1),
                outcome: GuestTestOutcome::Passed
            }
        ));
        assert!(matches!(
            decoded[3].kind,
            TestEventKind::RunFinished {
                passed: 1,
                failed: 0
            }
        ));
        assert!(harness.body.statements.iter().any(|statement| matches!(
            statement,
            wir::SemanticStatement::Let(wir::LetStatement {
                operation: wir::SemanticOperation::Call {
                    function: wir::FunctionId(0),
                    arguments,
                    activation: None,
                },
                ..
            }) if arguments.is_empty()
        )));
        assert!(matches!(
            harness.body.statements.as_slice(),
            [
                ..,
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::TestFinish { .. },
                    ..
                }),
                wir::SemanticStatement::Unreachable
            ]
        ));
        assert_eq!(
            output.report(),
            &LoweringReport {
                semantic_types: u32::try_from(module.types.len()).expect("type count"),
                function_instances: 2,
                // `runtime_case`'s bounded-`while` tier guard adds 5 real
                // operations (init, compare, the loop's carried-value join,
                // literal, and the checked add) beyond the previously
                // trivial `pass; return` body.
                operations: 16,
                proofs: 5,
                image_nodes: 0,
                tests: 1,
            }
        );
    }

    #[test]
    fn scalar_generated_group_lowers_real_source_body_and_transitive_helper() {
        let image = analyze_scalar_generated_test_group();
        let facts = image.facts().clone();
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("scalar generated SemanticWir");
        let module = output.wir().as_wir();
        assert_eq!(module.source_summary.reachable_declarations, 2);
        assert_eq!(module.functions.len(), 3);
        assert_eq!(module.image_entry, wir::FunctionId(2));
        assert!(matches!(
            module.types[0].kind,
            wir::TypeKind::Primitive(wir::PrimitiveType::Unit)
        ));
        assert!(matches!(
            module.types[1].kind,
            wir::TypeKind::Primitive(wir::PrimitiveType::Bool)
        ));
        assert!(matches!(
            module.types[2].kind,
            wir::TypeKind::Primitive(wir::PrimitiveType::U32)
        ));
        let wir::TypeKind::Function(helper_type) = &module.types[3].kind else {
            panic!("helper function type");
        };
        assert_eq!(helper_type.color, wir::FunctionColor::Sync);
        assert_eq!(helper_type.result, wir::TypeId(2));
        assert_eq!(
            helper_type.parameters,
            [
                wir::ParameterType {
                    access: wir::AccessMode::Read,
                    ty: wir::TypeId(2),
                },
                wir::ParameterType {
                    access: wir::AccessMode::Read,
                    ty: wir::TypeId(2),
                },
            ]
        );

        let test = &module.functions[0];
        assert_eq!(test.id, wir::FunctionId(0));
        assert_eq!(test.instance_key, facts.functions[0].key.0);
        assert_eq!(test.source, facts.functions[0].source);
        assert_eq!(test.role, wir::FunctionRole::Test);
        assert_eq!(test.values.len(), 4);
        assert_eq!(test.values[0].name.as_deref(), Some("flag"));
        assert_eq!(test.values[1].name.as_deref(), Some("number"));
        assert_eq!(test.values[2].name.as_deref(), Some("other"));
        assert_eq!(test.values[3].origin, Some(span(0, 315, 345)));
        let [flag, number, other, branch, returned] = test.body.statements.as_slice() else {
            panic!("exact scalar test body");
        };
        assert!(matches!(
            flag,
            wir::SemanticStatement::Let(wir::LetStatement {
                results,
                operation: wir::SemanticOperation::Constant(wir::Constant::Bool(true)),
                source: Some(source),
            }) if results.as_slice() == [wir::ValueId(0)] && *source == span(0, 238, 242)
        ));
        assert!(matches!(
            number,
            wir::SemanticStatement::Let(wir::LetStatement {
                results,
                operation: wir::SemanticOperation::Constant(wir::Constant::Unsigned { bits: 32, value: 7 }),
                ..
            }) if results.as_slice() == [wir::ValueId(1)]
        ));
        assert!(matches!(
            other,
            wir::SemanticStatement::Let(wir::LetStatement {
                results,
                operation: wir::SemanticOperation::Constant(wir::Constant::Unsigned { bits: 32, value: 9 }),
                ..
            }) if results.as_slice() == [wir::ValueId(2)]
        ));
        let wir::SemanticStatement::If {
            condition,
            then_region,
            else_region,
            results,
            source,
        } = branch
        else {
            panic!("lowered source if");
        };
        assert_eq!(*condition, wir::ValueId(0));
        assert!(else_region.statements.is_empty());
        assert!(results.is_empty());
        assert_eq!(*source, Some(span(0, 270, 350)));
        assert!(matches!(
            then_region.statements.as_slice(),
            [wir::SemanticStatement::Let(wir::LetStatement {
                results,
                operation: wir::SemanticOperation::Call {
                    function,
                    arguments,
                    activation: None,
                },
                source: Some(source),
            })]
                if results.as_slice() == [wir::ValueId(3)]
                    && *function == wir::FunctionId(1)
                    && arguments.as_slice() == [
                        wir::Argument { access: wir::AccessMode::Read, value: wir::ValueId(1) },
                        wir::Argument { access: wir::AccessMode::Read, value: wir::ValueId(2) },
                    ]
                    && *source == span(0, 315, 345)
        ));
        assert!(matches!(returned, wir::SemanticStatement::Return(values) if values.is_empty()));

        let helper = &module.functions[1];
        assert_eq!(helper.instance_key, facts.functions[1].key.0);
        assert_eq!(helper.role, wir::FunctionRole::Ordinary);
        assert_eq!(helper.parameters, [wir::ValueId(0), wir::ValueId(1)]);
        // `helper`'s body carries the bounded-`while` tier guard (see
        // `fixture_with_runtime_test`'s `scalar` branch), so beyond
        // `x`/`y`/`copied` it also owns the guard local and every SSA
        // value the loop's carried-value join threads through it.
        assert_eq!(helper.values.len(), 12);
        assert_eq!(helper.values[0].name.as_deref(), Some("x"));
        assert_eq!(helper.values[1].name.as_deref(), Some("y"));
        assert_eq!(helper.values[2].name.as_deref(), Some("copied"));
        assert_eq!(helper.values[3].name.as_deref(), Some("guard"));
        assert!(matches!(
            helper.body.statements.as_slice(),
            [
                wir::SemanticStatement::Let(wir::LetStatement {
                    results: copy_results,
                    operation: wir::SemanticOperation::Copy { value: wir::ValueId(0) },
                    ..
                }),
                wir::SemanticStatement::Let(_),
                wir::SemanticStatement::Loop { .. },
                wir::SemanticStatement::Return(returned),
            ] if copy_results.as_slice() == [wir::ValueId(2)]
                && returned.as_slice() == [wir::ValueId(6)]
        ));
        assert_eq!(
            output.report(),
            &LoweringReport {
                semantic_types: 8,
                function_instances: 3,
                // `helper`'s bounded-`while` tier guard adds 5 real
                // operations beyond its previously trivial `copied = x`
                // body (see the analogous comment on
                // `generated_group_lowers_exact_test_functions_protocol_frames_and_terminal_finish`).
                operations: 21,
                proofs: 7,
                image_nodes: 0,
                tests: 1,
            }
        );

        let mut forged = module.clone();
        let wir::SemanticStatement::If { then_region, .. } =
            &mut forged.functions[0].body.statements[3]
        else {
            panic!("forged source if");
        };
        let wir::SemanticStatement::Let(wir::LetStatement {
            operation: wir::SemanticOperation::Call { arguments, .. },
            ..
        }) = &mut then_region.statements[0]
        else {
            panic!("forged source call");
        };
        arguments.swap(0, 1);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged,
                output.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn real_scalar_assignments_lower_if_results_yields_and_post_join_use_exactly() {
        let image = analyze_scalar_join_generated_test_group();
        let facts = image.facts().clone();
        let branch_definition = facts
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(5))
            .and_then(|fact| fact.definitions.first())
            .copied()
            .expect("semantic scalar branch join definition");
        assert_eq!(branch_definition.local, LocalId(1));
        let incoming = [StatementId(8), StatementId(10)].map(|statement| {
            facts
                .statements
                .iter()
                .find(|fact| fact.statement == statement)
                .and_then(|fact| fact.definitions.first())
                .map(|definition| definition.value)
                .expect("semantic branch assignment definition")
        });
        assert_ne!(incoming[0], incoming[1]);
        assert_ne!(branch_definition.value, incoming[0]);
        assert_ne!(branch_definition.value, incoming[1]);

        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("real scalar join SemanticWir");
        let test = &output.wir().as_wir().functions[0];
        let [_, _, _, branch, call, returned] = test.body.statements.as_slice() else {
            panic!("exact scalar join test body");
        };
        let wir::SemanticStatement::If {
            condition,
            then_region,
            else_region,
            results,
            source,
        } = branch
        else {
            panic!("scalar result branch");
        };
        assert_eq!(*condition, wir::ValueId(0));
        assert_eq!(*source, Some(span(0, 270, 350)));
        let [join] = results.as_slice() else {
            panic!("one scalar branch result");
        };
        let [
            wir::SemanticStatement::Let(then_assignment),
            wir::SemanticStatement::Yield(then_yield),
        ] = then_region.statements.as_slice()
        else {
            panic!("exact then assignment and yield");
        };
        let [then_value] = then_assignment.results.as_slice() else {
            panic!("one then assignment value");
        };
        assert_eq!(then_yield, &vec![*then_value]);
        assert!(matches!(
            then_assignment.operation,
            wir::SemanticOperation::Constant(wir::Constant::Unsigned {
                bits: 32,
                value: 11,
            })
        ));
        let [
            wir::SemanticStatement::Let(else_assignment),
            wir::SemanticStatement::Yield(else_yield),
        ] = else_region.statements.as_slice()
        else {
            panic!("exact else assignment and yield");
        };
        let [else_value] = else_assignment.results.as_slice() else {
            panic!("one else assignment value");
        };
        assert_eq!(else_yield, &vec![*else_value]);
        assert_ne!(then_value, else_value);
        assert_ne!(join, then_value);
        assert_ne!(join, else_value);
        assert!(matches!(
            else_assignment.operation,
            wir::SemanticOperation::Constant(wir::Constant::Unsigned {
                bits: 32,
                value: 13,
            })
        ));
        let wir::SemanticStatement::Let(wir::LetStatement {
            operation: wir::SemanticOperation::Call { arguments, .. },
            ..
        }) = call
        else {
            panic!("post-join helper call");
        };
        assert_eq!(arguments[0].value, *join);
        assert_ne!(arguments[0].value, *then_value);
        assert_ne!(arguments[0].value, *else_value);
        assert!(matches!(returned, wir::SemanticStatement::Return(values) if values.is_empty()));

        let mut substituted = output.wir().as_wir().clone();
        let wir::SemanticStatement::Let(wir::LetStatement {
            operation: wir::SemanticOperation::Call { arguments, .. },
            ..
        }) = &mut substituted.functions[0].body.statements[4]
        else {
            panic!("forged post-join call");
        };
        arguments[0].value = *then_value;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                substituted,
                output.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn compound_assignments_lower_all_checked_operators_with_reserved_old_value_and_one_rhs() {
        let cases = [
            (wrela_hir::AssignmentOperator::Add, wir::BinaryOperator::Add),
            (
                wrela_hir::AssignmentOperator::Subtract,
                wir::BinaryOperator::Subtract,
            ),
            (
                wrela_hir::AssignmentOperator::Multiply,
                wir::BinaryOperator::Multiply,
            ),
            (
                wrela_hir::AssignmentOperator::Divide,
                wir::BinaryOperator::Divide,
            ),
            (
                wrela_hir::AssignmentOperator::Remainder,
                wir::BinaryOperator::Remainder,
            ),
            (
                wrela_hir::AssignmentOperator::BitAnd,
                wir::BinaryOperator::BitAnd,
            ),
            (
                wrela_hir::AssignmentOperator::BitOr,
                wir::BinaryOperator::BitOr,
            ),
            (
                wrela_hir::AssignmentOperator::BitXor,
                wir::BinaryOperator::BitXor,
            ),
            (
                wrela_hir::AssignmentOperator::ShiftLeft,
                wir::BinaryOperator::ShiftLeft,
            ),
            (
                wrela_hir::AssignmentOperator::ShiftRight,
                wir::BinaryOperator::ShiftRight,
            ),
        ];
        for (source_operator, lowered_operator) in cases {
            let image =
                analyze_generated_test_group_from(compound_assignment_fixture(source_operator));
            let facts = image.facts();
            let previous = facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(2))
                .and_then(|fact| fact.definitions.first())
                .map(|definition| definition.value)
                .expect("initial compound target");
            let definition = facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(8))
                .and_then(|fact| fact.definitions.first())
                .copied()
                .expect("compound assignment definition");
            let rhs = facts
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(7))
                .expect("compound right-hand side fact");
            assert_eq!(definition.local, LocalId(1));
            assert_ne!(definition.value, previous);
            assert_ne!(rhs.result, Some(definition.value));
            assert!(!facts.expressions.iter().any(|expression| {
                expression.function == rhs.function && expression.result == Some(definition.value)
            }));

            let output = CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image,
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .expect("compound assignment SemanticWir");
            let test = &output.wir().as_wir().functions[0];
            let wir::SemanticStatement::If {
                then_region,
                else_region,
                results,
                ..
            } = &test.body.statements[3]
            else {
                panic!("compound assignment branch");
            };
            let [
                wir::SemanticStatement::Let(call),
                wir::SemanticStatement::Let(compound),
                wir::SemanticStatement::Yield(yielded),
            ] = then_region.statements.as_slice()
            else {
                panic!("one RHS call, one compound operation, and one yield");
            };
            let [call_result] = call.results.as_slice() else {
                panic!("one compound RHS result");
            };
            assert!(matches!(
                call.operation,
                wir::SemanticOperation::Call { .. }
            ));
            let [compound_result] = compound.results.as_slice() else {
                panic!("one fresh compound result");
            };
            assert!(matches!(
                compound.operation,
                wir::SemanticOperation::Binary {
                    operator,
                    left: wir::ValueId(1),
                    right,
                    arithmetic: wir::ArithmeticMode::Checked,
                } if operator == lowered_operator && right == *call_result
            ));
            assert_eq!(compound.source, Some(span(0, 310, 350)));
            assert_eq!(yielded.as_slice(), [*compound_result]);
            assert_eq!(results.len(), 1);
            assert!(matches!(
                else_region.statements.as_slice(),
                [wir::SemanticStatement::Yield(values)] if values.as_slice() == [wir::ValueId(1)]
            ));
        }

        let image = analyze_generated_test_group_from(compound_assignment_fixture(
            wrela_hir::AssignmentOperator::Divide,
        ));
        let baseline = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline compound lowering");
        let mut forged = baseline.wir().as_wir().clone();
        let wir::SemanticStatement::If { then_region, .. } =
            &mut forged.functions[0].body.statements[3]
        else {
            panic!("forged compound branch");
        };
        let wir::SemanticStatement::Let(wir::LetStatement {
            operation: wir::SemanticOperation::Binary { left, .. },
            ..
        }) = &mut then_region.statements[1]
        else {
            panic!("forged compound operation");
        };
        *left = wir::ValueId(2);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                forged,
                baseline.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
        let operation_count = baseline.report().operations;
        let mut exact = LoweringLimits::standard();
        exact.operations = operation_count;
        assert!(
            CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image.clone(),
                        limits: exact,
                    },
                    &|| false,
                )
                .is_ok()
        );
        let mut below = exact;
        below.operations = operation_count - 1;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: below,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                ..
            })
        ));

        let polls = Cell::new(0_u32);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: exact,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count compound lowering polls");
        let cancel_at = polls.get();
        polls.set(0);
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: exact,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn real_scalar_branch_joins_lower_for_every_supported_primitive_type() {
        let cases = [
            (
                Builtin::Unit,
                Literal::Unit,
                Literal::Unit,
                Literal::Unit,
                Literal::Unit,
            ),
            (
                Builtin::Bool,
                Literal::Boolean(false),
                Literal::Boolean(true),
                Literal::Boolean(true),
                Literal::Boolean(false),
            ),
            (
                Builtin::U8,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::U16,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::U64,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::U128,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::Usize,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::I8,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::I16,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::I32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::I64,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::I128,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::Isize,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
                Literal::Integer("4".to_owned()),
            ),
            (
                Builtin::F32,
                Literal::Float("1.0".to_owned()),
                Literal::Float("2.0".to_owned()),
                Literal::Float("3.0".to_owned()),
                Literal::Float("4.0".to_owned()),
            ),
            (
                Builtin::F64,
                Literal::Float("1.0".to_owned()),
                Literal::Float("2.0".to_owned()),
                Literal::Float("3.0".to_owned()),
                Literal::Float("4.0".to_owned()),
            ),
        ];
        for (ty, initial, other, then_value, else_value) in cases {
            let image = analyze_generated_test_group_from(scalar_join_fixture_for(
                ty, initial, other, then_value, else_value,
            ));
            let output = CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image,
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .unwrap_or_else(|error| panic!("{ty:?} scalar join lowering: {error:?}"));
            let test = &output.wir().as_wir().functions[0];
            let wir::SemanticStatement::If {
                then_region,
                else_region,
                results,
                ..
            } = &test.body.statements[3]
            else {
                panic!("{ty:?} scalar result branch");
            };
            let [join] = results.as_slice() else {
                panic!("{ty:?} scalar join result");
            };
            let [_, wir::SemanticStatement::Yield(then_values)] = then_region.statements.as_slice()
            else {
                panic!("{ty:?} scalar then yield");
            };
            let [_, wir::SemanticStatement::Yield(else_values)] = else_region.statements.as_slice()
            else {
                panic!("{ty:?} scalar else yield");
            };
            let [then_value] = then_values.as_slice() else {
                panic!("{ty:?} scalar then value");
            };
            let [else_value] = else_values.as_slice() else {
                panic!("{ty:?} scalar else value");
            };
            assert_eq!(
                test.values[join.0 as usize].ty,
                test.values[then_value.0 as usize].ty
            );
            assert_eq!(
                test.values[join.0 as usize].ty,
                test.values[else_value.0 as usize].ty
            );
            let wir::SemanticStatement::Let(wir::LetStatement {
                operation: wir::SemanticOperation::Call { arguments, .. },
                ..
            }) = &test.body.statements[4]
            else {
                panic!("{ty:?} post-join call");
            };
            assert_eq!(arguments[0].value, *join);
        }
    }

    #[test]
    fn real_scalar_operator_facts_lower_exact_operations_and_checked_conversions() {
        fn lower_helper(
            image: wrela_sema::AnalyzedImage,
        ) -> (wrela_sema::AnalyzedImage, LowerOutput) {
            let output = CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image.clone(),
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "real scalar operation lowering: {error:?}; types: {:?}",
                        image.facts().types
                    )
                });
            (image, output)
        }

        fn helper_operation(module: &wir::SemanticWir) -> &wir::SemanticOperation {
            // `helper`'s body carries the bounded-`while` tier guard (see
            // `fixture_with_runtime_test`'s `scalar` branch) after the
            // operation that computes `copied`: the operation's own `Let`,
            // the guard's initializing `Let`, the guard `Loop`, then the
            // `return copied`.
            let [
                wir::SemanticStatement::Let(statement),
                wir::SemanticStatement::Let(_),
                wir::SemanticStatement::Loop { .. },
                wir::SemanticStatement::Return(_),
            ] = module.functions[1].body.statements.as_slice()
            else {
                panic!("exact scalar helper body");
            };
            assert_eq!(statement.source, Some(span(0, 199, 205)));
            &statement.operation
        }

        for (source_operator, ty, argument, expected) in [
            (
                wrela_hir::UnaryOperator::Negate,
                Builtin::I32,
                Literal::Integer("7".to_owned()),
                wir::UnaryOperator::Negate,
            ),
            (
                wrela_hir::UnaryOperator::Negate,
                Builtin::F64,
                Literal::Float("1.5".to_owned()),
                wir::UnaryOperator::Negate,
            ),
            (
                wrela_hir::UnaryOperator::BitNot,
                Builtin::U32,
                Literal::Integer("7".to_owned()),
                wir::UnaryOperator::BitNot,
            ),
            (
                wrela_hir::UnaryOperator::BoolNot,
                Builtin::Bool,
                Literal::Boolean(true),
                wir::UnaryOperator::BoolNot,
            ),
        ] {
            let (_, output) = lower_helper(analyze_scalar_unary_operation(
                source_operator,
                ty,
                argument,
            ));
            assert!(matches!(
                helper_operation(output.wir().as_wir()),
                wir::SemanticOperation::Unary {
                    operator,
                    operand: wir::ValueId(0),
                    arithmetic: wir::ArithmeticMode::Checked,
                } if *operator == expected
            ));
        }

        let binary_cases = [
            (
                wrela_hir::BinaryOperator::Add,
                wir::BinaryOperator::Add,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::AddWrapping,
                wir::BinaryOperator::Add,
                wir::ArithmeticMode::Wrapping,
            ),
            (
                wrela_hir::BinaryOperator::Subtract,
                wir::BinaryOperator::Subtract,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::SubtractWrapping,
                wir::BinaryOperator::Subtract,
                wir::ArithmeticMode::Wrapping,
            ),
            (
                wrela_hir::BinaryOperator::Multiply,
                wir::BinaryOperator::Multiply,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::MultiplyWrapping,
                wir::BinaryOperator::Multiply,
                wir::ArithmeticMode::Wrapping,
            ),
            (
                wrela_hir::BinaryOperator::Divide,
                wir::BinaryOperator::Divide,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::Remainder,
                wir::BinaryOperator::Remainder,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::BitOr,
                wir::BinaryOperator::BitOr,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::BitXor,
                wir::BinaryOperator::BitXor,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::BitAnd,
                wir::BinaryOperator::BitAnd,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::ShiftLeft,
                wir::BinaryOperator::ShiftLeft,
                wir::ArithmeticMode::Checked,
            ),
            (
                wrela_hir::BinaryOperator::ShiftRight,
                wir::BinaryOperator::ShiftRight,
                wir::ArithmeticMode::Checked,
            ),
        ];
        for (source_operator, expected_operator, expected_arithmetic) in binary_cases {
            let (_, output) = lower_helper(analyze_scalar_binary_operation(source_operator));
            assert!(matches!(
                helper_operation(output.wir().as_wir()),
                wir::SemanticOperation::Binary {
                    operator,
                    left: wir::ValueId(0),
                    right: wir::ValueId(0),
                    arithmetic,
                } if *operator == expected_operator && *arithmetic == expected_arithmetic
            ));
        }

        for (source_operator, expected) in [
            (
                wrela_hir::ComparisonOperator::Equal,
                wir::BinaryOperator::Equal,
            ),
            (
                wrela_hir::ComparisonOperator::NotEqual,
                wir::BinaryOperator::NotEqual,
            ),
            (
                wrela_hir::ComparisonOperator::Less,
                wir::BinaryOperator::Less,
            ),
            (
                wrela_hir::ComparisonOperator::LessEqual,
                wir::BinaryOperator::LessEqual,
            ),
            (
                wrela_hir::ComparisonOperator::Greater,
                wir::BinaryOperator::Greater,
            ),
            (
                wrela_hir::ComparisonOperator::GreaterEqual,
                wir::BinaryOperator::GreaterEqual,
            ),
        ] {
            let (_, output) = lower_helper(analyze_scalar_comparison_operation(source_operator));
            assert!(matches!(
                helper_operation(output.wir().as_wir()),
                wir::SemanticOperation::Binary {
                    operator,
                    arithmetic: wir::ArithmeticMode::Checked,
                    ..
                } if *operator == expected
            ));
        }

        let image = analyze_scalar_cast_operation();
        let (image, output) = lower_helper(image);
        let module = output.wir().as_wir();
        let destination = module.functions[1].values[2].ty;
        assert!(matches!(
            helper_operation(module),
            wir::SemanticOperation::Convert {
                value: wir::ValueId(0),
                destination: operation_destination,
                checked: true,
            } if *operation_destination == destination
        ));

        let exact_operations = output.report().operations;
        let mut exact_limits = LoweringLimits::standard();
        exact_limits.operations = exact_operations;
        assert!(
            CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image.clone(),
                        limits: exact_limits,
                    },
                    &|| false,
                )
                .is_ok()
        );
        let mut below_limits = LoweringLimits::standard();
        below_limits.operations = exact_operations - 1;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: below_limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                ..
            })
        ));

        let mut forged = module.clone();
        let wir::SemanticStatement::Let(statement) = &mut forged.functions[1].body.statements[0]
        else {
            unreachable!();
        };
        let wir::SemanticOperation::Convert { checked, .. } = &mut statement.operation else {
            unreachable!();
        };
        *checked = false;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                forged,
                output.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let polls = Cell::new(0u32);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    polls.set(polls.get().saturating_add(1));
                    false
                },
            )
            .expect("counted scalar conversion lowering");
        let final_poll = polls.get();
        assert!(final_poll > 3);
        polls.set(0);
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let next = polls.get().saturating_add(1);
                    polls.set(next);
                    next >= final_poll
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), final_poll);
    }

    #[test]
    fn real_producer_mutate_and_take_access_reach_exact_scalar_calls() {
        fn call_arguments(region: &wir::SemanticRegion) -> &[wir::Argument] {
            let [
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::Call { arguments, .. },
                    ..
                }),
            ] = region.statements.as_slice()
            else {
                panic!("exact ownership-aware call region");
            };
            arguments
        }

        for (source_access, lowered_access) in [
            (AccessMode::Mutate, wir::AccessMode::Mutate),
            (AccessMode::Take, wir::AccessMode::Take),
        ] {
            let image = analyze_scalar_generated_test_group_with_access(source_access);
            let helper = &image.facts().functions[1];
            assert_eq!(helper.parameters[0].access, lower_hir_access(source_access));
            let x_binding = image
                .facts()
                .expressions
                .iter()
                .find_map(|fact| match &fact.resolution {
                    sema::ExpressionResolution::DirectCall { arguments, .. }
                        if arguments
                            .iter()
                            .any(|argument| argument.access == lower_hir_access(source_access)) =>
                    {
                        arguments
                            .iter()
                            .find(|argument| argument.access == lower_hir_access(source_access))
                    }
                    _ => None,
                })
                .expect("real producer exclusive binding");
            assert!(matches!(
                image.facts().values[x_binding.value.0 as usize].origin,
                sema::SemanticValueOrigin::Local(LocalId(1))
            ));

            let output = CanonicalSemanticLowerer::new()
                .lower(
                    LowerRequest {
                        input: image.clone(),
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .expect("ownership-aware scalar lowering");
            let module = output.wir().as_wir();
            let function_type = module
                .types
                .iter()
                .find_map(|ty| match &ty.kind {
                    wir::TypeKind::Function(function) => Some(function),
                    _ => None,
                })
                .expect("lowered helper type");
            assert_eq!(function_type.parameters[0].access, lowered_access);
            assert_eq!(function_type.parameters[1].access, wir::AccessMode::Read);

            let wir::SemanticStatement::If {
                then_region,
                else_region,
                ..
            } = &module.functions[0].body.statements[3]
            else {
                panic!("ownership-aware source if");
            };
            assert_eq!(
                call_arguments(then_region),
                [
                    wir::Argument {
                        access: lowered_access,
                        value: wir::ValueId(1),
                    },
                    wir::Argument {
                        access: wir::AccessMode::Read,
                        value: wir::ValueId(2),
                    },
                ]
            );
            if source_access == AccessMode::Take {
                assert_eq!(
                    call_arguments(else_region),
                    [
                        wir::Argument {
                            access: wir::AccessMode::Take,
                            value: wir::ValueId(1),
                        },
                        wir::Argument {
                            access: wir::AccessMode::Read,
                            value: wir::ValueId(2),
                        },
                    ]
                );
                assert!(image.facts().statements.iter().any(|fact| {
                    fact.statement == StatementId(5) && !fact.moved_after.is_empty()
                }));
            } else {
                assert!(else_region.statements.is_empty());
            }

            let exact_operations = output.report().operations;
            let mut exact_limits = LoweringLimits::standard();
            exact_limits.operations = exact_operations;
            assert!(
                CanonicalSemanticLowerer::new()
                    .lower(
                        LowerRequest {
                            input: image.clone(),
                            limits: exact_limits,
                        },
                        &|| false,
                    )
                    .is_ok()
            );
            let mut below_limits = LoweringLimits::standard();
            below_limits.operations = exact_operations - 1;
            assert!(matches!(
                CanonicalSemanticLowerer::new().lower(
                    LowerRequest {
                        input: image.clone(),
                        limits: below_limits,
                    },
                    &|| false,
                ),
                Err(LowerError::ResourceLimit {
                    resource: "SemanticWir operations",
                    ..
                })
            ));

            let mut forged = module.clone();
            let wir::SemanticStatement::If { then_region, .. } =
                &mut forged.functions[0].body.statements[3]
            else {
                unreachable!();
            };
            let wir::SemanticStatement::Let(wir::LetStatement {
                operation: wir::SemanticOperation::Call { arguments, .. },
                ..
            }) = &mut then_region.statements[0]
            else {
                unreachable!();
            };
            arguments[0].access = wir::AccessMode::Read;
            assert!(matches!(
                seal(
                    &LowerRequest {
                        input: image,
                        limits: LoweringLimits::standard(),
                    },
                    forged,
                    output.report().clone(),
                    &|| false,
                ),
                Err(LowerError::InvalidReport(_))
            ));
        }
    }

    #[test]
    fn scalar_generated_group_enforces_combined_limits_and_cancellation() {
        let image = analyze_scalar_generated_test_group();
        let mut operation_limits = LoweringLimits::standard();
        operation_limits.operations = 15;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: operation_limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: 15,
            })
        ));
        // 16 is the exact total `facts.values` across every discovered
        // function (`runtime_case` + `helper`, both grown by the bounded-
        // `while` tier guard), the smallest limit that still clears the
        // `preflight_input` `"semantic values"` pre-check so the assertion
        // below exercises the *cumulative* `"SemanticWir values"` check
        // instead (module total is 21).
        let mut value_limits = LoweringLimits::standard();
        value_limits.values = 16;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: value_limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir values",
                limit: 16,
            })
        ));

        let polls = Cell::new(0_u32);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count scalar lowering cancellation polls");
        let cancel_at = polls.get();
        let cancelled = Cell::new(0_u32);
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let next = cancelled.get() + 1;
                    cancelled.set(next);
                    next >= cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(cancelled.get(), cancel_at);
    }

    #[test]
    fn scalar_integer_identity_preserves_fixed_and_pointer_sized_types() {
        assert_eq!(
            lower_integer_type(false, 32, false),
            Ok(("u32", wir::TypeKind::Primitive(wir::PrimitiveType::U32)))
        );
        assert_eq!(
            lower_integer_type(false, 64, true),
            Ok(("usize", wir::TypeKind::Primitive(wir::PrimitiveType::Usize),))
        );
        assert_eq!(
            lower_integer_type(true, 64, true),
            Ok(("isize", wir::TypeKind::Primitive(wir::PrimitiveType::Isize),))
        );
    }

    #[test]
    fn declared_group_preserves_the_real_image_root_without_fabricating_function_tests() {
        let image = analyze_declared_test_group();
        let group = image
            .facts()
            .compiled_test_group
            .as_ref()
            .expect("compiled group")
            .clone();
        assert!(matches!(group.root, ImageRoot::Declared { .. }));
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("declared test image lowering");
        let module = output.wir().as_wir();
        assert_eq!(module.name, "runtime-image");
        assert_eq!(module.compiled_test_group.as_ref(), Some(&group));
        assert!(module.tests.is_empty());
        assert!(matches!(
            module.functions[0].origin,
            wir::FunctionOrigin::GeneratedImageEntry { constructor: 0 }
        ));
        assert_eq!(output.report().tests, 0);
    }

    #[test]
    fn generated_group_enforces_operation_limits_cancellation_and_exact_frame_sealing() {
        let image = analyze_generated_test_group();
        let mut limits = LoweringLimits::standard();
        limits.operations = 10;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit: 10
            })
        ));

        let polls = Cell::new(0u32);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count cancellation polls");
        let cancel_at = polls.get() / 2;
        let cancelled_polls = Cell::new(0u32);
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let next = cancelled_polls.get() + 1;
                    cancelled_polls.set(next);
                    next >= cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(cancelled_polls.get() >= cancel_at);

        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline generated lowering");
        let mut forged = output.wir().as_wir().clone();
        let frame = forged.functions[1]
            .body
            .statements
            .iter_mut()
            .find_map(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::Constant(wir::Constant::Bytes(bytes)),
                    ..
                }) => Some(bytes),
                _ => None,
            })
            .expect("embedded frame");
        frame[0] ^= 1;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged,
                output.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn proof_kinds_map_one_to_one_without_semantic_relabeling() {
        let cases = [
            (sema::ProofKind::TypeChecked, wir::ProofKind::TypeChecked),
            (
                sema::ProofKind::EffectsAllowed,
                wir::ProofKind::EffectsAllowed,
            ),
            (
                sema::ProofKind::DefiniteInitialization,
                wir::ProofKind::DefiniteInitialization,
            ),
            (sema::ProofKind::Ownership, wir::ProofKind::Ownership),
            (
                sema::ProofKind::AccessExclusive,
                wir::ProofKind::AccessExclusive,
            ),
            (
                sema::ProofKind::ViewDoesNotEscape,
                wir::ProofKind::ViewDoesNotEscape,
            ),
            (sema::ProofKind::RegionBound, wir::ProofKind::RegionBound),
            (
                sema::ProofKind::CapacityBound,
                wir::ProofKind::CapacityBound,
            ),
            (
                sema::ProofKind::WaitGraphAcyclic,
                wir::ProofKind::WaitGraphAcyclic,
            ),
            (
                sema::ProofKind::CleanupAcyclic,
                wir::ProofKind::CleanupAcyclic,
            ),
            (sema::ProofKind::WorkBound, wir::ProofKind::WorkBound),
            (sema::ProofKind::StackBound, wir::ProofKind::StackBound),
            (sema::ProofKind::IsrSafe, wir::ProofKind::IsrSafe),
            (
                sema::ProofKind::DmaTransition,
                wir::ProofKind::DmaTransition,
            ),
            (
                sema::ProofKind::MmioPartition,
                wir::ProofKind::MmioPartition,
            ),
            (
                sema::ProofKind::DeviceValueValidated,
                wir::ProofKind::DeviceValueValidated,
            ),
            (sema::ProofKind::WireLayout, wir::ProofKind::WireLayout),
            (
                sema::ProofKind::ReceiptLineage,
                wir::ProofKind::ReceiptLineage,
            ),
            (sema::ProofKind::ActorAsIf, wir::ProofKind::ActorAsIf),
            (
                sema::ProofKind::SupervisionComplete,
                wir::ProofKind::SupervisionComplete,
            ),
            (sema::ProofKind::ImageClosed, wir::ProofKind::ImageClosed),
        ];
        for (source, expected) in cases {
            assert_eq!(lower_proof_kind(&source), expected);
        }
    }

    #[test]
    fn sealer_rejects_proof_origin_color_key_and_build_substitution() {
        let (image, _target) = analyze_minimum();
        let output = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline lowering");
        let baseline = output.wir().as_wir().clone();
        let request = LowerRequest {
            input: image,
            limits: LoweringLimits::standard(),
        };

        let mut wrong_proof = baseline.clone();
        wrong_proof.proofs[1].kind = wir::ProofKind::Ownership;
        assert!(seal(&request, wrong_proof, output.report().clone(), &|| false).is_err());

        let mut lost_sources = baseline.clone();
        lost_sources.proofs[0].sources.clear();
        assert!(seal(&request, lost_sources, output.report().clone(), &|| false).is_err());

        let mut wrong_origin = baseline.clone();
        wrong_origin.functions[0].origin =
            wir::FunctionOrigin::GeneratedImageEntry { constructor: 1 };
        assert!(seal(&request, wrong_origin, output.report().clone(), &|| false).is_err());

        let mut wrong_color = baseline.clone();
        wrong_color.functions[0].color = wir::FunctionColor::Async;
        assert!(seal(&request, wrong_color, output.report().clone(), &|| false).is_err());

        let mut wrong_key = baseline.clone();
        wrong_key.functions[0].instance_key = Sha256Digest::from_bytes([0x44; 32]);
        assert!(seal(&request, wrong_key, output.report().clone(), &|| false).is_err());

        let mut wrong_build = baseline;
        wrong_build.build.request = Sha256Digest::from_bytes([0x55; 32]);
        assert!(seal(&request, wrong_build, output.report().clone(), &|| false).is_err());
    }

    #[test]
    fn resource_limits_and_cancellation_precede_construction() {
        let (image, _target) = analyze_minimum();
        let mut limits = LoweringLimits::standard();
        limits.model_edges = 1;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic model edges",
                limit: 1
            })
        ));
        let facts = image.facts();
        let input_payload = facts.graph.as_ref().map_or(0_u64, |graph| {
            u64::try_from(graph.name.len()).expect("fixture graph name length")
        }) + facts
            .functions
            .iter()
            .map(|function| u64::try_from(function.name.len()).expect("fixture function name"))
            .sum::<u64>()
            + facts
                .proofs
                .iter()
                .map(|proof| {
                    u64::try_from(proof.subject.len()).expect("fixture proof subject")
                        + proof
                            .explanation
                            .iter()
                            .map(|line| {
                                u64::try_from(line.len()).expect("fixture proof explanation")
                            })
                            .sum::<u64>()
                })
                .sum::<u64>();
        let mut missing_unit_payload = LoweringLimits::standard();
        missing_unit_payload.payload_bytes = input_payload;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: missing_unit_payload,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic payload bytes",
                limit
            }) if limit == input_payload
        ));
        let mut exact_payload = LoweringLimits::standard();
        exact_payload.payload_bytes = input_payload + 4;
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: exact_payload,
                },
                &|| false,
            )
            .expect("payload policy includes synthesized unit name exactly");
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| true,
            ),
            Err(LowerError::Cancelled)
        ));
        let polls = Cell::new(0u32);
        let cancel_during_proofs = || {
            let poll = polls.get();
            polls.set(poll + 1);
            poll >= 5
        };
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &cancel_during_proofs,
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() >= 6);

        let large = "x".repeat(128 * 1024);
        let comparison_polls = Cell::new(0_u32);
        assert!(matches!(
            text_matches(&large, &large, &|| {
                let next = comparison_polls.get() + 1;
                comparison_polls.set(next);
                next > 1
            }),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(comparison_polls.get(), 2);

        let name = "actor".repeat(32 * 1024);
        let name_polls = Cell::new(0_u32);
        assert!(matches!(
            bounded_text_pair(&name, ACTIVATION_REGION_SUFFIX, u64::MAX, &|| {
                let next = name_polls.get().saturating_add(1);
                name_polls.set(next);
                next > 8
            },),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(name_polls.get(), 9);
    }

    #[test]
    fn unsupported_fact_families_fail_explicitly() {
        let (image, _target) = analyze_minimum();
        let mut facts = image.into_facts();
        facts.functions[0].origin = sema::FunctionOrigin::Source {
            declaration: DeclarationId(0),
            body: BodyId(0),
        };
        assert!(matches!(
            supported_minimum(&facts),
            Err(LowerError::UnsupportedInput {
                feature: "source function bodies"
            })
        ));
    }

    #[test]
    fn generic_flat_structure_specialization_lowers_constructor_and_projection() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub struct Cell[T]:
    pub value: T
    pub stamp: u8

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        cell: Cell[u64] = Cell(value=7, stamp=3)
        projected: u64 = cell.value
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        let facts = image.facts();
        let (cell_declaration, cell_arguments, cell_fields) = facts
            .types
            .iter()
            .find_map(|ty| match &ty.kind {
                sema::SemanticTypeKind::Structure {
                    declaration,
                    arguments,
                    fields,
                } if !arguments.is_empty() => Some((*declaration, arguments, fields)),
                _ => None,
            })
            .expect("semantic Cell specialization");
        let declaration = image
            .hir()
            .as_program()
            .declaration(cell_declaration)
            .expect("source Cell declaration");
        let wrela_hir::DeclarationKind::Structure(source_cell) = &declaration.kind else {
            panic!("Cell source must remain a structure")
        };
        assert!(generic_structure_source_generics_match(
            image.hir().as_program(),
            declaration,
            source_cell,
            cell_arguments,
        ));
        assert!(
            source_cell
                .fields
                .iter()
                .zip(cell_fields)
                .all(|(source, semantic)| generic_structure_source_field_matches(
                    facts,
                    source_cell,
                    cell_arguments,
                    &source.ty,
                    semantic.ty,
                ))
        );
        let forged_arguments = vec![sema::SemanticArgument::Type(cell_fields[1].ty)];
        assert!(
            !generic_structure_source_field_matches(
                facts,
                source_cell,
                &forged_arguments,
                &source_cell.fields[0].ty,
                cell_fields[0].ty,
            ),
            "same-declaration substitution forgery must not authenticate"
        );
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("copy-scalar generic flat structure should lower");
        let wir = lowered.wir().as_wir();
        let cell = wir
            .types
            .iter()
            .find(|ty| ty.source_name == "Cell")
            .expect("lowered Cell specialization");
        assert!(matches!(&cell.kind, wir::TypeKind::Struct { fields }
            if matches!(fields.as_slice(), [value, stamp]
                if value.name == "value" && stamp.name == "stamp"
                    && value.ty != stamp.ty)));
        assert!(wir.functions.iter().any(|function| {
            let has_aggregate = function.body.statements.iter().any(|statement| {
                matches!(statement,
                    wir::SemanticStatement::Let(wir::LetStatement {
                        operation: wir::SemanticOperation::Aggregate { ty, fields }, ..
                    }) if *ty == cell.id && fields.len() == 2)
            });
            let has_projection = function.body.statements.iter().any(|statement| {
                matches!(
                    statement,
                    wir::SemanticStatement::Let(wir::LetStatement {
                        operation: wir::SemanticOperation::Project { field: 0, .. },
                        ..
                    })
                )
            });
            has_aggregate && has_projection
        }));

        let mut forged = wir.clone();
        let cell = forged
            .types
            .iter_mut()
            .find(|ty| ty.source_name == "Cell")
            .expect("lowered Cell specialization");
        let wir::TypeKind::Struct { fields } = &mut cell.kind else {
            panic!("Cell must remain a structure")
        };
        fields[0].name = "forged".to_owned();
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                forged,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut forged_substitution = lowered.wir().as_wir().clone();
        let cell = forged_substitution
            .types
            .iter_mut()
            .find(|ty| ty.source_name == "Cell")
            .expect("lowered Cell specialization");
        let wir::TypeKind::Struct { fields } = &mut cell.kind else {
            panic!("Cell must remain a structure")
        };
        fields[0].ty = fields[1].ty;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged_substitution,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn non_type_generic_structure_specialization_fails_closed_by_name() {
        let (image, _target) = analyze_minimum();
        let facts = image.into_facts();
        let specialization = sema::SemanticType {
            id: sema::SemanticTypeId(
                u32::try_from(facts.types.len()).expect("fixture semantic type count"),
            ),
            kind: sema::SemanticTypeKind::Structure {
                declaration: DeclarationId(0),
                arguments: vec![sema::SemanticArgument::Constant(sema::ConstantValue::Unit)],
                fields: Vec::new(),
            },
            linearity: sema::Linearity::ExplicitCopy,
            size_upper_bound: Some(0),
            alignment_lower_bound: 1,
            source: Some(span(0, 0, 1)),
        };
        assert!(matches!(
            validate_supported_source_type(&specialization, &facts),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-generic-structure-argument-lowering-pending (non-type or non-scalar specialization)"
            })
        ));
    }

    #[test]
    fn generic_function_lowering_tails_fail_closed_by_name() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub fn identity[T](value: T) -> T:
    return value

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        small: u8 = identity(1)
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        let (hir, facts) = image.into_parts();
        let identity = facts
            .functions
            .iter()
            .position(|function| !function.generic_arguments.is_empty())
            .expect("generic identity specialization");

        let mut non_type = facts.clone();
        non_type.functions[identity].generic_arguments[0] =
            sema::SemanticArgument::Constant(sema::ConstantValue::Unit);
        assert!(matches!(
            validate_generic_function_lowering_boundary_parts(&non_type, hir.as_program()),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-generic-function-argument-lowering-pending (non-type or non-scalar specialization)"
            })
        ));

        let mut non_scalar = facts.clone();
        non_scalar.functions[identity].generic_arguments[0] =
            sema::SemanticArgument::Type(sema::SemanticTypeId(0));
        assert!(matches!(
            validate_generic_function_lowering_boundary_parts(&non_scalar, hir.as_program()),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-generic-function-argument-lowering-pending (non-type or non-scalar specialization)"
            })
        ));

        let mut wrong_result = facts;
        wrong_result.functions[identity].result = sema::SemanticTypeId(0);
        assert!(matches!(
            validate_generic_function_lowering_boundary_parts(&wrong_result, hir.as_program()),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-generic-function-signature-lowering-pending (unsupported or unauthenticated substitution)"
            })
        ));
    }

    #[test]
    fn generic_copy_scalar_function_specializations_lower_exactly() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub fn identity[T](value: T) -> T:
    return value

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        small: u8 = identity(1)
        wide: u64 = identity(2)
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        let facts = image.facts();
        let identity_declaration = image
            .hir()
            .as_program()
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "identity")
            })
            .expect("identity declaration")
            .id;
        let semantic_identities: Vec<_> = facts
            .functions
            .iter()
            .filter(|function| {
                matches!(function.origin, sema::FunctionOrigin::Source { declaration, .. }
                    if declaration == identity_declaration)
            })
            .collect();
        assert_eq!(semantic_identities.len(), 2);

        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("copy-scalar generic function specializations should lower");
        let wir = lowered.wir().as_wir();
        for semantic in &semantic_identities {
            let [sema::SemanticArgument::Type(argument)] = semantic.generic_arguments.as_slice()
            else {
                panic!("identity must retain one concrete type argument")
            };
            let lowered_function = wir
                .functions
                .get(semantic.id.0 as usize)
                .filter(|function| function.id == wir::FunctionId(semantic.id.0))
                .expect("identity specialization retains dense identity");
            assert_eq!(lowered_function.instance_key, semantic.key.0);
            assert_eq!(lowered_function.parameters.len(), 1);
            assert_eq!(lowered_function.result, wir::TypeId(argument.0));
            assert_eq!(
                lowered_function.body.parameters,
                lowered_function.parameters
            );
            assert!(matches!(lowered_function.body.statements.as_slice(),
                [wir::SemanticStatement::Return(values)]
                    if values.as_slice() == lowered_function.parameters.as_slice()));
        }
        let call_targets: Vec<_> = wir
            .functions
            .iter()
            .flat_map(|function| &function.body.statements)
            .filter_map(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation:
                        wir::SemanticOperation::Call {
                            function,
                            arguments,
                            ..
                        },
                    ..
                }) if arguments.len() == 1 => Some(*function),
                _ => None,
            })
            .filter(|target| {
                semantic_identities
                    .iter()
                    .any(|identity| target.0 == identity.id.0)
            })
            .collect();
        assert_eq!(call_targets.len(), 2);
        assert!(
            semantic_identities
                .iter()
                .all(|identity| call_targets.contains(&wir::FunctionId(identity.id.0)))
        );

        let mut forged_key = wir.clone();
        forged_key.functions[semantic_identities[0].id.0 as usize].instance_key =
            Sha256Digest::from_bytes([0x51; 32]);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                forged_key,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut forged_call = wir.clone();
        let first = wir::FunctionId(semantic_identities[0].id.0);
        let second = wir::FunctionId(semantic_identities[1].id.0);
        let operation = forged_call
            .functions
            .iter_mut()
            .flat_map(|function| &mut function.body.statements)
            .find_map(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::Call { function, .. },
                    ..
                }) if *function == first => Some(function),
                _ => None,
            })
            .expect("call to first specialization");
        *operation = second;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged_call,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn uniform_copy_scalar_generic_enum_specialization_lowers() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub enum Choice[T]:
    left(T)
    right(T)

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        choice: Choice[u64] = Choice.left(7)
        match choice:
            case Choice.left(value):
                pass
            case Choice.right(value):
                pass
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("uniform copy-scalar generic enum specialization should lower");
        assert!(lowered.wir().as_wir().types.iter().any(|ty| {
            matches!(&ty.kind, wir::TypeKind::Enum { variants }
                if ty.source_name == "Choice"
                    && matches!(variants.as_slice(), [left, right]
                        if left.name == "left" && right.name == "right"
                            && left.fields.len() == 1 && right.fields.len() == 1
                            && left.fields[0].ty == right.fields[0].ty))
        }));

        let mut forged = lowered.wir().as_wir().clone();
        let choice = forged
            .types
            .iter_mut()
            .find(|ty| ty.source_name == "Choice")
            .expect("lowered Choice specialization");
        let wir::TypeKind::Enum { variants } = &mut choice.kind else {
            panic!("Choice must remain an enum")
        };
        variants[0].name = "forged".to_owned();
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn mixed_arity_generic_enum_lowering_fails_closed_by_name() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub enum Maybe[T]:
    none
    some(T)

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        value: Maybe[u64] = Maybe.some(7)
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-generic-enum-mixed-arity-lowering-pending (unit or non-unary generic enum variants)"
            })
        ));
    }

    #[test]
    fn heterogeneous_copy_scalar_generic_enum_specialization_lowers_exactly() {
        let image = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub enum Either[T, U]:
    first(T)
    second(U)

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        value: Either[u8, u64] = Either.first(7)
        match value:
            case Either.first(small):
                pass
            case Either.second(large):
                pass
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("heterogeneous copy-scalar generic enum specialization should lower");
        let wir = lowered.wir().as_wir();
        let either = wir
            .types
            .iter()
            .find(|ty| ty.source_name == "Either")
            .expect("lowered Either specialization");
        let wir::TypeKind::Enum { variants } = &either.kind else {
            panic!("Either must remain an enum")
        };
        let [first, second] = variants.as_slice() else {
            panic!("Either must retain both source variants")
        };
        assert_eq!(first.name, "first");
        assert_eq!(second.name, "second");
        assert_ne!(first.fields[0].ty, second.fields[0].ty);

        let mut forged = wir.clone();
        let forged_either = forged
            .types
            .iter_mut()
            .find(|ty| ty.source_name == "Either")
            .expect("forged Either specialization");
        let wir::TypeKind::Enum { variants } = &mut forged_either.kind else {
            panic!("Either must remain an enum")
        };
        variants[1].fields[0].ty = variants[0].fields[0].ty;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn concrete_method_call_stops_at_named_lowering_boundary() {
        let mut facts = analyze_parsed_actor().into_facts();
        let template = facts
            .expressions
            .first()
            .expect("actor fixture expression")
            .clone();
        let mut method = template;
        method.resolution = sema::ExpressionResolution::MethodCall {
            function: sema::FunctionInstanceId(0),
            receiver: sema::ValueId(0),
            receiver_access: sema::AccessMode::Read,
            arguments: Vec::new(),
        };
        facts.expressions.push(method);

        assert!(matches!(
            validate_method_call_lowering_boundary(&facts),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-method-call-lowering-pending (concrete receiver method calls)"
            })
        ));
    }

    #[test]
    fn admission_result_stops_at_named_try_send_lowering_boundary() {
        let mut facts = analyze_parsed_actor().into_facts();
        let template = facts
            .expressions
            .first()
            .expect("actor fixture expression")
            .clone();
        let mut try_send = template;
        try_send.resolution =
            sema::ExpressionResolution::Builtin(sema::IntrinsicOperation::ActorTrySend {
                actor: sema::ActorId(0),
            });
        facts.expressions.push(try_send);

        assert!(matches!(
            validate_admission_result_lowering_boundary(&facts),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-admission-result-lowering-pending (try-send outcome dispatch)"
            })
        ));
    }

    #[test]
    fn free_scope_normal_exit_lowers_exact_semantic_cleanup_sequence() {
        let image = analyze_pass_only_scope_actor();
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("pass-only free scope should lower through SemanticWir");
        let wir = lowered.wir().as_wir();
        let [scope] = wir.scopes.as_slice() else {
            panic!("one exact scope activation plan")
        };
        assert_eq!(scope.name, "irqs_masked");
        assert!(scope.dependencies.is_empty());
        assert_eq!(scope.reverse_source_order, 0);
        assert_eq!(
            wir.functions[scope.exit.0 as usize].role,
            wir::FunctionRole::Cleanup
        );

        let turn = wir
            .functions
            .iter()
            .find(|function| matches!(function.role, wir::FunctionRole::ActorTurn(_)))
            .expect("actor turn containing the scope");
        let operations: Vec<_> = turn
            .body
            .statements
            .iter()
            .filter_map(|statement| match statement {
                wir::SemanticStatement::Let(statement) => Some(&statement.operation),
                _ => None,
            })
            .collect();
        let enter = operations.iter().position(|operation| {
            matches!(operation, wir::SemanticOperation::EnterScope { scope: id, .. } if *id == scope.id)
        });
        let commit = operations.iter().position(|operation| {
            matches!(operation, wir::SemanticOperation::CommitScope { scope: id, .. } if *id == scope.id)
        });
        let exit = operations.iter().position(|operation| {
            matches!(operation, wir::SemanticOperation::ExitScope { scope: id } if *id == scope.id)
        });
        assert!(
            matches!((enter, commit, exit), (Some(enter), Some(commit), Some(exit)) if enter < commit && commit < exit)
        );

        let mut forged = wir.clone();
        forged.scopes[0].cleanup_proof = wir::ProofId(0);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                forged,
                lowered.report().clone(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn nested_free_scopes_preserve_proved_reverse_cleanup_order() {
        let source = PASS_ONLY_SCOPE_ACTOR_SOURCE.replace(
            "        with irqs_masked() as mask:\n            pass",
            "        with irqs_masked() as outer:\n            with irqs_masked() as inner:\n                pass",
        );
        let image = analyze_parsed_actor_source(&source);
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("nested pass-only scopes should lower");
        let wir = lowered.wir().as_wir();
        assert_eq!(wir.scopes.len(), 2);
        assert!(wir.scopes[0].dependencies.is_empty());
        assert_eq!(wir.scopes[1].dependencies, [wir::ScopeId(0)]);
        assert_eq!(wir.scopes[0].reverse_source_order, 0);
        assert_eq!(wir.scopes[1].reverse_source_order, 1);
        let turn = wir
            .functions
            .iter()
            .find(|function| matches!(function.role, wir::FunctionRole::ActorTurn(_)))
            .expect("actor turn");
        let markers: Vec<_> = turn
            .body
            .statements
            .iter()
            .filter_map(|statement| match statement {
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::EnterScope { scope, .. },
                    ..
                }) => Some(("enter", *scope)),
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::CommitScope { scope, .. },
                    ..
                }) => Some(("commit", *scope)),
                wir::SemanticStatement::Let(wir::LetStatement {
                    operation: wir::SemanticOperation::ExitScope { scope },
                    ..
                }) => Some(("exit", *scope)),
                _ => None,
            })
            .collect();
        assert_eq!(
            markers,
            [
                ("enter", wir::ScopeId(1)),
                ("enter", wir::ScopeId(0)),
                ("commit", wir::ScopeId(0)),
                ("exit", wir::ScopeId(0)),
                ("commit", wir::ScopeId(1)),
                ("exit", wir::ScopeId(1)),
            ]
        );
    }

    #[test]
    fn scope_lowering_has_exact_operation_limit_and_late_cancellation() {
        let image = analyze_pass_only_scope_actor();
        let baseline = CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("scope lowering baseline");
        let exact_operations = baseline.report().operations;
        let mut exact = LoweringLimits::standard();
        exact.operations = exact_operations;
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact scope operation limit");
        let mut one_under = exact;
        one_under.operations = exact_operations - 1;
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image.clone(),
                    limits: one_under,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "SemanticWir operations",
                limit,
            }) if limit == exact_operations - 1
        ));

        let polls = Cell::new(0_u64);
        CanonicalSemanticLowerer::new()
            .lower(
                LowerRequest {
                    input: image.clone(),
                    limits: exact,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count exact scope cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: image,
                    limits: exact,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scope_lowering_tails_fail_closed_by_name() {
        let parameterized = analyze_parsed_actor_source(
            r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked(token: u32) -> Masked:
    enter Masked(token=token)
    exit state:
        pass

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        with irqs_masked(1) as mask:
            pass
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#,
        );
        assert!(matches!(
            CanonicalSemanticLowerer::new().lower(
                LowerRequest {
                    input: parameterized,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "semantic-scope-parameter-lowering-pending (parameterized acquisition)",
            })
        ));
    }
}
