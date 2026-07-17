use super::*;

use crate::comptime_check::{
    CheckedComptimeClosure, ComptimeCheckLimits, SOURCE_COMPTIME_CLOSURE_PROOF_MARKER,
    check_source_comptime_unit_test,
};

use wrela_diagnostics::{Category, Diagnostic, Severity};
use wrela_hir::{
    AssignmentOperator, BodyId, Builtin, DeclarationKind, Definition, ExpressionId, ExpressionKind,
    FunctionColor, Literal, LocalId, StatementId, StatementKind, TypeExpression,
    TypeExpressionKind,
};
use wrela_test_model::{
    ComptimeTest, FailurePhase, FullImageTestGroup, ImageRoot, ImageScenario, ImageTest,
    ImageTestInvocation, PlannedAssertionDescriptor, TEST_PLAN_SCHEMA, TestDescriptor, TestId,
    TestKind, TestOutcome, TestPlan, TestPlanLimits,
};

const COMPTIME_TEST_TIMEOUT_NS: u64 = 30_000_000_000;
const INTEGRATION_TEST_TIMEOUT_NS: u64 = 30_000_000_000;
const GENERATED_BOOT_TIMEOUT_NS: u64 = 30_000_000_000;
const GENERATED_SHUTDOWN_TIMEOUT_NS: u64 = 5_000_000_000;
const GENERATED_MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
const GENERATED_GROUP_NAME: &str = "wrela-generated-integration-tests";
const GENERATED_HARNESS_NAME: &str = "__wrela_test_harness";
const MAX_TEST_FILTER_BYTES: usize = 4096;
const MAX_RUNTIME_ASSERTION_EXPRESSION_BYTES: usize = 4096;
const BUILTIN_ATTRIBUTE_DIAGNOSTIC_CODE: &str = "semantic-builtin-attribute-not-implemented";

/// Production semantic analyzer for the minimum closed image surface and its
/// real compiler-evaluated/generated-image test forms. Unsupported source
/// operations remain explicit diagnostics; no test result or image fact is
/// synthesized in place of source semantics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalSemanticAnalyzer;

impl CanonicalSemanticAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Derive the exact declaration ChangeSet from a sealed prior product.
    /// This is the production entry for stateful compiler consumers: callers
    /// provide no declaration identities and therefore cannot underreport a
    /// dependency edge.
    pub fn derive_change_set(
        &self,
        current_hir: &ValidatedProgram,
        current_source_graph: Sha256Digest,
        previous: PreviousAnalysisProduct<'_>,
        reuse_limits: AnalysisReuseLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<DerivedAnalysisChangeSet, AnalysisFailure> {
        reuse_limits.validate()?;
        if previous.contract_version != ANALYSIS_CHANGE_SET_REUSE_VERSION {
            return Err(AnalysisFailure::UnsupportedReuseVersion {
                observed: previous.contract_version,
            });
        }
        check_cancelled(is_cancelled)?;
        let previous = previous
            .output
            .successful()
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let previous_source_graph = previous.facts().build.source_graph;
        if previous_source_graph == current_source_graph
            || !compatible_hir_graphs(previous.hir(), current_hir)
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        let mut meter = AnalysisReuseMeter::new(reuse_limits, is_cancelled);
        let changed_declarations = affected_declarations(previous.hir(), current_hir, &mut meter)?;
        Ok(DerivedAnalysisChangeSet {
            changes: AnalysisChangeSet {
                previous_source_graph: Some(previous_source_graph),
                changed_declarations,
            },
            comparisons: meter.used,
        })
    }

    /// Analyze with explicit sealed-product reuse and independently bounded
    /// comparison work. A cold tracked run cannot smuggle incremental flags;
    /// an incremental run rejects any omitted direct or dependent declaration.
    pub fn analyze_tracked(
        &self,
        request: AnalysisRequest<'_>,
        previous: Option<PreviousAnalysisProduct<'_>>,
        reuse_limits: AnalysisReuseLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TrackedAnalysisOutput, AnalysisFailure> {
        reuse_limits.validate()?;
        let Some(previous) = previous else {
            if request.changes.previous_source_graph.is_some()
                || !request.changes.changed_declarations.is_empty()
            {
                return Err(AnalysisFailure::RequestMismatch);
            }
            let output = self.analyze(request, is_cancelled)?;
            let executed = output.partial().functions.len() as u64;
            return Ok(TrackedAnalysisOutput {
                output,
                reuse: AnalysisReuseReport::cold(executed),
            });
        };
        if previous.contract_version != ANALYSIS_CHANGE_SET_REUSE_VERSION {
            return Err(AnalysisFailure::UnsupportedReuseVersion {
                observed: previous.contract_version,
            });
        }
        let previous_image = validate_previous_analysis(&request, previous.output, is_cancelled)?;
        let mut meter = AnalysisReuseMeter::new(reuse_limits, is_cancelled);
        let recomputed =
            affected_declarations(previous_image.hir(), request.hir.as_ref(), &mut meter)?;
        if request.changes.changed_declarations.as_slice() != recomputed.as_slice() {
            return Err(AnalysisFailure::RequestMismatch);
        }

        let affected = recomputed
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut semantic_declarations = std::collections::BTreeSet::new();
        match &previous_image.facts().root {
            AnalysisRoot::DeclaredImage { declaration, .. } => {
                semantic_declarations.insert(*declaration);
            }
            AnalysisRoot::GeneratedTestHarness { .. } => {}
        }
        for function in &previous_image.facts().functions {
            meter.poll()?;
            if let Some(declaration) =
                function_origin_declaration(&function.origin, previous_image.hir().as_program())
            {
                semantic_declarations.insert(declaration);
            }
        }
        let semantic_affected = semantic_declarations
            .iter()
            .any(|declaration| affected.contains(declaration));
        let (output, reused_declarations, reused_functions, producer_functions_executed) =
            if semantic_affected {
                // This is the honest fallback boundary for revision 0.1:
                // affected semantic roots are recomputed cold rather than
                // represented as unsupported partial reuse.
                let output = self.analyze(request.clone(), is_cancelled)?;
                let executed = output.partial().functions.len() as u64;
                (output, Vec::new(), Vec::new(), executed)
            } else {
                if !matches!(request.mode, AnalysisMode::Image { .. })
                    || previous_image.facts().test_plan.is_some()
                    || previous_image.facts().compiled_test_group.is_some()
                    || !previous_image.facts().comptime_test_results.is_empty()
                    || previous_image.facts().functions.len() != 1
                    || !matches!(
                        previous_image.facts().functions[0].origin,
                        FunctionOrigin::GeneratedImageEntry { .. }
                    )
                    || previous_image.facts().graph.as_ref().is_none_or(|graph| {
                        !graph.actors.is_empty()
                            || !graph.tasks.is_empty()
                            || !graph.devices.is_empty()
                            || !graph.pools.is_empty()
                            || !graph.regions.is_empty()
                            || !graph.brands.is_empty()
                    })
                {
                    return Err(AnalysisFailure::UnsupportedReuseShape(
                        "whole-product semantic reuse currently supports the minimum ordinary image",
                    ));
                }
                let expected_root = analysis_root(&request, is_cancelled)?;
                meter.equal(&expected_root, &previous_image.facts().root)?;
                let mut facts = previous_image.facts().clone();
                facts.hir = HirSummary::from_validated(request.hir.as_ref())?;
                facts.build = request.build.identity.clone();
                facts.target_digest = request.target.content_digest();
                facts.root = expected_root;
                // Generated-entry keys are request identities rather than
                // semantic facts. Rebinding this fixed-width identity is the
                // only current-build work on the whole-product reuse path.
                facts.functions[0].key = FunctionKey(request.build.identity.request);
                let output = finish_analysis(
                    &request,
                    facts,
                    previous.output.diagnostics().to_vec(),
                    is_cancelled,
                )?;
                let reused_functions = previous_image
                    .facts()
                    .functions
                    .iter()
                    .map(|function| function.id)
                    .collect();
                (
                    output,
                    semantic_declarations.into_iter().collect(),
                    reused_functions,
                    0,
                )
            };
        meter.poll()?;
        Ok(TrackedAnalysisOutput {
            output,
            reuse: AnalysisReuseReport {
                reused_declarations,
                reused_functions,
                recomputed_declarations: recomputed,
                producer_functions_executed,
                comparisons: meter.used,
            },
        })
    }
}

struct AnalysisReuseMeter<'a> {
    used: u64,
    limits: AnalysisReuseLimits,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> AnalysisReuseMeter<'a> {
    fn new(limits: AnalysisReuseLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            used: 0,
            limits,
            is_cancelled,
        }
    }

    fn poll(&mut self) -> Result<(), AnalysisFailure> {
        check_cancelled(self.is_cancelled)?;
        self.used = self
            .used
            .checked_add(1)
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "semantic reuse comparisons",
                limit: self.limits.comparisons,
            })?;
        if self.used > self.limits.comparisons {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "semantic reuse comparisons",
                limit: self.limits.comparisons,
            });
        }
        Ok(())
    }

    fn equal<T: PartialEq>(&mut self, left: &T, right: &T) -> Result<(), AnalysisFailure> {
        self.poll()?;
        if left == right {
            Ok(())
        } else {
            Err(AnalysisFailure::RequestMismatch)
        }
    }
}

fn validate_previous_analysis<'a>(
    request: &AnalysisRequest<'_>,
    previous: &'a AnalysisOutput,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a AnalyzedImage, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let previous = previous
        .successful()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let old = &previous.facts().build;
    let new = &request.build.identity;
    if request.changes.previous_source_graph != Some(old.source_graph)
        || old.source_graph == new.source_graph
        || old.compiler != new.compiler
        || old.language != new.language
        || old.target != new.target
        || old.target_package != new.target_package
        || old.standard_library != new.standard_library
        || old.profile != new.profile
        || previous.facts().target_digest != request.target.content_digest()
        || previous.facts().target_digest != new.target_package
        || request.target.identity() != &new.target
        || !compatible_hir_graphs(previous.hir(), request.hir.as_ref())
    {
        return Err(AnalysisFailure::RequestMismatch);
    }
    Ok(previous)
}

fn compatible_hir_graphs(previous: &ValidatedProgram, current: &ValidatedProgram) -> bool {
    let previous = previous.as_program();
    let current = current.as_program();
    previous.modules.len() == current.modules.len()
        && previous.declarations.len() == current.declarations.len()
        && previous.bodies.len() == current.bodies.len()
        && previous.parameters.len() == current.parameters.len()
        && previous.locals.len() == current.locals.len()
        && previous.statements.len() == current.statements.len()
        && previous.expressions.len() == current.expressions.len()
        && previous.patterns.len() == current.patterns.len()
        && previous.regions.len() == current.regions.len()
        && previous.packages.root() == current.packages.root()
        && previous.packages.modules() == current.packages.modules()
        && previous
            .packages
            .packages()
            .iter()
            .zip(current.packages.packages())
            .all(|(left, right)| {
                left.id == right.id
                    && left.identity.name == right.identity.name
                    && left.identity.version == right.identity.version
                    && left.dependencies == right.dependencies
            })
}

fn affected_declarations(
    previous: &ValidatedProgram,
    current: &ValidatedProgram,
    meter: &mut AnalysisReuseMeter<'_>,
) -> Result<Vec<DeclarationId>, AnalysisFailure> {
    if !compatible_hir_graphs(previous, current) {
        return Err(AnalysisFailure::RequestMismatch);
    }
    let previous = previous.as_program();
    let current = current.as_program();
    let mut affected = std::collections::BTreeSet::new();
    let mut requires_conservative_reanalysis = false;
    for index in 0..current.declarations.len() {
        meter.poll()?;
        let id =
            DeclarationId(
                u32::try_from(index).map_err(|_| AnalysisFailure::ResourceLimit {
                    resource: "semantic reuse declaration identities",
                    limit: meter.limits.comparisons,
                })?,
            );
        if !declaration_semantically_equal(previous, current, id, meter)? {
            affected.insert(id);
            if !declaration_change_is_literal_only(previous, current, id, meter)? {
                requires_conservative_reanalysis = true;
            }
        }
    }
    // The revision-0.1 semantic product does not yet expose a complete
    // declaration dependency graph for types, attributes, generics, roles,
    // effects, resources, or name-resolution edges. Until it does, only a
    // literal payload edit inside a private, attribute-free, non-generic sync
    // runtime helper is narrow enough to prove local. Every other HIR mutation
    // conservatively invalidates the complete declaration product.
    if requires_conservative_reanalysis {
        let mut all = Vec::with_capacity(current.declarations.len());
        for index in 0..current.declarations.len() {
            meter.poll()?;
            all.push(DeclarationId(u32::try_from(index).map_err(|_| {
                AnalysisFailure::ResourceLimit {
                    resource: "semantic reuse declaration identities",
                    limit: meter.limits.comparisons,
                }
            })?));
        }
        return Ok(all);
    }
    loop {
        let before = affected.len();
        for program in [previous, current] {
            for expression in &program.expressions {
                meter.poll()?;
                let ExpressionKind::Reference(Definition::Declaration(target)) = &expression.kind
                else {
                    continue;
                };
                let Some(owner) = expression_owner_declaration(program, expression.owner) else {
                    continue;
                };
                if affected.contains(&target.declaration) {
                    affected.insert(owner);
                }
            }
        }
        if affected.len() == before {
            break;
        }
    }
    Ok(affected.into_iter().collect())
}

fn declaration_change_is_literal_only(
    previous: &wrela_hir::Program,
    current: &wrela_hir::Program,
    declaration: DeclarationId,
    meter: &mut AnalysisReuseMeter<'_>,
) -> Result<bool, AnalysisFailure> {
    let index = declaration.0 as usize;
    meter.poll()?;
    let (Some(previous_declaration), Some(current_declaration)) = (
        previous.declarations.get(index),
        current.declarations.get(index),
    ) else {
        return Ok(false);
    };
    if previous_declaration != current_declaration
        || !narrow_runtime_literal_owner(previous, previous_declaration)
        || !narrow_runtime_literal_owner(current, current_declaration)
    {
        return Ok(false);
    }
    macro_rules! require_equal_owned {
        ($arena:ident, $owner:expr) => {{
            let left = previous
                .$arena
                .iter()
                .filter(|value| $owner(previous, value, declaration))
                .collect::<Vec<_>>();
            let right = current
                .$arena
                .iter()
                .filter(|value| $owner(current, value, declaration))
                .collect::<Vec<_>>();
            meter.poll()?;
            if left != right {
                return Ok(false);
            }
        }};
    }
    require_equal_owned!(generic_parameters, generic_owned_by);
    require_equal_owned!(parameters, parameter_owned_by);
    require_equal_owned!(bodies, body_owned_by);
    require_equal_owned!(scopes, scope_owned_by);
    require_equal_owned!(locals, local_owned_by);
    require_equal_owned!(statements, statement_owned_by);
    require_equal_owned!(patterns, pattern_owned_by);
    require_equal_owned!(regions, region_owned_by);

    let left = previous
        .expressions
        .iter()
        .filter(|value| expression_owned_by(previous, value, declaration))
        .collect::<Vec<_>>();
    let right = current
        .expressions
        .iter()
        .filter(|value| expression_owned_by(current, value, declaration))
        .collect::<Vec<_>>();
    meter.poll()?;
    if left.len() != right.len() {
        return Ok(false);
    }
    let mut changed_literal = false;
    for (left, right) in left.into_iter().zip(right) {
        meter.poll()?;
        if left == right {
            continue;
        }
        if left.id != right.id
            || left.owner != right.owner
            || left.scope != right.scope
            || left.source != right.source
            || !matches!(
                (&left.kind, &right.kind),
                (ExpressionKind::Literal(_), ExpressionKind::Literal(_))
            )
        {
            return Ok(false);
        }
        changed_literal = true;
    }
    Ok(changed_literal)
}

fn narrow_runtime_literal_owner(
    program: &wrela_hir::Program,
    declaration: &wrela_hir::Declaration,
) -> bool {
    let DeclarationKind::Function(function) = &declaration.kind else {
        return false;
    };
    declaration.owner == wrela_hir::DeclarationOwner::Module(declaration.module)
        && declaration.visibility == wrela_hir::Visibility::Private
        && declaration.attributes.is_empty()
        && function.color == FunctionColor::Sync
        && function.generics.is_empty()
        && function.parameters.is_empty()
        && function.body.is_some()
        && !program.image_candidates.contains(&declaration.id)
        && !program.test_candidates.contains(&declaration.id)
}

fn declaration_semantically_equal(
    previous: &wrela_hir::Program,
    current: &wrela_hir::Program,
    declaration: DeclarationId,
    meter: &mut AnalysisReuseMeter<'_>,
) -> Result<bool, AnalysisFailure> {
    let index = declaration.0 as usize;
    meter.poll()?;
    if previous.declarations.get(index) != current.declarations.get(index) {
        return Ok(false);
    }
    macro_rules! equal_owned {
        ($arena:ident, $owner:expr) => {{
            let left = previous
                .$arena
                .iter()
                .filter(|value| $owner(previous, value, declaration))
                .collect::<Vec<_>>();
            let right = current
                .$arena
                .iter()
                .filter(|value| $owner(current, value, declaration))
                .collect::<Vec<_>>();
            meter.poll()?;
            if left != right {
                return Ok(false);
            }
        }};
    }
    equal_owned!(generic_parameters, generic_owned_by);
    equal_owned!(parameters, parameter_owned_by);
    equal_owned!(bodies, body_owned_by);
    equal_owned!(scopes, scope_owned_by);
    equal_owned!(locals, local_owned_by);
    equal_owned!(statements, statement_owned_by);
    equal_owned!(expressions, expression_owned_by);
    equal_owned!(patterns, pattern_owned_by);
    equal_owned!(regions, region_owned_by);
    Ok(true)
}

fn generic_owned_by(
    _: &wrela_hir::Program,
    value: &wrela_hir::GenericParameter,
    declaration: DeclarationId,
) -> bool {
    value.owner == declaration
}

fn parameter_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Parameter,
    declaration: DeclarationId,
) -> bool {
    match value.owner {
        wrela_hir::CallableOwner::Declaration(owner) => owner == declaration,
        wrela_hir::CallableOwner::Closure(expression) => {
            expression_owner_declaration(program, wrela_hir::ExpressionOwner::Closure(expression))
                == Some(declaration)
        }
    }
}

fn body_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Body,
    declaration: DeclarationId,
) -> bool {
    body_owner_declaration(program, value.id) == Some(declaration)
}

fn scope_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::LexicalScope,
    declaration: DeclarationId,
) -> bool {
    body_owner_declaration(program, value.body) == Some(declaration)
}

fn local_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Local,
    declaration: DeclarationId,
) -> bool {
    body_owner_declaration(program, value.body) == Some(declaration)
}

fn statement_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Statement,
    declaration: DeclarationId,
) -> bool {
    body_owner_declaration(program, value.body) == Some(declaration)
}

fn expression_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Expression,
    declaration: DeclarationId,
) -> bool {
    expression_owner_declaration(program, value.owner) == Some(declaration)
}

fn pattern_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::Pattern,
    declaration: DeclarationId,
) -> bool {
    expression_owner_declaration(program, value.owner) == Some(declaration)
}

fn region_owned_by(
    program: &wrela_hir::Program,
    value: &wrela_hir::RegionBinding,
    declaration: DeclarationId,
) -> bool {
    body_owner_declaration(program, value.body) == Some(declaration)
}

fn body_owner_declaration(program: &wrela_hir::Program, body: BodyId) -> Option<DeclarationId> {
    match program.bodies.get(body.0 as usize)?.owner {
        wrela_hir::BodyOwner::Declaration(declaration) => Some(declaration),
        wrela_hir::BodyOwner::Closure(expression) => {
            expression_owner_declaration(program, wrela_hir::ExpressionOwner::Closure(expression))
        }
    }
}

fn expression_owner_declaration(
    program: &wrela_hir::Program,
    owner: wrela_hir::ExpressionOwner,
) -> Option<DeclarationId> {
    match owner {
        wrela_hir::ExpressionOwner::Declaration(declaration) => Some(declaration),
        wrela_hir::ExpressionOwner::Body(body) => body_owner_declaration(program, body),
        wrela_hir::ExpressionOwner::Closure(expression) => {
            let expression = program.expressions.get(expression.0 as usize)?;
            expression_owner_declaration(program, expression.owner)
        }
    }
}

fn function_origin_declaration(
    origin: &FunctionOrigin,
    hir: &wrela_hir::Program,
) -> Option<DeclarationId> {
    match origin {
        FunctionOrigin::Source { declaration, .. }
        | FunctionOrigin::GeneratedImageEntry {
            constructor: declaration,
        } => Some(*declaration),
        FunctionOrigin::SourceClosure { expression } => {
            let expression = hir.expressions.get(expression.0 as usize)?;
            expression_owner_declaration(hir, expression.owner)
        }
        FunctionOrigin::GeneratedTestHarness { .. } => None,
    }
}

#[derive(Debug)]
struct BuiltinAttributeCensus {
    diagnostics: Vec<Diagnostic>,
    work_units: u64,
    diagnostic_bytes: u64,
}

impl BuiltinAttributeCensus {
    fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
            work_units: 0,
            diagnostic_bytes: 0,
        }
    }

    fn visit_owner(
        &mut self,
        limits: AnalysisLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisFailure> {
        check_cancelled(is_cancelled)?;
        self.work_units = self
            .work_units
            .checked_add(1)
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "semantic built-in attribute census work",
                limit: limits.fact_edges,
            })?;
        if self.work_units > limits.fact_edges {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "semantic built-in attribute census work",
                limit: limits.fact_edges,
            });
        }
        Ok(())
    }

    fn visit_attribute(
        &mut self,
        attribute: &wrela_hir::Attribute,
        limits: AnalysisLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisFailure> {
        self.visit_owner(limits, is_cancelled)?;
        let wrela_hir::AttributeIdentity::Builtin(builtin) = attribute.identity else {
            return Ok(());
        };
        if builtin_attribute_has_semantic_consumer(builtin) {
            return Ok(());
        }
        let next_count =
            self.diagnostics
                .len()
                .checked_add(1)
                .ok_or(AnalysisFailure::ResourceLimit {
                    resource: "semantic diagnostics",
                    limit: u64::from(limits.diagnostic_count),
                })?;
        if next_count > limits.diagnostic_count as usize {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "semantic diagnostics",
                limit: u64::from(limits.diagnostic_count),
            });
        }
        let message = unimplemented_builtin_attribute_message(builtin);
        let bytes = u64::try_from(BUILTIN_ATTRIBUTE_DIAGNOSTIC_CODE.len())
            .ok()
            .and_then(|code| {
                u64::try_from(message.len())
                    .ok()
                    .and_then(|message| code.checked_add(message))
            })
            .and_then(|bytes| self.diagnostic_bytes.checked_add(bytes))
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: limits.diagnostic_bytes,
            })?;
        if bytes > limits.diagnostic_bytes {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: limits.diagnostic_bytes,
            });
        }
        self.diagnostics
            .try_reserve_exact(1)
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "semantic diagnostics",
                limit: u64::from(limits.diagnostic_count),
            })?;
        let code = copy_builtin_attribute_diagnostic_text(
            BUILTIN_ATTRIBUTE_DIAGNOSTIC_CODE,
            limits.diagnostic_bytes,
        )?;
        let message = copy_builtin_attribute_diagnostic_text(message, limits.diagnostic_bytes)?;
        self.diagnostics.push(Diagnostic {
            category: unimplemented_builtin_attribute_category(builtin),
            code: Some(code),
            severity: Severity::Error,
            primary: attribute.source,
            message,
            labels: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
            related: Vec::new(),
            repairs: Vec::new(),
        });
        self.diagnostic_bytes = bytes;
        Ok(())
    }

    fn visit_attributes(
        &mut self,
        attributes: &[wrela_hir::Attribute],
        limits: AnalysisLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisFailure> {
        for attribute in attributes {
            self.visit_attribute(attribute, limits, is_cancelled)?;
        }
        Ok(())
    }
}

fn census_builtin_attributes(
    program: &wrela_hir::Program,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BuiltinAttributeCensus, AnalysisFailure> {
    let mut census = BuiltinAttributeCensus::new();
    for declaration in &program.declarations {
        census.visit_owner(limits, is_cancelled)?;
        census.visit_attributes(&declaration.attributes, limits, is_cancelled)?;
        if let DeclarationKind::Structure(aggregate) | DeclarationKind::Class(aggregate) =
            &declaration.kind
        {
            for field in &aggregate.fields {
                census.visit_owner(limits, is_cancelled)?;
                census.visit_attributes(&field.attributes, limits, is_cancelled)?;
            }
        }
    }
    for statement in &program.statements {
        census.visit_owner(limits, is_cancelled)?;
        census.visit_attributes(&statement.attributes, limits, is_cancelled)?;
    }
    Ok(census)
}

const fn builtin_attribute_has_semantic_consumer(builtin: wrela_hir::BuiltinAttribute) -> bool {
    matches!(
        builtin,
        wrela_hir::BuiltinAttribute::Image
            | wrela_hir::BuiltinAttribute::App
            | wrela_hir::BuiltinAttribute::Service
            | wrela_hir::BuiltinAttribute::Driver
            | wrela_hir::BuiltinAttribute::Task
            | wrela_hir::BuiltinAttribute::Test
    )
}

const fn unimplemented_builtin_attribute_category(
    builtin: wrela_hir::BuiltinAttribute,
) -> Category {
    match builtin {
        wrela_hir::BuiltinAttribute::ReceiptHandoff => Category::ACTOR,
        wrela_hir::BuiltinAttribute::Dma => Category::DMA,
        wrela_hir::BuiltinAttribute::IsrSafe
        | wrela_hir::BuiltinAttribute::Wire
        | wrela_hir::BuiltinAttribute::Mmio
        | wrela_hir::BuiltinAttribute::Offset
        | wrela_hir::BuiltinAttribute::LayoutAssert => Category::HARDWARE,
        wrela_hir::BuiltinAttribute::SuspendSafe => Category::ASYNC,
        wrela_hir::BuiltinAttribute::NoPromote => Category::OWNERSHIP,
        wrela_hir::BuiltinAttribute::Budget | wrela_hir::BuiltinAttribute::Uninterrupted => {
            Category::CAPACITY
        }
        wrela_hir::BuiltinAttribute::Image
        | wrela_hir::BuiltinAttribute::App
        | wrela_hir::BuiltinAttribute::Service
        | wrela_hir::BuiltinAttribute::Driver
        | wrela_hir::BuiltinAttribute::Task
        | wrela_hir::BuiltinAttribute::Test => Category::TYPE,
    }
}

const fn unimplemented_builtin_attribute_message(
    builtin: wrela_hir::BuiltinAttribute,
) -> &'static str {
    match builtin {
        wrela_hir::BuiltinAttribute::IsrSafe => {
            "built-in attribute `@isr_safe` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::ReceiptHandoff => {
            "built-in attribute `@receipt_handoff` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Dma => {
            "built-in attribute `@dma` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Wire => {
            "built-in attribute `@wire` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Mmio => {
            "built-in attribute `@mmio` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Offset => {
            "built-in attribute `@offset` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::LayoutAssert => {
            "built-in attribute `@layout_assert` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::SuspendSafe => {
            "built-in attribute `@suspend_safe` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::NoPromote => {
            "built-in attribute `@no_promote` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Budget => {
            "built-in attribute `@budget` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Uninterrupted => {
            "built-in attribute `@uninterrupted` is recognized but its semantic contract is not implemented"
        }
        wrela_hir::BuiltinAttribute::Image
        | wrela_hir::BuiltinAttribute::App
        | wrela_hir::BuiltinAttribute::Service
        | wrela_hir::BuiltinAttribute::Driver
        | wrela_hir::BuiltinAttribute::Task
        | wrela_hir::BuiltinAttribute::Test => {
            "implemented built-in attribute cannot produce an unimplemented diagnostic"
        }
    }
}

fn copy_builtin_attribute_diagnostic_text(
    value: &str,
    limit: u64,
) -> Result<String, AnalysisFailure> {
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > limit {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "diagnostic bytes",
            limit,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "diagnostic bytes",
            limit,
        })?;
    output.push_str(value);
    Ok(output)
}

impl SemanticAnalyzer for CanonicalSemanticAnalyzer {
    fn analyze(
        &self,
        request: AnalysisRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AnalysisOutput, AnalysisFailure> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        request
            .build
            .validate()
            .map_err(|error| AnalysisFailure::InvalidBuild(error.to_string()))?;

        let root = analysis_root(&request, is_cancelled)?;
        let mut partial = empty_partial(&request, root)?;
        let census =
            census_builtin_attributes(request.hir.as_program(), request.limits, is_cancelled)?;
        let mut diagnostics = census.diagnostics;
        diagnose_unsupported_initializers(&request, &mut diagnostics, is_cancelled)?;
        if !diagnostics.is_empty() {
            check_cancelled(is_cancelled)?;
            return finish_analysis(&request, partial, diagnostics, is_cancelled);
        }
        diagnostics
            .try_reserve_exact(1)
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "semantic diagnostics",
                limit: u64::from(request.limits.diagnostic_count),
            })?;

        match &request.mode {
            AnalysisMode::Image { name, entry } => {
                let result = ImageEvaluator::new(&request, is_cancelled)?.evaluate(*entry);
                match result {
                    Ok(image) if image.name() == Some(*name) => {
                        if let Some(diagnostic) = populate_evaluated_image(
                            &request,
                            &mut partial,
                            *entry,
                            image,
                            is_cancelled,
                        )? {
                            push_diagnostic(&mut diagnostics, diagnostic, request.limits)?;
                        }
                    }
                    Ok(image) => {
                        let mut diagnostic = Diagnostic::error(
                            Category::IMAGE,
                            image.name_source,
                            "runtime Image name differs from the selected manifest image",
                        );
                        diagnostic.code = Some("semantic-image-name-mismatch".to_owned());
                        diagnostic.help.push(format!(
                            "use the selected manifest image name `{name}` in this Image constructor"
                        ));
                        diagnostics.push(diagnostic);
                    }
                    Err(EvaluationFailure::Diagnostic(diagnostic)) => {
                        diagnostics.push(*diagnostic);
                    }
                    Err(EvaluationFailure::Analysis(error)) => return Err(error),
                }
            }
            AnalysisMode::DiscoverTests {
                image_entry,
                image_name,
                declared_image_tests,
                source_selection,
            } => {
                if evaluate_and_populate_declared_image(
                    &request,
                    &mut partial,
                    *image_entry,
                    image_name,
                    &mut diagnostics,
                    is_cancelled,
                )? {
                    discover_tests(
                        &request,
                        &mut partial,
                        declared_image_tests,
                        *source_selection,
                        &mut diagnostics,
                        is_cancelled,
                    )?;
                }
            }
            AnalysisMode::CompileTestGroup {
                plan,
                group,
                declared_entry,
            } => {
                let record = plan.group(*group).ok_or(AnalysisFailure::RequestMismatch)?;
                partial.compiled_test_group = Some(record.clone());
                match (&record.root, declared_entry) {
                    (ImageRoot::GeneratedHarness { .. }, None) => compile_generated_test_group(
                        &request,
                        &mut partial,
                        plan,
                        *group,
                        &mut diagnostics,
                        is_cancelled,
                    )?,
                    (ImageRoot::Declared { image_name, .. }, Some(entry)) => {
                        let _ = evaluate_and_populate_declared_image(
                            &request,
                            &mut partial,
                            *entry,
                            image_name,
                            &mut diagnostics,
                            is_cancelled,
                        )?;
                    }
                    _ => return Err(AnalysisFailure::RequestMismatch),
                }
            }
        }

        cancellable_stable_sort_owned_by(
            &mut partial.expressions,
            u64::from(request.limits.expression_facts),
            "expression fact sort scratch",
            is_cancelled,
            &|left, right| {
                Ok((left.function, left.expression).cmp(&(right.function, right.expression)))
            },
        )?;
        cancellable_stable_sort_owned_by(
            &mut partial.statements,
            u64::from(request.limits.statement_facts),
            "statement fact sort scratch",
            is_cancelled,
            &|left, right| {
                Ok((left.function, left.statement).cmp(&(right.function, right.statement)))
            },
        )?;
        finish_analysis(&request, partial, diagnostics, is_cancelled)
    }
}

fn analysis_root(
    request: &AnalysisRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisRoot, AnalysisFailure> {
    match &request.mode {
        AnalysisMode::Image { name, entry } => Ok(AnalysisRoot::DeclaredImage {
            image_name: copy_analysis_text(name, request.limits.fact_bytes, is_cancelled)?,
            declaration: *entry,
            test_group: None,
        }),
        AnalysisMode::DiscoverTests {
            image_name,
            image_entry,
            ..
        } => Ok(AnalysisRoot::DeclaredImage {
            image_name: copy_analysis_text(image_name, request.limits.fact_bytes, is_cancelled)?,
            declaration: *image_entry,
            test_group: None,
        }),
        AnalysisMode::CompileTestGroup {
            plan,
            group,
            declared_entry,
        } => {
            let record = plan.group(*group).ok_or(AnalysisFailure::RequestMismatch)?;
            match (&record.root, declared_entry) {
                (TestImageRoot::GeneratedHarness { harness_name }, None) => {
                    Ok(AnalysisRoot::GeneratedTestHarness {
                        group: *group,
                        harness_name: copy_analysis_text(
                            harness_name,
                            request.limits.fact_bytes,
                            is_cancelled,
                        )?,
                    })
                }
                (TestImageRoot::Declared { image_name, .. }, Some(declaration)) => {
                    Ok(AnalysisRoot::DeclaredImage {
                        image_name: copy_analysis_text(
                            image_name,
                            request.limits.fact_bytes,
                            is_cancelled,
                        )?,
                        declaration: *declaration,
                        test_group: Some(*group),
                    })
                }
                _ => Err(AnalysisFailure::RequestMismatch),
            }
        }
    }
}

fn copy_static_analysis_text(value: &str, limit: u64) -> Result<String, AnalysisFailure> {
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > limit {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        })?;
    output.push_str(value);
    Ok(output)
}

fn copy_analysis_text(
    value: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > limit {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        })?;
    append_polled_test_text(&mut output, value, is_cancelled)?;
    Ok(output)
}

fn empty_partial(
    request: &AnalysisRequest<'_>,
    root: AnalysisRoot,
) -> Result<PartialAnalysis, AnalysisFailure> {
    Ok(PartialAnalysis {
        hir: HirSummary::from_validated(request.hir.as_ref())?,
        build: request.build.identity.clone(),
        target_digest: request.target.content_digest(),
        root,
        types: Vec::new(),
        functions: Vec::new(),
        values: Vec::new(),
        expressions: Vec::new(),
        statements: Vec::new(),
        scope_protocols: Vec::new(),
        scope_activations: Vec::new(),
        graph: None,
        proofs: Vec::new(),
        baked_artifacts: Vec::new(),
        test_plan: None,
        comptime_test_results: Vec::new(),
        compiled_test_group: None,
    })
}

fn evaluate_and_populate_declared_image(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    entry: DeclarationId,
    expected_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let result = ImageEvaluator::new(request, is_cancelled)?.evaluate(entry);
    match result {
        Ok(image) if image.name() == Some(expected_name) => {
            if let Some(diagnostic) =
                populate_evaluated_image(request, partial, entry, image, is_cancelled)?
            {
                push_diagnostic(diagnostics, diagnostic, request.limits)?;
                Ok(false)
            } else {
                Ok(true)
            }
        }
        Ok(image) => {
            let mut diagnostic = Diagnostic::error(
                Category::IMAGE,
                image.name_source,
                "runtime Image name differs from the selected manifest image",
            );
            diagnostic.code = Some("semantic-image-name-mismatch".to_owned());
            diagnostic.help.push(format!(
                "use the selected manifest image name `{expected_name}` in this Image constructor"
            ));
            push_diagnostic(diagnostics, diagnostic, request.limits)?;
            Ok(false)
        }
        Err(EvaluationFailure::Diagnostic(diagnostic)) => {
            push_diagnostic(diagnostics, *diagnostic, request.limits)?;
            Ok(false)
        }
        Err(EvaluationFailure::Analysis(error)) => Err(error),
    }
}

fn push_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    diagnostic: Diagnostic,
    limits: AnalysisLimits,
) -> Result<(), AnalysisFailure> {
    if diagnostics.len() >= limits.diagnostic_count as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic diagnostics",
            limit: u64::from(limits.diagnostic_count),
        });
    }
    diagnostics
        .try_reserve(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic diagnostics",
            limit: u64::from(limits.diagnostic_count),
        })?;
    diagnostics.push(diagnostic);
    Ok(())
}

fn diagnose_unsupported_initializers(
    request: &AnalysisRequest<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    for declaration in &request.hir.as_program().declarations {
        check_cancelled(is_cancelled)?;
        if matches!(&declaration.kind, DeclarationKind::Initializer(_)) {
            let mut diagnostic = Diagnostic::error(
                Category::TYPE,
                declaration.source,
                "class initializers are not yet executable by semantic analysis",
            );
            diagnostic.code = Some("semantic-initializer-not-supported".to_owned());
            diagnostic.notes.push(
                "the dedicated initializer HIR is rejected before function, actor-message, and WIR production"
                    .to_owned(),
            );
            diagnostic.help.push(
                "remove the initializer until class construction semantics are implemented"
                    .to_owned(),
            );
            push_diagnostic(diagnostics, diagnostic, request.limits)?;
        }
    }
    Ok(())
}

fn test_plan_limits(limits: AnalysisLimits) -> TestPlanLimits {
    TestPlanLimits {
        tests: limits.tests,
        groups: limits.test_groups,
        scenarios: limits.test_scenarios,
        scenario_steps: limits.test_scenario_steps,
        payload_bytes: limits.test_bytes,
        report_bytes: limits.test_report_bytes,
        events_per_group: limits.test_events_per_group,
        output_bytes_per_group: limits.test_output_bytes_per_group,
        execution_timeout_ns_per_group: limits.test_timeout_ns_per_group,
    }
}

fn source_test_key(request: &AnalysisRequest<'_>, declaration: DeclarationId) -> FunctionKey {
    let mut bytes = *request.build.identity.request.as_bytes();
    // The request digest already binds the complete source graph, build
    // profile, test selection, and order. This fixed-width domain tweak is
    // injective for declaration IDs within that cryptographic identity and is
    // stable across discovery and per-group compilation.
    bytes[0] ^= 0x53;
    for (destination, source) in bytes[24..28].iter_mut().zip(declaration.0.to_be_bytes()) {
        *destination ^= source;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 0x53;
    }
    FunctionKey(wrela_build_model::Sha256Digest::from_bytes(bytes))
}

fn generated_harness_key(request: &AnalysisRequest<'_>, group: ImageGroupId) -> FunctionKey {
    let mut bytes = *request.build.identity.request.as_bytes();
    bytes[0] ^= 0x48;
    for (destination, source) in bytes[24..28].iter_mut().zip(group.0.to_be_bytes()) {
        *destination ^= source;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 0x48;
    }
    FunctionKey(wrela_build_model::Sha256Digest::from_bytes(bytes))
}

fn copy_test_name(
    request: &AnalysisRequest<'_>,
    declaration: DeclarationId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let program = request.hir.as_program();
    let declaration = program
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let module = program
        .modules
        .get(declaration.module.0 as usize)
        .filter(|module| module.id == declaration.module)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let package = program
        .packages
        .package(module.package)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let local_name = declaration
        .name
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?
        .as_str();
    let mut module_bytes = 0usize;
    for (index, segment) in module.path.segments().iter().enumerate() {
        check_cancelled(is_cancelled)?;
        module_bytes = module_bytes
            .checked_add(usize::from(index != 0))
            .and_then(|bytes| bytes.checked_add(segment.len()))
            .ok_or_else(|| test_resource_failure(request))?;
    }
    let length = package
        .identity
        .name
        .as_str()
        .len()
        .checked_add(package.identity.version.as_str().len())
        .and_then(|total| total.checked_add(module_bytes))
        .and_then(|total| total.checked_add(local_name.len()))
        .and_then(|total| total.checked_add(5))
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        })?;
    if u64::try_from(length).unwrap_or(u64::MAX) > request.limits.test_bytes {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        })?;
    append_polled_test_text(&mut output, package.identity.name.as_str(), is_cancelled)?;
    output.push('@');
    append_polled_test_text(&mut output, package.identity.version.as_str(), is_cancelled)?;
    output.push_str("::");
    for (index, segment) in module.path.segments().iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if index != 0 {
            output.push('.');
        }
        append_polled_test_text(&mut output, segment, is_cancelled)?;
    }
    output.push_str("::");
    append_polled_test_text(&mut output, local_name, is_cancelled)?;
    if output.len() != length {
        return Err(AnalysisFailure::RequestMismatch);
    }
    Ok(output)
}

fn append_polled_test_text(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let mut start = 0;
    while start < value.len() {
        check_cancelled(is_cancelled)?;
        let mut end = start
            .checked_add(COMPTIME_SOURCE_COPY_CHUNK_BYTES)
            .unwrap_or(value.len())
            .min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(AnalysisFailure::RequestMismatch);
        }
        output.push_str(&value[start..end]);
        start = end;
    }
    Ok(())
}

#[derive(Debug)]
struct SupportedSourceTest {
    declaration: DeclarationId,
    body: BodyId,
    color: FunctionColor,
    key: FunctionKey,
    name: String,
    source: Span,
    checked_comptime: Option<CheckedComptimeClosure>,
    runtime_statements: Vec<StatementId>,
    assertions: Vec<PlannedAssertionDescriptor>,
    work_bound: u64,
}

#[derive(Debug)]
struct PendingImageTest {
    name: String,
    kind: TestKind,
    source: Option<Span>,
    timeout_ns: u64,
    invocation: ImageTestInvocation,
    assertions: Vec<PlannedAssertionDescriptor>,
}

#[derive(Debug)]
struct PendingImageGroup {
    name: String,
    root: ImageRoot,
    tests: Vec<PendingImageTest>,
    deterministic_seed: Option<u64>,
    boot_timeout_ns: u64,
    shutdown_timeout_ns: u64,
    maximum_events: u32,
    maximum_output_bytes: u64,
}

fn discover_tests(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    declared_image_tests: &[DeclaredImageTest],
    source_selection: TestDiscoverySelection<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let program = request.hir.as_program();
    let source_count = program.test_candidates.len();
    let total_count = source_count.checked_add(declared_image_tests.len()).ok_or(
        AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        },
    )?;
    if total_count > request.limits.tests as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit: request.limits.test_bytes,
        });
    }

    let mut unit_tests = Vec::new();
    let mut comptime_results = Vec::new();
    let mut runtime_tests = Vec::new();
    unit_tests
        .try_reserve_exact(source_count)
        .map_err(|_| test_resource_failure(request))?;
    comptime_results
        .try_reserve_exact(source_count)
        .map_err(|_| test_resource_failure(request))?;
    runtime_tests
        .try_reserve_exact(source_count)
        .map_err(|_| test_resource_failure(request))?;

    let initial_diagnostic_count = diagnostics.len();
    let mut runtime_aggregate_work = RuntimeAggregateWork::default();
    for candidate in &program.test_candidates {
        check_cancelled(is_cancelled)?;
        if !source_test_selected(request, *candidate, source_selection, is_cancelled)? {
            continue;
        }
        let supported = match inspect_source_test(request, *candidate, is_cancelled)? {
            Ok(test) => test,
            Err(diagnostic) => {
                push_diagnostic(diagnostics, diagnostic, request.limits)?;
                continue;
            }
        };
        match append_source_test_function(
            request,
            partial,
            &supported,
            &mut runtime_aggregate_work,
            is_cancelled,
        )? {
            Ok(_) => {}
            Err(diagnostic) => {
                push_diagnostic(diagnostics, diagnostic, request.limits)?;
                continue;
            }
        }
        let descriptor = TestDescriptor {
            id: TestId(
                u32::try_from(unit_tests.len()).map_err(|_| test_resource_failure(request))?,
            ),
            name: copy_bounded_test_text(request, &supported.name, is_cancelled)?,
            kind: TestKind::ComptimeUnit,
            source: Some(supported.source),
            timeout_ns: COMPTIME_TEST_TIMEOUT_NS,
        };
        match supported.color {
            FunctionColor::Comptime => {
                let result_descriptor = TestDescriptor {
                    id: TestId(descriptor.id.0),
                    name: copy_bounded_test_text(request, &descriptor.name, is_cancelled)?,
                    kind: TestKind::ComptimeUnit,
                    source: descriptor.source,
                    timeout_ns: descriptor.timeout_ns,
                };
                match evaluate_comptime_test(request, &supported, result_descriptor, is_cancelled)?
                {
                    ComptimeCase::Result(result) => {
                        unit_tests.push(ComptimeTest {
                            descriptor,
                            function_key: supported.key,
                        });
                        comptime_results.push(result);
                    }
                    ComptimeCase::Unsupported(diagnostic) => {
                        push_diagnostic(diagnostics, diagnostic, request.limits)?;
                    }
                }
            }
            FunctionColor::Sync | FunctionColor::Async => {
                runtime_tests.push(PendingImageTest {
                    name: supported.name,
                    kind: TestKind::IntegrationImage,
                    source: Some(supported.source),
                    timeout_ns: INTEGRATION_TEST_TIMEOUT_NS,
                    invocation: ImageTestInvocation::GeneratedFunction {
                        function_key: supported.key,
                    },
                    assertions: supported.assertions,
                });
            }
            FunctionColor::Isr => return Err(AnalysisFailure::RequestMismatch),
        }
    }

    if diagnostics.len() != initial_diagnostic_count {
        return Ok(());
    }
    if runtime_tests.len() != 1
        && let Some(asserting) = runtime_tests
            .iter()
            .find(|test| !test.assertions.is_empty())
    {
        let mut diagnostic = Diagnostic::error(
            Category::COMPTIME,
            asserting.source.unwrap_or_else(|| fallback_span(program)),
            "runtime assertions require exactly one selected generated source test",
        );
        diagnostic.code = Some("semantic-runtime-assertion-selection".to_owned());
        diagnostic.help.push(
            "select the asserting test alone so assertion failure can terminate with a complete canonical report"
                .to_owned(),
        );
        push_diagnostic(diagnostics, diagnostic, request.limits)?;
        return Ok(());
    }

    let mut scenarios = canonical_declared_scenarios(request, declared_image_tests, is_cancelled)?;
    let mut groups = Vec::new();
    let group_capacity = declared_image_tests
        .len()
        .checked_add(usize::from(!runtime_tests.is_empty()))
        .ok_or_else(|| test_resource_failure(request))?;
    if group_capacity > request.limits.test_groups as usize {
        return Err(test_resource_failure(request));
    }
    groups
        .try_reserve_exact(group_capacity)
        .map_err(|_| test_resource_failure(request))?;
    if !runtime_tests.is_empty() {
        if declared_image_tests
            .iter()
            .any(|test| test.name == GENERATED_GROUP_NAME)
        {
            let mut diagnostic = Diagnostic::error(
                Category::COMPTIME,
                fallback_span(program),
                "manifest image-test name collides with the compiler-generated integration group",
            );
            diagnostic.code = Some("semantic-test-group-name-reserved".to_owned());
            diagnostic.help.push(format!(
                "rename the manifest image test `{GENERATED_GROUP_NAME}`"
            ));
            push_diagnostic(diagnostics, diagnostic, request.limits)?;
            return Ok(());
        }
        let generated_events = u32::try_from(runtime_tests.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| count.checked_add(3))
            .ok_or_else(|| test_resource_failure(request))?;
        let generated_timeout = GENERATED_BOOT_TIMEOUT_NS
            .checked_add(GENERATED_SHUTDOWN_TIMEOUT_NS)
            .and_then(|value| {
                value.checked_add(
                    INTEGRATION_TEST_TIMEOUT_NS
                        .checked_mul(u64::try_from(runtime_tests.len()).ok()?)?,
                )
            })
            .ok_or_else(|| test_resource_failure(request))?;
        if generated_timeout > request.limits.test_timeout_ns_per_group
            || generated_events > request.limits.test_events_per_group
            || GENERATED_MAXIMUM_OUTPUT_BYTES > request.limits.test_output_bytes_per_group
        {
            return Err(test_resource_failure(request));
        }
        groups.push(PendingImageGroup {
            name: copy_bounded_test_text(request, GENERATED_GROUP_NAME, is_cancelled)?,
            root: ImageRoot::GeneratedHarness {
                harness_name: copy_bounded_test_text(
                    request,
                    GENERATED_HARNESS_NAME,
                    is_cancelled,
                )?,
            },
            tests: runtime_tests,
            deterministic_seed: None,
            boot_timeout_ns: GENERATED_BOOT_TIMEOUT_NS,
            shutdown_timeout_ns: GENERATED_SHUTDOWN_TIMEOUT_NS,
            maximum_events: generated_events,
            maximum_output_bytes: GENERATED_MAXIMUM_OUTPUT_BYTES,
        });
    }
    for declared in declared_image_tests {
        check_cancelled(is_cancelled)?;
        let scenario = scenarios
            .get(declared.scenario.id.0 as usize)
            .filter(|scenario| **scenario == declared.scenario)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let timeout_ns = declared
            .boot_timeout_ns
            .checked_add(declared.shutdown_timeout_ns)
            .and_then(|value| value.checked_add(scenario.wait_budget_ns()?))
            .ok_or_else(|| test_resource_failure(request))?;
        if timeout_ns > request.limits.test_timeout_ns_per_group
            || declared.maximum_events > request.limits.test_events_per_group
            || declared.maximum_output_bytes > request.limits.test_output_bytes_per_group
        {
            return Err(test_resource_failure(request));
        }
        groups.push(PendingImageGroup {
            name: copy_bounded_test_text(request, &declared.name, is_cancelled)?,
            root: ImageRoot::Declared {
                image_name: copy_bounded_test_text(request, &declared.image_name, is_cancelled)?,
                scenario: declared.scenario.id,
            },
            tests: vec![PendingImageTest {
                name: copy_bounded_test_text(request, &declared.name, is_cancelled)?,
                kind: TestKind::DeclaredImage,
                source: None,
                timeout_ns,
                invocation: ImageTestInvocation::DeclaredScenario,
                assertions: Vec::new(),
            }],
            deterministic_seed: declared.deterministic_seed,
            boot_timeout_ns: declared.boot_timeout_ns,
            shutdown_timeout_ns: declared.shutdown_timeout_ns,
            maximum_events: declared.maximum_events,
            maximum_output_bytes: declared.maximum_output_bytes,
        });
    }
    cancellable_stable_sort_owned_by(
        &mut groups,
        u64::from(request.limits.test_groups),
        "test group sort scratch",
        is_cancelled,
        &|left, right| cancellable_str_cmp(&left.name, &right.name, is_cancelled),
    )?;
    for pair in groups.windows(2) {
        if cancellable_str_cmp(&pair[0].name, &pair[1].name, is_cancelled)?
            == std::cmp::Ordering::Equal
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
    }

    let mut next_test =
        u32::try_from(unit_tests.len()).map_err(|_| test_resource_failure(request))?;
    let mut image_groups = Vec::new();
    image_groups
        .try_reserve_exact(groups.len())
        .map_err(|_| test_resource_failure(request))?;
    for (group_index, pending) in groups.into_iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let mut tests = Vec::new();
        tests
            .try_reserve_exact(pending.tests.len())
            .map_err(|_| test_resource_failure(request))?;
        for test in pending.tests {
            let id = TestId(next_test);
            next_test = next_test
                .checked_add(1)
                .ok_or_else(|| test_resource_failure(request))?;
            tests.push(ImageTest {
                descriptor: TestDescriptor {
                    id,
                    name: test.name,
                    kind: test.kind,
                    source: test.source,
                    timeout_ns: test.timeout_ns,
                },
                invocation: test.invocation,
                assertions: test.assertions,
            });
        }
        image_groups.push(FullImageTestGroup {
            id: ImageGroupId(
                u32::try_from(group_index).map_err(|_| test_resource_failure(request))?,
            ),
            name: pending.name,
            root: pending.root,
            tests,
            deterministic_seed: pending.deterministic_seed,
            boot_timeout_ns: pending.boot_timeout_ns,
            shutdown_timeout_ns: pending.shutdown_timeout_ns,
            maximum_events: pending.maximum_events,
            maximum_output_bytes: pending.maximum_output_bytes,
        });
    }
    let plan = TestPlan {
        schema: TEST_PLAN_SCHEMA,
        build: request.build.identity.clone(),
        target: request.target.identity().clone(),
        scenarios: std::mem::take(&mut scenarios),
        unit_tests,
        image_groups,
    }
    .seal_with_limits_and_cancellation(test_plan_limits(request.limits), is_cancelled)
    .map_err(|error| match error {
        wrela_test_model::TestModelError::ResourceLimit { .. }
        | wrela_test_model::TestModelError::TooManyTests(_) => test_resource_failure(request),
        wrela_test_model::TestModelError::Cancelled => AnalysisFailure::Cancelled,
        error => AnalysisFailure::InternalInvariant(format!(
            "canonical test discovery produced an invalid plan: {error}"
        )),
    })?;
    partial.test_plan = Some(plan);
    partial.comptime_test_results = comptime_results;
    Ok(())
}

fn source_test_selected(
    request: &AnalysisRequest<'_>,
    declaration: DeclarationId,
    selection: TestDiscoverySelection<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    let program = request.hir.as_program();
    let declaration_record = program
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let module = program
        .modules
        .get(declaration_record.module.0 as usize)
        .filter(|module| module.id == declaration_record.module)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if module.package != program.packages.root() {
        return Ok(false);
    }
    let function = match &declaration_record.kind {
        DeclarationKind::Function(function) => Some(function),
        _ => None,
    }
    .ok_or(AnalysisFailure::RequestMismatch)?;
    Ok(match selection {
        TestDiscoverySelection::All => true,
        TestDiscoverySelection::Comptime => function.color == FunctionColor::Comptime,
        TestDiscoverySelection::Integration => {
            matches!(function.color, FunctionColor::Sync | FunctionColor::Async)
        }
        TestDiscoverySelection::None => false,
        TestDiscoverySelection::NameContains(filter) => bounded_name_contains(
            &copy_test_name(request, declaration, is_cancelled)?,
            filter,
            is_cancelled,
        )?,
    })
}

fn bounded_name_contains(
    value: &str,
    filter: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    if filter.is_empty() || filter.len() > MAX_TEST_FILTER_BYTES {
        return Err(AnalysisFailure::RequestMismatch);
    }
    if filter.len() > value.len() {
        return Ok(false);
    }

    // Knuth-Morris-Pratt keeps the public substring selection linear even for
    // adversarial repeated prefixes. The only scratch is one bounded entry per
    // filter byte, and every construction/search transition polls cancellation.
    let needle = filter.as_bytes();
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(needle.len())
        .map_err(|_| test_resource_failure_for_limit(MAX_TEST_FILTER_BYTES as u64))?;
    prefix.push(0usize);
    let mut matched = 0usize;
    for index in 1..needle.len() {
        check_cancelled(is_cancelled)?;
        while matched != 0 && needle[index] != needle[matched] {
            check_cancelled(is_cancelled)?;
            matched = prefix[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
        }
        prefix.push(matched);
    }

    matched = 0;
    for byte in value.bytes() {
        check_cancelled(is_cancelled)?;
        while matched != 0 && byte != needle[matched] {
            check_cancelled(is_cancelled)?;
            matched = prefix[matched - 1];
        }
        if byte == needle[matched] {
            matched += 1;
            if matched == needle.len() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn test_resource_failure_for_limit(limit: u64) -> AnalysisFailure {
    AnalysisFailure::ResourceLimit {
        resource: "test name filter",
        limit,
    }
}

fn test_resource_failure(request: &AnalysisRequest<'_>) -> AnalysisFailure {
    AnalysisFailure::ResourceLimit {
        resource: "test plan or results",
        limit: request.limits.test_bytes,
    }
}

fn copy_bounded_test_text(
    request: &AnalysisRequest<'_>,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > request.limits.test_bytes {
        return Err(test_resource_failure(request));
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| test_resource_failure(request))?;
    append_polled_test_text(&mut output, value, is_cancelled)?;
    Ok(output)
}

fn canonical_declared_scenarios(
    request: &AnalysisRequest<'_>,
    declared: &[DeclaredImageTest],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ImageScenario>, AnalysisFailure> {
    let mut unique = std::collections::HashMap::new();
    unique
        .try_reserve(declared.len())
        .map_err(|_| test_resource_failure(request))?;
    let mut scenarios = Vec::new();
    scenarios
        .try_reserve_exact(declared.len())
        .map_err(|_| test_resource_failure(request))?;
    let mut steps = 0usize;
    let mut payload = 0u64;
    for test in declared {
        let scenario = &test.scenario;
        steps = steps
            .checked_add(scenario.steps.len())
            .ok_or_else(|| test_resource_failure(request))?;
        for length in [
            test.name.len(),
            test.image_name.len(),
            scenario.name.len(),
            scenario.source_path.len(),
        ] {
            payload = payload
                .checked_add(u64::try_from(length).map_err(|_| test_resource_failure(request))?)
                .ok_or_else(|| test_resource_failure(request))?;
        }
        for step in &scenario.steps {
            let length = match step {
                wrela_test_model::ImageScenarioStep::SendSerial { bytes }
                | wrela_test_model::ImageScenarioStep::ExpectSerial { bytes, .. } => bytes.len(),
                wrela_test_model::ImageScenarioStep::ExpectTestEvent {
                    message_contains, ..
                } => message_contains.as_ref().map_or(0, String::len),
                wrela_test_model::ImageScenarioStep::ExpectExit { .. }
                | wrela_test_model::ImageScenarioStep::RequestShutdown { .. } => 0,
            };
            payload = payload
                .checked_add(u64::try_from(length).map_err(|_| test_resource_failure(request))?)
                .ok_or_else(|| test_resource_failure(request))?;
        }
        if steps > request.limits.test_scenario_steps as usize
            || payload > request.limits.test_bytes
        {
            return Err(test_resource_failure(request));
        }
        match unique.get(&scenario.id.0).copied() {
            Some(index) => {
                if scenarios.get(index) != Some(scenario) {
                    return Err(AnalysisFailure::RequestMismatch);
                }
            }
            None => {
                unique.insert(scenario.id.0, scenarios.len());
                scenarios.push(scenario.clone());
            }
        }
    }
    cancellable_stable_sort_owned_by(
        &mut scenarios,
        u64::from(request.limits.test_scenarios),
        "test scenario sort scratch",
        is_cancelled,
        &|left, right| Ok(left.id.cmp(&right.id)),
    )?;
    if scenarios.len() > request.limits.test_scenarios as usize {
        return Err(AnalysisFailure::RequestMismatch);
    }
    for (expected, scenario) in scenarios.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if scenario.id.0 as usize != expected {
            return Err(AnalysisFailure::RequestMismatch);
        }
    }
    for pair in scenarios.windows(2) {
        if cancellable_str_cmp(&pair[0].name, &pair[1].name, is_cancelled)?
            != std::cmp::Ordering::Less
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
    }
    Ok(scenarios)
}

fn inspect_source_test(
    request: &AnalysisRequest<'_>,
    id: DeclarationId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Result<SupportedSourceTest, Diagnostic>, AnalysisFailure> {
    let program = request.hir.as_program();
    let declaration = program
        .declaration(id)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Function(function) = &declaration.kind else {
        return Err(AnalysisFailure::RequestMismatch);
    };
    if !function.generics.is_empty() || !function.parameters.is_empty() {
        return Err(AnalysisFailure::RequestMismatch);
    }
    if !test_result_is_unit(function.result.as_ref()) {
        return Ok(Err(test_source_diagnostic(
            declaration.source,
            "semantic-test-result-not-supported",
            "revision 0.1 tests in the production semantic subset must return unit",
        )));
    }
    let Some(body_id) = function.body else {
        return Ok(Err(test_source_diagnostic(
            declaration.source,
            "semantic-test-body-missing",
            "a test function must have a body",
        )));
    };
    let _body = program
        .body(body_id)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let checked_comptime = if function.color == FunctionColor::Comptime {
        match check_source_comptime_unit_test(
            request.hir.as_ref(),
            request.target.pointer_width(),
            id,
            ComptimeCheckLimits {
                work_units: request.limits.fact_edges,
                storage_entries: request.limits.fact_edges,
                syntax_depth: request.limits.constant_depth.min(COMPTIME_SYNTAX_DEPTH),
                diagnostic_bytes: request.limits.diagnostic_bytes,
                test_bytes: request.limits.test_bytes,
            },
            is_cancelled,
        )? {
            Ok(checked) => Some(checked),
            Err(diagnostic) => return Ok(Err(diagnostic)),
        }
    } else {
        None
    };
    let mut runtime_statements = Vec::new();
    let mut runtime_callees = Vec::new();
    if function.color != FunctionColor::Comptime {
        match inspect_runtime_body_shape(
            request,
            body_id,
            function.color,
            true,
            &mut runtime_statements,
            &mut runtime_callees,
            is_cancelled,
        ) {
            Ok(()) => {}
            Err(RuntimeShapeFailure::Unsupported(source)) => {
                return Ok(Err(test_source_diagnostic(
                    source,
                    "semantic-runtime-test-body-not-supported",
                    "runtime bodies support scalar initialization and assignment, direct calls, return, and scalar `if` joins",
                )));
            }
            Err(RuntimeShapeFailure::UnsupportedAssertion(source)) => {
                return Ok(Err(test_source_diagnostic(
                    source,
                    "semantic-runtime-assertion-not-supported",
                    "runtime assertions are supported only in selected generated tests",
                )));
            }
            Err(RuntimeShapeFailure::Failure(error)) => return Err(error),
        }
        let mut seen_declarations = vec![false; program.declarations.len()];
        if let Some(slot) = seen_declarations.get_mut(id.0 as usize) {
            *slot = true;
        }
        while let Some(callee) = runtime_callees.pop() {
            check_cancelled(is_cancelled)?;
            let Some(seen) = seen_declarations.get_mut(callee.0 as usize) else {
                return Err(AnalysisFailure::RequestMismatch);
            };
            if *seen {
                continue;
            }
            *seen = true;
            let declaration = program
                .declaration(callee)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            let DeclarationKind::Function(helper) = &declaration.kind else {
                continue;
            };
            let Some(helper_body) = helper.body else {
                continue;
            };
            inspect_runtime_body_shape(
                request,
                helper_body,
                helper.color,
                true,
                &mut runtime_statements,
                &mut runtime_callees,
                is_cancelled,
            )
            .map_err(|failure| match failure {
                RuntimeShapeFailure::Failure(error) => error,
                RuntimeShapeFailure::Unsupported(_)
                | RuntimeShapeFailure::UnsupportedAssertion(_) => AnalysisFailure::RequestMismatch,
            })?;
        }
    }
    let work_bound = u64::try_from(runtime_statements.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| test_resource_failure(request))?;
    let mut assertions = Vec::new();
    for statement in &runtime_statements {
        check_cancelled(is_cancelled)?;
        if let Some(wrela_hir::Statement {
            kind:
                StatementKind::Assert {
                    expression,
                    witness,
                    message,
                    comptime: false,
                    ..
                },
            ..
        }) = program.statement(*statement)
        {
            if expression.len() > MAX_RUNTIME_ASSERTION_EXPRESSION_BYTES
                || expression.chars().all(char::is_whitespace)
            {
                return Ok(Err(test_source_diagnostic(
                    witness.source,
                    "semantic-runtime-assertion-expression-limit",
                    "runtime assertion condition source exceeds its bounded report payload",
                )));
            }
            if message.as_ref().is_some_and(|message| {
                message.len() > MAX_RUNTIME_ASSERTION_EXPRESSION_BYTES
                    || message.chars().all(char::is_whitespace)
            }) {
                return Ok(Err(test_source_diagnostic(
                    witness.source,
                    "semantic-runtime-assertion-message-limit",
                    "runtime assertion message is empty or exceeds its bounded report payload",
                )));
            }
            assertions.push(PlannedAssertionDescriptor {
                source: witness.source,
                expression: copy_bounded_test_text(request, expression, is_cancelled)?,
                message: match message {
                    Some(message) => Some(copy_bounded_test_text(request, message, is_cancelled)?),
                    None => None,
                },
            });
        }
    }
    cancellable_stable_sort_owned_by(
        &mut assertions,
        u64::from(request.limits.statement_facts),
        "runtime assertion descriptor sort scratch",
        is_cancelled,
        &|left, right| {
            check_cancelled(is_cancelled)?;
            let ordering = (
                left.source.file.0,
                left.source.range.start,
                left.source.range.end,
            )
                .cmp(&(
                    right.source.file.0,
                    right.source.range.start,
                    right.source.range.end,
                ))
                .then_with(|| left.expression.cmp(&right.expression));
            check_cancelled(is_cancelled)?;
            Ok(ordering.then_with(|| left.message.cmp(&right.message)))
        },
    )?;
    if assertions.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AnalysisFailure::RequestMismatch);
    }
    Ok(Ok(SupportedSourceTest {
        declaration: id,
        body: body_id,
        color: function.color,
        key: source_test_key(request, id),
        name: copy_test_name(request, id, is_cancelled)?,
        source: declaration.source,
        checked_comptime,
        runtime_statements,
        assertions,
        work_bound,
    }))
}

enum RuntimeShapeFailure {
    Unsupported(Span),
    UnsupportedAssertion(Span),
    Failure(AnalysisFailure),
}

fn inspect_runtime_body_shape(
    request: &AnalysisRequest<'_>,
    root: BodyId,
    color: FunctionColor,
    allow_assertions: bool,
    statements: &mut Vec<StatementId>,
    callees: &mut Vec<DeclarationId>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), RuntimeShapeFailure> {
    let program = request.hir.as_program();
    let mut bodies = Vec::new();
    reserve_runtime_shape(
        &mut bodies,
        1,
        request.limits.fact_edges,
        "runtime body scratch",
    )?;
    bodies.push(root);
    let mut visited_bodies = 0u64;
    while let Some(body_id) = bodies.pop() {
        check_cancelled(is_cancelled).map_err(RuntimeShapeFailure::Failure)?;
        visited_bodies = visited_bodies.checked_add(1).ok_or({
            RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit {
                resource: "runtime body traversal",
                limit: request.limits.fact_edges,
            })
        })?;
        if visited_bodies > request.limits.fact_edges
            || usize::try_from(visited_bodies).map_or(true, |count| count > program.bodies.len())
        {
            return Err(RuntimeShapeFailure::Failure(
                AnalysisFailure::ResourceLimit {
                    resource: "runtime body traversal",
                    limit: request.limits.fact_edges,
                },
            ));
        }
        let body = program
            .body(body_id)
            .ok_or_else(|| RuntimeShapeFailure::Unsupported(fallback_span(program)))?;
        reserve_runtime_shape(
            statements,
            body.statements.len(),
            u64::from(request.limits.statement_facts),
            "statement facts",
        )?;
        let mut returned = false;
        for statement_id in &body.statements {
            check_cancelled(is_cancelled).map_err(RuntimeShapeFailure::Failure)?;
            let statement = program
                .statement(*statement_id)
                .ok_or(RuntimeShapeFailure::Unsupported(body.source))?;
            if !statement.attributes.is_empty() || returned {
                return Err(RuntimeShapeFailure::Unsupported(statement.source));
            }
            match &statement.kind {
                StatementKind::Pass => {}
                StatementKind::Return(value) => {
                    if let Some(expression) = value {
                        inspect_runtime_expression_shape(
                            request,
                            *expression,
                            color,
                            callees,
                            is_cancelled,
                        )?;
                    }
                    returned = true;
                }
                StatementKind::Initialize { value, .. }
                | StatementKind::Assign { value, .. }
                | StatementKind::Expression(value)
                | StatementKind::Send(value) => {
                    inspect_runtime_expression_shape(
                        request,
                        *value,
                        color,
                        callees,
                        is_cancelled,
                    )?;
                }
                StatementKind::If {
                    branches,
                    else_body,
                } => {
                    let [(condition, then_body)] = branches.as_slice() else {
                        return Err(RuntimeShapeFailure::Unsupported(statement.source));
                    };
                    inspect_runtime_expression_shape(
                        request,
                        *condition,
                        color,
                        callees,
                        is_cancelled,
                    )?;
                    let reserve = usize::from(else_body.is_some()).checked_add(1).ok_or({
                        RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit {
                            resource: "runtime body scratch",
                            limit: request.limits.fact_edges,
                        })
                    })?;
                    reserve_runtime_shape(
                        &mut bodies,
                        reserve,
                        request.limits.fact_edges,
                        "runtime body scratch",
                    )?;
                    if let Some(otherwise) = else_body {
                        bodies.push(*otherwise);
                    }
                    bodies.push(*then_body);
                }
                StatementKind::Match { scrutinee, arms } => {
                    inspect_runtime_expression_shape(
                        request,
                        *scrutinee,
                        color,
                        callees,
                        is_cancelled,
                    )?;
                    reserve_runtime_shape(
                        &mut bodies,
                        arms.len(),
                        request.limits.fact_edges,
                        "runtime match body scratch",
                    )?;
                    for arm in arms.iter().rev() {
                        if let Some(guard) = arm.guard {
                            inspect_runtime_expression_shape(
                                request,
                                guard,
                                color,
                                callees,
                                is_cancelled,
                            )?;
                        }
                        bodies.push(arm.body);
                    }
                }
                StatementKind::Assert {
                    condition,
                    comptime: false,
                    ..
                } if allow_assertions => {
                    inspect_runtime_expression_shape(
                        request,
                        *condition,
                        color,
                        callees,
                        is_cancelled,
                    )?;
                }
                StatementKind::Assert { .. } => {
                    return Err(RuntimeShapeFailure::UnsupportedAssertion(statement.source));
                }
                StatementKind::Break
                | StatementKind::Continue
                | StatementKind::Yield(_)
                | StatementKind::For { .. }
                | StatementKind::While { .. }
                | StatementKind::Loop { .. }
                | StatementKind::With { .. }
                | StatementKind::ComptimeIf { .. }
                | StatementKind::Error => {
                    return Err(RuntimeShapeFailure::Unsupported(statement.source));
                }
            }
            statements.push(*statement_id);
        }
    }
    cancellable_stable_sort_by(
        statements,
        u64::from(request.limits.statement_facts),
        "runtime statement sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )
    .map_err(RuntimeShapeFailure::Failure)?;
    for pair in statements.windows(2) {
        check_cancelled(is_cancelled).map_err(RuntimeShapeFailure::Failure)?;
        if pair[0] == pair[1] {
            return Err(RuntimeShapeFailure::Unsupported(
                program
                    .body(root)
                    .map_or_else(|| fallback_span(program), |body| body.source),
            ));
        }
    }
    Ok(())
}

fn inspect_runtime_expression_shape(
    request: &AnalysisRequest<'_>,
    root: ExpressionId,
    color: FunctionColor,
    callees: &mut Vec<DeclarationId>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), RuntimeShapeFailure> {
    let program = request.hir.as_program();
    let mut pending = Vec::new();
    let limit = u64::from(request.limits.expression_facts);
    reserve_runtime_shape(&mut pending, 1, limit, "runtime expression scratch")?;
    pending.push(root);
    let mut visited = 0u64;
    while let Some(id) = pending.pop() {
        check_cancelled(is_cancelled).map_err(RuntimeShapeFailure::Failure)?;
        visited = visited.checked_add(1).ok_or({
            RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit {
                resource: "runtime expression traversal",
                limit,
            })
        })?;
        if visited > limit {
            return Err(RuntimeShapeFailure::Failure(
                AnalysisFailure::ResourceLimit {
                    resource: "runtime expression traversal",
                    limit,
                },
            ));
        }
        let expression = program
            .expression(id)
            .ok_or_else(|| RuntimeShapeFailure::Unsupported(fallback_span(program)))?;
        match &expression.kind {
            ExpressionKind::Literal(
                Literal::Unit | Literal::Boolean(_) | Literal::Integer(_) | Literal::Float(_),
            )
            | ExpressionKind::Reference(
                Definition::Local(_)
                | Definition::Parameter(_)
                | Definition::Declaration(_)
                | Definition::Variant(_),
            ) => {}
            ExpressionKind::Call { callee, arguments } => {
                if let Some(ExpressionKind::Reference(Definition::Declaration(declaration))) =
                    program
                        .expression(*callee)
                        .map(|expression| &expression.kind)
                {
                    reserve_runtime_shape(
                        callees,
                        1,
                        request.limits.fact_edges,
                        "runtime callee scratch",
                    )?;
                    callees.push(declaration.declaration);
                }
                let additional = arguments.len().checked_add(1).ok_or({
                    RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit {
                        resource: "runtime expression scratch",
                        limit,
                    })
                })?;
                reserve_runtime_shape(
                    &mut pending,
                    additional,
                    limit,
                    "runtime expression scratch",
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
                            }));
                        }
                    }
                }
            }
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Await,
                operand,
            } if color == FunctionColor::Async => {
                reserve_runtime_shape(&mut pending, 1, limit, "runtime expression scratch")?;
                pending.push(*operand);
            }
            ExpressionKind::Try(operand) => {
                reserve_runtime_shape(&mut pending, 1, limit, "runtime expression scratch")?;
                pending.push(*operand);
            }
            ExpressionKind::Unary {
                operator:
                    wrela_hir::UnaryOperator::Negate
                    | wrela_hir::UnaryOperator::BitNot
                    | wrela_hir::UnaryOperator::BoolNot,
                operand,
            }
            | ExpressionKind::Cast { value: operand, .. } => {
                reserve_runtime_shape(&mut pending, 1, limit, "runtime expression scratch")?;
                pending.push(*operand);
            }
            ExpressionKind::Binary {
                operator:
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
                    | wrela_hir::BinaryOperator::ShiftLeftModular
                    | wrela_hir::BinaryOperator::ShiftRight,
                left,
                right,
            }
            | ExpressionKind::Compare {
                left,
                operator:
                    wrela_hir::ComparisonOperator::Equal
                    | wrela_hir::ComparisonOperator::NotEqual
                    | wrela_hir::ComparisonOperator::Less
                    | wrela_hir::ComparisonOperator::LessEqual
                    | wrela_hir::ComparisonOperator::Greater
                    | wrela_hir::ComparisonOperator::GreaterEqual,
                right,
            } => {
                reserve_runtime_shape(&mut pending, 2, limit, "runtime expression scratch")?;
                pending.push(*right);
                pending.push(*left);
            }
            ExpressionKind::Field { base, .. } => {
                reserve_runtime_shape(&mut pending, 1, limit, "runtime expression scratch")?;
                pending.push(*base);
            }
            _ => return Err(RuntimeShapeFailure::Unsupported(expression.source)),
        }
    }
    Ok(())
}

fn reserve_runtime_shape<T>(
    output: &mut Vec<T>,
    additional: usize,
    limit: u64,
    resource: &'static str,
) -> Result<(), RuntimeShapeFailure> {
    let required = output
        .len()
        .checked_add(additional)
        .and_then(|required| u64::try_from(required).ok())
        .ok_or({
            RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit { resource, limit })
        })?;
    if required > limit {
        return Err(RuntimeShapeFailure::Failure(
            AnalysisFailure::ResourceLimit { resource, limit },
        ));
    }
    output.try_reserve_exact(additional).map_err(|_| {
        RuntimeShapeFailure::Failure(AnalysisFailure::ResourceLimit { resource, limit })
    })
}

fn test_result_is_unit(result: Option<&wrela_hir::TypeExpression>) -> bool {
    match result {
        None => true,
        Some(result) => matches!(
            &result.kind,
            TypeExpressionKind::Named {
                definition: Definition::Builtin(wrela_hir::Builtin::Unit),
                arguments,
            } if arguments.is_empty()
        ),
    }
}

fn test_source_diagnostic(source: Span, code: &str, message: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::COMPTIME, source, message);
    diagnostic.code = Some(code.to_owned());
    diagnostic
}

fn append_source_test_function(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    test: &SupportedSourceTest,
    runtime_aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Result<FunctionInstanceId, Diagnostic>, AnalysisFailure> {
    let checkpoint = RuntimeCheckpoint::new(partial);
    let aggregate_checkpoint = runtime_aggregate_work.comparisons;
    let result = append_source_test_function_inner(
        request,
        partial,
        test,
        runtime_aggregate_work,
        is_cancelled,
    );
    if !matches!(&result, Ok(Ok(_))) {
        checkpoint.rollback(partial);
        runtime_aggregate_work.comparisons = aggregate_checkpoint;
    }
    result
}

fn append_source_test_function_inner(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    test: &SupportedSourceTest,
    runtime_aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Result<FunctionInstanceId, Diagnostic>, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let checked_comptime = match (test.color, test.checked_comptime.as_ref()) {
        (FunctionColor::Comptime, Some(checked))
            if checked
                .declarations
                .first()
                .is_some_and(|record| record.declaration == test.declaration) =>
        {
            Some(checked)
        }
        (FunctionColor::Sync | FunctionColor::Async, None) => None,
        _ => return Err(AnalysisFailure::RequestMismatch),
    };
    let proof_count = 2usize;
    if partial.functions.len() >= request.limits.monomorphizations as usize
        || partial
            .proofs
            .len()
            .checked_add(proof_count)
            .is_none_or(|count| count > request.limits.proofs as usize)
        || partial
            .statements
            .len()
            .checked_add(test.runtime_statements.len())
            .is_none_or(|count| count > request.limits.statement_facts as usize)
    {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic test functions, proofs, or statements",
            limit: u64::from(request.limits.monomorphizations),
        });
    }
    partial
        .functions
        .try_reserve(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "monomorphizations",
            limit: u64::from(request.limits.monomorphizations),
        })?;
    partial
        .proofs
        .try_reserve(proof_count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        })?;
    partial
        .statements
        .try_reserve(test.runtime_statements.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "statement facts",
            limit: u64::from(request.limits.statement_facts),
        })?;
    let function_id = FunctionInstanceId(u32::try_from(partial.functions.len()).map_err(|_| {
        AnalysisFailure::ResourceLimit {
            resource: "monomorphizations",
            limit: u64::from(request.limits.monomorphizations),
        }
    })?);
    let first_proof = ProofId(u32::try_from(partial.proofs.len()).map_err(|_| {
        AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        }
    })?);
    let (type_sources, type_bound, type_explanation) = if let Some(checked) = checked_comptime {
        let source_count = u64::try_from(checked.declarations.len()).map_err(|_| {
            AnalysisFailure::ResourceLimit {
                resource: "semantic fact edges",
                limit: request.limits.fact_edges,
            }
        })?;
        if source_count > request.limits.fact_edges {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "semantic fact edges",
                limit: request.limits.fact_edges,
            });
        }
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(checked.declarations.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "semantic fact edges",
                limit: request.limits.fact_edges,
            })?;
        for record in &checked.declarations {
            sources.push(record.source);
        }
        (
            sources,
            Some(checked.work_count),
            vec![SOURCE_COMPTIME_CLOSURE_PROOF_MARKER.to_owned()],
        )
    } else {
        (
            vec![test.source],
            None,
            vec![
                "the supported runtime scalar test body and unit result are well typed".to_owned(),
            ],
        )
    };
    partial.proofs.push(Proof {
        id: first_proof,
        kind: ProofKind::TypeChecked,
        subject: bounded_test_fact(request, "test type: ", &test.name, is_cancelled)?,
        sources: type_sources,
        depends_on: Vec::new(),
        bound: type_bound,
        explanation: type_explanation,
    });
    let effect_proof = ProofId(first_proof.0.checked_add(1).ok_or(
        AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        },
    )?);
    partial.proofs.push(Proof {
        id: effect_proof,
        kind: ProofKind::EffectsAllowed,
        subject: bounded_test_fact(request, "test effects: ", &test.name, is_cancelled)?,
        sources: vec![test.source],
        depends_on: vec![first_proof],
        bound: Some(if test.color == FunctionColor::Comptime {
            request
                .limits
                .evaluator_steps
                .min(request.build.profile.comptime.steps)
        } else {
            test.work_bound
        }),
        explanation: vec![match test.color {
            FunctionColor::Comptime => {
                "the test executes only inside the bounded comptime evaluator".to_owned()
            }
            FunctionColor::Sync | FunctionColor::Async => {
                "the selected runtime test body admits only bounded scalar effects and MAY_FAIL assertion paths"
                    .to_owned()
            }
            FunctionColor::Isr => return Err(AnalysisFailure::RequestMismatch),
        }],
    });
    partial.functions.push(FunctionInstance {
        id: function_id,
        key: test.key,
        name: copy_analysis_text(&test.name, request.limits.fact_bytes, is_cancelled)?,
        origin: FunctionOrigin::Source {
            declaration: test.declaration,
            body: test.body,
        },
        role: FunctionRole::Test,
        color: test.color,
        generic_arguments: Vec::new(),
        parameters: Vec::new(),
        result: SemanticTypeId(0),
        effects: EffectSet(0),
        stack_bytes_bound: 0,
        frame_bytes_bound: 0,
        uninterrupted_work_bound: Some(if test.color == FunctionColor::Comptime {
            request
                .limits
                .evaluator_steps
                .min(request.build.profile.comptime.steps)
        } else {
            test.work_bound
        }),
        recursive_depth_bound: Some(if test.color == FunctionColor::Comptime {
            request
                .build
                .profile
                .comptime
                .call_depth
                .min(COMPTIME_HOST_CALL_DEPTH)
        } else {
            1
        }),
        proofs: vec![first_proof, effect_proof],
        source: Some(test.source),
    });
    if test.color != FunctionColor::Comptime {
        match populate_runtime_body(
            request,
            partial,
            RuntimeBodyTarget {
                function: function_id,
                declaration: test.declaration,
                body: test.body,
                allow_assertions: true,
            },
            runtime_aggregate_work,
            is_cancelled,
        ) {
            Ok(()) => {}
            Err(RuntimeFailure::Diagnostic(diagnostic)) => {
                return Ok(Err(*diagnostic));
            }
            Err(RuntimeFailure::Analysis(error)) => return Err(error),
        }
    }
    Ok(Ok(function_id))
}

#[derive(Debug)]
enum RuntimeFailure {
    Diagnostic(Box<Diagnostic>),
    Analysis(AnalysisFailure),
}

impl From<AnalysisFailure> for RuntimeFailure {
    fn from(value: AnalysisFailure) -> Self {
        Self::Analysis(value)
    }
}

type RuntimeResult<T> = Result<T, RuntimeFailure>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeAuthority {
    Read,
    Mutate,
    Own,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeBindingOrigin {
    Local(LocalId),
    Parameter(wrela_hir::ParameterId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeBinding {
    value: ValueId,
    state: OwnershipState,
    authority: RuntimeAuthority,
    origin: RuntimeBindingOrigin,
    source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeExpression {
    ty: SemanticTypeId,
    result: Option<ValueId>,
    referenced: Option<ValueId>,
    effects: EffectSet,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeExpressionRequest {
    expected: Option<SemanticTypeId>,
    desired_result: Option<ValueId>,
    access: AccessMode,
}

struct RuntimeState<'a> {
    locals: &'a mut [Option<RuntimeBinding>],
    parameters: &'a mut [Option<RuntimeBinding>],
    aggregate_work: &'a mut RuntimeAggregateWork,
    allow_assertions: bool,
}

#[derive(Debug, Default)]
struct RuntimeAggregateWork {
    comparisons: u64,
}

fn charge_runtime_aggregate_lookup(
    request: &AnalysisRequest<'_>,
    work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    work.comparisons = work
        .comparisons
        .checked_add(1)
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "runtime type and aggregate lookup work",
            limit: request.limits.runtime_aggregate_lookup_work,
        })?;
    if work.comparisons > request.limits.runtime_aggregate_lookup_work {
        Err(AnalysisFailure::ResourceLimit {
            resource: "runtime type and aggregate lookup work",
            limit: request.limits.runtime_aggregate_lookup_work,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RuntimeDirectCall<'a> {
    expression: ExpressionId,
    source: Span,
    callee: ExpressionId,
    arguments: &'a [wrela_hir::CallArgument],
}

#[derive(Debug, Clone, Copy)]
struct RuntimeAwait {
    expression: ExpressionId,
    source: Span,
    operand: ExpressionId,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeUnary {
    expression: ExpressionId,
    source: Span,
    operator: wrela_hir::UnaryOperator,
    operand: ExpressionId,
}

#[derive(Debug, Clone, Copy)]
enum RuntimeBinaryOperator {
    Arithmetic(wrela_hir::BinaryOperator),
    Compare(wrela_hir::ComparisonOperator),
}

#[derive(Debug, Clone, Copy)]
struct RuntimeBinary {
    expression: ExpressionId,
    source: Span,
    operator: RuntimeBinaryOperator,
    left: ExpressionId,
    right: ExpressionId,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCast<'a> {
    expression: ExpressionId,
    source: Span,
    value: ExpressionId,
    destination: &'a TypeExpression,
}

struct RuntimeStatementPost<'a> {
    effects: EffectSet,
    definitions: Vec<LocalDefinition>,
    locals: &'a [Option<RuntimeBinding>],
    parameters: &'a [Option<RuntimeBinding>],
}

struct RuntimeExpressionFact {
    function: FunctionInstanceId,
    expression: ExpressionId,
    ty: SemanticTypeId,
    result: Option<ValueId>,
    resolution: ExpressionResolution,
    effects: EffectSet,
    ownership_before: OwnershipState,
    ownership_after: OwnershipState,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCheckpoint {
    types: usize,
    functions: usize,
    values: usize,
    expressions: usize,
    statements: usize,
    proofs: usize,
}

impl RuntimeCheckpoint {
    fn new(partial: &PartialAnalysis) -> Self {
        Self {
            types: partial.types.len(),
            functions: partial.functions.len(),
            values: partial.values.len(),
            expressions: partial.expressions.len(),
            statements: partial.statements.len(),
            proofs: partial.proofs.len(),
        }
    }

    fn rollback(self, partial: &mut PartialAnalysis) {
        partial.types.truncate(self.types);
        partial.functions.truncate(self.functions);
        partial.values.truncate(self.values);
        partial.expressions.truncate(self.expressions);
        partial.statements.truncate(self.statements);
        partial.proofs.truncate(self.proofs);
    }
}

fn runtime_ownership_diagnostic(
    request: &AnalysisRequest<'_>,
    primary: Span,
    code: &'static str,
    message: &'static str,
    binding: Option<RuntimeBinding>,
    note: &'static str,
    help: &'static str,
) -> Result<Diagnostic, AnalysisFailure> {
    let mut diagnostic = Diagnostic::error(Category::OWNERSHIP, primary, message);
    diagnostic.code = Some(copy_static_analysis_text(code, request.limits.fact_bytes)?);
    if let Some(binding) = binding {
        diagnostic
            .labels
            .try_reserve_exact(1)
            .map_err(|_| fact_resource(request, "ownership diagnostic labels"))?;
        diagnostic.labels.push(wrela_diagnostics::Label {
            span: binding.source,
            message: copy_static_analysis_text(
                match binding.origin {
                    RuntimeBindingOrigin::Local(_) => "the local value is introduced here",
                    RuntimeBindingOrigin::Parameter(_) => {
                        "the parameter access contract is declared here"
                    }
                },
                request.limits.fact_bytes,
            )?,
        });
    }
    diagnostic
        .notes
        .try_reserve_exact(1)
        .map_err(|_| fact_resource(request, "ownership diagnostic notes"))?;
    diagnostic
        .notes
        .push(copy_static_analysis_text(note, request.limits.fact_bytes)?);
    diagnostic
        .help
        .try_reserve_exact(1)
        .map_err(|_| fact_resource(request, "ownership diagnostic help"))?;
    diagnostic
        .help
        .push(copy_static_analysis_text(help, request.limits.fact_bytes)?);
    Ok(diagnostic)
}

fn runtime_diagnostic(
    request: &AnalysisRequest<'_>,
    primary: Span,
    code: &'static str,
    message: &'static str,
    binding: Option<RuntimeBinding>,
    note: &'static str,
    help: &'static str,
) -> RuntimeFailure {
    match runtime_ownership_diagnostic(request, primary, code, message, binding, note, help) {
        Ok(diagnostic) => RuntimeFailure::Diagnostic(Box::new(diagnostic)),
        Err(error) => RuntimeFailure::Analysis(error),
    }
}

fn runtime_type_diagnostic(
    request: &AnalysisRequest<'_>,
    primary: Span,
    code: &'static str,
    message: &'static str,
    note: &'static str,
    help: &'static str,
) -> RuntimeFailure {
    let build = || -> Result<Diagnostic, AnalysisFailure> {
        let mut diagnostic = Diagnostic::error(Category::TYPE, primary, message);
        diagnostic.code = Some(copy_static_analysis_text(code, request.limits.fact_bytes)?);
        diagnostic
            .notes
            .try_reserve_exact(1)
            .map_err(|_| fact_resource(request, "scalar diagnostic notes"))?;
        diagnostic
            .notes
            .push(copy_static_analysis_text(note, request.limits.fact_bytes)?);
        diagnostic
            .help
            .try_reserve_exact(1)
            .map_err(|_| fact_resource(request, "scalar diagnostic help"))?;
        diagnostic
            .help
            .push(copy_static_analysis_text(help, request.limits.fact_bytes)?);
        Ok(diagnostic)
    };
    match build() {
        Ok(diagnostic) => RuntimeFailure::Diagnostic(Box::new(diagnostic)),
        Err(error) => RuntimeFailure::Analysis(error),
    }
}

fn runtime_authority(access: AccessMode) -> RuntimeAuthority {
    match access {
        AccessMode::Value | AccessMode::Read => RuntimeAuthority::Read,
        AccessMode::Mutate => RuntimeAuthority::Mutate,
        AccessMode::Take => RuntimeAuthority::Own,
    }
}

fn accesses_conflict(first: AccessMode, second: AccessMode) -> bool {
    !matches!(
        (first, second),
        (
            AccessMode::Value | AccessMode::Read,
            AccessMode::Value | AccessMode::Read
        )
    )
}

fn runtime_binding_by_value(
    locals: &[Option<RuntimeBinding>],
    parameters: &[Option<RuntimeBinding>],
    value: ValueId,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<Option<RuntimeBinding>> {
    for slot in locals.iter().chain(parameters) {
        check_cancelled(is_cancelled)?;
        if slot.is_some_and(|binding| binding.value == value) {
            return Ok(*slot);
        }
    }
    Ok(None)
}

fn join_runtime_branches(
    request: &AnalysisRequest<'_>,
    source: Span,
    destination: &mut [Option<RuntimeBinding>],
    then_bindings: &[Option<RuntimeBinding>],
    else_bindings: &[Option<RuntimeBinding>],
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    if destination.len() != then_bindings.len() || destination.len() != else_bindings.len() {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    for index in 0..destination.len() {
        check_cancelled(is_cancelled)?;
        let Some(original) = destination[index] else {
            continue;
        };
        let Some(then_binding) = then_bindings[index] else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        let Some(else_binding) = else_bindings[index] else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        if then_binding.value != original.value
            || else_binding.value != original.value
            || then_binding.authority != original.authority
            || else_binding.authority != original.authority
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        if then_binding.state != else_binding.state {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-branch-ownership-mismatch",
                "branches leave a value in inconsistent ownership states",
                Some(original),
                "every path through a conditional must agree whether the value remains owned",
                "take the value on every branch or preserve it on every branch",
            ));
        }
        destination[index] = Some(then_binding);
    }
    Ok(())
}

struct RuntimeLocalBranchJoin<'a> {
    source: Span,
    destination: &'a mut [Option<RuntimeBinding>],
    then_bindings: &'a [Option<RuntimeBinding>],
    else_bindings: &'a [Option<RuntimeBinding>],
    definitions: &'a mut Vec<LocalDefinition>,
}

fn join_runtime_local_branches(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    join: RuntimeLocalBranchJoin<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    let RuntimeLocalBranchJoin {
        source,
        destination,
        then_bindings,
        else_bindings,
        definitions,
    } = join;
    if destination.len() != then_bindings.len() || destination.len() != else_bindings.len() {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    for index in 0..destination.len() {
        check_cancelled(is_cancelled)?;
        let Some(original) = destination[index] else {
            continue;
        };
        let Some(then_binding) = then_bindings[index] else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        let Some(else_binding) = else_bindings[index] else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        if then_binding.authority != original.authority
            || else_binding.authority != original.authority
            || then_binding.origin != original.origin
            || else_binding.origin != original.origin
            || then_binding.source != original.source
            || else_binding.source != original.source
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        if then_binding.state != else_binding.state {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-branch-ownership-mismatch",
                "branches leave a value in inconsistent ownership states",
                Some(original),
                "every path through a conditional must agree whether the value remains owned",
                "take the value on every branch or preserve it on every branch",
            ));
        }
        if then_binding.value == else_binding.value {
            destination[index] = Some(then_binding);
            continue;
        }
        if then_binding.state != OwnershipState::Owned
            || then_binding.authority != RuntimeAuthority::Own
        {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-branch-value-join-state",
                "branch-assigned values cannot converge after ownership was consumed",
                Some(original),
                "a scalar value join requires one live owned value from every branch",
                "join the assigned value before taking or moving it",
            ));
        }
        let RuntimeBindingOrigin::Local(local) = original.origin else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        if local.0 as usize != index {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        let original_value = partial
            .values
            .get(original.value.0 as usize)
            .filter(|value| value.function == function)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let then_value = partial
            .values
            .get(then_binding.value.0 as usize)
            .filter(|value| value.function == function)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let else_value = partial
            .values
            .get(else_binding.value.0 as usize)
            .filter(|value| value.function == function)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if original_value.ty != then_value.ty || original_value.ty != else_value.ty {
            return Err(runtime_type_diagnostic(
                request,
                source,
                "semantic-branch-value-type-mismatch",
                "branch-assigned local values have incompatible types",
                "every incoming value of an SSA join must have the local's exact scalar type",
                "assign the same declared scalar type on every branch",
            ));
        }
        let local_record = request
            .hir
            .as_program()
            .locals
            .get(local.0 as usize)
            .filter(|record| record.id == local)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let merged = append_semantic_value(
            request,
            partial,
            function,
            original_value.ty,
            (
                SemanticValueOrigin::Local(local),
                Some(local_record.source),
                Some(local_record.name.as_str()),
            ),
            is_cancelled,
        )?;
        if u64::try_from(definitions.len()).map_or(true, |count| count >= request.limits.fact_edges)
        {
            return Err(fact_resource(request, "branch local definitions").into());
        }
        definitions
            .try_reserve(1)
            .map_err(|_| fact_resource(request, "branch local definitions"))?;
        definitions.push(LocalDefinition {
            local,
            value: merged,
        });
        destination[index] = Some(RuntimeBinding {
            value: merged,
            state: OwnershipState::Owned,
            ..original
        });
    }
    Ok(())
}

fn validate_runtime_exit(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    function: FunctionInstanceId,
    locals: &[Option<RuntimeBinding>],
    parameters: &[Option<RuntimeBinding>],
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    for binding in locals.iter().chain(parameters).flatten() {
        check_cancelled(is_cancelled)?;
        let value = partial
            .values
            .get(binding.value.0 as usize)
            .filter(|value| value.function == function)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let ty = partial
            .types
            .get(value.ty.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if binding.authority == RuntimeAuthority::Own
            && binding.state == OwnershipState::Owned
            && ty.linearity == Linearity::StrictLinear
        {
            return Err(runtime_diagnostic(
                request,
                binding.source,
                "semantic-linear-value-not-consumed",
                "strict linear value is not consumed exactly once",
                Some(*binding),
                "strict linear ownership must be transferred before the function exits",
                "pass the value to a take parameter on every exit path",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RuntimeBodyTarget {
    function: FunctionInstanceId,
    declaration: DeclarationId,
    body: BodyId,
    allow_assertions: bool,
}

fn populate_runtime_body(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    target: RuntimeBodyTarget,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    let RuntimeBodyTarget {
        function,
        declaration,
        body,
        allow_assertions,
    } = target;
    check_cancelled(is_cancelled)?;
    let program = request.hir.as_program();
    let function_record = partial
        .functions
        .get(function.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let source = program
        .declaration(declaration)
        .and_then(|record| match &record.kind {
            DeclarationKind::Function(source) if source.body == Some(body) => Some(source),
            _ => None,
        })
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if function_record.parameters.len() != source.parameters.len() {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    let mut locals = optional_binding_map(program.locals.len(), request.limits.values)?;
    let mut parameters = optional_binding_map(program.parameters.len(), request.limits.values)?;
    for (source_id, semantic) in source.parameters.iter().zip(&function_record.parameters) {
        if semantic.parameter != *source_id {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        let source_parameter = program
            .parameters
            .get(source_id.0 as usize)
            .filter(|parameter| parameter.id == *source_id)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let slot = parameters
            .get_mut(source_id.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if slot
            .replace(RuntimeBinding {
                value: semantic.value,
                state: OwnershipState::Owned,
                authority: runtime_authority(semantic.access),
                origin: RuntimeBindingOrigin::Parameter(*source_id),
                source: source_parameter.source,
            })
            .is_some()
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }
    analyze_runtime_body(
        request,
        partial,
        function,
        body,
        &mut locals,
        &mut parameters,
        allow_assertions,
        aggregate_work,
        is_cancelled,
    )?;
    let body_effects = partial
        .statements
        .iter()
        .filter(|statement| statement.function == function)
        .fold(0u64, |effects, statement| effects | statement.effects.0);
    partial
        .functions
        .get_mut(function.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?
        .effects
        .0 |= body_effects;
    validate_runtime_exit(
        request,
        partial,
        function,
        &locals,
        &parameters,
        is_cancelled,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn analyze_runtime_body(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    body_id: BodyId,
    locals: &mut [Option<RuntimeBinding>],
    parameters: &mut [Option<RuntimeBinding>],
    allow_assertions: bool,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    check_cancelled(is_cancelled)?;
    let body = request
        .hir
        .as_program()
        .body(body_id)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    for &statement_id in &body.statements {
        check_cancelled(is_cancelled)?;
        let statement = request
            .hir
            .as_program()
            .statement(statement_id)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if statement.body != body_id || !statement.attributes.is_empty() {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        let mut definitions = Vec::new();
        let mut statement_effects = EffectSet(0);
        match &statement.kind {
            StatementKind::Pass => {}
            StatementKind::Initialize { local, value } => {
                let local_record = request
                    .hir
                    .as_program()
                    .locals
                    .get(local.0 as usize)
                    .filter(|record| record.id == *local && record.body == body_id)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                let ty = semantic_type_from_source(
                    request,
                    partial,
                    local_record
                        .ty
                        .as_ref()
                        .ok_or(AnalysisFailure::RequestMismatch)?,
                    &mut *aggregate_work,
                    is_cancelled,
                )?;
                let value_id = append_semantic_value(
                    request,
                    partial,
                    function,
                    ty,
                    (
                        SemanticValueOrigin::Local(*local),
                        Some(local_record.source),
                        Some(local_record.name.as_str()),
                    ),
                    is_cancelled,
                )?;
                let outcome = analyze_runtime_expression(
                    request,
                    partial,
                    function,
                    *value,
                    RuntimeExpressionRequest {
                        expected: Some(ty),
                        desired_result: Some(value_id),
                        access: AccessMode::Value,
                    },
                    &mut RuntimeState {
                        locals: &mut *locals,
                        parameters: &mut *parameters,
                        aggregate_work: &mut *aggregate_work,
                        allow_assertions,
                    },
                    is_cancelled,
                )?;
                statement_effects = outcome.effects;
                let slot = locals.get_mut(local.0 as usize).ok_or_else(|| {
                    AnalysisFailure::InternalInvariant(
                        "runtime initializer local slot is missing".to_owned(),
                    )
                })?;
                if slot
                    .replace(RuntimeBinding {
                        value: value_id,
                        state: OwnershipState::Owned,
                        authority: RuntimeAuthority::Own,
                        origin: RuntimeBindingOrigin::Local(*local),
                        source: local_record.source,
                    })
                    .is_some()
                {
                    return Err(AnalysisFailure::InternalInvariant(
                        "runtime initializer local slot is already occupied".to_owned(),
                    )
                    .into());
                }
                definitions
                    .try_reserve_exact(1)
                    .map_err(|_| fact_resource(request, "statement local definitions"))?;
                definitions.push(LocalDefinition {
                    local: *local,
                    value: value_id,
                });
            }
            StatementKind::Assign {
                targets,
                operator,
                value,
            } => {
                let [target] = targets.as_slice() else {
                    return Err(runtime_type_diagnostic(
                        request,
                        statement.source,
                        "semantic-assignment-target",
                        "scalar assignment requires exactly one local target",
                        "tuple and multi-place assignment require aggregate ownership lowering",
                        "assign one initialized scalar local",
                    ));
                };
                let Definition::Local(local) = target.root else {
                    return Err(runtime_type_diagnostic(
                        request,
                        target.source,
                        "semantic-assignment-target",
                        "scalar assignment target must be a local value",
                        "parameters, declarations, and projected places are not local SSA bindings",
                        "assign an initialized scalar local",
                    ));
                };
                if !target.projections.is_empty() {
                    return Err(runtime_type_diagnostic(
                        request,
                        target.source,
                        "semantic-assignment-form",
                        "scalar assignment requires a direct local target",
                        "projected assignment requires aggregate place-level mutation semantics",
                        "assign the explicitly typed scalar local directly",
                    ));
                }
                let current = locals
                    .get(local.0 as usize)
                    .copied()
                    .flatten()
                    .ok_or_else(|| {
                        runtime_diagnostic(
                            request,
                            target.source,
                            "semantic-assignment-uninitialized",
                            "assignment target is not initialized on this path",
                            None,
                            "SSA reassignment requires an existing local value on every reaching path",
                            "initialize the local before the conditional",
                        )
                    })?;
                if current.state != OwnershipState::Owned
                    || current.authority != RuntimeAuthority::Own
                {
                    return Err(runtime_diagnostic(
                        request,
                        target.source,
                        "semantic-assignment-ownership",
                        "assignment target is not a live owned scalar value",
                        Some(current),
                        "a taken, moved, or borrowed value cannot be overwritten through this SSA path",
                        "assign before transferring or borrowing the value",
                    ));
                }
                let current_ty = partial
                    .values
                    .get(current.value.0 as usize)
                    .filter(|record| record.function == function)
                    .map(|record| record.ty)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                let local_record = request
                    .hir
                    .as_program()
                    .locals
                    .get(local.0 as usize)
                    .filter(|record| record.id == local)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                let compound = compound_assignment_binary_operator(*operator);
                if compound.is_some()
                    && !matches!(
                        runtime_scalar_type(partial, current_ty),
                        Some(RuntimeScalarType::Integer { .. })
                    )
                {
                    return Err(runtime_type_diagnostic(
                        request,
                        statement.source,
                        "semantic-compound-assignment-type",
                        "compound assignment requires an integer local",
                        "revision 0.1 defines compound arithmetic, bitwise, and shift assignment only for integers",
                        "use an integer local or write an explicitly supported operation",
                    ));
                }
                let value_id = if compound.is_some() {
                    *locals
                        .get_mut(local.0 as usize)
                        .ok_or(AnalysisFailure::RequestMismatch)? = Some(RuntimeBinding {
                        state: OwnershipState::BorrowedMut,
                        ..current
                    });
                    let outcome = analyze_runtime_expression(
                        request,
                        partial,
                        function,
                        *value,
                        RuntimeExpressionRequest {
                            expected: Some(current_ty),
                            desired_result: None,
                            access: AccessMode::Value,
                        },
                        &mut RuntimeState {
                            locals: &mut *locals,
                            parameters: &mut *parameters,
                            aggregate_work: &mut *aggregate_work,
                            allow_assertions,
                        },
                        is_cancelled,
                    )?;
                    statement_effects = outcome.effects;
                    let reserved = locals
                        .get(local.0 as usize)
                        .copied()
                        .flatten()
                        .ok_or(AnalysisFailure::RequestMismatch)?;
                    if reserved
                        != (RuntimeBinding {
                            state: OwnershipState::BorrowedMut,
                            ..current
                        })
                    {
                        return Err(AnalysisFailure::RequestMismatch.into());
                    }
                    append_semantic_value(
                        request,
                        partial,
                        function,
                        current_ty,
                        (
                            SemanticValueOrigin::Local(local),
                            Some(local_record.source),
                            Some(local_record.name.as_str()),
                        ),
                        is_cancelled,
                    )?
                } else {
                    let value_id = append_semantic_value(
                        request,
                        partial,
                        function,
                        current_ty,
                        (
                            SemanticValueOrigin::Local(local),
                            Some(local_record.source),
                            Some(local_record.name.as_str()),
                        ),
                        is_cancelled,
                    )?;
                    let outcome = analyze_runtime_expression(
                        request,
                        partial,
                        function,
                        *value,
                        RuntimeExpressionRequest {
                            expected: Some(current_ty),
                            desired_result: Some(value_id),
                            access: AccessMode::Value,
                        },
                        &mut RuntimeState {
                            locals: &mut *locals,
                            parameters: &mut *parameters,
                            aggregate_work: &mut *aggregate_work,
                            allow_assertions,
                        },
                        is_cancelled,
                    )?;
                    statement_effects = outcome.effects;
                    value_id
                };
                *locals
                    .get_mut(local.0 as usize)
                    .ok_or(AnalysisFailure::RequestMismatch)? = Some(RuntimeBinding {
                    value: value_id,
                    state: OwnershipState::Owned,
                    ..current
                });
                definitions
                    .try_reserve_exact(1)
                    .map_err(|_| fact_resource(request, "statement local definitions"))?;
                definitions.push(LocalDefinition {
                    local,
                    value: value_id,
                });
            }
            StatementKind::Expression(expression) => {
                let outcome = analyze_runtime_expression(
                    request,
                    partial,
                    function,
                    *expression,
                    RuntimeExpressionRequest {
                        expected: None,
                        desired_result: None,
                        access: AccessMode::Value,
                    },
                    &mut RuntimeState {
                        locals: &mut *locals,
                        parameters: &mut *parameters,
                        aggregate_work: &mut *aggregate_work,
                        allow_assertions,
                    },
                    is_cancelled,
                )?;
                statement_effects = outcome.effects;
            }
            StatementKind::Send(expression) => {
                let outcome = analyze_actor_send_expression(
                    request,
                    partial,
                    function,
                    *expression,
                    &mut RuntimeState {
                        locals: &mut *locals,
                        parameters: &mut *parameters,
                        aggregate_work: &mut *aggregate_work,
                        allow_assertions,
                    },
                    is_cancelled,
                )?;
                statement_effects = outcome.effects;
            }
            StatementKind::Assert {
                condition,
                expression,
                witness: _,
                message,
                comptime: false,
            } if allow_assertions => {
                if message.as_ref().is_some_and(|message| {
                    message.len() > MAX_RUNTIME_ASSERTION_EXPRESSION_BYTES
                        || message.chars().all(char::is_whitespace)
                }) {
                    return Err(runtime_type_diagnostic(
                        request,
                        statement.source,
                        "semantic-runtime-assertion-message-limit",
                        "runtime assertion message is empty or exceeds its bounded report payload",
                        "a present assertion message must contain 1 through 4096 UTF-8 bytes",
                        "provide a shorter nonempty message or omit it",
                    ));
                }
                if expression.len() > MAX_RUNTIME_ASSERTION_EXPRESSION_BYTES
                    || expression.chars().all(char::is_whitespace)
                {
                    return Err(runtime_type_diagnostic(
                        request,
                        statement.source,
                        "semantic-runtime-assertion-expression-limit",
                        "runtime assertion condition source exceeds its bounded report payload",
                        "the exact declared-source condition must fit the 4096-byte assertion bound",
                        "simplify the assertion condition or call a boolean helper",
                    ));
                }
                let _condition_source = request
                    .hir
                    .as_program()
                    .expression(*condition)
                    .filter(|record| record.source.range.start <= record.source.range.end)
                    .map(|record| record.source)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                let bool_ty = ensure_primitive_type(
                    request,
                    partial,
                    PrimitiveSemanticType::Bool,
                    &mut *aggregate_work,
                    is_cancelled,
                )?;
                let outcome = analyze_runtime_expression(
                    request,
                    partial,
                    function,
                    *condition,
                    RuntimeExpressionRequest {
                        expected: Some(bool_ty),
                        desired_result: None,
                        access: AccessMode::Value,
                    },
                    &mut RuntimeState {
                        locals: &mut *locals,
                        parameters: &mut *parameters,
                        aggregate_work: &mut *aggregate_work,
                        allow_assertions,
                    },
                    is_cancelled,
                )?;
                if outcome.ty != bool_ty {
                    return Err(AnalysisFailure::RequestMismatch.into());
                }
                statement_effects = EffectSet(outcome.effects.0 | EffectSet::MAY_FAIL);
            }
            StatementKind::Return(expression) => {
                let result = partial
                    .functions
                    .get(function.0 as usize)
                    .map(|record| record.result)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                match *expression {
                    Some(expression) => {
                        let outcome = analyze_runtime_expression(
                            request,
                            partial,
                            function,
                            expression,
                            RuntimeExpressionRequest {
                                expected: Some(result),
                                desired_result: None,
                                access: AccessMode::Value,
                            },
                            &mut RuntimeState {
                                locals: &mut *locals,
                                parameters: &mut *parameters,
                                aggregate_work: &mut *aggregate_work,
                                allow_assertions,
                            },
                            is_cancelled,
                        )?;
                        statement_effects = outcome.effects;
                    }
                    None if result == SemanticTypeId(0) => {}
                    None => return Err(AnalysisFailure::RequestMismatch.into()),
                }
            }
            StatementKind::If {
                branches,
                else_body,
            } => {
                let [(condition, then_body)] = branches.as_slice() else {
                    return Err(AnalysisFailure::RequestMismatch.into());
                };
                let bool_ty = ensure_primitive_type(
                    request,
                    partial,
                    PrimitiveSemanticType::Bool,
                    &mut *aggregate_work,
                    is_cancelled,
                )?;
                let condition = analyze_runtime_expression(
                    request,
                    partial,
                    function,
                    *condition,
                    RuntimeExpressionRequest {
                        expected: Some(bool_ty),
                        desired_result: None,
                        access: AccessMode::Value,
                    },
                    &mut RuntimeState {
                        locals: &mut *locals,
                        parameters: &mut *parameters,
                        aggregate_work: &mut *aggregate_work,
                        allow_assertions,
                    },
                    is_cancelled,
                )?;
                statement_effects = condition.effects;
                let branch_fact_start = partial.statements.len();
                let mut then_locals = copy_binding_map(locals, request.limits.values)?;
                let mut then_parameters = copy_binding_map(parameters, request.limits.values)?;
                analyze_runtime_body(
                    request,
                    partial,
                    function,
                    *then_body,
                    &mut then_locals,
                    &mut then_parameters,
                    allow_assertions,
                    &mut *aggregate_work,
                    is_cancelled,
                )?;
                let mut else_locals = copy_binding_map(locals, request.limits.values)?;
                let mut else_parameters = copy_binding_map(parameters, request.limits.values)?;
                if let Some(otherwise) = *else_body {
                    analyze_runtime_body(
                        request,
                        partial,
                        function,
                        otherwise,
                        &mut else_locals,
                        &mut else_parameters,
                        allow_assertions,
                        &mut *aggregate_work,
                        is_cancelled,
                    )?;
                }
                join_runtime_local_branches(
                    request,
                    partial,
                    function,
                    RuntimeLocalBranchJoin {
                        source: statement.source,
                        destination: locals,
                        then_bindings: &then_locals,
                        else_bindings: &else_locals,
                        definitions: &mut definitions,
                    },
                    is_cancelled,
                )?;
                for branch in partial
                    .statements
                    .get(branch_fact_start..)
                    .ok_or(AnalysisFailure::RequestMismatch)?
                {
                    statement_effects.0 |= branch.effects.0;
                }
                join_runtime_branches(
                    request,
                    statement.source,
                    parameters,
                    &then_parameters,
                    &else_parameters,
                    is_cancelled,
                )?;
            }
            StatementKind::Match { scrutinee, arms } => {
                statement_effects = analyze_closed_enum_match(
                    request,
                    partial,
                    function,
                    *scrutinee,
                    arms,
                    locals,
                    parameters,
                    allow_assertions,
                    &mut *aggregate_work,
                    &mut definitions,
                    is_cancelled,
                )?;
            }
            _ => return Err(AnalysisFailure::RequestMismatch.into()),
        }
        append_statement_fact(
            request,
            partial,
            function,
            statement_id,
            RuntimeStatementPost {
                effects: statement_effects,
                definitions,
                locals,
                parameters,
            },
            is_cancelled,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn analyze_closed_enum_match(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    scrutinee_id: ExpressionId,
    arms: &[wrela_hir::MatchArm],
    locals: &mut [Option<RuntimeBinding>],
    parameters: &mut [Option<RuntimeBinding>],
    allow_assertions: bool,
    aggregate_work: &mut RuntimeAggregateWork,
    definitions: &mut Vec<LocalDefinition>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<EffectSet> {
    let scrutinee_source = request
        .hir
        .as_program()
        .expression(scrutinee_id)
        .map(|record| record.source)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let scrutinee = analyze_runtime_expression(
        request,
        partial,
        function,
        scrutinee_id,
        RuntimeExpressionRequest {
            expected: None,
            desired_result: None,
            access: AccessMode::Read,
        },
        &mut RuntimeState {
            locals: &mut *locals,
            parameters: &mut *parameters,
            aggregate_work: &mut *aggregate_work,
            allow_assertions,
        },
        is_cancelled,
    )?;
    let (enumeration, variants, payload_ty) = partial
        .types
        .get(scrutinee.ty.0 as usize)
        .and_then(|record| match &record.kind {
            SemanticTypeKind::Enumeration {
                declaration,
                variants,
                ..
            } => variants
                .first()
                .and_then(|variant| variant.fields.first())
                .map(|field| (*declaration, variants.len(), field.ty)),
            _ => None,
        })
        .ok_or_else(|| {
            runtime_type_diagnostic(
                request,
                scrutinee_source,
                "semantic-runtime-match-scrutinee",
                "runtime match requires a supported closed enum",
                "R1 matching dispatches only on a canonical dense enum tag",
                "match a nongeneric scalar-backed enum value",
            )
        })?;
    if arms.len() != variants {
        return Err(runtime_type_diagnostic(
            request,
            fallback_span(request.hir.as_program()),
            "semantic-runtime-match-nonexhaustive",
            "runtime enum match is not exactly exhaustive",
            "every declared variant must appear once in an unguarded constructor arm",
            "add each missing variant and remove duplicates",
        ));
    }
    let mut covered = Vec::new();
    covered
        .try_reserve_exact(variants)
        .map_err(|_| fact_resource(request, "runtime match coverage"))?;
    covered.resize(variants, false);
    let mut effects = scrutinee.effects;
    for arm in arms {
        check_cancelled(is_cancelled)?;
        if arm.guard.is_some() {
            return Err(runtime_type_diagnostic(
                request,
                arm.source,
                "semantic-runtime-match-guard-not-supported",
                "runtime enum match arms must be unguarded",
                "guarded arms do not contribute to closed exhaustiveness",
                "move the condition into the arm body",
            ));
        }
        let pattern = request
            .hir
            .as_program()
            .patterns
            .get(arm.pattern.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let [alternative] = pattern.alternatives.as_slice() else {
            return Err(runtime_type_diagnostic(
                request,
                pattern.source,
                "semantic-runtime-match-alternatives-not-supported",
                "runtime enum match arm requires one pattern",
                "pattern alternatives are outside this exact constructor-only slice",
                "write one arm per variant",
            ));
        };
        let wrela_hir::PrimaryPattern::Constructor {
            candidates,
            arguments,
            ..
        } = &alternative.kind
        else {
            let code = if matches!(alternative.kind, wrela_hir::PrimaryPattern::Wildcard) {
                "semantic-runtime-match-wildcard-not-supported"
            } else {
                "semantic-runtime-match-constructor-only"
            };
            return Err(runtime_type_diagnostic(
                request,
                alternative.source,
                code,
                "runtime enum match arm must use an explicit constructor",
                "wildcard, literal, binding-only, tuple, and array arms hide the closed variant set",
                "name one declared enum variant in each arm",
            ));
        };
        let [candidate] = candidates.as_slice() else {
            return Err(runtime_type_diagnostic(
                request,
                alternative.source,
                "semantic-runtime-match-constructor-only",
                "runtime enum constructor pattern is ambiguous or unresolved",
                "closed dispatch requires one exact declaration and variant identity",
                "import or qualify one declared variant",
            ));
        };
        if candidate.enumeration.declaration != enumeration
            || candidate.variant as usize >= variants
            || covered[candidate.variant as usize]
        {
            return Err(runtime_type_diagnostic(
                request,
                alternative.source,
                "semantic-runtime-match-nonexhaustive",
                "runtime enum match repeats or substitutes a variant",
                "every variant of the scrutinee enum must appear exactly once",
                "use each declared variant once",
            ));
        }
        covered[candidate.variant as usize] = true;
        let [argument] = arguments.as_slice() else {
            return Err(runtime_type_diagnostic(
                request,
                alternative.source,
                "semantic-runtime-match-payload-shape",
                "runtime enum pattern requires one payload binding",
                "the matched representation contains exactly one shared scalar payload",
                "bind the variant payload once",
            ));
        };
        if argument.take {
            return Err(runtime_type_diagnostic(
                request,
                argument.source,
                "semantic-runtime-match-take-not-supported",
                "runtime enum pattern payload cannot use `take`",
                "R1 payloads are implicit copy scalars",
                "remove `take` from the payload binding",
            ));
        }
        let payload_pattern = request
            .hir
            .as_program()
            .patterns
            .get(argument.pattern.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let [payload_alternative] = payload_pattern.alternatives.as_slice() else {
            return Err(runtime_type_diagnostic(
                request,
                payload_pattern.source,
                "semantic-runtime-match-alternatives-not-supported",
                "runtime enum payload requires one binding pattern",
                "payload alternatives are outside the exact R1 slice",
                "bind the scalar payload directly",
            ));
        };
        let wrela_hir::PrimaryPattern::Bind(local) = &payload_alternative.kind else {
            return Err(runtime_type_diagnostic(
                request,
                payload_alternative.source,
                "semantic-runtime-match-payload-shape",
                "runtime enum payload pattern must bind one scalar name",
                "wildcard and nested destructuring are outside the exact R1 slice",
                "bind the payload to a local name",
            ));
        };
        let local_record = request
            .hir
            .as_program()
            .locals
            .get(local.0 as usize)
            .filter(|record| record.id == *local && record.body == arm.body)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let value = append_semantic_value(
            request,
            partial,
            function,
            payload_ty,
            (
                SemanticValueOrigin::Local(*local),
                Some(local_record.source),
                Some(local_record.name.as_str()),
            ),
            is_cancelled,
        )?;
        definitions
            .try_reserve(1)
            .map_err(|_| fact_resource(request, "runtime match bindings"))?;
        definitions.push(LocalDefinition {
            local: *local,
            value,
        });
        let mut arm_locals = copy_binding_map(locals, request.limits.values)?;
        let mut arm_parameters = copy_binding_map(parameters, request.limits.values)?;
        let slot = arm_locals
            .get_mut(local.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if slot
            .replace(RuntimeBinding {
                value,
                state: OwnershipState::Owned,
                authority: RuntimeAuthority::Own,
                origin: RuntimeBindingOrigin::Local(*local),
                source: local_record.source,
            })
            .is_some()
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        let fact_start = partial.statements.len();
        analyze_runtime_body(
            request,
            partial,
            function,
            arm.body,
            &mut arm_locals,
            &mut arm_parameters,
            allow_assertions,
            &mut *aggregate_work,
            is_cancelled,
        )?;
        let mut state_changed =
            arm_parameters.len() != parameters.len() || arm_locals.len() != locals.len();
        for (left, right) in arm_parameters.iter().zip(parameters.iter()) {
            check_cancelled(is_cancelled)?;
            state_changed |= left != right;
        }
        for (index, (left, right)) in arm_locals.iter().zip(locals.iter()).enumerate() {
            check_cancelled(is_cancelled)?;
            if index != local.0 as usize {
                state_changed |= left != right;
            }
        }
        if state_changed {
            return Err(runtime_type_diagnostic(
                request,
                arm.source,
                "semantic-runtime-match-state-change-not-supported",
                "runtime enum match arm changes outer local state",
                "R1 match arms may consume the payload and return or perform effects, but do not join outer SSA assignments",
                "return from each arm or move the assignment after the match",
            ));
        }
        for statement in partial
            .statements
            .get(fact_start..)
            .ok_or(AnalysisFailure::RequestMismatch)?
        {
            check_cancelled(is_cancelled)?;
            effects.0 |= statement.effects.0;
        }
    }
    let mut missing = false;
    for covered in &covered {
        check_cancelled(is_cancelled)?;
        missing |= !covered;
    }
    if missing {
        return Err(runtime_type_diagnostic(
            request,
            fallback_span(request.hir.as_program()),
            "semantic-runtime-match-nonexhaustive",
            "runtime enum match omits a variant",
            "every variant must appear exactly once",
            "add the missing constructor arm",
        ));
    }
    Ok(effects)
}

fn analyze_runtime_expression(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    expression_id: ExpressionId,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    check_cancelled(is_cancelled)?;
    let expression = request
        .hir
        .as_program()
        .expression(expression_id)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    match &expression.kind {
        ExpressionKind::Literal(literal) => {
            if !matches!(
                expression_request.access,
                AccessMode::Value | AccessMode::Read
            ) {
                return Err(runtime_diagnostic(
                    request,
                    expression.source,
                    "semantic-access-temporary",
                    "mutable or take access requires an owned source value",
                    None,
                    "a literal is a temporary value, not caller-owned mutable storage",
                    "bind the value to a local before requesting mutable or take access",
                ));
            }
            let ty = match (expression_request.expected, literal) {
                (Some(ty), _) => ty,
                (None, Literal::Unit) => SemanticTypeId(0),
                (None, Literal::Boolean(_)) => ensure_primitive_type(
                    request,
                    partial,
                    PrimitiveSemanticType::Bool,
                    &mut *state.aggregate_work,
                    is_cancelled,
                )?,
                (None, Literal::Integer(_)) => ensure_primitive_type(
                    request,
                    partial,
                    PrimitiveSemanticType::Integer {
                        signed: true,
                        bits: 64,
                        pointer_sized: false,
                    },
                    &mut *state.aggregate_work,
                    is_cancelled,
                )?,
                (None, Literal::Float(_)) => {
                    return Err(runtime_type_diagnostic(
                        request,
                        expression.source,
                        "semantic-float-context-required",
                        "floating literal requires an explicit f32 or f64 context",
                        "revision 0.1 does not silently choose a floating-point width",
                        "bind the literal to a typed local or convert an explicitly typed value",
                    ));
                }
                (None, _) => return Err(AnalysisFailure::RequestMismatch.into()),
            };
            let constant = lower_scalar_literal(request, partial, ty, literal, is_cancelled)
                .map_err(|error| {
                    if error == AnalysisFailure::RequestMismatch {
                        runtime_type_diagnostic(
                            request,
                            expression.source,
                            "semantic-literal-type-mismatch",
                            "literal does not fit its required scalar type",
                            "literal spelling and contextual type must describe one exact value",
                            "change the literal or its explicit scalar type",
                        )
                    } else {
                        RuntimeFailure::Analysis(error)
                    }
                })?;
            let value = expression_result(
                request,
                partial,
                function,
                (expression_id, expression.source),
                ty,
                expression_request.desired_result,
                is_cancelled,
            )?;
            append_expression_fact(
                request,
                partial,
                RuntimeExpressionFact {
                    function,
                    expression: expression_id,
                    ty,
                    result: Some(value),
                    resolution: ExpressionResolution::Constant(constant),
                    effects: EffectSet(0),
                    ownership_before: OwnershipState::Owned,
                    ownership_after: OwnershipState::Owned,
                },
            )?;
            Ok(RuntimeExpression {
                ty,
                result: Some(value),
                referenced: None,
                effects: EffectSet(0),
            })
        }
        ExpressionKind::Reference(Definition::Local(local)) => {
            let slot = state
                .locals
                .get_mut(local.0 as usize)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            let binding = slot.as_ref().copied().ok_or_else(|| {
                runtime_diagnostic(
                    request,
                    expression.source,
                    "semantic-use-before-initialize",
                    "local value is used before it is initialized",
                    None,
                    "every local must be initialized on every incoming control-flow path",
                    "initialize the local before this expression",
                )
            })?;
            reference_operand(
                request,
                partial,
                (function, expression_id),
                binding,
                expression_request,
                slot,
                is_cancelled,
            )
        }
        ExpressionKind::Reference(Definition::Parameter(parameter)) => {
            let slot = state
                .parameters
                .get_mut(parameter.0 as usize)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            let binding = slot
                .as_ref()
                .copied()
                .ok_or(AnalysisFailure::RequestMismatch)?;
            reference_operand(
                request,
                partial,
                (function, expression_id),
                binding,
                expression_request,
                slot,
                is_cancelled,
            )
        }
        ExpressionKind::Call { callee, arguments } => {
            if !matches!(
                expression_request.access,
                AccessMode::Value | AccessMode::Read
            ) {
                return Err(runtime_diagnostic(
                    request,
                    expression.source,
                    "semantic-access-temporary",
                    "mutable or take access requires a named owned value",
                    None,
                    "revision 0.1 does not extend mutable or take access through call temporaries",
                    "bind the call result to a local before transferring it",
                ));
            }
            analyze_direct_call(
                request,
                partial,
                function,
                RuntimeDirectCall {
                    expression: expression_id,
                    source: expression.source,
                    callee: *callee,
                    arguments,
                },
                expression_request,
                state,
                is_cancelled,
            )
        }
        ExpressionKind::Field { base, name } => analyze_flat_structure_field(
            request,
            partial,
            function,
            expression_id,
            expression.source,
            *base,
            name,
            expression_request,
            state,
            is_cancelled,
        ),
        ExpressionKind::Unary {
            operator:
                operator @ (wrela_hir::UnaryOperator::Negate
                | wrela_hir::UnaryOperator::BitNot
                | wrela_hir::UnaryOperator::BoolNot),
            operand,
        } => analyze_scalar_unary(
            request,
            partial,
            function,
            RuntimeUnary {
                expression: expression_id,
                source: expression.source,
                operator: *operator,
                operand: *operand,
            },
            expression_request,
            state,
            is_cancelled,
        ),
        ExpressionKind::Binary {
            operator,
            left,
            right,
        } if !matches!(
            operator,
            wrela_hir::BinaryOperator::LogicalOr | wrela_hir::BinaryOperator::LogicalAnd
        ) =>
        {
            analyze_scalar_binary(
                request,
                partial,
                function,
                RuntimeBinary {
                    expression: expression_id,
                    source: expression.source,
                    operator: RuntimeBinaryOperator::Arithmetic(*operator),
                    left: *left,
                    right: *right,
                },
                expression_request,
                state,
                is_cancelled,
            )
        }
        ExpressionKind::Compare {
            left,
            operator,
            right,
        } if !matches!(
            operator,
            wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn
        ) =>
        {
            analyze_scalar_binary(
                request,
                partial,
                function,
                RuntimeBinary {
                    expression: expression_id,
                    source: expression.source,
                    operator: RuntimeBinaryOperator::Compare(*operator),
                    left: *left,
                    right: *right,
                },
                expression_request,
                state,
                is_cancelled,
            )
        }
        ExpressionKind::Cast { value, ty } => analyze_scalar_cast(
            request,
            partial,
            function,
            RuntimeCast {
                expression: expression_id,
                source: expression.source,
                value: *value,
                destination: ty,
            },
            expression_request,
            state,
            is_cancelled,
        ),
        ExpressionKind::Unary {
            operator: wrela_hir::UnaryOperator::Await,
            operand,
        } => analyze_await_expression(
            request,
            partial,
            function,
            RuntimeAwait {
                expression: expression_id,
                source: expression.source,
                operand: *operand,
            },
            expression_request,
            state,
            is_cancelled,
        ),
        ExpressionKind::Try(operand) => analyze_result_try_expression(
            request,
            partial,
            function,
            expression_id,
            expression.source,
            *operand,
            expression_request,
            state,
            is_cancelled,
        ),
        _ => Err(AnalysisFailure::RequestMismatch.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_result_try_expression(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    expression: ExpressionId,
    source: Span,
    operand: ExpressionId,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    if !matches!(
        expression_request.access,
        AccessMode::Value | AccessMode::Read
    ) {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-access",
            "postfix question produces a temporary payload value",
            "mutable and take access cannot target the branch-merged result of propagation",
            "bind the propagated payload before requesting exclusive access",
        ));
    }
    if request
        .hir
        .as_program()
        .expression(operand)
        .is_some_and(|operand| {
            matches!(
                operand.kind,
                ExpressionKind::Reference(Definition::Local(_) | Definition::Parameter(_))
                    | ExpressionKind::Field { .. }
            )
        })
    {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-rvalue-required",
            "postfix question requires an owned Result rvalue",
            "named-place consumption and its cleanup semantics are outside this bounded slice",
            "propagate a freshly returned or constructed Result value",
        ));
    }
    let operand_outcome = analyze_runtime_expression(
        request,
        partial,
        function,
        operand,
        RuntimeExpressionRequest {
            expected: None,
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    if operand_outcome.result.is_none() || operand_outcome.referenced.is_some() {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-rvalue-required",
            "postfix question requires an owned Result rvalue",
            "named-place consumption and its cleanup semantics are outside this bounded slice",
            "propagate a freshly returned or constructed Result value",
        ));
    }
    let result_type = operand_outcome.ty;
    let Some(result_record) = partial.types.get(result_type.0 as usize) else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    let SemanticTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    } = &result_record.kind
    else {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-result-required",
            "postfix question operand is not the authenticated core Result specialization",
            "R3 accepts only owned rvalues of core.result.Result[S, S]",
            "return or construct a supported core Result value before applying `?`",
        ));
    };
    let result_declaration = request
        .hir
        .as_program()
        .declaration(*declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let result_module = request
        .hir
        .as_program()
        .modules
        .get(result_declaration.module.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let resolved = wrela_hir::ResolvedDeclaration {
        package: result_module.package,
        module: result_declaration.module,
        declaration: *declaration,
    };
    let supported = is_exact_core_result_declaration(request, &resolved, result_declaration)
        && matches!(arguments.as_slice(), [SemanticArgument::Type(ok), SemanticArgument::Type(err)] if ok == err)
        && matches!(variants.as_slice(), [ok, err]
            if ok.name == "Ok"
                && err.name == "Err"
                && matches!((ok.fields.as_slice(), err.fields.as_slice()), ([ok_field], [err_field])
                    if ok_field.ty == err_field.ty));
    if !supported {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-result-required",
            "postfix question operand is not the authenticated core Result specialization",
            "R3 accepts only exact core.result.Result[S, S] with its canonical Ok and Err variants",
            "use the supported core Result declaration with one identical copy-scalar payload",
        ));
    }
    let payload_type = variants[0].fields[0].ty;
    if runtime_scalar_type(partial, payload_type).is_none() {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-result-required",
            "postfix question Result payload is outside the supported scalar subset",
            "linear, nominal, and aggregate propagation require later cleanup semantics",
            "use Result[S, S] with a supported copy scalar S",
        ));
    }
    let enclosing_result = partial
        .functions
        .get(function.0 as usize)
        .map(|function| function.result)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if enclosing_result != result_type {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-enclosing-result",
            "postfix question requires the enclosing function to return the same Result type",
            "the Err branch returns early without conversion or From semantics",
            "change the function result to the exact operand Result[S, S] specialization",
        ));
    }
    if expression_request
        .expected
        .is_some_and(|expected| expected != payload_type)
    {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-try-result-required",
            "postfix question payload does not match its required context",
            "the Ok branch yields the exact scalar stored by Result[S, S]",
            "use the propagated scalar directly or change the surrounding type",
        ));
    }
    let append_internal = |partial: &mut PartialAnalysis, ty| {
        append_semantic_value(
            request,
            partial,
            function,
            ty,
            (
                SemanticValueOrigin::Expression(expression),
                Some(source),
                None,
            ),
            is_cancelled,
        )
    };
    let ok_payload = append_internal(partial, payload_type)?;
    let err_payload = append_internal(partial, payload_type)?;
    let propagated = append_internal(partial, result_type)?;
    let result = expression_result(
        request,
        partial,
        function,
        (expression, source),
        payload_type,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression,
            ty: payload_type,
            result: Some(result),
            resolution: ExpressionResolution::ResultTry {
                result_type,
                ok_variant: 0,
                err_variant: 1,
                ok_payload,
                err_payload,
                propagated,
            },
            effects: operand_outcome.effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: payload_type,
        result: Some(result),
        referenced: None,
        effects: operand_outcome.effects,
    })
}

fn analyze_actor_send_expression(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    expression_id: ExpressionId,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    check_cancelled(is_cancelled)?;
    let resolved =
        resolve_self_actor_send(request, partial, function, expression_id, is_cancelled)?;
    let permit = partial
        .proofs
        .iter()
        .filter(|proof| {
            proof.kind == ProofKind::CapacityBound
                && proof.bound == Some(1)
                && proof.sources.as_slice() == [resolved.source]
                && proof.depends_on.as_slice() == [resolved.mailbox_proof]
        })
        .map(|proof| proof.id)
        .next()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let (callee, base) = match request
        .hir
        .as_program()
        .expression(expression_id)
        .map(|expression| &expression.kind)
    {
        Some(ExpressionKind::Call { callee, .. }) => {
            let base = match request
                .hir
                .as_program()
                .expression(*callee)
                .map(|expression| &expression.kind)
            {
                Some(ExpressionKind::Field { base, .. }) => *base,
                _ => return Err(AnalysisFailure::RequestMismatch.into()),
            };
            (*callee, base)
        }
        _ => return Err(AnalysisFailure::RequestMismatch.into()),
    };
    let receiver_ty = partial
        .functions
        .get(function.0 as usize)
        .and_then(|function| function.parameters.first())
        .map(|parameter| parameter.ty)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let _receiver = analyze_runtime_expression(
        request,
        partial,
        function,
        base,
        RuntimeExpressionRequest {
            expected: Some(receiver_ty),
            desired_result: None,
            access: AccessMode::Read,
        },
        state,
        is_cancelled,
    )?;
    let target = partial
        .functions
        .get(resolved.method.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let target_color = target.color;
    let target_result = target.result;
    let target_parameters = target
        .parameters
        .get(1..)
        .ok_or(AnalysisFailure::RequestMismatch)?
        .to_vec();
    let function_ty = ensure_function_type(
        request,
        partial,
        target_color,
        &target_parameters,
        target_result,
        &mut *state.aggregate_work,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: callee,
            ty: function_ty,
            result: None,
            resolution: ExpressionResolution::Function(resolved.method),
            effects: EffectSet(0),
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    let reservation_ty = partial
        .types
        .iter()
        .find(|ty| ty.kind == SemanticTypeKind::Reservation)
        .map(|ty| ty.id)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let reservation = expression_result(
        request,
        partial,
        function,
        (expression_id, resolved.source),
        reservation_ty,
        None,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: expression_id,
            ty: reservation_ty,
            result: Some(reservation),
            resolution: ExpressionResolution::ActorRequest {
                actor: resolved.actor,
                method: resolved.method,
                permit,
            },
            effects: EffectSet(EffectSet::ACTOR),
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Taken,
        },
    )?;
    Ok(RuntimeExpression {
        ty: reservation_ty,
        result: Some(reservation),
        referenced: None,
        effects: EffectSet(EffectSet::ACTOR),
    })
}

fn compound_assignment_binary_operator(
    operator: AssignmentOperator,
) -> Option<wrela_hir::BinaryOperator> {
    Some(match operator {
        AssignmentOperator::Assign => return None,
        AssignmentOperator::Add => wrela_hir::BinaryOperator::Add,
        AssignmentOperator::Subtract => wrela_hir::BinaryOperator::Subtract,
        AssignmentOperator::Multiply => wrela_hir::BinaryOperator::Multiply,
        AssignmentOperator::Divide => wrela_hir::BinaryOperator::Divide,
        AssignmentOperator::Remainder => wrela_hir::BinaryOperator::Remainder,
        AssignmentOperator::BitAnd => wrela_hir::BinaryOperator::BitAnd,
        AssignmentOperator::BitOr => wrela_hir::BinaryOperator::BitOr,
        AssignmentOperator::BitXor => wrela_hir::BinaryOperator::BitXor,
        AssignmentOperator::ShiftLeft => wrela_hir::BinaryOperator::ShiftLeft,
        AssignmentOperator::ShiftRight => wrela_hir::BinaryOperator::ShiftRight,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeScalarType {
    Bool,
    Integer { signed: bool, bits: u16 },
    Float { bits: u16 },
}

fn runtime_scalar_type(partial: &PartialAnalysis, ty: SemanticTypeId) -> Option<RuntimeScalarType> {
    match partial.types.get(ty.0 as usize)?.kind {
        SemanticTypeKind::Bool => Some(RuntimeScalarType::Bool),
        SemanticTypeKind::Integer { signed, bits, .. } => {
            Some(RuntimeScalarType::Integer { signed, bits })
        }
        SemanticTypeKind::Float { bits } => Some(RuntimeScalarType::Float { bits }),
        _ => None,
    }
}

fn known_runtime_expression_type(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    state: &mut RuntimeState<'_>,
    expression: ExpressionId,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<Option<SemanticTypeId>> {
    let Some(expression) = request.hir.as_program().expression(expression) else {
        return Ok(None);
    };
    Ok(match &expression.kind {
        ExpressionKind::Literal(Literal::Unit) => Some(SemanticTypeId(0)),
        ExpressionKind::Literal(Literal::Boolean(_)) => {
            let mut found = None;
            for ty in &partial.types {
                charge_runtime_aggregate_lookup(request, &mut *state.aggregate_work, is_cancelled)?;
                if ty.kind == SemanticTypeKind::Bool {
                    found = Some(ty.id);
                    break;
                }
            }
            found
        }
        ExpressionKind::Reference(Definition::Local(local)) => state
            .locals
            .get(local.0 as usize)
            .and_then(|binding| *binding)
            .and_then(|binding| partial.values.get(binding.value.0 as usize))
            .map(|value| value.ty),
        ExpressionKind::Reference(Definition::Parameter(parameter)) => state
            .parameters
            .get(parameter.0 as usize)
            .and_then(|binding| *binding)
            .and_then(|binding| partial.values.get(binding.value.0 as usize))
            .map(|value| value.ty),
        _ => None,
    })
}

fn require_scalar_temporary_access(
    request: &AnalysisRequest<'_>,
    source: Span,
    access: AccessMode,
) -> RuntimeResult<()> {
    if matches!(access, AccessMode::Value | AccessMode::Read) {
        Ok(())
    } else {
        Err(runtime_diagnostic(
            request,
            source,
            "semantic-access-temporary",
            "mutable or take access requires a named owned value",
            None,
            "a scalar operator result is a temporary value",
            "bind the result to a local before requesting exclusive access",
        ))
    }
}

fn analyze_scalar_unary(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    unary: RuntimeUnary,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    require_scalar_temporary_access(request, unary.source, expression_request.access)?;
    let operand = analyze_runtime_expression(
        request,
        partial,
        function,
        unary.operand,
        RuntimeExpressionRequest {
            expected: expression_request.expected,
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    let scalar = runtime_scalar_type(partial, operand.ty).ok_or_else(|| {
        runtime_type_diagnostic(
            request,
            unary.source,
            "semantic-unary-operand",
            "unary operator requires a primitive scalar operand",
            "the operand type has no built-in scalar unary meaning",
            "use bool, a fixed-width integer, a target-width integer, f32, or f64",
        )
    })?;
    let valid = match unary.operator {
        wrela_hir::UnaryOperator::Negate => matches!(
            scalar,
            RuntimeScalarType::Integer { signed: true, .. } | RuntimeScalarType::Float { .. }
        ),
        wrela_hir::UnaryOperator::BitNot => matches!(scalar, RuntimeScalarType::Integer { .. }),
        wrela_hir::UnaryOperator::BoolNot => scalar == RuntimeScalarType::Bool,
        wrela_hir::UnaryOperator::Await
        | wrela_hir::UnaryOperator::Take
        | wrela_hir::UnaryOperator::Copy
        | wrela_hir::UnaryOperator::Comptime => false,
    };
    if !valid {
        return Err(runtime_type_diagnostic(
            request,
            unary.source,
            "semantic-unary-type",
            "unary operator is not defined for this scalar type",
            "negation requires a signed integer or float, `~` requires an integer, and `not` requires bool",
            "change the operand type or choose the matching scalar operator",
        ));
    }
    let result = expression_result(
        request,
        partial,
        function,
        (unary.expression, unary.source),
        operand.ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: unary.expression,
            ty: operand.ty,
            result: Some(result),
            resolution: ExpressionResolution::Value(result),
            effects: operand.effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: operand.ty,
        result: Some(result),
        referenced: None,
        effects: operand.effects,
    })
}

fn analyze_scalar_binary(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    binary: RuntimeBinary,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    require_scalar_temporary_access(request, binary.source, expression_request.access)?;
    let comparison = matches!(binary.operator, RuntimeBinaryOperator::Compare(_));
    let operand_expected = if !comparison && expression_request.expected.is_some() {
        expression_request.expected
    } else {
        let known_left =
            known_runtime_expression_type(request, partial, state, binary.left, is_cancelled)?;
        let known_right = if known_left.is_none() {
            known_runtime_expression_type(request, partial, state, binary.right, is_cancelled)?
        } else {
            None
        };
        known_left.or(known_right)
    };
    let left = analyze_runtime_expression(
        request,
        partial,
        function,
        binary.left,
        RuntimeExpressionRequest {
            expected: operand_expected,
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    let right = analyze_runtime_expression(
        request,
        partial,
        function,
        binary.right,
        RuntimeExpressionRequest {
            expected: Some(left.ty),
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    if left.ty != right.ty {
        return Err(runtime_type_diagnostic(
            request,
            binary.source,
            "semantic-binary-type-mismatch",
            "binary operands must have exactly the same scalar type",
            "revision 0.1 performs no implicit numeric widening",
            "convert one operand explicitly with checked `as`",
        ));
    }
    let operand = runtime_scalar_type(partial, left.ty).ok_or_else(|| {
        runtime_type_diagnostic(
            request,
            binary.source,
            "semantic-binary-operand",
            "binary operator requires primitive scalar operands",
            "the operand type has no built-in scalar binary meaning",
            "use bool, integer, f32, or f64 operands",
        )
    })?;
    let valid = match binary.operator {
        RuntimeBinaryOperator::Arithmetic(operator) => match operator {
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
            | wrela_hir::BinaryOperator::ShiftLeftModular
            | wrela_hir::BinaryOperator::ShiftRight => {
                matches!(operand, RuntimeScalarType::Integer { .. })
            }
            wrela_hir::BinaryOperator::LogicalOr | wrela_hir::BinaryOperator::LogicalAnd => false,
        },
        RuntimeBinaryOperator::Compare(operator) => match operand {
            RuntimeScalarType::Bool => matches!(
                operator,
                wrela_hir::ComparisonOperator::Equal | wrela_hir::ComparisonOperator::NotEqual
            ),
            RuntimeScalarType::Integer { .. } | RuntimeScalarType::Float { .. } => true,
        },
    };
    if !valid {
        return Err(runtime_type_diagnostic(
            request,
            binary.source,
            "semantic-binary-type",
            "binary operator is not defined for this scalar type",
            "arithmetic, bitwise, and shifts require integers; bool supports equality only",
            "change the operands or choose an operator defined for their exact type",
        ));
    }
    let result_ty = if comparison {
        ensure_primitive_type(
            request,
            partial,
            PrimitiveSemanticType::Bool,
            &mut *state.aggregate_work,
            is_cancelled,
        )?
    } else {
        left.ty
    };
    if expression_request
        .expected
        .is_some_and(|expected| expected != result_ty)
    {
        return Err(runtime_type_diagnostic(
            request,
            binary.source,
            "semantic-binary-result",
            "binary result type does not match its required context",
            "comparisons produce bool and integer operators preserve their operand type",
            "change the context or convert the result explicitly",
        ));
    }
    let result = expression_result(
        request,
        partial,
        function,
        (binary.expression, binary.source),
        result_ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    let effects = EffectSet(left.effects.0 | right.effects.0);
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: binary.expression,
            ty: result_ty,
            result: Some(result),
            resolution: ExpressionResolution::Value(result),
            effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: result_ty,
        result: Some(result),
        referenced: None,
        effects,
    })
}

fn analyze_scalar_cast(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    cast: RuntimeCast<'_>,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    require_scalar_temporary_access(request, cast.source, expression_request.access)?;
    let destination = semantic_type_from_source(
        request,
        partial,
        cast.destination,
        &mut *state.aggregate_work,
        is_cancelled,
    )?;
    if expression_request
        .expected
        .is_some_and(|expected| expected != destination)
    {
        return Err(runtime_type_diagnostic(
            request,
            cast.source,
            "semantic-conversion-result",
            "conversion destination does not match its required context",
            "the explicit `as` type is the exact result type",
            "change the destination type or the surrounding type annotation",
        ));
    }
    let value = analyze_runtime_expression(
        request,
        partial,
        function,
        cast.value,
        RuntimeExpressionRequest {
            expected: None,
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    if runtime_scalar_type(partial, value.ty).is_none_or(|source| {
        !matches!(
            source,
            RuntimeScalarType::Integer { .. } | RuntimeScalarType::Float { .. }
        )
    }) || runtime_scalar_type(partial, destination).is_none_or(|destination| {
        !matches!(
            destination,
            RuntimeScalarType::Integer { .. } | RuntimeScalarType::Float { .. }
        )
    }) {
        return Err(runtime_type_diagnostic(
            request,
            cast.source,
            "semantic-conversion-type",
            "`as` requires numeric source and destination types",
            "revision 0.1 does not expose representations, brands, or enum discriminants through casts",
            "use an integer or floating-point destination",
        ));
    }
    let result = expression_result(
        request,
        partial,
        function,
        (cast.expression, cast.source),
        destination,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: cast.expression,
            ty: destination,
            result: Some(result),
            resolution: ExpressionResolution::Value(result),
            effects: value.effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: destination,
        result: Some(result),
        referenced: None,
        effects: value.effects,
    })
}

fn analyze_await_expression(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    await_expression: RuntimeAwait,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    let color = partial
        .functions
        .get(function.0 as usize)
        .map(|function| function.color)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if color != FunctionColor::Async {
        let mut diagnostic = Diagnostic::error(
            Category::ASYNC,
            await_expression.source,
            "only an async function may suspend at `await`",
        );
        diagnostic.code = Some("semantic-await-in-sync-function".to_owned());
        diagnostic
            .help
            .push("make the enclosing function async or remove the await".to_owned());
        return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
    }
    if !matches!(
        expression_request.access,
        AccessMode::Value | AccessMode::Read
    ) {
        return Err(runtime_diagnostic(
            request,
            await_expression.source,
            "semantic-access-temporary",
            "mutable or take access cannot target an awaited temporary",
            None,
            "await completion creates a new owned result value",
            "bind the awaited result before requesting exclusive access",
        ));
    }
    let awaited = analyze_runtime_expression(
        request,
        partial,
        function,
        await_expression.operand,
        RuntimeExpressionRequest {
            expected: expression_request.expected,
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    let target_is_async = partial
        .expressions
        .iter()
        .find(|fact| fact.function == function && fact.expression == await_expression.operand)
        .and_then(|fact| match fact.resolution {
            ExpressionResolution::DirectCall {
                function: target, ..
            }
            | ExpressionResolution::ActorRequest { method: target, .. } => Some(target),
            _ => None,
        })
        .and_then(|target| partial.functions.get(target.0 as usize))
        .is_some_and(|target| target.color == FunctionColor::Async);
    if !target_is_async {
        let mut diagnostic = Diagnostic::error(
            Category::ASYNC,
            await_expression.source,
            "await operand is not a statically known async activation",
        );
        diagnostic.code = Some("semantic-await-operand".to_owned());
        diagnostic.notes.push(
            "revision 0.1 admits only closed-world direct async calls and actor requests"
                .to_owned(),
        );
        return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
    }
    let result = expression_result(
        request,
        partial,
        function,
        (await_expression.expression, await_expression.source),
        awaited.ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    let effects = EffectSet(awaited.effects.0 | EffectSet::SUSPEND);
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: await_expression.expression,
            ty: awaited.ty,
            result: Some(result),
            resolution: ExpressionResolution::Builtin(IntrinsicOperation::Await),
            effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: awaited.ty,
        result: Some(result),
        referenced: None,
        effects,
    })
}

fn reference_operand(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    identity: (FunctionInstanceId, ExpressionId),
    mut binding: RuntimeBinding,
    expression_request: RuntimeExpressionRequest,
    slot: &mut Option<RuntimeBinding>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    let (function, expression) = identity;
    let source = request
        .hir
        .as_program()
        .expression(expression)
        .map(|expression| expression.source)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let (ty, before) = access_runtime_binding(
        request,
        partial,
        function,
        source,
        &mut binding,
        expression_request.expected,
        expression_request.access,
        expression_request.desired_result.is_some(),
        slot,
    )?;
    let result = expression_request
        .desired_result
        .map(|desired| {
            expression_result(
                request,
                partial,
                function,
                (expression, source),
                ty,
                Some(desired),
                is_cancelled,
            )
        })
        .transpose()?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression,
            ty,
            result,
            resolution: ExpressionResolution::Value(binding.value),
            effects: EffectSet(0),
            ownership_before: before,
            ownership_after: binding.state,
        },
    )?;
    Ok(RuntimeExpression {
        ty,
        result,
        referenced: Some(binding.value),
        effects: EffectSet(0),
    })
}

#[allow(clippy::too_many_arguments)]
fn access_runtime_binding(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    function: FunctionInstanceId,
    source: Span,
    binding: &mut RuntimeBinding,
    expected: Option<SemanticTypeId>,
    access: AccessMode,
    copy_requested: bool,
    slot: &mut Option<RuntimeBinding>,
) -> RuntimeResult<(SemanticTypeId, OwnershipState)> {
    let record = partial
        .values
        .get(binding.value.0 as usize)
        .filter(|record| record.function == function)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if expected.is_some_and(|expected| expected != record.ty) {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-scalar-type-mismatch",
            "scalar expression type does not match its required context",
            "revision 0.1 performs no implicit numeric conversion",
            "use an explicit checked `as` conversion",
        ));
    }
    let ty = record.ty;
    if copy_requested
        && partial
            .types
            .get(ty.0 as usize)
            .is_some_and(|ty| ty.linearity == Linearity::ExplicitCopy)
    {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-explicit-copy-required",
            "aggregate value cannot be implicitly copied into a new binding",
            "flat runtime structures preserve nominal ownership and require an explicit copy operation",
            "construct a fresh value, return the existing value, or use an explicitly supported copy form",
        ));
    }
    let before = binding.state;
    if before == OwnershipState::BorrowedMut {
        return Err(runtime_diagnostic(
            request,
            source,
            "semantic-compound-overlap",
            "compound assignment right-hand side overlaps its reserved destination",
            Some(*binding),
            "the destination place is reserved before the right-hand side is evaluated",
            "compute the right-hand side without reading, taking, or borrowing the destination local",
        ));
    }
    if before != OwnershipState::Owned {
        return Err(runtime_diagnostic(
            request,
            source,
            if access == AccessMode::Take {
                "semantic-double-take"
            } else {
                "semantic-use-after-take"
            },
            if access == AccessMode::Take {
                "value is taken more than once"
            } else {
                "value is used after ownership was taken"
            },
            Some(*binding),
            "take access leaves its source uninitialized",
            "reinitialize the value before using it again",
        ));
    }
    match access {
        AccessMode::Value | AccessMode::Read => {}
        AccessMode::Mutate if binding.authority == RuntimeAuthority::Read => {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-mutate-read-only",
                "cannot request mutable access through a read-only binding",
                Some(*binding),
                "read access permits observation but not mutation",
                "declare a mutable parameter or mutate an owned local instead",
            ));
        }
        AccessMode::Mutate => {}
        AccessMode::Take if binding.authority != RuntimeAuthority::Own => {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-take-borrowed",
                "cannot take ownership through a borrowed binding",
                Some(*binding),
                "read and mutable parameters return ownership to their caller",
                "declare the parameter with take access to transfer ownership",
            ));
        }
        AccessMode::Take => binding.state = OwnershipState::Taken,
    }
    *slot = Some(*binding);
    Ok((ty, before))
}

fn analyze_runtime_place(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    function: FunctionInstanceId,
    place: &wrela_hir::PlaceTarget,
    expected: SemanticTypeId,
    access: AccessMode,
    state: &mut RuntimeState<'_>,
) -> RuntimeResult<RuntimeExpression> {
    if !place.projections.is_empty() {
        return Err(runtime_type_diagnostic(
            request,
            place.source,
            "semantic-exclusive-place-projection",
            "projected exclusive call access is not yet supported",
            "the place is preserved explicitly, but aggregate place ownership lowering is not implemented",
            "bind the projected value to an owned local before passing it with `mut` or `take`",
        ));
    }
    let slot = match place.root {
        Definition::Local(local) => state.locals.get_mut(local.0 as usize),
        Definition::Parameter(parameter) => state.parameters.get_mut(parameter.0 as usize),
        _ => None,
    }
    .ok_or(AnalysisFailure::RequestMismatch)?;
    let mut binding = slot.ok_or(AnalysisFailure::RequestMismatch)?;
    let (ty, _) = access_runtime_binding(
        request,
        partial,
        function,
        place.source,
        &mut binding,
        Some(expected),
        access,
        false,
        slot,
    )?;
    Ok(RuntimeExpression {
        ty,
        result: None,
        referenced: Some(binding.value),
        effects: EffectSet(0),
    })
}

fn analyze_direct_call(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    call: RuntimeDirectCall<'_>,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    let callee_expression = request
        .hir
        .as_program()
        .expression(call.callee)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if let Some(resolved) =
        exact_resolved_enum_constructor(request.hir.as_program(), call.callee, is_cancelled)?
    {
        return analyze_closed_enum_constructor(
            request,
            partial,
            function,
            call,
            &resolved,
            expression_request,
            state,
            is_cancelled,
        );
    }
    let ExpressionKind::Reference(Definition::Declaration(resolved)) = &callee_expression.kind
    else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    if request
        .hir
        .as_program()
        .declaration(resolved.declaration)
        .is_some_and(|record| matches!(&record.kind, DeclarationKind::Structure(_)))
    {
        return analyze_flat_structure_constructor(
            request,
            partial,
            function,
            call,
            resolved.declaration,
            expression_request,
            state,
            is_cancelled,
        );
    }
    if request
        .hir
        .as_program()
        .declaration(resolved.declaration)
        .is_some_and(|record| matches!(&record.kind, DeclarationKind::Class(_)))
    {
        return Err(runtime_type_diagnostic(
            request,
            call.source,
            "semantic-class-construction-not-supported",
            "class construction is not yet supported by semantic analysis",
            "classes require the dedicated initializer protocol; they cannot use structure field construction",
            "remove the class construction call until initializer execution is implemented",
        ));
    }
    let target = ensure_ordinary_source_function(
        request,
        partial,
        resolved.declaration,
        state.allow_assertions,
        &mut *state.aggregate_work,
        is_cancelled,
    )?;
    if target == function {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    let target_record = partial
        .functions
        .get(target.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if u64::try_from(target_record.parameters.len())
        .map_or(true, |count| count > request.limits.fact_edges)
    {
        return Err(fact_resource(request, "direct-call target parameters").into());
    }
    let target_color = target_record.color;
    let target_result = target_record.result;
    let target_effects = target_record.effects;
    let mut target_parameters = Vec::new();
    target_parameters
        .try_reserve_exact(target_record.parameters.len())
        .map_err(|_| fact_resource(request, "direct-call target parameters"))?;
    for parameter in &target_record.parameters {
        check_cancelled(is_cancelled)?;
        target_parameters.push(*parameter);
    }
    if target_color == FunctionColor::Async {
        let caller_is_async = partial
            .functions
            .get(function.0 as usize)
            .is_some_and(|function| function.color == FunctionColor::Async);
        let mut await_parents = 0u32;
        for parent in &request.hir.as_program().expressions {
            check_cancelled(is_cancelled)?;
            if matches!(
                parent.kind,
                ExpressionKind::Unary {
                    operator: wrela_hir::UnaryOperator::Await,
                    operand,
                } if operand == call.expression
            ) {
                await_parents = await_parents
                    .checked_add(1)
                    .ok_or_else(|| fact_resource(request, "async await parents"))?;
            }
        }
        if !caller_is_async || await_parents != 1 {
            let mut diagnostic = Diagnostic::error(
                Category::ASYNC,
                call.source,
                if caller_is_async {
                    "async activation must be consumed by exactly one immediate await"
                } else {
                    "a synchronous function cannot directly activate async work"
                },
            );
            diagnostic.code = Some(if caller_is_async {
                "semantic-async-result-not-awaited".to_owned()
            } else {
                "semantic-async-call-in-sync-function".to_owned()
            });
            diagnostic.help.push(
                "await the call in an async function or install a statically bounded @task entry"
                    .to_owned(),
            );
            return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
        }
    }
    if expression_request
        .expected
        .is_some_and(|expected| expected != target_result)
        || call.arguments.len() != target_parameters.len()
    {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    let function_ty = ensure_function_type(
        request,
        partial,
        target_color,
        &target_parameters,
        target_result,
        &mut *state.aggregate_work,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.callee,
            ty: function_ty,
            result: None,
            resolution: ExpressionResolution::Function(target),
            effects: EffectSet(0),
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;

    let mut resolved_arguments =
        optional_call_map(call.arguments.len(), request.limits.fact_edges)?;
    let mut accesses: Vec<(ValueId, AccessMode, Span)> = Vec::new();
    accesses
        .try_reserve_exact(call.arguments.len())
        .map_err(|_| fact_resource(request, "direct-call ownership accesses"))?;
    for (source_index, argument) in call.arguments.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let parameter_index = match &argument.name {
            Some(name) => {
                let mut found = None;
                for (index, parameter) in target_parameters.iter().enumerate() {
                    check_cancelled(is_cancelled)?;
                    let matches = request
                        .hir
                        .as_program()
                        .parameters
                        .get(parameter.parameter.0 as usize)
                        .and_then(|parameter| parameter.name.as_ref())
                        .is_some_and(|parameter_name| parameter_name == name);
                    if matches && found.replace(index).is_some() {
                        return Err(AnalysisFailure::RequestMismatch.into());
                    }
                }
                found.ok_or(AnalysisFailure::RequestMismatch)?
            }
            None => source_index,
        };
        let target_parameter = target_parameters
            .get(parameter_index)
            .copied()
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let access = match (&argument.value, target_parameter.access) {
            (wrela_hir::CallArgumentValue::Value(_), AccessMode::Value | AccessMode::Read) => {
                target_parameter.access
            }
            (wrela_hir::CallArgumentValue::Exclusive { .. }, expected)
                if lower_access(argument.access()) == expected =>
            {
                expected
            }
            _ => {
                return Err(runtime_diagnostic(
                    request,
                    argument.source,
                    "semantic-access-marker-mismatch",
                    "call argument access does not match the parameter contract",
                    None,
                    "the source access marker must exactly name the callee parameter access",
                    "change the argument marker to match the declared parameter",
                ));
            }
        };
        let outcome = match &argument.value {
            wrela_hir::CallArgumentValue::Value(value) => analyze_runtime_expression(
                request,
                partial,
                function,
                *value,
                RuntimeExpressionRequest {
                    expected: Some(target_parameter.ty),
                    desired_result: None,
                    access: target_parameter.access,
                },
                state,
                is_cancelled,
            )?,
            wrela_hir::CallArgumentValue::Exclusive { place, .. } => analyze_runtime_place(
                request,
                partial,
                function,
                place,
                target_parameter.ty,
                target_parameter.access,
                state,
            )?,
        };
        if let Some(value) = outcome.referenced {
            let mut conflict = None;
            for previous in &accesses {
                check_cancelled(is_cancelled)?;
                if previous.0 == value && accesses_conflict(previous.1, target_parameter.access) {
                    conflict = Some(*previous);
                    break;
                }
            }
            if let Some((_, previous_access, previous_source)) = conflict {
                let binding =
                    runtime_binding_by_value(state.locals, state.parameters, value, is_cancelled)?;
                let mut diagnostic = runtime_ownership_diagnostic(
                    request,
                    argument.source,
                    "semantic-overlapping-access",
                    "one call requests overlapping exclusive access to the same value",
                    binding,
                    "mutable and take access are exclusive for the complete call",
                    "move one argument into a distinct local or use read access only",
                )?;
                diagnostic
                    .labels
                    .try_reserve(1)
                    .map_err(|_| fact_resource(request, "ownership diagnostic labels"))?;
                diagnostic.labels.insert(
                    0,
                    wrela_diagnostics::Label {
                        span: previous_source,
                        message: copy_static_analysis_text(
                            if previous_access == AccessMode::Mutate {
                                "the first mutable access begins here"
                            } else if previous_access == AccessMode::Take {
                                "the first ownership transfer begins here"
                            } else {
                                "the first overlapping read begins here"
                            },
                            request.limits.fact_bytes,
                        )?,
                    },
                );
                return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
            }
            accesses.push((value, target_parameter.access, argument.source));
        }
        let slot = resolved_arguments
            .get_mut(parameter_index)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if slot
            .replace(ResolvedCallArgument {
                source_index: u32::try_from(source_index)
                    .map_err(|_| fact_resource(request, "direct-call arguments"))?,
                parameter_index: u32::try_from(parameter_index)
                    .map_err(|_| fact_resource(request, "direct-call arguments"))?,
                access,
                value: outcome
                    .referenced
                    .or(outcome.result)
                    .ok_or(AnalysisFailure::RequestMismatch)?,
            })
            .is_some()
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }
    let mut exact_arguments = Vec::new();
    exact_arguments
        .try_reserve_exact(resolved_arguments.len())
        .map_err(|_| fact_resource(request, "direct-call arguments"))?;
    for argument in resolved_arguments {
        exact_arguments.push(argument.ok_or(AnalysisFailure::RequestMismatch)?);
    }
    let result = expression_result(
        request,
        partial,
        function,
        (call.expression, call.source),
        target_result,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.expression,
            ty: target_result,
            result: Some(result),
            resolution: ExpressionResolution::DirectCall {
                function: target,
                arguments: exact_arguments,
            },
            effects: target_effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: target_result,
        result: Some(result),
        referenced: None,
        effects: target_effects,
    })
}

#[allow(clippy::too_many_arguments)]
fn analyze_closed_enum_constructor(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    call: RuntimeDirectCall<'_>,
    resolved: &wrela_hir::ResolvedVariant,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    let declaration = request
        .hir
        .resolved_declaration(&resolved.enumeration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Enumeration(enumeration) = &declaration.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    let ty = if enumeration.generics.is_empty() {
        ensure_closed_scalar_enum_type(
            request,
            partial,
            resolved.enumeration.declaration,
            &mut *state.aggregate_work,
            is_cancelled,
        )?
    } else {
        if !is_exact_core_result_declaration(request, &resolved.enumeration, declaration) {
            return Err(runtime_type_diagnostic(
                request,
                call.source,
                "semantic-runtime-result-not-core",
                "generic enum constructor is not owned by authenticated core Result",
                "generic constructor specialization cannot be forged by another package",
                "use Result.Ok or Result.Err imported from core.result",
            ));
        }
        let Some(expected) = expression_request.expected else {
            return Err(runtime_type_diagnostic(
                request,
                call.source,
                "semantic-runtime-result-constructor-context",
                "core Result constructor requires an exact contextual Result[T, T] type",
                "R2 does not infer generic Result arguments from a context-free payload",
                "add an explicit Result[T, T] local, parameter, or return type",
            ));
        };
        let valid_expected = partial.types.get(expected.0 as usize).is_some_and(|record| {
            matches!(&record.kind, SemanticTypeKind::Enumeration {
                declaration,
                arguments,
                ..
            } if *declaration == resolved.enumeration.declaration
                && matches!(arguments.as_slice(), [SemanticArgument::Type(left), SemanticArgument::Type(right)] if left == right))
        });
        if !valid_expected {
            return Err(runtime_type_diagnostic(
                request,
                call.source,
                "semantic-runtime-result-constructor-context",
                "core Result constructor context is not the exact supported specialization",
                "the constructor must target authenticated Result[T, T] with one supported scalar T",
                "construct the Result variant in an explicit matching Result[T, T] context",
            ));
        }
        expected
    };
    if expression_request
        .expected
        .is_some_and(|expected| expected != ty)
    {
        return Err(runtime_type_diagnostic(
            request,
            call.source,
            "semantic-constructor-result-type",
            "enum constructor does not produce the required nominal type",
            "closed enum identities are never substituted by layout",
            "construct the exact enum named by the surrounding type",
        ));
    }
    let payload_ty = partial
        .types
        .get(ty.0 as usize)
        .and_then(|record| match &record.kind {
            SemanticTypeKind::Enumeration { variants, .. } => variants
                .get(resolved.variant as usize)
                .and_then(|variant| variant.fields.first())
                .map(|field| field.ty),
            _ => None,
        })
        .ok_or_else(|| {
            AnalysisFailure::InternalInvariant(
                "runtime enum constructor payload type is missing".to_owned(),
            )
        })?;
    let [argument] = call.arguments else {
        return Err(runtime_type_diagnostic(
            request,
            call.source,
            "semantic-runtime-enum-constructor-argument",
            "runtime enum constructor requires exactly one positional payload",
            "R1 variants have one shared scalar payload slot",
            "supply one positional scalar argument",
        ));
    };
    if argument.name.is_some() {
        return Err(runtime_type_diagnostic(
            request,
            argument.source,
            "semantic-runtime-enum-constructor-argument",
            "runtime enum constructor payload must be positional",
            "named payload arguments are not part of the canonical R1 representation",
            "remove the argument name",
        ));
    }
    let wrela_hir::CallArgumentValue::Value(payload_expression) = argument.value else {
        return Err(runtime_type_diagnostic(
            request,
            argument.source,
            "semantic-runtime-enum-constructor-access",
            "runtime enum constructor payload uses value access",
            "borrow, mutate, and take markers do not initialize the owned payload slot",
            "remove the access marker",
        ));
    };
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.callee,
            ty,
            result: None,
            resolution: ExpressionResolution::Constructor {
                ty,
                variant: Some(resolved.variant),
            },
            effects: EffectSet(0),
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    let payload = analyze_runtime_expression(
        request,
        partial,
        function,
        payload_expression,
        RuntimeExpressionRequest {
            expected: Some(payload_ty),
            desired_result: None,
            access: AccessMode::Value,
        },
        state,
        is_cancelled,
    )?;
    let result = expression_result(
        request,
        partial,
        function,
        (call.expression, call.source),
        ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.expression,
            ty,
            result: Some(result),
            resolution: ExpressionResolution::Constructor {
                ty,
                variant: Some(resolved.variant),
            },
            effects: payload.effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty,
        result: Some(result),
        referenced: None,
        effects: payload.effects,
    })
}

#[allow(clippy::too_many_arguments)]
fn analyze_flat_structure_constructor(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    call: RuntimeDirectCall<'_>,
    declaration: DeclarationId,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    check_cancelled(is_cancelled)?;
    let ty = ensure_flat_structure_type(
        request,
        partial,
        declaration,
        &mut *state.aggregate_work,
        is_cancelled,
    )?;
    if expression_request
        .expected
        .is_some_and(|expected| expected != ty)
    {
        return Err(runtime_type_diagnostic(
            request,
            call.source,
            "semantic-constructor-result-type",
            "structure constructor does not produce the required nominal type",
            "nominal structure identities are never substituted by layout",
            "construct the exact structure named by the surrounding type",
        ));
    }
    let program = request.hir.as_program();
    let record = program
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Structure(aggregate) = &record.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    if call.arguments.len() != aggregate.fields.len() {
        return Err(runtime_type_diagnostic(
            request,
            call.source,
            "semantic-runtime-constructor-argument",
            "runtime structure construction must supply every field exactly once",
            "defaults and partial aggregate initialization are outside the flat runtime structure subset",
            "supply one value for every declared field",
        ));
    }
    let semantic_fields = partial
        .types
        .get(ty.0 as usize)
        .and_then(|record| match &record.kind {
            SemanticTypeKind::Structure {
                declaration: candidate,
                fields,
                ..
            } if *candidate == declaration => Some(fields),
            _ => None,
        })
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let mut field_types = Vec::new();
    field_types
        .try_reserve_exact(semantic_fields.len())
        .map_err(|_| fact_resource(request, "runtime constructor field types"))?;
    for field in semantic_fields {
        charge_runtime_aggregate_lookup(request, &mut *state.aggregate_work, is_cancelled)?;
        field_types.push(field.ty);
    }
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.callee,
            ty,
            result: None,
            resolution: ExpressionResolution::Constructor { ty, variant: None },
            effects: EffectSet(0),
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;

    let caller_module = runtime_function_module(request, partial, function)?;
    let mut resolved = optional_call_map(aggregate.fields.len(), request.limits.fact_edges)?;
    let mut effects = EffectSet(0);
    for (source_index, argument) in call.arguments.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let wrela_hir::CallArgumentValue::Value(argument_value) = &argument.value else {
            return Err(runtime_type_diagnostic(
                request,
                argument.source,
                "semantic-runtime-constructor-access",
                "runtime structure constructor fields use value access",
                "borrow, mutate, and take markers do not describe aggregate field initialization",
                "remove the access marker from this constructor argument",
            ));
        };
        if aggregate.fields.len() != 1 && argument.name.is_none() {
            return Err(runtime_type_diagnostic(
                request,
                argument.source,
                "semantic-runtime-constructor-argument",
                "a runtime structure with multiple fields requires named constructor arguments",
                "named fields make source-to-layout ordering explicit and deterministic",
                "name every constructor argument",
            ));
        }
        let field_index = if let Some(name) = &argument.name {
            let mut selected = None;
            for (index, field) in aggregate.fields.iter().enumerate() {
                charge_runtime_aggregate_lookup(request, &mut *state.aggregate_work, is_cancelled)?;
                if field.name == *name && selected.replace(index).is_some() {
                    return Err(runtime_type_diagnostic(
                        request,
                        argument.source,
                        "semantic-runtime-constructor-argument",
                        "runtime structure field name is ambiguous",
                        "constructor field selection requires one exact declaration",
                        "remove the duplicate field declaration",
                    ));
                }
            }
            selected.ok_or_else(|| {
                runtime_type_diagnostic(
                    request,
                    argument.source,
                    "semantic-runtime-constructor-argument",
                    "runtime constructor argument does not name a declared field",
                    "field names are matched exactly and nominally",
                    "use one of the structure's declared field names",
                )
            })?
        } else {
            source_index
        };
        let field = aggregate
            .fields
            .get(field_index)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if caller_module != record.module && field.visibility == wrela_hir::Visibility::Private {
            return Err(runtime_type_diagnostic(
                request,
                argument.source,
                "semantic-runtime-field-private",
                "runtime structure field is private to its declaring module",
                "construction from another module may initialize only visible fields",
                "make the field public or construct the value inside its declaring module",
            ));
        }
        let slot = resolved
            .get_mut(field_index)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if slot.is_some() {
            return Err(runtime_type_diagnostic(
                request,
                argument.source,
                "semantic-runtime-constructor-argument",
                "runtime constructor supplies one field more than once",
                "each field has exactly one deterministic initializer",
                "remove the duplicate field argument",
            ));
        }
        let outcome = analyze_runtime_expression(
            request,
            partial,
            function,
            *argument_value,
            RuntimeExpressionRequest {
                expected: field_types.get(field_index).copied(),
                desired_result: None,
                access: AccessMode::Value,
            },
            state,
            is_cancelled,
        )?;
        effects.0 |= outcome.effects.0;
        *slot = Some(ResolvedCallArgument {
            source_index: u32::try_from(source_index)
                .map_err(|_| fact_resource(request, "runtime constructor arguments"))?,
            parameter_index: u32::try_from(field_index)
                .map_err(|_| fact_resource(request, "runtime constructor arguments"))?,
            access: AccessMode::Value,
            value: outcome
                .referenced
                .or(outcome.result)
                .ok_or(AnalysisFailure::RequestMismatch)?,
        });
    }
    for field in &resolved {
        charge_runtime_aggregate_lookup(request, &mut *state.aggregate_work, is_cancelled)?;
        if field.is_none() {
            return Err(runtime_type_diagnostic(
                request,
                call.source,
                "semantic-runtime-constructor-argument",
                "runtime structure construction must supply every field exactly once",
                "one or more declared fields have no initializer",
                "supply one value for every declared field",
            ));
        }
    }
    let result = expression_result(
        request,
        partial,
        function,
        (call.expression, call.source),
        ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression: call.expression,
            ty,
            result: Some(result),
            resolution: ExpressionResolution::Constructor { ty, variant: None },
            effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty,
        result: Some(result),
        referenced: None,
        effects,
    })
}

#[allow(clippy::too_many_arguments)]
fn analyze_flat_structure_field(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    expression: ExpressionId,
    source: Span,
    base: ExpressionId,
    name: &wrela_hir::Name,
    expression_request: RuntimeExpressionRequest,
    state: &mut RuntimeState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<RuntimeExpression> {
    if !matches!(
        expression_request.access,
        AccessMode::Value | AccessMode::Read
    ) {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-field-access",
            "flat runtime field projection supports read access only",
            "projected mutation and ownership transfer require place-level aggregate lowering",
            "read the field value or reconstruct the enclosing structure",
        ));
    }
    let base_value = analyze_runtime_expression(
        request,
        partial,
        function,
        base,
        RuntimeExpressionRequest {
            expected: None,
            desired_result: None,
            access: AccessMode::Read,
        },
        state,
        is_cancelled,
    )?;
    let (declaration, field_index, field_ty) = {
        let record = partial
            .types
            .get(base_value.ty.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let SemanticTypeKind::Structure {
            declaration,
            fields,
            ..
        } = &record.kind
        else {
            return Err(runtime_type_diagnostic(
                request,
                source,
                "semantic-runtime-field-base",
                "field projection requires a supported flat runtime structure",
                "scalar and unsupported aggregate values do not have runtime fields",
                "project a field from a nongeneric structure with scalar fields",
            ));
        };
        let mut selected = None;
        for (index, field) in fields.iter().enumerate() {
            charge_runtime_aggregate_lookup(request, &mut *state.aggregate_work, is_cancelled)?;
            if field.name == name.as_str() && selected.replace(index).is_some() {
                return Err(runtime_type_diagnostic(
                    request,
                    source,
                    "semantic-runtime-field",
                    "runtime structure field name is ambiguous",
                    "field selection requires one exact declaration",
                    "remove the duplicate field declaration",
                ));
            }
        }
        let index = selected.ok_or_else(|| {
            runtime_type_diagnostic(
                request,
                source,
                "semantic-runtime-field",
                "runtime structure does not declare the selected field",
                "field names are matched exactly and nominally",
                "select one of the structure's declared fields",
            )
        })?;
        (*declaration, index, fields[index].ty)
    };
    let declaration_record = request
        .hir
        .as_program()
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Structure(aggregate) = &declaration_record.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    let field = aggregate
        .fields
        .get(field_index)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if runtime_function_module(request, partial, function)? != declaration_record.module
        && field.visibility == wrela_hir::Visibility::Private
    {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-field-private",
            "runtime structure field is private to its declaring module",
            "field projection from another module preserves source visibility",
            "expose a public accessor from the declaring module",
        ));
    }
    if expression_request
        .expected
        .is_some_and(|expected| expected != field_ty)
    {
        return Err(runtime_type_diagnostic(
            request,
            source,
            "semantic-runtime-field-type",
            "projected field does not match its required type",
            "runtime structure fields preserve their exact declared scalar types",
            "use the field in a matching context",
        ));
    }
    let result = expression_result(
        request,
        partial,
        function,
        (expression, source),
        field_ty,
        expression_request.desired_result,
        is_cancelled,
    )?;
    let index = u32::try_from(field_index)
        .map_err(|_| fact_resource(request, "runtime structure fields"))?;
    append_expression_fact(
        request,
        partial,
        RuntimeExpressionFact {
            function,
            expression,
            ty: field_ty,
            result: Some(result),
            resolution: ExpressionResolution::Field { index },
            effects: base_value.effects,
            ownership_before: OwnershipState::Owned,
            ownership_after: OwnershipState::Owned,
        },
    )?;
    Ok(RuntimeExpression {
        ty: field_ty,
        result: Some(result),
        referenced: None,
        effects: base_value.effects,
    })
}

fn runtime_function_module(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    function: FunctionInstanceId,
) -> RuntimeResult<wrela_package::ModuleId> {
    let declaration = partial
        .functions
        .get(function.0 as usize)
        .and_then(|function| match function.origin {
            FunctionOrigin::Source { declaration, .. } => Some(declaration),
            _ => None,
        })
        .ok_or(AnalysisFailure::RequestMismatch)?;
    request
        .hir
        .as_program()
        .declaration(declaration)
        .map(|declaration| declaration.module)
        .ok_or(AnalysisFailure::RequestMismatch.into())
}

fn ensure_ordinary_source_function(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    declaration: DeclarationId,
    allow_assertions: bool,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<FunctionInstanceId> {
    for existing in &partial.functions {
        check_cancelled(is_cancelled)?;
        if matches!(
            existing.origin,
            FunctionOrigin::Source {
                declaration: candidate,
                ..
            } if candidate == declaration
        ) {
            return Ok(existing.id);
        }
    }
    check_cancelled(is_cancelled)?;
    let declaration_record = request
        .hir
        .as_program()
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Function(source_function) = &declaration_record.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    let body = source_function
        .body
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if !matches!(
        source_function.color,
        FunctionColor::Sync | FunctionColor::Async
    ) || !source_function.generics.is_empty()
    {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    let mut body_statements = Vec::new();
    let mut body_callees = Vec::new();
    match inspect_runtime_body_shape(
        request,
        body,
        source_function.color,
        allow_assertions,
        &mut body_statements,
        &mut body_callees,
        is_cancelled,
    ) {
        Ok(()) => {}
        Err(RuntimeShapeFailure::Unsupported(source)) => {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-runtime-function-body-not-supported",
                "function body is outside the revision 0.1 ownership subset",
                None,
                "loops, awaits, closures, actors, and indirect calls are rejected by this path",
                "use scalar locals, direct calls, named arguments, and conditionals only",
            ));
        }
        Err(RuntimeShapeFailure::UnsupportedAssertion(source)) => {
            return Err(runtime_diagnostic(
                request,
                source,
                "semantic-runtime-assertion-not-supported",
                "runtime assertions are supported only in selected generated tests",
                None,
                "ordinary images and actor turns cannot yet abandon and supervise an assertion-failed activation",
                "move this assertion into a selected @test function",
            ));
        }
        Err(RuntimeShapeFailure::Failure(error)) => return Err(error.into()),
    }
    if source_function.color == FunctionColor::Async {
        let closure = collect_source_body_closure(request.hir.as_program(), body, is_cancelled)?;
        let mut first_await = None;
        for expression in closure.expressions {
            check_cancelled(is_cancelled)?;
            let expression = request
                .hir
                .as_program()
                .expression(expression)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            if matches!(
                expression.kind,
                ExpressionKind::Unary {
                    operator: wrela_hir::UnaryOperator::Await,
                    ..
                }
            ) {
                first_await = Some(expression.source);
                break;
            }
        }
        if let Some(await_source) = first_await {
            for parameter_id in &source_function.parameters {
                check_cancelled(is_cancelled)?;
                let parameter = request
                    .hir
                    .as_program()
                    .parameter(*parameter_id)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                if matches!(
                    parameter.access,
                    wrela_hir::AccessMode::Read | wrela_hir::AccessMode::Mutate
                ) || parameter
                    .ty
                    .as_ref()
                    .is_some_and(|ty| matches!(ty.kind, TypeExpressionKind::View { .. }))
                {
                    let mut diagnostic = Diagnostic::error(
                        Category::ASYNC,
                        await_source,
                        "borrowed access may not remain live across suspension",
                    );
                    diagnostic.code = Some("semantic-view-across-await".to_owned());
                    diagnostic
                        .labels
                        .try_reserve_exact(1)
                        .map_err(|_| fact_resource(request, "async diagnostic labels"))?;
                    diagnostic.labels.push(wrela_diagnostics::Label {
                        span: parameter.source,
                        message: "this loan belongs to the caller".to_owned(),
                    });
                    diagnostic.help.push(
                        "copy or take the required value before await, then reacquire any view afterward"
                            .to_owned(),
                    );
                    return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
                }
            }
        }
    }
    let result = match source_function.result.as_ref() {
        Some(result) => {
            semantic_type_from_source(request, partial, result, &mut *aggregate_work, is_cancelled)?
        }
        None => SemanticTypeId(0),
    };
    let proof_count = if source_function.color == FunctionColor::Async {
        4usize
    } else {
        2usize
    };
    if partial.functions.len() >= request.limits.monomorphizations as usize
        || partial
            .proofs
            .len()
            .checked_add(proof_count)
            .is_none_or(|count| count > request.limits.proofs as usize)
    {
        return Err(fact_resource(request, "ordinary source functions").into());
    }
    let function_id = FunctionInstanceId(
        u32::try_from(partial.functions.len())
            .map_err(|_| fact_resource(request, "ordinary source functions"))?,
    );
    let type_proof = ProofId(
        u32::try_from(partial.proofs.len())
            .map_err(|_| fact_resource(request, "ordinary source proofs"))?,
    );
    let effect_proof = ProofId(
        type_proof
            .0
            .checked_add(1)
            .ok_or_else(|| fact_resource(request, "ordinary source proofs"))?,
    );
    let name = copy_test_name(request, declaration, is_cancelled)?;
    partial
        .proofs
        .try_reserve(proof_count)
        .map_err(|_| fact_resource(request, "ordinary source proofs"))?;
    partial.proofs.push(Proof {
        id: type_proof,
        kind: ProofKind::TypeChecked,
        subject: bounded_test_fact(request, "function type: ", &name, is_cancelled)?,
        sources: vec![declaration_record.source],
        depends_on: Vec::new(),
        bound: None,
        explanation: vec!["the scalar source function body is well typed".to_owned()],
    });
    partial.proofs.push(Proof {
        id: effect_proof,
        kind: ProofKind::EffectsAllowed,
        subject: bounded_test_fact(request, "function effects: ", &name, is_cancelled)?,
        sources: vec![declaration_record.source],
        depends_on: vec![type_proof],
        bound: Some(
            u64::try_from(body_statements.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| fact_resource(request, "ordinary source work bound"))?,
        ),
        explanation: vec![if source_function.color == FunctionColor::Async {
            "the closed async body may suspend only at statically resolved direct calls".to_owned()
        } else if allow_assertions {
            "the selected test helper admits only bounded scalar effects and MAY_FAIL assertion paths"
                .to_owned()
        } else {
            "the scalar source body has no source-visible effects".to_owned()
        }],
    });
    let mut function_proofs = vec![type_proof, effect_proof];
    if source_function.color == FunctionColor::Async {
        let view_proof = ProofId(
            effect_proof
                .0
                .checked_add(1)
                .ok_or_else(|| fact_resource(request, "ordinary source proofs"))?,
        );
        let cleanup_proof = ProofId(
            view_proof
                .0
                .checked_add(1)
                .ok_or_else(|| fact_resource(request, "ordinary source proofs"))?,
        );
        partial.proofs.push(Proof {
            id: view_proof,
            kind: ProofKind::ViewDoesNotEscape,
            subject: bounded_test_fact(
                request,
                "async suspension safety: ",
                &name,
                is_cancelled,
            )?,
            sources: vec![declaration_record.source],
            depends_on: vec![type_proof],
            bound: Some(0),
            explanation: vec![
                "the supported async body carries no borrowed view or external mutable loan across suspension"
                    .to_owned(),
            ],
        });
        partial.proofs.push(Proof {
            id: cleanup_proof,
            kind: ProofKind::CleanupAcyclic,
            subject: bounded_test_fact(
                request,
                "async cancellation cleanup: ",
                &name,
                is_cancelled,
            )?,
            sources: vec![declaration_record.source],
            depends_on: vec![type_proof, view_proof],
            bound: Some(
                u64::try_from(source_function.parameters.len())
                    .map_err(|_| fact_resource(request, "async cleanup bound"))?,
            ),
            explanation: vec![
                "cancellation observes a fixed frame state and destroys owned scalar values in reverse source order"
                    .to_owned(),
            ],
        });
        function_proofs.extend([view_proof, cleanup_proof]);
    }

    let mut semantic_parameters = Vec::new();
    semantic_parameters
        .try_reserve_exact(source_function.parameters.len())
        .map_err(|_| fact_resource(request, "ordinary source parameters"))?;
    for parameter_id in &source_function.parameters {
        let parameter = request
            .hir
            .as_program()
            .parameters
            .get(parameter_id.0 as usize)
            .filter(|parameter| parameter.id == *parameter_id)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let ty = semantic_type_from_source(
            request,
            partial,
            parameter
                .ty
                .as_ref()
                .ok_or(AnalysisFailure::RequestMismatch)?,
            &mut *aggregate_work,
            is_cancelled,
        )?;
        let value = append_semantic_value(
            request,
            partial,
            function_id,
            ty,
            (
                SemanticValueOrigin::Parameter(*parameter_id),
                Some(parameter.source),
                parameter.name.as_ref().map(wrela_hir::Name::as_str),
            ),
            is_cancelled,
        )?;
        semantic_parameters.push(FunctionParameter {
            parameter: *parameter_id,
            value,
            access: lower_access(parameter.access),
            ty,
        });
    }
    partial
        .functions
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "ordinary source functions"))?;
    let work_bound = u64::try_from(body_statements.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| fact_resource(request, "ordinary source work bound"))?;
    partial.functions.push(FunctionInstance {
        id: function_id,
        key: source_test_key(request, declaration),
        name,
        origin: FunctionOrigin::Source { declaration, body },
        role: FunctionRole::Ordinary,
        color: source_function.color,
        generic_arguments: Vec::new(),
        parameters: semantic_parameters,
        result,
        effects: EffectSet(if source_function.color == FunctionColor::Async {
            EffectSet::SUSPEND
        } else {
            0
        }),
        stack_bytes_bound: 0,
        frame_bytes_bound: if source_function.color == FunctionColor::Async {
            16
        } else {
            0
        },
        uninterrupted_work_bound: Some(work_bound),
        recursive_depth_bound: Some(1),
        proofs: function_proofs,
        source: Some(declaration_record.source),
    });
    populate_runtime_body(
        request,
        partial,
        RuntimeBodyTarget {
            function: function_id,
            declaration,
            body,
            allow_assertions,
        },
        aggregate_work,
        is_cancelled,
    )?;
    Ok(function_id)
}

fn append_expression_fact(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    fact: RuntimeExpressionFact,
) -> Result<(), AnalysisFailure> {
    if partial.expressions.len() >= request.limits.expression_facts as usize {
        return Err(fact_resource(request, "expression facts"));
    }
    let proofs = copy_function_proofs(request, partial, fact.function)?;
    partial
        .expressions
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "expression facts"))?;
    partial.expressions.push(ExpressionFact {
        function: fact.function,
        expression: fact.expression,
        ty: fact.ty,
        category: ValueCategory::Value,
        region: None,
        effects: fact.effects,
        resolution: fact.resolution,
        result: fact.result,
        ownership_before: fact.ownership_before,
        ownership_after: fact.ownership_after,
        proofs,
    });
    Ok(())
}

fn append_statement_fact(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    statement: StatementId,
    post: RuntimeStatementPost<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let RuntimeStatementPost {
        effects,
        definitions,
        locals,
        parameters,
    } = post;
    if partial.statements.len() >= request.limits.statement_facts as usize {
        return Err(fact_resource(request, "statement facts"));
    }
    let proofs = copy_function_proofs(request, partial, function)?;
    let mut initialized_after = Vec::new();
    let capacity = locals
        .len()
        .checked_add(parameters.len())
        .ok_or_else(|| fact_resource(request, "statement initialized values"))?;
    if u64::try_from(capacity).map_or(true, |capacity| capacity > request.limits.fact_edges) {
        return Err(fact_resource(request, "statement initialized values"));
    }
    initialized_after
        .try_reserve_exact(capacity)
        .map_err(|_| fact_resource(request, "statement initialized values"))?;
    initialized_after.extend(
        parameters
            .iter()
            .chain(locals)
            .flatten()
            .filter(|binding| binding.state == OwnershipState::Owned)
            .map(|binding| binding.value),
    );
    cancellable_stable_sort_by(
        &mut initialized_after,
        request.limits.fact_edges,
        "statement initialized-value sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )?;
    cancellable_dedup(&mut initialized_after, is_cancelled)?;
    let mut moved_after = Vec::new();
    moved_after
        .try_reserve_exact(capacity)
        .map_err(|_| fact_resource(request, "statement moved values"))?;
    moved_after.extend(
        parameters
            .iter()
            .chain(locals)
            .flatten()
            .filter(|binding| binding.state == OwnershipState::Taken)
            .map(|binding| binding.value),
    );
    cancellable_stable_sort_by(
        &mut moved_after,
        request.limits.fact_edges,
        "statement moved-value sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )?;
    cancellable_dedup(&mut moved_after, is_cancelled)?;
    partial
        .statements
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "statement facts"))?;
    partial.statements.push(StatementFact {
        function,
        statement,
        effects,
        definitions,
        initialized_after,
        moved_after,
        live_loans_after: Vec::new(),
        proofs,
    });
    Ok(())
}

fn expression_result(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    location: (ExpressionId, Span),
    ty: SemanticTypeId,
    desired: Option<ValueId>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValueId, AnalysisFailure> {
    let (expression, source) = location;
    if let Some(value) = desired {
        let record = partial
            .values
            .get(value.0 as usize)
            .filter(|record| record.function == function && record.ty == ty)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let origin_matches = match record.origin {
            SemanticValueOrigin::Local(_) => true,
            SemanticValueOrigin::Expression(candidate) => candidate == expression,
            SemanticValueOrigin::Parameter(_) => false,
        };
        if !origin_matches {
            return Err(AnalysisFailure::RequestMismatch);
        }
        Ok(value)
    } else {
        append_semantic_value(
            request,
            partial,
            function,
            ty,
            (
                SemanticValueOrigin::Expression(expression),
                Some(source),
                None,
            ),
            is_cancelled,
        )
    }
}

fn append_semantic_value(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    function: FunctionInstanceId,
    ty: SemanticTypeId,
    description: (SemanticValueOrigin, Option<Span>, Option<&str>),
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValueId, AnalysisFailure> {
    let (origin, source, name) = description;
    if partial.values.len() >= request.limits.values as usize {
        return Err(fact_resource(request, "semantic values"));
    }
    let id = ValueId(
        u32::try_from(partial.values.len())
            .map_err(|_| fact_resource(request, "semantic values"))?,
    );
    let source_name = name
        .map(|name| copy_analysis_text(name, request.limits.fact_bytes, is_cancelled))
        .transpose()?;
    partial
        .values
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic values"))?;
    partial.values.push(SemanticValue {
        id,
        function,
        ty,
        category: ValueCategory::Value,
        origin,
        source,
        source_name,
    });
    Ok(id)
}

fn copy_function_proofs(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    function: FunctionInstanceId,
) -> Result<Vec<ProofId>, AnalysisFailure> {
    let source = &partial
        .functions
        .get(function.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?
        .proofs;
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(source.len())
        .map_err(|_| fact_resource(request, "fact proof edges"))?;
    proofs.extend_from_slice(source);
    Ok(proofs)
}

#[derive(Debug, Clone, Copy)]
enum PrimitiveSemanticType {
    Bool,
    Integer {
        signed: bool,
        bits: u16,
        pointer_sized: bool,
    },
    Float {
        bits: u16,
    },
}

fn semantic_type_from_source(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    source: &TypeExpression,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<SemanticTypeId> {
    match &source.kind {
        TypeExpressionKind::Named {
            definition: Definition::Builtin(Builtin::Unit),
            arguments,
        } if arguments.is_empty() => Ok(SemanticTypeId(0)),
        TypeExpressionKind::Named {
            definition: Definition::Builtin(Builtin::Bool),
            arguments,
        } if arguments.is_empty() => Ok(ensure_primitive_type(
            request,
            partial,
            PrimitiveSemanticType::Bool,
            &mut *aggregate_work,
            is_cancelled,
        )?),
        TypeExpressionKind::Named {
            definition: Definition::Builtin(builtin),
            arguments,
        } if arguments.is_empty() => {
            let Some(primitive) = primitive_from_builtin(request, *builtin) else {
                return Err(runtime_diagnostic(
                    request,
                    source.source,
                    "semantic-runtime-type-not-supported",
                    "type is outside the revision 0.1 runtime scalar subset",
                    None,
                    "this path requires a primitive boolean, integer, or floating-point type",
                    "use an explicitly supported scalar type",
                ));
            };
            Ok(ensure_primitive_type(
                request,
                partial,
                primitive,
                &mut *aggregate_work,
                is_cancelled,
            )?)
        }
        TypeExpressionKind::Named {
            definition: Definition::Declaration(resolved),
            arguments,
        } => {
            let declaration = request
                .hir
                .resolved_declaration(resolved)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            if matches!(declaration.kind, DeclarationKind::Enumeration(_)) {
                return if arguments.is_empty() {
                    ensure_closed_scalar_enum_type(
                        request,
                        partial,
                        declaration.id,
                        &mut *aggregate_work,
                        is_cancelled,
                    )
                } else {
                    ensure_core_result_type(
                        request,
                        partial,
                        resolved,
                        arguments,
                        &mut *aggregate_work,
                        is_cancelled,
                    )
                };
            }
            if !arguments.is_empty() {
                return Err(runtime_type_diagnostic(
                    request,
                    source.source,
                    "semantic-runtime-generic-type-not-supported",
                    "runtime generic type is outside the authenticated core Result specialization",
                    "revision R2 admits only core.result.Result[T, E] under its exact scalar contract",
                    "use core.result.Result with two identical supported copy-scalar arguments",
                ));
            }
            if !matches!(declaration.kind, DeclarationKind::Structure(_)) {
                return Err(runtime_type_diagnostic(
                    request,
                    source.source,
                    "semantic-runtime-type-not-supported",
                    "nominal runtime type is outside the flat structure subset",
                    "revision 0.1 admits only nongeneric structures whose fields are supported scalars",
                    "use a flat scalar-backed structure or a supported primitive type",
                ));
            }
            ensure_flat_structure_type(
                request,
                partial,
                declaration.id,
                &mut *aggregate_work,
                is_cancelled,
            )
        }
        TypeExpressionKind::View { .. } => Err(runtime_diagnostic(
            request,
            source.source,
            "semantic-view-escape",
            "borrowed view cannot escape into revision 0.1 runtime value state",
            None,
            "runtime parameters, results, and branch-joined locals outlive this bounded view model",
            "pass the owned scalar value or keep the view inside an explicitly scoped borrow",
        )),
        _ => Err(runtime_diagnostic(
            request,
            source.source,
            "semantic-runtime-type-not-supported",
            "type is outside the revision 0.1 runtime ownership subset",
            None,
            "this path currently proves primitive scalar runtime value state",
            "use a supported scalar type until aggregate ownership lowering is available",
        )),
    }
}

fn ensure_core_result_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    resolved: &wrela_hir::ResolvedDeclaration,
    arguments: &[wrela_hir::GenericArgument],
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<SemanticTypeId> {
    let record = request
        .hir
        .resolved_declaration(resolved)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if !is_exact_core_result_declaration(request, resolved, record) {
        return Err(runtime_type_diagnostic(
            request,
            record.source,
            "semantic-runtime-result-not-core",
            "runtime generic enum is not the authenticated core Result declaration",
            "user and dependency packages cannot forge the core.result.Result specialization authority",
            "import Result from core.result",
        ));
    }
    let [ok_argument, err_argument] = arguments else {
        return Err(runtime_type_diagnostic(
            request,
            record.source,
            "semantic-runtime-result-argument-count",
            "core Result requires exactly two runtime type arguments",
            "R2 specializes Result[T, E] only after both type arguments are resolved",
            "supply Result[T, E] with two identical supported copy-scalar types",
        ));
    };
    let ok =
        core_result_scalar_argument(request, partial, ok_argument, aggregate_work, is_cancelled)?;
    let err =
        core_result_scalar_argument(request, partial, err_argument, aggregate_work, is_cancelled)?;
    if ok != err {
        return Err(runtime_type_diagnostic(
            request,
            err_argument.source,
            "semantic-runtime-result-payload-mismatch",
            "core Result runtime arguments must resolve to the identical scalar type",
            "the current canonical tagged representation has one shared payload slot",
            "use the same supported copy-scalar type for T and E",
        ));
    }
    let semantic_arguments = [SemanticArgument::Type(ok), SemanticArgument::Type(err)];
    for existing in &partial.types {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if matches!(&existing.kind, SemanticTypeKind::Enumeration {
            declaration,
            arguments,
            ..
        } if *declaration == record.id && arguments.as_slice() == semantic_arguments)
        {
            return Ok(existing.id);
        }
    }
    let payload = partial
        .types
        .get(ok.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let alignment = payload.alignment_lower_bound.max(1);
    let offset = (1_u64 + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
    let size = offset
        .checked_add(
            payload
                .size_upper_bound
                .ok_or(AnalysisFailure::RequestMismatch)?,
        )
        .and_then(|size| size.checked_add(u64::from(alignment) - 1))
        .map(|size| size & !(u64::from(alignment) - 1))
        .ok_or_else(|| fact_resource(request, "runtime Result layout"))?;
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "semantic types").into());
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len()).map_err(|_| fact_resource(request, "semantic types"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic types"))?;
    partial.types.push(SemanticType {
        id,
        kind: SemanticTypeKind::Enumeration {
            declaration: record.id,
            arguments: semantic_arguments.to_vec(),
            variants: ["Ok", "Err"]
                .into_iter()
                .map(|name| SemanticVariant {
                    name: name.to_owned(),
                    fields: vec![SemanticField {
                        name: String::new(),
                        ty: ok,
                        public: true,
                    }],
                })
                .collect(),
        },
        linearity: Linearity::ExplicitCopy,
        size_upper_bound: Some(size),
        alignment_lower_bound: alignment,
        source: Some(record.source),
    });
    Ok(id)
}

fn core_result_scalar_argument(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    argument: &wrela_hir::GenericArgument,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<SemanticTypeId> {
    let wrela_hir::GenericArgumentKind::Type(source) = &argument.kind else {
        return Err(runtime_type_diagnostic(
            request,
            argument.source,
            "semantic-runtime-result-argument-type",
            "core Result runtime arguments must be types",
            "constant, region, capacity, and unresolved arguments are outside R2",
            "supply two identical supported copy-scalar type arguments",
        ));
    };
    if !matches!(&source.kind, TypeExpressionKind::Named {
        definition: Definition::Builtin(_),
        arguments,
    } if arguments.is_empty())
    {
        return Err(runtime_type_diagnostic(
            request,
            source.source,
            "semantic-runtime-result-argument-type",
            "core Result runtime argument is not a supported copy scalar",
            "nominal, nested generic, view, tuple, and function types require later specialization semantics",
            "use bool, an integer type, or f32/f64",
        ));
    }
    let ty = semantic_type_from_source(request, partial, source, aggregate_work, is_cancelled)?;
    let record = partial
        .types
        .get(ty.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if record.linearity != Linearity::ScalarCopy
        || !matches!(
            record.kind,
            SemanticTypeKind::Bool
                | SemanticTypeKind::Integer { .. }
                | SemanticTypeKind::Float { bits: 32 | 64 }
        )
    {
        return Err(runtime_type_diagnostic(
            request,
            source.source,
            "semantic-runtime-result-argument-type",
            "core Result runtime argument is not a supported stored copy scalar",
            "unit and non-runtime builtins have no canonical payload slot",
            "use bool, an integer type, or f32/f64",
        ));
    }
    Ok(ty)
}

fn is_exact_core_result_declaration(
    request: &AnalysisRequest<'_>,
    resolved: &wrela_hir::ResolvedDeclaration,
    record: &wrela_hir::Declaration,
) -> bool {
    if resolved.package != request.standard_library_package
        || record.visibility != wrela_hir::Visibility::Public
        || record.name.as_ref().map(wrela_hir::Name::as_str) != Some("Result")
        || request
            .hir
            .as_program()
            .modules
            .get(resolved.module.0 as usize)
            .is_none_or(|module| module.path.dotted() != "result")
    {
        return false;
    }
    let DeclarationKind::Enumeration(enumeration) = &record.kind else {
        return false;
    };
    let [ok_generic, err_generic] = enumeration.generics.as_slice() else {
        return false;
    };
    let generic_is_type = |id| {
        request
            .hir
            .as_program()
            .generic_parameter(id)
            .is_some_and(|generic| {
                matches!(generic.kind, wrela_hir::GenericParameterKind::Type { .. })
            })
    };
    if !generic_is_type(*ok_generic) || !generic_is_type(*err_generic) {
        return false;
    }
    let [ok, err] = enumeration.variants.as_slice() else {
        return false;
    };
    let exact_variant =
        |variant: &wrela_hir::EnumVariant, name: &str, generic: wrela_hir::GenericParameterId| {
            variant.name.as_str() == name
                && matches!(variant.fields.as_slice(), [field]
                if field.name.is_none()
                    && matches!(&field.ty.kind, TypeExpressionKind::Named {
                        definition: Definition::Generic(candidate),
                        arguments,
                    } if *candidate == generic && arguments.is_empty()))
        };
    exact_variant(ok, "Ok", *ok_generic) && exact_variant(err, "Err", *err_generic)
}

fn ensure_closed_scalar_enum_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    declaration: DeclarationId,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<SemanticTypeId> {
    for existing in &partial.types {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if matches!(&existing.kind, SemanticTypeKind::Enumeration {
            declaration: candidate,
            arguments,
            ..
        } if *candidate == declaration && arguments.is_empty())
        {
            return Ok(existing.id);
        }
    }
    let record = request
        .hir
        .as_program()
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Enumeration(enumeration) = &record.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    if !enumeration.generics.is_empty() {
        return Err(runtime_type_diagnostic(
            request,
            record.source,
            "semantic-runtime-enum-generic-not-supported",
            "runtime enum must be nongeneric in this revision slice",
            "generic Result specialization is a later atomic capability",
            "declare a local nongeneric closed enum",
        ));
    }
    if enumeration.variants.is_empty() || enumeration.variants.len() > 256 {
        return Err(runtime_type_diagnostic(
            request,
            record.source,
            "semantic-runtime-enum-variant-count",
            "runtime enum must declare between one and 256 variants",
            "the canonical machine discriminant is one dense u8 tag in declaration order",
            "declare at least one and at most 256 variants",
        ));
    }
    let mut variants = Vec::new();
    variants
        .try_reserve_exact(enumeration.variants.len())
        .map_err(|_| fact_resource(request, "runtime enum variants"))?;
    let mut shared_payload = None;
    for variant in &enumeration.variants {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        let [field] = variant.fields.as_slice() else {
            return Err(runtime_type_diagnostic(
                request,
                variant.source,
                "semantic-runtime-enum-payload-shape",
                "runtime enum variants require exactly one positional payload",
                "zero, multiple, and named payload fields are outside this bounded revision slice",
                "give every variant one positional scalar payload",
            ));
        };
        if field.name.is_some() {
            return Err(runtime_type_diagnostic(
                request,
                field.source,
                "semantic-runtime-enum-payload-shape",
                "runtime enum payload must be positional",
                "named variant fields are not part of the canonical R1 representation",
                "remove the payload field name",
            ));
        }
        let payload = match &field.ty.kind {
            TypeExpressionKind::Named {
                definition: Definition::Builtin(_),
                arguments,
            } if arguments.is_empty() => semantic_type_from_source(
                request,
                partial,
                &field.ty,
                &mut *aggregate_work,
                is_cancelled,
            )?,
            _ => {
                return Err(runtime_type_diagnostic(
                    request,
                    field.source,
                    "semantic-runtime-enum-payload-type",
                    "runtime enum payload is not a supported copy scalar",
                    "nested, generic, view, and nominal payloads require later ownership lowering",
                    "use one primitive boolean, integer, or floating-point payload type",
                ));
            }
        };
        let payload_record = partial
            .types
            .get(payload.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if payload_record.linearity != Linearity::ScalarCopy
            || !matches!(
                payload_record.kind,
                SemanticTypeKind::Bool
                    | SemanticTypeKind::Integer { .. }
                    | SemanticTypeKind::Float { bits: 32 | 64 }
            )
        {
            return Err(runtime_type_diagnostic(
                request,
                field.source,
                "semantic-runtime-enum-payload-type",
                "runtime enum payload is not a supported copy scalar",
                "all variants must use one identical stored scalar type",
                "use one primitive boolean, integer, or floating-point payload type",
            ));
        }
        if shared_payload.is_some_and(|expected| expected != payload) {
            return Err(runtime_type_diagnostic(
                request,
                field.source,
                "semantic-runtime-enum-payload-type",
                "runtime enum variants use different payload types",
                "the canonical tagged representation has one shared payload slot",
                "use the same scalar payload type for every variant",
            ));
        }
        shared_payload = Some(payload);
        variants.push(SemanticVariant {
            name: copy_analysis_text(
                variant.name.as_str(),
                request.limits.fact_bytes,
                is_cancelled,
            )?,
            fields: vec![SemanticField {
                name: String::new(),
                ty: payload,
                public: true,
            }],
        });
    }
    let payload = shared_payload.ok_or(AnalysisFailure::RequestMismatch)?;
    let payload_record = partial
        .types
        .get(payload.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let alignment = payload_record.alignment_lower_bound.max(1);
    let offset = (1_u64 + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
    let size = offset
        .checked_add(
            payload_record
                .size_upper_bound
                .ok_or(AnalysisFailure::RequestMismatch)?,
        )
        .and_then(|size| size.checked_add(u64::from(alignment) - 1))
        .map(|size| size & !(u64::from(alignment) - 1))
        .ok_or_else(|| fact_resource(request, "runtime enum layout"))?;
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "semantic types").into());
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len()).map_err(|_| fact_resource(request, "semantic types"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic types"))?;
    partial.types.push(SemanticType {
        id,
        kind: SemanticTypeKind::Enumeration {
            declaration,
            arguments: Vec::new(),
            variants,
        },
        linearity: Linearity::ExplicitCopy,
        size_upper_bound: Some(size),
        alignment_lower_bound: alignment,
        source: Some(record.source),
    });
    Ok(id)
}

fn ensure_flat_structure_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    declaration: DeclarationId,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<SemanticTypeId> {
    for existing in &partial.types {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if matches!(
            &existing.kind,
            SemanticTypeKind::Structure {
                declaration: candidate,
                arguments,
                ..
            } if *candidate == declaration && arguments.is_empty()
        ) {
            return Ok(existing.id);
        }
    }
    let record = request
        .hir
        .as_program()
        .declaration(declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Structure(aggregate) = &record.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    if !aggregate.generics.is_empty() || !aggregate.implements.is_empty() {
        return Err(runtime_type_diagnostic(
            request,
            record.source,
            "semantic-runtime-aggregate-not-supported",
            "runtime structure is outside the flat scalar-backed subset",
            "generic arguments and interface specializations require aggregate monomorphization support",
            "use a nongeneric structure with scalar fields",
        ));
    }
    if u64::try_from(aggregate.fields.len()).map_or(true, |count| count > request.limits.fact_edges)
    {
        return Err(fact_resource(request, "runtime structure fields").into());
    }
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(aggregate.fields.len())
        .map_err(|_| fact_resource(request, "runtime structure fields"))?;
    let mut size = 0_u64;
    let mut alignment = 1_u32;
    for field in &aggregate.fields {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if field.default.is_some() || !field.attributes.is_empty() {
            return Err(runtime_type_diagnostic(
                request,
                field.source,
                "semantic-runtime-aggregate-not-supported",
                "runtime structure field is outside the flat scalar-backed subset",
                "field defaults and field attributes require aggregate initialization semantics not yet lowered",
                "use an unadorned scalar field with no default",
            ));
        }
        let field_ty = match &field.ty.kind {
            TypeExpressionKind::Named {
                definition: Definition::Builtin(_),
                arguments,
            } if arguments.is_empty() => semantic_type_from_source(
                request,
                partial,
                &field.ty,
                &mut *aggregate_work,
                is_cancelled,
            )?,
            _ => {
                return Err(runtime_type_diagnostic(
                    request,
                    field.ty.source,
                    "semantic-runtime-aggregate-not-supported",
                    "runtime structure field is not a supported scalar",
                    "nested aggregates, views, and generic field types are intentionally outside this bounded vertical",
                    "store a primitive boolean, integer, or floating-point value directly",
                ));
            }
        };
        let field_record = partial
            .types
            .get(field_ty.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        if field_record.linearity != Linearity::ScalarCopy
            || !matches!(
                field_record.kind,
                SemanticTypeKind::Bool
                    | SemanticTypeKind::Integer { .. }
                    | SemanticTypeKind::Float { bits: 32 | 64 }
            )
        {
            return Err(runtime_type_diagnostic(
                request,
                field.ty.source,
                "semantic-runtime-aggregate-not-supported",
                "runtime structure field is not a supported scalar value",
                "unit and non-runtime builtins do not provide a flat stored field representation",
                "store a boolean, integer, or floating-point value",
            ));
        }
        let field_size = field_record
            .size_upper_bound
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let field_alignment = field_record.alignment_lower_bound;
        let mask = u64::from(field_alignment)
            .checked_sub(1)
            .ok_or_else(|| fact_resource(request, "runtime structure layout"))?;
        size = size
            .checked_add(mask)
            .map(|value| value & !mask)
            .and_then(|value| value.checked_add(field_size))
            .ok_or_else(|| fact_resource(request, "runtime structure layout"))?;
        alignment = alignment.max(field_alignment);
        fields.push(SemanticField {
            name: copy_analysis_text(field.name.as_str(), request.limits.fact_bytes, is_cancelled)?,
            ty: field_ty,
            public: field.visibility != wrela_hir::Visibility::Private,
        });
    }
    let mask = u64::from(alignment)
        .checked_sub(1)
        .ok_or_else(|| fact_resource(request, "runtime structure layout"))?;
    size = size
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or_else(|| fact_resource(request, "runtime structure layout"))?;
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "semantic types").into());
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len()).map_err(|_| fact_resource(request, "semantic types"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic types"))?;
    partial.types.push(SemanticType {
        id,
        kind: SemanticTypeKind::Structure {
            declaration,
            arguments: Vec::new(),
            fields,
        },
        linearity: Linearity::ExplicitCopy,
        size_upper_bound: Some(size),
        alignment_lower_bound: alignment,
        source: Some(record.source),
    });
    Ok(id)
}

fn ensure_primitive_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    primitive: PrimitiveSemanticType,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SemanticTypeId, AnalysisFailure> {
    let kind = match primitive {
        PrimitiveSemanticType::Bool => SemanticTypeKind::Bool,
        PrimitiveSemanticType::Integer {
            signed,
            bits,
            pointer_sized,
        } => SemanticTypeKind::Integer {
            signed,
            bits,
            pointer_sized,
        },
        PrimitiveSemanticType::Float { bits } => SemanticTypeKind::Float { bits },
    };
    for existing in &partial.types {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if existing.kind == kind {
            return Ok(existing.id);
        }
    }
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "semantic types"));
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len()).map_err(|_| fact_resource(request, "semantic types"))?,
    );
    let (size, alignment) = match primitive {
        PrimitiveSemanticType::Bool => (1, 1),
        PrimitiveSemanticType::Integer { bits, .. } | PrimitiveSemanticType::Float { bits } => {
            let bytes = u64::from(bits.div_ceil(8));
            let alignment = u32::try_from(bytes)
                .map_err(|_| fact_resource(request, "semantic type alignment"))?;
            (bytes, alignment)
        }
    };
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic types"))?;
    partial.types.push(SemanticType {
        id,
        kind,
        linearity: Linearity::ScalarCopy,
        size_upper_bound: Some(size),
        alignment_lower_bound: alignment,
        source: None,
    });
    Ok(id)
}

fn primitive_from_builtin(
    request: &AnalysisRequest<'_>,
    builtin: Builtin,
) -> Option<PrimitiveSemanticType> {
    let integer = |signed, bits, pointer_sized| PrimitiveSemanticType::Integer {
        signed,
        bits,
        pointer_sized,
    };
    Some(match builtin {
        Builtin::Bool => PrimitiveSemanticType::Bool,
        Builtin::U8 => integer(false, 8, false),
        Builtin::U16 => integer(false, 16, false),
        Builtin::U32 => integer(false, 32, false),
        Builtin::U64 => integer(false, 64, false),
        Builtin::U128 => integer(false, 128, false),
        Builtin::Usize => integer(false, u16::from(request.target.pointer_width()), true),
        Builtin::I8 => integer(true, 8, false),
        Builtin::I16 => integer(true, 16, false),
        Builtin::I32 => integer(true, 32, false),
        Builtin::I64 => integer(true, 64, false),
        Builtin::I128 => integer(true, 128, false),
        Builtin::Isize => integer(true, u16::from(request.target.pointer_width()), true),
        Builtin::F32 => PrimitiveSemanticType::Float { bits: 32 },
        Builtin::F64 => PrimitiveSemanticType::Float { bits: 64 },
        Builtin::Never
        | Builtin::Unit
        | Builtin::Char
        | Builtin::Static
        | Builtin::Str
        | Builtin::Bytes
        | Builtin::String
        | Builtin::Option
        | Builtin::Result
        | Builtin::Actor
        | Builtin::Receipt
        | Builtin::Dma
        | Builtin::Mmio
        | Builtin::Validated => return None,
    })
}

fn ensure_function_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    color: FunctionColor,
    source_parameters: &[FunctionParameter],
    result: SemanticTypeId,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SemanticTypeId, AnalysisFailure> {
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(source_parameters.len())
        .map_err(|_| fact_resource(request, "function type parameters"))?;
    for parameter in source_parameters {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        parameters.push(SemanticParameter {
            access: parameter.access,
            ty: parameter.ty,
        });
    }
    let kind = SemanticTypeKind::Function {
        color,
        parameters,
        result,
    };
    for existing in &partial.types {
        charge_runtime_aggregate_lookup(request, &mut *aggregate_work, is_cancelled)?;
        if existing.kind == kind {
            return Ok(existing.id);
        }
    }
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "semantic types"));
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len()).map_err(|_| fact_resource(request, "semantic types"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "semantic types"))?;
    partial.types.push(SemanticType {
        id,
        kind,
        linearity: Linearity::ScalarCopy,
        size_upper_bound: Some(0),
        alignment_lower_bound: 1,
        source: None,
    });
    Ok(id)
}

fn lower_scalar_literal(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    ty: SemanticTypeId,
    literal: &Literal,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ConstantValue, AnalysisFailure> {
    let kind = partial
        .types
        .get(ty.0 as usize)
        .map(|record| &record.kind)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    match (literal, kind) {
        (Literal::Unit, SemanticTypeKind::Unit) => Ok(ConstantValue::Unit),
        (Literal::Boolean(value), SemanticTypeKind::Bool) => Ok(ConstantValue::Bool(*value)),
        (Literal::Integer(spelling), SemanticTypeKind::Integer { signed, bits, .. }) => {
            let value = parse_integer_spelling(spelling).ok_or(AnalysisFailure::RequestMismatch)?;
            if *signed {
                let maximum = if *bits == 128 {
                    i128::MAX as u128
                } else {
                    (1_u128 << u32::from(*bits - 1)) - 1
                };
                if value > maximum {
                    return Err(AnalysisFailure::RequestMismatch);
                }
                let value = i128::try_from(value).map_err(|_| AnalysisFailure::RequestMismatch)?;
                Ok(ConstantValue::Signed { bits: *bits, value })
            } else {
                if *bits < 128 && value >= (1_u128 << u32::from(*bits)) {
                    return Err(AnalysisFailure::RequestMismatch);
                }
                Ok(ConstantValue::Unsigned { bits: *bits, value })
            }
        }
        (Literal::Float(spelling), SemanticTypeKind::Float { bits: 32 }) => {
            let value = parse_float_spelling(spelling, request.limits.fact_bytes, is_cancelled)?
                .and_then(|spelling| spelling.parse::<f32>().ok())
                .filter(|value| value.is_finite())
                .ok_or(AnalysisFailure::RequestMismatch)?;
            Ok(ConstantValue::Float32(value.to_bits()))
        }
        (Literal::Float(spelling), SemanticTypeKind::Float { bits: 64 }) => {
            let value = parse_float_spelling(spelling, request.limits.fact_bytes, is_cancelled)?
                .and_then(|spelling| spelling.parse::<f64>().ok())
                .filter(|value| value.is_finite())
                .ok_or(AnalysisFailure::RequestMismatch)?;
            Ok(ConstantValue::Float64(value.to_bits()))
        }
        _ => Err(AnalysisFailure::RequestMismatch),
    }
}

fn parse_float_spelling(
    value: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<String>, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    if u64::try_from(value.len()).map_or(true, |bytes| bytes > limit) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        });
    }
    let mut spelling = String::new();
    spelling
        .try_reserve_exact(value.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit,
        })?;
    let mut start = 0;
    while start < value.len() {
        check_cancelled(is_cancelled)?;
        let mut end = start
            .checked_add(COMPTIME_SOURCE_COPY_CHUNK_BYTES)
            .unwrap_or(value.len())
            .min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Ok(None);
        }
        spelling.extend(
            value[start..end]
                .chars()
                .filter(|character| *character != '_'),
        );
        start = end;
    }
    Ok(Some(spelling))
}

fn parse_integer_spelling(value: &str) -> Option<u128> {
    let (digits, radix) = value.strip_prefix("0x").map_or_else(
        || {
            value.strip_prefix("0o").map_or_else(
                || {
                    value
                        .strip_prefix("0b")
                        .map_or((value, 10), |digits| (digits, 2))
                },
                |digits| (digits, 8),
            )
        },
        |digits| (digits, 16),
    );
    let mut result = 0u128;
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
        result = result.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(result)
}

fn lower_access(access: wrela_hir::AccessMode) -> AccessMode {
    match access {
        wrela_hir::AccessMode::Value => AccessMode::Value,
        wrela_hir::AccessMode::Read => AccessMode::Read,
        wrela_hir::AccessMode::Mutate => AccessMode::Mutate,
        wrela_hir::AccessMode::Take => AccessMode::Take,
    }
}

fn optional_binding_map(
    count: usize,
    limit: u32,
) -> Result<Vec<Option<RuntimeBinding>>, AnalysisFailure> {
    if count > limit as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "runtime ownership maps",
            limit: u64::from(limit),
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "runtime ownership maps",
            limit: u64::from(limit),
        })?;
    output.resize(count, None);
    Ok(output)
}

fn copy_binding_map(
    source: &[Option<RuntimeBinding>],
    limit: u32,
) -> Result<Vec<Option<RuntimeBinding>>, AnalysisFailure> {
    let mut output = optional_binding_map(source.len(), limit)?;
    output.copy_from_slice(source);
    Ok(output)
}

fn optional_call_map(
    count: usize,
    limit: u64,
) -> Result<Vec<Option<ResolvedCallArgument>>, AnalysisFailure> {
    if u64::try_from(count).map_or(true, |count| count > limit) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "direct-call arguments",
            limit,
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "direct-call arguments",
            limit,
        })?;
    output.resize(count, None);
    Ok(output)
}

fn fact_resource(request: &AnalysisRequest<'_>, resource: &'static str) -> AnalysisFailure {
    AnalysisFailure::ResourceLimit {
        resource,
        limit: request.limits.fact_edges,
    }
}

fn bounded_test_fact(
    request: &AnalysisRequest<'_>,
    prefix: &str,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let length = prefix
        .len()
        .checked_add(value.len())
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit: request.limits.fact_bytes,
        })?;
    if u64::try_from(length).unwrap_or(u64::MAX) > request.limits.fact_bytes {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit: request.limits.fact_bytes,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic fact bytes",
            limit: request.limits.fact_bytes,
        })?;
    append_polled_test_text(&mut output, prefix, is_cancelled)?;
    append_polled_test_text(&mut output, value, is_cancelled)?;
    Ok(output)
}

fn compile_generated_test_group(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    plan: &ValidatedTestPlan,
    group: ImageGroupId,
    diagnostics: &mut Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let record = plan.group(group).ok_or(AnalysisFailure::RequestMismatch)?;
    let ImageRoot::GeneratedHarness { harness_name } = &record.root else {
        return Err(AnalysisFailure::RequestMismatch);
    };
    let expected_events = u32::try_from(record.tests.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(3))
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if record.name != GENERATED_GROUP_NAME
        || harness_name != GENERATED_HARNESS_NAME
        || record.deterministic_seed.is_some()
        || record.boot_timeout_ns != GENERATED_BOOT_TIMEOUT_NS
        || record.shutdown_timeout_ns != GENERATED_SHUTDOWN_TIMEOUT_NS
        || record.maximum_events != expected_events
        || record.maximum_output_bytes != GENERATED_MAXIMUM_OUTPUT_BYTES
        || record.tests.iter().any(|test| !test.assertions.is_empty()) && record.tests.len() != 1
    {
        return Err(AnalysisFailure::RequestMismatch);
    }
    populate_unit_type(request, partial)?;
    let program = request.hir.as_program();
    let mut candidates = std::collections::HashMap::new();
    candidates
        .try_reserve(program.test_candidates.len())
        .map_err(|_| test_resource_failure(request))?;
    for declaration in &program.test_candidates {
        check_cancelled(is_cancelled)?;
        if candidates
            .insert(source_test_key(request, *declaration), *declaration)
            .is_some()
        {
            return Err(AnalysisFailure::InternalInvariant(
                "semantic source test keys are not unique".to_owned(),
            ));
        }
    }
    let initial_diagnostic_count = diagnostics.len();
    let mut selected = Vec::new();
    let mut runtime_aggregate_work = RuntimeAggregateWork::default();
    selected
        .try_reserve_exact(record.tests.len())
        .map_err(|_| test_resource_failure(request))?;
    for planned in &record.tests {
        check_cancelled(is_cancelled)?;
        let ImageTestInvocation::GeneratedFunction { function_key } = planned.invocation else {
            return Err(AnalysisFailure::RequestMismatch);
        };
        let declaration = candidates
            .get(&function_key)
            .copied()
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let test = match inspect_source_test(request, declaration, is_cancelled)? {
            Ok(test) => test,
            Err(diagnostic) => {
                push_diagnostic(diagnostics, diagnostic, request.limits)?;
                continue;
            }
        };
        if !matches!(test.color, FunctionColor::Sync | FunctionColor::Async)
            || planned.descriptor.kind != TestKind::IntegrationImage
            || planned.descriptor.name != test.name
            || planned.descriptor.source != Some(test.source)
            || planned.descriptor.timeout_ns != INTEGRATION_TEST_TIMEOUT_NS
            || planned.assertions != test.assertions
            || test.key != function_key
        {
            return Err(AnalysisFailure::RequestMismatch);
        }
        match append_source_test_function(
            request,
            partial,
            &test,
            &mut runtime_aggregate_work,
            is_cancelled,
        )? {
            Ok(_) => selected.push(test),
            Err(diagnostic) => {
                push_diagnostic(diagnostics, diagnostic, request.limits)?;
            }
        }
    }
    if diagnostics.len() != initial_diagnostic_count {
        return Ok(());
    }
    populate_generated_harness(
        request,
        partial,
        group,
        harness_name,
        &selected,
        is_cancelled,
    )?;
    Ok(())
}

fn populate_unit_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
) -> Result<(), AnalysisFailure> {
    if !partial.types.is_empty() || request.limits.types == 0 {
        return Err(AnalysisFailure::RequestMismatch);
    }
    partial
        .types
        .try_reserve_exact(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic types",
            limit: u64::from(request.limits.types),
        })?;
    partial.types.push(SemanticType {
        id: SemanticTypeId(0),
        kind: SemanticTypeKind::Unit,
        linearity: Linearity::ScalarCopy,
        size_upper_bound: Some(0),
        alignment_lower_bound: 1,
        source: None,
    });
    Ok(())
}

fn populate_generated_harness(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    group: ImageGroupId,
    harness_name: &str,
    tests: &[SupportedSourceTest],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    if partial.functions.len() >= request.limits.monomorphizations as usize
        || partial
            .proofs
            .len()
            .checked_add(3)
            .is_none_or(|count| count > request.limits.proofs as usize)
    {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "generated test harness facts",
            limit: u64::from(request.limits.monomorphizations),
        });
    }
    partial
        .functions
        .try_reserve(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "monomorphizations",
            limit: u64::from(request.limits.monomorphizations),
        })?;
    partial
        .proofs
        .try_reserve(3)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        })?;
    let function_id = FunctionInstanceId(u32::try_from(partial.functions.len()).map_err(|_| {
        AnalysisFailure::ResourceLimit {
            resource: "monomorphizations",
            limit: u64::from(request.limits.monomorphizations),
        }
    })?);
    let type_proof = ProofId(u32::try_from(partial.proofs.len()).map_err(|_| {
        AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        }
    })?);
    let effect_proof = ProofId(type_proof.0.checked_add(1).ok_or(
        AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        },
    )?);
    let closed_proof = ProofId(effect_proof.0.checked_add(1).ok_or(
        AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        },
    )?);
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(tests.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "proof edges",
            limit: request.limits.proof_edges,
        })?;
    sources.extend(tests.iter().map(|test| test.source));
    partial.proofs.push(Proof {
        id: type_proof,
        kind: ProofKind::TypeChecked,
        subject: "generated integration-test harness".to_owned(),
        sources: sources.clone(),
        depends_on: Vec::new(),
        bound: Some(u64::try_from(tests.len()).map_err(|_| test_resource_failure(request))?),
        explanation: vec![
            "every selected function has the sealed zero-argument unit test signature".to_owned(),
        ],
    });
    partial.proofs.push(Proof {
        id: effect_proof,
        kind: ProofKind::EffectsAllowed,
        subject: "generated integration-test harness effects".to_owned(),
        sources: sources.clone(),
        depends_on: vec![type_proof],
        bound: Some(
            u64::try_from(tests.len())
                .ok()
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| count.checked_add(2))
                .ok_or_else(|| test_resource_failure(request))?,
        ),
        explanation: vec![
            "the harness invokes only selected test functions and the compiler-owned bounded event runtime"
                .to_owned(),
        ],
    });
    partial.proofs.push(Proof {
        id: closed_proof,
        kind: ProofKind::ImageClosed,
        subject: "closed generated integration-test image".to_owned(),
        sources,
        depends_on: vec![type_proof, effect_proof],
        bound: Some(u64::try_from(tests.len()).map_err(|_| test_resource_failure(request))?),
        explanation: vec![
            "the image contains the generated harness and exactly the selected test functions"
                .to_owned(),
        ],
    });
    let work_bound = tests.iter().try_fold(2u64, |total, test| {
        total.checked_add(3)?.checked_add(test.work_bound)
    });
    partial.functions.push(FunctionInstance {
        id: function_id,
        key: generated_harness_key(request, group),
        name: "__wrela_test_entry".to_owned(),
        origin: FunctionOrigin::GeneratedTestHarness { group },
        role: FunctionRole::ImageEntry,
        color: FunctionColor::Sync,
        generic_arguments: Vec::new(),
        parameters: Vec::new(),
        result: SemanticTypeId(0),
        effects: EffectSet(EffectSet::FIRMWARE),
        stack_bytes_bound: 0,
        frame_bytes_bound: 0,
        uninterrupted_work_bound: Some(work_bound.ok_or_else(|| test_resource_failure(request))?),
        recursive_depth_bound: Some(1),
        proofs: vec![type_proof, effect_proof, closed_proof],
        source: None,
    });
    partial.graph = Some(ImageGraph {
        name: copy_analysis_text(harness_name, request.limits.fact_bytes, is_cancelled)?,
        entry: function_id,
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        brands: Vec::new(),
        static_bytes: 0,
        peak_bytes: 0,
        startup_order: vec![ImageOwner::Runtime],
        shutdown_order: vec![ImageOwner::Runtime],
    });
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct EvaluatedImage {
    /// Image name followed by every actor name in one contiguous allocation.
    names: String,
    name_len: u32,
    name_source: Span,
    /// Actor records contain checked ranges into `names` and are `Copy`, so
    /// dropping an image is O(1) even when evaluation stops at cancellation.
    actors: Vec<EvaluatedActor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvaluatedActorKind {
    App,
    Service,
    Driver,
}

impl EvaluatedActorKind {
    fn from_install_method(name: &str) -> Option<Self> {
        match name {
            "app" => Some(Self::App),
            "service" => Some(Self::Service),
            "driver" => Some(Self::Driver),
            _ => None,
        }
    }

    const fn attribute(self) -> wrela_hir::BuiltinAttribute {
        match self {
            Self::App => wrela_hir::BuiltinAttribute::App,
            Self::Service => wrela_hir::BuiltinAttribute::Service,
            Self::Driver => wrela_hir::BuiltinAttribute::Driver,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvaluatedActor {
    class: DeclarationId,
    kind: EvaluatedActorKind,
    name_start: u64,
    name_len: u64,
    mailbox_capacity: u32,
    source: Span,
    mailbox_source: Span,
}

impl EvaluatedImage {
    fn name(&self) -> Option<&str> {
        self.names.get(..usize::try_from(self.name_len).ok()?)
    }

    fn actor_name(&self, actor: EvaluatedActor) -> Option<&str> {
        actor.name_in(&self.names)
    }
}

impl EvaluatedActor {
    fn name_in(self, actor_names: &str) -> Option<&str> {
        let start = usize::try_from(self.name_start).ok()?;
        let length = usize::try_from(self.name_len).ok()?;
        let end = start.checked_add(length)?;
        actor_names.get(start..end)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ComptimeValue {
    Text(String),
    Boolean(bool),
    Integer(ComptimeInteger),
    SelectedTarget,
    TargetType,
    ImageConstructor,
    ActorClass {
        declaration: DeclarationId,
        kind: EvaluatedActorKind,
    },
    /// Flat, nominal comptime-only structure value. Field values are stored in
    /// source declaration order and are restricted by the closure checker to
    /// target scalar values.
    Structure {
        declaration: DeclarationId,
        fields: Vec<ComptimeScalar>,
    },
    Image(EvaluatedImage),
    Unit,
}

/// Representation-enforced payload for the bounded flat-structure vertical.
///
/// Keeping structure elements `Copy` means dropping the backing vector is an
/// O(1) deallocation after the evaluator has explicitly polled its logical
/// field cleanup. No recursive `ComptimeValue` drop glue can hide unmetered
/// work in assignment replacement or successful frame teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComptimeScalar {
    Boolean(bool),
    Integer(ComptimeInteger),
    Unit,
}

impl ComptimeScalar {
    const fn into_value(self) -> ComptimeValue {
        match self {
            Self::Boolean(value) => ComptimeValue::Boolean(value),
            Self::Integer(value) => ComptimeValue::Integer(value),
            Self::Unit => ComptimeValue::Unit,
        }
    }

    fn from_value(value: ComptimeValue) -> Option<Self> {
        match value {
            ComptimeValue::Boolean(value) => Some(Self::Boolean(value)),
            ComptimeValue::Integer(value) => Some(Self::Integer(value)),
            ComptimeValue::Unit => Some(Self::Unit),
            _ => None,
        }
    }
}

impl ComptimeValue {
    const fn value_type(&self) -> Option<ComptimeType> {
        match self {
            Self::Boolean(_) => Some(ComptimeType::Bool),
            Self::Integer(value) => Some(value.scalar_type()),
            Self::Structure { declaration, .. } => Some(ComptimeType::Structure(*declaration)),
            Self::Unit => Some(ComptimeType::Unit),
            Self::Text(_)
            | Self::SelectedTarget
            | Self::TargetType
            | Self::ImageConstructor
            | Self::ActorClass { .. }
            | Self::Image(_) => None,
        }
    }
}

/// An integer value in the selected Wrela target's exact scalar domain.
///
/// `raw` is always masked to `bits`; signed values use target-width two's
/// complement rather than a host integer representation.  Keeping the source
/// signedness and resolved width on every value makes `usize`/`isize`
/// evaluation independent of the compiler host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ComptimeInteger {
    signed: bool,
    bits: u16,
    raw: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComptimeType {
    Unit,
    Bool,
    Integer { signed: bool, bits: u16 },
    Structure(DeclarationId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComptimeExpressionAccess {
    /// Ordinary value production. A non-scalar local is moved; a non-scalar
    /// parameter cannot be moved because bare parameters are read borrows.
    Move,
    /// A source read. Scalars are copied and flat structures are represented
    /// by a bounded evaluator-private snapshot without changing ownership.
    Read,
    /// The explicit source `copy` operation.
    Copy,
}

impl ComptimeInteger {
    fn new(signed: bool, bits: u16, raw: u128) -> Option<Self> {
        if bits == 0 || bits > 128 || raw & !integer_mask(bits) != 0 {
            return None;
        }
        Some(Self { signed, bits, raw })
    }

    const fn scalar_type(self) -> ComptimeType {
        ComptimeType::Integer {
            signed: self.signed,
            bits: self.bits,
        }
    }

    fn signed_value(self) -> Option<i128> {
        if !self.signed {
            return None;
        }
        let sign_bit = 1_u128 << u32::from(self.bits - 1);
        let extended = if self.raw & sign_bit == 0 {
            self.raw
        } else {
            self.raw | !integer_mask(self.bits)
        };
        Some(extended as i128)
    }

    fn shift_count(self) -> Option<u32> {
        if self.signed && self.signed_value()? < 0 {
            return None;
        }
        u32::try_from(self.raw).ok()
    }
}

const fn integer_mask(bits: u16) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    }
}

fn integer_from_signed(bits: u16, value: i128) -> Option<ComptimeInteger> {
    if bits == 0 || bits > 128 {
        return None;
    }
    let (minimum, maximum) = if bits == 128 {
        (i128::MIN, i128::MAX)
    } else {
        let magnitude = 1_i128 << u32::from(bits - 1);
        (-magnitude, magnitude - 1)
    };
    (minimum..=maximum)
        .contains(&value)
        .then_some(ComptimeInteger {
            signed: true,
            bits,
            raw: value as u128 & integer_mask(bits),
        })
}

#[derive(Debug)]
struct ComptimeBinding<K> {
    id: K,
    /// `None` is a source-visible moved local. Parameters are immutable reads
    /// in the supported subset and therefore never transition to `None`.
    value: Option<ComptimeValue>,
}

#[derive(Debug)]
struct ComptimeFrame {
    declaration: DeclarationId,
    call_source: Option<Span>,
    parameters: Vec<ComptimeBinding<wrela_hir::ParameterId>>,
    locals: Vec<ComptimeBinding<LocalId>>,
    charged_bytes: u64,
    host_depth: u32,
}

#[derive(Debug)]
enum EvaluationFailure {
    Diagnostic(Box<Diagnostic>),
    Analysis(AnalysisFailure),
}

enum ComptimeCase {
    Result(TestCaseResult),
    Unsupported(Diagnostic),
}

fn evaluate_comptime_test(
    request: &AnalysisRequest<'_>,
    test: &SupportedSourceTest,
    descriptor: TestDescriptor,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ComptimeCase, AnalysisFailure> {
    let mut evaluator = match ImageEvaluator::new(request, is_cancelled) {
        Ok(evaluator) => evaluator,
        Err(AnalysisFailure::ResourceLimit { resource, limit })
            if resource.starts_with("comptime evaluator")
                || resource == "comptime local values" =>
        {
            return Ok(ComptimeCase::Result(TestCaseResult {
                descriptor,
                outcome: TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: format!("comptime test exceeded {resource} limit {limit}"),
                },
                duration_ns: None,
            }));
        }
        Err(error) => return Err(error),
    };
    match evaluator.evaluate_test(test.declaration) {
        Ok(()) => Ok(ComptimeCase::Result(TestCaseResult {
            descriptor,
            outcome: TestOutcome::Passed,
            duration_ns: None,
        })),
        Err(EvaluationFailure::Diagnostic(diagnostic))
            if diagnostic.code.as_deref() == Some("semantic-comptime-assertion") =>
        {
            Ok(ComptimeCase::Result(TestCaseResult {
                descriptor,
                outcome: TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: comptime_diagnostic_message(
                        *diagnostic,
                        false,
                        request.limits.test_bytes,
                        is_cancelled,
                    )?,
                },
                duration_ns: None,
            }))
        }
        Err(EvaluationFailure::Diagnostic(diagnostic))
            if diagnostic.code.as_deref() == Some("semantic-comptime-arithmetic")
                || diagnostic.code.as_deref() == Some("semantic-comptime-shift-count")
                || diagnostic.code.as_deref() == Some("semantic-comptime-shift-result-loss")
                || diagnostic.code.as_deref() == Some("semantic-comptime-resource-limit") =>
        {
            let include_code =
                diagnostic.code.as_deref() != Some("semantic-comptime-resource-limit");
            Ok(ComptimeCase::Result(TestCaseResult {
                descriptor,
                outcome: TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: comptime_diagnostic_message(
                        *diagnostic,
                        include_code,
                        request.limits.test_bytes,
                        is_cancelled,
                    )?,
                },
                duration_ns: None,
            }))
        }
        Err(EvaluationFailure::Diagnostic(diagnostic)) => {
            Ok(ComptimeCase::Unsupported(*diagnostic))
        }
        Err(EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit { resource, limit }))
            if resource.starts_with("comptime evaluator")
                || resource == "comptime local values" =>
        {
            Ok(ComptimeCase::Result(TestCaseResult {
                descriptor,
                outcome: TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: format!("comptime test exceeded {resource} limit {limit}"),
                },
                duration_ns: None,
            }))
        }
        Err(EvaluationFailure::Analysis(error)) => Err(error),
    }
}

fn comptime_diagnostic_message(
    diagnostic: Diagnostic,
    include_code: bool,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let prefix_bytes = if include_code {
        diagnostic
            .code
            .as_deref()
            .unwrap_or("semantic-comptime-evaluation")
            .len()
            .checked_add(2)
    } else {
        Some(0)
    }
    .ok_or(AnalysisFailure::ResourceLimit {
        resource: "test plan or results",
        limit,
    })?;
    // Three decimal source coordinates plus punctuation fit comfortably in
    // this canonical per-frame reserve on every supported source model.
    let stack_bytes = 64usize
        .checked_add(diagnostic.labels.len().checked_mul(72).ok_or(
            AnalysisFailure::ResourceLimit {
                resource: "test plan or results",
                limit,
            },
        )?)
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit,
        })?;
    let total = diagnostic
        .message
        .len()
        .checked_add(prefix_bytes)
        .and_then(|bytes| bytes.checked_add(stack_bytes))
        .ok_or(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit,
        })?;
    if u64::try_from(total).map_or(true, |bytes| bytes > limit) {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "test plan or results",
            limit,
        });
    }
    let mut message = if include_code {
        let mut message = String::new();
        message
            .try_reserve_exact(total)
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "test plan or results",
                limit,
            })?;
        message.push_str(
            diagnostic
                .code
                .as_deref()
                .unwrap_or("semantic-comptime-evaluation"),
        );
        message.push_str(": ");
        message.push_str(&diagnostic.message);
        message
    } else {
        let mut message = diagnostic.message;
        message
            .try_reserve_exact(stack_bytes)
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "test plan or results",
                limit,
            })?;
        message
    };
    use std::fmt::Write as _;
    let primary = diagnostic.primary;
    write!(
        message,
        " [source {}:{}-{}",
        primary.file.0, primary.range.start, primary.range.end
    )
    .map_err(|_| AnalysisFailure::RequestMismatch)?;
    if !diagnostic.labels.is_empty() {
        message.push_str("; comptime calls");
        for label in &diagnostic.labels {
            check_cancelled(is_cancelled)?;
            write!(
                message,
                " <- {}:{}-{}",
                label.span.file.0, label.span.range.start, label.span.range.end
            )
            .map_err(|_| AnalysisFailure::RequestMismatch)?;
        }
    }
    message.push(']');
    check_cancelled(is_cancelled)?;
    Ok(message)
}

// Canonical evaluator-accounting units.  They deliberately describe the
// abstract evaluator state, not Rust allocation/layout details, so quota
// behavior is identical on every compiler host.
const COMPTIME_FRAME_BYTES: u64 = 64;
const COMPTIME_BINDING_BYTES: u64 = 32;
const COMPTIME_STRUCTURE_BYTES: usize = 32;
const COMPTIME_STRUCTURE_FIELD_BYTES: usize = 32;

fn comptime_structure_payload_bytes(field_count: usize) -> Option<u64> {
    field_count
        .checked_mul(COMPTIME_STRUCTURE_FIELD_BYTES)
        .and_then(|bytes| bytes.checked_add(COMPTIME_STRUCTURE_BYTES))
        .and_then(|bytes| u64::try_from(bytes).ok())
}
const COMPTIME_ACTOR_BYTES: usize = 64;
const COMPTIME_SOURCE_COPY_CHUNK_BYTES: usize = 64;
const COMPTIME_SYNTAX_DEPTH: u32 = 32;
// Each source invocation currently uses a small, fixed chain of Rust frames.
// Keep the language-visible active-call bound below the reviewed host-safe
// envelope until the evaluator moves to an explicit continuation stack.
const COMPTIME_HOST_CALL_DEPTH: u32 = 32;
// Bound the complete retained Rust recursion shape, not just active Wrela
// calls or one callee's local syntax depth in isolation. Flat aggregate values
// added more evaluator state to each host frame, so the reviewed cumulative
// envelope is conservatively capped at 48 for the 1 MiB small-stack proof.
// The independent language-visible active-call cap remains 32.
const COMPTIME_HOST_RECURSION_DEPTH: u32 = 48;

struct ImageEvaluator<'request, 'input> {
    request: &'request AnalysisRequest<'input>,
    program: &'request wrela_hir::Program,
    frames: Vec<ComptimeFrame>,
    steps: u64,
    step_limit: u64,
    retained_bytes: u64,
    peak_bytes: u64,
    byte_limit: u64,
    depth_limit: u32,
    current_source: Span,
    resource_source: Option<Span>,
    attempted_call: Option<(DeclarationId, Span)>,
    is_cancelled: &'request dyn Fn() -> bool,
}

impl<'request, 'input> ImageEvaluator<'request, 'input> {
    fn new(
        request: &'request AnalysisRequest<'input>,
        is_cancelled: &'request dyn Fn() -> bool,
    ) -> Result<Self, AnalysisFailure> {
        let program = request.hir.as_program();
        let byte_limit = request
            .limits
            .evaluator_bytes
            .min(request.build.profile.comptime.memory_bytes);
        Ok(Self {
            request,
            program,
            frames: Vec::new(),
            steps: 0,
            step_limit: request
                .limits
                .evaluator_steps
                .min(request.build.profile.comptime.steps),
            retained_bytes: 0,
            peak_bytes: 0,
            byte_limit,
            depth_limit: request
                .build
                .profile
                .comptime
                .call_depth
                .min(COMPTIME_HOST_CALL_DEPTH),
            current_source: fallback_span(program),
            resource_source: None,
            attempted_call: None,
            is_cancelled,
        })
    }

    fn evaluate(mut self, constructor: DeclarationId) -> Result<EvaluatedImage, EvaluationFailure> {
        let program = self.program;
        let declaration = program.declaration(constructor).ok_or_else(|| {
            self.diagnostic(
                fallback_span(program),
                "semantic-image-constructor-missing",
                "selected image constructor is absent from HIR",
            )
        })?;
        let wrela_hir::DeclarationKind::Function(function) = &declaration.kind else {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-image-constructor-kind",
                "selected image entry is not a function",
            ));
        };
        if function.color != FunctionColor::Comptime {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-image-constructor-color",
                "an image constructor must be a comptime function",
            ));
        }
        if function.body.is_none() {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-image-constructor-body",
                "an image constructor must have a body",
            ));
        }
        match self.invoke_function(constructor, Vec::new(), None, 0)? {
            ComptimeValue::Image(image) => Ok(image),
            _ => Err(self.diagnostic(
                declaration.source,
                "semantic-image-result",
                "image constructor did not return a closed Image value",
            )),
        }
    }

    fn evaluate_test(&mut self, test: DeclarationId) -> Result<(), EvaluationFailure> {
        let program = self.program;
        let declaration = program.declaration(test).ok_or_else(|| {
            self.diagnostic(
                fallback_span(program),
                "semantic-test-missing",
                "selected comptime test is absent from HIR",
            )
        })?;
        let wrela_hir::DeclarationKind::Function(function) = &declaration.kind else {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-test-kind",
                "selected comptime test is not a function",
            ));
        };
        if function.color != FunctionColor::Comptime {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-test-color",
                "compiler-evaluated tests must be comptime functions",
            ));
        }
        if function.body.is_none() {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-test-body-missing",
                "a comptime test must have a body",
            ));
        }
        let value = match self.invoke_function(test, Vec::new(), None, 0) {
            Ok(value) => value,
            Err(EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                resource,
                limit,
            })) if resource.starts_with("comptime evaluator") => {
                return Err(self.resource_diagnostic(resource, limit));
            }
            Err(error) => return Err(error),
        };
        match value {
            ComptimeValue::Unit => Ok(()),
            _ => Err(self.diagnostic(
                declaration.source,
                "semantic-test-result-not-supported",
                "a comptime test must complete with the unit value",
            )),
        }
    }

    fn execute_body(&mut self, body: BodyId, depth: u32) -> Result<Control, EvaluationFailure> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let body = program.body(body).ok_or_else(|| {
            self.diagnostic(
                fallback_span(program),
                "semantic-comptime-body",
                "comptime body reference is invalid",
            )
        })?;
        for statement_id in &body.statements {
            self.current_source = body.source;
            self.work()?;
            let statement = program.statement(*statement_id).ok_or_else(|| {
                self.diagnostic(
                    body.source,
                    "semantic-comptime-statement",
                    "comptime statement reference is invalid",
                )
            })?;
            self.current_source = statement.source;
            match &statement.kind {
                StatementKind::Initialize { local, value } => {
                    let expected = self.local_value_type(*local);
                    let value = self.evaluate_owned_expression(*value, expected, depth)?;
                    self.store(*local, value, statement.source)?;
                }
                StatementKind::Assign {
                    targets,
                    operator: AssignmentOperator::Assign,
                    value,
                } if targets.len() == 1 && targets[0].projections.is_empty() => {
                    let Definition::Local(local) = targets[0].root else {
                        return Err(self.unsupported(statement.source));
                    };
                    let expected = self.local_value_type(local);
                    let value = self.evaluate_owned_expression(*value, expected, depth)?;
                    self.store(local, value, statement.source)?;
                }
                StatementKind::Assign {
                    targets,
                    operator,
                    value,
                } if targets.len() == 1 && targets[0].projections.is_empty() => {
                    let Definition::Local(local) = targets[0].root else {
                        return Err(self.unsupported(statement.source));
                    };
                    let current = self.load_local(local, statement.source)?;
                    let expected = current.value_type();
                    let right = self.evaluate_expression(*value, expected, depth)?;
                    let binary = compound_assignment_binary_operator(*operator)
                        .ok_or_else(|| self.unsupported(statement.source))?;
                    let value =
                        self.evaluate_binary_values(binary, current, right, statement.source)?;
                    self.store(local, value, statement.source)?;
                }
                StatementKind::Return(value) => {
                    let expected = self.current_result_value_type();
                    let value = match value {
                        Some(value) => self.evaluate_owned_expression(*value, expected, depth)?,
                        None => ComptimeValue::Unit,
                    };
                    return Ok(Control::Return(value));
                }
                StatementKind::Pass => {}
                StatementKind::Expression(expression) => {
                    let value = self.evaluate_expression(*expression, None, depth)?;
                    self.dispose_temporary_value(value, statement.source)?;
                }
                StatementKind::Assert {
                    condition, message, ..
                } => match self.evaluate_expression(*condition, Some(ComptimeType::Bool), depth)? {
                    ComptimeValue::Boolean(true) => {}
                    ComptimeValue::Boolean(false) => {
                        return Err(if let Some(message) = message.as_deref() {
                            let message = self.copy_source_diagnostic_text(message)?;
                            self.diagnostic_owned(
                                statement.source,
                                "semantic-comptime-assertion",
                                message,
                            )
                        } else {
                            self.diagnostic(
                                statement.source,
                                "semantic-comptime-assertion",
                                "comptime assertion failed",
                            )
                        });
                    }
                    _ => return Err(self.unsupported(statement.source)),
                },
                StatementKind::If {
                    branches,
                    else_body,
                } => {
                    let mut selected = None;
                    for (condition, branch) in branches {
                        match self.evaluate_expression(
                            *condition,
                            Some(ComptimeType::Bool),
                            depth,
                        )? {
                            ComptimeValue::Boolean(true) => {
                                selected = Some(*branch);
                                break;
                            }
                            ComptimeValue::Boolean(false) => {}
                            _ => return Err(self.unsupported(statement.source)),
                        }
                    }
                    if let Some(selected) = selected.or(*else_body) {
                        if let Control::Return(value) = self.execute_body(selected, depth + 1)? {
                            return Ok(Control::Return(value));
                        }
                    }
                }
                StatementKind::ComptimeIf {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let selected = match self.evaluate_expression(
                        *condition,
                        Some(ComptimeType::Bool),
                        depth,
                    )? {
                        ComptimeValue::Boolean(true) => Some(*then_body),
                        ComptimeValue::Boolean(false) => *else_body,
                        _ => return Err(self.unsupported(statement.source)),
                    };
                    if let Some(selected) = selected {
                        if let Control::Return(value) = self.execute_body(selected, depth + 1)? {
                            return Ok(Control::Return(value));
                        }
                    }
                }
                StatementKind::Assign { .. }
                | StatementKind::Break
                | StatementKind::Continue
                | StatementKind::Send(_)
                | StatementKind::Yield(_)
                | StatementKind::Match { .. }
                | StatementKind::For { .. }
                | StatementKind::While { .. }
                | StatementKind::Loop { .. }
                | StatementKind::With { .. }
                | StatementKind::Error => return Err(self.unsupported(statement.source)),
            }
        }
        Ok(Control::Continue)
    }

    fn evaluate_expression(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        depth: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.evaluate_expression_with_access(id, expected, depth, ComptimeExpressionAccess::Read)
    }

    fn evaluate_owned_expression(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        depth: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.evaluate_expression_with_access(id, expected, depth, ComptimeExpressionAccess::Move)
    }

    fn evaluate_expression_with_access(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        depth: u32,
        access: ComptimeExpressionAccess,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let expression = program.expression(id).ok_or_else(|| {
            self.diagnostic(
                fallback_span(program),
                "semantic-comptime-expression",
                "comptime expression reference is invalid",
            )
        })?;
        self.current_source = expression.source;
        self.work()?;
        let value = match &expression.kind {
            ExpressionKind::Literal(Literal::String(value)) => {
                if expected.is_some() {
                    return Err(self.type_mismatch(expression.source));
                }
                Ok(ComptimeValue::Text(self.copy_source_text(value)?))
            }
            ExpressionKind::Literal(Literal::Boolean(value)) => Ok(ComptimeValue::Boolean(*value)),
            ExpressionKind::Literal(Literal::Integer(value)) => {
                self.evaluate_integer_literal(value, expected, expression.source)
            }
            ExpressionKind::Literal(Literal::Unit) => Ok(ComptimeValue::Unit),
            ExpressionKind::Reference(Definition::Local(local)) => {
                self.access_local(*local, expression.source, access)
            }
            ExpressionKind::Reference(Definition::Parameter(parameter)) => {
                self.access_parameter(*parameter, expression.source, access)
            }
            ExpressionKind::Reference(Definition::Declaration(declaration)) => {
                if let Some(name) = self.standard_declaration_name(declaration) {
                    return match name {
                        "Image" => Ok(ComptimeValue::ImageConstructor),
                        "Target" => Ok(ComptimeValue::TargetType),
                        _ => Err(self.unsupported(expression.source)),
                    };
                }
                if let Some(kind) = self.actor_class_kind(declaration.declaration) {
                    Ok(ComptimeValue::ActorClass {
                        declaration: declaration.declaration,
                        kind,
                    })
                } else {
                    Err(self.unsupported(expression.source))
                }
            }
            ExpressionKind::Reference(Definition::Variant(variant)) => {
                if self.is_selected_target_variant(variant) {
                    Ok(ComptimeValue::SelectedTarget)
                } else {
                    Err(self.unsupported(expression.source))
                }
            }
            ExpressionKind::Field { base, name } => {
                let base = self.evaluate_expression(*base, None, depth + 1)?;
                if base == ComptimeValue::TargetType && name.as_str() == "aarch64_qemu_virt_uefi" {
                    Ok(ComptimeValue::SelectedTarget)
                } else {
                    self.evaluate_structure_field(base, name, expression.source)
                }
            }
            ExpressionKind::Call { callee, arguments } => {
                if let Some((image, install_kind)) = self.image_install_target(*callee) {
                    self.evaluate_image_install(
                        image,
                        install_kind,
                        arguments,
                        expression.source,
                        depth + 1,
                    )
                } else if let Some(declaration) = self.direct_function_callee(*callee)? {
                    self.evaluate_user_call(declaration, arguments, expression.source, depth + 1)
                } else if let Some(declaration) = self.direct_structure_callee(*callee)? {
                    self.evaluate_structure_constructor(
                        declaration,
                        arguments,
                        expression.source,
                        depth + 1,
                    )
                } else if self.direct_class_callee(*callee)?.is_some() {
                    Err(self.diagnostic(
                        expression.source,
                        "semantic-class-construction-not-supported",
                        "class construction is not yet supported by semantic analysis",
                    ))
                } else {
                    let callee = self.evaluate_expression(*callee, None, depth + 1)?;
                    if callee != ComptimeValue::ImageConstructor {
                        return Err(self.unsupported(expression.source));
                    }
                    let mut image_name = None;
                    let mut target = None;
                    for argument in arguments {
                        let Some(argument_value) = argument.expression() else {
                            return Err(self.unsupported(argument.source));
                        };
                        let Some(name) = argument.name.as_ref().map(wrela_hir::Name::as_str) else {
                            return Err(self.unsupported(argument.source));
                        };
                        let value_source = self
                            .program
                            .expression(argument_value)
                            .map_or(argument.source, |expression| expression.source);
                        let argument_value =
                            self.evaluate_expression(argument_value, None, depth + 1)?;
                        match (name, argument_value) {
                            ("name", ComptimeValue::Text(value)) if image_name.is_none() => {
                                image_name = Some((value, value_source));
                            }
                            ("target", ComptimeValue::SelectedTarget) if target.is_none() => {
                                target = Some(());
                            }
                            _ => return Err(self.unsupported(argument.source)),
                        }
                    }
                    let (name, name_source) = image_name.ok_or_else(|| {
                        self.diagnostic(
                            expression.source,
                            "semantic-image-name",
                            "Image construction requires one string `name` argument",
                        )
                    })?;
                    if target.is_none() {
                        return Err(self.diagnostic(
                            expression.source,
                            "semantic-image-target",
                            "Image construction requires the selected target",
                        ));
                    }
                    if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
                        return Err(self.diagnostic(
                            expression.source,
                            "semantic-image-name",
                            "runtime image name must contain 1 to 255 non-control UTF-8 bytes",
                        ));
                    }
                    let name_len =
                        u32::try_from(name.len()).map_err(|_| self.evaluator_byte_failure())?;
                    Ok(ComptimeValue::Image(EvaluatedImage {
                        names: name,
                        name_len,
                        name_source,
                        actors: Vec::new(),
                    }))
                }
            }
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Comptime,
                operand,
            } => self.evaluate_expression_with_access(*operand, expected, depth + 1, access),
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Copy,
                operand,
            } => self.evaluate_expression_with_access(
                *operand,
                expected,
                depth + 1,
                ComptimeExpressionAccess::Copy,
            ),
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::BoolNot,
                operand,
            } => match self.evaluate_expression(*operand, Some(ComptimeType::Bool), depth + 1)? {
                ComptimeValue::Boolean(value) => Ok(ComptimeValue::Boolean(!value)),
                _ => Err(self.type_mismatch(expression.source)),
            },
            ExpressionKind::Unary {
                operator:
                    operator @ (wrela_hir::UnaryOperator::Negate | wrela_hir::UnaryOperator::BitNot),
                operand,
            } => {
                let operand_type = match expected {
                    Some(expected) => Some(expected),
                    None => self.expression_value_type(*operand, 0)?,
                };
                if *operator == wrela_hir::UnaryOperator::Negate {
                    if let Some(Literal::Integer(spelling)) = self
                        .program
                        .expression(*operand)
                        .and_then(|expression| match &expression.kind {
                            ExpressionKind::Literal(literal) => Some(literal),
                            _ => None,
                        })
                    {
                        let negative_bits = match expected {
                            Some(ComptimeType::Integer { signed: true, bits }) => Some(bits),
                            None => Some(64),
                            _ => None,
                        };
                        if let Some(bits) = negative_bits {
                            self.work()?;
                            return self.evaluate_negative_integer_literal(
                                spelling,
                                bits,
                                expression.source,
                            );
                        }
                    }
                }
                let operand = self.evaluate_expression(*operand, operand_type, depth + 1)?;
                self.evaluate_unary_value(*operator, operand, expression.source)
            }
            ExpressionKind::Binary {
                operator:
                    operator @ (wrela_hir::BinaryOperator::LogicalAnd
                    | wrela_hir::BinaryOperator::LogicalOr),
                left,
                right,
            } => {
                let left = self.evaluate_expression(*left, Some(ComptimeType::Bool), depth + 1)?;
                let ComptimeValue::Boolean(left) = left else {
                    return Err(self.type_mismatch(expression.source));
                };
                if (*operator == wrela_hir::BinaryOperator::LogicalAnd && !left)
                    || (*operator == wrela_hir::BinaryOperator::LogicalOr && left)
                {
                    Ok(ComptimeValue::Boolean(left))
                } else {
                    match self.evaluate_expression(*right, Some(ComptimeType::Bool), depth + 1)? {
                        ComptimeValue::Boolean(right) => Ok(ComptimeValue::Boolean(right)),
                        _ => Err(self.type_mismatch(expression.source)),
                    }
                }
            }
            ExpressionKind::Binary {
                operator,
                left,
                right,
            } => {
                let operand_type = match expected {
                    Some(expected) => Some(expected),
                    None => match self.expression_value_type(*left, 0)? {
                        Some(left) => Some(left),
                        None => self.expression_value_type(*right, 0)?,
                    },
                };
                let left = self.evaluate_expression(*left, operand_type, depth + 1)?;
                let right_type = left.value_type().or(operand_type);
                let right = self.evaluate_expression(*right, right_type, depth + 1)?;
                self.evaluate_binary_values(*operator, left, right, expression.source)
            }
            ExpressionKind::Compare {
                left,
                operator,
                right,
            } if !matches!(
                operator,
                wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn
            ) =>
            {
                let operand_type = match self.expression_value_type(*left, 0)? {
                    Some(left) => Some(left),
                    None => self.expression_value_type(*right, 0)?,
                };
                let left = self.evaluate_expression(*left, operand_type, depth + 1)?;
                let right_type = left.value_type().or(operand_type);
                let right = self.evaluate_expression(*right, right_type, depth + 1)?;
                self.evaluate_comparison(*operator, left, right, expression.source)
            }
            ExpressionKind::Literal(_)
            | ExpressionKind::Reference(_)
            | ExpressionKind::Closure { .. }
            | ExpressionKind::Unary { .. }
            | ExpressionKind::Compare { .. }
            | ExpressionKind::IsPattern { .. }
            | ExpressionKind::Range { .. }
            | ExpressionKind::Cast { .. }
            | ExpressionKind::Try(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::Tuple(_)
            | ExpressionKind::Array(_)
            | ExpressionKind::Race(_)
            | ExpressionKind::TrySend(_)
            | ExpressionKind::Interpolate(_)
            | ExpressionKind::Error => Err(self.unsupported(expression.source)),
        }?;
        self.require_expected(value, expected, expression.source)
    }

    fn direct_declaration_callee(
        &self,
        callee: ExpressionId,
    ) -> Result<Option<DeclarationId>, EvaluationFailure> {
        let Some(ExpressionKind::Reference(Definition::Declaration(resolved))) =
            self.program.expression(callee).map(|value| &value.kind)
        else {
            return Ok(None);
        };
        let declaration = self
            .program
            .declaration(resolved.declaration)
            .ok_or_else(|| {
                self.diagnostic(
                    fallback_span(self.program),
                    "semantic-comptime-call-target",
                    "comptime call target is missing from HIR",
                )
            })?;
        let module = self
            .program
            .modules
            .get(declaration.module.0 as usize)
            .filter(|module| {
                module.id == resolved.module
                    && module.package == resolved.package
                    && declaration.module == resolved.module
            })
            .ok_or_else(|| {
                self.diagnostic(
                    declaration.source,
                    "semantic-comptime-call-target",
                    "resolved comptime call target identity does not match its declaration",
                )
            })?;
        let _ = module;
        Ok(Some(resolved.declaration))
    }

    fn direct_function_callee(
        &self,
        callee: ExpressionId,
    ) -> Result<Option<DeclarationId>, EvaluationFailure> {
        let Some(declaration) = self.direct_declaration_callee(callee)? else {
            return Ok(None);
        };
        Ok(self
            .program
            .declaration(declaration)
            .is_some_and(|record| matches!(&record.kind, DeclarationKind::Function(_)))
            .then_some(declaration))
    }

    fn direct_structure_callee(
        &self,
        callee: ExpressionId,
    ) -> Result<Option<DeclarationId>, EvaluationFailure> {
        let Some(declaration) = self.direct_declaration_callee(callee)? else {
            return Ok(None);
        };
        let is_standard_image = self
            .program
            .declaration(declaration)
            .and_then(|record| {
                self.program
                    .modules
                    .get(record.module.0 as usize)
                    .map(|module| (record, module))
            })
            .is_some_and(|(record, module)| {
                module.package == self.request.standard_library_package
                    && record.name.as_ref().map(wrela_hir::Name::as_str) == Some("Image")
            });
        Ok(self
            .program
            .declaration(declaration)
            .is_some_and(|record| {
                !is_standard_image && matches!(&record.kind, DeclarationKind::Structure(_))
            })
            .then_some(declaration))
    }

    fn direct_class_callee(
        &self,
        callee: ExpressionId,
    ) -> Result<Option<DeclarationId>, EvaluationFailure> {
        let Some(declaration) = self.direct_declaration_callee(callee)? else {
            return Ok(None);
        };
        Ok(self
            .program
            .declaration(declaration)
            .is_some_and(|record| matches!(&record.kind, DeclarationKind::Class(_)))
            .then_some(declaration))
    }

    fn evaluate_structure_constructor(
        &mut self,
        declaration: DeclarationId,
        arguments: &[wrela_hir::CallArgument],
        source: Span,
        depth: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let record = program
            .declaration(declaration)
            .ok_or_else(|| self.unsupported(source))?;
        if !self.check_flat_scalar_structure(declaration)? {
            return Err(self.aggregate_not_supported(record.source));
        }
        let DeclarationKind::Structure(aggregate) = &record.kind else {
            return Err(self.aggregate_not_supported(record.source));
        };
        if arguments.len() != aggregate.fields.len() {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-constructor-argument",
                "comptime structure construction must supply every field exactly once",
            ));
        }
        let caller_module = self
            .frames
            .last()
            .and_then(|frame| program.declaration(frame.declaration))
            .map(|caller| caller.module)
            .ok_or_else(|| self.unsupported(source))?;
        let field_count = aggregate.fields.len();
        let payload = field_count
            .checked_mul(COMPTIME_STRUCTURE_FIELD_BYTES)
            .and_then(|bytes| bytes.checked_add(COMPTIME_STRUCTURE_BYTES))
            .ok_or_else(|| self.evaluator_byte_failure())?;
        self.retain(payload)?;
        let scratch_bytes = u64::try_from(field_count)
            .ok()
            .and_then(|count| count.checked_mul(COMPTIME_STRUCTURE_FIELD_BYTES as u64))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(|| self.evaluator_byte_failure())?;
        self.retain_u64(scratch_bytes)?;

        let mut resolved = Vec::new();
        resolved
            .try_reserve_exact(field_count)
            .map_err(|_| self.evaluator_byte_failure())?;
        for _ in 0..field_count {
            self.work()?;
            resolved.push(None);
        }
        for (source_index, argument) in arguments.iter().enumerate() {
            self.work()?;
            let Some(argument_value) = argument.expression() else {
                return Err(self.aggregate_not_supported(argument.source));
            };
            if field_count != 1 && argument.name.is_none() {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "a comptime structure with more than one field requires every constructor argument to be named",
                ));
            }
            let field_index = if let Some(argument_name) = &argument.name {
                let mut selected = None;
                for (index, field) in aggregate.fields.iter().enumerate() {
                    self.work()?;
                    if self.comptime_names_equal(field.name.as_str(), argument_name.as_str())?
                        && selected.replace(index).is_some()
                    {
                        return Err(self.diagnostic(
                            argument.source,
                            "semantic-comptime-constructor-argument",
                            "comptime structure field name is ambiguous",
                        ));
                    }
                }
                selected.ok_or_else(|| {
                    self.diagnostic(
                        argument.source,
                        "semantic-comptime-constructor-argument",
                        "comptime constructor argument does not name a declared field",
                    )
                })?
            } else {
                source_index
            };
            let field = aggregate.fields.get(field_index).ok_or_else(|| {
                self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "comptime constructor supplies too many positional fields",
                )
            })?;
            self.require_structure_field_visible(
                field,
                caller_module == record.module,
                argument.source,
            )?;
            let expected = self
                .source_scalar_type_only(&field.ty)
                .ok_or_else(|| self.aggregate_not_supported(field.ty.source))?;
            let value = self.evaluate_expression(argument_value, Some(expected), depth + 1)?;
            let value = ComptimeScalar::from_value(value)
                .ok_or_else(|| self.type_mismatch(argument.source))?;
            let slot = resolved
                .get_mut(field_index)
                .ok_or_else(|| self.unsupported(argument.source))?;
            if slot.replace(value).is_some() {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "comptime constructor supplies one field more than once",
                ));
            }
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(field_count)
            .map_err(|_| self.evaluator_byte_failure())?;
        for field in resolved {
            self.work()?;
            fields.push(field.ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-constructor-argument",
                    "comptime structure construction must supply every field exactly once",
                )
            })?);
        }
        self.release(scratch_bytes)?;
        Ok(ComptimeValue::Structure {
            declaration,
            fields,
        })
    }

    fn evaluate_structure_field(
        &mut self,
        base: ComptimeValue,
        name: &wrela_hir::Name,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let ComptimeValue::Structure {
            declaration,
            fields,
        } = base
        else {
            return Err(self.unsupported(source));
        };
        let program = self.program;
        let record = program
            .declaration(declaration)
            .ok_or_else(|| self.unsupported(source))?;
        if !self.check_flat_scalar_structure(declaration)? {
            return Err(self.aggregate_not_supported(record.source));
        }
        let DeclarationKind::Structure(aggregate) = &record.kind else {
            return Err(self.aggregate_not_supported(record.source));
        };
        if fields.len() != aggregate.fields.len() {
            return Err(self.aggregate_not_supported(source));
        }
        let caller_module = self
            .frames
            .last()
            .and_then(|frame| program.declaration(frame.declaration))
            .map(|caller| caller.module)
            .ok_or_else(|| self.unsupported(source))?;
        let mut selected = None;
        for (index, field) in aggregate.fields.iter().enumerate() {
            self.work()?;
            if self.comptime_names_equal(field.name.as_str(), name.as_str())?
                && selected.replace(index).is_some()
            {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-field",
                    "comptime structure field name is ambiguous",
                ));
            }
        }
        let index = selected.ok_or_else(|| {
            self.diagnostic(
                source,
                "semantic-comptime-field",
                "comptime structure does not declare the selected field",
            )
        })?;
        let field = aggregate
            .fields
            .get(index)
            .ok_or_else(|| self.unsupported(source))?;
        self.require_structure_field_visible(field, caller_module == record.module, source)?;
        let expected = self
            .source_scalar_type_only(&field.ty)
            .ok_or_else(|| self.aggregate_not_supported(field.ty.source))?;
        let payload = u64::try_from(
            fields
                .len()
                .checked_mul(COMPTIME_STRUCTURE_FIELD_BYTES)
                .and_then(|bytes| bytes.checked_add(COMPTIME_STRUCTURE_BYTES))
                .ok_or_else(|| self.evaluator_byte_failure())?,
        )
        .map_err(|_| self.evaluator_byte_failure())?;
        let mut selected_value = None;
        for (field_index, value) in fields.iter().enumerate() {
            self.work()?;
            if field_index == index {
                selected_value = Some(*value);
            }
        }
        let value = selected_value.ok_or_else(|| self.aggregate_not_supported(source))?;
        drop(fields);
        self.release(payload)?;
        self.require_expected(value.into_value(), Some(expected), source)
    }

    fn evaluate_user_call(
        &mut self,
        declaration: DeclarationId,
        arguments: &[wrela_hir::CallArgument],
        source: Span,
        depth: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let declaration_record = program
            .declaration(declaration)
            .ok_or_else(|| self.unsupported(source))?;
        let DeclarationKind::Function(function) = &declaration_record.kind else {
            return Err(self.unsupported(source));
        };
        if function.color != FunctionColor::Comptime
            || !function.generics.is_empty()
            || function.body.is_none()
            || arguments.len() != function.parameters.len()
        {
            return Err(self.unsupported(source));
        }
        if let Some(result) = function.result.as_ref() {
            if self
                .validated_source_value_type(result, result.source)?
                .is_none()
            {
                return Err(self.unsupported(source));
            }
        }

        let scratch_bytes = u64::try_from(function.parameters.len())
            .ok()
            .and_then(|count| count.checked_mul(COMPTIME_BINDING_BYTES))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(|| self.evaluator_byte_failure())?;
        self.retain_u64(scratch_bytes)?;

        let mut resolved = Vec::new();
        resolved
            .try_reserve_exact(function.parameters.len())
            .map_err(|_| self.evaluator_byte_failure())?;
        for _ in &function.parameters {
            self.work()?;
            resolved.push(None);
        }
        for (source_index, argument) in arguments.iter().enumerate() {
            self.work()?;
            let parameter_index = if let Some(argument_name) = &argument.name {
                let mut selected = None;
                for (index, parameter_id) in function.parameters.iter().enumerate() {
                    self.work()?;
                    let parameter = self
                        .program
                        .parameters
                        .get(parameter_id.0 as usize)
                        .filter(|parameter| parameter.id == *parameter_id)
                        .ok_or_else(|| self.unsupported(argument.source))?;
                    if let Some(parameter_name) = &parameter.name {
                        if self
                            .comptime_names_equal(parameter_name.as_str(), argument_name.as_str())?
                            && selected.replace(index).is_some()
                        {
                            return Err(self.unsupported(argument.source));
                        }
                    }
                }
                selected.ok_or_else(|| self.unsupported(argument.source))?
            } else {
                source_index
            };
            let parameter_id = *function
                .parameters
                .get(parameter_index)
                .ok_or_else(|| self.unsupported(argument.source))?;
            let parameter = self
                .program
                .parameters
                .get(parameter_id.0 as usize)
                .filter(|parameter| {
                    parameter.id == parameter_id
                        && parameter.owner == wrela_hir::CallableOwner::Declaration(declaration)
                        && !parameter.receiver
                })
                .ok_or_else(|| self.unsupported(argument.source))?;
            if parameter.access != wrela_hir::AccessMode::Value
                || argument.access() != wrela_hir::AccessMode::Value
            {
                return Err(self.unsupported(argument.source));
            }
            let Some(argument_value) = argument.expression() else {
                return Err(self.unsupported(argument.source));
            };
            let parameter_type = match parameter.ty.as_ref() {
                Some(ty) => self.validated_source_value_type(ty, parameter.source)?,
                None => None,
            }
            .ok_or_else(|| self.unsupported(parameter.source))?;
            let value =
                self.evaluate_expression(argument_value, Some(parameter_type), depth + 1)?;
            let slot = resolved
                .get_mut(parameter_index)
                .ok_or_else(|| self.unsupported(argument.source))?;
            if slot.replace((parameter_id, value)).is_some() {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-call-argument",
                    "comptime call supplies one parameter more than once",
                ));
            }
        }
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(resolved.len())
            .map_err(|_| self.evaluator_byte_failure())?;
        for argument in resolved {
            self.work()?;
            ordered.push(argument.ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-call-argument",
                    "comptime call does not supply every parameter",
                )
            })?);
        }
        self.release(scratch_bytes)?;
        self.invoke_function(declaration, ordered, Some(source), depth)
    }

    fn invoke_function(
        &mut self,
        declaration: DeclarationId,
        parameters: Vec<(wrela_hir::ParameterId, ComptimeValue)>,
        call_source: Option<Span>,
        syntax_contribution: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.attempted_call = call_source.map(|source| (declaration, source));
        self.current_source = call_source.unwrap_or_else(|| {
            self.program
                .declaration(declaration)
                .map_or_else(|| fallback_span(self.program), |value| value.source)
        });
        self.work()?;
        let active_depth = u32::try_from(self.frames.len())
            .ok()
            .and_then(|depth| depth.checked_add(1))
            .ok_or_else(|| self.call_depth_failure())?;
        if active_depth > self.depth_limit {
            self.resource_source = Some(self.current_source);
            self.attempted_call = call_source.map(|source| (declaration, source));
            return Err(self.call_depth_failure());
        }
        let parent_host_depth = self.frames.last().map_or(0, |frame| frame.host_depth);
        let host_increment = if self.frames.is_empty() {
            1
        } else {
            // Active calls already consume one independently bounded language
            // frame. Charge the additional retained syntax above that base so
            // 32 shallow calls remain admissible while deeply wrapped calls
            // share the conservative cumulative host envelope.
            syntax_contribution.saturating_sub(1).max(1)
        };
        let host_depth = parent_host_depth
            .checked_add(host_increment)
            .ok_or_else(|| self.host_recursion_failure())?;
        if host_depth > COMPTIME_HOST_RECURSION_DEPTH {
            self.resource_source = Some(self.current_source);
            self.attempted_call = call_source.map(|source| (declaration, source));
            return Err(self.host_recursion_failure());
        }
        let program = self.program;
        let declaration_record = program.declaration(declaration).ok_or_else(|| {
            self.unsupported(call_source.unwrap_or_else(|| fallback_span(program)))
        })?;
        let DeclarationKind::Function(function) = &declaration_record.kind else {
            return Err(self.unsupported(declaration_record.source));
        };
        if function.color != FunctionColor::Comptime || !function.generics.is_empty() {
            return Err(self.unsupported(declaration_record.source));
        }
        let body = function
            .body
            .ok_or_else(|| self.unsupported(declaration_record.source))?;
        let mut parameter_mismatch = parameters.len() != function.parameters.len();
        if !parameter_mismatch {
            for (expected, (actual, _)) in function.parameters.iter().zip(&parameters) {
                self.work()?;
                if expected != actual {
                    parameter_mismatch = true;
                    break;
                }
            }
        }
        if parameter_mismatch {
            return Err(self.diagnostic(
                call_source.unwrap_or(declaration_record.source),
                "semantic-comptime-call-argument",
                "comptime invocation arguments do not match the function declaration",
            ));
        }
        let parameter_count =
            u64::try_from(parameters.len()).map_err(|_| self.evaluator_byte_failure())?;
        let charged_bytes = COMPTIME_FRAME_BYTES
            .checked_add(
                parameter_count
                    .checked_mul(COMPTIME_BINDING_BYTES)
                    .ok_or_else(|| self.evaluator_byte_failure())?,
            )
            .ok_or_else(|| self.evaluator_byte_failure())?;
        self.retain_u64(charged_bytes)?;
        let mut frame_parameters = Vec::new();
        frame_parameters
            .try_reserve_exact(parameters.len())
            .map_err(|_| self.evaluator_byte_failure())?;
        for (id, value) in parameters {
            self.work()?;
            frame_parameters.push(ComptimeBinding {
                id,
                value: Some(value),
            });
        }
        self.frames
            .try_reserve(1)
            .map_err(|_| self.evaluator_byte_failure())?;
        self.frames.push(ComptimeFrame {
            declaration,
            call_source,
            parameters: frame_parameters,
            locals: Vec::new(),
            charged_bytes,
            host_depth,
        });
        // The callee now has an ordinary frame, so stack construction must no
        // longer synthesize the pre-push attempted-call entry.
        self.attempted_call = None;

        let expected = match function.result.as_ref() {
            Some(result) => self.validated_source_value_type(result, result.source)?,
            None => Some(ComptimeType::Unit),
        };
        let execution = self.execute_body(body, 1);
        let result = match execution {
            Ok(Control::Return(value)) => self.require_expected(
                value,
                expected,
                call_source.unwrap_or(declaration_record.source),
            ),
            Ok(Control::Continue) if expected == Some(ComptimeType::Unit) => {
                Ok(ComptimeValue::Unit)
            }
            Ok(Control::Continue) => Err(self.diagnostic(
                declaration_record.source,
                "semantic-comptime-missing-return",
                "comptime function completed without returning its declared result",
            )),
            Err(error) => Err(error),
        };
        if result.is_ok() {
            let released_payload = self.poll_successful_frame_cleanup()?;
            let frame = self.frames.pop().expect("comptime frame was just pushed");
            let released_bytes = frame
                .charged_bytes
                .checked_add(released_payload)
                .ok_or_else(|| self.evaluator_byte_failure())?;
            self.release(released_bytes)?;
        }
        result
    }

    fn scan_integer_spelling(
        &mut self,
        spelling: &str,
        source: Span,
    ) -> Result<Option<u128>, EvaluationFailure> {
        let (radix, prefix_bytes) = if spelling.starts_with("0x") {
            (16_u128, 2)
        } else if spelling.starts_with("0o") {
            (8_u128, 2)
        } else if spelling.starts_with("0b") {
            (2_u128, 2)
        } else {
            (10_u128, 0)
        };
        let mut result = 0_u128;
        for (index, byte) in spelling.bytes().enumerate() {
            self.current_source = source;
            self.work()?;
            if index < prefix_bytes || byte == b'_' {
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => u128::from(byte - b'0'),
                b'a'..=b'f' => u128::from(byte - b'a' + 10),
                b'A'..=b'F' => u128::from(byte - b'A' + 10),
                _ => return Ok(None),
            };
            if digit >= radix {
                return Ok(None);
            }
            let Some(next) = result
                .checked_mul(radix)
                .and_then(|value| value.checked_add(digit))
            else {
                return Ok(None);
            };
            result = next;
        }
        Ok(Some(result))
    }

    fn comptime_names_equal(&mut self, left: &str, right: &str) -> Result<bool, EvaluationFailure> {
        self.work()?;
        if left.len() != right.len() {
            return Ok(false);
        }
        for (left, right) in left.bytes().zip(right.bytes()) {
            self.work()?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn copy_source_text(&mut self, value: &str) -> Result<String, EvaluationFailure> {
        self.retain(value.len())?;
        self.copy_precharged_text(value)
    }

    fn copy_precharged_text(&mut self, value: &str) -> Result<String, EvaluationFailure> {
        let mut output = String::new();
        output
            .try_reserve_exact(value.len())
            .map_err(|_| self.evaluator_byte_failure())?;
        let mut start = 0;
        while start < value.len() {
            self.work()?;
            let mut end = start
                .checked_add(COMPTIME_SOURCE_COPY_CHUNK_BYTES)
                .unwrap_or(value.len())
                .min(value.len());
            while end > start && !value.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err(self.type_mismatch(self.current_source));
            }
            output.push_str(&value[start..end]);
            start = end;
        }
        Ok(output)
    }

    fn copy_comptime_value(
        &mut self,
        value: &ComptimeValue,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let payload = match value {
            ComptimeValue::Text(value) => value.len(),
            ComptimeValue::Structure { fields, .. } => {
                for _field in fields {
                    self.work()?;
                }
                fields
                    .len()
                    .checked_mul(COMPTIME_STRUCTURE_FIELD_BYTES)
                    .and_then(|bytes| bytes.checked_add(COMPTIME_STRUCTURE_BYTES))
                    .ok_or_else(|| self.evaluator_byte_failure())?
            }
            ComptimeValue::Image(value) => {
                value.name().ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
                let mut bytes = value.names.len();
                for actor in &value.actors {
                    self.work()?;
                    value.actor_name(*actor).ok_or(EvaluationFailure::Analysis(
                        AnalysisFailure::RequestMismatch,
                    ))?;
                    bytes = bytes
                        .checked_add(COMPTIME_ACTOR_BYTES)
                        .ok_or_else(|| self.evaluator_byte_failure())?;
                }
                bytes
            }
            ComptimeValue::Boolean(_)
            | ComptimeValue::Integer(_)
            | ComptimeValue::SelectedTarget
            | ComptimeValue::TargetType
            | ComptimeValue::ImageConstructor
            | ComptimeValue::ActorClass { .. }
            | ComptimeValue::Unit => 0,
        };
        self.retain(payload)?;
        Ok(match value {
            ComptimeValue::Text(value) => ComptimeValue::Text(self.copy_precharged_text(value)?),
            ComptimeValue::Image(value) => {
                let mut actors = Vec::new();
                actors
                    .try_reserve_exact(value.actors.len())
                    .map_err(|_| self.evaluator_byte_failure())?;
                for actor in &value.actors {
                    self.work()?;
                    actors.push(*actor);
                }
                ComptimeValue::Image(EvaluatedImage {
                    names: self.copy_precharged_text(&value.names)?,
                    name_len: value.name_len,
                    name_source: value.name_source,
                    actors,
                })
            }
            ComptimeValue::Structure {
                declaration,
                fields,
            } => {
                let mut copied = Vec::new();
                copied
                    .try_reserve_exact(fields.len())
                    .map_err(|_| self.evaluator_byte_failure())?;
                for field in fields {
                    self.work()?;
                    copied.push(*field);
                }
                ComptimeValue::Structure {
                    declaration: *declaration,
                    fields: copied,
                }
            }
            ComptimeValue::Boolean(value) => ComptimeValue::Boolean(*value),
            ComptimeValue::Integer(value) => ComptimeValue::Integer(*value),
            ComptimeValue::SelectedTarget => ComptimeValue::SelectedTarget,
            ComptimeValue::TargetType => ComptimeValue::TargetType,
            ComptimeValue::ImageConstructor => ComptimeValue::ImageConstructor,
            ComptimeValue::ActorClass { declaration, kind } => ComptimeValue::ActorClass {
                declaration: *declaration,
                kind: *kind,
            },
            ComptimeValue::Unit => ComptimeValue::Unit,
        })
    }

    fn copy_source_diagnostic_text(&mut self, value: &str) -> Result<String, EvaluationFailure> {
        let bytes = u64::try_from(value.len()).map_err(|_| {
            EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: self.request.limits.diagnostic_bytes,
            })
        })?;
        if bytes > self.request.limits.diagnostic_bytes {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: self.request.limits.diagnostic_bytes,
                },
            ));
        }
        if bytes > self.request.limits.test_bytes {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "test plan or results",
                    limit: self.request.limits.test_bytes,
                },
            ));
        }
        self.copy_source_text(value)
    }

    fn evaluate_integer_literal(
        &mut self,
        spelling: &str,
        expected: Option<ComptimeType>,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let raw = self
            .scan_integer_spelling(spelling, source)?
            .ok_or_else(|| self.type_mismatch(source))?;
        let (signed, bits) = match expected {
            Some(ComptimeType::Integer { signed, bits }) => (signed, bits),
            Some(ComptimeType::Bool | ComptimeType::Unit | ComptimeType::Structure(_)) => {
                return Err(self.type_mismatch(source));
            }
            None if raw <= i64::MAX as u128 => (true, 64),
            None if raw <= u64::MAX as u128 => (false, 64),
            None => {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-integer-literal",
                    "unconstrained integer literal exceeds the u64 default domain",
                ));
            }
        };
        let fits = if signed {
            raw <= integer_mask(bits) >> 1
        } else {
            raw <= integer_mask(bits)
        };
        if !fits {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-integer-literal",
                "integer literal does not fit its target scalar type",
            ));
        }
        Ok(ComptimeValue::Integer(
            ComptimeInteger::new(signed, bits, raw).ok_or_else(|| self.type_mismatch(source))?,
        ))
    }

    fn evaluate_negative_integer_literal(
        &mut self,
        spelling: &str,
        bits: u16,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let magnitude = self
            .scan_integer_spelling(spelling, source)?
            .ok_or_else(|| self.type_mismatch(source))?;
        let maximum_magnitude = 1_u128 << u32::from(bits - 1);
        if magnitude > maximum_magnitude {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-integer-literal",
                "negative integer literal does not fit its target scalar type",
            ));
        }
        let value = if bits == 128 && magnitude == maximum_magnitude {
            i128::MIN
        } else {
            -i128::try_from(magnitude).map_err(|_| self.type_mismatch(source))?
        };
        Ok(ComptimeValue::Integer(
            integer_from_signed(bits, value).ok_or_else(|| self.type_mismatch(source))?,
        ))
    }

    fn evaluate_unary_value(
        &self,
        operator: wrela_hir::UnaryOperator,
        operand: ComptimeValue,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let ComptimeValue::Integer(value) = operand else {
            return Err(self.type_mismatch(source));
        };
        let result = match operator {
            wrela_hir::UnaryOperator::Negate if value.signed => {
                let signed = value
                    .signed_value()
                    .ok_or_else(|| self.type_mismatch(source))?;
                let negated = signed.checked_neg().ok_or_else(|| {
                    self.arithmetic_failure(source, "comptime integer negation overflow")
                })?;
                integer_from_signed(value.bits, negated).ok_or_else(|| {
                    self.arithmetic_failure(source, "comptime integer negation overflow")
                })?
            }
            wrela_hir::UnaryOperator::BitNot => ComptimeInteger {
                raw: !value.raw & integer_mask(value.bits),
                ..value
            },
            _ => return Err(self.unsupported(source)),
        };
        Ok(ComptimeValue::Integer(result))
    }

    fn evaluate_binary_values(
        &self,
        operator: wrela_hir::BinaryOperator,
        left: ComptimeValue,
        right: ComptimeValue,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let (ComptimeValue::Integer(left), ComptimeValue::Integer(right)) = (left, right) else {
            return Err(self.type_mismatch(source));
        };
        if left.scalar_type() != right.scalar_type() {
            return Err(self.type_mismatch(source));
        }
        let mask = integer_mask(left.bits);
        let overflow = || self.arithmetic_failure(source, "comptime integer arithmetic overflow");
        let divide_by_zero =
            || self.arithmetic_failure(source, "comptime integer division by zero");
        let invalid_shift = || self.shift_count_failure(source);
        let lost_shift_result = || self.shift_result_loss_failure(source);
        let value = match operator {
            wrela_hir::BinaryOperator::AddWrapping => ComptimeInteger {
                raw: left.raw.wrapping_add(right.raw) & mask,
                ..left
            },
            wrela_hir::BinaryOperator::SubtractWrapping => ComptimeInteger {
                raw: left.raw.wrapping_sub(right.raw) & mask,
                ..left
            },
            wrela_hir::BinaryOperator::MultiplyWrapping => ComptimeInteger {
                raw: left.raw.wrapping_mul(right.raw) & mask,
                ..left
            },
            wrela_hir::BinaryOperator::BitOr => ComptimeInteger {
                raw: left.raw | right.raw,
                ..left
            },
            wrela_hir::BinaryOperator::BitXor => ComptimeInteger {
                raw: left.raw ^ right.raw,
                ..left
            },
            wrela_hir::BinaryOperator::BitAnd => ComptimeInteger {
                raw: left.raw & right.raw,
                ..left
            },
            wrela_hir::BinaryOperator::ShiftLeft => {
                let shift = right
                    .shift_count()
                    .filter(|shift| *shift < u32::from(left.bits));
                let shift = shift.ok_or_else(invalid_shift)?;
                let shifted = ComptimeInteger {
                    // `shift < left.bits <= 128`, so the host shift is defined;
                    // the mask models the selected target width exactly.
                    raw: left.raw.checked_shl(shift).unwrap_or(0) & mask,
                    ..left
                };
                let preserves_mathematical_result = if left.signed {
                    shifted
                        .signed_value()
                        .zip(left.signed_value())
                        .is_some_and(|(shifted, original)| shifted >> shift == original)
                } else {
                    shifted.raw >> shift == left.raw
                };
                if !preserves_mathematical_result {
                    return Err(lost_shift_result());
                }
                shifted
            }
            wrela_hir::BinaryOperator::ShiftLeftModular => {
                let shift = right
                    .shift_count()
                    .filter(|shift| *shift < u32::from(left.bits));
                let shift = shift.ok_or_else(invalid_shift)?;
                ComptimeInteger {
                    // Modular left shift wraps only the result. Its count has
                    // the same checked target-width domain as ordinary `<<`.
                    raw: left.raw.checked_shl(shift).unwrap_or(0) & mask,
                    ..left
                }
            }
            wrela_hir::BinaryOperator::ShiftRight => {
                let shift = right
                    .shift_count()
                    .filter(|shift| *shift < u32::from(left.bits));
                let shift = shift.ok_or_else(invalid_shift)?;
                let raw = if left.signed {
                    (left
                        .signed_value()
                        .ok_or_else(|| self.type_mismatch(source))?
                        >> shift) as u128
                        & mask
                } else {
                    left.raw >> shift
                };
                ComptimeInteger { raw, ..left }
            }
            operator if left.signed => {
                let left_value = left
                    .signed_value()
                    .ok_or_else(|| self.type_mismatch(source))?;
                let right_value = right
                    .signed_value()
                    .ok_or_else(|| self.type_mismatch(source))?;
                let signed = match operator {
                    wrela_hir::BinaryOperator::Add => left_value.checked_add(right_value),
                    wrela_hir::BinaryOperator::Subtract => left_value.checked_sub(right_value),
                    wrela_hir::BinaryOperator::Multiply => left_value.checked_mul(right_value),
                    wrela_hir::BinaryOperator::Divide if right_value == 0 => {
                        return Err(divide_by_zero());
                    }
                    wrela_hir::BinaryOperator::Divide => left_value.checked_div(right_value),
                    wrela_hir::BinaryOperator::Remainder if right_value == 0 => {
                        return Err(divide_by_zero());
                    }
                    wrela_hir::BinaryOperator::Remainder
                        if left_value == i128::MIN && right_value == -1 =>
                    {
                        Some(0)
                    }
                    wrela_hir::BinaryOperator::Remainder => left_value.checked_rem(right_value),
                    _ => return Err(self.unsupported(source)),
                }
                .ok_or_else(overflow)?;
                integer_from_signed(left.bits, signed).ok_or_else(overflow)?
            }
            operator => {
                let raw = match operator {
                    wrela_hir::BinaryOperator::Add => left.raw.checked_add(right.raw),
                    wrela_hir::BinaryOperator::Subtract => left.raw.checked_sub(right.raw),
                    wrela_hir::BinaryOperator::Multiply => left.raw.checked_mul(right.raw),
                    wrela_hir::BinaryOperator::Divide if right.raw == 0 => {
                        return Err(divide_by_zero());
                    }
                    wrela_hir::BinaryOperator::Divide => left.raw.checked_div(right.raw),
                    wrela_hir::BinaryOperator::Remainder if right.raw == 0 => {
                        return Err(divide_by_zero());
                    }
                    wrela_hir::BinaryOperator::Remainder => left.raw.checked_rem(right.raw),
                    _ => return Err(self.unsupported(source)),
                }
                .filter(|raw| *raw <= mask)
                .ok_or_else(overflow)?;
                ComptimeInteger { raw, ..left }
            }
        };
        Ok(ComptimeValue::Integer(value))
    }

    fn evaluate_comparison(
        &self,
        operator: wrela_hir::ComparisonOperator,
        left: ComptimeValue,
        right: ComptimeValue,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        if matches!(&left, ComptimeValue::Structure { .. })
            || matches!(&right, ComptimeValue::Structure { .. })
        {
            return Err(self.unsupported(source));
        }
        if left.value_type() != right.value_type() {
            return Err(self.type_mismatch(source));
        }
        let ordering = match (&left, &right) {
            (ComptimeValue::Integer(left), ComptimeValue::Integer(right)) if left.signed => left
                .signed_value()
                .zip(right.signed_value())
                .map(|(left, right)| left.cmp(&right)),
            (ComptimeValue::Integer(left), ComptimeValue::Integer(right)) => {
                Some(left.raw.cmp(&right.raw))
            }
            _ => None,
        };
        let result = match operator {
            wrela_hir::ComparisonOperator::Equal => left == right,
            wrela_hir::ComparisonOperator::NotEqual => left != right,
            wrela_hir::ComparisonOperator::Less => ordering.is_some_and(|value| value.is_lt()),
            wrela_hir::ComparisonOperator::LessEqual => ordering.is_some_and(|value| value.is_le()),
            wrela_hir::ComparisonOperator::Greater => ordering.is_some_and(|value| value.is_gt()),
            wrela_hir::ComparisonOperator::GreaterEqual => {
                ordering.is_some_and(|value| value.is_ge())
            }
            wrela_hir::ComparisonOperator::In | wrela_hir::ComparisonOperator::NotIn => {
                return Err(self.unsupported(source));
            }
        };
        if ordering.is_none()
            && !matches!(
                operator,
                wrela_hir::ComparisonOperator::Equal | wrela_hir::ComparisonOperator::NotEqual
            )
        {
            return Err(self.type_mismatch(source));
        }
        Ok(ComptimeValue::Boolean(result))
    }

    fn expression_value_type(
        &mut self,
        expression: ExpressionId,
        depth: u32,
    ) -> Result<Option<ComptimeType>, EvaluationFailure> {
        if depth >= COMPTIME_SYNTAX_DEPTH {
            return Ok(None);
        }
        let program = self.program;
        let Some(expression) = program.expression(expression) else {
            return Ok(None);
        };
        Ok(match &expression.kind {
            ExpressionKind::Literal(Literal::Boolean(_)) => Some(ComptimeType::Bool),
            ExpressionKind::Literal(Literal::Integer(spelling)) => self
                .scan_integer_spelling(spelling, expression.source)?
                .and_then(|value| {
                    if value <= i64::MAX as u128 {
                        Some(ComptimeType::Integer {
                            signed: true,
                            bits: 64,
                        })
                    } else if value <= u64::MAX as u128 {
                        Some(ComptimeType::Integer {
                            signed: false,
                            bits: 64,
                        })
                    } else {
                        None
                    }
                }),
            ExpressionKind::Literal(Literal::Unit) => Some(ComptimeType::Unit),
            ExpressionKind::Reference(Definition::Local(local)) => {
                self.bound_local_value_type(*local)?
            }
            ExpressionKind::Reference(Definition::Parameter(parameter)) => {
                self.parameter_value_type(*parameter)
            }
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::BoolNot,
                ..
            }
            | ExpressionKind::Binary {
                operator:
                    wrela_hir::BinaryOperator::LogicalAnd | wrela_hir::BinaryOperator::LogicalOr,
                ..
            }
            | ExpressionKind::Compare { .. } => Some(ComptimeType::Bool),
            ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::Negate,
                operand,
            } => {
                if let Some((spelling, source)) = program.expression(*operand).and_then(|operand| {
                    let ExpressionKind::Literal(Literal::Integer(spelling)) = &operand.kind else {
                        return None;
                    };
                    Some((spelling.as_str(), operand.source))
                }) {
                    self.scan_integer_spelling(spelling, source)?
                        .and_then(|magnitude| {
                            (magnitude <= (1_u128 << 63)).then_some(ComptimeType::Integer {
                                signed: true,
                                bits: 64,
                            })
                        })
                } else {
                    self.expression_value_type(*operand, depth + 1)?
                }
            }
            ExpressionKind::Unary { operand, .. } => {
                self.expression_value_type(*operand, depth + 1)?
            }
            ExpressionKind::Binary { left, right, .. } => {
                match self.expression_value_type(*left, depth + 1)? {
                    Some(left) => Some(left),
                    None => self.expression_value_type(*right, depth + 1)?,
                }
            }
            ExpressionKind::Field { base, name } => {
                let Some(ComptimeType::Structure(declaration)) =
                    self.expression_value_type(*base, depth + 1)?
                else {
                    return Ok(None);
                };
                if !self.check_flat_scalar_structure(declaration)? {
                    return Ok(None);
                }
                let Some(record) = program.declaration(declaration) else {
                    return Ok(None);
                };
                let DeclarationKind::Structure(aggregate) = &record.kind else {
                    return Ok(None);
                };
                let mut selected = None;
                for field in &aggregate.fields {
                    self.work()?;
                    if self.comptime_names_equal(field.name.as_str(), name.as_str())? {
                        if selected.is_some() {
                            return Ok(None);
                        }
                        selected = self.source_scalar_type_only(&field.ty);
                    }
                }
                selected
            }
            ExpressionKind::Call { callee, .. } => {
                let Some(callee) = program.expression(*callee) else {
                    return Ok(None);
                };
                let ExpressionKind::Reference(Definition::Declaration(resolved)) = &callee.kind
                else {
                    return Ok(None);
                };
                let Some(declaration) = program.declaration(resolved.declaration) else {
                    return Ok(None);
                };
                match &declaration.kind {
                    DeclarationKind::Function(function) => function
                        .result
                        .as_ref()
                        .and_then(|result| self.source_value_type(result))
                        .or_else(|| function.result.is_none().then_some(ComptimeType::Unit)),
                    DeclarationKind::Structure(_)
                        if self.check_flat_scalar_structure(declaration.id)? =>
                    {
                        Some(ComptimeType::Structure(declaration.id))
                    }
                    _ => None,
                }
            }
            _ => None,
        })
    }

    fn source_value_type(&self, source: &TypeExpression) -> Option<ComptimeType> {
        let TypeExpressionKind::Named {
            definition,
            arguments,
        } = &source.kind
        else {
            return None;
        };
        if !arguments.is_empty() {
            return None;
        }
        match definition {
            Definition::Builtin(builtin) => self.scalar_builtin_type(*builtin),
            Definition::Declaration(resolved) => {
                let declaration = self.request.hir.resolved_declaration(resolved)?;
                (matches!(&declaration.kind, DeclarationKind::Structure(_))
                    && !self.is_standard_image_declaration(declaration.id))
                .then_some(ComptimeType::Structure(declaration.id))
            }
            _ => None,
        }
    }

    fn source_scalar_type_only(&self, source: &TypeExpression) -> Option<ComptimeType> {
        let TypeExpressionKind::Named {
            definition: Definition::Builtin(builtin),
            arguments,
        } = &source.kind
        else {
            return None;
        };
        if arguments.is_empty() {
            self.scalar_builtin_type(*builtin)
        } else {
            None
        }
    }

    fn scalar_builtin_type(&self, builtin: Builtin) -> Option<ComptimeType> {
        Some(match builtin {
            Builtin::Unit => ComptimeType::Unit,
            Builtin::Bool => ComptimeType::Bool,
            Builtin::U8 => ComptimeType::Integer {
                signed: false,
                bits: 8,
            },
            Builtin::U16 => ComptimeType::Integer {
                signed: false,
                bits: 16,
            },
            Builtin::U32 => ComptimeType::Integer {
                signed: false,
                bits: 32,
            },
            Builtin::U64 => ComptimeType::Integer {
                signed: false,
                bits: 64,
            },
            Builtin::U128 => ComptimeType::Integer {
                signed: false,
                bits: 128,
            },
            Builtin::Usize => ComptimeType::Integer {
                signed: false,
                bits: u16::from(self.request.target.pointer_width()),
            },
            Builtin::I8 => ComptimeType::Integer {
                signed: true,
                bits: 8,
            },
            Builtin::I16 => ComptimeType::Integer {
                signed: true,
                bits: 16,
            },
            Builtin::I32 => ComptimeType::Integer {
                signed: true,
                bits: 32,
            },
            Builtin::I64 => ComptimeType::Integer {
                signed: true,
                bits: 64,
            },
            Builtin::I128 => ComptimeType::Integer {
                signed: true,
                bits: 128,
            },
            Builtin::Isize => ComptimeType::Integer {
                signed: true,
                bits: u16::from(self.request.target.pointer_width()),
            },
            _ => return None,
        })
    }

    fn check_flat_scalar_structure(
        &mut self,
        declaration: DeclarationId,
    ) -> Result<bool, EvaluationFailure> {
        let program = self.program;
        let Some(declaration) = program.declaration(declaration) else {
            return Ok(false);
        };
        let DeclarationKind::Structure(aggregate) = &declaration.kind else {
            return Ok(false);
        };
        self.work()?;
        if !aggregate.generics.is_empty() || !aggregate.implements.is_empty() {
            return Ok(false);
        }
        for field in &aggregate.fields {
            self.work()?;
            if field.default.is_some()
                || !field.attributes.is_empty()
                || self.source_scalar_type_only(&field.ty).is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validated_source_value_type(
        &mut self,
        source_type: &TypeExpression,
        diagnostic_source: Span,
    ) -> Result<Option<ComptimeType>, EvaluationFailure> {
        let ty = self.source_value_type(source_type);
        if let Some(ComptimeType::Structure(declaration)) = ty {
            if !self.check_flat_scalar_structure(declaration)? {
                return Err(self.aggregate_not_supported(diagnostic_source));
            }
        }
        Ok(ty)
    }

    fn is_standard_image_declaration(&self, declaration: DeclarationId) -> bool {
        self.program
            .declaration(declaration)
            .and_then(|record| {
                self.program
                    .modules
                    .get(record.module.0 as usize)
                    .map(|module| (record, module))
            })
            .is_some_and(|(record, module)| {
                module.package == self.request.standard_library_package
                    && record.name.as_ref().map(wrela_hir::Name::as_str) == Some("Image")
            })
    }

    fn require_structure_field_visible(
        &self,
        field: &wrela_hir::Field,
        same_module: bool,
        source: Span,
    ) -> Result<(), EvaluationFailure> {
        if same_module || field.visibility != wrela_hir::Visibility::Private {
            Ok(())
        } else {
            Err(self.diagnostic(
                source,
                "semantic-comptime-field-private",
                "comptime structure field is private to its declaring module",
            ))
        }
    }

    fn local_value_type(&self, local: LocalId) -> Option<ComptimeType> {
        self.program
            .locals
            .get(local.0 as usize)
            .filter(|record| record.id == local)
            .and_then(|record| record.ty.as_ref())
            .and_then(|ty| self.source_value_type(ty))
    }

    fn bound_local_value_type(
        &mut self,
        local: LocalId,
    ) -> Result<Option<ComptimeType>, EvaluationFailure> {
        if let Some(ty) = self.local_value_type(local) {
            return Ok(Some(ty));
        }
        let local_count = self.frames.last().map_or(0, |frame| frame.locals.len());
        for index in (0..local_count).rev() {
            self.work()?;
            if let Some(binding) = self
                .frames
                .last()
                .and_then(|frame| frame.locals.get(index))
                .filter(|binding| binding.id == local)
            {
                return Ok(binding.value.as_ref().and_then(ComptimeValue::value_type));
            }
        }
        Ok(None)
    }

    fn parameter_value_type(&self, parameter: wrela_hir::ParameterId) -> Option<ComptimeType> {
        self.program
            .parameters
            .get(parameter.0 as usize)
            .filter(|record| record.id == parameter)
            .and_then(|record| record.ty.as_ref())
            .and_then(|ty| self.source_value_type(ty))
    }

    fn current_result_value_type(&self) -> Option<ComptimeType> {
        let declaration = self.frames.last()?.declaration;
        let DeclarationKind::Function(function) = &self.program.declaration(declaration)?.kind
        else {
            return None;
        };
        function
            .result
            .as_ref()
            .and_then(|result| self.source_value_type(result))
            .or_else(|| function.result.is_none().then_some(ComptimeType::Unit))
    }

    fn require_expected(
        &self,
        value: ComptimeValue,
        expected: Option<ComptimeType>,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        if expected.is_some_and(|expected| value.value_type() != Some(expected)) {
            Err(self.type_mismatch(source))
        } else {
            Ok(value)
        }
    }

    fn type_mismatch(&self, source: Span) -> EvaluationFailure {
        self.diagnostic(
            source,
            "semantic-comptime-type-mismatch",
            "comptime value does not match its required target type",
        )
    }

    fn arithmetic_failure(&self, source: Span, message: &str) -> EvaluationFailure {
        self.diagnostic(source, "semantic-comptime-arithmetic", message)
    }

    fn shift_count_failure(&self, source: Span) -> EvaluationFailure {
        self.diagnostic(
            source,
            "semantic-comptime-shift-count",
            "comptime integer shift count is negative or not less than the target width",
        )
    }

    fn shift_result_loss_failure(&self, source: Span) -> EvaluationFailure {
        self.diagnostic(
            source,
            "semantic-comptime-shift-result-loss",
            "checked comptime left-shift result is not representable in the operand type",
        )
    }

    fn call_depth_failure(&self) -> EvaluationFailure {
        EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
            resource: "comptime evaluator depth",
            limit: u64::from(self.depth_limit),
        })
    }

    fn host_recursion_failure(&self) -> EvaluationFailure {
        EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
            resource: "comptime evaluator host recursion",
            limit: u64::from(COMPTIME_HOST_RECURSION_DEPTH),
        })
    }

    fn evaluator_byte_failure(&self) -> EvaluationFailure {
        EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
            resource: "comptime evaluator bytes",
            limit: self.byte_limit,
        })
    }

    fn resource_diagnostic(&self, resource: &'static str, limit: u64) -> EvaluationFailure {
        let source = self.resource_source.unwrap_or(self.current_source);
        let message = format!("comptime test exceeded {resource} limit {limit}");
        self.diagnostic(source, "semantic-comptime-resource-limit", &message)
    }

    fn image_install_target(&self, callee: ExpressionId) -> Option<(LocalId, EvaluatedActorKind)> {
        let ExpressionKind::Field { base, name } = &self.program.expression(callee)?.kind else {
            return None;
        };
        let ExpressionKind::Reference(Definition::Local(image)) = self
            .program
            .expression(*base)
            .map(|expression| &expression.kind)?
        else {
            return None;
        };
        EvaluatedActorKind::from_install_method(name.as_str()).map(|kind| (*image, kind))
    }

    fn actor_class_kind(&self, declaration: DeclarationId) -> Option<EvaluatedActorKind> {
        let declaration = self.program.declaration(declaration)?;
        if !matches!(declaration.kind, DeclarationKind::Class(_)) {
            return None;
        }
        let mut selected = None;
        for attribute in &declaration.attributes {
            let wrela_hir::AttributeIdentity::Builtin(identity) = attribute.identity else {
                continue;
            };
            let kind = match identity {
                wrela_hir::BuiltinAttribute::App => EvaluatedActorKind::App,
                wrela_hir::BuiltinAttribute::Service => EvaluatedActorKind::Service,
                wrela_hir::BuiltinAttribute::Driver => EvaluatedActorKind::Driver,
                _ => continue,
            };
            if selected.replace(kind).is_some() {
                return None;
            }
        }
        selected
    }

    fn evaluate_image_install(
        &mut self,
        image: LocalId,
        install_kind: EvaluatedActorKind,
        arguments: &[wrela_hir::CallArgument],
        source: Span,
        depth: u32,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        if arguments.len() != 2 {
            return Err(self.diagnostic_category(
                Category::ACTOR,
                source,
                "semantic-actor-install-shape",
                "actor installation requires one actor class and one `mailbox` capacity",
            ));
        }
        let class_argument = &arguments[0];
        let Some(class_argument_value) = class_argument.expression() else {
            return Err(self.unsupported(class_argument.source));
        };
        if class_argument.name.is_some() {
            return Err(self.unsupported(class_argument.source));
        }
        let class = self.evaluate_expression(class_argument_value, None, depth)?;
        let ComptimeValue::ActorClass {
            declaration: class,
            kind: class_kind,
        } = class
        else {
            return Err(self.diagnostic_category(
                Category::ACTOR,
                class_argument.source,
                "semantic-actor-install-class",
                "the first actor installation argument must name an actor class",
            ));
        };
        if class_kind != install_kind {
            return Err(self.diagnostic_category(
                Category::ACTOR,
                class_argument.source,
                "semantic-actor-install-role",
                "the image installation method does not match the actor class role",
            ));
        }
        if install_kind == EvaluatedActorKind::Driver {
            return Err(self.diagnostic_category(
                Category::HARDWARE,
                source,
                "semantic-hardware-actor-not-supported",
                "driver installation requires coherent target device and authority facts",
            ));
        }
        let mailbox_argument = &arguments[1];
        if mailbox_argument.name.as_ref().map(wrela_hir::Name::as_str) != Some("mailbox")
            || mailbox_argument.access() != wrela_hir::AccessMode::Value
        {
            return Err(self.diagnostic_category(
                Category::CAPACITY,
                mailbox_argument.source,
                "semantic-actor-mailbox-shape",
                "actor installation requires a named `mailbox` capacity",
            ));
        }
        let mailbox_source = self
            .program
            .expression(
                mailbox_argument
                    .expression()
                    .ok_or_else(|| self.unsupported(mailbox_argument.source))?,
            )
            .map_or(mailbox_argument.source, |expression| expression.source);
        let mailbox = self.evaluate_expression(
            mailbox_argument
                .expression()
                .ok_or_else(|| self.unsupported(mailbox_argument.source))?,
            None,
            depth,
        )?;
        let ComptimeValue::Integer(mailbox) = mailbox else {
            return Err(self.diagnostic_category(
                Category::CAPACITY,
                mailbox_source,
                "semantic-actor-mailbox-constant",
                "actor mailbox capacity must be a compile-time unsigned integer",
            ));
        };
        let mailbox_capacity = (!mailbox.signed
            || mailbox.signed_value().is_some_and(|value| value >= 0))
        .then_some(mailbox.raw)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            self.diagnostic_category(
                Category::CAPACITY,
                mailbox_source,
                "semantic-actor-mailbox-capacity",
                "actor mailbox capacity must fit in u32 and be greater than zero",
            )
        })?;
        let program = self.program;
        let declaration = program.declaration(class).ok_or_else(|| {
            self.diagnostic_category(
                Category::ACTOR,
                class_argument.source,
                "semantic-actor-install-class",
                "the installed actor class is missing from HIR",
            )
        })?;
        let actor_name = declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or_else(|| self.unsupported(class_argument.source))?;
        self.current_source = declaration.source;
        let actor_name = self.copy_source_text(actor_name)?;
        let current = self.load_local(image, source)?;
        let ComptimeValue::Image(current_image) = &current else {
            return Err(self.diagnostic_category(
                Category::IMAGE,
                source,
                "semantic-image-install-base",
                "actor installation must target an initialized local Image value",
            ));
        };
        if let Some(previous) = current_image
            .actors
            .iter()
            .find(|actor| actor.class == class)
        {
            let mut diagnostic = match self.diagnostic_category(
                Category::ACTOR,
                source,
                "semantic-actor-instance-ambiguous",
                "revision 0.1 requires one concrete image instance per actor class in this subset",
            ) {
                EvaluationFailure::Diagnostic(diagnostic) => diagnostic,
                EvaluationFailure::Analysis(_) => unreachable!(),
            };
            diagnostic.labels.try_reserve_exact(1).map_err(|_| {
                EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit: self.byte_limit,
                })
            })?;
            diagnostic.labels.push(wrela_diagnostics::Label {
                span: previous.source,
                message: "the first concrete instance is installed here".to_owned(),
            });
            return Err(EvaluationFailure::Diagnostic(diagnostic));
        }
        if current_image.actors.len() >= self.request.limits.image_nodes as usize {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "image actor nodes",
                    limit: u64::from(self.request.limits.image_nodes),
                },
            ));
        }
        self.dispose_temporary_value(current, source)?;
        self.retain(COMPTIME_ACTOR_BYTES)?;
        let byte_limit = self.byte_limit;
        {
            let Some(ComptimeValue::Image(current)) = self.local_mut(image) else {
                return Err(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ));
            };
            current.actors.try_reserve(1).map_err(|_| {
                EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit: byte_limit,
                })
            })?;
        }
        let (name_start, actor_name_len) =
            self.append_precharged_image_name(image, &actor_name, declaration.source)?;
        let Some(ComptimeValue::Image(current)) = self.local_mut(image) else {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch,
            ));
        };
        current.actors.push(EvaluatedActor {
            class,
            kind: install_kind,
            name_start,
            name_len: actor_name_len,
            mailbox_capacity,
            source,
            mailbox_source,
        });
        Ok(ComptimeValue::Unit)
    }

    fn standard_declaration_name(
        &self,
        declaration: &wrela_hir::ResolvedDeclaration,
    ) -> Option<&str> {
        if declaration.package != self.request.standard_library_package {
            return None;
        }
        self.program
            .declaration(declaration.declaration)?
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
    }

    fn is_selected_target_variant(&self, variant: &wrela_hir::ResolvedVariant) -> bool {
        self.standard_declaration_name(&variant.enumeration) == Some("Target")
            && self
                .request
                .hir
                .resolved_variant(variant)
                .is_some_and(|value| value.name.as_str() == "aarch64_qemu_virt_uefi")
            && self.request.target.identity()
                == &wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi()
    }

    fn poll_structure_disposal(
        &mut self,
        field_count: usize,
        source: Span,
    ) -> Result<u64, EvaluationFailure> {
        self.current_source = source;
        // One unit for the aggregate allocation followed by one unit for every
        // logical field. The Copy-only payload representation makes the
        // subsequent host deallocation O(1), so no unmetered element drop glue
        // remains after this successful scan.
        self.work()?;
        for _ in 0..field_count {
            self.work()?;
        }
        comptime_structure_payload_bytes(field_count).ok_or_else(|| self.evaluator_byte_failure())
    }

    /// Explicitly disposes the evaluator-owned payload in `value` and returns
    /// its canonical retained-byte charge. Callers release that charge only
    /// after this method succeeds.
    ///
    /// Text is one allocation, a flat structure is one allocation plus one
    /// unit per scalar field, and an image polls every logical actor before
    /// releasing its one contiguous image-and-actor-name arena.
    /// Actor records are `Copy`, so cancellation leaves only O(1)-drop host
    /// allocations and cannot fall back to an implicit project-sized tail
    /// destructor. If polling fails, no unperformed cleanup is credited.
    fn dispose_owned_payload(
        &mut self,
        value: &mut ComptimeValue,
        source: Span,
    ) -> Result<u64, EvaluationFailure> {
        self.current_source = source;
        match value {
            ComptimeValue::Text(text) => {
                let payload =
                    u64::try_from(text.len()).map_err(|_| self.evaluator_byte_failure())?;
                self.work()?;
                drop(std::mem::take(text));
                Ok(payload)
            }
            ComptimeValue::Structure { fields, .. } => {
                let payload = self.poll_structure_disposal(fields.len(), source)?;
                drop(std::mem::take(fields));
                Ok(payload)
            }
            ComptimeValue::Image(image) => {
                image.name().ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
                let actor_bytes = image
                    .actors
                    .len()
                    .checked_mul(COMPTIME_ACTOR_BYTES)
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or_else(|| self.evaluator_byte_failure())?;
                let names_bytes =
                    u64::try_from(image.names.len()).map_err(|_| self.evaluator_byte_failure())?;
                let payload = actor_bytes
                    .checked_add(names_bytes)
                    .ok_or_else(|| self.evaluator_byte_failure())?;
                for actor in &image.actors {
                    self.work()?;
                    image.actor_name(*actor).ok_or(EvaluationFailure::Analysis(
                        AnalysisFailure::RequestMismatch,
                    ))?;
                }
                drop(std::mem::take(&mut image.actors));
                self.work()?;
                drop(std::mem::take(&mut image.names));
                Ok(payload)
            }
            ComptimeValue::Boolean(_)
            | ComptimeValue::Integer(_)
            | ComptimeValue::SelectedTarget
            | ComptimeValue::TargetType
            | ComptimeValue::ImageConstructor
            | ComptimeValue::ActorClass { .. }
            | ComptimeValue::Unit => Ok(0),
        }
    }

    fn poll_successful_frame_cleanup(&mut self) -> Result<u64, EvaluationFailure> {
        let mut released_payload = 0_u64;
        while self
            .frames
            .last()
            .is_some_and(|frame| !frame.locals.is_empty())
        {
            self.work()?;
            let mut value = self
                .frames
                .last_mut()
                .and_then(|frame| frame.locals.last_mut())
                .and_then(|binding| binding.value.take());
            let disposal = if let Some(payload) = value.as_mut() {
                self.dispose_owned_payload(payload, self.current_source)
            } else {
                Ok(0)
            };
            match disposal {
                Ok(payload) => {
                    released_payload = released_payload
                        .checked_add(payload)
                        .ok_or_else(|| self.evaluator_byte_failure())?;
                }
                Err(error) => {
                    let binding = self
                        .frames
                        .last_mut()
                        .and_then(|frame| frame.locals.last_mut())
                        .ok_or(EvaluationFailure::Analysis(
                            AnalysisFailure::RequestMismatch,
                        ))?;
                    binding.value = value;
                    return Err(error);
                }
            }
            let binding = self
                .frames
                .last_mut()
                .and_then(|frame| frame.locals.pop())
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
            drop(binding);
        }
        while self
            .frames
            .last()
            .is_some_and(|frame| !frame.parameters.is_empty())
        {
            self.work()?;
            let mut value = self
                .frames
                .last_mut()
                .and_then(|frame| frame.parameters.last_mut())
                .and_then(|binding| binding.value.take());
            let disposal = if let Some(payload) = value.as_mut() {
                self.dispose_owned_payload(payload, self.current_source)
            } else {
                Ok(0)
            };
            match disposal {
                Ok(payload) => {
                    released_payload = released_payload
                        .checked_add(payload)
                        .ok_or_else(|| self.evaluator_byte_failure())?;
                }
                Err(error) => {
                    let binding = self
                        .frames
                        .last_mut()
                        .and_then(|frame| frame.parameters.last_mut())
                        .ok_or(EvaluationFailure::Analysis(
                            AnalysisFailure::RequestMismatch,
                        ))?;
                    binding.value = value;
                    return Err(error);
                }
            }
            let binding = self
                .frames
                .last_mut()
                .and_then(|frame| frame.parameters.pop())
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
            drop(binding);
        }
        Ok(released_payload)
    }

    fn dispose_temporary_value(
        &mut self,
        mut value: ComptimeValue,
        source: Span,
    ) -> Result<(), EvaluationFailure> {
        let released_payload = self.dispose_owned_payload(&mut value, source)?;
        drop(value);
        self.release(released_payload)?;
        Ok(())
    }

    fn store(
        &mut self,
        local: LocalId,
        value: ComptimeValue,
        source: Span,
    ) -> Result<(), EvaluationFailure> {
        let declaration = self
            .frames
            .last()
            .map(|frame| frame.declaration)
            .ok_or_else(|| self.unsupported(source))?;
        let valid = self
            .program
            .locals
            .get(local.0 as usize)
            .filter(|record| record.id == local)
            .and_then(|record| self.program.body(record.body))
            .is_some_and(|body| body.owner == wrela_hir::BodyOwner::Declaration(declaration));
        if !valid {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-local",
                "comptime local reference is invalid",
            ));
        }
        let local_count = self.frames.last().map_or(0, |frame| frame.locals.len());
        let mut existing = None;
        for index in 0..local_count {
            self.work()?;
            if self
                .frames
                .last()
                .and_then(|frame| frame.locals.get(index))
                .is_some_and(|binding| binding.id == local)
            {
                existing = Some(index);
                break;
            }
        }
        if let Some(index) = existing {
            let mut old_value = self
                .frames
                .last_mut()
                .and_then(|frame| frame.locals.get_mut(index))
                .and_then(|binding| binding.value.take());
            let disposal = if let Some(payload) = old_value.as_mut() {
                self.dispose_owned_payload(payload, source)
            } else {
                Ok(0)
            };
            let released_payload = match disposal {
                Ok(payload) => payload,
                Err(error) => {
                    let binding = self
                        .frames
                        .last_mut()
                        .and_then(|frame| frame.locals.get_mut(index))
                        .ok_or(EvaluationFailure::Analysis(
                            AnalysisFailure::RequestMismatch,
                        ))?;
                    binding.value = old_value;
                    return Err(error);
                }
            };
            let binding = self
                .frames
                .last_mut()
                .and_then(|frame| frame.locals.get_mut(index))
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
            binding.value = Some(value);
            drop(old_value);
            self.release(released_payload)?;
            return Ok(());
        }
        self.retain_u64(COMPTIME_BINDING_BYTES)?;
        let byte_limit = self.byte_limit;
        let frame = self.frames.last_mut().ok_or(EvaluationFailure::Analysis(
            AnalysisFailure::RequestMismatch,
        ))?;
        frame.locals.try_reserve(1).map_err(|_| {
            EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                resource: "comptime evaluator bytes",
                limit: self.byte_limit,
            })
        })?;
        frame.locals.push(ComptimeBinding {
            id: local,
            value: Some(value),
        });
        frame.charged_bytes = frame
            .charged_bytes
            .checked_add(COMPTIME_BINDING_BYTES)
            .ok_or(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit: byte_limit,
                },
            ))?;
        Ok(())
    }

    fn access_local(
        &mut self,
        local: LocalId,
        source: Span,
        access: ComptimeExpressionAccess,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let local_count = self.frames.last().map_or(0, |frame| frame.locals.len());
        let mut selected = None;
        for index in (0..local_count).rev() {
            self.work()?;
            if self
                .frames
                .last()
                .and_then(|frame| frame.locals.get(index))
                .is_some_and(|binding| binding.id == local)
            {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or_else(|| {
            self.diagnostic(
                source,
                "semantic-comptime-uninitialized",
                "comptime local is used before initialization",
            )
        })?;
        let original = self
            .frames
            .last_mut()
            .and_then(|frame| frame.locals.get_mut(index))
            .and_then(|binding| binding.value.take())
            .ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-use-after-move",
                    "comptime local is used after its aggregate value was moved",
                )
            })?;
        if access == ComptimeExpressionAccess::Move
            && matches!(&original, ComptimeValue::Structure { .. })
        {
            return Ok(original);
        }
        let value = self.copy_comptime_value(&original);
        let Some(binding) = self
            .frames
            .last_mut()
            .and_then(|frame| frame.locals.get_mut(index))
        else {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch,
            ));
        };
        binding.value = Some(original);
        value
    }

    fn load_local(
        &mut self,
        local: LocalId,
        source: Span,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        self.access_local(local, source, ComptimeExpressionAccess::Read)
    }

    fn access_parameter(
        &mut self,
        parameter: wrela_hir::ParameterId,
        source: Span,
        access: ComptimeExpressionAccess,
    ) -> Result<ComptimeValue, EvaluationFailure> {
        let parameter_count = self.frames.last().map_or(0, |frame| frame.parameters.len());
        let mut selected = None;
        for index in 0..parameter_count {
            self.work()?;
            if self
                .frames
                .last()
                .and_then(|frame| frame.parameters.get(index))
                .is_some_and(|binding| binding.id == parameter)
            {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or_else(|| {
            self.diagnostic(
                source,
                "semantic-comptime-parameter",
                "comptime parameter reference is invalid in this invocation",
            )
        })?;
        let original = self
            .frames
            .last_mut()
            .and_then(|frame| frame.parameters.get_mut(index))
            .and_then(|binding| binding.value.take())
            .ok_or(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch,
            ))?;
        if access == ComptimeExpressionAccess::Move
            && matches!(&original, ComptimeValue::Structure { .. })
        {
            let Some(binding) = self
                .frames
                .last_mut()
                .and_then(|frame| frame.parameters.get_mut(index))
            else {
                return Err(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ));
            };
            binding.value = Some(original);
            return Err(self.diagnostic(
                source,
                "semantic-comptime-borrowed-value-move",
                "a bare comptime parameter is read-only; use `copy` to produce an owned aggregate result",
            ));
        }
        let value = self.copy_comptime_value(&original);
        let Some(binding) = self
            .frames
            .last_mut()
            .and_then(|frame| frame.parameters.get_mut(index))
        else {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch,
            ));
        };
        binding.value = Some(original);
        value
    }

    fn local_mut(&mut self, local: LocalId) -> Option<&mut ComptimeValue> {
        self.frames
            .last_mut()?
            .locals
            .iter_mut()
            .rev()
            .find(|binding| binding.id == local)
            .and_then(|binding| binding.value.as_mut())
    }

    fn append_precharged_image_name(
        &mut self,
        image: LocalId,
        value: &str,
        source: Span,
    ) -> Result<(u64, u64), EvaluationFailure> {
        let byte_limit = self.byte_limit;
        let value_len = u64::try_from(value.len()).map_err(|_| self.evaluator_byte_failure())?;
        let name_start = {
            let Some(ComptimeValue::Image(current)) = self.local_mut(image) else {
                return Err(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ));
            };
            current
                .names
                .len()
                .checked_add(value.len())
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
            current.names.try_reserve_exact(value.len()).map_err(|_| {
                EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit: byte_limit,
                })
            })?;
            u64::try_from(current.names.len())
                .map_err(|_| EvaluationFailure::Analysis(AnalysisFailure::RequestMismatch))?
        };
        self.current_source = source;
        let mut copied = 0_usize;
        while copied < value.len() {
            self.work()?;
            let mut end = copied
                .checked_add(COMPTIME_SOURCE_COPY_CHUNK_BYTES)
                .unwrap_or(value.len())
                .min(value.len());
            while end > copied && !value.is_char_boundary(end) {
                end -= 1;
            }
            if end == copied {
                return Err(self.type_mismatch(source));
            }
            let Some(ComptimeValue::Image(current)) = self.local_mut(image) else {
                return Err(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ));
            };
            current.names.push_str(&value[copied..end]);
            copied = end;
        }
        Ok((name_start, value_len))
    }

    fn work(&mut self) -> Result<(), EvaluationFailure> {
        check_cancelled(self.is_cancelled).map_err(EvaluationFailure::Analysis)?;
        let Some(steps) = self.steps.checked_add(1) else {
            self.resource_source = Some(self.current_source);
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: self.step_limit,
                },
            ));
        };
        self.steps = steps;
        if self.steps > self.step_limit {
            self.resource_source = Some(self.current_source);
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: self.step_limit,
                },
            ));
        }
        Ok(())
    }

    fn enter_syntax(&mut self, depth: u32) -> Result<(), EvaluationFailure> {
        if depth > COMPTIME_SYNTAX_DEPTH {
            self.resource_source = Some(self.current_source);
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator syntax depth",
                    limit: u64::from(COMPTIME_SYNTAX_DEPTH),
                },
            ))
        } else if self
            .frames
            .last()
            .map_or(0, |frame| frame.host_depth)
            .checked_add(depth)
            .is_none_or(|host_depth| host_depth > COMPTIME_HOST_RECURSION_DEPTH)
        {
            self.resource_source = Some(self.current_source);
            Err(self.host_recursion_failure())
        } else {
            Ok(())
        }
    }

    fn retain(&mut self, bytes: usize) -> Result<(), EvaluationFailure> {
        let bytes = u64::try_from(bytes).map_err(|_| self.evaluator_byte_failure())?;
        self.retain_u64(bytes)
    }

    fn retain_u64(&mut self, bytes: u64) -> Result<(), EvaluationFailure> {
        let Some(retained_bytes) = self.retained_bytes.checked_add(bytes) else {
            self.resource_source = Some(self.current_source);
            return Err(self.evaluator_byte_failure());
        };
        if retained_bytes > self.byte_limit {
            self.resource_source = Some(self.current_source);
            return Err(self.evaluator_byte_failure());
        }
        self.retained_bytes = retained_bytes;
        self.peak_bytes = self.peak_bytes.max(self.retained_bytes);
        Ok(())
    }

    fn release(&mut self, bytes: u64) -> Result<(), EvaluationFailure> {
        self.retained_bytes =
            self.retained_bytes
                .checked_sub(bytes)
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ))?;
        Ok(())
    }

    fn unsupported(&self, source: Span) -> EvaluationFailure {
        self.diagnostic(
            source,
            "semantic-comptime-operation-not-implemented",
            "this comptime operation is not yet implemented by the production semantic analyzer",
        )
    }

    fn aggregate_not_supported(&self, source: Span) -> EvaluationFailure {
        self.diagnostic(
            source,
            "semantic-comptime-aggregate-not-supported",
            "comptime aggregate values currently support only nongeneric structures with scalar fields and no defaults or interface specializations",
        )
    }

    fn diagnostic(&self, source: Span, code: &str, message: &str) -> EvaluationFailure {
        self.diagnostic_category(Category::COMPTIME, source, code, message)
    }

    fn diagnostic_owned(&self, source: Span, code: &str, message: String) -> EvaluationFailure {
        let mut diagnostic = Diagnostic::error(Category::COMPTIME, source, message);
        diagnostic.code = Some(code.to_owned());
        self.finish_diagnostic(diagnostic)
    }

    fn stack_label(
        &self,
        declaration: DeclarationId,
        call_source: Span,
        label_bytes: usize,
    ) -> Result<wrela_diagnostics::Label, EvaluationFailure> {
        const PREFIX: &str = "comptime call to `";
        const SUFFIX: &str = "` entered here";
        let declaration = self
            .program
            .declaration(declaration)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let module = self
            .program
            .modules
            .get(declaration.module.0 as usize)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let name = declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let mut message = String::new();
        message
            .try_reserve_exact(label_bytes)
            .map_err(|_| self.evaluator_byte_failure())?;
        message.push_str(PREFIX);
        for (index, segment) in module.path.segments().iter().enumerate() {
            check_cancelled(self.is_cancelled).map_err(EvaluationFailure::Analysis)?;
            if index != 0 {
                message.push('.');
            }
            self.append_polled_source_text(&mut message, segment)?;
        }
        message.push('.');
        self.append_polled_source_text(&mut message, name)?;
        message.push_str(SUFFIX);
        if message.len() != label_bytes {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch,
            ));
        }
        Ok(wrela_diagnostics::Label {
            span: call_source,
            message,
        })
    }

    fn stack_label_bytes(&self, declaration: DeclarationId) -> Result<usize, EvaluationFailure> {
        const PREFIX: &str = "comptime call to `";
        const SUFFIX: &str = "` entered here";
        let declaration = self
            .program
            .declaration(declaration)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let module = self
            .program
            .modules
            .get(declaration.module.0 as usize)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let name = declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or_else(|| self.evaluator_byte_failure())?;
        let mut module_bytes = 0usize;
        for (index, segment) in module.path.segments().iter().enumerate() {
            check_cancelled(self.is_cancelled).map_err(EvaluationFailure::Analysis)?;
            module_bytes = module_bytes
                .checked_add(usize::from(index != 0))
                .and_then(|bytes| bytes.checked_add(segment.len()))
                .ok_or_else(|| self.evaluator_byte_failure())?;
        }
        PREFIX
            .len()
            .checked_add(module_bytes)
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| bytes.checked_add(name.len()))
            .and_then(|bytes| bytes.checked_add(SUFFIX.len()))
            .ok_or_else(|| self.evaluator_byte_failure())
    }

    fn append_polled_source_text(
        &self,
        output: &mut String,
        value: &str,
    ) -> Result<(), EvaluationFailure> {
        let mut start = 0;
        while start < value.len() {
            check_cancelled(self.is_cancelled).map_err(EvaluationFailure::Analysis)?;
            let mut end = start
                .checked_add(COMPTIME_SOURCE_COPY_CHUNK_BYTES)
                .unwrap_or(value.len())
                .min(value.len());
            while end > start && !value.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err(EvaluationFailure::Analysis(
                    AnalysisFailure::RequestMismatch,
                ));
            }
            output.push_str(&value[start..end]);
            start = end;
        }
        Ok(())
    }

    fn diagnostic_category(
        &self,
        category: Category,
        source: Span,
        code: &str,
        message: &str,
    ) -> EvaluationFailure {
        let mut diagnostic = Diagnostic::error(category, source, message);
        diagnostic.code = Some(code.to_owned());
        self.finish_diagnostic(diagnostic)
    }

    fn finish_diagnostic(&self, mut diagnostic: Diagnostic) -> EvaluationFailure {
        let diagnostic_limit = self.request.limits.diagnostic_bytes;
        let test_limit = self.request.limits.test_bytes;
        let mut diagnostic_bytes = diagnostic
            .message
            .len()
            .saturating_add(diagnostic.code.as_ref().map_or(0, String::len));
        for label in &diagnostic.labels {
            diagnostic_bytes = diagnostic_bytes.saturating_add(label.message.len());
        }
        let output_limit_failure = |resource, limit| {
            EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit { resource, limit })
        };
        if u64::try_from(diagnostic_bytes).map_or(true, |bytes| bytes > diagnostic_limit) {
            return output_limit_failure("diagnostic bytes", diagnostic_limit);
        }
        if u64::try_from(diagnostic_bytes).map_or(true, |bytes| bytes > test_limit) {
            return output_limit_failure("test plan or results", test_limit);
        }
        let stack_entries = usize::from(self.attempted_call.is_some()).saturating_add(
            self.frames
                .iter()
                .filter(|frame| frame.call_source.is_some())
                .count(),
        );
        if stack_entries != 0 {
            if diagnostic.labels.try_reserve_exact(stack_entries).is_err() {
                return self.evaluator_byte_failure();
            }
            if let Some((declaration, call_source)) = self.attempted_call {
                let label_bytes = match self.stack_label_bytes(declaration) {
                    Ok(bytes) => bytes,
                    Err(error) => return error,
                };
                if let Err(error) =
                    self.charge_stack_label_output(label_bytes, &mut diagnostic_bytes)
                {
                    return error;
                }
                match self.stack_label(declaration, call_source, label_bytes) {
                    Ok(label) => diagnostic.labels.push(label),
                    Err(error) => return error,
                }
            }
            for frame in self.frames.iter().rev() {
                if let Some(call_source) = frame.call_source {
                    let label_bytes = match self.stack_label_bytes(frame.declaration) {
                        Ok(bytes) => bytes,
                        Err(error) => return error,
                    };
                    if let Err(error) =
                        self.charge_stack_label_output(label_bytes, &mut diagnostic_bytes)
                    {
                        return error;
                    }
                    match self.stack_label(frame.declaration, call_source, label_bytes) {
                        Ok(label) => diagnostic.labels.push(label),
                        Err(error) => return error,
                    }
                }
            }
        }
        EvaluationFailure::Diagnostic(Box::new(diagnostic))
    }

    fn charge_stack_label_output(
        &self,
        label_bytes: usize,
        diagnostic_bytes: &mut usize,
    ) -> Result<(), EvaluationFailure> {
        *diagnostic_bytes =
            diagnostic_bytes
                .checked_add(label_bytes)
                .ok_or(EvaluationFailure::Analysis(
                    AnalysisFailure::ResourceLimit {
                        resource: "diagnostic bytes",
                        limit: self.request.limits.diagnostic_bytes,
                    },
                ))?;
        let output_bytes = u64::try_from(*diagnostic_bytes).map_err(|_| {
            EvaluationFailure::Analysis(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: self.request.limits.diagnostic_bytes,
            })
        })?;
        if output_bytes > self.request.limits.diagnostic_bytes {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: self.request.limits.diagnostic_bytes,
                },
            ));
        }
        if output_bytes > self.request.limits.test_bytes {
            return Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "test plan or results",
                    limit: self.request.limits.test_bytes,
                },
            ));
        }
        Ok(())
    }
}

enum Control {
    Continue,
    Return(ComptimeValue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActorMethodRole {
    Turn,
    Task(TaskId),
}

#[derive(Debug)]
struct ActorMethodPlan {
    declaration: DeclarationId,
    body: BodyId,
    role: ActorMethodRole,
    color: FunctionColor,
    source: Span,
    runtime_statements: Vec<StatementId>,
    has_send: bool,
    await_sources: Vec<Span>,
    function: Option<FunctionInstanceId>,
}

#[derive(Debug)]
struct ActorPlan {
    id: ActorId,
    evaluated: EvaluatedActor,
    class_source: Span,
    methods: Vec<ActorMethodPlan>,
}

fn populate_evaluated_image(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    constructor: DeclarationId,
    mut image: EvaluatedImage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<Diagnostic>, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let image_name = copy_analysis_text(
        image.name().ok_or(AnalysisFailure::RequestMismatch)?,
        request.limits.fact_bytes,
        is_cancelled,
    )?;
    let actors = std::mem::take(&mut image.actors);
    let names = std::mem::take(&mut image.names);
    let checkpoint = RuntimeCheckpoint::new(partial);
    populate_minimum_image(request, partial, constructor, image_name)?;
    if actors.is_empty() {
        return Ok(None);
    }
    match populate_actor_image(request, partial, actors, &names, is_cancelled) {
        Ok(()) => Ok(None),
        Err(RuntimeFailure::Diagnostic(diagnostic)) => {
            checkpoint.rollback(partial);
            partial.graph = None;
            Ok(Some(*diagnostic))
        }
        Err(RuntimeFailure::Analysis(error)) => {
            checkpoint.rollback(partial);
            partial.graph = None;
            Err(error)
        }
    }
}

fn inspect_actor_plans(
    request: &AnalysisRequest<'_>,
    actors: Vec<EvaluatedActor>,
    actor_names: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<Vec<ActorPlan>> {
    if actors.len() > request.limits.image_nodes as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "image actor nodes",
            limit: u64::from(request.limits.image_nodes),
        }
        .into());
    }
    let program = request.hir.as_program();
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(actors.len())
        .map_err(|_| fact_resource(request, "actor analysis plans"))?;
    let mut next_task = 0u32;
    for (actor_index, actor) in actors.into_iter().enumerate() {
        check_cancelled(is_cancelled)?;
        actor
            .name_in(actor_names)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let declaration = program
            .declaration(actor.class)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let DeclarationKind::Class(class) = &declaration.kind else {
            return Err(actor_runtime_diagnostic(
                Category::ACTOR,
                actor.source,
                "semantic-actor-install-class",
                "installed actor declaration is not a class",
                "install an @app or @service class",
            ));
        };
        if declaration.visibility != wrela_hir::Visibility::Public
            || !class.generics.is_empty()
            || !class.implements.is_empty()
        {
            return Err(actor_runtime_diagnostic(
                Category::ACTOR,
                declaration.source,
                "semantic-actor-class-shape",
                "actor class must be public, concrete, and non-generic in this revision 0.1 slice",
                "remove generic and interface specialization from the installed actor class",
            ));
        }
        if !class.fields.is_empty() {
            return Err(actor_runtime_diagnostic(
                Category::ACTOR,
                class.fields[0].source,
                "semantic-actor-state-not-supported",
                "actor field initialization is not coherent in the current image-construction slice",
                "use a stateless actor until typed image wiring and actor-state initialization are lowered",
            ));
        }
        let mut actor_attribute = None;
        let mut duplicate_actor_attribute = false;
        for attribute in &declaration.attributes {
            check_cancelled(is_cancelled)?;
            if matches!(
                attribute.identity,
                wrela_hir::AttributeIdentity::Builtin(
                    wrela_hir::BuiltinAttribute::App
                        | wrela_hir::BuiltinAttribute::Service
                        | wrela_hir::BuiltinAttribute::Driver
                )
            ) && actor_attribute.replace(attribute).is_some()
            {
                duplicate_actor_attribute = true;
            }
        }
        if duplicate_actor_attribute
            || actor_attribute.is_none_or(|attribute| {
                attribute.identity != wrela_hir::AttributeIdentity::Builtin(actor.kind.attribute())
                    || !attribute.arguments.is_empty()
            })
        {
            return Err(actor_runtime_diagnostic(
                Category::ACTOR,
                declaration.source,
                "semantic-actor-role",
                "installed actor class has an ambiguous or mismatched actor role",
                "declare exactly one matching @app or @service attribute without arguments",
            ));
        }
        let mut methods = Vec::new();
        methods
            .try_reserve_exact(class.members.len())
            .map_err(|_| fact_resource(request, "actor method plans"))?;
        for member_id in &class.members {
            check_cancelled(is_cancelled)?;
            let member = program
                .declaration(*member_id)
                .ok_or(AnalysisFailure::RequestMismatch)?;
            let DeclarationKind::Function(function) = &member.kind else {
                return Err(actor_runtime_diagnostic(
                    Category::ACTOR,
                    member.source,
                    "semantic-actor-member-kind",
                    "actor classes in this slice may contain only runtime functions",
                    "move nested types and protocols outside the actor class",
                ));
            };
            if function.color == FunctionColor::Isr {
                return Err(actor_runtime_diagnostic(
                    Category::HARDWARE,
                    member.source,
                    "semantic-isr-not-supported",
                    "ISR actor members require a concrete target device and interrupt binding",
                    "bind the ISR through a supported driver/device image installation",
                ));
            }
            if function.color == FunctionColor::Comptime || !function.generics.is_empty() {
                return Err(actor_runtime_diagnostic(
                    Category::ACTOR,
                    member.source,
                    "semantic-actor-method-shape",
                    "actor runtime methods must be concrete sync or async functions",
                    "remove comptime color and generic parameters from the installed runtime method",
                ));
            }
            let mut task_attribute = None;
            let mut method_attribute_invalid = false;
            for attribute in &member.attributes {
                check_cancelled(is_cancelled)?;
                if attribute.identity
                    == wrela_hir::AttributeIdentity::Builtin(wrela_hir::BuiltinAttribute::Task)
                {
                    if task_attribute.replace(attribute).is_some() {
                        method_attribute_invalid = true;
                    }
                } else {
                    method_attribute_invalid = true;
                }
            }
            if method_attribute_invalid
                || task_attribute.is_some_and(|attribute| !attribute.arguments.is_empty())
            {
                return Err(actor_runtime_diagnostic(
                    Category::ACTOR,
                    member.source,
                    "semantic-actor-method-attribute",
                    "actor method attributes are outside the supported static task subset",
                    "use a bare @task attribute or no method attribute",
                ));
            }
            let role = if task_attribute.is_none() {
                if member.visibility != wrela_hir::Visibility::Public {
                    return Err(actor_runtime_diagnostic(
                        Category::ACTOR,
                        member.source,
                        "semantic-actor-private-helper-not-supported",
                        "private actor helpers are not yet closed by this actor-body slice",
                        "move the helper to a module-level concrete function",
                    ));
                }
                ActorMethodRole::Turn
            } else {
                let task = TaskId(next_task);
                next_task = next_task
                    .checked_add(1)
                    .ok_or_else(|| fact_resource(request, "image task nodes"))?;
                ActorMethodRole::Task(task)
            };
            let Some(body) = function.body else {
                return Err(actor_runtime_diagnostic(
                    Category::ACTOR,
                    member.source,
                    "semantic-actor-method-body",
                    "installed actor method must have a body",
                    "provide a concrete bounded runtime body",
                ));
            };
            if !test_result_is_unit(function.result.as_ref()) || function.parameters.is_empty() {
                return Err(actor_runtime_diagnostic(
                    Category::TYPE,
                    member.source,
                    "semantic-actor-method-signature",
                    "actor methods in this slice require a receiver and a unit result",
                    "add `mut self` and return unit",
                ));
            }
            let receiver = program
                .parameter(function.parameters[0])
                .ok_or(AnalysisFailure::RequestMismatch)?;
            if !receiver.receiver || receiver.access != wrela_hir::AccessMode::Mutate {
                return Err(actor_runtime_diagnostic(
                    Category::ACTOR,
                    receiver.source,
                    "semantic-actor-receiver",
                    "actor turn and task methods require the actor-owned `mut self` receiver",
                    "declare `mut self` as the first parameter",
                ));
            }
            let mut runtime_statements = Vec::new();
            let mut runtime_callees = Vec::new();
            match inspect_runtime_body_shape(
                request,
                body,
                function.color,
                false,
                &mut runtime_statements,
                &mut runtime_callees,
                is_cancelled,
            ) {
                Ok(()) => {}
                Err(RuntimeShapeFailure::Unsupported(source)) => {
                    return Err(actor_runtime_diagnostic(
                        Category::ASYNC,
                        source,
                        "semantic-actor-body-not-supported",
                        "actor body is outside the bounded scalar async subset",
                        "use scalar locals, direct calls, await, return, and no-phi conditionals",
                    ));
                }
                Err(RuntimeShapeFailure::UnsupportedAssertion(source)) => {
                    return Err(actor_runtime_diagnostic(
                        Category::ACTOR,
                        source,
                        "semantic-runtime-assertion-not-supported",
                        "runtime assertions are supported only in selected generated tests",
                        "actor abandonment and supervision are required before assertion failure can terminate a turn",
                    ));
                }
                Err(RuntimeShapeFailure::Failure(error)) => return Err(error.into()),
            }
            let closure = collect_source_body_closure(program, body, is_cancelled)?;
            let has_send = runtime_statements.iter().any(|statement| {
                program
                    .statement(*statement)
                    .is_some_and(|statement| matches!(statement.kind, StatementKind::Send(_)))
            });
            let mut await_sources = Vec::new();
            await_sources
                .try_reserve_exact(closure.expressions.len())
                .map_err(|_| fact_resource(request, "async suspension points"))?;
            for expression in closure.expressions {
                check_cancelled(is_cancelled)?;
                let expression = program
                    .expression(expression)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                if matches!(
                    expression.kind,
                    ExpressionKind::Unary {
                        operator: wrela_hir::UnaryOperator::Await,
                        ..
                    }
                ) {
                    await_sources.push(expression.source);
                }
            }
            cancellable_stable_sort_by(
                &mut await_sources,
                u64::from(request.limits.expression_facts),
                "async suspension-point sort scratch",
                is_cancelled,
                &|left, right| {
                    Ok((left.file, left.range.start, left.range.end).cmp(&(
                        right.file,
                        right.range.start,
                        right.range.end,
                    )))
                },
            )?;
            if let Some(await_source) = await_sources.first().copied() {
                for parameter_id in function.parameters.iter().skip(1) {
                    let parameter = program
                        .parameter(*parameter_id)
                        .ok_or(AnalysisFailure::RequestMismatch)?;
                    if matches!(
                        parameter.access,
                        wrela_hir::AccessMode::Read | wrela_hir::AccessMode::Mutate
                    ) || parameter
                        .ty
                        .as_ref()
                        .is_some_and(|ty| matches!(ty.kind, TypeExpressionKind::View { .. }))
                    {
                        let mut diagnostic = Diagnostic::error(
                            Category::ASYNC,
                            await_source,
                            "borrowed access may not remain live across actor suspension",
                        );
                        diagnostic.code = Some("semantic-view-across-await".to_owned());
                        diagnostic
                            .labels
                            .try_reserve_exact(1)
                            .map_err(|_| fact_resource(request, "async diagnostic labels"))?;
                        diagnostic.labels.push(wrela_diagnostics::Label {
                            span: parameter.source,
                            message: "this external loan belongs to the caller".to_owned(),
                        });
                        diagnostic.notes.push(
                            "only the turn-rooted self access is stable while the non-reentrant actor is suspended"
                                .to_owned(),
                        );
                        diagnostic.help.push(
                            "copy or take the required value before await, then reacquire any view afterward"
                                .to_owned(),
                        );
                        return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
                    }
                }
            }
            methods.push(ActorMethodPlan {
                declaration: *member_id,
                body,
                role,
                color: function.color,
                source: member.source,
                runtime_statements,
                has_send,
                await_sources,
                function: None,
            });
        }
        if methods.is_empty() {
            return Err(actor_runtime_diagnostic(
                Category::ACTOR,
                declaration.source,
                "semantic-actor-empty",
                "installed actor has no public turn or static task entry",
                "add a public method or bare @task method",
            ));
        }
        plans.push(ActorPlan {
            id: ActorId(
                u32::try_from(actor_index)
                    .map_err(|_| fact_resource(request, "image actor nodes"))?,
            ),
            evaluated: actor,
            class_source: declaration.source,
            methods,
        });
    }
    let total_nodes = plans
        .len()
        .checked_add(
            usize::try_from(next_task).map_err(|_| fact_resource(request, "image task nodes"))?,
        )
        .ok_or_else(|| fact_resource(request, "image actor and task nodes"))?;
    if total_nodes > request.limits.image_nodes as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "image actor and task nodes",
            limit: u64::from(request.limits.image_nodes),
        }
        .into());
    }
    Ok(plans)
}

fn actor_runtime_diagnostic(
    category: Category,
    source: Span,
    code: &'static str,
    message: &'static str,
    help: &'static str,
) -> RuntimeFailure {
    let mut diagnostic = Diagnostic::error(category, source, message);
    diagnostic.code = Some(code.to_owned());
    diagnostic.help.push(help.to_owned());
    RuntimeFailure::Diagnostic(Box::new(diagnostic))
}

#[derive(Debug, Clone, Copy)]
struct ResolvedActorSend {
    actor: ActorId,
    method: FunctionInstanceId,
    mailbox_proof: ProofId,
    source: Span,
}

fn resolve_self_actor_send(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    caller: FunctionInstanceId,
    expression: ExpressionId,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<ResolvedActorSend> {
    check_cancelled(is_cancelled)?;
    let program = request.hir.as_program();
    let call = program
        .expression(expression)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let ExpressionKind::Call { callee, arguments } = &call.kind else {
        return Err(actor_runtime_diagnostic(
            Category::ACTOR,
            call.source,
            "semantic-actor-send-call",
            "one-way send requires an actor method call",
            "write `send self.method()` in the bounded startup-task subset",
        ));
    };
    if !arguments.is_empty() {
        return Err(actor_runtime_diagnostic(
            Category::TYPE,
            call.source,
            "semantic-actor-send-payload-not-supported",
            "one-way send payload is outside the implemented unit-message subset",
            "use a unit-returning actor method with no message parameters",
        ));
    }
    let callee_expression = program
        .expression(*callee)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let ExpressionKind::Field { base, name } = &callee_expression.kind else {
        return Err(actor_runtime_diagnostic(
            Category::ACTOR,
            callee_expression.source,
            "semantic-actor-send-receiver",
            "the implemented one-way send subset requires the image-wired self actor",
            "send from a static @task with `send self.method()`",
        ));
    };
    let base_expression = program
        .expression(*base)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let ExpressionKind::Reference(Definition::Parameter(receiver)) = base_expression.kind else {
        return Err(actor_runtime_diagnostic(
            Category::ACTOR,
            base_expression.source,
            "semantic-actor-send-receiver",
            "the implemented one-way send subset requires the image-wired self actor",
            "send from a static @task with `send self.method()`",
        ));
    };
    let caller_record = partial
        .functions
        .get(caller.0 as usize)
        .filter(|function| function.id == caller)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let FunctionRole::TaskEntry(task_id) = caller_record.role else {
        return Err(actor_runtime_diagnostic(
            Category::ACTOR,
            call.source,
            "semantic-actor-send-producer",
            "one-way send is currently admitted only from a startup-once @task",
            "move the send into a bare @task method so its burst bound is finite",
        ));
    };
    if caller_record
        .parameters
        .first()
        .is_none_or(|parameter| parameter.parameter != receiver)
    {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    let graph = partial
        .graph
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let actor = graph
        .tasks
        .get(task_id.0 as usize)
        .filter(|task| task.id == task_id)
        .and_then(|task| task.supervisor)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let actor_record = graph
        .actors
        .get(actor.0 as usize)
        .filter(|record| record.id == actor)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let mut method = None;
    for candidate in &actor_record.turn_functions {
        check_cancelled(is_cancelled)?;
        let candidate_record = partial
            .functions
            .get(candidate.0 as usize)
            .filter(|function| function.id == *candidate)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let matches_name = match candidate_record.origin {
            FunctionOrigin::Source { declaration, .. } => program
                .declaration(declaration)
                .and_then(|declaration| declaration.name.as_ref())
                .is_some_and(|candidate_name| candidate_name == name),
            _ => false,
        };
        if matches_name && method.replace(*candidate).is_some() {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }
    let method = method.ok_or_else(|| {
        actor_runtime_diagnostic(
            Category::ACTOR,
            callee_expression.source,
            "semantic-actor-send-target",
            "one-way send target is not a public turn on the image-wired actor",
            "name one public unit-message actor method",
        )
    })?;
    let method_record = partial
        .functions
        .get(method.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if method_record.role != FunctionRole::ActorTurn(actor)
        || method_record.color != FunctionColor::Async
        || method_record.parameters.len() != 1
        || method_record.result != SemanticTypeId(0)
    {
        return Err(actor_runtime_diagnostic(
            Category::ACTOR,
            callee_expression.source,
            "semantic-actor-send-target",
            "one-way send target must be one async unit-message actor turn",
            "declare `pub async fn method(mut self)` with a bounded body",
        ));
    }
    let mut mailbox_proof = None;
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        if region.owner == ImageOwner::Actor(actor)
            && region.class == RegionClass::Image
            && mailbox_proof.replace(region.proof).is_some()
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }
    Ok(ResolvedActorSend {
        actor,
        method,
        mailbox_proof: mailbox_proof.ok_or(AnalysisFailure::RequestMismatch)?,
        source: call.source,
    })
}

fn ensure_actor_reservation_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
) -> Result<SemanticTypeId, AnalysisFailure> {
    if let Some(existing) = partial
        .types
        .iter()
        .find(|ty| ty.kind == SemanticTypeKind::Reservation)
    {
        return Ok(existing.id);
    }
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "actor reservation type"));
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len())
            .map_err(|_| fact_resource(request, "actor reservation type"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "actor reservation type"))?;
    partial.types.push(SemanticType {
        id,
        kind: SemanticTypeKind::Reservation,
        linearity: Linearity::StrictLinear,
        size_upper_bound: Some(8),
        alignment_lower_bound: 8,
        source: None,
    });
    Ok(id)
}

fn prepare_actor_sends(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    plans: &[ActorPlan],
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    check_cancelled(is_cancelled)?;
    let actor_count = partial
        .graph
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?
        .actors
        .len();
    let mut admitted = Vec::new();
    admitted
        .try_reserve_exact(actor_count)
        .map_err(|_| fact_resource(request, "actor send admission counts"))?;
    admitted.resize(actor_count, 0u32);
    let mut any_send = false;
    for plan in plans {
        for method in &plan.methods {
            check_cancelled(is_cancelled)?;
            let caller = method.function.ok_or(AnalysisFailure::RequestMismatch)?;
            for statement in &method.runtime_statements {
                check_cancelled(is_cancelled)?;
                let statement = request
                    .hir
                    .as_program()
                    .statement(*statement)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                let StatementKind::Send(expression) = statement.kind else {
                    continue;
                };
                any_send = true;
                let resolved =
                    resolve_self_actor_send(request, partial, caller, expression, is_cancelled)?;
                let count = admitted
                    .get_mut(resolved.actor.0 as usize)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| fact_resource(request, "actor send admission count"))?;
                let mailbox_capacity = partial
                    .graph
                    .as_ref()
                    .and_then(|graph| graph.actors.get(resolved.actor.0 as usize))
                    .map(|actor| actor.mailbox_capacity)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                if *count > mailbox_capacity {
                    return Err(actor_runtime_diagnostic(
                        Category::CAPACITY,
                        statement.source,
                        "semantic-actor-send-mailbox-over-bound",
                        "startup one-way sends exceed the sealed mailbox capacity",
                        "increase the explicit mailbox bound or reduce the startup send burst",
                    ));
                }
                if *count > 1 {
                    return Err(actor_runtime_diagnostic(
                        Category::ACTOR,
                        statement.source,
                        "semantic-actor-send-single-message-bound",
                        "the implemented FIFO dispatch subset admits one startup message per actor",
                        "keep one startup send until recurring mailbox scheduling is implemented",
                    ));
                }
                if partial.proofs.len() >= request.limits.proofs as usize {
                    return Err(fact_resource(request, "actor send admission proof").into());
                }
                let permit = ProofId(
                    u32::try_from(partial.proofs.len())
                        .map_err(|_| fact_resource(request, "actor send admission proof"))?,
                );
                let target_name = partial
                    .functions
                    .get(resolved.method.0 as usize)
                    .map(|function| function.name.as_str())
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                partial
                    .proofs
                    .try_reserve(1)
                    .map_err(|_| fact_resource(request, "actor send admission proof"))?;
                partial.proofs.push(Proof {
                    id: permit,
                    kind: ProofKind::CapacityBound,
                    subject: bounded_actor_text(
                        request,
                        "one-way admission: ",
                        "",
                        target_name,
                        is_cancelled,
                    )?,
                    sources: vec![resolved.source],
                    depends_on: vec![resolved.mailbox_proof],
                    bound: Some(1),
                    explanation: vec![
                        "the startup-once producer contributes one message to an initially empty bounded mailbox before FIFO dispatch"
                            .to_owned(),
                    ],
                });
                let caller_record = partial
                    .functions
                    .get_mut(caller.0 as usize)
                    .ok_or(AnalysisFailure::RequestMismatch)?;
                caller_record
                    .proofs
                    .try_reserve(1)
                    .map_err(|_| fact_resource(request, "actor send proof references"))?;
                caller_record.proofs.push(permit);
                caller_record.proofs.sort_unstable();
                caller_record.proofs.dedup();
            }
        }
    }
    if any_send {
        let _ = ensure_actor_reservation_type(request, partial)?;
    }
    Ok(())
}

fn populate_actor_image(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    actors: Vec<EvaluatedActor>,
    actor_names: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<()> {
    check_cancelled(is_cancelled)?;
    let mut plans = inspect_actor_plans(request, actors, actor_names, is_cancelled)?;
    let Some(mut graph) = partial.graph.take() else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    if partial.proofs.last().map(|proof| (proof.id, &proof.kind))
        != Some((ProofId(2), &ProofKind::ImageClosed))
    {
        return Err(AnalysisFailure::RequestMismatch.into());
    }
    partial.proofs.pop();
    let entry = partial
        .functions
        .get_mut(graph.entry.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    if entry.proofs.pop() != Some(ProofId(2)) {
        return Err(AnalysisFailure::RequestMismatch.into());
    }

    let mut class_types = Vec::new();
    class_types
        .try_reserve_exact(plans.len())
        .map_err(|_| fact_resource(request, "actor class types"))?;
    let mut runtime_aggregate_work = RuntimeAggregateWork::default();
    for plan in &plans {
        check_cancelled(is_cancelled)?;
        class_types.push(append_actor_class_type(request, partial, plan)?);
    }

    let mut actor_nodes = Vec::new();
    let mut task_nodes = Vec::new();
    actor_nodes
        .try_reserve_exact(plans.len())
        .map_err(|_| fact_resource(request, "image actor nodes"))?;
    let task_count = plans
        .iter()
        .try_fold(0usize, |count, plan| {
            count.checked_add(
                plan.methods
                    .iter()
                    .filter(|method| matches!(method.role, ActorMethodRole::Task(_)))
                    .count(),
            )
        })
        .ok_or_else(|| fact_resource(request, "image task nodes"))?;
    task_nodes
        .try_reserve_exact(task_count)
        .map_err(|_| fact_resource(request, "image task nodes"))?;

    for (plan_index, plan) in plans.iter_mut().enumerate() {
        check_cancelled(is_cancelled)?;
        let plan_name = plan
            .evaluated
            .name_in(actor_names)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let class_ty = *class_types
            .get(plan_index)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let mut turn_functions = Vec::new();
        let mut message_types = Vec::new();
        turn_functions
            .try_reserve_exact(plan.methods.len())
            .map_err(|_| fact_resource(request, "actor turn functions"))?;
        message_types
            .try_reserve_exact(plan.methods.len())
            .map_err(|_| fact_resource(request, "actor message types"))?;
        for method in &mut plan.methods {
            check_cancelled(is_cancelled)?;
            let function = append_actor_method_function(
                request,
                partial,
                plan.id,
                class_ty,
                method,
                &mut runtime_aggregate_work,
                is_cancelled,
            )?;
            method.function = Some(function);
            match method.role {
                ActorMethodRole::Turn => {
                    turn_functions.push(function);
                    let (color, result, message_parameters) = {
                        let record = partial
                            .functions
                            .get(function.0 as usize)
                            .ok_or(AnalysisFailure::RequestMismatch)?;
                        let source = record
                            .parameters
                            .get(1..)
                            .ok_or(AnalysisFailure::RequestMismatch)?;
                        let mut parameters = Vec::new();
                        parameters
                            .try_reserve_exact(source.len())
                            .map_err(|_| fact_resource(request, "actor message parameters"))?;
                        parameters.extend_from_slice(source);
                        (record.color, record.result, parameters)
                    };
                    let message_type = ensure_function_type(
                        request,
                        partial,
                        color,
                        &message_parameters,
                        result,
                        &mut runtime_aggregate_work,
                        is_cancelled,
                    )?;
                    message_types.push(message_type);
                }
                ActorMethodRole::Task(task) => {
                    task_nodes.push(TaskNode {
                        id: task,
                        name: bounded_actor_text(
                            request,
                            plan_name,
                            ".",
                            request
                                .hir
                                .as_program()
                                .declaration(method.declaration)
                                .and_then(|declaration| declaration.name.as_ref())
                                .map(wrela_hir::Name::as_str)
                                .ok_or(AnalysisFailure::RequestMismatch)?,
                            is_cancelled,
                        )?,
                        entry: function,
                        slots: 1,
                        priority: 1,
                        supervisor: Some(plan.id),
                        source: method.source,
                    });
                }
            }
        }
        cancellable_stable_sort_by(
            &mut turn_functions,
            u64::from(request.limits.monomorphizations),
            "actor turn-function sort scratch",
            is_cancelled,
            &|left, right| Ok(left.cmp(right)),
        )?;
        cancellable_stable_sort_by(
            &mut message_types,
            u64::from(request.limits.types),
            "actor message-type sort scratch",
            is_cancelled,
            &|left, right| Ok(left.cmp(right)),
        )?;
        cancellable_dedup(&mut message_types, is_cancelled)?;
        actor_nodes.push(ActorNode {
            id: plan.id,
            name: copy_analysis_text(plan_name, request.limits.fact_bytes, is_cancelled)?,
            class: class_ty,
            mailbox_capacity: plan.evaluated.mailbox_capacity,
            message_types,
            turn_functions,
            priority: 1,
            supervisor: None,
            source: plan.evaluated.source,
        });
    }
    cancellable_stable_sort_owned_by(
        &mut task_nodes,
        u64::from(request.limits.image_nodes),
        "image task-node sort scratch",
        is_cancelled,
        &|left, right| Ok(left.id.cmp(&right.id)),
    )?;
    for (index, task) in task_nodes.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if task.id.0 as usize != index {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }

    graph.actors = actor_nodes;
    graph.tasks = task_nodes;
    append_actor_regions_and_capacity_proofs(request, partial, &plans, &mut graph, is_cancelled)?;
    partial.graph = Some(graph);
    prepare_actor_sends(request, partial, &plans, is_cancelled)?;

    for plan in &plans {
        for method in &plan.methods {
            check_cancelled(is_cancelled)?;
            let function = method.function.ok_or(AnalysisFailure::RequestMismatch)?;
            populate_runtime_body(
                request,
                partial,
                RuntimeBodyTarget {
                    function,
                    declaration: method.declaration,
                    body: method.body,
                    allow_assertions: false,
                },
                &mut runtime_aggregate_work,
                is_cancelled,
            )?;
        }
    }

    let wait_proof = analyze_wait_graph(request, partial, is_cancelled)?;
    let regions = &partial
        .graph
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?
        .regions;
    let mut capacity_proofs = Vec::new();
    capacity_proofs
        .try_reserve_exact(regions.len())
        .map_err(|_| fact_resource(request, "capacity proof references"))?;
    capacity_proofs.extend(regions.iter().map(|region| region.proof));
    let closed_proof = append_actor_image_closed_proof(
        request,
        partial,
        &plans,
        wait_proof,
        &capacity_proofs,
        is_cancelled,
    )?;
    let graph = partial
        .graph
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let entry = partial
        .functions
        .get_mut(graph.entry.0 as usize)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let additional_proofs = capacity_proofs
        .len()
        .checked_add(2)
        .ok_or_else(|| fact_resource(request, "image entry proof references"))?;
    entry
        .proofs
        .try_reserve(additional_proofs)
        .map_err(|_| fact_resource(request, "image entry proof references"))?;
    entry.effects = EffectSet(EffectSet::FIRMWARE | EffectSet::ACTOR | EffectSet::TASK);
    entry.uninterrupted_work_bound = Some(
        1u64.checked_add(
            u64::try_from(graph.actors.len())
                .map_err(|_| fact_resource(request, "image startup work"))?,
        )
        .and_then(|work| work.checked_add(u64::try_from(graph.tasks.len()).ok()?))
        .ok_or_else(|| fact_resource(request, "image startup work"))?,
    );
    entry.proofs.push(wait_proof);
    entry.proofs.extend(capacity_proofs);
    entry.proofs.push(closed_proof);
    cancellable_stable_sort_by(
        &mut entry.proofs,
        u64::from(request.limits.proofs),
        "image entry proof sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )?;
    cancellable_dedup(&mut entry.proofs, is_cancelled)?;
    Ok(())
}

fn append_actor_class_type(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    plan: &ActorPlan,
) -> Result<SemanticTypeId, AnalysisFailure> {
    if partial.types.len() >= request.limits.types as usize {
        return Err(fact_resource(request, "actor class types"));
    }
    let id = SemanticTypeId(
        u32::try_from(partial.types.len())
            .map_err(|_| fact_resource(request, "actor class types"))?,
    );
    partial
        .types
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "actor class types"))?;
    partial.types.push(SemanticType {
        id,
        kind: SemanticTypeKind::Class {
            declaration: plan.evaluated.class,
            arguments: Vec::new(),
            fields: Vec::new(),
        },
        linearity: Linearity::ReclaimableLinear,
        size_upper_bound: Some(0),
        alignment_lower_bound: 1,
        source: Some(plan.class_source),
    });
    Ok(id)
}

fn append_actor_method_function(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    actor: ActorId,
    class_ty: SemanticTypeId,
    plan: &ActorMethodPlan,
    aggregate_work: &mut RuntimeAggregateWork,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<FunctionInstanceId> {
    check_cancelled(is_cancelled)?;
    let program = request.hir.as_program();
    let declaration = program
        .declaration(plan.declaration)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let DeclarationKind::Function(source) = &declaration.kind else {
        return Err(AnalysisFailure::RequestMismatch.into());
    };
    let proof_count = if plan.color == FunctionColor::Async {
        5usize
    } else {
        3usize
    };
    if partial.functions.len() >= request.limits.monomorphizations as usize
        || partial
            .proofs
            .len()
            .checked_add(proof_count)
            .is_none_or(|count| count > request.limits.proofs as usize)
    {
        return Err(fact_resource(request, "actor functions and proofs").into());
    }
    let id = FunctionInstanceId(
        u32::try_from(partial.functions.len())
            .map_err(|_| fact_resource(request, "actor functions"))?,
    );
    let name = bounded_actor_text(
        request,
        program
            .declaration(actor_class_declaration(partial, class_ty)?)
            .and_then(|class| class.name.as_ref())
            .map(wrela_hir::Name::as_str)
            .ok_or(AnalysisFailure::RequestMismatch)?,
        ".",
        declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or(AnalysisFailure::RequestMismatch)?,
        is_cancelled,
    )?;
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(source.parameters.len())
        .map_err(|_| fact_resource(request, "actor function parameters"))?;
    for (index, parameter_id) in source.parameters.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let parameter = program
            .parameter(*parameter_id)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let ty = if index == 0 {
            class_ty
        } else {
            semantic_type_from_source(
                request,
                partial,
                parameter
                    .ty
                    .as_ref()
                    .ok_or(AnalysisFailure::RequestMismatch)?,
                &mut *aggregate_work,
                is_cancelled,
            )?
        };
        let value = append_semantic_value(
            request,
            partial,
            id,
            ty,
            (
                SemanticValueOrigin::Parameter(*parameter_id),
                Some(parameter.source),
                Some(if parameter.receiver {
                    "self"
                } else {
                    parameter
                        .name
                        .as_ref()
                        .map(wrela_hir::Name::as_str)
                        .ok_or(AnalysisFailure::RequestMismatch)?
                }),
            ),
            is_cancelled,
        )?;
        parameters.push(FunctionParameter {
            parameter: *parameter_id,
            value,
            access: lower_access(parameter.access),
            ty,
        });
    }
    let first_proof = ProofId(
        u32::try_from(partial.proofs.len())
            .map_err(|_| fact_resource(request, "actor function proofs"))?,
    );
    let type_proof = first_proof;
    let effect_proof = ProofId(
        type_proof
            .0
            .checked_add(1)
            .ok_or_else(|| fact_resource(request, "actor function proofs"))?,
    );
    let ownership_proof = ProofId(
        effect_proof
            .0
            .checked_add(1)
            .ok_or_else(|| fact_resource(request, "actor function proofs"))?,
    );
    partial
        .proofs
        .try_reserve(proof_count)
        .map_err(|_| fact_resource(request, "actor function proofs"))?;
    partial.proofs.push(Proof {
        id: type_proof,
        kind: ProofKind::TypeChecked,
        subject: bounded_test_fact(request, "actor function type: ", &name, is_cancelled)?,
        sources: vec![plan.source],
        depends_on: Vec::new(),
        bound: None,
        explanation: vec![
            "the concrete actor receiver, scalar parameters, and unit result are well typed"
                .to_owned(),
        ],
    });
    let work_bound = u64::try_from(plan.runtime_statements.len())
        .ok()
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| fact_resource(request, "actor work bound"))?;
    partial.proofs.push(Proof {
        id: effect_proof,
        kind: ProofKind::EffectsAllowed,
        subject: bounded_test_fact(request, "actor function effects: ", &name, is_cancelled)?,
        sources: vec![plan.source],
        depends_on: vec![type_proof],
        bound: Some(work_bound),
        explanation: vec![if plan.color == FunctionColor::Async {
            "suspension is limited to statically resolved direct async activations".to_owned()
        } else {
            "the turn runs synchronously to completion under its finite statement bound".to_owned()
        }],
    });
    partial.proofs.push(Proof {
        id: ownership_proof,
        kind: ProofKind::Ownership,
        subject: bounded_test_fact(request, "actor turn ownership: ", &name, is_cancelled)?,
        sources: vec![plan.source],
        depends_on: vec![type_proof, effect_proof],
        bound: Some(1),
        explanation: vec![match plan.role {
            ActorMethodRole::Turn => "the actor owns exactly one non-reentrant external turn slot, retained across suspension".to_owned(),
            ActorMethodRole::Task(_) => "the static task owns its one generated activation slot and cannot alias an actor turn".to_owned(),
        }],
    });
    let mut proofs = vec![type_proof, effect_proof, ownership_proof];
    if plan.color == FunctionColor::Async {
        let view_proof = ProofId(
            ownership_proof
                .0
                .checked_add(1)
                .ok_or_else(|| fact_resource(request, "actor function proofs"))?,
        );
        let cleanup_proof = ProofId(
            view_proof
                .0
                .checked_add(1)
                .ok_or_else(|| fact_resource(request, "actor function proofs"))?,
        );
        let source_count = plan.await_sources.len().max(1);
        let mut sources = Vec::new();
        let mut cleanup_sources = Vec::new();
        sources
            .try_reserve_exact(source_count)
            .map_err(|_| fact_resource(request, "actor suspension proof sources"))?;
        cleanup_sources
            .try_reserve_exact(source_count)
            .map_err(|_| fact_resource(request, "actor cleanup proof sources"))?;
        if plan.await_sources.is_empty() {
            sources.push(plan.source);
            cleanup_sources.push(plan.source);
        } else {
            sources.extend_from_slice(&plan.await_sources);
            cleanup_sources.extend_from_slice(&plan.await_sources);
        }
        partial.proofs.push(Proof {
            id: view_proof,
            kind: ProofKind::ViewDoesNotEscape,
            subject: bounded_test_fact(
                request,
                "actor suspension safety: ",
                &name,
                is_cancelled,
            )?,
            sources,
            depends_on: vec![type_proof, ownership_proof],
            bound: Some(0),
            explanation: vec!["no external view or mutable loan is live at any suspension point; only turn-rooted self authority persists".to_owned()],
        });
        partial.proofs.push(Proof {
            id: cleanup_proof,
            kind: ProofKind::CleanupAcyclic,
            subject: bounded_test_fact(
                request,
                "actor cancellation cleanup: ",
                &name,
                is_cancelled,
            )?,
            sources: cleanup_sources,
            depends_on: vec![type_proof, ownership_proof, view_proof],
            bound: Some(
                u64::try_from(source.parameters.len())
                    .map_err(|_| fact_resource(request, "actor cleanup bound"))?,
            ),
            explanation: vec!["cancellation visits the fixed frame state once and destroys owned scalar values in reverse source order".to_owned()],
        });
        proofs.extend([view_proof, cleanup_proof]);
    }
    let frame_bytes_bound = if plan.color == FunctionColor::Async {
        let local_count = plan
            .runtime_statements
            .iter()
            .filter(|statement| {
                request
                    .hir
                    .as_program()
                    .statement(**statement)
                    .is_some_and(|statement| {
                        matches!(statement.kind, StatementKind::Initialize { .. })
                    })
            })
            .count();
        let live_values = source
            .parameters
            .len()
            .saturating_sub(1)
            .checked_add(local_count)
            .ok_or_else(|| fact_resource(request, "actor frame values"))?;
        16u64
            .checked_add(
                u64::try_from(live_values)
                    .ok()
                    .and_then(|values| values.checked_mul(16))
                    .ok_or_else(|| fact_resource(request, "actor frame bytes"))?,
            )
            .ok_or_else(|| fact_resource(request, "actor frame bytes"))?
    } else {
        0
    };
    partial
        .functions
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "actor functions"))?;
    partial.functions.push(FunctionInstance {
        id,
        key: actor_function_key(request, actor, plan.declaration, plan.role),
        name,
        origin: FunctionOrigin::Source {
            declaration: plan.declaration,
            body: plan.body,
        },
        role: match plan.role {
            ActorMethodRole::Turn => FunctionRole::ActorTurn(actor),
            ActorMethodRole::Task(task) => FunctionRole::TaskEntry(task),
        },
        color: plan.color,
        generic_arguments: Vec::new(),
        parameters,
        result: SemanticTypeId(0),
        effects: EffectSet(
            match plan.role {
                ActorMethodRole::Turn => EffectSet::ACTOR,
                ActorMethodRole::Task(_) => EffectSet::TASK,
            } | if plan.has_send { EffectSet::ACTOR } else { 0 }
                | if plan.color == FunctionColor::Async {
                    EffectSet::SUSPEND
                } else {
                    0
                },
        ),
        stack_bytes_bound: 64,
        frame_bytes_bound,
        uninterrupted_work_bound: Some(work_bound),
        recursive_depth_bound: Some(1),
        proofs,
        source: Some(plan.source),
    });
    Ok(id)
}

fn actor_class_declaration(
    partial: &PartialAnalysis,
    class: SemanticTypeId,
) -> Result<DeclarationId, AnalysisFailure> {
    let Some(SemanticType {
        kind: SemanticTypeKind::Class { declaration, .. },
        ..
    }) = partial.types.get(class.0 as usize)
    else {
        return Err(AnalysisFailure::RequestMismatch);
    };
    Ok(*declaration)
}

fn actor_function_key(
    request: &AnalysisRequest<'_>,
    actor: ActorId,
    declaration: DeclarationId,
    role: ActorMethodRole,
) -> FunctionKey {
    let mut bytes = *request.build.identity.request.as_bytes();
    bytes[0] ^= 0x41;
    bytes[1] ^= match role {
        ActorMethodRole::Turn => 0x54,
        ActorMethodRole::Task(_) => 0x4b,
    };
    for (destination, source) in bytes[20..24].iter_mut().zip(actor.0.to_be_bytes()) {
        *destination ^= source;
    }
    for (destination, source) in bytes[24..28].iter_mut().zip(declaration.0.to_be_bytes()) {
        *destination ^= source;
    }
    if let ActorMethodRole::Task(task) = role {
        for (destination, source) in bytes[28..32].iter_mut().zip(task.0.to_be_bytes()) {
            *destination ^= source;
        }
    }
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 0x41;
    }
    FunctionKey(wrela_build_model::Sha256Digest::from_bytes(bytes))
}

fn bounded_actor_text(
    request: &AnalysisRequest<'_>,
    left: &str,
    separator: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let resource_failure = || AnalysisFailure::ResourceLimit {
        resource: "semantic fact bytes",
        limit: request.limits.fact_bytes,
    };
    let length = left
        .len()
        .checked_add(separator.len())
        .and_then(|length| length.checked_add(right.len()))
        .ok_or_else(&resource_failure)?;
    if u64::try_from(length).map_or(true, |length| length > request.limits.fact_bytes) {
        return Err(resource_failure());
    }
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| resource_failure())?;
    append_polled_test_text(&mut output, left, is_cancelled)?;
    append_polled_test_text(&mut output, separator, is_cancelled)?;
    append_polled_test_text(&mut output, right, is_cancelled)?;
    if output.len() != length {
        return Err(AnalysisFailure::RequestMismatch);
    }
    Ok(output)
}

fn append_actor_regions_and_capacity_proofs(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    plans: &[ActorPlan],
    graph: &mut ImageGraph,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
    let region_count = graph
        .actors
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(graph.tasks.len()))
        .ok_or_else(|| fact_resource(request, "image capacity regions"))?;
    if region_count > request.limits.image_nodes as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "image capacity regions",
            limit: u64::from(request.limits.image_nodes),
        });
    }
    graph
        .regions
        .try_reserve_exact(region_count)
        .map_err(|_| fact_resource(request, "image capacity regions"))?;
    let mut static_bytes = 0u64;
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        let plan = plans
            .get(actor.id.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let mailbox_bytes = u64::from(actor.mailbox_capacity)
            .checked_mul(16)
            .ok_or_else(|| fact_resource(request, "actor mailbox bytes"))?;
        let proof = append_capacity_proof(
            request,
            partial,
            bounded_actor_text(request, "actor mailbox: ", "", &actor.name, is_cancelled)?,
            vec![plan.evaluated.mailbox_source],
            u64::from(actor.mailbox_capacity),
            "the explicit logical mailbox slot count is finite; each supported scalar message reserves a fixed 16-byte upper-bound slot",
        )?;
        graph.regions.push(Region {
            id: RegionId(
                u32::try_from(graph.regions.len())
                    .map_err(|_| fact_resource(request, "image capacity regions"))?,
            ),
            name: bounded_actor_text(request, &actor.name, ".", "mailbox", is_cancelled)?,
            class: RegionClass::Image,
            capacity_bytes: mailbox_bytes,
            alignment: 8,
            owner: ImageOwner::Actor(actor.id),
            proof,
            source: plan.evaluated.source,
        });
        static_bytes = static_bytes
            .checked_add(mailbox_bytes)
            .ok_or_else(|| fact_resource(request, "image static bytes"))?;
        let turn_frame_bytes = actor
            .turn_functions
            .iter()
            .filter_map(|function| partial.functions.get(function.0 as usize))
            .map(|function| function.frame_bytes_bound.max(1))
            .max()
            .unwrap_or(1);
        let turn_proof = append_capacity_proof(
            request,
            partial,
            bounded_actor_text(request, "actor turn slot: ", "", &actor.name, is_cancelled)?,
            vec![plan.evaluated.source],
            1,
            "non-reentrant actor scheduling admits exactly one active external turn and retains that fixed frame across suspension",
        )?;
        graph.regions.push(Region {
            id: RegionId(
                u32::try_from(graph.regions.len())
                    .map_err(|_| fact_resource(request, "image capacity regions"))?,
            ),
            name: bounded_actor_text(request, &actor.name, ".", "turn-frame", is_cancelled)?,
            class: RegionClass::TaskFrame,
            capacity_bytes: turn_frame_bytes,
            alignment: 8,
            owner: ImageOwner::Actor(actor.id),
            proof: turn_proof,
            source: plan.evaluated.source,
        });
        static_bytes = static_bytes
            .checked_add(turn_frame_bytes)
            .ok_or_else(|| fact_resource(request, "image static bytes"))?;
    }
    for task in &graph.tasks {
        check_cancelled(is_cancelled)?;
        let function = partial
            .functions
            .get(task.entry.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let frame_bytes = function.frame_bytes_bound.max(1);
        let capacity_bytes = frame_bytes
            .checked_mul(u64::from(task.slots))
            .ok_or_else(|| fact_resource(request, "task frame bytes"))?;
        let proof = append_capacity_proof(
            request,
            partial,
            bounded_actor_text(request, "task slots: ", "", &task.name, is_cancelled)?,
            vec![task.source],
            u64::from(task.slots),
            "the image installs one static activation slot and reserves its complete state-machine frame before boot",
        )?;
        graph.regions.push(Region {
            id: RegionId(
                u32::try_from(graph.regions.len())
                    .map_err(|_| fact_resource(request, "image capacity regions"))?,
            ),
            name: bounded_actor_text(request, &task.name, ".", "frame", is_cancelled)?,
            class: RegionClass::TaskFrame,
            capacity_bytes,
            alignment: 8,
            owner: ImageOwner::Task(task.id),
            proof,
            source: task.source,
        });
        static_bytes = static_bytes
            .checked_add(capacity_bytes)
            .ok_or_else(|| fact_resource(request, "image static bytes"))?;
    }
    graph.static_bytes = static_bytes;
    graph.peak_bytes = static_bytes;
    let owner_count = 1usize
        .checked_add(graph.actors.len())
        .and_then(|count| count.checked_add(graph.tasks.len()))
        .ok_or_else(|| fact_resource(request, "image owner order"))?;
    graph
        .startup_order
        .try_reserve(owner_count.saturating_sub(graph.startup_order.len()))
        .map_err(|_| fact_resource(request, "image startup order"))?;
    graph.startup_order.clear();
    graph.startup_order.push(ImageOwner::Runtime);
    graph
        .startup_order
        .extend(graph.actors.iter().map(|actor| ImageOwner::Actor(actor.id)));
    graph
        .startup_order
        .extend(graph.tasks.iter().map(|task| ImageOwner::Task(task.id)));
    graph
        .shutdown_order
        .try_reserve(owner_count.saturating_sub(graph.shutdown_order.len()))
        .map_err(|_| fact_resource(request, "image shutdown order"))?;
    graph.shutdown_order.clear();
    graph.shutdown_order.extend(
        graph
            .tasks
            .iter()
            .rev()
            .map(|task| ImageOwner::Task(task.id)),
    );
    graph.shutdown_order.extend(
        graph
            .actors
            .iter()
            .rev()
            .map(|actor| ImageOwner::Actor(actor.id)),
    );
    graph.shutdown_order.push(ImageOwner::Runtime);
    Ok(())
}

fn append_capacity_proof(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    subject: String,
    sources: Vec<Span>,
    bound: u64,
    explanation: &'static str,
) -> Result<ProofId, AnalysisFailure> {
    if partial.proofs.len() >= request.limits.proofs as usize {
        return Err(fact_resource(request, "capacity proofs"));
    }
    let id = ProofId(
        u32::try_from(partial.proofs.len())
            .map_err(|_| fact_resource(request, "capacity proofs"))?,
    );
    partial
        .proofs
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "capacity proofs"))?;
    partial.proofs.push(Proof {
        id,
        kind: ProofKind::CapacityBound,
        subject,
        sources,
        depends_on: Vec::new(),
        bound: Some(bound),
        explanation: vec![explanation.to_owned()],
    });
    Ok(id)
}

#[derive(Debug, Clone, Copy)]
struct WaitEdge {
    from: FunctionInstanceId,
    to: FunctionInstanceId,
    source: Span,
}

fn analyze_wait_graph(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    is_cancelled: &dyn Fn() -> bool,
) -> RuntimeResult<ProofId> {
    check_cancelled(is_cancelled)?;
    if partial.functions.len() > request.limits.fixed_point_iterations as usize {
        return Err(AnalysisFailure::ResourceLimit {
            resource: "semantic wait graph iterations",
            limit: u64::from(request.limits.fixed_point_iterations),
        }
        .into());
    }
    let program = request.hir.as_program();
    let mut edges = Vec::new();
    let mut awaited_operands = std::collections::HashSet::new();
    awaited_operands
        .try_reserve(partial.expressions.len())
        .map_err(|_| fact_resource(request, "wait graph awaited operands"))?;
    for fact in &partial.expressions {
        check_cancelled(is_cancelled)?;
        if fact.resolution != ExpressionResolution::Builtin(IntrinsicOperation::Await) {
            continue;
        }
        let expression = program
            .expression(fact.expression)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let ExpressionKind::Unary {
            operator: wrela_hir::UnaryOperator::Await,
            operand,
        } = expression.kind
        else {
            return Err(AnalysisFailure::RequestMismatch.into());
        };
        if !awaited_operands.insert((fact.function, operand)) {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
        let operand_fact = partial
            .expressions
            .iter()
            .find(|operand_fact| {
                operand_fact.function == fact.function && operand_fact.expression == operand
            })
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let target = match operand_fact.resolution {
            ExpressionResolution::DirectCall {
                function: target, ..
            } => target,
            _ => return Err(AnalysisFailure::RequestMismatch.into()),
        };
        if u64::try_from(edges.len()).map_or(true, |count| count >= request.limits.fact_edges) {
            return Err(fact_resource(request, "semantic wait graph edges").into());
        }
        edges
            .try_reserve(1)
            .map_err(|_| fact_resource(request, "semantic wait graph edges"))?;
        edges.push(WaitEdge {
            from: fact.function,
            to: target,
            source: expression.source,
        });
    }
    for fact in &partial.expressions {
        check_cancelled(is_cancelled)?;
        let target = match fact.resolution {
            ExpressionResolution::DirectCall {
                function: target, ..
            } => target,
            _ => continue,
        };
        if partial
            .functions
            .get(target.0 as usize)
            .is_some_and(|target| target.color == FunctionColor::Async)
            && !awaited_operands.contains(&(fact.function, fact.expression))
        {
            let source = program
                .expression(fact.expression)
                .map_or_else(|| fallback_span(program), |expression| expression.source);
            let mut diagnostic = Diagnostic::error(
                Category::ASYNC,
                source,
                "async activation is created without an immediate await boundary",
            );
            diagnostic.code = Some("semantic-async-result-not-awaited".to_owned());
            diagnostic.notes.push(
                "revision 0.1 does not allocate implicit futures or detached dynamic task frames"
                    .to_owned(),
            );
            diagnostic.help.push(
                "await the call immediately or install a statically bounded @task entry".to_owned(),
            );
            return Err(RuntimeFailure::Diagnostic(Box::new(diagnostic)));
        }
    }
    cancellable_stable_sort_by(
        &mut edges,
        request.limits.fact_edges,
        "wait-graph edge sort scratch",
        is_cancelled,
        &|left, right| {
            Ok((
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
                )))
        },
    )?;
    for pair in edges.windows(2) {
        check_cancelled(is_cancelled)?;
        if pair[0].from == pair[1].from
            && pair[0].to == pair[1].to
            && pair[0].source == pair[1].source
        {
            return Err(AnalysisFailure::RequestMismatch.into());
        }
    }
    if let Some(cycle) = find_wait_cycle(partial.functions.len(), &edges, is_cancelled)? {
        return Err(wait_cycle_diagnostic(
            request,
            partial,
            &cycle,
            is_cancelled,
        )?);
    }
    if partial.proofs.len() >= request.limits.proofs as usize {
        return Err(fact_resource(request, "wait graph proof").into());
    }
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(edges.len())
        .map_err(|_| fact_resource(request, "wait graph proof sources"))?;
    sources.extend(edges.iter().map(|edge| edge.source));
    cancellable_stable_sort_by(
        &mut sources,
        request.limits.fact_edges,
        "wait-graph source sort scratch",
        is_cancelled,
        &|left, right| {
            Ok((left.file, left.range.start, left.range.end).cmp(&(
                right.file,
                right.range.start,
                right.range.end,
            )))
        },
    )?;
    cancellable_dedup(&mut sources, is_cancelled)?;
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(partial.functions.len())
        .map_err(|_| fact_resource(request, "wait graph proof dependencies"))?;
    for function in &partial.functions {
        check_cancelled(is_cancelled)?;
        if function.color == FunctionColor::Async {
            if let Some(proof) = function.proofs.get(1).copied() {
                dependencies.push(proof);
            }
        }
    }
    cancellable_stable_sort_by(
        &mut dependencies,
        u64::from(request.limits.monomorphizations),
        "wait-graph dependency sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )?;
    cancellable_dedup(&mut dependencies, is_cancelled)?;
    let id = ProofId(
        u32::try_from(partial.proofs.len())
            .map_err(|_| fact_resource(request, "wait graph proof"))?,
    );
    partial
        .proofs
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "wait graph proof"))?;
    partial.proofs.push(Proof {
        id,
        kind: ProofKind::WaitGraphAcyclic,
        subject: copy_analysis_text(
            "closed actor/task wait-for graph",
            request.limits.fact_bytes,
            is_cancelled,
        )?,
        sources,
        depends_on: dependencies,
        bound: Some(
            u64::try_from(edges.len())
                .map_err(|_| fact_resource(request, "wait graph proof bound"))?,
        ),
        explanation: vec![
            "every await edge names a concrete monomorphized activation; bounded traversal found no hold-and-wait cycle"
                .to_owned(),
        ],
    });
    Ok(id)
}

fn find_wait_cycle(
    node_count: usize,
    edges: &[WaitEdge],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<Vec<WaitEdge>>, AnalysisFailure> {
    let limit = u64::try_from(edges.len()).unwrap_or(u64::MAX);
    let mut colors = Vec::new();
    let mut parents = Vec::new();
    let mut stack = Vec::new();
    colors
        .try_reserve_exact(node_count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic wait graph scratch",
            limit,
        })?;
    parents
        .try_reserve_exact(node_count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic wait graph scratch",
            limit,
        })?;
    stack
        .try_reserve_exact(node_count)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic wait graph scratch",
            limit,
        })?;
    colors.resize(node_count, 0u8);
    parents.resize(node_count, None::<WaitEdge>);
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
            *next += 1;
            let target = edge.to.0 as usize;
            let Some(color) = colors.get(target).copied() else {
                return Err(AnalysisFailure::RequestMismatch);
            };
            if color == 0 {
                colors[target] = 1;
                parents[target] = Some(edge);
                let target_start =
                    edges.partition_point(|candidate| (candidate.from.0 as usize) < target);
                stack.push((target, target_start));
            } else if color == 1 {
                let mut cycle = Vec::new();
                cycle
                    .try_reserve_exact(node_count.saturating_add(1))
                    .map_err(|_| AnalysisFailure::ResourceLimit {
                        resource: "semantic wait cycle",
                        limit,
                    })?;
                cycle.push(edge);
                let mut current = *node;
                while current != target {
                    let parent = parents
                        .get(current)
                        .and_then(|edge| *edge)
                        .ok_or(AnalysisFailure::RequestMismatch)?;
                    cycle.push(parent);
                    current = parent.from.0 as usize;
                    if cycle.len() > node_count {
                        return Err(AnalysisFailure::RequestMismatch);
                    }
                }
                cycle.reverse();
                return Ok(Some(cycle));
            }
        }
    }
    Ok(None)
}

fn wait_cycle_diagnostic(
    request: &AnalysisRequest<'_>,
    partial: &PartialAnalysis,
    cycle: &[WaitEdge],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<RuntimeFailure, AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let primary = cycle
        .last()
        .map(|edge| edge.source)
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let mut diagnostic = Diagnostic::error(
        Category::ASYNC,
        primary,
        "blocking actor/task wait-for cycle",
    );
    diagnostic.code = Some("semantic-wait-cycle".to_owned());
    diagnostic
        .labels
        .try_reserve_exact(cycle.len())
        .map_err(|_| fact_resource(request, "wait-cycle diagnostic labels"))?;
    diagnostic
        .notes
        .try_reserve_exact(cycle.len())
        .map_err(|_| fact_resource(request, "wait-cycle diagnostic notes"))?;
    for edge in cycle {
        let from = partial
            .functions
            .get(edge.from.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        let to = partial
            .functions
            .get(edge.to.0 as usize)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        diagnostic.labels.push(wrela_diagnostics::Label {
            span: edge.source,
            message: bounded_actor_text(
                request,
                &from.name,
                " waits for ",
                &to.name,
                is_cancelled,
            )?,
        });
        diagnostic.notes.push(bounded_actor_text(
            request,
            &from.name,
            " retains its activation while awaiting ",
            &to.name,
            is_cancelled,
        )?);
    }
    diagnostic.help.push(
        "break the cycle with a one-way notification, move work behind an external completion, or merge the mutually waiting state"
            .to_owned(),
    );
    Ok(RuntimeFailure::Diagnostic(Box::new(diagnostic)))
}

fn append_actor_image_closed_proof(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    plans: &[ActorPlan],
    wait_proof: ProofId,
    capacity_proofs: &[ProofId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProofId, AnalysisFailure> {
    if partial.proofs.len() >= request.limits.proofs as usize {
        return Err(fact_resource(request, "closed actor image proof"));
    }
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(capacity_proofs.len().saturating_add(3))
        .map_err(|_| fact_resource(request, "closed actor image proof dependencies"))?;
    dependencies.extend([ProofId(0), ProofId(1), wait_proof]);
    dependencies.extend_from_slice(capacity_proofs);
    cancellable_stable_sort_by(
        &mut dependencies,
        u64::from(request.limits.proofs),
        "closed-image dependency sort scratch",
        is_cancelled,
        &|left, right| Ok(left.cmp(right)),
    )?;
    cancellable_dedup(&mut dependencies, is_cancelled)?;
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(plans.len().saturating_add(1))
        .map_err(|_| fact_resource(request, "closed actor image proof sources"))?;
    sources.push(
        partial
            .proofs
            .first()
            .and_then(|proof| proof.sources.first())
            .copied()
            .ok_or(AnalysisFailure::RequestMismatch)?,
    );
    sources.extend(plans.iter().map(|plan| plan.evaluated.source));
    let graph = partial
        .graph
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    let id = ProofId(
        u32::try_from(partial.proofs.len())
            .map_err(|_| fact_resource(request, "closed actor image proof"))?,
    );
    partial
        .proofs
        .try_reserve(1)
        .map_err(|_| fact_resource(request, "closed actor image proof"))?;
    partial.proofs.push(Proof {
        id,
        kind: ProofKind::ImageClosed,
        subject: copy_analysis_text(
            "closed bounded actor image",
            request.limits.fact_bytes,
            is_cancelled,
        )?,
        sources,
        depends_on: dependencies,
        bound: Some(graph.static_bytes),
        explanation: vec![
            "the concrete actor, task, mailbox, frame, startup, shutdown, cancellation, and wait-for sets are finite and image-owned"
                .to_owned(),
        ],
    });
    if let Some(effect) = partial.proofs.get_mut(1) {
        effect.bound = Some(
            u64::try_from(graph.actors.len())
                .ok()
                .and_then(|actors| actors.checked_add(u64::try_from(graph.tasks.len()).ok()?))
                .ok_or_else(|| fact_resource(request, "image effect bound"))?,
        );
        effect.explanation = vec![
            "the generated entry initializes only the closed actor/task graph and then transfers control to the bounded executor"
                .to_owned(),
        ];
    }
    Ok(id)
}

fn populate_minimum_image(
    request: &AnalysisRequest<'_>,
    partial: &mut PartialAnalysis,
    constructor: DeclarationId,
    image_name: String,
) -> Result<(), AnalysisFailure> {
    let source = request
        .hir
        .as_program()
        .declaration(constructor)
        .ok_or(AnalysisFailure::RequestMismatch)?
        .source;
    partial
        .types
        .try_reserve_exact(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic types",
            limit: u64::from(request.limits.types),
        })?;
    partial.types.push(SemanticType {
        id: SemanticTypeId(0),
        kind: SemanticTypeKind::Unit,
        linearity: Linearity::ScalarCopy,
        size_upper_bound: Some(0),
        alignment_lower_bound: 1,
        source: None,
    });

    partial
        .proofs
        .try_reserve_exact(3)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic proofs",
            limit: u64::from(request.limits.proofs),
        })?;
    partial.proofs.extend([
        Proof {
            id: ProofId(0),
            kind: ProofKind::TypeChecked,
            subject: "minimum image constructor".to_owned(),
            sources: vec![source],
            depends_on: Vec::new(),
            bound: None,
            explanation: vec![
                "the constructor and generated runtime entry are well typed".to_owned(),
            ],
        },
        Proof {
            id: ProofId(1),
            kind: ProofKind::EffectsAllowed,
            subject: "minimum image effects".to_owned(),
            sources: vec![source],
            depends_on: vec![ProofId(0)],
            bound: Some(1),
            explanation: vec!["the empty runtime graph has no source runtime effects".to_owned()],
        },
        Proof {
            id: ProofId(2),
            kind: ProofKind::ImageClosed,
            subject: "minimum closed image".to_owned(),
            sources: vec![source],
            depends_on: vec![ProofId(0), ProofId(1)],
            bound: Some(0),
            explanation: vec!["the image contains only the compiler-owned runtime root".to_owned()],
        },
    ]);

    partial
        .functions
        .try_reserve_exact(1)
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource: "semantic functions",
            limit: u64::from(request.limits.monomorphizations),
        })?;
    partial.functions.push(FunctionInstance {
        id: FunctionInstanceId(0),
        key: FunctionKey(request.build.identity.request),
        name: "__wrela_image_entry".to_owned(),
        origin: FunctionOrigin::GeneratedImageEntry { constructor },
        role: FunctionRole::ImageEntry,
        color: FunctionColor::Sync,
        generic_arguments: Vec::new(),
        parameters: Vec::new(),
        result: SemanticTypeId(0),
        effects: EffectSet(EffectSet::FIRMWARE),
        stack_bytes_bound: 0,
        frame_bytes_bound: 0,
        uninterrupted_work_bound: Some(1),
        recursive_depth_bound: Some(1),
        proofs: vec![ProofId(0), ProofId(1), ProofId(2)],
        source: None,
    });

    partial.graph = Some(ImageGraph {
        name: image_name,
        entry: FunctionInstanceId(0),
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        brands: Vec::new(),
        static_bytes: 0,
        peak_bytes: 0,
        startup_order: vec![ImageOwner::Runtime],
        shutdown_order: vec![ImageOwner::Runtime],
    });
    Ok(())
}

fn fallback_span(program: &wrela_hir::Program) -> Span {
    program.modules.first().map_or(
        Span {
            file: wrela_source::FileId(0),
            range: wrela_source::TextRange { start: 0, end: 0 },
        },
        |module| module.source,
    )
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), AnalysisFailure> {
    if is_cancelled() {
        Err(AnalysisFailure::Cancelled)
    } else {
        Ok(())
    }
}

/// Stable bottom-up merge sort with explicit scratch bounds and one
/// cancellation poll before every scratch fill, merge output, and copy-back.
fn cancellable_stable_sort_by<T: Copy>(
    values: &mut [T],
    maximum_entries: u64,
    resource: &'static str,
    is_cancelled: &dyn Fn() -> bool,
    compare: &impl Fn(&T, &T) -> Result<std::cmp::Ordering, AnalysisFailure>,
) -> Result<(), AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let length = u64::try_from(values.len()).map_err(|_| AnalysisFailure::ResourceLimit {
        resource,
        limit: maximum_entries,
    })?;
    if length > maximum_entries {
        return Err(AnalysisFailure::ResourceLimit {
            resource,
            limit: maximum_entries,
        });
    }
    let Some(first) = values.first().copied() else {
        return Ok(());
    };
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(values.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource,
            limit: maximum_entries,
        })?;
    for _ in 0..values.len() {
        check_cancelled(is_cancelled)?;
        scratch.push(first);
    }
    let mut width = 1_usize;
    let mut source_is_values = true;
    while width < values.len() {
        if source_is_values {
            cancellable_merge_pass(values, &mut scratch, width, is_cancelled, compare)?;
        } else {
            cancellable_merge_pass(&scratch, values, width, is_cancelled, compare)?;
        }
        source_is_values = !source_is_values;
        width = width.checked_mul(2).unwrap_or(values.len());
    }
    if !source_is_values {
        for (destination, source) in values.iter_mut().zip(scratch) {
            check_cancelled(is_cancelled)?;
            *destination = source;
        }
    }
    check_cancelled(is_cancelled)
}

fn cancellable_merge_pass<T: Copy>(
    source: &[T],
    destination: &mut [T],
    width: usize,
    is_cancelled: &dyn Fn() -> bool,
    compare: &impl Fn(&T, &T) -> Result<std::cmp::Ordering, AnalysisFailure>,
) -> Result<(), AnalysisFailure> {
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
            check_cancelled(is_cancelled)?;
            let take_left = right >= end
                || left < middle
                    && compare(&source[left], &source[right])? != std::cmp::Ordering::Greater;
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

fn cancellable_stable_sort_owned_by<T>(
    values: &mut [T],
    maximum_entries: u64,
    resource: &'static str,
    is_cancelled: &dyn Fn() -> bool,
    compare: &impl Fn(&T, &T) -> Result<std::cmp::Ordering, AnalysisFailure>,
) -> Result<(), AnalysisFailure> {
    check_cancelled(is_cancelled)?;
    let length = u64::try_from(values.len()).map_err(|_| AnalysisFailure::ResourceLimit {
        resource,
        limit: maximum_entries,
    })?;
    if length > maximum_entries {
        return Err(AnalysisFailure::ResourceLimit {
            resource,
            limit: maximum_entries,
        });
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(values.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource,
            limit: maximum_entries,
        })?;
    for index in 0..values.len() {
        check_cancelled(is_cancelled)?;
        order.push(index);
    }
    cancellable_stable_sort_by(
        &mut order,
        maximum_entries,
        resource,
        is_cancelled,
        &|left, right| compare(&values[*left], &values[*right]),
    )?;
    let mut destinations = Vec::new();
    destinations
        .try_reserve_exact(values.len())
        .map_err(|_| AnalysisFailure::ResourceLimit {
            resource,
            limit: maximum_entries,
        })?;
    for _ in 0..values.len() {
        check_cancelled(is_cancelled)?;
        destinations.push(0_usize);
    }
    for (destination, source) in order.into_iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let slot = destinations
            .get_mut(source)
            .ok_or(AnalysisFailure::RequestMismatch)?;
        *slot = destination;
    }
    for index in 0..values.len() {
        while destinations[index] != index {
            check_cancelled(is_cancelled)?;
            let destination = destinations[index];
            values.swap(index, destination);
            destinations.swap(index, destination);
        }
    }
    check_cancelled(is_cancelled)
}

fn cancellable_dedup<T: Copy + Eq>(
    values: &mut Vec<T>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFailure> {
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

fn cancellable_str_cmp(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<std::cmp::Ordering, AnalysisFailure> {
    for (left, right) in left.bytes().zip(right.bytes()) {
        check_cancelled(is_cancelled)?;
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(left.len().cmp(&right.len()))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use wrela_build_model::{
        BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
        TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
    };
    use wrela_hir::{
        AccessMode, AggregateDeclaration, Attribute, AttributeIdentity, Body, BodyOwner, Builtin,
        BuiltinAttribute, CallArgument, CallableOwner, Declaration, DeclarationKind,
        DeclarationOwner, EnumDeclaration, EnumVariant, Expression, ExpressionOwner,
        FunctionDeclaration, LexicalScope, Local, Module, Name, Parameter, Program,
        ResolvedDeclaration, ResolvedVariant, Statement, TypeExpression, TypeExpressionKind,
        Visibility,
    };
    use wrela_hir_lower::{
        CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest, LoweringLimits,
    };
    use wrela_package::{
        DependencyAlias, ModuleId, ModulePath, PackageGraphBuilder, PackageId, PackageIdentity,
        PackageName, PackageVersion,
    };
    use wrela_source::{FileId, SourceDatabase, SourceInput, TextRange};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
    use wrela_target::TargetPackage;

    const STANDARD_LIBRARY_PACKAGE_DIGEST: Sha256Digest = Sha256Digest::from_bytes([2; 32]);
    const STANDARD_LIBRARY_COMPONENT_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0x22; 32]);
    const TARGET_DIGEST: Sha256Digest = Sha256Digest::from_bytes([3; 32]);

    #[derive(Debug, Clone, Copy)]
    enum ProgramKind {
        MinimumImage,
        UnsupportedCallee,
        WrongResultType,
        PassingTests,
        FailingComptimeTest,
        UnsupportedRuntimeTest,
        ScalarRuntimeTest,
    }

    struct Fixture {
        hir: Arc<ValidatedProgram>,
        target: TargetPackage,
        build: ValidatedBuildConfiguration,
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

    const PARSED_CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
    const PARSED_COMPTIME_IMAGE_SOURCE: &str = "module app.image\n\nfrom core.image import Image, Target\n\n@image\npub comptime fn boot() -> Image:\n    return Image(name=\"bootstrap\", target=Target.aarch64_qemu_virt_uefi)\n";
    const PARSED_COMPTIME_MATH_SOURCE: &str = "module app.math\n\npub comptime fn add(left: u32, right: u32) -> u32:\n    return left + right\n\npub comptime fn leaf(value: u32) -> u32:\n    return add(value, 1)\n\npub comptime fn middle(value: u32) -> u32:\n    return leaf(value)\n";
    const PARSED_COMPTIME_TEST_SOURCE: &str = "module app.math_test\n\nfrom app.math import add, middle\n\n@test\ncomptime fn imported_scalars_work():\n    caller: u32 = 40\n    nested: u32 = middle(caller)\n    caller = add(caller, 2)\n    valid: bool = nested == 41 and not false\n    if valid:\n        comptime assert caller == 42, \"caller local was not preserved\"\n    else:\n        comptime assert false, \"nested scalar call failed\"\n";
    const PARSED_UNIMPLEMENTED_ATTRIBUTES_SOURCE: &str = r#"module app.math

@layout_assert
@dma
@wire
@mmio
pub struct Packet:
    @offset
    pub byte: u8

@isr_safe
@receipt_handoff
@suspend_safe
@no_promote
@budget
pub fn marked():
    @uninterrupted
    loop:
        break
"#;
    const PARSED_ATTRIBUTE_TEST_SOURCE: &str = r#"module app.math_test

@test
comptime fn attribute_census_fixture():
    comptime assert true, "attribute fixture"
"#;
    const PARSED_WIRE_ATTRIBUTE_SOURCE: &str = r#"module app.math

@wire
pub struct Packet:
    pass
"#;

    struct ParsedActorFixture {
        fixture: Fixture,
        entry: DeclarationId,
    }

    fn parsed_actor_fixture(application_source: &str) -> ParsedActorFixture {
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
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("actor fixture parses")
                .into_parts();
            assert!(
                diagnostics.is_empty(),
                "actor fixture must parse without recovery: {diagnostics:?}"
            );
            parsed_files.push(parsed);
        }
        let mut graph = PackageGraphBuilder::new(identity(
            "actor-image",
            Sha256Digest::from_bytes([0xb0; 32]),
        ));
        let core = graph
            .add_package(identity("wrela-core", STANDARD_LIBRARY_PACKAGE_DIGEST))
            .expect("core package");
        graph
            .add_dependency(
                graph.root(),
                DependencyAlias::new("core").expect("core alias"),
                core,
            )
            .expect("core dependency");
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["app".to_owned()]).expect("app module path"),
                application_file,
            )
            .expect("app module");
        graph
            .add_module(
                core,
                ModulePath::new(["image".to_owned()]).expect("core module path"),
                core_file,
            )
            .expect("core module");
        let packages = Arc::new(graph.finish().expect("actor package graph"));
        let source_graph_digest = Sha256Digest::from_bytes([0xd0; 32]);
        let changes = HirChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let output = CanonicalHirLowerer::new()
            .lower(
                LowerRequest {
                    packages,
                    source_graph_digest,
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &changes,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("actor fixture lowers");
        assert!(
            output.diagnostics().is_empty(),
            "actor fixture must lower without recovery: {:?}",
            output.diagnostics()
        );
        let hir = Arc::new(output.into_parts().0.into_program());
        let entry = *hir
            .as_program()
            .image_candidates
            .first()
            .expect("actor image entry");
        let base = fixture(ProgramKind::MinimumImage);
        ParsedActorFixture {
            fixture: Fixture {
                hir,
                target: base.target,
                build: base.build,
            },
            entry,
        }
    }

    fn parsed_comptime_fixture(math_source: &str, test_source: &str) -> ParsedActorFixture {
        let mut sources = SourceDatabase::default();
        let mut files = Vec::new();
        for (path, text, digest) in [
            (
                "app/image.wr",
                PARSED_COMPTIME_IMAGE_SOURCE,
                Sha256Digest::from_bytes([0xa1; 32]),
            ),
            (
                "app/math.wr",
                math_source,
                Sha256Digest::from_bytes([0xa2; 32]),
            ),
            (
                "app/math_test.wr",
                test_source,
                Sha256Digest::from_bytes([0xa3; 32]),
            ),
            (
                "core/image.wr",
                PARSED_CORE_IMAGE_SOURCE,
                Sha256Digest::from_bytes([0xc1; 32]),
            ),
        ] {
            let file = sources
                .add(SourceInput {
                    path: path.to_owned(),
                    text: text.to_owned(),
                    digest,
                })
                .expect("comptime fixture source");
            files.push(file);
        }
        let mut parsed_files = Vec::new();
        parsed_files
            .try_reserve_exact(files.len())
            .expect("bounded parsed comptime files");
        for file in &files {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file: *file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("comptime fixture parses")
                .into_parts();
            assert!(
                diagnostics.is_empty(),
                "comptime fixture must parse without recovery: {diagnostics:?}"
            );
            parsed_files.push(parsed);
        }
        let mut graph = PackageGraphBuilder::new(identity(
            "comptime-tests",
            Sha256Digest::from_bytes([0xb0; 32]),
        ));
        let core = graph
            .add_package(identity("wrela-core", STANDARD_LIBRARY_PACKAGE_DIGEST))
            .expect("core package");
        graph
            .add_dependency(
                graph.root(),
                DependencyAlias::new("core").expect("core alias"),
                core,
            )
            .expect("core dependency");
        for (module, file) in [
            (["app", "image"], files[0]),
            (["app", "math"], files[1]),
            (["app", "math_test"], files[2]),
        ] {
            graph
                .add_module(
                    graph.root(),
                    ModulePath::new(module.map(str::to_owned)).expect("application module path"),
                    file,
                )
                .expect("application module");
        }
        graph
            .add_module(
                core,
                ModulePath::new(["image".to_owned()]).expect("core image module path"),
                files[3],
            )
            .expect("core module");
        let packages = Arc::new(graph.finish().expect("comptime package graph"));
        let changes = HirChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let output = CanonicalHirLowerer::new()
            .lower(
                LowerRequest {
                    packages,
                    source_graph_digest: Sha256Digest::from_bytes([0xd1; 32]),
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &changes,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("comptime fixture lowers");
        assert!(
            output.diagnostics().is_empty(),
            "comptime fixture must lower without recovery: {:?}",
            output.diagnostics()
        );
        let hir = Arc::new(output.into_parts().0.into_program());
        let entry = *hir
            .as_program()
            .image_candidates
            .first()
            .expect("comptime image entry");
        let base = fixture(ProgramKind::MinimumImage);
        ParsedActorFixture {
            fixture: Fixture {
                hir,
                target: base.target,
                build: base.build,
            },
            entry,
        }
    }

    fn parsed_comptime_discovery_request<'a>(
        fixture: &'a ParsedActorFixture,
        changes: &'a AnalysisChangeSet,
        limits: AnalysisLimits,
    ) -> AnalysisRequest<'a> {
        AnalysisRequest {
            hir: Arc::clone(&fixture.fixture.hir),
            standard_library_package: PackageId(1),
            target: fixture.fixture.target.semantic(),
            build: &fixture.fixture.build,
            mode: AnalysisMode::DiscoverTests {
                image_entry: fixture.entry,
                image_name: "bootstrap",
                declared_image_tests: &[],
                source_selection: TestDiscoverySelection::Comptime,
            },
            changes,
            limits,
        }
    }

    fn set_comptime_call_depth(fixture: &mut ParsedActorFixture, call_depth: u32) {
        let mut profile = BuildProfile::development();
        profile.comptime.call_depth = call_depth;
        let profile_digest = Sha256Digest::from_bytes([call_depth as u8; 32]);
        let mut identity = fixture.fixture.build.identity.clone();
        identity.profile = profile_digest;
        fixture.fixture.build =
            seal_build_configuration(BuildConfiguration { identity, profile }, profile_digest)
                .expect("bounded comptime test build");
    }

    fn parsed_actor_request<'a>(
        fixture: &'a ParsedActorFixture,
        changes: &'a AnalysisChangeSet,
        limits: AnalysisLimits,
    ) -> AnalysisRequest<'a> {
        AnalysisRequest {
            hir: Arc::clone(&fixture.fixture.hir),
            standard_library_package: PackageId(1),
            target: fixture.fixture.target.semantic(),
            build: &fixture.fixture.build,
            mode: AnalysisMode::Image {
                name: "actor-image",
                entry: fixture.entry,
            },
            changes,
            limits,
        }
    }

    fn unique_attribute_span(source: &str, spelling: &str) -> Span {
        let mut matches = source.match_indices(spelling);
        let (start, matched) = matches.next().expect("attribute spelling is present");
        assert!(matches.next().is_none(), "attribute spelling is unique");
        span(
            1,
            u32::try_from(start).expect("bounded attribute offset"),
            u32::try_from(start + matched.len()).expect("bounded attribute end"),
        )
    }

    fn fixture(kind: ProgramKind) -> Fixture {
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
        let result_kind = if matches!(kind, ProgramKind::WrongResultType) {
            TypeExpressionKind::Named {
                definition: Definition::Builtin(Builtin::Unit),
                arguments: Vec::new(),
            }
        } else {
            TypeExpressionKind::Named {
                definition: Definition::Declaration(image_declaration.clone()),
                arguments: Vec::new(),
            }
        };
        let callee_kind = if matches!(kind, ProgramKind::UnsupportedCallee) {
            ExpressionKind::Literal(Literal::Integer("1".to_owned()))
        } else {
            ExpressionKind::Reference(Definition::Declaration(image_declaration))
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
                        color: FunctionColor::Comptime,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: Some(TypeExpression {
                            kind: result_kind,
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
                    kind: callee_kind,
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
                    kind: ExpressionKind::Reference(Definition::Variant(ResolvedVariant {
                        enumeration: target_declaration,
                        variant: 0,
                    })),
                    source: span(0, 70, 90),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: vec![DeclarationId(0)],
            test_candidates: Vec::new(),
        };
        if matches!(
            kind,
            ProgramKind::PassingTests
                | ProgramKind::FailingComptimeTest
                | ProgramKind::UnsupportedRuntimeTest
                | ProgramKind::ScalarRuntimeTest
        ) {
            program.modules[0]
                .declarations
                .extend([DeclarationId(3), DeclarationId(4)]);
            program.declarations.extend([
                Declaration {
                    id: DeclarationId(3),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(name("unit_case")),
                    visibility: Visibility::Private,
                    attributes: vec![Attribute {
                        identity: AttributeIdentity::Builtin(BuiltinAttribute::Test),
                        arguments: Vec::new(),
                        source: span(0, 210, 215),
                    }],
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Comptime,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: None,
                        body: Some(BodyId(1)),
                    }),
                    source: span(0, 210, 300),
                },
                Declaration {
                    id: DeclarationId(4),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(name("runtime_case")),
                    visibility: Visibility::Private,
                    attributes: vec![Attribute {
                        identity: AttributeIdentity::Builtin(BuiltinAttribute::Test),
                        arguments: Vec::new(),
                        source: span(0, 310, 315),
                    }],
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Sync,
                        generics: Vec::new(),
                        parameters: Vec::new(),
                        result: None,
                        body: Some(BodyId(2)),
                    }),
                    source: span(0, 310, 400),
                },
            ]);
            program.bodies.extend([
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(3)),
                    scope: wrela_hir::ScopeId(1),
                    locals: Vec::new(),
                    statements: vec![StatementId(1)],
                    source: span(0, 220, 290),
                },
                Body {
                    id: BodyId(2),
                    owner: BodyOwner::Declaration(DeclarationId(4)),
                    scope: wrela_hir::ScopeId(2),
                    locals: Vec::new(),
                    statements: vec![StatementId(2)],
                    source: span(0, 320, 390),
                },
            ]);
            program.scopes.extend([
                LexicalScope {
                    id: wrela_hir::ScopeId(1),
                    body: BodyId(1),
                    parent: None,
                    source: span(0, 220, 290),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(2),
                    body: BodyId(2),
                    parent: None,
                    source: span(0, 320, 390),
                },
            ]);
            program.statements.extend([
                Statement {
                    id: StatementId(1),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Assert {
                        condition: ExpressionId(4),
                        expression: "true".to_owned(),
                        witness: wrela_hir::AssertionSourceWitness {
                            source: span(0, 240, 245),
                            expression: "true".to_owned(),
                        },
                        message: Some("unit assertion".to_owned()),
                        comptime: true,
                    },
                    source: span(0, 230, 270),
                },
                Statement {
                    id: StatementId(2),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: if matches!(kind, ProgramKind::UnsupportedRuntimeTest) {
                        StatementKind::Expression(ExpressionId(5))
                    } else {
                        StatementKind::Pass
                    },
                    source: span(0, 330, 370),
                },
            ]);
            program.expressions.push(Expression {
                id: ExpressionId(4),
                owner: ExpressionOwner::Body(BodyId(1)),
                scope: Some(wrela_hir::ScopeId(1)),
                kind: ExpressionKind::Literal(Literal::Boolean(!matches!(
                    kind,
                    ProgramKind::FailingComptimeTest
                ))),
                source: span(0, 240, 245),
            });
            if matches!(kind, ProgramKind::UnsupportedRuntimeTest) {
                program.expressions.push(Expression {
                    id: ExpressionId(5),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(wrela_hir::ScopeId(2)),
                    kind: ExpressionKind::Literal(Literal::String("unsupported".to_owned())),
                    source: span(0, 340, 342),
                });
            }
            program.test_candidates = vec![DeclarationId(3), DeclarationId(4)];
        }
        if matches!(kind, ProgramKind::ScalarRuntimeTest) {
            let bool_ty = |source| TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: Definition::Builtin(Builtin::Bool),
                    arguments: Vec::new(),
                },
                source,
            };
            let u32_ty = |source| TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: Definition::Builtin(Builtin::U32),
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
                    parameters: vec![wrela_hir::ParameterId(0)],
                    result: Some(u32_ty(span(0, 416, 419))),
                    body: Some(BodyId(3)),
                }),
                source: span(0, 401, 450),
            });
            program.parameters.push(Parameter {
                id: wrela_hir::ParameterId(0),
                owner: CallableOwner::Declaration(DeclarationId(5)),
                name: Some(name("x")),
                access: AccessMode::Value,
                ty: Some(u32_ty(span(0, 411, 414))),
                receiver: false,
                source: span(0, 408, 414),
            });
            let DeclarationKind::Function(runtime) = &mut program.declarations[4].kind else {
                unreachable!();
            };
            runtime.body = Some(BodyId(2));
            program.bodies[2].locals = vec![LocalId(0), LocalId(1)];
            program.bodies[2].statements = vec![
                StatementId(2),
                StatementId(3),
                StatementId(4),
                StatementId(5),
            ];
            program.bodies.extend([
                Body {
                    id: BodyId(3),
                    owner: BodyOwner::Declaration(DeclarationId(5)),
                    scope: wrela_hir::ScopeId(3),
                    locals: vec![LocalId(2)],
                    statements: vec![StatementId(6), StatementId(8)],
                    source: span(0, 401, 450),
                },
                Body {
                    id: BodyId(4),
                    owner: BodyOwner::Declaration(DeclarationId(4)),
                    scope: wrela_hir::ScopeId(4),
                    locals: Vec::new(),
                    statements: vec![StatementId(7)],
                    source: span(0, 355, 380),
                },
            ]);
            program.scopes.extend([
                LexicalScope {
                    id: wrela_hir::ScopeId(3),
                    body: BodyId(3),
                    parent: None,
                    source: span(0, 401, 450),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(4),
                    body: BodyId(4),
                    parent: Some(wrela_hir::ScopeId(2)),
                    source: span(0, 355, 380),
                },
            ]);
            program.locals.extend([
                Local {
                    id: LocalId(0),
                    body: BodyId(2),
                    scope: wrela_hir::ScopeId(2),
                    name: name("flag"),
                    ty: Some(bool_ty(span(0, 322, 326))),
                    shadowed: None,
                    source: span(0, 322, 326),
                },
                Local {
                    id: LocalId(1),
                    body: BodyId(2),
                    scope: wrela_hir::ScopeId(2),
                    name: name("n"),
                    ty: Some(u32_ty(span(0, 333, 336))),
                    shadowed: None,
                    source: span(0, 331, 336),
                },
                Local {
                    id: LocalId(2),
                    body: BodyId(3),
                    scope: wrela_hir::ScopeId(3),
                    name: name("copied"),
                    ty: Some(u32_ty(span(0, 422, 425))),
                    shadowed: None,
                    source: span(0, 420, 425),
                },
            ]);
            program.statements[2] = Statement {
                id: StatementId(2),
                body: BodyId(2),
                attributes: Vec::new(),
                kind: StatementKind::Initialize {
                    local: LocalId(0),
                    value: ExpressionId(5),
                },
                source: span(0, 322, 331),
            };
            program.statements.extend([
                Statement {
                    id: StatementId(3),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(1),
                        value: ExpressionId(6),
                    },
                    source: span(0, 331, 340),
                },
                Statement {
                    id: StatementId(4),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::If {
                        branches: vec![(ExpressionId(7), BodyId(4))],
                        else_body: None,
                    },
                    source: span(0, 341, 380),
                },
                Statement {
                    id: StatementId(5),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(None),
                    source: span(0, 381, 389),
                },
                Statement {
                    id: StatementId(6),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(2),
                        value: ExpressionId(11),
                    },
                    source: span(0, 420, 432),
                },
                Statement {
                    id: StatementId(7),
                    body: BodyId(4),
                    attributes: Vec::new(),
                    kind: StatementKind::Expression(ExpressionId(8)),
                    source: span(0, 355, 375),
                },
                Statement {
                    id: StatementId(8),
                    body: BodyId(3),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(Some(ExpressionId(12))),
                    source: span(0, 433, 440),
                },
            ]);
            program.expressions.extend([
                Expression {
                    id: ExpressionId(5),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(wrela_hir::ScopeId(2)),
                    kind: ExpressionKind::Literal(Literal::Boolean(true)),
                    source: span(0, 328, 330),
                },
                Expression {
                    id: ExpressionId(6),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(wrela_hir::ScopeId(2)),
                    kind: ExpressionKind::Literal(Literal::Integer("7".to_owned())),
                    source: span(0, 336, 337),
                },
                Expression {
                    id: ExpressionId(7),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(wrela_hir::ScopeId(2)),
                    kind: ExpressionKind::Reference(Definition::Local(LocalId(0))),
                    source: span(0, 344, 348),
                },
                Expression {
                    id: ExpressionId(8),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Call {
                        callee: ExpressionId(9),
                        arguments: vec![CallArgument {
                            name: Some(name("x")),
                            value: wrela_hir::CallArgumentValue::Value(ExpressionId(10)),
                            source: span(0, 363, 367),
                        }],
                    },
                    source: span(0, 355, 370),
                },
                Expression {
                    id: ExpressionId(9),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Reference(Definition::Declaration(ResolvedDeclaration {
                        package: PackageId(0),
                        module: ModuleId(0),
                        declaration: DeclarationId(5),
                    })),
                    source: span(0, 355, 361),
                },
                Expression {
                    id: ExpressionId(10),
                    owner: ExpressionOwner::Body(BodyId(4)),
                    scope: Some(wrela_hir::ScopeId(4)),
                    kind: ExpressionKind::Reference(Definition::Local(LocalId(1))),
                    source: span(0, 363, 364),
                },
                Expression {
                    id: ExpressionId(11),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Reference(Definition::Parameter(wrela_hir::ParameterId(
                        0,
                    ))),
                    source: span(0, 430, 431),
                },
                Expression {
                    id: ExpressionId(12),
                    owner: ExpressionOwner::Body(BodyId(3)),
                    scope: Some(wrela_hir::ScopeId(3)),
                    kind: ExpressionKind::Reference(Definition::Local(LocalId(2))),
                    source: span(0, 437, 440),
                },
            ]);
        }
        let program = program.validate().expect("valid semantic test HIR");

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

    fn mutate_fixture(kind: ProgramKind, mutate: impl FnOnce(&mut Program)) -> Fixture {
        let Fixture { hir, target, build } = fixture(kind);
        let mut program = Arc::try_unwrap(hir)
            .expect("fixture owns its HIR")
            .into_program();
        mutate(&mut program);
        Fixture {
            hir: Arc::new(program.validate().expect("valid mutated scalar HIR")),
            target,
            build,
        }
    }

    fn mutate_scalar_fixture(mutate: impl FnOnce(&mut Program)) -> Fixture {
        mutate_fixture(ProgramKind::ScalarRuntimeTest, mutate)
    }

    fn set_scalar_call_access(program: &mut Program, access: AccessMode) {
        let DeclarationKind::Function(helper) = &mut program.declarations[5].kind else {
            unreachable!();
        };
        program.parameters[helper.parameters[0].0 as usize].access = access;
        let ExpressionKind::Call { arguments, .. } = &mut program.expressions[8].kind else {
            unreachable!();
        };
        arguments[0].value = wrela_hir::CallArgumentValue::Exclusive {
            access: match access {
                AccessMode::Mutate => wrela_hir::ExclusiveAccess::Mutate,
                AccessMode::Take => wrela_hir::ExclusiveAccess::Take,
                _ => unreachable!("exclusive test access"),
            },
            place: wrela_hir::PlaceTarget {
                root: Definition::Local(LocalId(1)),
                projections: Vec::new(),
                source: span(0, 363, 364),
            },
        };
        remove_scalar_fixture_expression(program, ExpressionId(10));
    }

    fn shift_scalar_fixture_expression(id: &mut ExpressionId, removed: ExpressionId) {
        assert_ne!(
            *id, removed,
            "removed scalar fixture expression remains referenced"
        );
        if id.0 > removed.0 {
            id.0 -= 1;
        }
    }

    fn remove_scalar_fixture_expression(program: &mut Program, removed: ExpressionId) {
        program.expressions.remove(removed.0 as usize);
        for (index, expression) in program.expressions.iter_mut().enumerate() {
            expression.id = ExpressionId(index as u32);
            match &mut expression.kind {
                ExpressionKind::Call { callee, arguments } => {
                    shift_scalar_fixture_expression(callee, removed);
                    for argument in arguments {
                        match &mut argument.value {
                            wrela_hir::CallArgumentValue::Value(value) => {
                                shift_scalar_fixture_expression(value, removed);
                            }
                            wrela_hir::CallArgumentValue::Exclusive { place, .. } => {
                                for projection in &mut place.projections {
                                    if let wrela_hir::PlaceProjection::Index(index) = projection {
                                        shift_scalar_fixture_expression(index, removed);
                                    }
                                }
                            }
                        }
                    }
                }
                ExpressionKind::Unary { operand, .. } => {
                    shift_scalar_fixture_expression(operand, removed);
                }
                ExpressionKind::Binary { left, right, .. }
                | ExpressionKind::Compare { left, right, .. } => {
                    shift_scalar_fixture_expression(left, removed);
                    shift_scalar_fixture_expression(right, removed);
                }
                ExpressionKind::Cast { value, .. } => {
                    shift_scalar_fixture_expression(value, removed);
                }
                ExpressionKind::Field { base, .. } => {
                    shift_scalar_fixture_expression(base, removed);
                }
                ExpressionKind::Literal(_) | ExpressionKind::Reference(_) => {}
                other => panic!("unsupported scalar fixture expression during remap: {other:?}"),
            }
        }
        for statement in &mut program.statements {
            match &mut statement.kind {
                StatementKind::Initialize { value, .. }
                | StatementKind::Expression(value)
                | StatementKind::Send(value)
                | StatementKind::Yield(value) => {
                    shift_scalar_fixture_expression(value, removed);
                }
                StatementKind::Return(Some(value)) => {
                    shift_scalar_fixture_expression(value, removed);
                }
                StatementKind::If { branches, .. } => {
                    for (condition, _) in branches {
                        shift_scalar_fixture_expression(condition, removed);
                    }
                }
                StatementKind::Assert { condition, .. } => {
                    shift_scalar_fixture_expression(condition, removed);
                }
                StatementKind::Assign { targets, value, .. } => {
                    shift_scalar_fixture_expression(value, removed);
                    for target in targets {
                        for projection in &mut target.projections {
                            if let wrela_hir::PlaceProjection::Index(index) = projection {
                                shift_scalar_fixture_expression(index, removed);
                            }
                        }
                    }
                }
                StatementKind::Return(None) | StatementKind::Pass => {}
                other => panic!("unsupported scalar fixture statement during remap: {other:?}"),
            }
        }
    }

    fn scalar_type(builtin: Builtin, source: Span) -> TypeExpression {
        TypeExpression {
            kind: TypeExpressionKind::Named {
                definition: Definition::Builtin(builtin),
                arguments: Vec::new(),
            },
            source,
        }
    }

    fn configure_scalar_helper_types(
        program: &mut Program,
        input: Builtin,
        result: Builtin,
        argument: Literal,
    ) {
        let DeclarationKind::Function(helper) = &mut program.declarations[5].kind else {
            unreachable!();
        };
        helper.result = Some(scalar_type(result, span(0, 416, 419)));
        program.parameters[0].ty = Some(scalar_type(input, span(0, 411, 414)));
        program.locals[1].ty = Some(scalar_type(input, span(0, 333, 336)));
        program.locals[2].ty = Some(scalar_type(result, span(0, 422, 425)));
        program.expressions[6].kind = ExpressionKind::Literal(argument);
        program.expressions[11].source = span(0, 430, 436);
        program.statements[6].source = span(0, 420, 436);
    }

    fn scalar_operand_expression(id: u32) -> Expression {
        Expression {
            id: ExpressionId(id),
            owner: ExpressionOwner::Body(BodyId(3)),
            scope: Some(wrela_hir::ScopeId(3)),
            kind: ExpressionKind::Reference(Definition::Parameter(wrela_hir::ParameterId(0))),
            source: span(0, 431 + id - 13, 432 + id - 13),
        }
    }

    fn configure_compound_assignment_fixture(
        program: &mut Program,
        operator: AssignmentOperator,
        rhs_overlaps_target: bool,
    ) {
        program.statements[7].kind = StatementKind::Assign {
            targets: vec![wrela_hir::PlaceTarget {
                root: Definition::Local(LocalId(1)),
                projections: Vec::new(),
                source: span(0, 355, 356),
            }],
            operator,
            value: ExpressionId(8),
        };
        program.statements[7].source = span(0, 355, 375);
        if !rhs_overlaps_target {
            program.expressions[10].kind =
                ExpressionKind::Literal(Literal::Integer("2".to_owned()));
        }
    }

    fn analyze_compiled_scalar_fixture(fixture: &Fixture) -> AnalyzedImage {
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(fixture, &changes), &|| false)
            .expect("scalar operation discovery");
        assert!(
            discovery.diagnostics().is_empty(),
            "scalar discovery diagnostics: {:?}",
            discovery.diagnostics()
        );
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("scalar operation plan")
            .clone();
        let mut compile = request(fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            group: plan.image_groups()[0].id,
            plan: &plan,
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("scalar operation analysis");
        assert!(
            output.diagnostics().is_empty(),
            "scalar operation diagnostics: {:?}",
            output.diagnostics()
        );
        output
            .into_parts()
            .0
            .expect("sealed scalar operation image")
    }

    fn add_scalar_else_call(program: &mut Program) {
        let call_id = ExpressionId(program.expressions.len() as u32);
        let callee_id = ExpressionId(call_id.0 + 1);
        let StatementKind::If { else_body, .. } = &mut program.statements[4].kind else {
            unreachable!();
        };
        *else_body = Some(BodyId(5));
        program.bodies.push(Body {
            id: BodyId(5),
            owner: BodyOwner::Declaration(DeclarationId(4)),
            scope: wrela_hir::ScopeId(5),
            locals: Vec::new(),
            statements: vec![StatementId(9)],
            source: span(0, 375, 380),
        });
        program.scopes.push(LexicalScope {
            id: wrela_hir::ScopeId(5),
            body: BodyId(5),
            parent: Some(wrela_hir::ScopeId(2)),
            source: span(0, 375, 380),
        });
        program.statements.push(Statement {
            id: StatementId(9),
            body: BodyId(5),
            attributes: Vec::new(),
            kind: StatementKind::Expression(call_id),
            source: span(0, 375, 379),
        });
        program.expressions.extend([
            Expression {
                id: call_id,
                owner: ExpressionOwner::Body(BodyId(5)),
                scope: Some(wrela_hir::ScopeId(5)),
                kind: ExpressionKind::Call {
                    callee: callee_id,
                    arguments: vec![CallArgument {
                        name: Some(name("x")),
                        value: wrela_hir::CallArgumentValue::Exclusive {
                            access: wrela_hir::ExclusiveAccess::Take,
                            place: wrela_hir::PlaceTarget {
                                root: Definition::Local(LocalId(1)),
                                projections: Vec::new(),
                                source: span(0, 378, 379),
                            },
                        },
                        source: span(0, 377, 379),
                    }],
                },
                source: span(0, 375, 379),
            },
            Expression {
                id: callee_id,
                owner: ExpressionOwner::Body(BodyId(5)),
                scope: Some(wrela_hir::ScopeId(5)),
                kind: ExpressionKind::Reference(Definition::Declaration(ResolvedDeclaration {
                    package: PackageId(0),
                    module: ModuleId(0),
                    declaration: DeclarationId(5),
                })),
                source: span(0, 375, 376),
            },
        ]);
    }

    fn configure_scalar_join_fixture(
        program: &mut Program,
        ty: Builtin,
        initial: Literal,
        then_value: Literal,
        else_value: Literal,
    ) {
        program.locals[1].ty = Some(scalar_type(ty, span(0, 333, 336)));
        program.expressions[6].kind = ExpressionKind::Literal(initial);
        let StatementKind::If { else_body, .. } = &mut program.statements[4].kind else {
            unreachable!();
        };
        *else_body = Some(BodyId(5));
        program.bodies[2].statements = vec![
            StatementId(2),
            StatementId(3),
            StatementId(4),
            StatementId(5),
            StatementId(10),
        ];
        program.bodies.push(Body {
            id: BodyId(5),
            owner: BodyOwner::Declaration(DeclarationId(4)),
            scope: wrela_hir::ScopeId(5),
            locals: Vec::new(),
            statements: vec![StatementId(9)],
            source: span(0, 375, 380),
        });
        program.scopes.push(LexicalScope {
            id: wrela_hir::ScopeId(5),
            body: BodyId(5),
            parent: Some(wrela_hir::ScopeId(2)),
            source: span(0, 375, 380),
        });
        program.statements[7] = Statement {
            id: StatementId(7),
            body: BodyId(4),
            attributes: Vec::new(),
            kind: StatementKind::Assign {
                targets: vec![wrela_hir::PlaceTarget {
                    root: Definition::Local(LocalId(1)),
                    projections: Vec::new(),
                    source: span(0, 355, 356),
                }],
                operator: AssignmentOperator::Assign,
                value: ExpressionId(8),
            },
            source: span(0, 355, 364),
        };
        program.statements.extend([
            Statement {
                id: StatementId(9),
                body: BodyId(5),
                attributes: Vec::new(),
                kind: StatementKind::Assign {
                    targets: vec![wrela_hir::PlaceTarget {
                        root: Definition::Local(LocalId(1)),
                        projections: Vec::new(),
                        source: span(0, 375, 376),
                    }],
                    operator: AssignmentOperator::Assign,
                    value: ExpressionId(9),
                },
                source: span(0, 375, 379),
            },
            Statement {
                id: StatementId(10),
                body: BodyId(2),
                attributes: Vec::new(),
                kind: StatementKind::Return(None),
                source: span(0, 387, 389),
            },
        ]);
        program.statements[5] = Statement {
            id: StatementId(5),
            body: BodyId(2),
            attributes: Vec::new(),
            kind: StatementKind::Expression(ExpressionId(10)),
            source: span(0, 385, 386),
        };
        program.expressions[8] = Expression {
            id: ExpressionId(8),
            owner: ExpressionOwner::Body(BodyId(4)),
            scope: Some(wrela_hir::ScopeId(4)),
            kind: ExpressionKind::Literal(then_value),
            source: span(0, 359, 363),
        };
        program.expressions[9] = Expression {
            id: ExpressionId(9),
            owner: ExpressionOwner::Body(BodyId(5)),
            scope: Some(wrela_hir::ScopeId(5)),
            kind: ExpressionKind::Literal(else_value),
            source: span(0, 377, 378),
        };
        program.expressions[10] = Expression {
            id: ExpressionId(10),
            owner: ExpressionOwner::Body(BodyId(2)),
            scope: Some(wrela_hir::ScopeId(2)),
            kind: ExpressionKind::Reference(Definition::Local(LocalId(1))),
            source: span(0, 385, 386),
        };
    }

    fn configure_nested_scalar_join_fixture(program: &mut Program) {
        configure_scalar_join_fixture(
            program,
            Builtin::U32,
            Literal::Integer("1".to_owned()),
            Literal::Integer("2".to_owned()),
            Literal::Integer("5".to_owned()),
        );
        program.bodies[4].statements = vec![StatementId(7)];
        program.bodies.extend([
            Body {
                id: BodyId(6),
                owner: BodyOwner::Declaration(DeclarationId(4)),
                scope: wrela_hir::ScopeId(6),
                locals: Vec::new(),
                statements: vec![StatementId(11)],
                source: span(0, 360, 365),
            },
            Body {
                id: BodyId(7),
                owner: BodyOwner::Declaration(DeclarationId(4)),
                scope: wrela_hir::ScopeId(7),
                locals: Vec::new(),
                statements: vec![StatementId(12)],
                source: span(0, 367, 372),
            },
        ]);
        program.scopes.extend([
            LexicalScope {
                id: wrela_hir::ScopeId(6),
                body: BodyId(6),
                parent: Some(wrela_hir::ScopeId(4)),
                source: span(0, 360, 365),
            },
            LexicalScope {
                id: wrela_hir::ScopeId(7),
                body: BodyId(7),
                parent: Some(wrela_hir::ScopeId(4)),
                source: span(0, 367, 372),
            },
        ]);
        program.statements[7] = Statement {
            id: StatementId(7),
            body: BodyId(4),
            attributes: Vec::new(),
            kind: StatementKind::If {
                branches: vec![(ExpressionId(8), BodyId(6))],
                else_body: Some(BodyId(7)),
            },
            source: span(0, 355, 374),
        };
        program.statements.extend([
            Statement {
                id: StatementId(11),
                body: BodyId(6),
                attributes: Vec::new(),
                kind: StatementKind::Assign {
                    targets: vec![wrela_hir::PlaceTarget {
                        root: Definition::Local(LocalId(1)),
                        projections: Vec::new(),
                        source: span(0, 360, 361),
                    }],
                    operator: AssignmentOperator::Assign,
                    value: ExpressionId(13),
                },
                source: span(0, 360, 365),
            },
            Statement {
                id: StatementId(12),
                body: BodyId(7),
                attributes: Vec::new(),
                kind: StatementKind::Assign {
                    targets: vec![wrela_hir::PlaceTarget {
                        root: Definition::Local(LocalId(1)),
                        projections: Vec::new(),
                        source: span(0, 367, 368),
                    }],
                    operator: AssignmentOperator::Assign,
                    value: ExpressionId(14),
                },
                source: span(0, 367, 372),
            },
        ]);
        program.expressions[8] = Expression {
            id: ExpressionId(8),
            owner: ExpressionOwner::Body(BodyId(4)),
            scope: Some(wrela_hir::ScopeId(4)),
            kind: ExpressionKind::Reference(Definition::Local(LocalId(0))),
            source: span(0, 356, 360),
        };
        program.expressions.extend([
            Expression {
                id: ExpressionId(13),
                owner: ExpressionOwner::Body(BodyId(6)),
                scope: Some(wrela_hir::ScopeId(6)),
                kind: ExpressionKind::Literal(Literal::Integer("2".to_owned())),
                source: span(0, 363, 364),
            },
            Expression {
                id: ExpressionId(14),
                owner: ExpressionOwner::Body(BodyId(7)),
                scope: Some(wrela_hir::ScopeId(7)),
                kind: ExpressionKind::Literal(Literal::Integer("3".to_owned())),
                source: span(0, 370, 371),
            },
        ]);
    }

    fn add_mutating_sink_called_through_read_parameter(program: &mut Program) {
        let u32_type = |source| TypeExpression {
            kind: TypeExpressionKind::Named {
                definition: Definition::Builtin(Builtin::U32),
                arguments: Vec::new(),
            },
            source,
        };
        program.modules[0].declarations.push(DeclarationId(6));
        program.declarations.push(Declaration {
            id: DeclarationId(6),
            module: ModuleId(0),
            owner: DeclarationOwner::Module(ModuleId(0)),
            name: Some(name("mutating_sink")),
            visibility: Visibility::Private,
            attributes: Vec::new(),
            kind: DeclarationKind::Function(FunctionDeclaration {
                color: FunctionColor::Sync,
                generics: Vec::new(),
                parameters: vec![wrela_hir::ParameterId(1)],
                result: None,
                body: Some(BodyId(5)),
            }),
            source: span(0, 451, 480),
        });
        program.parameters.push(Parameter {
            id: wrela_hir::ParameterId(1),
            owner: CallableOwner::Declaration(DeclarationId(6)),
            name: Some(name("target")),
            access: AccessMode::Mutate,
            ty: Some(u32_type(span(0, 458, 461))),
            receiver: false,
            source: span(0, 454, 461),
        });
        program.bodies.push(Body {
            id: BodyId(5),
            owner: BodyOwner::Declaration(DeclarationId(6)),
            scope: wrela_hir::ScopeId(5),
            locals: Vec::new(),
            statements: vec![StatementId(10)],
            source: span(0, 451, 480),
        });
        program.scopes.push(LexicalScope {
            id: wrela_hir::ScopeId(5),
            body: BodyId(5),
            parent: None,
            source: span(0, 451, 480),
        });
        program.bodies[3].statements = vec![StatementId(6), StatementId(8), StatementId(9)];
        program.statements[8] = Statement {
            id: StatementId(8),
            body: BodyId(3),
            attributes: Vec::new(),
            kind: StatementKind::Expression(ExpressionId(13)),
            source: span(0, 426, 432),
        };
        program.statements.extend([
            Statement {
                id: StatementId(9),
                body: BodyId(3),
                attributes: Vec::new(),
                kind: StatementKind::Return(Some(ExpressionId(12))),
                source: span(0, 433, 440),
            },
            Statement {
                id: StatementId(10),
                body: BodyId(5),
                attributes: Vec::new(),
                kind: StatementKind::Return(None),
                source: span(0, 470, 476),
            },
        ]);
        program.expressions.extend([
            Expression {
                id: ExpressionId(13),
                owner: ExpressionOwner::Body(BodyId(3)),
                scope: Some(wrela_hir::ScopeId(3)),
                kind: ExpressionKind::Call {
                    callee: ExpressionId(14),
                    arguments: vec![CallArgument {
                        name: Some(name("target")),
                        value: wrela_hir::CallArgumentValue::Exclusive {
                            access: wrela_hir::ExclusiveAccess::Mutate,
                            place: wrela_hir::PlaceTarget {
                                root: Definition::Parameter(wrela_hir::ParameterId(0)),
                                projections: Vec::new(),
                                source: span(0, 429, 430),
                            },
                        },
                        source: span(0, 428, 431),
                    }],
                },
                source: span(0, 426, 432),
            },
            Expression {
                id: ExpressionId(14),
                owner: ExpressionOwner::Body(BodyId(3)),
                scope: Some(wrela_hir::ScopeId(3)),
                kind: ExpressionKind::Reference(Definition::Declaration(ResolvedDeclaration {
                    package: PackageId(0),
                    module: ModuleId(0),
                    declaration: DeclarationId(6),
                })),
                source: span(0, 426, 427),
            },
        ]);
    }

    fn add_reordered_same_type_read_argument(program: &mut Program) {
        let helper = match &mut program.declarations[5].kind {
            DeclarationKind::Function(helper) => helper,
            _ => unreachable!(),
        };
        helper.parameters.push(wrela_hir::ParameterId(1));
        program.parameters.push(Parameter {
            id: wrela_hir::ParameterId(1),
            owner: CallableOwner::Declaration(DeclarationId(5)),
            name: Some(name("y")),
            access: AccessMode::Read,
            ty: Some(TypeExpression {
                kind: TypeExpressionKind::Named {
                    definition: Definition::Builtin(Builtin::U32),
                    arguments: Vec::new(),
                },
                source: span(0, 414, 417),
            }),
            receiver: false,
            source: span(0, 414, 417),
        });
        let ExpressionKind::Call { arguments, .. } = &mut program.expressions[8].kind else {
            unreachable!();
        };
        arguments.insert(
            0,
            CallArgument {
                name: Some(name("y")),
                value: wrela_hir::CallArgumentValue::Value(ExpressionId(13)),
                source: span(0, 361, 363),
            },
        );
        program.expressions.push(Expression {
            id: ExpressionId(13),
            owner: ExpressionOwner::Body(BodyId(4)),
            scope: Some(wrela_hir::ScopeId(4)),
            kind: ExpressionKind::Reference(Definition::Local(LocalId(1))),
            source: span(0, 362, 363),
        });
    }

    fn request<'a>(
        fixture: &'a Fixture,
        changes: &'a AnalysisChangeSet,
        limits: AnalysisLimits,
    ) -> AnalysisRequest<'a> {
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: PackageId(1),
            target: fixture.target.semantic(),
            build: &fixture.build,
            mode: AnalysisMode::Image {
                name: "runtime-image",
                entry: DeclarationId(0),
            },
            changes,
            limits,
        }
    }

    fn no_changes() -> AnalysisChangeSet {
        AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        }
    }

    fn discovery_request<'a>(
        fixture: &'a Fixture,
        changes: &'a AnalysisChangeSet,
    ) -> AnalysisRequest<'a> {
        discovery_request_with_selection(fixture, changes, TestDiscoverySelection::All)
    }

    fn discovery_request_with_selection<'a>(
        fixture: &'a Fixture,
        changes: &'a AnalysisChangeSet,
        source_selection: TestDiscoverySelection<'a>,
    ) -> AnalysisRequest<'a> {
        let mut request = request(fixture, changes, AnalysisLimits::standard());
        request.mode = AnalysisMode::DiscoverTests {
            image_name: "runtime-image",
            image_entry: DeclarationId(0),
            declared_image_tests: &[],
            source_selection,
        };
        request
    }

    #[test]
    fn minimum_image_is_evaluated_and_retains_exact_hir() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("semantic analysis");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed image");
        assert!(Arc::ptr_eq(image.shared_hir(), &fixture.hir));
        assert_eq!(
            image.facts().graph.as_ref().expect("graph").name,
            "runtime-image"
        );
        assert!(matches!(
            image.facts().functions.as_slice(),
            [FunctionInstance {
                origin: FunctionOrigin::GeneratedImageEntry {
                    constructor: DeclarationId(0)
                },
                role: FunctionRole::ImageEntry,
                color: FunctionColor::Sync,
                source: None,
                ..
            }]
        ));
    }

    const BOUNDED_ACTOR_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub class Worker:
    pub async fn ping(mut self):
        await checkpoint()

    @task
    async fn pulse(mut self):
        await checkpoint()

@image
pub comptime fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;

    #[test]
    fn parsed_actor_image_proves_non_reentrancy_async_frames_and_capacities() {
        let fixture = parsed_actor_fixture(BOUNDED_ACTOR_SOURCE);
        let changes = no_changes();
        let census = census_builtin_attributes(
            fixture.fixture.hir.as_program(),
            AnalysisLimits::standard(),
            &|| false,
        )
        .expect("implemented actor attributes are censused");
        assert!(
            census.diagnostics.is_empty(),
            "@image, @service, and @task have genuine semantic consumers"
        );
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_actor_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("parsed actor semantic analysis");
        assert!(
            output.diagnostics().is_empty(),
            "bounded parsed actor image must analyze cleanly: {:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("sealed actor image");
        assert!(Arc::ptr_eq(image.shared_hir(), &fixture.fixture.hir));
        let facts = image.facts();
        let graph = facts.graph.as_ref().expect("closed actor graph");
        assert_eq!(graph.actors.len(), 1);
        assert_eq!(graph.tasks.len(), 1);
        assert_eq!(graph.regions.len(), 3);
        assert_eq!(graph.actors[0].mailbox_capacity, 2);
        assert_eq!(graph.actors[0].turn_functions.len(), 1);
        assert_eq!(graph.tasks[0].slots, 1);
        assert_eq!(graph.static_bytes, 64);
        assert_eq!(graph.peak_bytes, graph.static_bytes);
        assert_eq!(
            graph.startup_order,
            vec![
                ImageOwner::Runtime,
                ImageOwner::Actor(ActorId(0)),
                ImageOwner::Task(TaskId(0)),
            ]
        );
        assert_eq!(
            graph.shutdown_order,
            vec![
                ImageOwner::Task(TaskId(0)),
                ImageOwner::Actor(ActorId(0)),
                ImageOwner::Runtime,
            ]
        );
        assert!(facts.functions.iter().any(|function| {
            function.role == FunctionRole::ActorTurn(ActorId(0))
                && function.color == FunctionColor::Async
                && function.frame_bytes_bound == 16
                && function.effects.0 & EffectSet::SUSPEND != 0
        }));
        assert!(facts.functions.iter().any(|function| {
            function.role == FunctionRole::TaskEntry(TaskId(0))
                && function.color == FunctionColor::Async
                && function.frame_bytes_bound == 16
        }));
        assert_eq!(
            facts
                .expressions
                .iter()
                .filter(|fact| {
                    fact.resolution == ExpressionResolution::Builtin(IntrinsicOperation::Await)
                })
                .count(),
            2
        );
        assert!(
            facts
                .statements
                .iter()
                .filter(|fact| fact.effects.0 & EffectSet::SUSPEND != 0)
                .count()
                >= 2
        );
        assert!(
            facts.proofs.iter().any(|proof| {
                proof.kind == ProofKind::WaitGraphAcyclic && proof.bound == Some(2)
            })
        );
        assert!(facts.proofs.iter().any(|proof| {
            proof.kind == ProofKind::CleanupAcyclic
                && proof
                    .explanation
                    .iter()
                    .any(|line| line.contains("reverse source order"))
        }));
        assert!(facts.proofs.iter().any(|proof| {
            proof.kind == ProofKind::Ownership
                && proof
                    .explanation
                    .iter()
                    .any(|line| line.contains("non-reentrant"))
        }));
        assert_eq!(
            facts
                .proofs
                .iter()
                .filter(|proof| proof.kind == ProofKind::CapacityBound)
                .count(),
            3
        );
    }

    #[test]
    fn parsed_initializer_stops_before_callable_or_wir_facts() {
        const SOURCE: &str = r#"module app

from core.image import Image, Target

class Cache:
    init(mut self):
        pass

@image
pub comptime fn boot() -> Image:
    return Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
"#;
        let fixture = parsed_actor_fixture(SOURCE);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_actor_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("unsupported initializer is a structured source diagnostic");
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-initializer-not-supported")
        );
        assert!(output.has_errors());
        let partial = output.partial();
        assert!(partial.functions.is_empty());
        assert!(partial.expressions.is_empty());
        assert!(partial.statements.is_empty());
        assert!(partial.graph.is_none());
    }

    #[test]
    fn parsed_runtime_class_construction_has_one_exact_unsupported_diagnostic() {
        const TYPES: &str = "module app.math\n\npub class Cache:\n    value: u32\n";
        const TEST: &str = concat!(
            "module app.math_test\n\n",
            "from app.math import Cache\n\n",
            "@test\n",
            "fn class_construction_is_closed():\n",
            "    Cache()\n",
        );
        let fixture = parsed_comptime_fixture(TYPES, TEST);
        let changes = no_changes();
        let mut discovery =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let AnalysisMode::DiscoverTests {
            source_selection, ..
        } = &mut discovery.mode
        else {
            unreachable!()
        };
        *source_selection = TestDiscoverySelection::Integration;
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery, &|| false)
            .expect("class construction is a structured source diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        let diagnostic = &output.diagnostics()[0];
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-class-construction-not-supported")
        );
        assert_eq!(diagnostic.category, Category::TYPE);
        let start = u32::try_from(TEST.find("Cache()").expect("call spelling"))
            .expect("bounded source offset");
        assert_eq!(diagnostic.primary, span(2, start, start + 7));
        assert!(
            output.partial().expressions.iter().all(|fact| {
                !matches!(fact.resolution, ExpressionResolution::Constructor { .. })
            })
        );
    }

    #[test]
    fn parsed_builtin_attribute_census_rejects_every_unimplemented_contract_at_its_span() {
        let fixture = parsed_comptime_fixture(
            PARSED_UNIMPLEMENTED_ATTRIBUTES_SOURCE,
            PARSED_ATTRIBUTE_TEST_SOURCE,
        );
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("unsupported attributes are recoverable source diagnostics");
        assert!(output.successful().is_none());
        assert!(output.partial().proofs.is_empty());
        assert!(output.partial().functions.is_empty());
        assert!(output.partial().graph.is_none());
        let expected = [
            (
                BuiltinAttribute::LayoutAssert,
                "@layout_assert",
                Category::HARDWARE,
            ),
            (BuiltinAttribute::Dma, "@dma", Category::DMA),
            (BuiltinAttribute::Wire, "@wire", Category::HARDWARE),
            (BuiltinAttribute::Mmio, "@mmio", Category::HARDWARE),
            (BuiltinAttribute::Offset, "@offset", Category::HARDWARE),
            (BuiltinAttribute::IsrSafe, "@isr_safe", Category::HARDWARE),
            (
                BuiltinAttribute::ReceiptHandoff,
                "@receipt_handoff",
                Category::ACTOR,
            ),
            (
                BuiltinAttribute::SuspendSafe,
                "@suspend_safe",
                Category::ASYNC,
            ),
            (
                BuiltinAttribute::NoPromote,
                "@no_promote",
                Category::OWNERSHIP,
            ),
            (BuiltinAttribute::Budget, "@budget", Category::CAPACITY),
            (
                BuiltinAttribute::Uninterrupted,
                "@uninterrupted",
                Category::CAPACITY,
            ),
        ];
        assert_eq!(output.diagnostics().len(), expected.len());
        for (builtin, spelling, category) in expected {
            let expected_span =
                unique_attribute_span(PARSED_UNIMPLEMENTED_ATTRIBUTES_SOURCE, spelling);
            let diagnostic = output
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.primary == expected_span)
                .unwrap_or_else(|| panic!("missing diagnostic for {spelling}"));
            assert_eq!(diagnostic.category, category);
            assert_eq!(
                diagnostic.code.as_deref(),
                Some(BUILTIN_ATTRIBUTE_DIAGNOSTIC_CODE)
            );
            assert_eq!(
                diagnostic.message,
                unimplemented_builtin_attribute_message(builtin)
            );
            assert_eq!(diagnostic.severity, Severity::Error);
            assert!(diagnostic.labels.is_empty());
            assert!(diagnostic.notes.is_empty());
            assert!(diagnostic.help.is_empty());
        }
    }

    #[test]
    fn parsed_builtin_attribute_census_has_exact_work_diagnostic_and_cancellation_bounds() {
        let fixture = parsed_comptime_fixture(
            PARSED_UNIMPLEMENTED_ATTRIBUTES_SOURCE,
            PARSED_ATTRIBUTE_TEST_SOURCE,
        );
        let program = fixture.fixture.hir.as_program();
        let baseline = census_builtin_attributes(program, AnalysisLimits::standard(), &|| false)
            .expect("baseline attribute census");
        assert_eq!(baseline.diagnostics.len(), 11);
        assert!(baseline.work_units > 11);

        let mut limits = AnalysisLimits::standard();
        limits.fact_edges = baseline.work_units;
        assert_eq!(
            census_builtin_attributes(program, limits, &|| false)
                .expect("exact census work bound")
                .work_units,
            baseline.work_units
        );
        limits.fact_edges = baseline.work_units - 1;
        assert!(matches!(
            census_builtin_attributes(program, limits, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic built-in attribute census work",
                limit,
            }) if limit == baseline.work_units - 1
        ));

        let exact_diagnostic_bytes = baseline.diagnostic_bytes;
        let changes = no_changes();
        let mut limits = AnalysisLimits::standard();
        limits.diagnostic_count = 11;
        limits.diagnostic_bytes = exact_diagnostic_bytes;
        let exact = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_comptime_discovery_request(&fixture, &changes, limits),
                &|| false,
            )
            .expect("exact diagnostic bounds");
        assert_eq!(exact.diagnostics().len(), 11);

        limits.diagnostic_bytes = exact_diagnostic_bytes - 1;
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(
                parsed_comptime_discovery_request(&fixture, &changes, limits),
                &|| false,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit,
            }) if limit == exact_diagnostic_bytes - 1
        ));
        limits.diagnostic_bytes = exact_diagnostic_bytes;
        limits.diagnostic_count = 10;
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(
                parsed_comptime_discovery_request(&fixture, &changes, limits),
                &|| false,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic diagnostics",
                limit: 10,
            })
        ));

        let polls = Cell::new(0_u64);
        let cancel_at_last_work = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next == baseline.work_units
        };
        assert!(matches!(
            census_builtin_attributes(program, AnalysisLimits::standard(), &cancel_at_last_work,),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), baseline.work_units);

        let wire =
            parsed_comptime_fixture(PARSED_WIRE_ATTRIBUTE_SOURCE, PARSED_ATTRIBUTE_TEST_SOURCE);
        let wire_census = census_builtin_attributes(
            wire.fixture.hir.as_program(),
            AnalysisLimits::standard(),
            &|| false,
        )
        .expect("single-attribute census");
        assert_eq!(wire_census.diagnostics.len(), 1);
        assert_eq!(
            wire_census.diagnostics[0].primary,
            unique_attribute_span(PARSED_WIRE_ATTRIBUTE_SOURCE, "@wire")
        );
    }

    #[test]
    fn builtin_attribute_census_names_exactly_the_six_existing_semantic_consumers() {
        for implemented in [
            BuiltinAttribute::Image,
            BuiltinAttribute::App,
            BuiltinAttribute::Service,
            BuiltinAttribute::Driver,
            BuiltinAttribute::Task,
            BuiltinAttribute::Test,
        ] {
            assert!(builtin_attribute_has_semantic_consumer(implemented));
        }
        for unimplemented in [
            BuiltinAttribute::IsrSafe,
            BuiltinAttribute::ReceiptHandoff,
            BuiltinAttribute::Dma,
            BuiltinAttribute::Wire,
            BuiltinAttribute::Mmio,
            BuiltinAttribute::Offset,
            BuiltinAttribute::LayoutAssert,
            BuiltinAttribute::SuspendSafe,
            BuiltinAttribute::NoPromote,
            BuiltinAttribute::Budget,
            BuiltinAttribute::Uninterrupted,
        ] {
            assert!(!builtin_attribute_has_semantic_consumer(unimplemented));
        }
    }

    #[test]
    fn parsed_async_wait_cycle_is_a_structured_exact_span_diagnostic() {
        const MUTUAL_WAIT: &str = "async fn checkpoint():\n    await other()\n\nasync fn other():\n    await checkpoint()";
        let source = BOUNDED_ACTOR_SOURCE.replace("async fn checkpoint():\n    pass", MUTUAL_WAIT);
        let mutual_start = source.find(MUTUAL_WAIT).expect("mutual wait source");
        let await_other_start = mutual_start
            .checked_add(MUTUAL_WAIT.find("await other()").expect("first wait"))
            .expect("bounded source offset");
        let await_checkpoint_start = mutual_start
            .checked_add(MUTUAL_WAIT.find("await checkpoint()").expect("second wait"))
            .expect("bounded source offset");
        let mut expected_ranges = vec![
            (
                u32::try_from(await_other_start).expect("source offset"),
                u32::try_from(await_other_start + "await other()".len()).expect("source offset"),
            ),
            (
                u32::try_from(await_checkpoint_start).expect("source offset"),
                u32::try_from(await_checkpoint_start + "await checkpoint()".len())
                    .expect("source offset"),
            ),
        ];
        expected_ranges.sort_unstable();
        let fixture = parsed_actor_fixture(&source);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_actor_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("cycle is a recoverable semantic diagnostic");
        assert!(output.successful().is_none());
        let [diagnostic] = output.diagnostics() else {
            panic!(
                "one wait-cycle diagnostic expected: {:?}",
                output.diagnostics()
            );
        };
        assert_eq!(diagnostic.category, Category::ASYNC);
        assert_eq!(diagnostic.code.as_deref(), Some("semantic-wait-cycle"));
        let mut actual_ranges: Vec<_> = diagnostic
            .labels
            .iter()
            .map(|label| (label.span.range.start, label.span.range.end))
            .collect();
        actual_ranges.sort_unstable();
        assert_eq!(actual_ranges, expected_ranges);
        assert!(
            expected_ranges
                .contains(&(diagnostic.primary.range.start, diagnostic.primary.range.end,))
        );
        assert!(diagnostic.notes.iter().all(|note| note.contains("await")));
    }

    #[test]
    fn parsed_actor_view_mailbox_driver_and_node_limit_fail_closed() {
        let borrowed = BOUNDED_ACTOR_SOURCE.replace(
            "pub async fn ping(mut self):",
            "pub async fn ping(mut self, read borrowed: u32):",
        );
        let zero_mailbox = BOUNDED_ACTOR_SOURCE.replace("mailbox=2", "mailbox=0");
        let driver = BOUNDED_ACTOR_SOURCE
            .replace("@service\npub class Worker", "@driver\npub class Worker")
            .replace("img.service(Worker", "img.driver(Worker");
        for (source, code, category) in [
            (
                borrowed.as_str(),
                "semantic-view-across-await",
                Category::ASYNC,
            ),
            (
                zero_mailbox.as_str(),
                "semantic-actor-mailbox-capacity",
                Category::CAPACITY,
            ),
            (
                driver.as_str(),
                "semantic-hardware-actor-not-supported",
                Category::HARDWARE,
            ),
        ] {
            let fixture = parsed_actor_fixture(source);
            let changes = no_changes();
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(
                    parsed_actor_request(&fixture, &changes, AnalysisLimits::standard()),
                    &|| false,
                )
                .expect("invalid actor source is recoverable");
            assert!(output.successful().is_none());
            assert!(matches!(
                output.diagnostics(),
                [diagnostic]
                    if diagnostic.code.as_deref() == Some(code)
                        && diagnostic.category == category
                        && diagnostic.primary.range.end > diagnostic.primary.range.start
            ));
        }

        let fixture = parsed_actor_fixture(BOUNDED_ACTOR_SOURCE);
        let changes = no_changes();
        let mut limits = AnalysisLimits::standard();
        limits.image_nodes = 1;
        assert!(matches!(
            CanonicalSemanticAnalyzer::new()
                .analyze(parsed_actor_request(&fixture, &changes, limits), &|| false,),
            Err(AnalysisFailure::ResourceLimit {
                resource: "image actor and task nodes",
                limit: 1,
            })
        ));
    }

    #[test]
    fn wait_graph_cycle_search_polls_cancellation() {
        let source = span(0, 1, 2);
        let edges = [
            WaitEdge {
                from: FunctionInstanceId(0),
                to: FunctionInstanceId(1),
                source,
            },
            WaitEdge {
                from: FunctionInstanceId(1),
                to: FunctionInstanceId(0),
                source,
            },
        ];
        let polls = Cell::new(0u32);
        assert!(matches!(
            find_wait_cycle(2, &edges, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= 3
            }),
            Err(AnalysisFailure::Cancelled)
        ));
    }

    #[test]
    fn image_result_must_be_the_selected_standard_library_image_type() {
        let fixture = fixture(ProgramKind::WrongResultType);
        let changes = no_changes();
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(
                request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            ),
            Err(AnalysisFailure::RequestMismatch)
        ));
    }

    #[test]
    fn runtime_image_name_must_match_the_selected_manifest_image() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let mut request = request(&fixture, &changes, AnalysisLimits::standard());
        request.mode = AnalysisMode::Image {
            name: "manifest-selector",
            entry: DeclarationId(0),
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(request, &|| false)
            .expect("source diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-image-name-mismatch")
        );
        assert_eq!(output.diagnostics()[0].primary, span(0, 50, 63));
    }

    #[test]
    fn standard_library_selection_is_the_root_core_package_not_the_component_digest() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        assert_ne!(
            fixture
                .hir
                .as_program()
                .packages
                .package(PackageId(1))
                .expect("standard package")
                .identity
                .source_digest,
            fixture.build.identity.standard_library
        );
        let mut wrong = request(&fixture, &changes, AnalysisLimits::standard());
        wrong.standard_library_package = PackageId(0);
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(wrong, &|| false),
            Err(AnalysisFailure::RequestMismatch)
        ));
    }

    #[test]
    fn discovery_evaluates_comptime_and_seals_generated_runtime_group() {
        let fixture = fixture(ProgramKind::PassingTests);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("test discovery");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed discovery image");
        let facts = image.facts();
        assert_eq!(facts.graph.as_ref().expect("graph").name, "runtime-image");
        let plan = facts.test_plan.as_ref().expect("test plan");
        assert_eq!(plan.limits(), test_plan_limits(AnalysisLimits::standard()));
        assert_eq!(
            plan.as_plan().clone().seal_with_limits_and_cancellation(
                test_plan_limits(AnalysisLimits::standard()),
                &|| true,
            ),
            Err(wrela_test_model::TestModelError::Cancelled)
        );
        let mut plan_limited = AnalysisLimits::standard();
        plan_limited.test_bytes = 1;
        assert!(matches!(
            plan.as_plan()
                .clone()
                .seal_with_limits_and_cancellation(test_plan_limits(plan_limited), &|| false,),
            Err(wrela_test_model::TestModelError::ResourceLimit {
                resource: "test plan",
                limit: 1,
            })
        ));
        assert_eq!(plan.unit_tests().len(), 1);
        assert_eq!(plan.image_groups().len(), 1);
        assert_eq!(facts.comptime_test_results.len(), 1);
        assert_eq!(facts.comptime_test_results[0].outcome, TestOutcome::Passed);
        assert_eq!(
            plan.image_groups()[0].root,
            ImageRoot::GeneratedHarness {
                harness_name: GENERATED_HARNESS_NAME.to_owned()
            }
        );
        assert_eq!(plan.image_groups()[0].tests[0].descriptor.id, TestId(1));
        let planned_keys: std::collections::BTreeSet<_> =
            plan.unit_tests()
                .iter()
                .map(|test| test.function_key)
                .chain(plan.image_groups()[0].tests.iter().filter_map(
                    |test| match test.invocation {
                        ImageTestInvocation::GeneratedFunction { function_key } => {
                            Some(function_key)
                        }
                        ImageTestInvocation::DeclaredScenario => None,
                    },
                ))
                .collect();
        let semantic_keys: std::collections::BTreeSet<_> = facts
            .functions
            .iter()
            .filter(|function| function.role == FunctionRole::Test)
            .map(|function| function.key)
            .collect();
        assert_eq!(semantic_keys, planned_keys);
    }

    #[test]
    fn discovery_selection_filters_before_assigning_dense_test_ids() {
        let fixture = fixture(ProgramKind::PassingTests);
        let changes = no_changes();
        let cases = [
            (TestDiscoverySelection::Comptime, 1, 0),
            (TestDiscoverySelection::Integration, 0, 1),
            (TestDiscoverySelection::None, 0, 0),
            (TestDiscoverySelection::NameContains("unit"), 1, 0),
            (TestDiscoverySelection::NameContains("runtime"), 0, 1),
            (TestDiscoverySelection::NameContains("missing"), 0, 0),
        ];
        for (selection, unit_count, image_count) in cases {
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(
                    discovery_request_with_selection(&fixture, &changes, selection),
                    &|| false,
                )
                .expect("selected test discovery");
            assert!(output.diagnostics().is_empty());
            let image = output.successful().expect("sealed selected discovery");
            let facts = image.facts();
            let plan = facts.test_plan.as_ref().expect("selected test plan");
            assert_eq!(plan.unit_tests().len(), unit_count);
            assert_eq!(plan.image_groups().len(), image_count);
            assert_eq!(facts.comptime_test_results.len(), unit_count);
            let ids: Vec<_> = plan
                .unit_tests()
                .iter()
                .map(|test| test.descriptor.id)
                .chain(
                    plan.image_groups()
                        .iter()
                        .flat_map(|group| group.tests.iter().map(|test| test.descriptor.id)),
                )
                .collect();
            assert_eq!(
                ids,
                (0..ids.len())
                    .map(|index| TestId(u32::try_from(index).expect("bounded test ID")))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn parsed_imported_comptime_functions_execute_real_scalar_source() {
        let fixture =
            parsed_comptime_fixture(PARSED_COMPTIME_MATH_SOURCE, PARSED_COMPTIME_TEST_SOURCE);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("parsed imported comptime discovery");
        assert!(
            output.diagnostics().is_empty(),
            "real scalar comptime diagnostics: {:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("sealed comptime discovery");
        let plan = image.facts().test_plan.as_ref().expect("comptime plan");
        assert_eq!(plan.unit_tests().len(), 1);
        assert!(plan.image_groups().is_empty());
        assert_eq!(image.facts().comptime_test_results.len(), 1);
        assert_eq!(
            image.facts().comptime_test_results[0].outcome,
            TestOutcome::Passed
        );
        let closure_proof = image
            .facts()
            .proofs
            .iter()
            .find(|proof| {
                proof
                    .explanation
                    .iter()
                    .any(|line| line == SOURCE_COMPTIME_CLOSURE_PROOF_MARKER)
            })
            .expect("bounded source comptime closure proof");
        assert_eq!(closure_proof.kind, ProofKind::TypeChecked);
        assert_eq!(closure_proof.sources.len(), 4);
        assert!(closure_proof.bound.is_some_and(|nodes| nodes > 0));
    }

    #[test]
    fn parsed_checked_and_modular_left_shifts_are_exact_bounded_and_cancellable() {
        const MATH: &str = r#"module app.math

pub comptime fn checked_u8(value: u8, count: u8) -> u8:
    return value << count

pub comptime fn modular_u8(value: u8, count: u8) -> u8:
    return value <<% count

pub comptime fn checked_i8(value: i8, count: i8) -> i8:
    return value << count
"#;
        const TEST: &str = r#"module app.math_test

from app.math import checked_u8, modular_u8, checked_i8

@test
comptime fn safe_and_modular_shifts():
    checked_unsigned: u8 = checked_u8(1, 7)
    checked_signed: i8 = checked_i8(-64, 1)
    modular_unsigned: u8 = modular_u8(255, 1)
    comptime assert checked_unsigned == 128 and checked_signed == -128 and modular_unsigned == 254, "target-width left shifts"

@test
comptime fn checked_unsigned_result_loss():
    value: u8 = checked_u8(128, 1)

@test
comptime fn checked_signed_positive_result_loss():
    value: i8 = checked_i8(64, 1)

@test
comptime fn checked_signed_negative_result_loss():
    value: i8 = checked_i8(-65, 1)

@test
comptime fn checked_count_out_of_range():
    value: u8 = checked_u8(1, 8)

@test
comptime fn modular_count_out_of_range():
    value: u8 = modular_u8(1, 8)

@test
comptime fn negative_count_out_of_range():
    value: i8 = checked_i8(1, -1)
"#;
        let fixture = parsed_comptime_fixture(MATH, TEST);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("parsed shift discovery");
        assert!(
            output.diagnostics().is_empty(),
            "parsed shift diagnostics: {:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("sealed parsed shift discovery");
        assert_eq!(image.facts().comptime_test_results.len(), 7);
        let safe = image
            .facts()
            .comptime_test_results
            .iter()
            .find(|result| result.descriptor.name.ends_with("safe_and_modular_shifts"))
            .expect("safe shift result");
        assert_eq!(safe.outcome, TestOutcome::Passed);
        for (name, code) in [
            (
                "checked_unsigned_result_loss",
                "semantic-comptime-shift-result-loss",
            ),
            (
                "checked_signed_positive_result_loss",
                "semantic-comptime-shift-result-loss",
            ),
            (
                "checked_signed_negative_result_loss",
                "semantic-comptime-shift-result-loss",
            ),
            (
                "checked_count_out_of_range",
                "semantic-comptime-shift-count",
            ),
            (
                "modular_count_out_of_range",
                "semantic-comptime-shift-count",
            ),
            (
                "negative_count_out_of_range",
                "semantic-comptime-shift-count",
            ),
        ] {
            let result = image
                .facts()
                .comptime_test_results
                .iter()
                .find(|result| result.descriptor.name.ends_with(name))
                .expect("named failing shift result");
            assert!(matches!(
                &result.outcome,
                TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message,
                } if message.starts_with(code)
            ));
        }

        let safe_test = fixture
            .fixture
            .hir
            .as_program()
            .test_candidates
            .iter()
            .copied()
            .find(|candidate| {
                fixture
                    .fixture
                    .hir
                    .as_program()
                    .declaration(*candidate)
                    .and_then(|declaration| declaration.name.as_ref())
                    .is_some_and(|name| name.as_str() == "safe_and_modular_shifts")
            })
            .expect("safe parsed shift declaration");
        let evaluator_request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let baseline_polls = Cell::new(0_u64);
        let count_polls = || {
            baseline_polls.set(baseline_polls.get() + 1);
            false
        };
        let mut evaluator = ImageEvaluator::new(&evaluator_request, &count_polls)
            .expect("baseline shift evaluator");
        evaluator
            .evaluate_test(safe_test)
            .expect("baseline safe shift evaluation");
        let exact_steps = evaluator.steps;
        let exact_polls = baseline_polls.get();
        assert!(exact_steps > 1);
        assert!(exact_polls > 1);

        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_steps = exact_steps;
        let exact_request = parsed_comptime_discovery_request(&fixture, &changes, exact_limits);
        ImageEvaluator::new(&exact_request, &|| false)
            .expect("exact-step shift evaluator")
            .evaluate_test(safe_test)
            .expect("exact-step safe shifts");

        let mut one_under_limits = AnalysisLimits::standard();
        one_under_limits.evaluator_steps = exact_steps - 1;
        let one_under_request =
            parsed_comptime_discovery_request(&fixture, &changes, one_under_limits);
        assert!(matches!(
            ImageEvaluator::new(&one_under_request, &|| false)
                .expect("one-under shift evaluator")
                .evaluate_test(safe_test),
            Err(EvaluationFailure::Diagnostic(diagnostic))
                if diagnostic.code.as_deref() == Some("semantic-comptime-resource-limit")
                    && diagnostic.message
                        == format!(
                            "comptime test exceeded comptime evaluator steps limit {}",
                            exact_steps - 1
                        )
        ));

        let late_polls = Cell::new(0_u64);
        let cancel_late = || {
            let next = late_polls.get() + 1;
            late_polls.set(next);
            next == exact_polls
        };
        let mut cancelled =
            ImageEvaluator::new(&evaluator_request, &cancel_late).expect("late shift evaluator");
        assert!(matches!(
            cancelled.evaluate_test(safe_test),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(late_polls.get(), exact_polls);
    }

    #[test]
    fn parsed_imported_comptime_infers_locals_signed_minimum_and_named_arguments() {
        const MATH: &str = "module app.math\n\npub comptime fn add(left: u32, right: u32) -> u32:\n    return left + right\n\npub comptime fn preserve(value: i64) -> i64:\n    return value\n";
        const TEST: &str = "module app.math_test\n\nfrom app.math import add, preserve\n\n@test\ncomptime fn inferred_imported_scalars_work():\n    sum = add(right=2, left=40)\n    minimum = preserve(-9223372036854775808)\n    valid = sum == 42 and minimum == -9223372036854775808\n    comptime assert valid, \"inferred imported scalar result\"\n    comptime assert -9223372036854775808 == -9223372036854775808, \"unconstrained signed minimum\"\n";
        let fixture = parsed_comptime_fixture(MATH, TEST);
        let changes = no_changes();

        let mut request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        request.mode = AnalysisMode::DiscoverTests {
            image_entry: fixture.entry,
            image_name: "bootstrap",
            declared_image_tests: &[],
            source_selection: TestDiscoverySelection::NameContains("imported_scalars"),
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(request, &|| false)
            .expect("real inferred imported comptime discovery");
        assert!(
            output.diagnostics().is_empty(),
            "inferred imported comptime diagnostics: {:?}",
            output.diagnostics()
        );
        let image = output
            .successful()
            .expect("sealed inferred comptime discovery");
        let plan = image
            .facts()
            .test_plan
            .as_ref()
            .expect("inferred comptime plan");
        assert_eq!(plan.unit_tests().len(), 1);
        assert_eq!(
            image.facts().comptime_test_results[0].outcome,
            TestOutcome::Passed
        );

        let mut request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        request.mode = AnalysisMode::DiscoverTests {
            image_entry: fixture.entry,
            image_name: "bootstrap",
            declared_image_tests: &[],
            source_selection: TestDiscoverySelection::NameContains("not_selected"),
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(request, &|| false)
            .expect("real imported comptime exclusion");
        assert!(output.diagnostics().is_empty());
        assert!(
            output
                .successful()
                .expect("sealed empty selection")
                .facts()
                .test_plan
                .as_ref()
                .expect("empty selection plan")
                .unit_tests()
                .is_empty()
        );
    }

    #[test]
    fn stable_sort_has_exact_work_last_comparison_cancellation_and_owned_order() {
        let mut values = [8_u32, 7, 6, 5, 4, 3, 2, 1];
        let polls = Cell::new(0_u64);
        let comparisons = Cell::new(0_u64);
        let last_comparison_poll = Cell::new(0_u64);
        cancellable_stable_sort_by(
            &mut values,
            8,
            "sort test scratch",
            &|| {
                polls.set(polls.get() + 1);
                false
            },
            &|left, right| {
                comparisons.set(comparisons.get() + 1);
                last_comparison_poll.set(polls.get());
                Ok(left.cmp(right))
            },
        )
        .expect("exact bounded stable sort");
        assert_eq!(values, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(polls.get(), 42);
        assert_eq!(comparisons.get(), 12);
        assert_eq!(last_comparison_poll.get(), 29);

        let mut cancelled_values = [8_u32, 7, 6, 5, 4, 3, 2, 1];
        let cancellation_polls = Cell::new(0_u64);
        let cancelled_comparisons = Cell::new(0_u64);
        assert!(matches!(
            cancellable_stable_sort_by(
                &mut cancelled_values,
                8,
                "sort test scratch",
                &|| {
                    let next = cancellation_polls.get() + 1;
                    cancellation_polls.set(next);
                    next == 29
                },
                &|left, right| {
                    cancelled_comparisons.set(cancelled_comparisons.get() + 1);
                    Ok(left.cmp(right))
                },
            ),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(cancellation_polls.get(), 29);
        assert_eq!(cancelled_comparisons.get(), 11);

        let bound_polls = Cell::new(0_u64);
        assert!(matches!(
            cancellable_stable_sort_by(
                &mut cancelled_values,
                7,
                "sort test scratch",
                &|| {
                    bound_polls.set(bound_polls.get() + 1);
                    false
                },
                &|left, right| Ok(left.cmp(right)),
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "sort test scratch",
                limit: 7,
            })
        ));
        assert_eq!(bound_polls.get(), 1, "the size bound preempts scratch fill");

        #[derive(Debug, PartialEq, Eq)]
        struct OwnedSortValue {
            key: String,
            source_order: u32,
        }
        let mut owned = [
            OwnedSortValue {
                key: "same".to_owned(),
                source_order: 0,
            },
            OwnedSortValue {
                key: "first".to_owned(),
                source_order: 1,
            },
            OwnedSortValue {
                key: "same".to_owned(),
                source_order: 2,
            },
        ];
        cancellable_stable_sort_owned_by(
            &mut owned,
            3,
            "owned sort test scratch",
            &|| false,
            &|left, right| cancellable_str_cmp(&left.key, &right.key, &|| false),
        )
        .expect("owned stable sort");
        assert_eq!(
            owned
                .iter()
                .map(|value| (value.key.as_str(), value.source_order))
                .collect::<Vec<_>>(),
            [("first", 1), ("same", 0), ("same", 2)]
        );
    }

    #[test]
    fn source_name_matching_copying_and_proof_text_poll_cancellation() {
        let value = "a".repeat(128 * 1024);
        let filter = format!("{}b", "a".repeat(MAX_TEST_FILTER_BYTES - 1));
        let polls = Cell::new(0usize);
        assert!(
            !bounded_name_contains(&value, &filter, &|| {
                polls.set(polls.get() + 1);
                false
            })
            .expect("linear bounded substring search")
        );
        assert!(
            polls.get() <= 2 * value.len() + 3 * filter.len() + 1,
            "KMP cancellation polls must remain linear"
        );

        let polls = Cell::new(0usize);
        let cancel_late = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 20_000
        };
        assert!(matches!(
            bounded_name_contains(&value, &filter, &cancel_late),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), 20_000);
        assert!(
            bounded_name_contains(
                &"x".repeat(MAX_TEST_FILTER_BYTES),
                &"x".repeat(MAX_TEST_FILTER_BYTES),
                &|| false,
            )
            .expect("exact filter bound")
        );
        assert!(matches!(
            bounded_name_contains(
                &"x".repeat(MAX_TEST_FILTER_BYTES + 1),
                &"x".repeat(MAX_TEST_FILTER_BYTES + 1),
                &|| false,
            ),
            Err(AnalysisFailure::RequestMismatch)
        ));

        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let request = request(&fixture, &changes, AnalysisLimits::standard());
        let long_name = "n".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES * 64);
        fn assert_copy_cancelled(
            copy: impl Fn(&dyn Fn() -> bool) -> Result<String, AnalysisFailure>,
        ) {
            let polls = Cell::new(0usize);
            let cancel_during_copy = || {
                let next = polls.get() + 1;
                polls.set(next);
                next == 17
            };
            assert!(matches!(
                copy(&cancel_during_copy),
                Err(AnalysisFailure::Cancelled)
            ));
            assert_eq!(polls.get(), 17);
        }
        assert_copy_cancelled(|cancel| {
            copy_analysis_text(&long_name, long_name.len() as u64, cancel)
        });
        assert_copy_cancelled(|cancel| copy_bounded_test_text(&request, &long_name, cancel));
        assert_copy_cancelled(|cancel| bounded_test_fact(&request, "test: ", &long_name, cancel));
    }

    #[test]
    fn source_sized_scalar_and_actor_text_copies_have_exact_limits_and_cancellation() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let left = "actor".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES);
        let separator = ".";
        let right = "turn";
        let exact_bytes = left.len() + separator.len() + right.len();
        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.fact_bytes = exact_bytes as u64;
        let exact_request = request(&fixture, &changes, exact_limits);
        let exact = bounded_actor_text(&exact_request, &left, separator, right, &|| false)
            .expect("exact actor text byte bound");
        assert_eq!(exact.len(), exact_bytes);
        assert!(exact.starts_with(&left));
        assert!(exact.ends_with(right));
        assert!(matches!(
            bounded_actor_text(&exact_request, &left, separator, "turns", &|| false,),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic fact bytes",
                limit,
            }) if limit == exact_bytes as u64
        ));

        let long_actor = "a".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES * 64);
        let polls = Cell::new(0usize);
        let cancel_actor_copy = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 17
        };
        let standard_request = request(&fixture, &changes, AnalysisLimits::standard());
        assert!(matches!(
            bounded_actor_text(
                &standard_request,
                &long_actor,
                separator,
                right,
                &cancel_actor_copy,
            ),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), 17);

        let exact_float = "1_".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES / 2);
        let copied = parse_float_spelling(&exact_float, exact_float.len() as u64, &|| false)
            .expect("exact float spelling byte bound")
            .expect("copyable float spelling");
        assert_eq!(copied, "1".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES / 2));
        let over_float = format!("{exact_float}0");
        let over_polls = Cell::new(0usize);
        assert!(matches!(
            parse_float_spelling(&over_float, exact_float.len() as u64, &|| {
                over_polls.set(over_polls.get() + 1);
                false
            }),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic fact bytes",
                limit,
            }) if limit == exact_float.len() as u64
        ));
        assert_eq!(
            over_polls.get(),
            1,
            "over-limit spelling fails before copying"
        );

        let long_float = "1".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES * 64);
        let polls = Cell::new(0usize);
        let cancel_float_copy = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 17
        };
        assert!(matches!(
            parse_float_spelling(&long_float, long_float.len() as u64, &cancel_float_copy,),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), 17);
    }

    #[test]
    fn long_named_comptime_argument_comparison_polls_each_source_byte() {
        let parameter = "parameter".repeat(28);
        let math = format!(
            "module app.math\n\npub comptime fn identity({parameter}: u32) -> u32:\n    return {parameter}\n"
        );
        let test_source = format!(
            "module app.math_test\n\nfrom app.math import identity\n\n@test\ncomptime fn named_argument_is_polled():\n    result = identity({parameter}=42)\n    comptime assert result == 42, \"named result\"\n"
        );
        let fixture = parsed_comptime_fixture(&math, &test_source);
        let changes = no_changes();
        let test = fixture.fixture.hir.as_program().test_candidates[0];
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        assert!(
            ImageEvaluator::new(&request, &|| false)
                .expect("long-name evaluator")
                .evaluate_test(test)
                .is_ok()
        );

        let polls = Cell::new(0usize);
        let cancel_inside_name = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 100
        };
        let mut evaluator =
            ImageEvaluator::new(&request, &cancel_inside_name).expect("cancellable name evaluator");
        assert!(matches!(
            evaluator.evaluate_test(test),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(polls.get(), 100);
        assert_eq!(evaluator.steps, 99);
    }

    #[test]
    fn imported_comptime_evaluator_has_exact_step_memory_depth_and_cancellation_bounds() {
        const MATH: &str = "module app.math\n\npub comptime fn leaf() -> u32:\n    return 42\n\npub comptime fn middle() -> u32:\n    return leaf()\n";
        const TEST: &str = "module app.math_test\n\nfrom app.math import middle\n\n@test\ncomptime fn bounded_import():\n    result: u32 = middle()\n    comptime assert result == 42, \"nested result\"\n";
        let mut fixture = parsed_comptime_fixture(MATH, TEST);
        let test = fixture.fixture.hir.as_program().test_candidates[0];
        let changes = no_changes();

        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let mut evaluator = ImageEvaluator::new(&request, &|| false).expect("bounded evaluator");
        assert!(evaluator.evaluate_test(test).is_ok());
        assert_eq!(evaluator.steps, 19);
        assert_eq!(evaluator.peak_bytes, 192);

        for (steps, passes) in [(19, true), (18, false)] {
            let mut limits = AnalysisLimits::standard();
            limits.evaluator_steps = steps;
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let mut evaluator =
                ImageEvaluator::new(&request, &|| false).expect("step-bounded evaluator");
            let result = evaluator.evaluate_test(test);
            assert_eq!(result.is_ok(), passes);
            if !passes {
                assert!(matches!(
                    result,
                    Err(EvaluationFailure::Diagnostic(diagnostic))
                        if diagnostic.code.as_deref()
                            == Some("semantic-comptime-resource-limit")
                            && diagnostic.message
                                == "comptime test exceeded comptime evaluator steps limit 18"
                ));
            }
        }
        for (bytes, passes) in [(192, true), (191, false)] {
            let mut limits = AnalysisLimits::standard();
            limits.evaluator_bytes = bytes;
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let mut evaluator =
                ImageEvaluator::new(&request, &|| false).expect("memory-bounded evaluator");
            let result = evaluator.evaluate_test(test);
            assert_eq!(result.is_ok(), passes);
            if !passes {
                assert!(matches!(
                    result,
                    Err(EvaluationFailure::Diagnostic(diagnostic))
                        if diagnostic.code.as_deref()
                            == Some("semantic-comptime-resource-limit")
                            && diagnostic.message
                                == "comptime test exceeded comptime evaluator bytes limit 191"
                ));
            }
        }

        set_comptime_call_depth(&mut fixture, 3);
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        assert!(
            ImageEvaluator::new(&request, &|| false)
                .expect("depth evaluator")
                .evaluate_test(test)
                .is_ok(),
            "exact active-call depth is admitted"
        );
        set_comptime_call_depth(&mut fixture, 2);
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let error = ImageEvaluator::new(&request, &|| false)
            .expect("over-depth evaluator")
            .evaluate_test(test)
            .expect_err("active-call depth plus one must fail");
        let EvaluationFailure::Diagnostic(diagnostic) = error else {
            panic!("depth quota must be a typed test diagnostic");
        };
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-resource-limit")
        );
        assert_eq!(diagnostic.primary, diagnostic.labels[0].span);
        let labels: Vec<_> = diagnostic
            .labels
            .iter()
            .map(|label| label.message.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "comptime call to `app.math.leaf` entered here",
                "comptime call to `app.math.middle` entered here",
            ]
        );

        set_comptime_call_depth(&mut fixture, 3);
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let polls = Cell::new(0u32);
        let cancel_in_leaf = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 8
        };
        assert!(matches!(
            ImageEvaluator::new(&request, &cancel_in_leaf)
                .expect("cancellable evaluator")
                .evaluate_test(test),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(polls.get(), 8);
    }

    #[test]
    fn imported_flat_structure_evaluator_has_exact_step_memory_depth_and_cancellation_bounds() {
        const VALUES: &str = r#"module app.math

pub struct Pair:
    pub left: u32
    pub right: u32

pub comptime fn forward(value: Pair) -> Pair:
    return copy value

pub comptime fn make_and_forward(left: u32, right: u32) -> Pair:
    pair: Pair = Pair(left=left, right=right)
    return forward(pair)
"#;
        const TEST: &str = r#"module app.math_test

from app.math import make_and_forward

@test
comptime fn aggregate_bound():
    result = make_and_forward(20, 22)
    comptime assert result.left + result.right == 42, "aggregate result"
"#;
        let mut fixture = parsed_comptime_fixture(VALUES, TEST);
        let test = fixture.fixture.hir.as_program().test_candidates[0];
        let changes = no_changes();
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let mut evaluator = ImageEvaluator::new(&request, &|| false).expect("aggregate evaluator");
        assert!(evaluator.evaluate_test(test).is_ok());
        assert_eq!(evaluator.steps, 163);
        assert_eq!(evaluator.peak_bytes, 608);

        for (steps, passes) in [(163, true), (162, false)] {
            let mut limits = AnalysisLimits::standard();
            limits.evaluator_steps = steps;
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let result = ImageEvaluator::new(&request, &|| false)
                .expect("step-bounded aggregate evaluator")
                .evaluate_test(test);
            assert_eq!(result.is_ok(), passes);
            if !passes {
                assert!(matches!(
                    result,
                    Err(EvaluationFailure::Diagnostic(diagnostic))
                        if diagnostic.code.as_deref()
                            == Some("semantic-comptime-resource-limit")
                            && diagnostic.message
                                == "comptime test exceeded comptime evaluator steps limit 162"
                ));
            }
        }
        for (bytes, passes) in [(608, true), (607, false)] {
            let mut limits = AnalysisLimits::standard();
            limits.evaluator_bytes = bytes;
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let result = ImageEvaluator::new(&request, &|| false)
                .expect("memory-bounded aggregate evaluator")
                .evaluate_test(test);
            assert_eq!(result.is_ok(), passes);
            if !passes {
                assert!(matches!(
                    result,
                    Err(EvaluationFailure::Diagnostic(diagnostic))
                        if diagnostic.code.as_deref()
                            == Some("semantic-comptime-resource-limit")
                            && diagnostic.message
                                == "comptime test exceeded comptime evaluator bytes limit 607"
                ));
            }
        }

        for (resource, limit) in [("steps", 76_u64), ("bytes", 511_u64)] {
            let mut limits = AnalysisLimits::standard();
            if resource == "steps" {
                limits.evaluator_steps = limit;
            } else {
                limits.evaluator_bytes = limit;
            }
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let error = ImageEvaluator::new(&request, &|| false)
                .expect("pre-push aggregate evaluator")
                .evaluate_test(test)
                .expect_err("nested pre-push quota must fail");
            let EvaluationFailure::Diagnostic(diagnostic) = error else {
                panic!("nested pre-push quota must become a diagnostic");
            };
            assert_eq!(
                diagnostic.code.as_deref(),
                Some("semantic-comptime-resource-limit")
            );
            assert_eq!(
                diagnostic
                    .labels
                    .iter()
                    .map(|label| label.message.as_str())
                    .collect::<Vec<_>>(),
                [
                    "comptime call to `app.math.forward` entered here",
                    "comptime call to `app.math.make_and_forward` entered here",
                ],
                "{resource} failure before the forward frame is pushed must retain the attempted callee and parent stack"
            );
        }

        let polls = Cell::new(0u64);
        let cancel_mid_structure = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 70
        };
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let mut cancelled =
            ImageEvaluator::new(&request, &cancel_mid_structure).expect("cancellable aggregate");
        assert!(matches!(
            cancelled.evaluate_test(test),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(polls.get(), 70);
        assert_eq!(cancelled.steps, 69);

        let program = fixture.fixture.hir.as_program();
        let pair = program
            .declarations
            .iter()
            .find(|declaration| declaration.name.as_ref().map(Name::as_str) == Some("Pair"))
            .map(|declaration| declaration.id)
            .expect("parsed Pair declaration");
        let constructor = program
            .expressions
            .iter()
            .find_map(|expression| {
                let ExpressionKind::Call { callee, arguments } = &expression.kind else {
                    return None;
                };
                let ExpressionKind::Reference(Definition::Declaration(resolved)) =
                    &program.expression(*callee)?.kind
                else {
                    return None;
                };
                (resolved.declaration == pair).then_some((arguments.as_slice(), expression.source))
            })
            .expect("parsed Pair constructor call");
        let fill_polls = Cell::new(0u64);
        let cancel_first_slot_fill = || {
            let next = fill_polls.get() + 1;
            fill_polls.set(next);
            // Declaration + two field-shape scans consume the first three
            // units; the fourth poll is the first constructor slot push.
            next == 4
        };
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let mut fill_cancelled = ImageEvaluator::new(&request, &cancel_first_slot_fill)
            .expect("constructor fill evaluator");
        fill_cancelled.frames.push(ComptimeFrame {
            declaration: test,
            call_source: None,
            parameters: Vec::new(),
            locals: Vec::new(),
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            fill_cancelled.evaluate_structure_constructor(pair, constructor.0, constructor.1, 1,),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(fill_polls.get(), 4);
        assert_eq!(fill_cancelled.steps, 3);

        set_comptime_call_depth(&mut fixture, 3);
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        assert!(
            ImageEvaluator::new(&request, &|| false)
                .expect("exact aggregate depth")
                .evaluate_test(test)
                .is_ok()
        );
        set_comptime_call_depth(&mut fixture, 2);
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let error = ImageEvaluator::new(&request, &|| false)
            .expect("over aggregate depth")
            .evaluate_test(test)
            .expect_err("aggregate active-call depth plus one");
        let EvaluationFailure::Diagnostic(diagnostic) = error else {
            panic!("aggregate depth quota must become a test diagnostic");
        };
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-resource-limit")
        );
        assert_eq!(diagnostic.labels.len(), 2);
        assert!(
            diagnostic
                .labels
                .iter()
                .any(|label| label.message.contains("app.math.forward"))
        );
    }

    #[test]
    fn aggregate_replacement_and_successful_call_cleanup_are_exact_and_cancellable() {
        const VALUES: &str = r#"module app.math

pub struct Pair:
    pub left: u32
    pub right: u32

pub comptime fn cleanup(value: Pair) -> u32:
    local: Pair = copy value
    local = Pair(right=local.right, left=local.left)
    return local.left
"#;
        const TEST: &str = r#"module app.math_test

from app.math import Pair, cleanup

@test
comptime fn cleanup_fixture():
    value = Pair(right=22, left=20)
    comptime assert cleanup(value) == 20, "cleanup result"
"#;
        let fixture = parsed_comptime_fixture(VALUES, TEST);
        let program = fixture.fixture.hir.as_program();
        let pair = program
            .declarations
            .iter()
            .find(|declaration| declaration.name.as_ref().map(Name::as_str) == Some("Pair"))
            .map(|declaration| declaration.id)
            .expect("parsed Pair declaration");
        let cleanup = program
            .declarations
            .iter()
            .find(|declaration| declaration.name.as_ref().map(Name::as_str) == Some("cleanup"))
            .expect("parsed cleanup declaration");
        let DeclarationKind::Function(cleanup_function) = &cleanup.kind else {
            panic!("cleanup is a function");
        };
        let parameter = cleanup_function.parameters[0];
        let local = program
            .locals
            .iter()
            .find(|local| {
                program
                    .body(local.body)
                    .is_some_and(|body| body.owner == BodyOwner::Declaration(cleanup.id))
            })
            .expect("parsed cleanup local")
            .id;
        let source = cleanup.source;
        let pair_value = || ComptimeValue::Structure {
            declaration: pair,
            fields: vec![
                ComptimeScalar::Integer(ComptimeInteger::new(false, 32, 20).expect("left")),
                ComptimeScalar::Integer(ComptimeInteger::new(false, 32, 22).expect("right")),
            ],
        };
        let changes = no_changes();
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());

        let mut replacement = ImageEvaluator::new(&request, &|| false).expect("replacement");
        replacement
            .retain_u64(
                comptime_structure_payload_bytes(2)
                    .expect("Pair payload")
                    .checked_mul(2)
                    .expect("two Pair payloads"),
            )
            .expect("retain old and replacement Pair");
        replacement.frames.push(ComptimeFrame {
            declaration: cleanup.id,
            call_source: None,
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(pair_value()),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        replacement
            .store(local, pair_value(), source)
            .expect("exact metered replacement");
        assert_eq!(replacement.steps, 4);
        assert_eq!(replacement.retained_bytes, 96);

        let mut over_limits = AnalysisLimits::standard();
        over_limits.evaluator_steps = 3;
        let over_request = parsed_comptime_discovery_request(&fixture, &changes, over_limits);
        let mut over = ImageEvaluator::new(&over_request, &|| false).expect("over replacement");
        over.retain_u64(
            comptime_structure_payload_bytes(2)
                .expect("Pair payload")
                .checked_mul(2)
                .expect("two Pair payloads"),
        )
        .expect("retain over-bound Pairs");
        over.frames.push(ComptimeFrame {
            declaration: cleanup.id,
            call_source: None,
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(pair_value()),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            over.store(local, pair_value(), source),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 3,
                }
            ))
        ));
        assert_eq!(over.steps, 4);

        let replacement_polls = Cell::new(0_u64);
        let cancel_replacement = || {
            let next = replacement_polls.get() + 1;
            replacement_polls.set(next);
            next == 3
        };
        let mut cancelled =
            ImageEvaluator::new(&request, &cancel_replacement).expect("cancel replacement");
        cancelled
            .retain_u64(
                comptime_structure_payload_bytes(2)
                    .expect("Pair payload")
                    .checked_mul(2)
                    .expect("two Pair payloads"),
            )
            .expect("retain cancellable Pairs");
        cancelled.frames.push(ComptimeFrame {
            declaration: cleanup.id,
            call_source: None,
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(pair_value()),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            cancelled.store(local, pair_value(), source),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(replacement_polls.get(), 3);
        assert_eq!(cancelled.steps, 2);
        assert!(matches!(
            cancelled.frames[0].locals[0].value,
            Some(ComptimeValue::Structure { ref fields, .. }) if fields[0]
                == ComptimeScalar::Integer(
                    ComptimeInteger::new(false, 32, 20).expect("old left")
                )
        ));

        let invoke = |limits: AnalysisLimits,
                      is_cancelled: &dyn Fn() -> bool|
         -> (
            Result<ComptimeValue, EvaluationFailure>,
            u64,
            u64,
            u64,
            usize,
            usize,
            usize,
        ) {
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let mut evaluator = ImageEvaluator::new(&request, is_cancelled).expect("cleanup call");
            evaluator
                .retain_u64(comptime_structure_payload_bytes(2).expect("Pair payload"))
                .expect("retain parameter Pair");
            let result =
                evaluator.invoke_function(cleanup.id, vec![(parameter, pair_value())], None, 0);
            let (parameters, locals) = evaluator
                .frames
                .last()
                .map_or((0, 0), |frame| (frame.parameters.len(), frame.locals.len()));
            (
                result,
                evaluator.steps,
                evaluator.peak_bytes,
                evaluator.retained_bytes,
                evaluator.frames.len(),
                parameters,
                locals,
            )
        };
        let (result, exact_steps, exact_bytes, retained_bytes, frames, parameters, locals) =
            invoke(AnalysisLimits::standard(), &|| false);
        assert!(matches!(result, Ok(ComptimeValue::Integer(value)) if value.raw == 20));
        assert_eq!(exact_steps, 113);
        assert_eq!(exact_bytes, 640);
        assert_eq!((retained_bytes, frames, parameters, locals), (0, 0, 0, 0));

        let mut exact_step_limits = AnalysisLimits::standard();
        exact_step_limits.evaluator_steps = 113;
        assert!(invoke(exact_step_limits, &|| false).0.is_ok());
        let mut over_step_limits = AnalysisLimits::standard();
        over_step_limits.evaluator_steps = 112;
        assert!(matches!(
            invoke(over_step_limits, &|| false).0,
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 112,
                }
            ))
        ));
        let mut exact_byte_limits = AnalysisLimits::standard();
        exact_byte_limits.evaluator_bytes = 640;
        assert!(invoke(exact_byte_limits, &|| false).0.is_ok());
        let mut over_byte_limits = AnalysisLimits::standard();
        over_byte_limits.evaluator_bytes = 639;
        assert!(matches!(
            invoke(over_byte_limits, &|| false).0,
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit: 639,
                }
            ))
        ));

        let cleanup_polls = Cell::new(0_u64);
        let cancel_last_parameter_field = || {
            let next = cleanup_polls.get() + 1;
            cleanup_polls.set(next);
            next == 113
        };
        let (
            cancelled_result,
            cancelled_steps,
            _,
            _,
            cancelled_frames,
            cancelled_parameters,
            cancelled_locals,
        ) = invoke(AnalysisLimits::standard(), &cancel_last_parameter_field);
        assert!(matches!(
            cancelled_result,
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(cleanup_polls.get(), 113);
        assert_eq!(cancelled_steps, 112);
        assert_eq!(
            (cancelled_frames, cancelled_parameters, cancelled_locals),
            (1, 1, 0),
            "cancellation before the final parameter field is disposed retains the source frame and current binding"
        );
    }

    #[test]
    fn text_payload_cleanup_is_exact_for_replacement_temporaries_and_frames() {
        const TEXT_BYTES: usize = COMPTIME_SOURCE_COPY_CHUNK_BYTES;
        let fixture = parsed_actor_fixture(BOUNDED_ACTOR_SOURCE);
        let program = fixture.fixture.hir.as_program();
        let declaration = fixture.entry;
        let local = program
            .locals
            .iter()
            .find(|local| {
                program
                    .body(local.body)
                    .is_some_and(|body| body.owner == BodyOwner::Declaration(declaration))
            })
            .expect("parsed image local")
            .id;
        let source = program
            .declaration(declaration)
            .expect("image declaration")
            .source;
        let old_text = "o".repeat(TEXT_BYTES);
        let new_text = "n".repeat(TEXT_BYTES);
        let text_bytes = u64::try_from(TEXT_BYTES).expect("bounded text bytes");
        let simultaneous_bytes = text_bytes.checked_mul(2).expect("two text payloads");
        let changes = no_changes();

        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_steps = 2;
        exact_limits.evaluator_bytes = simultaneous_bytes;
        let request = parsed_actor_request(&fixture, &changes, exact_limits);
        let mut exact = ImageEvaluator::new(&request, &|| false).expect("exact text evaluator");
        exact
            .retain_u64(simultaneous_bytes)
            .expect("exact old and replacement text retention");
        exact.frames.push(ComptimeFrame {
            declaration,
            call_source: None,
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Text(old_text.clone())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        exact
            .store(local, ComptimeValue::Text(new_text.clone()), source)
            .expect("exact text replacement cleanup");
        assert_eq!(exact.steps, 2, "one local scan plus one text disposal");
        assert_eq!(exact.peak_bytes, simultaneous_bytes);
        assert_eq!(exact.retained_bytes, text_bytes);
        assert!(matches!(
            exact.frames[0].locals[0].value,
            Some(ComptimeValue::Text(ref value)) if value == &new_text
        ));

        exact.steps = 0;
        exact
            .retain_u64(text_bytes)
            .expect("released replacement space is reusable at the exact byte bound");
        exact
            .dispose_temporary_value(ComptimeValue::Text(old_text.clone()), source)
            .expect("text expression temporary cleanup");
        assert_eq!(exact.steps, 1);
        assert_eq!(exact.retained_bytes, text_bytes);

        let mut one_under_step_limits = AnalysisLimits::standard();
        one_under_step_limits.evaluator_steps = 1;
        one_under_step_limits.evaluator_bytes = simultaneous_bytes;
        let request = parsed_actor_request(&fixture, &changes, one_under_step_limits);
        let mut one_under =
            ImageEvaluator::new(&request, &|| false).expect("one-under text evaluator");
        one_under
            .retain_u64(simultaneous_bytes)
            .expect("retained text pair");
        one_under.frames.push(ComptimeFrame {
            declaration,
            call_source: None,
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Text(old_text.clone())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            one_under.store(local, ComptimeValue::Text(new_text.clone()), source),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 1,
                }
            ))
        ));
        assert_eq!(one_under.steps, 2);
        assert_eq!(one_under.retained_bytes, simultaneous_bytes);
        assert!(matches!(
            one_under.frames[0].locals[0].value,
            Some(ComptimeValue::Text(ref value)) if value == &old_text
        ));

        let mut zero_step_limits = AnalysisLimits::standard();
        zero_step_limits.evaluator_steps = 0;
        zero_step_limits.evaluator_bytes = text_bytes;
        let request = parsed_actor_request(&fixture, &changes, zero_step_limits);
        let mut temporary =
            ImageEvaluator::new(&request, &|| false).expect("one-under temporary evaluator");
        temporary
            .retain_u64(text_bytes)
            .expect("temporary text retention");
        assert!(matches!(
            temporary.dispose_temporary_value(ComptimeValue::Text(old_text.clone()), source),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 0,
                }
            ))
        ));
        assert_eq!(temporary.steps, 1);
        assert_eq!(temporary.retained_bytes, text_bytes);

        let mut frame_limits = AnalysisLimits::standard();
        frame_limits.evaluator_steps = 4;
        frame_limits.evaluator_bytes = simultaneous_bytes;
        let request = parsed_actor_request(&fixture, &changes, frame_limits);
        let mut frame = ImageEvaluator::new(&request, &|| false).expect("exact frame evaluator");
        frame
            .retain_u64(simultaneous_bytes)
            .expect("frame text payloads");
        frame.current_source = source;
        frame.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: vec![ComptimeBinding {
                id: wrela_hir::ParameterId(0),
                value: Some(ComptimeValue::Text(old_text.clone())),
            }],
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Text(new_text.clone())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        let released = frame
            .poll_successful_frame_cleanup()
            .expect("exact text frame cleanup");
        assert_eq!(frame.steps, 4, "each binding and text allocation is polled");
        assert_eq!(released, simultaneous_bytes);
        assert!(frame.frames[0].locals.is_empty());
        assert!(frame.frames[0].parameters.is_empty());
        frame
            .release(released)
            .expect("exact frame payload release cannot underflow");
        assert_eq!(frame.retained_bytes, 0);

        let mut one_under_frame_limits = AnalysisLimits::standard();
        one_under_frame_limits.evaluator_steps = 3;
        one_under_frame_limits.evaluator_bytes = simultaneous_bytes;
        let request = parsed_actor_request(&fixture, &changes, one_under_frame_limits);
        let mut one_under_frame =
            ImageEvaluator::new(&request, &|| false).expect("one-under frame evaluator");
        one_under_frame
            .retain_u64(simultaneous_bytes)
            .expect("one-under frame text payloads");
        one_under_frame.current_source = source;
        one_under_frame.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: vec![ComptimeBinding {
                id: wrela_hir::ParameterId(0),
                value: Some(ComptimeValue::Text(old_text.clone())),
            }],
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Text(new_text)),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            one_under_frame.poll_successful_frame_cleanup(),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 3,
                }
            ))
        ));
        assert_eq!(one_under_frame.steps, 4);
        assert!(one_under_frame.frames[0].locals.is_empty());
        assert!(matches!(
            one_under_frame.frames[0].parameters[0].value,
            Some(ComptimeValue::Text(ref value)) if value == &old_text
        ));
        assert_eq!(one_under_frame.retained_bytes, simultaneous_bytes);

        let mut one_under_byte_limits = AnalysisLimits::standard();
        one_under_byte_limits.evaluator_bytes = simultaneous_bytes - 1;
        let request = parsed_actor_request(&fixture, &changes, one_under_byte_limits);
        let mut one_under_bytes =
            ImageEvaluator::new(&request, &|| false).expect("one-under byte evaluator");
        one_under_bytes
            .retain_u64(text_bytes)
            .expect("first text fits one-under pair bound");
        assert!(matches!(
            one_under_bytes.retain_u64(text_bytes),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit,
                }
            )) if limit == simultaneous_bytes - 1
        ));
        assert_eq!(one_under_bytes.retained_bytes, text_bytes);
        assert!(matches!(
            one_under_bytes.release(text_bytes + 1),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::RequestMismatch
            ))
        ));
        assert_eq!(
            one_under_bytes.retained_bytes, text_bytes,
            "an invariant underflow fails closed without resetting retention"
        );
    }

    #[test]
    fn image_payload_cleanup_polls_each_actor_and_cancels_at_the_tail() {
        const ACTOR_COUNT: usize = 128;
        let fixture = parsed_actor_fixture(BOUNDED_ACTOR_SOURCE);
        let program = fixture.fixture.hir.as_program();
        let declaration = fixture.entry;
        let local = program
            .locals
            .iter()
            .find(|local| {
                program
                    .body(local.body)
                    .is_some_and(|body| body.owner == BodyOwner::Declaration(declaration))
            })
            .expect("parsed image local")
            .id;
        let source = program
            .declaration(declaration)
            .expect("image declaration")
            .source;
        let image = || {
            let image_name = "bounded-cleanup-image";
            let mut names = image_name.to_owned();
            let mut actors = Vec::new();
            for index in 0..ACTOR_COUNT {
                let actor_name = format!("actor-{index:03}");
                let name_start = u64::try_from(names.len()).expect("bounded actor-name offset");
                let name_len = u64::try_from(actor_name.len()).expect("bounded actor-name length");
                names.push_str(&actor_name);
                actors.push(EvaluatedActor {
                    class: DeclarationId(u32::try_from(index).expect("bounded actor id")),
                    kind: EvaluatedActorKind::Service,
                    name_start,
                    name_len,
                    mailbox_capacity: 1,
                    source,
                    mailbox_source: source,
                });
            }
            EvaluatedImage {
                names,
                name_len: u32::try_from(image_name.len()).expect("bounded image-name length"),
                name_source: source,
                actors,
            }
        };
        let payload_bytes = |image: &EvaluatedImage| {
            let actor_bytes = image
                .actors
                .len()
                .checked_mul(COMPTIME_ACTOR_BYTES)
                .expect("bounded actor metadata");
            image
                .names
                .len()
                .checked_add(actor_bytes)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .expect("bounded image payload")
        };
        let payload = payload_bytes(&image());
        let exact_steps = u64::try_from(ACTOR_COUNT)
            .expect("bounded actor count")
            .checked_add(2)
            .expect("local, actors, and contiguous name arena cleanup");
        let changes = no_changes();

        let request = parsed_actor_request(&fixture, &changes, AnalysisLimits::standard());
        let mut source_evaluator =
            ImageEvaluator::new(&request, &|| false).expect("source image evaluator");
        let source_value = source_evaluator
            .invoke_function(declaration, Vec::new(), None, 0)
            .expect("parsed image constructor with actor installation");
        let ComptimeValue::Image(ref source_image) = source_value else {
            panic!("parsed image constructor result");
        };
        assert_eq!(source_image.actors.len(), 1);
        let source_payload = payload_bytes(source_image);
        assert_eq!(
            source_evaluator.retained_bytes, source_payload,
            "the successful install snapshot is disposed, leaving only the returned image"
        );
        source_evaluator
            .dispose_temporary_value(source_value, source)
            .expect("returned source image cleanup");
        assert_eq!(source_evaluator.retained_bytes, 0);

        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_steps = exact_steps;
        exact_limits.evaluator_bytes = payload;
        let request = parsed_actor_request(&fixture, &changes, exact_limits);
        let mut exact = ImageEvaluator::new(&request, &|| false).expect("exact image evaluator");
        exact
            .retain_u64(payload)
            .expect("exact image payload retention");
        exact.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Image(image())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        exact
            .store(local, ComptimeValue::Unit, source)
            .expect("exact image replacement cleanup");
        assert_eq!(exact.steps, exact_steps);
        assert_eq!(exact.peak_bytes, payload);
        assert_eq!(exact.retained_bytes, 0);
        assert!(matches!(
            exact.frames[0].locals[0].value,
            Some(ComptimeValue::Unit)
        ));

        let mut one_under_step_limits = AnalysisLimits::standard();
        one_under_step_limits.evaluator_steps = exact_steps - 1;
        one_under_step_limits.evaluator_bytes = payload;
        let request = parsed_actor_request(&fixture, &changes, one_under_step_limits);
        let mut one_under =
            ImageEvaluator::new(&request, &|| false).expect("one-under image evaluator");
        one_under
            .retain_u64(payload)
            .expect("one-under image payload retention");
        one_under.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Image(image())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            one_under.store(local, ComptimeValue::Unit, source),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit,
                }
            )) if limit == exact_steps - 1
        ));
        assert_eq!(one_under.steps, exact_steps);
        assert_eq!(one_under.retained_bytes, payload);
        assert!(matches!(
            one_under.frames[0].locals[0].value,
            Some(ComptimeValue::Image(ref image))
                if image.actors.is_empty()
                    && !image.names.is_empty()
                    && image.name() == Some("bounded-cleanup-image")
        ));

        let cancellation_polls = Cell::new(0_u64);
        let cancel_before_last_actor = || {
            let next = cancellation_polls.get() + 1;
            cancellation_polls.set(next);
            next == u64::try_from(ACTOR_COUNT).expect("bounded cancellation poll") + 1
        };
        let request = parsed_actor_request(&fixture, &changes, AnalysisLimits::standard());
        let mut cancelled = ImageEvaluator::new(&request, &cancel_before_last_actor)
            .expect("cancellable image evaluator");
        cancelled
            .retain_u64(payload)
            .expect("cancellable image payload retention");
        cancelled.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(ComptimeValue::Image(image())),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            cancelled.store(local, ComptimeValue::Unit, source),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(
            cancellation_polls.get(),
            u64::try_from(ACTOR_COUNT).expect("bounded cancellation count") + 1
        );
        assert_eq!(
            cancelled.steps,
            u64::try_from(ACTOR_COUNT).expect("bounded completed cleanup work")
        );
        assert_eq!(cancelled.current_source, source);
        assert_eq!(cancelled.frames.len(), 1, "source frame remains published");
        assert_eq!(cancelled.retained_bytes, payload);
        assert!(matches!(
            cancelled.frames[0].locals[0].value,
            Some(ComptimeValue::Image(ref image))
                if image.actors.len() == ACTOR_COUNT
                    && image.actors[0].class == DeclarationId(0)
                    && !image.names.is_empty()
                    && image.name() == Some("bounded-cleanup-image")
        ));

        let mut temporary_limits = AnalysisLimits::standard();
        temporary_limits.evaluator_steps = exact_steps - 1;
        temporary_limits.evaluator_bytes = payload;
        let request = parsed_actor_request(&fixture, &changes, temporary_limits);
        let mut temporary =
            ImageEvaluator::new(&request, &|| false).expect("image temporary evaluator");
        temporary
            .retain_u64(payload)
            .expect("image temporary retention");
        temporary
            .dispose_temporary_value(ComptimeValue::Image(image()), source)
            .expect("image expression temporary cleanup");
        assert_eq!(temporary.steps, exact_steps - 1);
        assert_eq!(temporary.retained_bytes, 0);

        let mut one_under_byte_limits = AnalysisLimits::standard();
        one_under_byte_limits.evaluator_bytes = payload - 1;
        let request = parsed_actor_request(&fixture, &changes, one_under_byte_limits);
        let mut one_under_bytes =
            ImageEvaluator::new(&request, &|| false).expect("one-under image byte evaluator");
        assert!(matches!(
            one_under_bytes.retain_u64(payload),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit,
                }
            )) if limit == payload - 1
        ));
        assert_eq!(one_under_bytes.retained_bytes, 0);
        assert_eq!(one_under_bytes.peak_bytes, 0);
    }

    #[test]
    fn contiguous_image_name_append_is_chunk_polled_and_tail_cancellable() {
        const CHUNKS: usize = 64;
        let fixture = parsed_actor_fixture(BOUNDED_ACTOR_SOURCE);
        let program = fixture.fixture.hir.as_program();
        let declaration = fixture.entry;
        let local = program
            .locals
            .iter()
            .find(|local| {
                program
                    .body(local.body)
                    .is_some_and(|body| body.owner == BodyOwner::Declaration(declaration))
            })
            .expect("parsed image local")
            .id;
        let source = program
            .declaration(declaration)
            .expect("image declaration")
            .source;
        let actor_name = "a".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES * CHUNKS);
        let base_name = "image";
        let total_bytes = u64::try_from(base_name.len() + actor_name.len())
            .expect("bounded contiguous name arena");
        let value = || {
            ComptimeValue::Image(EvaluatedImage {
                names: base_name.to_owned(),
                name_len: u32::try_from(base_name.len()).expect("bounded base image name"),
                name_source: source,
                actors: Vec::new(),
            })
        };
        let changes = no_changes();

        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_steps = u64::try_from(CHUNKS).expect("bounded chunk count");
        exact_limits.evaluator_bytes = total_bytes;
        let request = parsed_actor_request(&fixture, &changes, exact_limits);
        let mut exact = ImageEvaluator::new(&request, &|| false).expect("exact arena append");
        exact
            .retain_u64(total_bytes)
            .expect("precharged contiguous arena");
        exact.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(value()),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        let (start, length) = exact
            .append_precharged_image_name(local, &actor_name, source)
            .expect("exact chunk-polled arena append");
        assert_eq!(start, u64::try_from(base_name.len()).expect("base offset"));
        assert_eq!(
            length,
            u64::try_from(actor_name.len()).expect("actor length")
        );
        assert_eq!(exact.steps, u64::try_from(CHUNKS).expect("exact chunks"));
        assert!(matches!(
            exact.frames[0].locals[0].value,
            Some(ComptimeValue::Image(ref image))
                if image.names.len()
                    == usize::try_from(total_bytes).expect("host arena length")
        ));

        let cancellation_polls = Cell::new(0_u64);
        let cancel_last_chunk = || {
            let next = cancellation_polls.get() + 1;
            cancellation_polls.set(next);
            next == u64::try_from(CHUNKS).expect("bounded cancellation chunk")
        };
        let request = parsed_actor_request(&fixture, &changes, AnalysisLimits::standard());
        let mut cancelled =
            ImageEvaluator::new(&request, &cancel_last_chunk).expect("cancellable arena append");
        cancelled
            .retain_u64(total_bytes)
            .expect("cancellable precharged arena");
        cancelled.frames.push(ComptimeFrame {
            declaration,
            call_source: Some(source),
            parameters: Vec::new(),
            locals: vec![ComptimeBinding {
                id: local,
                value: Some(value()),
            }],
            charged_bytes: 0,
            host_depth: 1,
        });
        assert!(matches!(
            cancelled.append_precharged_image_name(local, &actor_name, source),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(
            cancellation_polls.get(),
            u64::try_from(CHUNKS).expect("cancellation chunks")
        );
        assert_eq!(
            cancelled.steps,
            u64::try_from(CHUNKS - 1).expect("completed chunks")
        );
        assert_eq!(cancelled.current_source, source);
        assert!(matches!(
            cancelled.frames[0].locals[0].value,
            Some(ComptimeValue::Image(ref image))
                if image.names.len()
                    == base_name.len()
                        + (CHUNKS - 1) * COMPTIME_SOURCE_COPY_CHUNK_BYTES
        ));

        let mut one_under_limits = AnalysisLimits::standard();
        one_under_limits.evaluator_bytes = total_bytes - 1;
        let request = parsed_actor_request(&fixture, &changes, one_under_limits);
        let mut one_under =
            ImageEvaluator::new(&request, &|| false).expect("one-under arena bytes");
        assert!(matches!(
            one_under.retain_u64(total_bytes),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit,
                }
            )) if limit == total_bytes - 1
        ));
    }

    #[test]
    fn first_field_projection_polls_a_large_flat_structure_tail() {
        const FIELD_COUNT: usize = 64;
        let mut fields = String::new();
        for index in 0..FIELD_COUNT {
            fields.push_str(&format!("    pub field_{index:02}: u32\n"));
        }
        let values = format!("module app.math\n\npub struct Wide:\n{fields}");
        const TEST: &str = r#"module app.math_test

@test
comptime fn projection_fixture():
    comptime assert true, "fixture"
"#;
        let fixture = parsed_comptime_fixture(&values, TEST);
        let program = fixture.fixture.hir.as_program();
        let wide = program
            .declarations
            .iter()
            .find(|declaration| declaration.name.as_ref().map(Name::as_str) == Some("Wide"))
            .map(|declaration| declaration.id)
            .expect("parsed Wide declaration");
        let test = program.test_candidates[0];
        let source = program.declaration(wide).expect("Wide source").source;
        let value = || ComptimeValue::Structure {
            declaration: wide,
            fields: (0..FIELD_COUNT)
                .map(|index| {
                    ComptimeScalar::Integer(
                        ComptimeInteger::new(false, 32, index as u128).expect("wide field"),
                    )
                })
                .collect(),
        };
        let changes = no_changes();
        let field_name = Name::new("field_00".to_owned()).expect("field name");
        let project = |limits: AnalysisLimits,
                       is_cancelled: &dyn Fn() -> bool|
         -> (Result<ComptimeValue, EvaluationFailure>, u64, u64) {
            let request = parsed_comptime_discovery_request(&fixture, &changes, limits);
            let mut evaluator =
                ImageEvaluator::new(&request, is_cancelled).expect("wide projection");
            evaluator.frames.push(ComptimeFrame {
                declaration: test,
                call_source: None,
                parameters: Vec::new(),
                locals: Vec::new(),
                charged_bytes: 0,
                host_depth: 1,
            });
            evaluator
                .retain_u64(comptime_structure_payload_bytes(FIELD_COUNT).expect("Wide payload"))
                .expect("retain Wide");
            let result = evaluator.evaluate_structure_field(value(), &field_name, source);
            (result, evaluator.steps, evaluator.retained_bytes)
        };
        let (projected, exact_steps, retained_bytes) =
            project(AnalysisLimits::standard(), &|| false);
        let projected = projected.expect("first Wide field");
        assert!(matches!(projected, ComptimeValue::Integer(value) if value.raw == 0));
        assert_eq!(exact_steps, 715);
        assert_eq!(retained_bytes, 0);

        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_steps = 715;
        assert!(project(exact_limits, &|| false).0.is_ok());
        let mut over_limits = AnalysisLimits::standard();
        over_limits.evaluator_steps = 714;
        assert!(matches!(
            project(over_limits, &|| false).0,
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator steps",
                    limit: 714,
                }
            ))
        ));

        let polls = Cell::new(0_u64);
        let cancel_last_tail_field = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 715
        };
        let (cancelled, cancelled_steps, _) =
            project(AnalysisLimits::standard(), &cancel_last_tail_field);
        assert!(matches!(
            cancelled,
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(polls.get(), 715);
        assert_eq!(cancelled_steps, 714);
    }

    #[test]
    fn recursive_comptime_calls_admit_exact_host_cap_and_reject_cap_plus_one() {
        const MATH: &str = "module app.math\n\npub comptime fn countdown(value: u32) -> u32:\n    if value == 0:\n        return 0\n    return countdown(value - 1)\n";
        let test_source = |count| {
            format!(
                "module app.math_test\n\nfrom app.math import countdown\n\n@test\ncomptime fn recursion_is_bounded():\n    result: u32 = countdown({count})\n    comptime assert result == 0, \"countdown result\"\n"
            )
        };
        let passing_source = test_source(30);
        let failing_source = test_source(31);
        let passing = parsed_comptime_fixture(MATH, &passing_source);
        let failing = parsed_comptime_fixture(MATH, &failing_source);
        std::thread::Builder::new()
            .name("bounded-comptime-recursion".to_owned())
            .stack_size(1024 * 1024)
            .spawn(move || {
                let changes = no_changes();
                let test = passing.fixture.hir.as_program().test_candidates[0];
                let request = parsed_comptime_discovery_request(
                    &passing,
                    &changes,
                    AnalysisLimits::standard(),
                );
                assert!(
                    ImageEvaluator::new(&request, &|| false)
                        .expect("exact-cap evaluator")
                        .evaluate_test(test)
                        .is_ok()
                );

                let test = failing.fixture.hir.as_program().test_candidates[0];
                let request = parsed_comptime_discovery_request(
                    &failing,
                    &changes,
                    AnalysisLimits::standard(),
                );
                let error = ImageEvaluator::new(&request, &|| false)
                    .expect("cap-plus-one evaluator")
                    .evaluate_test(test)
                    .expect_err("active-call cap plus one must fail closed");
                let EvaluationFailure::Diagnostic(diagnostic) = error else {
                    panic!("call-depth cap must be a typed test diagnostic");
                };
                assert_eq!(
                    diagnostic.code.as_deref(),
                    Some("semantic-comptime-resource-limit")
                );
                assert_eq!(
                    diagnostic.message,
                    "comptime test exceeded comptime evaluator depth limit 32"
                );
                assert_eq!(diagnostic.labels.len(), 32);
                assert_eq!(diagnostic.primary, diagnostic.labels[0].span);
                assert_eq!(
                    diagnostic.labels[0].message,
                    "comptime call to `app.math.countdown` entered here"
                );
            })
            .expect("spawn small-stack evaluator regression")
            .join()
            .expect("small-stack evaluator regression completes");
    }

    #[test]
    fn nested_syntax_and_calls_share_one_small_stack_host_envelope() {
        let math = |wrapper_count| {
            let wrappers = "comptime ".repeat(wrapper_count);
            format!(
                "module app.math\n\npub comptime fn countdown(value: u32) -> u32:\n    if value == 0:\n        return 0\n    return {wrappers}countdown(value - 1)\n"
            )
        };
        let source = |count, wrapper_count| {
            let wrappers = "comptime ".repeat(wrapper_count);
            format!(
                "module app.math_test\n\nfrom app.math import countdown\n\n@test\ncomptime fn combined_host_bound():\n    result = {wrappers}countdown({count})\n    comptime assert result == 0, \"countdown result\"\n"
            )
        };
        // The root frame contributes 1, the once-wrapped first call contributes
        // 2 above its separately bounded active-call base, seven recursive calls
        // contribute 6 each, and the leaf expression adds 2:
        // 1 + 2 + 7 * 6 + 2 = the exact cumulative host limit of 48.
        let passing = parsed_comptime_fixture(&math(5), &source(7, 1));
        // One additional root wrapper requests exactly 49 without increasing
        // active Wrela call depth or approaching the unsafe historical bound.
        let failing = parsed_comptime_fixture(&math(5), &source(7, 2));

        std::thread::Builder::new()
            .name("combined-comptime-host-depth".to_owned())
            .stack_size(1024 * 1024)
            .spawn(move || {
                let changes = no_changes();
                let passing_test = passing.fixture.hir.as_program().test_candidates[0];
                let request = parsed_comptime_discovery_request(
                    &passing,
                    &changes,
                    AnalysisLimits::standard(),
                );
                let result = ImageEvaluator::new(&request, &|| false)
                    .expect("combined exact-bound evaluator")
                    .evaluate_test(passing_test);
                assert!(
                    result.is_ok(),
                    "the combined bound admits its exact safe case: {result:?}"
                );

                let failing_test = failing.fixture.hir.as_program().test_candidates[0];
                let request = parsed_comptime_discovery_request(
                    &failing,
                    &changes,
                    AnalysisLimits::standard(),
                );
                let error = ImageEvaluator::new(&request, &|| false)
                    .expect("combined over-bound evaluator")
                    .evaluate_test(failing_test)
                    .expect_err("combined host envelope plus one must fail closed");
                let EvaluationFailure::Diagnostic(diagnostic) = error else {
                    panic!("combined host quota must be a typed test diagnostic");
                };
                assert_eq!(
                    diagnostic.code.as_deref(),
                    Some("semantic-comptime-resource-limit")
                );
                assert_eq!(
                    diagnostic.message,
                    "comptime test exceeded comptime evaluator host recursion limit 48"
                );
                assert!(!diagnostic.labels.is_empty());
                assert_eq!(diagnostic.primary.file, diagnostic.labels[0].span.file);
                assert!(diagnostic.labels.iter().all(|label| {
                    label.message == "comptime call to `app.math.countdown` entered here"
                }));
            })
            .expect("spawn combined small-stack evaluator regression")
            .join()
            .expect("combined small-stack evaluator regression completes");
    }

    #[test]
    fn comptime_integer_defaults_minima_and_target_operations_are_exact() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let request = request(&fixture, &changes, AnalysisLimits::standard());
        let mut evaluator = ImageEvaluator::new(&request, &|| false).expect("integer evaluator");
        let source = span(0, 40, 41);

        let ComptimeValue::Integer(i64_max) = evaluator
            .evaluate_integer_literal("9223372036854775807", None, source)
            .expect("i64 default maximum")
        else {
            panic!("integer literal value");
        };
        assert_eq!(
            i64_max.scalar_type(),
            ComptimeType::Integer {
                signed: true,
                bits: 64,
            }
        );
        let ComptimeValue::Integer(u64_min) = evaluator
            .evaluate_integer_literal("9223372036854775808", None, source)
            .expect("u64 default begins above i64")
        else {
            panic!("integer literal value");
        };
        assert_eq!(
            u64_min.scalar_type(),
            ComptimeType::Integer {
                signed: false,
                bits: 64,
            }
        );
        let ComptimeValue::Integer(u64_max) = evaluator
            .evaluate_integer_literal("18446744073709551615", None, source)
            .expect("u64 default maximum")
        else {
            panic!("integer literal value");
        };
        assert_eq!(u64_max.raw, u64::MAX as u128);
        assert!(matches!(
            evaluator.evaluate_integer_literal("18446744073709551616", None, source),
            Err(EvaluationFailure::Diagnostic(diagnostic))
                if diagnostic.code.as_deref() == Some("semantic-comptime-integer-literal")
        ));

        for (bits, spelling, expected) in [
            (8, "128", i8::MIN as i128),
            (64, "9223372036854775808", i64::MIN as i128),
            (128, "170141183460469231731687303715884105728", i128::MIN),
        ] {
            let ComptimeValue::Integer(value) = evaluator
                .evaluate_negative_integer_literal(spelling, bits, source)
                .expect("exact signed minimum")
            else {
                panic!("negative integer value");
            };
            assert_eq!(value.signed_value(), Some(expected));
        }
        assert!(matches!(
            evaluator.evaluate_negative_integer_literal("129", 8, source),
            Err(EvaluationFailure::Diagnostic(diagnostic))
                if diagnostic.code.as_deref() == Some("semantic-comptime-integer-literal")
        ));

        let signed = |value| {
            ComptimeValue::Integer(
                integer_from_signed(8, value).expect("representable signed test integer"),
            )
        };
        let ComptimeValue::Integer(remainder) = evaluator
            .evaluate_binary_values(
                wrela_hir::BinaryOperator::Remainder,
                signed(-5),
                signed(2),
                source,
            )
            .expect("signed target remainder")
        else {
            panic!("integer remainder");
        };
        assert_eq!(remainder.signed_value(), Some(-1));
        let ComptimeValue::Integer(shifted) = evaluator
            .evaluate_binary_values(
                wrela_hir::BinaryOperator::ShiftRight,
                signed(-4),
                signed(1),
                source,
            )
            .expect("arithmetic target shift")
        else {
            panic!("integer shift");
        };
        assert_eq!(shifted.signed_value(), Some(-2));
        assert_eq!(
            evaluator
                .evaluate_comparison(
                    wrela_hir::ComparisonOperator::Less,
                    signed(-1),
                    signed(0),
                    source,
                )
                .expect("signed target comparison"),
            ComptimeValue::Boolean(true)
        );

        let unsigned = |raw| {
            ComptimeValue::Integer(
                ComptimeInteger::new(false, 8, raw).expect("representable unsigned test integer"),
            )
        };
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::AddWrapping,
                    unsigned(255),
                    unsigned(1),
                    source,
                )
                .expect("target-width wrapping addition"),
            unsigned(0)
        );
        assert!(matches!(
            evaluator.evaluate_binary_values(
                wrela_hir::BinaryOperator::Add,
                unsigned(255),
                unsigned(1),
                source,
            ),
            Err(EvaluationFailure::Diagnostic(diagnostic))
                if diagnostic.code.as_deref() == Some("semantic-comptime-arithmetic")
        ));
        assert_eq!(
            evaluator.source_value_type(&scalar_type(Builtin::Usize, source)),
            Some(ComptimeType::Integer {
                signed: false,
                bits: 64,
            })
        );
        assert_eq!(
            evaluator.source_value_type(&scalar_type(Builtin::Isize, source)),
            Some(ComptimeType::Integer {
                signed: true,
                bits: 64,
            })
        );
    }

    #[test]
    fn comptime_checked_and_modular_left_shifts_observe_exact_target_boundaries() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let request = request(&fixture, &changes, AnalysisLimits::standard());
        let evaluator = ImageEvaluator::new(&request, &|| false).expect("shift evaluator");
        let source = span(0, 40, 41);
        let unsigned = |raw| {
            ComptimeValue::Integer(
                ComptimeInteger::new(false, 8, raw).expect("representable u8 shift operand"),
            )
        };
        let signed = |value| {
            ComptimeValue::Integer(
                integer_from_signed(8, value).expect("representable i8 shift operand"),
            )
        };
        let unsigned_128 = |raw| {
            ComptimeValue::Integer(
                ComptimeInteger::new(false, 128, raw).expect("representable u128 shift operand"),
            )
        };
        let signed_128 = |value| {
            ComptimeValue::Integer(
                integer_from_signed(128, value).expect("representable i128 shift operand"),
            )
        };

        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeft,
                    unsigned(1),
                    unsigned(7),
                    source,
                )
                .expect("u8 checked boundary shift"),
            unsigned(128)
        );
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeft,
                    signed(-64),
                    signed(1),
                    source,
                )
                .expect("i8 checked negative boundary shift"),
            signed(-128)
        );
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeftModular,
                    unsigned(255),
                    unsigned(1),
                    source,
                )
                .expect("u8 modular result loss"),
            unsigned(254)
        );
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeftModular,
                    signed(-65),
                    signed(1),
                    source,
                )
                .expect("i8 modular result loss"),
            signed(126)
        );
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeft,
                    signed_128(-1),
                    signed_128(127),
                    source,
                )
                .expect("i128 checked sign boundary"),
            signed_128(i128::MIN)
        );
        assert_eq!(
            evaluator
                .evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeftModular,
                    unsigned_128(u128::MAX),
                    unsigned_128(1),
                    source,
                )
                .expect("u128 modular result loss"),
            unsigned_128(u128::MAX - 1)
        );

        for (left, right) in [
            (unsigned(128), unsigned(1)),
            (signed(64), signed(1)),
            (signed(-65), signed(1)),
            (signed_128(i128::MAX), signed_128(1)),
            (unsigned_128(u128::MAX), unsigned_128(1)),
        ] {
            assert!(matches!(
                evaluator.evaluate_binary_values(
                    wrela_hir::BinaryOperator::ShiftLeft,
                    left,
                    right,
                    source,
                ),
                Err(EvaluationFailure::Diagnostic(diagnostic))
                    if diagnostic.code.as_deref()
                        == Some("semantic-comptime-shift-result-loss")
            ));
        }
        for (operator, left, right) in [
            (
                wrela_hir::BinaryOperator::ShiftLeft,
                unsigned(1),
                unsigned(8),
            ),
            (
                wrela_hir::BinaryOperator::ShiftLeftModular,
                unsigned(1),
                unsigned(8),
            ),
            (wrela_hir::BinaryOperator::ShiftLeft, signed(1), signed(-1)),
            (
                wrela_hir::BinaryOperator::ShiftLeftModular,
                signed(1),
                signed(-1),
            ),
        ] {
            assert!(matches!(
                evaluator.evaluate_binary_values(operator, left, right, source),
                Err(EvaluationFailure::Diagnostic(diagnostic))
                    if diagnostic.code.as_deref() == Some("semantic-comptime-shift-count")
            ));
        }
        assert!(matches!(
            evaluator.evaluate_binary_values(
                wrela_hir::BinaryOperator::ShiftLeft,
                unsigned(1),
                ComptimeValue::Integer(
                    ComptimeInteger::new(false, 16, 1).expect("u16 shift operand")
                ),
                source,
            ),
            Err(EvaluationFailure::Diagnostic(diagnostic))
                if diagnostic.code.as_deref() == Some("semantic-comptime-type-mismatch")
        ));
    }

    #[test]
    fn evaluator_source_payload_scans_have_exact_bounds_and_late_cancellation() {
        const U128_MAX: &str = "340282366920938463463374607431768211455";
        const I128_MIN_MAGNITUDE: &str = "170141183460469231731687303715884105728";
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let source = span(0, 40, 79);

        let standard_request = request(&fixture, &changes, AnalysisLimits::standard());
        let mut maximum =
            ImageEvaluator::new(&standard_request, &|| false).expect("maximum evaluator");
        let ComptimeValue::Integer(value) = maximum
            .evaluate_integer_literal(
                U128_MAX,
                Some(ComptimeType::Integer {
                    signed: false,
                    bits: 128,
                }),
                source,
            )
            .expect("u128 maximum literal")
        else {
            panic!("maximum integer value");
        };
        assert_eq!(value.raw, u128::MAX);
        assert_eq!(maximum.steps, U128_MAX.len() as u64);

        let mut minimum =
            ImageEvaluator::new(&standard_request, &|| false).expect("minimum evaluator");
        let ComptimeValue::Integer(value) = minimum
            .evaluate_negative_integer_literal(I128_MIN_MAGNITUDE, 128, source)
            .expect("i128 minimum literal")
        else {
            panic!("minimum integer value");
        };
        assert_eq!(value.signed_value(), Some(i128::MIN));
        assert_eq!(minimum.steps, I128_MIN_MAGNITUDE.len() as u64);

        let polls = Cell::new(0usize);
        let cancel_before_last_byte = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == U128_MAX.len()
        };
        let mut cancelled = ImageEvaluator::new(&standard_request, &cancel_before_last_byte)
            .expect("cancel evaluator");
        assert!(matches!(
            cancelled.evaluate_integer_literal(
                U128_MAX,
                Some(ComptimeType::Integer {
                    signed: false,
                    bits: 128,
                }),
                source,
            ),
            Err(EvaluationFailure::Analysis(AnalysisFailure::Cancelled))
        ));
        assert_eq!(polls.get(), U128_MAX.len());
        assert_eq!(cancelled.steps, (U128_MAX.len() - 1) as u64);

        let exact_text = "x".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES);
        let over_text = "x".repeat(COMPTIME_SOURCE_COPY_CHUNK_BYTES + 1);
        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.evaluator_bytes = COMPTIME_SOURCE_COPY_CHUNK_BYTES as u64;
        let exact_request = request(&fixture, &changes, exact_limits);
        let mut exact = ImageEvaluator::new(&exact_request, &|| false).expect("exact byte limit");
        assert_eq!(
            exact.copy_source_text(&exact_text).expect("exact text"),
            exact_text
        );
        assert_eq!(exact.steps, 1);
        assert_eq!(exact.peak_bytes, COMPTIME_SOURCE_COPY_CHUNK_BYTES as u64);

        let mut over = ImageEvaluator::new(&exact_request, &|| false).expect("over byte limit");
        assert!(matches!(
            over.copy_source_text(&over_text),
            Err(EvaluationFailure::Analysis(
                AnalysisFailure::ResourceLimit {
                    resource: "comptime evaluator bytes",
                    limit,
                }
            )) if limit == COMPTIME_SOURCE_COPY_CHUNK_BYTES as u64
        ));
        assert_eq!(over.steps, 0, "over-limit text fails before copying");
        assert_eq!(
            over.peak_bytes, 0,
            "over-limit text never publishes retention"
        );
    }

    #[test]
    fn nested_unsupported_comptime_operation_retains_callee_and_call_site() {
        const MATH: &str = "module app.math\n\npub comptime fn leaf() -> u32:\n    loop:\n        pass\n    return 0\n\npub comptime fn middle() -> u32:\n    return leaf()\n";
        const TEST: &str = "module app.math_test\n\nfrom app.math import middle\n\n@test\ncomptime fn unsupported_import():\n    value: u32 = middle()\n";
        let fixture = parsed_comptime_fixture(MATH, TEST);
        let changes = no_changes();
        let program = fixture.fixture.hir.as_program();
        let test = program.test_candidates[0];
        let declaration_named = |name: &str| {
            program
                .declarations
                .iter()
                .find(|declaration| {
                    declaration
                        .name
                        .as_ref()
                        .is_some_and(|candidate| candidate.as_str() == name)
                })
                .expect("named comptime declaration")
        };
        let leaf = declaration_named("leaf");
        let middle = declaration_named("middle");
        let function_body = |declaration: &wrela_hir::Declaration| {
            let DeclarationKind::Function(function) = &declaration.kind else {
                panic!("comptime function declaration");
            };
            program
                .body(function.body.expect("comptime body"))
                .expect("body")
        };
        let leaf_body = function_body(leaf);
        let leaf_primary = program
            .statement(leaf_body.statements[0])
            .expect("leaf statement")
            .source;
        let middle_body = function_body(middle);
        let StatementKind::Return(Some(middle_call)) = &program
            .statement(middle_body.statements[0])
            .expect("middle return")
            .kind
        else {
            panic!("middle call return");
        };
        let middle_call_source = program
            .expression(*middle_call)
            .expect("middle call expression")
            .source;
        let test_body = function_body(program.declaration(test).expect("test declaration"));
        let StatementKind::Initialize {
            value: test_call, ..
        } = &program
            .statement(test_body.statements[0])
            .expect("test initialization")
            .kind
        else {
            panic!("test call initialization");
        };
        let test_call_source = program
            .expression(*test_call)
            .expect("test call expression")
            .source;
        let request =
            parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard());
        let error = ImageEvaluator::new(&request, &|| false)
            .expect("unsupported evaluator")
            .evaluate_test(test)
            .expect_err("unsupported nested operation must fail closed");
        let EvaluationFailure::Diagnostic(diagnostic) = error else {
            panic!("unsupported operation must be a source diagnostic");
        };
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-operation-not-implemented")
        );
        assert_eq!(diagnostic.primary, leaf_primary);
        let actual: Vec<_> = diagnostic
            .labels
            .iter()
            .map(|label| (label.span, label.message.as_str()))
            .collect();
        assert_eq!(
            actual,
            [
                (
                    middle_call_source,
                    "comptime call to `app.math.leaf` entered here",
                ),
                (
                    test_call_source,
                    "comptime call to `app.math.middle` entered here",
                ),
            ]
        );
    }

    #[test]
    fn static_comptime_closure_rejects_an_untaken_unsupported_rhs_before_proof() {
        const MATH: &str = "module app.math\n\npub comptime fn unsupported() -> bool:\n    loop:\n        pass\n    return true\n";
        const TEST: &str = "module app.math_test\n\nfrom app.math import unsupported\n\n@test\ncomptime fn hidden_unsupported_rhs():\n    comptime assert true or unsupported(), \"runtime short circuit must not hide unsupported source\"\n";
        let fixture = parsed_comptime_fixture(MATH, TEST);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                parsed_comptime_discovery_request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("bounded static closure diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-comptime-operation-not-implemented")
        );
        assert!(!output.partial().proofs.iter().any(|proof| {
            proof
                .explanation
                .iter()
                .any(|line| line == SOURCE_COMPTIME_CLOSURE_PROOF_MARKER)
        }));
    }

    #[test]
    fn source_test_discovery_excludes_dependency_candidates_before_ids() {
        let fixture = mutate_fixture(ProgramKind::PassingTests, |program| {
            program.modules[0]
                .declarations
                .retain(|declaration| *declaration != DeclarationId(4));
            program.modules[1].declarations.push(DeclarationId(4));
            program.modules[1].declarations.sort_unstable();
            program.declarations[4].module = ModuleId(1);
            program.declarations[4].owner = DeclarationOwner::Module(ModuleId(1));
            program.declarations[4].source = span(1, 121, 190);
            program.declarations[4].attributes[0].source = span(1, 121, 126);
            program.bodies[2].source = span(1, 130, 185);
            program.scopes[2].source = span(1, 130, 185);
            program.statements[2].source = span(1, 140, 145);
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("root-only discovery");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed root-only discovery");
        let plan = image.facts().test_plan.as_ref().expect("root-only plan");
        assert_eq!(plan.unit_tests().len(), 1);
        assert!(plan.image_groups().is_empty());
        assert_eq!(plan.unit_tests()[0].descriptor.id, TestId(0));
        assert_eq!(image.facts().comptime_test_results.len(), 1);
    }

    #[test]
    fn failed_comptime_assertion_is_a_real_test_result_not_fake_success() {
        let fixture = fixture(ProgramKind::FailingComptimeTest);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("test discovery");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed discovery image");
        assert!(matches!(
            &image.facts().comptime_test_results[0].outcome,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message
            } if message == "unit assertion [source 0:230-270]"
        ));
    }

    #[test]
    fn unsupported_runtime_body_is_a_structured_source_error() {
        let fixture = fixture(ProgramKind::UnsupportedRuntimeTest);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("diagnostic discovery");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-runtime-test-body-not-supported")
        );
        assert_eq!(output.diagnostics()[0].primary, span(0, 340, 342));
    }

    #[test]
    fn loops_awaits_closures_and_actor_sends_fail_closed() {
        for case in 0..4 {
            let fixture =
                mutate_fixture(ProgramKind::UnsupportedRuntimeTest, |program| match case {
                    0 => {
                        program.expressions.pop();
                        program.statements[2].kind = StatementKind::Loop { body: BodyId(3) };
                        program.bodies.push(Body {
                            id: BodyId(3),
                            owner: BodyOwner::Declaration(DeclarationId(4)),
                            scope: wrela_hir::ScopeId(3),
                            locals: Vec::new(),
                            statements: vec![StatementId(3)],
                            source: span(0, 340, 360),
                        });
                        program.scopes.push(LexicalScope {
                            id: wrela_hir::ScopeId(3),
                            body: BodyId(3),
                            parent: Some(wrela_hir::ScopeId(2)),
                            source: span(0, 340, 360),
                        });
                        program.statements.push(Statement {
                            id: StatementId(3),
                            body: BodyId(3),
                            attributes: Vec::new(),
                            kind: StatementKind::Pass,
                            source: span(0, 345, 350),
                        });
                    }
                    1 => {
                        program.expressions[5].kind = ExpressionKind::Unary {
                            operator: wrela_hir::UnaryOperator::Await,
                            operand: ExpressionId(6),
                        };
                        program.expressions.push(Expression {
                            id: ExpressionId(6),
                            owner: ExpressionOwner::Body(BodyId(2)),
                            scope: Some(wrela_hir::ScopeId(2)),
                            kind: ExpressionKind::Literal(Literal::Unit),
                            source: span(0, 341, 342),
                        });
                    }
                    2 => {
                        program.expressions[5].kind = ExpressionKind::Closure {
                            color: FunctionColor::Sync,
                            take_captures: false,
                            parameters: Vec::new(),
                            body: wrela_hir::ClosureBody::Expression(ExpressionId(6)),
                            captures: Vec::new(),
                        };
                        program.expressions.push(Expression {
                            id: ExpressionId(6),
                            owner: ExpressionOwner::Closure(ExpressionId(5)),
                            scope: None,
                            kind: ExpressionKind::Literal(Literal::Unit),
                            source: span(0, 341, 342),
                        });
                    }
                    3 => {
                        program.statements[2].kind = StatementKind::Send(ExpressionId(5));
                    }
                    _ => unreachable!(),
                });
            let changes = no_changes();
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(discovery_request(&fixture, &changes), &|| false)
                .expect("closed unsupported runtime diagnostic");
            assert!(output.successful().is_none());
            assert_eq!(output.diagnostics().len(), 1);
            assert_eq!(
                output.diagnostics()[0].code.as_deref(),
                Some("semantic-runtime-test-body-not-supported")
            );
            assert_eq!(
                output.diagnostics()[0].primary,
                if matches!(case, 1..=3) {
                    span(0, 340, 342)
                } else {
                    span(0, 330, 370)
                }
            );
        }
    }

    #[test]
    fn generated_group_compilation_is_bound_to_plan_group_and_function_keys() {
        let fixture = fixture(ProgramKind::PassingTests);
        let changes = no_changes();
        let discovery_output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("test discovery");
        let discovery = discovery_output.successful().expect("sealed discovery");
        let plan = discovery.facts().test_plan.as_ref().expect("plan");
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan,
            group: ImageGroupId(0),
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("group compilation");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed group image");
        assert!(matches!(
            image.facts().root,
            AnalysisRoot::GeneratedTestHarness {
                group: ImageGroupId(0),
                ..
            }
        ));
        let graph = image.facts().graph.as_ref().expect("graph");
        let entry = &image.facts().functions[graph.entry.0 as usize];
        assert!(matches!(
            entry.origin,
            FunctionOrigin::GeneratedTestHarness {
                group: ImageGroupId(0)
            }
        ));
        let selected_key = match plan.image_groups()[0].tests[0].invocation {
            ImageTestInvocation::GeneratedFunction { function_key } => function_key,
            ImageTestInvocation::DeclaredScenario => panic!("generated invocation"),
        };
        assert!(image.facts().functions.iter().any(|function| {
            function.role == FunctionRole::Test && function.key == selected_key
        }));
        assert!(image.facts().test_plan.is_none());
        assert!(image.facts().comptime_test_results.is_empty());
    }

    #[test]
    fn scalar_runtime_body_emits_exact_local_call_and_no_phi_facts() {
        let fixture = fixture(ProgramKind::ScalarRuntimeTest);
        let changes = no_changes();
        let discovery_output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("scalar test discovery");
        assert!(discovery_output.diagnostics().is_empty());
        let plan = discovery_output
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("scalar test plan")
            .clone();
        let group = plan.image_groups()[0].id;
        let mut bounded_limits = AnalysisLimits::standard();
        bounded_limits.expression_facts = 6;
        let mut bounded = request(&fixture, &changes, bounded_limits);
        bounded.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(bounded, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "expression facts",
                ..
            })
        ));
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("scalar group analysis");
        assert!(output.diagnostics().is_empty());
        let image = output.successful().expect("sealed scalar group");
        let facts = image.facts();
        assert_eq!(facts.functions.len(), 3);
        assert_eq!(facts.functions[0].role, FunctionRole::Test);
        assert_eq!(facts.functions[1].role, FunctionRole::Ordinary);
        assert_eq!(facts.functions[2].role, FunctionRole::ImageEntry);
        assert!(
            facts
                .types
                .iter()
                .any(|ty| ty.kind == SemanticTypeKind::Bool)
        );
        assert!(facts.types.iter().any(|ty| {
            ty.kind
                == (SemanticTypeKind::Integer {
                    signed: false,
                    bits: 32,
                    pointer_sized: false,
                })
        }));
        assert_eq!(facts.values.len(), 5);
        assert_eq!(
            facts.values[0].origin,
            SemanticValueOrigin::Local(LocalId(0))
        );
        assert_eq!(
            facts.values[1].origin,
            SemanticValueOrigin::Local(LocalId(1))
        );
        assert_eq!(
            facts.values[2].origin,
            SemanticValueOrigin::Parameter(wrela_hir::ParameterId(0))
        );
        assert_eq!(
            facts.values[3].origin,
            SemanticValueOrigin::Local(LocalId(2))
        );
        assert_eq!(
            facts.values[4].origin,
            SemanticValueOrigin::Expression(ExpressionId(8))
        );
        let call = facts
            .expressions
            .iter()
            .find(|fact| {
                fact.function == FunctionInstanceId(0) && fact.expression == ExpressionId(8)
            })
            .expect("direct call fact");
        assert_eq!(call.region, None);
        assert_eq!(call.result, Some(ValueId(4)));
        assert!(matches!(
            &call.resolution,
            ExpressionResolution::DirectCall {
                function: FunctionInstanceId(1),
                arguments,
            } if arguments.as_slice() == [ResolvedCallArgument {
                source_index: 0,
                parameter_index: 0,
                access: super::AccessMode::Value,
                value: ValueId(1),
            }]
        ));
        assert!(matches!(
            facts.statements.iter().find(|fact| fact.statement == StatementId(2)),
            Some(StatementFact { definitions, .. })
                if definitions.as_slice() == [LocalDefinition {
                    local: LocalId(0),
                    value: ValueId(0),
                }]
        ));
        assert_eq!(
            facts.functions[1].parameters[0].parameter,
            wrela_hir::ParameterId(0)
        );
        assert_eq!(
            facts
                .compiled_test_group
                .as_ref()
                .map(|group| group.tests.len()),
            Some(1)
        );

        let exact_expression_facts =
            u32::try_from(facts.expressions.len()).expect("bounded expression fact count");
        let mut exact_limits = AnalysisLimits::standard();
        exact_limits.expression_facts = exact_expression_facts;
        let mut exact = request(&fixture, &changes, exact_limits);
        exact.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        assert!(
            CanonicalSemanticAnalyzer::new()
                .analyze(exact, &|| false)
                .expect("exact expression limit")
                .successful()
                .is_some()
        );
        let mut below_limits = AnalysisLimits::standard();
        below_limits.expression_facts = exact_expression_facts - 1;
        let mut below = request(&fixture, &changes, below_limits);
        below.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(below, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "expression facts",
                ..
            })
        ));

        let (hir, mut substituted) = image.clone().into_parts();
        let call = substituted
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(8))
            .expect("mutable call fact");
        let ExpressionResolution::DirectCall { arguments, .. } = &mut call.resolution else {
            unreachable!();
        };
        arguments[0].source_index = 1;
        assert!(
            substituted
                .validate_for_seal(hir.as_ref(), &|| false)
                .is_err()
        );

        let mut wrong_local = facts.clone();
        wrong_local
            .statements
            .iter_mut()
            .find(|fact| fact.statement == StatementId(2))
            .expect("local definition fact")
            .definitions[0]
            .value = ValueId(1);
        assert!(
            wrong_local
                .validate_for_seal(image.hir(), &|| false)
                .is_err()
        );

        let mut missing_result = facts.clone();
        missing_result
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(8))
            .expect("call result fact")
            .result = None;
        assert!(
            missing_result
                .validate_for_seal(image.hir(), &|| false)
                .is_err()
        );
        assert!(matches!(
            facts.validate_for_seal(image.hir(), &|| true),
            Err(AnalysisFailure::Cancelled)
        ));
    }

    #[test]
    fn scalar_operators_and_checked_casts_produce_exact_sealed_facts() {
        let unary_cases = [
            (
                wrela_hir::UnaryOperator::Negate,
                Builtin::I32,
                Literal::Integer("7".to_owned()),
            ),
            (
                wrela_hir::UnaryOperator::Negate,
                Builtin::F64,
                Literal::Float("1.5".to_owned()),
            ),
            (
                wrela_hir::UnaryOperator::BitNot,
                Builtin::U32,
                Literal::Integer("7".to_owned()),
            ),
            (
                wrela_hir::UnaryOperator::BoolNot,
                Builtin::Bool,
                Literal::Boolean(true),
            ),
        ];
        for (operator, ty, argument) in unary_cases {
            let fixture = mutate_scalar_fixture(|program| {
                configure_scalar_helper_types(program, ty, ty, argument);
                program.expressions[11].kind = ExpressionKind::Unary {
                    operator,
                    operand: ExpressionId(13),
                };
                program.expressions.push(scalar_operand_expression(13));
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            let fact = image
                .facts()
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(11))
                .expect("unary fact");
            assert!(matches!(
                fact,
                ExpressionFact {
                    resolution: ExpressionResolution::Value(value),
                    result: Some(result),
                    effects: EffectSet(0),
                    ownership_before: OwnershipState::Owned,
                    ownership_after: OwnershipState::Owned,
                    ..
                } if value == result
            ));
        }

        let binary_operators = [
            wrela_hir::BinaryOperator::Add,
            wrela_hir::BinaryOperator::AddWrapping,
            wrela_hir::BinaryOperator::Subtract,
            wrela_hir::BinaryOperator::SubtractWrapping,
            wrela_hir::BinaryOperator::Multiply,
            wrela_hir::BinaryOperator::MultiplyWrapping,
            wrela_hir::BinaryOperator::Divide,
            wrela_hir::BinaryOperator::Remainder,
            wrela_hir::BinaryOperator::BitOr,
            wrela_hir::BinaryOperator::BitXor,
            wrela_hir::BinaryOperator::BitAnd,
            wrela_hir::BinaryOperator::ShiftLeft,
            wrela_hir::BinaryOperator::ShiftLeftModular,
            wrela_hir::BinaryOperator::ShiftRight,
        ];
        for operator in binary_operators {
            let fixture = mutate_scalar_fixture(|program| {
                configure_scalar_helper_types(
                    program,
                    Builtin::U32,
                    Builtin::U32,
                    Literal::Integer("7".to_owned()),
                );
                program.expressions[11].kind = ExpressionKind::Binary {
                    operator,
                    left: ExpressionId(13),
                    right: ExpressionId(14),
                };
                program
                    .expressions
                    .extend([scalar_operand_expression(13), scalar_operand_expression(14)]);
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            assert!(
                image
                    .facts()
                    .expressions
                    .iter()
                    .any(|fact| fact.expression == ExpressionId(11))
            );
        }

        let comparisons = [
            wrela_hir::ComparisonOperator::Equal,
            wrela_hir::ComparisonOperator::NotEqual,
            wrela_hir::ComparisonOperator::Less,
            wrela_hir::ComparisonOperator::LessEqual,
            wrela_hir::ComparisonOperator::Greater,
            wrela_hir::ComparisonOperator::GreaterEqual,
        ];
        for operator in comparisons {
            let fixture = mutate_scalar_fixture(|program| {
                configure_scalar_helper_types(
                    program,
                    Builtin::U32,
                    Builtin::Bool,
                    Literal::Integer("7".to_owned()),
                );
                program.expressions[11].kind = ExpressionKind::Compare {
                    left: ExpressionId(13),
                    operator,
                    right: ExpressionId(14),
                };
                program
                    .expressions
                    .extend([scalar_operand_expression(13), scalar_operand_expression(14)]);
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            let fact = image
                .facts()
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(11))
                .expect("comparison fact");
            assert!(matches!(
                image.facts().types[fact.ty.0 as usize].kind,
                SemanticTypeKind::Bool
            ));
        }

        let fixture = mutate_scalar_fixture(|program| {
            configure_scalar_helper_types(
                program,
                Builtin::U32,
                Builtin::U64,
                Literal::Integer("7".to_owned()),
            );
            program.expressions[11].kind = ExpressionKind::Cast {
                value: ExpressionId(13),
                ty: scalar_type(Builtin::U64, span(0, 433, 436)),
            };
            program.expressions.push(scalar_operand_expression(13));
        });
        let image = analyze_compiled_scalar_fixture(&fixture);
        let cast = image
            .facts()
            .expressions
            .iter()
            .find(|fact| fact.expression == ExpressionId(11))
            .expect("cast fact");
        assert!(matches!(
            image.facts().types[cast.ty.0 as usize].kind,
            SemanticTypeKind::Integer {
                signed: false,
                bits: 64,
                pointer_sized: false,
            }
        ));

        let mut corrupt_effect = image.facts().clone();
        corrupt_effect
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(11))
            .expect("mutable cast fact")
            .effects = EffectSet(EffectSet::MAY_FAIL);
        assert!(
            corrupt_effect
                .validate_for_seal(image.hir(), &|| false)
                .is_err()
        );
    }

    #[test]
    fn compound_assignments_define_fresh_statement_values_for_all_checked_operators_and_integers() {
        let operators = [
            AssignmentOperator::Add,
            AssignmentOperator::Subtract,
            AssignmentOperator::Multiply,
            AssignmentOperator::Divide,
            AssignmentOperator::Remainder,
            AssignmentOperator::BitAnd,
            AssignmentOperator::BitOr,
            AssignmentOperator::BitXor,
            AssignmentOperator::ShiftLeft,
            AssignmentOperator::ShiftRight,
        ];
        for operator in operators {
            let fixture = mutate_scalar_fixture(|program| {
                configure_compound_assignment_fixture(program, operator, false);
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            let facts = image.facts();
            let previous = facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(3))
                .and_then(|fact| fact.definitions.first())
                .map(|definition| definition.value)
                .expect("initialized compound target");
            let definition = facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(7))
                .and_then(|fact| fact.definitions.first())
                .copied()
                .expect("compound assignment definition");
            let rhs = facts
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(8))
                .expect("compound RHS fact");
            assert_eq!(definition.local, LocalId(1));
            assert_ne!(definition.value, previous);
            assert_ne!(rhs.result, Some(definition.value));
            assert!(matches!(
                facts.values[definition.value.0 as usize].origin,
                SemanticValueOrigin::Local(LocalId(1))
            ));
            assert!(!facts.expressions.iter().any(|expression| {
                expression.function == rhs.function && expression.result == Some(definition.value)
            }));
            let join = facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(4))
                .and_then(|fact| fact.definitions.first())
                .map(|definition| definition.value)
                .expect("compound branch join");
            assert_ne!(join, previous);
            assert_ne!(join, definition.value);

            let rhs_result = rhs.result.expect("call RHS result");
            let mut forged = facts.clone();
            forged
                .statements
                .iter_mut()
                .find(|fact| fact.statement == StatementId(7))
                .and_then(|fact| fact.definitions.first_mut())
                .expect("mutable compound definition")
                .value = rhs_result;
            assert!(forged.validate_for_seal(image.hir(), &|| false).is_err());
        }

        let integer_types = [
            Builtin::U8,
            Builtin::U16,
            Builtin::U32,
            Builtin::U64,
            Builtin::U128,
            Builtin::Usize,
            Builtin::I8,
            Builtin::I16,
            Builtin::I32,
            Builtin::I64,
            Builtin::I128,
            Builtin::Isize,
        ];
        for ty in integer_types {
            let fixture = mutate_scalar_fixture(|program| {
                configure_scalar_helper_types(program, ty, ty, Literal::Integer("7".to_owned()));
                configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            assert!(
                image.facts().statements.iter().any(|fact| {
                    fact.statement == StatementId(7) && fact.definitions.len() == 1
                })
            );
        }
    }

    #[test]
    fn compound_assignments_reject_overlap_non_integer_projected_multi_and_taken_targets() {
        let changes = no_changes();
        let diagnostic = |fixture: &Fixture| {
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(discovery_request(fixture, &changes), &|| false)
                .expect("compound assignment diagnostic is recoverable");
            assert!(output.successful().is_none());
            assert_eq!(output.diagnostics().len(), 1);
            output.diagnostics()[0].clone()
        };

        let overlap = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, true);
        });
        let overlap = diagnostic(&overlap);
        assert_eq!(overlap.code.as_deref(), Some("semantic-compound-overlap"));
        assert_eq!(overlap.primary, span(0, 363, 364));

        let non_integer = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
            let StatementKind::Assign { targets, .. } = &mut program.statements[7].kind else {
                unreachable!();
            };
            targets[0].root = Definition::Local(LocalId(0));
        });
        assert_eq!(
            diagnostic(&non_integer).code.as_deref(),
            Some("semantic-compound-assignment-type")
        );

        let mismatched_rhs = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
            program.expressions[10].kind = ExpressionKind::Literal(Literal::Boolean(true));
        });
        assert_eq!(
            diagnostic(&mismatched_rhs).code.as_deref(),
            Some("semantic-literal-type-mismatch")
        );

        let projected = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
            let StatementKind::Assign { targets, .. } = &mut program.statements[7].kind else {
                unreachable!();
            };
            targets[0]
                .projections
                .push(wrela_hir::PlaceProjection::Tuple(0));
        });
        assert_eq!(
            diagnostic(&projected).code.as_deref(),
            Some("semantic-assignment-form")
        );

        let multi = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
            let StatementKind::Assign { targets, .. } = &mut program.statements[7].kind else {
                unreachable!();
            };
            targets.push(wrela_hir::PlaceTarget {
                root: Definition::Local(LocalId(0)),
                projections: Vec::new(),
                source: span(0, 357, 358),
            });
        });
        assert_eq!(
            diagnostic(&multi).code.as_deref(),
            Some("semantic-assignment-target")
        );

        let taken = mutate_scalar_fixture(|program| {
            set_scalar_call_access(program, AccessMode::Take);
            let rhs = ExpressionId(program.expressions.len() as u32);
            program.bodies[4].statements.push(StatementId(9));
            program.statements.push(Statement {
                id: StatementId(9),
                body: BodyId(4),
                attributes: Vec::new(),
                kind: StatementKind::Assign {
                    targets: vec![wrela_hir::PlaceTarget {
                        root: Definition::Local(LocalId(1)),
                        projections: Vec::new(),
                        source: span(0, 376, 377),
                    }],
                    operator: AssignmentOperator::Add,
                    value: rhs,
                },
                source: span(0, 376, 380),
            });
            program.expressions.push(Expression {
                id: rhs,
                owner: ExpressionOwner::Body(BodyId(4)),
                scope: Some(wrela_hir::ScopeId(4)),
                kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                source: span(0, 379, 380),
            });
        });
        assert_eq!(
            diagnostic(&taken).code.as_deref(),
            Some("semantic-assignment-ownership")
        );
    }

    #[test]
    fn compound_assignment_enforces_exact_value_limit_and_late_cancellation() {
        let fixture = mutate_scalar_fixture(|program| {
            configure_compound_assignment_fixture(program, AssignmentOperator::Add, false);
        });
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("compound assignment discovery");
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("compound assignment test plan")
            .clone();
        let group = plan.image_groups()[0].id;
        let compile = |limits, is_cancelled: &dyn Fn() -> bool| {
            let mut request = request(&fixture, &changes, limits);
            request.mode = AnalysisMode::CompileTestGroup {
                plan: &plan,
                group,
                declared_entry: None,
            };
            CanonicalSemanticAnalyzer::new().analyze(request, is_cancelled)
        };
        let baseline = compile(AnalysisLimits::standard(), &|| false)
            .expect("baseline compound assignment analysis");
        let value_count = u32::try_from(
            baseline
                .successful()
                .expect("sealed compound assignment baseline")
                .facts()
                .values
                .len(),
        )
        .expect("bounded compound semantic values");
        let mut exact = AnalysisLimits::standard();
        exact.values = value_count;
        assert!(
            compile(exact, &|| false)
                .expect("exact compound semantic value limit")
                .successful()
                .is_some()
        );
        let mut below = exact;
        below.values = value_count - 1;
        assert!(matches!(
            compile(below, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic values",
                ..
            })
        ));

        let polls = Cell::new(0_u32);
        compile(exact, &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("count compound cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            compile(exact, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == cancel_at
            }),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scalar_if_else_assignments_produce_exact_join_values_for_every_scalar_type() {
        let cases = [
            (Builtin::Unit, Literal::Unit, Literal::Unit, Literal::Unit),
            (
                Builtin::Bool,
                Literal::Boolean(false),
                Literal::Boolean(true),
                Literal::Boolean(false),
            ),
            (
                Builtin::U8,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::U16,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::U64,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::U128,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::Usize,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::I8,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::I16,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::I32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::I64,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::I128,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::Isize,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            ),
            (
                Builtin::F32,
                Literal::Float("1.0".to_owned()),
                Literal::Float("2.0".to_owned()),
                Literal::Float("3.0".to_owned()),
            ),
            (
                Builtin::F64,
                Literal::Float("1.0".to_owned()),
                Literal::Float("2.0".to_owned()),
                Literal::Float("3.0".to_owned()),
            ),
        ];
        for (ty, initial, then_value, else_value) in cases {
            let fixture = mutate_scalar_fixture(|program| {
                configure_scalar_join_fixture(program, ty, initial, then_value, else_value);
            });
            let image = analyze_compiled_scalar_fixture(&fixture);
            let join = image
                .facts()
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(4))
                .expect("if statement fact");
            let [definition] = join.definitions.as_slice() else {
                panic!("one exact scalar join definition")
            };
            assert_eq!(definition.local, LocalId(1));
            let reference = image
                .facts()
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(10))
                .expect("post-join reference fact");
            assert!(matches!(
                reference,
                ExpressionFact {
                    resolution: ExpressionResolution::Value(value),
                    result: None,
                    effects: EffectSet(0),
                    ..
                } if *value == definition.value
            ));
            let incoming = [StatementId(7), StatementId(9)].map(|statement| {
                image
                    .facts()
                    .statements
                    .iter()
                    .find(|fact| fact.statement == statement)
                    .and_then(|fact| fact.definitions.first())
                    .map(|definition| definition.value)
                    .expect("branch assignment definition")
            });
            assert_ne!(incoming[0], incoming[1]);
            assert_ne!(definition.value, incoming[0]);
            assert_ne!(definition.value, incoming[1]);
        }

        let fixture = mutate_scalar_fixture(|program| {
            configure_scalar_join_fixture(
                program,
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            );
        });
        let image = analyze_compiled_scalar_fixture(&fixture);
        let join = image
            .facts()
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(4))
            .and_then(|fact| fact.definitions.first())
            .map(|definition| definition.value)
            .expect("join definition");
        let incoming = image
            .facts()
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(7))
            .and_then(|fact| fact.definitions.first())
            .map(|definition| definition.value)
            .expect("then assignment definition");
        let mut substituted = image.facts().clone();
        substituted.values[join.0 as usize].ty = SemanticTypeId(1);
        assert!(
            substituted
                .validate_for_seal(image.hir(), &|| false)
                .is_err()
        );

        let mut wrong_reaching_value = image.facts().clone();
        let post_join = wrong_reaching_value
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(10))
            .expect("mutable post-join reference");
        post_join.resolution = ExpressionResolution::Value(incoming);
        assert!(
            wrong_reaching_value
                .validate_for_seal(image.hir(), &|| false)
                .is_err()
        );

        let fixture = mutate_scalar_fixture(|program| {
            configure_scalar_join_fixture(
                program,
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            );
            program.parameters[0].access = AccessMode::Mutate;
            program.expressions[10].kind = ExpressionKind::Call {
                callee: ExpressionId(13),
                arguments: vec![CallArgument {
                    name: Some(name("x")),
                    value: wrela_hir::CallArgumentValue::Exclusive {
                        access: wrela_hir::ExclusiveAccess::Mutate,
                        place: wrela_hir::PlaceTarget {
                            root: Definition::Local(LocalId(1)),
                            projections: Vec::new(),
                            source: span(0, 385, 386),
                        },
                    },
                    source: span(0, 385, 386),
                }],
            };
            program.expressions[10].source = span(0, 384, 387);
            program.statements[5].source = span(0, 384, 387);
            program.expressions.push(Expression {
                id: ExpressionId(13),
                owner: ExpressionOwner::Body(BodyId(2)),
                scope: Some(wrela_hir::ScopeId(2)),
                kind: ExpressionKind::Reference(Definition::Declaration(ResolvedDeclaration {
                    package: PackageId(0),
                    module: ModuleId(0),
                    declaration: DeclarationId(5),
                })),
                source: span(0, 384, 385),
            });
        });
        let image = analyze_compiled_scalar_fixture(&fixture);
        let current = image
            .facts()
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(4))
            .and_then(|fact| fact.definitions.first())
            .map(|definition| definition.value)
            .expect("joined reaching value");
        let stale = image
            .facts()
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(7))
            .and_then(|fact| fact.definitions.first())
            .map(|definition| definition.value)
            .expect("stale branch value");
        assert_ne!(current, stale);
        let mut forged = image.facts().clone();
        let binding = forged
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(10))
            .and_then(|fact| match &mut fact.resolution {
                ExpressionResolution::DirectCall { arguments, .. } => arguments.first_mut(),
                _ => None,
            })
            .expect("exclusive post-join binding");
        assert_eq!(binding.value, current);
        binding.value = stale;
        assert!(forged.validate_for_seal(image.hir(), &|| false).is_err());
    }

    #[test]
    fn nested_scalar_assignments_join_inner_result_into_outer_result_exactly() {
        let fixture = mutate_scalar_fixture(configure_nested_scalar_join_fixture);
        let image = analyze_compiled_scalar_fixture(&fixture);
        let facts = image.facts();
        let inner = facts
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(7))
            .and_then(|fact| fact.definitions.first())
            .copied()
            .expect("inner scalar join");
        let outer = facts
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(4))
            .and_then(|fact| fact.definitions.first())
            .copied()
            .expect("outer scalar join");
        let outer_else = facts
            .statements
            .iter()
            .find(|fact| fact.statement == StatementId(9))
            .and_then(|fact| fact.definitions.first())
            .copied()
            .expect("outer else assignment");
        assert_eq!(inner.local, LocalId(1));
        assert_eq!(outer.local, LocalId(1));
        assert_eq!(outer_else.local, LocalId(1));
        assert_ne!(inner.value, outer_else.value);
        assert_ne!(outer.value, inner.value);
        assert_ne!(outer.value, outer_else.value);
        assert!(matches!(
            facts
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(10)),
            Some(ExpressionFact {
                resolution: ExpressionResolution::Value(value),
                ..
            }) if *value == outer.value
        ));
    }

    #[test]
    fn scalar_join_rejects_uninitialized_targets_and_mismatched_branch_values() {
        let uninitialized = mutate_scalar_fixture(|program| {
            configure_scalar_join_fixture(
                program,
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            );
            program.statements[3].kind = StatementKind::Expression(ExpressionId(6));
            program.statements[5].kind = StatementKind::Initialize {
                local: LocalId(1),
                value: ExpressionId(10),
            };
            program.statements[5].source = span(0, 331, 386);
            program.expressions[10].kind =
                ExpressionKind::Literal(Literal::Integer("0".to_owned()));
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&uninitialized, &changes), &|| false)
            .expect("uninitialized scalar assignment diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-assignment-uninitialized")
        );

        let mismatched = mutate_scalar_fixture(|program| {
            configure_scalar_join_fixture(
                program,
                Builtin::U32,
                Literal::Integer("1".to_owned()),
                Literal::Integer("2".to_owned()),
                Literal::Integer("3".to_owned()),
            );
            program.expressions[9].kind = ExpressionKind::Literal(Literal::Boolean(false));
        });
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&mismatched, &changes), &|| false)
            .expect("mismatched scalar assignment diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-literal-type-mismatch")
        );
    }

    #[test]
    fn scalar_join_enforces_exact_value_limit_max_plus_one_and_late_cancellation() {
        let fixture = mutate_scalar_fixture(configure_nested_scalar_join_fixture);
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("nested join discovery");
        assert!(discovery.diagnostics().is_empty());
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("nested join plan")
            .clone();
        let group = plan.image_groups()[0].id;
        let compile = |limits, is_cancelled: &dyn Fn() -> bool| {
            let mut request = request(&fixture, &changes, limits);
            request.mode = AnalysisMode::CompileTestGroup {
                plan: &plan,
                group,
                declared_entry: None,
            };
            CanonicalSemanticAnalyzer::new().analyze(request, is_cancelled)
        };
        let baseline =
            compile(AnalysisLimits::standard(), &|| false).expect("baseline nested join analysis");
        let value_count = u32::try_from(
            baseline
                .successful()
                .expect("sealed baseline nested join")
                .facts()
                .values
                .len(),
        )
        .expect("bounded semantic value count");
        let mut exact = AnalysisLimits::standard();
        exact.values = value_count;
        assert!(
            compile(exact, &|| false)
                .expect("exact semantic value limit")
                .successful()
                .is_some()
        );
        let mut below = exact;
        below.values = value_count - 1;
        assert!(matches!(
            compile(below, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic values",
                ..
            })
        ));

        let polls = Cell::new(0_u32);
        compile(exact, &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("count nested join cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            compile(exact, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == cancel_at
            }),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scalar_operator_type_errors_are_structured_and_fail_closed() {
        let fixture = mutate_scalar_fixture(|program| {
            configure_scalar_helper_types(
                program,
                Builtin::Bool,
                Builtin::Bool,
                Literal::Boolean(true),
            );
            program.expressions[11].kind = ExpressionKind::Unary {
                operator: wrela_hir::UnaryOperator::BitNot,
                operand: ExpressionId(13),
            };
            program.expressions.push(scalar_operand_expression(13));
        });
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("invalid scalar discovery is recoverable");
        assert!(discovery.successful().is_none());
        assert_eq!(discovery.diagnostics().len(), 1);
        assert_eq!(
            discovery.diagnostics()[0].code.as_deref(),
            Some("semantic-unary-type")
        );
        assert_eq!(discovery.diagnostics()[0].primary, span(0, 430, 436));

        let modular_bool = mutate_scalar_fixture(|program| {
            configure_scalar_helper_types(
                program,
                Builtin::Bool,
                Builtin::Bool,
                Literal::Boolean(true),
            );
            program.expressions[11].kind = ExpressionKind::Binary {
                operator: wrela_hir::BinaryOperator::ShiftLeftModular,
                left: ExpressionId(13),
                right: ExpressionId(14),
            };
            program
                .expressions
                .extend([scalar_operand_expression(13), scalar_operand_expression(14)]);
        });
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&modular_bool, &changes), &|| false)
            .expect("invalid modular shift discovery is recoverable");
        assert!(discovery.successful().is_none());
        assert_eq!(discovery.diagnostics().len(), 1);
        assert_eq!(
            discovery.diagnostics()[0].code.as_deref(),
            Some("semantic-binary-type")
        );
        assert_eq!(discovery.diagnostics()[0].primary, span(0, 430, 436));
    }

    #[test]
    fn declared_scenario_is_merged_and_compiles_the_exact_declared_root() {
        let fixture = fixture(ProgramKind::PassingTests);
        let changes = no_changes();
        let declared = [DeclaredImageTest {
            name: "boots".to_owned(),
            image_name: "runtime-image".to_owned(),
            scenario: ImageScenario {
                id: wrela_test_model::ScenarioId(0),
                schema: wrela_test_model::IMAGE_SCENARIO_SCHEMA,
                name: "boots".to_owned(),
                source_path: "fixtures/boots.toml".to_owned(),
                digest: Sha256Digest::from_bytes([0x44; 32]),
                steps: vec![wrela_test_model::ImageScenarioStep::ExpectExit {
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
        let mut discover = request(&fixture, &changes, AnalysisLimits::standard());
        discover.mode = AnalysisMode::DiscoverTests {
            image_name: "runtime-image",
            image_entry: DeclarationId(0),
            declared_image_tests: &declared,
            source_selection: TestDiscoverySelection::All,
        };
        let discovery_output = CanonicalSemanticAnalyzer::new()
            .analyze(discover, &|| false)
            .expect("test discovery");
        let discovery = discovery_output.successful().expect("sealed discovery");
        let plan = discovery.facts().test_plan.as_ref().expect("plan");
        let declared_group = plan
            .image_groups()
            .iter()
            .find(|group| matches!(group.root, ImageRoot::Declared { .. }))
            .expect("declared group");
        assert_eq!(declared_group.name, "boots");
        assert_eq!(declared_group.tests[0].descriptor.timeout_ns, 60);
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan,
            group: declared_group.id,
            declared_entry: Some(DeclarationId(0)),
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("declared group compilation");
        let image = output.successful().expect("sealed declared image");
        assert!(matches!(
            image.facts().root,
            AnalysisRoot::DeclaredImage {
                declaration: DeclarationId(0),
                test_group: Some(actual),
                ..
            } if actual == declared_group.id
        ));
        assert_eq!(
            image.facts().graph.as_ref().expect("graph").name,
            "runtime-image"
        );
    }

    #[test]
    fn unsupported_comptime_operations_produce_a_stable_partial_diagnostic() {
        let fixture = fixture(ProgramKind::UnsupportedCallee);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("diagnostic result");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-comptime-operation-not-implemented")
        );
    }

    #[test]
    fn evaluator_limits_and_cancellation_are_hard_failures() {
        let fixture = fixture(ProgramKind::MinimumImage);
        let changes = no_changes();
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_steps = 1;
        assert!(matches!(
            CanonicalSemanticAnalyzer::new()
                .analyze(request(&fixture, &changes, limits), &|| false,),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime evaluator steps",
                limit: 1
            })
        ));
        let mut limits = AnalysisLimits::standard();
        limits.fact_bytes = 4;
        assert!(matches!(
            CanonicalSemanticAnalyzer::new()
                .analyze(request(&fixture, &changes, limits), &|| false,),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic fact bytes",
                limit: 4
            })
        ));
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(
                request(&fixture, &changes, AnalysisLimits::standard()),
                &|| true,
            ),
            Err(AnalysisFailure::Cancelled)
        ));

        let output = CanonicalSemanticAnalyzer::new()
            .analyze(
                request(&fixture, &changes, AnalysisLimits::standard()),
                &|| false,
            )
            .expect("initial semantic analysis");
        let (product, diagnostics) = output.into_parts();
        let partial = product.expect("complete analysis").into_facts();
        let polls = Cell::new(0u32);
        let cancel_during_seal = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert!(matches!(
            finish_analysis(
                &request(&fixture, &changes, AnalysisLimits::standard()),
                partial,
                diagnostics,
                &cancel_during_seal,
            ),
            Err(AnalysisFailure::Cancelled)
        ));
        assert!(polls.get() >= 3);
    }

    #[test]
    fn scalar_mutate_access_preserves_owned_state_across_a_conditional() {
        let fixture = mutate_scalar_fixture(|program| {
            set_scalar_call_access(program, AccessMode::Mutate);
        });
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("mutate discovery");
        assert!(discovery.diagnostics().is_empty());
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("mutate test plan")
            .clone();
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group: plan.image_groups()[0].id,
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("mutate compile");
        let facts = output.successful().expect("mutate image").facts();
        let argument = facts
            .expressions
            .iter()
            .find(|fact| fact.expression == ExpressionId(10))
            .expect("mutable argument fact");
        assert_eq!(argument.ownership_before, OwnershipState::Owned);
        assert_eq!(argument.ownership_after, OwnershipState::Owned);
        assert!(
            facts
                .statements
                .iter()
                .all(|fact| fact.moved_after.is_empty())
        );
        assert!(matches!(
            &facts
                .expressions
                .iter()
                .find(|fact| fact.expression == ExpressionId(8))
                .expect("mutable call fact")
                .resolution,
            ExpressionResolution::DirectCall { arguments, .. }
                if arguments[0].access == super::AccessMode::Mutate
        ));
    }

    #[test]
    fn reordered_named_same_type_arguments_retain_exact_source_identity() {
        let fixture = mutate_scalar_fixture(add_reordered_same_type_read_argument);
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("same-type discovery");
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("same-type plan")
            .clone();
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group: plan.image_groups()[0].id,
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("same-type compile");
        let image = output.successful().expect("same-type image");
        let call = image
            .facts()
            .expressions
            .iter()
            .find(|fact| fact.expression == ExpressionId(8))
            .expect("same-type call");
        assert!(matches!(
            &call.resolution,
            ExpressionResolution::DirectCall { arguments, .. }
                if arguments.as_slice() == [
                    ResolvedCallArgument {
                        source_index: 1,
                        parameter_index: 0,
                        access: super::AccessMode::Value,
                        value: ValueId(1),
                    },
                    ResolvedCallArgument {
                        source_index: 0,
                        parameter_index: 1,
                        access: super::AccessMode::Read,
                        value: ValueId(1),
                    },
                ]
        ));

        let (hir, mut substituted) = image.clone().into_parts();
        let call = substituted
            .expressions
            .iter_mut()
            .find(|fact| fact.expression == ExpressionId(8))
            .expect("mutable same-type call");
        let ExpressionResolution::DirectCall { arguments, .. } = &mut call.resolution else {
            unreachable!();
        };
        arguments[0].source_index = 0;
        arguments[1].source_index = 1;
        assert!(
            substituted
                .validate_for_seal(hir.as_ref(), &|| false)
                .is_err()
        );
    }

    #[test]
    fn one_call_cannot_alias_read_and_mutate_access_to_the_same_value() {
        let fixture = mutate_scalar_fixture(|program| {
            add_reordered_same_type_read_argument(program);
            program.parameters[0].access = AccessMode::Mutate;
            let ExpressionKind::Call { arguments, .. } = &mut program.expressions[8].kind else {
                unreachable!();
            };
            arguments[1].value = wrela_hir::CallArgumentValue::Exclusive {
                access: wrela_hir::ExclusiveAccess::Mutate,
                place: wrela_hir::PlaceTarget {
                    root: Definition::Local(LocalId(1)),
                    projections: Vec::new(),
                    source: span(0, 363, 364),
                },
            };
            remove_scalar_fixture_expression(program, ExpressionId(10));
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("overlapping access diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        let diagnostic = &output.diagnostics()[0];
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-overlapping-access")
        );
        assert_eq!(diagnostic.primary, span(0, 363, 367));
        assert_eq!(diagnostic.labels[0].span, span(0, 361, 363));
    }

    #[test]
    fn scalar_take_access_joins_only_when_every_branch_consumes() {
        let fixture = mutate_scalar_fixture(|program| {
            set_scalar_call_access(program, AccessMode::Take);
            add_scalar_else_call(program);
        });
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("take discovery");
        assert!(discovery.diagnostics().is_empty());
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("take test plan")
            .clone();
        let mut compile = request(&fixture, &changes, AnalysisLimits::standard());
        compile.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group: plan.image_groups()[0].id,
            declared_entry: None,
        };
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(compile, &|| false)
            .expect("take compile");
        let image = output.successful().expect("take image");
        let facts = image.facts();
        let take_calls = facts
            .expressions
            .iter()
            .filter_map(|fact| match &fact.resolution {
                ExpressionResolution::DirectCall { arguments, .. }
                    if arguments
                        .iter()
                        .any(|argument| argument.access == super::AccessMode::Take) =>
                {
                    Some(arguments)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(take_calls.len(), 2);
        assert!(
            take_calls
                .iter()
                .all(|arguments| arguments[0].value == ValueId(1))
        );
        assert_eq!(
            facts
                .statements
                .iter()
                .find(|fact| fact.statement == StatementId(4))
                .expect("joined if fact")
                .moved_after,
            [ValueId(1)]
        );

        let (hir, mut wrong_transition) = image.clone().into_parts();
        let forged_arguments = wrong_transition
            .expressions
            .iter_mut()
            .find_map(|fact| match &mut fact.resolution {
                ExpressionResolution::DirectCall { arguments, .. }
                    if arguments
                        .iter()
                        .any(|argument| argument.access == super::AccessMode::Take) =>
                {
                    Some(arguments)
                }
                _ => None,
            })
            .expect("mutable take binding");
        forged_arguments[0].access = super::AccessMode::Mutate;
        assert!(
            wrong_transition
                .validate_for_seal(hir.as_ref(), &|| false)
                .is_err()
        );

        let call_result = facts
            .expressions
            .iter()
            .find(|fact| fact.expression == ExpressionId(8))
            .and_then(|fact| fact.result)
            .expect("same-type call result");
        let (hir, mut wrong_moved_value) = image.clone().into_parts();
        wrong_moved_value
            .statements
            .iter_mut()
            .find(|fact| fact.statement == StatementId(4))
            .expect("mutable joined state")
            .moved_after[0] = call_result;
        assert!(
            wrong_moved_value
                .validate_for_seal(hir.as_ref(), &|| false)
                .is_err()
        );
    }

    #[test]
    fn take_on_only_one_branch_is_a_stable_ownership_diagnostic() {
        let fixture = mutate_scalar_fixture(|program| {
            set_scalar_call_access(program, AccessMode::Take);
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("branch ownership diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        let diagnostic = &output.diagnostics()[0];
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-branch-ownership-mismatch")
        );
        assert_eq!(diagnostic.primary, span(0, 341, 380));
        assert_eq!(diagnostic.labels[0].span, span(0, 331, 336));
        assert_eq!(
            diagnostic.notes,
            ["every path through a conditional must agree whether the value remains owned"]
        );
        assert_eq!(
            diagnostic.help,
            ["take the value on every branch or preserve it on every branch"]
        );
    }

    #[test]
    fn mutable_marker_cannot_target_a_read_only_parameter() {
        let fixture = mutate_scalar_fixture(|program| {
            let ExpressionKind::Call { arguments, .. } = &mut program.expressions[8].kind else {
                unreachable!();
            };
            arguments[0].value = wrela_hir::CallArgumentValue::Exclusive {
                access: wrela_hir::ExclusiveAccess::Mutate,
                place: wrela_hir::PlaceTarget {
                    root: Definition::Local(LocalId(1)),
                    projections: Vec::new(),
                    source: span(0, 363, 364),
                },
            };
            remove_scalar_fixture_expression(program, ExpressionId(10));
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("access diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        assert_eq!(
            output.diagnostics()[0].code.as_deref(),
            Some("semantic-access-marker-mismatch")
        );
        assert_eq!(output.diagnostics()[0].primary, span(0, 363, 367));
    }

    #[test]
    fn read_parameter_cannot_be_forwarded_as_mutable() {
        let fixture = mutate_scalar_fixture(add_mutating_sink_called_through_read_parameter);
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("read-only authority diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        let diagnostic = &output.diagnostics()[0];
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-mutate-read-only")
        );
        assert_eq!(diagnostic.primary, span(0, 429, 430));
        assert_eq!(diagnostic.labels[0].span, span(0, 408, 414));
    }

    #[test]
    fn borrowed_parameter_cannot_be_forwarded_by_take() {
        let fixture = mutate_scalar_fixture(|program| {
            add_mutating_sink_called_through_read_parameter(program);
            program.parameters[1].access = AccessMode::Take;
            let ExpressionKind::Call { arguments, .. } = &mut program.expressions[13].kind else {
                unreachable!();
            };
            let wrela_hir::CallArgumentValue::Exclusive { access, .. } = &mut arguments[0].value
            else {
                unreachable!();
            };
            *access = wrela_hir::ExclusiveAccess::Take;
        });
        let changes = no_changes();
        let output = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("borrowed take diagnostic");
        assert!(output.successful().is_none());
        assert_eq!(output.diagnostics().len(), 1);
        let diagnostic = &output.diagnostics()[0];
        assert_eq!(diagnostic.code.as_deref(), Some("semantic-take-borrowed"));
        assert_eq!(diagnostic.primary, span(0, 429, 430));
        assert_eq!(diagnostic.labels[0].span, span(0, 408, 414));
    }

    #[test]
    fn views_are_rejected_at_function_and_branch_state_boundaries() {
        for parameter_boundary in [true, false] {
            let fixture = mutate_scalar_fixture(|program| {
                let (slot, source) = if parameter_boundary {
                    (&mut program.parameters[0].ty, span(0, 411, 414))
                } else {
                    (&mut program.locals[1].ty, span(0, 333, 336))
                };
                let target = slot.take().expect("source scalar type");
                *slot = Some(TypeExpression {
                    kind: TypeExpressionKind::View {
                        mutable: false,
                        target: Box::new(target),
                    },
                    source,
                });
            });
            let changes = no_changes();
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(discovery_request(&fixture, &changes), &|| false)
                .expect("view escape diagnostic");
            assert!(output.successful().is_none());
            assert_eq!(output.diagnostics().len(), 1);
            assert_eq!(
                output.diagnostics()[0].code.as_deref(),
                Some("semantic-view-escape")
            );
            assert_eq!(
                output.diagnostics()[0].primary,
                if parameter_boundary {
                    span(0, 411, 414)
                } else {
                    span(0, 333, 336)
                }
            );
        }
    }

    #[test]
    fn taken_value_cannot_be_read_or_taken_again() {
        for (second_take, expected_code) in [
            (false, "semantic-use-after-take"),
            (true, "semantic-double-take"),
        ] {
            let fixture = mutate_scalar_fixture(|program| {
                set_scalar_call_access(program, AccessMode::Take);
                add_scalar_else_call(program);
                let post_expression = ExpressionId(program.expressions.len() as u32);
                program.bodies[2].statements.push(StatementId(10));
                program.statements[5].kind = StatementKind::Expression(post_expression);
                program.statements.push(Statement {
                    id: StatementId(10),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(None),
                    source: span(0, 388, 389),
                });
                if second_take {
                    let callee = ExpressionId(post_expression.0 + 1);
                    program.expressions.extend([
                        Expression {
                            id: post_expression,
                            owner: ExpressionOwner::Body(BodyId(2)),
                            scope: Some(wrela_hir::ScopeId(2)),
                            kind: ExpressionKind::Call {
                                callee,
                                arguments: vec![CallArgument {
                                    name: Some(name("x")),
                                    value: wrela_hir::CallArgumentValue::Exclusive {
                                        access: wrela_hir::ExclusiveAccess::Take,
                                        place: wrela_hir::PlaceTarget {
                                            root: Definition::Local(LocalId(1)),
                                            projections: Vec::new(),
                                            source: span(0, 384, 385),
                                        },
                                    },
                                    source: span(0, 383, 386),
                                }],
                            },
                            source: span(0, 381, 387),
                        },
                        Expression {
                            id: callee,
                            owner: ExpressionOwner::Body(BodyId(2)),
                            scope: Some(wrela_hir::ScopeId(2)),
                            kind: ExpressionKind::Reference(Definition::Declaration(
                                ResolvedDeclaration {
                                    package: PackageId(0),
                                    module: ModuleId(0),
                                    declaration: DeclarationId(5),
                                },
                            )),
                            source: span(0, 381, 382),
                        },
                    ]);
                } else {
                    program.expressions.push(Expression {
                        id: post_expression,
                        owner: ExpressionOwner::Body(BodyId(2)),
                        scope: Some(wrela_hir::ScopeId(2)),
                        kind: ExpressionKind::Reference(Definition::Local(LocalId(1))),
                        source: span(0, 384, 385),
                    });
                }
            });
            let changes = no_changes();
            let output = CanonicalSemanticAnalyzer::new()
                .analyze(discovery_request(&fixture, &changes), &|| false)
                .expect("post-take diagnostic");
            assert!(output.successful().is_none());
            assert_eq!(output.diagnostics().len(), 1);
            assert_eq!(output.diagnostics()[0].code.as_deref(), Some(expected_code));
            assert_eq!(output.diagnostics()[0].primary, span(0, 384, 385));
        }
    }

    #[test]
    fn ownership_diagnostics_and_late_runtime_cancellation_are_bounded() {
        let mut limits = AnalysisLimits::standard();
        limits.diagnostic_count = 1;
        let mut diagnostics = Vec::new();
        push_diagnostic(
            &mut diagnostics,
            test_source_diagnostic(
                span(0, 1, 2),
                "semantic-first",
                "first bounded source error",
            ),
            limits,
        )
        .expect("diagnostic at exact limit");
        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(
            push_diagnostic(
                &mut diagnostics,
                test_source_diagnostic(
                    span(0, 2, 3),
                    "semantic-second",
                    "second bounded source error",
                ),
                limits,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "semantic diagnostics",
                limit: 1,
            })
        ));

        let fixture = fixture(ProgramKind::ScalarRuntimeTest);
        let changes = no_changes();
        let discovery = CanonicalSemanticAnalyzer::new()
            .analyze(discovery_request(&fixture, &changes), &|| false)
            .expect("late-cancellation discovery");
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .expect("late-cancellation plan")
            .clone();
        let group = plan.image_groups()[0].id;
        let polls = Cell::new(0u32);
        let mut baseline = request(&fixture, &changes, AnalysisLimits::standard());
        baseline.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        let baseline_output = CanonicalSemanticAnalyzer::new()
            .analyze(baseline, &|| {
                polls.set(polls.get().saturating_add(1));
                false
            })
            .expect("counted runtime analysis");
        assert!(baseline_output.successful().is_some());
        let final_poll = polls.get();
        assert!(final_poll > 3);

        polls.set(0);
        let mut cancelled = request(&fixture, &changes, AnalysisLimits::standard());
        cancelled.mode = AnalysisMode::CompileTestGroup {
            plan: &plan,
            group,
            declared_entry: None,
        };
        assert!(matches!(
            CanonicalSemanticAnalyzer::new().analyze(cancelled, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= final_poll
            }),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), final_poll);
    }
}
