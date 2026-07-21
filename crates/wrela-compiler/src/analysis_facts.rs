use std::fmt::Write;

use wrela_image_report::{
    AnalysisFactRequest as ReportRequest, AnalysisFacts, BoundFact, ImageEdgeFact, ImageNodeFact,
    ProofFact, RegionCapacityEvidenceFact, ValidatedAnalysisFacts, WorkFact, seal_analysis_facts,
};
use wrela_sema::{
    AnalysisRoot, FunctionOrigin, FunctionRole, ImageOwner, Linearity, PartialAnalysis, ProofKind,
    RegionClass, SemanticTypeKind,
};
use wrela_test_model::{ImageRoot as TestImageRoot, ImageTestInvocation, TestKind};

use crate::{AnalysisFactAssembler, AnalysisFactAssemblyError, AnalysisFactRequest};

/// Production projection for the executable semantic surface currently
/// emitted by `CanonicalSemanticAnalyzer`.
///
/// The minimum closed image, bounded stateless actor/task images, and sealed
/// synchronous bounded-value test images (including transitively reachable
/// ordinary helpers and flat scalar-backed structures) are projected without
/// inventing hardware, recovery, actor-lowering, or interface-dispatch facts.
/// Richer semantic databases are rejected until every corresponding public
/// report fact has an exact source.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalAnalysisFactAssembler;

impl CanonicalAnalysisFactAssembler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AnalysisFactAssembler for CanonicalAnalysisFactAssembler {
    fn assemble(
        &self,
        request: AnalysisFactRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedAnalysisFacts, AnalysisFactAssemblyError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        let projection = supported_projection(request.analysis, request.limits, is_cancelled)?;
        preflight_projection(&projection, request.limits, is_cancelled)?;
        let facts = assemble_projection(&projection, request.limits, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        seal_projection(
            &projection,
            ReportRequest {
                build: &projection.semantic.build,
                image_name: &projection.graph.name,
                limits: request.limits,
            },
            facts,
            is_cancelled,
        )
    }
}

struct SupportedProjection<'a> {
    semantic: &'a PartialAnalysis,
    graph: &'a wrela_sema::ImageGraph,
    reachable_declarations: u64,
    kind: ProjectionKind,
}

#[derive(Debug, Default)]
struct ActorReportFacts {
    image_nodes: Vec<ImageNodeFact>,
    image_edges: Vec<ImageEdgeFact>,
    region_capacity_evidence: Vec<RegionCapacityEvidenceFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionKind {
    Scalar,
    Actor,
}

fn supported_projection<'a>(
    analysis: &'a wrela_sema::AnalyzedImage,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SupportedProjection<'a>, AnalysisFactAssemblyError> {
    check_cancelled(is_cancelled)?;
    let facts = analysis.facts();
    let graph = facts
        .graph
        .as_ref()
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "complete image graph is absent",
        ))?;
    if facts.test_plan.is_some() || !facts.comptime_test_results.is_empty() {
        return Err(unsupported("test-discovery facts in executable images"));
    }
    if !facts.scope_protocols.is_empty()
        || !facts.scope_activations.is_empty()
        || !facts.baked_artifacts.is_empty()
    {
        return Err(unsupported("scope protocols or baked artifacts"));
    }
    let (reachable_declarations, kind) = match &facts.root {
        AnalysisRoot::DeclaredImage { .. } if !graph.actors.is_empty() => (
            supported_actor_image(analysis, graph, limits, is_cancelled)?,
            ProjectionKind::Actor,
        ),
        AnalysisRoot::DeclaredImage { .. } => {
            require_empty_runtime_graph(graph)?;
            require_unit_type(facts)?;
            (
                supported_declared_image(facts, graph)?,
                ProjectionKind::Scalar,
            )
        }
        AnalysisRoot::GeneratedTestHarness { .. } => {
            require_empty_runtime_graph(graph)?;
            require_supported_runtime_types(facts, is_cancelled)?;
            (
                supported_generated_test_image(analysis, graph, limits, is_cancelled)?,
                ProjectionKind::Scalar,
            )
        }
    };
    check_cancelled(is_cancelled)?;
    Ok(SupportedProjection {
        semantic: facts,
        graph,
        reachable_declarations,
        kind,
    })
}

fn require_empty_runtime_graph(
    graph: &wrela_sema::ImageGraph,
) -> Result<(), AnalysisFactAssemblyError> {
    if !graph.actors.is_empty()
        || !graph.tasks.is_empty()
        || !graph.devices.is_empty()
        || !graph.pools.is_empty()
        || !graph.regions.is_empty()
        || !graph.brands.is_empty()
        || graph.static_bytes != 0
        || graph.peak_bytes != 0
        || graph.startup_order.as_slice() != [ImageOwner::Runtime]
        || graph.shutdown_order.as_slice() != [ImageOwner::Runtime]
    {
        return Err(unsupported("nonempty runtime image graphs"));
    }
    Ok(())
}

fn require_unit_type(facts: &PartialAnalysis) -> Result<(), AnalysisFactAssemblyError> {
    let [ty] = facts.types.as_slice() else {
        return Err(unsupported("semantic type sets other than unit"));
    };
    if ty.id != wrela_sema::SemanticTypeId(0)
        || ty.kind != SemanticTypeKind::Unit
        || ty.linearity != Linearity::ScalarCopy
        || ty.size_upper_bound != Some(0)
        || ty.alignment_lower_bound != 1
        || ty.source.is_some()
    {
        return Err(unsupported("semantic types other than canonical unit"));
    }
    Ok(())
}

fn require_supported_runtime_types(
    facts: &PartialAnalysis,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let Some(unit) = facts.types.first() else {
        return Err(unsupported("runtime images without canonical unit"));
    };
    if unit.id != wrela_sema::SemanticTypeId(0)
        || unit.kind != SemanticTypeKind::Unit
        || unit.linearity != Linearity::ScalarCopy
        || unit.size_upper_bound != Some(0)
        || unit.alignment_lower_bound != 1
        || unit.source.is_some()
    {
        return Err(unsupported("runtime images without canonical unit"));
    }
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        let supported = match &ty.kind {
            SemanticTypeKind::Unit | SemanticTypeKind::Bool | SemanticTypeKind::Integer { .. } => {
                is_runtime_value_type(facts, ty.id)
            }
            SemanticTypeKind::Structure { .. } => {
                validate_flat_runtime_structure(facts, ty.id, is_cancelled)?
            }
            SemanticTypeKind::Function {
                color,
                parameters,
                result,
            } => {
                ty.linearity == Linearity::ScalarCopy
                    && ty.size_upper_bound == Some(0)
                    && ty.alignment_lower_bound == 1
                    && ty.source.is_none()
                    && *color == wrela_hir::FunctionColor::Sync
                    && is_runtime_value_type(facts, *result)
                    && parameters
                        .iter()
                        .all(|parameter| is_runtime_value_type(facts, parameter.ty))
            }
            _ => false,
        };
        if !supported {
            return Err(unsupported(
                "runtime types outside the bounded flat-value subset",
            ));
        }
    }
    Ok(())
}

fn supported_actor_image(
    analysis: &wrela_sema::AnalyzedImage,
    graph: &wrela_sema::ImageGraph,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, AnalysisFactAssemblyError> {
    let facts = analysis.facts();
    let constructor = match facts.root {
        AnalysisRoot::DeclaredImage {
            declaration,
            test_group: None,
            ..
        } => declaration,
        AnalysisRoot::DeclaredImage {
            test_group: Some(_),
            ..
        } => return Err(unsupported("actor images compiled as declared scenarios")),
        AnalysisRoot::GeneratedTestHarness { .. } => {
            return Err(unsupported(
                "actor images compiled as generated test harnesses",
            ));
        }
    };
    if facts.compiled_test_group.is_some() {
        return Err(unsupported("compiled test metadata in actor images"));
    }
    if graph.actors.is_empty()
        || !graph.devices.is_empty()
        || !graph.pools.is_empty()
        || !graph.brands.is_empty()
    {
        return Err(unsupported(
            "runtime graphs outside the stateless actor/task slice",
        ));
    }
    require_supported_actor_types(analysis, is_cancelled)?;
    let entry = facts
        .functions
        .get(graph.entry.0 as usize)
        .filter(|function| function.id == graph.entry)
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "actor image entry is absent",
        ))?;
    if entry.origin != (FunctionOrigin::GeneratedImageEntry { constructor })
        || entry.role != FunctionRole::ImageEntry
        || entry.color != wrela_hir::FunctionColor::Sync
        || !entry.generic_arguments.is_empty()
        || !entry.parameters.is_empty()
        || entry.result != wrela_sema::SemanticTypeId(0)
        || entry.effects
            != wrela_sema::EffectSet(
                wrela_sema::EffectSet::FIRMWARE
                    | wrela_sema::EffectSet::ACTOR
                    | wrela_sema::EffectSet::TASK,
            )
        || entry.source.is_some()
        || facts.values.iter().any(|value| value.function == entry.id)
        || facts
            .expressions
            .iter()
            .any(|expression| expression.function == entry.id)
        || facts
            .statements
            .iter()
            .any(|statement| statement.function == entry.id)
    {
        return Err(unsupported("noncanonical generated actor image entries"));
    }
    validate_actor_graph(facts, graph, entry, limits, is_cancelled)?;
    validate_actor_functions(analysis, graph, entry.id, is_cancelled)?;
    validate_actor_proofs(facts, graph, entry, is_cancelled)?;
    actor_reachable_declarations(facts, constructor, limits, is_cancelled)
}

fn require_supported_actor_types(
    analysis: &wrela_sema::AnalyzedImage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let facts = analysis.facts();
    let Some(unit) = facts.types.first() else {
        return Err(unsupported("actor images without canonical unit"));
    };
    if unit.id != wrela_sema::SemanticTypeId(0)
        || unit.kind != SemanticTypeKind::Unit
        || unit.linearity != Linearity::ScalarCopy
        || unit.size_upper_bound != Some(0)
        || unit.alignment_lower_bound != 1
        || unit.source.is_some()
    {
        return Err(unsupported("actor images without canonical unit"));
    }
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        let scalar = match &ty.kind {
            SemanticTypeKind::Unit | SemanticTypeKind::Bool => true,
            SemanticTypeKind::Integer {
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
            SemanticTypeKind::Function {
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
            SemanticTypeKind::Class {
                declaration,
                arguments,
                fields,
            } => {
                let source_matches = analysis
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
                    || ty.linearity != Linearity::ReclaimableLinear
                    || ty.size_upper_bound != Some(0)
                    || ty.alignment_lower_bound != 1
                {
                    return Err(unsupported("noncanonical actor class types"));
                }
                continue;
            }
            _ => false,
        };
        if !scalar || ty.linearity != Linearity::ScalarCopy {
            return Err(unsupported("types outside the bounded actor scalar subset"));
        }
    }
    Ok(())
}

fn validate_actor_graph(
    facts: &PartialAnalysis,
    graph: &wrela_sema::ImageGraph,
    entry: &wrela_sema::FunctionInstance,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let expected_regions = graph
        .actors
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(graph.tasks.len()))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "actor graph regions",
            limit: limits.items,
        })?;
    let expected_owners = graph
        .actors
        .len()
        .checked_add(graph.tasks.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "actor image owner order",
            limit: limits.items,
        })?;
    if graph.regions.len() != expected_regions
        || graph.static_bytes == 0
        || graph.startup_order.len() != expected_owners
        || graph.shutdown_order.len() != expected_owners
        || graph.startup_order.first() != Some(&ImageOwner::Runtime)
        || graph.shutdown_order.last() != Some(&ImageOwner::Runtime)
    {
        return Err(unsupported(
            "noncanonical actor capacity graph or owner order",
        ));
    }
    let mut static_bytes = 0u64;
    for (index, actor) in graph.actors.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let mailbox_index =
            index
                .checked_mul(2)
                .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.items,
                })?;
        let turn_index =
            mailbox_index
                .checked_add(1)
                .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.items,
                })?;
        let shutdown_index = graph
            .tasks
            .len()
            .checked_add(graph.actors.len() - index - 1)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "actor shutdown order",
                limit: limits.items,
            })?;
        if actor.id.0 as usize != index
            || actor.priority != 1
            || actor.supervisor.is_some()
            || actor.mailbox_capacity == 0
            || graph.startup_order.get(index + 1) != Some(&ImageOwner::Actor(actor.id))
            || graph.shutdown_order.get(shutdown_index) != Some(&ImageOwner::Actor(actor.id))
            || actor.turn_functions.iter().any(|id| {
                facts.functions.get(id.0 as usize).is_none_or(|function| {
                    function.id != *id || function.role != FunctionRole::ActorTurn(actor.id)
                })
            })
        {
            return Err(unsupported("noncanonical actor identity or owner order"));
        }
        let mailbox = graph.regions.get(mailbox_index).ok_or(
            AnalysisFactAssemblyError::InvalidSemanticFacts("actor mailbox region is absent"),
        )?;
        let turn = graph.regions.get(turn_index).ok_or(
            AnalysisFactAssemblyError::InvalidSemanticFacts("actor turn-frame region is absent"),
        )?;
        let mailbox_bytes = u64::from(actor.mailbox_capacity).checked_mul(16).ok_or(
            AnalysisFactAssemblyError::ResourceLimit {
                resource: "actor mailbox bytes",
                limit: limits.payload_bytes,
            },
        )?;
        let turn_bytes = actor
            .turn_functions
            .iter()
            .filter_map(|id| facts.functions.get(id.0 as usize))
            .map(|function| function.frame_bytes_bound.max(1))
            .max()
            .unwrap_or(1);
        if mailbox.id.0 as usize != mailbox_index
            || mailbox.class != RegionClass::Image
            || mailbox.owner != ImageOwner::Actor(actor.id)
            || mailbox.capacity_bytes != mailbox_bytes
            || mailbox.alignment != 8
            || mailbox.source != actor.source
            || !joined_name_matches(&mailbox.name, &actor.name, ".mailbox")
            || !capacity_proof_matches(facts, mailbox.proof, u64::from(actor.mailbox_capacity))
            || entry.proofs.binary_search(&mailbox.proof).is_err()
            || turn.id.0 as usize != turn_index
            || turn.class != RegionClass::TaskFrame
            || turn.owner != ImageOwner::Actor(actor.id)
            || turn.capacity_bytes != turn_bytes
            || turn.alignment != 8
            || turn.source != actor.source
            || !joined_name_matches(&turn.name, &actor.name, ".turn-frame")
            || !capacity_proof_matches(facts, turn.proof, 1)
            || entry.proofs.binary_search(&turn.proof).is_err()
        {
            return Err(unsupported("actor capacity proof or region substitution"));
        }
        static_bytes = static_bytes
            .checked_add(mailbox_bytes)
            .and_then(|bytes| bytes.checked_add(turn_bytes))
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "actor static bytes",
                limit: limits.payload_bytes,
            })?;
    }
    let task_region_start =
        graph
            .actors
            .len()
            .checked_mul(2)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "task region identity",
                limit: limits.items,
            })?;
    for (index, task) in graph.tasks.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let function = facts
            .functions
            .get(task.entry.0 as usize)
            .filter(|function| {
                function.id == task.entry && function.role == FunctionRole::TaskEntry(task.id)
            })
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "task entry relation is absent",
            ))?;
        let region_index = task_region_start.checked_add(index).ok_or(
            AnalysisFactAssemblyError::ResourceLimit {
                resource: "task region identity",
                limit: limits.items,
            },
        )?;
        let startup_index = graph
            .actors
            .len()
            .checked_add(index)
            .and_then(|value| value.checked_add(1))
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "task startup order",
                limit: limits.items,
            })?;
        let shutdown_index = graph.tasks.len() - index - 1;
        let region = graph.regions.get(region_index).ok_or(
            AnalysisFactAssemblyError::InvalidSemanticFacts("task frame region is absent"),
        )?;
        let frame_bytes = function
            .frame_bytes_bound
            .max(1)
            .checked_mul(u64::from(task.slots))
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "task frame bytes",
                limit: limits.payload_bytes,
            })?;
        if task.id.0 as usize != index
            || task.slots != 1
            || task.priority != 1
            || task
                .supervisor
                .is_none_or(|actor| actor.0 as usize >= graph.actors.len())
            || graph.startup_order.get(startup_index) != Some(&ImageOwner::Task(task.id))
            || graph.shutdown_order.get(shutdown_index) != Some(&ImageOwner::Task(task.id))
            || region.id.0 as usize != region_index
            || region.class != RegionClass::TaskFrame
            || region.owner != ImageOwner::Task(task.id)
            || region.capacity_bytes != frame_bytes
            || region.alignment != 8
            || region.source != task.source
            || !joined_name_matches(&region.name, &task.name, ".frame")
            || !capacity_proof_matches(facts, region.proof, u64::from(task.slots))
            || entry.proofs.binary_search(&region.proof).is_err()
        {
            return Err(unsupported("task capacity proof or region substitution"));
        }
        static_bytes = static_bytes.checked_add(frame_bytes).ok_or(
            AnalysisFactAssemblyError::ResourceLimit {
                resource: "actor static bytes",
                limit: limits.payload_bytes,
            },
        )?;
    }
    if static_bytes != graph.static_bytes || graph.peak_bytes != graph.static_bytes {
        return Err(unsupported(
            "actor image static or peak capacity substitution",
        ));
    }
    Ok(())
}

fn validate_actor_functions(
    analysis: &wrela_sema::AnalyzedImage,
    graph: &wrela_sema::ImageGraph,
    entry: wrela_sema::FunctionInstanceId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let facts = analysis.facts();
    let program = analysis.hir().as_program();
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if function.id == entry {
            continue;
        }
        let FunctionOrigin::Source { declaration, body } = function.origin else {
            return Err(unsupported("non-source functions in actor runtime closure"));
        };
        let source = program.declaration(declaration).ok_or(
            AnalysisFactAssemblyError::InvalidSemanticFacts(
                "actor function source declaration is absent",
            ),
        )?;
        let wrela_hir::DeclarationKind::Function(declared) = &source.kind else {
            return Err(unsupported("non-function actor source origins"));
        };
        let role_matches = match function.role {
            FunctionRole::ActorTurn(actor) => graph
                .actors
                .get(actor.0 as usize)
                .is_some_and(|node| node.turn_functions.binary_search(&function.id).is_ok()),
            FunctionRole::TaskEntry(task) => graph
                .tasks
                .get(task.0 as usize)
                .is_some_and(|node| node.entry == function.id),
            FunctionRole::Ordinary => true,
            FunctionRole::Isr(_)
            | FunctionRole::Cleanup
            | FunctionRole::ImageEntry
            | FunctionRole::Test => false,
        };
        let role_effect = match function.role {
            FunctionRole::ActorTurn(_) => wrela_sema::EffectSet::ACTOR,
            FunctionRole::TaskEntry(_) => wrela_sema::EffectSet::TASK,
            FunctionRole::Ordinary => 0,
            _ => u64::MAX,
        };
        let expected_effects = role_effect
            | if function.color == wrela_hir::FunctionColor::Async {
                wrela_sema::EffectSet::SUSPEND
            } else {
                0
            };
        if declared.body != Some(body)
            || declared.color != function.color
            || function.source != Some(source.source)
            || !matches!(
                function.color,
                wrela_hir::FunctionColor::Sync | wrela_hir::FunctionColor::Async
            )
            || !function.generic_arguments.is_empty()
            || !role_matches
            || function.effects.0 != expected_effects
            || function.recursive_depth_bound != Some(1)
            || function.uninterrupted_work_bound.is_none()
            || (function.color == wrela_hir::FunctionColor::Async
                && function.frame_bytes_bound < 16)
            || (function.color == wrela_hir::FunctionColor::Sync && function.frame_bytes_bound != 0)
        {
            return Err(unsupported("noncanonical actor source functions"));
        }
    }
    Ok(())
}

fn validate_actor_proofs(
    facts: &PartialAnalysis,
    graph: &wrela_sema::ImageGraph,
    entry: &wrela_sema::FunctionInstance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if matches!(
            function.role,
            FunctionRole::ActorTurn(_) | FunctionRole::TaskEntry(_)
        ) && !function_proof_kind(facts, function, &ProofKind::Ownership, Some(1))
        {
            return Err(unsupported("actor function ownership proof substitution"));
        }
        if function.color == wrela_hir::FunctionColor::Async {
            let cleanup_bound = u64::try_from(function.parameters.len()).map_err(|_| {
                AnalysisFactAssemblyError::InvalidSemanticFacts(
                    "async cleanup parameter bound does not fit u64",
                )
            })?;
            if !function_proof_kind(facts, function, &ProofKind::ViewDoesNotEscape, Some(0))
                || !function_proof_kind(
                    facts,
                    function,
                    &ProofKind::CleanupAcyclic,
                    Some(cleanup_bound),
                )
            {
                return Err(unsupported(
                    "actor suspension or cleanup proof substitution",
                ));
            }
        }
    }
    let mut wait_proofs = facts
        .proofs
        .iter()
        .filter(|proof| proof.kind == ProofKind::WaitGraphAcyclic);
    let wait = wait_proofs
        .next()
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "actor wait-graph proof is absent",
        ))?;
    if wait_proofs.next().is_some() || entry.proofs.binary_search(&wait.id).is_err() {
        return Err(unsupported("actor wait-graph proof substitution"));
    }
    for region in &graph.regions {
        if entry.proofs.binary_search(&region.proof).is_err() {
            return Err(unsupported("actor entry omits a capacity proof"));
        }
    }
    let mut closed_proofs = facts
        .proofs
        .iter()
        .filter(|proof| proof.kind == ProofKind::ImageClosed);
    let closed = closed_proofs
        .next()
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "actor closed-image proof is absent",
        ))?;
    if closed.bound != Some(graph.static_bytes)
        || closed.depends_on.binary_search(&wait.id).is_err()
        || entry.proofs.binary_search(&closed.id).is_err()
        || closed.depends_on.windows(2).any(|pair| pair[0] >= pair[1])
        || closed_proofs.next().is_some()
    {
        return Err(unsupported("actor closed-image proof substitution"));
    }
    Ok(())
}

fn function_proof_kind(
    facts: &PartialAnalysis,
    function: &wrela_sema::FunctionInstance,
    kind: &ProofKind,
    exact_bound: Option<u64>,
) -> bool {
    function.proofs.iter().any(|id| {
        facts.proofs.get(id.0 as usize).is_some_and(|proof| {
            proof.id == *id
                && &proof.kind == kind
                && exact_bound.is_none_or(|bound| proof.bound == Some(bound))
        })
    })
}

fn capacity_proof_matches(facts: &PartialAnalysis, id: wrela_sema::ProofId, bound: u64) -> bool {
    facts.proofs.get(id.0 as usize).is_some_and(|proof| {
        proof.id == id && proof.kind == ProofKind::CapacityBound && proof.bound == Some(bound)
    })
}

fn joined_name_matches(value: &str, prefix: &str, suffix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|remainder| remainder == suffix)
}

fn actor_reachable_declarations(
    facts: &PartialAnalysis,
    constructor: wrela_hir::DeclarationId,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, AnalysisFactAssemblyError> {
    let capacity = facts
        .functions
        .len()
        .checked_add(facts.types.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "actor reachable declarations",
            limit: limits.items,
        })?;
    let mut declarations = try_vec(capacity, "actor reachable declarations", limits.items)?;
    declarations.push(constructor);
    for function in &facts.functions {
        check_cancelled(is_cancelled)?;
        if let FunctionOrigin::Source { declaration, .. } = function.origin {
            declarations.push(declaration);
        }
    }
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        if let SemanticTypeKind::Class { declaration, .. } = ty.kind {
            declarations.push(declaration);
        }
    }
    declarations.sort_unstable();
    declarations.dedup();
    u64::try_from(declarations.len()).map_err(|_| AnalysisFactAssemblyError::ResourceLimit {
        resource: "actor reachable declarations",
        limit: limits.items,
    })
}

fn supported_declared_image(
    facts: &PartialAnalysis,
    graph: &wrela_sema::ImageGraph,
) -> Result<u64, AnalysisFactAssemblyError> {
    if !facts.values.is_empty() || !facts.expressions.is_empty() || !facts.statements.is_empty() {
        return Err(unsupported("source runtime bodies in declared images"));
    }
    let (declaration, test_group) = match &facts.root {
        AnalysisRoot::DeclaredImage {
            declaration,
            test_group,
            ..
        } => (*declaration, *test_group),
        AnalysisRoot::GeneratedTestHarness { .. } => {
            return Err(unsupported("generated harness as a declared image"));
        }
    };
    match (test_group, facts.compiled_test_group.as_ref()) {
        (None, None) => {}
        (Some(group), Some(record))
            if record.id == group
                && matches!(
                    &record.root,
                    TestImageRoot::Declared { image_name, .. } if image_name == &graph.name
                )
                && matches!(
                    record.tests.as_slice(),
                    [test]
                        if test.descriptor.kind == TestKind::DeclaredImage
                            && test.descriptor.source.is_none()
                            && matches!(test.invocation, ImageTestInvocation::DeclaredScenario)
                ) => {}
        _ => {
            return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "declared compiled test root lacks its exact sealed group",
            ));
        }
    }
    let [function] = facts.functions.as_slice() else {
        return Err(unsupported("multiple runtime function instances"));
    };
    if function.id != wrela_sema::FunctionInstanceId(0)
        || function.origin
            != (FunctionOrigin::GeneratedImageEntry {
                constructor: declaration,
            })
        || function.role != FunctionRole::ImageEntry
        || function.color != wrela_hir::FunctionColor::Sync
        || !function.generic_arguments.is_empty()
        || !function.parameters.is_empty()
        || function.result != wrela_sema::SemanticTypeId(0)
        || function.effects != wrela_sema::EffectSet(wrela_sema::EffectSet::FIRMWARE)
        || function.source.is_some()
        || function.stack_bytes_bound != 0
        || function.frame_bytes_bound != 0
        || function.uninterrupted_work_bound != Some(1)
        || function.recursive_depth_bound != Some(1)
        || function.proofs.as_slice()
            != [
                wrela_sema::ProofId(0),
                wrela_sema::ProofId(1),
                wrela_sema::ProofId(2),
            ]
        || graph.entry != function.id
    {
        return Err(unsupported("noncanonical generated image entries"));
    }
    if facts.proofs.len() != 3
        || !matches!(facts.proofs[0].kind, ProofKind::TypeChecked)
        || !matches!(facts.proofs[1].kind, ProofKind::EffectsAllowed)
        || !matches!(facts.proofs[2].kind, ProofKind::ImageClosed)
    {
        return Err(unsupported("noncanonical minimum-image proof sets"));
    }
    Ok(1)
}

fn supported_generated_test_image(
    analysis: &wrela_sema::AnalyzedImage,
    graph: &wrela_sema::ImageGraph,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, AnalysisFactAssemblyError> {
    let facts = analysis.facts();
    let (root_group, harness_name) = match &facts.root {
        AnalysisRoot::GeneratedTestHarness {
            group,
            harness_name,
        } => (*group, harness_name),
        AnalysisRoot::DeclaredImage { .. } => {
            return Err(unsupported("declared image as a generated test harness"));
        }
    };
    if graph.name != *harness_name {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test root name differs from its image graph",
        ));
    }
    let group = facts
        .compiled_test_group
        .as_ref()
        .filter(|group| group.id == root_group)
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test root lacks its exact sealed group",
        ))?;
    if !matches!(
        &group.root,
        TestImageRoot::GeneratedHarness { harness_name: planned } if planned == harness_name
    ) {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test group names a different root",
        ));
    }
    let source_function_count = facts.functions.len().checked_sub(1).ok_or(
        AnalysisFactAssemblyError::InvalidSemanticFacts("generated test harness is absent"),
    )?;
    if source_function_count < group.tests.len() {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test image omits a selected source function",
        ));
    }
    let expected_proofs = source_function_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(3));
    if expected_proofs != Some(facts.proofs.len()) {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test image does not contain its exact proof set",
        ));
    }
    let mut selected_tests = 0usize;
    let declaration_capacity = source_function_count.checked_add(facts.types.len()).ok_or(
        AnalysisFactAssemblyError::ResourceLimit {
            resource: "reachable source declarations",
            limit: limits.items,
        },
    )?;
    let mut reachable_declarations = try_vec(
        declaration_capacity,
        "reachable source declarations",
        limits.items,
    )?;
    for (index, function) in facts.functions[..source_function_count].iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let FunctionOrigin::Source { declaration, .. } = function.origin else {
            return Err(unsupported("generated functions outside the test harness"));
        };
        retain_reachable_declaration(&mut reachable_declarations, declaration, is_cancelled)?;
        let first_proof = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(2))
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis proof identities",
                limit: u64::from(u32::MAX),
            })?;
        validate_scalar_source_function(facts, function, first_proof)?;

        let mut matching_test = None;
        for planned in &group.tests {
            check_cancelled(is_cancelled)?;
            let ImageTestInvocation::GeneratedFunction { function_key } = planned.invocation else {
                return Err(unsupported("declared scenarios in a generated harness"));
            };
            if function.key == function_key && matching_test.replace(planned).is_some() {
                return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
                    "generated test plan repeats a function identity",
                ));
            }
        }
        match function.role {
            FunctionRole::Test => {
                let planned =
                    matching_test.ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                        "generated image contains an unselected test function",
                    ))?;
                if function.name != planned.descriptor.name
                    || function.source != planned.descriptor.source
                    || planned.descriptor.kind != TestKind::IntegrationImage
                    || planned.descriptor.source.is_none()
                    || !function.parameters.is_empty()
                    || function.result != wrela_sema::SemanticTypeId(0)
                {
                    return Err(unsupported(
                        "generated test functions outside the synchronous zero-argument unit subset",
                    ));
                }
                selected_tests = selected_tests.checked_add(1).ok_or(
                    AnalysisFactAssemblyError::ResourceLimit {
                        resource: "selected analysis tests",
                        limit: limits.items,
                    },
                )?;
            }
            FunctionRole::Ordinary if matching_test.is_none() => {}
            _ => {
                return Err(unsupported(
                    "source functions outside selected tests and reachable bounded-value helpers",
                ));
            }
        }
    }
    if selected_tests != group.tests.len() {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated image does not contain every selected test function",
        ));
    }
    for ty in &facts.types {
        check_cancelled(is_cancelled)?;
        if let SemanticTypeKind::Structure { declaration, .. } = &ty.kind {
            if !is_flat_runtime_structure(facts, ty.id) {
                return Err(unsupported(
                    "runtime structures outside the bounded flat-value subset",
                ));
            }
            retain_reachable_declaration(&mut reachable_declarations, *declaration, is_cancelled)?;
        }
    }
    let reachable_declarations = u64::try_from(reachable_declarations.len()).map_err(|_| {
        AnalysisFactAssemblyError::ResourceLimit {
            resource: "reachable source declarations",
            limit: limits.items,
        }
    })?;

    let harness = facts
        .functions
        .last()
        .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "generated test harness is absent",
        ))?;
    let harness_proof = u32::try_from(source_function_count)
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis proof identities",
            limit: u64::from(u32::MAX),
        })?;
    let harness_effect_proof =
        harness_proof
            .checked_add(1)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis proof identities",
                limit: u64::from(u32::MAX),
            })?;
    let harness_closed_proof =
        harness_proof
            .checked_add(2)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis proof identities",
                limit: u64::from(u32::MAX),
            })?;
    if harness.id.0 as usize != source_function_count
        || graph.entry != harness.id
        || harness.origin != (FunctionOrigin::GeneratedTestHarness { group: root_group })
        || harness.role != FunctionRole::ImageEntry
        || harness.color != wrela_hir::FunctionColor::Sync
        || !harness.generic_arguments.is_empty()
        || !harness.parameters.is_empty()
        || harness.result != wrela_sema::SemanticTypeId(0)
        || harness.effects != wrela_sema::EffectSet(wrela_sema::EffectSet::FIRMWARE)
        || harness.source.is_some()
        || harness.stack_bytes_bound != 0
        || harness.frame_bytes_bound != 0
        || harness
            .uninterrupted_work_bound
            .is_none_or(|bound| bound == 0)
        || harness.recursive_depth_bound != Some(1)
        || harness.proofs.as_slice()
            != [
                wrela_sema::ProofId(harness_proof),
                wrela_sema::ProofId(harness_effect_proof),
                wrela_sema::ProofId(harness_closed_proof),
            ]
        || !matches!(
            facts
                .proofs
                .get(harness_proof as usize)
                .map(|proof| &proof.kind),
            Some(ProofKind::TypeChecked)
        )
        || !matches!(
            facts
                .proofs
                .get(harness_effect_proof as usize)
                .map(|proof| &proof.kind),
            Some(ProofKind::EffectsAllowed)
        )
        || !matches!(
            facts
                .proofs
                .get(harness_closed_proof as usize)
                .map(|proof| &proof.kind),
            Some(ProofKind::ImageClosed)
        )
    {
        return Err(unsupported("noncanonical generated test harness entry"));
    }
    validate_scalar_runtime_facts(facts, source_function_count, limits, is_cancelled)?;
    Ok(reachable_declarations)
}

fn retain_reachable_declaration(
    declarations: &mut Vec<wrela_hir::DeclarationId>,
    declaration: wrela_hir::DeclarationId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    for existing in declarations.iter() {
        check_cancelled(is_cancelled)?;
        if *existing == declaration {
            return Ok(());
        }
    }
    declarations.push(declaration);
    Ok(())
}

fn validate_scalar_source_function(
    facts: &PartialAnalysis,
    function: &wrela_sema::FunctionInstance,
    first_proof: u32,
) -> Result<(), AnalysisFactAssemblyError> {
    let second_proof =
        first_proof
            .checked_add(1)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis proof identities",
                limit: u64::from(u32::MAX),
            })?;
    if function.color != wrela_hir::FunctionColor::Sync
        || !function.generic_arguments.is_empty()
        || !is_runtime_value_type(facts, function.result)
        || function.effects != wrela_sema::EffectSet(0)
        || function.stack_bytes_bound != 0
        || function.frame_bytes_bound != 0
        || function
            .uninterrupted_work_bound
            .is_none_or(|bound| bound == 0)
        || function.recursive_depth_bound != Some(1)
        || function.source.is_none()
        || function
            .parameters
            .iter()
            .any(|parameter| !is_runtime_value_type(facts, parameter.ty))
        || function.proofs.as_slice()
            != [
                wrela_sema::ProofId(first_proof),
                wrela_sema::ProofId(second_proof),
            ]
        || !matches!(
            facts
                .proofs
                .get(first_proof as usize)
                .map(|proof| &proof.kind),
            Some(ProofKind::TypeChecked)
        )
        || !matches!(
            facts
                .proofs
                .get(second_proof as usize)
                .map(|proof| &proof.kind),
            Some(ProofKind::EffectsAllowed)
        )
    {
        return Err(unsupported(
            "source functions outside the synchronous bounded-value subset",
        ));
    }
    Ok(())
}

/// The callee of a direct or operator-desugared call resolution.
const fn scalar_call_target(
    resolution: &wrela_sema::ExpressionResolution,
) -> Option<wrela_sema::FunctionInstanceId> {
    match resolution {
        wrela_sema::ExpressionResolution::DirectCall {
            function: target, ..
        }
        | wrela_sema::ExpressionResolution::OperatorCall {
            function: target, ..
        } => Some(*target),
        _ => None,
    }
}

fn validate_scalar_runtime_facts(
    facts: &PartialAnalysis,
    source_function_count: usize,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    for value in &facts.values {
        check_cancelled(is_cancelled)?;
        if value.function.0 as usize >= source_function_count
            || value.category != wrela_sema::ValueCategory::Value
            || !is_runtime_value_type(facts, value.ty)
        {
            return Err(unsupported(
                "runtime values outside the bounded-value subset",
            ));
        }
    }
    for expression in &facts.expressions {
        check_cancelled(is_cancelled)?;
        let function = facts
            .functions
            .get(expression.function.0 as usize)
            .filter(|function| function.id == expression.function)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "runtime expression has a foreign function owner",
            ))?;
        let supported_resolution = supported_scalar_resolution(facts, expression, is_cancelled)?;
        if expression.function.0 as usize >= source_function_count
            || expression.category != wrela_sema::ValueCategory::Value
            || expression.region.is_some()
            || expression.effects != wrela_sema::EffectSet(0)
            || expression.ownership_before != wrela_sema::OwnershipState::Owned
            || !matches!(
                expression.ownership_after,
                wrela_sema::OwnershipState::Owned | wrela_sema::OwnershipState::Taken
            )
            || expression.proofs != function.proofs
            || expression.result.is_some_and(|result| {
                facts.values.get(result.0 as usize).is_none_or(|value| {
                    value.function != expression.function
                        || !matches!(
                            value.origin,
                            wrela_sema::SemanticValueOrigin::Expression(origin)
                                if origin == expression.expression
                        ) && !matches!(value.origin, wrela_sema::SemanticValueOrigin::Local(_))
                })
            })
            || !supported_resolution
        {
            return Err(unsupported(
                "runtime expressions outside bounded direct calls and flat structures",
            ));
        }
    }
    for statement in &facts.statements {
        check_cancelled(is_cancelled)?;
        let function = facts
            .functions
            .get(statement.function.0 as usize)
            .filter(|function| function.id == statement.function)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "runtime statement has a foreign function owner",
            ))?;
        let foreign_value = statement
            .definitions
            .iter()
            .map(|definition| definition.value)
            .chain(statement.initialized_after.iter().copied())
            .chain(statement.moved_after.iter().copied())
            .any(|value| {
                facts
                    .values
                    .get(value.0 as usize)
                    .is_none_or(|value| value.function != statement.function)
            });
        if statement.function.0 as usize >= source_function_count
            || statement.effects != wrela_sema::EffectSet(0)
            || !statement.live_loans_after.is_empty()
            || statement.proofs != function.proofs
            || foreign_value
        {
            return Err(unsupported(
                "runtime statements outside bounded-value ownership state",
            ));
        }
    }
    validate_scalar_call_graph(facts, source_function_count, limits, is_cancelled)
}

fn supported_scalar_resolution(
    facts: &PartialAnalysis,
    expression: &wrela_sema::ExpressionFact,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFactAssemblyError> {
    Ok(match &expression.resolution {
        wrela_sema::ExpressionResolution::Constant(constant) => {
            is_runtime_value_type(facts, expression.ty)
                && matches!(
                    constant,
                    wrela_sema::ConstantValue::Unit
                        | wrela_sema::ConstantValue::Bool(_)
                        | wrela_sema::ConstantValue::Unsigned {
                            bits: 8 | 16 | 32 | 64 | 128,
                            ..
                        }
                        | wrela_sema::ConstantValue::Signed {
                            bits: 8 | 16 | 32 | 64 | 128,
                            ..
                        }
                )
        }
        wrela_sema::ExpressionResolution::Value(value) => {
            facts.values.get(value.0 as usize).is_some_and(|value| {
                value.function == expression.function
                    && value.ty == expression.ty
                    && is_runtime_value_type(facts, value.ty)
            })
        }
        wrela_sema::ExpressionResolution::Function(target) => facts
            .functions
            .get(target.0 as usize)
            .is_some_and(|function| {
                function.id == *target && function.role == FunctionRole::Ordinary
            }),
        wrela_sema::ExpressionResolution::DirectCall {
            function: target,
            arguments,
        } => facts
            .functions
            .get(target.0 as usize)
            .is_some_and(|function| {
                function.id == *target
                    && function.role == FunctionRole::Ordinary
                    && arguments.len() == function.parameters.len()
                    && function.result == expression.ty
                    && is_runtime_value_type(facts, expression.ty)
            }),
        // A desugared `core.ops` operator is a direct call plus the
        // raw-result/negate relation: without `negate` the call writes the
        // expression's own result; with `negate` (`<=`/`>=` only) the call
        // writes a distinct intermediate and the expression result is its
        // logical NOT.
        wrela_sema::ExpressionResolution::OperatorCall {
            function: target,
            arguments,
            raw_result,
            negate,
        } => facts
            .functions
            .get(target.0 as usize)
            .is_some_and(|function| {
                function.id == *target
                    && function.role == FunctionRole::Ordinary
                    && arguments.len() == function.parameters.len()
                    && function.result == expression.ty
                    && is_runtime_value_type(facts, expression.ty)
                    && facts.values.get(raw_result.0 as usize).is_some_and(|raw| {
                        raw.function == expression.function && raw.ty == function.result
                    })
                    && if *negate {
                        expression.result != Some(*raw_result)
                    } else {
                        expression.result == Some(*raw_result)
                    }
            }),
        wrela_sema::ExpressionResolution::Constructor { ty, variant: None } => {
            *ty == expression.ty && is_flat_runtime_structure(facts, *ty)
        }
        wrela_sema::ExpressionResolution::Field { index } => {
            if !is_stored_runtime_scalar(facts, expression.ty) {
                return Ok(false);
            }
            let mut matched = false;
            for ty in &facts.types {
                check_cancelled(is_cancelled)?;
                if is_flat_runtime_structure(facts, ty.id)
                    && matches!(
                        &ty.kind,
                        SemanticTypeKind::Structure { fields, .. }
                            if fields
                                .get(*index as usize)
                                .is_some_and(|field| field.ty == expression.ty)
                    )
                {
                    matched = true;
                    break;
                }
            }
            matched
        }
        _ => false,
    })
}

fn validate_scalar_call_graph(
    facts: &PartialAnalysis,
    source_function_count: usize,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let mut incoming = try_vec(
        source_function_count,
        "analysis scalar call graph",
        limits.items,
    )?;
    incoming.resize(source_function_count, 0u64);
    for expression in &facts.expressions {
        check_cancelled(is_cancelled)?;
        let Some(target) = scalar_call_target(&expression.resolution) else {
            continue;
        };
        let target = incoming.get_mut(target.0 as usize).ok_or(
            AnalysisFactAssemblyError::InvalidSemanticFacts(
                "scalar call graph has a foreign target",
            ),
        )?;
        *target = target
            .checked_add(1)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis scalar call graph",
                limit: limits.items,
            })?;
    }
    for function in &facts.functions[..source_function_count] {
        check_cancelled(is_cancelled)?;
        if function.role == FunctionRole::Ordinary && incoming[function.id.0 as usize] == 0 {
            return Err(unsupported("unreachable scalar helper functions"));
        }
    }

    let mut ready = try_vec(
        source_function_count,
        "analysis scalar call graph",
        limits.items,
    )?;
    for (function, count) in incoming.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if *count == 0 {
            ready.push(function);
        }
    }
    let mut cursor = 0usize;
    while let Some(function) = ready.get(cursor).copied() {
        cursor = cursor
            .checked_add(1)
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis scalar call graph",
                limit: limits.items,
            })?;
        let start = facts
            .expressions
            .partition_point(|expression| (expression.function.0 as usize) < function);
        let end = facts
            .expressions
            .partition_point(|expression| (expression.function.0 as usize) <= function);
        for expression in &facts.expressions[start..end] {
            check_cancelled(is_cancelled)?;
            let Some(target) = scalar_call_target(&expression.resolution) else {
                continue;
            };
            let count = incoming.get_mut(target.0 as usize).ok_or(
                AnalysisFactAssemblyError::InvalidSemanticFacts(
                    "scalar call graph has a foreign target",
                ),
            )?;
            *count =
                count
                    .checked_sub(1)
                    .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                        "scalar call graph indegree is inconsistent",
                    ))?;
            if *count == 0 {
                ready.push(target.0 as usize);
            }
        }
    }
    if cursor != source_function_count {
        return Err(unsupported("recursive scalar helper calls"));
    }
    Ok(())
}

fn is_runtime_value_type(facts: &PartialAnalysis, id: wrela_sema::SemanticTypeId) -> bool {
    let Some(ty) = facts.types.get(id.0 as usize).filter(|ty| ty.id == id) else {
        return false;
    };
    match ty.kind {
        SemanticTypeKind::Unit => {
            id == wrela_sema::SemanticTypeId(0)
                && ty.linearity == Linearity::ScalarCopy
                && ty.size_upper_bound == Some(0)
                && ty.alignment_lower_bound == 1
                && ty.source.is_none()
        }
        SemanticTypeKind::Bool | SemanticTypeKind::Integer { .. } => {
            is_stored_runtime_scalar(facts, id)
        }
        SemanticTypeKind::Structure { .. } => is_flat_runtime_structure(facts, id),
        _ => false,
    }
}

fn is_stored_runtime_scalar(facts: &PartialAnalysis, id: wrela_sema::SemanticTypeId) -> bool {
    let Some(ty) = facts.types.get(id.0 as usize).filter(|ty| ty.id == id) else {
        return false;
    };
    if ty.linearity != Linearity::ScalarCopy || ty.source.is_some() {
        return false;
    }
    let (size, alignment) = match ty.kind {
        SemanticTypeKind::Bool => (1_u64, 1_u32),
        SemanticTypeKind::Integer {
            bits,
            pointer_sized,
            ..
        } if (!pointer_sized && matches!(bits, 8 | 16 | 32 | 64 | 128))
            || (pointer_sized && bits == 64) =>
        {
            let bytes = u64::from(bits / 8);
            let Ok(alignment) = u32::try_from(bytes) else {
                return false;
            };
            (bytes, alignment)
        }
        _ => return false,
    };
    ty.size_upper_bound == Some(size) && ty.alignment_lower_bound == alignment
}

fn is_flat_runtime_structure(facts: &PartialAnalysis, id: wrela_sema::SemanticTypeId) -> bool {
    let Some(ty) = facts.types.get(id.0 as usize).filter(|ty| ty.id == id) else {
        return false;
    };
    let SemanticTypeKind::Structure { arguments, .. } = &ty.kind else {
        return false;
    };
    arguments.is_empty()
        && matches!(
            ty.linearity,
            Linearity::ExplicitCopy | Linearity::ScalarCopy
        )
        && ty.source.is_some()
}

fn validate_flat_runtime_structure(
    facts: &PartialAnalysis,
    id: wrela_sema::SemanticTypeId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFactAssemblyError> {
    let Some(ty) = facts.types.get(id.0 as usize).filter(|ty| ty.id == id) else {
        return Ok(false);
    };
    let SemanticTypeKind::Structure { fields, .. } = &ty.kind else {
        return Ok(false);
    };
    if !is_flat_runtime_structure(facts, id) {
        return Ok(false);
    }
    let mut size = 0_u64;
    let mut alignment = 1_u32;
    for field in fields {
        check_cancelled(is_cancelled)?;
        let Some(field_ty) = facts
            .types
            .get(field.ty.0 as usize)
            .filter(|field_ty| field_ty.id == field.ty)
        else {
            return Ok(false);
        };
        if !is_stored_runtime_scalar(facts, field.ty) {
            return Ok(false);
        }
        let Some(field_size) = field_ty.size_upper_bound else {
            return Ok(false);
        };
        let field_alignment = field_ty.alignment_lower_bound;
        let Some(mask) = u64::from(field_alignment).checked_sub(1) else {
            return Ok(false);
        };
        let Some(aligned) = size.checked_add(mask).map(|value| value & !mask) else {
            return Ok(false);
        };
        let Some(next_size) = aligned.checked_add(field_size) else {
            return Ok(false);
        };
        size = next_size;
        alignment = alignment.max(field_alignment);
    }
    let Some(mask) = u64::from(alignment).checked_sub(1) else {
        return Ok(false);
    };
    let Some(size) = size.checked_add(mask).map(|value| value & !mask) else {
        return Ok(false);
    };
    Ok(ty.size_upper_bound == Some(size) && ty.alignment_lower_bound == alignment)
}

fn preflight_projection(
    projection: &SupportedProjection<'_>,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let mut budget = Budget::new(limits);

    // These strings are retained by the report sealer alongside the facts,
    // so they participate in the producer's allocation bound even though the
    // report schema measures fact payload separately.
    budget.text(&projection.graph.name)?;
    budget.text(projection.semantic.build.target.as_str())?;

    let (static_source, peak_source, stack_source, frame_source) = match projection.kind {
        ProjectionKind::Scalar => (
            "FlowWir.static_bytes",
            "FlowWir.peak_bytes",
            "FlowFunction.stack_bound",
            "FlowFunction.frame_bound",
        ),
        ProjectionKind::Actor => (
            "Semantic.ImageGraph.static_bytes",
            "Semantic.ImageGraph.peak_bytes",
            "Semantic.FunctionInstance.stack_bytes_bound",
            "Semantic.FunctionInstance.frame_bytes_bound",
        ),
    };
    for (category, owner, source, unit) in [
        (
            "image-static-memory",
            projection.graph.name.as_str(),
            static_source,
            "bytes",
        ),
        (
            "image-peak-memory",
            projection.graph.name.as_str(),
            peak_source,
            "bytes",
        ),
    ] {
        budget.item()?;
        for value in [category, owner, source, unit] {
            budget.text(value)?;
        }
    }

    for function in &projection.semantic.functions {
        check_cancelled(is_cancelled)?;
        let owner = function_owner(function, &mut budget)?;
        for (category, source) in [
            ("function-stack", stack_source),
            ("function-frame", frame_source),
        ] {
            budget.item()?;
            for value in [category, owner.as_str(), source, "bytes"] {
                budget.text(value)?;
            }
        }
        budget.item()?;
    }

    if projection.kind == ProjectionKind::Actor {
        preflight_actor_facts(projection, &mut budget, is_cancelled)?;
    }

    for proof in &projection.semantic.proofs {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        for value in [
            proof_kind_name(&proof.kind),
            proof.subject.as_str(),
            "proved",
        ] {
            budget.text(value)?;
        }
        for source in &proof.sources {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
            let _ = source_identity(*source, &mut budget)?;
        }
        for _dependency in &proof.depends_on {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
        }
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
            budget.text(line)?;
        }
    }

    for owner in &projection.graph.startup_order {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        let _ = image_owner_identity(projection.graph, *owner, &mut budget)?;
    }
    for owner in &projection.graph.shutdown_order {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        let _ = image_owner_identity(projection.graph, *owner, &mut budget)?;
    }
    budget_compiled_group(
        projection.semantic.compiled_test_group.as_ref(),
        &mut budget,
    )?;
    check_cancelled(is_cancelled)
}

fn preflight_actor_facts(
    projection: &SupportedProjection<'_>,
    budget: &mut Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AnalysisFactAssemblyError> {
    let graph = projection.graph;
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        let identity = actor_identity(actor, budget)?;
        budget.item()?;
        for value in [
            "actor-mailbox",
            identity.as_str(),
            "Semantic.ActorNode.mailbox_capacity",
            "messages",
        ] {
            budget.text(value)?;
        }
        let _source = source_identity(actor.source, budget)?;
        budget.item()?;
        for value in ["actor", "runtime"] {
            budget.text(value)?;
        }
    }
    for task in &graph.tasks {
        check_cancelled(is_cancelled)?;
        let identity = task_identity(task, budget)?;
        budget.item()?;
        for value in [
            "task-slots",
            identity.as_str(),
            "Semantic.TaskNode.slots",
            "slots",
        ] {
            budget.text(value)?;
        }
        budget.item()?;
        for value in [
            "task-frame",
            identity.as_str(),
            "Semantic.FunctionInstance.frame_bytes_bound",
            "bytes",
        ] {
            budget.text(value)?;
        }
        let owner = task
            .supervisor
            .map_or(ImageOwner::Runtime, ImageOwner::Actor);
        let owner_identity = image_owner_identity(graph, owner, budget)?;
        let _source = source_identity(task.source, budget)?;
        budget.item()?;
        for value in ["task", identity.as_str(), owner_identity.as_str()] {
            budget.text(value)?;
        }
        budget.item()?;
        budget.text("task-supervision")?;
    }
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        let identity = region_identity(region, budget)?;
        budget.item()?;
        for value in [
            "region-capacity",
            identity.as_str(),
            "Semantic.Region.capacity_bytes",
            "bytes",
        ] {
            budget.text(value)?;
        }
        budget.item()?;
        for value in [
            "region-alignment",
            identity.as_str(),
            "Semantic.Region.alignment",
            "bytes",
        ] {
            budget.text(value)?;
        }
        let _owner = image_owner_identity(graph, region.owner, budget)?;
        let _source = source_identity(region.source, budget)?;
        budget.item()?;
        budget.text(actor_region_kind(region)?)?;
        budget.item()?;
        budget.text(&identity)?;
    }
    Ok(())
}

fn assemble_projection(
    projection: &SupportedProjection<'_>,
    limits: wrela_image_report::AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisFacts, AnalysisFactAssemblyError> {
    let mut budget = Budget::new(limits);

    let actor_bound_count = if projection.kind == ProjectionKind::Actor {
        projection
            .graph
            .actors
            .len()
            .checked_add(projection.graph.tasks.len().checked_mul(2).ok_or(
                AnalysisFactAssemblyError::ResourceLimit {
                    resource: "analysis bounds",
                    limit: limits.items,
                },
            )?)
            .and_then(|count| count.checked_add(projection.graph.regions.len().checked_mul(2)?))
            .ok_or(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis bounds",
                limit: limits.items,
            })?
    } else {
        0
    };
    let bound_count = projection
        .semantic
        .functions
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .and_then(|count| count.checked_add(actor_bound_count))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis bounds",
            limit: limits.items,
        })?;
    let mut bounds = try_vec(bound_count, "analysis bounds", limits.items)?;
    let (static_source, peak_source, stack_source, frame_source) = match projection.kind {
        ProjectionKind::Scalar => (
            "FlowWir.static_bytes",
            "FlowWir.peak_bytes",
            "FlowFunction.stack_bound",
            "FlowFunction.frame_bound",
        ),
        ProjectionKind::Actor => (
            "Semantic.ImageGraph.static_bytes",
            "Semantic.ImageGraph.peak_bytes",
            "Semantic.FunctionInstance.stack_bytes_bound",
            "Semantic.FunctionInstance.frame_bytes_bound",
        ),
    };
    bounds.push(bound(
        "image-static-memory",
        &projection.graph.name,
        static_source,
        projection.graph.static_bytes,
        "bytes",
        &mut budget,
    )?);
    bounds.push(bound(
        "image-peak-memory",
        &projection.graph.name,
        peak_source,
        projection.graph.peak_bytes,
        "bytes",
        &mut budget,
    )?);
    let mut work = try_vec(
        projection.semantic.functions.len(),
        "analysis work facts",
        limits.items,
    )?;
    for function in &projection.semantic.functions {
        check_cancelled(is_cancelled)?;
        let owner = function_owner(function, &mut budget)?;
        bounds.push(bound(
            "function-stack",
            &owner,
            stack_source,
            function.stack_bytes_bound,
            "bytes",
            &mut budget,
        )?);
        bounds.push(bound(
            "function-frame",
            &owner,
            frame_source,
            function.frame_bytes_bound,
            "bytes",
            &mut budget,
        )?);
        budget.item()?;
        work.push(WorkFact {
            function: owner,
            stack_bytes: function.stack_bytes_bound,
            frame_bytes: function.frame_bytes_bound,
            // Actor source functions retain their proven semantic work bound.
            // Scalar report behavior remains unchanged until FlowWir exposes
            // checkpoint facts for that established path.
            uninterrupted_work: (projection.kind == ProjectionKind::Actor)
                .then_some(function.uninterrupted_work_bound)
                .flatten(),
            checkpoint_count: 0,
        });
    }

    let actor_facts = if projection.kind == ProjectionKind::Actor {
        assemble_actor_facts(projection, &mut bounds, &mut budget, is_cancelled)?
    } else {
        ActorReportFacts::default()
    };

    let mut proofs = try_vec(
        projection.semantic.proofs.len(),
        "analysis proofs",
        limits.items,
    )?;
    for proof in &projection.semantic.proofs {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        let mut sources = try_vec(
            proof.sources.len(),
            "analysis proof sources",
            limits.proof_edges,
        )?;
        for source in &proof.sources {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
            sources.push(source_identity(*source, &mut budget)?);
        }
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "analysis proof dependencies",
            limits.proof_edges,
        )?;
        for dependency in &proof.depends_on {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
            depends_on.push(dependency.0);
        }
        let mut why_chain = try_vec(
            proof.explanation.len(),
            "analysis proof edges",
            limits.proof_edges,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            budget.proof_edge()?;
            why_chain.push(copy_text(line, &mut budget)?);
        }
        proofs.push(ProofFact {
            id: proof.id.0,
            category: copy_text(proof_kind_name(&proof.kind), &mut budget)?,
            subject: copy_text(&proof.subject, &mut budget)?,
            result: copy_text("proved", &mut budget)?,
            bound: proof.bound,
            sources,
            depends_on,
            why_chain,
        });
    }

    let mut startup_order = try_vec(
        projection.graph.startup_order.len(),
        "analysis startup order",
        limits.items,
    )?;
    for owner in &projection.graph.startup_order {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        startup_order.push(image_owner_identity(projection.graph, *owner, &mut budget)?);
    }
    let mut shutdown_order = try_vec(
        projection.graph.shutdown_order.len(),
        "analysis shutdown order",
        limits.items,
    )?;
    for owner in &projection.graph.shutdown_order {
        check_cancelled(is_cancelled)?;
        budget.item()?;
        shutdown_order.push(image_owner_identity(projection.graph, *owner, &mut budget)?);
    }
    budget_compiled_group(
        projection.semantic.compiled_test_group.as_ref(),
        &mut budget,
    )?;
    check_cancelled(is_cancelled)?;

    Ok(AnalysisFacts {
        // Revision 0.1 defines this as distinct HIR declaration IDs retained
        // in runtime provenance. The minimum retains its constructor.
        reachable_declarations: projection.reachable_declarations,
        monomorphized_instantiations: u64::try_from(projection.semantic.functions.len()).map_err(
            |_| AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis function facts",
                limit: limits.items,
            },
        )?,
        resolved_interface_calls: 0,
        bounds,
        proofs,
        actor_lowerings: Vec::new(),
        image_nodes: actor_facts.image_nodes,
        region_capacity_evidence: actor_facts.region_capacity_evidence,
        // Source semantic facts precede activation lowering. The backend adds
        // exact FlowWir ActivationPlan evidence after that sealed boundary.
        activation_frame_evidence: Vec::new(),
        image_edges: actor_facts.image_edges,
        work,
        hardware: Vec::new(),
        recovery: Vec::new(),
        // Copy the sealed group verbatim. Reconstructing it from a root name
        // or function origin would lose declared scenarios and plan policy.
        compiled_test_group: projection.semantic.compiled_test_group.clone(),
        startup_order,
        shutdown_order,
    })
}

fn assemble_actor_facts(
    projection: &SupportedProjection<'_>,
    bounds: &mut Vec<BoundFact>,
    budget: &mut Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ActorReportFacts, AnalysisFactAssemblyError> {
    let graph = projection.graph;
    let node_count = graph
        .actors
        .len()
        .checked_add(graph.tasks.len())
        .and_then(|count| count.checked_add(graph.regions.len()))
        .ok_or_else(|| budget.resource("analysis fact items"))?;
    let mut nodes = try_vec(node_count, "analysis image nodes", budget.limits.items)?;
    let mut edges = try_vec(
        graph.tasks.len(),
        "analysis image edges",
        budget.limits.items,
    )?;
    let mut region_capacity_evidence = try_vec(
        graph.regions.len(),
        "analysis region capacity evidence",
        budget.limits.items,
    )?;
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        let identity = actor_identity(actor, budget)?;
        bounds.push(bound(
            "actor-mailbox",
            &identity,
            "Semantic.ActorNode.mailbox_capacity",
            u64::from(actor.mailbox_capacity),
            "messages",
            budget,
        )?);
        let source = source_identity(actor.source, budget)?;
        budget.item()?;
        nodes.push(ImageNodeFact {
            kind: copy_text("actor", budget)?,
            name: identity,
            owner: copy_text("runtime", budget)?,
            source,
            static_bytes: 0,
        });
    }
    for task in &graph.tasks {
        check_cancelled(is_cancelled)?;
        let identity = task_identity(task, budget)?;
        bounds.push(bound(
            "task-slots",
            &identity,
            "Semantic.TaskNode.slots",
            u64::from(task.slots),
            "slots",
            budget,
        )?);
        let entry = projection
            .semantic
            .functions
            .get(task.entry.0 as usize)
            .filter(|entry| entry.id == task.entry)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "task frame source function is absent",
            ))?;
        bounds.push(bound(
            "task-frame",
            &identity,
            "Semantic.FunctionInstance.frame_bytes_bound",
            entry.frame_bytes_bound,
            "bytes",
            budget,
        )?);
        let owner = task
            .supervisor
            .map_or(ImageOwner::Runtime, ImageOwner::Actor);
        let owner = image_owner_identity(graph, owner, budget)?;
        let source = source_identity(task.source, budget)?;
        budget.item()?;
        nodes.push(ImageNodeFact {
            kind: copy_text("task", budget)?,
            name: copy_text(&identity, budget)?,
            owner: copy_text(&owner, budget)?,
            source,
            static_bytes: 0,
        });
        budget.item()?;
        edges.push(ImageEdgeFact {
            kind: copy_text("task-supervision", budget)?,
            source: identity,
            destination: owner,
            capacity: Some(u64::from(task.slots)),
            priority: Some(task.priority),
        });
    }
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        let identity = region_identity(region, budget)?;
        bounds.push(bound(
            "region-capacity",
            &identity,
            "Semantic.Region.capacity_bytes",
            region.capacity_bytes,
            "bytes",
            budget,
        )?);
        bounds.push(bound(
            "region-alignment",
            &identity,
            "Semantic.Region.alignment",
            u64::from(region.alignment),
            "bytes",
            budget,
        )?);
        let owner = image_owner_identity(graph, region.owner, budget)?;
        let source = source_identity(region.source, budget)?;
        budget.item()?;
        region_capacity_evidence.push(RegionCapacityEvidenceFact {
            region: copy_text(&identity, budget)?,
            capacity_proof: region.proof.0,
        });
        budget.item()?;
        nodes.push(ImageNodeFact {
            kind: copy_text(actor_region_kind(region)?, budget)?,
            name: identity,
            owner,
            source,
            static_bytes: region.capacity_bytes,
        });
    }
    Ok(ActorReportFacts {
        image_nodes: nodes,
        image_edges: edges,
        region_capacity_evidence,
    })
}

fn seal_projection(
    projection: &SupportedProjection<'_>,
    request: ReportRequest<'_>,
    facts: AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedAnalysisFacts, AnalysisFactAssemblyError> {
    if request.build != &projection.semantic.build || request.image_name != projection.graph.name {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "analysis report request differs from the sealed semantic image",
        ));
    }
    let limits = request.limits;
    let sealed = seal_analysis_facts(request, facts, is_cancelled)?;
    if sealed.build() != &projection.semantic.build
        || sealed.image_name() != projection.graph.name
        || sealed.limits() != limits
        || !projection_matches(projection, sealed.as_facts(), is_cancelled)?
    {
        return Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "sealed public facts differ from the semantic image",
        ));
    }
    Ok(sealed)
}

fn projection_matches(
    projection: &SupportedProjection<'_>,
    facts: &AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFactAssemblyError> {
    let graph = projection.graph;
    let semantic = projection.semantic;
    let actor_bound_count = if projection.kind == ProjectionKind::Actor {
        graph
            .tasks
            .len()
            .checked_mul(2)
            .and_then(|tasks| graph.actors.len().checked_add(tasks))
            .and_then(|count| count.checked_add(graph.regions.len().checked_mul(2)?))
    } else {
        Some(0)
    };
    let expected_bounds = semantic
        .functions
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .and_then(|count| count.checked_add(actor_bound_count?));
    let (static_source, peak_source, stack_source, frame_source) = match projection.kind {
        ProjectionKind::Scalar => (
            "FlowWir.static_bytes",
            "FlowWir.peak_bytes",
            "FlowFunction.stack_bound",
            "FlowFunction.frame_bound",
        ),
        ProjectionKind::Actor => (
            "Semantic.ImageGraph.static_bytes",
            "Semantic.ImageGraph.peak_bytes",
            "Semantic.FunctionInstance.stack_bytes_bound",
            "Semantic.FunctionInstance.frame_bytes_bound",
        ),
    };
    let mut bounds_match = expected_bounds == Some(facts.bounds.len())
        && facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "image-static-memory",
                &graph.name,
                static_source,
                graph.static_bytes,
                "bytes",
            )
        })
        && facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "image-peak-memory",
                &graph.name,
                peak_source,
                graph.peak_bytes,
                "bytes",
            )
        });
    let mut work_matches = facts.work.len() == semantic.functions.len();
    for function in &semantic.functions {
        check_cancelled(is_cancelled)?;
        let owner = raw_function_owner(function, u64::MAX)?;
        bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "function-stack",
                &owner,
                stack_source,
                function.stack_bytes_bound,
                "bytes",
            )
        }) && facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "function-frame",
                &owner,
                frame_source,
                function.frame_bytes_bound,
                "bytes",
            )
        });
        work_matches &= facts.work.iter().any(|fact| {
            fact.function == owner
                && fact.stack_bytes == function.stack_bytes_bound
                && fact.frame_bytes == function.frame_bytes_bound
                && fact.uninterrupted_work
                    == if projection.kind == ProjectionKind::Actor {
                        function.uninterrupted_work_bound
                    } else {
                        None
                    }
                && fact.checkpoint_count == 0
        });
    }
    let proof_headers_match = facts.proofs.len() == semantic.proofs.len();
    let mut proofs_match = proof_headers_match;
    if proofs_match {
        for (proof, projected) in semantic.proofs.iter().zip(&facts.proofs) {
            check_cancelled(is_cancelled)?;
            if !proof_matches(proof, projected, is_cancelled)? {
                proofs_match = false;
                break;
            }
        }
    }
    let actor_facts_match = if projection.kind == ProjectionKind::Actor {
        actor_projection_matches(projection, facts, &mut bounds_match, is_cancelled)?
    } else {
        facts.image_nodes.is_empty()
            && facts.image_edges.is_empty()
            && facts.region_capacity_evidence.is_empty()
    };
    Ok(
        facts.reachable_declarations == projection.reachable_declarations
            && u64::try_from(semantic.functions.len())
                .is_ok_and(|count| facts.monomorphized_instantiations == count)
            && facts.resolved_interface_calls == 0
            && bounds_match
            && proofs_match
            && facts.actor_lowerings.is_empty()
            && actor_facts_match
            && work_matches
            && facts.hardware.is_empty()
            && facts.recovery.is_empty()
            && facts.compiled_test_group == semantic.compiled_test_group
            && owner_order_matches(graph, &facts.startup_order, &graph.startup_order)?
            && owner_order_matches(graph, &facts.shutdown_order, &graph.shutdown_order)?,
    )
}

fn actor_projection_matches(
    projection: &SupportedProjection<'_>,
    facts: &AnalysisFacts,
    bounds_match: &mut bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFactAssemblyError> {
    let graph = projection.graph;
    let expected_nodes = graph
        .actors
        .len()
        .checked_add(graph.tasks.len())
        .and_then(|count| count.checked_add(graph.regions.len()));
    let mut nodes_match = expected_nodes == Some(facts.image_nodes.len());
    let mut edges_match = facts.image_edges.len() == graph.tasks.len();
    let mut region_capacity_evidence_match =
        facts.region_capacity_evidence.len() == graph.regions.len();
    for actor in &graph.actors {
        check_cancelled(is_cancelled)?;
        let identity = raw_actor_identity(actor, u64::MAX)?;
        let source = raw_source_identity(actor.source, u64::MAX)?;
        *bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "actor-mailbox",
                &identity,
                "Semantic.ActorNode.mailbox_capacity",
                u64::from(actor.mailbox_capacity),
                "messages",
            )
        });
        nodes_match &= facts.image_nodes.iter().any(|fact| {
            fact.kind == "actor"
                && fact.name == identity
                && fact.owner == "runtime"
                && fact.source == source
                && fact.static_bytes == 0
        });
    }
    for task in &graph.tasks {
        check_cancelled(is_cancelled)?;
        let identity = raw_task_identity(task, u64::MAX)?;
        let owner = task
            .supervisor
            .map_or(ImageOwner::Runtime, ImageOwner::Actor);
        let owner = raw_image_owner_identity(graph, owner, u64::MAX)?;
        let source = raw_source_identity(task.source, u64::MAX)?;
        *bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "task-slots",
                &identity,
                "Semantic.TaskNode.slots",
                u64::from(task.slots),
                "slots",
            )
        });
        let entry = projection
            .semantic
            .functions
            .get(task.entry.0 as usize)
            .filter(|entry| entry.id == task.entry)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "task frame source function is absent",
            ))?;
        *bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "task-frame",
                &identity,
                "Semantic.FunctionInstance.frame_bytes_bound",
                entry.frame_bytes_bound,
                "bytes",
            )
        });
        nodes_match &= facts.image_nodes.iter().any(|fact| {
            fact.kind == "task"
                && fact.name == identity
                && fact.owner == owner
                && fact.source == source
                && fact.static_bytes == 0
        });
        let destination = owner;
        let edge_source = identity;
        edges_match &= facts.image_edges.iter().any(|fact| {
            fact.kind == "task-supervision"
                && fact.source == edge_source
                && fact.destination == destination
                && fact.capacity == Some(u64::from(task.slots))
                && fact.priority == Some(task.priority)
        });
    }
    for region in &graph.regions {
        check_cancelled(is_cancelled)?;
        let identity = raw_region_identity(region, u64::MAX)?;
        let owner = raw_image_owner_identity(graph, region.owner, u64::MAX)?;
        let source = raw_source_identity(region.source, u64::MAX)?;
        let region_kind = actor_region_kind(region)?;
        *bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "region-capacity",
                &identity,
                "Semantic.Region.capacity_bytes",
                region.capacity_bytes,
                "bytes",
            )
        });
        *bounds_match &= facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "region-alignment",
                &identity,
                "Semantic.Region.alignment",
                u64::from(region.alignment),
                "bytes",
            )
        });
        nodes_match &= facts.image_nodes.iter().any(|fact| {
            fact.kind == region_kind
                && fact.name == identity
                && fact.owner == owner
                && fact.source == source
                && fact.static_bytes == region.capacity_bytes
        });
        region_capacity_evidence_match &= facts
            .region_capacity_evidence
            .iter()
            .any(|fact| fact.region == identity && fact.capacity_proof == region.proof.0);
    }
    Ok(nodes_match && edges_match && region_capacity_evidence_match)
}

fn owner_order_matches(
    graph: &wrela_sema::ImageGraph,
    actual: &[String],
    expected: &[ImageOwner],
) -> Result<bool, AnalysisFactAssemblyError> {
    if actual.len() != expected.len() {
        return Ok(false);
    }
    for (actual, expected) in actual.iter().zip(expected) {
        if actual != &raw_image_owner_identity(graph, *expected, u64::MAX)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn bound_matches(
    fact: &BoundFact,
    category: &str,
    owner: &str,
    source: &str,
    amount: u64,
    unit: &str,
) -> bool {
    fact.category == category
        && fact.owner == owner
        && fact.source == source
        && fact.amount == amount
        && fact.unit == unit
}

fn proof_matches(
    source: &wrela_sema::Proof,
    projected: &ProofFact,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, AnalysisFactAssemblyError> {
    if projected.id != source.id.0
        || projected.category != proof_kind_name(&source.kind)
        || projected.subject != source.subject
        || projected.result != "proved"
    {
        return Ok(false);
    }
    let mut why = projected.why_chain.iter().map(String::as_str);
    for explanation in &source.explanation {
        check_cancelled(is_cancelled)?;
        if why.next() != Some(explanation.as_str()) {
            return Ok(false);
        }
    }
    Ok(why.next().is_none())
}

fn bound(
    category: &str,
    owner: &str,
    source: &str,
    amount: u64,
    unit: &str,
    budget: &mut Budget,
) -> Result<BoundFact, AnalysisFactAssemblyError> {
    budget.item()?;
    Ok(BoundFact {
        category: copy_text(category, budget)?,
        owner: copy_text(owner, budget)?,
        source: copy_text(source, budget)?,
        amount,
        unit: copy_text(unit, budget)?,
    })
}

fn budget_compiled_group(
    group: Option<&wrela_test_model::FullImageTestGroup>,
    budget: &mut Budget,
) -> Result<(), AnalysisFactAssemblyError> {
    let Some(group) = group else {
        return Ok(());
    };
    budget.item()?;
    budget.text(&group.name)?;
    match &group.root {
        TestImageRoot::GeneratedHarness { harness_name } => budget.text(harness_name)?,
        TestImageRoot::Declared { image_name, .. } => budget.text(image_name)?,
    }
    for test in &group.tests {
        budget.item()?;
        budget.text(&test.descriptor.name)?;
    }
    Ok(())
}

fn proof_kind_name(kind: &ProofKind) -> &'static str {
    match kind {
        ProofKind::TypeChecked => "type-checked",
        ProofKind::EffectsAllowed => "effects-allowed",
        ProofKind::DefiniteInitialization => "definite-initialization",
        ProofKind::Ownership => "ownership",
        ProofKind::AccessExclusive => "access-exclusive",
        ProofKind::ViewDoesNotEscape => "view-does-not-escape",
        ProofKind::RegionBound => "region-bound",
        ProofKind::CapacityBound => "capacity-bound",
        ProofKind::WaitGraphAcyclic => "wait-graph-acyclic",
        ProofKind::CleanupAcyclic => "cleanup-acyclic",
        ProofKind::WorkBound => "work-bound",
        ProofKind::StackBound => "stack-bound",
        ProofKind::IsrSafe => "isr-safe",
        ProofKind::DmaTransition => "dma-transition",
        ProofKind::MmioPartition => "mmio-partition",
        ProofKind::DeviceValueValidated => "device-value-validated",
        ProofKind::WireLayout => "wire-layout",
        ProofKind::ReceiptLineage => "receipt-lineage",
        ProofKind::ActorAsIf => "actor-as-if",
        ProofKind::SupervisionComplete => "supervision-complete",
        ProofKind::ImageClosed => "image-closed",
    }
}

fn function_owner(
    function: &wrela_sema::FunctionInstance,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_function_owner(function, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_function_owner(
    function: &wrela_sema::FunctionInstance,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    raw_named_identity("function", u64::from(function.id.0), &function.name, limit)
}

fn actor_identity(
    actor: &wrela_sema::ActorNode,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_actor_identity(actor, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_actor_identity(
    actor: &wrela_sema::ActorNode,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    raw_named_identity("actor", u64::from(actor.id.0), &actor.name, limit)
}

fn task_identity(
    task: &wrela_sema::TaskNode,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_task_identity(task, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_task_identity(
    task: &wrela_sema::TaskNode,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    raw_named_identity("task", u64::from(task.id.0), &task.name, limit)
}

fn region_identity(
    region: &wrela_sema::Region,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_region_identity(region, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_region_identity(
    region: &wrela_sema::Region,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    raw_named_identity("region", u64::from(region.id.0), &region.name, limit)
}

fn actor_region_kind(
    region: &wrela_sema::Region,
) -> Result<&'static str, AnalysisFactAssemblyError> {
    match (region.owner, region.class) {
        (ImageOwner::Actor(_), RegionClass::Image) => Ok("actor-mailbox-region"),
        (ImageOwner::Actor(_), RegionClass::TaskFrame) => Ok("actor-turn-frame-region"),
        (ImageOwner::Task(_), RegionClass::TaskFrame) => Ok("task-frame-region"),
        _ => Err(AnalysisFactAssemblyError::InvalidSemanticFacts(
            "actor projection contains an unclassified region",
        )),
    }
}

fn raw_named_identity(
    kind: &str,
    id: u64,
    name: &str,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    let capacity = kind
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(decimal_digits(id)))
        .and_then(|value| value.checked_add(name.len()))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        })?;
    let mut text = String::new();
    text.try_reserve_exact(capacity)
        .map_err(|_| AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        })?;
    write!(text, "{kind}:{id}:{name}").map_err(|_| {
        AnalysisFactAssemblyError::InvalidSemanticFacts("analysis identity formatting failed")
    })?;
    Ok(text)
}

fn image_owner_identity(
    graph: &wrela_sema::ImageGraph,
    owner: ImageOwner,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_image_owner_identity(graph, owner, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_image_owner_identity(
    graph: &wrela_sema::ImageGraph,
    owner: ImageOwner,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    match owner {
        ImageOwner::Runtime => copy_raw_text("runtime", limit),
        ImageOwner::Actor(id) => graph
            .actors
            .get(id.0 as usize)
            .filter(|actor| actor.id == id)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "actor image owner is foreign",
            ))
            .and_then(|actor| raw_actor_identity(actor, limit)),
        ImageOwner::Task(id) => graph
            .tasks
            .get(id.0 as usize)
            .filter(|task| task.id == id)
            .ok_or(AnalysisFactAssemblyError::InvalidSemanticFacts(
                "task image owner is foreign",
            ))
            .and_then(|task| raw_task_identity(task, limit)),
        ImageOwner::Device(_) | ImageOwner::Pool(_) | ImageOwner::Artifact(_) => {
            Err(unsupported("image owners outside the actor/task slice"))
        }
    }
}

fn source_identity(
    source: wrela_source::Span,
    budget: &mut Budget,
) -> Result<String, AnalysisFactAssemblyError> {
    let output = raw_source_identity(source, budget.limits.payload_bytes)?;
    budget.text(&output)?;
    Ok(output)
}

fn raw_source_identity(
    source: wrela_source::Span,
    limit: u64,
) -> Result<String, AnalysisFactAssemblyError> {
    let capacity = "file::bytes:.."
        .len()
        .checked_add(decimal_digits(u64::from(source.file.0)))
        .and_then(|value| value.checked_add(decimal_digits(u64::from(source.range.start))))
        .and_then(|value| value.checked_add(decimal_digits(u64::from(source.range.end))))
        .ok_or(AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        })?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        })?;
    write!(
        output,
        "file:{}:bytes:{}..{}",
        source.file.0, source.range.start, source.range.end
    )
    .map_err(|_| {
        AnalysisFactAssemblyError::InvalidSemanticFacts("source identity formatting failed")
    })?;
    Ok(output)
}

fn copy_raw_text(value: &str, limit: u64) -> Result<String, AnalysisFactAssemblyError> {
    if u64::try_from(value.len()).map_or(true, |bytes| bytes > limit) {
        return Err(AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        });
    }
    let mut output = String::new();
    output.try_reserve_exact(value.len()).map_err(|_| {
        AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact payload",
            limit,
        }
    })?;
    output.push_str(value);
    Ok(output)
}

fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1usize;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn copy_text(value: &str, budget: &mut Budget) -> Result<String, AnalysisFactAssemblyError> {
    budget.text(value)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| budget.resource("analysis fact payload"))?;
    output.push_str(value);
    Ok(output)
}

fn try_vec<T>(
    capacity: usize,
    resource: &'static str,
    limit: u64,
) -> Result<Vec<T>, AnalysisFactAssemblyError> {
    if u64::try_from(capacity).map_or(true, |count| count > limit) {
        return Err(AnalysisFactAssemblyError::ResourceLimit { resource, limit });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| AnalysisFactAssemblyError::ResourceLimit { resource, limit })?;
    Ok(output)
}

struct Budget {
    limits: wrela_image_report::AnalysisFactLimits,
    items: u64,
    proof_edges: u64,
    payload_bytes: u64,
}

impl Budget {
    const fn new(limits: wrela_image_report::AnalysisFactLimits) -> Self {
        Self {
            limits,
            items: 0,
            proof_edges: 0,
            payload_bytes: 0,
        }
    }

    fn item(&mut self) -> Result<(), AnalysisFactAssemblyError> {
        self.items = self
            .items
            .checked_add(1)
            .ok_or_else(|| self.resource("analysis fact items"))?;
        if self.items > self.limits.items {
            return Err(self.resource("analysis fact items"));
        }
        Ok(())
    }

    fn proof_edge(&mut self) -> Result<(), AnalysisFactAssemblyError> {
        self.proof_edges = self
            .proof_edges
            .checked_add(1)
            .ok_or_else(|| self.resource("analysis proof edges"))?;
        if self.proof_edges > self.limits.proof_edges {
            return Err(self.resource("analysis proof edges"));
        }
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), AnalysisFactAssemblyError> {
        self.text_bytes(value.len())
    }

    fn text_bytes(&mut self, bytes: usize) -> Result<(), AnalysisFactAssemblyError> {
        self.payload_bytes = self
            .payload_bytes
            .checked_add(u64::try_from(bytes).map_err(|_| self.resource("analysis fact payload"))?)
            .ok_or_else(|| self.resource("analysis fact payload"))?;
        if self.payload_bytes > self.limits.payload_bytes {
            return Err(self.resource("analysis fact payload"));
        }
        Ok(())
    }

    fn resource(&self, resource: &'static str) -> AnalysisFactAssemblyError {
        let limit = match resource {
            "analysis fact items" => self.limits.items,
            "analysis proof edges" => self.limits.proof_edges,
            _ => self.limits.payload_bytes,
        };
        AnalysisFactAssemblyError::ResourceLimit { resource, limit }
    }
}

fn unsupported(feature: &'static str) -> AnalysisFactAssemblyError {
    AnalysisFactAssemblyError::UnsupportedInput { feature }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), AnalysisFactAssemblyError> {
    if is_cancelled() {
        Err(AnalysisFactAssemblyError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Arc};

    use super::*;
    use wrela_build_model::{
        BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
        TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
    };
    use wrela_hir::{
        AggregateDeclaration, AssignmentOperator, Attribute, AttributeIdentity, Body, BodyId,
        BodyOwner, BuiltinAttribute, CallArgument, Declaration, DeclarationId, DeclarationKind,
        DeclarationOwner, Definition, EnumDeclaration, EnumVariant, Expression, ExpressionId,
        ExpressionKind, ExpressionOwner, FunctionColor, FunctionDeclaration, LexicalScope, Literal,
        Local, Module, Name, PlaceTarget, Program, ResolvedDeclaration, ResolvedVariant, Statement,
        StatementId, StatementKind, TypeExpression, TypeExpressionKind, ValidatedProgram,
        Visibility,
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
        AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, AnalysisRoot,
        CanonicalSemanticAnalyzer, EffectSet, FunctionInstance, FunctionInstanceId, FunctionOrigin,
        FunctionRole, HirSummary, ImageGraph, ImageOwner, Linearity, PartialAnalysis, Proof,
        ProofId, SemanticAnalyzer, SemanticArgument, SemanticField, SemanticType, SemanticTypeId,
        SemanticTypeKind, TestDiscoverySelection,
    };
    use wrela_semantic_lower::{
        CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
        LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
    };
    use wrela_source::{FileId, SourceDatabase, SourceInput, Span, TextRange};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
    use wrela_target::TargetPackage;
    use wrela_test_model::{
        DeclaredImageTest, FunctionKey, ImageRoot, ImageScenario, ImageScenarioStep, ScenarioId,
    };

    const STANDARD_LIBRARY_PACKAGE_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0x21; 32]);
    const STANDARD_LIBRARY_COMPONENT_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0x22; 32]);
    const TARGET_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0x23; 32]);
    const PARSED_CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
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

    struct ProducerFixture {
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
        Name::new(value.to_owned()).expect("fixture name")
    }

    fn package_identity(name: &str, digest: Sha256Digest) -> PackageIdentity {
        PackageIdentity {
            name: PackageName::new(name).expect("package name"),
            version: PackageVersion::new("1.0.0").expect("package version"),
            source_digest: digest,
        }
    }

    fn producer_fixture() -> ProducerFixture {
        let root_path = ModulePath::new(["app".to_owned()]).expect("root path");
        let standard_path = ModulePath::new(["prelude".to_owned()]).expect("standard path");
        let mut packages = PackageGraphBuilder::new(package_identity(
            "root",
            Sha256Digest::from_bytes([0x20; 32]),
        ));
        let standard = packages
            .add_package(package_identity(
                "wrela-std",
                STANDARD_LIBRARY_PACKAGE_DIGEST,
            ))
            .expect("standard package");
        packages
            .add_dependency(
                packages.root(),
                DependencyAlias::new("core").expect("dependency alias"),
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

        let image_type = ResolvedDeclaration {
            package: PackageId(1),
            module: ModuleId(1),
            declaration: DeclarationId(1),
        };
        let target_type = ResolvedDeclaration {
            package: PackageId(1),
            module: ModuleId(1),
            declaration: DeclarationId(2),
        };
        let program = Program {
            packages,
            modules: vec![
                Module {
                    id: ModuleId(0),
                    package: PackageId(0),
                    path: root_path,
                    declarations: vec![DeclarationId(0), DeclarationId(3)],
                    reexports: Vec::new(),
                    source: span(0, 0, 400),
                },
                Module {
                    id: ModuleId(1),
                    package: PackageId(1),
                    path: standard_path,
                    declarations: vec![DeclarationId(1), DeclarationId(2)],
                    reexports: Vec::new(),
                    source: span(1, 0, 200),
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
                                definition: Definition::Declaration(image_type.clone()),
                                arguments: Vec::new(),
                            },
                            source: span(0, 7, 12),
                        }),
                        body: Some(BodyId(0)),
                    }),
                    source: span(0, 0, 180),
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
                    source: span(0, 210, 300),
                },
            ],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![
                Body {
                    id: BodyId(0),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: wrela_hir::ScopeId(0),
                    locals: Vec::new(),
                    statements: vec![StatementId(0)],
                    source: span(0, 20, 180),
                },
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(3)),
                    scope: wrela_hir::ScopeId(1),
                    locals: vec![wrela_hir::LocalId(0)],
                    statements: vec![StatementId(1), StatementId(2)],
                    source: span(0, 220, 290),
                },
                // `runtime_case`'s body is a bounded `while` (not a bare
                // `pass`): a trivial `pass` body is structurally within the
                // static comptime-legality checker's supported subset, so it
                // would be silently misrouted into the comptime tier instead
                // of exercising the generated runtime/image test harness
                // this fixture's callers expect. A bounded `while` is
                // unsupported by the static checker but fully supported by
                // the runtime-shape checker, so it deterministically stays
                // selectable as a runtime test.
                Body {
                    id: BodyId(2),
                    owner: BodyOwner::Declaration(DeclarationId(3)),
                    scope: wrela_hir::ScopeId(2),
                    locals: Vec::new(),
                    statements: vec![StatementId(3)],
                    source: span(0, 270, 289),
                },
            ],
            scopes: vec![
                LexicalScope {
                    id: wrela_hir::ScopeId(0),
                    body: BodyId(0),
                    parent: None,
                    source: span(0, 20, 180),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(1),
                    body: BodyId(1),
                    parent: None,
                    source: span(0, 220, 290),
                },
                LexicalScope {
                    id: wrela_hir::ScopeId(2),
                    body: BodyId(2),
                    parent: Some(wrela_hir::ScopeId(1)),
                    source: span(0, 270, 289),
                },
            ],
            locals: vec![Local {
                id: wrela_hir::LocalId(0),
                body: BodyId(1),
                scope: wrela_hir::ScopeId(1),
                name: name("guard"),
                ty: Some(TypeExpression {
                    kind: TypeExpressionKind::Named {
                        definition: Definition::Builtin(wrela_hir::Builtin::U32),
                        arguments: Vec::new(),
                    },
                    source: span(0, 230, 233),
                }),
                shadowed: None,
                source: span(0, 230, 235),
            }],
            statements: vec![
                Statement {
                    id: StatementId(0),
                    body: BodyId(0),
                    attributes: Vec::new(),
                    kind: StatementKind::Return(Some(ExpressionId(0))),
                    source: span(0, 30, 170),
                },
                Statement {
                    id: StatementId(1),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: wrela_hir::LocalId(0),
                        value: ExpressionId(4),
                    },
                    source: span(0, 230, 245),
                },
                Statement {
                    id: StatementId(2),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::While {
                        condition: ExpressionId(5),
                        body: BodyId(2),
                    },
                    source: span(0, 246, 289),
                },
                Statement {
                    id: StatementId(3),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Assign {
                        targets: vec![PlaceTarget {
                            root: Definition::Local(wrela_hir::LocalId(0)),
                            projections: Vec::new(),
                            source: span(0, 270, 275),
                        }],
                        operator: AssignmentOperator::Add,
                        value: ExpressionId(6),
                    },
                    source: span(0, 270, 284),
                },
            ],
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
                    kind: ExpressionKind::Reference(Definition::Declaration(image_type)),
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
                        enumeration: target_type,
                        variant: 0,
                    })),
                    source: span(0, 70, 90),
                },
                Expression {
                    id: ExpressionId(4),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("0".to_owned())),
                    source: span(0, 244, 245),
                },
                Expression {
                    id: ExpressionId(5),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Compare {
                        left: ExpressionId(7),
                        operator: wrela_hir::ComparisonOperator::Less,
                        right: ExpressionId(8),
                    },
                    source: span(0, 252, 264),
                },
                Expression {
                    id: ExpressionId(6),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(wrela_hir::ScopeId(2)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 281, 282),
                },
                Expression {
                    id: ExpressionId(7),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Reference(Definition::Local(wrela_hir::LocalId(0))),
                    source: span(0, 252, 257),
                },
                Expression {
                    id: ExpressionId(8),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(wrela_hir::ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Integer("1".to_owned())),
                    source: span(0, 260, 261),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: vec![DeclarationId(0)],
            test_candidates: vec![DeclarationId(3)],
        }
        .validate()
        .expect("valid producer HIR");
        let profile = BuildProfile::development();
        let profile_digest = Sha256Digest::from_bytes([0x24; 32]);
        let build = seal_build_configuration(
            BuildConfiguration {
                identity: BuildIdentity {
                    compiler: Sha256Digest::from_bytes([0x25; 32]),
                    language: LanguageRevision::Design0_1,
                    target: TargetIdentity::aarch64_qemu_virt_uefi(),
                    target_package: TARGET_DIGEST,
                    standard_library: STANDARD_LIBRARY_COMPONENT_DIGEST,
                    source_graph: Sha256Digest::from_bytes([0x26; 32]),
                    request: Sha256Digest::from_bytes([0x27; 32]),
                    profile: profile_digest,
                },
                profile,
            },
            profile_digest,
        )
        .expect("sealed producer build");
        ProducerFixture {
            hir: Arc::new(program),
            target: TargetPackage::aarch64_qemu_virt_uefi(TARGET_DIGEST),
            build,
        }
    }

    fn analyze_parsed_actor() -> wrela_sema::AnalyzedImage {
        let base = producer_fixture();
        let mut sources = SourceDatabase::default();
        let application_file = sources
            .add(SourceInput {
                path: "app.wr".to_owned(),
                text: BOUNDED_ACTOR_SOURCE.to_owned(),
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
        let mut packages = PackageGraphBuilder::new(package_identity(
            "actor-image",
            Sha256Digest::from_bytes([0xb0; 32]),
        ));
        let core = packages
            .add_package(package_identity(
                "wrela-core",
                STANDARD_LIBRARY_PACKAGE_DIGEST,
            ))
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

    fn producer_request<'a>(
        fixture: &'a ProducerFixture,
        changes: &'a AnalysisChangeSet,
        mode: AnalysisMode<'a>,
    ) -> AnalysisRequest<'a> {
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: PackageId(1),
            target: fixture.target.semantic(),
            build: &fixture.build,
            mode,
            changes,
            limits: AnalysisLimits::standard(),
        }
    }

    fn compiled_test_images() -> (wrela_sema::AnalyzedImage, wrela_sema::AnalyzedImage) {
        let fixture = producer_fixture();
        let changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let declared = [DeclaredImageTest {
            name: "boots".to_owned(),
            image_name: "runtime-image".to_owned(),
            scenario: ImageScenario {
                id: ScenarioId(0),
                schema: wrela_test_model::IMAGE_SCENARIO_SCHEMA,
                name: "boots".to_owned(),
                source_path: "fixtures/boots.toml".to_owned(),
                digest: Sha256Digest::from_bytes([0x28; 32]),
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
                producer_request(
                    &fixture,
                    &changes,
                    AnalysisMode::DiscoverTests {
                        image_name: "runtime-image",
                        image_entry: DeclarationId(0),
                        declared_image_tests: &declared,
                        source_selection: TestDiscoverySelection::All,
                    },
                ),
                &|| false,
            )
            .expect("test discovery");
        assert!(discovery.diagnostics().is_empty());
        let discovery = discovery.successful().expect("sealed test plan");
        let plan = discovery.facts().test_plan.as_ref().expect("test plan");
        let generated = plan
            .image_groups()
            .iter()
            .find(|group| matches!(group.root, ImageRoot::GeneratedHarness { .. }))
            .expect("generated group")
            .id;
        let declared_group = plan
            .image_groups()
            .iter()
            .find(|group| matches!(group.root, ImageRoot::Declared { .. }))
            .expect("declared group")
            .id;
        let generated = CanonicalSemanticAnalyzer::new()
            .analyze(
                producer_request(
                    &fixture,
                    &changes,
                    AnalysisMode::CompileTestGroup {
                        plan,
                        group: generated,
                        declared_entry: None,
                    },
                ),
                &|| false,
            )
            .expect("generated group compilation")
            .successful()
            .expect("sealed generated image")
            .clone();
        let declared_image = CanonicalSemanticAnalyzer::new()
            .analyze(
                producer_request(
                    &fixture,
                    &changes,
                    AnalysisMode::CompileTestGroup {
                        plan,
                        group: declared_group,
                        declared_entry: Some(DeclarationId(0)),
                    },
                ),
                &|| false,
            )
            .expect("declared group compilation")
            .successful()
            .expect("sealed declared image")
            .clone();
        (generated, declared_image)
    }

    fn build() -> BuildIdentity {
        BuildIdentity {
            compiler: Sha256Digest::from_bytes([1; 32]),
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: Sha256Digest::from_bytes([2; 32]),
            standard_library: Sha256Digest::from_bytes([3; 32]),
            source_graph: Sha256Digest::from_bytes([4; 32]),
            request: Sha256Digest::from_bytes([5; 32]),
            profile: Sha256Digest::from_bytes([6; 32]),
        }
    }

    fn proof(id: u32, kind: ProofKind, depends_on: &[u32], bound: Option<u64>) -> Proof {
        Proof {
            id: ProofId(id),
            kind,
            subject: format!("semantic proof {id}"),
            sources: vec![span(id % 2, id * 10, id * 10 + 4)],
            depends_on: depends_on.iter().copied().map(ProofId).collect(),
            bound,
            explanation: vec![format!("semantic explanation {id}")],
        }
    }

    fn fixture() -> PartialAnalysis {
        let build = build();
        let retained_hir = producer_fixture().hir;
        let analysis = PartialAnalysis {
            hir: HirSummary::from_validated(retained_hir.as_ref()).expect("fixture HIR summary"),
            target_digest: build.target_package,
            root: AnalysisRoot::DeclaredImage {
                image_name: "manifest-selector".to_owned(),
                declaration: DeclarationId(3),
                test_group: None,
            },
            types: vec![SemanticType {
                id: SemanticTypeId(0),
                kind: SemanticTypeKind::Unit,
                linearity: Linearity::ScalarCopy,
                size_upper_bound: Some(0),
                alignment_lower_bound: 1,
                source: None,
            }],
            functions: vec![FunctionInstance {
                id: FunctionInstanceId(0),
                key: FunctionKey(build.request),
                name: "__wrela_image_entry".to_owned(),
                origin: FunctionOrigin::GeneratedImageEntry {
                    constructor: DeclarationId(3),
                },
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
            }],
            values: Vec::new(),
            expressions: Vec::new(),
            statements: Vec::new(),
            scope_protocols: Vec::new(),
            scope_activations: Vec::new(),
            graph: Some(ImageGraph {
                name: "runtime-image".to_owned(),
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
            }),
            proofs: vec![
                proof(0, ProofKind::TypeChecked, &[], None),
                proof(1, ProofKind::EffectsAllowed, &[0], Some(1)),
                proof(2, ProofKind::ImageClosed, &[0, 1], Some(0)),
            ],
            baked_artifacts: Vec::new(),
            test_plan: None,
            comptime_test_results: Vec::new(),
            compiled_test_group: None,
            build,
        };
        analysis
            .validate_partial_structure()
            .expect("valid partial semantic fixture");
        analysis
            .validate_for_seal(retained_hir.as_ref(), &|| false)
            .expect("complete semantic fixture");
        analysis
    }

    fn assemble_fixture(
        semantic: &PartialAnalysis,
    ) -> Result<ValidatedAnalysisFacts, AnalysisFactAssemblyError> {
        let limits = wrela_image_report::AnalysisFactLimits::standard();
        let graph = semantic.graph.as_ref().expect("fixture graph");
        let projection = SupportedProjection {
            semantic,
            graph,
            reachable_declarations: supported_declared_image(semantic, graph)?,
            kind: ProjectionKind::Scalar,
        };
        preflight_projection(&projection, limits, &|| false)?;
        let facts = assemble_projection(&projection, limits, &|| false)?;
        seal_projection(
            &projection,
            ReportRequest {
                build: &semantic.build,
                image_name: &graph.name,
                limits,
            },
            facts,
            &|| false,
        )
    }

    #[test]
    fn proof_categories_are_exact_and_distinct() {
        let kinds = [
            ProofKind::TypeChecked,
            ProofKind::EffectsAllowed,
            ProofKind::DefiniteInitialization,
            ProofKind::Ownership,
            ProofKind::AccessExclusive,
            ProofKind::ViewDoesNotEscape,
            ProofKind::RegionBound,
            ProofKind::CapacityBound,
            ProofKind::WaitGraphAcyclic,
            ProofKind::CleanupAcyclic,
            ProofKind::WorkBound,
            ProofKind::StackBound,
            ProofKind::IsrSafe,
            ProofKind::DmaTransition,
            ProofKind::MmioPartition,
            ProofKind::DeviceValueValidated,
            ProofKind::WireLayout,
            ProofKind::ReceiptLineage,
            ProofKind::ActorAsIf,
            ProofKind::SupervisionComplete,
            ProofKind::ImageClosed,
        ];
        let mut names: Vec<_> = kinds.iter().map(proof_kind_name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), kinds.len());
    }

    #[test]
    fn forged_exclusive_call_place_never_reaches_analysis_fact_projection() {
        let fixture = producer_fixture();
        let mut program = fixture.hir.as_program().clone();
        let ExpressionKind::Call { arguments, .. } = &mut program.expressions[0].kind else {
            panic!("producer fixture image constructor call");
        };
        arguments[0].value = wrela_hir::CallArgumentValue::Exclusive {
            access: wrela_hir::ExclusiveAccess::Take,
            place: wrela_hir::PlaceTarget {
                root: Definition::Builtin(wrela_hir::Builtin::U64),
                projections: Vec::new(),
                source: arguments[0].source,
            },
        };
        assert!(program.validate().is_err());
    }

    #[test]
    fn construction_budget_enforces_exact_boundaries() {
        let limits = wrela_image_report::AnalysisFactLimits {
            items: 1,
            proof_edges: 1,
            payload_bytes: 1,
        };
        let mut budget = Budget::new(limits);
        budget.item().expect("exact item");
        assert!(matches!(
            budget.item(),
            Err(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis fact items",
                limit: 1
            })
        ));
        budget.proof_edge().expect("exact proof edge");
        assert!(budget.proof_edge().is_err());
        budget.text("x").expect("exact payload");
        assert!(budget.text("y").is_err());
        assert!(matches!(
            check_cancelled(&|| true),
            Err(AnalysisFactAssemblyError::Cancelled)
        ));
    }

    #[test]
    fn analyzer_generated_group_projects_exact_backend_aligned_facts() {
        let (generated, _) = compiled_test_images();
        let sealed = CanonicalAnalysisFactAssembler::new()
            .assemble(
                AnalysisFactRequest {
                    analysis: &generated,
                    limits: wrela_image_report::AnalysisFactLimits::standard(),
                },
                &|| false,
            )
            .expect("generated test analysis facts");
        let semantic = generated.facts();
        assert_eq!(sealed.build(), &semantic.build);
        assert_eq!(sealed.image_name(), "__wrela_test_harness");
        assert_eq!(
            sealed.as_facts().compiled_test_group,
            semantic.compiled_test_group
        );
        assert_eq!(sealed.as_facts().reachable_declarations, 1);
        assert_eq!(sealed.as_facts().monomorphized_instantiations, 2);
        assert_eq!(sealed.as_facts().work.len(), 2);
        assert!(sealed.as_facts().work.iter().all(|fact| {
            fact.function.starts_with("function:")
                && fact.uninterrupted_work.is_none()
                && fact.checkpoint_count == 0
        }));
    }

    #[test]
    fn analyzer_declared_group_projects_verbatim_group_and_rejects_substitution() {
        let (_, declared) = compiled_test_images();
        let limits = wrela_image_report::AnalysisFactLimits::standard();
        let projection =
            supported_projection(&declared, limits, &|| false).expect("supported group");
        let baseline = assemble_projection(&projection, limits, &|| false).expect("declared facts");
        assert_eq!(
            baseline.compiled_test_group,
            declared.facts().compiled_test_group
        );
        assert_eq!(baseline.reachable_declarations, 1);

        let mut substituted = baseline;
        let group = substituted
            .compiled_test_group
            .as_mut()
            .expect("compiled group");
        let ImageRoot::Declared { scenario, .. } = &mut group.root else {
            panic!("declared root");
        };
        *scenario = ScenarioId(scenario.0 + 1);
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &declared.facts().build,
                    image_name: &projection.graph.name,
                    limits,
                },
                substituted,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
                | Err(AnalysisFactAssemblyError::Report(_))
        ));
    }

    #[test]
    fn analyzer_generated_group_honors_limits_and_cancellation() {
        let (generated, _) = compiled_test_images();
        let mut limits = wrela_image_report::AnalysisFactLimits::standard();
        limits.items = 1;
        assert!(matches!(
            CanonicalAnalysisFactAssembler::new().assemble(
                AnalysisFactRequest {
                    analysis: &generated,
                    limits,
                },
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::ResourceLimit { .. })
        ));
        assert!(matches!(
            CanonicalAnalysisFactAssembler::new().assemble(
                AnalysisFactRequest {
                    analysis: &generated,
                    limits: wrela_image_report::AnalysisFactLimits::standard(),
                },
                &|| true,
            ),
            Err(AnalysisFactAssemblyError::Cancelled)
        ));
    }

    #[test]
    fn parsed_actor_pipeline_projects_exact_nodes_capacities_sources_and_proofs() {
        let image = analyze_parsed_actor();
        let lowered = CanonicalSemanticLowerer::new()
            .lower(
                SemanticLowerRequest {
                    input: image.clone(),
                    limits: SemanticLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("parsed actor SemanticWir lowering");
        let sealed = CanonicalAnalysisFactAssembler::new()
            .assemble(
                AnalysisFactRequest {
                    analysis: &image,
                    limits: wrela_image_report::AnalysisFactLimits::standard(),
                },
                &|| false,
            )
            .expect("parsed actor analysis facts");
        let semantic = image.facts();
        let graph = semantic.graph.as_ref().expect("actor graph");
        let facts = sealed.as_facts();
        let semantic_wir = lowered.wir().as_wir();
        assert_eq!(semantic_wir.actors.len(), graph.actors.len());
        assert_eq!(semantic_wir.tasks.len(), graph.tasks.len());
        assert_eq!(semantic_wir.activations.len(), 2);
        assert_eq!(
            semantic_wir.regions.len(),
            graph.regions.len() + semantic_wir.activations.len(),
            "Semantic lowering adds one source-bound Call region per async helper activation"
        );
        let activation_bytes = semantic_wir
            .activations
            .iter()
            .map(|plan| plan.frame_bytes * u64::from(plan.maximum_live))
            .sum::<u64>();
        assert_eq!(
            semantic_wir.static_bytes,
            graph.static_bytes + activation_bytes
        );
        assert_eq!(semantic_wir.peak_bytes, graph.peak_bytes + activation_bytes);
        assert_eq!(
            facts.reachable_declarations,
            semantic_wir.source_summary.reachable_declarations
        );
        assert_eq!(facts.image_nodes.len(), 5);
        assert_eq!(facts.image_edges.len(), 1);
        assert_eq!(
            facts
                .image_nodes
                .iter()
                .map(|node| node.static_bytes)
                .sum::<u64>(),
            graph.static_bytes
        );
        for actor in &graph.actors {
            let identity = raw_actor_identity(actor, u64::MAX).expect("actor identity");
            let source = raw_source_identity(actor.source, u64::MAX).expect("actor source");
            assert!(facts.image_nodes.iter().any(|node| {
                node.kind == "actor"
                    && node.name == identity
                    && node.owner == "runtime"
                    && node.source == source
                    && node.static_bytes == 0
            }));
            assert!(facts.bounds.iter().any(|fact| {
                bound_matches(
                    fact,
                    "actor-mailbox",
                    &identity,
                    "Semantic.ActorNode.mailbox_capacity",
                    u64::from(actor.mailbox_capacity),
                    "messages",
                )
            }));
        }
        for task in &graph.tasks {
            let identity = raw_task_identity(task, u64::MAX).expect("task identity");
            let source = raw_source_identity(task.source, u64::MAX).expect("task source");
            let owner = raw_image_owner_identity(
                graph,
                task.supervisor
                    .map_or(ImageOwner::Runtime, ImageOwner::Actor),
                u64::MAX,
            )
            .expect("task owner");
            assert!(facts.image_nodes.iter().any(|node| {
                node.kind == "task"
                    && node.name == identity
                    && node.owner == owner
                    && node.source == source
                    && node.static_bytes == 0
            }));
            assert!(facts.image_edges.iter().any(|edge| {
                edge.kind == "task-supervision"
                    && edge.source == identity
                    && edge.destination == owner
                    && edge.capacity == Some(u64::from(task.slots))
                    && edge.priority == Some(task.priority)
            }));
            assert!(facts.bounds.iter().any(|fact| {
                bound_matches(
                    fact,
                    "task-slots",
                    &identity,
                    "Semantic.TaskNode.slots",
                    u64::from(task.slots),
                    "slots",
                )
            }));
            let entry = semantic
                .functions
                .get(task.entry.0 as usize)
                .expect("task entry");
            assert!(facts.bounds.iter().any(|fact| {
                bound_matches(
                    fact,
                    "task-frame",
                    &identity,
                    "Semantic.FunctionInstance.frame_bytes_bound",
                    entry.frame_bytes_bound,
                    "bytes",
                )
            }));
        }
        for region in &graph.regions {
            let identity = raw_region_identity(region, u64::MAX).expect("region identity");
            let source = raw_source_identity(region.source, u64::MAX).expect("region source");
            let owner =
                raw_image_owner_identity(graph, region.owner, u64::MAX).expect("region owner");
            assert!(facts.image_nodes.iter().any(|node| {
                node.kind == actor_region_kind(region).expect("region kind")
                    && node.name == identity
                    && node.owner == owner
                    && node.source == source
                    && node.static_bytes == region.capacity_bytes
            }));
            assert!(facts.bounds.iter().any(|fact| {
                bound_matches(
                    fact,
                    "region-capacity",
                    &identity,
                    "Semantic.Region.capacity_bytes",
                    region.capacity_bytes,
                    "bytes",
                )
            }));
            assert!(facts.bounds.iter().any(|fact| {
                bound_matches(
                    fact,
                    "region-alignment",
                    &identity,
                    "Semantic.Region.alignment",
                    u64::from(region.alignment),
                    "bytes",
                )
            }));
            assert!(
                facts.region_capacity_evidence.iter().any(|fact| {
                    fact.region == identity && fact.capacity_proof == region.proof.0
                })
            );
        }
        for required in [
            "ownership",
            "view-does-not-escape",
            "cleanup-acyclic",
            "wait-graph-acyclic",
            "image-closed",
        ] {
            assert!(facts.proofs.iter().any(|proof| proof.category == required));
        }
        assert!(facts.work.iter().any(|work| {
            work.frame_bytes == 16
                && work.uninterrupted_work.is_some()
                && work.checkpoint_count == 0
        }));
        assert_eq!(
            facts.startup_order,
            graph
                .startup_order
                .iter()
                .map(|owner| raw_image_owner_identity(graph, *owner, u64::MAX).expect("owner"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            facts.shutdown_order,
            graph
                .shutdown_order
                .iter()
                .map(|owner| raw_image_owner_identity(graph, *owner, u64::MAX).expect("owner"))
                .collect::<Vec<_>>()
        );
        assert!(facts.actor_lowerings.is_empty());
        assert_eq!(facts.region_capacity_evidence.len(), graph.regions.len());
        assert!(facts.hardware.is_empty());
        assert!(facts.recovery.is_empty());
    }

    #[test]
    fn actor_projection_sealer_rejects_identity_proof_and_capacity_substitution() {
        let image = analyze_parsed_actor();
        let limits = wrela_image_report::AnalysisFactLimits::standard();
        let projection = supported_projection(&image, limits, &|| false).expect("actor projection");
        let baseline =
            assemble_projection(&projection, limits, &|| false).expect("actor report facts");

        let mut wrong_build = image.facts().build.clone();
        wrong_build.request = Sha256Digest::from_bytes([0x7a; 32]);
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &wrong_build,
                    image_name: &projection.graph.name,
                    limits,
                },
                baseline.clone(),
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &image.facts().build,
                    image_name: "substituted-actor-image",
                    limits,
                },
                baseline.clone(),
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_source = baseline.clone();
        wrong_source.image_nodes[0].source = "file:99:bytes:0..1".to_owned();
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &image.facts().build,
                    image_name: &projection.graph.name,
                    limits,
                },
                wrong_source,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_proof = baseline.clone();
        let proof = wrong_proof
            .proofs
            .iter_mut()
            .find(|proof| proof.category == "ownership")
            .expect("ownership proof");
        proof.category = "view-does-not-escape".to_owned();
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &image.facts().build,
                    image_name: &projection.graph.name,
                    limits,
                },
                wrong_proof,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_region_proof = baseline.clone();
        wrong_region_proof.region_capacity_evidence[0].capacity_proof = wrong_region_proof
            .region_capacity_evidence[0]
            .capacity_proof
            .checked_add(1)
            .expect("region proof substitution");
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &image.facts().build,
                    image_name: &projection.graph.name,
                    limits,
                },
                wrong_region_proof,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_capacity = baseline;
        let mailbox = wrong_capacity
            .bounds
            .iter_mut()
            .find(|bound| bound.category == "actor-mailbox")
            .expect("mailbox bound");
        mailbox.amount = mailbox.amount.checked_add(1).expect("mailbox substitution");
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &image.facts().build,
                    image_name: &projection.graph.name,
                    limits,
                },
                wrong_capacity,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));
    }

    #[test]
    fn actor_semantic_contract_rejects_capacity_and_proof_substitution() {
        let image = analyze_parsed_actor();
        let limits = wrela_image_report::AnalysisFactLimits::standard();

        let mut wrong_capacity = image.facts().clone();
        let graph = wrong_capacity.graph.as_ref().expect("actor graph").clone();
        let capacity = graph.regions[0].proof;
        wrong_capacity.proofs[capacity.0 as usize].bound = wrong_capacity.proofs
            [capacity.0 as usize]
            .bound
            .and_then(|bound| bound.checked_add(1));
        let entry = wrong_capacity.functions[graph.entry.0 as usize].clone();
        assert!(matches!(
            validate_actor_graph(&wrong_capacity, &graph, &entry, limits, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "actor capacity proof or region substitution",
            })
        ));

        let mut wrong_proof = image.facts().clone();
        let graph = wrong_proof.graph.as_ref().expect("actor graph").clone();
        let function = wrong_proof
            .functions
            .iter()
            .find(|function| matches!(function.role, FunctionRole::ActorTurn(_)))
            .expect("actor turn")
            .clone();
        let ownership = function
            .proofs
            .iter()
            .copied()
            .find(|id| wrong_proof.proofs[id.0 as usize].kind == ProofKind::Ownership)
            .expect("ownership proof");
        wrong_proof.proofs[ownership.0 as usize].bound = Some(2);
        let entry = wrong_proof.functions[graph.entry.0 as usize].clone();
        assert!(matches!(
            validate_actor_proofs(&wrong_proof, &graph, &entry, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "actor function ownership proof substitution",
            })
        ));
    }

    #[test]
    fn actor_projection_enforces_exact_item_limit_and_midflight_cancellation() {
        let image = analyze_parsed_actor();
        let polls = Cell::new(0u64);
        let count_only = || {
            polls.set(polls.get().saturating_add(1));
            false
        };
        let baseline = CanonicalAnalysisFactAssembler::new()
            .assemble(
                AnalysisFactRequest {
                    analysis: &image,
                    limits: wrela_image_report::AnalysisFactLimits::standard(),
                },
                &count_only,
            )
            .expect("baseline actor report");
        let facts = baseline.as_facts();
        let exact_items = [
            facts.bounds.len(),
            facts.proofs.len(),
            facts.actor_lowerings.len(),
            facts.image_nodes.len(),
            facts.image_edges.len(),
            facts.region_capacity_evidence.len(),
            facts.work.len(),
            facts.hardware.len(),
            facts.recovery.len(),
            facts.startup_order.len(),
            facts.shutdown_order.len(),
        ]
        .into_iter()
        .try_fold(0u64, |total, count| {
            total.checked_add(u64::try_from(count).ok()?)
        })
        .expect("actor fact item count");
        let mut exact = wrela_image_report::AnalysisFactLimits::standard();
        exact.items = exact_items;
        CanonicalAnalysisFactAssembler::new()
            .assemble(
                AnalysisFactRequest {
                    analysis: &image,
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact actor fact item limit");
        let mut one_too_many = exact;
        one_too_many.items = exact_items - 1;
        assert!(matches!(
            CanonicalAnalysisFactAssembler::new().assemble(
                AnalysisFactRequest {
                    analysis: &image,
                    limits: one_too_many,
                },
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis fact items",
                limit,
            }) if limit == exact_items - 1
        ));

        let cancel_at = (polls.get() / 2).max(2);
        let cancelled_polls = Cell::new(0u64);
        let cancel_midflight = || {
            let next = cancelled_polls.get().saturating_add(1);
            cancelled_polls.set(next);
            next >= cancel_at
        };
        assert!(matches!(
            CanonicalAnalysisFactAssembler::new().assemble(
                AnalysisFactRequest {
                    analysis: &image,
                    limits: wrela_image_report::AnalysisFactLimits::standard(),
                },
                &cancel_midflight,
            ),
            Err(AnalysisFactAssemblyError::Cancelled)
        ));
        assert!(cancelled_polls.get() > 1);
    }

    #[test]
    fn minimum_projection_preserves_identity_provenance_proofs_and_bounds() {
        let semantic = fixture();
        let sealed = assemble_fixture(&semantic).expect("sealed analysis-fact projection");
        assert_eq!(sealed.build(), &semantic.build);
        assert_eq!(sealed.image_name(), "runtime-image");
        let facts = sealed.as_facts();
        // Four HIR declarations exist, but only the constructor retained by
        // the generated runtime entry is reachable provenance.
        assert_eq!(semantic.hir.declarations, 4);
        assert_eq!(facts.reachable_declarations, 1);
        assert_eq!(facts.monomorphized_instantiations, 1);
        assert_eq!(facts.resolved_interface_calls, 0);
        assert!(facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "image-static-memory",
                "runtime-image",
                "FlowWir.static_bytes",
                0,
                "bytes",
            )
        }));
        assert!(facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "image-peak-memory",
                "runtime-image",
                "FlowWir.peak_bytes",
                0,
                "bytes",
            )
        }));
        assert!(facts.bounds.iter().any(|fact| {
            bound_matches(
                fact,
                "function-stack",
                "function:0:__wrela_image_entry",
                "FlowFunction.stack_bound",
                0,
                "bytes",
            )
        }));
        assert_eq!(facts.proofs.len(), 3);
        assert_eq!(facts.proofs[0].category, "type-checked");
        assert_eq!(facts.proofs[0].why_chain, ["semantic explanation 0"]);
        assert_eq!(facts.proofs[1].category, "effects-allowed");
        assert_eq!(facts.proofs[1].why_chain, ["semantic explanation 1"]);
        assert_eq!(facts.proofs[2].category, "image-closed");
        assert_eq!(facts.proofs[2].why_chain, ["semantic explanation 2"]);
        assert!(matches!(
            facts.work.as_slice(),
            [WorkFact {
                function,
                stack_bytes: 0,
                frame_bytes: 0,
                uninterrupted_work: None,
                checkpoint_count: 0,
            }] if function == "function:0:__wrela_image_entry"
        ));
        assert_eq!(facts.startup_order, ["runtime"]);
        assert_eq!(facts.shutdown_order, ["runtime"]);
        assert!(facts.actor_lowerings.is_empty());
        assert!(facts.image_nodes.is_empty());
        assert!(facts.image_edges.is_empty());
        assert!(facts.hardware.is_empty());
        assert!(facts.recovery.is_empty());
        assert!(facts.compiled_test_group.is_none());
    }

    #[test]
    fn projection_sealer_rejects_identity_fact_and_provenance_substitution() {
        let semantic = fixture();
        let graph = semantic.graph.as_ref().expect("fixture graph");
        let projection = SupportedProjection {
            semantic: &semantic,
            graph,
            reachable_declarations: supported_declared_image(&semantic, graph)
                .expect("supported fixture"),
            kind: ProjectionKind::Scalar,
        };
        let limits = wrela_image_report::AnalysisFactLimits::standard();
        let baseline = assemble_projection(&projection, limits, &|| false).expect("baseline facts");

        let mut wrong_build = semantic.build.clone();
        wrong_build.request = Sha256Digest::from_bytes([0x77; 32]);
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &wrong_build,
                    image_name: &graph.name,
                    limits,
                },
                baseline.clone(),
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &semantic.build,
                    image_name: "substituted-image",
                    limits,
                },
                baseline.clone(),
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_proof_source = baseline.clone();
        wrong_proof_source.proofs[0].why_chain[0] = "substituted explanation".to_owned();
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &semantic.build,
                    image_name: &graph.name,
                    limits,
                },
                wrong_proof_source,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_reachability = baseline.clone();
        wrong_reachability.reachable_declarations = semantic.hir.declarations.into();
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &semantic.build,
                    image_name: &graph.name,
                    limits,
                },
                wrong_reachability,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));

        let mut wrong_work = baseline;
        wrong_work.work[0].uninterrupted_work = Some(2);
        assert!(matches!(
            seal_projection(
                &projection,
                ReportRequest {
                    build: &semantic.build,
                    image_name: &graph.name,
                    limits,
                },
                wrong_work,
                &|| false,
            ),
            Err(AnalysisFactAssemblyError::InvalidSemanticFacts(_))
        ));
    }

    #[test]
    fn preflight_limits_and_cancellation_precede_projection_allocation() {
        let semantic = fixture();
        let graph = semantic.graph.as_ref().expect("fixture graph");
        let projection = SupportedProjection {
            semantic: &semantic,
            graph,
            reachable_declarations: 1,
            kind: ProjectionKind::Scalar,
        };
        let mut limits = wrela_image_report::AnalysisFactLimits::standard();
        limits.items = 8;
        assert!(matches!(
            preflight_projection(&projection, limits, &|| false),
            Err(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis fact items",
                limit: 8,
            })
        ));
        let mut limits = wrela_image_report::AnalysisFactLimits::standard();
        limits.proof_edges = 2;
        assert!(matches!(
            preflight_projection(&projection, limits, &|| false),
            Err(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis proof edges",
                limit: 2,
            })
        ));
        let mut limits = wrela_image_report::AnalysisFactLimits::standard();
        limits.payload_bytes = 1;
        assert!(matches!(
            preflight_projection(&projection, limits, &|| false),
            Err(AnalysisFactAssemblyError::ResourceLimit {
                resource: "analysis fact payload",
                limit: 1,
            })
        ));
        assert!(matches!(
            preflight_projection(
                &projection,
                wrela_image_report::AnalysisFactLimits::standard(),
                &|| true,
            ),
            Err(AnalysisFactAssemblyError::Cancelled)
        ));
    }

    #[test]
    fn richer_semantic_inputs_are_rejected_explicitly() {
        let mut semantic = fixture();
        semantic.functions[0].effects = EffectSet(EffectSet::FIRMWARE | EffectSet::ALLOCATE);
        assert!(matches!(
            supported_declared_image(&semantic, semantic.graph.as_ref().expect("graph")),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "noncanonical generated image entries",
            })
        ));

        let mut semantic = fixture();
        semantic.proofs[1].kind = ProofKind::Ownership;
        assert!(matches!(
            supported_declared_image(&semantic, semantic.graph.as_ref().expect("graph")),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "noncanonical minimum-image proof sets",
            })
        ));
    }

    #[test]
    fn flat_runtime_structure_admission_is_exact_and_cancellable() {
        let mut semantic = fixture();
        semantic.types.push(SemanticType {
            id: SemanticTypeId(1),
            kind: SemanticTypeKind::Integer {
                signed: false,
                bits: 64,
                pointer_sized: false,
            },
            linearity: Linearity::ScalarCopy,
            size_upper_bound: Some(8),
            alignment_lower_bound: 8,
            source: None,
        });
        semantic.types.push(SemanticType {
            id: SemanticTypeId(2),
            kind: SemanticTypeKind::Structure {
                declaration: DeclarationId(0),
                arguments: Vec::new(),
                fields: vec![SemanticField {
                    name: "nanoseconds".to_owned(),
                    ty: SemanticTypeId(1),
                    public: false,
                }],
            },
            linearity: Linearity::ExplicitCopy,
            size_upper_bound: Some(8),
            alignment_lower_bound: 8,
            source: Some(span(0, 0, 8)),
        });
        require_supported_runtime_types(&semantic, &|| false)
            .expect("exact scalar-backed runtime structure");
        assert!(is_runtime_value_type(&semantic, SemanticTypeId(2)));

        let mut generic = semantic.clone();
        let SemanticTypeKind::Structure { arguments, .. } = &mut generic.types[2].kind else {
            panic!("flat structure fixture");
        };
        arguments.push(SemanticArgument::Type(SemanticTypeId(1)));
        assert!(matches!(
            require_supported_runtime_types(&generic, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "runtime types outside the bounded flat-value subset",
            })
        ));

        let mut wrong_layout = semantic.clone();
        wrong_layout.types[2].size_upper_bound = Some(16);
        assert!(matches!(
            require_supported_runtime_types(&wrong_layout, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "runtime types outside the bounded flat-value subset",
            })
        ));

        let mut nested = semantic.clone();
        nested.types.push(SemanticType {
            id: SemanticTypeId(3),
            kind: SemanticTypeKind::Structure {
                declaration: DeclarationId(1),
                arguments: Vec::new(),
                fields: vec![SemanticField {
                    name: "nested".to_owned(),
                    ty: SemanticTypeId(2),
                    public: false,
                }],
            },
            linearity: Linearity::ExplicitCopy,
            size_upper_bound: Some(8),
            alignment_lower_bound: 8,
            source: Some(span(0, 8, 16)),
        });
        assert!(matches!(
            require_supported_runtime_types(&nested, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "runtime types outside the bounded flat-value subset",
            })
        ));

        let polls = Cell::new(0_u32);
        assert_eq!(
            require_supported_runtime_types(&semantic, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next == 4
            }),
            Err(AnalysisFactAssemblyError::Cancelled)
        );
        assert_eq!(polls.get(), 4);
    }

    #[test]
    fn actor_async_and_hardware_surfaces_remain_fail_closed() {
        let mut semantic = fixture();
        semantic.functions[0].color = FunctionColor::Async;
        assert!(matches!(
            supported_declared_image(&semantic, semantic.graph.as_ref().expect("graph")),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "noncanonical generated image entries",
            })
        ));

        let mut semantic = fixture();
        semantic.types.push(SemanticType {
            id: SemanticTypeId(1),
            kind: SemanticTypeKind::Function {
                color: FunctionColor::Async,
                parameters: Vec::new(),
                result: SemanticTypeId(0),
            },
            linearity: Linearity::ScalarCopy,
            size_upper_bound: Some(0),
            alignment_lower_bound: 1,
            source: None,
        });
        assert!(matches!(
            require_supported_runtime_types(&semantic, &|| false),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "runtime types outside the bounded flat-value subset",
            })
        ));

        let mut semantic = fixture();
        semantic
            .graph
            .as_mut()
            .expect("graph")
            .actors
            .push(wrela_sema::ActorNode {
                id: wrela_sema::ActorId(0),
                name: "worker".to_owned(),
                class: SemanticTypeId(0),
                mailbox_capacity: 1,
                message_types: Vec::new(),
                turn_functions: Vec::new(),
                priority: 0,
                supervisor: None,
                source: span(0, 0, 1),
            });
        assert!(matches!(
            require_empty_runtime_graph(semantic.graph.as_ref().expect("graph")),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "nonempty runtime image graphs",
            })
        ));

        let mut semantic = fixture();
        semantic
            .graph
            .as_mut()
            .expect("graph")
            .devices
            .push(wrela_sema::DeviceNode {
                id: wrela_sema::DeviceId(0),
                name: "uart".to_owned(),
                target_binding: "uart0".to_owned(),
                owner: wrela_sema::ActorId(0),
                required_features: Vec::new(),
                optional_features: Vec::new(),
                queue_capacity: None,
                maximum_in_flight: None,
                interrupt_functions: Vec::new(),
                reset_timeout_ns: 1,
                source: span(0, 0, 1),
            });
        assert!(matches!(
            require_empty_runtime_graph(semantic.graph.as_ref().expect("graph")),
            Err(AnalysisFactAssemblyError::UnsupportedInput {
                feature: "nonempty runtime image graphs",
            })
        ));
    }
}
