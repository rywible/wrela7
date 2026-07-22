use std::str;

use wrela_build_model::{BuildIdentity, Sha256Digest};
use wrela_source::{FileId, Span, TextRange};
use wrela_test_model::{
    FullImageTestGroup, FunctionKey, ImageGroupId, ImageRoot, ImageTest, ImageTestInvocation,
    PlannedAssertionDescriptor, ScenarioId, TestDescriptor, TestId, TestKind,
};

use crate::{
    ActivationCancellationFact, ActivationFrameEvidenceFact, ActorLoweringFact, ActorLoweringKind,
    ActorPlacementInputFact, AnalysisFactLimits, AnalysisFactRequest, AnalysisFacts,
    BackendFactLimits, BackendFacts, BoundFact, HardwareFact, ImageEdgeFact, ImageNodeFact,
    ImageReport, IsoPoolFact, OptimizationAction, OptimizationDecisionFact, PromotionFact,
    ProofFact, REPORT_SCHEMA_VERSION, RecoveryFact, RegionAssignmentFact,
    RegionCapacityEvidenceFact, RegionClass, ReportError, RepresentationFacts,
    SchedulerOwnershipFact, SectionFact, SymbolFact, WorkFact, copy_build_identity,
    seal_analysis_facts,
};

/// Decode and authenticate one canonical schema-v16 image report.
///
/// The caller supplies the build identity expected at this trust boundary and
/// all resource ceilings. The decoded facts are resealed through the same
/// constructors used by producers, and the result must encode to exactly the
/// bytes supplied by the caller.
///
/// # Errors
///
/// Returns a [`ReportError`] when cancellation is requested, the input or its
/// decoded facts exceed a caller ceiling, identity or schema authentication
/// fails, JSON is malformed or noncanonical, or the reconstructed report does
/// not satisfy the producer-side fact and extent invariants.
#[allow(clippy::too_many_lines)]
pub fn decode_image_report_json(
    bytes: &[u8],
    expected_build: &BuildIdentity,
    analysis_limits: AnalysisFactLimits,
    backend_limits: BackendFactLimits,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageReport, ReportError> {
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    analysis_limits.validate()?;
    backend_limits.validate()?;
    let encoded_bytes = u64::try_from(bytes.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    if encoded_bytes > maximum_bytes {
        return Err(ReportError::ResourceLimit {
            resource: "encoded image report bytes",
            limit: maximum_bytes,
        });
    }

    let mut parser = Parser::new(bytes, maximum_bytes, is_cancelled);
    let mut budget = DecodeBudget::new(analysis_limits, backend_limits);
    parser.object_start()?;

    parser.field("schema", true)?;
    let schema = parser.u32("schema")?;
    if schema != REPORT_SCHEMA_VERSION {
        return Err(ReportError::UnsupportedSchema(schema));
    }
    parser.field("image_name", false)?;
    let image_name = parser.string()?;
    budget.analysis_payload(&image_name)?;
    parser.field("language", false)?;
    parser.expected_string(expected_build.language.as_str())?;
    parser.field("target", false)?;
    parser.expected_string(expected_build.target.as_str())?;
    parse_expected_digest(&mut parser, "compiler_sha256", expected_build.compiler)?;
    parse_expected_digest(
        &mut parser,
        "target_package_sha256",
        expected_build.target_package,
    )?;
    parse_expected_digest(
        &mut parser,
        "standard_library_sha256",
        expected_build.standard_library,
    )?;
    parse_expected_digest(
        &mut parser,
        "source_graph_sha256",
        expected_build.source_graph,
    )?;
    parse_expected_digest(&mut parser, "request_sha256", expected_build.request)?;
    parse_expected_digest(&mut parser, "profile_sha256", expected_build.profile)?;
    parser.field("flow_wir_sha256", false)?;
    let flow_wir_digest = parser.digest("SHA-256 digest")?;

    parser.field("reachable_declarations", false)?;
    let reachable_declarations = parser.u64("reachable declaration count")?;
    parser.field("monomorphized_instantiations", false)?;
    let monomorphized_instantiations = parser.u64("monomorphized instantiation count")?;
    parser.field("resolved_interface_calls", false)?;
    let resolved_interface_calls = parser.u64("resolved interface call count")?;
    parser.field("artifact_bytes", false)?;
    let artifact_bytes = parser.u64("artifact byte count")?;
    parser.field("artifact_sha256", false)?;
    let artifact_digest = parser.digest("SHA-256 digest")?;
    parser.field("relocation_directory_bytes", false)?;
    let relocation_directory_bytes = parser.u64("base-relocation directory byte count")?;
    parser.field("base_relocation_blocks", false)?;
    let base_relocation_blocks = parser.u32("base-relocation block count")?;
    parser.field("base_relocation_dir64_count", false)?;
    let base_relocation_dir64_count = parser.u32("DIR64 base-relocation count")?;
    parser.field("base_relocation_provenance_sha256", false)?;
    let base_relocation_provenance_digest = parser.digest("SHA-256 digest")?;

    parser.field("bounds", false)?;
    let bounds = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_bound(parser)?;
        budget.analysis_payloads([&fact.category, &fact.owner, &fact.source, &fact.unit])?;
        Ok(fact)
    })?;
    parser.field("actor_lowerings", false)?;
    let actor_lowerings = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_actor_lowering(parser)?;
        budget.analysis_payloads([&fact.source, &fact.destination, &fact.message])?;
        Ok(fact)
    })?;
    parser.field("image_nodes", false)?;
    let image_nodes = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_image_node(parser)?;
        budget.analysis_payloads([&fact.kind, &fact.name, &fact.owner, &fact.source])?;
        Ok(fact)
    })?;
    parser.field("iso_pools", false)?;
    let iso_pools = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_iso_pool(parser)?;
        budget.analysis_payloads([
            &fact.pool,
            &fact.brand,
            &fact.region,
            &fact.payload_type,
            &fact.owner,
            &fact.source,
            &fact.brand_source,
            &fact.slots_source,
            &fact.maximum_payload_source,
            &fact.payload_source,
        ])?;
        Ok(fact)
    })?;
    parser.field("region_capacity_evidence", false)?;
    let region_capacity_evidence = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_region_capacity_evidence(parser)?;
        budget.analysis_payload(&fact.region)?;
        Ok(fact)
    })?;
    parser.field("activation_frame_evidence", false)?;
    let activation_frame_evidence = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_activation_frame_evidence(parser)?;
        budget.analysis_payloads([
            &fact.region,
            &fact.caller,
            &fact.callee,
            &fact.owner,
            &fact.source,
        ])?;
        Ok(fact)
    })?;
    parser.field("image_edges", false)?;
    let image_edges = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_image_edge(parser)?;
        budget.analysis_payloads([&fact.kind, &fact.source, &fact.destination])?;
        Ok(fact)
    })?;
    parser.field("work", false)?;
    let work = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_work(parser)?;
        budget.analysis_payload(&fact.function)?;
        Ok(fact)
    })?;
    parser.field("hardware", false)?;
    let hardware = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_hardware(parser)?;
        budget.analysis_payloads([&fact.device, &fact.binding, &fact.owner, &fact.dma_policy])?;
        Ok(fact)
    })?;
    parser.field("recovery", false)?;
    let recovery = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_recovery(parser, &mut budget)?;
        budget.analysis_payloads([&fact.subject, &fact.supervisor])?;
        Ok(fact)
    })?;
    parser.field("scheduler_ownership", false)?;
    let scheduler_ownership = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_scheduler_ownership(parser, &mut budget)?;
        Ok(fact)
    })?;
    parser.field("actor_placement_inputs", false)?;
    let actor_placement_inputs = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_actor_placement_input(parser)?;
        budget.analysis_payload(&fact.actor)?;
        Ok(fact)
    })?;
    parser.field("compiled_test_group", false)?;
    let compiled_test_group = parse_compiled_test_group(&mut parser, &mut budget)?;
    parser.field("startup_order", false)?;
    let startup_order = parse_string_array(&mut parser, |value| {
        budget.analysis_item()?;
        budget.analysis_payload(value)
    })?;
    parser.field("shutdown_order", false)?;
    let shutdown_order = parse_string_array(&mut parser, |value| {
        budget.analysis_item()?;
        budget.analysis_payload(value)
    })?;
    parser.field("proofs", false)?;
    let proofs = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_proof(parser, &mut budget)?;
        budget.analysis_payloads([&fact.category, &fact.subject, &fact.result])?;
        Ok(fact)
    })?;
    parser.field("region_assignments", false)?;
    let region_assignments = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_region_assignment(parser)?;
        budget.analysis_payload(&fact.allocation)?;
        Ok(fact)
    })?;
    parser.field("promotions", false)?;
    let promotions = parse_array(&mut parser, |parser| {
        budget.analysis_item()?;
        let fact = parse_promotion(parser)?;
        budget.analysis_payloads([&fact.allocation, &fact.reason])?;
        Ok(fact)
    })?;

    parser.field("sections", false)?;
    let sections = parse_array(&mut parser, |parser| {
        budget.backend_item()?;
        let fact = parse_section(parser)?;
        budget.backend_payloads([&fact.name, &fact.owner])?;
        Ok(fact)
    })?;
    parser.field("symbols", false)?;
    let symbols = parse_array(&mut parser, |parser| {
        budget.backend_item()?;
        let fact = parse_symbol(parser)?;
        budget.backend_payloads([&fact.name, &fact.section])?;
        Ok(fact)
    })?;
    parser.field("representations", false)?;
    let representations = parse_representations(&mut parser)?;
    budget.backend_payload(&representations.optimization_pipeline_name)?;
    parser.field("required_runtime_intrinsics", false)?;
    let required_runtime_intrinsics = parse_string_array(&mut parser, |value| {
        budget.backend_item()?;
        budget.backend_payload(value)
    })?;
    parser.field("target_variable_reservations", false)?;
    let target_variable_reservations = parse_array(&mut parser, |parser| {
        budget.backend_item()?;
        let fact = parse_bound(parser)?;
        budget.backend_payloads([&fact.category, &fact.owner, &fact.source, &fact.unit])?;
        Ok(fact)
    })?;
    parser.field("excluded_target_variables", false)?;
    let excluded_target_variables = parse_string_array(&mut parser, |value| {
        budget.backend_item()?;
        budget.backend_payload(value)
    })?;
    parser.field("optimization_decisions", false)?;
    let optimization_decisions = parse_array(&mut parser, |parser| {
        budget.backend_item()?;
        let fact = parse_optimization_decision(parser, &mut budget)?;
        budget.backend_payloads([&fact.pass, &fact.subject, &fact.justification])?;
        Ok(fact)
    })?;
    parser.object_end()?;
    parser.finish()?;

    let analysis = AnalysisFacts {
        reachable_declarations,
        monomorphized_instantiations,
        resolved_interface_calls,
        bounds,
        proofs,
        actor_lowerings,
        image_nodes,
        iso_pools,
        region_capacity_evidence,
        activation_frame_evidence,
        region_assignments,
        promotions,
        image_edges,
        work,
        hardware,
        recovery,
        actor_placement_inputs,
        scheduler_ownership,
        compiled_test_group,
        startup_order,
        shutdown_order,
    };
    let sealed_analysis = seal_analysis_facts(
        AnalysisFactRequest {
            build: expected_build,
            image_name: &image_name,
            limits: analysis_limits,
        },
        analysis,
        is_cancelled,
    )?;
    let backend = BackendFacts {
        flow_wir_digest,
        artifact_bytes,
        artifact_digest,
        relocation_directory_bytes,
        base_relocation_blocks,
        base_relocation_dir64_count,
        base_relocation_provenance_digest,
        sections,
        symbols,
        representations,
        required_runtime_intrinsics,
        target_variable_reservations,
        excluded_target_variables,
        optimization_decisions,
    };
    let report = ImageReport::new(
        copy_build_identity(expected_build)?,
        image_name,
        sealed_analysis,
        backend,
        backend_limits,
        is_cancelled,
    )?;
    let canonical = report.to_json_with_cancellation(is_cancelled)?;
    if canonical.as_bytes() != bytes {
        return Err(ReportError::NonCanonical("JSON encoding"));
    }
    Ok(report)
}

fn parse_expected_digest(
    parser: &mut Parser<'_>,
    field: &'static str,
    expected: Sha256Digest,
) -> Result<(), ReportError> {
    parser.field(field, false)?;
    if parser.digest("SHA-256 digest")? != expected {
        return Err(ReportError::IdentityMismatch);
    }
    Ok(())
}

fn parse_bound(parser: &mut Parser<'_>) -> Result<BoundFact, ReportError> {
    parser.object_start()?;
    parser.field("category", true)?;
    let category = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("source", false)?;
    let source = parser.string()?;
    parser.field("amount", false)?;
    let amount = parser.u64("bound amount")?;
    parser.field("unit", false)?;
    let unit = parser.string()?;
    parser.object_end()?;
    Ok(BoundFact {
        category,
        owner,
        source,
        amount,
        unit,
    })
}

fn parse_actor_lowering(parser: &mut Parser<'_>) -> Result<ActorLoweringFact, ReportError> {
    parser.object_start()?;
    parser.field("source", true)?;
    let source = parser.string()?;
    parser.field("destination", false)?;
    let destination = parser.string()?;
    parser.field("message", false)?;
    let message = parser.string()?;
    parser.field("kind", false)?;
    let kind = match parser.string()?.as_str() {
        "queued" => ActorLoweringKind::Queued,
        "direct-dispatch" => ActorLoweringKind::DirectDispatch,
        "tail-forwarded" => ActorLoweringKind::TailForwarded,
        "fused" => ActorLoweringKind::Fused,
        _ => return Err(ReportError::InvalidEncoding("actor lowering kind")),
    };
    parser.field("logical_slots", false)?;
    let logical_slots = parser.u64("logical slot count")?;
    parser.field("physical_bytes", false)?;
    let physical_bytes = parser.u64("physical byte count")?;
    parser.object_end()?;
    Ok(ActorLoweringFact {
        source,
        destination,
        message,
        kind,
        logical_slots,
        physical_bytes,
    })
}

fn parse_image_node(parser: &mut Parser<'_>) -> Result<ImageNodeFact, ReportError> {
    parser.object_start()?;
    parser.field("kind", true)?;
    let kind = parser.string()?;
    parser.field("name", false)?;
    let name = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("source", false)?;
    let source = parser.string()?;
    parser.field("static_bytes", false)?;
    let static_bytes = parser.u64("static byte count")?;
    parser.object_end()?;
    Ok(ImageNodeFact {
        kind,
        name,
        owner,
        source,
        static_bytes,
    })
}

fn parse_iso_pool(parser: &mut Parser<'_>) -> Result<IsoPoolFact, ReportError> {
    parser.object_start()?;
    parser.field("pool", true)?;
    let pool = parser.string()?;
    parser.field("brand", false)?;
    let brand = parser.string()?;
    parser.field("region", false)?;
    let region = parser.string()?;
    parser.field("payload_type", false)?;
    let payload_type = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("source", false)?;
    let source = parser.string()?;
    parser.field("brand_source", false)?;
    let brand_source = parser.string()?;
    parser.field("slots_source", false)?;
    let slots_source = parser.string()?;
    parser.field("maximum_payload_source", false)?;
    let maximum_payload_source = parser.string()?;
    parser.field("payload_source", false)?;
    let payload_source = parser.string()?;
    parser.field("slots", false)?;
    let slots = parser.u64("iso pool slot count")?;
    parser.field("maximum_payload_bytes", false)?;
    let maximum_payload_bytes = parser.u64("iso pool maximum payload bytes")?;
    parser.field("payload_bytes", false)?;
    let payload_bytes = parser.u64("iso pool payload bytes")?;
    parser.field("alignment", false)?;
    let alignment = parser.u32("iso pool alignment")?;
    parser.field("capacity_proof", false)?;
    let capacity_proof = parser.u32("iso pool capacity proof identifier")?;
    parser.object_end()?;
    Ok(IsoPoolFact {
        pool,
        brand,
        region,
        payload_type,
        owner,
        source,
        brand_source,
        slots_source,
        maximum_payload_source,
        payload_source,
        slots,
        maximum_payload_bytes,
        payload_bytes,
        alignment,
        capacity_proof,
    })
}

fn parse_region_capacity_evidence(
    parser: &mut Parser<'_>,
) -> Result<RegionCapacityEvidenceFact, ReportError> {
    parser.object_start()?;
    parser.field("region", true)?;
    let region = parser.string()?;
    parser.field("capacity_proof", false)?;
    let capacity_proof = parser.u32("region capacity proof identifier")?;
    parser.object_end()?;
    Ok(RegionCapacityEvidenceFact {
        region,
        capacity_proof,
    })
}

fn parse_region_class(parser: &mut Parser<'_>) -> Result<RegionClass, ReportError> {
    match parser.string()?.as_str() {
        "image" => Ok(RegionClass::Image),
        "task-frame" => Ok(RegionClass::TaskFrame),
        "call" => Ok(RegionClass::Call),
        "request" => Ok(RegionClass::Request),
        "pool" => Ok(RegionClass::Pool),
        "static" => Ok(RegionClass::Static),
        _ => Err(ReportError::InvalidEncoding("region class")),
    }
}

fn parse_region_assignment(parser: &mut Parser<'_>) -> Result<RegionAssignmentFact, ReportError> {
    parser.object_start()?;
    parser.field("allocation", true)?;
    let allocation = parser.string()?;
    parser.field("region_class", false)?;
    let region_class = parse_region_class(parser)?;
    parser.object_end()?;
    Ok(RegionAssignmentFact {
        allocation,
        region_class,
    })
}

fn parse_promotion(parser: &mut Parser<'_>) -> Result<PromotionFact, ReportError> {
    parser.object_start()?;
    parser.field("allocation", true)?;
    let allocation = parser.string()?;
    parser.field("source_region", false)?;
    let source_region = parse_region_class(parser)?;
    parser.field("destination_region", false)?;
    let destination_region = parse_region_class(parser)?;
    parser.field("reason", false)?;
    let reason = parser.string()?;
    parser.field("proof", false)?;
    let proof = parser.u32("promotion proof identifier")?;
    parser.object_end()?;
    Ok(PromotionFact {
        allocation,
        source_region,
        destination_region,
        reason,
        proof,
    })
}

fn parse_scheduler_ownership(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<SchedulerOwnershipFact, ReportError> {
    parser.object_start()?;
    parser.field("core", true)?;
    let core = parser.u32("scheduler core identifier")?;
    parser.field("actors", false)?;
    let actors = parse_string_array(parser, |value| {
        budget.analysis_item()?;
        budget.analysis_payload(value)
    })?;
    parser.field("tasks", false)?;
    let tasks = parse_string_array(parser, |value| {
        budget.analysis_item()?;
        budget.analysis_payload(value)
    })?;
    parser.object_end()?;
    Ok(SchedulerOwnershipFact {
        core,
        actors,
        tasks,
    })
}

fn parse_actor_placement_input(
    parser: &mut Parser<'_>,
) -> Result<ActorPlacementInputFact, ReportError> {
    parser.object_start()?;
    parser.field("actor", true)?;
    let actor = parser.string()?;
    parser.field("maximum_uninterrupted_work", false)?;
    let maximum_uninterrupted_work = parser.u64("actor maximum uninterrupted work")?;
    parser.field("reserved_region_bytes", false)?;
    let reserved_region_bytes = parser.u64("actor reserved region byte count")?;
    parser.object_end()?;
    Ok(ActorPlacementInputFact {
        actor,
        maximum_uninterrupted_work,
        reserved_region_bytes,
    })
}

fn parse_activation_frame_evidence(
    parser: &mut Parser<'_>,
) -> Result<ActivationFrameEvidenceFact, ReportError> {
    parser.object_start()?;
    parser.field("plan", true)?;
    let plan = parser.u32("activation plan identifier")?;
    parser.field("region", false)?;
    let region = parser.string()?;
    parser.field("caller", false)?;
    let caller = parser.string()?;
    parser.field("callee", false)?;
    let callee = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("source", false)?;
    let source = parser.string()?;
    parser.field("frame_bytes", false)?;
    let frame_bytes = parser.u64("activation frame byte count")?;
    parser.field("maximum_live", false)?;
    let maximum_live = parser.u32("activation maximum live count")?;
    parser.field("cancellation", false)?;
    let cancellation = match parser.string()?.as_str() {
        "drop-callee-then-propagate" => ActivationCancellationFact::DropCalleeThenPropagate,
        _ => return Err(ReportError::InvalidEncoding("activation cancellation")),
    };
    parser.field("capacity_proof", false)?;
    let capacity_proof = parser.u32("activation capacity proof identifier")?;
    parser.object_end()?;
    Ok(ActivationFrameEvidenceFact {
        plan,
        region,
        caller,
        callee,
        owner,
        source,
        frame_bytes,
        maximum_live,
        cancellation,
        capacity_proof,
    })
}

fn parse_image_edge(parser: &mut Parser<'_>) -> Result<ImageEdgeFact, ReportError> {
    parser.object_start()?;
    parser.field("kind", true)?;
    let kind = parser.string()?;
    parser.field("source", false)?;
    let source = parser.string()?;
    parser.field("destination", false)?;
    let destination = parser.string()?;
    parser.field("capacity", false)?;
    let capacity = parser.optional_u64("edge capacity")?;
    parser.field("priority", false)?;
    let priority = parser
        .optional_u64("edge priority")?
        .map(|value| u8::try_from(value).map_err(|_| ReportError::InvalidEncoding("edge priority")))
        .transpose()?;
    parser.object_end()?;
    Ok(ImageEdgeFact {
        kind,
        source,
        destination,
        capacity,
        priority,
    })
}

fn parse_work(parser: &mut Parser<'_>) -> Result<WorkFact, ReportError> {
    parser.object_start()?;
    parser.field("function", true)?;
    let function = parser.string()?;
    parser.field("stack_bytes", false)?;
    let stack_bytes = parser.u64("stack byte count")?;
    parser.field("frame_bytes", false)?;
    let frame_bytes = parser.u64("frame byte count")?;
    parser.field("uninterrupted_work", false)?;
    let uninterrupted_work = parser.optional_u64("uninterrupted work")?;
    parser.field("checkpoint_count", false)?;
    let checkpoint_count = parser.u64("checkpoint count")?;
    parser.object_end()?;
    Ok(WorkFact {
        function,
        stack_bytes,
        frame_bytes,
        uninterrupted_work,
        checkpoint_count,
    })
}

fn parse_hardware(parser: &mut Parser<'_>) -> Result<HardwareFact, ReportError> {
    parser.object_start()?;
    parser.field("device", true)?;
    let device = parser.string()?;
    parser.field("binding", false)?;
    let binding = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("dma_policy", false)?;
    let dma_policy = parser.string()?;
    parser.field("queue_capacity", false)?;
    let queue_capacity = parser.optional_u64("queue capacity")?;
    parser.field("maximum_in_flight", false)?;
    let maximum_in_flight = parser.optional_u64("maximum in-flight count")?;
    parser.object_end()?;
    Ok(HardwareFact {
        device,
        binding,
        owner,
        dma_policy,
        queue_capacity,
        maximum_in_flight,
    })
}

fn parse_recovery(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<RecoveryFact, ReportError> {
    parser.object_start()?;
    parser.field("subject", true)?;
    let subject = parser.string()?;
    parser.field("supervisor", false)?;
    let supervisor = parser.string()?;
    parser.field("reset_timeout_ns", false)?;
    let reset_timeout_ns = parser.u64("reset timeout")?;
    parser.field("quarantine_bytes", false)?;
    let quarantine_bytes = parser.u64("quarantine byte count")?;
    parser.field("cleanup_path", false)?;
    let cleanup_path = parse_string_array(parser, |value| {
        budget.analysis_proof_edge()?;
        budget.analysis_payload(value)
    })?;
    parser.object_end()?;
    Ok(RecoveryFact {
        subject,
        supervisor,
        reset_timeout_ns,
        quarantine_bytes,
        cleanup_path,
    })
}

fn parse_compiled_test_group(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<Option<FullImageTestGroup>, ReportError> {
    if parser.consume_null()? {
        return Ok(None);
    }
    budget.analysis_item()?;
    parser.object_start()?;
    parser.field("id", true)?;
    let id = ImageGroupId(parser.u32("test-group identifier")?);
    parser.field("name", false)?;
    let name = parser.string()?;
    budget.analysis_payload(&name)?;
    parser.field("root", false)?;
    parser.object_start()?;
    parser.field("kind", true)?;
    let root = match parser.string()?.as_str() {
        "generated-harness" => {
            parser.field("harness_name", false)?;
            let harness_name = parser.string()?;
            budget.analysis_payload(&harness_name)?;
            ImageRoot::GeneratedHarness { harness_name }
        }
        "declared-image" => {
            parser.field("image_name", false)?;
            let image_name = parser.string()?;
            budget.analysis_payload(&image_name)?;
            parser.field("scenario", false)?;
            let scenario = ScenarioId(parser.u32("scenario identifier")?);
            ImageRoot::Declared {
                image_name,
                scenario,
            }
        }
        _ => return Err(ReportError::InvalidEncoding("test-group root kind")),
    };
    parser.object_end()?;
    parser.field("tests", false)?;
    let tests = parse_array(parser, |parser| {
        budget.analysis_item()?;
        parse_compiled_test(parser, budget)
    })?;
    parser.field("deterministic_seed", false)?;
    let deterministic_seed = parser.optional_u64("deterministic seed")?;
    parser.field("boot_timeout_ns", false)?;
    let boot_timeout_ns = parser.u64("boot timeout")?;
    parser.field("shutdown_timeout_ns", false)?;
    let shutdown_timeout_ns = parser.u64("shutdown timeout")?;
    parser.field("maximum_events", false)?;
    let maximum_events = parser.u32("maximum event count")?;
    parser.field("maximum_output_bytes", false)?;
    let maximum_output_bytes = parser.u64("maximum output bytes")?;
    parser.object_end()?;
    Ok(Some(FullImageTestGroup {
        id,
        name,
        root,
        tests,
        deterministic_seed,
        boot_timeout_ns,
        shutdown_timeout_ns,
        maximum_events,
        maximum_output_bytes,
    }))
}

fn parse_compiled_test(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<ImageTest, ReportError> {
    parser.object_start()?;
    parser.field("id", true)?;
    let id = TestId(parser.u32("test identifier")?);
    parser.field("name", false)?;
    let name = parser.string()?;
    budget.analysis_payload(&name)?;
    parser.field("kind", false)?;
    let kind = match parser.string()?.as_str() {
        "comptime-unit" => TestKind::ComptimeUnit,
        "integration-image" => TestKind::IntegrationImage,
        "declared-image" => TestKind::DeclaredImage,
        _ => return Err(ReportError::InvalidEncoding("planned test kind")),
    };
    parser.field("source", false)?;
    let source = parse_optional_source(parser)?;
    parser.field("timeout_ns", false)?;
    let timeout_ns = parser.u64("test timeout")?;
    parser.field("invocation", false)?;
    parser.object_start()?;
    parser.field("kind", true)?;
    let invocation = match parser.string()?.as_str() {
        "generated-function" => {
            parser.field("function_key_sha256", false)?;
            ImageTestInvocation::GeneratedFunction {
                function_key: FunctionKey(parser.digest("function-key SHA-256 digest")?),
            }
        }
        "declared-scenario" => ImageTestInvocation::DeclaredScenario,
        _ => return Err(ReportError::InvalidEncoding("test invocation kind")),
    };
    parser.object_end()?;
    parser.field("assertions", false)?;
    let assertions = parse_array(parser, |parser| {
        budget.analysis_item()?;
        parser.object_start()?;
        parser.field("source", true)?;
        let source = parse_optional_source(parser)?
            .ok_or(ReportError::InvalidEncoding("planned assertion source"))?;
        parser.field("expression", false)?;
        let expression = parser.string()?;
        budget.analysis_payload(&expression)?;
        parser.field("message", false)?;
        let message = if parser.consume_null()? {
            None
        } else {
            let message = parser.string()?;
            budget.analysis_payload(&message)?;
            Some(message)
        };
        parser.object_end()?;
        Ok(PlannedAssertionDescriptor {
            source,
            expression,
            message,
        })
    })?;
    parser.object_end()?;
    Ok(ImageTest {
        descriptor: TestDescriptor {
            id,
            name,
            kind,
            source,
            timeout_ns,
        },
        invocation,
        assertions,
    })
}

fn parse_optional_source(parser: &mut Parser<'_>) -> Result<Option<Span>, ReportError> {
    if parser.consume_null()? {
        return Ok(None);
    }
    parser.object_start()?;
    parser.field("file", true)?;
    let file = FileId(parser.u32("source file identifier")?);
    parser.field("start", false)?;
    let start = parser.u32("source start offset")?;
    parser.field("end", false)?;
    let end = parser.u32("source end offset")?;
    parser.object_end()?;
    Ok(Some(Span {
        file,
        range: TextRange { start, end },
    }))
}

fn parse_proof(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<ProofFact, ReportError> {
    parser.object_start()?;
    parser.field("id", true)?;
    let id = parser.u32("proof identifier")?;
    parser.field("category", false)?;
    let category = parser.string()?;
    parser.field("subject", false)?;
    let subject = parser.string()?;
    parser.field("result", false)?;
    let result = parser.string()?;
    parser.field("bound", false)?;
    let bound = parser.optional_u64("proof bound")?;
    parser.field("sources", false)?;
    let sources = parse_string_array(parser, |value| {
        budget.analysis_proof_edge()?;
        budget.analysis_payload(value)
    })?;
    parser.field("depends_on", false)?;
    let depends_on = parse_array(parser, |parser| {
        budget.analysis_proof_edge()?;
        parser.u32("proof dependency identifier")
    })?;
    parser.field("why_chain", false)?;
    let why_chain = parse_string_array(parser, |value| {
        budget.analysis_proof_edge()?;
        budget.analysis_payload(value)
    })?;
    parser.object_end()?;
    Ok(ProofFact {
        id,
        category,
        subject,
        result,
        bound,
        sources,
        depends_on,
        why_chain,
    })
}

fn parse_section(parser: &mut Parser<'_>) -> Result<SectionFact, ReportError> {
    parser.object_start()?;
    parser.field("name", true)?;
    let name = parser.string()?;
    parser.field("owner", false)?;
    let owner = parser.string()?;
    parser.field("bytes", false)?;
    let bytes = parser.u64("section byte count")?;
    parser.object_end()?;
    Ok(SectionFact { name, owner, bytes })
}

fn parse_symbol(parser: &mut Parser<'_>) -> Result<SymbolFact, ReportError> {
    parser.object_start()?;
    parser.field("name", true)?;
    let name = parser.string()?;
    parser.field("section", false)?;
    let section = parser.string()?;
    parser.field("offset", false)?;
    let offset = parser.u64("symbol offset")?;
    parser.field("bytes", false)?;
    let bytes = parser.u64("symbol byte count")?;
    parser.object_end()?;
    Ok(SymbolFact {
        name,
        section,
        offset,
        bytes,
    })
}

fn parse_representations(parser: &mut Parser<'_>) -> Result<RepresentationFacts, ReportError> {
    parser.object_start()?;
    parser.field("semantic_wir_version", true)?;
    let semantic_wir_version = parser.u32("SemanticWir version")?;
    parser.field("flow_wir_version", false)?;
    let flow_wir_version = parser.u32("FlowWir version")?;
    parser.field("flow_wir_wire_version", false)?;
    let flow_wir_wire_version = parser.u32("FlowWir wire version")?;
    parser.field("machine_wir_version", false)?;
    let machine_wir_version = parser.u32("MachineWir version")?;
    parser.field("runtime_abi_version", false)?;
    let runtime_abi_version = parser.u32("runtime ABI version")?;
    parser.field("optimization_pipeline_name", false)?;
    let optimization_pipeline_name = parser.string()?;
    parser.field("optimization_pipeline_revision", false)?;
    let optimization_pipeline_revision = parser.u32("optimization pipeline revision")?;
    parser.field("optimization_pipeline_implementation_sha256", false)?;
    let optimization_pipeline_implementation = parser.digest("SHA-256 digest")?;
    parser.object_end()?;
    Ok(RepresentationFacts {
        semantic_wir_version,
        flow_wir_version,
        flow_wir_wire_version,
        machine_wir_version,
        runtime_abi_version,
        optimization_pipeline_name,
        optimization_pipeline_revision,
        optimization_pipeline_implementation,
    })
}

fn parse_optimization_decision(
    parser: &mut Parser<'_>,
    budget: &mut DecodeBudget,
) -> Result<OptimizationDecisionFact, ReportError> {
    parser.object_start()?;
    parser.field("pass", true)?;
    let pass = parser.string()?;
    parser.field("subject", false)?;
    let subject = parser.string()?;
    parser.field("action", false)?;
    let action = match parser.string()?.as_str() {
        "removed" => OptimizationAction::Removed,
        "folded" => OptimizationAction::Folded,
        "inlined" => OptimizationAction::Inlined,
        "coalesced" => OptimizationAction::Coalesced,
        "reordered" => OptimizationAction::Reordered,
        "retained" => OptimizationAction::Retained,
        _ => return Err(ReportError::InvalidEncoding("optimization action")),
    };
    parser.field("justification", false)?;
    let justification = parser.string()?;
    parser.field("relied_on", false)?;
    let relied_on = parse_array(parser, |parser| {
        budget.backend_proof_edge()?;
        parser.u32("optimization proof identifier")
    })?;
    parser.object_end()?;
    Ok(OptimizationDecisionFact {
        pass,
        subject,
        action,
        justification,
        relied_on,
    })
}

fn parse_string_array(
    parser: &mut Parser<'_>,
    mut account: impl FnMut(&str) -> Result<(), ReportError>,
) -> Result<Vec<String>, ReportError> {
    parse_array(parser, |parser| {
        let value = parser.string()?;
        account(&value)?;
        Ok(value)
    })
}

fn parse_array<T>(
    parser: &mut Parser<'_>,
    mut parse_item: impl FnMut(&mut Parser<'_>) -> Result<T, ReportError>,
) -> Result<Vec<T>, ReportError> {
    parser.array_start()?;
    let mut values = Vec::new();
    if parser.consume(b']')? {
        return Ok(values);
    }
    loop {
        parser.check_cancelled()?;
        let item = parse_item(parser)?;
        values
            .try_reserve(1)
            .map_err(|_| parser.allocation_error())?;
        values.push(item);
        if parser.consume(b']')? {
            return Ok(values);
        }
        parser.expect(b',', "array separator")?;
    }
}

struct DecodeBudget {
    analysis_limits: AnalysisFactLimits,
    backend_limits: BackendFactLimits,
    analysis_items: u64,
    analysis_proof_edges: u64,
    analysis_payload_bytes: u64,
    backend_items: u64,
    backend_proof_edges: u64,
    backend_payload_bytes: u64,
}

impl DecodeBudget {
    const fn new(analysis_limits: AnalysisFactLimits, backend_limits: BackendFactLimits) -> Self {
        Self {
            analysis_limits,
            backend_limits,
            analysis_items: 0,
            analysis_proof_edges: 0,
            analysis_payload_bytes: 0,
            backend_items: 0,
            backend_proof_edges: 0,
            backend_payload_bytes: 0,
        }
    }

    fn analysis_item(&mut self) -> Result<(), ReportError> {
        add_bounded(
            &mut self.analysis_items,
            1,
            self.analysis_limits.items,
            "analysis fact items",
        )
    }

    fn analysis_proof_edge(&mut self) -> Result<(), ReportError> {
        add_bounded(
            &mut self.analysis_proof_edges,
            1,
            self.analysis_limits.proof_edges,
            "analysis proof edges",
        )
    }

    fn analysis_payload(&mut self, value: &str) -> Result<(), ReportError> {
        add_bounded(
            &mut self.analysis_payload_bytes,
            u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?,
            self.analysis_limits.payload_bytes,
            "analysis fact payload",
        )
    }

    fn analysis_payloads<const N: usize>(&mut self, values: [&str; N]) -> Result<(), ReportError> {
        for value in values {
            self.analysis_payload(value)?;
        }
        Ok(())
    }

    fn backend_item(&mut self) -> Result<(), ReportError> {
        add_bounded(
            &mut self.backend_items,
            1,
            self.backend_limits.items,
            "backend fact items",
        )
    }

    fn backend_proof_edge(&mut self) -> Result<(), ReportError> {
        add_bounded(
            &mut self.backend_proof_edges,
            1,
            self.backend_limits.optimization_proof_edges,
            "optimization proof edges",
        )
    }

    fn backend_payload(&mut self, value: &str) -> Result<(), ReportError> {
        add_bounded(
            &mut self.backend_payload_bytes,
            u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?,
            self.backend_limits.payload_bytes,
            "backend fact payload",
        )
    }

    fn backend_payloads<const N: usize>(&mut self, values: [&str; N]) -> Result<(), ReportError> {
        for value in values {
            self.backend_payload(value)?;
        }
        Ok(())
    }
}

fn add_bounded(
    total: &mut u64,
    amount: u64,
    limit: u64,
    resource: &'static str,
) -> Result<(), ReportError> {
    *total = total
        .checked_add(amount)
        .ok_or(ReportError::MeasurementOverflow)?;
    if *total > limit {
        return Err(ReportError::ResourceLimit { resource, limit });
    }
    Ok(())
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    maximum_bytes: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Parser<'a> {
    const fn new(bytes: &'a [u8], maximum_bytes: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes,
            position: 0,
            maximum_bytes,
            is_cancelled,
        }
    }

    const fn allocation_error(&self) -> ReportError {
        ReportError::ResourceLimit {
            resource: "decoded image report allocation",
            limit: self.maximum_bytes,
        }
    }

    fn check_cancelled(&self) -> Result<(), ReportError> {
        if (self.is_cancelled)() {
            Err(ReportError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn object_start(&mut self) -> Result<(), ReportError> {
        self.expect(b'{', "JSON object")
    }

    fn object_end(&mut self) -> Result<(), ReportError> {
        self.expect(b'}', "JSON object terminator")
    }

    fn array_start(&mut self) -> Result<(), ReportError> {
        self.expect(b'[', "JSON array")
    }

    fn field(&mut self, expected: &'static str, first: bool) -> Result<(), ReportError> {
        if !first {
            self.expect(b',', "object field separator")?;
        }
        if self.string()? != expected {
            return Err(ReportError::InvalidEncoding("JSON field"));
        }
        self.expect(b':', "object field separator")
    }

    fn expected_string(&mut self, expected: &str) -> Result<(), ReportError> {
        if self.string()? != expected {
            return Err(ReportError::IdentityMismatch);
        }
        Ok(())
    }

    fn digest(&mut self, kind: &'static str) -> Result<Sha256Digest, ReportError> {
        let value = self.string()?;
        let encoded = value.as_bytes();
        if encoded.len() != 64 {
            return Err(ReportError::InvalidEncoding(kind));
        }
        let mut digest = [0u8; 32];
        for (output, pair) in digest.iter_mut().zip(encoded.chunks_exact(2)) {
            let high = lower_hex(pair[0]).ok_or(ReportError::InvalidEncoding(kind))?;
            let low = lower_hex(pair[1]).ok_or(ReportError::InvalidEncoding(kind))?;
            *output = (high << 4) | low;
        }
        Ok(Sha256Digest::from_bytes(digest))
    }

    fn u32(&mut self, kind: &'static str) -> Result<u32, ReportError> {
        u32::try_from(self.u64(kind)?).map_err(|_| ReportError::InvalidEncoding(kind))
    }

    fn u64(&mut self, kind: &'static str) -> Result<u64, ReportError> {
        self.skip_whitespace()?;
        let start = self.position;
        let mut value = 0u64;
        while let Some(byte @ b'0'..=b'9') = self.bytes.get(self.position).copied() {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or(ReportError::InvalidEncoding(kind))?;
            self.position += 1;
            self.check_cancelled()?;
        }
        if self.position == start {
            return Err(ReportError::InvalidEncoding(kind));
        }
        Ok(value)
    }

    fn optional_u64(&mut self, kind: &'static str) -> Result<Option<u64>, ReportError> {
        self.skip_whitespace()?;
        if self.remaining().starts_with(b"null") {
            self.position += 4;
            self.check_cancelled()?;
            Ok(None)
        } else {
            self.u64(kind).map(Some)
        }
    }

    fn string(&mut self) -> Result<String, ReportError> {
        self.skip_whitespace()?;
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(ReportError::InvalidEncoding("JSON string"));
        }
        self.position += 1;
        let mut output = String::new();
        let mut raw_start = self.position;
        loop {
            self.check_cancelled()?;
            let Some(byte) = self.bytes.get(self.position).copied() else {
                return Err(ReportError::InvalidEncoding("JSON string"));
            };
            match byte {
                b'"' => {
                    self.push_utf8(&mut output, &self.bytes[raw_start..self.position])?;
                    self.position += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.push_utf8(&mut output, &self.bytes[raw_start..self.position])?;
                    self.position += 1;
                    self.push_escape(&mut output)?;
                    raw_start = self.position;
                }
                0x00..=0x1f => return Err(ReportError::InvalidEncoding("JSON string")),
                _ => self.position += 1,
            }
        }
    }

    fn push_escape(&mut self, output: &mut String) -> Result<(), ReportError> {
        let Some(escape) = self.bytes.get(self.position).copied() else {
            return Err(ReportError::InvalidEncoding("JSON string escape"));
        };
        self.position += 1;
        match escape {
            b'"' => self.push_character(output, '"')?,
            b'\\' => self.push_character(output, '\\')?,
            b'/' => self.push_character(output, '/')?,
            b'b' => self.push_character(output, '\u{0008}')?,
            b'f' => self.push_character(output, '\u{000c}')?,
            b'n' => self.push_character(output, '\n')?,
            b'r' => self.push_character(output, '\r')?,
            b't' => self.push_character(output, '\t')?,
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if !self.remaining().starts_with(b"\\u") {
                        return Err(ReportError::InvalidEncoding("JSON Unicode escape"));
                    }
                    self.position += 2;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ReportError::InvalidEncoding("JSON Unicode escape"));
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ReportError::InvalidEncoding("JSON Unicode escape"));
                } else {
                    u32::from(first)
                };
                self.push_character(
                    output,
                    char::from_u32(scalar)
                        .ok_or(ReportError::InvalidEncoding("JSON Unicode escape"))?,
                )?;
            }
            _ => return Err(ReportError::InvalidEncoding("JSON string escape")),
        }
        Ok(())
    }

    fn push_utf8(&self, output: &mut String, bytes: &[u8]) -> Result<(), ReportError> {
        let value = str::from_utf8(bytes).map_err(|_| ReportError::InvalidEncoding("UTF-8"))?;
        output
            .try_reserve(value.len())
            .map_err(|_| self.allocation_error())?;
        let mut start = 0;
        while start < value.len() {
            self.check_cancelled()?;
            let mut end = start.saturating_add(4_096).min(value.len());
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            output.push_str(&value[start..end]);
            start = end;
        }
        self.check_cancelled()?;
        Ok(())
    }

    fn push_character(&self, output: &mut String, value: char) -> Result<(), ReportError> {
        output
            .try_reserve(value.len_utf8())
            .map_err(|_| self.allocation_error())?;
        output.push(value);
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, ReportError> {
        let end = self
            .position
            .checked_add(4)
            .ok_or(ReportError::MeasurementOverflow)?;
        let encoded = self
            .bytes
            .get(self.position..end)
            .ok_or(ReportError::InvalidEncoding("JSON Unicode escape"))?;
        let mut value = 0u16;
        for byte in encoded {
            value = (value << 4)
                | u16::from(hex(*byte).ok_or(ReportError::InvalidEncoding("JSON Unicode escape"))?);
        }
        self.position = end;
        Ok(value)
    }

    fn consume(&mut self, expected: u8) -> Result<bool, ReportError> {
        self.skip_whitespace()?;
        if self.bytes.get(self.position) == Some(&expected) {
            self.position += 1;
            self.check_cancelled()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn consume_null(&mut self) -> Result<bool, ReportError> {
        self.skip_whitespace()?;
        if self.remaining().starts_with(b"null") {
            self.position = self
                .position
                .checked_add(4)
                .ok_or(ReportError::MeasurementOverflow)?;
            self.check_cancelled()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect(&mut self, expected: u8, kind: &'static str) -> Result<(), ReportError> {
        if !self.consume(expected)? {
            return Err(ReportError::InvalidEncoding(kind));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.skip_whitespace()?;
        if self.position != self.bytes.len() {
            return Err(ReportError::InvalidEncoding("trailing JSON data"));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) -> Result<(), ReportError> {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
            self.check_cancelled()?;
        }
        Ok(())
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
}

const fn lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};

    use crate::{
        ActorLoweringFact, ActorLoweringKind, ActorPlacementInputFact, AnalysisFactLimits,
        AnalysisFactRequest, AnalysisFacts, BackendFactLimits, BackendFacts, BoundFact,
        HardwareFact, ImageEdgeFact, ImageNodeFact, ImageReport, OptimizationAction,
        OptimizationDecisionFact, PromotionFact, ProofFact, RecoveryFact, RegionAssignmentFact,
        RegionCapacityEvidenceFact, RegionClass, ReportError, RepresentationFacts,
        SchedulerOwnershipFact, SectionFact, SymbolFact, WorkFact, seal_analysis_facts,
    };

    use super::{Parser, decode_image_report_json};

    fn build(byte: u8) -> BuildIdentity {
        let digest = Sha256Digest::from_bytes([byte; 32]);
        BuildIdentity {
            compiler: digest,
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: digest,
            source_graph: digest,
            request: digest,
            profile: digest,
        }
    }

    fn full_report(actor_kind: ActorLoweringKind, action: OptimizationAction) -> ImageReport {
        full_report_with_group(actor_kind, action, None)
    }

    #[allow(clippy::too_many_lines)]
    fn full_report_with_group(
        actor_kind: ActorLoweringKind,
        action: OptimizationAction,
        compiled_test_group: Option<wrela_test_model::FullImageTestGroup>,
    ) -> ImageReport {
        let build = build(0x5a);
        let digest = Sha256Digest::from_bytes([0xa5; 32]);
        let facts = AnalysisFacts {
            reachable_declarations: 7,
            monomorphized_instantiations: 6,
            resolved_interface_calls: 5,
            bounds: vec![
                BoundFact {
                    category: "task-slots".to_owned(),
                    owner: "task:0:alpha".to_owned(),
                    source: "src/\"main\".wr".to_owned(),
                    amount: 4,
                    unit: "slots".to_owned(),
                },
                BoundFact {
                    category: "task-frame".to_owned(),
                    owner: "task:0:alpha".to_owned(),
                    source: "src/main.wr".to_owned(),
                    amount: 48,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:0:alpha-frame".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 48,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:0:alpha-frame".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:1:alpha-spill".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 16,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:1:alpha-spill".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
            ],
            proofs: vec![
                ProofFact {
                    id: 0,
                    category: "capacity-bound".to_owned(),
                    subject: "task:0:alpha".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(4),
                    sources: vec!["file:0:bytes:21..30".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["queue <= 4".to_owned()],
                },
                ProofFact {
                    id: 1,
                    category: "ownership".to_owned(),
                    subject: "device.uart".to_owned(),
                    result: "proved".to_owned(),
                    bound: None,
                    sources: vec!["file:0:bytes:10..20".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["one owner".to_owned()],
                },
                ProofFact {
                    id: 2,
                    category: "region-bound".to_owned(),
                    subject: "alloc:0:actor-state".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: Vec::new(),
                    depends_on: Vec::new(),
                    why_chain: vec!["bounded promotion".to_owned()],
                },
                ProofFact {
                    id: 3,
                    category: "region-bound".to_owned(),
                    subject: "alloc:4:pool-slot".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: Vec::new(),
                    depends_on: Vec::new(),
                    why_chain: vec!["bounded promotion".to_owned()],
                },
            ],
            actor_lowerings: vec![ActorLoweringFact {
                source: "actor:0:alpha".to_owned(),
                destination: "actor:1:beta".to_owned(),
                message: "Ping\\雪".to_owned(),
                kind: actor_kind,
                logical_slots: 4,
                physical_bytes: 64,
            }],
            image_nodes: vec![
                ImageNodeFact {
                    kind: "task".to_owned(),
                    name: "task:0:alpha".to_owned(),
                    owner: "runtime".to_owned(),
                    source: "file:0:bytes:10..20".to_owned(),
                    static_bytes: 0,
                },
                ImageNodeFact {
                    kind: "task-frame-region".to_owned(),
                    name: "region:0:alpha-frame".to_owned(),
                    owner: "task:0:alpha".to_owned(),
                    source: "file:0:bytes:21..30".to_owned(),
                    static_bytes: 48,
                },
                ImageNodeFact {
                    kind: "task-frame-region".to_owned(),
                    name: "region:1:alpha-spill".to_owned(),
                    owner: "task:0:alpha".to_owned(),
                    source: "file:0:bytes:31..40".to_owned(),
                    static_bytes: 16,
                },
            ],
            iso_pools: Vec::new(),
            region_capacity_evidence: vec![
                RegionCapacityEvidenceFact {
                    region: "region:0:alpha-frame".to_owned(),
                    capacity_proof: 0,
                },
                RegionCapacityEvidenceFact {
                    region: "region:1:alpha-spill".to_owned(),
                    capacity_proof: 0,
                },
            ],
            activation_frame_evidence: Vec::new(),
            region_assignments: vec![
                RegionAssignmentFact {
                    allocation: "alloc:0:actor-state".to_owned(),
                    region_class: RegionClass::Image,
                },
                RegionAssignmentFact {
                    allocation: "alloc:1:frame-live".to_owned(),
                    region_class: RegionClass::TaskFrame,
                },
                RegionAssignmentFact {
                    allocation: "alloc:2:scratch".to_owned(),
                    region_class: RegionClass::Call,
                },
                RegionAssignmentFact {
                    allocation: "alloc:3:req-buffer".to_owned(),
                    region_class: RegionClass::Request,
                },
                RegionAssignmentFact {
                    allocation: "alloc:4:pool-slot".to_owned(),
                    region_class: RegionClass::Pool,
                },
                RegionAssignmentFact {
                    allocation: "alloc:5:baked-table".to_owned(),
                    region_class: RegionClass::Static,
                },
            ],
            promotions: vec![
                PromotionFact {
                    allocation: "alloc:0:actor-state".to_owned(),
                    source_region: RegionClass::TaskFrame,
                    destination_region: RegionClass::Image,
                    reason: "escapes through `self.pending`".to_owned(),
                    proof: 2,
                },
                PromotionFact {
                    allocation: "alloc:4:pool-slot".to_owned(),
                    source_region: RegionClass::Call,
                    destination_region: RegionClass::Pool,
                    reason: "moved into durable pool 雪".to_owned(),
                    proof: 3,
                },
            ],
            image_edges: vec![ImageEdgeFact {
                kind: "task-supervision".to_owned(),
                source: "task:0:alpha".to_owned(),
                destination: "runtime".to_owned(),
                capacity: Some(4),
                priority: Some(2),
            }],
            work: vec![WorkFact {
                function: "function:0:alpha.handle".to_owned(),
                stack_bytes: 512,
                frame_bytes: 48,
                uninterrupted_work: Some(99),
                checkpoint_count: 3,
            }],
            hardware: vec![HardwareFact {
                device: "device:0:uart0".to_owned(),
                binding: "pl011".to_owned(),
                owner: "actor:0:alpha".to_owned(),
                dma_policy: "none".to_owned(),
                queue_capacity: Some(8),
                maximum_in_flight: Some(1),
            }],
            recovery: vec![RecoveryFact {
                subject: "device:0:uart0".to_owned(),
                supervisor: "root".to_owned(),
                reset_timeout_ns: 50,
                quarantine_bytes: 256,
                cleanup_path: vec!["mask".to_owned(), "reset".to_owned()],
            }],
            actor_placement_inputs: vec![ActorPlacementInputFact {
                actor: "actor:0:alpha".to_owned(),
                maximum_uninterrupted_work: 99,
                reserved_region_bytes: 48,
            }],
            scheduler_ownership: vec![SchedulerOwnershipFact {
                core: 0,
                actors: vec!["actor:0:alpha".to_owned()],
                tasks: vec!["task:0:alpha".to_owned()],
            }],
            compiled_test_group,
            startup_order: vec!["device:0:uart0".to_owned(), "task:0:alpha".to_owned()],
            shutdown_order: vec!["task:0:alpha".to_owned(), "device:0:uart0".to_owned()],
        };
        let analysis = seal_analysis_facts(
            AnalysisFactRequest {
                build: &build,
                image_name: "image\t雪",
                limits: AnalysisFactLimits::standard(),
            },
            facts,
            &|| false,
        )
        .expect("seal fixture analysis");
        let backend = BackendFacts {
            flow_wir_digest: digest,
            artifact_bytes: 4096,
            artifact_digest: digest,
            relocation_directory_bytes: 24,
            base_relocation_blocks: 2,
            base_relocation_dir64_count: 3,
            base_relocation_provenance_digest: Sha256Digest::from_bytes([0x6b; 32]),
            sections: vec![
                SectionFact {
                    name: ".data".to_owned(),
                    owner: "image".to_owned(),
                    bytes: 32,
                },
                SectionFact {
                    name: ".text".to_owned(),
                    owner: "image".to_owned(),
                    bytes: 64,
                },
            ],
            symbols: vec![SymbolFact {
                name: "entry".to_owned(),
                section: ".text".to_owned(),
                offset: 4,
                bytes: 16,
            }],
            representations: RepresentationFacts {
                semantic_wir_version: 13,
                flow_wir_version: 17,
                flow_wir_wire_version: 17,
                machine_wir_version: 18,
                runtime_abi_version: 2,
                optimization_pipeline_name: "development-v1".to_owned(),
                optimization_pipeline_revision: 8,
                optimization_pipeline_implementation: digest,
            },
            required_runtime_intrinsics: vec![
                "wrela.runtime.enter".to_owned(),
                "wrela.runtime.poll".to_owned(),
            ],
            target_variable_reservations: vec![BoundFact {
                category: "target".to_owned(),
                owner: "runtime".to_owned(),
                source: "target.toml".to_owned(),
                amount: 8192,
                unit: "bytes".to_owned(),
            }],
            excluded_target_variables: vec!["host.clock".to_owned()],
            optimization_decisions: vec![OptimizationDecisionFact {
                pass: "scalar".to_owned(),
                subject: "function:0:alpha.handle".to_owned(),
                action,
                justification: "sealed proofs".to_owned(),
                relied_on: vec![0, 1],
            }],
        };
        ImageReport::new(
            build,
            "image\t雪".to_owned(),
            analysis,
            backend,
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("construct fixture report")
    }

    fn decode(bytes: &[u8]) -> Result<ImageReport, ReportError> {
        decode_image_report_json(
            bytes,
            &build(0x5a),
            AnalysisFactLimits::standard(),
            BackendFactLimits::standard(),
            u64::try_from(bytes.len()).expect("fixture length"),
            &|| false,
        )
    }

    #[test]
    fn generated_and_declared_compiled_group_bindings_round_trip_exactly() {
        let generated = wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(3),
            name: "integration".to_owned(),
            root: wrela_test_model::ImageRoot::GeneratedHarness {
                harness_name: "image\t雪".to_owned(),
            },
            tests: vec![wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(8),
                    name: "passes".to_owned(),
                    kind: wrela_test_model::TestKind::IntegrationImage,
                    source: Some(wrela_source::Span {
                        file: wrela_source::FileId(2),
                        range: wrela_source::TextRange { start: 4, end: 9 },
                    }),
                    timeout_ns: 99,
                },
                invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                    function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                        [0x44; 32],
                    )),
                },
                assertions: Vec::new(),
            }],
            deterministic_seed: Some(5),
            boot_timeout_ns: 11,
            shutdown_timeout_ns: 12,
            maximum_events: 5,
            maximum_output_bytes: 13,
        };
        let declared = wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(4),
            name: "scenario".to_owned(),
            root: wrela_test_model::ImageRoot::Declared {
                image_name: "image\t雪".to_owned(),
                scenario: wrela_test_model::ScenarioId(6),
            },
            tests: vec![wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(9),
                    name: "scenario".to_owned(),
                    kind: wrela_test_model::TestKind::DeclaredImage,
                    source: None,
                    timeout_ns: 101,
                },
                invocation: wrela_test_model::ImageTestInvocation::DeclaredScenario,
                assertions: Vec::new(),
            }],
            deterministic_seed: None,
            boot_timeout_ns: 21,
            shutdown_timeout_ns: 22,
            maximum_events: 23,
            maximum_output_bytes: 24,
        };
        for group in [generated, declared] {
            let report = full_report_with_group(
                ActorLoweringKind::Queued,
                OptimizationAction::Retained,
                Some(group.clone()),
            );
            let json = report.to_json();
            let decoded = decode(json.as_bytes()).expect("compiled group report round trip");
            assert_eq!(
                decoded.analysis().compiled_test_group.as_ref(),
                Some(&group)
            );
        }
    }

    #[test]
    fn canonical_roundtrip_covers_all_fields_and_enum_spellings() {
        let actor_kinds = [
            ActorLoweringKind::Queued,
            ActorLoweringKind::DirectDispatch,
            ActorLoweringKind::TailForwarded,
            ActorLoweringKind::Fused,
        ];
        let actions = [
            OptimizationAction::Removed,
            OptimizationAction::Folded,
            OptimizationAction::Inlined,
            OptimizationAction::Coalesced,
            OptimizationAction::Reordered,
            OptimizationAction::Retained,
        ];
        for (actor_kind, action) in actor_kinds.into_iter().zip(actions.into_iter().cycle()) {
            let report = full_report(actor_kind, action);
            let bytes = report.to_json();
            assert_eq!(decode(bytes.as_bytes()), Ok(report));
        }
        for action in actions {
            let report = full_report(ActorLoweringKind::Queued, action);
            let bytes = report.to_json();
            assert_eq!(decode(bytes.as_bytes()), Ok(report));
        }
    }

    #[test]
    fn canonical_roundtrip_covers_all_optional_number_absences() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained)
            .to_json()
            .replacen(
                "\"uninterrupted_work\":99",
                "\"uninterrupted_work\":null",
                1,
            )
            .replacen("\"queue_capacity\":8", "\"queue_capacity\":null", 1)
            .replacen("\"maximum_in_flight\":1", "\"maximum_in_flight\":null", 1);
        let report = decode(json.as_bytes()).expect("decode absent optional numbers");
        assert_eq!(report.to_json(), json);
        assert_eq!(report.analysis().work[0].uninterrupted_work, None);
        assert_eq!(report.analysis().hardware[0].queue_capacity, None);
        assert_eq!(report.analysis().hardware[0].maximum_in_flight, None);
    }

    #[test]
    fn expected_identity_and_lowercase_digests_are_exact() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        assert_eq!(
            decode_image_report_json(
                json.as_bytes(),
                &build(0x5b),
                AnalysisFactLimits::standard(),
                BackendFactLimits::standard(),
                json.len() as u64,
                &|| false,
            ),
            Err(ReportError::IdentityMismatch)
        );

        let uppercase = json.replacen(&"a5".repeat(32), &"A5".repeat(32), 1);
        assert!(matches!(
            decode(uppercase.as_bytes()),
            Err(ReportError::InvalidEncoding("SHA-256 digest"))
        ));
        let non_hex = json.replacen(&"a5".repeat(32), &format!("{}g5", "a5".repeat(31)), 1);
        assert!(matches!(
            decode(non_hex.as_bytes()),
            Err(ReportError::InvalidEncoding("SHA-256 digest"))
        ));
    }

    #[test]
    fn schema_scalar_enum_and_json_structure_mutations_fail_closed() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        let schema = json.replacen("\"schema\":17", "\"schema\":18", 1);
        assert_eq!(
            decode(schema.as_bytes()),
            Err(ReportError::UnsupportedSchema(18))
        );
        let stale_schema = json.replacen("\"schema\":17", "\"schema\":16", 1);
        assert_eq!(
            decode(stale_schema.as_bytes()),
            Err(ReportError::UnsupportedSchema(16))
        );

        let oversized_u32 = json.replacen(
            "\"semantic_wir_version\":13",
            "\"semantic_wir_version\":4294967296",
            1,
        );
        assert!(matches!(
            decode(oversized_u32.as_bytes()),
            Err(ReportError::InvalidEncoding("SemanticWir version"))
        ));
        let oversized_u64 = json.replacen(
            "\"artifact_bytes\":4096",
            "\"artifact_bytes\":18446744073709551616",
            1,
        );
        assert!(matches!(
            decode(oversized_u64.as_bytes()),
            Err(ReportError::InvalidEncoding("artifact byte count"))
        ));
        let oversized_relocations = json.replacen(
            "\"base_relocation_dir64_count\":3",
            "\"base_relocation_dir64_count\":4294967296",
            1,
        );
        assert!(matches!(
            decode(oversized_relocations.as_bytes()),
            Err(ReportError::InvalidEncoding("DIR64 base-relocation count"))
        ));
        let oversized_capacity_proof =
            json.replacen("\"capacity_proof\":0", "\"capacity_proof\":4294967296", 1);
        assert!(matches!(
            decode(oversized_capacity_proof.as_bytes()),
            Err(ReportError::InvalidEncoding(
                "region capacity proof identifier"
            ))
        ));
        let oversized_u8 = json.replacen("\"priority\":2", "\"priority\":256", 1);
        assert!(matches!(
            decode(oversized_u8.as_bytes()),
            Err(ReportError::InvalidEncoding("edge priority"))
        ));
        let bad_actor = json.replacen("\"kind\":\"queued\"", "\"kind\":\"invalid\"", 1);
        assert!(matches!(
            decode(bad_actor.as_bytes()),
            Err(ReportError::InvalidEncoding("actor lowering kind"))
        ));
        let bad_action = json.replacen("\"action\":\"retained\"", "\"action\":\"invalid\"", 1);
        assert!(matches!(
            decode(bad_action.as_bytes()),
            Err(ReportError::InvalidEncoding("optimization action"))
        ));
        let trailing = format!("{json}x");
        assert!(matches!(
            decode(trailing.as_bytes()),
            Err(ReportError::InvalidEncoding("trailing JSON data"))
        ));
    }

    #[test]
    fn equivalent_but_noncanonical_json_is_rejected_after_reencoding() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        let whitespace = json.replacen('{', "{ ", 1);
        assert_eq!(
            decode(whitespace.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
        let escaped = json.replacen(
            "\"image_name\":\"image\\t雪\"",
            "\"image_name\":\"\\u0069mage\\t雪\"",
            1,
        );
        assert_eq!(
            decode(escaped.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
        let leading_zero = json.replacen("\"artifact_bytes\":4096", "\"artifact_bytes\":04096", 1);
        assert_eq!(
            decode(leading_zero.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
        let leading_zero_relocations = json.replacen(
            "\"base_relocation_dir64_count\":3",
            "\"base_relocation_dir64_count\":03",
            1,
        );
        assert_eq!(
            decode(leading_zero_relocations.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
        let leading_zero_capacity_proof =
            json.replacen("\"capacity_proof\":0", "\"capacity_proof\":00", 1);
        assert_eq!(
            decode(leading_zero_capacity_proof.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
        let trailing_whitespace = format!("{json}\n");
        assert_eq!(
            decode(trailing_whitespace.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );
    }

    #[test]
    fn relocation_evidence_corruption_and_omission_fail_closed() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        for corrupt in [
            json.replacen(
                "\"relocation_directory_bytes\":24",
                "\"relocation_directory_bytes\":0",
                1,
            ),
            json.replacen(
                "\"base_relocation_blocks\":2",
                "\"base_relocation_blocks\":0",
                1,
            ),
            json.replacen(
                "\"base_relocation_dir64_count\":3",
                "\"base_relocation_dir64_count\":0",
                1,
            ),
            json.replacen(&"6b".repeat(32), &"00".repeat(32), 1),
        ] {
            assert_eq!(
                decode(corrupt.as_bytes()),
                Err(ReportError::InvalidMeasurement)
            );
        }

        let missing_relocation_blocks = json.replacen(",\"base_relocation_blocks\":2", "", 1);
        assert!(decode(missing_relocation_blocks.as_bytes()).is_err());
    }

    #[test]
    fn region_capacity_evidence_corruption_and_omission_fail_closed() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        let first = "{\"region\":\"region:0:alpha-frame\",\"capacity_proof\":0}";
        let second = "{\"region\":\"region:1:alpha-spill\",\"capacity_proof\":0}";
        let canonical_pair = format!("{first},{second}");

        for corrupt in [
            json.replacen(",{\"region\":\"region:1:alpha-spill\",\"capacity_proof\":0}", "", 1),
            json.replacen("\"capacity_proof\":0", "\"capacity_proof\":2", 1),
            json.replacen("\"region\":\"region:0:alpha-frame\"", "\"region\":\"task:0:alpha\"", 1),
            json.replacen("\"region\":\"region:0:alpha-frame\"", "\"region\":\"region:9:absent\"", 1),
            json.replacen("\"region\":\"region:0:alpha-frame\"", "\"region\":\"region:00:alpha-frame\"", 1),
            json.replacen("\"category\":\"capacity-bound\"", "\"category\":\"ownership\"", 1),
            json.replacen("\"static_bytes\":48", "\"static_bytes\":49", 1),
            json.replacen(
                "\"region_capacity_evidence\":[",
                "\"region_capacity_evidence\":[{\"region\":\"actor:0:alpha\",\"capacity_proof\":0},",
                1,
            ),
        ] {
            assert!(decode(corrupt.as_bytes()).is_err());
        }

        let duplicate = json.replacen(&canonical_pair, &format!("{first},{first},{second}"), 1);
        assert!(decode(duplicate.as_bytes()).is_err());

        let reordered = json.replacen(&canonical_pair, &format!("{second},{first}"), 1);
        assert_eq!(
            decode(reordered.as_bytes()),
            Err(ReportError::NonCanonical("JSON encoding"))
        );

        let missing_field = json.replacen(
            &format!(",\"region_capacity_evidence\":[{canonical_pair}]"),
            "",
            1,
        );
        assert!(decode(missing_field.as_bytes()).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn encoded_and_fact_resources_are_bounded_during_decode() {
        let report = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained);
        let json = report.to_json();
        let expected = build(0x5a);
        let run = |analysis_limits, backend_limits, maximum_bytes| {
            decode_image_report_json(
                json.as_bytes(),
                &expected,
                analysis_limits,
                backend_limits,
                maximum_bytes,
                &|| false,
            )
        };
        assert!(
            run(
                AnalysisFactLimits::standard(),
                BackendFactLimits::standard(),
                json.len() as u64,
            )
            .is_ok()
        );
        let analysis = report.analysis();
        let exact_analysis_items = [
            analysis.bounds.len(),
            analysis.proofs.len(),
            analysis.actor_lowerings.len(),
            analysis.image_nodes.len(),
            analysis.region_capacity_evidence.len(),
            analysis.region_assignments.len(),
            analysis.promotions.len(),
            analysis.image_edges.len(),
            analysis.work.len(),
            analysis.hardware.len(),
            analysis.recovery.len(),
            analysis.actor_placement_inputs.len(),
            analysis.scheduler_ownership.len(),
            analysis
                .scheduler_ownership
                .iter()
                .map(|fact| fact.actors.len() + fact.tasks.len())
                .sum(),
            analysis.startup_order.len(),
            analysis.shutdown_order.len(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, count| {
            total.checked_add(u64::try_from(count).expect("bounded analysis item count"))
        })
        .expect("bounded exact analysis item limit");
        assert!(
            run(
                AnalysisFactLimits {
                    items: exact_analysis_items,
                    ..AnalysisFactLimits::standard()
                },
                BackendFactLimits::standard(),
                json.len() as u64,
            )
            .is_ok()
        );
        assert!(matches!(
            run(
                AnalysisFactLimits {
                    items: exact_analysis_items - 1,
                    ..AnalysisFactLimits::standard()
                },
                BackendFactLimits::standard(),
                json.len() as u64,
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit,
            }) if limit == exact_analysis_items - 1
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits::standard(),
                BackendFactLimits::standard(),
                json.len() as u64 - 1
            ),
            Err(ReportError::ResourceLimit {
                resource: "encoded image report bytes",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits {
                    items: 1,
                    ..AnalysisFactLimits::standard()
                },
                BackendFactLimits::standard(),
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits {
                    proof_edges: 1,
                    ..AnalysisFactLimits::standard()
                },
                BackendFactLimits::standard(),
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis proof edges",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits {
                    payload_bytes: 1,
                    ..AnalysisFactLimits::standard()
                },
                BackendFactLimits::standard(),
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact payload",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits::standard(),
                BackendFactLimits {
                    items: 1,
                    ..BackendFactLimits::standard()
                },
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "backend fact items",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits::standard(),
                BackendFactLimits {
                    optimization_proof_edges: 1,
                    ..BackendFactLimits::standard()
                },
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "optimization proof edges",
                ..
            })
        ));
        assert!(matches!(
            run(
                AnalysisFactLimits::standard(),
                BackendFactLimits {
                    payload_bytes: 1,
                    ..BackendFactLimits::standard()
                },
                json.len() as u64
            ),
            Err(ReportError::ResourceLimit {
                resource: "backend fact payload",
                ..
            })
        ));
    }

    #[test]
    fn cancellation_is_observed_before_and_during_parsing() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        assert_eq!(
            decode_image_report_json(
                json.as_bytes(),
                &build(0x5a),
                AnalysisFactLimits::standard(),
                BackendFactLimits::standard(),
                json.len() as u64,
                &|| true,
            ),
            Err(ReportError::Cancelled)
        );

        let checks = Cell::new(0usize);
        let cancelled = || {
            let next = checks.get() + 1;
            checks.set(next);
            next > 64
        };
        assert_eq!(
            decode_image_report_json(
                json.as_bytes(),
                &build(0x5a),
                AnalysisFactLimits::standard(),
                BackendFactLimits::standard(),
                json.len() as u64,
                &cancelled,
            ),
            Err(ReportError::Cancelled)
        );
    }

    #[test]
    fn decoded_long_string_copy_stops_at_the_exact_interior_chunk() {
        let bytes = vec![b'a'; 8_192];
        let checks = Cell::new(0usize);
        let cancelled = || {
            let next = checks.get() + 1;
            checks.set(next);
            next == 2
        };
        let parser = Parser::new(&[], 8_192, &cancelled);
        let mut output = String::new();

        assert_eq!(
            parser.push_utf8(&mut output, &bytes),
            Err(ReportError::Cancelled)
        );
        assert_eq!(output.len(), 4_096);
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn malformed_utf8_and_unicode_escapes_are_rejected() {
        let json = full_report(ActorLoweringKind::Queued, OptimizationAction::Retained).to_json();
        let surrogate = json.replacen(
            "\"image_name\":\"image\\t雪\"",
            "\"image_name\":\"image\\ud800\"",
            1,
        );
        assert!(matches!(
            decode(surrogate.as_bytes()),
            Err(ReportError::InvalidEncoding("JSON Unicode escape"))
        ));

        let mut invalid_utf8 = json.into_bytes();
        let position = invalid_utf8
            .windows(3)
            .position(|window| window == "雪".as_bytes())
            .expect("fixture Unicode scalar");
        invalid_utf8[position] = 0xff;
        assert!(matches!(
            decode(&invalid_utf8),
            Err(ReportError::InvalidEncoding("UTF-8"))
        ));
    }
}
