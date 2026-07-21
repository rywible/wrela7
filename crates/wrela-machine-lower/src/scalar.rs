use wrela_flow_wir as flow;
use wrela_machine_wir::{
    ArithmeticOp, BackendFacts, BlockId, CallingConvention, CheckedIntegerOp, CheckedNumericKind,
    ConversionOp, DataLayout, Endianness, FloatPredicate, FunctionId, GlobalId, InstructionId,
    IntegerPredicate, IntegerSignedness, Linkage, MACHINE_WIR_VERSION,
    MachineActivationCancellation, MachineActivationId, MachineActivationOwner,
    MachineActivationPlan, MachineActivationSchedule, MachineAssertionFailure, MachineBlock,
    MachineFence, MachineFunction, MachineFunctionOrigin, MachineFunctionRole, MachineGlobal,
    MachineImmediate, MachineInstruction, MachineOperation, MachineRegionStorage,
    MachineRegionStorageId, MachineRegionStorageKind, MachineTarget, MachineTerminator,
    MachineTestEntry, MachineTestId, MachineTestKind, MachineType, MachineTypeId, MachineTypeKind,
    MachineUnaryOp, MachineValue, MachineWir, MemorySemantics, ProofId,
    REGION_STORAGE_SECTION_PREFIX, REGION_STORAGE_SYMBOL_PREFIX, ScalarFailureKind,
    ScalarFailureProvenance, Section, SectionId, SectionKind, Symbol, SymbolDefinition, SymbolId,
    SymbolVisibility, ValueId,
};
use wrela_runtime_abi::{
    INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
    RuntimeIntrinsic, RuntimeRequirements,
};
use wrela_test_model::{GuestTestOutcome, TestEvent, TestEventKind, TestId};
use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, TestEventCodec};

use super::{
    CANCELLABLE_COPY_CHUNK_BYTES, IMAGE_ENTER_RUNTIME_REASON, LayoutSummary, MachineLowerError,
    MachineLoweringLimits, MachineLoweringReport, MachineLoweringRequest, check_cancelled,
    check_resource, copy_text, model_resources, push_text_chunks, try_vec, unsupported,
    validate_limits,
};

const CODE_BASE_BYTES: u64 = 64;
const CODE_BYTES_PER_OPERATION: u64 = 64;
const SCALAR_BACKEND_PROOF_PREFIX: &str = "FlowWir proof: ";
const TEST_PAYLOAD_SECTION: &str = ".rdata.wrela.test";
const TEST_PAYLOAD_SYMBOL_PREFIX: &str = "__wrela_test_frame_";
const ASSERTION_PAYLOAD_SYMBOL_PREFIX: &str = "__wrela_assert_payload_";
const ASSERTION_STORAGE_BYTES: usize = flow::ASSERTION_EXPRESSION_BYTES_MAX;
/// One fixed, target-laid-out unit-message envelope per sealed mailbox slot.
/// The first eight bytes hold the release/acquire message tag; the remaining
/// bytes are reserved for future compiler-defined envelope metadata.
const ACTOR_MAILBOX_SCALAR_SLOT_BYTES: u64 = 16;
const FATAL_RUNTIME_REASON: &str =
    "checked scalar and actor-mailbox failures abandon through the target fatal runtime";
const TEST_EMIT_RUNTIME_REASON: &str = "generated test harness emits canonical protocol frames";
const TEST_FINISH_RUNTIME_REASON: &str =
    "generated test harness terminates through the target runtime";
const TEST_ASSERT_RUNTIME_REASON: &str =
    "a single selected generated source test fails through the noreturn assertion runtime";

#[derive(Debug, Clone, Copy)]
struct TestPayloadPlan {
    global: GlobalId,
    function: flow::FunctionId,
    block: flow::BlockId,
    definition_index: u32,
    value: flow::ValueId,
    ty: flow::TypeId,
    bytes: u64,
    offset: u64,
}

#[derive(Debug, Clone)]
struct AssertionPayloadPlan {
    global: GlobalId,
    function: flow::FunctionId,
    instruction: flow::InstructionId,
    message: bool,
    bytes: Vec<u8>,
    offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct FlowActorDispatch {
    actor: flow::ActorId,
    method: flow::FunctionId,
    producer: flow::FunctionId,
    permit: flow::ProofId,
}

#[derive(Debug, Clone, Copy)]
struct ActorDispatchPlan {
    actor: u32,
    method: FunctionId,
    producer: FunctionId,
    permit: ProofId,
    mailbox: GlobalId,
}

struct ScalarPlan {
    void_type: MachineTypeId,
    pointer_type: MachineTypeId,
    status_type: MachineTypeId,
    code_bounds: Vec<u64>,
    code_bytes: u64,
    test_payloads: Vec<TestPayloadPlan>,
    test_payload_index: TestPayloadIndex,
    test_payload_bytes: u64,
    assertion_payloads: Vec<AssertionPayloadPlan>,
    assertion_payload_bytes: u64,
    image_enter_calls: u64,
    test_emit_calls: u64,
    test_finish_calls: u64,
    test_assert_calls: u64,
    fatal_calls: u64,
    activations: Vec<MachineActivationPlan>,
    region_storage: Vec<MachineRegionStorage>,
    storage_byte_type: Option<MachineTypeId>,
    assertion_storage_type: Option<MachineTypeId>,
    startup_task: Option<FunctionId>,
    mailbox_turn: Option<FunctionId>,
    actor_dispatch: Option<ActorDispatchPlan>,
}

impl ScalarPlan {
    fn assertion_payload(
        &self,
        function: flow::FunctionId,
        instruction: flow::InstructionId,
        message: bool,
    ) -> Option<&AssertionPayloadPlan> {
        self.assertion_payloads
            .binary_search_by_key(&(function.0, instruction.0, message), |payload| {
                (payload.function.0, payload.instruction.0, payload.message)
            })
            .ok()
            .and_then(|index| self.assertion_payloads.get(index))
    }
}

struct TestPayloadIndex {
    /// Payload-count-sized deterministic index. This deliberately avoids both
    /// randomized hashing and scratch proportional to erased input values.
    entries: Vec<TestPayloadIndexEntry>,
}

#[derive(Clone, Copy)]
struct OutputModelPreflight<'a> {
    test_payloads: &'a [TestPayloadPlan],
    assertion_payloads: &'a [AssertionPayloadPlan],
    activations: &'a [MachineActivationPlan],
    region_storage: &'a [MachineRegionStorage],
    image_enter_calls: u64,
    fatal_calls: u64,
    test_assert_calls: u64,
}

#[derive(Clone, Copy)]
struct TestPayloadIndexEntry {
    function: u32,
    value: u32,
    payload: usize,
}

impl TestPayloadIndex {
    fn get(&self, function: flow::FunctionId, value: flow::ValueId) -> Option<usize> {
        self.entries
            .binary_search_by_key(&(function.0, value.0), |entry| {
                (entry.function, entry.value)
            })
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|entry| entry.payload)
    }

    fn contains(&self, function: flow::FunctionId, value: flow::ValueId) -> bool {
        self.get(function, value).is_some()
    }

    fn contains_function(&self, function: flow::FunctionId) -> bool {
        let index = self
            .entries
            .partition_point(|entry| entry.function < function.0);
        self.entries
            .get(index)
            .is_some_and(|entry| entry.function == function.0)
    }
}

#[derive(Clone, Copy)]
enum ValueMapping<'a> {
    /// Validation-only mapping used before the canonical output value table is
    /// constructed. Supported non-unit scalar values retain their Flow IDs.
    DenseShift(u32),
    /// Canonical lowering map. Only retained Flow IDs are stored, in ascending
    /// order, so zero-sized input values do not consume output-model capacity.
    Canonical {
        retained: &'a [flow::ValueId],
        value_count: usize,
        first: u32,
    },
}

fn scalar_runtime_requirements(plan: &ScalarPlan) -> RuntimeRequirements {
    let mut intrinsics = vec![RuntimeIntrinsic::ImageEnter];
    if plan.fatal_calls != 0 {
        intrinsics.push(RuntimeIntrinsic::Fatal);
    }
    if plan.test_emit_calls != 0 || plan.test_finish_calls != 0 {
        intrinsics.extend([RuntimeIntrinsic::TestEmit, RuntimeIntrinsic::TestFinish]);
    }
    if plan.test_assert_calls != 0 {
        intrinsics.push(RuntimeIntrinsic::TestAssertionFail);
    }
    RuntimeRequirements::new(intrinsics)
}

pub(super) fn lower_scalar_image(
    request: &MachineLoweringRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(MachineWir, MachineLoweringReport), MachineLowerError> {
    let mut plan = preflight(request, is_cancelled)?;
    let input = request.input.wir().as_wir();
    let backend = request.target.backend();

    let types = lower_types(
        input,
        plan.pointer_type,
        plan.status_type,
        &plan,
        request.limits,
        is_cancelled,
    )?;
    let sections = lower_sections(input, &plan, request.limits, is_cancelled)?;
    let symbols = lower_symbols(
        input,
        &plan,
        backend.entry_symbol(),
        request.limits,
        is_cancelled,
    )?;
    let globals = lower_globals(input, &plan, request.limits, is_cancelled)?;
    let proofs = lower_proofs(input, request.limits, is_cancelled)?;
    let functions = lower_functions(
        input,
        &plan,
        plan.pointer_type,
        plan.status_type,
        request.limits,
        is_cancelled,
    )?;
    let tests = lower_tests(input, request.limits, is_cancelled)?;

    let mut features = try_vec(
        backend.llvm_features().len(),
        "MachineWir model edges",
        request.limits.model_edges,
        is_cancelled,
    )?;
    for feature in backend.llvm_features() {
        features.push(copy_text(
            feature,
            "MachineWir payload bytes",
            request.limits.payload_bytes,
            is_cancelled,
        )?);
    }
    let target_identity = copy_text(
        request.target.identity().as_str(),
        "MachineWir payload bytes",
        request.limits.payload_bytes,
        is_cancelled,
    )?;
    let runtime = scalar_runtime_requirements(&plan);
    let wir = MachineWir {
        version: MACHINE_WIR_VERSION,
        name: copy_text(
            &input.name,
            "MachineWir payload bytes",
            request.limits.payload_bytes,
            is_cancelled,
        )?,
        build: request.build.identity.clone(),
        target: MachineTarget {
            identity: target_identity.clone(),
            llvm_triple: copy_text(
                backend.llvm_triple(),
                "MachineWir payload bytes",
                request.limits.payload_bytes,
                is_cancelled,
            )?,
            data_layout: copy_text(
                backend.llvm_data_layout(),
                "MachineWir payload bytes",
                request.limits.payload_bytes,
                is_cancelled,
            )?,
            cpu: copy_text(
                backend.llvm_cpu(),
                "MachineWir payload bytes",
                request.limits.payload_bytes,
                is_cancelled,
            )?,
            features,
            coff_machine: copy_text(
                backend.coff_machine(),
                "MachineWir payload bytes",
                request.limits.payload_bytes,
                is_cancelled,
            )?,
        },
        layout: target_layout(),
        runtime: runtime.clone(),
        types,
        sections,
        symbols,
        globals,
        functions,
        activations: std::mem::take(&mut plan.activations),
        region_storage: std::mem::take(&mut plan.region_storage),
        interrupts: Vec::new(),
        tests,
        proofs,
        image_entry: FunctionId(input.image_entry.0),
    };
    validate_limits(&wir, request.limits, is_cancelled)?;
    model_resources(&wir, request.limits, is_cancelled)?;
    let mut maximum_alignment = 1u32;
    for ty in &wir.types {
        check_cancelled(is_cancelled)?;
        maximum_alignment = maximum_alignment.max(ty.alignment);
    }
    for section in &wir.sections {
        check_cancelled(is_cancelled)?;
        maximum_alignment = maximum_alignment.max(section.alignment);
    }
    let runtime_use_count = usize::from(plan.image_enter_calls != 0)
        .checked_add(usize::from(plan.fatal_calls != 0))
        .and_then(|count| count.checked_add(usize::from(plan.test_emit_calls != 0)))
        .and_then(|count| count.checked_add(usize::from(plan.test_finish_calls != 0)))
        .and_then(|count| count.checked_add(usize::from(plan.test_assert_calls != 0)))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: request.limits.model_edges,
        })?;
    let mut runtime_uses = try_vec(
        runtime_use_count,
        "MachineWir model edges",
        request.limits.model_edges,
        is_cancelled,
    )?;
    if plan.image_enter_calls != 0 {
        runtime_uses.push(super::RuntimeUse {
            intrinsic: RuntimeIntrinsic::ImageEnter,
            call_sites: plan.image_enter_calls,
            reason: copy_text(
                IMAGE_ENTER_RUNTIME_REASON,
                "machine lowering report bytes",
                request.limits.report_bytes,
                is_cancelled,
            )?,
        });
    }
    if plan.fatal_calls != 0 {
        runtime_uses.push(super::RuntimeUse {
            intrinsic: RuntimeIntrinsic::Fatal,
            call_sites: plan.fatal_calls,
            reason: copy_text(
                FATAL_RUNTIME_REASON,
                "machine lowering report bytes",
                request.limits.report_bytes,
                is_cancelled,
            )?,
        });
    }
    if plan.test_emit_calls != 0 {
        runtime_uses.push(super::RuntimeUse {
            intrinsic: RuntimeIntrinsic::TestEmit,
            call_sites: plan.test_emit_calls,
            reason: copy_text(
                TEST_EMIT_RUNTIME_REASON,
                "machine lowering report bytes",
                request.limits.report_bytes,
                is_cancelled,
            )?,
        });
    }
    if plan.test_finish_calls != 0 {
        runtime_uses.push(super::RuntimeUse {
            intrinsic: RuntimeIntrinsic::TestFinish,
            call_sites: plan.test_finish_calls,
            reason: copy_text(
                TEST_FINISH_RUNTIME_REASON,
                "machine lowering report bytes",
                request.limits.report_bytes,
                is_cancelled,
            )?,
        });
    }
    if plan.test_assert_calls != 0 {
        runtime_uses.push(super::RuntimeUse {
            intrinsic: RuntimeIntrinsic::TestAssertionFail,
            call_sites: plan.test_assert_calls,
            reason: copy_text(
                TEST_ASSERT_RUNTIME_REASON,
                "machine lowering report bytes",
                request.limits.report_bytes,
                is_cancelled,
            )?,
        });
    }
    let report = MachineLoweringReport {
        target_identity,
        types_laid_out: u64::try_from(wir.types.len()).map_err(|_| {
            MachineLowerError::ResourceLimit {
                resource: "MachineWir types",
                limit: request.limits.types,
            }
        })?,
        functions_lowered: u64::try_from(wir.functions.len()).map_err(|_| {
            MachineLowerError::ResourceLimit {
                resource: "MachineWir functions",
                limit: request.limits.functions,
            }
        })?,
        layout: LayoutSummary {
            code_bytes_upper_bound: plan.code_bytes,
            read_only_bytes: plan
                .test_payload_bytes
                .checked_add(plan.assertion_payload_bytes)
                .and_then(|bytes| bytes.checked_add(u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)))
                .ok_or(MachineLowerError::LayoutOverflow {
                    subject: "test payload and runtime metadata sections".to_owned(),
                })?,
            writable_bytes: input.static_bytes,
            zero_fill_bytes: 0,
            maximum_stack_bytes: 0,
            maximum_alignment,
        },
        runtime,
        runtime_uses,
    };
    check_cancelled(is_cancelled)?;
    Ok((wir, report))
}

fn discover_actor_dispatch(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<FlowActorDispatch>, MachineLowerError> {
    let mut dispatch = None;
    let mut commit_count = 0_u8;
    let mut receive = None;

    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for (index, instruction) in block.instructions.iter().enumerate() {
                check_cancelled(is_cancelled)?;
                match &instruction.operation {
                    flow::FlowOperation::ActorReserve {
                        actor,
                        method,
                        proof,
                    } => {
                        if dispatch.is_some() {
                            return Err(unsupported("more than one actor message admission"));
                        }
                        let [reservation] = instruction.results.as_slice() else {
                            return Err(unsupported(
                                "an actor reservation without one strict-linear result",
                            ));
                        };
                        let reservation_type = function
                            .values
                            .get(reservation.0 as usize)
                            .and_then(|value| input.types.get(value.ty.0 as usize));
                        let adjacent_commit = block.instructions.get(index.saturating_add(1));
                        if reservation_type
                            .is_none_or(|ty| ty.kind != flow::FlowTypeKind::Reservation)
                            || !matches!(adjacent_commit,
                                Some(flow::Instruction {
                                    results,
                                    operation: flow::FlowOperation::ActorCommit {
                                        reservation: committed,
                                        arguments,
                                    },
                                    source,
                                    ..
                                }) if results.is_empty()
                                    && committed == reservation
                                    && arguments.is_empty()
                                    && *source == instruction.source)
                        {
                            return Err(unsupported(
                                "an actor reservation without its adjacent unit commit",
                            ));
                        }
                        let task_actor = match function.role {
                            flow::FunctionRole::TaskEntry(task) => input
                                .tasks
                                .get(task.0 as usize)
                                .filter(|record| record.id == task)
                                .and_then(|record| record.supervisor),
                            _ => None,
                        };
                        let target = input.functions.get(method.0 as usize).filter(|target| {
                            target.id == *method
                                && target.role == flow::FunctionRole::ActorTurn(*actor)
                                && target.color == flow::FunctionColor::Async
                                && target.parameters.len() == 1
                                && target.result_types.is_empty()
                        });
                        let state_matches = target.is_some_and(|target| {
                            target
                                .parameters
                                .first()
                                .and_then(|state| target.values.get(state.0 as usize))
                                .map(|state| state.ty)
                                == input
                                    .actors
                                    .get(actor.0 as usize)
                                    .map(|record| record.state_type)
                        });
                        let mut mailbox_proof = None;
                        for region in &input.regions {
                            check_cancelled(is_cancelled)?;
                            if region.owner == flow::PlanOwner::Actor(*actor)
                                && region.class == flow::RegionClass::Image
                                && mailbox_proof.replace(region.capacity_proof).is_some()
                            {
                                return Err(unsupported(
                                    "more than one mailbox-capacity authority for an actor",
                                ));
                            }
                        }
                        let permit_record = input.proofs.get(proof.0 as usize);
                        let mut function_has_permit = false;
                        for listed in &function.proofs {
                            check_cancelled(is_cancelled)?;
                            function_has_permit |= listed == proof;
                        }
                        let cross_actor = input.actors.len() == 2
                            && task_actor == Some(flow::ActorId(1))
                            && *actor == flow::ActorId(0)
                            && matches!(
                                index.checked_sub(1).and_then(|prior| block.instructions.get(prior)),
                                Some(flow::Instruction {
                                    results,
                                    operation: flow::FlowOperation::ActorCapability {
                                        actor: capability_actor,
                                        proof: wiring_proof,
                                    },
                                    ..
                                }) if *capability_actor == *actor
                                    && matches!(results.as_slice(), [capability]
                                        if function.values.get(capability.0 as usize).is_some_and(|value| {
                                            input.types.get(value.ty.0 as usize).is_some_and(|ty| {
                                                ty.kind == flow::FlowTypeKind::ActorHandle(*actor)
                                                    && ty.copyable
                                                    && !ty.strict_linear
                                            })
                                        }))
                                    && input.proofs.get(wiring_proof.0 as usize).is_some_and(|proof| {
                                        proof.kind == flow::ProofKind::ActorAsIf
                                            && proof.bound == Some(1)
                                            && proof.sources.len() == 1
                                            && proof.depends_on.is_empty()
                                    })
                            );
                        if (task_actor != Some(*actor) && !cross_actor)
                            || target.is_none()
                            || !state_matches
                            || permit_record.is_none_or(|permit| {
                                permit.id != *proof
                                    || permit.kind != flow::ProofKind::CapacityBound
                                    || permit.bound != Some(1)
                                    || instruction
                                        .source
                                        .is_none_or(|source| permit.sources.as_slice() != [source])
                                    || mailbox_proof.is_none_or(|mailbox| {
                                        permit.depends_on.as_slice() != [mailbox]
                                    })
                            })
                            || !function_has_permit
                        {
                            return Err(unsupported(
                                "an actor admission without exact target and capacity authority",
                            ));
                        }
                        dispatch = Some(FlowActorDispatch {
                            actor: *actor,
                            method: *method,
                            producer: function.id,
                            permit: *proof,
                        });
                    }
                    flow::FlowOperation::ActorCommit {
                        reservation,
                        arguments,
                    } => {
                        commit_count = commit_count.saturating_add(1);
                        let prior = index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        if !instruction.results.is_empty()
                            || !arguments.is_empty()
                            || !matches!(prior,
                                Some(flow::Instruction {
                                    results,
                                    operation: flow::FlowOperation::ActorReserve { .. },
                                    source,
                                    ..
                                }) if results.as_slice() == [*reservation]
                                    && *source == instruction.source)
                        {
                            return Err(unsupported("a non-adjacent actor unit commit"));
                        }
                    }
                    flow::FlowOperation::MailboxReceive { actor, method }
                        if receive.replace((*actor, *method)).is_some()
                            || !instruction.results.is_empty()
                            || block.id != function.entry
                            || index != 0
                            || function.id != *method
                            || function.role != flow::FunctionRole::ActorTurn(*actor) =>
                    {
                        return Err(unsupported(
                            "a substituted or duplicate actor mailbox receive",
                        ));
                    }
                    flow::FlowOperation::MailboxReceive { .. } => {}
                    _ => {}
                }
            }
        }
    }

    match (dispatch, receive, commit_count) {
        (None, None, 0) => Ok(None),
        (Some(dispatch), Some((actor, method)), 1)
            if (dispatch.actor, dispatch.method) == (actor, method) =>
        {
            Ok(Some(dispatch))
        }
        _ => Err(unsupported(
            "an incomplete actor reserve, commit, and receive chain",
        )),
    }
}

fn bind_actor_dispatch(
    input: &flow::FlowWir,
    dispatch: Option<FlowActorDispatch>,
    region_storage: &[MachineRegionStorage],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<ActorDispatchPlan>, MachineLowerError> {
    let Some(dispatch) = dispatch else {
        return Ok(None);
    };
    let actor = input
        .actors
        .get(dispatch.actor.0 as usize)
        .filter(|actor| actor.id == dispatch.actor && actor.mailbox_capacity == 1)
        .ok_or(unsupported(
            "an executable unit-message actor without one mailbox slot",
        ))?;
    let mut mailbox = None;
    for storage in region_storage {
        check_cancelled(is_cancelled)?;
        if storage.kind
            == (MachineRegionStorageKind::ActorMailbox {
                actor: actor.id.0,
                mailbox_capacity: actor.mailbox_capacity,
            })
            && mailbox.replace(storage.global).is_some()
        {
            return Err(unsupported("more than one machine actor mailbox"));
        }
    }
    let mailbox = mailbox.ok_or(unsupported("an actor dispatch without mailbox storage"))?;
    Ok(Some(ActorDispatchPlan {
        actor: dispatch.actor.0,
        method: FunctionId(dispatch.method.0),
        producer: FunctionId(dispatch.producer.0),
        permit: ProofId(dispatch.permit.0),
        mailbox,
    }))
}

fn preflight(
    request: &MachineLoweringRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScalarPlan, MachineLowerError> {
    let input = request.input.wir().as_wir();
    if input.functions.is_empty() {
        return Err(unsupported("an empty FlowWir function table"));
    }
    let flow_actor_dispatch = discover_actor_dispatch(input, is_cancelled)?;
    let activations = lower_activation_subset(
        input,
        flow_actor_dispatch.as_ref(),
        request.limits,
        is_cancelled,
    )?;
    let activation_subset = !activations.is_empty();
    if !input.globals.is_empty()
        || !input.devices.is_empty()
        || !input.pools.is_empty()
        || !input.checkpoints.is_empty()
        || (!activation_subset
            && (!input.actors.is_empty()
                || !input.tasks.is_empty()
                || !input.regions.is_empty()
                || input.startup_order.as_slice() != [flow::PlanOwner::Runtime]
                || input.shutdown_order.as_slice() != [flow::PlanOwner::Runtime]
                || input.static_bytes != 0
                || input.peak_bytes != 0))
    {
        return Err(unsupported(
            "globals, runtime plans, devices, checkpoints, or image memory in scalar lowering",
        ));
    }

    let test_payloads = collect_test_payloads(input, request.limits, is_cancelled)?;
    let test_payload_bytes = test_payloads.iter().try_fold(0u64, |total, payload| {
        total
            .checked_add(payload.bytes)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: request.limits.static_bytes,
            })
    })?;
    validate_static_test_payload_stream(
        input,
        &test_payloads,
        test_payload_bytes,
        request.limits,
        is_cancelled,
    )?;
    let assertion_payloads = collect_assertion_payloads(
        input,
        test_payloads.len(),
        test_payload_bytes,
        request.limits,
        is_cancelled,
    )?;
    let assertion_payload_bytes = u64::try_from(assertion_payloads.len())
        .ok()
        .and_then(|count| count.checked_mul(ASSERTION_STORAGE_BYTES as u64))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir static bytes",
            limit: request.limits.static_bytes,
        })?;
    let test_payload_index =
        validate_test_payload_uses(input, &test_payloads, request.limits, is_cancelled)?;
    let test_emit_calls =
        u64::try_from(test_payloads.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir globals",
            limit: u64::from(request.limits.globals),
        })?;
    let test_finish_calls = count_test_finish_calls(input, is_cancelled)?;
    let test_assert_calls = count_test_assertions(input, is_cancelled)?;
    if test_assert_calls != 0 && input.tests.len() != 1 {
        return Err(unsupported(
            "runtime assertions require exactly one selected generated source test",
        ));
    }
    let fatal_calls = count_checked_scalar_failures(input, is_cancelled)?
        .checked_add(u64::from(flow_actor_dispatch.is_some()) * 2)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: request.limits.instructions,
        })?;
    validate_test_harness_surface(input, test_emit_calls, test_finish_calls, is_cancelled)?;
    // Every generated UEFI image entry must transition the runtime before any
    // user or compiler-generated body operation.
    let image_enter_calls = 1;
    let region_storage_count = if activation_subset {
        count_u64(
            input.regions.len(),
            "MachineWir region storage",
            u64::from(request.limits.globals),
        )?
    } else {
        0
    };
    let output_globals = test_emit_calls
        .checked_add(u64::try_from(assertion_payloads.len()).map_err(|_| {
            MachineLowerError::ResourceLimit {
                resource: "MachineWir globals",
                limit: u64::from(request.limits.globals),
            }
        })?)
        .and_then(|count| count.checked_add(region_storage_count))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir globals",
            limit: u64::from(request.limits.globals),
        })?;
    check_resource(
        "MachineWir globals",
        output_globals,
        u64::from(request.limits.globals),
    )?;

    let pointer_index =
        u32::try_from(input.types.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir types",
            limit: request.limits.types,
        })?;
    let status_index = pointer_index
        .checked_add(1)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir types",
            limit: request.limits.types,
        })?;
    let storage_byte_type = if region_storage_count == 0 && assertion_payloads.is_empty() {
        None
    } else {
        Some(MachineTypeId(status_index.checked_add(1).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir types",
                limit: request.limits.types,
            },
        )?))
    };
    let assertion_storage_type = if assertion_payloads.is_empty() {
        None
    } else {
        Some(MachineTypeId(
            storage_byte_type
                .ok_or(unsupported("assertion storage without a byte type"))?
                .0
                .checked_add(1)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir types",
                    limit: request.limits.types,
                })?,
        ))
    };
    let output_types = u64::try_from(input.types.len())
        .ok()
        .and_then(|count| count.checked_add(2))
        .and_then(|count| {
            count.checked_add(
                region_storage_count
                    + u64::from(storage_byte_type.is_some())
                    + u64::from(assertion_storage_type.is_some()),
            )
        })
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir types",
            limit: request.limits.types,
        })?;
    check_resource("MachineWir types", output_types, request.limits.types)?;
    check_resource(
        "MachineWir functions",
        count_u64(
            input.functions.len(),
            "MachineWir functions",
            request.limits.functions,
        )?,
        request.limits.functions,
    )?;
    let sections = u64::try_from(input.functions.len())
        .ok()
        .and_then(|count| count.checked_add(1 + u64::from(test_emit_calls != 0)))
        .and_then(|count| count.checked_add(region_storage_count))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(request.limits.sections),
        })?;
    check_resource(
        "MachineWir sections",
        sections,
        u64::from(request.limits.sections),
    )?;
    let runtime_symbols = u64::from(fatal_calls != 0)
        .checked_add(1)
        .and_then(|count| count.checked_add(u64::from(test_emit_calls != 0) * 2))
        .and_then(|count| count.checked_add(u64::from(test_assert_calls != 0)))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(request.limits.symbols),
        })?;
    let symbols = u64::try_from(input.functions.len())
        .ok()
        .and_then(|count| count.checked_add(test_emit_calls))
        .and_then(|count| count.checked_add(region_storage_count))
        .and_then(|count| count.checked_add(runtime_symbols))
        .and_then(|count| count.checked_add(1))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(request.limits.symbols),
        })?;
    check_resource(
        "MachineWir symbols",
        symbols,
        u64::from(request.limits.symbols),
    )?;
    check_resource(
        "MachineWir proofs",
        count_u64(
            input.proofs.len(),
            "MachineWir proofs",
            u64::from(request.limits.proofs),
        )?,
        u64::from(request.limits.proofs),
    )?;

    // Function color is the outer execution contract. Reject the complete
    // async/ISR surface before inspecting its activation representation so a
    // caller never mistakes type layout support for scheduler support.
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        if function.color != flow::FunctionColor::Sync && !activation_subset {
            return Err(unsupported(
                "asynchronous or interrupt-colored functions without an exact runtime lowering",
            ));
        }
    }
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        require_supported_type(
            &input.types,
            ty,
            activation_subset,
            flow_actor_dispatch.is_some(),
        )?;
    }
    let void_type = find_void_type(input, is_cancelled)?;
    validate_payload_types(input, &test_payloads, request.limits, is_cancelled)?;
    validate_proof_closure(
        &input.proofs,
        &activations,
        u64::from(request.limits.proofs),
        is_cancelled,
    )?;
    let region_storage = lower_region_storage(
        input,
        &activations,
        test_payloads.len() + assertion_payloads.len(),
        storage_byte_type,
        assertion_storage_type,
        request.limits,
        is_cancelled,
    )?;
    let actor_dispatch =
        bind_actor_dispatch(input, flow_actor_dispatch, &region_storage, is_cancelled)?;
    let image = input
        .functions
        .get(input.image_entry.0 as usize)
        .ok_or(unsupported("a missing image entry"))?;
    if image.role != flow::FunctionRole::ImageEntry
        || !image.parameters.is_empty()
        || !image.result_types.is_empty()
    {
        return Err(unsupported(
            "an image entry with source parameters or return values",
        ));
    }

    let mut code_bounds = try_vec(
        input.functions.len(),
        "MachineWir functions",
        request.limits.functions,
        is_cancelled,
    )?;
    let mut code_bytes = 0u64;
    let mut instruction_count = 0u64;
    let report_bytes = request
        .target
        .identity()
        .as_str()
        .len()
        .checked_add(
            IMAGE_ENTER_RUNTIME_REASON.len()
                + usize::from(!test_payloads.is_empty())
                    * (TEST_EMIT_RUNTIME_REASON.len() + TEST_FINISH_RUNTIME_REASON.len())
                + usize::from(test_assert_calls != 0) * TEST_ASSERT_RUNTIME_REASON.len(),
        )
        .and_then(|bytes| {
            bytes.checked_add(usize::from(fatal_calls != 0) * FATAL_RUNTIME_REASON.len())
        })
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "machine lowering report bytes",
            limit: request.limits.report_bytes,
        })?;
    check_resource(
        "machine lowering report bytes",
        count_u64(
            report_bytes,
            "machine lowering report bytes",
            request.limits.report_bytes,
        )?,
        request.limits.report_bytes,
    )?;
    let mut startup_instruction_count = 0_usize;
    for activation in &activations {
        check_cancelled(is_cancelled)?;
        if matches!(
            activation.schedule,
            MachineActivationSchedule::StartupOnce | MachineActivationSchedule::MailboxOnce
        ) {
            startup_instruction_count = startup_instruction_count.checked_add(1).ok_or(
                MachineLowerError::ResourceLimit {
                    resource: "MachineWir instructions",
                    limit: request.limits.instructions,
                },
            )?;
        }
    }

    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        validate_function_surface(input, function, &activations, is_cancelled)?;
        let return_count = count_return_blocks(function, is_cancelled)?;
        let generated_returns = if function.role == flow::FunctionRole::ImageEntry {
            return_count
        } else {
            0
        };
        let mut retained = 0usize;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if !matches!(instruction.operation, flow::FlowOperation::Drop { .. })
                    && !erases_unit_definition(input, function, instruction)?
                {
                    retained = retained
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir instructions",
                            limit: request.limits.instructions,
                        })?;
                }
            }
        }
        let function_test_emits = count_test_emits(function, is_cancelled)?;
        let retained_and_generated = retained
            .checked_add(generated_returns)
            .and_then(|count| count.checked_add(function_test_emits))
            .and_then(|count| {
                count.checked_add(if function.id == input.image_entry {
                    startup_instruction_count
                } else {
                    0
                })
            })
            .and_then(|count| {
                count.checked_add(usize::from(
                    function.id == input.image_entry && image_enter_calls != 0,
                ))
            })
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit: request.limits.instructions,
            })?;
        let mut expansion_units = function.parameters.len();
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            expansion_units = expansion_units
                .checked_add(terminator_edges(
                    &block.terminator,
                    request.limits.model_edges,
                    is_cancelled,
                )?)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir model edges",
                    limit: request.limits.model_edges,
                })?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                expansion_units = expansion_units
                    .checked_add(operation_edges(&instruction.operation))
                    .and_then(|count| {
                        count.checked_add(operation_code_units(&instruction.operation))
                    })
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: request.limits.model_edges,
                    })?;
            }
        }
        let generated_entry_blocks =
            usize::from(function.id == input.image_entry && image_enter_calls != 0) * 2;
        let generated_emit_blocks =
            function_test_emits
                .checked_mul(2)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir model edges",
                    limit: request.limits.model_edges,
                })?;
        // The generated entry transition has one runtime call, two blocks,
        // two call arguments, one switch case, and one failure return value.
        let generated_entry_expansion = generated_entry_blocks * 2;
        // Every TestEmit status is consumed by a one-case zero-success switch;
        // its default block returns the unchanged nonzero EFI_STATUS.
        let generated_emit_expansion = generated_emit_blocks;
        let operations = retained_and_generated
            .checked_add(function.blocks.len())
            .and_then(|count| count.checked_add(generated_entry_blocks))
            .and_then(|count| count.checked_add(generated_emit_blocks))
            .and_then(|count| count.checked_add(expansion_units))
            .and_then(|count| count.checked_add(generated_entry_expansion))
            .and_then(|count| count.checked_add(generated_emit_expansion))
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit: request.limits.instructions,
            })?;
        let operations =
            u64::try_from(operations).map_err(|_| MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit: request.limits.instructions,
            })?;
        instruction_count = instruction_count
            .checked_add(count_u64(
                retained_and_generated,
                "MachineWir instructions",
                request.limits.instructions,
            )?)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit: request.limits.instructions,
            })?;
        check_resource(
            "MachineWir instructions",
            instruction_count,
            request.limits.instructions,
        )?;
        let bound = CODE_BASE_BYTES
            .checked_add(operations.checked_mul(CODE_BYTES_PER_OPERATION).ok_or(
                MachineLowerError::LayoutOverflow {
                    subject: "scalar function code reservation".to_owned(),
                },
            )?)
            .ok_or_else(|| MachineLowerError::LayoutOverflow {
                subject: "scalar function code reservation".to_owned(),
            })?;
        code_bytes = code_bytes
            .checked_add(bound)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: request.limits.static_bytes,
            })?;
        code_bounds.push(bound);

        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                validate_supported_operation(
                    input,
                    function,
                    instruction,
                    &test_payload_index,
                    &activations,
                    is_cancelled,
                )?;
            }
        }
    }
    preflight_output_model_resources(
        request,
        input,
        OutputModelPreflight {
            test_payloads: &test_payloads,
            assertion_payloads: &assertion_payloads,
            activations: &activations,
            region_storage: &region_storage,
            image_enter_calls,
            fatal_calls,
            test_assert_calls,
        },
        is_cancelled,
    )?;
    code_bytes = code_bytes
        .checked_add(u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir static bytes",
            limit: request.limits.static_bytes,
        })?;
    code_bytes =
        code_bytes
            .checked_add(test_payload_bytes)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: request.limits.static_bytes,
            })?;
    code_bytes = code_bytes.checked_add(assertion_payload_bytes).ok_or(
        MachineLowerError::ResourceLimit {
            resource: "MachineWir static bytes",
            limit: request.limits.static_bytes,
        },
    )?;
    code_bytes =
        code_bytes
            .checked_add(input.static_bytes)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: request.limits.static_bytes,
            })?;
    check_resource(
        "MachineWir static bytes",
        code_bytes,
        request.limits.static_bytes,
    )?;
    check_resource(
        "build profile static bytes",
        code_bytes,
        request.build.profile.memory.static_bytes,
    )?;
    check_cancelled(is_cancelled)?;
    Ok(ScalarPlan {
        void_type,
        pointer_type: MachineTypeId(pointer_index),
        status_type: MachineTypeId(status_index),
        code_bounds,
        code_bytes: code_bytes
            - u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)
            - test_payload_bytes
            - assertion_payload_bytes
            - input.static_bytes,
        test_payloads,
        test_payload_index,
        test_payload_bytes,
        assertion_payloads,
        assertion_payload_bytes,
        image_enter_calls,
        test_emit_calls,
        test_finish_calls,
        test_assert_calls,
        fatal_calls,
        region_storage,
        storage_byte_type,
        assertion_storage_type,
        startup_task: activations.iter().find_map(|activation| {
            (activation.schedule == MachineActivationSchedule::StartupOnce)
                .then_some(activation.caller)
        }),
        mailbox_turn: activations.iter().find_map(|activation| {
            (activation.schedule == MachineActivationSchedule::MailboxOnce)
                .then_some(activation.caller)
        }),
        actor_dispatch,
        activations,
    })
}

fn lower_activation_subset(
    input: &flow::FlowWir,
    dispatch: Option<&FlowActorDispatch>,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineActivationPlan>, MachineLowerError> {
    let has_surface = !input.actors.is_empty()
        || !input.tasks.is_empty()
        || !input.regions.is_empty()
        || !input.activations.is_empty();
    if !has_surface {
        return Ok(Vec::new());
    }
    let (actor, app) = match input.actors.as_slice() {
        [actor] => (actor, None),
        [service, app]
            if service.id == flow::ActorId(0)
                && app.id == flow::ActorId(1)
                && dispatch.is_some_and(|dispatch| dispatch.actor == service.id) =>
        {
            (service, Some(app))
        }
        _ => {
            return Err(unsupported(
                "actor activation images outside the exact one-actor or image-wired two-actor plan",
            ));
        }
    };
    let [task] = input.tasks.as_slice() else {
        return Err(unsupported(
            "actor activation images with exactly one static task",
        ));
    };
    let plan_order_matches = if let Some(app) = app {
        app.mailbox_capacity == 1
            && app.message_types.is_empty()
            && app.turn_functions.is_empty()
            && app.supervisor.is_none()
            && task.supervisor == Some(app.id)
            && input.startup_order.as_slice()
                == [
                    flow::PlanOwner::Runtime,
                    flow::PlanOwner::Actor(actor.id),
                    flow::PlanOwner::Actor(app.id),
                    flow::PlanOwner::Task(task.id),
                ]
            && input.shutdown_order.as_slice()
                == [
                    flow::PlanOwner::Task(task.id),
                    flow::PlanOwner::Actor(app.id),
                    flow::PlanOwner::Actor(actor.id),
                    flow::PlanOwner::Runtime,
                ]
    } else {
        task.supervisor
            .is_none_or(|supervisor| supervisor == actor.id)
            && input.startup_order.as_slice()
                == [
                    flow::PlanOwner::Runtime,
                    flow::PlanOwner::Actor(actor.id),
                    flow::PlanOwner::Task(task.id),
                ]
            && input.shutdown_order.as_slice()
                == [
                    flow::PlanOwner::Task(task.id),
                    flow::PlanOwner::Actor(actor.id),
                    flow::PlanOwner::Runtime,
                ]
    };
    if input.activations.len() != 2
        || actor.id != flow::ActorId(0)
        || actor.mailbox_capacity == 0
        || actor.message_types.len() > 1
        || actor.turn_functions.len() != 1
        || actor.supervisor.is_some()
        || task.id != flow::TaskId(0)
        || task.slots != 1
        || !plan_order_matches
        || input.static_bytes == 0
        || input.static_bytes != input.peak_bytes
    {
        return Err(unsupported(
            "the one-actor, one-single-slot-task immediate activation contract",
        ));
    }

    let mut output = try_vec(
        input.activations.len(),
        "MachineWir activations",
        limits.model_edges,
        is_cancelled,
    )?;
    let mut shared_callee = None;
    for plan in &input.activations {
        check_cancelled(is_cancelled)?;
        let caller = input
            .functions
            .get(plan.caller.0 as usize)
            .ok_or(unsupported("an activation with an unknown caller"))?;
        let callee = input
            .functions
            .get(plan.callee.0 as usize)
            .ok_or(unsupported("an activation with an unknown callee"))?;
        let region = input
            .regions
            .get(plan.region.0 as usize)
            .ok_or(unsupported("an activation with an unknown frame region"))?;
        let capacity = input
            .proofs
            .get(plan.capacity_proof.0 as usize)
            .ok_or(unsupported("an activation with an unknown capacity proof"))?;
        let [cleanup] = capacity.depends_on.as_slice() else {
            return Err(unsupported(
                "an activation capacity proof without one cleanup dependency",
            ));
        };
        let cleanup_record = input
            .proofs
            .get(cleanup.0 as usize)
            .ok_or(unsupported("an activation with an unknown cleanup proof"))?;
        let (owner, schedule) = match caller.role {
            flow::FunctionRole::ActorTurn(id)
                if id == actor.id && actor.turn_functions.as_slice() == [caller.id] =>
            {
                (
                    MachineActivationOwner::Actor {
                        actor: id.0,
                        mailbox_capacity: actor.mailbox_capacity,
                    },
                    if dispatch.is_some_and(|dispatch| {
                        dispatch.actor == id && dispatch.method == caller.id
                    }) {
                        MachineActivationSchedule::MailboxOnce
                    } else {
                        MachineActivationSchedule::DormantMailbox
                    },
                )
            }
            flow::FunctionRole::TaskEntry(id) if id == task.id && task.entry == caller.id => (
                MachineActivationOwner::Task {
                    task: id.0,
                    slots: task.slots,
                    supervisor: task.supervisor.map(|actor| actor.0),
                },
                MachineActivationSchedule::StartupOnce,
            ),
            _ => {
                return Err(unsupported(
                    "an activation caller outside actor/task authority",
                ));
            }
        };
        let [entry, resume] = caller.blocks.as_slice() else {
            return Err(unsupported(
                "an activation caller without one entry and resume block",
            ));
        };
        let Some(call) = entry.instructions.last() else {
            return Err(unsupported("an activation caller without an async call"));
        };
        let message_shape = match (owner, schedule, dispatch) {
            (
                MachineActivationOwner::Actor { actor, .. },
                MachineActivationSchedule::MailboxOnce,
                Some(dispatch),
            ) => matches!(entry.instructions.as_slice(), [receive, candidate]
                if candidate.id == call.id
                    && receive.results.is_empty()
                    && matches!(receive.operation,
                        flow::FlowOperation::MailboxReceive {
                            actor: receive_actor,
                            method,
                        } if receive_actor.0 == actor
                            && method == dispatch.method)),
            (
                MachineActivationOwner::Actor { .. },
                MachineActivationSchedule::DormantMailbox,
                None,
            ) => entry.instructions.len() == 1,
            (
                MachineActivationOwner::Task { .. },
                MachineActivationSchedule::StartupOnce,
                Some(dispatch),
            ) if dispatch.producer == caller.id => {
                if app.is_some() {
                    let [capability, reserve, commit, candidate] = entry.instructions.as_slice()
                    else {
                        return Err(unsupported(
                            "an image-wired startup activation message shape",
                        ));
                    };
                    matches!(
                        (&capability.operation, capability.results.as_slice()),
                        (
                            flow::FlowOperation::ActorCapability { actor, proof },
                            [handle],
                        ) if *actor == dispatch.actor
                            && caller.values.get(handle.0 as usize).is_some_and(|value| {
                                input.types.get(value.ty.0 as usize).is_some_and(|ty| {
                                    ty.kind == flow::FlowTypeKind::ActorHandle(*actor)
                                        && ty.copyable
                                        && !ty.strict_linear
                                })
                            })
                            && input.proofs.get(proof.0 as usize).is_some_and(|proof| {
                                proof.kind == flow::ProofKind::ActorAsIf
                                    && proof.bound == Some(1)
                                    && proof.sources.len() == 1
                                    && proof.depends_on.is_empty()
                            })
                    ) && candidate.id == call.id
                        && matches!(
                            (&reserve.operation, reserve.results.as_slice()),
                            (
                                flow::FlowOperation::ActorReserve {
                                    actor,
                                    method,
                                    proof,
                                },
                                [reservation],
                            ) if *actor == dispatch.actor
                                && *method == dispatch.method
                                && *proof == dispatch.permit
                                && commit.results.is_empty()
                                && matches!(&commit.operation,
                                    flow::FlowOperation::ActorCommit {
                                        reservation: committed,
                                        arguments,
                                    } if committed == reservation && arguments.is_empty())
                                && reserve.source == commit.source
                        )
                } else {
                    matches!(entry.instructions.as_slice(), [reserve, commit, candidate]
                    if candidate.id == call.id
                        && matches!(
                            (&reserve.operation, reserve.results.as_slice()),
                            (
                                flow::FlowOperation::ActorReserve {
                                    actor,
                                    method,
                                    proof,
                                },
                                [reservation],
                            ) if *actor == dispatch.actor
                                && *method == dispatch.method
                                && *proof == dispatch.permit
                                && commit.results.is_empty()
                                && matches!(&commit.operation,
                                    flow::FlowOperation::ActorCommit {
                                        reservation: committed,
                                        arguments,
                                    } if committed == reservation && arguments.is_empty())
                                && reserve.source == commit.source
                        ))
                }
            }
            (MachineActivationOwner::Task { .. }, MachineActivationSchedule::StartupOnce, None) => {
                entry.instructions.len() == 1
            }
            _ => false,
        };
        let [activation_value] = call.results.as_slice() else {
            return Err(unsupported("an async call without one strict-linear token"));
        };
        let activation_type = caller
            .values
            .get(activation_value.0 as usize)
            .and_then(|value| input.types.get(value.ty.0 as usize))
            .ok_or(unsupported(
                "an async call with an unknown activation token",
            ))?;
        let flow::FlowTypeKind::Activation { result } = activation_type.kind else {
            return Err(unsupported("an async call result without activation type"));
        };
        let result_is_unit = input
            .types
            .get(result.0 as usize)
            .is_some_and(|ty| ty.kind == flow::FlowTypeKind::Unit);
        let (state, resume_id) = match entry.terminator {
            flow::Terminator::Suspend {
                state,
                activation,
                resume,
            } if activation == *activation_value => (state, resume),
            _ => return Err(unsupported("an async call without its exact suspend edge")),
        };
        let call_matches = matches!(
            &call.operation,
            flow::FlowOperation::AsyncCall {
                function,
                arguments,
                plan: call_plan,
            } if *function == plan.callee && arguments.is_empty() && *call_plan == plan.id
        );
        let resume_matches = resume.id == resume_id
            && resume.instructions.is_empty()
            && matches!(&resume.terminator, flow::Terminator::Return(values) if values.is_empty())
            && matches!(resume.parameters.as_slice(), [value]
                if caller.values.get(value.0 as usize).is_some_and(|value| value.ty == result));
        let callee_matches = callee.role == flow::FunctionRole::Ordinary
            && callee.color == flow::FunctionColor::Async
            && callee.parameters.is_empty()
            && callee.result_types.is_empty()
            && matches!(callee.blocks.as_slice(), [block]
                if block.id == callee.entry
                    && block.parameters.is_empty()
                    && block.instructions.is_empty()
                    && matches!(&block.terminator, flow::Terminator::Return(values) if values.is_empty()));
        let mut caller_has_capacity = false;
        for proof in &caller.proofs {
            check_cancelled(is_cancelled)?;
            caller_has_capacity |= proof == &plan.capacity_proof;
        }
        let mut callee_has_cleanup = false;
        for proof in &callee.proofs {
            check_cancelled(is_cancelled)?;
            callee_has_cleanup |= proof == cleanup;
        }
        let proof_matches = capacity.kind == flow::ProofKind::CapacityBound
            && capacity.bound == Some(u64::from(plan.maximum_live))
            && capacity.sources.as_slice() == [plan.source]
            && cleanup_record.kind == flow::ProofKind::CleanupAcyclic
            && callee
                .source
                .is_some_and(|source| cleanup_record.sources.as_slice() == [source])
            && caller_has_capacity
            && callee_has_cleanup;
        let frame_matches = region.class == flow::RegionClass::TaskFrame
            && region.owner
                == match owner {
                    MachineActivationOwner::Actor { actor, .. } => {
                        flow::PlanOwner::Actor(flow::ActorId(actor))
                    }
                    MachineActivationOwner::Task { task, .. } => {
                        flow::PlanOwner::Task(flow::TaskId(task))
                    }
                }
            && region.capacity_bytes == plan.frame_bytes
            && region.capacity_proof == plan.capacity_proof
            && region.source == plan.source
            && region.alignment <= u64::from(u32::MAX);
        if plan.id.0 as usize != output.len()
            || plan.frame_bytes == 0
            || plan.maximum_live != 1
            || plan.cancellation != flow::ActivationCancellation::DropCalleeThenPropagate
            || state != 0
            || !message_shape
            || call.source != Some(plan.source)
            || caller.color != flow::FunctionColor::Async
            || !activation_type.strict_linear
            || activation_type.copyable
            || !result_is_unit
            || !call_matches
            || !resume_matches
            || !callee_matches
            || !proof_matches
            || !frame_matches
            || shared_callee.is_some_and(|shared| shared != plan.callee)
        {
            return Err(unsupported(
                "an activation outside the immediate unit helper subset",
            ));
        }
        shared_callee = Some(plan.callee);
        output.push(MachineActivationPlan {
            id: MachineActivationId(plan.id.0),
            owner,
            schedule,
            caller: FunctionId(plan.caller.0),
            callee: FunctionId(plan.callee.0),
            call_instruction: InstructionId(call.id.0),
            state,
            resume_block: BlockId(resume_id.0),
            region: plan.region.0,
            region_capacity_bytes: region.capacity_bytes,
            region_alignment: u32::try_from(region.alignment)
                .map_err(|_| unsupported("an activation frame alignment outside machine range"))?,
            frame_bytes: plan.frame_bytes,
            maximum_live: plan.maximum_live,
            cancellation: MachineActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: ProofId(plan.capacity_proof.0),
            capacity_bound: capacity.bound.unwrap_or(0),
            cleanup_proof: ProofId(cleanup.0),
            source: plan.source,
        });
    }
    let actor_count = output
        .iter()
        .filter(|plan| {
            matches!(
                plan.schedule,
                MachineActivationSchedule::DormantMailbox | MachineActivationSchedule::MailboxOnce
            )
        })
        .count();
    let task_count = output
        .iter()
        .filter(|plan| plan.schedule == MachineActivationSchedule::StartupOnce)
        .count();
    if actor_count != 1 || task_count != 1 {
        return Err(unsupported(
            "one actor-turn and one startup-task activation",
        ));
    }
    check_cancelled(is_cancelled)?;
    Ok(output)
}

fn lower_region_storage(
    input: &flow::FlowWir,
    activations: &[MachineActivationPlan],
    test_payload_count: usize,
    storage_byte_type: Option<MachineTypeId>,
    assertion_storage_type: Option<MachineTypeId>,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineRegionStorage>, MachineLowerError> {
    if activations.is_empty() {
        if !input.regions.is_empty()
            || (storage_byte_type.is_some() && assertion_storage_type.is_none())
        {
            return Err(unsupported(
                "region storage outside actor activation lowering",
            ));
        }
        return Ok(Vec::new());
    }
    let byte_type = storage_byte_type.ok_or(unsupported(
        "actor region storage without its canonical byte type",
    ))?;
    let (actor, app) = match input.actors.as_slice() {
        [actor] => (actor, None),
        [service, app]
            if service.id == flow::ActorId(0)
                && app.id == flow::ActorId(1)
                && app.turn_functions.is_empty() =>
        {
            (service, Some(app))
        }
        _ => {
            return Err(unsupported(
                "actor region storage outside the exact actor plan",
            ));
        }
    };
    let [task] = input.tasks.as_slice() else {
        return Err(unsupported("actor region storage without one task"));
    };
    let static_region_count = if app.is_some() { 4 } else { 3 };
    let expected_regions = activations.len().checked_add(static_region_count).ok_or(
        MachineLowerError::ResourceLimit {
            resource: "MachineWir region storage",
            limit: u64::from(limits.globals),
        },
    )?;
    if input.regions.len() != expected_regions {
        return Err(unsupported(
            "the complete actor mailbox, root-frame, and activation-frame region set",
        ));
    }
    check_resource(
        "MachineWir region storage",
        count_u64(
            input.regions.len(),
            "MachineWir region storage",
            u64::from(limits.globals),
        )?,
        u64::from(limits.globals),
    )?;

    let first_global =
        u32::try_from(test_payload_count).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir globals",
            limit: u64::from(limits.globals),
        })?;
    let first_symbol = input
        .functions
        .len()
        .checked_add(test_payload_count)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(limits.symbols),
        })?;
    let first_section = input
        .functions
        .len()
        .checked_add(usize::from(test_payload_count != 0))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(limits.sections),
        })?;
    let first_type = assertion_storage_type
        .map_or(byte_type.0, |ty| ty.0)
        .checked_add(1)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir types",
            limit: limits.types,
        })?;
    let mut output = try_vec(
        input.regions.len(),
        "MachineWir region storage",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    let mut total_bytes = 0u64;

    for (index, region) in input.regions.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let id = u32::try_from(index).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir region storage",
            limit: u64::from(limits.globals),
        })?;
        if region.id.0 != id || region.reset_function.is_some() {
            return Err(unsupported("a noncanonical static actor region identity"));
        }
        let (kind, capacity_units, bytes_per_unit, expected_name_suffix) = match index {
            0 => {
                let expected_bytes = u64::from(actor.mailbox_capacity)
                    .checked_mul(ACTOR_MAILBOX_SCALAR_SLOT_BYTES)
                    .ok_or(MachineLowerError::LayoutOverflow {
                        subject: "actor mailbox storage".to_owned(),
                    })?;
                if region.class != flow::RegionClass::Image
                    || region.owner != flow::PlanOwner::Actor(actor.id)
                    || region.capacity_bytes != expected_bytes
                    || region.alignment != 8
                {
                    return Err(unsupported("the fixed scalar actor mailbox region"));
                }
                (
                    MachineRegionStorageKind::ActorMailbox {
                        actor: actor.id.0,
                        mailbox_capacity: actor.mailbox_capacity,
                    },
                    u64::from(actor.mailbox_capacity),
                    ACTOR_MAILBOX_SCALAR_SLOT_BYTES,
                    ".mailbox",
                )
            }
            1 => {
                let [turn] = actor.turn_functions.as_slice() else {
                    return Err(unsupported("one actor turn-frame owner"));
                };
                let function = input
                    .functions
                    .get(turn.0 as usize)
                    .ok_or(unsupported("an unknown actor turn-frame owner"))?;
                let frame_bytes = function.frame_bound.max(1);
                if region.class != flow::RegionClass::TaskFrame
                    || region.owner != flow::PlanOwner::Actor(actor.id)
                    || region.capacity_bytes != frame_bytes
                    || region.alignment != 8
                {
                    return Err(unsupported("the fixed actor turn-frame region"));
                }
                (
                    MachineRegionStorageKind::ActorTurnFrame {
                        actor: actor.id.0,
                        function: FunctionId(turn.0),
                    },
                    1,
                    frame_bytes,
                    ".turn-frame",
                )
            }
            2 if app.is_some() => {
                let app = app.expect("guarded image-wired app");
                let expected_bytes = u64::from(app.mailbox_capacity)
                    .checked_mul(ACTOR_MAILBOX_SCALAR_SLOT_BYTES)
                    .ok_or(MachineLowerError::LayoutOverflow {
                        subject: "client actor mailbox storage".to_owned(),
                    })?;
                if region.class != flow::RegionClass::Image
                    || region.owner != flow::PlanOwner::Actor(app.id)
                    || region.capacity_bytes != expected_bytes
                    || region.alignment != 8
                {
                    return Err(unsupported("the fixed client actor mailbox region"));
                }
                (
                    MachineRegionStorageKind::ActorMailbox {
                        actor: app.id.0,
                        mailbox_capacity: app.mailbox_capacity,
                    },
                    u64::from(app.mailbox_capacity),
                    ACTOR_MAILBOX_SCALAR_SLOT_BYTES,
                    ".mailbox",
                )
            }
            index if index == static_region_count - 1 => {
                let frame_bytes = task.frame_bytes_bound.max(1);
                let expected_bytes = frame_bytes.checked_mul(u64::from(task.slots)).ok_or(
                    MachineLowerError::LayoutOverflow {
                        subject: "task entry-frame storage".to_owned(),
                    },
                )?;
                if region.class != flow::RegionClass::TaskFrame
                    || region.owner != flow::PlanOwner::Task(task.id)
                    || region.capacity_bytes != expected_bytes
                    || region.alignment != 8
                {
                    return Err(unsupported("the fixed task entry-frame region"));
                }
                (
                    MachineRegionStorageKind::TaskEntryFrame {
                        task: task.id.0,
                        function: FunctionId(task.entry.0),
                        slots: task.slots,
                    },
                    u64::from(task.slots),
                    frame_bytes,
                    ".frame",
                )
            }
            _ => {
                let activation_index = index - static_region_count;
                let activation = activations.get(activation_index).ok_or(unsupported(
                    "an actor activation-frame region without a plan",
                ))?;
                let owner = match activation.owner {
                    MachineActivationOwner::Actor { actor, .. } => {
                        flow::PlanOwner::Actor(flow::ActorId(actor))
                    }
                    MachineActivationOwner::Task { task, .. } => {
                        flow::PlanOwner::Task(flow::TaskId(task))
                    }
                };
                if activation.id.0 as usize != activation_index
                    || activation.region != region.id.0
                    || region.class != flow::RegionClass::TaskFrame
                    || region.owner != owner
                    || region.capacity_bytes != activation.region_capacity_bytes
                    || region.alignment != u64::from(activation.region_alignment)
                    || region.capacity_proof.0 != activation.capacity_proof.0
                    || region.source != activation.source
                {
                    return Err(unsupported("the exact actor activation-frame region"));
                }
                (
                    MachineRegionStorageKind::ActivationFrame {
                        activation: activation.id,
                    },
                    u64::from(activation.maximum_live),
                    activation.frame_bytes,
                    ".async-activation-frame",
                )
            }
        };
        if !joined_name_has_suffix(&region.name, expected_name_suffix, is_cancelled)?
            || capacity_units.checked_mul(bytes_per_unit) != Some(region.capacity_bytes)
        {
            return Err(unsupported("a substituted actor region name or capacity"));
        }
        let proof = input
            .proofs
            .get(region.capacity_proof.0 as usize)
            .ok_or(unsupported(
                "an actor region with an unknown capacity proof",
            ))?;
        let [capacity_source] = proof.sources.as_slice() else {
            return Err(unsupported(
                "an actor region capacity proof without one source",
            ));
        };
        if proof.kind != flow::ProofKind::CapacityBound || proof.bound != Some(capacity_units) {
            return Err(unsupported("a substituted actor region capacity proof"));
        }
        let alignment = u32::try_from(region.alignment)
            .map_err(|_| unsupported("an actor region alignment outside the machine domain"))?;
        let global = GlobalId(first_global.checked_add(id).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir globals",
                limit: u64::from(limits.globals),
            },
        )?);
        let symbol = SymbolId(first_symbol.checked_add(id).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir symbols",
                limit: u64::from(limits.symbols),
            },
        )?);
        let section = SectionId(first_section.checked_add(id).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir sections",
                limit: u64::from(limits.sections),
            },
        )?);
        let ty = MachineTypeId(first_type.checked_add(id).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir types",
                limit: limits.types,
            },
        )?);
        total_bytes = total_bytes.checked_add(region.capacity_bytes).ok_or(
            MachineLowerError::LayoutOverflow {
                subject: "actor region storage".to_owned(),
            },
        )?;
        output.push(MachineRegionStorage {
            id: MachineRegionStorageId(id),
            flow_region: region.id.0,
            name: copy_text(
                &region.name,
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            kind,
            global,
            symbol,
            section,
            ty,
            capacity_proof: ProofId(region.capacity_proof.0),
            capacity_units,
            bytes_per_unit,
            capacity_bytes: region.capacity_bytes,
            alignment,
            source: region.source,
            capacity_source: *capacity_source,
        });
    }
    if total_bytes != input.static_bytes || total_bytes != input.peak_bytes {
        return Err(unsupported(
            "actor region storage without exact static and peak closure",
        ));
    }
    check_cancelled(is_cancelled)?;
    Ok(output)
}

fn joined_name_has_suffix(
    value: &str,
    suffix: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    let Some(start) = value.len().checked_sub(suffix.len()) else {
        return Ok(false);
    };
    let Some(tail) = value.get(start..) else {
        return Ok(false);
    };
    for (index, (left, right)) in tail.bytes().zip(suffix.bytes()).enumerate() {
        if index % CANCELLABLE_COPY_CHUNK_BYTES == 0 {
            check_cancelled(is_cancelled)?;
        }
        if left != right {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

/// Meter the exact post-erasure MachineWir aggregate surface before allocating
/// it. In particular, zero-sized `unit` definitions, parameters, results, and
/// edge arguments do not consume MachineWir model edges or payload bytes.
fn preflight_output_model_resources(
    request: &MachineLoweringRequest<'_>,
    input: &flow::FlowWir,
    preflight: OutputModelPreflight<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let OutputModelPreflight {
        test_payloads,
        assertion_payloads,
        activations,
        region_storage,
        image_enter_calls,
        fatal_calls,
        test_assert_calls,
    } = preflight;
    let edge_limit = request.limits.model_edges;
    let payload_limit = request.limits.payload_bytes;
    let backend = request.target.backend();
    let mut edges = 0u64;
    let mut payload = generated_fixed_payload(request, input, is_cancelled)?;
    add_payload(
        &mut payload,
        request.build.identity.target.as_str().len(),
        payload_limit,
    )?;

    edges = add_edges(edges, backend.llvm_features().len(), edge_limit)?;
    edges = add_edges(
        edges,
        1 + usize::from(fatal_calls != 0)
            + usize::from(!test_payloads.is_empty()) * 2
            + usize::from(test_assert_calls != 0),
        edge_limit,
    )?;
    let types = input
        .types
        .len()
        .checked_add(2)
        .and_then(|count| {
            count.checked_add(usize::from(
                !region_storage.is_empty() || !assertion_payloads.is_empty(),
            ))
        })
        .and_then(|count| count.checked_add(usize::from(!assertion_payloads.is_empty())))
        .and_then(|count| count.checked_add(region_storage.len()))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: edge_limit,
        })?;
    let sections = input
        .functions
        .len()
        .checked_add(1 + usize::from(!test_payloads.is_empty()))
        .and_then(|count| count.checked_add(region_storage.len()))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: edge_limit,
        })?;
    let runtime_symbols = 1usize
        .checked_add(usize::from(fatal_calls != 0))
        .and_then(|count| count.checked_add(usize::from(!test_payloads.is_empty()) * 2))
        .and_then(|count| count.checked_add(usize::from(test_assert_calls != 0)))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: edge_limit,
        })?;
    let symbols = input
        .functions
        .len()
        .checked_add(test_payloads.len())
        .and_then(|count| count.checked_add(assertion_payloads.len()))
        .and_then(|count| count.checked_add(region_storage.len()))
        .and_then(|count| count.checked_add(runtime_symbols))
        .and_then(|count| count.checked_add(1))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: edge_limit,
        })?;
    edges = add_edges(
        edges,
        sum_counts(
            [
                types,
                sections,
                symbols,
                test_payloads
                    .len()
                    .checked_add(assertion_payloads.len())
                    .and_then(|count| count.checked_add(region_storage.len()))
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    })?,
                input.functions.len(),
                activations.len(),
                region_storage.len(),
                input.tests.len(),
                input.proofs.len(),
            ],
            edge_limit,
        )?,
        edge_limit,
    )?;

    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        if let Some(name) = &ty.name {
            add_payload(&mut payload, name.len(), payload_limit)?;
        }
        if let flow::FlowTypeKind::Function { parameters, .. } = &ty.kind {
            let mut retained = 0usize;
            for parameter in parameters {
                check_cancelled(is_cancelled)?;
                if !flow_type_is_erased_in(&input.types, *parameter)? {
                    retained = retained
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir model edges",
                            limit: edge_limit,
                        })?;
                }
            }
            edges = add_edges(edges, retained, edge_limit)?;
        }
    }

    add_payload(
        &mut payload,
        RuntimeIntrinsic::ImageEnter.symbol_name().len(),
        payload_limit,
    )?;
    if !test_payloads.is_empty() {
        for text in [
            TEST_PAYLOAD_SECTION,
            "generated-test-harness",
            RuntimeIntrinsic::TestEmit.symbol_name(),
            RuntimeIntrinsic::TestFinish.symbol_name(),
        ] {
            add_payload(&mut payload, text.len(), payload_limit)?;
        }
        for planned in test_payloads {
            check_cancelled(is_cancelled)?;
            add_payload(
                &mut payload,
                TEST_PAYLOAD_SYMBOL_PREFIX.len() + decimal_digits(planned.global.0),
                payload_limit,
            )?;
            let bytes =
                usize::try_from(planned.bytes).map_err(|_| MachineLowerError::ResourceLimit {
                    resource: "MachineWir payload bytes",
                    limit: payload_limit,
                })?;
            add_payload(&mut payload, bytes, payload_limit)?;
            add_payload(&mut payload, 8, payload_limit)?;
        }
        for planned in assertion_payloads {
            add_payload(
                &mut payload,
                ASSERTION_PAYLOAD_SYMBOL_PREFIX.len() + decimal_digits(planned.global.0),
                payload_limit,
            )?;
            add_payload(&mut payload, planned.bytes.len(), payload_limit)?;
        }
    }
    if fatal_calls != 0 {
        add_payload(
            &mut payload,
            RuntimeIntrinsic::Fatal.symbol_name().len(),
            payload_limit,
        )?;
    }
    if !assertion_payloads.is_empty() {
        add_payload(
            &mut payload,
            "generated-test-assertion".len(),
            payload_limit,
        )?;
    }
    if input.functions.iter().any(|function| {
        function.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(instruction.operation, flow::FlowOperation::Assert { .. })
            })
        })
    }) {
        add_payload(
            &mut payload,
            RuntimeIntrinsic::TestAssertionFail.symbol_name().len(),
            payload_limit,
        )?;
    }
    for storage in region_storage {
        check_cancelled(is_cancelled)?;
        let digits = decimal_digits(storage.id.0);
        add_payload(&mut payload, storage.name.len(), payload_limit)?;
        add_payload(&mut payload, storage.name.len(), payload_limit)?;
        add_payload(&mut payload, storage.name.len(), payload_limit)?;
        add_payload(
            &mut payload,
            REGION_STORAGE_SECTION_PREFIX.len() + digits,
            payload_limit,
        )?;
        add_payload(
            &mut payload,
            REGION_STORAGE_SYMBOL_PREFIX.len() + digits,
            payload_limit,
        )?;
    }
    for test in &input.tests {
        check_cancelled(is_cancelled)?;
        add_payload(&mut payload, test.name.len(), payload_limit)?;
    }
    let mut startup_instructions = 0_usize;
    for activation in activations {
        check_cancelled(is_cancelled)?;
        if matches!(
            activation.schedule,
            MachineActivationSchedule::StartupOnce | MachineActivationSchedule::MailboxOnce
        ) {
            startup_instructions =
                startup_instructions
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    })?;
        }
    }

    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        let image_entry = function.id == input.image_entry;
        let parameters = if image_entry {
            2
        } else {
            retained_value_count(input, function, &function.parameters, is_cancelled)?
        };
        let source_values = function.values.iter().try_fold(0usize, |count, value| {
            check_cancelled(is_cancelled)?;
            if flow_type_is_erased_in(&input.types, value.ty)? {
                Ok(count)
            } else {
                count
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    })
            }
        })?;
        let generated_returns = if image_entry {
            count_return_blocks(function, is_cancelled)?
        } else {
            0
        };
        let test_emits = count_test_emits(function, is_cancelled)?;
        let enters_runtime = image_entry && image_enter_calls != 0;
        let blocks = function
            .blocks
            .len()
            .checked_add(
                test_emits
                    .checked_mul(2)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    })?,
            )
            .and_then(|count| count.checked_add(usize::from(enters_runtime) * 2))
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: edge_limit,
            })?;
        let values = source_values
            .checked_add(usize::from(image_entry) * 2)
            .and_then(|count| count.checked_add(generated_returns))
            .and_then(|count| count.checked_add(test_emits.checked_mul(2)?))
            .and_then(|count| count.checked_add(usize::from(enters_runtime)))
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: edge_limit,
            })?;
        edges = add_edges(
            edges,
            sum_counts(
                [parameters, function.proofs.len(), values, blocks],
                edge_limit,
            )?,
            edge_limit,
        )?;

        if enters_runtime {
            // Entry call record, one result, two UEFI arguments, the one-case
            // success switch, and the propagated failure return value.
            edges = add_edges(edges, 6, edge_limit)?;
        }

        for value in &function.values {
            check_cancelled(is_cancelled)?;
            if !flow_type_is_erased_in(&input.types, value.ty)? {
                if let Some(name) = &value.source_name {
                    add_payload(&mut payload, name.len(), payload_limit)?;
                }
            }
        }

        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            let parameters =
                retained_value_count(input, function, &block.parameters, is_cancelled)?;
            edges = add_edges(edges, parameters, edge_limit)?;
            let mut machine_instructions = if image_entry && block.id == function.entry {
                startup_instructions
            } else {
                0
            };
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if matches!(instruction.operation, flow::FlowOperation::TestEmit { .. }) {
                    machine_instructions = machine_instructions.checked_add(2).ok_or(
                        MachineLowerError::ResourceLimit {
                            resource: "MachineWir model edges",
                            limit: edge_limit,
                        },
                    )?;
                    // One result for the generated size, one for the runtime
                    // status, two runtime arguments, the exact-zero switch
                    // case, and the unchanged-status failure return.
                    edges = add_edges(edges, 6, edge_limit)?;
                    continue;
                }
                if matches!(instruction.operation, flow::FlowOperation::Drop { .. })
                    || erases_unit_definition(input, function, instruction)?
                {
                    continue;
                }
                machine_instructions = machine_instructions.checked_add(1).ok_or(
                    MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    },
                )?;
                let results =
                    retained_value_count(input, function, &instruction.results, is_cancelled)?;
                edges = add_edges(edges, results, edge_limit)?;
                match &instruction.operation {
                    flow::FlowOperation::Call { arguments, .. }
                    | flow::FlowOperation::AsyncCall { arguments, .. } => {
                        let arguments =
                            retained_value_count(input, function, arguments, is_cancelled)?;
                        edges = add_edges(edges, arguments, edge_limit)?;
                    }
                    flow::FlowOperation::ActorCommit { .. } => {
                        edges = add_edges(edges, 1, edge_limit)?;
                    }
                    flow::FlowOperation::TestFinish { .. } => {
                        edges = add_edges(edges, 1, edge_limit)?;
                    }
                    flow::FlowOperation::Immediate(flow::Immediate::Bool(_)) => {
                        add_payload(&mut payload, 1, payload_limit)?;
                    }
                    flow::FlowOperation::Immediate(flow::Immediate::Integer {
                        bytes_le, ..
                    }) => add_payload(&mut payload, bytes_le.len(), payload_limit)?,
                    flow::FlowOperation::Assert { failure, .. } => {
                        add_payload(&mut payload, failure.expression.len(), payload_limit)?;
                        if let Some(message) = &failure.message {
                            add_payload(&mut payload, message.len(), payload_limit)?;
                        }
                    }
                    _ => {}
                }
            }
            if image_entry && matches!(block.terminator, flow::Terminator::Return(_)) {
                machine_instructions = machine_instructions.checked_add(1).ok_or(
                    MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: edge_limit,
                    },
                )?;
                // The generated status immediate has one result and is the one
                // return argument of the UEFI entry.
                edges = add_edges(edges, 2, edge_limit)?;
                add_payload(&mut payload, 8, payload_limit)?;
            } else {
                edges = add_edges(
                    edges,
                    lowered_terminator_edges(
                        input,
                        function,
                        activations,
                        &block.terminator,
                        is_cancelled,
                    )?,
                    edge_limit,
                )?;
            }
            edges = add_edges(edges, machine_instructions, edge_limit)?;
        }
    }

    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        edges = add_edges(
            edges,
            1usize
                .checked_add(proof.depends_on.len())
                .and_then(|count| count.checked_add(proof.sources.len()))
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir model edges",
                    limit: edge_limit,
                })?,
            edge_limit,
        )?;
        add_payload(
            &mut payload,
            SCALAR_BACKEND_PROOF_PREFIX.len(),
            payload_limit,
        )?;
        add_payload(&mut payload, proof.subject.len(), payload_limit)?;
    }
    edges = add_edges(edges, activations.len(), edge_limit)?;
    let storage_joins =
        region_storage
            .len()
            .checked_mul(6)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: edge_limit,
            })?;
    edges = add_edges(edges, storage_joins, edge_limit)?;
    check_resource("MachineWir model edges", edges, edge_limit)?;
    check_resource("MachineWir payload bytes", payload, payload_limit)?;
    Ok(())
}

fn retained_value_count(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    values: &[flow::ValueId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    values.iter().try_fold(0usize, |count, value| {
        check_cancelled(is_cancelled)?;
        if flow_type_is_erased_in(&input.types, flow_value_type(function, *value)?)? {
            Ok(count)
        } else {
            count
                .checked_add(1)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir model edges",
                    limit: u64::MAX,
                })
        }
    })
}

fn lowered_terminator_edges(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    activations: &[MachineActivationPlan],
    terminator: &flow::Terminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    let limit = u64::MAX;
    match terminator {
        flow::Terminator::Jump { arguments, .. }
        | flow::Terminator::Return(arguments)
        | flow::Terminator::TailCall { arguments, .. } => {
            retained_value_count(input, function, arguments, is_cancelled)
        }
        flow::Terminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => sum_counts(
            [
                retained_value_count(input, function, then_arguments, is_cancelled)?,
                retained_value_count(input, function, else_arguments, is_cancelled)?,
            ],
            limit,
        ),
        flow::Terminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            let mut edges = sum_counts(
                [
                    cases.len(),
                    retained_value_count(input, function, default_arguments, is_cancelled)?,
                ],
                limit,
            )?;
            for case in cases {
                check_cancelled(is_cancelled)?;
                edges = edges
                    .checked_add(retained_value_count(
                        input,
                        function,
                        &case.arguments,
                        is_cancelled,
                    )?)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit,
                    })?;
            }
            Ok(edges)
        }
        flow::Terminator::Suspend {
            state,
            activation,
            resume,
        } if activations.iter().any(|plan| {
            plan.caller.0 == function.id.0
                && plan.state == *state
                && plan.resume_block.0 == resume.0
        }) && flow_type_is_erased_in(
            &input.types,
            flow_value_type(function, *activation)?,
        )? =>
        {
            Ok(0)
        }
        flow::Terminator::Unreachable => Ok(0),
        flow::Terminator::Suspend { .. } | flow::Terminator::Trap { .. } => Err(unsupported(
            "an asynchronous, interrupt, or trapping scalar terminator",
        )),
    }
}

fn require_supported_type(
    types: &[flow::FlowType],
    ty: &flow::FlowType,
    activation_subset: bool,
    actor_dispatch: bool,
) -> Result<(), MachineLowerError> {
    match ty.kind {
        flow::FlowTypeKind::Unit
        | flow::FlowTypeKind::Scalar(flow::ScalarType::Bool)
        | flow::FlowTypeKind::Scalar(flow::ScalarType::Float32)
        | flow::FlowTypeKind::Scalar(flow::ScalarType::Float64)
        | flow::FlowTypeKind::Scalar(flow::ScalarType::Address) => Ok(()),
        flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
            bits: 8 | 16 | 32 | 64 | 128,
            ..
        }) => Ok(()),
        flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { .. }) => Err(unsupported(
            "integer widths outside 8, 16, 32, 64, and 128 bits",
        )),
        flow::FlowTypeKind::Array { .. } | flow::FlowTypeKind::Function { .. } => Ok(()),
        flow::FlowTypeKind::Activation { .. } if activation_subset => Ok(()),
        flow::FlowTypeKind::Reservation if actor_dispatch => Ok(()),
        flow::FlowTypeKind::ActorHandle(_) if actor_dispatch => Ok(()),
        flow::FlowTypeKind::Struct { ref fields } if activation_subset && fields.is_empty() => {
            Ok(())
        }
        flow::FlowTypeKind::Struct { .. } if flat_u64_struct_field(types, ty.id).is_some() => {
            Ok(())
        }
        flow::FlowTypeKind::Enum { .. } if closed_scalar_enum_payload(types, ty.id).is_some() => {
            Ok(())
        }
        flow::FlowTypeKind::Activation { .. } => Err(unsupported(
            "async activation values without an exact scheduler/runtime lowering",
        )),
        flow::FlowTypeKind::Reservation => Err(unsupported(
            "actor reservations without an exact mailbox dispatch lowering",
        )),
        flow::FlowTypeKind::Tuple(_)
        | flow::FlowTypeKind::Struct { .. }
        | flow::FlowTypeKind::Enum { .. }
        | flow::FlowTypeKind::RegionHandle(_)
        | flow::FlowTypeKind::PoolHandle(_)
        | flow::FlowTypeKind::ActorHandle(_)
        | flow::FlowTypeKind::TaskHandle(_)
        | flow::FlowTypeKind::Receipt { .. }
        | flow::FlowTypeKind::DmaToken { .. }
        | flow::FlowTypeKind::OpaqueTarget { .. } => Err(unsupported(
            "aggregate, handle, or target-defined scalar types",
        )),
    }
}

fn flat_u64_struct_field(types: &[flow::FlowType], ty: flow::TypeId) -> Option<flow::TypeId> {
    let flow::FlowTypeKind::Struct { fields } = &types.get(ty.0 as usize)?.kind else {
        return None;
    };
    let [field] = fields.as_slice() else {
        return None;
    };
    types.get(field.0 as usize).and_then(|field_type| {
        matches!(
            field_type.kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: false,
                bits: 64,
            })
        )
        .then_some(*field)
    })
}

fn closed_scalar_enum_payload(types: &[flow::FlowType], ty: flow::TypeId) -> Option<flow::TypeId> {
    let flow::FlowTypeKind::Enum { variants } = &types.get(ty.0 as usize)?.kind else {
        return None;
    };
    if variants.is_empty() || variants.len() > 256 {
        return None;
    }
    let [payload] = variants.first()?.as_slice() else {
        return None;
    };
    if !variants
        .iter()
        .all(|variant| variant.as_slice() == [*payload])
    {
        return None;
    }
    matches!(
        types.get(payload.0 as usize)?.kind,
        flow::FlowTypeKind::Scalar(
            flow::ScalarType::Bool
                | flow::ScalarType::Integer {
                    bits: 8 | 16 | 32 | 64 | 128,
                    ..
                }
                | flow::ScalarType::Float32
                | flow::ScalarType::Float64
        )
    )
    .then_some(*payload)
}

fn canonical_u8_type(types: &[flow::FlowType]) -> Option<flow::TypeId> {
    types.iter().find_map(|ty| {
        (ty.kind
            == flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: false,
                bits: 8,
            }))
        .then_some(ty.id)
    })
}

fn collect_test_payloads(
    input: &flow::FlowWir,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<TestPayloadPlan>, MachineLowerError> {
    let mut emit_count = 0usize;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        emit_count = emit_count
            .checked_add(count_test_emits(function, is_cancelled)?)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir globals",
                limit: u64::from(limits.globals),
            })?;
    }
    let mut payloads = try_vec(
        emit_count,
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    let mut offset = 0u64;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for (index, instruction) in block.instructions.iter().enumerate() {
                check_cancelled(is_cancelled)?;
                let flow::FlowOperation::TestEmit { payload } = &instruction.operation else {
                    continue;
                };
                if !instruction.results.is_empty()
                    || function.id != input.image_entry
                    || !matches!(
                        function.origin,
                        flow::FunctionOrigin::GeneratedTestHarness { .. }
                    )
                {
                    return Err(unsupported(
                        "test emission outside the generated image-entry harness",
                    ));
                }
                let Some(definition) = index
                    .checked_sub(1)
                    .and_then(|previous| block.instructions.get(previous))
                else {
                    return Err(unsupported(
                        "a test payload without an immediately preceding static definition",
                    ));
                };
                let flow::FlowOperation::Immediate(flow::Immediate::Bytes(bytes)) =
                    &definition.operation
                else {
                    return Err(unsupported(
                        "a test payload that is not a static byte-array immediate",
                    ));
                };
                if definition.results.as_slice() != [*payload] {
                    return Err(unsupported(
                        "a test payload that is not exclusively consumed by its adjacent emission",
                    ));
                }
                let value = function
                    .values
                    .get(payload.0 as usize)
                    .ok_or(unsupported("a test payload with an unknown value"))?;
                let bytes_len =
                    u64::try_from(bytes.len()).map_err(|_| MachineLowerError::ResourceLimit {
                        resource: "MachineWir static bytes",
                        limit: limits.static_bytes,
                    })?;
                let global = GlobalId(u32::try_from(payloads.len()).map_err(|_| {
                    MachineLowerError::ResourceLimit {
                        resource: "MachineWir globals",
                        limit: u64::from(limits.globals),
                    }
                })?);
                payloads.push(TestPayloadPlan {
                    global,
                    function: function.id,
                    block: block.id,
                    definition_index: u32::try_from(index - 1).map_err(|_| {
                        MachineLowerError::ResourceLimit {
                            resource: "MachineWir instructions",
                            limit: limits.instructions,
                        }
                    })?,
                    value: *payload,
                    ty: value.ty,
                    bytes: bytes_len,
                    offset,
                });
                offset = offset
                    .checked_add(bytes_len)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir static bytes",
                        limit: limits.static_bytes,
                    })?;
                check_resource("MachineWir static bytes", offset, limits.static_bytes)?;
            }
        }
    }
    Ok(payloads)
}

fn collect_assertion_payloads(
    input: &flow::FlowWir,
    first_global: usize,
    first_offset: u64,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<AssertionPayloadPlan>, MachineLowerError> {
    let assertion_count =
        usize::try_from(count_test_assertions(input, is_cancelled)?).map_err(|_| {
            MachineLowerError::ResourceLimit {
                resource: "MachineWir globals",
                limit: u64::from(limits.globals),
            }
        })?;
    let capacity = assertion_count
        .checked_mul(2)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir globals",
            limit: u64::from(limits.globals),
        })?;
    let mut output = try_vec(
        capacity,
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    let mut offset = first_offset;
    for function in &input.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                let flow::FlowOperation::Assert { failure, .. } = &instruction.operation else {
                    continue;
                };
                for (message, text) in std::iter::once((false, failure.expression.as_str()))
                    .chain(failure.message.as_deref().map(|value| (true, value)))
                {
                    let index = first_global.checked_add(output.len()).ok_or(
                        MachineLowerError::ResourceLimit {
                            resource: "MachineWir globals",
                            limit: u64::from(limits.globals),
                        },
                    )?;
                    let mut bytes = try_vec(
                        ASSERTION_STORAGE_BYTES,
                        "MachineWir payload bytes",
                        limits.payload_bytes,
                        is_cancelled,
                    )?;
                    bytes.extend_from_slice(text.as_bytes());
                    bytes.resize(ASSERTION_STORAGE_BYTES, 0);
                    output.push(AssertionPayloadPlan {
                        global: GlobalId(u32::try_from(index).map_err(|_| {
                            MachineLowerError::ResourceLimit {
                                resource: "MachineWir globals",
                                limit: u64::from(limits.globals),
                            }
                        })?),
                        function: function.id,
                        instruction: instruction.id,
                        message,
                        bytes,
                        offset,
                    });
                    offset = offset.checked_add(ASSERTION_STORAGE_BYTES as u64).ok_or(
                        MachineLowerError::ResourceLimit {
                            resource: "MachineWir static bytes",
                            limit: limits.static_bytes,
                        },
                    )?;
                }
            }
        }
    }
    output.shrink_to_fit();
    for pair in output.windows(2) {
        if (pair[0].function.0, pair[0].instruction.0, pair[0].message)
            >= (pair[1].function.0, pair[1].instruction.0, pair[1].message)
        {
            return Err(unsupported("noncanonical assertion payload order"));
        }
    }
    Ok(output)
}

fn validate_static_test_payload_stream(
    input: &flow::FlowWir,
    payloads: &[TestPayloadPlan],
    _payload_bytes: u64,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    if payloads.is_empty() {
        return Ok(());
    }
    let expected = input
        .tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "generated test events",
            limit: limits.model_edges,
        })?;
    let mut events = try_vec(
        expected,
        "generated test events",
        limits.model_edges,
        is_cancelled,
    )?;
    for _ in 0..expected {
        check_cancelled(is_cancelled)?;
        events.push(None::<TestEvent>);
    }
    for payload in payloads {
        check_cancelled(is_cancelled)?;
        let bytes = input
            .functions
            .get(payload.function.0 as usize)
            .and_then(|function| function.blocks.get(payload.block.0 as usize))
            .and_then(|block| block.instructions.get(payload.definition_index as usize))
            .and_then(|instruction| match &instruction.operation {
                flow::FlowOperation::Immediate(flow::Immediate::Bytes(bytes)) => Some(bytes),
                _ => None,
            })
            .ok_or(unsupported("a substituted generated test payload"))?;
        let event = CanonicalTestEventCodec
            .decode(bytes, ProtocolLimits::standard(), is_cancelled)
            .map_err(|_| unsupported("noncanonical generated passing test lifecycle frames"))?;
        let slot = usize::try_from(event.sequence)
            .ok()
            .and_then(|index| events.get_mut(index))
            .ok_or(unsupported(
                "noncanonical generated passing test lifecycle frames",
            ))?;
        if slot.is_some() {
            return Err(unsupported(
                "noncanonical generated passing test lifecycle frames",
            ));
        }
        *slot = Some(event);
    }
    if !exact_flow_generated_passing_events(&events, &input.tests) {
        return Err(unsupported(
            "substituted or non-passing compiler-generated test lifecycle frames",
        ));
    }
    Ok(())
}

fn exact_flow_generated_passing_events(
    events: &[Option<TestEvent>],
    tests: &[flow::TestEntry],
) -> bool {
    let expected = tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2));
    if expected != Some(events.len()) {
        return false;
    }
    if events.first().and_then(Option::as_ref).is_none_or(|event| {
        event.sequence != 0
            || !matches!(event.kind, TestEventKind::RunStarted { test_count }
                if usize::try_from(test_count).ok() == Some(tests.len()))
    }) {
        return false;
    }
    for (index, test) in tests.iter().enumerate() {
        let start_index = index * 2 + 1;
        let finish_index = start_index + 1;
        let protocol_id = TestId(test.plan_id);
        if events.get(start_index).and_then(Option::as_ref).is_none_or(|event| {
            event.sequence != start_index as u64
                || !matches!(event.kind, TestEventKind::TestStarted { test } if test == protocol_id)
        }) || events.get(finish_index).and_then(Option::as_ref).is_none_or(|event| {
            event.sequence != finish_index as u64
                || !matches!(event.kind, TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::Passed,
                } if test == protocol_id)
        }) {
            return false;
        }
    }
    let terminal_index = events.len() - 1;
    events.last().and_then(Option::as_ref).is_some_and(|event| {
        event.sequence == terminal_index as u64
            && matches!(event.kind, TestEventKind::RunFinished { passed, failed }
                if usize::try_from(passed).ok() == Some(tests.len()) && failed == 0)
    })
}

fn count_test_finish_calls(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, MachineLowerError> {
    let mut count = 0u64;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if matches!(
                    instruction.operation,
                    flow::FlowOperation::TestFinish { .. }
                ) {
                    count = count
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir instructions",
                            limit: u64::MAX,
                        })?;
                }
            }
        }
    }
    Ok(count)
}

fn count_test_assertions(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, MachineLowerError> {
    let mut count = 0u64;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if matches!(instruction.operation, flow::FlowOperation::Assert { .. }) {
                    count = count
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir instructions",
                            limit: u64::MAX,
                        })?;
                }
            }
        }
    }
    Ok(count)
}

fn count_checked_scalar_failures(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, MachineLowerError> {
    let mut count = 0u64;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                let checked = matches!(
                    instruction.operation,
                    flow::FlowOperation::Binary {
                        op: flow::BinaryOp::AddChecked
                            | flow::BinaryOp::SubChecked
                            | flow::BinaryOp::MulChecked
                            | flow::BinaryOp::DivChecked
                            | flow::BinaryOp::RemChecked
                            | flow::BinaryOp::ShiftLeftChecked
                            | flow::BinaryOp::ShiftLeftWrapping
                            | flow::BinaryOp::ShiftRightChecked,
                        ..
                    } | flow::FlowOperation::Cast {
                        mode: flow::CastMode::Checked,
                        ..
                    }
                );
                if checked {
                    count = count
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir instructions",
                            limit: u64::MAX,
                        })?;
                }
            }
        }
    }
    Ok(count)
}

fn validate_test_harness_surface(
    input: &flow::FlowWir,
    emit_calls: u64,
    finish_calls: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let image = input
        .functions
        .get(input.image_entry.0 as usize)
        .ok_or(unsupported("a missing image entry"))?;
    let generated_harness = matches!(
        image.origin,
        flow::FunctionOrigin::GeneratedTestHarness { .. }
    );
    if generated_harness {
        if emit_calls == 0 || finish_calls != 1 || input.tests.is_empty() {
            return Err(unsupported(
                "a generated test harness without frames, one finish, and executable tests",
            ));
        }
    } else if emit_calls != 0 || finish_calls != 0 {
        return Err(unsupported(
            "compiler-only test intrinsics in a non-test image",
        ));
    }
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for (index, instruction) in block.instructions.iter().enumerate() {
                check_cancelled(is_cancelled)?;
                if !matches!(
                    instruction.operation,
                    flow::FlowOperation::TestFinish { .. }
                ) {
                    continue;
                }
                if function.id != input.image_entry
                    || !generated_harness
                    || index + 1 != block.instructions.len()
                    || !matches!(block.terminator, flow::Terminator::Unreachable)
                {
                    return Err(unsupported(
                        "a returning or nonterminal generated test finish",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_payload_types(
    input: &flow::FlowWir,
    payloads: &[TestPayloadPlan],
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut payload_types = try_vec(
        input.types.len(),
        "MachineWir types",
        limits.types,
        is_cancelled,
    )?;
    for _ in 0..input.types.len() {
        check_cancelled(is_cancelled)?;
        payload_types.push(false);
    }
    for payload in payloads {
        check_cancelled(is_cancelled)?;
        let payload_type = payload_types
            .get_mut(payload.ty.0 as usize)
            .ok_or(unsupported("a test payload with an unknown array type"))?;
        *payload_type = true;
        let ty = input
            .types
            .get(payload.ty.0 as usize)
            .ok_or(unsupported("a test payload with an unknown array type"))?;
        let flow::FlowTypeKind::Array { element, length } = ty.kind else {
            return Err(unsupported("a test payload whose type is not a byte array"));
        };
        let byte = input
            .types
            .get(element.0 as usize)
            .ok_or(unsupported("a test payload with an unknown element type"))?;
        if length != payload.bytes
            || byte.kind
                != flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                    signed: false,
                    bits: 8,
                })
            || !ty.copyable
            || ty.strict_linear
        {
            return Err(unsupported(
                "a test payload without the exact static unsigned-byte-array type",
            ));
        }
    }
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        if matches!(ty.kind, flow::FlowTypeKind::Array { .. })
            && payload_types.get(ty.id.0 as usize) != Some(&true)
        {
            return Err(unsupported(
                "an array type outside generated static test payloads",
            ));
        }
    }
    Ok(())
}

fn validate_test_payload_uses(
    input: &flow::FlowWir,
    payloads: &[TestPayloadPlan],
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestPayloadIndex, MachineLowerError> {
    let mut entries = try_vec(
        payloads.len(),
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    for (index, payload) in payloads.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let function = input
            .functions
            .get(payload.function.0 as usize)
            .ok_or(unsupported("a test payload in an unknown function"))?;
        if function.values.get(payload.value.0 as usize).is_none() {
            return Err(unsupported("a test payload with an unknown value"));
        }
        entries.push(TestPayloadIndexEntry {
            function: payload.function.0,
            value: payload.value.0,
            payload: index,
        });
    }
    cancellable_sort_test_payload_index(&mut entries, limits, is_cancelled)?;
    for pair in entries.windows(2) {
        check_cancelled(is_cancelled)?;
        if matches!(pair, [left, right]
            if (left.function, left.value) == (right.function, right.value))
        {
            return Err(unsupported(
                "a test payload consumed by more than one emission",
            ));
        }
    }
    let payload_index = TestPayloadIndex { entries };
    let mut use_counts = try_vec(
        payloads.len(),
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    for _ in payloads {
        check_cancelled(is_cancelled)?;
        use_counts.push(0u8);
    }
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        if !payload_index.contains_function(function.id) {
            continue;
        }
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                record_operation_payload_uses(
                    function.id,
                    &instruction.operation,
                    &payload_index,
                    &mut use_counts,
                    is_cancelled,
                )?;
            }
            record_terminator_payload_uses(
                function.id,
                &block.terminator,
                &payload_index,
                &mut use_counts,
                is_cancelled,
            )?;
        }
    }
    for count in use_counts {
        check_cancelled(is_cancelled)?;
        if count != 1 {
            return Err(unsupported(
                "a test payload that is not exclusively consumed by its adjacent emission",
            ));
        }
    }
    Ok(payload_index)
}

fn cancellable_sort_test_payload_index(
    entries: &mut [TestPayloadIndexEntry],
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    if entries.len() < 2 {
        return check_cancelled(is_cancelled);
    }
    let mut scratch = try_vec(
        entries.len(),
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    for entry in entries.iter().copied() {
        check_cancelled(is_cancelled)?;
        scratch.push(entry);
    }
    let mut width = 1usize;
    while width < entries.len() {
        let mut start = 0usize;
        while start < entries.len() {
            check_cancelled(is_cancelled)?;
            let middle = start.saturating_add(width).min(entries.len());
            let end = middle.saturating_add(width).min(entries.len());
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle || right < end {
                check_cancelled(is_cancelled)?;
                let take_left = right == end
                    || (left < middle
                        && (entries[left].function, entries[left].value)
                            <= (entries[right].function, entries[right].value));
                scratch[output] = if take_left {
                    let entry = entries[left];
                    left += 1;
                    entry
                } else {
                    let entry = entries[right];
                    right += 1;
                    entry
                };
                output += 1;
            }
            start = end;
        }
        for (index, entry) in scratch.iter().copied().enumerate() {
            check_cancelled(is_cancelled)?;
            entries[index] = entry;
        }
        width = width.checked_mul(2).unwrap_or(entries.len());
    }
    check_cancelled(is_cancelled)
}

fn record_payload_use(
    function: flow::FunctionId,
    value: flow::ValueId,
    payload_index: &TestPayloadIndex,
    use_counts: &mut [u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    check_cancelled(is_cancelled)?;
    if let Some(index) = payload_index.get(function, value) {
        let count = use_counts
            .get_mut(index)
            .ok_or(unsupported("an unknown indexed test payload"))?;
        *count = count.saturating_add(1);
    }
    Ok(())
}

fn record_operation_payload_uses(
    function: flow::FunctionId,
    operation: &flow::FlowOperation,
    payload_index: &TestPayloadIndex,
    use_counts: &mut [u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut record =
        |value| record_payload_use(function, value, payload_index, use_counts, is_cancelled);
    match operation {
        flow::FlowOperation::Binary { left, right, .. } => {
            record(*left)?;
            record(*right)?;
        }
        flow::FlowOperation::Unary { value, .. }
        | flow::FlowOperation::Cast { value, .. }
        | flow::FlowOperation::Load { address: value, .. }
        | flow::FlowOperation::Move { value }
        | flow::FlowOperation::Copy { value }
        | flow::FlowOperation::Drop { value }
        | flow::FlowOperation::TestEmit { payload: value }
        | flow::FlowOperation::TestFinish { outcome: value } => record(*value)?,
        flow::FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            record(*condition)?;
            record(*then_value)?;
            record(*else_value)?;
        }
        flow::FlowOperation::Store { address, value, .. } => {
            record(*address)?;
            record(*value)?;
        }
        flow::FlowOperation::InsertField {
            aggregate, value, ..
        } => {
            record(*aggregate)?;
            record(*value)?;
        }
        flow::FlowOperation::Call { arguments, .. }
        | flow::FlowOperation::AsyncCall { arguments, .. } => {
            for argument in arguments {
                record(*argument)?;
            }
        }
        flow::FlowOperation::Immediate(_) | flow::FlowOperation::Fence { .. } => {}
        _ => {}
    }
    Ok(())
}

fn record_terminator_payload_uses(
    function: flow::FunctionId,
    terminator: &flow::Terminator,
    payload_index: &TestPayloadIndex,
    use_counts: &mut [u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut record =
        |value| record_payload_use(function, value, payload_index, use_counts, is_cancelled);
    match terminator {
        flow::Terminator::Jump { arguments, .. }
        | flow::Terminator::Return(arguments)
        | flow::Terminator::TailCall { arguments, .. } => {
            for argument in arguments {
                record(*argument)?;
            }
        }
        flow::Terminator::Branch {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            record(*condition)?;
            for argument in then_arguments.iter().chain(else_arguments) {
                record(*argument)?;
            }
        }
        flow::Terminator::Switch {
            value,
            cases,
            default_arguments,
            ..
        } => {
            record(*value)?;
            for case in cases {
                check_cancelled(is_cancelled)?;
                for argument in &case.arguments {
                    record(*argument)?;
                }
            }
            for argument in default_arguments {
                record(*argument)?;
            }
        }
        flow::Terminator::Suspend { activation, .. } => record(*activation)?,
        flow::Terminator::Trap { detail, .. } => {
            if let Some(detail) = detail {
                record(*detail)?;
            }
        }
        flow::Terminator::Unreachable => {}
    }
    Ok(())
}

fn validate_proof_closure(
    proofs: &[flow::Proof],
    activations: &[MachineActivationPlan],
    proof_limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut root = None;
    for (index, proof) in proofs.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if proof.id.0 as usize != index {
            return Err(unsupported("a non-dense FlowWir proof graph"));
        }
        let mut previous = None;
        for dependency in &proof.depends_on {
            check_cancelled(is_cancelled)?;
            if dependency.0 >= proof.id.0
                || previous.is_some_and(|previous| dependency.0 <= previous)
            {
                return Err(unsupported(
                    "a cyclic, forward, or noncanonical FlowWir proof dependency",
                ));
            }
            previous = Some(dependency.0);
        }
        if proof.kind == flow::ProofKind::ImageClosed && root.replace(index).is_some() {
            return Err(unsupported("more than one FlowWir image-closure root"));
        }
    }
    let Some(root) = root.filter(|root| root.saturating_add(1) == proofs.len()) else {
        return Err(unsupported("an exact final FlowWir image-closure root"));
    };

    // The first bit records reachability from the one image root. The second
    // records whether a node's own backward ancestry contains TypeChecked.
    // Strictly backward proof IDs make both joins linear, deterministic, and
    // immune to recursion depth while preserving cancellation polling.
    let mut joins = try_vec(proofs.len(), "MachineWir proofs", proof_limit, is_cancelled)?;
    for _ in proofs {
        check_cancelled(is_cancelled)?;
        joins.push((false, false));
    }
    for (index, proof) in proofs.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        joins[index].1 = proof.kind == flow::ProofKind::TypeChecked
            || proof
                .depends_on
                .iter()
                .any(|dependency| joins.get(dependency.0 as usize).is_some_and(|join| join.1));
    }
    joins[root].0 = true;
    for index in (0..=root).rev() {
        check_cancelled(is_cancelled)?;
        if joins[index].0 {
            for dependency in &proofs[index].depends_on {
                check_cancelled(is_cancelled)?;
                joins[dependency.0 as usize].0 = true;
            }
        }
    }
    let has_typed_effect_authority = proofs.iter().enumerate().any(|(index, proof)| {
        joins[index].0 && proof.kind == flow::ProofKind::EffectsAllowed && joins[index].1
    });
    if !has_typed_effect_authority {
        return Err(unsupported(
            "a FlowWir image closure without reachable typed effect authority",
        ));
    }

    if !activations.is_empty() {
        let image_closed = &proofs[root];
        if image_closed.sources.len() != activations.len()
            || !image_closed
                .sources
                .iter()
                .zip(activations)
                .all(|(source, activation)| *source == activation.source)
            || image_closed.depends_on.len() != activations.len().saturating_add(1)
        {
            return Err(unsupported(
                "an actor image closure without exact activation authority",
            ));
        }
        let mut base = None;
        for dependency in &image_closed.depends_on {
            check_cancelled(is_cancelled)?;
            if activations
                .iter()
                .any(|activation| activation.capacity_proof.0 == dependency.0)
            {
                continue;
            }
            if base.replace(*dependency).is_some() {
                return Err(unsupported(
                    "an actor image closure with ambiguous base capacity authority",
                ));
            }
        }
        if activations.iter().any(|activation| {
            image_closed
                .depends_on
                .iter()
                .filter(|dependency| dependency.0 == activation.capacity_proof.0)
                .count()
                != 1
        }) {
            return Err(unsupported(
                "an actor image closure with substituted activation capacity authority",
            ));
        }
        let Some(base) = base.and_then(|base| proofs.get(base.0 as usize)) else {
            return Err(unsupported(
                "an actor image closure without base capacity authority",
            ));
        };
        let mut expected_bound = base
            .bound
            .filter(|_| base.kind == flow::ProofKind::CapacityBound);
        for activation in activations {
            check_cancelled(is_cancelled)?;
            expected_bound =
                expected_bound.and_then(|bound| bound.checked_add(activation.frame_bytes));
        }
        if image_closed.bound != expected_bound {
            return Err(unsupported(
                "an actor image closure without its exact static byte bound",
            ));
        }
    }
    check_cancelled(is_cancelled)
}

fn validate_function_surface(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    activations: &[MachineActivationPlan],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let activation_function = activations
        .iter()
        .any(|plan| plan.caller.0 == function.id.0 || plan.callee.0 == function.id.0);
    if function.color != flow::FunctionColor::Sync && !activation_function {
        return Err(unsupported(
            "asynchronous or interrupt-colored functions without an exact runtime lowering",
        ));
    }
    if function.result_types.len() > 1 {
        return Err(unsupported("functions with multiple return values"));
    }
    if (function.stack_bound != 0 || function.frame_bound != 0) && !activation_function {
        return Err(unsupported("nonzero scalar function stack or frame bounds"));
    }
    match function.role {
        flow::FunctionRole::Ordinary
        | flow::FunctionRole::Cleanup
        | flow::FunctionRole::ImageEntry
        | flow::FunctionRole::Test => {}
        flow::FunctionRole::ActorTurn(_) | flow::FunctionRole::TaskEntry(_)
            if activation_function => {}
        flow::FunctionRole::ActorTurn(_)
        | flow::FunctionRole::TaskEntry(_)
        | flow::FunctionRole::Isr(_) => {
            return Err(unsupported("actor, task, or interrupt functions"));
        }
    }
    if function.entry.0 as usize >= function.blocks.len()
        || function
            .blocks
            .get(function.entry.0 as usize)
            .is_some_and(|entry| !entry.parameters.is_empty())
    {
        return Err(unsupported("an entry block with block parameters"));
    }
    if function.role == flow::FunctionRole::ImageEntry && function.id != input.image_entry {
        return Err(unsupported("multiple image-entry functions"));
    }
    for ty in function
        .values
        .iter()
        .map(|value| value.ty)
        .chain(function.result_types.iter().copied())
    {
        check_cancelled(is_cancelled)?;
        if input
            .types
            .get(ty.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, flow::FlowTypeKind::Function { .. }))
        {
            return Err(unsupported("a first-class function-typed scalar value"));
        }
    }
    Ok(())
}

fn flow_scalar_type(
    input: &flow::FlowWir,
    ty: flow::TypeId,
) -> Result<flow::ScalarType, MachineLowerError> {
    input
        .types
        .get(ty.0 as usize)
        .and_then(|ty| match ty.kind {
            flow::FlowTypeKind::Scalar(scalar) => Some(scalar),
            _ => None,
        })
        .ok_or(unsupported("an operation on a non-scalar type"))
}

fn lower_scalar_unary(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    op: flow::UnaryOp,
    value: flow::ValueId,
) -> Result<MachineUnaryOp, MachineLowerError> {
    let result = require_single_result(instruction)?;
    let operand_ty = flow_value_type(function, value)?;
    if flow_value_type(function, result)? != operand_ty {
        return Err(unsupported(
            "a unary operation whose result type differs from its operand",
        ));
    }
    match (op, flow_scalar_type(input, operand_ty)?) {
        (flow::UnaryOp::BoolNot, flow::ScalarType::Bool) => Ok(MachineUnaryOp::BoolNot),
        (flow::UnaryOp::BitNot, flow::ScalarType::Integer { .. }) => Ok(MachineUnaryOp::BitNot),
        (flow::UnaryOp::Negate, flow::ScalarType::Float32 | flow::ScalarType::Float64) => {
            Ok(MachineUnaryOp::FloatNegate)
        }
        (flow::UnaryOp::Negate, flow::ScalarType::Integer { .. }) => Err(unsupported(
            "checked integer negation without an explicit trap edge",
        )),
        _ => Err(unsupported(
            "a unary operation on an incompatible scalar type",
        )),
    }
}

fn legal_flow_bitcast(source: flow::ScalarType, destination: flow::ScalarType) -> bool {
    match (source, destination) {
        (flow::ScalarType::Bool, flow::ScalarType::Bool)
        | (flow::ScalarType::Address, flow::ScalarType::Address)
        | (flow::ScalarType::Float32, flow::ScalarType::Float32)
        | (flow::ScalarType::Float64, flow::ScalarType::Float64) => true,
        (flow::ScalarType::Bool, flow::ScalarType::Integer { bits: 8, .. }) => true,
        (
            flow::ScalarType::Integer { bits: source, .. },
            flow::ScalarType::Integer {
                bits: destination, ..
            },
        ) => source == destination,
        (flow::ScalarType::Integer { bits: 32, .. }, flow::ScalarType::Float32)
        | (flow::ScalarType::Float32, flow::ScalarType::Integer { bits: 32, .. })
        | (flow::ScalarType::Integer { bits: 64, .. }, flow::ScalarType::Float64)
        | (flow::ScalarType::Float64, flow::ScalarType::Integer { bits: 64, .. }) => true,
        _ => false,
    }
}

fn exact_flow_conversion(
    source: flow::ScalarType,
    destination: flow::ScalarType,
) -> Option<ConversionOp> {
    if source == destination {
        return Some(ConversionOp::Bitcast);
    }
    match (source, destination) {
        (
            flow::ScalarType::Integer {
                signed: source_signed,
                bits: source_bits,
            },
            flow::ScalarType::Integer {
                signed: destination_signed,
                bits: destination_bits,
            },
        ) if destination_bits > source_bits && (!source_signed || destination_signed) => {
            Some(if source_signed {
                ConversionOp::SignExtend
            } else {
                ConversionOp::ZeroExtend
            })
        }
        (flow::ScalarType::Float32, flow::ScalarType::Float64) => Some(ConversionOp::FloatExtend),
        (
            flow::ScalarType::Integer {
                signed: false,
                bits,
            },
            flow::ScalarType::Float32,
        ) if bits <= 24 => Some(ConversionOp::UnsignedIntegerToFloat),
        (flow::ScalarType::Integer { signed: true, bits }, flow::ScalarType::Float32)
            if bits <= 25 =>
        {
            Some(ConversionOp::SignedIntegerToFloat)
        }
        (
            flow::ScalarType::Integer {
                signed: false,
                bits,
            },
            flow::ScalarType::Float64,
        ) if bits <= 53 => Some(ConversionOp::UnsignedIntegerToFloat),
        (flow::ScalarType::Integer { signed: true, bits }, flow::ScalarType::Float64)
            if bits <= 54 =>
        {
            Some(ConversionOp::SignedIntegerToFloat)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum LoweredScalarConversion {
    Exact(ConversionOp),
    Checked {
        source: CheckedNumericKind,
        destination: CheckedNumericKind,
    },
}

fn checked_numeric_kind(scalar: flow::ScalarType) -> Option<CheckedNumericKind> {
    match scalar {
        flow::ScalarType::Integer { signed: false, .. } => {
            Some(CheckedNumericKind::UnsignedInteger)
        }
        flow::ScalarType::Integer { signed: true, .. } => Some(CheckedNumericKind::SignedInteger),
        flow::ScalarType::Float32 => Some(CheckedNumericKind::Float32),
        flow::ScalarType::Float64 => Some(CheckedNumericKind::Float64),
        flow::ScalarType::Bool | flow::ScalarType::Address => None,
    }
}

fn lower_scalar_conversion(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    value: flow::ValueId,
    to: flow::TypeId,
    mode: flow::CastMode,
) -> Result<LoweredScalarConversion, MachineLowerError> {
    let result = require_single_result(instruction)?;
    if flow_value_type(function, result)? != to {
        return Err(unsupported(
            "a scalar conversion whose result differs from its destination",
        ));
    }
    let source = flow_scalar_type(input, flow_value_type(function, value)?)?;
    let destination = flow_scalar_type(input, to)?;
    match mode {
        flow::CastMode::Bitcast if legal_flow_bitcast(source, destination) => {
            Ok(LoweredScalarConversion::Exact(ConversionOp::Bitcast))
        }
        flow::CastMode::Bitcast => Err(unsupported("an illegal scalar bitcast")),
        flow::CastMode::Exact => exact_flow_conversion(source, destination)
            .map(LoweredScalarConversion::Exact)
            .ok_or(unsupported(
                "a scalar conversion that is not universally lossless",
            )),
        flow::CastMode::Checked => checked_numeric_kind(source)
            .zip(checked_numeric_kind(destination))
            .map(|(source, destination)| LoweredScalarConversion::Checked {
                source,
                destination,
            })
            .ok_or(unsupported("a checked conversion on non-numeric scalars")),
    }
}

/// Whether a pure Flow instruction exists only to carry the zero-sized `unit`
/// value through structured SSA. MachineWir has no value of type `void`, so
/// these definitions are erased together with all of their uses. Effectful
/// unit-returning calls are deliberately not included: the call remains while
/// only its zero-sized result is erased.
fn erases_unit_definition(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
) -> Result<bool, MachineLowerError> {
    let [result] = instruction.results.as_slice() else {
        return Ok(false);
    };
    if !flow_value_is_unit(input, function, *result)? {
        return Ok(false);
    }
    match &instruction.operation {
        flow::FlowOperation::Immediate(flow::Immediate::Unit) => Ok(true),
        flow::FlowOperation::Immediate(flow::Immediate::Zero(ty)) => {
            Ok(*ty == flow_value_type(function, *result)?)
        }
        flow::FlowOperation::Move { value } | flow::FlowOperation::Copy { value } => {
            flow_value_is_unit(input, function, *value)
        }
        flow::FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            let condition_is_bool = input
                .types
                .get(flow_value_type(function, *condition)?.0 as usize)
                .is_some_and(|ty| ty.kind == flow::FlowTypeKind::Scalar(flow::ScalarType::Bool));
            Ok(condition_is_bool
                && flow_value_is_unit(input, function, *then_value)?
                && flow_value_is_unit(input, function, *else_value)?)
        }
        _ => Ok(false),
    }
}

fn validate_supported_operation(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    test_payload_index: &TestPayloadIndex,
    activations: &[MachineActivationPlan],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    if erases_unit_definition(input, function, instruction)? {
        return Ok(());
    }
    let mut has_unit_result = false;
    for result in &instruction.results {
        check_cancelled(is_cancelled)?;
        has_unit_result |= flow_value_is_unit(input, function, *result)?;
    }
    if has_unit_result && !matches!(instruction.operation, flow::FlowOperation::Call { .. }) {
        return Err(unsupported(
            "an effectful zero-sized unit definition outside a direct call",
        ));
    }
    match &instruction.operation {
        flow::FlowOperation::Binary {
            op:
                op @ (flow::BinaryOp::AddChecked
                | flow::BinaryOp::SubChecked
                | flow::BinaryOp::MulChecked
                | flow::BinaryOp::DivChecked
                | flow::BinaryOp::RemChecked
                | flow::BinaryOp::ShiftLeftChecked
                | flow::BinaryOp::ShiftLeftWrapping
                | flow::BinaryOp::ShiftRightChecked),
            left,
            right,
        } => lower_binary(
            input,
            function,
            instruction,
            *op,
            *left,
            *right,
            ValueMapping::DenseShift(0),
        )
        .map(|_| ()),
        flow::FlowOperation::ActorCapability { .. }
        | flow::FlowOperation::Immediate(
            flow::Immediate::Bool(_)
            | flow::Immediate::Integer { .. }
            | flow::Immediate::Float32(_)
            | flow::Immediate::Float64(_)
            | flow::Immediate::Zero(_)
            | flow::Immediate::FunctionAddress(_),
        )
        | flow::FlowOperation::Binary {
            op:
                flow::BinaryOp::AddWrapping
                | flow::BinaryOp::SubWrapping
                | flow::BinaryOp::MulWrapping
                | flow::BinaryOp::BitAnd
                | flow::BinaryOp::BitOr
                | flow::BinaryOp::BitXor
                | flow::BinaryOp::Equal
                | flow::BinaryOp::NotEqual
                | flow::BinaryOp::Less
                | flow::BinaryOp::LessEqual
                | flow::BinaryOp::Greater
                | flow::BinaryOp::GreaterEqual,
            ..
        }
        | flow::FlowOperation::Select { .. }
        | flow::FlowOperation::Load { .. }
        | flow::FlowOperation::Store { .. }
        | flow::FlowOperation::Move { .. }
        | flow::FlowOperation::Copy { .. }
        | flow::FlowOperation::Drop { .. }
        | flow::FlowOperation::Fence { .. } => Ok(()),
        flow::FlowOperation::Unary { op, value } => {
            lower_scalar_unary(input, function, instruction, *op, *value).map(|_| ())
        }
        flow::FlowOperation::Cast { value, to, mode } => {
            lower_scalar_conversion(input, function, instruction, *value, *to, *mode).map(|_| ())
        }
        flow::FlowOperation::MakeAggregate { ty, fields } => {
            let result = require_single_result(instruction)?;
            let Some(field_type) = flat_u64_struct_field(&input.types, *ty) else {
                return Err(unsupported(
                    "an aggregate constructor outside the one-field u64 representation",
                ));
            };
            let [field] = fields.as_slice() else {
                return Err(unsupported(
                    "an aggregate constructor without exactly one field value",
                ));
            };
            if flow_value_type(function, result)? != *ty
                || flow_value_type(function, *field)? != field_type
            {
                return Err(unsupported(
                    "an aggregate constructor with mismatched field or result types",
                ));
            }
            Ok(())
        }
        flow::FlowOperation::InsertField {
            aggregate,
            field,
            value,
        } => {
            let result = require_single_result(instruction)?;
            validate_flat_structure_field_update(
                &input.types,
                function,
                result,
                *aggregate,
                *field,
                *value,
            )?;
            Ok(())
        }
        flow::FlowOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => {
            let result = require_single_result(instruction)?;
            let payload_ty = closed_scalar_enum_payload(&input.types, *ty)
                .ok_or(unsupported("a noncanonical enum construction"))?;
            let variant_count = input
                .types
                .get(ty.0 as usize)
                .and_then(|record| match &record.kind {
                    flow::FlowTypeKind::Enum { variants } => Some(variants.len()),
                    _ => None,
                })
                .ok_or(unsupported("an enum construction without an enum type"))?;
            if usize::from(*variant) >= variant_count
                || flow_value_type(function, result)? != *ty
                || flow_value_type(function, *payload)? != payload_ty
            {
                return Err(unsupported(
                    "an enum construction with mismatched tag or payload",
                ));
            }
            Ok(())
        }
        flow::FlowOperation::EnumTag { value } => {
            let result = require_single_result(instruction)?;
            let enum_ty = flow_value_type(function, *value)?;
            if closed_scalar_enum_payload(&input.types, enum_ty).is_none()
                || Some(flow_value_type(function, result)?) != canonical_u8_type(&input.types)
            {
                return Err(unsupported("an enum tag projection with mismatched types"));
            }
            Ok(())
        }
        flow::FlowOperation::EnumPayload { value } => {
            let result = require_single_result(instruction)?;
            let enum_ty = flow_value_type(function, *value)?;
            if closed_scalar_enum_payload(&input.types, enum_ty)
                != Some(flow_value_type(function, result)?)
            {
                return Err(unsupported(
                    "an enum payload projection with mismatched types",
                ));
            }
            Ok(())
        }
        flow::FlowOperation::ExtractField { aggregate, field } => {
            let result = require_single_result(instruction)?;
            let aggregate_type = flow_value_type(function, *aggregate)?;
            let Some(field_type) = flat_u64_struct_field(&input.types, aggregate_type) else {
                return Err(unsupported(
                    "a field extraction outside the one-field u64 representation",
                ));
            };
            if *field != 0 || flow_value_type(function, result)? != field_type {
                return Err(unsupported(
                    "a field extraction with an invalid field or result type",
                ));
            }
            Ok(())
        }
        flow::FlowOperation::Immediate(flow::Immediate::Bytes(_)) => {
            let [result] = instruction.results.as_slice() else {
                return Err(unsupported(
                    "a static test payload without exactly one address result",
                ));
            };
            if test_payload_index.contains(function.id, *result) {
                Ok(())
            } else {
                Err(unsupported(
                    "a byte immediate outside a generated test frame",
                ))
            }
        }
        flow::FlowOperation::TestEmit { payload } => {
            require_no_results(instruction)?;
            if test_payload_index.contains(function.id, *payload) {
                Ok(())
            } else {
                Err(unsupported("an unplanned generated test emission"))
            }
        }
        flow::FlowOperation::TestFinish { outcome } => {
            require_no_results(instruction)?;
            let outcome_ty = flow_value_type(function, *outcome)?;
            if function.id != input.image_entry
                || !matches!(
                    function.origin,
                    flow::FunctionOrigin::GeneratedTestHarness { .. }
                )
                || input.types.get(outcome_ty.0 as usize).is_none_or(|ty| {
                    ty.kind
                        != flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                            signed: false,
                            bits: 32,
                        })
                })
            {
                Err(unsupported(
                    "a test finish without an exact generated-harness u32 outcome",
                ))
            } else {
                Ok(())
            }
        }
        flow::FlowOperation::Assert { condition, failure } => {
            require_no_results(instruction)?;
            let condition_ty = flow_value_type(function, *condition)?;
            let condition_is_bool = input
                .types
                .get(condition_ty.0 as usize)
                .is_some_and(|ty| ty.kind == flow::FlowTypeKind::Scalar(flow::ScalarType::Bool));
            let message_is_valid = failure.message.as_ref().is_none_or(|message| {
                !message.is_empty() && message.len() <= flow::ASSERTION_EXPRESSION_BYTES_MAX
            });
            if input.tests.len() != 1
                || !function_is_reachable_from_selected_test(input, function.id, is_cancelled)?
                || !condition_is_bool
                || failure.expression.is_empty()
                || failure.expression.len() > flow::ASSERTION_EXPRESSION_BYTES_MAX
                || !message_is_valid
                || failure.source.range.start > failure.source.range.end
                || instruction.source != Some(failure.source)
            {
                Err(unsupported(
                    "a runtime assertion outside one selected generated source-test closure",
                ))
            } else {
                Ok(())
            }
        }
        flow::FlowOperation::Call { function, .. } => {
            if *function == input.image_entry {
                Err(unsupported("a direct call to the UEFI image entry"))
            } else if input
                .functions
                .get(function.0 as usize)
                .is_none_or(|callee| callee.color != flow::FunctionColor::Sync)
            {
                Err(unsupported(
                    "an ordinary scalar call without an exact synchronous callee",
                ))
            } else {
                Ok(())
            }
        }
        flow::FlowOperation::ActorReserve { .. } => {
            let [result] = instruction.results.as_slice() else {
                return Err(unsupported(
                    "an actor reservation without one strict-linear result",
                ));
            };
            if input
                .types
                .get(flow_value_type(function, *result)?.0 as usize)
                .is_some_and(|ty| ty.kind == flow::FlowTypeKind::Reservation)
            {
                Ok(())
            } else {
                Err(unsupported(
                    "an actor reservation with the wrong result type",
                ))
            }
        }
        flow::FlowOperation::ActorCommit { arguments, .. } => {
            require_no_results(instruction)?;
            if arguments.is_empty() {
                Ok(())
            } else {
                Err(unsupported("actor message payload lowering"))
            }
        }
        flow::FlowOperation::MailboxReceive { .. } => require_no_results(instruction),
        flow::FlowOperation::AsyncCall {
            function: callee,
            arguments,
            plan,
        } if arguments.is_empty()
            && activations.iter().any(|activation| {
                activation.id.0 == plan.0
                    && activation.caller.0 == function.id.0
                    && activation.callee.0 == callee.0
                    && activation.call_instruction.0 == instruction.id.0
                    && instruction.source == Some(activation.source)
            }) =>
        {
            Ok(())
        }
        flow::FlowOperation::AsyncCall { .. } => Err(unsupported(
            "an asynchronous call without an exact scheduler/runtime lowering",
        )),
        flow::FlowOperation::Immediate(flow::Immediate::Unit) => Err(unsupported(
            "a unit immediate without an exact zero-sized unit result",
        )),
        flow::FlowOperation::Immediate(flow::Immediate::GlobalAddress(_)) => {
            Err(unsupported("global-address immediates"))
        }
        flow::FlowOperation::BeginAccess { .. }
        | flow::FlowOperation::EndAccess { .. }
        | flow::FlowOperation::Allocate { .. }
        | flow::FlowOperation::RegionReset { .. }
        | flow::FlowOperation::ActorReject { .. }
        | flow::FlowOperation::ReplyResolve { .. }
        | flow::FlowOperation::ReceiptCommit { .. }
        | flow::FlowOperation::ReceiptResolve { .. }
        | flow::FlowOperation::TaskAcquireSlot { .. }
        | flow::FlowOperation::TaskStart { .. }
        | flow::FlowOperation::TaskCancel { .. }
        | flow::FlowOperation::Park { .. }
        | flow::FlowOperation::Wake { .. }
        | flow::FlowOperation::Checkpoint { .. }
        | flow::FlowOperation::DeadlineRead
        | flow::FlowOperation::InterruptMask
        | flow::FlowOperation::InterruptRestore { .. }
        | flow::FlowOperation::InterruptPublish { .. }
        | flow::FlowOperation::MmioRead { .. }
        | flow::FlowOperation::MmioWrite { .. }
        | flow::FlowOperation::DmaTransition { .. }
        | flow::FlowOperation::QueueReserve { .. }
        | flow::FlowOperation::QueuePublish { .. }
        | flow::FlowOperation::ValidateDeviceValue { .. }
        | flow::FlowOperation::Check { .. }
        | flow::FlowOperation::RecordEvent { .. }
        | flow::FlowOperation::ReplayEvent { .. } => Err(unsupported(
            "aggregate, ownership, runtime, device, async, or test operations",
        )),
    }
}

fn function_is_reachable_from_selected_test(
    input: &flow::FlowWir,
    target: flow::FunctionId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    let [test] = input.tests.as_slice() else {
        return Ok(false);
    };
    let mut pending = vec![test.function];
    let mut seen = vec![false; input.functions.len()];
    while let Some(function_id) = pending.pop() {
        check_cancelled(is_cancelled)?;
        if function_id == target {
            return Ok(true);
        }
        let Some(slot) = seen.get_mut(function_id.0 as usize) else {
            return Ok(false);
        };
        if *slot {
            continue;
        }
        *slot = true;
        let Some(function) = input.functions.get(function_id.0 as usize) else {
            return Ok(false);
        };
        for block in &function.blocks {
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if let flow::FlowOperation::Call {
                    function: callee, ..
                } = instruction.operation
                {
                    pending.push(callee);
                }
            }
        }
    }
    Ok(false)
}

fn lower_types(
    input: &flow::FlowWir,
    pointer_type: MachineTypeId,
    status_type: MachineTypeId,
    plan: &ScalarPlan,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineType>, MachineLowerError> {
    let capacity = input
        .types
        .len()
        .checked_add(2)
        .and_then(|count| count.checked_add(usize::from(plan.storage_byte_type.is_some())))
        .and_then(|count| count.checked_add(usize::from(plan.assertion_storage_type.is_some())))
        .and_then(|count| count.checked_add(plan.region_storage.len()))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir types",
            limit: limits.types,
        })?;
    let mut types = try_vec(capacity, "MachineWir types", limits.types, is_cancelled)?;
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        let (kind, size, alignment) = match &ty.kind {
            flow::FlowTypeKind::Function { parameters, result } => lower_passive_function_type(
                &input.types,
                parameters,
                *result,
                limits,
                is_cancelled,
            )?,
            flow::FlowTypeKind::Struct { fields } if fields.is_empty() => {
                lower_type_kind(&ty.kind, limits, is_cancelled)?
            }
            flow::FlowTypeKind::Struct { .. } => {
                let field = flat_u64_struct_field(&input.types, ty.id)
                    .ok_or(unsupported("a non-scalar-backed aggregate type"))?;
                let field = input
                    .types
                    .get(field.0 as usize)
                    .ok_or(unsupported("a flat aggregate with an unknown field type"))?;
                lower_type_kind(&field.kind, limits, is_cancelled)?
            }
            flow::FlowTypeKind::Enum { .. } => {
                let payload = closed_scalar_enum_payload(&input.types, ty.id)
                    .ok_or(unsupported("a noncanonical closed enum type"))?;
                let tag = canonical_u8_type(&input.types).ok_or(unsupported(
                    "a closed enum without the canonical u8 tag type",
                ))?;
                let payload_kind = &input
                    .types
                    .get(payload.0 as usize)
                    .ok_or(unsupported("an enum with an unknown payload type"))?
                    .kind;
                let (_, payload_size, payload_alignment) =
                    lower_type_kind(payload_kind, limits, is_cancelled)?;
                let alignment = payload_alignment.max(1);
                let payload_offset =
                    (1_u64 + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
                let unaligned_size = payload_offset.checked_add(payload_size).ok_or(
                    MachineLowerError::LayoutOverflow {
                        subject: "closed enum representation".to_owned(),
                    },
                )?;
                let size =
                    (unaligned_size + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
                let variant_count = match &ty.kind {
                    flow::FlowTypeKind::Enum { variants } => u16::try_from(variants.len())
                        .map_err(|_| unsupported("an enum exceeding 256 variants"))?,
                    _ => return Err(unsupported("a non-enum tagged representation")),
                };
                (
                    MachineTypeKind::TaggedEnum {
                        tag: MachineTypeId(tag.0),
                        payload: MachineTypeId(payload.0),
                        variants: variant_count,
                    },
                    size,
                    alignment,
                )
            }
            _ => lower_type_kind(&ty.kind, limits, is_cancelled)?,
        };
        types.push(MachineType {
            id: MachineTypeId(ty.id.0),
            kind,
            size,
            alignment,
            source_name: match &ty.name {
                Some(name) => Some(copy_text(
                    name,
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?),
                None => None,
            },
        });
    }
    types.push(MachineType {
        id: pointer_type,
        kind: MachineTypeKind::Pointer {
            address_space: 0,
            pointee: None,
        },
        size: 8,
        alignment: 8,
        source_name: None,
    });
    types.push(MachineType {
        id: status_type,
        kind: MachineTypeKind::Integer { bits: 64 },
        size: 8,
        alignment: 8,
        source_name: None,
    });
    if let Some(byte_type) = plan.storage_byte_type {
        if byte_type.0 as usize != types.len() {
            return Err(unsupported("a non-dense actor storage byte type"));
        }
        types.push(MachineType {
            id: byte_type,
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: None,
        });
        if let Some(assertion_type) = plan.assertion_storage_type {
            if assertion_type.0 as usize != types.len() {
                return Err(unsupported("a non-dense assertion storage type"));
            }
            types.push(MachineType {
                id: assertion_type,
                kind: MachineTypeKind::Array {
                    element: byte_type,
                    length: ASSERTION_STORAGE_BYTES as u64,
                },
                size: ASSERTION_STORAGE_BYTES as u64,
                alignment: 1,
                source_name: Some(copy_text(
                    "generated-test-assertion",
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?),
            });
        }
        for storage in &plan.region_storage {
            check_cancelled(is_cancelled)?;
            if storage.ty.0 as usize != types.len() {
                return Err(unsupported("a non-dense actor region storage type"));
            }
            types.push(MachineType {
                id: storage.ty,
                kind: MachineTypeKind::Array {
                    element: byte_type,
                    length: storage.capacity_bytes,
                },
                size: storage.capacity_bytes,
                alignment: storage.alignment,
                source_name: Some(copy_text(
                    &storage.name,
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?),
            });
        }
    }
    Ok(types)
}

fn lower_passive_function_type(
    types: &[flow::FlowType],
    parameters: &[flow::TypeId],
    result: flow::TypeId,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(MachineTypeKind, u64, u32), MachineLowerError> {
    let mut retained_count = 0usize;
    for parameter in parameters {
        check_cancelled(is_cancelled)?;
        if !flow_type_is_erased_in(types, *parameter)? {
            retained_count =
                retained_count
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit: limits.model_edges,
                    })?;
        }
    }
    let mut machine_parameters = try_vec(
        retained_count,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for parameter in parameters {
        check_cancelled(is_cancelled)?;
        if !flow_type_is_erased_in(types, *parameter)? {
            machine_parameters.push(MachineTypeId(parameter.0));
        }
    }
    Ok((
        MachineTypeKind::Function {
            parameters: machine_parameters,
            result: MachineTypeId(result.0),
        },
        0,
        1,
    ))
}

fn lower_type_kind(
    kind: &flow::FlowTypeKind,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(MachineTypeKind, u64, u32), MachineLowerError> {
    match kind {
        flow::FlowTypeKind::Unit => Ok((MachineTypeKind::Void, 0, 1)),
        flow::FlowTypeKind::Scalar(flow::ScalarType::Bool) => {
            Ok((MachineTypeKind::Integer { bits: 8 }, 1, 1))
        }
        flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { bits, .. }) => {
            let bytes = u64::from(*bits / 8);
            let alignment = u32::from((*bits / 8).min(16));
            Ok((MachineTypeKind::Integer { bits: *bits }, bytes, alignment))
        }
        flow::FlowTypeKind::Scalar(flow::ScalarType::Float32) => {
            Ok((MachineTypeKind::Float32, 4, 4))
        }
        flow::FlowTypeKind::Scalar(flow::ScalarType::Float64) => {
            Ok((MachineTypeKind::Float64, 8, 8))
        }
        flow::FlowTypeKind::Scalar(flow::ScalarType::Address) => Ok((
            MachineTypeKind::Pointer {
                address_space: 0,
                pointee: None,
            },
            8,
            8,
        )),
        flow::FlowTypeKind::ActorHandle(_) => Ok((MachineTypeKind::Integer { bits: 64 }, 8, 8)),
        flow::FlowTypeKind::Reservation => Ok((
            MachineTypeKind::Pointer {
                address_space: 0,
                pointee: None,
            },
            8,
            8,
        )),
        flow::FlowTypeKind::Array { element, length } => Ok((
            MachineTypeKind::Array {
                element: MachineTypeId(element.0),
                length: *length,
            },
            *length,
            1,
        )),
        flow::FlowTypeKind::Function { parameters, result } => {
            let mut machine_parameters = try_vec(
                parameters.len(),
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            for parameter in parameters {
                check_cancelled(is_cancelled)?;
                machine_parameters.push(MachineTypeId(parameter.0));
            }
            Ok((
                MachineTypeKind::Function {
                    parameters: machine_parameters,
                    result: MachineTypeId(result.0),
                },
                0,
                1,
            ))
        }
        flow::FlowTypeKind::Activation { .. } => Ok((MachineTypeKind::Void, 0, 1)),
        flow::FlowTypeKind::Struct { fields } if fields.is_empty() => {
            Ok((MachineTypeKind::Void, 0, 1))
        }
        _ => Err(unsupported("a type outside scalar lowering")),
    }
}

fn lower_sections(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Section>, MachineLowerError> {
    let capacity = input
        .functions
        .len()
        .checked_add(1 + usize::from(!plan.test_payloads.is_empty()))
        .and_then(|count| count.checked_add(plan.region_storage.len()))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(limits.sections),
        })?;
    let mut sections = try_vec(
        capacity,
        "MachineWir sections",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    for (function, reserved_bytes) in input.functions.iter().zip(&plan.code_bounds) {
        let entry = function.id == input.image_entry;
        sections.push(Section {
            id: SectionId(function.id.0),
            name: if entry {
                copy_text(
                    ".text.wrela.entry",
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?
            } else {
                numbered_text(
                    ".text.wrela.",
                    function.id.0,
                    limits.payload_bytes,
                    is_cancelled,
                )?
            },
            kind: SectionKind::Code,
            alignment: 16,
            reserved_bytes: *reserved_bytes,
            owner: copy_text(
                if entry { "image" } else { "function" },
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
        });
    }
    let mut next_section =
        u32::try_from(input.functions.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(limits.sections),
        })?;
    if !plan.test_payloads.is_empty() {
        sections.push(Section {
            id: SectionId(next_section),
            name: copy_text(
                TEST_PAYLOAD_SECTION,
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            kind: SectionKind::ReadOnlyData,
            alignment: 8,
            reserved_bytes: plan
                .test_payload_bytes
                .checked_add(plan.assertion_payload_bytes)
                .ok_or(MachineLowerError::LayoutOverflow {
                    subject: "generated test read-only payloads".to_owned(),
                })?,
            owner: copy_text(
                "generated-test-harness",
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
        });
        next_section = next_section
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir sections",
                limit: u64::from(limits.sections),
            })?;
    }
    for storage in &plan.region_storage {
        check_cancelled(is_cancelled)?;
        if storage.section.0 != next_section {
            return Err(unsupported("a non-dense actor region storage section"));
        }
        sections.push(Section {
            id: storage.section,
            name: numbered_text(
                REGION_STORAGE_SECTION_PREFIX,
                storage.id.0,
                limits.payload_bytes,
                is_cancelled,
            )?,
            kind: SectionKind::WritableData,
            alignment: storage.alignment,
            reserved_bytes: storage.capacity_bytes,
            owner: copy_text(
                &storage.name,
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
        });
        next_section = next_section
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir sections",
                limit: u64::from(limits.sections),
            })?;
    }
    sections.push(Section {
        id: SectionId(next_section),
        name: copy_text(
            INTERRUPT_ROUTE_SECTION,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        kind: SectionKind::RuntimeMetadata,
        alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
        reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
        owner: copy_text(
            "runtime",
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
    });
    Ok(sections)
}

fn lower_symbols(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    entry_symbol: &str,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Symbol>, MachineLowerError> {
    let runtime_symbols = usize::from(plan.image_enter_calls != 0)
        .checked_add(usize::from(plan.fatal_calls != 0))
        .and_then(|count| count.checked_add(usize::from(!plan.test_payloads.is_empty()) * 2))
        .and_then(|count| count.checked_add(usize::from(plan.test_assert_calls != 0)))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(limits.symbols),
        })?;
    let capacity = input
        .functions
        .len()
        .checked_add(plan.test_payloads.len())
        .and_then(|count| count.checked_add(plan.assertion_payloads.len()))
        .and_then(|count| count.checked_add(plan.region_storage.len()))
        .and_then(|count| count.checked_add(runtime_symbols))
        .and_then(|count| count.checked_add(1))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(limits.symbols),
        })?;
    let mut symbols = try_vec(
        capacity,
        "MachineWir symbols",
        u64::from(limits.symbols),
        is_cancelled,
    )?;
    for function in &input.functions {
        let entry = function.id == input.image_entry;
        symbols.push(Symbol {
            id: SymbolId(function.id.0),
            name: if entry {
                copy_text(
                    entry_symbol,
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?
            } else {
                numbered_text(
                    "__wrela_fn_",
                    function.id.0,
                    limits.payload_bytes,
                    is_cancelled,
                )?
            },
            visibility: if entry {
                SymbolVisibility::ImageEntry
            } else {
                SymbolVisibility::Private
            },
            definition: SymbolDefinition::Function(FunctionId(function.id.0)),
        });
    }
    let mut next_symbol =
        u32::try_from(input.functions.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(limits.symbols),
        })?;
    for payload in &plan.test_payloads {
        symbols.push(Symbol {
            id: SymbolId(next_symbol),
            name: numbered_text(
                TEST_PAYLOAD_SYMBOL_PREFIX,
                payload.global.0,
                limits.payload_bytes,
                is_cancelled,
            )?,
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Global(payload.global),
        });
        next_symbol = next_symbol
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir symbols",
                limit: u64::from(limits.symbols),
            })?;
    }
    for payload in &plan.assertion_payloads {
        symbols.push(Symbol {
            id: SymbolId(next_symbol),
            name: numbered_text(
                ASSERTION_PAYLOAD_SYMBOL_PREFIX,
                payload.global.0,
                limits.payload_bytes,
                is_cancelled,
            )?,
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Global(payload.global),
        });
        next_symbol = next_symbol
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir symbols",
                limit: u64::from(limits.symbols),
            })?;
    }
    for storage in &plan.region_storage {
        check_cancelled(is_cancelled)?;
        if storage.symbol.0 != next_symbol {
            return Err(unsupported("a non-dense actor region storage symbol"));
        }
        symbols.push(Symbol {
            id: storage.symbol,
            name: numbered_text(
                REGION_STORAGE_SYMBOL_PREFIX,
                storage.id.0,
                limits.payload_bytes,
                is_cancelled,
            )?,
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Global(storage.global),
        });
        next_symbol = next_symbol
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir symbols",
                limit: u64::from(limits.symbols),
            })?;
    }
    for intrinsic in scalar_runtime_requirements(plan).intrinsics {
        symbols.push(Symbol {
            id: SymbolId(next_symbol),
            name: copy_text(
                intrinsic.symbol_name(),
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            visibility: SymbolVisibility::Runtime,
            definition: SymbolDefinition::ExternalRuntime(intrinsic),
        });
        next_symbol = next_symbol
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir symbols",
                limit: u64::from(limits.symbols),
            })?;
    }
    let metadata_section = u32::try_from(input.functions.len())
        .ok()
        .and_then(|id| id.checked_add(u32::from(!plan.test_payloads.is_empty())))
        .and_then(|id| id.checked_add(u32::try_from(plan.region_storage.len()).ok()?))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(limits.sections),
        })?;
    symbols.push(Symbol {
        id: SymbolId(next_symbol),
        name: copy_text(
            INTERRUPT_ROUTE_TABLE_SYMBOL,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        visibility: SymbolVisibility::RuntimeMetadata,
        definition: SymbolDefinition::SectionOffset {
            section: SectionId(metadata_section),
            offset: 0,
            bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
        },
    });
    Ok(symbols)
}

fn lower_globals(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineGlobal>, MachineLowerError> {
    let mut globals = try_vec(
        plan.test_payloads
            .len()
            .checked_add(plan.assertion_payloads.len())
            .and_then(|count| count.checked_add(plan.region_storage.len()))
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir globals",
                limit: u64::from(limits.globals),
            })?,
        "MachineWir globals",
        u64::from(limits.globals),
        is_cancelled,
    )?;
    let section = SectionId(u32::try_from(input.functions.len()).map_err(|_| {
        MachineLowerError::ResourceLimit {
            resource: "MachineWir sections",
            limit: u64::from(limits.sections),
        }
    })?);
    let first_symbol =
        u32::try_from(input.functions.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir symbols",
            limit: u64::from(limits.symbols),
        })?;
    for payload in &plan.test_payloads {
        check_cancelled(is_cancelled)?;
        let function = input
            .functions
            .get(payload.function.0 as usize)
            .ok_or(unsupported(
                "a planned test payload with an unknown function",
            ))?;
        let block = function
            .blocks
            .get(payload.block.0 as usize)
            .ok_or(unsupported("a planned test payload with an unknown block"))?;
        let definition = block
            .instructions
            .get(payload.definition_index as usize)
            .ok_or(unsupported(
                "a planned test payload with an unknown definition",
            ))?;
        let flow::FlowOperation::Immediate(flow::Immediate::Bytes(bytes)) = &definition.operation
        else {
            return Err(unsupported("a planned test payload that changed shape"));
        };
        let symbol =
            first_symbol
                .checked_add(payload.global.0)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir symbols",
                    limit: u64::from(limits.symbols),
                })?;
        globals.push(MachineGlobal {
            id: payload.global,
            symbol: SymbolId(symbol),
            ty: MachineTypeId(payload.ty.0),
            section,
            offset: payload.offset,
            alignment: 1,
            initializer: MachineImmediate::Bytes(copy_bytes(
                bytes,
                limits.payload_bytes,
                is_cancelled,
            )?),
        });
    }
    let assertion_type = plan.assertion_storage_type;
    for payload in &plan.assertion_payloads {
        check_cancelled(is_cancelled)?;
        if payload.global.0 as usize != globals.len() {
            return Err(unsupported("a non-dense assertion payload global"));
        }
        let symbol =
            first_symbol
                .checked_add(payload.global.0)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir symbols",
                    limit: u64::from(limits.symbols),
                })?;
        globals.push(MachineGlobal {
            id: payload.global,
            symbol: SymbolId(symbol),
            ty: assertion_type.ok_or(unsupported(
                "assertion payload without its sealed storage type",
            ))?,
            section,
            offset: payload.offset,
            alignment: 1,
            initializer: MachineImmediate::Bytes(copy_bytes(
                &payload.bytes,
                limits.payload_bytes,
                is_cancelled,
            )?),
        });
    }
    for storage in &plan.region_storage {
        check_cancelled(is_cancelled)?;
        if storage.global.0 as usize != globals.len() {
            return Err(unsupported("a non-dense actor region storage global"));
        }
        globals.push(MachineGlobal {
            id: storage.global,
            symbol: storage.symbol,
            ty: storage.ty,
            section: storage.section,
            offset: 0,
            alignment: storage.alignment,
            initializer: MachineImmediate::Zero(storage.ty),
        });
    }
    Ok(globals)
}

fn lower_tests(
    input: &flow::FlowWir,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineTestEntry>, MachineLowerError> {
    let mut tests = try_vec(
        input.tests.len(),
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for test in &input.tests {
        check_cancelled(is_cancelled)?;
        tests.push(MachineTestEntry {
            id: MachineTestId(test.id.0),
            plan_id: test.plan_id,
            name: copy_text(
                &test.name,
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            function: FunctionId(test.function.0),
            kind: match test.kind {
                flow::TestKind::Comptime => MachineTestKind::Comptime,
                flow::TestKind::Integration => MachineTestKind::Integration,
                flow::TestKind::Image => MachineTestKind::Image,
            },
            source: test.source,
            timeout_ns: test.timeout_ns,
        });
    }
    Ok(tests)
}

fn lower_proofs(
    input: &flow::FlowWir,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<wrela_machine_wir::BackendProof>, MachineLowerError> {
    let mut proofs = try_vec(
        input.proofs.len(),
        "MachineWir proofs",
        u64::from(limits.proofs),
        is_cancelled,
    )?;
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        let mut sources = try_vec(
            1,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        sources.push(proof.id.0);
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        for dependency in &proof.depends_on {
            check_cancelled(is_cancelled)?;
            depends_on.push(ProofId(dependency.0));
        }
        let mut proof_sources = try_vec(
            proof.sources.len(),
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        for source in &proof.sources {
            check_cancelled(is_cancelled)?;
            proof_sources.push(*source);
        }
        proofs.push(wrela_machine_wir::BackendProof {
            id: ProofId(proof.id.0),
            source_proofs: sources,
            kind: lower_proof_kind(&proof.kind),
            depends_on,
            bound: proof.bound,
            sources: proof_sources,
            statement: prefixed_text(
                SCALAR_BACKEND_PROOF_PREFIX,
                &proof.subject,
                limits.payload_bytes,
                is_cancelled,
            )?,
            source: proof.sources.first().copied(),
        });
    }
    Ok(proofs)
}

fn lower_proof_kind(kind: &flow::ProofKind) -> wrela_machine_wir::BackendProofKind {
    use flow::ProofKind as Flow;
    use wrela_machine_wir::BackendProofKind as Machine;
    match kind {
        Flow::TypeChecked => Machine::TypeChecked,
        Flow::EffectsAllowed => Machine::EffectsAllowed,
        Flow::DefiniteInitialization => Machine::DefiniteInitialization,
        Flow::Ownership => Machine::Ownership,
        Flow::AccessExclusive => Machine::AccessExclusive,
        Flow::ViewDoesNotEscape => Machine::ViewDoesNotEscape,
        Flow::RegionBound => Machine::RegionBound,
        Flow::CapacityBound => Machine::CapacityBound,
        Flow::WaitGraphAcyclic => Machine::WaitGraphAcyclic,
        Flow::CleanupAcyclic => Machine::CleanupAcyclic,
        Flow::WorkBound => Machine::WorkBound,
        Flow::StackBound => Machine::StackBound,
        Flow::IsrSafe => Machine::IsrSafe,
        Flow::DmaTransition => Machine::DmaTransition,
        Flow::MmioPartition => Machine::MmioPartition,
        Flow::DeviceValueValidated => Machine::DeviceValueValidated,
        Flow::WireLayout => Machine::WireLayout,
        Flow::ReceiptLineage => Machine::ReceiptLineage,
        Flow::ActorAsIf => Machine::ActorAsIf,
        Flow::SupervisionComplete => Machine::SupervisionComplete,
        Flow::ImageClosed => Machine::ImageClosed,
        Flow::FlowControl => Machine::FlowControl,
        Flow::ValueRange => Machine::ValueRange,
        Flow::Alignment => Machine::Alignment,
        Flow::NoAlias => Machine::NoAlias,
    }
}

fn lower_functions(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    pointer_type: MachineTypeId,
    status_type: MachineTypeId,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<MachineFunction>, MachineLowerError> {
    let mut functions = try_vec(
        input.functions.len(),
        "MachineWir functions",
        limits.functions,
        is_cancelled,
    )?;
    for function in &input.functions {
        functions.push(lower_function(
            input,
            plan,
            function,
            pointer_type,
            status_type,
            limits,
            is_cancelled,
        )?);
    }
    Ok(functions)
}

fn count_return_blocks(
    function: &flow::FlowFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    let mut count = 0usize;
    for block in &function.blocks {
        check_cancelled(is_cancelled)?;
        if matches!(block.terminator, flow::Terminator::Return(_)) {
            count = count
                .checked_add(1)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir instructions",
                    limit: u64::MAX,
                })?;
        }
    }
    Ok(count)
}

fn count_test_emits(
    function: &flow::FlowFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    let mut count = 0usize;
    for block in &function.blocks {
        check_cancelled(is_cancelled)?;
        for instruction in &block.instructions {
            check_cancelled(is_cancelled)?;
            if matches!(instruction.operation, flow::FlowOperation::TestEmit { .. }) {
                count = count
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir instructions",
                        limit: u64::MAX,
                    })?;
            }
        }
    }
    Ok(count)
}

fn count_test_emits_in_block(
    block: &flow::Block,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    let mut count = 0usize;
    for instruction in &block.instructions {
        check_cancelled(is_cancelled)?;
        if matches!(instruction.operation, flow::FlowOperation::TestEmit { .. }) {
            count = count
                .checked_add(1)
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir instructions",
                    limit: u64::MAX,
                })?;
        }
    }
    Ok(count)
}

struct LoweredBlock {
    source: MachineBlock,
    generated: Vec<MachineBlock>,
}

fn lower_function(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    function: &flow::FlowFunction,
    pointer_type: MachineTypeId,
    status_type: MachineTypeId,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineFunction, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    let entry = function.id == input.image_entry;
    let first_source_value = if entry { 2 } else { 0 };
    let (value_mapping, first_generated_value) = build_value_mapping(
        &input.types,
        function,
        first_source_value,
        limits.model_edges,
        is_cancelled,
    )?;
    let mapping = ValueMapping::Canonical {
        retained: &value_mapping,
        value_count: function.values.len(),
        first: first_source_value,
    };
    let return_count = if entry {
        count_return_blocks(function, is_cancelled)?
    } else {
        0
    };
    let test_emit_count = count_test_emits(function, is_cancelled)?;
    let test_generated_values =
        test_emit_count
            .checked_mul(2)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
    let enters_runtime = entry && plan.image_enter_calls != 0;
    let value_capacity = usize::try_from(first_generated_value)
        .ok()
        .and_then(|count| count.checked_add(return_count))
        .and_then(|count| count.checked_add(test_generated_values))
        .and_then(|count| count.checked_add(usize::from(enters_runtime)))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: limits.model_edges,
        })?;
    let mut values = try_vec(
        value_capacity,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    if entry {
        values.extend([
            MachineValue {
                id: ValueId(0),
                ty: pointer_type,
                source_name: None,
            },
            MachineValue {
                id: ValueId(1),
                ty: pointer_type,
                source_name: None,
            },
        ]);
    }
    for retained in &value_mapping {
        check_cancelled(is_cancelled)?;
        let value = function
            .values
            .get(retained.0 as usize)
            .ok_or(unsupported("an unknown retained FlowWir value"))?;
        values.push(MachineValue {
            id: map_value(*retained, mapping)?,
            ty: if plan.test_payload_index.contains(function.id, value.id) {
                pointer_type
            } else {
                MachineTypeId(value.ty.0)
            },
            source_name: match &value.source_name {
                Some(name) => Some(copy_text(
                    name,
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?),
                None => None,
            },
        });
    }
    let mut next_status = first_generated_value;
    for _ in 0..return_count {
        check_cancelled(is_cancelled)?;
        values.push(MachineValue {
            id: ValueId(next_status),
            ty: status_type,
            source_name: None,
        });
        next_status = next_status
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
    }
    for _ in 0..test_generated_values {
        check_cancelled(is_cancelled)?;
        values.push(MachineValue {
            id: ValueId(next_status),
            ty: status_type,
            source_name: None,
        });
        next_status = next_status
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
    }
    let image_enter_status = if enters_runtime {
        let status = ValueId(next_status);
        values.push(MachineValue {
            id: status,
            ty: status_type,
            source_name: None,
        });
        next_status = next_status
            .checked_add(1)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
        Some(status)
    } else {
        None
    };
    let mut status_cursor = first_generated_value;
    let mut instruction_cursor = 0u32;
    let generated_test_blocks =
        test_emit_count
            .checked_mul(2)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
    let block_capacity = function
        .blocks
        .len()
        .checked_add(generated_test_blocks)
        .and_then(|count| count.checked_add(usize::from(enters_runtime) * 2))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: limits.model_edges,
        })?;
    let mut blocks = try_vec(
        block_capacity,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    let mut generated_blocks = try_vec(
        generated_test_blocks,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    let mut next_block =
        u32::try_from(function.blocks.len()).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: limits.model_edges,
        })?;
    for block in &function.blocks {
        check_cancelled(is_cancelled)?;
        let lowered = lower_block(
            input,
            plan,
            function,
            block,
            mapping,
            entry,
            status_type,
            &mut status_cursor,
            &mut instruction_cursor,
            &mut next_block,
            limits,
            is_cancelled,
        )?;
        blocks.push(lowered.source);
        for generated in lowered.generated {
            check_cancelled(is_cancelled)?;
            generated_blocks.push(generated);
        }
    }
    if generated_blocks.len() != generated_test_blocks {
        return Err(unsupported(
            "a noncanonical generated TestEmit control-flow expansion",
        ));
    }
    for generated in generated_blocks {
        check_cancelled(is_cancelled)?;
        blocks.push(generated);
    }

    let machine_entry = if let Some(status) = image_enter_status {
        if status_cursor != status.0 || next_status != status.0.saturating_add(1) {
            return Err(unsupported(
                "a generated image-entry status allocation that is not canonical",
            ));
        }
        let expected_prologue =
            u32::try_from(blocks.len()).map_err(|_| MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
        if next_block != expected_prologue {
            return Err(unsupported(
                "a noncanonical generated TestEmit block allocation",
            ));
        }
        let prologue_id = BlockId(next_block);
        let failure_id = BlockId(prologue_id.0.checked_add(1).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            },
        )?);

        let mut call_arguments = try_vec(
            2,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        call_arguments.extend([ValueId(0), ValueId(1)]);
        let mut call_results = try_vec(
            1,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        call_results.push(status);
        let mut prologue_instructions = try_vec(
            1,
            "MachineWir instructions",
            limits.instructions,
            is_cancelled,
        )?;
        prologue_instructions.push(MachineInstruction {
            id: take_instruction_id(&mut instruction_cursor)?,
            results: call_results,
            operation: MachineOperation::RuntimeCall {
                intrinsic: RuntimeIntrinsic::ImageEnter,
                arguments: call_arguments,
            },
            source: None,
        });
        let mut success_cases = try_vec(
            1,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        success_cases.push((0, BlockId(function.entry.0), Vec::new()));
        blocks.push(MachineBlock {
            id: prologue_id,
            parameters: Vec::new(),
            instructions: prologue_instructions,
            terminator: MachineTerminator::Switch {
                value: status,
                cases: success_cases,
                default: failure_id,
                default_arguments: Vec::new(),
            },
        });
        let mut failure_return = try_vec(
            1,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        failure_return.push(status);
        blocks.push(MachineBlock {
            id: failure_id,
            parameters: Vec::new(),
            instructions: Vec::new(),
            terminator: MachineTerminator::Return(failure_return),
        });
        prologue_id
    } else {
        BlockId(function.entry.0)
    };

    renumber_instruction_ids(&mut blocks, is_cancelled)?;

    let parameters = if entry {
        let mut parameters = try_vec(
            2,
            "MachineWir model edges",
            limits.model_edges,
            is_cancelled,
        )?;
        parameters.extend([ValueId(0), ValueId(1)]);
        parameters
    } else {
        map_values(
            &function.parameters,
            mapping,
            limits.model_edges,
            is_cancelled,
        )?
    };
    let result = if entry {
        status_type
    } else if let Some(result) = function.result_types.first() {
        MachineTypeId(result.0)
    } else {
        plan.void_type
    };
    let mut proofs = try_vec(
        function.proofs.len(),
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for proof in &function.proofs {
        check_cancelled(is_cancelled)?;
        proofs.push(ProofId(proof.0));
    }
    Ok(MachineFunction {
        id: FunctionId(function.id.0),
        flow_function: function.id.0,
        origin: lower_origin(function.origin),
        role: lower_role(function.role),
        symbol: SymbolId(function.id.0),
        section: SectionId(function.id.0),
        linkage: if entry {
            Linkage::ExportedEntry
        } else {
            Linkage::Private
        },
        convention: if entry {
            CallingConvention::UefiAarch64
        } else {
            CallingConvention::Internal
        },
        parameters,
        result,
        proofs,
        values,
        stack_slots: Vec::new(),
        blocks,
        entry: machine_entry,
        stack_bytes: 0,
        source: function.source,
    })
}

fn lowered_segment_capacity(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instructions: &[flow::Instruction],
    generated_return: bool,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    let mut capacity = 0usize;
    for instruction in instructions {
        check_cancelled(is_cancelled)?;
        let retained = if matches!(instruction.operation, flow::FlowOperation::TestEmit { .. }) {
            2
        } else if matches!(instruction.operation, flow::FlowOperation::Drop { .. })
            || erases_unit_definition(input, function, instruction)?
        {
            0
        } else {
            1
        };
        capacity = capacity
            .checked_add(retained)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit,
            })?;
        if matches!(instruction.operation, flow::FlowOperation::TestEmit { .. }) {
            return Ok(capacity);
        }
    }
    capacity
        .checked_add(usize::from(generated_return))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit,
        })
}

fn take_block_id(cursor: &mut u32, limit: u64) -> Result<BlockId, MachineLowerError> {
    let block = BlockId(*cursor);
    *cursor = cursor
        .checked_add(1)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit,
        })?;
    Ok(block)
}

fn renumber_instruction_ids(
    blocks: &mut [MachineBlock],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut cursor = 0u32;
    for block in blocks {
        check_cancelled(is_cancelled)?;
        for instruction in &mut block.instructions {
            check_cancelled(is_cancelled)?;
            instruction.id = take_instruction_id(&mut cursor)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lower_block(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    function: &flow::FlowFunction,
    block: &flow::Block,
    mapping: ValueMapping<'_>,
    image_entry: bool,
    status_type: MachineTypeId,
    status_cursor: &mut u32,
    instruction_cursor: &mut u32,
    block_cursor: &mut u32,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LoweredBlock, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    let generated_return = image_entry && matches!(block.terminator, flow::Terminator::Return(_));
    let startup_task = (image_entry && block.id == function.entry)
        .then_some(plan.startup_task)
        .flatten();
    let mailbox_dispatch = (image_entry && block.id == function.entry)
        .then_some(plan.actor_dispatch.zip(plan.mailbox_turn))
        .flatten();
    let capacity = lowered_segment_capacity(
        input,
        function,
        &block.instructions,
        generated_return,
        limits.instructions,
        is_cancelled,
    )?
    .checked_add(usize::from(startup_task.is_some()))
    .and_then(|capacity| capacity.checked_add(usize::from(mailbox_dispatch.is_some())))
    .ok_or(MachineLowerError::ResourceLimit {
        resource: "MachineWir instructions",
        limit: limits.instructions,
    })?;
    let mut instructions = try_vec(
        capacity,
        "MachineWir instructions",
        limits.instructions,
        is_cancelled,
    )?;
    let block_emit_count = count_test_emits_in_block(block, is_cancelled)?;
    let generated_capacity =
        block_emit_count
            .checked_mul(2)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: limits.model_edges,
            })?;
    let mut generated = try_vec(
        generated_capacity,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    let mut source = None;
    let mut current_id = BlockId(block.id.0);
    let mut current_parameters =
        map_values(&block.parameters, mapping, limits.model_edges, is_cancelled)?;
    if let Some(task) = startup_task {
        instructions.push(MachineInstruction {
            id: take_instruction_id(instruction_cursor)?,
            results: Vec::new(),
            operation: MachineOperation::Call {
                function: task,
                arguments: Vec::new(),
                convention: CallingConvention::Internal,
            },
            source: None,
        });
    }
    if let Some((dispatch, turn)) = mailbox_dispatch {
        if dispatch.method != turn {
            return Err(unsupported("a substituted one-shot mailbox turn"));
        }
        instructions.push(MachineInstruction {
            id: take_instruction_id(instruction_cursor)?,
            results: Vec::new(),
            operation: MachineOperation::MailboxDispatch {
                mailbox: dispatch.mailbox,
                actor: dispatch.actor,
                method: dispatch.method,
            },
            source: None,
        });
    }
    for (index, instruction) in block.instructions.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if let flow::FlowOperation::TestEmit { payload } = &instruction.operation {
            let payload = plan
                .test_payload_index
                .get(function.id, *payload)
                .and_then(|index| plan.test_payloads.get(index))
                .ok_or(unsupported("an unplanned generated test emission"))?;
            let size = take_generated_value(status_cursor, limits.model_edges)?;
            let status = take_generated_value(status_cursor, limits.model_edges)?;
            let mut size_results = try_vec(
                1,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            size_results.push(size);
            instructions.push(MachineInstruction {
                id: take_instruction_id(instruction_cursor)?,
                results: size_results,
                operation: MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: status_type,
                    bytes_le: copy_bytes(
                        &payload.bytes.to_le_bytes(),
                        limits.payload_bytes,
                        is_cancelled,
                    )?,
                }),
                source: instruction.source,
            });
            let mut arguments = try_vec(
                2,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            arguments.extend([map_value(payload.value, mapping)?, size]);
            let mut results = try_vec(
                1,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            results.push(status);
            instructions.push(MachineInstruction {
                id: take_instruction_id(instruction_cursor)?,
                results,
                operation: MachineOperation::RuntimeCall {
                    intrinsic: RuntimeIntrinsic::TestEmit,
                    arguments,
                },
                source: instruction.source,
            });

            let failure = take_block_id(block_cursor, limits.model_edges)?;
            let success = take_block_id(block_cursor, limits.model_edges)?;
            let mut cases = try_vec(
                1,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            cases.push((0, success, Vec::new()));
            let completed = MachineBlock {
                id: current_id,
                parameters: std::mem::take(&mut current_parameters),
                instructions,
                terminator: MachineTerminator::Switch {
                    value: status,
                    cases,
                    default: failure,
                    default_arguments: Vec::new(),
                },
            };
            if source.is_none() {
                source = Some(completed);
            } else {
                generated.push(completed);
            }
            let mut returned = try_vec(
                1,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            returned.push(status);
            generated.push(MachineBlock {
                id: failure,
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(returned),
            });
            current_id = success;
            let next_capacity = lowered_segment_capacity(
                input,
                function,
                &block.instructions[index + 1..],
                generated_return,
                limits.instructions,
                is_cancelled,
            )?;
            instructions = try_vec(
                next_capacity,
                "MachineWir instructions",
                limits.instructions,
                is_cancelled,
            )?;
            continue;
        }
        if let Some(operation) = lower_operation(
            input,
            plan,
            function,
            instruction,
            mapping,
            limits,
            is_cancelled,
        )? {
            instructions.push(MachineInstruction {
                id: take_instruction_id(instruction_cursor)?,
                results: map_values(
                    &instruction.results,
                    mapping,
                    limits.model_edges,
                    is_cancelled,
                )?,
                operation,
                source: instruction.source,
            });
        } else if !instruction.results.is_empty()
            && !erases_unit_definition(input, function, instruction)?
        {
            return Err(unsupported("an erased non-unit operation with results"));
        }
    }
    let terminator = if image_entry {
        match &block.terminator {
            flow::Terminator::Return(values) => {
                if !values.is_empty() {
                    return Err(unsupported("an image entry return value"));
                }
                let status = ValueId(*status_cursor);
                *status_cursor =
                    status_cursor
                        .checked_add(1)
                        .ok_or(MachineLowerError::ResourceLimit {
                            resource: "MachineWir model edges",
                            limit: limits.model_edges,
                        })?;
                let mut bytes = try_vec(
                    8,
                    "MachineWir payload bytes",
                    limits.payload_bytes,
                    is_cancelled,
                )?;
                bytes.resize(8, 0);
                let mut results = try_vec(
                    1,
                    "MachineWir model edges",
                    limits.model_edges,
                    is_cancelled,
                )?;
                results.push(status);
                instructions.push(MachineInstruction {
                    id: take_instruction_id(instruction_cursor)?,
                    results,
                    operation: MachineOperation::Immediate(MachineImmediate::Integer {
                        ty: status_type,
                        bytes_le: bytes,
                    }),
                    source: block.source,
                });
                let mut returned = try_vec(
                    1,
                    "MachineWir model edges",
                    limits.model_edges,
                    is_cancelled,
                )?;
                returned.push(status);
                MachineTerminator::Return(returned)
            }
            flow::Terminator::TailCall { .. } => {
                return Err(unsupported("a tail call from the UEFI image entry"));
            }
            other => lower_terminator(input, plan, function, other, mapping, limits, is_cancelled)?,
        }
    } else {
        lower_terminator(
            input,
            plan,
            function,
            &block.terminator,
            mapping,
            limits,
            is_cancelled,
        )?
    };
    let completed = MachineBlock {
        id: current_id,
        parameters: current_parameters,
        instructions,
        terminator,
    };
    let source = if let Some(source) = source {
        generated.push(completed);
        source
    } else {
        completed
    };
    if generated.len() != generated_capacity {
        return Err(unsupported(
            "a noncanonical generated TestEmit block expansion",
        ));
    }
    Ok(LoweredBlock { source, generated })
}

fn lower_operation(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    mapping: ValueMapping<'_>,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<MachineOperation>, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    if erases_unit_definition(input, function, instruction)? {
        return Ok(None);
    }
    let operation = match &instruction.operation {
        flow::FlowOperation::Immediate(flow::Immediate::Bytes(_)) => {
            let result = require_single_result(instruction)?;
            let payload = plan
                .test_payload_index
                .get(function.id, result)
                .and_then(|index| plan.test_payloads.get(index))
                .ok_or(unsupported("an unplanned static test payload"))?;
            MachineOperation::GlobalAddress(payload.global)
        }
        flow::FlowOperation::Immediate(immediate) => MachineOperation::Immediate(lower_immediate(
            input,
            function,
            instruction,
            immediate,
            limits,
            is_cancelled,
        )?),
        flow::FlowOperation::Binary { op, left, right } => {
            lower_binary(input, function, instruction, *op, *left, *right, mapping)?
        }
        flow::FlowOperation::Unary { op, value } => MachineOperation::Unary {
            op: lower_scalar_unary(input, function, instruction, *op, *value)?,
            value: map_value(*value, mapping)?,
        },
        flow::FlowOperation::Cast { value, to, mode } => {
            match lower_scalar_conversion(input, function, instruction, *value, *to, *mode)? {
                LoweredScalarConversion::Exact(op) => MachineOperation::Convert {
                    op,
                    value: map_value(*value, mapping)?,
                    destination: MachineTypeId(to.0),
                },
                LoweredScalarConversion::Checked {
                    source,
                    destination,
                } => MachineOperation::CheckedConvert {
                    source,
                    destination_kind: destination,
                    value: map_value(*value, mapping)?,
                    destination: MachineTypeId(to.0),
                    failure: scalar_failure(ScalarFailureKind::Conversion, function, instruction),
                },
            }
        }
        flow::FlowOperation::MakeAggregate { ty, fields } => {
            let result = require_single_result(instruction)?;
            let [field] = fields.as_slice() else {
                return Err(unsupported(
                    "an aggregate constructor without exactly one field value",
                ));
            };
            if value_type(function, result)? != MachineTypeId(ty.0)
                || flat_u64_struct_field(&input.types, *ty)
                    != Some(flow_value_type(function, *field)?)
            {
                return Err(unsupported(
                    "an aggregate constructor outside flat u64 lowering",
                ));
            }
            MachineOperation::Convert {
                op: ConversionOp::Bitcast,
                value: map_value(*field, mapping)?,
                destination: MachineTypeId(ty.0),
            }
        }
        flow::FlowOperation::InsertField {
            aggregate,
            field,
            value,
        } => {
            let result = require_single_result(instruction)?;
            let aggregate_type = validate_flat_structure_field_update(
                &input.types,
                function,
                result,
                *aggregate,
                *field,
                *value,
            )?;
            MachineOperation::Convert {
                op: ConversionOp::Bitcast,
                value: map_value(*value, mapping)?,
                destination: MachineTypeId(aggregate_type.0),
            }
        }
        flow::FlowOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => MachineOperation::MakeEnum {
            ty: MachineTypeId(ty.0),
            variant: *variant,
            payload: map_value(*payload, mapping)?,
        },
        flow::FlowOperation::EnumTag { value } => MachineOperation::EnumTag {
            value: map_value(*value, mapping)?,
        },
        flow::FlowOperation::EnumPayload { value } => MachineOperation::EnumPayload {
            value: map_value(*value, mapping)?,
        },
        flow::FlowOperation::ExtractField { aggregate, field } => {
            let result = require_single_result(instruction)?;
            let aggregate_type = flow_value_type(function, *aggregate)?;
            if *field != 0
                || flat_u64_struct_field(&input.types, aggregate_type)
                    != Some(flow_value_type(function, result)?)
            {
                return Err(unsupported("a field extraction outside flat u64 lowering"));
            }
            MachineOperation::Convert {
                op: ConversionOp::Bitcast,
                value: map_value(*aggregate, mapping)?,
                destination: value_type(function, result)?,
            }
        }
        flow::FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            require_single_result(instruction)?;
            MachineOperation::Select {
                condition: map_value(*condition, mapping)?,
                then_value: map_value(*then_value, mapping)?,
                else_value: map_value(*else_value, mapping)?,
            }
        }
        flow::FlowOperation::Load { address, proof } => {
            let result = require_single_result(instruction)?;
            MachineOperation::Load {
                address: map_value(*address, mapping)?,
                ty: value_type(function, result)?,
                semantics: MemorySemantics::Ordinary,
                facts: conservative_facts(*proof),
            }
        }
        flow::FlowOperation::Store {
            address,
            value,
            proof,
        } => {
            require_no_results(instruction)?;
            MachineOperation::Store {
                address: map_value(*address, mapping)?,
                value: map_value(*value, mapping)?,
                semantics: MemorySemantics::Ordinary,
                facts: conservative_facts(*proof),
            }
        }
        flow::FlowOperation::Move { value } | flow::FlowOperation::Copy { value } => {
            let result = require_single_result(instruction)?;
            MachineOperation::Convert {
                op: ConversionOp::Bitcast,
                value: map_value(*value, mapping)?,
                destination: value_type(function, result)?,
            }
        }
        flow::FlowOperation::Drop { .. } => {
            require_no_results(instruction)?;
            return Ok(None);
        }
        flow::FlowOperation::Call {
            function: callee,
            arguments,
        } => {
            if *callee == input.image_entry {
                return Err(unsupported("a direct call to the UEFI image entry"));
            }
            if instruction.results.len() > 1 {
                return Err(unsupported("a call with multiple results"));
            }
            MachineOperation::Call {
                function: FunctionId(callee.0),
                arguments: map_values(arguments, mapping, limits.model_edges, is_cancelled)?,
                convention: CallingConvention::Internal,
            }
        }
        flow::FlowOperation::ActorCapability { actor, proof } => {
            let result = require_single_result(instruction)?;
            if input
                .types
                .get(flow_value_type(function, result)?.0 as usize)
                .is_none_or(|ty| ty.kind != flow::FlowTypeKind::ActorHandle(*actor))
                || input.proofs.get(proof.0 as usize).is_none_or(|record| {
                    record.kind != flow::ProofKind::ActorAsIf
                        || record.bound != Some(1)
                        || record.sources.len() != 1
                        || !record.depends_on.is_empty()
                })
            {
                return Err(unsupported("a substituted image-wired actor capability"));
            }
            MachineOperation::Immediate(MachineImmediate::Integer {
                ty: value_type(function, result)?,
                bytes_le: u64::from(actor.0).to_le_bytes().to_vec(),
            })
        }
        flow::FlowOperation::ActorReserve {
            actor,
            method,
            proof,
        } => {
            require_single_result(instruction)?;
            let dispatch = plan
                .actor_dispatch
                .filter(|dispatch| {
                    dispatch.producer.0 == function.id.0
                        && dispatch.actor == actor.0
                        && dispatch.method.0 == method.0
                        && dispatch.permit.0 == proof.0
                })
                .ok_or(unsupported("a substituted machine actor reservation"))?;
            MachineOperation::ActorReserve {
                mailbox: dispatch.mailbox,
                actor: dispatch.actor,
                method: dispatch.method,
                proof: dispatch.permit,
                failure: scalar_failure(ScalarFailureKind::ActorMailboxFull, function, instruction),
            }
        }
        flow::FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            require_no_results(instruction)?;
            let dispatch = plan
                .actor_dispatch
                .filter(|dispatch| dispatch.producer.0 == function.id.0 && arguments.is_empty())
                .ok_or(unsupported("a substituted machine actor commit"))?;
            MachineOperation::ActorCommit {
                reservation: map_value(*reservation, mapping)?,
                mailbox: dispatch.mailbox,
                actor: dispatch.actor,
                method: dispatch.method,
            }
        }
        flow::FlowOperation::MailboxReceive { actor, method } => {
            require_no_results(instruction)?;
            let dispatch = plan
                .actor_dispatch
                .filter(|dispatch| {
                    dispatch.method.0 == function.id.0
                        && dispatch.actor == actor.0
                        && dispatch.method.0 == method.0
                })
                .ok_or(unsupported("a substituted machine mailbox receive"))?;
            MachineOperation::MailboxReceive {
                mailbox: dispatch.mailbox,
                actor: dispatch.actor,
                method: dispatch.method,
                failure: scalar_failure(
                    ScalarFailureKind::ActorMailboxMismatch,
                    function,
                    instruction,
                ),
            }
        }
        flow::FlowOperation::AsyncCall {
            function: callee,
            arguments,
            plan: activation,
        } => {
            let supported = plan.activations.iter().any(|plan| {
                plan.id.0 == activation.0
                    && plan.caller.0 == function.id.0
                    && plan.callee.0 == callee.0
                    && plan.call_instruction.0 == instruction.id.0
            });
            if !supported
                || !instruction
                    .results
                    .iter()
                    .all(|result| mapped_value(*result, mapping).ok().flatten().is_none())
            {
                return Err(unsupported(
                    "an asynchronous call outside immediate activation lowering",
                ));
            }
            MachineOperation::Call {
                function: FunctionId(callee.0),
                arguments: map_values(arguments, mapping, limits.model_edges, is_cancelled)?,
                convention: CallingConvention::Internal,
            }
        }
        flow::FlowOperation::Fence { kind } => {
            require_no_results(instruction)?;
            MachineOperation::Fence(match kind {
                flow::FenceKind::Acquire => MachineFence::Acquire,
                flow::FenceKind::Release => MachineFence::Release,
                flow::FenceKind::AcquireRelease => MachineFence::AcquireRelease,
                flow::FenceKind::DeviceRead => MachineFence::DeviceRead,
                flow::FenceKind::DeviceWrite => MachineFence::DeviceWrite,
                flow::FenceKind::DeviceFull => MachineFence::DeviceFull,
            })
        }
        flow::FlowOperation::TestFinish { outcome } => {
            require_no_results(instruction)?;
            let mut arguments = try_vec(
                1,
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            arguments.push(map_value(*outcome, mapping)?);
            MachineOperation::RuntimeCall {
                intrinsic: RuntimeIntrinsic::TestFinish,
                arguments,
            }
        }
        flow::FlowOperation::Assert { condition, failure } => {
            require_no_results(instruction)?;
            let expression_global = plan
                .assertion_payload(function.id, instruction.id, false)
                .map(|payload| payload.global)
                .ok_or(unsupported(
                    "an assertion without sealed expression storage",
                ))?;
            let message_global = if failure.message.is_some() {
                Some(
                    plan.assertion_payload(function.id, instruction.id, true)
                        .map(|payload| payload.global)
                        .ok_or(unsupported("an assertion without sealed message storage"))?,
                )
            } else {
                None
            };
            MachineOperation::TestAssert {
                condition: map_value(*condition, mapping)?,
                failure: MachineAssertionFailure {
                    expression: copy_text(
                        &failure.expression,
                        "MachineWir payload bytes",
                        limits.payload_bytes,
                        is_cancelled,
                    )?,
                    expression_global,
                    message: match &failure.message {
                        Some(message) => Some(copy_text(
                            message,
                            "MachineWir payload bytes",
                            limits.payload_bytes,
                            is_cancelled,
                        )?),
                        None => None,
                    },
                    message_global,
                    source: failure.source,
                },
            }
        }
        flow::FlowOperation::TestEmit { .. } => {
            return Err(unsupported("a test emission outside block expansion"));
        }
        _ => return Err(unsupported("an operation outside scalar lowering")),
    };
    Ok(Some(operation))
}

fn validate_flat_structure_field_update(
    types: &[flow::FlowType],
    function: &flow::FlowFunction,
    result: flow::ValueId,
    aggregate: flow::ValueId,
    field: u32,
    value: flow::ValueId,
) -> Result<flow::TypeId, MachineLowerError> {
    let aggregate_type = flow_value_type(function, aggregate)?;
    if field != 0
        || flat_u64_struct_field(types, aggregate_type) != Some(flow_value_type(function, value)?)
        || flow_value_type(function, result)? != aggregate_type
    {
        return Err(unsupported(
            "machine-flat-structure-field-update-lowering-pending",
        ));
    }
    Ok(aggregate_type)
}

fn lower_immediate(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    immediate: &flow::Immediate,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineImmediate, MachineLowerError> {
    let result = require_single_result(instruction)?;
    let result_type = value_type(function, result)?;
    let result_flow_type = input
        .types
        .get(result_type.0 as usize)
        .ok_or(unsupported("an immediate with an unknown result type"))?;
    match immediate {
        flow::Immediate::Bool(value) => {
            if result_flow_type.kind != flow::FlowTypeKind::Scalar(flow::ScalarType::Bool) {
                return Err(unsupported("a bool immediate with a non-bool result"));
            }
            let mut bytes = try_vec(
                1,
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?;
            bytes.push(u8::from(*value));
            Ok(MachineImmediate::Integer {
                ty: result_type,
                bytes_le: bytes,
            })
        }
        flow::Immediate::Integer { bits, bytes_le } => {
            if !matches!(
                result_flow_type.kind,
                flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { bits: expected, .. })
                    if expected == *bits
            ) {
                return Err(unsupported(
                    "an integer immediate whose width differs from its result",
                ));
            }
            Ok(MachineImmediate::Integer {
                ty: result_type,
                bytes_le: copy_bytes(bytes_le, limits.payload_bytes, is_cancelled)?,
            })
        }
        flow::Immediate::Float32(bits) => {
            if result_flow_type.kind != flow::FlowTypeKind::Scalar(flow::ScalarType::Float32) {
                return Err(unsupported(
                    "a float32 immediate with a different result type",
                ));
            }
            Ok(MachineImmediate::Float32(*bits))
        }
        flow::Immediate::Float64(bits) => {
            if result_flow_type.kind != flow::FlowTypeKind::Scalar(flow::ScalarType::Float64) {
                return Err(unsupported(
                    "a float64 immediate with a different result type",
                ));
            }
            Ok(MachineImmediate::Float64(*bits))
        }
        flow::Immediate::Bytes(bytes) => Ok(MachineImmediate::Bytes(copy_bytes(
            bytes,
            limits.payload_bytes,
            is_cancelled,
        )?)),
        flow::Immediate::Zero(ty) if result_type == MachineTypeId(ty.0) => {
            Ok(MachineImmediate::Zero(result_type))
        }
        flow::Immediate::FunctionAddress(function) => {
            if result_flow_type.kind != flow::FlowTypeKind::Scalar(flow::ScalarType::Address) {
                return Err(unsupported(
                    "a function-address immediate with a non-address result",
                ));
            }
            Ok(MachineImmediate::SymbolAddress(SymbolId(function.0)))
        }
        flow::Immediate::Unit | flow::Immediate::Zero(_) | flow::Immediate::GlobalAddress(_) => {
            Err(unsupported("an immediate outside scalar lowering"))
        }
    }
}

fn lower_binary(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
    op: flow::BinaryOp,
    left: flow::ValueId,
    right: flow::ValueId,
    mapping: ValueMapping<'_>,
) -> Result<MachineOperation, MachineLowerError> {
    let result = require_single_result(instruction)?;
    let left_type = flow_value_type(function, left)?;
    if flow_value_type(function, right)? != left_type {
        return Err(unsupported(
            "a binary operation with differing operand types",
        ));
    }
    let kind = &input
        .types
        .get(left_type.0 as usize)
        .ok_or(unsupported("a binary operation with an unknown type"))?
        .kind;
    let left = map_value(left, mapping)?;
    let right = map_value(right, mapping)?;
    match op {
        flow::BinaryOp::AddChecked
        | flow::BinaryOp::SubChecked
        | flow::BinaryOp::MulChecked
        | flow::BinaryOp::DivChecked
        | flow::BinaryOp::RemChecked
        | flow::BinaryOp::ShiftLeftChecked
        | flow::BinaryOp::ShiftLeftWrapping
        | flow::BinaryOp::ShiftRightChecked => {
            let flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { signed, .. }) = kind else {
                return Err(unsupported(
                    "a checked integer operation on a non-integer type",
                ));
            };
            if value_type(function, result)? != MachineTypeId(left_type.0) {
                return Err(unsupported(
                    "a checked integer operation with a mismatched result type",
                ));
            }
            Ok(MachineOperation::CheckedInteger {
                op: match op {
                    flow::BinaryOp::AddChecked => CheckedIntegerOp::Add,
                    flow::BinaryOp::SubChecked => CheckedIntegerOp::Subtract,
                    flow::BinaryOp::MulChecked => CheckedIntegerOp::Multiply,
                    flow::BinaryOp::DivChecked => CheckedIntegerOp::Divide,
                    flow::BinaryOp::RemChecked => CheckedIntegerOp::Remainder,
                    flow::BinaryOp::ShiftLeftChecked => CheckedIntegerOp::ShiftLeft,
                    flow::BinaryOp::ShiftLeftWrapping => CheckedIntegerOp::ShiftLeftWrapping,
                    flow::BinaryOp::ShiftRightChecked => CheckedIntegerOp::ShiftRight,
                    _ => return Err(unsupported("a non-checked integer operation")),
                },
                signedness: if *signed {
                    IntegerSignedness::Signed
                } else {
                    IntegerSignedness::Unsigned
                },
                left,
                right,
                failure: scalar_failure(ScalarFailureKind::Arithmetic, function, instruction),
            })
        }
        flow::BinaryOp::AddWrapping
        | flow::BinaryOp::SubWrapping
        | flow::BinaryOp::MulWrapping
        | flow::BinaryOp::BitAnd
        | flow::BinaryOp::BitOr
        | flow::BinaryOp::BitXor => {
            if !matches!(
                kind,
                flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { .. })
            ) || value_type(function, result)? != MachineTypeId(left_type.0)
            {
                return Err(unsupported("a wrapping operation on a non-integer type"));
            }
            let operation = match op {
                flow::BinaryOp::AddWrapping => ArithmeticOp::IntegerAdd,
                flow::BinaryOp::SubWrapping => ArithmeticOp::IntegerSubtract,
                flow::BinaryOp::MulWrapping => ArithmeticOp::IntegerMultiply,
                flow::BinaryOp::BitAnd => ArithmeticOp::BitAnd,
                flow::BinaryOp::BitOr => ArithmeticOp::BitOr,
                flow::BinaryOp::BitXor => ArithmeticOp::BitXor,
                _ => return Err(unsupported("a non-wrapping arithmetic operation")),
            };
            Ok(MachineOperation::Arithmetic {
                op: operation,
                left,
                right,
            })
        }
        flow::BinaryOp::Equal
        | flow::BinaryOp::NotEqual
        | flow::BinaryOp::Less
        | flow::BinaryOp::LessEqual
        | flow::BinaryOp::Greater
        | flow::BinaryOp::GreaterEqual => {
            if !matches!(
                input
                    .types
                    .get(value_type(function, result)?.0 as usize)
                    .map(|ty| &ty.kind),
                Some(flow::FlowTypeKind::Scalar(flow::ScalarType::Bool))
            ) {
                return Err(unsupported("a comparison with a non-bool result"));
            }
            match kind {
                flow::FlowTypeKind::Scalar(
                    flow::ScalarType::Float32 | flow::ScalarType::Float64,
                ) => Ok(MachineOperation::FloatCompare {
                    predicate: match op {
                        flow::BinaryOp::Equal => FloatPredicate::OrderedEqual,
                        flow::BinaryOp::NotEqual => FloatPredicate::UnorderedNotEqual,
                        flow::BinaryOp::Less => FloatPredicate::OrderedLess,
                        flow::BinaryOp::LessEqual => FloatPredicate::OrderedLessEqual,
                        flow::BinaryOp::Greater => FloatPredicate::OrderedGreater,
                        flow::BinaryOp::GreaterEqual => FloatPredicate::OrderedGreaterEqual,
                        _ => return Err(unsupported("a non-comparison floating operation")),
                    },
                    left,
                    right,
                }),
                flow::FlowTypeKind::Scalar(flow::ScalarType::Bool) => {
                    Ok(MachineOperation::IntegerCompare {
                        predicate: unsigned_predicate(op)?,
                        left,
                        right,
                    })
                }
                flow::FlowTypeKind::Scalar(flow::ScalarType::Integer { signed, .. }) => {
                    Ok(MachineOperation::IntegerCompare {
                        predicate: if *signed {
                            signed_predicate(op)?
                        } else {
                            unsigned_predicate(op)?
                        },
                        left,
                        right,
                    })
                }
                _ => Err(unsupported("a comparison on a non-scalar value")),
            }
        }
    }
}

fn scalar_failure(
    kind: ScalarFailureKind,
    function: &flow::FlowFunction,
    instruction: &flow::Instruction,
) -> ScalarFailureProvenance {
    ScalarFailureProvenance {
        kind,
        flow_function: function.id.0,
        flow_instruction: instruction.id.0,
    }
}

fn lower_terminator(
    input: &flow::FlowWir,
    plan: &ScalarPlan,
    function: &flow::FlowFunction,
    terminator: &flow::Terminator,
    mapping: ValueMapping<'_>,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineTerminator, MachineLowerError> {
    match terminator {
        flow::Terminator::Jump { target, arguments } => Ok(MachineTerminator::Jump {
            block: BlockId(target.0),
            arguments: map_values(arguments, mapping, limits.model_edges, is_cancelled)?,
        }),
        flow::Terminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => Ok(MachineTerminator::Branch {
            condition: map_value(*condition, mapping)?,
            then_block: BlockId(then_block.0),
            then_arguments: map_values(then_arguments, mapping, limits.model_edges, is_cancelled)?,
            else_block: BlockId(else_block.0),
            else_arguments: map_values(else_arguments, mapping, limits.model_edges, is_cancelled)?,
        }),
        flow::Terminator::Switch {
            value,
            cases,
            default,
            default_arguments,
        } => {
            let mut lowered_cases = try_vec(
                cases.len(),
                "MachineWir model edges",
                limits.model_edges,
                is_cancelled,
            )?;
            for case in cases {
                check_cancelled(is_cancelled)?;
                lowered_cases.push((
                    case.value,
                    BlockId(case.target.0),
                    map_values(&case.arguments, mapping, limits.model_edges, is_cancelled)?,
                ));
            }
            Ok(MachineTerminator::Switch {
                value: map_value(*value, mapping)?,
                cases: lowered_cases,
                default: BlockId(default.0),
                default_arguments: map_values(
                    default_arguments,
                    mapping,
                    limits.model_edges,
                    is_cancelled,
                )?,
            })
        }
        flow::Terminator::Return(values) => Ok(MachineTerminator::Return(map_values(
            values,
            mapping,
            limits.model_edges,
            is_cancelled,
        )?)),
        flow::Terminator::TailCall {
            function: callee,
            arguments,
        } => {
            if *callee == input.image_entry || function.id == input.image_entry {
                return Err(unsupported("a tail call involving the UEFI image entry"));
            }
            if input
                .functions
                .get(callee.0 as usize)
                .is_none_or(|callee| callee.color != flow::FunctionColor::Sync)
            {
                return Err(unsupported(
                    "a scalar tail call without an exact synchronous callee",
                ));
            }
            Ok(MachineTerminator::TailCall {
                function: FunctionId(callee.0),
                arguments: map_values(arguments, mapping, limits.model_edges, is_cancelled)?,
            })
        }
        flow::Terminator::Suspend {
            state,
            activation,
            resume,
        } if plan.activations.iter().any(|plan| {
            plan.caller.0 == function.id.0
                && plan.state == *state
                && plan.resume_block.0 == resume.0
                && mapped_value(*activation, mapping).ok().flatten().is_none()
        }) =>
        {
            Ok(MachineTerminator::Jump {
                block: BlockId(resume.0),
                arguments: Vec::new(),
            })
        }
        flow::Terminator::Suspend { .. } | flow::Terminator::Trap { .. } => {
            Err(unsupported("suspending or trapping scalar control flow"))
        }
        flow::Terminator::Unreachable => Ok(MachineTerminator::Unreachable),
    }
}

fn conservative_facts(proof: flow::ProofId) -> BackendFacts {
    BackendFacts {
        proof: ProofId(proof.0),
        alignment: None,
        non_null: false,
        no_alias: false,
        in_bounds: false,
        no_unsigned_wrap: false,
        no_signed_wrap: false,
    }
}

fn target_layout() -> DataLayout {
    DataLayout {
        pointer_bits: 64,
        pointer_alignment: 8,
        stack_alignment: 16,
        aggregate_alignment: 8,
        maximum_object_alignment: 16,
        endianness: Endianness::Little,
    }
}

fn lower_role(role: flow::FunctionRole) -> MachineFunctionRole {
    match role {
        flow::FunctionRole::Ordinary => MachineFunctionRole::Ordinary,
        flow::FunctionRole::ActorTurn(id) => MachineFunctionRole::ActorTurn(id.0),
        flow::FunctionRole::TaskEntry(id) => MachineFunctionRole::TaskEntry(id.0),
        flow::FunctionRole::Isr(id) => MachineFunctionRole::Isr(id.0),
        flow::FunctionRole::Cleanup => MachineFunctionRole::Cleanup,
        flow::FunctionRole::ImageEntry => MachineFunctionRole::ImageEntry,
        flow::FunctionRole::Test => MachineFunctionRole::Test,
    }
}

fn lower_origin(origin: flow::FunctionOrigin) -> MachineFunctionOrigin {
    match origin {
        flow::FunctionOrigin::SourceSemantic { semantic_function } => {
            MachineFunctionOrigin::SourceSemantic { semantic_function }
        }
        flow::FunctionOrigin::GeneratedImageEntry {
            semantic_function,
            constructor,
        } => MachineFunctionOrigin::GeneratedImageEntry {
            semantic_function,
            constructor,
        },
        flow::FunctionOrigin::GeneratedTestHarness {
            semantic_function,
            group,
        } => MachineFunctionOrigin::GeneratedTestHarness {
            semantic_function,
            group,
        },
        flow::FunctionOrigin::GeneratedAsyncState {
            semantic_function,
            state,
        } => MachineFunctionOrigin::GeneratedAsyncState {
            semantic_function,
            state,
        },
        flow::FunctionOrigin::GeneratedCleanup {
            semantic_function,
            scope,
        } => MachineFunctionOrigin::GeneratedCleanup {
            semantic_function,
            scope,
        },
    }
}

fn find_void_type(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineTypeId, MachineLowerError> {
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        if ty.kind == flow::FlowTypeKind::Unit {
            return Ok(MachineTypeId(ty.id.0));
        }
    }
    Err(unsupported("a function returning unit without a unit type"))
}

fn flow_value_type(
    function: &flow::FlowFunction,
    value: flow::ValueId,
) -> Result<flow::TypeId, MachineLowerError> {
    function
        .values
        .get(value.0 as usize)
        .map(|value| value.ty)
        .ok_or(unsupported("an unknown FlowWir value"))
}

fn value_type(
    function: &flow::FlowFunction,
    value: flow::ValueId,
) -> Result<MachineTypeId, MachineLowerError> {
    flow_value_type(function, value).map(|ty| MachineTypeId(ty.0))
}

fn flow_type_is_unit(input: &flow::FlowWir, ty: flow::TypeId) -> Result<bool, MachineLowerError> {
    flow_type_is_unit_in(&input.types, ty)
}

fn flow_type_is_unit_in(
    types: &[flow::FlowType],
    ty: flow::TypeId,
) -> Result<bool, MachineLowerError> {
    types
        .get(ty.0 as usize)
        .map(|ty| ty.kind == flow::FlowTypeKind::Unit)
        .ok_or(unsupported("an unknown FlowWir value type"))
}

fn flow_type_is_erased_in(
    types: &[flow::FlowType],
    ty: flow::TypeId,
) -> Result<bool, MachineLowerError> {
    types
        .get(ty.0 as usize)
        .map(|ty| match &ty.kind {
            flow::FlowTypeKind::Unit | flow::FlowTypeKind::Activation { .. } => true,
            flow::FlowTypeKind::Struct { fields } => fields.is_empty(),
            _ => false,
        })
        .ok_or(unsupported("an unknown FlowWir value type"))
}

fn flow_value_is_unit(
    input: &flow::FlowWir,
    function: &flow::FlowFunction,
    value: flow::ValueId,
) -> Result<bool, MachineLowerError> {
    flow_type_is_unit(input, flow_value_type(function, value)?)
}

fn build_value_mapping(
    types: &[flow::FlowType],
    function: &flow::FlowFunction,
    first: u32,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<flow::ValueId>, u32), MachineLowerError> {
    let mut retained_count = 0usize;
    for value in &function.values {
        check_cancelled(is_cancelled)?;
        if !flow_type_is_erased_in(types, value.ty)? {
            retained_count =
                retained_count
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit,
                    })?;
        }
    }
    let retained = u32::try_from(retained_count).map_err(|_| MachineLowerError::ResourceLimit {
        resource: "MachineWir model edges",
        limit,
    })?;
    let next = first
        .checked_add(retained)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit,
        })?;
    let mut mapping = try_vec(
        retained_count,
        "MachineWir retained value mapping entries",
        limit,
        is_cancelled,
    )?;
    for value in &function.values {
        check_cancelled(is_cancelled)?;
        if !flow_type_is_erased_in(types, value.ty)? {
            mapping.push(value.id);
        }
    }
    Ok((mapping, next))
}

fn require_single_result(
    instruction: &flow::Instruction,
) -> Result<flow::ValueId, MachineLowerError> {
    let [result] = instruction.results.as_slice() else {
        return Err(unsupported("an operation without exactly one result"));
    };
    Ok(*result)
}

fn require_no_results(instruction: &flow::Instruction) -> Result<(), MachineLowerError> {
    if instruction.results.is_empty() {
        Ok(())
    } else {
        Err(unsupported("a result-bearing side-effect operation"))
    }
}

fn map_value(
    value: flow::ValueId,
    mapping: ValueMapping<'_>,
) -> Result<ValueId, MachineLowerError> {
    mapped_value(value, mapping)?.ok_or(unsupported(
        "an erased zero-sized value in a retained MachineWir operation",
    ))
}

fn mapped_value(
    value: flow::ValueId,
    mapping: ValueMapping<'_>,
) -> Result<Option<ValueId>, MachineLowerError> {
    match mapping {
        ValueMapping::DenseShift(shift) => value.0.checked_add(shift).map(ValueId).map(Some).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: u64::from(u32::MAX),
            },
        ),
        ValueMapping::Canonical {
            retained,
            value_count,
            first,
        } => {
            if value.0 as usize >= value_count {
                return Err(unsupported("an unknown FlowWir value during value erasure"));
            }
            let Ok(index) = retained.binary_search_by_key(&value.0, |candidate| candidate.0) else {
                return Ok(None);
            };
            let index = u32::try_from(index).map_err(|_| MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: u64::from(u32::MAX),
            })?;
            first.checked_add(index).map(ValueId).map(Some).ok_or(
                MachineLowerError::ResourceLimit {
                    resource: "MachineWir model edges",
                    limit: u64::from(u32::MAX),
                },
            )
        }
    }
}

fn map_values(
    values: &[flow::ValueId],
    mapping: ValueMapping<'_>,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ValueId>, MachineLowerError> {
    let mut retained_count = 0usize;
    for value in values {
        check_cancelled(is_cancelled)?;
        if mapped_value(*value, mapping)?.is_some() {
            retained_count =
                retained_count
                    .checked_add(1)
                    .ok_or(MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit,
                    })?;
        }
    }
    let mut output = try_vec(
        retained_count,
        "MachineWir model edges",
        limit,
        is_cancelled,
    )?;
    for value in values {
        check_cancelled(is_cancelled)?;
        if let Some(value) = mapped_value(*value, mapping)? {
            output.push(value);
        }
    }
    Ok(output)
}

fn take_instruction_id(cursor: &mut u32) -> Result<InstructionId, MachineLowerError> {
    let id = *cursor;
    *cursor = cursor
        .checked_add(1)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: u64::from(u32::MAX),
        })?;
    Ok(InstructionId(id))
}

fn take_generated_value(cursor: &mut u32, limit: u64) -> Result<ValueId, MachineLowerError> {
    let value = ValueId(*cursor);
    *cursor = cursor
        .checked_add(1)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit,
        })?;
    Ok(value)
}

fn copy_bytes(
    bytes: &[u8],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, MachineLowerError> {
    let mut output = try_vec(bytes.len(), "MachineWir payload bytes", limit, is_cancelled)?;
    for chunk in bytes.chunks(CANCELLABLE_COPY_CHUNK_BYTES) {
        check_cancelled(is_cancelled)?;
        output.extend_from_slice(chunk);
    }
    check_cancelled(is_cancelled)?;
    Ok(output)
}

fn numbered_text(
    prefix: &str,
    number: u32,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, MachineLowerError> {
    let mut digits = [0u8; 10];
    let mut cursor = digits.len();
    let mut remaining = number;
    loop {
        cursor -= 1;
        let digit = u8::try_from(remaining % 10)
            .map_err(|_| unsupported("an invalid generated decimal digit"))?;
        digits[cursor] = b'0' + digit;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let suffix = std::str::from_utf8(&digits[cursor..])
        .map_err(|_| unsupported("a non-UTF-8 generated identifier"))?;
    prefixed_text(prefix, suffix, limit, is_cancelled)
}

fn prefixed_text(
    prefix: &str,
    suffix: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    let capacity =
        prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir payload bytes",
                limit,
            })?;
    check_resource(
        "MachineWir payload bytes",
        count_u64(capacity, "MachineWir payload bytes", limit)?,
        limit,
    )?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir payload bytes",
            limit,
        })?;
    check_cancelled(is_cancelled)?;
    push_text_chunks(&mut output, prefix, is_cancelled)?;
    push_text_chunks(&mut output, suffix, is_cancelled)?;
    Ok(output)
}

fn signed_predicate(op: flow::BinaryOp) -> Result<IntegerPredicate, MachineLowerError> {
    Ok(match op {
        flow::BinaryOp::Equal => IntegerPredicate::Equal,
        flow::BinaryOp::NotEqual => IntegerPredicate::NotEqual,
        flow::BinaryOp::Less => IntegerPredicate::SignedLess,
        flow::BinaryOp::LessEqual => IntegerPredicate::SignedLessEqual,
        flow::BinaryOp::Greater => IntegerPredicate::SignedGreater,
        flow::BinaryOp::GreaterEqual => IntegerPredicate::SignedGreaterEqual,
        _ => return Err(unsupported("a non-comparison signed operation")),
    })
}

fn unsigned_predicate(op: flow::BinaryOp) -> Result<IntegerPredicate, MachineLowerError> {
    Ok(match op {
        flow::BinaryOp::Equal => IntegerPredicate::Equal,
        flow::BinaryOp::NotEqual => IntegerPredicate::NotEqual,
        flow::BinaryOp::Less => IntegerPredicate::UnsignedLess,
        flow::BinaryOp::LessEqual => IntegerPredicate::UnsignedLessEqual,
        flow::BinaryOp::Greater => IntegerPredicate::UnsignedGreater,
        flow::BinaryOp::GreaterEqual => IntegerPredicate::UnsignedGreaterEqual,
        _ => return Err(unsupported("a non-comparison unsigned operation")),
    })
}

fn operation_edges(operation: &flow::FlowOperation) -> usize {
    match operation {
        flow::FlowOperation::MakeAggregate { fields, .. }
        | flow::FlowOperation::Call {
            arguments: fields, ..
        }
        | flow::FlowOperation::AsyncCall {
            arguments: fields, ..
        }
        | flow::FlowOperation::TaskStart {
            arguments: fields, ..
        } => fields.len(),
        flow::FlowOperation::ActorCommit { arguments, .. } => arguments.len().saturating_add(1),
        _ => 0,
    }
}

fn operation_code_units(operation: &flow::FlowOperation) -> usize {
    match operation {
        flow::FlowOperation::Binary {
            op: flow::BinaryOp::DivChecked | flow::BinaryOp::RemChecked,
            ..
        } => 512,
        flow::FlowOperation::Binary {
            op:
                flow::BinaryOp::AddChecked
                | flow::BinaryOp::SubChecked
                | flow::BinaryOp::MulChecked
                | flow::BinaryOp::ShiftLeftChecked
                | flow::BinaryOp::ShiftLeftWrapping
                | flow::BinaryOp::ShiftRightChecked,
            ..
        } => 16,
        flow::FlowOperation::Cast {
            mode: flow::CastMode::Checked,
            ..
        } => 24,
        flow::FlowOperation::ActorReserve { .. } | flow::FlowOperation::MailboxReceive { .. } => 16,
        flow::FlowOperation::Assert { .. } => 32,
        _ => 0,
    }
}

fn terminator_edges(
    terminator: &flow::Terminator,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, MachineLowerError> {
    match terminator {
        flow::Terminator::Jump { arguments, .. }
        | flow::Terminator::Return(arguments)
        | flow::Terminator::TailCall { arguments, .. } => Ok(arguments.len()),
        flow::Terminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => sum_counts([then_arguments.len(), else_arguments.len()], limit),
        flow::Terminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            let mut total = sum_counts([cases.len(), default_arguments.len()], limit)?;
            for case in cases {
                check_cancelled(is_cancelled)?;
                total = total.checked_add(case.arguments.len()).ok_or(
                    MachineLowerError::ResourceLimit {
                        resource: "MachineWir model edges",
                        limit,
                    },
                )?;
            }
            Ok(total)
        }
        flow::Terminator::Suspend { .. }
        | flow::Terminator::Trap { .. }
        | flow::Terminator::Unreachable => Ok(0),
    }
}

fn generated_fixed_payload(
    request: &MachineLoweringRequest<'_>,
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, MachineLowerError> {
    let backend = request.target.backend();
    let mut total = 0u64;
    for value in [
        input.name.as_str(),
        request.target.identity().as_str(),
        backend.llvm_triple(),
        backend.llvm_data_layout(),
        backend.llvm_cpu(),
        backend.coff_machine(),
        backend.entry_symbol(),
        INTERRUPT_ROUTE_SECTION,
        INTERRUPT_ROUTE_TABLE_SYMBOL,
        "runtime",
    ] {
        check_cancelled(is_cancelled)?;
        add_payload(&mut total, value.len(), request.limits.payload_bytes)?;
    }
    for feature in backend.llvm_features() {
        check_cancelled(is_cancelled)?;
        add_payload(&mut total, feature.len(), request.limits.payload_bytes)?;
    }
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        let digits = decimal_digits(function.id.0);
        if function.id == input.image_entry {
            add_payload(
                &mut total,
                ".text.wrela.entry".len() + "image".len(),
                request.limits.payload_bytes,
            )?;
        } else {
            add_payload(
                &mut total,
                ".text.wrela.".len() + digits + "function".len(),
                request.limits.payload_bytes,
            )?;
            add_payload(
                &mut total,
                "__wrela_fn_".len() + digits,
                request.limits.payload_bytes,
            )?;
        }
    }
    Ok(total)
}

fn decimal_digits(mut value: u32) -> usize {
    let mut digits = 1usize;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn add_payload(total: &mut u64, count: usize, limit: u64) -> Result<(), MachineLowerError> {
    *total = total
        .checked_add(count_u64(count, "MachineWir payload bytes", limit)?)
        .filter(|total| *total <= limit)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir payload bytes",
            limit,
        })?;
    Ok(())
}

fn add_edges(total: u64, count: usize, limit: u64) -> Result<u64, MachineLowerError> {
    total
        .checked_add(count_u64(count, "MachineWir model edges", limit)?)
        .filter(|total| *total <= limit)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit,
        })
}

fn count_u64(count: usize, resource: &'static str, limit: u64) -> Result<u64, MachineLowerError> {
    u64::try_from(count).map_err(|_| MachineLowerError::ResourceLimit { resource, limit })
}

fn sum_counts<const N: usize>(counts: [usize; N], limit: u64) -> Result<usize, MachineLowerError> {
    counts
        .into_iter()
        .try_fold(0usize, |total, count| total.checked_add(count))
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit,
        })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn field_update_function(aggregate: flow::TypeId, field: flow::TypeId) -> flow::FlowFunction {
        flow::FlowFunction {
            id: flow::FunctionId(0),
            name: "field_update".to_owned(),
            origin: flow::FunctionOrigin::SourceSemantic {
                semantic_function: 0,
            },
            role: flow::FunctionRole::Ordinary,
            color: flow::FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: vec![
                flow::Value {
                    id: flow::ValueId(0),
                    ty: aggregate,
                    source_name: None,
                    source: None,
                },
                flow::Value {
                    id: flow::ValueId(1),
                    ty: field,
                    source_name: None,
                    source: None,
                },
                flow::Value {
                    id: flow::ValueId(2),
                    ty: aggregate,
                    source_name: None,
                    source: None,
                },
            ],
            blocks: Vec::new(),
            entry: flow::BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        }
    }

    #[test]
    fn aggregate_field_update_rejects_unlowered_shapes_with_named_tail() {
        let u64_type = flow::FlowType {
            id: flow::TypeId(0),
            kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: false,
                bits: 64,
            }),
            name: Some("u64".to_owned()),
            copyable: true,
            strict_linear: false,
        };
        let error = Err(MachineLowerError::UnsupportedInput {
            feature: "machine-flat-structure-field-update-lowering-pending",
        });

        let two_field_types = vec![
            u64_type.clone(),
            flow::FlowType {
                id: flow::TypeId(1),
                kind: flow::FlowTypeKind::Struct {
                    fields: vec![flow::TypeId(0), flow::TypeId(0)],
                },
                name: Some("Pair".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ];
        assert_eq!(
            validate_flat_structure_field_update(
                &two_field_types,
                &field_update_function(flow::TypeId(1), flow::TypeId(0)),
                flow::ValueId(2),
                flow::ValueId(0),
                0,
                flow::ValueId(1),
            ),
            error
        );

        let non_u64_types = vec![
            flow::FlowType {
                id: flow::TypeId(0),
                kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                    signed: false,
                    bits: 32,
                }),
                name: Some("u32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            flow::FlowType {
                id: flow::TypeId(1),
                kind: flow::FlowTypeKind::Struct {
                    fields: vec![flow::TypeId(0)],
                },
                name: Some("Word".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ];
        assert_eq!(
            validate_flat_structure_field_update(
                &non_u64_types,
                &field_update_function(flow::TypeId(1), flow::TypeId(0)),
                flow::ValueId(2),
                flow::ValueId(0),
                0,
                flow::ValueId(1),
            ),
            error
        );
    }

    fn exact_erasure_types() -> Vec<flow::FlowType> {
        vec![
            flow::FlowType {
                id: flow::TypeId(0),
                kind: flow::FlowTypeKind::Unit,
                name: None,
                copyable: true,
                strict_linear: false,
            },
            flow::FlowType {
                id: flow::TypeId(1),
                kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Bool),
                name: None,
                copyable: true,
                strict_linear: false,
            },
        ]
    }

    #[test]
    fn retained_construction_uses_post_erasure_lengths() {
        let types = exact_erasure_types();
        let values = (0..5)
            .map(|id| flow::Value {
                id: flow::ValueId(id),
                ty: if id == 4 {
                    flow::TypeId(1)
                } else {
                    flow::TypeId(0)
                },
                source_name: None,
                source: None,
            })
            .collect();
        let function = flow::FlowFunction {
            id: flow::FunctionId(0),
            name: "erasure".to_owned(),
            origin: flow::FunctionOrigin::SourceSemantic {
                semantic_function: 0,
            },
            role: flow::FunctionRole::Ordinary,
            color: flow::FunctionColor::Sync,
            parameters: (0..5).map(flow::ValueId).collect(),
            result_types: Vec::new(),
            values,
            blocks: Vec::new(),
            entry: flow::BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        };
        let (retained, next) = build_value_mapping(&types, &function, 0, 1, &|| false)
            .expect("one retained mapping entry under exact output limit");
        assert_eq!(retained, [flow::ValueId(4)]);
        assert_eq!(next, 1);
        let mapping = ValueMapping::Canonical {
            retained: &retained,
            value_count: function.values.len(),
            first: 0,
        };
        assert_eq!(
            map_values(&function.parameters, mapping, 1, &|| false)
                .expect("one retained argument under exact output limit"),
            [ValueId(0)]
        );

        let mut limits = MachineLoweringLimits::standard();
        limits.model_edges = 1;
        let parameters = [
            flow::TypeId(0),
            flow::TypeId(0),
            flow::TypeId(0),
            flow::TypeId(0),
            flow::TypeId(1),
        ];
        let (kind, _, _) =
            lower_passive_function_type(&types, &parameters, flow::TypeId(0), limits, &|| false)
                .expect("one retained passive parameter under exact output limit");
        assert!(matches!(
            kind,
            MachineTypeKind::Function {
                parameters,
                result: MachineTypeId(0),
            } if parameters == [MachineTypeId(1)]
        ));
        limits.model_edges = 0;
        assert!(matches!(
            lower_passive_function_type(&types, &parameters, flow::TypeId(0), limits, &|| false,),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: 0,
            })
        ));
    }

    #[test]
    fn project_sized_sort_proof_and_copy_phases_cancel_mid_scan() {
        let allocation_polls = Cell::new(0u64);
        assert_eq!(
            try_vec::<u8>(4_096, "MachineWir payload bytes", 4_096, &|| {
                let next = allocation_polls.get() + 1;
                allocation_polls.set(next);
                next == 2
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(allocation_polls.get(), 2);

        let mut entries = (0..2_049)
            .rev()
            .map(|value| TestPayloadIndexEntry {
                function: value % 3,
                value,
                payload: value as usize,
            })
            .collect::<Vec<_>>();
        let mut limits = MachineLoweringLimits::standard();
        limits.globals = entries.len() as u32;
        let sort_polls = Cell::new(0u64);
        // `try_vec` polls before and after reserve, and scratch initialization polls once per
        // element. This checkpoint is therefore exactly 100 polls into the
        // merge phase, proving that cancellation aborts active sorting rather
        // than merely its scratch fill.
        let scratch_fill_polls = entries.len() as u64 + 2;
        let sort_cancel_at = scratch_fill_polls + 100;
        assert_eq!(
            cancellable_sort_test_payload_index(&mut entries, limits, &|| {
                let next = sort_polls.get() + 1;
                sort_polls.set(next);
                next == sort_cancel_at
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(sort_polls.get(), sort_cancel_at);

        let proofs = (0..2_049)
            .map(|id| flow::Proof {
                id: flow::ProofId(id),
                kind: flow::ProofKind::TypeChecked,
                subject: String::new(),
                sources: Vec::new(),
                depends_on: Vec::new(),
                bound: None,
                explanation: Vec::new(),
            })
            .collect::<Vec<_>>();
        let proof_polls = Cell::new(0u64);
        assert_eq!(
            validate_proof_closure(&proofs, &[], proofs.len() as u64, &|| {
                let next = proof_polls.get() + 1;
                proof_polls.set(next);
                next == 100
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(proof_polls.get(), 100);

        let bytes = vec![0x5a; CANCELLABLE_COPY_CHUNK_BYTES * 2 + 1];
        let byte_polls = Cell::new(0u64);
        assert_eq!(
            copy_bytes(&bytes, bytes.len() as u64, &|| {
                let next = byte_polls.get() + 1;
                byte_polls.set(next);
                next == 4
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(byte_polls.get(), 4);

        let text = "x".repeat(CANCELLABLE_COPY_CHUNK_BYTES * 2 + 1);
        let text_polls = Cell::new(0u64);
        assert_eq!(
            copy_text(
                &text,
                "MachineWir payload bytes",
                text.len() as u64,
                &|| {
                    let next = text_polls.get() + 1;
                    text_polls.set(next);
                    next == 4
                }
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(text_polls.get(), 4);
    }

    #[test]
    fn passive_function_type_mapping_obeys_exact_edges_and_cancellation() {
        let function = flow::FlowTypeKind::Function {
            parameters: vec![flow::TypeId(2), flow::TypeId(2)],
            result: flow::TypeId(2),
        };
        let mut limits = MachineLoweringLimits::standard();
        limits.model_edges = 2;
        let (kind, size, alignment) =
            lower_type_kind(&function, limits, &|| false).expect("exact function-type edges");
        assert_eq!((size, alignment), (0, 1));
        assert_eq!(
            kind,
            MachineTypeKind::Function {
                parameters: vec![MachineTypeId(2), MachineTypeId(2)],
                result: MachineTypeId(2),
            }
        );

        limits.model_edges = 1;
        assert_eq!(
            lower_type_kind(&function, limits, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: 1,
            })
        );

        limits.model_edges = 2;
        let polls = Cell::new(0u32);
        lower_type_kind(&function, limits, &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("count function-type cancellation polls");
        let cancel_at = polls.get();
        assert!(cancel_at >= 3);
        let observed = Cell::new(0u32);
        assert_eq!(
            lower_type_kind(&function, limits, &|| {
                let next = observed.get() + 1;
                observed.set(next);
                next == cancel_at
            }),
            Err(MachineLowerError::Cancelled)
        );
    }

    #[test]
    fn flow_v9_async_edges_track_activation_plan_and_fail_closed() {
        let activation = flow::FlowType {
            id: flow::TypeId(1),
            kind: flow::FlowTypeKind::Activation {
                result: flow::TypeId(0),
            },
            name: Some("__wrela_activation_0".to_owned()),
            copyable: false,
            strict_linear: true,
        };
        assert_eq!(
            require_supported_type(&[], &activation, false, false),
            Err(MachineLowerError::UnsupportedInput {
                feature: "async activation values without an exact scheduler/runtime lowering",
            })
        );

        let async_call = flow::FlowOperation::AsyncCall {
            function: flow::FunctionId(2),
            arguments: vec![flow::ValueId(3), flow::ValueId(4)],
            plan: flow::ActivationId(0),
        };
        assert_eq!(operation_edges(&async_call), 2);
        let function = flow::FunctionId(9);
        let payload_index = TestPayloadIndex {
            entries: vec![
                TestPayloadIndexEntry {
                    function: function.0,
                    value: 3,
                    payload: 0,
                },
                TestPayloadIndexEntry {
                    function: function.0,
                    value: 5,
                    payload: 1,
                },
            ],
        };
        let mut use_counts = [0u8; 2];
        record_operation_payload_uses(
            function,
            &async_call,
            &payload_index,
            &mut use_counts,
            &|| false,
        )
        .expect("count async-call payload operands");
        assert_eq!(use_counts, [1, 0]);

        let suspend = flow::Terminator::Suspend {
            state: 0,
            activation: flow::ValueId(5),
            resume: flow::BlockId(1),
        };
        record_terminator_payload_uses(
            function,
            &suspend,
            &payload_index,
            &mut use_counts,
            &|| false,
        )
        .expect("count suspend activation payload operand");
        assert_eq!(use_counts, [1, 1]);
        assert_eq!(
            terminator_edges(&suspend, 1, &|| false)
                .expect("suspend carries no ordinary SSA edge arguments"),
            0
        );
    }

    #[test]
    fn generated_static_lifecycle_matches_only_the_exact_compiler_pass_stream() {
        let test = flow::TestEntry {
            id: flow::TestId(0),
            plan_id: 7,
            function_key: wrela_build_model::Sha256Digest::from_bytes([0x71; 32]),
            name: "passes_one".to_owned(),
            function: flow::FunctionId(0),
            kind: flow::TestKind::Integration,
            source: wrela_source::Span {
                file: wrela_source::FileId(0),
                range: wrela_source::TextRange { start: 1, end: 5 },
            },
            timeout_ns: 1,
        };
        let event = |sequence, kind| {
            Some(TestEvent {
                protocol: wrela_test_model::TEST_PROTOCOL_VERSION,
                sequence,
                kind,
            })
        };
        let canonical = vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(1, TestEventKind::TestStarted { test: TestId(7) }),
            event(
                2,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: GuestTestOutcome::Passed,
                },
            ),
            event(
                3,
                TestEventKind::RunFinished {
                    passed: 1,
                    failed: 0,
                },
            ),
        ];
        assert!(exact_flow_generated_passing_events(
            &canonical,
            std::slice::from_ref(&test)
        ));

        let mut wrong_count = canonical.clone();
        wrong_count[0] = event(0, TestEventKind::RunStarted { test_count: 2 });
        assert!(!exact_flow_generated_passing_events(
            &wrong_count,
            std::slice::from_ref(&test)
        ));

        let mut wrong_id = canonical.clone();
        wrong_id[1] = event(1, TestEventKind::TestStarted { test: TestId(8) });
        assert!(!exact_flow_generated_passing_events(
            &wrong_id,
            std::slice::from_ref(&test)
        ));

        let mut assertion = canonical.clone();
        assertion[2] = event(
            2,
            TestEventKind::AssertionFailed {
                test: TestId(7),
                failure: wrela_test_model::AssertionFailure {
                    expression: "false".to_owned(),
                    message: None,
                    source: Some(test.source),
                    expected: None,
                    actual: None,
                },
            },
        );
        assert!(!exact_flow_generated_passing_events(
            &assertion,
            std::slice::from_ref(&test)
        ));

        let mut fatal = canonical.clone();
        fatal[2] = event(
            2,
            TestEventKind::TestFinished {
                test: TestId(7),
                outcome: GuestTestOutcome::LanguageFatal {
                    cause: wrela_test_model::LanguageFatalCause::InvalidShiftCount,
                },
            },
        );
        assert!(!exact_flow_generated_passing_events(
            &fatal,
            std::slice::from_ref(&test)
        ));

        let mut wrong_summary = canonical.clone();
        wrong_summary[3] = event(
            3,
            TestEventKind::RunFinished {
                passed: 0,
                failed: 1,
            },
        );
        assert!(!exact_flow_generated_passing_events(
            &wrong_summary,
            std::slice::from_ref(&test)
        ));

        let mut missing = canonical.clone();
        missing[2] = None;
        assert!(!exact_flow_generated_passing_events(
            &missing,
            std::slice::from_ref(&test)
        ));

        let mut permuted = canonical;
        permuted.swap(1, 2);
        assert!(!exact_flow_generated_passing_events(&permuted, &[test]));
    }
}
