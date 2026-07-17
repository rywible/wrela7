use std::fmt::Write as _;

use wrela_build_model::OptimizationLevel;
use wrela_flow_wir::{
    BinaryOp, BlockId, CastMode, FlowFunction, FlowOperation, FlowType, FlowTypeKind, FlowWir,
    FunctionRole, Immediate, Instruction, InstructionId, ProofId, ScalarType, Terminator,
    TestEntry, TypeId, UnaryOp, ValueId,
};

use super::{
    DecisionKind, ModelResources, OptimizationDecision, OptimizationLimits, OptimizationProfile,
    OptimizationReport, OptimizationRequest, OptimizeError, OptimizedFlowWir, PassStatistics,
    WorkMeter, check_cancelled, ensure_limit, flow_validation_limits, flow_wir_equal,
    length_as_u64, map_validation_failure, optimization_report_equal, scan_model, scan_report,
    validate_canonical_profile,
};

const CONSTANT_FOLD_PASS: &str = "scalar-constant-fold-v1";
const CONTROL_SIMPLIFY_PASS: &str = "constant-control-flow-v1";
const UNREACHABLE_PASS: &str = "unreachable-block-elimination-v1";
const PROVEN_TRUE_CHECK_PASS: &str = "proven-true-check-elimination-v1";
const DEAD_PURE_PASS: &str = "dead-pure-instruction-elimination-v1";
const DEVELOPMENT_PASSES: [&str; 4] = [
    CONSTANT_FOLD_PASS,
    CONTROL_SIMPLIFY_PASS,
    UNREACHABLE_PASS,
    DEAD_PURE_PASS,
];
const AGGRESSIVE_PASSES: [&str; 5] = [
    CONSTANT_FOLD_PASS,
    CONTROL_SIMPLIFY_PASS,
    UNREACHABLE_PASS,
    PROVEN_TRUE_CHECK_PASS,
    DEAD_PURE_PASS,
];

pub fn optimize(
    request: OptimizationRequest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OptimizedFlowWir, OptimizeError> {
    check_cancelled(is_cancelled)?;
    validate_transform_profile(&request.profile)?;
    request.limits.validate()?;

    let OptimizationRequest {
        input,
        profile,
        limits,
    } = request;
    let mut work = WorkMeter::new(limits.work, is_cancelled);
    work.checkpoint()?;
    let input_resources = scan_model(input.as_wir(), limits, &mut work)?;
    work.checkpoint()?;

    let (output, report) = execute_pipeline(
        input.into_wir(),
        profile,
        limits,
        input_resources,
        &mut work,
    )?;
    let output_resources = scan_model(&output, limits, &mut work)?;
    enforce_growth(&report.profile, input_resources, output_resources)?;
    scan_report(&report, limits, &mut work)?;
    validate_report_shape(
        &report,
        input_resources.instructions,
        output_resources.instructions,
        input_resources.tests,
        output_resources.tests,
        &mut work,
    )?;
    work.checkpoint()?;

    let wir = output
        .validate_with_limits(flow_validation_limits(limits), is_cancelled)
        .map_err(map_validation_failure)?;
    work.checkpoint()?;
    Ok(OptimizedFlowWir { wir, report })
}

/// Re-execute the canonical pipeline and accept externally supplied optimizer
/// output only when both the model and explanatory report are byte-for-byte
/// equivalent at their Rust model boundary. This is deliberately more costly
/// than `optimize`; every attacker-controlled candidate is independently
/// bounded before equality is attempted.
pub fn seal(
    request: OptimizationRequest,
    candidate: &FlowWir,
    candidate_report: &OptimizationReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OptimizedFlowWir, OptimizeError> {
    check_cancelled(is_cancelled)?;
    validate_transform_profile(&request.profile)?;
    request.limits.validate()?;

    let mut candidate_work = WorkMeter::new(request.limits.work, is_cancelled);
    candidate_work.checkpoint()?;
    let candidate_resources = scan_model(candidate, request.limits, &mut candidate_work)?;
    let report_scan_work = scan_report(candidate_report, request.limits, &mut candidate_work)?;
    candidate_work.charge(candidate_resources.scan_work)?;
    candidate_work.charge(report_scan_work)?;
    candidate_work.checkpoint()?;

    let expected = optimize(request, is_cancelled)?;
    if !flow_wir_equal(expected.wir.as_wir(), candidate, &mut candidate_work)? {
        return Err(OptimizeError::InvalidReport(
            "optimizer output does not match the canonical transforming pipeline",
        ));
    }
    if !optimization_report_equal(&expected.report, candidate_report, &mut candidate_work)? {
        return Err(OptimizeError::InvalidReport(
            "optimizer report does not match the canonical transforming pipeline",
        ));
    }
    candidate_work.checkpoint()?;
    Ok(expected)
}

fn validate_transform_profile(profile: &OptimizationProfile) -> Result<(), OptimizeError> {
    validate_canonical_profile(profile)?;
    if profile.level == OptimizationLevel::None {
        return Err(OptimizeError::UnsupportedOptimizationLevel(profile.level));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn execute_pipeline(
    mut wir: FlowWir,
    profile: OptimizationProfile,
    limits: OptimizationLimits,
    input_resources: ModelResources,
    work: &mut WorkMeter<'_>,
) -> Result<(FlowWir, OptimizationReport), OptimizeError> {
    let pipeline_passes = pipeline_passes(profile.level)?;
    ensure_limit(
        u64::try_from(pipeline_passes.len()).map_err(|_| OptimizeError::ResourceLimit {
            resource: "optimization passes",
            limit: u64::from(limits.passes),
        })?,
        "optimization passes",
        u64::from(limits.passes),
    )?;

    let mut passes = Vec::new();
    reserve_items(
        &mut passes,
        pipeline_passes.len(),
        "optimization passes",
        u64::from(limits.passes),
    )?;
    let mut decisions = DecisionSink::new(&profile, limits)?;
    let mut current_instructions = input_resources.instructions;
    // Test metadata is immutable executable-plan provenance. Keep the exact
    // owned table outside the mutable pass pipeline, then restore that same
    // allocation after rechecking its links against every transformed module.
    let tests = std::mem::take(&mut wir.tests);
    let test_entries = u32::try_from(tests.len()).map_err(|_| OptimizeError::ResourceLimit {
        resource: "FlowWir tests",
        limit: u64::from(limits.tests),
    })?;
    verify_test_table_links(&wir.functions, &tests, limits, "pipeline-input", work)?;

    let (folded, fold_iterations) =
        fold_scalar_constants(&mut wir, &profile, limits, &mut decisions, work)?;
    verify_after_pass(&wir, &profile, limits, CONSTANT_FOLD_PASS, false, work)?;
    verify_test_table_links(&wir.functions, &tests, limits, CONSTANT_FOLD_PASS, work)?;
    passes.push(PassStatistics {
        pass: report_text(CONSTANT_FOLD_PASS, limits)?,
        iterations: fold_iterations,
        changed: folded,
        instructions_before: current_instructions,
        instructions_after: current_instructions,
        test_entries_before: test_entries,
        test_entries_after: test_entries,
        test_table_preserved: true,
    });

    let simplified = simplify_constant_control_flow(&mut wir, limits, &mut decisions, work)?;
    verify_after_pass(&wir, &profile, limits, CONTROL_SIMPLIFY_PASS, false, work)?;
    verify_test_table_links(&wir.functions, &tests, limits, CONTROL_SIMPLIFY_PASS, work)?;
    passes.push(PassStatistics {
        pass: report_text(CONTROL_SIMPLIFY_PASS, limits)?,
        iterations: 1,
        changed: simplified,
        instructions_before: current_instructions,
        instructions_after: current_instructions,
        test_entries_before: test_entries,
        test_entries_after: test_entries,
        test_table_preserved: true,
    });

    let before_unreachable = current_instructions;
    let removed_unreachable = eliminate_unreachable_blocks(&mut wir, &mut decisions, limits, work)?;
    current_instructions = instruction_count(&wir, work)?;
    verify_after_pass(&wir, &profile, limits, UNREACHABLE_PASS, true, work)?;
    verify_test_table_links(&wir.functions, &tests, limits, UNREACHABLE_PASS, work)?;
    passes.push(PassStatistics {
        pass: report_text(UNREACHABLE_PASS, limits)?,
        iterations: 1,
        changed: removed_unreachable,
        instructions_before: before_unreachable,
        instructions_after: current_instructions,
        test_entries_before: test_entries,
        test_entries_after: test_entries,
        test_table_preserved: true,
    });

    if is_aggressive(profile.level) {
        let before_checks = current_instructions;
        let removed_checks = eliminate_proven_true_checks(&mut wir, &mut decisions, limits, work)?;
        current_instructions = instruction_count(&wir, work)?;
        verify_after_pass(&wir, &profile, limits, PROVEN_TRUE_CHECK_PASS, true, work)?;
        verify_test_table_links(&wir.functions, &tests, limits, PROVEN_TRUE_CHECK_PASS, work)?;
        passes.push(PassStatistics {
            pass: report_text(PROVEN_TRUE_CHECK_PASS, limits)?,
            iterations: 1,
            changed: removed_checks,
            instructions_before: before_checks,
            instructions_after: current_instructions,
            test_entries_before: test_entries,
            test_entries_after: test_entries,
            test_table_preserved: true,
        });
    }

    let before_dce = current_instructions;
    let removed_dead = eliminate_dead_pure_instructions(&mut wir, &mut decisions, limits, work)?;
    current_instructions = instruction_count(&wir, work)?;
    verify_after_pass(&wir, &profile, limits, DEAD_PURE_PASS, true, work)?;
    verify_test_table_links(&wir.functions, &tests, limits, DEAD_PURE_PASS, work)?;
    passes.push(PassStatistics {
        pass: report_text(DEAD_PURE_PASS, limits)?,
        iterations: 1,
        changed: removed_dead,
        instructions_before: before_dce,
        instructions_after: current_instructions,
        test_entries_before: test_entries,
        test_entries_after: test_entries,
        test_table_preserved: true,
    });

    wir.tests = tests;

    Ok((
        wir,
        OptimizationReport {
            profile,
            passes,
            decisions: decisions.finish(),
        },
    ))
}

const fn pipeline_passes(
    level: OptimizationLevel,
) -> Result<&'static [&'static str], OptimizeError> {
    match level {
        OptimizationLevel::Development => Ok(&DEVELOPMENT_PASSES),
        OptimizationLevel::Performance | OptimizationLevel::Size => Ok(&AGGRESSIVE_PASSES),
        OptimizationLevel::None => Err(OptimizeError::UnsupportedOptimizationLevel(level)),
    }
}

const fn is_aggressive(level: OptimizationLevel) -> bool {
    matches!(
        level,
        OptimizationLevel::Performance | OptimizationLevel::Size
    )
}

fn enforce_growth(
    profile: &OptimizationProfile,
    input: ModelResources,
    output: ModelResources,
) -> Result<(), OptimizeError> {
    let growth = input
        .instructions
        .checked_mul(u64::from(profile.maximum_ir_growth_percent))
        .and_then(|value| value.checked_div(100))
        .ok_or(OptimizeError::InvalidReport(
            "optimization growth calculation overflow",
        ))?;
    let allowed = input
        .instructions
        .checked_add(growth)
        .ok_or(OptimizeError::InvalidReport(
            "optimization growth calculation overflow",
        ))?;
    ensure_limit(output.instructions, "optimized IR instructions", allowed)
}

fn validate_report_shape(
    report: &OptimizationReport,
    input_instructions: u64,
    output_instructions: u64,
    input_tests: u64,
    output_tests: u64,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let expected_passes = pipeline_passes(report.profile.level)?;
    if report.passes.len() != expected_passes.len() {
        return Err(OptimizeError::InvalidReport(
            "optimizer report does not contain the canonical pass sequence",
        ));
    }
    if input_tests != output_tests {
        return Err(OptimizeError::InvalidReport(
            "optimization changed the test table length",
        ));
    }
    let test_entries = u32::try_from(input_tests).map_err(|_| {
        OptimizeError::InvalidReport("optimizer test table length cannot be reported")
    })?;
    let mut previous = input_instructions;
    for (statistics, expected_name) in report.passes.iter().zip(expected_passes) {
        work.checkpoint()?;
        if statistics.pass != *expected_name
            || statistics.iterations == 0
            || statistics.iterations > report.profile.maximum_iterations
            || statistics.instructions_before != previous
            || (!statistics.changed
                && statistics.instructions_before != statistics.instructions_after)
            || statistics.test_entries_before != test_entries
            || statistics.test_entries_after != test_entries
            || !statistics.test_table_preserved
        {
            return Err(OptimizeError::InvalidReport(
                "optimizer pass statistics are noncanonical",
            ));
        }
        previous = statistics.instructions_after;
    }
    if previous != output_instructions {
        return Err(OptimizeError::InvalidReport(
            "development pass statistics do not end at the output",
        ));
    }
    for decision in &report.decisions {
        work.checkpoint()?;
        if !expected_passes.contains(&decision.pass.as_str())
            || decision.subject.is_empty()
            || decision.justification.is_empty()
            || !decision.relied_on.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(OptimizeError::InvalidReport(
                "optimization decision is noncanonical",
            ));
        }
    }
    Ok(())
}

fn verify_test_table_links(
    functions: &[FlowFunction],
    tests: &[TestEntry],
    limits: OptimizationLimits,
    pass: &'static str,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    ensure_limit(
        length_as_u64(tests.len(), "FlowWir tests", u64::from(limits.tests))?,
        "FlowWir tests",
        u64::from(limits.tests),
    )?;
    let mut listed = filled_vec(
        functions.len(),
        false,
        "optimizer test function set",
        u64::from(limits.functions),
    )?;
    for (expected, test) in tests.iter().enumerate() {
        work.checkpoint()?;
        let Some(function) = functions.get(test.function.0 as usize) else {
            return proof_violation(pass, "test metadata names an unknown function");
        };
        let Some(slot) = listed.get_mut(test.function.0 as usize) else {
            return proof_violation(pass, "test metadata function lookup failed");
        };
        if test.id.0 as usize != expected || *slot || function.role != FunctionRole::Test {
            return proof_violation(
                pass,
                "test metadata is non-dense, duplicated, or names a non-test function",
            );
        }
        *slot = true;
    }
    for (index, function) in functions.iter().enumerate() {
        work.checkpoint()?;
        if (function.role == FunctionRole::Test) != listed[index] {
            return proof_violation(pass, "test function set drifted from test metadata");
        }
    }
    Ok(())
}

struct DecisionSink {
    decisions: Vec<OptimizationDecision>,
    limits: OptimizationLimits,
    report_bytes: u64,
}

impl DecisionSink {
    fn new(
        profile: &OptimizationProfile,
        limits: OptimizationLimits,
    ) -> Result<Self, OptimizeError> {
        let mut report_bytes = length_as_u64(
            profile.pipeline.name.len(),
            "optimization report bytes",
            limits.report_bytes,
        )?;
        for pass in pipeline_passes(profile.level)? {
            let bytes =
                length_as_u64(pass.len(), "optimization report bytes", limits.report_bytes)?;
            report_bytes = report_bytes
                .checked_add(bytes)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimization report bytes",
                    limit: limits.report_bytes,
                })?;
        }
        ensure_limit(
            report_bytes,
            "optimization report bytes",
            limits.report_bytes,
        )?;
        Ok(Self {
            decisions: Vec::new(),
            limits,
            report_bytes,
        })
    }

    fn push(
        &mut self,
        pass: &'static str,
        subject: String,
        kind: DecisionKind,
        justification: &'static str,
        relied_on: Vec<ProofId>,
    ) -> Result<(), OptimizeError> {
        let next_count = u64::try_from(self.decisions.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(OptimizeError::ResourceLimit {
                resource: "optimization decisions",
                limit: self.limits.decisions,
            })?;
        ensure_limit(next_count, "optimization decisions", self.limits.decisions)?;
        if !relied_on.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(OptimizeError::InvalidReport(
                "optimization proof reliance must be sorted and unique",
            ));
        }
        let string_bytes = pass
            .len()
            .checked_add(subject.len())
            .and_then(|bytes| bytes.checked_add(justification.len()))
            .and_then(|bytes| bytes.checked_add(relied_on.len().checked_mul(4)?))
            .ok_or(OptimizeError::ResourceLimit {
                resource: "optimization report bytes",
                limit: self.limits.report_bytes,
            })?;
        let string_bytes = length_as_u64(
            string_bytes,
            "optimization report bytes",
            self.limits.report_bytes,
        )?;
        self.report_bytes =
            self.report_bytes
                .checked_add(string_bytes)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimization report bytes",
                    limit: self.limits.report_bytes,
                })?;
        ensure_limit(
            self.report_bytes,
            "optimization report bytes",
            self.limits.report_bytes,
        )?;
        self.decisions
            .try_reserve(1)
            .map_err(|_| OptimizeError::ResourceLimit {
                resource: "optimization decisions",
                limit: self.limits.decisions,
            })?;
        let pass = report_text(pass, self.limits)?;
        let justification = report_text(justification, self.limits)?;
        self.decisions.push(OptimizationDecision {
            pass,
            subject,
            kind,
            justification,
            relied_on,
        });
        Ok(())
    }

    fn finish(self) -> Vec<OptimizationDecision> {
        self.decisions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarConstant {
    Bool(bool),
    Integer {
        signed: bool,
        bits: u16,
        value: u128,
    },
    Float32(u32),
    Float64(u64),
}

fn fold_scalar_constants(
    wir: &mut FlowWir,
    profile: &OptimizationProfile,
    limits: OptimizationLimits,
    decisions: &mut DecisionSink,
    work: &mut WorkMeter<'_>,
) -> Result<(bool, u32), OptimizeError> {
    let mut changed = false;
    let mut maximum_iterations = 1;
    let types = &wir.types;
    for function in &mut wir.functions {
        work.checkpoint()?;
        let mut constants = filled_vec(
            function.values.len(),
            None,
            "optimizer temporary values",
            limits.values,
        )?;
        seed_immediates(function, types, &mut constants, work)?;
        let mut iterations = 0u32;
        loop {
            iterations = iterations
                .checked_add(1)
                .ok_or_else(|| OptimizeError::ResourceLimit {
                    resource: "optimization iterations",
                    limit: u64::from(profile.maximum_iterations),
                })?;
            let mut iteration_changed = false;
            for block in &mut function.blocks {
                work.checkpoint()?;
                for instruction in &mut block.instructions {
                    work.checkpoint()?;
                    if matches!(instruction.operation, FlowOperation::Immediate(_)) {
                        continue;
                    }
                    let Some(result) = single_result(instruction) else {
                        continue;
                    };
                    let Some(result_type) =
                        function.values.get(result.0 as usize).map(|value| value.ty)
                    else {
                        continue;
                    };
                    let Some(folded) =
                        fold_operation(&instruction.operation, result_type, &constants, types)
                    else {
                        continue;
                    };
                    let Some(constant) = constant_from_immediate(&folded, result_type, types)
                    else {
                        continue;
                    };
                    instruction.operation = FlowOperation::Immediate(folded);
                    if let Some(slot) = constants.get_mut(result.0 as usize) {
                        *slot = Some(constant);
                    }
                    decisions.push(
                        CONSTANT_FOLD_PASS,
                        instruction_subject(function.id.0, instruction.id.0)?,
                        DecisionKind::Folded,
                        "replaced an exact scalar operation with its canonical immediate value",
                        Vec::new(),
                    )?;
                    iteration_changed = true;
                    changed = true;
                }
            }
            if !iteration_changed {
                break;
            }
            if iterations == profile.maximum_iterations {
                if has_foldable_scalar_operation(function, types, &constants, work)? {
                    return Err(OptimizeError::ResourceLimit {
                        resource: "optimization iterations",
                        limit: u64::from(profile.maximum_iterations),
                    });
                }
                break;
            }
        }
        maximum_iterations = maximum_iterations.max(iterations);
    }
    Ok((changed, maximum_iterations))
}

fn has_foldable_scalar_operation(
    function: &FlowFunction,
    types: &[FlowType],
    constants: &[Option<ScalarConstant>],
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    for block in &function.blocks {
        work.checkpoint()?;
        for instruction in &block.instructions {
            work.checkpoint()?;
            if matches!(instruction.operation, FlowOperation::Immediate(_)) {
                continue;
            }
            let Some(result) = single_result(instruction) else {
                continue;
            };
            let Some(result_type) = function.values.get(result.0 as usize).map(|value| value.ty)
            else {
                continue;
            };
            if fold_operation(&instruction.operation, result_type, constants, types).is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn seed_immediates(
    function: &FlowFunction,
    types: &[FlowType],
    constants: &mut [Option<ScalarConstant>],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    for block in &function.blocks {
        work.checkpoint()?;
        for instruction in &block.instructions {
            work.checkpoint()?;
            let (Some(result), FlowOperation::Immediate(immediate)) =
                (single_result(instruction), &instruction.operation)
            else {
                continue;
            };
            let Some(result_type) = function.values.get(result.0 as usize).map(|value| value.ty)
            else {
                continue;
            };
            if let Some(constant) = constant_from_immediate(immediate, result_type, types) {
                if let Some(slot) = constants.get_mut(result.0 as usize) {
                    *slot = Some(constant);
                }
            }
        }
    }
    Ok(())
}

fn fold_operation(
    operation: &FlowOperation,
    result_type: TypeId,
    constants: &[Option<ScalarConstant>],
    types: &[FlowType],
) -> Option<Immediate> {
    match operation {
        FlowOperation::Unary { op, value } => {
            fold_unary(*op, constant(*value, constants)?, result_type, types)
        }
        FlowOperation::Binary { op, left, right } => fold_binary(
            *op,
            constant(*left, constants)?,
            constant(*right, constants)?,
            result_type,
            types,
        ),
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            let ScalarConstant::Bool(condition) = constant(*condition, constants)? else {
                return None;
            };
            let selected = if condition { *then_value } else { *else_value };
            constant_to_immediate(constant(selected, constants)?, result_type, types)
        }
        FlowOperation::Cast {
            value,
            to,
            mode: CastMode::Exact,
        } if *to == result_type => {
            constant_to_immediate(constant(*value, constants)?, result_type, types)
        }
        FlowOperation::Immediate(_)
        | FlowOperation::Cast { .. }
        | FlowOperation::MakeAggregate { .. }
        | FlowOperation::MakeEnum { .. }
        | FlowOperation::EnumTag { .. }
        | FlowOperation::EnumPayload { .. }
        | FlowOperation::ExtractField { .. }
        | FlowOperation::InsertField { .. }
        | FlowOperation::BeginAccess { .. }
        | FlowOperation::EndAccess { .. }
        | FlowOperation::Load { .. }
        | FlowOperation::Store { .. }
        | FlowOperation::Move { .. }
        | FlowOperation::Copy { .. }
        | FlowOperation::Drop { .. }
        | FlowOperation::Call { .. }
        | FlowOperation::AsyncCall { .. }
        | FlowOperation::Allocate { .. }
        | FlowOperation::RegionReset { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::ActorCommit { .. }
        | FlowOperation::ActorReject { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::ReplyResolve { .. }
        | FlowOperation::ReceiptCommit { .. }
        | FlowOperation::ReceiptResolve { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::TaskStart { .. }
        | FlowOperation::TaskCancel { .. }
        | FlowOperation::Park { .. }
        | FlowOperation::Wake { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::InterruptRestore { .. }
        | FlowOperation::InterruptPublish { .. }
        | FlowOperation::MmioRead { .. }
        | FlowOperation::MmioWrite { .. }
        | FlowOperation::Fence { .. }
        | FlowOperation::DmaTransition { .. }
        | FlowOperation::QueueReserve { .. }
        | FlowOperation::QueuePublish { .. }
        | FlowOperation::ValidateDeviceValue { .. }
        | FlowOperation::Check { .. }
        | FlowOperation::RecordEvent { .. }
        | FlowOperation::ReplayEvent { .. }
        | FlowOperation::Assert { .. }
        | FlowOperation::TestEmit { .. }
        | FlowOperation::TestFinish { .. } => None,
    }
}

fn fold_unary(
    op: UnaryOp,
    operand: ScalarConstant,
    result_type: TypeId,
    types: &[FlowType],
) -> Option<Immediate> {
    let result = match (op, operand) {
        (UnaryOp::BoolNot, ScalarConstant::Bool(value)) => ScalarConstant::Bool(!value),
        (
            UnaryOp::BitNot,
            ScalarConstant::Integer {
                signed,
                bits,
                value,
            },
        ) => ScalarConstant::Integer {
            signed,
            bits,
            value: (!value) & integer_mask(bits)?,
        },
        (
            UnaryOp::Negate,
            ScalarConstant::Integer {
                signed: true,
                bits,
                value,
            },
        ) => {
            let signed_value = sign_extend(value, bits)?;
            let negated = signed_value.checked_neg()?;
            if !signed_fits(negated, bits)? {
                return None;
            }
            ScalarConstant::Integer {
                signed: true,
                bits,
                value: signed_to_raw(negated, bits)?,
            }
        }
        (UnaryOp::Negate, ScalarConstant::Float32(value)) => {
            ScalarConstant::Float32(value ^ (1_u32 << 31))
        }
        (UnaryOp::Negate, ScalarConstant::Float64(value)) => {
            ScalarConstant::Float64(value ^ (1_u64 << 63))
        }
        _ => return None,
    };
    constant_to_immediate(result, result_type, types)
}

fn fold_binary(
    op: BinaryOp,
    left: ScalarConstant,
    right: ScalarConstant,
    result_type: TypeId,
    types: &[FlowType],
) -> Option<Immediate> {
    if let (
        ScalarConstant::Integer {
            signed: left_signed,
            bits: left_bits,
            value: left_value,
        },
        ScalarConstant::Integer {
            signed: right_signed,
            bits: right_bits,
            value: right_value,
        },
    ) = (left, right)
    {
        if left_signed != right_signed || left_bits != right_bits {
            return None;
        }
        let value = fold_integer_binary(op, left_signed, left_bits, left_value, right_value)?;
        return constant_to_immediate(value, result_type, types);
    }

    let comparison = match (left, right) {
        (ScalarConstant::Bool(left), ScalarConstant::Bool(right)) => match op {
            BinaryOp::Equal => Some(left == right),
            BinaryOp::NotEqual => Some(left != right),
            _ => None,
        },
        (ScalarConstant::Float32(left), ScalarConstant::Float32(right)) => {
            compare_float(op, &f32::from_bits(left), &f32::from_bits(right))
        }
        (ScalarConstant::Float64(left), ScalarConstant::Float64(right)) => {
            compare_float(op, &f64::from_bits(left), &f64::from_bits(right))
        }
        _ => None,
    }?;
    constant_to_immediate(ScalarConstant::Bool(comparison), result_type, types)
}

fn fold_integer_binary(
    op: BinaryOp,
    signed: bool,
    bits: u16,
    left: u128,
    right: u128,
) -> Option<ScalarConstant> {
    let mask = integer_mask(bits)?;
    let integer = |value| ScalarConstant::Integer {
        signed,
        bits,
        value: value & mask,
    };
    let boolean = |value| ScalarConstant::Bool(value);
    match op {
        BinaryOp::AddWrapping => Some(integer(left.wrapping_add(right))),
        BinaryOp::SubWrapping => Some(integer(left.wrapping_sub(right))),
        BinaryOp::MulWrapping => Some(integer(left.wrapping_mul(right))),
        BinaryOp::BitAnd => Some(integer(left & right)),
        BinaryOp::BitOr => Some(integer(left | right)),
        BinaryOp::BitXor => Some(integer(left ^ right)),
        BinaryOp::AddChecked | BinaryOp::SubChecked | BinaryOp::MulChecked => {
            checked_integer_arithmetic(op, signed, bits, left, right).map(integer)
        }
        BinaryOp::DivChecked | BinaryOp::RemChecked => {
            checked_integer_division(op, signed, bits, left, right).map(integer)
        }
        BinaryOp::ShiftLeftChecked | BinaryOp::ShiftLeftWrapping | BinaryOp::ShiftRightChecked => {
            checked_integer_shift(op, signed, bits, left, right).map(integer)
        }
        BinaryOp::Equal => Some(boolean(left == right)),
        BinaryOp::NotEqual => Some(boolean(left != right)),
        BinaryOp::Less | BinaryOp::LessEqual | BinaryOp::Greater | BinaryOp::GreaterEqual => {
            Some(boolean(compare_integer(op, signed, bits, left, right)?))
        }
    }
}

fn checked_integer_arithmetic(
    op: BinaryOp,
    signed: bool,
    bits: u16,
    left: u128,
    right: u128,
) -> Option<u128> {
    if signed {
        let left = sign_extend(left, bits)?;
        let right = sign_extend(right, bits)?;
        let result = match op {
            BinaryOp::AddChecked => left.checked_add(right),
            BinaryOp::SubChecked => left.checked_sub(right),
            BinaryOp::MulChecked => left.checked_mul(right),
            _ => None,
        }?;
        signed_fits(result, bits)?
            .then(|| signed_to_raw(result, bits))
            .flatten()
    } else {
        let result = match op {
            BinaryOp::AddChecked => left.checked_add(right),
            BinaryOp::SubChecked => left.checked_sub(right),
            BinaryOp::MulChecked => left.checked_mul(right),
            _ => None,
        }?;
        (result <= integer_mask(bits)?).then_some(result)
    }
}

fn checked_integer_division(
    op: BinaryOp,
    signed: bool,
    bits: u16,
    left: u128,
    right: u128,
) -> Option<u128> {
    if signed {
        let left = sign_extend(left, bits)?;
        let right = sign_extend(right, bits)?;
        if right == 0 {
            return None;
        }
        let result = match op {
            BinaryOp::DivChecked => left.checked_div(right),
            BinaryOp::RemChecked => left.checked_rem(right),
            _ => None,
        }?;
        if op == BinaryOp::DivChecked && !signed_fits(result, bits)? {
            return None;
        }
        signed_to_raw(result, bits)
    } else {
        if right == 0 {
            return None;
        }
        match op {
            BinaryOp::DivChecked => Some(left / right),
            BinaryOp::RemChecked => Some(left % right),
            _ => None,
        }
    }
}

fn checked_integer_shift(
    op: BinaryOp,
    signed: bool,
    bits: u16,
    left: u128,
    right: u128,
) -> Option<u128> {
    if signed && sign_extend(right, bits)? < 0 {
        return None;
    }
    let count = u32::try_from(right).ok()?;
    if count >= u32::from(bits) {
        return None;
    }
    let mask = integer_mask(bits)?;
    let left = left & mask;
    match op {
        BinaryOp::ShiftLeftChecked => {
            let shifted = (left << count) & mask;
            let roundtrips = if signed {
                (sign_extend(shifted, bits)? >> count) == sign_extend(left, bits)?
            } else {
                (shifted >> count) == left
            };
            roundtrips.then_some(shifted)
        }
        BinaryOp::ShiftLeftWrapping => Some((left << count) & mask),
        BinaryOp::ShiftRightChecked if signed => {
            signed_to_raw(sign_extend(left, bits)? >> count, bits)
        }
        BinaryOp::ShiftRightChecked => Some(left >> count),
        _ => None,
    }
}

fn compare_integer(op: BinaryOp, signed: bool, bits: u16, left: u128, right: u128) -> Option<bool> {
    if signed {
        let left = sign_extend(left, bits)?;
        let right = sign_extend(right, bits)?;
        match op {
            BinaryOp::Less => Some(left < right),
            BinaryOp::LessEqual => Some(left <= right),
            BinaryOp::Greater => Some(left > right),
            BinaryOp::GreaterEqual => Some(left >= right),
            _ => None,
        }
    } else {
        match op {
            BinaryOp::Less => Some(left < right),
            BinaryOp::LessEqual => Some(left <= right),
            BinaryOp::Greater => Some(left > right),
            BinaryOp::GreaterEqual => Some(left >= right),
            _ => None,
        }
    }
}

fn compare_float<T: PartialEq + PartialOrd>(op: BinaryOp, left: &T, right: &T) -> Option<bool> {
    match op {
        BinaryOp::Equal => Some(left == right),
        BinaryOp::NotEqual => Some(left != right),
        BinaryOp::Less => Some(left < right),
        BinaryOp::LessEqual => Some(left <= right),
        BinaryOp::Greater => Some(left > right),
        BinaryOp::GreaterEqual => Some(left >= right),
        _ => None,
    }
}

fn constant_from_immediate(
    immediate: &Immediate,
    result_type: TypeId,
    types: &[FlowType],
) -> Option<ScalarConstant> {
    let kind = &types.get(result_type.0 as usize)?.kind;
    match (immediate, kind) {
        (Immediate::Bool(value), FlowTypeKind::Scalar(ScalarType::Bool)) => {
            Some(ScalarConstant::Bool(*value))
        }
        (
            Immediate::Integer { bits, bytes_le },
            FlowTypeKind::Scalar(ScalarType::Integer {
                signed,
                bits: type_bits,
            }),
        ) if bits == type_bits && integer_byte_width(*bits)? == bytes_le.len() => {
            let mut value = 0u128;
            for (index, byte) in bytes_le.iter().copied().enumerate() {
                value |= u128::from(byte) << (index * 8);
            }
            if value & !integer_mask(*bits)? != 0 {
                return None;
            }
            Some(ScalarConstant::Integer {
                signed: *signed,
                bits: *bits,
                value,
            })
        }
        (Immediate::Float32(value), FlowTypeKind::Scalar(ScalarType::Float32)) => {
            Some(ScalarConstant::Float32(*value))
        }
        (Immediate::Float64(value), FlowTypeKind::Scalar(ScalarType::Float64)) => {
            Some(ScalarConstant::Float64(*value))
        }
        (Immediate::Zero(ty), FlowTypeKind::Scalar(ScalarType::Bool)) if *ty == result_type => {
            Some(ScalarConstant::Bool(false))
        }
        (Immediate::Zero(ty), FlowTypeKind::Scalar(ScalarType::Integer { signed, bits }))
            if *ty == result_type =>
        {
            Some(ScalarConstant::Integer {
                signed: *signed,
                bits: *bits,
                value: 0,
            })
        }
        (Immediate::Zero(ty), FlowTypeKind::Scalar(ScalarType::Float32)) if *ty == result_type => {
            Some(ScalarConstant::Float32(0))
        }
        (Immediate::Zero(ty), FlowTypeKind::Scalar(ScalarType::Float64)) if *ty == result_type => {
            Some(ScalarConstant::Float64(0))
        }
        _ => None,
    }
}

fn constant_to_immediate(
    constant: ScalarConstant,
    result_type: TypeId,
    types: &[FlowType],
) -> Option<Immediate> {
    match (constant, &types.get(result_type.0 as usize)?.kind) {
        (ScalarConstant::Bool(value), FlowTypeKind::Scalar(ScalarType::Bool)) => {
            Some(Immediate::Bool(value))
        }
        (
            ScalarConstant::Integer {
                signed,
                bits,
                value,
            },
            FlowTypeKind::Scalar(ScalarType::Integer {
                signed: result_signed,
                bits: result_bits,
            }),
        ) if signed == *result_signed && bits == *result_bits => {
            let width = integer_byte_width(bits)?;
            let mut bytes_le = Vec::new();
            bytes_le.try_reserve_exact(width).ok()?;
            let encoded = value.to_le_bytes();
            bytes_le.extend_from_slice(encoded.get(..width)?);
            Some(Immediate::Integer { bits, bytes_le })
        }
        (ScalarConstant::Float32(value), FlowTypeKind::Scalar(ScalarType::Float32)) => {
            Some(Immediate::Float32(value))
        }
        (ScalarConstant::Float64(value), FlowTypeKind::Scalar(ScalarType::Float64)) => {
            Some(Immediate::Float64(value))
        }
        _ => None,
    }
}

fn constant(value: ValueId, constants: &[Option<ScalarConstant>]) -> Option<ScalarConstant> {
    constants.get(value.0 as usize).copied().flatten()
}

fn integer_byte_width(bits: u16) -> Option<usize> {
    if bits == 0 || bits > 128 {
        return None;
    }
    Some(usize::from(bits).div_ceil(8))
}

fn integer_mask(bits: u16) -> Option<u128> {
    match bits {
        128 => Some(u128::MAX),
        1..=127 => Some((1u128 << u32::from(bits)) - 1),
        _ => None,
    }
}

fn sign_extend(value: u128, bits: u16) -> Option<i128> {
    let mask = integer_mask(bits)?;
    let value = value & mask;
    if bits == 128 {
        return Some(i128::from_ne_bytes(value.to_ne_bytes()));
    }
    let sign = 1u128 << u32::from(bits - 1);
    if value & sign == 0 {
        i128::try_from(value).ok()
    } else {
        Some(i128::from_ne_bytes((value | !mask).to_ne_bytes()))
    }
}

fn signed_fits(value: i128, bits: u16) -> Option<bool> {
    match bits {
        128 => Some(true),
        1..=127 => {
            let shift = u32::from(bits - 1);
            Some(value >= -(1i128 << shift) && value < (1i128 << shift))
        }
        _ => None,
    }
}

fn signed_to_raw(value: i128, bits: u16) -> Option<u128> {
    Some(u128::from_ne_bytes(value.to_ne_bytes()) & integer_mask(bits)?)
}

#[allow(clippy::too_many_lines)]
fn simplify_constant_control_flow(
    wir: &mut FlowWir,
    limits: OptimizationLimits,
    decisions: &mut DecisionSink,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    let mut changed = false;
    let types = &wir.types;
    for function in &mut wir.functions {
        let mut constants = filled_vec(
            function.values.len(),
            None,
            "optimizer temporary values",
            limits.values,
        )?;
        seed_immediates(function, types, &mut constants, work)?;
        for block in &mut function.blocks {
            work.checkpoint()?;
            let choice = match &block.terminator {
                Terminator::Branch { condition, .. } => match constant(*condition, &constants) {
                    Some(ScalarConstant::Bool(value)) => Some(ControlChoice::Branch(value)),
                    _ => None,
                },
                Terminator::Switch { value, .. } => match constant(*value, &constants) {
                    Some(ScalarConstant::Bool(value)) => {
                        Some(ControlChoice::Switch(u128::from(value)))
                    }
                    Some(ScalarConstant::Integer { value, .. }) => {
                        Some(ControlChoice::Switch(value))
                    }
                    _ => None,
                },
                Terminator::Jump { .. }
                | Terminator::Return(_)
                | Terminator::Suspend { .. }
                | Terminator::TailCall { .. }
                | Terminator::Trap { .. }
                | Terminator::Unreachable => None,
            };
            if let Some(choice) = choice {
                let original = std::mem::replace(&mut block.terminator, Terminator::Unreachable);
                block.terminator = match (original, choice) {
                    (
                        Terminator::Branch {
                            then_block,
                            then_arguments,
                            ..
                        },
                        ControlChoice::Branch(true),
                    ) => Terminator::Jump {
                        target: then_block,
                        arguments: then_arguments,
                    },
                    (
                        Terminator::Branch {
                            then_block: _,
                            then_arguments: _,
                            else_block,
                            else_arguments,
                            ..
                        },
                        ControlChoice::Branch(false),
                    ) => Terminator::Jump {
                        target: else_block,
                        arguments: else_arguments,
                    },
                    (
                        Terminator::Switch {
                            cases,
                            default,
                            default_arguments,
                            ..
                        },
                        ControlChoice::Switch(selected),
                    ) => {
                        let mut selected_case = None;
                        for case in cases {
                            work.checkpoint()?;
                            if case.value == selected {
                                selected_case = Some(case);
                                break;
                            }
                        }
                        selected_case.map_or(
                            Terminator::Jump {
                                target: default,
                                arguments: default_arguments,
                            },
                            |case| Terminator::Jump {
                                target: case.target,
                                arguments: case.arguments,
                            },
                        )
                    }
                    _ => {
                        return proof_violation(
                            CONTROL_SIMPLIFY_PASS,
                            "control-flow choice no longer matches its terminator",
                        );
                    }
                };
                decisions.push(
                    CONTROL_SIMPLIFY_PASS,
                    block_subject(function.id.0, block.id.0)?,
                    DecisionKind::Folded,
                    "replaced a constant branch or switch with its uniquely selected edge",
                    Vec::new(),
                )?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

#[derive(Debug, Clone, Copy)]
enum ControlChoice {
    Branch(bool),
    Switch(u128),
}

fn eliminate_unreachable_blocks(
    wir: &mut FlowWir,
    decisions: &mut DecisionSink,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    let mut changed = false;
    for function in &mut wir.functions {
        work.checkpoint()?;
        let reachable = reachable_blocks(function, limits, work)?;
        if all_retained(&reachable, work)? {
            continue;
        }
        for (index, reachable) in reachable.iter().copied().enumerate() {
            work.checkpoint()?;
            if !reachable {
                decisions.push(
                    UNREACHABLE_PASS,
                    block_subject(function.id.0, index_as_u32(index, "FlowWir blocks", limits.blocks)?)?,
                    DecisionKind::Removed,
                    "removed a block with no path from the function entry after control-flow simplification",
                    Vec::new(),
                )?;
            }
        }
        compact_function(function, &reachable, None, limits, work)?;
        changed = true;
    }
    Ok(changed)
}

fn reachable_blocks(
    function: &FlowFunction,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<Vec<bool>, OptimizeError> {
    let mut reachable = filled_vec(
        function.blocks.len(),
        false,
        "optimizer temporary blocks",
        limits.blocks,
    )?;
    let mut pending = Vec::new();
    reserve_items(
        &mut pending,
        function.blocks.len(),
        "optimizer temporary blocks",
        limits.blocks,
    )?;
    let Some(entry) = reachable.get_mut(function.entry.0 as usize) else {
        return proof_violation(UNREACHABLE_PASS, "function entry is an unknown block");
    };
    *entry = true;
    pending.push(function.entry);
    while let Some(block) = pending.pop() {
        work.checkpoint()?;
        let index = block.0 as usize;
        let Some(block) = function.blocks.get(index) else {
            return proof_violation(UNREACHABLE_PASS, "encountered an unknown block record");
        };
        let mut invalid_edge = false;
        for_each_edge(&block.terminator, work, |successor| {
            let Some(mark) = reachable.get_mut(successor.0 as usize) else {
                invalid_edge = true;
                return;
            };
            if !std::mem::replace(mark, true) {
                pending.push(successor);
            }
        })?;
        if invalid_edge {
            return proof_violation(UNREACHABLE_PASS, "encountered an unknown block edge");
        }
    }
    Ok(reachable)
}

fn eliminate_proven_true_checks(
    wir: &mut FlowWir,
    decisions: &mut DecisionSink,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    let mut changed = false;
    let types = &wir.types;
    for function in &mut wir.functions {
        work.checkpoint()?;
        let mut constants = filled_vec(
            function.values.len(),
            None,
            "optimizer temporary values",
            limits.values,
        )?;
        seed_immediates(function, types, &mut constants, work)?;
        let instruction_total = function_instruction_count(function, work)?;
        let instruction_total =
            usize::try_from(instruction_total).map_err(|_| OptimizeError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: limits.instructions,
            })?;
        let mut removed = filled_vec(
            instruction_total,
            false,
            "optimizer temporary instructions",
            limits.instructions,
        )?;
        let mut function_changed = false;
        for block in &function.blocks {
            work.checkpoint()?;
            for instruction in &block.instructions {
                work.checkpoint()?;
                let FlowOperation::Check {
                    condition, proof, ..
                } = instruction.operation
                else {
                    continue;
                };
                if constant(condition, &constants) != Some(ScalarConstant::Bool(true)) {
                    continue;
                }
                let Some(slot) = removed.get_mut(instruction.id.0 as usize) else {
                    return proof_violation(
                        PROVEN_TRUE_CHECK_PASS,
                        "check instruction ID is not dense",
                    );
                };
                *slot = true;
                let mut relied_on = Vec::new();
                if let Some(proof) = proof {
                    reserve_items(
                        &mut relied_on,
                        1,
                        "optimization proof links",
                        u64::from(limits.proofs),
                    )?;
                    relied_on.push(proof);
                }
                decisions.push(
                    PROVEN_TRUE_CHECK_PASS,
                    instruction_subject(function.id.0, instruction.id.0)?,
                    DecisionKind::Removed,
                    "removed a check whose canonical Boolean condition proves its failure edge unreachable",
                    relied_on,
                )?;
                function_changed = true;
            }
        }
        if function_changed {
            let keep_blocks = filled_vec(
                function.blocks.len(),
                true,
                "optimizer temporary blocks",
                limits.blocks,
            )?;
            compact_function(function, &keep_blocks, Some(&removed), limits, work)?;
            changed = true;
        }
    }
    Ok(changed)
}

#[allow(clippy::too_many_lines)]
fn eliminate_dead_pure_instructions(
    wir: &mut FlowWir,
    decisions: &mut DecisionSink,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    let mut changed = false;
    let types = &wir.types;
    for function in &mut wir.functions {
        work.checkpoint()?;
        let instruction_total = function_instruction_count(function, work)?;
        let instruction_total_usize =
            usize::try_from(instruction_total).map_err(|_| OptimizeError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: limits.instructions,
            })?;
        let mut use_counts = filled_vec(
            function.values.len(),
            0u64,
            "optimizer temporary values",
            limits.values,
        )?;
        let mut definitions = filled_vec(
            function.values.len(),
            None,
            "optimizer temporary values",
            limits.values,
        )?;
        let mut locations = filled_vec(
            instruction_total_usize,
            None,
            "optimizer temporary instructions",
            limits.instructions,
        )?;

        for (block_index, block) in function.blocks.iter().enumerate() {
            work.checkpoint()?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                work.checkpoint()?;
                let id = instruction.id.0 as usize;
                let Some(location) = locations.get_mut(id) else {
                    return proof_violation(DEAD_PURE_PASS, "instruction IDs are not dense");
                };
                *location = Some((block_index, instruction_index));
                for result in &instruction.results {
                    work.checkpoint()?;
                    let Some(definition) = definitions.get_mut(result.0 as usize) else {
                        return proof_violation(
                            DEAD_PURE_PASS,
                            "instruction defines an unknown value",
                        );
                    };
                    *definition = Some(instruction.id.0);
                }
                charge_operation_uses(&instruction.operation, &mut use_counts, work)?;
            }
            charge_terminator_uses(&block.terminator, &mut use_counts, work)?;
        }

        let mut removed = filled_vec(
            instruction_total_usize,
            false,
            "optimizer temporary instructions",
            limits.instructions,
        )?;
        let mut queued = filled_vec(
            instruction_total_usize,
            false,
            "optimizer temporary instructions",
            limits.instructions,
        )?;
        let mut pending = Vec::new();
        reserve_items(
            &mut pending,
            instruction_total_usize,
            "optimizer temporary instructions",
            limits.instructions,
        )?;
        for block in &function.blocks {
            work.checkpoint()?;
            for instruction in &block.instructions {
                work.checkpoint()?;
                if removable_when_dead(instruction, function, types)
                    && results_are_dead(instruction, &use_counts)?
                {
                    queued[instruction.id.0 as usize] = true;
                    pending.push(instruction.id.0);
                }
            }
        }

        while let Some(instruction_id) = pending.pop() {
            work.checkpoint()?;
            let removed_slot = removed.get_mut(instruction_id as usize).ok_or_else(|| {
                OptimizeError::ProofViolation {
                    pass: DEAD_PURE_PASS.to_owned(),
                    detail: "dead-instruction worklist contains an unknown instruction".to_owned(),
                }
            })?;
            if *removed_slot {
                continue;
            }
            let instruction = instruction_at(function, &locations, instruction_id)?;
            if !removable_when_dead(instruction, function, types)
                || !results_are_dead(instruction, &use_counts)?
            {
                continue;
            }
            *removed_slot = true;
            let mut use_accounting_failed = false;
            for_each_operation_value(&instruction.operation, work, |operand| {
                let Some(count) = use_counts.get_mut(operand.0 as usize) else {
                    use_accounting_failed = true;
                    return;
                };
                let Some(next) = count.checked_sub(1) else {
                    use_accounting_failed = true;
                    return;
                };
                *count = next;
            })?;
            if use_accounting_failed {
                return proof_violation(
                    DEAD_PURE_PASS,
                    "dead-instruction operand use accounting underflowed",
                );
            }
            let mut dependency_lookup_failed = false;
            for_each_operation_value(&instruction.operation, work, |operand| {
                if use_counts.get(operand.0 as usize) != Some(&0) {
                    return;
                }
                let Some(Some(definition)) = definitions.get(operand.0 as usize) else {
                    return;
                };
                let definition_index = *definition as usize;
                let Some(already_queued) = queued.get_mut(definition_index) else {
                    dependency_lookup_failed = true;
                    return;
                };
                if *already_queued {
                    return;
                }
                let Ok(definition_instruction) = instruction_at(function, &locations, *definition)
                else {
                    dependency_lookup_failed = true;
                    return;
                };
                let Ok(is_dead) = results_are_dead(definition_instruction, &use_counts) else {
                    dependency_lookup_failed = true;
                    return;
                };
                if removable_when_dead(definition_instruction, function, types) && is_dead {
                    *already_queued = true;
                    pending.push(*definition);
                }
            })?;
            if dependency_lookup_failed {
                return proof_violation(
                    DEAD_PURE_PASS,
                    "dead-instruction dependency lookup failed",
                );
            }
        }

        let mut function_changed = false;
        for block in &function.blocks {
            work.checkpoint()?;
            for instruction in &block.instructions {
                work.checkpoint()?;
                if removed.get(instruction.id.0 as usize) == Some(&true) {
                    decisions.push(
                        DEAD_PURE_PASS,
                        instruction_subject(function.id.0, instruction.id.0)?,
                        DecisionKind::Removed,
                        "removed a result-dead scalar instruction proven free of traps and observable effects",
                        Vec::new(),
                    )?;
                    function_changed = true;
                } else {
                    let proofs = operation_proofs(&instruction.operation, limits)?;
                    if !proofs.is_empty() {
                        decisions.push(
                            DEAD_PURE_PASS,
                            instruction_subject(function.id.0, instruction.id.0)?,
                            DecisionKind::Retained,
                            "retained a proof-constrained operation without changing its safety obligation",
                            proofs,
                        )?;
                    } else if !instruction.results.is_empty()
                        && results_are_dead(instruction, &use_counts)?
                        && !removable_when_dead(instruction, function, types)
                    {
                        decisions.push(
                            DEAD_PURE_PASS,
                            instruction_subject(function.id.0, instruction.id.0)?,
                            DecisionKind::Retained,
                            "retained a result-dead operation because it may trap or has observable ownership, memory, runtime, or device effects",
                            Vec::new(),
                        )?;
                    }
                }
            }
        }
        if function_changed {
            let keep_blocks = filled_vec(
                function.blocks.len(),
                true,
                "optimizer temporary blocks",
                limits.blocks,
            )?;
            compact_function(function, &keep_blocks, Some(&removed), limits, work)?;
            changed = true;
        }
    }
    Ok(changed)
}

#[allow(clippy::too_many_lines)]
fn removable_when_dead(
    instruction: &Instruction,
    function: &FlowFunction,
    types: &[FlowType],
) -> bool {
    let Some(result) = single_result(instruction) else {
        return false;
    };
    let Some(result_record) = function.values.get(result.0 as usize) else {
        return false;
    };
    let Some(result_type) = types.get(result_record.ty.0 as usize) else {
        return false;
    };
    if !result_type.copyable || result_type.strict_linear {
        return false;
    }

    let value_type = |value: ValueId| {
        function
            .values
            .get(value.0 as usize)
            .and_then(|value| types.get(value.ty.0 as usize))
    };
    match &instruction.operation {
        FlowOperation::Immediate(immediate) => match (immediate, &result_type.kind) {
            (Immediate::Unit, FlowTypeKind::Unit)
            | (Immediate::Bool(_), FlowTypeKind::Scalar(ScalarType::Bool))
            | (Immediate::Float32(_), FlowTypeKind::Scalar(ScalarType::Float32))
            | (Immediate::Float64(_), FlowTypeKind::Scalar(ScalarType::Float64))
            | (
                Immediate::GlobalAddress(_) | Immediate::FunctionAddress(_),
                FlowTypeKind::Scalar(ScalarType::Address),
            ) => true,
            (Immediate::Integer { .. }, FlowTypeKind::Scalar(ScalarType::Integer { .. })) => {
                constant_from_immediate(immediate, result_record.ty, types).is_some()
            }
            (Immediate::Zero(ty), FlowTypeKind::Unit | FlowTypeKind::Scalar(_)) => {
                *ty == result_record.ty
            }
            _ => false,
        },
        FlowOperation::Unary { op, value } => {
            let Some(operand_type) = value_type(*value) else {
                return false;
            };
            operand_type.id == result_type.id
                && matches!(
                    (op, &result_type.kind),
                    (UnaryOp::BoolNot, FlowTypeKind::Scalar(ScalarType::Bool))
                        | (
                            UnaryOp::BitNot,
                            FlowTypeKind::Scalar(ScalarType::Integer { .. })
                        )
                        | (
                            UnaryOp::Negate,
                            FlowTypeKind::Scalar(ScalarType::Float32 | ScalarType::Float64)
                        )
                )
        }
        FlowOperation::Binary { op, left, right } => {
            let (Some(left_type), Some(right_type)) = (value_type(*left), value_type(*right))
            else {
                return false;
            };
            if left_type.id != right_type.id {
                return false;
            }
            match op {
                BinaryOp::AddWrapping
                | BinaryOp::SubWrapping
                | BinaryOp::MulWrapping
                | BinaryOp::BitAnd
                | BinaryOp::BitOr
                | BinaryOp::BitXor => {
                    left_type.id == result_type.id
                        && matches!(
                            &left_type.kind,
                            FlowTypeKind::Scalar(ScalarType::Integer { .. })
                        )
                }
                BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual => {
                    matches!(&result_type.kind, FlowTypeKind::Scalar(ScalarType::Bool))
                        && matches!(
                            &left_type.kind,
                            FlowTypeKind::Scalar(
                                ScalarType::Bool
                                    | ScalarType::Integer { .. }
                                    | ScalarType::Float32
                                    | ScalarType::Float64
                            )
                        )
                }
                BinaryOp::AddChecked
                | BinaryOp::SubChecked
                | BinaryOp::MulChecked
                | BinaryOp::DivChecked
                | BinaryOp::RemChecked
                | BinaryOp::ShiftLeftChecked
                | BinaryOp::ShiftLeftWrapping
                | BinaryOp::ShiftRightChecked => false,
            }
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            matches!(
                value_type(*condition).map(|ty| &ty.kind),
                Some(FlowTypeKind::Scalar(ScalarType::Bool))
            ) && value_type(*then_value).map(|ty| ty.id) == Some(result_type.id)
                && value_type(*else_value).map(|ty| ty.id) == Some(result_type.id)
                && matches!(
                    &result_type.kind,
                    FlowTypeKind::Unit | FlowTypeKind::Scalar(_)
                )
        }
        _ => false,
    }
}

fn operation_proofs(
    operation: &FlowOperation,
    limits: OptimizationLimits,
) -> Result<Vec<ProofId>, OptimizeError> {
    let proof = match operation {
        FlowOperation::BeginAccess { proof, .. }
        | FlowOperation::Load { proof, .. }
        | FlowOperation::Store { proof, .. }
        | FlowOperation::Allocate { proof, .. }
        | FlowOperation::ActorReserve { proof, .. }
        | FlowOperation::TaskAcquireSlot { proof, .. }
        | FlowOperation::Checkpoint { proof, .. }
        | FlowOperation::DmaTransition { proof, .. }
        | FlowOperation::QueueReserve { proof, .. }
        | FlowOperation::ValidateDeviceValue { proof, .. } => Some(*proof),
        FlowOperation::Check { proof, .. } => *proof,
        _ => None,
    };
    let mut proofs = Vec::new();
    if let Some(proof) = proof {
        reserve_items(
            &mut proofs,
            1,
            "optimization proof reliance",
            u64::from(limits.proofs),
        )?;
        proofs.push(proof);
    }
    Ok(proofs)
}

fn results_are_dead(instruction: &Instruction, use_counts: &[u64]) -> Result<bool, OptimizeError> {
    for result in &instruction.results {
        let Some(count) = use_counts.get(result.0 as usize) else {
            return proof_violation(DEAD_PURE_PASS, "instruction result is an unknown value");
        };
        if *count != 0 {
            return Ok(false);
        }
    }
    Ok(!instruction.results.is_empty())
}

fn instruction_at<'a>(
    function: &'a FlowFunction,
    locations: &[Option<(usize, usize)>],
    id: u32,
) -> Result<&'a Instruction, OptimizeError> {
    let (block, instruction) = locations
        .get(id as usize)
        .copied()
        .flatten()
        .ok_or_else(|| OptimizeError::ProofViolation {
            pass: DEAD_PURE_PASS.to_owned(),
            detail: "instruction lookup failed during dead-code elimination".to_owned(),
        })?;
    function
        .blocks
        .get(block)
        .and_then(|block| block.instructions.get(instruction))
        .ok_or_else(|| OptimizeError::ProofViolation {
            pass: DEAD_PURE_PASS.to_owned(),
            detail: "instruction location was not stable during dead-code elimination".to_owned(),
        })
}

fn charge_operation_uses(
    operation: &FlowOperation,
    use_counts: &mut [u64],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let mut invalid = false;
    let mut overflow = false;
    let mut uses = 0u64;
    for_each_operation_value(operation, work, |value| {
        let Some(next_uses) = uses.checked_add(1) else {
            overflow = true;
            return;
        };
        uses = next_uses;
        let Some(count) = use_counts.get_mut(value.0 as usize) else {
            invalid = true;
            return;
        };
        let Some(next) = count.checked_add(1) else {
            overflow = true;
            return;
        };
        *count = next;
    })?;
    if invalid || overflow {
        return proof_violation(DEAD_PURE_PASS, "operation use accounting overflowed");
    }
    Ok(())
}

fn charge_terminator_uses(
    terminator: &Terminator,
    use_counts: &mut [u64],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let mut invalid = false;
    let mut overflow = false;
    let mut uses = 0u64;
    for_each_terminator_value(terminator, work, |value| {
        let Some(next_uses) = uses.checked_add(1) else {
            overflow = true;
            return;
        };
        uses = next_uses;
        let Some(count) = use_counts.get_mut(value.0 as usize) else {
            invalid = true;
            return;
        };
        let Some(next) = count.checked_add(1) else {
            overflow = true;
            return;
        };
        *count = next;
    })?;
    if invalid || overflow {
        return proof_violation(DEAD_PURE_PASS, "terminator use accounting overflowed");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn compact_function(
    function: &mut FlowFunction,
    keep_blocks: &[bool],
    removed_instructions: Option<&[bool]>,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    if keep_blocks.len() != function.blocks.len() {
        return proof_violation(
            "compaction",
            "block keep-set length does not match the function",
        );
    }
    let mut block_map = filled_vec(
        function.blocks.len(),
        None,
        "optimizer temporary blocks",
        limits.blocks,
    )?;
    let mut next_block = 0u32;
    for (index, keep) in keep_blocks.iter().copied().enumerate() {
        work.checkpoint()?;
        if keep {
            block_map[index] = Some(BlockId(next_block));
            next_block = next_block
                .checked_add(1)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "FlowWir blocks",
                    limit: limits.blocks,
                })?;
        }
    }

    let mut keep_values = filled_vec(
        function.values.len(),
        false,
        "optimizer temporary values",
        limits.values,
    )?;
    for parameter in &function.parameters {
        work.checkpoint()?;
        mark_value(*parameter, &mut keep_values, "function parameter")?;
    }
    for (block_index, block) in function.blocks.iter().enumerate() {
        work.checkpoint()?;
        if !keep_blocks[block_index] {
            continue;
        }
        for parameter in &block.parameters {
            work.checkpoint()?;
            mark_value(*parameter, &mut keep_values, "block parameter")?;
        }
        for instruction in &block.instructions {
            work.checkpoint()?;
            if removed_instructions.and_then(|removed| removed.get(instruction.id.0 as usize))
                == Some(&true)
            {
                continue;
            }
            for result in &instruction.results {
                work.checkpoint()?;
                mark_value(*result, &mut keep_values, "instruction result")?;
            }
        }
    }

    let mut value_map = filled_vec(
        function.values.len(),
        None,
        "optimizer temporary values",
        limits.values,
    )?;
    let retained_values = count_retained(&keep_values, "FlowWir values", limits.values, work)?;
    let mut values = Vec::new();
    reserve_items(
        &mut values,
        retained_values,
        "FlowWir values",
        limits.values,
    )?;
    for (index, mut value) in std::mem::take(&mut function.values).into_iter().enumerate() {
        work.checkpoint()?;
        if !keep_values[index] {
            continue;
        }
        let new_id = ValueId(index_as_u32(values.len(), "FlowWir values", limits.values)?);
        value_map[index] = Some(new_id);
        value.id = new_id;
        values.push(value);
    }
    function.values = values;
    map_value_slice(
        &mut function.parameters,
        &value_map,
        "function parameters",
        work,
    )?;
    function.entry = map_block(function.entry, &block_map, work)?;

    let retained_blocks = count_retained(keep_blocks, "FlowWir blocks", limits.blocks, work)?;
    let mut blocks = Vec::new();
    reserve_items(
        &mut blocks,
        retained_blocks,
        "FlowWir blocks",
        limits.blocks,
    )?;
    let mut next_instruction = 0u32;
    for (block_index, mut block) in std::mem::take(&mut function.blocks).into_iter().enumerate() {
        work.checkpoint()?;
        if !keep_blocks[block_index] {
            continue;
        }
        block.id = block_map[block_index].ok_or_else(|| OptimizeError::ProofViolation {
            pass: "compaction".to_owned(),
            detail: "retained block has no dense remapping".to_owned(),
        })?;
        map_value_slice(&mut block.parameters, &value_map, "block parameters", work)?;
        let mut retained_instructions = 0usize;
        for instruction in &block.instructions {
            work.checkpoint()?;
            if removed_instructions.and_then(|removed| removed.get(instruction.id.0 as usize))
                != Some(&true)
            {
                retained_instructions =
                    retained_instructions
                        .checked_add(1)
                        .ok_or(OptimizeError::ResourceLimit {
                            resource: "FlowWir instructions",
                            limit: limits.instructions,
                        })?;
            }
        }
        let mut instructions = Vec::new();
        reserve_items(
            &mut instructions,
            retained_instructions,
            "FlowWir instructions",
            limits.instructions,
        )?;
        for mut instruction in std::mem::take(&mut block.instructions) {
            work.checkpoint()?;
            if removed_instructions.and_then(|removed| removed.get(instruction.id.0 as usize))
                == Some(&true)
            {
                continue;
            }
            instruction.id = InstructionId(next_instruction);
            next_instruction =
                next_instruction
                    .checked_add(1)
                    .ok_or(OptimizeError::ResourceLimit {
                        resource: "FlowWir instructions",
                        limit: limits.instructions,
                    })?;
            map_value_slice(
                &mut instruction.results,
                &value_map,
                "instruction results",
                work,
            )?;
            map_operation_values(&mut instruction.operation, &value_map, work)?;
            instructions.push(instruction);
        }
        block.instructions = instructions;
        map_terminator(&mut block.terminator, &value_map, &block_map, work)?;
        blocks.push(block);
    }
    function.blocks = blocks;
    Ok(())
}

fn mark_value(
    value: ValueId,
    keep_values: &mut [bool],
    context: &'static str,
) -> Result<(), OptimizeError> {
    let Some(keep) = keep_values.get_mut(value.0 as usize) else {
        return Err(OptimizeError::ProofViolation {
            pass: "compaction".to_owned(),
            detail: format!("{context} refers to an unknown value"),
        });
    };
    *keep = true;
    Ok(())
}

fn map_value(
    value: &mut ValueId,
    value_map: &[Option<ValueId>],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    work.checkpoint()?;
    *value = value_map
        .get(value.0 as usize)
        .copied()
        .flatten()
        .ok_or_else(|| OptimizeError::ProofViolation {
            pass: "compaction".to_owned(),
            detail: "retained operation refers to a removed value".to_owned(),
        })?;
    Ok(())
}

fn map_value_slice(
    values: &mut [ValueId],
    value_map: &[Option<ValueId>],
    _context: &'static str,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    for value in values {
        map_value(value, value_map, work)?;
    }
    Ok(())
}

fn map_block(
    block: BlockId,
    block_map: &[Option<BlockId>],
    work: &mut WorkMeter<'_>,
) -> Result<BlockId, OptimizeError> {
    work.checkpoint()?;
    block_map
        .get(block.0 as usize)
        .copied()
        .flatten()
        .ok_or_else(|| OptimizeError::ProofViolation {
            pass: "compaction".to_owned(),
            detail: "retained control-flow edge refers to a removed block".to_owned(),
        })
}

#[allow(clippy::too_many_lines)]
fn map_operation_values(
    operation: &mut FlowOperation,
    value_map: &[Option<ValueId>],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    match operation {
        FlowOperation::Immediate(_)
        | FlowOperation::RegionReset { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::MmioRead { .. }
        | FlowOperation::Fence { .. } => {}
        FlowOperation::Unary { value, .. }
        | FlowOperation::Cast { value, .. }
        | FlowOperation::EnumTag { value }
        | FlowOperation::EnumPayload { value }
        | FlowOperation::ExtractField {
            aggregate: value, ..
        }
        | FlowOperation::EndAccess { access: value }
        | FlowOperation::Load { address: value, .. }
        | FlowOperation::Move { value }
        | FlowOperation::Copy { value }
        | FlowOperation::Drop { value }
        | FlowOperation::ActorReject { reservation: value }
        | FlowOperation::TaskCancel { task: value }
        | FlowOperation::Park { wait_set: value }
        | FlowOperation::Wake { target: value }
        | FlowOperation::InterruptRestore { token: value }
        | FlowOperation::ValidateDeviceValue { value, .. }
        | FlowOperation::Check {
            condition: value, ..
        }
        | FlowOperation::Assert {
            condition: value, ..
        }
        | FlowOperation::RecordEvent { payload: value, .. }
        | FlowOperation::ReplayEvent {
            destination: value, ..
        }
        | FlowOperation::TestEmit { payload: value }
        | FlowOperation::TestFinish { outcome: value }
        | FlowOperation::MmioWrite { value, .. } => map_value(value, value_map, work)?,
        FlowOperation::Binary { left, right, .. } => {
            map_value(left, value_map, work)?;
            map_value(right, value_map, work)?;
        }
        FlowOperation::MakeAggregate { fields, .. } => {
            map_value_slice(fields, value_map, "aggregate", work)?;
        }
        FlowOperation::MakeEnum { payload, .. } => map_value(payload, value_map, work)?,
        FlowOperation::InsertField {
            aggregate, value, ..
        }
        | FlowOperation::Store {
            address: aggregate,
            value,
            ..
        }
        | FlowOperation::ReplyResolve {
            endpoint: aggregate,
            outcome: value,
        }
        | FlowOperation::ReceiptCommit {
            receipt: aggregate,
            payload: value,
        }
        | FlowOperation::ReceiptResolve {
            receipt: aggregate,
            outcome: value,
        }
        | FlowOperation::InterruptPublish {
            cell: aggregate,
            value,
        }
        | FlowOperation::QueuePublish {
            reservation: aggregate,
            payload: value,
        } => {
            map_value(aggregate, value_map, work)?;
            map_value(value, value_map, work)?;
        }
        FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            map_value(reservation, value_map, work)?;
            map_value_slice(arguments, value_map, "actor commit arguments", work)?;
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            map_value(condition, value_map, work)?;
            map_value(then_value, value_map, work)?;
            map_value(else_value, value_map, work)?;
        }
        FlowOperation::BeginAccess { place, .. } => map_value(place, value_map, work)?,
        FlowOperation::Call { arguments, .. } | FlowOperation::AsyncCall { arguments, .. } => {
            map_value_slice(arguments, value_map, "call", work)?;
        }
        FlowOperation::Allocate { count, .. } => map_value(count, value_map, work)?,
        FlowOperation::TaskStart {
            slot, arguments, ..
        } => {
            map_value(slot, value_map, work)?;
            map_value_slice(arguments, value_map, "task start", work)?;
        }
        FlowOperation::DmaTransition { token, .. } => map_value(token, value_map, work)?,
        FlowOperation::QueueReserve { descriptors, .. } => {
            map_value(descriptors, value_map, work)?;
        }
    }
    Ok(())
}

fn map_terminator(
    terminator: &mut Terminator,
    value_map: &[Option<ValueId>],
    block_map: &[Option<BlockId>],
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    match terminator {
        Terminator::Jump { target, arguments } => {
            *target = map_block(*target, block_map, work)?;
            map_value_slice(arguments, value_map, "jump", work)?;
        }
        Terminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => {
            map_value(condition, value_map, work)?;
            *then_block = map_block(*then_block, block_map, work)?;
            *else_block = map_block(*else_block, block_map, work)?;
            map_value_slice(then_arguments, value_map, "branch", work)?;
            map_value_slice(else_arguments, value_map, "branch", work)?;
        }
        Terminator::Switch {
            value,
            cases,
            default,
            default_arguments,
        } => {
            map_value(value, value_map, work)?;
            for case in cases {
                case.target = map_block(case.target, block_map, work)?;
                map_value_slice(&mut case.arguments, value_map, "switch", work)?;
            }
            *default = map_block(*default, block_map, work)?;
            map_value_slice(default_arguments, value_map, "switch", work)?;
        }
        Terminator::Return(values) => map_value_slice(values, value_map, "return", work)?,
        Terminator::Suspend {
            resume, activation, ..
        } => {
            *resume = map_block(*resume, block_map, work)?;
            map_value(activation, value_map, work)?;
        }
        Terminator::TailCall { arguments, .. } => {
            map_value_slice(arguments, value_map, "tail call", work)?;
        }
        Terminator::Trap { detail, .. } => {
            if let Some(detail) = detail {
                map_value(detail, value_map, work)?;
            }
        }
        Terminator::Unreachable => {}
    }
    Ok(())
}

fn verify_after_pass(
    wir: &FlowWir,
    profile: &OptimizationProfile,
    limits: OptimizationLimits,
    pass: &'static str,
    require_reachable: bool,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    if !profile.verify_after_each_pass {
        return Ok(());
    }
    for function in &wir.functions {
        work.checkpoint()?;
        if function.entry.0 as usize >= function.blocks.len() {
            return proof_violation(pass, "function entry is not a known block");
        }
        let mut definitions = filled_vec(
            function.values.len(),
            0u8,
            "optimizer verification values",
            limits.values,
        )?;
        for (expected, value) in function.values.iter().enumerate() {
            work.checkpoint()?;
            if value.id.0 as usize != expected {
                return proof_violation(pass, "value IDs are not dense");
            }
        }
        for parameter in &function.parameters {
            work.checkpoint()?;
            define_verified_value(*parameter, &mut definitions, pass)?;
        }
        let mut expected_instruction = 0u32;
        for (expected_block, block) in function.blocks.iter().enumerate() {
            work.checkpoint()?;
            if block.id.0 as usize != expected_block {
                return proof_violation(pass, "block IDs are not dense");
            }
            for parameter in &block.parameters {
                work.checkpoint()?;
                define_verified_value(*parameter, &mut definitions, pass)?;
            }
            for instruction in &block.instructions {
                work.checkpoint()?;
                if instruction.id.0 != expected_instruction {
                    return proof_violation(pass, "instruction IDs are not dense");
                }
                expected_instruction =
                    expected_instruction
                        .checked_add(1)
                        .ok_or(OptimizeError::ResourceLimit {
                            resource: "FlowWir instructions",
                            limit: limits.instructions,
                        })?;
                for result in &instruction.results {
                    work.checkpoint()?;
                    define_verified_value(*result, &mut definitions, pass)?;
                }
                verify_operation_references(
                    &instruction.operation,
                    function,
                    wir,
                    pass,
                    limits,
                    work,
                )?;
            }
            verify_terminator_references(&block.terminator, function, pass, work)?;
        }
        for count in &definitions {
            work.checkpoint()?;
            if *count != 1 {
                return proof_violation(pass, "a value does not have exactly one definition");
            }
        }
        if require_reachable {
            let reachable = reachable_blocks(function, limits, work)?;
            if !all_retained(&reachable, work)? {
                return proof_violation(pass, "the pass left an unreachable block");
            }
        }
    }
    Ok(())
}

fn define_verified_value(
    value: ValueId,
    definitions: &mut [u8],
    pass: &'static str,
) -> Result<(), OptimizeError> {
    let Some(count) = definitions.get_mut(value.0 as usize) else {
        return proof_violation(pass, "a definition names an unknown value");
    };
    *count = count
        .checked_add(1)
        .ok_or_else(|| OptimizeError::ProofViolation {
            pass: pass.to_owned(),
            detail: "value definition count overflowed".to_owned(),
        })?;
    Ok(())
}

fn verify_operation_references(
    operation: &FlowOperation,
    function: &FlowFunction,
    wir: &FlowWir,
    pass: &'static str,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let mut invalid_value = false;
    for_each_operation_value(operation, work, |value| {
        invalid_value |= value.0 as usize >= function.values.len();
    })?;
    if invalid_value {
        return proof_violation(pass, "an operation names an unknown value");
    }
    for proof in operation_proofs(operation, limits)? {
        if proof.0 as usize >= wir.proofs.len() {
            return proof_violation(pass, "an operation names an unknown proof");
        }
    }
    Ok(())
}

fn verify_terminator_references(
    terminator: &Terminator,
    function: &FlowFunction,
    pass: &'static str,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let mut invalid_value = false;
    for_each_terminator_value(terminator, work, |value| {
        invalid_value |= value.0 as usize >= function.values.len();
    })?;
    let mut invalid_block = false;
    for_each_edge(terminator, work, |block| {
        invalid_block |= block.0 as usize >= function.blocks.len();
    })?;
    if invalid_value || invalid_block {
        return proof_violation(pass, "a terminator names an unknown value or block");
    }
    Ok(())
}

fn single_result(instruction: &Instruction) -> Option<ValueId> {
    match instruction.results.as_slice() {
        [result] => Some(*result),
        _ => None,
    }
}

fn instruction_count(wir: &FlowWir, work: &mut WorkMeter<'_>) -> Result<u64, OptimizeError> {
    let mut total = 0u64;
    for function in &wir.functions {
        work.checkpoint()?;
        let function_count = function_instruction_count(function, work)?;
        total = total
            .checked_add(function_count)
            .ok_or(OptimizeError::InvalidReport("instruction count overflowed"))?;
    }
    Ok(total)
}

fn function_instruction_count(
    function: &FlowFunction,
    work: &mut WorkMeter<'_>,
) -> Result<u64, OptimizeError> {
    let mut total = 0u64;
    for block in &function.blocks {
        work.checkpoint()?;
        let count = u64::try_from(block.instructions.len())
            .map_err(|_| OptimizeError::InvalidReport("instruction count overflowed"))?;
        total = total
            .checked_add(count)
            .ok_or(OptimizeError::InvalidReport("instruction count overflowed"))?;
    }
    Ok(total)
}

fn reserve_items<T>(
    values: &mut Vec<T>,
    count: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), OptimizeError> {
    ensure_limit(length_as_u64(count, resource, limit)?, resource, limit)?;
    values
        .try_reserve_exact(count)
        .map_err(|_| OptimizeError::ResourceLimit { resource, limit })
}

fn filled_vec<T: Clone>(
    length: usize,
    value: T,
    resource: &'static str,
    limit: u64,
) -> Result<Vec<T>, OptimizeError> {
    let mut values = Vec::new();
    reserve_items(&mut values, length, resource, limit)?;
    values.resize(length, value);
    Ok(values)
}

fn report_text(value: &str, limits: OptimizationLimits) -> Result<String, OptimizeError> {
    ensure_limit(
        length_as_u64(
            value.len(),
            "optimization report bytes",
            limits.report_bytes,
        )?,
        "optimization report bytes",
        limits.report_bytes,
    )?;
    let mut text = String::new();
    text.try_reserve_exact(value.len())
        .map_err(|_| OptimizeError::ResourceLimit {
            resource: "optimization report bytes",
            limit: limits.report_bytes,
        })?;
    text.push_str(value);
    Ok(text)
}

fn count_retained(
    values: &[bool],
    resource: &'static str,
    limit: u64,
    work: &mut WorkMeter<'_>,
) -> Result<usize, OptimizeError> {
    let mut retained = 0usize;
    for keep in values {
        work.checkpoint()?;
        if *keep {
            retained = retained
                .checked_add(1)
                .ok_or(OptimizeError::ResourceLimit { resource, limit })?;
        }
    }
    ensure_limit(length_as_u64(retained, resource, limit)?, resource, limit)?;
    Ok(retained)
}

fn all_retained(values: &[bool], work: &mut WorkMeter<'_>) -> Result<bool, OptimizeError> {
    for keep in values {
        work.checkpoint()?;
        if !*keep {
            return Ok(false);
        }
    }
    Ok(true)
}

fn index_as_u32(index: usize, resource: &'static str, limit: u64) -> Result<u32, OptimizeError> {
    u32::try_from(index).map_err(|_| OptimizeError::ResourceLimit { resource, limit })
}

fn instruction_subject(function: u32, instruction: u32) -> Result<String, OptimizeError> {
    subject(function, 'i', instruction)
}

fn block_subject(function: u32, block: u32) -> Result<String, OptimizeError> {
    subject(function, 'b', block)
}

fn subject(function: u32, kind: char, id: u32) -> Result<String, OptimizeError> {
    let mut subject = String::new();
    subject
        .try_reserve_exact(32)
        .map_err(|_| OptimizeError::ResourceLimit {
            resource: "optimization report bytes",
            limit: 32,
        })?;
    write!(&mut subject, "f{function}:{kind}{id}").map_err(|_| {
        OptimizeError::InvalidReport("failed to format optimization decision subject")
    })?;
    Ok(subject)
}

fn proof_violation<T>(pass: &'static str, detail: &'static str) -> Result<T, OptimizeError> {
    Err(OptimizeError::ProofViolation {
        pass: pass.to_owned(),
        detail: detail.to_owned(),
    })
}

fn for_each_edge(
    terminator: &Terminator,
    work: &mut WorkMeter<'_>,
    mut visit: impl FnMut(BlockId),
) -> Result<(), OptimizeError> {
    let mut visit_edge = |block| {
        work.checkpoint()?;
        visit(block);
        Ok(())
    };
    match terminator {
        Terminator::Jump { target, .. } => visit_edge(*target)?,
        Terminator::Branch {
            then_block,
            else_block,
            ..
        } => {
            visit_edge(*then_block)?;
            visit_edge(*else_block)?;
        }
        Terminator::Switch { cases, default, .. } => {
            for case in cases {
                visit_edge(case.target)?;
            }
            visit_edge(*default)?;
        }
        Terminator::Suspend { resume, .. } => visit_edge(*resume)?,
        Terminator::Return(_)
        | Terminator::TailCall { .. }
        | Terminator::Trap { .. }
        | Terminator::Unreachable => {}
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn for_each_operation_value(
    operation: &FlowOperation,
    work: &mut WorkMeter<'_>,
    mut visit: impl FnMut(ValueId),
) -> Result<(), OptimizeError> {
    let mut visit_value = |value| {
        work.checkpoint()?;
        visit(value);
        Ok(())
    };
    match operation {
        FlowOperation::Immediate(_)
        | FlowOperation::RegionReset { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::MmioRead { .. }
        | FlowOperation::Fence { .. } => {}
        FlowOperation::Unary { value, .. }
        | FlowOperation::Cast { value, .. }
        | FlowOperation::EnumTag { value }
        | FlowOperation::EnumPayload { value }
        | FlowOperation::ExtractField {
            aggregate: value, ..
        }
        | FlowOperation::EndAccess { access: value }
        | FlowOperation::Load { address: value, .. }
        | FlowOperation::Move { value }
        | FlowOperation::Copy { value }
        | FlowOperation::Drop { value }
        | FlowOperation::ActorReject { reservation: value }
        | FlowOperation::TaskCancel { task: value }
        | FlowOperation::Park { wait_set: value }
        | FlowOperation::Wake { target: value }
        | FlowOperation::InterruptRestore { token: value }
        | FlowOperation::ValidateDeviceValue { value, .. }
        | FlowOperation::Check {
            condition: value, ..
        }
        | FlowOperation::Assert {
            condition: value, ..
        }
        | FlowOperation::RecordEvent { payload: value, .. }
        | FlowOperation::ReplayEvent {
            destination: value, ..
        }
        | FlowOperation::TestEmit { payload: value }
        | FlowOperation::TestFinish { outcome: value }
        | FlowOperation::MmioWrite { value, .. } => visit_value(*value)?,
        FlowOperation::Binary { left, right, .. } => {
            visit_value(*left)?;
            visit_value(*right)?;
        }
        FlowOperation::MakeAggregate { fields, .. } => {
            for value in fields {
                visit_value(*value)?;
            }
        }
        FlowOperation::MakeEnum { payload, .. } => visit_value(*payload)?,
        FlowOperation::InsertField {
            aggregate, value, ..
        }
        | FlowOperation::Store {
            address: aggregate,
            value,
            ..
        }
        | FlowOperation::ReplyResolve {
            endpoint: aggregate,
            outcome: value,
        }
        | FlowOperation::ReceiptCommit {
            receipt: aggregate,
            payload: value,
        }
        | FlowOperation::ReceiptResolve {
            receipt: aggregate,
            outcome: value,
        }
        | FlowOperation::InterruptPublish {
            cell: aggregate,
            value,
        }
        | FlowOperation::QueuePublish {
            reservation: aggregate,
            payload: value,
        } => {
            visit_value(*aggregate)?;
            visit_value(*value)?;
        }
        FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            visit_value(*reservation)?;
            for argument in arguments {
                visit_value(*argument)?;
            }
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            visit_value(*condition)?;
            visit_value(*then_value)?;
            visit_value(*else_value)?;
        }
        FlowOperation::BeginAccess { place, .. } => visit_value(*place)?,
        FlowOperation::Call { arguments, .. } | FlowOperation::AsyncCall { arguments, .. } => {
            for value in arguments {
                visit_value(*value)?;
            }
        }
        FlowOperation::Allocate { count, .. } => visit_value(*count)?,
        FlowOperation::TaskStart {
            slot, arguments, ..
        } => {
            visit_value(*slot)?;
            for value in arguments {
                visit_value(*value)?;
            }
        }
        FlowOperation::DmaTransition { token, .. } => visit_value(*token)?,
        FlowOperation::QueueReserve { descriptors, .. } => visit_value(*descriptors)?,
    }
    Ok(())
}

fn for_each_terminator_value(
    terminator: &Terminator,
    work: &mut WorkMeter<'_>,
    mut visit: impl FnMut(ValueId),
) -> Result<(), OptimizeError> {
    let mut visit_value = |value| {
        work.checkpoint()?;
        visit(value);
        Ok(())
    };
    match terminator {
        Terminator::Jump { arguments, .. }
        | Terminator::Return(arguments)
        | Terminator::TailCall { arguments, .. } => {
            for value in arguments {
                visit_value(*value)?;
            }
        }
        Terminator::Branch {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            visit_value(*condition)?;
            for value in then_arguments.iter().chain(else_arguments) {
                visit_value(*value)?;
            }
        }
        Terminator::Switch {
            value,
            cases,
            default_arguments,
            ..
        } => {
            visit_value(*value)?;
            for case in cases {
                for value in &case.arguments {
                    visit_value(*value)?;
                }
            }
            for value in default_arguments {
                visit_value(*value)?;
            }
        }
        Terminator::Suspend { activation, .. } => visit_value(*activation)?,
        Terminator::Trap { detail, .. } => {
            if let Some(value) = detail {
                visit_value(*value)?;
            }
        }
        Terminator::Unreachable => {}
    }
    Ok(())
}

#[cfg(test)]
mod scalar_semantics_tests {
    use super::{
        ScalarConstant, constant_from_immediate, fold_binary, fold_unary, removable_when_dead,
    };
    use wrela_flow_wir::{
        BinaryOp, BlockId, FlowFunction, FlowType, FlowTypeKind, FunctionColor, FunctionId,
        FunctionOrigin, FunctionRole, Immediate, Instruction, InstructionId, ScalarType, TypeId,
        UnaryOp, Value, ValueId,
    };

    fn ty(id: u32, scalar: ScalarType) -> FlowType {
        FlowType {
            id: TypeId(id),
            kind: FlowTypeKind::Scalar(scalar),
            name: None,
            copyable: true,
            strict_linear: false,
        }
    }

    fn types() -> Vec<FlowType> {
        vec![
            ty(0, ScalarType::Bool),
            ty(
                1,
                ScalarType::Integer {
                    signed: false,
                    bits: 8,
                },
            ),
            ty(
                2,
                ScalarType::Integer {
                    signed: true,
                    bits: 8,
                },
            ),
            ty(3, ScalarType::Float32),
            ty(4, ScalarType::Float64),
            ty(
                5,
                ScalarType::Integer {
                    signed: false,
                    bits: 128,
                },
            ),
            ty(
                6,
                ScalarType::Integer {
                    signed: true,
                    bits: 128,
                },
            ),
        ]
    }

    #[test]
    fn integer_folding_preserves_wrapping_trapping_and_signed_rules() {
        let types = types();
        let unsigned = |value| ScalarConstant::Integer {
            signed: false,
            bits: 8,
            value,
        };
        assert_eq!(
            fold_binary(
                BinaryOp::AddWrapping,
                unsigned(250),
                unsigned(36),
                TypeId(1),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 8,
                bytes_le: vec![30],
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::AddChecked,
                unsigned(250),
                unsigned(36),
                TypeId(1),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                unsigned(1),
                unsigned(8),
                TypeId(1),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                unsigned(0x40),
                unsigned(1),
                TypeId(1),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 8,
                bytes_le: vec![0x80],
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                unsigned(0x80),
                unsigned(1),
                TypeId(1),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                unsigned(0x80),
                unsigned(1),
                TypeId(1),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 8,
                bytes_le: vec![0],
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                unsigned(1),
                unsigned(8),
                TypeId(1),
                &types,
            ),
            None
        );

        let signed = |value| ScalarConstant::Integer {
            signed: true,
            bits: 8,
            value,
        };
        assert_eq!(
            fold_unary(UnaryOp::Negate, signed(0x80), TypeId(2), &types),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::DivChecked,
                signed(0x80),
                signed(0xff),
                TypeId(2),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                signed(0xc0),
                signed(1),
                TypeId(2),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 8,
                bytes_le: vec![0x80],
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                signed(0x40),
                signed(1),
                TypeId(2),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                signed(0x80),
                signed(1),
                TypeId(2),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 8,
                bytes_le: vec![0],
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                signed(1),
                signed(0xff),
                TypeId(2),
                &types,
            ),
            None
        );

        let unsigned_128 = |value| ScalarConstant::Integer {
            signed: false,
            bits: 128,
            value,
        };
        let signed_128 = |value| ScalarConstant::Integer {
            signed: true,
            bits: 128,
            value,
        };
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                unsigned_128(1),
                unsigned_128(127),
                TypeId(5),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 128,
                bytes_le: (1_u128 << 127).to_le_bytes().to_vec(),
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                unsigned_128(1_u128 << 127),
                unsigned_128(1),
                TypeId(5),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                unsigned_128(1_u128 << 127),
                unsigned_128(1),
                TypeId(5),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 128,
                bytes_le: 0_u128.to_le_bytes().to_vec(),
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                unsigned_128(1),
                unsigned_128(128),
                TypeId(5),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                signed_128(3_u128 << 126),
                signed_128(1),
                TypeId(6),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 128,
                bytes_le: (1_u128 << 127).to_le_bytes().to_vec(),
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftChecked,
                signed_128(1_u128 << 126),
                signed_128(1),
                TypeId(6),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                signed_128(1_u128 << 126),
                signed_128(1),
                TypeId(6),
                &types,
            ),
            Some(Immediate::Integer {
                bits: 128,
                bytes_le: (1_u128 << 127).to_le_bytes().to_vec(),
            })
        );
        assert_eq!(
            fold_binary(
                BinaryOp::ShiftLeftWrapping,
                signed_128(1),
                signed_128(u128::MAX),
                TypeId(6),
                &types,
            ),
            None
        );
        assert_eq!(
            fold_binary(BinaryOp::Less, signed(0xff), signed(1), TypeId(0), &types,),
            Some(Immediate::Bool(true))
        );
    }

    #[test]
    fn checked_count_wrapping_shift_is_never_dead_code_eliminated() {
        let types = types();
        let function = FlowFunction {
            id: FunctionId(0),
            name: "shift".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 0,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Sync,
            parameters: vec![ValueId(0), ValueId(1)],
            result_types: vec![TypeId(1)],
            values: (0..3)
                .map(|id| Value {
                    id: ValueId(id),
                    ty: TypeId(1),
                    source_name: None,
                    source: None,
                })
                .collect(),
            blocks: Vec::new(),
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        };
        let mut instruction = Instruction {
            id: InstructionId(0),
            results: vec![ValueId(2)],
            operation: wrela_flow_wir::FlowOperation::Binary {
                op: BinaryOp::ShiftLeftWrapping,
                left: ValueId(0),
                right: ValueId(1),
            },
            source: None,
        };
        assert!(!removable_when_dead(&instruction, &function, &types));
        instruction.operation = wrela_flow_wir::FlowOperation::Binary {
            op: BinaryOp::AddWrapping,
            left: ValueId(0),
            right: ValueId(1),
        };
        assert!(removable_when_dead(&instruction, &function, &types));
    }

    #[test]
    fn floating_nan_comparisons_and_integer_encodings_are_exact() {
        let types = types();
        let nan = ScalarConstant::Float32(f32::NAN.to_bits());
        let one = ScalarConstant::Float32(1.0f32.to_bits());
        assert_eq!(
            fold_binary(BinaryOp::Equal, nan, one, TypeId(0), &types),
            Some(Immediate::Bool(false))
        );
        assert_eq!(
            fold_binary(BinaryOp::NotEqual, nan, one, TypeId(0), &types),
            Some(Immediate::Bool(true))
        );
        assert_eq!(
            fold_unary(
                UnaryOp::Negate,
                ScalarConstant::Float32(0x7fc0_1234),
                TypeId(3),
                &types,
            ),
            Some(Immediate::Float32(0xffc0_1234))
        );
        assert_eq!(
            fold_unary(
                UnaryOp::Negate,
                ScalarConstant::Float64(0x7ff8_0000_0000_1234),
                TypeId(4),
                &types,
            ),
            Some(Immediate::Float64(0xfff8_0000_0000_1234))
        );

        let seven_bit_types = vec![ty(
            0,
            ScalarType::Integer {
                signed: false,
                bits: 7,
            },
        )];
        assert_eq!(
            constant_from_immediate(
                &Immediate::Integer {
                    bits: 7,
                    bytes_le: vec![0xff],
                },
                TypeId(0),
                &seven_bit_types,
            ),
            None
        );
    }
}
