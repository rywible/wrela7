//! Total conversion from a sealed semantic analysis result to specialized,
//! syntax-free SemanticWir.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_sema::AnalyzedImage;
use wrela_semantic_wir::{
    SemanticRegion, SemanticStatement, SemanticWir, ValidatedSemanticWir, ValidationErrors,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
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
    validate_model_resources(&wir, request.limits)?;
    let wir = wir.validate().map_err(LowerError::InvalidOutput)?;
    validate_report(&request.input, &wir, &report, request.limits)?;
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    Ok(LowerOutput { wir, report })
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

fn validate_model_resources(
    wir: &wrela_semantic_wir::SemanticWir,
    limits: LoweringLimits,
) -> Result<(), LowerError> {
    use wrela_semantic_wir::{Constant, SemanticOperation, SemanticStatement, TypeKind};

    let mut meter = ResourceMeter::default();
    meter.text(&wir.name);
    for count in [
        wir.types.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.actors.len(),
        wir.tasks.len(),
        wir.devices.len(),
        wir.pools.len(),
        wir.regions.len(),
        wir.scopes.len(),
        wir.proofs.len(),
        wir.tests.len(),
        wir.startup_order.len(),
        wir.shutdown_order.len(),
    ] {
        meter.add_edges(count);
    }

    for ty in &wir.types {
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
            | TypeKind::Receipt { .. }
            | TypeKind::DmaPayload { .. }
            | TypeKind::DmaShared { .. }
            | TypeKind::Mmio { .. }
            | TypeKind::Validated { .. } => {}
        }
    }

    let mut constants: Vec<(&Constant, u32)> = Vec::new();
    for global in &wir.globals {
        meter.text(&global.name);
        constants.push((&global.initializer, 1));
    }
    for function in &wir.functions {
        meter.text(&function.name);
        meter.edges(&function.parameters);
        meter.edges(&function.values);
        for value in &function.values {
            if let Some(name) = &value.name {
                meter.text(name);
            }
        }
        let mut regions = vec![&function.body];
        while let Some(region) = regions.pop() {
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
                            SemanticOperation::Unary { .. }
                            | SemanticOperation::Binary { .. }
                            | SemanticOperation::Convert { .. }
                            | SemanticOperation::Project { .. }
                            | SemanticOperation::Index { .. }
                            | SemanticOperation::BeginAccess { .. }
                            | SemanticOperation::EndAccess { .. }
                            | SemanticOperation::Move { .. }
                            | SemanticOperation::Copy { .. }
                            | SemanticOperation::Drop { .. }
                            | SemanticOperation::ActorReserve { .. }
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

    for actor in &wir.actors {
        meter.text(&actor.name);
        meter.edges(&actor.message_types);
        meter.edges(&actor.turn_functions);
    }
    for task in &wir.tasks {
        meter.text(&task.name);
    }
    for device in &wir.devices {
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
    for pool in &wir.pools {
        meter.text(&pool.name);
        meter.edges(&pool.reachable_devices);
    }
    for region in &wir.regions {
        meter.text(&region.name);
    }
    for scope in &wir.scopes {
        meter.text(&scope.name);
        meter.edges(&scope.dependencies);
    }
    for proof in &wir.proofs {
        meter.text(&proof.subject);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            meter.text(line);
        }
    }
    for test in &wir.tests {
        meter.text(&test.name);
    }

    if meter.overflowed
        || meter.edges > limits.model_edges
        || meter.payload_bytes > limits.payload_bytes
        || meter.maximum_constant_depth > limits.constant_depth
    {
        return Err(resource_error(limits));
    }
    Ok(())
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
) -> Result<(), LowerError> {
    let wir = validated.as_wir();
    let facts = input.facts();
    if wir.build != facts.build
        || facts
            .graph
            .as_ref()
            .is_none_or(|graph| graph.name != wir.name)
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
    let functions_match = facts.functions.len() == wir.functions.len()
        && facts
            .functions
            .iter()
            .zip(&wir.functions)
            .all(|(source, output)| semantic_function_matches(source, output));
    let graph_matches = facts
        .graph
        .as_ref()
        .is_some_and(|graph| semantic_graph_matches(graph, wir));
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
) -> bool {
    let origin = match source.origin {
        wrela_sema::FunctionOrigin::Source { .. } => wrela_semantic_wir::FunctionOrigin::Source,
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
    output.id.0 == source.id.0
        && output.name == source.name
        && output.origin == origin
        && output.role == role
        && output.result.0 == source.result.0
        && output.effects.0 == source.effects.0
        && output.source == source.source
        && output.stack_bound == source.stack_bytes_bound
        && output.frame_bound == source.frame_bytes_bound
        && output.uninterrupted_bound == source.uninterrupted_work_bound
}

fn semantic_graph_matches(
    graph: &wrela_sema::ImageGraph,
    output: &wrela_semantic_wir::SemanticWir,
) -> bool {
    output.image_entry.0 == graph.entry.0
        && output.static_bytes == graph.static_bytes
        && output.peak_bytes == graph.peak_bytes
        && graph
            .actors
            .iter()
            .zip(&output.actors)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && out.ty.0 == source.class.0
                    && out.priority == source.priority
                    && out.mailbox_capacity == source.mailbox_capacity
                    && out
                        .message_types
                        .iter()
                        .map(|id| id.0)
                        .eq(source.message_types.iter().map(|id| id.0))
                    && out
                        .turn_functions
                        .iter()
                        .map(|id| id.0)
                        .eq(source.turn_functions.iter().map(|id| id.0))
                    && out.supervisor.map(|id| id.0) == source.supervisor.map(|id| id.0)
            })
        && graph.actors.len() == output.actors.len()
        && graph.tasks.iter().zip(&output.tasks).all(|(source, out)| {
            out.id.0 == source.id.0
                && out.name == source.name
                && out.entry.0 == source.entry.0
                && out.slots == source.slots
                && out.priority == source.priority
                && out.supervisor.map(|id| id.0) == source.supervisor.map(|id| id.0)
        })
        && graph.tasks.len() == output.tasks.len()
        && graph
            .devices
            .iter()
            .zip(&output.devices)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && out.target_binding == source.target_binding
                    && out.owner.0 == source.owner.0
                    && out.required_features == source.required_features
                    && out.optional_features == source.optional_features
                    && out
                        .interrupt_functions
                        .iter()
                        .map(|id| id.0)
                        .eq(source.interrupt_functions.iter().map(|id| id.0))
                    && out.queue_capacity == source.queue_capacity
                    && out.maximum_in_flight == source.maximum_in_flight
                    && out.reset_timeout_ns == source.reset_timeout_ns
            })
        && graph.devices.len() == output.devices.len()
        && graph.pools.iter().zip(&output.pools).all(|(source, out)| {
            out.id.0 == source.id.0
                && out.name == source.name
                && out.payload.0 == source.payload.0
                && out.capacity == source.capacity
                && out.alignment == u64::from(source.alignment)
                && out
                    .reachable_devices
                    .iter()
                    .map(|id| id.0)
                    .eq(source.reachable_devices.iter().map(|id| id.0))
        })
        && graph.pools.len() == output.pools.len()
        && graph
            .regions
            .iter()
            .zip(&output.regions)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && semantic_region_class(out.class, source.class)
                    && out.capacity_bytes == source.capacity_bytes
                    && out.alignment == u64::from(source.alignment)
                    && semantic_owner(out.owner, source.owner)
                    && out.proof.0 == source.proof.0
                    && out.source == source.source
            })
        && graph.regions.len() == output.regions.len()
        && output
            .startup_order
            .iter()
            .zip(&graph.startup_order)
            .all(|(out, source)| semantic_owner(*out, *source))
        && output.startup_order.len() == graph.startup_order.len()
        && output
            .shutdown_order
            .iter()
            .zip(&graph.shutdown_order)
            .all(|(out, source)| semantic_owner(*out, *source))
        && output.shutdown_order.len() == graph.shutdown_order.len()
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
    use super::{LowerError, LoweringLimits};

    #[test]
    fn semantic_wir_policy_rejects_zero_capacity() {
        LoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = LoweringLimits::standard();
        limits.types = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
    }
}
