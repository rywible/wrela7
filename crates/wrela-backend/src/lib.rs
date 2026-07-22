//! Private backend composition: decode and independently validate FlowWir,
//! optimize it, fix AArch64 layout/runtime ABI, generate COFF, link EFI, and
//! report the exact artifact.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
pub use wrela_backend_protocol::{
    BackendFailure, BackendFailureKind, BackendOutcome, BackendPath, BackendRequest,
    BackendResponse, BackendSuccess, MAX_FRAME_BYTES as MAX_PROTOCOL_FRAME_BYTES, RequestId,
    decode_response, encode_request, encode_response,
};
use wrela_build_model::{Sha256Digest, ValidatedBuildConfiguration};
use wrela_codegen_llvm::{
    CanonicalLlvmCodeGenerator, CodeGenerator, CodegenOptions, CodegenRequest,
};
pub use wrela_codegen_llvm::{CodegenError, ObjectArtifact, llvm_backend_available};
pub use wrela_flow_opt::{
    CanonicalFlowOptimizer, FlowOptimizer, OptimizationLimits, OptimizationProfile,
};
use wrela_flow_opt::{DecisionKind, OptimizationRequest, OptimizedFlowWir};
pub use wrela_flow_wir as flow_wir;
use wrela_flow_wir::{PlanOwner, ProofKind, ValidatedFlowWir};
use wrela_flow_wir_codec::{
    CanonicalFlowWirCodec, CodecLimits, DecodeRequest, FlowWirCodec,
    decode_and_verify as decode_flow_wir,
};
use wrela_image_report::{
    ActivationCancellationFact, ActivationFrameEvidenceFact, ActivationFrameResetFact,
    ActorPlacementInputFact, AnalysisFactLimits, AnalysisFactRequest, AnalysisFacts,
    BackendFactLimits, BackendFacts, BoundFact, HardwareFact, ImageEdgeFact, ImageNodeFact,
    ImageReport, OptimizationAction, OptimizationDecisionFact, ProofFact,
    RegionCapacityEvidenceFact, ReportError, RepresentationFacts, SchedulerOwnershipFact,
    SectionFact, SymbolFact, WorkFact, seal_analysis_facts,
};
use wrela_link_efi::{
    CanonicalCoffObjectInspector, CanonicalLinkedImageInspector, CoffObject, CoffObjectKind,
    EfiArtifact, EfiLinker, LinkError, LinkLimits, LinkRequest, LldEfiLinker, TargetRuntimeObject,
};
/// MachineWir inspection surface retained by preparation-only consumers and
/// source-level integration tests. These are the exact sealed backend facts;
/// exposing them here avoids a second, lossy debug-string reporting path.
pub use wrela_machine_lower::machine_wir;
pub use wrela_machine_lower::{
    CanonicalMachineLowerer, MachineLowerError, MachineLowerer, MachineLoweringLimits,
};
use wrela_machine_lower::{MachineLoweringOutput, MachineLoweringRequest};
use wrela_target::TargetPackage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendPreparationOptions {
    pub codec_limits: CodecLimits,
    pub optimization: OptimizationProfile,
    pub optimization_limits: OptimizationLimits,
    pub machine_limits: MachineLoweringLimits,
}

impl BackendPreparationOptions {
    /// Validate every independently callable preparation-stage policy before
    /// hashing or decoding caller input. Machine validation limits remain the
    /// caller's exact nested policy; this boundary never substitutes defaults.
    pub fn validate(&self) -> Result<(), BackendInputError> {
        self.codec_limits
            .validate()
            .map_err(BackendInputError::Decode)?;
        self.optimization
            .validate()
            .map_err(BackendInputError::Optimize)?;
        self.optimization_limits
            .validate()
            .map_err(BackendInputError::Optimize)?;
        self.machine_limits
            .validate()
            .map_err(BackendInputError::MachineLower)
    }
}

/// Complete resource policy for one private backend job. Keeping this as one
/// value lets the composition root validate every backend ceiling without
/// depending directly on the backend's implementation crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendLimits {
    pub codec: CodecLimits,
    pub optimization: OptimizationLimits,
    pub machine: MachineLoweringLimits,
    pub codegen: CodegenOptions,
    pub link: LinkLimits,
    pub analysis_report_facts: AnalysisFactLimits,
    pub report_facts: BackendFactLimits,
    pub maximum_report_bytes: u64,
}

impl BackendLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            codec: CodecLimits::standard(),
            optimization: OptimizationLimits::standard(),
            machine: MachineLoweringLimits::standard(),
            codegen: CodegenOptions::standard(),
            link: LinkLimits::standard(),
            analysis_report_facts: AnalysisFactLimits::standard(),
            report_facts: BackendFactLimits::standard(),
            maximum_report_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), BackendExecutionError> {
        let aligned_machine_validation = self.machine.with_aligned_validation().validation;
        if self.machine.validation != aligned_machine_validation {
            return Err(BackendExecutionError::InvalidRequest(
                "backend machine validation arena, edge, and payload ceilings must exactly match machine lowering policy"
                    .to_owned(),
            ));
        }
        self.codec
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.optimization
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.machine
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.codegen
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        if !self.link.is_valid()
            || self.analysis_report_facts.validate().is_err()
            || self.report_facts.validate().is_err()
            || self.maximum_report_bytes == 0
            || self.codec.test_plan != self.optimization.test_plan
            || self.codegen.maximum_object_bytes != self.link.object_bytes
            || self.codegen.maximum_sections != self.link.sections
            || self.codegen.maximum_symbols != self.link.symbols
            || self.codegen.maximum_measurement_bytes != self.link.measurement_bytes
        {
            return Err(BackendExecutionError::InvalidRequest(
                "backend codegen/link/report ceilings are invalid or inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedBackendInput {
    optimized: OptimizedFlowWir,
    machine: MachineLoweringOutput,
}

impl PreparedBackendInput {
    #[must_use]
    pub fn optimized(&self) -> &OptimizedFlowWir {
        &self.optimized
    }

    #[must_use]
    pub fn machine(&self) -> &MachineLoweringOutput {
        &self.machine
    }

    #[must_use]
    pub fn into_parts(self) -> (OptimizedFlowWir, MachineLoweringOutput) {
        (self.optimized, self.machine)
    }
}

#[derive(Clone, Copy)]
pub struct BackendPreparationServices<'a> {
    pub codec: &'a dyn FlowWirCodec,
    pub hasher: &'a dyn BackendContentHasher,
    pub optimizer: &'a dyn FlowOptimizer,
    pub machine_lowerer: &'a dyn MachineLowerer,
}

/// SHA-256 capability used before the backend decodes a frontend-produced IR
/// frame. It is injected so tests can verify the ordering without filesystem
/// or global crypto state.
pub trait BackendContentHasher {
    /// Return `None` only when cancellation was observed while hashing.
    fn sha256(&self, bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest>;
}

/// Production bounded SHA-256 implementation used for in-memory artifacts.
/// Cancellation is polled before hashing and after every fixed-size chunk.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalBackendContentHasher;

impl CanonicalBackendContentHasher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BackendContentHasher for CanonicalBackendContentHasher {
    fn sha256(&self, bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest> {
        if is_cancelled() {
            return None;
        }
        let mut hasher = Sha256::new();
        for chunk in bytes.chunks(64 * 1024) {
            if is_cancelled() {
                return None;
            }
            hasher.update(chunk);
        }
        if is_cancelled() {
            return None;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Some(Sha256Digest::from_bytes(digest))
    }
}

/// All paths are inside one driver-created private directory. Final paths are
/// distinct from temporary paths so a failed job cannot expose partial output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendJobPathCandidate {
    pub private_root: PathBuf,
    pub generated_object: PathBuf,
    pub temporary_image: PathBuf,
    pub temporary_map: PathBuf,
    pub temporary_report: PathBuf,
    pub final_image: PathBuf,
    pub final_report: PathBuf,
}

/// Validated private namespace for one backend job. Fields are immutable after
/// construction so path validation cannot be invalidated before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendJobPaths(BackendJobPathCandidate);

impl BackendJobPaths {
    pub fn new(candidate: BackendJobPathCandidate) -> Result<Self, BackendExecutionError> {
        let paths = [
            &candidate.generated_object,
            &candidate.temporary_image,
            &candidate.temporary_map,
            &candidate.temporary_report,
            &candidate.final_image,
            &candidate.final_report,
        ];
        let valid = normal_absolute_path(&candidate.private_root)
            && candidate.private_root.components().count() > 1
            && paths.iter().all(|path| {
                normal_absolute_path(path)
                    && path.starts_with(&candidate.private_root)
                    && *path != &candidate.private_root
            })
            && paths
                .iter()
                .enumerate()
                .all(|(index, path)| paths[..index].iter().all(|other| other != path));
        if !valid {
            return Err(BackendExecutionError::InvalidPaths);
        }
        Ok(Self(candidate))
    }

    #[must_use]
    pub fn private_root(&self) -> &Path {
        &self.0.private_root
    }

    #[must_use]
    pub fn generated_object(&self) -> &Path {
        &self.0.generated_object
    }

    #[must_use]
    pub fn temporary_image(&self) -> &Path {
        &self.0.temporary_image
    }

    #[must_use]
    pub fn temporary_map(&self) -> &Path {
        &self.0.temporary_map
    }

    #[must_use]
    pub fn temporary_report(&self) -> &Path {
        &self.0.temporary_report
    }

    #[must_use]
    pub fn final_image(&self) -> &Path {
        &self.0.final_image
    }

    #[must_use]
    pub fn final_report(&self) -> &Path {
        &self.0.final_report
    }
}

fn normal_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && normalized.as_os_str() == path.as_os_str()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendExecutionOptions {
    pub optimization: OptimizationProfile,
    pub limits: BackendLimits,
}

impl BackendExecutionOptions {
    pub fn validate(&self) -> Result<(), BackendExecutionError> {
        self.optimization
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.limits.validate()
    }

    #[must_use]
    pub fn preparation(&self) -> BackendPreparationOptions {
        BackendPreparationOptions {
            codec_limits: self.limits.codec,
            optimization: self.optimization.clone(),
            optimization_limits: self.limits.optimization,
            machine_limits: self.limits.machine,
        }
    }
}

#[derive(Debug)]
pub struct BackendExecutionRequest<'a> {
    pub protocol: &'a BackendRequest,
    /// Independently profile-digest-verified form of `protocol.build`.
    pub build: &'a ValidatedBuildConfiguration,
    pub wir_bytes: &'a [u8],
    pub target: &'a TargetPackage,
    pub target_runtime: TargetRuntimeObject<'a>,
    pub paths: &'a BackendJobPaths,
    pub options: BackendExecutionOptions,
}

impl BackendExecutionRequest<'_> {
    /// Validate all orchestration-only joins before decoding or LLVM work.
    pub fn validate(&self) -> Result<(), BackendExecutionError> {
        self.target
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        if self.paths.final_image()
            != self
                .paths
                .private_root()
                .join(self.protocol.output.as_str())
            || self.paths.final_report()
                != self
                    .paths
                    .private_root()
                    .join(self.protocol.report.as_str())
        {
            return Err(BackendExecutionError::InvalidPaths);
        }
        if self.protocol.build != *self.build.as_configuration()
            || self.build.identity.target != *self.target.identity()
            || self.build.identity.target_package != self.target.semantic().content_digest()
            || self.protocol.target_runtime_digest != self.target_runtime.digest
            || self.protocol.target_runtime_bytes != self.target_runtime.bytes
            || self.target_runtime.target_package != self.target.semantic().content_digest()
            || self.target_runtime.runtime_abi_version
                != self.target.backend().runtime_abi_version()
            || self.target_runtime.bytes == 0
            || !normal_absolute_path(self.target_runtime.path)
        {
            return Err(BackendExecutionError::InvalidRequest(
                "request build, target package, or verified runtime object disagree".to_owned(),
            ));
        }
        self.options.validate()?;
        Ok(())
    }
}

/// Complete inputs for deterministic report construction. Every measurement
/// comes from a sealed producer rather than another filesystem inspection.
pub struct BackendReportRequest<'a> {
    pub flow_wir_digest: Sha256Digest,
    pub optimized: &'a OptimizedFlowWir,
    pub machine: &'a MachineLoweringOutput,
    pub object: &'a ObjectArtifact,
    pub artifact: &'a EfiArtifact,
    pub target: &'a TargetPackage,
    pub analysis_fact_limits: AnalysisFactLimits,
    pub fact_limits: BackendFactLimits,
    pub maximum_report_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackendReport(ImageReport);

impl VerifiedBackendReport {
    #[must_use]
    pub fn as_report(&self) -> &ImageReport {
        &self.0
    }

    #[must_use]
    pub fn into_report(self) -> ImageReport {
        self.0
    }
}

pub trait BackendReportAssembler {
    fn assemble(
        &self,
        request: BackendReportRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedBackendReport, BackendReportError>;
}

/// Production report projection. Every emitted fact is copied or derived from
/// a sealed FlowWir, MachineWir, optimizer report, object, target, or linked
/// image measurement; absent evidence produces no speculative fact.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalBackendReportAssembler;

impl CanonicalBackendReportAssembler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BackendReportAssembler for CanonicalBackendReportAssembler {
    fn assemble(
        &self,
        request: BackendReportRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedBackendReport, BackendReportError> {
        if is_cancelled() {
            return Err(BackendReportError::Cancelled);
        }
        request
            .analysis_fact_limits
            .validate()
            .map_err(BackendReportError::Report)?;
        request
            .fact_limits
            .validate()
            .map_err(BackendReportError::Report)?;
        let flow = request.optimized.wir().as_wir();
        let mut analysis = analysis_facts(flow, request.target, is_cancelled)?;
        analysis.compiled_test_group = flow.compiled_test_group.clone();
        analysis.reachable_declarations = flow.source_summary.reachable_declarations;
        analysis.monomorphized_instantiations = flow.source_summary.monomorphized_instantiations;
        analysis.resolved_interface_calls = flow.source_summary.resolved_interface_calls;
        let analysis = seal_analysis_facts(
            AnalysisFactRequest {
                build: &flow.build,
                image_name: &flow.name,
                limits: request.analysis_fact_limits,
            },
            analysis,
            is_cancelled,
        )
        .map_err(BackendReportError::Report)?;

        let backend = backend_facts(&request, is_cancelled)?;
        let report = ImageReport::new(
            flow.build.clone(),
            flow.name.clone(),
            analysis,
            backend,
            request.fact_limits,
            is_cancelled,
        )
        .map_err(BackendReportError::Report)?;
        seal_backend_report(&request, report, is_cancelled)
    }
}

fn analysis_facts(
    flow: &wrela_flow_wir::FlowWir,
    target: &TargetPackage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisFacts, BackendReportError> {
    let mut facts = AnalysisFacts::default();
    let bound_capacity = 2usize
        .checked_add(flow.functions.len().checked_mul(2).ok_or(
            BackendReportError::ResourceExhausted("analysis bound count"),
        )?)
        .and_then(|count| count.checked_add(flow.actors.len()))
        .and_then(|count| count.checked_add(flow.tasks.len().checked_mul(2)?))
        .and_then(|count| count.checked_add(flow.devices.len().checked_mul(2)?))
        .and_then(|count| count.checked_add(flow.pools.len().checked_mul(2)?))
        .and_then(|count| count.checked_add(flow.regions.len().checked_mul(2)?))
        .ok_or(BackendReportError::ResourceExhausted(
            "analysis bound count",
        ))?;
    facts
        .bounds
        .try_reserve_exact(bound_capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis bounds"))?;
    facts
        .proofs
        .try_reserve_exact(flow.proofs.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis proofs"))?;
    facts
        .work
        .try_reserve_exact(flow.functions.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis work facts"))?;
    facts
        .hardware
        .try_reserve_exact(flow.devices.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis hardware facts"))?;
    let node_capacity = flow
        .actors
        .len()
        .checked_add(flow.tasks.len())
        .and_then(|count| count.checked_add(flow.regions.len()))
        .ok_or(BackendReportError::ResourceExhausted("analysis node count"))?;
    facts
        .image_nodes
        .try_reserve_exact(node_capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis image nodes"))?;
    facts
        .region_capacity_evidence
        .try_reserve_exact(flow.regions.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis region capacity evidence"))?;
    facts
        .activation_frame_evidence
        .try_reserve_exact(flow.activations.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis activation evidence"))?;
    facts
        .scheduler_ownership
        .try_reserve_exact(flow.schedulers.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis scheduler ownership"))?;
    facts
        .actor_placement_inputs
        .try_reserve_exact(flow.actors.len())
        .map_err(|_| BackendReportError::ResourceExhausted("actor placement inputs"))?;
    let edge_capacity = flow
        .actors
        .len()
        .checked_add(flow.tasks.len())
        .ok_or(BackendReportError::ResourceExhausted("analysis edge count"))?;
    facts
        .image_edges
        .try_reserve_exact(edge_capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis image edges"))?;
    facts
        .startup_order
        .try_reserve_exact(flow.startup_order.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis startup order"))?;
    facts
        .shutdown_order
        .try_reserve_exact(flow.shutdown_order.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis shutdown order"))?;

    push_bound(
        &mut facts.bounds,
        "image-static-memory",
        &flow.name,
        "FlowWir.static_bytes",
        flow.static_bytes,
        "bytes",
    )?;
    push_bound(
        &mut facts.bounds,
        "image-peak-memory",
        &flow.name,
        "FlowWir.peak_bytes",
        flow.peak_bytes,
        "bytes",
    )?;
    for function in &flow.functions {
        check_report_cancelled(is_cancelled)?;
        let owner = named_identity("function", function.id.0, &function.name)?;
        push_bound(
            &mut facts.bounds,
            "function-stack",
            &owner,
            "FlowFunction.stack_bound",
            function.stack_bound,
            "bytes",
        )?;
        push_bound(
            &mut facts.bounds,
            "function-frame",
            &owner,
            "FlowFunction.frame_bound",
            function.frame_bound,
            "bytes",
        )?;
        let mut checkpoint_count = 0u64;
        let mut uninterrupted_work = None::<u64>;
        for checkpoint in flow
            .checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.function == function.id)
        {
            checkpoint_count =
                checkpoint_count
                    .checked_add(1)
                    .ok_or(BackendReportError::ResourceExhausted(
                        "function checkpoint count",
                    ))?;
            uninterrupted_work = Some(
                uninterrupted_work
                    .unwrap_or(0)
                    .max(checkpoint.uninterrupted_bound),
            );
        }
        facts.work.push(WorkFact {
            function: owner,
            stack_bytes: function.stack_bound,
            frame_bytes: function.frame_bound,
            uninterrupted_work,
            checkpoint_count,
        });
    }
    for actor in &flow.actors {
        check_report_cancelled(is_cancelled)?;
        let owner = named_identity("actor", actor.id.0, &actor.name)?;
        push_bound(
            &mut facts.bounds,
            "actor-mailbox",
            &owner,
            "ActorPlan.mailbox_capacity",
            u64::from(actor.mailbox_capacity),
            "messages",
        )?;
        facts.image_nodes.push(ImageNodeFact {
            kind: copy_report_text("actor")?,
            name: copy_report_text(&owner)?,
            owner: copy_report_text("runtime")?,
            // FlowWir currently retains the actor plan record but not the
            // actor declaration span. Keep that structural provenance exact.
            source: copy_report_text("FlowWir.ActorPlan")?,
            static_bytes: 0,
        });
        if let Some(supervisor) = actor.supervisor {
            facts.image_edges.push(ImageEdgeFact {
                kind: copy_report_text("actor-supervision")?,
                source: owner,
                destination: actor_identity(flow, supervisor)?,
                capacity: None,
                priority: Some(actor.priority),
            });
        }
    }
    for task in &flow.tasks {
        check_report_cancelled(is_cancelled)?;
        let owner = named_identity("task", task.id.0, &task.name)?;
        push_bound(
            &mut facts.bounds,
            "task-slots",
            &owner,
            "TaskPlan.slots",
            u64::from(task.slots),
            "slots",
        )?;
        push_bound(
            &mut facts.bounds,
            "task-frame",
            &owner,
            "TaskPlan.frame_bytes_bound",
            task.frame_bytes_bound,
            "bytes",
        )?;
        let supervisor = task.supervisor.map_or_else(
            || copy_report_text("runtime"),
            |id| actor_identity(flow, id),
        )?;
        facts.image_nodes.push(ImageNodeFact {
            kind: copy_report_text("task")?,
            name: copy_report_text(&owner)?,
            owner: copy_report_text(&supervisor)?,
            // As with actors, FlowWir has exact plan provenance but does not
            // retain the task declaration span itself.
            source: copy_report_text("FlowWir.TaskPlan")?,
            static_bytes: 0,
        });
        facts.image_edges.push(ImageEdgeFact {
            kind: copy_report_text("task-supervision")?,
            source: owner,
            destination: supervisor,
            capacity: Some(u64::from(task.slots)),
            priority: Some(task.priority),
        });
    }
    for scheduler in &flow.schedulers {
        check_report_cancelled(is_cancelled)?;
        let mut actors = Vec::new();
        actors
            .try_reserve_exact(scheduler.actors.len())
            .map_err(|_| BackendReportError::ResourceExhausted("scheduler actor ownership"))?;
        for actor in &scheduler.actors {
            check_report_cancelled(is_cancelled)?;
            actors.push(actor_identity(flow, *actor)?);
        }
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(scheduler.tasks.len())
            .map_err(|_| BackendReportError::ResourceExhausted("scheduler task ownership"))?;
        for task in &scheduler.tasks {
            check_report_cancelled(is_cancelled)?;
            tasks.push(task_identity(flow, *task)?);
        }
        facts.scheduler_ownership.push(SchedulerOwnershipFact {
            core: scheduler.core,
            actors,
            tasks,
        });
    }
    facts.actor_placement_inputs = actor_placement_inputs(flow, is_cancelled)?;
    let semantic = target.semantic();
    for device in &flow.devices {
        check_report_cancelled(is_cancelled)?;
        let owner = named_identity("device", device.id.0, &device.name)?;
        if let Some(queue_capacity) = device.queue_capacity {
            push_bound(
                &mut facts.bounds,
                "device-queue",
                &owner,
                "DevicePlan.queue_capacity",
                u64::from(queue_capacity),
                "descriptors",
            )?;
        }
        if let Some(maximum_in_flight) = device.maximum_in_flight {
            push_bound(
                &mut facts.bounds,
                "device-in-flight",
                &owner,
                "DevicePlan.maximum_in_flight",
                u64::from(maximum_in_flight),
                "operations",
            )?;
        }
        facts.hardware.push(HardwareFact {
            device: owner,
            binding: device.target_binding.clone(),
            owner: actor_identity(flow, device.owner)?,
            dma_policy: format!(
                "target-coherent={};target-iommu={}",
                semantic.coherent_dma(),
                semantic.iommu_available()
            ),
            queue_capacity: device.queue_capacity.map(u64::from),
            maximum_in_flight: device.maximum_in_flight.map(u64::from),
        });
    }
    for pool in &flow.pools {
        check_report_cancelled(is_cancelled)?;
        let owner = named_identity("pool", pool.id.0, &pool.name)?;
        push_bound(
            &mut facts.bounds,
            "pool-capacity",
            &owner,
            "PoolPlan.capacity",
            pool.capacity,
            "elements",
        )?;
        push_bound(
            &mut facts.bounds,
            "pool-alignment",
            &owner,
            "PoolPlan.alignment",
            pool.alignment,
            "bytes",
        )?;
    }
    let activation_regions = reportable_activation_regions(flow, is_cancelled)?;
    for (region_index, region) in flow.regions.iter().enumerate() {
        check_report_cancelled(is_cancelled)?;
        let activation = activation_regions
            .get(region_index)
            .copied()
            .flatten()
            .and_then(|index| flow.activations.get(index));
        let owner = if activation.is_some() {
            named_identity_cancellable("region", region.id.0, &region.name, is_cancelled)?
        } else {
            named_identity("region", region.id.0, &region.name)?
        };
        if activation.is_some() {
            push_bound_cancellable(
                &mut facts.bounds,
                "region-capacity",
                &owner,
                "RegionPlan.capacity_bytes",
                region.capacity_bytes,
                "bytes",
                is_cancelled,
            )?;
            push_bound_cancellable(
                &mut facts.bounds,
                "region-alignment",
                &owner,
                "RegionPlan.alignment",
                region.alignment,
                "bytes",
                is_cancelled,
            )?;
        } else {
            push_bound(
                &mut facts.bounds,
                "region-capacity",
                &owner,
                "RegionPlan.capacity_bytes",
                region.capacity_bytes,
                "bytes",
            )?;
            push_bound(
                &mut facts.bounds,
                "region-alignment",
                &owner,
                "RegionPlan.alignment",
                region.alignment,
                "bytes",
            )?;
        }
        let kind = activation
            .and_then(|activation| {
                flow.functions
                    .get(activation.caller.0 as usize)
                    .and_then(|caller| activation_region_kind(caller.role))
            })
            .or_else(|| report_region_kind(region.owner, region.class));
        if let Some(kind) = kind {
            let capacity_proof = exact_region_capacity_proof(flow, region.capacity_proof)?;
            facts
                .region_capacity_evidence
                .push(RegionCapacityEvidenceFact {
                    region: if activation.is_some() {
                        copy_report_text_cancellable(&owner, is_cancelled)?
                    } else {
                        copy_report_text(&owner)?
                    },
                    capacity_proof,
                });
            facts.image_nodes.push(ImageNodeFact {
                kind: copy_report_text(kind)?,
                name: owner,
                owner: if activation.is_some() {
                    owner_name_cancellable(flow, region.owner, is_cancelled)?
                } else {
                    owner_name(flow, &region.owner)?
                },
                source: source_identity(
                    activation.map_or(region.source, |plan| plan.source).file.0,
                    activation
                        .map_or(region.source, |plan| plan.source)
                        .range
                        .start,
                    activation
                        .map_or(region.source, |plan| plan.source)
                        .range
                        .end,
                )?,
                static_bytes: region.capacity_bytes,
            });
        }
    }
    for plan in &flow.activations {
        check_report_cancelled(is_cancelled)?;
        let region = flow
            .regions
            .get(plan.region.0 as usize)
            .filter(|region| region.id == plan.region)
            .ok_or(BackendReportError::Mismatch(
                "activation report region is foreign",
            ))?;
        let caller = flow
            .functions
            .get(plan.caller.0 as usize)
            .filter(|caller| caller.id == plan.caller)
            .ok_or(BackendReportError::Mismatch(
                "activation report caller is foreign",
            ))?;
        let callee = flow
            .functions
            .get(plan.callee.0 as usize)
            .filter(|callee| callee.id == plan.callee)
            .ok_or(BackendReportError::Mismatch(
                "activation report callee is foreign",
            ))?;
        facts
            .activation_frame_evidence
            .push(ActivationFrameEvidenceFact {
                plan: plan.id.0,
                region: named_identity_cancellable(
                    "region",
                    region.id.0,
                    &region.name,
                    is_cancelled,
                )?,
                caller: named_identity_cancellable(
                    "function",
                    caller.id.0,
                    &caller.name,
                    is_cancelled,
                )?,
                callee: named_identity_cancellable(
                    "function",
                    callee.id.0,
                    &callee.name,
                    is_cancelled,
                )?,
                owner: owner_name_cancellable(flow, region.owner, is_cancelled)?,
                source: source_identity(
                    plan.source.file.0,
                    plan.source.range.start,
                    plan.source.range.end,
                )?,
                frame_bytes: plan.frame_bytes,
                maximum_live: plan.maximum_live,
                cancellation: match plan.cancellation {
                    wrela_flow_wir::ActivationCancellation::DropCalleeThenPropagate => {
                        ActivationCancellationFact::DropCalleeThenPropagate
                    }
                },
                capacity_proof: plan.capacity_proof.0,
            });
    }
    facts.activation_frame_resets = reportable_activation_frame_resets(flow, is_cancelled)?;
    for proof in &flow.proofs {
        check_report_cancelled(is_cancelled)?;
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(proof.sources.len())
            .map_err(|_| BackendReportError::ResourceExhausted("analysis proof sources"))?;
        for source in &proof.sources {
            check_report_cancelled(is_cancelled)?;
            sources.push(source_identity(
                source.file.0,
                source.range.start,
                source.range.end,
            )?);
        }
        let mut depends_on = Vec::new();
        depends_on
            .try_reserve_exact(proof.depends_on.len())
            .map_err(|_| BackendReportError::ResourceExhausted("analysis proof dependencies"))?;
        for dependency in &proof.depends_on {
            check_report_cancelled(is_cancelled)?;
            depends_on.push(dependency.0);
        }
        let mut why_chain = Vec::new();
        why_chain
            .try_reserve_exact(proof.explanation.len())
            .map_err(|_| BackendReportError::ResourceExhausted("analysis proof explanation"))?;
        for line in &proof.explanation {
            check_report_cancelled(is_cancelled)?;
            why_chain.push(copy_report_text(line)?);
        }
        facts.proofs.push(ProofFact {
            id: proof.id.0,
            category: copy_report_text(proof_kind_name(&proof.kind))?,
            subject: copy_report_text(&proof.subject)?,
            result: copy_report_text("proved")?,
            bound: proof.bound,
            sources,
            depends_on,
            why_chain,
        });
    }
    for owner in &flow.startup_order {
        check_report_cancelled(is_cancelled)?;
        facts.startup_order.push(owner_name(flow, owner)?);
    }
    for owner in &flow.shutdown_order {
        check_report_cancelled(is_cancelled)?;
        facts.shutdown_order.push(owner_name(flow, owner)?);
    }
    Ok(facts)
}

/// Join only the placement inputs that FlowWir currently authenticates.
///
/// This intentionally returns no rows for an image with pools, actor-owned
/// globals, or a turn without a checkpoint work bound. Publishing a partial
/// vector would let a later consumer mistake a subset for the normative total.
/// Target per-core capacities and explicit-assignment provenance remain absent,
/// so these rows are not placement proposals.
fn actor_placement_inputs(
    flow: &wrela_flow_wir::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ActorPlacementInputFact>, BackendReportError> {
    if !flow.pools.is_empty() {
        return Ok(Vec::new());
    }
    for global in &flow.globals {
        check_report_cancelled(is_cancelled)?;
        if matches!(global.owner, PlanOwner::Actor(_)) {
            return Ok(Vec::new());
        }
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(flow.actors.len())
        .map_err(|_| BackendReportError::ResourceExhausted("actor placement inputs"))?;
    for actor in &flow.actors {
        check_report_cancelled(is_cancelled)?;
        let mut maximum_uninterrupted_work = 0_u64;
        for function_id in &actor.turn_functions {
            check_report_cancelled(is_cancelled)?;
            let function = flow
                .functions
                .get(function_id.0 as usize)
                .filter(|function| function.id == *function_id)
                .ok_or(BackendReportError::Mismatch(
                    "actor placement turn function is foreign",
                ))?;
            let mut function_work = None::<u64>;
            for checkpoint in &flow.checkpoints {
                check_report_cancelled(is_cancelled)?;
                if checkpoint.function == function.id {
                    function_work = Some(
                        function_work
                            .unwrap_or(0)
                            .max(checkpoint.uninterrupted_bound),
                    );
                }
            }
            let Some(function_work) = function_work else {
                return Ok(Vec::new());
            };
            maximum_uninterrupted_work = maximum_uninterrupted_work.max(function_work);
        }
        let mut reserved_region_bytes = 0_u64;
        for region in &flow.regions {
            check_report_cancelled(is_cancelled)?;
            if region.owner == PlanOwner::Actor(actor.id) {
                reserved_region_bytes = reserved_region_bytes
                    .checked_add(region.capacity_bytes)
                    .ok_or(BackendReportError::ResourceExhausted(
                        "actor reserved region bytes",
                    ))?;
            }
        }
        if reserved_region_bytes == 0 {
            return Ok(Vec::new());
        }
        inputs.push(ActorPlacementInputFact {
            actor: actor_identity(flow, actor.id)?,
            maximum_uninterrupted_work,
            reserved_region_bytes,
        });
    }
    Ok(inputs)
}

fn reportable_activation_regions(
    flow: &wrela_flow_wir::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Option<usize>>, BackendReportError> {
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(flow.regions.len())
        .map_err(|_| BackendReportError::ResourceExhausted("activation report index"))?;
    for _ in &flow.regions {
        check_report_cancelled(is_cancelled)?;
        regions.push(None);
    }
    for (plan_index, plan) in flow.activations.iter().enumerate() {
        check_report_cancelled(is_cancelled)?;
        if usize::try_from(plan.id.0).ok() != Some(plan_index) {
            return Err(BackendReportError::Mismatch(
                "activation report plan identifier is not dense",
            ));
        }
        let caller = flow
            .functions
            .get(plan.caller.0 as usize)
            .filter(|caller| caller.id == plan.caller)
            .ok_or(BackendReportError::Mismatch(
                "activation report caller is foreign",
            ))?;
        let callee = flow
            .functions
            .get(plan.callee.0 as usize)
            .filter(|callee| callee.id == plan.callee)
            .ok_or(BackendReportError::Mismatch(
                "activation report callee is foreign",
            ))?;
        let expected_owner = match caller.role {
            wrela_flow_wir::FunctionRole::ActorTurn(actor) => PlanOwner::Actor(actor),
            wrela_flow_wir::FunctionRole::TaskEntry(task) => PlanOwner::Task(task),
            _ => {
                return Err(BackendReportError::Mismatch(
                    "activation report caller has an unsupported owner",
                ));
            }
        };
        let region_index = usize::try_from(plan.region.0).map_err(|_| {
            BackendReportError::Mismatch("activation report region is not indexable")
        })?;
        let region = flow
            .regions
            .get(region_index)
            .filter(|region| region.id == plan.region)
            .ok_or(BackendReportError::Mismatch(
                "activation report region is foreign",
            ))?;
        let proof = flow
            .proofs
            .get(plan.capacity_proof.0 as usize)
            .filter(|proof| proof.id == plan.capacity_proof)
            .ok_or(BackendReportError::Mismatch(
                "activation report capacity proof is foreign",
            ))?;
        let cleanup = proof
            .depends_on
            .first()
            .and_then(|dependency| flow.proofs.get(dependency.0 as usize));
        let capacity_bytes = plan.frame_bytes.checked_mul(u64::from(plan.maximum_live));
        let region_name_matches =
            activation_region_name_matches(&region.name, &caller.name, is_cancelled)?;
        if plan.maximum_live != 1
            || !region_name_matches
            || activation_region_kind(caller.role).is_none()
            || caller.color != wrela_flow_wir::FunctionColor::Async
            || callee.color != wrela_flow_wir::FunctionColor::Async
            || callee.role != wrela_flow_wir::FunctionRole::Ordinary
            || callee.frame_bound.max(1) != plan.frame_bytes
            || region.class != wrela_flow_wir::RegionClass::TaskFrame
            || region.owner != expected_owner
            || region.source != plan.source
            || Some(region.capacity_bytes) != capacity_bytes
            || region.capacity_proof != plan.capacity_proof
            || proof.kind != ProofKind::CapacityBound
            || proof.bound != Some(u64::from(plan.maximum_live))
            || proof.sources.as_slice() != [plan.source]
            || proof.depends_on.len() != 1
            || cleanup.is_none_or(|cleanup| cleanup.kind != ProofKind::CleanupAcyclic)
            || proof
                .depends_on
                .first()
                .is_none_or(|cleanup| callee.proofs.binary_search(cleanup).is_err())
            || caller.proofs.binary_search(&plan.capacity_proof).is_err()
            || !matches!(
                plan.cancellation,
                wrela_flow_wir::ActivationCancellation::DropCalleeThenPropagate
            )
        {
            return Err(BackendReportError::Mismatch(
                "activation report plan is not exactly source/proof/capacity bound",
            ));
        }
        let slot = regions
            .get_mut(region_index)
            .ok_or(BackendReportError::Mismatch(
                "activation report region index is absent",
            ))?;
        if slot.replace(plan_index).is_some() {
            return Err(BackendReportError::Mismatch(
                "activation report region is referenced more than once",
            ));
        }
    }
    Ok(regions)
}

/// Project the one task-frame region reset that FlowWir authenticates for a
/// completed immediate activation, or nothing at all.
///
/// The admitted profile is exactly the one the completed-activation frame reset
/// is lowered from: a single activation plan whose task-entry caller suspends on
/// it and, in the resume block that await returns to, resets that same
/// activation's own task-frame region as the block's only instruction before
/// returning. Every other shape — a second reset anywhere in the image, a reset
/// of some other region, a reset without the await's source span, an actor-owned
/// or non-task-frame region, or a capacity proof that is not an exact finite
/// `CapacityBound` over the await — yields no row. Publishing a partial row
/// would let a consumer mistake an unreset frame for a reset one.
fn reportable_activation_frame_resets(
    flow: &wrela_flow_wir::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ActivationFrameResetFact>, BackendReportError> {
    let mut reset = None;
    for function in &flow.functions {
        check_report_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_report_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_report_cancelled(is_cancelled)?;
                if matches!(
                    instruction.operation,
                    wrela_flow_wir::FlowOperation::RegionReset { .. }
                ) && reset.replace((function, block, instruction)).is_some()
                {
                    return Ok(Vec::new());
                }
            }
        }
    }
    let Some((caller, resume, reset)) = reset else {
        return Ok(Vec::new());
    };
    let [plan] = flow.activations.as_slice() else {
        return Ok(Vec::new());
    };
    let [entry, expected_resume] = caller.blocks.as_slice() else {
        return Ok(Vec::new());
    };
    let [sole_reset] = resume.instructions.as_slice() else {
        return Ok(Vec::new());
    };
    let [call] = entry.instructions.as_slice() else {
        return Ok(Vec::new());
    };
    let [activation_value] = call.results.as_slice() else {
        return Ok(Vec::new());
    };
    let (Some(region), Some(proof)) = (
        flow.regions.get(plan.region.0 as usize),
        flow.proofs.get(plan.capacity_proof.0 as usize),
    ) else {
        return Ok(Vec::new());
    };
    let expected_owner = match caller.role {
        wrela_flow_wir::FunctionRole::TaskEntry(task) => PlanOwner::Task(task),
        _ => return Ok(Vec::new()),
    };
    check_report_cancelled(is_cancelled)?;
    let exact = caller.id == plan.caller
        && caller.color == wrela_flow_wir::FunctionColor::Async
        && caller.entry == entry.id
        && resume.id == expected_resume.id
        && resume.id != entry.id
        && matches!(&call.operation,
            wrela_flow_wir::FlowOperation::AsyncCall { function, plan: called, .. }
                if *function == plan.callee && *called == plan.id)
        && matches!(entry.terminator,
            wrela_flow_wir::Terminator::Suspend { state: 0, activation: value, resume: target }
                if value == *activation_value && target == resume.id)
        && matches!(&resume.terminator, wrela_flow_wir::Terminator::Return(values) if values.is_empty())
        && sole_reset.id == reset.id
        && reset.results.is_empty()
        && reset.source == Some(plan.source)
        && matches!(reset.operation,
            wrela_flow_wir::FlowOperation::RegionReset { region } if region == plan.region)
        && region.id == plan.region
        && region.class == wrela_flow_wir::RegionClass::TaskFrame
        && region.owner == expected_owner
        && region.reset_function.is_none()
        && region.source == plan.source
        && region.capacity_bytes == plan.frame_bytes
        && region.capacity_bytes != 0
        && region.alignment != 0
        && region.alignment.is_power_of_two()
        && region.capacity_proof == plan.capacity_proof
        && proof.id == plan.capacity_proof
        && proof.kind == wrela_flow_wir::ProofKind::CapacityBound
        && proof.sources.as_slice() == [plan.source];
    let Some(capacity_bound) = proof.bound.filter(|bound| *bound != 0) else {
        return Ok(Vec::new());
    };
    if !exact {
        return Ok(Vec::new());
    }
    check_report_cancelled(is_cancelled)?;
    let mut resets = Vec::new();
    resets
        .try_reserve_exact(1)
        .map_err(|_| BackendReportError::ResourceExhausted("activation frame resets"))?;
    resets.push(ActivationFrameResetFact {
        plan: plan.id.0,
        region: named_identity_cancellable("region", region.id.0, &region.name, is_cancelled)?,
        owner: owner_name_cancellable(flow, region.owner, is_cancelled)?,
        source: source_identity(
            plan.source.file.0,
            plan.source.range.start,
            plan.source.range.end,
        )?,
        region_class: wrela_image_report::RegionClass::TaskFrame,
        capacity_bytes: region.capacity_bytes,
        alignment: region.alignment,
        capacity_proof: plan.capacity_proof.0,
        capacity_bound,
    });
    Ok(resets)
}

fn exact_region_capacity_proof(
    flow: &wrela_flow_wir::FlowWir,
    capacity_proof: wrela_flow_wir::ProofId,
) -> Result<u32, BackendReportError> {
    let proof_index = usize::try_from(capacity_proof.0).map_err(|_| {
        BackendReportError::Mismatch("reported region capacity proof identifier is not indexable")
    })?;
    flow.proofs
        .get(proof_index)
        .filter(|proof| proof.id == capacity_proof && proof.kind == ProofKind::CapacityBound)
        .map(|proof| proof.id.0)
        .ok_or(BackendReportError::Mismatch(
            "reported region capacity proof is absent or has the wrong kind",
        ))
}

fn backend_facts(
    request: &BackendReportRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BackendFacts, BackendReportError> {
    let artifact = request.artifact.measurements();
    let flow = request.optimized.wir().as_wir();
    let machine = request.machine.wir().as_wir();
    let profile = &request.optimized.report().profile;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(artifact.sections.len())
        .map_err(|_| BackendReportError::ResourceExhausted("report sections"))?;
    for section in &artifact.sections {
        check_report_cancelled(is_cancelled)?;
        let owner = machine
            .sections
            .iter()
            .find(|candidate| candidate.name == section.name)
            .map_or("linked-image-layout", |candidate| candidate.owner.as_str());
        sections.push(SectionFact {
            name: section.name.clone(),
            owner: owner.to_owned(),
            bytes: section.virtual_bytes,
        });
    }
    let section_addresses: BTreeMap<_, _> = artifact
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_address))
        .collect();
    let mut symbols = Vec::new();
    symbols
        .try_reserve_exact(artifact.symbols.len())
        .map_err(|_| BackendReportError::ResourceExhausted("report symbols"))?;
    for symbol in &artifact.symbols {
        check_report_cancelled(is_cancelled)?;
        let section_address =
            section_addresses
                .get(symbol.section.as_str())
                .ok_or(BackendReportError::Mismatch(
                    "linked symbol refers to an unmeasured section",
                ))?;
        let offset = symbol.virtual_address.checked_sub(*section_address).ok_or(
            BackendReportError::Mismatch("linked symbol precedes its measured section"),
        )?;
        symbols.push(SymbolFact {
            name: symbol.name.clone(),
            section: symbol.section.clone(),
            offset,
            bytes: symbol.bytes,
        });
    }
    let required_runtime_intrinsics = canonical_runtime_intrinsic_names(
        machine
            .runtime
            .intrinsics
            .iter()
            .map(|intrinsic| intrinsic.symbol_name()),
        is_cancelled,
    )?;
    let decisions = &request.optimized.report().decisions;
    let mut optimization_decisions = Vec::new();
    optimization_decisions
        .try_reserve_exact(decisions.len())
        .map_err(|_| BackendReportError::ResourceExhausted("optimization decisions"))?;
    for decision in decisions {
        check_report_cancelled(is_cancelled)?;
        let mut relied_on = Vec::new();
        relied_on
            .try_reserve_exact(decision.relied_on.len())
            .map_err(|_| BackendReportError::ResourceExhausted("optimization proof edges"))?;
        relied_on.extend(decision.relied_on.iter().map(|proof| proof.0));
        optimization_decisions.push(OptimizationDecisionFact {
            pass: decision.pass.clone(),
            subject: decision.subject.clone(),
            action: optimization_action(decision.kind),
            justification: decision.justification.clone(),
            relied_on,
        });
    }
    Ok(BackendFacts {
        flow_wir_digest: request.flow_wir_digest,
        artifact_bytes: artifact.artifact_bytes,
        artifact_digest: artifact.artifact_digest,
        relocation_directory_bytes: artifact.relocation_directory_bytes,
        base_relocation_blocks: artifact.base_relocation_blocks,
        base_relocation_dir64_count: artifact.base_relocations,
        base_relocation_provenance_digest: artifact.base_relocation_provenance_digest,
        sections,
        symbols,
        representations: RepresentationFacts {
            semantic_wir_version: flow.source_summary.semantic_wir_version,
            flow_wir_version: flow.version,
            flow_wir_wire_version: wrela_flow_wir_codec::FLOW_WIR_WIRE_VERSION,
            machine_wir_version: machine.version,
            runtime_abi_version: machine.runtime.version,
            optimization_pipeline_name: profile.pipeline.name.clone(),
            optimization_pipeline_revision: profile.pipeline.revision,
            optimization_pipeline_implementation: profile.pipeline.implementation,
        },
        required_runtime_intrinsics,
        target_variable_reservations: Vec::new(),
        excluded_target_variables: Vec::new(),
        optimization_decisions,
    })
}

fn canonical_runtime_intrinsic_names<'a>(
    intrinsics: impl ExactSizeIterator<Item = &'a str>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<String>, BackendReportError> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(intrinsics.len())
        .map_err(|_| BackendReportError::ResourceExhausted("runtime intrinsics"))?;
    for intrinsic in intrinsics {
        check_report_cancelled(is_cancelled)?;
        names.push(copy_report_text(intrinsic)?);
    }
    check_report_cancelled(is_cancelled)?;
    names.sort_unstable();
    check_report_cancelled(is_cancelled)?;
    Ok(names)
}

fn push_bound(
    facts: &mut Vec<BoundFact>,
    category: &str,
    owner: &str,
    source: &str,
    amount: u64,
    unit: &str,
) -> Result<(), BackendReportError> {
    facts.push(BoundFact {
        category: copy_report_text(category)?,
        owner: copy_report_text(owner)?,
        source: copy_report_text(source)?,
        amount,
        unit: copy_report_text(unit)?,
    });
    Ok(())
}

fn push_bound_cancellable(
    facts: &mut Vec<BoundFact>,
    category: &str,
    owner: &str,
    source: &str,
    amount: u64,
    unit: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), BackendReportError> {
    facts.push(BoundFact {
        category: copy_report_text_cancellable(category, is_cancelled)?,
        owner: copy_report_text_cancellable(owner, is_cancelled)?,
        source: copy_report_text_cancellable(source, is_cancelled)?,
        amount,
        unit: copy_report_text_cancellable(unit, is_cancelled)?,
    });
    Ok(())
}

fn owner_name(
    flow: &wrela_flow_wir::FlowWir,
    owner: &PlanOwner,
) -> Result<String, BackendReportError> {
    match owner {
        PlanOwner::Runtime => copy_report_text("runtime"),
        PlanOwner::Actor(id) => actor_identity(flow, *id),
        PlanOwner::Task(id) => flow
            .tasks
            .get(id.0 as usize)
            .filter(|task| task.id == *id)
            .ok_or(BackendReportError::Mismatch(
                "startup/shutdown task owner is foreign",
            ))
            .and_then(|task| named_identity("task", task.id.0, &task.name)),
        PlanOwner::Device(id) => flow
            .devices
            .get(id.0 as usize)
            .filter(|device| device.id == *id)
            .ok_or(BackendReportError::Mismatch(
                "startup/shutdown device owner is foreign",
            ))
            .and_then(|device| named_identity("device", device.id.0, &device.name)),
        PlanOwner::Pool(id) => flow
            .pools
            .get(id.0 as usize)
            .filter(|pool| pool.id == *id)
            .ok_or(BackendReportError::Mismatch(
                "startup/shutdown pool owner is foreign",
            ))
            .and_then(|pool| named_identity("pool", pool.id.0, &pool.name)),
        PlanOwner::BakedArtifact(id) => numbered_identity("baked-artifact", *id),
    }
}

fn owner_name_cancellable(
    flow: &wrela_flow_wir::FlowWir,
    owner: PlanOwner,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendReportError> {
    match owner {
        PlanOwner::Runtime => copy_report_text_cancellable("runtime", is_cancelled),
        PlanOwner::Actor(id) => flow
            .actors
            .get(id.0 as usize)
            .filter(|actor| actor.id == id)
            .ok_or(BackendReportError::Mismatch(
                "activation report actor owner is foreign",
            ))
            .and_then(|actor| {
                named_identity_cancellable("actor", actor.id.0, &actor.name, is_cancelled)
            }),
        PlanOwner::Task(id) => flow
            .tasks
            .get(id.0 as usize)
            .filter(|task| task.id == id)
            .ok_or(BackendReportError::Mismatch(
                "activation report task owner is foreign",
            ))
            .and_then(|task| {
                named_identity_cancellable("task", task.id.0, &task.name, is_cancelled)
            }),
        PlanOwner::Device(_) | PlanOwner::Pool(_) | PlanOwner::BakedArtifact(_) => Err(
            BackendReportError::Mismatch("activation report owner is not an actor or task"),
        ),
    }
}

fn actor_identity(
    flow: &wrela_flow_wir::FlowWir,
    id: wrela_flow_wir::ActorId,
) -> Result<String, BackendReportError> {
    flow.actors
        .get(id.0 as usize)
        .filter(|actor| actor.id == id)
        .ok_or(BackendReportError::Mismatch(
            "actor report owner is foreign",
        ))
        .and_then(|actor| named_identity("actor", actor.id.0, &actor.name))
}

fn task_identity(
    flow: &wrela_flow_wir::FlowWir,
    id: wrela_flow_wir::TaskId,
) -> Result<String, BackendReportError> {
    flow.tasks
        .get(id.0 as usize)
        .filter(|task| task.id == id)
        .ok_or(BackendReportError::Mismatch(
            "scheduler report task owner is foreign",
        ))
        .and_then(|task| named_identity("task", task.id.0, &task.name))
}

const fn report_region_kind(
    owner: PlanOwner,
    class: wrela_flow_wir::RegionClass,
) -> Option<&'static str> {
    match (owner, class) {
        (PlanOwner::Actor(_), wrela_flow_wir::RegionClass::Image) => Some("actor-mailbox-region"),
        (PlanOwner::Actor(_), wrela_flow_wir::RegionClass::TaskFrame) => {
            Some("actor-turn-frame-region")
        }
        (PlanOwner::Task(_), wrela_flow_wir::RegionClass::TaskFrame) => Some("task-frame-region"),
        _ => None,
    }
}

const fn activation_region_kind(role: wrela_flow_wir::FunctionRole) -> Option<&'static str> {
    match role {
        wrela_flow_wir::FunctionRole::ActorTurn(_) => Some("actor-activation-frame-region"),
        wrela_flow_wir::FunctionRole::TaskEntry(_) => Some("task-activation-frame-region"),
        wrela_flow_wir::FunctionRole::Ordinary
        | wrela_flow_wir::FunctionRole::Isr(_)
        | wrela_flow_wir::FunctionRole::Cleanup
        | wrela_flow_wir::FunctionRole::ImageEntry
        | wrela_flow_wir::FunctionRole::Test => None,
    }
}

fn activation_region_name_matches(
    region_name: &str,
    caller_name: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    const SUFFIX: &str = ".async-activation-frame";
    let Some(prefix_length) = region_name.len().checked_sub(SUFFIX.len()) else {
        return Ok(false);
    };
    let (prefix, suffix) = region_name.as_bytes().split_at(prefix_length);
    if suffix != SUFFIX.as_bytes() || prefix.len() != caller_name.len() {
        return Ok(false);
    }
    for (actual, expected) in prefix
        .chunks(4_096)
        .zip(caller_name.as_bytes().chunks(4_096))
    {
        check_report_cancelled(is_cancelled)?;
        if actual != expected {
            return Ok(false);
        }
    }
    check_report_cancelled(is_cancelled)?;
    Ok(true)
}

fn named_identity(kind: &str, id: u32, name: &str) -> Result<String, BackendReportError> {
    let capacity = kind
        .len()
        .checked_add(decimal_digits(id))
        .and_then(|capacity| capacity.checked_add(name.len()))
        .and_then(|capacity| capacity.checked_add(2))
        .ok_or(BackendReportError::ResourceExhausted(
            "analysis identity text",
        ))?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis identity text"))?;
    fmt::write(&mut output, format_args!("{kind}:{id}:{name}"))
        .map_err(|_| BackendReportError::Mismatch("analysis identity formatting failed"))?;
    Ok(output)
}

fn named_identity_cancellable(
    kind: &str,
    id: u32,
    name: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendReportError> {
    let capacity = kind
        .len()
        .checked_add(decimal_digits(id))
        .and_then(|capacity| capacity.checked_add(name.len()))
        .and_then(|capacity| capacity.checked_add(2))
        .ok_or(BackendReportError::ResourceExhausted(
            "analysis identity text",
        ))?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis identity text"))?;
    fmt::write(&mut output, format_args!("{kind}:{id}:"))
        .map_err(|_| BackendReportError::Mismatch("analysis identity formatting failed"))?;
    push_report_text_cancellable(&mut output, name, is_cancelled)?;
    Ok(output)
}

fn numbered_identity(kind: &str, id: u32) -> Result<String, BackendReportError> {
    let capacity = kind
        .len()
        .checked_add(decimal_digits(id))
        .and_then(|capacity| capacity.checked_add(1))
        .ok_or(BackendReportError::ResourceExhausted(
            "analysis identity text",
        ))?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis identity text"))?;
    fmt::write(&mut output, format_args!("{kind}:{id}"))
        .map_err(|_| BackendReportError::Mismatch("analysis identity formatting failed"))?;
    Ok(output)
}

fn source_identity(file: u32, start: u32, end: u32) -> Result<String, BackendReportError> {
    if start > end {
        return Err(BackendReportError::Mismatch(
            "analysis source identity range is reversed",
        ));
    }
    let capacity = "file::bytes:.."
        .len()
        .checked_add(decimal_digits(file))
        .and_then(|capacity| capacity.checked_add(decimal_digits(start)))
        .and_then(|capacity| capacity.checked_add(decimal_digits(end)))
        .ok_or(BackendReportError::ResourceExhausted(
            "analysis source identity",
        ))?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| BackendReportError::ResourceExhausted("analysis source identity"))?;
    fmt::write(
        &mut output,
        format_args!("file:{file}:bytes:{start}..{end}"),
    )
    .map_err(|_| BackendReportError::Mismatch("analysis source identity formatting failed"))?;
    Ok(output)
}

fn copy_report_text(value: &str) -> Result<String, BackendReportError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis fact text"))?;
    output.push_str(value);
    Ok(output)
}

fn copy_report_text_cancellable(
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendReportError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| BackendReportError::ResourceExhausted("analysis fact text"))?;
    push_report_text_cancellable(&mut output, value, is_cancelled)?;
    Ok(output)
}

fn push_report_text_cancellable(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), BackendReportError> {
    let mut start = 0_usize;
    while start < value.len() {
        check_report_cancelled(is_cancelled)?;
        let mut end = start.saturating_add(4_096).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(BackendReportError::Mismatch(
                "analysis fact text has no bounded UTF-8 boundary",
            ));
        }
        output.push_str(&value[start..end]);
        start = end;
    }
    check_report_cancelled(is_cancelled)
}

const fn decimal_digits(mut value: u32) -> usize {
    let mut digits = 1_usize;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

const fn proof_kind_name(kind: &ProofKind) -> &'static str {
    match kind {
        ProofKind::TypeChecked => "type-checked",
        ProofKind::EffectsAllowed => "effects-allowed",
        ProofKind::DefiniteInitialization => "definite-initialization",
        ProofKind::Ownership => "ownership",
        ProofKind::AccessExclusive => "access-exclusive",
        ProofKind::ViewDoesNotEscape => "view-does-not-escape",
        ProofKind::RegionBound => "region-bound",
        ProofKind::CapacityBound => "capacity-bound",
        ProofKind::ActorReplyExactlyOnce => "actor-reply-exactly-once",
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
        ProofKind::FlowControl => "flow-control",
        ProofKind::ValueRange => "value-range",
        ProofKind::Alignment => "alignment",
        ProofKind::NoAlias => "no-alias",
    }
}

const fn optimization_action(kind: DecisionKind) -> OptimizationAction {
    match kind {
        DecisionKind::Removed => OptimizationAction::Removed,
        DecisionKind::Folded => OptimizationAction::Folded,
        DecisionKind::Inlined => OptimizationAction::Inlined,
        DecisionKind::Coalesced => OptimizationAction::Coalesced,
        DecisionKind::Reordered => OptimizationAction::Reordered,
        DecisionKind::Retained => OptimizationAction::Retained,
    }
}

fn check_report_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), BackendReportError> {
    if is_cancelled() {
        Err(BackendReportError::Cancelled)
    } else {
        Ok(())
    }
}

/// Bind an assembled report to every independently sealed backend input. This
/// catches a report implementation that is internally valid but describes a
/// different IR, pipeline, target, object, or linked image.
pub fn seal_backend_report(
    request: &BackendReportRequest<'_>,
    report: ImageReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<VerifiedBackendReport, BackendReportError> {
    if is_cancelled() {
        return Err(BackendReportError::Cancelled);
    }
    report
        .validate_with_cancellation(is_cancelled)
        .map_err(BackendReportError::Report)?;
    request
        .analysis_fact_limits
        .validate()
        .map_err(BackendReportError::Report)?;
    request
        .fact_limits
        .validate()
        .map_err(BackendReportError::Report)?;
    if request.maximum_report_bytes == 0 {
        return Err(BackendReportError::Mismatch("report byte limit is zero"));
    }
    let flow = request.optimized.wir().as_wir();
    let machine = request.machine.wir().as_wir();
    let backend = report.backend();
    let representations = &backend.representations;
    let pipeline = &request.optimized.report().profile.pipeline;
    let analysis = report.analysis();
    if report.build() != &flow.build
        || report.build() != &machine.build
        || report.build() != request.object.build()
        || report.build() != request.artifact.build()
        || report.image_name() != flow.name
        || report.image_name() != machine.name
        || report.analysis_limits() != request.analysis_fact_limits
        || report.backend_limits() != request.fact_limits
        || backend.flow_wir_digest != request.flow_wir_digest
        || analysis.reachable_declarations != flow.source_summary.reachable_declarations
        || analysis.monomorphized_instantiations != flow.source_summary.monomorphized_instantiations
        || analysis.resolved_interface_calls != flow.source_summary.resolved_interface_calls
        || representations.semantic_wir_version != flow.source_summary.semantic_wir_version
        || representations.flow_wir_version != flow.version
        || representations.flow_wir_wire_version != wrela_flow_wir_codec::FLOW_WIR_WIRE_VERSION
        || representations.machine_wir_version != machine.version
        || representations.runtime_abi_version != machine.runtime.version
        || representations.optimization_pipeline_name != pipeline.name
        || representations.optimization_pipeline_revision != pipeline.revision
        || representations.optimization_pipeline_implementation != pipeline.implementation
        || request.target.identity() != &flow.build.target
        || request.target.semantic().content_digest() != flow.build.target_package
        || !report_artifact_measurements_match(backend, request.artifact.measurements())
    {
        return Err(BackendReportError::Mismatch(
            "report identity, version, pipeline, target, or artifact facts differ from inputs",
        ));
    }
    let mut expected_analysis = analysis_facts(flow, request.target, is_cancelled)?;
    expected_analysis.compiled_test_group = flow.compiled_test_group.clone();
    expected_analysis.reachable_declarations = flow.source_summary.reachable_declarations;
    expected_analysis.monomorphized_instantiations =
        flow.source_summary.monomorphized_instantiations;
    expected_analysis.resolved_interface_calls = flow.source_summary.resolved_interface_calls;
    let expected_analysis = seal_analysis_facts(
        AnalysisFactRequest {
            build: &flow.build,
            image_name: &flow.name,
            limits: request.analysis_fact_limits,
        },
        expected_analysis,
        is_cancelled,
    )
    .map_err(BackendReportError::Report)?;
    require_exact_analysis_binding(expected_analysis.as_facts(), analysis, is_cancelled)?;
    let expected_intrinsics = canonical_runtime_intrinsic_names(
        machine
            .runtime
            .intrinsics
            .iter()
            .map(|intrinsic| intrinsic.symbol_name()),
        is_cancelled,
    )?;
    if backend.required_runtime_intrinsics != expected_intrinsics
        || !report_sections_match(backend, request.artifact.measurements(), is_cancelled)?
        || !report_symbols_match(backend, request.artifact.measurements(), is_cancelled)?
    {
        return Err(BackendReportError::Mismatch(
            "report runtime, section, or symbol facts differ from linked image",
        ));
    }
    let json = report
        .to_json_with_cancellation(is_cancelled)
        .map_err(BackendReportError::Report)?;
    let bytes = u64::try_from(json.len())
        .map_err(|_| BackendReportError::Mismatch("report byte count overflowed"))?;
    if bytes > request.maximum_report_bytes {
        return Err(BackendReportError::Mismatch(
            "canonical report exceeds the request byte limit",
        ));
    }
    if is_cancelled() {
        return Err(BackendReportError::Cancelled);
    }
    Ok(VerifiedBackendReport(report))
}

fn require_exact_analysis_binding(
    expected: &AnalysisFacts,
    reported: &AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), BackendReportError> {
    check_report_cancelled(is_cancelled)?;
    let old_fields_match = expected.reachable_declarations == reported.reachable_declarations
        && expected.monomorphized_instantiations == reported.monomorphized_instantiations
        && expected.resolved_interface_calls == reported.resolved_interface_calls
        && expected.bounds == reported.bounds
        && expected.actor_lowerings == reported.actor_lowerings
        && expected.image_nodes == reported.image_nodes
        && expected.region_capacity_evidence == reported.region_capacity_evidence
        && expected.activation_frame_resets == reported.activation_frame_resets
        && expected.image_edges == reported.image_edges
        && expected.work == reported.work
        && expected.hardware == reported.hardware
        && expected.recovery == reported.recovery
        && expected.actor_placement_inputs == reported.actor_placement_inputs
        && expected.compiled_test_group == reported.compiled_test_group
        && expected.startup_order == reported.startup_order
        && expected.shutdown_order == reported.shutdown_order;
    if old_fields_match
        && proof_facts_match(&expected.proofs, &reported.proofs, is_cancelled)?
        && activation_evidence_matches(
            &expected.activation_frame_evidence,
            &reported.activation_frame_evidence,
            is_cancelled,
        )?
    {
        Ok(())
    } else {
        Err(BackendReportError::Mismatch(
            "report analysis graph, bounds, proofs, or origins differ from FlowWir",
        ))
    }
}

fn proof_facts_match(
    expected: &[ProofFact],
    reported: &[ProofFact],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    if expected.len() != reported.len() {
        return Ok(false);
    }
    for (expected, reported) in expected.iter().zip(reported) {
        check_report_cancelled(is_cancelled)?;
        if expected.id != reported.id
            || expected.bound != reported.bound
            || !report_text_equal(&expected.category, &reported.category, is_cancelled)?
            || !report_text_equal(&expected.subject, &reported.subject, is_cancelled)?
            || !report_text_equal(&expected.result, &reported.result, is_cancelled)?
            || !report_text_slices_equal(&expected.sources, &reported.sources, is_cancelled)?
            || !report_u32_slices_equal(&expected.depends_on, &reported.depends_on, is_cancelled)?
            || !report_text_slices_equal(&expected.why_chain, &reported.why_chain, is_cancelled)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn activation_evidence_matches(
    expected: &[ActivationFrameEvidenceFact],
    reported: &[ActivationFrameEvidenceFact],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    if expected.len() != reported.len() {
        return Ok(false);
    }
    for (expected, reported) in expected.iter().zip(reported) {
        check_report_cancelled(is_cancelled)?;
        if expected.plan != reported.plan
            || expected.frame_bytes != reported.frame_bytes
            || expected.maximum_live != reported.maximum_live
            || expected.cancellation != reported.cancellation
            || expected.capacity_proof != reported.capacity_proof
            || !report_text_equal(&expected.region, &reported.region, is_cancelled)?
            || !report_text_equal(&expected.caller, &reported.caller, is_cancelled)?
            || !report_text_equal(&expected.callee, &reported.callee, is_cancelled)?
            || !report_text_equal(&expected.owner, &reported.owner, is_cancelled)?
            || !report_text_equal(&expected.source, &reported.source, is_cancelled)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn report_text_slices_equal(
    expected: &[String],
    reported: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    if expected.len() != reported.len() {
        return Ok(false);
    }
    for (expected, reported) in expected.iter().zip(reported) {
        if !report_text_equal(expected, reported, is_cancelled)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn report_u32_slices_equal(
    expected: &[u32],
    reported: &[u32],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    if expected.len() != reported.len() {
        return Ok(false);
    }
    for (expected, reported) in expected.iter().zip(reported) {
        check_report_cancelled(is_cancelled)?;
        if expected != reported {
            return Ok(false);
        }
    }
    Ok(true)
}

fn report_text_equal(
    expected: &str,
    reported: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    if expected.len() != reported.len() {
        return Ok(false);
    }
    for (expected, reported) in expected
        .as_bytes()
        .chunks(4_096)
        .zip(reported.as_bytes().chunks(4_096))
    {
        check_report_cancelled(is_cancelled)?;
        if expected != reported {
            return Ok(false);
        }
    }
    check_report_cancelled(is_cancelled)?;
    Ok(true)
}

fn report_artifact_measurements_match(
    report: &wrela_image_report::BackendFacts,
    artifact: &wrela_link_efi::ImageMeasurements,
) -> bool {
    report.artifact_bytes == artifact.artifact_bytes
        && report.artifact_digest == artifact.artifact_digest
        && report.relocation_directory_bytes == artifact.relocation_directory_bytes
        && report.base_relocation_blocks == artifact.base_relocation_blocks
        && report.base_relocation_dir64_count == artifact.base_relocations
        && report.base_relocation_provenance_digest == artifact.base_relocation_provenance_digest
}

fn report_sections_match(
    report: &wrela_image_report::BackendFacts,
    artifact: &wrela_link_efi::ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    let measured: BTreeMap<_, _> = artifact
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_bytes))
        .collect();
    if measured.len() != artifact.sections.len() || report.sections.len() != measured.len() {
        return Ok(false);
    }
    for reported in &report.sections {
        if is_cancelled() {
            return Err(BackendReportError::Cancelled);
        }
        if measured.get(reported.name.as_str()).copied() != Some(reported.bytes) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn report_symbols_match(
    report: &wrela_image_report::BackendFacts,
    artifact: &wrela_link_efi::ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    let sections: BTreeMap<_, _> = artifact
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_address))
        .collect();
    let symbols: BTreeMap<_, _> = artifact
        .symbols
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol))
        .collect();
    if sections.len() != artifact.sections.len()
        || symbols.len() != artifact.symbols.len()
        || report.symbols.len() != symbols.len()
    {
        return Ok(false);
    }
    for reported in &report.symbols {
        if is_cancelled() {
            return Err(BackendReportError::Cancelled);
        }
        let Some(measured) = symbols.get(reported.name.as_str()) else {
            return Ok(false);
        };
        let Some(section_address) = sections.get(measured.section.as_str()) else {
            return Ok(false);
        };
        if measured.section != reported.section
            || measured.bytes != reported.bytes
            || measured.virtual_address.checked_sub(*section_address) != Some(reported.offset)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendReportError {
    Cancelled,
    Report(ReportError),
    Mismatch(&'static str),
    ResourceExhausted(&'static str),
}

impl fmt::Display for BackendReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend report assembly was cancelled"),
            Self::Report(error) => error.fmt(formatter),
            Self::Mismatch(reason) => write!(formatter, "backend report mismatch: {reason}"),
            Self::ResourceExhausted(resource) => {
                write!(formatter, "backend report could not reserve {resource}")
            }
        }
    }
}

impl std::error::Error for BackendReportError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBackendArtifacts {
    success: BackendSuccess,
    build: wrela_build_model::BuildIdentity,
}

impl PublishedBackendArtifacts {
    #[must_use]
    pub fn success(&self) -> &BackendSuccess {
        &self.success
    }
}

/// Bind an atomic publication result to the exact request, post-link artifact,
/// and canonical report. This is the only constructor for a successful
/// publication capability.
pub fn seal_publication(
    request: &BackendRequest,
    artifact: &EfiArtifact,
    report: &VerifiedBackendReport,
    success: BackendSuccess,
    hasher: &dyn BackendContentHasher,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PublishedBackendArtifacts, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let report = report.as_report();
    if artifact.build() != &request.build.identity || report.build() != &request.build.identity {
        return Err(BackendExecutionError::InternalInvariant(
            "published artifact or report build identity differs from the request".to_owned(),
        ));
    }
    if success.artifact != request.output || success.report != request.report {
        return Err(BackendExecutionError::InternalInvariant(
            "publisher returned paths other than the requested artifact/report paths".to_owned(),
        ));
    }
    if success.artifact_digest != artifact.measurements().artifact_digest {
        return Err(BackendExecutionError::DigestMismatch { artifact: "image" });
    }
    if report.backend().flow_wir_digest != request.wir_digest
        || !report_artifact_measurements_match(report.backend(), artifact.measurements())
    {
        return Err(BackendExecutionError::InternalInvariant(
            "published report describes different FlowWir or artifact measurements".to_owned(),
        ));
    }
    let report_json = bounded_report_json(report, maximum_report_bytes, is_cancelled)?;
    let report_digest = hasher
        .sha256(report_json.as_bytes(), is_cancelled)
        .ok_or(BackendExecutionError::Cancelled)?;
    if success.report_digest != report_digest {
        return Err(BackendExecutionError::DigestMismatch { artifact: "report" });
    }
    Ok(PublishedBackendArtifacts {
        success,
        build: request.build.identity.clone(),
    })
}

/// Only capability allowed to materialize the generated object and atomically
/// publish the final image/report pair. Implementations must verify the report
/// digest over `ImageReport::to_json()` and the artifact digest supplied by the
/// post-link inspector before a rename/publish becomes visible.
pub trait BackendPublisher {
    fn materialize_object(
        &self,
        path: &Path,
        object: &ObjectArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), BackendExecutionError>;

    fn publish(
        &self,
        request: &BackendRequest,
        paths: &BackendJobPaths,
        artifact: &EfiArtifact,
        report: &VerifiedBackendReport,
        maximum_report_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PublishedBackendArtifacts, BackendExecutionError>;
}

/// Filesystem publisher for the driver-created private job namespace.
/// Staging files are created exclusively, synced, remeasured, and renamed;
/// no destination is overwritten and a failed second rename removes the first.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilesystemBackendPublisher;

impl FilesystemBackendPublisher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BackendPublisher for FilesystemBackendPublisher {
    fn materialize_object(
        &self,
        path: &Path,
        object: &ObjectArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), BackendExecutionError> {
        if is_cancelled() {
            return Err(BackendExecutionError::Cancelled);
        }
        write_new_synced_file(path, object.bytes(), "materialize generated object")?;
        if is_cancelled() {
            let _ = fs::remove_file(path);
            return Err(BackendExecutionError::Cancelled);
        }
        let (bytes, digest) = measure_stable_file(
            path,
            u64::try_from(object.bytes().len()).map_err(|_| {
                BackendExecutionError::InvalidRequest(
                    "generated object byte count overflowed".to_owned(),
                )
            })?,
            is_cancelled,
        )?;
        let expected = CanonicalBackendContentHasher
            .sha256(object.bytes(), is_cancelled)
            .ok_or(BackendExecutionError::Cancelled)?;
        let expected_bytes = u64::try_from(object.bytes().len()).map_err(|_| {
            BackendExecutionError::InvalidRequest(
                "generated object byte count overflowed".to_owned(),
            )
        })?;
        if bytes != expected_bytes || digest != expected {
            let _ = fs::remove_file(path);
            return Err(BackendExecutionError::DigestMismatch {
                artifact: "generated object",
            });
        }
        Ok(())
    }

    fn publish(
        &self,
        request: &BackendRequest,
        paths: &BackendJobPaths,
        artifact: &EfiArtifact,
        report: &VerifiedBackendReport,
        maximum_report_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PublishedBackendArtifacts, BackendExecutionError> {
        if is_cancelled() {
            return Err(BackendExecutionError::Cancelled);
        }
        if artifact.path() != paths.temporary_image()
            || artifact.map() != paths.temporary_map()
            || paths.final_image() != paths.private_root().join(request.output.as_str())
            || paths.final_report() != paths.private_root().join(request.report.as_str())
        {
            return Err(BackendExecutionError::InvalidPaths);
        }
        if !report_artifact_measurements_match(
            report.as_report().backend(),
            artifact.measurements(),
        ) {
            return Err(BackendExecutionError::InternalInvariant(
                "report relocation evidence differs from the artifact being published".to_owned(),
            ));
        }
        ensure_absent(paths.temporary_report(), "stage report")?;
        ensure_absent(paths.final_image(), "publish image")?;
        ensure_absent(paths.final_report(), "publish report")?;
        let report_json =
            bounded_report_json(report.as_report(), maximum_report_bytes, is_cancelled)?;
        write_new_synced_file(
            paths.temporary_report(),
            report_json.as_bytes(),
            "stage report",
        )?;
        let staged = (|| {
            let (image_bytes, image_digest) = measure_stable_file(
                paths.temporary_image(),
                artifact.measurements().artifact_bytes,
                is_cancelled,
            )?;
            let (report_bytes, report_digest) =
                measure_stable_file(paths.temporary_report(), maximum_report_bytes, is_cancelled)?;
            let expected_report_bytes = u64::try_from(report_json.len()).map_err(|_| {
                BackendExecutionError::InvalidRequest(
                    "canonical report byte count overflowed".to_owned(),
                )
            })?;
            if image_bytes != artifact.measurements().artifact_bytes
                || image_digest != artifact.measurements().artifact_digest
                || report_bytes != expected_report_bytes
            {
                return Err(BackendExecutionError::DigestMismatch {
                    artifact: "staged image or report",
                });
            }
            if is_cancelled() {
                return Err(BackendExecutionError::Cancelled);
            }
            fs::rename(paths.temporary_image(), paths.final_image())
                .map_err(|error| private_io("publish image", error))?;
            if let Err(error) = fs::rename(paths.temporary_report(), paths.final_report()) {
                let _ = fs::remove_file(paths.final_image());
                return Err(private_io("publish report", error));
            }
            sync_parent(paths.final_image(), "sync image directory")?;
            sync_parent(paths.final_report(), "sync report directory")?;
            let (final_image_bytes, final_image_digest) = measure_stable_file(
                paths.final_image(),
                artifact.measurements().artifact_bytes,
                is_cancelled,
            )?;
            let (final_report_bytes, final_report_digest) =
                measure_stable_file(paths.final_report(), maximum_report_bytes, is_cancelled)?;
            if final_image_bytes != image_bytes
                || final_image_digest != image_digest
                || final_report_bytes != report_bytes
                || final_report_digest != report_digest
            {
                return Err(BackendExecutionError::DigestMismatch {
                    artifact: "published image or report",
                });
            }
            Ok(BackendSuccess {
                artifact: request.output.clone(),
                artifact_digest: final_image_digest,
                report: request.report.clone(),
                report_digest: final_report_digest,
            })
        })();
        let success = match staged {
            Ok(success) => success,
            Err(error) => {
                let _ = fs::remove_file(paths.temporary_report());
                let _ = fs::remove_file(paths.final_image());
                let _ = fs::remove_file(paths.final_report());
                return Err(error);
            }
        };
        match seal_publication(
            request,
            artifact,
            report,
            success,
            &CanonicalBackendContentHasher,
            maximum_report_bytes,
            is_cancelled,
        ) {
            Ok(publication) => Ok(publication),
            Err(error) => {
                let _ = fs::remove_file(paths.final_image());
                let _ = fs::remove_file(paths.final_report());
                Err(error)
            }
        }
    }
}

fn write_new_synced_file(
    path: &Path,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), BackendExecutionError> {
    validate_output_parent(path, operation)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| private_io(operation, error))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(private_io(operation, error));
    }
    drop(file);
    Ok(())
}

fn validate_output_parent(
    path: &Path,
    operation: &'static str,
) -> Result<(), BackendExecutionError> {
    if !normal_absolute_path(path) {
        return Err(BackendExecutionError::InvalidPaths);
    }
    let parent = path.parent().ok_or(BackendExecutionError::InvalidPaths)?;
    let canonical = fs::canonicalize(parent).map_err(|error| private_io(operation, error))?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| private_io(operation, error))?;
    if canonical != parent || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackendExecutionError::InvalidPaths);
    }
    Ok(())
}

fn ensure_absent(path: &Path, operation: &'static str) -> Result<(), BackendExecutionError> {
    validate_output_parent(path, operation)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(BackendExecutionError::InvalidPaths),
        Err(error) => Err(private_io(operation, error)),
    }
}

fn sync_parent(path: &Path, operation: &'static str) -> Result<(), BackendExecutionError> {
    let parent = path.parent().ok_or(BackendExecutionError::InvalidPaths)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| private_io(operation, error))
}

fn measure_stable_file(
    path: &Path,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, Sha256Digest), BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let canonical = fs::canonicalize(path).map_err(|error| private_io("measure file", error))?;
    if canonical != path {
        return Err(BackendExecutionError::InvalidPaths);
    }
    let before = fs::symlink_metadata(path).map_err(|error| private_io("measure file", error))?;
    validate_regular_file(&before)?;
    let identity = publisher_file_identity(&before);
    if identity.bytes > maximum_bytes {
        return Err(BackendExecutionError::InvalidRequest(format!(
            "measured file exceeds {maximum_bytes} bytes"
        )));
    }
    let mut file = File::open(path).map_err(|error| private_io("measure file", error))?;
    let opened = file
        .metadata()
        .map_err(|error| private_io("measure file", error))?;
    validate_regular_file(&opened)?;
    if publisher_file_identity(&opened) != identity {
        return Err(BackendExecutionError::InvalidPaths);
    }
    let mut remaining = identity.bytes;
    let mut buffer = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    while remaining != 0 {
        if is_cancelled() {
            return Err(BackendExecutionError::Cancelled);
        }
        let buffer_bytes = u64::try_from(buffer.len()).map_err(|_| {
            BackendExecutionError::InvalidRequest("measurement buffer length overflowed".to_owned())
        })?;
        let wanted = usize::try_from(remaining.min(buffer_bytes)).map_err(|_| {
            BackendExecutionError::InvalidRequest("measured file length overflowed".to_owned())
        })?;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|error| private_io("measure file", error))?;
        if read == 0 {
            return Err(BackendExecutionError::InvalidPaths);
        }
        hasher.update(&buffer[..read]);
        let read_bytes = u64::try_from(read).map_err(|_| {
            BackendExecutionError::InvalidRequest("measured read length overflowed".to_owned())
        })?;
        remaining = remaining
            .checked_sub(read_bytes)
            .ok_or(BackendExecutionError::InvalidPaths)?;
    }
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| private_io("measure file", error))?
        != 0
    {
        return Err(BackendExecutionError::InvalidPaths);
    }
    let after = fs::symlink_metadata(path).map_err(|error| private_io("measure file", error))?;
    let opened_after = file
        .metadata()
        .map_err(|error| private_io("measure file", error))?;
    validate_regular_file(&after)?;
    validate_regular_file(&opened_after)?;
    if publisher_file_identity(&after) != identity
        || publisher_file_identity(&opened_after) != identity
    {
        return Err(BackendExecutionError::InvalidPaths);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((identity.bytes, Sha256Digest::from_bytes(digest)))
}

fn validate_regular_file(metadata: &fs::Metadata) -> Result<(), BackendExecutionError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackendExecutionError::InvalidPaths);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(BackendExecutionError::InvalidPaths);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublisherFileIdentity {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    modified_time: u64,
}

#[cfg(unix)]
fn publisher_file_identity(metadata: &fs::Metadata) -> PublisherFileIdentity {
    use std::os::unix::fs::MetadataExt;
    PublisherFileIdentity {
        bytes: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

#[cfg(windows)]
fn publisher_file_identity(metadata: &fs::Metadata) -> PublisherFileIdentity {
    use std::os::windows::fs::MetadataExt;
    PublisherFileIdentity {
        bytes: metadata.len(),
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        modified_time: metadata.last_write_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn publisher_file_identity(metadata: &fs::Metadata) -> PublisherFileIdentity {
    PublisherFileIdentity {
        bytes: metadata.len(),
    }
}

fn private_io(operation: &'static str, error: io::Error) -> BackendExecutionError {
    BackendExecutionError::PrivateIo {
        operation,
        message: error.to_string(),
    }
}

#[derive(Debug)]
pub struct BackendExecutionOutput {
    response: BackendResponse,
    product: BackendExecutionProduct,
}

#[derive(Debug)]
enum BackendExecutionProduct {
    Success {
        artifact: Box<EfiArtifact>,
        report: Box<ImageReport>,
    },
    Failure(BackendFailure),
}

pub type BackendSuccessProduct = (Box<EfiArtifact>, Box<ImageReport>);
pub type BackendExecutionParts = (
    BackendResponse,
    Result<BackendSuccessProduct, BackendFailure>,
);

impl BackendExecutionOutput {
    #[must_use]
    pub fn response(&self) -> &BackendResponse {
        &self.response
    }

    #[must_use]
    pub fn artifact(&self) -> Option<&EfiArtifact> {
        match &self.product {
            BackendExecutionProduct::Success { artifact, .. } => Some(artifact),
            BackendExecutionProduct::Failure(_) => None,
        }
    }

    #[must_use]
    pub fn report(&self) -> Option<&ImageReport> {
        match &self.product {
            BackendExecutionProduct::Success { report, .. } => Some(report),
            BackendExecutionProduct::Failure(_) => None,
        }
    }

    #[must_use]
    pub fn failure(&self) -> Option<&BackendFailure> {
        match &self.product {
            BackendExecutionProduct::Success { .. } => None,
            BackendExecutionProduct::Failure(failure) => Some(failure),
        }
    }

    pub fn into_parts(self) -> BackendExecutionParts {
        let product = match self.product {
            BackendExecutionProduct::Success { artifact, report } => Ok((artifact, report)),
            BackendExecutionProduct::Failure(failure) => Err(failure),
        };
        (self.response, product)
    }
}

/// Finish a backend success only when publication is still bound to the exact
/// artifact and report passed to the consumer.
pub fn finish_success(
    request: &BackendRequest,
    publication: PublishedBackendArtifacts,
    artifact: EfiArtifact,
    report: VerifiedBackendReport,
    hasher: &dyn BackendContentHasher,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BackendExecutionOutput, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let report_json = bounded_report_json(report.as_report(), maximum_report_bytes, is_cancelled)?;
    let report_digest = hasher
        .sha256(report_json.as_bytes(), is_cancelled)
        .ok_or(BackendExecutionError::Cancelled)?;
    if publication.build != request.build.identity
        || artifact.build() != &publication.build
        || report.as_report().build() != &publication.build
        || report.as_report().backend().flow_wir_digest != request.wir_digest
        || !report_artifact_measurements_match(
            report.as_report().backend(),
            artifact.measurements(),
        )
        || publication.success.artifact_digest != artifact.measurements().artifact_digest
        || publication.success.report_digest != report_digest
    {
        return Err(BackendExecutionError::InternalInvariant(
            "published success was paired with a different request, artifact, or report".to_owned(),
        ));
    }
    let response = BackendResponse {
        request_id: request.request_id,
        outcome: BackendOutcome::Success(publication.success),
    };
    let report = report.into_report();
    Ok(BackendExecutionOutput {
        response,
        product: BackendExecutionProduct::Success {
            artifact: Box::new(artifact),
            report: Box::new(report),
        },
    })
}

fn bounded_report_json(
    report: &ImageReport,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    if maximum_report_bytes == 0 {
        return Err(BackendExecutionError::InvalidRequest(
            "maximum report bytes must be nonzero".to_owned(),
        ));
    }
    let json = report
        .to_json_with_cancellation(is_cancelled)
        .map_err(|error| BackendExecutionError::InternalInvariant(error.to_string()))?;
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let bytes = u64::try_from(json.len()).map_err(|_| {
        BackendExecutionError::InvalidRequest("image report byte count overflow".to_owned())
    })?;
    if bytes > maximum_report_bytes {
        return Err(BackendExecutionError::InvalidRequest(format!(
            "image report exceeds {maximum_report_bytes} bytes"
        )));
    }
    Ok(json)
}

/// Construct a failure response from one source of truth; the typed protocol
/// outcome and local failure value cannot disagree.
#[must_use]
pub fn finish_failure(request: &BackendRequest, failure: BackendFailure) -> BackendExecutionOutput {
    BackendExecutionOutput {
        response: BackendResponse {
            request_id: request.request_id,
            outcome: BackendOutcome::Failure(failure.clone()),
        },
        product: BackendExecutionProduct::Failure(failure),
    }
}

/// Production backend service boundary. A job failure is returned as a typed
/// protocol response; only cancellation, private-workspace I/O, or a violated
/// internal invariant escapes as `BackendExecutionError`.
pub trait BackendExecutor {
    fn execute(
        &self,
        request: BackendExecutionRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<BackendExecutionOutput, BackendExecutionError>;
}

/// Every replaceable boundary in the backend pipeline. The composed executor
/// is public so tests can inject stage failures while production uses the
/// canonical implementations below.
#[derive(Clone, Copy)]
pub struct BackendPipelineServices<'a> {
    pub codec: &'a dyn FlowWirCodec,
    pub hasher: &'a dyn BackendContentHasher,
    pub optimizer: &'a dyn FlowOptimizer,
    pub machine_lowerer: &'a dyn MachineLowerer,
    pub code_generator: &'a dyn CodeGenerator,
    pub linker: &'a dyn EfiLinker,
    pub report_assembler: &'a dyn BackendReportAssembler,
    pub publisher: &'a dyn BackendPublisher,
}

pub struct ComposedBackendExecutor<'a> {
    services: BackendPipelineServices<'a>,
}

impl<'a> ComposedBackendExecutor<'a> {
    #[must_use]
    pub const fn new(services: BackendPipelineServices<'a>) -> Self {
        Self { services }
    }
}

impl BackendExecutor for ComposedBackendExecutor<'_> {
    fn execute(
        &self,
        request: BackendExecutionRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<BackendExecutionOutput, BackendExecutionError> {
        execute_pipeline(self.services, request, is_cancelled)
    }
}

/// Production composition root. In a default build this intentionally reaches
/// `CodegenError::BackendNotBuilt` only after canonical FlowWir acceptance and
/// MachineWir lowering. The bundled-backend feature supplies LLVM and LLD.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalBackendExecutor;

impl CanonicalBackendExecutor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BackendExecutor for CanonicalBackendExecutor {
    fn execute(
        &self,
        request: BackendExecutionRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<BackendExecutionOutput, BackendExecutionError> {
        let codec = CanonicalFlowWirCodec;
        let hasher = CanonicalBackendContentHasher::new();
        let optimizer = CanonicalFlowOptimizer::new();
        let machine_lowerer = CanonicalMachineLowerer::new();
        let code_generator = CanonicalLlvmCodeGenerator::new();
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_inspector = CanonicalLinkedImageInspector::new();
        let linker = LldEfiLinker {
            object_inspector: &object_inspector,
            image_inspector: &image_inspector,
        };
        let report_assembler = CanonicalBackendReportAssembler::new();
        let publisher = FilesystemBackendPublisher::new();
        ComposedBackendExecutor::new(BackendPipelineServices {
            codec: &codec,
            hasher: &hasher,
            optimizer: &optimizer,
            machine_lowerer: &machine_lowerer,
            code_generator: &code_generator,
            linker: &linker,
            report_assembler: &report_assembler,
            publisher: &publisher,
        })
        .execute(request, is_cancelled)
    }
}

fn execute_pipeline(
    services: BackendPipelineServices<'_>,
    request: BackendExecutionRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BackendExecutionOutput, BackendExecutionError> {
    request.validate()?;
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let preparation = request.options.preparation();
    let prepared = match prepare_for_codegen(
        BackendPreparationServices {
            codec: services.codec,
            hasher: services.hasher,
            optimizer: services.optimizer,
            machine_lowerer: services.machine_lowerer,
        },
        request.wir_bytes,
        request.protocol.wir_digest,
        request.target,
        request.build,
        preparation,
        is_cancelled,
    ) {
        Ok(prepared) => prepared,
        Err(error) if error.is_cancelled() => {
            return Err(BackendExecutionError::Cancelled);
        }
        Err(error) => {
            let kind = match error {
                BackendInputError::Target(_) | BackendInputError::BuildTargetMismatch => {
                    BackendFailureKind::Target
                }
                BackendInputError::Optimize(_) | BackendInputError::MachineLower(_) => {
                    BackendFailureKind::Codegen
                }
                BackendInputError::Cancelled
                | BackendInputError::FlowWirDigestMismatch
                | BackendInputError::Decode(_) => BackendFailureKind::Verification,
            };
            return Ok(stage_failure(
                request.protocol,
                kind,
                "backend input acceptance",
                &error,
            ));
        }
    };
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }

    let object = match services.code_generator.emit_object(
        CodegenRequest {
            module: prepared.machine().wir(),
            target: request.target.backend(),
            options: request.options.limits.codegen,
        },
        is_cancelled,
    ) {
        Ok(object) => object,
        Err(CodegenError::Cancelled) => return Err(BackendExecutionError::Cancelled),
        Err(CodegenError::BackendNotBuilt) => {
            return Ok(finish_failure(
                request.protocol,
                BackendFailure {
                    kind: BackendFailureKind::Codegen,
                    message: "canonical FlowWir was accepted, optimized, and lowered to sealed MachineWir, but this backend was built without LLVM code generation"
                        .to_owned(),
                },
            ));
        }
        Err(error) => {
            return Ok(stage_failure(
                request.protocol,
                BackendFailureKind::Codegen,
                "LLVM object generation",
                &error,
            ));
        }
    };
    let object_bytes = u64::try_from(object.bytes().len()).map_err(|_| {
        BackendExecutionError::InternalInvariant(
            "sealed object length cannot be represented by the link protocol".to_owned(),
        )
    })?;
    let object_digest = services
        .hasher
        .sha256(object.bytes(), is_cancelled)
        .ok_or(BackendExecutionError::Cancelled)?;
    services.publisher.materialize_object(
        request.paths.generated_object(),
        &object,
        is_cancelled,
    )?;

    let objects = [
        CoffObject {
            ordinal: 0,
            path: request.paths.generated_object(),
            expected_digest: object_digest,
            expected_bytes: object_bytes,
            kind: CoffObjectKind::Image {
                build: request.protocol.build.identity.clone(),
            },
        },
        request.target_runtime.as_coff_object(1),
    ];
    let artifact = match services.linker.link(
        &LinkRequest {
            build: &request.protocol.build.identity,
            objects: &objects,
            target: request.target.backend(),
            output: request.paths.temporary_image(),
            map_output: request.paths.temporary_map(),
            limits: request.options.limits.link,
        },
        is_cancelled,
    ) {
        Ok(artifact) => artifact,
        Err(LinkError::Cancelled) => return Err(BackendExecutionError::Cancelled),
        Err(error) => {
            return Ok(stage_failure(
                request.protocol,
                BackendFailureKind::Link,
                "EFI linking",
                &error,
            ));
        }
    };

    let report = match services.report_assembler.assemble(
        BackendReportRequest {
            flow_wir_digest: request.protocol.wir_digest,
            optimized: prepared.optimized(),
            machine: prepared.machine(),
            object: &object,
            artifact: &artifact,
            target: request.target,
            analysis_fact_limits: request.options.limits.analysis_report_facts,
            fact_limits: request.options.limits.report_facts,
            maximum_report_bytes: request.options.limits.maximum_report_bytes,
        },
        is_cancelled,
    ) {
        Ok(report) => report,
        Err(BackendReportError::Cancelled) => return Err(BackendExecutionError::Cancelled),
        Err(error) => {
            return Ok(stage_failure(
                request.protocol,
                BackendFailureKind::Report,
                "canonical image report assembly",
                &error,
            ));
        }
    };
    let publication = services.publisher.publish(
        request.protocol,
        request.paths,
        &artifact,
        &report,
        request.options.limits.maximum_report_bytes,
        is_cancelled,
    )?;
    finish_success(
        request.protocol,
        publication,
        artifact,
        report,
        services.hasher,
        request.options.limits.maximum_report_bytes,
        is_cancelled,
    )
}

fn stage_failure(
    request: &BackendRequest,
    kind: BackendFailureKind,
    stage: &'static str,
    error: &dyn fmt::Display,
) -> BackendExecutionOutput {
    finish_failure(
        request,
        BackendFailure {
            kind,
            message: bounded_failure_message(format!("{stage} failed: {error}")),
        },
    )
}

fn bounded_failure_message(mut message: String) -> String {
    const MAXIMUM_FAILURE_BYTES: usize = 4096;
    if message.len() <= MAXIMUM_FAILURE_BYTES {
        return message;
    }
    let mut end = MAXIMUM_FAILURE_BYTES - 3;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push_str("...");
    message
}

#[derive(Debug)]
pub enum BackendExecutionError {
    Cancelled,
    InvalidPaths,
    InvalidRequest(String),
    PrivateIo {
        operation: &'static str,
        message: String,
    },
    DigestMismatch {
        artifact: &'static str,
    },
    InternalInvariant(String),
}

impl fmt::Display for BackendExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend execution was cancelled"),
            Self::InvalidPaths => {
                formatter.write_str("backend private or publication paths are invalid")
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid backend execution request: {message}")
            }
            Self::PrivateIo { operation, message } => {
                write!(formatter, "backend {operation} failed: {message}")
            }
            Self::DigestMismatch { artifact } => write!(
                formatter,
                "published {artifact} digest differs from its sealed measurement"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "backend invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for BackendExecutionError {}

/// Exact frontend artifact and provenance expected by backend verification.
/// Keeping these fields together prevents callers from accidentally mixing an
/// artifact from one build with the target or limits from another invocation.
pub struct BackendDecodeRequest<'a> {
    pub bytes: &'a [u8],
    pub expected_digest: Sha256Digest,
    pub target: &'a TargetPackage,
    pub build: &'a ValidatedBuildConfiguration,
    pub limits: CodecLimits,
}

/// Decode and structurally validate the exact frontend/backend exchange type.
pub fn decode_and_verify(
    codec: &dyn FlowWirCodec,
    hasher: &dyn BackendContentHasher,
    request: BackendDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedFlowWir, BackendInputError> {
    if hasher
        .sha256(request.bytes, is_cancelled)
        .ok_or(BackendInputError::Cancelled)?
        != request.expected_digest
    {
        return Err(BackendInputError::FlowWirDigestMismatch);
    }
    request
        .target
        .validate()
        .map_err(BackendInputError::Target)?;
    if request.target.identity() != &request.build.identity.target
        || request.target.semantic().content_digest() != request.build.identity.target_package
    {
        return Err(BackendInputError::BuildTargetMismatch);
    }
    decode_flow_wir(
        codec,
        DecodeRequest {
            bytes: request.bytes,
            limits: request.limits,
            expected_build: Some(&request.build.identity),
        },
        is_cancelled,
    )
    .map_err(BackendInputError::Decode)
}

/// Complete all representation transitions required before LLVM. The backend
/// owns these implementations and re-establishes their invariants even when
/// the frontend has already done equivalent checking.
pub fn prepare_for_codegen(
    services: BackendPreparationServices<'_>,
    bytes: &[u8],
    expected_digest: Sha256Digest,
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
    options: BackendPreparationOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PreparedBackendInput, BackendInputError> {
    if is_cancelled() {
        return Err(BackendInputError::Cancelled);
    }
    options.validate()?;
    if is_cancelled() {
        return Err(BackendInputError::Cancelled);
    }
    let decoded = decode_and_verify(
        services.codec,
        services.hasher,
        BackendDecodeRequest {
            bytes,
            expected_digest,
            target,
            build,
            limits: options.codec_limits,
        },
        is_cancelled,
    )?;
    let optimized = services
        .optimizer
        .optimize(
            OptimizationRequest {
                input: decoded,
                profile: options.optimization,
                limits: options.optimization_limits,
            },
            is_cancelled,
        )
        .map_err(BackendInputError::Optimize)?;
    let machine = services
        .machine_lowerer
        .lower(
            MachineLoweringRequest {
                input: &optimized,
                target,
                build,
                limits: options.machine_limits,
            },
            is_cancelled,
        )
        .map_err(BackendInputError::MachineLower)?;
    Ok(PreparedBackendInput { optimized, machine })
}

/// Canonical in-process form of the private backend preparation boundary.
///
/// Production process orchestration still supplies and verifies the protocol
/// digest explicitly. This helper is useful to composition tests that already
/// own a canonical encoded frame and need the same decode, optimize, and
/// MachineWir consumers without constructing filesystem/linker services.
pub fn prepare_canonical_frame_for_codegen(
    bytes: &[u8],
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PreparedBackendInput, BackendInputError> {
    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(bytes, is_cancelled)
        .ok_or(BackendInputError::Cancelled)?;
    let optimization = OptimizationProfile::from_build_policy(
        &build.profile.optimization,
        build.identity.compiler,
    )
    .map_err(BackendInputError::Optimize)?;
    prepare_for_codegen(
        BackendPreparationServices {
            codec: &codec,
            hasher: &hasher,
            optimizer: &optimizer,
            machine_lowerer: &machine_lowerer,
        },
        bytes,
        expected_digest,
        target,
        build,
        BackendPreparationOptions {
            codec_limits: CodecLimits::standard(),
            optimization,
            optimization_limits: OptimizationLimits::standard(),
            machine_limits: MachineLoweringLimits::standard().with_aligned_validation(),
        },
        is_cancelled,
    )
}

/// Emit the independently measured native object for an already prepared
/// input. The code generator still revalidates the exact MachineWir/target
/// contract and its COFF consumer verifies symbols and relocations before an
/// artifact is returned. Builds without the frozen LLVM payload return
/// [`CodegenError::BackendNotBuilt`].
pub fn emit_prepared_object(
    prepared: &PreparedBackendInput,
    target: &TargetPackage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ObjectArtifact, CodegenError> {
    CanonicalLlvmCodeGenerator::new().emit_object(
        CodegenRequest {
            module: prepared.machine().wir(),
            target: target.backend(),
            options: CodegenOptions::standard(),
        },
        is_cancelled,
    )
}

#[derive(Debug)]
pub enum BackendInputError {
    Cancelled,
    FlowWirDigestMismatch,
    Target(wrela_target::TargetError),
    BuildTargetMismatch,
    Decode(wrela_flow_wir_codec::CodecError),
    Optimize(wrela_flow_opt::OptimizeError),
    MachineLower(MachineLowerError),
}

impl BackendInputError {
    /// Stable cancellation classification across each independently bounded
    /// preparation stage. Callers need not infer cancellation from diagnostic
    /// text or lose the stage-specific error retained for debugging.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::Decode(wrela_flow_wir_codec::CodecError::Cancelled)
                | Self::Optimize(wrela_flow_opt::OptimizeError::Cancelled)
                | Self::MachineLower(MachineLowerError::Cancelled)
        )
    }

    /// Return the exact structured Machine lowering failure when preparation
    /// reached that boundary.
    #[must_use]
    pub const fn machine_lower_error(&self) -> Option<&MachineLowerError> {
        match self {
            Self::MachineLower(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for BackendInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend input verification was cancelled"),
            Self::FlowWirDigestMismatch => {
                formatter.write_str("FlowWir bytes do not match the backend request digest")
            }
            Self::Target(error) => error.fmt(formatter),
            Self::BuildTargetMismatch => {
                formatter.write_str("backend build and selected target differ")
            }
            Self::Decode(error) => error.fmt(formatter),
            Self::Optimize(error) => error.fmt(formatter),
            Self::MachineLower(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BackendInputError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_flow_wir::{
        ActivationCancellation, ActivationId, ActivationPlan, ActorId, ActorPlan, Block, BlockId,
        Checkpoint, CheckpointId, FLOW_WIR_VERSION, FlowFunction, FlowOperation, FlowType,
        FlowTypeKind, FlowWir, FunctionColor, FunctionId, FunctionOrigin, FunctionRole,
        Instruction, InstructionId, PlanOwner, Proof, ProofId, ProofKind, RegionClass, RegionId,
        RegionPlan, SchedulerPlan, SourceSummary, TaskId, TaskPlan, Terminator, TypeId, Value,
        ValueId,
    };
    use wrela_image_report::{
        ActivationCancellationFact, ActivationFrameEvidenceFact, ActivationFrameResetFact,
        ActorPlacementInputFact, AnalysisFactLimits, AnalysisFactRequest, AnalysisFacts, ProofFact,
        RegionCapacityEvidenceFact, ReportError, seal_analysis_facts,
    };
    use wrela_source::{FileId, Span, TextRange};
    use wrela_target::TargetPackage;

    use super::{
        BackendContentHasher, BackendExecutionError, BackendInputError, BackendJobPathCandidate,
        BackendJobPaths, BackendLimits, BackendReportError, CanonicalBackendContentHasher,
        MachineLowerError, actor_placement_inputs, analysis_facts,
        canonical_runtime_intrinsic_names, exact_region_capacity_proof,
        report_artifact_measurements_match, report_region_kind, reportable_activation_frame_resets,
        reportable_activation_regions, require_exact_analysis_binding, source_identity,
    };

    #[test]
    fn runtime_intrinsic_report_names_use_canonical_symbol_order_and_are_cancellable() {
        let intrinsics = [
            "wrela_rt_v2_image_enter",
            "wrela_rt_v2_fatal",
            "wrela_rt_v2_test_emit",
            "wrela_rt_v2_test_finish",
        ];
        assert_eq!(
            canonical_runtime_intrinsic_names(intrinsics.into_iter(), &|| false)
                .expect("canonical runtime intrinsic names"),
            [
                "wrela_rt_v2_fatal",
                "wrela_rt_v2_image_enter",
                "wrela_rt_v2_test_emit",
                "wrela_rt_v2_test_finish",
            ]
        );

        let polls = Cell::new(0_u32);
        canonical_runtime_intrinsic_names(intrinsics.into_iter(), &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded cancellation polls"),
            );
            false
        })
        .expect("measure runtime intrinsic cancellation polls");
        let final_poll = polls.get();
        let polls = Cell::new(0_u32);
        assert_eq!(
            canonical_runtime_intrinsic_names(intrinsics.into_iter(), &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded cancellation polls");
                polls.set(next);
                next == final_poll
            }),
            Err(BackendReportError::Cancelled)
        );
    }

    fn actor_report_flow_fixture() -> (wrela_flow_wir::ValidatedFlowWir, TargetPackage) {
        let target_digest = Sha256Digest::from_bytes([0x52; 32]);
        let build = BuildIdentity {
            compiler: Sha256Digest::from_bytes([0x51; 32]),
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: target_digest,
            standard_library: Sha256Digest::from_bytes([0x53; 32]),
            source_graph: Sha256Digest::from_bytes([0x54; 32]),
            request: Sha256Digest::from_bytes([0x55; 32]),
            profile: Sha256Digest::from_bytes([0x56; 32]),
        };
        let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
        let function = |id: u32,
                        name: &str,
                        origin: FunctionOrigin,
                        role: FunctionRole,
                        color: FunctionColor| FlowFunction {
            id: FunctionId(id),
            name: name.to_owned(),
            origin,
            role,
            color,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: None,
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: if matches!(role, FunctionRole::TaskEntry(_)) {
                16
            } else {
                0
            },
            proofs: if id == 0 {
                vec![
                    ProofId(2),
                    ProofId(3),
                    ProofId(4),
                    ProofId(5),
                    ProofId(6),
                    ProofId(7),
                    ProofId(8),
                    ProofId(9),
                ]
            } else {
                Vec::new()
            },
            source: (id != 0).then_some(source),
        };
        let flow = FlowWir {
            version: FLOW_WIR_VERSION,
            name: "actor-report-image".to_owned(),
            build,
            source_summary: SourceSummary {
                semantic_wir_version: 15,
                // The generated image entry is the one retained base semantic
                // function; actor/task bodies below are generated async states
                // rooted in that dense semantic provenance ID.
                semantic_functions: 1,
                hir_files: 1,
                hir_declarations: 4,
                reachable_declarations: 4,
                monomorphized_instantiations: 4,
                resolved_interface_calls: 0,
            },
            types: vec![FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            }],
            globals: Vec::new(),
            functions: vec![
                function(
                    0,
                    "__wrela_image_entry",
                    FunctionOrigin::GeneratedImageEntry {
                        semantic_function: 0,
                        constructor: 0,
                    },
                    FunctionRole::ImageEntry,
                    FunctionColor::Sync,
                ),
                function(
                    1,
                    "root_turn",
                    FunctionOrigin::GeneratedAsyncState {
                        semantic_function: 0,
                        state: 0,
                    },
                    FunctionRole::ActorTurn(ActorId(0)),
                    FunctionColor::Async,
                ),
                function(
                    2,
                    "worker_turn",
                    FunctionOrigin::GeneratedAsyncState {
                        semantic_function: 0,
                        state: 0,
                    },
                    FunctionRole::ActorTurn(ActorId(1)),
                    FunctionColor::Async,
                ),
                function(
                    3,
                    "flush_task",
                    FunctionOrigin::GeneratedAsyncState {
                        semantic_function: 0,
                        state: 0,
                    },
                    FunctionRole::TaskEntry(TaskId(0)),
                    FunctionColor::Async,
                ),
            ],
            actors: vec![
                ActorPlan {
                    id: ActorId(0),
                    name: "root".to_owned(),
                    state_type: TypeId(0),
                    mailbox_capacity: 8,
                    message_types: vec![TypeId(0)],
                    turn_functions: vec![FunctionId(1)],
                    priority: 1,
                    supervisor: None,
                },
                ActorPlan {
                    id: ActorId(1),
                    name: "worker".to_owned(),
                    state_type: TypeId(0),
                    mailbox_capacity: 4,
                    message_types: vec![TypeId(0)],
                    turn_functions: vec![FunctionId(2)],
                    priority: 2,
                    supervisor: Some(ActorId(0)),
                },
            ],
            tasks: vec![TaskPlan {
                id: TaskId(0),
                name: "flush".to_owned(),
                entry: FunctionId(3),
                slots: 2,
                priority: 3,
                frame_bytes_bound: 16,
                supervisor: Some(ActorId(1)),
            }],
            devices: Vec::new(),
            pools: Vec::new(),
            regions: vec![
                RegionPlan {
                    id: RegionId(0),
                    name: "root.mailbox".to_owned(),
                    class: RegionClass::Image,
                    capacity_bytes: 128,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(0)),
                    capacity_proof: ProofId(3),
                    source,
                },
                RegionPlan {
                    id: RegionId(1),
                    name: "root.turn-frame".to_owned(),
                    class: RegionClass::TaskFrame,
                    capacity_bytes: 1,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(0)),
                    capacity_proof: ProofId(4),
                    source,
                },
                RegionPlan {
                    id: RegionId(2),
                    name: "worker.mailbox".to_owned(),
                    class: RegionClass::Image,
                    capacity_bytes: 64,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(1)),
                    capacity_proof: ProofId(5),
                    source,
                },
                RegionPlan {
                    id: RegionId(3),
                    name: "worker.turn-frame".to_owned(),
                    class: RegionClass::TaskFrame,
                    capacity_bytes: 1,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(1)),
                    capacity_proof: ProofId(6),
                    source,
                },
                RegionPlan {
                    id: RegionId(4),
                    name: "flush.frame".to_owned(),
                    class: RegionClass::TaskFrame,
                    capacity_bytes: 32,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Task(TaskId(0)),
                    capacity_proof: ProofId(7),
                    source,
                },
            ],
            activations: Vec::new(),
            schedulers: vec![SchedulerPlan {
                core: 0,
                actors: vec![ActorId(0), ActorId(1)],
                tasks: vec![TaskId(0)],
            }],
            proofs: vec![
                Proof {
                    id: ProofId(0),
                    kind: ProofKind::TypeChecked,
                    subject: "actor/task report fixture types".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: None,
                    explanation: vec!["sealed fixture type proof".to_owned()],
                },
                Proof {
                    id: ProofId(1),
                    kind: ProofKind::EffectsAllowed,
                    subject: "actor/task report fixture effects".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(0)],
                    bound: None,
                    explanation: vec!["sealed fixture effect proof".to_owned()],
                },
                Proof {
                    id: ProofId(2),
                    kind: ProofKind::WaitGraphAcyclic,
                    subject: "actor/task report fixture wait graph".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(1)],
                    bound: Some(0),
                    explanation: vec!["sealed fixture wait proof".to_owned()],
                },
                Proof {
                    id: ProofId(3),
                    kind: ProofKind::CapacityBound,
                    subject: "root mailbox capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(8),
                    explanation: vec!["eight root mailbox slots".to_owned()],
                },
                Proof {
                    id: ProofId(4),
                    kind: ProofKind::CapacityBound,
                    subject: "root turn capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(1),
                    explanation: vec!["one root turn frame".to_owned()],
                },
                Proof {
                    id: ProofId(5),
                    kind: ProofKind::CapacityBound,
                    subject: "worker mailbox capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(4),
                    explanation: vec!["four worker mailbox slots".to_owned()],
                },
                Proof {
                    id: ProofId(6),
                    kind: ProofKind::CapacityBound,
                    subject: "worker turn capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(1),
                    explanation: vec!["one worker turn frame".to_owned()],
                },
                Proof {
                    id: ProofId(7),
                    kind: ProofKind::CapacityBound,
                    subject: "flush task capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(2),
                    explanation: vec!["two flush task frames".to_owned()],
                },
                Proof {
                    id: ProofId(8),
                    kind: ProofKind::SupervisionComplete,
                    subject: "complete static actor/task parent topology".to_owned(),
                    sources: vec![source, source, source],
                    depends_on: vec![ProofId(0)],
                    bound: Some(3),
                    explanation: vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()],
                },
                Proof {
                    id: ProofId(9),
                    kind: ProofKind::ImageClosed,
                    subject: "closed actor/task report fixture".to_owned(),
                    sources: vec![source, source, source],
                    depends_on: vec![
                        ProofId(0),
                        ProofId(1),
                        ProofId(2),
                        ProofId(3),
                        ProofId(4),
                        ProofId(5),
                        ProofId(6),
                        ProofId(7),
                        ProofId(8),
                    ],
                    bound: Some(226),
                    explanation: vec!["all actor and task capacities are closed".to_owned()],
                },
            ],
            checkpoints: Vec::new(),
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![
                PlanOwner::Runtime,
                PlanOwner::Actor(ActorId(0)),
                PlanOwner::Actor(ActorId(1)),
                PlanOwner::Task(TaskId(0)),
            ],
            shutdown_order: vec![
                PlanOwner::Task(TaskId(0)),
                PlanOwner::Actor(ActorId(1)),
                PlanOwner::Actor(ActorId(0)),
                PlanOwner::Runtime,
            ],
            image_entry: FunctionId(0),
            static_bytes: 226,
            peak_bytes: 226,
        };
        (
            flow.validate().expect("validated actor report FlowWir"),
            target,
        )
    }

    fn actor_region_report_flow_fixture() -> (wrela_flow_wir::ValidatedFlowWir, TargetPackage) {
        actor_report_flow_fixture()
    }

    fn actor_activation_report_flow_fixture() -> (wrela_flow_wir::ValidatedFlowWir, TargetPackage) {
        let (source_flow, target) = actor_region_report_flow_fixture();
        let source = source_flow.as_wir().regions[0].source;
        let build = source_flow.as_wir().build.clone();
        let unit = TypeId(0);
        let activation = TypeId(1);
        let flow = FlowWir {
            version: FLOW_WIR_VERSION,
            name: "actor-activation-report-image".to_owned(),
            build,
            source_summary: SourceSummary {
                semantic_wir_version: 15,
                semantic_functions: 3,
                hir_files: 1,
                hir_declarations: 3,
                reachable_declarations: 3,
                monomorphized_instantiations: 3,
                resolved_interface_calls: 0,
            },
            types: vec![
                FlowType {
                    id: unit,
                    kind: FlowTypeKind::Unit,
                    name: Some("unit".to_owned()),
                    copyable: true,
                    strict_linear: false,
                },
                FlowType {
                    id: activation,
                    kind: FlowTypeKind::Activation { result: unit },
                    name: Some("__wrela_activation_0".to_owned()),
                    copyable: false,
                    strict_linear: true,
                },
            ],
            globals: Vec::new(),
            functions: vec![
                FlowFunction {
                    id: FunctionId(0),
                    name: "__wrela_image_entry".to_owned(),
                    origin: FunctionOrigin::GeneratedImageEntry {
                        semantic_function: 0,
                        constructor: 0,
                    },
                    role: FunctionRole::ImageEntry,
                    color: FunctionColor::Sync,
                    parameters: Vec::new(),
                    result_types: Vec::new(),
                    values: Vec::new(),
                    blocks: vec![Block {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: Terminator::Return(Vec::new()),
                        source: None,
                    }],
                    entry: BlockId(0),
                    stack_bound: 0,
                    frame_bound: 0,
                    proofs: vec![
                        ProofId(3),
                        ProofId(4),
                        ProofId(5),
                        ProofId(6),
                        ProofId(7),
                        ProofId(9),
                    ],
                    source: None,
                },
                FlowFunction {
                    id: FunctionId(1),
                    name: "async-unit".to_owned(),
                    origin: FunctionOrigin::SourceSemantic {
                        semantic_function: 1,
                    },
                    role: FunctionRole::ActorTurn(ActorId(0)),
                    color: FunctionColor::Async,
                    parameters: Vec::new(),
                    result_types: Vec::new(),
                    values: vec![
                        Value {
                            id: ValueId(0),
                            ty: activation,
                            source_name: None,
                            source: Some(source),
                        },
                        Value {
                            id: ValueId(1),
                            ty: unit,
                            source_name: None,
                            source: Some(source),
                        },
                    ],
                    blocks: vec![
                        Block {
                            id: BlockId(0),
                            parameters: Vec::new(),
                            instructions: vec![Instruction {
                                id: InstructionId(0),
                                results: vec![ValueId(0)],
                                operation: FlowOperation::AsyncCall {
                                    function: FunctionId(2),
                                    arguments: Vec::new(),
                                    plan: ActivationId(0),
                                },
                                source: Some(source),
                            }],
                            terminator: Terminator::Suspend {
                                state: 0,
                                activation: ValueId(0),
                                resume: BlockId(1),
                            },
                            source: Some(source),
                        },
                        Block {
                            id: BlockId(1),
                            parameters: vec![ValueId(1)],
                            instructions: Vec::new(),
                            terminator: Terminator::Return(Vec::new()),
                            source: Some(source),
                        },
                    ],
                    entry: BlockId(0),
                    stack_bound: 8,
                    frame_bound: 8,
                    proofs: vec![ProofId(8)],
                    source: Some(source),
                },
                FlowFunction {
                    id: FunctionId(2),
                    name: "async-helper".to_owned(),
                    origin: FunctionOrigin::SourceSemantic {
                        semantic_function: 2,
                    },
                    role: FunctionRole::Ordinary,
                    color: FunctionColor::Async,
                    parameters: Vec::new(),
                    result_types: Vec::new(),
                    values: Vec::new(),
                    blocks: vec![Block {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: Terminator::Return(Vec::new()),
                        source: Some(source),
                    }],
                    entry: BlockId(0),
                    stack_bound: 8,
                    frame_bound: 8,
                    proofs: vec![ProofId(2)],
                    source: Some(source),
                },
            ],
            actors: vec![ActorPlan {
                id: ActorId(0),
                name: "actor".to_owned(),
                state_type: unit,
                mailbox_capacity: 1,
                message_types: Vec::new(),
                turn_functions: vec![FunctionId(1)],
                priority: 1,
                supervisor: None,
            }],
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: vec![
                RegionPlan {
                    id: RegionId(0),
                    name: "actor.mailbox".to_owned(),
                    class: RegionClass::Image,
                    capacity_bytes: 16,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(0)),
                    capacity_proof: ProofId(3),
                    source,
                },
                RegionPlan {
                    id: RegionId(1),
                    name: "actor.turn-frame".to_owned(),
                    class: RegionClass::TaskFrame,
                    capacity_bytes: 8,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(0)),
                    capacity_proof: ProofId(4),
                    source,
                },
                RegionPlan {
                    id: RegionId(2),
                    name: "async-unit.async-activation-frame".to_owned(),
                    class: RegionClass::TaskFrame,
                    capacity_bytes: 8,
                    alignment: 8,
                    reset_function: None,
                    owner: PlanOwner::Actor(ActorId(0)),
                    capacity_proof: ProofId(8),
                    source,
                },
            ],
            activations: vec![ActivationPlan {
                id: ActivationId(0),
                caller: FunctionId(1),
                callee: FunctionId(2),
                region: RegionId(2),
                frame_bytes: 8,
                maximum_live: 1,
                cancellation: ActivationCancellation::DropCalleeThenPropagate,
                capacity_proof: ProofId(8),
                source,
            }],
            schedulers: vec![SchedulerPlan {
                core: 0,
                actors: vec![ActorId(0)],
                tasks: Vec::new(),
            }],
            proofs: vec![
                Proof {
                    id: ProofId(0),
                    kind: ProofKind::TypeChecked,
                    subject: "actor image types".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: None,
                    explanation: vec!["actor image is typed".to_owned()],
                },
                Proof {
                    id: ProofId(1),
                    kind: ProofKind::EffectsAllowed,
                    subject: "actor image effects".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(0)],
                    bound: None,
                    explanation: vec!["actor image effects are closed".to_owned()],
                },
                Proof {
                    id: ProofId(2),
                    kind: ProofKind::CleanupAcyclic,
                    subject: "helper cleanup".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(0),
                    explanation: vec!["drop helper frame".to_owned()],
                },
                Proof {
                    id: ProofId(3),
                    kind: ProofKind::CapacityBound,
                    subject: "mailbox capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(1),
                    explanation: vec!["one mailbox slot".to_owned()],
                },
                Proof {
                    id: ProofId(4),
                    kind: ProofKind::CapacityBound,
                    subject: "turn capacity".to_owned(),
                    sources: vec![source],
                    depends_on: Vec::new(),
                    bound: Some(1),
                    explanation: vec!["one turn frame".to_owned()],
                },
                Proof {
                    id: ProofId(5),
                    kind: ProofKind::WaitGraphAcyclic,
                    subject: "closed actor wait graph".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(1)],
                    bound: Some(1),
                    explanation: vec!["one acyclic await edge".to_owned()],
                },
                Proof {
                    id: ProofId(6),
                    kind: ProofKind::SupervisionComplete,
                    subject: "complete static actor/task parent topology".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(0)],
                    bound: Some(1),
                    explanation: vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()],
                },
                Proof {
                    id: ProofId(7),
                    kind: ProofKind::CapacityBound,
                    subject: "base actor allocation".to_owned(),
                    sources: vec![source, source],
                    depends_on: vec![
                        ProofId(0),
                        ProofId(1),
                        ProofId(3),
                        ProofId(4),
                        ProofId(5),
                        ProofId(6),
                    ],
                    bound: Some(24),
                    explanation: vec!["mailbox plus root turn frame".to_owned()],
                },
                Proof {
                    id: ProofId(8),
                    kind: ProofKind::CapacityBound,
                    subject: "call activation".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(2)],
                    bound: Some(1),
                    explanation: vec!["one helper frame".to_owned()],
                },
                Proof {
                    id: ProofId(9),
                    kind: ProofKind::ImageClosed,
                    subject: "closed actor image".to_owned(),
                    sources: vec![source],
                    depends_on: vec![ProofId(7), ProofId(8)],
                    bound: Some(32),
                    explanation: vec!["base plus helper activation".to_owned()],
                },
            ],
            checkpoints: Vec::new(),
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![PlanOwner::Runtime, PlanOwner::Actor(ActorId(0))],
            shutdown_order: vec![PlanOwner::Actor(ActorId(0)), PlanOwner::Runtime],
            image_entry: FunctionId(0),
            static_bytes: 32,
            peak_bytes: 32,
        };
        (
            flow.validate()
                .expect("validated actor activation report FlowWir"),
            target,
        )
    }

    fn task_activation_report_flow_fixture() -> (wrela_flow_wir::ValidatedFlowWir, TargetPackage) {
        let (flow, target) = actor_activation_report_flow_fixture();
        let mut flow = flow.as_wir().clone();
        let source = flow.activations[0].source;
        flow.name = "task-activation-report-image".to_owned();
        flow.functions[1].role = FunctionRole::TaskEntry(TaskId(0));
        flow.functions[1].proofs = vec![ProofId(9)];
        flow.functions[0].proofs = vec![
            ProofId(3),
            ProofId(4),
            ProofId(5),
            ProofId(6),
            ProofId(7),
            ProofId(8),
            ProofId(10),
        ];
        flow.functions.push(FlowFunction {
            id: FunctionId(3),
            name: "actor-turn".to_owned(),
            origin: FunctionOrigin::GeneratedAsyncState {
                semantic_function: 0,
                state: 0,
            },
            role: FunctionRole::ActorTurn(ActorId(0)),
            color: FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 1,
            frame_bound: 1,
            proofs: Vec::new(),
            source: Some(source),
        });
        flow.actors[0].turn_functions = vec![FunctionId(3)];
        flow.tasks = vec![TaskPlan {
            id: TaskId(0),
            name: "task".to_owned(),
            entry: FunctionId(1),
            slots: 1,
            priority: 2,
            frame_bytes_bound: 8,
            supervisor: Some(ActorId(0)),
        }];
        flow.schedulers[0].tasks = vec![TaskId(0)];
        flow.regions = vec![
            RegionPlan {
                id: RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(3),
                source,
            },
            RegionPlan {
                id: RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 1,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(4),
                source,
            },
            RegionPlan {
                id: RegionId(2),
                name: "task.frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Task(TaskId(0)),
                capacity_proof: ProofId(5),
                source,
            },
            RegionPlan {
                id: RegionId(3),
                name: "async-unit.async-activation-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Task(TaskId(0)),
                capacity_proof: ProofId(9),
                source,
            },
        ];
        flow.activations[0].region = RegionId(3);
        flow.activations[0].capacity_proof = ProofId(9);
        flow.proofs = vec![
            Proof {
                id: ProofId(0),
                kind: ProofKind::TypeChecked,
                subject: "task activation image types".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: None,
                explanation: vec!["task activation image is typed".to_owned()],
            },
            Proof {
                id: ProofId(1),
                kind: ProofKind::EffectsAllowed,
                subject: "task activation image effects".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(0)],
                bound: None,
                explanation: vec!["task activation effects are closed".to_owned()],
            },
            Proof {
                id: ProofId(2),
                kind: ProofKind::CleanupAcyclic,
                subject: "task helper cleanup".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["drop task helper frame".to_owned()],
            },
            Proof {
                id: ProofId(3),
                kind: ProofKind::CapacityBound,
                subject: "actor mailbox capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one actor mailbox slot".to_owned()],
            },
            Proof {
                id: ProofId(4),
                kind: ProofKind::CapacityBound,
                subject: "actor turn capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one actor turn frame".to_owned()],
            },
            Proof {
                id: ProofId(5),
                kind: ProofKind::CapacityBound,
                subject: "task frame capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one task root frame".to_owned()],
            },
            Proof {
                id: ProofId(6),
                kind: ProofKind::WaitGraphAcyclic,
                subject: "task activation wait graph".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(1)],
                bound: Some(1),
                explanation: vec!["one acyclic task await edge".to_owned()],
            },
            Proof {
                id: ProofId(7),
                kind: ProofKind::SupervisionComplete,
                subject: "complete static actor/task parent topology".to_owned(),
                sources: vec![source, source],
                depends_on: vec![ProofId(0)],
                bound: Some(2),
                explanation: vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()],
            },
            Proof {
                id: ProofId(8),
                kind: ProofKind::CapacityBound,
                subject: "base actor and task allocation".to_owned(),
                sources: vec![source, source],
                depends_on: vec![
                    ProofId(0),
                    ProofId(1),
                    ProofId(3),
                    ProofId(4),
                    ProofId(5),
                    ProofId(6),
                    ProofId(7),
                ],
                bound: Some(25),
                explanation: vec!["actor and task root frames are closed".to_owned()],
            },
            Proof {
                id: ProofId(9),
                kind: ProofKind::CapacityBound,
                subject: "task helper activation".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(2)],
                bound: Some(1),
                explanation: vec!["one suspended task helper frame".to_owned()],
            },
            Proof {
                id: ProofId(10),
                kind: ProofKind::ImageClosed,
                subject: "closed task activation image".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(8), ProofId(9)],
                bound: Some(33),
                explanation: vec!["base allocation plus task helper activation".to_owned()],
            },
        ];
        flow.startup_order = vec![
            PlanOwner::Runtime,
            PlanOwner::Actor(ActorId(0)),
            PlanOwner::Task(TaskId(0)),
        ];
        flow.shutdown_order = vec![
            PlanOwner::Task(TaskId(0)),
            PlanOwner::Actor(ActorId(0)),
            PlanOwner::Runtime,
        ];
        flow.static_bytes = 33;
        flow.peak_bytes = 33;
        (
            flow.validate()
                .expect("validated task activation report FlowWir"),
            target,
        )
    }

    #[test]
    fn backend_limits_reject_decode_optimization_test_policy_drift() {
        let mut limits = BackendLimits::standard();
        limits.optimization.test_plan.events_per_group -= 1;
        assert!(matches!(
            limits.validate(),
            Err(BackendExecutionError::InvalidRequest(_))
        ));
    }

    #[test]
    fn backend_limits_reject_machine_validation_policy_drift() {
        for drifted in [
            {
                let mut limits = BackendLimits::standard();
                limits.machine.validation.arena_records -= 1;
                limits
            },
            {
                let mut limits = BackendLimits::standard();
                limits.machine.validation.model_edges -= 1;
                limits
            },
            {
                let mut limits = BackendLimits::standard();
                limits.machine.validation.payload_bytes -= 1;
                limits
            },
        ] {
            let error = drifted.validate().expect_err("nested policy drift");
            assert!(matches!(error, BackendExecutionError::InvalidRequest(_)));
            assert!(error.to_string().contains("must exactly match"));
        }

        let mut caller_owned = BackendLimits::standard();
        caller_owned.machine.model_edges -= 1;
        caller_owned.machine.payload_bytes -= 1;
        caller_owned.machine.instructions -= 1;
        caller_owned.machine.validation.validation_work = 17;
        caller_owned.machine = caller_owned.machine.with_aligned_validation();
        caller_owned
            .validate()
            .expect("aligned caller-owned machine validation policy");
        assert_eq!(caller_owned.machine.validation.validation_work, 17);
        assert_eq!(
            caller_owned.machine.validation.model_edges,
            caller_owned.machine.model_edges
        );
        assert_eq!(
            caller_owned.machine.validation.payload_bytes,
            caller_owned.machine.payload_bytes
        );
    }

    fn paths(root: &str) -> BackendJobPathCandidate {
        let root = PathBuf::from(root);
        BackendJobPathCandidate {
            generated_object: root.join("image.obj"),
            temporary_image: root.join("image.tmp.efi"),
            temporary_map: root.join("image.tmp.map"),
            temporary_report: root.join("image.tmp.json"),
            final_image: root.join("image.efi"),
            final_report: root.join("image.json"),
            private_root: root,
        }
    }

    #[test]
    fn backend_paths_require_one_normal_private_namespace() {
        BackendJobPaths::new(paths("/private/wrela/job")).expect("valid private namespace");
        assert!(matches!(
            BackendJobPaths::new(paths("/")),
            Err(BackendExecutionError::InvalidPaths)
        ));
        assert!(matches!(
            BackendJobPaths::new(paths("/private/./wrela/job")),
            Err(BackendExecutionError::InvalidPaths)
        ));
        assert!(matches!(
            BackendJobPaths::new(paths("/private/wrela/../job")),
            Err(BackendExecutionError::InvalidPaths)
        ));

        let mut duplicate = paths("/private/wrela/job");
        duplicate.final_report = duplicate.final_image.clone();
        assert!(matches!(
            BackendJobPaths::new(duplicate),
            Err(BackendExecutionError::InvalidPaths)
        ));

        let mut root_as_file = paths("/private/wrela/job");
        root_as_file.final_report = root_as_file.private_root.clone();
        assert!(matches!(
            BackendJobPaths::new(root_as_file),
            Err(BackendExecutionError::InvalidPaths)
        ));
    }

    #[test]
    fn canonical_hasher_is_exact_and_polls_cancellation() {
        let hasher = CanonicalBackendContentHasher::new();
        assert_eq!(
            hasher.sha256(b"abc", &|| false),
            Some(Sha256Digest::from_bytes([
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]))
        );
        let polls = Cell::new(0u32);
        let cancel = || {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded cancellation polls"),
            );
            polls.get() >= 2
        };
        assert_eq!(hasher.sha256(&[0u8; 64 * 1024 + 1], &cancel), None);
        assert_eq!(polls.get(), 2);
    }

    #[test]
    fn validated_flow_projects_canonical_actor_task_report_graph() {
        let (flow, target) = actor_report_flow_fixture();
        let mut cyclic = flow.as_wir().clone();
        cyclic.actors[0].supervisor = Some(ActorId(1));
        assert!(
            cyclic.validate().is_err(),
            "the authenticated actor-parent forest rejects a mutual cycle"
        );
        let projected = analysis_facts(flow.as_wir(), &target, &|| false)
            .expect("project validated actor report facts");
        for (kind, name, owner, source, bytes) in [
            ("actor", "actor:0:root", "runtime", "FlowWir.ActorPlan", 0),
            ("actor", "actor:1:worker", "runtime", "FlowWir.ActorPlan", 0),
            (
                "task",
                "task:0:flush",
                "actor:1:worker",
                "FlowWir.TaskPlan",
                0,
            ),
        ] {
            assert!(projected.image_nodes.iter().any(|node| {
                node.kind == kind
                    && node.name == name
                    && node.owner == owner
                    && node.source == source
                    && node.static_bytes == bytes
            }));
        }
        assert!(projected.image_edges.iter().any(|edge| {
            edge.kind == "actor-supervision"
                && edge.source == "actor:1:worker"
                && edge.destination == "actor:0:root"
                && edge.capacity.is_none()
                && edge.priority == Some(2)
        }));
        assert!(projected.image_edges.iter().any(|edge| {
            edge.kind == "task-supervision"
                && edge.source == "task:0:flush"
                && edge.destination == "actor:1:worker"
                && edge.capacity == Some(2)
                && edge.priority == Some(3)
        }));
        assert_eq!(projected.scheduler_ownership.len(), 1);
        assert_eq!(projected.scheduler_ownership[0].core, 0);
        assert_eq!(
            projected.scheduler_ownership[0].actors,
            ["actor:0:root", "actor:1:worker"]
        );
        assert_eq!(projected.scheduler_ownership[0].tasks, ["task:0:flush"]);
        assert_eq!(projected.proofs[8].category, "supervision-complete");
        assert_eq!(projected.region_capacity_evidence.len(), 5);
        assert_eq!(
            exact_region_capacity_proof(flow.as_wir(), ProofId(3)),
            Ok(3)
        );
        assert!(matches!(
            exact_region_capacity_proof(flow.as_wir(), ProofId(0)),
            Err(BackendReportError::Mismatch(_))
        ));
        let mut wrong_kind = flow.as_wir().clone();
        wrong_kind.proofs[3].kind = ProofKind::Ownership;
        assert!(matches!(
            exact_region_capacity_proof(&wrong_kind, ProofId(3)),
            Err(BackendReportError::Mismatch(_))
        ));
        assert_eq!(
            projected.startup_order,
            ["runtime", "actor:0:root", "actor:1:worker", "task:0:flush"]
        );

        let item_count = [
            projected.bounds.len(),
            projected.proofs.len(),
            projected.image_nodes.len(),
            projected.region_capacity_evidence.len(),
            projected.image_edges.len(),
            projected.work.len(),
            projected.scheduler_ownership.len(),
            projected
                .scheduler_ownership
                .iter()
                .map(|fact| fact.actors.len() + fact.tasks.len())
                .sum(),
            projected.startup_order.len(),
            projected.shutdown_order.len(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, count| {
            total.checked_add(u64::try_from(count).expect("bounded projected fact count"))
        })
        .expect("bounded projected fact total");
        let build = &flow.as_wir().build;
        let limits = AnalysisFactLimits {
            items: item_count,
            proof_edges: projected
                .proofs
                .iter()
                .map(|proof| proof.sources.len() + proof.depends_on.len() + proof.why_chain.len())
                .try_fold(0_u64, |total, count| {
                    total.checked_add(u64::try_from(count).expect("bounded proof edges"))
                })
                .expect("bounded proof edge total"),
            payload_bytes: 64 * 1024,
        };
        let sealed = seal_analysis_facts(
            AnalysisFactRequest {
                build,
                image_name: &flow.as_wir().name,
                limits,
            },
            projected.clone(),
            &|| false,
        )
        .expect("exact actor report consumer limit");
        sealed
            .as_facts()
            .image_nodes
            .iter()
            .find(|node| node.name == "task:0:flush")
            .expect("canonical task node");

        let mut substituted = projected;
        let edge = substituted
            .image_edges
            .iter_mut()
            .find(|edge| edge.kind == "actor-supervision")
            .expect("actor supervision edge");
        edge.destination = "actor:0".to_owned();
        assert_eq!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    build,
                    image_name: &flow.as_wir().name,
                    limits: AnalysisFactLimits::standard(),
                },
                substituted,
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        );

        let polls = Cell::new(0_u64);
        analysis_facts(flow.as_wir(), &target, &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded report projection polls"),
            );
            false
        })
        .expect("measure report projection cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            analysis_facts(flow.as_wir(), &target, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded report projection polls");
                polls.set(next);
                next == cancel_at
            }),
            Err(BackendReportError::Cancelled)
        );
    }

    #[test]
    fn actor_placement_input_join_is_exact_and_withholds_partial_profiles() {
        let (validated, _) = actor_report_flow_fixture();
        assert!(
            actor_placement_inputs(validated.as_wir(), &|| false)
                .expect("inspect absent work inputs")
                .is_empty(),
            "a missing turn-work fact withholds the entire placement input set"
        );

        let mut bounded = validated.as_wir().clone();
        let source = bounded.regions[0].source;
        bounded.checkpoints = vec![
            Checkpoint {
                id: CheckpointId(0),
                function: FunctionId(1),
                source,
                uninterrupted_bound: 11,
                may_observe_cancellation: true,
                may_yield: true,
            },
            Checkpoint {
                id: CheckpointId(1),
                function: FunctionId(2),
                source,
                uninterrupted_bound: 7,
                may_observe_cancellation: true,
                may_yield: true,
            },
        ];
        let joined = actor_placement_inputs(&bounded, &|| false)
            .expect("join exact actor work and owned-region bytes");
        assert_eq!(joined.len(), 2);
        assert_eq!(joined[0].actor, "actor:0:root");
        assert_eq!(joined[0].maximum_uninterrupted_work, 11);
        assert_eq!(joined[0].reserved_region_bytes, 129);
        assert_eq!(joined[1].actor, "actor:1:worker");
        assert_eq!(joined[1].maximum_uninterrupted_work, 7);
        assert_eq!(joined[1].reserved_region_bytes, 65);

        let polls = Cell::new(0_u64);
        actor_placement_inputs(&bounded, &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("measure exact placement-input projection polls");
        let exact_stop = polls.get();
        let polls = Cell::new(0_u64);
        assert!(matches!(
            actor_placement_inputs(&bounded, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == exact_stop
            }),
            Err(BackendReportError::Cancelled)
        ));

        bounded.checkpoints.pop();
        assert!(
            actor_placement_inputs(&bounded, &|| false)
                .expect("inspect incomplete input set")
                .is_empty(),
            "one missing actor input must not publish a prefix-valid proposal source"
        );
    }

    #[test]
    fn reportable_region_projects_exact_capacity_proof_and_nonregion_links_stay_absent() {
        let (flow, target) = actor_region_report_flow_fixture();
        let projected = analysis_facts(flow.as_wir(), &target, &|| false)
            .expect("project validated reportable region facts");
        assert!(projected.region_capacity_evidence.iter().any(|evidence| {
            evidence
                == &RegionCapacityEvidenceFact {
                    region: "region:4:flush.frame".to_owned(),
                    capacity_proof: 7,
                }
        }));
        assert!(projected.image_nodes.iter().any(|node| {
            node.kind == "task-frame-region"
                && node.name == "region:4:flush.frame"
                && node.owner == "task:0:flush"
                && node.source == "file:0:bytes:0..0"
                && node.static_bytes == 32
        }));
        assert!(projected.bounds.iter().any(|bound| {
            bound.category == "region-capacity"
                && bound.owner == "region:4:flush.frame"
                && bound.amount == 32
                && bound.unit == "bytes"
        }));
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &flow.as_wir().build,
                image_name: &flow.as_wir().name,
                limits: AnalysisFactLimits::standard(),
            },
            projected,
            &|| false,
        )
        .expect("seal exact reportable-region proof join");

        let mut nonreportable = flow.as_wir().clone();
        nonreportable.regions[4].class = RegionClass::Call;
        let projected = analysis_facts(&nonreportable, &target, &|| false)
            .expect("project nonreportable region without evidence");
        assert!(
            projected
                .region_capacity_evidence
                .iter()
                .all(|evidence| evidence.region != "region:4:flush.frame")
        );
        assert!(
            projected
                .image_nodes
                .iter()
                .all(|node| node.name != "region:4:flush.frame")
        );
    }

    #[test]
    fn validated_actor_activation_projects_exact_plan_and_proof_traceability() {
        let (flow, target) = actor_activation_report_flow_fixture();
        let projected = analysis_facts(flow.as_wir(), &target, &|| false)
            .expect("project validated actor activation report facts");
        assert_eq!(projected.activation_frame_evidence.len(), 1);
        let activation = &projected.activation_frame_evidence[0];
        assert_eq!(activation.plan, 0);
        assert_eq!(
            activation.region,
            "region:2:async-unit.async-activation-frame"
        );
        assert_eq!(activation.caller, "function:1:async-unit");
        assert_eq!(activation.callee, "function:2:async-helper");
        assert_eq!(activation.owner, "actor:0:actor");
        assert_eq!(activation.source, "file:0:bytes:0..0");
        assert_eq!(activation.frame_bytes, 8);
        assert_eq!(activation.maximum_live, 1);
        assert_eq!(activation.capacity_proof, 8);
        assert!(projected.image_nodes.iter().any(|node| {
            node.kind == "actor-activation-frame-region"
                && node.name == activation.region
                && node.owner == activation.owner
                && node.source == activation.source
                && node.static_bytes == 8
        }));
        assert!(projected.region_capacity_evidence.iter().any(|evidence| {
            evidence.region == activation.region && evidence.capacity_proof == 8
        }));
        let proof = &projected.proofs[8];
        assert_eq!(proof.bound, Some(1));
        assert_eq!(proof.sources, ["file:0:bytes:0..0"]);
        assert_eq!(proof.depends_on, [2]);
        assert_eq!(projected.proofs[2].category, "cleanup-acyclic");
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &flow.as_wir().build,
                image_name: &flow.as_wir().name,
                limits: AnalysisFactLimits::standard(),
            },
            projected,
            &|| false,
        )
        .expect("seal exact actor activation traceability");

        let regions = reportable_activation_regions(flow.as_wir(), &|| false)
            .expect("index exact activation-linked region");
        assert_eq!(regions, [None, None, Some(0)]);

        let mut substituted_region = flow.as_wir().clone();
        substituted_region.activations[0].region = RegionId(1);
        assert!(matches!(
            reportable_activation_regions(&substituted_region, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));

        let mut duplicate_region = flow.as_wir().clone();
        let mut duplicate = duplicate_region.activations[0].clone();
        duplicate.id = ActivationId(1);
        duplicate_region.activations.push(duplicate);
        assert!(matches!(
            reportable_activation_regions(&duplicate_region, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));

        let mut substituted_source = flow.as_wir().clone();
        substituted_source.activations[0].source.range.end = 1;
        assert!(matches!(
            reportable_activation_regions(&substituted_source, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));

        let mut substituted_proof = flow.as_wir().clone();
        substituted_proof.activations[0].capacity_proof = ProofId(4);
        assert!(matches!(
            reportable_activation_regions(&substituted_proof, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));

        let polls = Cell::new(0_u64);
        reportable_activation_regions(flow.as_wir(), &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded activation projection polls"),
            );
            false
        })
        .expect("measure activation projection polls");
        let exact_stop = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            reportable_activation_regions(flow.as_wir(), &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded activation projection polls");
                polls.set(next);
                next == exact_stop
            }),
            Err(BackendReportError::Cancelled)
        );
    }

    /// The exact completed-activation profile: the task-entry caller suspends
    /// on its single immediate activation and resets that activation's own
    /// task-frame region as the only instruction of the resume block.
    fn completed_activation_reset_report_flow_fixture()
    -> (wrela_flow_wir::ValidatedFlowWir, TargetPackage) {
        let (flow, target) = task_activation_report_flow_fixture();
        let mut flow = flow.as_wir().clone();
        let source = flow.activations[0].source;
        flow.name = "completed-activation-reset-report-image".to_owned();
        flow.functions[1].blocks[1].instructions = vec![Instruction {
            id: InstructionId(1),
            results: Vec::new(),
            operation: FlowOperation::RegionReset {
                region: flow.activations[0].region,
            },
            source: Some(source),
        }];
        (
            flow.validate()
                .expect("validated completed-activation reset report FlowWir"),
            target,
        )
    }

    #[test]
    fn completed_activation_reset_projects_exact_task_frame_region_contract() {
        let (flow, target) = completed_activation_reset_report_flow_fixture();
        let projected = analysis_facts(flow.as_wir(), &target, &|| false)
            .expect("project completed-activation reset report facts");
        assert_eq!(
            projected.activation_frame_resets,
            [ActivationFrameResetFact {
                plan: 0,
                region: "region:3:async-unit.async-activation-frame".to_owned(),
                owner: "task:0:task".to_owned(),
                source: "file:0:bytes:0..0".to_owned(),
                region_class: wrela_image_report::RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                capacity_proof: 9,
                capacity_bound: 1,
            }]
        );
        let [activation] = projected.activation_frame_evidence.as_slice() else {
            panic!("one exact completed activation evidence record")
        };
        assert_eq!(activation.plan, projected.activation_frame_resets[0].plan);
        assert_eq!(
            activation.region,
            projected.activation_frame_resets[0].region
        );
        assert_eq!(activation.owner, projected.activation_frame_resets[0].owner);
        assert_eq!(
            activation.frame_bytes,
            projected.activation_frame_resets[0].capacity_bytes
        );
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &flow.as_wir().build,
                image_name: &flow.as_wir().name,
                limits: AnalysisFactLimits::standard(),
            },
            projected.clone(),
            &|| false,
        )
        .expect("seal exact completed-activation reset contract");

        // A report that claims a different region contract than the FlowWir
        // authenticated is rejected at the exact analysis binding.
        for mutate in [
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_bytes = 16,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_bound = 2,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_proof = 5,
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_resets[0].owner = "actor:0:actor".to_owned();
            },
            |facts: &mut AnalysisFacts| facts.activation_frame_resets.clear(),
        ] {
            let mut substituted = projected.clone();
            mutate(&mut substituted);
            assert_eq!(
                require_exact_analysis_binding(&projected, &substituted, &|| false),
                Err(BackendReportError::Mismatch(
                    "report analysis graph, bounds, proofs, or origins differ from FlowWir"
                ))
            );
        }
        assert_eq!(
            require_exact_analysis_binding(&projected, &projected, &|| false),
            Ok(())
        );

        // Every near miss of the admitted profile projects no reset at all
        // rather than a partial or approximate region account.
        let source_flow = flow.as_wir();
        for (mutate_index, mutate) in [
            (|flow: &mut FlowWir| {
                flow.functions[1].blocks[1].instructions[0].source = None;
            }) as fn(&mut FlowWir),
            |flow: &mut FlowWir| {
                flow.functions[1].blocks[1].instructions[0].operation =
                    FlowOperation::RegionReset {
                        region: RegionId(2),
                    };
            },
            |flow: &mut FlowWir| {
                let mut second = flow.functions[1].blocks[1].instructions[0].clone();
                second.id = InstructionId(2);
                flow.functions[1].blocks[1].instructions.push(second);
            },
            |flow: &mut FlowWir| {
                flow.functions[1].blocks[1].instructions.clear();
            },
            |flow: &mut FlowWir| {
                let mut reset = flow.functions[1].blocks[1].instructions.remove(0);
                reset.id = InstructionId(0);
                flow.functions[3].blocks[0].instructions.push(reset);
            },
        ]
        .into_iter()
        .enumerate()
        {
            let mut near_miss = source_flow.clone();
            mutate(&mut near_miss);
            let near_miss = near_miss.validate().unwrap_or_else(|error| {
                panic!("near-miss {mutate_index} stays structurally valid FlowWir: {error:?}")
            });
            let projected = analysis_facts(near_miss.as_wir(), &target, &|| false)
                .expect("project near-miss reset profile");
            assert!(projected.activation_frame_resets.is_empty());
        }

        let polls = Cell::new(0_u64);
        reportable_activation_frame_resets(source_flow, &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded reset projection polls"),
            );
            false
        })
        .expect("measure reset projection polls");
        let exact_stop = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            reportable_activation_frame_resets(source_flow, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded reset projection polls");
                polls.set(next);
                next == exact_stop
            }),
            Err(BackendReportError::Cancelled)
        );
        assert_eq!(polls.get(), exact_stop);
    }

    #[test]
    fn validated_task_activation_projects_distinct_task_owned_frame_kind() {
        let (flow, target) = task_activation_report_flow_fixture();
        let projected = analysis_facts(flow.as_wir(), &target, &|| false)
            .expect("project validated task activation report facts");
        let [activation] = projected.activation_frame_evidence.as_slice() else {
            panic!("one exact task activation evidence record")
        };
        assert_eq!(activation.plan, 0);
        assert_eq!(
            activation.region,
            "region:3:async-unit.async-activation-frame"
        );
        assert_eq!(activation.caller, "function:1:async-unit");
        assert_eq!(activation.callee, "function:2:async-helper");
        assert_eq!(activation.owner, "task:0:task");
        assert_eq!(activation.capacity_proof, 9);
        assert!(projected.image_nodes.iter().any(|node| {
            node.kind == "task-activation-frame-region"
                && node.name == activation.region
                && node.owner == activation.owner
                && node.source == activation.source
                && node.static_bytes == 8
        }));
        assert!(
            projected
                .image_nodes
                .iter()
                .all(|node| { node.name != activation.region || node.kind != "task-frame-region" })
        );
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &flow.as_wir().build,
                image_name: &flow.as_wir().name,
                limits: AnalysisFactLimits::standard(),
            },
            projected,
            &|| false,
        )
        .expect("seal exact task activation traceability");
    }

    #[test]
    fn region_roles_and_source_origins_use_exact_flow_provenance() {
        assert_eq!(
            report_region_kind(
                PlanOwner::Actor(ActorId(0)),
                wrela_flow_wir::RegionClass::Image,
            ),
            Some("actor-mailbox-region")
        );
        assert_eq!(
            report_region_kind(
                PlanOwner::Actor(ActorId(0)),
                wrela_flow_wir::RegionClass::TaskFrame,
            ),
            Some("actor-turn-frame-region")
        );
        assert_eq!(
            report_region_kind(
                PlanOwner::Task(TaskId(0)),
                wrela_flow_wir::RegionClass::TaskFrame,
            ),
            Some("task-frame-region")
        );
        assert_eq!(
            report_region_kind(
                PlanOwner::Actor(ActorId(0)),
                wrela_flow_wir::RegionClass::Call,
            ),
            None
        );
        assert_eq!(
            source_identity(7, 11, 19).expect("bounded source identity"),
            "file:7:bytes:11..19"
        );
        assert!(matches!(
            source_identity(7, 19, 11),
            Err(BackendReportError::Mismatch(
                "analysis source identity range is reversed"
            ))
        ));
    }

    #[test]
    fn exact_analysis_binding_rejects_substituted_region_capacity_proof_id() {
        let long_caller = format!("function:0:{}", "caller".repeat(2_048));
        let expected = AnalysisFacts {
            actor_placement_inputs: vec![ActorPlacementInputFact {
                actor: "actor:0:owner".to_owned(),
                maximum_uninterrupted_work: 7,
                reserved_region_bytes: 8,
            }],
            region_capacity_evidence: vec![RegionCapacityEvidenceFact {
                region: "region:0:frame".to_owned(),
                capacity_proof: 3,
            }],
            activation_frame_evidence: vec![ActivationFrameEvidenceFact {
                plan: 0,
                region: "region:0:frame".to_owned(),
                caller: long_caller,
                callee: "function:1:callee".to_owned(),
                owner: "actor:0:owner".to_owned(),
                source: "file:0:bytes:0..1".to_owned(),
                frame_bytes: 8,
                maximum_live: 1,
                cancellation: ActivationCancellationFact::DropCalleeThenPropagate,
                capacity_proof: 3,
            }],
            proofs: vec![
                ProofFact {
                    id: 0,
                    category: "cleanup-acyclic".to_owned(),
                    subject: "callee cleanup".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(0),
                    sources: vec!["file:0:bytes:0..1".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["drop callee".to_owned()],
                },
                ProofFact {
                    id: 1,
                    category: "capacity-bound".to_owned(),
                    subject: "activation capacity".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: vec!["file:0:bytes:0..1".to_owned()],
                    depends_on: vec![0],
                    why_chain: vec!["one frame".to_owned()],
                },
            ],
            ..AnalysisFacts::default()
        };
        let mut substituted = expected.clone();
        substituted.region_capacity_evidence[0].capacity_proof = 4;
        assert!(matches!(
            require_exact_analysis_binding(&expected, &substituted, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));

        let mut wrong_region = expected.clone();
        wrong_region.region_capacity_evidence[0].region = "region:1:frame".to_owned();
        assert!(matches!(
            require_exact_analysis_binding(&expected, &wrong_region, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));
        let mut wrong_placement_input = expected.clone();
        wrong_placement_input.actor_placement_inputs[0].reserved_region_bytes = 9;
        assert!(matches!(
            require_exact_analysis_binding(&expected, &wrong_placement_input, &|| false),
            Err(BackendReportError::Mismatch(_))
        ));
        for mutate in [
            |facts: &mut AnalysisFacts| facts.activation_frame_evidence[0].capacity_proof = 4,
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_evidence[0].callee = "function:2:other".to_owned();
            },
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_evidence[0].maximum_live = 2;
            },
            |facts: &mut AnalysisFacts| facts.proofs[1].bound = Some(2),
            |facts: &mut AnalysisFacts| {
                facts.proofs[1].sources[0] = "file:0:bytes:1..1".to_owned();
            },
            |facts: &mut AnalysisFacts| facts.proofs[1].depends_on.clear(),
        ] {
            let mut substituted = expected.clone();
            mutate(&mut substituted);
            assert!(matches!(
                require_exact_analysis_binding(&expected, &substituted, &|| false),
                Err(BackendReportError::Mismatch(_))
            ));
        }
        assert_eq!(
            require_exact_analysis_binding(&expected, &expected, &|| false),
            Ok(())
        );
        let polls = Cell::new(0_u64);
        require_exact_analysis_binding(&expected, &expected, &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded exact-binding polls"),
            );
            false
        })
        .expect("measure exact binding cancellation polls");
        let exact_stop = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            require_exact_analysis_binding(&expected, &expected, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded exact-binding polls");
                polls.set(next);
                next == exact_stop
            }),
            Err(BackendReportError::Cancelled)
        );
    }

    #[test]
    fn relocation_evidence_binding_rejects_each_artifact_substitution() {
        let artifact_digest = Sha256Digest::from_bytes([0x71; 32]);
        let provenance_digest = Sha256Digest::from_bytes([0x72; 32]);
        let measurements = wrela_link_efi::ImageMeasurements {
            artifact_bytes: 1_536,
            artifact_digest,
            coff_machine: "ARM64".to_owned(),
            subsystem: "EFI_APPLICATION".to_owned(),
            image_base: 0x4000_0000,
            entry_symbol: "wrela_image_entry".to_owned(),
            entry_virtual_address: 0x4000_1000,
            relocation_directory_bytes: 12,
            base_relocation_blocks: 1,
            base_relocations: 1,
            base_relocation_provenance_digest: provenance_digest,
            sections: Vec::new(),
            symbols: Vec::new(),
        };
        let report = wrela_image_report::BackendFacts {
            flow_wir_digest: Sha256Digest::from_bytes([0x73; 32]),
            artifact_bytes: measurements.artifact_bytes,
            artifact_digest: measurements.artifact_digest,
            relocation_directory_bytes: measurements.relocation_directory_bytes,
            base_relocation_blocks: measurements.base_relocation_blocks,
            base_relocation_dir64_count: measurements.base_relocations,
            base_relocation_provenance_digest: measurements.base_relocation_provenance_digest,
            sections: Vec::new(),
            symbols: Vec::new(),
            representations: wrela_image_report::RepresentationFacts {
                semantic_wir_version: 1,
                flow_wir_version: 1,
                flow_wir_wire_version: 1,
                machine_wir_version: 1,
                runtime_abi_version: 2,
                optimization_pipeline_name: "fixture".to_owned(),
                optimization_pipeline_revision: 1,
                optimization_pipeline_implementation: Sha256Digest::from_bytes([0x74; 32]),
            },
            required_runtime_intrinsics: Vec::new(),
            target_variable_reservations: Vec::new(),
            excluded_target_variables: Vec::new(),
            optimization_decisions: Vec::new(),
        };
        assert!(report_artifact_measurements_match(&report, &measurements));

        let reject = |mut substituted: wrela_image_report::BackendFacts,
                      mutate: fn(&mut wrela_image_report::BackendFacts)| {
            mutate(&mut substituted);
            assert!(!report_artifact_measurements_match(
                &substituted,
                &measurements
            ));
        };
        reject(report.clone(), |report| {
            report.artifact_bytes = report
                .artifact_bytes
                .checked_add(1)
                .expect("bounded substituted artifact extent");
        });
        reject(report.clone(), |report| {
            report.artifact_digest = Sha256Digest::from_bytes([0x75; 32]);
        });
        reject(report.clone(), |report| {
            report.relocation_directory_bytes = report
                .relocation_directory_bytes
                .checked_add(4)
                .expect("bounded substituted relocation extent");
        });
        reject(report.clone(), |report| {
            report.base_relocation_blocks = report
                .base_relocation_blocks
                .checked_add(1)
                .expect("bounded substituted relocation blocks");
        });
        reject(report.clone(), |report| {
            report.base_relocation_dir64_count = report
                .base_relocation_dir64_count
                .checked_add(1)
                .expect("bounded substituted DIR64 count");
        });
        reject(report, |report| {
            report.base_relocation_provenance_digest = Sha256Digest::from_bytes([0x76; 32]);
        });
    }

    #[test]
    fn preparation_cancellation_classification_is_exact_across_wrapped_stages() {
        let cancellations = [
            BackendInputError::Cancelled,
            BackendInputError::Decode(wrela_flow_wir_codec::CodecError::Cancelled),
            BackendInputError::Optimize(wrela_flow_opt::OptimizeError::Cancelled),
            BackendInputError::MachineLower(MachineLowerError::Cancelled),
        ];
        for error in cancellations {
            assert!(error.is_cancelled());
        }

        assert!(!BackendInputError::FlowWirDigestMismatch.is_cancelled());
        assert!(
            !BackendInputError::MachineLower(MachineLowerError::UnsupportedInput {
                feature: "nearby non-cancellation fixture",
            })
            .is_cancelled()
        );
    }
}
