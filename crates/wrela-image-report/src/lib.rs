//! Backend-neutral, versioned image-report schema and deterministic rendering.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{BuildIdentity, Sha256Digest};

/// Current machine-readable report schema.
pub const REPORT_SCHEMA_VERSION: u32 = 5;

/// One finite capacity or memory fact established by the build.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundFact {
    pub category: String,
    pub owner: String,
    pub source: String,
    pub amount: u64,
    pub unit: String,
}

/// One proof result or required recovery path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProofFact {
    /// Dense FlowWir proof ID retained so optimization decisions can refer to
    /// the exact proof they consumed.
    pub id: u32,
    pub category: String,
    pub subject: String,
    pub result: String,
    pub why_chain: Vec<String>,
}

/// Physical lowering selected for one logical actor edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActorLoweringKind {
    Queued,
    DirectDispatch,
    TailForwarded,
    Fused,
}

impl ActorLoweringKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::DirectDispatch => "direct-dispatch",
            Self::TailForwarded => "tail-forwarded",
            Self::Fused => "fused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorLoweringFact {
    pub source: String,
    pub destination: String,
    pub message: String,
    pub kind: ActorLoweringKind,
    pub logical_slots: u64,
    pub physical_bytes: u64,
}

/// One logical node produced by compile-time image construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageNodeFact {
    pub kind: String,
    pub name: String,
    pub owner: String,
    pub source: String,
    pub static_bytes: u64,
}

/// One logical scheduling, request, supervision, or hardware edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageEdgeFact {
    pub kind: String,
    pub source: String,
    pub destination: String,
    pub capacity: Option<u64>,
    pub priority: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkFact {
    pub function: String,
    pub stack_bytes: u64,
    pub frame_bytes: u64,
    pub uninterrupted_work: Option<u64>,
    pub checkpoint_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HardwareFact {
    pub device: String,
    pub binding: String,
    pub owner: String,
    pub dma_policy: String,
    pub queue_capacity: Option<u64>,
    pub maximum_in_flight: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryFact {
    pub subject: String,
    pub supervisor: String,
    pub reset_timeout_ns: u64,
    pub quarantine_bytes: u64,
    pub cleanup_path: Vec<String>,
}

/// Frontend and WIR facts independent of final object bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisFacts {
    pub reachable_declarations: u64,
    pub monomorphized_instantiations: u64,
    pub resolved_interface_calls: u64,
    pub bounds: Vec<BoundFact>,
    pub proofs: Vec<ProofFact>,
    pub actor_lowerings: Vec<ActorLoweringFact>,
    pub image_nodes: Vec<ImageNodeFact>,
    pub image_edges: Vec<ImageEdgeFact>,
    pub work: Vec<WorkFact>,
    pub hardware: Vec<HardwareFact>,
    pub recovery: Vec<RecoveryFact>,
    pub startup_order: Vec<String>,
    pub shutdown_order: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisFactLimits {
    pub items: u64,
    pub proof_edges: u64,
    pub payload_bytes: u64,
}

pub struct AnalysisFactRequest<'a> {
    pub build: &'a BuildIdentity,
    pub image_name: &'a str,
    pub limits: AnalysisFactLimits,
}

impl AnalysisFactLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            items: 64_000_000,
            proof_edges: 256_000_000,
            payload_bytes: 1024 * 1024 * 1024,
        }
    }

    pub const fn validate(self) -> Result<(), ReportError> {
        if self.items == 0 || self.proof_edges == 0 || self.payload_bytes == 0 {
            Err(ReportError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnalysisFacts {
    build: BuildIdentity,
    image_name: String,
    facts: AnalysisFacts,
    limits: AnalysisFactLimits,
}

impl ValidatedAnalysisFacts {
    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn image_name(&self) -> &str {
        &self.image_name
    }

    #[must_use]
    pub fn as_facts(&self) -> &AnalysisFacts {
        &self.facts
    }

    #[must_use]
    pub const fn limits(&self) -> AnalysisFactLimits {
        self.limits
    }

    #[must_use]
    pub fn into_facts(self) -> AnalysisFacts {
        self.facts
    }
}

pub fn seal_analysis_facts(
    request: AnalysisFactRequest<'_>,
    mut facts: AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedAnalysisFacts, ReportError> {
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    request.limits.validate()?;
    if request.image_name.trim().is_empty() {
        return Err(ReportError::InvalidScalar);
    }
    canonicalize_analysis(&mut facts);
    validate_analysis(&facts)?;
    let (items, proof_edges, payload_bytes) = measure_analysis(&facts)?;
    if items > request.limits.items {
        return Err(ReportError::ResourceLimit {
            resource: "analysis fact items",
            limit: request.limits.items,
        });
    }
    if proof_edges > request.limits.proof_edges {
        return Err(ReportError::ResourceLimit {
            resource: "analysis proof edges",
            limit: request.limits.proof_edges,
        });
    }
    if payload_bytes > request.limits.payload_bytes {
        return Err(ReportError::ResourceLimit {
            resource: "analysis fact payload",
            limit: request.limits.payload_bytes,
        });
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(ValidatedAnalysisFacts {
        build: request.build.clone(),
        image_name: request.image_name.to_owned(),
        facts,
        limits: request.limits,
    })
}

/// One final emitted section measurement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SectionFact {
    pub name: String,
    pub owner: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolFact {
    pub name: String,
    pub section: String,
    pub offset: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationFacts {
    pub semantic_wir_version: u32,
    pub flow_wir_version: u32,
    pub flow_wir_wire_version: u32,
    pub machine_wir_version: u32,
    pub runtime_abi_version: u32,
    pub optimization_pipeline_name: String,
    pub optimization_pipeline_revision: u32,
    pub optimization_pipeline_implementation: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptimizationAction {
    Removed,
    Folded,
    Inlined,
    Coalesced,
    Reordered,
    Retained,
}

impl OptimizationAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Folded => "folded",
            Self::Inlined => "inlined",
            Self::Coalesced => "coalesced",
            Self::Reordered => "reordered",
            Self::Retained => "retained",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptimizationDecisionFact {
    pub pass: String,
    pub subject: String,
    pub action: OptimizationAction,
    pub justification: String,
    /// Sorted, unique FlowWir proof IDs.
    pub relied_on: Vec<u32>,
}

/// Backend facts available only after layout and linking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFacts {
    /// Digest of the exact canonical FlowWir frame independently validated by
    /// the backend. Together with `image_name`, this distinguishes artifacts
    /// emitted from the same source/build request.
    pub flow_wir_digest: Sha256Digest,
    pub artifact_bytes: u64,
    pub artifact_digest: Sha256Digest,
    pub sections: Vec<SectionFact>,
    pub symbols: Vec<SymbolFact>,
    pub representations: RepresentationFacts,
    pub required_runtime_intrinsics: Vec<String>,
    pub target_variable_reservations: Vec<BoundFact>,
    pub excluded_target_variables: Vec<String>,
    pub optimization_decisions: Vec<OptimizationDecisionFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendFactLimits {
    pub items: u64,
    pub optimization_proof_edges: u64,
    pub payload_bytes: u64,
}

impl BackendFactLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            items: 64_000_000,
            optimization_proof_edges: 256_000_000,
            payload_bytes: 1024 * 1024 * 1024,
        }
    }

    pub const fn validate(self) -> Result<(), ReportError> {
        if self.items == 0 || self.optimization_proof_edges == 0 || self.payload_bytes == 0 {
            Err(ReportError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Complete report bound to exactly the same inputs as WIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReport {
    schema: u32,
    build: BuildIdentity,
    image_name: String,
    analysis: AnalysisFacts,
    analysis_limits: AnalysisFactLimits,
    backend: BackendFacts,
    backend_limits: BackendFactLimits,
}

impl ImageReport {
    pub fn new(
        build: BuildIdentity,
        image_name: String,
        analysis: ValidatedAnalysisFacts,
        mut backend: BackendFacts,
        backend_limits: BackendFactLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        backend_limits.validate()?;
        if analysis.build() != &build || analysis.image_name() != image_name {
            return Err(ReportError::IdentityMismatch);
        }
        let analysis_limits = analysis.limits();
        let analysis = analysis.into_facts();
        canonicalize_backend(&mut backend);
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        validate_backend(&analysis, &backend)?;
        let (items, optimization_proof_edges, payload_bytes) = measure_backend(&backend)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if items > backend_limits.items {
            return Err(ReportError::ResourceLimit {
                resource: "backend fact items",
                limit: backend_limits.items,
            });
        }
        if optimization_proof_edges > backend_limits.optimization_proof_edges {
            return Err(ReportError::ResourceLimit {
                resource: "optimization proof edges",
                limit: backend_limits.optimization_proof_edges,
            });
        }
        if payload_bytes > backend_limits.payload_bytes {
            return Err(ReportError::ResourceLimit {
                resource: "backend fact payload",
                limit: backend_limits.payload_bytes,
            });
        }
        let report = Self {
            schema: REPORT_SCHEMA_VERSION,
            build,
            image_name,
            analysis,
            analysis_limits,
            backend,
            backend_limits,
        };
        report.validate_with_cancellation(is_cancelled)?;
        Ok(report)
    }

    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn image_name(&self) -> &str {
        &self.image_name
    }

    #[must_use]
    pub fn analysis(&self) -> &AnalysisFacts {
        &self.analysis
    }

    #[must_use]
    pub const fn analysis_limits(&self) -> AnalysisFactLimits {
        self.analysis_limits
    }

    #[must_use]
    pub fn backend(&self) -> &BackendFacts {
        &self.backend
    }

    #[must_use]
    pub const fn backend_limits(&self) -> BackendFactLimits {
        self.backend_limits
    }

    pub fn validate(&self) -> Result<(), ReportError> {
        self.validate_with_cancellation(&|| false)
    }

    pub fn validate_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if self.schema != REPORT_SCHEMA_VERSION {
            return Err(ReportError::UnsupportedSchema(self.schema));
        }
        if self.image_name.trim().is_empty() || self.backend.artifact_bytes == 0 {
            return Err(ReportError::InvalidScalar);
        }
        let versions = &self.backend.representations;
        if versions.semantic_wir_version == 0
            || versions.flow_wir_version == 0
            || versions.flow_wir_wire_version == 0
            || versions.machine_wir_version == 0
            || versions.runtime_abi_version == 0
            || versions.optimization_pipeline_name.trim().is_empty()
            || versions.optimization_pipeline_revision == 0
            || versions
                .optimization_pipeline_implementation
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ReportError::InvalidRepresentations);
        }
        require_sorted_unique(
            "runtime intrinsics",
            &self.backend.required_runtime_intrinsics,
        )?;
        require_sorted_unique(
            "excluded target variables",
            &self.backend.excluded_target_variables,
        )?;
        validate_analysis(&self.analysis)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        validate_backend(&self.analysis, &self.backend)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        Ok(())
    }

    /// Stable readable summary for the CLI.
    #[must_use]
    pub fn render_summary(&self) -> String {
        format!(
            "image ............................... {}\ntarget .............................. {}\nlanguage revision ................... {}\nreachable declarations .............. {}\nartifact bytes ...................... {}\nartifact sha256 ..................... {}\n",
            self.image_name,
            self.build.target,
            self.build.language.as_str(),
            self.analysis.reachable_declarations,
            self.backend.artifact_bytes,
            self.backend.artifact_digest.to_hex(),
        )
    }

    /// Canonical JSON with fixed field order and preserved fact order.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_json_with_cancellation(&|| false)
            .expect("an uncancelled canonical report encoding cannot be cancelled")
    }

    pub fn to_json_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<String, ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let mut output = String::new();
        output.push('{');
        json_number(&mut output, "schema", self.schema as u64, false);
        json_string(&mut output, "image_name", &self.image_name, true);
        json_string(&mut output, "language", self.build.language.as_str(), true);
        json_string(&mut output, "target", self.build.target.as_str(), true);
        json_string(
            &mut output,
            "compiler_sha256",
            &self.build.compiler.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "target_package_sha256",
            &self.build.target_package.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "standard_library_sha256",
            &self.build.standard_library.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "source_graph_sha256",
            &self.build.source_graph.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "request_sha256",
            &self.build.request.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "profile_sha256",
            &self.build.profile.to_hex(),
            true,
        );
        json_string(
            &mut output,
            "flow_wir_sha256",
            &self.backend.flow_wir_digest.to_hex(),
            true,
        );
        json_number(
            &mut output,
            "reachable_declarations",
            self.analysis.reachable_declarations,
            true,
        );
        json_number(
            &mut output,
            "monomorphized_instantiations",
            self.analysis.monomorphized_instantiations,
            true,
        );
        json_number(
            &mut output,
            "resolved_interface_calls",
            self.analysis.resolved_interface_calls,
            true,
        );
        json_number(
            &mut output,
            "artifact_bytes",
            self.backend.artifact_bytes,
            true,
        );
        json_string(
            &mut output,
            "artifact_sha256",
            &self.backend.artifact_digest.to_hex(),
            true,
        );
        output.push_str(",\"bounds\":[");
        for (index, fact) in self.analysis.bounds.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "category", &fact.category, false);
            json_string(&mut output, "owner", &fact.owner, true);
            json_string(&mut output, "source", &fact.source, true);
            json_number(&mut output, "amount", fact.amount, true);
            json_string(&mut output, "unit", &fact.unit, true);
            output.push('}');
        }
        output.push_str("],\"actor_lowerings\":[");
        for (index, fact) in self.analysis.actor_lowerings.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "source", &fact.source, false);
            json_string(&mut output, "destination", &fact.destination, true);
            json_string(&mut output, "message", &fact.message, true);
            json_string(&mut output, "kind", fact.kind.as_str(), true);
            json_number(&mut output, "logical_slots", fact.logical_slots, true);
            json_number(&mut output, "physical_bytes", fact.physical_bytes, true);
            output.push('}');
        }
        output.push_str("],\"image_nodes\":[");
        for (index, fact) in self.analysis.image_nodes.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "kind", &fact.kind, false);
            json_string(&mut output, "name", &fact.name, true);
            json_string(&mut output, "owner", &fact.owner, true);
            json_string(&mut output, "source", &fact.source, true);
            json_number(&mut output, "static_bytes", fact.static_bytes, true);
            output.push('}');
        }
        output.push_str("],\"image_edges\":[");
        for (index, fact) in self.analysis.image_edges.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "kind", &fact.kind, false);
            json_string(&mut output, "source", &fact.source, true);
            json_string(&mut output, "destination", &fact.destination, true);
            json_optional_number(&mut output, "capacity", fact.capacity, true);
            json_optional_number(&mut output, "priority", fact.priority.map(u64::from), true);
            output.push('}');
        }
        output.push_str("],\"work\":[");
        for (index, fact) in self.analysis.work.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "function", &fact.function, false);
            json_number(&mut output, "stack_bytes", fact.stack_bytes, true);
            json_number(&mut output, "frame_bytes", fact.frame_bytes, true);
            json_optional_number(
                &mut output,
                "uninterrupted_work",
                fact.uninterrupted_work,
                true,
            );
            json_number(&mut output, "checkpoint_count", fact.checkpoint_count, true);
            output.push('}');
        }
        output.push_str("],\"hardware\":[");
        for (index, fact) in self.analysis.hardware.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "device", &fact.device, false);
            json_string(&mut output, "binding", &fact.binding, true);
            json_string(&mut output, "owner", &fact.owner, true);
            json_string(&mut output, "dma_policy", &fact.dma_policy, true);
            json_optional_number(&mut output, "queue_capacity", fact.queue_capacity, true);
            json_optional_number(
                &mut output,
                "maximum_in_flight",
                fact.maximum_in_flight,
                true,
            );
            output.push('}');
        }
        output.push_str("],\"recovery\":[");
        for (index, fact) in self.analysis.recovery.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "subject", &fact.subject, false);
            json_string(&mut output, "supervisor", &fact.supervisor, true);
            json_number(&mut output, "reset_timeout_ns", fact.reset_timeout_ns, true);
            json_number(&mut output, "quarantine_bytes", fact.quarantine_bytes, true);
            output.push_str(",\"cleanup_path\":");
            json_string_array(&mut output, &fact.cleanup_path, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"startup_order\":");
        json_string_array(&mut output, &self.analysis.startup_order, is_cancelled)?;
        output.push_str(",\"shutdown_order\":");
        json_string_array(&mut output, &self.analysis.shutdown_order, is_cancelled)?;
        output.push_str(",\"proofs\":[");
        for (index, fact) in self.analysis.proofs.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_number(&mut output, "id", u64::from(fact.id), false);
            json_string(&mut output, "category", &fact.category, true);
            json_string(&mut output, "subject", &fact.subject, true);
            json_string(&mut output, "result", &fact.result, true);
            output.push_str(",\"why_chain\":");
            json_string_array(&mut output, &fact.why_chain, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"sections\":[");
        for (index, fact) in self.backend.sections.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "name", &fact.name, false);
            json_string(&mut output, "owner", &fact.owner, true);
            json_number(&mut output, "bytes", fact.bytes, true);
            output.push('}');
        }
        output.push_str("],\"symbols\":[");
        for (index, fact) in self.backend.symbols.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "name", &fact.name, false);
            json_string(&mut output, "section", &fact.section, true);
            json_number(&mut output, "offset", fact.offset, true);
            json_number(&mut output, "bytes", fact.bytes, true);
            output.push('}');
        }
        output.push_str("],\"representations\":{");
        json_number(
            &mut output,
            "semantic_wir_version",
            self.backend.representations.semantic_wir_version as u64,
            false,
        );
        json_number(
            &mut output,
            "flow_wir_version",
            self.backend.representations.flow_wir_version as u64,
            true,
        );
        json_number(
            &mut output,
            "flow_wir_wire_version",
            self.backend.representations.flow_wir_wire_version as u64,
            true,
        );
        json_number(
            &mut output,
            "machine_wir_version",
            self.backend.representations.machine_wir_version as u64,
            true,
        );
        json_number(
            &mut output,
            "runtime_abi_version",
            self.backend.representations.runtime_abi_version as u64,
            true,
        );
        json_string(
            &mut output,
            "optimization_pipeline_name",
            &self.backend.representations.optimization_pipeline_name,
            true,
        );
        json_number(
            &mut output,
            "optimization_pipeline_revision",
            u64::from(self.backend.representations.optimization_pipeline_revision),
            true,
        );
        json_string(
            &mut output,
            "optimization_pipeline_implementation_sha256",
            &self
                .backend
                .representations
                .optimization_pipeline_implementation
                .to_hex(),
            true,
        );
        output.push('}');
        output.push_str(",\"required_runtime_intrinsics\":");
        json_string_array(
            &mut output,
            &self.backend.required_runtime_intrinsics,
            is_cancelled,
        )?;
        output.push_str(",\"target_variable_reservations\":[");
        for (index, fact) in self.backend.target_variable_reservations.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "category", &fact.category, false);
            json_string(&mut output, "owner", &fact.owner, true);
            json_string(&mut output, "source", &fact.source, true);
            json_number(&mut output, "amount", fact.amount, true);
            json_string(&mut output, "unit", &fact.unit, true);
            output.push('}');
        }
        output.push_str("],\"excluded_target_variables\":");
        json_string_array(
            &mut output,
            &self.backend.excluded_target_variables,
            is_cancelled,
        )?;
        output.push_str(",\"optimization_decisions\":[");
        for (index, decision) in self.backend.optimization_decisions.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "pass", &decision.pass, false);
            json_string(&mut output, "subject", &decision.subject, true);
            json_string(&mut output, "action", decision.action.as_str(), true);
            json_string(&mut output, "justification", &decision.justification, true);
            output.push_str(",\"relied_on\":");
            json_u32_array(&mut output, &decision.relied_on, is_cancelled)?;
            output.push('}');
        }
        output.push(']');
        output.push('}');
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        Ok(output)
    }
}

fn canonicalize_analysis(analysis: &mut AnalysisFacts) {
    analysis.bounds.sort();
    analysis.proofs.sort();
    analysis.actor_lowerings.sort();
    analysis.image_nodes.sort();
    analysis.image_edges.sort();
    analysis.work.sort();
    analysis.hardware.sort();
    analysis.recovery.sort();
}

fn canonicalize_backend(backend: &mut BackendFacts) {
    backend.sections.sort();
    backend.symbols.sort();
    backend.required_runtime_intrinsics.sort();
    backend.target_variable_reservations.sort();
    backend.excluded_target_variables.sort();
    for decision in &mut backend.optimization_decisions {
        decision.relied_on.sort_unstable();
    }
    backend.optimization_decisions.sort();
}

fn measure_analysis(analysis: &AnalysisFacts) -> Result<(u64, u64, u64), ReportError> {
    let mut items = 0u64;
    let mut proof_edges = 0u64;
    let mut payload = 0u64;
    let mut add_items = |count: usize| -> Result<(), ReportError> {
        items = items
            .checked_add(u64::try_from(count).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        Ok(())
    };
    for count in [
        analysis.bounds.len(),
        analysis.proofs.len(),
        analysis.actor_lowerings.len(),
        analysis.image_nodes.len(),
        analysis.image_edges.len(),
        analysis.work.len(),
        analysis.hardware.len(),
        analysis.recovery.len(),
        analysis.startup_order.len(),
        analysis.shutdown_order.len(),
    ] {
        add_items(count)?;
    }
    let mut add = |value: &str| -> Result<(), ReportError> {
        payload = payload
            .checked_add(u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        Ok(())
    };
    for fact in &analysis.bounds {
        for value in [&fact.category, &fact.owner, &fact.source, &fact.unit] {
            add(value)?;
        }
    }
    for fact in &analysis.proofs {
        for value in [&fact.category, &fact.subject, &fact.result] {
            add(value)?;
        }
        proof_edges = proof_edges
            .checked_add(
                u64::try_from(fact.why_chain.len())
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .ok_or(ReportError::MeasurementOverflow)?;
        for value in &fact.why_chain {
            add(value)?;
        }
    }
    for fact in &analysis.actor_lowerings {
        for value in [&fact.source, &fact.destination, &fact.message] {
            add(value)?;
        }
    }
    for fact in &analysis.image_nodes {
        for value in [&fact.kind, &fact.name, &fact.owner, &fact.source] {
            add(value)?;
        }
    }
    for fact in &analysis.image_edges {
        for value in [&fact.kind, &fact.source, &fact.destination] {
            add(value)?;
        }
    }
    for fact in &analysis.work {
        add(&fact.function)?;
    }
    for fact in &analysis.hardware {
        for value in [&fact.device, &fact.binding, &fact.owner, &fact.dma_policy] {
            add(value)?;
        }
    }
    for fact in &analysis.recovery {
        add(&fact.subject)?;
        add(&fact.supervisor)?;
        proof_edges = proof_edges
            .checked_add(
                u64::try_from(fact.cleanup_path.len())
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .ok_or(ReportError::MeasurementOverflow)?;
        for value in &fact.cleanup_path {
            add(value)?;
        }
    }
    for value in analysis
        .startup_order
        .iter()
        .chain(&analysis.shutdown_order)
    {
        add(value)?;
    }
    Ok((items, proof_edges, payload))
}

fn measure_backend(backend: &BackendFacts) -> Result<(u64, u64, u64), ReportError> {
    let mut items = 0u64;
    for count in [
        backend.sections.len(),
        backend.symbols.len(),
        backend.required_runtime_intrinsics.len(),
        backend.target_variable_reservations.len(),
        backend.excluded_target_variables.len(),
        backend.optimization_decisions.len(),
    ] {
        items = items
            .checked_add(u64::try_from(count).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
    }
    let mut optimization_proof_edges = 0u64;
    let mut payload = 0u64;
    let mut add = |value: &str| -> Result<(), ReportError> {
        payload = payload
            .checked_add(u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        Ok(())
    };
    add(&backend.representations.optimization_pipeline_name)?;
    for fact in &backend.sections {
        add(&fact.name)?;
        add(&fact.owner)?;
    }
    for fact in &backend.symbols {
        add(&fact.name)?;
        add(&fact.section)?;
    }
    for value in &backend.required_runtime_intrinsics {
        add(value)?;
    }
    for fact in &backend.target_variable_reservations {
        for value in [&fact.category, &fact.owner, &fact.source, &fact.unit] {
            add(value)?;
        }
    }
    for value in &backend.excluded_target_variables {
        add(value)?;
    }
    for decision in &backend.optimization_decisions {
        add(&decision.pass)?;
        add(&decision.subject)?;
        add(&decision.justification)?;
        optimization_proof_edges = optimization_proof_edges
            .checked_add(
                u64::try_from(decision.relied_on.len())
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .ok_or(ReportError::MeasurementOverflow)?;
    }
    Ok((items, optimization_proof_edges, payload))
}

fn validate_analysis(analysis: &AnalysisFacts) -> Result<(), ReportError> {
    require_canonical("bounds", &analysis.bounds)?;
    require_canonical("proofs", &analysis.proofs)?;
    require_canonical("actor lowerings", &analysis.actor_lowerings)?;
    require_canonical("image nodes", &analysis.image_nodes)?;
    require_canonical("image edges", &analysis.image_edges)?;
    require_canonical("work facts", &analysis.work)?;
    require_canonical("hardware facts", &analysis.hardware)?;
    require_canonical("recovery facts", &analysis.recovery)?;
    require_nonempty_unique("startup order", &analysis.startup_order)?;
    require_nonempty_unique("shutdown order", &analysis.shutdown_order)?;
    if !analysis
        .work
        .windows(2)
        .all(|pair| pair[0].function < pair[1].function)
        || !analysis
            .hardware
            .windows(2)
            .all(|pair| pair[0].device < pair[1].device)
        || !analysis
            .recovery
            .windows(2)
            .all(|pair| pair[0].subject < pair[1].subject)
    {
        return Err(ReportError::NonCanonical("named analysis facts"));
    }
    if analysis.bounds.iter().any(invalid_bound)
        || analysis.proofs.iter().enumerate().any(|(index, proof)| {
            proof.id as usize != index
                || empty(&proof.category)
                || empty(&proof.subject)
                || empty(&proof.result)
                || proof.why_chain.is_empty()
                || proof.why_chain.iter().any(|item| empty(item))
        })
        || analysis
            .actor_lowerings
            .iter()
            .any(|fact| empty(&fact.source) || empty(&fact.destination) || empty(&fact.message))
        || analysis.image_nodes.iter().any(|fact| {
            empty(&fact.kind) || empty(&fact.name) || empty(&fact.owner) || empty(&fact.source)
        })
        || analysis
            .image_edges
            .iter()
            .any(|fact| empty(&fact.kind) || empty(&fact.source) || empty(&fact.destination))
        || analysis.work.iter().any(|fact| empty(&fact.function))
        || analysis.hardware.iter().any(|fact| {
            empty(&fact.device)
                || empty(&fact.binding)
                || empty(&fact.owner)
                || empty(&fact.dma_policy)
        })
        || analysis.recovery.iter().any(|fact| {
            empty(&fact.subject)
                || empty(&fact.supervisor)
                || fact.cleanup_path.is_empty()
                || fact.cleanup_path.iter().any(|item| empty(item))
        })
    {
        return Err(ReportError::InvalidFact);
    }
    Ok(())
}

fn validate_backend(analysis: &AnalysisFacts, backend: &BackendFacts) -> Result<(), ReportError> {
    require_canonical("sections", &backend.sections)?;
    require_canonical("symbols", &backend.symbols)?;
    require_canonical(
        "target variable reservations",
        &backend.target_variable_reservations,
    )?;
    require_canonical("optimization decisions", &backend.optimization_decisions)?;
    if !backend
        .sections
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
        || !backend
            .symbols
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        || !backend
            .optimization_decisions
            .windows(2)
            .all(|pair| (&pair[0].pass, &pair[0].subject) < (&pair[1].pass, &pair[1].subject))
    {
        return Err(ReportError::NonCanonical("named backend facts"));
    }
    if backend
        .target_variable_reservations
        .iter()
        .any(invalid_bound)
    {
        return Err(ReportError::InvalidFact);
    }
    let section_extents: std::collections::BTreeMap<_, _> = backend
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.bytes))
        .collect();
    if backend
        .sections
        .iter()
        .any(|section| empty(&section.name) || empty(&section.owner))
        || backend.symbols.iter().any(|symbol| {
            empty(&symbol.name)
                || empty(&symbol.section)
                || section_extents
                    .get(symbol.section.as_str())
                    .is_none_or(|section_bytes| {
                        symbol
                            .offset
                            .checked_add(symbol.bytes)
                            .is_none_or(|end| end > *section_bytes)
                    })
        })
    {
        return Err(ReportError::InvalidMeasurement);
    }
    if backend.optimization_decisions.iter().any(|decision| {
        empty(&decision.pass)
            || empty(&decision.subject)
            || empty(&decision.justification)
            || decision.relied_on.windows(2).any(|pair| pair[0] >= pair[1])
            || decision
                .relied_on
                .iter()
                .any(|proof| *proof as usize >= analysis.proofs.len())
    }) {
        return Err(ReportError::InvalidOptimizationDecision);
    }
    Ok(())
}

fn invalid_bound(fact: &BoundFact) -> bool {
    empty(&fact.category) || empty(&fact.owner) || empty(&fact.source) || empty(&fact.unit)
}

fn empty(value: &str) -> bool {
    value.trim().is_empty()
}

fn require_canonical<T: Ord>(kind: &'static str, values: &[T]) -> Result<(), ReportError> {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ReportError::NonCanonical(kind));
    }
    Ok(())
}

fn require_nonempty_unique(kind: &'static str, values: &[String]) -> Result<(), ReportError> {
    if values.iter().any(|value| empty(value)) {
        return Err(ReportError::InvalidFact);
    }
    let mut seen = std::collections::BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.as_str())) {
        return Err(ReportError::NonCanonical(kind));
    }
    Ok(())
}

fn require_sorted_unique(kind: &'static str, values: &[String]) -> Result<(), ReportError> {
    if values.iter().any(|value| value.trim().is_empty())
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(ReportError::NonCanonical(kind));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    MeasurementOverflow,
    IdentityMismatch,
    UnsupportedSchema(u32),
    InvalidScalar,
    InvalidRepresentations,
    InvalidMeasurement,
    InvalidFact,
    InvalidOptimizationDecision,
    NonCanonical(&'static str),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("image report construction was cancelled"),
            Self::InvalidLimits => formatter.write_str("image report limits must be nonzero"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} exceeded limit {limit}")
            }
            Self::MeasurementOverflow => {
                formatter.write_str("image report measurement arithmetic overflowed")
            }
            Self::IdentityMismatch => {
                formatter.write_str("image report facts describe a different build or image")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported image report schema {schema}")
            }
            Self::InvalidScalar => {
                formatter.write_str("image report has an invalid name or artifact size")
            }
            Self::InvalidRepresentations => {
                formatter.write_str("image report representation versions are incomplete")
            }
            Self::InvalidMeasurement => formatter
                .write_str("image report contains an invalid section or symbol measurement"),
            Self::InvalidFact => {
                formatter.write_str("image report contains an incomplete or invalid fact")
            }
            Self::InvalidOptimizationDecision => {
                formatter.write_str("image report contains an invalid optimization decision")
            }
            Self::NonCanonical(kind) => {
                write!(formatter, "image report {kind} are not canonical")
            }
        }
    }
}

impl std::error::Error for ReportError {}

fn json_string_array(
    output: &mut String,
    values: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if index != 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
    output.push(']');
    Ok(())
}

fn json_u32_array(
    output: &mut String,
    values: &[u32],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if index != 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    Ok(())
}

fn json_string(output: &mut String, name: &str, value: &str, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    push_json_string(output, value);
}

fn json_number(output: &mut String, name: &str, value: u64, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    output.push_str(&value.to_string());
}

fn json_optional_number(output: &mut String, name: &str, value: Option<u64>, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    match value {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};

    use super::{
        AnalysisFactLimits, AnalysisFactRequest, AnalysisFacts, BackendFactLimits, BackendFacts,
        ImageReport, OptimizationAction, OptimizationDecisionFact, ProofFact, ReportError,
        SectionFact, SymbolFact, ValidatedAnalysisFacts, seal_analysis_facts,
    };

    fn build(digest: Sha256Digest) -> BuildIdentity {
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

    fn backend(digest: Sha256Digest) -> BackendFacts {
        BackendFacts {
            flow_wir_digest: digest,
            artifact_bytes: 42,
            artifact_digest: digest,
            sections: Vec::new(),
            symbols: Vec::new(),
            representations: super::RepresentationFacts {
                semantic_wir_version: 1,
                flow_wir_version: 1,
                flow_wir_wire_version: 1,
                machine_wir_version: 1,
                runtime_abi_version: 1,
                optimization_pipeline_name: "fixture".to_owned(),
                optimization_pipeline_revision: 1,
                optimization_pipeline_implementation: digest,
            },
            required_runtime_intrinsics: Vec::new(),
            target_variable_reservations: Vec::new(),
            excluded_target_variables: Vec::new(),
            optimization_decisions: Vec::new(),
        }
    }

    fn sealed_analysis(
        digest: Sha256Digest,
        image_name: &str,
        facts: AnalysisFacts,
    ) -> ValidatedAnalysisFacts {
        let build = build(digest);
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &build,
                image_name,
                limits: AnalysisFactLimits::standard(),
            },
            facts,
            &|| false,
        )
        .expect("valid analysis facts")
    }

    #[test]
    fn report_json_is_deterministic_and_escaped() {
        let digest = Sha256Digest::from_bytes([1; 32]);
        let report = ImageReport::new(
            build(digest),
            "a\"b".to_owned(),
            sealed_analysis(digest, "a\"b", AnalysisFacts::default()),
            backend(digest),
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("valid report");
        let json = report.to_json();
        assert!(json.contains("\"image_name\":\"a\\\"b\""));
        assert_eq!(json, report.to_json());
        serde_json::from_str::<serde_json::Value>(&json).expect("valid JSON");
    }

    #[test]
    fn constructor_canonicalizes_fact_sets_and_proof_links() {
        let digest = Sha256Digest::from_bytes([2; 32]);
        let mut analysis = AnalysisFacts {
            proofs: vec![
                ProofFact {
                    id: 1,
                    category: "ownership".to_owned(),
                    subject: "z".to_owned(),
                    result: "proved".to_owned(),
                    why_chain: vec!["z".to_owned()],
                },
                ProofFact {
                    id: 0,
                    category: "capacity".to_owned(),
                    subject: "a".to_owned(),
                    result: "proved".to_owned(),
                    why_chain: vec!["a".to_owned()],
                },
            ],
            ..AnalysisFacts::default()
        };
        analysis.startup_order = vec!["device".to_owned(), "actor".to_owned()];
        let mut backend = backend(digest);
        backend.sections = vec![
            SectionFact {
                name: ".text.z".to_owned(),
                owner: "image".to_owned(),
                bytes: 16,
            },
            SectionFact {
                name: ".text.a".to_owned(),
                owner: "image".to_owned(),
                bytes: 8,
            },
        ];
        backend.symbols = vec![SymbolFact {
            name: "entry".to_owned(),
            section: ".text.a".to_owned(),
            offset: 0,
            bytes: 8,
        }];
        backend.optimization_decisions = vec![OptimizationDecisionFact {
            pass: "cleanup".to_owned(),
            subject: "call".to_owned(),
            action: OptimizationAction::Retained,
            justification: "observable".to_owned(),
            relied_on: vec![1, 0],
        }];

        let report = ImageReport::new(
            build(digest),
            "image".to_owned(),
            sealed_analysis(digest, "image", analysis),
            backend,
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("canonical report");
        assert_eq!(
            report
                .analysis()
                .proofs
                .iter()
                .map(|proof| proof.id)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(report.backend().sections[0].name, ".text.a");
        assert_eq!(report.backend().optimization_decisions[0].relied_on, [0, 1]);
    }

    #[test]
    fn symbol_measurements_cannot_escape_their_section() {
        let digest = Sha256Digest::from_bytes([3; 32]);
        let mut backend = backend(digest);
        backend.sections.push(SectionFact {
            name: ".text".to_owned(),
            owner: "image".to_owned(),
            bytes: 4,
        });
        backend.symbols.push(SymbolFact {
            name: "entry".to_owned(),
            section: ".text".to_owned(),
            offset: 4,
            bytes: 1,
        });
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend,
                BackendFactLimits::standard(),
                &|| false,
            ),
            Err(ReportError::InvalidMeasurement)
        ));
    }

    #[test]
    fn analysis_and_backend_candidates_are_bounded_before_publication() {
        let digest = Sha256Digest::from_bytes([4; 32]);
        let analysis_build = build(digest);
        let analysis_error = seal_analysis_facts(
            AnalysisFactRequest {
                build: &analysis_build,
                image_name: "image",
                limits: AnalysisFactLimits {
                    items: 1,
                    proof_edges: 1,
                    payload_bytes: 4,
                },
            },
            AnalysisFacts {
                startup_order: vec!["actor".to_owned()],
                ..AnalysisFacts::default()
            },
            &|| false,
        );
        assert!(matches!(
            analysis_error,
            Err(ReportError::ResourceLimit {
                resource: "analysis fact payload",
                limit: 4
            })
        ));

        let mut backend = backend(digest);
        backend.required_runtime_intrinsics = vec!["runtime.poll".to_owned()];
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend,
                BackendFactLimits {
                    items: 1,
                    optimization_proof_edges: 1,
                    payload_bytes: 4,
                },
                &|| false,
            ),
            Err(ReportError::ResourceLimit {
                resource: "backend fact payload",
                limit: 4
            })
        ));
    }

    #[test]
    fn analysis_facts_cannot_cross_build_or_image_boundaries() {
        let digest = Sha256Digest::from_bytes([5; 32]);
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "other-image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend(digest),
                BackendFactLimits::standard(),
                &|| false,
            ),
            Err(ReportError::IdentityMismatch)
        ));
    }
}
