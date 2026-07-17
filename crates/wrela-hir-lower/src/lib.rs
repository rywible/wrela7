//! Import/name resolution, generic-kind classification, desugaring, and HIR
//! construction from a complete set of parsed files.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use wrela_build_model::Sha256Digest;
use wrela_diagnostics::{Diagnostic, WithDiagnostics};
use wrela_hir::{
    Builtin, DeclarationId, GenericParameterId, LocalId, ManifestDeclarationError, Name,
    ParameterId, Program, RegionId, ResolvedDeclaration, ResolvedVariant, ValidatedProgram,
};
use wrela_package::{ImageDeclaration, ModuleId, PackageGraph, PackageId};
use wrela_source::{FileId, SourceDatabase, Span};
use wrela_syntax::ParsedFile;

mod lower;

pub use lower::CanonicalHirLowerer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweringLimits {
    pub modules: u32,
    pub declarations: u32,
    pub generic_parameters: u32,
    pub parameters: u32,
    pub bodies: u32,
    pub locals: u32,
    pub statements: u32,
    pub expressions: u32,
    pub patterns: u32,
    pub regions: u32,
    pub scopes: u32,
    pub import_scc_size: u32,
    pub generic_classification_depth: u32,
    pub resolved_uses: u64,
    pub model_edges: u64,
    pub payload_bytes: u64,
    pub diagnostics: u32,
    pub diagnostic_bytes: u64,
}

impl LoweringLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            modules: 1_000_000,
            declarations: 4_000_000,
            generic_parameters: 4_000_000,
            parameters: 16_000_000,
            bodies: 4_000_000,
            locals: 16_000_000,
            statements: 64_000_000,
            expressions: 64_000_000,
            patterns: 16_000_000,
            regions: 16_000_000,
            scopes: 16_000_000,
            import_scc_size: 1_000_000,
            generic_classification_depth: 1024,
            resolved_uses: 256_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            diagnostics: 100_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), LowerFailure> {
        if self.modules == 0
            || self.declarations == 0
            || self.generic_parameters == 0
            || self.parameters == 0
            || self.bodies == 0
            || self.locals == 0
            || self.statements == 0
            || self.expressions == 0
            || self.patterns == 0
            || self.regions == 0
            || self.scopes == 0
            || self.import_scc_size == 0
            || self.generic_classification_depth == 0
            || self.generic_classification_depth > 1024
            || self.resolved_uses == 0
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.diagnostics == 0
            || self.diagnostic_bytes == 0
        {
            Err(LowerFailure::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Incremental identity only. Internal dependency/query structures do not
/// cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    pub previous_source_graph: Option<Sha256Digest>,
    pub changed_files: Vec<FileId>,
}

/// Version of the sealed HIR-product reuse contract. This is intentionally
/// independent of source and HIR syntax versions: it versions the comparison,
/// dependency-impact, and publication rules used by [`PreviousHirProduct`].
pub const HIR_CHANGE_SET_REUSE_VERSION: u32 = 2;

/// Finite work policy for comparing a current HIR product with a sealed prior
/// product. Reuse comparison is independently bounded because it is additional
/// work over ordinary cold lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HirReuseLimits {
    pub comparisons: u64,
}

impl HirReuseLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            comparisons: 256_000_000,
        }
    }

    fn validate(self) -> Result<(), LowerFailure> {
        if self.comparisons == 0 {
            Err(LowerFailure::InvalidReuseLimits)
        } else {
            Ok(())
        }
    }
}

/// Explicit sealed prior product. A digest in [`ChangeSet`] never grants reuse
/// by itself: the producer must provide the corresponding successfully sealed
/// HIR output under the exact supported contract version.
#[derive(Debug, Clone, Copy)]
pub struct PreviousHirProduct<'a> {
    pub contract_version: u32,
    pub output: &'a LowerOutput,
}

/// Evidence produced by tracked cold or incremental lowering. File and
/// declaration identities are canonical and sorted; a cold run reports empty
/// reuse sets and zero comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HirReuseReport {
    pub reused_modules: Vec<ModuleId>,
    pub reused_declarations: Vec<DeclarationId>,
    pub recomputed_files: Vec<FileId>,
    /// Declarations whose substantive generic/parameter-header and kind/body
    /// lowering producer executed. The global package/module/declaration
    /// identity census still runs for every request so stable identities and
    /// namespace conflicts are validated before any reuse decision.
    pub producer_declarations_executed: u64,
    pub comparisons: u64,
}

impl HirReuseReport {
    #[must_use]
    pub const fn cold(producer_declarations_executed: u64) -> Self {
        Self {
            reused_modules: Vec::new(),
            reused_declarations: Vec::new(),
            recomputed_files: Vec::new(),
            producer_declarations_executed,
            comparisons: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LowerRequest<'a> {
    /// Exact immutable graph produced by workspace loading. Lowering clones
    /// only this `Arc`, never the image-sized graph.
    pub packages: Arc<PackageGraph>,
    pub source_graph_digest: Sha256Digest,
    /// Exactly one parsed file for every module source, sorted by FileId.
    pub parsed_files: &'a [ParsedFile],
    pub sources: &'a SourceDatabase,
    pub changes: &'a ChangeSet,
    pub limits: LoweringLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingKind {
    Local,
    Parameter,
    Declaration,
    Variant,
    Module,
    GenericType,
    GenericConstant,
    GenericRegion,
    LocalRegion,
    Builtin,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedBinding {
    Local(LocalId),
    Parameter(ParameterId),
    Declaration(ResolvedDeclaration),
    Variant(ResolvedVariant),
    Module {
        package: PackageId,
        module: ModuleId,
    },
    Generic(GenericParameterId),
    LocalRegion(RegionId),
    Builtin(Builtin),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReferenceSpelling {
    Identifier(Name),
    SelfValue,
}

impl ReferenceSpelling {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Identifier(name) => name.as_str(),
            Self::SelfValue => "self",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUse {
    pub source: Span,
    pub spelling: ReferenceSpelling,
    pub kind: BindingKind,
    /// Absent exactly for an unresolved recovery use.
    pub target: Option<ResolvedBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleResolutionSummary {
    pub module: ModuleId,
    pub declarations: Vec<DeclarationId>,
    pub imports: u32,
    pub resolved_uses: u64,
    pub error_uses: u64,
    pub reused_from_previous_revision: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoweredProgram {
    program: Arc<ValidatedProgram>,
    /// Sorted source-facing resolution index used by diagnostics and lints.
    uses: Vec<ResolvedUse>,
    modules: Vec<ModuleResolutionSummary>,
    source_graph_digest: Sha256Digest,
    source_revisions: Vec<SourceRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRevision {
    pub file: FileId,
    pub path: String,
    pub digest: Sha256Digest,
}

impl LoweredProgram {
    #[must_use]
    pub fn program(&self) -> &ValidatedProgram {
        &self.program
    }

    /// Shared sealed HIR retained by both incremental lowering and semantic
    /// analysis. Persistent sessions clone this `Arc`, never the project-sized
    /// validated program.
    #[must_use]
    pub fn shared_program(&self) -> &Arc<ValidatedProgram> {
        &self.program
    }

    #[must_use]
    pub fn source_revisions(&self) -> &[SourceRevision] {
        &self.source_revisions
    }

    #[must_use]
    pub fn uses(&self) -> &[ResolvedUse] {
        &self.uses
    }

    #[must_use]
    pub fn modules(&self) -> &[ModuleResolutionSummary] {
        &self.modules
    }

    #[must_use]
    pub fn source_graph_digest(&self) -> Sha256Digest {
        self.source_graph_digest
    }

    /// Convert the root manifest's exact image declaration into the HIR ID
    /// consumed by semantic analysis.
    pub fn image_entry(
        &self,
        image: &ImageDeclaration,
    ) -> Result<ResolvedDeclaration, ManifestDeclarationError> {
        self.program.manifest_declaration(
            self.program.as_program().packages.root(),
            &image.module,
            &image.entry,
        )
    }

    /// Consume the lowering product when the pipeline advances to semantic
    /// analysis. This transfers the project-sized validated HIR instead of
    /// requiring consumers to clone it through [`Self::program`]. Resolution
    /// indexes and module summaries are deliberately dropped at this boundary;
    /// callers that still need them must keep using the borrowed accessors.
    #[must_use]
    pub fn into_program(self) -> ValidatedProgram {
        Arc::try_unwrap(self.program).unwrap_or_else(|program| (*program).clone())
    }

    /// Consume the HIR product while preserving shared ownership for a
    /// semantic or incremental consumer.
    #[must_use]
    pub fn into_shared_program(self) -> Arc<ValidatedProgram> {
        self.program
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoweredProgramCandidate {
    pub program: Program,
    pub uses: Vec<ResolvedUse>,
    pub modules: Vec<ModuleResolutionSummary>,
    pub source_graph_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LowerOutput {
    lowered: LoweredProgram,
    diagnostics: Vec<Diagnostic>,
}

impl LowerOutput {
    #[must_use]
    pub fn lowered(&self) -> &LoweredProgram {
        &self.lowered
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn into_parts(self) -> (LoweredProgram, Vec<Diagnostic>) {
        (self.lowered, self.diagnostics)
    }
}

/// One ordinary lowering output paired with independently checkable reuse
/// evidence. The output itself remains byte/structurally identical to a cold
/// recomputation; execution history is deliberately kept out of sealed HIR.
#[derive(Debug, Clone, PartialEq)]
pub struct TrackedLowerOutput {
    output: LowerOutput,
    reuse: HirReuseReport,
}

impl TrackedLowerOutput {
    #[must_use]
    pub fn output(&self) -> &LowerOutput {
        &self.output
    }

    #[must_use]
    pub fn reuse(&self) -> &HirReuseReport {
        &self.reuse
    }

    #[must_use]
    pub fn into_parts(self) -> (LowerOutput, HirReuseReport) {
        (self.output, self.reuse)
    }
}

pub trait HirLowerer {
    fn lower(
        &self,
        request: LowerRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerFailure>;
}

/// Validate and atomically seal HIR, resolution indexes, summaries, and
/// diagnostics against the exact parsed source graph supplied to lowering.
pub fn seal_lower_output(
    request: &LowerRequest<'_>,
    candidate: LoweredProgramCandidate,
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LowerOutput, LowerFailure> {
    if is_cancelled() {
        return Err(LowerFailure::Cancelled);
    }
    request.limits.validate()?;
    validate_lower_inputs(request, is_cancelled)?;
    if candidate.source_graph_digest != request.source_graph_digest
        || !Arc::ptr_eq(&candidate.program.packages, &request.packages)
    {
        return Err(LowerFailure::SourceGraphMismatch);
    }
    validate_arena_counts(&candidate.program, request.limits)?;
    if candidate.uses.len() as u64 > request.limits.resolved_uses {
        return Err(LowerFailure::ResourceLimit {
            resource: "resolved uses",
            limit: request.limits.resolved_uses,
        });
    }
    validate_model_resources(
        &candidate.program,
        &candidate.uses,
        &candidate.modules,
        request.limits,
        is_cancelled,
    )?;
    let program = candidate
        .program
        .validate()
        .map_err(|error| LowerFailure::InvalidProgram(error.to_string()))?;
    validate_uses(request, &program, &candidate.uses, is_cancelled)?;
    validate_module_summaries(
        request,
        &program,
        &candidate.uses,
        &candidate.modules,
        is_cancelled,
    )?;
    let diagnostics = validate_diagnostics(request, diagnostics, is_cancelled)?;
    if is_cancelled() {
        return Err(LowerFailure::Cancelled);
    }
    let source_revisions = source_revisions(request, is_cancelled)?;
    Ok(LowerOutput {
        lowered: LoweredProgram {
            program: Arc::new(program),
            uses: candidate.uses,
            modules: candidate.modules,
            source_graph_digest: candidate.source_graph_digest,
            source_revisions,
        },
        diagnostics,
    })
}

fn source_revisions(
    request: &LowerRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<SourceRevision>, LowerFailure> {
    let mut revisions = Vec::new();
    revisions
        .try_reserve_exact(request.sources.len())
        .map_err(|_| LowerFailure::ResourceLimit {
            resource: "source revision records",
            limit: u64::from(request.limits.modules),
        })?;
    for index in 0..request.sources.len() {
        poll_cancellation(is_cancelled)?;
        let file = FileId(
            u32::try_from(index).map_err(|_| LowerFailure::ResourceLimit {
                resource: "source revision records",
                limit: u64::from(request.limits.modules),
            })?,
        );
        let source = request
            .sources
            .get(file)
            .ok_or(LowerFailure::MissingParsedFile(file))?;
        let mut path = String::new();
        path.try_reserve_exact(source.path().len())
            .map_err(|_| LowerFailure::ResourceLimit {
                resource: "source revision path bytes",
                limit: request.limits.payload_bytes,
            })?;
        path.push_str(source.path());
        revisions.push(SourceRevision {
            file,
            path,
            digest: source.digest(),
        });
    }
    Ok(revisions)
}

fn validate_arena_counts(
    model: &wrela_hir::Program,
    limits: LoweringLimits,
) -> Result<(), LowerFailure> {
    let counts = [
        ("modules", model.modules.len(), limits.modules),
        (
            "declarations",
            model.declarations.len(),
            limits.declarations,
        ),
        (
            "generic parameters",
            model.generic_parameters.len(),
            limits.generic_parameters,
        ),
        ("parameters", model.parameters.len(), limits.parameters),
        ("bodies", model.bodies.len(), limits.bodies),
        ("scopes", model.scopes.len(), limits.scopes),
        ("locals", model.locals.len(), limits.locals),
        ("statements", model.statements.len(), limits.statements),
        ("expressions", model.expressions.len(), limits.expressions),
        ("patterns", model.patterns.len(), limits.patterns),
        ("regions", model.regions.len(), limits.regions),
    ];
    if let Some((resource, _, limit)) = counts
        .into_iter()
        .find(|(_, actual, limit)| *actual > *limit as usize)
    {
        return Err(LowerFailure::ResourceLimit {
            resource,
            limit: u64::from(limit),
        });
    }
    Ok(())
}

fn poll_cancellation(is_cancelled: &dyn Fn() -> bool) -> Result<(), LowerFailure> {
    if is_cancelled() {
        Err(LowerFailure::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct ModelResourceMeter {
    edges: u64,
    payload_bytes: u64,
    maximum_depth: u32,
    overflowed: bool,
}

impl ModelResourceMeter {
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
        let Ok(count) = u64::try_from(value.len()) else {
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.payload_bytes.checked_add(count) {
            self.payload_bytes = total;
        } else {
            self.overflowed = true;
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        let Ok(count) = u64::try_from(value.len()) else {
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.payload_bytes.checked_add(count) {
            self.payload_bytes = total;
        } else {
            self.overflowed = true;
        }
    }
}

fn push_model_work<T>(work: &mut Vec<T>, value: T, limit: u64) -> Result<(), LowerFailure> {
    let current = u64::try_from(work.len()).map_err(|_| LowerFailure::ResourceLimit {
        resource: "HIR model traversal worklist",
        limit,
    })?;
    if current >= limit {
        return Err(LowerFailure::ResourceLimit {
            resource: "HIR model traversal worklist",
            limit,
        });
    }
    work.try_reserve(1)
        .map_err(|_| LowerFailure::ResourceLimit {
            resource: "HIR model traversal worklist",
            limit,
        })?;
    work.push(value);
    Ok(())
}

fn measure_attributes(
    attributes: &[wrela_hir::Attribute],
    meter: &mut ModelResourceMeter,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    for attribute in attributes {
        poll_cancellation(is_cancelled)?;
        meter.edges(&attribute.arguments);
        for argument in &attribute.arguments {
            poll_cancellation(is_cancelled)?;
            if let Some(name) = &argument.name {
                meter.text(name.as_str());
            }
        }
    }
    Ok(())
}

fn validate_model_resources(
    model: &wrela_hir::Program,
    uses: &[ResolvedUse],
    modules: &[ModuleResolutionSummary],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    use wrela_hir::{
        DeclarationKind, ExpressionKind, GenericArgumentKind, GenericParameterKind,
        InterpolationPart, PrimaryPattern, ProjectionCarrier, ProjectionCarrierKind, StatementKind,
        TypeExpression, TypeExpressionKind,
    };

    let mut meter = ModelResourceMeter::default();
    for count in [
        model.modules.len(),
        model.declarations.len(),
        model.generic_parameters.len(),
        model.parameters.len(),
        model.bodies.len(),
        model.scopes.len(),
        model.locals.len(),
        model.statements.len(),
        model.expressions.len(),
        model.patterns.len(),
        model.regions.len(),
        model.image_candidates.len(),
        model.test_candidates.len(),
        uses.len(),
        modules.len(),
    ] {
        meter.add_edges(count);
    }
    let mut types: Vec<(&TypeExpression, u32)> = Vec::new();
    let mut carriers: Vec<(&ProjectionCarrier, u32)> = Vec::new();

    for module in &model.modules {
        poll_cancellation(is_cancelled)?;
        meter.edges(&module.declarations);
        meter.edges(&module.reexports);
        for reexport in &module.reexports {
            poll_cancellation(is_cancelled)?;
            meter.text(reexport.local_name.as_str());
        }
    }
    for declaration in &model.declarations {
        poll_cancellation(is_cancelled)?;
        if let Some(name) = &declaration.name {
            meter.text(name.as_str());
        }
        meter.edges(&declaration.attributes);
        measure_attributes(&declaration.attributes, &mut meter, is_cancelled)?;
        match &declaration.kind {
            DeclarationKind::Constant(value) => {
                if let Some(ty) = &value.ty {
                    push_model_work(&mut types, (ty, 1), limits.model_edges)?;
                }
            }
            DeclarationKind::Function(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.parameters);
                if let Some(result) = &value.result {
                    push_model_work(&mut types, (result, 1), limits.model_edges)?;
                }
            }
            DeclarationKind::Initializer(value) => {
                meter.edges(&value.parameters);
                if let Some(result) = &value.result {
                    push_model_work(&mut types, (result, 1), limits.model_edges)?;
                }
            }
            DeclarationKind::Structure(value) | DeclarationKind::Class(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.implements);
                meter.edges(&value.fields);
                meter.edges(&value.members);
                for ty in &value.implements {
                    push_model_work(&mut types, (ty, 1), limits.model_edges)?;
                }
                for field in &value.fields {
                    poll_cancellation(is_cancelled)?;
                    meter.text(field.name.as_str());
                    meter.edges(&field.attributes);
                    measure_attributes(&field.attributes, &mut meter, is_cancelled)?;
                    push_model_work(&mut types, (&field.ty, 1), limits.model_edges)?;
                }
            }
            DeclarationKind::Enumeration(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.variants);
                meter.edges(&value.members);
                for variant in &value.variants {
                    poll_cancellation(is_cancelled)?;
                    meter.text(variant.name.as_str());
                    meter.edges(&variant.fields);
                    for field in &variant.fields {
                        poll_cancellation(is_cancelled)?;
                        if let Some(name) = &field.name {
                            meter.text(name.as_str());
                        }
                        push_model_work(&mut types, (&field.ty, 1), limits.model_edges)?;
                    }
                }
            }
            DeclarationKind::Interface(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.requirements);
            }
            DeclarationKind::Implementation(value) => {
                meter.edges(&value.members);
                push_model_work(&mut types, (&value.interface, 1), limits.model_edges)?;
                push_model_work(
                    &mut types,
                    (&value.implementing_type, 1),
                    limits.model_edges,
                )?;
            }
            DeclarationKind::Projection(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.parameters);
                meter.edges(&value.provenance);
                push_model_work(&mut carriers, (&value.carrier, 1), limits.model_edges)?;
            }
            DeclarationKind::Scope(value) => {
                meter.edges(&value.parameters);
                push_model_work(&mut types, (&value.result, 1), limits.model_edges)?;
            }
            DeclarationKind::ComptimeSelection(value) => {
                meter.edges(&value.then_declarations);
                meter.edges(&value.else_declarations);
            }
            DeclarationKind::Brand | DeclarationKind::Error => {}
        }
    }
    for parameter in &model.generic_parameters {
        poll_cancellation(is_cancelled)?;
        meter.text(parameter.name.as_str());
        match &parameter.kind {
            GenericParameterKind::Type { bound: Some(ty) } => {
                push_model_work(&mut types, (ty, 1), limits.model_edges)?;
            }
            GenericParameterKind::Constant { ty } => {
                push_model_work(&mut types, (ty, 1), limits.model_edges)?;
            }
            GenericParameterKind::Type { bound: None } | GenericParameterKind::Region => {}
        }
    }
    for parameter in &model.parameters {
        poll_cancellation(is_cancelled)?;
        if let Some(name) = &parameter.name {
            meter.text(name.as_str());
        }
        if let Some(ty) = &parameter.ty {
            push_model_work(&mut types, (ty, 1), limits.model_edges)?;
        }
    }
    for body in &model.bodies {
        poll_cancellation(is_cancelled)?;
        meter.edges(&body.locals);
        meter.edges(&body.statements);
    }
    for local in &model.locals {
        poll_cancellation(is_cancelled)?;
        meter.text(local.name.as_str());
        if let Some(ty) = &local.ty {
            push_model_work(&mut types, (ty, 1), limits.model_edges)?;
        }
    }
    for region in &model.regions {
        poll_cancellation(is_cancelled)?;
        meter.text(region.name.as_str());
    }
    for statement in &model.statements {
        poll_cancellation(is_cancelled)?;
        meter.edges(&statement.attributes);
        measure_attributes(&statement.attributes, &mut meter, is_cancelled)?;
        match &statement.kind {
            StatementKind::Assign { targets, .. } => {
                meter.edges(targets);
                for target in targets {
                    poll_cancellation(is_cancelled)?;
                    meter.edges(&target.projections);
                    for projection in &target.projections {
                        if let wrela_hir::PlaceProjection::Field(name) = projection {
                            meter.text(name.as_str());
                        }
                    }
                }
            }
            StatementKind::Assert {
                message: Some(message),
                ..
            } => meter.text(message),
            StatementKind::If { branches, .. } => meter.edges(branches),
            StatementKind::Match { arms, .. } => meter.edges(arms),
            StatementKind::Initialize { .. }
            | StatementKind::Return(_)
            | StatementKind::Break
            | StatementKind::Continue
            | StatementKind::Pass
            | StatementKind::Assert { message: None, .. }
            | StatementKind::Send(_)
            | StatementKind::Yield(_)
            | StatementKind::Expression(_)
            | StatementKind::For { .. }
            | StatementKind::While { .. }
            | StatementKind::Loop { .. }
            | StatementKind::With { .. }
            | StatementKind::ComptimeIf { .. }
            | StatementKind::Error => {}
        }
    }
    for expression in &model.expressions {
        poll_cancellation(is_cancelled)?;
        match &expression.kind {
            ExpressionKind::Literal(value) => measure_literal(value, &mut meter),
            ExpressionKind::Closure {
                parameters,
                captures,
                ..
            } => {
                meter.edges(parameters);
                meter.edges(captures);
            }
            ExpressionKind::Cast { ty, .. } => {
                push_model_work(&mut types, (ty, 1), limits.model_edges)?;
            }
            ExpressionKind::Field { name, .. } => meter.text(name.as_str()),
            ExpressionKind::Call { arguments, .. } => {
                meter.edges(arguments);
                for argument in arguments {
                    if let Some(name) = &argument.name {
                        meter.text(name.as_str());
                    }
                    if let wrela_hir::CallArgumentValue::Exclusive { place, .. } = &argument.value {
                        meter.edges(&place.projections);
                        for projection in &place.projections {
                            if let wrela_hir::PlaceProjection::Field(name) = projection {
                                meter.text(name.as_str());
                            }
                        }
                    }
                }
            }
            ExpressionKind::Tuple(values)
            | ExpressionKind::Array(values)
            | ExpressionKind::Race(values) => meter.edges(values),
            ExpressionKind::Interpolate(parts) => {
                meter.edges(parts);
                for part in parts {
                    poll_cancellation(is_cancelled)?;
                    match part {
                        InterpolationPart::Text { value, .. } => meter.text(value),
                        InterpolationPart::Value { format, .. } => {
                            if let Some(value) = format {
                                meter.text(value);
                            }
                        }
                    }
                }
            }
            ExpressionKind::Reference(_)
            | ExpressionKind::Unary { .. }
            | ExpressionKind::Binary { .. }
            | ExpressionKind::Compare { .. }
            | ExpressionKind::IsPattern { .. }
            | ExpressionKind::Range { .. }
            | ExpressionKind::Try(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::TrySend(_)
            | ExpressionKind::Error => {}
        }
    }
    for pattern in &model.patterns {
        poll_cancellation(is_cancelled)?;
        meter.edges(&pattern.alternatives);
        for alternative in &pattern.alternatives {
            poll_cancellation(is_cancelled)?;
            match &alternative.kind {
                PrimaryPattern::Literal { literal, .. } => measure_literal(literal, &mut meter),
                PrimaryPattern::Constructor {
                    spelling,
                    candidates,
                    arguments,
                } => {
                    meter.text(spelling.as_str());
                    meter.edges(candidates);
                    meter.edges(arguments);
                }
                PrimaryPattern::ContextualName {
                    spelling,
                    candidates,
                    ..
                } => {
                    meter.text(spelling.as_str());
                    meter.edges(candidates);
                }
                PrimaryPattern::Tuple(arguments) | PrimaryPattern::Array(arguments) => {
                    meter.edges(arguments);
                }
                PrimaryPattern::Wildcard | PrimaryPattern::Bind(_) | PrimaryPattern::Error => {}
            }
        }
    }
    for value in uses {
        poll_cancellation(is_cancelled)?;
        meter.text(value.spelling.as_str());
    }
    for module in modules {
        poll_cancellation(is_cancelled)?;
        meter.edges(&module.declarations);
    }
    while let Some((ty, depth)) = types.pop() {
        poll_cancellation(is_cancelled)?;
        meter.add_edges(1);
        meter.maximum_depth = meter.maximum_depth.max(depth);
        let Some(next) = depth.checked_add(1) else {
            meter.overflowed = true;
            continue;
        };
        match &ty.kind {
            TypeExpressionKind::Named { arguments, .. } => {
                meter.edges(arguments);
                for argument in arguments {
                    poll_cancellation(is_cancelled)?;
                    if let GenericArgumentKind::Type(ty) = &argument.kind {
                        push_model_work(&mut types, (ty, next), limits.model_edges)?;
                    }
                }
            }
            TypeExpressionKind::Array { element, .. }
            | TypeExpressionKind::View {
                target: element, ..
            } => push_model_work(&mut types, (element, next), limits.model_edges)?,
            TypeExpressionKind::Tuple(values) => {
                meter.edges(values);
                for ty in values {
                    poll_cancellation(is_cancelled)?;
                    push_model_work(&mut types, (ty, next), limits.model_edges)?;
                }
            }
            TypeExpressionKind::Iso { brand, payload } => {
                push_model_work(&mut types, (brand, next), limits.model_edges)?;
                push_model_work(&mut types, (payload, next), limits.model_edges)?;
            }
            TypeExpressionKind::Function {
                parameters, result, ..
            } => {
                meter.edges(parameters);
                for parameter in parameters {
                    poll_cancellation(is_cancelled)?;
                    push_model_work(&mut types, (&parameter.ty, next), limits.model_edges)?;
                }
                push_model_work(&mut types, (result, next), limits.model_edges)?;
            }
            TypeExpressionKind::SelfType { .. } | TypeExpressionKind::Error => {}
        }
    }
    while let Some((carrier, depth)) = carriers.pop() {
        poll_cancellation(is_cancelled)?;
        meter.add_edges(1);
        meter.maximum_depth = meter.maximum_depth.max(depth);
        let Some(next) = depth.checked_add(1) else {
            meter.overflowed = true;
            continue;
        };
        match &carrier.kind {
            ProjectionCarrierKind::View { ty, .. } => {
                push_model_work(&mut types, (ty, next), limits.model_edges)?;
            }
            ProjectionCarrierKind::Tuple(values) => {
                meter.edges(values);
                for value in values {
                    poll_cancellation(is_cancelled)?;
                    push_model_work(&mut carriers, (value, next), limits.model_edges)?;
                }
            }
            ProjectionCarrierKind::Option(value) => {
                push_model_work(&mut carriers, (value, next), limits.model_edges)?;
            }
            ProjectionCarrierKind::Result { carrier, error } => {
                push_model_work(&mut carriers, (carrier, next), limits.model_edges)?;
                push_model_work(&mut types, (error, next), limits.model_edges)?;
            }
            ProjectionCarrierKind::Error => {}
        }
    }
    // Projection carriers can introduce additional type-expression roots.
    while let Some((ty, depth)) = types.pop() {
        poll_cancellation(is_cancelled)?;
        meter.add_edges(1);
        meter.maximum_depth = meter.maximum_depth.max(depth);
        let Some(next) = depth.checked_add(1) else {
            meter.overflowed = true;
            continue;
        };
        match &ty.kind {
            TypeExpressionKind::Named { arguments, .. } => {
                meter.edges(arguments);
                for argument in arguments {
                    poll_cancellation(is_cancelled)?;
                    if let GenericArgumentKind::Type(ty) = &argument.kind {
                        push_model_work(&mut types, (ty, next), limits.model_edges)?;
                    }
                }
            }
            TypeExpressionKind::Array { element, .. }
            | TypeExpressionKind::View {
                target: element, ..
            } => push_model_work(&mut types, (element, next), limits.model_edges)?,
            TypeExpressionKind::Tuple(values) => {
                meter.edges(values);
                for ty in values {
                    poll_cancellation(is_cancelled)?;
                    push_model_work(&mut types, (ty, next), limits.model_edges)?;
                }
            }
            TypeExpressionKind::Iso { brand, payload } => {
                push_model_work(&mut types, (brand, next), limits.model_edges)?;
                push_model_work(&mut types, (payload, next), limits.model_edges)?;
            }
            TypeExpressionKind::Function {
                parameters, result, ..
            } => {
                meter.edges(parameters);
                for parameter in parameters {
                    poll_cancellation(is_cancelled)?;
                    push_model_work(&mut types, (&parameter.ty, next), limits.model_edges)?;
                }
                push_model_work(&mut types, (result, next), limits.model_edges)?;
            }
            TypeExpressionKind::SelfType { .. } | TypeExpressionKind::Error => {}
        }
    }
    if meter.overflowed
        || meter.edges > limits.model_edges
        || meter.payload_bytes > limits.payload_bytes
        || meter.maximum_depth > limits.generic_classification_depth
    {
        return Err(LowerFailure::ResourceLimit {
            resource: "HIR model edges, payload bytes, or nested type depth",
            limit: limits.payload_bytes,
        });
    }
    Ok(())
}

fn measure_literal(value: &wrela_hir::Literal, meter: &mut ModelResourceMeter) {
    match value {
        wrela_hir::Literal::Integer(value)
        | wrela_hir::Literal::Float(value)
        | wrela_hir::Literal::String(value) => meter.text(value),
        wrela_hir::Literal::Bytes(value) => meter.bytes(value),
        wrela_hir::Literal::Character(_)
        | wrela_hir::Literal::Boolean(_)
        | wrela_hir::Literal::Unit => {}
    }
}

fn validate_lower_inputs(
    request: &LowerRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    poll_cancellation(is_cancelled)?;
    if request.sources.len() > request.limits.modules as usize
        || request.parsed_files.len() > request.limits.modules as usize
        || request.packages.modules().len() > request.limits.modules as usize
    {
        return Err(LowerFailure::ResourceLimit {
            resource: "input modules",
            limit: u64::from(request.limits.modules),
        });
    }
    if request.parsed_files.len() != request.sources.len()
        || request.packages.modules().len() != request.sources.len()
    {
        return Err(LowerFailure::SourceGraphMismatch);
    }
    let mut graph_sources = Vec::new();
    graph_sources
        .try_reserve_exact(request.sources.len())
        .map_err(|_| LowerFailure::ResourceLimit {
            resource: "input module index allocation",
            limit: u64::from(request.limits.modules),
        })?;
    graph_sources.resize(request.sources.len(), false);
    for module in request.packages.modules() {
        poll_cancellation(is_cancelled)?;
        let Some(slot) = graph_sources.get_mut(module.source.0 as usize) else {
            return Err(LowerFailure::ParsedFileOutsideGraph(module.source));
        };
        if *slot {
            return Err(LowerFailure::DuplicateParsedFile(module.source));
        }
        *slot = true;
    }
    for present in &graph_sources {
        poll_cancellation(is_cancelled)?;
        if !present {
            return Err(LowerFailure::SourceGraphMismatch);
        }
    }
    graph_sources.fill(false);
    for parsed in request.parsed_files {
        poll_cancellation(is_cancelled)?;
        let Some(slot) = graph_sources.get_mut(parsed.file().0 as usize) else {
            return Err(LowerFailure::ParsedFileOutsideGraph(parsed.file()));
        };
        if *slot {
            return Err(LowerFailure::DuplicateParsedFile(parsed.file()));
        }
        *slot = true;
    }
    for (index, parsed) in request.parsed_files.iter().enumerate() {
        poll_cancellation(is_cancelled)?;
        let file = FileId(
            u32::try_from(index).map_err(|_| LowerFailure::ResourceLimit {
                resource: "parsed files",
                limit: u64::from(request.limits.modules),
            })?,
        );
        let source = request
            .sources
            .get(file)
            .ok_or(LowerFailure::MissingParsedFile(file))?;
        if parsed.file() != file {
            return Err(LowerFailure::MissingParsedFile(file));
        }
        if parsed.source_digest() != source.digest() {
            return Err(LowerFailure::StaleParsedFile(file));
        }
        if !parsed.recovery_complete() {
            return Err(LowerFailure::IncompleteParsedFile(file));
        }
    }
    let mut previous = None;
    for file in &request.changes.changed_files {
        poll_cancellation(is_cancelled)?;
        if previous.is_some_and(|previous| previous >= *file)
            || request.sources.get(*file).is_none()
        {
            return Err(LowerFailure::InvalidChangeSet);
        }
        previous = Some(*file);
    }
    if request.changes.previous_source_graph == Some(request.source_graph_digest)
        && !request.changes.changed_files.is_empty()
    {
        return Err(LowerFailure::InvalidChangeSet);
    }
    Ok(())
}

fn validate_uses(
    request: &LowerRequest<'_>,
    program: &ValidatedProgram,
    uses: &[ResolvedUse],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    for pair in uses.windows(2) {
        poll_cancellation(is_cancelled)?;
        if use_key(&pair[0]) >= use_key(&pair[1]) {
            return Err(LowerFailure::InvalidOutput(
                "resolved-use index is not strictly canonical".to_owned(),
            ));
        }
    }
    for resolved_use in uses {
        poll_cancellation(is_cancelled)?;
        if request.sources.span_text(resolved_use.source) != Some(resolved_use.spelling.as_str())
            || !binding_matches(resolved_use, program)
        {
            return Err(LowerFailure::InvalidOutput(
                "resolved use has an invalid name, span, kind, or target".to_owned(),
            ));
        }
    }
    Ok(())
}

fn binding_matches(resolved_use: &ResolvedUse, program: &ValidatedProgram) -> bool {
    use wrela_hir::GenericParameterKind;

    if matches!(&resolved_use.spelling, ReferenceSpelling::SelfValue)
        && resolved_use.kind != BindingKind::Parameter
    {
        return false;
    }
    match (&resolved_use.kind, &resolved_use.target) {
        (BindingKind::Error, None) => true,
        (BindingKind::Local, Some(ResolvedBinding::Local(id))) => {
            program.as_program().local(*id).is_some()
        }
        (BindingKind::Parameter, Some(ResolvedBinding::Parameter(id))) => program
            .as_program()
            .parameter(*id)
            .is_some_and(|parameter| {
                parameter.receiver == matches!(&resolved_use.spelling, ReferenceSpelling::SelfValue)
            }),
        (BindingKind::Declaration, Some(ResolvedBinding::Declaration(target))) => {
            program.resolved_declaration(target).is_some()
        }
        (BindingKind::Variant, Some(ResolvedBinding::Variant(target))) => {
            program.resolved_variant(target).is_some()
        }
        (BindingKind::Module, Some(ResolvedBinding::Module { package, module })) => program
            .as_program()
            .modules
            .get(module.0 as usize)
            .is_some_and(|record| record.package == *package),
        (BindingKind::GenericType, Some(ResolvedBinding::Generic(id))) => program
            .as_program()
            .generic_parameter(*id)
            .is_some_and(|parameter| matches!(parameter.kind, GenericParameterKind::Type { .. })),
        (BindingKind::GenericConstant, Some(ResolvedBinding::Generic(id))) => program
            .as_program()
            .generic_parameter(*id)
            .is_some_and(|parameter| {
                matches!(parameter.kind, GenericParameterKind::Constant { .. })
            }),
        (BindingKind::GenericRegion, Some(ResolvedBinding::Generic(id))) => program
            .as_program()
            .generic_parameter(*id)
            .is_some_and(|parameter| matches!(parameter.kind, GenericParameterKind::Region)),
        (BindingKind::LocalRegion, Some(ResolvedBinding::LocalRegion(id))) => {
            program.as_program().region(*id).is_some()
        }
        (BindingKind::Builtin, Some(ResolvedBinding::Builtin(_))) => true,
        _ => false,
    }
}

fn use_key(value: &ResolvedUse) -> (u32, u32, u32, &str, u8) {
    (
        value.source.file.0,
        value.source.range.start,
        value.source.range.end,
        value.spelling.as_str(),
        match value.kind {
            BindingKind::Local => 0,
            BindingKind::Parameter => 1,
            BindingKind::Declaration => 2,
            BindingKind::Variant => 3,
            BindingKind::Module => 4,
            BindingKind::GenericType => 5,
            BindingKind::GenericConstant => 6,
            BindingKind::GenericRegion => 7,
            BindingKind::LocalRegion => 8,
            BindingKind::Builtin => 9,
            BindingKind::Error => 10,
        },
    )
}

fn validate_module_summaries(
    request: &LowerRequest<'_>,
    program: &ValidatedProgram,
    uses: &[ResolvedUse],
    summaries: &[ModuleResolutionSummary],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    let model = program.as_program();
    if summaries.len() != model.modules.len() {
        return Err(LowerFailure::InvalidOutput(
            "module summary coverage differs from HIR modules".to_owned(),
        ));
    }
    let mut use_counts = Vec::new();
    use_counts
        .try_reserve_exact(request.sources.len())
        .map_err(|_| LowerFailure::ResourceLimit {
            resource: "module use-count allocation",
            limit: u64::from(request.limits.modules),
        })?;
    use_counts.resize(request.sources.len(), (0u64, 0u64));
    for resolved_use in uses {
        poll_cancellation(is_cancelled)?;
        let counts = use_counts
            .get_mut(resolved_use.source.file.0 as usize)
            .ok_or_else(|| {
                LowerFailure::InvalidOutput("resolved use is outside the source graph".to_owned())
            })?;
        if resolved_use.kind == BindingKind::Error {
            counts.1 = counts.1.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                resource: "module error uses",
                limit: request.limits.resolved_uses,
            })?;
        } else {
            counts.0 = counts.0.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                resource: "module resolved uses",
                limit: request.limits.resolved_uses,
            })?;
        }
    }
    for (index, summary) in summaries.iter().enumerate() {
        poll_cancellation(is_cancelled)?;
        let module = &model.modules[index];
        let graph_module = &request.packages.modules()[index];
        let parsed = request
            .parsed_files
            .get(graph_module.source.0 as usize)
            .ok_or(LowerFailure::MissingParsedFile(graph_module.source))?;
        let (resolved, errors) = use_counts
            .get(graph_module.source.0 as usize)
            .copied()
            .ok_or(LowerFailure::MissingParsedFile(graph_module.source))?;
        let reuse_permitted = request.changes.previous_source_graph.is_some()
            && !request.changes.changed_files.contains(&graph_module.source);
        if summary.module != module.id
            || summary.declarations != module.declarations
            || summary.imports as usize != parsed.ast().imports.len()
            || summary.resolved_uses != resolved
            || summary.error_uses != errors
            || (summary.reused_from_previous_revision && !reuse_permitted)
        {
            return Err(LowerFailure::InvalidOutput(
                "module summary disagrees with HIR, parsed input, or resolution index".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_diagnostics(
    request: &LowerRequest<'_>,
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Diagnostic>, LowerFailure> {
    if diagnostics.len() > request.limits.diagnostics as usize {
        return Err(LowerFailure::ResourceLimit {
            resource: "diagnostics",
            limit: u64::from(request.limits.diagnostics),
        });
    }
    let mut bytes = 0u64;
    for diagnostic in &diagnostics {
        poll_cancellation(is_cancelled)?;
        if diagnostic.message.trim().is_empty()
            || request.sources.span_text(diagnostic.primary).is_none()
            || diagnostic.labels.iter().any(|label| {
                label.message.trim().is_empty() || request.sources.span_text(label.span).is_none()
            })
            || diagnostic.related.iter().any(|related| {
                related.message.trim().is_empty()
                    || request.sources.span_text(related.span).is_none()
            })
            || diagnostic.repairs.iter().any(|repair| {
                repair.message.trim().is_empty()
                    || repair.edits.is_empty()
                    || !repair.edits.windows(2).all(|pair| {
                        (pair[0].span.file, pair[0].span.range.start)
                            < (pair[1].span.file, pair[1].span.range.start)
                            && (pair[0].span.file != pair[1].span.file
                                || pair[0].span.range.end <= pair[1].span.range.start)
                    })
                    || repair
                        .edits
                        .iter()
                        .any(|edit| request.sources.span_text(edit.span).is_none())
            })
        {
            return Err(LowerFailure::InvalidOutput(
                "lowering diagnostic is malformed or outside the source graph".to_owned(),
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
            poll_cancellation(is_cancelled)?;
            bytes = bytes
                .checked_add(u64::try_from(value.len()).map_err(|_| {
                    LowerFailure::ResourceLimit {
                        resource: "diagnostic bytes",
                        limit: request.limits.diagnostic_bytes,
                    }
                })?)
                .ok_or(LowerFailure::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: request.limits.diagnostic_bytes,
                })?;
        }
    }
    if bytes > request.limits.diagnostic_bytes {
        return Err(LowerFailure::ResourceLimit {
            resource: "diagnostic bytes",
            limit: request.limits.diagnostic_bytes,
        });
    }
    let mut output = WithDiagnostics {
        value: (),
        diagnostics,
    };
    output.sort_diagnostics();
    Ok(output.diagnostics)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerFailure {
    Cancelled,
    InvalidLimits,
    InvalidReuseLimits,
    UnsupportedReuseVersion { observed: u32 },
    UnsupportedReuseShape(&'static str),
    SourceGraphMismatch,
    MissingParsedFile(FileId),
    DuplicateParsedFile(FileId),
    StaleParsedFile(FileId),
    IncompleteParsedFile(FileId),
    ParsedFileOutsideGraph(FileId),
    InvalidChangeSet,
    InvalidProgram(String),
    InvalidOutput(String),
    ResourceLimit { resource: &'static str, limit: u64 },
    InternalInvariant(String),
}

impl fmt::Display for LowerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("HIR lowering was cancelled"),
            Self::InvalidLimits => formatter.write_str("HIR lowering limits must be nonzero"),
            Self::InvalidReuseLimits => {
                formatter.write_str("HIR reuse comparison limits must be nonzero")
            }
            Self::UnsupportedReuseVersion { observed } => write!(
                formatter,
                "HIR reuse contract version {observed} is unsupported"
            ),
            Self::UnsupportedReuseShape(reason) => {
                write!(formatter, "HIR reuse shape is unsupported: {reason}")
            }
            Self::SourceGraphMismatch => {
                formatter.write_str("HIR input source graph digest is inconsistent")
            }
            Self::MissingParsedFile(file) => {
                write!(formatter, "module source {} was not parsed", file.0)
            }
            Self::DuplicateParsedFile(file) => {
                write!(formatter, "source {} was parsed more than once", file.0)
            }
            Self::StaleParsedFile(file) => write!(
                formatter,
                "parsed source {} does not match current source bytes",
                file.0
            ),
            Self::IncompleteParsedFile(file) => write!(
                formatter,
                "parsing source {} stopped before lossless recovery completed",
                file.0
            ),
            Self::ParsedFileOutsideGraph(file) => write!(
                formatter,
                "parsed source {} is outside the package graph",
                file.0
            ),
            Self::InvalidChangeSet => formatter.write_str("HIR incremental change set is invalid"),
            Self::InvalidProgram(message) => {
                write!(formatter, "lowered HIR program is invalid: {message}")
            }
            Self::InvalidOutput(message) => {
                write!(formatter, "HIR lowering output is inconsistent: {message}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "HIR lowering exceeded {resource} limit {limit}")
            }
            Self::InternalInvariant(message) => {
                write!(formatter, "HIR lowering invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for LowerFailure {}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use wrela_build_model::Sha256Digest;
    use wrela_hir::{Declaration, DeclarationKind, DeclarationOwner, Module, Program, Visibility};
    use wrela_package::{
        DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName,
        PackageVersion,
    };
    use wrela_source::{SourceInput, TextRange};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};

    struct Fixture {
        sources: SourceDatabase,
        parsed_files: Vec<ParsedFile>,
        packages: Arc<PackageGraph>,
        candidate: LoweredProgramCandidate,
        changes: ChangeSet,
        source_graph_digest: Sha256Digest,
        declaration_name: Span,
    }

    struct SourceFixture {
        sources: SourceDatabase,
        parsed_files: Vec<ParsedFile>,
        packages: Arc<PackageGraph>,
        changes: ChangeSet,
        source_graph_digest: Sha256Digest,
    }

    impl SourceFixture {
        fn request(&self, limits: LoweringLimits) -> LowerRequest<'_> {
            LowerRequest {
                packages: Arc::clone(&self.packages),
                source_graph_digest: self.source_graph_digest,
                parsed_files: &self.parsed_files,
                sources: &self.sources,
                changes: &self.changes,
                limits,
            }
        }
    }

    impl Fixture {
        fn request(&self, limits: LoweringLimits) -> LowerRequest<'_> {
            LowerRequest {
                packages: Arc::clone(&self.packages),
                source_graph_digest: self.source_graph_digest,
                parsed_files: &self.parsed_files,
                sources: &self.sources,
                changes: &self.changes,
                limits,
            }
        }
    }

    fn fixture() -> Fixture {
        let source_digest = Sha256Digest::from_bytes([3; 32]);
        let mut sources = SourceDatabase::default();
        let file = sources
            .add(SourceInput {
                path: "boot.wr".to_owned(),
                text: "module boot\nbrand start\n".to_owned(),
                digest: source_digest,
            })
            .expect("source");
        let parsed = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("parse")
            .into_parts()
            .0;
        let source = parsed.ast().meta.span;
        let declaration = parsed.ast().declarations.first().expect("declaration");
        let wrela_syntax::DeclarationKind::Brand(brand) = &declaration.kind else {
            panic!("expected brand")
        };
        let declaration_source = declaration.meta.span;
        let declaration_name = brand.name.meta.span;

        let path = ModulePath::new(["boot".to_owned()]).expect("module path");
        let identity = PackageIdentity {
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1").expect("package version"),
            source_digest: Sha256Digest::from_bytes([1; 32]),
        };
        let mut graph = PackageGraphBuilder::new(identity);
        graph
            .add_module(graph.root(), path.clone(), file)
            .expect("module");
        let packages = Arc::new(graph.finish().expect("graph"));
        let source_graph_digest = Sha256Digest::from_bytes([9; 32]);
        let candidate = LoweredProgramCandidate {
            program: Program {
                packages: Arc::clone(&packages),
                modules: vec![Module {
                    id: ModuleId(0),
                    package: PackageId(0),
                    path,
                    declarations: vec![DeclarationId(0)],
                    reexports: Vec::new(),
                    source,
                }],
                declarations: vec![Declaration {
                    id: DeclarationId(0),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(Name::new("start".to_owned()).expect("name")),
                    visibility: Visibility::Private,
                    attributes: Vec::new(),
                    kind: DeclarationKind::Brand,
                    source: declaration_source,
                }],
                generic_parameters: Vec::new(),
                parameters: Vec::new(),
                bodies: Vec::new(),
                scopes: Vec::new(),
                locals: Vec::new(),
                statements: Vec::new(),
                expressions: Vec::new(),
                patterns: Vec::new(),
                regions: Vec::new(),
                image_candidates: Vec::new(),
                test_candidates: Vec::new(),
            },
            uses: Vec::new(),
            modules: vec![ModuleResolutionSummary {
                module: ModuleId(0),
                declarations: vec![DeclarationId(0)],
                imports: 0,
                resolved_uses: 0,
                error_uses: 0,
                reused_from_previous_revision: false,
            }],
            source_graph_digest,
        };
        Fixture {
            sources,
            parsed_files: vec![parsed],
            packages,
            candidate,
            changes: ChangeSet {
                previous_source_graph: None,
                changed_files: Vec::new(),
            },
            source_graph_digest,
            declaration_name,
        }
    }

    fn source_fixture(path: &str, module: &[&str], text: &str) -> SourceFixture {
        let mut sources = SourceDatabase::default();
        let file = sources
            .add(SourceInput {
                path: path.to_owned(),
                text: text.to_owned(),
                digest: Sha256Digest::from_bytes([0x31; 32]),
            })
            .expect("source");
        let (parsed, parse_diagnostics) = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("parse")
            .into_parts();
        assert!(
            parse_diagnostics.is_empty(),
            "fixture must parse cleanly: {parse_diagnostics:?}"
        );
        let identity = PackageIdentity {
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1").expect("package version"),
            source_digest: Sha256Digest::from_bytes([0x32; 32]),
        };
        let mut graph = PackageGraphBuilder::new(identity);
        graph
            .add_module(
                graph.root(),
                ModulePath::new(module.iter().map(|segment| (*segment).to_owned()))
                    .expect("module path"),
                file,
            )
            .expect("module");
        SourceFixture {
            sources,
            parsed_files: vec![parsed],
            packages: Arc::new(graph.finish().expect("graph")),
            changes: ChangeSet {
                previous_source_graph: None,
                changed_files: Vec::new(),
            },
            source_graph_digest: Sha256Digest::from_bytes([0x33; 32]),
        }
    }

    fn package_import_fixture() -> SourceFixture {
        let modules = [
            (
                "aaa/main.wr",
                &["aaa", "main"][..],
                concat!(
                    "module aaa.main\n",
                    "import api.bridge as bridge\n",
                    "import api.leaf\n",
                    "from api.bridge import leaf as imported_leaf, Thing as ImportedThing, ready\n",
                    "import external.dep.types as dep_types\n",
                    "from external.dep.types import Token\n",
                    "const TOKEN: Token = dep_types.make()\n",
                    "const READY = ready\n",
                    "const DIRECT = api.leaf.Thing\n",
                    "fn through_bridge(value: bridge.leaf.Thing) -> imported_leaf.Thing:\n",
                    "    return value\n",
                    "fn through_name(value: ImportedThing) -> ImportedThing:\n",
                    "    return value\n",
                ),
                false,
            ),
            (
                "api/bridge.wr",
                &["api", "bridge"][..],
                concat!(
                    "module api.bridge\n",
                    "pub import api.leaf as leaf\n",
                    "pub from api.leaf import Thing, ready\n",
                ),
                false,
            ),
            (
                "api/leaf.wr",
                &["api", "leaf"][..],
                concat!(
                    "module api.leaf\n",
                    "pub brand Thing\n",
                    "pub enum State:\n",
                    "    ready\n",
                ),
                false,
            ),
            (
                "cycle/a.wr",
                &["cycle", "a"][..],
                concat!(
                    "module cycle.a\n",
                    "import cycle.b as b_module\n",
                    "pub fn a() -> u64:\n",
                    "    return b_module.b()\n",
                ),
                false,
            ),
            (
                "cycle/b.wr",
                &["cycle", "b"][..],
                concat!(
                    "module cycle.b\n",
                    "import cycle.a as a_module\n",
                    "pub fn b() -> u64:\n",
                    "    return 1\n",
                ),
                false,
            ),
            (
                "dep/types.wr",
                &["dep", "types"][..],
                concat!(
                    "module dep.types\n",
                    "pub brand Token\n",
                    "pub fn make() -> Token:\n",
                    "    pass\n",
                ),
                true,
            ),
        ];
        let mut sources = SourceDatabase::default();
        let mut parsed_files = Vec::new();
        let mut files = Vec::new();
        for (index, (path, _, text, dependency)) in modules.iter().enumerate() {
            let file = sources
                .add(SourceInput {
                    path: (*path).to_owned(),
                    text: (*text).to_owned(),
                    digest: Sha256Digest::from_bytes([0x40 + index as u8; 32]),
                })
                .expect("source");
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("parse")
                .into_parts();
            assert!(diagnostics.is_empty(), "fixture parse: {diagnostics:?}");
            parsed_files.push(parsed);
            files.push((file, *dependency));
        }
        let identity = |name: &str, digest| PackageIdentity {
            name: PackageName::new(name).expect("package name"),
            version: PackageVersion::new("1").expect("package version"),
            source_digest: digest,
        };
        let mut graph =
            PackageGraphBuilder::new(identity("root", Sha256Digest::from_bytes([0x50; 32])));
        let dependency = graph
            .add_package(identity("dependency", Sha256Digest::from_bytes([0x51; 32])))
            .expect("dependency package");
        graph
            .add_dependency(
                graph.root(),
                DependencyAlias::new("external").expect("dependency alias"),
                dependency,
            )
            .expect("dependency edge");
        for ((_, path, _, _), (file, is_dependency)) in modules.iter().zip(files) {
            let package = if is_dependency {
                dependency
            } else {
                graph.root()
            };
            graph
                .add_module(
                    package,
                    ModulePath::new(path.iter().map(|segment| (*segment).to_owned()))
                        .expect("module path"),
                    file,
                )
                .expect("module");
        }
        SourceFixture {
            sources,
            parsed_files,
            packages: Arc::new(graph.finish().expect("package graph")),
            changes: ChangeSet {
                previous_source_graph: None,
                changed_files: Vec::new(),
            },
            source_graph_digest: Sha256Digest::from_bytes([0x52; 32]),
        }
    }

    #[test]
    fn hir_policy_rejects_zero_capacity() {
        LoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = LoweringLimits::standard();
        limits.modules = 0;
        assert!(matches!(
            limits.validate(),
            Err(LowerFailure::InvalidLimits)
        ));
    }

    #[test]
    fn seals_against_the_exact_parsed_source_and_shared_graph() {
        let fixture = fixture();
        let output = seal_lower_output(
            &fixture.request(LoweringLimits::standard()),
            fixture.candidate.clone(),
            Vec::new(),
            &|| false,
        )
        .expect("sealed HIR");
        assert_eq!(
            output.lowered().program().as_program().declarations.len(),
            1
        );
    }

    #[test]
    fn canonical_lowerer_produces_sealed_hir_from_real_syntax() {
        let fixture = fixture();
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("canonical syntax-to-HIR lowering");
        let declaration = &output.lowered().program().as_program().declarations[0];
        assert_eq!(declaration.name.as_ref().map(Name::as_str), Some("start"));
        assert!(matches!(declaration.kind, DeclarationKind::Brand));
        assert!(output.diagnostics().is_empty());
    }

    #[test]
    fn canonical_lowerer_covers_normative_declaration_and_type_syntax() {
        let fixture = source_fixture(
            "declarations-types.wr",
            &["contracts", "declarations_types"],
            include_str!("../../../tests/contracts/syntax/v3/declarations-types.wr"),
        );
        let lowerer = CanonicalHirLowerer::new();
        let output = lowerer
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("normative declarations/types lower to sealed HIR");
        let repeated = lowerer
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("repeat lowering");
        assert_eq!(output, repeated, "lowering must be deterministic");
        let program = output.lowered().program().as_program();
        assert_eq!(program.modules.len(), 1);
        assert!(program.declarations.len() > 20);
        assert!(program.generic_parameters.len() >= 10);
        assert!(program.parameters.len() >= 12);
        assert!(!program.bodies.is_empty());
        assert!(!program.expressions.is_empty());
        let packet = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "Packet")
            })
            .expect("Packet declaration");
        let DeclarationKind::Structure(packet) = &packet.kind else {
            panic!("Packet must lower as a structure")
        };
        let bounded = packet
            .fields
            .iter()
            .find(|field| field.name.as_str() == "bounded")
            .expect("bounded field");
        let wrela_hir::TypeExpressionKind::Named { arguments, .. } = &bounded.ty.kind else {
            panic!("bounded field type")
        };
        assert!(matches!(
            arguments.as_slice(),
            [wrela_hir::GenericArgument {
                kind: wrela_hir::GenericArgumentKind::BoundedCapacity(_),
                ..
            }]
        ));
        let callback = packet
            .fields
            .iter()
            .find(|field| field.name.as_str() == "callback")
            .expect("callback field");
        let wrela_hir::TypeExpressionKind::Function { parameters, .. } = &callback.ty.kind else {
            panic!("callback function type")
        };
        let wrela_hir::TypeExpressionKind::Named { arguments, .. } = &parameters[2].ty.kind else {
            panic!("Packet generic application")
        };
        assert!(matches!(
            arguments.as_slice(),
            [
                wrela_hir::GenericArgument {
                    kind: wrela_hir::GenericArgumentKind::Type(_),
                    ..
                },
                wrela_hir::GenericArgument {
                    kind: wrela_hir::GenericArgumentKind::Constant(_),
                    ..
                },
                wrela_hir::GenericArgument {
                    kind: wrela_hir::GenericArgumentKind::Region(_),
                    ..
                }
            ]
        ));
        assert!(
            output
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code.as_deref() == Some("hir-unresolved-name") })
        );
    }

    #[test]
    fn canonical_lowerer_covers_normative_statement_and_expression_syntax() {
        let fixture = source_fixture(
            "statements-expressions.wr",
            &["contracts", "statements_expressions"],
            include_str!("../../../tests/contracts/syntax/v3/statements-expressions.wr"),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("normative statements/expressions lower to sealed HIR");
        let program = output.lowered().program().as_program();
        assert!(program.statements.len() >= 70);
        assert!(program.expressions.len() >= 100);
        assert!(program.patterns.len() >= 10);
        assert!(program.scopes.len() >= 10);
        assert!(program.locals.len() >= 20);
        assert!(program.bodies.len() >= 10);
    }

    #[test]
    fn exclusive_call_places_are_explicit_and_forged_nonlocal_roots_are_rejected() {
        let fixture = source_fixture(
            "statements-expressions.wr",
            &["contracts", "statements_expressions"],
            include_str!("../../../tests/contracts/syntax/v3/statements-expressions.wr"),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("exclusive-place fixture lowers");
        let mut program = output.lowered().program().as_program().clone();
        let forbidden_root = wrela_hir::Definition::Builtin(wrela_hir::Builtin::U64);
        let place =
            program
                .expressions
                .iter_mut()
                .find_map(|expression| match &mut expression.kind {
                    wrela_hir::ExpressionKind::Call { arguments, .. } => arguments
                        .iter_mut()
                        .find_map(|argument| match &mut argument.value {
                            wrela_hir::CallArgumentValue::Exclusive { place, .. } => Some(place),
                            wrela_hir::CallArgumentValue::Value(_) => None,
                        }),
                    _ => None,
                })
                .expect("fixture has an explicit exclusive place");
        assert!(matches!(
            place.root,
            wrela_hir::Definition::Local(_) | wrela_hir::Definition::Parameter(_)
        ));
        place.root = forbidden_root;
        assert!(program.validate().is_err());
    }

    #[test]
    fn canonical_lowerer_preserves_checked_and_modular_left_shift() {
        let fixture = source_fixture(
            "shift-frontend.wr",
            &["shift_frontend"],
            concat!(
                "module shift_frontend\n",
                "fn shifts(left: u32, count: u32):\n",
                "    checked = left << count\n",
                "    modular = left <<% count\n",
                "    mixed = left + 1 <<% count + 2 << 1\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("checked and modular shifts lower to sealed HIR");
        assert_eq!(output.diagnostics(), &[]);
        let program = output.lowered().program().as_program();
        let expression_by_source = |spelling: &str| {
            program
                .expressions
                .iter()
                .find(|expression| fixture.sources.span_text(expression.source) == Some(spelling))
                .unwrap_or_else(|| panic!("missing HIR expression `{spelling}`"))
        };

        assert!(matches!(
            &expression_by_source("left << count").kind,
            wrela_hir::ExpressionKind::Binary {
                operator: wrela_hir::BinaryOperator::ShiftLeft,
                ..
            }
        ));
        assert!(matches!(
            &expression_by_source("left <<% count").kind,
            wrela_hir::ExpressionKind::Binary {
                operator: wrela_hir::BinaryOperator::ShiftLeftModular,
                ..
            }
        ));

        let wrela_hir::ExpressionKind::Binary {
            operator: wrela_hir::BinaryOperator::ShiftLeft,
            left,
            ..
        } = &expression_by_source("left + 1 <<% count + 2 << 1").kind
        else {
            panic!("outer checked shift must retain shared left associativity");
        };
        let modular = program.expression(*left).expect("outer shift left operand");
        let wrela_hir::ExpressionKind::Binary {
            operator: wrela_hir::BinaryOperator::ShiftLeftModular,
            left: modular_left,
            right: modular_right,
        } = &modular.kind
        else {
            panic!("modular shift must remain distinct in HIR");
        };
        for operand in [*modular_left, *modular_right] {
            assert!(matches!(
                &program.expression(operand).expect("modular operand").kind,
                wrela_hir::ExpressionKind::Binary {
                    operator: wrela_hir::BinaryOperator::Add,
                    ..
                }
            ));
        }
    }

    #[test]
    fn source_elif_chain_normalizes_to_ordered_single_branch_hir() {
        let fixture = source_fixture(
            "elif-chain.wr",
            &["elif_chain"],
            concat!(
                "module elif_chain\n",
                "fn choose(first: bool, second: bool, third: bool) -> u32:\n",
                "    joined: u32 = 7\n",
                "    if first:\n",
                "        joined = 11\n",
                "    elif second:\n",
                "        joined = 13\n",
                "    elif third:\n",
                "        joined = 17\n",
                "    else:\n",
                "        joined = 19\n",
                "    return joined\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("elif chain lowers to sealed HIR");
        assert!(
            output.diagnostics().is_empty(),
            "clean elif source must not recover: {:?}",
            output.diagnostics()
        );
        let program = output.lowered().program().as_program();
        assert_eq!(
            program
                .statements
                .iter()
                .filter(|statement| matches!(statement.kind, wrela_hir::StatementKind::If { .. }))
                .count(),
            3
        );
        assert!(program.statements.iter().all(|statement| {
            !matches!(
                &statement.kind,
                wrela_hir::StatementKind::If { branches, .. } if branches.len() != 1
            )
        }));

        let declaration = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "choose")
            })
            .expect("choose declaration");
        let wrela_hir::DeclarationKind::Function(function) = &declaration.kind else {
            panic!("choose must be a function")
        };
        let mut containing_body = function.body.expect("choose body");
        let mut statement = program
            .body(containing_body)
            .expect("choose body record")
            .statements
            .iter()
            .find_map(|id| {
                program
                    .statement(*id)
                    .filter(|statement| {
                        matches!(statement.kind, wrela_hir::StatementKind::If { .. })
                    })
                    .map(|_| *id)
            })
            .expect("outer if statement");
        let expected_conditions = ["first", "second", "third"];
        let expected_statement_prefixes = ["if first", "elif second", "elif third"];
        for (index, (expected_condition, expected_prefix)) in expected_conditions
            .iter()
            .zip(expected_statement_prefixes)
            .enumerate()
        {
            let record = program.statement(statement).expect("if statement record");
            assert_eq!(record.body, containing_body);
            assert!(
                fixture
                    .sources
                    .span_text(record.source)
                    .is_some_and(|text| text.trim_start().starts_with(expected_prefix)),
                "synthetic statement {index} must retain its source clause"
            );
            let wrela_hir::StatementKind::If {
                branches,
                else_body,
            } = &record.kind
            else {
                panic!("normalized chain member must be an if")
            };
            let [(condition, then_body)] = branches.as_slice() else {
                panic!("normalized if must have exactly one branch")
            };
            let condition = program
                .expression(*condition)
                .expect("condition expression");
            let body = program.body(containing_body).expect("containing body");
            assert_eq!(
                fixture.sources.span_text(condition.source),
                Some(*expected_condition)
            );
            assert_eq!(
                condition.owner,
                wrela_hir::ExpressionOwner::Body(containing_body)
            );
            assert_eq!(condition.scope, Some(body.scope));
            let branch_scope = program
                .scope(program.body(*then_body).expect("then body").scope)
                .expect("then scope");
            assert_eq!(branch_scope.parent, Some(body.scope));

            if index + 1 < expected_conditions.len() {
                let nested_body = else_body.expect("elif requires synthetic else body");
                let nested = program.body(nested_body).expect("synthetic else body");
                let nested_scope = program.scope(nested.scope).expect("synthetic else scope");
                assert_eq!(nested_scope.parent, Some(body.scope));
                assert_eq!(
                    nested.source,
                    program.statement(nested.statements[0]).unwrap().source
                );
                let [nested_statement] = nested.statements.as_slice() else {
                    panic!("synthetic else body must contain only the next if")
                };
                containing_body = nested_body;
                statement = *nested_statement;
            } else {
                let final_else = program.body(else_body.expect("final else body")).unwrap();
                let [assignment] = final_else.statements.as_slice() else {
                    panic!("final source else body must be retained directly")
                };
                assert!(matches!(
                    program.statement(*assignment).unwrap().kind,
                    wrela_hir::StatementKind::Assign { .. }
                ));
            }
        }

        let condition_use_starts = output
            .lowered()
            .uses()
            .iter()
            .filter(|use_record| expected_conditions.contains(&use_record.spelling.as_str()))
            .map(|use_record| use_record.source.range.start)
            .collect::<Vec<_>>();
        assert_eq!(condition_use_starts.len(), expected_conditions.len());
        assert!(
            condition_use_starts
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn class_initializer_lowers_to_dedicated_private_hir() {
        let fixture = source_fixture(
            "initializer.wr",
            &["initializer"],
            concat!(
                "module initializer\n",
                "class Cache:\n",
                "    value: u64\n",
                "    init(mut self, value: u64):\n",
                "        pass\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("initializer lowers to sealed HIR");
        assert!(
            output.diagnostics().is_empty(),
            "{:?}",
            output.diagnostics()
        );
        let program = output.lowered().program().as_program();
        let class = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "Cache")
            })
            .expect("class declaration");
        let wrela_hir::DeclarationKind::Class(class_kind) = &class.kind else {
            panic!("Cache must remain a class")
        };
        let initializer = class_kind
            .members
            .iter()
            .filter_map(|id| program.declaration(*id))
            .find(|member| matches!(member.kind, wrela_hir::DeclarationKind::Initializer(_)))
            .expect("dedicated initializer member");
        assert_eq!(
            initializer.owner,
            wrela_hir::DeclarationOwner::Declaration(class.id)
        );
        assert_eq!(initializer.visibility, wrela_hir::Visibility::Private);
        assert!(initializer.name.is_none());
        assert!(initializer.attributes.is_empty());
        let wrela_hir::DeclarationKind::Initializer(kind) = &initializer.kind else {
            unreachable!()
        };
        assert_eq!(kind.parameters.len(), 2);
        let receiver = program.parameter(kind.parameters[0]).expect("receiver");
        assert!(receiver.receiver);
        assert_eq!(receiver.access, wrela_hir::AccessMode::Mutate);
        assert!(receiver.name.is_none());
        assert!(receiver.ty.is_none());
        assert_eq!(
            program.body(kind.body).expect("required body").owner,
            wrela_hir::BodyOwner::Declaration(initializer.id)
        );
        assert!(!program.image_candidates.contains(&initializer.id));
        assert!(!program.test_candidates.contains(&initializer.id));
    }

    #[test]
    fn source_elif_without_else_retains_the_incoming_path_and_exact_limits() {
        let fixture = source_fixture(
            "elif-no-else.wr",
            &["elif_no_else"],
            concat!(
                "module elif_no_else\n",
                "fn choose(first: bool, second: bool) -> u32:\n",
                "    joined: u32 = 7\n",
                "    if first:\n",
                "        joined = 11\n",
                "    elif second:\n",
                "        joined = 13\n",
                "    return joined\n",
            ),
        );
        let lowerer = CanonicalHirLowerer::new();
        let baseline = lowerer
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("elif without else lowers");
        assert!(baseline.diagnostics().is_empty());
        let program = baseline.lowered().program().as_program();
        let ifs = program
            .statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                wrela_hir::StatementKind::If {
                    branches,
                    else_body,
                } => Some((branches, else_body)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(ifs.len(), 2);
        assert!(ifs.iter().all(|(branches, _)| branches.len() == 1));
        assert_eq!(
            ifs.iter()
                .filter(|(_, else_body)| else_body.is_some())
                .count(),
            1
        );

        let exact_statements = u32::try_from(program.statements.len()).expect("statement count");
        let exact_bodies = u32::try_from(program.bodies.len()).expect("body count");
        let mut limits = LoweringLimits::standard();
        limits.statements = exact_statements;
        limits.bodies = exact_bodies;
        lowerer
            .lower(fixture.request(limits), &|| false)
            .expect("exact elif arena limits succeed");

        let mut limits = LoweringLimits::standard();
        limits.statements = exact_statements - 1;
        assert_eq!(
            lowerer.lower(fixture.request(limits), &|| false),
            Err(LowerFailure::ResourceLimit {
                resource: "statements",
                limit: u64::from(exact_statements - 1),
            })
        );
        let mut limits = LoweringLimits::standard();
        limits.bodies = exact_bodies - 1;
        assert_eq!(
            lowerer.lower(fixture.request(limits), &|| false),
            Err(LowerFailure::ResourceLimit {
                resource: "bodies",
                limit: u64::from(exact_bodies - 1),
            })
        );
    }

    #[test]
    fn bare_local_assignment_reuses_one_ancestor_binding_across_nested_branches() {
        let fixture = source_fixture(
            "nested-assignments.wr",
            &["nested_assignments"],
            concat!(
                "module nested_assignments\n",
                "fn join(flag: bool) -> u32:\n",
                "    joined: u32 = 7\n",
                "    if flag:\n",
                "        sibling: u32 = 99\n",
                "        if flag:\n",
                "            joined = 11\n",
                "        else:\n",
                "            joined = 13\n",
                "    else:\n",
                "        joined = 17\n",
                "    return joined\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("real nested assignments lower to sealed HIR");
        assert!(
            output.diagnostics().is_empty(),
            "bare reassignment must not recover as redeclaration: {:?}",
            output.diagnostics()
        );
        let program = output.lowered().program().as_program();
        let joined = program
            .locals
            .iter()
            .find(|local| local.name.as_str() == "joined")
            .expect("one joined local");
        assert_eq!(
            program
                .locals
                .iter()
                .filter(|local| local.name.as_str() == "joined")
                .count(),
            1,
            "branch joins must not allocate replacement locals"
        );
        let assignments = program
            .statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                wrela_hir::StatementKind::Assign {
                    targets, operator, ..
                } => Some((statement, targets, operator)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(assignments.len(), 3);
        for (statement, targets, operator) in assignments {
            assert_eq!(*operator, wrela_hir::AssignmentOperator::Assign);
            let [target] = targets.as_slice() else {
                panic!("scalar branch assignment must have one target")
            };
            assert!(matches!(
                target.root,
                wrela_hir::Definition::Local(local) if local == joined.id
            ));
            assert!(target.projections.is_empty());
            assert_eq!(
                fixture.sources.span_text(target.source),
                Some("joined"),
                "target provenance must be the bare identifier"
            );
            let body = program.body(statement.body).expect("assignment body");
            let mut scope = Some(body.scope);
            let mut ancestor_visible = false;
            for _ in 0..program.scopes.len() {
                let Some(current) = scope else {
                    break;
                };
                if current == joined.scope {
                    ancestor_visible = true;
                    break;
                }
                scope = program.scope(current).and_then(|scope| scope.parent);
            }
            assert!(
                ancestor_visible,
                "joined must be an assignment-scope ancestor"
            );
        }
        assert_eq!(
            output
                .lowered()
                .uses()
                .iter()
                .filter(|use_record| {
                    use_record.spelling.as_str() == "joined"
                        && use_record.kind == BindingKind::Local
                        && use_record.target == Some(ResolvedBinding::Local(joined.id))
                })
                .count(),
            4,
            "three assignment targets and the return must bind the same local"
        );
    }

    #[test]
    fn typed_redeclaration_and_shadow_without_a_binding_recover_but_remain_rejected() {
        let fixture = source_fixture(
            "assignment-recovery.wr",
            &["assignment_recovery"],
            concat!(
                "module assignment_recovery\n",
                "fn recover():\n",
                "    value: u32 = 1\n",
                "    value: u32 = 2\n",
                "    shadow fresh = 3\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("malformed assignment forms recover to sealed HIR");
        let codes = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                "hir-local-redeclaration-requires-shadow",
                "hir-shadow-without-binding"
            ]
        );
        let program = output.lowered().program().as_program();
        let values = program
            .locals
            .iter()
            .filter(|local| local.name.as_str() == "value")
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].shadowed, None);
        assert_eq!(values[1].shadowed, Some(values[0].id));
        let fresh = program
            .locals
            .iter()
            .find(|local| local.name.as_str() == "fresh")
            .expect("recovered fresh local");
        assert_eq!(fresh.shadowed, None);
    }

    #[test]
    fn canonical_lowerer_enforces_cancellation_and_construction_limits() {
        let fixture = source_fixture(
            "declarations-types.wr",
            &["contracts", "declarations_types"],
            include_str!("../../../tests/contracts/syntax/v3/declarations-types.wr"),
        );
        let lowerer = CanonicalHirLowerer::new();
        assert_eq!(
            lowerer.lower(fixture.request(LoweringLimits::standard()), &|| true),
            Err(LowerFailure::Cancelled)
        );
        let polls = Cell::new(0u32);
        assert_eq!(
            lowerer.lower(fixture.request(LoweringLimits::standard()), &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next > 16
            }),
            Err(LowerFailure::Cancelled)
        );
        assert!(polls.get() > 16);

        let mut limits = LoweringLimits::standard();
        limits.declarations = 1;
        assert!(matches!(
            lowerer.lower(fixture.request(limits), &|| false),
            Err(LowerFailure::ResourceLimit { limit: 1, .. })
        ));

        let mut limits = LoweringLimits::standard();
        limits.diagnostics = 1;
        assert_eq!(
            lowerer.lower(fixture.request(limits), &|| false),
            Err(LowerFailure::ResourceLimit {
                resource: "diagnostics",
                limit: 1,
            })
        );
    }

    #[test]
    fn canonical_lowerer_resolves_packages_cycles_and_transitive_reexports() {
        let fixture = package_import_fixture();
        let lowerer = CanonicalHirLowerer::new();
        let output = lowerer
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("package-wide imports lower");
        assert!(
            output.diagnostics().is_empty(),
            "{:?}",
            output.diagnostics()
        );
        assert!(output.lowered().uses().iter().any(|use_record| {
            use_record.kind == BindingKind::Module
                && use_record.spelling.as_str() == "imported_leaf"
        }));
        assert!(output.lowered().uses().iter().any(|use_record| {
            use_record.kind == BindingKind::Variant && use_record.spelling.as_str() == "ready"
        }));
        assert!(output.lowered().uses().iter().any(|use_record| {
            use_record.kind == BindingKind::Declaration && use_record.spelling.as_str() == "Token"
        }));
        let bridge = output
            .lowered()
            .program()
            .as_program()
            .modules
            .iter()
            .find(|module| module.path.dotted() == "api.bridge")
            .expect("bridge module");
        assert_eq!(bridge.reexports.len(), 3);

        let mut limits = LoweringLimits::standard();
        limits.import_scc_size = 1;
        assert_eq!(
            lowerer.lower(fixture.request(limits), &|| false),
            Err(LowerFailure::ResourceLimit {
                resource: "import SCC size",
                limit: 1,
            })
        );
    }

    #[test]
    fn canonical_lowerer_maps_every_builtin_attribute_and_rejects_unknown_namespaces() {
        let fixture = source_fixture(
            "attributes.wr",
            &["attributes"],
            concat!(
                "module attributes\n",
                "@image\n",
                "@app\n",
                "@service\n",
                "@driver\n",
                "@task\n",
                "@isr_safe\n",
                "@receipt_handoff\n",
                "@dma\n",
                "@wire\n",
                "@mmio\n",
                "@offset\n",
                "@layout_assert\n",
                "@suspend_safe\n",
                "@no_promote\n",
                "@budget\n",
                "@uninterrupted\n",
                "pub comptime fn all_attributes():\n",
                "    pass\n",
                "@test\n",
                "fn test_entry():\n",
                "    pass\n",
                "@vendor.flag\n",
                "fn rejected():\n",
                "    pass\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("attribute lowering");
        assert_eq!(
            output
                .diagnostics()
                .iter()
                .filter(|diagnostic| {
                    diagnostic.code.as_deref() == Some("hir-unknown-attribute")
                })
                .count(),
            1
        );
        let program = output.lowered().program().as_program();
        let all = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "all_attributes")
            })
            .expect("attribute declaration");
        let expected = [
            wrela_hir::BuiltinAttribute::Image,
            wrela_hir::BuiltinAttribute::App,
            wrela_hir::BuiltinAttribute::Service,
            wrela_hir::BuiltinAttribute::Driver,
            wrela_hir::BuiltinAttribute::Task,
            wrela_hir::BuiltinAttribute::IsrSafe,
            wrela_hir::BuiltinAttribute::ReceiptHandoff,
            wrela_hir::BuiltinAttribute::Dma,
            wrela_hir::BuiltinAttribute::Wire,
            wrela_hir::BuiltinAttribute::Mmio,
            wrela_hir::BuiltinAttribute::Offset,
            wrela_hir::BuiltinAttribute::LayoutAssert,
            wrela_hir::BuiltinAttribute::Test,
            wrela_hir::BuiltinAttribute::SuspendSafe,
            wrela_hir::BuiltinAttribute::NoPromote,
            wrela_hir::BuiltinAttribute::Budget,
            wrela_hir::BuiltinAttribute::Uninterrupted,
        ];
        let test_entry = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "test_entry")
            })
            .expect("test declaration");
        assert_eq!(all.attributes.len(), expected.len() - 1);
        assert_eq!(test_entry.attributes.len(), 1);
        for builtin in expected {
            assert!(
                all.attributes
                    .iter()
                    .chain(&test_entry.attributes)
                    .any(|attribute| {
                        attribute.identity == wrela_hir::AttributeIdentity::Builtin(builtin)
                    })
            );
        }
        let rejected = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "rejected")
            })
            .expect("rejected declaration");
        assert!(rejected.attributes.is_empty());
        assert_eq!(program.image_candidates, vec![all.id]);
        assert_eq!(program.test_candidates, vec![test_entry.id]);
    }

    #[test]
    fn canonical_lowerer_resolves_pattern_candidates_and_shared_alternative_bindings() {
        let fixture = source_fixture(
            "patterns.wr",
            &["patterns"],
            concat!(
                "module patterns\n",
                "enum State:\n",
                "    ready\n",
                "    payload(u64,)\n",
                "fn inspect(value: State) -> u64:\n",
                "    match value:\n",
                "        case ready:\n",
                "            return 0\n",
                "        case payload(ready):\n",
                "            return 0\n",
                "        case payload(bind x) | payload(bind x):\n",
                "            return x\n",
                "        case State.payload(bind z):\n",
                "            return z\n",
                "    if value is payload(bind y) and y > 0:\n",
                "        return y\n",
                "    return 0\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("pattern lowering");
        assert!(
            output.diagnostics().is_empty(),
            "{:?}",
            output.diagnostics()
        );
        let program = output.lowered().program().as_program();
        assert!(program.patterns.iter().any(|pattern| {
            pattern.alternatives.iter().any(|alternative| {
                matches!(
                    &alternative.kind,
                    wrela_hir::PrimaryPattern::ContextualName {
                        spelling,
                        candidates,
                        ..
                    } if spelling.as_str() == "ready" && candidates.len() == 1
                )
            })
        }));
        assert!(program.patterns.iter().any(|pattern| {
            pattern.alternatives.iter().any(|alternative| {
                matches!(
                    &alternative.kind,
                    wrela_hir::PrimaryPattern::Constructor {
                        spelling,
                        candidates,
                        ..
                    } if spelling.as_str() == "payload" && candidates.len() == 1
                )
            })
        }));
        assert_eq!(
            program
                .locals
                .iter()
                .filter(|local| local.name.as_str() == "x")
                .count(),
            1,
            "pattern alternatives must reuse the same local binding"
        );
    }

    #[test]
    fn canonical_lowerer_recovers_duplicate_subtrees_and_invalid_entry_attributes() {
        let fixture = source_fixture(
            "recovery.wr",
            &["recovery"],
            concat!(
                "module recovery\n",
                "struct Same:\n",
                "    pub fn retained():\n",
                "        pass\n",
                "struct Same:\n",
                "    pub fn must_not_escape_error_parent():\n",
                "        pass\n",
                "@image\n",
                "fn invalid_image(value: u64):\n",
                "    pass\n",
                "fn after():\n",
                "    pass\n",
            ),
        );
        let output = CanonicalHirLowerer::new()
            .lower(fixture.request(LoweringLimits::standard()), &|| false)
            .expect("recoverable source still seals");
        assert!(
            output.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_deref() == Some("hir-duplicate-declaration")
            })
        );
        assert!(output.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("hir-invalid-entry-attribute")
        }));
        let program = output.lowered().program().as_program();
        assert!(!program.declarations.iter().any(|declaration| {
            declaration
                .name
                .as_ref()
                .is_some_and(|name| name.as_str() == "must_not_escape_error_parent")
        }));
        let invalid_image = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "invalid_image")
            })
            .expect("invalid image function retained without the attribute");
        assert!(invalid_image.attributes.is_empty());
        assert!(program.image_candidates.is_empty());
    }

    #[test]
    fn rejects_an_equivalent_but_cloned_package_graph() {
        let fixture = fixture();
        let mut candidate = fixture.candidate.clone();
        candidate.program.packages = Arc::new(fixture.packages.as_ref().clone());
        assert_eq!(
            seal_lower_output(
                &fixture.request(LoweringLimits::standard()),
                candidate,
                Vec::new(),
                &|| false,
            ),
            Err(LowerFailure::SourceGraphMismatch)
        );
    }

    #[test]
    fn validates_resolved_use_spelling_and_exact_target() {
        let fixture = fixture();
        let mut candidate = fixture.candidate.clone();
        candidate.uses.push(ResolvedUse {
            source: fixture.declaration_name,
            spelling: ReferenceSpelling::Identifier(Name::new("start".to_owned()).expect("name")),
            kind: BindingKind::Declaration,
            target: Some(ResolvedBinding::Declaration(ResolvedDeclaration {
                package: PackageId(0),
                module: ModuleId(0),
                declaration: DeclarationId(0),
            })),
        });
        candidate.modules[0].resolved_uses = 1;
        seal_lower_output(
            &fixture.request(LoweringLimits::standard()),
            candidate.clone(),
            Vec::new(),
            &|| false,
        )
        .expect("resolved use");

        candidate.uses[0].source = Span {
            file: FileId(0),
            range: TextRange { start: 7, end: 11 },
        };
        assert!(matches!(
            seal_lower_output(
                &fixture.request(LoweringLimits::standard()),
                candidate,
                Vec::new(),
                &|| false,
            ),
            Err(LowerFailure::InvalidOutput(_))
        ));
    }

    #[test]
    fn arena_limits_and_cancellation_precede_program_validation() {
        let fixture = fixture();
        let mut oversized = fixture.candidate.clone();
        oversized
            .program
            .declarations
            .push(oversized.program.declarations[0].clone());
        let mut limits = LoweringLimits::standard();
        limits.declarations = 1;
        assert_eq!(
            seal_lower_output(&fixture.request(limits), oversized, Vec::new(), &|| false,),
            Err(LowerFailure::ResourceLimit {
                resource: "declarations",
                limit: 1,
            })
        );
        assert_eq!(
            seal_lower_output(
                &fixture.request(LoweringLimits::standard()),
                fixture.candidate.clone(),
                Vec::new(),
                &|| true,
            ),
            Err(LowerFailure::Cancelled)
        );
    }
}
