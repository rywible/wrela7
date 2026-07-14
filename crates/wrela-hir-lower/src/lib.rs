//! Import/name resolution, generic-kind classification, desugaring, and HIR
//! construction from a complete set of parsed files.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_diagnostics::{Diagnostic, WithDiagnostics};
use wrela_hir::{
    DeclarationId, ManifestDeclarationError, Name, Program, ResolvedDeclaration, ValidatedProgram,
};
use wrela_package::{ImageDeclaration, ModuleId, PackageGraph};
use wrela_source::{FileId, SourceDatabase, Span};
use wrela_syntax::ParsedFile;

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

#[derive(Debug)]
pub struct LowerRequest<'a> {
    pub packages: PackageGraph,
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
    Module,
    GenericType,
    GenericConstant,
    GenericRegion,
    Builtin,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUse {
    pub source: Span,
    pub spelling: Name,
    pub kind: BindingKind,
    pub target: Option<ResolvedDeclaration>,
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
    program: ValidatedProgram,
    /// Sorted source-facing resolution index used by diagnostics and lints.
    uses: Vec<ResolvedUse>,
    modules: Vec<ModuleResolutionSummary>,
    source_graph_digest: Sha256Digest,
}

impl LoweredProgram {
    #[must_use]
    pub fn program(&self) -> &ValidatedProgram {
        &self.program
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
    validate_lower_inputs(request)?;
    if candidate.source_graph_digest != request.source_graph_digest
        || candidate.program.packages != request.packages
    {
        return Err(LowerFailure::SourceGraphMismatch);
    }
    validate_model_resources(
        &candidate.program,
        &candidate.uses,
        &candidate.modules,
        request.limits,
    )?;
    let program = candidate
        .program
        .validate()
        .map_err(|error| LowerFailure::InvalidProgram(error.to_string()))?;
    let model = program.as_program();
    let counts = [
        ("modules", model.modules.len(), request.limits.modules),
        (
            "declarations",
            model.declarations.len(),
            request.limits.declarations,
        ),
        (
            "generic parameters",
            model.generic_parameters.len(),
            request.limits.generic_parameters,
        ),
        (
            "parameters",
            model.parameters.len(),
            request.limits.parameters,
        ),
        ("bodies", model.bodies.len(), request.limits.bodies),
        ("scopes", model.scopes.len(), request.limits.scopes),
        ("locals", model.locals.len(), request.limits.locals),
        (
            "statements",
            model.statements.len(),
            request.limits.statements,
        ),
        (
            "expressions",
            model.expressions.len(),
            request.limits.expressions,
        ),
        ("patterns", model.patterns.len(), request.limits.patterns),
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
    if candidate.uses.len() as u64 > request.limits.resolved_uses {
        return Err(LowerFailure::ResourceLimit {
            resource: "resolved uses",
            limit: request.limits.resolved_uses,
        });
    }
    validate_uses(request, &program, &candidate.uses)?;
    validate_module_summaries(request, &program, &candidate.uses, &candidate.modules)?;
    let diagnostics = validate_diagnostics(request, diagnostics)?;
    if is_cancelled() {
        return Err(LowerFailure::Cancelled);
    }
    Ok(LowerOutput {
        lowered: LoweredProgram {
            program,
            uses: candidate.uses,
            modules: candidate.modules,
            source_graph_digest: candidate.source_graph_digest,
        },
        diagnostics,
    })
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

fn validate_model_resources(
    model: &wrela_hir::Program,
    uses: &[ResolvedUse],
    modules: &[ModuleResolutionSummary],
    limits: LoweringLimits,
) -> Result<(), LowerFailure> {
    use wrela_hir::{
        DeclarationKind, ExpressionKind, GenericArgument, GenericParameterKind, InterpolationPart,
        PrimaryPattern, ProjectionCarrier, StatementKind, TypeExpression, TypeExpressionKind,
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
        model.image_candidates.len(),
        model.test_candidates.len(),
        uses.len(),
        modules.len(),
    ] {
        meter.add_edges(count);
    }
    let mut types: Vec<(&TypeExpression, u32)> = Vec::new();
    let mut carriers: Vec<(&ProjectionCarrier, u32)> = Vec::new();
    let mut attributes = Vec::new();

    for module in &model.modules {
        meter.edges(&module.declarations);
        meter.edges(&module.reexports);
        for reexport in &module.reexports {
            meter.text(reexport.local_name.as_str());
        }
    }
    for declaration in &model.declarations {
        meter.text(declaration.name.as_str());
        meter.edges(&declaration.attributes);
        attributes.extend(&declaration.attributes);
        match &declaration.kind {
            DeclarationKind::Constant(value) => {
                if let Some(ty) = &value.ty {
                    types.push((ty, 1));
                }
            }
            DeclarationKind::Function(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.parameters);
                types.push((&value.result, 1));
            }
            DeclarationKind::Structure(value) | DeclarationKind::Class(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.implements);
                meter.edges(&value.fields);
                meter.edges(&value.members);
                types.extend(value.implements.iter().map(|ty| (ty, 1)));
                for field in &value.fields {
                    meter.text(field.name.as_str());
                    meter.edges(&field.attributes);
                    attributes.extend(&field.attributes);
                    types.push((&field.ty, 1));
                }
            }
            DeclarationKind::Enumeration(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.variants);
                meter.edges(&value.members);
                for variant in &value.variants {
                    meter.text(variant.name.as_str());
                    meter.edges(&variant.fields);
                    for field in &variant.fields {
                        if let Some(name) = &field.name {
                            meter.text(name.as_str());
                        }
                        types.push((&field.ty, 1));
                    }
                }
            }
            DeclarationKind::Interface(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.requirements);
            }
            DeclarationKind::Implementation(value) => {
                meter.edges(&value.members);
                types.push((&value.interface, 1));
                types.push((&value.implementing_type, 1));
            }
            DeclarationKind::Projection(value) => {
                meter.edges(&value.generics);
                meter.edges(&value.parameters);
                meter.edges(&value.provenance);
                carriers.push((&value.carrier, 1));
            }
            DeclarationKind::Scope(value) => {
                meter.edges(&value.parameters);
                types.push((&value.result, 1));
            }
            DeclarationKind::ComptimeSelection(value) => {
                meter.edges(&value.then_declarations);
                meter.edges(&value.else_declarations);
            }
            DeclarationKind::Brand | DeclarationKind::Error => {}
        }
    }
    for parameter in &model.generic_parameters {
        meter.text(parameter.name.as_str());
        match &parameter.kind {
            GenericParameterKind::Type { bound: Some(ty) } => types.push((ty, 1)),
            GenericParameterKind::Constant { ty } => types.push((ty, 1)),
            GenericParameterKind::Type { bound: None } | GenericParameterKind::Region => {}
        }
    }
    for parameter in &model.parameters {
        meter.text(parameter.name.as_str());
        types.push((&parameter.ty, 1));
    }
    for body in &model.bodies {
        meter.edges(&body.locals);
        meter.edges(&body.statements);
    }
    for local in &model.locals {
        meter.text(local.name.as_str());
        if let Some(ty) = &local.ty {
            types.push((ty, 1));
        }
    }
    for statement in &model.statements {
        meter.edges(&statement.attributes);
        attributes.extend(&statement.attributes);
        match &statement.kind {
            StatementKind::Assign { targets, .. } => {
                meter.edges(targets);
                for target in targets {
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
            ExpressionKind::Compare { tails, .. } => meter.edges(tails),
            ExpressionKind::Cast { ty, .. } => types.push((ty, 1)),
            ExpressionKind::Field { name, .. } => meter.text(name.as_str()),
            ExpressionKind::Call { arguments, .. } => {
                meter.edges(arguments);
                for argument in arguments {
                    if let Some(name) = &argument.name {
                        meter.text(name.as_str());
                    }
                }
            }
            ExpressionKind::Tuple(values)
            | ExpressionKind::Array(values)
            | ExpressionKind::Race(values) => meter.edges(values),
            ExpressionKind::Interpolate(parts) => {
                meter.edges(parts);
                for part in parts {
                    match part {
                        InterpolationPart::Text(value) => meter.text(value),
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
            | ExpressionKind::IsPattern { .. }
            | ExpressionKind::Range { .. }
            | ExpressionKind::Try(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::TrySend(_)
            | ExpressionKind::Error => {}
        }
    }
    for pattern in &model.patterns {
        meter.edges(&pattern.alternatives);
        for alternative in &pattern.alternatives {
            match alternative {
                PrimaryPattern::Literal { literal, .. } => measure_literal(literal, &mut meter),
                PrimaryPattern::Constructor {
                    candidates,
                    arguments,
                } => {
                    meter.edges(candidates);
                    meter.edges(arguments);
                }
                PrimaryPattern::Tuple(arguments) | PrimaryPattern::Array(arguments) => {
                    meter.edges(arguments);
                }
                PrimaryPattern::Wildcard | PrimaryPattern::Bind(_) | PrimaryPattern::Error => {}
            }
        }
    }
    for attribute in attributes {
        meter.edges(&attribute.arguments);
        for argument in &attribute.arguments {
            if let Some(name) = &argument.name {
                meter.text(name.as_str());
            }
        }
    }
    for value in uses {
        meter.text(value.spelling.as_str());
    }
    for module in modules {
        meter.edges(&module.declarations);
    }
    while let Some((ty, depth)) = types.pop() {
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
                    if let GenericArgument::Type(ty) = argument {
                        types.push((ty, next));
                    }
                }
            }
            TypeExpressionKind::Array { element, .. }
            | TypeExpressionKind::View {
                target: element, ..
            } => types.push((element, next)),
            TypeExpressionKind::Tuple(values) => {
                meter.edges(values);
                types.extend(values.iter().map(|ty| (ty, next)));
            }
            TypeExpressionKind::Iso { brand, payload } => {
                types.push((brand, next));
                types.push((payload, next));
            }
            TypeExpressionKind::Function {
                parameters, result, ..
            } => {
                meter.edges(parameters);
                types.extend(parameters.iter().map(|parameter| (&parameter.ty, next)));
                types.push((result, next));
            }
            TypeExpressionKind::Error => {}
        }
    }
    while let Some((carrier, depth)) = carriers.pop() {
        meter.add_edges(1);
        meter.maximum_depth = meter.maximum_depth.max(depth);
        let Some(next) = depth.checked_add(1) else {
            meter.overflowed = true;
            continue;
        };
        match carrier {
            ProjectionCarrier::View { ty, .. } => types.push((ty, next)),
            ProjectionCarrier::Tuple(values) => {
                meter.edges(values);
                carriers.extend(values.iter().map(|value| (value, next)));
            }
            ProjectionCarrier::Option(value) => carriers.push((value, next)),
            ProjectionCarrier::Result { carrier, error } => {
                carriers.push((carrier, next));
                types.push((error, next));
            }
            ProjectionCarrier::Error => {}
        }
    }
    // Projection carriers can introduce additional type-expression roots.
    while let Some((ty, depth)) = types.pop() {
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
                    if let GenericArgument::Type(ty) = argument {
                        types.push((ty, next));
                    }
                }
            }
            TypeExpressionKind::Array { element, .. }
            | TypeExpressionKind::View {
                target: element, ..
            } => types.push((element, next)),
            TypeExpressionKind::Tuple(values) => {
                meter.edges(values);
                types.extend(values.iter().map(|ty| (ty, next)));
            }
            TypeExpressionKind::Iso { brand, payload } => {
                types.push((brand, next));
                types.push((payload, next));
            }
            TypeExpressionKind::Function {
                parameters, result, ..
            } => {
                meter.edges(parameters);
                types.extend(parameters.iter().map(|parameter| (&parameter.ty, next)));
                types.push((result, next));
            }
            TypeExpressionKind::Error => {}
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

fn validate_lower_inputs(request: &LowerRequest<'_>) -> Result<(), LowerFailure> {
    if request.parsed_files.len() != request.sources.len()
        || request.packages.modules().len() != request.sources.len()
    {
        return Err(LowerFailure::SourceGraphMismatch);
    }
    let mut graph_sources = vec![false; request.sources.len()];
    for module in request.packages.modules() {
        let Some(slot) = graph_sources.get_mut(module.source.0 as usize) else {
            return Err(LowerFailure::ParsedFileOutsideGraph(module.source));
        };
        if *slot {
            return Err(LowerFailure::DuplicateParsedFile(module.source));
        }
        *slot = true;
    }
    if graph_sources.iter().any(|present| !present) {
        return Err(LowerFailure::SourceGraphMismatch);
    }
    for (index, parsed) in request.parsed_files.iter().enumerate() {
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
            return Err(
                if request
                    .parsed_files
                    .iter()
                    .filter(|candidate| candidate.file() == parsed.file())
                    .count()
                    > 1
                {
                    LowerFailure::DuplicateParsedFile(parsed.file())
                } else {
                    LowerFailure::MissingParsedFile(file)
                },
            );
        }
        if parsed.source_digest() != source.digest() {
            return Err(LowerFailure::StaleParsedFile(file));
        }
        if !parsed.recovery_complete() {
            return Err(LowerFailure::IncompleteParsedFile(file));
        }
    }
    if !request
        .changes
        .changed_files
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        || request
            .changes
            .changed_files
            .iter()
            .any(|file| request.sources.get(*file).is_none())
        || (request.changes.previous_source_graph == Some(request.source_graph_digest)
            && !request.changes.changed_files.is_empty())
    {
        return Err(LowerFailure::InvalidChangeSet);
    }
    Ok(())
}

fn validate_uses(
    request: &LowerRequest<'_>,
    program: &ValidatedProgram,
    uses: &[ResolvedUse],
) -> Result<(), LowerFailure> {
    if !uses
        .windows(2)
        .all(|pair| use_key(&pair[0]) < use_key(&pair[1]))
    {
        return Err(LowerFailure::InvalidOutput(
            "resolved-use index is not strictly canonical".to_owned(),
        ));
    }
    for resolved_use in uses {
        if !resolved_use.spelling.is_valid()
            || request.sources.span_text(resolved_use.source).is_none()
            || match resolved_use.kind {
                BindingKind::Declaration => resolved_use
                    .target
                    .as_ref()
                    .is_none_or(|target| program.resolved_declaration(target).is_none()),
                _ => resolved_use.target.is_some(),
            }
        {
            return Err(LowerFailure::InvalidOutput(
                "resolved use has an invalid name, span, kind, or target".to_owned(),
            ));
        }
    }
    Ok(())
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
            BindingKind::Module => 3,
            BindingKind::GenericType => 4,
            BindingKind::GenericConstant => 5,
            BindingKind::GenericRegion => 6,
            BindingKind::Builtin => 7,
            BindingKind::Error => 8,
        },
    )
}

fn validate_module_summaries(
    request: &LowerRequest<'_>,
    program: &ValidatedProgram,
    uses: &[ResolvedUse],
    summaries: &[ModuleResolutionSummary],
) -> Result<(), LowerFailure> {
    let model = program.as_program();
    if summaries.len() != model.modules.len() {
        return Err(LowerFailure::InvalidOutput(
            "module summary coverage differs from HIR modules".to_owned(),
        ));
    }
    let mut use_counts = std::collections::BTreeMap::new();
    for resolved_use in uses {
        let counts = use_counts
            .entry(resolved_use.source.file)
            .or_insert((0usize, 0usize));
        if resolved_use.kind == BindingKind::Error {
            counts.1 += 1;
        } else {
            counts.0 += 1;
        }
    }
    for (index, summary) in summaries.iter().enumerate() {
        let module = &model.modules[index];
        let graph_module = &request.packages.modules()[index];
        let parsed = request
            .parsed_files
            .get(graph_module.source.0 as usize)
            .ok_or(LowerFailure::MissingParsedFile(graph_module.source))?;
        let (resolved, errors) = use_counts
            .get(&graph_module.source)
            .copied()
            .unwrap_or_default();
        let reuse_permitted = request.changes.previous_source_graph.is_some()
            && !request.changes.changed_files.contains(&graph_module.source);
        if summary.module != module.id
            || summary.declarations != module.declarations
            || summary.imports as usize != parsed.ast().imports.len()
            || summary.resolved_uses as usize != resolved
            || summary.error_uses as usize != errors
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
) -> Result<Vec<Diagnostic>, LowerFailure> {
    if diagnostics.len() > request.limits.diagnostics as usize {
        return Err(LowerFailure::ResourceLimit {
            resource: "diagnostics",
            limit: u64::from(request.limits.diagnostics),
        });
    }
    let mut bytes = 0u64;
    for diagnostic in &diagnostics {
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
    use super::{LowerFailure, LoweringLimits};

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
}
