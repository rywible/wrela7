//! Production package-wide syntax-to-HIR lowering.
//!
//! This module deliberately keeps every source-derived arena allocation behind
//! the request policy and performs declaration collection before resolving any
//! import or use.  That ordering makes module cycles ordinary name-binding
//! cycles rather than an implementation recursion hazard.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

use wrela_diagnostics::{Category, Diagnostic};
use wrela_hir as hir;
use wrela_package::{ModuleId, PackageId};
use wrela_source::{Span, TextRange};
use wrela_syntax as syntax;
use wrela_syntax::{SyntaxParser, WrelaSyntaxParser};

use super::{
    BindingKind, HIR_CHANGE_SET_REUSE_VERSION, HirLowerer, HirReuseLimits, HirReuseReport,
    LowerFailure, LowerOutput, LowerRequest, LoweredProgramCandidate, ModuleResolutionSummary,
    PreviousHirProduct, ReferenceSpelling, ResolvedBinding, ResolvedUse, TrackedLowerOutput,
    poll_cancellation, seal_lower_output, validate_lower_inputs,
};

/// Canonical production implementation of the syntax-to-resolved-HIR
/// boundary.  It contains no cache or private arena state and is safe to reuse
/// across compilation requests.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalHirLowerer;

impl CanonicalHirLowerer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Lower with explicit, bounded reuse evidence. `None` is a tracked cold
    /// run and cannot carry incremental flags. `Some` requires the exact sealed
    /// prior product; digest-only reuse is rejected.
    pub fn lower_tracked(
        &self,
        request: LowerRequest<'_>,
        previous: Option<PreviousHirProduct<'_>>,
        reuse_limits: HirReuseLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TrackedLowerOutput, LowerFailure> {
        reuse_limits.validate()?;
        let Some(previous) = previous else {
            if request.changes.previous_source_graph.is_some()
                || !request.changes.changed_files.is_empty()
            {
                return Err(LowerFailure::InvalidChangeSet);
            }
            let output = self.lower(request, is_cancelled)?;
            let executed = output.lowered.program.as_program().declarations.len() as u64;
            return Ok(TrackedLowerOutput {
                output,
                reuse: HirReuseReport::cold(executed),
            });
        };
        if previous.contract_version != HIR_CHANGE_SET_REUSE_VERSION {
            return Err(LowerFailure::UnsupportedReuseVersion {
                observed: previous.contract_version,
            });
        }
        validate_previous_product(&request, previous.output, is_cancelled)?;
        let mut meter = HirReuseMeter::new(reuse_limits, is_cancelled);
        let affected = affected_files(&request, previous.output, &mut meter)?;
        if request.changes.changed_files.as_slice() != affected.as_slice() {
            return Err(LowerFailure::InvalidChangeSet);
        }
        let affected_set = affected.iter().copied().collect::<BTreeSet<_>>();
        let reusable_files = request
            .packages
            .modules()
            .iter()
            .map(|module| module.source)
            .filter(|file| !affected_set.contains(file))
            .collect::<BTreeSet<_>>();
        validate_reusable_modules(&request, previous.output, &reusable_files, &mut meter)?;

        request.limits.validate()?;
        validate_lower_inputs(&request, is_cancelled)?;
        let mut session = LoweringSession::new(&request, is_cancelled)?;
        session.collect_modules()?;
        session.collect_declarations()?;
        session.collect_headers_reusing(previous.output, &reusable_files, &mut meter)?;
        session.resolve_imports()?;
        session.enforce_import_scc_limit()?;
        session.load_reused_module_uses(previous.output, &reusable_files, &mut meter)?;
        let producer_declarations_executed =
            session.lower_declarations_reusing(previous.output, &reusable_files, &mut meter)?;
        let (candidate, diagnostics) = session.finish()?;
        let output = seal_lower_output(&request, candidate, diagnostics, is_cancelled)?;
        meter.poll()?;
        let reused_modules = request
            .packages
            .modules()
            .iter()
            .filter(|module| reusable_files.contains(&module.source))
            .map(|module| module.id)
            .collect();
        let reused_declarations = output
            .lowered
            .program
            .as_program()
            .declarations
            .iter()
            .filter(|declaration| {
                let file = request.packages.modules()[declaration.module.0 as usize].source;
                reusable_files.contains(&file)
            })
            .map(|declaration| declaration.id)
            .collect();
        Ok(TrackedLowerOutput {
            output,
            reuse: HirReuseReport {
                reused_modules,
                reused_declarations,
                recomputed_files: affected,
                producer_declarations_executed,
                comparisons: meter.used,
            },
        })
    }
}

struct HirReuseMeter<'a> {
    used: u64,
    limits: HirReuseLimits,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> HirReuseMeter<'a> {
    fn new(limits: HirReuseLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            used: 0,
            limits,
            is_cancelled,
        }
    }

    fn poll(&mut self) -> Result<(), LowerFailure> {
        poll_cancellation(self.is_cancelled)?;
        self.used = self
            .used
            .checked_add(1)
            .ok_or(LowerFailure::ResourceLimit {
                resource: "HIR reuse comparisons",
                limit: self.limits.comparisons,
            })?;
        if self.used > self.limits.comparisons {
            return Err(LowerFailure::ResourceLimit {
                resource: "HIR reuse comparisons",
                limit: self.limits.comparisons,
            });
        }
        Ok(())
    }
}

fn validate_previous_product(
    request: &LowerRequest<'_>,
    previous: &LowerOutput,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerFailure> {
    poll_cancellation(is_cancelled)?;
    if request.changes.previous_source_graph != Some(previous.lowered.source_graph_digest)
        || previous.lowered.source_graph_digest == request.source_graph_digest
        || previous.lowered.source_revisions.len() != request.sources.len()
        || !compatible_package_graphs(
            previous.lowered.program.as_program().packages.as_ref(),
            request.packages.as_ref(),
        )
    {
        return Err(LowerFailure::InvalidChangeSet);
    }
    let mut direct_changes = Vec::new();
    for revision in &previous.lowered.source_revisions {
        poll_cancellation(is_cancelled)?;
        let current = request
            .sources
            .get(revision.file)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        if current.path() != revision.path {
            return Err(LowerFailure::InvalidChangeSet);
        }
        if current.digest() != revision.digest {
            direct_changes.push(revision.file);
        }
    }
    if direct_changes.is_empty() {
        return Err(LowerFailure::InvalidChangeSet);
    }
    Ok(())
}

fn compatible_package_graphs(
    previous: &wrela_package::PackageGraph,
    current: &wrela_package::PackageGraph,
) -> bool {
    previous.root() == current.root()
        && previous.packages().len() == current.packages().len()
        && previous.modules() == current.modules()
        && previous
            .packages()
            .iter()
            .zip(current.packages())
            .all(|(left, right)| {
                left.id == right.id
                    && left.identity.name == right.identity.name
                    && left.identity.version == right.identity.version
                    && left.dependencies == right.dependencies
            })
}

fn affected_files(
    request: &LowerRequest<'_>,
    previous: &LowerOutput,
    meter: &mut HirReuseMeter<'_>,
) -> Result<Vec<wrela_source::FileId>, LowerFailure> {
    let mut affected = BTreeSet::new();
    for revision in &previous.lowered.source_revisions {
        meter.poll()?;
        let current_source = request
            .sources
            .get(revision.file)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        if current_source.digest() != revision.digest {
            affected.insert(revision.file);
        }
    }
    loop {
        let before = affected.len();
        for record in &previous.lowered.uses {
            meter.poll()?;
            let Some(target_module) = binding_module(record.target.as_ref()) else {
                continue;
            };
            let target_file = request
                .packages
                .modules()
                .get(target_module.0 as usize)
                .ok_or(LowerFailure::InvalidChangeSet)?
                .source;
            if affected.contains(&target_file) {
                affected.insert(record.source.file);
            }
        }
        if affected.len() == before {
            break;
        }
    }
    Ok(affected.into_iter().collect())
}

fn validate_reusable_modules(
    request: &LowerRequest<'_>,
    previous: &LowerOutput,
    reusable_files: &BTreeSet<wrela_source::FileId>,
    meter: &mut HirReuseMeter<'_>,
) -> Result<(), LowerFailure> {
    if previous
        .diagnostics
        .iter()
        .any(|diagnostic| reusable_files.contains(&diagnostic.primary.file))
    {
        return Err(LowerFailure::UnsupportedReuseShape(
            "diagnostic-bearing unchanged modules require a future diagnostic-slice cache",
        ));
    }
    let previous_program = previous.lowered.program.as_program();
    for graph_module in request.packages.modules() {
        meter.poll()?;
        if !reusable_files.contains(&graph_module.source) {
            continue;
        }
        let index = graph_module.id.0 as usize;
        let prior_module = previous_program
            .modules
            .get(index)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        let parsed = request
            .parsed_files
            .get(graph_module.source.0 as usize)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        if prior_module.declarations.len() != parsed.ast().declarations.len() {
            return Err(LowerFailure::UnsupportedReuseShape(
                "an unchanged module changed its top-level declaration shape",
            ));
        }
    }
    Ok(())
}

fn binding_module(binding: Option<&ResolvedBinding>) -> Option<ModuleId> {
    match binding? {
        ResolvedBinding::Declaration(declaration) => Some(declaration.module),
        ResolvedBinding::Variant(variant) => Some(variant.enumeration.module),
        ResolvedBinding::Module { module, .. } => Some(*module),
        ResolvedBinding::Local(_)
        | ResolvedBinding::Parameter(_)
        | ResolvedBinding::Generic(_)
        | ResolvedBinding::LocalRegion(_)
        | ResolvedBinding::Builtin(_) => None,
    }
}

fn install_reused_record<T: Clone>(
    target: &mut Vec<T>,
    id: u32,
    record: &T,
    resource: &'static str,
    limit: u32,
) -> Result<(), LowerFailure> {
    let index = id as usize;
    if index < target.len() {
        target[index] = record.clone();
        Ok(())
    } else if index == target.len() {
        push(target, record.clone(), resource, limit)
    } else {
        Err(LowerFailure::UnsupportedReuseShape(
            "a reused dense arena no longer begins at its prior identity",
        ))
    }
}

fn parameter_declaration(
    program: &hir::Program,
    parameter: &hir::Parameter,
) -> Option<hir::DeclarationId> {
    match parameter.owner {
        hir::CallableOwner::Declaration(declaration) => Some(declaration),
        hir::CallableOwner::Closure(expression) => {
            let expression = program.expressions.get(expression.0 as usize)?;
            expression_declaration(program, expression.owner)
        }
    }
}

fn body_declaration(program: &hir::Program, body: hir::BodyId) -> Option<hir::DeclarationId> {
    match program.bodies.get(body.0 as usize)?.owner {
        hir::BodyOwner::Declaration(declaration) => Some(declaration),
        hir::BodyOwner::Closure(expression) => {
            let expression = program.expressions.get(expression.0 as usize)?;
            expression_declaration(program, expression.owner)
        }
    }
}

fn expression_declaration(
    program: &hir::Program,
    owner: hir::ExpressionOwner,
) -> Option<hir::DeclarationId> {
    match owner {
        hir::ExpressionOwner::Declaration(declaration) => Some(declaration),
        hir::ExpressionOwner::Body(body) => body_declaration(program, body),
        hir::ExpressionOwner::Closure(expression) => {
            let expression = program.expressions.get(expression.0 as usize)?;
            expression_declaration(program, expression.owner)
        }
    }
}

impl HirLowerer for CanonicalHirLowerer {
    fn lower(
        &self,
        request: LowerRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerFailure> {
        request.limits.validate()?;
        validate_lower_inputs(&request, is_cancelled)?;
        let mut session = LoweringSession::new(&request, is_cancelled)?;
        session.collect_modules()?;
        session.collect_declarations()?;
        session.collect_headers()?;
        session.resolve_imports()?;
        session.enforce_import_scc_limit()?;
        session.lower_declarations()?;
        let (candidate, diagnostics) = session.finish()?;
        seal_lower_output(&request, candidate, diagnostics, is_cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedName {
    Value,
    Type,
    Region,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SymbolTarget {
    Declaration(hir::ResolvedDeclaration),
    Variant(hir::ResolvedVariant),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NamespaceTarget {
    Symbol(SymbolTarget),
    Module {
        package: PackageId,
        module: ModuleId,
    },
}

#[derive(Debug, Clone)]
struct Symbol {
    owner: SymbolOwner,
    name: hir::Name,
    target: SymbolTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolOwner {
    Module(ModuleId),
    Declaration(hir::DeclarationId),
}

#[derive(Debug, Clone)]
struct NamedImport {
    module: ModuleId,
    local_name: hir::Name,
    target: SymbolTarget,
    source: Span,
}

#[derive(Debug, Clone)]
struct ModuleImport {
    module: ModuleId,
    local_path: Vec<hir::Name>,
    target_package: PackageId,
    target_module: ModuleId,
    source: Span,
}

#[derive(Debug, Clone, Copy)]
struct PendingNamedImport<'a> {
    module: ModuleId,
    target_module: ModuleId,
    public: bool,
    imported: &'a syntax::ImportedName,
}

#[derive(Debug, Clone, Copy)]
enum DeclarationSyntax<'a> {
    Constant(&'a syntax::ConstantDeclaration),
    Brand(&'a syntax::BrandDeclaration),
    Function(&'a syntax::FunctionDeclaration),
    Initializer(&'a syntax::InitializerDeclaration),
    Structure(&'a syntax::TypeDeclaration),
    Enumeration(&'a syntax::EnumDeclaration),
    Interface(&'a syntax::InterfaceDeclaration),
    Implementation(&'a syntax::ImplementationDeclaration),
    Projection(&'a syntax::ProjectionDeclaration),
    Scope(&'a syntax::ScopeDeclaration),
    ComptimeDeclaration(&'a syntax::ComptimeDeclarationIf),
    ComptimeMember(&'a syntax::ComptimeMemberIf),
    Error,
}

#[derive(Debug, Clone)]
struct DeclarationPlan<'a> {
    syntax: DeclarationSyntax<'a>,
    attributes: &'a [syntax::Attribute],
    recover_as_error: bool,
}

#[derive(Debug, Clone, Default)]
struct DeclarationHeader {
    generics: Vec<hir::GenericParameterId>,
    parameters: Vec<hir::ParameterId>,
    children: Vec<hir::DeclarationId>,
    then_count: usize,
    exit_parameter: Option<hir::ParameterId>,
    variants: Vec<VariantHeader>,
}

#[derive(Debug, Clone)]
struct VariantHeader {
    name: hir::Name,
    variant: u32,
    source: Span,
}

#[derive(Debug, Clone)]
struct OwnedVisibleBinding {
    name: hir::Name,
    target: ResolutionTarget,
    kind: BindingKind,
}

#[derive(Debug, Clone)]
struct BodyContext {
    body: hir::BodyId,
    scope: hir::ScopeId,
    owner_declaration: hir::DeclarationId,
    visible: Vec<OwnedVisibleBinding>,
}

#[derive(Debug)]
struct CaptureFrame {
    first_parameter: u32,
    first_local: u32,
    captures: Vec<hir::Definition>,
}

#[derive(Debug, Clone, Copy)]
struct ClosureSyntax<'a> {
    asynchronous: bool,
    take_captures: bool,
    parameters: &'a [syntax::Parameter],
    body: &'a syntax::ClosureBody,
}

#[derive(Debug, Clone, Copy)]
struct ExpressionContext {
    owner: hir::ExpressionOwner,
    scope: Option<hir::ScopeId>,
    declaration: hir::DeclarationId,
}

#[derive(Debug, Clone)]
enum ResolutionTarget {
    Definition(hir::Definition),
    Region(hir::RegionReference),
}

#[derive(Debug, Clone)]
struct NameResolution {
    target: ResolutionTarget,
    kind: BindingKind,
    binding: ResolvedBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedArgument {
    Type,
    Constant,
    Region,
    Capacity,
}

struct LoweringSession<'a, 'request> {
    request: &'request LowerRequest<'a>,
    is_cancelled: &'request dyn Fn() -> bool,
    program: hir::Program,
    plans: Vec<DeclarationPlan<'a>>,
    headers: Vec<DeclarationHeader>,
    symbols: Vec<Symbol>,
    named_imports: Vec<NamedImport>,
    /// Ambient prelude bindings installed for every module after ordinary
    /// imports and module symbols, so an import or module-scope declaration
    /// may shadow them.
    prelude_bindings: Vec<NamedImport>,
    module_imports: Vec<ModuleImport>,
    import_edges: Vec<Vec<ModuleId>>,
    uses: Vec<ResolvedUse>,
    diagnostics: Vec<Diagnostic>,
    body_stack: Vec<BodyContext>,
    lexical_overrides: Vec<OwnedVisibleBinding>,
    capture_stack: Vec<CaptureFrame>,
}

impl<'a, 'request> LoweringSession<'a, 'request> {
    fn new(
        request: &'request LowerRequest<'a>,
        is_cancelled: &'request dyn Fn() -> bool,
    ) -> Result<Self, LowerFailure> {
        let module_capacity = request.packages.modules().len();
        let mut import_edges = Vec::new();
        reserve(
            &mut import_edges,
            module_capacity,
            "module import graph",
            request.limits.modules,
        )?;
        for _ in 0..module_capacity {
            push(
                &mut import_edges,
                Vec::new(),
                "module import graph",
                request.limits.modules,
            )?;
        }
        Ok(Self {
            request,
            is_cancelled,
            program: hir::Program {
                packages: Arc::clone(&request.packages),
                modules: Vec::new(),
                declarations: Vec::new(),
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
            plans: Vec::new(),
            headers: Vec::new(),
            symbols: Vec::new(),
            named_imports: Vec::new(),
            prelude_bindings: Vec::new(),
            module_imports: Vec::new(),
            import_edges,
            uses: Vec::new(),
            diagnostics: Vec::new(),
            body_stack: Vec::new(),
            lexical_overrides: Vec::new(),
            capture_stack: Vec::new(),
        })
    }

    fn finish(mut self) -> Result<(LoweredProgramCandidate, Vec<Diagnostic>), LowerFailure> {
        poll_cancellation(self.is_cancelled)?;
        self.uses.sort_by(compare_use);
        self.uses
            .dedup_by(|left, right| compare_use(left, right) == Ordering::Equal);
        let mut summaries = Vec::new();
        reserve(
            &mut summaries,
            self.program.modules.len(),
            "module summaries",
            self.request.limits.modules,
        )?;
        for module in &self.program.modules {
            poll_cancellation(self.is_cancelled)?;
            let graph_module = &self.request.packages.modules()[module.id.0 as usize];
            let parsed = &self.request.parsed_files[graph_module.source.0 as usize];
            let mut declarations = Vec::new();
            reserve(
                &mut declarations,
                module.declarations.len(),
                "module summary declarations",
                self.request.limits.declarations,
            )?;
            declarations.extend_from_slice(&module.declarations);
            let mut resolved = 0u64;
            let mut errors = 0u64;
            for use_record in &self.uses {
                if use_record.source.file == graph_module.source {
                    if use_record.kind == BindingKind::Error {
                        errors = errors.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                            resource: "resolved uses",
                            limit: self.request.limits.resolved_uses,
                        })?;
                    } else {
                        resolved = resolved.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                            resource: "resolved uses",
                            limit: self.request.limits.resolved_uses,
                        })?;
                    }
                }
            }
            push(
                &mut summaries,
                ModuleResolutionSummary {
                    module: module.id,
                    declarations,
                    imports: u32::try_from(parsed.ast().imports.len()).map_err(|_| {
                        LowerFailure::ResourceLimit {
                            resource: "module imports",
                            limit: u64::from(self.request.limits.modules),
                        }
                    })?,
                    resolved_uses: resolved,
                    error_uses: errors,
                    reused_from_previous_revision: false,
                },
                "module summaries",
                self.request.limits.modules,
            )?;
        }
        Ok((
            LoweredProgramCandidate {
                program: self.program,
                uses: self.uses,
                modules: summaries,
                source_graph_digest: self.request.source_graph_digest,
            },
            self.diagnostics,
        ))
    }

    fn emit(
        &mut self,
        code: &'static str,
        primary: Span,
        message: &'static str,
    ) -> Result<(), LowerFailure> {
        if self.diagnostics.len() >= self.request.limits.diagnostics as usize {
            return Err(LowerFailure::ResourceLimit {
                resource: "diagnostics",
                limit: u64::from(self.request.limits.diagnostics),
            });
        }
        let mut diagnostic = Diagnostic::error(
            Category::NAME,
            primary,
            clone_text(message, self.request.limits.diagnostic_bytes)?,
        );
        diagnostic.code = Some(clone_text(code, self.request.limits.diagnostic_bytes)?);
        push(
            &mut self.diagnostics,
            diagnostic,
            "diagnostics",
            self.request.limits.diagnostics,
        )
    }

    fn name(&self, identifier: &syntax::Identifier) -> Result<hir::Name, LowerFailure> {
        let spelling = clone_text(&identifier.spelling, self.request.limits.payload_bytes)?;
        hir::Name::new(spelling).map_err(|_| {
            LowerFailure::InternalInvariant(
                "validated syntax contained a non-source identifier".to_owned(),
            )
        })
    }

    fn call_argument_name(
        &self,
        identifier: &syntax::Identifier,
    ) -> Result<hir::Name, LowerFailure> {
        let spelling = clone_text(&identifier.spelling, self.request.limits.payload_bytes)?;
        hir::Name::new_argument_label(spelling).map_err(|_| {
            LowerFailure::InternalInvariant(
                "validated syntax contained an invalid call argument label".to_owned(),
            )
        })
    }

    fn collect_modules(&mut self) -> Result<(), LowerFailure> {
        reserve(
            &mut self.program.modules,
            self.request.packages.modules().len(),
            "modules",
            self.request.limits.modules,
        )?;
        for graph_module in self.request.packages.modules() {
            poll_cancellation(self.is_cancelled)?;
            let parsed = self
                .request
                .parsed_files
                .get(graph_module.source.0 as usize)
                .ok_or(LowerFailure::MissingParsedFile(graph_module.source))?;
            let module_matches = parsed.ast().module.as_ref().is_some_and(|declaration| {
                declaration.path.segments.len() == graph_module.path.segments().len()
                    && declaration
                        .path
                        .segments
                        .iter()
                        .zip(graph_module.path.segments())
                        .all(|(left, right)| left.spelling == *right)
            });
            if !module_matches {
                let span = parsed
                    .ast()
                    .module
                    .as_ref()
                    .map_or(parsed.ast().meta.span, |module| module.meta.span);
                self.emit(
                    "hir-module-path-mismatch",
                    span,
                    "the source module declaration does not match its declared package module path",
                )?;
            }
            push(
                &mut self.program.modules,
                hir::Module {
                    id: graph_module.id,
                    package: graph_module.package,
                    path: graph_module.path.clone(),
                    declarations: Vec::new(),
                    reexports: Vec::new(),
                    source: parsed.ast().meta.span,
                },
                "modules",
                self.request.limits.modules,
            )?;
        }
        Ok(())
    }

    fn collect_declarations(&mut self) -> Result<(), LowerFailure> {
        for module_index in 0..self.request.packages.modules().len() {
            poll_cancellation(self.is_cancelled)?;
            let graph_module = &self.request.packages.modules()[module_index];
            let parsed = &self.request.parsed_files[graph_module.source.0 as usize];
            for declaration in &parsed.ast().declarations {
                let id = self.predeclare_top(graph_module.id, declaration)?;
                push(
                    &mut self.program.modules[module_index].declarations,
                    id,
                    "module declarations",
                    self.request.limits.declarations,
                )?;
            }
        }
        self.symbols.sort_by(|left, right| {
            (left.owner, left.name.as_str()).cmp(&(right.owner, right.name.as_str()))
        });
        Ok(())
    }

    fn predeclare_top(
        &mut self,
        module: ModuleId,
        declaration: &'a syntax::TopLevelDeclaration,
    ) -> Result<hir::DeclarationId, LowerFailure> {
        let syntax = match &declaration.kind {
            syntax::DeclarationKind::Constant(value) => DeclarationSyntax::Constant(value),
            syntax::DeclarationKind::Brand(value) => DeclarationSyntax::Brand(value),
            syntax::DeclarationKind::Function(value) => DeclarationSyntax::Function(value),
            syntax::DeclarationKind::Structure(value) => DeclarationSyntax::Structure(value),
            syntax::DeclarationKind::Enumeration(value) => DeclarationSyntax::Enumeration(value),
            syntax::DeclarationKind::Interface(value) => DeclarationSyntax::Interface(value),
            syntax::DeclarationKind::Implementation(value) => {
                DeclarationSyntax::Implementation(value)
            }
            syntax::DeclarationKind::Projection(value) => DeclarationSyntax::Projection(value),
            syntax::DeclarationKind::Scope(value) => DeclarationSyntax::Scope(value),
            syntax::DeclarationKind::ComptimeIf(value) => {
                DeclarationSyntax::ComptimeDeclaration(value)
            }
            syntax::DeclarationKind::Error(_) => DeclarationSyntax::Error,
        };
        self.predeclare(
            module,
            hir::DeclarationOwner::Module(module),
            declaration.public,
            &declaration.attributes,
            declaration.meta.span,
            syntax,
        )
    }

    fn predeclare_member(
        &mut self,
        module: ModuleId,
        owner: hir::DeclarationId,
        member: &'a syntax::MemberDeclaration,
    ) -> Result<Option<hir::DeclarationId>, LowerFailure> {
        let syntax = match &member.kind {
            syntax::MemberKind::Field(_) => return Ok(None),
            syntax::MemberKind::Function(value) => DeclarationSyntax::Function(value),
            syntax::MemberKind::Initializer(value) => DeclarationSyntax::Initializer(value),
            syntax::MemberKind::Projection(value) => DeclarationSyntax::Projection(value),
            syntax::MemberKind::Scope(value) => DeclarationSyntax::Scope(value),
            syntax::MemberKind::Constant(value) => DeclarationSyntax::Constant(value),
            syntax::MemberKind::ComptimeIf(value) => DeclarationSyntax::ComptimeMember(value),
            syntax::MemberKind::Error(_) => DeclarationSyntax::Error,
        };
        let is_initializer = matches!(syntax, DeclarationSyntax::Initializer(_));
        self.predeclare(
            module,
            hir::DeclarationOwner::Declaration(owner),
            if is_initializer { false } else { member.public },
            if is_initializer {
                &[]
            } else {
                &member.attributes
            },
            member.meta.span,
            syntax,
        )
        .map(Some)
    }

    fn predeclare_interface_member(
        &mut self,
        module: ModuleId,
        owner: hir::DeclarationId,
        member: &'a syntax::InterfaceMember,
    ) -> Result<hir::DeclarationId, LowerFailure> {
        match member {
            syntax::InterfaceMember::Function {
                attributes,
                declaration,
            } => self.predeclare(
                module,
                hir::DeclarationOwner::Declaration(owner),
                true,
                attributes,
                declaration_source_with_attributes(declaration.meta.span, attributes),
                DeclarationSyntax::Function(declaration),
            ),
            syntax::InterfaceMember::Projection {
                attributes,
                declaration,
            } => self.predeclare(
                module,
                hir::DeclarationOwner::Declaration(owner),
                true,
                attributes,
                declaration_source_with_attributes(declaration.meta.span, attributes),
                DeclarationSyntax::Projection(declaration),
            ),
            syntax::InterfaceMember::Error(error) => self.predeclare(
                module,
                hir::DeclarationOwner::Declaration(owner),
                false,
                &[],
                error.meta.span,
                DeclarationSyntax::Error,
            ),
        }
    }

    fn predeclare(
        &mut self,
        module: ModuleId,
        owner: hir::DeclarationOwner,
        public: bool,
        attributes: &'a [syntax::Attribute],
        source: Span,
        syntax: DeclarationSyntax<'a>,
    ) -> Result<hir::DeclarationId, LowerFailure> {
        poll_cancellation(self.is_cancelled)?;
        let id =
            hir::DeclarationId(u32::try_from(self.program.declarations.len()).map_err(|_| {
                LowerFailure::ResourceLimit {
                    resource: "declarations",
                    limit: u64::from(self.request.limits.declarations),
                }
            })?);
        let identifier = declaration_identifier(syntax);
        let mut name = identifier
            .map(|identifier| self.name(identifier))
            .transpose()?;
        let symbol_owner = match owner {
            hir::DeclarationOwner::Module(module) => SymbolOwner::Module(module),
            hir::DeclarationOwner::Declaration(owner) => SymbolOwner::Declaration(owner),
        };
        let duplicate = name.as_ref().is_some_and(|name| {
            self.symbols
                .iter()
                .any(|symbol| symbol.owner == symbol_owner && symbol.name == *name)
        });
        let recover_as_error = matches!(syntax, DeclarationSyntax::Error) || duplicate;
        if duplicate {
            self.emit(
                "hir-duplicate-declaration",
                identifier.map_or(source, |identifier| identifier.meta.span),
                "this declaration duplicates a name in the same source namespace",
            )?;
            name = None;
        }
        let package = self.program.modules[module.0 as usize].package;
        if let Some(symbol_name) = name.clone() {
            push(
                &mut self.symbols,
                Symbol {
                    owner: symbol_owner,
                    name: symbol_name,
                    target: SymbolTarget::Declaration(hir::ResolvedDeclaration {
                        package,
                        module,
                        declaration: id,
                    }),
                },
                "declaration symbols",
                self.request.limits.declarations,
            )?;
        }
        push(
            &mut self.program.declarations,
            hir::Declaration {
                id,
                module,
                owner,
                name,
                visibility: if public && !recover_as_error {
                    hir::Visibility::Public
                } else {
                    hir::Visibility::Private
                },
                attributes: Vec::new(),
                kind: hir::DeclarationKind::Error,
                source,
            },
            "declarations",
            self.request.limits.declarations,
        )?;
        push(
            &mut self.plans,
            DeclarationPlan {
                syntax,
                attributes,
                recover_as_error,
            },
            "declaration plans",
            self.request.limits.declarations,
        )?;
        push(
            &mut self.headers,
            DeclarationHeader::default(),
            "declaration headers",
            self.request.limits.declarations,
        )?;

        if recover_as_error {
            return Ok(id);
        }

        let mut children = Vec::new();
        let mut then_count = 0usize;
        match syntax {
            DeclarationSyntax::Structure(value) => {
                for member in &value.members {
                    if let Some(child) = self.predeclare_member(module, id, member)? {
                        push(
                            &mut children,
                            child,
                            "nested declarations",
                            self.request.limits.declarations,
                        )?;
                    }
                }
            }
            DeclarationSyntax::Interface(value) => {
                for member in &value.members {
                    let child = self.predeclare_interface_member(module, id, member)?;
                    push(
                        &mut children,
                        child,
                        "interface requirements",
                        self.request.limits.declarations,
                    )?;
                }
            }
            DeclarationSyntax::Implementation(value) => {
                for member in &value.members {
                    if let Some(child) = self.predeclare_member(module, id, member)? {
                        push(
                            &mut children,
                            child,
                            "implementation members",
                            self.request.limits.declarations,
                        )?;
                    }
                }
            }
            DeclarationSyntax::ComptimeDeclaration(value) => {
                for declaration in &value.then_declarations {
                    let child_syntax = top_syntax(declaration);
                    let child = self.predeclare(
                        module,
                        hir::DeclarationOwner::Declaration(id),
                        declaration.public,
                        &declaration.attributes,
                        declaration.meta.span,
                        child_syntax,
                    )?;
                    push(
                        &mut children,
                        child,
                        "comptime declarations",
                        self.request.limits.declarations,
                    )?;
                }
                then_count = children.len();
                for declaration in &value.else_declarations {
                    let child_syntax = top_syntax(declaration);
                    let child = self.predeclare(
                        module,
                        hir::DeclarationOwner::Declaration(id),
                        declaration.public,
                        &declaration.attributes,
                        declaration.meta.span,
                        child_syntax,
                    )?;
                    push(
                        &mut children,
                        child,
                        "comptime declarations",
                        self.request.limits.declarations,
                    )?;
                }
            }
            DeclarationSyntax::ComptimeMember(value) => {
                for member in &value.then_members {
                    if let Some(child) = self.predeclare_member(module, id, member)? {
                        push(
                            &mut children,
                            child,
                            "comptime members",
                            self.request.limits.declarations,
                        )?;
                    }
                }
                then_count = children.len();
                for member in &value.else_members {
                    if let Some(child) = self.predeclare_member(module, id, member)? {
                        push(
                            &mut children,
                            child,
                            "comptime members",
                            self.request.limits.declarations,
                        )?;
                    }
                }
            }
            DeclarationSyntax::Enumeration(value) => {
                let mut variants = Vec::new();
                for variant in &value.variants {
                    let name = self.name(&variant.name)?;
                    if variants
                        .iter()
                        .any(|header: &VariantHeader| header.name == name)
                    {
                        self.emit(
                            "hir-duplicate-variant",
                            variant.name.meta.span,
                            "this enum variant duplicates an earlier variant",
                        )?;
                        continue;
                    }
                    let variant_index =
                        u32::try_from(variants.len()).map_err(|_| LowerFailure::ResourceLimit {
                            resource: "enum variants",
                            limit: u64::from(self.request.limits.declarations),
                        })?;
                    push(
                        &mut variants,
                        VariantHeader {
                            name: name.clone(),
                            variant: variant_index,
                            source: variant.meta.span,
                        },
                        "enum variants",
                        self.request.limits.declarations,
                    )?;
                    push(
                        &mut self.symbols,
                        Symbol {
                            owner: SymbolOwner::Declaration(id),
                            name,
                            target: SymbolTarget::Variant(hir::ResolvedVariant {
                                enumeration: hir::ResolvedDeclaration {
                                    package,
                                    module,
                                    declaration: id,
                                },
                                variant: variant_index,
                            }),
                        },
                        "variant symbols",
                        self.request.limits.declarations,
                    )?;
                }
                self.headers[id.0 as usize].variants = variants;
            }
            DeclarationSyntax::Constant(_)
            | DeclarationSyntax::Brand(_)
            | DeclarationSyntax::Function(_)
            | DeclarationSyntax::Initializer(_)
            | DeclarationSyntax::Projection(_)
            | DeclarationSyntax::Scope(_)
            | DeclarationSyntax::Error => {}
        }
        self.headers[id.0 as usize].children = children;
        self.headers[id.0 as usize].then_count = then_count;
        Ok(id)
    }

    fn collect_headers(&mut self) -> Result<(), LowerFailure> {
        let declaration_count = self.plans.len();
        for index in 0..declaration_count {
            poll_cancellation(self.is_cancelled)?;
            self.collect_one_header(index)?;
        }
        Ok(())
    }

    fn collect_headers_reusing(
        &mut self,
        previous: &LowerOutput,
        reusable_files: &BTreeSet<wrela_source::FileId>,
        meter: &mut HirReuseMeter<'_>,
    ) -> Result<(), LowerFailure> {
        for index in 0..self.plans.len() {
            poll_cancellation(self.is_cancelled)?;
            let declaration = self
                .program
                .declarations
                .get(index)
                .ok_or(LowerFailure::InvalidChangeSet)?;
            let source = self
                .request
                .packages
                .modules()
                .get(declaration.module.0 as usize)
                .ok_or(LowerFailure::InvalidChangeSet)?
                .source;
            if reusable_files.contains(&source) {
                self.reuse_declaration_header(hir::DeclarationId(index as u32), previous, meter)?;
            } else {
                self.collect_one_header(index)?;
            }
        }
        Ok(())
    }

    fn collect_one_header(&mut self, index: usize) -> Result<(), LowerFailure> {
        let id = hir::DeclarationId(index as u32);
        if self.plans[index].recover_as_error {
            return Ok(());
        }
        let syntax = self.plans[index].syntax;
        let generics = syntax_generics(syntax);
        for generic in generics {
            let (meta, identifier, kind) = match generic {
                syntax::GenericParameter::Type { meta, name, .. } => {
                    (*meta, name, hir::GenericParameterKind::Type { bound: None })
                }
                syntax::GenericParameter::Constant { meta, name, .. } => (
                    *meta,
                    name,
                    hir::GenericParameterKind::Constant {
                        ty: hir::TypeExpression {
                            kind: hir::TypeExpressionKind::Error,
                            source: meta.span,
                        },
                    },
                ),
                syntax::GenericParameter::Region { meta, name } => {
                    (*meta, name, hir::GenericParameterKind::Region)
                }
            };
            let name = self.name(identifier)?;
            let duplicate = self.headers[index]
                .generics
                .iter()
                .any(|generic| self.program.generic_parameters[generic.0 as usize].name == name);
            if duplicate {
                self.emit(
                    "hir-duplicate-generic-parameter",
                    identifier.meta.span,
                    "this generic parameter duplicates an earlier parameter",
                )?;
                continue;
            }
            let generic_id = hir::GenericParameterId(
                u32::try_from(self.program.generic_parameters.len()).map_err(|_| {
                    LowerFailure::ResourceLimit {
                        resource: "generic parameters",
                        limit: u64::from(self.request.limits.generic_parameters),
                    }
                })?,
            );
            push(
                &mut self.program.generic_parameters,
                hir::GenericParameter {
                    id: generic_id,
                    owner: id,
                    name,
                    kind,
                    source: meta.span,
                },
                "generic parameters",
                self.request.limits.generic_parameters,
            )?;
            push(
                &mut self.headers[index].generics,
                generic_id,
                "declaration generics",
                self.request.limits.generic_parameters,
            )?;
        }

        for parameter in syntax_parameters(syntax) {
            self.predeclare_parameter(id, parameter)?;
        }
        if let DeclarationSyntax::Scope(scope) = syntax {
            let name = self.name(&scope.exit_binding)?;
            if self.headers[index].parameters.iter().any(|parameter| {
                self.program.parameters[parameter.0 as usize].name.as_ref() == Some(&name)
            }) {
                self.emit(
                    "hir-duplicate-scope-exit-binding",
                    scope.exit_binding.meta.span,
                    "the scope exit binding duplicates a scope parameter",
                )?;
            } else {
                let parameter = self.allocate_parameter(
                    id,
                    Some(name),
                    hir::AccessMode::Value,
                    Some(hir::TypeExpression {
                        kind: hir::TypeExpressionKind::Error,
                        source: scope.exit_binding.meta.span,
                    }),
                    false,
                    false,
                    scope.exit_binding.meta.span,
                )?;
                push(
                    &mut self.headers[index].parameters,
                    parameter,
                    "declaration parameters",
                    self.request.limits.parameters,
                )?;
                self.headers[index].exit_parameter = Some(parameter);
            }
        }
        Ok(())
    }

    fn reuse_declaration_header(
        &mut self,
        declaration: hir::DeclarationId,
        previous: &LowerOutput,
        meter: &mut HirReuseMeter<'_>,
    ) -> Result<(), LowerFailure> {
        let previous_program = previous.lowered.program.as_program();
        for record in previous_program
            .generic_parameters
            .iter()
            .filter(|record| record.owner == declaration)
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.generic_parameters,
                record.id.0,
                record,
                "reused generic parameter headers",
                self.request.limits.generic_parameters,
            )?;
            push(
                &mut self.headers[declaration.0 as usize].generics,
                record.id,
                "reused declaration generics",
                self.request.limits.generic_parameters,
            )?;
        }
        for record in previous_program.parameters.iter().filter(|record| {
            matches!(
                record.owner,
                hir::CallableOwner::Declaration(owner) if owner == declaration
            )
        }) {
            meter.poll()?;
            install_reused_record(
                &mut self.program.parameters,
                record.id.0,
                record,
                "reused parameter headers",
                self.request.limits.parameters,
            )?;
            push(
                &mut self.headers[declaration.0 as usize].parameters,
                record.id,
                "reused declaration parameters",
                self.request.limits.parameters,
            )?;
        }
        if let Some(prior) = previous_program.declarations.get(declaration.0 as usize) {
            if let hir::DeclarationKind::Scope(scope) = &prior.kind {
                self.headers[declaration.0 as usize].exit_parameter = Some(scope.exit_parameter);
            }
        }
        Ok(())
    }

    fn predeclare_parameter(
        &mut self,
        owner: hir::DeclarationId,
        parameter: &syntax::Parameter,
    ) -> Result<(), LowerFailure> {
        let owner_index = owner.0 as usize;
        if parameter.receiver {
            let receiver_legal = matches!(
                self.program.declarations[owner_index].owner,
                hir::DeclarationOwner::Declaration(parent)
                    if matches!(
                        self.plans[parent.0 as usize].syntax,
                        DeclarationSyntax::Structure(_)
                            | DeclarationSyntax::Enumeration(_)
                            | DeclarationSyntax::Interface(_)
                            | DeclarationSyntax::Implementation(_)
                    )
            ) && self.headers[owner_index].parameters.is_empty();
            if !receiver_legal {
                self.emit(
                    "hir-invalid-receiver",
                    parameter.meta.span,
                    "a receiver is only legal as the first parameter of a nested callable declaration",
                )?;
                return Ok(());
            }
            let id = self.allocate_parameter(
                owner,
                None,
                lower_access(parameter.access),
                None,
                true,
                false,
                parameter.meta.span,
            )?;
            push(
                &mut self.headers[owner_index].parameters,
                id,
                "declaration parameters",
                self.request.limits.parameters,
            )?;
            return Ok(());
        }
        let name = self.name(&parameter.name)?;
        if self.headers[owner_index]
            .parameters
            .iter()
            .any(|id| self.program.parameters[id.0 as usize].name.as_ref() == Some(&name))
        {
            self.emit(
                "hir-duplicate-parameter",
                parameter.name.meta.span,
                "this callable parameter duplicates an earlier parameter",
            )?;
            return Ok(());
        }
        let ty = parameter.ty.as_ref().map_or_else(
            || {
                self.emit(
                    "hir-missing-parameter-type",
                    parameter.meta.span,
                    "ordinary parameters require an explicit type",
                )?;
                Ok(hir::TypeExpression {
                    kind: hir::TypeExpressionKind::Error,
                    source: parameter.meta.span,
                })
            },
            |ty| {
                Ok(hir::TypeExpression {
                    kind: hir::TypeExpressionKind::Error,
                    source: ty.meta.span,
                })
            },
        )?;
        let id = self.allocate_parameter(
            owner,
            Some(name),
            lower_access(parameter.access),
            Some(ty),
            false,
            parameter.positional_only,
            parameter.meta.span,
        )?;
        push(
            &mut self.headers[owner_index].parameters,
            id,
            "declaration parameters",
            self.request.limits.parameters,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate_parameter(
        &mut self,
        owner: hir::DeclarationId,
        name: Option<hir::Name>,
        access: hir::AccessMode,
        ty: Option<hir::TypeExpression>,
        receiver: bool,
        positional_only: bool,
        source: Span,
    ) -> Result<hir::ParameterId, LowerFailure> {
        let id = hir::ParameterId(u32::try_from(self.program.parameters.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "parameters",
                limit: u64::from(self.request.limits.parameters),
            }
        })?);
        push(
            &mut self.program.parameters,
            hir::Parameter {
                id,
                owner: hir::CallableOwner::Declaration(owner),
                name,
                access,
                ty,
                receiver,
                positional_only,
                source,
            },
            "parameters",
            self.request.limits.parameters,
        )?;
        Ok(id)
    }

    fn resolve_imports(&mut self) -> Result<(), LowerFailure> {
        // Module imports do not depend on exported symbols. Install all of
        // them first so a module reexport is visible independent of canonical
        // module ordering.
        let mut pending_named = Vec::new();
        for module_index in 0..self.program.modules.len() {
            poll_cancellation(self.is_cancelled)?;
            let module_id = ModuleId(module_index as u32);
            let graph_module = &self.request.packages.modules()[module_index];
            let parsed = &self.request.parsed_files[graph_module.source.0 as usize];
            for import in &parsed.ast().imports {
                match &import.items {
                    syntax::ImportItems::Module { path, alias } => {
                        self.resolve_module_import(
                            module_id,
                            graph_module.package,
                            import,
                            path,
                            alias.as_ref(),
                        )?;
                    }
                    syntax::ImportItems::Names { module, names, .. } => {
                        let Some((_, target_module)) =
                            self.import_module_target(graph_module.package, module)?
                        else {
                            self.emit(
                                "hir-unknown-import-module",
                                module.meta.span,
                                "this from-import does not name a declared module in the package graph",
                            )?;
                            continue;
                        };
                        self.add_import_edge(module_id, target_module)?;
                        let target_package = self.program.modules[target_module.0 as usize].package;
                        self.record_module_path_use(module, target_package, target_module)?;
                        for imported in names {
                            push64(
                                &mut pending_named,
                                PendingNamedImport {
                                    module: module_id,
                                    target_module,
                                    public: import.public,
                                    imported,
                                },
                                "pending named imports",
                                self.request.limits.resolved_uses,
                            )?;
                        }
                    }
                }
            }
        }
        self.resolve_pending_named_imports(&pending_named)?;
        self.inject_fixed_prelude()?;
        self.named_imports.sort_by(|left, right| {
            (
                left.module,
                left.local_name.as_str(),
                left.source.range.start,
            )
                .cmp(&(
                    right.module,
                    right.local_name.as_str(),
                    right.source.range.start,
                ))
        });
        self.module_imports.sort_by(|left, right| {
            left.module
                .cmp(&right.module)
                .then_with(|| {
                    left.local_path
                        .iter()
                        .map(hir::Name::as_str)
                        .cmp(right.local_path.iter().map(hir::Name::as_str))
                })
                .then_with(|| left.source.range.start.cmp(&right.source.range.start))
        });
        for module in &mut self.program.modules {
            module.reexports.sort_by(|left, right| {
                (left.local_name.as_str(), left.source.range.start)
                    .cmp(&(right.local_name.as_str(), right.source.range.start))
            });
        }
        Ok(())
    }

    fn inject_fixed_prelude(&mut self) -> Result<(), LowerFailure> {
        const PRELUDE_NAMES: &[&str] = &["Option", "Some", "None", "Result", "Ok", "Err", "panic"];
        let mut core_packages = Vec::new();
        for package in self.request.packages.packages() {
            poll_cancellation(self.is_cancelled)?;
            if package.identity.name.as_str() == "wrela-core" {
                push64(
                    &mut core_packages,
                    package.id,
                    "prelude core packages",
                    self.request.limits.resolved_uses,
                )?;
            }
        }
        if core_packages.is_empty() {
            return Ok(());
        }

        let mut targets = Vec::new();
        for symbol in &self.symbols {
            poll_cancellation(self.is_cancelled)?;
            if !PRELUDE_NAMES.contains(&symbol.name.as_str()) {
                continue;
            }
            let package = match &symbol.target {
                SymbolTarget::Declaration(resolved) => resolved.package,
                SymbolTarget::Variant(resolved) => resolved.enumeration.package,
            };
            if !core_packages.contains(&package) {
                continue;
            }
            push64(
                &mut targets,
                (symbol.name.clone(), symbol.target.clone()),
                "prelude targets",
                self.request.limits.resolved_uses,
            )?;
        }
        if targets.is_empty() {
            return Ok(());
        }

        let module_count = self.program.modules.len();
        for module_index in 0..module_count {
            poll_cancellation(self.is_cancelled)?;
            let module = ModuleId(module_index as u32);
            let source = self.program.modules[module_index].source;
            for (name, target) in &targets {
                poll_cancellation(self.is_cancelled)?;
                let shadowed = self.named_imports.iter().any(|binding| {
                    binding.module == module && binding.local_name.as_str() == name.as_str()
                }) || self.symbols.iter().any(|symbol| {
                    symbol.owner == SymbolOwner::Module(module)
                        && symbol.name.as_str() == name.as_str()
                });
                if shadowed {
                    continue;
                }
                push64(
                    &mut self.prelude_bindings,
                    NamedImport {
                        module,
                        local_name: name.clone(),
                        target: target.clone(),
                        source,
                    },
                    "prelude bindings",
                    self.request.limits.resolved_uses,
                )?;
            }
        }
        self.prelude_bindings.sort_by(|left, right| {
            (
                left.module,
                left.local_name.as_str(),
                left.source.range.start,
            )
                .cmp(&(
                    right.module,
                    right.local_name.as_str(),
                    right.source.range.start,
                ))
        });
        Ok(())
    }

    fn resolve_module_import(
        &mut self,
        module: ModuleId,
        current_package: PackageId,
        import: &syntax::ImportDeclaration,
        path: &syntax::QualifiedName,
        alias: Option<&syntax::Identifier>,
    ) -> Result<(), LowerFailure> {
        let Some((package, target_module)) = self.import_module_target(current_package, path)?
        else {
            self.emit(
                "hir-unknown-import-module",
                path.meta.span,
                "this import does not name a declared module in the package graph",
            )?;
            return Ok(());
        };
        self.add_import_edge(module, target_module)?;
        self.record_module_path_use(path, package, target_module)?;
        let mut local_path = Vec::new();
        if let Some(alias) = alias {
            push(
                &mut local_path,
                self.name(alias)?,
                "module import path",
                self.request.limits.modules,
            )?;
        } else {
            reserve(
                &mut local_path,
                path.segments.len(),
                "module import path",
                self.request.limits.modules,
            )?;
            for segment in &path.segments {
                push(
                    &mut local_path,
                    self.name(segment)?,
                    "module import path",
                    self.request.limits.modules,
                )?;
            }
        }
        let local_name = local_path.first().cloned().ok_or_else(|| {
            LowerFailure::InternalInvariant("validated module import had an empty path".to_owned())
        })?;
        if self.import_name_conflicts(module, &local_name) {
            self.emit(
                "hir-import-name-conflict",
                alias.map_or(path.meta.span, |alias| alias.meta.span),
                "this module import conflicts with another name in the module",
            )?;
            return Ok(());
        }
        push64(
            &mut self.module_imports,
            ModuleImport {
                module,
                local_path,
                target_package: package,
                target_module,
                source: import.meta.span,
            },
            "module imports",
            self.request.limits.resolved_uses,
        )?;
        if import.public {
            self.add_reexport(
                module,
                local_name,
                hir::ReexportTarget::Module {
                    package,
                    module: target_module,
                },
                import.meta.span,
            )?;
        }
        Ok(())
    }

    fn resolve_pending_named_imports(
        &mut self,
        pending: &[PendingNamedImport<'a>],
    ) -> Result<(), LowerFailure> {
        let mut resolved = Vec::new();
        resolved
            .try_reserve_exact(pending.len())
            .map_err(|_| LowerFailure::ResourceLimit {
                resource: "pending named imports",
                limit: self.request.limits.resolved_uses,
            })?;
        resolved.resize(pending.len(), false);
        let mut remaining = pending.len();
        let mut work = 0u64;
        while remaining != 0 {
            poll_cancellation(self.is_cancelled)?;
            let mut exports_added = false;
            for (index, task) in pending.iter().enumerate() {
                if resolved[index] {
                    continue;
                }
                work = work.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                    resource: "import resolution work",
                    limit: self.request.limits.model_edges,
                })?;
                if work > self.request.limits.model_edges {
                    return Err(LowerFailure::ResourceLimit {
                        resource: "import resolution work",
                        limit: self.request.limits.model_edges,
                    });
                }
                poll_cancellation(self.is_cancelled)?;
                let imported_name = self.name(&task.imported.name)?;
                let matches = self.exported_namespaces(task.target_module, &imported_name)?;
                let target = match matches.as_slice() {
                    [] => continue,
                    [target] => target.clone(),
                    _ => {
                        self.emit(
                            "hir-ambiguous-import-name",
                            task.imported.name.meta.span,
                            "this imported name is ambiguous in its source module",
                        )?;
                        self.record_error_use(&task.imported.name)?;
                        resolved[index] = true;
                        remaining -= 1;
                        continue;
                    }
                };
                exports_added |= self.install_named_import(*task, imported_name, target)?;
                resolved[index] = true;
                remaining -= 1;
            }
            if remaining == 0 {
                break;
            }
            if !exports_added {
                for (index, task) in pending.iter().enumerate() {
                    if resolved[index] {
                        continue;
                    }
                    self.emit(
                        "hir-unknown-import-name",
                        task.imported.name.meta.span,
                        "the imported module has no public declaration, variant, or module with this name",
                    )?;
                    self.record_error_use(&task.imported.name)?;
                }
                break;
            }
        }
        Ok(())
    }

    fn install_named_import(
        &mut self,
        task: PendingNamedImport<'a>,
        imported_name: hir::Name,
        target: NamespaceTarget,
    ) -> Result<bool, LowerFailure> {
        let local_name = task
            .imported
            .alias
            .as_ref()
            .map_or_else(|| Ok(imported_name), |alias| self.name(alias))?;
        if self.import_name_conflicts(task.module, &local_name) {
            self.emit(
                "hir-import-name-conflict",
                task.imported.meta.span,
                "this imported name conflicts with another name in the module",
            )?;
            return Ok(false);
        }
        match target {
            NamespaceTarget::Symbol(target) => {
                self.record_symbol_use(&task.imported.name, &target)?;
                push64(
                    &mut self.named_imports,
                    NamedImport {
                        module: task.module,
                        local_name: local_name.clone(),
                        target: target.clone(),
                        source: task.imported.meta.span,
                    },
                    "named imports",
                    self.request.limits.resolved_uses,
                )?;
                if task.public {
                    let reexport_target = match target {
                        SymbolTarget::Declaration(value) => hir::ReexportTarget::Declaration(value),
                        SymbolTarget::Variant(value) => hir::ReexportTarget::Variant(value),
                    };
                    self.add_reexport(
                        task.module,
                        local_name,
                        reexport_target,
                        task.imported.meta.span,
                    )?;
                }
            }
            NamespaceTarget::Module { package, module } => {
                let spelling = self.name(&task.imported.name)?;
                self.push_use(ResolvedUse {
                    source: task.imported.name.meta.span,
                    spelling: ReferenceSpelling::Identifier(spelling),
                    kind: BindingKind::Module,
                    target: Some(ResolvedBinding::Module { package, module }),
                })?;
                self.add_import_edge(task.module, module)?;
                let mut local_path = Vec::new();
                push64(
                    &mut local_path,
                    local_name.clone(),
                    "module import path",
                    self.request.limits.resolved_uses,
                )?;
                push64(
                    &mut self.module_imports,
                    ModuleImport {
                        module: task.module,
                        local_path,
                        target_package: package,
                        target_module: module,
                        source: task.imported.meta.span,
                    },
                    "module imports",
                    self.request.limits.resolved_uses,
                )?;
                if task.public {
                    self.add_reexport(
                        task.module,
                        local_name,
                        hir::ReexportTarget::Module { package, module },
                        task.imported.meta.span,
                    )?;
                }
            }
        }
        Ok(task.public)
    }

    fn import_module_target(
        &self,
        current_package: PackageId,
        path: &syntax::QualifiedName,
    ) -> Result<Option<(PackageId, ModuleId)>, LowerFailure> {
        let Some(first) = path.segments.first() else {
            return Ok(None);
        };
        let package = self
            .request
            .packages
            .package(current_package)
            .ok_or_else(|| {
                LowerFailure::InternalInvariant("module refers to an absent package".to_owned())
            })?;
        let dependency = package
            .dependencies
            .iter()
            .find(|edge| edge.alias.as_str() == first.spelling);
        let (target_package, module_segments) = dependency
            .map_or((current_package, path.segments.as_slice()), |edge| {
                (edge.package, &path.segments[1..])
            });
        if module_segments.is_empty() {
            return Ok(None);
        }
        for module in self.request.packages.modules() {
            poll_cancellation(self.is_cancelled)?;
            if module.package == target_package
                && module.path.segments().len() == module_segments.len()
                && module
                    .path
                    .segments()
                    .iter()
                    .zip(module_segments)
                    .all(|(left, right)| *left == right.spelling)
            {
                return Ok(Some((target_package, module.id)));
            }
        }
        Ok(None)
    }

    fn add_import_edge(&mut self, source: ModuleId, target: ModuleId) -> Result<(), LowerFailure> {
        let edges = &mut self.import_edges[source.0 as usize];
        if !edges.contains(&target) {
            push(
                edges,
                target,
                "module import edges",
                self.request.limits.modules,
            )?;
            edges.sort_unstable();
        }
        Ok(())
    }

    fn exported_namespaces(
        &self,
        module: ModuleId,
        name: &hir::Name,
    ) -> Result<Vec<NamespaceTarget>, LowerFailure> {
        let mut matches = Vec::new();
        for reexport in &self.program.modules[module.0 as usize].reexports {
            if reexport.local_name != *name {
                continue;
            }
            let target = match &reexport.target {
                hir::ReexportTarget::Declaration(value) => {
                    NamespaceTarget::Symbol(SymbolTarget::Declaration(value.clone()))
                }
                hir::ReexportTarget::Variant(value) => {
                    NamespaceTarget::Symbol(SymbolTarget::Variant(value.clone()))
                }
                hir::ReexportTarget::Module { package, module } => NamespaceTarget::Module {
                    package: *package,
                    module: *module,
                },
            };
            push(
                &mut matches,
                target,
                "exported namespace matches",
                self.request.limits.declarations,
            )?;
        }
        for symbol in &self.symbols {
            let visible = match &symbol.target {
                SymbolTarget::Declaration(target) => {
                    self.program.declarations[target.declaration.0 as usize].visibility
                        != hir::Visibility::Private
                }
                SymbolTarget::Variant(target) => {
                    self.program.declarations[target.enumeration.declaration.0 as usize].visibility
                        != hir::Visibility::Private
                }
            };
            let symbol_module = match &symbol.target {
                SymbolTarget::Declaration(value) => value.module,
                SymbolTarget::Variant(value) => value.enumeration.module,
            };
            let module_namespace = match &symbol.target {
                SymbolTarget::Declaration(_) => symbol.owner == SymbolOwner::Module(module),
                SymbolTarget::Variant(value) => matches!(
                    self.program.declarations[value.enumeration.declaration.0 as usize].owner,
                    hir::DeclarationOwner::Module(owner) if owner == module
                ),
            };
            if symbol_module == module && module_namespace && symbol.name == *name && visible {
                push(
                    &mut matches,
                    NamespaceTarget::Symbol(symbol.target.clone()),
                    "exported namespace matches",
                    self.request.limits.declarations,
                )?;
            }
        }
        Ok(matches)
    }

    fn import_name_conflicts(&self, module: ModuleId, name: &hir::Name) -> bool {
        self.symbols
            .iter()
            .any(|symbol| symbol.owner == SymbolOwner::Module(module) && symbol.name == *name)
            || self
                .named_imports
                .iter()
                .any(|binding| binding.module == module && binding.local_name == *name)
            || self.module_imports.iter().any(|binding| {
                binding.module == module
                    && binding.local_path.len() == 1
                    && binding.local_path.first() == Some(name)
            })
    }

    fn add_reexport(
        &mut self,
        module: ModuleId,
        local_name: hir::Name,
        target: hir::ReexportTarget,
        source: Span,
    ) -> Result<(), LowerFailure> {
        if self.program.modules[module.0 as usize]
            .reexports
            .iter()
            .any(|reexport| reexport.local_name == local_name)
        {
            self.emit(
                "hir-reexport-name-conflict",
                source,
                "this public import duplicates another exported name",
            )?;
            return Ok(());
        }
        push64(
            &mut self.program.modules[module.0 as usize].reexports,
            hir::Reexport {
                local_name,
                target,
                source,
            },
            "module reexports",
            self.request.limits.resolved_uses,
        )
    }

    fn record_module_path_use(
        &mut self,
        path: &syntax::QualifiedName,
        package: PackageId,
        module: ModuleId,
    ) -> Result<(), LowerFailure> {
        if let Some(segment) = path.segments.last() {
            let spelling = self.name(segment)?;
            self.push_use(ResolvedUse {
                source: segment.meta.span,
                spelling: ReferenceSpelling::Identifier(spelling),
                kind: BindingKind::Module,
                target: Some(ResolvedBinding::Module { package, module }),
            })?;
        }
        Ok(())
    }

    fn record_symbol_use(
        &mut self,
        identifier: &syntax::Identifier,
        target: &SymbolTarget,
    ) -> Result<(), LowerFailure> {
        let spelling = self.name(identifier)?;
        let (kind, target) = match target {
            SymbolTarget::Declaration(value) => (
                BindingKind::Declaration,
                ResolvedBinding::Declaration(value.clone()),
            ),
            SymbolTarget::Variant(value) => (
                BindingKind::Variant,
                ResolvedBinding::Variant(value.clone()),
            ),
        };
        self.push_use(ResolvedUse {
            source: identifier.meta.span,
            spelling: ReferenceSpelling::Identifier(spelling),
            kind,
            target: Some(target),
        })
    }

    fn record_error_use(&mut self, identifier: &syntax::Identifier) -> Result<(), LowerFailure> {
        self.push_use(ResolvedUse {
            source: identifier.meta.span,
            spelling: ReferenceSpelling::Identifier(self.name(identifier)?),
            kind: BindingKind::Error,
            target: None,
        })
    }

    fn push_use(&mut self, value: ResolvedUse) -> Result<(), LowerFailure> {
        push64(
            &mut self.uses,
            value,
            "resolved uses",
            self.request.limits.resolved_uses,
        )
    }

    fn enforce_import_scc_limit(&self) -> Result<(), LowerFailure> {
        let count = self.import_edges.len();
        let mut reverse = Vec::new();
        reserve(
            &mut reverse,
            count,
            "reverse import graph",
            self.request.limits.modules,
        )?;
        for _ in 0..count {
            push(
                &mut reverse,
                Vec::new(),
                "reverse import graph",
                self.request.limits.modules,
            )?;
        }
        for (source, targets) in self.import_edges.iter().enumerate() {
            poll_cancellation(self.is_cancelled)?;
            for target in targets {
                let values = &mut reverse[target.0 as usize];
                push(
                    values,
                    ModuleId(source as u32),
                    "reverse import edges",
                    self.request.limits.modules,
                )?;
            }
        }
        let mut visited = Vec::new();
        reserve(
            &mut visited,
            count,
            "import traversal marks",
            self.request.limits.modules,
        )?;
        visited.resize(count, false);
        let mut order = Vec::new();
        reserve(
            &mut order,
            count,
            "import traversal order",
            self.request.limits.modules,
        )?;
        for start in 0..count {
            if visited[start] {
                continue;
            }
            let mut stack = Vec::new();
            push(
                &mut stack,
                (start, 0usize),
                "import traversal stack",
                self.request.limits.modules,
            )?;
            visited[start] = true;
            while let Some((node, next)) = stack.last_mut() {
                poll_cancellation(self.is_cancelled)?;
                if *next < self.import_edges[*node].len() {
                    let target = self.import_edges[*node][*next].0 as usize;
                    *next += 1;
                    if !visited[target] {
                        visited[target] = true;
                        push(
                            &mut stack,
                            (target, 0),
                            "import traversal stack",
                            self.request.limits.modules,
                        )?;
                    }
                } else {
                    let (finished, _) = stack.pop().ok_or_else(|| {
                        LowerFailure::InternalInvariant(
                            "import traversal stack became inconsistent".to_owned(),
                        )
                    })?;
                    push(
                        &mut order,
                        finished,
                        "import traversal order",
                        self.request.limits.modules,
                    )?;
                }
            }
        }
        visited.fill(false);
        for start in order.into_iter().rev() {
            if visited[start] {
                continue;
            }
            let mut stack = Vec::new();
            push(
                &mut stack,
                start,
                "import component stack",
                self.request.limits.modules,
            )?;
            visited[start] = true;
            let mut component_size = 0u32;
            while let Some(node) = stack.pop() {
                poll_cancellation(self.is_cancelled)?;
                component_size =
                    component_size
                        .checked_add(1)
                        .ok_or(LowerFailure::ResourceLimit {
                            resource: "import SCC size",
                            limit: u64::from(self.request.limits.import_scc_size),
                        })?;
                if component_size > self.request.limits.import_scc_size {
                    return Err(LowerFailure::ResourceLimit {
                        resource: "import SCC size",
                        limit: u64::from(self.request.limits.import_scc_size),
                    });
                }
                for predecessor in &reverse[node] {
                    let predecessor = predecessor.0 as usize;
                    if !visited[predecessor] {
                        visited[predecessor] = true;
                        push(
                            &mut stack,
                            predecessor,
                            "import component stack",
                            self.request.limits.modules,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn lower_declarations(&mut self) -> Result<(), LowerFailure> {
        for index in 0..self.plans.len() {
            poll_cancellation(self.is_cancelled)?;
            self.lower_one_declaration(index)?;
        }
        Ok(())
    }

    fn load_reused_module_uses(
        &mut self,
        previous: &LowerOutput,
        reusable_files: &BTreeSet<wrela_source::FileId>,
        meter: &mut HirReuseMeter<'_>,
    ) -> Result<(), LowerFailure> {
        for record in &previous.lowered.uses {
            meter.poll()?;
            if reusable_files.contains(&record.source.file) {
                push64(
                    &mut self.uses,
                    record.clone(),
                    "reused resolved uses",
                    self.request.limits.resolved_uses,
                )?;
            }
        }
        Ok(())
    }

    fn lower_declarations_reusing(
        &mut self,
        previous: &LowerOutput,
        reusable_files: &BTreeSet<wrela_source::FileId>,
        meter: &mut HirReuseMeter<'_>,
    ) -> Result<u64, LowerFailure> {
        let mut executed = 0u64;
        for index in 0..self.plans.len() {
            poll_cancellation(self.is_cancelled)?;
            let declaration = self
                .program
                .declarations
                .get(index)
                .ok_or(LowerFailure::InvalidChangeSet)?;
            let source = self
                .request
                .packages
                .modules()
                .get(declaration.module.0 as usize)
                .ok_or(LowerFailure::InvalidChangeSet)?
                .source;
            if reusable_files.contains(&source) {
                self.reuse_declaration(hir::DeclarationId(index as u32), previous, meter)?;
            } else {
                executed = executed.checked_add(1).ok_or(LowerFailure::ResourceLimit {
                    resource: "executed declaration producers",
                    limit: u64::from(self.request.limits.declarations),
                })?;
                self.lower_one_declaration(index)?;
            }
        }
        Ok(executed)
    }

    fn lower_one_declaration(&mut self, index: usize) -> Result<(), LowerFailure> {
        if self.plans[index].recover_as_error {
            return Ok(());
        }
        let id = hir::DeclarationId(index as u32);
        self.lower_generic_headers(id)?;
        self.lower_parameter_headers(id)?;
        let attributes = self.lower_attributes(
            id,
            self.plans[index].attributes,
            hir::ExpressionOwner::Declaration(id),
            None,
            false,
        )?;
        let kind = self.lower_declaration_kind(id, self.plans[index].syntax)?;
        self.program.declarations[index].attributes = attributes;
        self.program.declarations[index].kind = kind;
        let is_function = matches!(
            self.program.declarations[index].kind,
            hir::DeclarationKind::Function(_)
        );
        if is_function {
            let attributes = &self.program.declarations[index].attributes;
            if attributes.iter().any(|attribute| {
                attribute.identity == hir::AttributeIdentity::Builtin(hir::BuiltinAttribute::Image)
            }) {
                push(
                    &mut self.program.image_candidates,
                    id,
                    "image candidates",
                    self.request.limits.declarations,
                )?;
            }
            if attributes.iter().any(|attribute| {
                attribute.identity == hir::AttributeIdentity::Builtin(hir::BuiltinAttribute::Test)
            }) {
                push(
                    &mut self.program.test_candidates,
                    id,
                    "test candidates",
                    self.request.limits.declarations,
                )?;
            }
        }
        Ok(())
    }

    fn reuse_declaration(
        &mut self,
        declaration: hir::DeclarationId,
        previous: &LowerOutput,
        meter: &mut HirReuseMeter<'_>,
    ) -> Result<(), LowerFailure> {
        let previous_program = previous.lowered.program.as_program();
        let index = declaration.0 as usize;
        let prior = previous_program
            .declarations
            .get(index)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        let current = self
            .program
            .declarations
            .get(index)
            .ok_or(LowerFailure::InvalidChangeSet)?;
        meter.poll()?;
        if current.id != prior.id
            || current.module != prior.module
            || current.owner != prior.owner
            || current.name != prior.name
            || current.visibility != prior.visibility
            || current.source != prior.source
        {
            return Err(LowerFailure::UnsupportedReuseShape(
                "an unchanged declaration changed its stable identity",
            ));
        }

        for record in previous_program
            .generic_parameters
            .iter()
            .filter(|record| record.owner == declaration)
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.generic_parameters,
                record.id.0,
                record,
                "reused generic parameters",
                self.request.limits.generic_parameters,
            )?;
        }
        for record in previous_program
            .parameters
            .iter()
            .filter(|record| parameter_declaration(previous_program, record) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.parameters,
                record.id.0,
                record,
                "reused parameters",
                self.request.limits.parameters,
            )?;
        }
        for record in previous_program
            .bodies
            .iter()
            .filter(|record| body_declaration(previous_program, record.id) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.bodies,
                record.id.0,
                record,
                "reused bodies",
                self.request.limits.bodies,
            )?;
        }
        for record in previous_program
            .scopes
            .iter()
            .filter(|record| body_declaration(previous_program, record.body) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.scopes,
                record.id.0,
                record,
                "reused scopes",
                self.request.limits.scopes,
            )?;
        }
        for record in previous_program
            .locals
            .iter()
            .filter(|record| body_declaration(previous_program, record.body) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.locals,
                record.id.0,
                record,
                "reused locals",
                self.request.limits.locals,
            )?;
        }
        for record in previous_program
            .statements
            .iter()
            .filter(|record| body_declaration(previous_program, record.body) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.statements,
                record.id.0,
                record,
                "reused statements",
                self.request.limits.statements,
            )?;
        }
        for record in previous_program.expressions.iter().filter(|record| {
            expression_declaration(previous_program, record.owner) == Some(declaration)
        }) {
            meter.poll()?;
            install_reused_record(
                &mut self.program.expressions,
                record.id.0,
                record,
                "reused expressions",
                self.request.limits.expressions,
            )?;
        }
        for record in previous_program.patterns.iter().filter(|record| {
            expression_declaration(previous_program, record.owner) == Some(declaration)
        }) {
            meter.poll()?;
            install_reused_record(
                &mut self.program.patterns,
                record.id.0,
                record,
                "reused patterns",
                self.request.limits.patterns,
            )?;
        }
        for record in previous_program
            .regions
            .iter()
            .filter(|record| body_declaration(previous_program, record.body) == Some(declaration))
        {
            meter.poll()?;
            install_reused_record(
                &mut self.program.regions,
                record.id.0,
                record,
                "reused regions",
                self.request.limits.regions,
            )?;
        }
        self.program.declarations[index] = prior.clone();
        if previous_program.image_candidates.contains(&declaration) {
            push(
                &mut self.program.image_candidates,
                declaration,
                "reused image candidates",
                self.request.limits.declarations,
            )?;
        }
        if previous_program.test_candidates.contains(&declaration) {
            push(
                &mut self.program.test_candidates,
                declaration,
                "reused test candidates",
                self.request.limits.declarations,
            )?;
        }
        Ok(())
    }

    fn lower_generic_headers(&mut self, owner: hir::DeclarationId) -> Result<(), LowerFailure> {
        let syntax_generics = syntax_generics(self.plans[owner.0 as usize].syntax);
        let ids = copy_slice(
            &self.headers[owner.0 as usize].generics,
            "generic header worklist",
            self.request.limits.generic_parameters,
        )?;
        for id in ids {
            poll_cancellation(self.is_cancelled)?;
            let name = self.program.generic_parameters[id.0 as usize].name.clone();
            let Some(syntax) = syntax_generics
                .iter()
                .find(|generic| generic_name(generic).spelling == name.as_str())
            else {
                return Err(LowerFailure::InternalInvariant(
                    "predeclared generic no longer has source syntax".to_owned(),
                ));
            };
            let context = ExpressionContext {
                owner: hir::ExpressionOwner::Declaration(owner),
                scope: None,
                declaration: owner,
            };
            let kind = match syntax {
                syntax::GenericParameter::Type { bound, .. } => hir::GenericParameterKind::Type {
                    bound: bound
                        .as_ref()
                        .map(|value| self.lower_type(context, value, 0))
                        .transpose()?,
                },
                syntax::GenericParameter::Constant { ty, .. } => {
                    hir::GenericParameterKind::Constant {
                        ty: self.lower_type(context, ty, 0)?,
                    }
                }
                syntax::GenericParameter::Region { .. } => hir::GenericParameterKind::Region,
            };
            self.program.generic_parameters[id.0 as usize].kind = kind;
        }
        Ok(())
    }

    fn lower_parameter_headers(&mut self, owner: hir::DeclarationId) -> Result<(), LowerFailure> {
        let syntax_parameters = syntax_parameters(self.plans[owner.0 as usize].syntax);
        let ids = copy_slice(
            &self.headers[owner.0 as usize].parameters,
            "parameter header worklist",
            self.request.limits.parameters,
        )?;
        for id in ids {
            poll_cancellation(self.is_cancelled)?;
            if Some(id) == self.headers[owner.0 as usize].exit_parameter {
                self.program.parameters[id.0 as usize].ty = None;
                continue;
            }
            if self.program.parameters[id.0 as usize].receiver {
                continue;
            }
            let name = self.program.parameters[id.0 as usize]
                .name
                .clone()
                .ok_or_else(|| {
                    LowerFailure::InternalInvariant(
                        "ordinary predeclared parameter lost its name".to_owned(),
                    )
                })?;
            let Some(parameter) = syntax_parameters
                .iter()
                .find(|parameter| !parameter.receiver && parameter.name.spelling == name.as_str())
            else {
                return Err(LowerFailure::InternalInvariant(
                    "predeclared parameter no longer has source syntax".to_owned(),
                ));
            };
            let context = ExpressionContext {
                owner: hir::ExpressionOwner::Declaration(owner),
                scope: None,
                declaration: owner,
            };
            self.program.parameters[id.0 as usize].ty = parameter
                .ty
                .as_ref()
                .map(|ty| self.lower_type(context, ty, 0))
                .transpose()?;
        }
        Ok(())
    }

    fn lower_declaration_kind(
        &mut self,
        id: hir::DeclarationId,
        syntax: DeclarationSyntax<'a>,
    ) -> Result<hir::DeclarationKind, LowerFailure> {
        let context = ExpressionContext {
            owner: hir::ExpressionOwner::Declaration(id),
            scope: None,
            declaration: id,
        };
        let header = self.clone_declaration_header(id)?;
        match syntax {
            DeclarationSyntax::Constant(value) => {
                Ok(hir::DeclarationKind::Constant(hir::ConstantDeclaration {
                    ty: value
                        .ty
                        .as_ref()
                        .map(|ty| self.lower_type(context, ty, 0))
                        .transpose()?,
                    value: self.lower_expression(context, &value.value, 0)?,
                }))
            }
            DeclarationSyntax::Brand(_) => Ok(hir::DeclarationKind::Brand),
            DeclarationSyntax::Function(value) => {
                let body = value
                    .body
                    .as_ref()
                    .map(|suite| {
                        self.lower_root_suite(
                            hir::BodyOwner::Declaration(id),
                            id,
                            suite,
                            self.declaration_bindings(id)?,
                        )
                    })
                    .transpose()?;
                Ok(hir::DeclarationKind::Function(hir::FunctionDeclaration {
                    color: lower_color(value.color),
                    generics: header.generics,
                    parameters: header.parameters,
                    result: value
                        .return_type
                        .as_ref()
                        .map(|ty| self.lower_type(context, ty, 0))
                        .transpose()?,
                    body,
                }))
            }
            DeclarationSyntax::Initializer(value) => {
                let body = self.lower_root_suite(
                    hir::BodyOwner::Declaration(id),
                    id,
                    &value.body,
                    self.declaration_bindings(id)?,
                )?;
                Ok(hir::DeclarationKind::Initializer(
                    hir::InitializerDeclaration {
                        parameters: header.parameters,
                        result: value
                            .return_type
                            .as_ref()
                            .map(|ty| self.lower_type(context, ty, 0))
                            .transpose()?,
                        body,
                    },
                ))
            }
            DeclarationSyntax::Structure(value) => {
                let aggregate = self.lower_aggregate(id, value, header)?;
                Ok(hir::DeclarationKind::Structure(aggregate))
            }
            DeclarationSyntax::Enumeration(value) => Ok(hir::DeclarationKind::Enumeration(
                self.lower_enumeration(id, value, header)?,
            )),
            DeclarationSyntax::Interface(_) => {
                Ok(hir::DeclarationKind::Interface(hir::InterfaceDeclaration {
                    generics: header.generics,
                    requirements: header.children,
                }))
            }
            DeclarationSyntax::Implementation(value) => Ok(hir::DeclarationKind::Implementation(
                hir::ImplementationDeclaration {
                    interface: self.lower_type(context, &value.interface, 0)?,
                    implementing_type: self.lower_type(context, &value.implementing_type, 0)?,
                    members: header.children,
                },
            )),
            DeclarationSyntax::Projection(value) => {
                let carrier = self.lower_projection_carrier(context, &value.carrier, 0)?;
                // Provenance is implicit now: every parameter (including a
                // receiver) is an eligible borrow source, so no explicit
                // `from ...` set is parsed. Populate it from the full
                // parameter list so downstream HIR representation and
                // validation are unchanged.
                let mut provenance = header.parameters.clone();
                provenance.sort_unstable();
                let body = value
                    .body
                    .as_ref()
                    .map(|suite| {
                        self.lower_root_suite(
                            hir::BodyOwner::Declaration(id),
                            id,
                            suite,
                            self.declaration_bindings(id)?,
                        )
                    })
                    .transpose()?;
                Ok(hir::DeclarationKind::Projection(
                    hir::ProjectionDeclaration {
                        generics: header.generics,
                        parameters: header.parameters,
                        carrier,
                        provenance,
                        body,
                    },
                ))
            }
            DeclarationSyntax::Scope(value) => {
                let result = self.lower_type(context, &value.return_type, 0)?;
                let exit_parameter = header.exit_parameter.ok_or_else(|| {
                    LowerFailure::InternalInvariant(
                        "scope declaration has no exit parameter".to_owned(),
                    )
                })?;
                let mut setup_bindings = self.declaration_bindings(id)?;
                setup_bindings.retain(|binding| {
                    !matches!(
                        binding.target,
                        ResolutionTarget::Definition(hir::Definition::Parameter(parameter))
                            if parameter == exit_parameter
                    )
                });
                let setup = self.begin_body(
                    hir::BodyOwner::Declaration(id),
                    id,
                    value.meta.span,
                    setup_bindings,
                    None,
                )?;
                self.lower_into_current_body(&value.setup)?;
                let setup_context = self.current_expression_context()?;
                let enter = self.lower_expression(setup_context, &value.enter, 0)?;
                let setup_scope = self.current_body()?.scope;
                let setup_visible = self.current_visible()?;
                self.finish_body(setup)?;
                let abort = if let Some(suite) = &value.abort {
                    let visible = self.clone_visible_bindings(&setup_visible)?;
                    Some(self.lower_statement_list_body(
                        hir::BodyOwner::Declaration(id),
                        id,
                        suite.meta.span,
                        &suite.statements,
                        visible,
                        Some(setup_scope),
                    )?)
                } else {
                    None
                };
                let mut exit_visible = setup_visible;
                let exit_record = &self.program.parameters[exit_parameter.0 as usize];
                if let Some(name) = &exit_record.name {
                    push64(
                        &mut exit_visible,
                        OwnedVisibleBinding {
                            name: name.clone(),
                            target: ResolutionTarget::Definition(hir::Definition::Parameter(
                                exit_parameter,
                            )),
                            kind: BindingKind::Parameter,
                        },
                        "scope exit bindings",
                        self.request.limits.model_edges,
                    )?;
                }
                let exit = self.lower_statement_list_body(
                    hir::BodyOwner::Declaration(id),
                    id,
                    value.exit.meta.span,
                    &value.exit.statements,
                    exit_visible,
                    Some(setup_scope),
                )?;
                Ok(hir::DeclarationKind::Scope(hir::ScopeDeclaration {
                    parameters: header.parameters,
                    result,
                    setup,
                    enter,
                    abort,
                    exit_parameter,
                    exit,
                }))
            }
            DeclarationSyntax::ComptimeDeclaration(value) => {
                let condition = self.lower_expression(context, &value.condition, 0)?;
                let then_declarations = copy_slice(
                    &header.children[..header.then_count],
                    "comptime then declarations",
                    self.request.limits.declarations,
                )?;
                let else_declarations = copy_slice(
                    &header.children[header.then_count..],
                    "comptime else declarations",
                    self.request.limits.declarations,
                )?;
                Ok(hir::DeclarationKind::ComptimeSelection(
                    hir::ComptimeSelection {
                        condition,
                        then_declarations,
                        else_declarations,
                    },
                ))
            }
            DeclarationSyntax::ComptimeMember(value) => {
                let condition = self.lower_expression(context, &value.condition, 0)?;
                let then_declarations = copy_slice(
                    &header.children[..header.then_count],
                    "comptime then declarations",
                    self.request.limits.declarations,
                )?;
                let else_declarations = copy_slice(
                    &header.children[header.then_count..],
                    "comptime else declarations",
                    self.request.limits.declarations,
                )?;
                Ok(hir::DeclarationKind::ComptimeSelection(
                    hir::ComptimeSelection {
                        condition,
                        then_declarations,
                        else_declarations,
                    },
                ))
            }
            DeclarationSyntax::Error => Ok(hir::DeclarationKind::Error),
        }
    }

    fn clone_declaration_header(
        &self,
        declaration: hir::DeclarationId,
    ) -> Result<DeclarationHeader, LowerFailure> {
        let source = &self.headers[declaration.0 as usize];
        let generics = copy_slice(
            &source.generics,
            "declaration generic references",
            self.request.limits.generic_parameters,
        )?;
        let parameters = copy_slice(
            &source.parameters,
            "declaration parameter references",
            self.request.limits.parameters,
        )?;
        let children = copy_slice(
            &source.children,
            "declaration child references",
            self.request.limits.declarations,
        )?;
        let mut variants = Vec::new();
        for variant in &source.variants {
            push64(
                &mut variants,
                variant.clone(),
                "enum variant headers",
                self.request.limits.model_edges,
            )?;
        }
        Ok(DeclarationHeader {
            generics,
            parameters,
            children,
            then_count: source.then_count,
            exit_parameter: source.exit_parameter,
            variants,
        })
    }

    fn lower_attributes(
        &mut self,
        declaration: hir::DeclarationId,
        attributes: &[syntax::Attribute],
        owner: hir::ExpressionOwner,
        scope: Option<hir::ScopeId>,
        statement_only: bool,
    ) -> Result<Vec<hir::Attribute>, LowerFailure> {
        let mut output = Vec::new();
        for attribute in attributes {
            poll_cancellation(self.is_cancelled)?;
            let builtin = if attribute.name.segments.len() == 1 {
                builtin_attribute(&attribute.name.segments[0].spelling)
            } else {
                None
            };
            let Some(builtin) = builtin else {
                self.emit(
                    "hir-unknown-attribute",
                    attribute.name.meta.span,
                    "unknown attributes are rejected until their namespace is declared non-semantic",
                )?;
                if let Some(identifier) = attribute.name.segments.last() {
                    self.record_error_use(identifier)?;
                }
                continue;
            };
            if statement_only && builtin != hir::BuiltinAttribute::Uninterrupted {
                self.emit(
                    "hir-invalid-statement-attribute",
                    attribute.meta.span,
                    "only @uninterrupted is permitted on a source statement",
                )?;
                continue;
            }
            if !statement_only
                && builtin == hir::BuiltinAttribute::Uninterrupted
                && !matches!(
                    self.plans[declaration.0 as usize].syntax,
                    DeclarationSyntax::Function(_)
                        | DeclarationSyntax::Projection(_)
                        | DeclarationSyntax::Scope(_)
                )
            {
                self.emit(
                    "hir-invalid-uninterrupted-attribute",
                    attribute.meta.span,
                    "@uninterrupted is not legal on this declaration",
                )?;
                continue;
            }
            if matches!(
                builtin,
                hir::BuiltinAttribute::Image | hir::BuiltinAttribute::Test
            ) {
                let DeclarationSyntax::Function(function) =
                    self.plans[declaration.0 as usize].syntax
                else {
                    self.emit(
                        "hir-invalid-entry-attribute",
                        attribute.meta.span,
                        "@image and @test require a function declaration",
                    )?;
                    continue;
                };
                let header = &self.headers[declaration.0 as usize];
                let valid_shape = header.generics.is_empty()
                    && header.parameters.is_empty()
                    && match builtin {
                        hir::BuiltinAttribute::Image => {
                            function.color == syntax::FunctionColor::Sync
                                && self.program.declarations[declaration.0 as usize].visibility
                                    != hir::Visibility::Private
                        }
                        hir::BuiltinAttribute::Test => function.color != syntax::FunctionColor::Isr,
                        _ => true,
                    };
                let arguments_ok = match builtin {
                    hir::BuiltinAttribute::Image => attribute.arguments.is_empty(),
                    hir::BuiltinAttribute::Test => {
                        test_attribute_arguments_are_supported(&attribute.arguments)
                    }
                    _ => true,
                };
                if !valid_shape {
                    self.emit(
                        "hir-invalid-entry-attribute",
                        attribute.meta.span,
                        "entry attributes require their exact zero-argument function signature",
                    )?;
                    continue;
                }
                if !arguments_ok {
                    if builtin == hir::BuiltinAttribute::Test {
                        self.emit(
                            "hir-invalid-test-attribute-argument",
                            attribute.meta.span,
                            "@test accepts no arguments or the single argument `runtime`",
                        )?;
                    } else {
                        self.emit(
                            "hir-invalid-entry-attribute",
                            attribute.meta.span,
                            "entry attributes require their exact zero-argument function signature",
                        )?;
                    }
                    continue;
                }
                if output.iter().any(|existing: &hir::Attribute| {
                    matches!(
                        existing.identity,
                        hir::AttributeIdentity::Builtin(
                            hir::BuiltinAttribute::Image | hir::BuiltinAttribute::Test
                        )
                    )
                }) {
                    self.emit(
                        "hir-conflicting-entry-attribute",
                        attribute.meta.span,
                        "a function cannot be both an image and a test entry",
                    )?;
                    continue;
                }
            }
            let expression_context = ExpressionContext {
                owner,
                scope,
                declaration,
            };
            let mut arguments = Vec::new();
            let mut saw_named = false;
            let mut valid_arguments = true;
            for argument in &attribute.arguments {
                let name = argument
                    .name
                    .as_ref()
                    .map(|name| self.name(name))
                    .transpose()?;
                if name.is_some() {
                    saw_named = true;
                } else if saw_named {
                    self.emit(
                        "hir-positional-after-named-attribute-argument",
                        argument.meta.span,
                        "positional attribute arguments must precede named arguments",
                    )?;
                    valid_arguments = false;
                    break;
                }
                if name.as_ref().is_some_and(|name| {
                    arguments.iter().any(|existing: &hir::AttributeArgument| {
                        existing.name.as_ref() == Some(name)
                    })
                }) {
                    self.emit(
                        "hir-duplicate-attribute-argument",
                        argument.meta.span,
                        "this named attribute argument is duplicated",
                    )?;
                    valid_arguments = false;
                    break;
                }
                // `@test(runtime)` is a tier keyword, not a resolvable value
                // name; keep an Error expression so the argument remains
                // covered without emitting `hir-unresolved-name`.
                let value = if builtin == hir::BuiltinAttribute::Test
                    && is_test_runtime_attribute_argument(argument)
                {
                    self.lower_test_runtime_marker(expression_context, &argument.value)?
                } else {
                    self.lower_expression(expression_context, &argument.value, 0)?
                };
                push64(
                    &mut arguments,
                    hir::AttributeArgument {
                        name,
                        value,
                        source: argument.meta.span,
                    },
                    "attribute arguments",
                    self.request.limits.model_edges,
                )?;
            }
            if !valid_arguments {
                // Child expressions already produced for preceding valid
                // arguments must remain covered; retain those arguments and
                // let the rejecting diagnostic describe the malformed suffix.
            }
            push64(
                &mut output,
                hir::Attribute {
                    identity: hir::AttributeIdentity::Builtin(builtin),
                    arguments,
                    source: attribute.meta.span,
                },
                "attributes",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn lower_test_runtime_marker(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Expression,
    ) -> Result<hir::ExpressionId, LowerFailure> {
        poll_cancellation(self.is_cancelled)?;
        let id =
            hir::ExpressionId(u32::try_from(self.program.expressions.len()).map_err(|_| {
                LowerFailure::ResourceLimit {
                    resource: "expressions",
                    limit: u64::from(self.request.limits.expressions),
                }
            })?);
        push(
            &mut self.program.expressions,
            hir::Expression {
                id,
                owner: context.owner,
                scope: context.scope,
                kind: hir::ExpressionKind::Error,
                source: value.meta.span,
            },
            "expressions",
            self.request.limits.expressions,
        )?;
        Ok(id)
    }

    fn lower_aggregate(
        &mut self,
        id: hir::DeclarationId,
        value: &syntax::TypeDeclaration,
        header: DeclarationHeader,
    ) -> Result<hir::AggregateDeclaration, LowerFailure> {
        let context = ExpressionContext {
            owner: hir::ExpressionOwner::Declaration(id),
            scope: None,
            declaration: id,
        };
        let mut implements = Vec::new();
        for ty in &value.implements {
            let lowered = self.lower_type(context, ty, 0)?;
            push64(
                &mut implements,
                lowered,
                "implemented interfaces",
                self.request.limits.model_edges,
            )?;
        }
        let mut fields = Vec::new();
        for member in &value.members {
            let syntax::MemberKind::Field(field) = &member.kind else {
                continue;
            };
            let name = self.name(&field.name)?;
            if fields
                .iter()
                .any(|existing: &hir::Field| existing.name == name)
            {
                self.emit(
                    "hir-duplicate-field",
                    field.name.meta.span,
                    "this field duplicates an earlier aggregate field",
                )?;
                continue;
            }
            if header.children.iter().any(|child| {
                self.program.declarations[child.0 as usize].name.as_ref() == Some(&name)
            }) {
                self.emit(
                    "hir-field-member-name-conflict",
                    field.name.meta.span,
                    "this field conflicts with a nested declaration name",
                )?;
                continue;
            }
            let attributes = self.lower_attributes(
                id,
                &member.attributes,
                hir::ExpressionOwner::Declaration(id),
                None,
                false,
            )?;
            let ty = self.lower_type(context, &field.ty, 0)?;
            let default = field
                .default
                .as_ref()
                .map(|value| self.lower_expression(context, value, 0))
                .transpose()?;
            push64(
                &mut fields,
                hir::Field {
                    name,
                    visibility: if member.public {
                        hir::Visibility::Public
                    } else {
                        hir::Visibility::Private
                    },
                    attributes,
                    ty,
                    default,
                    source: member.meta.span,
                },
                "aggregate fields",
                self.request.limits.model_edges,
            )?;
        }
        Ok(hir::AggregateDeclaration {
            generics: header.generics,
            implements,
            fields,
            members: header.children,
            linear: value.linear,
            copy: value.copy,
            deriving: {
                let mut names = Vec::new();
                for name in &value.deriving {
                    push64(
                        &mut names,
                        self.name(name)?,
                        "deriving names",
                        self.request.limits.model_edges,
                    )?;
                }
                names
            },
        })
    }

    fn lower_enumeration(
        &mut self,
        id: hir::DeclarationId,
        value: &syntax::EnumDeclaration,
        header: DeclarationHeader,
    ) -> Result<hir::EnumDeclaration, LowerFailure> {
        let context = ExpressionContext {
            owner: hir::ExpressionOwner::Declaration(id),
            scope: None,
            declaration: id,
        };
        let mut variants = Vec::new();
        for expected in &header.variants {
            let source_variant = value
                .variants
                .iter()
                .find(|variant| variant.meta.span == expected.source)
                .ok_or_else(|| {
                    LowerFailure::InternalInvariant(
                        "predeclared enum variant lost its source node".to_owned(),
                    )
                })?;
            let mut fields = Vec::new();
            match &source_variant.payload {
                syntax::EnumPayload::None => {}
                syntax::EnumPayload::Positional(types) => {
                    for ty in types {
                        push64(
                            &mut fields,
                            hir::VariantField {
                                name: None,
                                ty: self.lower_type(context, ty, 0)?,
                                source: ty.meta.span,
                            },
                            "enum payload fields",
                            self.request.limits.model_edges,
                        )?;
                    }
                }
                syntax::EnumPayload::Named(source_fields) => {
                    for field in source_fields {
                        let name = self.name(&field.name)?;
                        if fields.iter().any(|existing: &hir::VariantField| {
                            existing.name.as_ref() == Some(&name)
                        }) {
                            self.emit(
                                "hir-duplicate-variant-field",
                                field.name.meta.span,
                                "this named variant field is duplicated",
                            )?;
                            continue;
                        }
                        push64(
                            &mut fields,
                            hir::VariantField {
                                name: Some(name),
                                ty: self.lower_type(context, &field.ty, 0)?,
                                source: field.meta.span,
                            },
                            "enum payload fields",
                            self.request.limits.model_edges,
                        )?;
                    }
                }
            }
            push64(
                &mut variants,
                hir::EnumVariant {
                    name: expected.name.clone(),
                    fields,
                    source: expected.source,
                },
                "enum variants",
                self.request.limits.model_edges,
            )?;
        }
        Ok(hir::EnumDeclaration {
            generics: header.generics,
            variants,
            members: header.children,
            deriving: {
                let mut names = Vec::new();
                for name in &value.deriving {
                    push64(
                        &mut names,
                        self.name(name)?,
                        "deriving names",
                        self.request.limits.model_edges,
                    )?;
                }
                names
            },
        })
    }

    fn lower_projection_carrier(
        &mut self,
        context: ExpressionContext,
        value: &syntax::ProjectionCarrier,
        depth: u32,
    ) -> Result<hir::ProjectionCarrier, LowerFailure> {
        self.check_depth(depth)?;
        poll_cancellation(self.is_cancelled)?;
        let (source, kind) = match value {
            syntax::ProjectionCarrier::View { meta, mutable, ty } => (
                meta.span,
                hir::ProjectionCarrierKind::View {
                    mutable: *mutable,
                    ty: self.lower_type(context, ty, depth + 1)?,
                },
            ),
            syntax::ProjectionCarrier::Option { meta, carrier } => (
                meta.span,
                hir::ProjectionCarrierKind::Option(Box::new(self.lower_projection_carrier(
                    context,
                    carrier,
                    depth + 1,
                )?)),
            ),
            syntax::ProjectionCarrier::Result {
                meta,
                carrier,
                error,
            } => (
                meta.span,
                hir::ProjectionCarrierKind::Result {
                    carrier: Box::new(self.lower_projection_carrier(
                        context,
                        carrier,
                        depth + 1,
                    )?),
                    error: self.lower_type(context, error, depth + 1)?,
                },
            ),
            syntax::ProjectionCarrier::Error(error) => {
                (error.meta.span, hir::ProjectionCarrierKind::Error)
            }
        };
        Ok(hir::ProjectionCarrier { kind, source })
    }

    fn check_depth(&self, depth: u32) -> Result<(), LowerFailure> {
        if depth > self.request.limits.generic_classification_depth {
            Err(LowerFailure::ResourceLimit {
                resource: "HIR lowering nesting depth",
                limit: u64::from(self.request.limits.generic_classification_depth),
            })
        } else {
            Ok(())
        }
    }

    fn lower_type(
        &mut self,
        context: ExpressionContext,
        value: &syntax::TypeExpression,
        depth: u32,
    ) -> Result<hir::TypeExpression, LowerFailure> {
        self.check_depth(depth)?;
        poll_cancellation(self.is_cancelled)?;
        let kind = match &value.kind {
            syntax::TypeExpressionKind::Named { name, arguments } => {
                if name.segments.len() == 1 && name.segments[0].spelling == "Self" {
                    let Some(owner) = self.self_type_owner(context.declaration) else {
                        self.emit(
                            "hir-self-type-outside-nominal-context",
                            name.meta.span,
                            "Self is only available inside a nominal type, interface, or implementation",
                        )?;
                        return Ok(hir::TypeExpression {
                            kind: hir::TypeExpressionKind::Error,
                            source: value.meta.span,
                        });
                    };
                    if !arguments.is_empty() {
                        self.emit(
                            "hir-self-type-arguments",
                            value.meta.span,
                            "Self does not accept explicit generic arguments",
                        )?;
                    }
                    self.record_declaration_use(&name.segments[0], owner)?;
                    hir::TypeExpressionKind::SelfType { owner }
                } else {
                    let Some(resolution) =
                        self.resolve_qualified(context, name, ExpectedName::Type)?
                    else {
                        return Ok(hir::TypeExpression {
                            kind: hir::TypeExpressionKind::Error,
                            source: value.meta.span,
                        });
                    };
                    let ResolutionTarget::Definition(definition) = resolution.target else {
                        self.emit(
                            "hir-region-used-as-type",
                            name.meta.span,
                            "a region name cannot be used as an ordinary type",
                        )?;
                        return Ok(hir::TypeExpression {
                            kind: hir::TypeExpressionKind::Error,
                            source: value.meta.span,
                        });
                    };
                    let lowered_arguments = self.lower_generic_arguments(
                        context,
                        &definition,
                        arguments,
                        value.meta.span,
                        depth + 1,
                    )?;
                    hir::TypeExpressionKind::Named {
                        definition,
                        arguments: lowered_arguments,
                    }
                }
            }
            syntax::TypeExpressionKind::Array { element, length } => {
                hir::TypeExpressionKind::Array {
                    element: Box::new(self.lower_type(context, element, depth + 1)?),
                    length: self.lower_expression(context, length, depth + 1)?,
                }
            }
            syntax::TypeExpressionKind::Tuple(values) => {
                let mut output = Vec::new();
                for ty in values {
                    push64(
                        &mut output,
                        self.lower_type(context, ty, depth + 1)?,
                        "tuple type elements",
                        self.request.limits.model_edges,
                    )?;
                }
                hir::TypeExpressionKind::Tuple(output)
            }
            syntax::TypeExpressionKind::View { mutable, target } => hir::TypeExpressionKind::View {
                mutable: *mutable,
                target: Box::new(self.lower_type(context, target, depth + 1)?),
            },
            syntax::TypeExpressionKind::Iso { brand, payload } => hir::TypeExpressionKind::Iso {
                brand: Box::new(self.lower_type(context, brand, depth + 1)?),
                payload: Box::new(self.lower_type(context, payload, depth + 1)?),
            },
            syntax::TypeExpressionKind::Function {
                asynchronous,
                parameters,
                result,
            } => {
                let mut lowered_parameters = Vec::new();
                for parameter in parameters {
                    push64(
                        &mut lowered_parameters,
                        hir::FunctionTypeParameter {
                            access: lower_access(parameter.access),
                            ty: self.lower_type(context, &parameter.ty, depth + 1)?,
                            source: parameter.meta.span,
                        },
                        "function type parameters",
                        self.request.limits.model_edges,
                    )?;
                }
                hir::TypeExpressionKind::Function {
                    color: if *asynchronous {
                        hir::FunctionColor::Async
                    } else {
                        hir::FunctionColor::Sync
                    },
                    parameters: lowered_parameters,
                    result: Box::new(self.lower_type(context, result, depth + 1)?),
                }
            }
            syntax::TypeExpressionKind::Error(_) => hir::TypeExpressionKind::Error,
        };
        Ok(hir::TypeExpression {
            kind,
            source: value.meta.span,
        })
    }

    fn lower_generic_arguments(
        &mut self,
        context: ExpressionContext,
        definition: &hir::Definition,
        arguments: &[syntax::BracketArgument],
        type_source: Span,
        depth: u32,
    ) -> Result<Vec<hir::GenericArgument>, LowerFailure> {
        self.check_depth(depth)?;
        let expected = self.expected_arguments(definition)?;
        let optional_capacity = matches!(
            definition,
            hir::Definition::Builtin(hir::Builtin::Bytes | hir::Builtin::String)
        );
        if (!optional_capacity && arguments.len() != expected.len())
            || (optional_capacity && arguments.len() > 1)
        {
            self.emit(
                "hir-generic-argument-count",
                type_source,
                "generic argument count does not match the resolved declaration",
            )?;
        }
        let mut output = Vec::new();
        for (index, expected_kind) in expected.iter().copied().enumerate() {
            let Some(argument) = arguments.get(index) else {
                push64(
                    &mut output,
                    hir::GenericArgument {
                        kind: hir::GenericArgumentKind::Error,
                        source: span_at_end(type_source),
                    },
                    "generic arguments",
                    self.request.limits.model_edges,
                )?;
                continue;
            };
            let lowered =
                self.lower_generic_argument(context, argument, expected_kind, depth + 1)?;
            push64(
                &mut output,
                lowered,
                "generic arguments",
                self.request.limits.model_edges,
            )?;
        }
        if optional_capacity {
            if let Some(argument) = arguments.first() {
                push64(
                    &mut output,
                    self.lower_generic_argument(
                        context,
                        argument,
                        ExpectedArgument::Capacity,
                        depth + 1,
                    )?,
                    "generic arguments",
                    self.request.limits.model_edges,
                )?;
            }
            for argument in arguments.iter().skip(1) {
                self.emit(
                    "hir-extra-generic-argument",
                    bracket_argument_span(argument),
                    "a bounded byte or string type accepts at most one capacity argument",
                )?;
            }
        } else if arguments.len() > expected.len() {
            for argument in &arguments[expected.len()..] {
                self.emit(
                    "hir-extra-generic-argument",
                    bracket_argument_span(argument),
                    "this generic argument has no matching resolved parameter",
                )?;
            }
        }
        Ok(output)
    }

    fn lower_generic_argument(
        &mut self,
        context: ExpressionContext,
        argument: &syntax::BracketArgument,
        expected: ExpectedArgument,
        depth: u32,
    ) -> Result<hir::GenericArgument, LowerFailure> {
        self.check_depth(depth)?;
        let source = bracket_argument_span(argument);
        let kind = match argument {
            syntax::BracketArgument::BoundedCapacity { maximum, .. } => {
                if expected != ExpectedArgument::Capacity {
                    self.emit(
                        "hir-capacity-argument-kind",
                        source,
                        "bounded-capacity syntax is legal only for a capacity generic",
                    )?;
                    hir::GenericArgumentKind::Error
                } else {
                    hir::GenericArgumentKind::BoundedCapacity(self.lower_expression(
                        context,
                        maximum,
                        depth + 1,
                    )?)
                }
            }
            syntax::BracketArgument::UnclassifiedTypeOrExpression { .. } => {
                let fragment_kind = match expected {
                    ExpectedArgument::Type => syntax::FragmentKind::Type,
                    ExpectedArgument::Constant
                    | ExpectedArgument::Region
                    | ExpectedArgument::Capacity => syntax::FragmentKind::Expression,
                };
                let parsed = &self.request.parsed_files[source.file.0 as usize];
                let parser = WrelaSyntaxParser::new();
                let output = parser
                    .parse_fragment(
                        syntax::FragmentParseRequest {
                            sources: self.request.sources,
                            parsed,
                            argument,
                            kind: fragment_kind,
                            limits: self.fragment_limits(),
                        },
                        self.is_cancelled,
                    )
                    .map_err(|failure| match failure {
                        syntax::ParseFailure::Cancelled => LowerFailure::Cancelled,
                        syntax::ParseFailure::ResourceLimit { resource, limit } => {
                            LowerFailure::ResourceLimit { resource, limit }
                        }
                        other => LowerFailure::InternalInvariant(other.to_string()),
                    })?;
                let (parsed_fragment, diagnostics) = output.into_parts();
                for diagnostic in diagnostics {
                    push(
                        &mut self.diagnostics,
                        diagnostic,
                        "diagnostics",
                        self.request.limits.diagnostics,
                    )?;
                }
                match (expected, parsed_fragment.fragment()) {
                    (ExpectedArgument::Type, syntax::SyntaxFragment::Type(ty)) => {
                        hir::GenericArgumentKind::Type(self.lower_type(context, ty, depth + 1)?)
                    }
                    (
                        ExpectedArgument::Constant,
                        syntax::SyntaxFragment::Expression(expression),
                    ) => hir::GenericArgumentKind::Constant(self.lower_expression(
                        context,
                        expression,
                        depth + 1,
                    )?),
                    (
                        ExpectedArgument::Capacity,
                        syntax::SyntaxFragment::Expression(expression),
                    ) => hir::GenericArgumentKind::Constant(self.lower_expression(
                        context,
                        expression,
                        depth + 1,
                    )?),
                    (ExpectedArgument::Region, syntax::SyntaxFragment::Expression(expression)) => {
                        self.lower_region_argument(context, expression)?
                    }
                    _ => {
                        return Err(LowerFailure::InternalInvariant(
                            "contextual parser returned the wrong fragment kind".to_owned(),
                        ));
                    }
                }
            }
            syntax::BracketArgument::Error(_) => hir::GenericArgumentKind::Error,
        };
        Ok(hir::GenericArgument { kind, source })
    }

    fn lower_region_argument(
        &mut self,
        context: ExpressionContext,
        expression: &syntax::Expression,
    ) -> Result<hir::GenericArgumentKind, LowerFailure> {
        let syntax::ExpressionKind::Name(name) = &expression.kind else {
            self.emit(
                "hir-region-argument-name",
                expression.meta.span,
                "a region generic argument must be one visible region name",
            )?;
            return Ok(hir::GenericArgumentKind::Error);
        };
        let Some(resolution) = self.resolve_qualified(context, name, ExpectedName::Region)? else {
            return Ok(hir::GenericArgumentKind::Error);
        };
        match resolution.target {
            ResolutionTarget::Region(region) => Ok(hir::GenericArgumentKind::Region(region)),
            ResolutionTarget::Definition(_) => Ok(hir::GenericArgumentKind::Error),
        }
    }

    fn fragment_limits(&self) -> syntax::ParseLimits {
        syntax::ParseLimits {
            tokens: self.request.limits.expressions,
            ast_nodes: self.request.limits.expressions,
            nesting_depth: self.request.limits.generic_classification_depth,
            literal_bytes: self.request.limits.payload_bytes,
            diagnostics: self.request.limits.diagnostics,
            diagnostic_bytes: self.request.limits.diagnostic_bytes,
        }
    }

    fn expected_arguments(
        &self,
        definition: &hir::Definition,
    ) -> Result<Vec<ExpectedArgument>, LowerFailure> {
        let mut output = Vec::new();
        match definition {
            hir::Definition::Declaration(resolved) => {
                let generics = &self.headers[resolved.declaration.0 as usize].generics;
                reserve(
                    &mut output,
                    generics.len(),
                    "expected generic arguments",
                    self.request.limits.generic_parameters,
                )?;
                for id in generics {
                    let expected = match self.program.generic_parameters[id.0 as usize].kind {
                        hir::GenericParameterKind::Type { .. } => ExpectedArgument::Type,
                        hir::GenericParameterKind::Constant { .. } => ExpectedArgument::Constant,
                        hir::GenericParameterKind::Region => ExpectedArgument::Region,
                    };
                    push(
                        &mut output,
                        expected,
                        "expected generic arguments",
                        self.request.limits.generic_parameters,
                    )?;
                }
            }
            hir::Definition::Builtin(builtin) => {
                let count = match builtin {
                    hir::Builtin::Option
                    | hir::Builtin::Actor
                    | hir::Builtin::Receipt
                    | hir::Builtin::Static
                    | hir::Builtin::Mmio => 1,
                    hir::Builtin::Result | hir::Builtin::Dma | hir::Builtin::Validated => 2,
                    _ => 0,
                };
                for _ in 0..count {
                    push(
                        &mut output,
                        ExpectedArgument::Type,
                        "expected generic arguments",
                        self.request.limits.generic_parameters,
                    )?;
                }
            }
            hir::Definition::Generic(_)
            | hir::Definition::Variant(_)
            | hir::Definition::Parameter(_)
            | hir::Definition::Local(_)
            | hir::Definition::Module { .. } => {}
        }
        Ok(output)
    }

    fn self_type_owner(&self, mut declaration: hir::DeclarationId) -> Option<hir::DeclarationId> {
        for _ in 0..=self.program.declarations.len() {
            let record = self.program.declarations.get(declaration.0 as usize)?;
            if matches!(
                self.plans[declaration.0 as usize].syntax,
                DeclarationSyntax::Structure(_)
                    | DeclarationSyntax::Enumeration(_)
                    | DeclarationSyntax::Interface(_)
                    | DeclarationSyntax::Implementation(_)
            ) {
                return Some(declaration);
            }
            let hir::DeclarationOwner::Declaration(parent) = record.owner else {
                return None;
            };
            declaration = parent;
        }
        None
    }

    fn resolve_qualified(
        &mut self,
        context: ExpressionContext,
        name: &syntax::QualifiedName,
        expected: ExpectedName,
    ) -> Result<Option<NameResolution>, LowerFailure> {
        let Some(first) = name.segments.first() else {
            return Ok(None);
        };
        if name.segments.len() == 1 {
            let resolution = self.resolve_unqualified(context, first, expected)?;
            if let Some(resolution) = &resolution {
                self.record_resolution(first, resolution)?;
            } else {
                self.emit(
                    "hir-unresolved-name",
                    first.meta.span,
                    "this name is not visible in the current package, module, or lexical scope",
                )?;
                if first.spelling != "self" {
                    self.record_error_use(first)?;
                }
            }
            return Ok(resolution);
        }

        let module = self.program.declarations[context.declaration.0 as usize].module;
        let mut best_module: Option<&ModuleImport> = None;
        for binding in &self.module_imports {
            if binding.module != module || binding.local_path.len() >= name.segments.len() {
                continue;
            }
            if binding
                .local_path
                .iter()
                .zip(&name.segments)
                .all(|(left, right)| left.as_str() == right.spelling)
                && best_module.is_none_or(|best| best.local_path.len() < binding.local_path.len())
            {
                best_module = Some(binding);
            }
        }
        if let Some(binding) = best_module.cloned() {
            if let Some(prefix) = name
                .segments
                .get(binding.local_path.len().saturating_sub(1))
            {
                self.push_use(ResolvedUse {
                    source: prefix.meta.span,
                    spelling: ReferenceSpelling::Identifier(self.name(prefix)?),
                    kind: BindingKind::Module,
                    target: Some(ResolvedBinding::Module {
                        package: binding.target_package,
                        module: binding.target_module,
                    }),
                })?;
            }
            let remaining = &name.segments[binding.local_path.len()..];
            let Some((mut namespace, mut consumed)) =
                self.lookup_module_symbol(binding.target_module, &remaining[0], true)
            else {
                self.emit(
                    "hir-unresolved-qualified-name",
                    remaining[0].meta.span,
                    "the imported module does not export this name",
                )?;
                self.record_error_use(remaining.last().unwrap_or(&remaining[0]))?;
                return Ok(None);
            };
            if let NamespaceTarget::Module { package, module } = &namespace {
                let (package, module) = (*package, *module);
                self.push_use(ResolvedUse {
                    source: remaining[0].meta.span,
                    spelling: ReferenceSpelling::Identifier(self.name(&remaining[0])?),
                    kind: BindingKind::Module,
                    target: Some(ResolvedBinding::Module { package, module }),
                })?;
                namespace = NamespaceTarget::Module { package, module };
            }
            while consumed < remaining.len() {
                let next = match &namespace {
                    NamespaceTarget::Symbol(target) => self
                        .lookup_child_symbol(target, &remaining[consumed], true)
                        .map(NamespaceTarget::Symbol),
                    NamespaceTarget::Module { module, .. } => self
                        .lookup_module_symbol(*module, &remaining[consumed], true)
                        .map(|(target, _)| target),
                };
                let Some(next) = next else {
                    self.emit(
                        "hir-unresolved-qualified-name",
                        remaining[consumed].meta.span,
                        "this namespace has no visible nested declaration, enum variant, or module with this name",
                    )?;
                    self.record_error_use(remaining.last().unwrap_or(&remaining[consumed]))?;
                    return Ok(None);
                };
                match next {
                    NamespaceTarget::Module { package, module } => {
                        self.push_use(ResolvedUse {
                            source: remaining[consumed].meta.span,
                            spelling: ReferenceSpelling::Identifier(
                                self.name(&remaining[consumed])?,
                            ),
                            kind: BindingKind::Module,
                            target: Some(ResolvedBinding::Module { package, module }),
                        })?;
                        namespace = NamespaceTarget::Module { package, module };
                    }
                    NamespaceTarget::Symbol(target) => {
                        namespace = NamespaceTarget::Symbol(target);
                    }
                }
                consumed += 1;
            }
            let NamespaceTarget::Symbol(target) = namespace else {
                self.emit(
                    "hir-qualified-name-kind",
                    name.meta.span,
                    "a module name is not a value or type in this source position",
                )?;
                return Ok(None);
            };
            let resolution = self.symbol_resolution(target, expected);
            if let Some(resolution) = &resolution {
                self.record_resolution(name.segments.last().unwrap_or(first), resolution)?;
            } else {
                self.emit(
                    "hir-qualified-name-kind",
                    name.meta.span,
                    "the resolved qualified name has the wrong kind for this source position",
                )?;
                self.record_error_use(name.segments.last().unwrap_or(first))?;
            }
            return Ok(resolution);
        }

        let Some(base) = self.resolve_unqualified(context, first, ExpectedName::Any)? else {
            self.emit(
                "hir-unresolved-qualified-base",
                first.meta.span,
                "the first component of this qualified name is not visible",
            )?;
            self.record_error_use(name.segments.last().unwrap_or(first))?;
            return Ok(None);
        };
        self.record_resolution(first, &base)?;
        let ResolutionTarget::Definition(definition) = base.target else {
            self.emit(
                "hir-region-qualified-name",
                name.meta.span,
                "region names do not have nested members",
            )?;
            self.record_error_use(name.segments.last().unwrap_or(first))?;
            return Ok(None);
        };
        let mut target = match definition {
            hir::Definition::Declaration(value) => SymbolTarget::Declaration(value),
            hir::Definition::Variant(value) => SymbolTarget::Variant(value),
            _ => {
                self.emit(
                    "hir-nonnamespace-qualified-name",
                    name.meta.span,
                    "this value does not introduce a source namespace",
                )?;
                self.record_error_use(name.segments.last().unwrap_or(first))?;
                return Ok(None);
            }
        };
        for segment in &name.segments[1..] {
            let Some(next) = self.lookup_child_symbol(&target, segment, false) else {
                self.emit(
                    "hir-unresolved-qualified-name",
                    segment.meta.span,
                    "this declaration has no nested declaration or enum variant with this name",
                )?;
                self.record_error_use(name.segments.last().unwrap_or(segment))?;
                return Ok(None);
            };
            target = next;
        }
        let resolution = self.symbol_resolution(target, expected);
        if let Some(resolution) = &resolution {
            self.record_resolution(name.segments.last().unwrap_or(first), resolution)?;
        } else {
            self.emit(
                "hir-qualified-name-kind",
                name.meta.span,
                "the resolved qualified name has the wrong kind for this source position",
            )?;
            self.record_error_use(name.segments.last().unwrap_or(first))?;
        }
        Ok(resolution)
    }

    fn lower_module_qualified_expression_kind(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Expression,
    ) -> Result<Option<hir::ExpressionKind>, LowerFailure> {
        let mut fields = Vec::new();
        let mut cursor = value;
        while let syntax::ExpressionKind::Field { base, field } = &cursor.kind {
            poll_cancellation(self.is_cancelled)?;
            push64(
                &mut fields,
                field,
                "qualified expression segments",
                self.request.limits.model_edges,
            )?;
            cursor = base;
        }
        let syntax::ExpressionKind::Name(root) = &cursor.kind else {
            return Ok(None);
        };
        let mut segments = Vec::new();
        reserve(
            &mut segments,
            root.segments.len().saturating_add(fields.len()),
            "qualified expression segments",
            self.request.limits.generic_classification_depth,
        )?;
        for segment in &root.segments {
            push(
                &mut segments,
                segment,
                "qualified expression segments",
                self.request.limits.generic_classification_depth,
            )?;
        }
        for field in fields.into_iter().rev() {
            push(
                &mut segments,
                field,
                "qualified expression segments",
                self.request.limits.generic_classification_depth,
            )?;
        }
        let module = self.program.declarations[context.declaration.0 as usize].module;
        let mut best_module: Option<&ModuleImport> = None;
        for binding in &self.module_imports {
            if binding.module != module || binding.local_path.len() >= segments.len() {
                continue;
            }
            if binding
                .local_path
                .iter()
                .zip(&segments)
                .all(|(left, right)| left.as_str() == right.spelling)
                && best_module.is_none_or(|best| best.local_path.len() < binding.local_path.len())
            {
                best_module = Some(binding);
            }
        }
        let Some(binding) = best_module.cloned() else {
            return Ok(None);
        };
        let prefix = segments[binding.local_path.len() - 1];
        let prefix_name = self.name(prefix)?;
        self.push_use(ResolvedUse {
            source: prefix.meta.span,
            spelling: ReferenceSpelling::Identifier(prefix_name),
            kind: BindingKind::Module,
            target: Some(ResolvedBinding::Module {
                package: binding.target_package,
                module: binding.target_module,
            }),
        })?;
        let remaining = &segments[binding.local_path.len()..];
        let Some((mut namespace, _)) =
            self.lookup_module_symbol(binding.target_module, remaining[0], true)
        else {
            self.emit(
                "hir-unresolved-qualified-name",
                remaining[0].meta.span,
                "the imported module does not export this name",
            )?;
            self.record_error_use(remaining.last().copied().unwrap_or(remaining[0]))?;
            return Ok(Some(hir::ExpressionKind::Error));
        };
        for segment in &remaining[1..] {
            let next = match &namespace {
                NamespaceTarget::Symbol(target) => self
                    .lookup_child_symbol(target, segment, true)
                    .map(NamespaceTarget::Symbol),
                NamespaceTarget::Module { module, .. } => self
                    .lookup_module_symbol(*module, segment, true)
                    .map(|(target, _)| target),
            };
            let Some(next) = next else {
                self.emit(
                    "hir-unresolved-qualified-name",
                    segment.meta.span,
                    "this namespace has no visible nested declaration, enum variant, or module with this name",
                )?;
                self.record_error_use(remaining.last().copied().unwrap_or(segment))?;
                return Ok(Some(hir::ExpressionKind::Error));
            };
            if let NamespaceTarget::Module { package, module } = &next {
                let spelling = self.name(segment)?;
                self.push_use(ResolvedUse {
                    source: segment.meta.span,
                    spelling: ReferenceSpelling::Identifier(spelling),
                    kind: BindingKind::Module,
                    target: Some(ResolvedBinding::Module {
                        package: *package,
                        module: *module,
                    }),
                })?;
            }
            namespace = next;
        }
        let NamespaceTarget::Symbol(target) = namespace else {
            self.emit(
                "hir-qualified-name-kind",
                value.meta.span,
                "a module name is not a runtime value in this source position",
            )?;
            return Ok(Some(hir::ExpressionKind::Error));
        };
        let Some(resolution) = self.symbol_resolution(target, ExpectedName::Value) else {
            self.emit(
                "hir-qualified-name-kind",
                value.meta.span,
                "the resolved qualified name is not a runtime value",
            )?;
            self.record_error_use(remaining.last().copied().unwrap_or(prefix))?;
            return Ok(Some(hir::ExpressionKind::Error));
        };
        self.record_resolution(remaining.last().copied().unwrap_or(prefix), &resolution)?;
        let ResolutionTarget::Definition(definition) = resolution.target else {
            return Ok(Some(hir::ExpressionKind::Error));
        };
        Ok(Some(hir::ExpressionKind::Reference(definition)))
    }

    fn resolve_unqualified(
        &self,
        context: ExpressionContext,
        identifier: &syntax::Identifier,
        expected: ExpectedName,
    ) -> Result<Option<NameResolution>, LowerFailure> {
        if identifier.spelling == "self" {
            if matches!(expected, ExpectedName::Value | ExpectedName::Any) {
                let parameter = self.find_receiver(context.declaration);
                return Ok(parameter.map(|id| NameResolution {
                    target: ResolutionTarget::Definition(hir::Definition::Parameter(id)),
                    kind: BindingKind::Parameter,
                    binding: ResolvedBinding::Parameter(id),
                }));
            }
            return Ok(None);
        }
        if let Some(binding) = self
            .lexical_overrides
            .iter()
            .rev()
            .find(|binding| binding.name.as_str() == identifier.spelling)
        {
            if resolution_matches(&binding.target, &binding.kind, expected) {
                return Ok(Some(NameResolution {
                    target: binding.target.clone(),
                    kind: binding.kind.clone(),
                    binding: binding_for_target(&binding.target, &binding.kind)?,
                }));
            }
        }
        if let Some(body) = self.body_stack.last() {
            if let Some(binding) = body
                .visible
                .iter()
                .rev()
                .find(|binding| binding.name.as_str() == identifier.spelling)
            {
                if resolution_matches(&binding.target, &binding.kind, expected) {
                    return Ok(Some(NameResolution {
                        target: binding.target.clone(),
                        kind: binding.kind.clone(),
                        binding: binding_for_target(&binding.target, &binding.kind)?,
                    }));
                }
            }
        }
        let mut declaration = context.declaration;
        for _ in 0..=self.program.declarations.len() {
            let header = &self.headers[declaration.0 as usize];
            for parameter in &header.parameters {
                let parameter = &self.program.parameters[parameter.0 as usize];
                if parameter
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == identifier.spelling)
                    && matches!(expected, ExpectedName::Value | ExpectedName::Any)
                {
                    return Ok(Some(NameResolution {
                        target: ResolutionTarget::Definition(hir::Definition::Parameter(
                            parameter.id,
                        )),
                        kind: BindingKind::Parameter,
                        binding: ResolvedBinding::Parameter(parameter.id),
                    }));
                }
            }
            for generic in &header.generics {
                let generic = &self.program.generic_parameters[generic.0 as usize];
                if generic.name.as_str() != identifier.spelling {
                    continue;
                }
                let (target, kind) = match generic.kind {
                    hir::GenericParameterKind::Type { .. } => (
                        ResolutionTarget::Definition(hir::Definition::Generic(generic.id)),
                        BindingKind::GenericType,
                    ),
                    hir::GenericParameterKind::Constant { .. } => (
                        ResolutionTarget::Definition(hir::Definition::Generic(generic.id)),
                        BindingKind::GenericConstant,
                    ),
                    hir::GenericParameterKind::Region => (
                        ResolutionTarget::Region(hir::RegionReference::Generic(generic.id)),
                        BindingKind::GenericRegion,
                    ),
                };
                if resolution_matches(&target, &kind, expected) {
                    return Ok(Some(NameResolution {
                        target,
                        kind,
                        binding: ResolvedBinding::Generic(generic.id),
                    }));
                }
            }
            if let Some(symbol) = self.symbols.iter().find(|symbol| {
                symbol.owner == SymbolOwner::Declaration(declaration)
                    && symbol.name.as_str() == identifier.spelling
            }) && let Some(resolution) = self.symbol_resolution(symbol.target.clone(), expected)
            {
                return Ok(Some(resolution));
            }
            let hir::DeclarationOwner::Declaration(parent) =
                self.program.declarations[declaration.0 as usize].owner
            else {
                break;
            };
            declaration = parent;
        }
        let module = self.program.declarations[context.declaration.0 as usize].module;
        if expected == ExpectedName::Any
            && let Some(binding) = self.module_imports.iter().find(|binding| {
                binding.module == module
                    && binding.local_path.len() == 1
                    && binding.local_path[0].as_str() == identifier.spelling
            })
        {
            return Ok(Some(NameResolution {
                target: ResolutionTarget::Definition(hir::Definition::Module {
                    package: binding.target_package,
                    module: binding.target_module,
                }),
                kind: BindingKind::Module,
                binding: ResolvedBinding::Module {
                    package: binding.target_package,
                    module: binding.target_module,
                },
            }));
        }
        if let Some(binding) = self.named_imports.iter().find(|binding| {
            binding.module == module && binding.local_name.as_str() == identifier.spelling
        }) && let Some(resolution) = self.symbol_resolution(binding.target.clone(), expected)
        {
            return Ok(Some(resolution));
        }
        if let Some(symbol) = self.symbols.iter().find(|symbol| {
            symbol.owner == SymbolOwner::Module(module)
                && symbol.name.as_str() == identifier.spelling
        }) && let Some(resolution) = self.symbol_resolution(symbol.target.clone(), expected)
        {
            return Ok(Some(resolution));
        }
        if let Some(binding) = self.prelude_bindings.iter().find(|binding| {
            binding.module == module && binding.local_name.as_str() == identifier.spelling
        }) && let Some(resolution) = self.symbol_resolution(binding.target.clone(), expected)
        {
            return Ok(Some(resolution));
        }
        if let Some(builtin) = builtin(&identifier.spelling) {
            let target = ResolutionTarget::Definition(hir::Definition::Builtin(builtin));
            let kind = BindingKind::Builtin;
            if resolution_matches(&target, &kind, expected) {
                return Ok(Some(NameResolution {
                    target,
                    kind,
                    binding: ResolvedBinding::Builtin(builtin),
                }));
            }
        }
        Ok(None)
    }

    fn lookup_module_symbol(
        &self,
        module: ModuleId,
        identifier: &syntax::Identifier,
        public_only: bool,
    ) -> Option<(NamespaceTarget, usize)> {
        if let Some(reexport) = self.program.modules[module.0 as usize]
            .reexports
            .iter()
            .find(|reexport| reexport.local_name.as_str() == identifier.spelling)
        {
            let target = match &reexport.target {
                hir::ReexportTarget::Declaration(value) => {
                    NamespaceTarget::Symbol(SymbolTarget::Declaration(value.clone()))
                }
                hir::ReexportTarget::Variant(value) => {
                    NamespaceTarget::Symbol(SymbolTarget::Variant(value.clone()))
                }
                hir::ReexportTarget::Module { package, module } => NamespaceTarget::Module {
                    package: *package,
                    module: *module,
                },
            };
            return Some((target, 1));
        }
        self.symbols.iter().find_map(|symbol| {
            let target_module = match &symbol.target {
                SymbolTarget::Declaration(value) => value.module,
                SymbolTarget::Variant(value) => value.enumeration.module,
            };
            let module_namespace = match &symbol.target {
                SymbolTarget::Declaration(_) => symbol.owner == SymbolOwner::Module(module),
                SymbolTarget::Variant(value) => matches!(
                    self.program.declarations[value.enumeration.declaration.0 as usize].owner,
                    hir::DeclarationOwner::Module(owner) if owner == module
                ),
            };
            if target_module != module
                || !module_namespace
                || symbol.name.as_str() != identifier.spelling
            {
                return None;
            }
            let visible = match &symbol.target {
                SymbolTarget::Declaration(value) => {
                    self.program.declarations[value.declaration.0 as usize].visibility
                        != hir::Visibility::Private
                }
                SymbolTarget::Variant(value) => {
                    self.program.declarations[value.enumeration.declaration.0 as usize].visibility
                        != hir::Visibility::Private
                }
            };
            (!public_only || visible).then(|| (NamespaceTarget::Symbol(symbol.target.clone()), 1))
        })
    }

    fn lookup_child_symbol(
        &self,
        target: &SymbolTarget,
        identifier: &syntax::Identifier,
        public_only: bool,
    ) -> Option<SymbolTarget> {
        let SymbolTarget::Declaration(declaration) = target else {
            return None;
        };
        self.symbols
            .iter()
            .find(|symbol| {
                symbol.owner == SymbolOwner::Declaration(declaration.declaration)
                    && symbol.name.as_str() == identifier.spelling
                    && (!public_only
                        || match &symbol.target {
                            SymbolTarget::Declaration(value) => {
                                self.program.declarations[value.declaration.0 as usize].visibility
                                    != hir::Visibility::Private
                            }
                            SymbolTarget::Variant(_) => true,
                        })
            })
            .map(|symbol| symbol.target.clone())
    }

    fn symbol_resolution(
        &self,
        target: SymbolTarget,
        expected: ExpectedName,
    ) -> Option<NameResolution> {
        if expected == ExpectedName::Type {
            match &target {
                SymbolTarget::Declaration(value)
                    if !matches!(
                        self.plans[value.declaration.0 as usize].syntax,
                        DeclarationSyntax::Brand(_)
                            | DeclarationSyntax::Structure(_)
                            | DeclarationSyntax::Enumeration(_)
                            | DeclarationSyntax::Interface(_)
                    ) =>
                {
                    return None;
                }
                SymbolTarget::Variant(_) => return None,
                SymbolTarget::Declaration(_) => {}
            }
        }
        let (definition, kind, binding) = match target {
            SymbolTarget::Declaration(value) => (
                hir::Definition::Declaration(value.clone()),
                BindingKind::Declaration,
                ResolvedBinding::Declaration(value),
            ),
            SymbolTarget::Variant(value) => (
                hir::Definition::Variant(value.clone()),
                BindingKind::Variant,
                ResolvedBinding::Variant(value),
            ),
        };
        let resolution_target = ResolutionTarget::Definition(definition);
        resolution_matches(&resolution_target, &kind, expected).then_some(NameResolution {
            target: resolution_target,
            kind,
            binding,
        })
    }

    fn record_resolution(
        &mut self,
        identifier: &syntax::Identifier,
        resolution: &NameResolution,
    ) -> Result<(), LowerFailure> {
        // `unit` is a keyword-backed builtin, not a source identifier, so it
        // deliberately has no `ReferenceSpelling::Identifier` representation.
        if identifier.spelling == "unit" {
            return Ok(());
        }
        let spelling = if identifier.spelling == "self" {
            ReferenceSpelling::SelfValue
        } else {
            ReferenceSpelling::Identifier(self.name(identifier)?)
        };
        self.push_use(ResolvedUse {
            source: identifier.meta.span,
            spelling,
            kind: resolution.kind.clone(),
            target: Some(resolution.binding.clone()),
        })?;
        if let ResolutionTarget::Definition(definition) = &resolution.target {
            for frame in &mut self.capture_stack {
                let captured = match definition {
                    hir::Definition::Parameter(id) => id.0 < frame.first_parameter,
                    hir::Definition::Local(id) => id.0 < frame.first_local,
                    _ => false,
                };
                if captured && !frame.captures.contains(definition) {
                    push64(
                        &mut frame.captures,
                        definition.clone(),
                        "closure captures",
                        self.request.limits.model_edges,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn record_declaration_use(
        &mut self,
        identifier: &syntax::Identifier,
        declaration: hir::DeclarationId,
    ) -> Result<(), LowerFailure> {
        let module = self.program.declarations[declaration.0 as usize].module;
        let package = self.program.modules[module.0 as usize].package;
        let target = hir::ResolvedDeclaration {
            package,
            module,
            declaration,
        };
        self.record_resolution(
            identifier,
            &NameResolution {
                target: ResolutionTarget::Definition(hir::Definition::Declaration(target.clone())),
                kind: BindingKind::Declaration,
                binding: ResolvedBinding::Declaration(target),
            },
        )
    }

    fn find_receiver(&self, declaration: hir::DeclarationId) -> Option<hir::ParameterId> {
        let mut current = declaration;
        for _ in 0..=self.program.declarations.len() {
            if let Some(receiver) = self.headers[current.0 as usize]
                .parameters
                .iter()
                .find(|id| self.program.parameters[id.0 as usize].receiver)
            {
                return Some(*receiver);
            }
            let hir::DeclarationOwner::Declaration(parent) =
                self.program.declarations[current.0 as usize].owner
            else {
                return None;
            };
            current = parent;
        }
        None
    }

    fn declaration_bindings(
        &self,
        declaration: hir::DeclarationId,
    ) -> Result<Vec<OwnedVisibleBinding>, LowerFailure> {
        let mut output = Vec::new();
        for parameter in &self.headers[declaration.0 as usize].parameters {
            let parameter = &self.program.parameters[parameter.0 as usize];
            if let Some(name) = &parameter.name {
                push64(
                    &mut output,
                    OwnedVisibleBinding {
                        name: name.clone(),
                        target: ResolutionTarget::Definition(hir::Definition::Parameter(
                            parameter.id,
                        )),
                        kind: BindingKind::Parameter,
                    },
                    "declaration bindings",
                    self.request.limits.model_edges,
                )?;
            }
        }
        for generic in &self.headers[declaration.0 as usize].generics {
            let generic = &self.program.generic_parameters[generic.0 as usize];
            let (target, kind) = match generic.kind {
                hir::GenericParameterKind::Type { .. } => (
                    ResolutionTarget::Definition(hir::Definition::Generic(generic.id)),
                    BindingKind::GenericType,
                ),
                hir::GenericParameterKind::Constant { .. } => (
                    ResolutionTarget::Definition(hir::Definition::Generic(generic.id)),
                    BindingKind::GenericConstant,
                ),
                hir::GenericParameterKind::Region => (
                    ResolutionTarget::Region(hir::RegionReference::Generic(generic.id)),
                    BindingKind::GenericRegion,
                ),
            };
            push64(
                &mut output,
                OwnedVisibleBinding {
                    name: generic.name.clone(),
                    target,
                    kind,
                },
                "declaration bindings",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn lower_root_suite(
        &mut self,
        owner: hir::BodyOwner,
        declaration: hir::DeclarationId,
        suite: &syntax::Suite,
        visible: Vec<OwnedVisibleBinding>,
    ) -> Result<hir::BodyId, LowerFailure> {
        self.lower_statement_list_body(
            owner,
            declaration,
            suite.meta.span,
            &suite.statements,
            visible,
            None,
        )
    }

    fn lower_statement_list_body(
        &mut self,
        owner: hir::BodyOwner,
        declaration: hir::DeclarationId,
        source: Span,
        statements: &[syntax::Statement],
        visible: Vec<OwnedVisibleBinding>,
        parent_scope: Option<hir::ScopeId>,
    ) -> Result<hir::BodyId, LowerFailure> {
        let body = self.begin_body(owner, declaration, source, visible, parent_scope)?;
        self.lower_into_current_body(statements)?;
        self.finish_body(body)?;
        Ok(body)
    }

    fn begin_body(
        &mut self,
        owner: hir::BodyOwner,
        declaration: hir::DeclarationId,
        source: Span,
        visible: Vec<OwnedVisibleBinding>,
        parent_scope: Option<hir::ScopeId>,
    ) -> Result<hir::BodyId, LowerFailure> {
        let body = hir::BodyId(u32::try_from(self.program.bodies.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "bodies",
                limit: u64::from(self.request.limits.bodies),
            }
        })?);
        let scope = hir::ScopeId(u32::try_from(self.program.scopes.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "scopes",
                limit: u64::from(self.request.limits.scopes),
            }
        })?);
        push(
            &mut self.program.bodies,
            hir::Body {
                id: body,
                owner,
                scope,
                locals: Vec::new(),
                statements: Vec::new(),
                source,
            },
            "bodies",
            self.request.limits.bodies,
        )?;
        push(
            &mut self.program.scopes,
            hir::LexicalScope {
                id: scope,
                body,
                parent: parent_scope,
                source,
            },
            "scopes",
            self.request.limits.scopes,
        )?;
        push(
            &mut self.body_stack,
            BodyContext {
                body,
                scope,
                owner_declaration: declaration,
                visible,
            },
            "body context stack",
            self.request.limits.generic_classification_depth,
        )?;
        Ok(body)
    }

    fn finish_body(&mut self, expected: hir::BodyId) -> Result<(), LowerFailure> {
        let context = self.body_stack.pop().ok_or_else(|| {
            LowerFailure::InternalInvariant("body context stack underflow".to_owned())
        })?;
        if context.body != expected {
            return Err(LowerFailure::InternalInvariant(
                "body context stack ended out of order".to_owned(),
            ));
        }
        Ok(())
    }

    fn lower_into_current_body(
        &mut self,
        statements: &[syntax::Statement],
    ) -> Result<(), LowerFailure> {
        let body = self.current_body()?.body;
        for statement in statements {
            poll_cancellation(self.is_cancelled)?;
            let id = self.lower_statement(statement)?;
            push(
                &mut self.program.bodies[body.0 as usize].statements,
                id,
                "body statements",
                self.request.limits.statements,
            )?;
        }
        Ok(())
    }

    fn current_body(&self) -> Result<&BodyContext, LowerFailure> {
        self.body_stack.last().ok_or_else(|| {
            LowerFailure::InternalInvariant("body lowering requires a lexical body".to_owned())
        })
    }

    fn current_body_mut(&mut self) -> Result<&mut BodyContext, LowerFailure> {
        self.body_stack.last_mut().ok_or_else(|| {
            LowerFailure::InternalInvariant("body lowering requires a lexical body".to_owned())
        })
    }

    fn push_current_visible(
        &mut self,
        binding: OwnedVisibleBinding,
        resource: &'static str,
    ) -> Result<(), LowerFailure> {
        let limit = self.request.limits.model_edges;
        push64(
            &mut self.current_body_mut()?.visible,
            binding,
            resource,
            limit,
        )
    }

    fn current_expression_context(&self) -> Result<ExpressionContext, LowerFailure> {
        let body = self.current_body()?;
        Ok(ExpressionContext {
            owner: hir::ExpressionOwner::Body(body.body),
            scope: Some(body.scope),
            declaration: body.owner_declaration,
        })
    }

    fn current_visible(&self) -> Result<Vec<OwnedVisibleBinding>, LowerFailure> {
        self.clone_visible_bindings(&self.current_body()?.visible)
    }

    fn visible_or_empty(&self) -> Result<Vec<OwnedVisibleBinding>, LowerFailure> {
        self.body_stack.last().map_or_else(
            || Ok(Vec::new()),
            |body| self.clone_visible_bindings(&body.visible),
        )
    }

    fn clone_visible_bindings(
        &self,
        bindings: &[OwnedVisibleBinding],
    ) -> Result<Vec<OwnedVisibleBinding>, LowerFailure> {
        let mut output = Vec::new();
        for binding in bindings {
            push64(
                &mut output,
                binding.clone(),
                "visible lexical bindings",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn lower_child_suite(
        &mut self,
        suite: &syntax::Suite,
        parent_scope: hir::ScopeId,
        extra_visible: &[OwnedVisibleBinding],
    ) -> Result<hir::BodyId, LowerFailure> {
        let (parent_body, parent_declaration) = {
            let parent = self.current_body()?;
            (parent.body, parent.owner_declaration)
        };
        let mut visible = self.current_visible()?;
        for binding in extra_visible {
            push64(
                &mut visible,
                binding.clone(),
                "visible lexical bindings",
                self.request.limits.model_edges,
            )?;
        }
        self.lower_statement_list_body(
            self.program.bodies[parent_body.0 as usize].owner,
            parent_declaration,
            suite.meta.span,
            &suite.statements,
            visible,
            Some(parent_scope),
        )
    }

    fn lower_statement(
        &mut self,
        statement: &syntax::Statement,
    ) -> Result<hir::StatementId, LowerFailure> {
        let (body, scope, owner_declaration) = {
            let body = self.current_body()?;
            (body.body, body.scope, body.owner_declaration)
        };
        let id = self.allocate_statement(body, statement.meta.span)?;
        let context = self.current_expression_context()?;
        let kind = match &statement.kind {
            syntax::StatementKind::LocalAssignment {
                shadow,
                name,
                ty,
                value,
            } => {
                let visible_local = self
                    .resolve_unqualified(context, name, ExpectedName::Value)?
                    .and_then(|resolution| match resolution {
                        NameResolution {
                            target: ResolutionTarget::Definition(hir::Definition::Local(local)),
                            kind: BindingKind::Local,
                            binding: ResolvedBinding::Local(binding),
                        } if local == binding => Some(local),
                        _ => None,
                    });
                let value = self.lower_expression(context, value, 0)?;
                if !*shadow
                    && ty.is_none()
                    && let Some(local) = visible_local
                {
                    self.record_resolution(
                        name,
                        &NameResolution {
                            target: ResolutionTarget::Definition(hir::Definition::Local(local)),
                            kind: BindingKind::Local,
                            binding: ResolvedBinding::Local(local),
                        },
                    )?;
                    let mut targets = Vec::new();
                    push64(
                        &mut targets,
                        hir::PlaceTarget {
                            root: hir::Definition::Local(local),
                            projections: Vec::new(),
                            source: name.meta.span,
                        },
                        "assignment targets",
                        self.request.limits.model_edges,
                    )?;
                    hir::StatementKind::Assign {
                        targets,
                        operator: hir::AssignmentOperator::Assign,
                        value,
                    }
                } else {
                    let ty = ty
                        .as_ref()
                        .map(|ty| self.lower_type(context, ty, 0))
                        .transpose()?;
                    let name_value = self.name(name)?;
                    let shadowed = visible_local;
                    if *shadow && shadowed.is_none() {
                        self.emit(
                            "hir-shadow-without-binding",
                            name.meta.span,
                            "shadow requires an earlier local binding with the same name",
                        )?;
                    } else if !*shadow && shadowed.is_some() {
                        self.emit(
                            "hir-local-redeclaration-requires-shadow",
                            name.meta.span,
                            "use shadow to intentionally replace an earlier local binding",
                        )?;
                    }
                    let local = self.allocate_local(
                        body,
                        scope,
                        name_value.clone(),
                        ty,
                        shadowed,
                        name.meta.span,
                    )?;
                    self.push_current_visible(
                        OwnedVisibleBinding {
                            name: name_value,
                            target: ResolutionTarget::Definition(hir::Definition::Local(local)),
                            kind: BindingKind::Local,
                        },
                        "visible lexical bindings",
                    )?;
                    hir::StatementKind::Initialize { local, value }
                }
            }
            syntax::StatementKind::PlaceAssignment {
                target,
                operator,
                value,
            } => {
                let mut targets = Vec::new();
                self.lower_assignment_target(context, target, &mut targets, 0)?;
                if targets.is_empty() {
                    self.emit(
                        "hir-invalid-assignment-target",
                        statement.meta.span,
                        "assignment requires at least one resolvable place target",
                    )?;
                    hir::StatementKind::Error
                } else {
                    hir::StatementKind::Assign {
                        targets,
                        operator: lower_assignment_operator(*operator),
                        value: self.lower_expression(context, value, 0)?,
                    }
                }
            }
            syntax::StatementKind::Return(value) => hir::StatementKind::Return(
                value
                    .as_ref()
                    .map(|value| self.lower_expression(context, value, 0))
                    .transpose()?,
            ),
            syntax::StatementKind::Break => hir::StatementKind::Break,
            syntax::StatementKind::Continue => hir::StatementKind::Continue,
            syntax::StatementKind::Pass => hir::StatementKind::Pass,
            syntax::StatementKind::Assert { condition, message } => hir::StatementKind::Assert {
                condition: self.lower_expression(context, condition, 0)?,
                expression: self.assertion_expression(condition)?,
                witness: hir::AssertionSourceWitness {
                    source: condition.meta.span,
                    expression: self.assertion_expression(condition)?,
                },
                message: message
                    .as_ref()
                    .map(|literal| self.literal_message(literal))
                    .transpose()?,
                comptime: false,
            },
            syntax::StatementKind::ComptimeAssert { condition, message } => {
                hir::StatementKind::Assert {
                    condition: self.lower_expression(context, condition, 0)?,
                    expression: self.assertion_expression(condition)?,
                    witness: hir::AssertionSourceWitness {
                        source: condition.meta.span,
                        expression: self.assertion_expression(condition)?,
                    },
                    message: message
                        .as_ref()
                        .map(|literal| self.literal_message(literal))
                        .transpose()?,
                    comptime: true,
                }
            }
            syntax::StatementKind::Send(value) => {
                hir::StatementKind::Send(self.lower_expression(context, value, 0)?)
            }
            syntax::StatementKind::Yield(value) => {
                hir::StatementKind::Yield(self.lower_expression(context, value, 0)?)
            }
            syntax::StatementKind::Expression(value) => {
                hir::StatementKind::Expression(self.lower_expression(context, value, 0)?)
            }
            syntax::StatementKind::If(value) => {
                self.lower_if_statement(value, statement.meta.span)?
            }
            syntax::StatementKind::Match { scrutinee, arms } => {
                self.lower_match_statement(context, scrutinee, arms)?
            }
            syntax::StatementKind::For {
                take_binding,
                binding,
                take_iterable,
                iterable,
                body,
            } => {
                let iterable = self.lower_expression(context, iterable, 0)?;
                let (parent_body, parent_scope, parent_declaration) = {
                    let parent = self.current_body()?;
                    (parent.body, parent.scope, parent.owner_declaration)
                };
                let visible = self.current_visible()?;
                let child = self.begin_body(
                    self.program.bodies[parent_body.0 as usize].owner,
                    parent_declaration,
                    statement.meta.span,
                    visible,
                    Some(parent_scope),
                )?;
                let child_scope = self.current_body()?.scope;
                let name = self.name(binding)?;
                let local = self.allocate_local(
                    child,
                    child_scope,
                    name.clone(),
                    None,
                    None,
                    binding.meta.span,
                )?;
                self.push_current_visible(
                    OwnedVisibleBinding {
                        name,
                        target: ResolutionTarget::Definition(hir::Definition::Local(local)),
                        kind: BindingKind::Local,
                    },
                    "visible lexical bindings",
                )?;
                self.lower_into_current_body(&body.statements)?;
                self.finish_body(child)?;
                hir::StatementKind::For {
                    take_binding: *take_binding,
                    binding: local,
                    take_iterable: *take_iterable,
                    iterable,
                    body: child,
                }
            }
            syntax::StatementKind::While { condition, body } => hir::StatementKind::While {
                condition: self.lower_expression(context, condition, 0)?,
                body: self.lower_child_suite(body, scope, &[])?,
            },
            syntax::StatementKind::Loop(body) => hir::StatementKind::Loop {
                body: self.lower_child_suite(body, scope, &[])?,
            },
            syntax::StatementKind::With {
                value,
                binding,
                body,
            } => self.lower_with_statement(
                context,
                value,
                binding.as_ref(),
                body,
                statement.meta.span,
            )?,
            syntax::StatementKind::ComptimeIf {
                condition,
                then_suite,
                else_suite,
            } => hir::StatementKind::ComptimeIf {
                condition: self.lower_expression(context, condition, 0)?,
                then_body: self.lower_child_suite(then_suite, scope, &[])?,
                else_body: else_suite
                    .as_ref()
                    .map(|suite| self.lower_child_suite(suite, scope, &[]))
                    .transpose()?,
            },
            syntax::StatementKind::Error(_) => hir::StatementKind::Error,
        };
        let loop_statement = matches!(
            kind,
            hir::StatementKind::For { .. }
                | hir::StatementKind::While { .. }
                | hir::StatementKind::Loop { .. }
        );
        let attributes = if loop_statement {
            self.lower_attributes(
                owner_declaration,
                &statement.attributes,
                hir::ExpressionOwner::Body(body),
                Some(scope),
                true,
            )?
        } else {
            if !statement.attributes.is_empty() {
                self.emit(
                    "hir-statement-attribute-requires-loop",
                    statement.meta.span,
                    "statement attributes are only legal on for, while, or loop",
                )?;
            }
            Vec::new()
        };
        self.program.statements[id.0 as usize].attributes = attributes;
        self.program.statements[id.0 as usize].kind = kind;
        Ok(id)
    }

    fn assertion_expression(
        &mut self,
        condition: &syntax::Expression,
    ) -> Result<String, LowerFailure> {
        let source = self
            .request
            .sources
            .span_text(condition.meta.span)
            .ok_or_else(|| {
                LowerFailure::InternalInvariant(
                    "assertion condition source span is not retained".to_owned(),
                )
            })?;
        clone_text(source, self.request.limits.payload_bytes)
    }

    fn allocate_statement(
        &mut self,
        body: hir::BodyId,
        source: Span,
    ) -> Result<hir::StatementId, LowerFailure> {
        let id = hir::StatementId(u32::try_from(self.program.statements.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "statements",
                limit: u64::from(self.request.limits.statements),
            }
        })?);
        push(
            &mut self.program.statements,
            hir::Statement {
                id,
                body,
                attributes: Vec::new(),
                kind: hir::StatementKind::Error,
                source,
            },
            "statements",
            self.request.limits.statements,
        )?;
        Ok(id)
    }

    fn allocate_local(
        &mut self,
        body: hir::BodyId,
        scope: hir::ScopeId,
        name: hir::Name,
        ty: Option<hir::TypeExpression>,
        shadowed: Option<hir::LocalId>,
        source: Span,
    ) -> Result<hir::LocalId, LowerFailure> {
        let id = hir::LocalId(u32::try_from(self.program.locals.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "locals",
                limit: u64::from(self.request.limits.locals),
            }
        })?);
        push(
            &mut self.program.locals,
            hir::Local {
                id,
                body,
                scope,
                name,
                ty,
                shadowed,
                source,
            },
            "locals",
            self.request.limits.locals,
        )?;
        push(
            &mut self.program.bodies[body.0 as usize].locals,
            id,
            "body locals",
            self.request.limits.locals,
        )?;
        Ok(id)
    }

    fn lower_assignment_target(
        &mut self,
        context: ExpressionContext,
        target: &syntax::AssignmentTarget,
        output: &mut Vec<hir::PlaceTarget>,
        depth: u32,
    ) -> Result<(), LowerFailure> {
        self.check_depth(depth)?;
        match target {
            syntax::AssignmentTarget::Place(expression) => {
                let Some(place) = self.lower_place(context, expression, depth + 1)? else {
                    self.emit(
                        "hir-invalid-place-expression",
                        expression.meta.span,
                        "this expression cannot be used as an assignment place",
                    )?;
                    return Ok(());
                };
                push64(
                    output,
                    place,
                    "assignment targets",
                    self.request.limits.model_edges,
                )
            }
            syntax::AssignmentTarget::Tuple { elements, .. } => {
                for element in elements {
                    self.lower_assignment_target(context, element, output, depth + 1)?;
                }
                Ok(())
            }
            syntax::AssignmentTarget::Error(_) => Ok(()),
        }
    }

    fn lower_place(
        &mut self,
        context: ExpressionContext,
        expression: &syntax::Expression,
        depth: u32,
    ) -> Result<Option<hir::PlaceTarget>, LowerFailure> {
        self.check_depth(depth)?;
        match &expression.kind {
            syntax::ExpressionKind::Name(name) => {
                let Some(resolution) =
                    self.resolve_qualified(context, name, ExpectedName::Value)?
                else {
                    return Ok(None);
                };
                let ResolutionTarget::Definition(root) = resolution.target else {
                    return Ok(None);
                };
                Ok(Some(hir::PlaceTarget {
                    root,
                    projections: Vec::new(),
                    source: expression.meta.span,
                }))
            }
            syntax::ExpressionKind::Field { base, field } => {
                let Some(mut place) = self.lower_place(context, base, depth + 1)? else {
                    return Ok(None);
                };
                push64(
                    &mut place.projections,
                    hir::PlaceProjection::Field(self.name(field)?),
                    "place projections",
                    self.request.limits.model_edges,
                )?;
                place.source = expression.meta.span;
                Ok(Some(place))
            }
            syntax::ExpressionKind::Index { base, index } => {
                let Some(mut place) = self.lower_place(context, base, depth + 1)? else {
                    return Ok(None);
                };
                let index = self.lower_expression(context, index, depth + 1)?;
                push64(
                    &mut place.projections,
                    hir::PlaceProjection::Index(index),
                    "place projections",
                    self.request.limits.model_edges,
                )?;
                place.source = expression.meta.span;
                Ok(Some(place))
            }
            syntax::ExpressionKind::Parenthesized(inner) => {
                self.lower_place(context, inner, depth + 1)
            }
            _ => Ok(None),
        }
    }

    fn lower_if_statement(
        &mut self,
        value: &syntax::IfStatement,
        statement_source: Span,
    ) -> Result<hir::StatementKind, LowerFailure> {
        // Runtime semantic IR intentionally has a binary structured `If`.
        // Preserve source short-circuit order by representing every `elif` as
        // the sole statement in the preceding branch's synthetic else body.
        // Keeping the construction iterative avoids a source-sized Rust call
        // stack; `begin_body` still applies the explicit lexical-depth bound.
        let branch_count = value
            .elif
            .len()
            .checked_add(1)
            .ok_or(LowerFailure::ResourceLimit {
                resource: "if branches",
                limit: self.request.limits.model_edges,
            })?;
        if u64::try_from(branch_count).map_or(true, |count| count > self.request.limits.model_edges)
        {
            return Err(LowerFailure::ResourceLimit {
                resource: "if branches",
                limit: self.request.limits.model_edges,
            });
        }

        let mut outer = None;
        let mut synthetic_bodies = Vec::new();
        for branch_index in 0..branch_count {
            poll_cancellation(self.is_cancelled)?;
            let nested_statement = if branch_index == 0 {
                None
            } else {
                let source = self.elif_tail_source(value, branch_index - 1, statement_source)?;
                let body = self.current_body()?.body;
                Some((self.allocate_statement(body, source)?, body))
            };
            let (source_condition, source_suite) = if branch_index == 0 {
                (&value.condition, &value.then_suite)
            } else {
                let (condition, suite) = &value.elif[branch_index - 1];
                (condition, suite)
            };
            let context = self.current_expression_context()?;
            let parent_scope = self.current_body()?.scope;
            let condition = self.lower_expression(context, source_condition, 0)?;
            let (success_scope, bindings) = self.condition_bindings(condition)?;
            let then_body = self.lower_child_suite(
                source_suite,
                success_scope.unwrap_or(parent_scope),
                &bindings,
            )?;
            let mut branches = Vec::new();
            push64(
                &mut branches,
                (condition, then_body),
                "if branches",
                self.request.limits.model_edges,
            )?;

            let else_body = if branch_index + 1 < branch_count {
                let source = self.elif_tail_source(value, branch_index, statement_source)?;
                let (parent_body, parent_declaration) = {
                    let parent = self.current_body()?;
                    (parent.body, parent.owner_declaration)
                };
                let visible = self.current_visible()?;
                let body = self.begin_body(
                    self.program.bodies[parent_body.0 as usize].owner,
                    parent_declaration,
                    source,
                    visible,
                    Some(parent_scope),
                )?;
                push(
                    &mut synthetic_bodies,
                    body,
                    "if normalization body stack",
                    self.request.limits.generic_classification_depth,
                )?;
                Some(body)
            } else {
                value
                    .else_suite
                    .as_ref()
                    .map(|suite| self.lower_child_suite(suite, parent_scope, &[]))
                    .transpose()?
            };
            let kind = hir::StatementKind::If {
                branches,
                else_body,
            };
            if let Some((statement, body)) = nested_statement {
                self.program.statements[statement.0 as usize].kind = kind;
                push(
                    &mut self.program.bodies[body.0 as usize].statements,
                    statement,
                    "body statements",
                    self.request.limits.statements,
                )?;
            } else {
                outer = Some(kind);
            }
        }
        while let Some(body) = synthetic_bodies.pop() {
            self.finish_body(body)?;
        }
        outer.ok_or_else(|| {
            LowerFailure::InternalInvariant("if normalization produced no outer branch".to_owned())
        })
    }

    fn elif_tail_source(
        &self,
        value: &syntax::IfStatement,
        elif_index: usize,
        statement_source: Span,
    ) -> Result<Span, LowerFailure> {
        let condition = value
            .elif
            .get(elif_index)
            .map(|branch| &branch.0)
            .ok_or_else(|| {
                LowerFailure::InternalInvariant("if normalization lost an elif branch".to_owned())
            })?;
        let parsed = self
            .request
            .parsed_files
            .get(condition.meta.span.file.0 as usize)
            .filter(|parsed| parsed.file() == condition.meta.span.file)
            .ok_or_else(|| {
                LowerFailure::InternalInvariant(
                    "if normalization cannot find the branch source file".to_owned(),
                )
            })?;
        let first_condition_token = condition.meta.tokens.first.0 as usize;
        let elif = first_condition_token
            .checked_sub(1)
            .and_then(|index| parsed.lexical().tokens.get(index))
            .filter(|token| token.kind == syntax::TokenKind::Keyword(syntax::Keyword::Elif))
            .ok_or_else(|| {
                LowerFailure::InternalInvariant(
                    "if normalization cannot recover the elif keyword span".to_owned(),
                )
            })?;
        if elif.span.file != statement_source.file
            || condition.meta.span.file != statement_source.file
            || elif.span.range.start > statement_source.range.end
        {
            return Err(LowerFailure::InternalInvariant(
                "if normalization found inconsistent source spans".to_owned(),
            ));
        }
        Ok(Span {
            file: statement_source.file,
            range: TextRange {
                start: elif.span.range.start,
                end: statement_source.range.end,
            },
        })
    }

    fn lower_match_statement(
        &mut self,
        context: ExpressionContext,
        scrutinee: &syntax::Expression,
        arms: &[syntax::MatchArm],
    ) -> Result<hir::StatementKind, LowerFailure> {
        let scrutinee = self.lower_expression(context, scrutinee, 0)?;
        let (parent_body, parent_scope, parent_declaration) = {
            let parent = self.current_body()?;
            (parent.body, parent.scope, parent.owner_declaration)
        };
        let parent_visible = self.current_visible()?;
        let mut lowered_arms = Vec::new();
        for arm in arms {
            let visible = self.clone_visible_bindings(&parent_visible)?;
            let body = self.begin_body(
                self.program.bodies[parent_body.0 as usize].owner,
                parent_declaration,
                arm.meta.span,
                visible,
                Some(parent_scope),
            )?;
            let scope = self.current_body()?.scope;
            let arm_context = ExpressionContext {
                owner: hir::ExpressionOwner::Body(body),
                scope: Some(scope),
                declaration: parent_declaration,
            };
            let pattern =
                self.lower_pattern(arm_context, &arm.pattern, Some(scope), &mut Vec::new(), 0)?;
            let bindings = self.pattern_bindings(pattern)?;
            for binding in bindings {
                self.push_current_visible(binding, "visible pattern bindings")?;
            }
            let guard = arm
                .guard
                .as_ref()
                .map(|guard| self.lower_expression(arm_context, guard, 0))
                .transpose()?;
            self.lower_into_current_body(&arm.body.statements)?;
            self.finish_body(body)?;
            push64(
                &mut lowered_arms,
                hir::MatchArm {
                    pattern,
                    guard,
                    body,
                    source: arm.meta.span,
                },
                "match arms",
                self.request.limits.model_edges,
            )?;
        }
        Ok(hir::StatementKind::Match {
            scrutinee,
            arms: lowered_arms,
        })
    }

    fn lower_with_statement(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Expression,
        binding: Option<&syntax::WithBinding>,
        suite: &syntax::Suite,
        statement_source: Span,
    ) -> Result<hir::StatementKind, LowerFailure> {
        let value = self.lower_expression(context, value, 0)?;
        let (parent_body, parent_scope, parent_declaration) = {
            let parent = self.current_body()?;
            (parent.body, parent.scope, parent.owner_declaration)
        };
        let visible = self.current_visible()?;
        let body = self.begin_body(
            self.program.bodies[parent_body.0 as usize].owner,
            parent_declaration,
            statement_source,
            visible,
            Some(parent_scope),
        )?;
        let scope = self.current_body()?.scope;
        let local = binding
            .map(|binding| {
                let name = self.name(&binding.name)?;
                let local = self.allocate_local(
                    body,
                    scope,
                    name.clone(),
                    None,
                    None,
                    binding.name.meta.span,
                )?;
                self.push_current_visible(
                    OwnedVisibleBinding {
                        name,
                        target: ResolutionTarget::Definition(hir::Definition::Local(local)),
                        kind: BindingKind::Local,
                    },
                    "visible with bindings",
                )?;
                Ok::<_, LowerFailure>(local)
            })
            .transpose()?;
        let region = binding
            .and_then(|binding| binding.region.as_ref())
            .map(|identifier| {
                let id =
                    hir::RegionId(u32::try_from(self.program.regions.len()).map_err(|_| {
                        LowerFailure::ResourceLimit {
                            resource: "regions",
                            limit: u64::from(self.request.limits.regions),
                        }
                    })?);
                let name = self.name(identifier)?;
                push(
                    &mut self.program.regions,
                    hir::RegionBinding {
                        id,
                        body,
                        name: name.clone(),
                        source: identifier.meta.span,
                    },
                    "regions",
                    self.request.limits.regions,
                )?;
                self.push_current_visible(
                    OwnedVisibleBinding {
                        name,
                        target: ResolutionTarget::Region(hir::RegionReference::Local(id)),
                        kind: BindingKind::LocalRegion,
                    },
                    "visible regions",
                )?;
                Ok::<_, LowerFailure>(id)
            })
            .transpose()?;
        self.lower_into_current_body(&suite.statements)?;
        self.finish_body(body)?;
        Ok(hir::StatementKind::With {
            value,
            binding: local,
            region,
            body,
        })
    }

    fn condition_bindings(
        &self,
        expression: hir::ExpressionId,
    ) -> Result<(Option<hir::ScopeId>, Vec<OwnedVisibleBinding>), LowerFailure> {
        let expression = &self.program.expressions[expression.0 as usize];
        match &expression.kind {
            hir::ExpressionKind::IsPattern { pattern, .. } => Ok((
                self.program.patterns[pattern.0 as usize].binding_scope,
                self.pattern_bindings(*pattern)?,
            )),
            hir::ExpressionKind::Binary {
                operator: hir::BinaryOperator::LogicalAnd,
                left,
                right,
            } => {
                let (left_scope, mut left_bindings) = self.condition_bindings(*left)?;
                let (right_scope, right_bindings) = self.condition_bindings(*right)?;
                for binding in right_bindings {
                    push64(
                        &mut left_bindings,
                        binding,
                        "condition bindings",
                        self.request.limits.model_edges,
                    )?;
                }
                Ok((right_scope.or(left_scope), left_bindings))
            }
            _ => Ok((None, Vec::new())),
        }
    }

    fn pattern_bindings(
        &self,
        pattern: hir::PatternId,
    ) -> Result<Vec<OwnedVisibleBinding>, LowerFailure> {
        let mut ids = Vec::new();
        let mut stack = Vec::new();
        push(
            &mut stack,
            pattern,
            "pattern binding traversal",
            self.request.limits.patterns,
        )?;
        while let Some(pattern) = stack.pop() {
            poll_cancellation(self.is_cancelled)?;
            for alternative in &self.program.patterns[pattern.0 as usize].alternatives {
                match &alternative.kind {
                    hir::PrimaryPattern::Bind(binding) => push(
                        &mut ids,
                        *binding,
                        "pattern bindings",
                        self.request.limits.locals,
                    )?,
                    hir::PrimaryPattern::Constructor { arguments, .. }
                    | hir::PrimaryPattern::Tuple(arguments)
                    | hir::PrimaryPattern::Array(arguments) => {
                        for argument in arguments {
                            push(
                                &mut stack,
                                argument.pattern,
                                "pattern binding traversal",
                                self.request.limits.patterns,
                            )?;
                        }
                    }
                    hir::PrimaryPattern::Wildcard
                    | hir::PrimaryPattern::Literal { .. }
                    | hir::PrimaryPattern::Error => {}
                }
            }
        }
        ids.sort_unstable();
        ids.dedup();
        let mut output = Vec::new();
        for id in ids {
            let local = &self.program.locals[id.0 as usize];
            push64(
                &mut output,
                OwnedVisibleBinding {
                    name: local.name.clone(),
                    target: ResolutionTarget::Definition(hir::Definition::Local(id)),
                    kind: BindingKind::Local,
                },
                "visible pattern bindings",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn literal_message(&mut self, literal: &syntax::Literal) -> Result<String, LowerFailure> {
        match &literal.value {
            syntax::LiteralValue::Text(value) => {
                clone_text(value, self.request.limits.payload_bytes)
            }
            _ => {
                self.emit(
                    "hir-assert-message-string",
                    literal.meta.span,
                    "an assertion message must be a decoded string literal",
                )?;
                clone_text(
                    "invalid assertion message",
                    self.request.limits.payload_bytes,
                )
            }
        }
    }

    fn lower_expression(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Expression,
        depth: u32,
    ) -> Result<hir::ExpressionId, LowerFailure> {
        self.lower_expression_expected(context, value, depth, ExpectedName::Value)
    }

    fn lower_expression_expected(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Expression,
        depth: u32,
        expected: ExpectedName,
    ) -> Result<hir::ExpressionId, LowerFailure> {
        self.check_depth(depth)?;
        poll_cancellation(self.is_cancelled)?;
        if let syntax::ExpressionKind::Parenthesized(inner) = &value.kind {
            return self.lower_expression_expected(context, inner, depth + 1, expected);
        }
        let module_qualified_kind = self.lower_module_qualified_expression_kind(context, value)?;
        let id =
            hir::ExpressionId(u32::try_from(self.program.expressions.len()).map_err(|_| {
                LowerFailure::ResourceLimit {
                    resource: "expressions",
                    limit: u64::from(self.request.limits.expressions),
                }
            })?);
        push(
            &mut self.program.expressions,
            hir::Expression {
                id,
                owner: context.owner,
                scope: context.scope,
                kind: hir::ExpressionKind::Error,
                source: value.meta.span,
            },
            "expressions",
            self.request.limits.expressions,
        )?;
        let kind = if let Some(kind) = module_qualified_kind {
            kind
        } else {
            match &value.kind {
                syntax::ExpressionKind::Literal(literal) => match self.lower_literal(literal)? {
                    Some(literal) => hir::ExpressionKind::Literal(literal),
                    None => hir::ExpressionKind::Error,
                },
                syntax::ExpressionKind::Name(name) => {
                    let Some(resolution) = self.resolve_qualified(context, name, expected)? else {
                        self.program.expressions[id.0 as usize].kind = hir::ExpressionKind::Error;
                        return Ok(id);
                    };
                    let ResolutionTarget::Definition(definition) = resolution.target else {
                        self.emit(
                            "hir-region-used-as-value",
                            name.meta.span,
                            "a proof-only region name cannot be used as a runtime value",
                        )?;
                        self.program.expressions[id.0 as usize].kind = hir::ExpressionKind::Error;
                        return Ok(id);
                    };
                    hir::ExpressionKind::Reference(definition)
                }
                syntax::ExpressionKind::Closure {
                    asynchronous,
                    take_captures,
                    parameters,
                    body,
                } => self.lower_closure_expression(
                    id,
                    context,
                    ClosureSyntax {
                        asynchronous: *asynchronous,
                        take_captures: *take_captures,
                        parameters,
                        body,
                    },
                    depth + 1,
                )?,
                syntax::ExpressionKind::Unary { operator, operand } => hir::ExpressionKind::Unary {
                    operator: lower_unary_operator(*operator),
                    operand: self.lower_expression(context, operand, depth + 1)?,
                },
                syntax::ExpressionKind::Binary {
                    operator,
                    left,
                    right,
                } => {
                    let left = self.lower_expression(context, left, depth + 1)?;
                    let (right_context, overrides) =
                        if *operator == syntax::BinaryOperator::LogicalAnd {
                            let (scope, bindings) = self.condition_bindings(left)?;
                            (
                                ExpressionContext {
                                    scope: scope.or(context.scope),
                                    ..context
                                },
                                bindings,
                            )
                        } else {
                            (context, Vec::new())
                        };
                    let override_start = self.lexical_overrides.len();
                    for binding in overrides {
                        push64(
                            &mut self.lexical_overrides,
                            binding,
                            "logical-and bindings",
                            self.request.limits.model_edges,
                        )?;
                    }
                    let right = self.lower_expression(right_context, right, depth + 1)?;
                    self.lexical_overrides.truncate(override_start);
                    hir::ExpressionKind::Binary {
                        operator: lower_binary_operator(*operator),
                        left,
                        right,
                    }
                }
                syntax::ExpressionKind::Comparison { first, tails } => {
                    if tails.len() != 1 {
                        self.emit(
                            "hir-comparison-chain",
                            value.meta.span,
                            "comparison operators do not chain in revision 0.1",
                        )?;
                        hir::ExpressionKind::Error
                    } else {
                        let tail = &tails[0];
                        hir::ExpressionKind::Compare {
                            left: self.lower_expression(context, first, depth + 1)?,
                            operator: lower_comparison_operator(tail.operator),
                            right: self.lower_expression(context, &tail.right, depth + 1)?,
                        }
                    }
                }
                syntax::ExpressionKind::IsPattern {
                    value,
                    negated,
                    pattern,
                } => {
                    let scrutinee = self.lower_expression(context, value, depth + 1)?;
                    let binding_scope = match context.owner {
                        hir::ExpressionOwner::Body(body) => Some(self.allocate_synthetic_scope(
                            body,
                            context.scope.ok_or_else(|| {
                                LowerFailure::InternalInvariant(
                                    "body expression had no lexical scope".to_owned(),
                                )
                            })?,
                            pattern.meta.span,
                        )?),
                        hir::ExpressionOwner::Declaration(_) | hir::ExpressionOwner::Closure(_) => {
                            None
                        }
                    };
                    let pattern = self.lower_pattern(
                        context,
                        pattern,
                        binding_scope,
                        &mut Vec::new(),
                        depth + 1,
                    )?;
                    hir::ExpressionKind::IsPattern {
                        value: scrutinee,
                        negated: *negated,
                        pattern,
                    }
                }
                syntax::ExpressionKind::Range {
                    start,
                    end,
                    inclusive,
                } => hir::ExpressionKind::Range {
                    start: self.lower_expression(context, start, depth + 1)?,
                    end: self.lower_expression(context, end, depth + 1)?,
                    inclusive: *inclusive,
                },
                syntax::ExpressionKind::Cast { value, ty } => hir::ExpressionKind::Cast {
                    value: self.lower_expression(context, value, depth + 1)?,
                    ty: self.lower_type(context, ty, depth + 1)?,
                },
                syntax::ExpressionKind::Try(inner) => {
                    hir::ExpressionKind::Try(self.lower_expression(context, inner, depth + 1)?)
                }
                syntax::ExpressionKind::Field { base, field } => hir::ExpressionKind::Field {
                    base: self.lower_expression_expected(
                        context,
                        base,
                        depth + 1,
                        ExpectedName::Any,
                    )?,
                    name: self.name(field)?,
                },
                syntax::ExpressionKind::Call { callee, arguments } => {
                    if !self.valid_call_argument_order(arguments)? {
                        self.emit(
                        "hir-invalid-call-arguments",
                        value.meta.span,
                        "call arguments must place positional values first and use each name once",
                    )?;
                        hir::ExpressionKind::Error
                    } else if arguments.iter().any(|argument| {
                        matches!(
                            &argument.value,
                            syntax::ArgumentValue::InvalidExclusive { .. }
                        )
                    }) {
                        hir::ExpressionKind::Error
                    } else {
                        let callee = self.lower_expression(context, callee, depth + 1)?;
                        let mut lowered_arguments = Vec::new();
                        for argument in arguments {
                            let argument_value = match &argument.value {
                                syntax::ArgumentValue::Value(value) => {
                                    hir::CallArgumentValue::Value(self.lower_expression(
                                        context,
                                        value,
                                        depth + 1,
                                    )?)
                                }
                                syntax::ArgumentValue::Exclusive { access, place } => {
                                    let place_source = place.meta.span;
                                    let Some(place) =
                                        self.lower_place(context, place, depth + 1)?
                                    else {
                                        return Err(LowerFailure::InternalInvariant(format!(
                                            "sealed exclusive call place at {:?} did not lower",
                                            place_source
                                        )));
                                    };
                                    hir::CallArgumentValue::Exclusive {
                                        access: match access {
                                            syntax::ExclusiveAccess::Mutate => {
                                                hir::ExclusiveAccess::Mutate
                                            }
                                            syntax::ExclusiveAccess::Take => {
                                                hir::ExclusiveAccess::Take
                                            }
                                        },
                                        place,
                                    }
                                }
                                syntax::ArgumentValue::InvalidExclusive { .. } => unreachable!(
                                    "invalid exclusive arguments are rejected before lowering"
                                ),
                            };
                            push64(
                                &mut lowered_arguments,
                                hir::CallArgument {
                                    name: argument
                                        .name
                                        .as_ref()
                                        .map(|name| self.call_argument_name(name))
                                        .transpose()?,
                                    value: argument_value,
                                    source: argument.meta.span,
                                },
                                "call arguments",
                                self.request.limits.model_edges,
                            )?;
                        }
                        hir::ExpressionKind::Call {
                            callee,
                            arguments: lowered_arguments,
                        }
                    }
                }
                syntax::ExpressionKind::Index { base, index } => hir::ExpressionKind::Index {
                    base: self.lower_expression(context, base, depth + 1)?,
                    index: self.lower_expression(context, index, depth + 1)?,
                },
                syntax::ExpressionKind::Tuple(values) => hir::ExpressionKind::Tuple(
                    self.lower_expression_list(context, values, depth + 1)?,
                ),
                syntax::ExpressionKind::Array(values) => hir::ExpressionKind::Array(
                    self.lower_expression_list(context, values, depth + 1)?,
                ),
                syntax::ExpressionKind::DotName { name, .. } => {
                    let spelling = self.name(name)?;
                    let candidates = self.visible_variant_candidates(context, &spelling, false)?;
                    if candidates.is_empty() {
                        self.emit(
                            "hir-unresolved-dot-variant",
                            name.meta.span,
                            "this dot-variant name does not resolve to a visible enum variant",
                        )?;
                        hir::ExpressionKind::Error
                    } else {
                        hir::ExpressionKind::DotName {
                            spelling,
                            candidates,
                        }
                    }
                }
                syntax::ExpressionKind::TrySend(inner) => hir::ExpressionKind::TrySend(
                    self.lower_expression(context, inner, depth + 1)?,
                ),
                syntax::ExpressionKind::If {
                    condition,
                    then_branch,
                    elif_branches,
                    else_branch,
                } => {
                    let mut lowered_elif = Vec::new();
                    for (elif_condition, elif_branch) in elif_branches {
                        let condition =
                            self.lower_expression(context, elif_condition, depth + 1)?;
                        let branch = self.lower_expression(context, elif_branch, depth + 1)?;
                        push64(
                            &mut lowered_elif,
                            (condition, branch),
                            "if expression elif branches",
                            self.request.limits.model_edges,
                        )?;
                    }
                    hir::ExpressionKind::If {
                        condition: self.lower_expression(context, condition, depth + 1)?,
                        then_branch: self.lower_expression(context, then_branch, depth + 1)?,
                        elif_branches: lowered_elif,
                        else_branch: self.lower_expression(context, else_branch, depth + 1)?,
                    }
                }
                syntax::ExpressionKind::Interpolated(parts) => {
                    let mut output = Vec::new();
                    for part in parts {
                        let part = match part {
                            syntax::InterpolationPart::Text { span, decoded } => {
                                hir::InterpolationPart::Text {
                                    value: clone_text(decoded, self.request.limits.payload_bytes)?,
                                    source: *span,
                                }
                            }
                            syntax::InterpolationPart::Value {
                                expression,
                                format,
                                format_span,
                            } => hir::InterpolationPart::Value {
                                expression: self.lower_expression(
                                    context,
                                    expression,
                                    depth + 1,
                                )?,
                                format: format
                                    .as_ref()
                                    .map(|value| {
                                        clone_text(value, self.request.limits.payload_bytes)
                                    })
                                    .transpose()?,
                                format_source: *format_span,
                            },
                        };
                        push64(
                            &mut output,
                            part,
                            "interpolation parts",
                            self.request.limits.model_edges,
                        )?;
                    }
                    hir::ExpressionKind::Interpolate(output)
                }
                syntax::ExpressionKind::Parenthesized(_) => {
                    return Err(LowerFailure::InternalInvariant(
                        "parenthesized expression reached post-normalization lowering".to_owned(),
                    ));
                }
                syntax::ExpressionKind::Error(_) => hir::ExpressionKind::Error,
            }
        };
        self.program.expressions[id.0 as usize].kind = kind;
        Ok(id)
    }

    fn lower_expression_list(
        &mut self,
        context: ExpressionContext,
        values: &[syntax::Expression],
        depth: u32,
    ) -> Result<Vec<hir::ExpressionId>, LowerFailure> {
        let mut output = Vec::new();
        for value in values {
            let id = self.lower_expression(context, value, depth + 1)?;
            push64(
                &mut output,
                id,
                "expression list",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn valid_call_argument_order(
        &self,
        arguments: &[syntax::Argument],
    ) -> Result<bool, LowerFailure> {
        let mut names = Vec::new();
        for argument in arguments {
            poll_cancellation(self.is_cancelled)?;
            if let Some(name) = &argument.name {
                push64(
                    &mut names,
                    name.spelling.as_str(),
                    "call argument names",
                    self.request.limits.model_edges,
                )?;
            }
        }
        names.sort_unstable();
        Ok(names.windows(2).all(|pair| pair[0] != pair[1]))
    }

    fn lower_closure_expression(
        &mut self,
        expression: hir::ExpressionId,
        outer_context: ExpressionContext,
        syntax: ClosureSyntax<'_>,
        depth: u32,
    ) -> Result<hir::ExpressionKind, LowerFailure> {
        let first_parameter = u32::try_from(self.program.parameters.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "parameters",
                limit: u64::from(self.request.limits.parameters),
            }
        })?;
        let first_local =
            u32::try_from(self.program.locals.len()).map_err(|_| LowerFailure::ResourceLimit {
                resource: "locals",
                limit: u64::from(self.request.limits.locals),
            })?;
        let mut parameter_ids = Vec::new();
        let override_start = self.lexical_overrides.len();
        for parameter in syntax.parameters {
            if parameter.receiver {
                self.emit(
                    "hir-closure-receiver",
                    parameter.meta.span,
                    "closures cannot declare a self receiver",
                )?;
                continue;
            }
            let name = self.name(&parameter.name)?;
            if self.lexical_overrides[override_start..]
                .iter()
                .any(|binding| binding.name == name)
            {
                self.emit(
                    "hir-duplicate-closure-parameter",
                    parameter.name.meta.span,
                    "this closure parameter duplicates an earlier parameter",
                )?;
                continue;
            }
            let parameter_context = ExpressionContext {
                owner: hir::ExpressionOwner::Closure(expression),
                scope: None,
                declaration: outer_context.declaration,
            };
            let ty = parameter
                .ty
                .as_ref()
                .map(|ty| self.lower_type(parameter_context, ty, depth + 1))
                .transpose()?;
            if ty.is_none() {
                self.emit(
                    "hir-missing-closure-parameter-type",
                    parameter.meta.span,
                    "closure parameters require an explicit type",
                )?;
                continue;
            }
            let id =
                hir::ParameterId(u32::try_from(self.program.parameters.len()).map_err(|_| {
                    LowerFailure::ResourceLimit {
                        resource: "parameters",
                        limit: u64::from(self.request.limits.parameters),
                    }
                })?);
            push(
                &mut self.program.parameters,
                hir::Parameter {
                    id,
                    owner: hir::CallableOwner::Closure(expression),
                    name: Some(name.clone()),
                    access: lower_access(parameter.access),
                    ty,
                    receiver: false,
                    positional_only: parameter.positional_only,
                    source: parameter.meta.span,
                },
                "parameters",
                self.request.limits.parameters,
            )?;
            push(
                &mut parameter_ids,
                id,
                "closure parameters",
                self.request.limits.parameters,
            )?;
            push64(
                &mut self.lexical_overrides,
                OwnedVisibleBinding {
                    name,
                    target: ResolutionTarget::Definition(hir::Definition::Parameter(id)),
                    kind: BindingKind::Parameter,
                },
                "closure parameter bindings",
                self.request.limits.model_edges,
            )?;
        }
        push(
            &mut self.capture_stack,
            CaptureFrame {
                first_parameter,
                first_local,
                captures: Vec::new(),
            },
            "closure capture stack",
            self.request.limits.generic_classification_depth,
        )?;
        let body = match syntax.body {
            syntax::ClosureBody::Expression(source_expression) => {
                let mut visible = self.visible_or_empty()?;
                for binding in &self.lexical_overrides[override_start..] {
                    push64(
                        &mut visible,
                        binding.clone(),
                        "closure visible bindings",
                        self.request.limits.model_edges,
                    )?;
                }
                let body = self.begin_body(
                    hir::BodyOwner::Closure(expression),
                    outer_context.declaration,
                    source_expression.meta.span,
                    visible,
                    None,
                )?;
                let body_context = self.current_expression_context()?;
                let value = self.lower_expression(body_context, source_expression, depth + 1)?;
                let statement =
                    hir::StatementId(u32::try_from(self.program.statements.len()).map_err(
                        |_| LowerFailure::ResourceLimit {
                            resource: "statements",
                            limit: u64::from(self.request.limits.statements),
                        },
                    )?);
                push(
                    &mut self.program.statements,
                    hir::Statement {
                        id: statement,
                        body,
                        attributes: Vec::new(),
                        kind: hir::StatementKind::Return(Some(value)),
                        source: source_expression.meta.span,
                    },
                    "statements",
                    self.request.limits.statements,
                )?;
                push(
                    &mut self.program.bodies[body.0 as usize].statements,
                    statement,
                    "body statements",
                    self.request.limits.statements,
                )?;
                self.finish_body(body)?;
                hir::ClosureBody::Body(body)
            }
            syntax::ClosureBody::Suite(suite) => {
                let mut visible = self.visible_or_empty()?;
                for binding in &self.lexical_overrides[override_start..] {
                    push64(
                        &mut visible,
                        binding.clone(),
                        "closure visible bindings",
                        self.request.limits.model_edges,
                    )?;
                }
                hir::ClosureBody::Body(self.lower_root_suite(
                    hir::BodyOwner::Closure(expression),
                    outer_context.declaration,
                    suite,
                    visible,
                )?)
            }
        };
        let frame = self.capture_stack.pop().ok_or_else(|| {
            LowerFailure::InternalInvariant("closure capture stack underflow".to_owned())
        })?;
        self.lexical_overrides.truncate(override_start);
        Ok(hir::ExpressionKind::Closure {
            color: if syntax.asynchronous {
                hir::FunctionColor::Async
            } else {
                hir::FunctionColor::Sync
            },
            take_captures: syntax.take_captures,
            parameters: parameter_ids,
            body,
            captures: frame.captures,
        })
    }

    fn lower_literal(
        &mut self,
        literal: &syntax::Literal,
    ) -> Result<Option<hir::Literal>, LowerFailure> {
        let value = match &literal.value {
            syntax::LiteralValue::IntegerSpelling => hir::Literal::Integer(clone_text(
                &literal.spelling,
                self.request.limits.payload_bytes,
            )?),
            syntax::LiteralValue::FloatSpelling => hir::Literal::Float(clone_text(
                &literal.spelling,
                self.request.limits.payload_bytes,
            )?),
            syntax::LiteralValue::Text(value) => {
                hir::Literal::String(clone_text(value, self.request.limits.payload_bytes)?)
            }
            syntax::LiteralValue::Bytes(value) => {
                let mut bytes = Vec::new();
                if value.len() as u64 > self.request.limits.payload_bytes {
                    return Err(LowerFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: self.request.limits.payload_bytes,
                    });
                }
                bytes
                    .try_reserve_exact(value.len())
                    .map_err(|_| LowerFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: self.request.limits.payload_bytes,
                    })?;
                bytes.extend_from_slice(value);
                hir::Literal::Bytes(bytes)
            }
            syntax::LiteralValue::Character(value) => hir::Literal::Character(*value),
            syntax::LiteralValue::Boolean(value) => hir::Literal::Boolean(*value),
            syntax::LiteralValue::Unit => hir::Literal::Unit,
            syntax::LiteralValue::Invalid => {
                self.emit(
                    "hir-invalid-literal",
                    literal.meta.span,
                    "this recovered literal has no valid decoded value",
                )?;
                return Ok(None);
            }
        };
        Ok(Some(value))
    }

    fn allocate_synthetic_scope(
        &mut self,
        body: hir::BodyId,
        parent: hir::ScopeId,
        source: Span,
    ) -> Result<hir::ScopeId, LowerFailure> {
        let id = hir::ScopeId(u32::try_from(self.program.scopes.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "scopes",
                limit: u64::from(self.request.limits.scopes),
            }
        })?);
        push(
            &mut self.program.scopes,
            hir::LexicalScope {
                id,
                body,
                parent: Some(parent),
                source,
            },
            "scopes",
            self.request.limits.scopes,
        )?;
        Ok(id)
    }

    fn lower_pattern(
        &mut self,
        context: ExpressionContext,
        value: &syntax::Pattern,
        binding_scope: Option<hir::ScopeId>,
        shared_bindings: &mut Vec<(hir::Name, hir::LocalId)>,
        depth: u32,
    ) -> Result<hir::PatternId, LowerFailure> {
        self.check_depth(depth)?;
        poll_cancellation(self.is_cancelled)?;
        let id = hir::PatternId(u32::try_from(self.program.patterns.len()).map_err(|_| {
            LowerFailure::ResourceLimit {
                resource: "patterns",
                limit: u64::from(self.request.limits.patterns),
            }
        })?);
        push(
            &mut self.program.patterns,
            hir::Pattern {
                id,
                owner: context.owner,
                binding_scope,
                alternatives: Vec::new(),
                source: value.meta.span,
            },
            "patterns",
            self.request.limits.patterns,
        )?;
        let mut alternatives = Vec::new();
        for alternative in &value.alternatives {
            let source = primary_pattern_span(alternative);
            let kind = self.lower_primary_pattern(
                context,
                alternative,
                binding_scope,
                shared_bindings,
                depth + 1,
            )?;
            push64(
                &mut alternatives,
                hir::PatternAlternative { kind, source },
                "pattern alternatives",
                self.request.limits.model_edges,
            )?;
        }
        if alternatives.is_empty() {
            push64(
                &mut alternatives,
                hir::PatternAlternative {
                    kind: hir::PrimaryPattern::Error,
                    source: value.meta.span,
                },
                "pattern alternatives",
                self.request.limits.model_edges,
            )?;
        }
        self.program.patterns[id.0 as usize].alternatives = alternatives;
        Ok(id)
    }

    fn lower_primary_pattern(
        &mut self,
        context: ExpressionContext,
        value: &syntax::PrimaryPattern,
        binding_scope: Option<hir::ScopeId>,
        shared_bindings: &mut Vec<(hir::Name, hir::LocalId)>,
        depth: u32,
    ) -> Result<hir::PrimaryPattern, LowerFailure> {
        self.check_depth(depth)?;
        match value {
            syntax::PrimaryPattern::Wildcard(_) => Ok(hir::PrimaryPattern::Wildcard),
            syntax::PrimaryPattern::Literal { negative, literal } => {
                let Some(literal) = self.lower_literal(literal)? else {
                    return Ok(hir::PrimaryPattern::Error);
                };
                Ok(hir::PrimaryPattern::Literal {
                    negative: *negative,
                    literal,
                })
            }
            syntax::PrimaryPattern::Bind(identifier) => {
                let Some(local) =
                    self.pattern_binding(binding_scope, identifier, shared_bindings)?
                else {
                    return Ok(hir::PrimaryPattern::Error);
                };
                Ok(hir::PrimaryPattern::Bind(local))
            }
            syntax::PrimaryPattern::Constructor { name, arguments } => {
                let identifier = name.segments.last().ok_or_else(|| {
                    LowerFailure::InternalInvariant(
                        "constructor pattern has no name segment".to_owned(),
                    )
                })?;
                let spelling = self.name(identifier)?;
                let candidates = self.constructor_candidates(context, name)?;
                if candidates.is_empty() {
                    self.emit(
                        "hir-unresolved-pattern-constructor",
                        name.meta.span,
                        "this pattern constructor does not resolve to a visible enum variant",
                    )?;
                    if name.segments.len() == 1 {
                        self.record_error_use(identifier)?;
                    }
                    return Ok(hir::PrimaryPattern::Error);
                }
                if candidates.len() == 1 {
                    let candidate = candidates[0].clone();
                    self.record_resolution(
                        identifier,
                        &NameResolution {
                            target: ResolutionTarget::Definition(hir::Definition::Variant(
                                candidate.clone(),
                            )),
                            kind: BindingKind::Variant,
                            binding: ResolvedBinding::Variant(candidate),
                        },
                    )?;
                }
                let lowered_arguments = self.lower_pattern_arguments(
                    context,
                    arguments,
                    binding_scope,
                    shared_bindings,
                    depth + 1,
                )?;
                Ok(hir::PrimaryPattern::Constructor {
                    spelling,
                    candidates,
                    arguments: lowered_arguments,
                })
            }
            syntax::PrimaryPattern::DotVariant {
                name, arguments, ..
            } => {
                let spelling = self.name(name)?;
                let candidates = self.visible_variant_candidates(context, &spelling, false)?;
                if candidates.is_empty() {
                    self.emit(
                        "hir-unresolved-pattern-constructor",
                        name.meta.span,
                        "this pattern constructor does not resolve to a visible enum variant",
                    )?;
                    self.record_error_use(name)?;
                    return Ok(hir::PrimaryPattern::Error);
                }
                if candidates.len() == 1 {
                    let candidate = candidates[0].clone();
                    self.record_resolution(
                        name,
                        &NameResolution {
                            target: ResolutionTarget::Definition(hir::Definition::Variant(
                                candidate.clone(),
                            )),
                            kind: BindingKind::Variant,
                            binding: ResolvedBinding::Variant(candidate),
                        },
                    )?;
                }
                let lowered_arguments = self.lower_pattern_arguments(
                    context,
                    arguments,
                    binding_scope,
                    shared_bindings,
                    depth + 1,
                )?;
                Ok(hir::PrimaryPattern::Constructor {
                    spelling,
                    candidates,
                    arguments: lowered_arguments,
                })
            }
            syntax::PrimaryPattern::Tuple { elements, .. } => {
                let arguments = self.lower_pattern_arguments(
                    context,
                    elements,
                    binding_scope,
                    shared_bindings,
                    depth + 1,
                )?;
                Ok(hir::PrimaryPattern::Tuple(arguments))
            }
            syntax::PrimaryPattern::Array { elements, .. } => {
                let arguments = self.lower_pattern_arguments(
                    context,
                    elements,
                    binding_scope,
                    shared_bindings,
                    depth + 1,
                )?;
                Ok(hir::PrimaryPattern::Array(arguments))
            }
            syntax::PrimaryPattern::Error(_) => Ok(hir::PrimaryPattern::Error),
        }
    }

    fn lower_pattern_arguments(
        &mut self,
        context: ExpressionContext,
        arguments: &[syntax::PatternArgument],
        binding_scope: Option<hir::ScopeId>,
        shared_bindings: &mut Vec<(hir::Name, hir::LocalId)>,
        depth: u32,
    ) -> Result<Vec<hir::PatternArgument>, LowerFailure> {
        let mut output = Vec::new();
        for argument in arguments {
            let pattern = self.lower_pattern(
                context,
                &argument.pattern,
                binding_scope,
                shared_bindings,
                depth + 1,
            )?;
            push64(
                &mut output,
                hir::PatternArgument {
                    take: argument.take,
                    pattern,
                    source: argument.meta.span,
                },
                "pattern arguments",
                self.request.limits.model_edges,
            )?;
        }
        Ok(output)
    }

    fn pattern_binding(
        &mut self,
        binding_scope: Option<hir::ScopeId>,
        identifier: &syntax::Identifier,
        shared_bindings: &mut Vec<(hir::Name, hir::LocalId)>,
    ) -> Result<Option<hir::LocalId>, LowerFailure> {
        let Some(scope) = binding_scope else {
            self.emit(
                "hir-pattern-binding-without-scope",
                identifier.meta.span,
                "this pattern binding has no lexical success scope",
            )?;
            return Ok(None);
        };
        let name = self.name(identifier)?;
        if let Some((_, local)) = shared_bindings
            .iter()
            .find(|(existing, _)| *existing == name)
        {
            return Ok(Some(*local));
        }
        let body = self.program.scopes[scope.0 as usize].body;
        let local =
            self.allocate_local(body, scope, name.clone(), None, None, identifier.meta.span)?;
        push64(
            shared_bindings,
            (name, local),
            "pattern bindings",
            self.request.limits.model_edges,
        )?;
        Ok(Some(local))
    }

    fn constructor_candidates(
        &mut self,
        context: ExpressionContext,
        name: &syntax::QualifiedName,
    ) -> Result<Vec<hir::ResolvedVariant>, LowerFailure> {
        if name.segments.len() == 1 {
            let spelling = self.name(&name.segments[0])?;
            return self.visible_variant_candidates(context, &spelling, false);
        }
        let Some(resolution) = self.resolve_qualified(context, name, ExpectedName::Any)? else {
            return Ok(Vec::new());
        };
        match resolution.target {
            ResolutionTarget::Definition(hir::Definition::Variant(variant)) => {
                let mut output = Vec::new();
                push64(
                    &mut output,
                    variant,
                    "pattern variant candidates",
                    self.request.limits.model_edges,
                )?;
                Ok(output)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn visible_variant_candidates(
        &self,
        context: ExpressionContext,
        spelling: &hir::Name,
        fieldless_only: bool,
    ) -> Result<Vec<hir::ResolvedVariant>, LowerFailure> {
        let module = self.program.declarations[context.declaration.0 as usize].module;
        let mut output = Vec::new();
        for symbol in &self.symbols {
            let SymbolTarget::Variant(variant) = &symbol.target else {
                continue;
            };
            if symbol.name != *spelling {
                continue;
            }
            let enumeration =
                &self.program.declarations[variant.enumeration.declaration.0 as usize];
            let owner_visible = enumeration.module == module
                && matches!(enumeration.owner, hir::DeclarationOwner::Module(_));
            let nested_visible =
                self.declaration_is_ancestor(variant.enumeration.declaration, context.declaration);
            let imported = self.named_imports.iter().any(|binding| {
                binding.module == module
                    && binding.local_name == *spelling
                    && binding.target == SymbolTarget::Variant(variant.clone())
            }) || self.prelude_bindings.iter().any(|binding| {
                binding.module == module
                    && binding.local_name == *spelling
                    && binding.target == SymbolTarget::Variant(variant.clone())
            });
            // A dot-form or bare pattern name also resolves against any
            // enum whose *type* (not necessarily each individual variant)
            // is imported into this module, e.g. `from core.result import
            // Result` makes `.Ok`/`.Err` resolvable without separately
            // importing each variant by name.
            let enum_type_imported = self.named_imports.iter().any(|binding| {
                binding.module == module
                    && binding.target == SymbolTarget::Declaration(variant.enumeration.clone())
            }) || self.prelude_bindings.iter().any(|binding| {
                binding.module == module
                    && binding.target == SymbolTarget::Declaration(variant.enumeration.clone())
            });
            if !(owner_visible || nested_visible || imported || enum_type_imported) {
                continue;
            }
            if fieldless_only && !self.variant_is_fieldless(variant) {
                continue;
            }
            push64(
                &mut output,
                variant.clone(),
                "pattern variant candidates",
                self.request.limits.model_edges,
            )?;
        }
        output.sort();
        output.dedup();
        Ok(output)
    }

    fn declaration_is_ancestor(
        &self,
        ancestor: hir::DeclarationId,
        mut declaration: hir::DeclarationId,
    ) -> bool {
        for _ in 0..=self.program.declarations.len() {
            if declaration == ancestor {
                return true;
            }
            let hir::DeclarationOwner::Declaration(parent) =
                self.program.declarations[declaration.0 as usize].owner
            else {
                return false;
            };
            declaration = parent;
        }
        false
    }

    fn variant_is_fieldless(&self, variant: &hir::ResolvedVariant) -> bool {
        let header = &self.headers[variant.enumeration.declaration.0 as usize];
        let Some(source_header) = header
            .variants
            .iter()
            .find(|candidate| candidate.variant == variant.variant)
        else {
            return false;
        };
        let DeclarationSyntax::Enumeration(enumeration) =
            self.plans[variant.enumeration.declaration.0 as usize].syntax
        else {
            return false;
        };
        enumeration
            .variants
            .iter()
            .find(|candidate| candidate.meta.span == source_header.source)
            .is_some_and(|candidate| matches!(candidate.payload, syntax::EnumPayload::None))
    }
}

fn reserve<T>(
    values: &mut Vec<T>,
    additional: usize,
    resource: &'static str,
    limit: u32,
) -> Result<(), LowerFailure> {
    if values.len().saturating_add(additional) > limit as usize {
        return Err(LowerFailure::ResourceLimit {
            resource,
            limit: u64::from(limit),
        });
    }
    values
        .try_reserve(additional)
        .map_err(|_| LowerFailure::ResourceLimit {
            resource,
            limit: u64::from(limit),
        })
}

fn push<T>(
    values: &mut Vec<T>,
    value: T,
    resource: &'static str,
    limit: u32,
) -> Result<(), LowerFailure> {
    reserve(values, 1, resource, limit)?;
    values.push(value);
    Ok(())
}

fn push64<T>(
    values: &mut Vec<T>,
    value: T,
    resource: &'static str,
    limit: u64,
) -> Result<(), LowerFailure> {
    let next = u64::try_from(values.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(LowerFailure::ResourceLimit { resource, limit })?;
    if next > limit {
        return Err(LowerFailure::ResourceLimit { resource, limit });
    }
    values
        .try_reserve(1)
        .map_err(|_| LowerFailure::ResourceLimit { resource, limit })?;
    values.push(value);
    Ok(())
}

fn copy_slice<T: Copy>(
    values: &[T],
    resource: &'static str,
    limit: u32,
) -> Result<Vec<T>, LowerFailure> {
    let mut output = Vec::new();
    reserve(&mut output, values.len(), resource, limit)?;
    output.extend_from_slice(values);
    Ok(output)
}

fn clone_text(value: &str, limit: u64) -> Result<String, LowerFailure> {
    if value.len() as u64 > limit {
        return Err(LowerFailure::ResourceLimit {
            resource: "HIR payload bytes",
            limit,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| LowerFailure::ResourceLimit {
            resource: "HIR payload bytes",
            limit,
        })?;
    output.push_str(value);
    Ok(output)
}

fn compare_use(left: &ResolvedUse, right: &ResolvedUse) -> Ordering {
    (
        left.source.file.0,
        left.source.range.start,
        left.source.range.end,
        left.spelling.as_str(),
        binding_rank(&left.kind),
    )
        .cmp(&(
            right.source.file.0,
            right.source.range.start,
            right.source.range.end,
            right.spelling.as_str(),
            binding_rank(&right.kind),
        ))
}

const fn binding_rank(kind: &BindingKind) -> u8 {
    match kind {
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
    }
}

fn span_at_end(span: Span) -> Span {
    Span {
        file: span.file,
        range: TextRange {
            start: span.range.end,
            end: span.range.end,
        },
    }
}

fn declaration_source_with_attributes(declaration: Span, attributes: &[syntax::Attribute]) -> Span {
    attributes.first().map_or(declaration, |attribute| Span {
        file: declaration.file,
        range: TextRange {
            start: attribute.meta.span.range.start,
            end: declaration.range.end,
        },
    })
}

fn declaration_identifier(value: DeclarationSyntax<'_>) -> Option<&syntax::Identifier> {
    match value {
        DeclarationSyntax::Constant(value) => Some(&value.name),
        DeclarationSyntax::Brand(value) => Some(&value.name),
        DeclarationSyntax::Function(value) => Some(&value.name),
        DeclarationSyntax::Initializer(_) => None,
        DeclarationSyntax::Structure(value) => Some(&value.name),
        DeclarationSyntax::Enumeration(value) => Some(&value.name),
        DeclarationSyntax::Interface(value) => Some(&value.name),
        DeclarationSyntax::Projection(value) => Some(&value.name),
        DeclarationSyntax::Scope(value) => Some(&value.name),
        DeclarationSyntax::Implementation(_)
        | DeclarationSyntax::ComptimeDeclaration(_)
        | DeclarationSyntax::ComptimeMember(_)
        | DeclarationSyntax::Error => None,
    }
}

fn top_syntax(declaration: &syntax::TopLevelDeclaration) -> DeclarationSyntax<'_> {
    match &declaration.kind {
        syntax::DeclarationKind::Constant(value) => DeclarationSyntax::Constant(value),
        syntax::DeclarationKind::Brand(value) => DeclarationSyntax::Brand(value),
        syntax::DeclarationKind::Function(value) => DeclarationSyntax::Function(value),
        syntax::DeclarationKind::Structure(value) => DeclarationSyntax::Structure(value),
        syntax::DeclarationKind::Enumeration(value) => DeclarationSyntax::Enumeration(value),
        syntax::DeclarationKind::Interface(value) => DeclarationSyntax::Interface(value),
        syntax::DeclarationKind::Implementation(value) => DeclarationSyntax::Implementation(value),
        syntax::DeclarationKind::Projection(value) => DeclarationSyntax::Projection(value),
        syntax::DeclarationKind::Scope(value) => DeclarationSyntax::Scope(value),
        syntax::DeclarationKind::ComptimeIf(value) => DeclarationSyntax::ComptimeDeclaration(value),
        syntax::DeclarationKind::Error(_) => DeclarationSyntax::Error,
    }
}

fn syntax_generics(value: DeclarationSyntax<'_>) -> &[syntax::GenericParameter] {
    match value {
        DeclarationSyntax::Function(value) => &value.generics,
        DeclarationSyntax::Structure(value) => &value.generics,
        DeclarationSyntax::Enumeration(value) => &value.generics,
        DeclarationSyntax::Interface(value) => &value.generics,
        DeclarationSyntax::Projection(value) => &value.generics,
        DeclarationSyntax::Constant(_)
        | DeclarationSyntax::Brand(_)
        | DeclarationSyntax::Initializer(_)
        | DeclarationSyntax::Implementation(_)
        | DeclarationSyntax::Scope(_)
        | DeclarationSyntax::ComptimeDeclaration(_)
        | DeclarationSyntax::ComptimeMember(_)
        | DeclarationSyntax::Error => &[],
    }
}

fn syntax_parameters(value: DeclarationSyntax<'_>) -> &[syntax::Parameter] {
    match value {
        DeclarationSyntax::Function(value) => &value.parameters,
        DeclarationSyntax::Initializer(value) => &value.parameters,
        DeclarationSyntax::Projection(value) => &value.parameters,
        DeclarationSyntax::Scope(value) => &value.parameters,
        DeclarationSyntax::Constant(_)
        | DeclarationSyntax::Brand(_)
        | DeclarationSyntax::Structure(_)
        | DeclarationSyntax::Enumeration(_)
        | DeclarationSyntax::Interface(_)
        | DeclarationSyntax::Implementation(_)
        | DeclarationSyntax::ComptimeDeclaration(_)
        | DeclarationSyntax::ComptimeMember(_)
        | DeclarationSyntax::Error => &[],
    }
}

const fn lower_access(value: syntax::AccessMode) -> hir::AccessMode {
    match value {
        syntax::AccessMode::Value => hir::AccessMode::Value,
        syntax::AccessMode::Read => hir::AccessMode::Read,
        syntax::AccessMode::Mutate => hir::AccessMode::Mutate,
        syntax::AccessMode::Take => hir::AccessMode::Take,
    }
}

fn generic_name(value: &syntax::GenericParameter) -> &syntax::Identifier {
    match value {
        syntax::GenericParameter::Type { name, .. }
        | syntax::GenericParameter::Constant { name, .. }
        | syntax::GenericParameter::Region { name, .. } => name,
    }
}

const fn lower_color(value: syntax::FunctionColor) -> hir::FunctionColor {
    match value {
        syntax::FunctionColor::Sync => hir::FunctionColor::Sync,
        syntax::FunctionColor::Async => hir::FunctionColor::Async,
        syntax::FunctionColor::Isr => hir::FunctionColor::Isr,
    }
}

const fn lower_assignment_operator(value: syntax::AssignmentOperator) -> hir::AssignmentOperator {
    match value {
        syntax::AssignmentOperator::Assign => hir::AssignmentOperator::Assign,
        syntax::AssignmentOperator::Add => hir::AssignmentOperator::Add,
        syntax::AssignmentOperator::Subtract => hir::AssignmentOperator::Subtract,
        syntax::AssignmentOperator::Multiply => hir::AssignmentOperator::Multiply,
        syntax::AssignmentOperator::Divide => hir::AssignmentOperator::Divide,
        syntax::AssignmentOperator::Remainder => hir::AssignmentOperator::Remainder,
        syntax::AssignmentOperator::BitAnd => hir::AssignmentOperator::BitAnd,
        syntax::AssignmentOperator::BitOr => hir::AssignmentOperator::BitOr,
        syntax::AssignmentOperator::BitXor => hir::AssignmentOperator::BitXor,
        syntax::AssignmentOperator::ShiftLeft => hir::AssignmentOperator::ShiftLeft,
        syntax::AssignmentOperator::ShiftRight => hir::AssignmentOperator::ShiftRight,
    }
}

const fn lower_unary_operator(value: syntax::UnaryOperator) -> hir::UnaryOperator {
    match value {
        syntax::UnaryOperator::Negate => hir::UnaryOperator::Negate,
        syntax::UnaryOperator::BitNot => hir::UnaryOperator::BitNot,
        syntax::UnaryOperator::BoolNot => hir::UnaryOperator::BoolNot,
        syntax::UnaryOperator::Await => hir::UnaryOperator::Await,
        syntax::UnaryOperator::Take => hir::UnaryOperator::Take,
        syntax::UnaryOperator::Copy => hir::UnaryOperator::Copy,
        syntax::UnaryOperator::Comptime => hir::UnaryOperator::Comptime,
    }
}

const fn lower_binary_operator(value: syntax::BinaryOperator) -> hir::BinaryOperator {
    match value {
        syntax::BinaryOperator::LogicalOr => hir::BinaryOperator::LogicalOr,
        syntax::BinaryOperator::LogicalAnd => hir::BinaryOperator::LogicalAnd,
        syntax::BinaryOperator::Add => hir::BinaryOperator::Add,
        syntax::BinaryOperator::AddWrapping => hir::BinaryOperator::AddWrapping,
        syntax::BinaryOperator::Subtract => hir::BinaryOperator::Subtract,
        syntax::BinaryOperator::SubtractWrapping => hir::BinaryOperator::SubtractWrapping,
        syntax::BinaryOperator::Multiply => hir::BinaryOperator::Multiply,
        syntax::BinaryOperator::MultiplyWrapping => hir::BinaryOperator::MultiplyWrapping,
        syntax::BinaryOperator::Divide => hir::BinaryOperator::Divide,
        syntax::BinaryOperator::Remainder => hir::BinaryOperator::Remainder,
        syntax::BinaryOperator::BitOr => hir::BinaryOperator::BitOr,
        syntax::BinaryOperator::BitXor => hir::BinaryOperator::BitXor,
        syntax::BinaryOperator::BitAnd => hir::BinaryOperator::BitAnd,
        syntax::BinaryOperator::ShiftLeft => hir::BinaryOperator::ShiftLeft,
        syntax::BinaryOperator::ShiftRight => hir::BinaryOperator::ShiftRight,
    }
}

const fn lower_comparison_operator(value: syntax::ComparisonOperator) -> hir::ComparisonOperator {
    match value {
        syntax::ComparisonOperator::Equal => hir::ComparisonOperator::Equal,
        syntax::ComparisonOperator::NotEqual => hir::ComparisonOperator::NotEqual,
        syntax::ComparisonOperator::Less => hir::ComparisonOperator::Less,
        syntax::ComparisonOperator::LessEqual => hir::ComparisonOperator::LessEqual,
        syntax::ComparisonOperator::Greater => hir::ComparisonOperator::Greater,
        syntax::ComparisonOperator::GreaterEqual => hir::ComparisonOperator::GreaterEqual,
        syntax::ComparisonOperator::In => hir::ComparisonOperator::In,
        syntax::ComparisonOperator::NotIn => hir::ComparisonOperator::NotIn,
    }
}

fn builtin_attribute(value: &str) -> Option<hir::BuiltinAttribute> {
    Some(match value {
        "image" => hir::BuiltinAttribute::Image,
        "app" => hir::BuiltinAttribute::App,
        "service" => hir::BuiltinAttribute::Service,
        "driver" => hir::BuiltinAttribute::Driver,
        "task" => hir::BuiltinAttribute::Task,
        "isr_safe" => hir::BuiltinAttribute::IsrSafe,
        "receipt_handoff" => hir::BuiltinAttribute::ReceiptHandoff,
        "dma" => hir::BuiltinAttribute::Dma,
        "wire" => hir::BuiltinAttribute::Wire,
        "mmio" => hir::BuiltinAttribute::Mmio,
        "offset" => hir::BuiltinAttribute::Offset,
        "layout_assert" => hir::BuiltinAttribute::LayoutAssert,
        "test" => hir::BuiltinAttribute::Test,
        "suspend_safe" => hir::BuiltinAttribute::SuspendSafe,
        "no_promote" => hir::BuiltinAttribute::NoPromote,
        "budget" => hir::BuiltinAttribute::Budget,
        "uninterrupted" => hir::BuiltinAttribute::Uninterrupted,
        _ => return None,
    })
}

fn test_attribute_arguments_are_supported(arguments: &[syntax::AttributeArgument]) -> bool {
    match arguments {
        [] => true,
        [argument] => is_test_runtime_attribute_argument(argument),
        _ => false,
    }
}

fn is_test_runtime_attribute_argument(argument: &syntax::AttributeArgument) -> bool {
    argument.name.is_none() && is_bare_name_expression(&argument.value, "runtime")
}

fn is_bare_name_expression(expression: &syntax::Expression, expected: &str) -> bool {
    match &expression.kind {
        syntax::ExpressionKind::Name(name) => {
            name.segments.len() == 1 && name.segments[0].spelling == expected
        }
        syntax::ExpressionKind::Parenthesized(inner) => is_bare_name_expression(inner, expected),
        _ => false,
    }
}

fn builtin(value: &str) -> Option<hir::Builtin> {
    Some(match value {
        "never" => hir::Builtin::Never,
        "unit" => hir::Builtin::Unit,
        "bool" => hir::Builtin::Bool,
        "u8" => hir::Builtin::U8,
        "u16" => hir::Builtin::U16,
        "u32" => hir::Builtin::U32,
        "u64" => hir::Builtin::U64,
        "u128" => hir::Builtin::U128,
        "usize" => hir::Builtin::Usize,
        "i8" => hir::Builtin::I8,
        "i16" => hir::Builtin::I16,
        "i32" => hir::Builtin::I32,
        "i64" => hir::Builtin::I64,
        "i128" => hir::Builtin::I128,
        "isize" => hir::Builtin::Isize,
        "f32" => hir::Builtin::F32,
        "f64" => hir::Builtin::F64,
        "char" => hir::Builtin::Char,
        "static" => hir::Builtin::Static,
        "str" => hir::Builtin::Str,
        "Bytes" => hir::Builtin::Bytes,
        "String" => hir::Builtin::String,
        "Actor" => hir::Builtin::Actor,
        "Receipt" => hir::Builtin::Receipt,
        "Dma" => hir::Builtin::Dma,
        "Mmio" => hir::Builtin::Mmio,
        "Validated" => hir::Builtin::Validated,
        _ => return None,
    })
}

fn bracket_argument_span(value: &syntax::BracketArgument) -> Span {
    match value {
        syntax::BracketArgument::UnclassifiedTypeOrExpression { meta, .. }
        | syntax::BracketArgument::BoundedCapacity { meta, .. } => meta.span,
        syntax::BracketArgument::Error(error) => error.meta.span,
    }
}

fn resolution_matches(
    target: &ResolutionTarget,
    kind: &BindingKind,
    expected: ExpectedName,
) -> bool {
    match expected {
        ExpectedName::Any => true,
        ExpectedName::Value => {
            matches!(target, ResolutionTarget::Definition(_))
                && !matches!(kind, BindingKind::GenericType | BindingKind::Module)
        }
        ExpectedName::Type => matches!(
            kind,
            BindingKind::Declaration | BindingKind::GenericType | BindingKind::Builtin
        ),
        ExpectedName::Region => {
            matches!(kind, BindingKind::GenericRegion | BindingKind::LocalRegion)
        }
    }
}

fn binding_for_target(
    target: &ResolutionTarget,
    kind: &BindingKind,
) -> Result<ResolvedBinding, LowerFailure> {
    match target {
        ResolutionTarget::Region(hir::RegionReference::Generic(id)) => {
            Ok(ResolvedBinding::Generic(*id))
        }
        ResolutionTarget::Region(hir::RegionReference::Local(id)) => {
            Ok(ResolvedBinding::LocalRegion(*id))
        }
        ResolutionTarget::Definition(definition) => match definition {
            hir::Definition::Declaration(value) => Ok(ResolvedBinding::Declaration(value.clone())),
            hir::Definition::Variant(value) => Ok(ResolvedBinding::Variant(value.clone())),
            hir::Definition::Parameter(id) => Ok(ResolvedBinding::Parameter(*id)),
            hir::Definition::Local(id) => Ok(ResolvedBinding::Local(*id)),
            hir::Definition::Generic(id) => Ok(ResolvedBinding::Generic(*id)),
            hir::Definition::Builtin(value) => Ok(ResolvedBinding::Builtin(*value)),
            hir::Definition::Module { package, module } => Ok(ResolvedBinding::Module {
                package: *package,
                module: *module,
            }),
        },
    }
    .and_then(|binding| {
        let matches = matches!(
            (kind, &binding),
            (BindingKind::Local, ResolvedBinding::Local(_))
                | (BindingKind::Parameter, ResolvedBinding::Parameter(_))
                | (BindingKind::Declaration, ResolvedBinding::Declaration(_))
                | (BindingKind::Variant, ResolvedBinding::Variant(_))
                | (BindingKind::Module, ResolvedBinding::Module { .. })
                | (BindingKind::GenericType, ResolvedBinding::Generic(_))
                | (BindingKind::GenericConstant, ResolvedBinding::Generic(_))
                | (BindingKind::GenericRegion, ResolvedBinding::Generic(_))
                | (BindingKind::LocalRegion, ResolvedBinding::LocalRegion(_))
                | (BindingKind::Builtin, ResolvedBinding::Builtin(_))
        );
        if matches {
            Ok(binding)
        } else {
            Err(LowerFailure::InternalInvariant(
                "resolved binding kind disagrees with its target".to_owned(),
            ))
        }
    })
}

fn primary_pattern_span(value: &syntax::PrimaryPattern) -> Span {
    match value {
        syntax::PrimaryPattern::Wildcard(meta)
        | syntax::PrimaryPattern::Tuple { meta, .. }
        | syntax::PrimaryPattern::Array { meta, .. }
        | syntax::PrimaryPattern::DotVariant { meta, .. } => meta.span,
        syntax::PrimaryPattern::Literal { literal, .. } => literal.meta.span,
        syntax::PrimaryPattern::Constructor { name, .. } => name.meta.span,
        syntax::PrimaryPattern::Bind(identifier) => identifier.meta.span,
        syntax::PrimaryPattern::Error(error) => error.meta.span,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wrela_build_model::Sha256Digest;
    use wrela_package::{
        DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName,
        PackageVersion,
    };
    use wrela_source::{SourceDatabase, SourceInput};
    use wrela_syntax::{ParseLimits, ParseRequest};

    use super::*;
    use crate::{ChangeSet, LoweringLimits};

    const CORE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
    const APPLICATION_SOURCE: &str =
        include_str!("../../../std/examples/minimal-image/src/bootstrap/image.wr");

    fn identity(name: &str, digest: u8) -> PackageIdentity {
        PackageIdentity {
            name: PackageName::new(name).expect("fixture package name"),
            version: PackageVersion::new("0.1.0").expect("fixture package version"),
            source_digest: Sha256Digest::from_bytes([digest; 32]),
        }
    }

    #[test]
    fn checked_in_core_and_minimum_application_lower_with_exact_package_resolution() {
        let mut sources = SourceDatabase::default();
        let application_file = sources
            .add(SourceInput {
                path: "bootstrap/image.wr".to_owned(),
                text: APPLICATION_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xa1; 32]),
            })
            .expect("application source");
        let core_file = sources
            .add(SourceInput {
                path: "image.wr".to_owned(),
                text: CORE_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xc1; 32]),
            })
            .expect("core source");

        let mut parsed_files = Vec::new();
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
                .expect("checked-in source parses")
                .into_parts();
            assert!(
                diagnostics.is_empty(),
                "checked-in source must parse without recovery: {diagnostics:?}"
            );
            parsed_files.push(parsed);
        }

        let mut graph = PackageGraphBuilder::new(identity("bootstrap-image", 0xb0));
        let core = graph
            .add_package(identity("wrela-core", 0xc0))
            .expect("core package");
        graph
            .add_dependency(
                graph.root(),
                DependencyAlias::new("core").expect("reserved core alias"),
                core,
            )
            .expect("core dependency");
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["bootstrap".to_owned(), "image".to_owned()])
                    .expect("application module"),
                application_file,
            )
            .expect("application graph module");
        graph
            .add_module(
                core,
                ModulePath::new(["image".to_owned()]).expect("core module"),
                core_file,
            )
            .expect("core graph module");
        let packages = Arc::new(graph.finish().expect("package graph"));
        let core_package = packages
            .packages()
            .iter()
            .find(|package| package.identity.name.as_str() == "wrela-core")
            .expect("resolved core package")
            .id;
        let core_module = packages
            .modules()
            .iter()
            .find(|module| module.package == core_package && module.path.dotted() == "image")
            .expect("resolved core module")
            .id;
        let source_graph_digest = Sha256Digest::from_bytes([0xd0; 32]);
        let changes = ChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let output = CanonicalHirLowerer::new()
            .lower(
                LowerRequest {
                    packages: Arc::clone(&packages),
                    source_graph_digest,
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &changes,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("checked-in core and application lower");
        assert!(
            output.diagnostics().is_empty(),
            "checked-in bootstrap sources must seal cleanly: {:?}",
            output.diagnostics()
        );
        let program = output.lowered().program().as_program();
        assert!(Arc::ptr_eq(&program.packages, &packages));

        let image = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration.module == core_module
                    && declaration.name.as_ref().map(hir::Name::as_str) == Some("Image")
            })
            .expect("public core Image declaration");
        assert_eq!(image.visibility, hir::Visibility::Public);
        let hir::DeclarationKind::Structure(image_kind) = &image.kind else {
            panic!("core Image must be a structure")
        };

        let target = program
            .declarations
            .iter()
            .find(|declaration| {
                declaration.module == core_module
                    && declaration.name.as_ref().map(hir::Name::as_str) == Some("Target")
            })
            .expect("public core Target declaration");
        assert_eq!(target.visibility, hir::Visibility::Public);
        let hir::DeclarationKind::Enumeration(target_kind) = &target.kind else {
            panic!("core Target must be an enumeration")
        };
        assert_eq!(target_kind.variants.len(), 1);
        assert_eq!(
            target_kind.variants[0].name.as_str(),
            "aarch64_qemu_virt_uefi"
        );
        assert_eq!(image_kind.fields.len(), 2);
        assert_eq!(image_kind.fields[0].name.as_str(), "name");
        assert_eq!(image_kind.fields[0].visibility, hir::Visibility::Public);
        assert_eq!(image_kind.fields[1].name.as_str(), "target");
        assert_eq!(image_kind.fields[1].visibility, hir::Visibility::Public);
        assert!(matches!(
            &image_kind.fields[1].ty.kind,
            hir::TypeExpressionKind::Named {
                definition: hir::Definition::Declaration(declaration),
                arguments,
            } if declaration.package == core_package
                && declaration.module == core_module
                && declaration.declaration == target.id
                && arguments.is_empty()
        ));

        let boot = program
            .declarations
            .iter()
            .find(|declaration| declaration.name.as_ref().map(hir::Name::as_str) == Some("boot"))
            .expect("application image constructor");
        assert_eq!(boot.visibility, hir::Visibility::Public);
        assert_eq!(program.image_candidates, [boot.id]);
        let hir::DeclarationKind::Function(boot_kind) = &boot.kind else {
            panic!("application image constructor must be a function")
        };
        assert_eq!(boot_kind.color, hir::FunctionColor::Sync);
        assert!(boot_kind.generics.is_empty());
        assert!(boot_kind.parameters.is_empty());
        assert!(matches!(
            boot_kind.result.as_ref().map(|result| &result.kind),
            Some(hir::TypeExpressionKind::Named {
                definition: hir::Definition::Declaration(declaration),
                arguments,
            }) if declaration.package == core_package
                && declaration.module == core_module
                && declaration.declaration == image.id
                && arguments.is_empty()
        ));
        let body = &program.bodies[boot_kind.body.expect("image constructor body").0 as usize];
        assert_eq!(body.statements.len(), 1);
        let hir::StatementKind::Return(Some(returned)) =
            &program.statements[body.statements[0].0 as usize].kind
        else {
            panic!("image constructor must return its Image value")
        };
        let hir::ExpressionKind::Call { callee, arguments } =
            &program.expressions[returned.0 as usize].kind
        else {
            panic!("image constructor return must call Image")
        };
        assert!(matches!(
            &program.expressions[callee.0 as usize].kind,
            hir::ExpressionKind::Reference(hir::Definition::Declaration(declaration))
                if declaration.package == core_package
                    && declaration.module == core_module
                    && declaration.declaration == image.id
        ));
        assert_eq!(arguments.len(), 2);
        assert_eq!(
            arguments[0].name.as_ref().map(hir::Name::as_str),
            Some("name")
        );
        assert!(matches!(
            &program.expressions[arguments[0].expression().expect("value argument").0 as usize].kind,
            hir::ExpressionKind::Literal(hir::Literal::String(value)) if value == "bootstrap"
        ));
        assert_eq!(
            arguments[1].name.as_ref().map(hir::Name::as_str),
            Some("target")
        );
        match &program.expressions[arguments[1].expression().expect("value argument").0 as usize]
            .kind
        {
            hir::ExpressionKind::Reference(hir::Definition::Variant(variant)) => {
                assert_eq!(variant.enumeration.package, core_package);
                assert_eq!(variant.enumeration.module, core_module);
                assert_eq!(variant.enumeration.declaration, target.id);
                assert_eq!(variant.variant, 0);
            }
            hir::ExpressionKind::Field { base, name } => {
                assert_eq!(name.as_str(), "aarch64_qemu_virt_uefi");
                assert!(matches!(
                    &program.expressions[base.0 as usize].kind,
                    hir::ExpressionKind::Reference(hir::Definition::Declaration(declaration))
                        if declaration.package == core_package
                            && declaration.module == core_module
                            && declaration.declaration == target.id
                ));
            }
            other => panic!("selected target has unsupported HIR shape: {other:?}"),
        }

        for expected in [("Image", image.id), ("Target", target.id)] {
            assert!(output.lowered().uses().iter().any(|use_record| {
                use_record.spelling.as_str() == expected.0
                    && matches!(
                        &use_record.target,
                        Some(ResolvedBinding::Declaration(declaration))
                            if declaration.package == core_package
                                && declaration.module == core_module
                                && declaration.declaration == expected.1
                    )
            }));
        }
    }
}
