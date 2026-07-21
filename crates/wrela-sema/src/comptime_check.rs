//! Bounded whole-closure checking for source comptime unit tests.
//!
//! The evaluator is deliberately partial.  Before semantic analysis publishes
//! a `TypeChecked` proof for a source test, this pass checks every operation in
//! the reachable direct-call closure, including branches and short-circuit
//! operands that a particular evaluation does not execute.

use super::AnalysisFailure;

use std::cell::Cell;

use wrela_diagnostics::{Category, Diagnostic};
use wrela_hir::{
    AccessMode, AssignmentOperator, BinaryOperator, BodyId, BodyOwner, Builtin, CallableOwner,
    ComparisonOperator, DeclarationId, DeclarationKind, Definition, ExpressionId, ExpressionKind,
    FunctionColor, Literal, LocalId, ParameterId, StatementKind, TypeExpression,
    TypeExpressionKind, UnaryOperator, ValidatedProgram,
};
use wrela_source::Span;

/// Stable proof explanation marker for the bounded whole-closure check.
pub(crate) const SOURCE_COMPTIME_CLOSURE_PROOF_MARKER: &str =
    "bounded source comptime flat-aggregate call closure checked";

// Canonical host-independent diagnostic accounting. One retained label charges
// 64 logical bytes for its span plus owned-message/vector metadata; the UTF-8
// message payload is charged separately. This is intentionally unrelated to
// Rust layout so the same source has the same quota behavior on every host.
const COMPTIME_DIAGNOSTIC_LABEL_STRUCTURAL_BYTES: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComptimeCheckLimits {
    /// Deterministic checker work units. Every structural node, scanned source
    /// byte, and linear lookup element consumes one unit.
    pub work_units: u64,
    /// Canonical logical entries retained by checker work tables.
    pub storage_entries: u64,
    /// Maximum nested body/expression syntax depth.
    pub syntax_depth: u32,
    /// Aggregate logical bytes retained by one checker-produced diagnostic,
    /// including UTF-8 payload and canonical label structure.
    pub diagnostic_bytes: u64,
    /// Aggregate logical bytes that the diagnostic may contribute to test
    /// output, under the same accounting model.
    pub test_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckedComptimeDeclaration {
    pub declaration: DeclarationId,
    pub source: Span,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CheckedComptimeClosure {
    pub declarations: Vec<CheckedComptimeDeclaration>,
    /// Declaration, parameter, body, statement, and expression nodes.
    pub node_count: u64,
    /// Exact deterministic work consumed while checking the closure.
    pub work_count: u64,
}

/// Check one parameterless, unit-result source test and every directly called
/// comptime function before the caller publishes any type proof.
///
/// Source errors are returned as stable diagnostics. Cancellation, quota
/// exhaustion, and allocation failure remain analysis failures so callers can
/// preserve the semantic driver's existing classification policy.
pub(crate) fn check_source_comptime_unit_test(
    hir: &ValidatedProgram,
    standard_library_package: wrela_package::PackageId,
    target_pointer_width: u8,
    root: DeclarationId,
    limits: ComptimeCheckLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Result<CheckedComptimeClosure, Diagnostic>, AnalysisFailure> {
    if limits.work_units == 0
        || limits.storage_entries == 0
        || limits.syntax_depth == 0
        || limits.diagnostic_bytes == 0
        || limits.test_bytes == 0
    {
        return Err(AnalysisFailure::InvalidLimits);
    }
    if target_pointer_width == 0 || target_pointer_width > 128 {
        return Err(AnalysisFailure::InternalInvariant(
            "target pointer width is outside the comptime scalar domain".to_owned(),
        ));
    }

    let mut checker = Checker::new(
        hir,
        standard_library_package,
        u16::from(target_pointer_width),
        limits,
        is_cancelled,
    )?;
    match checker.check(root) {
        Ok(closure) => Ok(Ok(closure)),
        Err(CheckFailure::Diagnostic(mut diagnostics)) => {
            let Some(diagnostic) = diagnostics.pop() else {
                return Err(AnalysisFailure::InternalInvariant(
                    "comptime checker returned an empty diagnostic envelope".to_owned(),
                ));
            };
            if !diagnostics.is_empty() {
                return Err(AnalysisFailure::InternalInvariant(
                    "comptime checker returned multiple diagnostics in one envelope".to_owned(),
                ));
            }
            Ok(Err(diagnostic))
        }
        Err(CheckFailure::Analysis(error)) => Err(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComptimeType {
    Unit,
    Bool,
    Integer {
        signed: bool,
        bits: u16,
    },
    /// Nominal identity of one nongeneric structure whose fields are all
    /// scalar values. Declaration ids are dense and globally unique in one
    /// validated package graph, including across imported modules.
    Structure(DeclarationId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpressionAccess {
    Move,
    Read,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Unseen,
    Visiting(usize),
    Checked(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallParent {
    caller: DeclarationId,
    call_source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingDeclaration {
    declaration: DeclarationId,
    parent: Option<CallParent>,
}

enum CheckFailure {
    // A one-element Vec keeps the recursive error type small while allowing
    // its allocation to be fallible and structurally quota-charged. The public
    // boundary unwraps the sole element without cloning.
    Diagnostic(Vec<Diagnostic>),
    Analysis(AnalysisFailure),
}

impl From<AnalysisFailure> for CheckFailure {
    fn from(error: AnalysisFailure) -> Self {
        Self::Analysis(error)
    }
}

type CheckResult<T> = Result<T, CheckFailure>;

struct Checker<'a> {
    hir: &'a ValidatedProgram,
    program: &'a wrela_hir::Program,
    standard_library_package: wrela_package::PackageId,
    pointer_width: u16,
    limits: ComptimeCheckLimits,
    states: Vec<VisitState>,
    local_types: Vec<Option<ComptimeType>>,
    local_initialized: Vec<bool>,
    pending: Vec<PendingDeclaration>,
    next_pending: usize,
    current_declaration: Option<DeclarationId>,
    checked: Vec<CheckedComptimeDeclaration>,
    nodes: u64,
    work_units: Cell<u64>,
    storage_entries: Cell<u64>,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Checker<'a> {
    fn new(
        hir: &'a ValidatedProgram,
        standard_library_package: wrela_package::PackageId,
        pointer_width: u16,
        limits: ComptimeCheckLimits,
        is_cancelled: &'a dyn Fn() -> bool,
    ) -> Result<Self, AnalysisFailure> {
        if is_cancelled() {
            return Err(AnalysisFailure::Cancelled);
        }
        let program = hir.as_program();
        let state_entries = u64::try_from(program.declarations.len()).map_err(|_| {
            AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            }
        })?;
        let local_entries =
            u64::try_from(program.locals.len()).map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            })?;
        let storage_entries = state_entries
            .checked_add(local_entries)
            .and_then(|entries| entries.checked_add(local_entries))
            .ok_or(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            })?;
        if storage_entries > limits.storage_entries {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            });
        }
        if storage_entries > limits.work_units {
            return Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker work units",
                limit: limits.work_units,
            });
        }

        let mut states = Vec::new();
        states
            .try_reserve_exact(program.declarations.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            })?;
        for _ in &program.declarations {
            if is_cancelled() {
                return Err(AnalysisFailure::Cancelled);
            }
            states.push(VisitState::Unseen);
        }
        let mut local_types = Vec::new();
        local_types
            .try_reserve_exact(program.locals.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            })?;
        for _ in &program.locals {
            if is_cancelled() {
                return Err(AnalysisFailure::Cancelled);
            }
            local_types.push(None);
        }
        let mut local_initialized = Vec::new();
        local_initialized
            .try_reserve_exact(program.locals.len())
            .map_err(|_| AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit: limits.storage_entries,
            })?;
        for _ in &program.locals {
            if is_cancelled() {
                return Err(AnalysisFailure::Cancelled);
            }
            local_initialized.push(false);
        }

        Ok(Self {
            hir,
            program,
            standard_library_package,
            pointer_width,
            limits,
            states,
            local_types,
            local_initialized,
            pending: Vec::new(),
            next_pending: 0,
            current_declaration: None,
            checked: Vec::new(),
            nodes: 0,
            work_units: Cell::new(storage_entries),
            storage_entries: Cell::new(storage_entries),
            is_cancelled,
        })
    }

    fn check(&mut self, root: DeclarationId) -> CheckResult<CheckedComptimeClosure> {
        let root_source = self.program.declaration(root).map_or_else(
            || fallback_span(self.program),
            |declaration| declaration.source,
        );
        self.queue_declaration(root, root_source, None)?;

        while let Some(pending) = self.pending.get(self.next_pending).copied() {
            self.poll()?;
            let declaration = pending.declaration;
            self.next_pending = self.next_pending.checked_add(1).ok_or_else(|| {
                self.resource_failure("comptime source checker work units", self.limits.work_units)
            })?;
            let is_root = declaration == root;
            self.current_declaration = Some(declaration);
            self.check_declaration(declaration, is_root)?;
            let record = self
                .program
                .declaration(declaration)
                .ok_or_else(|| self.invariant("queued comptime declaration is absent from HIR"))?;
            let state_index = declaration.0 as usize;
            if state_index >= self.states.len() {
                return Err(self.invariant("queued comptime declaration state is absent"));
            }
            let state = &mut self.states[state_index];
            let VisitState::Visiting(pending_index) = *state else {
                return Err(self.invariant("queued comptime declaration has invalid state"));
            };
            *state = VisitState::Checked(pending_index);
            self.retain_storage(1)?;
            self.checked.try_reserve(1).map_err(|_| {
                self.resource_failure(
                    "comptime source checker storage entries",
                    self.limits.storage_entries,
                )
            })?;
            self.checked.push(CheckedComptimeDeclaration {
                declaration,
                source: record.source,
            });
        }

        self.poll()?;
        self.current_declaration = None;
        Ok(CheckedComptimeClosure {
            declarations: std::mem::take(&mut self.checked),
            node_count: self.nodes,
            work_count: self.work_units.get(),
        })
    }

    fn check_declaration(&mut self, id: DeclarationId, is_root: bool) -> CheckResult<()> {
        let program = self.program;
        let declaration = program
            .declaration(id)
            .ok_or_else(|| self.invariant("comptime declaration is absent from HIR"))?;
        self.node(declaration.source)?;
        let DeclarationKind::Function(function) = &declaration.kind else {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-comptime-call-target",
                "comptime call target is not a function",
            ));
        };
        if function.color != FunctionColor::Sync
            || !function.generics.is_empty()
            || function.body.is_none()
        {
            return Err(self.signature_diagnostic(declaration.source));
        }
        if is_root && !function.parameters.is_empty() {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-test-parameters-not-supported",
                "a source comptime unit test cannot declare parameters",
            ));
        }

        for parameter in &function.parameters {
            let record = self.parameter(*parameter, id, declaration.source)?;
            let record_source = record.source;
            let receiver = record.receiver;
            let access = record.access;
            let supported = if receiver {
                // A receiver has no separately written type; it is legal
                // only when its enclosing struct/impl names a concrete
                // struct, and only `read self` is reachable through operator
                // desugaring (chapter 10 §12).
                access == AccessMode::Read
                    && crate::interfaces::receiver_concrete_struct(self.program, id).is_some()
            } else {
                let parameter_type = match record.ty.as_ref() {
                    Some(ty) => self.source_type(ty)?,
                    None => None,
                };
                access == AccessMode::Value && parameter_type.is_some()
            };
            self.node(record_source)?;
            if !supported {
                return Err(self.signature_diagnostic(record_source));
            }
        }
        let result = match function.result.as_ref() {
            Some(result) => self
                .source_type(result)?
                .ok_or_else(|| self.signature_diagnostic(result.source))?,
            None => ComptimeType::Unit,
        };
        if is_root && result != ComptimeType::Unit {
            return Err(self.diagnostic(
                function
                    .result
                    .as_ref()
                    .map_or(declaration.source, |result| result.source),
                "semantic-test-result-not-supported",
                "a source comptime unit test must have a unit result",
            ));
        }
        let body = function.body.expect("checked above");
        let definitely_returns = self.check_body(body, id, result, 1)?;
        if result != ComptimeType::Unit && !definitely_returns {
            return Err(self.diagnostic(
                declaration.source,
                "semantic-comptime-missing-return",
                "comptime function can complete without returning its declared result",
            ));
        }
        Ok(())
    }

    fn check_body(
        &mut self,
        id: BodyId,
        declaration: DeclarationId,
        result: ComptimeType,
        depth: u32,
    ) -> CheckResult<bool> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let body = program
            .body(id)
            .ok_or_else(|| self.invariant("comptime body is absent from HIR"))?;
        self.node(body.source)?;
        if body.owner != BodyOwner::Declaration(declaration) {
            return Err(self.invariant("comptime body owner does not match its declaration"));
        }
        let mut definitely_returns = false;
        for statement_id in &body.statements {
            let statement = program
                .statement(*statement_id)
                .ok_or_else(|| self.invariant("comptime statement is absent from HIR"))?;
            self.node(statement.source)?;
            let statement_returns = match &statement.kind {
                StatementKind::Initialize { local, value } => {
                    let explicit =
                        self.local_declared_type(*local, declaration, statement.source)?;
                    let value_type = self.check_owned_expression(
                        *value,
                        explicit,
                        declaration,
                        depth.checked_add(1).ok_or_else(|| {
                            self.resource_failure(
                                "comptime source checker syntax depth",
                                u64::from(self.limits.syntax_depth),
                            )
                        })?,
                    )?;
                    self.bind_local(*local, explicit.unwrap_or(value_type), statement.source)?;
                    false
                }
                StatementKind::Assign {
                    targets,
                    operator,
                    value,
                } if targets.len() == 1 && targets[0].projections.is_empty() => {
                    let Definition::Local(local) = targets[0].root else {
                        return Err(self.unsupported(statement.source));
                    };
                    let ty = self.bound_local_type(local, declaration, statement.source)?;
                    if *operator == AssignmentOperator::Assign {
                        self.check_owned_expression(*value, Some(ty), declaration, depth + 1)?;
                    } else {
                        self.require_local_initialized(local, statement.source)?;
                        self.check_expression(*value, Some(ty), declaration, depth + 1)?;
                        if !matches!(ty, ComptimeType::Integer { .. }) {
                            return Err(self.type_mismatch(statement.source));
                        }
                    }
                    self.mark_local_initialized(local, statement.source)?;
                    false
                }
                StatementKind::Return(value) => {
                    match value {
                        Some(value) => {
                            self.check_owned_expression(
                                *value,
                                Some(result),
                                declaration,
                                depth + 1,
                            )?;
                        }
                        None if result == ComptimeType::Unit => {}
                        None => return Err(self.type_mismatch(statement.source)),
                    }
                    true
                }
                StatementKind::Pass => false,
                StatementKind::Assert { condition, .. } => {
                    self.check_expression(
                        *condition,
                        Some(ComptimeType::Bool),
                        declaration,
                        depth + 1,
                    )?;
                    false
                }
                StatementKind::Expression(expression) => {
                    self.check_expression(*expression, None, declaration, depth + 1)?;
                    false
                }
                StatementKind::If {
                    branches,
                    else_body,
                } => {
                    let entry = self.allocate_initialization_snapshot()?;
                    let mut joined = self.allocate_initialization_snapshot()?;
                    let mut has_continuing_path = false;
                    let mut every_branch_returns = !branches.is_empty();
                    for (condition, branch) in branches {
                        self.restore_initialization_snapshot(&entry)?;
                        self.check_expression(
                            *condition,
                            Some(ComptimeType::Bool),
                            declaration,
                            depth + 1,
                        )?;
                        let branch_returns =
                            self.check_body(*branch, declaration, result, depth + 1)?;
                        every_branch_returns &= branch_returns;
                        if !branch_returns {
                            if has_continuing_path {
                                self.intersect_initialization_snapshot(&mut joined)?;
                            } else {
                                self.capture_initialization_snapshot(&mut joined)?;
                                has_continuing_path = true;
                            }
                        }
                    }
                    let else_returns = match else_body {
                        Some(body) => {
                            self.restore_initialization_snapshot(&entry)?;
                            let returns = self.check_body(*body, declaration, result, depth + 1)?;
                            if !returns {
                                if has_continuing_path {
                                    self.intersect_initialization_snapshot(&mut joined)?;
                                } else {
                                    self.capture_initialization_snapshot(&mut joined)?;
                                    has_continuing_path = true;
                                }
                            }
                            returns
                        }
                        None => {
                            self.restore_initialization_snapshot(&entry)?;
                            if has_continuing_path {
                                self.intersect_initialization_snapshot(&mut joined)?;
                            } else {
                                self.capture_initialization_snapshot(&mut joined)?;
                                has_continuing_path = true;
                            }
                            false
                        }
                    };
                    if has_continuing_path {
                        self.restore_initialization_snapshot(&joined)?;
                    } else {
                        // Structural checking continues after definitely
                        // returning statements, so use the deterministic entry
                        // state for unreachable follow-on validation.
                        self.restore_initialization_snapshot(&entry)?;
                    }
                    self.release_initialization_snapshot(joined)?;
                    self.release_initialization_snapshot(entry)?;
                    every_branch_returns && else_returns
                }
                StatementKind::ComptimeIf {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.check_expression(
                        *condition,
                        Some(ComptimeType::Bool),
                        declaration,
                        depth + 1,
                    )?;
                    let entry = self.allocate_initialization_snapshot()?;
                    let mut joined = self.allocate_initialization_snapshot()?;
                    let mut has_continuing_path = false;
                    self.restore_initialization_snapshot(&entry)?;
                    let then_returns =
                        self.check_body(*then_body, declaration, result, depth + 1)?;
                    if !then_returns {
                        self.capture_initialization_snapshot(&mut joined)?;
                        has_continuing_path = true;
                    }
                    let else_returns = match else_body {
                        Some(body) => {
                            self.restore_initialization_snapshot(&entry)?;
                            let returns = self.check_body(*body, declaration, result, depth + 1)?;
                            if !returns {
                                if has_continuing_path {
                                    self.intersect_initialization_snapshot(&mut joined)?;
                                } else {
                                    self.capture_initialization_snapshot(&mut joined)?;
                                    has_continuing_path = true;
                                }
                            }
                            returns
                        }
                        None => {
                            self.restore_initialization_snapshot(&entry)?;
                            if has_continuing_path {
                                self.intersect_initialization_snapshot(&mut joined)?;
                            } else {
                                self.capture_initialization_snapshot(&mut joined)?;
                                has_continuing_path = true;
                            }
                            false
                        }
                    };
                    if has_continuing_path {
                        self.restore_initialization_snapshot(&joined)?;
                    } else {
                        self.restore_initialization_snapshot(&entry)?;
                    }
                    self.release_initialization_snapshot(joined)?;
                    self.release_initialization_snapshot(entry)?;
                    then_returns && else_returns
                }
                StatementKind::Assign { .. }
                | StatementKind::Break
                | StatementKind::Continue
                | StatementKind::Send(_)
                | StatementKind::Yield(_)
                | StatementKind::Match { .. }
                | StatementKind::For { .. }
                | StatementKind::While { .. }
                | StatementKind::Loop { .. }
                | StatementKind::With { .. }
                | StatementKind::Error => return Err(self.unsupported(statement.source)),
            };
            definitely_returns |= statement_returns;
        }
        Ok(definitely_returns)
    }

    fn check_expression(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        declaration: DeclarationId,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        self.check_expression_with_access(id, expected, declaration, depth, ExpressionAccess::Read)
    }

    fn check_owned_expression(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        declaration: DeclarationId,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        self.check_expression_with_access(id, expected, declaration, depth, ExpressionAccess::Move)
    }

    fn check_expression_with_access(
        &mut self,
        id: ExpressionId,
        expected: Option<ComptimeType>,
        declaration: DeclarationId,
        depth: u32,
        access: ExpressionAccess,
    ) -> CheckResult<ComptimeType> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let expression = program
            .expression(id)
            .ok_or_else(|| self.invariant("comptime expression is absent from HIR"))?;
        self.node(expression.source)?;
        let actual = match &expression.kind {
            ExpressionKind::Literal(Literal::Boolean(_)) => ComptimeType::Bool,
            ExpressionKind::Literal(Literal::Unit) => ComptimeType::Unit,
            ExpressionKind::Literal(Literal::Integer(spelling)) => {
                self.integer_literal_type(spelling, expected, expression.source)?
            }
            ExpressionKind::Reference(Definition::Local(local)) => {
                let ty = self.bound_local_type(*local, declaration, expression.source)?;
                self.require_local_initialized(*local, expression.source)?;
                if access == ExpressionAccess::Move && matches!(ty, ComptimeType::Structure(_)) {
                    self.mark_local_moved(*local, expression.source)?;
                }
                ty
            }
            ExpressionKind::Reference(Definition::Parameter(parameter)) => {
                let ty = self.parameter_type(*parameter, declaration, expression.source)?;
                if access == ExpressionAccess::Move && matches!(ty, ComptimeType::Structure(_)) {
                    return Err(self.diagnostic(
                        expression.source,
                        "semantic-comptime-borrowed-value-move",
                        "a bare comptime parameter is read-only; use `copy` to produce an owned aggregate result",
                    ));
                }
                ty
            }
            ExpressionKind::Unary {
                operator: UnaryOperator::Comptime,
                operand,
            } => self.check_expression_with_access(
                *operand,
                expected,
                declaration,
                depth + 1,
                access,
            )?,
            ExpressionKind::Unary {
                operator: UnaryOperator::Copy,
                operand,
            } => self.check_expression_with_access(
                *operand,
                expected,
                declaration,
                depth + 1,
                ExpressionAccess::Copy,
            )?,
            ExpressionKind::Unary {
                operator: UnaryOperator::BoolNot,
                operand,
            } => {
                self.check_expression(*operand, Some(ComptimeType::Bool), declaration, depth + 1)?;
                ComptimeType::Bool
            }
            ExpressionKind::Unary {
                operator: UnaryOperator::Negate,
                operand,
            } => {
                if let Some(Literal::Integer(spelling)) =
                    program
                        .expression(*operand)
                        .and_then(|operand| match &operand.kind {
                            ExpressionKind::Literal(literal) => Some(literal),
                            _ => None,
                        })
                {
                    let ty =
                        self.negative_integer_literal_type(spelling, expected, expression.source)?;
                    // The operand is still a source expression node even though
                    // its magnitude is checked as part of the signed literal.
                    let operand_source = self
                        .program
                        .expression(*operand)
                        .map_or(expression.source, |operand| operand.source);
                    self.enter_syntax(depth + 1)?;
                    self.node(operand_source)?;
                    ty
                } else {
                    let ty = self.check_expression(*operand, expected, declaration, depth + 1)?;
                    if !matches!(ty, ComptimeType::Integer { signed: true, .. }) {
                        return Err(self.type_mismatch(expression.source));
                    }
                    ty
                }
            }
            ExpressionKind::Unary {
                operator: UnaryOperator::BitNot,
                operand,
            } => {
                let ty = self.check_expression(*operand, expected, declaration, depth + 1)?;
                if !matches!(ty, ComptimeType::Integer { .. }) {
                    return Err(self.type_mismatch(expression.source));
                }
                ty
            }
            ExpressionKind::Binary {
                operator: BinaryOperator::LogicalAnd | BinaryOperator::LogicalOr,
                left,
                right,
            } => {
                // Deliberately check both sides: static support cannot depend on
                // the value selected by one evaluator run.
                self.check_expression(*left, Some(ComptimeType::Bool), declaration, depth + 1)?;
                self.check_expression(*right, Some(ComptimeType::Bool), declaration, depth + 1)?;
                ComptimeType::Bool
            }
            ExpressionKind::Binary {
                operator,
                left,
                right,
            } => {
                let desugar = crate::interfaces::DesugarOperator::from_binary(*operator);
                if expected.is_some_and(|ty| {
                    !(matches!(ty, ComptimeType::Integer { .. })
                        || (desugar.is_some() && matches!(ty, ComptimeType::Structure(_))))
                }) {
                    return Err(self.type_mismatch(expression.source));
                }
                let left_type = self.check_expression(*left, expected, declaration, depth + 1)?;
                match (desugar, left_type) {
                    (Some(desugar), ComptimeType::Structure(struct_declaration)) => self
                        .check_operator_call(
                            desugar,
                            struct_declaration,
                            *right,
                            declaration,
                            expression.source,
                            depth,
                        )?,
                    (_, ComptimeType::Integer { .. }) => {
                        self.check_expression(*right, Some(left_type), declaration, depth + 1)?;
                        left_type
                    }
                    _ => return Err(self.type_mismatch(expression.source)),
                }
            }
            ExpressionKind::Compare {
                left,
                operator,
                right,
            } if !matches!(operator, ComparisonOperator::In | ComparisonOperator::NotIn) => {
                let left_type = self.check_expression(*left, None, declaration, depth + 1)?;
                if let (Some(desugar), ComptimeType::Structure(struct_declaration)) = (
                    crate::interfaces::DesugarOperator::from_comparison(*operator),
                    left_type,
                ) {
                    return self
                        .check_operator_call(
                            desugar,
                            struct_declaration,
                            *right,
                            declaration,
                            expression.source,
                            depth,
                        )
                        .and_then(|actual| {
                            self.require_expected(actual, expected, expression.source)
                        });
                }
                if matches!(left_type, ComptimeType::Structure(_)) {
                    return Err(self.unsupported(expression.source));
                }
                self.check_expression(*right, Some(left_type), declaration, depth + 1)?;
                if !matches!(
                    operator,
                    ComparisonOperator::Equal | ComparisonOperator::NotEqual
                ) && !matches!(left_type, ComptimeType::Integer { .. })
                {
                    return Err(self.type_mismatch(expression.source));
                }
                ComptimeType::Bool
            }
            ExpressionKind::Field { base, name } => {
                self.check_structure_field(*base, name, declaration, expression.source, depth + 1)?
            }
            ExpressionKind::Call { callee, arguments } => self.check_call(
                *callee,
                arguments,
                expected,
                declaration,
                expression.source,
                depth + 1,
            )?,
            ExpressionKind::Literal(_)
            | ExpressionKind::Reference(_)
            | ExpressionKind::Closure { .. }
            | ExpressionKind::Unary { .. }
            | ExpressionKind::Compare { .. }
            | ExpressionKind::IsPattern { .. }
            | ExpressionKind::Range { .. }
            | ExpressionKind::Cast { .. }
            | ExpressionKind::Try(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::Tuple(_)
            | ExpressionKind::Array(_)
            | ExpressionKind::DotName { .. }
            | ExpressionKind::TrySend(_)
            | ExpressionKind::Interpolate(_)
            | ExpressionKind::If { .. }
            | ExpressionKind::Error => return Err(self.unsupported(expression.source)),
        };
        self.require_expected(actual, expected, expression.source)
    }

    fn check_structure_field(
        &mut self,
        base: ExpressionId,
        name: &wrela_hir::Name,
        caller: DeclarationId,
        source: Span,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        let base_type = self.check_expression(base, None, caller, depth)?;
        let ComptimeType::Structure(structure) = base_type else {
            return Err(self.unsupported(source));
        };
        self.ensure_flat_structure(structure, source)?;
        let declaration = self
            .program
            .declaration(structure)
            .ok_or_else(|| self.invariant("comptime field structure is absent from HIR"))?;
        let DeclarationKind::Structure(aggregate) = &declaration.kind else {
            return Err(self.aggregate_not_supported(source));
        };
        let caller_module = self
            .program
            .declaration(caller)
            .map(|declaration| declaration.module)
            .ok_or_else(|| self.invariant("comptime field caller is absent from HIR"))?;
        let target_module = declaration.module;
        let mut selected = None;
        for (index, field) in aggregate.fields.iter().enumerate() {
            self.work()?;
            if self.names_equal(field.name.as_str(), name.as_str())?
                && selected.replace(index).is_some()
            {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-field",
                    "comptime structure field name is ambiguous",
                ));
            }
        }
        let field = selected
            .and_then(|index| aggregate.fields.get(index))
            .ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-field",
                    "comptime structure does not declare the selected field",
                )
            })?;
        self.require_field_visible(field, caller_module == target_module, source)?;
        self.scalar_type(&field.ty)
            .ok_or_else(|| self.aggregate_not_supported(field.ty.source))
    }

    fn check_call(
        &mut self,
        callee: ExpressionId,
        arguments: &[wrela_hir::CallArgument],
        expected: Option<ComptimeType>,
        caller: DeclarationId,
        source: Span,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        self.enter_syntax(depth)?;
        let program = self.program;
        let callee_expression = program
            .expression(callee)
            .ok_or_else(|| self.invariant("comptime call callee is absent from HIR"))?;
        self.node(callee_expression.source)?;
        let ExpressionKind::Reference(Definition::Declaration(resolved)) = &callee_expression.kind
        else {
            return Err(self.unsupported(source));
        };
        let target = self.hir.resolved_declaration(resolved).ok_or_else(|| {
            self.diagnostic(
                callee_expression.source,
                "semantic-comptime-call-target",
                "resolved comptime call target identity does not match its declaration",
            )
        })?;
        let target_id = target.id;
        if matches!(&target.kind, DeclarationKind::Structure(_)) {
            return self.check_structure_constructor(
                target_id, arguments, expected, caller, source, depth,
            );
        }
        let DeclarationKind::Function(function) = &target.kind else {
            return Err(self.diagnostic(
                callee_expression.source,
                "semantic-comptime-call-target",
                "comptime call target is not a function",
            ));
        };
        if function.color != FunctionColor::Sync
            || !function.generics.is_empty()
            || function.body.is_none()
            || arguments.len() != function.parameters.len()
        {
            return Err(self.call_signature_diagnostic(target.source, target_id, source));
        }
        let result_type = match function.result.as_ref() {
            Some(result) => self
                .source_type(result)?
                .ok_or_else(|| self.call_signature_diagnostic(result.source, target_id, source))?,
            None => ComptimeType::Unit,
        };

        let argument_entries = u64::try_from(arguments.len()).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        self.retain_storage(argument_entries)?;
        let mut supplied = Vec::new();
        supplied.try_reserve_exact(arguments.len()).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        for _ in arguments {
            self.work()?;
            supplied.push(false);
        }

        let mut non_receiver_count = 0usize;
        for parameter_id in &function.parameters {
            self.work()?;
            let parameter = self.parameter(*parameter_id, target_id, target.source)?;
            if !parameter.receiver {
                non_receiver_count = non_receiver_count.checked_add(1).ok_or_else(|| {
                    self.resource_failure(
                        "comptime source checker storage entries",
                        self.limits.storage_entries,
                    )
                })?;
            }
        }

        for argument in arguments.iter() {
            self.work()?;
            let parameter_index = if let Some(argument_name) = &argument.name {
                let mut selected = None;
                for (index, parameter_id) in function.parameters.iter().enumerate() {
                    self.work()?;
                    let parameter = self.parameter(*parameter_id, target_id, target.source)?;
                    if let Some(parameter_name) = &parameter.name {
                        if self.names_equal(parameter_name.as_str(), argument_name.as_str())?
                            && selected.replace(index).is_some()
                        {
                            return Err(self.diagnostic(
                                argument.source,
                                "semantic-comptime-call-argument",
                                "comptime call argument name is ambiguous",
                            ));
                        }
                    }
                }
                let parameter_index = selected.ok_or_else(|| {
                    self.diagnostic(
                        argument.source,
                        "semantic-argument-unknown-label",
                        "call argument label does not name a declared parameter",
                    )
                })?;
                let parameter = self.parameter(
                    function.parameters[parameter_index],
                    target_id,
                    target.source,
                )?;
                if (!parameter.receiver && non_receiver_count <= 1) || parameter.positional_only {
                    return Err(self.diagnostic(
                        argument.source,
                        "semantic-argument-label-forbidden",
                        "this parameter is positional-only and must not be labeled",
                    ));
                }
                parameter_index
            } else {
                let mut found = None;
                for (index, parameter_id) in function.parameters.iter().enumerate() {
                    self.work()?;
                    if *supplied.get(index).unwrap_or(&true) {
                        continue;
                    }
                    let parameter = self.parameter(*parameter_id, target_id, target.source)?;
                    let positional =
                        parameter.receiver || non_receiver_count <= 1 || parameter.positional_only;
                    if parameter.receiver || !positional {
                        continue;
                    }
                    found = Some(index);
                    break;
                }
                found.ok_or_else(|| {
                    self.diagnostic(
                        argument.source,
                        "semantic-argument-label-required",
                        "this call needs a labeled argument for a remaining parameter",
                    )
                })?
            };
            let parameter_id = *function.parameters.get(parameter_index).ok_or_else(|| {
                self.diagnostic(
                    argument.source,
                    "semantic-comptime-call-argument",
                    "comptime call supplies too many positional arguments",
                )
            })?;
            let parameter = self.parameter(parameter_id, target_id, target.source)?;
            if parameter.receiver
                || parameter.access != AccessMode::Value
                || argument.access() != AccessMode::Value
            {
                return Err(self.call_signature_diagnostic(argument.source, target_id, source));
            }
            let Some(argument_value) = argument.expression() else {
                return Err(self.call_signature_diagnostic(argument.source, target_id, source));
            };
            let parameter_type = match parameter.ty.as_ref() {
                Some(ty) => self.source_type(ty)?,
                None => None,
            }
            .ok_or_else(|| self.call_signature_diagnostic(parameter.source, target_id, source))?;
            let slot = supplied
                .get_mut(parameter_index)
                .ok_or_else(|| self.invariant("resolved comptime argument slot is absent"))?;
            if *slot {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-call-argument",
                    "comptime call supplies one parameter more than once",
                ));
            }
            *slot = true;
            self.check_expression(argument_value, Some(parameter_type), caller, depth + 1)?;
        }
        for supplied in &supplied {
            self.work()?;
            if !supplied {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-call-argument",
                    "comptime call does not supply every parameter",
                ));
            }
        }
        self.release_storage(argument_entries);
        self.queue_declaration(
            target_id,
            source,
            Some(CallParent {
                caller,
                call_source: source,
            }),
        )?;
        self.require_expected(result_type, expected, source)
    }

    /// Check a binary/comparison operator desugared to a `core.ops` impl
    /// method call (chapter 10 §12). There is no source `Call` expression to
    /// walk here, so this mirrors `check_call`'s signature validation and
    /// closure enqueueing directly against the resolved impl method.
    fn check_operator_call(
        &mut self,
        operator: crate::interfaces::DesugarOperator,
        struct_declaration: DeclarationId,
        right: ExpressionId,
        caller: DeclarationId,
        source: Span,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        self.check_expression(
            right,
            Some(ComptimeType::Structure(struct_declaration)),
            caller,
            depth + 1,
        )?;
        let (model, _) = crate::interfaces::collect_interface_model(
            self.program,
            self.standard_library_package,
            self.is_cancelled,
        )?;
        let Some(resolution) = model.resolve_operator(self.program, operator, struct_declaration)
        else {
            return Err(self.unsupported(source));
        };
        let target = self
            .program
            .declaration(resolution.function)
            .ok_or_else(|| self.invariant("comptime operator impl target is absent from HIR"))?;
        let target_source = target.source;
        let DeclarationKind::Function(function) = &target.kind else {
            return Err(self.call_signature_diagnostic(target_source, resolution.function, source));
        };
        if function.color != FunctionColor::Sync
            || !function.generics.is_empty()
            || function.body.is_none()
            || function.parameters.len() != 2
        {
            return Err(self.call_signature_diagnostic(target_source, resolution.function, source));
        }
        let result_type = match function.result.as_ref() {
            Some(result) => self.source_type(result)?.ok_or_else(|| {
                self.call_signature_diagnostic(result.source, resolution.function, source)
            })?,
            None => ComptimeType::Unit,
        };
        if resolution.negate && result_type != ComptimeType::Bool {
            return Err(self.call_signature_diagnostic(target_source, resolution.function, source));
        }
        self.queue_declaration(
            resolution.function,
            source,
            Some(CallParent {
                caller,
                call_source: source,
            }),
        )?;
        Ok(if resolution.negate {
            ComptimeType::Bool
        } else {
            result_type
        })
    }

    fn check_structure_constructor(
        &mut self,
        structure: DeclarationId,
        arguments: &[wrela_hir::CallArgument],
        expected: Option<ComptimeType>,
        caller: DeclarationId,
        source: Span,
        depth: u32,
    ) -> CheckResult<ComptimeType> {
        self.ensure_flat_structure(structure, source)?;
        let declaration = self
            .program
            .declaration(structure)
            .ok_or_else(|| self.invariant("comptime structure constructor is absent from HIR"))?;
        let DeclarationKind::Structure(aggregate) = &declaration.kind else {
            return Err(self.aggregate_not_supported(source));
        };
        if arguments.len() != aggregate.fields.len() {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-constructor-argument",
                "comptime structure construction must supply every field exactly once",
            ));
        }
        let caller_module = self
            .program
            .declaration(caller)
            .map(|declaration| declaration.module)
            .ok_or_else(|| self.invariant("comptime constructor caller is absent from HIR"))?;
        let field_count = aggregate.fields.len();
        let target_module = declaration.module;

        let entries = u64::try_from(field_count).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        self.retain_storage(entries)?;
        let mut supplied = Vec::new();
        supplied.try_reserve_exact(field_count).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        for _ in 0..field_count {
            self.work()?;
            supplied.push(false);
        }

        for (source_index, argument) in arguments.iter().enumerate() {
            self.work()?;
            let Some(argument_value) = argument.expression() else {
                return Err(self.aggregate_not_supported(argument.source));
            };
            if field_count != 1 && argument.name.is_none() {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "a comptime structure with more than one field requires every constructor argument to be named",
                ));
            }
            let field_index = if let Some(argument_name) = &argument.name {
                let mut selected = None;
                for (index, field) in aggregate.fields.iter().enumerate() {
                    self.work()?;
                    if self.names_equal(field.name.as_str(), argument_name.as_str())?
                        && selected.replace(index).is_some()
                    {
                        return Err(self.diagnostic(
                            argument.source,
                            "semantic-comptime-constructor-argument",
                            "comptime structure field name is ambiguous",
                        ));
                    }
                }
                selected.ok_or_else(|| {
                    self.diagnostic(
                        argument.source,
                        "semantic-comptime-constructor-argument",
                        "comptime constructor argument does not name a declared field",
                    )
                })?
            } else {
                source_index
            };
            let field = aggregate.fields.get(field_index).ok_or_else(|| {
                self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "comptime constructor supplies too many positional fields",
                )
            })?;
            self.require_field_visible(field, caller_module == target_module, argument.source)?;
            let field_type = self
                .scalar_type(&field.ty)
                .ok_or_else(|| self.aggregate_not_supported(field.ty.source))?;
            let slot = supplied.get_mut(field_index).ok_or_else(|| {
                self.invariant("resolved comptime constructor field slot is absent")
            })?;
            if *slot {
                return Err(self.diagnostic(
                    argument.source,
                    "semantic-comptime-constructor-argument",
                    "comptime constructor supplies one field more than once",
                ));
            }
            *slot = true;
            self.check_expression(argument_value, Some(field_type), caller, depth + 1)?;
        }
        for supplied in &supplied {
            self.work()?;
            if !supplied {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-constructor-argument",
                    "comptime structure construction must supply every field exactly once",
                ));
            }
        }
        self.release_storage(entries);
        self.require_expected(ComptimeType::Structure(structure), expected, source)
    }

    /// Look up a parameter belonging to `declaration`. A receiver (`self`) is
    /// a legal result here: callers that must reject it (ordinary call
    /// argument binding) check `parameter.receiver` explicitly at their own
    /// call site, since a receiver is reachable only through operator
    /// desugaring, never through explicit call-argument syntax.
    fn parameter(
        &self,
        id: ParameterId,
        declaration: DeclarationId,
        source: Span,
    ) -> CheckResult<&'a wrela_hir::Parameter> {
        self.program
            .parameter(id)
            .filter(|parameter| {
                parameter.id == id && parameter.owner == CallableOwner::Declaration(declaration)
            })
            .ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-call-argument",
                    "comptime parameter does not belong to the called function",
                )
            })
    }

    fn parameter_type(
        &mut self,
        id: ParameterId,
        declaration: DeclarationId,
        source: Span,
    ) -> CheckResult<ComptimeType> {
        let parameter = self.parameter(id, declaration, source)?;
        let ty = if parameter.receiver {
            crate::interfaces::receiver_concrete_struct(self.program, declaration)
                .map(ComptimeType::Structure)
        } else {
            match parameter.ty.as_ref() {
                Some(ty) => self.source_type(ty)?,
                None => None,
            }
        };
        ty.ok_or_else(|| self.signature_diagnostic(parameter.source))
    }

    fn local_declared_type(
        &mut self,
        id: LocalId,
        declaration: DeclarationId,
        source: Span,
    ) -> CheckResult<Option<ComptimeType>> {
        let local = self.local(id, declaration, source)?;
        match local.ty.as_ref() {
            Some(ty) => self
                .source_type(ty)?
                .map(Some)
                .ok_or_else(|| self.signature_diagnostic(ty.source)),
            None => Ok(None),
        }
    }

    fn local(
        &self,
        id: LocalId,
        declaration: DeclarationId,
        source: Span,
    ) -> CheckResult<&'a wrela_hir::Local> {
        self.program
            .local(id)
            .filter(|local| {
                local.id == id
                    && self
                        .program
                        .body(local.body)
                        .is_some_and(|body| body.owner == BodyOwner::Declaration(declaration))
            })
            .ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-local",
                    "comptime local does not belong to the active function",
                )
            })
    }

    fn bind_local(&mut self, id: LocalId, ty: ComptimeType, source: Span) -> CheckResult<()> {
        let slot_index = id.0 as usize;
        if slot_index >= self.local_types.len() {
            return Err(self.invariant("comptime local type slot is absent"));
        }
        let slot = &mut self.local_types[slot_index];
        if slot.is_some_and(|existing| existing != ty) {
            return Err(self.type_mismatch(source));
        }
        *slot = Some(ty);
        self.mark_local_initialized(id, source)?;
        Ok(())
    }

    fn require_local_initialized(&self, id: LocalId, source: Span) -> CheckResult<()> {
        match self.local_initialized.get(id.0 as usize) {
            Some(true) => Ok(()),
            Some(false) => Err(self.diagnostic(
                source,
                "semantic-comptime-use-after-move",
                "comptime local is used after its aggregate value was moved",
            )),
            None => Err(self.invariant("comptime local initialization slot is absent")),
        }
    }

    fn mark_local_initialized(&mut self, id: LocalId, _source: Span) -> CheckResult<()> {
        let Some(initialized) = self.local_initialized.get_mut(id.0 as usize) else {
            return Err(self.invariant("comptime local initialization slot is absent"));
        };
        *initialized = true;
        self.work()
    }

    fn mark_local_moved(&mut self, id: LocalId, _source: Span) -> CheckResult<()> {
        let Some(initialized) = self.local_initialized.get_mut(id.0 as usize) else {
            return Err(self.invariant("comptime local initialization slot is absent"));
        };
        *initialized = false;
        self.work()
    }

    fn allocate_initialization_snapshot(&self) -> CheckResult<Vec<bool>> {
        let entries = u64::try_from(self.local_initialized.len()).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        self.retain_storage(entries)?;
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(self.local_initialized.len())
            .map_err(|_| {
                self.resource_failure(
                    "comptime source checker storage entries",
                    self.limits.storage_entries,
                )
            })?;
        for initialized in &self.local_initialized {
            self.work()?;
            snapshot.push(*initialized);
        }
        Ok(snapshot)
    }

    fn restore_initialization_snapshot(&mut self, snapshot: &[bool]) -> CheckResult<()> {
        if snapshot.len() != self.local_initialized.len() {
            return Err(self.invariant("comptime initialization snapshot has the wrong length"));
        }
        for (index, initialized) in snapshot.iter().copied().enumerate() {
            self.work()?;
            let Some(slot) = self.local_initialized.get_mut(index) else {
                return Err(self.invariant("comptime initialization slot is absent"));
            };
            *slot = initialized;
        }
        Ok(())
    }

    fn capture_initialization_snapshot(&self, snapshot: &mut [bool]) -> CheckResult<()> {
        if snapshot.len() != self.local_initialized.len() {
            return Err(self.invariant("comptime initialization snapshot has the wrong length"));
        }
        for (index, slot) in snapshot.iter_mut().enumerate() {
            self.work()?;
            *slot = self.local_initialized[index];
        }
        Ok(())
    }

    fn intersect_initialization_snapshot(&self, snapshot: &mut [bool]) -> CheckResult<()> {
        if snapshot.len() != self.local_initialized.len() {
            return Err(self.invariant("comptime initialization snapshot has the wrong length"));
        }
        for (index, slot) in snapshot.iter_mut().enumerate() {
            self.work()?;
            *slot &= self.local_initialized[index];
        }
        Ok(())
    }

    fn release_initialization_snapshot(&self, snapshot: Vec<bool>) -> CheckResult<()> {
        let entries = u64::try_from(snapshot.len()).map_err(|_| {
            self.invariant("comptime initialization snapshot length is not representable")
        })?;
        self.release_storage(entries);
        drop(snapshot);
        Ok(())
    }

    fn bound_local_type(
        &mut self,
        id: LocalId,
        declaration: DeclarationId,
        source: Span,
    ) -> CheckResult<ComptimeType> {
        let declared = self.local_declared_type(id, declaration, source)?;
        declared
            .or_else(|| self.local_types.get(id.0 as usize).copied().flatten())
            .ok_or_else(|| {
                self.diagnostic(
                    source,
                    "semantic-comptime-uninitialized",
                    "unannotated comptime local is used before its initializer fixes its type",
                )
            })
    }

    fn scalar_type(&self, ty: &TypeExpression) -> Option<ComptimeType> {
        let TypeExpressionKind::Named {
            definition: Definition::Builtin(builtin),
            arguments,
        } = &ty.kind
        else {
            return None;
        };
        if !arguments.is_empty() {
            return None;
        }
        Some(match builtin {
            Builtin::Unit => ComptimeType::Unit,
            Builtin::Bool => ComptimeType::Bool,
            Builtin::U8 => ComptimeType::Integer {
                signed: false,
                bits: 8,
            },
            Builtin::U16 => ComptimeType::Integer {
                signed: false,
                bits: 16,
            },
            Builtin::U32 => ComptimeType::Integer {
                signed: false,
                bits: 32,
            },
            Builtin::U64 => ComptimeType::Integer {
                signed: false,
                bits: 64,
            },
            Builtin::U128 => ComptimeType::Integer {
                signed: false,
                bits: 128,
            },
            Builtin::Usize => ComptimeType::Integer {
                signed: false,
                bits: self.pointer_width,
            },
            Builtin::I8 => ComptimeType::Integer {
                signed: true,
                bits: 8,
            },
            Builtin::I16 => ComptimeType::Integer {
                signed: true,
                bits: 16,
            },
            Builtin::I32 => ComptimeType::Integer {
                signed: true,
                bits: 32,
            },
            Builtin::I64 => ComptimeType::Integer {
                signed: true,
                bits: 64,
            },
            Builtin::I128 => ComptimeType::Integer {
                signed: true,
                bits: 128,
            },
            Builtin::Isize => ComptimeType::Integer {
                signed: true,
                bits: self.pointer_width,
            },
            Builtin::Never
            | Builtin::F32
            | Builtin::F64
            | Builtin::Char
            | Builtin::Static
            | Builtin::Str
            | Builtin::Bytes
            | Builtin::String
            | Builtin::Option
            | Builtin::Result
            | Builtin::Actor
            | Builtin::Receipt
            | Builtin::Dma
            | Builtin::Mmio
            | Builtin::Validated => return None,
        })
    }

    fn source_type(&mut self, ty: &TypeExpression) -> CheckResult<Option<ComptimeType>> {
        if let Some(scalar) = self.scalar_type(ty) {
            return Ok(Some(scalar));
        }
        if let TypeExpressionKind::SelfType { owner } = &ty.kind {
            let Some(id) = crate::interfaces::concrete_struct_for_self_owner(self.program, *owner)
            else {
                return Ok(None);
            };
            self.ensure_flat_structure(id, ty.source)?;
            return Ok(Some(ComptimeType::Structure(id)));
        }
        let TypeExpressionKind::Named {
            definition: Definition::Declaration(resolved),
            arguments,
        } = &ty.kind
        else {
            return Ok(None);
        };
        if !arguments.is_empty() {
            return Ok(None);
        }
        let declaration = self.hir.resolved_declaration(resolved).ok_or_else(|| {
            self.invariant("resolved comptime source type identity is absent from HIR")
        })?;
        let id = declaration.id;
        if !matches!(&declaration.kind, DeclarationKind::Structure(_)) {
            return Ok(None);
        }
        self.ensure_flat_structure(id, ty.source)?;
        Ok(Some(ComptimeType::Structure(id)))
    }

    fn ensure_flat_structure(&mut self, id: DeclarationId, source: Span) -> CheckResult<()> {
        let declaration = self
            .program
            .declaration(id)
            .ok_or_else(|| self.invariant("comptime structure type is absent from HIR"))?;
        let declaration_source = declaration.source;
        let DeclarationKind::Structure(aggregate) = &declaration.kind else {
            return Err(self.aggregate_not_supported(source));
        };
        if !aggregate.generics.is_empty() || !aggregate.implements.is_empty() {
            return Err(self.aggregate_not_supported(declaration_source));
        }
        self.node(declaration_source)?;
        let field_count = aggregate.fields.len();
        for index in 0..field_count {
            let field = self
                .program
                .declaration(id)
                .and_then(|declaration| match &declaration.kind {
                    DeclarationKind::Structure(aggregate) => aggregate.fields.get(index),
                    _ => None,
                })
                .ok_or_else(|| self.invariant("comptime structure field is absent from HIR"))?;
            let field_source = field.source;
            let supported = field.default.is_none()
                && field.attributes.is_empty()
                && self.scalar_type(&field.ty).is_some();
            self.node(field_source)?;
            if !supported {
                return Err(self.aggregate_not_supported(field_source));
            }
        }
        Ok(())
    }

    fn require_field_visible(
        &self,
        field: &wrela_hir::Field,
        same_module: bool,
        source: Span,
    ) -> CheckResult<()> {
        if same_module || field.visibility != wrela_hir::Visibility::Private {
            Ok(())
        } else {
            Err(self.diagnostic(
                source,
                "semantic-comptime-field-private",
                "comptime structure field is private to its declaring module",
            ))
        }
    }

    fn integer_literal_type(
        &mut self,
        spelling: &str,
        expected: Option<ComptimeType>,
        source: Span,
    ) -> CheckResult<ComptimeType> {
        let value = self.scan_integer_spelling(spelling)?.ok_or_else(|| {
            self.diagnostic(
                source,
                "semantic-comptime-integer-literal",
                "integer literal is not valid in the comptime scalar domain",
            )
        })?;
        let ty = match expected {
            Some(ty @ ComptimeType::Integer { signed, bits }) => {
                let maximum = if signed {
                    integer_mask(bits) >> 1
                } else {
                    integer_mask(bits)
                };
                if value > maximum {
                    return Err(self.diagnostic(
                        source,
                        "semantic-comptime-integer-literal",
                        "integer literal does not fit its target scalar type",
                    ));
                }
                ty
            }
            Some(ComptimeType::Unit | ComptimeType::Bool | ComptimeType::Structure(_)) => {
                return Err(self.type_mismatch(source));
            }
            None if value <= i64::MAX as u128 => ComptimeType::Integer {
                signed: true,
                bits: 64,
            },
            None if value <= u64::MAX as u128 => ComptimeType::Integer {
                signed: false,
                bits: 64,
            },
            None => {
                return Err(self.diagnostic(
                    source,
                    "semantic-comptime-integer-literal",
                    "unconstrained integer literal exceeds the u64 default domain",
                ));
            }
        };
        Ok(ty)
    }

    fn negative_integer_literal_type(
        &mut self,
        spelling: &str,
        expected: Option<ComptimeType>,
        source: Span,
    ) -> CheckResult<ComptimeType> {
        let magnitude = self.scan_integer_spelling(spelling)?.ok_or_else(|| {
            self.diagnostic(
                source,
                "semantic-comptime-integer-literal",
                "negative integer literal is not valid in the comptime scalar domain",
            )
        })?;
        let ty = match expected {
            Some(ty @ ComptimeType::Integer { signed: true, .. }) => ty,
            Some(_) => return Err(self.type_mismatch(source)),
            None => ComptimeType::Integer {
                signed: true,
                bits: 64,
            },
        };
        let ComptimeType::Integer { bits, .. } = ty else {
            return Err(self.type_mismatch(source));
        };
        let maximum_magnitude = 1_u128 << u32::from(bits - 1);
        if magnitude > maximum_magnitude {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-integer-literal",
                "negative integer literal does not fit its target scalar type",
            ));
        }
        Ok(ty)
    }

    fn scan_integer_spelling(&mut self, value: &str) -> CheckResult<Option<u128>> {
        let (digits, radix) = value.strip_prefix("0x").map_or_else(
            || {
                value.strip_prefix("0o").map_or_else(
                    || {
                        value
                            .strip_prefix("0b")
                            .map_or((value, 10), |digits| (digits, 2))
                    },
                    |digits| (digits, 8),
                )
            },
            |digits| (digits, 16),
        );
        for _ in 0..value.len().saturating_sub(digits.len()) {
            self.work()?;
        }
        let mut result = 0_u128;
        for byte in digits.bytes() {
            self.work()?;
            if byte == b'_' {
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => u128::from(byte - b'0'),
                b'a'..=b'f' => u128::from(byte - b'a' + 10),
                b'A'..=b'F' => u128::from(byte - b'A' + 10),
                _ => return Ok(None),
            };
            if digit >= radix {
                return Ok(None);
            }
            let Some(next) = result
                .checked_mul(radix)
                .and_then(|result| result.checked_add(digit))
            else {
                return Ok(None);
            };
            result = next;
        }
        Ok(Some(result))
    }

    fn require_expected(
        &self,
        actual: ComptimeType,
        expected: Option<ComptimeType>,
        source: Span,
    ) -> CheckResult<ComptimeType> {
        if expected.is_some_and(|expected| expected != actual) {
            Err(self.type_mismatch(source))
        } else {
            Ok(actual)
        }
    }

    fn names_equal(&mut self, left: &str, right: &str) -> CheckResult<bool> {
        self.work()?;
        if left.len() != right.len() {
            return Ok(false);
        }
        for (left, right) in left.bytes().zip(right.bytes()) {
            self.work()?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn queue_declaration(
        &mut self,
        id: DeclarationId,
        source: Span,
        parent: Option<CallParent>,
    ) -> CheckResult<()> {
        self.poll()?;
        let state_index = id.0 as usize;
        if state_index >= self.states.len() {
            return Err(self.diagnostic(
                source,
                "semantic-comptime-call-target",
                "comptime call target is absent from HIR",
            ));
        }
        match self.states[state_index] {
            VisitState::Unseen => {
                self.retain_storage(1)?;
                self.pending.try_reserve(1).map_err(|_| {
                    self.resource_failure(
                        "comptime source checker storage entries",
                        self.limits.storage_entries,
                    )
                })?;
                let pending_index = self.pending.len();
                self.pending.push(PendingDeclaration {
                    declaration: id,
                    parent,
                });
                self.states[state_index] = VisitState::Visiting(pending_index);
            }
            VisitState::Visiting(_) | VisitState::Checked(_) => {}
        }
        Ok(())
    }

    fn enter_syntax(&self, depth: u32) -> CheckResult<()> {
        if depth > self.limits.syntax_depth {
            Err(self.resource_failure(
                "comptime source checker syntax depth",
                u64::from(self.limits.syntax_depth),
            ))
        } else {
            Ok(())
        }
    }

    fn node(&mut self, _source: Span) -> CheckResult<()> {
        self.work()?;
        self.nodes = self.nodes.checked_add(1).ok_or_else(|| {
            self.resource_failure("comptime source checker work units", self.limits.work_units)
        })?;
        Ok(())
    }

    fn work(&self) -> CheckResult<()> {
        self.poll()?;
        let work_units = self.work_units.get().checked_add(1).ok_or_else(|| {
            self.resource_failure("comptime source checker work units", self.limits.work_units)
        })?;
        self.work_units.set(work_units);
        if work_units > self.limits.work_units {
            return Err(
                self.resource_failure("comptime source checker work units", self.limits.work_units)
            );
        }
        Ok(())
    }

    fn poll(&self) -> CheckResult<()> {
        if (self.is_cancelled)() {
            Err(CheckFailure::Analysis(AnalysisFailure::Cancelled))
        } else {
            Ok(())
        }
    }

    fn retain_storage(&self, entries: u64) -> CheckResult<()> {
        self.poll()?;
        let storage_entries = self
            .storage_entries
            .get()
            .checked_add(entries)
            .ok_or_else(|| {
                self.resource_failure(
                    "comptime source checker storage entries",
                    self.limits.storage_entries,
                )
            })?;
        self.storage_entries.set(storage_entries);
        if storage_entries > self.limits.storage_entries {
            return Err(self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            ));
        }
        Ok(())
    }

    fn release_storage(&self, entries: u64) {
        self.storage_entries
            .set(self.storage_entries.get().saturating_sub(entries));
    }

    fn unsupported(&self, source: Span) -> CheckFailure {
        self.diagnostic(
            source,
            "semantic-comptime-operation-not-implemented",
            "this comptime operation is not yet implemented by the production semantic analyzer",
        )
    }

    fn aggregate_not_supported(&self, source: Span) -> CheckFailure {
        self.diagnostic(
            source,
            "semantic-comptime-aggregate-not-supported",
            "comptime aggregate values currently support only nongeneric structures with scalar fields and no defaults or interface specializations",
        )
    }

    fn signature_diagnostic(&self, source: Span) -> CheckFailure {
        self.diagnostic(
            source,
            "semantic-comptime-signature-not-supported",
            "comptime source unit tests support only nongeneric value-parameter scalar and flat scalar-field structure functions",
        )
    }

    fn call_signature_diagnostic(
        &self,
        source: Span,
        declaration: DeclarationId,
        call_source: Span,
    ) -> CheckFailure {
        self.diagnostic_with_attempted_call(
            source,
            "semantic-comptime-signature-not-supported",
            "comptime source unit tests support only nongeneric value-parameter scalar and flat scalar-field structure functions",
            Some((declaration, call_source)),
        )
    }

    fn type_mismatch(&self, source: Span) -> CheckFailure {
        self.diagnostic(
            source,
            "semantic-comptime-type-mismatch",
            "comptime value does not match its required target type",
        )
    }

    fn diagnostic(&self, source: Span, code: &str, message: &str) -> CheckFailure {
        self.diagnostic_with_attempted_call(source, code, message, None)
    }

    fn diagnostic_with_attempted_call(
        &self,
        source: Span,
        code: &str,
        message: &str,
        attempted_call: Option<(DeclarationId, Span)>,
    ) -> CheckFailure {
        match self.build_diagnostic(source, code, message, attempted_call) {
            Ok(diagnostic) => self.retain_diagnostic_envelope(diagnostic),
            Err(error) => error,
        }
    }

    fn retain_diagnostic_envelope(&self, diagnostic: Diagnostic) -> CheckFailure {
        if let Err(error) = self.retain_storage(1) {
            return error;
        }
        let mut diagnostics = Vec::new();
        if let Err(error) = self.poll() {
            return error;
        }
        if diagnostics.try_reserve_exact(1).is_err() {
            return self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            );
        }
        diagnostics.push(diagnostic);
        CheckFailure::Diagnostic(diagnostics)
    }

    fn build_diagnostic(
        &self,
        source: Span,
        code: &str,
        message: &str,
        attempted_call: Option<(DeclarationId, Span)>,
    ) -> CheckResult<Diagnostic> {
        let mut stack_entries = 0usize;
        self.visit_stack_labels(attempted_call, |_, _, _| {
            stack_entries = stack_entries.checked_add(1).ok_or_else(|| {
                self.resource_failure(
                    "comptime source checker storage entries",
                    self.limits.storage_entries,
                )
            })?;
            Ok(())
        })?;
        let label_entries = u64::try_from(stack_entries).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;

        // Measure the entire returned diagnostic before allocating any of its
        // owned strings or label storage. The later construction pass is
        // separately metered because it performs a second linear copy.
        let mut output_bytes = 0u64;
        self.scan_diagnostic_text(code, &mut output_bytes)?;
        self.scan_diagnostic_text(message, &mut output_bytes)?;
        let label_structural_bytes = label_entries
            .checked_mul(COMPTIME_DIAGNOSTIC_LABEL_STRUCTURAL_BYTES)
            .ok_or_else(|| self.diagnostic_allocation_failure())?;
        self.charge_diagnostic_bytes(&mut output_bytes, label_structural_bytes)?;
        self.visit_stack_labels(attempted_call, |checker, declaration, _| {
            let label_bytes = checker.stack_label_bytes(declaration)?;
            checker.charge_diagnostic_bytes(&mut output_bytes, label_bytes)
        })?;

        // A retained Label is one canonical structural entry. Charging the
        // full count before reserve keeps Vec capacity attacks under the same
        // checker storage contract as pending/checked declarations.
        self.retain_storage(label_entries)?;
        let mut labels = Vec::new();
        self.poll()?;
        labels.try_reserve_exact(stack_entries).map_err(|_| {
            self.resource_failure(
                "comptime source checker storage entries",
                self.limits.storage_entries,
            )
        })?;
        let message = self.copy_diagnostic_text(message)?;
        let code = self.copy_diagnostic_text(code)?;
        self.visit_stack_labels(attempted_call, |checker, declaration, call_source| {
            let label_bytes = checker.stack_label_bytes(declaration)?;
            let label_bytes = usize::try_from(label_bytes)
                .map_err(|_| checker.diagnostic_allocation_failure())?;
            labels.push(checker.stack_label(declaration, call_source, label_bytes)?);
            Ok(())
        })?;
        if labels.len() != stack_entries {
            return Err(
                self.invariant("comptime checker diagnostic stack changed during construction")
            );
        }

        let mut diagnostic = Diagnostic::error(Category::COMPTIME, source, message);
        diagnostic.code = Some(code);
        diagnostic.labels = labels;
        Ok(diagnostic)
    }

    fn visit_stack_labels(
        &self,
        attempted_call: Option<(DeclarationId, Span)>,
        mut visit: impl FnMut(&Self, DeclarationId, Span) -> CheckResult<()>,
    ) -> CheckResult<()> {
        if let Some((declaration, call_source)) = attempted_call {
            self.work()?;
            visit(self, declaration, call_source)?;
        }
        let mut current = self.current_declaration;
        let mut walked = 0usize;
        while let Some(declaration) = current {
            self.work()?;
            walked = walked.checked_add(1).ok_or_else(|| {
                self.invariant("comptime checker first-parent call graph is cyclic")
            })?;
            if walked > self.states.len() {
                return Err(self.invariant("comptime checker first-parent call graph is cyclic"));
            }
            let Some(parent) = self.call_parent(declaration) else {
                break;
            };
            visit(self, declaration, parent.call_source)?;
            current = Some(parent.caller);
        }
        Ok(())
    }

    fn call_parent(&self, declaration: DeclarationId) -> Option<CallParent> {
        let pending_index = match self.states.get(declaration.0 as usize)? {
            VisitState::Visiting(index) | VisitState::Checked(index) => *index,
            VisitState::Unseen => return None,
        };
        self.pending.get(pending_index)?.parent
    }

    fn stack_label_bytes(&self, declaration: DeclarationId) -> CheckResult<u64> {
        let declaration = self
            .program
            .declaration(declaration)
            .ok_or_else(|| self.invariant("comptime checker stack declaration is absent"))?;
        let module = self
            .program
            .modules
            .get(declaration.module.0 as usize)
            .ok_or_else(|| self.invariant("comptime checker stack module is absent"))?;
        let name = declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or_else(|| self.invariant("comptime checker stack function is anonymous"))?;
        const PREFIX: &str = "comptime call to `";
        const SUFFIX: &str = "` entered here";
        let mut message_bytes =
            u64::try_from(PREFIX.len()).map_err(|_| self.diagnostic_allocation_failure())?;
        for (index, segment) in module.path.segments().iter().enumerate() {
            if index != 0 {
                message_bytes = message_bytes
                    .checked_add(1)
                    .ok_or_else(|| self.diagnostic_allocation_failure())?;
            }
            message_bytes = message_bytes
                .checked_add(self.scan_source_text(segment)?)
                .ok_or_else(|| self.diagnostic_allocation_failure())?;
        }
        let name_bytes = self.scan_source_text(name)?;
        let suffix_bytes =
            u64::try_from(SUFFIX.len()).map_err(|_| self.diagnostic_allocation_failure())?;
        message_bytes = message_bytes
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(name_bytes))
            .and_then(|bytes| bytes.checked_add(suffix_bytes))
            .ok_or_else(|| self.diagnostic_allocation_failure())?;
        Ok(message_bytes)
    }

    fn stack_label(
        &self,
        declaration: DeclarationId,
        call_source: Span,
        message_bytes: usize,
    ) -> CheckResult<wrela_diagnostics::Label> {
        let declaration = self
            .program
            .declaration(declaration)
            .ok_or_else(|| self.invariant("comptime checker stack declaration is absent"))?;
        let module = self
            .program
            .modules
            .get(declaration.module.0 as usize)
            .ok_or_else(|| self.invariant("comptime checker stack module is absent"))?;
        let name = declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str)
            .ok_or_else(|| self.invariant("comptime checker stack function is anonymous"))?;
        const PREFIX: &str = "comptime call to `";
        const SUFFIX: &str = "` entered here";
        let mut message = String::new();
        self.poll()?;
        message
            .try_reserve_exact(message_bytes)
            .map_err(|_| self.diagnostic_allocation_failure())?;
        self.append_diagnostic_text(&mut message, PREFIX)?;
        for (index, segment) in module.path.segments().iter().enumerate() {
            if index != 0 {
                self.append_diagnostic_text(&mut message, ".")?;
            }
            self.append_diagnostic_text(&mut message, segment)?;
        }
        self.append_diagnostic_text(&mut message, ".")?;
        self.append_diagnostic_text(&mut message, name)?;
        self.append_diagnostic_text(&mut message, SUFFIX)?;
        if message.len() != message_bytes {
            return Err(
                self.invariant("comptime checker stack label size changed during construction")
            );
        }
        Ok(wrela_diagnostics::Label {
            span: call_source,
            message,
        })
    }

    fn scan_source_text(&self, value: &str) -> CheckResult<u64> {
        let mut bytes = 0u64;
        for _ in value.as_bytes() {
            self.work()?;
            bytes = bytes
                .checked_add(1)
                .ok_or_else(|| self.diagnostic_allocation_failure())?;
        }
        Ok(bytes)
    }

    fn scan_diagnostic_text(&self, value: &str, total: &mut u64) -> CheckResult<()> {
        for _ in value.as_bytes() {
            self.work()?;
            self.charge_diagnostic_bytes(total, 1)?;
        }
        Ok(())
    }

    fn charge_diagnostic_bytes(&self, total: &mut u64, bytes: u64) -> CheckResult<()> {
        let next = total
            .checked_add(bytes)
            .ok_or_else(|| self.diagnostic_allocation_failure())?;
        if next > self.limits.diagnostic_bytes {
            return Err(self.resource_failure("diagnostic bytes", self.limits.diagnostic_bytes));
        }
        if next > self.limits.test_bytes {
            return Err(self.resource_failure("test plan or results", self.limits.test_bytes));
        }
        *total = next;
        Ok(())
    }

    fn copy_diagnostic_text(&self, value: &str) -> CheckResult<String> {
        let mut output = String::new();
        self.poll()?;
        output
            .try_reserve_exact(value.len())
            .map_err(|_| self.diagnostic_allocation_failure())?;
        self.append_diagnostic_text(&mut output, value)?;
        Ok(output)
    }

    fn append_diagnostic_text(&self, output: &mut String, value: &str) -> CheckResult<()> {
        for character in value.chars() {
            for _ in 0..character.len_utf8() {
                self.work()?;
            }
            output.push(character);
        }
        Ok(())
    }

    fn diagnostic_allocation_failure(&self) -> CheckFailure {
        if self.limits.diagnostic_bytes <= self.limits.test_bytes {
            self.resource_failure("diagnostic bytes", self.limits.diagnostic_bytes)
        } else {
            self.resource_failure("test plan or results", self.limits.test_bytes)
        }
    }

    fn invariant(&self, message: &str) -> CheckFailure {
        CheckFailure::Analysis(AnalysisFailure::InternalInvariant(message.to_owned()))
    }

    fn resource_failure(&self, resource: &'static str, limit: u64) -> CheckFailure {
        CheckFailure::Analysis(AnalysisFailure::ResourceLimit { resource, limit })
    }
}

fn integer_mask(bits: u16) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << u32::from(bits)) - 1
    }
}

fn fallback_span(program: &wrela_hir::Program) -> Span {
    program.modules.first().map_or(
        Span {
            file: wrela_source::FileId(0),
            range: wrela_source::TextRange { start: 0, end: 0 },
        },
        |module| module.source,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use wrela_build_model::Sha256Digest;
    use wrela_hir_lower::{
        CanonicalHirLowerer, ChangeSet, HirLowerer, LowerRequest, LoweringLimits,
    };
    use wrela_package::{
        ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
    };
    use wrela_source::{SourceDatabase, SourceInput};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};

    const MATH: &str = "module app.math\n\npub fn add(left: u32, right: u32) -> u32:\n    return left + right\n\npub fn countdown(value: u32) -> u32:\n    if value == 0:\n        return 0\n    return countdown(value - 1)\n";
    const TEST: &str = "module app.math_test\n\nfrom app.math import add, countdown\n\n@test\nfn scalar_closure():\n    value = add(right=22, left=20)\n    zero: u32 = countdown(2)\n    comptime assert value == 42 and zero == 0, \"scalar closure\"\n";

    fn lower(math: &str, test: &str) -> ValidatedProgram {
        let mut sources = SourceDatabase::default();
        let math_file = sources
            .add(SourceInput {
                path: "app/math.wr".to_owned(),
                text: math.to_owned(),
                digest: Sha256Digest::from_bytes([0x31; 32]),
            })
            .expect("math source");
        let test_file = sources
            .add(SourceInput {
                path: "app/math_test.wr".to_owned(),
                text: test.to_owned(),
                digest: Sha256Digest::from_bytes([0x32; 32]),
            })
            .expect("test source");
        let mut parsed_files = Vec::new();
        for file in [math_file, test_file] {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &|| false,
                )
                .expect("source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed_files.push(parsed);
        }

        let identity = PackageIdentity {
            name: PackageName::new("checker-tests").expect("package name"),
            version: PackageVersion::new("1.0.0").expect("package version"),
            source_digest: Sha256Digest::from_bytes([0x40; 32]),
        };
        let mut graph = PackageGraphBuilder::new(identity);
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["app".to_owned(), "math".to_owned()]).expect("math module"),
                math_file,
            )
            .expect("math graph module");
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["app".to_owned(), "math_test".to_owned()]).expect("test module"),
                test_file,
            )
            .expect("test graph module");
        let changes = ChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let output = CanonicalHirLowerer::new()
            .lower(
                LowerRequest {
                    packages: Arc::new(graph.finish().expect("package graph")),
                    source_graph_digest: Sha256Digest::from_bytes([0x41; 32]),
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &changes,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("source lowers");
        assert!(
            output.diagnostics().is_empty(),
            "lowering diagnostics: {:?}",
            output.diagnostics()
        );
        output.into_parts().0.into_program()
    }

    fn limits(work_units: u64) -> ComptimeCheckLimits {
        ComptimeCheckLimits {
            work_units,
            storage_entries: 1_000_000,
            syntax_depth: 32,
            diagnostic_bytes: 1_000_000,
            test_bytes: 1_000_000,
        }
    }

    fn long_first_parent_sources(depth: usize, name_bytes: usize) -> (String, String) {
        assert!(depth >= 2);
        let suffix = "q".repeat(name_bytes);
        let names = (0..depth)
            .map(|index| format!("layer_{index}_{suffix}"))
            .collect::<Vec<_>>();
        let mut math = String::from("module app.math\n\n");
        for (index, name) in names.iter().enumerate() {
            if let Some(next) = names.get(index + 1) {
                math.push_str(&format!(
                    "pub fn {name}() -> bool:\n    return {next}()\n\n"
                ));
            } else {
                math.push_str(&format!(
                    "pub fn {name}() -> bool:\n    loop:\n        pass\n    return true\n"
                ));
            }
        }
        let first = &names[0];
        let test = format!(
            "module app.math_test\n\nfrom app.math import {first}\n\n@test\nfn long_qualified_first_parent_stack():\n    comptime assert {first}(), \"long stack\"\n"
        );
        (math, test)
    }

    fn minimum_admitted_limit(
        mut low: u64,
        mut high: u64,
        mut admitted: impl FnMut(u64) -> bool,
    ) -> u64 {
        assert!(low <= high);
        assert!(admitted(high), "upper calibration bound must be admitted");
        while low < high {
            let middle = low + (high - low) / 2;
            if admitted(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    fn accounted_diagnostic_bytes(diagnostic: &Diagnostic) -> u64 {
        let mut bytes = u64::try_from(diagnostic.message.len()).expect("message bytes fit u64");
        bytes = bytes
            .checked_add(
                diagnostic
                    .code
                    .as_ref()
                    .map_or(0, String::len)
                    .try_into()
                    .expect("code bytes fit u64"),
            )
            .expect("bounded diagnostic bytes");
        for label in &diagnostic.labels {
            bytes = bytes
                .checked_add(u64::try_from(label.message.len()).expect("label bytes fit u64"))
                .and_then(|bytes| bytes.checked_add(COMPTIME_DIAGNOSTIC_LABEL_STRUCTURAL_BYTES))
                .expect("bounded diagnostic label bytes");
        }
        bytes
    }

    #[test]
    fn checks_real_imported_named_recursive_closure_with_an_exact_work_bound() {
        let hir = lower(MATH, TEST);
        let root = hir.as_program().test_candidates[0];
        let checked = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(1_000_000),
            &|| false,
        )
        .expect("checker analysis")
        .expect("supported closure");
        assert_eq!(checked.declarations.len(), 3);
        assert_eq!(checked.declarations[0].declaration, root);
        assert!(checked.node_count > 0);
        assert!(checked.work_count > checked.node_count);

        let exact = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(checked.work_count),
            &|| false,
        )
        .expect("exact checker analysis")
        .expect("exact bound is admitted");
        assert_eq!(exact, checked);
        assert!(matches!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(checked.work_count - 1),
                &|| false,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker work units",
                limit,
            }) if limit == checked.work_count - 1
        ));
    }

    #[test]
    fn aggregate_branch_initialization_snapshots_have_exact_storage_and_join_paths() {
        const VALUES: &str = r#"module app.math

pub struct Pair:
    pub left: u32
    pub right: u32

pub fn make(left: u32, right: u32) -> Pair:
    return Pair(right=right, left=left)
"#;
        const VALID: &str = r#"module app.math_test

from app.math import make

@test
fn every_path_reinitializes():
    value = make(left=20, right=22)
    if true:
        moved = value
        value = make(left=moved.left, right=1)
    else:
        moved = value
        value = make(left=moved.right, right=2)
    comptime assert value.left == 20, "joined value"
"#;
        let hir = lower(VALUES, VALID);
        let root = hir.as_program().test_candidates[0];
        let exact_storage = minimum_admitted_limit(1, 1_000_000, |storage_entries| {
            let mut candidate = limits(10_000_000);
            candidate.storage_entries = storage_entries;
            matches!(
                check_source_comptime_unit_test(
                    &hir,
                    hir.as_program().packages.root(),
                    64,
                    root,
                    candidate,
                    &|| false
                ),
                Ok(Ok(_))
            )
        });
        let mut exact = limits(10_000_000);
        exact.storage_entries = exact_storage;
        check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            exact,
            &|| false,
        )
        .expect("exact branch snapshot analysis")
        .expect("every continuing path reinitializes the aggregate");
        let mut over = exact;
        over.storage_entries = exact_storage - 1;
        assert!(matches!(
            check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, over, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit,
            }) if limit == exact_storage - 1
        ));

        const INVALID: &str = r#"module app.math_test

from app.math import make

@test
fn one_path_leaves_value_moved():
    value = make(left=20, right=22)
    if true:
        moved = value
        comptime assert moved.left == 20, "moved path"
    else:
        pass
    comptime assert value.right == 22, "invalid joined value"
"#;
        let hir = lower(VALUES, INVALID);
        let root = hir.as_program().test_candidates[0];
        let diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(10_000_000),
            &|| false,
        )
        .expect("invalid branch join analysis")
        .expect_err("a move on one continuing path poisons the joined local");
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-use-after-move")
        );
    }

    #[test]
    fn checks_short_circuit_rhs_and_polls_cancellation() {
        // A plain `fn` is phase-neutral and would now be comptime-legal here,
        // so this exercises a callee color that can never be comptime-legal
        // (comptime forbids async operations) instead.
        const RUNTIME_MATH: &str =
            "module app.math\n\npub async fn runtime_only() -> bool:\n    return true\n";
        const SHORT_CIRCUIT_TEST: &str = "module app.math_test\n\nfrom app.math import runtime_only\n\n@test\nfn rejected_rhs():\n    comptime assert false and runtime_only(), \"must inspect rhs\"\n";
        let hir = lower(RUNTIME_MATH, SHORT_CIRCUIT_TEST);
        let root = hir.as_program().test_candidates[0];
        let diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(1_000_000),
            &|| false,
        )
        .expect("checker analysis")
        .expect_err("runtime RHS is rejected even though it short-circuits");
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-signature-not-supported")
        );
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(
            diagnostic.labels[0].message,
            "comptime call to `app.math.runtime_only` entered here"
        );

        let polls = Cell::new(0_u32);
        let cancelled = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 3
        };
        assert_eq!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(1_000_000),
                &cancelled,
            ),
            Err(AnalysisFailure::Cancelled)
        );
        assert_eq!(polls.get(), 3);
    }

    #[test]
    fn nested_diagnostic_uses_the_deterministic_first_parent_call_path() {
        const DIAMOND_MATH: &str = "module app.math\n\npub fn hidden() -> bool:\n    loop:\n        pass\n    return true\n\npub fn left() -> bool:\n    return hidden()\n\npub fn right() -> bool:\n    return hidden()\n";
        const DIAMOND_TEST: &str = "module app.math_test\n\nfrom app.math import left, right\n\n@test\nfn diamond_path():\n    comptime assert left() or right(), \"both branches are checked\"\n";
        let hir = lower(DIAMOND_MATH, DIAMOND_TEST);
        let root = hir.as_program().test_candidates[0];
        let diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(1_000_000),
            &|| false,
        )
        .expect("checker analysis")
        .expect_err("hidden loop is unsupported");
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("semantic-comptime-operation-not-implemented")
        );
        let labels: Vec<_> = diagnostic
            .labels
            .iter()
            .map(|label| label.message.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "comptime call to `app.math.hidden` entered here",
                "comptime call to `app.math.left` entered here",
            ]
        );
    }

    #[test]
    fn long_integer_spelling_has_exact_work_and_mid_scan_cancellation() {
        let spelling = format!("0x{}1", "0_".repeat(1_024));
        let test = format!(
            "module app.math_test\n\n@test\nfn long_literal():\n    value = {spelling}\n    comptime assert value == 1, \"long literal\"\n"
        );
        let hir = lower("module app.math\n", &test);
        let root = hir.as_program().test_candidates[0];
        let polls = Cell::new(0_u64);
        let checked = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(1_000_000),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("checker analysis")
        .expect("long literal closure");
        assert!(checked.work_count > 2_048);
        let exact = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(checked.work_count),
            &|| false,
        )
        .expect("exact work analysis")
        .expect("exact long-literal work bound");
        assert_eq!(exact.work_count, checked.work_count);
        assert!(matches!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(checked.work_count - 1),
                &|| false,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker work units",
                limit,
            }) if limit == checked.work_count - 1
        ));

        let cancel_at = polls.get() / 2;
        assert!(cancel_at > 512);
        let cancelled_polls = Cell::new(0_u64);
        assert_eq!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(1_000_000),
                &|| {
                    let next = cancelled_polls.get() + 1;
                    cancelled_polls.set(next);
                    next == cancel_at
                },
            ),
            Err(AnalysisFailure::Cancelled)
        );
        assert_eq!(cancelled_polls.get(), cancel_at);
    }

    #[test]
    fn long_stack_diagnostic_bytes_and_structural_label_bytes_are_exact() {
        const DEPTH: usize = 6;
        let (math, test) = long_first_parent_sources(DEPTH, 240);
        let hir = lower(&math, &test);
        let root = hir.as_program().test_candidates[0];
        let diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(10_000_000),
            &|| false,
        )
        .expect("generous diagnostic analysis")
        .expect_err("deep loop is unsupported");
        assert_eq!(diagnostic.labels.len(), DEPTH);
        assert!(diagnostic.labels.iter().all(|label| {
            label
                .message
                .starts_with("comptime call to `app.math.layer_")
        }));
        let exact_bytes = accounted_diagnostic_bytes(&diagnostic);
        assert!(exact_bytes > (DEPTH as u64) * COMPTIME_DIAGNOSTIC_LABEL_STRUCTURAL_BYTES);

        let mut exact_diagnostic = limits(10_000_000);
        exact_diagnostic.diagnostic_bytes = exact_bytes;
        let exact = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            exact_diagnostic,
            &|| false,
        )
        .expect("exact diagnostic-byte analysis")
        .expect_err("supported diagnostic is retained at its exact byte bound");
        assert_eq!(accounted_diagnostic_bytes(&exact), exact_bytes);

        let mut over_diagnostic = exact_diagnostic;
        over_diagnostic.diagnostic_bytes = exact_bytes - 1;
        assert!(matches!(
            check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, over_diagnostic, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit,
            }) if limit == exact_bytes - 1
        ));

        let mut exact_test = limits(10_000_000);
        exact_test.test_bytes = exact_bytes;
        let exact = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            exact_test,
            &|| false,
        )
        .expect("exact test-output-byte analysis")
        .expect_err("supported diagnostic is retained at its exact test-output bound");
        assert_eq!(accounted_diagnostic_bytes(&exact), exact_bytes);

        let mut over_test = exact_test;
        over_test.test_bytes = exact_bytes - 1;
        assert!(matches!(
            check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, over_test, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "test plan or results",
                limit,
            }) if limit == exact_bytes - 1
        ));
    }

    #[test]
    fn diagnostic_and_test_output_limits_must_be_nonzero() {
        let hir = lower(MATH, TEST);
        let root = hir.as_program().test_candidates[0];
        let mut no_diagnostic_bytes = limits(1_000_000);
        no_diagnostic_bytes.diagnostic_bytes = 0;
        assert_eq!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                no_diagnostic_bytes,
                &|| false,
            ),
            Err(AnalysisFailure::InvalidLimits)
        );

        let mut no_test_bytes = limits(1_000_000);
        no_test_bytes.test_bytes = 0;
        assert_eq!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                no_test_bytes,
                &|| false
            ),
            Err(AnalysisFailure::InvalidLimits)
        );
    }

    #[test]
    fn long_stack_label_storage_is_charged_before_reserve_at_exact_and_plus_one() {
        const DEPTH: usize = 6;
        let (math, test) = long_first_parent_sources(DEPTH, 240);
        let hir = lower(&math, &test);
        let program = hir.as_program();
        let root = program.test_candidates[0];
        assert_eq!(program.declarations.len(), DEPTH + 1);
        assert!(program.locals.is_empty());

        let exact_storage = minimum_admitted_limit(1, 1_000_000, |storage_entries| {
            let mut candidate = limits(10_000_000);
            candidate.storage_entries = storage_entries;
            matches!(
                check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, candidate, &|| false),
                Ok(Err(diagnostic))
                    if diagnostic.code.as_deref()
                        == Some("semantic-comptime-operation-not-implemented")
            )
        });
        // Dense declaration states + pending declarations + already checked
        // declarations + retained labels + the one diagnostic envelope.
        let expected_storage = u64::try_from(4 * DEPTH + 3).expect("fixture storage fits u64");
        assert_eq!(exact_storage, expected_storage);

        let mut exact = limits(10_000_000);
        exact.storage_entries = exact_storage;
        let diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            exact,
            &|| false,
        )
        .expect("exact structural-storage analysis")
        .expect_err("diagnostic labels fit at the exact structural bound");
        assert_eq!(diagnostic.labels.len(), DEPTH);

        let mut over = exact;
        over.storage_entries = exact_storage - 1;
        assert!(matches!(
            check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, over, &|| false),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker storage entries",
                limit,
            }) if limit == exact_storage - 1
        ));
    }

    #[test]
    fn long_stack_error_path_work_is_exact_and_source_copy_is_cancellable() {
        const DEPTH: usize = 6;
        const NAME_BYTES: usize = 240;
        let (math, test) = long_first_parent_sources(DEPTH, NAME_BYTES);
        let hir = lower(&math, &test);
        let root = hir.as_program().test_candidates[0];

        let exact_work = minimum_admitted_limit(1, 10_000_000, |work_units| {
            matches!(
                check_source_comptime_unit_test(&hir, hir.as_program().packages.root(), 64, root, limits(work_units), &|| false),
                Ok(Err(diagnostic))
                    if diagnostic.code.as_deref()
                        == Some("semantic-comptime-operation-not-implemented")
            )
        });
        let exact_diagnostic = check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(exact_work),
            &|| false,
        )
        .expect("exact error-path work analysis")
        .expect_err("diagnostic construction fits its exact work bound");
        assert_eq!(exact_diagnostic.labels.len(), DEPTH);
        assert!(exact_work > accounted_diagnostic_bytes(&exact_diagnostic));
        assert!(matches!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(exact_work - 1),
                &|| false,
            ),
            Err(AnalysisFailure::ResourceLimit {
                resource: "comptime source checker work units",
                limit,
            }) if limit == exact_work - 1
        ));

        let polls = Cell::new(0u64);
        check_source_comptime_unit_test(
            &hir,
            hir.as_program().packages.root(),
            64,
            root,
            limits(10_000_000),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("poll calibration analysis")
        .expect_err("poll calibration reaches the long diagnostic stack");
        let cancel_at = polls
            .get()
            .checked_sub(128)
            .expect("long final qualified-name copy has more than 128 polls");
        assert!(cancel_at > NAME_BYTES as u64);
        let cancelled_polls = Cell::new(0u64);
        assert_eq!(
            check_source_comptime_unit_test(
                &hir,
                hir.as_program().packages.root(),
                64,
                root,
                limits(10_000_000),
                &|| {
                    let next = cancelled_polls.get() + 1;
                    cancelled_polls.set(next);
                    next == cancel_at
                }
            ),
            Err(AnalysisFailure::Cancelled)
        );
        assert_eq!(cancelled_polls.get(), cancel_at);
    }
}
