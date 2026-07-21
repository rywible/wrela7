//! Static interface/impl collection, whole-image coherence validation, and
//! operator desugaring resolution for the bounded concrete subset described
//! by chapter 02 §3.4 ("Interfaces") and chapter 10 §12 ("Operator
//! interfaces").
//!
//! Scope is deliberately narrow: non-generic `interface` declarations,
//! `impl Interface for ConcreteStruct` blocks whose method bodies are
//! ordinary ideas, and desugaring of `+ - < <= > >=` on a nominal struct type
//! with a unique visible implementation. Everything else (generic
//! interfaces/impls, generic bounds, enum/non-struct targets) fails closed
//! with a stable diagnostic from this module.
//!
//! This module is a pure function of the whole-image HIR: it never consults
//! or mutates analysis state, so both the runtime tier (`analyzer.rs`) and
//! the comptime tiers (`analyzer.rs`'s evaluator and `comptime_check.rs`)
//! recompute it on demand and always agree.

use std::collections::BTreeMap;

use wrela_diagnostics::{Category, Diagnostic, Label};
use wrela_hir::{
    BinaryOperator, ComparisonOperator, Declaration, DeclarationId, DeclarationKind,
    DeclarationOwner, Definition, FunctionDeclaration, ImplementationDeclaration, Name, Program,
    ResolvedDeclaration, TypeExpression, TypeExpressionKind, Visibility,
};
use wrela_package::PackageId;

use crate::AnalysisFailure;

/// One of the three well-known `core.ops` operator interfaces (chapter 10
/// §12). Only these three ever participate in operator desugaring; any other
/// non-generic interface may still be declared and implemented, but has no
/// operator surface and is simply never reached by a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OpsInterface {
    Add,
    Sub,
    Ord,
}

impl OpsInterface {
    const ALL: [Self; 3] = [Self::Add, Self::Sub, Self::Ord];

    fn source_name(self) -> &'static str {
        match self {
            Self::Add => "Add",
            Self::Sub => "Sub",
            Self::Ord => "Ord",
        }
    }

    fn method_name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "subtract",
            Self::Ord => "less_than",
        }
    }
}

/// The six operators chapter 10 §12 desugars through `core.ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DesugarOperator {
    Add,
    Subtract,
    LessThan,
    GreaterThan,
    LessEqual,
    GreaterEqual,
}

impl DesugarOperator {
    pub(crate) fn from_binary(operator: BinaryOperator) -> Option<Self> {
        match operator {
            BinaryOperator::Add => Some(Self::Add),
            BinaryOperator::Subtract => Some(Self::Subtract),
            _ => None,
        }
    }

    pub(crate) fn from_comparison(operator: ComparisonOperator) -> Option<Self> {
        match operator {
            ComparisonOperator::Less => Some(Self::LessThan),
            ComparisonOperator::Greater => Some(Self::GreaterThan),
            ComparisonOperator::LessEqual => Some(Self::LessEqual),
            ComparisonOperator::GreaterEqual => Some(Self::GreaterEqual),
            _ => None,
        }
    }

    fn interface(self) -> OpsInterface {
        match self {
            Self::Add => OpsInterface::Add,
            Self::Subtract => OpsInterface::Sub,
            Self::LessThan | Self::GreaterThan | Self::LessEqual | Self::GreaterEqual => {
                OpsInterface::Ord
            }
        }
    }

    /// `(swap, negate)`: `swap` selects whether the impl call binds
    /// `(right, left)` instead of `(left, right)` to `(self, other)`;
    /// `negate` requests a logical NOT of the raw call result. Both operands
    /// are always evaluated left-to-right exactly as written regardless of
    /// `swap` — only the argument *binding* and result differ.
    pub(crate) fn mapping(self) -> (bool, bool) {
        match self {
            Self::Add | Self::Subtract | Self::LessThan => (false, false),
            Self::GreaterThan => (true, false),
            Self::LessEqual => (true, true),
            Self::GreaterEqual => (false, true),
        }
    }

    /// The impl method this operator desugars to.
    pub(crate) fn method_name(self) -> &'static str {
        self.interface().method_name()
    }
}

/// One resolved operator desugaring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorResolution {
    pub function: DeclarationId,
    pub swap: bool,
    pub negate: bool,
}

/// Whole-image interface/impl coherence facts, computed once per analysis.
/// Purely a function of HIR, so recomputation is referentially transparent
/// and every tier that needs it (runtime, comptime interpreter, comptime
/// static checker) can call [`collect_interface_model`] independently.
#[derive(Debug, Default)]
pub(crate) struct InterfaceModel {
    ops_interfaces: BTreeMap<OpsInterface, DeclarationId>,
    impls: BTreeMap<(DeclarationId, DeclarationId), DeclarationId>,
}

impl InterfaceModel {
    /// Resolve `operator` on a value of `struct_declaration`'s type to the
    /// unique visible impl method, if any.
    pub(crate) fn resolve_operator(
        &self,
        program: &Program,
        operator: DesugarOperator,
        struct_declaration: DeclarationId,
    ) -> Option<OperatorResolution> {
        let interface = operator.interface();
        let interface_declaration = *self.ops_interfaces.get(&interface)?;
        let impl_declaration = *self
            .impls
            .get(&(interface_declaration, struct_declaration))?;
        let DeclarationKind::Implementation(implementation) =
            &program.declaration(impl_declaration)?.kind
        else {
            return None;
        };
        let method_name = interface.method_name();
        let function = implementation
            .members
            .iter()
            .copied()
            .find(|member| declaration_name(program, *member) == Some(method_name))?;
        let (swap, negate) = operator.mapping();
        Some(OperatorResolution {
            function,
            swap,
            negate,
        })
    }
}

/// Collect every well-known `core.ops` interface and validate every `impl`
/// block in the whole loaded image, returning the resulting coherent model
/// plus any stable diagnostics for orphan violations, duplicate impls,
/// signature mismatches, and out-of-scope shapes.
pub(crate) fn collect_interface_model(
    program: &Program,
    standard_library_package: PackageId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(InterfaceModel, Vec<Diagnostic>), AnalysisFailure> {
    let mut model = InterfaceModel::default();
    let mut diagnostics = Vec::new();
    for declaration in &program.declarations {
        poll(is_cancelled)?;
        if let DeclarationKind::Interface(_) = &declaration.kind {
            if let Some(known) =
                identify_ops_interface(program, standard_library_package, declaration.id)
            {
                model.ops_interfaces.entry(known).or_insert(declaration.id);
            }
        }
    }
    for declaration in &program.declarations {
        poll(is_cancelled)?;
        if let DeclarationKind::Implementation(implementation) = &declaration.kind {
            validate_one_implementation(
                program,
                declaration,
                implementation,
                &mut model,
                &mut diagnostics,
            );
        }
    }
    Ok((model, diagnostics))
}

fn poll(is_cancelled: &dyn Fn() -> bool) -> Result<(), AnalysisFailure> {
    if is_cancelled() {
        Err(AnalysisFailure::Cancelled)
    } else {
        Ok(())
    }
}

pub(crate) fn declaration_name(program: &Program, id: DeclarationId) -> Option<&str> {
    program.declaration(id)?.name.as_ref().map(Name::as_str)
}

fn module_package(program: &Program, module: wrela_package::ModuleId) -> Option<PackageId> {
    program
        .modules
        .get(module.0 as usize)
        .map(|module| module.package)
}

fn declaration_package(program: &Program, id: DeclarationId) -> Option<PackageId> {
    module_package(program, program.declaration(id)?.module)
}

/// A type expression naming a non-generic nominal declaration directly — the
/// only shape this bounded subset resolves for an interface reference or an
/// implementing type.
struct NominalRef {
    resolved: ResolvedDeclaration,
}

fn nominal_ref(ty: &TypeExpression) -> Option<NominalRef> {
    match &ty.kind {
        TypeExpressionKind::Named {
            definition: Definition::Declaration(resolved),
            arguments,
        } if arguments.is_empty() => Some(NominalRef {
            resolved: resolved.clone(),
        }),
        _ => None,
    }
}

fn identify_ops_interface(
    program: &Program,
    standard_library_package: PackageId,
    declaration: DeclarationId,
) -> Option<OpsInterface> {
    let record = program.declaration(declaration)?;
    if declaration_package(program, declaration)? != standard_library_package {
        return None;
    }
    if program.modules.get(record.module.0 as usize)?.path.dotted() != "ops" {
        return None;
    }
    let name = record.name.as_ref()?.as_str();
    OpsInterface::ALL
        .into_iter()
        .find(|candidate| candidate.source_name() == name)
}

/// A concrete type identity used to compare an interface requirement's
/// signature against an impl member's signature after substituting `Self`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConcreteTypeRef {
    Declaration(DeclarationId),
    Builtin(wrela_hir::Builtin),
}

fn concrete_type_ref(
    ty: &TypeExpression,
    self_owner: DeclarationId,
    implementing_type: DeclarationId,
) -> Option<ConcreteTypeRef> {
    match &ty.kind {
        TypeExpressionKind::SelfType { owner } if *owner == self_owner => {
            Some(ConcreteTypeRef::Declaration(implementing_type))
        }
        TypeExpressionKind::Named {
            definition: Definition::Declaration(resolved),
            arguments,
        } if arguments.is_empty() => Some(ConcreteTypeRef::Declaration(resolved.declaration)),
        TypeExpressionKind::Named {
            definition: Definition::Builtin(builtin),
            arguments,
        } if arguments.is_empty() => Some(ConcreteTypeRef::Builtin(*builtin)),
        _ => None,
    }
}

fn function_shape(program: &Program, id: DeclarationId) -> Option<&FunctionDeclaration> {
    match &program.declaration(id)?.kind {
        DeclarationKind::Function(function) => Some(function),
        _ => None,
    }
}

/// An implementation's declared access effects MUST match the interface
/// exactly (chapter 02 §3.4), and `Self` in either signature must denote the
/// same concrete implementing type.
fn implementation_signature_matches(
    program: &Program,
    interface_declaration: DeclarationId,
    impl_declaration: DeclarationId,
    implementing_type: DeclarationId,
    requirement: DeclarationId,
    member: DeclarationId,
) -> bool {
    let Some(interface_function) = function_shape(program, requirement) else {
        return false;
    };
    let Some(impl_function) = function_shape(program, member) else {
        return false;
    };
    if impl_function.body.is_none() {
        return false;
    }
    if interface_function.color != impl_function.color {
        return false;
    }
    if !interface_function.generics.is_empty() || !impl_function.generics.is_empty() {
        return false;
    }
    if interface_function.parameters.len() != impl_function.parameters.len() {
        return false;
    }
    for (interface_parameter, impl_parameter) in interface_function
        .parameters
        .iter()
        .zip(impl_function.parameters.iter())
    {
        let Some(interface_parameter) = program.parameters.get(interface_parameter.0 as usize)
        else {
            return false;
        };
        let Some(impl_parameter) = program.parameters.get(impl_parameter.0 as usize) else {
            return false;
        };
        if interface_parameter.receiver != impl_parameter.receiver
            || interface_parameter.access != impl_parameter.access
        {
            return false;
        }
        if interface_parameter.receiver {
            // A receiver has no separately written type on either side; it
            // is always exactly `Self`.
            continue;
        }
        let (Some(interface_ty), Some(impl_ty)) =
            (interface_parameter.ty.as_ref(), impl_parameter.ty.as_ref())
        else {
            return false;
        };
        match (
            concrete_type_ref(interface_ty, interface_declaration, implementing_type),
            concrete_type_ref(impl_ty, impl_declaration, implementing_type),
        ) {
            (Some(left), Some(right)) if left == right => {}
            _ => return false,
        }
    }
    match (&interface_function.result, &impl_function.result) {
        (None, None) => true,
        (Some(interface_ty), Some(impl_ty)) => matches!(
            (
                concrete_type_ref(interface_ty, interface_declaration, implementing_type),
                concrete_type_ref(impl_ty, impl_declaration, implementing_type),
            ),
            (Some(left), Some(right)) if left == right
        ),
        _ => false,
    }
}

fn unsupported_diagnostic(
    source: wrela_source::Span,
    code: &str,
    message: &str,
    help: &str,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, source, message.to_owned());
    diagnostic.code = Some(code.to_owned());
    diagnostic.help.push(help.to_owned());
    diagnostic
}

fn validate_one_implementation(
    program: &Program,
    declaration: &Declaration,
    implementation: &ImplementationDeclaration,
    model: &mut InterfaceModel,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if declaration.visibility != Visibility::Private {
        diagnostics.push(unsupported_diagnostic(
            declaration.source,
            "semantic-interface-impl-visibility",
            "an implementation block cannot be marked `pub`",
            "impl blocks are visible only through their interface/type packages",
        ));
        return;
    }
    let Some(interface_ref) = nominal_ref(&implementation.interface) else {
        diagnostics.push(unsupported_diagnostic(
            implementation.interface.source,
            "semantic-interface-unsupported",
            "this implementation's interface reference is outside the supported concrete subset",
            "revision 0.1 supports only a bare non-generic interface name after `impl`",
        ));
        return;
    };
    let Some(interface_record) = program.declaration(interface_ref.resolved.declaration) else {
        return;
    };
    let DeclarationKind::Interface(interface_body) = &interface_record.kind else {
        diagnostics.push(unsupported_diagnostic(
            implementation.interface.source,
            "semantic-interface-unsupported",
            "`impl ... for` names a declaration that is not an interface",
            "the type between `impl` and `for` must be a declared `interface`",
        ));
        return;
    };
    if !interface_body.generics.is_empty() {
        diagnostics.push(unsupported_diagnostic(
            implementation.interface.source,
            "semantic-interface-unsupported",
            "generic interfaces are outside the supported concrete subset",
            "revision 0.1's bounded interface support admits only non-generic interfaces",
        ));
        return;
    }

    let Some(type_ref) = nominal_ref(&implementation.implementing_type) else {
        diagnostics.push(unsupported_diagnostic(
            implementation.implementing_type.source,
            "semantic-interface-unsupported",
            "this implementation's target type is outside the supported concrete subset",
            "revision 0.1 supports only a bare non-generic nominal struct after `for`",
        ));
        return;
    };
    let Some(type_record) = program.declaration(type_ref.resolved.declaration) else {
        return;
    };
    let DeclarationKind::Structure(aggregate) = &type_record.kind else {
        diagnostics.push(unsupported_diagnostic(
            implementation.implementing_type.source,
            "semantic-interface-unsupported",
            "interfaces may be implemented only for a concrete nominal struct",
            "enums and other nominal kinds are outside the supported concrete subset",
        ));
        return;
    };
    if !aggregate.generics.is_empty() {
        diagnostics.push(unsupported_diagnostic(
            implementation.implementing_type.source,
            "semantic-interface-unsupported",
            "generic struct targets are outside the supported concrete subset",
            "revision 0.1's bounded interface support admits only a concrete non-generic struct",
        ));
        return;
    }

    // Orphan rule (chapter 02 §3.4): legal only in a package declaring the
    // interface or the implementing type constructor.
    let impl_package = declaration_package(program, declaration.id);
    if impl_package != Some(interface_ref.resolved.package)
        && impl_package != Some(type_ref.resolved.package)
    {
        diagnostics.push(unsupported_diagnostic(
            declaration.source,
            "semantic-interface-orphan",
            "this implementation violates the orphan rule",
            "an impl is legal only in a package that declares the interface or the implementing type",
        ));
        return;
    }

    // Every interface requirement must have a matching, exactly-shaped
    // implementation member.
    for requirement in &interface_body.requirements {
        let Some(name) = declaration_name(program, *requirement) else {
            continue;
        };
        let Some(member) = implementation
            .members
            .iter()
            .copied()
            .find(|candidate| declaration_name(program, *candidate) == Some(name))
        else {
            diagnostics.push(unsupported_diagnostic(
                declaration.source,
                "semantic-interface-signature-mismatch",
                "this implementation is missing a required interface method",
                "every interface method name must have a matching implementation member",
            ));
            return;
        };
        if !implementation_signature_matches(
            program,
            interface_ref.resolved.declaration,
            declaration.id,
            type_ref.resolved.declaration,
            *requirement,
            member,
        ) {
            diagnostics.push(unsupported_diagnostic(
                declaration.source,
                "semantic-interface-signature-mismatch",
                "this implementation's method signature does not match its interface exactly",
                "parameters, access effects, `Self` substitution, and the result type must match exactly",
            ));
            return;
        }
    }

    // Whole-image coherence: at most one impl per (interface, concrete type).
    let key = (
        interface_ref.resolved.declaration,
        type_ref.resolved.declaration,
    );
    if let Some(existing) = model.impls.get(&key).copied() {
        let mut diagnostic = Diagnostic::error(
            Category::TYPE,
            declaration.source,
            "two implementations both apply to the same interface and concrete type".to_owned(),
        );
        diagnostic.code = Some("semantic-interface-duplicate-impl".to_owned());
        if let Some(existing_record) = program.declaration(existing) {
            diagnostic.labels.push(Label {
                span: existing_record.source,
                message: "the first implementation is here".to_owned(),
            });
        }
        diagnostic.help.push(
            "the whole image permits at most one implementation of an interface for a concrete type"
                .to_owned(),
        );
        diagnostics.push(diagnostic);
        return;
    }

    model.impls.insert(key, declaration.id);
}

/// The nearest enclosing `Structure`/`Implementation` declaration for `Self`,
/// mirroring `wrela-hir-lower`'s own walk. A bare `interface` is never
/// returned: its methods have no body, so nothing ever derives a receiver's
/// concrete type from inside one.
fn self_type_owner(program: &Program, mut declaration: DeclarationId) -> Option<DeclarationId> {
    for _ in 0..=program.declarations.len() {
        let record = program.declaration(declaration)?;
        if matches!(
            record.kind,
            DeclarationKind::Structure(_) | DeclarationKind::Implementation(_)
        ) {
            return Some(declaration);
        }
        let DeclarationOwner::Declaration(parent) = record.owner else {
            return None;
        };
        declaration = parent;
    }
    None
}

/// Resolve a `Self`-owner declaration (as produced by [`self_type_owner`] or
/// by HIR's own `TypeExpressionKind::SelfType.owner`) to the concrete struct
/// it denotes.
pub(crate) fn concrete_struct_for_self_owner(
    program: &Program,
    owner: DeclarationId,
) -> Option<DeclarationId> {
    match &program.declaration(owner)?.kind {
        DeclarationKind::Structure(_) => Some(owner),
        DeclarationKind::Implementation(implementation) => {
            let nominal = nominal_ref(&implementation.implementing_type)?;
            let target = nominal.resolved.declaration;
            matches!(
                program.declaration(target)?.kind,
                DeclarationKind::Structure(_)
            )
            .then_some(target)
        }
        _ => None,
    }
}

/// The concrete struct a receiver (`self`) parameter denotes, derived from
/// its owning function's enclosing `Structure`/`Implementation` declaration
/// (chapter 02 §3.2/§3.4: a receiver has no separately written type).
pub(crate) fn receiver_concrete_struct(
    program: &Program,
    function_declaration: DeclarationId,
) -> Option<DeclarationId> {
    let owner = self_type_owner(program, function_declaration)?;
    concrete_struct_for_self_owner(program, owner)
}
