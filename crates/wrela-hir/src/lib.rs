//! Pure, normalized, name-resolved high-level IR.
//!
//! HIR removes layout, import syntax, parentheses, sugar, and ambiguous generic
//! argument kinds. It retains source provenance and language structure needed
//! by type/effect/ownership/comptime analysis. No inferred semantic fact lives
//! here.

#![forbid(unsafe_code)]

use std::fmt;

use unicode_normalization::UnicodeNormalization;

use wrela_package::{ModuleId, ModulePath, PackageGraph, PackageId};
use wrela_source::Span;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(DeclarationId);
id_type!(BodyId);
id_type!(ExpressionId);
id_type!(StatementId);
id_type!(PatternId);
id_type!(LocalId);
id_type!(ParameterId);
id_type!(GenericParameterId);
id_type!(ScopeId);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// HIR lowering may construct only scanner-validated NFC identifiers.
    #[must_use]
    pub fn from_validated(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        let value = self.as_str();
        !value.is_empty()
            && value.len() <= 4096
            && value.nfc().collect::<String>() == value
            && !value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
    Reexported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Value,
    Read,
    Mutate,
    Take,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionColor {
    Sync,
    Async,
    Isr,
    Comptime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDeclaration {
    pub package: PackageId,
    pub module: ModuleId,
    pub declaration: DeclarationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    Declaration(ResolvedDeclaration),
    Parameter(ParameterId),
    Local(LocalId),
    Generic(GenericParameterId),
    Builtin(Builtin),
    Module {
        package: PackageId,
        module: ModuleId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    F32,
    F64,
    Char,
    Static,
    Str,
    Bytes,
    String,
    Option,
    Result,
    Actor,
    Receipt,
    Dma,
    Mmio,
    Validated,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub name: ResolvedDeclaration,
    pub arguments: Vec<AttributeArgument>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeArgument {
    pub name: Option<Name>,
    pub value: ExpressionId,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub id: ModuleId,
    pub package: PackageId,
    pub path: ModulePath,
    pub declarations: Vec<DeclarationId>,
    pub reexports: Vec<Reexport>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reexport {
    pub local_name: Name,
    pub target: ResolvedDeclaration,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    pub id: DeclarationId,
    pub module: ModuleId,
    pub owner: DeclarationOwner,
    pub name: Name,
    pub visibility: Visibility,
    pub attributes: Vec<Attribute>,
    pub kind: DeclarationKind,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationOwner {
    Module(ModuleId),
    Declaration(DeclarationId),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeclarationKind {
    Constant(ConstantDeclaration),
    Brand,
    Function(FunctionDeclaration),
    Structure(AggregateDeclaration),
    Class(AggregateDeclaration),
    Enumeration(EnumDeclaration),
    Interface(InterfaceDeclaration),
    Implementation(ImplementationDeclaration),
    Projection(ProjectionDeclaration),
    Scope(ScopeDeclaration),
    /// Preserved only when a comptime declaration branch could not yet be
    /// reduced during HIR lowering.
    ComptimeSelection(ComptimeSelection),
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConstantDeclaration {
    pub ty: Option<TypeExpression>,
    pub value: ExpressionId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDeclaration {
    pub color: FunctionColor,
    pub generics: Vec<GenericParameterId>,
    pub parameters: Vec<ParameterId>,
    pub result: TypeExpression,
    pub body: Option<BodyId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenericParameter {
    pub id: GenericParameterId,
    pub owner: DeclarationId,
    pub name: Name,
    pub kind: GenericParameterKind,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GenericParameterKind {
    Type { bound: Option<TypeExpression> },
    Constant { ty: TypeExpression },
    Region,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub id: ParameterId,
    pub owner: CallableOwner,
    pub name: Name,
    pub access: AccessMode,
    pub ty: TypeExpression,
    pub receiver: bool,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallableOwner {
    Declaration(DeclarationId),
    Closure(ExpressionId),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AggregateDeclaration {
    pub generics: Vec<GenericParameterId>,
    pub implements: Vec<TypeExpression>,
    pub fields: Vec<Field>,
    pub members: Vec<DeclarationId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: Name,
    pub visibility: Visibility,
    pub attributes: Vec<Attribute>,
    pub ty: TypeExpression,
    pub default: Option<ExpressionId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDeclaration {
    pub generics: Vec<GenericParameterId>,
    pub variants: Vec<EnumVariant>,
    pub members: Vec<DeclarationId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    pub name: Name,
    pub fields: Vec<VariantField>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariantField {
    pub name: Option<Name>,
    pub ty: TypeExpression,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceDeclaration {
    pub generics: Vec<GenericParameterId>,
    pub requirements: Vec<DeclarationId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImplementationDeclaration {
    pub interface: TypeExpression,
    pub implementing_type: TypeExpression,
    pub members: Vec<DeclarationId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectionDeclaration {
    pub generics: Vec<GenericParameterId>,
    pub parameters: Vec<ParameterId>,
    pub carrier: ProjectionCarrier,
    pub provenance: Vec<ParameterId>,
    pub body: Option<BodyId>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectionCarrier {
    View {
        mutable: bool,
        ty: TypeExpression,
    },
    Tuple(Vec<ProjectionCarrier>),
    Option(Box<ProjectionCarrier>),
    Result {
        carrier: Box<ProjectionCarrier>,
        error: TypeExpression,
    },
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopeDeclaration {
    pub parameters: Vec<ParameterId>,
    pub result: TypeExpression,
    pub setup: BodyId,
    pub enter: ExpressionId,
    pub abort: Option<BodyId>,
    pub exit_parameter: ParameterId,
    pub exit: BodyId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComptimeSelection {
    pub condition: ExpressionId,
    pub then_declarations: Vec<DeclarationId>,
    pub else_declarations: Vec<DeclarationId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeExpression {
    pub kind: TypeExpressionKind,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeExpressionKind {
    Named {
        definition: Definition,
        arguments: Vec<GenericArgument>,
    },
    Array {
        element: Box<TypeExpression>,
        length: ExpressionId,
    },
    Tuple(Vec<TypeExpression>),
    View {
        mutable: bool,
        target: Box<TypeExpression>,
    },
    Iso {
        brand: Box<TypeExpression>,
        payload: Box<TypeExpression>,
    },
    Function {
        color: FunctionColor,
        parameters: Vec<FunctionTypeParameter>,
        result: Box<TypeExpression>,
    },
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GenericArgument {
    Type(TypeExpression),
    Constant(ExpressionId),
    BoundedCapacity(ExpressionId),
    Region(GenericParameterId),
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionTypeParameter {
    pub access: AccessMode,
    pub ty: TypeExpression,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Body {
    pub id: BodyId,
    pub owner: BodyOwner,
    pub scope: ScopeId,
    pub locals: Vec<LocalId>,
    pub statements: Vec<StatementId>,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyOwner {
    Declaration(DeclarationId),
    Closure(ExpressionId),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexicalScope {
    pub id: ScopeId,
    pub body: BodyId,
    pub parent: Option<ScopeId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Local {
    pub id: LocalId,
    pub body: BodyId,
    pub scope: ScopeId,
    pub name: Name,
    pub ty: Option<TypeExpression>,
    pub shadowed: Option<LocalId>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub id: StatementId,
    pub body: BodyId,
    pub attributes: Vec<Attribute>,
    pub kind: StatementKind,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatementKind {
    Initialize {
        local: LocalId,
        value: ExpressionId,
    },
    Assign {
        targets: Vec<PlaceTarget>,
        operator: AssignmentOperator,
        value: ExpressionId,
    },
    Return(Option<ExpressionId>),
    Break,
    Continue,
    Pass,
    Assert {
        condition: ExpressionId,
        message: Option<String>,
        comptime: bool,
    },
    Send(ExpressionId),
    Yield(ExpressionId),
    Expression(ExpressionId),
    If {
        branches: Vec<(ExpressionId, BodyId)>,
        else_body: Option<BodyId>,
    },
    Match {
        scrutinee: ExpressionId,
        arms: Vec<MatchArm>,
    },
    For {
        take_binding: bool,
        binding: LocalId,
        take_iterable: bool,
        iterable: ExpressionId,
        body: BodyId,
    },
    While {
        condition: ExpressionId,
        body: BodyId,
    },
    Loop {
        body: BodyId,
    },
    With {
        value: ExpressionId,
        binding: Option<LocalId>,
        region: Option<GenericParameterId>,
        body: BodyId,
    },
    ComptimeIf {
        condition: ExpressionId,
        then_body: BodyId,
        else_body: Option<BodyId>,
    },
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentOperator {
    Assign,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlaceTarget {
    pub root: Definition,
    pub projections: Vec<PlaceProjection>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlaceProjection {
    Field(Name),
    Index(ExpressionId),
    Tuple(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub pattern: PatternId,
    pub guard: Option<ExpressionId>,
    pub body: BodyId,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub id: ExpressionId,
    pub owner: ExpressionOwner,
    pub kind: ExpressionKind,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionOwner {
    Declaration(DeclarationId),
    Body(BodyId),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExpressionKind {
    Literal(Literal),
    Reference(Definition),
    Closure {
        color: FunctionColor,
        take_captures: bool,
        parameters: Vec<ParameterId>,
        body: ClosureBody,
        captures: Vec<Definition>,
    },
    Unary {
        operator: UnaryOperator,
        operand: ExpressionId,
    },
    Binary {
        operator: BinaryOperator,
        left: ExpressionId,
        right: ExpressionId,
    },
    Compare {
        first: ExpressionId,
        tails: Vec<(ComparisonOperator, ExpressionId)>,
    },
    IsPattern {
        value: ExpressionId,
        negated: bool,
        pattern: PatternId,
    },
    Range {
        start: ExpressionId,
        end: ExpressionId,
        inclusive: bool,
    },
    Cast {
        value: ExpressionId,
        ty: TypeExpression,
    },
    Try(ExpressionId),
    Field {
        base: ExpressionId,
        name: Name,
    },
    Call {
        callee: ExpressionId,
        arguments: Vec<CallArgument>,
    },
    Index {
        base: ExpressionId,
        index: ExpressionId,
    },
    Tuple(Vec<ExpressionId>),
    Array(Vec<ExpressionId>),
    Race(Vec<ExpressionId>),
    TrySend(ExpressionId),
    Interpolate(Vec<InterpolationPart>),
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClosureBody {
    Expression(ExpressionId),
    Body(BodyId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Negate,
    BitNot,
    BoolNot,
    Await,
    Take,
    Copy,
    Comptime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    LogicalOr,
    LogicalAnd,
    Add,
    AddWrapping,
    Subtract,
    SubtractWrapping,
    Multiply,
    MultiplyWrapping,
    Divide,
    Remainder,
    BitOr,
    BitXor,
    BitAnd,
    ShiftLeft,
    ShiftRight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOperator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    In,
    NotIn,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallArgument {
    pub name: Option<Name>,
    pub access: AccessMode,
    pub value: ExpressionId,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterpolationPart {
    Text(String),
    Value {
        expression: ExpressionId,
        format: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Integer(String),
    Float(String),
    String(String),
    Bytes(Vec<u8>),
    Character(char),
    Boolean(bool),
    Unit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub id: PatternId,
    pub owner: ExpressionOwner,
    pub alternatives: Vec<PrimaryPattern>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrimaryPattern {
    Wildcard,
    Literal {
        negative: bool,
        literal: Literal,
    },
    Constructor {
        candidates: Vec<ResolvedDeclaration>,
        arguments: Vec<PatternArgument>,
    },
    Bind(LocalId),
    Tuple(Vec<PatternArgument>),
    Array(Vec<PatternArgument>),
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatternArgument {
    pub take: bool,
    pub pattern: PatternId,
    pub source: Span,
}

/// Complete immutable name-resolution output.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub packages: PackageGraph,
    pub modules: Vec<Module>,
    pub declarations: Vec<Declaration>,
    pub generic_parameters: Vec<GenericParameter>,
    pub parameters: Vec<Parameter>,
    pub bodies: Vec<Body>,
    pub scopes: Vec<LexicalScope>,
    pub locals: Vec<Local>,
    pub statements: Vec<Statement>,
    pub expressions: Vec<Expression>,
    pub patterns: Vec<Pattern>,
    /// Attributed candidates; semantic analysis proves exactly one selection
    /// for the requested image build.
    pub image_candidates: Vec<DeclarationId>,
    pub test_candidates: Vec<DeclarationId>,
}

impl Program {
    #[must_use]
    pub fn declaration(&self, id: DeclarationId) -> Option<&Declaration> {
        self.declarations.get(id.0 as usize)
    }

    #[must_use]
    pub fn body(&self, id: BodyId) -> Option<&Body> {
        self.bodies.get(id.0 as usize)
    }

    #[must_use]
    pub fn generic_parameter(&self, id: GenericParameterId) -> Option<&GenericParameter> {
        self.generic_parameters.get(id.0 as usize)
    }

    #[must_use]
    pub fn parameter(&self, id: ParameterId) -> Option<&Parameter> {
        self.parameters.get(id.0 as usize)
    }

    #[must_use]
    pub fn scope(&self, id: ScopeId) -> Option<&LexicalScope> {
        self.scopes.get(id.0 as usize)
    }

    #[must_use]
    pub fn local(&self, id: LocalId) -> Option<&Local> {
        self.locals.get(id.0 as usize)
    }

    #[must_use]
    pub fn statement(&self, id: StatementId) -> Option<&Statement> {
        self.statements.get(id.0 as usize)
    }

    #[must_use]
    pub fn expression(&self, id: ExpressionId) -> Option<&Expression> {
        self.expressions.get(id.0 as usize)
    }

    #[must_use]
    pub fn pattern(&self, id: PatternId) -> Option<&Pattern> {
        self.patterns.get(id.0 as usize)
    }

    /// Seal all arenas and references before semantic analysis or HIR linting.
    pub fn validate(self) -> Result<ValidatedProgram, ValidationErrors> {
        let mut errors = Vec::new();
        require_dense(
            "modules",
            self.modules.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "declarations",
            self.declarations.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "generic parameters",
            self.generic_parameters.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "parameters",
            self.parameters.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "bodies",
            self.bodies.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "scopes",
            self.scopes.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "locals",
            self.locals.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "statements",
            self.statements.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "expressions",
            self.expressions.iter().map(|value| value.id.0),
            &mut errors,
        );
        require_dense(
            "patterns",
            self.patterns.iter().map(|value| value.id.0),
            &mut errors,
        );

        if self.modules.len() != self.packages.modules().len() {
            errors.push(ValidationError::Coverage("package modules"));
        }
        for (module, graph_module) in self.modules.iter().zip(self.packages.modules()) {
            if module.id != graph_module.id
                || module.package != graph_module.package
                || module.path != graph_module.path
                || module.source.file != graph_module.source
                || !valid_span(module.source)
                || !strict_ids(module.declarations.iter().map(|id| id.0))
                || !module.reexports.windows(2).all(|pair| {
                    (pair[0].local_name.as_str(), pair[0].source.range.start)
                        < (pair[1].local_name.as_str(), pair[1].source.range.start)
                })
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "module",
                    id: module.id.0,
                    reason: "graph identity, source, declarations, or reexports",
                });
            }
            for declaration in &module.declarations {
                if self.declaration(*declaration).is_none_or(|value| {
                    value.module != module.id || value.owner != DeclarationOwner::Module(module.id)
                }) {
                    errors.push(invalid_reference("module declaration", declaration.0));
                }
            }
            for reexport in &module.reexports {
                validate_name(&reexport.local_name, "reexport", &mut errors);
                if !valid_span(reexport.source)
                    || reexport.source.file != graph_module.source
                    || !valid_resolved_declaration(&self, &reexport.target)
                {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "module reexport",
                        id: module.id.0,
                        reason: "source or resolved target",
                    });
                }
            }
        }

        let mut top_level_declarations = vec![0u8; self.declarations.len()];
        for module in &self.modules {
            for declaration in &module.declarations {
                increment_coverage(&mut top_level_declarations, declaration.0);
            }
        }
        for declaration in &self.declarations {
            validate_declaration(&self, declaration, &mut errors);
            match declaration.owner {
                DeclarationOwner::Module(module) => {
                    if module != declaration.module
                        || top_level_declarations
                            .get(declaration.id.0 as usize)
                            .copied()
                            != Some(1)
                    {
                        errors.push(ValidationError::InvalidRecord {
                            arena: "declaration",
                            id: declaration.id.0,
                            reason: "top-level owner coverage",
                        });
                    }
                }
                DeclarationOwner::Declaration(owner) => {
                    if owner.0 >= declaration.id.0
                        || self.declaration(owner).is_none_or(|parent| {
                            parent.module != declaration.module
                                || !declaration_owns(parent, declaration.id)
                        })
                    {
                        errors.push(ValidationError::InvalidRecord {
                            arena: "declaration",
                            id: declaration.id.0,
                            reason: "nested owner",
                        });
                    }
                }
            }
        }

        for generic in &self.generic_parameters {
            let valid_owner = self.declaration(generic.owner).is_some_and(|owner| {
                declaration_generics(owner)
                    .binary_search(&generic.id)
                    .is_ok()
                    && owner.source.file == generic.source.file
            });
            validate_name(&generic.name, "generic parameter", &mut errors);
            if !valid_owner || !valid_span(generic.source) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "generic parameter",
                    id: generic.id.0,
                    reason: "owner or source",
                });
            }
            match &generic.kind {
                GenericParameterKind::Type { bound } => {
                    if let Some(bound) = bound {
                        validate_type(
                            &self,
                            bound,
                            ExpressionOwner::Declaration(generic.owner),
                            0,
                            &mut errors,
                        );
                    }
                }
                GenericParameterKind::Constant { ty } => validate_type(
                    &self,
                    ty,
                    ExpressionOwner::Declaration(generic.owner),
                    0,
                    &mut errors,
                ),
                GenericParameterKind::Region => {}
            }
        }
        require_owner_coverage(
            "generic parameter",
            self.generic_parameters.len(),
            self.declarations
                .iter()
                .flat_map(declaration_generics)
                .map(|id| id.0),
            &mut errors,
        );

        for parameter in &self.parameters {
            validate_name(&parameter.name, "parameter", &mut errors);
            let (listed, expected_file, expression_owner) = match parameter.owner {
                CallableOwner::Declaration(owner) => {
                    self.declaration(owner)
                        .map_or((false, None, None), |declaration| {
                            (
                                declaration_parameters(declaration)
                                    .binary_search(&parameter.id)
                                    .is_ok(),
                                Some(declaration.source.file),
                                Some(ExpressionOwner::Declaration(owner)),
                            )
                        })
                }
                CallableOwner::Closure(owner) => {
                    self.expression(owner)
                        .map_or((false, None, None), |expression| {
                            let listed = matches!(
                                &expression.kind,
                                ExpressionKind::Closure { parameters, .. }
                                    if parameters.binary_search(&parameter.id).is_ok()
                            );
                            (listed, Some(expression.source.file), Some(expression.owner))
                        })
                }
            };
            if !listed
                || expected_file != Some(parameter.source.file)
                || !valid_span(parameter.source)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "parameter",
                    id: parameter.id.0,
                    reason: "owner or source",
                });
            }
            if let Some(expression_owner) = expression_owner {
                validate_type(&self, &parameter.ty, expression_owner, 0, &mut errors);
            }
        }
        require_owner_coverage(
            "parameter",
            self.parameters.len(),
            self.declarations
                .iter()
                .flat_map(declaration_parameters)
                .chain(
                    self.expressions
                        .iter()
                        .flat_map(|expression| match &expression.kind {
                            ExpressionKind::Closure { parameters, .. } => parameters.as_slice(),
                            _ => &[],
                        }),
                )
                .map(|id| id.0),
            &mut errors,
        );

        let mut local_coverage = vec![0u8; self.locals.len()];
        let mut statement_coverage = vec![0u8; self.statements.len()];
        for body in &self.bodies {
            if !valid_body_owner(&self, body.owner)
                || !valid_span(body.source)
                || body_owner_file(&self, body.owner) != Some(body.source.file)
                || !strict_ids(body.locals.iter().map(|id| id.0))
                || !strict_ids(body.statements.iter().map(|id| id.0))
                || self
                    .scope(body.scope)
                    .is_none_or(|scope| scope.body != body.id)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "body",
                    id: body.id.0,
                    reason: "owner, source, root scope, locals, or statements",
                });
            }
            for local in &body.locals {
                increment_coverage(&mut local_coverage, local.0);
                if self.local(*local).is_none_or(|value| value.body != body.id) {
                    errors.push(invalid_reference("body local", local.0));
                }
            }
            for statement in &body.statements {
                increment_coverage(&mut statement_coverage, statement.0);
                if self
                    .statement(*statement)
                    .is_none_or(|value| value.body != body.id)
                {
                    errors.push(invalid_reference("body statement", statement.0));
                }
            }
        }
        require_exact_coverage("locals", &local_coverage, &mut errors);
        require_exact_coverage("statements", &statement_coverage, &mut errors);
        let mut body_coverage = vec![0u8; self.bodies.len()];
        for declaration in &self.declarations {
            match &declaration.kind {
                DeclarationKind::Function(value) => {
                    if let Some(body) = value.body {
                        increment_coverage(&mut body_coverage, body.0);
                    }
                }
                DeclarationKind::Projection(value) => {
                    if let Some(body) = value.body {
                        increment_coverage(&mut body_coverage, body.0);
                    }
                }
                DeclarationKind::Scope(value) => {
                    increment_coverage(&mut body_coverage, value.setup.0);
                    if let Some(body) = value.abort {
                        increment_coverage(&mut body_coverage, body.0);
                    }
                    increment_coverage(&mut body_coverage, value.exit.0);
                }
                _ => {}
            }
        }
        for expression in &self.expressions {
            if let ExpressionKind::Closure {
                body: ClosureBody::Body(body),
                ..
            } = &expression.kind
            {
                increment_coverage(&mut body_coverage, body.0);
            }
        }
        for statement in &self.statements {
            for body in statement_bodies(&statement.kind) {
                increment_coverage(&mut body_coverage, body.0);
            }
        }
        require_exact_coverage("bodies", &body_coverage, &mut errors);
        let mut scope_coverage = vec![0u8; self.scopes.len()];
        for body in &self.bodies {
            increment_coverage(&mut scope_coverage, body.scope.0);
        }
        require_exact_coverage("body root scopes", &scope_coverage, &mut errors);

        let mut expression_coverage = vec![0u8; self.expressions.len()];
        for declaration in &self.declarations {
            collect_declaration_expressions(declaration, &mut expression_coverage);
        }
        for generic in &self.generic_parameters {
            match &generic.kind {
                GenericParameterKind::Type { bound } => {
                    if let Some(bound) = bound {
                        collect_type_expressions(bound, &mut expression_coverage, 0);
                    }
                }
                GenericParameterKind::Constant { ty } => {
                    collect_type_expressions(ty, &mut expression_coverage, 0);
                }
                GenericParameterKind::Region => {}
            }
        }
        for parameter in &self.parameters {
            collect_type_expressions(&parameter.ty, &mut expression_coverage, 0);
        }
        for local in &self.locals {
            if let Some(ty) = &local.ty {
                collect_type_expressions(ty, &mut expression_coverage, 0);
            }
        }
        for statement in &self.statements {
            collect_statement_expressions(&statement.kind, &mut expression_coverage);
            for attribute in &statement.attributes {
                collect_attribute_expressions(attribute, &mut expression_coverage);
            }
        }
        for expression in &self.expressions {
            collect_expression_children(&expression.kind, &mut expression_coverage);
        }
        require_exact_coverage("expressions", &expression_coverage, &mut errors);

        let mut pattern_coverage = vec![0u8; self.patterns.len()];
        for statement in &self.statements {
            if let StatementKind::Match { arms, .. } = &statement.kind {
                for arm in arms {
                    increment_coverage(&mut pattern_coverage, arm.pattern.0);
                }
            }
        }
        for expression in &self.expressions {
            if let ExpressionKind::IsPattern { pattern, .. } = &expression.kind {
                increment_coverage(&mut pattern_coverage, pattern.0);
            }
        }
        for pattern in &self.patterns {
            for alternative in &pattern.alternatives {
                let arguments = match alternative {
                    PrimaryPattern::Constructor { arguments, .. }
                    | PrimaryPattern::Tuple(arguments)
                    | PrimaryPattern::Array(arguments) => arguments.as_slice(),
                    _ => &[],
                };
                for argument in arguments {
                    increment_coverage(&mut pattern_coverage, argument.pattern.0);
                }
            }
        }
        require_exact_coverage("patterns", &pattern_coverage, &mut errors);

        for scope in &self.scopes {
            if !valid_span(scope.source)
                || self
                    .body(scope.body)
                    .is_none_or(|body| body.source.file != scope.source.file)
                || scope.parent.is_some_and(|parent| {
                    parent.0 >= scope.id.0
                        || self
                            .scope(parent)
                            .is_none_or(|parent| parent.source.file != scope.source.file)
                })
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "scope",
                    id: scope.id.0,
                    reason: "body, parent, or source",
                });
            }
        }
        for local in &self.locals {
            validate_name(&local.name, "local", &mut errors);
            if !valid_span(local.source)
                || self
                    .body(local.body)
                    .is_none_or(|body| body.source.file != local.source.file)
                || self
                    .scope(local.scope)
                    .is_none_or(|scope| scope.body != local.body)
                || local.shadowed.is_some_and(|shadowed| {
                    shadowed.0 >= local.id.0 || self.local(shadowed).is_none()
                })
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "local",
                    id: local.id.0,
                    reason: "body, scope, shadow, or source",
                });
            }
            if let Some(ty) = &local.ty {
                validate_type(&self, ty, ExpressionOwner::Body(local.body), 0, &mut errors);
            }
        }
        for statement in &self.statements {
            validate_statement(&self, statement, &mut errors);
        }
        for expression in &self.expressions {
            validate_expression(&self, expression, &mut errors);
        }
        for pattern in &self.patterns {
            validate_pattern(&self, pattern, &mut errors);
        }
        for candidate in self.image_candidates.iter().chain(&self.test_candidates) {
            if self
                .declaration(*candidate)
                .is_none_or(|declaration| !matches!(declaration.kind, DeclarationKind::Function(_)))
            {
                errors.push(invalid_reference("entry candidate", candidate.0));
            }
        }
        if !strict_ids(self.image_candidates.iter().map(|id| id.0))
            || !strict_ids(self.test_candidates.iter().map(|id| id.0))
        {
            errors.push(ValidationError::NonCanonical("entry candidates"));
        }

        if errors.is_empty() {
            Ok(ValidatedProgram(self))
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

/// Program whose dense arenas, owners, cross-references, source provenance,
/// and body/expression graphs have been independently validated.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedProgram(Program);

impl ValidatedProgram {
    #[must_use]
    pub fn as_program(&self) -> &Program {
        &self.0
    }

    #[must_use]
    pub fn into_program(self) -> Program {
        self.0
    }

    #[must_use]
    pub fn resolved_declaration(&self, resolved: &ResolvedDeclaration) -> Option<&Declaration> {
        self.0
            .declaration(resolved.declaration)
            .filter(|declaration| {
                declaration.module == resolved.module
                    && self
                        .0
                        .modules
                        .get(resolved.module.0 as usize)
                        .is_some_and(|module| module.package == resolved.package)
            })
    }

    /// Resolve the exact manifest `(package, module path, entry name)` tuple
    /// without exposing or rebuilding HIR-lowering's internal symbol tables.
    pub fn manifest_declaration(
        &self,
        package: PackageId,
        path: &ModulePath,
        name: &str,
    ) -> Result<ResolvedDeclaration, ManifestDeclarationError> {
        let module = self
            .0
            .modules
            .iter()
            .find(|module| module.package == package && &module.path == path)
            .ok_or(ManifestDeclarationError::UnknownModule)?;
        let mut matches = module.declarations.iter().filter(|id| {
            self.0
                .declaration(**id)
                .is_some_and(|declaration| declaration.name.as_str() == name)
        });
        let declaration = *matches
            .next()
            .ok_or(ManifestDeclarationError::UnknownDeclaration)?;
        if matches.next().is_some() {
            return Err(ManifestDeclarationError::AmbiguousDeclaration);
        }
        Ok(ResolvedDeclaration {
            package,
            module: module.id,
            declaration,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDeclarationError {
    UnknownModule,
    UnknownDeclaration,
    AmbiguousDeclaration,
}

impl fmt::Display for ManifestDeclarationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownModule => "manifest image module is absent from HIR",
            Self::UnknownDeclaration => "manifest image entry is absent from its module",
            Self::AmbiguousDeclaration => "manifest image entry is ambiguous in its module",
        })
    }
}

impl std::error::Error for ManifestDeclarationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    NonDense(&'static str),
    NonCanonical(&'static str),
    Coverage(&'static str),
    InvalidName {
        kind: &'static str,
        value: String,
    },
    InvalidRecord {
        arena: &'static str,
        id: u32,
        reason: &'static str,
    },
    InvalidReference {
        kind: &'static str,
        id: u32,
    },
    NestingLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HIR validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

fn require_dense(
    name: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut Vec<ValidationError>,
) {
    if ids
        .into_iter()
        .enumerate()
        .any(|(index, id)| u32::try_from(index).ok() != Some(id))
    {
        errors.push(ValidationError::NonDense(name));
    }
}

fn strict_ids(ids: impl IntoIterator<Item = u32>) -> bool {
    let mut previous = None;
    ids.into_iter().all(|id| {
        let valid = previous.is_none_or(|previous| previous < id);
        previous = Some(id);
        valid
    })
}

fn increment_coverage(coverage: &mut [u8], id: u32) {
    if let Some(count) = coverage.get_mut(id as usize) {
        *count = count.saturating_add(1);
    }
}

fn require_exact_coverage(name: &'static str, coverage: &[u8], errors: &mut Vec<ValidationError>) {
    if coverage.iter().any(|count| *count != 1) {
        errors.push(ValidationError::Coverage(name));
    }
}

fn require_owner_coverage(
    name: &'static str,
    count: usize,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut Vec<ValidationError>,
) {
    let mut coverage = vec![0u8; count];
    for id in ids {
        increment_coverage(&mut coverage, id);
    }
    require_exact_coverage(name, &coverage, errors);
}

fn invalid_reference(kind: &'static str, id: u32) -> ValidationError {
    ValidationError::InvalidReference { kind, id }
}

fn valid_span(span: Span) -> bool {
    span.range.start <= span.range.end
}

fn validate_name(name: &Name, kind: &'static str, errors: &mut Vec<ValidationError>) {
    let value = name.as_str();
    if !name.is_valid() {
        errors.push(ValidationError::InvalidName {
            kind,
            value: value.to_owned(),
        });
    }
}

fn declaration_generics(declaration: &Declaration) -> &[GenericParameterId] {
    match &declaration.kind {
        DeclarationKind::Function(value) => &value.generics,
        DeclarationKind::Structure(value) | DeclarationKind::Class(value) => &value.generics,
        DeclarationKind::Enumeration(value) => &value.generics,
        DeclarationKind::Interface(value) => &value.generics,
        DeclarationKind::Projection(value) => &value.generics,
        _ => &[],
    }
}

fn declaration_parameters(declaration: &Declaration) -> &[ParameterId] {
    match &declaration.kind {
        DeclarationKind::Function(value) => &value.parameters,
        DeclarationKind::Projection(value) => &value.parameters,
        DeclarationKind::Scope(value) => &value.parameters,
        _ => &[],
    }
}

fn declaration_children(declaration: &Declaration) -> &[DeclarationId] {
    match &declaration.kind {
        DeclarationKind::Structure(value) | DeclarationKind::Class(value) => &value.members,
        DeclarationKind::Enumeration(value) => &value.members,
        DeclarationKind::Interface(value) => &value.requirements,
        DeclarationKind::Implementation(value) => &value.members,
        _ => &[],
    }
}

fn declaration_owns(declaration: &Declaration, child: DeclarationId) -> bool {
    declaration_children(declaration)
        .binary_search(&child)
        .is_ok()
        || matches!(
            &declaration.kind,
            DeclarationKind::ComptimeSelection(value)
                if value.then_declarations.binary_search(&child).is_ok()
                    || value.else_declarations.binary_search(&child).is_ok()
        )
}

fn valid_resolved_declaration(program: &Program, resolved: &ResolvedDeclaration) -> bool {
    program
        .declaration(resolved.declaration)
        .is_some_and(|declaration| {
            declaration.module == resolved.module
                && program
                    .modules
                    .get(resolved.module.0 as usize)
                    .is_some_and(|module| module.package == resolved.package)
        })
}

fn valid_definition(program: &Program, definition: &Definition) -> bool {
    match definition {
        Definition::Declaration(value) => valid_resolved_declaration(program, value),
        Definition::Parameter(id) => program.parameter(*id).is_some(),
        Definition::Local(id) => program.local(*id).is_some(),
        Definition::Generic(id) => program.generic_parameter(*id).is_some(),
        Definition::Builtin(_) => true,
        Definition::Module { package, module } => program
            .modules
            .get(module.0 as usize)
            .is_some_and(|record| record.package == *package),
    }
}

fn valid_body_owner(program: &Program, owner: BodyOwner) -> bool {
    match owner {
        BodyOwner::Declaration(id) => program.declaration(id).is_some(),
        BodyOwner::Closure(id) => program
            .expression(id)
            .is_some_and(|expression| matches!(expression.kind, ExpressionKind::Closure { .. })),
    }
}

fn expression_owner_file(
    program: &Program,
    owner: ExpressionOwner,
) -> Option<wrela_source::FileId> {
    match owner {
        ExpressionOwner::Declaration(id) => program.declaration(id).map(|value| value.source.file),
        ExpressionOwner::Body(id) => program.body(id).map(|value| value.source.file),
    }
}

fn body_owner_file(program: &Program, owner: BodyOwner) -> Option<wrela_source::FileId> {
    match owner {
        BodyOwner::Declaration(id) => program.declaration(id).map(|value| value.source.file),
        BodyOwner::Closure(id) => program.expression(id).map(|value| value.source.file),
    }
}

fn statement_bodies(kind: &StatementKind) -> Vec<BodyId> {
    match kind {
        StatementKind::If {
            branches,
            else_body,
        } => branches
            .iter()
            .map(|(_, body)| *body)
            .chain(else_body.iter().copied())
            .collect(),
        StatementKind::Match { arms, .. } => arms.iter().map(|arm| arm.body).collect(),
        StatementKind::For { body, .. }
        | StatementKind::While { body, .. }
        | StatementKind::Loop { body }
        | StatementKind::With { body, .. } => vec![*body],
        StatementKind::ComptimeIf {
            then_body,
            else_body,
            ..
        } => std::iter::once(*then_body)
            .chain(else_body.iter().copied())
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_attribute_expressions(attribute: &Attribute, coverage: &mut [u8]) {
    for argument in &attribute.arguments {
        increment_coverage(coverage, argument.value.0);
    }
}

fn collect_type_expressions(ty: &TypeExpression, coverage: &mut [u8], depth: u32) {
    if depth >= 1024 {
        return;
    }
    match &ty.kind {
        TypeExpressionKind::Named { arguments, .. } => {
            for argument in arguments {
                match argument {
                    GenericArgument::Type(ty) => {
                        collect_type_expressions(ty, coverage, depth + 1);
                    }
                    GenericArgument::Constant(id) | GenericArgument::BoundedCapacity(id) => {
                        increment_coverage(coverage, id.0);
                    }
                    GenericArgument::Region(_) | GenericArgument::Error => {}
                }
            }
        }
        TypeExpressionKind::Array { element, length } => {
            collect_type_expressions(element, coverage, depth + 1);
            increment_coverage(coverage, length.0);
        }
        TypeExpressionKind::Tuple(values) => {
            for value in values {
                collect_type_expressions(value, coverage, depth + 1);
            }
        }
        TypeExpressionKind::View { target, .. } => {
            collect_type_expressions(target, coverage, depth + 1);
        }
        TypeExpressionKind::Iso { brand, payload } => {
            collect_type_expressions(brand, coverage, depth + 1);
            collect_type_expressions(payload, coverage, depth + 1);
        }
        TypeExpressionKind::Function {
            parameters, result, ..
        } => {
            for parameter in parameters {
                collect_type_expressions(&parameter.ty, coverage, depth + 1);
            }
            collect_type_expressions(result, coverage, depth + 1);
        }
        TypeExpressionKind::Error => {}
    }
}

fn collect_declaration_expressions(declaration: &Declaration, coverage: &mut [u8]) {
    for attribute in &declaration.attributes {
        collect_attribute_expressions(attribute, coverage);
    }
    match &declaration.kind {
        DeclarationKind::Constant(value) => {
            if let Some(ty) = &value.ty {
                collect_type_expressions(ty, coverage, 0);
            }
            increment_coverage(coverage, value.value.0);
        }
        DeclarationKind::Function(value) => {
            collect_type_expressions(&value.result, coverage, 0);
        }
        DeclarationKind::Structure(value) | DeclarationKind::Class(value) => {
            for ty in &value.implements {
                collect_type_expressions(ty, coverage, 0);
            }
            for field in &value.fields {
                for attribute in &field.attributes {
                    collect_attribute_expressions(attribute, coverage);
                }
                collect_type_expressions(&field.ty, coverage, 0);
                if let Some(default) = field.default {
                    increment_coverage(coverage, default.0);
                }
            }
        }
        DeclarationKind::Enumeration(value) => {
            for variant in &value.variants {
                for field in &variant.fields {
                    collect_type_expressions(&field.ty, coverage, 0);
                }
            }
        }
        DeclarationKind::Implementation(value) => {
            collect_type_expressions(&value.interface, coverage, 0);
            collect_type_expressions(&value.implementing_type, coverage, 0);
        }
        DeclarationKind::Projection(value) => {
            collect_carrier_expressions(&value.carrier, coverage);
        }
        DeclarationKind::Scope(value) => {
            collect_type_expressions(&value.result, coverage, 0);
            increment_coverage(coverage, value.enter.0);
        }
        DeclarationKind::ComptimeSelection(value) => {
            increment_coverage(coverage, value.condition.0);
        }
        DeclarationKind::Brand | DeclarationKind::Interface(_) | DeclarationKind::Error => {}
    }
}

fn collect_carrier_expressions(carrier: &ProjectionCarrier, coverage: &mut [u8]) {
    match carrier {
        ProjectionCarrier::View { ty, .. } => collect_type_expressions(ty, coverage, 0),
        ProjectionCarrier::Tuple(values) => {
            for value in values {
                collect_carrier_expressions(value, coverage);
            }
        }
        ProjectionCarrier::Option(value) => collect_carrier_expressions(value, coverage),
        ProjectionCarrier::Result { carrier, error } => {
            collect_carrier_expressions(carrier, coverage);
            collect_type_expressions(error, coverage, 0);
        }
        ProjectionCarrier::Error => {}
    }
}

fn collect_statement_expressions(kind: &StatementKind, coverage: &mut [u8]) {
    match kind {
        StatementKind::Initialize { value, .. } => increment_coverage(coverage, value.0),
        StatementKind::Assign { targets, value, .. } => {
            for target in targets {
                for projection in &target.projections {
                    if let PlaceProjection::Index(index) = projection {
                        increment_coverage(coverage, index.0);
                    }
                }
            }
            increment_coverage(coverage, value.0);
        }
        StatementKind::Return(value) => {
            if let Some(value) = value {
                increment_coverage(coverage, value.0);
            }
        }
        StatementKind::Assert { condition, .. } => increment_coverage(coverage, condition.0),
        StatementKind::Send(value)
        | StatementKind::Yield(value)
        | StatementKind::Expression(value) => increment_coverage(coverage, value.0),
        StatementKind::If { branches, .. } => {
            for (condition, _) in branches {
                increment_coverage(coverage, condition.0);
            }
        }
        StatementKind::Match { scrutinee, arms } => {
            increment_coverage(coverage, scrutinee.0);
            for arm in arms {
                if let Some(guard) = arm.guard {
                    increment_coverage(coverage, guard.0);
                }
            }
        }
        StatementKind::For { iterable, .. } => increment_coverage(coverage, iterable.0),
        StatementKind::While { condition, .. } | StatementKind::ComptimeIf { condition, .. } => {
            increment_coverage(coverage, condition.0);
        }
        StatementKind::With { value, .. } => increment_coverage(coverage, value.0),
        StatementKind::Break
        | StatementKind::Continue
        | StatementKind::Pass
        | StatementKind::Loop { .. }
        | StatementKind::Error => {}
    }
}

fn collect_expression_children(kind: &ExpressionKind, coverage: &mut [u8]) {
    match kind {
        ExpressionKind::Closure {
            body: ClosureBody::Expression(body),
            ..
        } => increment_coverage(coverage, body.0),
        ExpressionKind::Unary { operand, .. }
        | ExpressionKind::Try(operand)
        | ExpressionKind::TrySend(operand) => increment_coverage(coverage, operand.0),
        ExpressionKind::Binary { left, right, .. } => {
            increment_coverage(coverage, left.0);
            increment_coverage(coverage, right.0);
        }
        ExpressionKind::Compare { first, tails } => {
            increment_coverage(coverage, first.0);
            for (_, value) in tails {
                increment_coverage(coverage, value.0);
            }
        }
        ExpressionKind::IsPattern { value, .. } => increment_coverage(coverage, value.0),
        ExpressionKind::Range { start, end, .. } => {
            increment_coverage(coverage, start.0);
            increment_coverage(coverage, end.0);
        }
        ExpressionKind::Cast { value, ty } => {
            increment_coverage(coverage, value.0);
            collect_type_expressions(ty, coverage, 0);
        }
        ExpressionKind::Field { base, .. } => increment_coverage(coverage, base.0),
        ExpressionKind::Call { callee, arguments } => {
            increment_coverage(coverage, callee.0);
            for argument in arguments {
                increment_coverage(coverage, argument.value.0);
            }
        }
        ExpressionKind::Index { base, index } => {
            increment_coverage(coverage, base.0);
            increment_coverage(coverage, index.0);
        }
        ExpressionKind::Tuple(values)
        | ExpressionKind::Array(values)
        | ExpressionKind::Race(values) => {
            for value in values {
                increment_coverage(coverage, value.0);
            }
        }
        ExpressionKind::Interpolate(parts) => {
            for part in parts {
                if let InterpolationPart::Value { expression, .. } = part {
                    increment_coverage(coverage, expression.0);
                }
            }
        }
        ExpressionKind::Literal(_)
        | ExpressionKind::Reference(_)
        | ExpressionKind::Closure {
            body: ClosureBody::Body(_),
            ..
        }
        | ExpressionKind::Error => {}
    }
}

fn validate_type(
    program: &Program,
    ty: &TypeExpression,
    expression_owner: ExpressionOwner,
    depth: u32,
    errors: &mut Vec<ValidationError>,
) {
    if depth >= 1024 {
        errors.push(ValidationError::NestingLimit);
        return;
    }
    if !valid_span(ty.source)
        || expression_owner_file(program, expression_owner) != Some(ty.source.file)
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "type expression",
            id: depth,
            reason: "source owner",
        });
    }
    match &ty.kind {
        TypeExpressionKind::Named {
            definition,
            arguments,
        } => {
            if !valid_definition(program, definition) {
                errors.push(invalid_reference("type definition", 0));
            }
            for argument in arguments {
                match argument {
                    GenericArgument::Type(value) => {
                        validate_type(program, value, expression_owner, depth + 1, errors);
                    }
                    GenericArgument::Constant(id) | GenericArgument::BoundedCapacity(id) => {
                        if program
                            .expression(*id)
                            .is_none_or(|value| value.owner != expression_owner)
                        {
                            errors.push(invalid_reference("generic constant expression", id.0));
                        }
                    }
                    GenericArgument::Region(id) => {
                        if program
                            .generic_parameter(*id)
                            .is_none_or(|value| !matches!(value.kind, GenericParameterKind::Region))
                        {
                            errors.push(invalid_reference("generic region", id.0));
                        }
                    }
                    GenericArgument::Error => {}
                }
            }
        }
        TypeExpressionKind::Array { element, length } => {
            validate_type(program, element, expression_owner, depth + 1, errors);
            if program
                .expression(*length)
                .is_none_or(|value| value.owner != expression_owner)
            {
                errors.push(invalid_reference("array length", length.0));
            }
        }
        TypeExpressionKind::Tuple(values) => {
            for value in values {
                validate_type(program, value, expression_owner, depth + 1, errors);
            }
        }
        TypeExpressionKind::View { target, .. } => {
            validate_type(program, target, expression_owner, depth + 1, errors);
        }
        TypeExpressionKind::Iso { brand, payload } => {
            validate_type(program, brand, expression_owner, depth + 1, errors);
            validate_type(program, payload, expression_owner, depth + 1, errors);
        }
        TypeExpressionKind::Function {
            parameters, result, ..
        } => {
            for parameter in parameters {
                if !valid_span(parameter.source) || parameter.source.file != ty.source.file {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "function type parameter",
                        id: depth,
                        reason: "source",
                    });
                }
                validate_type(program, &parameter.ty, expression_owner, depth + 1, errors);
            }
            validate_type(program, result, expression_owner, depth + 1, errors);
        }
        TypeExpressionKind::Error => {}
    }
}

fn validate_attribute(
    program: &Program,
    attribute: &Attribute,
    owner: ExpressionOwner,
    errors: &mut Vec<ValidationError>,
) {
    if !valid_resolved_declaration(program, &attribute.name)
        || !valid_span(attribute.source)
        || expression_owner_file(program, owner) != Some(attribute.source.file)
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "attribute",
            id: 0,
            reason: "name, owner, or source",
        });
    }
    for argument in &attribute.arguments {
        if let Some(name) = &argument.name {
            validate_name(name, "attribute argument", errors);
        }
        if !valid_span(argument.source)
            || argument.source.file != attribute.source.file
            || program
                .expression(argument.value)
                .is_none_or(|value| value.owner != owner)
        {
            errors.push(invalid_reference("attribute argument", argument.value.0));
        }
    }
}

fn validate_declaration(
    program: &Program,
    declaration: &Declaration,
    errors: &mut Vec<ValidationError>,
) {
    validate_name(&declaration.name, "declaration", errors);
    let Some(module) = program.modules.get(declaration.module.0 as usize) else {
        errors.push(invalid_reference(
            "declaration module",
            declaration.module.0,
        ));
        return;
    };
    if !valid_span(declaration.source) || declaration.source.file != module.source.file {
        errors.push(ValidationError::InvalidRecord {
            arena: "declaration",
            id: declaration.id.0,
            reason: "source",
        });
    }
    for attribute in &declaration.attributes {
        validate_attribute(
            program,
            attribute,
            ExpressionOwner::Declaration(declaration.id),
            errors,
        );
    }
    let owner = ExpressionOwner::Declaration(declaration.id);
    if !strict_ids(declaration_generics(declaration).iter().map(|id| id.0))
        || !strict_ids(declaration_parameters(declaration).iter().map(|id| id.0))
        || !strict_ids(declaration_children(declaration).iter().map(|id| id.0))
    {
        errors.push(ValidationError::NonCanonical("declaration references"));
    }
    for generic in declaration_generics(declaration) {
        if program
            .generic_parameter(*generic)
            .is_none_or(|value| value.owner != declaration.id)
        {
            errors.push(invalid_reference("declaration generic", generic.0));
        }
    }
    for parameter in declaration_parameters(declaration) {
        if program
            .parameter(*parameter)
            .is_none_or(|value| value.owner != CallableOwner::Declaration(declaration.id))
        {
            errors.push(invalid_reference("declaration parameter", parameter.0));
        }
    }
    for child in declaration_children(declaration) {
        if program
            .declaration(*child)
            .is_none_or(|value| value.owner != DeclarationOwner::Declaration(declaration.id))
        {
            errors.push(invalid_reference("nested declaration", child.0));
        }
    }
    match &declaration.kind {
        DeclarationKind::Constant(value) => {
            if let Some(ty) = &value.ty {
                validate_type(program, ty, owner, 0, errors);
            }
            check_expression_owner(program, value.value, owner, "constant value", errors);
        }
        DeclarationKind::Brand | DeclarationKind::Error => {}
        DeclarationKind::Function(value) => {
            validate_type(program, &value.result, owner, 0, errors);
            if let Some(body) = value.body {
                check_body_owner(
                    program,
                    body,
                    BodyOwner::Declaration(declaration.id),
                    "function body",
                    errors,
                );
            }
        }
        DeclarationKind::Structure(value) | DeclarationKind::Class(value) => {
            for implementation in &value.implements {
                validate_type(program, implementation, owner, 0, errors);
            }
            for field in &value.fields {
                validate_name(&field.name, "field", errors);
                if !valid_span(field.source) || field.source.file != declaration.source.file {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "field",
                        id: declaration.id.0,
                        reason: "source",
                    });
                }
                for attribute in &field.attributes {
                    validate_attribute(program, attribute, owner, errors);
                }
                validate_type(program, &field.ty, owner, 0, errors);
                if let Some(default) = field.default {
                    check_expression_owner(program, default, owner, "field default", errors);
                }
            }
        }
        DeclarationKind::Enumeration(value) => {
            for variant in &value.variants {
                validate_name(&variant.name, "enum variant", errors);
                if !valid_span(variant.source) || variant.source.file != declaration.source.file {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "enum variant",
                        id: declaration.id.0,
                        reason: "source",
                    });
                }
                for field in &variant.fields {
                    if let Some(name) = &field.name {
                        validate_name(name, "variant field", errors);
                    }
                    validate_type(program, &field.ty, owner, 0, errors);
                }
            }
        }
        DeclarationKind::Interface(_) => {}
        DeclarationKind::Implementation(value) => {
            validate_type(program, &value.interface, owner, 0, errors);
            validate_type(program, &value.implementing_type, owner, 0, errors);
        }
        DeclarationKind::Projection(value) => {
            validate_carrier(program, &value.carrier, owner, errors);
            for parameter in &value.provenance {
                if program.parameter(*parameter).is_none() {
                    errors.push(invalid_reference("projection provenance", parameter.0));
                }
            }
            if let Some(body) = value.body {
                check_body_owner(
                    program,
                    body,
                    BodyOwner::Declaration(declaration.id),
                    "projection body",
                    errors,
                );
            }
        }
        DeclarationKind::Scope(value) => {
            validate_type(program, &value.result, owner, 0, errors);
            check_body_owner(
                program,
                value.setup,
                BodyOwner::Declaration(declaration.id),
                "scope setup",
                errors,
            );
            check_expression_owner(program, value.enter, owner, "scope enter", errors);
            if let Some(abort) = value.abort {
                check_body_owner(
                    program,
                    abort,
                    BodyOwner::Declaration(declaration.id),
                    "scope abort",
                    errors,
                );
            }
            if value
                .parameters
                .binary_search(&value.exit_parameter)
                .is_err()
            {
                errors.push(invalid_reference(
                    "scope exit parameter",
                    value.exit_parameter.0,
                ));
            }
            check_body_owner(
                program,
                value.exit,
                BodyOwner::Declaration(declaration.id),
                "scope exit",
                errors,
            );
        }
        DeclarationKind::ComptimeSelection(value) => {
            check_expression_owner(
                program,
                value.condition,
                owner,
                "comptime condition",
                errors,
            );
            if !strict_ids(value.then_declarations.iter().map(|id| id.0))
                || !strict_ids(value.else_declarations.iter().map(|id| id.0))
            {
                errors.push(ValidationError::NonCanonical("comptime declarations"));
            }
            for child in value
                .then_declarations
                .iter()
                .chain(&value.else_declarations)
            {
                if program.declaration(*child).is_none_or(|child_declaration| {
                    child_declaration.owner != DeclarationOwner::Declaration(declaration.id)
                }) {
                    errors.push(invalid_reference("comptime declaration", child.0));
                }
            }
        }
    }
}

fn validate_carrier(
    program: &Program,
    carrier: &ProjectionCarrier,
    owner: ExpressionOwner,
    errors: &mut Vec<ValidationError>,
) {
    match carrier {
        ProjectionCarrier::View { ty, .. } => validate_type(program, ty, owner, 0, errors),
        ProjectionCarrier::Tuple(values) => {
            for value in values {
                validate_carrier(program, value, owner, errors);
            }
        }
        ProjectionCarrier::Option(value) => validate_carrier(program, value, owner, errors),
        ProjectionCarrier::Result { carrier, error } => {
            validate_carrier(program, carrier, owner, errors);
            validate_type(program, error, owner, 0, errors);
        }
        ProjectionCarrier::Error => {}
    }
}

fn check_expression_owner(
    program: &Program,
    id: ExpressionId,
    owner: ExpressionOwner,
    kind: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if program
        .expression(id)
        .is_none_or(|value| value.owner != owner)
    {
        errors.push(invalid_reference(kind, id.0));
    }
}

fn check_body_owner(
    program: &Program,
    id: BodyId,
    owner: BodyOwner,
    kind: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if program.body(id).is_none_or(|value| value.owner != owner) {
        errors.push(invalid_reference(kind, id.0));
    }
}

fn validate_statement(program: &Program, statement: &Statement, errors: &mut Vec<ValidationError>) {
    let owner = ExpressionOwner::Body(statement.body);
    let Some(body) = program.body(statement.body) else {
        errors.push(invalid_reference("statement body", statement.body.0));
        return;
    };
    if !valid_span(statement.source) || statement.source.file != body.source.file {
        errors.push(ValidationError::InvalidRecord {
            arena: "statement",
            id: statement.id.0,
            reason: "body or source",
        });
    }
    for attribute in &statement.attributes {
        validate_attribute(program, attribute, owner, errors);
    }
    let expression = |id: ExpressionId, kind: &'static str, errors: &mut Vec<ValidationError>| {
        check_expression_owner(program, id, owner, kind, errors);
    };
    let child_body = |id: BodyId, kind: &'static str, errors: &mut Vec<ValidationError>| {
        if id.0 <= statement.body.0
            || program
                .body(id)
                .is_none_or(|value| value.owner != body.owner)
        {
            errors.push(invalid_reference(kind, id.0));
        }
    };
    match &statement.kind {
        StatementKind::Initialize { local, value } => {
            if program
                .local(*local)
                .is_none_or(|value| value.body != statement.body)
            {
                errors.push(invalid_reference("initialized local", local.0));
            }
            expression(*value, "initializer", errors);
        }
        StatementKind::Assign { targets, value, .. } => {
            if targets.is_empty() {
                errors.push(ValidationError::InvalidRecord {
                    arena: "assignment",
                    id: statement.id.0,
                    reason: "empty targets",
                });
            }
            for target in targets {
                if !valid_definition(program, &target.root) || !valid_span(target.source) {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "assignment target",
                        id: statement.id.0,
                        reason: "root or source",
                    });
                }
                for projection in &target.projections {
                    match projection {
                        PlaceProjection::Field(name) => validate_name(name, "field", errors),
                        PlaceProjection::Index(index) => {
                            expression(*index, "place index", errors);
                        }
                        PlaceProjection::Tuple(_) => {}
                    }
                }
            }
            expression(*value, "assignment value", errors);
        }
        StatementKind::Return(value) => {
            if let Some(value) = value {
                expression(*value, "return value", errors);
            }
        }
        StatementKind::Break
        | StatementKind::Continue
        | StatementKind::Pass
        | StatementKind::Error => {}
        StatementKind::Assert { condition, .. } => expression(*condition, "assertion", errors),
        StatementKind::Send(value)
        | StatementKind::Yield(value)
        | StatementKind::Expression(value) => expression(*value, "statement expression", errors),
        StatementKind::If {
            branches,
            else_body,
        } => {
            if branches.is_empty() {
                errors.push(ValidationError::InvalidRecord {
                    arena: "if statement",
                    id: statement.id.0,
                    reason: "empty branches",
                });
            }
            for (condition, branch) in branches {
                expression(*condition, "if condition", errors);
                child_body(*branch, "if body", errors);
            }
            if let Some(body) = else_body {
                child_body(*body, "else body", errors);
            }
        }
        StatementKind::Match { scrutinee, arms } => {
            expression(*scrutinee, "match scrutinee", errors);
            for arm in arms {
                if !valid_span(arm.source) || arm.source.file != statement.source.file {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "match arm",
                        id: statement.id.0,
                        reason: "source",
                    });
                }
                if program
                    .pattern(arm.pattern)
                    .is_none_or(|value| value.owner != owner)
                {
                    errors.push(invalid_reference("match pattern", arm.pattern.0));
                }
                if let Some(guard) = arm.guard {
                    expression(guard, "match guard", errors);
                }
                child_body(arm.body, "match body", errors);
            }
        }
        StatementKind::For {
            binding,
            iterable,
            body,
            ..
        } => {
            if program.local(*binding).is_none() {
                errors.push(invalid_reference("for binding", binding.0));
            }
            expression(*iterable, "for iterable", errors);
            child_body(*body, "for body", errors);
        }
        StatementKind::While { condition, body } => {
            expression(*condition, "while condition", errors);
            child_body(*body, "while body", errors);
        }
        StatementKind::Loop { body } => child_body(*body, "loop body", errors),
        StatementKind::With {
            value,
            binding,
            region,
            body,
        } => {
            expression(*value, "with value", errors);
            if binding.is_some_and(|binding| program.local(binding).is_none()) {
                errors.push(invalid_reference(
                    "with binding",
                    binding.unwrap_or(LocalId(0)).0,
                ));
            }
            if region.is_some_and(|region| {
                program
                    .generic_parameter(region)
                    .is_none_or(|value| !matches!(value.kind, GenericParameterKind::Region))
            }) {
                errors.push(invalid_reference(
                    "with region",
                    region.unwrap_or(GenericParameterId(0)).0,
                ));
            }
            child_body(*body, "with body", errors);
        }
        StatementKind::ComptimeIf {
            condition,
            then_body,
            else_body,
        } => {
            expression(*condition, "comptime condition", errors);
            child_body(*then_body, "comptime body", errors);
            if let Some(body) = else_body {
                child_body(*body, "comptime else body", errors);
            }
        }
    }
}

fn validate_expression(
    program: &Program,
    expression: &Expression,
    errors: &mut Vec<ValidationError>,
) {
    if !valid_span(expression.source)
        || expression_owner_file(program, expression.owner) != Some(expression.source.file)
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "expression",
            id: expression.id.0,
            reason: "owner or source",
        });
    }
    let child = |id: ExpressionId, kind: &'static str, errors: &mut Vec<ValidationError>| {
        if id.0 <= expression.id.0
            || program
                .expression(id)
                .is_none_or(|value| value.owner != expression.owner)
        {
            errors.push(invalid_reference(kind, id.0));
        }
    };
    match &expression.kind {
        ExpressionKind::Literal(value) => validate_literal(value, expression.id, errors),
        ExpressionKind::Reference(value) => {
            if !valid_definition(program, value) {
                errors.push(invalid_reference("expression definition", expression.id.0));
            }
        }
        ExpressionKind::Closure {
            parameters,
            body,
            captures,
            ..
        } => {
            if !strict_ids(parameters.iter().map(|id| id.0)) {
                errors.push(ValidationError::NonCanonical("closure parameters"));
            }
            for parameter in parameters {
                if program
                    .parameter(*parameter)
                    .is_none_or(|value| value.owner != CallableOwner::Closure(expression.id))
                {
                    errors.push(invalid_reference("closure parameter", parameter.0));
                }
            }
            match body {
                ClosureBody::Expression(id) => child(*id, "closure expression", errors),
                ClosureBody::Body(id) => check_body_owner(
                    program,
                    *id,
                    BodyOwner::Closure(expression.id),
                    "closure body",
                    errors,
                ),
            }
            for capture in captures {
                if !valid_definition(program, capture) {
                    errors.push(invalid_reference("closure capture", expression.id.0));
                }
            }
        }
        ExpressionKind::Unary { operand, .. } => child(*operand, "unary operand", errors),
        ExpressionKind::Binary { left, right, .. } => {
            child(*left, "binary left", errors);
            child(*right, "binary right", errors);
        }
        ExpressionKind::Compare { first, tails } => {
            child(*first, "comparison first", errors);
            for (_, id) in tails {
                child(*id, "comparison tail", errors);
            }
        }
        ExpressionKind::IsPattern { value, pattern, .. } => {
            child(*value, "pattern value", errors);
            if program
                .pattern(*pattern)
                .is_none_or(|value| value.owner != expression.owner)
            {
                errors.push(invalid_reference("expression pattern", pattern.0));
            }
        }
        ExpressionKind::Range { start, end, .. } => {
            child(*start, "range start", errors);
            child(*end, "range end", errors);
        }
        ExpressionKind::Cast { value, ty } => {
            child(*value, "cast value", errors);
            validate_type(program, ty, expression.owner, 0, errors);
        }
        ExpressionKind::Try(value) | ExpressionKind::TrySend(value) => {
            child(*value, "try value", errors);
        }
        ExpressionKind::Field { base, name } => {
            child(*base, "field base", errors);
            validate_name(name, "field", errors);
        }
        ExpressionKind::Call { callee, arguments } => {
            child(*callee, "callee", errors);
            for argument in arguments {
                if let Some(name) = &argument.name {
                    validate_name(name, "call argument", errors);
                }
                if !valid_span(argument.source) || argument.source.file != expression.source.file {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "call argument",
                        id: expression.id.0,
                        reason: "source",
                    });
                }
                child(argument.value, "call argument", errors);
            }
        }
        ExpressionKind::Index { base, index } => {
            child(*base, "index base", errors);
            child(*index, "index", errors);
        }
        ExpressionKind::Tuple(values)
        | ExpressionKind::Array(values)
        | ExpressionKind::Race(values) => {
            for value in values {
                child(*value, "aggregate expression", errors);
            }
        }
        ExpressionKind::Interpolate(parts) => {
            for part in parts {
                match part {
                    InterpolationPart::Text(value) => {
                        if value.len() > 16 * 1024 * 1024 {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "interpolation",
                                id: expression.id.0,
                                reason: "text bound",
                            });
                        }
                    }
                    InterpolationPart::Value { expression, format } => {
                        child(*expression, "interpolation value", errors);
                        if format.as_ref().is_some_and(|value| value.len() > 4096) {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "interpolation",
                                id: expression.0,
                                reason: "format bound",
                            });
                        }
                    }
                }
            }
        }
        ExpressionKind::Error => {}
    }
}

fn validate_literal(value: &Literal, id: ExpressionId, errors: &mut Vec<ValidationError>) {
    let valid = match value {
        Literal::Integer(value) | Literal::Float(value) | Literal::String(value) => {
            !value.is_empty() && value.len() <= 16 * 1024 * 1024
        }
        Literal::Bytes(value) => value.len() <= 16 * 1024 * 1024,
        Literal::Character(_) | Literal::Boolean(_) | Literal::Unit => true,
    };
    if !valid {
        errors.push(ValidationError::InvalidRecord {
            arena: "literal",
            id: id.0,
            reason: "empty or oversized spelling",
        });
    }
}

fn validate_pattern(program: &Program, pattern: &Pattern, errors: &mut Vec<ValidationError>) {
    if pattern.alternatives.is_empty()
        || !valid_span(pattern.source)
        || expression_owner_file(program, pattern.owner) != Some(pattern.source.file)
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "pattern",
            id: pattern.id.0,
            reason: "alternatives, body, or source",
        });
    }
    for alternative in &pattern.alternatives {
        match alternative {
            PrimaryPattern::Wildcard | PrimaryPattern::Error => {}
            PrimaryPattern::Literal { literal, .. } => {
                validate_literal(literal, ExpressionId(pattern.id.0), errors);
            }
            PrimaryPattern::Constructor {
                candidates,
                arguments,
            } => {
                if candidates.is_empty()
                    || candidates
                        .iter()
                        .any(|value| !valid_resolved_declaration(program, value))
                {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "constructor pattern",
                        id: pattern.id.0,
                        reason: "candidates",
                    });
                }
                validate_pattern_arguments(program, pattern, arguments, errors);
            }
            PrimaryPattern::Bind(local) => {
                if program.local(*local).is_none() {
                    errors.push(invalid_reference("pattern binding", local.0));
                }
            }
            PrimaryPattern::Tuple(arguments) | PrimaryPattern::Array(arguments) => {
                validate_pattern_arguments(program, pattern, arguments, errors);
            }
        }
    }
}

fn validate_pattern_arguments(
    program: &Program,
    parent: &Pattern,
    arguments: &[PatternArgument],
    errors: &mut Vec<ValidationError>,
) {
    for argument in arguments {
        if !valid_span(argument.source)
            || argument.source.file != parent.source.file
            || argument.pattern.0 <= parent.id.0
            || program
                .pattern(argument.pattern)
                .is_none_or(|value| value.owner != parent.owner)
        {
            errors.push(invalid_reference("pattern argument", argument.pattern.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_build_model::Sha256Digest;
    use wrela_package::{PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion};
    use wrela_source::{FileId, TextRange};

    #[test]
    fn resolves_manifest_entry_without_rebuilding_name_tables() {
        let path = ModulePath::new(["boot".to_owned()]).expect("module path");
        let identity = PackageIdentity {
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1").expect("package version"),
            source_digest: Sha256Digest::from_bytes([1; 32]),
        };
        let mut graph = PackageGraphBuilder::new(identity);
        graph
            .add_module(graph.root(), path.clone(), FileId(0))
            .expect("module");
        let graph = graph.finish().expect("graph");
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 0 },
        };
        let program = Program {
            packages: graph,
            modules: vec![Module {
                id: ModuleId(0),
                package: PackageId(0),
                path: path.clone(),
                declarations: vec![DeclarationId(0)],
                reexports: Vec::new(),
                source,
            }],
            declarations: vec![Declaration {
                id: DeclarationId(0),
                module: ModuleId(0),
                owner: DeclarationOwner::Module(ModuleId(0)),
                name: Name::from_validated("start".to_owned()),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Brand,
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: Vec::new(),
            scopes: Vec::new(),
            locals: Vec::new(),
            statements: Vec::new(),
            expressions: Vec::new(),
            patterns: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        }
        .validate()
        .expect("valid HIR");

        let resolved = program
            .manifest_declaration(PackageId(0), &path, "start")
            .expect("manifest entry");
        assert_eq!(resolved.declaration, DeclarationId(0));
        assert!(matches!(
            program.manifest_declaration(PackageId(0), &path, "missing"),
            Err(ManifestDeclarationError::UnknownDeclaration)
        ));
    }
}
