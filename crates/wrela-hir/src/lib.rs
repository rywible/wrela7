//! Pure, normalized, name-resolved high-level IR.
//!
//! HIR removes layout, import syntax, parentheses, sugar, and ambiguous generic
//! argument kinds. It retains source provenance and language structure needed
//! by type/effect/ownership/comptime analysis. No inferred semantic fact lives
//! here.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use wrela_package::{ModuleId, ModulePath, PackageGraph, PackageId, is_valid_source_identifier};
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
id_type!(RegionId);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Construct a source-facing name under the exact revision 0.1 scanner
    /// identifier contract.
    pub fn new(value: String) -> Result<Self, InvalidName> {
        if is_valid_source_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidName)
        }
    }

    /// Construct a call argument label. The image-pool intrinsic reserves the
    /// declaration keyword `brand` as its normative label; no other keyword is
    /// admitted through this role-specific constructor.
    pub fn new_argument_label(value: String) -> Result<Self, InvalidName> {
        if is_valid_source_identifier(&value) || value == "brand" {
            Ok(Self(value))
        } else {
            Err(InvalidName)
        }
    }

    /// Construct an expression member name. `from` is the sole revision 0.1
    /// keyword admitted in member position because the generated conversion
    /// contract spells calls as `Destination.from(value)`.
    pub fn new_member(value: String) -> Result<Self, InvalidName> {
        if is_valid_source_identifier(&value) || value == "from" {
            Ok(Self(value))
        } else {
            Err(InvalidName)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_valid_source_identifier(self.as_str())
    }

    #[must_use]
    pub fn is_valid_argument_label(&self) -> bool {
        self.is_valid() || self.as_str() == "brand"
    }

    #[must_use]
    pub fn is_valid_member(&self) -> bool {
        self.is_valid() || self.as_str() == "from"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidName;

impl fmt::Display for InvalidName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid revision 0.1 source identifier")
    }
}

impl std::error::Error for InvalidName {}

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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResolvedDeclaration {
    pub package: PackageId,
    pub module: ModuleId,
    pub declaration: DeclarationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResolvedVariant {
    pub enumeration: ResolvedDeclaration,
    pub variant: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    Declaration(ResolvedDeclaration),
    Variant(ResolvedVariant),
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
    Never,
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
    pub identity: AttributeIdentity,
    pub arguments: Vec<AttributeArgument>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeIdentity {
    Builtin(BuiltinAttribute),
    /// A name imported from an explicitly declared non-semantic tool
    /// namespace. Semantic compiler attributes use [`Self::Builtin`].
    Tool(ResolvedDeclaration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BuiltinAttribute {
    Image,
    App,
    Service,
    Driver,
    Task,
    IsrSafe,
    ReceiptHandoff,
    Dma,
    Wire,
    Mmio,
    Offset,
    LayoutAssert,
    Test,
    SuspendSafe,
    NoPromote,
    Budget,
    Uninterrupted,
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
    pub target: ReexportTarget,
    pub source: Span,
}

/// Exact namespace identity exported by a public import. Source permits both
/// `pub from ... import name` (including enum variants) and
/// `pub import module.path as alias`, so a declaration-only target would lose
/// a real name-resolution distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReexportTarget {
    Declaration(ResolvedDeclaration),
    Variant(ResolvedVariant),
    Module {
        package: PackageId,
        module: ModuleId,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    pub id: DeclarationId,
    pub module: ModuleId,
    pub owner: DeclarationOwner,
    /// Source-visible name. Implementations, unresolved comptime selections,
    /// and recovery declarations are deliberately anonymous.
    pub name: Option<Name>,
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
    /// A struct-owned construction body. Initializers are deliberately not
    /// functions: they have no source name, generics, visibility, attributes,
    /// color, or optional body.
    Initializer(InitializerDeclaration),
    Structure(AggregateDeclaration),
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
    /// Absent for the source-level implicit `unit` result. Keeping this
    /// distinction avoids assigning a fabricated span to a synthesized type.
    pub result: Option<TypeExpression>,
    pub body: Option<BodyId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InitializerDeclaration {
    pub parameters: Vec<ParameterId>,
    /// Retained as written so the semantic boundary can issue the adopted
    /// surface diagnostic before any callable or WIR representation exists.
    pub result: Option<TypeExpression>,
    pub body: BodyId,
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
    /// Ordinary parameters have a source identifier. The receiver is spelled
    /// with the reserved `self` token and therefore has no forgeable `Name`.
    pub name: Option<Name>,
    pub access: AccessMode,
    /// Ordinary parameters carry their explicit source type. A receiver has
    /// no separately written type; semantic analysis derives it from its
    /// enclosing nominal/interface/implementation declaration.
    pub ty: Option<TypeExpression>,
    pub receiver: bool,
    /// `_ name: Type` — call sites must omit the argument label. The unary
    /// non-receiver rule also forces positional-only at call sites even when
    /// this flag is false.
    pub positional_only: bool,
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
    /// `linear struct Name:` — non-copyable regardless of fields.
    pub linear: bool,
    /// `copy struct Name:` — implicitly duplicable when fields are recursively copyable.
    pub copy: bool,
    /// Closed compiler-known `deriving(...)` names from the declaration header.
    pub deriving: Vec<Name>,
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
    /// Closed compiler-known `deriving(...)` names from the declaration header.
    pub deriving: Vec<Name>,
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
pub struct ProjectionCarrier {
    pub kind: ProjectionCarrierKind,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectionCarrierKind {
    View {
        mutable: bool,
        ty: TypeExpression,
    },
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
    /// The exact source `Self` type. Its declaration identity is retained
    /// instead of expanding it into an implementing/named type with invented
    /// generic arguments or provenance.
    SelfType {
        owner: DeclarationId,
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
pub struct GenericArgument {
    pub kind: GenericArgumentKind,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GenericArgumentKind {
    Type(TypeExpression),
    Constant(ExpressionId),
    BoundedCapacity(ExpressionId),
    Region(RegionReference),
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RegionReference {
    Generic(GenericParameterId),
    Local(RegionId),
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

/// Immediate-producer witness binding retained assertion text to the exact
/// condition span. The duplicated text is intentional: the sealed HIR
/// validator rejects one-sided mutation before semantics can consume it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionSourceWitness {
    pub source: Span,
    pub expression: String,
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
        /// Exact UTF-8 source bytes covered by the condition expression span.
        /// Runtime assertion reporting retains this here because HIR otherwise
        /// deliberately does not retain the complete source database.
        expression: String,
        witness: AssertionSourceWitness,
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
        /// Fresh proof-only region brand introduced for the child body.
        region: Option<RegionId>,
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
    /// Lexical scope for body-owned expressions. Declaration-owned constant,
    /// attribute, default, and type-level expressions have no body scope.
    pub scope: Option<ScopeId>,
    pub kind: ExpressionKind,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionOwner {
    Declaration(DeclarationId),
    Body(BodyId),
    /// Expressions in an expression-bodied closure. Block-bodied closures use
    /// their ordinary child [`BodyId`] owner instead.
    Closure(ExpressionId),
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
        left: ExpressionId,
        operator: ComparisonOperator,
        right: ExpressionId,
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
    /// A leading-dot variant reference (`.Name`), pending contextual
    /// resolution among same-spelling enum variants visible at this point.
    /// `.Name(args)` lowers as `Call { callee: DotName { .. }, .. }`.
    DotName {
        spelling: Name,
        candidates: Vec<ResolvedVariant>,
    },
    TrySend(ExpressionId),
    Interpolate(Vec<InterpolationPart>),
    /// Inline conditional expression with a mandatory else branch.
    If {
        condition: ExpressionId,
        then_branch: ExpressionId,
        elif_branches: Vec<(ExpressionId, ExpressionId)>,
        else_branch: ExpressionId,
    },
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
    pub value: CallArgumentValue,
    pub source: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusiveAccess {
    Mutate,
    Take,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallArgumentValue {
    Value(ExpressionId),
    Exclusive {
        access: ExclusiveAccess,
        place: PlaceTarget,
    },
}

impl CallArgument {
    #[must_use]
    pub const fn access(&self) -> AccessMode {
        match self.value {
            CallArgumentValue::Value(_) => AccessMode::Value,
            CallArgumentValue::Exclusive {
                access: ExclusiveAccess::Mutate,
                ..
            } => AccessMode::Mutate,
            CallArgumentValue::Exclusive {
                access: ExclusiveAccess::Take,
                ..
            } => AccessMode::Take,
        }
    }

    #[must_use]
    pub const fn expression(&self) -> Option<ExpressionId> {
        match self.value {
            CallArgumentValue::Value(expression) => Some(expression),
            CallArgumentValue::Exclusive { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterpolationPart {
    Text {
        value: String,
        source: Span,
    },
    Value {
        expression: ExpressionId,
        format: Option<String>,
        /// Exact format-spec bytes, excluding `:` and `}`.
        format_source: Option<Span>,
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
    /// Scope into which this pattern's bindings are introduced. Match-arm
    /// patterns use the arm body root even when they bind nothing; `is` may
    /// use a synthetic child scope in its body. It is absent when no lexical
    /// success scope exists.
    pub binding_scope: Option<ScopeId>,
    pub alternatives: Vec<PatternAlternative>,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatternAlternative {
    pub kind: PrimaryPattern,
    pub source: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrimaryPattern {
    Wildcard,
    Literal {
        negative: bool,
        literal: Literal,
    },
    /// A qualified (`Enum.variant(...)`) or leading-dot (`.variant(...)`)
    /// variant pattern. `candidates` narrows same-spelling visible variants;
    /// exactly one must remain by the semantic boundary.
    Constructor {
        spelling: Name,
        candidates: Vec<ResolvedVariant>,
        arguments: Vec<PatternArgument>,
    },
    /// A bare identifier pattern. Always a fresh binding — bare identifiers
    /// no longer disambiguate against fieldless enum variants.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionBinding {
    pub id: RegionId,
    /// Root body in which the proof-only name first becomes visible.
    pub body: BodyId,
    pub name: Name,
    pub source: Span,
}

/// Complete immutable name-resolution output.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    /// Shared immutable graph from the exact workspace-load request. Keeping
    /// this behind `Arc` prevents an image-sized graph clone at the lowering
    /// seal boundary.
    pub packages: Arc<PackageGraph>,
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
    pub regions: Vec<RegionBinding>,
    /// Attributed candidates; semantic analysis proves exactly one selection
    /// for the requested image build.
    pub image_candidates: Vec<DeclarationId>,
    pub test_candidates: Vec<DeclarationId>,
}

/// Resource policy for independently validating an untrusted HIR model.
///
/// Lowering has its own request policy, but `Program` is public and may be
/// decoded or assembled by other producers. The model boundary therefore
/// enforces finite work and retained-error bounds itself instead of trusting a
/// particular producer to have done so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum records in any one dense arena.
    pub arena_records: u64,
    /// Maximum aggregate vector elements and recursively visited type/carrier
    /// nodes in the model.
    pub model_edges: u64,
    /// Maximum aggregate bytes held by source-facing names, literal spellings,
    /// messages, and interpolation text/format strings.
    pub payload_bytes: u64,
    /// Conservative upper bound for validation work, including sorting and
    /// bounded scope/declaration ancestry walks. This bounds CPU independently
    /// of retained model size.
    pub validation_work: u64,
    /// Maximum nested type-expression or projection-carrier depth.
    pub nesting: u32,
    /// Maximum number of validation errors retained in memory.
    pub errors: u32,
}

impl ValidationLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            arena_records: 64_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            validation_work: 1_100_000_000_000,
            nesting: 1024,
            errors: 100_000,
        }
    }

    fn is_valid(self) -> bool {
        self.arena_records > 0
            && self.arena_records <= u64::from(u32::MAX)
            && self.model_edges > 0
            && self.payload_bytes > 0
            && self.validation_work > 0
            && self.nesting > 0
            && self.nesting <= 1024
            && self.errors > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    InvalidLimits,
    Cancelled,
    ResourceLimit { resource: &'static str, limit: u64 },
    Invalid(ValidationErrors),
}

impl fmt::Display for ValidationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid HIR validation limits"),
            Self::Cancelled => formatter.write_str("HIR validation cancelled"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "HIR {resource} exceeds limit {limit}")
            }
            Self::Invalid(errors) => errors.fmt(formatter),
        }
    }
}

impl std::error::Error for ValidationFailure {}

struct ResourceMeter<'a> {
    limits: ValidationLimits,
    edges: u64,
    payload_bytes: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> ResourceMeter<'a> {
    fn new(limits: ValidationLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
            edges: 0,
            payload_bytes: 0,
            is_cancelled,
        }
    }

    fn poll(&self) -> Result<(), ValidationFailure> {
        if (self.is_cancelled)() {
            Err(ValidationFailure::Cancelled)
        } else {
            Ok(())
        }
    }

    fn arena(&mut self, resource: &'static str, length: usize) -> Result<(), ValidationFailure> {
        self.poll()?;
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource,
            limit: self.limits.arena_records,
        })?;
        if length > self.limits.arena_records {
            return Err(ValidationFailure::ResourceLimit {
                resource,
                limit: self.limits.arena_records,
            });
        }
        self.edges(length)
    }

    fn edges_usize(&mut self, length: usize) -> Result<(), ValidationFailure> {
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "model edges",
            limit: self.limits.model_edges,
        })?;
        self.edges(length)
    }

    fn edges(&mut self, amount: u64) -> Result<(), ValidationFailure> {
        self.poll()?;
        self.edges = self
            .edges
            .checked_add(amount)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            })?;
        if self.edges > self.limits.model_edges {
            return Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: self.limits.model_edges,
            });
        }
        Ok(())
    }

    fn payload(&mut self, length: usize) -> Result<(), ValidationFailure> {
        self.poll()?;
        let length = u64::try_from(length).map_err(|_| ValidationFailure::ResourceLimit {
            resource: "payload bytes",
            limit: self.limits.payload_bytes,
        })?;
        self.payload_bytes =
            self.payload_bytes
                .checked_add(length)
                .ok_or(ValidationFailure::ResourceLimit {
                    resource: "payload bytes",
                    limit: self.limits.payload_bytes,
                })?;
        if self.payload_bytes > self.limits.payload_bytes {
            return Err(ValidationFailure::ResourceLimit {
                resource: "payload bytes",
                limit: self.limits.payload_bytes,
            });
        }
        Ok(())
    }

    fn name(&mut self, name: &Name) -> Result<(), ValidationFailure> {
        self.payload(name.as_str().len())
    }

    fn depth(&self, depth: u32) -> Result<(), ValidationFailure> {
        if depth > self.limits.nesting {
            Err(ValidationFailure::ResourceLimit {
                resource: "model nesting",
                limit: u64::from(self.limits.nesting),
            })
        } else {
            Ok(())
        }
    }

    fn finish(&self) -> Result<(), ValidationFailure> {
        // Every retained edge is visited by a small fixed number of linear
        // passes. Fallible name-set sorting costs at most 32 comparisons per
        // edge because all arena/vector counts fit in `u32`. Provenance walks
        // are capped by `nesting`; the additional 64 covers the other passes
        // and leaves a deliberately conservative implementation margin.
        let multiplier = u64::from(self.limits.nesting).checked_add(64).ok_or(
            ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            },
        )?;
        let work = self
            .edges
            .checked_mul(multiplier)
            .ok_or(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })?;
        if work > self.limits.validation_work {
            Err(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: self.limits.validation_work,
            })
        } else {
            Ok(())
        }
    }
}

fn validate_program_resources(
    program: &Program,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ValidationFailure> {
    let mut meter = ResourceMeter::new(limits, is_cancelled);

    meter.arena("modules", program.modules.len())?;
    meter.arena("declarations", program.declarations.len())?;
    meter.arena("generic parameters", program.generic_parameters.len())?;
    meter.arena("parameters", program.parameters.len())?;
    meter.arena("bodies", program.bodies.len())?;
    meter.arena("scopes", program.scopes.len())?;
    meter.arena("locals", program.locals.len())?;
    meter.arena("statements", program.statements.len())?;
    meter.arena("expressions", program.expressions.len())?;
    meter.arena("patterns", program.patterns.len())?;
    meter.arena("regions", program.regions.len())?;
    validate_ancestry_depths(program, limits, is_cancelled)?;

    // The shared graph is already sealed by `wrela-package`, but it remains
    // retained input and must participate in this boundary's aggregate bound.
    meter.arena("package graph packages", program.packages.packages().len())?;
    meter.arena("package graph modules", program.packages.modules().len())?;
    for package in program.packages.packages() {
        meter.edges_usize(package.dependencies.len())?;
        meter.payload(package.identity.name.as_str().len())?;
        meter.payload(package.identity.version.as_str().len())?;
        for dependency in &package.dependencies {
            meter.payload(dependency.alias.as_str().len())?;
        }
    }
    for module in program.packages.modules() {
        meter.edges_usize(module.path.segments().len())?;
        for segment in module.path.segments() {
            meter.payload(segment.len())?;
        }
    }

    for module in &program.modules {
        meter.edges_usize(module.path.segments().len())?;
        meter.edges_usize(module.declarations.len())?;
        meter.edges_usize(module.reexports.len())?;
        for segment in module.path.segments() {
            meter.payload(segment.len())?;
        }
        for reexport in &module.reexports {
            meter.name(&reexport.local_name)?;
        }
    }
    for declaration in &program.declarations {
        if let Some(name) = &declaration.name {
            meter.name(name)?;
        }
        meter.edges_usize(declaration.attributes.len())?;
        for attribute in &declaration.attributes {
            meter_attribute(&mut meter, attribute)?;
        }
        meter_declaration(&mut meter, declaration)?;
    }
    for generic in &program.generic_parameters {
        meter.name(&generic.name)?;
        match &generic.kind {
            GenericParameterKind::Type { bound } => {
                if let Some(bound) = bound {
                    meter_type(&mut meter, bound, 1)?;
                }
            }
            GenericParameterKind::Constant { ty } => meter_type(&mut meter, ty, 1)?,
            GenericParameterKind::Region => {}
        }
    }
    for parameter in &program.parameters {
        if let Some(name) = &parameter.name {
            meter.name(name)?;
        }
        if let Some(ty) = &parameter.ty {
            meter_type(&mut meter, ty, 1)?;
        }
    }
    for body in &program.bodies {
        meter.edges_usize(body.locals.len())?;
        meter.edges_usize(body.statements.len())?;
    }
    for local in &program.locals {
        meter.name(&local.name)?;
        if let Some(ty) = &local.ty {
            meter_type(&mut meter, ty, 1)?;
        }
    }
    for statement in &program.statements {
        meter.edges_usize(statement.attributes.len())?;
        for attribute in &statement.attributes {
            meter_attribute(&mut meter, attribute)?;
        }
        meter_statement(&mut meter, &statement.kind)?;
    }
    for expression in &program.expressions {
        meter_expression(&mut meter, &expression.kind)?;
    }
    for pattern in &program.patterns {
        meter.edges_usize(pattern.alternatives.len())?;
        for alternative in &pattern.alternatives {
            meter_pattern(&mut meter, &alternative.kind)?;
        }
    }
    for region in &program.regions {
        meter.name(&region.name)?;
    }
    meter.edges_usize(program.image_candidates.len())?;
    meter.edges_usize(program.test_candidates.len())?;
    meter.poll()?;
    meter.finish()
}

fn validate_ancestry_depths(
    program: &Program,
    limits: ValidationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ValidationFailure> {
    let mut declaration_depths = Vec::new();
    declaration_depths
        .try_reserve_exact(program.declarations.len())
        .map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation ancestry scratch",
            limit: limits.validation_work,
        })?;
    for (index, declaration) in program.declarations.iter().enumerate() {
        if is_cancelled() {
            return Err(ValidationFailure::Cancelled);
        }
        let depth = match declaration.owner {
            DeclarationOwner::Module(_) => 1,
            DeclarationOwner::Declaration(parent) => usize::try_from(parent.0)
                .ok()
                .filter(|parent| *parent < index)
                .and_then(|parent| declaration_depths.get(parent).copied())
                .and_then(|depth: u32| depth.checked_add(1))
                .unwrap_or(u32::MAX),
        };
        if depth > limits.nesting {
            return Err(ValidationFailure::ResourceLimit {
                resource: "declaration ancestry depth",
                limit: u64::from(limits.nesting),
            });
        }
        declaration_depths.push(depth);
    }

    let mut scope_depths = Vec::new();
    scope_depths
        .try_reserve_exact(program.scopes.len())
        .map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation ancestry scratch",
            limit: limits.validation_work,
        })?;
    for (index, scope) in program.scopes.iter().enumerate() {
        if is_cancelled() {
            return Err(ValidationFailure::Cancelled);
        }
        let depth = scope.parent.map_or(1, |parent| {
            usize::try_from(parent.0)
                .ok()
                .filter(|parent| *parent < index)
                .and_then(|parent| scope_depths.get(parent).copied())
                .and_then(|depth: u32| depth.checked_add(1))
                .unwrap_or(u32::MAX)
        });
        if depth > limits.nesting {
            return Err(ValidationFailure::ResourceLimit {
                resource: "lexical scope depth",
                limit: u64::from(limits.nesting),
            });
        }
        scope_depths.push(depth);
    }

    let mut expression_depths = Vec::new();
    expression_depths
        .try_reserve_exact(program.expressions.len())
        .map_err(|_| ValidationFailure::ResourceLimit {
            resource: "validation ancestry scratch",
            limit: limits.validation_work,
        })?;
    for (index, expression) in program.expressions.iter().enumerate() {
        if is_cancelled() {
            return Err(ValidationFailure::Cancelled);
        }
        let depth = match expression.owner {
            ExpressionOwner::Closure(parent) => usize::try_from(parent.0)
                .ok()
                .filter(|parent| *parent < index)
                .and_then(|parent| expression_depths.get(parent).copied())
                .and_then(|depth: u32| depth.checked_add(1))
                .unwrap_or(u32::MAX),
            ExpressionOwner::Declaration(_) | ExpressionOwner::Body(_) => 1,
        };
        if depth > limits.nesting {
            return Err(ValidationFailure::ResourceLimit {
                resource: "expression ownership depth",
                limit: u64::from(limits.nesting),
            });
        }
        expression_depths.push(depth);
    }
    Ok(())
}

fn meter_attribute(
    meter: &mut ResourceMeter<'_>,
    attribute: &Attribute,
) -> Result<(), ValidationFailure> {
    meter.edges_usize(attribute.arguments.len())?;
    for argument in &attribute.arguments {
        if let Some(name) = &argument.name {
            meter.name(name)?;
        }
    }
    Ok(())
}

fn meter_declaration(
    meter: &mut ResourceMeter<'_>,
    declaration: &Declaration,
) -> Result<(), ValidationFailure> {
    match &declaration.kind {
        DeclarationKind::Constant(value) => {
            if let Some(ty) = &value.ty {
                meter_type(meter, ty, 1)?;
            }
        }
        DeclarationKind::Function(value) => {
            meter.edges_usize(value.generics.len())?;
            meter.edges_usize(value.parameters.len())?;
            if let Some(result) = &value.result {
                meter_type(meter, result, 1)?;
            }
        }
        DeclarationKind::Initializer(value) => {
            meter.edges_usize(value.parameters.len())?;
            if let Some(result) = &value.result {
                meter_type(meter, result, 1)?;
            }
        }
        DeclarationKind::Structure(value) => {
            meter.edges_usize(value.generics.len())?;
            meter.edges_usize(value.implements.len())?;
            meter.edges_usize(value.fields.len())?;
            meter.edges_usize(value.members.len())?;
            for implementation in &value.implements {
                meter_type(meter, implementation, 1)?;
            }
            for field in &value.fields {
                meter.name(&field.name)?;
                meter.edges_usize(field.attributes.len())?;
                for attribute in &field.attributes {
                    meter_attribute(meter, attribute)?;
                }
                meter_type(meter, &field.ty, 1)?;
            }
        }
        DeclarationKind::Enumeration(value) => {
            meter.edges_usize(value.generics.len())?;
            meter.edges_usize(value.variants.len())?;
            meter.edges_usize(value.members.len())?;
            for variant in &value.variants {
                meter.name(&variant.name)?;
                meter.edges_usize(variant.fields.len())?;
                for field in &variant.fields {
                    if let Some(name) = &field.name {
                        meter.name(name)?;
                    }
                    meter_type(meter, &field.ty, 1)?;
                }
            }
        }
        DeclarationKind::Interface(value) => {
            meter.edges_usize(value.generics.len())?;
            meter.edges_usize(value.requirements.len())?;
        }
        DeclarationKind::Implementation(value) => {
            meter_type(meter, &value.interface, 1)?;
            meter_type(meter, &value.implementing_type, 1)?;
            meter.edges_usize(value.members.len())?;
        }
        DeclarationKind::Projection(value) => {
            meter.edges_usize(value.generics.len())?;
            meter.edges_usize(value.parameters.len())?;
            meter.edges_usize(value.provenance.len())?;
            meter_carrier(meter, &value.carrier, 1)?;
        }
        DeclarationKind::Scope(value) => {
            meter.edges_usize(value.parameters.len())?;
            meter_type(meter, &value.result, 1)?;
        }
        DeclarationKind::ComptimeSelection(value) => {
            meter.edges_usize(value.then_declarations.len())?;
            meter.edges_usize(value.else_declarations.len())?;
        }
        DeclarationKind::Brand | DeclarationKind::Error => {}
    }
    Ok(())
}

fn meter_type(
    meter: &mut ResourceMeter<'_>,
    ty: &TypeExpression,
    depth: u32,
) -> Result<(), ValidationFailure> {
    meter.depth(depth)?;
    meter.edges(1)?;
    let next = depth
        .checked_add(1)
        .ok_or(ValidationFailure::ResourceLimit {
            resource: "model nesting",
            limit: u64::from(meter.limits.nesting),
        })?;
    match &ty.kind {
        TypeExpressionKind::Named { arguments, .. } => {
            meter.edges_usize(arguments.len())?;
            for argument in arguments {
                if let GenericArgumentKind::Type(ty) = &argument.kind {
                    meter_type(meter, ty, next)?;
                }
            }
        }
        TypeExpressionKind::SelfType { .. } | TypeExpressionKind::Error => {}
        TypeExpressionKind::Array { element, .. }
        | TypeExpressionKind::View {
            target: element, ..
        } => meter_type(meter, element, next)?,
        TypeExpressionKind::Tuple(values) => {
            meter.edges_usize(values.len())?;
            for value in values {
                meter_type(meter, value, next)?;
            }
        }
        TypeExpressionKind::Iso { brand, payload } => {
            meter_type(meter, brand, next)?;
            meter_type(meter, payload, next)?;
        }
        TypeExpressionKind::Function {
            parameters, result, ..
        } => {
            meter.edges_usize(parameters.len())?;
            for parameter in parameters {
                meter_type(meter, &parameter.ty, next)?;
            }
            meter_type(meter, result, next)?;
        }
    }
    Ok(())
}

fn meter_carrier(
    meter: &mut ResourceMeter<'_>,
    carrier: &ProjectionCarrier,
    depth: u32,
) -> Result<(), ValidationFailure> {
    meter.depth(depth)?;
    meter.edges(1)?;
    let next = depth
        .checked_add(1)
        .ok_or(ValidationFailure::ResourceLimit {
            resource: "model nesting",
            limit: u64::from(meter.limits.nesting),
        })?;
    match &carrier.kind {
        ProjectionCarrierKind::View { ty, .. } => meter_type(meter, ty, 1)?,
        ProjectionCarrierKind::Option(value) => meter_carrier(meter, value, next)?,
        ProjectionCarrierKind::Result { carrier, error } => {
            meter_carrier(meter, carrier, next)?;
            meter_type(meter, error, 1)?;
        }
        ProjectionCarrierKind::Error => {}
    }
    Ok(())
}

fn meter_statement(
    meter: &mut ResourceMeter<'_>,
    statement: &StatementKind,
) -> Result<(), ValidationFailure> {
    match statement {
        StatementKind::Assign { targets, .. } => {
            meter.edges_usize(targets.len())?;
            for target in targets {
                meter.edges_usize(target.projections.len())?;
                for projection in &target.projections {
                    if let PlaceProjection::Field(name) = projection {
                        meter.name(name)?;
                    }
                }
            }
        }
        StatementKind::Assert {
            expression,
            witness,
            message,
            ..
        } => {
            meter.payload(expression.len())?;
            meter.payload(witness.expression.len())?;
            if let Some(message) = message {
                meter.payload(message.len())?;
            }
        }
        StatementKind::If { branches, .. } => meter.edges_usize(branches.len())?,
        StatementKind::Match { arms, .. } => meter.edges_usize(arms.len())?,
        StatementKind::Initialize { .. }
        | StatementKind::Return(_)
        | StatementKind::Break
        | StatementKind::Continue
        | StatementKind::Pass
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
    Ok(())
}

fn meter_expression(
    meter: &mut ResourceMeter<'_>,
    expression: &ExpressionKind,
) -> Result<(), ValidationFailure> {
    match expression {
        ExpressionKind::Literal(literal) => meter_literal(meter, literal)?,
        ExpressionKind::Closure {
            parameters,
            captures,
            ..
        } => {
            meter.edges_usize(parameters.len())?;
            meter.edges_usize(captures.len())?;
        }
        ExpressionKind::Field { name, .. } => meter.name(name)?,
        ExpressionKind::Call { arguments, .. } => {
            meter.edges_usize(arguments.len())?;
            for argument in arguments {
                if let Some(name) = &argument.name {
                    meter.name(name)?;
                }
                if let CallArgumentValue::Exclusive { place, .. } = &argument.value {
                    meter.edges_usize(place.projections.len())?;
                    for projection in &place.projections {
                        if let PlaceProjection::Field(name) = projection {
                            meter.name(name)?;
                        }
                    }
                }
            }
        }
        ExpressionKind::Tuple(values) | ExpressionKind::Array(values) => {
            meter.edges_usize(values.len())?;
        }
        ExpressionKind::DotName {
            spelling,
            candidates,
        } => {
            meter.name(spelling)?;
            meter.edges_usize(candidates.len())?;
        }
        ExpressionKind::Interpolate(parts) => {
            meter.edges_usize(parts.len())?;
            for part in parts {
                match part {
                    InterpolationPart::Text { value, .. } => meter.payload(value.len())?,
                    InterpolationPart::Value { format, .. } => {
                        if let Some(format) = format {
                            meter.payload(format.len())?;
                        }
                    }
                }
            }
        }
        ExpressionKind::Cast { ty, .. } => meter_type(meter, ty, 1)?,
        ExpressionKind::Reference(_)
        | ExpressionKind::Unary { .. }
        | ExpressionKind::Binary { .. }
        | ExpressionKind::Compare { .. }
        | ExpressionKind::IsPattern { .. }
        | ExpressionKind::Range { .. }
        | ExpressionKind::Try(_)
        | ExpressionKind::Index { .. }
        | ExpressionKind::TrySend(_)
        | ExpressionKind::If { .. }
        | ExpressionKind::Error => {}
    }
    Ok(())
}

fn meter_pattern(
    meter: &mut ResourceMeter<'_>,
    pattern: &PrimaryPattern,
) -> Result<(), ValidationFailure> {
    match pattern {
        PrimaryPattern::Literal { literal, .. } => meter_literal(meter, literal)?,
        PrimaryPattern::Constructor {
            spelling,
            candidates,
            arguments,
        } => {
            meter.name(spelling)?;
            meter.edges_usize(candidates.len())?;
            meter.edges_usize(arguments.len())?;
        }
        PrimaryPattern::Tuple(arguments) | PrimaryPattern::Array(arguments) => {
            meter.edges_usize(arguments.len())?;
        }
        PrimaryPattern::Wildcard | PrimaryPattern::Bind(_) | PrimaryPattern::Error => {}
    }
    Ok(())
}

fn meter_literal(
    meter: &mut ResourceMeter<'_>,
    literal: &Literal,
) -> Result<(), ValidationFailure> {
    match literal {
        Literal::Integer(value) | Literal::Float(value) | Literal::String(value) => {
            meter.payload(value.len())
        }
        Literal::Bytes(value) => meter.payload(value.len()),
        Literal::Character(_) | Literal::Boolean(_) | Literal::Unit => Ok(()),
    }
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

    #[must_use]
    pub fn region(&self, id: RegionId) -> Option<&RegionBinding> {
        self.regions.get(id.0 as usize)
    }

    /// Seal all arenas and references before semantic analysis or HIR linting.
    pub fn validate(self) -> Result<ValidatedProgram, ValidationErrors> {
        match self.validate_with_limits(ValidationLimits::standard(), &|| false) {
            Ok(program) => Ok(program),
            Err(ValidationFailure::Invalid(errors)) => Err(errors),
            Err(ValidationFailure::InvalidLimits) => {
                Err(ValidationErrors(vec![ValidationError::InvalidLimits]))
            }
            Err(ValidationFailure::Cancelled) => {
                Err(ValidationErrors(vec![ValidationError::Cancelled]))
            }
            Err(ValidationFailure::ResourceLimit { resource, limit }) => {
                Err(ValidationErrors(vec![ValidationError::ResourceLimit {
                    resource,
                    limit,
                }]))
            }
        }
    }

    /// Validate an untrusted model under an explicit finite policy and
    /// deterministic cancellation hook.
    pub fn validate_with_limits(
        self,
        limits: ValidationLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedProgram, ValidationFailure> {
        if !limits.is_valid() {
            return Err(ValidationFailure::InvalidLimits);
        }
        validate_program_resources(&self, limits, is_cancelled)?;
        if is_cancelled() {
            return Err(ValidationFailure::Cancelled);
        }
        self.validate_core(limits.errors, is_cancelled)
    }

    fn validate_core(
        self,
        error_limit: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedProgram, ValidationFailure> {
        let mut errors = ValidationErrorSink::new(error_limit, is_cancelled);
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
        require_dense(
            "regions",
            self.regions.iter().map(|value| value.id.0),
            &mut errors,
        );

        if self.modules.len() != self.packages.modules().len() {
            errors.push(ValidationError::Coverage("package modules"));
        }
        for (module, graph_module) in self.modules.iter().zip(self.packages.modules()) {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if module.id != graph_module.id
                || module.package != graph_module.package
                || module.path != graph_module.path
                || module.source.file != graph_module.source
                || !valid_span(module.source)
                || !strict_ids(module.declarations.iter().map(|id| id.0), &mut errors)
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
                    || !span_contains(module.source, reexport.source)
                    || !valid_reexport_target(&self, &reexport.target)
                {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "module reexport",
                        id: module.id.0,
                        reason: "source or resolved target",
                    });
                }
            }
            if duplicate_names(
                module
                    .declarations
                    .len()
                    .saturating_add(module.reexports.len()),
                module
                    .declarations
                    .iter()
                    .filter_map(|id| self.declaration(*id))
                    .filter_map(|declaration| declaration.name.as_ref())
                    .map(Name::as_str)
                    .chain(
                        module
                            .reexports
                            .iter()
                            .map(|reexport| reexport.local_name.as_str()),
                    ),
                &mut errors,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "module",
                    id: module.id.0,
                    reason: "duplicate local name",
                });
            }
        }

        // Every declaration is owned by exactly one namespace edge. Merely
        // checking that a nested declaration names a parent is insufficient:
        // the same declaration could otherwise be listed in both comptime
        // branches (or in two containers) while still claiming that parent.
        let mut declaration_coverage = fallible_zeroed(self.declarations.len(), &mut errors);
        for module in &self.modules {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            for declaration in &module.declarations {
                increment_coverage(&mut declaration_coverage, declaration.0);
            }
        }
        for declaration in &self.declarations {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            for child in declaration_children(declaration) {
                increment_coverage(&mut declaration_coverage, child.0);
            }
            if let DeclarationKind::ComptimeSelection(selection) = &declaration.kind {
                for child in selection
                    .then_declarations
                    .iter()
                    .chain(&selection.else_declarations)
                {
                    increment_coverage(&mut declaration_coverage, child.0);
                }
            }
        }
        require_exact_coverage("declarations", &declaration_coverage, &mut errors);
        for declaration in &self.declarations {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            validate_declaration(&self, declaration, &mut errors);
            match declaration.owner {
                DeclarationOwner::Module(module) => {
                    if module != declaration.module
                        || declaration_coverage.get(declaration.id.0 as usize).copied() != Some(1)
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
                        || declaration_coverage.get(declaration.id.0 as usize).copied() != Some(1)
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
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            let valid_owner = self.declaration(generic.owner).is_some_and(|owner| {
                declaration_generics(owner)
                    .binary_search(&generic.id)
                    .is_ok()
                    && span_contains(owner.source, generic.source)
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
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            let implicit_scope_exit = is_scope_exit_parameter(&self, parameter.id);
            let valid_shape = if parameter.receiver {
                parameter.name.is_none() && parameter.ty.is_none() && !implicit_scope_exit
            } else if implicit_scope_exit {
                parameter.name.is_some() && parameter.ty.is_none()
            } else {
                parameter.name.is_some() && parameter.ty.is_some()
            };
            if !valid_shape {
                errors.push(ValidationError::InvalidRecord {
                    arena: "parameter",
                    id: parameter.id.0,
                    reason: "receiver/name shape",
                });
            }
            if let Some(name) = &parameter.name {
                validate_name(name, "parameter", &mut errors);
            }
            let (listed, expected_span, expression_owner) = match parameter.owner {
                CallableOwner::Declaration(owner) => {
                    self.declaration(owner)
                        .map_or((false, None, None), |declaration| {
                            (
                                declaration_parameters(declaration)
                                    .binary_search(&parameter.id)
                                    .is_ok(),
                                Some(declaration.source),
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
                            (
                                listed,
                                Some(expression.source),
                                Some(ExpressionOwner::Closure(owner)),
                            )
                        })
                }
            };
            if !listed
                || !valid_span(parameter.source)
                || expected_span.is_none_or(|owner| !span_contains(owner, parameter.source))
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "parameter",
                    id: parameter.id.0,
                    reason: "owner or source",
                });
            }
            if let (Some(expression_owner), Some(ty)) = (expression_owner, &parameter.ty) {
                validate_type(&self, ty, expression_owner, 0, &mut errors);
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

        let mut local_coverage = fallible_zeroed(self.locals.len(), &mut errors);
        let mut statement_coverage = fallible_zeroed(self.statements.len(), &mut errors);
        for body in &self.bodies {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if !valid_body_owner(&self, body.owner)
                || !valid_span(body.source)
                || body_owner_span(&self, body.owner)
                    .is_none_or(|owner| !span_contains(owner, body.source))
                || !strict_ids(body.locals.iter().map(|id| id.0), &mut errors)
                || !strict_ids(body.statements.iter().map(|id| id.0), &mut errors)
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
                if errors.poll() {
                    return Err(ValidationFailure::Cancelled);
                }
                increment_coverage(&mut local_coverage, local.0);
                if self.local(*local).is_none_or(|value| value.body != body.id) {
                    errors.push(invalid_reference("body local", local.0));
                }
            }
            for statement in &body.statements {
                if errors.poll() {
                    return Err(ValidationFailure::Cancelled);
                }
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
        let mut body_coverage = fallible_zeroed(self.bodies.len(), &mut errors);
        for declaration in &self.declarations {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            match &declaration.kind {
                DeclarationKind::Function(value) => {
                    if let Some(body) = value.body {
                        increment_coverage(&mut body_coverage, body.0);
                    }
                }
                DeclarationKind::Initializer(value) => {
                    increment_coverage(&mut body_coverage, value.body.0);
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
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let ExpressionKind::Closure {
                body: ClosureBody::Body(body),
                ..
            } = &expression.kind
            {
                increment_coverage(&mut body_coverage, body.0);
            }
        }
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            for_each_statement_body(&statement.kind, |body| {
                increment_coverage(&mut body_coverage, body.0);
            });
        }
        require_exact_coverage("bodies", &body_coverage, &mut errors);
        let mut scope_coverage = fallible_zeroed(self.scopes.len(), &mut errors);
        for body in &self.bodies {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            increment_coverage(&mut scope_coverage, body.scope.0);
        }
        let mut invalid_scope_coverage = false;
        for scope in &self.scopes {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            let coverage = scope_coverage
                .get(scope.id.0 as usize)
                .copied()
                .unwrap_or(0);
            invalid_scope_coverage |= coverage > 1 || (coverage == 0 && scope.parent.is_none());
        }
        if invalid_scope_coverage {
            errors.push(ValidationError::Coverage("body and synthetic scopes"));
        }

        let mut expression_coverage = fallible_zeroed(self.expressions.len(), &mut errors);
        for declaration in &self.declarations {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            collect_declaration_expressions(declaration, &mut expression_coverage);
        }
        for generic in &self.generic_parameters {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
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
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let Some(ty) = &parameter.ty {
                collect_type_expressions(ty, &mut expression_coverage, 0);
            }
        }
        for local in &self.locals {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let Some(ty) = &local.ty {
                collect_type_expressions(ty, &mut expression_coverage, 0);
            }
        }
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            collect_statement_expressions(&statement.kind, &mut expression_coverage);
            for attribute in &statement.attributes {
                collect_attribute_expressions(attribute, &mut expression_coverage);
            }
        }
        for expression in &self.expressions {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            collect_expression_children(&expression.kind, &mut expression_coverage);
        }
        require_exact_coverage("expressions", &expression_coverage, &mut errors);

        let mut pattern_coverage = fallible_zeroed(self.patterns.len(), &mut errors);
        // Every binding in an alternative belongs to the one lexical binding
        // set introduced by the top-level pattern.  Keep that root explicit
        // while validating: a local has one canonical source occurrence, so a
        // second, disjoint alternative cannot require that source span to be
        // contained by its own nested pattern node.
        let mut pattern_roots = Vec::new();
        if pattern_roots
            .try_reserve_exact(self.patterns.len())
            .is_err()
        {
            errors.allocation_failed = true;
        } else {
            pattern_roots.resize(self.patterns.len(), None::<PatternId>);
        }
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let StatementKind::Match { arms, .. } = &statement.kind {
                for arm in arms {
                    increment_coverage(&mut pattern_coverage, arm.pattern.0);
                    set_pattern_root(&mut pattern_roots, arm.pattern, arm.pattern);
                }
            }
        }
        for expression in &self.expressions {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let ExpressionKind::IsPattern { pattern, .. } = &expression.kind {
                increment_coverage(&mut pattern_coverage, pattern.0);
                set_pattern_root(&mut pattern_roots, *pattern, *pattern);
            }
        }
        for pattern in &self.patterns {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            let root = pattern_roots
                .get(pattern.id.0 as usize)
                .copied()
                .flatten()
                .unwrap_or(pattern.id);
            for alternative in &pattern.alternatives {
                if errors.poll() {
                    return Err(ValidationFailure::Cancelled);
                }
                let arguments = match &alternative.kind {
                    PrimaryPattern::Constructor { arguments, .. }
                    | PrimaryPattern::Tuple(arguments)
                    | PrimaryPattern::Array(arguments) => arguments.as_slice(),
                    _ => &[],
                };
                for argument in arguments {
                    if errors.poll() {
                        return Err(ValidationFailure::Cancelled);
                    }
                    increment_coverage(&mut pattern_coverage, argument.pattern.0);
                    set_pattern_root(&mut pattern_roots, argument.pattern, root);
                }
            }
        }
        require_exact_coverage("patterns", &pattern_coverage, &mut errors);

        for scope in &self.scopes {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if !valid_span(scope.source)
                || self
                    .body(scope.body)
                    .is_none_or(|body| !span_contains(body.source, scope.source))
                || scope.parent.is_some_and(|parent| {
                    parent.0 >= scope.id.0
                        || self.scope(parent).is_none_or(|parent_scope| {
                            !same_body_owner(&self, parent_scope.body, scope.body)
                        })
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
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            validate_name(&local.name, "local", &mut errors);
            if !valid_span(local.source)
                || self
                    .body(local.body)
                    .is_none_or(|body| !span_contains(body.source, local.source))
                || self
                    .scope(local.scope)
                    .is_none_or(|scope| scope.body != local.body)
                || local.shadowed.is_some_and(|shadowed| {
                    shadowed.0 >= local.id.0
                        || self.local(shadowed).is_none_or(|shadowed_local| {
                            shadowed_local.name != local.name
                                || !same_body_owner(&self, shadowed_local.body, local.body)
                                || !scope_is_ancestor_or_same(
                                    &self,
                                    shadowed_local.scope,
                                    local.scope,
                                )
                                || shadowed_local.source.file != local.source.file
                                || shadowed_local.source.range.start >= local.source.range.start
                        })
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
        validate_local_shadowing(&self, &mut errors);
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            validate_statement(&self, statement, &mut errors);
        }
        for expression in &self.expressions {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            validate_expression(&self, expression, &mut errors);
        }
        for pattern in &self.patterns {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            let binding_root = pattern_roots
                .get(pattern.id.0 as usize)
                .copied()
                .flatten()
                .and_then(|root| self.pattern(root))
                .unwrap_or(pattern);
            validate_pattern(&self, pattern, binding_root, &mut errors);
        }
        let mut local_binding_coverage = fallible_zeroed(self.locals.len(), &mut errors);
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            match &statement.kind {
                StatementKind::Initialize { local, .. } => {
                    increment_coverage(&mut local_binding_coverage, local.0);
                }
                StatementKind::For { binding, .. } => {
                    increment_coverage(&mut local_binding_coverage, binding.0);
                }
                StatementKind::With {
                    binding: Some(binding),
                    ..
                } => {
                    increment_coverage(&mut local_binding_coverage, binding.0);
                }
                _ => {}
            }
        }
        for pattern in &self.patterns {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            for alternative in &pattern.alternatives {
                if errors.poll() {
                    return Err(ValidationFailure::Cancelled);
                }
                if let PrimaryPattern::Bind(binding) = &alternative.kind {
                    increment_coverage(&mut local_binding_coverage, binding.0);
                }
            }
        }
        let mut missing_local_binding = false;
        for count in &local_binding_coverage {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            missing_local_binding |= *count == 0;
        }
        if missing_local_binding {
            errors.push(ValidationError::Coverage("local bindings"));
        }
        let mut region_coverage = fallible_zeroed(self.regions.len(), &mut errors);
        for statement in &self.statements {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if let StatementKind::With {
                region: Some(region),
                ..
            } = &statement.kind
            {
                increment_coverage(&mut region_coverage, region.0);
            }
        }
        require_exact_coverage("with regions", &region_coverage, &mut errors);
        for region in &self.regions {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            validate_name(&region.name, "local region", &mut errors);
            if !valid_span(region.source)
                || self
                    .body(region.body)
                    .is_none_or(|body| body.source.file != region.source.file)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "region",
                    id: region.id.0,
                    reason: "body, name, or source",
                });
            }
        }
        for candidate in &self.image_candidates {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if self
                .declaration(*candidate)
                .is_none_or(|declaration| !valid_image_candidate(declaration))
            {
                errors.push(invalid_reference("image candidate", candidate.0));
            }
        }
        for candidate in &self.test_candidates {
            if errors.poll() {
                return Err(ValidationFailure::Cancelled);
            }
            if self
                .declaration(*candidate)
                .is_none_or(|declaration| !valid_test_candidate(declaration))
            {
                errors.push(invalid_reference("entry candidate", candidate.0));
            }
        }
        if !strict_ids(self.image_candidates.iter().map(|id| id.0), &mut errors)
            || !strict_ids(self.test_candidates.iter().map(|id| id.0), &mut errors)
        {
            errors.push(ValidationError::NonCanonical("entry candidates"));
        }
        validate_entry_candidate_coverage(&self, &mut errors);

        if errors.poll() {
            return Err(ValidationFailure::Cancelled);
        }
        let errors = errors
            .finish()
            .map_err(|()| ValidationFailure::ResourceLimit {
                resource: "validation error storage",
                limit: u64::from(error_limit),
            })?;
        if errors.is_empty() {
            Ok(ValidatedProgram(self))
        } else {
            Err(ValidationFailure::Invalid(ValidationErrors(errors)))
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

    #[must_use]
    pub fn resolved_variant(&self, resolved: &ResolvedVariant) -> Option<&EnumVariant> {
        let declaration = self.resolved_declaration(&resolved.enumeration)?;
        let DeclarationKind::Enumeration(enumeration) = &declaration.kind else {
            return None;
        };
        enumeration.variants.get(resolved.variant as usize)
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
            self.0.declaration(**id).is_some_and(|declaration| {
                declaration
                    .name
                    .as_ref()
                    .is_some_and(|candidate| candidate.as_str() == name)
            })
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
    TooManyErrors {
        limit: u32,
    },
    InvalidLimits,
    Cancelled,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
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

struct ValidationErrorSink<'a> {
    errors: Vec<ValidationError>,
    limit: u32,
    truncated: bool,
    allocation_failed: bool,
    is_cancelled: &'a dyn Fn() -> bool,
    cancelled: bool,
}

impl<'a> ValidationErrorSink<'a> {
    fn new(limit: u32, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            errors: Vec::new(),
            limit,
            truncated: false,
            allocation_failed: false,
            is_cancelled,
            cancelled: false,
        }
    }

    fn poll(&mut self) -> bool {
        if !self.cancelled && (self.is_cancelled)() {
            self.cancelled = true;
        }
        self.cancelled
    }

    fn push(&mut self, error: ValidationError) {
        if self.poll() {
            return;
        }
        if self.errors.len() >= self.limit as usize {
            self.truncated = true;
            return;
        }
        if self.errors.try_reserve(1).is_err() {
            self.allocation_failed = true;
            return;
        }
        self.errors.push(error);
    }

    fn finish(mut self) -> Result<Vec<ValidationError>, ()> {
        if self.allocation_failed {
            return Err(());
        }
        if self.truncated {
            let marker = ValidationError::TooManyErrors { limit: self.limit };
            if let Some(last) = self.errors.last_mut() {
                *last = marker;
            } else if self.errors.try_reserve(1).is_ok() {
                self.errors.push(marker);
            } else {
                return Err(());
            }
        }
        Ok(self.errors)
    }
}

fn require_dense(
    name: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationErrorSink,
) {
    for (index, id) in ids.into_iter().enumerate() {
        if errors.poll() {
            return;
        }
        if u32::try_from(index).ok() != Some(id) {
            errors.push(ValidationError::NonDense(name));
            return;
        }
    }
}

fn strict_ids(ids: impl IntoIterator<Item = u32>, errors: &mut ValidationErrorSink) -> bool {
    let mut previous = None;
    for id in ids {
        if errors.poll() {
            return false;
        }
        let valid = previous.is_none_or(|previous| previous < id);
        if !valid {
            return false;
        }
        previous = Some(id);
    }
    true
}

fn increment_coverage(coverage: &mut [u8], id: u32) {
    if let Some(count) = coverage.get_mut(id as usize) {
        *count = count.saturating_add(1);
    }
}

fn set_pattern_root(roots: &mut [Option<PatternId>], pattern: PatternId, root: PatternId) {
    if let Some(slot) = roots.get_mut(pattern.0 as usize)
        && slot.is_none()
    {
        *slot = Some(root);
    }
}

fn require_exact_coverage(name: &'static str, coverage: &[u8], errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
    if coverage.iter().any(|count| *count != 1) {
        errors.push(ValidationError::Coverage(name));
    }
}

fn require_owner_coverage(
    name: &'static str,
    count: usize,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut ValidationErrorSink,
) {
    let mut coverage = fallible_zeroed(count, errors);
    for id in ids {
        increment_coverage(&mut coverage, id);
    }
    require_exact_coverage(name, &coverage, errors);
}

fn fallible_zeroed(length: usize, errors: &mut ValidationErrorSink) -> Vec<u8> {
    let mut values = Vec::new();
    if values.try_reserve_exact(length).is_err() {
        errors.allocation_failed = true;
        return values;
    }
    values.resize(length, 0);
    values
}

fn duplicate_names<'a>(
    capacity: usize,
    names: impl IntoIterator<Item = &'a str>,
    errors: &mut ValidationErrorSink,
) -> bool {
    if errors.poll() {
        return false;
    }
    let mut values = Vec::new();
    if values.try_reserve_exact(capacity).is_err() {
        errors.allocation_failed = true;
        return false;
    }
    values.extend(names);
    values.sort_unstable();
    values.windows(2).any(|pair| pair[0] == pair[1])
}

fn invalid_reference(kind: &'static str, id: u32) -> ValidationError {
    ValidationError::InvalidReference { kind, id }
}

fn valid_span(span: Span) -> bool {
    span.range.start <= span.range.end
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file
        && outer.range.start <= inner.range.start
        && inner.range.end <= outer.range.end
}

fn validate_name(name: &Name, kind: &'static str, errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
    if !name.is_valid() {
        errors.push(ValidationError::InvalidName { kind });
    }
}

fn validate_argument_name(name: &Name, errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
    if !name.is_valid_argument_label() {
        errors.push(ValidationError::InvalidName {
            kind: "call argument",
        });
    }
}

fn validate_member_name(name: &Name, kind: &'static str, errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
    if !name.is_valid_member() {
        errors.push(ValidationError::InvalidName { kind });
    }
}

fn declaration_generics(declaration: &Declaration) -> &[GenericParameterId] {
    match &declaration.kind {
        DeclarationKind::Function(value) => &value.generics,
        DeclarationKind::Structure(value) => &value.generics,
        DeclarationKind::Enumeration(value) => &value.generics,
        DeclarationKind::Interface(value) => &value.generics,
        DeclarationKind::Projection(value) => &value.generics,
        _ => &[],
    }
}

fn declaration_parameters(declaration: &Declaration) -> &[ParameterId] {
    match &declaration.kind {
        DeclarationKind::Function(value) => &value.parameters,
        DeclarationKind::Initializer(value) => &value.parameters,
        DeclarationKind::Projection(value) => &value.parameters,
        DeclarationKind::Scope(value) => &value.parameters,
        _ => &[],
    }
}

fn is_scope_exit_parameter(program: &Program, parameter: ParameterId) -> bool {
    program.parameter(parameter).is_some_and(|record| {
        let CallableOwner::Declaration(owner) = record.owner else {
            return false;
        };
        matches!(
            program.declaration(owner).map(|declaration| &declaration.kind),
            Some(DeclarationKind::Scope(scope)) if scope.exit_parameter == parameter
        )
    })
}

fn declaration_children(declaration: &Declaration) -> &[DeclarationId] {
    match &declaration.kind {
        DeclarationKind::Structure(value) => &value.members,
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

fn valid_reexport_target(program: &Program, target: &ReexportTarget) -> bool {
    let declaration_is_public = |resolved: &ResolvedDeclaration| {
        valid_resolved_declaration(program, resolved)
            && program
                .declaration(resolved.declaration)
                .is_some_and(|declaration| {
                    matches!(
                        declaration.visibility,
                        Visibility::Public | Visibility::Reexported
                    )
                })
    };
    match target {
        ReexportTarget::Declaration(resolved) => declaration_is_public(resolved),
        ReexportTarget::Variant(resolved) => {
            declaration_is_public(&resolved.enumeration)
                && resolved_variant(program, resolved).is_some()
        }
        ReexportTarget::Module { package, module } => program
            .modules
            .get(module.0 as usize)
            .is_some_and(|record| record.package == *package),
    }
}

fn resolved_variant<'a>(
    program: &'a Program,
    resolved: &ResolvedVariant,
) -> Option<&'a EnumVariant> {
    let declaration = program.declaration(resolved.enumeration.declaration)?;
    if declaration.module != resolved.enumeration.module
        || program
            .modules
            .get(resolved.enumeration.module.0 as usize)
            .is_none_or(|module| module.package != resolved.enumeration.package)
    {
        return None;
    }
    let DeclarationKind::Enumeration(enumeration) = &declaration.kind else {
        return None;
    };
    enumeration.variants.get(resolved.variant as usize)
}

fn expression_owner_declaration(
    program: &Program,
    mut owner: ExpressionOwner,
) -> Option<DeclarationId> {
    // Malformed closure/body ownership may form a cycle before sealing. Keep
    // this provenance walk locally bounded even though valid HIR is acyclic.
    for _ in 0..=program
        .bodies
        .len()
        .saturating_add(program.expressions.len())
    {
        match owner {
            ExpressionOwner::Declaration(declaration) => return Some(declaration),
            ExpressionOwner::Closure(closure) => owner = program.expression(closure)?.owner,
            ExpressionOwner::Body(body) => match program.body(body)?.owner {
                BodyOwner::Declaration(declaration) => return Some(declaration),
                BodyOwner::Closure(closure) => owner = program.expression(closure)?.owner,
            },
        }
    }
    None
}

fn generic_visible_from(
    program: &Program,
    generic: GenericParameterId,
    owner: ExpressionOwner,
) -> bool {
    let Some(generic) = program.generic_parameter(generic) else {
        return false;
    };
    let Some(mut declaration) = expression_owner_declaration(program, owner) else {
        return false;
    };
    for _ in 0..=program.declarations.len() {
        if declaration == generic.owner {
            return true;
        }
        let Some(DeclarationOwner::Declaration(parent)) =
            program.declaration(declaration).map(|value| value.owner)
        else {
            return false;
        };
        declaration = parent;
    }
    false
}

fn valid_type_definition(
    program: &Program,
    definition: &Definition,
    owner: ExpressionOwner,
) -> bool {
    match definition {
        Definition::Declaration(resolved) => {
            program
                .declaration(resolved.declaration)
                .is_some_and(|declaration| {
                    valid_resolved_declaration(program, resolved)
                        && matches!(
                            &declaration.kind,
                            DeclarationKind::Brand
                                | DeclarationKind::Structure(_)
                                | DeclarationKind::Enumeration(_)
                                | DeclarationKind::Interface(_)
                        )
                })
        }
        Definition::Generic(id) => {
            generic_visible_from(program, *id, owner)
                && program.generic_parameter(*id).is_some_and(|generic| {
                    matches!(&generic.kind, GenericParameterKind::Type { .. })
                })
        }
        Definition::Builtin(_) => true,
        Definition::Variant(_)
        | Definition::Parameter(_)
        | Definition::Local(_)
        | Definition::Module { .. } => false,
    }
}

fn nearest_self_type_owner(
    program: &Program,
    expression_owner: ExpressionOwner,
) -> Option<DeclarationId> {
    let mut declaration = expression_owner_declaration(program, expression_owner)?;
    for _ in 0..=program.declarations.len() {
        let record = program.declaration(declaration)?;
        if matches!(
            record.kind,
            DeclarationKind::Structure(_)
                | DeclarationKind::Enumeration(_)
                | DeclarationKind::Interface(_)
                | DeclarationKind::Implementation(_)
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

fn generic_argument_matches_parameter(
    argument: &GenericArgumentKind,
    parameter: &GenericParameterKind,
) -> bool {
    matches!(argument, GenericArgumentKind::Error)
        || matches!(
            (argument, parameter),
            (
                GenericArgumentKind::Type(_),
                GenericParameterKind::Type { .. }
            ) | (
                GenericArgumentKind::Constant(_),
                GenericParameterKind::Constant { .. }
            ) | (GenericArgumentKind::Region(_), GenericParameterKind::Region)
        )
}

fn generic_arguments_match_definition(
    program: &Program,
    definition: &Definition,
    arguments: &[GenericArgument],
) -> bool {
    match definition {
        Definition::Declaration(resolved) => {
            let Some(declaration) = program.declaration(resolved.declaration) else {
                return false;
            };
            let parameters = declaration_generics(declaration);
            parameters.len() == arguments.len()
                && parameters
                    .iter()
                    .zip(arguments)
                    .all(|(parameter, argument)| {
                        program
                            .generic_parameter(*parameter)
                            .is_some_and(|parameter| {
                                generic_argument_matches_parameter(&argument.kind, &parameter.kind)
                            })
                    })
        }
        Definition::Generic(_) => arguments.is_empty(),
        Definition::Builtin(builtin) => arguments.iter().all(|argument| {
            !matches!(&argument.kind, GenericArgumentKind::BoundedCapacity(_))
                || matches!(builtin, Builtin::Bytes | Builtin::String)
        }),
        Definition::Variant(_)
        | Definition::Parameter(_)
        | Definition::Local(_)
        | Definition::Module { .. } => false,
    }
}

fn same_body_owner(program: &Program, left: BodyId, right: BodyId) -> bool {
    program
        .body(left)
        .zip(program.body(right))
        .is_some_and(|(left, right)| left.owner == right.owner)
}

fn scope_is_strict_ancestor(program: &Program, ancestor: ScopeId, descendant: ScopeId) -> bool {
    let mut current = descendant;
    for _ in 0..program.scopes.len() {
        let Some(parent) = program.scope(current).and_then(|scope| scope.parent) else {
            return false;
        };
        if parent == ancestor {
            return true;
        }
        current = parent;
    }
    false
}

fn scope_is_ancestor_or_same(program: &Program, ancestor: ScopeId, descendant: ScopeId) -> bool {
    ancestor == descendant || scope_is_strict_ancestor(program, ancestor, descendant)
}

fn expression_scope(program: &Program, expression: &Expression) -> Option<ScopeId> {
    let mut owner = expression.owner;
    for _ in 0..=program.expressions.len() {
        match owner {
            ExpressionOwner::Declaration(_) => return None,
            ExpressionOwner::Body(body) => {
                let scope = expression.scope?;
                return program
                    .scope(scope)
                    .is_some_and(|record| record.body == body)
                    .then_some(scope);
            }
            ExpressionOwner::Closure(closure) => owner = program.expression(closure)?.owner,
        }
    }
    None
}

fn valid_expression_scope_shape(program: &Program, expression: &Expression) -> bool {
    match expression.owner {
        ExpressionOwner::Declaration(_) | ExpressionOwner::Closure(_) => expression.scope.is_none(),
        ExpressionOwner::Body(body) => expression.scope.is_some_and(|scope| {
            program
                .scope(scope)
                .is_some_and(|record| record.body == body)
        }),
    }
}

fn local_visible_at(
    program: &Program,
    local: LocalId,
    scope: Option<ScopeId>,
    source: Span,
) -> bool {
    let Some(scope) = scope else {
        return false;
    };
    program.local(local).is_some_and(|local| {
        local.source.file == source.file
            && local.source.range.start <= source.range.start
            && scope_is_ancestor_or_same(program, local.scope, scope)
    })
}

fn parameter_visible_from(
    program: &Program,
    parameter: ParameterId,
    expression_owner: ExpressionOwner,
) -> bool {
    let Some(parameter) = program.parameter(parameter) else {
        return false;
    };
    match parameter.owner {
        CallableOwner::Declaration(owner) => {
            expression_owner_declaration(program, expression_owner)
                .is_some_and(|current| current == owner)
        }
        CallableOwner::Closure(closure) => {
            let mut owner = expression_owner;
            for _ in 0..=program
                .bodies
                .len()
                .saturating_add(program.expressions.len())
            {
                match owner {
                    ExpressionOwner::Closure(candidate) if candidate == closure => return true,
                    ExpressionOwner::Closure(candidate) => {
                        let Some(expression) = program.expression(candidate) else {
                            return false;
                        };
                        owner = expression.owner;
                    }
                    ExpressionOwner::Declaration(_) => return false,
                    ExpressionOwner::Body(body) => {
                        match program.body(body).map(|body| body.owner) {
                            Some(BodyOwner::Closure(candidate)) if candidate == closure => {
                                return true;
                            }
                            Some(BodyOwner::Closure(candidate)) => {
                                let Some(expression) = program.expression(candidate) else {
                                    return false;
                                };
                                owner = expression.owner;
                            }
                            Some(BodyOwner::Declaration(_)) | None => return false,
                        }
                    }
                }
            }
            false
        }
    }
}

fn declaration_visible_from(
    program: &Program,
    resolved: &ResolvedDeclaration,
    expression_owner: ExpressionOwner,
) -> bool {
    let Some(target) = program.declaration(resolved.declaration) else {
        return false;
    };
    if !valid_resolved_declaration(program, resolved) {
        return false;
    }
    if matches!(
        target.visibility,
        Visibility::Public | Visibility::Reexported
    ) {
        return true;
    }
    expression_owner_declaration(program, expression_owner)
        .and_then(|owner| program.declaration(owner))
        .is_some_and(|owner| owner.module == target.module)
}

fn definition_visible_at(
    program: &Program,
    definition: &Definition,
    expression_owner: ExpressionOwner,
    scope: Option<ScopeId>,
    source: Span,
) -> bool {
    match definition {
        Definition::Declaration(resolved) => {
            declaration_visible_from(program, resolved, expression_owner)
        }
        Definition::Variant(resolved) => {
            resolved_variant(program, resolved).is_some()
                && declaration_visible_from(program, &resolved.enumeration, expression_owner)
        }
        Definition::Parameter(parameter) => {
            parameter_visible_from(program, *parameter, expression_owner)
        }
        Definition::Local(local) => local_visible_at(program, *local, scope, source),
        Definition::Generic(generic) => generic_visible_from(program, *generic, expression_owner),
        Definition::Builtin(_) => true,
        Definition::Module { package, module } => program
            .modules
            .get(module.0 as usize)
            .is_some_and(|record| record.package == *package),
    }
}

fn declaration_allows_receiver(program: &Program, declaration: &Declaration) -> bool {
    let DeclarationOwner::Declaration(parent) = declaration.owner else {
        return false;
    };
    program.declaration(parent).is_some_and(|parent| {
        matches!(
            &parent.kind,
            DeclarationKind::Structure(_)
                | DeclarationKind::Enumeration(_)
                | DeclarationKind::Interface(_)
                | DeclarationKind::Implementation(_)
        )
    })
}

fn validate_local_shadowing(program: &Program, errors: &mut ValidationErrorSink) {
    let mut locals = Vec::new();
    if locals.try_reserve_exact(program.locals.len()).is_err() {
        errors.allocation_failed = true;
        return;
    }
    locals.extend(&program.locals);
    locals.sort_unstable_by(|left, right| {
        (left.name.as_str(), left.id).cmp(&(right.name.as_str(), right.id))
    });

    let mut latest_by_scope = Vec::new();
    if latest_by_scope
        .try_reserve_exact(program.scopes.len())
        .is_err()
    {
        errors.allocation_failed = true;
        return;
    }
    latest_by_scope.resize(program.scopes.len(), None::<&Local>);
    let mut touched = Vec::new();
    if touched.try_reserve_exact(program.locals.len()).is_err() {
        errors.allocation_failed = true;
        return;
    }

    let mut start = 0;
    while start < locals.len() {
        if errors.poll() {
            return;
        }
        let name = &locals[start].name;
        let mut end = start + 1;
        while end < locals.len() && locals[end].name == *name {
            end += 1;
        }
        for local in &locals[start..end] {
            if errors.poll() {
                return;
            }
            let mut expected = None;
            let mut scope = Some(local.scope);
            while let Some(current) = scope {
                if errors.poll() {
                    return;
                }
                if let Some(candidate) = latest_by_scope
                    .get(current.0 as usize)
                    .and_then(|candidate| *candidate)
                    && expected.is_none_or(|existing: &Local| existing.id < candidate.id)
                {
                    expected = Some(candidate);
                }
                scope = program.scope(current).and_then(|scope| scope.parent);
            }
            if local.shadowed != expected.map(|local| local.id) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "local",
                    id: local.id.0,
                    reason: "noncanonical shadow link",
                });
            }
            let index = local.scope.0 as usize;
            if let Some(slot) = latest_by_scope.get_mut(index) {
                if slot.is_none() {
                    touched.push(index);
                }
                *slot = Some(local);
            }
        }
        for index in touched.drain(..) {
            latest_by_scope[index] = None;
        }
        start = end;
    }
}

fn validate_entry_candidate_coverage(program: &Program, errors: &mut ValidationErrorSink) {
    let mut image_candidates = program.image_candidates.iter().copied();
    let mut test_candidates = program.test_candidates.iter().copied();
    let mut image_matches = true;
    let mut test_matches = true;

    for declaration in &program.declarations {
        let image_count = declaration
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.identity == AttributeIdentity::Builtin(BuiltinAttribute::Image)
            })
            .count();
        let test_count = declaration
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.identity == AttributeIdentity::Builtin(BuiltinAttribute::Test)
            })
            .count();
        let malformed_entry_attribute = declaration.attributes.iter().any(|attribute| {
            match attribute.identity {
                AttributeIdentity::Builtin(BuiltinAttribute::Image) => {
                    !attribute.arguments.is_empty()
                }
                // Lowering admits only bare `@test` or `@test(runtime)`; a
                // single retained argument is therefore the runtime force.
                AttributeIdentity::Builtin(BuiltinAttribute::Test) => attribute.arguments.len() > 1,
                _ => false,
            }
        });
        if image_count > 1 || test_count > 1 {
            errors.push(ValidationError::InvalidRecord {
                arena: "declaration attribute",
                id: declaration.id.0,
                reason: "duplicate entry attribute",
            });
        }
        if malformed_entry_attribute || (image_count == 1 && test_count == 1) {
            errors.push(ValidationError::InvalidRecord {
                arena: "declaration attribute",
                id: declaration.id.0,
                reason: "entry attribute arguments or conflict",
            });
        }
        if image_count == 1 && image_candidates.next() != Some(declaration.id) {
            image_matches = false;
        }
        if test_count == 1 && test_candidates.next() != Some(declaration.id) {
            test_matches = false;
        }
    }
    if image_candidates.next().is_some() {
        image_matches = false;
    }
    if test_candidates.next().is_some() {
        test_matches = false;
    }
    if !image_matches {
        errors.push(ValidationError::Coverage("image candidates"));
    }
    if !test_matches {
        errors.push(ValidationError::Coverage("test candidates"));
    }
}

fn valid_image_candidate(declaration: &Declaration) -> bool {
    matches!(
        declaration.visibility,
        Visibility::Public | Visibility::Reexported
    ) && matches!(
        &declaration.kind,
        DeclarationKind::Function(function)
            if function.color == FunctionColor::Sync
                && function.generics.is_empty()
                && function.parameters.is_empty()
    )
}

fn valid_test_candidate(declaration: &Declaration) -> bool {
    matches!(
        &declaration.kind,
        DeclarationKind::Function(function)
            if function.color != FunctionColor::Isr
                && function.generics.is_empty()
                && function.parameters.is_empty()
    )
}

fn region_visible_from(program: &Program, region: RegionId, owner: ExpressionOwner) -> bool {
    let Some(binding) = program.region(region) else {
        return false;
    };
    let body = match owner {
        ExpressionOwner::Body(body) => body,
        ExpressionOwner::Closure(closure) => {
            let Some(ExpressionOwner::Body(body)) = program
                .expression(closure)
                .map(|expression| expression.owner)
            else {
                return false;
            };
            body
        }
        ExpressionOwner::Declaration(_) => return false,
    };
    let Some(target_scope) = program.body(binding.body).map(|body| body.scope) else {
        return false;
    };
    let Some(mut scope) = program.body(body).map(|body| body.scope) else {
        return false;
    };
    // Scope parents are validated as strictly earlier IDs. Retain a local
    // bound here so a malformed unsealed model cannot make this walk cycle.
    for _ in 0..=program.scopes.len() {
        if scope == target_scope {
            return true;
        }
        let Some(parent) = program.scope(scope).and_then(|scope| scope.parent) else {
            return false;
        };
        scope = parent;
    }
    false
}

fn valid_body_owner(program: &Program, owner: BodyOwner) -> bool {
    match owner {
        BodyOwner::Declaration(id) => program.declaration(id).is_some(),
        BodyOwner::Closure(id) => program
            .expression(id)
            .is_some_and(|expression| matches!(expression.kind, ExpressionKind::Closure { .. })),
    }
}

fn expression_owner_span(program: &Program, owner: ExpressionOwner) -> Option<Span> {
    match owner {
        ExpressionOwner::Declaration(id) => program.declaration(id).map(|value| value.source),
        ExpressionOwner::Body(id) => program.body(id).map(|value| value.source),
        ExpressionOwner::Closure(id) => program.expression(id).map(|value| value.source),
    }
}

fn body_owner_span(program: &Program, owner: BodyOwner) -> Option<Span> {
    match owner {
        BodyOwner::Declaration(id) => program.declaration(id).map(|value| value.source),
        BodyOwner::Closure(id) => program.expression(id).map(|value| value.source),
    }
}

fn for_each_statement_body(kind: &StatementKind, mut visit: impl FnMut(BodyId)) {
    match kind {
        StatementKind::If {
            branches,
            else_body,
        } => {
            for (_, body) in branches {
                visit(*body);
            }
            if let Some(body) = else_body {
                visit(*body);
            }
        }
        StatementKind::Match { arms, .. } => {
            for arm in arms {
                visit(arm.body);
            }
        }
        StatementKind::For { body, .. }
        | StatementKind::While { body, .. }
        | StatementKind::Loop { body }
        | StatementKind::With { body, .. } => visit(*body),
        StatementKind::ComptimeIf {
            then_body,
            else_body,
            ..
        } => {
            visit(*then_body);
            if let Some(body) = else_body {
                visit(*body);
            }
        }
        _ => {}
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
                match &argument.kind {
                    GenericArgumentKind::Type(ty) => {
                        collect_type_expressions(ty, coverage, depth + 1);
                    }
                    GenericArgumentKind::Constant(id)
                    | GenericArgumentKind::BoundedCapacity(id) => {
                        increment_coverage(coverage, id.0);
                    }
                    GenericArgumentKind::Region(_) | GenericArgumentKind::Error => {}
                }
            }
        }
        TypeExpressionKind::SelfType { .. } => {}
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
            if let Some(result) = &value.result {
                collect_type_expressions(result, coverage, 0);
            }
        }
        DeclarationKind::Initializer(value) => {
            if let Some(result) = &value.result {
                collect_type_expressions(result, coverage, 0);
            }
        }
        DeclarationKind::Structure(value) => {
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
            collect_carrier_expressions(&value.carrier, coverage, 0);
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

fn collect_carrier_expressions(carrier: &ProjectionCarrier, coverage: &mut [u8], depth: u32) {
    if depth >= 1024 {
        return;
    }
    match &carrier.kind {
        ProjectionCarrierKind::View { ty, .. } => collect_type_expressions(ty, coverage, 0),
        ProjectionCarrierKind::Option(value) => {
            collect_carrier_expressions(value, coverage, depth + 1);
        }
        ProjectionCarrierKind::Result { carrier, error } => {
            collect_carrier_expressions(carrier, coverage, depth + 1);
            collect_type_expressions(error, coverage, 0);
        }
        ProjectionCarrierKind::Error => {}
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
        ExpressionKind::Compare { left, right, .. } => {
            increment_coverage(coverage, left.0);
            increment_coverage(coverage, right.0);
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
                match &argument.value {
                    CallArgumentValue::Value(value) => increment_coverage(coverage, value.0),
                    CallArgumentValue::Exclusive { place, .. } => {
                        for projection in &place.projections {
                            if let PlaceProjection::Index(index) = projection {
                                increment_coverage(coverage, index.0);
                            }
                        }
                    }
                }
            }
        }
        ExpressionKind::Index { base, index } => {
            increment_coverage(coverage, base.0);
            increment_coverage(coverage, index.0);
        }
        ExpressionKind::Tuple(values) | ExpressionKind::Array(values) => {
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
        ExpressionKind::If {
            condition,
            then_branch,
            elif_branches,
            else_branch,
        } => {
            increment_coverage(coverage, condition.0);
            increment_coverage(coverage, then_branch.0);
            for (elif_condition, elif_branch) in elif_branches {
                increment_coverage(coverage, elif_condition.0);
                increment_coverage(coverage, elif_branch.0);
            }
            increment_coverage(coverage, else_branch.0);
        }
        ExpressionKind::Literal(_)
        | ExpressionKind::Reference(_)
        | ExpressionKind::DotName { .. }
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
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    if depth >= 1024 {
        errors.push(ValidationError::NestingLimit);
        return;
    }
    if !valid_span(ty.source)
        || expression_owner_span(program, expression_owner)
            .is_none_or(|owner| !span_contains(owner, ty.source))
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
            if !valid_type_definition(program, definition, expression_owner) {
                errors.push(invalid_reference("type definition", 0));
            }
            if !generic_arguments_match_definition(program, definition, arguments) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "type expression",
                    id: depth,
                    reason: "generic argument count or kind",
                });
            }
            for argument in arguments {
                if errors.poll() {
                    return;
                }
                if !valid_span(argument.source) || !span_contains(ty.source, argument.source) {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "generic argument",
                        id: depth,
                        reason: "source",
                    });
                }
                match &argument.kind {
                    GenericArgumentKind::Type(value) => {
                        if !span_contains(argument.source, value.source) {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "generic type argument",
                                id: depth,
                                reason: "source",
                            });
                        }
                        validate_type(program, value, expression_owner, depth + 1, errors);
                    }
                    GenericArgumentKind::Constant(id)
                    | GenericArgumentKind::BoundedCapacity(id) => {
                        if program.expression(*id).is_none_or(|value| {
                            value.owner != expression_owner
                                || !span_contains(argument.source, value.source)
                        }) {
                            errors.push(invalid_reference("generic constant expression", id.0));
                        }
                    }
                    GenericArgumentKind::Region(RegionReference::Generic(id)) => {
                        if program.generic_parameter(*id).is_none_or(|value| {
                            !matches!(value.kind, GenericParameterKind::Region)
                                || !generic_visible_from(program, *id, expression_owner)
                        }) {
                            errors.push(invalid_reference("generic region", id.0));
                        }
                    }
                    GenericArgumentKind::Region(RegionReference::Local(id)) => {
                        if !region_visible_from(program, *id, expression_owner) {
                            errors.push(invalid_reference("local region", id.0));
                        }
                    }
                    GenericArgumentKind::Error => {}
                }
            }
        }
        TypeExpressionKind::SelfType { owner } => {
            if nearest_self_type_owner(program, expression_owner) != Some(*owner) {
                errors.push(invalid_reference("Self type owner", owner.0));
            }
        }
        TypeExpressionKind::Array { element, length } => {
            validate_type(program, element, expression_owner, depth + 1, errors);
            if program.expression(*length).is_none_or(|value| {
                value.owner != expression_owner || !span_contains(ty.source, value.source)
            }) {
                errors.push(invalid_reference("array length", length.0));
            }
        }
        TypeExpressionKind::Tuple(values) => {
            for value in values {
                if errors.poll() {
                    return;
                }
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
                if errors.poll() {
                    return;
                }
                if !valid_span(parameter.source) || !span_contains(ty.source, parameter.source) {
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
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    if matches!(
        &attribute.identity,
        AttributeIdentity::Tool(identity) if !valid_resolved_declaration(program, identity)
    ) || !valid_span(attribute.source)
        || expression_owner_span(program, owner)
            .is_none_or(|owner| !span_contains(owner, attribute.source))
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "attribute",
            id: 0,
            reason: "name, owner, or source",
        });
    }
    let mut saw_named = false;
    for argument in &attribute.arguments {
        if errors.poll() {
            return;
        }
        if let Some(name) = &argument.name {
            validate_name(name, "attribute argument", errors);
            saw_named = true;
        } else if saw_named {
            errors.push(ValidationError::InvalidRecord {
                arena: "attribute argument",
                id: 0,
                reason: "positional argument after named argument",
            });
        }
        if !valid_span(argument.source)
            || !span_contains(attribute.source, argument.source)
            || program.expression(argument.value).is_none_or(|value| {
                value.owner != owner || !span_contains(argument.source, value.source)
            })
        {
            errors.push(invalid_reference("attribute argument", argument.value.0));
        }
    }
    if duplicate_names(
        attribute.arguments.len(),
        attribute
            .arguments
            .iter()
            .filter_map(|argument| argument.name.as_ref())
            .map(Name::as_str),
        errors,
    ) {
        errors.push(ValidationError::InvalidRecord {
            arena: "attribute argument",
            id: 0,
            reason: "duplicate name",
        });
    }
}

fn validate_declaration(
    program: &Program,
    declaration: &Declaration,
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    let name_required = !matches!(
        &declaration.kind,
        DeclarationKind::Implementation(_)
            | DeclarationKind::Initializer(_)
            | DeclarationKind::ComptimeSelection(_)
            | DeclarationKind::Error
    );
    if declaration.name.is_some() != name_required {
        errors.push(ValidationError::InvalidRecord {
            arena: "declaration",
            id: declaration.id.0,
            reason: "source name presence",
        });
    }
    if let Some(name) = &declaration.name {
        validate_name(name, "declaration", errors);
    }
    let Some(module) = program.modules.get(declaration.module.0 as usize) else {
        errors.push(invalid_reference(
            "declaration module",
            declaration.module.0,
        ));
        return;
    };
    if !valid_span(declaration.source) || !span_contains(module.source, declaration.source) {
        errors.push(ValidationError::InvalidRecord {
            arena: "declaration",
            id: declaration.id.0,
            reason: "source",
        });
    }
    for attribute in &declaration.attributes {
        if errors.poll() {
            return;
        }
        validate_attribute(
            program,
            attribute,
            ExpressionOwner::Declaration(declaration.id),
            errors,
        );
    }
    let owner = ExpressionOwner::Declaration(declaration.id);
    if !strict_ids(
        declaration_generics(declaration).iter().map(|id| id.0),
        errors,
    ) || !strict_ids(
        declaration_parameters(declaration).iter().map(|id| id.0),
        errors,
    ) || !strict_ids(
        declaration_children(declaration).iter().map(|id| id.0),
        errors,
    ) {
        errors.push(ValidationError::NonCanonical("declaration references"));
    }
    for generic in declaration_generics(declaration) {
        if errors.poll() {
            return;
        }
        let Some(value) = program.generic_parameter(*generic) else {
            errors.push(invalid_reference("declaration generic", generic.0));
            continue;
        };
        if value.owner != declaration.id {
            errors.push(ValidationError::InvalidRecord {
                arena: "declaration generic",
                id: generic.0,
                reason: "owner or duplicate name",
            });
        }
    }
    if duplicate_names(
        declaration_generics(declaration).len(),
        declaration_generics(declaration)
            .iter()
            .filter_map(|id| program.generic_parameter(*id))
            .map(|generic| generic.name.as_str()),
        errors,
    ) {
        errors.push(ValidationError::InvalidRecord {
            arena: "declaration generic",
            id: declaration.id.0,
            reason: "duplicate name",
        });
    }
    let mut receiver_count = 0usize;
    for (index, parameter) in declaration_parameters(declaration).iter().enumerate() {
        if errors.poll() {
            return;
        }
        let Some(value) = program.parameter(*parameter) else {
            errors.push(invalid_reference("declaration parameter", parameter.0));
            continue;
        };
        if value.receiver {
            receiver_count += 1;
            if index != 0
                || receiver_count != 1
                || !declaration_allows_receiver(program, declaration)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "declaration parameter",
                    id: parameter.0,
                    reason: "receiver position or declaration context",
                });
            }
        }
        if value.owner != CallableOwner::Declaration(declaration.id) {
            errors.push(ValidationError::InvalidRecord {
                arena: "declaration parameter",
                id: parameter.0,
                reason: "owner or duplicate name",
            });
        }
    }
    if duplicate_names(
        declaration_parameters(declaration).len(),
        declaration_parameters(declaration)
            .iter()
            .filter_map(|id| program.parameter(*id))
            .filter_map(|parameter| parameter.name.as_ref())
            .map(Name::as_str),
        errors,
    ) {
        errors.push(ValidationError::InvalidRecord {
            arena: "declaration parameter",
            id: declaration.id.0,
            reason: "duplicate name",
        });
    }
    for child in declaration_children(declaration) {
        if errors.poll() {
            return;
        }
        let Some(value) = program.declaration(*child) else {
            errors.push(invalid_reference("nested declaration", child.0));
            continue;
        };
        if value.owner != DeclarationOwner::Declaration(declaration.id) {
            errors.push(ValidationError::InvalidRecord {
                arena: "nested declaration",
                id: child.0,
                reason: "owner or duplicate name",
            });
        }
    }
    if duplicate_names(
        declaration_children(declaration).len(),
        declaration_children(declaration)
            .iter()
            .filter_map(|id| program.declaration(*id))
            .filter_map(|child| child.name.as_ref())
            .map(Name::as_str),
        errors,
    ) {
        errors.push(ValidationError::InvalidRecord {
            arena: "nested declaration",
            id: declaration.id.0,
            reason: "duplicate name",
        });
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
            if let Some(result) = &value.result {
                validate_type(program, result, owner, 0, errors);
            }
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
        DeclarationKind::Initializer(value) => {
            let direct_struct_owner = match declaration.owner {
                DeclarationOwner::Declaration(parent) => program
                    .declaration(parent)
                    .is_some_and(|parent| matches!(&parent.kind, DeclarationKind::Structure(_))),
                DeclarationOwner::Module(_) => false,
            };
            let receiver_is_exact = value.parameters.first().is_some_and(|parameter| {
                program.parameter(*parameter).is_some_and(|parameter| {
                    parameter.receiver
                        && parameter.access == AccessMode::Mutate
                        && parameter.name.is_none()
                        && parameter.ty.is_none()
                })
            }) && value
                .parameters
                .iter()
                .skip(1)
                .all(|parameter| program.parameter(*parameter).is_some_and(|p| !p.receiver));
            if !direct_struct_owner
                || declaration.visibility != Visibility::Private
                || !declaration.attributes.is_empty()
                || !receiver_is_exact
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "initializer",
                    id: declaration.id.0,
                    reason: "struct owner, private anonymous shape, or mutate receiver",
                });
            }
            if let Some(result) = &value.result {
                validate_type(program, result, owner, 0, errors);
            }
            check_body_owner(
                program,
                value.body,
                BodyOwner::Declaration(declaration.id),
                "initializer body",
                errors,
            );
        }
        DeclarationKind::Structure(value) => {
            for implementation in &value.implements {
                if errors.poll() {
                    return;
                }
                validate_type(program, implementation, owner, 0, errors);
            }
            for field in &value.fields {
                if errors.poll() {
                    return;
                }
                validate_name(&field.name, "field", errors);
                if !valid_span(field.source) || !span_contains(declaration.source, field.source) {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "field",
                        id: declaration.id.0,
                        reason: "source or duplicate name",
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
            if duplicate_names(
                value.fields.len().saturating_add(value.members.len()),
                value.fields.iter().map(|field| field.name.as_str()).chain(
                    value
                        .members
                        .iter()
                        .filter_map(|id| program.declaration(*id))
                        .filter_map(|member| member.name.as_ref())
                        .map(Name::as_str),
                ),
                errors,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "aggregate member",
                    id: declaration.id.0,
                    reason: "field/member namespace collision",
                });
            }
            if value
                .members
                .iter()
                .filter_map(|member| program.declaration(*member))
                .filter(|member| matches!(&member.kind, DeclarationKind::Initializer(_)))
                .count()
                > 1
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "initializer",
                    id: declaration.id.0,
                    reason: "more than one initializer in a struct",
                });
            }
        }
        DeclarationKind::Enumeration(value) => {
            for variant in &value.variants {
                if errors.poll() {
                    return;
                }
                validate_name(&variant.name, "enum variant", errors);
                if !valid_span(variant.source) || !span_contains(declaration.source, variant.source)
                {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "enum variant",
                        id: declaration.id.0,
                        reason: "source or duplicate name",
                    });
                }
                let named_payload = variant
                    .fields
                    .first()
                    .and_then(|field| field.name.as_ref())
                    .is_some();
                for field in &variant.fields {
                    if errors.poll() {
                        return;
                    }
                    if field.name.is_some() != named_payload {
                        errors.push(ValidationError::InvalidRecord {
                            arena: "variant field",
                            id: declaration.id.0,
                            reason: "mixed positional and named payload",
                        });
                    }
                    if let Some(name) = &field.name {
                        validate_name(name, "variant field", errors);
                    }
                    if !valid_span(field.source) || !span_contains(variant.source, field.source) {
                        errors.push(ValidationError::InvalidRecord {
                            arena: "variant field",
                            id: declaration.id.0,
                            reason: "source",
                        });
                    }
                    validate_type(program, &field.ty, owner, 0, errors);
                }
                if duplicate_names(
                    variant.fields.len(),
                    variant
                        .fields
                        .iter()
                        .filter_map(|field| field.name.as_ref())
                        .map(Name::as_str),
                    errors,
                ) {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "variant field",
                        id: declaration.id.0,
                        reason: "duplicate name",
                    });
                }
            }
            if duplicate_names(
                value.variants.len().saturating_add(value.members.len()),
                value
                    .variants
                    .iter()
                    .map(|variant| variant.name.as_str())
                    .chain(
                        value
                            .members
                            .iter()
                            .filter_map(|id| program.declaration(*id))
                            .filter_map(|member| member.name.as_ref())
                            .map(Name::as_str),
                    ),
                errors,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "enum member",
                    id: declaration.id.0,
                    reason: "variant/member namespace collision",
                });
            }
        }
        DeclarationKind::Interface(_) => {}
        DeclarationKind::Implementation(value) => {
            validate_type(program, &value.interface, owner, 0, errors);
            validate_type(program, &value.implementing_type, owner, 0, errors);
        }
        DeclarationKind::Projection(value) => {
            validate_carrier(program, &value.carrier, owner, 0, errors);
            if !strict_ids(value.provenance.iter().map(|id| id.0), errors) {
                errors.push(ValidationError::NonCanonical("projection provenance"));
            }
            for parameter in &value.provenance {
                if value.parameters.binary_search(parameter).is_err() {
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
            let setup_scope = program.body(value.setup).map(|body| body.scope);
            if program.expression(value.enter).is_none_or(|expression| {
                expression.owner != ExpressionOwner::Body(value.setup)
                    || expression.scope != setup_scope
            }) {
                errors.push(invalid_reference("scope enter", value.enter.0));
            }
            if let Some(abort) = value.abort {
                check_scope_phase_body(
                    program,
                    abort,
                    declaration.id,
                    setup_scope,
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
            check_scope_phase_body(
                program,
                value.exit,
                declaration.id,
                setup_scope,
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
            if !strict_ids(value.then_declarations.iter().map(|id| id.0), errors)
                || !strict_ids(value.else_declarations.iter().map(|id| id.0), errors)
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
    depth: u32,
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    if depth >= 1024 {
        errors.push(ValidationError::NestingLimit);
        return;
    }
    if !valid_span(carrier.source)
        || expression_owner_span(program, owner)
            .is_none_or(|owner| !span_contains(owner, carrier.source))
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "projection carrier",
            id: depth,
            reason: "source",
        });
    }
    match &carrier.kind {
        ProjectionCarrierKind::View { ty, .. } => validate_type(program, ty, owner, 0, errors),
        ProjectionCarrierKind::Option(value) => {
            if !span_contains(carrier.source, value.source) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "projection carrier",
                    id: depth,
                    reason: "child source",
                });
            }
            validate_carrier(program, value, owner, depth + 1, errors);
        }
        ProjectionCarrierKind::Result {
            carrier: child,
            error,
        } => {
            if !span_contains(carrier.source, child.source)
                || !span_contains(carrier.source, error.source)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "projection carrier",
                    id: depth,
                    reason: "child source",
                });
            }
            validate_carrier(program, child, owner, depth + 1, errors);
            validate_type(program, error, owner, 0, errors);
        }
        ProjectionCarrierKind::Error => {}
    }
}

fn check_expression_owner(
    program: &Program,
    id: ExpressionId,
    owner: ExpressionOwner,
    kind: &'static str,
    errors: &mut ValidationErrorSink,
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
    errors: &mut ValidationErrorSink,
) {
    if program.body(id).is_none_or(|value| {
        value.owner != owner
            || program
                .scope(value.scope)
                .is_none_or(|scope| scope.parent.is_some())
    }) {
        errors.push(invalid_reference(kind, id.0));
    }
}

fn check_scope_phase_body(
    program: &Program,
    id: BodyId,
    declaration: DeclarationId,
    setup_scope: Option<ScopeId>,
    kind: &'static str,
    errors: &mut ValidationErrorSink,
) {
    if program.body(id).is_none_or(|value| {
        value.owner != BodyOwner::Declaration(declaration)
            || program
                .scope(value.scope)
                .is_none_or(|scope| scope.parent != setup_scope)
    }) {
        errors.push(invalid_reference(kind, id.0));
    }
}

fn validate_statement(program: &Program, statement: &Statement, errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
    let owner = ExpressionOwner::Body(statement.body);
    let Some(body) = program.body(statement.body) else {
        errors.push(invalid_reference("statement body", statement.body.0));
        return;
    };
    if !valid_span(statement.source) || !span_contains(body.source, statement.source) {
        errors.push(ValidationError::InvalidRecord {
            arena: "statement",
            id: statement.id.0,
            reason: "body or source",
        });
    }
    for attribute in &statement.attributes {
        if errors.poll() {
            return;
        }
        validate_attribute(program, attribute, owner, errors);
    }
    if statement.attributes.len() > 1
        || statement.attributes.iter().any(|attribute| {
            attribute.identity != AttributeIdentity::Builtin(BuiltinAttribute::Uninterrupted)
        })
        || (!statement.attributes.is_empty()
            && !matches!(
                statement.kind,
                StatementKind::For { .. }
                    | StatementKind::While { .. }
                    | StatementKind::Loop { .. }
            ))
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "statement attribute",
            id: statement.id.0,
            reason: "only one uninterrupted attribute is legal on a loop",
        });
    }
    let expression = |id: ExpressionId, kind: &'static str, errors: &mut ValidationErrorSink| {
        if program.expression(id).is_none_or(|value| {
            value.owner != owner
                || value.scope != Some(body.scope)
                || !span_contains(statement.source, value.source)
        }) {
            errors.push(invalid_reference(kind, id.0));
        }
    };
    let child_body = |id: BodyId, kind: &'static str, errors: &mut ValidationErrorSink| {
        if id.0 <= statement.body.0
            || program.body(id).is_none_or(|value| {
                value.owner != body.owner
                    || !span_contains(statement.source, value.source)
                    || program
                        .scope(value.scope)
                        .is_none_or(|scope| scope.parent != Some(body.scope))
            })
        {
            errors.push(invalid_reference(kind, id.0));
        }
    };
    let conditional_child_body =
        |condition: ExpressionId,
         id: BodyId,
         kind: &'static str,
         errors: &mut ValidationErrorSink| {
            let condition_source = program.expression(condition).map(|value| value.source);
            if id.0 <= statement.body.0
                || program.body(id).is_none_or(|value| {
                    value.owner != body.owner
                        || !span_contains(statement.source, value.source)
                        || program.scope(value.scope).is_none_or(|scope| {
                            let Some(parent) = scope.parent else {
                                return true;
                            };
                            parent != body.scope
                                && program.scope(parent).is_none_or(|parent_scope| {
                                    parent_scope.body != statement.body
                                        || condition_source.is_none_or(|source| {
                                            !span_contains(source, parent_scope.source)
                                        })
                                })
                        })
                })
            {
                errors.push(invalid_reference(kind, id.0));
            }
        };
    match &statement.kind {
        StatementKind::Initialize { local, value } => {
            if program.local(*local).is_none_or(|value| {
                value.body != statement.body
                    || value.scope != body.scope
                    || !span_contains(statement.source, value.source)
            }) {
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
                if !definition_visible_at(
                    program,
                    &target.root,
                    owner,
                    Some(body.scope),
                    target.source,
                ) || !valid_span(target.source)
                    || !span_contains(statement.source, target.source)
                {
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
        StatementKind::Assert {
            condition,
            expression: source_expression,
            witness,
            ..
        } => {
            expression(*condition, "assertion", errors);
            let condition_source = program.expression(*condition).map(|record| record.source);
            if source_expression.chars().all(char::is_whitespace)
                || witness.expression != *source_expression
                || condition_source != Some(witness.source)
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "statements",
                    id: statement.id.0,
                    reason: "assertion condition source witness disagrees with its expression",
                });
            }
        }
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
                conditional_child_body(*condition, *branch, "if body", errors);
            }
            if let Some(body) = else_body {
                child_body(*body, "else body", errors);
            }
        }
        StatementKind::Match { scrutinee, arms } => {
            expression(*scrutinee, "match scrutinee", errors);
            for arm in arms {
                if !valid_span(arm.source) || !span_contains(statement.source, arm.source) {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "match arm",
                        id: statement.id.0,
                        reason: "source",
                    });
                }
                child_body(arm.body, "match body", errors);
                let arm_scope = program.body(arm.body).map(|body| body.scope);
                if program.pattern(arm.pattern).is_none_or(|value| {
                    value.owner != ExpressionOwner::Body(arm.body)
                        || value.binding_scope != arm_scope
                        || !span_contains(arm.source, value.source)
                }) {
                    errors.push(invalid_reference("match pattern", arm.pattern.0));
                }
                if let Some(guard) = arm.guard {
                    if program.expression(guard).is_none_or(|value| {
                        value.owner != ExpressionOwner::Body(arm.body)
                            || value.scope != arm_scope
                            || !span_contains(arm.source, value.source)
                    }) {
                        errors.push(invalid_reference("match guard", guard.0));
                    }
                }
            }
        }
        StatementKind::For {
            binding,
            iterable,
            body,
            ..
        } => {
            if program.local(*binding).is_none_or(|binding| {
                binding.body != *body || !span_contains(statement.source, binding.source)
            }) {
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
            if binding.is_some_and(|binding| {
                program.local(binding).is_none_or(|binding| {
                    binding.body != *body || !span_contains(statement.source, binding.source)
                })
            }) {
                errors.push(invalid_reference(
                    "with binding",
                    binding.unwrap_or(LocalId(0)).0,
                ));
            }
            if region.is_some_and(|region| {
                program.region(region).is_none_or(|value| {
                    value.body != *body || !span_contains(statement.source, value.source)
                })
            }) {
                errors.push(invalid_reference(
                    "with region",
                    region.unwrap_or(RegionId(0)).0,
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
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    if !valid_span(expression.source)
        || !valid_expression_scope_shape(program, expression)
        || expression_owner_span(program, expression.owner)
            .is_none_or(|owner| !span_contains(owner, expression.source))
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "expression",
            id: expression.id.0,
            reason: "owner or source",
        });
    }
    let child = |id: ExpressionId, kind: &'static str, errors: &mut ValidationErrorSink| {
        if id.0 <= expression.id.0
            || program.expression(id).is_none_or(|value| {
                value.owner != expression.owner
                    || value.scope != expression.scope
                    || !span_contains(expression.source, value.source)
            })
        {
            errors.push(invalid_reference(kind, id.0));
        }
    };
    match &expression.kind {
        ExpressionKind::Literal(value) => validate_literal(value, expression.id, errors),
        ExpressionKind::Reference(value) => {
            if !definition_visible_at(
                program,
                value,
                expression.owner,
                expression_scope(program, expression),
                expression.source,
            ) {
                errors.push(invalid_reference("expression definition", expression.id.0));
            }
        }
        ExpressionKind::Closure {
            parameters,
            body,
            captures,
            ..
        } => {
            if !strict_ids(parameters.iter().map(|id| id.0), errors) {
                errors.push(ValidationError::NonCanonical("closure parameters"));
            }
            for parameter in parameters {
                if errors.poll() {
                    return;
                }
                if program.parameter(*parameter).is_none_or(|value| {
                    value.owner != CallableOwner::Closure(expression.id) || value.receiver
                }) {
                    errors.push(invalid_reference("closure parameter", parameter.0));
                }
            }
            match body {
                ClosureBody::Expression(id) => {
                    if id.0 <= expression.id.0
                        || program.expression(*id).is_none_or(|value| {
                            value.owner != ExpressionOwner::Closure(expression.id)
                                || value.scope.is_some()
                                || !span_contains(expression.source, value.source)
                        })
                    {
                        errors.push(invalid_reference("closure expression", id.0));
                    }
                }
                ClosureBody::Body(id) => check_body_owner(
                    program,
                    *id,
                    BodyOwner::Closure(expression.id),
                    "closure body",
                    errors,
                ),
            }
            for capture in captures {
                if errors.poll() {
                    return;
                }
                if !definition_visible_at(
                    program,
                    capture,
                    expression.owner,
                    expression_scope(program, expression),
                    expression.source,
                ) {
                    errors.push(invalid_reference("closure capture", expression.id.0));
                }
            }
        }
        ExpressionKind::Unary { operand, .. } => child(*operand, "unary operand", errors),
        ExpressionKind::Binary {
            operator,
            left,
            right,
        } => {
            child(*left, "binary left", errors);
            if *operator == BinaryOperator::LogicalAnd {
                let valid_right = program.expression(*right).is_some_and(|right_expression| {
                    right.0 > expression.id.0
                        && right_expression.owner == expression.owner
                        && span_contains(expression.source, right_expression.source)
                        && match (expression.scope, right_expression.scope) {
                            (Some(parent), Some(child_scope)) => {
                                scope_is_ancestor_or_same(program, parent, child_scope)
                            }
                            (None, None) => true,
                            _ => false,
                        }
                });
                if !valid_right {
                    errors.push(invalid_reference("logical-and right", right.0));
                }
            } else {
                child(*right, "binary right", errors);
            }
        }
        ExpressionKind::Compare { left, right, .. } => {
            child(*left, "comparison left", errors);
            child(*right, "comparison right", errors);
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
            validate_member_name(name, "field", errors);
        }
        ExpressionKind::Call { callee, arguments } => {
            child(*callee, "callee", errors);
            let mut names = Vec::new();
            for argument in arguments {
                if errors.poll() {
                    return;
                }
                if let Some(name) = &argument.name {
                    validate_argument_name(name, errors);
                    if names.iter().any(|existing| existing == name) {
                        errors.push(ValidationError::InvalidRecord {
                            arena: "call argument",
                            id: expression.id.0,
                            reason: "duplicate named argument",
                        });
                    }
                    names.push(name.clone());
                }
                if !valid_span(argument.source)
                    || !span_contains(expression.source, argument.source)
                {
                    errors.push(ValidationError::InvalidRecord {
                        arena: "call argument",
                        id: expression.id.0,
                        reason: "source",
                    });
                }
                match &argument.value {
                    CallArgumentValue::Value(value) => child(*value, "call argument", errors),
                    CallArgumentValue::Exclusive { place, .. } => {
                        if !matches!(place.root, Definition::Local(_) | Definition::Parameter(_))
                            || !definition_visible_at(
                                program,
                                &place.root,
                                expression.owner,
                                expression_scope(program, expression),
                                place.source,
                            )
                            || !valid_span(place.source)
                            || !span_contains(argument.source, place.source)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "exclusive call place",
                                id: expression.id.0,
                                reason: "root or source",
                            });
                        }
                        for projection in &place.projections {
                            match projection {
                                PlaceProjection::Field(name) => {
                                    validate_name(name, "exclusive call field", errors);
                                }
                                PlaceProjection::Index(index) => {
                                    child(*index, "exclusive call index", errors);
                                }
                                PlaceProjection::Tuple(_) => {}
                            }
                        }
                    }
                }
            }
            if duplicate_names(
                arguments.len(),
                arguments
                    .iter()
                    .filter_map(|argument| argument.name.as_ref())
                    .map(Name::as_str),
                errors,
            ) {
                errors.push(ValidationError::InvalidRecord {
                    arena: "call argument",
                    id: expression.id.0,
                    reason: "duplicate name",
                });
            }
        }
        ExpressionKind::Index { base, index } => {
            child(*base, "index base", errors);
            child(*index, "index", errors);
        }
        ExpressionKind::Tuple(values) | ExpressionKind::Array(values) => {
            for value in values {
                if errors.poll() {
                    return;
                }
                child(*value, "aggregate expression", errors);
            }
        }
        ExpressionKind::DotName {
            spelling,
            candidates,
        } => {
            validate_name(spelling, "dot-name expression", errors);
            if candidates.is_empty()
                || !candidates.windows(2).all(|pair| pair[0] < pair[1])
                || candidates.iter().any(|value| {
                    resolved_variant(program, value).is_none_or(|variant| variant.name != *spelling)
                })
            {
                errors.push(ValidationError::InvalidRecord {
                    arena: "dot-name expression",
                    id: expression.id.0,
                    reason: "candidates",
                });
            }
        }
        ExpressionKind::Interpolate(parts) => {
            for part in parts {
                if errors.poll() {
                    return;
                }
                match part {
                    InterpolationPart::Text { value, source } => {
                        if value.len() > 16 * 1024 * 1024
                            || !span_contains(expression.source, *source)
                        {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "interpolation",
                                id: expression.id.0,
                                reason: "text bound or source",
                            });
                        }
                    }
                    InterpolationPart::Value {
                        expression: value,
                        format,
                        format_source,
                    } => {
                        child(*value, "interpolation value", errors);
                        if format.as_ref().is_some_and(|value| {
                            value.is_empty()
                                || value.len() > 4096
                                || !value.is_ascii()
                                || value.bytes().any(|byte| matches!(byte, b'{' | b'}'))
                        }) || format.is_some() != format_source.is_some()
                            || format_source
                                .is_some_and(|source| !span_contains(expression.source, source))
                        {
                            errors.push(ValidationError::InvalidRecord {
                                arena: "interpolation",
                                id: value.0,
                                reason: "format bound or source",
                            });
                        }
                    }
                }
            }
        }
        ExpressionKind::If {
            condition,
            then_branch,
            elif_branches,
            else_branch,
        } => {
            child(*condition, "if condition", errors);
            child(*then_branch, "if then branch", errors);
            for (elif_condition, elif_branch) in elif_branches {
                child(*elif_condition, "if elif condition", errors);
                child(*elif_branch, "if elif branch", errors);
            }
            child(*else_branch, "if else branch", errors);
        }
        ExpressionKind::Error => {}
    }
}

fn validate_literal(value: &Literal, id: ExpressionId, errors: &mut ValidationErrorSink) {
    if errors.poll() {
        return;
    }
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

fn validate_pattern(
    program: &Program,
    pattern: &Pattern,
    binding_root: &Pattern,
    errors: &mut ValidationErrorSink,
) {
    if errors.poll() {
        return;
    }
    if pattern.alternatives.is_empty()
        || !valid_span(pattern.source)
        || expression_owner_span(program, pattern.owner)
            .is_none_or(|owner| !span_contains(owner, pattern.source))
        || pattern.binding_scope.is_some_and(|scope| {
            let ExpressionOwner::Body(owner_body) = pattern.owner else {
                return true;
            };
            program.scope(scope).is_none_or(|scope| {
                !same_body_owner(program, owner_body, scope.body)
                    || !span_contains(
                        expression_owner_span(program, pattern.owner).unwrap_or(pattern.source),
                        scope.source,
                    )
            })
        })
    {
        errors.push(ValidationError::InvalidRecord {
            arena: "pattern",
            id: pattern.id.0,
            reason: "alternatives, body, or source",
        });
    }
    for alternative in &pattern.alternatives {
        if errors.poll() {
            return;
        }
        if !valid_span(alternative.source) || !span_contains(pattern.source, alternative.source) {
            errors.push(ValidationError::InvalidRecord {
                arena: "pattern alternative",
                id: pattern.id.0,
                reason: "source",
            });
        }
        match &alternative.kind {
            PrimaryPattern::Wildcard | PrimaryPattern::Error => {}
            PrimaryPattern::Literal { literal, .. } => {
                validate_literal(literal, ExpressionId(pattern.id.0), errors);
            }
            PrimaryPattern::Constructor {
                spelling,
                candidates,
                arguments,
            } => {
                validate_name(spelling, "constructor pattern", errors);
                if candidates.is_empty()
                    || !candidates.windows(2).all(|pair| pair[0] < pair[1])
                    || candidates.iter().any(|value| {
                        resolved_variant(program, value)
                            .is_none_or(|variant| variant.name != *spelling)
                    })
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
                if !valid_pattern_binding(program, pattern, binding_root, *local) {
                    errors.push(invalid_reference("pattern binding", local.0));
                }
            }
            PrimaryPattern::Tuple(arguments) | PrimaryPattern::Array(arguments) => {
                validate_pattern_arguments(program, pattern, arguments, errors);
            }
        }
    }
}

fn valid_pattern_binding(
    program: &Program,
    pattern: &Pattern,
    binding_root: &Pattern,
    local: LocalId,
) -> bool {
    let Some(binding_scope) = pattern.binding_scope else {
        return false;
    };
    program.local(local).is_some_and(|local| {
        binding_root.owner == pattern.owner
            && binding_root.binding_scope == pattern.binding_scope
            && span_contains(binding_root.source, pattern.source)
            && local.scope == binding_scope
            && span_contains(binding_root.source, local.source)
            && program
                .scope(binding_scope)
                .is_some_and(|scope| local.body == scope.body)
    })
}

fn validate_pattern_arguments(
    program: &Program,
    parent: &Pattern,
    arguments: &[PatternArgument],
    errors: &mut ValidationErrorSink,
) {
    for argument in arguments {
        if errors.poll() {
            return;
        }
        if !valid_span(argument.source)
            || !span_contains(parent.source, argument.source)
            || argument.pattern.0 <= parent.id.0
            || program.pattern(argument.pattern).is_none_or(|value| {
                value.owner != parent.owner
                    || value.binding_scope != parent.binding_scope
                    || !span_contains(argument.source, value.source)
            })
        {
            errors.push(invalid_reference("pattern argument", argument.pattern.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use wrela_build_model::Sha256Digest;
    use wrela_package::{PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion};
    use wrela_source::{FileId, TextRange};

    fn test_graph(path: &ModulePath) -> Arc<PackageGraph> {
        let identity = PackageIdentity {
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1").expect("package version"),
            source_digest: Sha256Digest::from_bytes([1; 32]),
        };
        let mut graph = PackageGraphBuilder::new(identity);
        graph
            .add_module(graph.root(), path.clone(), FileId(0))
            .expect("module");
        Arc::new(graph.finish().expect("graph"))
    }

    fn span(start: u32, end: u32) -> Span {
        Span {
            file: FileId(0),
            range: TextRange { start, end },
        }
    }

    fn empty_program(path: ModulePath) -> Program {
        Program {
            packages: test_graph(&path),
            modules: vec![Module {
                id: ModuleId(0),
                package: PackageId(0),
                path,
                declarations: Vec::new(),
                reexports: Vec::new(),
                source: span(0, 100),
            }],
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
        }
    }

    fn initializer_program() -> Program {
        let path = ModulePath::new(["initializer".to_owned()]).expect("module path");
        let mut program = empty_program(path);
        program.modules[0].declarations = vec![DeclarationId(0)];
        program.declarations = vec![
            Declaration {
                id: DeclarationId(0),
                module: ModuleId(0),
                owner: DeclarationOwner::Module(ModuleId(0)),
                name: Some(Name::new("Cache".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Structure(AggregateDeclaration {
                    generics: Vec::new(),
                    implements: Vec::new(),
                    fields: Vec::new(),
                    members: vec![DeclarationId(1)],
                    linear: false,
                    copy: false,
                    deriving: Vec::new(),
                }),
                source: span(1, 99),
            },
            Declaration {
                id: DeclarationId(1),
                module: ModuleId(0),
                owner: DeclarationOwner::Declaration(DeclarationId(0)),
                name: None,
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Initializer(InitializerDeclaration {
                    parameters: vec![ParameterId(0)],
                    result: None,
                    body: BodyId(0),
                }),
                source: span(10, 90),
            },
        ];
        program.parameters = vec![Parameter {
            id: ParameterId(0),
            owner: CallableOwner::Declaration(DeclarationId(1)),
            name: None,
            access: AccessMode::Mutate,
            ty: None,
            receiver: true,
            positional_only: false,
            source: span(15, 23),
        }];
        program.bodies = vec![Body {
            id: BodyId(0),
            owner: BodyOwner::Declaration(DeclarationId(1)),
            scope: ScopeId(0),
            locals: Vec::new(),
            statements: Vec::new(),
            source: span(24, 89),
        }];
        program.scopes = vec![LexicalScope {
            id: ScopeId(0),
            body: BodyId(0),
            parent: None,
            source: span(24, 89),
        }];
        program
    }

    fn ancestor_assignment_program() -> Program {
        let path = ModulePath::new(["assignments".to_owned()]).expect("module path");
        let source = span(0, 200);
        Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("join".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Function(FunctionDeclaration {
                    color: FunctionColor::Sync,
                    generics: Vec::new(),
                    parameters: Vec::new(),
                    result: None,
                    body: Some(BodyId(0)),
                }),
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![
                Body {
                    id: BodyId(0),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(0),
                    locals: vec![LocalId(0)],
                    statements: vec![StatementId(0), StatementId(1)],
                    source: span(10, 190),
                },
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(1),
                    locals: vec![LocalId(1)],
                    statements: vec![StatementId(2), StatementId(3)],
                    source: span(50, 110),
                },
                Body {
                    id: BodyId(2),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(2),
                    locals: Vec::new(),
                    statements: vec![StatementId(4)],
                    source: span(120, 170),
                },
            ],
            scopes: vec![
                LexicalScope {
                    id: ScopeId(0),
                    body: BodyId(0),
                    parent: None,
                    source: span(10, 190),
                },
                LexicalScope {
                    id: ScopeId(1),
                    body: BodyId(1),
                    parent: Some(ScopeId(0)),
                    source: span(50, 110),
                },
                LexicalScope {
                    id: ScopeId(2),
                    body: BodyId(2),
                    parent: Some(ScopeId(0)),
                    source: span(120, 170),
                },
            ],
            locals: vec![
                Local {
                    id: LocalId(0),
                    body: BodyId(0),
                    scope: ScopeId(0),
                    name: Name::new("joined".to_owned()).expect("name"),
                    ty: None,
                    shadowed: None,
                    source: span(20, 26),
                },
                Local {
                    id: LocalId(1),
                    body: BodyId(1),
                    scope: ScopeId(1),
                    name: Name::new("sibling".to_owned()).expect("name"),
                    ty: None,
                    shadowed: None,
                    source: span(60, 67),
                },
            ],
            statements: vec![
                Statement {
                    id: StatementId(0),
                    body: BodyId(0),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(0),
                        value: ExpressionId(0),
                    },
                    source: span(20, 35),
                },
                Statement {
                    id: StatementId(1),
                    body: BodyId(0),
                    attributes: Vec::new(),
                    kind: StatementKind::If {
                        branches: vec![(ExpressionId(1), BodyId(1))],
                        else_body: Some(BodyId(2)),
                    },
                    source: span(40, 175),
                },
                Statement {
                    id: StatementId(2),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(1),
                        value: ExpressionId(2),
                    },
                    source: span(60, 75),
                },
                Statement {
                    id: StatementId(3),
                    body: BodyId(1),
                    attributes: Vec::new(),
                    kind: StatementKind::Assign {
                        targets: vec![PlaceTarget {
                            root: Definition::Local(LocalId(0)),
                            projections: Vec::new(),
                            source: span(80, 86),
                        }],
                        operator: AssignmentOperator::Assign,
                        value: ExpressionId(3),
                    },
                    source: span(80, 95),
                },
                Statement {
                    id: StatementId(4),
                    body: BodyId(2),
                    attributes: Vec::new(),
                    kind: StatementKind::Assign {
                        targets: vec![PlaceTarget {
                            root: Definition::Local(LocalId(0)),
                            projections: Vec::new(),
                            source: span(130, 136),
                        }],
                        operator: AssignmentOperator::Assign,
                        value: ExpressionId(4),
                    },
                    source: span(130, 145),
                },
            ],
            expressions: vec![
                Expression {
                    id: ExpressionId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(30, 31),
                },
                Expression {
                    id: ExpressionId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Boolean(true)),
                    source: span(43, 47),
                },
                Expression {
                    id: ExpressionId(2),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(72, 73),
                },
                Expression {
                    id: ExpressionId(3),
                    owner: ExpressionOwner::Body(BodyId(1)),
                    scope: Some(ScopeId(1)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(90, 92),
                },
                Expression {
                    id: ExpressionId(4),
                    owner: ExpressionOwner::Body(BodyId(2)),
                    scope: Some(ScopeId(2)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(140, 142),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        }
    }

    fn sole_assignment_target(program: &mut Program, statement: StatementId) -> &mut PlaceTarget {
        let StatementKind::Assign { targets, .. } =
            &mut program.statements[statement.0 as usize].kind
        else {
            panic!("fixture statement must be an assignment")
        };
        let [target] = targets.as_mut_slice() else {
            panic!("fixture assignment must have one target")
        };
        target
    }

    #[test]
    fn explicit_validation_policy_bounds_size_work_and_error_storage() {
        let path = ModulePath::new(["limits".to_owned()]).expect("module path");
        let program = empty_program(path.clone());
        let too_few_edges = ValidationLimits {
            model_edges: 1,
            ..ValidationLimits::standard()
        };
        assert!(matches!(
            program
                .clone()
                .validate_with_limits(too_few_edges, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "model edges",
                limit: 1
            })
        ));

        let too_little_work = ValidationLimits {
            validation_work: 1,
            ..ValidationLimits::standard()
        };
        assert!(matches!(
            program.validate_with_limits(too_little_work, &|| false),
            Err(ValidationFailure::ResourceLimit {
                resource: "validation work",
                limit: 1
            })
        ));

        let mut malformed = empty_program(path);
        malformed.modules[0].id = ModuleId(7);
        malformed.modules[0].package = PackageId(7);
        malformed.modules[0].reexports.push(Reexport {
            local_name: Name::new("broken".to_owned()).expect("name"),
            target: ReexportTarget::Module {
                package: PackageId(7),
                module: ModuleId(7),
            },
            source: span(101, 102),
        });
        let bounded_errors = ValidationLimits {
            errors: 2,
            ..ValidationLimits::standard()
        };
        let Err(ValidationFailure::Invalid(ValidationErrors(errors))) =
            malformed.validate_with_limits(bounded_errors, &|| false)
        else {
            panic!("malformed program must fail model validation");
        };
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors.last(),
            Some(&ValidationError::TooManyErrors { limit: 2 })
        );
    }

    #[test]
    fn cancellation_is_polled_again_during_core_validation() {
        let path = ModulePath::new(["cancel".to_owned()]).expect("module path");
        let program = empty_program(path);
        let limits = ValidationLimits::standard();
        let calls = Cell::new(0_u64);
        validate_program_resources(&program, limits, &|| {
            calls.set(calls.get() + 1);
            false
        })
        .expect("resource preflight");
        let preflight_calls = calls.get();
        calls.set(0);
        let result = program.validate_with_limits(limits, &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next > preflight_calls + 3
        });
        assert_eq!(result, Err(ValidationFailure::Cancelled));
        assert!(calls.get() > preflight_calls, "must enter core validation");
    }

    #[test]
    fn initializer_shape_is_validated_as_a_dedicated_struct_member() {
        let program = initializer_program();
        program.clone().validate().expect("valid initializer HIR");

        for malformed in [
            {
                let mut value = program.clone();
                value.declarations[1].name = Some(Name::new("init".to_owned()).expect("name"));
                value
            },
            {
                let mut value = program.clone();
                value.declarations[1].visibility = Visibility::Public;
                value
            },
            {
                let mut value = program.clone();
                value.declarations[1].attributes.push(Attribute {
                    identity: AttributeIdentity::Builtin(BuiltinAttribute::Test),
                    arguments: Vec::new(),
                    source: span(11, 14),
                });
                value
            },
            {
                let mut value = program.clone();
                value.parameters[0].access = AccessMode::Read;
                value
            },
            {
                let mut value = program.clone();
                value.parameters[0].receiver = false;
                value
            },
            {
                let mut value = program.clone();
                value.parameters[0].name = Some(Name::new("receiver".to_owned()).expect("name"));
                value
            },
            {
                let mut value = program.clone();
                value.parameters[0].ty = Some(TypeExpression {
                    kind: TypeExpressionKind::Named {
                        definition: Definition::Builtin(Builtin::Unit),
                        arguments: Vec::new(),
                    },
                    source: span(18, 22),
                });
                value
            },
            {
                let mut value = program.clone();
                value.parameters[0].owner = CallableOwner::Declaration(DeclarationId(0));
                value
            },
            {
                let mut value = program.clone();
                value.bodies[0].owner = BodyOwner::Declaration(DeclarationId(0));
                value
            },
            {
                let mut value = program.clone();
                value.declarations[1].owner = DeclarationOwner::Module(ModuleId(0));
                value
            },
            {
                let mut value = program.clone();
                value.declarations[0].kind = DeclarationKind::Brand;
                value
            },
            {
                let mut value = program.clone();
                value.parameters.push(Parameter {
                    id: ParameterId(1),
                    owner: CallableOwner::Declaration(DeclarationId(1)),
                    name: None,
                    access: AccessMode::Mutate,
                    ty: None,
                    receiver: true,
                    positional_only: false,
                    source: span(24, 28),
                });
                let DeclarationKind::Initializer(initializer) = &mut value.declarations[1].kind
                else {
                    unreachable!()
                };
                initializer.parameters.push(ParameterId(1));
                value
            },
            {
                let mut value = program.clone();
                let DeclarationKind::Initializer(initializer) = &mut value.declarations[1].kind
                else {
                    unreachable!()
                };
                initializer.body = BodyId(7);
                value
            },
        ] {
            malformed
                .validate()
                .expect_err("initializer representation mutation must fail");
        }

        let mut duplicate = program;
        let mut second = duplicate.declarations[1].clone();
        second.id = DeclarationId(2);
        second.kind = DeclarationKind::Error;
        second.owner = DeclarationOwner::Declaration(DeclarationId(0));
        duplicate.declarations.push(second);
        let DeclarationKind::Structure(structure) = &mut duplicate.declarations[0].kind else {
            unreachable!()
        };
        structure.members.push(DeclarationId(2));
        // First prove the struct edge itself is canonical, then mutate it
        // into a second initializer without constructing a second body arena.
        duplicate
            .clone()
            .validate()
            .expect("anonymous recovery member");
        duplicate.declarations[2].kind = duplicate.declarations[1].kind.clone();
        duplicate
            .validate()
            .expect_err("a struct cannot contain two initializers");
    }

    #[test]
    fn assignment_targets_accept_ancestor_locals_and_reject_scope_or_source_substitution() {
        let program = ancestor_assignment_program();
        program
            .clone()
            .validate()
            .expect("ancestor-local assignments must validate");

        let mut same_scope = program.clone();
        sole_assignment_target(&mut same_scope, StatementId(3)).root =
            Definition::Local(LocalId(1));
        same_scope
            .validate()
            .expect("a preceding local in the assignment scope must remain visible");

        let assert_target_rejected = |program: Program, statement: u32| {
            let errors = program
                .validate()
                .expect_err("malformed assignment target must fail validation");
            assert!(errors.0.contains(&ValidationError::InvalidRecord {
                arena: "assignment target",
                id: statement,
                reason: "root or source",
            }));
        };

        let mut sibling_scope = program.clone();
        sole_assignment_target(&mut sibling_scope, StatementId(4)).root =
            Definition::Local(LocalId(1));
        assert_target_rejected(sibling_scope, 4);

        let mut nonexistent = program.clone();
        sole_assignment_target(&mut nonexistent, StatementId(4)).root =
            Definition::Local(LocalId(u32::MAX));
        assert_target_rejected(nonexistent, 4);

        let mut escaped_source = program;
        sole_assignment_target(&mut escaped_source, StatementId(4)).source = span(0, 1);
        assert_target_rejected(escaped_source, 4);
    }

    #[test]
    fn public_imports_preserve_module_and_variant_namespace_identities() {
        let path = ModulePath::new(["facade".to_owned()]).expect("module path");
        let source = span(0, 100);
        let enumeration = ResolvedDeclaration {
            package: PackageId(0),
            module: ModuleId(0),
            declaration: DeclarationId(0),
        };
        let mut program = Program {
            packages: test_graph(&path),
            modules: vec![Module {
                id: ModuleId(0),
                package: PackageId(0),
                path,
                declarations: vec![DeclarationId(0)],
                reexports: vec![
                    Reexport {
                        local_name: Name::new("module_alias".to_owned()).expect("name"),
                        target: ReexportTarget::Module {
                            package: PackageId(0),
                            module: ModuleId(0),
                        },
                        source: span(2, 8),
                    },
                    Reexport {
                        local_name: Name::new("ready".to_owned()).expect("name"),
                        target: ReexportTarget::Variant(ResolvedVariant {
                            enumeration: enumeration.clone(),
                            variant: 0,
                        }),
                        source: span(9, 15),
                    },
                ],
                source,
            }],
            declarations: vec![Declaration {
                id: DeclarationId(0),
                module: ModuleId(0),
                owner: DeclarationOwner::Module(ModuleId(0)),
                name: Some(Name::new("Status".to_owned()).expect("name")),
                visibility: Visibility::Public,
                attributes: Vec::new(),
                kind: DeclarationKind::Enumeration(EnumDeclaration {
                    generics: Vec::new(),
                    variants: vec![EnumVariant {
                        name: Name::new("ready".to_owned()).expect("name"),
                        fields: Vec::new(),
                        source: span(20, 30),
                    }],
                    members: Vec::new(),
                    deriving: Vec::new(),
                }),
                source: span(16, 90),
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
        };
        program.clone().validate().expect("valid public imports");
        program.modules[0].reexports[1].target = ReexportTarget::Variant(ResolvedVariant {
            enumeration,
            variant: 1,
        });
        assert!(program.validate().is_err());
    }

    #[test]
    fn receiver_and_self_type_keep_implicit_and_explicit_provenance_distinct() {
        let path = ModulePath::new(["nominal".to_owned()]).expect("module path");
        let source = span(0, 100);
        let mut program = Program {
            packages: test_graph(&path),
            modules: vec![Module {
                id: ModuleId(0),
                package: PackageId(0),
                path,
                declarations: vec![DeclarationId(0)],
                reexports: Vec::new(),
                source,
            }],
            declarations: vec![
                Declaration {
                    id: DeclarationId(0),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Module(ModuleId(0)),
                    name: Some(Name::new("Boxed".to_owned()).expect("name")),
                    visibility: Visibility::Private,
                    attributes: Vec::new(),
                    kind: DeclarationKind::Structure(AggregateDeclaration {
                        generics: Vec::new(),
                        implements: Vec::new(),
                        fields: Vec::new(),
                        members: vec![DeclarationId(1)],
                        linear: false,
                        copy: false,
                        deriving: Vec::new(),
                    }),
                    source,
                },
                Declaration {
                    id: DeclarationId(1),
                    module: ModuleId(0),
                    owner: DeclarationOwner::Declaration(DeclarationId(0)),
                    name: Some(Name::new("identity".to_owned()).expect("name")),
                    visibility: Visibility::Private,
                    attributes: Vec::new(),
                    kind: DeclarationKind::Function(FunctionDeclaration {
                        color: FunctionColor::Sync,
                        generics: Vec::new(),
                        parameters: vec![ParameterId(0)],
                        result: Some(TypeExpression {
                            kind: TypeExpressionKind::SelfType {
                                owner: DeclarationId(0),
                            },
                            source: span(30, 34),
                        }),
                        body: None,
                    }),
                    source: span(20, 80),
                },
            ],
            generic_parameters: Vec::new(),
            parameters: vec![Parameter {
                id: ParameterId(0),
                owner: CallableOwner::Declaration(DeclarationId(1)),
                name: None,
                access: AccessMode::Read,
                ty: None,
                receiver: true,
                positional_only: false,
                source: span(24, 28),
            }],
            bodies: Vec::new(),
            scopes: Vec::new(),
            locals: Vec::new(),
            statements: Vec::new(),
            expressions: Vec::new(),
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        };
        program.clone().validate().expect("valid receiver and Self");
        let DeclarationKind::Function(function) = &mut program.declarations[1].kind else {
            unreachable!();
        };
        let Some(result) = &mut function.result else {
            unreachable!();
        };
        result.kind = TypeExpressionKind::SelfType {
            owner: DeclarationId(1),
        };
        assert!(program.validate().is_err());
    }

    #[test]
    fn explicit_shadowing_in_one_suite_has_an_exact_predecessor_link() {
        let path = ModulePath::new(["shadowing".to_owned()]).expect("module path");
        let source = span(0, 100);
        let mut program = Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("run".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Function(FunctionDeclaration {
                    color: FunctionColor::Sync,
                    generics: Vec::new(),
                    parameters: Vec::new(),
                    result: None,
                    body: Some(BodyId(0)),
                }),
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![Body {
                id: BodyId(0),
                owner: BodyOwner::Declaration(DeclarationId(0)),
                scope: ScopeId(0),
                locals: vec![LocalId(0), LocalId(1)],
                statements: vec![StatementId(0), StatementId(1)],
                source,
            }],
            scopes: vec![LexicalScope {
                id: ScopeId(0),
                body: BodyId(0),
                parent: None,
                source,
            }],
            locals: vec![
                Local {
                    id: LocalId(0),
                    body: BodyId(0),
                    scope: ScopeId(0),
                    name: Name::new("value".to_owned()).expect("name"),
                    ty: None,
                    shadowed: None,
                    source: span(10, 15),
                },
                Local {
                    id: LocalId(1),
                    body: BodyId(0),
                    scope: ScopeId(0),
                    name: Name::new("value".to_owned()).expect("name"),
                    ty: None,
                    shadowed: Some(LocalId(0)),
                    source: span(30, 35),
                },
            ],
            statements: vec![
                Statement {
                    id: StatementId(0),
                    body: BodyId(0),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(0),
                        value: ExpressionId(0),
                    },
                    source: span(10, 25),
                },
                Statement {
                    id: StatementId(1),
                    body: BodyId(0),
                    attributes: Vec::new(),
                    kind: StatementKind::Initialize {
                        local: LocalId(1),
                        value: ExpressionId(1),
                    },
                    source: span(30, 45),
                },
            ],
            expressions: vec![
                Expression {
                    id: ExpressionId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(20, 22),
                },
                Expression {
                    id: ExpressionId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(40, 42),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        };
        program.clone().validate().expect("valid explicit shadow");
        program.locals[1].shadowed = None;
        assert!(program.validate().is_err());
    }

    #[test]
    fn scope_enter_and_cleanup_share_the_setup_lexical_state() {
        let path = ModulePath::new(["scopes".to_owned()]).expect("module path");
        let source = span(0, 100);
        let mut program = Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("transaction".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Scope(ScopeDeclaration {
                    parameters: vec![ParameterId(0)],
                    result: TypeExpression {
                        kind: TypeExpressionKind::Named {
                            definition: Definition::Builtin(Builtin::Unit),
                            arguments: Vec::new(),
                        },
                        source: span(5, 9),
                    },
                    setup: BodyId(0),
                    enter: ExpressionId(0),
                    abort: Some(BodyId(1)),
                    exit_parameter: ParameterId(0),
                    exit: BodyId(2),
                }),
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: vec![Parameter {
                id: ParameterId(0),
                owner: CallableOwner::Declaration(DeclarationId(0)),
                name: Some(Name::new("replacement".to_owned()).expect("name")),
                access: AccessMode::Mutate,
                ty: None,
                receiver: false,
                positional_only: false,
                source: span(75, 86),
            }],
            bodies: vec![
                Body {
                    id: BodyId(0),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(0),
                    locals: vec![LocalId(0)],
                    statements: vec![StatementId(0)],
                    source: span(10, 60),
                },
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(1),
                    locals: Vec::new(),
                    statements: Vec::new(),
                    source: span(60, 74),
                },
                Body {
                    id: BodyId(2),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(2),
                    locals: Vec::new(),
                    statements: Vec::new(),
                    source: span(74, 95),
                },
            ],
            scopes: vec![
                LexicalScope {
                    id: ScopeId(0),
                    body: BodyId(0),
                    parent: None,
                    source: span(10, 60),
                },
                LexicalScope {
                    id: ScopeId(1),
                    body: BodyId(1),
                    parent: Some(ScopeId(0)),
                    source: span(60, 74),
                },
                LexicalScope {
                    id: ScopeId(2),
                    body: BodyId(2),
                    parent: Some(ScopeId(0)),
                    source: span(74, 95),
                },
            ],
            locals: vec![Local {
                id: LocalId(0),
                body: BodyId(0),
                scope: ScopeId(0),
                name: Name::new("prepared".to_owned()).expect("name"),
                ty: None,
                shadowed: None,
                source: span(20, 28),
            }],
            statements: vec![Statement {
                id: StatementId(0),
                body: BodyId(0),
                attributes: Vec::new(),
                kind: StatementKind::Initialize {
                    local: LocalId(0),
                    value: ExpressionId(1),
                },
                source: span(20, 40),
            }],
            expressions: vec![
                Expression {
                    id: ExpressionId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Reference(Definition::Local(LocalId(0))),
                    source: span(45, 53),
                },
                Expression {
                    id: ExpressionId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(30, 31),
                },
            ],
            patterns: Vec::new(),
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        };
        program.clone().validate().expect("valid scope phases");
        program.expressions[0].owner = ExpressionOwner::Declaration(DeclarationId(0));
        program.expressions[0].scope = None;
        assert!(program.validate().is_err());
    }

    #[test]
    fn contextual_payload_binding_is_confined_to_the_is_success_scope() {
        let path = ModulePath::new(["patterns".to_owned()]).expect("module path");
        let source = span(0, 100);
        let mut program = Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("inspect".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Function(FunctionDeclaration {
                    color: FunctionColor::Sync,
                    generics: Vec::new(),
                    parameters: Vec::new(),
                    result: None,
                    body: Some(BodyId(0)),
                }),
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![
                Body {
                    id: BodyId(0),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(0),
                    locals: vec![LocalId(0)],
                    statements: vec![StatementId(0)],
                    source,
                },
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(2),
                    locals: Vec::new(),
                    statements: Vec::new(),
                    source: span(50, 70),
                },
            ],
            scopes: vec![
                LexicalScope {
                    id: ScopeId(0),
                    body: BodyId(0),
                    parent: None,
                    source,
                },
                LexicalScope {
                    id: ScopeId(1),
                    body: BodyId(0),
                    parent: Some(ScopeId(0)),
                    source: span(18, 35),
                },
                LexicalScope {
                    id: ScopeId(2),
                    body: BodyId(1),
                    parent: Some(ScopeId(1)),
                    source: span(50, 70),
                },
            ],
            locals: vec![Local {
                id: LocalId(0),
                body: BodyId(0),
                scope: ScopeId(1),
                name: Name::new("payload".to_owned()).expect("name"),
                ty: None,
                shadowed: None,
                source: span(19, 23),
            }],
            statements: vec![Statement {
                id: StatementId(0),
                body: BodyId(0),
                attributes: Vec::new(),
                kind: StatementKind::If {
                    branches: vec![(ExpressionId(0), BodyId(1))],
                    else_body: None,
                },
                source: span(10, 70),
            }],
            expressions: vec![
                Expression {
                    id: ExpressionId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Binary {
                        operator: BinaryOperator::LogicalAnd,
                        left: ExpressionId(1),
                        right: ExpressionId(2),
                    },
                    source: span(12, 48),
                },
                Expression {
                    id: ExpressionId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::IsPattern {
                        value: ExpressionId(3),
                        negated: false,
                        pattern: PatternId(0),
                    },
                    source: span(14, 36),
                },
                Expression {
                    id: ExpressionId(2),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(1)),
                    kind: ExpressionKind::Reference(Definition::Local(LocalId(0))),
                    source: span(40, 47),
                },
                Expression {
                    id: ExpressionId(3),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    scope: Some(ScopeId(0)),
                    kind: ExpressionKind::Literal(Literal::Unit),
                    source: span(14, 15),
                },
            ],
            patterns: vec![
                Pattern {
                    id: PatternId(0),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    binding_scope: Some(ScopeId(1)),
                    alternatives: vec![
                        PatternAlternative {
                            kind: PrimaryPattern::Tuple(vec![PatternArgument {
                                take: false,
                                pattern: PatternId(1),
                                source: span(19, 23),
                            }]),
                            source: span(18, 24),
                        },
                        PatternAlternative {
                            kind: PrimaryPattern::Tuple(vec![PatternArgument {
                                take: false,
                                pattern: PatternId(2),
                                source: span(30, 34),
                            }]),
                            source: span(29, 35),
                        },
                    ],
                    source: span(18, 35),
                },
                Pattern {
                    id: PatternId(1),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    binding_scope: Some(ScopeId(1)),
                    alternatives: vec![PatternAlternative {
                        kind: PrimaryPattern::Bind(LocalId(0)),
                        source: span(19, 23),
                    }],
                    source: span(19, 23),
                },
                Pattern {
                    id: PatternId(2),
                    owner: ExpressionOwner::Body(BodyId(0)),
                    binding_scope: Some(ScopeId(1)),
                    alternatives: vec![PatternAlternative {
                        kind: PrimaryPattern::Bind(LocalId(0)),
                        source: span(30, 34),
                    }],
                    source: span(30, 34),
                },
            ],
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        };
        program.clone().validate().expect("valid success scope");
        program.expressions[2].scope = Some(ScopeId(0));
        assert!(program.validate().is_err());
    }

    #[test]
    fn names_share_the_exact_source_identifier_contract() {
        for accepted in ["start", "Δelta", "café", "变量", "a_1", "\u{1c89}name"] {
            assert_eq!(
                Name::new(accepted.to_owned()).expect("valid").as_str(),
                accepted
            );
        }
        for rejected in ["", "_", "fn", "1start", "e\u{301}", "a\u{200d}b"] {
            assert!(
                Name::new(rejected.to_owned()).is_err(),
                "accepted {rejected:?}"
            );
        }
        assert!(Name::new("a".repeat(256)).is_err());

        assert_eq!(
            Name::new_member("from".to_owned())
                .expect("generated conversion member")
                .as_str(),
            "from"
        );
        assert!(Name::new("from".to_owned()).is_err());
        assert!(Name::new_member("if".to_owned()).is_err());
    }

    #[test]
    fn resolves_manifest_entry_without_rebuilding_name_tables() {
        let path = ModulePath::new(["boot".to_owned()]).expect("module path");
        let graph = test_graph(&path);
        let source = span(0, 0);
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
                name: Some(Name::new("start".to_owned()).expect("name")),
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
            regions: Vec::new(),
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

    #[test]
    fn builtin_attributes_and_resolved_variants_have_explicit_identities() {
        let path = ModulePath::new(["status".to_owned()]).expect("module path");
        let source = span(0, 10);
        let program = Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("Status".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: vec![Attribute {
                    identity: AttributeIdentity::Builtin(BuiltinAttribute::Wire),
                    arguments: Vec::new(),
                    source,
                }],
                kind: DeclarationKind::Enumeration(EnumDeclaration {
                    generics: Vec::new(),
                    variants: vec![EnumVariant {
                        name: Name::new("ready".to_owned()).expect("variant"),
                        fields: Vec::new(),
                        source,
                    }],
                    members: Vec::new(),
                    deriving: Vec::new(),
                }),
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
            regions: Vec::new(),
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        }
        .validate()
        .expect("valid attributed enum");
        let enumeration = ResolvedDeclaration {
            package: PackageId(0),
            module: ModuleId(0),
            declaration: DeclarationId(0),
        };
        assert_eq!(
            program
                .resolved_variant(&ResolvedVariant {
                    enumeration: enumeration.clone(),
                    variant: 0,
                })
                .expect("variant")
                .name
                .as_str(),
            "ready"
        );
        assert!(
            program
                .resolved_variant(&ResolvedVariant {
                    enumeration,
                    variant: 1,
                })
                .is_none()
        );
    }

    #[test]
    fn with_region_is_a_fresh_lexical_brand_visible_in_its_child_body() {
        let path = ModulePath::new(["request".to_owned()]).expect("module path");
        let source = span(0, 20);
        let unit_type = || TypeExpression {
            kind: TypeExpressionKind::Named {
                definition: Definition::Builtin(Builtin::Unit),
                arguments: Vec::new(),
            },
            source,
        };
        let program = Program {
            packages: test_graph(&path),
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
                name: Some(Name::new("handle".to_owned()).expect("name")),
                visibility: Visibility::Private,
                attributes: Vec::new(),
                kind: DeclarationKind::Function(FunctionDeclaration {
                    color: FunctionColor::Sync,
                    generics: Vec::new(),
                    parameters: Vec::new(),
                    result: Some(unit_type()),
                    body: Some(BodyId(0)),
                }),
                source,
            }],
            generic_parameters: Vec::new(),
            parameters: Vec::new(),
            bodies: vec![
                Body {
                    id: BodyId(0),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(0),
                    locals: Vec::new(),
                    statements: vec![StatementId(0)],
                    source,
                },
                Body {
                    id: BodyId(1),
                    owner: BodyOwner::Declaration(DeclarationId(0)),
                    scope: ScopeId(1),
                    locals: vec![LocalId(0)],
                    statements: Vec::new(),
                    source,
                },
            ],
            scopes: vec![
                LexicalScope {
                    id: ScopeId(0),
                    body: BodyId(0),
                    parent: None,
                    source,
                },
                LexicalScope {
                    id: ScopeId(1),
                    body: BodyId(1),
                    parent: Some(ScopeId(0)),
                    source,
                },
            ],
            locals: vec![Local {
                id: LocalId(0),
                body: BodyId(1),
                scope: ScopeId(1),
                name: Name::new("value".to_owned()).expect("local"),
                ty: Some(TypeExpression {
                    kind: TypeExpressionKind::Named {
                        definition: Definition::Builtin(Builtin::Actor),
                        arguments: vec![GenericArgument {
                            kind: GenericArgumentKind::Region(RegionReference::Local(RegionId(0))),
                            source,
                        }],
                    },
                    source,
                }),
                shadowed: None,
                source,
            }],
            statements: vec![Statement {
                id: StatementId(0),
                body: BodyId(0),
                attributes: Vec::new(),
                kind: StatementKind::With {
                    value: ExpressionId(0),
                    binding: Some(LocalId(0)),
                    region: Some(RegionId(0)),
                    body: BodyId(1),
                },
                source,
            }],
            expressions: vec![Expression {
                id: ExpressionId(0),
                owner: ExpressionOwner::Body(BodyId(0)),
                scope: Some(ScopeId(0)),
                kind: ExpressionKind::Literal(Literal::Unit),
                source,
            }],
            patterns: Vec::new(),
            regions: vec![RegionBinding {
                id: RegionId(0),
                body: BodyId(1),
                name: Name::new("R".to_owned()).expect("region"),
                source: span(5, 6),
            }],
            image_candidates: Vec::new(),
            test_candidates: Vec::new(),
        };
        program.validate().expect("valid local region");
    }
}
