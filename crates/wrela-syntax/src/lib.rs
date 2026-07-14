//! Lossless, recoverable, typed abstract syntax for one Wrela source file.
//!
//! This is deliberately an AST, not a concrete-syntax tree. Every AST node
//! retains an exact token interval, while the ordered token/trivia table keeps
//! comments, literal spelling, parentheses, semicolons, and physical layout
//! available to the formatter without exposing parser implementation nodes.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_diagnostics::{Diagnostic, WithDiagnostics};
use wrela_source::{FileId, SourceDatabase, SourceFile, Span, TextRange};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(AstId);
id_type!(TokenId);
id_type!(TriviaId);

/// Hard implementation ceiling that keeps parser and validator recursion below
/// the process stack budget even when a caller supplies custom limits.
pub const MAX_PARSE_NESTING_DEPTH: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenRange {
    pub first: TokenId,
    /// Exclusive token index.
    pub end: TokenId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeMeta {
    pub id: AstId,
    pub span: Span,
    pub tokens: TokenRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Keyword {
    Module,
    Pub,
    Import,
    From,
    As,
    Const,
    Brand,
    Fn,
    Async,
    Isr,
    Comptime,
    Struct,
    Class,
    Enum,
    Iface,
    Impl,
    For,
    Projection,
    Scope,
    Implements,
    Region,
    View,
    Mut,
    Iso,
    Read,
    Take,
    SelfValue,
    If,
    Elif,
    Else,
    Match,
    Case,
    Bind,
    In,
    Not,
    While,
    Loop,
    With,
    Enter,
    Abort,
    Exit,
    Shadow,
    Return,
    Break,
    Continue,
    Pass,
    Assert,
    Send,
    Try,
    Yield,
    Await,
    Copy,
    Race,
    True,
    False,
    Unit,
    Or,
    And,
    Is,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Punctuation {
    At,
    Dot,
    Comma,
    Colon,
    Semicolon,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    LeftBrace,
    RightBrace,
    Arrow,
    Question,
    Pipe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
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
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    AddAssign,
    SubtractAssign,
    MultiplyAssign,
    DivideAssign,
    RemainderAssign,
    BitAndAssign,
    BitOrAssign,
    BitXorAssign,
    ShiftLeftAssign,
    ShiftRightAssign,
    AddWrapping,
    SubtractWrapping,
    MultiplyWrapping,
    BitNot,
    Range,
    RangeInclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Identifier,
    IntegerLiteral,
    FloatLiteral,
    StringLiteral,
    ByteStringLiteral,
    CharacterLiteral,
    InterpolatedString,
    Keyword(Keyword),
    Punctuation(Punctuation),
    Operator(Operator),
    Newline,
    Indent,
    Dedent,
    EndOfFile,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NewlineOrigin {
    Physical,
    Semicolon,
    EndOfFile,
    SyntheticRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub id: TokenId,
    pub kind: TokenKind,
    pub span: Span,
    pub newline_origin: Option<NewlineOrigin>,
    /// Literal/identifier raw spelling. Other token text is determined by kind.
    pub spelling: Option<String>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriviaKind {
    Spaces,
    Comment,
    SuppressedPhysicalNewline,
    BlankLine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trivia {
    pub id: TriviaId,
    pub kind: TriviaKind,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LexicalElement {
    Token(TokenId),
    Trivia(TriviaId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LosslessLexicalTable {
    pub tokens: Vec<Token>,
    pub trivia: Vec<Trivia>,
    pub order: Vec<LexicalElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    pub meta: NodeMeta,
    pub spelling: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    pub meta: NodeMeta,
    pub segments: Vec<Identifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AstFile {
    pub meta: NodeMeta,
    pub module: Option<ModuleDeclaration>,
    pub imports: Vec<ImportDeclaration>,
    pub declarations: Vec<TopLevelDeclaration>,
    pub recovery_nodes: Vec<ErrorNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDeclaration {
    pub meta: NodeMeta,
    pub path: QualifiedName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportItems {
    Module {
        path: QualifiedName,
        alias: Option<Identifier>,
    },
    Names {
        module: QualifiedName,
        names: Vec<ImportedName>,
        parenthesized: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedName {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub alias: Option<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDeclaration {
    pub meta: NodeMeta,
    pub public: bool,
    pub items: ImportItems,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub meta: NodeMeta,
    pub name: QualifiedName,
    pub arguments: Vec<AttributeArgument>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeArgument {
    pub meta: NodeMeta,
    pub name: Option<Identifier>,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TopLevelDeclaration {
    pub meta: NodeMeta,
    pub attributes: Vec<Attribute>,
    pub public: bool,
    pub kind: DeclarationKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeclarationKind {
    Constant(ConstantDeclaration),
    Brand(BrandDeclaration),
    Function(FunctionDeclaration),
    Structure(TypeDeclaration),
    Class(TypeDeclaration),
    Enumeration(EnumDeclaration),
    Interface(InterfaceDeclaration),
    Implementation(ImplementationDeclaration),
    Projection(ProjectionDeclaration),
    Scope(ScopeDeclaration),
    ComptimeIf(ComptimeDeclarationIf),
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConstantDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub ty: Option<TypeExpression>,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionColor {
    Sync,
    Async,
    Isr,
    Comptime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDeclaration {
    pub meta: NodeMeta,
    pub color: FunctionColor,
    pub name: Identifier,
    pub generics: Vec<GenericParameter>,
    pub parameters: Vec<Parameter>,
    pub return_type: Option<TypeExpression>,
    pub body: Option<Suite>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GenericParameter {
    Type {
        meta: NodeMeta,
        name: Identifier,
        bound: Option<TypeExpression>,
    },
    Constant {
        meta: NodeMeta,
        name: Identifier,
        ty: TypeExpression,
    },
    Region {
        meta: NodeMeta,
        name: Identifier,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Value,
    Read,
    Mutate,
    Take,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub meta: NodeMeta,
    pub access: AccessMode,
    pub name: Identifier,
    pub ty: Option<TypeExpression>,
    pub receiver: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub generics: Vec<GenericParameter>,
    pub implements: Vec<TypeExpression>,
    pub members: Vec<MemberDeclaration>,
    pub explicit_pass: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemberDeclaration {
    pub meta: NodeMeta,
    pub attributes: Vec<Attribute>,
    pub public: bool,
    pub kind: MemberKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemberKind {
    Field(FieldDeclaration),
    Function(FunctionDeclaration),
    Projection(ProjectionDeclaration),
    Scope(ScopeDeclaration),
    Constant(ConstantDeclaration),
    ComptimeIf(ComptimeMemberIf),
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub ty: TypeExpression,
    pub default: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub generics: Vec<GenericParameter>,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub payload: EnumPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnumPayload {
    None,
    Positional(Vec<TypeExpression>),
    Named(Vec<VariantField>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariantField {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub ty: TypeExpression,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub generics: Vec<GenericParameter>,
    pub members: Vec<InterfaceMember>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceMember {
    Function {
        attributes: Vec<Attribute>,
        declaration: FunctionDeclaration,
    },
    Projection {
        attributes: Vec<Attribute>,
        declaration: ProjectionDeclaration,
    },
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImplementationDeclaration {
    pub meta: NodeMeta,
    pub interface: TypeExpression,
    pub implementing_type: TypeExpression,
    pub members: Vec<MemberDeclaration>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectionDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub generics: Vec<GenericParameter>,
    pub parameters: Vec<Parameter>,
    pub carrier: ProjectionCarrier,
    pub provenance: Vec<Identifier>,
    pub body: Option<Suite>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectionCarrier {
    View {
        meta: NodeMeta,
        mutable: bool,
        ty: Box<TypeExpression>,
    },
    Tuple {
        meta: NodeMeta,
        elements: Vec<ProjectionCarrier>,
    },
    Option {
        meta: NodeMeta,
        carrier: Box<ProjectionCarrier>,
    },
    Result {
        meta: NodeMeta,
        carrier: Box<ProjectionCarrier>,
        error: Box<TypeExpression>,
    },
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopeDeclaration {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub parameters: Vec<Parameter>,
    pub return_type: TypeExpression,
    pub setup: Vec<Statement>,
    pub enter: Expression,
    pub abort: Option<Suite>,
    pub exit_binding: Identifier,
    pub exit: Suite,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComptimeDeclarationIf {
    pub meta: NodeMeta,
    pub condition: Expression,
    pub then_declarations: Vec<TopLevelDeclaration>,
    pub else_declarations: Vec<TopLevelDeclaration>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComptimeMemberIf {
    pub meta: NodeMeta,
    pub condition: Expression,
    pub then_members: Vec<MemberDeclaration>,
    pub else_members: Vec<MemberDeclaration>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Suite {
    pub meta: NodeMeta,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub meta: NodeMeta,
    pub attributes: Vec<Attribute>,
    pub kind: StatementKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatementKind {
    LocalAssignment {
        shadow: bool,
        name: Identifier,
        ty: Option<TypeExpression>,
        value: Expression,
    },
    PlaceAssignment {
        target: AssignmentTarget,
        operator: AssignmentOperator,
        value: Expression,
    },
    Return(Option<Expression>),
    Break,
    Continue,
    Pass,
    Assert {
        condition: Expression,
        message: Option<Literal>,
    },
    Send(Expression),
    Yield(Expression),
    ComptimeAssert {
        condition: Expression,
        message: Option<Literal>,
    },
    Expression(Expression),
    If(IfStatement),
    Match {
        scrutinee: Expression,
        arms: Vec<MatchArm>,
    },
    For {
        take_binding: bool,
        binding: Identifier,
        take_iterable: bool,
        iterable: Expression,
        body: Suite,
    },
    While {
        condition: Expression,
        body: Suite,
    },
    Loop(Suite),
    With {
        value: Expression,
        binding: Option<WithBinding>,
        body: Suite,
    },
    ComptimeIf {
        condition: Expression,
        then_suite: Suite,
        else_suite: Option<Suite>,
    },
    Error(ErrorNode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub enum AssignmentTarget {
    Place(Expression),
    Tuple {
        meta: NodeMeta,
        elements: Vec<AssignmentTarget>,
    },
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IfStatement {
    pub condition: Expression,
    pub then_suite: Suite,
    pub elif: Vec<(Expression, Suite)>,
    pub else_suite: Option<Suite>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub meta: NodeMeta,
    pub pattern: Pattern,
    pub guard: Option<Expression>,
    pub body: Suite,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithBinding {
    pub meta: NodeMeta,
    pub name: Identifier,
    pub region: Option<Identifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub meta: NodeMeta,
    pub kind: ExpressionKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExpressionKind {
    Literal(Literal),
    Name(QualifiedName),
    Closure {
        asynchronous: bool,
        take_captures: bool,
        parameters: Vec<Parameter>,
        body: ClosureBody,
    },
    Unary {
        operator: UnaryOperator,
        operand: Box<Expression>,
    },
    Binary {
        operator: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Comparison {
        first: Box<Expression>,
        tails: Vec<ComparisonTail>,
    },
    IsPattern {
        value: Box<Expression>,
        negated: bool,
        pattern: Box<Pattern>,
    },
    Range {
        start: Box<Expression>,
        end: Box<Expression>,
        inclusive: bool,
    },
    Cast {
        value: Box<Expression>,
        ty: Box<TypeExpression>,
    },
    Try(Box<Expression>),
    Field {
        base: Box<Expression>,
        field: Identifier,
    },
    Call {
        callee: Box<Expression>,
        arguments: Vec<Argument>,
    },
    Index {
        base: Box<Expression>,
        index: Box<Expression>,
    },
    Parenthesized(Box<Expression>),
    Tuple(Vec<Expression>),
    Array(Vec<Expression>),
    Race(Vec<Expression>),
    TrySend(Box<Expression>),
    Interpolated(Vec<InterpolationPart>),
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClosureBody {
    Expression(Box<Expression>),
    Suite(Suite),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    Negate,
    BitNot,
    BoolNot,
    Await,
    Take,
    Copy,
    Comptime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub struct ComparisonTail {
    pub operator: ComparisonOperator,
    pub right: Expression,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Argument {
    pub meta: NodeMeta,
    pub name: Option<Identifier>,
    pub access: AccessMode,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterpolationPart {
    Text {
        span: Span,
        decoded: String,
    },
    Value {
        expression: Expression,
        format: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    pub meta: NodeMeta,
    pub kind: LiteralKind,
    /// Exact source spelling, retained independently of decoded value.
    pub spelling: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiteralKind {
    Integer,
    Float,
    String,
    ByteString,
    Character,
    Boolean,
    Unit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub meta: NodeMeta,
    pub alternatives: Vec<PrimaryPattern>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrimaryPattern {
    Wildcard(NodeMeta),
    Literal {
        negative: bool,
        literal: Literal,
    },
    Constructor {
        name: QualifiedName,
        arguments: Vec<PatternArgument>,
    },
    Bind(Identifier),
    Tuple {
        meta: NodeMeta,
        elements: Vec<PatternArgument>,
    },
    Array {
        meta: NodeMeta,
        elements: Vec<PatternArgument>,
    },
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatternArgument {
    pub meta: NodeMeta,
    pub take: bool,
    pub pattern: Pattern,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeExpression {
    pub meta: NodeMeta,
    pub kind: TypeExpressionKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeExpressionKind {
    Named {
        name: QualifiedName,
        arguments: Vec<BracketArgument>,
    },
    Array {
        element: Box<TypeExpression>,
        length: Box<Expression>,
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
        asynchronous: bool,
        parameters: Vec<FunctionTypeParameter>,
        result: Box<TypeExpression>,
    },
    Error(ErrorNode),
}

/// Parsing intentionally does not guess whether a bracket argument is a type
/// or constant. HIR lowering classifies it from the resolved generic kind.
#[derive(Debug, Clone, PartialEq)]
pub enum BracketArgument {
    UnclassifiedTypeOrExpression { meta: NodeMeta, tokens: TokenRange },
    BoundedCapacity { meta: NodeMeta, maximum: Expression },
    Error(ErrorNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionTypeParameter {
    pub meta: NodeMeta,
    pub access: AccessMode,
    pub ty: TypeExpression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorNode {
    pub meta: NodeMeta,
    pub expected: Vec<String>,
}

/// Candidate assembled by a parser implementation before cross-checking.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedFileCandidate {
    pub file: FileId,
    pub source_digest: Sha256Digest,
    pub lexical: LosslessLexicalTable,
    pub ast: AstFile,
    /// False only when a hard resource bound stopped recovery before EOF.
    pub recovery_complete: bool,
}

/// Recoverably parsed contents of exactly one source file. Private fields make
/// successful validation durable across every consumer boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedFile {
    file: FileId,
    source_digest: Sha256Digest,
    lexical: LosslessLexicalTable,
    ast: AstFile,
    recovery_complete: bool,
    node_ranges: Vec<TextRange>,
}

impl ParsedFile {
    #[must_use]
    pub fn file(&self) -> FileId {
        self.file
    }

    #[must_use]
    pub fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }

    #[must_use]
    pub fn lexical(&self) -> &LosslessLexicalTable {
        &self.lexical
    }

    #[must_use]
    pub fn ast(&self) -> &AstFile {
        &self.ast
    }

    #[must_use]
    pub fn recovery_complete(&self) -> bool {
        self.recovery_complete
    }

    /// Select the smallest AST node that encloses a requested source range.
    /// Ties are broken by dense AST ID, making range formatting deterministic.
    #[must_use]
    pub fn smallest_enclosing_node(&self, requested: TextRange) -> Option<TextRange> {
        self.node_ranges
            .iter()
            .copied()
            .filter(|range| range.start <= requested.start && range.end >= requested.end)
            .min_by_key(|range| (range.end - range.start, range.start, range.end))
    }
}

/// Atomic recoverable parser product: a structurally validated parsed file and
/// its canonical diagnostics can never be replaced independently.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseOutput {
    parsed: ParsedFile,
    diagnostics: Vec<Diagnostic>,
}

impl ParseOutput {
    #[must_use]
    pub fn parsed(&self) -> &ParsedFile {
        &self.parsed
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn into_parts(self) -> (ParsedFile, Vec<Diagnostic>) {
        (self.parsed, self.diagnostics)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    pub tokens: u32,
    pub ast_nodes: u32,
    pub nesting_depth: u32,
    pub literal_bytes: u64,
    pub diagnostics: u32,
    pub diagnostic_bytes: u64,
}

impl ParseLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            tokens: 16_000_000,
            ast_nodes: 16_000_000,
            nesting_depth: MAX_PARSE_NESTING_DEPTH,
            literal_bytes: 1 << 30,
            diagnostics: 100_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), ParseFailure> {
        if self.tokens == 0
            || self.ast_nodes == 0
            || self.nesting_depth == 0
            || self.literal_bytes == 0
            || self.diagnostics == 0
            || self.diagnostic_bytes == 0
            || self.nesting_depth > MAX_PARSE_NESTING_DEPTH
        {
            Err(ParseFailure::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct ParseRequest<'a> {
    pub sources: &'a SourceDatabase,
    pub file: FileId,
    pub limits: ParseLimits,
}

/// Validate and atomically seal a parser implementation's complete output.
pub fn seal_parse_output(
    request: &ParseRequest<'_>,
    candidate: ParsedFileCandidate,
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ParseOutput, ParseFailure> {
    if is_cancelled() {
        return Err(ParseFailure::Cancelled);
    }
    request.limits.validate()?;
    let source = request
        .sources
        .get(request.file)
        .ok_or(ParseFailure::UnknownSource(request.file))?;
    if candidate.file != request.file || candidate.source_digest != source.digest() {
        return Err(ParseFailure::StaleOutput(request.file));
    }
    validate_lexical_table(
        &candidate.lexical,
        source,
        candidate.recovery_complete,
        request.limits,
    )?;
    let node_ranges = validate_ast(
        &candidate.ast,
        &candidate.lexical,
        source,
        candidate.recovery_complete,
        request.limits,
    )?;
    let diagnostics = validate_parse_diagnostics(diagnostics, source, request.limits)?;
    if is_cancelled() {
        return Err(ParseFailure::Cancelled);
    }
    Ok(ParseOutput {
        parsed: ParsedFile {
            file: candidate.file,
            source_digest: candidate.source_digest,
            lexical: candidate.lexical,
            ast: candidate.ast,
            recovery_complete: candidate.recovery_complete,
            node_ranges,
        },
        diagnostics,
    })
}

fn validate_lexical_table(
    lexical: &LosslessLexicalTable,
    source: &SourceFile,
    recovery_complete: bool,
    limits: ParseLimits,
) -> Result<(), ParseFailure> {
    if lexical.tokens.is_empty() || lexical.tokens.len() > limits.tokens as usize {
        return Err(ParseFailure::ResourceLimit {
            resource: "tokens",
            limit: u64::from(limits.tokens),
        });
    }
    let mut literal_bytes = 0u64;
    for (index, token) in lexical.tokens.iter().enumerate() {
        if token.id.0 as usize != index || !valid_span(source, token.span) {
            return Err(ParseFailure::InternalInvariant(
                "token IDs or spans are invalid".to_owned(),
            ));
        }
        let empty = token.span.range.start == token.span.range.end;
        if token.synthetic != empty {
            return Err(ParseFailure::InternalInvariant(
                "structural token synthesis disagrees with its empty span".to_owned(),
            ));
        }
        if matches!(token.kind, TokenKind::EndOfFile) && (!token.synthetic || !empty) {
            return Err(ParseFailure::InternalInvariant(
                "EOF must be one synthetic empty token".to_owned(),
            ));
        }
        if matches!(token.kind, TokenKind::Newline) != token.newline_origin.is_some()
            || token.newline_origin.is_some_and(|origin| {
                origin == NewlineOrigin::SyntheticRecovery && !token.synthetic
            })
        {
            return Err(ParseFailure::InternalInvariant(
                "newline origin is inconsistent".to_owned(),
            ));
        }
        let carries_spelling = matches!(
            token.kind,
            TokenKind::Identifier
                | TokenKind::IntegerLiteral
                | TokenKind::FloatLiteral
                | TokenKind::StringLiteral
                | TokenKind::ByteStringLiteral
                | TokenKind::CharacterLiteral
                | TokenKind::InterpolatedString
                | TokenKind::Error
        );
        if carries_spelling != token.spelling.is_some() {
            return Err(ParseFailure::InternalInvariant(
                "token raw spelling is missing or attached to a derived token".to_owned(),
            ));
        }
        if let Some(spelling) = &token.spelling {
            if !token.synthetic && source.slice(token.span.range) != Some(spelling.as_str()) {
                return Err(ParseFailure::InternalInvariant(
                    "token spelling differs from source bytes".to_owned(),
                ));
            }
            if matches!(
                token.kind,
                TokenKind::IntegerLiteral
                    | TokenKind::FloatLiteral
                    | TokenKind::StringLiteral
                    | TokenKind::ByteStringLiteral
                    | TokenKind::CharacterLiteral
                    | TokenKind::InterpolatedString
            ) {
                literal_bytes = literal_bytes
                    .checked_add(u64::try_from(spelling.len()).map_err(|_| {
                        ParseFailure::InternalInvariant(
                            "literal byte count does not fit u64".to_owned(),
                        )
                    })?)
                    .ok_or(ParseFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: limits.literal_bytes,
                    })?;
            }
        }
    }
    if literal_bytes > limits.literal_bytes
        || lexical
            .tokens
            .iter()
            .filter(|token| token.kind == TokenKind::EndOfFile)
            .count()
            != 1
        || lexical.tokens.last().map(|token| token.kind) != Some(TokenKind::EndOfFile)
        || lexical.trivia.iter().enumerate().any(|(index, trivia)| {
            trivia.id.0 as usize != index
                || !valid_span(source, trivia.span)
                || trivia.span.range.start == trivia.span.range.end
        })
    {
        return Err(ParseFailure::InternalInvariant(
            "lexical table limits, IDs, or EOF are invalid".to_owned(),
        ));
    }

    let mut next_token = 0usize;
    let mut next_trivia = 0usize;
    let mut cursor = 0u32;
    for element in &lexical.order {
        let (range, synthetic) = match *element {
            LexicalElement::Token(id) => {
                if id.0 as usize != next_token {
                    return Err(ParseFailure::InternalInvariant(
                        "token order is not canonical".to_owned(),
                    ));
                }
                next_token += 1;
                let token = &lexical.tokens[id.0 as usize];
                (token.span.range, token.synthetic)
            }
            LexicalElement::Trivia(id) => {
                if id.0 as usize != next_trivia {
                    return Err(ParseFailure::InternalInvariant(
                        "trivia order is not canonical".to_owned(),
                    ));
                }
                next_trivia += 1;
                (lexical.trivia[id.0 as usize].span.range, false)
            }
        };
        if range.start != cursor || (!synthetic && range.end == range.start) {
            return Err(ParseFailure::InternalInvariant(
                "lossless lexical order has a gap, overlap, or empty physical element".to_owned(),
            ));
        }
        cursor = range.end;
    }
    let source_bytes = u32::try_from(source.text().len()).map_err(|_| {
        ParseFailure::InternalInvariant("source length does not fit u32".to_owned())
    })?;
    if next_token != lexical.tokens.len()
        || next_trivia != lexical.trivia.len()
        || lexical.order.last()
            != Some(&LexicalElement::Token(TokenId(
                u32::try_from(lexical.tokens.len() - 1).map_err(|_| {
                    ParseFailure::InternalInvariant("token count does not fit u32".to_owned())
                })?,
            )))
        || (recovery_complete && cursor != source_bytes)
        || cursor > source_bytes
    {
        return Err(ParseFailure::InternalInvariant(
            "lossless lexical table does not cover its declared source prefix".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ast(
    ast: &AstFile,
    lexical: &LosslessLexicalTable,
    source: &SourceFile,
    recovery_complete: bool,
    limits: ParseLimits,
) -> Result<Vec<TextRange>, ParseFailure> {
    let seen_len = usize::try_from(limits.ast_nodes).map_err(|_| ParseFailure::InvalidLimits)?;
    let mut validator = AstValidator {
        source,
        lexical,
        limits,
        seen: vec![false; seen_len],
        nodes: 0,
        maximum_id: 0,
        ranges: Vec::new(),
    };
    validator.file(ast, 1, None)?;
    if validator.nodes == 0
        || validator.maximum_id.checked_add(1) != Some(validator.nodes)
        || validator.seen[..validator.nodes as usize]
            .iter()
            .any(|seen| !seen)
    {
        return Err(ParseFailure::InternalInvariant(
            "AST IDs are not a dense zero-based set".to_owned(),
        ));
    }
    let eof = lexical
        .tokens
        .last()
        .ok_or_else(|| ParseFailure::InternalInvariant("AST has no EOF token".to_owned()))?;
    if ast.meta.id != AstId(0)
        || ast.meta.span.range.start != 0
        || ast.meta.span.range.end != eof.span.range.end
        || ast.meta.tokens.first != TokenId(0)
        || ast.meta.tokens.end.0 as usize != lexical.tokens.len()
        || (recovery_complete && ast.meta.span.range.end as usize != source.text().len())
    {
        return Err(ParseFailure::InternalInvariant(
            "file AST does not exactly cover its parsed source prefix".to_owned(),
        ));
    }
    validator.ranges.sort_by_key(|(id, _)| *id);
    Ok(validator
        .ranges
        .into_iter()
        .map(|(_, range)| range)
        .collect())
}

struct AstValidator<'a> {
    source: &'a SourceFile,
    lexical: &'a LosslessLexicalTable,
    limits: ParseLimits,
    seen: Vec<bool>,
    nodes: u32,
    maximum_id: u32,
    ranges: Vec<(u32, TextRange)>,
}

impl AstValidator<'_> {
    fn meta(
        &mut self,
        meta: NodeMeta,
        depth: u32,
        parent: Option<NodeMeta>,
    ) -> Result<NodeMeta, ParseFailure> {
        if depth > self.limits.nesting_depth {
            return Err(ParseFailure::ResourceLimit {
                resource: "AST nesting depth",
                limit: u64::from(self.limits.nesting_depth),
            });
        }
        let id = meta.id.0 as usize;
        if id >= self.seen.len() || self.seen[id] {
            return Err(ParseFailure::InternalInvariant(
                "AST node ID is duplicated or outside its limit".to_owned(),
            ));
        }
        if !valid_span(self.source, meta.span)
            || meta.tokens.first.0 > meta.tokens.end.0
            || meta.tokens.end.0 as usize > self.lexical.tokens.len()
        {
            return Err(ParseFailure::InternalInvariant(
                "AST node span or token interval is invalid".to_owned(),
            ));
        }
        if let Some(parent) = parent
            && (meta.span.file != parent.span.file
                || meta.span.range.start < parent.span.range.start
                || meta.span.range.end > parent.span.range.end
                || meta.tokens.first.0 < parent.tokens.first.0
                || meta.tokens.end.0 > parent.tokens.end.0)
        {
            return Err(ParseFailure::InternalInvariant(
                "AST child escapes its parent span or token interval".to_owned(),
            ));
        }
        if meta.tokens.first.0 < meta.tokens.end.0 {
            let first = &self.lexical.tokens[meta.tokens.first.0 as usize];
            let last = &self.lexical.tokens[meta.tokens.end.0 as usize - 1];
            if first.span.range.start < meta.span.range.start
                || last.span.range.end > meta.span.range.end
            {
                return Err(ParseFailure::InternalInvariant(
                    "AST token interval escapes its source span".to_owned(),
                ));
            }
        }
        self.seen[id] = true;
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                limit: u64::from(self.limits.ast_nodes),
            })?;
        self.maximum_id = self.maximum_id.max(meta.id.0);
        self.ranges.push((meta.id.0, meta.span.range));
        Ok(meta)
    }

    fn file(
        &mut self,
        value: &AstFile,
        depth: u32,
        parent: Option<NodeMeta>,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, parent)?;
        if let Some(module) = &value.module {
            self.module(module, depth + 1, parent)?;
        }
        for import in &value.imports {
            self.import(import, depth + 1, parent)?;
        }
        for declaration in &value.declarations {
            self.top_level(declaration, depth + 1, parent)?;
        }
        for error in &value.recovery_nodes {
            self.error(error, depth + 1, parent)?;
        }
        Ok(())
    }

    fn identifier(
        &mut self,
        value: &Identifier,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let meta = self.meta(value.meta, depth, Some(parent))?;
        if value.spelling.is_empty() {
            return Err(ParseFailure::InternalInvariant(
                "identifier spelling is empty".to_owned(),
            ));
        }
        let source_spelling = self.source.slice(meta.span.range);
        let synthetic_spelling = (meta.tokens.end.0 == meta.tokens.first.0 + 1)
            .then(|| &self.lexical.tokens[meta.tokens.first.0 as usize])
            .filter(|token| token.synthetic && token.kind == TokenKind::Identifier)
            .and_then(|token| token.spelling.as_deref());
        if source_spelling != Some(value.spelling.as_str())
            && synthetic_spelling != Some(value.spelling.as_str())
        {
            return Err(ParseFailure::InternalInvariant(
                "identifier spelling differs from its token/source interval".to_owned(),
            ));
        }
        Ok(())
    }

    fn qualified(
        &mut self,
        value: &QualifiedName,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        if value.segments.is_empty() {
            return Err(ParseFailure::InternalInvariant(
                "qualified name has no segments".to_owned(),
            ));
        }
        for segment in &value.segments {
            self.identifier(segment, depth + 1, parent)?;
        }
        Ok(())
    }

    fn module(
        &mut self,
        value: &ModuleDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.qualified(&value.path, depth + 1, parent)
    }

    fn import(
        &mut self,
        value: &ImportDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        match &value.items {
            ImportItems::Module { path, alias } => {
                self.qualified(path, depth + 1, parent)?;
                if let Some(alias) = alias {
                    self.identifier(alias, depth + 1, parent)?;
                }
            }
            ImportItems::Names { module, names, .. } => {
                self.qualified(module, depth + 1, parent)?;
                if names.is_empty() {
                    return Err(ParseFailure::InternalInvariant(
                        "from-import has no names".to_owned(),
                    ));
                }
                for name in names {
                    let name_parent = self.meta(name.meta, depth + 1, Some(parent))?;
                    self.identifier(&name.name, depth + 2, name_parent)?;
                    if let Some(alias) = &name.alias {
                        self.identifier(alias, depth + 2, name_parent)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn attribute(
        &mut self,
        value: &Attribute,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.qualified(&value.name, depth + 1, parent)?;
        for argument in &value.arguments {
            let argument_parent = self.meta(argument.meta, depth + 1, Some(parent))?;
            if let Some(name) = &argument.name {
                self.identifier(name, depth + 2, argument_parent)?;
            }
            self.expression(&argument.value, depth + 2, argument_parent)?;
        }
        Ok(())
    }

    fn attributes(
        &mut self,
        values: &[Attribute],
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        for value in values {
            self.attribute(value, depth, parent)?;
        }
        Ok(())
    }

    fn top_level(
        &mut self,
        value: &TopLevelDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.attributes(&value.attributes, depth + 1, parent)?;
        match &value.kind {
            DeclarationKind::Constant(value) => self.constant(value, depth + 1, parent),
            DeclarationKind::Brand(value) => {
                let inner = self.meta(value.meta, depth + 1, Some(parent))?;
                self.identifier(&value.name, depth + 2, inner)
            }
            DeclarationKind::Function(value) => self.function(value, depth + 1, parent),
            DeclarationKind::Structure(value) | DeclarationKind::Class(value) => {
                self.type_declaration(value, depth + 1, parent)
            }
            DeclarationKind::Enumeration(value) => self.enumeration(value, depth + 1, parent),
            DeclarationKind::Interface(value) => self.interface(value, depth + 1, parent),
            DeclarationKind::Implementation(value) => self.implementation(value, depth + 1, parent),
            DeclarationKind::Projection(value) => self.projection(value, depth + 1, parent),
            DeclarationKind::Scope(value) => self.scope(value, depth + 1, parent),
            DeclarationKind::ComptimeIf(value) => {
                let inner = self.meta(value.meta, depth + 1, Some(parent))?;
                self.expression(&value.condition, depth + 2, inner)?;
                for declaration in &value.then_declarations {
                    self.top_level(declaration, depth + 2, inner)?;
                }
                for declaration in &value.else_declarations {
                    self.top_level(declaration, depth + 2, inner)?;
                }
                Ok(())
            }
            DeclarationKind::Error(value) => self.error(value, depth + 1, parent),
        }
    }

    fn constant(
        &mut self,
        value: &ConstantDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        if let Some(ty) = &value.ty {
            self.ty(ty, depth + 1, parent)?;
        }
        self.expression(&value.value, depth + 1, parent)
    }

    fn generic(
        &mut self,
        value: &GenericParameter,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        match value {
            GenericParameter::Type { meta, name, bound } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.identifier(name, depth + 1, parent)?;
                if let Some(bound) = bound {
                    self.ty(bound, depth + 1, parent)?;
                }
            }
            GenericParameter::Constant { meta, name, ty } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.identifier(name, depth + 1, parent)?;
                self.ty(ty, depth + 1, parent)?;
            }
            GenericParameter::Region { meta, name } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.identifier(name, depth + 1, parent)?;
            }
        }
        Ok(())
    }

    fn parameter(
        &mut self,
        value: &Parameter,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        if let Some(ty) = &value.ty {
            self.ty(ty, depth + 1, parent)?;
        }
        Ok(())
    }

    fn function(
        &mut self,
        value: &FunctionDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for generic in &value.generics {
            self.generic(generic, depth + 1, parent)?;
        }
        for parameter in &value.parameters {
            self.parameter(parameter, depth + 1, parent)?;
        }
        if let Some(ty) = &value.return_type {
            self.ty(ty, depth + 1, parent)?;
        }
        if let Some(body) = &value.body {
            self.suite(body, depth + 1, parent)?;
        }
        Ok(())
    }

    fn type_declaration(
        &mut self,
        value: &TypeDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for generic in &value.generics {
            self.generic(generic, depth + 1, parent)?;
        }
        for implementation in &value.implements {
            self.ty(implementation, depth + 1, parent)?;
        }
        for member in &value.members {
            self.member(member, depth + 1, parent)?;
        }
        Ok(())
    }

    fn member(
        &mut self,
        value: &MemberDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.attributes(&value.attributes, depth + 1, parent)?;
        match &value.kind {
            MemberKind::Field(value) => self.field(value, depth + 1, parent),
            MemberKind::Function(value) => self.function(value, depth + 1, parent),
            MemberKind::Projection(value) => self.projection(value, depth + 1, parent),
            MemberKind::Scope(value) => self.scope(value, depth + 1, parent),
            MemberKind::Constant(value) => self.constant(value, depth + 1, parent),
            MemberKind::ComptimeIf(value) => {
                let inner = self.meta(value.meta, depth + 1, Some(parent))?;
                self.expression(&value.condition, depth + 2, inner)?;
                for member in &value.then_members {
                    self.member(member, depth + 2, inner)?;
                }
                for member in &value.else_members {
                    self.member(member, depth + 2, inner)?;
                }
                Ok(())
            }
            MemberKind::Error(value) => self.error(value, depth + 1, parent),
        }
    }

    fn field(
        &mut self,
        value: &FieldDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        self.ty(&value.ty, depth + 1, parent)?;
        if let Some(default) = &value.default {
            self.expression(default, depth + 1, parent)?;
        }
        Ok(())
    }

    fn enumeration(
        &mut self,
        value: &EnumDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for generic in &value.generics {
            self.generic(generic, depth + 1, parent)?;
        }
        for variant in &value.variants {
            let variant_parent = self.meta(variant.meta, depth + 1, Some(parent))?;
            self.identifier(&variant.name, depth + 2, variant_parent)?;
            match &variant.payload {
                EnumPayload::None => {}
                EnumPayload::Positional(types) => {
                    for ty in types {
                        self.ty(ty, depth + 2, variant_parent)?;
                    }
                }
                EnumPayload::Named(fields) => {
                    for field in fields {
                        let field_parent =
                            self.meta(field.meta, depth + 2, Some(variant_parent))?;
                        self.identifier(&field.name, depth + 3, field_parent)?;
                        self.ty(&field.ty, depth + 3, field_parent)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn interface(
        &mut self,
        value: &InterfaceDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for generic in &value.generics {
            self.generic(generic, depth + 1, parent)?;
        }
        for member in &value.members {
            match member {
                InterfaceMember::Function {
                    attributes,
                    declaration,
                } => {
                    self.attributes(attributes, depth + 1, parent)?;
                    self.function(declaration, depth + 1, parent)?;
                }
                InterfaceMember::Projection {
                    attributes,
                    declaration,
                } => {
                    self.attributes(attributes, depth + 1, parent)?;
                    self.projection(declaration, depth + 1, parent)?;
                }
                InterfaceMember::Error(value) => self.error(value, depth + 1, parent)?,
            }
        }
        Ok(())
    }

    fn implementation(
        &mut self,
        value: &ImplementationDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.ty(&value.interface, depth + 1, parent)?;
        self.ty(&value.implementing_type, depth + 1, parent)?;
        for member in &value.members {
            self.member(member, depth + 1, parent)?;
        }
        Ok(())
    }

    fn projection(
        &mut self,
        value: &ProjectionDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for generic in &value.generics {
            self.generic(generic, depth + 1, parent)?;
        }
        for parameter in &value.parameters {
            self.parameter(parameter, depth + 1, parent)?;
        }
        self.carrier(&value.carrier, depth + 1, parent)?;
        for provenance in &value.provenance {
            self.identifier(provenance, depth + 1, parent)?;
        }
        if let Some(body) = &value.body {
            self.suite(body, depth + 1, parent)?;
        }
        Ok(())
    }

    fn carrier(
        &mut self,
        value: &ProjectionCarrier,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        match value {
            ProjectionCarrier::View { meta, ty, .. } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.ty(ty, depth + 1, parent)
            }
            ProjectionCarrier::Tuple { meta, elements } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                for element in elements {
                    self.carrier(element, depth + 1, parent)?;
                }
                Ok(())
            }
            ProjectionCarrier::Option { meta, carrier } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.carrier(carrier, depth + 1, parent)
            }
            ProjectionCarrier::Result {
                meta,
                carrier,
                error,
            } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                self.carrier(carrier, depth + 1, parent)?;
                self.ty(error, depth + 1, parent)
            }
            ProjectionCarrier::Error(value) => self.error(value, depth, parent),
        }
    }

    fn scope(
        &mut self,
        value: &ScopeDeclaration,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.identifier(&value.name, depth + 1, parent)?;
        for parameter in &value.parameters {
            self.parameter(parameter, depth + 1, parent)?;
        }
        self.ty(&value.return_type, depth + 1, parent)?;
        for statement in &value.setup {
            self.statement(statement, depth + 1, parent)?;
        }
        self.expression(&value.enter, depth + 1, parent)?;
        if let Some(abort) = &value.abort {
            self.suite(abort, depth + 1, parent)?;
        }
        self.identifier(&value.exit_binding, depth + 1, parent)?;
        self.suite(&value.exit, depth + 1, parent)
    }

    fn suite(&mut self, value: &Suite, depth: u32, parent: NodeMeta) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        for statement in &value.statements {
            self.statement(statement, depth + 1, parent)?;
        }
        Ok(())
    }

    fn statement(
        &mut self,
        value: &Statement,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        self.attributes(&value.attributes, depth + 1, parent)?;
        match &value.kind {
            StatementKind::LocalAssignment {
                name, ty, value, ..
            } => {
                self.identifier(name, depth + 1, parent)?;
                if let Some(ty) = ty {
                    self.ty(ty, depth + 1, parent)?;
                }
                self.expression(value, depth + 1, parent)
            }
            StatementKind::PlaceAssignment { target, value, .. } => {
                self.assignment_target(target, depth + 1, parent)?;
                self.expression(value, depth + 1, parent)
            }
            StatementKind::Return(value) => {
                if let Some(value) = value {
                    self.expression(value, depth + 1, parent)?;
                }
                Ok(())
            }
            StatementKind::Break | StatementKind::Continue | StatementKind::Pass => Ok(()),
            StatementKind::Assert { condition, message }
            | StatementKind::ComptimeAssert { condition, message } => {
                self.expression(condition, depth + 1, parent)?;
                if let Some(message) = message {
                    self.literal(message, depth + 1, parent)?;
                }
                Ok(())
            }
            StatementKind::Send(value)
            | StatementKind::Yield(value)
            | StatementKind::Expression(value) => self.expression(value, depth + 1, parent),
            StatementKind::If(value) => {
                self.expression(&value.condition, depth + 1, parent)?;
                self.suite(&value.then_suite, depth + 1, parent)?;
                for (condition, suite) in &value.elif {
                    self.expression(condition, depth + 1, parent)?;
                    self.suite(suite, depth + 1, parent)?;
                }
                if let Some(suite) = &value.else_suite {
                    self.suite(suite, depth + 1, parent)?;
                }
                Ok(())
            }
            StatementKind::Match { scrutinee, arms } => {
                self.expression(scrutinee, depth + 1, parent)?;
                for arm in arms {
                    let arm_parent = self.meta(arm.meta, depth + 1, Some(parent))?;
                    self.pattern(&arm.pattern, depth + 2, arm_parent)?;
                    if let Some(guard) = &arm.guard {
                        self.expression(guard, depth + 2, arm_parent)?;
                    }
                    self.suite(&arm.body, depth + 2, arm_parent)?;
                }
                Ok(())
            }
            StatementKind::For {
                binding,
                iterable,
                body,
                ..
            } => {
                self.identifier(binding, depth + 1, parent)?;
                self.expression(iterable, depth + 1, parent)?;
                self.suite(body, depth + 1, parent)
            }
            StatementKind::While { condition, body } => {
                self.expression(condition, depth + 1, parent)?;
                self.suite(body, depth + 1, parent)
            }
            StatementKind::Loop(body) => self.suite(body, depth + 1, parent),
            StatementKind::With {
                value,
                binding,
                body,
            } => {
                self.expression(value, depth + 1, parent)?;
                if let Some(binding) = binding {
                    let binding_parent = self.meta(binding.meta, depth + 1, Some(parent))?;
                    self.identifier(&binding.name, depth + 2, binding_parent)?;
                    if let Some(region) = &binding.region {
                        self.identifier(region, depth + 2, binding_parent)?;
                    }
                }
                self.suite(body, depth + 1, parent)
            }
            StatementKind::ComptimeIf {
                condition,
                then_suite,
                else_suite,
            } => {
                self.expression(condition, depth + 1, parent)?;
                self.suite(then_suite, depth + 1, parent)?;
                if let Some(suite) = else_suite {
                    self.suite(suite, depth + 1, parent)?;
                }
                Ok(())
            }
            StatementKind::Error(value) => self.error(value, depth + 1, parent),
        }
    }

    fn assignment_target(
        &mut self,
        value: &AssignmentTarget,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        match value {
            AssignmentTarget::Place(value) => self.expression(value, depth, parent),
            AssignmentTarget::Tuple { meta, elements } => {
                let parent = self.meta(*meta, depth, Some(parent))?;
                for element in elements {
                    self.assignment_target(element, depth + 1, parent)?;
                }
                Ok(())
            }
            AssignmentTarget::Error(value) => self.error(value, depth, parent),
        }
    }

    fn expression(
        &mut self,
        value: &Expression,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        match &value.kind {
            ExpressionKind::Literal(value) => self.literal(value, depth + 1, parent),
            ExpressionKind::Name(value) => self.qualified(value, depth + 1, parent),
            ExpressionKind::Closure {
                parameters, body, ..
            } => {
                for parameter in parameters {
                    self.parameter(parameter, depth + 1, parent)?;
                }
                match body {
                    ClosureBody::Expression(value) => {
                        self.expression(value, depth + 1, parent)?;
                    }
                    ClosureBody::Suite(value) => self.suite(value, depth + 1, parent)?,
                }
                Ok(())
            }
            ExpressionKind::Unary { operand, .. }
            | ExpressionKind::Try(operand)
            | ExpressionKind::Parenthesized(operand)
            | ExpressionKind::TrySend(operand) => self.expression(operand, depth + 1, parent),
            ExpressionKind::Binary { left, right, .. } => {
                self.expression(left, depth + 1, parent)?;
                self.expression(right, depth + 1, parent)
            }
            ExpressionKind::Comparison { first, tails } => {
                self.expression(first, depth + 1, parent)?;
                for tail in tails {
                    self.expression(&tail.right, depth + 1, parent)?;
                }
                Ok(())
            }
            ExpressionKind::IsPattern { value, pattern, .. } => {
                self.expression(value, depth + 1, parent)?;
                self.pattern(pattern, depth + 1, parent)
            }
            ExpressionKind::Range { start, end, .. } => {
                self.expression(start, depth + 1, parent)?;
                self.expression(end, depth + 1, parent)
            }
            ExpressionKind::Cast { value, ty } => {
                self.expression(value, depth + 1, parent)?;
                self.ty(ty, depth + 1, parent)
            }
            ExpressionKind::Field { base, field } => {
                self.expression(base, depth + 1, parent)?;
                self.identifier(field, depth + 1, parent)
            }
            ExpressionKind::Call { callee, arguments } => {
                self.expression(callee, depth + 1, parent)?;
                for argument in arguments {
                    let argument_parent = self.meta(argument.meta, depth + 1, Some(parent))?;
                    if let Some(name) = &argument.name {
                        self.identifier(name, depth + 2, argument_parent)?;
                    }
                    self.expression(&argument.value, depth + 2, argument_parent)?;
                }
                Ok(())
            }
            ExpressionKind::Index { base, index } => {
                self.expression(base, depth + 1, parent)?;
                self.expression(index, depth + 1, parent)
            }
            ExpressionKind::Tuple(values)
            | ExpressionKind::Array(values)
            | ExpressionKind::Race(values) => {
                for value in values {
                    self.expression(value, depth + 1, parent)?;
                }
                Ok(())
            }
            ExpressionKind::Interpolated(parts) => {
                for part in parts {
                    match part {
                        InterpolationPart::Text { span, .. } => {
                            if !valid_span(self.source, *span)
                                || span.range.start < parent.span.range.start
                                || span.range.end > parent.span.range.end
                            {
                                return Err(ParseFailure::InternalInvariant(
                                    "interpolation text escapes its expression".to_owned(),
                                ));
                            }
                        }
                        InterpolationPart::Value { expression, .. } => {
                            self.expression(expression, depth + 1, parent)?;
                        }
                    }
                }
                Ok(())
            }
            ExpressionKind::Error(value) => self.error(value, depth + 1, parent),
        }
    }

    fn literal(
        &mut self,
        value: &Literal,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let meta = self.meta(value.meta, depth, Some(parent))?;
        if value.spelling.is_empty() {
            return Err(ParseFailure::InternalInvariant(
                "literal spelling is empty".to_owned(),
            ));
        }
        if self.source.slice(meta.span.range) != Some(value.spelling.as_str()) {
            return Err(ParseFailure::InternalInvariant(
                "literal spelling differs from its source interval".to_owned(),
            ));
        }
        Ok(())
    }

    fn pattern(
        &mut self,
        value: &Pattern,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        if value.alternatives.is_empty() {
            return Err(ParseFailure::InternalInvariant(
                "pattern has no alternatives".to_owned(),
            ));
        }
        for alternative in &value.alternatives {
            match alternative {
                PrimaryPattern::Wildcard(meta) => {
                    self.meta(*meta, depth + 1, Some(parent))?;
                }
                PrimaryPattern::Literal { literal, .. } => {
                    self.literal(literal, depth + 1, parent)?;
                }
                PrimaryPattern::Constructor { name, arguments } => {
                    self.qualified(name, depth + 1, parent)?;
                    self.pattern_arguments(arguments, depth + 1, parent)?;
                }
                PrimaryPattern::Bind(value) => self.identifier(value, depth + 1, parent)?,
                PrimaryPattern::Tuple { meta, elements }
                | PrimaryPattern::Array { meta, elements } => {
                    let inner = self.meta(*meta, depth + 1, Some(parent))?;
                    self.pattern_arguments(elements, depth + 2, inner)?;
                }
                PrimaryPattern::Error(value) => self.error(value, depth + 1, parent)?,
            }
        }
        Ok(())
    }

    fn pattern_arguments(
        &mut self,
        values: &[PatternArgument],
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        for value in values {
            let inner = self.meta(value.meta, depth, Some(parent))?;
            self.pattern(&value.pattern, depth + 1, inner)?;
        }
        Ok(())
    }

    fn ty(
        &mut self,
        value: &TypeExpression,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        let parent = self.meta(value.meta, depth, Some(parent))?;
        match &value.kind {
            TypeExpressionKind::Named { name, arguments } => {
                self.qualified(name, depth + 1, parent)?;
                for argument in arguments {
                    match argument {
                        BracketArgument::UnclassifiedTypeOrExpression { meta, tokens } => {
                            let inner = self.meta(*meta, depth + 1, Some(parent))?;
                            if tokens.first.0 > tokens.end.0
                                || tokens.first.0 < inner.tokens.first.0
                                || tokens.end.0 > inner.tokens.end.0
                            {
                                return Err(ParseFailure::InternalInvariant(
                                    "unclassified generic token range is invalid".to_owned(),
                                ));
                            }
                        }
                        BracketArgument::BoundedCapacity { meta, maximum } => {
                            let inner = self.meta(*meta, depth + 1, Some(parent))?;
                            self.expression(maximum, depth + 2, inner)?;
                        }
                        BracketArgument::Error(value) => {
                            self.error(value, depth + 1, parent)?;
                        }
                    }
                }
                Ok(())
            }
            TypeExpressionKind::Array { element, length } => {
                self.ty(element, depth + 1, parent)?;
                self.expression(length, depth + 1, parent)
            }
            TypeExpressionKind::Tuple(values) => {
                for value in values {
                    self.ty(value, depth + 1, parent)?;
                }
                Ok(())
            }
            TypeExpressionKind::View { target, .. } => self.ty(target, depth + 1, parent),
            TypeExpressionKind::Iso { brand, payload } => {
                self.ty(brand, depth + 1, parent)?;
                self.ty(payload, depth + 1, parent)
            }
            TypeExpressionKind::Function {
                parameters, result, ..
            } => {
                for parameter in parameters {
                    let inner = self.meta(parameter.meta, depth + 1, Some(parent))?;
                    self.ty(&parameter.ty, depth + 2, inner)?;
                }
                self.ty(result, depth + 1, parent)
            }
            TypeExpressionKind::Error(value) => self.error(value, depth + 1, parent),
        }
    }

    fn error(
        &mut self,
        value: &ErrorNode,
        depth: u32,
        parent: NodeMeta,
    ) -> Result<(), ParseFailure> {
        self.meta(value.meta, depth, Some(parent))?;
        if value.expected.is_empty()
            || value
                .expected
                .iter()
                .any(|expected| expected.is_empty() || expected.len() > 4096)
        {
            return Err(ParseFailure::InternalInvariant(
                "recovery node has no bounded expected-token description".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_parse_diagnostics(
    diagnostics: Vec<Diagnostic>,
    source: &SourceFile,
    limits: ParseLimits,
) -> Result<Vec<Diagnostic>, ParseFailure> {
    if diagnostics.len() > limits.diagnostics as usize {
        return Err(ParseFailure::ResourceLimit {
            resource: "diagnostics",
            limit: u64::from(limits.diagnostics),
        });
    }
    let mut bytes = 0u64;
    for diagnostic in &diagnostics {
        if diagnostic.message.trim().is_empty()
            || !valid_span(source, diagnostic.primary)
            || diagnostic.code.as_ref().is_some_and(|code| {
                code.is_empty()
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || diagnostic
                .labels
                .iter()
                .any(|label| label.message.trim().is_empty() || !valid_span(source, label.span))
            || diagnostic.related.iter().any(|related| {
                related.message.trim().is_empty() || !valid_span(source, related.span)
            })
            || diagnostic.repairs.iter().any(|repair| {
                repair.message.trim().is_empty()
                    || repair.edits.is_empty()
                    || !repair
                        .edits
                        .windows(2)
                        .all(|pair| pair[0].span.range.end <= pair[1].span.range.start)
                    || repair
                        .edits
                        .iter()
                        .any(|edit| !valid_span(source, edit.span))
            })
        {
            return Err(ParseFailure::InternalInvariant(
                "parser diagnostic is malformed or refers outside its source".to_owned(),
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
                    ParseFailure::InternalInvariant(
                        "diagnostic byte count does not fit u64".to_owned(),
                    )
                })?)
                .ok_or(ParseFailure::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: limits.diagnostic_bytes,
                })?;
        }
    }
    if bytes > limits.diagnostic_bytes {
        return Err(ParseFailure::ResourceLimit {
            resource: "diagnostic bytes",
            limit: limits.diagnostic_bytes,
        });
    }
    let mut output = WithDiagnostics {
        value: (),
        diagnostics,
    };
    output.sort_diagnostics();
    Ok(output.diagnostics)
}

fn valid_span(source: &SourceFile, span: Span) -> bool {
    span.file == source.id() && source.slice(span.range).is_some()
}

/// Parser implementation boundary. Implementations return a best-effort AST
/// plus diagnostics and poll cancellation at bounded scanner/parser intervals.
pub trait SyntaxParser {
    fn parse(
        &self,
        request: ParseRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ParseOutput, ParseFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseFailure {
    UnknownSource(FileId),
    StaleOutput(FileId),
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    InternalInvariant(String),
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSource(id) => write!(formatter, "unknown source file {}", id.0),
            Self::StaleOutput(id) => {
                write!(
                    formatter,
                    "parser output for source {} is stale or misidentified",
                    id.0
                )
            }
            Self::Cancelled => formatter.write_str("parsing was cancelled"),
            Self::InvalidLimits => formatter.write_str("parser limits must be nonzero"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "parser exceeded {resource} limit {limit}")
            }
            Self::InternalInvariant(message) => {
                write!(formatter, "parser invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for ParseFailure {}

#[cfg(test)]
mod contract_tests {
    use super::{ParseFailure, ParseLimits};

    #[test]
    fn parse_policy_rejects_zero_capacity() {
        ParseLimits::standard().validate().expect("standard limits");
        let mut limits = ParseLimits::standard();
        limits.tokens = 0;
        assert!(matches!(
            limits.validate(),
            Err(ParseFailure::InvalidLimits)
        ));
    }
}
