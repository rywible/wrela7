//! Backend-independent diagnostics expressed in source-language concepts.

#![forbid(unsafe_code)]

use wrela_source::Span;

/// Stable diagnostic category used by tooling and suppression policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Category(&'static str);

impl Category {
    pub const SYNTAX: Self = Self("syntax");
    pub const PACKAGE: Self = Self("package");
    pub const NAME: Self = Self("name");
    pub const TYPE: Self = Self("type");
    pub const EFFECT: Self = Self("effect");
    pub const OWNERSHIP: Self = Self("ownership");
    pub const REGION: Self = Self("region");
    pub const ACTOR: Self = Self("actor");
    pub const ASYNC: Self = Self("async");
    pub const CAPACITY: Self = Self("capacity");
    pub const HARDWARE: Self = Self("hardware");
    pub const COMPTIME: Self = Self("comptime");
    pub const IMAGE: Self = Self("image");
    pub const TARGET: Self = Self("target");
    pub const PROFILE: Self = Self("profile");
    pub const DMA: Self = Self("dma");

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Diagnostic importance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Compilation cannot continue successfully.
    Error,
    /// Advisory issue that does not invalidate the image.
    Warning,
}

/// A secondary source annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// Source range being explained.
    pub span: Span,
    /// Explanation attached to that range.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    MachineApplicable,
    MaybeIncorrect,
    RequiresReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEdit {
    pub span: Span,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    pub message: String,
    pub applicability: Applicability,
    /// Sorted, nonoverlapping edits applied atomically.
    pub edits: Vec<SourceEdit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedDiagnostic {
    pub span: Span,
    pub message: String,
}

/// One structured compiler diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable category such as `view`, `region`, or `actor-cycle`.
    pub category: Category,
    /// Stable phase-owned code suitable for CI policy and documentation.
    pub code: Option<String>,
    /// Whether the diagnostic rejects the build.
    pub severity: Severity,
    /// Main source range.
    pub primary: Span,
    /// Human-readable summary.
    pub message: String,
    /// Additional source annotations.
    pub labels: Vec<Label>,
    /// Whole-image causality or suggested repair steps.
    pub notes: Vec<String>,
    /// Concise action-oriented guidance distinct from causal notes.
    pub help: Vec<String>,
    /// Cross-file related locations that are not source labels on the primary.
    pub related: Vec<RelatedDiagnostic>,
    /// Structured repairs; terminal rendering never reparses prose.
    pub repairs: Vec<Repair>,
}

impl Diagnostic {
    /// Construct an error with its required primary source span.
    #[must_use]
    pub fn error(category: Category, primary: Span, message: impl Into<String>) -> Self {
        Self {
            category,
            code: None,
            severity: Severity::Error,
            primary,
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
            related: Vec::new(),
            repairs: Vec::new(),
        }
    }
}

/// Output convention shared by recoverable frontend layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithDiagnostics<T> {
    /// Best-effort layer output.
    pub value: T,
    /// Errors and warnings produced while constructing it.
    pub diagnostics: Vec<Diagnostic>,
}

impl<T> WithDiagnostics<T> {
    /// Construct an output without diagnostics.
    #[must_use]
    pub fn clean(value: T) -> Self {
        Self {
            value,
            diagnostics: Vec::new(),
        }
    }

    /// Whether the layer emitted at least one rejecting diagnostic.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    /// Canonicalize phase output before it crosses a crate or process boundary.
    pub fn sort_diagnostics(&mut self) {
        self.diagnostics
            .sort_by(|left, right| diagnostic_key(left).cmp(&diagnostic_key(right)));
    }
}

fn diagnostic_key(diagnostic: &Diagnostic) -> (&str, u8, u32, u32, u32, &str) {
    (
        diagnostic.category.as_str(),
        match diagnostic.severity {
            Severity::Error => 0,
            Severity::Warning => 1,
        },
        diagnostic.primary.file.0,
        diagnostic.primary.range.start,
        diagnostic.primary.range.end,
        &diagnostic.message,
    )
}
