//! Backend-independent diagnostics expressed in source-language concepts.

#![forbid(unsafe_code)]

use wrela_source::Span;

/// Stable diagnostic category used by tooling and suppression policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Category(pub String);

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

/// One structured compiler diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable category such as `view`, `region`, or `actor-cycle`.
    pub category: Category,
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
}

impl Diagnostic {
    /// Construct an error with its required primary source span.
    #[must_use]
    pub fn error(category: impl Into<String>, primary: Span, message: impl Into<String>) -> Self {
        Self {
            category: Category(category.into()),
            severity: Severity::Error,
            primary,
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
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
}
