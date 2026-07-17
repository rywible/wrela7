//! Backend-independent diagnostics expressed in source-language concepts.

#![forbid(unsafe_code)]

use std::cmp::Ordering;

pub use wrela_source::{FileId, Span, TextRange};

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
        self.diagnostics.sort_unstable_by(compare_diagnostics);
    }
}

/// Failure from the bounded, cancellable canonical diagnostic sorter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSortError {
    Cancelled,
    Allocation,
}

/// Canonicalize diagnostics without cloning their project-controlled strings.
/// Small runs use the standard in-memory sorter; all project-sized merging is
/// fallibly allocated and polls cancellation between moved records.
pub fn canonicalize_diagnostics(
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Diagnostic>, DiagnosticSortError> {
    const RUN_DIAGNOSTICS: usize = 256;
    if is_cancelled() {
        return Err(DiagnosticSortError::Cancelled);
    }
    if diagnostics.len() <= 1 {
        return Ok(diagnostics);
    }
    if diagnostics.len() <= RUN_DIAGNOSTICS {
        let mut diagnostics = diagnostics;
        diagnostics.sort_unstable_by(compare_diagnostics);
        if is_cancelled() {
            return Err(DiagnosticSortError::Cancelled);
        }
        return Ok(diagnostics);
    }

    let run_count = diagnostics.len().div_ceil(RUN_DIAGNOSTICS);
    let mut runs = Vec::new();
    runs.try_reserve_exact(run_count)
        .map_err(|_| DiagnosticSortError::Allocation)?;
    let mut remaining = diagnostics.len();
    let mut diagnostics = diagnostics.into_iter();
    loop {
        if is_cancelled() {
            return Err(DiagnosticSortError::Cancelled);
        }
        let mut run = Vec::new();
        let run_capacity = remaining.min(RUN_DIAGNOSTICS);
        run.try_reserve_exact(run_capacity)
            .map_err(|_| DiagnosticSortError::Allocation)?;
        for _ in 0..run_capacity {
            let Some(diagnostic) = diagnostics.next() else {
                break;
            };
            run.push(diagnostic);
        }
        if run.is_empty() {
            break;
        }
        remaining = remaining.saturating_sub(run.len());
        run.sort_unstable_by(compare_diagnostics);
        runs.push(run);
    }

    while runs.len() > 1 {
        if is_cancelled() {
            return Err(DiagnosticSortError::Cancelled);
        }
        let mut merged_runs = Vec::new();
        merged_runs
            .try_reserve_exact(runs.len().div_ceil(2))
            .map_err(|_| DiagnosticSortError::Allocation)?;
        let previous_runs = std::mem::take(&mut runs);
        let mut run_iter = previous_runs.into_iter();
        while let Some(left) = run_iter.next() {
            if is_cancelled() {
                return Err(DiagnosticSortError::Cancelled);
            }
            let Some(right) = run_iter.next() else {
                merged_runs.push(left);
                break;
            };
            merged_runs.push(merge_diagnostic_runs(left, right, is_cancelled)?);
        }
        runs = merged_runs;
    }
    if is_cancelled() {
        return Err(DiagnosticSortError::Cancelled);
    }
    runs.pop().ok_or(DiagnosticSortError::Allocation)
}

fn merge_diagnostic_runs(
    left: Vec<Diagnostic>,
    right: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Diagnostic>, DiagnosticSortError> {
    let count = left
        .len()
        .checked_add(right.len())
        .ok_or(DiagnosticSortError::Allocation)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(count)
        .map_err(|_| DiagnosticSortError::Allocation)?;
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    while left.peek().is_some() || right.peek().is_some() {
        if is_cancelled() {
            return Err(DiagnosticSortError::Cancelled);
        }
        let next = match (left.peek(), right.peek()) {
            (Some(left_value), Some(right_value)) => {
                if compare_diagnostics(left_value, right_value) != Ordering::Greater {
                    left.next()
                } else {
                    right.next()
                }
            }
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => None,
        }
        .ok_or(DiagnosticSortError::Allocation)?;
        merged.push(next);
    }
    Ok(merged)
}

/// Total order over every public diagnostic field. Exact duplicates therefore
/// become adjacent under canonicalization even when their primary keys match
/// a different diagnostic.
#[must_use]
pub fn compare_diagnostics(left: &Diagnostic, right: &Diagnostic) -> Ordering {
    left.category
        .as_str()
        .cmp(right.category.as_str())
        .then_with(|| severity_rank(left.severity).cmp(&severity_rank(right.severity)))
        .then_with(|| compare_span(left.primary, right.primary))
        .then_with(|| left.message.cmp(&right.message))
        .then_with(|| left.code.cmp(&right.code))
        .then_with(|| {
            compare_slices(&left.labels, &right.labels, |left, right| {
                compare_span(left.span, right.span).then_with(|| left.message.cmp(&right.message))
            })
        })
        .then_with(|| left.notes.cmp(&right.notes))
        .then_with(|| left.help.cmp(&right.help))
        .then_with(|| {
            compare_slices(&left.related, &right.related, |left, right| {
                compare_span(left.span, right.span).then_with(|| left.message.cmp(&right.message))
            })
        })
        .then_with(|| {
            compare_slices(&left.repairs, &right.repairs, |left, right| {
                left.message
                    .cmp(&right.message)
                    .then_with(|| {
                        applicability_rank(left.applicability)
                            .cmp(&applicability_rank(right.applicability))
                    })
                    .then_with(|| {
                        compare_slices(&left.edits, &right.edits, |left, right| {
                            compare_span(left.span, right.span)
                                .then_with(|| left.replacement.cmp(&right.replacement))
                        })
                    })
            })
        })
}

fn compare_slices<T>(left: &[T], right: &[T], compare: impl Fn(&T, &T) -> Ordering) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = compare(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_span(left: Span, right: Span) -> Ordering {
    (left.file, left.range.start, left.range.end).cmp(&(
        right.file,
        right.range.start,
        right.range.end,
    ))
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
    }
}

const fn applicability_rank(applicability: Applicability) -> u8 {
    match applicability {
        Applicability::MachineApplicable => 0,
        Applicability::MaybeIncorrect => 1,
        Applicability::RequiresReview => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use wrela_source::{FileId, TextRange};

    use super::*;

    fn diagnostic(code: usize) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(
            Category::TYPE,
            Span {
                file: FileId(0),
                range: TextRange::new(0, 0).expect("valid span"),
            },
            "same primary key",
        );
        diagnostic.code = Some(format!("code-{code:04}"));
        diagnostic
    }

    #[test]
    fn canonical_sort_uses_every_field_and_moves_without_cloning() {
        let sorted =
            canonicalize_diagnostics(vec![diagnostic(2), diagnostic(0), diagnostic(1)], &|| false)
                .expect("canonical diagnostics");
        assert_eq!(
            sorted
                .iter()
                .map(|diagnostic| diagnostic.code.as_deref().expect("code"))
                .collect::<Vec<_>>(),
            ["code-0000", "code-0001", "code-0002"]
        );
    }

    #[test]
    fn project_sized_merge_sort_is_cancellable() {
        let diagnostics = (0..600).rev().map(diagnostic).collect();
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 20
        };
        assert_eq!(
            canonicalize_diagnostics(diagnostics, &cancelled),
            Err(DiagnosticSortError::Cancelled)
        );
        assert!(polls.get() >= 20);
    }
}
