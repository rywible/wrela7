//! Layered lint contracts for syntax, resolved HIR, and successful whole-image
//! semantic analysis.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use wrela_diagnostics::{Diagnostic, Severity};
use wrela_hir::ValidatedProgram;
use wrela_sema::AnalyzedImage;
use wrela_syntax::ParsedFile;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LintName(String);

impl LintName {
    pub fn new(value: impl Into<String>) -> Result<Self, LintError> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(LintError::InvalidLintName(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LintLevel {
    Allow,
    Warn,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LintLayer {
    Syntax,
    Hir,
    Semantic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintDescriptor {
    pub name: LintName,
    pub layer: LintLayer,
    pub summary: String,
    pub default_level: LintLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LintConfiguration {
    pub levels: BTreeMap<LintName, LintLevel>,
    pub sealed_deployment: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LintLimits {
    pub findings: u32,
    pub diagnostic_bytes: u64,
}

impl LintLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            findings: 100_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), LintError> {
        if self.findings == 0 || self.diagnostic_bytes == 0 {
            Err(LintError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Validated canonical lint inventory. A linter implementation cannot publish
/// an unordered or ambiguous descriptor slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintRegistry {
    descriptors: Vec<LintDescriptor>,
}

impl LintRegistry {
    pub fn new(mut descriptors: Vec<LintDescriptor>) -> Result<Self, LintError> {
        if descriptors.len() > 65_536 {
            return Err(LintError::TooManyDescriptors);
        }
        descriptors.sort_by(|left, right| left.name.cmp(&right.name));
        for descriptor in &descriptors {
            if descriptor.summary.trim().is_empty() || descriptor.summary.len() > 4096 {
                return Err(LintError::InvalidDescriptor(descriptor.name.clone()));
            }
        }
        if let Some(pair) = descriptors
            .windows(2)
            .find(|pair| pair[0].name == pair[1].name)
        {
            return Err(LintError::DuplicateDescriptor(pair[0].name.clone()));
        }
        Ok(Self { descriptors })
    }

    #[must_use]
    pub fn descriptors(&self) -> &[LintDescriptor] {
        &self.descriptors
    }

    #[must_use]
    pub fn descriptor(&self, name: &LintName) -> Option<&LintDescriptor> {
        self.descriptors
            .binary_search_by(|descriptor| descriptor.name.cmp(name))
            .ok()
            .and_then(|index| self.descriptors.get(index))
    }
}

#[derive(Debug)]
pub enum LintInput<'a> {
    Syntax(&'a [ParsedFile]),
    Hir(&'a ValidatedProgram),
    Semantic(&'a AnalyzedImage),
}

#[derive(Debug)]
pub struct LintRequest<'a> {
    pub input: LintInput<'a>,
    /// Exact inventory selected from `Linter::registry()` by orchestration.
    pub registry: &'a LintRegistry,
    pub configuration: &'a LintConfiguration,
    pub limits: LintLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub lint: LintName,
    pub level: LintLevel,
    pub diagnostic: Diagnostic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintOutput {
    findings: Vec<LintFinding>,
    denied: bool,
}

impl LintOutput {
    #[must_use]
    pub fn findings(&self) -> &[LintFinding] {
        &self.findings
    }

    #[must_use]
    pub fn denied(&self) -> bool {
        self.denied
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintOutputCandidate {
    pub findings: Vec<LintFinding>,
}

pub trait Linter {
    fn registry(&self) -> &LintRegistry;
    fn lint(
        &self,
        request: LintRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LintOutput, LintError>;
}

/// Seal findings against the linter inventory, selected information layer,
/// effective configuration, diagnostic shape, and request bounds.
pub fn seal_lint_output(
    request: &LintRequest<'_>,
    mut candidate: LintOutputCandidate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LintOutput, LintError> {
    if is_cancelled() {
        return Err(LintError::Cancelled);
    }
    request.limits.validate()?;
    for name in request.configuration.levels.keys() {
        if request.registry.descriptor(name).is_none() {
            return Err(LintError::UnknownLint(name.clone()));
        }
    }
    if candidate.findings.len() > request.limits.findings as usize {
        return Err(LintError::ResourceLimit {
            resource: "lint findings",
            limit: u64::from(request.limits.findings),
        });
    }
    let input_layer = match request.input {
        LintInput::Syntax(_) => LintLayer::Syntax,
        LintInput::Hir(_) => LintLayer::Hir,
        LintInput::Semantic(_) => LintLayer::Semantic,
    };
    let mut diagnostic_bytes = 0u64;
    for finding in &candidate.findings {
        let descriptor = request
            .registry
            .descriptor(&finding.lint)
            .ok_or_else(|| LintError::UnknownLint(finding.lint.clone()))?;
        if descriptor.layer != input_layer {
            return Err(LintError::WrongLayer {
                lint: finding.lint.clone(),
                expected: descriptor.layer,
            });
        }
        let effective = request
            .configuration
            .levels
            .get(&finding.lint)
            .copied()
            .unwrap_or(descriptor.default_level);
        let expected_severity = match effective {
            LintLevel::Allow => {
                return Err(LintError::SuppressedFinding(finding.lint.clone()));
            }
            LintLevel::Warn => Severity::Warning,
            LintLevel::Deny => Severity::Error,
        };
        if finding.level != effective
            || finding.diagnostic.severity != expected_severity
            || !valid_diagnostic(&finding.diagnostic)
        {
            return Err(LintError::InvalidFinding(finding.lint.clone()));
        }
        diagnostic_bytes = diagnostic_bytes
            .checked_add(
                diagnostic_size(&finding.diagnostic).ok_or(LintError::ResourceLimit {
                    resource: "lint diagnostic bytes",
                    limit: request.limits.diagnostic_bytes,
                })?,
            )
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic bytes",
                limit: request.limits.diagnostic_bytes,
            })?;
    }
    if diagnostic_bytes > request.limits.diagnostic_bytes {
        return Err(LintError::ResourceLimit {
            resource: "lint diagnostic bytes",
            limit: request.limits.diagnostic_bytes,
        });
    }
    candidate
        .findings
        .sort_by(|left, right| lint_finding_key(left).cmp(&lint_finding_key(right)));
    if candidate.findings.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LintError::DuplicateFinding);
    }
    let denied = candidate
        .findings
        .iter()
        .any(|finding| finding.level == LintLevel::Deny);
    if is_cancelled() {
        return Err(LintError::Cancelled);
    }
    Ok(LintOutput {
        findings: candidate.findings,
        denied,
    })
}

fn lint_finding_key(finding: &LintFinding) -> (&LintName, u32, u32, u32, &str) {
    (
        &finding.lint,
        finding.diagnostic.primary.file.0,
        finding.diagnostic.primary.range.start,
        finding.diagnostic.primary.range.end,
        &finding.diagnostic.message,
    )
}

fn valid_diagnostic(diagnostic: &Diagnostic) -> bool {
    let valid_range = |start: u32, end: u32| start <= end;
    !diagnostic.message.trim().is_empty()
        && valid_range(diagnostic.primary.range.start, diagnostic.primary.range.end)
        && diagnostic.code.as_ref().is_none_or(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && diagnostic.labels.iter().all(|label| {
            valid_range(label.span.range.start, label.span.range.end)
                && !label.message.trim().is_empty()
        })
        && diagnostic.related.iter().all(|related| {
            valid_range(related.span.range.start, related.span.range.end)
                && !related.message.trim().is_empty()
        })
        && diagnostic.repairs.iter().all(|repair| {
            !repair.message.trim().is_empty()
                && !repair.edits.is_empty()
                && repair.edits.windows(2).all(|pair| {
                    (
                        pair[0].span.file,
                        pair[0].span.range.start,
                        pair[0].span.range.end,
                    ) < (
                        pair[1].span.file,
                        pair[1].span.range.start,
                        pair[1].span.range.end,
                    ) && (pair[0].span.file != pair[1].span.file
                        || pair[0].span.range.end <= pair[1].span.range.start)
                })
                && repair
                    .edits
                    .iter()
                    .all(|edit| valid_range(edit.span.range.start, edit.span.range.end))
        })
}

fn diagnostic_size(diagnostic: &Diagnostic) -> Option<u64> {
    std::iter::once(diagnostic.message.as_str())
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
        .try_fold(0u64, |total, value| {
            total.checked_add(u64::try_from(value.len()).ok()?)
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintError {
    Cancelled,
    InvalidLimits,
    InvalidLintName(String),
    UnknownLint(LintName),
    DuplicateDescriptor(LintName),
    TooManyDescriptors,
    InvalidDescriptor(LintName),
    SuppressedFinding(LintName),
    InvalidFinding(LintName),
    DuplicateFinding,
    ResourceLimit { resource: &'static str, limit: u64 },
    WrongLayer { lint: LintName, expected: LintLayer },
}

impl fmt::Display for LintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("linting was cancelled"),
            Self::InvalidLimits => formatter.write_str("lint limits must be nonzero"),
            Self::InvalidLintName(name) => write!(formatter, "invalid lint name {name:?}"),
            Self::UnknownLint(name) => write!(formatter, "unknown lint {}", name.as_str()),
            Self::DuplicateDescriptor(name) => {
                write!(formatter, "duplicate lint {}", name.as_str())
            }
            Self::TooManyDescriptors => formatter.write_str("lint registry is too large"),
            Self::InvalidDescriptor(name) => {
                write!(
                    formatter,
                    "lint {} has an invalid descriptor",
                    name.as_str()
                )
            }
            Self::SuppressedFinding(name) => {
                write!(
                    formatter,
                    "allowed lint {} emitted a finding",
                    name.as_str()
                )
            }
            Self::InvalidFinding(name) => {
                write!(
                    formatter,
                    "lint {} emitted an invalid finding",
                    name.as_str()
                )
            }
            Self::DuplicateFinding => formatter.write_str("linter emitted a duplicate finding"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "linting exceeded {resource} limit {limit}")
            }
            Self::WrongLayer { lint, expected } => {
                write!(
                    formatter,
                    "lint {} requires {expected:?} input",
                    lint.as_str()
                )
            }
        }
    }
}

impl std::error::Error for LintError {}

#[cfg(test)]
mod contract_tests {
    use super::{LintError, LintLimits};

    #[test]
    fn lint_policy_rejects_zero_capacity() {
        LintLimits::standard().validate().expect("standard limits");
        let mut limits = LintLimits::standard();
        limits.findings = 0;
        assert!(matches!(limits.validate(), Err(LintError::InvalidLimits)));
    }
}
