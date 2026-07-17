//! Layered lint contracts for syntax, resolved HIR, and successful whole-image
//! semantic analysis.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use wrela_diagnostics::{Diagnostic, Severity, compare_diagnostics};
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
    pub configuration_entries: u32,
    pub findings: u32,
    /// Aggregate number of nested diagnostic strings, labels, repairs, and
    /// replacement records inspected while sealing findings.
    pub diagnostic_elements: u64,
    pub diagnostic_bytes: u64,
}

impl LintLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            configuration_entries: 65_536,
            findings: 100_000,
            diagnostic_elements: 1_000_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), LintError> {
        if self.configuration_entries == 0
            || self.findings == 0
            || self.diagnostic_elements == 0
            || self.diagnostic_bytes == 0
        {
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
    if u32::try_from(request.configuration.levels.len()).map_or(true, |entries| {
        entries > request.limits.configuration_entries
    }) {
        return Err(LintError::ResourceLimit {
            resource: "lint configuration entries",
            limit: u64::from(request.limits.configuration_entries),
        });
    }
    for (work, name) in request.configuration.levels.keys().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if request.registry.descriptor(name).is_none() {
            return Err(LintError::UnknownLint(name.clone()));
        }
    }
    if u32::try_from(candidate.findings.len())
        .map_or(true, |findings| findings > request.limits.findings)
    {
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
    let mut diagnostic_elements = 0u64;
    for (work, finding) in candidate.findings.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        diagnostic_elements = diagnostic_elements
            .checked_add(diagnostic_element_count(
                &finding.diagnostic,
                request.limits.diagnostic_elements,
                is_cancelled,
            )?)
            .filter(|elements| *elements <= request.limits.diagnostic_elements)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic elements",
                limit: request.limits.diagnostic_elements,
            })?;
        let remaining_bytes = request
            .limits
            .diagnostic_bytes
            .checked_sub(diagnostic_bytes)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic bytes",
                limit: request.limits.diagnostic_bytes,
            })?;
        diagnostic_bytes = diagnostic_bytes
            .checked_add(diagnostic_size(
                &finding.diagnostic,
                remaining_bytes,
                request.limits.diagnostic_bytes,
                is_cancelled,
            )?)
            .filter(|bytes| *bytes <= request.limits.diagnostic_bytes)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic bytes",
                limit: request.limits.diagnostic_bytes,
            })?;
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
            || !valid_diagnostic(&finding.diagnostic, is_cancelled)?
        {
            return Err(LintError::InvalidFinding(finding.lint.clone()));
        }
    }
    candidate.findings = canonicalize_findings(candidate.findings, is_cancelled)?;
    let mut denied = false;
    for (work, finding) in candidate.findings.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if work != 0 && candidate.findings[work - 1] == *finding {
            return Err(LintError::DuplicateFinding);
        }
        denied |= finding.level == LintLevel::Deny;
    }
    if is_cancelled() {
        return Err(LintError::Cancelled);
    }
    Ok(LintOutput {
        findings: candidate.findings,
        denied,
    })
}

fn compare_findings(left: &LintFinding, right: &LintFinding) -> Ordering {
    left.lint
        .cmp(&right.lint)
        .then_with(|| left.level.cmp(&right.level))
        .then_with(|| compare_diagnostics(&left.diagnostic, &right.diagnostic))
}

fn canonicalize_findings(
    findings: Vec<LintFinding>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<LintFinding>, LintError> {
    const RUN_FINDINGS: usize = 256;
    if is_cancelled() {
        return Err(LintError::Cancelled);
    }
    if findings.len() <= 1 {
        return Ok(findings);
    }
    if findings.len() <= RUN_FINDINGS {
        let mut findings = findings;
        findings.sort_unstable_by(compare_findings);
        if is_cancelled() {
            return Err(LintError::Cancelled);
        }
        return Ok(findings);
    }

    let run_count = findings.len().div_ceil(RUN_FINDINGS);
    let mut runs = Vec::new();
    runs.try_reserve_exact(run_count)
        .map_err(|_| LintError::ResourceExhausted("lint finding sort runs"))?;
    let mut remaining = findings.len();
    let mut findings = findings.into_iter();
    loop {
        if is_cancelled() {
            return Err(LintError::Cancelled);
        }
        let run_capacity = remaining.min(RUN_FINDINGS);
        let mut run = Vec::new();
        run.try_reserve_exact(run_capacity)
            .map_err(|_| LintError::ResourceExhausted("lint finding sort run"))?;
        for _ in 0..run_capacity {
            let Some(finding) = findings.next() else {
                break;
            };
            run.push(finding);
        }
        if run.is_empty() {
            break;
        }
        remaining = remaining.saturating_sub(run.len());
        run.sort_unstable_by(compare_findings);
        runs.push(run);
    }

    while runs.len() > 1 {
        if is_cancelled() {
            return Err(LintError::Cancelled);
        }
        let mut merged_runs = Vec::new();
        merged_runs
            .try_reserve_exact(runs.len().div_ceil(2))
            .map_err(|_| LintError::ResourceExhausted("merged lint finding sort runs"))?;
        let previous_runs = std::mem::take(&mut runs);
        let mut run_iter = previous_runs.into_iter();
        while let Some(left) = run_iter.next() {
            if is_cancelled() {
                return Err(LintError::Cancelled);
            }
            let Some(right) = run_iter.next() else {
                merged_runs.push(left);
                break;
            };
            merged_runs.push(merge_finding_runs(left, right, is_cancelled)?);
        }
        runs = merged_runs;
    }
    if is_cancelled() {
        return Err(LintError::Cancelled);
    }
    runs.pop()
        .ok_or(LintError::ResourceExhausted("canonical lint findings"))
}

fn merge_finding_runs(
    left: Vec<LintFinding>,
    right: Vec<LintFinding>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<LintFinding>, LintError> {
    let count = left
        .len()
        .checked_add(right.len())
        .ok_or(LintError::ResourceExhausted("merged lint finding sort run"))?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(count)
        .map_err(|_| LintError::ResourceExhausted("merged lint finding sort run"))?;
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    while left.peek().is_some() || right.peek().is_some() {
        if is_cancelled() {
            return Err(LintError::Cancelled);
        }
        let next = match (left.peek(), right.peek()) {
            (Some(left_value), Some(right_value)) => {
                if compare_findings(left_value, right_value) != Ordering::Greater {
                    left.next()
                } else {
                    right.next()
                }
            }
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => None,
        }
        .ok_or(LintError::ResourceExhausted("merged lint finding sort run"))?;
        merged.push(next);
    }
    Ok(merged)
}

fn valid_diagnostic(
    diagnostic: &Diagnostic,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LintError> {
    if !valid_range(diagnostic.primary.range.start, diagnostic.primary.range.end)
        || !nonblank(&diagnostic.message, is_cancelled)?
    {
        return Ok(false);
    }
    if let Some(code) = &diagnostic.code {
        if code.is_empty() {
            return Ok(false);
        }
        for (work, byte) in code.bytes().enumerate() {
            poll_cancel(work, is_cancelled)?;
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
                return Ok(false);
            }
        }
    }
    for (work, label) in diagnostic.labels.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if !valid_range(label.span.range.start, label.span.range.end)
            || !nonblank(&label.message, is_cancelled)?
        {
            return Ok(false);
        }
    }
    for (work, note) in diagnostic.notes.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if !nonblank(note, is_cancelled)? {
            return Ok(false);
        }
    }
    for (work, help) in diagnostic.help.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if !nonblank(help, is_cancelled)? {
            return Ok(false);
        }
    }
    for (work, related) in diagnostic.related.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if !valid_range(related.span.range.start, related.span.range.end)
            || !nonblank(&related.message, is_cancelled)?
        {
            return Ok(false);
        }
    }
    for (repair_work, repair) in diagnostic.repairs.iter().enumerate() {
        poll_cancel(repair_work, is_cancelled)?;
        if repair.edits.is_empty() || !nonblank(&repair.message, is_cancelled)? {
            return Ok(false);
        }
        for (edit_work, edit) in repair.edits.iter().enumerate() {
            poll_cancel(edit_work, is_cancelled)?;
            if !valid_range(edit.span.range.start, edit.span.range.end) {
                return Ok(false);
            }
            if let Some(previous) = edit_work
                .checked_sub(1)
                .and_then(|previous| repair.edits.get(previous))
            {
                let previous_key = (
                    previous.span.file,
                    previous.span.range.start,
                    previous.span.range.end,
                );
                let current_key = (edit.span.file, edit.span.range.start, edit.span.range.end);
                if previous_key >= current_key
                    || (previous.span.file == edit.span.file
                        && previous.span.range.end > edit.span.range.start)
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

const fn valid_range(start: u32, end: u32) -> bool {
    start <= end
}

fn nonblank(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, LintError> {
    for (work, character) in value.chars().enumerate() {
        poll_cancel(work, is_cancelled)?;
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn poll_cancel(work: usize, is_cancelled: &dyn Fn() -> bool) -> Result<(), LintError> {
    if work % 256 == 0 && is_cancelled() {
        Err(LintError::Cancelled)
    } else {
        Ok(())
    }
}

fn diagnostic_element_count(
    diagnostic: &Diagnostic,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, LintError> {
    let mut total = 1u64;
    for length in [
        usize::from(diagnostic.code.is_some()),
        diagnostic.labels.len(),
        diagnostic.notes.len(),
        diagnostic.help.len(),
        diagnostic.related.len(),
        diagnostic.repairs.len(),
    ] {
        total = total
            .checked_add(u64::try_from(length).map_err(|_| LintError::ResourceLimit {
                resource: "lint diagnostic elements",
                limit,
            })?)
            .filter(|elements| *elements <= limit)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic elements",
                limit,
            })?;
    }
    for (work, repair) in diagnostic.repairs.iter().enumerate() {
        poll_cancel(work, is_cancelled)?;
        total = total
            .checked_add(u64::try_from(repair.edits.len()).map_err(|_| {
                LintError::ResourceLimit {
                    resource: "lint diagnostic elements",
                    limit,
                }
            })?)
            .filter(|elements| *elements <= limit)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic elements",
                limit,
            })?;
    }
    Ok(total)
}

fn diagnostic_size(
    diagnostic: &Diagnostic,
    maximum: u64,
    reported_limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, LintError> {
    let mut bytes = 0u64;
    let mut work = 0usize;
    let mut add = |value: &str| -> Result<(), LintError> {
        poll_cancel(work, is_cancelled)?;
        work = work.saturating_add(1);
        bytes = bytes
            .checked_add(
                u64::try_from(value.len()).map_err(|_| LintError::ResourceLimit {
                    resource: "lint diagnostic bytes",
                    limit: reported_limit,
                })?,
            )
            .filter(|bytes| *bytes <= maximum)
            .ok_or(LintError::ResourceLimit {
                resource: "lint diagnostic bytes",
                limit: reported_limit,
            })?;
        Ok(())
    };

    add(&diagnostic.message)?;
    if let Some(code) = &diagnostic.code {
        add(code)?;
    }
    for label in &diagnostic.labels {
        add(&label.message)?;
    }
    for note in &diagnostic.notes {
        add(note)?;
    }
    for help in &diagnostic.help {
        add(help)?;
    }
    for related in &diagnostic.related {
        add(&related.message)?;
    }
    for repair in &diagnostic.repairs {
        add(&repair.message)?;
        for edit in &repair.edits {
            add(&edit.replacement)?;
        }
    }
    Ok(bytes)
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
    ResourceExhausted(&'static str),
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
            Self::ResourceExhausted(resource) => {
                write!(formatter, "cannot allocate bounded {resource}")
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
    use std::cell::Cell;

    use wrela_diagnostics::{Category, Diagnostic, FileId, Severity, Span, TextRange};

    use super::{
        LintConfiguration, LintDescriptor, LintError, LintFinding, LintInput, LintLayer, LintLevel,
        LintLimits, LintName, LintOutputCandidate, LintRegistry, LintRequest,
        canonicalize_findings, seal_lint_output,
    };

    fn fixture() -> (LintRegistry, LintName) {
        let name = LintName::new("fixture-lint").expect("lint name");
        let registry = LintRegistry::new(vec![LintDescriptor {
            name: name.clone(),
            layer: LintLayer::Syntax,
            summary: "fixture lint".to_owned(),
            default_level: LintLevel::Warn,
        }])
        .expect("lint registry");
        (registry, name)
    }

    fn finding(name: &LintName, note: &str) -> LintFinding {
        LintFinding {
            lint: name.clone(),
            level: LintLevel::Warn,
            diagnostic: Diagnostic {
                category: Category::SYNTAX,
                code: Some(name.as_str().to_owned()),
                severity: Severity::Warning,
                primary: Span {
                    file: FileId(0),
                    range: TextRange { start: 1, end: 2 },
                },
                message: "fixture finding".to_owned(),
                labels: Vec::new(),
                notes: vec![note.to_owned()],
                help: Vec::new(),
                related: Vec::new(),
                repairs: Vec::new(),
            },
        }
    }

    #[test]
    fn lint_policy_rejects_zero_capacity() {
        LintLimits::standard().validate().expect("standard limits");
        let mut limits = LintLimits::standard();
        limits.findings = 0;
        assert!(matches!(limits.validate(), Err(LintError::InvalidLimits)));

        let mut limits = LintLimits::standard();
        limits.configuration_entries = 0;
        assert!(matches!(limits.validate(), Err(LintError::InvalidLimits)));

        let mut limits = LintLimits::standard();
        limits.diagnostic_elements = 0;
        assert!(matches!(limits.validate(), Err(LintError::InvalidLimits)));
    }

    #[test]
    fn lint_seal_uses_total_order_and_bounds_nested_diagnostics() {
        let (registry, name) = fixture();
        let configuration = LintConfiguration::default();
        let mut limits = LintLimits::standard();
        let request = |limits| LintRequest {
            input: LintInput::Syntax(&[]),
            registry: &registry,
            configuration: &configuration,
            limits,
        };
        let output = seal_lint_output(
            &request(limits),
            LintOutputCandidate {
                findings: vec![finding(&name, "z-note"), finding(&name, "a-note")],
            },
            &|| false,
        )
        .expect("canonical findings");
        assert_eq!(output.findings()[0].diagnostic.notes, ["a-note"]);
        assert_eq!(output.findings()[1].diagnostic.notes, ["z-note"]);

        limits.diagnostic_elements = 2;
        assert!(matches!(
            seal_lint_output(
                &request(limits),
                LintOutputCandidate {
                    findings: vec![finding(&name, "one-note")],
                },
                &|| false,
            ),
            Err(LintError::ResourceLimit {
                resource: "lint diagnostic elements",
                limit: 2,
            })
        ));

        let mut malformed = finding(&name, "valid");
        malformed.diagnostic.notes[0].clear();
        assert!(matches!(
            seal_lint_output(
                &request(LintLimits::standard()),
                LintOutputCandidate {
                    findings: vec![malformed],
                },
                &|| false,
            ),
            Err(LintError::InvalidFinding(_))
        ));
    }

    #[test]
    fn lint_seal_polls_cancellation_inside_large_diagnostic_text() {
        let (registry, name) = fixture();
        let configuration = LintConfiguration::default();
        let request = LintRequest {
            input: LintInput::Syntax(&[]),
            registry: &registry,
            configuration: &configuration,
            limits: LintLimits::standard(),
        };
        let mut candidate = finding(&name, "valid");
        candidate.diagnostic.message = " ".repeat(4096);
        let polls = Cell::new(0u32);
        assert_eq!(
            seal_lint_output(
                &request,
                LintOutputCandidate {
                    findings: vec![candidate],
                },
                &|| {
                    let next = polls.get().saturating_add(1);
                    polls.set(next);
                    next >= 6
                },
            ),
            Err(LintError::Cancelled)
        );
        assert!(polls.get() >= 6);
    }

    #[test]
    fn project_sized_finding_sort_is_total_and_cancellable() {
        let (_, name) = fixture();
        let findings: Vec<_> = (0..600)
            .rev()
            .map(|value| finding(&name, &format!("note-{value:04}")))
            .collect();
        let sorted = canonicalize_findings(findings.clone(), &|| false)
            .expect("bounded canonical finding sort");
        assert_eq!(sorted[0].diagnostic.notes, ["note-0000"]);
        assert_eq!(sorted[599].diagnostic.notes, ["note-0599"]);

        let polls = Cell::new(0u32);
        assert_eq!(
            canonicalize_findings(findings, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= 4
            }),
            Err(LintError::Cancelled)
        );
        assert!(polls.get() >= 4);
    }
}
