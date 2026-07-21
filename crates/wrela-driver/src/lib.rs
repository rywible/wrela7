//! Public command, event, outcome, and error vocabulary for the Wrela
//! toolchain. This crate owns no compiler composition, filesystem/process I/O,
//! or cache implementation; those remain behind the production composition
//! root.

#![forbid(unsafe_code)]

pub mod engine;

use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use wrela_build_model::{Sha256Digest, TargetIdentity, ValidatedBuildConfiguration};
use wrela_diagnostics::{
    Diagnostic, DiagnosticSortError, canonicalize_diagnostics, compare_diagnostics,
};
use wrela_format::{FormatOutput, TextEdit};
use wrela_image_report::{ImageReport, ReportError, ValidatedAnalysisFacts};
use wrela_lint::{LintFinding, LintOutput};
use wrela_source::{SourceDatabase, SourceFile, Span};
use wrela_test_model::{EncodedTestReport, ValidatedTestReport};

/// Minimal digest capability needed to bind public outcomes to canonical
/// report bytes without coupling the driver vocabulary to compiler internals.
pub trait OutcomeContentHasher {
    /// Return `None` only when cancellation was observed while hashing.
    fn sha256(&self, bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    name: String,
    path: PathBuf,
    present: bool,
}

impl DoctorCheck {
    pub fn new(name: String, path: PathBuf, present: bool) -> Result<Self, OutcomeError> {
        if name.trim().is_empty()
            || name.len() > 4096
            || path.as_os_str().as_encoded_bytes().len() > 1024 * 1024
            || !normal_absolute_path(&path)
        {
            return Err(OutcomeError::InvalidDoctorCheck);
        }
        Ok(Self {
            name,
            path,
            present,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    #[must_use]
    pub const fn present(&self) -> bool {
        self.present
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorOutcome {
    checks: Vec<DoctorCheck>,
}

impl DoctorOutcome {
    pub fn new(mut checks: Vec<DoctorCheck>) -> Result<Self, OutcomeError> {
        checks.sort_by(|left, right| left.name.cmp(&right.name));
        if checks.is_empty()
            || checks.len() > 1024
            || checks.windows(2).any(|pair| pair[0].name == pair[1].name)
        {
            return Err(OutcomeError::InvalidDoctorCheck);
        }
        Ok(Self { checks })
    }

    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.checks.iter().all(DoctorCheck::present)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeError {
    Cancelled,
    InvalidDoctorCheck,
    InvalidDiagnostics,
    DiagnosticResourceLimit,
    BuildIdentityMismatch,
    InvalidPublication,
    InvalidFormatOutput,
}

impl fmt::Display for OutcomeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("outcome construction was cancelled"),
            Self::InvalidDoctorCheck => formatter.write_str("invalid doctor check set"),
            Self::InvalidDiagnostics => formatter.write_str("invalid successful diagnostic set"),
            Self::DiagnosticResourceLimit => {
                formatter.write_str("cannot allocate the bounded canonical diagnostic report")
            }
            Self::BuildIdentityMismatch => {
                formatter.write_str("outcome analysis describes a different build or image")
            }
            Self::InvalidPublication => {
                formatter.write_str("outcome publication identity is invalid")
            }
            Self::InvalidFormatOutput => {
                formatter.write_str("format output paths or diagnostics are invalid")
            }
        }
    }
}

impl std::error::Error for OutcomeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSelection {
    pub manifest: PathBuf,
    pub image: String,
    pub target: TargetIdentity,
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticOptions {
    pub warnings_as_errors: bool,
    pub maximum_diagnostics: u32,
}

impl Default for DiagnosticOptions {
    fn default() -> Self {
        Self {
            warnings_as_errors: false,
            maximum_diagnostics: 100_000,
        }
    }
}

impl DiagnosticOptions {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.maximum_diagnostics > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestSelection {
    All,
    Comptime,
    Integration,
    Images,
    NameContains(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Doctor,
    Check {
        workspace: WorkspaceSelection,
        diagnostics: DiagnosticOptions,
    },
    Build {
        workspace: WorkspaceSelection,
        output_directory: PathBuf,
        diagnostics: DiagnosticOptions,
    },
    Test {
        workspace: WorkspaceSelection,
        output_directory: PathBuf,
        selection: TestSelection,
        diagnostics: DiagnosticOptions,
    },
    Format {
        manifest: PathBuf,
        files: Vec<PathBuf>,
        check_only: bool,
    },
    Lint {
        workspace: WorkspaceSelection,
        diagnostics: DiagnosticOptions,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent<'a> {
    PhaseStarted {
        phase: &'static str,
    },
    PhaseFinished {
        phase: &'static str,
        reused: bool,
    },
    /// A synchronous view of one diagnostic together with the sealed source
    /// database that gives every numeric file identity a stable path, text,
    /// and line map. Sinks that need to retain an event must render or copy a
    /// bounded presentation before this callback returns.
    Diagnostic {
        diagnostic: &'a Diagnostic,
        sources: &'a SourceDatabase,
    },
    ArtifactPublished {
        path: PathBuf,
        digest: Sha256Digest,
    },
    TestProgress {
        completed: u32,
        total: u32,
    },
}

pub trait EventSink {
    fn emit(&self, event: DriverEvent<'_>);
}

pub trait CompilerDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError>;
}

#[derive(Debug)]
pub enum CommandOutput {
    Doctor(DoctorOutcome),
    Check(Box<CheckOutcome>),
    Build(Box<BuildOutcome>),
    Test(Box<TestOutcome>),
    Format(FormatOutcome),
    Lint(LintOutcome),
}

impl CommandOutput {
    #[must_use]
    pub fn render_text(&self) -> String {
        match self {
            Self::Doctor(report) => report
                .checks()
                .iter()
                .map(|check| {
                    let state = if check.present() { "ok" } else { "missing" };
                    format!(
                        "{state:>7}  {:<16} {}\n",
                        check.name(),
                        check.path().display()
                    )
                })
                .collect(),
            Self::Check(outcome) => {
                let mut rendered = outcome.diagnostic_report().render_text();
                writeln!(
                    rendered,
                    "check completed with {} warning(s) and {} proof fact(s)",
                    outcome.diagnostic_report().warning_count(),
                    outcome.analysis().as_facts().proofs.len()
                )
                .expect("writing to a String cannot fail");
                rendered
            }
            Self::Build(outcome) => {
                let mut rendered = outcome.diagnostic_report().render_text();
                rendered.push_str(&outcome.report().render_summary());
                rendered
            }
            Self::Test(outcome) => {
                let mut rendered = outcome.diagnostic_report().render_text();
                writeln!(
                    rendered,
                    "test {}",
                    if outcome.report().passed() {
                        "passed"
                    } else {
                        "failed"
                    }
                )
                .expect("writing to a String cannot fail");
                rendered
            }
            Self::Format(outcome) => {
                if outcome.check_only() {
                    format!("{} file(s) would change\n", outcome.changed_files())
                } else {
                    format!("{} file(s) formatted\n", outcome.changed_files())
                }
            }
            Self::Lint(outcome) => {
                let mut rendered = outcome.diagnostic_report().render_text();
                writeln!(rendered, "{} lint finding(s)", outcome.findings().len())
                    .expect("writing to a String cannot fail");
                rendered
            }
        }
    }
}

/// Canonical diagnostics paired with the exact immutable sources whose
/// session-local [`wrela_source::FileId`] values appear in their spans.
/// Keeping this mapping in the public outcome/error vocabulary prevents a
/// terminal adapter from reducing useful diagnostics to anonymous numbers.
#[derive(Debug, PartialEq, Eq)]
pub struct DiagnosticReport {
    diagnostics: Vec<Diagnostic>,
    sources: SourceDatabase,
    errors: u32,
    warnings: u32,
}

impl DiagnosticReport {
    /// Seal a successful report. Every span must resolve into the supplied
    /// source database, diagnostics must be fully canonically ordered and
    /// duplicate-free, and no rejecting diagnostic is permitted.
    pub fn successful(
        diagnostics: Vec<Diagnostic>,
        sources: SourceDatabase,
        maximum_diagnostics: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, OutcomeError> {
        Self::seal(
            diagnostics,
            sources,
            maximum_diagnostics,
            false,
            is_cancelled,
        )
    }

    /// Seal a rejected report. At least one error must be present, while
    /// warnings remain available so a CLI can report the complete failure.
    pub fn rejected(
        diagnostics: Vec<Diagnostic>,
        sources: SourceDatabase,
        maximum_diagnostics: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, OutcomeError> {
        Self::seal(
            diagnostics,
            sources,
            maximum_diagnostics,
            true,
            is_cancelled,
        )
    }

    fn seal(
        diagnostics: Vec<Diagnostic>,
        sources: SourceDatabase,
        maximum_diagnostics: u32,
        require_error: bool,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, OutcomeError> {
        let diagnostics =
            canonicalize_diagnostics(diagnostics, is_cancelled).map_err(|error| match error {
                DiagnosticSortError::Cancelled => OutcomeError::Cancelled,
                DiagnosticSortError::Allocation => OutcomeError::DiagnosticResourceLimit,
            })?;
        if maximum_diagnostics == 0
            || diagnostics.len() > maximum_diagnostics as usize
            || diagnostics.windows(2).any(|pair| pair[0] == pair[1])
            || diagnostics
                .iter()
                .any(|diagnostic| !valid_diagnostic_sources(diagnostic, &sources))
        {
            return Err(OutcomeError::InvalidDiagnostics);
        }
        let errors = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error)
            .count();
        let warnings = diagnostics.len().saturating_sub(errors);
        if require_error != (errors != 0) {
            return Err(OutcomeError::InvalidDiagnostics);
        }
        Ok(Self {
            diagnostics,
            sources,
            errors: u32::try_from(errors).map_err(|_| OutcomeError::InvalidDiagnostics)?,
            warnings: u32::try_from(warnings).map_err(|_| OutcomeError::InvalidDiagnostics)?,
        })
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn sources(&self) -> &SourceDatabase {
        &self.sources
    }

    #[must_use]
    pub const fn error_count(&self) -> u32 {
        self.errors
    }

    #[must_use]
    pub const fn warning_count(&self) -> u32 {
        self.warnings
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<Diagnostic>, SourceDatabase) {
        (self.diagnostics, self.sources)
    }

    /// Stable human-facing rendering with canonical source paths, one-based
    /// line/byte-column positions, and bounded single-line excerpts.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut rendered = String::new();
        for diagnostic in &self.diagnostics {
            render_diagnostic(&mut rendered, diagnostic, &self.sources);
        }
        rendered
    }
}

#[derive(Debug)]
pub struct CheckOutcome {
    build: ValidatedBuildConfiguration,
    diagnostics: DiagnosticReport,
    analysis: ValidatedAnalysisFacts,
}

impl CheckOutcome {
    pub fn new(
        build: ValidatedBuildConfiguration,
        expected_image: &str,
        diagnostics: DiagnosticReport,
        analysis: ValidatedAnalysisFacts,
    ) -> Result<Self, OutcomeError> {
        if diagnostics.error_count() != 0 {
            return Err(OutcomeError::InvalidDiagnostics);
        }
        if expected_image.trim().is_empty()
            || analysis.build() != build.identity()
            || analysis.image_name() != expected_image
        {
            return Err(OutcomeError::BuildIdentityMismatch);
        }
        Ok(Self {
            build,
            diagnostics,
            analysis,
        })
    }

    #[must_use]
    pub fn build(&self) -> &ValidatedBuildConfiguration {
        &self.build
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        self.diagnostics.diagnostics()
    }

    #[must_use]
    pub fn diagnostic_report(&self) -> &DiagnosticReport {
        &self.diagnostics
    }

    #[must_use]
    pub fn analysis(&self) -> &ValidatedAnalysisFacts {
        &self.analysis
    }
}

#[derive(Debug)]
pub struct BuildOutcome {
    diagnostics: DiagnosticReport,
    artifact: PathBuf,
    artifact_digest: Sha256Digest,
    artifact_bytes: u64,
    report_path: PathBuf,
    report_digest: Sha256Digest,
    report_bytes: u64,
    report: ImageReport,
}

#[derive(Debug)]
pub struct BuildOutcomeCandidate {
    pub diagnostics: DiagnosticReport,
    pub artifact: PathBuf,
    pub artifact_digest: Sha256Digest,
    pub artifact_bytes: u64,
    pub report_path: PathBuf,
    pub report_digest: Sha256Digest,
    pub report_bytes: u64,
    pub report: ImageReport,
}

impl BuildOutcome {
    pub fn new(
        candidate: BuildOutcomeCandidate,
        hasher: &dyn OutcomeContentHasher,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, OutcomeError> {
        if is_cancelled() {
            return Err(OutcomeError::Cancelled);
        }
        candidate
            .report
            .validate_with_cancellation(is_cancelled)
            .map_err(map_report_outcome_error)?;
        let canonical_report = candidate
            .report
            .to_json_with_cancellation(is_cancelled)
            .map_err(map_report_outcome_error)?;
        let canonical_report_bytes =
            u64::try_from(canonical_report.len()).map_err(|_| OutcomeError::InvalidPublication)?;
        if candidate.diagnostics.error_count() != 0
            || !normal_absolute_path(&candidate.artifact)
            || !normal_absolute_path(&candidate.report_path)
            || candidate.artifact == candidate.report_path
            || candidate.artifact_bytes == 0
            || candidate.report_bytes == 0
            || candidate.artifact_digest != candidate.report.backend().artifact_digest
            || candidate.artifact_bytes != candidate.report.backend().artifact_bytes
            || candidate.report_bytes != canonical_report_bytes
            || candidate.report_digest
                != hasher
                    .sha256(canonical_report.as_bytes(), is_cancelled)
                    .ok_or(OutcomeError::Cancelled)?
            || digest_is_zero(candidate.artifact_digest)
            || digest_is_zero(candidate.report_digest)
        {
            return Err(OutcomeError::InvalidPublication);
        }
        if is_cancelled() {
            return Err(OutcomeError::Cancelled);
        }
        Ok(Self {
            diagnostics: candidate.diagnostics,
            artifact: candidate.artifact,
            artifact_digest: candidate.artifact_digest,
            artifact_bytes: candidate.artifact_bytes,
            report_path: candidate.report_path,
            report_digest: candidate.report_digest,
            report_bytes: candidate.report_bytes,
            report: candidate.report,
        })
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        self.diagnostics.diagnostics()
    }

    #[must_use]
    pub fn diagnostic_report(&self) -> &DiagnosticReport {
        &self.diagnostics
    }

    #[must_use]
    pub fn artifact(&self) -> &Path {
        &self.artifact
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> Sha256Digest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn artifact_bytes(&self) -> u64 {
        self.artifact_bytes
    }

    #[must_use]
    pub fn report_path(&self) -> &Path {
        &self.report_path
    }

    #[must_use]
    pub const fn report_digest(&self) -> Sha256Digest {
        self.report_digest
    }

    #[must_use]
    pub const fn report_bytes(&self) -> u64 {
        self.report_bytes
    }

    #[must_use]
    pub fn report(&self) -> &ImageReport {
        &self.report
    }
}

#[derive(Debug)]
pub struct TestOutcome {
    diagnostics: DiagnosticReport,
    report_path: PathBuf,
    report_digest: Sha256Digest,
    report_bytes: u64,
    report: ValidatedTestReport,
}

impl TestOutcome {
    pub fn new(
        diagnostics: DiagnosticReport,
        report_path: PathBuf,
        report_digest: Sha256Digest,
        report_bytes: u64,
        encoded: EncodedTestReport,
        hasher: &dyn OutcomeContentHasher,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, OutcomeError> {
        if is_cancelled() {
            return Err(OutcomeError::Cancelled);
        }
        let canonical_bytes =
            u64::try_from(encoded.len()).map_err(|_| OutcomeError::InvalidPublication)?;
        if diagnostics.error_count() != 0
            || !normal_absolute_path(&report_path)
            || digest_is_zero(report_digest)
            || report_bytes == 0
            || report_bytes != canonical_bytes
            || report_digest
                != hasher
                    .sha256(encoded.bytes(), is_cancelled)
                    .ok_or(OutcomeError::Cancelled)?
        {
            return Err(OutcomeError::InvalidPublication);
        }
        if is_cancelled() {
            return Err(OutcomeError::Cancelled);
        }
        let (report, _) = encoded.into_parts();
        Ok(Self {
            diagnostics,
            report_path,
            report_digest,
            report_bytes,
            report,
        })
    }

    #[must_use]
    pub fn diagnostic_report(&self) -> &DiagnosticReport {
        &self.diagnostics
    }

    #[must_use]
    pub fn report_path(&self) -> &Path {
        &self.report_path
    }

    #[must_use]
    pub const fn report_digest(&self) -> Sha256Digest {
        self.report_digest
    }

    #[must_use]
    pub const fn report_bytes(&self) -> u64 {
        self.report_bytes
    }

    #[must_use]
    pub fn report(&self) -> &ValidatedTestReport {
        &self.report
    }
}

fn valid_diagnostic_sources(diagnostic: &Diagnostic, sources: &SourceDatabase) -> bool {
    valid_report_span(diagnostic.primary, sources)
        && diagnostic
            .labels
            .iter()
            .all(|label| valid_report_span(label.span, sources))
        && diagnostic
            .related
            .iter()
            .all(|related| valid_report_span(related.span, sources))
        && diagnostic.repairs.iter().all(|repair| {
            repair
                .edits
                .iter()
                .all(|edit| valid_report_span(edit.span, sources))
        })
}

fn valid_report_span(span: Span, sources: &SourceDatabase) -> bool {
    sources
        .get(span.file)
        .is_some_and(|source| source.slice(span.range).is_some())
}

fn render_diagnostic(rendered: &mut String, diagnostic: &Diagnostic, sources: &SourceDatabase) {
    let severity = match diagnostic.severity {
        wrela_diagnostics::Severity::Error => "error",
        wrela_diagnostics::Severity::Warning => "warning",
    };
    let code = diagnostic
        .code
        .as_deref()
        .unwrap_or_else(|| diagnostic.category.as_str());
    let (source, line, column) = report_location(diagnostic.primary, sources);
    writeln!(
        rendered,
        "{severity}[{code}] {}:{line}:{column}: {}",
        source.path(),
        diagnostic.message
    )
    .expect("writing to a String cannot fail");
    let (excerpt, prefix, suffix) = bounded_line_excerpt(source, diagnostic.primary.range.start);
    rendered.push_str("  | ");
    if prefix {
        rendered.push('…');
    }
    rendered.push_str(excerpt);
    if suffix {
        rendered.push('…');
    }
    rendered.push('\n');

    for label in &diagnostic.labels {
        let (source, line, column) = report_location(label.span, sources);
        writeln!(
            rendered,
            "  = label {}:{line}:{column}: {}",
            source.path(),
            label.message
        )
        .expect("writing to a String cannot fail");
    }
    for note in &diagnostic.notes {
        writeln!(rendered, "  = note: {note}").expect("writing to a String cannot fail");
    }
    for help in &diagnostic.help {
        writeln!(rendered, "  = help: {help}").expect("writing to a String cannot fail");
    }
    for related in &diagnostic.related {
        let (source, line, column) = report_location(related.span, sources);
        writeln!(
            rendered,
            "  = related {}:{line}:{column}: {}",
            source.path(),
            related.message
        )
        .expect("writing to a String cannot fail");
    }
    for repair in &diagnostic.repairs {
        writeln!(rendered, "  = repair: {}", repair.message)
            .expect("writing to a String cannot fail");
        for edit in &repair.edits {
            let (source, line, column) = report_location(edit.span, sources);
            writeln!(
                rendered,
                "    {}:{line}:{column} replace with {:?}",
                source.path(),
                edit.replacement
            )
            .expect("writing to a String cannot fail");
        }
    }
}

fn report_location(span: Span, sources: &SourceDatabase) -> (&SourceFile, u32, u32) {
    let source = sources
        .get(span.file)
        .expect("DiagnosticReport sealed every file identity");
    let position = source
        .position(span.range.start)
        .expect("DiagnosticReport sealed every source range");
    (source, position.line, position.byte_column)
}

fn bounded_line_excerpt(source: &SourceFile, offset: u32) -> (&str, bool, bool) {
    const MAX_EXCERPT_BYTES: usize = 240;
    let text = source.text();
    let offset = offset as usize;
    let line_start = text[..offset].rfind('\n').map_or(0, |newline| newline + 1);
    let line_end = text[offset..]
        .find('\n')
        .map_or(text.len(), |newline| offset + newline);
    if line_end - line_start <= MAX_EXCERPT_BYTES {
        return (&text[line_start..line_end], false, false);
    }

    let mut start = offset.saturating_sub(MAX_EXCERPT_BYTES / 2).max(line_start);
    while start < offset && !text.is_char_boundary(start) {
        start += 1;
    }
    let mut end = start.saturating_add(MAX_EXCERPT_BYTES).min(line_end);
    while end > start && !text.is_char_boundary(end) {
        end -= 1;
    }
    if end <= offset && end < line_end {
        end = offset;
        while end < line_end && !text.is_char_boundary(end) {
            end += 1;
        }
    }
    (&text[start..end], start > line_start, end < line_end)
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && PathBuf::from_iter(path.components()) == path
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn digest_is_zero(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn map_report_outcome_error(error: ReportError) -> OutcomeError {
    match error {
        ReportError::Cancelled => OutcomeError::Cancelled,
        _ => OutcomeError::InvalidPublication,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatFileOutcome {
    path: PathBuf,
    output: FormatOutput,
}

impl FormatFileOutcome {
    pub fn new(path: PathBuf, output: FormatOutput) -> Result<Self, OutcomeError> {
        if !normal_absolute_path(&path) {
            return Err(OutcomeError::InvalidFormatOutput);
        }
        Ok(Self { path, output })
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    #[must_use]
    pub fn output(&self) -> &FormatOutput {
        &self.output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatOutcome {
    files: Vec<FormatFileOutcome>,
    diagnostics: Vec<Diagnostic>,
    maximum_edits_per_file: u32,
    check_only: bool,
}

impl FormatOutcome {
    pub fn new(
        mut files: Vec<FormatFileOutcome>,
        mut diagnostics: Vec<Diagnostic>,
        maximum_files: u32,
        maximum_edits_per_file: u32,
        maximum_diagnostics: u32,
        check_only: bool,
    ) -> Result<Self, OutcomeError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        diagnostics.sort_by(compare_diagnostics);
        if maximum_files == 0
            || maximum_edits_per_file == 0
            || maximum_diagnostics == 0
            || files.len() > maximum_files as usize
            || diagnostics.len() > maximum_diagnostics as usize
            || files.iter().any(|file| {
                !format_edit_count_within_limit(file.output.edits().len(), maximum_edits_per_file)
            })
            || files.windows(2).any(|pair| pair[0].path == pair[1].path)
            || diagnostics.windows(2).any(|pair| pair[0] == pair[1])
            || diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error)
        {
            return Err(OutcomeError::InvalidFormatOutput);
        }
        Ok(Self {
            files,
            diagnostics,
            maximum_edits_per_file,
            check_only,
        })
    }

    #[must_use]
    pub fn files(&self) -> &[FormatFileOutcome] {
        &self.files
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub const fn check_only(&self) -> bool {
        self.check_only
    }

    /// Exact caller-owned ceiling rechecked while sealing every file output.
    #[must_use]
    pub const fn maximum_edits_per_file(&self) -> u32 {
        self.maximum_edits_per_file
    }

    #[must_use]
    pub fn changed_files(&self) -> u32 {
        self.files
            .iter()
            .filter(|file| file.output.changed())
            .count()
            .try_into()
            .expect("FormatOutcome constructor bounded the file count")
    }

    pub fn edits(&self) -> impl Iterator<Item = &TextEdit> {
        self.files.iter().flat_map(|file| file.output.edits())
    }
}

fn format_edit_count_within_limit(edit_count: usize, maximum_edits_per_file: u32) -> bool {
    edit_count <= maximum_edits_per_file as usize
}

#[derive(Debug)]
pub struct LintOutcome {
    output: LintOutput,
    diagnostics: DiagnosticReport,
}

impl LintOutcome {
    pub fn new(output: LintOutput, diagnostics: DiagnosticReport) -> Result<Self, OutcomeError> {
        if output.denied()
            || diagnostics.error_count() != 0
            || output.findings().iter().any(|finding| {
                !diagnostics
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic == &finding.diagnostic)
            })
        {
            return Err(OutcomeError::InvalidDiagnostics);
        }
        Ok(Self {
            output,
            diagnostics,
        })
    }

    #[must_use]
    pub fn findings(&self) -> &[LintFinding] {
        self.output.findings()
    }

    #[must_use]
    pub fn diagnostic_report(&self) -> &DiagnosticReport {
        &self.diagnostics
    }

    #[must_use]
    pub fn denied(&self) -> bool {
        self.output.denied()
    }
}

#[derive(Debug)]
pub enum DriverError {
    Cancelled,
    Toolchain(String),
    CompilerServicesUnavailable,
    InvalidCommand(String),
    Input {
        phase: &'static str,
        message: String,
    },
    Rejected {
        report: DiagnosticReport,
    },
    Backend {
        phase: BackendFailurePhase,
        message: String,
    },
    Test {
        message: String,
    },
    Publication {
        path: PathBuf,
        message: String,
    },
}

/// Public phase classification retained when the private backend fails before
/// it can publish a runnable image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailurePhase {
    Compile,
    Link,
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("command was cancelled"),
            Self::Toolchain(error) => formatter.write_str(error),
            Self::CompilerServicesUnavailable => {
                formatter.write_str("compiler services are not linked in this developer build")
            }
            Self::InvalidCommand(message) => write!(formatter, "invalid command: {message}"),
            Self::Input { phase, message } => write!(formatter, "{phase} input failed: {message}"),
            Self::Rejected { report } => write!(
                formatter,
                "build rejected with {} error(s) and {} warning(s)",
                report.error_count(),
                report.warning_count()
            ),
            Self::Backend { message, .. } => write!(formatter, "backend failed: {message}"),
            Self::Test { message } => write!(formatter, "test execution failed: {message}"),
            Self::Publication { path, message } => {
                write!(formatter, "cannot publish {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for DriverError {}

impl DriverError {
    #[must_use]
    pub const fn diagnostic_report(&self) -> Option<&DiagnosticReport> {
        match self {
            Self::Rejected { report } => Some(report),
            Self::Cancelled
            | Self::Toolchain(_)
            | Self::CompilerServicesUnavailable
            | Self::InvalidCommand(_)
            | Self::Input { .. }
            | Self::Backend { .. }
            | Self::Test { .. }
            | Self::Publication { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DiagnosticReport, DoctorCheck, DoctorOutcome, DriverError, FormatOutcome, OutcomeError,
        ReportError, format_edit_count_within_limit, map_report_outcome_error,
    };
    use std::path::PathBuf;
    use wrela_build_model::Sha256Digest;
    use wrela_diagnostics::{Category, Diagnostic, Severity};
    use wrela_source::{FileId, SourceDatabase, SourceInput, Span, TextRange};

    fn sources() -> SourceDatabase {
        let mut sources = SourceDatabase::default();
        sources
            .add(SourceInput {
                path: "app/main.wr".to_owned(),
                text: "first\nbad thing\n".to_owned(),
                digest: Sha256Digest::from_bytes([1; 32]),
            })
            .expect("valid source database");
        sources
    }

    fn warning(code: &str) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(
            Category::TYPE,
            Span {
                file: FileId(0),
                range: TextRange::new(6, 9).expect("valid diagnostic span"),
            },
            "bad thing",
        );
        diagnostic.severity = Severity::Warning;
        diagnostic.code = Some(code.to_owned());
        diagnostic
    }

    #[test]
    fn doctor_outcome_is_canonical_and_unforgeable() {
        let outcome = DoctorOutcome::new(vec![
            DoctorCheck::new(
                "runtime".to_owned(),
                PathBuf::from("/toolchain/runtime"),
                true,
            )
            .expect("valid runtime check"),
            DoctorCheck::new(
                "backend".to_owned(),
                PathBuf::from("/toolchain/backend"),
                false,
            )
            .expect("valid backend check"),
        ])
        .expect("valid doctor outcome");
        assert_eq!(outcome.checks()[0].name(), "backend");
        assert!(!outcome.is_healthy());
        assert_eq!(
            DoctorCheck::new("bad".to_owned(), PathBuf::from("relative"), true),
            Err(OutcomeError::InvalidDoctorCheck)
        );
    }

    #[test]
    fn doctor_outcome_rejects_duplicate_observations() {
        let check = || {
            DoctorCheck::new(
                "backend".to_owned(),
                PathBuf::from("/toolchain/backend"),
                true,
            )
            .expect("valid check")
        };
        assert_eq!(
            DoctorOutcome::new(vec![check(), check()]),
            Err(OutcomeError::InvalidDoctorCheck)
        );
    }

    #[test]
    fn diagnostic_report_renders_stable_source_context() {
        let report =
            DiagnosticReport::successful(vec![warning("type-example")], sources(), 1, &|| false)
                .expect("valid warning report");
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.warning_count(), 1);
        let rendered = report.render_text();
        assert!(rendered.contains("warning[type-example] app/main.wr:2:1: bad thing"));
        assert!(rendered.contains("  | bad thing"));
    }

    #[test]
    fn diagnostic_report_rejects_nonadjacent_duplicates_under_partial_keys() {
        let repeated = warning("a");
        let middle = warning("b");
        assert_eq!(
            DiagnosticReport::successful(
                vec![repeated.clone(), middle, repeated],
                sources(),
                3,
                &|| false,
            ),
            Err(OutcomeError::InvalidDiagnostics)
        );
    }

    #[test]
    fn complete_diagnostic_order_is_permutation_independent() {
        let left = DiagnosticReport::successful(
            vec![warning("c"), warning("a"), warning("b")],
            sources(),
            3,
            &|| false,
        )
        .expect("first report");
        let right = DiagnosticReport::successful(
            vec![warning("b"), warning("c"), warning("a")],
            sources(),
            3,
            &|| false,
        )
        .expect("second report");
        assert_eq!(left, right);
    }

    #[test]
    fn rejection_counts_errors_and_warnings_by_actual_severity() {
        let advisory = warning("advisory");
        let mut error = warning("rejecting");
        error.severity = Severity::Error;
        let report = DiagnosticReport::rejected(vec![advisory, error], sources(), 2, &|| false)
            .expect("mixed rejection report");
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 1);
        assert_eq!(
            DriverError::Rejected { report }.to_string(),
            "build rejected with 1 error(s) and 1 warning(s)"
        );
    }

    #[test]
    fn backend_report_cancellation_is_preserved() {
        assert_eq!(
            map_report_outcome_error(ReportError::Cancelled),
            OutcomeError::Cancelled
        );
        assert_eq!(
            map_report_outcome_error(ReportError::InvalidLimits),
            OutcomeError::InvalidPublication
        );
    }

    #[test]
    fn format_outcome_retains_and_enforces_the_exact_edit_limit() {
        assert!(format_edit_count_within_limit(4, 4));
        assert!(!format_edit_count_within_limit(5, 4));

        let outcome = FormatOutcome::new(Vec::new(), Vec::new(), 1, 7, 1, true)
            .expect("valid empty format outcome");
        assert_eq!(outcome.maximum_edits_per_file(), 7);
        assert!(outcome.check_only());
        assert_eq!(
            FormatOutcome::new(Vec::new(), Vec::new(), 1, 0, 1, false),
            Err(OutcomeError::InvalidFormatOutput)
        );
    }
}
