//! Public command, event, outcome, and error vocabulary for the Wrela
//! toolchain. This crate owns no compiler composition, filesystem/process I/O,
//! or cache implementation; those remain behind the production composition
//! root.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{Sha256Digest, TargetIdentity, ValidatedBuildConfiguration};
use wrela_diagnostics::Diagnostic;
use wrela_format::{FormatOutput, TextEdit};
use wrela_image_report::{ImageReport, ValidatedAnalysisFacts};
use wrela_lint::{LintFinding, LintOutput};
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
    pub lockfile: PathBuf,
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
pub enum DriverEvent {
    PhaseStarted { phase: &'static str },
    PhaseFinished { phase: &'static str, reused: bool },
    Diagnostic(Diagnostic),
    ArtifactPublished { path: PathBuf, digest: Sha256Digest },
    TestProgress { completed: u32, total: u32 },
}

pub trait EventSink {
    fn emit(&self, event: DriverEvent);
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
            Self::Check(outcome) => format!(
                "check completed with {} diagnostic(s) and {} proof fact(s)\n",
                outcome.diagnostics().len(),
                outcome.analysis().as_facts().proofs.len()
            ),
            Self::Build(outcome) => outcome.report().render_summary(),
            Self::Test(outcome) => format!(
                "test {}\n",
                if outcome.report().passed() {
                    "passed"
                } else {
                    "failed"
                }
            ),
            Self::Format(outcome) => {
                format!("{} file(s) would change\n", outcome.changed_files())
            }
            Self::Lint(outcome) => format!("{} lint finding(s)\n", outcome.findings().len()),
        }
    }
}

#[derive(Debug)]
pub struct CheckOutcome {
    build: ValidatedBuildConfiguration,
    diagnostics: Vec<Diagnostic>,
    analysis: ValidatedAnalysisFacts,
}

impl CheckOutcome {
    pub fn new(
        build: ValidatedBuildConfiguration,
        expected_image: &str,
        mut diagnostics: Vec<Diagnostic>,
        analysis: ValidatedAnalysisFacts,
        maximum_diagnostics: u32,
    ) -> Result<Self, OutcomeError> {
        diagnostics.sort_by(|left, right| diagnostic_key(left).cmp(&diagnostic_key(right)));
        if maximum_diagnostics == 0
            || diagnostics.len() > maximum_diagnostics as usize
            || diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error)
            || diagnostics.windows(2).any(|pair| pair[0] == pair[1])
        {
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
        &self.diagnostics
    }

    #[must_use]
    pub fn analysis(&self) -> &ValidatedAnalysisFacts {
        &self.analysis
    }
}

#[derive(Debug)]
pub struct BuildOutcome {
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
            .map_err(|_| OutcomeError::InvalidPublication)?;
        let canonical_report = candidate
            .report
            .to_json_with_cancellation(is_cancelled)
            .map_err(|_| OutcomeError::InvalidPublication)?;
        let canonical_report_bytes =
            u64::try_from(canonical_report.len()).map_err(|_| OutcomeError::InvalidPublication)?;
        if !normal_absolute_path(&candidate.artifact)
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
    report_path: PathBuf,
    report_digest: Sha256Digest,
    report_bytes: u64,
    report: ValidatedTestReport,
}

impl TestOutcome {
    pub fn new(
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
        if !normal_absolute_path(&report_path)
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
            report_path,
            report_digest,
            report_bytes,
            report,
        })
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

fn diagnostic_key(diagnostic: &Diagnostic) -> (&str, u8, u32, u32, u32, &str) {
    (
        diagnostic.category.as_str(),
        match diagnostic.severity {
            wrela_diagnostics::Severity::Error => 0,
            wrela_diagnostics::Severity::Warning => 1,
        },
        diagnostic.primary.file.0,
        diagnostic.primary.range.start,
        diagnostic.primary.range.end,
        &diagnostic.message,
    )
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
}

impl FormatOutcome {
    pub fn new(
        mut files: Vec<FormatFileOutcome>,
        mut diagnostics: Vec<Diagnostic>,
        maximum_files: u32,
        maximum_diagnostics: u32,
    ) -> Result<Self, OutcomeError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        diagnostics.sort_by(|left, right| diagnostic_key(left).cmp(&diagnostic_key(right)));
        if maximum_files == 0
            || maximum_diagnostics == 0
            || files.len() > maximum_files as usize
            || diagnostics.len() > maximum_diagnostics as usize
            || files.windows(2).any(|pair| pair[0].path == pair[1].path)
            || diagnostics.windows(2).any(|pair| pair[0] == pair[1])
            || diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == wrela_diagnostics::Severity::Error)
        {
            return Err(OutcomeError::InvalidFormatOutput);
        }
        Ok(Self { files, diagnostics })
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

#[derive(Debug)]
pub struct LintOutcome {
    output: LintOutput,
}

impl LintOutcome {
    #[must_use]
    pub fn from_output(output: LintOutput) -> Self {
        Self { output }
    }

    #[must_use]
    pub fn findings(&self) -> &[LintFinding] {
        self.output.findings()
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
        diagnostics: Vec<Diagnostic>,
    },
    Backend {
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
            Self::Rejected { diagnostics } => write!(
                formatter,
                "build rejected with {} error(s)",
                diagnostics.len()
            ),
            Self::Backend { message } => write!(formatter, "backend failed: {message}"),
            Self::Test { message } => write!(formatter, "test execution failed: {message}"),
            Self::Publication { path, message } => {
                write!(formatter, "cannot publish {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for DriverError {}

#[cfg(test)]
mod tests {
    use super::{DoctorCheck, DoctorOutcome, OutcomeError};
    use std::path::PathBuf;

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
}
