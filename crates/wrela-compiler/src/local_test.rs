//! Concrete local revision-0.1 test composition.
//!
//! Discovery, independently sealed group compilation, native backend
//! execution, QEMU orchestration, canonical report encoding, and create-new
//! publication all consume the same verified toolchain observation and build
//! identity. No test is executed as a hosted process.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use wrela_diagnostics::{Diagnostic, Severity};
use wrela_driver::{
    BackendFailurePhase, Command, CommandOutput, CompilerDriver, DiagnosticReport, DriverError,
    DriverEvent, EventSink, TestOutcome, WorkspaceSelection,
};
use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, EncodeRequest, encode_and_verify};
use wrela_package_loader::{ContentHasher, SoftwareSha256, sha256_cancellable};
use wrela_sema::{
    AnalysisChangeSet, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer, SemanticAnalyzer,
};
use wrela_semantic_lower::{CanonicalSemanticLowerer, SemanticLowerer};
use wrela_test_model::{
    CanonicalTestReportCodec, FailurePhase, FullImageTestGroup, ImageExecutionEvidence,
    ImageGroupResult, ImageRoot, TestOutcome as ModelTestOutcome, ValidatedTestPlan,
    seal_test_report_encoding,
};
use wrela_test_runner::{
    CanonicalImageHarness, ImageArtifactRequest, LocalProcessExecutor, RunRequest, TestRunner,
    seal_image_artifact,
};

use crate::local_build::{
    BackendProcessRequest, LocalOutcomeHasher, execute_backend, map_flow_codec_error,
    merge_flow_diagnostics, normal_absolute_path, prepare_output_directory, publish_build,
    read_private_output, sync_directory, validate_output_selection, write_new_publication_file,
};
use crate::local_check::{LocalAnalysis, LocalCheckDriver};
use crate::{
    AnalysisFactAssembler, AnalysisFactAssemblyError, AnalysisFactRequest, BuildIntent,
    CanonicalAnalysisFactAssembler, CompositionError, PipelineLimits,
};

const REPORT_FILE_NAME: &str = "test-report.bin";
#[cfg(unix)]
const PRIVATE_RUN_CREATE_ATTEMPTS: u64 = 256;
#[cfg(unix)]
const MAXIMUM_GROUP_QMP_SUFFIX: &str = "group-4294967295/qmp.sock";
static TEST_TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct LocalTestDriver {
    frontend: LocalCheckDriver,
}

impl LocalTestDriver {
    pub fn new(
        toolchain: wrela_toolchain::Toolchain,
        limits: PipelineLimits,
    ) -> Result<Self, CompositionError> {
        Ok(Self {
            frontend: LocalCheckDriver::new(toolchain, limits)?,
        })
    }

    pub fn discover(limits: PipelineLimits) -> Result<Self, DriverError> {
        Ok(Self {
            frontend: LocalCheckDriver::discover(limits)?,
        })
    }

    #[must_use]
    pub const fn limits(&self) -> PipelineLimits {
        self.frontend.limits()
    }

    fn test(
        &self,
        workspace: &WorkspaceSelection,
        output_directory: &Path,
        selection: &wrela_driver::TestSelection,
        options: &wrela_driver::DiagnosticOptions,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        validate_output_selection(output_directory)?;
        let limits = self.limits();
        let LocalAnalysis {
            build,
            image_name: _,
            diagnostics,
            analysis,
            analyzed,
            verification,
            warnings_as_errors,
            standard_library_package,
            declared_image_entries,
        } = self.frontend.analyze(
            workspace,
            options,
            BuildIntent::Test { selection },
            events,
            is_cancelled,
        )?;
        if analysis.is_some() {
            return Err(test_error(
                "test discovery unexpectedly produced ordinary build-report facts",
            ));
        }
        let (hir, mut discovery) = analyzed.into_parts();
        let plan = discovery
            .test_plan
            .take()
            .ok_or_else(|| test_error("semantic test discovery omitted its sealed test plan"))?;
        let comptime_results = std::mem::take(&mut discovery.comptime_test_results);
        if discovery.compiled_test_group.is_some()
            || comptime_results.len() != plan.unit_tests().len()
        {
            return Err(test_error(
                "semantic test discovery returned mismatched plan metadata or results",
            ));
        }

        prepare_output_directory(output_directory)?;
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(plan.image_groups().len())
            .map_err(|_| test_error("cannot allocate bounded image artifact set"))?;
        let mut preexecution_results = Vec::new();
        preexecution_results
            .try_reserve_exact(plan.image_groups().len())
            .map_err(|_| test_error("cannot allocate bounded image failure set"))?;
        let mut diagnostics = diagnostics;
        let completed_units = u32::try_from(comptime_results.len())
            .map_err(|_| test_error("comptime result count does not fit progress protocol"))?;
        let total_tests = plan
            .unit_tests()
            .len()
            .checked_add(
                plan.image_groups()
                    .iter()
                    .map(|group| group.tests.len())
                    .sum::<usize>(),
            )
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(|| test_error("test count does not fit progress protocol"))?;
        events.emit(DriverEvent::TestProgress {
            completed: completed_units,
            total: total_tests,
        });

        for group in plan.image_groups() {
            check_cancelled(is_cancelled)?;
            let declared_entry = match &group.root {
                wrela_test_model::ImageRoot::GeneratedHarness { .. } => None,
                wrela_test_model::ImageRoot::Declared { image_name, .. } => Some(
                    declared_image_entries
                        .binary_search_by(|(name, _)| name.as_str().cmp(image_name))
                        .ok()
                        .and_then(|index| declared_image_entries.get(index))
                        .map(|(_, declaration)| *declaration)
                        .ok_or_else(|| {
                            test_error(format!(
                                "test group `{}` refers to unresolved image `{image_name}`",
                                group.name
                            ))
                        })?,
                ),
            };
            let compiled = CanonicalSemanticAnalyzer::new()
                .analyze(
                    AnalysisRequest {
                        hir: hir.clone(),
                        standard_library_package,
                        target: verification.target().semantic(),
                        build: &build,
                        mode: AnalysisMode::CompileTestGroup {
                            plan: &plan,
                            group: group.id,
                            declared_entry,
                        },
                        changes: &AnalysisChangeSet {
                            previous_source_graph: None,
                            changed_declarations: Vec::new(),
                        },
                        limits: limits.semantic,
                    },
                    is_cancelled,
                )
                .map_err(map_semantic_error)?;
            let (compiled, semantic_diagnostics) = compiled.into_parts();
            diagnostics = merge_diagnostics(
                diagnostics,
                semantic_diagnostics,
                warnings_as_errors,
                options.maximum_diagnostics,
                events,
                is_cancelled,
            )?;
            let compiled = compiled.map_err(|_| {
                test_error(format!(
                    "test group `{}` remained partial without a rejecting diagnostic",
                    group.name
                ))
            })?;
            let analysis = CanonicalAnalysisFactAssembler::new()
                .assemble(
                    AnalysisFactRequest {
                        analysis: &compiled,
                        limits: limits.analysis_facts,
                    },
                    is_cancelled,
                )
                .map_err(map_analysis_fact_error)?;
            let expected_image_name = compiled
                .facts()
                .graph
                .as_ref()
                .map(|graph| graph.name.clone())
                .ok_or_else(|| test_error("compiled test group has no closed image graph"))?;

            let semantic = CanonicalSemanticLowerer::new()
                .lower(
                    wrela_semantic_lower::LowerRequest {
                        input: compiled,
                        limits: limits.semantic_lower,
                    },
                    is_cancelled,
                )
                .map_err(map_semantic_lower_error)?;
            let flow = CanonicalFlowLowerer::new()
                .lower(
                    wrela_flow_lower::LowerRequest {
                        input: semantic.into_parts().0,
                        limits: limits.flow_lower,
                    },
                    is_cancelled,
                )
                .map_err(map_flow_lower_error)?;
            let (flow, _flow_report, flow_diagnostics) = flow.into_parts();
            diagnostics = merge_flow_diagnostics(
                diagnostics,
                flow_diagnostics,
                warnings_as_errors,
                options.maximum_diagnostics,
                events,
                is_cancelled,
            )?;
            let encoded = encode_and_verify(
                &CanonicalFlowWirCodec,
                EncodeRequest {
                    wir: &flow,
                    limits: limits.flow_codec,
                },
                is_cancelled,
            )
            .map_err(map_flow_codec_error)?;
            let wir_digest = sha256_cancellable(&SoftwareSha256, encoded.bytes(), is_cancelled)
                .map_err(|_| DriverError::Cancelled)?;
            let backend = match execute_backend(
                BackendProcessRequest {
                    build: &build,
                    flow_wir: encoded.bytes(),
                    flow_wir_digest: wir_digest,
                    verification: &verification,
                    limits: limits.backend,
                },
                is_cancelled,
            ) {
                Ok(backend) => backend,
                Err(DriverError::Cancelled) => return Err(DriverError::Cancelled),
                Err(DriverError::Backend { phase, message }) => {
                    preexecution_results.push(preexecution_failure(
                        &plan,
                        group,
                        match phase {
                            BackendFailurePhase::Compile => FailurePhase::Compile,
                            BackendFailurePhase::Link => FailurePhase::Link,
                        },
                        message,
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            };
            let report = wrela_image_report::decode_image_report_json(
                &backend.report,
                build.identity(),
                limits.backend.analysis_report_facts,
                limits.backend.report_facts,
                limits.backend.maximum_report_bytes,
                is_cancelled,
            )
            .map_err(map_backend_report_error)?;
            if report.image_name() != expected_image_name
                || report.analysis() != analysis.as_facts()
                || report.backend().flow_wir_digest != wir_digest
                || report.backend().artifact_digest != backend.artifact_digest
                || report.backend().artifact_bytes != backend.artifact_bytes
            {
                return Err(test_error(format!(
                    "backend report for test group `{}` disagrees with sealed inputs",
                    group.name
                )));
            }
            let publication = publish_build(
                output_directory,
                &group.name,
                &backend.artifact,
                backend.artifact_digest,
                &backend.report,
                backend.report_digest,
                limits,
                is_cancelled,
            )?;
            let artifact = seal_image_artifact(
                ImageArtifactRequest {
                    plan: &plan,
                    group: group.id,
                    path: publication.artifact_path,
                    digest: backend.artifact_digest,
                    bytes: backend.artifact_bytes,
                    maximum_bytes: limits.backend.link.image_bytes,
                    build: build.identity().clone(),
                },
                is_cancelled,
            )
            .map_err(map_run_error)?;
            events.emit(DriverEvent::ArtifactPublished {
                path: artifact.path().to_owned(),
                digest: artifact.digest(),
            });
            artifacts.push(artifact);
        }

        let working = PrivateRunDirectory::create(output_directory, is_cancelled)?;
        let report = TestRunner {
            executor: &LocalProcessExecutor::new(),
            harness: &CanonicalImageHarness::new(),
        }
        .run(
            RunRequest {
                plan: &plan,
                artifacts: &artifacts,
                preexecution_results: &preexecution_results,
                comptime_results: &comptime_results,
                target: verification.target(),
                toolchain: verification.toolchain(),
                working_directory: working.path(),
                limits: limits.test_runner,
            },
            is_cancelled,
        )
        .map_err(map_run_error)?;
        events.emit(DriverEvent::TestProgress {
            completed: total_tests,
            total: total_tests,
        });
        drop(working);

        let encoded = seal_test_report_encoding(
            &CanonicalTestReportCodec::new(),
            report,
            limits.test_plan.report_bytes,
            is_cancelled,
        )
        .map_err(map_test_report_codec_error)?;
        let publication = publish_report(
            output_directory,
            encoded.bytes(),
            limits.test_plan.report_bytes,
            is_cancelled,
        )?;
        let outcome = TestOutcome::new(
            diagnostics,
            publication.path,
            publication.digest,
            publication.bytes,
            encoded,
            &LocalOutcomeHasher,
            is_cancelled,
        )
        .map_err(|error| match error {
            wrela_driver::OutcomeError::Cancelled => DriverError::Cancelled,
            error => test_error(format!("invalid test outcome: {error}")),
        })?;
        Ok(CommandOutput::Test(Box::new(outcome)))
    }
}

fn preexecution_failure(
    plan: &ValidatedTestPlan,
    group: &FullImageTestGroup,
    phase: FailurePhase,
    message: String,
) -> ImageGroupResult {
    let scenario_digest = match group.root {
        ImageRoot::GeneratedHarness { .. } => None,
        ImageRoot::Declared { scenario, .. } => plan
            .scenarios()
            .get(scenario.0 as usize)
            .map(|scenario| scenario.digest),
    };
    ImageGroupResult {
        group: group.id,
        cases: Vec::new(),
        events: Vec::new(),
        evidence: ImageExecutionEvidence {
            image_digest: None,
            target_digest: plan.build().target_package,
            emulator_digest: None,
            scenario_digest,
            command_digest: None,
            event_stream_digest: None,
            exit_code: None,
            stderr: Vec::new(),
        },
        infrastructure_failure: Some(ModelTestOutcome::Failed { phase, message }),
    }
}

impl CompilerDriver for LocalTestDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        match command {
            Command::Test {
                workspace,
                output_directory,
                selection,
                diagnostics,
            } => self.test(
                workspace,
                output_directory,
                selection,
                diagnostics,
                events,
                is_cancelled,
            ),
            _ => Err(DriverError::InvalidCommand(
                "local test driver accepts only a normalized `test` command".to_owned(),
            )),
        }
    }
}

pub fn execute_local_test(command: &Command) -> Result<CommandOutput, DriverError> {
    LocalTestDriver::discover(PipelineLimits::standard())?.execute(
        command,
        &SilentEvents,
        &never_cancelled,
    )
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

const fn never_cancelled() -> bool {
    false
}

fn merge_diagnostics(
    diagnostics: DiagnosticReport,
    mut incoming: Vec<Diagnostic>,
    warnings_as_errors: bool,
    maximum_diagnostics: u32,
    events: &dyn EventSink,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<DiagnosticReport, DriverError> {
    if warnings_as_errors {
        for diagnostic in &mut incoming {
            check_cancelled(is_cancelled)?;
            if diagnostic.severity == Severity::Warning {
                diagnostic.severity = Severity::Error;
            }
        }
    }
    let (mut all, sources) = diagnostics.into_parts();
    all.try_reserve_exact(incoming.len())
        .map_err(|_| test_error("cannot allocate bounded test diagnostics"))?;
    all.extend(incoming);
    let rejected = all
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error);
    let report = if rejected {
        DiagnosticReport::rejected(all, sources, maximum_diagnostics, is_cancelled)
    } else {
        DiagnosticReport::successful(all, sources, maximum_diagnostics, is_cancelled)
    }
    .map_err(|error| match error {
        wrela_driver::OutcomeError::Cancelled => DriverError::Cancelled,
        error => test_error(format!("invalid test diagnostics: {error}")),
    })?;
    if rejected {
        emit_diagnostics(&report, events, is_cancelled)?;
        return Err(DriverError::Rejected { report });
    }
    Ok(report)
}

fn emit_diagnostics(
    report: &DiagnosticReport,
    events: &dyn EventSink,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DriverError> {
    for diagnostic in report.diagnostics() {
        check_cancelled(is_cancelled)?;
        events.emit(DriverEvent::Diagnostic {
            diagnostic,
            sources: report.sources(),
        });
    }
    check_cancelled(is_cancelled)
}

struct ReportPublication {
    path: PathBuf,
    digest: wrela_build_model::Sha256Digest,
    bytes: u64,
}

fn publish_report(
    output_directory: &Path,
    bytes: &[u8],
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ReportPublication, DriverError> {
    check_cancelled(is_cancelled)?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| publication_error(output_directory, "report length does not fit u64"))?;
    if bytes.is_empty() || length > maximum_bytes {
        return Err(publication_error(
            output_directory,
            "canonical test report exceeds its publication limit",
        ));
    }
    let digest = SoftwareSha256.sha256(bytes);
    let path = output_directory.join(REPORT_FILE_NAME);
    if !normal_absolute_path(&path) {
        return Err(publication_error(
            &path,
            "test report path is not normalized and absolute",
        ));
    }
    if fs::symlink_metadata(&path).is_ok() {
        return Err(publication_error(
            &path,
            "destination already exists; test reports use create-new publication",
        ));
    }
    let sequence = TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staged = output_directory.join(format!(
        ".wrela-test-report-{}-{sequence:016x}.tmp",
        std::process::id()
    ));
    write_new_publication_file(&staged, bytes)?;
    let published = (|| {
        check_cancelled(is_cancelled)?;
        fs::hard_link(&staged, &path)
            .map_err(|error| publication_error(&path, error.to_string()))?;
        fs::remove_file(&staged).map_err(|error| publication_error(&staged, error.to_string()))?;
        sync_directory(output_directory)?;
        let observed = read_private_output(&path, maximum_bytes, digest, is_cancelled)?;
        if observed != bytes {
            return Err(publication_error(
                &path,
                "published report differs from its sealed canonical bytes",
            ));
        }
        Ok(ReportPublication {
            path: path.clone(),
            digest,
            bytes: length,
        })
    })();
    if published.is_err() {
        let _ = fs::remove_file(&staged);
        let _ = fs::remove_file(&path);
        let _ = sync_directory(output_directory);
    }
    published
}

struct PrivateRunDirectory {
    path: PathBuf,
}

impl PrivateRunDirectory {
    fn create(
        output_directory: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, DriverError> {
        check_cancelled(is_cancelled)?;
        #[cfg(unix)]
        {
            let output_parent = fs::canonicalize(output_directory)
                .map_err(|error| publication_error(output_directory, error.to_string()))?;
            if let Some(directory) = Self::create_in_parent(&output_parent, is_cancelled)? {
                return Ok(directory);
            }
            let short_parent = fs::canonicalize("/tmp").map_err(|error| {
                publication_error(
                    Path::new("/tmp"),
                    format!("cannot resolve short private run root: {error}"),
                )
            })?;
            if short_parent != output_parent
                && let Some(directory) = Self::create_in_parent(&short_parent, is_cancelled)?
            {
                return Ok(directory);
            }
            Err(publication_error(
                output_directory,
                "cannot allocate a bounded private test-run directory",
            ))
        }
        #[cfg(not(unix))]
        {
            let sequence = TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = output_directory.join(format!(
                ".wrela-test-run-{}-{sequence:016x}",
                std::process::id()
            ));
            fs::create_dir(&path).map_err(|error| publication_error(&path, error.to_string()))?;
            let directory = Self { path };
            check_cancelled(is_cancelled)?;
            Ok(directory)
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn create_in_parent(
        parent: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Self>, DriverError> {
        let sample = parent.join(format!(".wrela-test-run-{}-{:016x}", std::process::id(), 0));
        if !private_run_path_supports_qmp(&sample) {
            return Ok(None);
        }
        for _ in 0..PRIVATE_RUN_CREATE_ATTEMPTS {
            check_cancelled(is_cancelled)?;
            let sequence = TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".wrela-test-run-{}-{sequence:016x}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    let directory = Self { path };
                    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                        .map_err(|error| publication_error(directory.path(), error.to_string()))?;
                    validate_private_run_directory(directory.path())?;
                    check_cancelled(is_cancelled)?;
                    return Ok(Some(directory));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(publication_error(&path, error.to_string())),
            }
        }
        Ok(None)
    }
}

#[cfg(unix)]
fn private_run_path_supports_qmp(path: &Path) -> bool {
    wrela_test_runner::valid_qmp_unix_path(&path.join(MAXIMUM_GROUP_QMP_SUFFIX))
}

#[cfg(unix)]
fn validate_private_run_directory(path: &Path) -> Result<(), DriverError> {
    let canonical =
        fs::canonicalize(path).map_err(|error| publication_error(path, error.to_string()))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| publication_error(path, error.to_string()))?;
    if canonical != path
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || !private_run_path_supports_qmp(path)
    {
        return Err(publication_error(
            path,
            "private test-run directory is not canonical, real, mode 0700, and QMP-bounded",
        ));
    }
    Ok(())
}

impl Drop for PrivateRunDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DriverError> {
    if is_cancelled() {
        Err(DriverError::Cancelled)
    } else {
        Ok(())
    }
}

fn map_semantic_error(error: wrela_sema::AnalysisFailure) -> DriverError {
    match error {
        wrela_sema::AnalysisFailure::Cancelled => DriverError::Cancelled,
        error => test_error(error.to_string()),
    }
}

fn map_semantic_lower_error(error: wrela_semantic_lower::LowerError) -> DriverError {
    match error {
        wrela_semantic_lower::LowerError::Cancelled => DriverError::Cancelled,
        error => test_error(error.to_string()),
    }
}

fn map_flow_lower_error(error: wrela_flow_lower::LowerError) -> DriverError {
    match error {
        wrela_flow_lower::LowerError::Cancelled => DriverError::Cancelled,
        error => test_error(error.to_string()),
    }
}

fn map_analysis_fact_error(error: AnalysisFactAssemblyError) -> DriverError {
    match error {
        AnalysisFactAssemblyError::Cancelled => DriverError::Cancelled,
        error => test_error(format!("test analysis facts failed: {error}")),
    }
}

fn map_backend_report_error(error: wrela_image_report::ReportError) -> DriverError {
    match error {
        wrela_image_report::ReportError::Cancelled => DriverError::Cancelled,
        error => test_error(format!("backend report verification failed: {error}")),
    }
}

fn map_run_error(error: wrela_test_runner::RunError) -> DriverError {
    match error {
        wrela_test_runner::RunError::Cancelled
        | wrela_test_runner::RunError::Execute(wrela_test_runner::ExecuteError::Cancelled)
        | wrela_test_runner::RunError::InvalidPlan(wrela_test_model::TestModelError::Cancelled)
        | wrela_test_runner::RunError::InvalidReport(wrela_test_model::TestModelError::Cancelled)
        | wrela_test_runner::RunError::GuestProtocol(wrela_test_model::TestModelError::Cancelled) => {
            DriverError::Cancelled
        }
        error => test_error(error.to_string()),
    }
}

fn map_test_report_codec_error(error: wrela_test_model::TestReportCodecError) -> DriverError {
    match error {
        wrela_test_model::TestReportCodecError::Cancelled => DriverError::Cancelled,
        error => test_error(format!("test report encoding failed: {error}")),
    }
}

fn test_error(message: impl Into<String>) -> DriverError {
    DriverError::Test {
        message: message.into(),
    }
}

fn publication_error(path: &Path, message: impl Into<String>) -> DriverError {
    DriverError::Publication {
        path: path.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
fn declared_test_output_path(directory: &Path, group: &str) -> PathBuf {
    directory.join(format!("{group}.efi"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_name_and_group_artifact_names_are_distinct() {
        assert_eq!(REPORT_FILE_NAME, "test-report.bin");
        assert_eq!(
            declared_test_output_path(std::path::Path::new("/tmp/out"), "boots"),
            std::path::PathBuf::from("/tmp/out/boots.efi")
        );
    }

    #[test]
    fn scalar_test_pipeline_errors_preserve_cancellation() {
        assert!(matches!(
            map_analysis_fact_error(AnalysisFactAssemblyError::Cancelled),
            DriverError::Cancelled
        ));
        assert!(matches!(
            map_backend_report_error(wrela_image_report::ReportError::Cancelled),
            DriverError::Cancelled
        ));
        assert!(matches!(
            map_run_error(wrela_test_runner::RunError::Execute(
                wrela_test_runner::ExecuteError::Cancelled,
            )),
            DriverError::Cancelled
        ));
        assert!(matches!(
            map_test_report_codec_error(wrela_test_model::TestReportCodecError::Cancelled),
            DriverError::Cancelled
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_run_directory_falls_back_to_a_short_root_and_cleans_up() {
        let unique = TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let fixture = fs::canonicalize("/tmp")
            .expect("canonical short temp root")
            .join(format!(
                "wrela-private-run-fixture-{}-{unique:016x}",
                std::process::id()
            ));
        let output = fixture.join("x".repeat(120));
        fs::create_dir_all(&output).expect("create long output fixture");
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700))
            .expect("restrict fixture root");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))
            .expect("restrict long output fixture");

        let directory = PrivateRunDirectory::create(&output, &|| false)
            .expect("allocate bounded private run directory");
        assert!(!directory.path().starts_with(&output));
        assert!(private_run_path_supports_qmp(directory.path()));
        assert_eq!(
            fs::symlink_metadata(directory.path())
                .expect("private run metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let path = directory.path().to_owned();
        drop(directory);
        assert!(!path.exists());
        fs::remove_dir_all(fixture).expect("remove long output fixture");
    }

    #[cfg(unix)]
    #[test]
    fn private_run_directory_cancellation_after_creation_leaves_no_residue() {
        let unique = TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let output = fs::canonicalize("/tmp")
            .expect("canonical short temp root")
            .join(format!(
                "wrela-private-run-cancel-{}-{unique:016x}",
                std::process::id()
            ));
        fs::create_dir(&output).expect("create cancellation fixture");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))
            .expect("restrict cancellation fixture");
        let polls = std::cell::Cell::new(0_u8);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert!(matches!(
            PrivateRunDirectory::create(&output, &cancelled),
            Err(DriverError::Cancelled)
        ));
        assert_eq!(
            fs::read_dir(&output)
                .expect("read cancellation fixture")
                .count(),
            0
        );
        assert_eq!(polls.get(), 3);
        fs::remove_dir(output).expect("remove cancellation fixture");
    }
}
