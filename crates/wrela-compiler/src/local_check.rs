//! Concrete, local revision-0.1 `check` command composition.
//!
//! Discovery produces one explicit [`Toolchain`] capability. Execution then
//! verifies that complete installation before any source is acquired, and all
//! later phases consume only the verified toolchain, target, workspace, and
//! sealed producer outputs. No phase searches `PATH` or reopens a component by
//! an undeclared locator.

use std::cmp::Ordering;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use wrela_diagnostics::{
    Diagnostic, DiagnosticSortError, Severity, canonicalize_diagnostics, compare_diagnostics,
};
use wrela_driver::{
    CheckOutcome, Command, CommandOutput, CompilerDriver, DiagnosticReport, DriverError,
    DriverEvent, EventSink, TestSelection, WorkspaceSelection,
};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
};
use wrela_package::PackageLocator;
use wrela_package_loader::SoftwareSha256;
use wrela_sema::{
    AnalysisChangeSet, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer, SemanticAnalyzer,
    TestDiscoverySelection,
};
use wrela_test_model::{
    CanonicalImageScenarioCodec, DeclaredImageTest, ScenarioDecodeRequest, ScenarioId,
    decode_and_verify_image_scenario,
};
use wrela_toolchain::Toolchain;

use crate::{
    AnalysisFactAssembler, AnalysisFactAssemblyError, AnalysisFactRequest, BuildIntent,
    BuildPlanner, BuildPlanningError, BuildPlanningRequest, CanonicalAnalysisFactAssembler,
    CanonicalBuildPlanner, CompositionError, FrontendInputError, FrontendWorkspaceRequest,
    LocalFrontendService, LocalToolchainVerificationError, LocalToolchainVerifier, PipelineLimits,
};

const MANIFEST_FILE_NAME: &str = "wrela.toml";
const LOCKFILE_FILE_NAME: &str = "wrela.lock";
const ROOT_LOCATOR: &str = ".";
const MAX_COMMAND_PATH_BYTES: usize = 64 * 1024;
const MAX_SELECTION_BYTES: usize = 4096;

/// Production driver for the local, in-process revision-0.1 check pipeline.
///
/// The toolchain location is resolved once, outside command execution. This
/// keeps the filesystem authority explicit and makes a single execution
/// independent of later environment changes.
#[derive(Debug, Clone)]
pub struct LocalCheckDriver {
    toolchain: Toolchain,
    limits: PipelineLimits,
}

impl LocalCheckDriver {
    /// Construct from one already selected toolchain root.
    pub fn new(toolchain: Toolchain, limits: PipelineLimits) -> Result<Self, CompositionError> {
        limits.validate()?;
        Ok(Self { toolchain, limits })
    }

    /// Resolve the declared development override or the installation that
    /// contains the running frontend. `Toolchain::discover` never searches
    /// `PATH`.
    pub fn discover(limits: PipelineLimits) -> Result<Self, DriverError> {
        let toolchain =
            Toolchain::discover().map_err(|error| DriverError::Toolchain(error.to_string()))?;
        Self::new(toolchain, limits).map_err(composition_error)
    }

    #[must_use]
    pub fn toolchain_root(&self) -> &Path {
        self.toolchain.root()
    }

    #[must_use]
    pub const fn limits(&self) -> PipelineLimits {
        self.limits
    }

    pub(super) fn analyze(
        &self,
        workspace: &WorkspaceSelection,
        options: &wrela_driver::DiagnosticOptions,
        intent: BuildIntent<'_>,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LocalAnalysis, DriverError> {
        check_cancelled(is_cancelled)?;
        let workspace_root = validate_selection(workspace, options, self.limits)?;
        let test_selection = match intent {
            BuildIntent::Test { selection } => Some(selection),
            BuildIntent::Check | BuildIntent::Build | BuildIntent::Lint => None,
        };

        phase_started(events, "toolchain-verification");
        let verification = LocalToolchainVerifier::new(self.toolchain.clone())
            .verify(
                &workspace.target,
                self.limits.toolchain_verify,
                is_cancelled,
            )
            .map_err(map_toolchain_verification_error)?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "toolchain-verification");

        let compiler_digest = verification
            .bind_running_frontend(self.limits.toolchain_verify.single_file_bytes, is_cancelled)
            .map_err(map_toolchain_verification_error)?;

        phase_started(events, "workspace-and-syntax");
        let frontend =
            LocalFrontendService::new_with_toolchain(workspace_root, verification.toolchain())
                .map_err(|error| map_frontend_error("workspace", error))?;
        let root_locator = PackageLocator::Workspace {
            path: ROOT_LOCATOR.to_owned(),
        };
        let mut parse_limits = self.limits.parse;
        parse_limits.diagnostics = parse_limits.diagnostics.min(options.maximum_diagnostics);
        let frontend = frontend
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &root_locator,
                    load_limits: self.limits.package_load,
                    parse_limits,
                },
                is_cancelled,
            )
            .map_err(|error| map_frontend_error("workspace and syntax", error))?;
        check_cancelled(is_cancelled)?;

        if frontend.workspace().image(&workspace.image).is_none() {
            return Err(invalid_command(format!(
                "image `{}` is not declared by the root manifest",
                workspace.image
            )));
        }
        let profile = frontend
            .workspace()
            .profile(&workspace.profile)
            .ok_or_else(|| {
                invalid_command(format!(
                    "profile `{}` is not declared by the root manifest",
                    workspace.profile
                ))
            })?;
        let warnings_as_errors =
            options.warnings_as_errors || profile.diagnostics.warnings_as_errors;

        let (loaded_workspace, parsed_outputs) = frontend.into_parts();
        let parsed_count = parsed_outputs.len();
        let mut parsed_files = Vec::new();
        parsed_files.try_reserve_exact(parsed_count).map_err(|_| {
            input_error(
                "syntax",
                format!(
                    "cannot allocate {} parsed module outputs within the configured limit",
                    parsed_count
                ),
            )
        })?;
        let mut diagnostics = DiagnosticCollector::new(options.maximum_diagnostics)?;
        for output in parsed_outputs {
            check_cancelled(is_cancelled)?;
            let (parsed, phase_diagnostics) = output.into_parts();
            diagnostics.add(phase_diagnostics, warnings_as_errors, is_cancelled)?;
            parsed_files.push(parsed);
        }
        phase_finished(events, "workspace-and-syntax");
        if diagnostics.has_errors() {
            let sources = loaded_workspace.into_parts().sources;
            return reject(
                diagnostics,
                sources,
                options.maximum_diagnostics,
                events,
                is_cancelled,
            );
        }

        phase_started(events, "build-planning");
        let image = loaded_workspace
            .image(&workspace.image)
            .ok_or_else(|| input_error("build planning", "selected image disappeared"))?;
        let profile = loaded_workspace
            .profile(&workspace.profile)
            .ok_or_else(|| input_error("build planning", "selected profile disappeared"))?;
        let planned = CanonicalBuildPlanner::new()
            .plan(
                BuildPlanningRequest {
                    workspace: &loaded_workspace,
                    image,
                    profile,
                    intent,
                    target: verification.target(),
                    toolchain: verification.toolchain(),
                    hasher: &SoftwareSha256,
                    compiler_digest,
                },
                is_cancelled,
            )
            .map_err(map_build_planning_error)?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "build-planning");
        let (build, standard_library_package) = planned.into_parts();

        // Planning is the final consumer of the aggregate loader product.
        // Split it now so HIR can take ownership of the project-sized package
        // graph while the source database and manifest selection remain
        // borrowed in this stack frame.
        let wrela_package_loader::LoadedWorkspaceParts {
            graph,
            sources,
            manifests,
            scenarios,
            source_graph_digest,
            ..
        } = loaded_workspace.into_parts();

        phase_started(events, "hir-lowering");
        let module_count = graph.modules().len();
        if module_count > self.limits.hir.modules as usize {
            return Err(input_error(
                "HIR lowering",
                format!(
                    "workspace has {module_count} modules, exceeding limit {}",
                    self.limits.hir.modules
                ),
            ));
        }
        let packages = Arc::new(graph);
        let hir_changes = ChangeSet {
            previous_source_graph: None,
            changed_files: Vec::new(),
        };
        let mut hir_limits = self.limits.hir;
        hir_limits.diagnostics = hir_limits.diagnostics.min(options.maximum_diagnostics);
        let hir_output = CanonicalHirLowerer::new()
            .lower(
                HirLowerRequest {
                    packages,
                    source_graph_digest,
                    parsed_files: &parsed_files,
                    sources: &sources,
                    changes: &hir_changes,
                    limits: hir_limits,
                },
                is_cancelled,
            )
            .map_err(map_hir_error)?;
        let (lowered, hir_diagnostics) = hir_output.into_parts();
        diagnostics.add(hir_diagnostics, warnings_as_errors, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "hir-lowering");
        if diagnostics.has_errors() {
            return reject(
                diagnostics,
                sources,
                options.maximum_diagnostics,
                events,
                is_cancelled,
            );
        }

        let root_manifest = manifests
            .first()
            .ok_or_else(|| input_error("HIR lowering", "root manifest disappeared"))?
            .manifest();
        let image = root_manifest
            .images
            .binary_search_by(|image| image.name.as_str().cmp(&workspace.image))
            .ok()
            .and_then(|index| root_manifest.images.get(index))
            .ok_or_else(|| input_error("HIR lowering", "selected image disappeared"))?;
        let entry = match lowered.image_entry(image) {
            Ok(entry) => entry,
            Err(_error) if diagnostics.has_errors() => {
                return reject(
                    diagnostics,
                    sources,
                    options.maximum_diagnostics,
                    events,
                    is_cancelled,
                );
            }
            Err(error) => {
                return Err(input_error(
                    "HIR lowering",
                    format!("selected image entry cannot be resolved: {error}"),
                ));
            }
        };
        let mut declared_image_entries = Vec::new();
        if test_selection.is_some() {
            declared_image_entries
                .try_reserve_exact(root_manifest.images.len())
                .map_err(|_| input_error("HIR lowering", "cannot allocate image-entry index"))?;
            for declared_image in &root_manifest.images {
                check_cancelled(is_cancelled)?;
                let resolved = lowered.image_entry(declared_image).map_err(|error| {
                    input_error(
                        "HIR lowering",
                        format!(
                            "declared image `{}` entry cannot be resolved: {error}",
                            declared_image.name
                        ),
                    )
                })?;
                declared_image_entries.push((declared_image.name.clone(), resolved.declaration));
            }
        }
        let declared_image_tests = match test_selection.as_ref() {
            Some(selection) => decode_declared_image_tests(
                root_manifest,
                manifests
                    .first()
                    .ok_or_else(|| input_error("test discovery", "root manifest disappeared"))?
                    .identity(),
                &scenarios,
                &workspace.image,
                selection,
                self.limits,
                is_cancelled,
            )?,
            None => Vec::new(),
        };

        phase_started(events, "semantic-analysis");
        let semantic_hir = Arc::new(lowered.into_program());
        let semantic_changes = AnalysisChangeSet {
            previous_source_graph: None,
            changed_declarations: Vec::new(),
        };
        let mut semantic_limits = self.limits.semantic;
        semantic_limits.diagnostic_count = semantic_limits
            .diagnostic_count
            .min(options.maximum_diagnostics);
        let semantic_output = CanonicalSemanticAnalyzer::new()
            .analyze(
                AnalysisRequest {
                    hir: semantic_hir,
                    standard_library_package,
                    target: verification.target().semantic(),
                    build: &build,
                    mode: match test_selection.as_ref() {
                        Some(selection) => AnalysisMode::DiscoverTests {
                            image_name: &image.name,
                            image_entry: entry.declaration,
                            declared_image_tests: &declared_image_tests,
                            source_selection: source_test_selection(selection),
                        },
                        None => AnalysisMode::Image {
                            name: &image.name,
                            entry: entry.declaration,
                        },
                    },
                    changes: &semantic_changes,
                    limits: semantic_limits,
                },
                is_cancelled,
            )
            .map_err(map_semantic_error)?;
        let (analyzed, semantic_diagnostics) = semantic_output.into_parts();
        diagnostics.add(semantic_diagnostics, warnings_as_errors, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "semantic-analysis");

        let analyzed = match analyzed {
            Ok(analyzed) => {
                if diagnostics.has_errors() {
                    return reject(
                        diagnostics,
                        sources,
                        options.maximum_diagnostics,
                        events,
                        is_cancelled,
                    );
                }
                analyzed
            }
            Err(_) => {
                if diagnostics.has_errors() {
                    return reject(
                        diagnostics,
                        sources,
                        options.maximum_diagnostics,
                        events,
                        is_cancelled,
                    );
                }
                return Err(input_error(
                    "semantic analysis",
                    "semantic analysis returned a partial result without a rejecting diagnostic",
                ));
            }
        };

        let analysis = if test_selection.is_none() {
            phase_started(events, "analysis-facts");
            let analysis = CanonicalAnalysisFactAssembler::new()
                .assemble(
                    AnalysisFactRequest {
                        analysis: &analyzed,
                        limits: self.limits.analysis_facts,
                    },
                    is_cancelled,
                )
                .map_err(map_analysis_fact_error)?;
            check_cancelled(is_cancelled)?;
            phase_finished(events, "analysis-facts");
            Some(analysis)
        } else {
            None
        };

        let diagnostics = DiagnosticReport::successful(
            diagnostics.into_vec(),
            sources,
            options.maximum_diagnostics,
            is_cancelled,
        )
        .map_err(|error| input_error("check outcome", error.to_string()))?;
        emit_diagnostic_report(&diagnostics, events, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        Ok(LocalAnalysis {
            build,
            image_name: image.name.clone(),
            diagnostics,
            analysis,
            analyzed,
            verification,
            warnings_as_errors,
            standard_library_package,
            declared_image_entries,
        })
    }

    fn check(
        &self,
        workspace: &WorkspaceSelection,
        options: &wrela_driver::DiagnosticOptions,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        let (build, image_name, diagnostics, analysis) = self
            .analyze(workspace, options, BuildIntent::Check, events, is_cancelled)?
            .into_check_parts()?;
        let outcome = CheckOutcome::new(build, &image_name, diagnostics, analysis)
            .map_err(|error| input_error("check outcome", error.to_string()))?;
        check_cancelled(is_cancelled)?;
        Ok(CommandOutput::Check(Box::new(outcome)))
    }
}

pub(super) struct LocalAnalysis {
    pub(super) build: wrela_build_model::ValidatedBuildConfiguration,
    pub(super) image_name: String,
    pub(super) diagnostics: DiagnosticReport,
    pub(super) analysis: Option<wrela_image_report::ValidatedAnalysisFacts>,
    pub(super) analyzed: wrela_sema::AnalyzedImage,
    pub(super) verification: crate::LocalToolchainVerification,
    pub(super) warnings_as_errors: bool,
    pub(super) standard_library_package: wrela_package::PackageId,
    pub(super) declared_image_entries: Vec<(String, wrela_hir::DeclarationId)>,
}

impl LocalAnalysis {
    fn into_check_parts(
        self,
    ) -> Result<
        (
            wrela_build_model::ValidatedBuildConfiguration,
            String,
            DiagnosticReport,
            wrela_image_report::ValidatedAnalysisFacts,
        ),
        DriverError,
    > {
        let Self {
            build,
            image_name,
            diagnostics,
            analysis,
            analyzed,
            verification,
            warnings_as_errors: _,
            standard_library_package: _,
            declared_image_entries: _,
        } = self;
        drop((analyzed, verification));
        Ok((
            build,
            image_name,
            diagnostics,
            analysis.ok_or_else(|| {
                input_error(
                    "analysis facts",
                    "pipeline omitted validated analysis facts for a check command",
                )
            })?,
        ))
    }
}

fn decode_declared_image_tests(
    manifest: &wrela_package::PackageManifest,
    root_identity: &wrela_package::PackageIdentity,
    scenarios: &[wrela_package_loader::ScenarioInput],
    selected_image: &str,
    selection: &TestSelection,
    limits: PipelineLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<DeclaredImageTest>, DriverError> {
    let selected_count = manifest
        .image_tests
        .iter()
        .filter(|test| {
            test.image == selected_image && declared_test_selected(&test.name, selection)
        })
        .count();
    if selected_count > limits.test_plan.scenarios as usize {
        return Err(input_error(
            "test discovery",
            format!(
                "selected image declares {selected_count} scenarios, exceeding limit {}",
                limits.test_plan.scenarios
            ),
        ));
    }
    let mut declared = Vec::new();
    declared.try_reserve_exact(selected_count).map_err(|_| {
        input_error(
            "test discovery",
            "cannot allocate declared image-test inputs",
        )
    })?;
    let maximum_scenario_bytes = limits
        .package_load
        .scenario_bytes
        .min(limits.test_plan.payload_bytes);
    for test in &manifest.image_tests {
        check_cancelled(is_cancelled)?;
        if test.image != selected_image || !declared_test_selected(&test.name, selection) {
            continue;
        }
        let mut matches = scenarios.iter().filter(|scenario| {
            scenario.package == *root_identity && scenario.path == test.scenario
        });
        let input = matches.next().ok_or_else(|| {
            input_error(
                "test discovery",
                format!(
                    "declared scenario `{}` for image test `{}` disappeared",
                    test.scenario, test.name
                ),
            )
        })?;
        if matches.next().is_some() {
            return Err(input_error(
                "test discovery",
                format!(
                    "declared scenario `{}` is ambiguous for image test `{}`",
                    test.scenario, test.name
                ),
            ));
        }
        let id =
            ScenarioId(u32::try_from(declared.len()).map_err(|_| {
                input_error("test discovery", "declared scenario identity overflow")
            })?);
        let scenario = decode_and_verify_image_scenario(
            &CanonicalImageScenarioCodec::new(),
            ScenarioDecodeRequest {
                id,
                name: &test.name,
                source_path: &test.scenario,
                bytes: &input.bytes,
                verified_digest: input.digest,
                maximum_bytes: maximum_scenario_bytes,
                maximum_steps: limits.test_plan.scenario_steps,
                maximum_step_bytes: limits.test_plan.payload_bytes,
            },
            is_cancelled,
        )
        .map_err(|error| match error {
            wrela_test_model::TestModelError::Cancelled => DriverError::Cancelled,
            error => input_error(
                "test discovery",
                format!("invalid scenario for image test `{}`: {error}", test.name),
            ),
        })?;
        declared.push(DeclaredImageTest {
            name: test.name.clone(),
            image_name: test.image.clone(),
            scenario,
            boot_timeout_ns: test.boot_timeout_ns,
            shutdown_timeout_ns: test.shutdown_timeout_ns,
            maximum_events: test.maximum_events,
            maximum_output_bytes: test.maximum_output_bytes,
            deterministic_seed: test.deterministic_seed,
        });
    }
    Ok(declared)
}

fn declared_test_selected(name: &str, selection: &TestSelection) -> bool {
    match selection {
        TestSelection::All | TestSelection::Images => true,
        TestSelection::Comptime | TestSelection::Integration => false,
        TestSelection::NameContains(filter) => name.contains(filter),
    }
}

fn source_test_selection(selection: &TestSelection) -> TestDiscoverySelection<'_> {
    match selection {
        TestSelection::All => TestDiscoverySelection::All,
        TestSelection::Comptime => TestDiscoverySelection::Comptime,
        TestSelection::Integration => TestDiscoverySelection::Integration,
        TestSelection::Images => TestDiscoverySelection::None,
        TestSelection::NameContains(filter) => TestDiscoverySelection::NameContains(filter),
    }
}

impl CompilerDriver for LocalCheckDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        match command {
            Command::Check {
                workspace,
                diagnostics,
            } => self.check(workspace, diagnostics, events, is_cancelled),
            _ => Err(invalid_command(
                "local check driver accepts only a normalized `check` command",
            )),
        }
    }
}

/// CLI-oriented entry point using standard policy and a deliberately silent
/// event sink. Embedders that render phase progress or structured diagnostics
/// should construct [`LocalCheckDriver`] and call [`CompilerDriver::execute`].
pub fn execute_local_check(command: &Command) -> Result<CommandOutput, DriverError> {
    let driver = LocalCheckDriver::discover(PipelineLimits::standard())?;
    driver.execute(command, &SilentEvents, &never_cancelled)
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

fn never_cancelled() -> bool {
    false
}

fn validate_selection<'a>(
    workspace: &'a WorkspaceSelection,
    options: &wrela_driver::DiagnosticOptions,
    limits: PipelineLimits,
) -> Result<&'a Path, DriverError> {
    if !options.is_valid() {
        return Err(invalid_command(
            "maximum diagnostics must be greater than zero",
        ));
    }
    let diagnostic_limit = limits
        .parse
        .diagnostics
        .min(limits.hir.diagnostics)
        .min(limits.semantic.diagnostic_count);
    if options.maximum_diagnostics > diagnostic_limit {
        return Err(invalid_command(format!(
            "maximum diagnostics {} exceeds pipeline limit {diagnostic_limit}",
            options.maximum_diagnostics
        )));
    }
    if !normal_absolute_path(&workspace.manifest)
        || !normal_absolute_path(&workspace.lockfile)
        || workspace.manifest.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
        || workspace.lockfile.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
    {
        return Err(invalid_command(
            "manifest and lockfile must be bounded, normalized absolute paths",
        ));
    }
    if workspace
        .manifest
        .file_name()
        .and_then(|name| name.to_str())
        != Some(MANIFEST_FILE_NAME)
    {
        return Err(invalid_command(format!(
            "manifest must be named `{MANIFEST_FILE_NAME}`"
        )));
    }
    let root = workspace
        .manifest
        .parent()
        .ok_or_else(|| invalid_command("manifest path does not identify a workspace directory"))?;
    let expected_lockfile = root.join(LOCKFILE_FILE_NAME);
    if workspace.lockfile != expected_lockfile {
        return Err(invalid_command(format!(
            "lockfile must be the manifest sibling `{LOCKFILE_FILE_NAME}`"
        )));
    }
    if !valid_selection_atom(&workspace.image) || !valid_selection_atom(&workspace.profile) {
        return Err(invalid_command(
            "image and profile selections must be nonempty bounded atoms",
        ));
    }
    Ok(root)
}

fn valid_selection_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SELECTION_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && PathBuf::from_iter(path.components()) == path
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn phase_started(events: &dyn EventSink, phase: &'static str) {
    events.emit(DriverEvent::PhaseStarted { phase });
}

fn phase_finished(events: &dyn EventSink, phase: &'static str) {
    events.emit(DriverEvent::PhaseFinished {
        phase,
        reused: false,
    });
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DriverError> {
    if is_cancelled() {
        Err(DriverError::Cancelled)
    } else {
        Ok(())
    }
}

fn reject<T>(
    diagnostics: DiagnosticCollector,
    sources: wrela_source::SourceDatabase,
    maximum_diagnostics: u32,
    events: &dyn EventSink,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<T, DriverError> {
    let report = DiagnosticReport::rejected(
        diagnostics.into_vec(),
        sources,
        maximum_diagnostics,
        is_cancelled,
    )
    .map_err(|error| input_error("diagnostics", error.to_string()))?;
    emit_diagnostic_report(&report, events, is_cancelled)?;
    Err(DriverError::Rejected { report })
}

fn emit_diagnostic_report(
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

fn composition_error(error: CompositionError) -> DriverError {
    input_error("composition", error.to_string())
}

fn invalid_command(message: impl Into<String>) -> DriverError {
    DriverError::InvalidCommand(message.into())
}

fn input_error(phase: &'static str, message: impl Into<String>) -> DriverError {
    DriverError::Input {
        phase,
        message: message.into(),
    }
}

fn map_toolchain_verification_error(error: LocalToolchainVerificationError) -> DriverError {
    match error {
        LocalToolchainVerificationError::Cancelled => DriverError::Cancelled,
        error => DriverError::Toolchain(error.to_string()),
    }
}

fn map_frontend_error(phase: &'static str, error: FrontendInputError) -> DriverError {
    match error {
        FrontendInputError::Cancelled => DriverError::Cancelled,
        error => input_error(phase, error.to_string()),
    }
}

fn map_hir_error(error: wrela_hir_lower::LowerFailure) -> DriverError {
    match error {
        wrela_hir_lower::LowerFailure::Cancelled => DriverError::Cancelled,
        error => input_error("HIR lowering", error.to_string()),
    }
}

fn map_build_planning_error(error: BuildPlanningError) -> DriverError {
    match error {
        BuildPlanningError::Cancelled => DriverError::Cancelled,
        error => input_error("build planning", error.to_string()),
    }
}

fn map_semantic_error(error: wrela_sema::AnalysisFailure) -> DriverError {
    match error {
        wrela_sema::AnalysisFailure::Cancelled => DriverError::Cancelled,
        error => input_error("semantic analysis", error.to_string()),
    }
}

fn map_analysis_fact_error(error: AnalysisFactAssemblyError) -> DriverError {
    match error {
        AnalysisFactAssemblyError::Cancelled => DriverError::Cancelled,
        error => input_error("analysis facts", error.to_string()),
    }
}

/// Bounded, canonical diagnostic accumulator shared by all recoverable source
/// phases. Its total ordering extends the driver's public diagnostic order so
/// exact duplicates are adjacent and can be removed without quadratic scans.
struct DiagnosticCollector {
    maximum: usize,
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticCollector {
    fn new(maximum: u32) -> Result<Self, DriverError> {
        let maximum = usize::try_from(maximum).map_err(|_| {
            input_error(
                "diagnostics",
                "maximum diagnostic count does not fit the host",
            )
        })?;
        Ok(Self {
            maximum,
            diagnostics: Vec::new(),
        })
    }

    fn add(
        &mut self,
        mut incoming: Vec<Diagnostic>,
        warnings_as_errors: bool,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DriverError> {
        if warnings_as_errors {
            for diagnostic in &mut incoming {
                check_cancelled(is_cancelled)?;
                if diagnostic.severity == Severity::Warning {
                    diagnostic.severity = Severity::Error;
                }
            }
        }
        let incoming =
            canonicalize_diagnostics(incoming, is_cancelled).map_err(|error| match error {
                DiagnosticSortError::Cancelled => DriverError::Cancelled,
                DiagnosticSortError::Allocation => input_error(
                    "diagnostics",
                    format!(
                        "cannot allocate the configured diagnostic limit {}",
                        self.maximum
                    ),
                ),
            })?;
        if incoming.is_empty() {
            return Ok(());
        }

        let requested = self
            .diagnostics
            .len()
            .checked_add(incoming.len())
            .map_or(self.maximum, |count| count.min(self.maximum));
        let mut merged = Vec::new();
        merged.try_reserve_exact(requested).map_err(|_| {
            input_error(
                "diagnostics",
                format!(
                    "cannot allocate the configured diagnostic limit {}",
                    self.maximum
                ),
            )
        })?;
        let mut existing = std::mem::take(&mut self.diagnostics).into_iter().peekable();
        let mut incoming = incoming.into_iter().peekable();
        while existing.peek().is_some() || incoming.peek().is_some() {
            check_cancelled(is_cancelled)?;
            let next = match (existing.peek(), incoming.peek()) {
                (Some(left), Some(right)) => match compare_diagnostics(left, right) {
                    Ordering::Less => existing.next(),
                    Ordering::Greater => incoming.next(),
                    Ordering::Equal => {
                        let value = existing.next();
                        let _duplicate = incoming.next();
                        value
                    }
                },
                (Some(_), None) => existing.next(),
                (None, Some(_)) => incoming.next(),
                (None, None) => None,
            };
            let Some(next) = next else {
                return Err(input_error(
                    "diagnostics",
                    "diagnostic merge reached an inconsistent iterator state",
                ));
            };
            if merged.last() == Some(&next) {
                continue;
            }
            if merged.len() == self.maximum {
                return Err(input_error(
                    "diagnostics",
                    format!(
                        "command produced more than {} distinct diagnostics",
                        self.maximum
                    ),
                ));
            }
            merged.push(next);
        }
        self.diagnostics = merged;
        Ok(())
    }

    fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    fn into_vec(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use wrela_build_model::TargetIdentity;
    use wrela_diagnostics::Category;
    use wrela_driver::DiagnosticOptions;
    use wrela_package::{
        PackageIdentity, PackageLocator, PackageManifest, PackageName, PackageVersion,
    };
    use wrela_package_loader::{
        CanonicalPackageCodec, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher,
        ManifestCodecLimits, PackageCodec, PackageContentKind, PackageContentRecord,
        canonical_tree_digest, package_content_digest,
    };
    use wrela_source::{FileId, SourceDatabase, SourceInput, Span, TextRange};
    use wrela_toolchain::{
        CanonicalToolchainManifestCodec, ComponentKind, ComponentPath,
        REQUIRED_LLVM_PROJECT_REVISION, ShippedComponent, ShippedStandardLibraryPackage,
        ShippedTarget, ShippedTargetFile, TOOLCHAIN_MANIFEST_SCHEMA, ToolchainCompatibility,
        ToolchainManifest, ToolchainManifestCodec, current_host_identity,
    };

    use super::*;

    const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
    const CORE_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
    const CORE_RESULT_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/result.wr");
    const CORE_TIME_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/time.wr");
    const APPLICATION_MANIFEST: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/wrela.toml");
    const APPLICATION_SOURCE: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/src/bootstrap/image.wr");
    const APPLICATION_LOCKFILE: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/wrela.lock");
    const TARGET_MANIFEST: &[u8] =
        include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
    const FRONTEND_BYTES: &[u8] = b"wrela check integration frontend";
    const BACKEND_BYTES: &[u8] = b"wrela check integration backend";
    const RUNTIME_OBJECT: &[u8] = b"wrela check integration runtime";
    const MAX_FIXTURE_FILE_BYTES: usize = 1024 * 1024;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    static HASHER: SoftwareSha256 = SoftwareSha256;

    #[derive(Debug)]
    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary base");
            for _ in 0..128 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
                let root = base.join(format!(
                    "wrela-local-check-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical fixture root"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create local-check fixture: {error}"),
                }
            }
            panic!("cannot allocate a unique local-check fixture")
        }

        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            assert!(bytes.len() <= MAX_FIXTURE_FILE_BYTES);
            self.write_trusted(relative, bytes)
        }

        fn write_trusted(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent directory");
            }
            fs::write(&path, bytes).expect("bounded fixture write");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordedEvent {
        PhaseStarted(&'static str),
        PhaseFinished(&'static str),
        Diagnostic {
            diagnostic: Box<Diagnostic>,
            source_path: String,
        },
        Other,
    }

    #[derive(Default)]
    struct RecordingEvents {
        events: RefCell<Vec<RecordedEvent>>,
    }

    impl EventSink for RecordingEvents {
        fn emit(&self, event: DriverEvent<'_>) {
            let recorded = match event {
                DriverEvent::PhaseStarted { phase } => RecordedEvent::PhaseStarted(phase),
                DriverEvent::PhaseFinished { phase, .. } => RecordedEvent::PhaseFinished(phase),
                DriverEvent::Diagnostic {
                    diagnostic,
                    sources,
                } => RecordedEvent::Diagnostic {
                    diagnostic: Box::new(diagnostic.clone()),
                    source_path: sources
                        .get(diagnostic.primary.file)
                        .expect("sealed diagnostic source")
                        .path()
                        .to_owned(),
                },
                DriverEvent::ArtifactPublished { .. } | DriverEvent::TestProgress { .. } => {
                    RecordedEvent::Other
                }
            };
            self.events.borrow_mut().push(recorded);
        }
    }

    fn selection(manifest: &str) -> WorkspaceSelection {
        let manifest = PathBuf::from(manifest);
        WorkspaceSelection {
            lockfile: manifest
                .parent()
                .expect("absolute fixture manifest parent")
                .join(LOCKFILE_FILE_NAME),
            manifest,
            image: "bootstrap".to_owned(),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            profile: "development".to_owned(),
        }
    }

    fn warning(message: &str) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(
            Category::IMAGE,
            Span {
                file: FileId(0),
                range: TextRange::new(0, 0).expect("fixture range"),
            },
            message,
        );
        diagnostic.severity = Severity::Warning;
        diagnostic
    }

    #[test]
    fn verified_local_check_reaches_real_analysis_facts() {
        let directory = TestDirectory::new();
        let workspace_root = directory.root.join("workspace");
        directory.write("workspace/wrela.toml", APPLICATION_MANIFEST);
        directory.write("workspace/wrela.lock", APPLICATION_LOCKFILE);
        directory.write("workspace/src/bootstrap/image.wr", APPLICATION_SOURCE);

        let toolchain_root = directory.root.join("toolchain");
        let running_frontend = fs::read(std::env::current_exe().expect("current test executable"))
            .expect("read current test executable");
        install_toolchain(&directory, &running_frontend);
        let driver =
            LocalCheckDriver::new(Toolchain::at(toolchain_root), PipelineLimits::standard())
                .expect("local check driver");
        let events = RecordingEvents::default();
        let output = driver
            .execute(
                &Command::Check {
                    workspace: WorkspaceSelection {
                        manifest: workspace_root.join(MANIFEST_FILE_NAME),
                        lockfile: workspace_root.join(LOCKFILE_FILE_NAME),
                        image: "bootstrap".to_owned(),
                        target: TargetIdentity::aarch64_qemu_virt_uefi(),
                        profile: "development".to_owned(),
                    },
                    diagnostics: DiagnosticOptions::default(),
                },
                &events,
                &never_cancelled,
            )
            .expect("complete local check");
        let CommandOutput::Check(outcome) = output else {
            panic!("expected sealed check output");
        };
        assert!(outcome.diagnostics().is_empty());
        assert_eq!(outcome.analysis().as_facts().proofs.len(), 3);
        assert_eq!(outcome.analysis().image_name(), "bootstrap");

        let started = events
            .events
            .borrow()
            .iter()
            .filter_map(|event| match event {
                RecordedEvent::PhaseStarted(phase) => Some(*phase),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            started,
            [
                "toolchain-verification",
                "workspace-and-syntax",
                "build-planning",
                "hir-lowering",
                "semantic-analysis",
                "analysis-facts",
            ]
        );
    }

    #[test]
    fn selection_requires_exact_normalized_workspace_files() {
        let limits = PipelineLimits::standard();
        let options = DiagnosticOptions::default();
        let valid = selection("/workspace/wrela.toml");
        assert_eq!(
            validate_selection(&valid, &options, limits).expect("valid selection"),
            Path::new("/workspace")
        );

        let mut wrong_lock = valid.clone();
        wrong_lock.lockfile = PathBuf::from("/workspace/other.lock");
        assert!(matches!(
            validate_selection(&wrong_lock, &options, limits),
            Err(DriverError::InvalidCommand(_))
        ));
        let relative = selection("workspace/wrela.toml");
        assert!(matches!(
            validate_selection(&relative, &options, limits),
            Err(DriverError::InvalidCommand(_))
        ));
    }

    #[test]
    fn public_test_selection_maps_source_and_declared_tests_consistently() {
        assert_eq!(
            source_test_selection(&TestSelection::All),
            TestDiscoverySelection::All
        );
        assert_eq!(
            source_test_selection(&TestSelection::Comptime),
            TestDiscoverySelection::Comptime
        );
        assert_eq!(
            source_test_selection(&TestSelection::Integration),
            TestDiscoverySelection::Integration
        );
        assert_eq!(
            source_test_selection(&TestSelection::Images),
            TestDiscoverySelection::None
        );
        let named = TestSelection::NameContains("boot".to_owned());
        assert_eq!(
            source_test_selection(&named),
            TestDiscoverySelection::NameContains("boot")
        );

        for selection in [TestSelection::All, TestSelection::Images] {
            assert!(declared_test_selected("boot-smoke", &selection));
        }
        for selection in [TestSelection::Comptime, TestSelection::Integration] {
            assert!(!declared_test_selected("boot-smoke", &selection));
        }
        assert!(declared_test_selected("boot-smoke", &named));
        assert!(!declared_test_selected("network-smoke", &named));
    }

    #[test]
    fn diagnostics_are_deduplicated_and_promoted_before_events() {
        let warning = warning("bounded warning");
        let mut collector = DiagnosticCollector::new(2).expect("collector");
        collector
            .add(vec![warning.clone(), warning], true, &never_cancelled)
            .expect("promoted diagnostics");
        assert!(collector.has_errors());
        assert_eq!(collector.diagnostics.len(), 1);

        let mut sources = SourceDatabase::default();
        sources
            .add(SourceInput {
                path: "test.wr".to_owned(),
                text: String::new(),
                digest: HASHER.sha256(b""),
            })
            .expect("diagnostic source");
        let report = DiagnosticReport::rejected(collector.into_vec(), sources, 2, &never_cancelled)
            .expect("rejected report");
        let events = RecordingEvents::default();
        emit_diagnostic_report(&report, &events, &never_cancelled).expect("diagnostic event");
        let events = events.events.borrow();
        let RecordedEvent::Diagnostic {
            diagnostic,
            source_path,
        } = &events[0]
        else {
            panic!("expected diagnostic event");
        };
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(source_path, "test.wr");
    }

    #[test]
    fn diagnostic_aggregate_limit_fails_closed() {
        let mut collector = DiagnosticCollector::new(1).expect("collector");
        collector
            .add(vec![warning("first")], false, &never_cancelled)
            .expect("first diagnostic");
        assert!(matches!(
            collector.add(vec![warning("second")], false, &never_cancelled),
            Err(DriverError::Input {
                phase: "diagnostics",
                ..
            })
        ));
    }

    #[test]
    fn diagnostic_canonicalization_is_cancellable_during_project_sized_work() {
        let incoming = (0..600)
            .rev()
            .map(|index| warning(&format!("warning {index:04}")))
            .collect();
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 20
        };
        let mut collector = DiagnosticCollector::new(600).expect("collector");
        assert!(matches!(
            collector.add(incoming, false, &cancelled),
            Err(DriverError::Cancelled)
        ));
        assert!(polls.get() >= 20);
    }

    #[test]
    fn check_driver_honors_cancellation_before_toolchain_io() {
        let driver = LocalCheckDriver::new(
            Toolchain::at("/toolchain-that-must-not-be-read"),
            PipelineLimits::standard(),
        )
        .expect("driver");
        let events = RecordingEvents::default();
        let result = driver.execute(
            &Command::Check {
                workspace: selection("/workspace/wrela.toml"),
                diagnostics: DiagnosticOptions::default(),
            },
            &events,
            &|| true,
        );
        assert!(matches!(result, Err(DriverError::Cancelled)));
        assert!(events.events.borrow().is_empty());
    }

    #[test]
    fn check_driver_rejects_other_commands_without_toolchain_io() {
        let driver = LocalCheckDriver::new(
            Toolchain::at("/toolchain-that-must-not-be-read"),
            PipelineLimits::standard(),
        )
        .expect("driver");
        let result = driver.execute(
            &Command::Doctor,
            &RecordingEvents::default(),
            &never_cancelled,
        );
        assert!(matches!(result, Err(DriverError::InvalidCommand(_))));
    }

    #[test]
    fn check_rejects_toolchain_frontend_that_is_not_the_running_compiler() {
        let directory = TestDirectory::new();
        directory.write("workspace/wrela.toml", APPLICATION_MANIFEST);
        directory.write("workspace/wrela.lock", APPLICATION_LOCKFILE);
        directory.write("workspace/src/bootstrap/image.wr", APPLICATION_SOURCE);
        install_toolchain(&directory, FRONTEND_BYTES);
        let driver = LocalCheckDriver::new(
            Toolchain::at(directory.root.join("toolchain")),
            PipelineLimits::standard(),
        )
        .expect("local check driver");
        let result = driver.execute(
            &Command::Check {
                workspace: selection(
                    directory
                        .root
                        .join("workspace/wrela.toml")
                        .to_str()
                        .expect("UTF-8 fixture path"),
                ),
                diagnostics: DiagnosticOptions::default(),
            },
            &RecordingEvents::default(),
            &never_cancelled,
        );
        assert!(matches!(
            result,
            Err(DriverError::Toolchain(message))
                if message.contains("differs from the verified toolchain frontend")
        ));
    }

    fn install_toolchain(directory: &TestDirectory, frontend_bytes: &[u8]) {
        let codec = CanonicalPackageCodec::new();
        let core = codec
            .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("checked-in core manifest");
        let core_identity = package_identity(
            &core,
            CORE_MANIFEST,
            &[
                ("image.wr", CORE_SOURCE),
                ("result.wr", CORE_RESULT_SOURCE),
                ("time.wr", CORE_TIME_SOURCE),
            ],
        );
        let core_manifest_digest = HASHER.sha256(CORE_MANIFEST);
        directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/wrela.toml",
            CORE_MANIFEST,
        );
        directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/src/image.wr",
            CORE_SOURCE,
        );
        directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/src/result.wr",
            CORE_RESULT_SOURCE,
        );
        directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/src/time.wr",
            CORE_TIME_SOURCE,
        );

        let frontend =
            directory.write_trusted(&format!("toolchain/{}", frontend_path()), frontend_bytes);
        let backend = directory.write(&format!("toolchain/{}", backend_path()), BACKEND_BYTES);
        set_executable(&frontend);
        set_executable(&backend);

        let target_root = "toolchain/share/wrela/targets/aarch64-qemu-virt-uefi";
        directory.write(&format!("{target_root}/target.toml"), TARGET_MANIFEST);
        directory.write(
            &format!("{target_root}/runtime/wrela-runtime-aarch64.obj"),
            RUNTIME_OBJECT,
        );

        let standard_library = tree_measurement(&[
            tree_record("wrela-core-0.1/src/image.wr", CORE_SOURCE),
            tree_record("wrela-core-0.1/src/result.wr", CORE_RESULT_SOURCE),
            tree_record("wrela-core-0.1/src/time.wr", CORE_TIME_SOURCE),
            tree_record("wrela-core-0.1/wrela.toml", CORE_MANIFEST),
        ]);
        let target = tree_measurement(&[
            tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
            tree_record("target.toml", TARGET_MANIFEST),
        ]);
        let target_path = "share/wrela/targets/aarch64-qemu-virt-uefi";
        let manifest = ToolchainManifest {
            schema: TOOLCHAIN_MANIFEST_SCHEMA,
            release: "0.1.0-check-test".to_owned(),
            host: host_identity().to_owned(),
            llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
            compatibility: ToolchainCompatibility::current(),
            standard_library_packages: vec![ShippedStandardLibraryPackage {
                identity: core_identity,
                locator: PackageLocator::Toolchain {
                    component: "wrela-core-0.1".to_owned(),
                },
                manifest_digest: core_manifest_digest,
            }],
            components: vec![
                shipped_component(ComponentKind::Frontend, frontend_path(), frontend_bytes),
                shipped_component(ComponentKind::Backend, backend_path(), BACKEND_BYTES),
                ShippedComponent {
                    kind: ComponentKind::StandardLibrary,
                    path: ComponentPath::new("share/wrela/std").expect("standard-library path"),
                    digest: standard_library.digest,
                    bytes: standard_library.content_bytes,
                },
            ],
            targets: vec![ShippedTarget {
                identity: TargetIdentity::aarch64_qemu_virt_uefi(),
                path: ComponentPath::new(target_path).expect("target path"),
                digest: target.digest,
                bytes: target.content_bytes,
                files: vec![shipped_target_file(
                    "runtime/wrela-runtime-aarch64.obj",
                    RUNTIME_OBJECT,
                )],
            }],
        };
        let manifest = CanonicalToolchainManifestCodec::new()
            .encode_canonical(
                &manifest,
                PipelineLimits::standard().toolchain_decode,
                &never_cancelled,
            )
            .expect("canonical toolchain manifest");
        directory.write("toolchain/share/wrela/toolchain.toml", &manifest);
    }

    fn package_identity(
        manifest: &PackageManifest,
        manifest_bytes: &[u8],
        sources: &[(&str, &[u8])],
    ) -> PackageIdentity {
        let mut records = sources
            .iter()
            .map(|(path, bytes)| PackageContentRecord {
                kind: PackageContentKind::Source,
                path,
                digest: HASHER.sha256(bytes),
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| (record.kind, record.path));
        let source_digest =
            package_content_digest(manifest_bytes, &records, &HASHER, &never_cancelled)
                .expect("canonical core package digest");
        PackageIdentity {
            name: PackageName::new(manifest.name.as_str()).expect("core package name"),
            version: PackageVersion::new(manifest.version.as_str()).expect("core package version"),
            source_digest,
        }
    }

    fn shipped_component(kind: ComponentKind, path: &str, bytes: &[u8]) -> ShippedComponent {
        ShippedComponent {
            kind,
            path: ComponentPath::new(path).expect("component path"),
            digest: HASHER.sha256(bytes),
            bytes: u64::try_from(bytes.len()).expect("component bytes"),
        }
    }

    fn shipped_target_file(path: &str, bytes: &[u8]) -> ShippedTargetFile {
        ShippedTargetFile {
            path: ComponentPath::new(path).expect("target file path"),
            digest: HASHER.sha256(bytes),
            bytes: u64::try_from(bytes.len()).expect("target file bytes"),
        }
    }

    fn tree_record<'a>(path: &'a str, bytes: &[u8]) -> CanonicalTreeRecord<'a> {
        CanonicalTreeRecord {
            path,
            bytes: u64::try_from(bytes.len()).expect("tree record bytes"),
            digest: HASHER.sha256(bytes),
        }
    }

    fn tree_measurement(
        records: &[CanonicalTreeRecord<'_>],
    ) -> wrela_package_loader::CanonicalTreeMeasurement {
        canonical_tree_digest(
            records,
            &HASHER,
            CanonicalTreeLimits::standard(),
            &never_cancelled,
        )
        .expect("canonical tree measurement")
    }

    fn manifest_limits() -> ManifestCodecLimits {
        ManifestCodecLimits {
            bytes: MAX_FIXTURE_FILE_BYTES as u64,
            string_bytes: MAX_FIXTURE_FILE_BYTES as u64,
            modules: 16,
            dependencies: 16,
            profiles: 16,
            images: 16,
            image_tests: 16,
        }
    }

    #[cfg(windows)]
    const fn frontend_path() -> &'static str {
        "bin/wrela.exe"
    }

    #[cfg(not(windows))]
    const fn frontend_path() -> &'static str {
        "bin/wrela"
    }

    #[cfg(windows)]
    const fn backend_path() -> &'static str {
        "libexec/wrela/wrela-backend.exe"
    }

    #[cfg(not(windows))]
    const fn backend_path() -> &'static str {
        "libexec/wrela/wrela-backend"
    }

    fn host_identity() -> &'static str {
        current_host_identity().expect("tests run on a supported revision-0.1 compiler host")
    }

    #[cfg(unix)]
    fn set_executable(path: &Path) {
        let mut permissions = fs::metadata(path)
            .expect("executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("executable permissions");
    }

    #[cfg(not(unix))]
    fn set_executable(_path: &Path) {}
}
