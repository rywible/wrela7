//! Concrete local revision-0.1 `lint` command composition.
//!
//! Linting deliberately reuses the production frontend through its sealed
//! whole-image semantic product. The linter therefore observes the same
//! verified toolchain, source graph, selected image, profile, and canonical
//! build identity as `check` and `build`; it never reparses files or invents a
//! parallel notion of reachability.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use wrela_diagnostics::{Category, Diagnostic, Severity, compare_diagnostics};
use wrela_driver::{
    Command, CommandOutput, CompilerDriver, DiagnosticReport, DriverError, DriverEvent, EventSink,
    LintOutcome, WorkspaceSelection,
};
use wrela_lint::{
    LintConfiguration, LintDescriptor, LintError, LintFinding, LintInput, LintLayer, LintLevel,
    LintLimits, LintName, LintOutput, LintOutputCandidate, LintRegistry, LintRequest, Linter,
    seal_lint_output,
};
use wrela_sema::{AnalysisRoot, AnalyzedImage, ExpressionResolution, ValueId};

use crate::local_check::{LocalAnalysis, LocalCheckDriver};
use crate::{BuildIntent, CompositionError, PipelineLimits};

const UNUSED_LOCAL_BINDING: &str = "unused-local-binding";
const UNUSED_PARAMETER: &str = "unused-parameter";
const VALUE_STATE_USED: u8 = 1 << 0;
const VALUE_STATE_PARAMETER: u8 = 1 << 1;

/// Production driver for the local, whole-image semantic lint pipeline.
#[derive(Debug, Clone)]
pub struct LocalLintDriver {
    frontend: LocalCheckDriver,
    linter: CanonicalSemanticLinter,
}

impl LocalLintDriver {
    pub fn new(
        toolchain: wrela_toolchain::Toolchain,
        limits: PipelineLimits,
    ) -> Result<Self, CompositionError> {
        Ok(Self {
            frontend: LocalCheckDriver::new(toolchain, limits)?,
            linter: CanonicalSemanticLinter::new().map_err(|error| {
                CompositionError::InvalidServices(format!(
                    "cannot construct the canonical lint registry: {error}"
                ))
            })?,
        })
    }

    pub fn discover(limits: PipelineLimits) -> Result<Self, DriverError> {
        Ok(Self {
            frontend: LocalCheckDriver::discover(limits)?,
            linter: CanonicalSemanticLinter::new().map_err(|error| {
                input_error(format!("invalid canonical lint registry: {error}"))
            })?,
        })
    }

    #[must_use]
    pub const fn limits(&self) -> PipelineLimits {
        self.frontend.limits()
    }

    fn lint(
        &self,
        workspace: &WorkspaceSelection,
        options: &wrela_driver::DiagnosticOptions,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        let LocalAnalysis {
            build,
            image_name,
            diagnostics,
            analysis,
            analyzed,
            verification,
            warnings_as_errors,
            standard_library_package: _,
            declared_image_entries: _,
        } = self
            .frontend
            .analyze(workspace, options, BuildIntent::Lint, events, is_cancelled)?;
        let analysis = analysis.ok_or_else(|| {
            input_error("ordinary lint analysis omitted its sealed frontend facts")
        })?;

        // These equalities are already prerequisites of the semantic and
        // analysis-fact seals. Rechecking them here makes the lint composition
        // fail closed if either producer's contract ever drifts.
        if analyzed.facts().build != *build.identity()
            || analysis.build() != build.identity()
            || analysis.image_name() != image_name
            || !matches!(
                &analyzed.facts().root,
                AnalysisRoot::DeclaredImage {
                    image_name: root_name,
                    ..
                } if root_name == &image_name
            )
        {
            return Err(input_error(
                "sealed semantic analysis disagrees with the selected lint build",
            ));
        }

        phase_started(events, "semantic-lint");
        let configuration = lint_configuration(
            self.linter.registry(),
            warnings_as_errors,
            build.profile().diagnostics.sealed_deployment,
        );
        let limits = remaining_lint_limits(
            self.limits().lint,
            diagnostics.diagnostics().len(),
            options.maximum_diagnostics,
        )?;
        let output = self
            .linter
            .lint(
                LintRequest {
                    input: LintInput::Semantic(&analyzed),
                    registry: self.linter.registry(),
                    configuration: &configuration,
                    limits,
                },
                is_cancelled,
            )
            .map_err(map_lint_error)?;
        check_cancelled(is_cancelled)?;

        let total_diagnostics = diagnostics
            .diagnostics()
            .len()
            .checked_add(output.findings().len())
            .ok_or_else(|| input_error("aggregate diagnostic count overflow"))?;
        if total_diagnostics > options.maximum_diagnostics as usize {
            return Err(input_error(format!(
                "command produced more than {} diagnostics across frontend and lint phases",
                options.maximum_diagnostics
            )));
        }
        for finding in output.findings() {
            check_cancelled(is_cancelled)?;
            events.emit(DriverEvent::Diagnostic {
                diagnostic: &finding.diagnostic,
                sources: diagnostics.sources(),
            });
        }
        check_cancelled(is_cancelled)?;
        phase_finished(events, "semantic-lint");

        // Retain the exact source database for both warning rendering and a
        // deny-level rejection; terminal adapters must never receive anonymous
        // numeric spans or only an aggregate count.
        let denied = output.denied();
        let (mut all, sources) = diagnostics.into_parts();
        all.try_reserve_exact(output.findings().len())
            .map_err(|_| input_error("cannot allocate the bounded lint diagnostic report"))?;
        all.extend(
            output
                .findings()
                .iter()
                .map(|finding| finding.diagnostic.clone()),
        );
        let report = if denied {
            DiagnosticReport::rejected(all, sources, options.maximum_diagnostics, is_cancelled)
        } else {
            DiagnosticReport::successful(all, sources, options.maximum_diagnostics, is_cancelled)
        }
        .map_err(|error| input_error(format!("invalid lint diagnostic report: {error}")))?;
        drop((analysis, verification, analyzed, build));
        if denied {
            return Err(DriverError::Rejected { report });
        }
        let outcome = LintOutcome::new(output, report)
            .map_err(|error| input_error(format!("invalid lint outcome: {error}")))?;
        Ok(CommandOutput::Lint(outcome))
    }
}

impl CompilerDriver for LocalLintDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        match command {
            Command::Lint {
                workspace,
                diagnostics,
            } => self.lint(workspace, diagnostics, events, is_cancelled),
            _ => Err(DriverError::InvalidCommand(
                "local lint driver accepts only a normalized `lint` command".to_owned(),
            )),
        }
    }
}

/// CLI-oriented entry point using standard policy and a silent event sink.
pub fn execute_local_lint(command: &Command) -> Result<CommandOutput, DriverError> {
    LocalLintDriver::discover(PipelineLimits::standard())?.execute(
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

/// Concrete whole-image semantic linter.
///
/// Value uses come from the sealed semantic database, including closure
/// captures and live loans. This avoids the false answers produced by a text
/// search and naturally handles shadowing, name resolution, and the exact
/// monomorphized image closure.
#[derive(Debug, Clone)]
struct CanonicalSemanticLinter {
    registry: LintRegistry,
    unused_local: LintName,
    unused_parameter: LintName,
}

impl CanonicalSemanticLinter {
    fn new() -> Result<Self, LintError> {
        let unused_local = LintName::new(UNUSED_LOCAL_BINDING)?;
        let unused_parameter = LintName::new(UNUSED_PARAMETER)?;
        let registry = LintRegistry::new(vec![
            LintDescriptor {
                name: unused_local.clone(),
                layer: LintLayer::Semantic,
                summary: "a source local binding has no read in the closed image".to_owned(),
                default_level: LintLevel::Warn,
            },
            LintDescriptor {
                name: unused_parameter.clone(),
                layer: LintLayer::Semantic,
                summary: "a source parameter has no read in its analyzed function".to_owned(),
                default_level: LintLevel::Warn,
            },
        ])?;
        Ok(Self {
            registry,
            unused_local,
            unused_parameter,
        })
    }

    fn lint_semantic(
        &self,
        image: &AnalyzedImage,
        configuration: &LintConfiguration,
        limits: LintLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LintOutputCandidate, LintError> {
        let facts = image.facts();
        let value_count = facts.values.len();
        let value_index_bytes =
            u64::try_from(value_count).map_err(|_| LintError::ResourceLimit {
                resource: "lint value-use index bytes",
                limit: limits.diagnostic_bytes,
            })?;
        if value_index_bytes > limits.diagnostic_bytes {
            return Err(LintError::ResourceLimit {
                resource: "lint value-use index bytes",
                limit: limits.diagnostic_bytes,
            });
        }
        let mut value_state = Vec::new();
        value_state
            .try_reserve_exact(value_count)
            .map_err(|_| LintError::ResourceLimit {
                resource: "lint value-use index bytes",
                limit: limits.diagnostic_bytes,
            })?;
        value_state.resize(value_count, 0u8);

        for function in &facts.functions {
            check_lint_cancelled(is_cancelled)?;
            for parameter in &function.parameters {
                mark_value(
                    &mut value_state,
                    parameter.value,
                    VALUE_STATE_PARAMETER,
                    &self.unused_parameter,
                )?;
            }
        }
        for expression in &facts.expressions {
            check_lint_cancelled(is_cancelled)?;
            match &expression.resolution {
                ExpressionResolution::Value(value) => mark_value(
                    &mut value_state,
                    *value,
                    VALUE_STATE_USED,
                    &self.unused_local,
                )?,
                ExpressionResolution::Closure { captures, .. } => {
                    for value in captures {
                        mark_value(
                            &mut value_state,
                            *value,
                            VALUE_STATE_USED,
                            &self.unused_local,
                        )?;
                    }
                }
                ExpressionResolution::Error
                | ExpressionResolution::Constant(_)
                | ExpressionResolution::Function(_)
                | ExpressionResolution::Constructor { .. }
                | ExpressionResolution::ResultTry { .. }
                | ExpressionResolution::DirectCall { .. }
                | ExpressionResolution::OperatorCall { .. }
                | ExpressionResolution::ActorRequest { .. }
                | ExpressionResolution::Field { .. }
                | ExpressionResolution::Index { .. }
                | ExpressionResolution::Builtin(_) => {}
            }
        }
        for statement in &facts.statements {
            check_lint_cancelled(is_cancelled)?;
            for loan in &statement.live_loans_after {
                mark_value(
                    &mut value_state,
                    loan.value,
                    VALUE_STATE_USED,
                    &self.unused_local,
                )?;
            }
        }

        let maximum = usize::try_from(limits.findings).map_err(|_| LintError::ResourceLimit {
            resource: "lint findings",
            limit: u64::from(limits.findings),
        })?;
        let mut findings = Vec::new();
        for (value, state) in facts.values.iter().zip(value_state) {
            check_lint_cancelled(is_cancelled)?;
            let Some(name) = value.source_name.as_deref() else {
                continue;
            };
            let Some(source) = value.source else {
                continue;
            };
            if state & VALUE_STATE_USED != 0 || name == "self" || name.starts_with('_') {
                continue;
            }
            let (lint, message) = if state & VALUE_STATE_PARAMETER != 0 {
                (
                    &self.unused_parameter,
                    "parameter is not read by the analyzed image",
                )
            } else {
                (
                    &self.unused_local,
                    "local binding is not read by the analyzed image",
                )
            };
            let level = effective_level(&self.registry, configuration, lint)?;
            if level == LintLevel::Allow {
                continue;
            }
            let severity = match level {
                LintLevel::Allow => continue,
                LintLevel::Warn => Severity::Warning,
                LintLevel::Deny => Severity::Error,
            };
            push_bounded_finding(
                &mut findings,
                LintFinding {
                    lint: lint.clone(),
                    level,
                    diagnostic: Diagnostic {
                        category: Category::NAME,
                        code: Some(lint.as_str().to_owned()),
                        severity,
                        primary: source,
                        message: message.to_owned(),
                        labels: Vec::new(),
                        notes: Vec::new(),
                        help: Vec::new(),
                        related: Vec::new(),
                        repairs: Vec::new(),
                    },
                },
                maximum,
                limits.findings,
                is_cancelled,
            )?;
        }
        canonicalize_findings(&mut findings, is_cancelled)?;
        Ok(LintOutputCandidate { findings })
    }
}

impl Linter for CanonicalSemanticLinter {
    fn registry(&self) -> &LintRegistry {
        &self.registry
    }

    fn lint(
        &self,
        request: LintRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LintOutput, LintError> {
        check_lint_cancelled(is_cancelled)?;
        request.limits.validate()?;
        if request.registry != &self.registry {
            let name = request
                .registry
                .descriptors()
                .first()
                .map_or_else(|| self.unused_local.clone(), |value| value.name.clone());
            return Err(LintError::InvalidDescriptor(name));
        }
        let candidate = match &request.input {
            LintInput::Semantic(image) => {
                self.lint_semantic(image, request.configuration, request.limits, is_cancelled)?
            }
            LintInput::Syntax(_) | LintInput::Hir(_) => {
                return Err(LintError::WrongLayer {
                    lint: self.unused_local.clone(),
                    expected: LintLayer::Semantic,
                });
            }
        };
        seal_lint_output(&request, candidate, is_cancelled)
    }
}

fn lint_configuration(
    registry: &LintRegistry,
    warnings_as_errors: bool,
    sealed_deployment: bool,
) -> LintConfiguration {
    let mut levels = BTreeMap::new();
    if warnings_as_errors {
        for descriptor in registry.descriptors() {
            if descriptor.default_level == LintLevel::Warn {
                levels.insert(descriptor.name.clone(), LintLevel::Deny);
            }
        }
    }
    LintConfiguration {
        levels,
        sealed_deployment,
    }
}

fn remaining_lint_limits(
    mut limits: LintLimits,
    prior_diagnostics: usize,
    command_maximum: u32,
) -> Result<LintLimits, DriverError> {
    let command_maximum = usize::try_from(command_maximum)
        .map_err(|_| input_error("maximum diagnostics does not fit the host"))?;
    if prior_diagnostics > command_maximum {
        return Err(input_error(
            "frontend diagnostics exceed the command diagnostic limit",
        ));
    }
    let remaining = command_maximum - prior_diagnostics;
    // LintLimits forbids zero. A one-finding probe when no aggregate capacity
    // remains lets a clean lint still succeed; any actual finding is rejected
    // by the aggregate check immediately after sealing.
    let remaining = remaining.max(1);
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    limits.findings = limits.findings.min(remaining);
    limits
        .validate()
        .map_err(|error| input_error(format!("invalid lint limits: {error}")))?;
    Ok(limits)
}

fn effective_level(
    registry: &LintRegistry,
    configuration: &LintConfiguration,
    name: &LintName,
) -> Result<LintLevel, LintError> {
    let descriptor = registry
        .descriptor(name)
        .ok_or_else(|| LintError::UnknownLint(name.clone()))?;
    Ok(configuration
        .levels
        .get(name)
        .copied()
        .unwrap_or(descriptor.default_level))
}

fn mark_value(
    states: &mut [u8],
    value: ValueId,
    bit: u8,
    rule: &LintName,
) -> Result<(), LintError> {
    let state = states
        .get_mut(value.0 as usize)
        .ok_or_else(|| LintError::InvalidFinding(rule.clone()))?;
    *state |= bit;
    Ok(())
}

fn push_bounded_finding(
    findings: &mut Vec<LintFinding>,
    finding: LintFinding,
    maximum: usize,
    configured_maximum: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LintError> {
    if findings.len() == maximum {
        canonicalize_findings(findings, is_cancelled)?;
        if findings.len() == maximum {
            if findings
                .binary_search_by(|existing| compare_findings(existing, &finding))
                .is_ok()
            {
                return Ok(());
            }
            return Err(LintError::ResourceLimit {
                resource: "lint findings",
                limit: u64::from(configured_maximum),
            });
        }
    }
    findings
        .try_reserve(1)
        .map_err(|_| LintError::ResourceLimit {
            resource: "lint findings",
            limit: u64::from(configured_maximum),
        })?;
    findings.push(finding);
    Ok(())
}

fn canonicalize_findings(
    findings: &mut Vec<LintFinding>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LintError> {
    check_lint_cancelled(is_cancelled)?;
    findings.sort_unstable_by(compare_findings);
    findings.dedup();
    check_lint_cancelled(is_cancelled)
}

fn compare_findings(left: &LintFinding, right: &LintFinding) -> Ordering {
    left.lint
        .cmp(&right.lint)
        .then_with(|| left.level.cmp(&right.level))
        .then_with(|| compare_diagnostics(&left.diagnostic, &right.diagnostic))
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

fn check_lint_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LintError> {
    if is_cancelled() {
        Err(LintError::Cancelled)
    } else {
        Ok(())
    }
}

fn map_lint_error(error: LintError) -> DriverError {
    match error {
        LintError::Cancelled => DriverError::Cancelled,
        error => input_error(error.to_string()),
    }
}

fn input_error(message: impl Into<String>) -> DriverError {
    DriverError::Input {
        phase: "lint",
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_source::{FileId, Span, TextRange};

    fn fixture_finding(lint: &LintName, start: u32) -> LintFinding {
        LintFinding {
            lint: lint.clone(),
            level: LintLevel::Warn,
            diagnostic: Diagnostic {
                category: Category::NAME,
                code: Some(lint.as_str().to_owned()),
                severity: Severity::Warning,
                primary: Span {
                    file: FileId(0),
                    range: TextRange {
                        start,
                        end: start + 1,
                    },
                },
                message: "fixture finding".to_owned(),
                labels: Vec::new(),
                notes: Vec::new(),
                help: Vec::new(),
                related: Vec::new(),
                repairs: Vec::new(),
            },
        }
    }

    #[test]
    fn registry_is_canonical_and_semantic() {
        let linter = CanonicalSemanticLinter::new().expect("canonical registry");
        let descriptors = linter.registry().descriptors();
        assert_eq!(descriptors.len(), 2);
        assert!(
            descriptors
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );
        assert!(
            descriptors
                .iter()
                .all(|descriptor| descriptor.layer == LintLayer::Semantic)
        );
    }

    #[test]
    fn warning_policy_promotes_every_advisory() {
        let linter = CanonicalSemanticLinter::new().expect("canonical registry");
        let ordinary = lint_configuration(linter.registry(), false, false);
        assert!(ordinary.levels.is_empty());
        assert!(!ordinary.sealed_deployment);

        let strict = lint_configuration(linter.registry(), true, true);
        assert!(strict.sealed_deployment);
        assert_eq!(strict.levels.len(), linter.registry().descriptors().len());
        assert!(
            strict
                .levels
                .values()
                .all(|level| *level == LintLevel::Deny)
        );
    }

    #[test]
    fn duplicate_monomorphization_findings_do_not_consume_capacity() {
        let lint = LintName::new(UNUSED_PARAMETER).expect("lint name");
        let finding = fixture_finding(&lint, 3);
        let mut findings = Vec::new();
        push_bounded_finding(&mut findings, finding.clone(), 1, 1, &|| false)
            .expect("first finding");
        push_bounded_finding(&mut findings, finding, 1, 1, &|| false).expect("duplicate finding");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            push_bounded_finding(&mut findings, fixture_finding(&lint, 9), 1, 1, &|| false),
            Err(LintError::ResourceLimit {
                resource: "lint findings",
                limit: 1
            })
        ));
    }

    #[test]
    fn linter_rejects_the_wrong_information_layer_and_cancellation() {
        let linter = CanonicalSemanticLinter::new().expect("canonical registry");
        let configuration = LintConfiguration::default();
        let request = || LintRequest {
            input: LintInput::Syntax(&[]),
            registry: linter.registry(),
            configuration: &configuration,
            limits: LintLimits::standard(),
        };
        assert!(matches!(
            linter.lint(request(), &|| false),
            Err(LintError::WrongLayer {
                expected: LintLayer::Semantic,
                ..
            })
        ));
        assert_eq!(linter.lint(request(), &|| true), Err(LintError::Cancelled));
    }

    #[test]
    fn aggregate_limit_reserves_only_remaining_capacity() {
        let standard = LintLimits::standard();
        assert_eq!(
            remaining_lint_limits(standard, 7, 10)
                .expect("remaining limits")
                .findings,
            3
        );
        assert_eq!(
            remaining_lint_limits(standard, 10, 10)
                .expect("zero-capacity probe")
                .findings,
            1
        );
        assert!(remaining_lint_limits(standard, 11, 10).is_err());
    }
}
