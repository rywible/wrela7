#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

use wrela_build_model::TargetIdentity;
use wrela_compiler::{
    LocalDoctorDriver, LocalTestDriver, LocalToolchainVerificationLimits, PipelineLimits,
};
use wrela_driver::{
    Command as DriverCommand, CompilerDriver, DiagnosticOptions, DriverError, DriverEvent,
    EventSink, TestSelection, WorkspaceSelection,
};
use wrela_package::{
    PackageIdentity, PackageLocator, PackageManifest, PackageName, PackageVersion,
};
use wrela_package_loader::{
    CanonicalPackageCodec, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher,
    ManifestCodecLimits, PackageCodec, PackageContentKind, PackageContentRecord, SoftwareSha256,
    canonical_tree_digest, package_content_digest,
};
use wrela_test_model::{
    CanonicalTestReportCodec, FailurePhase, TestOutcome as ModelTestOutcome, TestReport,
    TestReportCodec,
};
use wrela_toolchain::{
    CanonicalToolchainManifestCodec, ComponentKind, ComponentPath, REQUIRED_LLVM_PROJECT_REVISION,
    ShippedComponent, ShippedStandardLibraryPackage, ShippedTarget, ShippedTargetFile,
    TOOLCHAIN_MANIFEST_SCHEMA, ToolchainCompatibility, ToolchainDecodeLimits, ToolchainManifest,
    ToolchainManifestCodec, current_host_identity,
};

const APPLICATION_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/wrela.toml");
const APPLICATION_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/src/bootstrap/image.wr");
const COMPTIME_TEST_SOURCE: &[u8] = b"module bootstrap.image\n\nfrom core.image import Image, Target\n\n@image\npub fn boot() -> Image:\n    return Image(name=\"bootstrap\", target=Target.aarch64_qemu_virt_uefi)\n\n@test\nfn unit_case():\n    comptime assert true, \"unit assertion\"\n";
const FAILING_COMPTIME_TEST_SOURCE: &[u8] = b"module bootstrap.image\n\nfrom core.image import Image, Target\n\n@image\npub fn boot() -> Image:\n    return Image(name=\"bootstrap\", target=Target.aarch64_qemu_virt_uefi)\n\n@test\nfn unit_case():\n    comptime assert false, \"expected unit failure\"\n";
const SOURCE_UNIT_IMAGE: &[u8] = b"module app.image\n\nfrom core.image import Image, Target\n\n@image\npub fn boot() -> Image:\n    return Image(name=\"bootstrap\", target=Target.aarch64_qemu_virt_uefi)\n";
const SOURCE_UNIT_MATH: &[u8] = br#"module app.math

pub fn add(left: u32, right: u32) -> u32:
    return left + right

pub fn distance(left: u32, right: u32) -> u32:
    if left >= right:
        return left - right
    return right - left

pub fn add_two(value: u32) -> u32:
    return add(add(value, 1), 1)

pub fn scaled_remainder(value: u32) -> u32:
    scaled: u32 = value * 6
    quotient: u32 = scaled / 4
    remainder: u32 = scaled % 4
    return quotient + remainder

pub fn both(left: bool, right: bool) -> bool:
    return left and right

pub fn either(left: bool, right: bool) -> bool:
    return left or right

pub fn signed_edges() -> bool:
    minimum_i8: i8 = -128
    minimum_i128: i128 = -170141183460469231731687303715884105728
    quotient: i8 = -7 / 3
    remainder: i8 = -7 % 3
    shifted: i8 = -8 >> 2
    return minimum_i8 < -127 and minimum_i128 < 0 and quotient == -2 and remainder == -1 and shifted == -2

pub fn wrapping_edge() -> u8:
    maximum: u8 = 255
    return maximum +% 1

pub fn unconstrained_default() -> i64:
    value = 42
    return value

pub fn unconstrained_signed_minimum() -> bool:
    minimum = -9223372036854775808
    successor = minimum + 1
    return minimum < successor and successor == -9223372036854775807

pub fn fails_if_called() -> bool:
    zero: u32 = 0
    invalid: u32 = 1 / zero
    return invalid == 0

pub fn short_circuit_edges() -> bool:
    disjunction: bool = true or fails_if_called()
    conjunction: bool = false and fails_if_called()
    return disjunction and not conjunction

pub fn bitwise_edges(value: u32) -> bool:
    anded: u32 = value & 15
    ored: u32 = anded | 32
    xored: u32 = ored ^ 10
    shifted_left: u32 = xored << 1
    shifted_right: u32 = shifted_left >> 2
    return anded == 10 and ored == 42 and xored != value and shifted_left == 64 and shifted_right == 16

pub fn ordinary_branch_edge(value: u32) -> u32:
    if value <= 10:
        return 1
    elif value > 40 and value != 42:
        return 2
    else:
        return 3

pub fn comptime_branch_edge(flag: bool) -> u32:
    comptime if flag:
        return 7
    comptime else:
        return 9

pub fn target_word_edges() -> bool:
    highest: usize = 18446744073709551615
    one: usize = 1
    high_bit: usize = one << 63
    wrapped: usize = highest +% one
    minimum: isize = -9223372036854775808
    negative: isize = -8
    shifted: isize = negative >> 2
    return highest > high_bit and high_bit == 9223372036854775808 and wrapped == 0 and minimum < negative and shifted == -2

pub fn invalid_shift() -> u8:
    value: u8 = 1
    return value << 8

pub fn unsupported_loop():
    loop:
        pass
"#;
const PASSING_SOURCE_UNIT_TESTS: &[u8] = br#"module app.math_test

from app.math import add, add_two, bitwise_edges, both, comptime_branch_edge, distance, either, ordinary_branch_edge, scaled_remainder, short_circuit_edges, signed_edges, target_word_edges, unconstrained_default, unconstrained_signed_minimum, wrapping_edge

@test
fn imported_add_works():
    inferred = add(20, 22)
    adjusted = inferred + 8
    named: u32 = add(right=22, left=20)
    comptime assert inferred == 42 and adjusted == 50 and named == 42, "imported add returned the wrong value"

@test
fn nested_import_works():
    result: u32 = add_two(40)
    comptime assert result == 42, "nested imported calls returned the wrong value"

@test
fn scalar_branching_works():
    distance_result: u32 = distance(20, 62)
    arithmetic_result: u32 = scaled_remainder(7)
    boolean_result: bool = both(distance_result == 42, not false) and either(false, arithmetic_result == 12)
    bitwise_result: bool = bitwise_edges(42)
    ordinary_result: bool = ordinary_branch_edge(5) == 1 and ordinary_branch_edge(41) == 2 and ordinary_branch_edge(42) == 3
    comptime_result: bool = comptime_branch_edge(true) == 7 and comptime_branch_edge(false) == 9
    comptime assert boolean_result and bitwise_result and ordinary_result and comptime_result, "scalar arithmetic, branching, or boolean evaluation was wrong"

@test
fn short_circuit_skips_failing_rhs():
    comptime assert short_circuit_edges(), "boolean short-circuit evaluated a failing RHS"

@test
fn target_integer_edges_work():
    wrapped: u8 = wrapping_edge()
    defaulted: i64 = unconstrained_default()
    comptime assert signed_edges() and unconstrained_signed_minimum() and target_word_edges() and wrapped == 0 and defaulted == 42, "target integer edge semantics were wrong"
"#;
const FAILING_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import add\n\n@test\nfn imported_add_failure_is_reported():\n    result: u32 = add(20, 22)\n    comptime assert result == 41, \"imported add failure\"\n";
const DEPTH_SOURCE_UNIT_MATH: &[u8] = b"module app.math\n\npub fn leaf() -> u32:\n    return 42\n\npub fn middle() -> u32:\n    return leaf()\n";
const DEPTH_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import middle\n\n@test\nfn imported_call_depth_is_bounded():\n    result: u32 = middle()\n    comptime assert result == 42, \"nested imported call returned the wrong value\"\n";
const UNSUPPORTED_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import unsupported_loop\n\n@test\nfn unsupported_loop_is_diagnostic():\n    unsupported_loop()\n";
const ARITHMETIC_FAILURE_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import invalid_shift\n\n@test\nfn imported_invalid_shift_is_reported():\n    result: u8 = invalid_shift()\n    comptime assert result == 0, \"unreachable after invalid shift\"\n";
const CANCELLATION_SOURCE_UNIT_MATH: &[u8] = b"module app.math\n\npub fn countdown(value: u32) -> u32:\n    if value == 0:\n        return 0\n    return countdown(value - 1)\n";
const SHALLOW_CANCELLATION_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import countdown\n\n@test\nfn imported_countdown_is_cancellable():\n    result: u32 = countdown(0)\n    comptime assert result == 0, \"countdown returned the wrong value\"\n";
const DEEP_CANCELLATION_SOURCE_UNIT_TEST: &[u8] = b"module app.math_test\n\nfrom app.math import countdown\n\n@test\nfn imported_countdown_is_cancellable():\n    result: u32 = countdown(24)\n    comptime assert result == 0, \"countdown returned the wrong value\"\n";
// `runtime_case`'s body is a bounded `while` (not a bare `pass`): a trivial
// `pass` body is structurally within the static comptime-legality checker's
// supported subset (`StatementKind::Pass` is legal there), so it would be
// silently misrouted into the comptime tier instead of reaching the
// `--integration` selection this test exercises. A bounded `while` is
// unsupported by the static checker (forcing the runtime tier) but fully
// supported by the runtime-shape checker, so it deterministically stays
// selectable under `--integration`.
const INTEGRATION_TEST_SOURCE: &[u8] = b"module bootstrap.image\n\nfrom core.image import Image, Target\n\n@image\npub fn boot() -> Image:\n    return Image(name=\"bootstrap\", target=Target.aarch64_qemu_virt_uefi)\n\n@test\nfn runtime_case():\n    guard: u32 = 0\n    while guard < 1:\n        guard += 1\n";
const MALFORMED_APPLICATION_SOURCE: &[u8] = b"module bootstrap.image\n\nfrom core.image import Image, Target\n\n@image\npub fn boot() -> Image:\n    return Image(name=, target=Target.aarch64_qemu_virt_uefi)\n";
const UNFORMATTED_APPLICATION_SOURCE: &[u8] = b"module   bootstrap.image\n";
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_TIME_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/time.wr");
const TARGET_MANIFEST: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
const BACKEND_BYTES: &[u8] = b"wrela CLI test backend";
const RUNTIME_OBJECT: &[u8] = b"wrela CLI test runtime object";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
static HASHER: SoftwareSha256 = SoftwareSha256;
const EXIT_SUCCESS: i32 = 0;
const EXIT_UNSUCCESSFUL: i32 = 1;
const EXIT_USAGE: i32 = 2;

struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
        for _ in 0..128 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = temporary.join(format!("wrela-cli-check-{}-{sequence}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Self {
                        root: fs::canonicalize(root).expect("canonical test root"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create CLI test directory: {error}"),
            }
        }
        panic!("cannot allocate CLI test directory");
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent directory");
        }
        fs::write(&path, bytes).expect("test file write");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn source_unit_manifest(
    comptime_steps: u64,
    comptime_memory_bytes: u64,
    comptime_call_depth: u32,
) -> Vec<u8> {
    format!(
        "schema = 1\n\
language = \"0.1-design\"\n\
\n\
[package]\n\
name = \"source-unit\"\n\
version = \"0.1.0\"\n\
source_root = \"src\"\n\
\n\
[[dependency]]\n\
alias = \"core\"\n\
package = \"wrela-core\"\n\
requirement = \"=0.1.0\"\n\
\n\
[[profile]]\n\
name = \"development\"\n\
mode = \"development\"\n\
comptime_steps = {comptime_steps}\n\
comptime_memory_bytes = {comptime_memory_bytes}\n\
comptime_call_depth = {comptime_call_depth}\n\
static_bytes = 1048576\n\
peak_bytes = 1048576\n\
event_log_bytes = 0\n\
dma_coherent = false\n\
require_iommu = false\n\
reset_timeout_ns = 1\n\
quarantine_bytes = 0\n\
recording = \"disabled\"\n\
optimization = \"none\"\n\
sealed_deployment = false\n\
warnings_as_errors = false\n\
watchdogs = false\n\
\n\
[[image]]\n\
name = \"bootstrap\"\n\
module = \"app.image\"\n\
entry = \"boot\"\n\
target = \"aarch64-qemu-virt-uefi\"\n\
profile = \"development\"\n"
    )
    .into_bytes()
}

fn decode_test_report(bytes: &[u8]) -> TestReport {
    CanonicalTestReportCodec
        .decode(
            bytes,
            u64::try_from(bytes.len()).expect("report length fits u64"),
            &never_cancelled,
        )
        .expect("published report decodes canonically")
}

fn unique_slice_offset(source: &[u8], needle: &[u8]) -> usize {
    assert!(!needle.is_empty(), "source-span needle must not be empty");
    let mut matches = source
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset));
    let offset = matches.next().expect("source-span needle must be present");
    assert!(
        matches.next().is_none(),
        "source-span needle must be unique"
    );
    offset
}

fn fixture_source_span(file: u32, source: &[u8], context: &[u8], selected: &[u8]) -> String {
    let context_offset = unique_slice_offset(source, context);
    let selected_offset = unique_slice_offset(context, selected);
    let start = context_offset
        .checked_add(selected_offset)
        .expect("fixture source start fits usize");
    let end = start
        .checked_add(selected.len())
        .expect("fixture source end fits usize");
    format!("{file}:{start}-{end}")
}

#[derive(Default)]
struct SemanticPhaseEvents {
    active: Cell<bool>,
    finished: Cell<bool>,
}

impl EventSink for SemanticPhaseEvents {
    fn emit(&self, event: DriverEvent<'_>) {
        match event {
            DriverEvent::PhaseStarted {
                phase: "semantic-analysis",
            } => self.active.set(true),
            DriverEvent::PhaseFinished {
                phase: "semantic-analysis",
                ..
            } => {
                self.active.set(false);
                self.finished.set(true);
            }
            _ => {}
        }
    }
}

fn run_source_unit_driver_with_semantic_cancellation(
    directory: &TestDirectory,
    toolchain: &Path,
    test_source: &[u8],
    output_name: &str,
    cancel_at_semantic_poll: Option<u64>,
) -> (Result<(), DriverError>, u64, bool) {
    let workspace =
        install_source_unit_workspace(directory, CANCELLATION_SOURCE_UNIT_MATH, test_source, 64);
    let output_directory = directory.root.join(output_name);
    let driver = LocalTestDriver::new(
        wrela_toolchain::Toolchain::at(toolchain),
        PipelineLimits::standard(),
    )
    .expect("compose local source-unit test driver");
    let command = DriverCommand::Test {
        workspace: WorkspaceSelection {
            manifest: workspace.join("wrela.toml"),
            image: "bootstrap".to_owned(),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            profile: "development".to_owned(),
        },
        output_directory,
        selection: TestSelection::Comptime,
        diagnostics: DiagnosticOptions::default(),
    };
    let events = SemanticPhaseEvents::default();
    let semantic_polls = Cell::new(0_u64);
    let is_cancelled = || {
        if !events.active.get() {
            return false;
        }
        let next = semantic_polls
            .get()
            .checked_add(1)
            .expect("bounded semantic poll count");
        semantic_polls.set(next);
        cancel_at_semantic_poll.is_some_and(|limit| next >= limit)
    };
    let result = driver.execute(&command, &events, &is_cancelled).map(|_| ());
    (result, semantic_polls.get(), events.finished.get())
}

fn minimum_passing_bound(
    mut lowest: u64,
    mut highest: u64,
    mut passes: impl FnMut(u64) -> bool,
) -> u64 {
    assert!(lowest < highest);
    assert!(passes(highest), "upper calibration bound must pass");
    while lowest < highest {
        let middle = lowest + (highest - lowest) / 2;
        if passes(middle) {
            highest = middle;
        } else {
            lowest = middle + 1;
        }
    }
    lowest
}

#[test]
fn public_check_renders_structured_syntax_failure_with_source_location() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, MALFORMED_APPLICATION_SOURCE);
    let toolchain = install_toolchain(&directory);

    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("check")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public wrela binary");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 diagnostic output");
    assert!(stderr.contains("error[syntax-"), "{stderr}");
    assert!(stderr.contains("bootstrap/image.wr:"), "{stderr}");
    assert!(stderr.contains("expected"), "{stderr}");
    assert!(stderr.contains("build rejected with"), "{stderr}");
}

#[test]
fn public_check_and_lint_reach_real_analysis_while_build_fails_at_the_fake_backend() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, APPLICATION_SOURCE);
    let toolchain = install_toolchain(&directory);

    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("check")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .args(["--target", "aarch64-qemu-virt-uefi"])
        .arg("--profile")
        .arg("development")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public wrela binary");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_SUCCESS));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 check output");
    assert!(
        stdout.contains("check completed with 0 warning(s) and 3 proof fact(s)"),
        "{stdout}"
    );

    let lint = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("lint")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .args(["--target", "aarch64-qemu-virt-uefi"])
        .args(["--maximum-diagnostics", "100000"])
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public lint command");
    assert_eq!(lint.status.code(), Some(EXIT_SUCCESS));
    assert!(lint.stderr.is_empty());
    assert_eq!(lint.stdout, b"0 lint finding(s)\n");

    let output_directory = directory.root.join("failed-build-output");
    let build = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("build")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .args(["--target", "aarch64-qemu-virt-uefi"])
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public build against the deliberately invalid backend fixture");
    assert_eq!(build.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(build.stdout.is_empty());
    let stderr = String::from_utf8(build.stderr).expect("UTF-8 backend failure output");
    assert!(stderr.contains("error: backend failed:"), "{stderr}");
    assert!(
        !output_directory.exists(),
        "backend failure must not publish an output directory"
    );
}

#[test]
fn public_comptime_test_publishes_a_reproducible_canonical_report_without_backend_execution() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, COMPTIME_TEST_SOURCE);
    let toolchain = install_toolchain(&directory);
    let mut reports = Vec::new();
    for output_name in ["first-test-output", "second-test-output"] {
        let output_directory = directory.root.join(output_name);
        let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
            .arg("test")
            .arg(workspace.join("wrela.toml"))
            .arg("bootstrap")
            .arg(&output_directory)
            .arg("--comptime")
            .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
            .output()
            .expect("run public comptime test");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(EXIT_SUCCESS));
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout, b"test passed\n");
        let report = fs::read(output_directory.join("test-report.bin"))
            .expect("published canonical test report");
        assert!(!report.is_empty());
        assert!(
            fs::read_dir(&output_directory)
                .expect("test output directory")
                .all(|entry| entry
                    .expect("test output entry")
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "efi")),
            "comptime-only selection must not publish or execute an image"
        );
        reports.push(report);
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn public_source_unit_tests_import_production_functions_and_are_path_independent() {
    let first = TestDirectory::new();
    let second = TestDirectory::new();
    let mut reports = Vec::new();
    for directory in [&first, &second] {
        let workspace = install_source_unit_workspace(
            directory,
            SOURCE_UNIT_MATH,
            PASSING_SOURCE_UNIT_TESTS,
            64,
        );
        let toolchain = install_toolchain(directory);
        let output_directory = directory.root.join("source-unit-output");
        let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
            .arg("test")
            .arg(workspace.join("wrela.toml"))
            .arg("bootstrap")
            .arg(&output_directory)
            .arg("--comptime")
            .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
            .output()
            .expect("run public imported source unit tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(EXIT_SUCCESS));
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout, b"test passed\n");

        let bytes = fs::read(output_directory.join("test-report.bin"))
            .expect("published source-unit report");
        let report = decode_test_report(&bytes);
        assert!(report.images.is_empty());
        assert_eq!(report.unit.len(), 5);
        assert!(report.unit.iter().all(|case| {
            matches!(case.outcome, ModelTestOutcome::Passed) && case.duration_ns.is_none()
        }));
        let names = report
            .unit
            .iter()
            .map(|case| case.descriptor.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "source-unit@0.1.0::app.math_test::imported_add_works",
                "source-unit@0.1.0::app.math_test::nested_import_works",
                "source-unit@0.1.0::app.math_test::scalar_branching_works",
                "source-unit@0.1.0::app.math_test::short_circuit_skips_failing_rhs",
                "source-unit@0.1.0::app.math_test::target_integer_edges_work",
            ]
        );
        assert!(
            fs::read_dir(&output_directory)
                .expect("source-unit output directory")
                .all(|entry| entry
                    .expect("source-unit output entry")
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "efi")),
            "comptime source-unit tests must not invoke the fake backend"
        );
        reports.push(bytes);
    }

    assert_eq!(
        reports[0], reports[1],
        "canonical reports must not bind absolute workspace or output paths"
    );
}

#[test]
fn public_name_filter_selects_one_real_imported_source_unit_test() {
    let directory = TestDirectory::new();
    let workspace =
        install_source_unit_workspace(&directory, SOURCE_UNIT_MATH, PASSING_SOURCE_UNIT_TESTS, 64);
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("filtered-source-unit-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .args(["--name-contains", "app.math_test::nested_import_works"])
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run filtered imported source unit test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"test passed\n");

    let bytes = fs::read(output_directory.join("test-report.bin"))
        .expect("published filtered source-unit report");
    let report = decode_test_report(&bytes);
    assert!(report.images.is_empty());
    let [case] = report.unit.as_slice() else {
        panic!("name filter must select exactly one source unit test");
    };
    assert_eq!(case.descriptor.id.0, 0);
    assert_eq!(
        case.descriptor.name,
        "source-unit@0.1.0::app.math_test::nested_import_works"
    );
    assert_eq!(case.outcome, ModelTestOutcome::Passed);
}

#[test]
fn public_imported_source_unit_assertion_failure_is_canonical_report_data() {
    let directory = TestDirectory::new();
    let workspace =
        install_source_unit_workspace(&directory, SOURCE_UNIT_MATH, FAILING_SOURCE_UNIT_TEST, 64);
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("failed-imported-source-unit-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .arg("--comptime")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run failing imported source unit test");
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"test failed\n");

    let bytes = fs::read(output_directory.join("test-report.bin"))
        .expect("published failing imported source-unit report");
    let report = decode_test_report(&bytes);
    assert!(report.images.is_empty());
    let [case] = report.unit.as_slice() else {
        panic!("one failing source unit test must produce one case result");
    };
    assert_eq!(
        case.descriptor.name,
        "source-unit@0.1.0::app.math_test::imported_add_failure_is_reported"
    );
    let assertion = fixture_source_span(
        2,
        FAILING_SOURCE_UNIT_TEST,
        b"    comptime assert result == 41, \"imported add failure\"\n",
        b"comptime assert result == 41, \"imported add failure\"",
    );
    let expected = format!("imported add failure [source {assertion}]");
    assert!(
        matches!(
            &case.outcome,
            ModelTestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message,
            } if message == &expected
        ),
        "unexpected assertion outcome: {:?}",
        case.outcome
    );
}

#[test]
fn public_imported_source_unit_arithmetic_failure_preserves_code_and_call_stack() {
    let directory = TestDirectory::new();
    let workspace = install_source_unit_workspace(
        &directory,
        SOURCE_UNIT_MATH,
        ARITHMETIC_FAILURE_SOURCE_UNIT_TEST,
        64,
    );
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("arithmetic-failure-source-unit-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .arg("--comptime")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run arithmetic-failing imported source unit test");
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"test failed\n");

    let bytes = fs::read(output_directory.join("test-report.bin"))
        .expect("published arithmetic-failure source-unit report");
    let report = decode_test_report(&bytes);
    assert!(report.images.is_empty());
    let [case] = report.unit.as_slice() else {
        panic!("one arithmetic-failing source unit test must produce one result");
    };
    assert_eq!(
        case.descriptor.name,
        "source-unit@0.1.0::app.math_test::imported_invalid_shift_is_reported"
    );
    let primary = fixture_source_span(
        1,
        SOURCE_UNIT_MATH,
        b"    return value << 8\n",
        b"value << 8",
    );
    let imported_call = fixture_source_span(
        2,
        ARITHMETIC_FAILURE_SOURCE_UNIT_TEST,
        b"    result: u8 = invalid_shift()\n",
        b"invalid_shift()",
    );
    let expected = format!(
        "semantic-comptime-shift-count: comptime integer shift count is negative or not less than the target width [source {primary}; comptime calls <- {imported_call}]"
    );
    assert!(
        matches!(
            &case.outcome,
            ModelTestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message,
            } if message == &expected
        ),
        "unexpected arithmetic-failure outcome: {:?}",
        case.outcome
    );
}

#[test]
fn public_imported_source_unit_call_depth_accepts_exact_bound_and_reports_over_bound() {
    for (call_depth, expected_status, expected_message) in [
        (3, EXIT_SUCCESS, None),
        (
            2,
            EXIT_UNSUCCESSFUL,
            Some("comptime test exceeded comptime evaluator depth limit 2"),
        ),
    ] {
        let directory = TestDirectory::new();
        let workspace = install_source_unit_workspace(
            &directory,
            DEPTH_SOURCE_UNIT_MATH,
            DEPTH_SOURCE_UNIT_TEST,
            call_depth,
        );
        let toolchain = install_toolchain(&directory);
        let output_directory = directory.root.join("bounded-source-unit-output");
        let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
            .arg("test")
            .arg(workspace.join("wrela.toml"))
            .arg("bootstrap")
            .arg(&output_directory)
            .arg("--comptime")
            .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
            .output()
            .expect("run depth-bounded imported source unit test");
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout,
            if expected_message.is_some() {
                b"test failed\n".as_slice()
            } else {
                b"test passed\n".as_slice()
            }
        );

        let bytes = fs::read(output_directory.join("test-report.bin"))
            .expect("published depth-bounded source-unit report");
        let report = decode_test_report(&bytes);
        let [case] = report.unit.as_slice() else {
            panic!("depth fixture must produce one source unit result");
        };
        match expected_message {
            None => assert_eq!(case.outcome, ModelTestOutcome::Passed),
            Some(expected) => {
                let attempted_leaf = fixture_source_span(
                    1,
                    DEPTH_SOURCE_UNIT_MATH,
                    b"    return leaf()\n",
                    b"leaf()",
                );
                let imported_middle = fixture_source_span(
                    2,
                    DEPTH_SOURCE_UNIT_TEST,
                    b"    result: u32 = middle()\n",
                    b"middle()",
                );
                let expected = format!(
                    "{expected} [source {attempted_leaf}; comptime calls <- {attempted_leaf} <- {imported_middle}]"
                );
                assert!(matches!(
                    &case.outcome,
                    ModelTestOutcome::Failed {
                        phase: FailurePhase::Comptime,
                        message,
                    } if message == &expected
                ));
            }
        }
    }
}

#[test]
fn public_imported_source_unit_step_and_memory_quotas_are_exact() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain(&directory);
    let mut invocation = 0_u32;
    let mut run = |steps: u64, memory_bytes: u64| {
        let workspace = install_source_unit_workspace_with_limits(
            &directory,
            DEPTH_SOURCE_UNIT_MATH,
            DEPTH_SOURCE_UNIT_TEST,
            steps,
            memory_bytes,
            64,
        );
        let output_directory = directory
            .root
            .join(format!("quota-source-unit-output-{invocation}"));
        invocation = invocation.checked_add(1).expect("bounded invocation count");
        let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
            .arg("test")
            .arg(workspace.join("wrela.toml"))
            .arg("bootstrap")
            .arg(&output_directory)
            .arg("--comptime")
            .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
            .output()
            .expect("run quota-bounded imported source unit test");
        (output, output_directory)
    };

    let exact_steps =
        minimum_passing_bound(1, 4096, |steps| run(steps, 1_048_576).0.status.success());
    assert!(exact_steps > 1);
    let (exact_step_output, exact_step_directory) = run(exact_steps, 1_048_576);
    assert!(
        exact_step_output.status.success(),
        "{}",
        String::from_utf8_lossy(&exact_step_output.stderr)
    );
    let exact_step_report = fs::read(exact_step_directory.join("test-report.bin"))
        .expect("exact-step source-unit report");
    let exact_step_report = decode_test_report(&exact_step_report);
    let [exact_step_case] = exact_step_report.unit.as_slice() else {
        panic!("exact-step run must produce one source unit result");
    };
    assert_eq!(exact_step_case.outcome, ModelTestOutcome::Passed);

    let over_step_limit = exact_steps - 1;
    let (over_step_output, over_step_directory) = run(over_step_limit, 1_048_576);
    assert_eq!(over_step_output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(over_step_output.stderr.is_empty());
    assert_eq!(over_step_output.stdout, b"test failed\n");
    let over_step_report = fs::read(over_step_directory.join("test-report.bin"))
        .expect("over-step source-unit report");
    let over_step_report = decode_test_report(&over_step_report);
    let [over_step_case] = over_step_report.unit.as_slice() else {
        panic!("over-step run must produce one source unit result");
    };
    assert!(matches!(
        &over_step_case.outcome,
        ModelTestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message,
        } if message.starts_with(&format!(
            "comptime test exceeded comptime evaluator steps limit {over_step_limit}"
        ))
    ));

    let exact_memory = minimum_passing_bound(1, 1_048_576, |memory_bytes| {
        run(4096, memory_bytes).0.status.success()
    });
    assert!(exact_memory > 1);
    let (exact_memory_output, exact_memory_directory) = run(4096, exact_memory);
    assert!(
        exact_memory_output.status.success(),
        "{}",
        String::from_utf8_lossy(&exact_memory_output.stderr)
    );
    let exact_memory_report = fs::read(exact_memory_directory.join("test-report.bin"))
        .expect("exact-memory source-unit report");
    let exact_memory_report = decode_test_report(&exact_memory_report);
    let [exact_memory_case] = exact_memory_report.unit.as_slice() else {
        panic!("exact-memory run must produce one source unit result");
    };
    assert_eq!(exact_memory_case.outcome, ModelTestOutcome::Passed);

    let over_memory_limit = exact_memory - 1;
    let (over_memory_output, over_memory_directory) = run(4096, over_memory_limit);
    assert_eq!(over_memory_output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(over_memory_output.stderr.is_empty());
    assert_eq!(over_memory_output.stdout, b"test failed\n");
    let over_memory_report = fs::read(over_memory_directory.join("test-report.bin"))
        .expect("over-memory source-unit report");
    let over_memory_report = decode_test_report(&over_memory_report);
    let [over_memory_case] = over_memory_report.unit.as_slice() else {
        panic!("over-memory run must produce one source unit result");
    };
    assert!(matches!(
        &over_memory_case.outcome,
        ModelTestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message,
        } if message.starts_with(&format!(
            "comptime test exceeded comptime evaluator bytes limit {over_memory_limit} [source "
        )) && message.contains("; comptime calls <- ")
    ));
}

#[test]
fn public_unsupported_source_unit_operation_is_a_stable_source_diagnostic() {
    let directory = TestDirectory::new();
    let workspace = install_source_unit_workspace(
        &directory,
        SOURCE_UNIT_MATH,
        UNSUPPORTED_SOURCE_UNIT_TEST,
        64,
    );
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("unsupported-source-unit-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .arg("--comptime")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run unsupported imported source unit test");
    // Revision 0.1 has no comptime function color: `unsupported_loop_is_diagnostic`
    // (a plain `fn`) fails the static comptime-legality check because its
    // transitive call closure reaches `unsupported_loop`'s unconditional
    // `loop:`, which the static checker never accepts (loops are in its
    // explicit unsupported set); it also fails the runtime-shape checker's
    // own, unrelated check for the same reason (loops are not part of its
    // supported subset either). This fixture has exactly one test
    // candidate, so an explicit `--comptime` selection has nothing else to
    // fall back to: it fails closed with the comptime checker's own
    // `semantic-comptime-operation-not-implemented` diagnostic (the more
    // specific, correct explanation, carrying the call-stack trace back
    // through `app/math_test.wr` to the unsupported loop) rather than the
    // runtime shape checker's generic one.
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 unsupported-operation diagnostic");
    assert!(
        stderr.contains("error[semantic-comptime-operation-not-implemented]"),
        "{stderr}"
    );
    assert!(
        stderr.contains("app/math.wr:"),
        "the rejected loop must be diagnosed in the imported production callee: {stderr}"
    );
    assert!(
        stderr.contains("comptime call to `app.math.unsupported_loop` entered here"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "this comptime operation is not yet implemented by the production semantic analyzer"
        ),
        "{stderr}"
    );
    assert!(
        !output_directory.exists(),
        "rejected discovery must not publish a misleading test report"
    );
}

#[test]
fn real_imported_source_unit_cancellation_stops_before_partial_publication() {
    let directory = TestDirectory::new();
    let toolchain = install_in_process_toolchain(&directory);

    let (shallow, shallow_polls, shallow_finished) =
        run_source_unit_driver_with_semantic_cancellation(
            &directory,
            &toolchain,
            SHALLOW_CANCELLATION_SOURCE_UNIT_TEST,
            "shallow-cancellation-calibration-output",
            None,
        );
    assert!(shallow.is_ok(), "shallow calibration failed: {shallow:?}");
    assert!(shallow_finished);

    let (deep, deep_polls, deep_finished) = run_source_unit_driver_with_semantic_cancellation(
        &directory,
        &toolchain,
        DEEP_CANCELLATION_SOURCE_UNIT_TEST,
        "deep-cancellation-calibration-output",
        None,
    );
    assert!(deep.is_ok(), "deep calibration failed: {deep:?}");
    assert!(deep_finished);
    assert!(
        deep_polls > shallow_polls.saturating_add(24),
        "nested source evaluation must add observable cancellation polls: shallow={shallow_polls}, deep={deep_polls}"
    );

    let cancel_at = shallow_polls
        .checked_add(1)
        .expect("bounded cancellation threshold");
    let cancelled_output = directory.root.join("cancelled-source-unit-output");
    let (cancelled, cancelled_polls, cancelled_finished) =
        run_source_unit_driver_with_semantic_cancellation(
            &directory,
            &toolchain,
            DEEP_CANCELLATION_SOURCE_UNIT_TEST,
            "cancelled-source-unit-output",
            Some(cancel_at),
        );
    assert!(matches!(cancelled, Err(DriverError::Cancelled)));
    assert_eq!(cancelled_polls, cancel_at);
    assert!(
        !cancelled_finished,
        "cancellation must stop the semantic phase rather than a later publication phase"
    );
    assert!(
        !cancelled_output.exists(),
        "cancelled source-unit evaluation must not publish a partial output directory"
    );
}

#[test]
fn public_failed_comptime_test_publishes_report_and_returns_failure_status() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, FAILING_COMPTIME_TEST_SOURCE);
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("failed-test-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .arg("--comptime")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public failing comptime test");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"test failed\n");
    assert!(
        fs::metadata(output_directory.join("test-report.bin"))
            .expect("published failed test report")
            .len()
            > 0
    );
}

#[test]
fn public_integration_test_turns_pre_image_backend_failure_into_a_failed_report() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, INTEGRATION_TEST_SOURCE);
    let toolchain = install_toolchain(&directory);
    let output_directory = directory.root.join("compile-failure-output");
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("test")
        .arg(workspace.join("wrela.toml"))
        .arg("bootstrap")
        .arg(&output_directory)
        .arg("--integration")
        .env("WRELA_TOOLCHAIN_ROOT", &toolchain)
        .output()
        .expect("run public integration test with unavailable backend process");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"test failed\n");
    let report_bytes = fs::read(output_directory.join("test-report.bin"))
        .expect("published compile-failure report");
    let report_limit = u64::try_from(report_bytes.len()).expect("report length fits u64");
    let report = CanonicalTestReportCodec
        .decode(&report_bytes, report_limit, &never_cancelled)
        .expect("published report decodes canonically");
    let [image] = report.images.as_slice() else {
        panic!("integration selection must produce one image-group result");
    };
    assert!(image.cases.is_empty());
    assert!(image.events.is_empty());
    assert!(matches!(
        image.infrastructure_failure.as_ref(),
        Some(ModelTestOutcome::Failed {
            phase: FailurePhase::Compile,
            ..
        })
    ));
    assert!(image.evidence.image_digest.is_none());
    assert!(image.evidence.emulator_digest.is_none());
    assert!(image.evidence.command_digest.is_none());
    assert!(image.evidence.event_stream_digest.is_none());
    assert!(image.evidence.exit_code.is_none());
    assert!(
        fs::read_dir(&output_directory)
            .expect("compile-failure output directory")
            .all(|entry| entry
                .expect("compile-failure output entry")
                .path()
                .extension()
                .is_none_or(|extension| extension != "efi")),
        "a backend failure before linking must not publish a runnable image"
    );
}

#[test]
fn invalid_invocations_are_exit_two_and_bound_hostile_argument_rendering() {
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("x".repeat(4096))
        .output()
        .expect("run public wrela binary with an unknown command");

    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr.len() < 4096,
        "usage output must remain bounded"
    );
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 usage output");
    assert!(stderr.contains("unknown command"), "{stderr}");
    assert!(stderr.contains('…'), "{stderr}");
    assert!(stderr.contains("EXIT STATUS:"), "{stderr}");

    let unsupported_target = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .args([
            "check",
            "wrela.toml",
            "bootstrap",
            "--target",
            "x86_64-hosted",
        ])
        .output()
        .expect("run public wrela binary with an unsupported target");
    assert_eq!(unsupported_target.status.code(), Some(EXIT_USAGE));
    assert!(unsupported_target.stdout.is_empty());
    assert!(
        String::from_utf8(unsupported_target.stderr)
            .expect("UTF-8 target error")
            .contains("revision 0.1 supports only `aarch64-qemu-virt-uefi`")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_public_arguments_are_exit_two_usage_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .expect("run public wrela binary with a non-UTF-8 argument");

    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 usage output");
    assert!(
        stderr.contains("command arguments must be valid UTF-8"),
        "{stderr}"
    );
}

fn run_public_doctor(toolchain: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("doctor")
        .env("WRELA_TOOLCHAIN_ROOT", toolchain)
        .output()
        .expect("run public doctor command")
}

fn assert_public_doctor_integrity_failure(output: &std::process::Output, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(EXIT_UNSUCCESSFUL),
        "{label} unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "{label} printed a healthy table: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.starts_with(b"error: "),
        "{label} did not use the stable error channel: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.len() <= 128 * 1024,
        "{label} produced unbounded diagnostic output"
    );
}

#[test]
fn public_doctor_reports_missing_components_and_exits_unsuccessfully() {
    let directory = TestDirectory::new();
    let toolchain = directory.root.join("empty-toolchain");
    fs::create_dir(&toolchain).expect("empty toolchain root");
    let toolchain = fs::canonicalize(toolchain).expect("canonical toolchain root");

    let output = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("doctor")
        .env("WRELA_TOOLCHAIN_ROOT", toolchain)
        .output()
        .expect("run public doctor command");

    assert_eq!(output.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 doctor output");
    assert!(stdout.contains("missing"), "{stdout}");
}

#[test]
fn public_doctor_verifies_a_complete_installed_toolchain() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain(&directory);

    let output = run_public_doctor(&toolchain);

    assert_eq!(output.status.code(), Some(EXIT_SUCCESS));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 doctor output");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(
        lines.iter().all(|line| line.trim_start().starts_with("ok")),
        "{stdout}"
    );
}

#[test]
fn public_doctor_rejects_mutated_installed_content_while_every_path_exists() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain(&directory);
    let cases = [
        ("backend", toolchain.join(backend_path())),
        (
            "standard library source",
            toolchain.join("share/wrela/std/wrela-core-0.1/src/image.wr"),
        ),
        (
            "runtime object",
            toolchain.join(
                "share/wrela/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
            ),
        ),
        (
            "toolchain manifest",
            toolchain.join("share/wrela/toolchain.toml"),
        ),
    ];

    for (label, path) in cases {
        let original = fs::read(&path).unwrap_or_else(|error| panic!("read {label}: {error}"));
        assert!(!original.is_empty(), "{label} fixture must be nonempty");
        let mut mutated = original.clone();
        mutated[0] ^= 1;
        fs::write(&path, mutated).unwrap_or_else(|error| panic!("mutate {label}: {error}"));

        let output = run_public_doctor(&toolchain);
        assert_public_doctor_integrity_failure(&output, label);
        assert!(path.exists(), "{label} path must remain present");

        fs::write(&path, original).unwrap_or_else(|error| panic!("restore {label}: {error}"));
    }

    let restored = run_public_doctor(&toolchain);
    assert_eq!(
        restored.status.code(),
        Some(EXIT_SUCCESS),
        "restored fixture failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
}

#[test]
fn public_doctor_rejects_a_wrong_kind_component_instead_of_reporting_all_ok() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain(&directory);
    let backend = toolchain.join(backend_path());
    fs::remove_file(&backend).expect("remove backend file");
    fs::create_dir(&backend).expect("replace backend with directory");
    assert!(backend.exists());

    let output = run_public_doctor(&toolchain);

    assert_public_doctor_integrity_failure(&output, "wrong-kind backend");
}

#[cfg(unix)]
#[test]
fn public_doctor_rejects_a_symlinked_component_instead_of_reporting_all_ok() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain(&directory);
    let backend = toolchain.join(backend_path());
    let outside = directory.write("outside-backend", BACKEND_BYTES);
    set_executable(&outside);
    fs::remove_file(&backend).expect("remove backend file");
    symlink(outside, &backend).expect("install backend symlink");
    assert!(backend.exists());

    let output = run_public_doctor(&toolchain);

    assert_public_doctor_integrity_failure(&output, "symlinked backend");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("toolchain path contains a symlink"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn public_doctor_binds_the_running_frontend_to_the_verified_installation() {
    let directory = TestDirectory::new();
    let toolchain = install_toolchain_with_frontend(&directory, b"different frontend bytes");

    let output = run_public_doctor(&toolchain);

    assert_public_doctor_integrity_failure(&output, "running frontend mismatch");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("differs from the verified toolchain frontend"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn local_doctor_preserves_exact_file_limits_and_cancellation() {
    let directory = TestDirectory::new();
    let toolchain = install_in_process_toolchain(&directory);
    let running_frontend = std::env::current_exe().expect("running doctor test executable");
    let exact_bytes = fs::metadata(running_frontend)
        .expect("running frontend metadata")
        .len();
    assert!(exact_bytes > 1);

    let mut exact_limits = LocalToolchainVerificationLimits::standard();
    exact_limits.single_file_bytes = exact_bytes;
    let driver = LocalDoctorDriver::new(wrela_toolchain::Toolchain::at(&toolchain), exact_limits)
        .expect("compose exact-limit doctor");
    let polls = Cell::new(0_u64);
    let counting = || {
        polls.set(polls.get().checked_add(1).expect("bounded doctor polls"));
        false
    };
    let exact = driver
        .execute(
            &DriverCommand::Doctor,
            &SemanticPhaseEvents::default(),
            &counting,
        )
        .expect("exact single-file bound");
    let wrela_driver::CommandOutput::Doctor(exact) = exact else {
        panic!("doctor driver returned the wrong command output");
    };
    assert!(exact.is_healthy());
    let successful_polls = polls.get();
    assert!(successful_polls > 8, "verification did not poll deeply");

    let mut over_bound_limits = exact_limits;
    over_bound_limits.single_file_bytes = exact_bytes - 1;
    let over_bound = LocalDoctorDriver::new(
        wrela_toolchain::Toolchain::at(&toolchain),
        over_bound_limits,
    )
    .expect("compose over-bound doctor")
    .execute(
        &DriverCommand::Doctor,
        &SemanticPhaseEvents::default(),
        &never_cancelled,
    );
    assert!(matches!(
        over_bound,
        Err(DriverError::Toolchain(message))
            if message.contains("single-file bytes limit")
    ));

    let cancel_at = successful_polls / 2;
    let cancelled_polls = Cell::new(0_u64);
    let cancel_mid_verification = || {
        let next = cancelled_polls
            .get()
            .checked_add(1)
            .expect("bounded cancelled doctor polls");
        cancelled_polls.set(next);
        next >= cancel_at
    };
    let cancelled = driver.execute(
        &DriverCommand::Doctor,
        &SemanticPhaseEvents::default(),
        &cancel_mid_verification,
    );
    assert!(matches!(cancelled, Err(DriverError::Cancelled)));
    assert_eq!(cancelled_polls.get(), cancel_at);
}

#[test]
fn public_format_check_and_write_use_real_formatter_outcomes() {
    let directory = TestDirectory::new();
    let workspace = install_workspace(&directory, UNFORMATTED_APPLICATION_SOURCE);
    let manifest = workspace.join("wrela.toml");
    let source = workspace.join("src/bootstrap/image.wr");
    let original = fs::read(&source).expect("unformatted source");

    let check = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("format")
        .arg("--check")
        .arg(&manifest)
        .arg(&source)
        .output()
        .expect("run public format check");
    assert_eq!(check.status.code(), Some(EXIT_UNSUCCESSFUL));
    assert!(check.stderr.is_empty());
    assert_eq!(check.stdout, b"1 file(s) would change\n");
    assert_eq!(fs::read(&source).expect("source after check"), original);

    let write = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("format")
        .arg(&manifest)
        .arg(&source)
        .output()
        .expect("run public formatter");
    assert_eq!(write.status.code(), Some(EXIT_SUCCESS));
    assert!(write.stderr.is_empty());
    assert_eq!(write.stdout, b"1 file(s) formatted\n");
    assert_eq!(
        fs::read_to_string(&source).expect("formatted source"),
        "module bootstrap.image\n"
    );

    let clean_check = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("format")
        .arg(&manifest)
        .arg(&source)
        .arg("--check")
        .output()
        .expect("run clean public format check");
    assert_eq!(clean_check.status.code(), Some(EXIT_SUCCESS));
    assert!(clean_check.stderr.is_empty());
    assert_eq!(clean_check.stdout, b"0 file(s) would change\n");

    // Modules are derived from a walk of `source_root`, not declared, so a
    // file *inside* `source_root` is always a legitimate formatting target.
    // Only a file outside `source_root` remains an invalid selection.
    let undeclared = directory.write("workspace/undeclared.wr", b"module undeclared\n");
    let invalid = Command::new(env!("CARGO_BIN_EXE_wrela"))
        .arg("format")
        .arg("--check")
        .arg(&manifest)
        .arg(undeclared)
        .output()
        .expect("run invalid public format selection");
    assert_eq!(invalid.status.code(), Some(EXIT_USAGE));
    assert!(invalid.stdout.is_empty());
    let stderr = String::from_utf8(invalid.stderr).expect("UTF-8 invalid-command output");
    assert!(stderr.contains("error: invalid command:"), "{stderr}");
    assert!(!stderr.contains("USAGE:"), "{stderr}");
}

fn install_workspace(directory: &TestDirectory, application_source: &[u8]) -> PathBuf {
    install_workspace_package(
        directory,
        APPLICATION_MANIFEST,
        &[("bootstrap/image.wr", application_source)],
    )
}

fn install_source_unit_workspace(
    directory: &TestDirectory,
    production_source: &[u8],
    test_source: &[u8],
    comptime_call_depth: u32,
) -> PathBuf {
    install_source_unit_workspace_with_limits(
        directory,
        production_source,
        test_source,
        4096,
        1_048_576,
        comptime_call_depth,
    )
}

fn install_source_unit_workspace_with_limits(
    directory: &TestDirectory,
    production_source: &[u8],
    test_source: &[u8],
    comptime_steps: u64,
    comptime_memory_bytes: u64,
    comptime_call_depth: u32,
) -> PathBuf {
    let manifest = source_unit_manifest(comptime_steps, comptime_memory_bytes, comptime_call_depth);
    install_workspace_package(
        directory,
        &manifest,
        &[
            ("app/image.wr", SOURCE_UNIT_IMAGE),
            ("app/math.wr", production_source),
            ("app/math_test.wr", test_source),
        ],
    )
}

fn install_workspace_package(
    directory: &TestDirectory,
    application_manifest: &[u8],
    sources: &[(&str, &[u8])],
) -> PathBuf {
    let workspace = directory.root.join("workspace");
    directory.write("workspace/wrela.toml", application_manifest);
    for (path, bytes) in sources {
        directory.write(&format!("workspace/src/{path}"), bytes);
    }
    // There is no lockfile: the reserved `core` alias always resolves
    // against the installed toolchain's own standard-library index
    // (`docs/language/02-source-language.md` §2.1), so nothing else needs
    // recording here.
    workspace
}

fn install_toolchain(directory: &TestDirectory) -> PathBuf {
    let frontend_bytes = fs::read(env!("CARGO_BIN_EXE_wrela")).expect("read wrela binary");
    install_toolchain_with_frontend(directory, &frontend_bytes)
}

fn install_in_process_toolchain(directory: &TestDirectory) -> PathBuf {
    let executable = std::env::current_exe().expect("current CLI integration-test executable");
    let frontend_bytes = fs::read(executable).expect("read CLI integration-test executable");
    install_toolchain_with_frontend(directory, &frontend_bytes)
}

fn install_toolchain_with_frontend(directory: &TestDirectory, frontend_bytes: &[u8]) -> PathBuf {
    let root = directory.root.join("toolchain");
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/wrela.toml",
        CORE_MANIFEST,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/image.wr",
        CORE_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/ops.wr",
        CORE_OPS_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/result.wr",
        CORE_RESULT_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/time.wr",
        CORE_TIME_SOURCE,
    );

    let frontend = directory.write(&format!("toolchain/{}", frontend_path()), frontend_bytes);
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
        tree_record("wrela-core-0.1/src/ops.wr", CORE_OPS_SOURCE),
        tree_record("wrela-core-0.1/src/result.wr", CORE_RESULT_SOURCE),
        tree_record("wrela-core-0.1/src/time.wr", CORE_TIME_SOURCE),
        tree_record("wrela-core-0.1/wrela.toml", CORE_MANIFEST),
    ]);
    let target = tree_measurement(&[
        tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
        tree_record("target.toml", TARGET_MANIFEST),
    ]);
    let core_manifest = CanonicalPackageCodec::new()
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("core manifest");
    let canonical_core_manifest = canonical_manifest_bytes(&core_manifest);
    let manifest = ToolchainManifest {
        schema: TOOLCHAIN_MANIFEST_SCHEMA,
        release: "0.1.0-cli-test".to_owned(),
        host: current_host_identity()
            .expect("supported compiler host")
            .to_owned(),
        llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
        compatibility: ToolchainCompatibility::current(),
        standard_library_packages: vec![ShippedStandardLibraryPackage {
            identity: package_identity_with_sources(
                &core_manifest,
                &canonical_core_manifest,
                &[
                    ("image.wr", CORE_SOURCE),
                    ("ops.wr", CORE_OPS_SOURCE),
                    ("result.wr", CORE_RESULT_SOURCE),
                    ("time.wr", CORE_TIME_SOURCE),
                ],
            ),
            locator: PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
            manifest_digest: HASHER.sha256(&canonical_core_manifest),
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
            path: ComponentPath::new("share/wrela/targets/aarch64-qemu-virt-uefi")
                .expect("target path"),
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
            ToolchainDecodeLimits::standard(),
            &never_cancelled,
        )
        .expect("canonical toolchain manifest");
    directory.write("toolchain/share/wrela/toolchain.toml", &manifest);
    root
}

/// Re-encode a decoded manifest to its canonical bytes. Checked-in fixture
/// manifests may declare only `[[profile]]` overrides and no `[[module]]`
/// block (modules are derived, not decoded), so they are not necessarily
/// byte-canonical themselves; every package content or manifest digest below
/// must bind the same canonical bytes the production loader computes and
/// hashes, never the raw checked-in TOML.
fn canonical_manifest_bytes(manifest: &PackageManifest) -> Vec<u8> {
    CanonicalPackageCodec::new()
        .canonical_manifest(manifest, manifest_limits(), &never_cancelled)
        .expect("canonical manifest")
}

fn package_identity_with_sources(
    manifest: &PackageManifest,
    canonical_bytes: &[u8],
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
        package_content_digest(canonical_bytes, &records, &HASHER, &never_cancelled)
            .expect("package content digest");
    PackageIdentity {
        name: PackageName::new(manifest.name.as_str()).expect("package name"),
        version: PackageVersion::new(manifest.version.as_str()).expect("package version"),
        source_digest,
    }
}

fn manifest_limits() -> ManifestCodecLimits {
    ManifestCodecLimits {
        bytes: 1024 * 1024,
        string_bytes: 1024 * 1024,
        modules: 16,
        dependencies: 16,
        profiles: 16,
        images: 16,
        image_tests: 16,
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
    .expect("tree measurement")
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

fn never_cancelled() -> bool {
    false
}
