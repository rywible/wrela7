#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use wrela_backend::{
    BackendDecodeRequest, BackendInputError, CanonicalBackendContentHasher, decode_and_verify,
};
use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_compiler::{
    AnalysisFactAssembler, AnalysisFactRequest, BuildIntent, BuildPlanner, BuildPlanningError,
    BuildPlanningRequest, CanonicalAnalysisFactAssembler, CanonicalBuildPlanner,
    FrontendInputError, FrontendWorkspace, FrontendWorkspaceRequest, LocalFrontendService,
    PipelineLimits, seal_build_plan,
};
use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer, LowerRequest as FlowLowerRequest};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, EncodeRequest, encode_and_verify};
use wrela_hir::{DeclarationId, ValidatedProgram};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{DependencyAlias, PackageIdentity, PackageLocator, PackageManifest};
use wrela_package_loader::{
    CanonicalPackageCodec, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher, LoadLimits,
    ManifestCodecLimits, PackageCodec, PackageContentKind, PackageContentRecord, SoftwareSha256,
    canonical_tree_digest, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
};
use wrela_syntax::ParseLimits;
use wrela_target::{
    CanonicalTargetPackageCodec, TargetDecodeLimits, TargetDecodeRequest, TargetPackage,
    decode_and_verify_target_package,
};
use wrela_toolchain::{
    CanonicalToolchainManifestCodec, ComponentKind, ComponentPath,
    LocalToolchainVerificationLimits, LocalToolchainVerifier, REQUIRED_LLVM_PROJECT_REVISION,
    ShippedComponent, ShippedStandardLibraryPackage, ShippedTarget, ShippedTargetFile,
    TOOLCHAIN_MANIFEST_SCHEMA, Toolchain, ToolchainCompatibility, ToolchainDecodeLimits,
    ToolchainManifest, ToolchainManifestCodec, VerifiedToolchain, current_host_identity,
};

const MAX_FIXTURE_FILE_BYTES: usize = 1024 * 1024;
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_OPTION_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/option.wr");
const CORE_PANIC_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/panic.wr");
const CORE_TIME_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/time.wr");
const APPLICATION_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/wrela.toml");
const APPLICATION_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/src/bootstrap/image.wr");
const SCALAR_APPLICATION_SOURCE: &[u8] = br#"module bootstrap.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="bootstrap", target=Target.aarch64_qemu_virt_uefi)

@test(runtime)
fn scalar_runtime():
    flag: bool = true
    n: u32 = 7
    inverted_flag: bool = not flag
    signed: i32 = 7
    negated: i32 = -signed
    joined: u32 = n
    if flag:
        if inverted_flag:
            joined = 11
        else:
            joined = 13
    else:
        joined = 17
    helper(joined)
    # `@test(runtime)` keeps this in the runtime/image tier.
    return

fn helper(x: u32) -> u32:
    added: u32 = x + 3
    wrapped_add: u32 = added +% 1
    subtracted: u32 = added - 1
    wrapped_subtract: u32 = subtracted -% 1
    multiplied: u32 = subtracted * 2
    wrapped_multiply: u32 = multiplied *% 2
    divided: u32 = multiplied / 2
    remainder: u32 = divided % 3
    anded: u32 = remainder & x
    ored: u32 = anded | x
    xored: u32 = ored ^ x
    shifted_left: u32 = xored << 1
    shifted_right: u32 = shifted_left >> 1
    bit_not: u32 = ~shifted_right
    equal_value: bool = bit_not == x
    not_equal_value: bool = bit_not != x
    less_value: bool = bit_not < x
    less_equal_value: bool = bit_not <= x
    greater_value: bool = bit_not > x
    greater_equal_value: bool = bit_not >= x
    widened: u64 = bit_not as u64
    return bit_not
"#;
const TARGET_MANIFEST: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
const RUNTIME_OBJECT: &[u8] = b"runtime-object";

static HASHER: SoftwareSha256 = SoftwareSha256;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureKind {
    Canonical,
    ScalarRuntimeTest,
    MissingCoreDependency,
    WrongCoreAlias,
}

#[derive(Debug)]
struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary base");
        for _ in 0..128 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "wrela-build-planner-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Self {
                        root: fs::canonicalize(root).expect("canonical test directory"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create test directory: {error}"),
            }
        }
        panic!("cannot allocate a unique test directory")
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        assert!(
            bytes.len() <= MAX_FIXTURE_FILE_BYTES,
            "fixture file exceeds its explicit write bound"
        );
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture file parent");
        }
        fs::write(&path, bytes).expect("bounded fixture write");
        path
    }

    fn create_directory(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(&path).expect("fixture directory");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct CanonicalPackage {
    manifest_bytes: Vec<u8>,
    sources: Vec<(&'static str, &'static [u8])>,
    identity: PackageIdentity,
    manifest_digest: Sha256Digest,
}

impl CanonicalPackage {
    fn from_manifest(manifest: PackageManifest, sources: &[(&'static str, &'static [u8])]) -> Self {
        let codec = CanonicalPackageCodec::new();
        let manifest_bytes = codec
            .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
            .expect("canonical package manifest");
        let mut source_records = sources
            .iter()
            .map(|(path, bytes)| PackageContentRecord {
                kind: PackageContentKind::Source,
                path,
                digest: HASHER.sha256(bytes),
            })
            .collect::<Vec<_>>();
        source_records.sort_by_key(|record| (record.kind, record.path));
        let source_digest =
            package_content_digest(&manifest_bytes, &source_records, &HASHER, &never_cancelled)
                .expect("canonical package content digest");
        let identity = PackageIdentity {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            source_digest,
        };
        let manifest_digest = HASHER.sha256(&manifest_bytes);
        Self {
            manifest_bytes,
            sources: sources.to_vec(),
            identity,
            manifest_digest,
        }
    }

    fn total_bytes(&self) -> u64 {
        self.sources.iter().fold(
            u64::try_from(self.manifest_bytes.len()).expect("fixture manifest byte count"),
            |total, (_, bytes)| {
                total
                    .checked_add(u64::try_from(bytes.len()).expect("fixture source byte count"))
                    .expect("fixture package byte count")
            },
        )
    }
}

#[derive(Debug)]
struct Fixture {
    _directory: TestDirectory,
    frontend: FrontendWorkspace,
    toolchain: VerifiedToolchain,
    target: TargetPackage,
    compiler_digest: Sha256Digest,
    standard_library_component_digest: Sha256Digest,
    core_package_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy)]
struct ToolchainMeasurements {
    compiler_digest: Sha256Digest,
    compiler_bytes: u64,
    backend_digest: Sha256Digest,
    backend_bytes: u64,
    standard_library_digest: Sha256Digest,
    standard_library_bytes: u64,
    target_digest: Sha256Digest,
    target_bytes: u64,
}

impl Fixture {
    fn new(kind: FixtureKind) -> Self {
        Self::try_new(kind).expect("real checked-in workspace and core package")
    }

    /// Unlike [`Self::new`], surfaces a workspace-load failure instead of
    /// panicking -- there is no lockfile, so a malformed `core` dependency
    /// declaration now fails during loading rather than during later build
    /// planning (see `planner_rejects_invalid_standard_library_selection_and_stale_identity`).
    fn try_new(kind: FixtureKind) -> Result<Self, FrontendInputError> {
        let directory = TestDirectory::new();
        let codec = CanonicalPackageCodec::new();
        let core_manifest = codec
            .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("checked-in core manifest");
        let core = CanonicalPackage::from_manifest(
            core_manifest,
            &[
                ("image.wr", CORE_SOURCE),
                ("ops.wr", CORE_OPS_SOURCE),
                ("result.wr", CORE_RESULT_SOURCE),
            ("option.wr", CORE_OPTION_SOURCE),
            ("panic.wr", CORE_PANIC_SOURCE),
                ("time.wr", CORE_TIME_SOURCE),
            ],
        );
        assert_eq!(core.manifest_bytes, CORE_MANIFEST);

        let mut application_manifest = codec
            .decode_manifest(APPLICATION_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("checked-in application manifest");
        match kind {
            FixtureKind::Canonical | FixtureKind::ScalarRuntimeTest => {}
            FixtureKind::MissingCoreDependency => application_manifest.dependencies.clear(),
            FixtureKind::WrongCoreAlias => {
                application_manifest.dependencies[0].alias =
                    DependencyAlias::new("foundation").expect("fixture dependency alias");
            }
        }
        let application_source = if kind == FixtureKind::ScalarRuntimeTest {
            SCALAR_APPLICATION_SOURCE
        } else {
            APPLICATION_SOURCE
        };
        let application = CanonicalPackage::from_manifest(
            application_manifest,
            &[("bootstrap/image.wr", application_source)],
        );
        if kind == FixtureKind::Canonical {
            assert_eq!(application.manifest_bytes, APPLICATION_MANIFEST);
        }

        // There is no lockfile: the reserved `core` alias always resolves
        // against the verified toolchain's own standard-library index
        // (`docs/language/02-source-language.md` §2.1), never a workspace-
        // relative override, so there is no separate locator to record here.
        let root_locator = PackageLocator::Workspace {
            path: ".".to_owned(),
        };

        directory.write("workspace/wrela.toml", &application.manifest_bytes);
        for (source_path, source_bytes) in &application.sources {
            directory.write(&format!("workspace/src/{source_path}"), source_bytes);
        }
        let toolchain_core_base = "toolchain/share/wrela/std/wrela-core-0.1";
        directory.write(
            &format!("{toolchain_core_base}/wrela.toml"),
            &core.manifest_bytes,
        );
        for (source_path, source_bytes) in &core.sources {
            directory.write(
                &format!("{toolchain_core_base}/src/{source_path}"),
                source_bytes,
            );
        }
        directory.create_directory("toolchain/share/wrela/std");

        let target_measurement = canonical_tree_digest(
            &[
                tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
                tree_record("target.toml", TARGET_MANIFEST),
            ],
            &HASHER,
            CanonicalTreeLimits::standard(),
            &never_cancelled,
        )
        .expect("canonical target directory measurement");
        let target = decode_target(target_measurement.digest);
        let compiler_bytes = b"wrela frontend integration fixture";
        let backend_bytes = b"wrela backend integration fixture";
        let compiler_digest = HASHER.sha256(compiler_bytes);
        let standard_library_measurement = canonical_tree_digest(
            &[
                tree_record("wrela-core-0.1/src/image.wr", CORE_SOURCE),
                tree_record("wrela-core-0.1/src/ops.wr", CORE_OPS_SOURCE),
                tree_record("wrela-core-0.1/src/option.wr", CORE_OPTION_SOURCE),
                tree_record("wrela-core-0.1/src/panic.wr", CORE_PANIC_SOURCE),
                tree_record("wrela-core-0.1/src/result.wr", CORE_RESULT_SOURCE),
                tree_record("wrela-core-0.1/src/time.wr", CORE_TIME_SOURCE),
                tree_record("wrela-core-0.1/wrela.toml", &core.manifest_bytes),
            ],
            &HASHER,
            CanonicalTreeLimits::standard(),
            &never_cancelled,
        )
        .expect("canonical standard-library directory measurement");
        assert_eq!(
            standard_library_measurement.content_bytes,
            core.total_bytes()
        );
        let standard_library_component_digest = standard_library_measurement.digest;
        assert_ne!(
            standard_library_component_digest,
            core.identity.source_digest
        );

        let frontend_path = directory.write(
            &format!("toolchain/{}", frontend_component_path()),
            compiler_bytes,
        );
        let backend_path = directory.write(
            &format!("toolchain/{}", backend_component_path()),
            backend_bytes,
        );
        set_executable(&frontend_path);
        set_executable(&backend_path);
        directory.write(
            "toolchain/share/wrela/targets/aarch64-qemu-virt-uefi/target.toml",
            TARGET_MANIFEST,
        );
        directory.write(
            "toolchain/share/wrela/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
            RUNTIME_OBJECT,
        );

        let indexed_core = ShippedStandardLibraryPackage {
            identity: core.identity.clone(),
            locator: PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
            manifest_digest: core.manifest_digest,
        };
        let toolchain = verified_toolchain(
            &directory,
            ToolchainMeasurements {
                compiler_digest,
                compiler_bytes: u64::try_from(compiler_bytes.len()).expect("frontend byte count"),
                backend_digest: HASHER.sha256(backend_bytes),
                backend_bytes: u64::try_from(backend_bytes.len()).expect("backend byte count"),
                standard_library_digest: standard_library_component_digest,
                standard_library_bytes: standard_library_measurement.content_bytes,
                target_digest: target_measurement.digest,
                target_bytes: target_measurement.content_bytes,
            },
            indexed_core,
        );
        let workspace_root = directory.root.join("workspace");
        let frontend = LocalFrontendService::new_with_toolchain(&workspace_root, &toolchain)
            .expect("frontend backed by a verified toolchain")
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )?;
        assert!(
            frontend
                .parsed_modules()
                .iter()
                .all(|output| output.diagnostics().is_empty())
        );

        Ok(Self {
            _directory: directory,
            frontend,
            toolchain,
            target,
            compiler_digest,
            standard_library_component_digest,
            core_package_digest: core.identity.source_digest,
        })
    }

    fn request<'a>(
        &'a self,
        target: &'a TargetPackage,
        compiler_digest: Sha256Digest,
    ) -> BuildPlanningRequest<'a> {
        let manifest = self.frontend.workspace().root_manifest();
        BuildPlanningRequest {
            workspace: self.frontend.workspace(),
            image: manifest.images.first().expect("fixture image"),
            profile: manifest.profiles.first().expect("fixture profile"),
            intent: BuildIntent::Build,
            target,
            toolchain: &self.toolchain,
            hasher: &HASHER,
            compiler_digest,
        }
    }
}

fn tree_record<'a>(path: &'a str, bytes: &[u8]) -> CanonicalTreeRecord<'a> {
    CanonicalTreeRecord {
        path,
        bytes: u64::try_from(bytes.len()).expect("tree record byte count"),
        digest: HASHER.sha256(bytes),
    }
}

fn decode_target(digest: Sha256Digest) -> TargetPackage {
    decode_and_verify_target_package(
        &CanonicalTargetPackageCodec::new(),
        TargetDecodeRequest {
            toml_bytes: TARGET_MANIFEST,
            expected_identity: &TargetIdentity::aarch64_qemu_virt_uefi(),
            verified_digest: digest,
            limits: TargetDecodeLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("canonical checked-in target package")
}

fn verified_toolchain(
    directory: &TestDirectory,
    measurements: ToolchainMeasurements,
    standard_library_package: ShippedStandardLibraryPackage,
) -> VerifiedToolchain {
    let compatibility = ToolchainCompatibility::current();
    let components = vec![
        ShippedComponent {
            kind: ComponentKind::Frontend,
            path: ComponentPath::new(frontend_component_path()).expect("frontend component path"),
            digest: measurements.compiler_digest,
            bytes: measurements.compiler_bytes,
        },
        ShippedComponent {
            kind: ComponentKind::Backend,
            path: ComponentPath::new(backend_component_path()).expect("backend component path"),
            digest: measurements.backend_digest,
            bytes: measurements.backend_bytes,
        },
        ShippedComponent {
            kind: ComponentKind::StandardLibrary,
            path: ComponentPath::new("share/wrela/std").expect("standard-library component path"),
            digest: measurements.standard_library_digest,
            bytes: measurements.standard_library_bytes,
        },
    ];
    let target_files = vec![shipped_target_file(
        "runtime/wrela-runtime-aarch64.obj",
        RUNTIME_OBJECT,
    )];
    let targets = vec![ShippedTarget {
        identity: TargetIdentity::aarch64_qemu_virt_uefi(),
        path: ComponentPath::new("share/wrela/targets/aarch64-qemu-virt-uefi")
            .expect("target component path"),
        digest: measurements.target_digest,
        bytes: measurements.target_bytes,
        files: target_files,
    }];
    let manifest = ToolchainManifest {
        schema: TOOLCHAIN_MANIFEST_SCHEMA,
        release: "0.1.0".to_owned(),
        host: current_host_identity()
            .expect("supported revision-0.1 test host")
            .to_owned(),
        llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
        compatibility: compatibility.clone(),
        components,
        standard_library_packages: vec![standard_library_package],
        targets,
    };
    assert_eq!(
        manifest
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::StandardLibrary)
            .expect("standard-library measurement")
            .bytes,
        measurements.standard_library_bytes
    );
    assert_eq!(manifest.targets[0].bytes, measurements.target_bytes);
    let codec = CanonicalToolchainManifestCodec::new();
    let manifest_bytes = codec
        .encode_canonical(
            &manifest,
            ToolchainDecodeLimits::standard(),
            &never_cancelled,
        )
        .expect("canonical toolchain manifest encoding");
    directory.write("toolchain/share/wrela/toolchain.toml", &manifest_bytes);
    let verified = LocalToolchainVerifier::new(Toolchain::at(directory.root.join("toolchain")))
        .verify(
            &TargetIdentity::aarch64_qemu_virt_uefi(),
            LocalToolchainVerificationLimits::standard(),
            &never_cancelled,
        )
        .expect("complete content-verified fixture toolchain");
    assert_eq!(verified.manifest(), &manifest);
    verified.toolchain().clone()
}

fn shipped_target_file(path: &str, bytes: &[u8]) -> ShippedTargetFile {
    ShippedTargetFile {
        path: ComponentPath::new(path).expect("target file path"),
        digest: HASHER.sha256(bytes),
        bytes: u64::try_from(bytes.len()).expect("target file byte count"),
    }
}

#[cfg(windows)]
const fn frontend_component_path() -> &'static str {
    "bin/wrela.exe"
}

#[cfg(not(windows))]
const fn frontend_component_path() -> &'static str {
    "bin/wrela"
}

#[cfg(windows)]
const fn backend_component_path() -> &'static str {
    "libexec/wrela/wrela-backend.exe"
}

#[cfg(not(windows))]
const fn backend_component_path() -> &'static str {
    "libexec/wrela/wrela-backend"
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    let mut permissions = fs::metadata(path)
        .expect("executable fixture metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("executable fixture permissions");
}

#[cfg(not(unix))]
fn set_executable(_path: &std::path::Path) {}

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

fn load_limits() -> LoadLimits {
    LoadLimits {
        packages: 16,
        sources: 16,
        manifest_bytes_per_package: MAX_FIXTURE_FILE_BYTES as u64,
        manifest_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        source_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        scenarios: 16,
        scenario_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        bytes_per_package: MAX_FIXTURE_FILE_BYTES as u64,
    }
}

fn never_cancelled() -> bool {
    false
}

fn assert_debug_occurrences(debug: &str, needle: &str, expected: usize) {
    assert_eq!(
        debug.matches(needle).count(),
        expected,
        "expected {expected} occurrences of `{needle}` in:\n{debug}"
    );
}

fn plan_fixture(fixture: &Fixture) -> wrela_compiler::PlannedBuild {
    CanonicalBuildPlanner::new()
        .plan(
            fixture.request(&fixture.target, fixture.compiler_digest),
            &never_cancelled,
        )
        .expect("canonical build plan")
}

fn lower_fixture_hir(fixture: &Fixture) -> (Arc<ValidatedProgram>, DeclarationId) {
    let parsed_files = fixture
        .frontend
        .parsed_modules()
        .iter()
        .map(|output| output.parsed().clone())
        .collect::<Vec<_>>();
    let packages = Arc::new(fixture.frontend.workspace().graph().clone());
    let changes = ChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages,
                source_graph_digest: fixture.frontend.workspace().source_graph_digest(),
                parsed_files: &parsed_files,
                sources: fixture.frontend.workspace().sources(),
                changes: &changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("checked-in packages lower to sealed HIR");
    assert!(hir_output.diagnostics().is_empty());
    let image = fixture
        .frontend
        .workspace()
        .root_manifest()
        .images
        .first()
        .expect("fixture image");
    let entry = hir_output
        .lowered()
        .image_entry(image)
        .expect("manifest image entry resolves")
        .declaration;
    (Arc::new(hir_output.lowered().program().clone()), entry)
}

#[test]
fn checked_in_workspace_reaches_the_canonical_backend_handoff() {
    let fixture = Fixture::new(FixtureKind::Canonical);
    let planned = plan_fixture(&fixture);
    let graph = fixture.frontend.workspace().graph();
    let expected_core_package = graph
        .package(graph.root())
        .expect("root graph package")
        .dependencies
        .iter()
        .find(|dependency| dependency.alias.as_str() == "core")
        .expect("reserved root dependency")
        .package;
    assert_eq!(planned.standard_library_package(), expected_core_package);
    assert_eq!(
        planned.configuration().identity().standard_library,
        fixture.standard_library_component_digest
    );
    assert_ne!(
        planned.configuration().identity().standard_library,
        fixture.core_package_digest
    );

    let (hir, entry) = lower_fixture_hir(&fixture);
    let image = fixture
        .frontend
        .workspace()
        .root_manifest()
        .images
        .first()
        .expect("fixture image");
    let semantic_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let semantic_output = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: planned.standard_library_package(),
                target: fixture.target.semantic(),
                build: planned.configuration(),
                mode: AnalysisMode::Image {
                    name: &image.name,
                    entry,
                },
                changes: &semantic_changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("real semantic analysis");
    assert!(semantic_output.diagnostics().is_empty());
    let (analyzed, diagnostics) = semantic_output.into_parts();
    assert!(diagnostics.is_empty());
    let analyzed = analyzed.expect("sealed semantic image");
    assert_eq!(analyzed.facts().build, *planned.configuration().identity());

    let semantic_wir = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("minimum image lowers to semantic WIR");
    assert_eq!(semantic_wir.report().semantic_types, 1);
    assert_eq!(semantic_wir.report().function_instances, 1);
    assert_eq!(
        semantic_wir.wir().as_wir().version,
        ToolchainCompatibility::current().semantic_wir
    );
    assert_eq!(
        semantic_wir.wir().as_wir().build,
        *planned.configuration().identity()
    );
    assert_eq!(semantic_wir.wir().as_wir().name, "bootstrap");

    let limits = PipelineLimits::standard();
    let (semantic_wir, _) = semantic_wir.into_parts();
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: limits.flow_lower,
            },
            &never_cancelled,
        )
        .expect("real SemanticWir lowers to FlowWir");
    assert!(flow_output.diagnostics().is_empty());
    let (flow_wir, _, _) = flow_output.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: limits.flow_codec,
        },
        &never_cancelled,
    )
    .expect("real FlowWir encodes canonically");
    let flow_digest = HASHER.sha256(encoded.bytes());
    let decoded = decode_and_verify(
        &CanonicalFlowWirCodec,
        &CanonicalBackendContentHasher::new(),
        BackendDecodeRequest {
            bytes: encoded.bytes(),
            expected_digest: flow_digest,
            target: &fixture.target,
            build: planned.configuration(),
            limits: limits.backend.codec,
        },
        &never_cancelled,
    )
    .expect("private backend accepts real frontend FlowWir");
    assert_eq!(decoded, flow_wir);
}

#[test]
fn source_scalar_runtime_test_reaches_the_private_backend_boundary() {
    let fixture = Fixture::new(FixtureKind::ScalarRuntimeTest);
    let planned = plan_fixture(&fixture);
    let (hir, image_entry) = lower_fixture_hir(&fixture);
    let image = fixture
        .frontend
        .workspace()
        .root_manifest()
        .images
        .first()
        .expect("fixture image");
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let discovery_output = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&hir),
                standard_library_package: planned.standard_library_package(),
                target: fixture.target.semantic(),
                build: planned.configuration(),
                mode: AnalysisMode::DiscoverTests {
                    image_name: &image.name,
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("real source test discovery");
    assert!(discovery_output.diagnostics().is_empty());
    let plan = discovery_output
        .successful()
        .and_then(|analyzed| analyzed.facts().test_plan.as_ref())
        .expect("generated scalar test plan")
        .clone();
    assert_eq!(plan.image_groups().len(), 1);
    assert_eq!(plan.image_groups()[0].tests.len(), 1);
    let group = plan.image_groups()[0].id;

    let compilation_output = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: planned.standard_library_package(),
                target: fixture.target.semantic(),
                build: planned.configuration(),
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group,
                    declared_entry: None,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("real scalar test-group compilation");
    assert!(compilation_output.diagnostics().is_empty());
    let (analyzed, diagnostics) = compilation_output.into_parts();
    assert!(diagnostics.is_empty());
    let analyzed = analyzed.expect("sealed scalar test-group image");
    assert_eq!(analyzed.facts().functions.len(), 3);

    let limits = PipelineLimits::standard();
    let analysis = CanonicalAnalysisFactAssembler::new()
        .assemble(
            AnalysisFactRequest {
                analysis: &analyzed,
                limits: limits.analysis_facts,
            },
            &never_cancelled,
        )
        .expect("real scalar semantic facts project for backend reporting");
    assert_eq!(analysis.as_facts().reachable_declarations, 2);
    assert_eq!(analysis.as_facts().monomorphized_instantiations, 3);
    assert_eq!(analysis.as_facts().resolved_interface_calls, 0);
    assert_eq!(analysis.as_facts().proofs.len(), 7);
    assert_eq!(analysis.as_facts().work.len(), 3);
    assert_eq!(
        analysis.as_facts().compiled_test_group,
        analyzed.facts().compiled_test_group
    );

    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: limits.semantic_lower,
            },
            &never_cancelled,
        )
        .expect("scalar test group lowers to SemanticWir");
    let (semantic_wir, semantic_report) = semantic_output.into_parts();
    assert_eq!(semantic_report.function_instances, 3);
    let semantic_debug = format!("{:?}", semantic_wir.as_wir());
    assert_debug_occurrences(&semantic_debug, "operator: Negate", 1);
    assert_debug_occurrences(&semantic_debug, "operator: BoolNot", 1);
    assert_debug_occurrences(&semantic_debug, "operator: BitNot", 1);
    assert_debug_occurrences(&semantic_debug, "arithmetic: Checked", 19);
    assert_debug_occurrences(&semantic_debug, "arithmetic: Wrapping", 3);
    assert_debug_occurrences(&semantic_debug, "checked: true", 1);
    assert_debug_occurrences(&semantic_debug, "If {", 2);
    assert_debug_occurrences(&semantic_debug, "Yield([ValueId(", 4);

    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: limits.flow_lower,
            },
            &never_cancelled,
        )
        .expect("scalar SemanticWir lowers to FlowWir");
    assert!(flow_output.diagnostics().is_empty());
    let (flow_wir, flow_report, _) = flow_output.into_parts();
    assert_eq!(flow_report.source_functions, 3);
    assert_eq!(flow_wir.as_wir().functions.len(), 3);
    let flow_debug = format!("{:?}", flow_wir.as_wir());
    for operator in [
        "AddChecked",
        "AddWrapping",
        "SubChecked",
        "SubWrapping",
        "MulChecked",
        "MulWrapping",
        "DivChecked",
        "RemChecked",
        "BitAnd",
        "BitOr",
        "BitXor",
        "ShiftLeftChecked",
        "ShiftRightChecked",
        "Equal",
        "NotEqual",
        "Less",
        "LessEqual",
        "Greater",
        "GreaterEqual",
    ] {
        let expected = 1;
        assert_debug_occurrences(&flow_debug, &format!("op: {operator},"), expected);
    }
    assert_debug_occurrences(&flow_debug, "op: Negate,", 1);
    assert_debug_occurrences(&flow_debug, "op: BoolNot,", 1);
    assert_debug_occurrences(&flow_debug, "op: BitNot,", 1);
    assert_debug_occurrences(&flow_debug, "mode: Checked", 1);
    let scalar_test = &flow_wir.as_wir().functions[0];
    let join_blocks = scalar_test
        .blocks
        .iter()
        .filter(|block| !block.parameters.is_empty())
        .collect::<Vec<_>>();
    // Two single-value scalar `if`/nested-`if` joins.
    let scalar_joins = join_blocks
        .iter()
        .filter(|block| block.parameters.len() == 1)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(scalar_joins.len(), join_blocks.len(), "every join is a scalar join");
    assert_eq!(scalar_joins.len(), 2, "inner and outer scalar SSA joins");
    let join_blocks = scalar_joins;
    for join in &join_blocks {
        assert_eq!(join.parameters.len(), 1);
        let target = format!("target: {:?}", join.id);
        let incoming = scalar_test
            .blocks
            .iter()
            .filter(|block| format!("{:?}", block.terminator).contains(&target))
            .collect::<Vec<_>>();
        assert_eq!(incoming.len(), 2, "two exact incoming join edges");
        assert!(incoming.iter().all(|block| {
            let edge = format!("{:?}", block.terminator);
            edge.contains("arguments: [ValueId(")
        }));
    }
    let outer_join = join_blocks
        .iter()
        .find(|block| format!("{:?}", block.instructions).contains("Call {"))
        .expect("post-join helper call lives in the outer merge block");
    assert!(
        format!("{:?}", outer_join.instructions)
            .contains(&format!("arguments: [{:?}]", outer_join.parameters[0]))
    );
    assert_eq!(
        flow_wir.as_wir().source_summary.reachable_declarations,
        analysis.as_facts().reachable_declarations
    );
    assert_eq!(
        flow_wir
            .as_wir()
            .source_summary
            .monomorphized_instantiations,
        analysis.as_facts().monomorphized_instantiations
    );
    assert_eq!(
        flow_wir.as_wir().proofs.len(),
        analysis.as_facts().proofs.len()
    );

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: limits.flow_codec,
        },
        &never_cancelled,
    )
    .expect("scalar FlowWir encodes canonically");
    let flow_digest = HASHER.sha256(encoded.bytes());
    let backend_request = || BackendDecodeRequest {
        bytes: encoded.bytes(),
        expected_digest: flow_digest,
        target: &fixture.target,
        build: planned.configuration(),
        limits: limits.backend.codec,
    };
    let decoded = decode_and_verify(
        &CanonicalFlowWirCodec,
        &CanonicalBackendContentHasher::new(),
        backend_request(),
        &never_cancelled,
    )
    .expect("private backend accepts real scalar FlowWir");
    assert_eq!(decoded, flow_wir);
    assert!(matches!(
        decode_and_verify(
            &CanonicalFlowWirCodec,
            &CanonicalBackendContentHasher::new(),
            backend_request(),
            &|| true,
        ),
        Err(BackendInputError::Cancelled)
    ));
}

#[test]
fn planner_rejects_invalid_standard_library_selection_and_stale_identity() {
    // There is no lockfile: the reserved `core` alias is now a loader-level
    // precondition (`docs/language/02-source-language.md` §2.1), so a
    // malformed core dependency declaration fails closed during workspace
    // *loading* rather than reaching the build planner's own standard-
    // library-selection check at all. `selected_standard_library_package`
    // (in `wrela-compiler/src/lib.rs`) still guards a workspace assembled
    // some other way (e.g. `sealer_*` fixtures directly constructing a
    // `LoadedWorkspace`), so it remains live defense in depth.
    for kind in [
        FixtureKind::MissingCoreDependency,
        FixtureKind::WrongCoreAlias,
    ] {
        assert!(
            matches!(
                Fixture::try_new(kind),
                Err(FrontendInputError::Load(
                    wrela_package_loader::LoadError::Manifest(_)
                ))
            ),
            "fixture kind {kind:?} must fail closed during workspace loading"
        );
    }

    let fixture = Fixture::new(FixtureKind::Canonical);
    let stale_target = decode_target(HASHER.sha256(b"stale target package"));
    assert!(matches!(
        CanonicalBuildPlanner::new().plan(
            fixture.request(&stale_target, fixture.compiler_digest),
            &never_cancelled,
        ),
        Err(BuildPlanningError::Selection(_))
    ));
    assert!(matches!(
        CanonicalBuildPlanner::new().plan(
            fixture.request(&fixture.target, HASHER.sha256(b"different frontend")),
            &never_cancelled,
        ),
        Err(BuildPlanningError::Selection(_))
    ));
    assert_eq!(
        CanonicalBuildPlanner::new().plan(
            fixture.request(&fixture.target, fixture.compiler_digest),
            &|| true,
        ),
        Err(BuildPlanningError::Cancelled)
    );

    let planned = CanonicalBuildPlanner::new()
        .plan(
            fixture.request(&fixture.target, fixture.compiler_digest),
            &never_cancelled,
        )
        .expect("canonical build plan");
    let mut conflated = planned.configuration().as_configuration().clone();
    conflated.identity.standard_library = fixture.core_package_digest;
    assert!(matches!(
        seal_build_plan(
            &fixture.request(&fixture.target, fixture.compiler_digest),
            conflated,
            &never_cancelled,
        ),
        Err(BuildPlanningError::Selection(_))
    ));
}
