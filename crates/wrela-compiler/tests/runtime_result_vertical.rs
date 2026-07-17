#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use wrela_backend::{
    CodegenError, emit_prepared_object, llvm_backend_available,
    machine_wir::{MachineFunctionOrigin, MachineOperation, MachineTerminator, MachineTypeKind},
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, FlowOperation, FlowTypeKind,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits, Terminator,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir::DeclarationId;
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_link_efi::{CanonicalCoffObjectInspector, CoffObjectInspector, LinkLimits};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageLocator,
};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, LockfileCodecLimits, ManifestCodecLimits, PackageCodec,
    PackageContentKind, PackageContentRecord, SoftwareSha256, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, SemanticArgument, SemanticTypeKind as SemaTypeKind, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer, SemanticOperation, SemanticTypeKind,
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const WORKSPACE_MANIFEST: &[u8] = include_bytes!("../../../std/examples/runtime-result/wrela.toml");
const WORKSPACE_LOCKFILE: &[u8] = include_bytes!("../../../std/examples/runtime-result/wrela.lock");
const APPLICATION_SOURCE: &str =
    include_str!("../../../std/examples/runtime-result/src/runtime_result/image.wr");
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");
const IMAGE_NAME: &str = "runtime-result";
const SELECTORS: [(&str, usize); 2] = [
    ("result_ok_match_returns_payload", 2),
    ("result_bool_match_returns_payload", 1),
];
const TRY_SELECTORS: [&str; 2] = [
    "result_try_ok_yields_payload",
    "result_try_err_propagates_exact_error",
];

static HASHER: SoftwareSha256 = SoftwareSha256;
static OBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct SourceFixture {
    hir: Arc<wrela_hir::ValidatedProgram>,
    entry: DeclarationId,
    target: TargetPackage,
    build: wrela_build_model::ValidatedBuildConfiguration,
}

fn never_cancelled() -> bool {
    false
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

fn lockfile_limits() -> LockfileCodecLimits {
    LockfileCodecLimits {
        bytes: 1024 * 1024,
        string_bytes: 1024 * 1024,
        packages: 16,
        dependencies: 16,
    }
}

fn content_record<'a>(path: &'a str, source: &str) -> PackageContentRecord<'a> {
    PackageContentRecord {
        kind: PackageContentKind::Source,
        path,
        digest: HASHER.sha256(source.as_bytes()),
    }
}

fn add_source(sources: &mut SourceDatabase, path: &str, text: &str) -> FileId {
    sources
        .add(SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: HASHER.sha256(text.as_bytes()),
        })
        .expect("runtime-result source")
}

fn package_identities(
    application_source: &str,
    forged_result_source: Option<&str>,
    require_checked_lock: bool,
) -> (PackageIdentity, PackageIdentity) {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in runtime-result manifest");
    assert_eq!(
        codec
            .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
            .expect("canonical runtime-result manifest"),
        WORKSPACE_MANIFEST
    );
    assert_eq!(manifest.name.as_str(), IMAGE_NAME);
    assert_eq!(manifest.modules[0].module.dotted(), "runtime_result.image");
    let mut root_content = vec![content_record(
        "runtime_result/image.wr",
        application_source,
    )];
    if let Some(source) = forged_result_source {
        root_content.push(content_record("result.wr", source));
    }
    let root = PackageIdentity {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source_digest: package_content_digest(
            WORKSPACE_MANIFEST,
            &root_content,
            &HASHER,
            &never_cancelled,
        )
        .expect("runtime-result package identity"),
    };
    let core_manifest = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in core manifest");
    let core = PackageIdentity {
        name: core_manifest.name.clone(),
        version: core_manifest.version.clone(),
        source_digest: package_content_digest(
            CORE_MANIFEST,
            &[
                content_record("image.wr", CORE_IMAGE_SOURCE),
                content_record("result.wr", CORE_RESULT_SOURCE),
                content_record("time.wr", CORE_TIME_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("core package identity"),
    };
    if !require_checked_lock {
        return (root, core);
    }
    let lock = codec
        .decode_lockfile(WORKSPACE_LOCKFILE, lockfile_limits(), &never_cancelled)
        .expect("checked-in runtime-result lockfile");
    assert_eq!(
        codec
            .canonical_lockfile(&lock, lockfile_limits(), &never_cancelled)
            .expect("canonical runtime-result lockfile"),
        WORKSPACE_LOCKFILE
    );
    assert_eq!(lock.root, root);
    let workspace = lock
        .packages
        .iter()
        .find(|package| matches!(package.locator, PackageLocator::Workspace { .. }))
        .expect("locked workspace package");
    assert_eq!(workspace.identity, root);
    assert_eq!(workspace.manifest_digest, HASHER.sha256(WORKSPACE_MANIFEST));
    assert_eq!(workspace.dependencies[0].identity, core);
    let locked_core = lock
        .packages
        .iter()
        .find(|package| matches!(package.locator, PackageLocator::Toolchain { .. }))
        .expect("locked core package");
    assert_eq!(locked_core.identity, core);
    assert_eq!(locked_core.manifest_digest, HASHER.sha256(CORE_MANIFEST));
    (root, core)
}

fn source_fixture() -> SourceFixture {
    source_fixture_for(APPLICATION_SOURCE, true)
}

fn source_fixture_for(application_source: &str, require_checked_lock: bool) -> SourceFixture {
    try_source_fixture_for(application_source, require_checked_lock)
        .unwrap_or_else(|diagnostics| panic!("HIR diagnostics: {diagnostics:?}"))
}

fn try_source_fixture_for(
    application_source: &str,
    require_checked_lock: bool,
) -> Result<SourceFixture, Vec<wrela_diagnostics::Diagnostic>> {
    try_source_fixture_with_forged_result(application_source, None, require_checked_lock)
}

fn try_source_fixture_with_forged_result(
    application_source: &str,
    forged_result_source: Option<&str>,
    require_checked_lock: bool,
) -> Result<SourceFixture, Vec<wrela_diagnostics::Diagnostic>> {
    let (root, core_identity) = package_identities(
        application_source,
        forged_result_source,
        require_checked_lock,
    );
    let mut sources = SourceDatabase::default();
    let core_file = add_source(&mut sources, "core/image.wr", CORE_IMAGE_SOURCE);
    let core_result_file = add_source(&mut sources, "core/result.wr", CORE_RESULT_SOURCE);
    let application_file = add_source(&mut sources, "runtime_result/image.wr", application_source);
    let forged_result_file = forged_result_source
        .map(|source| add_source(&mut sources, "result.wr", source));
    let mut graph = PackageGraphBuilder::new(root.clone());
    let core = graph.add_package(core_identity).expect("core package node");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["runtime_result".to_owned(), "image".to_owned()])
                .expect("runtime-result module"),
            application_file,
        )
        .expect("runtime-result module record");
    if let Some(file) = forged_result_file {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["result".to_owned()]).expect("forged result module"),
                file,
            )
            .expect("forged result module record");
    }
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_file,
        )
        .expect("core image module record");
    graph
        .add_module(
            core,
            ModulePath::new(["result".to_owned()]).expect("core result module"),
            core_result_file,
        )
        .expect("core result module record");
    let parsed = sources
        .files()
        .iter()
        .map(|source| {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file: source.id(),
                        limits: ParseLimits::standard(),
                    },
                    &never_cancelled,
                )
                .expect("runtime-result source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();
    let hir = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("package graph")),
                source_graph_digest: root.source_digest,
                parsed_files: &parsed,
                sources: &sources,
                changes: &HirChangeSet {
                    previous_source_graph: None,
                    changed_files: Vec::new(),
                },
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-result HIR lowering");
    if !hir.diagnostics().is_empty() {
        return Err(hir.diagnostics().to_vec());
    }
    let entry = hir.lowered().program().as_program().image_candidates[0];
    let hir = Arc::new(hir.into_parts().0.into_program());
    let target_digest = Sha256Digest::from_bytes([0xc1; 32]);
    let profile_digest = Sha256Digest::from_bytes([0xc2; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xc3; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: root.source_digest,
                source_graph: root.source_digest,
                request: Sha256Digest::from_bytes([0xc4; 32]),
                profile: profile_digest,
            },
            profile: BuildProfile::development(),
        },
        profile_digest,
    )
    .expect("runtime-result build");
    Ok(SourceFixture {
        hir,
        entry,
        target: TargetPackage::aarch64_qemu_virt_uefi(target_digest),
        build,
    })
}

fn analyze_selected(
    fixture: &SourceFixture,
    selector: &str,
) -> wrela_sema::AnalyzedImage {
    let analyzer = CanonicalSemanticAnalyzer::new();
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let discovery = analyzer
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&fixture.hir),
                standard_library_package: wrela_package::PackageId(1),
                target: fixture.target.semantic(),
                build: &fixture.build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: IMAGE_NAME,
                    image_entry: fixture.entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::NameContains(selector),
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-result discovery");
    assert!(discovery.diagnostics().is_empty());
    let plan = discovery
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .expect("runtime-result plan")
        .clone();
    let [group] = plan.image_groups() else {
        panic!("selector must produce one image group");
    };
    let selected = analyzer
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&fixture.hir),
                standard_library_package: wrela_package::PackageId(1),
                target: fixture.target.semantic(),
                build: &fixture.build,
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group: group.id,
                    declared_entry: None,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("selected runtime-result analysis");
    assert!(selected.diagnostics().is_empty());
    selected
        .into_parts()
        .0
        .expect("sealed runtime-result image")
}

fn compile_selected(
    fixture: &SourceFixture,
    selector: &str,
) -> wrela_semantic_lower::semantic_wir::ValidatedSemanticWir {
    let image = analyze_selected(fixture, selector);
    let specialized = image
        .facts()
        .types
        .iter()
        .filter(|ty| {
            matches!(&ty.kind, SemaTypeKind::Enumeration { arguments, .. }
                if matches!(arguments.as_slice(), [SemanticArgument::Type(left), SemanticArgument::Type(right)] if left == right))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        specialized.len(),
        1,
        "identical Result uses must intern once"
    );
    let SemaTypeKind::Enumeration {
        declaration,
        arguments,
        variants,
    } = &specialized[0].kind
    else {
        unreachable!("specialized type filter admits only enums")
    };
    let source_declaration = fixture
        .hir
        .as_program()
        .declaration(*declaration)
        .expect("core Result source declaration");
    assert_eq!(
        source_declaration
            .name
            .as_ref()
            .map(wrela_hir::Name::as_str),
        Some("Result")
    );
    assert_eq!(source_declaration.visibility, wrela_hir::Visibility::Public);
    let source_module = fixture
        .hir
        .as_program()
        .modules
        .get(source_declaration.module.0 as usize)
        .expect("core Result source module");
    assert_eq!(source_module.package, wrela_package::PackageId(1));
    assert_eq!(source_module.path.dotted(), "result");
    let [SemanticArgument::Type(left), SemanticArgument::Type(right)] = arguments.as_slice() else {
        panic!("Result specialization must retain exactly two type arguments")
    };
    assert_eq!(left, right);
    assert!(matches!(variants.as_slice(), [ok, err] if ok.name == "Ok" && err.name == "Err"));
    let payload = image
        .facts()
        .types
        .get(left.0 as usize)
        .expect("Result specialization payload type");
    if selector == "result_bool_match_returns_payload" {
        assert!(matches!(payload.kind, SemaTypeKind::Bool));
    } else {
        assert!(matches!(
            payload.kind,
            SemaTypeKind::Integer {
                signed: false,
                bits: 8,
                pointer_sized: false,
            }
        ));
    }
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: image,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-result SemanticWir")
        .into_parts()
        .0
}

fn assert_discovery_diagnostic(application_source: &str, expected: &str) {
    let fixture = source_fixture_for(application_source, false);
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let output = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir: fixture.hir,
                standard_library_package: wrela_package::PackageId(1),
                target: fixture.target.semantic(),
                build: &fixture.build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: IMAGE_NAME,
                    image_entry: fixture.entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::NameContains("reject"),
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("bounded Result rejection analysis");
    assert!(output.successful().is_none());
    assert!(
        output
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some(expected)),
        "missing {expected}: {:?}",
        output.diagnostics()
    );
}

fn assert_hir_diagnostic(application_source: &str, expected: &str) {
    let diagnostics = try_source_fixture_for(application_source, false)
        .err()
        .expect("wrong generic arity must be rejected before sema");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some(expected)),
        "missing {expected}: {diagnostics:?}"
    );
}

fn inspect_native_object(bytes: &[u8], expected_digest: Sha256Digest) {
    let sequence = OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "wrela-runtime-result-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("create private object directory");
    let path = directory.join("runtime-result.obj");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create runtime-result object");
    file.write_all(bytes).expect("write runtime-result object");
    file.sync_all().expect("sync runtime-result object");
    let measured = CanonicalCoffObjectInspector::new()
        .inspect(&path, LinkLimits::standard().object_bytes, &never_cancelled)
        .expect("independent runtime-result COFF inspection");
    assert_eq!(measured.bytes, bytes.len() as u64);
    assert_eq!(measured.digest, expected_digest);
    assert_eq!(measured.coff_machine, "arm64");
    fs::remove_dir_all(directory).expect("remove private object directory");
}

#[test]
fn checked_in_runtime_result_reaches_exact_enum_machine_and_optional_native_coff() {
    let fixture = source_fixture();
    for (selector, expected_constructs) in SELECTORS {
        let semantic = compile_selected(&fixture, selector);
        assert_eq!(semantic.as_wir().version, 8);
        let erased_enums = semantic
            .as_wir()
            .types
            .iter()
            .filter(
                |ty| matches!(&ty.kind, SemanticTypeKind::Enum { variants } if variants.len() == 2),
            )
            .collect::<Vec<_>>();
        assert_eq!(
            erased_enums.len(),
            1,
            "SemanticWir must contain one erased Result enum"
        );
        assert_eq!(
            semantic
                .as_wir()
                .functions
                .iter()
                .flat_map(|function| &function.body.statements)
                .filter(|statement| matches!(
                    statement,
                    wrela_semantic_lower::semantic_wir::SemanticStatement::Let(statement)
                        if matches!(statement.operation, SemanticOperation::ConstructEnum { .. })
                ))
                .count(),
            expected_constructs
        );
        let flow = CanonicalFlowLowerer::new()
            .lower(
                FlowLowerRequest {
                    input: semantic,
                    limits: FlowLoweringLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("runtime-result FlowWir");
        assert!(flow.diagnostics().is_empty());
        let flow_model = flow.wir().as_wir();
        assert_eq!(flow_model.version, 10);
        assert!(
            flow_model.types.iter().any(
                |ty| matches!(&ty.kind, FlowTypeKind::Enum { variants } if variants.len() == 2)
            )
        );
        let source_operations = flow_model
            .functions
            .iter()
            .filter(|function| {
                matches!(
                    function.origin,
                    wrela_backend::flow_wir::FunctionOrigin::SourceSemantic { .. }
                )
            })
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .map(|instruction| &instruction.operation)
            .collect::<Vec<_>>();
        assert_eq!(
            source_operations
                .iter()
                .filter(|op| matches!(op, FlowOperation::MakeEnum { .. }))
                .count(),
            expected_constructs
        );
        assert_eq!(
            source_operations
                .iter()
                .filter(|op| matches!(op, FlowOperation::EnumTag { .. }))
                .count(),
            1
        );
        assert_eq!(
            source_operations
                .iter()
                .filter(|op| matches!(op, FlowOperation::EnumPayload { .. }))
                .count(),
            1
        );
        assert_eq!(
            flow_model
                .functions
                .iter()
                .filter(|function| matches!(
                    function.origin,
                    wrela_backend::flow_wir::FunctionOrigin::SourceSemantic { .. }
                ))
                .flat_map(|function| &function.blocks)
                .filter(|block| matches!(block.terminator, Terminator::Switch { .. }))
                .count(),
            1
        );

        let (flow_wir, _, _) = flow.into_parts();
        let encoded = encode_and_verify(
            &CanonicalFlowWirCodec,
            EncodeRequest {
                wir: &flow_wir,
                limits: CodecLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-result FlowWir v10 frame");
        assert_eq!(encoded.header().wire_version, 10);
        let prepared = prepare_canonical_frame_for_codegen(
            encoded.bytes(),
            &fixture.target,
            &fixture.build,
            &never_cancelled,
        )
        .expect("runtime-result MachineWir preparation");
        let machine = prepared.machine().wir().as_wir();
        assert_eq!(machine.version, 10);
        assert!(
            machine
                .types
                .iter()
                .any(|ty| matches!(ty.kind, MachineTypeKind::TaggedEnum { variants: 2, .. }))
        );
        let source_functions = machine.functions.iter().filter(|function| {
            matches!(
                function.origin,
                MachineFunctionOrigin::SourceSemantic { .. }
            )
        });
        let mut make = 0;
        let mut tag = 0;
        let mut payload = 0;
        let mut switches = 0;
        for function in source_functions {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    match instruction.operation {
                        MachineOperation::MakeEnum { .. } => make += 1,
                        MachineOperation::EnumTag { .. } => tag += 1,
                        MachineOperation::EnumPayload { .. } => payload += 1,
                        _ => {}
                    }
                }
                switches +=
                    usize::from(matches!(block.terminator, MachineTerminator::Switch { .. }));
            }
        }
        assert_eq!(make, expected_constructs);
        assert_eq!((tag, payload, switches), (1, 1, 1));
        match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
            Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
            Err(error) => panic!("runtime-result native object emission failed: {error}"),
            Ok(_) if !llvm_backend_available() => {
                panic!("native object emitted while LLVM reports unavailable")
            }
            Ok(first) => {
                let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                    .expect("repeat runtime-result native object emission");
                assert_eq!(first.bytes(), second.bytes());
                let digest = HASHER.sha256(first.bytes());
                assert_eq!(digest, HASHER.sha256(second.bytes()));
                inspect_native_object(first.bytes(), digest);
            }
        }
    }
}

#[test]
fn checked_in_runtime_result_try_reaches_exact_early_return_switch() {
    let fixture = source_fixture();
    for selector in TRY_SELECTORS {
        let semantic = compile_selected(&fixture, selector);
        assert_eq!(semantic.as_wir().version, 8);
        let propagation_name = if selector == "result_try_ok_yields_payload" {
            "propagate_try_ok"
        } else {
            "propagate_try_err"
        };
        let propagation = semantic
            .as_wir()
            .functions
            .iter()
            .find(|function| function.name.ends_with(propagation_name))
            .expect("selected propagation helper");
        let result_match = propagation
            .body
            .statements
            .iter()
            .find_map(|statement| match statement {
                wrela_semantic_lower::semantic_wir::SemanticStatement::Match {
                    arms,
                    results,
                    ..
                } if results.len() == 1 => Some((arms, results)),
                _ => None,
            })
            .expect("one result-bearing propagation match");
        let [ok_arm, err_arm] = result_match.0.as_slice() else {
            panic!("postfix question match must have Ok and Err arms")
        };
        assert_eq!(ok_arm.variant, Some(0));
        assert_eq!(err_arm.variant, Some(1));
        assert!(matches!(ok_arm.body.statements.as_slice(),
            [wrela_semantic_lower::semantic_wir::SemanticStatement::Yield(values)]
                if values == &ok_arm.bindings));
        assert!(matches!(err_arm.body.statements.as_slice(),
            [
                wrela_semantic_lower::semantic_wir::SemanticStatement::Let(statement),
                wrela_semantic_lower::semantic_wir::SemanticStatement::Return(values),
            ] if matches!(statement.operation, SemanticOperation::ConstructEnum { variant: 1, .. })
                && values == &statement.results));

        let flow = CanonicalFlowLowerer::new()
            .lower(
                FlowLowerRequest {
                    input: semantic,
                    limits: FlowLoweringLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("runtime-result Try FlowWir");
        assert!(flow.diagnostics().is_empty());
        assert_eq!(flow.wir().as_wir().version, 10);
        let flow_propagation = flow
            .wir()
            .as_wir()
            .functions
            .iter()
            .find(|function| function.name.ends_with(propagation_name))
            .expect("Flow propagation helper");
        let propagation_flow_id = flow_propagation.id;
        assert_eq!(
            flow_propagation
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, Terminator::Switch { .. }))
                .count(),
            1
        );
        assert_eq!(
            flow_propagation
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, Terminator::Return(_)))
                .count(),
            2
        );
        assert!(flow_propagation.blocks.iter().any(|block| {
            !block.parameters.is_empty()
                && block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.operation,
                        FlowOperation::MakeEnum { variant: 0, .. }
                    )
                })
        }));
        assert_eq!(
            flow_propagation
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .filter(|instruction| {
                    matches!(
                        instruction.operation,
                        FlowOperation::MakeEnum { variant: 1, .. }
                    )
                })
                .count(),
            1
        );

        let (flow_wir, _, _) = flow.into_parts();
        let encoded = encode_and_verify(
            &CanonicalFlowWirCodec,
            EncodeRequest {
                wir: &flow_wir,
                limits: CodecLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-result Try FlowWir v10 frame");
        assert_eq!(encoded.header().wire_version, 10);
        let prepared = prepare_canonical_frame_for_codegen(
            encoded.bytes(),
            &fixture.target,
            &fixture.build,
            &never_cancelled,
        )
        .expect("runtime-result Try MachineWir preparation");
        let machine = prepared.machine().wir().as_wir();
        assert_eq!(machine.version, 10);
        let machine_propagation = machine
            .functions
            .iter()
            .find(|function| function.flow_function == propagation_flow_id.0)
            .expect("Machine propagation helper");
        assert_eq!(
            machine_propagation
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, MachineTerminator::Switch { .. }))
                .count(),
            1
        );
        assert_eq!(
            machine_propagation
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, MachineTerminator::Return(_)))
                .count(),
            2
        );
        assert_eq!(
            machine_propagation
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .filter(|instruction| {
                    matches!(
                        instruction.operation,
                        MachineOperation::MakeEnum { variant: 1, .. }
                    )
                })
                .count(),
            1
        );
    }
}

#[test]
fn bounded_core_result_rejects_unsupported_specializations_stably() {
    let prefix = r#"module runtime_result.image

from core.image import Image, Target
from core.result import Result

@image
pub comptime fn boot() -> Image:
    return Image(name="runtime-result", target=Target.aarch64_qemu_virt_uefi)

"#;
    for (body, code) in [
        (
            "@test\nfn reject_mismatch():\n    value: Result[u8, bool] = Result.Ok(1)\n    return\n",
            "semantic-runtime-result-payload-mismatch",
        ),
        (
            "@test\nfn reject_nonscalar():\n    value: Result[unit, unit] = Result.Ok(unit)\n    return\n",
            "semantic-runtime-result-argument-type",
        ),
        (
            "@test\nfn reject_context_free():\n    value: u8 = Result.Ok(1)\n    return\n",
            "semantic-runtime-result-constructor-context",
        ),
    ] {
        assert_discovery_diagnostic(&format!("{prefix}{body}"), code);
    }
    assert_hir_diagnostic(
        &format!(
            "{prefix}@test\nfn reject_wrong_arity():\n    value: Result[u8] = Result.Ok(1)\n    return\n"
        ),
        "hir-generic-argument-count",
    );
    assert_discovery_diagnostic(
        r#"module runtime_result.image

from core.image import Image, Target

enum Forged[T, E]:
    Ok(T,)
    Err(E,)

@image
pub comptime fn boot() -> Image:
    return Image(name="runtime-result", target=Target.aarch64_qemu_virt_uefi)

@test
fn reject_forged():
    value: Forged[u8, u8] = Forged.Ok(1)
    return
"#,
        "semantic-runtime-result-not-core",
    );
}

#[test]
fn bounded_result_try_rejects_unsupported_ownership_stably() {
    let prefix = r#"module runtime_result.image

from core.image import Image, Target
from core.result import Result

@image
pub comptime fn boot() -> Image:
    return Image(name="runtime-result", target=Target.aarch64_qemu_virt_uefi)

"#;
    for (body, code) in [
        (
            r#"fn reject_named_helper() -> Result[u8, u8]:
    value: Result[u8, u8] = Result.Ok(1)
    payload: u8 = value?
    return Result.Ok(payload)

@test
fn reject_named_place():
    value: Result[u8, u8] = reject_named_helper()
    return
"#,
            "semantic-runtime-try-rvalue-required",
        ),
        (
            r#"enum Fake:
    Ok(u8,)
    Err(u8,)

fn fake_source() -> Fake:
    return Fake.Ok(1)

fn reject_fake_helper() -> Result[u8, u8]:
    payload: u8 = fake_source()?
    return Result.Ok(payload)

@test
fn reject_fake_result():
    value: Result[u8, u8] = reject_fake_helper()
    return
"#,
            "semantic-runtime-try-result-required",
        ),
        (
            r#"fn result_source() -> Result[u8, u8]:
    return Result.Ok(1)

fn reject_enclosing_helper() -> u8:
    return result_source()?

@test
fn reject_enclosing_result():
    value: u8 = reject_enclosing_helper()
    return
"#,
            "semantic-runtime-try-enclosing-result",
        ),
    ] {
        assert_discovery_diagnostic(&format!("{prefix}{body}"), code);
    }
}
