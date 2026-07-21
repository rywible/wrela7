use std::cell::Cell;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use wrela_backend::{
    BackendExecutionOptions, BackendExecutionRequest, BackendExecutor, BackendInputError,
    BackendJobPathCandidate, BackendJobPaths, BackendLimits, BackendPipelineServices,
    BackendPreparationOptions, BackendPreparationServices, CanonicalBackendContentHasher,
    CanonicalBackendReportAssembler, ComposedBackendExecutor, FilesystemBackendPublisher,
    prepare_for_codegen,
};
use wrela_backend_protocol::{
    BackendFailureKind, BackendOutcome, BackendPath, BackendRequest, MAX_FRAME_BYTES, RequestId,
    decode_response, encode_request,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, OptimizationLevel,
    Sha256Digest, TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
};
use wrela_codegen_llvm::{CodeGenerator, CodegenError, CodegenRequest, ObjectArtifact};
use wrela_flow_opt::{CanonicalFlowOptimizer, OptimizationLimits, OptimizationProfile};
use wrela_flow_wir::{
    Block, BlockId, FLOW_WIR_VERSION, FlowFunction, FlowType, FlowTypeKind, FlowWir, FunctionColor,
    FunctionId, FunctionOrigin, FunctionRole, PlanOwner, Proof, ProofId, ProofKind, SourceSummary,
    Terminator, TypeId,
};
use wrela_flow_wir_codec::{
    CanonicalFlowWirCodec, CodecLimits, DecodeRequest, EncodeRequest,
    decode_and_verify as decode_flow_wir, encode_and_verify,
};
use wrela_image_report::{AnalysisFactLimits, BackendFactLimits, decode_image_report_json};
use wrela_link_efi::{
    CanonicalCoffObjectInspector, CanonicalLinkedImageInspector, LldEfiLinker, TargetRuntimeObject,
};
use wrela_machine_lower::{CanonicalMachineLowerer, MachineLowerError, MachineLoweringLimits};
use wrela_target::TargetPackage;

const TARGET_TOML: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
const RUNTIME_OBJECT: &[u8] = include_bytes!(
    "../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj"
);
const RUNTIME_SOURCE: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime.S");
const RUNTIME_BUILDER: &[u8] = include_bytes!(
    "../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/build_runtime.py"
);
const RUNTIME_LOCK: &str = include_str!(
    "../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml"
);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary base");
        for _ in 0..128 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "wrela-backend-process-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    set_directory_mode(&root);
                    return Self {
                        root: fs::canonicalize(root).expect("canonical fixture directory"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create backend fixture: {error}"),
            }
        }
        panic!("cannot allocate backend fixture directory")
    }

    fn directory(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(&path).expect("create private fixture directory");
        set_directory_mode(&path);
        path
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        fs::write(&path, bytes).expect("write bounded fixture");
        set_file_mode(&path);
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Fixture {
    directory: TestDirectory,
    request: BackendRequest,
    build: ValidatedBuildConfiguration,
    wir_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        assert_runtime_fixture_enrollment();
        let directory = TestDirectory::new();
        directory.directory("build");
        directory.directory("targets/aarch64-qemu-virt-uefi/runtime");
        directory.write("targets/aarch64-qemu-virt-uefi/target.toml", TARGET_TOML);
        let runtime = RUNTIME_OBJECT.to_vec();
        directory.write(
            "targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
            &runtime,
        );

        let mut profile = BuildProfile::development();
        profile.optimization.level = OptimizationLevel::None;
        let profile_digest = digest(
            &profile
                .canonical_bytes()
                .expect("canonical development profile"),
        );
        let build = BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x11; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: Sha256Digest::from_bytes([0x22; 32]),
                standard_library: Sha256Digest::from_bytes([0x33; 32]),
                source_graph: Sha256Digest::from_bytes([0x44; 32]),
                request: Sha256Digest::from_bytes([0x55; 32]),
                profile: profile_digest,
            },
            profile,
        };
        let build = seal_build_configuration(build, profile_digest).expect("validated fixture");
        let wir_bytes = canonical_wir(build.identity.clone());
        directory.write("build/input.wir", &wir_bytes);
        let request = BackendRequest {
            request_id: RequestId(47),
            build: build.as_configuration().clone(),
            wir: BackendPath::new("build/input.wir").expect("WIR path"),
            wir_digest: digest(&wir_bytes),
            target_runtime_digest: digest(&runtime),
            target_runtime_bytes: u64::try_from(runtime.len()).expect("runtime byte count"),
            target_package: BackendPath::new("targets/aarch64-qemu-virt-uefi")
                .expect("target path"),
            output: BackendPath::new("build/image.efi").expect("output path"),
            report: BackendPath::new("build/image.json").expect("report path"),
        };
        Self {
            directory,
            request,
            build,
            wir_bytes,
        }
    }

    fn frame(&self) -> Vec<u8> {
        encode_request(&self.request, &self.build).expect("canonical request frame")
    }
}

fn canonical_wir(build: BuildIdentity) -> Vec<u8> {
    let proof =
        |id: u32, kind: ProofKind, depends_on: Vec<u32>, bound: Option<u64>, subject: &str| Proof {
            id: ProofId(id),
            kind,
            subject: subject.to_owned(),
            // The public FlowWir crate intentionally exposes the source type from
            // its source crate without re-exporting its constructor. Encode a
            // structurally valid source-free seed below, then insert the canonical
            // wire representation of one zero-width FileId(0) span per proof.
            sources: Vec::new(),
            depends_on: depends_on.into_iter().map(ProofId).collect(),
            bound,
            explanation: vec![format!("minimum image proof {id}")],
        };
    let seed = FlowWir {
        version: FLOW_WIR_VERSION,
        name: "canonical-process-image".to_owned(),
        build: build.clone(),
        source_summary: SourceSummary {
            semantic_wir_version: 10,
            semantic_functions: 1,
            hir_files: 1,
            hir_declarations: 1,
            reachable_declarations: 1,
            monomorphized_instantiations: 1,
            resolved_interface_calls: 0,
        },
        types: vec![FlowType {
            id: TypeId(0),
            kind: FlowTypeKind::Unit,
            name: Some("unit".to_owned()),
            copyable: true,
            strict_linear: false,
        }],
        globals: Vec::new(),
        functions: vec![FlowFunction {
            id: FunctionId(0),
            name: "__wrela_image_entry".to_owned(),
            origin: FunctionOrigin::GeneratedImageEntry {
                semantic_function: 0,
                constructor: 0,
            },
            role: FunctionRole::ImageEntry,
            color: FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: None,
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        }],
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        proofs: vec![
            proof(
                0,
                ProofKind::TypeChecked,
                Vec::new(),
                None,
                "fixture-proof-type-checked",
            ),
            proof(
                1,
                ProofKind::EffectsAllowed,
                vec![0],
                Some(1),
                "fixture-proof-effects-allowed",
            ),
            proof(
                2,
                ProofKind::ImageClosed,
                vec![0, 1],
                Some(0),
                "fixture-proof-image-closed",
            ),
        ],
        checkpoints: Vec::new(),
        tests: Vec::new(),
        compiled_test_group: None,
        startup_order: vec![PlanOwner::Runtime],
        shutdown_order: vec![PlanOwner::Runtime],
        image_entry: FunctionId(0),
        static_bytes: 0,
        peak_bytes: 0,
    }
    .validate()
    .expect("valid canonical FlowWir seed");
    let codec = CanonicalFlowWirCodec;
    let mut bytes = encode_and_verify(
        &codec,
        EncodeRequest {
            wir: &seed,
            limits: CodecLimits::standard(),
        },
        &|| false,
    )
    .expect("canonical source-free seed frame")
    .into_bytes();
    for subject in [
        "fixture-proof-type-checked",
        "fixture-proof-effects-allowed",
        "fixture-proof-image-closed",
    ] {
        insert_zero_width_proof_span(&mut bytes, subject);
    }
    let payload = u64::from_le_bytes(bytes[16..24].try_into().expect("payload length"))
        .checked_add(36)
        .expect("fixture payload length");
    bytes[16..24].copy_from_slice(&payload.to_le_bytes());
    let decoded = decode_flow_wir(
        &codec,
        DecodeRequest {
            bytes: &bytes,
            limits: CodecLimits::standard(),
            expected_build: Some(&build),
        },
        &|| false,
    )
    .expect("patched canonical fixture decodes and validates");
    let canonical = encode_and_verify(
        &codec,
        EncodeRequest {
            wir: &decoded,
            limits: CodecLimits::standard(),
        },
        &|| false,
    )
    .expect("patched fixture re-encodes canonically")
    .into_bytes();
    assert_eq!(canonical, bytes);
    canonical
}

fn insert_zero_width_proof_span(bytes: &mut Vec<u8>, subject: &str) {
    let positions: Vec<_> = bytes
        .windows(subject.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == subject.as_bytes()).then_some(index))
        .collect();
    assert_eq!(positions.len(), 1, "unique proof subject marker");
    let sources = positions[0]
        .checked_add(subject.len())
        .expect("fixture sources offset");
    assert_eq!(&bytes[sources..sources + 4], &[0, 0, 0, 0]);
    bytes[sources..sources + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes.splice(sources + 4..sources + 4, [0u8; 12]);
}

struct InjectedCodegenFailure {
    called: Cell<bool>,
}

struct UncalledHasher {
    called: Cell<bool>,
}

impl wrela_backend::BackendContentHasher for UncalledHasher {
    fn sha256(&self, _bytes: &[u8], _is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest> {
        self.called.set(true);
        None
    }
}

impl CodeGenerator for InjectedCodegenFailure {
    fn emit_object(
        &self,
        request: CodegenRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ObjectArtifact, CodegenError> {
        assert!(!is_cancelled());
        assert_eq!(request.module.as_wir().name, "canonical-process-image");
        self.called.set(true);
        Err(CodegenError::TargetMachineMismatch(
            "injected codegen rejection".to_owned(),
        ))
    }
}

#[test]
fn composed_executor_reaches_an_injected_codegen_only_after_canonical_acceptance() {
    let fixture = Fixture::new();
    let target = TargetPackage::aarch64_qemu_virt_uefi(fixture.build.identity.target_package);
    let paths = BackendJobPaths::new(BackendJobPathCandidate {
        private_root: fixture.directory.root.clone(),
        generated_object: fixture.directory.root.join("injected.obj"),
        temporary_image: fixture.directory.root.join("injected.tmp.efi"),
        temporary_map: fixture.directory.root.join("injected.tmp.map"),
        temporary_report: fixture.directory.root.join("injected.tmp.json"),
        final_image: fixture.directory.root.join("build/image.efi"),
        final_report: fixture.directory.root.join("build/image.json"),
    })
    .expect("valid injected pipeline paths");
    let runtime_path = fixture
        .directory
        .root
        .join("targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj");
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile().optimization,
        fixture.build.identity.compiler,
    )
    .expect("fixture optimization profile");
    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let code_generator = InjectedCodegenFailure {
        called: Cell::new(false),
    };
    let object_inspector = CanonicalCoffObjectInspector::new();
    let image_inspector = CanonicalLinkedImageInspector::new();
    let linker = LldEfiLinker {
        object_inspector: &object_inspector,
        image_inspector: &image_inspector,
    };
    let report_assembler = CanonicalBackendReportAssembler::new();
    let publisher = FilesystemBackendPublisher::new();
    let executor = ComposedBackendExecutor::new(BackendPipelineServices {
        codec: &codec,
        hasher: &hasher,
        optimizer: &optimizer,
        machine_lowerer: &machine_lowerer,
        code_generator: &code_generator,
        linker: &linker,
        report_assembler: &report_assembler,
        publisher: &publisher,
    });
    let output = executor
        .execute(
            BackendExecutionRequest {
                protocol: &fixture.request,
                build: &fixture.build,
                wir_bytes: &fixture.wir_bytes,
                target: &target,
                target_runtime: TargetRuntimeObject {
                    path: &runtime_path,
                    digest: fixture.request.target_runtime_digest,
                    bytes: fixture.request.target_runtime_bytes,
                    target_package: fixture.build.identity.target_package,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
                paths: &paths,
                options: BackendExecutionOptions {
                    optimization,
                    limits: BackendLimits::standard(),
                },
            },
            &|| false,
        )
        .expect("injected stage failure is a typed backend result");
    assert!(code_generator.called.get());
    let failure = output.failure().expect("typed injected failure");
    assert_eq!(failure.kind, BackendFailureKind::Codegen);
    assert!(failure.message.contains("injected codegen rejection"));
    assert!(!paths.generated_object().exists());
}

#[test]
fn real_preparation_handoff_preserves_machine_validation_failures_and_cancellation() {
    let fixture = Fixture::new();
    let target = TargetPackage::aarch64_qemu_virt_uefi(fixture.build.identity.target_package);
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile().optimization,
        fixture.build.identity.compiler,
    )
    .expect("fixture optimization profile");
    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let services = BackendPreparationServices {
        codec: &codec,
        hasher: &hasher,
        optimizer: &optimizer,
        machine_lowerer: &machine_lowerer,
    };
    let standard_options = BackendPreparationOptions {
        codec_limits: CodecLimits::standard(),
        optimization: optimization.clone(),
        optimization_limits: OptimizationLimits::standard(),
        machine_limits: MachineLoweringLimits::standard(),
    };
    let prepared = prepare_for_codegen(
        services,
        &fixture.wir_bytes,
        fixture.request.wir_digest,
        &target,
        &fixture.build,
        standard_options,
        &|| false,
    )
    .expect("real decode, optimize, and machine-lower handoff");
    assert_eq!(
        prepared.machine().wir().as_wir().name,
        "canonical-process-image"
    );

    let mut machine_limits = MachineLoweringLimits::standard();
    machine_limits.validation.validation_work = 1;
    let constrained_options = BackendPreparationOptions {
        codec_limits: CodecLimits::standard(),
        optimization,
        optimization_limits: OptimizationLimits::standard(),
        machine_limits,
    };
    let polls = Cell::new(0u64);
    assert!(matches!(
        prepare_for_codegen(
            services,
            &fixture.wir_bytes,
            fixture.request.wir_digest,
            &target,
            &fixture.build,
            constrained_options.clone(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        ),
        Err(BackendInputError::MachineLower(
            MachineLowerError::ResourceLimit {
                resource: "validation work",
                limit: 1,
            }
        ))
    ));
    let cancel_at = polls.get().saturating_sub(1);
    assert!(cancel_at > 10);
    let cancellation_polls = Cell::new(0u64);
    assert!(matches!(
        prepare_for_codegen(
            services,
            &fixture.wir_bytes,
            fixture.request.wir_digest,
            &target,
            &fixture.build,
            constrained_options,
            &|| {
                let next = cancellation_polls.get() + 1;
                cancellation_polls.set(next);
                next >= cancel_at
            },
        ),
        Err(BackendInputError::MachineLower(
            MachineLowerError::Cancelled
        ))
    ));
}

#[test]
fn preparation_rejects_nested_machine_policy_drift_before_hashing() {
    let fixture = Fixture::new();
    let target = TargetPackage::aarch64_qemu_virt_uefi(fixture.build.identity.target_package);
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile().optimization,
        fixture.build.identity.compiler,
    )
    .expect("fixture optimization profile");
    let codec = CanonicalFlowWirCodec;
    let hasher = UncalledHasher {
        called: Cell::new(false),
    };
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let mut machine_limits = MachineLoweringLimits::standard();
    machine_limits.validation.model_edges -= 1;
    let result = prepare_for_codegen(
        BackendPreparationServices {
            codec: &codec,
            hasher: &hasher,
            optimizer: &optimizer,
            machine_lowerer: &machine_lowerer,
        },
        &fixture.wir_bytes,
        fixture.request.wir_digest,
        &target,
        &fixture.build,
        BackendPreparationOptions {
            codec_limits: CodecLimits::standard(),
            optimization,
            optimization_limits: OptimizationLimits::standard(),
            machine_limits,
        },
        &|| false,
    );
    assert!(matches!(
        result,
        Err(BackendInputError::MachineLower(
            MachineLowerError::InvalidLimits
        ))
    ));
    assert!(!hasher.called.get());
}

#[test]
fn valid_front_boundary_reports_native_success_or_honest_default_failure() {
    let fixture = Fixture::new();
    let output = run_raw(&fixture.directory.root, &fixture.frame());
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert!(output.stderr.is_empty());
    let response = decode_response(&output.stdout).expect("canonical response frame");
    assert_eq!(response.request_id, fixture.request.request_id);
    if cfg!(feature = "bundled-backend") {
        let success = match response.outcome {
            BackendOutcome::Success(success) => success,
            BackendOutcome::Failure(failure) => {
                panic!("bundled backend did not publish a verified EFI image: {failure:?}")
            }
        };
        assert!(fixture.directory.root.join("build/image.efi").exists());
        let report_path = fixture.directory.root.join("build/image.json");
        let report_bytes = fs::read(&report_path).expect("published canonical report");
        let report = decode_image_report_json(
            &report_bytes,
            &fixture.build.identity,
            AnalysisFactLimits::standard(),
            BackendFactLimits::standard(),
            u64::try_from(report_bytes.len()).expect("bounded report byte count"),
            &|| false,
        )
        .expect("published schema-v10 report authenticates independently");
        assert!(report.analysis().region_capacity_evidence.is_empty());
        assert_eq!(report.backend().artifact_digest, success.artifact_digest);
        assert!(report.backend().relocation_directory_bytes > 0);
        assert!(report.backend().base_relocation_blocks > 0);
        assert!(report.backend().base_relocation_dir64_count > 0);
        assert!(
            report
                .backend()
                .base_relocation_provenance_digest
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
    } else {
        let BackendOutcome::Failure(failure) = response.outcome else {
            panic!("non-native backend reported success")
        };
        assert_eq!(failure.kind, BackendFailureKind::Codegen);
        assert!(failure.message.contains("canonical FlowWir was accepted"));
        assert!(failure.message.contains("sealed MachineWir"));
        assert!(failure.message.contains("without LLVM"));
        assert!(!fixture.directory.root.join("build/image.efi").exists());
        assert!(!fixture.directory.root.join("build/image.json").exists());
    }
}

#[test]
fn digest_valid_noncanonical_wir_is_rejected_before_codegen() {
    let mut fixture = Fixture::new();
    let mut noncanonical = fixture.wir_bytes.clone();
    noncanonical.push(0);
    fixture.directory.write("build/input.wir", &noncanonical);
    fixture.request.wir_digest = digest(&noncanonical);

    let output = run_raw(&fixture.directory.root, &fixture.frame());
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let response = decode_response(&output.stdout).expect("canonical failure response");
    let BackendOutcome::Failure(failure) = response.outcome else {
        panic!("noncanonical FlowWir produced success")
    };
    assert_eq!(failure.kind, BackendFailureKind::Verification);
    assert!(failure.message.contains("backend input acceptance"));
    assert!(failure.message.contains("trailing"));
}

#[test]
fn malformed_truncated_oversized_and_trailing_streams_are_bounded_transport_failures() {
    let directory = TestDirectory::new();
    let truncated = run_raw(&directory.root, b"W");
    assert_transport_failure(&truncated, "truncated");

    let mut oversized = Vec::from(*b"WRELBEP\0");
    oversized.extend_from_slice(&wrela_backend_protocol::PROTOCOL_VERSION.to_le_bytes());
    oversized.push(1);
    oversized.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
    let oversized = run_raw(&directory.root, &oversized);
    assert_transport_failure(&oversized, "exceeds");

    let fixture = Fixture::new();
    let mut trailing_frame = fixture.frame();
    trailing_frame.push(0);
    let trailing = run_raw(&fixture.directory.root, &trailing_frame);
    assert_transport_failure(&trailing, "trailing");

    let mut malformed = [0u8; 17];
    malformed[13..].copy_from_slice(&0u32.to_le_bytes());
    let malformed = run_raw(&directory.root, &malformed);
    assert_transport_failure(&malformed, "malformed");
}

#[test]
fn stale_profile_identity_is_a_request_attributed_verification_failure() {
    let fixture = Fixture::new();
    let mut frame = fixture.frame();
    let profile = fixture.request.build.identity.profile.as_bytes();
    let positions: Vec<_> = frame
        .windows(profile.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == profile).then_some(index))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "profile digest must be unique in fixture"
    );
    frame[positions[0]] ^= 0xff;

    let output = run_raw(&fixture.directory.root, &frame);
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let response = decode_response(&output.stdout).expect("typed stale response");
    assert_eq!(response.request_id, fixture.request.request_id);
    let BackendOutcome::Failure(failure) = response.outcome else {
        panic!("stale profile produced success")
    };
    assert_eq!(failure.kind, BackendFailureKind::Verification);
    assert!(failure.message.contains("profile digest"));
}

#[test]
fn wrong_wir_digest_and_non_private_input_never_reach_native_work() {
    let mut fixture = Fixture::new();
    fixture.request.wir_digest = Sha256Digest::from_bytes([0xee; 32]);
    let output = run_raw(&fixture.directory.root, &fixture.frame());
    let response = decode_response(&output.stdout).expect("digest failure response");
    let BackendOutcome::Failure(failure) = response.outcome else {
        panic!("wrong WIR digest produced success")
    };
    assert_eq!(failure.kind, BackendFailureKind::Verification);
    assert!(failure.message.contains("FlowWir input digest"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let external = fixture.directory.write("other.wir", b"replacement");
        let wir = fixture.directory.root.join("build/input.wir");
        fs::remove_file(&wir).expect("remove original WIR");
        symlink(external, &wir).expect("install WIR symlink");
        fixture.request.wir_digest = digest(b"replacement");
        let output = run_raw(&fixture.directory.root, &fixture.frame());
        let response = decode_response(&output.stdout).expect("private-input failure response");
        let BackendOutcome::Failure(failure) = response.outcome else {
            panic!("symlinked WIR produced success")
        };
        assert_eq!(failure.kind, BackendFailureKind::Input);
        assert!(failure.message.contains("unstable, non-private"));
    }
}

#[test]
fn stale_runtime_digest_and_length_fail_before_native_work() {
    let mut fixture = Fixture::new();
    fixture.request.target_runtime_digest = Sha256Digest::from_bytes([0xee; 32]);
    let output = run_raw(&fixture.directory.root, &fixture.frame());
    let response = decode_response(&output.stdout).expect("runtime digest failure response");
    let BackendOutcome::Failure(failure) = response.outcome else {
        panic!("wrong target runtime digest produced success")
    };
    assert_eq!(failure.kind, BackendFailureKind::Target);
    assert!(failure.message.contains("verified digest and length"));

    fixture.request.target_runtime_digest = digest(RUNTIME_OBJECT);
    fixture.request.target_runtime_bytes += 1;
    let output = run_raw(&fixture.directory.root, &fixture.frame());
    let response = decode_response(&output.stdout).expect("runtime length failure response");
    let BackendOutcome::Failure(failure) = response.outcome else {
        panic!("wrong target runtime length produced success")
    };
    assert_eq!(failure.kind, BackendFailureKind::Target);
}

#[test]
fn process_termination_while_reading_cannot_publish_or_emit_a_success_frame() {
    let fixture = Fixture::new();
    let mut child = backend_command(&fixture.directory.root)
        .spawn()
        .expect("spawn private backend");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(b"W").expect("write partial request");
    stdin.flush().expect("flush partial request");
    child.kill().expect("terminate cancelled backend job");
    drop(stdin);
    let output = child.wait_with_output().expect("collect cancelled backend");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!fixture.directory.root.join("build/image.efi").exists());
    assert!(!fixture.directory.root.join("build/image.json").exists());
}

#[test]
fn metadata_commands_are_exact_and_reject_extra_arguments() {
    let version = Command::new(env!("CARGO_BIN_EXE_wrela-backend"))
        .arg("--protocol-version")
        .output()
        .expect("protocol version command");
    assert!(version.status.success());
    assert_eq!(
        version.stdout,
        format!("{}\n", wrela_backend_protocol::PROTOCOL_VERSION).as_bytes()
    );
    assert!(version.stderr.is_empty());

    let invalid = Command::new(env!("CARGO_BIN_EXE_wrela-backend"))
        .args(["--version", "unexpected"])
        .output()
        .expect("invalid metadata command");
    assert_eq!(invalid.status.code(), Some(64));
    assert!(invalid.stdout.is_empty());
    assert!(invalid.stderr.len() <= 4096);

    let relative_root = Command::new(env!("CARGO_BIN_EXE_wrela-backend"))
        .args(["--private-root", "relative-job"])
        .output()
        .expect("invalid private root command");
    assert_eq!(relative_root.status.code(), Some(74));
    assert!(relative_root.stdout.is_empty());
    assert!(relative_root.stderr.len() <= 4096);
    assert!(
        std::str::from_utf8(&relative_root.stderr)
            .expect("UTF-8 private-root diagnostic")
            .contains("canonical private directory")
    );
}

fn run_raw(root: &Path, bytes: &[u8]) -> Output {
    let mut child = backend_command(root)
        .spawn()
        .expect("spawn private backend");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(bytes).expect("write request bytes");
    drop(stdin);
    child.wait_with_output().expect("collect private backend")
}

fn backend_command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wrela-backend"));
    command
        .arg("--private-root")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn assert_transport_failure(output: &Output, message: &str) {
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() <= 4096);
    let stderr = std::str::from_utf8(&output.stderr).expect("UTF-8 process diagnostic");
    assert!(stderr.contains(message), "unexpected stderr: {stderr:?}");
}

#[test]
fn checked_in_runtime_fixture_matches_its_enrollment() {
    assert_runtime_fixture_enrollment();
}

fn assert_runtime_fixture_enrollment() {
    assert_single_runtime_lock_line(
        "builder_sha256",
        &format!("builder_sha256 = \"{}\"", sha256_hex(RUNTIME_BUILDER)),
        "checked-in runtime builder differs from runtime-object.lock.toml",
    );
    assert_single_runtime_lock_line(
        "source_sha256",
        &format!("source_sha256 = \"{}\"", sha256_hex(RUNTIME_SOURCE)),
        "checked-in runtime source differs from runtime-object.lock.toml",
    );
    assert_single_runtime_lock_line(
        "object_sha256",
        &format!("object_sha256 = \"{}\"", sha256_hex(RUNTIME_OBJECT)),
        "checked-in runtime object differs from runtime-object.lock.toml",
    );
    assert_single_runtime_lock_line(
        "object_bytes",
        &format!("object_bytes = {}", RUNTIME_OBJECT.len()),
        "checked-in runtime object length differs from runtime-object.lock.toml",
    );
}

fn assert_single_runtime_lock_line(key: &str, expected: &str, diagnostic: &str) {
    assert!(
        has_single_canonical_runtime_lock_line(RUNTIME_LOCK, key, expected),
        "{diagnostic}"
    );
}

fn has_single_canonical_runtime_lock_line(lock: &str, key: &str, expected: &str) -> bool {
    let mut assignments = lock.lines().filter(|line| {
        line.split_once('=')
            .is_some_and(|(candidate, _)| candidate.trim() == key)
    });
    assignments.next() == Some(expected) && assignments.next().is_none()
}

#[test]
fn runtime_enrollment_rejects_a_conflicting_duplicate_assignment() {
    let expected = "object_bytes = 7932";
    assert!(has_single_canonical_runtime_lock_line(
        expected,
        "object_bytes",
        expected,
    ));
    assert!(!has_single_canonical_runtime_lock_line(
        "object_bytes = 7932\nobject_bytes = 1\n",
        "object_bytes",
        expected,
    ));
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    Sha256Digest::from_bytes(digest)
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory mode");
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path) {}

#[cfg(unix)]
fn set_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file mode");
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) {}
