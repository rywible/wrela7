#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use wrela_backend::{
    BackendReportAssembler, BackendReportRequest, CanonicalBackendReportAssembler, CodegenError,
    ObjectArtifact, PreparedBackendInput, emit_prepared_object, llvm_backend_available,
    machine_wir::{CheckedIntegerOp, ConversionOp, MachineFunctionOrigin, MachineOperation},
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_compiler::{
    AnalysisFactAssembler, AnalysisFactRequest, CanonicalAnalysisFactAssembler, LocalTestDriver,
    PipelineLimits,
};
use wrela_driver::{
    Command, CompilerDriver, DiagnosticOptions, DriverError, DriverEvent, EventSink, TestSelection,
    WorkspaceSelection,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowBinaryOp, FlowLowerer, FlowOperation, LowerError as FlowLowerError,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir::DeclarationId;
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_link_efi::{
    CanonicalCoffObjectInspector, CanonicalLinkedImageInspector, CoffInspectError, CoffObject,
    CoffObjectInspector, CoffObjectKind, EfiLinker, LinkError, LinkLimits, LinkRequest,
    LldEfiLinker,
};
use wrela_package::{DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, PackageContentKind,
    PackageContentRecord, SoftwareSha256, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::{TestId, TestKind};
use wrela_toolchain::Toolchain;

const WORKSPACE_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-runtime/wrela.toml");
const APPLICATION_SOURCE: &str =
    include_str!("../../../std/examples/stdlib-time-runtime/src/runtime/time_test.wr");
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_OPTION_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/option.wr");
const CORE_PANIC_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/panic.wr");
const CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");
const PASS_SELECTOR: &str = "installed_core_time_executes_in_qemu";
const FAILURE_SELECTOR: &str = "typed_checked_failure_reaches_qemu";
const IMAGE_NAME: &str = "stdlib-time-runtime";
const SOURCE_PATHS: [&str; 4] = [
    "core/image.wr",
    "core/ops.wr",
    "core/time.wr",
    "runtime/time_test.wr",
];

static HASHER: SoftwareSha256 = SoftwareSha256;
static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct SourceFixture {
    hir: Arc<wrela_hir::ValidatedProgram>,
    sources: SourceDatabase,
    application_file: FileId,
    core_time_file: FileId,
    entry: DeclarationId,
    root_identity: PackageIdentity,
    profile: BuildProfile,
}

#[test]
fn checked_in_runtime_workspace_is_canonical_and_names_two_exact_source_tests() {
    assert!(SOURCE_PATHS.windows(2).all(|pair| pair[0] < pair[1]));
    let (manifest, _root_identity) = canonical_workspace();
    assert_eq!(manifest.name.as_str(), IMAGE_NAME);
    assert_eq!(manifest.images.len(), 1);
    assert_eq!(manifest.images[0].name, IMAGE_NAME);
    assert_eq!(manifest.images[0].entry, "boot");
    assert_eq!(manifest.images[0].module.dotted(), "runtime.time_test");

    for selector in [PASS_SELECTOR, FAILURE_SELECTOR] {
        assert_eq!(
            APPLICATION_SOURCE
                .matches(&format!("fn {selector}():"))
                .count(),
            1,
            "selector must name exactly one source test"
        );
    }
    assert!(APPLICATION_SOURCE.contains("from core.time import as_nanoseconds, ns"));
    assert!(APPLICATION_SOURCE.contains("as_nanoseconds(ns(42))"));
    assert!(APPLICATION_SOURCE.contains("as_nanoseconds(ns(20) + ns(22))"));
    assert!(APPLICATION_SOURCE.contains("ordered: bool = ns(41) < ns(42)"));
    assert!(APPLICATION_SOURCE.contains("value: u8 = left << count"));
}

#[test]
fn installed_core_time_source_reaches_real_test_harness_machine_and_native_object() {
    let fixture = source_fixture(APPLICATION_SOURCE);
    let semantic = compile_selected(&fixture, PASS_SELECTOR);
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("installed core.time runtime test lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();

    let test_name = format!("{IMAGE_NAME}@0.1.0::runtime.time_test::{PASS_SELECTOR}");
    let test_function = flow_model
        .functions
        .iter()
        .find(|function| function.name == test_name)
        .expect("selected source test Flow function");
    let mut direct_callees = test_function
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match &instruction.operation {
            FlowOperation::Call { function, .. } => {
                Some(flow_model.functions[function.0 as usize].name.as_str())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    direct_callees.sort_unstable();
    assert_eq!(
        direct_callees,
        [
            "stdlib-time-runtime@0.1.0::runtime.time_test::force_invalid_shift_count",
            "stdlib-time-runtime@0.1.0::runtime.time_test::force_invalid_shift_count",
            "stdlib-time-runtime@0.1.0::runtime.time_test::force_invalid_shift_count",
            "wrela-core@0.1.0::time::add",
            "wrela-core@0.1.0::time::as_nanoseconds",
            "wrela-core@0.1.0::time::as_nanoseconds",
            "wrela-core@0.1.0::time::less_than",
            "wrela-core@0.1.0::time::ns",
            "wrela-core@0.1.0::time::ns",
            "wrela-core@0.1.0::time::ns",
            "wrela-core@0.1.0::time::ns",
            "wrela-core@0.1.0::time::ns",
        ]
    );
    assert_eq!(
        flow_model
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(&instruction.operation, FlowOperation::TestEmit { .. }))
            .count(),
        4,
        "one selected source test must produce the canonical four-event lifecycle"
    );
    assert_eq!(
        flow_model
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(
                &instruction.operation,
                FlowOperation::TestFinish { .. }
            ))
            .count(),
        1
    );
    let core_add = flow_model
        .functions
        .iter()
        .find(|function| function.name == "wrela-core@0.1.0::time::add")
        .expect("installed core.time.add is reachable");
    assert!(core_add.blocks.iter().flat_map(|block| &block.instructions).any(
        |instruction| matches!(
            &instruction.operation,
            FlowOperation::Binary {
                op: FlowBinaryOp::AddChecked,
                ..
            }
        ) && matches!(instruction.source, Some(source) if source.file == fixture.core_time_file)
    ));
    let core_as_nanoseconds = flow_model
        .functions
        .iter()
        .find(|function| function.name == "wrela-core@0.1.0::time::as_nanoseconds")
        .expect("installed core.time.as_nanoseconds is reachable");
    assert!(core_as_nanoseconds.blocks.iter().flat_map(|block| &block.instructions).any(
        |instruction| matches!(
            &instruction.operation,
            FlowOperation::ExtractField { field: 0, .. }
        ) && matches!(instruction.source, Some(source) if source.file == fixture.core_time_file)
    ));

    let report = flow.report().clone();
    let mut exact_limits = FlowLoweringLimits::standard();
    // `installed_core_time_executes_in_qemu`'s body ends in a bounded `guard:
    // @test(runtime)` attribute (the mechanism that keeps
    // it out of the comptime tier); its FlowWir lowering reserves one more
    // block than the report's final trimmed count, so the tight bound below
    // needs a `+ 1` fudge a marker-free body would not.
    exact_limits.blocks = report.blocks + 1;
    exact_limits.instructions = report.instructions;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: exact_limits,
            },
            &never_cancelled,
        )
        .expect("exact FlowWir producer bounds pass");
    assert!(report.instructions > 1);
    let mut one_instruction_under = exact_limits;
    one_instruction_under.instructions -= 1;
    assert_eq!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: one_instruction_under,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir instructions",
            limit: one_instruction_under.instructions,
        })
    );

    let successful_polls = Cell::new(0_u32);
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: exact_limits,
            },
            &|| {
                successful_polls.set(successful_polls.get().saturating_add(1));
                false
            },
        )
        .expect("count runtime FlowWir cancellation polls");
    let cancel_at = successful_polls.get().saturating_sub(1);
    assert!(cancel_at > 1);
    let cancelled_polls = Cell::new(0_u32);
    assert_eq!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic,
                limits: exact_limits,
            },
            &|| {
                let next = cancelled_polls.get().saturating_add(1);
                cancelled_polls.set(next);
                next == cancel_at
            },
        ),
        Err(FlowLowerError::Cancelled)
    );
    assert_eq!(cancelled_polls.get(), cancel_at);

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("canonical installed core.time FlowWir frame");
    let (build, target) = analysis_build(&fixture);
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("real backend consumes installed core.time FlowWir");
    let machine = prepared.machine().wir().as_wir();
    assert!(machine.functions.iter().any(|function| matches!(
        function.origin,
        MachineFunctionOrigin::GeneratedTestHarness { .. }
    )));
    assert!(machine.functions.iter().flat_map(|function| &function.blocks).flat_map(
        |block| &block.instructions
    ).any(|instruction| matches!(
        &instruction.operation,
        MachineOperation::CheckedInteger {
            op: CheckedIntegerOp::Add,
            ..
        }
    ) && matches!(instruction.source, Some(source) if source.file == fixture.core_time_file)));
    assert!(machine.functions.iter().flat_map(|function| &function.blocks).flat_map(
        |block| &block.instructions
    ).any(|instruction| matches!(
        &instruction.operation,
        MachineOperation::Convert {
            op: ConversionOp::Bitcast,
            ..
        }
    ) && matches!(instruction.source, Some(source) if source.file == fixture.core_time_file)));

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(CodegenError::BackendNotBuilt) => {
            panic!("LLVM reports available but rejected installed core.time runtime emission")
        }
        Err(error) => panic!("installed core.time runtime object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeat installed core.time runtime object emission");
            assert_eq!(first, second);
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            assert_core_time_object_links_with_checked_in_runtime(
                &first,
                &prepared,
                HASHER.sha256(encoded.bytes()),
                &build,
                &target,
            );
        }
    }
}

fn assert_core_time_object_links_with_checked_in_runtime(
    object: &ObjectArtifact,
    prepared: &PreparedBackendInput,
    flow_wir_digest: Sha256Digest,
    build: &wrela_build_model::ValidatedBuildConfiguration,
    target: &TargetPackage,
) {
    let generated_facts = ordinary_coff_facts(object.bytes());
    assert_only_reviewed_duplicate_unwind_sections(&generated_facts.physical_section_names);

    let directory = TestDirectory::new();
    let generated = directory.write("core-time.obj", object.bytes());
    let runtime =
        fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
        ))
        .expect("checked-in enrolled runtime object");
    let runtime_bytes = fs::read(&runtime).expect("checked-in runtime bytes");
    let runtime_facts = ordinary_coff_facts(&runtime_bytes);
    let output = directory.root.join("core-time.efi");
    let map = directory.root.join("core-time.map");
    let provenance_map = appended_path(&map, ".lldmap");

    let object_inspector = CanonicalCoffObjectInspector::new();
    let generated_measurement = object_inspector
        .inspect(
            &generated,
            LinkLimits::standard().object_bytes,
            &never_cancelled,
        )
        .expect("real core.time object inspection");
    let runtime_measurement = object_inspector
        .inspect(
            &runtime,
            LinkLimits::standard().object_bytes,
            &never_cancelled,
        )
        .expect("checked-in runtime object inspection");
    let objects = [
        CoffObject {
            ordinal: 0,
            path: &generated,
            expected_digest: generated_measurement.digest,
            expected_bytes: generated_measurement.bytes,
            kind: CoffObjectKind::Image {
                build: build.identity().clone(),
            },
        },
        CoffObject {
            ordinal: 1,
            path: &runtime,
            expected_digest: runtime_measurement.digest,
            expected_bytes: runtime_measurement.bytes,
            kind: CoffObjectKind::TargetRuntime {
                target_package: target.backend().content_digest(),
                runtime_abi_version: target.backend().runtime_abi_version(),
            },
        },
    ];
    let exact_object_bytes = generated_measurement
        .bytes
        .max(runtime_measurement.bytes)
        .max(generated_facts.uninitialized_bytes)
        .max(runtime_facts.uninitialized_bytes);
    let initial_limits = LinkLimits {
        objects: 2,
        object_bytes: exact_object_bytes,
        ..LinkLimits::standard()
    };
    let request = LinkRequest {
        build: build.identity(),
        objects: &objects,
        target: target.backend(),
        output: &output,
        map_output: &map,
        limits: initial_limits,
    };
    let image_inspector = CanonicalLinkedImageInspector::new();
    let linker = LldEfiLinker {
        object_inspector: &object_inspector,
        image_inspector: &image_inspector,
    };

    let one_byte_under_limit = exact_object_bytes
        .checked_sub(1)
        .expect("nonempty exact object byte bound");
    let one_byte_under = LinkRequest {
        limits: LinkLimits {
            object_bytes: one_byte_under_limit,
            ..initial_limits
        },
        ..request
    };
    assert!(matches!(
        linker.link(&one_byte_under, &never_cancelled),
        Err(LinkError::ObjectInspect {
            path,
            error: CoffInspectError::LimitExceeded {
                resource: "COFF uninitialized bytes",
                limit,
                actual,
            },
        }) if path == runtime
            && limit == one_byte_under_limit
            && actual == runtime_facts.uninitialized_bytes
    ));
    assert_link_outputs_absent(&output, &map, &provenance_map);
    assert!(matches!(
        linker.link(&request, &|| true),
        Err(LinkError::Cancelled)
    ));
    assert_link_outputs_absent(&output, &map, &provenance_map);

    let first = linker
        .link(&request, &never_cancelled)
        .expect("real core.time object and checked-in runtime EFI link");
    assert_eq!(first.path(), output);
    assert_eq!(first.map(), map);
    assert_eq!(first.build(), build.identity());
    assert_eq!(
        first.measurements().artifact_bytes,
        fs::metadata(&output).expect("linked EFI metadata").len()
    );
    assert!(
        first
            .measurements()
            .artifact_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
    );
    assert!(!provenance_map.exists());
    let first_image = fs::read(&output).expect("first linked EFI bytes");
    let first_map = fs::read(&map).expect("first linked map bytes");

    let input_sections = generated_facts
        .physical_section_names
        .len()
        .checked_add(runtime_facts.physical_section_names.len())
        .expect("input section count");
    let input_symbols = u64::from(generated_facts.symbols)
        .checked_add(u64::from(runtime_facts.symbols))
        .expect("input symbol count");
    let input_relocations = generated_facts
        .relocations
        .checked_add(runtime_facts.relocations)
        .expect("input relocation count");
    let exception_records = first
        .measurements()
        .sections
        .iter()
        .find(|section| section.name == ".pdata")
        .map(|section| {
            assert_eq!(section.virtual_bytes % 8, 0);
            section.virtual_bytes / 8
        })
        .filter(|records| *records > 0)
        .expect("linked ARM64 exception records");
    let exact_limits =
        LinkLimits {
            objects: 2,
            object_bytes: exact_object_bytes,
            sections: u32::try_from(input_sections.max(first.measurements().sections.len()))
                .expect("exact section limit"),
            symbols: u32::try_from(input_symbols.max(
                u64::try_from(first.measurements().symbols.len()).expect("linked symbol count"),
            ))
            .expect("exact symbol limit"),
            base_relocations: u32::try_from(
                input_relocations.max(u64::from(first.measurements().base_relocations)),
            )
            .expect("exact relocation limit"),
            exception_records: u32::try_from(exception_records).expect("exact exception limit"),
            ..LinkLimits::standard()
        };
    fs::remove_file(&output).expect("remove first linked EFI");
    fs::remove_file(&map).expect("remove first linked map");
    let exact_request = LinkRequest {
        limits: exact_limits,
        ..request
    };
    let exact = linker
        .link(&exact_request, &never_cancelled)
        .expect("publicly observable exact core.time EFI link limits");
    assert_eq!(exact.build(), build.identity());
    assert_eq!(exact.measurements(), first.measurements());
    assert_eq!(
        fs::read(&output).expect("exact linked EFI bytes"),
        first_image
    );
    assert_eq!(fs::read(&map).expect("exact linked map bytes"), first_map);
    assert!(!provenance_map.exists());

    let report = CanonicalBackendReportAssembler::new()
        .assemble(
            BackendReportRequest {
                flow_wir_digest,
                optimized: prepared.optimized(),
                machine: prepared.machine(),
                object,
                artifact: &exact,
                target,
                analysis_fact_limits: wrela_image_report::AnalysisFactLimits::standard(),
                fact_limits: wrela_image_report::BackendFactLimits::standard(),
                maximum_report_bytes: 1024 * 1024 * 1024,
            },
            &never_cancelled,
        )
        .expect("linked core.time image report");
    assert_eq!(report.as_report().build(), build.identity());
    assert_eq!(
        report.as_report().backend().artifact_digest,
        exact.measurements().artifact_digest
    );
    assert_eq!(
        report.as_report().backend().artifact_bytes,
        exact.measurements().artifact_bytes
    );
}

struct OrdinaryCoffFacts {
    physical_section_names: Vec<[u8; 8]>,
    symbols: u32,
    relocations: u64,
    uninitialized_bytes: u64,
}

fn ordinary_coff_facts(bytes: &[u8]) -> OrdinaryCoffFacts {
    const HEADER_BYTES: usize = 20;
    const SECTION_BYTES: usize = 40;
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    assert!(bytes.len() >= HEADER_BYTES, "ordinary COFF header");
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0xaa64);
    let section_count = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    let symbols = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let optional_header = usize::from(u16::from_le_bytes([bytes[16], bytes[17]]));
    assert_eq!(optional_header, 0, "ordinary COFF has no optional header");
    let table_start = HEADER_BYTES
        .checked_add(optional_header)
        .expect("COFF section-table start");
    let table_end = table_start
        .checked_add(
            section_count
                .checked_mul(SECTION_BYTES)
                .expect("COFF section-table bytes"),
        )
        .expect("COFF section-table end");
    assert!(table_end <= bytes.len(), "complete COFF section table");
    let mut physical_section_names = Vec::with_capacity(section_count);
    let mut relocations = 0_u64;
    let mut uninitialized_bytes = 0_u64;
    for index in 0..section_count {
        let start = table_start + index * SECTION_BYTES;
        physical_section_names.push(
            bytes[start..start + 8]
                .try_into()
                .expect("physical COFF section name"),
        );
        relocations = relocations
            .checked_add(u64::from(u16::from_le_bytes([
                bytes[start + 32],
                bytes[start + 33],
            ])))
            .expect("COFF relocation count");
        let characteristics = u32::from_le_bytes(
            bytes[start + 36..start + 40]
                .try_into()
                .expect("COFF section characteristics"),
        );
        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            let raw_bytes = u64::from(u32::from_le_bytes(
                bytes[start + 16..start + 20]
                    .try_into()
                    .expect("COFF section raw byte extent"),
            ));
            uninitialized_bytes = uninitialized_bytes
                .checked_add(raw_bytes)
                .expect("COFF uninitialized byte extent");
        }
    }
    OrdinaryCoffFacts {
        physical_section_names,
        symbols,
        relocations,
        uninitialized_bytes,
    }
}

fn assert_only_reviewed_duplicate_unwind_sections(names: &[[u8; 8]]) {
    const PDATA: [u8; 8] = *b".pdata\0\0";
    const XDATA: [u8; 8] = *b".xdata\0\0";
    let mut counts = BTreeMap::new();
    for name in names {
        *counts.entry(*name).or_insert(0_usize) += 1;
    }
    let repeated = counts
        .into_iter()
        .filter_map(|(name, count)| (count > 1).then_some(name))
        .collect::<Vec<_>>();
    assert!(
        !repeated.is_empty(),
        "real core.time object must exercise repeated ARM64 unwind sections"
    );
    assert!(
        repeated.iter().all(|name| matches!(*name, PDATA | XDATA)),
        "only reviewed .pdata/.xdata physical names may repeat: {repeated:?}"
    );
}

fn appended_path(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut encoded = path.as_os_str().to_os_string();
    encoded.push(suffix);
    PathBuf::from(encoded)
}

fn assert_link_outputs_absent(
    output: &std::path::Path,
    map: &std::path::Path,
    provenance: &std::path::Path,
) {
    for path in [output, map, provenance] {
        assert!(!path.exists(), "failed link retained {}", path.display());
    }
}

#[test]
fn selected_installed_core_time_pass_has_canonical_cancellable_analysis_facts() {
    let fixture = source_fixture(APPLICATION_SOURCE);
    let analysis = compile_selected_analysis(&fixture, PASS_SELECTOR);
    let structures = analysis
        .facts()
        .types
        .iter()
        .filter(|ty| matches!(ty.kind, wrela_sema::SemanticTypeKind::Structure { .. }))
        .collect::<Vec<_>>();
    let [duration] = structures.as_slice() else {
        panic!("selected core.time image must retain exactly one source structure type");
    };
    let wrela_sema::SemanticTypeKind::Structure {
        declaration,
        arguments,
        fields,
    } = &duration.kind
    else {
        unreachable!("filtered source structure type");
    };
    assert!(arguments.is_empty());
    let [nanoseconds] = fields.as_slice() else {
        panic!("Duration must retain exactly one semantic field");
    };
    assert_eq!(nanoseconds.name, "nanoseconds");
    assert!(!nanoseconds.public);
    let nanoseconds_type = analysis
        .facts()
        .types
        .get(nanoseconds.ty.0 as usize)
        .filter(|ty| ty.id == nanoseconds.ty)
        .expect("Duration.nanoseconds semantic type");
    assert!(matches!(
        nanoseconds_type.kind,
        wrela_sema::SemanticTypeKind::Integer {
            signed: false,
            bits: 64,
            pointer_sized: false,
        }
    ));
    assert_eq!(duration.linearity, wrela_sema::Linearity::ExplicitCopy);
    assert_eq!(duration.size_upper_bound, Some(8));
    assert_eq!(duration.alignment_lower_bound, 8);
    let declaration = fixture
        .hir
        .as_program()
        .declaration(*declaration)
        .expect("Duration HIR declaration");
    assert_eq!(
        declaration.name.as_ref().map(wrela_hir::Name::as_str),
        Some("Duration")
    );
    assert_eq!(duration.source, Some(declaration.source));
    let wrela_hir::DeclarationKind::Structure(aggregate) = &declaration.kind else {
        panic!("Duration semantic structure must name a HIR structure");
    };
    assert!(aggregate.generics.is_empty());
    assert!(aggregate.implements.is_empty());
    let [hir_nanoseconds] = aggregate.fields.as_slice() else {
        panic!("Duration HIR declaration must contain exactly one field");
    };
    assert_eq!(hir_nanoseconds.name.as_str(), "nanoseconds");
    assert_eq!(hir_nanoseconds.visibility, wrela_hir::Visibility::Private);
    assert!(hir_nanoseconds.attributes.is_empty());
    assert!(hir_nanoseconds.default.is_none());
    assert!(matches!(
        &hir_nanoseconds.ty.kind,
        wrela_hir::TypeExpressionKind::Named {
            definition: wrela_hir::Definition::Builtin(wrela_hir::Builtin::U64),
            arguments,
        } if arguments.is_empty()
    ));

    let limits = PipelineLimits::standard().analysis_facts;
    let assembler = CanonicalAnalysisFactAssembler::new();
    let facts = assembler
        .assemble(
            AnalysisFactRequest {
                analysis: &analysis,
                limits,
            },
            &never_cancelled,
        )
        .expect("selected installed core.time image has canonical analysis facts");
    assert_eq!(facts.build(), &analysis.facts().build);
    assert_eq!(
        facts.image_name(),
        analysis
            .facts()
            .graph
            .as_ref()
            .expect("selected runtime image graph")
            .name
    );
    assert_eq!(facts.limits(), limits);
    assert_eq!(
        facts.as_facts().compiled_test_group,
        analysis.facts().compiled_test_group
    );
    let mut expected_declarations = analysis
        .facts()
        .functions
        .iter()
        .filter_map(|function| match function.origin {
            wrela_sema::FunctionOrigin::Source { declaration, .. } => Some(declaration),
            _ => None,
        })
        .collect::<Vec<_>>();
    expected_declarations.push(declaration.id);
    expected_declarations.sort_unstable();
    expected_declarations.dedup();
    assert_eq!(
        facts.as_facts().reachable_declarations,
        u64::try_from(expected_declarations.len()).expect("retained declaration count fits u64")
    );

    let retained = facts.as_facts();
    let vector_items = [
        retained.bounds.len(),
        retained.proofs.len(),
        retained.actor_lowerings.len(),
        retained.image_nodes.len(),
        retained.region_capacity_evidence.len(),
        retained.activation_frame_evidence.len(),
        retained.image_edges.len(),
        retained.work.len(),
        retained.hardware.len(),
        retained.recovery.len(),
        retained.startup_order.len(),
        retained.shutdown_order.len(),
    ]
    .into_iter()
    .try_fold(0_u64, |total, count| {
        total.checked_add(u64::try_from(count).ok()?)
    })
    .expect("retained analysis fact item count fits u64");
    let compiled_group = retained
        .compiled_test_group
        .as_ref()
        .expect("selected image retains its compiled test group");
    assert_eq!(compiled_group.tests.len(), 1);
    let compiled_group_items = 1_u64
        .checked_add(
            u64::try_from(compiled_group.tests.len()).expect("compiled test count fits u64"),
        )
        .expect("compiled group item count fits u64");
    assert_eq!(compiled_group_items, 2);
    let exact_items = vector_items
        .checked_add(compiled_group_items)
        .expect("complete retained analysis item count fits u64");
    assert!(exact_items > 1);
    let exact_limits = wrela_image_report::AnalysisFactLimits {
        items: exact_items,
        ..limits
    };
    let exact = assembler
        .assemble(
            AnalysisFactRequest {
                analysis: &analysis,
                limits: exact_limits,
            },
            &never_cancelled,
        )
        .expect("exact retained analysis-fact item bound passes");
    assert_eq!(exact.as_facts(), retained);
    let one_item_under = wrela_image_report::AnalysisFactLimits {
        items: exact_items - 1,
        ..exact_limits
    };
    assert_eq!(
        assembler.assemble(
            AnalysisFactRequest {
                analysis: &analysis,
                limits: one_item_under,
            },
            &never_cancelled,
        ),
        Err(wrela_compiler::AnalysisFactAssemblyError::ResourceLimit {
            resource: "analysis fact items",
            limit: one_item_under.items,
        })
    );

    let successful_polls = Cell::new(0_u32);
    assembler
        .assemble(
            AnalysisFactRequest {
                analysis: &analysis,
                limits: exact_limits,
            },
            &|| {
                successful_polls.set(successful_polls.get().saturating_add(1));
                false
            },
        )
        .expect("count installed core.time analysis-fact cancellation polls");
    let cancel_at = successful_polls.get().saturating_sub(1);
    assert!(cancel_at > 1);
    let cancelled_polls = Cell::new(0_u32);
    assert_eq!(
        assembler.assemble(
            AnalysisFactRequest {
                analysis: &analysis,
                limits: exact_limits,
            },
            &|| {
                let next = cancelled_polls.get().saturating_add(1);
                cancelled_polls.set(next);
                next == cancel_at
            },
        ),
        Err(wrela_compiler::AnalysisFactAssemblyError::Cancelled)
    );
    assert_eq!(cancelled_polls.get(), cancel_at);
}

#[test]
fn typed_runtime_failure_and_source_diagnostic_remain_exact() {
    let fixture = source_fixture(APPLICATION_SOURCE);
    let semantic = compile_selected(&fixture, FAILURE_SELECTOR);
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("typed failure lowers to FlowWir");
    let (flow_wir, _, diagnostics) = flow.into_parts();
    assert!(diagnostics.is_empty());
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("typed failure canonical frame");
    let (build, target) = analysis_build(&fixture);
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("typed failure reaches real backend preparation");
    let shifts = prepared
        .machine()
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match &instruction.operation {
            // `typed_checked_failure_reaches_qemu`'s body ends in a bounded
            // `@test(runtime)` attribute (the mechanism that keeps
            // it out of the comptime tier); its `+= 1` also lowers to a
            // `CheckedInteger::Add` in this same function, which this
            // exercise is not about, so only the shift variant is collected.
            MachineOperation::CheckedInteger {
                op: op @ (CheckedIntegerOp::ShiftLeft | CheckedIntegerOp::ShiftLeftWrapping),
                ..
            } if matches!(instruction.source, Some(source) if source.file == fixture.application_file) =>
            {
                Some(*op)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(shifts, [CheckedIntegerOp::ShiftLeft]);
    assert_eq!(
        shifts[0]
            .invalid_shift_count_fatal_code()
            .expect("typed shift has exact runtime cause")
            .as_u32(),
        6
    );

    let invalid_source = APPLICATION_SOURCE.replacen("ns(42)", "ns(true)", 1);
    assert_ne!(invalid_source, APPLICATION_SOURCE);
    let invalid = source_fixture(&invalid_source);
    let output = discover(&invalid, PASS_SELECTOR)
        .expect("source-aware type rejection is an analysis result");
    assert!(output.successful().is_none());
    let diagnostic = output
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_deref() == Some("semantic-literal-type-mismatch"))
        .expect("installed core.time argument type diagnostic");
    assert_eq!(diagnostic.primary.file, invalid.application_file);
    assert_eq!(
        invalid
            .sources
            .span_text(diagnostic.primary)
            .expect("diagnostic source text"),
        "true"
    );
}

#[test]
fn cancelled_public_test_driver_creates_no_output_or_artifact() {
    let directory = TestDirectory::new();
    let output = directory.root.join("cancelled-output");
    let manifest = fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../std/examples/stdlib-time-runtime/wrela.toml"),
    )
    .expect("canonical runtime manifest");
    let workspace = WorkspaceSelection {
        manifest,
        image: IMAGE_NAME.to_owned(),
        target: TargetIdentity::aarch64_qemu_virt_uefi(),
        profile: "development".to_owned(),
    };
    let driver = LocalTestDriver::new(
        Toolchain::at(directory.root.join("unused-toolchain")),
        PipelineLimits::standard(),
    )
    .expect("compose cancellable public test driver");
    let result = driver.execute(
        &Command::Test {
            workspace,
            output_directory: output.clone(),
            selection: TestSelection::NameContains(PASS_SELECTOR.to_owned()),
            diagnostics: DiagnosticOptions::default(),
        },
        &SilentEvents,
        &|| true,
    );
    assert!(matches!(result, Err(DriverError::Cancelled)));
    assert!(!output.exists(), "cancelled test published an output tree");
}

fn compile_selected(
    fixture: &SourceFixture,
    selector: &str,
) -> wrela_semantic_lower::semantic_wir::ValidatedSemanticWir {
    let analyzed = compile_selected_analysis(fixture, selector);
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("selected runtime test lowers to SemanticWir")
        .into_parts()
        .0
}

fn compile_selected_analysis(fixture: &SourceFixture, selector: &str) -> wrela_sema::AnalyzedImage {
    let discovery = discover(fixture, selector)
        .unwrap_or_else(|error| panic!("{selector} discovery failed: {error}"));
    assert!(
        discovery.diagnostics().is_empty(),
        "{selector} discovery diagnostics: {:?}",
        discovery.diagnostics()
    );
    let discovered = discovery.successful().expect("sealed runtime discovery");
    let plan = discovered
        .facts()
        .test_plan
        .as_ref()
        .expect("runtime test plan")
        .clone();
    assert!(plan.unit_tests().is_empty());
    let [group] = plan.image_groups() else {
        panic!("selector must produce exactly one image group");
    };
    let [test] = group.tests.as_slice() else {
        panic!("selector must select exactly one runtime test");
    };
    assert_eq!(test.descriptor.id, TestId(0));
    assert_eq!(test.descriptor.kind, TestKind::IntegrationImage);
    assert_eq!(test.descriptor.timeout_ns, 30_000_000_000);
    assert_eq!(
        test.descriptor.name,
        format!("{IMAGE_NAME}@0.1.0::runtime.time_test::{selector}")
    );
    let group_id = group.id;
    let (build, target) = analysis_build(fixture);
    let compilation = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&fixture.hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group: group_id,
                    declared_entry: None,
                },
                changes: &AnalysisChangeSet {
                    previous_source_graph: None,
                    changed_declarations: Vec::new(),
                },
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .unwrap_or_else(|error| panic!("{selector} compilation failed: {error}"));
    assert!(
        compilation.diagnostics().is_empty(),
        "{selector} compilation diagnostics: {:?}",
        compilation.diagnostics()
    );
    compilation
        .into_parts()
        .0
        .expect("sealed selected runtime test image")
}

fn discover(
    fixture: &SourceFixture,
    selector: &str,
) -> Result<wrela_sema::AnalysisOutput, wrela_sema::AnalysisFailure> {
    let (build, target) = analysis_build(fixture);
    CanonicalSemanticAnalyzer::new().analyze(
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: wrela_package::PackageId(1),
            target: target.semantic(),
            build: &build,
            mode: AnalysisMode::DiscoverTests {
                image_name: IMAGE_NAME,
                image_entry: fixture.entry,
                declared_image_tests: &[],
                source_selection: TestDiscoverySelection::NameContains(selector),
            },
            changes: &AnalysisChangeSet {
                previous_source_graph: None,
                changed_declarations: Vec::new(),
            },
            limits: AnalysisLimits::standard(),
        },
        &never_cancelled,
    )
}

fn source_fixture(application_source: &str) -> SourceFixture {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("runtime manifest");
    let core_manifest = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("core manifest");
    let root_identity = PackageIdentity {
        name: manifest.name,
        version: manifest.version,
        source_digest: package_content_digest(
            WORKSPACE_MANIFEST,
            &[content_record("runtime/time_test.wr", application_source)],
            &HASHER,
            &never_cancelled,
        )
        .expect("runtime source identity"),
    };
    let core_identity = PackageIdentity {
        name: core_manifest.name,
        version: core_manifest.version,
        source_digest: package_content_digest(
            CORE_MANIFEST,
            &[
                content_record("image.wr", CORE_IMAGE_SOURCE),
                content_record("ops.wr", CORE_OPS_SOURCE),
                content_record("option.wr", CORE_OPTION_SOURCE),
                content_record("panic.wr", CORE_PANIC_SOURCE),
                content_record("result.wr", CORE_RESULT_SOURCE),
                content_record("time.wr", CORE_TIME_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("core source identity"),
    };
    let mut sources = SourceDatabase::default();
    let core_image_file = add_source(&mut sources, SOURCE_PATHS[0], CORE_IMAGE_SOURCE);
    let core_ops_file = add_source(&mut sources, SOURCE_PATHS[1], CORE_OPS_SOURCE);
    let core_time_file = add_source(&mut sources, SOURCE_PATHS[2], CORE_TIME_SOURCE);
    let application_file = add_source(&mut sources, SOURCE_PATHS[3], application_source);
    assert_eq!(
        sources
            .files()
            .iter()
            .map(wrela_source::SourceFile::path)
            .collect::<Vec<_>>(),
        SOURCE_PATHS
    );
    let mut graph = PackageGraphBuilder::new(root_identity.clone());
    let core = graph.add_package(core_identity).expect("core package");
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
            ModulePath::new(["runtime".to_owned(), "time_test".to_owned()])
                .expect("runtime module path"),
            application_file,
        )
        .expect("runtime module");
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module path"),
            core_image_file,
        )
        .expect("core image module");
    graph
        .add_module(
            core,
            ModulePath::new(["ops".to_owned()]).expect("core ops module path"),
            core_ops_file,
        )
        .expect("core ops module");
    graph
        .add_module(
            core,
            ModulePath::new(["time".to_owned()]).expect("core time module path"),
            core_time_file,
        )
        .expect("core time module");
    let parsed_files = sources
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
                .expect("runtime source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();
    let lowered = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("package graph")),
                source_graph_digest: root_identity.source_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &HirChangeSet {
                    previous_source_graph: None,
                    changed_files: Vec::new(),
                },
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime source lowers to HIR");
    assert!(
        lowered.diagnostics().is_empty(),
        "HIR diagnostics: {:?}",
        lowered.diagnostics()
    );
    let entry = *lowered
        .lowered()
        .program()
        .as_program()
        .image_candidates
        .first()
        .expect("runtime image entry");
    SourceFixture {
        hir: Arc::new(lowered.into_parts().0.into_program()),
        sources,
        application_file,
        core_time_file,
        entry,
        root_identity,
        profile: BuildProfile::development(),
    }
}

fn analysis_build(
    fixture: &SourceFixture,
) -> (
    wrela_build_model::ValidatedBuildConfiguration,
    TargetPackage,
) {
    let profile_digest = Sha256Digest::from_bytes([0xa1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xa2; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xa3; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xa4; 32]),
                source_graph: fixture.root_identity.source_digest,
                request: Sha256Digest::from_bytes([0xa5; 32]),
                profile: profile_digest,
            },
            profile: fixture.profile.clone(),
        },
        profile_digest,
    )
    .expect("runtime build configuration");
    (build, TargetPackage::aarch64_qemu_virt_uefi(target_digest))
}

fn canonical_workspace() -> (wrela_package::PackageManifest, PackageIdentity) {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in runtime manifest");
    // The checked-in manifest declares only `[[profile]]` overrides and no
    // `[[module]]` block (modules are derived by the loader, not decoded
    // here), so it need not be byte-identical to its own canonical
    // re-encoding; every digest below binds the canonical bytes, exactly as
    // the production loader does.
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical runtime manifest");
    assert_eq!(
        codec
            .decode_manifest(&canonical_manifest, manifest_limits(), &never_cancelled)
            .expect("redecode canonical runtime manifest"),
        manifest
    );
    let core_manifest = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in core manifest");
    let canonical_core_manifest = codec
        .canonical_manifest(&core_manifest, manifest_limits(), &never_cancelled)
        .expect("canonical core manifest");
    let root_identity = PackageIdentity {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_manifest,
            &[content_record("runtime/time_test.wr", APPLICATION_SOURCE)],
            &HASHER,
            &never_cancelled,
        )
        .expect("runtime package identity"),
    };
    // There is no lockfile to also cross-check against; computing the core
    // package's identity still exercises that its checked-in manifest and
    // sources hash without error, exactly as the loader itself would
    // independently do when it resolves the reserved `core` alias via the
    // toolchain rather than a recorded locator.
    let _core_identity = PackageIdentity {
        name: core_manifest.name.clone(),
        version: core_manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_core_manifest,
            &[
                content_record("image.wr", CORE_IMAGE_SOURCE),
                content_record("ops.wr", CORE_OPS_SOURCE),
                content_record("option.wr", CORE_OPTION_SOURCE),
                content_record("panic.wr", CORE_PANIC_SOURCE),
                content_record("result.wr", CORE_RESULT_SOURCE),
                content_record("time.wr", CORE_TIME_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("core package identity"),
    };
    (manifest, root_identity)
}

fn add_source(sources: &mut SourceDatabase, path: &str, text: &str) -> FileId {
    sources
        .add(SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: HASHER.sha256(text.as_bytes()),
        })
        .expect("bounded runtime source")
}

fn content_record<'a>(path: &'a str, source: &str) -> PackageContentRecord<'a> {
    PackageContentRecord {
        kind: PackageContentKind::Source,
        path,
        digest: HASHER.sha256(source.as_bytes()),
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

const fn never_cancelled() -> bool {
    false
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
        for _ in 0..128 {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "wrela-stdlib-time-runtime-{}-{sequence:016x}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Self {
                        root: fs::canonicalize(root).expect("canonical fixture root"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create fixture: {error}"),
            }
        }
        panic!("cannot allocate fixture directory")
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).expect("create private fixture file");
        file.write_all(bytes).expect("write private fixture file");
        file.sync_all().expect("seal private fixture file");
        drop(file);
        fs::canonicalize(path).expect("canonical private fixture file")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
