use wrela_runtime_abi as abi;

const RUNTIME_SOURCE: &str =
    include_str!("../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime.S");
const RUNTIME_OBJECT_LOCK: &str = include_str!(
    "../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml"
);
const RUNTIME_OBJECT: &[u8] = include_bytes!(
    "../../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj"
);

#[derive(Debug)]
struct RuntimeSourceFixture {
    intrinsic: abi::RuntimeIntrinsic,
    symbol: &'static str,
    parameters: &'static [abi::AbiType],
    result: abi::AbiType,
    effect: abi::RuntimeEffect,
    may_return: bool,
}

const RUNTIME_SOURCE_FIXTURE: [RuntimeSourceFixture; abi::RUNTIME_INTRINSIC_COUNT] = [
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::ImageEnter,
        symbol: "wrela_rt_v2_image_enter",
        parameters: &[abi::AbiType::Address, abi::AbiType::Address],
        result: abi::AbiType::Status,
        effect: abi::RuntimeEffect::EnterImage,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::ImageExit,
        symbol: "wrela_rt_v2_image_exit",
        parameters: &[abi::AbiType::Status],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::ExitImage,
        may_return: false,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::Fatal,
        symbol: "wrela_rt_v2_fatal",
        parameters: &[abi::AbiType::U32, abi::AbiType::U64],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::FatalTermination,
        may_return: false,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::CpuIdle,
        symbol: "wrela_rt_v2_cpu_idle",
        parameters: &[],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::CpuIdle,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::InterruptMask,
        symbol: "wrela_rt_v2_interrupt_mask",
        parameters: &[],
        result: abi::AbiType::U64,
        effect: abi::RuntimeEffect::MaskInterrupts,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::InterruptRestore,
        symbol: "wrela_rt_v2_interrupt_restore",
        parameters: &[abi::AbiType::U64],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::RestoreInterrupts,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::CacheMaintain,
        symbol: "wrela_rt_v2_cache_maintain",
        parameters: &[abi::AbiType::Address, abi::AbiType::Usize, abi::AbiType::U8],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::MaintainCache,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::RecordEvent,
        symbol: "wrela_rt_v2_record_event",
        parameters: &[
            abi::AbiType::U32,
            abi::AbiType::Address,
            abi::AbiType::Usize,
        ],
        result: abi::AbiType::Status,
        effect: abi::RuntimeEffect::AppendRecord,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::ReplayEvent,
        symbol: "wrela_rt_v2_replay_event",
        parameters: &[
            abi::AbiType::U32,
            abi::AbiType::Address,
            abi::AbiType::Usize,
        ],
        result: abi::AbiType::Usize,
        effect: abi::RuntimeEffect::ConsumeReplay,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::TestEmit,
        symbol: "wrela_rt_v2_test_emit",
        parameters: &[abi::AbiType::Address, abi::AbiType::Usize],
        result: abi::AbiType::Status,
        effect: abi::RuntimeEffect::EmitTestFrame,
        may_return: true,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::TestFinish,
        symbol: "wrela_rt_v2_test_finish",
        parameters: &[abi::AbiType::U32],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::FinishTests,
        may_return: false,
    },
    RuntimeSourceFixture {
        intrinsic: abi::RuntimeIntrinsic::TestAssertionFail,
        symbol: "wrela_rt_v2_test_assertion_fail",
        parameters: &[
            abi::AbiType::Address,
            abi::AbiType::Usize,
            abi::AbiType::Address,
            abi::AbiType::Usize,
            abi::AbiType::U32,
            abi::AbiType::U32,
            abi::AbiType::U32,
        ],
        result: abi::AbiType::Unit,
        effect: abi::RuntimeEffect::FailTestAssertion,
        may_return: false,
    },
];

#[test]
fn uefi_codegen_fixture_matches_the_exact_aarch64_handoff() {
    let entry = abi::AARCH64_UEFI_IMAGE_ENTRY;
    assert_eq!(entry.symbol, "wrela_image_entry");
    assert_eq!(
        entry.calling_convention,
        abi::AbiCallingConvention::UefiAarch64
    );
    assert_eq!(
        entry.parameters,
        [abi::AbiType::Address, abi::AbiType::Address]
    );
    assert_eq!(entry.result, abi::AbiType::Status);
    assert_eq!(entry.argument_registers, [0, 1]);
    assert_eq!(entry.result_register, 0);
    assert_eq!(entry.return_address_register, 30);
    assert_eq!(entry.stack_alignment_bytes, 16);
    assert_eq!(entry.reserved_platform_register, 18);
    assert!(entry.little_endian);
}

#[test]
fn runtime_source_fixture_matches_every_symbol_signature_and_effect() {
    assert_eq!(
        abi::ALL_RUNTIME_INTRINSICS,
        RUNTIME_SOURCE_FIXTURE.map(|fixture| fixture.intrinsic)
    );
    for fixture in &RUNTIME_SOURCE_FIXTURE {
        let signature = fixture.intrinsic.signature();
        assert_eq!(fixture.intrinsic.symbol_name(), fixture.symbol);
        assert_eq!(signature.intrinsic, fixture.intrinsic);
        assert_eq!(
            signature.calling_convention,
            abi::AbiCallingConvention::Aapcs64
        );
        assert_eq!(signature.parameters, fixture.parameters);
        assert_eq!(signature.result, fixture.result);
        assert_eq!(signature.effect, fixture.effect);
        assert_eq!(signature.may_return, fixture.may_return);
        assert_eq!(signature.may_return, fixture.intrinsic.may_return());
    }
}

#[test]
fn assertion_runtime_is_the_only_dynamic_assertion_authority_and_requires_one_active_test() {
    for required_source in [
        ".globl wrela_rt_v2_test_assertion_fail",
        "b.ne    .Ltest_emit_check_run_finished",
        "ldrb    w8, [x24, #17]",
        "cbnz    w8, .Ltest_emit_corrupt",
        "WRELA_ADDR x8, .Ltest_declared_count\n    ldr     w9, [x8]\n    cmp     w9, #1\n    b.ne    .Lassert_invalid",
        "WRELA_ADDR x8, .Ltest_started_count\n    ldr     w9, [x8]\n    cmp     w9, #1\n    b.ne    .Lassert_invalid",
        "cbnz    w28, .Lassert_invalid",
        "cmp     x26, #2\n    b.ne    .Lassert_invalid",
        ".equ WRELA_ASSERT_TEXT_MAX,       4096",
        ".equ WRELA_ASSERT_FRAME_BYTES,    8320",
        ".ascii  \"assertion failed\"",
        "mov     w9, #3\n    strb    w9, [x19, #44]",
        "mov     w9, #1\n    strb    w9, [x19, #49]",
        "mov     w8, #6\n    strb    w8, [x19, #44]",
        "b       wrela_rt_v2_test_finish",
    ] {
        assert!(
            RUNTIME_SOURCE.contains(required_source),
            "runtime assertion source omitted {required_source:?}"
        );
    }
}

#[test]
fn runtime_fatal_codes_and_source_keep_typed_causes_distinct() {
    assert_eq!(abi::RuntimeFatalCode::Arithmetic.as_u32(), 1);
    assert_eq!(abi::RuntimeFatalCode::Conversion.as_u32(), 2);
    assert_eq!(abi::RuntimeFatalCode::ActorMailboxFull.as_u32(), 3);
    assert_eq!(abi::RuntimeFatalCode::ActorMailboxMismatch.as_u32(), 4);
    assert_eq!(abi::RuntimeFatalCode::CheckedShiftResultLoss.as_u32(), 5);
    assert_eq!(abi::RuntimeFatalCode::InvalidShiftCount.as_u32(), 6);
    for required_source in [
        ".equ WRELA_FATAL_CHECKED_SHIFT_RESULT_LOSS, 5",
        ".equ WRELA_FATAL_INVALID_SHIFT_COUNT, 6",
        ".equ WRELA_LANGUAGE_FATAL_RESULT_LOSS, 0",
        ".equ WRELA_LANGUAGE_FATAL_INVALID_COUNT, 1",
        ".equ WRELA_FATAL_FRAME_BUFFER_BYTES, 64",
        ".equ WRELA_FATAL_TEST_FINISHED_PAYLOAD_BYTES, 19",
        ".equ WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES, 21",
        "WRELA_ADDR x8, .Lfatal_detail\n    str     x1, [x8]",
        "cmp     w9, #1\n    b.ne    .Lfatal_mark_and_halt",
        "stur    x21, [x19, #36]",
        "stur    w22, [x19, #45]",
        "strb    w20, [x19, #50]",
        "b       wrela_rt_v2_test_finish",
    ] {
        assert!(
            RUNTIME_SOURCE.contains(required_source),
            "runtime source omitted {required_source:?}"
        );
    }
    let active_check = RUNTIME_SOURCE
        .find("WRELA_ADDR x8, .Ltest_active\n    ldar    w9, [x8]")
        .expect("fatal path checks active-test state");
    let frame_build = RUNTIME_SOURCE
        .find("/* TestFinished(active, LanguageFatal(cause))")
        .expect("fatal path builds a typed terminal event");
    assert!(active_check < frame_build);
    let detail_store = RUNTIME_SOURCE
        .find("WRELA_ADDR x8, .Lfatal_detail\n    str     x1, [x8]")
        .expect("fatal path stores packed provenance");
    assert!(detail_store < active_check);
}

#[test]
fn direct_typed_fatal_frames_are_exact_and_bounded() {
    const TEST: u32 = 0x0000_dbc0;
    const FATAL: [u8; 51] = [
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0xb6, 0xd2,
        0xa1, 0x6c, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0xc0, 0xdb, 0x00, 0x00, 0x03, 0x00,
    ];
    const RUN_FINISHED: [u8; 53] = [
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0xad, 0x30,
        0x72, 0xd7, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    let mut fatal_payload = Vec::new();
    fatal_payload.extend_from_slice(&3_u32.to_le_bytes());
    fatal_payload.extend_from_slice(&2_u64.to_le_bytes());
    fatal_payload.push(4);
    fatal_payload.extend_from_slice(&TEST.to_le_bytes());
    fatal_payload.push(3);
    fatal_payload.push(0);
    assert_eq!(canonical_test_frame(2, &fatal_payload), FATAL);

    let mut run_payload = Vec::new();
    run_payload.extend_from_slice(&3_u32.to_le_bytes());
    run_payload.extend_from_slice(&3_u64.to_le_bytes());
    run_payload.push(6);
    run_payload.extend_from_slice(&0_u32.to_le_bytes());
    run_payload.extend_from_slice(&1_u32.to_le_bytes());
    assert_eq!(canonical_test_frame(3, &run_payload), RUN_FINISHED);

    let mut exact = [0_u8; FATAL.len()];
    assert_eq!(write_complete_frame(&mut exact, &FATAL), Some(FATAL.len()));
    assert_eq!(exact, FATAL);
    let mut one_under = [0_u8; FATAL.len() - 1];
    assert_eq!(write_complete_frame(&mut one_under, &FATAL), None);
    let mut exact = [0_u8; RUN_FINISHED.len()];
    assert_eq!(
        write_complete_frame(&mut exact, &RUN_FINISHED),
        Some(RUN_FINISHED.len())
    );
    let mut one_under = [0_u8; RUN_FINISHED.len() - 1];
    assert_eq!(write_complete_frame(&mut one_under, &RUN_FINISHED), None);
}

#[test]
fn checked_in_runtime_object_is_bound_to_source_and_lock_without_layout_drift() {
    assert_eq!(RUNTIME_OBJECT.len(), 9_894);
    assert_eq!(
        u16::from_le_bytes([RUNTIME_OBJECT[0], RUNTIME_OBJECT[1]]),
        0xaa64
    );
    assert_eq!(
        u16::from_le_bytes([RUNTIME_OBJECT[2], RUNTIME_OBJECT[3]]),
        4
    );
    assert_eq!(
        u32::from_le_bytes(RUNTIME_OBJECT[4..8].try_into().expect("COFF timestamp")),
        0
    );
    let bss = (0..4)
        .map(|index| 20 + index * 40)
        .find(|offset| &RUNTIME_OBJECT[*offset..*offset + 8] == b".bss\0\0\0\0")
        .expect("canonical .bss section");
    assert_eq!(
        u32::from_le_bytes(
            RUNTIME_OBJECT[bss + 16..bss + 20]
                .try_into()
                .expect(".bss extent")
        ),
        73_984
    );
    for bound_fact in [
        "runtime_abi_version = 2",
        "source_sha256 = \"a2222ad923a15540b2017fddb5a7dd51b50f1df62a370d6d618a22d84683c4ed\"",
        "object_sha256 = \"530530151e0d0ffa2b2049d0b01dfdb40afe25a5de3f2577fd63447b5d7bb52a\"",
        "object_bytes = 9894",
        "relocations = 169",
        "undefined_symbols = 0",
    ] {
        assert!(
            RUNTIME_OBJECT_LOCK.contains(bound_fact),
            "runtime object lock omitted {bound_fact:?}"
        );
    }
}

fn canonical_test_frame(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"WRELTST\0");
    frame.extend_from_slice(&1_u32.to_le_bytes());
    frame.extend_from_slice(&3_u32.to_le_bytes());
    frame.extend_from_slice(&sequence.to_le_bytes());
    frame.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fixture payload fits u32")
            .to_le_bytes(),
    );
    frame.extend_from_slice(&crc32c(payload).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut checksum = !0_u32;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            checksum = (checksum >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(checksum & 1));
        }
    }
    !checksum
}

fn write_complete_frame(output: &mut [u8], frame: &[u8]) -> Option<usize> {
    if output.len() < frame.len() {
        return None;
    }
    output[..frame.len()].copy_from_slice(frame);
    Some(frame.len())
}

#[test]
fn runtime_object_and_storage_fixture_matches_the_inspected_object() {
    assert_eq!(
        abi::RUNTIME_OBJECT_PATH,
        "runtime/wrela-runtime-aarch64.obj"
    );
    assert_eq!(abi::RUNTIME_OBJECT_LAYOUT.coff_machine, 0xaa64);
    assert_eq!(abi::RUNTIME_OBJECT_LAYOUT.coff_timestamp, 0);
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT
            .sections
            .map(|section| section.name),
        [".text", ".data", ".bss", ".rdata"]
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT
            .sections
            .map(|section| section.alignment),
        [16, 4, 64, 8]
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.sections[0].extent,
        abi::SectionExtent::NonEmpty
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.sections[1].extent,
        abi::SectionExtent::Exact(0)
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.sections[2].extent,
        abi::SectionExtent::Exact(73_984)
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.sections[3].extent,
        abi::SectionExtent::Exact(24)
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.relocation_anchor_target,
        abi::RuntimeIntrinsic::ImageEnter
    );
    assert_eq!(
        abi::RUNTIME_OBJECT_LAYOUT.external_definitions,
        abi::ALL_RUNTIME_INTRINSICS
    );
    assert_eq!(abi::RUNTIME_OBJECT_LAYOUT.undefined_external_symbols, 0);
    let event_log = abi::EVENT_LOG_LAYOUT;
    assert_eq!(event_log.storage_bytes, 65_536);
    assert_eq!(event_log.record_region_bytes, 65_528);
    assert_eq!(event_log.overflow_marker_bytes, 8);
    assert_eq!(event_log.record_header_bytes, 8);
    assert_eq!(event_log.overflow_kind, u32::MAX);
    assert!(event_log.little_endian);
}

#[test]
fn canonical_contract_rejects_each_class_of_drift() {
    let canonical = abi::RuntimeAbiContract::canonical();
    canonical.validate().expect("canonical ABI v2 contract");

    let mut drift = canonical.clone();
    drift.version += 1;
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::UnsupportedVersion(3))
    );

    let mut drift = canonical.clone();
    drift.image_entry.argument_registers.swap(0, 1);
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::ImageEntryContractMismatch)
    );

    let mut drift = canonical.clone();
    drift.intrinsics[0].effect = abi::RuntimeEffect::ExitImage;
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::IntrinsicContractMismatch(
            abi::RuntimeIntrinsic::ImageEnter
        ))
    );

    let mut drift = canonical.clone();
    drift.interrupt_routes.record_bytes += 8;
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::InterruptRouteLayoutMismatch)
    );

    let mut drift = canonical.clone();
    drift.event_log.record_region_bytes -= 1;
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::EventLogLayoutMismatch)
    );

    let mut drift = canonical;
    drift.runtime_object.sections[2].extent = abi::SectionExtent::Exact(65_663);
    assert_eq!(
        drift.validate(),
        Err(abi::RuntimeAbiError::RuntimeObjectLayoutMismatch)
    );
}

#[test]
fn route_table_fixture_accepts_only_exact_sorted_little_endian_records() {
    let mut table = Vec::new();
    table.extend_from_slice(&2_u32.to_le_bytes());
    table.extend_from_slice(&0_u32.to_le_bytes());
    table.extend_from_slice(&48_u32.to_le_bytes());
    table.extend_from_slice(&0_u32.to_le_bytes());
    table.extend_from_slice(&0x1000_u64.to_le_bytes());
    table.extend_from_slice(&52_u32.to_le_bytes());
    table.extend_from_slice(&0_u32.to_le_bytes());
    table.extend_from_slice(&0x2000_u64.to_le_bytes());
    assert_eq!(table.len(), 40);
    abi::INTERRUPT_ROUTE_LAYOUT
        .validate_table(&table)
        .expect("canonical two-route table");

    let mut drift = table.clone();
    drift[4] = 1;
    assert_eq!(
        abi::INTERRUPT_ROUTE_LAYOUT.validate_table(&drift),
        Err(abi::RuntimeAbiError::InterruptRouteReservedNonZero { record_index: None })
    );

    let mut drift = table.clone();
    drift[24..28].copy_from_slice(&48_u32.to_le_bytes());
    assert_eq!(
        abi::INTERRUPT_ROUTE_LAYOUT.validate_table(&drift),
        Err(abi::RuntimeAbiError::NonCanonicalInterruptRoutes { record_index: 1 })
    );

    let mut drift = table.clone();
    drift[28] = 1;
    assert_eq!(
        abi::INTERRUPT_ROUTE_LAYOUT.validate_table(&drift),
        Err(abi::RuntimeAbiError::InterruptRouteReservedNonZero {
            record_index: Some(1)
        })
    );

    let mut drift = table.clone();
    drift.push(0);
    assert_eq!(
        abi::INTERRUPT_ROUTE_LAYOUT.validate_table(&drift),
        Err(abi::RuntimeAbiError::InterruptRouteTableLength {
            route_count: 2,
            expected_bytes: 40,
            actual_bytes: 41,
        })
    );
    assert_eq!(
        abi::INTERRUPT_ROUTE_LAYOUT.validate_table(&table[..7]),
        Err(abi::RuntimeAbiError::InterruptRouteTableTruncated)
    );
}
