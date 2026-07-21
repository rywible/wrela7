use std::cell::Cell;

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_driver::engine::{
    CheckDiagnosticPolicy, CheckReportIdentityBuilder, CheckRequest, CheckRequestFields,
    CheckRequestStream, CheckResponseStream, ClientHello, DiagnosticSeverity,
    ENGINE_FRAME_HEADER_BYTES, EngineComptimeUsage, EngineEvent, EngineFrame, EngineMessage,
    EnginePath, EngineProtocolError, EngineProtocolLimits, EngineResourcePolicy,
    EngineResourceUsage, EngineResponseMessageRef, EngineTerminal, RequestStreamProgress,
    ResponseStreamProgress, ServerHello, TerminalStatus, TreeMode, TreeRecord,
    ValidatedRequestAction, ValidatedResponseAction, decode_frame, decode_frame_header,
    empty_tree_measurement, encode_frame, encode_response_frame, measure_tree, nonce_proof, sha256,
};

fn digest(bytes: &[u8]) -> Sha256Digest {
    sha256(bytes, &|| false).expect("fixture digest")
}

fn input_files() -> Vec<(TreeRecord, Vec<u8>)> {
    [
        (
            "src/math.wr",
            b"module app.math\n\npub fn add(left: u32, right: u32) -> u32:\n    return left + right\n"
                .as_slice(),
        ),
        (
            "wrela.toml",
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(path, bytes)| {
        (
            TreeRecord {
                path: EnginePath::new(path).expect("portable fixture path"),
                mode: TreeMode::Data,
                bytes: bytes.len() as u64,
                digest: digest(bytes),
            },
            bytes.to_vec(),
        )
    })
    .collect()
}

fn request_fixture() -> (CheckRequest, ClientHello, Vec<(TreeRecord, Vec<u8>)>) {
    let files = input_files();
    let records: Vec<_> = files.iter().map(|(record, _)| record.clone()).collect();
    let input = measure_tree(&records, EngineProtocolLimits::standard(), &|| false)
        .expect("canonical fixture tree");
    let payload_identity = digest(b"engine payload");
    let request = CheckRequest::seal(
        CheckRequestFields {
            engine_identity: digest(b"wrela-engine executable"),
            payload_identity,
            manifest: EnginePath::new("wrela.toml").expect("manifest path"),
            image: "app".to_owned(),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            profile: "dev".to_owned(),
            diagnostics: CheckDiagnosticPolicy {
                warnings_as_errors: false,
                maximum_diagnostics: 100,
            },
            resources: EngineResourcePolicy::check_standard(),
            input,
        },
        EngineProtocolLimits::standard(),
        &|| false,
    )
    .expect("sealed request");
    let hello = ClientHello {
        launcher_identity: digest(b"host launcher"),
        payload_identity,
        nonce: [0x5a; 32],
    };
    (request, hello, files)
}

fn encoded(sequence: u64, request: &CheckRequest, message: EngineMessage) -> Vec<u8> {
    encode_frame(
        &EngineFrame {
            sequence,
            request_identity: request.identity(),
            message,
        },
        EngineProtocolLimits::standard(),
        &|| false,
    )
    .expect("encoded fixture frame")
}

fn request_stream(request: &CheckRequest, hello: ClientHello) -> CheckRequestStream {
    CheckRequestStream::new(
        hello.launcher_identity,
        request.engine_identity,
        request.payload_identity,
        EngineProtocolLimits::standard(),
    )
    .expect("request stream")
}

#[test]
fn diagnostic_locations_round_trip_only_in_canonical_paired_forms() {
    let (request, _, _) = request_fixture();
    let source_free = EngineEvent::Diagnostic {
        stable_id: digest(b"source-free diagnostic"),
        severity: DiagnosticSeverity::Error,
        code: "engine-input".to_owned(),
        message: "workspace input failed".to_owned(),
        path: None,
        line: 0,
        column: 0,
    };
    let source_aware = EngineEvent::Diagnostic {
        stable_id: digest(b"source-aware diagnostic"),
        severity: DiagnosticSeverity::Warning,
        code: "unused-value".to_owned(),
        message: "the value is unused".to_owned(),
        path: Some(EnginePath::new("src/math.wr").expect("source path")),
        line: 4,
        column: 7,
    };
    for event in [source_free.clone(), source_aware.clone()] {
        let frame = encoded(0, &request, EngineMessage::Event(event.clone()));
        assert_eq!(
            decode_frame(&frame, EngineProtocolLimits::standard(), &|| false)
                .expect("canonical diagnostic frame")
                .message,
            EngineMessage::Event(event)
        );
    }

    for event in [
        EngineEvent::Diagnostic {
            stable_id: digest(b"source-free mixed diagnostic"),
            severity: DiagnosticSeverity::Error,
            code: "engine-input".to_owned(),
            message: "workspace input failed".to_owned(),
            path: None,
            line: 1,
            column: 0,
        },
        EngineEvent::Diagnostic {
            stable_id: digest(b"source-aware mixed diagnostic"),
            severity: DiagnosticSeverity::Warning,
            code: "unused-value".to_owned(),
            message: "the value is unused".to_owned(),
            path: Some(EnginePath::new("src/math.wr").expect("source path")),
            line: 0,
            column: 7,
        },
    ] {
        assert_eq!(
            encode_frame(
                &EngineFrame {
                    sequence: 0,
                    request_identity: request.identity(),
                    message: EngineMessage::Event(event),
                },
                EngineProtocolLimits::standard(),
                &|| false,
            ),
            Err(EngineProtocolError::InvalidText)
        );
    }
}

#[test]
fn report_observation_cancellation_keeps_a_canonical_prefix() {
    let (request, _, _) = request_fixture();
    let limits = EngineProtocolLimits::standard();
    let mut report = CheckReportIdentityBuilder::new(request.identity(), limits)
        .expect("cancellable report builder");
    let event = EngineEvent::Diagnostic {
        stable_id: digest(b"large cancellable diagnostic"),
        severity: DiagnosticSeverity::Error,
        code: "large-diagnostic".to_owned(),
        message: "x".repeat(256 * 1024),
        path: Some(EnginePath::new("src/math.wr").expect("diagnostic path")),
        line: 1,
        column: 1,
    };
    let polls = Cell::new(0u32);
    let cancelled = || {
        let next = polls.get().saturating_add(1);
        polls.set(next);
        next >= 8
    };
    assert_eq!(
        report.observe(&event, &cancelled),
        Err(EngineProtocolError::Cancelled)
    );
    assert_eq!(report.events(), 0);
    assert_eq!(report.event_bytes(), 0);
    let expected = CheckReportIdentityBuilder::new(request.identity(), limits)
        .expect("empty report builder")
        .finish(&|| false)
        .expect("empty report identity");
    assert_eq!(
        report.finish(&|| false).expect("cancelled prefix identity"),
        expected
    );
    assert_eq!(report.finish(&|| true), Err(EngineProtocolError::Cancelled));
    assert_eq!(
        report.finish(&|| false).expect("retriable report sealing"),
        expected
    );
}

fn reseal_payload(frame: &mut [u8]) {
    let payload = &frame[ENGINE_FRAME_HEADER_BYTES..];
    let payload_digest = digest(payload);
    frame[60..92].copy_from_slice(payload_digest.as_bytes());
}

fn response_before_terminal(
    request: &CheckRequest,
    hello: ClientHello,
    event: EngineEvent,
) -> (CheckResponseStream, u64, Sha256Digest) {
    let proof = nonce_proof(
        request.identity(),
        hello.launcher_identity,
        request.engine_identity,
        request.payload_identity,
        hello.nonce,
        &|| false,
    )
    .expect("nonce proof");
    let mut stream =
        CheckResponseStream::new(request, hello, EngineProtocolLimits::standard(), &|| false)
            .expect("response stream");
    stream
        .accept(
            &encoded(
                0,
                request,
                EngineMessage::ServerHello(ServerHello {
                    engine_identity: request.engine_identity,
                    payload_identity: request.payload_identity,
                    nonce_proof: proof,
                }),
            ),
            &|| false,
        )
        .expect("server hello");
    let mut report =
        CheckReportIdentityBuilder::new(request.identity(), EngineProtocolLimits::standard())
            .expect("report builder");
    report.observe(&event, &|| false).expect("report event");
    let report_identity = report.finish(&|| false).expect("report identity");
    let event = encoded(1, request, EngineMessage::Event(event));
    let event_bytes = (event.len() - ENGINE_FRAME_HEADER_BYTES) as u64;
    stream.accept(&event, &|| false).expect("event");
    let empty = empty_tree_measurement(&|| false).expect("empty output");
    stream
        .accept(
            &encoded(2, request, EngineMessage::OutputHeader(empty)),
            &|| false,
        )
        .expect("output header");
    stream
        .accept(
            &encoded(3, request, EngineMessage::OutputFinish(empty)),
            &|| false,
        )
        .expect("output finish");
    (stream, event_bytes, report_identity)
}

fn feed_complete_request(
    stream: &mut CheckRequestStream,
    request: &CheckRequest,
    hello: ClientHello,
    files: &[(TreeRecord, Vec<u8>)],
) {
    let mut sequence = 0;
    assert_eq!(
        stream
            .accept(
                &encoded(sequence, request, EngineMessage::ClientHello(hello)),
                &|| false,
            )
            .expect("client hello"),
        RequestStreamProgress::Pending
    );
    sequence += 1;
    assert_eq!(
        stream
            .accept(
                &encoded(
                    sequence,
                    request,
                    EngineMessage::RequestHeader(Box::new(request.clone())),
                ),
                &|| false,
            )
            .expect("request header"),
        RequestStreamProgress::Pending
    );
    sequence += 1;
    for (index, (record, bytes)) in files.iter().enumerate() {
        stream
            .accept(
                &encoded(
                    sequence,
                    request,
                    EngineMessage::InputRecord {
                        index: index as u32,
                        record: record.clone(),
                    },
                ),
                &|| false,
            )
            .expect("input record");
        sequence += 1;
        let split = bytes.len().min(7);
        for (offset, chunk) in [(0, &bytes[..split]), (split, &bytes[split..])] {
            if chunk.is_empty() {
                continue;
            }
            let accepted = stream
                .accept_validated(
                    &encoded(
                        sequence,
                        request,
                        EngineMessage::InputChunk {
                            record: index as u32,
                            offset: offset as u64,
                            bytes: chunk.to_vec(),
                        },
                    ),
                    &|| false,
                )
                .expect("input chunk");
            assert_eq!(
                accepted.into_action(),
                ValidatedRequestAction::InputChunk {
                    record: index as u32,
                    offset: offset as u64,
                    bytes: chunk.to_vec(),
                }
            );
            sequence += 1;
        }
    }
    assert_eq!(
        stream
            .accept(
                &encoded(sequence, request, EngineMessage::InputFinish(request.input),),
                &|| false,
            )
            .expect("input finish"),
        RequestStreamProgress::Complete
    );
}

#[test]
fn sha_tree_and_request_identities_are_exact_and_sensitive() {
    assert_eq!(
        digest(b"abc").to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let empty = empty_tree_measurement(&|| false).expect("empty output tree");
    assert_eq!(empty.records, 0);
    assert_eq!(empty.content_bytes, 0);
    assert_eq!(empty.path_bytes, 0);
    assert_eq!(
        empty.digest.to_hex(),
        "2481f7db8dd5431fc33f5dba8948e6323643b8edda3e0485b70d7de11aa95476"
    );
    assert_eq!(
        include_str!("contracts/engine/v1/empty-check-output.contract"),
        concat!(
            "engine-protocol=1\n",
            "frame-magic-hex=5752454c454e4700\n",
            "frame-header-bytes=92\n",
            "tree-encoding=1\n",
            "tree-magic-hex=5752454c4e545200\n",
            "empty-output-tree-digest=2481f7db8dd5431fc33f5dba8948e6323643b8edda3e0485b70d7de11aa95476\n",
            "empty-output-records=0\n",
            "empty-output-content-bytes=0\n",
            "empty-output-path-bytes=0\n",
        )
    );
    assert_eq!(
        empty,
        measure_tree(&[], EngineProtocolLimits::standard(), &|| false)
            .expect("deterministic empty tree")
    );

    let (request, _, _) = request_fixture();
    let mut changed = request.to_fields();
    changed.engine_identity = digest(b"different engine");
    let changed = CheckRequest::seal(changed, EngineProtocolLimits::standard(), &|| false)
        .expect("changed request");
    assert_ne!(request.identity(), changed.identity());
}

#[test]
fn paths_reject_host_and_noncanonical_spellings() {
    for rejected in [
        "",
        "/absolute",
        "../escape",
        "src/../escape",
        "src//main.wr",
        "src\\main.wr",
        "C:drive",
        "src/.",
        "src/file.",
        "src/\0file",
    ] {
        assert_eq!(
            EnginePath::new(rejected),
            Err(EngineProtocolError::InvalidPath),
            "{rejected:?}"
        );
    }
    assert_eq!(
        EnginePath::new("src/δ.wr")
            .expect("portable UTF-8")
            .as_str(),
        "src/δ.wr"
    );

    let (request, _, _) = request_fixture();
    let mut wrong_manifest_name = request.to_fields();
    wrong_manifest_name.manifest = EnginePath::new("workspace/other.toml").expect("sibling path");
    assert_eq!(
        CheckRequest::seal(
            wrong_manifest_name,
            EngineProtocolLimits::standard(),
            &|| false
        ),
        Err(EngineProtocolError::InvalidResourcePolicy)
    );
}

#[test]
fn frame_codec_rejects_corruption_and_trailing_bytes() {
    let (request, hello, _) = request_fixture();
    let original = encoded(0, &request, EngineMessage::ClientHello(hello));
    assert_eq!(
        decode_frame(&original, EngineProtocolLimits::standard(), &|| false)
            .expect("round trip")
            .message,
        EngineMessage::ClientHello(hello)
    );

    let mut wrong_magic = original.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        decode_frame(&wrong_magic, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::InvalidMagic)
    );
    let mut wrong_version = original.clone();
    wrong_version[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        decode_frame(&wrong_version, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::UnsupportedVersion(2))
    );
    let mut wrong_kind = original.clone();
    wrong_kind[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        decode_frame(&wrong_kind, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::UnknownFrameKind(u16::MAX))
    );
    let mut reserved = original.clone();
    reserved[14] = 1;
    assert_eq!(
        decode_frame(&reserved, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::NonZeroReserved)
    );
    let mut corrupt_payload = original.clone();
    *corrupt_payload.last_mut().expect("payload byte") ^= 1;
    assert_eq!(
        decode_frame(&corrupt_payload, EngineProtocolLimits::standard(), &|| {
            false
        }),
        Err(EngineProtocolError::PayloadDigestMismatch)
    );
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(matches!(
        decode_frame(&trailing, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::FrameLengthMismatch { .. })
    ));
    assert_eq!(
        decode_frame(
            &original[..ENGINE_FRAME_HEADER_BYTES - 1],
            EngineProtocolLimits::standard(),
            &|| false
        ),
        Err(EngineProtocolError::Truncated)
    );

    let mut canonical_trailing = original.clone();
    canonical_trailing.push(0);
    let payload_length = (canonical_trailing.len() - ENGINE_FRAME_HEADER_BYTES) as u32;
    canonical_trailing[24..28].copy_from_slice(&payload_length.to_le_bytes());
    reseal_payload(&mut canonical_trailing);
    assert_eq!(
        decode_frame(
            &canonical_trailing,
            EngineProtocolLimits::standard(),
            &|| false
        ),
        Err(EngineProtocolError::TrailingBytes)
    );
}

#[test]
fn validated_frame_header_exposes_only_bounded_reader_metadata() {
    let (request, hello, _) = request_fixture();
    let frame = encoded(7, &request, EngineMessage::ClientHello(hello));
    let header = decode_frame_header(
        &frame[..ENGINE_FRAME_HEADER_BYTES],
        EngineProtocolLimits::standard(),
        &|| false,
    )
    .expect("validated fixed frame header");
    assert_eq!(header.kind(), 1);
    assert_eq!(header.sequence(), 7);
    assert_eq!(header.payload_bytes(), 96);
    assert_eq!(header.encoded_frame_bytes(), frame.len() as u64);
    assert_eq!(header.request_identity(), request.identity());
    assert_eq!(
        header.payload_digest(),
        digest(&frame[ENGINE_FRAME_HEADER_BYTES..])
    );

    assert_eq!(
        decode_frame_header(&frame, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::TrailingBytes)
    );
    let mut oversized = frame[..ENGINE_FRAME_HEADER_BYTES].to_vec();
    oversized[24..28].copy_from_slice(&(1024 * 1024 + 1u32).to_le_bytes());
    assert_eq!(
        decode_frame_header(&oversized, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::FrameTooLarge {
            limit: 1024 * 1024,
            actual: 1024 * 1024 + 1,
        })
    );
    assert_eq!(
        decode_frame_header(
            &frame[..ENGINE_FRAME_HEADER_BYTES],
            EngineProtocolLimits::standard(),
            &|| true,
        ),
        Err(EngineProtocolError::Cancelled)
    );
}

#[test]
fn borrowed_response_encoder_is_byte_exact_without_message_clones() {
    let (request, client, _) = request_fixture();
    let server = ServerHello {
        engine_identity: request.engine_identity,
        payload_identity: request.payload_identity,
        nonce_proof: nonce_proof(
            request.identity(),
            client.launcher_identity,
            request.engine_identity,
            request.payload_identity,
            client.nonce,
            &|| false,
        )
        .expect("server nonce proof"),
    };
    let event = EngineEvent::PhaseStarted {
        phase: "parse".to_owned(),
    };
    let output = empty_tree_measurement(&|| false).expect("empty output");
    let terminal = EngineTerminal {
        status: TerminalStatus::Success,
        diagnostic_count: 0,
        report_identity: digest(b"borrowed response report"),
        usage: EngineResourceUsage {
            input_bytes: request.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes: 1,
            comptime: None,
        },
    };
    let cases = [
        (
            EngineMessage::ServerHello(server),
            EngineResponseMessageRef::ServerHello(&server),
        ),
        (
            EngineMessage::Event(event.clone()),
            EngineResponseMessageRef::Event(&event),
        ),
        (
            EngineMessage::OutputHeader(output),
            EngineResponseMessageRef::OutputHeader(output),
        ),
        (
            EngineMessage::OutputFinish(output),
            EngineResponseMessageRef::OutputFinish(output),
        ),
        (
            EngineMessage::Terminal(terminal.clone()),
            EngineResponseMessageRef::Terminal(&terminal),
        ),
    ];
    for (sequence, (owned, borrowed)) in cases.into_iter().enumerate() {
        assert_eq!(
            encode_response_frame(
                sequence as u64,
                request.identity(),
                borrowed,
                EngineProtocolLimits::standard(),
                &|| false,
            )
            .expect("borrowed response frame"),
            encoded(sequence as u64, &request, owned)
        );
    }
}

#[test]
fn decoded_records_reject_unsupported_modes_and_noncanonical_paths() {
    let (request, _, files) = request_fixture();
    let mut frame = encoded(
        0,
        &request,
        EngineMessage::InputRecord {
            index: 0,
            record: files[0].0.clone(),
        },
    );
    let path_length = files[0].0.path.as_str().len();
    let mode_offset = ENGINE_FRAME_HEADER_BYTES + 4 + 4 + path_length;
    frame[mode_offset] = 0xff;
    reseal_payload(&mut frame);
    assert_eq!(
        decode_frame(&frame, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::InvalidTag {
            field: "tree mode",
            tag: 0xff
        })
    );

    let mut bad_path = encoded(
        0,
        &request,
        EngineMessage::InputRecord {
            index: 0,
            record: files[0].0.clone(),
        },
    );
    bad_path[ENGINE_FRAME_HEADER_BYTES + 8] = b'/';
    reseal_payload(&mut bad_path);
    assert_eq!(
        decode_frame(&bad_path, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::InvalidPath)
    );
}

#[test]
fn frame_payload_limit_accepts_exact_bound_and_rejects_one_byte_over() {
    let (request, hello, _) = request_fixture();
    let frame = EngineFrame {
        sequence: 0,
        request_identity: request.identity(),
        message: EngineMessage::ClientHello(hello),
    };
    let mut exact = EngineProtocolLimits::standard();
    exact.frame_payload_bytes = 96;
    let encoded = encode_frame(&frame, exact, &|| false).expect("exact 96-byte hello payload");
    assert_eq!(encoded.len(), ENGINE_FRAME_HEADER_BYTES + 96);
    assert!(decode_frame(&encoded, exact, &|| false).is_ok());

    let mut over = exact;
    over.frame_payload_bytes = 95;
    assert!(matches!(
        encode_frame(&frame, over, &|| false),
        Err(EngineProtocolError::FrameTooLarge {
            limit: 95,
            actual: 96
        })
    ));
}

#[test]
fn request_stream_rejects_launcher_payload_and_engine_substitution() {
    let (request, hello, _) = request_fixture();
    let mut launcher = request_stream(&request, hello);
    let substituted_launcher = ClientHello {
        launcher_identity: digest(b"substituted launcher"),
        ..hello
    };
    assert_eq!(
        launcher.accept(
            &encoded(
                0,
                &request,
                EngineMessage::ClientHello(substituted_launcher),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::RequestIdentityMismatch)
    );

    let mut payload = request_stream(&request, hello);
    let substituted_payload = ClientHello {
        payload_identity: digest(b"substituted payload"),
        ..hello
    };
    assert_eq!(
        payload.accept(
            &encoded(0, &request, EngineMessage::ClientHello(substituted_payload),),
            &|| false,
        ),
        Err(EngineProtocolError::RequestIdentityMismatch)
    );

    let mut fields = request.to_fields();
    fields.engine_identity = digest(b"substituted engine");
    let substituted_request =
        CheckRequest::seal(fields, EngineProtocolLimits::standard(), &|| false)
            .expect("substituted request");
    let mut engine = CheckRequestStream::new(
        hello.launcher_identity,
        request.engine_identity,
        request.payload_identity,
        EngineProtocolLimits::standard(),
    )
    .expect("request stream");
    engine
        .accept(
            &encoded(0, &substituted_request, EngineMessage::ClientHello(hello)),
            &|| false,
        )
        .expect("hello remains independently valid");
    assert_eq!(
        engine.accept(
            &encoded(
                1,
                &substituted_request,
                EngineMessage::RequestHeader(Box::new(substituted_request.clone())),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::RequestIdentityMismatch)
    );
}

#[test]
fn request_stream_accepts_a_real_sealed_tree_and_late_cancellation() {
    let (request, hello, files) = request_fixture();
    let mut stream = request_stream(&request, hello);
    feed_complete_request(&mut stream, &request, hello, &files);
    assert!(stream.is_complete());
    assert_eq!(stream.request(), Some(&request));
    assert_eq!(stream.hello(), Some(hello));

    let final_sequence = 2 + (files.len() as u64 * 3) + 1;
    assert_eq!(
        stream
            .accept(
                &encoded(final_sequence, &request, EngineMessage::Cancel),
                &|| false,
            )
            .expect("late cancellation"),
        RequestStreamProgress::Cancelled
    );
    assert!(stream.is_cancelled());
}

#[test]
fn sealed_late_cancel_stream_accepts_only_the_exact_bound_continuation() {
    let (request, hello, files) = request_fixture();
    let complete = || {
        let mut stream = request_stream(&request, hello);
        feed_complete_request(&mut stream, &request, hello, &files);
        stream
    };

    let mut wrong_sequence = complete()
        .late_cancel_stream()
        .expect("late cancel continuation");
    let expected = wrong_sequence.expected_sequence();
    assert_eq!(wrong_sequence.request_identity(), request.identity());
    assert_eq!(
        wrong_sequence.accept(
            &encoded(expected + 1, &request, EngineMessage::Cancel),
            &|| false,
        ),
        Err(EngineProtocolError::SequenceMismatch {
            expected,
            actual: expected + 1,
        })
    );
    assert!(matches!(
        wrong_sequence.accept(&encoded(expected, &request, EngineMessage::Cancel), &|| {
            false
        },),
        Err(EngineProtocolError::UnexpectedMessage { .. })
    ));

    let mut wrong_identity = complete()
        .late_cancel_stream()
        .expect("identity-bound continuation");
    let substituted = encode_frame(
        &EngineFrame {
            sequence: expected,
            request_identity: digest(b"substituted late-cancel request"),
            message: EngineMessage::Cancel,
        },
        EngineProtocolLimits::standard(),
        &|| false,
    )
    .expect("substituted cancel frame");
    assert_eq!(
        wrong_identity.accept(&substituted, &|| false),
        Err(EngineProtocolError::RequestIdentityMismatch)
    );

    let mut wrong_message = complete()
        .late_cancel_stream()
        .expect("message-bound continuation");
    assert!(matches!(
        wrong_message.accept(
            &encoded(
                expected,
                &request,
                EngineMessage::Event(EngineEvent::PhaseStarted {
                    phase: "not-cancel".to_owned(),
                }),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::UnexpectedMessage {
            expected: "Cancel",
            ..
        })
    ));

    let mut accepted = complete()
        .late_cancel_stream()
        .expect("exact late cancel continuation");
    accepted
        .accept(&encoded(expected, &request, EngineMessage::Cancel), &|| {
            false
        })
        .expect("exact bound late cancel");
    assert!(matches!(
        accepted.accept(
            &encoded(expected + 1, &request, EngineMessage::Cancel),
            &|| false,
        ),
        Err(EngineProtocolError::UnexpectedMessage { .. })
    ));
}

#[test]
fn request_stream_rejects_sequence_order_chunk_offset_and_content_substitution() {
    let (request, hello, files) = request_fixture();
    let mut gap = request_stream(&request, hello);
    assert_eq!(
        gap.accept(
            &encoded(1, &request, EngineMessage::ClientHello(hello)),
            &|| false
        ),
        Err(EngineProtocolError::SequenceMismatch {
            expected: 0,
            actual: 1
        })
    );

    let mut offset = request_stream(&request, hello);
    offset
        .accept(
            &encoded(0, &request, EngineMessage::ClientHello(hello)),
            &|| false,
        )
        .expect("hello");
    offset
        .accept(
            &encoded(
                1,
                &request,
                EngineMessage::RequestHeader(Box::new(request.clone())),
            ),
            &|| false,
        )
        .expect("header");
    offset
        .accept(
            &encoded(
                2,
                &request,
                EngineMessage::InputRecord {
                    index: 0,
                    record: files[0].0.clone(),
                },
            ),
            &|| false,
        )
        .expect("record");
    assert_eq!(
        offset.accept(
            &encoded(
                3,
                &request,
                EngineMessage::InputChunk {
                    record: 0,
                    offset: 1,
                    bytes: files[0].1.clone(),
                },
            ),
            &|| false,
        ),
        Err(EngineProtocolError::ChunkOffsetMismatch {
            expected: 0,
            actual: 1
        })
    );

    let mut substituted_files = input_files();
    substituted_files[0].0.digest = digest(b"substituted declaration");
    let substituted_records: Vec<_> = substituted_files
        .iter()
        .map(|(record, _)| record.clone())
        .collect();
    let substituted_measurement = measure_tree(
        &substituted_records,
        EngineProtocolLimits::standard(),
        &|| false,
    )
    .expect("substituted metadata tree");
    let mut fields = request.to_fields();
    fields.input = substituted_measurement;
    let substituted_request =
        CheckRequest::seal(fields, EngineProtocolLimits::standard(), &|| false)
            .expect("substituted request");
    let substituted_hello = ClientHello {
        payload_identity: substituted_request.payload_identity,
        ..hello
    };
    let mut substitution = request_stream(&substituted_request, substituted_hello);
    substitution
        .accept(
            &encoded(
                0,
                &substituted_request,
                EngineMessage::ClientHello(substituted_hello),
            ),
            &|| false,
        )
        .expect("hello");
    substitution
        .accept(
            &encoded(
                1,
                &substituted_request,
                EngineMessage::RequestHeader(Box::new(substituted_request.clone())),
            ),
            &|| false,
        )
        .expect("header");
    substitution
        .accept(
            &encoded(
                2,
                &substituted_request,
                EngineMessage::InputRecord {
                    index: 0,
                    record: substituted_files[0].0.clone(),
                },
            ),
            &|| false,
        )
        .expect("record");
    assert_eq!(
        substitution.accept(
            &encoded(
                3,
                &substituted_request,
                EngineMessage::InputChunk {
                    record: 0,
                    offset: 0,
                    bytes: substituted_files[0].1.clone(),
                },
            ),
            &|| false,
        ),
        Err(EngineProtocolError::RecordDigestMismatch)
    );
}

#[test]
fn trees_enforce_order_and_exact_content_bounds() {
    let files = input_files();
    let mut records: Vec<_> = files.iter().map(|(record, _)| record.clone()).collect();
    records.reverse();
    assert_eq!(
        measure_tree(&records, EngineProtocolLimits::standard(), &|| false),
        Err(EngineProtocolError::TreeOrder)
    );

    let records: Vec<_> = files.iter().map(|(record, _)| record.clone()).collect();
    let total: u64 = records.iter().map(|record| record.bytes).sum();
    let mut exact = EngineProtocolLimits::standard();
    exact.tree_content_bytes = total;
    assert!(measure_tree(&records, exact, &|| false).is_ok());
    let mut over = exact;
    over.tree_content_bytes -= 1;
    assert!(matches!(
        measure_tree(&records, over, &|| false),
        Err(EngineProtocolError::ResourceLimit {
            resource: "tree content bytes",
            ..
        })
    ));
}

#[test]
fn response_stream_authenticates_engine_and_accepts_only_empty_check_output() {
    let (request, hello, _) = request_fixture();
    let proof = nonce_proof(
        request.identity(),
        hello.launcher_identity,
        request.engine_identity,
        request.payload_identity,
        hello.nonce,
        &|| false,
    )
    .expect("nonce proof");
    let mut stream =
        CheckResponseStream::new(&request, hello, EngineProtocolLimits::standard(), &|| false)
            .expect("response stream");
    stream
        .accept(
            &encoded(
                0,
                &request,
                EngineMessage::ServerHello(ServerHello {
                    engine_identity: request.engine_identity,
                    payload_identity: request.payload_identity,
                    nonce_proof: proof,
                }),
            ),
            &|| false,
        )
        .expect("server hello");
    let event = EngineEvent::Diagnostic {
        stable_id: digest(b"diagnostic"),
        severity: DiagnosticSeverity::Warning,
        code: "unused-value".to_owned(),
        message: "the value is unused".to_owned(),
        path: Some(EnginePath::new("src/math.wr").expect("diagnostic path")),
        line: 3,
        column: 5,
    };
    let mut report =
        CheckReportIdentityBuilder::new(request.identity(), EngineProtocolLimits::standard())
            .expect("report builder");
    report.observe(&event, &|| false).expect("report event");
    let report_identity = report.finish(&|| false).expect("report identity");
    let event_frame = encoded(1, &request, EngineMessage::Event(event.clone()));
    let event_bytes = (event_frame.len() - ENGINE_FRAME_HEADER_BYTES) as u64;
    let accepted_event = stream
        .accept_validated(&event_frame, &|| false)
        .expect("diagnostic event");
    assert_eq!(
        accepted_event.into_action(),
        ValidatedResponseAction::Event(event)
    );
    let empty = empty_tree_measurement(&|| false).expect("empty output");
    stream
        .accept(
            &encoded(2, &request, EngineMessage::OutputHeader(empty)),
            &|| false,
        )
        .expect("output header");
    stream
        .accept(
            &encoded(3, &request, EngineMessage::OutputFinish(empty)),
            &|| false,
        )
        .expect("output finish");
    let terminal = EngineTerminal {
        status: TerminalStatus::Success,
        diagnostic_count: 1,
        report_identity,
        usage: EngineResourceUsage {
            input_bytes: request.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes,
            comptime: Some(EngineComptimeUsage {
                steps: 42,
                peak_memory_bytes: 4096,
                peak_call_depth: 2,
            }),
        },
    };
    assert_eq!(
        stream
            .accept(
                &encoded(4, &request, EngineMessage::Terminal(terminal.clone())),
                &|| false,
            )
            .expect("terminal"),
        ResponseStreamProgress::Complete
    );
    assert!(stream.is_complete());
    assert_eq!(stream.terminal(), Some(&terminal));

    let wrong_engine = digest(b"substituted engine");
    let mut rejected =
        CheckResponseStream::new(&request, hello, EngineProtocolLimits::standard(), &|| false)
            .expect("response stream");
    let wrong_proof = nonce_proof(
        request.identity(),
        hello.launcher_identity,
        wrong_engine,
        request.payload_identity,
        hello.nonce,
        &|| false,
    )
    .expect("wrong proof");
    assert_eq!(
        rejected.accept(
            &encoded(
                0,
                &request,
                EngineMessage::ServerHello(ServerHello {
                    engine_identity: wrong_engine,
                    payload_identity: request.payload_identity,
                    nonce_proof: wrong_proof,
                }),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::NonceProofMismatch)
    );

    let wrong_launcher_proof = nonce_proof(
        request.identity(),
        digest(b"substituted launcher"),
        request.engine_identity,
        request.payload_identity,
        hello.nonce,
        &|| false,
    )
    .expect("substituted launcher proof");
    let mut rejected_launcher =
        CheckResponseStream::new(&request, hello, EngineProtocolLimits::standard(), &|| false)
            .expect("response stream");
    assert_eq!(
        rejected_launcher.accept(
            &encoded(
                0,
                &request,
                EngineMessage::ServerHello(ServerHello {
                    engine_identity: request.engine_identity,
                    payload_identity: request.payload_identity,
                    nonce_proof: wrong_launcher_proof,
                }),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::NonceProofMismatch)
    );

    let mut nonempty =
        CheckResponseStream::new(&request, hello, EngineProtocolLimits::standard(), &|| false)
            .expect("response stream");
    nonempty
        .accept(
            &encoded(
                0,
                &request,
                EngineMessage::ServerHello(ServerHello {
                    engine_identity: request.engine_identity,
                    payload_identity: request.payload_identity,
                    nonce_proof: proof,
                }),
            ),
            &|| false,
        )
        .expect("server hello");
    assert_eq!(
        nonempty.accept(
            &encoded(1, &request, EngineMessage::OutputHeader(request.input),),
            &|| false,
        ),
        Err(EngineProtocolError::TreeMeasurementMismatch)
    );
}

#[test]
fn response_terminal_matches_exact_diagnostics_and_rejection_policy() {
    let (request, hello, _) = request_fixture();
    let error = EngineEvent::Diagnostic {
        stable_id: digest(b"error diagnostic"),
        severity: DiagnosticSeverity::Error,
        code: "semantic-error".to_owned(),
        message: "the program is invalid".to_owned(),
        path: Some(EnginePath::new("src/math.wr").expect("path")),
        line: 1,
        column: 1,
    };
    let (mut success_with_error, event_bytes, error_report) =
        response_before_terminal(&request, hello, error.clone());
    let terminal = |status, diagnostic_count, report_identity, event_bytes| EngineTerminal {
        status,
        diagnostic_count,
        report_identity,
        usage: EngineResourceUsage {
            input_bytes: request.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes,
            comptime: Some(EngineComptimeUsage {
                steps: 1,
                peak_memory_bytes: 1,
                peak_call_depth: 1,
            }),
        },
    };
    assert_eq!(
        success_with_error.accept(
            &encoded(
                4,
                &request,
                EngineMessage::Terminal(terminal(
                    TerminalStatus::Success,
                    1,
                    error_report,
                    event_bytes,
                )),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::TerminalPolicyMismatch)
    );

    let (mut miscount, miscount_bytes, miscount_report) =
        response_before_terminal(&request, hello, error);
    assert_eq!(
        miscount.accept(
            &encoded(
                4,
                &request,
                EngineMessage::Terminal(terminal(
                    TerminalStatus::Rejected,
                    0,
                    miscount_report,
                    miscount_bytes,
                )),
            ),
            &|| false,
        ),
        Err(EngineProtocolError::TerminalPolicyMismatch)
    );

    let warning = EngineEvent::Diagnostic {
        stable_id: digest(b"warning diagnostic"),
        severity: DiagnosticSeverity::Warning,
        code: "warning".to_owned(),
        message: "warning only".to_owned(),
        path: Some(EnginePath::new("src/math.wr").expect("path")),
        line: 1,
        column: 1,
    };
    let (mut rejected_warning, warning_event_bytes, warning_report) =
        response_before_terminal(&request, hello, warning.clone());
    let warning_terminal = EngineTerminal {
        status: TerminalStatus::Rejected,
        diagnostic_count: 1,
        report_identity: warning_report,
        usage: EngineResourceUsage {
            input_bytes: request.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes: warning_event_bytes,
            comptime: Some(EngineComptimeUsage {
                steps: 1,
                peak_memory_bytes: 1,
                peak_call_depth: 1,
            }),
        },
    };
    assert_eq!(
        rejected_warning.accept(
            &encoded(4, &request, EngineMessage::Terminal(warning_terminal),),
            &|| false,
        ),
        Err(EngineProtocolError::TerminalPolicyMismatch)
    );

    let mut fields = request.to_fields();
    fields.diagnostics.warnings_as_errors = true;
    let warnings_as_errors =
        CheckRequest::seal(fields, EngineProtocolLimits::standard(), &|| false)
            .expect("warnings-as-errors request");
    let warnings_hello = ClientHello {
        payload_identity: warnings_as_errors.payload_identity,
        ..hello
    };
    let (mut accepted_warning, warning_event_bytes, warning_report) =
        response_before_terminal(&warnings_as_errors, warnings_hello, warning);
    let accepted_terminal = EngineTerminal {
        status: TerminalStatus::Rejected,
        diagnostic_count: 1,
        report_identity: warning_report,
        usage: EngineResourceUsage {
            input_bytes: warnings_as_errors.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes: warning_event_bytes,
            comptime: Some(EngineComptimeUsage {
                steps: 1,
                peak_memory_bytes: 1,
                peak_call_depth: 1,
            }),
        },
    };
    assert_eq!(
        accepted_warning
            .accept(
                &encoded(
                    4,
                    &warnings_as_errors,
                    EngineMessage::Terminal(accepted_terminal),
                ),
                &|| false,
            )
            .expect("warnings-as-errors rejection"),
        ResponseStreamProgress::Complete
    );

    let phase = EngineEvent::PhaseStarted {
        phase: "semantic-analysis".to_owned(),
    };
    let (mut substituted_report, phase_bytes, _) = response_before_terminal(&request, hello, phase);
    let terminal = EngineTerminal {
        status: TerminalStatus::Success,
        diagnostic_count: 0,
        report_identity: digest(b"substituted report identity"),
        usage: EngineResourceUsage {
            input_bytes: request.input.content_bytes,
            output_bytes: 0,
            events: 1,
            event_bytes: phase_bytes,
            comptime: Some(EngineComptimeUsage {
                steps: 1,
                peak_memory_bytes: 1,
                peak_call_depth: 1,
            }),
        },
    };
    assert_eq!(
        substituted_report.accept(
            &encoded(4, &request, EngineMessage::Terminal(terminal)),
            &|| false,
        ),
        Err(EngineProtocolError::TerminalPolicyMismatch)
    );
}

#[test]
fn cancellation_is_polled_during_hashing_and_decode() {
    let polls = Cell::new(0u32);
    assert_eq!(
        sha256(&vec![7; 2 * 64 * 1024], &|| {
            let next = polls.get() + 1;
            polls.set(next);
            next == 2
        }),
        Err(EngineProtocolError::Cancelled)
    );

    let (request, hello, _) = request_fixture();
    let frame = encoded(0, &request, EngineMessage::ClientHello(hello));
    assert_eq!(
        decode_frame(&frame, EngineProtocolLimits::standard(), &|| true),
        Err(EngineProtocolError::Cancelled)
    );
}
