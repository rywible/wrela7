//! Production QEMU command, PL011 transport, and test-event projection for the
//! revision-0.1 AArch64 target.

use std::ffi::OsString;

use wrela_build_model::Sha256Digest;
use wrela_target::{BootMedium, EmulatorKind, TargetRunnerContract, TestTransport};
use wrela_test_model::{
    FailurePhase, FullImageTestGroup, GuestTestOutcome, ImageExecutionEvidence, ImageGroupResult,
    TestCaseResult, TestEvent, TestEventKind, TestOutcome,
};
use wrela_test_protocol::{
    CanonicalTestEventCodec, ProtocolLimits, TEST_FRAME_MAGIC, decode_and_verify_stream,
    seal_encoded_event,
};

use crate::sha256::Sha256;
use crate::{
    ImageCommandRequest, ImageExecutionComponents, ImageHarness, ImageSummaryRequest, ProcessInput,
    ProcessShutdownControl, ProcessSpecification, RunError, VerifiedProcessFile,
};

const SLIP_END: u8 = 0xc0;
const SLIP_ESCAPE: u8 = 0xdb;
const SLIP_ESCAPED_END: u8 = 0xdc;
const SLIP_ESCAPED_ESCAPE: u8 = 0xdd;
const COMMAND_DIGEST_MAGIC: &[u8; 8] = b"WRELCMD\0";
const COMMAND_DIGEST_VERSION: u32 = 2;
const EVENT_DIGEST_MAGIC: &[u8; 8] = b"WRELEVS\0";
const EVENT_DIGEST_VERSION: u32 = 1;

/// Target-owned production harness. It constructs only the fixed QEMU `virt`
/// invocation described by the selected target package and delegates all
/// unescaped frame semantics to `wrela-test-protocol`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalImageHarness;

impl CanonicalImageHarness {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ImageHarness for CanonicalImageHarness {
    fn command(
        &self,
        request: ImageCommandRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessSpecification, RunError> {
        check_cancelled(is_cancelled)?;
        let runner = request.target.runner();
        if runner.emulator() != EmulatorKind::QemuSystemAarch64
            || runner.boot_medium() != BootMedium::VirtioBlockFat
            || runner.test_transport() != TestTransport::Pl011Serial
            || request.group.id != request.artifact.group()
            || request.artifact.build().target != *request.target.identity()
            || request.components.target_package.digest()
                != request.target.semantic().content_digest()
            || !super::normal_absolute_path(request.working_directory)
            || request.working_directory.components().count() <= 1
        {
            return Err(RunError::InvalidInvocation(
                "group, target, runner, or private working-directory identity differs".to_owned(),
            ));
        }
        let timeout_ns = request
            .group
            .execution_timeout_ns(request.scenario)
            .ok_or_else(|| {
                RunError::InvalidInvocation("test timeout budget overflow".to_owned())
            })?;
        let execution_policy = crate::protocol_execution_policy(request.group)?;
        let group_directory = request
            .working_directory
            .join(format!("group-{:010}", request.group.id.0));
        let firmware_code = group_directory.join("QEMU_EFI.fd");
        let firmware_variables = group_directory.join("QEMU_VARS.fd");
        let esp = group_directory.join("esp");
        let image = esp.join("EFI/BOOT/BOOTAA64.EFI");
        let qmp = group_directory.join("qmp.sock");
        for path in [
            &group_directory,
            &firmware_code,
            &firmware_variables,
            &esp,
            &image,
            &qmp,
        ] {
            if qemu_option_unsafe(path.as_os_str().as_encoded_bytes()) {
                return Err(RunError::InvalidInvocation(
                    "private QEMU paths contain comma or NUL option syntax".to_owned(),
                ));
            }
        }

        let mut inputs = vec![
            ProcessInput {
                source: VerifiedProcessFile::from_image(request.artifact),
                destination: image,
                writable: false,
            },
            ProcessInput {
                source: request.components.firmware_code.clone(),
                destination: firmware_code.clone(),
                writable: false,
            },
            ProcessInput {
                source: request.components.firmware_variables.clone(),
                destination: firmware_variables.clone(),
                writable: true,
            },
        ];
        inputs.sort_by(|left, right| left.destination.cmp(&right.destination));

        let needs_shutdown_control = request.scenario.is_some_and(|scenario| {
            scenario.steps.iter().any(|step| {
                matches!(
                    step,
                    wrela_test_model::ImageScenarioStep::RequestShutdown { .. }
                )
            })
        });
        if needs_shutdown_control && !super::valid_qmp_unix_path(&qmp) {
            return Err(RunError::InvalidInvocation(
                "private QMP socket path exceeds the sealed Unix-domain limit".to_owned(),
            ));
        }
        let shutdown_control =
            needs_shutdown_control.then(|| ProcessShutdownControl::QmpUnix { path: qmp.clone() });
        let arguments = qemu_arguments(
            runner,
            &firmware_code,
            &firmware_variables,
            &esp,
            shutdown_control.as_ref(),
        );
        let environment = vec![
            (os("HOME"), request.working_directory.as_os_str().to_owned()),
            (os("LC_ALL"), os("C")),
            (os("PATH"), OsString::new()),
            (os("SOURCE_DATE_EPOCH"), os("0")),
            (os("TMPDIR"), group_directory.as_os_str().to_owned()),
            (os("TZ"), os("UTC")),
        ];
        check_cancelled(is_cancelled)?;
        Ok(ProcessSpecification {
            program: request.components.emulator.path().to_owned(),
            arguments,
            current_directory: request.working_directory.to_owned(),
            environment,
            timeout_ns,
            protocol_limits: execution_policy.limits,
            maximum_output_bytes: execution_policy.maximum_output_bytes,
            shutdown_control,
            inputs,
        })
    }

    fn decode_events(
        &self,
        group: &FullImageTestGroup,
        output: &crate::ProcessOutput,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<TestEvent>, RunError> {
        check_cancelled(is_cancelled)?;
        let execution_policy = crate::protocol_execution_policy(group)?;
        let output_bytes = output
            .stdout
            .len()
            .checked_add(output.stderr.len())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| RunError::OutputLimitExceeded(group.name.clone()))?;
        if output_bytes > execution_policy.maximum_output_bytes {
            return Err(RunError::OutputLimitExceeded(group.name.clone()));
        }
        let limits = execution_policy.limits;
        let preserve_complete_prefix = output.timed_out || output.exit_code != Some(0);
        let stream = decode_slip(
            &output.stdout,
            limits,
            preserve_complete_prefix,
            is_cancelled,
        )?;
        decode_and_verify_stream(&CanonicalTestEventCodec, &stream, limits, is_cancelled)
            .map_err(|error| RunError::Protocol(error.to_string()))
    }

    fn command_digest(
        &self,
        command: &ProcessSpecification,
        components: &ImageExecutionComponents,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, RunError> {
        check_cancelled(is_cancelled)?;
        let mut digest = CanonicalDigest::new(COMMAND_DIGEST_MAGIC, COMMAND_DIGEST_VERSION);
        let working = command.current_directory.as_os_str().as_encoded_bytes();
        digest.bytes(components.emulator.digest().as_bytes())?;
        digest.u64(components.emulator.bytes())?;
        digest.count(command.arguments.len())?;
        for argument in &command.arguments {
            check_cancelled(is_cancelled)?;
            digest.normalized_bytes(argument.as_encoded_bytes(), working)?;
        }
        digest.bytes(b"$WORK")?;
        digest.count(command.environment.len())?;
        for (name, value) in &command.environment {
            check_cancelled(is_cancelled)?;
            digest.bytes(name.as_encoded_bytes())?;
            digest.normalized_bytes(value.as_encoded_bytes(), working)?;
        }
        digest.u64(command.timeout_ns)?;
        digest.u64(u64::from(command.protocol_limits.frame_bytes))?;
        digest.u64(u64::from(command.protocol_limits.string_bytes))?;
        digest.u64(u64::from(command.protocol_limits.events))?;
        digest.u64(command.maximum_output_bytes)?;
        match &command.shutdown_control {
            None => digest.byte(0),
            Some(ProcessShutdownControl::QmpUnix { path }) => {
                digest.byte(1);
                digest.normalized_bytes(path.as_os_str().as_encoded_bytes(), working)?;
            }
        }
        digest.count(command.inputs.len())?;
        for input in &command.inputs {
            check_cancelled(is_cancelled)?;
            digest.bytes(input.source.digest().as_bytes())?;
            digest.u64(input.source.bytes())?;
            digest.normalized_bytes(input.destination.as_os_str().as_encoded_bytes(), working)?;
            digest.byte(u8::from(input.writable));
        }
        check_cancelled(is_cancelled)?;
        Ok(digest.finish())
    }

    fn event_stream_digest(
        &self,
        events: &[TestEvent],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, RunError> {
        check_cancelled(is_cancelled)?;
        let mut digest = CanonicalDigest::new(EVENT_DIGEST_MAGIC, EVENT_DIGEST_VERSION);
        digest.count(events.len())?;
        let limits = ProtocolLimits {
            events: u32::try_from(events.len().max(1)).map_err(|_| {
                RunError::Protocol("event stream count does not fit protocol limits".to_owned())
            })?,
            ..ProtocolLimits::standard()
        };
        for event in events {
            check_cancelled(is_cancelled)?;
            let encoded = seal_encoded_event(&CanonicalTestEventCodec, event, limits, is_cancelled)
                .map_err(|error| RunError::Protocol(error.to_string()))?;
            digest.bytes(encoded.bytes())?;
        }
        check_cancelled(is_cancelled)?;
        Ok(digest.finish())
    }

    fn summarize(
        &self,
        request: ImageSummaryRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageGroupResult, RunError> {
        check_cancelled(is_cancelled)?;
        let CollectedCases { cases, terminal } =
            collect_cases(request.group, request.events, is_cancelled)?;
        let infrastructure_failure = if request.output.timed_out {
            if terminal.is_some() {
                return Err(RunError::UnexpectedTestEvent(
                    "a terminal guest event was observed before host timeout".to_owned(),
                ));
            }
            Some(TestOutcome::TimedOut {
                phase: if request.events.is_empty() {
                    FailurePhase::Boot
                } else {
                    FailurePhase::Runtime
                },
                timeout_ns: request.command.timeout_ns,
            })
        } else if request.output.exit_code != Some(0) {
            if terminal.is_some() {
                return Err(RunError::UnexpectedTestEvent(
                    "guest emitted RunFinished but QEMU did not exit successfully".to_owned(),
                ));
            }
            Some(TestOutcome::Crashed {
                code: request.output.exit_code,
                message: "QEMU exited before the guest emitted RunFinished".to_owned(),
            })
        } else if terminal.is_none() {
            Some(TestOutcome::Failed {
                phase: FailurePhase::Protocol,
                message: "guest stream ended without RunFinished".to_owned(),
            })
        } else {
            None
        };
        let command_digest =
            self.command_digest(request.command, request.components, is_cancelled)?;
        let event_stream_digest = self.event_stream_digest(request.events, is_cancelled)?;
        let result = ImageGroupResult {
            group: request.group.id,
            cases,
            events: request.events.to_vec(),
            evidence: ImageExecutionEvidence {
                image_digest: Some(request.artifact.digest()),
                target_digest: request.artifact.build().target_package,
                emulator_digest: Some(request.components.emulator.digest()),
                scenario_digest: request.scenario.map(|scenario| scenario.digest),
                command_digest: Some(command_digest),
                event_stream_digest: Some(event_stream_digest),
                exit_code: request.output.exit_code,
                stderr: request.output.stderr,
            },
            infrastructure_failure,
        };
        check_cancelled(is_cancelled)?;
        Ok(result)
    }
}

fn decode_slip(
    bytes: &[u8],
    limits: ProtocolLimits,
    preserve_complete_prefix: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, RunError> {
    let frame_limit = usize::try_from(limits.frame_bytes)
        .map_err(|_| RunError::Protocol("frame limit does not fit host usize".to_owned()))?;
    let stream_limit = usize::try_from(
        limits
            .maximum_stream_bytes()
            .map_err(|error| RunError::Protocol(error.to_string()))?,
    )
    .map_err(|_| RunError::Protocol("event-stream limit does not fit host usize".to_owned()))?;
    let mut stream = Vec::new();
    let mut frame = Vec::new();
    let mut started = false;
    let mut escaped = false;
    let mut raw_segment = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index % 4096 == 0 {
            check_cancelled(is_cancelled)?;
        }
        if !started {
            if byte == SLIP_END {
                started = true;
            }
            continue;
        }
        if raw_segment {
            if byte == SLIP_END {
                raw_segment = false;
                escaped = false;
                frame.clear();
            }
        } else if escaped {
            let decoded = match byte {
                SLIP_ESCAPED_END => SLIP_END,
                SLIP_ESCAPED_ESCAPE => SLIP_ESCAPE,
                _ => {
                    if frame.len() >= TEST_FRAME_MAGIC.len() {
                        return Err(RunError::Protocol(
                            "PL011 event frame contains a noncanonical SLIP escape".to_owned(),
                        ));
                    }
                    raw_segment = true;
                    frame.clear();
                    escaped = false;
                    continue;
                }
            };
            push_segment_byte(&mut frame, decoded, frame_limit, &mut raw_segment)?;
            escaped = false;
        } else {
            match byte {
                SLIP_END => {
                    if frame.len() >= TEST_FRAME_MAGIC.len() {
                        let total = stream.len().checked_add(frame.len()).ok_or_else(|| {
                            RunError::Protocol("event-stream byte count overflow".to_owned())
                        })?;
                        if total > stream_limit {
                            return Err(RunError::Protocol(
                                "unescaped event stream exceeds its bounded capacity".to_owned(),
                            ));
                        }
                        stream.try_reserve(frame.len()).map_err(|_| {
                            RunError::Protocol(
                                "cannot allocate bounded unescaped event stream".to_owned(),
                            )
                        })?;
                        stream.extend_from_slice(&frame);
                    }
                    frame.clear();
                }
                SLIP_ESCAPE => escaped = true,
                value => {
                    push_segment_byte(&mut frame, value, frame_limit, &mut raw_segment)?;
                }
            }
        }
    }
    check_cancelled(is_cancelled)?;
    if !preserve_complete_prefix && !raw_segment && frame.len() >= TEST_FRAME_MAGIC.len() {
        return Err(RunError::Protocol(
            "PL011 stream ends inside an incomplete SLIP frame".to_owned(),
        ));
    }
    Ok(stream)
}

fn push_segment_byte(
    frame: &mut Vec<u8>,
    byte: u8,
    limit: usize,
    raw_segment: &mut bool,
) -> Result<(), RunError> {
    if frame.len() < TEST_FRAME_MAGIC.len() && byte != TEST_FRAME_MAGIC[frame.len()] {
        frame.clear();
        *raw_segment = true;
        return Ok(());
    }
    push_frame_byte(frame, byte, limit)
}

fn push_frame_byte(frame: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), RunError> {
    if frame.len() >= limit {
        return Err(RunError::Protocol(
            "unescaped SLIP frame exceeds the protocol limit".to_owned(),
        ));
    }
    frame
        .try_reserve(1)
        .map_err(|_| RunError::Protocol("cannot allocate bounded SLIP frame".to_owned()))?;
    frame.push(byte);
    Ok(())
}

fn collect_cases(
    group: &FullImageTestGroup,
    events: &[TestEvent],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CollectedCases, RunError> {
    let first_test = group.tests.first().map(|test| test.descriptor.id.0);
    let state_index = |test: wrela_test_model::TestId| {
        test.0
            .checked_sub(first_test?)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|index| {
                group
                    .tests
                    .get(*index)
                    .is_some_and(|planned| planned.descriptor.id == test)
            })
    };
    let mut finished = Vec::new();
    finished.try_reserve_exact(group.tests.len()).map_err(|_| {
        RunError::InvalidInvocation("cannot allocate bounded test completion state".to_owned())
    })?;
    finished.resize(group.tests.len(), None);
    let mut terminal = None;
    for event in events {
        check_cancelled(is_cancelled)?;
        match &event.kind {
            TestEventKind::TestFinished { test, outcome } => {
                let state = state_index(*test).and_then(|index| finished.get_mut(index));
                if !matches!(state.as_deref(), Some(None)) {
                    return Err(RunError::UnexpectedTestEvent(format!(
                        "duplicate or unplanned TestFinished for id {}",
                        test.0
                    )));
                }
                let Some(state) = state else {
                    return Err(RunError::UnexpectedTestEvent(format!(
                        "unplanned TestFinished for id {}",
                        test.0
                    )));
                };
                *state = Some(outcome);
            }
            TestEventKind::RunFinished { passed, failed } => {
                if terminal.replace((*passed, *failed)).is_some() {
                    return Err(RunError::DuplicateTerminalEvent);
                }
            }
            TestEventKind::RunStarted { .. }
            | TestEventKind::TestStarted { .. }
            | TestEventKind::Log { .. }
            | TestEventKind::AssertionFailed { .. }
            | TestEventKind::Heartbeat { .. } => {}
        }
    }
    let mut cases = Vec::new();
    cases.try_reserve_exact(group.tests.len()).map_err(|_| {
        RunError::InvalidInvocation("cannot allocate bounded test case results".to_owned())
    })?;
    let mut encountered_gap = false;
    for (planned, outcome) in group.tests.iter().zip(finished) {
        check_cancelled(is_cancelled)?;
        match outcome {
            Some(outcome) if !encountered_gap => cases.push(TestCaseResult {
                descriptor: planned.descriptor.clone(),
                outcome: guest_outcome(outcome),
                duration_ns: None,
            }),
            Some(_) => {
                return Err(RunError::UnexpectedTestEvent(
                    "guest completed a non-prefix test after an unfinished test".to_owned(),
                ));
            }
            None => encountered_gap = true,
        }
    }
    Ok(CollectedCases { cases, terminal })
}

struct CollectedCases {
    cases: Vec<TestCaseResult>,
    terminal: Option<(u32, u32)>,
}

fn guest_outcome(outcome: &GuestTestOutcome) -> TestOutcome {
    match outcome {
        GuestTestOutcome::Passed => TestOutcome::Passed,
        GuestTestOutcome::Failed { message } => TestOutcome::Failed {
            phase: FailurePhase::Runtime,
            message: message.clone(),
        },
        GuestTestOutcome::TimedOut { timeout_ns } => TestOutcome::TimedOut {
            phase: FailurePhase::Runtime,
            timeout_ns: *timeout_ns,
        },
        GuestTestOutcome::LanguageFatal { cause } => TestOutcome::LanguageFatal { cause: *cause },
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), RunError> {
    if is_cancelled() {
        Err(RunError::Cancelled)
    } else {
        Ok(())
    }
}

fn qemu_option_unsafe(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| matches!(byte, 0 | b','))
}

fn os(value: impl AsRef<std::ffi::OsStr>) -> OsString {
    value.as_ref().to_owned()
}

fn option_path(prefix: &str, path: &std::path::Path) -> OsString {
    let mut value = OsString::from(prefix);
    value.push(path.as_os_str());
    value
}

fn qemu_arguments(
    runner: &TargetRunnerContract,
    firmware_code: &std::path::Path,
    firmware_variables: &std::path::Path,
    esp: &std::path::Path,
    shutdown_control: Option<&ProcessShutdownControl>,
) -> Vec<OsString> {
    let mut fat_drive = option_path("if=none,format=raw,file=fat:rw:", esp);
    fat_drive.push(",id=hd0");
    let mut arguments = vec![
        os("-machine"),
        os(runner.machine()),
        os("-cpu"),
        os(runner.cpu()),
        os("-accel"),
        os(runner.accelerator()),
        os("-m"),
        os(runner.memory_mib().to_string()),
        os("-smp"),
        os(runner.virtual_cpus().to_string()),
        os("-nic"),
        os("none"),
        os("-drive"),
        option_path(
            "if=pflash,format=raw,unit=0,readonly=on,file=",
            firmware_code,
        ),
        os("-drive"),
        option_path("if=pflash,format=raw,unit=1,file=", firmware_variables),
        os("-drive"),
        fat_drive,
        os("-device"),
        os("virtio-blk-device,drive=hd0"),
        os("-serial"),
        os("stdio"),
        os("-monitor"),
        os("none"),
        os("-display"),
        os("none"),
        os("-no-reboot"),
    ];
    if let Some(ProcessShutdownControl::QmpUnix { path }) = shutdown_control {
        arguments.push(os("-qmp"));
        let mut option = option_path("unix:", path);
        option.push(",server=on,wait=off");
        arguments.push(option);
    }
    arguments
}

struct CanonicalDigest {
    state: Sha256,
}

impl CanonicalDigest {
    fn new(magic: &[u8; 8], version: u32) -> Self {
        let mut state = Sha256::new();
        state.update(magic);
        state.update(&version.to_le_bytes());
        Self { state }
    }

    fn byte(&mut self, value: u8) {
        self.state.update(&[value]);
    }

    fn u64(&mut self, value: u64) -> Result<(), RunError> {
        self.state.update(&value.to_le_bytes());
        Ok(())
    }

    fn count(&mut self, value: usize) -> Result<(), RunError> {
        self.u64(u64::try_from(value).map_err(|_| {
            RunError::InvalidInvocation("canonical digest count does not fit u64".to_owned())
        })?)
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), RunError> {
        self.count(value.len())?;
        self.state.update(value);
        Ok(())
    }

    fn normalized_bytes(&mut self, value: &[u8], working: &[u8]) -> Result<(), RunError> {
        const WORK_MARKER: &[u8] = b"$WORK";
        if working.is_empty() {
            return Err(RunError::InvalidInvocation(
                "canonical command working path is empty".to_owned(),
            ));
        }
        let mut replacements = 0usize;
        let mut cursor = 0usize;
        while let Some(offset) = find_bytes(&value[cursor..], working) {
            replacements = replacements.checked_add(1).ok_or_else(|| {
                RunError::InvalidInvocation(
                    "canonical command path replacement count overflow".to_owned(),
                )
            })?;
            cursor = cursor
                .checked_add(offset)
                .and_then(|position| position.checked_add(working.len()))
                .ok_or_else(|| {
                    RunError::InvalidInvocation(
                        "canonical command path replacement offset overflow".to_owned(),
                    )
                })?;
        }
        let removed = working.len().checked_mul(replacements).ok_or_else(|| {
            RunError::InvalidInvocation(
                "canonical command path replacement length overflow".to_owned(),
            )
        })?;
        let inserted = WORK_MARKER.len().checked_mul(replacements).ok_or_else(|| {
            RunError::InvalidInvocation("canonical command marker length overflow".to_owned())
        })?;
        let normalized_length = value
            .len()
            .checked_sub(removed)
            .and_then(|length| length.checked_add(inserted))
            .ok_or_else(|| {
                RunError::InvalidInvocation(
                    "canonical command normalized length overflow".to_owned(),
                )
            })?;
        self.count(normalized_length)?;
        cursor = 0;
        while let Some(offset) = find_bytes(&value[cursor..], working) {
            let match_start = cursor + offset;
            self.state.update(&value[cursor..match_start]);
            self.state.update(WORK_MARKER);
            cursor = match_start + working.len();
        }
        self.state.update(&value[cursor..]);
        Ok(())
    }

    fn finish(self) -> Sha256Digest {
        self.state.finish()
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_DIGEST_MAGIC, COMMAND_DIGEST_VERSION, CanonicalDigest, CanonicalImageHarness,
        SLIP_END, SLIP_ESCAPE, SLIP_ESCAPED_END, SLIP_ESCAPED_ESCAPE, collect_cases, decode_slip,
        qemu_arguments,
    };
    use crate::{
        ImageHarness, ProcessOutput, ProcessShutdownControl, validate_decoded_group_prefix,
    };
    use wrela_build_model::Sha256Digest;
    use wrela_test_model::{
        FullImageTestGroup, FunctionKey, GuestTestOutcome, ImageGroupId, ImageRoot, ImageTest,
        ImageTestInvocation, LanguageFatalCause, TEST_PROTOCOL_VERSION, TestDescriptor, TestEvent,
        TestEventKind, TestId, TestKind, TestOutcome,
    };
    use wrela_test_protocol::{
        CanonicalTestEventCodec, ProtocolLimits, TEST_FRAME_MAGIC, seal_encoded_event,
    };

    #[test]
    fn qemu_arguments_match_the_target_owned_boot_contract() {
        let target = wrela_target::TargetPackage::aarch64_qemu_virt_uefi(
            wrela_build_model::Sha256Digest::from_bytes([7; 32]),
        );
        let arguments = qemu_arguments(
            target.runner(),
            std::path::Path::new("/private/QEMU_EFI.fd"),
            std::path::Path::new("/private/QEMU_VARS.fd"),
            std::path::Path::new("/private/esp"),
            None,
        );
        let rendered: Vec<_> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            rendered,
            [
                "-machine",
                "virt-10.0,gic-version=3,secure=off",
                "-cpu",
                "cortex-a57",
                "-accel",
                "tcg,thread=single",
                "-m",
                "512",
                "-smp",
                "1",
                "-nic",
                "none",
                "-drive",
                "if=pflash,format=raw,unit=0,readonly=on,file=/private/QEMU_EFI.fd",
                "-drive",
                "if=pflash,format=raw,unit=1,file=/private/QEMU_VARS.fd",
                "-drive",
                "if=none,format=raw,file=fat:rw:/private/esp,id=hd0",
                "-device",
                "virtio-blk-device,drive=hd0",
                "-serial",
                "stdio",
                "-monitor",
                "none",
                "-display",
                "none",
                "-no-reboot",
            ]
        );
    }

    #[test]
    fn qemu_shutdown_control_is_private_and_explicit() {
        let target = wrela_target::TargetPackage::aarch64_qemu_virt_uefi(
            wrela_build_model::Sha256Digest::from_bytes([7; 32]),
        );
        let control = ProcessShutdownControl::QmpUnix {
            path: std::path::PathBuf::from("/private/group/qmp.sock"),
        };
        let arguments = qemu_arguments(
            target.runner(),
            std::path::Path::new("/private/QEMU_EFI.fd"),
            std::path::Path::new("/private/QEMU_VARS.fd"),
            std::path::Path::new("/private/esp"),
            Some(&control),
        );
        let rendered: Vec<_> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &rendered[rendered.len() - 2..],
            ["-qmp", "unix:/private/group/qmp.sock,server=on,wait=off"]
        );
    }

    #[test]
    fn command_digest_normalizes_private_run_roots_without_losing_shape() {
        let mut left = CanonicalDigest::new(COMMAND_DIGEST_MAGIC, COMMAND_DIGEST_VERSION);
        left.normalized_bytes(
            b"if=pflash,file=/one/private/group/QEMU_EFI.fd",
            b"/one/private",
        )
        .expect("left command");
        let mut right = CanonicalDigest::new(COMMAND_DIGEST_MAGIC, COMMAND_DIGEST_VERSION);
        right
            .normalized_bytes(
                b"if=pflash,file=/another/root/group/QEMU_EFI.fd",
                b"/another/root",
            )
            .expect("right command");
        assert_eq!(left.finish(), right.finish());
    }

    fn slip(frame: &[u8]) -> Vec<u8> {
        let mut output = vec![SLIP_END];
        for byte in frame {
            match *byte {
                SLIP_END => output.extend_from_slice(&[SLIP_ESCAPE, SLIP_ESCAPED_END]),
                SLIP_ESCAPE => output.extend_from_slice(&[SLIP_ESCAPE, SLIP_ESCAPED_ESCAPE]),
                value => output.push(value),
            }
        }
        output.push(SLIP_END);
        output
    }

    fn producer_group(maximum_output_bytes: u64) -> FullImageTestGroup {
        FullImageTestGroup {
            id: ImageGroupId(0),
            name: "producer-shaped".to_owned(),
            root: ImageRoot::GeneratedHarness {
                harness_name: "generated".to_owned(),
            },
            tests: vec![ImageTest {
                descriptor: TestDescriptor {
                    id: TestId(41),
                    name: "runtime producer".to_owned(),
                    kind: TestKind::IntegrationImage,
                    source: None,
                    timeout_ns: 1_000_000,
                },
                invocation: ImageTestInvocation::GeneratedFunction {
                    function_key: FunctionKey(Sha256Digest::from_bytes([0x71; 32])),
                },
                assertions: Vec::new(),
            }],
            deterministic_seed: None,
            boot_timeout_ns: 1_000_000,
            shutdown_timeout_ns: 1_000_000,
            maximum_events: 4,
            maximum_output_bytes,
        }
    }

    fn producer_events() -> Vec<TestEvent> {
        vec![
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test: TestId(41) },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test: TestId(41),
                    outcome: GuestTestOutcome::Passed,
                },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::RunFinished {
                    passed: 1,
                    failed: 0,
                },
            },
        ]
    }

    fn language_fatal_events(cause: LanguageFatalCause) -> Vec<TestEvent> {
        let mut events = producer_events();
        events[2].kind = TestEventKind::TestFinished {
            test: TestId(41),
            outcome: GuestTestOutcome::LanguageFatal { cause },
        };
        events[3].kind = TestEventKind::RunFinished {
            passed: 0,
            failed: 1,
        };
        events
    }

    fn producer_serial(events: &[TestEvent], limits: ProtocolLimits) -> Vec<u8> {
        let mut serial = b"UEFI firmware banner\n".to_vec();
        for event in events {
            let frame = seal_encoded_event(&CanonicalTestEventCodec, event, limits, &|| false)
                .expect("seal producer event");
            serial.extend_from_slice(&slip(frame.bytes()));
        }
        serial
    }

    fn decode_producer_events(
        group: &FullImageTestGroup,
        events: &[TestEvent],
    ) -> Result<Vec<TestEvent>, crate::RunError> {
        let limits = crate::protocol_execution_policy(group)?.limits;
        CanonicalImageHarness::new().decode_events(
            group,
            &ProcessOutput {
                exit_code: Some(0),
                timed_out: false,
                stdout: producer_serial(events, limits),
                stderr: Vec::new(),
                duration_ns: 1,
            },
            &|| false,
        )
    }

    #[test]
    fn slip_transport_roundtrips_canonical_protocol_frames() {
        let event = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunFinished {
                passed: 0,
                failed: 0,
            },
        };
        let limits = ProtocolLimits::standard();
        let encoded = seal_encoded_event(&CanonicalTestEventCodec, &event, limits, &|| false)
            .expect("canonical frame");
        let mut serial = b"bounded firmware prefix\n".to_vec();
        serial.extend_from_slice(&slip(encoded.bytes()));
        assert_eq!(
            decode_slip(&serial, limits, false, &|| false).expect("valid SLIP"),
            encoded.bytes()
        );
        let events = CanonicalImageHarness::new()
            .event_stream_digest(&[event], &|| false)
            .expect("canonical event digest");
        assert!(events.as_bytes().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn slip_transport_rejects_invalid_escape_truncation_and_limit() {
        let limits = ProtocolLimits {
            frame_bytes: 32,
            string_bytes: 8,
            events: 1,
        };
        let mut invalid_escape = vec![SLIP_END];
        invalid_escape.extend_from_slice(TEST_FRAME_MAGIC);
        invalid_escape.extend_from_slice(&[SLIP_ESCAPE, 0]);
        assert!(decode_slip(&invalid_escape, limits, false, &|| false).is_err());
        let mut truncated = vec![SLIP_END];
        truncated.extend_from_slice(TEST_FRAME_MAGIC);
        truncated.push(1);
        assert!(decode_slip(&truncated, limits, false, &|| false).is_err());
        let mut oversized = vec![SLIP_END];
        oversized.extend_from_slice(TEST_FRAME_MAGIC);
        oversized.extend(std::iter::repeat_n(1, 25));
        oversized.push(SLIP_END);
        assert!(decode_slip(&oversized, limits, false, &|| false).is_err());
        assert!(matches!(
            decode_slip(&[SLIP_END, SLIP_END], limits, false, &|| true),
            Err(crate::RunError::Cancelled)
        ));
    }

    #[test]
    fn slip_transport_ignores_interleaved_nonprotocol_serial_segments() {
        let event = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunFinished {
                passed: 0,
                failed: 0,
            },
        };
        let limits = ProtocolLimits::standard();
        let encoded = seal_encoded_event(&CanonicalTestEventCodec, &event, limits, &|| false)
            .expect("canonical frame");
        let mut serial = slip(encoded.bytes());
        serial.extend_from_slice(b"pong\n");
        serial.extend_from_slice(&slip(encoded.bytes()));
        let mut expected = encoded.bytes().to_vec();
        expected.extend_from_slice(encoded.bytes());
        assert_eq!(
            decode_slip(&serial, limits, false, &|| false).expect("mixed serial stream"),
            expected
        );
    }

    #[test]
    fn production_harness_accepts_real_producer_shaped_lifecycle() {
        let group = producer_group(1024 * 1024);
        let events = producer_events();
        let limits = crate::protocol_execution_policy(&group)
            .expect("protocol policy")
            .limits;
        let output = ProcessOutput {
            exit_code: Some(0),
            timed_out: false,
            stdout: producer_serial(&events, limits),
            stderr: Vec::new(),
            duration_ns: 1,
        };
        let decoded = CanonicalImageHarness::new()
            .decode_events(&group, &output, &|| false)
            .expect("decode producer stream");
        assert_eq!(decoded, events);
        validate_decoded_group_prefix(&group, &decoded, &|| false)
            .expect("bind lifecycle to selected group");
    }

    #[test]
    fn typed_language_fatal_roundtrips_and_projects_exact_causes() {
        let group = producer_group(1024 * 1024);
        let mut digests = Vec::new();
        for cause in [
            LanguageFatalCause::CheckedShiftResultLoss,
            LanguageFatalCause::InvalidShiftCount,
        ] {
            let events = language_fatal_events(cause);
            let decoded = decode_producer_events(&group, &events)
                .expect("decode canonical language-fatal producer stream");
            assert_eq!(decoded, events);
            validate_decoded_group_prefix(&group, &decoded, &|| false)
                .expect("bind fatal lifecycle to selected group");
            let collected =
                collect_cases(&group, &decoded, &|| false).expect("project typed fatal case");
            assert_eq!(collected.terminal, Some((0, 1)));
            assert_eq!(collected.cases.len(), 1);
            assert_eq!(
                collected.cases[0].outcome,
                TestOutcome::LanguageFatal { cause }
            );
            digests.push(
                CanonicalImageHarness::new()
                    .event_stream_digest(&decoded, &|| false)
                    .expect("digest typed fatal stream"),
            );
        }
        assert_ne!(digests[0], digests[1]);
    }

    #[test]
    fn typed_language_fatal_rejects_inactive_duplicate_late_foreign_and_pass_after_fatal() {
        let cause = LanguageFatalCause::CheckedShiftResultLoss;
        let group = producer_group(1024 * 1024);

        let inactive = vec![
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestFinished {
                    test: TestId(41),
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            },
        ];
        assert!(matches!(
            decode_producer_events(&group, &inactive),
            Err(crate::RunError::Protocol(_))
        ));

        let mut duplicate = language_fatal_events(cause);
        duplicate.insert(
            3,
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::TestFinished {
                    test: TestId(41),
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            },
        );
        duplicate[4].sequence = 4;
        let mut five_events = group.clone();
        five_events.maximum_events = 5;
        assert!(matches!(
            decode_producer_events(&five_events, &duplicate),
            Err(crate::RunError::Protocol(_))
        ));

        let mut late = language_fatal_events(cause);
        late.push(TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 4,
            kind: TestEventKind::Heartbeat { monotonic_ticks: 1 },
        });
        assert!(matches!(
            decode_producer_events(&five_events, &late),
            Err(crate::RunError::Protocol(_))
        ));

        let mut foreign = language_fatal_events(cause);
        foreign[1].kind = TestEventKind::TestStarted { test: TestId(42) };
        foreign[2].kind = TestEventKind::TestFinished {
            test: TestId(42),
            outcome: GuestTestOutcome::LanguageFatal { cause },
        };
        let decoded = decode_producer_events(&group, &foreign)
            .expect("protocol cannot know the selected group test identities");
        assert!(matches!(
            validate_decoded_group_prefix(&group, &decoded, &|| false),
            Err(crate::RunError::UnexpectedTestEvent(_))
        ));

        let mut two_tests = group.clone();
        let mut second = two_tests.tests[0].clone();
        second.descriptor.id = TestId(42);
        second.descriptor.name = "runtime producer after fatal".to_owned();
        two_tests.tests.push(second);
        two_tests.maximum_events = 6;
        let pass_after_fatal = vec![
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 2 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test: TestId(41) },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test: TestId(41),
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::TestStarted { test: TestId(42) },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 4,
                kind: TestEventKind::TestFinished {
                    test: TestId(42),
                    outcome: GuestTestOutcome::Passed,
                },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 5,
                kind: TestEventKind::RunFinished {
                    passed: 1,
                    failed: 1,
                },
            },
        ];
        assert!(matches!(
            decode_producer_events(&two_tests, &pass_after_fatal),
            Err(crate::RunError::Protocol(_))
        ));
    }

    #[test]
    fn typed_language_fatal_transport_rejects_corrupt_truncated_limits_and_late_cancel() {
        let events = language_fatal_events(LanguageFatalCause::InvalidShiftCount);
        let group = producer_group(1024 * 1024);
        let limits = crate::protocol_execution_policy(&group)
            .expect("protocol policy")
            .limits;
        let frame = seal_encoded_event(&CanonicalTestEventCodec, &events[2], limits, &|| false)
            .expect("seal typed fatal frame");
        let mut corrupt = frame.bytes().to_vec();
        *corrupt.last_mut().expect("fatal frame payload") ^= 1;
        let corrupt_output = ProcessOutput {
            exit_code: Some(0),
            timed_out: false,
            stdout: slip(&corrupt),
            stderr: Vec::new(),
            duration_ns: 1,
        };
        assert!(matches!(
            CanonicalImageHarness::new().decode_events(&group, &corrupt_output, &|| false),
            Err(crate::RunError::Protocol(_))
        ));

        let mut truncated = slip(frame.bytes());
        assert_eq!(truncated.pop(), Some(SLIP_END));
        let truncated_output = ProcessOutput {
            stdout: truncated,
            ..corrupt_output
        };
        assert!(matches!(
            CanonicalImageHarness::new().decode_events(&group, &truncated_output, &|| false),
            Err(crate::RunError::Protocol(_))
        ));

        let exact_frame_bytes =
            u32::try_from(frame.bytes().len()).expect("bounded fatal frame length fits u32");
        let exact_limits = ProtocolLimits {
            frame_bytes: exact_frame_bytes,
            string_bytes: 1,
            ..limits
        };
        let slipped = slip(frame.bytes());
        assert_eq!(
            decode_slip(&slipped, exact_limits, false, &|| false)
                .expect("exact frame limit accepts typed fatal"),
            frame.bytes()
        );
        let tight_limits = ProtocolLimits {
            frame_bytes: exact_frame_bytes - 1,
            ..exact_limits
        };
        assert!(decode_slip(&slipped, tight_limits, false, &|| false).is_err());

        let serial = producer_serial(&events, limits);
        let exact_output_bytes = u64::try_from(serial.len()).expect("serial length fits u64");
        let exact_output_group = producer_group(exact_output_bytes);
        assert_eq!(
            decode_producer_events(&exact_output_group, &events)
                .expect("exact output limit accepts typed fatal"),
            events
        );
        let tight_output_group = producer_group(exact_output_bytes - 1);
        assert!(matches!(
            decode_producer_events(&tight_output_group, &events),
            Err(crate::RunError::OutputLimitExceeded(_))
        ));

        let polls = std::cell::Cell::new(0_u8);
        let late_cancel = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 2
        };
        assert!(matches!(
            decode_slip(&slipped, exact_limits, false, &late_cancel),
            Err(crate::RunError::Cancelled)
        ));
    }

    #[test]
    fn crash_and_timeout_preserve_only_complete_protocol_prefix_frames() {
        let group = producer_group(1024 * 1024);
        let events = producer_events();
        let limits = crate::protocol_execution_policy(&group)
            .expect("protocol policy")
            .limits;
        let mut serial = producer_serial(&events[..2], limits);
        let trailing = seal_encoded_event(&CanonicalTestEventCodec, &events[2], limits, &|| false)
            .expect("seal interrupted event");
        let trailing = slip(trailing.bytes());
        serial.extend_from_slice(&trailing[..trailing.len() / 2]);

        let timeout = ProcessOutput {
            exit_code: None,
            timed_out: true,
            stdout: serial.clone(),
            stderr: Vec::new(),
            duration_ns: 1,
        };
        assert_eq!(
            CanonicalImageHarness::new()
                .decode_events(&group, &timeout, &|| false)
                .expect("decode complete timeout prefix"),
            events[..2]
        );
        let crash = ProcessOutput {
            timed_out: false,
            ..timeout.clone()
        };
        assert_eq!(
            CanonicalImageHarness::new()
                .decode_events(&group, &crash, &|| false)
                .expect("decode complete crash prefix"),
            events[..2]
        );
        let nominal_success = ProcessOutput {
            exit_code: Some(0),
            ..crash
        };
        assert!(
            CanonicalImageHarness::new()
                .decode_events(&group, &nominal_success, &|| false)
                .is_err()
        );
    }

    #[test]
    fn production_harness_rejects_corrupt_stale_duplicate_and_dangling_frames() {
        let group = producer_group(1024 * 1024);
        let limits = crate::protocol_execution_policy(&group)
            .expect("protocol policy")
            .limits;
        let first = producer_events().remove(0);
        let sealed = seal_encoded_event(&CanonicalTestEventCodec, &first, limits, &|| false)
            .expect("seal first frame");

        let mut corrupt = sealed.bytes().to_vec();
        *corrupt.last_mut().expect("payload byte") ^= 1;
        let corrupt_output = ProcessOutput {
            exit_code: None,
            timed_out: false,
            stdout: slip(&corrupt),
            stderr: Vec::new(),
            duration_ns: 1,
        };
        assert!(
            CanonicalImageHarness::new()
                .decode_events(&group, &corrupt_output, &|| false)
                .is_err()
        );

        let mut stale = sealed.bytes().to_vec();
        stale[12..16].copy_from_slice(&1_u32.to_le_bytes());
        let stale_output = ProcessOutput {
            stdout: slip(&stale),
            ..corrupt_output.clone()
        };
        assert!(
            CanonicalImageHarness::new()
                .decode_events(&group, &stale_output, &|| false)
                .is_err()
        );

        let duplicate = vec![
            first.clone(),
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
        ];
        let duplicate_output = ProcessOutput {
            stdout: producer_serial(&duplicate, limits),
            ..corrupt_output.clone()
        };
        assert!(
            CanonicalImageHarness::new()
                .decode_events(&group, &duplicate_output, &|| false)
                .is_err()
        );

        let dangling = vec![
            first,
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::Log {
                    test: Some(TestId(41)),
                    level: wrela_test_model::LogLevel::Info,
                    message: "not active".to_owned(),
                },
            },
        ];
        let dangling_output = ProcessOutput {
            stdout: producer_serial(&dangling, limits),
            ..corrupt_output
        };
        assert!(
            CanonicalImageHarness::new()
                .decode_events(&group, &dangling_output, &|| false)
                .is_err()
        );
    }

    #[test]
    fn transport_and_process_policy_reject_maximum_plus_one_and_late_cancel() {
        let tiny = ProtocolLimits {
            frame_bytes: 32,
            string_bytes: 8,
            events: 1,
        };
        let mut maximum_plus_one = vec![SLIP_END];
        maximum_plus_one.extend_from_slice(TEST_FRAME_MAGIC);
        maximum_plus_one.extend(std::iter::repeat_n(1, 25));
        maximum_plus_one.push(SLIP_END);
        assert!(decode_slip(&maximum_plus_one, tiny, false, &|| false).is_err());

        let events = producer_events();
        let generous = producer_group(1024 * 1024);
        let limits = crate::protocol_execution_policy(&generous)
            .expect("protocol policy")
            .limits;
        let serial = producer_serial(&events, limits);
        let tight = producer_group(u64::try_from(serial.len() - 1).expect("tight limit"));
        let output = ProcessOutput {
            exit_code: Some(0),
            timed_out: false,
            stdout: serial,
            stderr: Vec::new(),
            duration_ns: 1,
        };
        assert!(matches!(
            CanonicalImageHarness::new().decode_events(&tight, &output, &|| false),
            Err(crate::RunError::OutputLimitExceeded(_))
        ));

        let polls = std::cell::Cell::new(0_u8);
        let late_cancel = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert!(matches!(
            decode_slip(
                &vec![0_u8; 8193],
                ProtocolLimits::standard(),
                false,
                &late_cancel,
            ),
            Err(crate::RunError::Cancelled)
        ));
    }
}
