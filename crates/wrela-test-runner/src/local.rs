//! Bounded local process capability for full-image QEMU execution.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use wrela_test_model::{ExpectedScenarioEvent, ImageScenarioStep, TestEvent, TestEventKind};
use wrela_test_protocol::{
    CanonicalTestEventCodec, ProtocolLimits, TEST_FRAME_MAGIC, decode_and_verify_event,
};

use crate::sha256::Sha256;
use crate::{
    ExecuteError, ImageScenario, ProcessExecutor, ProcessInput, ProcessOutput,
    ProcessShutdownControl, ProcessSpecification,
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const STREAM_CHANNEL_CHUNKS: usize = 8;
const STREAM_CHUNK_BYTES: usize = 16 * 1024;
const QMP_MESSAGE_BYTES: usize = 64 * 1024;
const QMP_MAXIMUM_MESSAGES_PER_PHASE: usize = 1024;
const QMP_MAXIMUM_JSON_DEPTH: u8 = 32;
const SLIP_END: u8 = 0xc0;
const SLIP_ESCAPE: u8 = 0xdb;
const SLIP_ESCAPED_END: u8 = 0xdc;
const SLIP_ESCAPED_ESCAPE: u8 = 0xdd;

/// Production child-process implementation. It remeasures every executable
/// input immediately before launch, stages private copies, clears the ambient
/// environment, and bounds both time and aggregate captured output.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalProcessExecutor;

impl LocalProcessExecutor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProcessExecutor for LocalProcessExecutor {
    fn execute(
        &self,
        specification: &ProcessSpecification,
        scenario: Option<&ImageScenario>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessOutput, ExecuteError> {
        validate_specification(specification)?;
        validate_scenario_contract(specification, scenario)?;
        check_cancelled(is_cancelled)?;
        verify_ambient_file(&specification.program, true, is_cancelled)?;
        let staged = stage_inputs(specification, is_cancelled)?;
        if let Err(error) = prepare_shutdown_control(specification) {
            return match cleanup_process_directory(specification, &staged, false) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        let result = match scenario {
            Some(scenario) => run_interactive_child(specification, scenario, is_cancelled),
            None => run_child(specification, is_cancelled),
        };
        match cleanup_process_directory(specification, &staged, true) {
            Ok(()) => result,
            Err(cleanup) => Err(cleanup),
        }
    }
}

fn validate_specification(specification: &ProcessSpecification) -> Result<(), ExecuteError> {
    let maximum_protocol_bytes = specification
        .protocol_limits
        .maximum_stream_bytes()
        .map_err(|_| {
            ExecuteError::InvalidSpecification("process protocol limits are invalid or excessive")
        })?;
    if specification.timeout_ns == 0
        || specification.maximum_output_bytes == 0
        || specification.maximum_output_bytes > maximum_protocol_bytes
    {
        return Err(ExecuteError::InvalidSpecification(
            "process timeout/output limits must be nonzero and within the protocol stream policy",
        ));
    }
    if let Some(ProcessShutdownControl::QmpUnix { path }) = &specification.shutdown_control {
        if !super::private_child(&specification.current_directory, path)
            || !super::valid_qmp_unix_path(path)
        {
            return Err(ExecuteError::InvalidSpecification(
                "QMP shutdown endpoint must be a bounded private normalized child path",
            ));
        }
        let parent = path.parent().ok_or(ExecuteError::InvalidSpecification(
            "QMP shutdown endpoint has no parent directory",
        ))?;
        ensure_existing_ancestors_are_not_symlinks(parent)?;
    }
    if !super::normal_absolute_path(&specification.program)
        || !super::normal_absolute_path(&specification.current_directory)
        || specification.current_directory.components().count() <= 1
    {
        return Err(ExecuteError::InvalidSpecification(
            "program and private current directory must be normalized absolute paths",
        ));
    }
    let directory = fs::symlink_metadata(&specification.current_directory).map_err(|error| {
        ExecuteError::Stage {
            path: specification.current_directory.clone(),
            error,
        }
    })?;
    if !directory.is_dir() || directory.file_type().is_symlink() {
        return Err(ExecuteError::InvalidSpecification(
            "private current directory must be a real directory",
        ));
    }
    #[cfg(unix)]
    if directory.mode() & 0o077 != 0 {
        return Err(ExecuteError::InvalidSpecification(
            "private current directory must deny group and world access",
        ));
    }
    if !specification
        .environment
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
        || specification
            .environment
            .iter()
            .any(|(name, value)| name.is_empty() || contains_nul(name) || contains_nul(value))
        || specification.arguments.iter().any(contains_nul)
    {
        return Err(ExecuteError::InvalidSpecification(
            "arguments and sorted environment must be free of NUL bytes",
        ));
    }
    if !specification.inputs.windows(2).all(|pair| {
        pair[0].destination < pair[1].destination && pair[0].source.path() != pair[1].source.path()
    }) || specification.inputs.iter().any(|input| {
        !super::private_child(&specification.current_directory, &input.destination)
            || input.source.path() == input.destination
    }) {
        return Err(ExecuteError::InvalidSpecification(
            "staged inputs must have distinct sorted sources and private destinations",
        ));
    }
    ensure_no_symlink_ancestors(&specification.current_directory)?;
    Ok(())
}

fn prepare_shutdown_control(specification: &ProcessSpecification) -> Result<(), ExecuteError> {
    let Some(ProcessShutdownControl::QmpUnix { path }) = &specification.shutdown_control else {
        return Ok(());
    };
    let parent = path.parent().ok_or(ExecuteError::InvalidSpecification(
        "QMP shutdown endpoint has no parent directory",
    ))?;
    ensure_no_symlink_ancestors(parent)?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| ExecuteError::Stage {
        path: parent.to_owned(),
        error,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ExecuteError::InvalidSpecification(
            "QMP shutdown endpoint parent must be a real directory",
        ));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        return Err(ExecuteError::InvalidSpecification(
            "QMP shutdown endpoint parent must deny group and world access",
        ));
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ExecuteError::Stage {
            path: path.clone(),
            error,
        }),
        Ok(_) => Err(ExecuteError::InvalidSpecification(
            "QMP shutdown endpoint must not exist before emulator launch",
        )),
    }
}

fn validate_scenario_contract(
    specification: &ProcessSpecification,
    scenario: Option<&ImageScenario>,
) -> Result<(), ExecuteError> {
    let Some(scenario) = scenario else {
        if specification.shutdown_control.is_some() {
            return Err(ExecuteError::InvalidSpecification(
                "generated harness cannot declare scenario shutdown control",
            ));
        }
        return Ok(());
    };
    scenario
        .validate_shape()
        .map_err(|_| ExecuteError::InvalidSpecification("image scenario shape is invalid"))?;
    let needs_shutdown = scenario
        .steps
        .iter()
        .any(|step| matches!(step, ImageScenarioStep::RequestShutdown { .. }));
    if needs_shutdown != specification.shutdown_control.is_some() {
        return Err(ExecuteError::InvalidSpecification(
            "scenario shutdown step and sealed process control differ",
        ));
    }
    Ok(())
}

fn contains_nul(value: &std::ffi::OsString) -> bool {
    value.as_encoded_bytes().contains(&0)
}

fn stage_inputs(
    specification: &ProcessSpecification,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<PathBuf>, ExecuteError> {
    let mut staged = Vec::new();
    staged
        .try_reserve_exact(specification.inputs.len())
        .map_err(|_| ExecuteError::InvalidSpecification("too many staged process inputs"))?;
    for (index, input) in specification.inputs.iter().enumerate() {
        if let Err(error) = stage_input(&specification.current_directory, input, is_cancelled) {
            let mut cleanup = None;
            retain_first_cleanup_error(&mut cleanup, remove_staged(&staged));
            retain_first_cleanup_error(
                &mut cleanup,
                remove_empty_parent_directories(
                    &specification.current_directory,
                    specification.inputs[..=index]
                        .iter()
                        .map(|input| input.destination.as_path()),
                ),
            );
            return cleanup.map_or_else(|| Err(error), Err);
        }
        staged.push(input.destination.clone());
    }
    Ok(staged)
}

fn stage_input(
    private_root: &Path,
    input: &ProcessInput,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ExecuteError> {
    check_cancelled(is_cancelled)?;
    if !super::private_child(private_root, &input.destination) {
        return Err(ExecuteError::InvalidSpecification(
            "staged input escapes the private process directory",
        ));
    }
    let parent = input
        .destination
        .parent()
        .ok_or(ExecuteError::InvalidSpecification(
            "staged input has no parent directory",
        ))?;
    fs::create_dir_all(parent).map_err(|error| ExecuteError::Stage {
        path: parent.to_owned(),
        error,
    })?;
    ensure_no_symlink_ancestors(parent)?;
    restrict_private_directories(private_root, parent)?;

    let source_path = input.source.path();
    let before = checked_source_metadata(source_path, false)?;
    let mut source = File::open(source_path).map_err(|error| ExecuteError::Stage {
        path: source_path.to_owned(),
        error,
    })?;
    if !same_open_file(
        &before,
        &source.metadata().map_err(|error| ExecuteError::Stage {
            path: source_path.to_owned(),
            error,
        })?,
    ) {
        return verification(source_path, "source changed while it was opened");
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut destination =
        options
            .open(&input.destination)
            .map_err(|error| ExecuteError::Stage {
                path: input.destination.clone(),
                error,
            })?;
    let mut created = CreatedFileGuard::new(input.destination.clone());
    let (bytes, digest) = copy_and_measure(
        &mut source,
        &mut destination,
        input.source.bytes(),
        source_path,
        Some(&input.destination),
        is_cancelled,
    )?;
    destination.flush().map_err(|error| ExecuteError::Stage {
        path: input.destination.clone(),
        error,
    })?;
    destination
        .sync_all()
        .map_err(|error| ExecuteError::Stage {
            path: input.destination.clone(),
            error,
        })?;
    let after_open = source.metadata().map_err(|error| ExecuteError::Stage {
        path: source_path.to_owned(),
        error,
    })?;
    let after_path = checked_source_metadata(source_path, false)?;
    if bytes != input.source.bytes()
        || digest != input.source.digest()
        || !same_open_file(&before, &after_open)
        || !same_open_file(&before, &after_path)
    {
        return verification(
            source_path,
            "staged source identity, size, or digest changed",
        );
    }

    set_staged_permissions(&input.destination, input.writable)?;
    let staged_metadata = destination
        .metadata()
        .map_err(|error| ExecuteError::Stage {
            path: input.destination.clone(),
            error,
        })?;
    let staged_path =
        fs::symlink_metadata(&input.destination).map_err(|error| ExecuteError::Stage {
            path: input.destination.clone(),
            error,
        })?;
    if staged_metadata.len() != bytes || !same_open_file(&staged_metadata, &staged_path) {
        return verification(
            &input.destination,
            "staged destination changed before process launch",
        );
    }
    sync_directory(parent)?;
    check_cancelled(is_cancelled)?;
    created.commit();
    Ok(())
}

/// Apply hygiene and open-time-identity checks to an ambient system path (the
/// resolved QEMU program) that carries no separately declared expected digest
/// or length to compare against, unlike a staged [`ProcessInput`] source.
fn verify_ambient_file(
    path: &Path,
    executable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ExecuteError> {
    check_cancelled(is_cancelled)?;
    let before = checked_source_metadata(path, executable)?;
    let file = File::open(path).map_err(|error| ExecuteError::Stage {
        path: path.to_owned(),
        error,
    })?;
    let opened = file.metadata().map_err(|error| ExecuteError::Stage {
        path: path.to_owned(),
        error,
    })?;
    if !same_open_file(&before, &opened) {
        return verification(path, "verified file changed while it was opened");
    }
    check_cancelled(is_cancelled)
}

fn checked_source_metadata(path: &Path, executable: bool) -> Result<fs::Metadata, ExecuteError> {
    if !super::normal_absolute_path(path) {
        return verification(
            path,
            "verified process source is not a normalized absolute path",
        );
    }
    ensure_no_symlink_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| ExecuteError::Stage {
        path: path.to_owned(),
        error,
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return verification(path, "verified process source is not a regular file");
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return verification(
                path,
                "verified process source is hard-linked or group/world writable",
            );
        }
        if executable && metadata.mode() & 0o111 == 0 {
            return verification(path, "verified process executable has no execute bit");
        }
    }
    Ok(metadata)
}

fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), ExecuteError> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| ExecuteError::Stage {
            path: ancestor.to_owned(),
            error,
        })?;
        if metadata.file_type().is_symlink() {
            return verification(path, "verified process path traverses a symbolic link");
        }
    }
    Ok(())
}

fn ensure_existing_ancestors_are_not_symlinks(path: &Path) -> Result<(), ExecuteError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return verification(path, "verified process path traverses a symbolic link");
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ExecuteError::Stage {
                    path: ancestor.to_owned(),
                    error,
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_open_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_open_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.permissions().readonly() == right.permissions().readonly()
}

fn copy_and_measure<W: Write>(
    source: &mut File,
    destination: &mut W,
    expected_bytes: u64,
    source_path: &Path,
    destination_path: Option<&Path>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, wrela_build_model::Sha256Digest), ExecuteError> {
    let mut total = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(is_cancelled)?;
        let read = source
            .read(&mut buffer)
            .map_err(|error| ExecuteError::Stage {
                path: source_path.to_owned(),
                error,
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ExecuteError::InvalidSpecification(
                "verified process input length overflowed",
            ))?;
        if total > expected_bytes {
            return verification(
                source_path,
                "verified process input exceeds its sealed length",
            );
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|error| ExecuteError::Stage {
                path: destination_path.unwrap_or(source_path).to_owned(),
                error,
            })?;
        digest.update(&buffer[..read]);
    }
    Ok((total, digest.finish()))
}

fn set_staged_permissions(path: &Path, writable: bool) -> Result<(), ExecuteError> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| ExecuteError::Stage {
            path: path.to_owned(),
            error,
        })?
        .permissions();
    #[cfg(unix)]
    permissions.set_mode(if writable { 0o600 } else { 0o400 });
    #[cfg(not(unix))]
    permissions.set_readonly(!writable);
    fs::set_permissions(path, permissions).map_err(|error| ExecuteError::Stage {
        path: path.to_owned(),
        error,
    })
}

fn restrict_private_directories(root: &Path, leaf: &Path) -> Result<(), ExecuteError> {
    if !leaf.starts_with(root) {
        return Err(ExecuteError::InvalidSpecification(
            "staging directory escapes the private root",
        ));
    }
    #[cfg(unix)]
    for path in leaf.ancestors() {
        let mut permissions = fs::metadata(path)
            .map_err(|error| ExecuteError::Stage {
                path: path.to_owned(),
                error,
            })?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).map_err(|error| ExecuteError::Stage {
            path: path.to_owned(),
            error,
        })?;
        if path == root {
            break;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ExecuteError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ExecuteError::Stage {
            path: path.to_owned(),
            error,
        })
}

fn run_child(
    specification: &ProcessSpecification,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, ExecuteError> {
    run_program(
        ChildRequest {
            program: &specification.program,
            arguments: &specification.arguments,
            current_directory: &specification.current_directory,
            environment: &specification.environment,
            timeout_ns: specification.timeout_ns,
            maximum_output_bytes: specification.maximum_output_bytes,
        },
        is_cancelled,
    )
}

fn run_interactive_child(
    specification: &ProcessSpecification,
    scenario: &ImageScenario,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, ExecuteError> {
    run_interactive_program(
        InteractiveRequest {
            program: &specification.program,
            arguments: &specification.arguments,
            current_directory: &specification.current_directory,
            environment: &specification.environment,
            timeout_ns: specification.timeout_ns,
            protocol_limits: specification.protocol_limits,
            maximum_output_bytes: specification.maximum_output_bytes,
            shutdown_control: specification.shutdown_control.as_ref(),
        },
        scenario,
        is_cancelled,
    )
}

struct InteractiveRequest<'a> {
    program: &'a Path,
    arguments: &'a [std::ffi::OsString],
    current_directory: &'a Path,
    environment: &'a [(std::ffi::OsString, std::ffi::OsString)],
    timeout_ns: u64,
    protocol_limits: ProtocolLimits,
    maximum_output_bytes: u64,
    shutdown_control: Option<&'a ProcessShutdownControl>,
}

fn run_interactive_program(
    request: InteractiveRequest<'_>,
    scenario: &ImageScenario,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, ExecuteError> {
    check_cancelled(is_cancelled)?;
    let mut command = Command::new(request.program);
    command
        .args(request.arguments)
        .current_dir(request.current_directory)
        .env_clear()
        .envs(request.environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_private_process_group(&mut command);
    let start = Instant::now();
    let mut child = command.spawn().map_err(ExecuteError::Spawn)?;
    let Some(stdin) = child.stdin.take() else {
        let _ = terminate(&mut child);
        return Err(ExecuteError::Wait(io::Error::other(
            "child stdin pipe was not created",
        )));
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = terminate(&mut child);
        return Err(ExecuteError::Wait(io::Error::other(
            "child stdout pipe was not created",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = terminate(&mut child);
        return Err(ExecuteError::Wait(io::Error::other(
            "child stderr pipe was not created",
        )));
    };
    let total = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(STREAM_CHANNEL_CHUNKS);
    let stdout_thread = match spawn_stream_reader(
        "wrela-qemu-live-stdout",
        stdout,
        stdout_sender,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        request.maximum_output_bytes,
    ) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = terminate(&mut child);
            return Err(error);
        }
    };
    let stderr_thread = match spawn_reader(
        "wrela-qemu-live-stderr",
        stderr,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        request.maximum_output_bytes,
    ) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = terminate(&mut child);
            drop(stdout_receiver);
            let _ = stdout_thread.join();
            return Err(error);
        }
    };
    let (stdin_sender, stdin_acknowledgements, stdin_thread) = match spawn_stdin_writer(stdin) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = terminate(&mut child);
            drop(stdout_receiver);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(error);
        }
    };
    let mut session = InteractiveSession {
        child,
        start,
        timeout: Duration::from_nanos(request.timeout_ns),
        maximum_output_bytes: request.maximum_output_bytes,
        exceeded,
        stdout_receiver,
        stdout_thread: Some(stdout_thread),
        stdout_closed: false,
        stderr_thread: Some(stderr_thread),
        stdin_sender: Some(stdin_sender),
        stdin_acknowledgements,
        stdin_thread: Some(stdin_thread),
        stdout: Vec::new(),
        observer: LiveSerialObserver::new(request.protocol_limits),
        status: None,
        observation_floor: 0,
    };

    let execution = drive_scenario(
        &mut session,
        scenario,
        request.shutdown_control,
        is_cancelled,
    );
    match execution {
        Ok(ScenarioProgress::Complete) => match session.wait_for_final_exit(is_cancelled) {
            Ok(timed_out) => finish_interactive_session(&mut session, timed_out, is_cancelled),
            Err(error) => {
                session.abort();
                Err(error)
            }
        },
        Ok(ScenarioProgress::TimedOut) => {
            finish_interactive_session(&mut session, true, is_cancelled)
        }
        Err(error) => {
            session.abort();
            Err(error)
        }
    }
}

fn finish_interactive_session(
    session: &mut InteractiveSession,
    timed_out: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, ExecuteError> {
    match session.finish(timed_out, is_cancelled) {
        Ok(output) => Ok(output),
        Err(error) => {
            session.abort();
            Err(error)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScenarioProgress {
    Complete,
    TimedOut,
}

fn drive_scenario(
    session: &mut InteractiveSession,
    scenario: &ImageScenario,
    shutdown_control: Option<&ProcessShutdownControl>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScenarioProgress, ExecuteError> {
    for step in &scenario.steps {
        session.pump(is_cancelled)?;
        match step {
            ImageScenarioStep::SendSerial { bytes } => {
                session.observation_floor = session.stdout.len();
                if session.send_serial(bytes, is_cancelled)? == ScenarioProgress::TimedOut {
                    return Ok(ScenarioProgress::TimedOut);
                }
            }
            ImageScenarioStep::ExpectSerial { bytes, timeout_ns } => {
                if session.expect_serial(bytes, *timeout_ns, is_cancelled)?
                    == ScenarioProgress::TimedOut
                {
                    return Ok(ScenarioProgress::TimedOut);
                }
            }
            ImageScenarioStep::ExpectTestEvent {
                kind,
                test,
                message_contains,
                timeout_ns,
            } => {
                if session.expect_event(
                    *kind,
                    *test,
                    message_contains.as_deref(),
                    *timeout_ns,
                    is_cancelled,
                )? == ScenarioProgress::TimedOut
                {
                    return Ok(ScenarioProgress::TimedOut);
                }
            }
            ImageScenarioStep::ExpectExit { code, timeout_ns } => {
                if session.expect_exit(*code, *timeout_ns, is_cancelled)?
                    == ScenarioProgress::TimedOut
                {
                    return Ok(ScenarioProgress::TimedOut);
                }
            }
            ImageScenarioStep::RequestShutdown { timeout_ns } => {
                session.observation_floor = session.stdout.len();
                let control = shutdown_control.ok_or(ExecuteError::InvalidSpecification(
                    "request-shutdown has no sealed control channel",
                ))?;
                if request_qmp_shutdown(session, control, *timeout_ns, is_cancelled)?
                    == ScenarioProgress::TimedOut
                {
                    return Ok(ScenarioProgress::TimedOut);
                }
            }
        }
    }
    Ok(ScenarioProgress::Complete)
}

#[derive(Debug, Clone, Copy)]
struct SerialRange {
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ObservedEvent {
    start: usize,
    end: usize,
    event: TestEvent,
}

/// Incremental demultiplexer for the shared PL011 byte stream. Canonical
/// `WRELTST` SLIP frames become typed events; all other delimited or preamble
/// bytes remain observable as scenario serial output.
#[derive(Debug)]
struct LiveSerialObserver {
    limits: ProtocolLimits,
    started: bool,
    raw_segment: bool,
    escaped: bool,
    segment_start: usize,
    frame: Vec<u8>,
    serial_ranges: Vec<SerialRange>,
    events: Vec<ObservedEvent>,
}

impl LiveSerialObserver {
    fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
            started: false,
            raw_segment: false,
            escaped: false,
            segment_start: 0,
            frame: Vec::new(),
            serial_ranges: Vec::new(),
            events: Vec::new(),
        }
    }

    fn push(
        &mut self,
        bytes: &[u8],
        absolute_start: usize,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ExecuteError> {
        let frame_limit = usize::try_from(self.limits.frame_bytes)
            .map_err(|_| scenario_error("live protocol frame limit does not fit host usize"))?;
        for (relative, byte) in bytes.iter().copied().enumerate() {
            if relative & 4095 == 0 {
                check_cancelled(is_cancelled)?;
            }
            let position = absolute_start
                .checked_add(relative)
                .ok_or_else(|| scenario_error("serial observation offset overflowed"))?;
            if byte == SLIP_END {
                if self.started {
                    self.finish_segment(position, is_cancelled)?;
                } else {
                    self.started = true;
                }
                self.segment_start = position
                    .checked_add(1)
                    .ok_or_else(|| scenario_error("serial observation offset overflowed"))?;
                continue;
            }
            if !self.started {
                self.add_serial_range(position, position + 1)?;
                continue;
            }
            if self.raw_segment {
                self.add_serial_range(position, position + 1)?;
                continue;
            }
            if self.frame.len() < TEST_FRAME_MAGIC.len() {
                self.push_frame_byte(byte, frame_limit)?;
                if TEST_FRAME_MAGIC.get(..self.frame.len()) != Some(self.frame.as_slice()) {
                    self.add_serial_range(self.segment_start, position + 1)?;
                    self.frame.clear();
                    self.raw_segment = true;
                }
                continue;
            }
            if self.escaped {
                let decoded = match byte {
                    SLIP_ESCAPED_END => SLIP_END,
                    SLIP_ESCAPED_ESCAPE => SLIP_ESCAPE,
                    _ => {
                        return Err(scenario_error(
                            "test-event frame contains a noncanonical SLIP escape",
                        ));
                    }
                };
                self.push_frame_byte(decoded, frame_limit)?;
                self.escaped = false;
            } else if byte == SLIP_ESCAPE {
                self.escaped = true;
            } else {
                self.push_frame_byte(byte, frame_limit)?;
            }
        }
        check_cancelled(is_cancelled)
    }

    fn push_frame_byte(&mut self, byte: u8, limit: usize) -> Result<(), ExecuteError> {
        if self.frame.len() >= limit {
            return Err(scenario_error(
                "test-event frame exceeds the protocol byte limit",
            ));
        }
        self.frame
            .try_reserve(1)
            .map_err(|_| scenario_error("cannot allocate bounded test-event frame"))?;
        self.frame.push(byte);
        Ok(())
    }

    fn finish_segment(
        &mut self,
        delimiter_position: usize,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ExecuteError> {
        if self.raw_segment {
            self.reset_segment();
            return Ok(());
        }
        if self.frame.is_empty() {
            self.reset_segment();
            return Ok(());
        }
        if self.frame.len() < TEST_FRAME_MAGIC.len() {
            self.add_serial_range(self.segment_start, delimiter_position)?;
            self.reset_segment();
            return Ok(());
        }
        if self.escaped {
            return Err(scenario_error("test-event frame ends inside a SLIP escape"));
        }
        let limits = self.limits;
        let event =
            decode_and_verify_event(&CanonicalTestEventCodec, &self.frame, limits, is_cancelled)
                .map_err(|error| {
                    scenario_error(format!("invalid live test-event frame: {error}"))
                })?;
        let expected_sequence = u64::try_from(self.events.len())
            .map_err(|_| scenario_error("live test-event count overflowed"))?;
        if event.sequence != expected_sequence {
            return Err(scenario_error(format!(
                "live test-event sequence gap: expected {expected_sequence}, got {}",
                event.sequence
            )));
        }
        if self.events.len() >= limits.events as usize {
            return Err(scenario_error(
                "live test-event count exceeds the selected group limit",
            ));
        }
        self.events
            .try_reserve(1)
            .map_err(|_| scenario_error("cannot allocate bounded live test-event list"))?;
        self.events.push(ObservedEvent {
            start: self.segment_start.saturating_sub(1),
            end: delimiter_position.saturating_add(1),
            event,
        });
        self.reset_segment();
        Ok(())
    }

    fn reset_segment(&mut self) {
        self.raw_segment = false;
        self.escaped = false;
        self.frame.clear();
    }

    fn add_serial_range(&mut self, start: usize, end: usize) -> Result<(), ExecuteError> {
        if start >= end {
            return Ok(());
        }
        if let Some(last) = self.serial_ranges.last_mut() {
            if last.end == start {
                last.end = end;
                return Ok(());
            }
        }
        self.serial_ranges
            .try_reserve(1)
            .map_err(|_| scenario_error("cannot allocate bounded serial observation ranges"))?;
        self.serial_ranges.push(SerialRange { start, end });
        Ok(())
    }

    fn find_serial(&self, stdout: &[u8], floor: usize, expected: &[u8]) -> Option<usize> {
        for range in &self.serial_ranges {
            let start = range.start.max(floor);
            if start >= range.end {
                continue;
            }
            let haystack = stdout.get(start..range.end)?;
            if let Some(offset) = find_subsequence(haystack, expected) {
                return start.checked_add(offset)?.checked_add(expected.len());
            }
        }
        None
    }

    fn find_event(
        &self,
        floor: usize,
        expected_kind: ExpectedScenarioEvent,
        expected_test: Option<wrela_test_model::TestId>,
        message_contains: Option<&str>,
    ) -> Option<usize> {
        self.events
            .iter()
            .find(|observed| {
                observed.start >= floor
                    && event_matches(
                        &observed.event,
                        expected_kind,
                        expected_test,
                        message_contains,
                    )
            })
            .map(|observed| observed.end)
    }

    fn finish(
        &mut self,
        stream_end: usize,
        preserve_complete_prefix: bool,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ExecuteError> {
        check_cancelled(is_cancelled)?;
        if !self.started || self.raw_segment || self.frame.is_empty() {
            return Ok(());
        }
        if self.frame.len() < TEST_FRAME_MAGIC.len() {
            self.add_serial_range(self.segment_start, stream_end)?;
            self.reset_segment();
            return Ok(());
        }
        if preserve_complete_prefix {
            self.reset_segment();
            return Ok(());
        }
        Err(scenario_error(
            "PL011 stream ended inside an incomplete test-event frame",
        ))
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn event_matches(
    event: &TestEvent,
    expected_kind: ExpectedScenarioEvent,
    expected_test: Option<wrela_test_model::TestId>,
    message_contains: Option<&str>,
) -> bool {
    let kind_matches = matches!(
        (expected_kind, &event.kind),
        (
            ExpectedScenarioEvent::RunStarted,
            TestEventKind::RunStarted { .. }
        ) | (
            ExpectedScenarioEvent::TestStarted,
            TestEventKind::TestStarted { .. }
        ) | (ExpectedScenarioEvent::Log, TestEventKind::Log { .. })
            | (
                ExpectedScenarioEvent::AssertionFailed,
                TestEventKind::AssertionFailed { .. }
            )
            | (
                ExpectedScenarioEvent::TestFinished,
                TestEventKind::TestFinished { .. }
            )
            | (
                ExpectedScenarioEvent::Heartbeat,
                TestEventKind::Heartbeat { .. }
            )
            | (
                ExpectedScenarioEvent::RunFinished,
                TestEventKind::RunFinished { .. }
            )
    );
    kind_matches
        && expected_test.is_none_or(|expected| event_test(&event.kind) == Some(expected))
        && message_contains.is_none_or(|needle| event_contains(&event.kind, needle))
}

fn event_test(kind: &TestEventKind) -> Option<wrela_test_model::TestId> {
    match kind {
        TestEventKind::TestStarted { test }
        | TestEventKind::AssertionFailed { test, .. }
        | TestEventKind::TestFinished { test, .. } => Some(*test),
        TestEventKind::Log { test, .. } => *test,
        TestEventKind::RunStarted { .. }
        | TestEventKind::Heartbeat { .. }
        | TestEventKind::RunFinished { .. } => None,
    }
}

fn event_contains(kind: &TestEventKind, needle: &str) -> bool {
    match kind {
        TestEventKind::Log { message, .. } => message.contains(needle),
        TestEventKind::AssertionFailed { failure, .. } => {
            failure.expression.contains(needle)
                || failure
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains(needle))
                || failure
                    .expected
                    .as_deref()
                    .is_some_and(|expected| expected.contains(needle))
                || failure
                    .actual
                    .as_deref()
                    .is_some_and(|actual| actual.contains(needle))
        }
        TestEventKind::TestFinished {
            outcome: wrela_test_model::GuestTestOutcome::Failed { message },
            ..
        } => message.contains(needle),
        TestEventKind::RunStarted { .. }
        | TestEventKind::TestStarted { .. }
        | TestEventKind::TestFinished { .. }
        | TestEventKind::Heartbeat { .. }
        | TestEventKind::RunFinished { .. } => false,
    }
}

struct InteractiveSession {
    child: Child,
    start: Instant,
    timeout: Duration,
    maximum_output_bytes: u64,
    exceeded: Arc<AtomicBool>,
    stdout_receiver: Receiver<Vec<u8>>,
    stdout_thread: Option<thread::JoinHandle<io::Result<()>>>,
    stdout_closed: bool,
    stderr_thread: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    stdin_sender: Option<SyncSender<Vec<u8>>>,
    stdin_acknowledgements: Receiver<io::Result<()>>,
    stdin_thread: Option<thread::JoinHandle<()>>,
    stdout: Vec<u8>,
    observer: LiveSerialObserver,
    status: Option<ExitStatus>,
    observation_floor: usize,
}

impl InteractiveSession {
    fn pump(&mut self, is_cancelled: &dyn Fn() -> bool) -> Result<(), ExecuteError> {
        check_cancelled(is_cancelled)?;
        loop {
            match self.stdout_receiver.try_recv() {
                Ok(chunk) => {
                    let start = self.stdout.len();
                    self.stdout
                        .try_reserve_exact(chunk.len())
                        .map_err(|_| scenario_error("cannot allocate bounded child stdout"))?;
                    self.stdout.extend_from_slice(&chunk);
                    self.observer
                        .push(&self.stdout[start..], start, is_cancelled)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.stdout_closed = true;
                    break;
                }
            }
        }
        if self.stdout_closed {
            if let Some(thread) = self.stdout_thread.take() {
                thread
                    .join()
                    .map_err(|_| {
                        ExecuteError::Wait(io::Error::other("live stdout reader thread panicked"))
                    })?
                    .map_err(ExecuteError::Wait)?;
            }
        }
        if self.exceeded.load(Ordering::Acquire) {
            return Err(ExecuteError::OutputLimit {
                stream: "aggregate stdout/stderr",
                limit: self.maximum_output_bytes,
            });
        }
        if self.status.is_none() {
            self.status = self.child.try_wait().map_err(ExecuteError::Wait)?;
        }
        Ok(())
    }

    fn send_serial(
        &mut self,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ScenarioProgress, ExecuteError> {
        if self.status.is_some() {
            return Err(scenario_error(
                "emulator exited before a send-serial scenario step",
            ));
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(bytes.len())
            .map_err(|_| scenario_error("cannot allocate bounded serial input"))?;
        payload.extend_from_slice(bytes);
        self.stdin_sender
            .as_ref()
            .ok_or_else(|| scenario_error("emulator serial input is already closed"))?
            .send(payload)
            .map_err(|_| scenario_error("emulator serial writer stopped unexpectedly"))?;
        loop {
            self.pump(is_cancelled)?;
            match self.stdin_acknowledgements.try_recv() {
                Ok(Ok(())) => return Ok(ScenarioProgress::Complete),
                Ok(Err(error)) => return Err(ExecuteError::Wait(error)),
                Err(TryRecvError::Disconnected) => {
                    return Err(scenario_error(
                        "emulator serial writer stopped before acknowledging input",
                    ));
                }
                Err(TryRecvError::Empty) => {}
            }
            if self.status.is_some() {
                return Err(scenario_error(
                    "emulator exited while a send-serial step was pending",
                ));
            }
            if self.global_timed_out() {
                return Ok(ScenarioProgress::TimedOut);
            }
            thread::sleep(self.poll_delay(None));
        }
    }

    fn expect_serial(
        &mut self,
        expected: &[u8],
        timeout_ns: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ScenarioProgress, ExecuteError> {
        let step_start = Instant::now();
        let step_timeout = Duration::from_nanos(timeout_ns);
        loop {
            self.pump(is_cancelled)?;
            if let Some(end) =
                self.observer
                    .find_serial(&self.stdout, self.observation_floor, expected)
            {
                self.observation_floor = end;
                return Ok(ScenarioProgress::Complete);
            }
            if self.status.is_some() {
                return Err(scenario_error(
                    "emulator exited before an expect-serial step matched",
                ));
            }
            if self.global_timed_out() || step_start.elapsed() >= step_timeout {
                return Ok(ScenarioProgress::TimedOut);
            }
            thread::sleep(self.poll_delay(Some((step_start, step_timeout))));
        }
    }

    fn expect_event(
        &mut self,
        expected_kind: ExpectedScenarioEvent,
        expected_test: Option<wrela_test_model::TestId>,
        message_contains: Option<&str>,
        timeout_ns: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ScenarioProgress, ExecuteError> {
        let step_start = Instant::now();
        let step_timeout = Duration::from_nanos(timeout_ns);
        loop {
            self.pump(is_cancelled)?;
            if let Some(end) = self.observer.find_event(
                self.observation_floor,
                expected_kind,
                expected_test,
                message_contains,
            ) {
                self.observation_floor = end;
                return Ok(ScenarioProgress::Complete);
            }
            if self.status.is_some() {
                return Err(scenario_error(
                    "emulator exited before an expect-test-event step matched",
                ));
            }
            if self.global_timed_out() || step_start.elapsed() >= step_timeout {
                return Ok(ScenarioProgress::TimedOut);
            }
            thread::sleep(self.poll_delay(Some((step_start, step_timeout))));
        }
    }

    fn expect_exit(
        &mut self,
        expected_code: Option<i32>,
        timeout_ns: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ScenarioProgress, ExecuteError> {
        let step_start = Instant::now();
        let step_timeout = Duration::from_nanos(timeout_ns);
        loop {
            self.pump(is_cancelled)?;
            if let Some(status) = self.status {
                if expected_code.is_some_and(|code| status.code() != Some(code)) {
                    return Err(scenario_error(format!(
                        "emulator exit code {:?} differs from scenario expectation {:?}",
                        status.code(),
                        expected_code
                    )));
                }
                return Ok(ScenarioProgress::Complete);
            }
            if self.global_timed_out() || step_start.elapsed() >= step_timeout {
                return Ok(ScenarioProgress::TimedOut);
            }
            thread::sleep(self.poll_delay(Some((step_start, step_timeout))));
        }
    }

    fn wait_for_final_exit(
        &mut self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, ExecuteError> {
        loop {
            self.pump(is_cancelled)?;
            if self.status.is_some() {
                return Ok(false);
            }
            if self.global_timed_out() {
                return Ok(true);
            }
            thread::sleep(self.poll_delay(None));
        }
    }

    fn global_timed_out(&self) -> bool {
        self.start.elapsed() >= self.timeout
    }

    fn poll_delay(&self, step: Option<(Instant, Duration)>) -> Duration {
        let global_remaining = self.timeout.saturating_sub(self.start.elapsed());
        let step_remaining = step.map_or(global_remaining, |(start, timeout)| {
            timeout
                .saturating_sub(start.elapsed())
                .min(global_remaining)
        });
        POLL_INTERVAL.min(step_remaining)
    }

    fn finish(
        &mut self,
        timed_out: bool,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessOutput, ExecuteError> {
        if timed_out && self.status.is_none() {
            self.status = Some(terminate(&mut self.child)?);
        }
        self.stdin_sender.take();
        self.drain_after_exit(is_cancelled)?;
        let preserve_complete_prefix =
            timed_out || self.status.is_none_or(|status| !status.success());
        self.observer
            .finish(self.stdout.len(), preserve_complete_prefix, is_cancelled)?;
        if let Some(thread) = self.stdin_thread.take() {
            thread.join().map_err(|_| {
                ExecuteError::Wait(io::Error::other("serial writer thread panicked"))
            })?;
        }
        let stderr = match self.stderr_thread.take() {
            Some(thread) => join_reader(thread)?,
            None => Vec::new(),
        };
        if self.exceeded.load(Ordering::Acquire) {
            return Err(ExecuteError::OutputLimit {
                stream: "aggregate stdout/stderr",
                limit: self.maximum_output_bytes,
            });
        }
        let duration_ns = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok(ProcessOutput {
            exit_code: self.status.and_then(|status| status.code()),
            timed_out,
            stdout: std::mem::take(&mut self.stdout),
            stderr,
            duration_ns,
        })
    }

    fn drain_after_exit(&mut self, is_cancelled: &dyn Fn() -> bool) -> Result<(), ExecuteError> {
        while !self.stdout_closed {
            self.pump(is_cancelled)?;
            if !self.stdout_closed {
                thread::sleep(POLL_INTERVAL);
            }
        }
        Ok(())
    }

    fn abort(&mut self) {
        if self.status.is_none() {
            self.status = terminate(&mut self.child).ok();
        }
        self.stdin_sender.take();
        while !self.stdout_closed {
            match self.stdout_receiver.recv_timeout(POLL_INTERVAL) {
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => self.stdout_closed = true,
            }
        }
        if let Some(thread) = self.stdout_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stdin_thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_stream_reader<R: Read + Send + 'static>(
    name: &str,
    mut reader: R,
    sender: SyncSender<Vec<u8>>,
    total: Arc<AtomicU64>,
    exceeded: Arc<AtomicBool>,
    limit: u64,
) -> Result<thread::JoinHandle<io::Result<()>>, ExecuteError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let mut buffer = [0u8; STREAM_CHUNK_BYTES];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    return Ok(());
                }
                if !reserve_output(&total, read as u64, limit) {
                    exceeded.store(true, Ordering::Release);
                    return Ok(());
                }
                let mut chunk = Vec::new();
                chunk.try_reserve_exact(read).map_err(io::Error::other)?;
                chunk.extend_from_slice(&buffer[..read]);
                if sender.send(chunk).is_err() {
                    return Ok(());
                }
            }
        })
        .map_err(ExecuteError::Wait)
}

type StdinWriter = (
    SyncSender<Vec<u8>>,
    Receiver<io::Result<()>>,
    thread::JoinHandle<()>,
);

fn spawn_stdin_writer(mut stdin: ChildStdin) -> Result<StdinWriter, ExecuteError> {
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(1);
    let (acknowledge, acknowledgements) = mpsc::sync_channel(1);
    let thread = thread::Builder::new()
        .name("wrela-qemu-stdin".to_owned())
        .spawn(move || {
            while let Ok(bytes) = receiver.recv() {
                let result = stdin.write_all(&bytes).and_then(|()| stdin.flush());
                let failed = result.is_err();
                if acknowledge.send(result).is_err() || failed {
                    break;
                }
            }
        })
        .map_err(ExecuteError::Wait)?;
    Ok((sender, acknowledgements, thread))
}

#[cfg(unix)]
fn request_qmp_shutdown(
    session: &mut InteractiveSession,
    control: &ProcessShutdownControl,
    timeout_ns: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScenarioProgress, ExecuteError> {
    let ProcessShutdownControl::QmpUnix { path } = control;
    let deadline = QmpDeadline {
        start: Instant::now(),
        timeout: Duration::from_nanos(timeout_ns),
    };
    let mut stream = loop {
        session.pump(is_cancelled)?;
        if session.status.is_some() {
            return Err(scenario_error(
                "emulator exited before request-shutdown could connect to QMP",
            ));
        }
        if qmp_timed_out(session, deadline) {
            return Ok(ScenarioProgress::TimedOut);
        }
        match UnixStream::connect(path) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                thread::sleep(session.poll_delay(Some((deadline.start, deadline.timeout))));
            }
            Err(error) => {
                return Err(scenario_error(format!(
                    "cannot connect to sealed QMP endpoint {}: {error}",
                    path.display()
                )));
            }
        }
    };
    let metadata = fs::symlink_metadata(path).map_err(|error| ExecuteError::Stage {
        path: path.clone(),
        error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(scenario_error(
            "sealed QMP endpoint did not become a Unix-domain socket",
        ));
    }
    stream.set_nonblocking(true).map_err(ExecuteError::Wait)?;
    let mut buffered = Vec::new();

    match read_qmp_line(session, &mut stream, &mut buffered, deadline, is_cancelled)? {
        QmpRead::Line(line) => {
            let greeting = parse_qmp_envelope(&line)?;
            if !greeting.qmp || greeting.returned || greeting.error || greeting.id.is_some() {
                return Err(scenario_error(
                    "QMP endpoint did not send an unambiguous greeting first",
                ));
            }
        }
        QmpRead::TimedOut => return Ok(ScenarioProgress::TimedOut),
        QmpRead::Closed => {
            return Err(scenario_error(
                "QMP endpoint closed before sending its greeting",
            ));
        }
    }

    const CAPABILITIES: &[u8] =
        b"{\"execute\":\"qmp_capabilities\",\"id\":\"wrela-capabilities\"}\r\n";
    if write_qmp_request(session, &mut stream, CAPABILITIES, deadline, is_cancelled)?
        == ScenarioProgress::TimedOut
    {
        return Ok(ScenarioProgress::TimedOut);
    }
    if wait_for_qmp_reply(
        session,
        &mut stream,
        &mut buffered,
        QmpIdentifier::Capabilities,
        false,
        deadline,
        is_cancelled,
    )? == ScenarioProgress::TimedOut
    {
        return Ok(ScenarioProgress::TimedOut);
    }

    const QUIT: &[u8] = b"{\"execute\":\"quit\",\"id\":\"wrela-quit\"}\r\n";
    if write_qmp_request(session, &mut stream, QUIT, deadline, is_cancelled)?
        == ScenarioProgress::TimedOut
    {
        return Ok(ScenarioProgress::TimedOut);
    }
    wait_for_qmp_reply(
        session,
        &mut stream,
        &mut buffered,
        QmpIdentifier::Quit,
        true,
        deadline,
        is_cancelled,
    )
}

#[cfg(not(unix))]
fn request_qmp_shutdown(
    _session: &mut InteractiveSession,
    _control: &ProcessShutdownControl,
    _timeout_ns: u64,
    _is_cancelled: &dyn Fn() -> bool,
) -> Result<ScenarioProgress, ExecuteError> {
    Err(ExecuteError::InvalidSpecification(
        "QMP Unix shutdown control is unsupported on this host",
    ))
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct QmpDeadline {
    start: Instant,
    timeout: Duration,
}

#[cfg(unix)]
fn qmp_timed_out(session: &InteractiveSession, deadline: QmpDeadline) -> bool {
    session.global_timed_out() || deadline.start.elapsed() >= deadline.timeout
}

#[cfg(unix)]
enum QmpRead {
    Line(Vec<u8>),
    TimedOut,
    Closed,
}

#[cfg(unix)]
fn read_qmp_line(
    session: &mut InteractiveSession,
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
    deadline: QmpDeadline,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<QmpRead, ExecuteError> {
    loop {
        if let Some(line) = take_qmp_line(buffered)? {
            return Ok(QmpRead::Line(line));
        }
        session.pump(is_cancelled)?;
        if qmp_timed_out(session, deadline) {
            return Ok(QmpRead::TimedOut);
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) if buffered.is_empty() => return Ok(QmpRead::Closed),
            Ok(0) => {
                return Err(scenario_error(
                    "QMP endpoint closed inside an incomplete message",
                ));
            }
            Ok(read) => {
                let next = buffered
                    .len()
                    .checked_add(read)
                    .ok_or_else(|| scenario_error("QMP message byte count overflowed"))?;
                if next > QMP_MESSAGE_BYTES {
                    return Err(scenario_error("QMP message exceeds its byte limit"));
                }
                buffered
                    .try_reserve_exact(read)
                    .map_err(|_| scenario_error("cannot allocate bounded QMP message"))?;
                buffered.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(session.poll_delay(Some((deadline.start, deadline.timeout))));
            }
            Err(error) => return Err(ExecuteError::Wait(error)),
        }
    }
}

#[cfg(unix)]
fn take_qmp_line(buffered: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ExecuteError> {
    let Some(newline) = buffered.iter().position(|byte| *byte == b'\n') else {
        return Ok(None);
    };
    if newline == 0 || buffered.get(newline - 1) != Some(&b'\r') {
        return Err(scenario_error(
            "QMP message is not terminated by canonical CRLF framing",
        ));
    }
    let remainder = buffered.split_off(newline + 1);
    let mut line = std::mem::replace(buffered, remainder);
    line.truncate(newline - 1);
    if line.is_empty() {
        return Err(scenario_error("QMP message is empty"));
    }
    Ok(Some(line))
}

#[cfg(unix)]
fn write_qmp_request(
    session: &mut InteractiveSession,
    stream: &mut UnixStream,
    request: &[u8],
    deadline: QmpDeadline,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScenarioProgress, ExecuteError> {
    let mut offset = 0usize;
    while offset < request.len() {
        session.pump(is_cancelled)?;
        if session.status.is_some() {
            return Err(scenario_error(
                "emulator exited while a QMP request was being written",
            ));
        }
        if qmp_timed_out(session, deadline) {
            return Ok(ScenarioProgress::TimedOut);
        }
        match stream.write(&request[offset..]) {
            Ok(0) => return Err(scenario_error("QMP endpoint stopped accepting a request")),
            Ok(written) => {
                offset = offset
                    .checked_add(written)
                    .ok_or_else(|| scenario_error("QMP request offset overflowed"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(session.poll_delay(Some((deadline.start, deadline.timeout))));
            }
            Err(error) => return Err(ExecuteError::Wait(error)),
        }
    }
    Ok(ScenarioProgress::Complete)
}

#[cfg(unix)]
fn wait_for_qmp_reply(
    session: &mut InteractiveSession,
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
    expected_id: QmpIdentifier,
    closure_after_request_is_success: bool,
    deadline: QmpDeadline,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ScenarioProgress, ExecuteError> {
    for _ in 0..QMP_MAXIMUM_MESSAGES_PER_PHASE {
        match read_qmp_line(session, stream, buffered, deadline, is_cancelled)? {
            QmpRead::Line(line) => {
                let envelope = parse_qmp_envelope(&line)?;
                if envelope.id != Some(expected_id) {
                    continue;
                }
                if envelope.error {
                    return Err(scenario_error(format!(
                        "QMP rejected the {} request",
                        expected_id.label()
                    )));
                }
                if !envelope.returned {
                    return Err(scenario_error(format!(
                        "QMP {} reply has neither return nor error",
                        expected_id.label()
                    )));
                }
                return Ok(ScenarioProgress::Complete);
            }
            QmpRead::TimedOut => return Ok(ScenarioProgress::TimedOut),
            QmpRead::Closed if closure_after_request_is_success => loop {
                session.pump(is_cancelled)?;
                if session.status.is_some() {
                    return Ok(ScenarioProgress::Complete);
                }
                if qmp_timed_out(session, deadline) {
                    return Ok(ScenarioProgress::TimedOut);
                }
                thread::sleep(session.poll_delay(Some((deadline.start, deadline.timeout))));
            },
            QmpRead::Closed => {
                return Err(scenario_error(
                    "QMP endpoint closed before acknowledging capabilities",
                ));
            }
        }
    }
    Err(scenario_error(
        "QMP emitted too many messages before the requested reply",
    ))
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QmpIdentifier {
    Capabilities,
    Quit,
    Other,
}

#[cfg(unix)]
impl QmpIdentifier {
    fn label(self) -> &'static str {
        match self {
            Self::Capabilities => "qmp_capabilities",
            Self::Quit => "quit",
            Self::Other => "unknown",
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct QmpEnvelope {
    qmp: bool,
    returned: bool,
    error: bool,
    id: Option<QmpIdentifier>,
}

#[cfg(unix)]
fn parse_qmp_envelope(bytes: &[u8]) -> Result<QmpEnvelope, ExecuteError> {
    let mut cursor = 0usize;
    json_whitespace(bytes, &mut cursor);
    json_expect(bytes, &mut cursor, b'{')?;
    let mut envelope = QmpEnvelope::default();
    json_whitespace(bytes, &mut cursor);
    if bytes.get(cursor) == Some(&b'}') {
        cursor += 1;
    } else {
        loop {
            let key = json_string(bytes, &mut cursor)?;
            json_whitespace(bytes, &mut cursor);
            json_expect(bytes, &mut cursor, b':')?;
            json_whitespace(bytes, &mut cursor);
            match key {
                JsonString::Plain(b"QMP") => {
                    if envelope.qmp {
                        return Err(scenario_error("QMP message contains duplicate QMP key"));
                    }
                    envelope.qmp = true;
                    json_skip_value(bytes, &mut cursor, 0)?;
                }
                JsonString::Plain(b"return") => {
                    if envelope.returned {
                        return Err(scenario_error("QMP message contains duplicate return key"));
                    }
                    envelope.returned = true;
                    json_skip_value(bytes, &mut cursor, 0)?;
                }
                JsonString::Plain(b"error") => {
                    if envelope.error {
                        return Err(scenario_error("QMP message contains duplicate error key"));
                    }
                    envelope.error = true;
                    json_skip_value(bytes, &mut cursor, 0)?;
                }
                JsonString::Plain(b"id") => {
                    if envelope.id.is_some() {
                        return Err(scenario_error("QMP message contains duplicate id key"));
                    }
                    envelope.id = match json_string(bytes, &mut cursor)? {
                        JsonString::Plain(b"wrela-capabilities") => {
                            Some(QmpIdentifier::Capabilities)
                        }
                        JsonString::Plain(b"wrela-quit") => Some(QmpIdentifier::Quit),
                        _ => Some(QmpIdentifier::Other),
                    };
                }
                _ => json_skip_value(bytes, &mut cursor, 0)?,
            }
            json_whitespace(bytes, &mut cursor);
            match bytes.get(cursor).copied() {
                Some(b',') => {
                    cursor += 1;
                    json_whitespace(bytes, &mut cursor);
                }
                Some(b'}') => {
                    cursor += 1;
                    break;
                }
                _ => return Err(scenario_error("QMP message is not a JSON object")),
            }
        }
    }
    json_whitespace(bytes, &mut cursor);
    if cursor != bytes.len() || (envelope.returned && envelope.error) {
        return Err(scenario_error(
            "QMP message has trailing data or conflicting result fields",
        ));
    }
    Ok(envelope)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonString<'a> {
    Plain(&'a [u8]),
    Escaped,
}

#[cfg(unix)]
fn json_string<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<JsonString<'a>, ExecuteError> {
    json_whitespace(bytes, cursor);
    json_expect(bytes, cursor, b'"')?;
    let start = *cursor;
    let mut escaped = false;
    while let Some(byte) = bytes.get(*cursor).copied() {
        match byte {
            b'"' => {
                let end = *cursor;
                *cursor += 1;
                return Ok(if escaped {
                    JsonString::Escaped
                } else {
                    JsonString::Plain(&bytes[start..end])
                });
            }
            b'\\' => {
                escaped = true;
                *cursor += 1;
                match bytes.get(*cursor).copied() {
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                        *cursor += 1;
                    }
                    Some(b'u') => {
                        *cursor += 1;
                        let end = cursor
                            .checked_add(4)
                            .ok_or_else(|| scenario_error("QMP JSON escape overflowed"))?;
                        if bytes
                            .get(*cursor..end)
                            .is_none_or(|digits| !digits.iter().all(u8::is_ascii_hexdigit))
                        {
                            return Err(scenario_error("QMP JSON has an invalid Unicode escape"));
                        }
                        *cursor = end;
                    }
                    _ => return Err(scenario_error("QMP JSON has an invalid string escape")),
                }
            }
            0x00..=0x1f => {
                return Err(scenario_error(
                    "QMP JSON string contains an unescaped control byte",
                ));
            }
            _ => *cursor += 1,
        }
    }
    Err(scenario_error("QMP JSON string is unterminated"))
}

#[cfg(unix)]
fn json_skip_value(bytes: &[u8], cursor: &mut usize, depth: u8) -> Result<(), ExecuteError> {
    if depth >= QMP_MAXIMUM_JSON_DEPTH {
        return Err(scenario_error("QMP JSON nesting exceeds its limit"));
    }
    json_whitespace(bytes, cursor);
    match bytes.get(*cursor).copied() {
        Some(b'"') => {
            let _ = json_string(bytes, cursor)?;
        }
        Some(b'{') => {
            *cursor += 1;
            json_whitespace(bytes, cursor);
            if bytes.get(*cursor) == Some(&b'}') {
                *cursor += 1;
                return Ok(());
            }
            loop {
                let _ = json_string(bytes, cursor)?;
                json_whitespace(bytes, cursor);
                json_expect(bytes, cursor, b':')?;
                json_skip_value(bytes, cursor, depth + 1)?;
                json_whitespace(bytes, cursor);
                match bytes.get(*cursor).copied() {
                    Some(b',') => *cursor += 1,
                    Some(b'}') => {
                        *cursor += 1;
                        break;
                    }
                    _ => return Err(scenario_error("QMP JSON object is malformed")),
                }
            }
        }
        Some(b'[') => {
            *cursor += 1;
            json_whitespace(bytes, cursor);
            if bytes.get(*cursor) == Some(&b']') {
                *cursor += 1;
                return Ok(());
            }
            loop {
                json_skip_value(bytes, cursor, depth + 1)?;
                json_whitespace(bytes, cursor);
                match bytes.get(*cursor).copied() {
                    Some(b',') => *cursor += 1,
                    Some(b']') => {
                        *cursor += 1;
                        break;
                    }
                    _ => return Err(scenario_error("QMP JSON array is malformed")),
                }
            }
        }
        Some(b't') => json_literal(bytes, cursor, b"true")?,
        Some(b'f') => json_literal(bytes, cursor, b"false")?,
        Some(b'n') => json_literal(bytes, cursor, b"null")?,
        Some(b'-' | b'0'..=b'9') => json_number(bytes, cursor)?,
        _ => return Err(scenario_error("QMP JSON value is malformed")),
    }
    Ok(())
}

#[cfg(unix)]
fn json_number(bytes: &[u8], cursor: &mut usize) -> Result<(), ExecuteError> {
    if bytes.get(*cursor) == Some(&b'-') {
        *cursor += 1;
    }
    match bytes.get(*cursor).copied() {
        Some(b'0') => *cursor += 1,
        Some(b'1'..=b'9') => {
            *cursor += 1;
            while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
                *cursor += 1;
            }
        }
        _ => return Err(scenario_error("QMP JSON number is malformed")),
    }
    if bytes.get(*cursor) == Some(&b'.') {
        *cursor += 1;
        let fraction = *cursor;
        while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
            *cursor += 1;
        }
        if *cursor == fraction {
            return Err(scenario_error("QMP JSON fraction is malformed"));
        }
    }
    if matches!(bytes.get(*cursor), Some(b'e' | b'E')) {
        *cursor += 1;
        if matches!(bytes.get(*cursor), Some(b'+' | b'-')) {
            *cursor += 1;
        }
        let exponent = *cursor;
        while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
            *cursor += 1;
        }
        if *cursor == exponent {
            return Err(scenario_error("QMP JSON exponent is malformed"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn json_literal(bytes: &[u8], cursor: &mut usize, literal: &[u8]) -> Result<(), ExecuteError> {
    let end = cursor
        .checked_add(literal.len())
        .ok_or_else(|| scenario_error("QMP JSON literal offset overflowed"))?;
    if bytes.get(*cursor..end) != Some(literal) {
        return Err(scenario_error("QMP JSON literal is malformed"));
    }
    *cursor = end;
    Ok(())
}

#[cfg(unix)]
fn json_expect(bytes: &[u8], cursor: &mut usize, expected: u8) -> Result<(), ExecuteError> {
    if bytes.get(*cursor) != Some(&expected) {
        return Err(scenario_error("QMP message is malformed JSON"));
    }
    *cursor += 1;
    Ok(())
}

#[cfg(unix)]
fn json_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        *cursor += 1;
    }
}

struct ChildRequest<'a> {
    program: &'a Path,
    arguments: &'a [std::ffi::OsString],
    current_directory: &'a Path,
    environment: &'a [(std::ffi::OsString, std::ffi::OsString)],
    timeout_ns: u64,
    maximum_output_bytes: u64,
}

fn run_program(
    request: ChildRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, ExecuteError> {
    check_cancelled(is_cancelled)?;
    let mut command = Command::new(request.program);
    command
        .args(request.arguments)
        .current_dir(request.current_directory)
        .env_clear()
        .envs(request.environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_private_process_group(&mut command);
    let start = Instant::now();
    let mut child = command.spawn().map_err(ExecuteError::Spawn)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = terminate(&mut child);
        return Err(ExecuteError::Wait(io::Error::other(
            "child stdout pipe was not created",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = terminate(&mut child);
        return Err(ExecuteError::Wait(io::Error::other(
            "child stderr pipe was not created",
        )));
    };
    let total = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_thread = match spawn_reader(
        "wrela-qemu-stdout",
        stdout,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        request.maximum_output_bytes,
    ) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = terminate(&mut child);
            return Err(error);
        }
    };
    let stderr_thread = match spawn_reader(
        "wrela-qemu-stderr",
        stderr,
        Arc::clone(&total),
        Arc::clone(&exceeded),
        request.maximum_output_bytes,
    ) {
        Ok(thread) => thread,
        Err(error) => {
            terminate(&mut child)?;
            let _ = stdout_thread.join();
            return Err(error);
        }
    };

    let timeout = Duration::from_nanos(request.timeout_ns);
    let (status, timed_out) = loop {
        if is_cancelled() {
            terminate(&mut child)?;
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ExecuteError::Cancelled);
        }
        if exceeded.load(Ordering::Acquire) {
            terminate(&mut child)?;
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ExecuteError::OutputLimit {
                stream: "aggregate stdout/stderr",
                limit: request.maximum_output_bytes,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) => {}
            Err(error) => {
                let _ = terminate(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(ExecuteError::Wait(error));
            }
        }
        if start.elapsed() >= timeout {
            let status = terminate(&mut child)?;
            break (status, true);
        }
        thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(start.elapsed())));
    };
    let stdout = join_reader(stdout_thread)?;
    let stderr = join_reader(stderr_thread)?;
    if exceeded.load(Ordering::Acquire) {
        return Err(ExecuteError::OutputLimit {
            stream: "aggregate stdout/stderr",
            limit: request.maximum_output_bytes,
        });
    }
    let duration_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    Ok(ProcessOutput {
        exit_code: status.code(),
        timed_out,
        stdout,
        stderr,
        duration_ns,
    })
}

fn spawn_reader<R: Read + Send + 'static>(
    name: &str,
    mut reader: R,
    total: Arc<AtomicU64>,
    exceeded: Arc<AtomicBool>,
    limit: u64,
) -> Result<thread::JoinHandle<io::Result<Vec<u8>>>, ExecuteError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    return Ok(output);
                }
                let read = read as u64;
                if !reserve_output(&total, read, limit) {
                    exceeded.store(true, Ordering::Release);
                    return Ok(output);
                }
                output
                    .try_reserve_exact(read as usize)
                    .map_err(io::Error::other)?;
                output.extend_from_slice(&buffer[..read as usize]);
            }
        })
        .map_err(ExecuteError::Wait)
}

fn reserve_output(total: &AtomicU64, additional: u64, limit: u64) -> bool {
    let mut observed = total.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(additional) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match total.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

fn configure_private_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        // QEMU becomes the leader of a private process group, so terminal
        // signals and host job control cannot leak into unrelated children.
        command.process_group(0);
    }
}

fn terminate(child: &mut Child) -> Result<ExitStatus, ExecuteError> {
    match child.try_wait().map_err(ExecuteError::Wait)? {
        Some(status) => Ok(status),
        None => {
            child.kill().map_err(ExecuteError::Wait)?;
            child.wait().map_err(ExecuteError::Wait)
        }
    }
}

fn join_reader(thread: thread::JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>, ExecuteError> {
    thread
        .join()
        .map_err(|_| ExecuteError::Wait(io::Error::other("output reader thread panicked")))?
        .map_err(ExecuteError::Wait)
}

fn remove_staged(paths: &[PathBuf]) -> Result<(), ExecuteError> {
    let mut failure = None;
    for path in paths.iter().rev() {
        retain_first_cleanup_error(&mut failure, remove_file_for_cleanup(path));
    }
    failure.map_or(Ok(()), Err)
}

fn cleanup_process_directory(
    specification: &ProcessSpecification,
    staged: &[PathBuf],
    remove_shutdown_endpoint: bool,
) -> Result<(), ExecuteError> {
    let mut failure = None;
    if remove_shutdown_endpoint {
        if let Some(ProcessShutdownControl::QmpUnix { path }) = &specification.shutdown_control {
            retain_first_cleanup_error(&mut failure, remove_file_for_cleanup(path));
        }
    }
    retain_first_cleanup_error(&mut failure, remove_staged(staged));
    retain_first_cleanup_error(
        &mut failure,
        remove_empty_parent_directories(
            &specification.current_directory,
            staged
                .iter()
                .map(PathBuf::as_path)
                .chain(
                    specification
                        .shutdown_control
                        .iter()
                        .map(|control| match control {
                            ProcessShutdownControl::QmpUnix { path } => path.as_path(),
                        }),
                ),
        ),
    );
    failure.map_or(Ok(()), Err)
}

fn remove_empty_parent_directories<'a>(
    root: &Path,
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), ExecuteError> {
    let mut directories = std::collections::BTreeSet::new();
    for path in paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == root {
                break;
            }
            if directory.starts_with(root) {
                directories.insert(directory.to_owned());
            }
            parent = directory.parent();
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    let mut failure = None;
    for directory in directories {
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                retain_first_cleanup_error(
                    &mut failure,
                    Err(ExecuteError::Cleanup {
                        path: directory,
                        error,
                    }),
                );
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn retain_first_cleanup_error(first: &mut Option<ExecuteError>, result: Result<(), ExecuteError>) {
    if first.is_none() {
        if let Err(error) = result {
            *first = Some(error);
        }
    }
}

fn remove_file_for_cleanup(path: &Path) -> Result<(), ExecuteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ExecuteError::Cleanup {
            path: path.to_owned(),
            error,
        }),
    }
}

fn scenario_error(message: impl fmt::Display) -> ExecuteError {
    ExecuteError::Scenario(message.to_string())
}

struct CreatedFileGuard {
    path: PathBuf,
    armed: bool,
}

impl CreatedFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreatedFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), ExecuteError> {
    if is_cancelled() {
        Err(ExecuteError::Cancelled)
    } else {
        Ok(())
    }
}

fn verification<T>(path: &Path, reason: &'static str) -> Result<T, ExecuteError> {
    Err(ExecuteError::Verification {
        path: path.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::VerifiedProcessFile;
    use wrela_build_model::Sha256Digest;
    use wrela_test_model::{
        GuestTestOutcome, IMAGE_SCENARIO_SCHEMA, ImageScenarioStep, LanguageFatalCause, ScenarioId,
        TEST_PROTOCOL_VERSION, TestEventKind, TestId,
    };
    use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};

    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> PathBuf {
        let unique = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        #[cfg(unix)]
        let temporary_root = fs::canonicalize("/tmp").expect("canonical short temp root");
        #[cfg(not(unix))]
        let temporary_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let path =
            temporary_root.join(format!("wrela-test-runner-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("create private test directory");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("restrict private test directory");
        path
    }

    fn scenario(steps: Vec<ImageScenarioStep>) -> ImageScenario {
        ImageScenario {
            id: ScenarioId(0),
            schema: IMAGE_SCENARIO_SCHEMA,
            name: "local-executor-test".to_owned(),
            source_path: "tests/local-executor.toml".to_owned(),
            digest: Sha256Digest::from_bytes([0x5a; 32]),
            steps,
        }
    }

    fn slip_event(event: &TestEvent) -> Vec<u8> {
        let encoded = seal_encoded_event(
            &CanonicalTestEventCodec,
            event,
            ProtocolLimits::standard(),
            &|| false,
        )
        .expect("seal event");
        let mut framed = vec![SLIP_END];
        for byte in encoded.bytes() {
            match *byte {
                SLIP_END => framed.extend_from_slice(&[SLIP_ESCAPE, SLIP_ESCAPED_END]),
                SLIP_ESCAPE => framed.extend_from_slice(&[SLIP_ESCAPE, SLIP_ESCAPED_ESCAPE]),
                byte => framed.push(byte),
            }
        }
        framed.push(SLIP_END);
        framed
    }

    #[test]
    fn aggregate_output_reservation_is_exact() {
        let total = AtomicU64::new(0);
        assert!(reserve_output(&total, 7, 10));
        assert!(!reserve_output(&total, 4, 10));
        assert!(reserve_output(&total, 3, 10));
        assert_eq!(total.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn live_serial_observer_demultiplexes_raw_bytes_and_canonical_events() {
        let started = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunStarted { test_count: 0 },
        };
        let finished = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 1,
            kind: TestEventKind::RunFinished {
                passed: 0,
                failed: 0,
            },
        };
        let mut stream = b"firmware banner\n".to_vec();
        stream.extend_from_slice(&slip_event(&started));
        stream.extend_from_slice(b"pong\n");
        stream.extend_from_slice(&slip_event(&finished));

        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        for index in 0..stream.len() {
            observer
                .push(&stream[index..index + 1], index, &|| false)
                .expect("observe one-byte chunks");
        }
        observer
            .finish(stream.len(), false, &|| false)
            .expect("complete stream");
        assert_eq!(
            observer.find_serial(&stream, 0, b"firmware banner\n"),
            Some(16)
        );
        let started_end = observer
            .find_event(0, ExpectedScenarioEvent::RunStarted, None, None)
            .expect("run-started event");
        let pong_end = observer
            .find_serial(&stream, started_end, b"pong\n")
            .expect("raw serial response");
        assert!(pong_end > started_end);
        assert!(
            observer
                .find_event(pong_end, ExpectedScenarioEvent::RunFinished, None, None,)
                .is_some()
        );
    }

    #[test]
    fn live_serial_observer_rejects_corrupt_frames_and_sequence_gaps() {
        let mut malformed = vec![SLIP_END];
        malformed.extend_from_slice(TEST_FRAME_MAGIC);
        malformed.extend_from_slice(&[SLIP_ESCAPE, 0x00, SLIP_END]);
        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        assert!(matches!(
            observer.push(&malformed, 0, &|| false),
            Err(ExecuteError::Scenario(_))
        ));

        let event = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 1,
            kind: TestEventKind::Heartbeat { monotonic_ticks: 1 },
        };
        let framed = slip_event(&event);
        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        assert!(matches!(
            observer.push(&framed, 0, &|| false),
            Err(ExecuteError::Scenario(_))
        ));

        let one_event = ProtocolLimits {
            events: 1,
            ..ProtocolLimits::standard()
        };
        let started = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunStarted { test_count: 0 },
        };
        let heartbeat = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 1,
            kind: TestEventKind::Heartbeat { monotonic_ticks: 1 },
        };
        let mut observer = LiveSerialObserver::new(one_event);
        let started = slip_event(&started);
        observer
            .push(&started, 0, &|| false)
            .expect("first event within limit");
        let heartbeat = slip_event(&heartbeat);
        assert!(matches!(
            observer.push(&heartbeat, started.len(), &|| false),
            Err(ExecuteError::Scenario(_))
        ));

        let complete = slip_event(&TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunStarted { test_count: 0 },
        });
        let truncated = &complete[..complete.len() / 2];
        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        observer
            .push(truncated, 0, &|| false)
            .expect("observe interrupted frame");
        observer
            .finish(truncated.len(), true, &|| false)
            .expect("abnormal exit preserves complete prefix");
        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        observer
            .push(truncated, 0, &|| false)
            .expect("observe interrupted frame");
        assert!(matches!(
            observer.finish(truncated.len(), false, &|| false),
            Err(ExecuteError::Scenario(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn interactive_scenario_sends_serial_observes_response_and_checks_exit() {
        let root = temporary_directory();
        let arguments = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("IFS= read -r line; printf 'pong\\n'; exit 7"),
        ];
        let scenario = scenario(vec![
            ImageScenarioStep::SendSerial {
                bytes: b"ping\n".to_vec(),
            },
            ImageScenarioStep::ExpectSerial {
                bytes: b"pong\n".to_vec(),
                timeout_ns: 1_000_000_000,
            },
            ImageScenarioStep::ExpectExit {
                code: Some(7),
                timeout_ns: 1_000_000_000,
            },
        ]);
        let output = run_interactive_program(
            InteractiveRequest {
                program: Path::new("/bin/sh"),
                arguments: &arguments,
                current_directory: &root,
                environment: &[],
                timeout_ns: 3_000_000_000,
                protocol_limits: ProtocolLimits::standard(),
                maximum_output_bytes: 1024,
                shutdown_control: None,
            },
            &scenario,
            &|| false,
        )
        .expect("run live serial scenario");
        assert_eq!(output.exit_code, Some(7));
        assert!(!output.timed_out);
        assert_eq!(output.stdout, b"pong\n");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn interactive_language_fatal_frames_preserve_typed_cause_and_reap_cleanly() {
        let root = temporary_directory();
        let test = TestId(41);
        let cause = LanguageFatalCause::CheckedShiftResultLoss;
        let events = [
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::RunFinished {
                    passed: 0,
                    failed: 1,
                },
            },
        ];
        let mut stream = Vec::new();
        for event in &events {
            stream.extend_from_slice(&slip_event(event));
        }
        let frames = root.join("language-fatal.frames");
        fs::write(&frames, &stream).expect("write producer-shaped fatal frames");
        let arguments = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("/bin/cat -- \"$1\"; exit 0"),
            std::ffi::OsString::from("wrela-language-fatal-test"),
            frames.as_os_str().to_owned(),
        ];
        let scenario = scenario(vec![
            ImageScenarioStep::ExpectTestEvent {
                kind: ExpectedScenarioEvent::TestFinished,
                test: Some(test),
                message_contains: None,
                timeout_ns: 1_000_000_000,
            },
            ImageScenarioStep::ExpectTestEvent {
                kind: ExpectedScenarioEvent::RunFinished,
                test: None,
                message_contains: None,
                timeout_ns: 1_000_000_000,
            },
            ImageScenarioStep::ExpectExit {
                code: Some(0),
                timeout_ns: 1_000_000_000,
            },
        ]);
        let output = run_interactive_program(
            InteractiveRequest {
                program: Path::new("/bin/sh"),
                arguments: &arguments,
                current_directory: &root,
                environment: &[],
                timeout_ns: 3_000_000_000,
                protocol_limits: ProtocolLimits::standard(),
                maximum_output_bytes: u64::try_from(stream.len())
                    .expect("bounded fatal stream length fits u64"),
                shutdown_control: None,
            },
            &scenario,
            &|| false,
        )
        .expect("consume typed fatal frames from a supervised child");
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        assert_eq!(output.stdout, stream);
        assert!(output.stderr.is_empty());

        let mut observer = LiveSerialObserver::new(ProtocolLimits::standard());
        observer
            .push(&output.stdout, 0, &|| false)
            .expect("observe exact child fatal stream");
        observer
            .finish(output.stdout.len(), false, &|| false)
            .expect("finish exact child fatal stream");
        assert!(matches!(
            &observer.events[2].event.kind,
            TestEventKind::TestFinished {
                test: actual,
                outcome: GuestTestOutcome::LanguageFatal { cause: actual_cause },
            } if *actual == test && *actual_cause == cause
        ));
        fs::remove_dir_all(root).expect("remove reaped child fixture directory");
    }

    #[cfg(unix)]
    #[test]
    fn interactive_scenario_enforces_individual_step_deadline() {
        let root = temporary_directory();
        let arguments = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("while :; do :; done"),
        ];
        let scenario = scenario(vec![
            ImageScenarioStep::ExpectSerial {
                bytes: b"never".to_vec(),
                timeout_ns: 20_000_000,
            },
            ImageScenarioStep::ExpectExit {
                code: None,
                timeout_ns: 1_000_000_000,
            },
        ]);
        let output = run_interactive_program(
            InteractiveRequest {
                program: Path::new("/bin/sh"),
                arguments: &arguments,
                current_directory: &root,
                environment: &[],
                timeout_ns: 2_000_000_000,
                protocol_limits: ProtocolLimits::standard(),
                maximum_output_bytes: 1024,
                shutdown_control: None,
            },
            &scenario,
            &|| false,
        )
        .expect("time out live scenario");
        assert!(output.timed_out);
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn request_shutdown_negotiates_qmp_and_issues_quit() {
        let root = temporary_directory();
        let socket = root.join("qmp.sock");
        let done = root.join("qmp-done");
        let listener = UnixListener::bind(&socket).expect("bind private QMP socket");
        let done_for_server = done.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept QMP client");
            stream
                .write_all(
                    b"{\"QMP\":{\"version\":{\"qemu\":{\"major\":10}},\"capabilities\":[]}}\r\n",
                )
                .expect("write QMP greeting");
            let mut reader = BufReader::new(stream.try_clone().expect("clone QMP stream"));
            let mut request = String::new();
            reader.read_line(&mut request).expect("read capabilities");
            assert_eq!(
                request,
                "{\"execute\":\"qmp_capabilities\",\"id\":\"wrela-capabilities\"}\r\n"
            );
            stream
                .write_all(b"{\"return\":{},\"id\":\"wrela-capabilities\"}\r\n")
                .expect("acknowledge capabilities");
            request.clear();
            reader.read_line(&mut request).expect("read quit");
            assert_eq!(request, "{\"execute\":\"quit\",\"id\":\"wrela-quit\"}\r\n");
            stream
                .write_all(b"{\"return\":{},\"id\":\"wrela-quit\"}\r\n")
                .expect("acknowledge quit");
            fs::write(done_for_server, b"done").expect("signal fake emulator exit");
        });

        let arguments = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("while [ ! -e \"$1\" ]; do :; done; exit 0"),
            std::ffi::OsString::from("wrela-qmp-test"),
            done.as_os_str().to_owned(),
        ];
        let control = ProcessShutdownControl::QmpUnix {
            path: socket.clone(),
        };
        let scenario = scenario(vec![
            ImageScenarioStep::RequestShutdown {
                timeout_ns: 1_000_000_000,
            },
            ImageScenarioStep::ExpectExit {
                code: Some(0),
                timeout_ns: 1_000_000_000,
            },
        ]);
        let output = run_interactive_program(
            InteractiveRequest {
                program: Path::new("/bin/sh"),
                arguments: &arguments,
                current_directory: &root,
                environment: &[],
                timeout_ns: 3_000_000_000,
                protocol_limits: ProtocolLimits::standard(),
                maximum_output_bytes: 1024,
                shutdown_control: Some(&control),
            },
            &scenario,
            &|| false,
        )
        .expect("execute QMP shutdown scenario");
        server.join().expect("join QMP server");
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn qmp_json_envelope_is_bounded_and_rejects_ambiguity() {
        let greeting = parse_qmp_envelope(
            br#" { "QMP" : { "version" : { "qemu" : { "major" : 10 } } }, "extra": [1,true,null] } "#,
        )
        .expect("parse QMP greeting");
        assert!(greeting.qmp);
        let reply =
            parse_qmp_envelope(br#"{"id":"wrela-quit","return":{},"timestamp":{"seconds":0}}"#)
                .expect("parse QMP reply");
        assert_eq!(reply.id, Some(QmpIdentifier::Quit));
        assert!(reply.returned);
        assert!(matches!(
            parse_qmp_envelope(br#"{"return":{},"return":{},"id":"wrela-quit"}"#),
            Err(ExecuteError::Scenario(_))
        ));
        assert!(matches!(
            parse_qmp_envelope(br#"{"return":{},"error":{},"id":"wrela-quit"}"#),
            Err(ExecuteError::Scenario(_))
        ));
        assert!(matches!(
            parse_qmp_envelope(br#"{"return":{},"id":"wrela-quit"} trailing"#),
            Err(ExecuteError::Scenario(_))
        ));

        let mut canonical = b"{}\r\nremaining".to_vec();
        assert_eq!(
            take_qmp_line(&mut canonical).expect("canonical QMP line"),
            Some(b"{}".to_vec())
        );
        assert_eq!(canonical, b"remaining");
        assert!(matches!(
            take_qmp_line(&mut b"{}\n".to_vec()),
            Err(ExecuteError::Scenario(_))
        ));
        assert!(matches!(
            take_qmp_line(&mut b"\r\n".to_vec()),
            Err(ExecuteError::Scenario(_))
        ));
    }

    #[test]
    fn verified_input_is_copied_with_exact_digest_and_permissions() {
        let root = temporary_directory();
        let source = root.join("source.efi");
        fs::write(&source, b"verified image bytes").expect("write source");
        #[cfg(unix)]
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("restrict source");
        let destination = root.join("run/image.efi");
        let input = ProcessInput {
            source: VerifiedProcessFile {
                path: source.clone(),
                digest: Sha256::digest(b"verified image bytes"),
                bytes: 20,
            },
            destination: destination.clone(),
            writable: false,
        };
        stage_input(&root, &input, &|| false).expect("stage verified input");
        assert_eq!(
            fs::read(&destination).expect("read staged input"),
            b"verified image bytes"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&destination).expect("metadata").mode() & 0o777,
            0o400
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn corrupt_input_never_leaves_a_staged_file() {
        let root = temporary_directory();
        let source = root.join("source.fd");
        fs::write(&source, b"changed").expect("write source");
        #[cfg(unix)]
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("restrict source");
        let destination = root.join("run/firmware.fd");
        let input = ProcessInput {
            source: VerifiedProcessFile {
                path: source,
                digest: Sha256::digest(b"expected"),
                bytes: 7,
            },
            destination: destination.clone(),
            writable: false,
        };
        assert!(matches!(
            stage_input(&root, &input, &|| false),
            Err(ExecuteError::Verification { .. })
        ));
        assert!(!destination.exists());
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn cleanup_removes_private_parents_and_reports_unexpected_residue() {
        let root = temporary_directory();
        let leaf = root.join("group/esp/EFI/BOOT/image.efi");
        fs::create_dir_all(leaf.parent().expect("leaf parent")).expect("create staged parents");
        remove_empty_parent_directories(&root, [leaf.as_path()])
            .expect("remove empty staged parents");
        assert!(!root.join("group").exists());

        fs::create_dir_all(leaf.parent().expect("leaf parent")).expect("recreate staged parents");
        fs::write(root.join("group/esp/residue"), b"unexpected child output")
            .expect("write unexpected residue");
        assert!(matches!(
            remove_empty_parent_directories(&root, [leaf.as_path()]),
            Err(ExecuteError::Cleanup { .. })
        ));
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn child_execution_clears_ambient_environment_and_captures_both_streams() {
        let root = temporary_directory();
        let arguments = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(
                "kill -0 -$$ || exit 9; printf '%s' \"${HOME-unset}\"; printf '%s' err >&2",
            ),
        ];
        let output = run_program(
            ChildRequest {
                program: Path::new("/bin/sh"),
                arguments: &arguments,
                current_directory: &root,
                environment: &[],
                timeout_ns: 1_000_000_000,
                maximum_output_bytes: 1024,
            },
            &|| false,
        )
        .expect("execute bounded child");
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.timed_out);
        assert_eq!(output.stdout, b"unset");
        assert_eq!(output.stderr, b"err");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn child_execution_enforces_timeout_and_aggregate_output_limit() {
        let root = temporary_directory();
        let busy_loop = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("while :; do :; done"),
        ];
        let timed_out = run_program(
            ChildRequest {
                program: Path::new("/bin/sh"),
                arguments: &busy_loop,
                current_directory: &root,
                environment: &[],
                timeout_ns: 20_000_000,
                maximum_output_bytes: 1024,
            },
            &|| false,
        )
        .expect("time out bounded child");
        assert!(timed_out.timed_out);

        let noisy = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("printf 1234; printf 56 >&2"),
        ];
        assert!(matches!(
            run_program(
                ChildRequest {
                    program: Path::new("/bin/sh"),
                    arguments: &noisy,
                    current_directory: &root,
                    environment: &[],
                    timeout_ns: 1_000_000_000,
                    maximum_output_bytes: 5,
                },
                &|| false,
            ),
            Err(ExecuteError::OutputLimit { limit: 5, .. })
        ));
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn child_execution_reaps_after_late_cancellation_and_protocol_error() {
        let root = temporary_directory();
        let busy_loop = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("while :; do :; done"),
        ];
        let polls = std::cell::Cell::new(0_u8);
        let late_cancel = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert!(matches!(
            run_program(
                ChildRequest {
                    program: Path::new("/bin/sh"),
                    arguments: &busy_loop,
                    current_directory: &root,
                    environment: &[],
                    timeout_ns: 1_000_000_000,
                    maximum_output_bytes: 1024,
                },
                &late_cancel,
            ),
            Err(ExecuteError::Cancelled)
        ));

        let malformed = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(
                "printf '\\300WRELTST\\000\\333\\000\\300'; while :; do :; done",
            ),
        ];
        let scenario = scenario(vec![ImageScenarioStep::ExpectSerial {
            bytes: b"never".to_vec(),
            timeout_ns: 500_000_000,
        }]);
        assert!(matches!(
            run_interactive_program(
                InteractiveRequest {
                    program: Path::new("/bin/sh"),
                    arguments: &malformed,
                    current_directory: &root,
                    environment: &[],
                    timeout_ns: 1_000_000_000,
                    protocol_limits: ProtocolLimits::standard(),
                    maximum_output_bytes: 1024,
                    shutdown_control: None,
                },
                &scenario,
                &|| false,
            ),
            Err(ExecuteError::Scenario(_))
        ));
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
