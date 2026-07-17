//! Linux-portable process boundary for one sealed headless compiler request.
//!
//! The process accepts no ambient workspace or tool discovery. Its fixed
//! arguments name one private staging parent, one explicit toolchain root, and
//! the three identities that the canonical engine-v1 handshake must bind. It
//! reads validated fixed headers and their bounded payloads until exactly one
//! request stream reaches EOF, then emits a fully encoded canonical response.
//! A request-bound cancel received before that EOF terminates the one-shot
//! request. Concurrent cancellation after execution begins belongs to the
//! persistent launcher/VM transport and is intentionally outside this slice.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

use wrela_build_model::Sha256Digest;
use wrela_compiler::{HeadlessCheckError, HeadlessCheckExecutor, PipelineLimits};
use wrela_driver::engine::{
    ENGINE_FRAME_HEADER_BYTES, EngineProtocolError, EngineProtocolLimits, RequestStreamProgress,
    decode_frame_header, sha256,
};
use wrela_toolchain::{LinuxPayloadAuthority, MAX_LINUX_PAYLOAD_AUTHORITY_BYTES, Toolchain};

const MAX_HOST_PATH_BYTES: usize = 64 * 1024;
const MAX_ENGINE_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
enum ProcessError {
    Usage,
    InvalidArgument(&'static str),
    EngineIdentityMismatch,
    PayloadAuthorityIdentityMismatch,
    PayloadAuthority,
    Protocol(EngineProtocolError),
    Executor(HeadlessCheckError),
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
    Allocation(&'static str),
    IncompleteRequest,
}

impl ProcessError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage | Self::InvalidArgument(_) => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: wrela-engine --staging-parent ABSOLUTE --toolchain-root ABSOLUTE --launcher-sha256 HEX --engine-sha256 HEX --payload-sha256 HEX",
            ),
            Self::InvalidArgument(name) => {
                write!(formatter, "invalid normalized engine argument {name}")
            }
            Self::EngineIdentityMismatch => {
                formatter.write_str("declared engine identity does not match this process image")
            }
            Self::PayloadAuthorityIdentityMismatch => formatter
                .write_str("sealed Linux payload authority does not match the request identity"),
            Self::PayloadAuthority => {
                formatter.write_str("sealed Linux payload authority is invalid")
            }
            Self::Protocol(error) => write!(formatter, "invalid engine-v1 request: {error}"),
            Self::Executor(error) => write!(formatter, "headless check failed: {error}"),
            Self::Io { operation, kind } => {
                write!(formatter, "engine {operation} failed: {kind}")
            }
            Self::Allocation(resource) => {
                write!(formatter, "engine cannot allocate bounded {resource}")
            }
            Self::IncompleteRequest => {
                formatter.write_str("engine input ended before one request was sealed or cancelled")
            }
        }
    }
}

impl From<EngineProtocolError> for ProcessError {
    fn from(value: EngineProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<HeadlessCheckError> for ProcessError {
    fn from(value: HeadlessCheckError) -> Self {
        Self::Executor(value)
    }
}

#[derive(Debug)]
struct Config {
    staging_parent: PathBuf,
    toolchain_root: PathBuf,
    launcher_identity: Sha256Digest,
    engine_identity: Sha256Digest,
    payload_identity: Sha256Digest,
}

#[derive(Debug)]
struct DirectChildConfig {
    authority_path: PathBuf,
    authority_digest: Sha256Digest,
    authority_bytes: u64,
    engine_bytes: u64,
    engine: Config,
}

impl DirectChildConfig {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, ProcessError> {
        let authority_path =
            exact_option_path(&mut arguments, "--payload-authority", "--payload-authority")?;
        let authority_digest = exact_option_digest(
            &mut arguments,
            "--payload-authority-sha256",
            "--payload-authority-sha256",
        )?;
        let authority_bytes = exact_option_count(
            &mut arguments,
            "--payload-authority-bytes",
            "--payload-authority-bytes",
            MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
        )?;
        let engine_bytes = exact_option_count(
            &mut arguments,
            "--engine-bytes",
            "--engine-bytes",
            MAX_ENGINE_IMAGE_BYTES,
        )?;
        let engine = Config::parse(arguments)?;
        Ok(Self {
            authority_path,
            authority_digest,
            authority_bytes,
            engine_bytes,
            engine,
        })
    }
}

impl Config {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, ProcessError> {
        let staging_parent =
            exact_option_path(&mut arguments, "--staging-parent", "--staging-parent")?;
        let toolchain_root =
            exact_option_path(&mut arguments, "--toolchain-root", "--toolchain-root")?;
        let launcher_identity =
            exact_option_digest(&mut arguments, "--launcher-sha256", "--launcher-sha256")?;
        let engine_identity =
            exact_option_digest(&mut arguments, "--engine-sha256", "--engine-sha256")?;
        let payload_identity =
            exact_option_digest(&mut arguments, "--payload-sha256", "--payload-sha256")?;
        if arguments.next().is_some() {
            return Err(ProcessError::Usage);
        }
        validate_directory_argument(&staging_parent, "--staging-parent")?;
        validate_directory_argument(&toolchain_root, "--toolchain-root")?;
        if staging_parent.starts_with(&toolchain_root)
            || toolchain_root.starts_with(&staging_parent)
        {
            return Err(ProcessError::InvalidArgument(
                "disjoint staging and toolchain roots",
            ));
        }
        Ok(Self {
            staging_parent,
            toolchain_root,
            launcher_identity,
            engine_identity,
            payload_identity,
        })
    }
}

fn exact_option_path(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
    name: &'static str,
) -> Result<PathBuf, ProcessError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(ProcessError::Usage);
    }
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(ProcessError::InvalidArgument(name))
}

fn exact_option_digest(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
    name: &'static str,
) -> Result<Sha256Digest, ProcessError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(ProcessError::Usage);
    }
    let value = arguments
        .next()
        .ok_or(ProcessError::InvalidArgument(name))?;
    parse_digest(&value).ok_or(ProcessError::InvalidArgument(name))
}

fn exact_option_count(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
    name: &'static str,
    maximum: u64,
) -> Result<u64, ProcessError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(ProcessError::Usage);
    }
    let value = arguments
        .next()
        .and_then(|value| value.to_str().map(str::to_owned))
        .ok_or(ProcessError::InvalidArgument(name))?;
    if value.is_empty() || value.starts_with('0') {
        return Err(ProcessError::InvalidArgument(name));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|count| *count <= maximum)
        .ok_or(ProcessError::InvalidArgument(name))
}

fn parse_digest(value: &OsStr) -> Option<Sha256Digest> {
    let text = value.to_str()?;
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = lowercase_hex_nibble(pair[0])?;
        let low = lowercase_hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    let digest = Sha256Digest::from_bytes(digest);
    (!digest.as_bytes().iter().all(|byte| *byte == 0)).then_some(digest)
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_directory_argument(path: &Path, name: &'static str) -> Result<(), ProcessError> {
    if path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        || !path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(ProcessError::InvalidArgument(name));
    }
    let normalized = path.components().collect::<PathBuf>();
    if normalized.as_os_str().as_encoded_bytes() != path.as_os_str().as_encoded_bytes() {
        return Err(ProcessError::InvalidArgument(name));
    }
    let canonical = fs::canonicalize(path).map_err(|error| ProcessError::Io {
        operation: "argument canonicalization",
        kind: error.kind(),
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| ProcessError::Io {
        operation: "argument metadata observation",
        kind: error.kind(),
    })?;
    if canonical.as_os_str().as_encoded_bytes() != path.as_os_str().as_encoded_bytes()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
    {
        return Err(ProcessError::InvalidArgument(name));
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() == Some(OsStr::new("direct")) {
        return match wrela_engine::run_direct(arguments) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "wrela-engine: {error}");
                ExitCode::from(error.exit_code())
            }
        };
    }
    if env::args_os().nth(1).as_deref() == Some(OsStr::new("direct-child")) {
        return match run_direct_child(env::args_os().skip(2)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "wrela-engine: {error}");
                ExitCode::from(error.exit_code())
            }
        };
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "wrela-engine: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<(), ProcessError> {
    let config = Config::parse(env::args_os().skip(1))?;
    let observed_engine = current_engine_identity()?;
    if observed_engine != config.engine_identity {
        return Err(ProcessError::EngineIdentityMismatch);
    }

    let limits = EngineProtocolLimits::standard();
    let mut executor = HeadlessCheckExecutor::new(
        &config.staging_parent,
        Toolchain::at(&config.toolchain_root),
        config.launcher_identity,
        config.engine_identity,
        config.payload_identity,
        PipelineLimits::standard(),
        limits,
    )?;
    execute_stream(&mut executor, limits)
}

fn execute_stream(
    executor: &mut HeadlessCheckExecutor,
    limits: EngineProtocolLimits,
) -> Result<(), ProcessError> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut progress = None;
    let mut frames = 0u64;
    while let Some(frame) = read_frame(&mut input, limits)? {
        frames = frames
            .checked_add(1)
            .filter(|count| *count <= limits.frames)
            .ok_or(EngineProtocolError::ResourceLimit {
                resource: "request frames",
                limit: limits.frames,
            })?;
        progress = Some(executor.accept_request_frame(&frame, &|| false)?);
    }
    if !matches!(
        progress,
        Some(RequestStreamProgress::Complete | RequestStreamProgress::Cancelled)
    ) {
        return Err(ProcessError::IncompleteRequest);
    }

    let response = executor.execute(&|| false)?;
    // Encode the complete response before touching stdout. Invalid requests,
    // response-limit failures, and allocation failures therefore publish no
    // response prefix that a launcher could mistake for authoritative output.
    let response_frames = response.encode_frames(limits, &|| false)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for frame in response_frames {
        output.write_all(&frame).map_err(|error| ProcessError::Io {
            operation: "response write",
            kind: error.kind(),
        })?;
    }
    output.flush().map_err(|error| ProcessError::Io {
        operation: "response flush",
        kind: error.kind(),
    })
}

fn run_direct_child(arguments: impl Iterator<Item = OsString>) -> Result<(), ProcessError> {
    if !cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "musl"
    )) {
        return Err(ProcessError::InvalidArgument("direct-child host"));
    }
    let config = DirectChildConfig::parse(arguments)?;
    validate_direct_child_authority_path(&config)?;
    let authority_bytes = read_exact_authority(&config)?;
    let authority = LinuxPayloadAuthority::decode_canonical(
        &authority_bytes,
        MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
        &|| false,
    )
    .map_err(|_| ProcessError::PayloadAuthority)?;
    if authority.payload_identity() != config.engine.payload_identity {
        return Err(ProcessError::PayloadAuthorityIdentityMismatch);
    }
    let observed_engine = current_engine_witness()?;
    if observed_engine.0 != config.engine.engine_identity
        || observed_engine.1 != config.engine_bytes
        || authority.frontend_engine().digest != observed_engine.0
        || authority.frontend_engine().bytes != observed_engine.1
    {
        return Err(ProcessError::EngineIdentityMismatch);
    }
    run_with_linux_payload_authority(config.engine, authority)
}

fn validate_direct_child_authority_path(config: &DirectChildConfig) -> Result<(), ProcessError> {
    let path = &config.authority_path;
    if path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        || !path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
        || path.components().collect::<PathBuf>() != *path
        || path.starts_with(&config.engine.staging_parent)
        || path.starts_with(&config.engine.toolchain_root)
    {
        return Err(ProcessError::InvalidArgument(
            "--payload-authority placement",
        ));
    }
    Ok(())
}

fn run_with_linux_payload_authority(
    config: Config,
    authority: LinuxPayloadAuthority,
) -> Result<(), ProcessError> {
    let limits = EngineProtocolLimits::standard();
    let mut executor = HeadlessCheckExecutor::new_with_linux_payload_authority(
        &config.staging_parent,
        Toolchain::at(&config.toolchain_root),
        config.launcher_identity,
        config.engine_identity,
        authority,
        PipelineLimits::standard(),
        limits,
    )?;
    execute_stream(&mut executor, limits)
}

fn read_exact_authority(config: &DirectChildConfig) -> Result<Vec<u8>, ProcessError> {
    let path = &config.authority_path;
    if !path.is_absolute() || path.components().collect::<PathBuf>() != *path {
        return Err(ProcessError::InvalidArgument("--payload-authority"));
    }
    let canonical = fs::canonicalize(path).map_err(|error| ProcessError::Io {
        operation: "payload authority canonicalization",
        kind: error.kind(),
    })?;
    let before = fs::symlink_metadata(path).map_err(|error| ProcessError::Io {
        operation: "payload authority metadata observation",
        kind: error.kind(),
    })?;
    if canonical != *path
        || !before.is_file()
        || before.file_type().is_symlink()
        || before.len() != config.authority_bytes
    {
        return Err(ProcessError::PayloadAuthority);
    }
    let mut file = File::open(path).map_err(|error| ProcessError::Io {
        operation: "payload authority open",
        kind: error.kind(),
    })?;
    let opened = file.metadata().map_err(|error| ProcessError::Io {
        operation: "payload authority opened metadata observation",
        kind: error.kind(),
    })?;
    if !same_file_observation(&before, &opened) {
        return Err(ProcessError::PayloadAuthority);
    }
    let length = usize::try_from(config.authority_bytes)
        .map_err(|_| ProcessError::Allocation("payload authority"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ProcessError::Allocation("payload authority"))?;
    (&mut file)
        .take(config.authority_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ProcessError::Io {
            operation: "payload authority read",
            kind: error.kind(),
        })?;
    let after = fs::symlink_metadata(path).map_err(|error| ProcessError::Io {
        operation: "payload authority final observation",
        kind: error.kind(),
    })?;
    if bytes.len() != length
        || !same_file_observation(&before, &after)
        || sha256(&bytes, &|| false)? != config.authority_digest
    {
        return Err(ProcessError::PayloadAuthority);
    }
    Ok(bytes)
}

fn read_frame(
    input: &mut impl Read,
    limits: EngineProtocolLimits,
) -> Result<Option<Vec<u8>>, ProcessError> {
    let mut header = [0u8; ENGINE_FRAME_HEADER_BYTES];
    if !read_first_byte(input, &mut header[0])? {
        return Ok(None);
    }
    read_exact(input, &mut header[1..])?;
    let validated = decode_frame_header(&header, limits, &|| false)?;
    let payload_bytes = validated.payload_bytes() as usize;
    let total = ENGINE_FRAME_HEADER_BYTES.checked_add(payload_bytes).ok_or(
        EngineProtocolError::FrameTooLarge {
            limit: u64::from(limits.frame_payload_bytes),
            actual: u64::MAX,
        },
    )?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ProcessError::Allocation("request frame"))?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    read_exact(input, &mut frame[ENGINE_FRAME_HEADER_BYTES..])?;
    Ok(Some(frame))
}

fn read_first_byte(input: &mut impl Read, byte: &mut u8) -> Result<bool, ProcessError> {
    loop {
        match input.read(std::slice::from_mut(byte)) {
            Ok(0) => return Ok(false),
            Ok(1) => return Ok(true),
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(ProcessError::Io {
                    operation: "request read",
                    kind: error.kind(),
                });
            }
        }
    }
}

fn read_exact(input: &mut impl Read, bytes: &mut [u8]) -> Result<(), ProcessError> {
    input.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ProcessError::Protocol(EngineProtocolError::Truncated)
        } else {
            ProcessError::Io {
                operation: "request read",
                kind: error.kind(),
            }
        }
    })
}

fn current_engine_identity() -> Result<Sha256Digest, ProcessError> {
    current_engine_witness().map(|witness| witness.0)
}

fn current_engine_witness() -> Result<(Sha256Digest, u64), ProcessError> {
    let executable = env::current_exe().map_err(|error| ProcessError::Io {
        operation: "process-image discovery",
        kind: error.kind(),
    })?;
    if executable.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES {
        return Err(ProcessError::InvalidArgument("engine process image"));
    }
    let canonical = fs::canonicalize(&executable).map_err(|error| ProcessError::Io {
        operation: "process-image canonicalization",
        kind: error.kind(),
    })?;
    let before = fs::symlink_metadata(&executable).map_err(|error| ProcessError::Io {
        operation: "process-image metadata observation",
        kind: error.kind(),
    })?;
    if canonical.as_os_str().as_encoded_bytes() != executable.as_os_str().as_encoded_bytes()
        || !before.is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > MAX_ENGINE_IMAGE_BYTES
    {
        return Err(ProcessError::InvalidArgument("engine process image"));
    }
    let mut file = File::open(&executable).map_err(|error| ProcessError::Io {
        operation: "process-image open",
        kind: error.kind(),
    })?;
    let opened = file.metadata().map_err(|error| ProcessError::Io {
        operation: "process-image opened metadata observation",
        kind: error.kind(),
    })?;
    if !same_file_observation(&before, &opened) {
        return Err(ProcessError::InvalidArgument("engine process image"));
    }
    let length = usize::try_from(before.len())
        .map_err(|_| ProcessError::Allocation("process-image bytes"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ProcessError::Allocation("process-image bytes"))?;
    (&mut file)
        .take(before.len().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ProcessError::Io {
            operation: "process-image read",
            kind: error.kind(),
        })?;
    let after = fs::symlink_metadata(&executable).map_err(|error| ProcessError::Io {
        operation: "process-image final metadata observation",
        kind: error.kind(),
    })?;
    if bytes.len() != length
        || !same_file_observation(&before, &after)
        || !same_file_observation(&opened, &after)
    {
        return Err(ProcessError::InvalidArgument("engine process image"));
    }
    let digest = sha256(&bytes, &|| false).map_err(ProcessError::Protocol)?;
    Ok((digest, before.len()))
}

#[cfg(unix)]
fn same_file_observation(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn config(authority_path: PathBuf) -> DirectChildConfig {
        DirectChildConfig {
            authority_path,
            authority_digest: digest(1),
            authority_bytes: 1,
            engine_bytes: 1,
            engine: Config {
                staging_parent: PathBuf::from("/private/staging"),
                toolchain_root: PathBuf::from("/private/toolchain"),
                launcher_identity: digest(2),
                engine_identity: digest(3),
                payload_identity: digest(4),
            },
        }
    }

    #[test]
    fn direct_child_authority_path_is_bounded_and_outside_mutable_roots() {
        validate_direct_child_authority_path(&config(PathBuf::from("/private/authority.lock")))
            .expect("outside authority");
        for invalid in [
            PathBuf::from("/private/staging/authority.lock"),
            PathBuf::from("/private/toolchain/authority.lock"),
            PathBuf::from("relative/authority.lock"),
            PathBuf::from(format!("/{}", "a".repeat(MAX_HOST_PATH_BYTES + 1))),
        ] {
            assert!(matches!(
                validate_direct_child_authority_path(&config(invalid)),
                Err(ProcessError::InvalidArgument(
                    "--payload-authority placement"
                ))
            ));
        }
    }
}

#[cfg(not(unix))]
fn same_file_observation(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}
