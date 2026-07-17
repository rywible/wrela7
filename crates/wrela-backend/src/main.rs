//! Private code-generation process. This is not installed on the user's PATH.
//!
//! One execution reads exactly one canonical backend request frame from
//! standard input and writes exactly one canonical response frame to standard
//! output. The only filesystem authority is the explicit, canonical private
//! root supplied by the composition root.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use wrela_backend::{
    BackendExecutionError, BackendExecutionOptions, BackendExecutionRequest, BackendExecutor,
    BackendJobPathCandidate, BackendJobPaths, BackendLimits, CanonicalBackendExecutor,
};
use wrela_backend_protocol::{
    BackendFailure, BackendFailureKind, BackendOutcome, BackendRequest, BackendResponse,
    MAX_FRAME_BYTES, RequestId, decode_request, encode_request, encode_response,
};
use wrela_build_model::{Sha256Digest, seal_build_configuration};
use wrela_flow_opt::OptimizationProfile;
use wrela_link_efi::{CanonicalCoffObjectInspector, CoffObjectInspector, TargetRuntimeObject};
use wrela_target::{
    CanonicalTargetPackageCodec, TargetDecodeLimits, TargetDecodeRequest,
    decode_and_verify_target_package,
};

const FRAME_HEADER_BYTES: usize = 8 + 4 + 1 + 4;
const REQUEST_MAGIC: &[u8; 8] = b"WRELBEP\0";
const REQUEST_MESSAGE_KIND: u8 = 1;
const MAX_PROCESS_ERROR_BYTES: usize = 4096;
const EXIT_USAGE: u8 = 64;
const EXIT_PROTOCOL: u8 = 65;
const EXIT_IO: u8 = 74;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            write_process_error(&error);
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<(), ProcessError> {
    match parse_mode(env::args_os())? {
        Mode::Version => {
            write_text_line(&format_args!("wrela-backend {}", env!("CARGO_PKG_VERSION")))
        }
        Mode::ProtocolVersion => write_text_line(&format_args!(
            "{}",
            wrela_backend_protocol::PROTOCOL_VERSION
        )),
        Mode::Execute { private_root } => execute(private_root),
    }
}

#[derive(Debug)]
enum Mode {
    Version,
    ProtocolVersion,
    Execute { private_root: PathBuf },
}

fn parse_mode(mut arguments: impl Iterator<Item = OsString>) -> Result<Mode, ProcessError> {
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return Err(ProcessError::Usage);
    };
    if command == "--version" {
        if arguments.next().is_some() {
            return Err(ProcessError::Usage);
        }
        return Ok(Mode::Version);
    }
    if command == "--protocol-version" {
        if arguments.next().is_some() {
            return Err(ProcessError::Usage);
        }
        return Ok(Mode::ProtocolVersion);
    }
    if command == "--private-root" {
        let Some(private_root) = arguments.next() else {
            return Err(ProcessError::Usage);
        };
        if arguments.next().is_some() {
            return Err(ProcessError::Usage);
        }
        return Ok(Mode::Execute {
            private_root: PathBuf::from(private_root),
        });
    }
    Err(ProcessError::Usage)
}

fn execute(private_root: PathBuf) -> Result<(), ProcessError> {
    let private_root = validate_private_root(private_root)?;
    let frame = read_request_frame(&mut io::stdin().lock())?;
    let request = decode_request(&frame).map_err(|_| ProcessError::InvalidProtocol)?;
    let response = process_request(&private_root, &frame, &request)?;
    let encoded = encode_response(&response).map_err(|_| ProcessError::ResponseEncoding)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|()| stdout.flush())
        .map_err(|_| ProcessError::Output)
}

fn process_request(
    private_root: &Path,
    frame: &[u8],
    request: &BackendRequest,
) -> Result<BackendResponse, ProcessError> {
    let profile = request
        .build
        .profile
        .canonical_bytes()
        .map_err(|_| ProcessError::RequestValidation)?;
    let profile_digest = sha256(&profile);
    let validated_build = match seal_build_configuration(request.build.clone(), profile_digest) {
        Ok(build) => build,
        Err(_) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Verification,
                "backend request profile digest does not match the canonical profile",
            );
        }
    };
    let canonical =
        encode_request(request, &validated_build).map_err(|_| ProcessError::RequestValidation)?;
    if canonical != frame {
        return failure_response(
            request.request_id,
            BackendFailureKind::Protocol,
            "backend request frame is not the canonical protocol encoding",
        );
    }

    let paths = match validate_request_paths(private_root, request) {
        Ok(paths) => paths,
        Err(()) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Input,
                "backend request paths do not name distinct, private, canonical inputs and absent outputs",
            );
        }
    };
    let limits = BackendLimits::standard();
    if limits.validate().is_err() {
        return failure_response(
            request.request_id,
            BackendFailureKind::Internal,
            "backend resource policy is internally inconsistent",
        );
    }
    let wir_bytes = match read_stable_file(&paths.wir, limits.codec.frame_bytes) {
        Ok(bytes) => bytes,
        Err(()) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Input,
                "FlowWir input is absent, unstable, non-private, or exceeds the backend byte limit",
            );
        }
    };
    if sha256(&wir_bytes) != request.wir_digest {
        return failure_response(
            request.request_id,
            BackendFailureKind::Verification,
            "FlowWir input digest does not match the backend request",
        );
    }

    let target_limits = TargetDecodeLimits::standard();
    let target_toml = paths.target_package.join("target.toml");
    let target_bytes = match read_stable_file(&target_toml, target_limits.bytes) {
        Ok(bytes) => bytes,
        Err(()) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Target,
                "target.toml is absent, unstable, non-private, or exceeds the target byte limit",
            );
        }
    };
    let target = match decode_and_verify_target_package(
        &CanonicalTargetPackageCodec::new(),
        TargetDecodeRequest {
            toml_bytes: &target_bytes,
            expected_identity: &request.build.identity.target,
            verified_digest: request.build.identity.target_package,
            limits: target_limits,
        },
        &never_cancelled,
    ) {
        Ok(target) => target,
        Err(_) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Target,
                "target package metadata is malformed, stale, noncanonical, or unsupported",
            );
        }
    };
    let runtime = paths.target_package.join(target.backend().runtime_object());
    let runtime_measurement = if runtime.starts_with(&paths.target_package) {
        CanonicalCoffObjectInspector::new()
            .inspect(&runtime, limits.link.object_bytes, &never_cancelled)
            .ok()
    } else {
        None
    };
    let runtime_measurement = match runtime_measurement {
        Some(measurement)
            if measurement.digest == request.target_runtime_digest
                && measurement.bytes == request.target_runtime_bytes =>
        {
            measurement
        }
        _ => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Target,
                "target runtime is absent, unstable, oversized, not canonical ARM64 COFF, or differs from the request's verified digest and length",
            );
        }
    };
    let job_paths = match backend_job_paths(private_root, &paths, request) {
        Ok(paths) => paths,
        Err(()) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Input,
                "backend staging paths are not private, distinct, and absent",
            );
        }
    };
    let optimization = match OptimizationProfile::from_build_policy(
        &validated_build.profile().optimization,
        validated_build.identity.compiler,
    ) {
        Ok(profile) => profile,
        Err(_) => {
            return failure_response(
                request.request_id,
                BackendFailureKind::Verification,
                "backend optimization policy is invalid or unsupported",
            );
        }
    };
    match CanonicalBackendExecutor::new().execute(
        BackendExecutionRequest {
            protocol: request,
            build: &validated_build,
            wir_bytes: &wir_bytes,
            target: &target,
            target_runtime: TargetRuntimeObject {
                path: &runtime,
                digest: runtime_measurement.digest,
                bytes: runtime_measurement.bytes,
                target_package: target.semantic().content_digest(),
                runtime_abi_version: target.backend().runtime_abi_version(),
            },
            paths: &job_paths,
            options: BackendExecutionOptions {
                optimization,
                limits,
            },
        },
        &never_cancelled,
    ) {
        Ok(output) => Ok(output.into_parts().0),
        Err(error) => execution_error_response(request.request_id, &error),
    }
}

fn failure_response(
    request_id: RequestId,
    kind: BackendFailureKind,
    message: &str,
) -> Result<BackendResponse, ProcessError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(message.len())
        .map_err(|_| ProcessError::ResourceExhausted)?;
    owned.push_str(message);
    Ok(BackendResponse {
        request_id,
        outcome: BackendOutcome::Failure(BackendFailure {
            kind,
            message: owned,
        }),
    })
}

struct RequestPaths {
    wir: PathBuf,
    target_package: PathBuf,
    output: PathBuf,
    report: PathBuf,
}

fn validate_request_paths(
    private_root: &Path,
    request: &BackendRequest,
) -> Result<RequestPaths, ()> {
    let wir = controlled_path(private_root, request.wir.as_str())?;
    let target_package = controlled_path(private_root, request.target_package.as_str())?;
    let output = controlled_path(private_root, request.output.as_str())?;
    let report = controlled_path(private_root, request.report.as_str())?;
    if wir == target_package
        || wir == output
        || wir == report
        || target_package == output
        || target_package == report
        || output == report
        || output.starts_with(&target_package)
        || report.starts_with(&target_package)
    {
        return Err(());
    }
    validate_directory(&target_package, false)?;
    validate_absent_output(private_root, &output)?;
    validate_absent_output(private_root, &report)?;
    Ok(RequestPaths {
        wir,
        target_package,
        output,
        report,
    })
}

fn backend_job_paths(
    private_root: &Path,
    request_paths: &RequestPaths,
    request: &BackendRequest,
) -> Result<BackendJobPaths, ()> {
    let stem = format!(".wrela-backend-{:016x}", request.request_id.0);
    let candidate = BackendJobPathCandidate {
        private_root: private_root.to_path_buf(),
        generated_object: private_root.join(format!("{stem}.obj")),
        temporary_image: private_root.join(format!("{stem}.tmp.efi")),
        temporary_map: private_root.join(format!("{stem}.tmp.map")),
        temporary_report: private_root.join(format!("{stem}.tmp.json")),
        final_image: request_paths.output.clone(),
        final_report: request_paths.report.clone(),
    };
    let staging = [
        &candidate.generated_object,
        &candidate.temporary_image,
        &candidate.temporary_map,
        &candidate.temporary_report,
    ];
    if staging.iter().any(|path| {
        *path == &request_paths.wir
            || *path == &request_paths.target_package
            || *path == &request_paths.output
            || *path == &request_paths.report
            || path.starts_with(&request_paths.target_package)
    }) {
        return Err(());
    }
    for path in staging {
        validate_absent_output(private_root, path)?;
    }
    BackendJobPaths::new(candidate).map_err(|_| ())
}

fn execution_error_response(
    request_id: RequestId,
    error: &BackendExecutionError,
) -> Result<BackendResponse, ProcessError> {
    let (kind, message) = match error {
        BackendExecutionError::InvalidPaths => (
            BackendFailureKind::Input,
            "backend private or publication paths became invalid",
        ),
        BackendExecutionError::InvalidRequest(_) => (
            BackendFailureKind::Verification,
            "backend execution request failed canonical validation",
        ),
        BackendExecutionError::DigestMismatch { .. } => (
            BackendFailureKind::Verification,
            "a private backend artifact changed after its sealed measurement",
        ),
        BackendExecutionError::Cancelled => (
            BackendFailureKind::Internal,
            "backend execution was cancelled before publication",
        ),
        BackendExecutionError::PrivateIo { .. } => (
            BackendFailureKind::Internal,
            "private backend artifact I/O failed before publication",
        ),
        BackendExecutionError::InternalInvariant(_) => (
            BackendFailureKind::Internal,
            "a sealed backend stage violated the composition invariant",
        ),
    };
    failure_response(request_id, kind, message)
}

fn controlled_path(private_root: &Path, relative: &str) -> Result<PathBuf, ()> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(());
    }
    let joined = private_root.join(relative);
    if joined.starts_with(private_root) && joined != private_root {
        Ok(joined)
    } else {
        Err(())
    }
}

fn validate_absent_output(private_root: &Path, output: &Path) -> Result<(), ()> {
    let parent = output.parent().ok_or(())?;
    if parent == private_root {
        validate_directory(private_root, true)?;
    } else {
        validate_directory(parent, false)?;
    }
    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(()),
    }
}

fn validate_private_root(private_root: PathBuf) -> Result<PathBuf, ProcessError> {
    if !normal_absolute_path(&private_root) {
        return Err(ProcessError::InvalidPrivateRoot);
    }
    let canonical =
        fs::canonicalize(&private_root).map_err(|_| ProcessError::InvalidPrivateRoot)?;
    if canonical != private_root || validate_directory(&private_root, true).is_err() {
        return Err(ProcessError::InvalidPrivateRoot);
    }
    Ok(private_root)
}

fn normal_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && normalized.as_os_str() == path.as_os_str()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn validate_directory(path: &Path, require_private: bool) -> Result<(), ()> {
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let forbidden = if require_private { 0o077 } else { 0o022 };
        if metadata.mode() & forbidden != 0 {
            return Err(());
        }
    }
    Ok(())
}

fn read_request_frame(reader: &mut impl Read) -> Result<Vec<u8>, ProcessError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => ProcessError::TruncatedProtocol,
            _ => ProcessError::Input,
        })?;
    let version_bytes: [u8; 4] = header[8..12]
        .try_into()
        .map_err(|_| ProcessError::InvalidProtocol)?;
    if &header[..8] != REQUEST_MAGIC
        || u32::from_le_bytes(version_bytes) != wrela_backend_protocol::PROTOCOL_VERSION
        || header[12] != REQUEST_MESSAGE_KIND
    {
        return Err(ProcessError::InvalidProtocol);
    }
    let length_bytes: [u8; 4] = header[FRAME_HEADER_BYTES - 4..]
        .try_into()
        .map_err(|_| ProcessError::InvalidProtocol)?;
    let payload_bytes = u32::from_le_bytes(length_bytes) as usize;
    if payload_bytes > MAX_FRAME_BYTES {
        return Err(ProcessError::OversizedProtocol);
    }
    let total = FRAME_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(ProcessError::OversizedProtocol)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ProcessError::ResourceExhausted)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    reader
        .read_exact(&mut frame[FRAME_HEADER_BYTES..])
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => ProcessError::TruncatedProtocol,
            _ => ProcessError::Input,
        })?;
    let mut trailing = [0u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(ProcessError::TrailingProtocol),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ProcessError::Input),
        }
    }
    Ok(frame)
}

fn read_stable_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, ()> {
    let (mut file, identity) = open_stable_file(path, maximum_bytes)?;
    let length = usize::try_from(identity.bytes).map_err(|_| ())?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| ())?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes).map_err(|_| ())?;
    ensure_exact_end(&mut file)?;
    verify_stable_file(path, &file, identity)?;
    Ok(bytes)
}

fn ensure_exact_end(file: &mut File) -> Result<(), ()> {
    let mut trailing = [0u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(()),
        _ => Err(()),
    }
}

fn open_stable_file(path: &Path, maximum_bytes: u64) -> Result<(File, FileIdentity), ()> {
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    if canonical != path {
        return Err(());
    }
    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    validate_regular_metadata(&before)?;
    let identity = file_identity(&before);
    if identity.bytes > maximum_bytes {
        return Err(());
    }
    let file = File::open(path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    validate_regular_metadata(&opened)?;
    if file_identity(&opened) != identity {
        return Err(());
    }
    Ok((file, identity))
}

fn verify_stable_file(path: &Path, file: &File, expected: FileIdentity) -> Result<(), ()> {
    let opened = file.metadata().map_err(|_| ())?;
    let current = fs::symlink_metadata(path).map_err(|_| ())?;
    validate_regular_metadata(&opened)?;
    validate_regular_metadata(&current)?;
    if file_identity(&opened) == expected && file_identity(&current) == expected {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_regular_metadata(metadata: &Metadata) -> Result<(), ()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    modified_time: u64,
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        bytes: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;

    FileIdentity {
        bytes: metadata.len(),
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        modified_time: metadata.last_write_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        bytes: metadata.len(),
    }
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    Sha256Digest::from_bytes(digest)
}

const fn never_cancelled() -> bool {
    false
}

fn write_text_line(arguments: &std::fmt::Arguments<'_>) -> Result<(), ProcessError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_fmt(*arguments)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| ProcessError::Output)
}

#[derive(Debug, Clone, Copy)]
enum ProcessError {
    Usage,
    InvalidPrivateRoot,
    Input,
    TruncatedProtocol,
    OversizedProtocol,
    TrailingProtocol,
    InvalidProtocol,
    RequestValidation,
    ResponseEncoding,
    ResourceExhausted,
    Output,
}

impl ProcessError {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => EXIT_USAGE,
            Self::TruncatedProtocol
            | Self::OversizedProtocol
            | Self::TrailingProtocol
            | Self::InvalidProtocol
            | Self::RequestValidation => EXIT_PROTOCOL,
            Self::InvalidPrivateRoot
            | Self::Input
            | Self::ResponseEncoding
            | Self::ResourceExhausted
            | Self::Output => EXIT_IO,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Usage => {
                "usage: wrela-backend (--version | --protocol-version | --private-root <absolute-private-directory>)"
            }
            Self::InvalidPrivateRoot => {
                "backend private root must be an existing canonical private directory"
            }
            Self::Input => "backend request input could not be read",
            Self::TruncatedProtocol => "backend request frame is truncated",
            Self::OversizedProtocol => "backend request frame exceeds the protocol byte limit",
            Self::TrailingProtocol => "backend request stream contains trailing bytes",
            Self::InvalidProtocol => "backend request frame is malformed or unsupported",
            Self::RequestValidation => "backend request could not be validated canonically",
            Self::ResponseEncoding => "backend response could not be encoded canonically",
            Self::ResourceExhausted => "backend process resource limit could not be reserved",
            Self::Output => "backend response output could not be written",
        }
    }
}

fn write_process_error(error: &ProcessError) {
    let message = error.message();
    let message = &message[..message.len().min(MAX_PROCESS_ERROR_BYTES)];
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"wrela-backend: ");
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}
