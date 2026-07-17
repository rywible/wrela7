//! Canonical acquisition contract for the still-missing Linux execution inputs.
//!
//! This module canonicalizes and cross-binds identity claims supplied by an
//! acquisition producer, then feeds the existing payload-authority boundary.
//! It does not observe or authenticate the underlying files. It deliberately
//! does not claim that any component executed, that a runner is native, or that
//! an appliance was booted. Those facts require a separately authenticated
//! native runner or immutable-appliance consumer.

use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_package_loader::{ContentHasher, SoftwareSha256};

use crate::{LinuxPayloadAuthority, LinuxPayloadFileWitness, LocalToolchainVerification};

pub const LINUX_EXECUTION_INPUT_SCHEMA: u32 = 1;
pub const LINUX_EXECUTION_INPUT_RECEIPT_SCHEMA: u32 = 1;
pub const LINUX_EXECUTION_INPUT_ROUTE: &str = "linux-arm64-direct";
pub const LINUX_EXECUTION_INPUT_HOST: &str = "aarch64-unknown-linux-musl";
pub const LINUX_EXECUTION_INPUT_TARGET: &str = "aarch64-qemu-virt-uefi";
pub const LINUX_EXECUTION_INPUT_EMULATOR: &str = "qemu-system-aarch64-linux-arm64";
pub const LINUX_EXECUTION_INPUT_RUNNER: &str = "native-arm64-linux";
pub const LINUX_EXECUTION_INPUT_USER_MODE_EMULATION: &str = "forbidden";
pub const LINUX_EXECUTION_INPUT_FILE_DIGEST: &str = "sha256";
pub const LINUX_EXECUTION_INPUT_TREE_DIGEST: &str = "wrela-canonical-tree-v1";
pub const MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES: u64 = 4096;
pub const MAX_LINUX_EXECUTION_INPUT_RECEIPT_BYTES: u64 = 4096;
pub const MAX_LINUX_NATIVE_RUNNER_AUTHORITY_BYTES: u64 = 16 * 1024 * 1024;

const REQUEST_IDENTITY_DOMAIN: &[u8] = b"wrela-linux-execution-input-request\0v1\0";
const RECEIPT_IDENTITY_DOMAIN: &[u8] = b"wrela-linux-execution-input-receipt\0v1\0";

/// One exact identity required before native Linux execution can be attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinuxExecutionInputKind {
    StaticEngine,
    ToolchainManifest,
    Backend,
    SystemQemu,
    FirmwareCode,
    FirmwareVariables,
    StandardLibrary,
    Target,
    Runtime,
    /// Raw SHA-256 of an external authority envelope. Merely assigning a
    /// digest to this role is not evidence that execution was native.
    NativeRunnerAuthority,
}

impl LinuxExecutionInputKind {
    pub const ALL: [Self; 10] = [
        Self::StaticEngine,
        Self::ToolchainManifest,
        Self::Backend,
        Self::SystemQemu,
        Self::FirmwareCode,
        Self::FirmwareVariables,
        Self::StandardLibrary,
        Self::Target,
        Self::Runtime,
        Self::NativeRunnerAuthority,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticEngine => "static_engine",
            Self::ToolchainManifest => "toolchain_manifest",
            Self::Backend => "backend",
            Self::SystemQemu => "qemu_system_aarch64",
            Self::FirmwareCode => "firmware_code",
            Self::FirmwareVariables => "firmware_variables",
            Self::StandardLibrary => "standard_library",
            Self::Target => "target",
            Self::Runtime => "runtime",
            Self::NativeRunnerAuthority => "native_runner_authority",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::StaticEngine => 0,
            Self::ToolchainManifest => 1,
            Self::Backend => 2,
            Self::SystemQemu => 3,
            Self::FirmwareCode => 4,
            Self::FirmwareVariables => 5,
            Self::StandardLibrary => 6,
            Self::Target => 7,
            Self::Runtime => 8,
            Self::NativeRunnerAuthority => 9,
        }
    }

    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        match self {
            Self::StaticEngine => 1024 * 1024 * 1024,
            Self::ToolchainManifest => 16 * 1024 * 1024,
            Self::Backend => 4 * 1024 * 1024 * 1024,
            Self::SystemQemu => 2 * 1024 * 1024 * 1024,
            Self::FirmwareCode | Self::FirmwareVariables => 256 * 1024 * 1024,
            Self::StandardLibrary | Self::Target => 4 * 1024 * 1024 * 1024,
            Self::Runtime => 256 * 1024 * 1024,
            Self::NativeRunnerAuthority => MAX_LINUX_NATIVE_RUNNER_AUTHORITY_BYTES,
        }
    }
}

/// Exact bounded identity claim for one input. Standard-library and target
/// roles use canonical tree digest v1; every other role uses raw SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxExecutionInput {
    pub kind: LinuxExecutionInputKind,
    pub witness: LinuxPayloadFileWitness,
}

/// Path-free expected identities for the complete direct-Linux input set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExecutionInputRequest {
    inputs: [LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()],
}

impl LinuxExecutionInputRequest {
    /// Construct only from the complete canonical role order. Callers cannot
    /// silently omit, duplicate, or alias an input identity.
    pub fn from_inputs(inputs: &[LinuxExecutionInput]) -> Result<Self, LinuxExecutionInputError> {
        if inputs.len() != LinuxExecutionInputKind::ALL.len() {
            return Err(LinuxExecutionInputError::MissingOrDuplicateInput);
        }
        for (index, expected) in LinuxExecutionInputKind::ALL.iter().enumerate() {
            if inputs[index].kind != *expected {
                return Err(LinuxExecutionInputError::MissingOrDuplicateInput);
            }
            validate_witness(inputs[index])?;
        }
        for (index, input) in inputs.iter().enumerate() {
            if inputs[index + 1..]
                .iter()
                .any(|candidate| candidate.witness.digest == input.witness.digest)
            {
                return Err(LinuxExecutionInputError::AliasedInputIdentity);
            }
        }
        let inputs: [LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()] =
            inputs
                .try_into()
                .map_err(|_| LinuxExecutionInputError::MissingOrDuplicateInput)?;
        Ok(Self { inputs })
    }

    #[must_use]
    pub fn input(&self, kind: LinuxExecutionInputKind) -> LinuxExecutionInput {
        self.inputs[kind.index()]
    }

    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut output = fixed_header(LINUX_EXECUTION_INPUT_SCHEMA);
        encode_inputs(&mut output, &self.inputs);
        output.into_bytes()
    }

    #[must_use]
    pub fn identity(&self) -> Sha256Digest {
        domain_digest(REQUEST_IDENTITY_DOMAIN, &self.encode_canonical())
    }

    pub fn decode_canonical(
        bytes: &[u8],
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, LinuxExecutionInputError> {
        check_cancelled(is_cancelled)?;
        validate_encoded_size(
            bytes,
            maximum_bytes,
            MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES,
        )?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| LinuxExecutionInputError::NonCanonical)?;
        let mut lines = text.split_terminator('\n');
        decode_fixed_header(&mut lines, LINUX_EXECUTION_INPUT_SCHEMA)?;
        let inputs = decode_inputs(&mut lines)?;
        if lines.next().is_some() {
            return Err(LinuxExecutionInputError::NonCanonical);
        }
        let request = Self::from_inputs(&inputs)?;
        if request.encode_canonical() != bytes {
            return Err(LinuxExecutionInputError::NonCanonical);
        }
        check_cancelled(is_cancelled)?;
        Ok(request)
    }
}

/// Canonical receipt claiming that an acquisition producer returned exactly
/// the requested identities. A real producer must still authenticate the
/// underlying inputs; this remains input identity, not execution evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExecutionInputReceipt {
    request: LinuxPayloadFileWitness,
    payload_authority_identity: Sha256Digest,
    inputs: [LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()],
}

impl LinuxExecutionInputReceipt {
    /// Seal exact producer observations against a decoded request. The
    /// cancellation hook is observed before validation, between identities,
    /// and before publication by the caller.
    pub fn seal(
        request: &LinuxExecutionInputRequest,
        observed: &[LinuxExecutionInput],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, LinuxExecutionInputError> {
        check_cancelled(is_cancelled)?;
        let observed = LinuxExecutionInputRequest::from_inputs(observed)?;
        for kind in LinuxExecutionInputKind::ALL {
            check_cancelled(is_cancelled)?;
            if request.input(kind) != observed.input(kind) {
                return Err(LinuxExecutionInputError::InputSubstitution(kind));
            }
        }
        let request_bytes = request.encode_canonical();
        let authority = payload_authority_from_inputs(&observed.inputs)?;
        check_cancelled(is_cancelled)?;
        Ok(Self {
            request: LinuxPayloadFileWitness {
                digest: request.identity(),
                bytes: u64::try_from(request_bytes.len())
                    .map_err(|_| LinuxExecutionInputError::InvalidMeasurement)?,
            },
            payload_authority_identity: authority.payload_identity(),
            inputs: observed.inputs,
        })
    }

    #[must_use]
    pub fn input(&self, kind: LinuxExecutionInputKind) -> LinuxExecutionInput {
        self.inputs[kind.index()]
    }

    /// Immediate handoff to the existing manifest/frontend payload authority.
    /// The local verifier still has to bind this authority to one complete
    /// immutable toolchain observation before compilation.
    pub fn payload_authority(&self) -> Result<LinuxPayloadAuthority, LinuxExecutionInputError> {
        let authority = payload_authority_from_inputs(&self.inputs)?;
        if authority.payload_identity() != self.payload_authority_identity {
            return Err(LinuxExecutionInputError::PayloadAuthorityMismatch);
        }
        Ok(authority)
    }

    /// Feed the derived manifest/frontend authority into the existing local
    /// verification consumer without repeating its filesystem scan. This
    /// binds input identities only: even a successful result leaves native
    /// runner and execution proof explicitly open.
    pub fn bind_payload_authority(
        &self,
        verification: &LocalToolchainVerification,
    ) -> Result<(), LinuxExecutionInputError> {
        let authority = self.payload_authority()?;
        verification
            .bind_linux_payload_authority(&authority)
            .map_err(|_| LinuxExecutionInputError::PayloadAuthorityMismatch)
    }

    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut output = format!(
            concat!(
                "schema={}\n",
                "request_sha256={}\n",
                "request_bytes={}\n",
                "payload_authority_sha256={}\n",
                "execution_proven=false\n",
                "runner_authority_proven=false\n"
            ),
            LINUX_EXECUTION_INPUT_RECEIPT_SCHEMA,
            self.request.digest.to_hex(),
            self.request.bytes,
            self.payload_authority_identity.to_hex(),
        );
        encode_inputs(&mut output, &self.inputs);
        output.into_bytes()
    }

    #[must_use]
    pub fn identity(&self) -> Sha256Digest {
        domain_digest(RECEIPT_IDENTITY_DOMAIN, &self.encode_canonical())
    }

    pub fn decode_canonical(
        bytes: &[u8],
        maximum_bytes: u64,
        request: &LinuxExecutionInputRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, LinuxExecutionInputError> {
        check_cancelled(is_cancelled)?;
        validate_encoded_size(
            bytes,
            maximum_bytes,
            MAX_LINUX_EXECUTION_INPUT_RECEIPT_BYTES,
        )?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| LinuxExecutionInputError::NonCanonical)?;
        let mut lines = text.split_terminator('\n');
        expect(
            &mut lines,
            "schema",
            &LINUX_EXECUTION_INPUT_RECEIPT_SCHEMA.to_string(),
        )?;
        let request_witness = witness(&mut lines, "request_sha256", "request_bytes")?;
        let payload_authority_identity = digest_value(&mut lines, "payload_authority_sha256")?;
        expect(&mut lines, "execution_proven", "false")?;
        expect(&mut lines, "runner_authority_proven", "false")?;
        let inputs = decode_inputs(&mut lines)?;
        if lines.next().is_some() {
            return Err(LinuxExecutionInputError::NonCanonical);
        }
        let observed = LinuxExecutionInputRequest::from_inputs(&inputs)?;
        let request_bytes = request.encode_canonical();
        let expected_request = LinuxPayloadFileWitness {
            digest: request.identity(),
            bytes: u64::try_from(request_bytes.len())
                .map_err(|_| LinuxExecutionInputError::InvalidMeasurement)?,
        };
        if request_witness != expected_request {
            return Err(LinuxExecutionInputError::RequestIdentityMismatch);
        }
        let receipt = Self::seal(request, &observed.inputs, is_cancelled)?;
        if receipt.payload_authority_identity != payload_authority_identity {
            return Err(LinuxExecutionInputError::PayloadAuthorityMismatch);
        }
        if receipt.encode_canonical() != bytes {
            return Err(LinuxExecutionInputError::NonCanonical);
        }
        check_cancelled(is_cancelled)?;
        Ok(receipt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxExecutionInputError {
    Cancelled,
    InvalidLimitsOrSize,
    NonCanonical,
    MissingOrDuplicateInput,
    AliasedInputIdentity,
    InvalidInputMeasurement(LinuxExecutionInputKind),
    InvalidMeasurement,
    InputSubstitution(LinuxExecutionInputKind),
    RequestIdentityMismatch,
    PayloadAuthorityMismatch,
}

impl fmt::Display for LinuxExecutionInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => {
                formatter.write_str("Linux execution input validation was cancelled")
            }
            Self::InvalidLimitsOrSize => {
                formatter.write_str("Linux execution input encoding is outside its byte limit")
            }
            Self::NonCanonical => {
                formatter.write_str("Linux execution input encoding is noncanonical")
            }
            Self::MissingOrDuplicateInput => formatter.write_str(
                "Linux execution input set is missing, duplicated, or not in canonical order",
            ),
            Self::AliasedInputIdentity => formatter
                .write_str("Linux execution inputs do not have separate content identities"),
            Self::InvalidInputMeasurement(kind) => write!(
                formatter,
                "Linux execution input {} has an invalid measurement",
                kind.as_str()
            ),
            Self::InvalidMeasurement => {
                formatter.write_str("Linux execution contract measurement is invalid")
            }
            Self::InputSubstitution(kind) => write!(
                formatter,
                "Linux execution input {} differs from the sealed request",
                kind.as_str()
            ),
            Self::RequestIdentityMismatch => formatter
                .write_str("Linux execution input receipt names a different request identity"),
            Self::PayloadAuthorityMismatch => formatter.write_str(
                "Linux execution input receipt differs from its derived payload authority",
            ),
        }
    }
}

impl std::error::Error for LinuxExecutionInputError {}

fn fixed_header(schema: u32) -> String {
    format!(
        concat!(
            "schema={}\n",
            "route={}\n",
            "host={}\n",
            "target={}\n",
            "emulator={}\n",
            "runner={}\n",
            "user_mode_emulation={}\n",
            "file_digest={}\n",
            "tree_digest={}\n"
        ),
        schema,
        LINUX_EXECUTION_INPUT_ROUTE,
        LINUX_EXECUTION_INPUT_HOST,
        LINUX_EXECUTION_INPUT_TARGET,
        LINUX_EXECUTION_INPUT_EMULATOR,
        LINUX_EXECUTION_INPUT_RUNNER,
        LINUX_EXECUTION_INPUT_USER_MODE_EMULATION,
        LINUX_EXECUTION_INPUT_FILE_DIGEST,
        LINUX_EXECUTION_INPUT_TREE_DIGEST,
    )
}

fn decode_fixed_header<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    schema: u32,
) -> Result<(), LinuxExecutionInputError> {
    expect(lines, "schema", &schema.to_string())?;
    expect(lines, "route", LINUX_EXECUTION_INPUT_ROUTE)?;
    expect(lines, "host", LINUX_EXECUTION_INPUT_HOST)?;
    expect(lines, "target", LINUX_EXECUTION_INPUT_TARGET)?;
    expect(lines, "emulator", LINUX_EXECUTION_INPUT_EMULATOR)?;
    expect(lines, "runner", LINUX_EXECUTION_INPUT_RUNNER)?;
    expect(
        lines,
        "user_mode_emulation",
        LINUX_EXECUTION_INPUT_USER_MODE_EMULATION,
    )?;
    expect(lines, "file_digest", LINUX_EXECUTION_INPUT_FILE_DIGEST)?;
    expect(lines, "tree_digest", LINUX_EXECUTION_INPUT_TREE_DIGEST)
}

fn encode_inputs(
    output: &mut String,
    inputs: &[LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()],
) {
    for input in inputs {
        output.push_str(input.kind.as_str());
        output.push_str("_sha256=");
        output.push_str(&input.witness.digest.to_hex());
        output.push('\n');
        output.push_str(input.kind.as_str());
        output.push_str("_bytes=");
        output.push_str(&input.witness.bytes.to_string());
        output.push('\n');
    }
}

fn decode_inputs<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
) -> Result<[LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()], LinuxExecutionInputError> {
    let mut inputs = Vec::with_capacity(LinuxExecutionInputKind::ALL.len());
    for kind in LinuxExecutionInputKind::ALL {
        inputs.push(LinuxExecutionInput {
            kind,
            witness: witness(
                lines,
                &format!("{}_sha256", kind.as_str()),
                &format!("{}_bytes", kind.as_str()),
            )?,
        });
    }
    inputs
        .try_into()
        .map_err(|_| LinuxExecutionInputError::MissingOrDuplicateInput)
}

fn validate_witness(input: LinuxExecutionInput) -> Result<(), LinuxExecutionInputError> {
    if input.witness.bytes == 0
        || input.witness.bytes > input.kind.maximum_bytes()
        || input
            .witness
            .digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(LinuxExecutionInputError::InvalidInputMeasurement(
            input.kind,
        ));
    }
    Ok(())
}

fn payload_authority_from_inputs(
    inputs: &[LinuxExecutionInput; LinuxExecutionInputKind::ALL.len()],
) -> Result<LinuxPayloadAuthority, LinuxExecutionInputError> {
    LinuxPayloadAuthority::from_witnesses(
        inputs[LinuxExecutionInputKind::ToolchainManifest.index()].witness,
        inputs[LinuxExecutionInputKind::StaticEngine.index()].witness,
    )
    .map_err(|_| LinuxExecutionInputError::PayloadAuthorityMismatch)
}

fn validate_encoded_size(
    bytes: &[u8],
    maximum_bytes: u64,
    hard_maximum: u64,
) -> Result<(), LinuxExecutionInputError> {
    if maximum_bytes == 0
        || maximum_bytes > hard_maximum
        || bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes
        || !bytes.ends_with(b"\n")
    {
        return Err(LinuxExecutionInputError::InvalidLimitsOrSize);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut digest = SoftwareSha256.begin_sha256();
    digest.update(domain);
    digest.update(bytes);
    digest.finish()
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LinuxExecutionInputError> {
    if is_cancelled() {
        Err(LinuxExecutionInputError::Cancelled)
    } else {
        Ok(())
    }
}

fn expect<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
    expected: &str,
) -> Result<(), LinuxExecutionInputError> {
    let value = value(lines, key)?;
    if value != expected {
        return Err(LinuxExecutionInputError::NonCanonical);
    }
    Ok(())
}

fn witness<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    digest_key: &str,
    bytes_key: &str,
) -> Result<LinuxPayloadFileWitness, LinuxExecutionInputError> {
    let digest = digest_value(lines, digest_key)?;
    let bytes = value(lines, bytes_key)?;
    if bytes.is_empty() || bytes.starts_with('0') {
        return Err(LinuxExecutionInputError::NonCanonical);
    }
    let bytes = bytes
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .ok_or(LinuxExecutionInputError::NonCanonical)?;
    Ok(LinuxPayloadFileWitness { digest, bytes })
}

fn digest_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<Sha256Digest, LinuxExecutionInputError> {
    parse_digest(value(lines, key)?).ok_or(LinuxExecutionInputError::NonCanonical)
}

fn value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, LinuxExecutionInputError> {
    let line = lines.next().ok_or(LinuxExecutionInputError::NonCanonical)?;
    let (actual_key, value) = line
        .split_once('=')
        .ok_or(LinuxExecutionInputError::NonCanonical)?;
    if actual_key != key {
        return Err(LinuxExecutionInputError::NonCanonical);
    }
    Ok(value)
}

fn parse_digest(text: &str) -> Option<Sha256Digest> {
    if text.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (lower_hex(pair[0])? << 4) | lower_hex(pair[1])?;
    }
    (!digest.iter().all(|byte| *byte == 0)).then_some(Sha256Digest::from_bytes(digest))
}

const fn lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn digest(label: &str) -> Sha256Digest {
        SoftwareSha256.sha256(label.as_bytes())
    }

    fn inputs() -> Vec<LinuxExecutionInput> {
        LinuxExecutionInputKind::ALL
            .iter()
            .enumerate()
            .map(|(index, kind)| LinuxExecutionInput {
                kind: *kind,
                witness: LinuxPayloadFileWitness {
                    digest: digest(kind.as_str()),
                    bytes: 1024 + index as u64,
                },
            })
            .collect()
    }

    fn request() -> LinuxExecutionInputRequest {
        LinuxExecutionInputRequest::from_inputs(&inputs()).expect("complete input request")
    }

    #[test]
    fn canonical_request_receipt_and_payload_authority_consumer_round_trip() {
        let request = request();
        let request_bytes = request.encode_canonical();
        let decoded = LinuxExecutionInputRequest::decode_canonical(
            &request_bytes,
            MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES,
            &|| false,
        )
        .expect("canonical request");
        assert_eq!(decoded, request);

        let receipt = LinuxExecutionInputReceipt::seal(&request, &inputs(), &|| false)
            .expect("matching acquisition receipt");
        let receipt_bytes = receipt.encode_canonical();
        let decoded = LinuxExecutionInputReceipt::decode_canonical(
            &receipt_bytes,
            MAX_LINUX_EXECUTION_INPUT_RECEIPT_BYTES,
            &request,
            &|| false,
        )
        .expect("canonical receipt");
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.identity(), receipt.identity());
        let authority = decoded.payload_authority().expect("payload authority");
        assert_eq!(
            authority.frontend_engine(),
            request.input(LinuxExecutionInputKind::StaticEngine).witness
        );
        assert_eq!(
            authority.toolchain_manifest(),
            request
                .input(LinuxExecutionInputKind::ToolchainManifest)
                .witness
        );
        let immediate_consumer: fn(
            &LinuxExecutionInputReceipt,
            &LocalToolchainVerification,
        ) -> Result<(), LinuxExecutionInputError> =
            LinuxExecutionInputReceipt::bind_payload_authority;
        let _ = immediate_consumer;

        let raw_request_digest = SoftwareSha256.sha256(&request_bytes);
        let raw_receipt_digest = SoftwareSha256.sha256(&receipt_bytes);
        assert_ne!(request.identity(), raw_request_digest);
        assert_ne!(receipt.identity(), raw_receipt_digest);
        assert_ne!(request.identity(), receipt.identity());
    }

    #[test]
    fn request_rejects_darwin_user_mode_stale_missing_duplicate_and_reordered_inputs() {
        let canonical = String::from_utf8(request().encode_canonical()).expect("request UTF-8");
        for malformed in [
            canonical.replacen("schema=1", "schema=2", 1),
            canonical.replacen(
                "host=aarch64-unknown-linux-musl",
                "host=aarch64-apple-darwin",
                1,
            ),
            canonical.replacen("runner=native-arm64-linux", "runner=qemu-user-aarch64", 1),
            canonical.replacen(
                "user_mode_emulation=forbidden",
                "user_mode_emulation=allowed",
                1,
            ),
            canonical.replacen("file_digest=sha256", "file_digest=sha512", 1),
            canonical.replacen("backend_sha256=", "unknown_sha256=", 1),
            canonical.replacen("static_engine_sha256=", "toolchain_manifest_sha256=", 1),
        ] {
            assert!(matches!(
                LinuxExecutionInputRequest::decode_canonical(
                    malformed.as_bytes(),
                    MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES,
                    &|| false,
                ),
                Err(LinuxExecutionInputError::NonCanonical)
                    | Err(LinuxExecutionInputError::MissingOrDuplicateInput)
            ));
        }

        let mut missing = inputs();
        missing.pop();
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&missing),
            Err(LinuxExecutionInputError::MissingOrDuplicateInput)
        ));
        let mut duplicate = inputs();
        duplicate[1] = duplicate[0];
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&duplicate),
            Err(LinuxExecutionInputError::MissingOrDuplicateInput)
        ));
        let mut reordered = inputs();
        reordered.swap(1, 2);
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&reordered),
            Err(LinuxExecutionInputError::MissingOrDuplicateInput)
        ));

        let mut aliased = inputs();
        aliased[LinuxExecutionInputKind::Backend.index()]
            .witness
            .digest = aliased[LinuxExecutionInputKind::StaticEngine.index()]
            .witness
            .digest;
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&aliased),
            Err(LinuxExecutionInputError::AliasedInputIdentity)
        ));

        for malformed in [
            canonical.replacen("backend_bytes=1026", "backend_bytes=01026", 1),
            canonical.replacen(
                &digest(LinuxExecutionInputKind::Backend.as_str()).to_hex(),
                &digest(LinuxExecutionInputKind::Backend.as_str())
                    .to_hex()
                    .to_uppercase(),
                1,
            ),
            format!("{canonical}\n"),
            canonical.trim_end().to_owned(),
        ] {
            assert!(
                LinuxExecutionInputRequest::decode_canonical(
                    malformed.as_bytes(),
                    MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES,
                    &|| false,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn receipt_rejects_component_request_and_execution_claim_substitution() {
        let request = request();
        let mut substituted = inputs();
        substituted[LinuxExecutionInputKind::Backend as usize]
            .witness
            .digest = digest("substituted backend");
        assert!(matches!(
            LinuxExecutionInputReceipt::seal(&request, &substituted, &|| false),
            Err(LinuxExecutionInputError::InputSubstitution(
                LinuxExecutionInputKind::Backend
            ))
        ));

        let receipt = LinuxExecutionInputReceipt::seal(&request, &inputs(), &|| false)
            .expect("matching acquisition receipt");
        let canonical = String::from_utf8(receipt.encode_canonical()).expect("receipt UTF-8");
        for malformed in [
            canonical.replacen("execution_proven=false", "execution_proven=true", 1),
            canonical.replacen(
                "runner_authority_proven=false",
                "runner_authority_proven=true",
                1,
            ),
            canonical.replacen("schema=1", "schema=2", 1),
            canonical.replacen(
                &format!("request_sha256={}", request.identity().to_hex()),
                &format!("request_sha256={}", digest("stale request").to_hex()),
                1,
            ),
            canonical.replacen(
                "payload_authority_sha256=",
                "unknown_payload_authority_sha256=",
                1,
            ),
        ] {
            assert!(
                LinuxExecutionInputReceipt::decode_canonical(
                    malformed.as_bytes(),
                    MAX_LINUX_EXECUTION_INPUT_RECEIPT_BYTES,
                    &request,
                    &|| false,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn exact_limits_and_cancellation_fail_closed() {
        let request = request();
        let bytes = request.encode_canonical();
        LinuxExecutionInputRequest::decode_canonical(&bytes, bytes.len() as u64, &|| false)
            .expect("exact byte bound");
        assert!(matches!(
            LinuxExecutionInputRequest::decode_canonical(&bytes, bytes.len() as u64 - 1, &|| false,),
            Err(LinuxExecutionInputError::InvalidLimitsOrSize)
        ));

        let receipt = LinuxExecutionInputReceipt::seal(&request, &inputs(), &|| false)
            .expect("matching receipt");
        let receipt_bytes = receipt.encode_canonical();
        LinuxExecutionInputReceipt::decode_canonical(
            &receipt_bytes,
            receipt_bytes.len() as u64,
            &request,
            &|| false,
        )
        .expect("exact receipt byte bound");
        assert!(matches!(
            LinuxExecutionInputReceipt::decode_canonical(
                &receipt_bytes,
                receipt_bytes.len() as u64 - 1,
                &request,
                &|| false,
            ),
            Err(LinuxExecutionInputError::InvalidLimitsOrSize)
        ));

        let polls = Cell::new(0_u8);
        assert!(matches!(
            LinuxExecutionInputReceipt::seal(&request, &inputs(), &|| {
                let current = polls.get();
                polls.set(current + 1);
                current >= 3
            }),
            Err(LinuxExecutionInputError::Cancelled)
        ));
        assert!(polls.get() >= 4);

        let mut oversized = inputs();
        oversized[LinuxExecutionInputKind::NativeRunnerAuthority.index()]
            .witness
            .bytes = LinuxExecutionInputKind::NativeRunnerAuthority.maximum_bytes() + 1;
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&oversized),
            Err(LinuxExecutionInputError::InvalidInputMeasurement(
                LinuxExecutionInputKind::NativeRunnerAuthority
            ))
        ));

        for kind in LinuxExecutionInputKind::ALL {
            let mut exact = inputs();
            exact[kind.index()].witness.bytes = kind.maximum_bytes();
            LinuxExecutionInputRequest::from_inputs(&exact).expect("exact component byte bound");

            exact[kind.index()].witness.bytes = kind.maximum_bytes() + 1;
            assert!(matches!(
                LinuxExecutionInputRequest::from_inputs(&exact),
                Err(LinuxExecutionInputError::InvalidInputMeasurement(actual)) if actual == kind
            ));
        }

        let mut zero_bytes = inputs();
        zero_bytes[LinuxExecutionInputKind::Runtime.index()]
            .witness
            .bytes = 0;
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&zero_bytes),
            Err(LinuxExecutionInputError::InvalidInputMeasurement(
                LinuxExecutionInputKind::Runtime
            ))
        ));
        let mut zero_digest = inputs();
        zero_digest[LinuxExecutionInputKind::Runtime.index()]
            .witness
            .digest = Sha256Digest::from_bytes([0; 32]);
        assert!(matches!(
            LinuxExecutionInputRequest::from_inputs(&zero_digest),
            Err(LinuxExecutionInputError::InvalidInputMeasurement(
                LinuxExecutionInputKind::Runtime
            ))
        ));

        let decode_polls = Cell::new(0_u8);
        assert!(matches!(
            LinuxExecutionInputRequest::decode_canonical(
                &bytes,
                MAX_LINUX_EXECUTION_INPUT_REQUEST_BYTES,
                &|| {
                    let current = decode_polls.get();
                    decode_polls.set(current + 1);
                    current > 0
                },
            ),
            Err(LinuxExecutionInputError::Cancelled)
        ));
        assert!(decode_polls.get() >= 2);
    }
}
