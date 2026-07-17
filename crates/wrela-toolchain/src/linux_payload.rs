//! Canonical authority for the exact revision-0.1 Linux engine payload.

use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_package_loader::{ContentHasher, SoftwareSha256};

use crate::{
    CanonicalToolchainManifestCodec, ComponentKind, ToolchainCompatibility, ToolchainDecodeLimits,
    ToolchainDecodeRequest, decode_and_verify_toolchain_manifest,
};

pub const LINUX_PAYLOAD_AUTHORITY_SCHEMA: u32 = 1;
pub const LINUX_PAYLOAD_ENGINE_PROTOCOL: u32 = 1;
pub const LINUX_PAYLOAD_HOST: &str = "aarch64-unknown-linux-musl";
pub const LINUX_PAYLOAD_ROUTE: &str = "linux-arm64-direct";
pub const MAX_LINUX_PAYLOAD_AUTHORITY_BYTES: u64 = 1024;
pub const MAX_LINUX_FRONTEND_ENGINE_BYTES: u64 = 1024 * 1024 * 1024;
const PAYLOAD_IDENTITY_DOMAIN: &[u8] = b"wrela-linux-payload-authority\0v1\0";

/// Exact byte witness retained by the Linux payload authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxPayloadFileWitness {
    pub digest: Sha256Digest,
    pub bytes: u64,
}

/// Path-free, exact-current authority for one canonical Linux toolchain
/// manifest and the frontend engine it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPayloadAuthority {
    toolchain_manifest: LinuxPayloadFileWitness,
    frontend_engine: LinuxPayloadFileWitness,
}

impl LinuxPayloadAuthority {
    /// Reconstruct the path-free representation from exact bounded witnesses.
    /// Consumers must still bind the canonical authority bytes and verified
    /// installation before treating this representation as execution proof.
    pub fn from_witnesses(
        toolchain_manifest: LinuxPayloadFileWitness,
        frontend_engine: LinuxPayloadFileWitness,
    ) -> Result<Self, LinuxPayloadAuthorityError> {
        let authority = Self {
            toolchain_manifest,
            frontend_engine,
        };
        authority.validate()?;
        Ok(authority)
    }

    /// Derive authority only from an already-canonical complete toolchain
    /// manifest. This is a producer helper, not filesystem verification.
    pub fn from_canonical_toolchain_manifest(
        manifest_bytes: &[u8],
        limits: ToolchainDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, LinuxPayloadAuthorityError> {
        check_cancelled(is_cancelled)?;
        let manifest = decode_and_verify_toolchain_manifest(
            &CanonicalToolchainManifestCodec::new(),
            ToolchainDecodeRequest {
                bytes: manifest_bytes,
                limits,
                required: &ToolchainCompatibility::current(),
            },
            is_cancelled,
        )
        .map_err(|_| LinuxPayloadAuthorityError::InvalidToolchainManifest)?;
        if manifest.host != LINUX_PAYLOAD_HOST {
            return Err(LinuxPayloadAuthorityError::InvalidHost);
        }
        let frontend = manifest
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Frontend)
            .ok_or(LinuxPayloadAuthorityError::InvalidFrontend)?;
        let manifest_bytes_count = u64::try_from(manifest_bytes.len())
            .map_err(|_| LinuxPayloadAuthorityError::InvalidMeasurement)?;
        let authority = Self::from_witnesses(
            LinuxPayloadFileWitness {
                digest: SoftwareSha256.sha256(manifest_bytes),
                bytes: manifest_bytes_count,
            },
            LinuxPayloadFileWitness {
                digest: frontend.digest,
                bytes: frontend.bytes,
            },
        )?;
        check_cancelled(is_cancelled)?;
        Ok(authority)
    }

    #[must_use]
    pub const fn toolchain_manifest(&self) -> LinuxPayloadFileWitness {
        self.toolchain_manifest
    }

    #[must_use]
    pub const fn frontend_engine(&self) -> LinuxPayloadFileWitness {
        self.frontend_engine
    }

    /// Domain- and version-separated identity over the canonical authority
    /// bytes. The generic toolchain manifest and engine wire stay unchanged.
    #[must_use]
    pub fn payload_identity(&self) -> Sha256Digest {
        let encoded = self.encode_canonical();
        let mut digest = SoftwareSha256.begin_sha256();
        digest.update(PAYLOAD_IDENTITY_DOMAIN);
        digest.update(&encoded);
        digest.finish()
    }

    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        format!(
            concat!(
                "schema={}\n",
                "route={}\n",
                "host={}\n",
                "engine_protocol={}\n",
                "toolchain_manifest_sha256={}\n",
                "toolchain_manifest_bytes={}\n",
                "frontend_engine_sha256={}\n",
                "frontend_engine_bytes={}\n"
            ),
            LINUX_PAYLOAD_AUTHORITY_SCHEMA,
            LINUX_PAYLOAD_ROUTE,
            LINUX_PAYLOAD_HOST,
            LINUX_PAYLOAD_ENGINE_PROTOCOL,
            self.toolchain_manifest.digest.to_hex(),
            self.toolchain_manifest.bytes,
            self.frontend_engine.digest.to_hex(),
            self.frontend_engine.bytes,
        )
        .into_bytes()
    }

    pub fn decode_canonical(
        bytes: &[u8],
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, LinuxPayloadAuthorityError> {
        check_cancelled(is_cancelled)?;
        if maximum_bytes == 0
            || maximum_bytes > MAX_LINUX_PAYLOAD_AUTHORITY_BYTES
            || bytes.is_empty()
            || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes
            || !bytes.ends_with(b"\n")
        {
            return Err(LinuxPayloadAuthorityError::InvalidLimitsOrSize);
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| LinuxPayloadAuthorityError::NonCanonical)?;
        let mut lines = text.split_terminator('\n');
        expect(
            &mut lines,
            "schema",
            &LINUX_PAYLOAD_AUTHORITY_SCHEMA.to_string(),
        )?;
        expect(&mut lines, "route", LINUX_PAYLOAD_ROUTE)?;
        expect(&mut lines, "host", LINUX_PAYLOAD_HOST)?;
        expect(
            &mut lines,
            "engine_protocol",
            &LINUX_PAYLOAD_ENGINE_PROTOCOL.to_string(),
        )?;
        let authority = Self {
            toolchain_manifest: witness(
                &mut lines,
                "toolchain_manifest_sha256",
                "toolchain_manifest_bytes",
            )?,
            frontend_engine: witness(
                &mut lines,
                "frontend_engine_sha256",
                "frontend_engine_bytes",
            )?,
        };
        if lines.next().is_some() {
            return Err(LinuxPayloadAuthorityError::NonCanonical);
        }
        authority.validate()?;
        if authority.encode_canonical() != bytes {
            return Err(LinuxPayloadAuthorityError::NonCanonical);
        }
        check_cancelled(is_cancelled)?;
        Ok(authority)
    }

    fn validate(&self) -> Result<(), LinuxPayloadAuthorityError> {
        if self.toolchain_manifest.bytes == 0
            || self.toolchain_manifest.bytes > ToolchainDecodeLimits::standard().bytes
            || self.frontend_engine.bytes == 0
            || self.frontend_engine.bytes > MAX_LINUX_FRONTEND_ENGINE_BYTES
            || self
                .toolchain_manifest
                .digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self
                .frontend_engine
                .digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(LinuxPayloadAuthorityError::InvalidMeasurement);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxPayloadAuthorityError {
    Cancelled,
    InvalidLimitsOrSize,
    InvalidToolchainManifest,
    InvalidHost,
    InvalidFrontend,
    InvalidMeasurement,
    NonCanonical,
}

impl fmt::Display for LinuxPayloadAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "Linux payload authority decoding was cancelled",
            Self::InvalidLimitsOrSize => "Linux payload authority size is out of policy",
            Self::InvalidToolchainManifest => "Linux payload authority manifest is invalid",
            Self::InvalidHost => "Linux payload authority host is invalid",
            Self::InvalidFrontend => "Linux payload authority frontend is invalid",
            Self::InvalidMeasurement => "Linux payload authority measurement is invalid",
            Self::NonCanonical => "Linux payload authority is noncanonical",
        })
    }
}

impl std::error::Error for LinuxPayloadAuthorityError {}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LinuxPayloadAuthorityError> {
    if is_cancelled() {
        Err(LinuxPayloadAuthorityError::Cancelled)
    } else {
        Ok(())
    }
}

fn expect<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
    expected: &str,
) -> Result<(), LinuxPayloadAuthorityError> {
    let line = lines
        .next()
        .ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    let (actual_key, value) = line
        .split_once('=')
        .ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    if actual_key != key || value != expected {
        return Err(LinuxPayloadAuthorityError::NonCanonical);
    }
    Ok(())
}

fn witness<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    digest_key: &str,
    bytes_key: &str,
) -> Result<LinuxPayloadFileWitness, LinuxPayloadAuthorityError> {
    let digest = value(lines, digest_key)?;
    let digest = parse_digest(digest).ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    let bytes = value(lines, bytes_key)?;
    if bytes.is_empty() || bytes.starts_with('0') {
        return Err(LinuxPayloadAuthorityError::NonCanonical);
    }
    let bytes = bytes
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    Ok(LinuxPayloadFileWitness { digest, bytes })
}

fn value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, LinuxPayloadAuthorityError> {
    let line = lines
        .next()
        .ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    let (actual_key, value) = line
        .split_once('=')
        .ok_or(LinuxPayloadAuthorityError::NonCanonical)?;
    if actual_key != key {
        return Err(LinuxPayloadAuthorityError::NonCanonical);
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

    const REPRESENTATIVE: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/representative.toml");
    const REPRESENTATIVE_AUTHORITY: &[u8] = include_bytes!(
        "../../../tests/contracts/toolchain/linux-payload-authority/v1/representative.lock"
    );

    fn digest(label: &[u8]) -> Sha256Digest {
        SoftwareSha256.sha256(label)
    }

    fn authority() -> LinuxPayloadAuthority {
        LinuxPayloadAuthority {
            toolchain_manifest: LinuxPayloadFileWitness {
                digest: digest(b"manifest"),
                bytes: 4096,
            },
            frontend_engine: LinuxPayloadFileWitness {
                digest: digest(b"engine"),
                bytes: 2_565_760,
            },
        }
    }

    #[test]
    fn canonical_round_trip_and_domain_identity_are_deterministic() {
        let authority = authority();
        let bytes = authority.encode_canonical();
        assert_eq!(
            LinuxPayloadAuthority::decode_canonical(
                &bytes,
                MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
                &|| false,
            )
            .expect("canonical authority"),
            authority
        );
        assert_eq!(authority.payload_identity(), authority.payload_identity());
        assert_ne!(authority.payload_identity(), SoftwareSha256.sha256(&bytes));
    }

    #[test]
    fn producer_derives_manifest_and_frontend_witnesses_from_canonical_linux_manifest() {
        let linux = String::from_utf8(REPRESENTATIVE.to_vec())
            .expect("representative manifest UTF-8")
            .replacen(
                "host = \"aarch64-apple-darwin\"",
                &format!("host = \"{LINUX_PAYLOAD_HOST}\""),
                1,
            );
        let authority = LinuxPayloadAuthority::from_canonical_toolchain_manifest(
            linux.as_bytes(),
            ToolchainDecodeLimits::standard(),
            &|| false,
        )
        .expect("Linux payload authority");
        assert_eq!(
            authority.toolchain_manifest(),
            LinuxPayloadFileWitness {
                digest: SoftwareSha256.sha256(linux.as_bytes()),
                bytes: linux.len() as u64,
            }
        );
        assert_ne!(authority.frontend_engine().digest, digest(b"manifest"));
        assert_eq!(authority.encode_canonical(), REPRESENTATIVE_AUTHORITY);
    }

    #[test]
    fn decoder_rejects_substitution_stale_unknown_reordering_and_noncanonical_counts() {
        let bytes = authority().encode_canonical();
        let text = String::from_utf8(bytes).expect("UTF-8 authority");
        for malformed in [
            text.replacen("schema=1", "schema=2", 1),
            text.replacen("route=linux-arm64-direct", "route=linux-arm64-appliance", 1),
            text.replacen(
                "host=aarch64-unknown-linux-musl",
                "unknown=x\nhost=aarch64-unknown-linux-musl",
                1,
            ),
            text.replacen(
                "route=linux-arm64-direct\nhost=aarch64-unknown-linux-musl",
                "host=aarch64-unknown-linux-musl\nroute=linux-arm64-direct",
                1,
            ),
            text.replacen(
                "toolchain_manifest_bytes=4096",
                "toolchain_manifest_bytes=04096",
                1,
            ),
        ] {
            assert!(matches!(
                LinuxPayloadAuthority::decode_canonical(
                    malformed.as_bytes(),
                    MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
                    &|| false,
                ),
                Err(LinuxPayloadAuthorityError::NonCanonical)
                    | Err(LinuxPayloadAuthorityError::InvalidMeasurement)
            ));
        }
        let substituted = text.replacen(
            &format!("frontend_engine_sha256={}", digest(b"engine").to_hex()),
            &format!("frontend_engine_sha256={}", digest(b"other").to_hex()),
            1,
        );
        let substituted = LinuxPayloadAuthority::decode_canonical(
            substituted.as_bytes(),
            MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
            &|| false,
        )
        .expect("substitution remains a distinct canonical authority");
        assert_ne!(
            substituted.payload_identity(),
            authority().payload_identity()
        );
    }

    #[test]
    fn decoder_enforces_exact_measurement_and_encoded_byte_limits() {
        let text = String::from_utf8(authority().encode_canonical()).expect("UTF-8 authority");
        let manifest_over = text.replacen(
            "toolchain_manifest_bytes=4096",
            &format!(
                "toolchain_manifest_bytes={}",
                ToolchainDecodeLimits::standard().bytes + 1
            ),
            1,
        );
        let frontend_over = text.replacen(
            "frontend_engine_bytes=2565760",
            &format!(
                "frontend_engine_bytes={}",
                MAX_LINUX_FRONTEND_ENGINE_BYTES + 1
            ),
            1,
        );
        for malformed in [manifest_over, frontend_over] {
            assert!(matches!(
                LinuxPayloadAuthority::decode_canonical(
                    malformed.as_bytes(),
                    MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
                    &|| false,
                ),
                Err(LinuxPayloadAuthorityError::InvalidMeasurement)
            ));
        }
        let exact = text
            .replacen(
                "toolchain_manifest_bytes=4096",
                &format!(
                    "toolchain_manifest_bytes={}",
                    ToolchainDecodeLimits::standard().bytes
                ),
                1,
            )
            .replacen(
                "frontend_engine_bytes=2565760",
                &format!("frontend_engine_bytes={MAX_LINUX_FRONTEND_ENGINE_BYTES}"),
                1,
            );
        LinuxPayloadAuthority::decode_canonical(
            exact.as_bytes(),
            MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
            &|| false,
        )
        .expect("exact maximum witnesses");
        let bytes = authority().encode_canonical();
        assert!(matches!(
            LinuxPayloadAuthority::decode_canonical(&bytes, bytes.len() as u64 - 1, &|| false),
            Err(LinuxPayloadAuthorityError::InvalidLimitsOrSize)
        ));
    }

    #[test]
    fn decoder_observes_cancellation_before_and_after_decode() {
        let bytes = authority().encode_canonical();
        assert!(matches!(
            LinuxPayloadAuthority::decode_canonical(
                &bytes,
                MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
                &|| true,
            ),
            Err(LinuxPayloadAuthorityError::Cancelled)
        ));
        let polls = Cell::new(0_u8);
        assert!(matches!(
            LinuxPayloadAuthority::decode_canonical(
                &bytes,
                MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
                &|| {
                    let current = polls.get();
                    polls.set(current + 1);
                    current > 0
                },
            ),
            Err(LinuxPayloadAuthorityError::Cancelled)
        ));
        assert!(polls.get() >= 2);
    }
}
