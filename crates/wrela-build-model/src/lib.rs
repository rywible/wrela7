//! Pure build identity and profile policy shared by compiler process boundaries.
//!
//! This crate owns data, validation, and stable scalar identities. It performs
//! no filesystem access, hashing, compilation, target loading, or process I/O.

#![forbid(unsafe_code)]

use std::fmt;

/// Version of [`BuildProfile::canonical_bytes`]. Increment for any byte-level
/// change, including a field addition, field reordering, or tag reassignment.
pub const PROFILE_ENCODING_VERSION: u32 = 2;
/// Maximum UTF-8 byte length of any profile/target atom.
pub const MAX_PROFILE_ATOM_BYTES: usize = 4096;
const PROFILE_MAGIC: &[u8; 8] = b"WRELPRF\0";

/// Language revision whose semantics the build must implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageRevision {
    /// The complete revision described by `docs/language`.
    Design0_1,
}

impl LanguageRevision {
    /// Stable spelling recorded in WIR, reports, and manifests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Design0_1 => "0.1-design",
        }
    }
}

/// Validated identity of one target package.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetIdentity(String);

impl TargetIdentity {
    /// Construct an identity suitable for manifests and serialized artifacts.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_atom(&value).map_err(IdentityError::InvalidTarget)?;
        Ok(Self(value))
    }

    /// Revision 0.1 QEMU `virt` AArch64 UEFI target.
    #[must_use]
    pub fn aarch64_qemu_virt_uefi() -> Self {
        Self("aarch64-qemu-virt-uefi".to_owned())
    }

    /// Stable manifest spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// SHA-256 digest of a declared build input or canonical contract encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wrap bytes produced by the toolchain's declared SHA-256 implementation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal form used in reports and manifests.
    #[must_use]
    pub fn to_hex(self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

/// Broad compilation intent. Safety semantics never vary by this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildMode {
    /// Favor compiler latency and development diagnostics.
    Development,
    /// Favor final image performance and footprint.
    Release,
}

/// Deterministic external-event behavior requested by the image profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordingMode {
    /// Normal execution with no deterministic event log.
    Disabled,
    /// Record every specified nondeterministic input and output digest.
    Record,
    /// Consume a previously recorded event stream and reject divergence.
    Replay,
}

/// Backend optimization policy. It cannot disable language safety checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptimizationLevel {
    /// Minimal semantics-preserving lowering for compiler development.
    None,
    /// Balanced optimization for interactive development.
    Development,
    /// Optimize runtime throughput and latency.
    Performance,
    /// Optimize final image footprint.
    Size,
}

/// Finite compile-time evaluator resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComptimeLimits {
    /// Maximum evaluator steps per build.
    pub steps: u64,
    /// Maximum evaluator-owned bytes.
    pub memory_bytes: u64,
    /// Maximum compile-time call depth.
    pub call_depth: u32,
}

/// Whole-image memory ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryLimits {
    /// Maximum emitted static and zero-fill reservation.
    pub static_bytes: u64,
    /// Maximum proved runtime memory peak.
    pub peak_bytes: u64,
    /// Maximum deterministic record/replay storage.
    pub event_log_bytes: u64,
}

/// Target assumptions used by DMA proof checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DmaPolicy {
    /// Whether the target contract guarantees coherent DMA.
    pub coherent: bool,
    /// Whether every device-visible region must be IOMMU isolated.
    pub require_iommu: bool,
}

/// Finite failure-recovery resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryPolicy {
    /// Maximum target-declared device reset time.
    pub reset_timeout_ns: u64,
    /// Maximum bytes that may remain quarantined concurrently.
    pub quarantine_bytes: u64,
}

/// Reproducible backend optimization inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OptimizationPolicy {
    /// Optimization strategy.
    pub level: OptimizationLevel,
    /// Declared profile-guidance input, when used.
    pub profile_data: Option<Sha256Digest>,
}

/// Diagnostic behavior that does not weaken language safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiagnosticPolicy {
    /// Apply sealed-deployment Unicode and hardening diagnostics.
    pub sealed_deployment: bool,
    /// Promote advisory warnings to build errors.
    pub warnings_as_errors: bool,
    /// Include target-supported development watchdogs.
    pub watchdogs: bool,
}

/// Complete named build profile consumed by semantic and backend phases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BuildProfile {
    /// Human-readable profile name recorded in the report.
    pub name: String,
    /// Compilation intent.
    pub mode: BuildMode,
    /// Compile-time evaluator bounds.
    pub comptime: ComptimeLimits,
    /// Image memory ceilings.
    pub memory: MemoryLimits,
    /// DMA assumptions.
    pub dma: DmaPolicy,
    /// Recovery bounds.
    pub recovery: RecoveryPolicy,
    /// Record/replay behavior.
    pub recording: RecordingMode,
    /// Backend policy and declared guidance inputs.
    pub optimization: OptimizationPolicy,
    /// Non-semantic diagnostic policy.
    pub diagnostics: DiagnosticPolicy,
}

/// Field defaults applied when a manifest `[[profile]]` block omits a key.
///
/// `name` and `mode` are the only keys a profile block must state explicitly;
/// every other field is optional and falls back to the matching value here.
/// These are revision 0.1's specified example defaults (see `docs/language`,
/// owned by another workstream) and must not drift from it silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileDefaults {
    pub comptime: ComptimeLimits,
    pub memory: MemoryLimits,
    pub dma: DmaPolicy,
    pub recovery: RecoveryPolicy,
    pub recording: RecordingMode,
    pub optimization_level: OptimizationLevel,
    pub diagnostics: DiagnosticPolicy,
}

/// The one canonical default table. Codecs read this directly instead of
/// duplicating the constants; `BuildProfile::with_defaults` applies it.
pub const PROFILE_DEFAULTS: ProfileDefaults = ProfileDefaults {
    comptime: ComptimeLimits {
        steps: 10_000_000,
        memory_bytes: 64 * 1024 * 1024,
        call_depth: 256,
    },
    memory: MemoryLimits {
        static_bytes: 256 * 1024 * 1024,
        peak_bytes: 512 * 1024 * 1024,
        event_log_bytes: 0,
    },
    // Conservative for the AArch64 QEMU `virt` reference machine.
    dma: DmaPolicy {
        coherent: false,
        require_iommu: false,
    },
    recovery: RecoveryPolicy {
        reset_timeout_ns: 5_000_000_000,
        quarantine_bytes: 16 * 1024 * 1024,
    },
    recording: RecordingMode::Disabled,
    optimization_level: OptimizationLevel::Development,
    diagnostics: DiagnosticPolicy {
        sealed_deployment: false,
        warnings_as_errors: false,
        watchdogs: true,
    },
};

impl BuildProfile {
    /// Build a profile from an explicit `name`/`mode` plus every default
    /// field from [`PROFILE_DEFAULTS`]. A manifest `[[profile]]` block that
    /// declares only overrides decodes by starting here and replacing the
    /// keys it states.
    #[must_use]
    pub fn with_defaults(name: String, mode: BuildMode) -> Self {
        let defaults = PROFILE_DEFAULTS;
        Self {
            name,
            mode,
            comptime: defaults.comptime,
            memory: defaults.memory,
            dma: defaults.dma,
            recovery: defaults.recovery,
            recording: defaults.recording,
            optimization: OptimizationPolicy {
                level: defaults.optimization_level,
                profile_data: None,
            },
            diagnostics: defaults.diagnostics,
        }
    }

    /// Reference development profile used by layer contract tests.
    #[must_use]
    pub fn development() -> Self {
        Self::with_defaults("development".to_owned(), BuildMode::Development)
    }

    /// Reject incomplete, contradictory, or nondeterministically ordered policy.
    pub fn validate(&self) -> Result<(), ProfileError> {
        validate_atom(&self.name).map_err(ProfileError::InvalidName)?;
        if self.comptime.steps == 0
            || self.comptime.memory_bytes == 0
            || self.comptime.call_depth == 0
        {
            return Err(ProfileError::ZeroComptimeLimit);
        }
        if self.memory.static_bytes == 0 || self.memory.peak_bytes < self.memory.static_bytes {
            return Err(ProfileError::InvalidMemoryLimits);
        }
        if self.recovery.reset_timeout_ns == 0 {
            return Err(ProfileError::ZeroResetTimeout);
        }
        if self.recording != RecordingMode::Disabled && self.memory.event_log_bytes == 0 {
            return Err(ProfileError::MissingEventLogCapacity);
        }
        Ok(())
    }

    /// Produce the sole byte sequence hashed into [`BuildIdentity::profile`].
    ///
    /// The encoding is self-identifying, little-endian, length-prefixed, and
    /// contains every policy field. It is separate from any transport format,
    /// so changing the backend protocol cannot silently change build identity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PROFILE_MAGIC);
        push_u32(&mut bytes, PROFILE_ENCODING_VERSION);
        push_string(&mut bytes, &self.name);
        push_u8(&mut bytes, mode_tag(self.mode));
        push_u64(&mut bytes, self.comptime.steps);
        push_u64(&mut bytes, self.comptime.memory_bytes);
        push_u32(&mut bytes, self.comptime.call_depth);
        push_u64(&mut bytes, self.memory.static_bytes);
        push_u64(&mut bytes, self.memory.peak_bytes);
        push_u64(&mut bytes, self.memory.event_log_bytes);
        push_bool(&mut bytes, self.dma.coherent);
        push_bool(&mut bytes, self.dma.require_iommu);
        push_u64(&mut bytes, self.recovery.reset_timeout_ns);
        push_u64(&mut bytes, self.recovery.quarantine_bytes);
        push_u8(&mut bytes, recording_tag(self.recording));
        push_u8(&mut bytes, optimization_tag(self.optimization.level));
        match self.optimization.profile_data {
            Some(digest) => {
                push_bool(&mut bytes, true);
                bytes.extend_from_slice(digest.as_bytes());
            }
            None => push_bool(&mut bytes, false),
        }
        push_bool(&mut bytes, self.diagnostics.sealed_deployment);
        push_bool(&mut bytes, self.diagnostics.warnings_as_errors);
        push_bool(&mut bytes, self.diagnostics.watchdogs);
        Ok(bytes)
    }
}

/// Content-addressed identity binding every input that may affect one build
/// request. Multiple named artifacts may be emitted by a test request, but the
/// canonical request digest binds their selected roots, test filter, intent,
/// and order; an artifact name/group remains part of its cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BuildIdentity {
    /// Compiler executable/build provenance.
    pub compiler: Sha256Digest,
    /// Language semantics revision.
    pub language: LanguageRevision,
    /// Selected target package identity.
    pub target: TargetIdentity,
    /// Exact target package contents.
    pub target_package: Sha256Digest,
    /// Exact standard-library closure.
    pub standard_library: Sha256Digest,
    /// Complete package/source input graph.
    pub source_graph: Sha256Digest,
    /// Canonical command selection: image root, build/test intent, selected
    /// tests or filter, and every other artifact-affecting request option.
    pub request: Sha256Digest,
    /// Canonical validated build-profile encoding.
    pub profile: Sha256Digest,
}

/// Validated identity and concrete profile for one build session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildConfiguration {
    /// Reproducibility identity embedded in WIR and reports.
    pub identity: BuildIdentity,
    /// Policy whose canonical digest must equal `identity.profile`.
    pub profile: BuildProfile,
}

impl BuildConfiguration {
    /// Validate policy shape. Digest computation and equality are owned by the
    /// driver because this pure model crate deliberately contains no hasher.
    pub fn validate(&self) -> Result<(), ProfileError> {
        self.profile.validate()
    }
}

/// Build configuration whose canonical profile digest has been computed by a
/// declared SHA-256 capability and matched to `BuildIdentity::profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBuildConfiguration(BuildConfiguration);

impl ValidatedBuildConfiguration {
    #[must_use]
    pub fn as_configuration(&self) -> &BuildConfiguration {
        &self.0
    }

    #[must_use]
    pub fn identity(&self) -> &BuildIdentity {
        &self.0.identity
    }

    #[must_use]
    pub fn profile(&self) -> &BuildProfile {
        &self.0.profile
    }

    #[must_use]
    pub fn into_configuration(self) -> BuildConfiguration {
        self.0
    }
}

impl std::ops::Deref for ValidatedBuildConfiguration {
    type Target = BuildConfiguration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Seal an assembled configuration using the caller-observed SHA-256 of
/// `configuration.profile.canonical_bytes()`.
pub fn seal_build_configuration(
    configuration: BuildConfiguration,
    observed_profile_digest: Sha256Digest,
) -> Result<ValidatedBuildConfiguration, ProfileError> {
    configuration.validate()?;
    if configuration.identity.profile != observed_profile_digest {
        return Err(ProfileError::ProfileDigestMismatch {
            expected: configuration.identity.profile,
            actual: observed_profile_digest,
        });
    }
    if [
        configuration.identity.compiler,
        configuration.identity.target_package,
        configuration.identity.standard_library,
        configuration.identity.source_graph,
        configuration.identity.request,
        configuration.identity.profile,
    ]
    .iter()
    .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err(ProfileError::ZeroBuildDigest);
    }
    Ok(ValidatedBuildConfiguration(configuration))
}

/// Invalid stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Target identity is empty, contains controls, whitespace, or separators.
    InvalidTarget(AtomError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(error) => write!(formatter, "invalid target identity: {error}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Invalid build profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    InvalidName(AtomError),
    ZeroComptimeLimit,
    InvalidMemoryLimits,
    ZeroResetTimeout,
    MissingEventLogCapacity,
    ProfileDigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    ZeroBuildDigest,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(error) => write!(formatter, "invalid profile name: {error}"),
            Self::ZeroComptimeLimit => formatter.write_str("comptime limits must be nonzero"),
            Self::InvalidMemoryLimits => {
                formatter.write_str("peak memory must be nonzero and at least static memory")
            }
            Self::ZeroResetTimeout => formatter.write_str("reset timeout must be nonzero"),
            Self::MissingEventLogCapacity => {
                formatter.write_str("record/replay requires nonzero event-log capacity")
            }
            Self::ProfileDigestMismatch { expected, actual } => write!(
                formatter,
                "profile digest mismatch: expected {}, got {}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::ZeroBuildDigest => {
                formatter.write_str("build identity contains an all-zero digest")
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// Reason a manifest atom is not canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomError {
    Empty,
    TooLong { length: usize, maximum: usize },
    ForbiddenCharacter(char),
}

impl fmt::Display for AtomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value is empty"),
            Self::TooLong { length, maximum } => {
                write!(formatter, "value is {length} bytes; maximum is {maximum}")
            }
            Self::ForbiddenCharacter(character) => {
                write!(formatter, "forbidden character {character:?}")
            }
        }
    }
}

fn validate_atom(value: &str) -> Result<(), AtomError> {
    if value.is_empty() {
        return Err(AtomError::Empty);
    }
    if value.len() > MAX_PROFILE_ATOM_BYTES {
        return Err(AtomError::TooLong {
            length: value.len(),
            maximum: MAX_PROFILE_ATOM_BYTES,
        });
    }
    if let Some(character) = value.chars().find(|character| {
        character.is_control() || character.is_whitespace() || "\\/:".contains(*character)
    }) {
        return Err(AtomError::ForbiddenCharacter(character));
    }
    Ok(())
}

fn mode_tag(value: BuildMode) -> u8 {
    match value {
        BuildMode::Development => 1,
        BuildMode::Release => 2,
    }
}

fn recording_tag(value: RecordingMode) -> u8 {
    match value {
        RecordingMode::Disabled => 0,
        RecordingMode::Record => 1,
        RecordingMode::Replay => 2,
    }
}

fn optimization_tag(value: OptimizationLevel) -> u8 {
    match value {
        OptimizationLevel::None => 0,
        OptimizationLevel::Development => 1,
        OptimizationLevel::Performance => 2,
        OptimizationLevel::Size => 3,
    }
}

fn push_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn push_bool(bytes: &mut Vec<u8>, value: bool) {
    push_u8(bytes, u8::from(value));
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    push_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{BuildProfile, PROFILE_ENCODING_VERSION, Sha256Digest, TargetIdentity};

    #[test]
    fn reference_profile_is_valid() {
        BuildProfile::development()
            .validate()
            .expect("valid profile");
    }

    #[test]
    fn digests_render_canonically() {
        let digest = Sha256Digest::from_bytes([0xab; 32]);
        assert_eq!(digest.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn target_identity_rejects_paths() {
        assert!(TargetIdentity::new("../target").is_err());
    }

    #[test]
    fn profile_encoding_is_versioned_and_sensitive_to_every_policy_change() {
        let profile = BuildProfile::development();
        let encoded = profile.canonical_bytes().expect("canonical profile");
        assert_eq!(&encoded[..8], b"WRELPRF\0");
        assert_eq!(
            u32::from_le_bytes(encoded[8..12].try_into().expect("version bytes")),
            PROFILE_ENCODING_VERSION
        );

        let mut changed = profile;
        changed.diagnostics.watchdogs = false;
        assert_ne!(
            encoded,
            changed
                .canonical_bytes()
                .expect("changed canonical profile")
        );
    }
}
