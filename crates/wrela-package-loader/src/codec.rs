use std::char;

use toml::Spanned;
use toml::de::{DeArray, DeInteger, DeTable, DeValue};
use wrela_build_model::{
    BuildMode, BuildProfile, ComptimeLimits, DiagnosticPolicy, DmaPolicy, LanguageRevision,
    MemoryLimits, OptimizationLevel, OptimizationPolicy, RecordingMode, RecoveryPolicy,
    Sha256Digest, TargetIdentity,
};
use wrela_package::{
    DependencyAlias, ImageDeclaration, ImageTestDeclaration, LOCKFILE_SCHEMA_VERSION,
    LockedDependency, LockedPackage, Lockfile, MANIFEST_SCHEMA_VERSION, ManifestDependency,
    ModulePath, PackageIdentity, PackageLocator, PackageManifest, PackageName, PackageVersion,
};

use crate::{DecodeError, LockfileCodecLimits, ManifestCodecLimits, PackageCodec};

const CANCELLATION_POLL_BYTES: usize = 4096;
const MAX_MANIFEST_TOML_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCKFILE_TOML_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 512;
const MAX_ERROR_FIELD_BYTES: usize = 256;

/// TOML 1.0 semantic codec for `wrela.toml` and generated `wrela.lock`.
///
/// Syntax follows <https://toml.io/en/v1.0.0/>. Exact base versions are pinned
/// in `Cargo.toml`, while the spec-bearing resolved identities are audited
/// against `Cargo.lock` by `xtask`; the parser's default 80-level recursion
/// guard remains active because `unbounded` is deliberately not enabled. The upstream
/// parse call cannot observe this API's cancellation callback, so input is
/// polled first and capped at 16 MiB; DOM projection, decoded strings, and
/// integer conversion resume cooperative polling after that bounded region.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalPackageCodec;

impl CanonicalPackageCodec {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PackageCodec for CanonicalPackageCodec {
    fn decode_manifest(
        &self,
        bytes: &[u8],
        limits: ManifestCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageManifest, DecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        let limits = bounded_manifest_limits(limits);
        let source = prepare_input(
            bytes,
            limits.bytes,
            MAX_MANIFEST_TOML_BYTES,
            "manifest TOML bytes",
            is_cancelled,
        )?;
        let document = parse_document(source)?;
        check_cancelled(is_cancelled)?;
        let manifest = project_manifest(document.get_ref(), limits, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        Ok(manifest)
    }

    fn decode_lockfile(
        &self,
        bytes: &[u8],
        limits: LockfileCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Lockfile, DecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        let limits = bounded_lockfile_limits(limits);
        let source = prepare_input(
            bytes,
            limits.bytes,
            MAX_LOCKFILE_TOML_BYTES,
            "lockfile TOML bytes",
            is_cancelled,
        )?;
        let document = parse_document(source)?;
        check_cancelled(is_cancelled)?;
        let lockfile = project_lockfile(document.get_ref(), limits, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        Ok(lockfile)
    }

    fn canonical_manifest(
        &self,
        manifest: &PackageManifest,
        limits: ManifestCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        let limits = bounded_manifest_limits(limits);
        if manifest.schema != MANIFEST_SCHEMA_VERSION {
            return Err(DecodeError::UnsupportedSchema(manifest.schema));
        }
        validate_manifest_resources(manifest, limits, is_cancelled)?;
        manifest
            .validate()
            .map_err(|error| noncanonical(&error.to_string()))?;
        encode_manifest(
            manifest,
            limits.bytes.min(MAX_MANIFEST_TOML_BYTES),
            is_cancelled,
        )
    }

    fn canonical_lockfile(
        &self,
        lockfile: &Lockfile,
        limits: LockfileCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        let limits = bounded_lockfile_limits(limits);
        if lockfile.schema != LOCKFILE_SCHEMA_VERSION {
            return Err(DecodeError::UnsupportedSchema(lockfile.schema));
        }
        validate_lockfile_resources(lockfile, limits, is_cancelled)?;
        lockfile
            .validate()
            .map_err(|error| noncanonical(&error.to_string()))?;
        encode_lockfile(
            lockfile,
            limits.bytes.min(MAX_LOCKFILE_TOML_BYTES),
            is_cancelled,
        )
    }
}

fn bounded_manifest_limits(mut limits: ManifestCodecLimits) -> ManifestCodecLimits {
    limits.bytes = limits.bytes.min(MAX_MANIFEST_TOML_BYTES);
    limits.string_bytes = limits.string_bytes.min(MAX_MANIFEST_TOML_BYTES);
    let entry_limit = u32::try_from(MAX_MANIFEST_TOML_BYTES).unwrap_or(u32::MAX);
    limits.modules = limits.modules.min(entry_limit);
    limits.dependencies = limits.dependencies.min(entry_limit);
    limits.profiles = limits.profiles.min(entry_limit);
    limits.images = limits.images.min(entry_limit);
    limits.image_tests = limits.image_tests.min(entry_limit);
    limits
}

fn bounded_lockfile_limits(mut limits: LockfileCodecLimits) -> LockfileCodecLimits {
    limits.bytes = limits.bytes.min(MAX_LOCKFILE_TOML_BYTES);
    limits.string_bytes = limits.string_bytes.min(MAX_LOCKFILE_TOML_BYTES);
    let entry_limit = u32::try_from(MAX_LOCKFILE_TOML_BYTES).unwrap_or(u32::MAX);
    limits.packages = limits.packages.min(entry_limit);
    limits.dependencies = limits.dependencies.min(entry_limit);
    limits
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DecodeError> {
    if is_cancelled() {
        Err(DecodeError::Cancelled)
    } else {
        Ok(())
    }
}

fn prepare_input<'a>(
    bytes: &'a [u8],
    request_limit: u64,
    absolute_limit: u64,
    resource: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, DecodeError> {
    let effective_limit = request_limit.min(absolute_limit);
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > effective_limit {
        return Err(resource_limit(resource, effective_limit));
    }
    for chunk in bytes.chunks(CANCELLATION_POLL_BYTES) {
        check_cancelled(is_cancelled)?;
        let _ = chunk;
    }
    check_cancelled(is_cancelled)?;
    std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
}

fn parse_document(source: &str) -> Result<Spanned<DeTable<'_>>, DecodeError> {
    DeTable::parse(source).map_err(map_toml_error)
}

fn map_toml_error(error: toml::de::Error) -> DecodeError {
    let byte_offset = error.span().map_or(0, |span| span.start);
    if error.message().contains("duplicate key") {
        match bounded_copy("TOML duplicate key", MAX_ERROR_FIELD_BYTES) {
            Ok(field) => DecodeError::DuplicateKey(field),
            Err(error) => error,
        }
    } else {
        malformed(byte_offset, error.message())
    }
}

fn malformed(byte_offset: usize, message: &str) -> DecodeError {
    match bounded_copy(message, MAX_ERROR_MESSAGE_BYTES) {
        Ok(message) => DecodeError::Malformed {
            byte_offset,
            message,
        },
        Err(error) => error,
    }
}

fn noncanonical(message: &str) -> DecodeError {
    match bounded_copy(message, MAX_ERROR_MESSAGE_BYTES) {
        Ok(message) => DecodeError::NonCanonical(message),
        Err(error) => error,
    }
}

fn bounded_copy(value: &str, maximum_bytes: usize) -> Result<String, DecodeError> {
    let truncated = value.len() > maximum_bytes;
    let append_marker = truncated && maximum_bytes >= '…'.len_utf8();
    let payload_limit = if append_marker {
        maximum_bytes - '…'.len_utf8()
    } else {
        maximum_bytes
    };
    let mut end = 0usize;
    for (index, character) in value.char_indices() {
        let next = index.saturating_add(character.len_utf8());
        if next > payload_limit {
            break;
        }
        end = next;
    }
    if value.is_empty() {
        end = 0;
    } else if !truncated && value.len() <= payload_limit {
        end = value.len();
    }
    let suffix = usize::from(append_marker) * '…'.len_utf8();
    let capacity = end.checked_add(suffix).ok_or_else(|| {
        resource_limit(
            "package TOML diagnostic bytes",
            u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
        )
    })?;
    let mut output = String::new();
    output.try_reserve_exact(capacity).map_err(|_| {
        resource_limit(
            "package TOML diagnostic bytes",
            u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
        )
    })?;
    output.push_str(&value[..end]);
    if append_marker {
        output.push('…');
    }
    Ok(output)
}

fn qualified_field(prefix: &str, key: &str) -> Result<String, DecodeError> {
    let mut prefix_bytes = prefix.len().min(MAX_ERROR_FIELD_BYTES);
    while !prefix.is_char_boundary(prefix_bytes) {
        prefix_bytes = prefix_bytes.saturating_sub(1);
    }
    let separator = usize::from(prefix_bytes != 0 && prefix_bytes < MAX_ERROR_FIELD_BYTES);
    let key_limit = MAX_ERROR_FIELD_BYTES
        .saturating_sub(prefix_bytes)
        .saturating_sub(separator);
    let key = bounded_copy(key, key_limit)?;
    let capacity = prefix_bytes
        .checked_add(separator)
        .and_then(|bytes| bytes.checked_add(key.len()))
        .ok_or_else(|| {
            resource_limit(
                "package TOML diagnostic bytes",
                u64::try_from(MAX_ERROR_FIELD_BYTES).unwrap_or(u64::MAX),
            )
        })?;
    let mut output = String::new();
    output.try_reserve_exact(capacity).map_err(|_| {
        resource_limit(
            "package TOML diagnostic bytes",
            u64::try_from(MAX_ERROR_FIELD_BYTES).unwrap_or(u64::MAX),
        )
    })?;
    output.push_str(&prefix[..prefix_bytes]);
    if separator != 0 {
        output.push('.');
    }
    output.push_str(&key);
    Ok(output)
}

fn resource_limit(resource: &'static str, limit: u64) -> DecodeError {
    DecodeError::ResourceLimit { resource, limit }
}

fn check_count(resource: &'static str, count: usize, limit: u32) -> Result<(), DecodeError> {
    if u64::try_from(count).unwrap_or(u64::MAX) > u64::from(limit) {
        Err(resource_limit(resource, u64::from(limit)))
    } else {
        Ok(())
    }
}

fn reserve<T>(
    values: &mut Vec<T>,
    additional: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), DecodeError> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| resource_limit(resource, limit))
}

struct StringBudget {
    used: u64,
    limit: u64,
}

impl StringBudget {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn add(&mut self, bytes: usize) -> Result<(), DecodeError> {
        self.used = self
            .used
            .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
            .ok_or_else(|| resource_limit("package TOML string bytes", self.limit))?;
        if self.used > self.limit {
            Err(resource_limit("package TOML string bytes", self.limit))
        } else {
            Ok(())
        }
    }

    fn account(&mut self, value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<(), DecodeError> {
        self.add(value.len())?;
        for chunk in value.as_bytes().chunks(CANCELLATION_POLL_BYTES) {
            check_cancelled(is_cancelled)?;
            let _ = chunk;
        }
        Ok(())
    }

    fn copy(
        &mut self,
        value: &str,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<String, DecodeError> {
        self.account(value, is_cancelled)?;
        copy_projected_string(value, self.limit)
    }
}

fn copy_projected_string(value: &str, limit: u64) -> Result<String, DecodeError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| resource_limit("package TOML projected string bytes", limit))?;
    output.push_str(value);
    Ok(output)
}

fn missing(path: &'static str) -> DecodeError {
    DecodeError::MissingField(path)
}

fn unsupported(field: &'static str, expected: &'static str) -> DecodeError {
    DecodeError::UnsupportedValue { field, expected }
}

fn check_allowed_fields(
    table: &DeTable<'_>,
    prefix: &'static str,
    allowed: &[&str],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    for (key, _) in table {
        check_cancelled(is_cancelled)?;
        let key: &str = key.get_ref();
        if !allowed.contains(&key) {
            return Err(DecodeError::UnknownField(qualified_field(prefix, key)?));
        }
    }
    Ok(())
}

fn required_value<'a, 'i>(
    table: &'a DeTable<'i>,
    key: &str,
    field: &'static str,
) -> Result<&'a Spanned<DeValue<'i>>, DecodeError> {
    table.get(key).ok_or_else(|| missing(field))
}

fn required_table<'a, 'i>(
    table: &'a DeTable<'i>,
    key: &str,
    field: &'static str,
) -> Result<&'a DeTable<'i>, DecodeError> {
    match required_value(table, key, field)?.get_ref() {
        DeValue::Table(value) => Ok(value),
        _ => Err(unsupported(field, "table")),
    }
}

fn optional_array<'a, 'i>(
    table: &'a DeTable<'i>,
    key: &str,
    field: &'static str,
) -> Result<Option<&'a DeArray<'i>>, DecodeError> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => match value.get_ref() {
            DeValue::Array(value) => Ok(Some(value)),
            _ => Err(unsupported(field, "array of tables")),
        },
    }
}

fn table_item<'a, 'i>(
    value: &'a Spanned<DeValue<'i>>,
    field: &'static str,
) -> Result<&'a DeTable<'i>, DecodeError> {
    match value.get_ref() {
        DeValue::Table(value) => Ok(value),
        _ => Err(unsupported(field, "array of tables")),
    }
}

fn string_value<'a, 'i>(
    value: &'a Spanned<DeValue<'i>>,
    field: &'static str,
) -> Result<&'a str, DecodeError> {
    match value.get_ref() {
        DeValue::String(value) => Ok(value.as_ref()),
        _ => Err(unsupported(field, "string")),
    }
}

fn required_text(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, DecodeError> {
    let value = string_value(required_value(table, key, field)?, field)?;
    budget.copy(value, is_cancelled)
}

fn optional_text(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<String>, DecodeError> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let value = string_value(value, field)?;
    budget.copy(value, is_cancelled).map(Some)
}

fn optional_bool(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
) -> Result<Option<bool>, DecodeError> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => match value.get_ref() {
            DeValue::Boolean(value) => Ok(Some(*value)),
            _ => Err(unsupported(field, "boolean")),
        },
    }
}

fn integer_value(
    value: &Spanned<DeValue<'_>>,
    field: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, DecodeError> {
    let DeValue::Integer(integer) = value.get_ref() else {
        return Err(unsupported(field, "nonnegative signed-64 TOML integer"));
    };
    parse_integer(integer, value.span().start, is_cancelled)
}

fn parse_integer(
    integer: &DeInteger<'_>,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, DecodeError> {
    let spelling = integer.as_str();
    if integer.radix() != 10 && (spelling.starts_with('+') || spelling.starts_with('-')) {
        return Err(malformed(
            byte_offset,
            "nondecimal TOML integers cannot have a sign",
        ));
    }
    let (negative, digits) = match spelling.as_bytes().first() {
        Some(b'+') => (false, &spelling.as_bytes()[1..]),
        Some(b'-') => (true, &spelling.as_bytes()[1..]),
        _ => (false, spelling.as_bytes()),
    };
    if digits.is_empty() {
        return Err(malformed(byte_offset, "TOML integer has no digits"));
    }
    let maximum = if negative {
        1u64 << 63
    } else {
        u64::try_from(i64::MAX).unwrap_or(u64::MAX)
    };
    let mut parsed = 0u64;
    for (index, byte) in digits.iter().copied().enumerate() {
        if index % CANCELLATION_POLL_BYTES == 0 {
            check_cancelled(is_cancelled)?;
        }
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => integer.radix(),
        };
        if digit >= integer.radix() {
            return Err(malformed(byte_offset, "invalid TOML integer digit"));
        }
        parsed = parsed
            .checked_mul(u64::from(integer.radix()))
            .and_then(|value| value.checked_add(u64::from(digit)))
            .filter(|value| *value <= maximum)
            .ok_or_else(|| {
                malformed(
                    byte_offset,
                    "TOML integer is outside the signed 64-bit range",
                )
            })?;
    }
    check_cancelled(is_cancelled)?;
    if negative && parsed != 0 {
        Err(malformed(
            byte_offset,
            "package TOML integer must be nonnegative",
        ))
    } else {
        Ok(parsed)
    }
}

fn required_u64(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, DecodeError> {
    integer_value(required_value(table, key, field)?, field, is_cancelled)
}

fn optional_u64(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u64>, DecodeError> {
    table
        .get(key)
        .map(|value| integer_value(value, field, is_cancelled))
        .transpose()
}

fn required_u32(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u32, DecodeError> {
    u32::try_from(required_u64(table, key, field, is_cancelled)?).map_err(|_| {
        malformed(
            table.get(key).map_or(0, |value| value.span().start),
            "integer does not fit u32",
        )
    })
}

fn optional_u32(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u32>, DecodeError> {
    let Some(value) = optional_u64(table, key, field, is_cancelled)? else {
        return Ok(None);
    };
    u32::try_from(value).map(Some).map_err(|_| {
        malformed(
            table.get(key).map_or(0, |value| value.span().start),
            "integer does not fit u32",
        )
    })
}

fn required_digest(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, DecodeError> {
    let value = required_value(table, key, field)?;
    let text = string_value(value, field)?;
    budget.account(text, is_cancelled)?;
    parse_digest(text, value.span().start)
}

fn optional_digest(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<Sha256Digest>, DecodeError> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let text = string_value(value, field)?;
    budget.account(text, is_cancelled)?;
    parse_digest(text, value.span().start).map(Some)
}

fn parse_digest(value: &str, byte_offset: usize) -> Result<Sha256Digest, DecodeError> {
    if value.len() != 64 {
        return Err(malformed(
            byte_offset,
            "SHA-256 digest must contain 64 hexadecimal digits",
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or_else(|| {
            malformed(
                byte_offset.saturating_add(index.saturating_mul(2)),
                "invalid SHA-256 hexadecimal digit",
            )
        })?;
        let low = hex_digit(pair[1]).ok_or_else(|| {
            malformed(
                byte_offset
                    .saturating_add(index.saturating_mul(2))
                    .saturating_add(1),
                "invalid SHA-256 hexadecimal digit",
            )
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Sha256Digest::from_bytes(bytes))
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn required_package_name(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageName, DecodeError> {
    let value = required_text(table, key, field, budget, is_cancelled)?;
    let offset = table.get(key).map_or(0, |value| value.span().start);
    PackageName::new(value).map_err(|error| malformed(offset, &error.to_string()))
}

fn required_package_version(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageVersion, DecodeError> {
    let value = required_text(table, key, field, budget, is_cancelled)?;
    let offset = table.get(key).map_or(0, |value| value.span().start);
    PackageVersion::new(value).map_err(|error| malformed(offset, &error.to_string()))
}

fn required_dependency_alias(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<DependencyAlias, DecodeError> {
    let value = required_text(table, key, field, budget, is_cancelled)?;
    let offset = table.get(key).map_or(0, |value| value.span().start);
    DependencyAlias::new(value).map_err(|error| malformed(offset, &error.to_string()))
}

fn required_module_path(
    table: &DeTable<'_>,
    key: &str,
    field: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ModulePath, DecodeError> {
    let value = required_value(table, key, field)?;
    let text = string_value(value, field)?;
    budget.account(text, is_cancelled)?;
    let segment_count = text.split('.').count();
    let mut segments = Vec::new();
    reserve(
        &mut segments,
        segment_count,
        "module path segments",
        budget.limit,
    )?;
    for segment in text.split('.') {
        check_cancelled(is_cancelled)?;
        segments.push(copy_projected_string(segment, budget.limit)?);
    }
    ModulePath::new(segments).map_err(|error| malformed(value.span().start, &error.to_string()))
}

fn project_manifest(
    root: &DeTable<'_>,
    limits: ManifestCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageManifest, DecodeError> {
    check_allowed_fields(
        root,
        "",
        &[
            "schema",
            "language",
            "package",
            "dependency",
            "profile",
            "image",
            "image_test",
        ],
        is_cancelled,
    )?;
    let schema = required_u32(root, "schema", "schema", is_cancelled)?;
    if schema != MANIFEST_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedSchema(schema));
    }
    let mut budget = StringBudget::new(limits.string_bytes);
    let language = required_text(root, "language", "language", &mut budget, is_cancelled)?;
    if language != "0.1-design" {
        return Err(unsupported("language", "0.1-design"));
    }

    let package = required_table(root, "package", "[package]")?;
    check_allowed_fields(
        package,
        "package",
        &["name", "version", "source_root"],
        is_cancelled,
    )?;
    let name = required_package_name(package, "name", "package.name", &mut budget, is_cancelled)?;
    let version = required_package_version(
        package,
        "version",
        "package.version",
        &mut budget,
        is_cancelled,
    )?;
    let source_root = required_text(
        package,
        "source_root",
        "package.source_root",
        &mut budget,
        is_cancelled,
    )?;

    let dependencies = project_dependencies(root, limits, &mut budget, is_cancelled)?;
    let profiles = project_profiles(root, limits, &mut budget, is_cancelled)?;
    let images = project_images(root, limits, &mut budget, is_cancelled)?;
    let image_tests = project_image_tests(root, limits, &mut budget, is_cancelled)?;
    let manifest = PackageManifest {
        schema,
        language: LanguageRevision::Design0_1,
        name,
        version,
        source_root,
        dependencies,
        profiles,
        images,
        image_tests,
    };
    manifest
        .validate()
        .map_err(|error| noncanonical(&error.to_string()))?;
    check_cancelled(is_cancelled)?;
    Ok(manifest)
}

fn project_dependencies(
    root: &DeTable<'_>,
    limits: ManifestCodecLimits,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ManifestDependency>, DecodeError> {
    let Some(values) = optional_array(root, "dependency", "[[dependency]]")? else {
        return Ok(Vec::new());
    };
    check_count("manifest dependencies", values.len(), limits.dependencies)?;
    let mut dependencies = Vec::new();
    reserve(
        &mut dependencies,
        values.len(),
        "manifest dependencies",
        u64::from(limits.dependencies),
    )?;
    for value in values {
        check_cancelled(is_cancelled)?;
        let table = table_item(value, "[[dependency]]")?;
        check_allowed_fields(
            table,
            "dependency",
            &["alias", "package", "requirement"],
            is_cancelled,
        )?;
        dependencies.push(ManifestDependency {
            alias: required_dependency_alias(
                table,
                "alias",
                "dependency.alias",
                budget,
                is_cancelled,
            )?,
            package: required_package_name(
                table,
                "package",
                "dependency.package",
                budget,
                is_cancelled,
            )?,
            requirement: required_text(
                table,
                "requirement",
                "dependency.requirement",
                budget,
                is_cancelled,
            )?,
        });
    }
    Ok(dependencies)
}

fn project_profiles(
    root: &DeTable<'_>,
    limits: ManifestCodecLimits,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<BuildProfile>, DecodeError> {
    let Some(values) = optional_array(root, "profile", "[[profile]]")? else {
        return Err(missing("[[profile]]"));
    };
    if values.is_empty() {
        return Err(missing("[[profile]]"));
    }
    check_count("manifest profiles", values.len(), limits.profiles)?;
    let mut profiles = Vec::new();
    reserve(
        &mut profiles,
        values.len(),
        "manifest profiles",
        u64::from(limits.profiles),
    )?;
    for value in values {
        check_cancelled(is_cancelled)?;
        profiles.push(project_profile(
            table_item(value, "[[profile]]")?,
            budget,
            is_cancelled,
        )?);
    }
    Ok(profiles)
}

fn project_profile(
    table: &DeTable<'_>,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BuildProfile, DecodeError> {
    check_allowed_fields(
        table,
        "profile",
        &[
            "name",
            "mode",
            "comptime_steps",
            "comptime_memory_bytes",
            "comptime_call_depth",
            "static_bytes",
            "peak_bytes",
            "event_log_bytes",
            "dma_coherent",
            "require_iommu",
            "reset_timeout_ns",
            "quarantine_bytes",
            "recording",
            "optimization",
            "profile_data",
            "sealed_deployment",
            "warnings_as_errors",
            "watchdogs",
        ],
        is_cancelled,
    )?;
    let mode = match required_text(table, "mode", "profile.mode", budget, is_cancelled)?.as_str() {
        "development" => BuildMode::Development,
        "release" => BuildMode::Release,
        _ => return Err(unsupported("profile.mode", "development or release")),
    };
    // Every field below `name`/`mode` is optional; an absent key falls back
    // to `wrela_build_model::PROFILE_DEFAULTS`. The canonical encoder always
    // writes every field explicitly (see `encode_manifest`), so this is the
    // only place partial profiles are ever materialized.
    let defaults = wrela_build_model::PROFILE_DEFAULTS;
    let recording = match optional_text(
        table,
        "recording",
        "profile.recording",
        budget,
        is_cancelled,
    )? {
        None => defaults.recording,
        Some(value) => match value.as_str() {
            "disabled" => RecordingMode::Disabled,
            "record" => RecordingMode::Record,
            "replay" => RecordingMode::Replay,
            _ => {
                return Err(unsupported(
                    "profile.recording",
                    "disabled, record, or replay",
                ));
            }
        },
    };
    let optimization = match optional_text(
        table,
        "optimization",
        "profile.optimization",
        budget,
        is_cancelled,
    )? {
        None => defaults.optimization_level,
        Some(value) => match value.as_str() {
            "none" => OptimizationLevel::None,
            "development" => OptimizationLevel::Development,
            "performance" => OptimizationLevel::Performance,
            "size" => OptimizationLevel::Size,
            _ => {
                return Err(unsupported(
                    "profile.optimization",
                    "none, development, performance, or size",
                ));
            }
        },
    };
    Ok(BuildProfile {
        name: required_text(table, "name", "profile.name", budget, is_cancelled)?,
        mode,
        comptime: ComptimeLimits {
            steps: optional_u64(
                table,
                "comptime_steps",
                "profile.comptime_steps",
                is_cancelled,
            )?
            .unwrap_or(defaults.comptime.steps),
            memory_bytes: optional_u64(
                table,
                "comptime_memory_bytes",
                "profile.comptime_memory_bytes",
                is_cancelled,
            )?
            .unwrap_or(defaults.comptime.memory_bytes),
            call_depth: optional_u32(
                table,
                "comptime_call_depth",
                "profile.comptime_call_depth",
                is_cancelled,
            )?
            .unwrap_or(defaults.comptime.call_depth),
        },
        memory: MemoryLimits {
            static_bytes: optional_u64(
                table,
                "static_bytes",
                "profile.static_bytes",
                is_cancelled,
            )?
            .unwrap_or(defaults.memory.static_bytes),
            peak_bytes: optional_u64(table, "peak_bytes", "profile.peak_bytes", is_cancelled)?
                .unwrap_or(defaults.memory.peak_bytes),
            event_log_bytes: optional_u64(
                table,
                "event_log_bytes",
                "profile.event_log_bytes",
                is_cancelled,
            )?
            .unwrap_or(defaults.memory.event_log_bytes),
        },
        dma: DmaPolicy {
            coherent: optional_bool(table, "dma_coherent", "profile.dma_coherent")?
                .unwrap_or(defaults.dma.coherent),
            require_iommu: optional_bool(table, "require_iommu", "profile.require_iommu")?
                .unwrap_or(defaults.dma.require_iommu),
        },
        recovery: RecoveryPolicy {
            reset_timeout_ns: optional_u64(
                table,
                "reset_timeout_ns",
                "profile.reset_timeout_ns",
                is_cancelled,
            )?
            .unwrap_or(defaults.recovery.reset_timeout_ns),
            quarantine_bytes: optional_u64(
                table,
                "quarantine_bytes",
                "profile.quarantine_bytes",
                is_cancelled,
            )?
            .unwrap_or(defaults.recovery.quarantine_bytes),
        },
        recording,
        optimization: OptimizationPolicy {
            level: optimization,
            profile_data: optional_digest(
                table,
                "profile_data",
                "profile.profile_data",
                budget,
                is_cancelled,
            )?,
        },
        diagnostics: DiagnosticPolicy {
            sealed_deployment: optional_bool(
                table,
                "sealed_deployment",
                "profile.sealed_deployment",
            )?
            .unwrap_or(defaults.diagnostics.sealed_deployment),
            warnings_as_errors: optional_bool(
                table,
                "warnings_as_errors",
                "profile.warnings_as_errors",
            )?
            .unwrap_or(defaults.diagnostics.warnings_as_errors),
            watchdogs: optional_bool(table, "watchdogs", "profile.watchdogs")?
                .unwrap_or(defaults.diagnostics.watchdogs),
        },
    })
}

fn project_images(
    root: &DeTable<'_>,
    limits: ManifestCodecLimits,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ImageDeclaration>, DecodeError> {
    let Some(values) = optional_array(root, "image", "[[image]]")? else {
        return Ok(Vec::new());
    };
    check_count("manifest images", values.len(), limits.images)?;
    let mut images = Vec::new();
    reserve(
        &mut images,
        values.len(),
        "manifest images",
        u64::from(limits.images),
    )?;
    for value in values {
        check_cancelled(is_cancelled)?;
        let table = table_item(value, "[[image]]")?;
        check_allowed_fields(
            table,
            "image",
            &["name", "module", "entry", "target", "profile"],
            is_cancelled,
        )?;
        let target = required_text(table, "target", "image.target", budget, is_cancelled)?;
        if target != "aarch64-qemu-virt-uefi" {
            return Err(unsupported("image.target", "aarch64-qemu-virt-uefi"));
        }
        images.push(ImageDeclaration {
            name: required_text(table, "name", "image.name", budget, is_cancelled)?,
            module: required_module_path(table, "module", "image.module", budget, is_cancelled)?,
            entry: required_text(table, "entry", "image.entry", budget, is_cancelled)?,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            profile: required_text(table, "profile", "image.profile", budget, is_cancelled)?,
        });
    }
    Ok(images)
}

fn project_image_tests(
    root: &DeTable<'_>,
    limits: ManifestCodecLimits,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ImageTestDeclaration>, DecodeError> {
    let Some(values) = optional_array(root, "image_test", "[[image_test]]")? else {
        return Ok(Vec::new());
    };
    check_count("manifest image tests", values.len(), limits.image_tests)?;
    let mut tests = Vec::new();
    reserve(
        &mut tests,
        values.len(),
        "manifest image tests",
        u64::from(limits.image_tests),
    )?;
    for value in values {
        check_cancelled(is_cancelled)?;
        let table = table_item(value, "[[image_test]]")?;
        check_allowed_fields(
            table,
            "image_test",
            &[
                "name",
                "image",
                "scenario",
                "boot_timeout_ns",
                "shutdown_timeout_ns",
                "maximum_events",
                "maximum_output_bytes",
                "deterministic_seed",
            ],
            is_cancelled,
        )?;
        tests.push(ImageTestDeclaration {
            name: required_text(table, "name", "image_test.name", budget, is_cancelled)?,
            image: required_text(table, "image", "image_test.image", budget, is_cancelled)?,
            scenario: required_text(
                table,
                "scenario",
                "image_test.scenario",
                budget,
                is_cancelled,
            )?,
            boot_timeout_ns: required_u64(
                table,
                "boot_timeout_ns",
                "image_test.boot_timeout_ns",
                is_cancelled,
            )?,
            shutdown_timeout_ns: required_u64(
                table,
                "shutdown_timeout_ns",
                "image_test.shutdown_timeout_ns",
                is_cancelled,
            )?,
            maximum_events: required_u32(
                table,
                "maximum_events",
                "image_test.maximum_events",
                is_cancelled,
            )?,
            maximum_output_bytes: required_u64(
                table,
                "maximum_output_bytes",
                "image_test.maximum_output_bytes",
                is_cancelled,
            )?,
            deterministic_seed: optional_u64(
                table,
                "deterministic_seed",
                "image_test.deterministic_seed",
                is_cancelled,
            )?,
        });
    }
    Ok(tests)
}

fn project_lockfile(
    root: &DeTable<'_>,
    limits: LockfileCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Lockfile, DecodeError> {
    check_allowed_fields(root, "", &["schema", "root", "package"], is_cancelled)?;
    let schema = required_u32(root, "schema", "schema", is_cancelled)?;
    if schema != LOCKFILE_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedSchema(schema));
    }
    let mut budget = StringBudget::new(limits.string_bytes);
    let root_identity = required_table(root, "root", "[root]")?;
    let root_identity = project_identity(root_identity, "root", &mut budget, is_cancelled)?;

    let Some(values) = optional_array(root, "package", "[[package]]")? else {
        return Err(missing("[[package]]"));
    };
    check_count("locked packages", values.len(), limits.packages)?;
    let mut packages = Vec::new();
    reserve(
        &mut packages,
        values.len(),
        "locked packages",
        u64::from(limits.packages),
    )?;
    let mut dependency_count = 0usize;
    for value in values {
        check_cancelled(is_cancelled)?;
        let table = table_item(value, "[[package]]")?;
        packages.push(project_locked_package(
            table,
            limits,
            &mut budget,
            &mut dependency_count,
            is_cancelled,
        )?);
    }
    let lockfile = Lockfile {
        schema,
        root: root_identity,
        packages,
    };
    lockfile
        .validate()
        .map_err(|error| noncanonical(&error.to_string()))?;
    check_cancelled(is_cancelled)?;
    Ok(lockfile)
}

fn project_identity(
    table: &DeTable<'_>,
    prefix: &'static str,
    budget: &mut StringBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageIdentity, DecodeError> {
    check_allowed_fields(
        table,
        prefix,
        &["name", "version", "source_digest"],
        is_cancelled,
    )?;
    let (name_field, version_field, digest_field) = match prefix {
        "root" => ("root.name", "root.version", "root.source_digest"),
        "package" => ("package.name", "package.version", "package.source_digest"),
        _ => (
            "package.dependency.name",
            "package.dependency.version",
            "package.dependency.source_digest",
        ),
    };
    Ok(PackageIdentity {
        name: required_package_name(table, "name", name_field, budget, is_cancelled)?,
        version: required_package_version(table, "version", version_field, budget, is_cancelled)?,
        source_digest: required_digest(table, "source_digest", digest_field, budget, is_cancelled)?,
    })
}

fn project_locked_package(
    table: &DeTable<'_>,
    limits: LockfileCodecLimits,
    budget: &mut StringBudget,
    dependency_count: &mut usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LockedPackage, DecodeError> {
    check_allowed_fields(
        table,
        "package",
        &[
            "name",
            "version",
            "source_digest",
            "manifest_digest",
            "locator",
            "locator_path",
            "locator_provider",
            "locator_key",
            "locator_component",
            "dependency",
        ],
        is_cancelled,
    )?;
    let identity = PackageIdentity {
        name: required_package_name(table, "name", "package.name", budget, is_cancelled)?,
        version: required_package_version(
            table,
            "version",
            "package.version",
            budget,
            is_cancelled,
        )?,
        source_digest: required_digest(
            table,
            "source_digest",
            "package.source_digest",
            budget,
            is_cancelled,
        )?,
    };
    let manifest_digest = required_digest(
        table,
        "manifest_digest",
        "package.manifest_digest",
        budget,
        is_cancelled,
    )?;
    let locator_kind = required_text(table, "locator", "package.locator", budget, is_cancelled)?;
    let locator_path = optional_text(
        table,
        "locator_path",
        "package.locator_path",
        budget,
        is_cancelled,
    )?;
    let locator_provider = optional_text(
        table,
        "locator_provider",
        "package.locator_provider",
        budget,
        is_cancelled,
    )?;
    let locator_key = optional_text(
        table,
        "locator_key",
        "package.locator_key",
        budget,
        is_cancelled,
    )?;
    let locator_component = optional_text(
        table,
        "locator_component",
        "package.locator_component",
        budget,
        is_cancelled,
    )?;
    let locator = match locator_kind.as_str() {
        "workspace" => {
            if locator_provider.is_some() || locator_key.is_some() || locator_component.is_some() {
                return Err(noncanonical(
                    "workspace locator contains fields for another locator kind",
                ));
            }
            PackageLocator::Workspace {
                path: locator_path.ok_or_else(|| missing("package.locator_path"))?,
            }
        }
        "archive" => {
            if locator_path.is_some() || locator_component.is_some() {
                return Err(noncanonical(
                    "archive locator contains fields for another locator kind",
                ));
            }
            PackageLocator::Archive {
                provider: locator_provider.ok_or_else(|| missing("package.locator_provider"))?,
                key: locator_key.ok_or_else(|| missing("package.locator_key"))?,
            }
        }
        "toolchain" => {
            if locator_path.is_some() || locator_provider.is_some() || locator_key.is_some() {
                return Err(noncanonical(
                    "toolchain locator contains fields for another locator kind",
                ));
            }
            PackageLocator::Toolchain {
                component: locator_component.ok_or_else(|| missing("package.locator_component"))?,
            }
        }
        _ => {
            return Err(unsupported(
                "package.locator",
                "workspace, archive, or toolchain",
            ));
        }
    };

    let mut dependencies = Vec::new();
    if let Some(values) = optional_array(table, "dependency", "[[package.dependency]]")? {
        *dependency_count = dependency_count
            .checked_add(values.len())
            .ok_or_else(|| resource_limit("locked dependencies", u64::from(limits.dependencies)))?;
        check_count(
            "locked dependencies",
            *dependency_count,
            limits.dependencies,
        )?;
        reserve(
            &mut dependencies,
            values.len(),
            "locked dependencies",
            u64::from(limits.dependencies),
        )?;
        for value in values {
            check_cancelled(is_cancelled)?;
            let table = table_item(value, "[[package.dependency]]")?;
            check_allowed_fields(
                table,
                "package.dependency",
                &["alias", "name", "version", "source_digest"],
                is_cancelled,
            )?;
            dependencies.push(LockedDependency {
                alias: required_dependency_alias(
                    table,
                    "alias",
                    "package.dependency.alias",
                    budget,
                    is_cancelled,
                )?,
                identity: PackageIdentity {
                    name: required_package_name(
                        table,
                        "name",
                        "package.dependency.name",
                        budget,
                        is_cancelled,
                    )?,
                    version: required_package_version(
                        table,
                        "version",
                        "package.dependency.version",
                        budget,
                        is_cancelled,
                    )?,
                    source_digest: required_digest(
                        table,
                        "source_digest",
                        "package.dependency.source_digest",
                        budget,
                        is_cancelled,
                    )?,
                },
            });
        }
    }
    Ok(LockedPackage {
        identity,
        locator,
        dependencies,
        manifest_digest,
    })
}

fn validate_manifest_resources(
    manifest: &PackageManifest,
    limits: ManifestCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    if manifest.profiles.is_empty() {
        return Err(noncanonical(
            "manifest must declare at least one build profile",
        ));
    }
    check_count(
        "manifest dependencies",
        manifest.dependencies.len(),
        limits.dependencies,
    )?;
    check_count(
        "manifest profiles",
        manifest.profiles.len(),
        limits.profiles,
    )?;
    check_count("manifest images", manifest.images.len(), limits.images)?;
    check_count(
        "manifest image tests",
        manifest.image_tests.len(),
        limits.image_tests,
    )?;

    let mut budget = StringBudget::new(limits.string_bytes);
    budget_text(&mut budget, manifest.language.as_str(), is_cancelled)?;
    budget_text(&mut budget, manifest.name.as_str(), is_cancelled)?;
    budget_text(&mut budget, manifest.version.as_str(), is_cancelled)?;
    budget_text(&mut budget, &manifest.source_root, is_cancelled)?;
    for dependency in &manifest.dependencies {
        check_cancelled(is_cancelled)?;
        budget_text(&mut budget, dependency.alias.as_str(), is_cancelled)?;
        budget_text(&mut budget, dependency.package.as_str(), is_cancelled)?;
        budget_text(&mut budget, &dependency.requirement, is_cancelled)?;
    }
    for profile in &manifest.profiles {
        check_cancelled(is_cancelled)?;
        budget_text(&mut budget, &profile.name, is_cancelled)?;
        budget_text(&mut budget, mode_spelling(profile.mode), is_cancelled)?;
        budget_text(
            &mut budget,
            recording_spelling(profile.recording),
            is_cancelled,
        )?;
        budget_text(
            &mut budget,
            optimization_spelling(profile.optimization.level),
            is_cancelled,
        )?;
        if profile.optimization.profile_data.is_some() {
            budget.add(64)?;
        }
    }
    for image in &manifest.images {
        check_cancelled(is_cancelled)?;
        budget_text(&mut budget, &image.name, is_cancelled)?;
        budget_module_path(&mut budget, &image.module, is_cancelled)?;
        budget_text(&mut budget, &image.entry, is_cancelled)?;
        budget_text(&mut budget, image.target.as_str(), is_cancelled)?;
        budget_text(&mut budget, &image.profile, is_cancelled)?;
    }
    for test in &manifest.image_tests {
        check_cancelled(is_cancelled)?;
        budget_text(&mut budget, &test.name, is_cancelled)?;
        budget_text(&mut budget, &test.image, is_cancelled)?;
        budget_text(&mut budget, &test.scenario, is_cancelled)?;
    }
    check_cancelled(is_cancelled)
}

fn validate_lockfile_resources(
    lockfile: &Lockfile,
    limits: LockfileCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    check_count("locked packages", lockfile.packages.len(), limits.packages)?;
    let dependency_count = lockfile
        .packages
        .iter()
        .try_fold(0usize, |total, package| {
            total
                .checked_add(package.dependencies.len())
                .ok_or_else(|| {
                    resource_limit("locked dependencies", u64::from(limits.dependencies))
                })
        })?;
    check_count("locked dependencies", dependency_count, limits.dependencies)?;

    let mut budget = StringBudget::new(limits.string_bytes);
    budget_identity(&mut budget, &lockfile.root, is_cancelled)?;
    for package in &lockfile.packages {
        check_cancelled(is_cancelled)?;
        budget_identity(&mut budget, &package.identity, is_cancelled)?;
        budget.add(64)?;
        match &package.locator {
            PackageLocator::Workspace { path } => {
                budget_text(&mut budget, "workspace", is_cancelled)?;
                budget_text(&mut budget, path, is_cancelled)?;
            }
            PackageLocator::Archive { provider, key } => {
                budget_text(&mut budget, "archive", is_cancelled)?;
                budget_text(&mut budget, provider, is_cancelled)?;
                budget_text(&mut budget, key, is_cancelled)?;
            }
            PackageLocator::Toolchain { component } => {
                budget_text(&mut budget, "toolchain", is_cancelled)?;
                budget_text(&mut budget, component, is_cancelled)?;
            }
        }
        for dependency in &package.dependencies {
            check_cancelled(is_cancelled)?;
            budget_text(&mut budget, dependency.alias.as_str(), is_cancelled)?;
            budget_identity(&mut budget, &dependency.identity, is_cancelled)?;
        }
    }
    check_cancelled(is_cancelled)
}

fn budget_identity(
    budget: &mut StringBudget,
    identity: &PackageIdentity,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    budget_text(budget, identity.name.as_str(), is_cancelled)?;
    budget_text(budget, identity.version.as_str(), is_cancelled)?;
    budget.add(64)
}

fn budget_module_path(
    budget: &mut StringBudget,
    module: &ModulePath,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    for (index, segment) in module.segments().iter().enumerate() {
        if index != 0 {
            budget.add(1)?;
        }
        budget_text(budget, segment, is_cancelled)?;
    }
    Ok(())
}

fn budget_text(
    budget: &mut StringBudget,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DecodeError> {
    budget.account(value, is_cancelled)
}

const fn mode_spelling(mode: BuildMode) -> &'static str {
    match mode {
        BuildMode::Development => "development",
        BuildMode::Release => "release",
    }
}

const fn recording_spelling(mode: RecordingMode) -> &'static str {
    match mode {
        RecordingMode::Disabled => "disabled",
        RecordingMode::Record => "record",
        RecordingMode::Replay => "replay",
    }
}

const fn optimization_spelling(level: OptimizationLevel) -> &'static str {
    match level {
        OptimizationLevel::None => "none",
        OptimizationLevel::Development => "development",
        OptimizationLevel::Performance => "performance",
        OptimizationLevel::Size => "size",
    }
}

struct CanonicalWriter<'a> {
    bytes: Vec<u8>,
    limit: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> CanonicalWriter<'a> {
    fn new(limit: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            is_cancelled,
        }
    }

    fn raw(&mut self, value: &str) -> Result<(), DecodeError> {
        self.raw_bytes(value.as_bytes())
    }

    fn raw_bytes(&mut self, value: &[u8]) -> Result<(), DecodeError> {
        for chunk in value.chunks(CANCELLATION_POLL_BYTES) {
            check_cancelled(self.is_cancelled)?;
            let next = self
                .bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| resource_limit("canonical package TOML bytes", self.limit))?;
            if u64::try_from(next).unwrap_or(u64::MAX) > self.limit {
                return Err(resource_limit("canonical package TOML bytes", self.limit));
            }
            self.bytes
                .try_reserve_exact(chunk.len())
                .map_err(|_| resource_limit("canonical package TOML bytes", self.limit))?;
            self.bytes.extend_from_slice(chunk);
        }
        Ok(())
    }

    fn quoted(&mut self, value: &str) -> Result<(), DecodeError> {
        self.raw("\"")?;
        let mut plain_start = 0usize;
        for (index, character) in value.char_indices() {
            if index % CANCELLATION_POLL_BYTES < 4 {
                check_cancelled(self.is_cancelled)?;
            }
            let escape = match character {
                '"' => Some("\\\""),
                '\\' => Some("\\\\"),
                '\u{0008}' => Some("\\b"),
                '\t' => Some("\\t"),
                '\n' => Some("\\n"),
                '\u{000c}' => Some("\\f"),
                '\r' => Some("\\r"),
                _ => None,
            };
            if let Some(escape) = escape {
                self.raw(&value[plain_start..index])?;
                self.raw(escape)?;
                plain_start = index.saturating_add(character.len_utf8());
            } else if character.is_control() {
                self.raw(&value[plain_start..index])?;
                self.unicode_escape(character)?;
                plain_start = index.saturating_add(character.len_utf8());
            }
        }
        self.raw(&value[plain_start..])?;
        self.raw("\"")
    }

    fn unicode_escape(&mut self, character: char) -> Result<(), DecodeError> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let scalar = u32::from(character);
        let (mut bytes, digits) = if scalar <= 0xffff {
            ([b'\\', b'u', b'0', b'0', b'0', b'0', 0, 0, 0, 0], 4usize)
        } else {
            (
                [b'\\', b'U', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0'],
                8usize,
            )
        };
        for index in 0..digits {
            let shift = (digits - index - 1) * 4;
            bytes[index + 2] = HEX[((scalar >> shift) & 0x0f) as usize];
        }
        self.raw_bytes(&bytes[..digits + 2])
    }

    fn assignment_text(&mut self, key: &str, value: &str) -> Result<(), DecodeError> {
        self.raw(key)?;
        self.raw(" = ")?;
        self.quoted(value)?;
        self.raw("\n")
    }

    fn assignment_digest(&mut self, key: &str, digest: Sha256Digest) -> Result<(), DecodeError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.raw(key)?;
        self.raw(" = \"")?;
        let mut encoded = [0u8; 64];
        for (index, byte) in digest.as_bytes().iter().copied().enumerate() {
            encoded[index * 2] = HEX[usize::from(byte >> 4)];
            encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        self.raw_bytes(&encoded)?;
        self.raw("\"\n")
    }

    fn assignment_u64(&mut self, key: &'static str, value: u64) -> Result<(), DecodeError> {
        if value > u64::try_from(i64::MAX).unwrap_or(u64::MAX) {
            return Err(unsupported(key, "TOML signed 64-bit integer"));
        }
        self.raw(key)?;
        self.raw(" = ")?;
        let mut encoded = [0u8; 20];
        let mut start = encoded.len();
        let mut remaining = value;
        loop {
            start = start.saturating_sub(1);
            encoded[start] = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.raw_bytes(&encoded[start..])?;
        self.raw("\n")
    }

    fn assignment_u32(&mut self, key: &'static str, value: u32) -> Result<(), DecodeError> {
        self.assignment_u64(key, u64::from(value))
    }

    fn assignment_bool(&mut self, key: &str, value: bool) -> Result<(), DecodeError> {
        self.raw(key)?;
        self.raw(if value { " = true\n" } else { " = false\n" })
    }

    fn finish(self) -> Result<Vec<u8>, DecodeError> {
        check_cancelled(self.is_cancelled)?;
        Ok(self.bytes)
    }
}

fn encode_manifest(
    manifest: &PackageManifest,
    byte_limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DecodeError> {
    let mut writer = CanonicalWriter::new(byte_limit, is_cancelled);
    writer.assignment_u32("schema", manifest.schema)?;
    writer.assignment_text("language", manifest.language.as_str())?;
    writer.raw("\n[package]\n")?;
    writer.assignment_text("name", manifest.name.as_str())?;
    writer.assignment_text("version", manifest.version.as_str())?;
    writer.assignment_text("source_root", &manifest.source_root)?;

    // Modules are derived by the loader from a filesystem walk of
    // `source_root`, not declared here; there is no `[[module]]` block to
    // emit.
    for dependency in &manifest.dependencies {
        writer.raw("\n[[dependency]]\n")?;
        writer.assignment_text("alias", dependency.alias.as_str())?;
        writer.assignment_text("package", dependency.package.as_str())?;
        writer.assignment_text("requirement", &dependency.requirement)?;
    }
    for profile in &manifest.profiles {
        writer.raw("\n[[profile]]\n")?;
        writer.assignment_text("name", &profile.name)?;
        writer.assignment_text("mode", mode_spelling(profile.mode))?;
        writer.assignment_u64("comptime_steps", profile.comptime.steps)?;
        writer.assignment_u64("comptime_memory_bytes", profile.comptime.memory_bytes)?;
        writer.assignment_u32("comptime_call_depth", profile.comptime.call_depth)?;
        writer.assignment_u64("static_bytes", profile.memory.static_bytes)?;
        writer.assignment_u64("peak_bytes", profile.memory.peak_bytes)?;
        writer.assignment_u64("event_log_bytes", profile.memory.event_log_bytes)?;
        writer.assignment_bool("dma_coherent", profile.dma.coherent)?;
        writer.assignment_bool("require_iommu", profile.dma.require_iommu)?;
        writer.assignment_u64("reset_timeout_ns", profile.recovery.reset_timeout_ns)?;
        writer.assignment_u64("quarantine_bytes", profile.recovery.quarantine_bytes)?;
        writer.assignment_text("recording", recording_spelling(profile.recording))?;
        writer.assignment_text(
            "optimization",
            optimization_spelling(profile.optimization.level),
        )?;
        if let Some(profile_data) = profile.optimization.profile_data {
            writer.assignment_digest("profile_data", profile_data)?;
        }
        writer.assignment_bool("sealed_deployment", profile.diagnostics.sealed_deployment)?;
        writer.assignment_bool("warnings_as_errors", profile.diagnostics.warnings_as_errors)?;
        writer.assignment_bool("watchdogs", profile.diagnostics.watchdogs)?;
    }
    for image in &manifest.images {
        writer.raw("\n[[image]]\n")?;
        writer.assignment_text("name", &image.name)?;
        writer.assignment_text("module", &image.module.dotted())?;
        writer.assignment_text("entry", &image.entry)?;
        writer.assignment_text("target", image.target.as_str())?;
        writer.assignment_text("profile", &image.profile)?;
    }
    for test in &manifest.image_tests {
        writer.raw("\n[[image_test]]\n")?;
        writer.assignment_text("name", &test.name)?;
        writer.assignment_text("image", &test.image)?;
        writer.assignment_text("scenario", &test.scenario)?;
        writer.assignment_u64("boot_timeout_ns", test.boot_timeout_ns)?;
        writer.assignment_u64("shutdown_timeout_ns", test.shutdown_timeout_ns)?;
        writer.assignment_u32("maximum_events", test.maximum_events)?;
        writer.assignment_u64("maximum_output_bytes", test.maximum_output_bytes)?;
        if let Some(seed) = test.deterministic_seed {
            writer.assignment_u64("deterministic_seed", seed)?;
        }
    }
    writer.finish()
}

fn encode_lockfile(
    lockfile: &Lockfile,
    byte_limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DecodeError> {
    let mut writer = CanonicalWriter::new(byte_limit, is_cancelled);
    writer.assignment_u32("schema", lockfile.schema)?;
    writer.raw("\n[root]\n")?;
    encode_identity(&mut writer, &lockfile.root)?;
    for package in &lockfile.packages {
        writer.raw("\n[[package]]\n")?;
        encode_identity(&mut writer, &package.identity)?;
        writer.assignment_digest("manifest_digest", package.manifest_digest)?;
        match &package.locator {
            PackageLocator::Workspace { path } => {
                writer.assignment_text("locator", "workspace")?;
                writer.assignment_text("locator_path", path)?;
            }
            PackageLocator::Archive { provider, key } => {
                writer.assignment_text("locator", "archive")?;
                writer.assignment_text("locator_provider", provider)?;
                writer.assignment_text("locator_key", key)?;
            }
            PackageLocator::Toolchain { component } => {
                writer.assignment_text("locator", "toolchain")?;
                writer.assignment_text("locator_component", component)?;
            }
        }
        for dependency in &package.dependencies {
            writer.raw("\n[[package.dependency]]\n")?;
            writer.assignment_text("alias", dependency.alias.as_str())?;
            encode_identity(&mut writer, &dependency.identity)?;
        }
    }
    writer.finish()
}

fn encode_identity(
    writer: &mut CanonicalWriter<'_>,
    identity: &PackageIdentity,
) -> Result<(), DecodeError> {
    writer.assignment_text("name", identity.name.as_str())?;
    writer.assignment_text("version", identity.version.as_str())?;
    writer.assignment_digest("source_digest", identity.source_digest)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::time::{Duration, Instant};

    use wrela_package::{
        LOCKFILE_SCHEMA_VERSION, LockedPackage, Lockfile, PackageIdentity, PackageLocator,
    };
    use wrela_source::SourceInput;

    use super::*;
    use crate::{
        CanonicalWorkspaceLoader, ContentDigest, ContentHasher, LoadLimits, LoadRequest,
        PackageBundle, PackageContentKind, PackageContentRecord, PackageSourceProvider,
        ProviderError, SoftwareSha256, WorkspaceLoader, package_content_digest,
    };

    const MINIMAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/minimal.toml");
    const REPRESENTATIVE_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/representative.toml");
    const NONCANONICAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/noncanonical.toml");
    const EQUIVALENT_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/equivalent.toml");
    const MINIMAL_LOCKFILE: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/minimal.lock");
    const REPRESENTATIVE_LOCKFILE: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/representative.lock");
    const NONCANONICAL_LOCKFILE: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/noncanonical.lock");
    const EQUIVALENT_LOCKFILE: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/equivalent.lock");
    const CHECKED_IN_CORE_MANIFEST: &[u8] =
        include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
    const CHECKED_IN_MINIMUM_IMAGE_MANIFEST: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/wrela.toml");
    const CHECKED_IN_MINIMUM_IMAGE_LOCKFILE: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/wrela.lock");
    const CHECKED_IN_CORE_SOURCE: &[u8] =
        include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
    const CHECKED_IN_CORE_OPS_SOURCE: &[u8] =
        include_bytes!("../../../std/wrela-core-0.1/src/ops.wr");
    const CHECKED_IN_CORE_RESULT_SOURCE: &[u8] =
        include_bytes!("../../../std/wrela-core-0.1/src/result.wr");
    const CHECKED_IN_CORE_TIME_SOURCE: &[u8] =
        include_bytes!("../../../std/wrela-core-0.1/src/time.wr");
    const CHECKED_IN_MINIMUM_IMAGE_SOURCE: &[u8] =
        include_bytes!("../../../std/examples/minimal-image/src/bootstrap/image.wr");

    fn never_cancelled() -> bool {
        false
    }

    const fn manifest_limits() -> ManifestCodecLimits {
        ManifestCodecLimits {
            bytes: MAX_MANIFEST_TOML_BYTES,
            string_bytes: 4 * 1024 * 1024,
            modules: 16_384,
            dependencies: 16_384,
            profiles: 16_384,
            images: 16_384,
            image_tests: 16_384,
        }
    }

    const fn lockfile_limits() -> LockfileCodecLimits {
        LockfileCodecLimits {
            bytes: MAX_LOCKFILE_TOML_BYTES,
            string_bytes: 4 * 1024 * 1024,
            packages: 16_384,
            dependencies: 16_384,
        }
    }

    fn replace_manifest(needle: &str, replacement: &str) -> Vec<u8> {
        String::from_utf8(MINIMAL_MANIFEST.to_vec())
            .expect("fixture is UTF-8")
            .replacen(needle, replacement, 1)
            .into_bytes()
    }

    #[test]
    fn canonical_schema_one_fixtures_round_trip_byte_exactly() {
        let codec = CanonicalPackageCodec::new();
        for fixture in [MINIMAL_MANIFEST, REPRESENTATIVE_MANIFEST] {
            let manifest = codec
                .decode_manifest(fixture, manifest_limits(), &never_cancelled)
                .expect("canonical manifest decodes");
            assert_eq!(
                codec
                    .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
                    .expect("manifest canonicalizes"),
                fixture
            );
        }
        for fixture in [MINIMAL_LOCKFILE, REPRESENTATIVE_LOCKFILE] {
            let lockfile = codec
                .decode_lockfile(fixture, lockfile_limits(), &never_cancelled)
                .expect("canonical lockfile decodes");
            assert_eq!(
                codec
                    .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
                    .expect("lockfile canonicalizes"),
                fixture
            );
        }

        let representative = codec
            .decode_manifest(REPRESENTATIVE_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("representative manifest");
        assert_eq!(representative.dependencies.len(), 2);
        assert_eq!(representative.images.len(), 1);
        assert_eq!(representative.image_tests.len(), 1);

        let lockfile = codec
            .decode_lockfile(REPRESENTATIVE_LOCKFILE, lockfile_limits(), &never_cancelled)
            .expect("representative lockfile");
        assert!(matches!(
            lockfile.packages[0].locator,
            PackageLocator::Workspace { .. }
        ));
        assert!(matches!(
            lockfile.packages[1].locator,
            PackageLocator::Archive { .. }
        ));
        assert!(matches!(
            lockfile.packages[2].locator,
            PackageLocator::Toolchain { .. }
        ));
    }

    #[test]
    fn checked_in_bootstrap_manifests_are_schema_one_and_derive_stable_modules() {
        // These checked-in manifests declare only `[[profile]]` overrides and
        // no `[[module]]` block (modules are derived from a source-root walk
        // by the loader, not decoded here), so they are valid schema-1 input
        // without being byte-identical to their own canonical re-encoding.
        // Round-tripping through decode -> canonical-encode -> decode again
        // must still be a fixed point.
        let codec = CanonicalPackageCodec::new();
        let core = codec
            .decode_manifest(
                CHECKED_IN_CORE_MANIFEST,
                manifest_limits(),
                &never_cancelled,
            )
            .expect("checked-in core manifest");
        assert_eq!(core.name.as_str(), "wrela-core");
        assert_eq!(core.version.as_str(), "0.1.0");
        assert!(core.dependencies.is_empty());
        assert_eq!(core.profiles.len(), 1);
        assert_eq!(core.profiles[0].name, "development");
        // The checked-in profile overrides everything but the fields that
        // already equal `PROFILE_DEFAULTS`; confirm the omitted fields
        // decoded to those defaults.
        assert_eq!(
            core.profiles[0].memory.event_log_bytes,
            wrela_build_model::PROFILE_DEFAULTS.memory.event_log_bytes
        );
        assert_eq!(
            core.profiles[0].dma,
            wrela_build_model::PROFILE_DEFAULTS.dma
        );
        assert_eq!(
            core.profiles[0].recording,
            wrela_build_model::PROFILE_DEFAULTS.recording
        );
        assert!(core.images.is_empty());
        let core_canonical = codec
            .canonical_manifest(&core, manifest_limits(), &never_cancelled)
            .expect("canonical core manifest");
        let core_roundtrip = codec
            .decode_manifest(&core_canonical, manifest_limits(), &never_cancelled)
            .expect("canonical core manifest redecodes");
        assert_eq!(core_roundtrip, core);

        let application = codec
            .decode_manifest(
                CHECKED_IN_MINIMUM_IMAGE_MANIFEST,
                manifest_limits(),
                &never_cancelled,
            )
            .expect("checked-in minimum image manifest");
        assert_eq!(application.images[0].module.dotted(), "bootstrap.image");
        assert_eq!(application.dependencies.len(), 1);
        assert_eq!(application.dependencies[0].alias.as_str(), "core");
        assert_eq!(application.dependencies[0].package.as_str(), "wrela-core");
        assert_eq!(application.images.len(), 1);
        assert_eq!(application.images[0].entry, "boot");
        assert_eq!(
            application.images[0].target,
            TargetIdentity::aarch64_qemu_virt_uefi()
        );
        let application_canonical = codec
            .canonical_manifest(&application, manifest_limits(), &never_cancelled)
            .expect("canonical minimum image manifest");
        let application_roundtrip = codec
            .decode_manifest(&application_canonical, manifest_limits(), &never_cancelled)
            .expect("canonical minimum image manifest redecodes");
        assert_eq!(application_roundtrip, application);

        // Package content digests bind the *canonical* manifest bytes (what
        // the loader always hashes), not the checked-in override-only TOML.
        let core_digest = package_content_digest(
            &core_canonical,
            &[
                PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: "image.wr",
                    digest: SoftwareSha256.sha256(CHECKED_IN_CORE_SOURCE),
                },
                PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: "ops.wr",
                    digest: SoftwareSha256.sha256(CHECKED_IN_CORE_OPS_SOURCE),
                },
                PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: "result.wr",
                    digest: SoftwareSha256.sha256(CHECKED_IN_CORE_RESULT_SOURCE),
                },
                PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: "time.wr",
                    digest: SoftwareSha256.sha256(CHECKED_IN_CORE_TIME_SOURCE),
                },
            ],
            &SoftwareSha256,
            &never_cancelled,
        )
        .expect("canonical core package content digest");
        assert_eq!(
            core_digest.to_hex(),
            "0011a42b0c7fa08e9388deebe81533ee1071c2d805ccc41f34d0958da9d8183f"
        );
        let application_digest = package_content_digest(
            &application_canonical,
            &[PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "bootstrap/image.wr",
                digest: SoftwareSha256.sha256(CHECKED_IN_MINIMUM_IMAGE_SOURCE),
            }],
            &SoftwareSha256,
            &never_cancelled,
        )
        .expect("canonical minimum application package content digest");
        assert_eq!(
            application_digest.to_hex(),
            "ca556c73183fe0c85b89515adf53d3f7afaa97dbbef353f2940040d8d69e8291"
        );

        let lockfile = codec
            .decode_lockfile(
                CHECKED_IN_MINIMUM_IMAGE_LOCKFILE,
                lockfile_limits(),
                &never_cancelled,
            )
            .expect("checked-in minimum image lockfile");
        assert_eq!(lockfile.root.source_digest, application_digest);
        assert_eq!(lockfile.packages.len(), 2);
        let locked_core = lockfile
            .packages
            .iter()
            .find(|package| package.identity.name.as_str() == "wrela-core")
            .expect("locked core package");
        assert_eq!(locked_core.identity.source_digest, core_digest);
        assert_eq!(
            locked_core.manifest_digest,
            SoftwareSha256.sha256(&core_canonical)
        );
        assert!(matches!(
            &locked_core.locator,
            PackageLocator::Toolchain { component } if component == "wrela-core-0.1"
        ));
        assert_eq!(
            codec
                .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
                .expect("canonical minimum image lockfile"),
            CHECKED_IN_MINIMUM_IMAGE_LOCKFILE
        );
    }

    #[test]
    fn toml_one_equivalent_forms_normalize_to_canonical_fixtures() {
        let codec = CanonicalPackageCodec::new();
        let canonical_manifest = codec
            .decode_manifest(MINIMAL_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("minimal manifest");
        for fixture in [NONCANONICAL_MANIFEST, EQUIVALENT_MANIFEST] {
            let decoded = codec
                .decode_manifest(fixture, manifest_limits(), &never_cancelled)
                .expect("equivalent TOML manifest");
            assert_eq!(decoded, canonical_manifest);
            assert_eq!(
                codec
                    .canonical_manifest(&decoded, manifest_limits(), &never_cancelled)
                    .expect("canonical manifest"),
                MINIMAL_MANIFEST
            );
        }

        let canonical_lockfile = codec
            .decode_lockfile(MINIMAL_LOCKFILE, lockfile_limits(), &never_cancelled)
            .expect("minimal lockfile");
        for fixture in [NONCANONICAL_LOCKFILE, EQUIVALENT_LOCKFILE] {
            let decoded = codec
                .decode_lockfile(fixture, lockfile_limits(), &never_cancelled)
                .expect("equivalent TOML lockfile");
            assert_eq!(decoded, canonical_lockfile);
            assert_eq!(
                codec
                    .canonical_lockfile(&decoded, lockfile_limits(), &never_cancelled)
                    .expect("canonical lockfile"),
                MINIMAL_LOCKFILE
            );
        }
    }

    #[test]
    fn parser_and_closed_schema_failures_are_structured_and_bounded() {
        let codec = CanonicalPackageCodec::new();
        let malformed_fixture =
            include_bytes!("../../../tests/contracts/package/v1/invalid/malformed.toml");
        let duplicate_fixture =
            include_bytes!("../../../tests/contracts/package/v1/invalid/duplicate.toml");
        let unknown_fixture =
            include_bytes!("../../../tests/contracts/package/v1/invalid/unknown.toml");
        let unsupported_schema =
            include_bytes!("../../../tests/contracts/package/v1/invalid/unsupported-schema.toml");
        let unsupported_value =
            include_bytes!("../../../tests/contracts/package/v1/invalid/unsupported-value.toml");
        let signed_hex =
            include_bytes!("../../../tests/contracts/package/v1/invalid/signed-hex.toml");
        let excessive_depth =
            include_bytes!("../../../tests/contracts/package/v1/invalid/depth.toml");
        let mixed_locator =
            include_bytes!("../../../tests/contracts/package/v1/invalid/mixed-locator.lock");

        assert!(matches!(
            codec.decode_manifest(malformed_fixture, manifest_limits(), &never_cancelled),
            Err(DecodeError::Malformed { .. })
        ));
        assert!(matches!(
            codec.decode_manifest(duplicate_fixture, manifest_limits(), &never_cancelled),
            Err(DecodeError::DuplicateKey(_))
        ));
        assert!(matches!(
            codec.decode_manifest(unknown_fixture, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnknownField(_))
        ));
        assert_eq!(
            codec.decode_manifest(unsupported_schema, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnsupportedSchema(2))
        );
        assert!(matches!(
            codec.decode_manifest(unsupported_value, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnsupportedValue {
                field: "language",
                ..
            })
        ));
        assert!(matches!(
            codec.decode_manifest(signed_hex, manifest_limits(), &never_cancelled),
            Err(DecodeError::Malformed { .. })
        ));
        assert!(matches!(
            codec.decode_manifest(excessive_depth, manifest_limits(), &never_cancelled),
            Err(DecodeError::Malformed { .. })
        ));
        assert!(matches!(
            codec.decode_lockfile(mixed_locator, lockfile_limits(), &never_cancelled),
            Err(DecodeError::NonCanonical(_))
        ));
        assert_eq!(
            codec.decode_manifest(&[0xff], manifest_limits(), &never_cancelled),
            Err(DecodeError::InvalidUtf8)
        );

        let long_key = "x".repeat(32 * 1024);
        let source = format!("schema = 1\n{long_key} = true\n");
        let error = codec
            .decode_manifest(source.as_bytes(), manifest_limits(), &never_cancelled)
            .expect_err("unknown key is rejected");
        let DecodeError::UnknownField(field) = error else {
            panic!("expected a bounded unknown-field error");
        };
        assert!(field.len() <= MAX_ERROR_FIELD_BYTES);
        assert!(field.is_char_boundary(field.len()));

        let error = codec
            .decode_manifest(malformed_fixture, manifest_limits(), &never_cancelled)
            .expect_err("malformed fixture is rejected");
        let DecodeError::Malformed { message, .. } = error else {
            panic!("expected a bounded parser diagnostic");
        };
        assert!(message.len() <= MAX_ERROR_MESSAGE_BYTES);
    }

    #[test]
    fn resource_limits_are_exact_and_apply_to_decode_and_encode() {
        let codec = CanonicalPackageCodec::new();
        let manifest_length = u64::try_from(MINIMAL_MANIFEST.len()).expect("fixture length");
        let mut exact_manifest = manifest_limits();
        exact_manifest.bytes = manifest_length;
        // language(10) + package.name(4) + package.version(5) +
        // package.source_root(3) + profile.mode(11) + profile.name(11) +
        // profile.recording(8) + profile.optimization(4) = 56. There is no
        // `[[module]]` block to budget for; modules are derived, not decoded.
        exact_manifest.string_bytes = 56;
        let manifest = codec
            .decode_manifest(MINIMAL_MANIFEST, exact_manifest, &never_cancelled)
            .expect("exact manifest limits");
        assert_eq!(
            codec
                .canonical_manifest(&manifest, exact_manifest, &never_cancelled)
                .expect("exact canonical manifest"),
            MINIMAL_MANIFEST
        );

        let mut too_few_bytes = exact_manifest;
        too_few_bytes.bytes = manifest_length - 1;
        assert!(matches!(
            codec.decode_manifest(MINIMAL_MANIFEST, too_few_bytes, &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "manifest TOML bytes",
                ..
            })
        ));
        let mut too_few_strings = exact_manifest;
        too_few_strings.string_bytes = 55;
        assert!(matches!(
            codec.decode_manifest(MINIMAL_MANIFEST, too_few_strings, &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "package TOML string bytes",
                ..
            })
        ));

        let lockfile_length = u64::try_from(MINIMAL_LOCKFILE.len()).expect("fixture length");
        let mut exact_lockfile = lockfile_limits();
        exact_lockfile.bytes = lockfile_length;
        exact_lockfile.string_bytes = 232;
        let lockfile = codec
            .decode_lockfile(MINIMAL_LOCKFILE, exact_lockfile, &never_cancelled)
            .expect("exact lockfile limits");
        assert_eq!(
            codec
                .canonical_lockfile(&lockfile, exact_lockfile, &never_cancelled)
                .expect("exact canonical lockfile"),
            MINIMAL_LOCKFILE
        );
        exact_lockfile.string_bytes = 231;
        assert!(matches!(
            codec.decode_lockfile(MINIMAL_LOCKFILE, exact_lockfile, &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "package TOML string bytes",
                ..
            })
        ));

        let mut no_dependencies = manifest_limits();
        no_dependencies.dependencies = 0;
        assert!(matches!(
            codec.decode_manifest(REPRESENTATIVE_MANIFEST, no_dependencies, &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "manifest dependencies",
                limit: 0
            })
        ));
        let mut invalid = manifest_limits();
        invalid.bytes = 0;
        assert_eq!(
            codec.decode_manifest(MINIMAL_MANIFEST, invalid, &never_cancelled),
            Err(DecodeError::InvalidLimits)
        );
    }

    #[test]
    fn toml_integers_are_signed_i64_and_wrong_scalar_shapes_are_rejected() {
        let codec = CanonicalPackageCodec::new();
        let maximum = u64::try_from(i64::MAX).expect("i64 maximum is nonnegative");
        let decimal =
            replace_manifest("comptime_steps = 1", "comptime_steps = 9223372036854775807");
        let decoded = codec
            .decode_manifest(&decimal, manifest_limits(), &never_cancelled)
            .expect("signed-i64 maximum");
        assert_eq!(decoded.profiles[0].comptime.steps, maximum);
        let encoded = codec
            .canonical_manifest(&decoded, manifest_limits(), &never_cancelled)
            .expect("signed-i64 maximum canonicalizes");
        assert!(
            encoded
                .windows(19)
                .any(|window| window == b"9223372036854775807")
        );

        let hexadecimal = replace_manifest(
            "comptime_steps = 1",
            "comptime_steps = 0x7fff_ffff_ffff_ffff",
        );
        assert_eq!(
            codec
                .decode_manifest(&hexadecimal, manifest_limits(), &never_cancelled)
                .expect("radix spelling")
                .profiles[0]
                .comptime
                .steps,
            maximum
        );

        for invalid in [
            replace_manifest("comptime_steps = 1", "comptime_steps = 9223372036854775808"),
            replace_manifest("comptime_steps = 1", "comptime_steps = -1"),
        ] {
            assert!(matches!(
                codec.decode_manifest(&invalid, manifest_limits(), &never_cancelled),
                Err(DecodeError::Malformed { .. })
            ));
        }

        let negative_zero = replace_manifest("event_log_bytes = 0", "event_log_bytes = -0");
        assert_eq!(
            codec
                .decode_manifest(&negative_zero, manifest_limits(), &never_cancelled)
                .expect("negative zero has the integer value zero")
                .profiles[0]
                .memory
                .event_log_bytes,
            0
        );

        let float = replace_manifest("comptime_steps = 1", "comptime_steps = 1.0");
        assert!(matches!(
            codec.decode_manifest(&float, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnsupportedValue {
                field: "profile.comptime_steps",
                ..
            })
        ));
        let datetime = replace_manifest("reset_timeout_ns = 1", "reset_timeout_ns = 1979-05-27");
        assert!(matches!(
            codec.decode_manifest(&datetime, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnsupportedValue {
                field: "profile.reset_timeout_ns",
                ..
            })
        ));

        let mut model = codec
            .decode_manifest(MINIMAL_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("minimal manifest");
        model.profiles[0].comptime.steps = maximum + 1;
        assert_eq!(
            codec.canonical_manifest(&model, manifest_limits(), &never_cancelled),
            Err(DecodeError::UnsupportedValue {
                field: "comptime_steps",
                expected: "TOML signed 64-bit integer"
            })
        );
    }

    #[test]
    fn absolute_byte_ceiling_bounds_the_noncooperative_parser_region() {
        let codec = CanonicalPackageCodec::new();
        let maximum =
            usize::try_from(MAX_MANIFEST_TOML_BYTES).expect("manifest ceiling fits usize");
        let mut at_ceiling = Vec::new();
        at_ceiling
            .try_reserve_exact(maximum)
            .expect("test input allocation");
        at_ceiling.extend_from_slice(MINIMAL_MANIFEST);
        at_ceiling.resize(maximum, b' ');

        let mut permissive = manifest_limits();
        permissive.bytes = u64::MAX;
        let started = Instant::now();
        let decoded = codec
            .decode_manifest(&at_ceiling, permissive, &never_cancelled)
            .expect("valid TOML at the absolute ceiling");
        assert_eq!(decoded.name.as_str(), "mini");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the absolute-cap parse must stay inside the ten-second contract"
        );
        drop(at_ceiling);

        let over_ceiling = vec![b' '; maximum + 1];
        assert_eq!(
            codec.decode_manifest(&over_ceiling, permissive, &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "manifest TOML bytes",
                limit: MAX_MANIFEST_TOML_BYTES
            })
        );
        assert_eq!(
            codec.decode_lockfile(&over_ceiling, lockfile_limits(), &never_cancelled),
            Err(DecodeError::ResourceLimit {
                resource: "lockfile TOML bytes",
                limit: MAX_LOCKFILE_TOML_BYTES
            })
        );
    }

    #[test]
    fn cancellation_is_polled_before_parse_and_during_dom_projection() {
        let codec = CanonicalPackageCodec::new();
        assert_eq!(
            codec.decode_manifest(MINIMAL_MANIFEST, manifest_limits(), &|| true),
            Err(DecodeError::Cancelled)
        );

        let input_calls = Cell::new(0u32);
        let cancel_during_input = || {
            let next = input_calls.get().saturating_add(1);
            input_calls.set(next);
            next >= 5
        };
        let long_invalid_input = vec![b' '; CANCELLATION_POLL_BYTES * 16];
        assert_eq!(
            codec.decode_manifest(&long_invalid_input, manifest_limits(), &cancel_during_input),
            Err(DecodeError::Cancelled)
        );

        let projection_calls = Cell::new(0u32);
        let cancel_during_projection = || {
            let next = projection_calls.get().saturating_add(1);
            projection_calls.set(next);
            next >= 5
        };
        assert_eq!(
            codec.decode_manifest(
                MINIMAL_MANIFEST,
                manifest_limits(),
                &cancel_during_projection
            ),
            Err(DecodeError::Cancelled)
        );
        assert_eq!(projection_calls.get(), 5);

        let long_integer = format!("value = 0x{}1\n", "0".repeat(CANCELLATION_POLL_BYTES * 2));
        let document = parse_document(&long_integer).expect("long radix integer parses");
        let value = document.get_ref().get("value").expect("long integer value");
        let DeValue::Integer(integer) = value.get_ref() else {
            panic!("expected an integer DOM value");
        };
        let integer_calls = Cell::new(0u32);
        let cancel_during_integer = || {
            let next = integer_calls.get().saturating_add(1);
            integer_calls.set(next);
            next >= 2
        };
        assert_eq!(
            parse_integer(integer, value.span().start, &cancel_during_integer),
            Err(DecodeError::Cancelled)
        );
        assert_eq!(integer_calls.get(), 2);
    }

    #[test]
    fn canonical_basic_strings_escape_without_losing_values() {
        let original = "quote=\" slash=\\ tab=\t newline=\n control=\u{1}";
        let mut writer = CanonicalWriter::new(1024, &never_cancelled);
        writer
            .assignment_text("value", original)
            .expect("string encoding");
        let encoded = writer.finish().expect("encoded TOML");
        let source = std::str::from_utf8(&encoded).expect("canonical output is UTF-8");
        let document = parse_document(source).expect("canonical output parses");
        let decoded = string_value(
            document.get_ref().get("value").expect("value field"),
            "value",
        )
        .expect("string value");
        assert_eq!(decoded, original);
    }

    #[derive(Clone)]
    struct OneBundleProvider {
        bundle: PackageBundle,
    }

    impl PackageSourceProvider for OneBundleProvider {
        fn acquire(
            &self,
            locator: &PackageLocator,
            expected: &PackageIdentity,
            maximum_bytes: u64,
            maximum_manifest_bytes: u64,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<PackageBundle, ProviderError> {
            if is_cancelled() {
                return Err(ProviderError::Unavailable("cancelled".to_owned()));
            }
            if locator != &self.bundle.locator || expected != &self.bundle.identity {
                return Err(ProviderError::IdentityMismatch);
            }
            if u64::try_from(self.bundle.manifest_bytes.len()).unwrap_or(u64::MAX)
                > maximum_manifest_bytes
            {
                return Err(ProviderError::TooLarge {
                    limit: maximum_manifest_bytes,
                });
            }
            let byte_count = self
                .bundle
                .manifest_bytes
                .len()
                .checked_add(
                    self.bundle
                        .sources
                        .iter()
                        .map(|source| source.text.len())
                        .sum::<usize>(),
                )
                .ok_or(ProviderError::TooLarge {
                    limit: maximum_bytes,
                })?;
            if u64::try_from(byte_count).unwrap_or(u64::MAX) > maximum_bytes {
                return Err(ProviderError::TooLarge {
                    limit: maximum_bytes,
                });
            }
            Ok(self.bundle.clone())
        }
    }

    #[derive(Clone)]
    struct CheckedInBootstrapProvider {
        bundles: Vec<PackageBundle>,
    }

    impl PackageSourceProvider for CheckedInBootstrapProvider {
        fn acquire(
            &self,
            locator: &PackageLocator,
            expected: &PackageIdentity,
            maximum_bytes: u64,
            maximum_manifest_bytes: u64,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<PackageBundle, ProviderError> {
            if is_cancelled() {
                return Err(ProviderError::Unavailable("cancelled".to_owned()));
            }
            let bundle = self
                .bundles
                .iter()
                .find(|bundle| &bundle.locator == locator)
                .ok_or_else(|| {
                    ProviderError::Unavailable("unknown checked-in package locator".to_owned())
                })?;
            if &bundle.identity != expected {
                return Err(ProviderError::IdentityMismatch);
            }
            if u64::try_from(bundle.manifest_bytes.len()).unwrap_or(u64::MAX)
                > maximum_manifest_bytes
            {
                return Err(ProviderError::TooLarge {
                    limit: maximum_manifest_bytes,
                });
            }
            let mut byte_count = bundle.manifest_bytes.len();
            for source in &bundle.sources {
                byte_count =
                    byte_count
                        .checked_add(source.text.len())
                        .ok_or(ProviderError::TooLarge {
                            limit: maximum_bytes,
                        })?;
            }
            if u64::try_from(byte_count).unwrap_or(u64::MAX) > maximum_bytes {
                return Err(ProviderError::TooLarge {
                    limit: maximum_bytes,
                });
            }
            Ok(bundle.clone())
        }
    }

    struct RecordingCodec<'a> {
        events: &'a RefCell<Vec<&'static str>>,
    }

    impl PackageCodec for RecordingCodec<'_> {
        fn decode_manifest(
            &self,
            bytes: &[u8],
            limits: ManifestCodecLimits,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<PackageManifest, DecodeError> {
            self.events.borrow_mut().push("decode-manifest");
            CanonicalPackageCodec::new().decode_manifest(bytes, limits, is_cancelled)
        }

        fn decode_lockfile(
            &self,
            bytes: &[u8],
            limits: LockfileCodecLimits,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Lockfile, DecodeError> {
            CanonicalPackageCodec::new().decode_lockfile(bytes, limits, is_cancelled)
        }

        fn canonical_manifest(
            &self,
            manifest: &PackageManifest,
            limits: ManifestCodecLimits,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, DecodeError> {
            CanonicalPackageCodec::new().canonical_manifest(manifest, limits, is_cancelled)
        }

        fn canonical_lockfile(
            &self,
            lockfile: &Lockfile,
            limits: LockfileCodecLimits,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, DecodeError> {
            CanonicalPackageCodec::new().canonical_lockfile(lockfile, limits, is_cancelled)
        }
    }

    struct RecordingHasher<'a> {
        events: &'a RefCell<Vec<&'static str>>,
        raw_manifest: &'a [u8],
    }

    impl ContentHasher for RecordingHasher<'_> {
        fn sha256(&self, bytes: &[u8]) -> Sha256Digest {
            if bytes == self.raw_manifest {
                self.events.borrow_mut().push("raw-manifest-hash");
            }
            SoftwareSha256.sha256(bytes)
        }

        fn begin_sha256(&self) -> Box<dyn ContentDigest + '_> {
            Box::new(RecordingDigest {
                inner: SoftwareSha256.begin_sha256(),
                events: self.events,
                raw_manifest: self.raw_manifest,
                first_update: true,
            })
        }
    }

    struct RecordingDigest<'a> {
        inner: Box<dyn ContentDigest + 'a>,
        events: &'a RefCell<Vec<&'static str>>,
        raw_manifest: &'a [u8],
        first_update: bool,
    }

    impl ContentDigest for RecordingDigest<'_> {
        fn update(&mut self, bytes: &[u8]) {
            if self.first_update && bytes == self.raw_manifest {
                self.events.borrow_mut().push("raw-manifest-hash");
            }
            self.first_update = false;
            self.inner.update(bytes);
        }

        fn finish(self: Box<Self>) -> Sha256Digest {
            self.inner.finish()
        }
    }

    #[test]
    fn workspace_loader_consumes_equivalent_noncanonical_manifest_toml() {
        let codec = CanonicalPackageCodec::new();
        let hasher = SoftwareSha256;
        let manifest = codec
            .decode_manifest(EQUIVALENT_MANIFEST, manifest_limits(), &never_cancelled)
            .expect("equivalent root manifest");
        let canonical_manifest = codec
            .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
            .expect("canonical root manifest");
        assert_eq!(canonical_manifest, MINIMAL_MANIFEST);

        let source_text = "fn mini() -> unit:\n    return ()\n";
        let source_digest = hasher.sha256(source_text.as_bytes());
        let records = [PackageContentRecord {
            kind: PackageContentKind::Source,
            path: "mini.wr",
            digest: source_digest,
        }];
        let package_digest =
            package_content_digest(&canonical_manifest, &records, &hasher, &never_cancelled)
                .expect("package content digest");
        let identity = PackageIdentity {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            source_digest: package_digest,
        };
        let locator = PackageLocator::Workspace {
            path: "packages/mini".to_owned(),
        };
        let lockfile = Lockfile {
            schema: LOCKFILE_SCHEMA_VERSION,
            root: identity.clone(),
            packages: vec![LockedPackage {
                identity: identity.clone(),
                locator: locator.clone(),
                dependencies: Vec::new(),
                manifest_digest: hasher.sha256(&canonical_manifest),
            }],
        };
        let canonical_lockfile = codec
            .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
            .expect("canonical test lockfile");
        let provider = OneBundleProvider {
            bundle: PackageBundle {
                identity,
                locator: locator.clone(),
                manifest_bytes: EQUIVALENT_MANIFEST.to_vec(),
                sources: vec![SourceInput {
                    path: "mini.wr".to_owned(),
                    text: source_text.to_owned(),
                    digest: source_digest,
                }],
                scenarios: Vec::new(),
            },
        };
        let events = RefCell::new(Vec::new());
        let recording_codec = RecordingCodec { events: &events };
        let recording_hasher = RecordingHasher {
            events: &events,
            raw_manifest: EQUIVALENT_MANIFEST,
        };

        let workspace = CanonicalWorkspaceLoader::new()
            .load(
                LoadRequest {
                    root_locator: locator,
                    root_manifest_bytes: EQUIVALENT_MANIFEST,
                    lockfile_bytes: &canonical_lockfile,
                    provider: &provider,
                    hasher: &recording_hasher,
                    codec: &recording_codec,
                    limits: LoadLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("loader accepts semantically equivalent manifest syntax");
        assert_eq!(workspace.root_manifest(), &manifest);
        assert_eq!(workspace.sources().len(), 1);
        assert_eq!(
            events.into_inner(),
            [
                "raw-manifest-hash",
                "decode-manifest",
                "raw-manifest-hash",
                "decode-manifest",
                "raw-manifest-hash",
                "decode-manifest",
            ]
        );
    }

    #[test]
    fn workspace_loader_seals_the_checked_in_minimum_image_and_toolchain_core() {
        let codec = CanonicalPackageCodec::new();
        let hasher = SoftwareSha256;
        let lockfile = codec
            .decode_lockfile(
                CHECKED_IN_MINIMUM_IMAGE_LOCKFILE,
                lockfile_limits(),
                &never_cancelled,
            )
            .expect("checked-in lockfile");
        let root = lockfile
            .packages
            .iter()
            .find(|package| package.identity == lockfile.root)
            .expect("locked root package");
        let core = lockfile
            .packages
            .iter()
            .find(|package| package.identity.name.as_str() == "wrela-core")
            .expect("locked core package");
        let root_locator = PackageLocator::Workspace {
            path: ".".to_owned(),
        };
        assert_eq!(root.locator, root_locator);
        let provider = CheckedInBootstrapProvider {
            bundles: vec![
                PackageBundle {
                    identity: root.identity.clone(),
                    locator: root_locator.clone(),
                    manifest_bytes: CHECKED_IN_MINIMUM_IMAGE_MANIFEST.to_vec(),
                    sources: vec![SourceInput {
                        path: "bootstrap/image.wr".to_owned(),
                        text: std::str::from_utf8(CHECKED_IN_MINIMUM_IMAGE_SOURCE)
                            .expect("application source UTF-8")
                            .to_owned(),
                        digest: hasher.sha256(CHECKED_IN_MINIMUM_IMAGE_SOURCE),
                    }],
                    scenarios: Vec::new(),
                },
                PackageBundle {
                    identity: core.identity.clone(),
                    locator: core.locator.clone(),
                    manifest_bytes: CHECKED_IN_CORE_MANIFEST.to_vec(),
                    sources: vec![
                        SourceInput {
                            path: "image.wr".to_owned(),
                            text: std::str::from_utf8(CHECKED_IN_CORE_SOURCE)
                                .expect("core image source UTF-8")
                                .to_owned(),
                            digest: hasher.sha256(CHECKED_IN_CORE_SOURCE),
                        },
                        SourceInput {
                            path: "ops.wr".to_owned(),
                            text: std::str::from_utf8(CHECKED_IN_CORE_OPS_SOURCE)
                                .expect("core ops source UTF-8")
                                .to_owned(),
                            digest: hasher.sha256(CHECKED_IN_CORE_OPS_SOURCE),
                        },
                        SourceInput {
                            path: "result.wr".to_owned(),
                            text: std::str::from_utf8(CHECKED_IN_CORE_RESULT_SOURCE)
                                .expect("core result source UTF-8")
                                .to_owned(),
                            digest: hasher.sha256(CHECKED_IN_CORE_RESULT_SOURCE),
                        },
                        SourceInput {
                            path: "time.wr".to_owned(),
                            text: std::str::from_utf8(CHECKED_IN_CORE_TIME_SOURCE)
                                .expect("core time source UTF-8")
                                .to_owned(),
                            digest: hasher.sha256(CHECKED_IN_CORE_TIME_SOURCE),
                        },
                    ],
                    scenarios: Vec::new(),
                },
            ],
        };

        let workspace = CanonicalWorkspaceLoader::new()
            .load(
                LoadRequest {
                    root_locator,
                    root_manifest_bytes: CHECKED_IN_MINIMUM_IMAGE_MANIFEST,
                    lockfile_bytes: CHECKED_IN_MINIMUM_IMAGE_LOCKFILE,
                    provider: &provider,
                    hasher: &hasher,
                    codec: &codec,
                    limits: LoadLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("checked-in bootstrap workspace loads and seals");
        assert_eq!(
            workspace.canonical_lockfile(),
            CHECKED_IN_MINIMUM_IMAGE_LOCKFILE
        );
        assert_eq!(workspace.graph().packages().len(), 2);
        assert_eq!(workspace.graph().modules().len(), 5);
        assert_eq!(workspace.sources().len(), 5);
        assert_eq!(workspace.root_manifest().name.as_str(), "bootstrap-image");
        assert_eq!(
            workspace
                .image("bootstrap")
                .map(|image| image.entry.as_str()),
            Some("boot")
        );
        assert!(workspace.profile("development").is_some());
        let root_record = workspace
            .graph()
            .package(workspace.graph().root())
            .expect("loaded root package");
        assert_eq!(root_record.identity, lockfile.root);
        assert_eq!(root_record.dependencies.len(), 1);
        assert_eq!(root_record.dependencies[0].alias.as_str(), "core");
        assert!(
            workspace
                .graph()
                .modules()
                .iter()
                .any(|module| module.path.dotted() == "bootstrap.image")
        );
        assert!(
            workspace
                .graph()
                .modules()
                .iter()
                .any(|module| module.path.dotted() == "image")
        );
    }
}
