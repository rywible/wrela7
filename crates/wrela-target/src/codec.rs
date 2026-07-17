use std::collections::BTreeSet;

use crate::{
    AARCH64_UEFI_COFF_MACHINE, AARCH64_UEFI_ENTRY_SYMBOL, AARCH64_UEFI_FIRMWARE_CODE,
    AARCH64_UEFI_FIRMWARE_VARIABLES, AARCH64_UEFI_LLVM_CPU, AARCH64_UEFI_LLVM_DATA_LAYOUT,
    AARCH64_UEFI_LLVM_FEATURES, AARCH64_UEFI_LLVM_TRIPLE, AARCH64_UEFI_QEMU_ACCELERATOR,
    AARCH64_UEFI_QEMU_MACHINE, AARCH64_UEFI_REVISION, AARCH64_UEFI_RUNTIME_ABI_VERSION,
    AARCH64_UEFI_RUNTIME_OBJECT, AARCH64_UEFI_SUBSYSTEM, AARCH64_UEFI_TARGET_NAME,
    TargetDecodeError, TargetDecodeLimits, TargetDecodeRequest, TargetPackage, TargetPackageCodec,
};

const CANONICAL_BYTES: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
const CANCELLATION_POLL_BYTES: usize = 1024;

/// Canonical schema-1 codec for the revision 0.1 AArch64 QEMU `virt` target.
///
/// The decoder accepts the small TOML subset needed to distinguish malformed,
/// duplicate, unknown, and unsupported input. [`crate::decode_and_verify_target_package`]
/// then requires the original bytes to equal this codec's canonical encoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalTargetPackageCodec;

impl CanonicalTargetPackageCodec {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl TargetPackageCodec for CanonicalTargetPackageCodec {
    fn decode(
        &self,
        request: TargetDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TargetPackage, TargetDecodeError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        check_byte_limit(request.toml_bytes, request.limits.bytes)?;

        poll_input_bytes(request.toml_bytes, is_cancelled)?;
        let source =
            std::str::from_utf8(request.toml_bytes).map_err(|_| TargetDecodeError::InvalidUtf8)?;
        let mut parser = Parser::new(request.limits, is_cancelled);
        parser.parse(source)?;
        check_cancelled(is_cancelled)?;

        let package = TargetPackage::aarch64_qemu_virt_uefi(request.verified_digest);
        package
            .validate()
            .map_err(TargetDecodeError::InvalidPackage)?;
        if package.identity() != request.expected_identity {
            return Err(TargetDecodeError::IdentityMismatch);
        }
        Ok(package)
    }

    fn encode_canonical(
        &self,
        package: &TargetPackage,
        limits: TargetDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TargetDecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        package
            .validate()
            .map_err(TargetDecodeError::InvalidPackage)?;
        check_byte_limit(CANONICAL_BYTES, limits.bytes)?;
        check_count_limit(
            "string bytes",
            required_string_bytes(),
            u64::from(limits.string_bytes),
        )?;
        check_count_limit(
            "MMIO bindings",
            package.semantic().mmio_bindings().len(),
            u64::from(limits.mmio_bindings),
        )?;
        check_count_limit(
            "LLVM features",
            package.backend().llvm_features().len(),
            u64::from(limits.llvm_features),
        )?;
        let canonical_source =
            std::str::from_utf8(CANONICAL_BYTES).map_err(|_| TargetDecodeError::InvalidUtf8)?;
        Parser::new(limits, is_cancelled).parse(canonical_source)?;
        check_cancelled(is_cancelled)?;
        Ok(CANONICAL_BYTES.to_vec())
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), TargetDecodeError> {
    if is_cancelled() {
        Err(TargetDecodeError::Cancelled)
    } else {
        Ok(())
    }
}

fn poll_input_bytes(
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TargetDecodeError> {
    for _ in bytes.chunks(CANCELLATION_POLL_BYTES) {
        check_cancelled(is_cancelled)?;
    }
    Ok(())
}

fn check_byte_limit(bytes: &[u8], limit: u64) -> Result<(), TargetDecodeError> {
    let actual = u64::try_from(bytes.len()).map_err(|_| TargetDecodeError::TooLarge {
        limit,
        actual: u64::MAX,
    })?;
    if actual > limit {
        Err(TargetDecodeError::TooLarge { limit, actual })
    } else {
        Ok(())
    }
}

fn check_count_limit(
    resource: &'static str,
    actual: usize,
    limit: u64,
) -> Result<(), TargetDecodeError> {
    let actual = u64::try_from(actual).unwrap_or(u64::MAX);
    if actual > limit {
        Err(TargetDecodeError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Root,
    Semantic,
    SemanticInterrupts,
    SemanticPlatform,
    Backend,
    BackendInterrupts,
    BackendLink,
    Runner,
}

impl Section {
    fn from_header(header: &str) -> Option<Self> {
        match header {
            "semantic" => Some(Self::Semantic),
            "semantic.interrupts" => Some(Self::SemanticInterrupts),
            "semantic.platform" => Some(Self::SemanticPlatform),
            "backend" => Some(Self::Backend),
            "backend.interrupts" => Some(Self::BackendInterrupts),
            "backend.link" => Some(Self::BackendLink),
            "runner" => Some(Self::Runner),
            _ => None,
        }
    }

    const fn path_prefix(self) -> &'static str {
        match self {
            Self::Root => "",
            Self::Semantic => "semantic.",
            Self::SemanticInterrupts => "semantic.interrupts.",
            Self::SemanticPlatform => "semantic.platform.",
            Self::Backend => "backend.",
            Self::BackendInterrupts => "backend.interrupts.",
            Self::BackendLink => "backend.link.",
            Self::Runner => "runner.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Expected {
    String(&'static str),
    Bool(bool),
    Integer {
        value: u64,
        spelling: &'static str,
    },
    Strings {
        values: &'static [&'static str],
        spelling: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
struct FieldSpec {
    section: Section,
    key: &'static str,
    path: &'static str,
    expected: Expected,
}

const fn string(
    section: Section,
    key: &'static str,
    path: &'static str,
    expected: &'static str,
) -> FieldSpec {
    FieldSpec {
        section,
        key,
        path,
        expected: Expected::String(expected),
    }
}

const fn boolean(
    section: Section,
    key: &'static str,
    path: &'static str,
    expected: bool,
) -> FieldSpec {
    FieldSpec {
        section,
        key,
        path,
        expected: Expected::Bool(expected),
    }
}

const fn integer(
    section: Section,
    key: &'static str,
    path: &'static str,
    expected: u64,
    spelling: &'static str,
) -> FieldSpec {
    FieldSpec {
        section,
        key,
        path,
        expected: Expected::Integer {
            value: expected,
            spelling,
        },
    }
}

const fn strings(
    section: Section,
    key: &'static str,
    path: &'static str,
    expected: &'static [&'static str],
    spelling: &'static str,
) -> FieldSpec {
    FieldSpec {
        section,
        key,
        path,
        expected: Expected::Strings {
            values: expected,
            spelling,
        },
    }
}

const FIELDS: &[FieldSpec] = &[
    integer(Section::Root, "schema", "schema", 1, "1"),
    string(Section::Root, "name", "name", AARCH64_UEFI_TARGET_NAME),
    string(
        Section::Semantic,
        "architecture",
        "semantic.architecture",
        "aarch64",
    ),
    integer(
        Section::Semantic,
        "pointer_width",
        "semantic.pointer_width",
        64,
        "64",
    ),
    string(
        Section::Semantic,
        "endianness",
        "semantic.endianness",
        "little",
    ),
    string(
        Section::Semantic,
        "uefi_revision",
        "semantic.uefi_revision",
        AARCH64_UEFI_REVISION,
    ),
    boolean(
        Section::Semantic,
        "coherent_dma",
        "semantic.coherent_dma",
        false,
    ),
    boolean(
        Section::Semantic,
        "iommu_available",
        "semantic.iommu_available",
        false,
    ),
    string(
        Section::SemanticInterrupts,
        "controller",
        "semantic.interrupts.controller",
        "gic-v3",
    ),
    boolean(
        Section::SemanticInterrupts,
        "nested_preemption",
        "semantic.interrupts.nested_preemption",
        false,
    ),
    string(
        Section::SemanticPlatform,
        "machine",
        "semantic.platform.machine",
        "qemu-virt",
    ),
    integer(
        Section::SemanticPlatform,
        "virtio_mmio_base",
        "semantic.platform.virtio_mmio_base",
        0x0a00_0000,
        "0x0a000000",
    ),
    integer(
        Section::SemanticPlatform,
        "virtio_mmio_size",
        "semantic.platform.virtio_mmio_size",
        0x200,
        "0x200",
    ),
    integer(
        Section::SemanticPlatform,
        "virtio_mmio_gic_spi",
        "semantic.platform.virtio_mmio_gic_spi",
        16,
        "16",
    ),
    integer(
        Section::SemanticPlatform,
        "virtio_mmio_gic_intid",
        "semantic.platform.virtio_mmio_gic_intid",
        48,
        "48",
    ),
    string(
        Section::Backend,
        "llvm_triple",
        "backend.llvm_triple",
        AARCH64_UEFI_LLVM_TRIPLE,
    ),
    string(
        Section::Backend,
        "llvm_data_layout",
        "backend.llvm_data_layout",
        AARCH64_UEFI_LLVM_DATA_LAYOUT,
    ),
    string(
        Section::Backend,
        "llvm_cpu",
        "backend.llvm_cpu",
        AARCH64_UEFI_LLVM_CPU,
    ),
    strings(
        Section::Backend,
        "llvm_features",
        "backend.llvm_features",
        AARCH64_UEFI_LLVM_FEATURES,
        "[\"+reserve-x18\"]",
    ),
    string(
        Section::Backend,
        "coff_machine",
        "backend.coff_machine",
        AARCH64_UEFI_COFF_MACHINE,
    ),
    string(
        Section::Backend,
        "object_format",
        "backend.object_format",
        "coff",
    ),
    string(
        Section::Backend,
        "image_format",
        "backend.image_format",
        "pe-coff",
    ),
    string(
        Section::Backend,
        "subsystem",
        "backend.subsystem",
        AARCH64_UEFI_SUBSYSTEM,
    ),
    string(
        Section::Backend,
        "entry",
        "backend.entry",
        AARCH64_UEFI_ENTRY_SYMBOL,
    ),
    string(
        Section::Backend,
        "runtime_object",
        "backend.runtime_object",
        AARCH64_UEFI_RUNTIME_OBJECT,
    ),
    integer(
        Section::Backend,
        "runtime_abi_version",
        "backend.runtime_abi_version",
        AARCH64_UEFI_RUNTIME_ABI_VERSION as u64,
        "2",
    ),
    string(
        Section::BackendInterrupts,
        "controller",
        "backend.interrupts.controller",
        "gic-v3",
    ),
    integer(
        Section::BackendInterrupts,
        "vector_table_alignment",
        "backend.interrupts.vector_table_alignment",
        2048,
        "2048",
    ),
    integer(
        Section::BackendInterrupts,
        "stack_alignment",
        "backend.interrupts.stack_alignment",
        16,
        "16",
    ),
    boolean(
        Section::BackendInterrupts,
        "nested_preemption",
        "backend.interrupts.nested_preemption",
        false,
    ),
    boolean(
        Section::BackendInterrupts,
        "saves_simd",
        "backend.interrupts.saves_simd",
        false,
    ),
    boolean(
        Section::BackendInterrupts,
        "cpu_irq_masked_during_handler",
        "backend.interrupts.cpu_irq_masked_during_handler",
        true,
    ),
    boolean(
        Section::BackendInterrupts,
        "eoi_deactivates",
        "backend.interrupts.eoi_deactivates",
        true,
    ),
    integer(
        Section::BackendInterrupts,
        "spurious_global_id_minimum",
        "backend.interrupts.spurious_global_id_minimum",
        1020,
        "1020",
    ),
    string(
        Section::BackendLink,
        "driver",
        "backend.link.driver",
        "lld-coff",
    ),
    boolean(
        Section::BackendLink,
        "dynamic_linking",
        "backend.link.dynamic_linking",
        false,
    ),
    boolean(
        Section::BackendLink,
        "default_libraries",
        "backend.link.default_libraries",
        false,
    ),
    boolean(
        Section::BackendLink,
        "relocations",
        "backend.link.relocations",
        true,
    ),
    string(
        Section::Runner,
        "emulator",
        "runner.emulator",
        "qemu-system-aarch64",
    ),
    string(
        Section::Runner,
        "machine",
        "runner.machine",
        AARCH64_UEFI_QEMU_MACHINE,
    ),
    string(Section::Runner, "cpu", "runner.cpu", AARCH64_UEFI_LLVM_CPU),
    string(
        Section::Runner,
        "accelerator",
        "runner.accelerator",
        AARCH64_UEFI_QEMU_ACCELERATOR,
    ),
    integer(
        Section::Runner,
        "memory_mib",
        "runner.memory_mib",
        512,
        "512",
    ),
    integer(
        Section::Runner,
        "virtual_cpus",
        "runner.virtual_cpus",
        1,
        "1",
    ),
    string(
        Section::Runner,
        "firmware_code",
        "runner.firmware_code",
        AARCH64_UEFI_FIRMWARE_CODE,
    ),
    string(
        Section::Runner,
        "firmware_variables_template",
        "runner.firmware_variables_template",
        AARCH64_UEFI_FIRMWARE_VARIABLES,
    ),
    string(Section::Runner, "boot", "runner.boot", "virtio-block-fat"),
    string(
        Section::Runner,
        "test_transport",
        "runner.test_transport",
        "pl011-framed",
    ),
];

struct Parser<'a> {
    limits: TargetDecodeLimits,
    is_cancelled: &'a dyn Fn() -> bool,
    section: Section,
    seen_sections: BTreeSet<Section>,
    seen_fields: BTreeSet<&'static str>,
    string_bytes: usize,
}

impl<'a> Parser<'a> {
    fn new(limits: TargetDecodeLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
            is_cancelled,
            section: Section::Root,
            seen_sections: BTreeSet::new(),
            seen_fields: BTreeSet::new(),
            string_bytes: 0,
        }
    }

    fn parse(&mut self, source: &str) -> Result<(), TargetDecodeError> {
        let bytes = source.as_bytes();
        let mut line_start = 0;
        for (offset, byte) in bytes.iter().enumerate() {
            poll_cancellation(offset, self.is_cancelled)?;
            if *byte == b'\n' {
                self.parse_line(&source[line_start..offset], line_start)?;
                line_start = offset + 1;
            }
        }
        if line_start < source.len() {
            self.parse_line(&source[line_start..], line_start)?;
        }
        check_cancelled(self.is_cancelled)?;
        for field in FIELDS {
            if !self.seen_fields.contains(field.path) {
                return Err(TargetDecodeError::MissingField(field.path));
            }
        }
        Ok(())
    }

    fn parse_line(&mut self, line: &str, byte_offset: usize) -> Result<(), TargetDecodeError> {
        let content =
            trim_toml_whitespace(strip_comment(line, self.is_cancelled)?, self.is_cancelled)?;
        if content.is_empty() {
            return Ok(());
        }
        if content.starts_with('[') {
            return self.parse_header(content, byte_offset);
        }

        let (key, value) = content
            .split_once('=')
            .ok_or_else(|| malformed(byte_offset, "expected a key/value assignment"))?;
        let key = trim_toml_whitespace(key, self.is_cancelled)?;
        if key.is_empty() {
            return Err(malformed(byte_offset, "assignment key is empty"));
        }
        let Some(field) = FIELDS
            .iter()
            .find(|field| field.section == self.section && field.key == key)
        else {
            return Err(TargetDecodeError::UnknownField(field_label(
                self.section,
                key,
            )));
        };
        if !self.seen_fields.insert(field.path) {
            return Err(TargetDecodeError::DuplicateKey(field.path.to_owned()));
        }
        self.check_value(
            field,
            trim_toml_whitespace(value, self.is_cancelled)?,
            byte_offset,
        )
    }

    fn parse_header(&mut self, content: &str, byte_offset: usize) -> Result<(), TargetDecodeError> {
        if !content.ends_with(']') || content.starts_with("[[") || content.ends_with("]]") {
            return Err(malformed(byte_offset, "invalid table header"));
        }
        let header = &content[1..content.len() - 1];
        let Some(section) = Section::from_header(header) else {
            return Err(TargetDecodeError::UnknownField(bounded_label(content)));
        };
        if !self.seen_sections.insert(section) {
            return Err(TargetDecodeError::DuplicateKey(bounded_label(content)));
        }
        self.section = section;
        Ok(())
    }

    fn check_value(
        &mut self,
        field: &FieldSpec,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), TargetDecodeError> {
        match field.expected {
            Expected::String(expected) => {
                let actual = parse_basic_string(value, byte_offset, self.is_cancelled)?;
                self.add_string_bytes(actual.len())?;
                if actual != expected {
                    return Err(unsupported(field.path, expected));
                }
            }
            Expected::Bool(expected) => {
                let actual = parse_bool(value, byte_offset)?;
                if actual != expected {
                    return Err(unsupported(
                        field.path,
                        if expected { "true" } else { "false" },
                    ));
                }
            }
            Expected::Integer {
                value: expected,
                spelling,
            } => {
                let actual = parse_integer(value, byte_offset, self.is_cancelled)?;
                if actual != expected {
                    return Err(unsupported(field.path, spelling));
                }
            }
            Expected::Strings { values, spelling } => {
                let actual = self.parse_string_array(value, byte_offset)?;
                if actual.as_slice() != values {
                    return Err(unsupported(field.path, spelling));
                }
            }
        }
        Ok(())
    }

    fn parse_string_array<'s>(
        &mut self,
        value: &'s str,
        byte_offset: usize,
    ) -> Result<Vec<&'s str>, TargetDecodeError> {
        let Some(inner) = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            return Err(malformed(byte_offset, "expected an array of strings"));
        };
        let bytes = inner.as_bytes();
        let mut values = Vec::new();
        let mut cursor = 0;
        loop {
            cursor = skip_ascii_whitespace(bytes, cursor, self.is_cancelled)?;
            if cursor == bytes.len() {
                break;
            }
            if bytes[cursor] != b'"' {
                return Err(malformed(byte_offset + cursor, "expected a quoted string"));
            }
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                poll_cancellation(cursor - start, self.is_cancelled)?;
                cursor += 1;
            }
            if cursor == bytes.len() {
                return Err(malformed(byte_offset + start, "unterminated string"));
            }
            let parsed = parse_basic_string(
                &inner[start..=cursor],
                byte_offset + start,
                self.is_cancelled,
            )?;
            let next_count = values.len().saturating_add(1);
            check_count_limit(
                "LLVM features",
                next_count,
                u64::from(self.limits.llvm_features),
            )?;
            self.add_string_bytes(parsed.len())?;
            values.push(parsed);
            cursor += 1;
            cursor = skip_ascii_whitespace(bytes, cursor, self.is_cancelled)?;
            if cursor == bytes.len() {
                break;
            }
            if bytes[cursor] != b',' {
                return Err(malformed(byte_offset + cursor, "expected an array comma"));
            }
            cursor += 1;
            let after_comma = skip_ascii_whitespace(bytes, cursor, self.is_cancelled)?;
            if after_comma == bytes.len() {
                break;
            }
            cursor = after_comma;
        }
        Ok(values)
    }

    fn add_string_bytes(&mut self, amount: usize) -> Result<(), TargetDecodeError> {
        self.string_bytes = self.string_bytes.saturating_add(amount);
        check_count_limit(
            "string bytes",
            self.string_bytes,
            u64::from(self.limits.string_bytes),
        )
    }
}

fn strip_comment<'a>(
    line: &'a str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, TargetDecodeError> {
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        if in_string && escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'#' if !in_string => return Ok(&line[..index]),
            _ => {}
        }
    }
    Ok(line)
}

fn parse_basic_string<'a>(
    value: &'a str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, TargetDecodeError> {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return Err(malformed(byte_offset, "expected a quoted string"));
    };
    for (index, character) in inner.char_indices() {
        poll_cancellation(index, is_cancelled)?;
        if character == '"' || character == '\\' || character.is_control() {
            return Err(malformed(
                byte_offset,
                "string escapes, quotes, and control characters are unsupported",
            ));
        }
    }
    Ok(inner)
}

fn parse_bool(value: &str, byte_offset: usize) -> Result<bool, TargetDecodeError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(malformed(byte_offset, "expected a boolean")),
    }
}

fn parse_integer(
    value: &str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, TargetDecodeError> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .map_or((value, 10), |digits| (digits, 16));
    if digits.is_empty() || (radix == 10 && digits.len() > 1 && digits.starts_with('0')) {
        return Err(malformed(byte_offset, "invalid unsigned integer"));
    }
    let mut result = 0_u64;
    let mut previous_was_digit = false;
    for (index, byte) in digits.bytes().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        if byte == b'_' {
            if !previous_was_digit || index + 1 == digits.len() {
                return Err(malformed(byte_offset + index, "invalid integer separator"));
            }
            previous_was_digit = false;
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => u64::from(byte - b'a' + 10),
            b'A'..=b'F' if radix == 16 => u64::from(byte - b'A' + 10),
            _ => return Err(malformed(byte_offset + index, "invalid unsigned integer")),
        };
        if digit >= radix {
            return Err(malformed(byte_offset + index, "invalid unsigned integer"));
        }
        result = result
            .checked_mul(radix)
            .and_then(|current| current.checked_add(digit))
            .ok_or_else(|| malformed(byte_offset + index, "unsigned integer overflow"))?;
        previous_was_digit = true;
    }
    if !previous_was_digit {
        return Err(malformed(byte_offset, "invalid unsigned integer"));
    }
    Ok(result)
}

fn skip_ascii_whitespace(
    bytes: &[u8],
    mut cursor: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, TargetDecodeError> {
    let start = cursor;
    while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\n') {
        poll_cancellation(cursor - start, is_cancelled)?;
        cursor += 1;
    }
    Ok(cursor)
}

fn trim_toml_whitespace<'a>(
    value: &'a str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, TargetDecodeError> {
    let bytes = value.as_bytes();
    let mut start = 0;
    while start < bytes.len() && matches!(bytes[start], b' ' | b'\t' | b'\r') {
        poll_cancellation(start, is_cancelled)?;
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && matches!(bytes[end - 1], b' ' | b'\t' | b'\r') {
        poll_cancellation(bytes.len() - end, is_cancelled)?;
        end -= 1;
    }
    Ok(&value[start..end])
}

fn poll_cancellation(
    bytes_since_start: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TargetDecodeError> {
    if bytes_since_start & (CANCELLATION_POLL_BYTES - 1) == 0 {
        check_cancelled(is_cancelled)?;
    }
    Ok(())
}

fn malformed(byte_offset: usize, message: &str) -> TargetDecodeError {
    TargetDecodeError::Malformed {
        byte_offset,
        message: message.to_owned(),
    }
}

fn unsupported(field: &'static str, expected: &'static str) -> TargetDecodeError {
    TargetDecodeError::UnsupportedValue { field, expected }
}

fn field_label(section: Section, key: &str) -> String {
    let mut label = section.path_prefix().to_owned();
    label.push_str(&bounded_label(key));
    label
}

fn bounded_label(value: &str) -> String {
    const MAX_CHARS: usize = 128;
    let mut characters = value.chars();
    let mut label = characters.by_ref().take(MAX_CHARS).collect::<String>();
    if characters.next().is_some() {
        label.push('…');
    }
    label
}

fn required_string_bytes() -> usize {
    FIELDS
        .iter()
        .map(|field| match field.expected {
            Expected::String(value) => value.len(),
            Expected::Strings { values, .. } => values.iter().map(|value| value.len()).sum(),
            Expected::Bool(_) | Expected::Integer { .. } => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{CANONICAL_BYTES, CanonicalTargetPackageCodec, required_string_bytes};
    use crate::{
        MAX_TARGET_LLVM_FEATURES, MAX_TARGET_MMIO_BINDINGS, MAX_TARGET_PACKAGE_BYTES,
        MAX_TARGET_STRING_BYTES, Sha256Digest, TargetDecodeError, TargetDecodeLimits,
        TargetDecodeRequest, TargetPackage, TargetPackageCodec, decode_and_verify_target_package,
    };
    use wrela_build_model::TargetIdentity;

    const REPRESENTATIVE: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/representative.toml");
    const MINIMUM: &[u8] = include_bytes!("../../../tests/contracts/target/v1/minimum.toml");
    const NONCANONICAL: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/noncanonical.toml");
    const DUPLICATE: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/duplicate.toml");
    const UNKNOWN: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/unknown.toml");
    const MALFORMED: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/malformed.toml");
    const WRONG_IDENTITY: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/wrong-identity.toml");
    const WRONG_VALUE: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/wrong-value.toml");
    const OVER_FEATURE_LIMIT: &[u8] =
        include_bytes!("../../../tests/contracts/target/v1/invalid/over-feature-limit.toml");

    fn digest() -> Sha256Digest {
        Sha256Digest::from_bytes([0x5a; 32])
    }

    fn replaced(needle: &str, replacement: &str) -> Vec<u8> {
        let source = std::str::from_utf8(CANONICAL_BYTES).expect("canonical fixture is UTF-8");
        assert!(source.contains(needle), "fixture omits {needle:?}");
        source.replacen(needle, replacement, 1).into_bytes()
    }

    fn decode(
        bytes: &[u8],
        limits: TargetDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TargetPackage, TargetDecodeError> {
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        CanonicalTargetPackageCodec.decode(
            TargetDecodeRequest {
                toml_bytes: bytes,
                expected_identity: &identity,
                verified_digest: digest(),
                limits,
            },
            is_cancelled,
        )
    }

    fn decode_and_verify(
        bytes: &[u8],
        expected_identity: &TargetIdentity,
        limits: TargetDecodeLimits,
    ) -> Result<TargetPackage, TargetDecodeError> {
        decode_and_verify_target_package(
            &CanonicalTargetPackageCodec,
            TargetDecodeRequest {
                toml_bytes: bytes,
                expected_identity,
                verified_digest: digest(),
                limits,
            },
            &|| false,
        )
    }

    #[test]
    fn production_target_decodes_and_reencodes_exactly() {
        assert_eq!(REPRESENTATIVE, CANONICAL_BYTES);
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        let package = decode_and_verify(CANONICAL_BYTES, &identity, TargetDecodeLimits::standard())
            .expect("production target must decode");
        let encoded = CanonicalTargetPackageCodec
            .encode_canonical(&package, TargetDecodeLimits::standard(), &|| false)
            .expect("production target must encode");
        assert_eq!(encoded, CANONICAL_BYTES);
    }

    #[test]
    fn minimum_complete_syntax_decodes_but_is_not_canonical() {
        let package = decode(MINIMUM, TargetDecodeLimits::standard(), &|| false)
            .expect("all required schema-1 fields are present");
        assert_eq!(
            CanonicalTargetPackageCodec
                .encode_canonical(&package, TargetDecodeLimits::standard(), &|| false)
                .expect("canonical encoding"),
            CANONICAL_BYTES
        );
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        assert_eq!(
            decode_and_verify(MINIMUM, &identity, TargetDecodeLimits::standard()),
            Err(TargetDecodeError::NonCanonical)
        );
    }

    #[test]
    fn noncanonical_equivalent_package_is_rejected_by_consumer_boundary() {
        decode(NONCANONICAL, TargetDecodeLimits::standard(), &|| false)
            .expect("noncanonical syntax still has exact schema values");
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        assert_eq!(
            decode_and_verify(NONCANONICAL, &identity, TargetDecodeLimits::standard()),
            Err(TargetDecodeError::NonCanonical)
        );
    }

    #[test]
    fn duplicate_unknown_malformed_and_utf8_inputs_are_distinct() {
        assert_eq!(
            decode(DUPLICATE, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::DuplicateKey("schema".to_owned()))
        );
        assert_eq!(
            decode(UNKNOWN, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::UnknownField("future_schema".to_owned()))
        );
        assert!(matches!(
            decode(MALFORMED, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::Malformed { .. })
        ));
        assert_eq!(
            decode(&[0xff], TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::InvalidUtf8)
        );

        let mut trailing_field = CANONICAL_BYTES.to_vec();
        trailing_field.extend_from_slice(b"unexpected = true\n");
        assert_eq!(
            decode(&trailing_field, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::UnknownField(
                "runner.unexpected".to_owned()
            ))
        );
    }

    #[test]
    fn unsupported_identity_and_enum_values_are_rejected() {
        assert_eq!(
            decode(WRONG_IDENTITY, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::UnsupportedValue {
                field: "name",
                expected: "aarch64-qemu-virt-uefi",
            })
        );
        assert_eq!(
            decode(WRONG_VALUE, TargetDecodeLimits::standard(), &|| false),
            Err(TargetDecodeError::UnsupportedValue {
                field: "semantic.architecture",
                expected: "aarch64",
            })
        );
    }

    #[test]
    fn runtime_abi_entry_and_firmware_manifest_drift_is_rejected() {
        for (bytes, field, expected) in [
            (
                replaced("runtime_abi_version = 2", "runtime_abi_version = 1"),
                "backend.runtime_abi_version",
                "2",
            ),
            (
                replaced("entry = \"wrela_image_entry\"", "entry = \"other_entry\""),
                "backend.entry",
                crate::AARCH64_UEFI_ENTRY_SYMBOL,
            ),
            (
                replaced(
                    "runtime_object = \"runtime/wrela-runtime-aarch64.obj\"",
                    "runtime_object = \"runtime/other.obj\"",
                ),
                "backend.runtime_object",
                crate::AARCH64_UEFI_RUNTIME_OBJECT,
            ),
            (
                replaced(
                    "firmware_code = \"firmware/QEMU_EFI.fd\"",
                    "firmware_code = \"firmware/other.fd\"",
                ),
                "runner.firmware_code",
                crate::AARCH64_UEFI_FIRMWARE_CODE,
            ),
        ] {
            assert_eq!(
                decode(&bytes, TargetDecodeLimits::standard(), &|| false),
                Err(TargetDecodeError::UnsupportedValue { field, expected })
            );
        }
    }

    #[test]
    fn byte_and_string_limits_accept_exact_and_reject_over_limit() {
        let mut limits = TargetDecodeLimits::standard();
        limits.bytes = u64::try_from(CANONICAL_BYTES.len()).expect("fixture length fits u64");
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        let package =
            decode_and_verify(CANONICAL_BYTES, &identity, limits).expect("exact byte limit");
        CanonicalTargetPackageCodec
            .encode_canonical(&package, limits, &|| false)
            .expect("encoder accepts exact byte limit");

        limits.bytes -= 1;
        assert_eq!(
            decode(CANONICAL_BYTES, limits, &|| false),
            Err(TargetDecodeError::TooLarge {
                limit: limits.bytes,
                actual: u64::try_from(CANONICAL_BYTES.len()).expect("fixture length fits u64"),
            })
        );
        assert_eq!(
            CanonicalTargetPackageCodec.encode_canonical(&package, limits, &|| false),
            Err(TargetDecodeError::TooLarge {
                limit: limits.bytes,
                actual: u64::try_from(CANONICAL_BYTES.len()).expect("fixture length fits u64"),
            })
        );

        let mut limits = TargetDecodeLimits::standard();
        limits.string_bytes =
            u32::try_from(required_string_bytes()).expect("schema string total fits u32");
        decode(CANONICAL_BYTES, limits, &|| false).expect("exact aggregate string limit");
        CanonicalTargetPackageCodec
            .encode_canonical(&package, limits, &|| false)
            .expect("encoder accepts exact aggregate string limit");
        limits.string_bytes -= 1;
        assert_eq!(
            decode(CANONICAL_BYTES, limits, &|| false),
            Err(TargetDecodeError::ResourceLimit {
                resource: "string bytes",
                limit: u64::from(limits.string_bytes),
            })
        );
        assert_eq!(
            CanonicalTargetPackageCodec.encode_canonical(&package, limits, &|| false),
            Err(TargetDecodeError::ResourceLimit {
                resource: "string bytes",
                limit: u64::from(limits.string_bytes),
            })
        );
    }

    #[test]
    fn collection_limits_are_checked_before_accepting_extra_items() {
        let mut limits = TargetDecodeLimits::standard();
        limits.llvm_features = 1;
        limits.mmio_bindings = 1;
        decode(CANONICAL_BYTES, limits, &|| false).expect("exact collection limits");
        assert_eq!(
            decode(OVER_FEATURE_LIMIT, limits, &|| false),
            Err(TargetDecodeError::ResourceLimit {
                resource: "LLVM features",
                limit: 1,
            })
        );

        limits.bytes = 0;
        assert_eq!(
            decode(CANONICAL_BYTES, limits, &|| false),
            Err(TargetDecodeError::InvalidLimits)
        );

        let mut limits = TargetDecodeLimits::standard();
        limits.bytes = MAX_TARGET_PACKAGE_BYTES + 1;
        assert_eq!(limits.validate(), Err(TargetDecodeError::InvalidLimits));
        limits = TargetDecodeLimits::standard();
        limits.string_bytes = MAX_TARGET_STRING_BYTES + 1;
        assert_eq!(limits.validate(), Err(TargetDecodeError::InvalidLimits));
        limits = TargetDecodeLimits::standard();
        limits.mmio_bindings = MAX_TARGET_MMIO_BINDINGS + 1;
        assert_eq!(limits.validate(), Err(TargetDecodeError::InvalidLimits));
        limits = TargetDecodeLimits::standard();
        limits.llvm_features = MAX_TARGET_LLVM_FEATURES + 1;
        assert_eq!(limits.validate(), Err(TargetDecodeError::InvalidLimits));
    }

    #[test]
    fn decode_and_encode_are_cancellable() {
        assert_eq!(
            decode(CANONICAL_BYTES, TargetDecodeLimits::standard(), &|| true),
            Err(TargetDecodeError::Cancelled)
        );

        let calls = Cell::new(0_u32);
        let cancel_during_parse = || {
            let current = calls.get();
            calls.set(current + 1);
            current >= 5
        };
        assert_eq!(
            decode(
                CANONICAL_BYTES,
                TargetDecodeLimits::standard(),
                &cancel_during_parse,
            ),
            Err(TargetDecodeError::Cancelled)
        );

        let long_line = vec![b' '; 8 * 1024];
        let calls = Cell::new(0_u32);
        let cancel_within_line = || {
            let current = calls.get();
            calls.set(current + 1);
            current >= 3
        };
        assert_eq!(
            decode(
                &long_line,
                TargetDecodeLimits::standard(),
                &cancel_within_line,
            ),
            Err(TargetDecodeError::Cancelled)
        );

        let package = TargetPackage::aarch64_qemu_virt_uefi(digest());
        assert_eq!(
            CanonicalTargetPackageCodec.encode_canonical(
                &package,
                TargetDecodeLimits::standard(),
                &|| true,
            ),
            Err(TargetDecodeError::Cancelled)
        );
    }

    #[test]
    fn consumer_rejects_a_different_selected_identity() {
        let other = TargetIdentity::new("other-aarch64-target").expect("valid identity spelling");
        assert_eq!(
            CanonicalTargetPackageCodec.decode(
                TargetDecodeRequest {
                    toml_bytes: CANONICAL_BYTES,
                    expected_identity: &other,
                    verified_digest: digest(),
                    limits: TargetDecodeLimits::standard(),
                },
                &|| false,
            ),
            Err(TargetDecodeError::IdentityMismatch)
        );
        assert_eq!(
            decode_and_verify(CANONICAL_BYTES, &other, TargetDecodeLimits::standard()),
            Err(TargetDecodeError::IdentityMismatch)
        );
    }
}
