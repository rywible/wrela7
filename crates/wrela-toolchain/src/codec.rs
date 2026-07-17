use std::fmt;

use wrela_build_model::{LanguageRevision, Sha256Digest, TargetIdentity};
use wrela_package::{PackageIdentity, PackageLocator, PackageName, PackageVersion};

use crate::{
    ComponentKind, ComponentPath, ManifestError, ShippedComponent, ShippedStandardLibraryPackage,
    ShippedTarget, ShippedTargetFile, ToolchainCompatibility, ToolchainDecodeError,
    ToolchainDecodeLimits, ToolchainDecodeRequest, ToolchainManifest, ToolchainManifestCodec,
    validate_standard_library_component,
};

const CANCELLATION_POLL_BYTES: usize = 1024;

/// Canonical schema-1 codec for `share/wrela/toolchain.toml`.
///
/// The grammar is the deliberately small TOML subset used by the canonical
/// encoder: root assignments, one `[compatibility]` table, and repeated
/// `[[standard_library_packages]]`, `[[components]]`, `[[targets]]`, and
/// `[[targets.files]]` tables. The decoder accepts harmless TOML whitespace,
/// comments, field reordering within a table, and basic-string escapes so the
/// consumer boundary can distinguish a valid-but-noncanonical representation
/// from malformed bytes. It does not implement ambient TOML features.
///
/// The standard-library component and target-package directory digests in
/// schema 1 commit to canonical tree digest version 1 (`WRELTRE\0`, version
/// `1`). Executable components and each target-file record use raw-file
/// SHA-256. Changing either interpretation requires a toolchain-manifest schema
/// change rather than silently reusing schema 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalToolchainManifestCodec;

impl CanonicalToolchainManifestCodec {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ToolchainManifestCodec for CanonicalToolchainManifestCodec {
    fn decode(
        &self,
        request: ToolchainDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ToolchainManifest, ToolchainDecodeError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        check_byte_limit(request.bytes.len(), request.limits.bytes)?;
        let source =
            std::str::from_utf8(request.bytes).map_err(|_| ToolchainDecodeError::InvalidUtf8)?;
        Parser::new(request.limits, is_cancelled).parse(source)
    }

    fn encode_canonical(
        &self,
        manifest: &ToolchainManifest,
        limits: ToolchainDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, ToolchainDecodeError> {
        check_cancelled(is_cancelled)?;
        limits.validate()?;
        check_manifest_limits(manifest, limits, is_cancelled)?;
        manifest
            .validate(&manifest.compatibility)
            .map_err(ToolchainDecodeError::InvalidManifest)?;

        let mut counter = CountingSink::default();
        write_manifest(&mut counter, manifest, is_cancelled)?;
        let byte_count = counter.len;
        check_byte_limit(byte_count, limits.bytes)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_count)
            .map_err(|_| ToolchainDecodeError::ResourceLimit {
                resource: "encoded bytes",
                limit: limits.bytes,
            })?;
        let mut sink = BufferSink { bytes };
        write_manifest(&mut sink, manifest, is_cancelled)?;
        debug_assert_eq!(sink.bytes.len(), byte_count);
        check_cancelled(is_cancelled)?;
        Ok(sink.bytes)
    }
}

fn check_manifest_limits(
    manifest: &ToolchainManifest,
    limits: ToolchainDecodeLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    check_count_limit(
        "standard-library packages",
        manifest.standard_library_packages.len(),
        u64::from(limits.standard_library_packages),
    )?;
    check_count_limit(
        "components",
        manifest.components.len(),
        u64::from(limits.components),
    )?;
    check_count_limit("targets", manifest.targets.len(), u64::from(limits.targets))?;
    let mut target_files = 0_usize;
    for (index, target) in manifest.targets.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        target_files = target_files.checked_add(target.files.len()).ok_or(
            ToolchainDecodeError::ResourceLimit {
                resource: "target files",
                limit: u64::from(limits.target_files),
            },
        )?;
        check_count_limit("target files", target_files, u64::from(limits.target_files))?;
    }

    let mut string_bytes = 0_usize;
    let string_limit = u64::from(limits.string_bytes);
    add_string_bytes(
        &mut string_bytes,
        manifest.release.as_str(),
        string_limit,
        is_cancelled,
    )?;
    add_string_bytes(
        &mut string_bytes,
        manifest.host.as_str(),
        string_limit,
        is_cancelled,
    )?;
    add_string_bytes(
        &mut string_bytes,
        manifest.llvm_project_revision.as_str(),
        string_limit,
        is_cancelled,
    )?;
    add_string_bytes(
        &mut string_bytes,
        manifest.compatibility.language.as_str(),
        string_limit,
        is_cancelled,
    )?;
    for (index, package) in manifest.standard_library_packages.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        add_string_bytes(
            &mut string_bytes,
            package.identity.name.as_str(),
            string_limit,
            is_cancelled,
        )?;
        add_string_bytes(
            &mut string_bytes,
            package.identity.version.as_str(),
            string_limit,
            is_cancelled,
        )?;
        add_fixed_string_bytes(&mut string_bytes, 64, string_limit)?;
        let component = match &package.locator {
            PackageLocator::Toolchain { component } => component.as_str(),
            PackageLocator::Workspace { path } => path.as_str(),
            PackageLocator::Archive { provider, .. } => provider.as_str(),
        };
        add_string_bytes(&mut string_bytes, component, string_limit, is_cancelled)?;
        add_fixed_string_bytes(&mut string_bytes, 64, string_limit)?;
    }
    for (index, component) in manifest.components.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        add_string_bytes(
            &mut string_bytes,
            component_kind_name(component.kind),
            string_limit,
            is_cancelled,
        )?;
        add_string_bytes(
            &mut string_bytes,
            component.path.as_str(),
            string_limit,
            is_cancelled,
        )?;
        add_fixed_string_bytes(&mut string_bytes, 64, string_limit)?;
    }
    for (index, target) in manifest.targets.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        add_string_bytes(
            &mut string_bytes,
            target.identity.as_str(),
            string_limit,
            is_cancelled,
        )?;
        add_string_bytes(
            &mut string_bytes,
            target.path.as_str(),
            string_limit,
            is_cancelled,
        )?;
        add_fixed_string_bytes(&mut string_bytes, 64, string_limit)?;
        for (file_index, file) in target.files.iter().enumerate() {
            poll_cancellation(file_index, is_cancelled)?;
            add_string_bytes(
                &mut string_bytes,
                file.path.as_str(),
                string_limit,
                is_cancelled,
            )?;
            add_fixed_string_bytes(&mut string_bytes, 64, string_limit)?;
        }
    }
    Ok(())
}

fn add_string_bytes(
    total: &mut usize,
    value: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    for (index, _) in value.char_indices() {
        poll_cancellation(index, is_cancelled)?;
    }
    add_fixed_string_bytes(total, value.len(), limit)
}

fn add_fixed_string_bytes(
    total: &mut usize,
    amount: usize,
    limit: u64,
) -> Result<(), ToolchainDecodeError> {
    *total = total
        .checked_add(amount)
        .ok_or(ToolchainDecodeError::ResourceLimit {
            resource: "string bytes",
            limit,
        })?;
    check_count_limit("string bytes", *total, limit)
}

trait Sink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), ToolchainDecodeError>;
}

#[derive(Default)]
struct CountingSink {
    len: usize,
}

impl Sink for CountingSink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), ToolchainDecodeError> {
        self.len =
            self.len
                .checked_add(bytes.len())
                .ok_or(ToolchainDecodeError::ResourceLimit {
                    resource: "encoded bytes",
                    limit: u64::MAX,
                })?;
        Ok(())
    }
}

struct BufferSink {
    bytes: Vec<u8>,
}

impl Sink for BufferSink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), ToolchainDecodeError> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

fn write_manifest(
    sink: &mut dyn Sink,
    manifest: &ToolchainManifest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    write_integer_assignment(sink, "schema", u64::from(manifest.schema))?;
    write_string_assignment(sink, "release", &manifest.release, is_cancelled)?;
    write_string_assignment(sink, "host", &manifest.host, is_cancelled)?;
    write_string_assignment(
        sink,
        "llvm_project_revision",
        &manifest.llvm_project_revision,
        is_cancelled,
    )?;
    sink.push(b"\n[compatibility]\n")?;
    write_string_assignment(
        sink,
        "language",
        manifest.compatibility.language.as_str(),
        is_cancelled,
    )?;
    for (key, value) in compatibility_numbers(&manifest.compatibility) {
        check_cancelled(is_cancelled)?;
        write_integer_assignment(sink, key, u64::from(value))?;
    }

    for (index, package) in manifest.standard_library_packages.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        sink.push(b"\n[[standard_library_packages]]\n")?;
        write_string_assignment(sink, "name", package.identity.name.as_str(), is_cancelled)?;
        write_string_assignment(
            sink,
            "version",
            package.identity.version.as_str(),
            is_cancelled,
        )?;
        write_digest_assignment(sink, "source_digest", package.identity.source_digest)?;
        let PackageLocator::Toolchain { component } = &package.locator else {
            return Err(ToolchainDecodeError::InvalidManifest(
                ManifestError::InvalidStandardLibraryPackages,
            ));
        };
        write_string_assignment(sink, "component", component, is_cancelled)?;
        write_digest_assignment(sink, "manifest_digest", package.manifest_digest)?;
    }

    for (index, component) in manifest.components.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        sink.push(b"\n[[components]]\n")?;
        write_string_assignment(
            sink,
            "kind",
            component_kind_name(component.kind),
            is_cancelled,
        )?;
        write_string_assignment(sink, "path", component.path.as_str(), is_cancelled)?;
        write_digest_assignment(sink, "digest", component.digest)?;
        write_integer_assignment(sink, "bytes", component.bytes)?;
    }

    for (index, target) in manifest.targets.iter().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        sink.push(b"\n[[targets]]\n")?;
        write_string_assignment(sink, "identity", target.identity.as_str(), is_cancelled)?;
        write_string_assignment(sink, "path", target.path.as_str(), is_cancelled)?;
        write_digest_assignment(sink, "digest", target.digest)?;
        write_integer_assignment(sink, "bytes", target.bytes)?;
        for (file_index, file) in target.files.iter().enumerate() {
            poll_cancellation(file_index, is_cancelled)?;
            sink.push(b"\n[[targets.files]]\n")?;
            write_string_assignment(sink, "path", file.path.as_str(), is_cancelled)?;
            write_digest_assignment(sink, "digest", file.digest)?;
            write_integer_assignment(sink, "bytes", file.bytes)?;
        }
    }
    check_cancelled(is_cancelled)
}

fn compatibility_numbers(compatibility: &ToolchainCompatibility) -> [(&'static str, u32); 14] {
    [
        (
            "build_profile_encoding",
            compatibility.build_profile_encoding,
        ),
        ("backend_protocol", compatibility.backend_protocol),
        ("target_package", compatibility.target_package),
        ("semantic_wir", compatibility.semantic_wir),
        ("flow_wir", compatibility.flow_wir),
        ("flow_wir_wire", compatibility.flow_wir_wire),
        ("machine_wir", compatibility.machine_wir),
        ("runtime_abi", compatibility.runtime_abi),
        ("image_report", compatibility.image_report),
        ("test_plan", compatibility.test_plan),
        ("test_report", compatibility.test_report),
        ("image_scenario", compatibility.image_scenario),
        ("test_event", compatibility.test_event),
        ("test_frame", compatibility.test_frame),
    ]
}

fn write_string_assignment(
    sink: &mut dyn Sink,
    key: &str,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    sink.push(key.as_bytes())?;
    sink.push(b" = ")?;
    write_basic_string(sink, value, is_cancelled)?;
    sink.push(b"\n")
}

fn write_integer_assignment(
    sink: &mut dyn Sink,
    key: &str,
    value: u64,
) -> Result<(), ToolchainDecodeError> {
    sink.push(key.as_bytes())?;
    sink.push(b" = ")?;
    write_u64(sink, value)?;
    sink.push(b"\n")
}

fn write_digest_assignment(
    sink: &mut dyn Sink,
    key: &str,
    digest: Sha256Digest,
) -> Result<(), ToolchainDecodeError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    sink.push(key.as_bytes())?;
    sink.push(b" = \"")?;
    for byte in digest.as_bytes() {
        sink.push(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])?;
    }
    sink.push(b"\"\n")
}

fn write_u64(sink: &mut dyn Sink, mut value: u64) -> Result<(), ToolchainDecodeError> {
    let mut digits = [0_u8; 20];
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(value % 10).expect("decimal digit fits u8");
        value /= 10;
        if value == 0 {
            break;
        }
    }
    sink.push(&digits[cursor..])
}

fn write_basic_string(
    sink: &mut dyn Sink,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    sink.push(b"\"")?;
    for (index, character) in value.char_indices() {
        poll_cancellation(index, is_cancelled)?;
        match character {
            '"' => sink.push(b"\\\"")?,
            '\\' => sink.push(b"\\\\")?,
            '\u{08}' => sink.push(b"\\b")?,
            '\t' => sink.push(b"\\t")?,
            '\n' => sink.push(b"\\n")?,
            '\u{0c}' => sink.push(b"\\f")?,
            '\r' => sink.push(b"\\r")?,
            character if character.is_control() => write_unicode_escape(sink, character)?,
            character => {
                let mut encoded = [0_u8; 4];
                sink.push(character.encode_utf8(&mut encoded).as_bytes())?;
            }
        }
    }
    sink.push(b"\"")
}

fn write_unicode_escape(sink: &mut dyn Sink, character: char) -> Result<(), ToolchainDecodeError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let value = u32::from(character);
    let (prefix, digits) = if value <= 0xffff {
        (&b"\\u"[..], 4_usize)
    } else {
        (&b"\\U"[..], 8_usize)
    };
    sink.push(prefix)?;
    let mut output = [b'0'; 8];
    for (index, digit) in output.iter_mut().enumerate().take(digits) {
        let shift = 4 * (digits - index - 1);
        *digit = HEX[((value >> shift) & 0x0f) as usize];
    }
    sink.push(&output[..digits])
}

fn component_kind_name(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Frontend => "frontend",
        ComponentKind::Backend => "backend",
        ComponentKind::StandardLibrary => "standard_library",
        ComponentKind::Aarch64Emulator => "aarch64_emulator",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Compatibility,
    StandardLibraryPackage,
    Component,
    Target,
    TargetFile,
}

impl Section {
    const fn field_prefix(self) -> &'static str {
        match self {
            Self::Root => "",
            Self::Compatibility => "compatibility.",
            Self::StandardLibraryPackage => "standard_library_packages.",
            Self::Component => "components.",
            Self::Target => "targets.",
            Self::TargetFile => "targets.files.",
        }
    }
}

#[derive(Default)]
struct RootBuilder {
    schema: Option<u32>,
    release: Option<String>,
    host: Option<String>,
    llvm_project_revision: Option<String>,
}

#[derive(Default)]
struct CompatibilityBuilder {
    language: Option<LanguageRevision>,
    build_profile_encoding: Option<u32>,
    backend_protocol: Option<u32>,
    target_package: Option<u32>,
    semantic_wir: Option<u32>,
    flow_wir: Option<u32>,
    flow_wir_wire: Option<u32>,
    machine_wir: Option<u32>,
    runtime_abi: Option<u32>,
    image_report: Option<u32>,
    test_plan: Option<u32>,
    test_report: Option<u32>,
    image_scenario: Option<u32>,
    test_event: Option<u32>,
    test_frame: Option<u32>,
}

#[derive(Default)]
struct StandardLibraryPackageBuilder {
    name: Option<PackageName>,
    version: Option<PackageVersion>,
    source_digest: Option<Sha256Digest>,
    component: Option<String>,
    manifest_digest: Option<Sha256Digest>,
}

#[derive(Default)]
struct ComponentBuilder {
    kind: Option<ComponentKind>,
    path: Option<ComponentPath>,
    digest: Option<Sha256Digest>,
    bytes: Option<u64>,
}

#[derive(Default)]
struct TargetBuilder {
    identity: Option<TargetIdentity>,
    path: Option<ComponentPath>,
    digest: Option<Sha256Digest>,
    bytes: Option<u64>,
    files: Vec<ShippedTargetFile>,
}

#[derive(Default)]
struct TargetFileBuilder {
    path: Option<ComponentPath>,
    digest: Option<Sha256Digest>,
    bytes: Option<u64>,
}

struct Parser<'a> {
    limits: ToolchainDecodeLimits,
    is_cancelled: &'a dyn Fn() -> bool,
    section: Section,
    root: RootBuilder,
    compatibility_seen: bool,
    compatibility: CompatibilityBuilder,
    standard_library_packages: Vec<ShippedStandardLibraryPackage>,
    current_standard_library_package: Option<StandardLibraryPackageBuilder>,
    components: Vec<ShippedComponent>,
    current_component: Option<ComponentBuilder>,
    targets: Vec<ShippedTarget>,
    current_target: Option<TargetBuilder>,
    current_target_file: Option<TargetFileBuilder>,
    standard_library_package_tables: usize,
    component_tables: usize,
    target_tables: usize,
    target_file_tables: usize,
    string_bytes: usize,
}

impl<'a> Parser<'a> {
    fn new(limits: ToolchainDecodeLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            limits,
            is_cancelled,
            section: Section::Root,
            root: RootBuilder::default(),
            compatibility_seen: false,
            compatibility: CompatibilityBuilder::default(),
            standard_library_packages: Vec::new(),
            current_standard_library_package: None,
            components: Vec::new(),
            current_component: None,
            targets: Vec::new(),
            current_target: None,
            current_target_file: None,
            standard_library_package_tables: 0,
            component_tables: 0,
            target_tables: 0,
            target_file_tables: 0,
            string_bytes: 0,
        }
    }

    fn parse(mut self, source: &str) -> Result<ToolchainManifest, ToolchainDecodeError> {
        let mut byte_offset = 0_usize;
        for chunk in source.split_inclusive('\n') {
            check_cancelled(self.is_cancelled)?;
            let line = chunk.strip_suffix('\n').unwrap_or(chunk);
            self.parse_line(line, byte_offset)?;
            byte_offset = byte_offset.saturating_add(chunk.len());
        }
        check_cancelled(self.is_cancelled)?;
        self.finish_standard_library_package()?;
        self.finish_component()?;
        self.finish_target()?;
        if !self.compatibility_seen {
            return Err(missing("compatibility"));
        }
        Ok(ToolchainManifest {
            schema: required(self.root.schema, "schema")?,
            release: required(self.root.release, "release")?,
            host: required(self.root.host, "host")?,
            llvm_project_revision: required(
                self.root.llvm_project_revision,
                "llvm_project_revision",
            )?,
            compatibility: self.compatibility.finish()?,
            standard_library_packages: self.standard_library_packages,
            components: self.components,
            targets: self.targets,
        })
    }

    fn parse_line(&mut self, line: &str, byte_offset: usize) -> Result<(), ToolchainDecodeError> {
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
        let value = trim_toml_whitespace(value, self.is_cancelled)?;
        match self.section {
            Section::Root => self.parse_root_field(key, value, byte_offset),
            Section::Compatibility => self.parse_compatibility_field(key, value, byte_offset),
            Section::StandardLibraryPackage => {
                self.parse_standard_library_package_field(key, value, byte_offset)
            }
            Section::Component => self.parse_component_field(key, value, byte_offset),
            Section::Target => self.parse_target_field(key, value, byte_offset),
            Section::TargetFile => self.parse_target_file_field(key, value, byte_offset),
        }
    }

    fn parse_header(
        &mut self,
        content: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match content {
            "[compatibility]" => self.enter_compatibility(byte_offset),
            "[[standard_library_packages]]" => self.enter_standard_library_package(byte_offset),
            "[[components]]" => self.enter_component(byte_offset),
            "[[targets]]" => self.enter_target(byte_offset),
            "[[targets.files]]" => self.enter_target_file(byte_offset),
            _ if !content.ends_with(']') => {
                Err(malformed(byte_offset, "unterminated table header"))
            }
            _ => Err(ToolchainDecodeError::UnknownField(bounded_label(content))),
        }
    }

    fn enter_compatibility(&mut self, byte_offset: usize) -> Result<(), ToolchainDecodeError> {
        if self.compatibility_seen {
            return Err(ToolchainDecodeError::DuplicateKey(
                "compatibility".to_owned(),
            ));
        }
        if self.section != Section::Root {
            return Err(malformed(
                byte_offset,
                "compatibility table must precede array tables",
            ));
        }
        self.compatibility_seen = true;
        self.section = Section::Compatibility;
        Ok(())
    }

    fn enter_standard_library_package(
        &mut self,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        if !self.compatibility_seen
            || !matches!(
                self.section,
                Section::Compatibility | Section::StandardLibraryPackage
            )
        {
            return Err(malformed(
                byte_offset,
                "standard-library package tables must follow compatibility",
            ));
        }
        self.finish_standard_library_package()?;
        check_next_count(
            "standard-library packages",
            self.standard_library_package_tables,
            u64::from(self.limits.standard_library_packages),
        )?;
        self.standard_library_package_tables += 1;
        self.current_standard_library_package = Some(StandardLibraryPackageBuilder::default());
        self.section = Section::StandardLibraryPackage;
        Ok(())
    }

    fn enter_component(&mut self, byte_offset: usize) -> Result<(), ToolchainDecodeError> {
        if !matches!(
            self.section,
            Section::StandardLibraryPackage | Section::Component
        ) {
            return Err(malformed(
                byte_offset,
                "component tables must follow the standard-library package index",
            ));
        }
        self.finish_standard_library_package()?;
        self.finish_component()?;
        check_next_count(
            "components",
            self.component_tables,
            u64::from(self.limits.components),
        )?;
        self.component_tables += 1;
        self.current_component = Some(ComponentBuilder::default());
        self.section = Section::Component;
        Ok(())
    }

    fn enter_target(&mut self, byte_offset: usize) -> Result<(), ToolchainDecodeError> {
        if !matches!(
            self.section,
            Section::Component | Section::Target | Section::TargetFile
        ) {
            return Err(malformed(
                byte_offset,
                "target tables must follow component tables",
            ));
        }
        self.finish_component()?;
        self.finish_target()?;
        check_next_count(
            "targets",
            self.target_tables,
            u64::from(self.limits.targets),
        )?;
        self.target_tables += 1;
        self.current_target = Some(TargetBuilder::default());
        self.section = Section::Target;
        Ok(())
    }

    fn enter_target_file(&mut self, byte_offset: usize) -> Result<(), ToolchainDecodeError> {
        if !matches!(self.section, Section::Target | Section::TargetFile)
            || self.current_target.is_none()
        {
            return Err(malformed(
                byte_offset,
                "target-file table has no containing target",
            ));
        }
        self.finish_target_file()?;
        check_next_count(
            "target files",
            self.target_file_tables,
            u64::from(self.limits.target_files),
        )?;
        self.target_file_tables += 1;
        self.current_target_file = Some(TargetFileBuilder::default());
        self.section = Section::TargetFile;
        Ok(())
    }

    fn parse_root_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match key {
            "schema" => set_once(
                &mut self.root.schema,
                "schema",
                parse_u32(value, byte_offset, self.is_cancelled)?,
            ),
            "release" => {
                let parsed = self.parse_string(value, byte_offset)?;
                set_once(&mut self.root.release, "release", parsed)
            }
            "host" => {
                let parsed = self.parse_string(value, byte_offset)?;
                set_once(&mut self.root.host, "host", parsed)
            }
            "llvm_project_revision" => {
                let parsed = self.parse_string(value, byte_offset)?;
                set_once(
                    &mut self.root.llvm_project_revision,
                    "llvm_project_revision",
                    parsed,
                )
            }
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_compatibility_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        if key == "language" {
            let language = self.parse_string(value, byte_offset)?;
            let language = match language.as_str() {
                "0.1-design" => LanguageRevision::Design0_1,
                _ => return Err(malformed(byte_offset, "unknown language revision")),
            };
            return set_once(
                &mut self.compatibility.language,
                "compatibility.language",
                language,
            );
        }
        let parsed = parse_u32(value, byte_offset, self.is_cancelled)?;
        match key {
            "build_profile_encoding" => set_once(
                &mut self.compatibility.build_profile_encoding,
                "compatibility.build_profile_encoding",
                parsed,
            ),
            "backend_protocol" => set_once(
                &mut self.compatibility.backend_protocol,
                "compatibility.backend_protocol",
                parsed,
            ),
            "target_package" => set_once(
                &mut self.compatibility.target_package,
                "compatibility.target_package",
                parsed,
            ),
            "semantic_wir" => set_once(
                &mut self.compatibility.semantic_wir,
                "compatibility.semantic_wir",
                parsed,
            ),
            "flow_wir" => set_once(
                &mut self.compatibility.flow_wir,
                "compatibility.flow_wir",
                parsed,
            ),
            "flow_wir_wire" => set_once(
                &mut self.compatibility.flow_wir_wire,
                "compatibility.flow_wir_wire",
                parsed,
            ),
            "machine_wir" => set_once(
                &mut self.compatibility.machine_wir,
                "compatibility.machine_wir",
                parsed,
            ),
            "runtime_abi" => set_once(
                &mut self.compatibility.runtime_abi,
                "compatibility.runtime_abi",
                parsed,
            ),
            "image_report" => set_once(
                &mut self.compatibility.image_report,
                "compatibility.image_report",
                parsed,
            ),
            "test_plan" => set_once(
                &mut self.compatibility.test_plan,
                "compatibility.test_plan",
                parsed,
            ),
            "test_report" => set_once(
                &mut self.compatibility.test_report,
                "compatibility.test_report",
                parsed,
            ),
            "image_scenario" => set_once(
                &mut self.compatibility.image_scenario,
                "compatibility.image_scenario",
                parsed,
            ),
            "test_event" => set_once(
                &mut self.compatibility.test_event,
                "compatibility.test_event",
                parsed,
            ),
            "test_frame" => set_once(
                &mut self.compatibility.test_frame,
                "compatibility.test_frame",
                parsed,
            ),
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_standard_library_package_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match key {
            "name" => {
                let value = self.parse_string(value, byte_offset)?;
                let name = PackageName::new(value)
                    .map_err(|_| malformed(byte_offset, "invalid package name"))?;
                let builder = self.standard_library_package_builder(byte_offset)?;
                set_once(&mut builder.name, "standard_library_packages.name", name)
            }
            "version" => {
                let value = self.parse_string(value, byte_offset)?;
                let version = PackageVersion::new(value)
                    .map_err(|_| malformed(byte_offset, "invalid package version"))?;
                let builder = self.standard_library_package_builder(byte_offset)?;
                set_once(
                    &mut builder.version,
                    "standard_library_packages.version",
                    version,
                )
            }
            "source_digest" => {
                let digest = self.parse_digest(value, byte_offset)?;
                let builder = self.standard_library_package_builder(byte_offset)?;
                set_once(
                    &mut builder.source_digest,
                    "standard_library_packages.source_digest",
                    digest,
                )
            }
            "component" => {
                let component = self.parse_string(value, byte_offset)?;
                validate_standard_library_component(&component)
                    .map_err(ToolchainDecodeError::InvalidManifest)?;
                let builder = self.standard_library_package_builder(byte_offset)?;
                set_once(
                    &mut builder.component,
                    "standard_library_packages.component",
                    component,
                )
            }
            "manifest_digest" => {
                let digest = self.parse_digest(value, byte_offset)?;
                let builder = self.standard_library_package_builder(byte_offset)?;
                set_once(
                    &mut builder.manifest_digest,
                    "standard_library_packages.manifest_digest",
                    digest,
                )
            }
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_component_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match key {
            "kind" => {
                let value = self.parse_string(value, byte_offset)?;
                let kind = match value.as_str() {
                    "frontend" => ComponentKind::Frontend,
                    "backend" => ComponentKind::Backend,
                    "standard_library" => ComponentKind::StandardLibrary,
                    "aarch64_emulator" => ComponentKind::Aarch64Emulator,
                    _ => return Err(malformed(byte_offset, "unknown component kind")),
                };
                let builder = self.component_builder(byte_offset)?;
                set_once(&mut builder.kind, "components.kind", kind)
            }
            "path" => {
                let value = self.parse_string(value, byte_offset)?;
                let path =
                    ComponentPath::new(value).map_err(ToolchainDecodeError::InvalidManifest)?;
                let builder = self.component_builder(byte_offset)?;
                set_once(&mut builder.path, "components.path", path)
            }
            "digest" => {
                let digest = self.parse_digest(value, byte_offset)?;
                let builder = self.component_builder(byte_offset)?;
                set_once(&mut builder.digest, "components.digest", digest)
            }
            "bytes" => {
                let bytes = parse_u64(value, byte_offset, self.is_cancelled)?;
                let builder = self.component_builder(byte_offset)?;
                set_once(&mut builder.bytes, "components.bytes", bytes)
            }
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_target_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match key {
            "identity" => {
                let value = self.parse_string(value, byte_offset)?;
                let identity = TargetIdentity::new(value)
                    .map_err(|_| malformed(byte_offset, "invalid target identity"))?;
                let builder = self.target_builder(byte_offset)?;
                set_once(&mut builder.identity, "targets.identity", identity)
            }
            "path" => {
                let value = self.parse_string(value, byte_offset)?;
                let path =
                    ComponentPath::new(value).map_err(ToolchainDecodeError::InvalidManifest)?;
                let builder = self.target_builder(byte_offset)?;
                set_once(&mut builder.path, "targets.path", path)
            }
            "digest" => {
                let digest = self.parse_digest(value, byte_offset)?;
                let builder = self.target_builder(byte_offset)?;
                set_once(&mut builder.digest, "targets.digest", digest)
            }
            "bytes" => {
                let bytes = parse_u64(value, byte_offset, self.is_cancelled)?;
                let builder = self.target_builder(byte_offset)?;
                set_once(&mut builder.bytes, "targets.bytes", bytes)
            }
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_target_file_field(
        &mut self,
        key: &str,
        value: &str,
        byte_offset: usize,
    ) -> Result<(), ToolchainDecodeError> {
        match key {
            "path" => {
                let value = self.parse_string(value, byte_offset)?;
                let path =
                    ComponentPath::new(value).map_err(ToolchainDecodeError::InvalidManifest)?;
                let builder = self.target_file_builder(byte_offset)?;
                set_once(&mut builder.path, "targets.files.path", path)
            }
            "digest" => {
                let digest = self.parse_digest(value, byte_offset)?;
                let builder = self.target_file_builder(byte_offset)?;
                set_once(&mut builder.digest, "targets.files.digest", digest)
            }
            "bytes" => {
                let bytes = parse_u64(value, byte_offset, self.is_cancelled)?;
                let builder = self.target_file_builder(byte_offset)?;
                set_once(&mut builder.bytes, "targets.files.bytes", bytes)
            }
            _ => Err(self.unknown_field(key)),
        }
    }

    fn parse_string(
        &mut self,
        value: &str,
        byte_offset: usize,
    ) -> Result<String, ToolchainDecodeError> {
        let decoded_bytes = decoded_basic_string_len(value, byte_offset, self.is_cancelled)?;
        let next = self.string_bytes.checked_add(decoded_bytes).ok_or(
            ToolchainDecodeError::ResourceLimit {
                resource: "string bytes",
                limit: u64::from(self.limits.string_bytes),
            },
        )?;
        check_count_limit("string bytes", next, u64::from(self.limits.string_bytes))?;
        self.string_bytes = next;
        decode_basic_string(value, decoded_bytes, byte_offset, self.is_cancelled)
    }

    fn parse_digest(
        &mut self,
        value: &str,
        byte_offset: usize,
    ) -> Result<Sha256Digest, ToolchainDecodeError> {
        let value = self.parse_string(value, byte_offset)?;
        parse_digest(&value, byte_offset)
    }

    fn finish_standard_library_package(&mut self) -> Result<(), ToolchainDecodeError> {
        let Some(builder) = self.current_standard_library_package.take() else {
            return Ok(());
        };
        reserve_one(
            &mut self.standard_library_packages,
            "standard-library packages",
            u64::from(self.limits.standard_library_packages),
        )?;
        self.standard_library_packages.push(builder.finish()?);
        Ok(())
    }

    fn finish_component(&mut self) -> Result<(), ToolchainDecodeError> {
        let Some(builder) = self.current_component.take() else {
            return Ok(());
        };
        reserve_one(
            &mut self.components,
            "components",
            u64::from(self.limits.components),
        )?;
        self.components.push(builder.finish()?);
        Ok(())
    }

    fn finish_target_file(&mut self) -> Result<(), ToolchainDecodeError> {
        let Some(builder) = self.current_target_file.take() else {
            return Ok(());
        };
        let file = builder.finish()?;
        let target = self
            .current_target
            .as_mut()
            .ok_or_else(|| malformed(0, "target-file table has no containing target"))?;
        reserve_one(
            &mut target.files,
            "target files",
            u64::from(self.limits.target_files),
        )?;
        target.files.push(file);
        Ok(())
    }

    fn finish_target(&mut self) -> Result<(), ToolchainDecodeError> {
        self.finish_target_file()?;
        let Some(builder) = self.current_target.take() else {
            return Ok(());
        };
        reserve_one(&mut self.targets, "targets", u64::from(self.limits.targets))?;
        self.targets.push(builder.finish()?);
        Ok(())
    }

    fn standard_library_package_builder(
        &mut self,
        byte_offset: usize,
    ) -> Result<&mut StandardLibraryPackageBuilder, ToolchainDecodeError> {
        self.current_standard_library_package
            .as_mut()
            .ok_or_else(|| malformed(byte_offset, "missing standard-library package table"))
    }

    fn component_builder(
        &mut self,
        byte_offset: usize,
    ) -> Result<&mut ComponentBuilder, ToolchainDecodeError> {
        self.current_component
            .as_mut()
            .ok_or_else(|| malformed(byte_offset, "missing component table"))
    }

    fn target_builder(
        &mut self,
        byte_offset: usize,
    ) -> Result<&mut TargetBuilder, ToolchainDecodeError> {
        self.current_target
            .as_mut()
            .ok_or_else(|| malformed(byte_offset, "missing target table"))
    }

    fn target_file_builder(
        &mut self,
        byte_offset: usize,
    ) -> Result<&mut TargetFileBuilder, ToolchainDecodeError> {
        self.current_target_file
            .as_mut()
            .ok_or_else(|| malformed(byte_offset, "missing target-file table"))
    }

    fn unknown_field(&self, key: &str) -> ToolchainDecodeError {
        let mut label = self.section.field_prefix().to_owned();
        label.push_str(&bounded_label(key));
        ToolchainDecodeError::UnknownField(label)
    }
}

impl CompatibilityBuilder {
    fn finish(self) -> Result<ToolchainCompatibility, ToolchainDecodeError> {
        Ok(ToolchainCompatibility {
            language: required(self.language, "compatibility.language")?,
            build_profile_encoding: required(
                self.build_profile_encoding,
                "compatibility.build_profile_encoding",
            )?,
            backend_protocol: required(self.backend_protocol, "compatibility.backend_protocol")?,
            target_package: required(self.target_package, "compatibility.target_package")?,
            semantic_wir: required(self.semantic_wir, "compatibility.semantic_wir")?,
            flow_wir: required(self.flow_wir, "compatibility.flow_wir")?,
            flow_wir_wire: required(self.flow_wir_wire, "compatibility.flow_wir_wire")?,
            machine_wir: required(self.machine_wir, "compatibility.machine_wir")?,
            runtime_abi: required(self.runtime_abi, "compatibility.runtime_abi")?,
            image_report: required(self.image_report, "compatibility.image_report")?,
            test_plan: required(self.test_plan, "compatibility.test_plan")?,
            test_report: required(self.test_report, "compatibility.test_report")?,
            image_scenario: required(self.image_scenario, "compatibility.image_scenario")?,
            test_event: required(self.test_event, "compatibility.test_event")?,
            test_frame: required(self.test_frame, "compatibility.test_frame")?,
        })
    }
}

impl StandardLibraryPackageBuilder {
    fn finish(self) -> Result<ShippedStandardLibraryPackage, ToolchainDecodeError> {
        Ok(ShippedStandardLibraryPackage {
            identity: PackageIdentity {
                name: required(self.name, "standard_library_packages.name")?,
                version: required(self.version, "standard_library_packages.version")?,
                source_digest: required(
                    self.source_digest,
                    "standard_library_packages.source_digest",
                )?,
            },
            locator: PackageLocator::Toolchain {
                component: required(self.component, "standard_library_packages.component")?,
            },
            manifest_digest: required(
                self.manifest_digest,
                "standard_library_packages.manifest_digest",
            )?,
        })
    }
}

impl ComponentBuilder {
    fn finish(self) -> Result<ShippedComponent, ToolchainDecodeError> {
        Ok(ShippedComponent {
            kind: required(self.kind, "components.kind")?,
            path: required(self.path, "components.path")?,
            digest: required(self.digest, "components.digest")?,
            bytes: required(self.bytes, "components.bytes")?,
        })
    }
}

impl TargetBuilder {
    fn finish(self) -> Result<ShippedTarget, ToolchainDecodeError> {
        Ok(ShippedTarget {
            identity: required(self.identity, "targets.identity")?,
            path: required(self.path, "targets.path")?,
            digest: required(self.digest, "targets.digest")?,
            bytes: required(self.bytes, "targets.bytes")?,
            files: self.files,
        })
    }
}

impl TargetFileBuilder {
    fn finish(self) -> Result<ShippedTargetFile, ToolchainDecodeError> {
        Ok(ShippedTargetFile {
            path: required(self.path, "targets.files.path")?,
            digest: required(self.digest, "targets.files.digest")?,
            bytes: required(self.bytes, "targets.files.bytes")?,
        })
    }
}

fn set_once<T>(
    slot: &mut Option<T>,
    path: &'static str,
    value: T,
) -> Result<(), ToolchainDecodeError> {
    if slot.is_some() {
        Err(ToolchainDecodeError::DuplicateKey(path.to_owned()))
    } else {
        *slot = Some(value);
        Ok(())
    }
}

fn required<T>(slot: Option<T>, path: &'static str) -> Result<T, ToolchainDecodeError> {
    slot.ok_or_else(|| missing(path))
}

fn missing(path: &'static str) -> ToolchainDecodeError {
    ToolchainDecodeError::MissingField(path.to_owned())
}

fn parse_digest(value: &str, byte_offset: usize) -> Result<Sha256Digest, ToolchainDecodeError> {
    if value.len() != 64 {
        return Err(malformed(
            byte_offset,
            "SHA-256 digest must contain exactly 64 hexadecimal digits",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])
            .ok_or_else(|| malformed(byte_offset + index * 2, "invalid SHA-256 hexadecimal"))?;
        let low = hex_digit(pair[1])
            .ok_or_else(|| malformed(byte_offset + index * 2 + 1, "invalid SHA-256 hexadecimal"))?;
        digest[index] = (high << 4) | low;
    }
    Ok(Sha256Digest::from_bytes(digest))
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_u32(
    value: &str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u32, ToolchainDecodeError> {
    let value = parse_u64(value, byte_offset, is_cancelled)?;
    u32::try_from(value).map_err(|_| malformed(byte_offset, "unsigned 32-bit integer overflow"))
}

fn parse_u64(
    value: &str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, ToolchainDecodeError> {
    if value.is_empty() || value.starts_with('_') || value.ends_with('_') {
        return Err(malformed(byte_offset, "invalid unsigned integer"));
    }
    let mut result = 0_u64;
    let mut previous_was_digit = false;
    let mut digit_count = 0_usize;
    for (index, byte) in value.bytes().enumerate() {
        poll_cancellation(index, is_cancelled)?;
        if byte == b'_' {
            if !previous_was_digit {
                return Err(malformed(byte_offset + index, "invalid integer separator"));
            }
            previous_was_digit = false;
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(malformed(byte_offset + index, "invalid unsigned integer"));
        }
        result = result
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| malformed(byte_offset + index, "unsigned integer overflow"))?;
        previous_was_digit = true;
        digit_count += 1;
    }
    if !previous_was_digit || (digit_count > 1 && value.starts_with('0')) {
        return Err(malformed(byte_offset, "invalid unsigned integer"));
    }
    Ok(result)
}

fn decoded_basic_string_len(
    value: &str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, ToolchainDecodeError> {
    scan_basic_string(value, byte_offset, is_cancelled, None)
}

fn decode_basic_string(
    value: &str,
    capacity: usize,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, ToolchainDecodeError> {
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ToolchainDecodeError::ResourceLimit {
            resource: "string bytes",
            limit: u64::try_from(capacity).unwrap_or(u64::MAX),
        })?;
    let decoded = scan_basic_string(value, byte_offset, is_cancelled, Some(&mut output))?;
    debug_assert_eq!(decoded, output.len());
    Ok(output)
}

fn scan_basic_string(
    value: &str,
    byte_offset: usize,
    is_cancelled: &dyn Fn() -> bool,
    mut output: Option<&mut String>,
) -> Result<usize, ToolchainDecodeError> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(malformed(byte_offset, "expected one basic string"));
    }
    let mut cursor = 1_usize;
    let end = bytes.len() - 1;
    let mut decoded_len = 0_usize;
    while cursor < end {
        poll_cancellation(cursor, is_cancelled)?;
        let byte = bytes[cursor];
        if byte == b'"' {
            return Err(malformed(
                byte_offset + cursor,
                "unescaped quote in basic string",
            ));
        }
        if byte == b'\\' {
            let (character, consumed) = parse_escape(bytes, cursor, end, byte_offset)?;
            decoded_len = decoded_len.checked_add(character.len_utf8()).ok_or(
                ToolchainDecodeError::ResourceLimit {
                    resource: "string bytes",
                    limit: u64::MAX,
                },
            )?;
            if let Some(output) = output.as_deref_mut() {
                output.push(character);
            }
            cursor += consumed;
            continue;
        }
        let rest = &value[cursor..end];
        let character = rest
            .chars()
            .next()
            .ok_or_else(|| malformed(byte_offset + cursor, "invalid basic string"))?;
        if character.is_control() {
            return Err(malformed(
                byte_offset + cursor,
                "unescaped control character in basic string",
            ));
        }
        decoded_len = decoded_len.checked_add(character.len_utf8()).ok_or(
            ToolchainDecodeError::ResourceLimit {
                resource: "string bytes",
                limit: u64::MAX,
            },
        )?;
        if let Some(output) = output.as_deref_mut() {
            output.push(character);
        }
        cursor += character.len_utf8();
    }
    Ok(decoded_len)
}

fn parse_escape(
    bytes: &[u8],
    cursor: usize,
    end: usize,
    byte_offset: usize,
) -> Result<(char, usize), ToolchainDecodeError> {
    let Some(escape) = bytes.get(cursor + 1).copied() else {
        return Err(malformed(
            byte_offset + cursor,
            "unterminated string escape",
        ));
    };
    match escape {
        b'"' => Ok(('"', 2)),
        b'\\' => Ok(('\\', 2)),
        b'b' => Ok(('\u{08}', 2)),
        b't' => Ok(('\t', 2)),
        b'n' => Ok(('\n', 2)),
        b'f' => Ok(('\u{0c}', 2)),
        b'r' => Ok(('\r', 2)),
        b'u' => parse_unicode_escape(bytes, cursor, end, byte_offset, 4),
        b'U' => parse_unicode_escape(bytes, cursor, end, byte_offset, 8),
        _ => Err(malformed(
            byte_offset + cursor,
            "unknown basic-string escape",
        )),
    }
}

fn parse_unicode_escape(
    bytes: &[u8],
    cursor: usize,
    end: usize,
    byte_offset: usize,
    digits: usize,
) -> Result<(char, usize), ToolchainDecodeError> {
    let digit_start = cursor + 2;
    let digit_end = digit_start.saturating_add(digits);
    if digit_end > end {
        return Err(malformed(byte_offset + cursor, "truncated Unicode escape"));
    }
    let mut value = 0_u32;
    for (index, byte) in bytes[digit_start..digit_end].iter().copied().enumerate() {
        let digit = hex_digit(byte).ok_or_else(|| {
            malformed(byte_offset + digit_start + index, "invalid Unicode escape")
        })?;
        value = value * 16 + u32::from(digit);
    }
    let character = char::from_u32(value)
        .ok_or_else(|| malformed(byte_offset + cursor, "invalid Unicode scalar value"))?;
    Ok((character, digits + 2))
}

fn strip_comment<'a>(
    line: &'a str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, ToolchainDecodeError> {
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

fn trim_toml_whitespace<'a>(
    value: &'a str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a str, ToolchainDecodeError> {
    let bytes = value.as_bytes();
    let mut start = 0_usize;
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

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), ToolchainDecodeError> {
    if is_cancelled() {
        Err(ToolchainDecodeError::Cancelled)
    } else {
        Ok(())
    }
}

fn poll_cancellation(
    work_since_start: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ToolchainDecodeError> {
    if work_since_start & (CANCELLATION_POLL_BYTES - 1) == 0 {
        check_cancelled(is_cancelled)?;
    }
    Ok(())
}

fn check_byte_limit(actual: usize, limit: u64) -> Result<(), ToolchainDecodeError> {
    let actual = u64::try_from(actual).map_err(|_| ToolchainDecodeError::TooLarge {
        limit,
        actual: u64::MAX,
    })?;
    if actual > limit {
        Err(ToolchainDecodeError::TooLarge { limit, actual })
    } else {
        Ok(())
    }
}

fn check_next_count(
    resource: &'static str,
    current: usize,
    limit: u64,
) -> Result<(), ToolchainDecodeError> {
    let next = current
        .checked_add(1)
        .ok_or(ToolchainDecodeError::ResourceLimit { resource, limit })?;
    check_count_limit(resource, next, limit)
}

fn check_count_limit(
    resource: &'static str,
    actual: usize,
    limit: u64,
) -> Result<(), ToolchainDecodeError> {
    let actual = u64::try_from(actual).unwrap_or(u64::MAX);
    if actual > limit {
        Err(ToolchainDecodeError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

fn reserve_one<T>(
    values: &mut Vec<T>,
    resource: &'static str,
    limit: u64,
) -> Result<(), ToolchainDecodeError> {
    values
        .try_reserve(1)
        .map_err(|_| ToolchainDecodeError::ResourceLimit { resource, limit })
}

fn malformed(byte_offset: usize, message: &str) -> ToolchainDecodeError {
    ToolchainDecodeError::Malformed {
        byte_offset,
        message: message.to_owned(),
    }
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

impl fmt::Debug for Parser<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Parser")
            .field("section", &self.section)
            .field("string_bytes", &self.string_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use wrela_build_model::Sha256Digest;
    use wrela_package::{PackageIdentity, PackageLocator, PackageName, PackageVersion};

    use super::CanonicalToolchainManifestCodec;
    use crate::{
        ComponentPath, ManifestError, ShippedStandardLibraryPackage, ToolchainCompatibility,
        ToolchainDecodeError, ToolchainDecodeLimits, ToolchainDecodeRequest, ToolchainManifest,
        ToolchainManifestCodec, decode_and_verify_toolchain_manifest,
    };

    const REPRESENTATIVE: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/representative.toml");
    const MINIMUM: &[u8] = include_bytes!("../../../tests/contracts/toolchain/v1/minimum.toml");
    const DUPLICATE: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/duplicate.toml");
    const UNKNOWN: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/unknown.toml");
    const MALFORMED: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/malformed.toml");
    const NONCANONICAL: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/noncanonical.toml");
    const ZERO_COMPONENT_BYTES: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/zero-component-bytes.toml");
    const CORRUPT_DIGEST: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/corrupt-digest.toml");
    const ESCAPING_PATH: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/escaping-path.toml");
    const OVER_COMPONENTS: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/over-components.toml");
    const CANCELLATION: &[u8] =
        include_bytes!("../../../tests/contracts/toolchain/v1/invalid/cancellation.toml");

    fn decode(
        bytes: &[u8],
        limits: ToolchainDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ToolchainManifest, ToolchainDecodeError> {
        let required = ToolchainCompatibility::current();
        CanonicalToolchainManifestCodec.decode(
            ToolchainDecodeRequest {
                bytes,
                limits,
                required: &required,
            },
            is_cancelled,
        )
    }

    fn decode_and_verify(bytes: &[u8]) -> Result<ToolchainManifest, ToolchainDecodeError> {
        let required = ToolchainCompatibility::current();
        decode_and_verify_toolchain_manifest(
            &CanonicalToolchainManifestCodec,
            ToolchainDecodeRequest {
                bytes,
                limits: ToolchainDecodeLimits::standard(),
                required: &required,
            },
            &|| false,
        )
    }

    fn representative() -> ToolchainManifest {
        decode_and_verify(REPRESENTATIVE).expect("representative fixture must verify")
    }

    #[test]
    fn complete_versioned_fixtures_round_trip_byte_exactly() {
        for bytes in [MINIMUM, REPRESENTATIVE] {
            let manifest = decode_and_verify(bytes).expect("canonical fixture");
            let encoded = CanonicalToolchainManifestCodec
                .encode_canonical(&manifest, ToolchainDecodeLimits::standard(), &|| false)
                .expect("canonical encoding");
            assert_eq!(encoded, bytes);
        }
        assert_ne!(
            decode_and_verify(MINIMUM).expect("minimum"),
            decode_and_verify(REPRESENTATIVE).expect("representative")
        );
    }

    #[test]
    fn equivalent_noncanonical_bytes_are_rejected_at_consumer_boundary() {
        decode(NONCANONICAL, ToolchainDecodeLimits::standard(), &|| false)
            .expect("noncanonical spacing remains semantically decodable");
        assert_eq!(
            {
                let required = ToolchainCompatibility::current();
                decode_and_verify_toolchain_manifest(
                    &CanonicalToolchainManifestCodec,
                    ToolchainDecodeRequest {
                        bytes: NONCANONICAL,
                        limits: ToolchainDecodeLimits::standard(),
                        required: &required,
                    },
                    &|| false,
                )
            },
            Err(ToolchainDecodeError::NonCanonical)
        );
    }

    #[test]
    fn duplicate_unknown_malformed_utf8_and_corrupt_digest_are_distinct() {
        assert_eq!(
            decode(DUPLICATE, ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::DuplicateKey("schema".to_owned()))
        );
        assert_eq!(
            decode(UNKNOWN, ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::UnknownField(
                "future_schema".to_owned()
            ))
        );
        assert!(matches!(
            decode(MALFORMED, ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::Malformed { .. })
        ));
        assert_eq!(
            decode(&[0xff], ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::InvalidUtf8)
        );
        assert!(matches!(
            decode(CORRUPT_DIGEST, ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::Malformed { .. })
        ));
        assert!(matches!(
            decode(ESCAPING_PATH, ToolchainDecodeLimits::standard(), &|| false),
            Err(ToolchainDecodeError::InvalidManifest(
                ManifestError::InvalidComponentPath(_)
            ))
        ));
    }

    #[test]
    fn numeric_overflow_and_missing_fields_are_checked() {
        assert!(matches!(
            decode(
                b"schema = 4294967296\n",
                ToolchainDecodeLimits::standard(),
                &|| false
            ),
            Err(ToolchainDecodeError::Malformed { .. })
        ));
        assert_eq!(
            decode(b"schema = 1\n", ToolchainDecodeLimits::standard(), &|| {
                false
            }),
            Err(ToolchainDecodeError::MissingField(
                "compatibility".to_owned()
            ))
        );
    }

    #[test]
    fn all_decode_limits_are_hard_capped_and_applied_before_growth() {
        let hard = ToolchainDecodeLimits::standard();
        let over_hard = [
            ToolchainDecodeLimits {
                bytes: hard.bytes + 1,
                ..hard
            },
            ToolchainDecodeLimits {
                string_bytes: hard.string_bytes + 1,
                ..hard
            },
            ToolchainDecodeLimits {
                components: hard.components + 1,
                ..hard
            },
            ToolchainDecodeLimits {
                targets: hard.targets + 1,
                ..hard
            },
            ToolchainDecodeLimits {
                target_files: hard.target_files + 1,
                ..hard
            },
            ToolchainDecodeLimits {
                standard_library_packages: hard.standard_library_packages + 1,
                ..hard
            },
        ];
        for limits in over_hard {
            assert_eq!(limits.validate(), Err(ToolchainDecodeError::InvalidLimits));
        }

        let mut limits = hard;
        limits.components = 1;
        assert_eq!(
            decode(OVER_COMPONENTS, limits, &|| false),
            Err(ToolchainDecodeError::ResourceLimit {
                resource: "components",
                limit: 1,
            })
        );

        let actual = u64::try_from(REPRESENTATIVE.len()).expect("fixture length fits u64");
        limits = hard;
        limits.bytes = actual - 1;
        assert_eq!(
            decode(REPRESENTATIVE, limits, &|| false),
            Err(ToolchainDecodeError::TooLarge {
                limit: actual - 1,
                actual,
            })
        );

        limits = hard;
        limits.string_bytes = 1;
        assert_eq!(
            decode(REPRESENTATIVE, limits, &|| false),
            Err(ToolchainDecodeError::ResourceLimit {
                resource: "string bytes",
                limit: 1,
            })
        );
    }

    #[test]
    fn decode_and_encode_poll_cancellation_during_long_input() {
        assert_eq!(
            decode(REPRESENTATIVE, ToolchainDecodeLimits::standard(), &|| true),
            Err(ToolchainDecodeError::Cancelled)
        );
        let calls = Cell::new(0_u32);
        let cancelled = || {
            let call = calls.get();
            calls.set(call + 1);
            call >= 3
        };
        assert_eq!(
            decode(CANCELLATION, ToolchainDecodeLimits::standard(), &cancelled),
            Err(ToolchainDecodeError::Cancelled)
        );
        assert_eq!(
            CanonicalToolchainManifestCodec.encode_canonical(
                &representative(),
                ToolchainDecodeLimits::standard(),
                &|| true,
            ),
            Err(ToolchainDecodeError::Cancelled)
        );
    }

    #[test]
    fn exact_layout_digest_and_measurement_mutations_are_rejected() {
        let required = ToolchainCompatibility::current();
        assert_eq!(
            decode_and_verify(ZERO_COMPONENT_BYTES),
            Err(ToolchainDecodeError::InvalidManifest(
                ManifestError::InvalidComponentMeasurement
            ))
        );
        let mut manifest = representative();
        manifest.components[0].bytes = 0;
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::InvalidComponentMeasurement)
        );

        let mut manifest = representative();
        manifest.components[0].digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::InvalidComponentMeasurement)
        );

        let mut manifest = representative();
        manifest.components[0].path =
            ComponentPath::new("bin/not-wrela").expect("portable mutation");
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::UnexpectedComponentLayout)
        );

        let mut manifest = representative();
        manifest.targets[0].files.pop();
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::InvalidTargetFiles)
        );

        let mut manifest = representative();
        manifest.targets[0].files[0].path =
            ComponentPath::new("firmware/other.fd").expect("portable mutation");
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::InvalidTargetFiles)
        );
    }

    #[test]
    fn standard_library_index_rejects_substitution_and_supports_exact_lookup() {
        let required = ToolchainCompatibility::current();
        let manifest = representative();
        let identity = manifest.standard_library_packages[0].identity.clone();
        let observed = crate::ObservedInstallation {
            components: manifest.components.clone(),
            targets: manifest.targets.clone(),
        };
        let verified = crate::Toolchain::at("/opt/wrela")
            .verify(manifest.clone(), &required, observed, &|| false)
            .expect("verified toolchain");
        let indexed = verified
            .standard_library_package(&identity)
            .expect("exact package identity");
        assert_eq!(indexed, &manifest.standard_library_packages[0]);
        assert_eq!(
            verified.standard_library_packages(),
            &manifest.standard_library_packages
        );

        let mut substituted = manifest.clone();
        substituted.standard_library_packages[0].manifest_digest =
            Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            substituted.validate(&required),
            Err(ManifestError::InvalidStandardLibraryPackages)
        );

        for invalid_component in ["nested/core", "core package", "cøre", "CON", ".", "core."] {
            let mut invalid = manifest.clone();
            invalid.standard_library_packages[0].locator = PackageLocator::Toolchain {
                component: invalid_component.to_owned(),
            };
            assert_eq!(
                invalid.validate(&required),
                Err(ManifestError::InvalidStandardLibraryPackages),
                "component {invalid_component:?} must be rejected"
            );
        }

        let mut duplicate_component = manifest;
        duplicate_component
            .standard_library_packages
            .push(ShippedStandardLibraryPackage {
                identity: PackageIdentity {
                    name: PackageName::new("wrela-extra").expect("name"),
                    version: PackageVersion::new("0.1.0").expect("version"),
                    source_digest: Sha256Digest::from_bytes([0x55; 32]),
                },
                locator: PackageLocator::Toolchain {
                    component: "wrela-core-0.1".to_owned(),
                },
                manifest_digest: Sha256Digest::from_bytes([0x56; 32]),
            });
        assert_eq!(
            duplicate_component.validate(&required),
            Err(ManifestError::InvalidStandardLibraryPackages)
        );
    }

    #[test]
    fn host_triple_deterministically_selects_executable_suffixes() {
        let required = ToolchainCompatibility::current();
        let mut manifest = representative();
        manifest.host = "x86_64-pc-windows-msvc".to_owned();
        assert_eq!(
            manifest.validate(&required),
            Err(ManifestError::UnexpectedComponentLayout)
        );
        manifest.components[0].path = ComponentPath::new("bin/wrela.exe").expect("path");
        manifest.components[1].path =
            ComponentPath::new("libexec/wrela/wrela-backend.exe").expect("path");
        manifest.components[3].path =
            ComponentPath::new("libexec/wrela/qemu-system-aarch64.exe").expect("path");
        manifest.validate(&required).expect("Windows layout");
    }

    #[test]
    fn incompatible_complete_tuple_is_rejected_before_capability_creation() {
        let mut required = ToolchainCompatibility::current();
        required.backend_protocol += 1;
        let request = ToolchainDecodeRequest {
            bytes: REPRESENTATIVE,
            limits: ToolchainDecodeLimits::standard(),
            required: &required,
        };
        assert!(matches!(
            decode_and_verify_toolchain_manifest(
                &CanonicalToolchainManifestCodec,
                request,
                &|| false
            ),
            Err(ToolchainDecodeError::InvalidManifest(
                ManifestError::IncompatibleVersion { .. }
            ))
        ));
    }
}
