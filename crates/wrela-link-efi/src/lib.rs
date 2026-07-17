//! Safe `AArch64` EFI link policy over the private raw LLD COFF boundary.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use wrela_build_model::{BuildIdentity, Sha256Digest};
use wrela_target::{ObjectFormat, TargetBackendContract};

mod inspect;

pub use inspect::{CanonicalCoffObjectInspector, CanonicalLinkedImageInspector};

pub(crate) const EFI_IMAGE_BASE: u64 = 0;
pub(crate) const PE_SECTION_ALIGNMENT: u32 = 4096;
const LLD_IMAGE_BASE_ARGUMENT: &str = "/base:0";
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const PE_SECTION_NAME_BYTES: usize = 8;
const MAP_SYMBOL_NAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkLimits {
    pub objects: u32,
    pub object_bytes: u64,
    /// Bounds both physical PE bytes and the virtual `SizeOfImage` extent.
    pub image_bytes: u64,
    pub map_bytes: u64,
    pub sections: u32,
    pub symbols: u32,
    pub base_relocations: u32,
    pub exception_records: u32,
    pub measurement_bytes: u64,
    pub argument_bytes: u64,
}

impl LinkLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            objects: 1024,
            object_bytes: 4 * 1024 * 1024 * 1024,
            image_bytes: 4 * 1024 * 1024 * 1024,
            map_bytes: 1024 * 1024 * 1024,
            sections: 65_536,
            symbols: 16_000_000,
            base_relocations: 16_000_000,
            exception_records: 16_000_000,
            measurement_bytes: 4 * 1024 * 1024 * 1024,
            argument_bytes: 64 * 1024 * 1024,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.objects > 0
            && self.object_bytes > 0
            && self.image_bytes > 0
            && self.map_bytes > 0
            && self.sections > 0
            && self.symbols > 0
            && self.base_relocations > 0
            && self.exception_records > 0
            && self.measurement_bytes > 0
            && self.argument_bytes > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoffObjectKind {
    Image {
        build: BuildIdentity,
    },
    TargetRuntime {
        target_package: Sha256Digest,
        runtime_abi_version: u32,
    },
}

/// Verified target-file evidence supplied by the driver after toolchain
/// manifest verification.
///
/// Backend orchestration converts this to the final
/// runtime-last `CoffObject` ordinal and the linker re-inspects the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRuntimeObject<'a> {
    pub path: &'a Path,
    pub digest: Sha256Digest,
    pub bytes: u64,
    pub target_package: Sha256Digest,
    pub runtime_abi_version: u32,
}

impl<'a> TargetRuntimeObject<'a> {
    #[must_use]
    pub const fn as_coff_object(&self, ordinal: u32) -> CoffObject<'a> {
        CoffObject {
            ordinal,
            path: self.path,
            expected_digest: self.digest,
            expected_bytes: self.bytes,
            kind: CoffObjectKind::TargetRuntime {
                target_package: self.target_package,
                runtime_abi_version: self.runtime_abi_version,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffObject<'a> {
    /// Dense link-order ordinal. The target runtime is always the final entry.
    pub ordinal: u32,
    pub path: &'a Path,
    /// Digest and length observed when the object was materialized from the
    /// sealed codegen artifact or verified target package.
    pub expected_digest: Sha256Digest,
    pub expected_bytes: u64,
    pub kind: CoffObjectKind,
}

/// Sealed input identity supplied to the post-link relocation-provenance
/// inspector. Fields are private so callers cannot substitute evidence that
/// was not derived from the validated link request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffProvenanceInput<'a> {
    ordinal: u32,
    path: &'a Path,
    expected_digest: Sha256Digest,
    expected_bytes: u64,
}

impl<'a> CoffProvenanceInput<'a> {
    const fn from_object(object: &'a CoffObject<'a>) -> Self {
        Self {
            ordinal: object.ordinal,
            path: object.path,
            expected_digest: object.expected_digest,
            expected_bytes: object.expected_bytes,
        }
    }

    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub const fn path(self) -> &'a Path {
        self.path
    }

    #[must_use]
    pub const fn expected_digest(self) -> Sha256Digest {
        self.expected_digest
    }

    #[must_use]
    pub const fn expected_bytes(self) -> u64 {
        self.expected_bytes
    }
}

#[derive(Debug)]
pub struct LinkRequest<'a> {
    pub build: &'a BuildIdentity,
    /// Deterministic order: generated image objects, then exactly one target
    /// runtime object.
    pub objects: &'a [CoffObject<'a>],
    pub target: &'a TargetBackendContract,
    pub output: &'a Path,
    /// Required because final symbol measurements are part of the image report.
    pub map_output: &'a Path,
    pub limits: LinkLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffObjectMeasurements {
    pub bytes: u64,
    pub digest: Sha256Digest,
    pub coff_machine: String,
}

/// Re-opens and bounds-checks every exact object path immediately before LLD.
///
/// Production implementations parse the ordinary COFF header and hash the
/// same bytes they inspect; a caller's `CoffObjectKind` is never sufficient
/// evidence by itself.
pub trait CoffObjectInspector {
    /// # Errors
    ///
    /// Returns a structural, I/O, limit, or cancellation error when the exact
    /// object cannot be inspected under `maximum_bytes`.
    fn inspect(
        &self,
        object: &Path,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CoffObjectMeasurements, CoffInspectError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_bytes: u64,
    pub file_offset: u64,
    pub file_bytes: u64,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedSymbol {
    pub name: String,
    pub section: String,
    pub virtual_address: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMeasurements {
    pub artifact_bytes: u64,
    pub artifact_digest: Sha256Digest,
    pub coff_machine: String,
    pub subsystem: String,
    pub image_base: u64,
    pub entry_symbol: String,
    pub entry_virtual_address: u64,
    pub relocation_directory_bytes: u64,
    pub base_relocation_blocks: u32,
    pub base_relocations: u32,
    pub base_relocation_provenance_digest: Sha256Digest,
    pub sections: Vec<LinkedSection>,
    pub symbols: Vec<LinkedSymbol>,
}

/// Hard ceilings applied by the PE32+/map inspector before decoding or
/// retaining section, symbol, base-relocation, or ARM64 exception records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInspectLimits {
    /// Bounds both physical PE bytes and the virtual `SizeOfImage` extent.
    pub image_bytes: u64,
    pub map_bytes: u64,
    pub sections: u32,
    pub symbols: u32,
    pub base_relocations: u32,
    pub exception_records: u32,
    pub measurement_bytes: u64,
}

/// Parses the emitted PE32+ image and deterministic LLD map. Production
/// implementations must bounds-check all offsets before allocation and hash
/// the exact image bytes they inspect.
pub trait LinkedImageInspector {
    /// # Errors
    ///
    /// Returns a structural, I/O, limit, or cancellation error when the image
    /// and map do not form canonical target measurements.
    #[allow(clippy::too_many_arguments)]
    fn inspect(
        &self,
        image: &Path,
        map: &Path,
        provenance_map: &Path,
        inputs: &[CoffProvenanceInput<'_>],
        target: &TargetBackendContract,
        limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageMeasurements, InspectError>;
}

/// Link service consumed by backend orchestration. Tests can inject a sealed
/// fake without loading LLD or touching the host filesystem.
pub trait EfiLinker {
    /// # Errors
    ///
    /// Returns the exact link-stage failure, including cancellation, invalid
    /// input evidence, native LLD failure, or post-link inspection failure.
    fn link(
        &self,
        request: &LinkRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EfiArtifact, LinkError>;
}

pub struct LldEfiLinker<'a> {
    pub object_inspector: &'a dyn CoffObjectInspector,
    pub image_inspector: &'a dyn LinkedImageInspector,
}

impl EfiLinker for LldEfiLinker<'_> {
    fn link(
        &self,
        request: &LinkRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EfiArtifact, LinkError> {
        link(
            request,
            self.object_inspector,
            self.image_inspector,
            is_cancelled,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiArtifact {
    path: PathBuf,
    map: PathBuf,
    build: BuildIdentity,
    measurements: ImageMeasurements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoffInspectError {
    Cancelled,
    Io(String),
    TooLarge {
        limit: u64,
        actual: u64,
    },
    LimitExceeded {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    Truncated,
    InvalidCoffHeader,
    LinkerDirectiveSection,
    InvalidEntryAbi,
    UnsupportedMachine(u16),
}

impl EfiArtifact {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn map(&self) -> &Path {
        &self.map
    }

    #[must_use]
    pub const fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub const fn measurements(&self) -> &ImageMeasurements {
        &self.measurements
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
    Cancelled,
    Io(String),
    Truncated,
    InvalidDosHeader,
    InvalidPeSignature,
    UnsupportedOptionalHeader(u16),
    LimitExceeded {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    InvalidBaseRelocations(&'static str),
    InvalidRelocationProvenance(&'static str),
    InvalidMap(String),
    NonCanonical(&'static str),
}

#[derive(Debug)]
pub enum LinkError {
    Cancelled,
    NoImageObject,
    MissingOrDuplicateRuntime,
    BuildIdentityMismatch,
    RuntimeTargetMismatch,
    UnsupportedObjectFormat,
    InvalidOutputPath,
    ArgumentTooLarge {
        limit: u64,
        actual: u64,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    InvalidLimits,
    ObjectInspect {
        path: PathBuf,
        error: CoffInspectError,
    },
    ObjectMismatch {
        path: PathBuf,
    },
    EntryAbiMismatch,
    Lld(wrela_lld_sys::LldError),
    ResidualOutput {
        path: PathBuf,
    },
    ImageTooLarge {
        limit: u64,
        actual: u64,
    },
    Inspect(InspectError),
    InvalidMeasurements(&'static str),
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("EFI linking was cancelled"),
            Self::NoImageObject => {
                formatter.write_str("the EFI linker requires at least one generated image object")
            }
            Self::MissingOrDuplicateRuntime => {
                formatter.write_str("the EFI linker requires exactly one target runtime object")
            }
            Self::BuildIdentityMismatch => formatter
                .write_str("generated COFF object build identity does not match the link build"),
            Self::RuntimeTargetMismatch => formatter.write_str(
                "target runtime object identity or ABI does not match the selected target",
            ),
            Self::UnsupportedObjectFormat => {
                formatter.write_str("the AArch64 EFI linker requires COFF object input")
            }
            Self::InvalidOutputPath => {
                formatter.write_str("EFI output and map paths must be explicit and distinct")
            }
            Self::ArgumentTooLarge { limit, actual } => write!(
                formatter,
                "LLD arguments contain {actual} bytes, exceeding {limit}"
            ),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "EFI linking exceeded {resource} limit {limit}")
            }
            Self::InvalidLimits => formatter.write_str("EFI link limits must be nonzero"),
            Self::ObjectInspect { path, error } => {
                write!(
                    formatter,
                    "cannot inspect COFF object {}: {error:?}",
                    path.display()
                )
            }
            Self::ObjectMismatch { path } => write!(
                formatter,
                "COFF object {} differs from its sealed bytes, digest, or ARM64 machine",
                path.display()
            ),
            Self::EntryAbiMismatch => formatter.write_str(
                "generated COFF objects must define exactly one external ARM64 function entry and the target runtime must not define it",
            ),
            Self::Lld(error) => error.fmt(formatter),
            Self::ResidualOutput { path } => write!(
                formatter,
                "EFI linking failed and left an unsealed output at {}",
                path.display()
            ),
            Self::ImageTooLarge { limit, actual } => write!(
                formatter,
                "EFI image contains {actual} bytes, exceeding {limit}"
            ),
            Self::Inspect(error) => write!(formatter, "cannot inspect linked EFI image: {error:?}"),
            Self::InvalidMeasurements(reason) => {
                write!(formatter, "linked EFI image failed verification: {reason}")
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// Executes the sealed COFF-to-UEFI link boundary.
///
/// # Errors
///
/// Returns an exact [`LinkError`] for cancellation, invalid or changed input,
/// native LLD failure, or noncanonical linked-image evidence.
pub fn link(
    request: &LinkRequest<'_>,
    object_inspector: &dyn CoffObjectInspector,
    image_inspector: &dyn LinkedImageInspector,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EfiArtifact, LinkError> {
    link_with_driver(
        request,
        object_inspector,
        image_inspector,
        is_cancelled,
        &wrela_lld_sys::link_coff,
    )
}

fn link_with_driver(
    request: &LinkRequest<'_>,
    object_inspector: &dyn CoffObjectInspector,
    image_inspector: &dyn LinkedImageInspector,
    is_cancelled: &dyn Fn() -> bool,
    driver: &dyn Fn(&[String]) -> Result<(), wrela_lld_sys::LldError>,
) -> Result<EfiArtifact, LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    validate_link_request(request, is_cancelled)?;
    let provenance_map = provenance_map_path(request.map_output)?;
    if !output_path_ready(request.output)
        || !output_path_ready(request.map_output)
        || !output_path_ready(&provenance_map)
    {
        return Err(LinkError::InvalidOutputPath);
    }
    inspect_objects(request, object_inspector, is_cancelled)?;
    let provenance_inputs = provenance_inputs(request, is_cancelled)?;
    let arguments = lld_arguments(request, &provenance_map, is_cancelled)?;
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    // Object inspection can be arbitrarily expensive within its declared
    // byte limits. Recheck the create-new destinations immediately before the
    // native boundary so an intervening file never becomes an LLD input.
    if !output_path_ready(request.output)
        || !output_path_ready(request.map_output)
        || !output_path_ready(&provenance_map)
    {
        return Err(LinkError::InvalidOutputPath);
    }
    let outputs = LinkOutputCleanup::new(request.output, request.map_output, &provenance_map);
    let linked = (|| {
        driver(&arguments).map_err(LinkError::Lld)?;
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        // LLD re-opens path arguments. Re-inspection closes persistent path or
        // byte replacement between the pre-link seal and native consumption.
        inspect_objects(request, object_inspector, is_cancelled)?;
        let measurements = image_inspector
            .inspect(
                request.output,
                request.map_output,
                &provenance_map,
                &provenance_inputs,
                request.target,
                ImageInspectLimits {
                    image_bytes: request.limits.image_bytes,
                    map_bytes: request.limits.map_bytes,
                    sections: request.limits.sections,
                    symbols: request.limits.symbols,
                    base_relocations: request.limits.base_relocations,
                    exception_records: request.limits.exception_records,
                    measurement_bytes: request.limits.measurement_bytes,
                },
                is_cancelled,
            )
            .map_err(|error| match error {
                InspectError::Cancelled => LinkError::Cancelled,
                error => LinkError::Inspect(error),
            })?;
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        seal_artifact(request, measurements, is_cancelled)
    })();
    match linked {
        Ok(artifact) => {
            if let Err(error) = outputs.remove_provenance() {
                return Err(outputs.cleanup(error));
            }
            outputs.preserve();
            Ok(artifact)
        }
        Err(error) => Err(outputs.cleanup(error)),
    }
}

struct LinkOutputCleanup<'a> {
    output: &'a Path,
    map: &'a Path,
    provenance_map: &'a Path,
    armed: bool,
}

impl<'a> LinkOutputCleanup<'a> {
    const fn new(output: &'a Path, map: &'a Path, provenance_map: &'a Path) -> Self {
        Self {
            output,
            map,
            provenance_map,
            armed: true,
        }
    }

    fn remove_provenance(&self) -> Result<(), LinkError> {
        remove_link_output(self.provenance_map);
        if path_is_absent(self.provenance_map) {
            Ok(())
        } else {
            Err(LinkError::ResidualOutput {
                path: self.provenance_map.to_owned(),
            })
        }
    }

    fn preserve(mut self) {
        self.armed = false;
    }

    fn cleanup(mut self, original: LinkError) -> LinkError {
        self.armed = false;
        for path in [self.output, self.map, self.provenance_map] {
            remove_link_output(path);
        }
        for path in [self.output, self.map, self.provenance_map] {
            if !path_is_absent(path) {
                return LinkError::ResidualOutput {
                    path: path.to_owned(),
                };
            }
        }
        original
    }
}

impl Drop for LinkOutputCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            remove_link_output(self.output);
            remove_link_output(self.map);
            remove_link_output(self.provenance_map);
        }
    }
}

fn provenance_map_path(map: &Path) -> Result<PathBuf, LinkError> {
    let mut encoded = map.as_os_str().to_os_string();
    encoded.push(".lldmap");
    let path = PathBuf::from(encoded);
    if path.as_os_str().as_encoded_bytes().len() <= map.as_os_str().as_encoded_bytes().len() {
        return Err(LinkError::InvalidOutputPath);
    }
    Ok(path)
}

fn provenance_inputs<'a>(
    request: &'a LinkRequest<'a>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<CoffProvenanceInput<'a>>, LinkError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(request.objects.len())
        .map_err(|_| LinkError::ResourceLimit {
            resource: "relocation provenance inputs",
            limit: u64::from(request.limits.objects),
        })?;
    for object in request.objects {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        inputs.push(CoffProvenanceInput::from_object(object));
    }
    Ok(inputs)
}

fn remove_link_output(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
}

fn path_is_absent(path: &Path) -> bool {
    matches!(
        fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

#[allow(clippy::too_many_lines)]
fn validate_link_request(
    request: &LinkRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    if request.target.object_format() != ObjectFormat::Coff {
        return Err(LinkError::UnsupportedObjectFormat);
    }
    if !request.limits.is_valid() || request.objects.len() > request.limits.objects as usize {
        return Err(LinkError::InvalidLimits);
    }
    if request.build.target != *request.target.identity()
        || request.build.target_package != request.target.content_digest()
    {
        return Err(LinkError::BuildIdentityMismatch);
    }
    let provenance_map = provenance_map_path(request.map_output)?;
    validate_argument_budget(request, &provenance_map, is_cancelled)?;
    if same_path(request.map_output, request.output, is_cancelled)?
        || same_path(&provenance_map, request.output, is_cancelled)?
        || same_path(&provenance_map, request.map_output, is_cancelled)?
        || !safe_absolute_path_with_cancellation(request.output, is_cancelled)?
        || !safe_absolute_path_with_cancellation(request.map_output, is_cancelled)?
        || !safe_absolute_path_with_cancellation(&provenance_map, is_cancelled)?
    {
        return Err(LinkError::InvalidOutputPath);
    }
    let mut object_paths = Vec::new();
    object_paths
        .try_reserve_exact(request.objects.len())
        .map_err(|_| LinkError::ResourceLimit {
            resource: "object paths",
            limit: u64::from(request.limits.objects),
        })?;
    let mut image_count = 0usize;
    let mut runtime = None;
    for (index, object) in request.objects.iter().enumerate() {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if object.ordinal as usize != index
            || same_path(object.path, request.output, is_cancelled)?
            || same_path(object.path, request.map_output, is_cancelled)?
            || same_path(object.path, &provenance_map, is_cancelled)?
            || !safe_absolute_path_with_cancellation(object.path, is_cancelled)?
        {
            return Err(LinkError::InvalidOutputPath);
        }
        if object.expected_bytes == 0
            || object.expected_bytes > request.limits.object_bytes
            || object
                .expected_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(LinkError::ObjectMismatch {
                path: object.path.to_owned(),
            });
        }
        match &object.kind {
            CoffObjectKind::Image { build } => {
                if build != request.build {
                    return Err(LinkError::BuildIdentityMismatch);
                }
                image_count = image_count.checked_add(1).ok_or(LinkError::InvalidLimits)?;
            }
            CoffObjectKind::TargetRuntime {
                target_package,
                runtime_abi_version,
            } => {
                if index + 1 != request.objects.len()
                    || runtime
                        .replace((*target_package, *runtime_abi_version))
                        .is_some()
                {
                    return Err(LinkError::MissingOrDuplicateRuntime);
                }
            }
        }
        object_paths.push((path_digest(object.path, is_cancelled)?, object.path));
    }
    if image_count == 0 {
        return Err(LinkError::NoImageObject);
    }
    if runtime.is_none() {
        return Err(LinkError::MissingOrDuplicateRuntime);
    }
    if runtime.ok_or(LinkError::MissingOrDuplicateRuntime)?
        != (
            request.target.content_digest(),
            request.target.runtime_abi_version(),
        )
    {
        return Err(LinkError::RuntimeTargetMismatch);
    }
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    object_paths.sort_unstable_by_key(|(digest, _)| *digest);
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    for pair in object_paths.windows(2) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if pair[0].0 == pair[1].0 && same_path(pair[0].1, pair[1].1, is_cancelled)? {
            return Err(LinkError::InvalidOutputPath);
        }
    }
    Ok(())
}

fn inspect_objects(
    request: &LinkRequest<'_>,
    object_inspector: &dyn CoffObjectInspector,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LinkError> {
    let mut image_entry_definitions = 0u32;
    for object in request.objects {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if object.expected_bytes == 0 || object.expected_bytes > request.limits.object_bytes {
            return Err(LinkError::ObjectMismatch {
                path: object.path.to_owned(),
            });
        }
        let measured = object_inspector
            .inspect(object.path, request.limits.object_bytes, is_cancelled)
            .map_err(|error| match error {
                CoffInspectError::Cancelled => LinkError::Cancelled,
                error => LinkError::ObjectInspect {
                    path: object.path.to_owned(),
                    error,
                },
            })?;
        if measured.bytes != object.expected_bytes
            || measured.digest != object.expected_digest
            || measured.coff_machine != request.target.coff_machine()
        {
            return Err(LinkError::ObjectMismatch {
                path: object.path.to_owned(),
            });
        }
        let entry = inspect::inspect_coff_entry_contract(
            object.path,
            request.target.entry_symbol(),
            request.limits.object_bytes,
            request.limits.sections,
            request.limits.symbols,
            is_cancelled,
        )
        .map_err(|error| match error {
            CoffInspectError::Cancelled => LinkError::Cancelled,
            error => LinkError::ObjectInspect {
                path: object.path.to_owned(),
                error,
            },
        })?;
        match object.kind {
            CoffObjectKind::Image { .. } => {
                image_entry_definitions = image_entry_definitions
                    .checked_add(u32::from(entry.defines_entry))
                    .ok_or(LinkError::EntryAbiMismatch)?;
            }
            CoffObjectKind::TargetRuntime { .. } if entry.defines_entry => {
                return Err(LinkError::EntryAbiMismatch);
            }
            CoffObjectKind::TargetRuntime { .. } => {}
        }
    }
    if image_entry_definitions != 1 {
        return Err(LinkError::EntryAbiMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn lld_arguments(
    request: &LinkRequest<'_>,
    provenance_map: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<String>, LinkError> {
    let count = request
        .objects
        .len()
        .checked_add(12)
        .ok_or_else(|| LinkError::ResourceLimit {
            resource: "LLD argument count",
            limit: u64::from(request.limits.objects) + 12,
        })?;
    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(count)
        .map_err(|_| LinkError::ResourceLimit {
            resource: "LLD argument count",
            limit: u64::from(request.limits.objects) + 12,
        })?;
    let mut bytes = 0u64;
    push_argument(
        &mut arguments,
        "/machine:",
        request.target.coff_machine(),
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    push_argument(
        &mut arguments,
        "/subsystem:",
        request.target.subsystem(),
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    push_argument(
        &mut arguments,
        "/entry:",
        request.target.entry_symbol(),
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    push_argument(
        &mut arguments,
        "",
        LLD_IMAGE_BASE_ARGUMENT,
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    for fixed in [
        "/nodefaultlib",
        "/brepro",
        "/dynamicbase",
        "/lldignoreenv",
        "/WX",
    ] {
        push_argument(
            &mut arguments,
            "",
            fixed,
            &mut bytes,
            request.limits.argument_bytes,
            is_cancelled,
        )?;
    }
    let output = request
        .output
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    push_argument(
        &mut arguments,
        "/out:",
        output,
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    let map = request
        .map_output
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    push_argument(
        &mut arguments,
        "/map:",
        map,
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    let provenance_map = provenance_map
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    push_argument(
        &mut arguments,
        "/lldmap:",
        provenance_map,
        &mut bytes,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    for object in request.objects {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        let path = object.path.to_str().ok_or(LinkError::InvalidOutputPath)?;
        push_argument(
            &mut arguments,
            "",
            path,
            &mut bytes,
            request.limits.argument_bytes,
            is_cancelled,
        )?;
    }
    Ok(arguments)
}

fn validate_argument_budget(
    request: &LinkRequest<'_>,
    provenance_map: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LinkError> {
    let mut total = 0u64;
    for (prefix, value) in [
        ("/machine:", request.target.coff_machine()),
        ("/subsystem:", request.target.subsystem()),
        ("/entry:", request.target.entry_symbol()),
        ("", LLD_IMAGE_BASE_ARGUMENT),
        ("", "/nodefaultlib"),
        ("", "/brepro"),
        ("", "/dynamicbase"),
        ("", "/lldignoreenv"),
        ("", "/WX"),
    ] {
        total = next_argument_total(
            prefix,
            value,
            total,
            request.limits.argument_bytes,
            is_cancelled,
        )?;
    }
    let output = request
        .output
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    total = next_argument_total(
        "/out:",
        output,
        total,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    let map = request
        .map_output
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    total = next_argument_total(
        "/map:",
        map,
        total,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    let provenance_map = provenance_map
        .to_str()
        .ok_or(LinkError::InvalidOutputPath)?;
    total = next_argument_total(
        "/lldmap:",
        provenance_map,
        total,
        request.limits.argument_bytes,
        is_cancelled,
    )?;
    for object in request.objects {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        let path = object.path.to_str().ok_or(LinkError::InvalidOutputPath)?;
        total = next_argument_total("", path, total, request.limits.argument_bytes, is_cancelled)?;
    }
    Ok(())
}

fn push_argument(
    arguments: &mut Vec<String>,
    prefix: &str,
    value: &str,
    total: &mut u64,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LinkError> {
    let actual = next_argument_total(prefix, value, *total, limit, is_cancelled)?;
    let capacity = prefix
        .len()
        .checked_add(value.len())
        .ok_or(LinkError::ArgumentTooLarge {
            limit,
            actual: u64::MAX,
        })?;
    let mut argument = Vec::new();
    argument
        .try_reserve_exact(capacity)
        .map_err(|_| LinkError::ArgumentTooLarge { limit, actual })?;
    argument.extend_from_slice(prefix.as_bytes());
    for chunk in value.as_bytes().chunks(4096) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        argument.extend_from_slice(chunk);
    }
    let argument = String::from_utf8(argument).map_err(|_| LinkError::InvalidOutputPath)?;
    arguments.push(argument);
    *total = actual;
    Ok(())
}

fn next_argument_total(
    prefix: &str,
    value: &str,
    total: u64,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, LinkError> {
    for chunk in value.as_bytes().chunks(4096) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if chunk.contains(&0) {
            return Err(LinkError::InvalidOutputPath);
        }
    }
    let argument_bytes = prefix
        .len()
        .checked_add(value.len())
        .and_then(|bytes| bytes.checked_add(1))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(LinkError::ArgumentTooLarge {
            limit,
            actual: u64::MAX,
        })?;
    let actual = total
        .checked_add(argument_bytes)
        .ok_or(LinkError::ArgumentTooLarge {
            limit,
            actual: u64::MAX,
        })?;
    if actual > limit {
        Err(LinkError::ArgumentTooLarge { limit, actual })
    } else {
        Ok(actual)
    }
}

/// Seal post-link measurements for production and injected linker tests. A
/// successful `EfiLinker` cannot expose an unverified artifact tuple.
///
/// # Errors
///
/// Returns an exact [`LinkError`] when the request or measurements do not
/// satisfy the target, resource, identity, entry, or cancellation contract.
pub fn seal_artifact(
    request: &LinkRequest<'_>,
    measurements: ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EfiArtifact, LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    validate_link_request(request, is_cancelled)?;
    if measurements.artifact_bytes > request.limits.image_bytes {
        return Err(LinkError::ImageTooLarge {
            limit: request.limits.image_bytes,
            actual: measurements.artifact_bytes,
        });
    }
    validate_measurements(&measurements, request.target, request.limits, is_cancelled)?;
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    Ok(EfiArtifact {
        path: request.output.to_owned(),
        map: request.map_output.to_owned(),
        build: request.build.clone(),
        measurements,
    })
}

#[cfg(test)]
fn safe_absolute_path(path: &Path) -> bool {
    safe_absolute_path_with_cancellation(path, &|| false).unwrap_or(false)
}

fn safe_absolute_path_with_cancellation(
    path: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LinkError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.is_empty() || matches!(bytes.last(), Some(b'/' | b'\\')) {
        return Ok(false);
    }
    let mut component_start = 0usize;
    let mut previous_separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index % 4096 == 0 && is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if byte == 0 {
            return Ok(false);
        }
        let separator = matches!(byte, b'/' | b'\\');
        if separator {
            if previous_separator || matches!(&bytes[component_start..index], b"." | b"..") {
                return Ok(false);
            }
            component_start = index + 1;
        }
        previous_separator = separator;
    }
    Ok(!matches!(&bytes[component_start..], b"." | b".."))
}

fn same_path(
    left: &Path,
    right: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LinkError> {
    let left = left.as_os_str().as_encoded_bytes();
    let right = right.as_os_str().as_encoded_bytes();
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.chunks(4096).zip(right.chunks(4096)) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn path_digest(path: &Path, is_cancelled: &dyn Fn() -> bool) -> Result<[u8; 32], LinkError> {
    let mut hasher = Sha256::new();
    for chunk in path.as_os_str().as_encoded_bytes().chunks(4096) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        hasher.update(chunk);
    }
    Ok(hasher.finalize().into())
}

fn output_path_ready(path: &Path) -> bool {
    if !matches!(
        fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(parent) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    fs::canonicalize(parent).is_ok_and(|canonical| canonical == parent)
}

#[allow(clippy::too_many_lines)]
fn validate_measurements(
    measurements: &ImageMeasurements,
    target: &TargetBackendContract,
    limits: LinkLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    let mut measurement_bytes = u64::try_from(measurements.coff_machine.len())
        .ok()
        .and_then(|total| total.checked_add(u64::try_from(measurements.subsystem.len()).ok()?))
        .and_then(|total| total.checked_add(u64::try_from(measurements.entry_symbol.len()).ok()?));
    for section in &measurements.sections {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if !canonical_graphic_name(&section.name, PE_SECTION_NAME_BYTES, is_cancelled)?
            || section.name.starts_with('/')
        {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol names are noncanonical",
            ));
        }
        measurement_bytes = measurement_bytes
            .and_then(|total| total.checked_add(u64::try_from(section.name.len()).ok()?));
    }
    for symbol in &measurements.symbols {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if !canonical_graphic_name(&symbol.name, MAP_SYMBOL_NAME_BYTES, is_cancelled)?
            || !canonical_graphic_name(&symbol.section, PE_SECTION_NAME_BYTES, is_cancelled)?
        {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol names are noncanonical",
            ));
        }
        measurement_bytes = measurement_bytes
            .and_then(|total| total.checked_add(u64::try_from(symbol.name.len()).ok()?))
            .and_then(|total| total.checked_add(u64::try_from(symbol.section.len()).ok()?));
    }
    if measurements.artifact_bytes == 0
        || measurements
            .artifact_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || measurements
            .base_relocation_provenance_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || measurements.sections.len() > limits.sections as usize
        || measurements.symbols.len() > limits.symbols as usize
        || measurements.base_relocations > limits.base_relocations
        || measurement_bytes.is_none_or(|bytes| bytes > limits.measurement_bytes)
        || measurements.coff_machine != target.coff_machine()
        || measurements.subsystem != target.subsystem()
        || measurements.image_base != EFI_IMAGE_BASE
        || measurements.entry_symbol != target.entry_symbol()
        || measurements.entry_virtual_address == 0
        || !plausible_base_relocation_measurements(measurements)
        || measurements.sections.is_empty()
    {
        return Err(LinkError::InvalidMeasurements(
            "header, entry, relocations, or sections do not match the target",
        ));
    }

    for pair in measurements.sections.windows(2) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if pair[0].virtual_address >= pair[1].virtual_address {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
    }

    let mut sections_by_name = Vec::new();
    sections_by_name
        .try_reserve_exact(measurements.sections.len())
        .map_err(|_| LinkError::ResourceLimit {
            resource: "section measurements",
            limit: u64::from(limits.sections),
        })?;
    let mut file_ranges = Vec::new();
    file_ranges
        .try_reserve_exact(measurements.sections.len())
        .map_err(|_| LinkError::ResourceLimit {
            resource: "section measurements",
            limit: u64::from(limits.sections),
        })?;
    let mut previous_virtual_end = None;
    for section in &measurements.sections {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        let Some(file_end) = section.file_offset.checked_add(section.file_bytes) else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        let Some(virtual_end) = section.virtual_address.checked_add(section.virtual_bytes) else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        let Some(loaded_end) = virtual_end
            .checked_add(u64::from(PE_SECTION_ALIGNMENT) - 1)
            .map(|end| end & !(u64::from(PE_SECTION_ALIGNMENT) - 1))
        else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        if section.name.is_empty()
            || section.name.len() > PE_SECTION_NAME_BYTES
            || section.name.starts_with('/')
            || !section.name.bytes().all(|byte| byte.is_ascii_graphic())
            || section.virtual_bytes == 0
            || file_end > measurements.artifact_bytes
            || loaded_end > limits.image_bytes
            || previous_virtual_end.is_some_and(|end| end > section.virtual_address)
        {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
        previous_virtual_end = Some(virtual_end);
        sections_by_name.push(section);
        file_ranges.push((section.file_offset, file_end));
    }
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    sections_by_name.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    if sections_by_name
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(LinkError::InvalidMeasurements(
            "section or symbol measurements are noncanonical or out of range",
        ));
    }
    file_ranges.sort_unstable();
    for pair in file_ranges.windows(2) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if pair[0].1 > pair[1].0 {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
    }

    for pair in measurements.symbols.windows(2) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if pair[0].name >= pair[1].name {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
    }
    let mut entry_matches = 0u32;
    for symbol in &measurements.symbols {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        let Ok(section_index) = sections_by_name
            .binary_search_by(|section| section.name.as_str().cmp(symbol.section.as_str()))
        else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        let section = sections_by_name[section_index];
        let Some(symbol_end) = symbol.virtual_address.checked_add(symbol.bytes) else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        let Some(section_end) = section.virtual_address.checked_add(section.virtual_bytes) else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
        if !canonical_graphic_name(&symbol.name, MAP_SYMBOL_NAME_BYTES, is_cancelled)?
            || !canonical_graphic_name(&symbol.section, PE_SECTION_NAME_BYTES, is_cancelled)?
            || symbol.bytes == 0
            || symbol.virtual_address < section.virtual_address
            || symbol_end > section_end
        {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
        if symbol.name == measurements.entry_symbol {
            if symbol.virtual_address != measurements.entry_virtual_address
                || section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
                || symbol.virtual_address >= section_end
            {
                return Err(LinkError::InvalidMeasurements(
                    "entry symbol does not exactly bind the executable PE entry point",
                ));
            }
            entry_matches = entry_matches
                .checked_add(1)
                .ok_or(LinkError::InvalidMeasurements(
                    "entry symbol evidence overflowed",
                ))?;
        }
    }
    if entry_matches != 1 {
        return Err(LinkError::InvalidMeasurements(
            "entry symbol does not exactly bind the executable PE entry point",
        ));
    }
    Ok(())
}

fn plausible_base_relocation_measurements(measurements: &ImageMeasurements) -> bool {
    let blocks = u64::from(measurements.base_relocation_blocks);
    let relocations = u64::from(measurements.base_relocations);
    if blocks == 0
        || relocations == 0
        || blocks > relocations
        || blocks
            .checked_mul(512)
            .is_none_or(|maximum| relocations > maximum)
    {
        return false;
    }
    let Some(minimum_bytes) = blocks
        .checked_mul(8)
        .and_then(|bytes| relocations.checked_mul(2)?.checked_add(bytes))
    else {
        return false;
    };
    let Some(maximum_bytes) = blocks
        .checked_mul(2)
        .and_then(|padding| minimum_bytes.checked_add(padding))
    else {
        return false;
    };
    measurements.relocation_directory_bytes % 4 == 0
        && measurements.relocation_directory_bytes >= minimum_bytes
        && measurements.relocation_directory_bytes <= maximum_bytes
        && (measurements.relocation_directory_bytes - minimum_bytes) % 2 == 0
}

fn canonical_graphic_name(
    value: &str,
    maximum_bytes: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LinkError> {
    if value.is_empty() || value.len() > maximum_bytes {
        return Ok(false);
    }
    for chunk in value.as_bytes().chunks(4096) {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        if !chunk.iter().all(u8::is_ascii_graphic) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    #[cfg(feature = "bundled-lld")]
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use wrela_build_model::{LanguageRevision, TargetIdentity};
    use wrela_target::{TargetBackendContract, TargetPackage};

    use super::*;

    static NEXT_NATIVE_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn identity(target_package: Sha256Digest) -> BuildIdentity {
        BuildIdentity {
            compiler: Sha256Digest::from_bytes([0x31; 32]),
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package,
            standard_library: Sha256Digest::from_bytes([0x33; 32]),
            source_graph: Sha256Digest::from_bytes([0x34; 32]),
            request: Sha256Digest::from_bytes([0x35; 32]),
            profile: Sha256Digest::from_bytes([0x36; 32]),
        }
    }

    struct RequestFixture {
        build: BuildIdentity,
        target: TargetPackage,
        image: PathBuf,
        runtime: PathBuf,
        output: PathBuf,
        map: PathBuf,
    }

    impl RequestFixture {
        fn new() -> Self {
            let digest = Sha256Digest::from_bytes([0x32; 32]);
            let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
            target.validate().expect("valid target");
            let root = std::fs::canonicalize(std::env::temp_dir())
                .expect("canonical temporary root")
                .join("wrela-link-model");
            Self {
                build: identity(digest),
                target,
                image: root.join("image.obj"),
                runtime: root.join("runtime.obj"),
                output: root.join("image.efi"),
                map: root.join("image.map"),
            }
        }

        fn objects(&self) -> [CoffObject<'_>; 2] {
            [
                CoffObject {
                    ordinal: 0,
                    path: &self.image,
                    expected_digest: Sha256Digest::from_bytes([0x61; 32]),
                    expected_bytes: 64,
                    kind: CoffObjectKind::Image {
                        build: self.build.clone(),
                    },
                },
                CoffObject {
                    ordinal: 1,
                    path: &self.runtime,
                    expected_digest: Sha256Digest::from_bytes([0x62; 32]),
                    expected_bytes: 64,
                    kind: CoffObjectKind::TargetRuntime {
                        target_package: self.target.backend().content_digest(),
                        runtime_abi_version: self.target.backend().runtime_abi_version(),
                    },
                },
            ]
        }

        fn request<'a>(
            &'a self,
            objects: &'a [CoffObject<'a>],
            limits: LinkLimits,
        ) -> LinkRequest<'a> {
            LinkRequest {
                build: &self.build,
                objects,
                target: self.target.backend(),
                output: &self.output,
                map_output: &self.map,
                limits,
            }
        }
    }

    #[test]
    fn link_paths_are_absolute_and_lexically_normal() {
        assert!(safe_absolute_path(Path::new("/private/wrela/image.efi")));
        assert!(!safe_absolute_path(Path::new("relative/image.efi")));
        assert!(!safe_absolute_path(Path::new("/private/./wrela/image.efi")));
        assert!(!safe_absolute_path(Path::new(
            "/private/wrela/../image.efi"
        )));
        assert!(!safe_absolute_path(Path::new("/private//wrela/image.efi")));
    }

    #[test]
    fn lld_arguments_are_fixed_order_utf8_and_exactly_bounded() {
        let fixture = RequestFixture::new();
        let objects = fixture.objects();
        let request = fixture.request(&objects, LinkLimits::standard());
        let provenance_map = provenance_map_path(request.map_output).expect("derived map path");
        let arguments = lld_arguments(&request, &provenance_map, &|| false)
            .expect("bounded canonical arguments");
        assert_eq!(
            arguments,
            [
                "/machine:arm64".to_owned(),
                "/subsystem:efi_application".to_owned(),
                "/entry:wrela_image_entry".to_owned(),
                "/base:0".to_owned(),
                "/nodefaultlib".to_owned(),
                "/brepro".to_owned(),
                "/dynamicbase".to_owned(),
                "/lldignoreenv".to_owned(),
                "/WX".to_owned(),
                format!("/out:{}", fixture.output.display()),
                format!("/map:{}", fixture.map.display()),
                format!("/lldmap:{}", provenance_map.display()),
                fixture.image.display().to_string(),
                fixture.runtime.display().to_string(),
            ]
        );
        let exact = arguments
            .iter()
            .map(|argument| argument.len() as u64 + 1)
            .sum();
        let mut limits = LinkLimits::standard();
        limits.argument_bytes = exact;
        validate_link_request(&fixture.request(&objects, limits), &|| false)
            .expect("exact argument bytes");
        limits.argument_bytes -= 1;
        assert!(matches!(
            validate_link_request(&fixture.request(&objects, limits), &|| false),
            Err(LinkError::ArgumentTooLarge {
                limit,
                actual
            }) if limit + 1 == actual
        ));
    }

    #[test]
    fn artifact_sealer_rechecks_complete_link_request_and_measurements() {
        let fixture = RequestFixture::new();
        let objects = fixture.objects();
        let request = fixture.request(&objects, LinkLimits::standard());
        let measurements = valid_measurements(request.target);
        let artifact = seal_artifact(&request, measurements.clone(), &|| false)
            .expect("complete verified artifact tuple");
        assert_eq!(artifact.path(), fixture.output);
        assert_eq!(artifact.map(), fixture.map);
        assert_eq!(artifact.measurements(), &measurements);

        let mut missing_entry = measurements.clone();
        missing_entry.symbols.clear();
        assert!(matches!(
            seal_artifact(&request, missing_entry, &|| false),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let mut wrong_base = valid_measurements(request.target);
        wrong_base.image_base = 0x0000_0001_4000_0000;
        assert!(matches!(
            seal_artifact(&request, wrong_base, &|| false),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let mut zero_digest = valid_measurements(request.target);
        zero_digest.artifact_digest = Sha256Digest::from_bytes([0; 32]);
        assert!(matches!(
            seal_artifact(&request, zero_digest, &|| false),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let mut entry_drift = valid_measurements(request.target);
        entry_drift.entry_virtual_address += 4;
        assert!(matches!(
            seal_artifact(&request, entry_drift, &|| false),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let mut empty_entry = valid_measurements(request.target);
        empty_entry.symbols[0].bytes = 0;
        assert!(matches!(
            seal_artifact(&request, empty_entry, &|| false),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let exact_measurement_bytes = measurements.coff_machine.len()
            + measurements.subsystem.len()
            + measurements.entry_symbol.len()
            + measurements
                .sections
                .iter()
                .map(|section| section.name.len())
                .sum::<usize>()
            + measurements
                .symbols
                .iter()
                .map(|symbol| symbol.name.len() + symbol.section.len())
                .sum::<usize>();
        let mut exact_limits = LinkLimits::standard();
        exact_limits.sections = 2;
        exact_limits.symbols = 1;
        exact_limits.base_relocations = 1;
        exact_limits.image_bytes = 0x3000;
        exact_limits.measurement_bytes = exact_measurement_bytes as u64;
        seal_artifact(
            &fixture.request(&objects, exact_limits),
            measurements.clone(),
            &|| false,
        )
        .expect("exact section, symbol, relocation, and measurement ceilings");
        let mut below_virtual_extent = exact_limits;
        below_virtual_extent.image_bytes = 0x2fff;
        assert!(matches!(
            seal_artifact(
                &fixture.request(&objects, below_virtual_extent),
                measurements.clone(),
                &|| false,
            ),
            Err(LinkError::InvalidMeasurements(_))
        ));
        let mut too_many_relocations = measurements.clone();
        too_many_relocations.base_relocations = 2;
        assert!(matches!(
            seal_artifact(
                &fixture.request(&objects, exact_limits),
                too_many_relocations,
                &|| false,
            ),
            Err(LinkError::InvalidMeasurements(_))
        ));
        exact_limits.measurement_bytes -= 1;
        assert!(matches!(
            seal_artifact(
                &fixture.request(&objects, exact_limits),
                measurements.clone(),
                &|| false,
            ),
            Err(LinkError::InvalidMeasurements(_))
        ));

        let mut stale_objects = fixture.objects();
        let CoffObjectKind::Image { build } = &mut stale_objects[0].kind else {
            panic!("image object");
        };
        build.source_graph = Sha256Digest::from_bytes([0x91; 32]);
        let stale = fixture.request(&stale_objects, LinkLimits::standard());
        assert!(matches!(
            seal_artifact(&stale, measurements, &|| false),
            Err(LinkError::BuildIdentityMismatch)
        ));
        assert!(matches!(
            validate_link_request(&request, &|| true),
            Err(LinkError::Cancelled)
        ));
    }

    fn valid_measurements(target: &TargetBackendContract) -> ImageMeasurements {
        ImageMeasurements {
            artifact_bytes: 1536,
            artifact_digest: Sha256Digest::from_bytes([0x71; 32]),
            coff_machine: target.coff_machine().to_owned(),
            subsystem: target.subsystem().to_owned(),
            image_base: EFI_IMAGE_BASE,
            entry_symbol: target.entry_symbol().to_owned(),
            entry_virtual_address: 0x1000,
            relocation_directory_bytes: 12,
            base_relocation_blocks: 1,
            base_relocations: 1,
            base_relocation_provenance_digest: Sha256Digest::from_bytes([0x73; 32]),
            sections: vec![
                LinkedSection {
                    name: ".text".to_owned(),
                    virtual_address: 0x1000,
                    virtual_bytes: 8,
                    file_offset: 512,
                    file_bytes: 512,
                    characteristics: 0x6000_0020,
                },
                LinkedSection {
                    name: ".reloc".to_owned(),
                    virtual_address: 0x2000,
                    virtual_bytes: 12,
                    file_offset: 1024,
                    file_bytes: 512,
                    characteristics: 0x4200_0040,
                },
            ],
            symbols: vec![LinkedSymbol {
                name: target.entry_symbol().to_owned(),
                section: ".text".to_owned(),
                virtual_address: 0x1000,
                bytes: 8,
            }],
        }
    }

    struct StaticImageInspector {
        measurements: ImageMeasurements,
    }

    impl LinkedImageInspector for StaticImageInspector {
        fn inspect(
            &self,
            _image: &Path,
            _map: &Path,
            _provenance_map: &Path,
            _inputs: &[CoffProvenanceInput<'_>],
            _target: &TargetBackendContract,
            _limits: ImageInspectLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ImageMeasurements, InspectError> {
            Ok(self.measurements.clone())
        }
    }

    struct RejectingImageInspector;

    impl LinkedImageInspector for RejectingImageInspector {
        fn inspect(
            &self,
            _image: &Path,
            _map: &Path,
            _provenance_map: &Path,
            _inputs: &[CoffProvenanceInput<'_>],
            _target: &TargetBackendContract,
            _limits: ImageInspectLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ImageMeasurements, InspectError> {
            Err(InspectError::InvalidMap(
                "injected post-link rejection".to_owned(),
            ))
        }
    }

    #[cfg(feature = "bundled-lld")]
    #[derive(Clone, Copy)]
    enum ContributionMapMutation {
        None,
        SubstituteFirstPdata,
        DuplicateFirstPdata,
    }

    #[cfg(feature = "bundled-lld")]
    struct ProbingImageInspector {
        mutation: ContributionMapMutation,
        observed_map: RefCell<Vec<u8>>,
    }

    #[cfg(feature = "bundled-lld")]
    impl ProbingImageInspector {
        fn new(mutation: ContributionMapMutation) -> Self {
            Self {
                mutation,
                observed_map: RefCell::new(Vec::new()),
            }
        }
    }

    #[cfg(feature = "bundled-lld")]
    impl LinkedImageInspector for ProbingImageInspector {
        fn inspect(
            &self,
            image: &Path,
            map: &Path,
            provenance_map: &Path,
            inputs: &[CoffProvenanceInput<'_>],
            target: &TargetBackendContract,
            limits: ImageInspectLimits,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ImageMeasurements, InspectError> {
            let raw = fs::read(provenance_map).expect("real LLD contribution map");
            self.observed_map.replace(raw.clone());
            let identity = format!("{}:(.pdata)", inputs[0].path().display());
            let canonical = String::from_utf8(raw).expect("ASCII LLD contribution map");
            let mutated = match self.mutation {
                ContributionMapMutation::None => None,
                ContributionMapMutation::SubstituteFirstPdata => Some(canonical.replacen(
                    &identity,
                    &format!("{}:(.pdatb)", inputs[0].path().display()),
                    1,
                )),
                ContributionMapMutation::DuplicateFirstPdata => {
                    let row = canonical
                        .lines()
                        .find(|line| line.ends_with(&identity))
                        .expect("first real duplicate pdata contribution");
                    let row = format!("{row}\n");
                    Some(canonical.replacen(&row, &(row.clone() + &row), 1))
                }
            };
            if let Some(mutated) = mutated {
                fs::write(provenance_map, mutated).expect("mutated contribution map fixture");
            }
            CanonicalLinkedImageInspector::new().inspect(
                image,
                map,
                provenance_map,
                inputs,
                target,
                limits,
                is_cancelled,
            )
        }
    }

    struct NativeDirectory {
        root: PathBuf,
    }

    impl NativeDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
            for _ in 0..128 {
                let sequence = NEXT_NATIVE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
                    "wrela-link-native-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical native directory"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create native link directory: {error}"),
                }
            }
            panic!("cannot allocate native link directory")
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(name);
            fs::write(&path, bytes).expect("write native object fixture");
            path
        }
    }

    impl Drop for NativeDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn entry_coff() -> Vec<u8> {
        const RAW_DATA: usize = 60;
        const SYMBOL_TABLE: usize = RAW_DATA + 8;
        coff_with_entry_symbol(SYMBOL_TABLE, |bytes| {
            bytes[20..25].copy_from_slice(b".text");
            bytes[36..40].copy_from_slice(&8u32.to_le_bytes());
            bytes[40..44].copy_from_slice(
                &u32::try_from(RAW_DATA)
                    .expect("raw data offset")
                    .to_le_bytes(),
            );
            bytes[56..60].copy_from_slice(&0x6050_0020u32.to_le_bytes());
            bytes[RAW_DATA..RAW_DATA + 8]
                .copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
            bytes[SYMBOL_TABLE + 12..SYMBOL_TABLE + 14].copy_from_slice(&1i16.to_le_bytes());
            bytes[SYMBOL_TABLE + 14..SYMBOL_TABLE + 16].copy_from_slice(&0x20u16.to_le_bytes());
        })
    }

    #[cfg(feature = "bundled-lld")]
    fn entry_coff_with_duplicate_live_pdata_sections() -> Vec<u8> {
        const fn packed_unwind(function_words: u32) -> u32 {
            (1 << 23) | (1 << 21) | (function_words << 2) | 1
        }

        const ENTRY_RAW_DATA: usize = 180;
        const ENTRY_RELOCATION: usize = ENTRY_RAW_DATA + 8;
        const HELPER_RAW_DATA: usize = ENTRY_RELOCATION + 10;
        const FIRST_PDATA: usize = HELPER_RAW_DATA + 12;
        const FIRST_PDATA_RELOCATION: usize = FIRST_PDATA + 8;
        const SECOND_PDATA: usize = FIRST_PDATA_RELOCATION + 10;
        const SECOND_PDATA_RELOCATION: usize = SECOND_PDATA + 8;
        const SYMBOL_TABLE: usize = SECOND_PDATA_RELOCATION + 10;
        const ENTRY_SYMBOL: usize = SYMBOL_TABLE;
        const HELPER_SYMBOL: usize = ENTRY_SYMBOL + 18;
        const STRING_TABLE: usize = HELPER_SYMBOL + 18;
        const ENTRY: &[u8] = b"wrela_image_entry";

        let mut bytes = vec![0u8; STRING_TABLE + 4 + ENTRY.len() + 1];
        bytes[0..2].copy_from_slice(&0xaa64u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&4u16.to_le_bytes());
        bytes[8..12].copy_from_slice(
            &u32::try_from(SYMBOL_TABLE)
                .expect("symbol table offset")
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());

        bytes[20..25].copy_from_slice(b".text");
        bytes[36..40].copy_from_slice(&8u32.to_le_bytes());
        bytes[40..44].copy_from_slice(
            &u32::try_from(ENTRY_RAW_DATA)
                .expect("entry raw data offset")
                .to_le_bytes(),
        );
        bytes[44..48].copy_from_slice(
            &u32::try_from(ENTRY_RELOCATION)
                .expect("entry relocation offset")
                .to_le_bytes(),
        );
        bytes[52..54].copy_from_slice(&1u16.to_le_bytes());
        bytes[56..60].copy_from_slice(&0x6050_0020u32.to_le_bytes());

        bytes[60..67].copy_from_slice(b".text$h");
        bytes[76..80].copy_from_slice(&12u32.to_le_bytes());
        bytes[80..84].copy_from_slice(
            &u32::try_from(HELPER_RAW_DATA)
                .expect("helper raw data offset")
                .to_le_bytes(),
        );
        bytes[96..100].copy_from_slice(&0x6050_0020u32.to_le_bytes());

        bytes[100..106].copy_from_slice(b".pdata");
        bytes[116..120].copy_from_slice(&8u32.to_le_bytes());
        bytes[120..124].copy_from_slice(
            &u32::try_from(FIRST_PDATA)
                .expect("first pdata offset")
                .to_le_bytes(),
        );
        bytes[124..128].copy_from_slice(
            &u32::try_from(FIRST_PDATA_RELOCATION)
                .expect("first pdata relocation offset")
                .to_le_bytes(),
        );
        bytes[132..134].copy_from_slice(&1u16.to_le_bytes());
        bytes[136..140].copy_from_slice(&0x4030_0040u32.to_le_bytes());

        bytes[140..146].copy_from_slice(b".pdata");
        bytes[156..160].copy_from_slice(&8u32.to_le_bytes());
        bytes[160..164].copy_from_slice(
            &u32::try_from(SECOND_PDATA)
                .expect("second pdata offset")
                .to_le_bytes(),
        );
        bytes[164..168].copy_from_slice(
            &u32::try_from(SECOND_PDATA_RELOCATION)
                .expect("second pdata relocation offset")
                .to_le_bytes(),
        );
        bytes[172..174].copy_from_slice(&1u16.to_le_bytes());
        bytes[176..180].copy_from_slice(&0x4030_0040u32.to_le_bytes());

        bytes[ENTRY_RAW_DATA..ENTRY_RAW_DATA + 4].copy_from_slice(&0x9400_0000u32.to_le_bytes());
        bytes[ENTRY_RAW_DATA + 4..ENTRY_RAW_DATA + 8]
            .copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
        bytes[HELPER_RAW_DATA..HELPER_RAW_DATA + 4].copy_from_slice(&0xaa00_03e0u32.to_le_bytes());
        bytes[HELPER_RAW_DATA + 4..HELPER_RAW_DATA + 8]
            .copy_from_slice(&0xd503_201fu32.to_le_bytes());
        bytes[HELPER_RAW_DATA + 8..HELPER_RAW_DATA + 12]
            .copy_from_slice(&0xd65f_03c0u32.to_le_bytes());

        bytes[FIRST_PDATA + 4..FIRST_PDATA + 8].copy_from_slice(&packed_unwind(2).to_le_bytes());
        bytes[SECOND_PDATA + 4..SECOND_PDATA + 8].copy_from_slice(&packed_unwind(3).to_le_bytes());

        bytes[ENTRY_RELOCATION + 4..ENTRY_RELOCATION + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[ENTRY_RELOCATION + 8..ENTRY_RELOCATION + 10]
            .copy_from_slice(&0x0003u16.to_le_bytes());
        bytes[FIRST_PDATA_RELOCATION + 8..FIRST_PDATA_RELOCATION + 10]
            .copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[SECOND_PDATA_RELOCATION + 4..SECOND_PDATA_RELOCATION + 8]
            .copy_from_slice(&1u32.to_le_bytes());
        bytes[SECOND_PDATA_RELOCATION + 8..SECOND_PDATA_RELOCATION + 10]
            .copy_from_slice(&0x0002u16.to_le_bytes());

        bytes[ENTRY_SYMBOL + 4..ENTRY_SYMBOL + 8].copy_from_slice(&4u32.to_le_bytes());
        bytes[ENTRY_SYMBOL + 12..ENTRY_SYMBOL + 14].copy_from_slice(&1i16.to_le_bytes());
        bytes[ENTRY_SYMBOL + 14..ENTRY_SYMBOL + 16].copy_from_slice(&0x20u16.to_le_bytes());
        bytes[ENTRY_SYMBOL + 16] = 2;

        bytes[HELPER_SYMBOL..HELPER_SYMBOL + 6].copy_from_slice(b"helper");
        bytes[HELPER_SYMBOL + 12..HELPER_SYMBOL + 14].copy_from_slice(&2i16.to_le_bytes());
        bytes[HELPER_SYMBOL + 14..HELPER_SYMBOL + 16].copy_from_slice(&0x20u16.to_le_bytes());
        bytes[HELPER_SYMBOL + 16] = 2;

        bytes[STRING_TABLE..STRING_TABLE + 4].copy_from_slice(
            &u32::try_from(4 + ENTRY.len() + 1)
                .expect("string table bytes")
                .to_le_bytes(),
        );
        bytes[STRING_TABLE + 4..STRING_TABLE + 4 + ENTRY.len()].copy_from_slice(ENTRY);
        bytes
    }

    #[cfg(feature = "bundled-lld")]
    fn entry_coff_with_initialized_data() -> Vec<u8> {
        const TEXT_RAW_DATA: usize = 100;
        const DATA_RAW_DATA: usize = TEXT_RAW_DATA + 8;
        const SYMBOL_TABLE: usize = DATA_RAW_DATA + 8;
        coff_with_entry_symbol(SYMBOL_TABLE, |bytes| {
            bytes[2..4].copy_from_slice(&2u16.to_le_bytes());

            bytes[20..25].copy_from_slice(b".text");
            bytes[36..40].copy_from_slice(&8u32.to_le_bytes());
            bytes[40..44].copy_from_slice(
                &u32::try_from(TEXT_RAW_DATA)
                    .expect("text raw data offset")
                    .to_le_bytes(),
            );
            bytes[56..60].copy_from_slice(&0x6050_0020u32.to_le_bytes());

            bytes[60..65].copy_from_slice(b".data");
            bytes[76..80].copy_from_slice(&8u32.to_le_bytes());
            bytes[80..84].copy_from_slice(
                &u32::try_from(DATA_RAW_DATA)
                    .expect("data raw data offset")
                    .to_le_bytes(),
            );
            bytes[96..100].copy_from_slice(&0xc040_0040u32.to_le_bytes());

            bytes[TEXT_RAW_DATA..TEXT_RAW_DATA + 8]
                .copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
            bytes[DATA_RAW_DATA..DATA_RAW_DATA + 8]
                .copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
            bytes[SYMBOL_TABLE + 12..SYMBOL_TABLE + 14].copy_from_slice(&1i16.to_le_bytes());
            bytes[SYMBOL_TABLE + 14..SYMBOL_TABLE + 16].copy_from_slice(&0x20u16.to_le_bytes());
        })
    }

    fn relocatable_runtime_coff() -> Vec<u8> {
        const RAW_DATA: usize = 60;
        const RELOCATION: usize = RAW_DATA + 8;
        const SYMBOL_TABLE: usize = RELOCATION + 10;
        coff_with_entry_symbol(SYMBOL_TABLE, |bytes| {
            bytes[20..26].copy_from_slice(b".rdata");
            bytes[36..40].copy_from_slice(&8u32.to_le_bytes());
            bytes[40..44].copy_from_slice(
                &u32::try_from(RAW_DATA)
                    .expect("raw data offset")
                    .to_le_bytes(),
            );
            bytes[44..48].copy_from_slice(
                &u32::try_from(RELOCATION)
                    .expect("relocation offset")
                    .to_le_bytes(),
            );
            bytes[52..54].copy_from_slice(&1u16.to_le_bytes());
            bytes[56..60].copy_from_slice(&0x4040_0040u32.to_le_bytes());
            bytes[RELOCATION + 8..RELOCATION + 10].copy_from_slice(&0x000eu16.to_le_bytes());
        })
    }

    fn coff_with_entry_symbol(symbol_table: usize, fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
        const ENTRY: &[u8] = b"wrela_image_entry";
        let string_table = symbol_table + 18;
        let mut bytes = vec![0u8; string_table + 4 + ENTRY.len() + 1];
        bytes[0..2].copy_from_slice(&0xaa64u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(
            &u32::try_from(symbol_table)
                .expect("symbol table offset")
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[symbol_table + 4..symbol_table + 8].copy_from_slice(&4u32.to_le_bytes());
        bytes[symbol_table + 16] = 2;
        bytes[string_table..string_table + 4].copy_from_slice(
            &u32::try_from(4 + ENTRY.len() + 1)
                .expect("string table bytes")
                .to_le_bytes(),
        );
        bytes[string_table + 4..string_table + 4 + ENTRY.len()].copy_from_slice(ENTRY);
        fill(&mut bytes);
        bytes
    }

    #[cfg(feature = "bundled-lld")]
    fn native_reproducible_link(
        root: &Path,
        digest: Sha256Digest,
        target: &TargetPackage,
        build: &BuildIdentity,
    ) -> (ImageMeasurements, Vec<u8>, Vec<u8>) {
        fs::create_dir(root).expect("create path-distinct native root");
        let image = root.join("image.obj");
        let runtime = root.join("runtime.obj");
        fs::write(&image, entry_coff()).expect("write entry object");
        fs::write(&runtime, relocatable_runtime_coff()).expect("write runtime object");
        let output = root.join("image.efi");
        let map = root.join("image.map");
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("entry object measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("runtime object measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let request = LinkRequest {
            build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        let image_inspector = CanonicalLinkedImageInspector::new();
        let linker = LldEfiLinker {
            object_inspector: &object_inspector,
            image_inspector: &image_inspector,
        };
        let artifact = linker
            .link(&request, &|| false)
            .expect("path-distinct native EFI link");
        let measurements = artifact.measurements().clone();
        let provenance_map = provenance_map_path(&map).expect("derived provenance map path");
        assert!(!provenance_map.exists());
        (
            measurements,
            fs::read(output).expect("native EFI bytes"),
            fs::read(map).expect("native map bytes"),
        )
    }

    #[test]
    fn object_seal_requires_one_image_entry_and_no_runtime_collision() {
        let directory = NativeDirectory::new();
        let first_image = directory.write("first.obj", &entry_coff());
        let second_image = directory.write("second.obj", &entry_coff());
        let runtime = directory.write("runtime.obj", &relocatable_runtime_coff());
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        let build = identity(digest);
        let inspector = CanonicalCoffObjectInspector::new();
        let first = inspector
            .inspect(&first_image, 1024 * 1024, &|| false)
            .expect("first entry object");
        let second = inspector
            .inspect(&second_image, 1024 * 1024, &|| false)
            .expect("second entry object");
        let runtime_measurement = inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("runtime object");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &first_image,
                expected_digest: first.digest,
                expected_bytes: first.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &second_image,
                expected_digest: second.digest,
                expected_bytes: second.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 2,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let output = directory.root.join("image.efi");
        let map = directory.root.join("image.map");
        let request = LinkRequest {
            build: &build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        assert!(matches!(
            inspect_objects(&request, &inspector, &|| false),
            Err(LinkError::EntryAbiMismatch)
        ));
        assert!(matches!(
            inspect_objects(&request, &inspector, &|| true),
            Err(LinkError::Cancelled)
        ));

        let collision_objects = [
            CoffObject {
                ordinal: 0,
                path: &first_image,
                expected_digest: first.digest,
                expected_bytes: first.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &second_image,
                expected_digest: second.digest,
                expected_bytes: second.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let collision_request = LinkRequest {
            build: &build,
            objects: &collision_objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        assert!(matches!(
            inspect_objects(&collision_request, &inspector, &|| false),
            Err(LinkError::EntryAbiMismatch)
        ));
    }

    #[test]
    fn every_failed_or_cancelled_native_attempt_removes_unsealed_outputs() {
        let directory = NativeDirectory::new();
        let image = directory.write("image.obj", &entry_coff());
        let runtime = directory.write("runtime.obj", &relocatable_runtime_coff());
        let output = directory.root.join("image.efi");
        let map = directory.root.join("image.map");
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        target.validate().expect("valid target");
        let build = identity(digest);
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("entry object measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("runtime object measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let request = LinkRequest {
            build: &build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };

        let failing_driver = |_: &[String]| {
            fs::write(&output, b"partial image").expect("partial native image");
            fs::write(&map, b"partial map").expect("partial native map");
            Err(wrela_lld_sys::LldError::DriverFailed {
                status: 1,
                diagnostic: "injected native failure".to_owned(),
            })
        };
        assert!(matches!(
            link_with_driver(
                &request,
                &object_inspector,
                &RejectingImageInspector,
                &|| false,
                &failing_driver,
            ),
            Err(LinkError::Lld(wrela_lld_sys::LldError::DriverFailed {
                status: 1,
                ..
            }))
        ));
        assert!(!output.exists());
        assert!(!map.exists());

        let cancelled = Cell::new(false);
        let cancelling_driver = |_: &[String]| {
            fs::write(&output, b"cancelled image").expect("cancelled native image");
            fs::write(&map, b"cancelled map").expect("cancelled native map");
            cancelled.set(true);
            Ok(())
        };
        assert!(matches!(
            link_with_driver(
                &request,
                &object_inspector,
                &RejectingImageInspector,
                &|| cancelled.get(),
                &cancelling_driver,
            ),
            Err(LinkError::Cancelled)
        ));
        assert!(!output.exists());
        assert!(!map.exists());

        let successful_driver = |_: &[String]| {
            fs::write(&output, vec![0u8; 1536]).expect("native image");
            fs::write(&map, b"native map").expect("native map");
            Ok(())
        };
        assert!(matches!(
            link_with_driver(
                &request,
                &object_inspector,
                &RejectingImageInspector,
                &|| false,
                &successful_driver,
            ),
            Err(LinkError::Inspect(InspectError::InvalidMap(_)))
        ));
        assert!(!output.exists());
        assert!(!map.exists());

        let inspector = StaticImageInspector {
            measurements: valid_measurements(target.backend()),
        };
        let artifact = link_with_driver(
            &request,
            &object_inspector,
            &inspector,
            &|| false,
            &successful_driver,
        )
        .expect("fully sealed success preserves outputs");
        assert_eq!(artifact.path(), output);
        assert!(output.is_file());
        assert!(map.is_file());
    }

    #[test]
    fn cleanup_failure_is_a_structured_residual_output_error() {
        let directory = NativeDirectory::new();
        let output = directory.root.join("residual.efi");
        let map = directory.root.join("residual.map");
        let provenance_map = provenance_map_path(&map).expect("derived map path");
        let cleanup = LinkOutputCleanup::new(&output, &map, &provenance_map);
        fs::create_dir(&output).expect("adversarial output directory");
        fs::write(&map, b"partial map").expect("partial map");
        assert!(matches!(
            cleanup.cleanup(LinkError::Cancelled),
            LinkError::ResidualOutput { path } if path == output
        ));
        assert!(output.is_dir());
        assert!(!map.exists());
    }

    #[cfg(feature = "bundled-lld")]
    #[test]
    fn public_linker_accepts_duplicate_unwind_sections_and_rejects_map_substitution() {
        let directory = NativeDirectory::new();
        let image = directory.write(
            "duplicate-unwind-image.obj",
            &entry_coff_with_duplicate_live_pdata_sections(),
        );
        let runtime = directory.write("duplicate-unwind-runtime.obj", &relocatable_runtime_coff());
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        target.validate().expect("valid target");
        let build = identity(digest);
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("duplicate-unwind image measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("relocation-bearing runtime measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let run = |stem: &str, mutation| {
            let output = directory.root.join(format!("{stem}.efi"));
            let map = directory.root.join(format!("{stem}.map"));
            let inspector = ProbingImageInspector::new(mutation);
            let request = LinkRequest {
                build: &build,
                objects: &objects,
                target: target.backend(),
                output: &output,
                map_output: &map,
                limits: LinkLimits::standard(),
            };
            let result = link(&request, &object_inspector, &inspector, &|| false);
            (result, inspector.observed_map.into_inner())
        };

        let (linked, raw_map) = run("canonical-duplicate-unwind", ContributionMapMutation::None);
        let identity = format!("{}:(.pdata)", image.display());
        let map = String::from_utf8(raw_map).expect("ASCII real LLD contribution map");
        let rows: Vec<_> = map
            .lines()
            .filter(|line| line.ends_with(&identity))
            .collect();
        assert_eq!(
            rows.len(),
            2,
            "real LLD must preserve both physical pdata contributions: {map}"
        );
        assert_eq!(&rows[0][9..23], "00000008     4");
        assert_eq!(&rows[1][9..23], "00000008     4");
        assert_eq!(
            u64::from_str_radix(&rows[1][..8], 16).expect("second pdata RVA")
                - u64::from_str_radix(&rows[0][..8], 16).expect("first pdata RVA"),
            8,
            "LLD must retain COFF ordinal order for indistinguishable pdata keys"
        );
        let artifact = linked.expect("real duplicate-unwind contribution inspection");
        assert_eq!(artifact.measurements().base_relocations, 1);

        let (substituted, _) = run(
            "substituted-duplicate-unwind",
            ContributionMapMutation::SubstituteFirstPdata,
        );
        assert!(matches!(
            substituted,
            Err(LinkError::Inspect(
                InspectError::InvalidRelocationProvenance(_)
            ))
        ));
        let (duplicated, _) = run(
            "duplicated-duplicate-unwind",
            ContributionMapMutation::DuplicateFirstPdata,
        );
        assert!(matches!(
            duplicated,
            Err(LinkError::Inspect(
                InspectError::InvalidRelocationProvenance(_)
            ))
        ));
    }

    #[cfg(feature = "bundled-lld")]
    #[test]
    fn bundled_lld_emits_reproducible_relocation_bearing_efi_and_map() {
        let directory = NativeDirectory::new();
        let image = directory.write("image.obj", &entry_coff());
        let runtime = directory.write("runtime.obj", &relocatable_runtime_coff());
        let output = directory.root.join("image.efi");
        let map = directory.root.join("image.map");
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        target.validate().expect("valid target");
        let build = identity(digest);
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("entry object measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("runtime object measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let request = LinkRequest {
            build: &build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        let image_inspector = CanonicalLinkedImageInspector::new();
        let linker = LldEfiLinker {
            object_inspector: &object_inspector,
            image_inspector: &image_inspector,
        };
        let first = linker
            .link(&request, &|| false)
            .expect("first native EFI link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let metadata = fs::symlink_metadata(&output).expect("native EFI metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(first.measurements().coff_machine, "arm64");
        assert_eq!(first.measurements().subsystem, "efi_application");
        assert_eq!(first.measurements().image_base, EFI_IMAGE_BASE);
        assert_eq!(first.measurements().relocation_directory_bytes, 12);
        assert_eq!(first.measurements().base_relocation_blocks, 1);
        assert_eq!(first.measurements().base_relocations, 1);
        assert!(
            first
                .measurements()
                .base_relocation_provenance_digest
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        let provenance_map = provenance_map_path(&map).expect("derived provenance map path");
        assert!(!provenance_map.exists());
        let first_image = fs::read(&output).expect("first image bytes");
        let first_map = fs::read(&map).expect("first map bytes");
        fs::remove_file(&output).expect("remove first image");
        fs::remove_file(&map).expect("remove first map");
        let second = linker
            .link(&request, &|| false)
            .expect("second native EFI link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let metadata = fs::symlink_metadata(&output).expect("repeated native EFI metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(first.measurements(), second.measurements());
        assert_eq!(first_image, fs::read(&output).expect("second image bytes"));
        assert_eq!(first_map, fs::read(&map).expect("second map bytes"));
        assert!(!provenance_map.exists());

        let path_roots = NativeDirectory::new();
        let (short_measurements, short_image, short_map) =
            native_reproducible_link(&path_roots.root.join("a"), digest, &target, &build);
        let (long_measurements, long_image, long_map) = native_reproducible_link(
            &path_roots
                .root
                .join("independent-much-longer-private-native-root"),
            digest,
            &target,
            &build,
        );
        assert_eq!(short_image, long_image);
        assert_eq!(short_map, long_map);
        assert_eq!(short_measurements, long_measurements);
    }

    #[cfg(feature = "bundled-lld")]
    #[test]
    fn bundled_lld_accepts_checked_in_runtime_zero_fill_data_extent() {
        let directory = NativeDirectory::new();
        let image = directory.write("image.obj", &entry_coff());
        let runtime = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
        ))
        .expect("checked-in runtime object");
        let output = directory.root.join("runtime-image.efi");
        let map = directory.root.join("runtime-image.map");
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        target.validate().expect("valid target");
        let build = identity(digest);
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("entry object measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("checked-in runtime measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let request = LinkRequest {
            build: &build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        let image_inspector = CanonicalLinkedImageInspector::new();
        let linker = LldEfiLinker {
            object_inspector: &object_inspector,
            image_inspector: &image_inspector,
        };
        let artifact = linker
            .link(&request, &|| false)
            .expect("checked-in runtime EFI link");
        let data = artifact
            .measurements()
            .sections
            .iter()
            .find(|section| section.name == ".data")
            .expect("pinned LLD zero-fill data section");
        assert_eq!(data.virtual_bytes, 73_984);
        assert_eq!((data.file_offset, data.file_bytes), (0, 0));
        assert_eq!(data.characteristics, 0xc000_0040);
    }

    #[cfg(feature = "bundled-lld")]
    #[test]
    fn bundled_lld_accepts_initialized_data_prefix_with_checked_in_runtime_zero_fill_tail() {
        let directory = NativeDirectory::new();
        let image = directory.write("mixed-image.obj", &entry_coff_with_initialized_data());
        let runtime = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
        ))
        .expect("checked-in runtime object");
        let output = directory.root.join("mixed-runtime-image.efi");
        let map = directory.root.join("mixed-runtime-image.map");
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        target.validate().expect("valid target");
        let build = identity(digest);
        let object_inspector = CanonicalCoffObjectInspector::new();
        let image_measurement = object_inspector
            .inspect(&image, 1024 * 1024, &|| false)
            .expect("entry and initialized data object measurement");
        let runtime_measurement = object_inspector
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("checked-in runtime measurement");
        let objects = [
            CoffObject {
                ordinal: 0,
                path: &image,
                expected_digest: image_measurement.digest,
                expected_bytes: image_measurement.bytes,
                kind: CoffObjectKind::Image {
                    build: build.clone(),
                },
            },
            CoffObject {
                ordinal: 1,
                path: &runtime,
                expected_digest: runtime_measurement.digest,
                expected_bytes: runtime_measurement.bytes,
                kind: CoffObjectKind::TargetRuntime {
                    target_package: digest,
                    runtime_abi_version: target.backend().runtime_abi_version(),
                },
            },
        ];
        let request = LinkRequest {
            build: &build,
            objects: &objects,
            target: target.backend(),
            output: &output,
            map_output: &map,
            limits: LinkLimits::standard(),
        };
        let image_inspector = CanonicalLinkedImageInspector::new();
        let linker = LldEfiLinker {
            object_inspector: &object_inspector,
            image_inspector: &image_inspector,
        };
        let artifact = linker
            .link(&request, &|| false)
            .expect("mixed initialized and zero-fill data EFI link");
        let data = artifact
            .measurements()
            .sections
            .iter()
            .find(|section| section.name == ".data")
            .expect("pinned LLD mixed data section");
        assert!(data.file_bytes > 0);
        assert!(data.virtual_bytes > data.file_bytes);
        assert_ne!(data.file_offset, 0);
        assert_eq!(data.characteristics, 0xc000_0040);
    }
}
