//! Safe AArch64 EFI link policy over the private raw LLD COFF boundary.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{BuildIdentity, Sha256Digest};
use wrela_target::{ObjectFormat, TargetBackendContract};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkLimits {
    pub objects: u32,
    pub object_bytes: u64,
    pub image_bytes: u64,
    pub map_bytes: u64,
    pub sections: u32,
    pub symbols: u32,
    pub measurement_bytes: u64,
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
            measurement_bytes: 4 * 1024 * 1024 * 1024,
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
            && self.measurement_bytes > 0
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
/// manifest verification. Backend orchestration converts this to the final
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
    pub fn as_coff_object(&self, ordinal: u32) -> CoffObject<'a> {
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
/// Production implementations parse the ordinary COFF header and hash the
/// same bytes they inspect; a caller's `CoffObjectKind` is never sufficient
/// evidence by itself.
pub trait CoffObjectInspector {
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
    pub entry_symbol: String,
    pub entry_virtual_address: u64,
    pub relocation_directory_bytes: u64,
    pub sections: Vec<LinkedSection>,
    pub symbols: Vec<LinkedSymbol>,
}

/// Parses the emitted PE32+ image and deterministic LLD map. Production
/// implementations must bounds-check all offsets before allocation and hash
/// the exact image bytes they inspect.
pub trait LinkedImageInspector {
    fn inspect(
        &self,
        image: &Path,
        map: &Path,
        maximum_image_bytes: u64,
        maximum_map_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageMeasurements, InspectError>;
}

/// Link service consumed by backend orchestration. Tests can inject a sealed
/// fake without loading LLD or touching the host filesystem.
pub trait EfiLinker {
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
    Io(String),
    TooLarge { limit: u64, actual: u64 },
    Truncated,
    InvalidCoffHeader,
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
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn measurements(&self) -> &ImageMeasurements {
        &self.measurements
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
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
    InvalidLimits,
    ObjectInspect {
        path: PathBuf,
        error: CoffInspectError,
    },
    ObjectMismatch {
        path: PathBuf,
    },
    Lld(wrela_lld_sys::LldError),
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
            Self::Lld(error) => error.fmt(formatter),
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

pub fn link(
    request: &LinkRequest<'_>,
    object_inspector: &dyn CoffObjectInspector,
    image_inspector: &dyn LinkedImageInspector,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EfiArtifact, LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    if request.target.object_format() != ObjectFormat::Coff {
        return Err(LinkError::UnsupportedObjectFormat);
    }
    if !request.limits.is_valid() {
        return Err(LinkError::InvalidLimits);
    }
    if request.objects.len() > request.limits.objects as usize {
        return Err(LinkError::InvalidLimits);
    }
    let object_paths: BTreeSet<_> = request.objects.iter().map(|object| object.path).collect();
    if request.map_output == request.output
        || !safe_absolute_path(request.output)
        || !safe_absolute_path(request.map_output)
        || request.objects.iter().any(|object| {
            !safe_absolute_path(object.path)
                || object.path == request.output
                || object.path == request.map_output
        })
        || request
            .objects
            .iter()
            .enumerate()
            .any(|(index, object)| object.ordinal as usize != index)
        || object_paths.len() != request.objects.len()
    {
        return Err(LinkError::InvalidOutputPath);
    }
    let image_count = request
        .objects
        .iter()
        .filter(|object| matches!(object.kind, CoffObjectKind::Image { .. }))
        .count();
    if image_count == 0 {
        return Err(LinkError::NoImageObject);
    }
    if request.objects.iter().any(|object| match &object.kind {
        CoffObjectKind::Image { build } => build != request.build,
        CoffObjectKind::TargetRuntime { .. } => false,
    }) {
        return Err(LinkError::BuildIdentityMismatch);
    }
    let runtimes: Vec<_> = request
        .objects
        .iter()
        .filter_map(|object| match object.kind {
            CoffObjectKind::TargetRuntime {
                target_package,
                runtime_abi_version,
            } => Some((target_package, runtime_abi_version)),
            CoffObjectKind::Image { .. } => None,
        })
        .collect();
    if runtimes.len() != 1
        || !matches!(
            request.objects.last().map(|object| &object.kind),
            Some(CoffObjectKind::TargetRuntime { .. })
        )
        || request.objects[..request.objects.len().saturating_sub(1)]
            .iter()
            .any(|object| !matches!(object.kind, CoffObjectKind::Image { .. }))
    {
        return Err(LinkError::MissingOrDuplicateRuntime);
    }
    if runtimes[0]
        != (
            request.target.content_digest(),
            request.target.runtime_abi_version(),
        )
    {
        return Err(LinkError::RuntimeTargetMismatch);
    }
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
            .map_err(|error| LinkError::ObjectInspect {
                path: object.path.to_owned(),
                error,
            })?;
        if measured.bytes != object.expected_bytes
            || measured.digest != object.expected_digest
            || measured.coff_machine != request.target.coff_machine()
        {
            return Err(LinkError::ObjectMismatch {
                path: object.path.to_owned(),
            });
        }
    }

    let mut arguments = vec![
        format!("/machine:{}", request.target.coff_machine()),
        format!("/subsystem:{}", request.target.subsystem()),
        format!("/entry:{}", request.target.entry_symbol()),
        "/nodefaultlib".to_owned(),
        "/brepro".to_owned(),
        "/dynamicbase".to_owned(),
        format!("/out:{}", request.output.display()),
        format!("/map:{}", request.map_output.display()),
    ];
    arguments.extend(
        request
            .objects
            .iter()
            .map(|object| object.path.display().to_string()),
    );
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    wrela_lld_sys::link_coff(&arguments).map_err(LinkError::Lld)?;
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    let measurements = image_inspector
        .inspect(
            request.output,
            request.map_output,
            request.limits.image_bytes,
            request.limits.map_bytes,
            is_cancelled,
        )
        .map_err(LinkError::Inspect)?;
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    seal_artifact(request, measurements, is_cancelled)
}

/// Seal post-link measurements for production and injected linker tests. A
/// successful `EfiLinker` cannot expose an unverified artifact tuple.
pub fn seal_artifact(
    request: &LinkRequest<'_>,
    measurements: ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EfiArtifact, LinkError> {
    if is_cancelled() {
        return Err(LinkError::Cancelled);
    }
    if !request.limits.is_valid() {
        return Err(LinkError::InvalidLimits);
    }
    if request.output == request.map_output
        || !safe_absolute_path(request.output)
        || !safe_absolute_path(request.map_output)
    {
        return Err(LinkError::InvalidOutputPath);
    }
    if request.build.target != *request.target.identity()
        || request.build.target_package != request.target.content_digest()
    {
        return Err(LinkError::BuildIdentityMismatch);
    }
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

fn safe_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && normalized.as_os_str() == path.as_os_str()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

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
        measurement_bytes = measurement_bytes
            .and_then(|total| total.checked_add(u64::try_from(section.name.len()).ok()?));
    }
    for symbol in &measurements.symbols {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        measurement_bytes = measurement_bytes
            .and_then(|total| total.checked_add(u64::try_from(symbol.name.len()).ok()?))
            .and_then(|total| total.checked_add(u64::try_from(symbol.section.len()).ok()?));
    }
    if measurements.artifact_bytes == 0
        || measurements.sections.len() > limits.sections as usize
        || measurements.symbols.len() > limits.symbols as usize
        || measurement_bytes.is_none_or(|bytes| bytes > limits.measurement_bytes)
        || measurements.coff_machine != target.coff_machine()
        || measurements.subsystem != target.subsystem()
        || measurements.entry_symbol != target.entry_symbol()
        || measurements.relocation_directory_bytes == 0
        || measurements.sections.is_empty()
    {
        return Err(LinkError::InvalidMeasurements(
            "header, entry, relocations, or sections do not match the target",
        ));
    }

    if !measurements
        .sections
        .windows(2)
        .all(|pair| pair[0].virtual_address < pair[1].virtual_address)
    {
        return Err(LinkError::InvalidMeasurements(
            "section or symbol measurements are noncanonical or out of range",
        ));
    }

    let mut sections = BTreeMap::new();
    let mut file_ranges = Vec::with_capacity(measurements.sections.len());
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
        if section.name.trim().is_empty()
            || file_end > measurements.artifact_bytes
            || previous_virtual_end.is_some_and(|end| end > section.virtual_address)
            || sections.insert(section.name.as_str(), section).is_some()
        {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
        previous_virtual_end = Some(virtual_end);
        file_ranges.push((section.file_offset, file_end));
    }
    file_ranges.sort_unstable();
    if file_ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(LinkError::InvalidMeasurements(
            "section or symbol measurements are noncanonical or out of range",
        ));
    }

    if !measurements
        .symbols
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err(LinkError::InvalidMeasurements(
            "section or symbol measurements are noncanonical or out of range",
        ));
    }
    let mut found_entry = false;
    for symbol in &measurements.symbols {
        if is_cancelled() {
            return Err(LinkError::Cancelled);
        }
        let Some(section) = sections.get(symbol.section.as_str()) else {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        };
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
        if symbol.virtual_address < section.virtual_address || symbol_end > section_end {
            return Err(LinkError::InvalidMeasurements(
                "section or symbol measurements are noncanonical or out of range",
            ));
        }
        found_entry |= symbol.name == measurements.entry_symbol
            && symbol.virtual_address == measurements.entry_virtual_address
            && section.characteristics & 0x2000_0000 != 0
            && symbol.virtual_address < section_end;
    }
    if !found_entry {
        return Err(LinkError::InvalidMeasurements(
            "section or symbol measurements are noncanonical or out of range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::safe_absolute_path;

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
}
