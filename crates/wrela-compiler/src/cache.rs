//! Bounded, content-addressed local artifact cache.
//!
//! The cache root is derived only from an already-authorized build output
//! directory. Cache files are untrusted inputs: a hit is not observable until
//! the complete key and payload digest are sealed, the real FlowWir codec has
//! decoded and revalidated the frame, and that model equals the current
//! producer output.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest};
use wrela_flow_wir_codec::{
    CanonicalFlowWirCodec, CodecError, CodecLimits, DecodeRequest, EncodeRequest,
    decode_and_verify, encode_and_verify,
};
use wrela_package_loader::{ContentHasher, SoftwareSha256, sha256_cancellable};

use crate::{
    ArtifactCache, CacheEntryCandidate, CacheError, CacheKey, CacheReadRequest, CachedArtifact,
    CachedArtifactKind, seal_cached_artifact,
};

const CACHE_DIRECTORY: &str = ".wrela-cache-v1";
const CACHE_ENTRY_MAGIC: &[u8; 8] = b"WRELCAC\0";
const CACHE_ENTRY_SCHEMA: u32 = 1;
const CACHE_ENTRY_HEADER_BYTES: usize = 56;
const MAX_CACHE_KEY_BYTES: usize = 16 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;
const FLOW_WIR_SUBJECT_DOMAIN: &[u8] = b"wrela-cache-v1:canonical-flow-wir-frame";
const STAGING_ATTEMPTS: u64 = 1024;

static NEXT_STAGING: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed cache capability rooted below one authorized build output
/// directory. No ambient home, environment, or network location is consulted.
#[derive(Debug, Clone)]
pub struct LocalArtifactCache {
    root: PathBuf,
}

impl LocalArtifactCache {
    /// Derive the only production cache root from a normalized absolute output
    /// directory supplied by the build command.
    pub fn for_output(output_directory: &Path) -> Result<Self, CacheError> {
        if !normal_absolute_path(output_directory) {
            return Err(CacheError::InvalidKey);
        }
        Ok(Self {
            root: output_directory.join(CACHE_DIRECTORY),
        })
    }

    /// Construct a cache capability at an explicit normalized absolute root.
    /// This is useful for an injected build composition or a hermetic fixture;
    /// callers remain responsible for having authority to that root.
    pub fn at(root: PathBuf) -> Result<Self, CacheError> {
        if !normal_absolute_path(&root) {
            return Err(CacheError::InvalidKey);
        }
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Exact final path for one key. The filename is SHA-256 of the complete
    /// canonical key encoding, not a caller-controlled label.
    pub fn entry_path(&self, key: &CacheKey) -> Result<PathBuf, CacheError> {
        let key_bytes = canonical_key_bytes(key)?;
        let digest = SoftwareSha256.sha256(&key_bytes).to_hex();
        Ok(self
            .root
            .join(kind_directory(key.kind()))
            .join(format!("{digest}.cache")))
    }
}

impl ArtifactCache for LocalArtifactCache {
    fn load(
        &self,
        request: &CacheReadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<CacheEntryCandidate>, CacheError> {
        check_cancelled(is_cancelled)?;
        if request.maximum_bytes == 0 {
            return Err(CacheError::InvalidLimit);
        }
        let key_bytes = canonical_key_bytes(request.key)?;
        let path = self.entry_path(request.key)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if !valid_cache_file(&metadata) {
            return Ok(None);
        }
        let maximum_file_bytes = request
            .maximum_bytes
            .checked_add(CACHE_ENTRY_HEADER_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(key_bytes.len() as u64))
            .ok_or(CacheError::ResourceLimit {
                limit: request.maximum_bytes,
            })?;
        if metadata.len() > maximum_file_bytes {
            return Ok(None);
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(canonical) => canonical,
            Err(_) => return Ok(None),
        };
        if canonical != path {
            return Ok(None);
        }
        let identity = FileIdentity::from_metadata(&metadata);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let opened = file.metadata().map_err(io_error)?;
        if !valid_cache_file(&opened) || FileIdentity::from_metadata(&opened) != identity {
            return Ok(None);
        }
        let length = match usize::try_from(identity.bytes) {
            Ok(length) => length,
            Err(_) => return Ok(None),
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| CacheError::ResourceLimit {
                limit: request.maximum_bytes,
            })?;
        let mut buffer = [0_u8; IO_CHUNK_BYTES];
        while bytes.len() < length {
            check_cancelled(is_cancelled)?;
            let wanted = (length - bytes.len()).min(buffer.len());
            let read = file.read(&mut buffer[..wanted]).map_err(io_error)?;
            if read == 0 {
                return Ok(None);
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(io_error)? != 0 {
            return Ok(None);
        }
        let opened_after = file.metadata().map_err(io_error)?;
        let current = match fs::symlink_metadata(&path) {
            Ok(current) => current,
            Err(_) => return Ok(None),
        };
        if !valid_cache_file(&opened_after)
            || !valid_cache_file(&current)
            || FileIdentity::from_metadata(&opened_after) != identity
            || FileIdentity::from_metadata(&current) != identity
        {
            return Ok(None);
        }
        check_cancelled(is_cancelled)?;
        parse_entry(request, &key_bytes, &bytes, is_cancelled)
    }

    fn store(
        &self,
        artifact: &CachedArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CacheError> {
        check_cancelled(is_cancelled)?;
        let key_bytes = canonical_key_bytes(artifact.key())?;
        let final_path = self.entry_path(artifact.key())?;
        let directory = final_path
            .parent()
            .ok_or_else(|| CacheError::Io("cache entry has no namespace directory".to_owned()))?;
        ensure_private_directory(&self.root)?;
        ensure_private_directory(directory)?;

        let mut staging = None;
        for _ in 0..STAGING_ATTEMPTS {
            check_cancelled(is_cancelled)?;
            let sequence = NEXT_STAGING.fetch_add(1, Ordering::Relaxed);
            let candidate = directory.join(format!(".tmp-{}-{sequence:016x}", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&candidate) {
                Ok(file) => {
                    staging = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        let (staging_path, mut file) = staging.ok_or_else(|| {
            CacheError::Io("cannot allocate a unique cache staging file".to_owned())
        })?;
        let staged = (|| {
            let payload_bytes = u64::try_from(artifact.bytes().len())
                .map_err(|_| CacheError::ResourceLimit { limit: u64::MAX })?;
            let key_length = u32::try_from(key_bytes.len())
                .map_err(|_| CacheError::Io("cache key length overflow".to_owned()))?;
            let mut header = Vec::new();
            header
                .try_reserve_exact(CACHE_ENTRY_HEADER_BYTES + key_bytes.len())
                .map_err(|_| CacheError::Io("cannot allocate cache entry header".to_owned()))?;
            header.extend_from_slice(CACHE_ENTRY_MAGIC);
            header.extend_from_slice(&CACHE_ENTRY_SCHEMA.to_le_bytes());
            header.extend_from_slice(&key_length.to_le_bytes());
            header.extend_from_slice(&payload_bytes.to_le_bytes());
            header.extend_from_slice(artifact.digest().as_bytes());
            header.extend_from_slice(&key_bytes);
            if header.len() != CACHE_ENTRY_HEADER_BYTES + key_bytes.len() {
                return Err(CacheError::Io(
                    "cache entry header extent drifted".to_owned(),
                ));
            }
            write_cancellable(&mut file, &header, is_cancelled)?;
            write_cancellable(&mut file, artifact.bytes(), is_cancelled)?;
            file.sync_all().map_err(io_error)?;
            check_cancelled(is_cancelled)?;
            Ok(())
        })();
        if let Err(error) = staged {
            drop(file);
            let _ = fs::remove_file(&staging_path);
            return Err(error);
        }
        drop(file);

        // This is the single visibility transition. Cancellation is checked
        // immediately before it and never converted into an error afterward.
        if let Err(error) = check_cancelled(is_cancelled) {
            let _ = fs::remove_file(&staging_path);
            return Err(error);
        }
        if let Err(error) = fs::rename(&staging_path, &final_path) {
            let _ = fs::remove_file(&staging_path);
            return Err(io_error(error));
        }
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        Ok(())
    }
}

/// Canonical cache key for the FlowWir frame owned by one complete build.
pub fn flow_wir_cache_key(build: &BuildIdentity) -> Result<CacheKey, CacheError> {
    CacheKey::new(
        CachedArtifactKind::FlowWirFrame,
        build.clone(),
        SoftwareSha256.sha256(FLOW_WIR_SUBJECT_DOMAIN),
    )
}

/// Bytes selected for the private backend and evidence of whether they were a
/// validated cache hit or the freshly encoded producer output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFlowWirFrame {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    reused: bool,
}

impl ResolvedFlowWirFrame {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn reused(&self) -> bool {
        self.reused
    }
}

/// Resolve the real local-build FlowWir product. Every non-cancellation cache
/// failure is a miss. A hit is reported only after the complete candidate is
/// sealed, decoded/revalidated by the real codec, and proved equal to the
/// freshly lowered model; the returned cached bytes are then the exact bytes
/// consumed by the private backend.
pub fn resolve_flow_wir_frame(
    cache: Option<&dyn ArtifactCache>,
    key: &CacheKey,
    produced: &wrela_backend::flow_wir::ValidatedFlowWir,
    codec_limits: CodecLimits,
    maximum_cache_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ResolvedFlowWirFrame, CodecError> {
    check_codec_cancelled(is_cancelled)?;
    if key.kind() == CachedArtifactKind::FlowWirFrame
        && key.build() == &produced.as_wir().build
        && maximum_cache_bytes != 0
    {
        if let Some(cache) = cache {
            let request = CacheReadRequest {
                key,
                maximum_bytes: maximum_cache_bytes.min(codec_limits.frame_bytes),
            };
            let candidate = match cache.load(&request, is_cancelled) {
                Ok(candidate) => candidate,
                Err(CacheError::Cancelled) => return Err(CodecError::Cancelled),
                Err(_) => None,
            };
            if let Some(candidate) = candidate {
                let artifact = match seal_cached_artifact(
                    &request,
                    candidate,
                    &SoftwareSha256,
                    is_cancelled,
                ) {
                    Ok(artifact) => Some(artifact),
                    Err(CacheError::Cancelled) => return Err(CodecError::Cancelled),
                    Err(_) => None,
                };
                if let Some(artifact) = artifact {
                    let decoded = decode_and_verify(
                        &CanonicalFlowWirCodec,
                        DecodeRequest {
                            bytes: artifact.bytes(),
                            limits: codec_limits,
                            expected_build: Some(key.build()),
                        },
                        is_cancelled,
                    );
                    match decoded {
                        Ok(decoded) if decoded.as_wir() == produced.as_wir() => {
                            check_codec_cancelled(is_cancelled)?;
                            let (bytes, digest) = artifact.into_bytes_and_digest();
                            return Ok(ResolvedFlowWirFrame {
                                bytes,
                                digest,
                                reused: true,
                            });
                        }
                        Err(CodecError::Cancelled) => return Err(CodecError::Cancelled),
                        Ok(_) | Err(_) => {}
                    }
                }
            }
        }
    }

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: produced,
            limits: codec_limits,
        },
        is_cancelled,
    )?;
    let bytes = encoded.into_bytes();
    let digest = sha256_cancellable(&SoftwareSha256, &bytes, is_cancelled)
        .map_err(|_| CodecError::Cancelled)?;
    if let Some(cache) = cache.filter(|_| {
        key.kind() == CachedArtifactKind::FlowWirFrame
            && key.build() == &produced.as_wir().build
            && u64::try_from(bytes.len())
                .ok()
                .is_some_and(|bytes| bytes <= maximum_cache_bytes)
    }) {
        let request = CacheReadRequest {
            key,
            maximum_bytes: maximum_cache_bytes.min(codec_limits.frame_bytes),
        };
        let artifact = seal_cached_artifact(
            &request,
            CacheEntryCandidate {
                key: key.clone(),
                bytes: bytes.clone(),
                digest,
            },
            &SoftwareSha256,
            is_cancelled,
        );
        match artifact {
            Ok(artifact) => match cache.store(&artifact, is_cancelled) {
                Ok(()) => {}
                Err(CacheError::Cancelled) => return Err(CodecError::Cancelled),
                Err(_) => {}
            },
            Err(CacheError::Cancelled) => return Err(CodecError::Cancelled),
            Err(_) => {}
        }
    }
    check_codec_cancelled(is_cancelled)?;
    Ok(ResolvedFlowWirFrame {
        bytes,
        digest,
        reused: false,
    })
}

fn canonical_key_bytes(key: &CacheKey) -> Result<Vec<u8>, CacheError> {
    let build = key.build();
    let target = build.target.as_str().as_bytes();
    let target_bytes = u32::try_from(target.len())
        .map_err(|_| CacheError::Io("cache target identity length overflow".to_owned()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(8 + 4 + 2 + 32 * 7 + 4 + target.len())
        .map_err(|_| CacheError::Io("cannot allocate canonical cache key".to_owned()))?;
    bytes.extend_from_slice(b"WRELKEY\0");
    bytes.extend_from_slice(&key.version().to_le_bytes());
    bytes.push(kind_tag(key.kind()));
    bytes.push(match build.language {
        LanguageRevision::Design0_1 => 0,
    });
    bytes.extend_from_slice(build.compiler.as_bytes());
    bytes.extend_from_slice(&target_bytes.to_le_bytes());
    bytes.extend_from_slice(target);
    bytes.extend_from_slice(build.target_package.as_bytes());
    bytes.extend_from_slice(build.standard_library.as_bytes());
    bytes.extend_from_slice(build.source_graph.as_bytes());
    bytes.extend_from_slice(build.request.as_bytes());
    bytes.extend_from_slice(build.profile.as_bytes());
    bytes.extend_from_slice(key.subject().as_bytes());
    if bytes.len() > MAX_CACHE_KEY_BYTES {
        return Err(CacheError::Io(
            "canonical cache key exceeds its bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn parse_entry(
    request: &CacheReadRequest<'_>,
    expected_key: &[u8],
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<CacheEntryCandidate>, CacheError> {
    if bytes.len() < CACHE_ENTRY_HEADER_BYTES
        || bytes.get(..8) != Some(CACHE_ENTRY_MAGIC)
        || read_u32(bytes, 8) != Some(CACHE_ENTRY_SCHEMA)
    {
        return Ok(None);
    }
    let Some(key_bytes) = read_u32(bytes, 12).and_then(|bytes| usize::try_from(bytes).ok()) else {
        return Ok(None);
    };
    let Some(payload_bytes) = read_u64(bytes, 16).and_then(|bytes| usize::try_from(bytes).ok())
    else {
        return Ok(None);
    };
    if key_bytes != expected_key.len()
        || usize::try_from(request.maximum_bytes)
            .ok()
            .is_none_or(|maximum| payload_bytes > maximum)
    {
        return Ok(None);
    }
    let Some(key_end) = CACHE_ENTRY_HEADER_BYTES.checked_add(key_bytes) else {
        return Ok(None);
    };
    let Some(payload_end) = key_end.checked_add(payload_bytes) else {
        return Ok(None);
    };
    if payload_end != bytes.len()
        || bytes.get(CACHE_ENTRY_HEADER_BYTES..key_end) != Some(expected_key)
    {
        return Ok(None);
    }
    let Some(digest) = bytes
        .get(24..56)
        .and_then(|digest| digest.try_into().ok())
        .map(Sha256Digest::from_bytes)
    else {
        return Ok(None);
    };
    let source = &bytes[key_end..payload_end];
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(source.len())
        .map_err(|_| CacheError::ResourceLimit {
            limit: request.maximum_bytes,
        })?;
    for chunk in source.chunks(IO_CHUNK_BYTES) {
        check_cancelled(is_cancelled)?;
        payload.extend_from_slice(chunk);
    }
    check_cancelled(is_cancelled)?;
    Ok(Some(CacheEntryCandidate {
        key: request.key.clone(),
        bytes: payload,
        digest,
    }))
}

fn write_cancellable(
    file: &mut File,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CacheError> {
    for chunk in bytes.chunks(IO_CHUNK_BYTES) {
        check_cancelled(is_cancelled)?;
        file.write_all(chunk).map_err(io_error)?;
    }
    check_cancelled(is_cancelled)
}

fn ensure_private_directory(path: &Path) -> Result<(), CacheError> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(CacheError::Io(
                        "cache directory path crosses a non-directory or symlink".to_owned(),
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    CacheError::Io("cache directory has no existing ancestor".to_owned())
                })?;
            }
            Err(error) => return Err(io_error(error)),
        }
    }
    for directory in missing.into_iter().rev() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        let metadata = fs::symlink_metadata(&directory).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CacheError::Io(
                "created cache path is not a real directory".to_owned(),
            ));
        }
    }
    let canonical = fs::canonicalize(path).map_err(io_error)?;
    if canonical != path {
        return Err(CacheError::Io(
            "cache directory canonicalized outside its authority".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !valid_private_directory(&metadata) {
        return Err(CacheError::Io(
            "cache namespace permissions are not private".to_owned(),
        ));
    }
    Ok(())
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        && path.components().collect::<PathBuf>() == path
}

fn valid_cache_file(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return false;
        }
    }
    true
}

fn valid_private_directory(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return false;
        }
    }
    true
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
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                bytes: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                bytes: metadata.len(),
            }
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

const fn kind_tag(kind: CachedArtifactKind) -> u8 {
    match kind {
        CachedArtifactKind::FlowWirFrame => 0,
        CachedArtifactKind::BackendImage => 1,
        CachedArtifactKind::ImageReport => 2,
        CachedArtifactKind::TestReport => 3,
    }
}

const fn kind_directory(kind: CachedArtifactKind) -> &'static str {
    match kind {
        CachedArtifactKind::FlowWirFrame => "flow-wir-frame",
        CachedArtifactKind::BackendImage => "backend-image",
        CachedArtifactKind::ImageReport => "image-report",
        CachedArtifactKind::TestReport => "test-report",
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CacheError> {
    if is_cancelled() {
        Err(CacheError::Cancelled)
    } else {
        Ok(())
    }
}

fn check_codec_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodecError> {
    if is_cancelled() {
        Err(CodecError::Cancelled)
    } else {
        Ok(())
    }
}

fn io_error(error: io::Error) -> CacheError {
    CacheError::Io(error.to_string())
}
