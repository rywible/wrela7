//! Throwaway: recompute a checked-in example's `wrela.lock` from real files
//! on disk, using the same canonical manifest/content-digest/lockfile codec
//! the production loader uses. Every root-package example in this repository
//! depends on exactly one toolchain package, the shipped `wrela-core`
//! standard library, so this tool always binds two packages: the workspace
//! root and `std/wrela-core-0.1`.
//!
//! Usage:
//!   cargo run -p wrela-package-loader --example regenerate_lockfile -- \
//!       <workspace-dir> <core-dir> <core-component-name>
//!
//! `<workspace-dir>` must contain `wrela.toml` and (after this tool runs) an
//! overwritten `wrela.lock`. `<core-dir>` must contain `std/wrela-core-0.1`'s
//! `wrela.toml`. `<core-component-name>` is the toolchain locator component,
//! e.g. `wrela-core-0.1`.

use std::fs;
use std::path::{Path, PathBuf};

use wrela_package::{
    DependencyAlias, LOCKFILE_SCHEMA_VERSION, LockedDependency, LockedPackage, Lockfile,
    PackageIdentity, PackageLocator,
};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, LockfileCodecLimits, ManifestCodecLimits, PackageCodec,
    PackageContentKind, PackageContentRecord, SoftwareSha256, package_content_digest,
};

fn never_cancelled() -> bool {
    false
}

fn manifest_limits() -> ManifestCodecLimits {
    ManifestCodecLimits {
        bytes: 16 * 1024 * 1024,
        string_bytes: 16 * 1024 * 1024,
        modules: 4096,
        dependencies: 64,
        profiles: 64,
        images: 64,
        image_tests: 64,
    }
}

fn lockfile_limits() -> LockfileCodecLimits {
    LockfileCodecLimits {
        bytes: 16 * 1024 * 1024,
        string_bytes: 16 * 1024 * 1024,
        packages: 64,
        dependencies: 64,
    }
}

/// Deterministic sorted walk of every `.wr` file beneath `root`, returning
/// portable `/`-separated relative paths paired with file bytes -- the same
/// bijection the production loader derives modules from.
fn collect_sources(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(root, &path, out);
        } else if path.extension().is_some_and(|extension| extension == "wr") {
            let relative = path
                .strip_prefix(root)
                .expect("child path")
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes =
                fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            out.push((relative, bytes));
        }
    }
}

struct PackageComputation {
    identity: PackageIdentity,
    canonical_manifest: Vec<u8>,
}

fn compute_package(
    codec: &CanonicalPackageCodec,
    hasher: &dyn ContentHasher,
    package_dir: &Path,
) -> PackageComputation {
    let manifest_bytes = fs::read(package_dir.join("wrela.toml")).expect("read wrela.toml");
    let manifest = codec
        .decode_manifest(&manifest_bytes, manifest_limits(), &never_cancelled)
        .expect("decode manifest");
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical manifest");
    let source_root = package_dir.join(&manifest.source_root);
    let sources = collect_sources(&source_root);
    let records = sources
        .iter()
        .map(|(path, bytes)| PackageContentRecord {
            kind: PackageContentKind::Source,
            path: path.as_str(),
            digest: hasher.sha256(bytes),
        })
        .collect::<Vec<_>>();
    let source_digest =
        package_content_digest(&canonical_manifest, &records, hasher, &never_cancelled)
            .expect("package content digest");
    PackageComputation {
        identity: PackageIdentity {
            name: manifest.name,
            version: manifest.version,
            source_digest,
        },
        canonical_manifest,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let workspace_dir = PathBuf::from(
        args.next()
            .expect("usage: <workspace-dir> <core-dir> <core-component>"),
    );
    let core_dir = PathBuf::from(args.next().expect("missing <core-dir>"));
    let core_component = args.next().expect("missing <core-component>");

    let codec = CanonicalPackageCodec::new();
    let hasher = SoftwareSha256;

    let root = compute_package(&codec, &hasher, &workspace_dir);
    let core = compute_package(&codec, &hasher, &core_dir);

    let mut packages = vec![
        LockedPackage {
            identity: root.identity.clone(),
            locator: PackageLocator::Workspace {
                path: ".".to_owned(),
            },
            dependencies: vec![LockedDependency {
                alias: DependencyAlias::new("core").expect("core alias"),
                identity: core.identity.clone(),
            }],
            manifest_digest: hasher.sha256(&root.canonical_manifest),
        },
        LockedPackage {
            identity: core.identity.clone(),
            locator: PackageLocator::Toolchain {
                component: core_component,
            },
            dependencies: Vec::new(),
            manifest_digest: hasher.sha256(&core.canonical_manifest),
        },
    ];
    packages.sort_by(|left, right| left.identity.cmp(&right.identity));

    let lockfile = Lockfile {
        schema: LOCKFILE_SCHEMA_VERSION,
        root: root.identity,
        packages,
    };
    let canonical_lockfile = codec
        .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
        .expect("canonical lockfile");
    let decoded = codec
        .decode_lockfile(&canonical_lockfile, lockfile_limits(), &never_cancelled)
        .expect("round-trip lockfile");
    assert_eq!(decoded, lockfile, "canonical lockfile must round-trip");

    let lock_path = workspace_dir.join("wrela.lock");
    fs::write(&lock_path, &canonical_lockfile).expect("write wrela.lock");
    println!(
        "{}: wrote {} canonical bytes",
        lock_path.display(),
        canonical_lockfile.len()
    );
}
