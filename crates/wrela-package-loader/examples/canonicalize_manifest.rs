//! Throwaway: rewrite a wrela.toml as its canonical encoding.
use std::fs;

use wrela_package_loader::{CanonicalPackageCodec, ManifestCodecLimits, PackageCodec};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: canonicalize_manifest <wrela.toml>");
    let bytes = fs::read(&path).expect("read manifest");
    let codec = CanonicalPackageCodec::new();
    let limits = ManifestCodecLimits {
        bytes: 1024 * 1024,
        string_bytes: 1024 * 1024,
        modules: 64,
        dependencies: 64,
        profiles: 64,
        images: 64,
        image_tests: 64,
    };
    let manifest = codec
        .decode_manifest(&bytes, limits, &|| false)
        .expect("decode manifest");
    let canonical = codec
        .canonical_manifest(&manifest, limits, &|| false)
        .expect("canonical manifest");
    fs::write(&path, &canonical).expect("write canonical manifest");
    println!(
        "{path}: {} -> {} bytes ({})",
        bytes.len(),
        canonical.len(),
        if bytes == canonical {
            "already canonical"
        } else {
            "rewritten"
        }
    );
}
