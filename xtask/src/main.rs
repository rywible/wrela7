//! Maintainer-only toolchain build, architecture, and distribution tasks.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

const HELP: &str = "\
xtask commands:
  architecture-check [--root <absolute-workspace>]  enforce crate dependency contracts
  diagnostic-index [--root <absolute-workspace>]    reconcile the stable diagnostic code index
  slices              list focused development slices
  check <slice|crate> [...]  cargo check --all-targets for one boundary
  test <slice|crate> [...]   cargo test for one boundary
  lint <slice|crate>         clippy -D warnings for one boundary
  gate <slice|crate> [--full]  complete locked, offline focused gate
  nightly             clean-worktree local nightly: xgate all, xarch, native --full gates
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullRoute {
    None,
    ArtifactNative,
    BackendNative,
    Distribution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoStep {
    label: &'static str,
    arguments: Vec<String>,
}

struct DevelopmentSlice {
    name: &'static str,
    purpose: &'static str,
    packages: &'static [&'static str],
    upstream: &'static [&'static str],
    downstream: &'static [&'static str],
    fixture_families: &'static [&'static str],
    native_requirements: &'static [&'static str],
    full_route: FullRoute,
    fast_budget_seconds: u64,
}

const DEVELOPMENT_SLICES: &[DevelopmentSlice] = &[
    DevelopmentSlice {
        name: "input",
        purpose: "build identity, source, package graph, and package loading",
        packages: &[
            "wrela-build-model",
            "wrela-source",
            "wrela-package",
            "wrela-package-loader",
        ],
        upstream: &[],
        downstream: &["syntax"],
        fixture_families: &["package/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 45,
    },
    DevelopmentSlice {
        name: "syntax",
        purpose: "lossless parsing and AST-only formatting",
        packages: &["wrela-syntax", "wrela-format"],
        upstream: &["input"],
        downstream: &["hir"],
        fixture_families: &["syntax/v3"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 45,
    },
    DevelopmentSlice {
        name: "hir",
        purpose: "normalized HIR model and package-wide name lowering",
        packages: &["wrela-hir", "wrela-hir-lower"],
        upstream: &["syntax"],
        downstream: &["semantic"],
        fixture_families: &["syntax/v3"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 60,
    },
    DevelopmentSlice {
        name: "semantic",
        purpose: "whole-image analysis, semantic linting, and SemanticWir",
        packages: &[
            "wrela-sema",
            "wrela-lint",
            "wrela-semantic-wir",
            "wrela-semantic-lower",
        ],
        upstream: &["hir"],
        downstream: &["flow"],
        fixture_families: &["protocol/v1", "syntax/v3", "target/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 90,
    },
    DevelopmentSlice {
        name: "flow",
        purpose: "FlowWir lowering, optimization, and canonical codec",
        packages: &[
            "wrela-flow-wir",
            "wrela-flow-lower",
            "wrela-flow-opt",
            "wrela-flow-wir-codec",
        ],
        upstream: &["semantic"],
        downstream: &["machine", "backend"],
        fixture_families: &["protocol/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 60,
    },
    DevelopmentSlice {
        name: "machine",
        purpose: "runtime ABI, AArch64 target binding, and MachineWir lowering",
        packages: &[
            "wrela-runtime-abi",
            "wrela-target",
            "wrela-machine-wir",
            "wrela-machine-lower",
        ],
        upstream: &["flow"],
        downstream: &["artifact", "backend"],
        fixture_families: &["protocol/v1", "target/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 60,
    },
    DevelopmentSlice {
        name: "artifact",
        purpose: "AArch64 COFF emission, EFI link inspection, and report assembly",
        packages: &[
            "wrela-codegen-llvm",
            "wrela-lld-sys",
            "wrela-link-efi",
            "wrela-image-report",
        ],
        upstream: &["machine"],
        downstream: &["backend", "testing"],
        fixture_families: &["protocol/v1", "target/v1"],
        native_requirements: &["system LLVM 22 (llvm-config on disk)", "system lld-link"],
        full_route: FullRoute::ArtifactNative,
        fast_budget_seconds: 90,
    },
    DevelopmentSlice {
        name: "frontend",
        purpose: "input through sealed semantic analysis and SemanticWir",
        packages: &[
            "wrela-build-model",
            "wrela-source",
            "wrela-package",
            "wrela-package-loader",
            "wrela-diagnostics",
            "wrela-syntax",
            "wrela-format",
            "wrela-hir",
            "wrela-hir-lower",
            "wrela-target",
            "wrela-test-model",
            "wrela-sema",
            "wrela-lint",
            "wrela-semantic-wir",
            "wrela-semantic-lower",
        ],
        upstream: &["input"],
        downstream: &["ir", "cli"],
        fixture_families: &["package/v1", "protocol/v1", "syntax/v3", "target/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 120,
    },
    DevelopmentSlice {
        name: "ir",
        purpose: "three named IRs, lowering, optimization, codec, target, and runtime ABI",
        packages: &[
            "wrela-semantic-wir",
            "wrela-semantic-lower",
            "wrela-flow-wir",
            "wrela-flow-lower",
            "wrela-flow-opt",
            "wrela-flow-wir-codec",
            "wrela-runtime-abi",
            "wrela-target",
            "wrela-machine-wir",
            "wrela-machine-lower",
        ],
        upstream: &["frontend"],
        downstream: &["backend"],
        fixture_families: &["protocol/v1", "syntax/v3", "target/v1"],
        native_requirements: &[],
        full_route: FullRoute::None,
        fast_budget_seconds: 120,
    },
    DevelopmentSlice {
        name: "backend",
        purpose: "backend protocol through COFF, EFI linking, and image report",
        packages: &[
            "wrela-backend-protocol",
            "wrela-codegen-llvm",
            "wrela-lld-sys",
            "wrela-link-efi",
            "wrela-image-report",
            "wrela-backend",
        ],
        upstream: &["flow", "machine", "artifact"],
        downstream: &["cli"],
        fixture_families: &["protocol/v1", "target/v1"],
        native_requirements: &["system LLVM 22 (llvm-config on disk)", "system lld-link"],
        full_route: FullRoute::BackendNative,
        fast_budget_seconds: 120,
    },
    DevelopmentSlice {
        name: "testing",
        purpose: "test plan/protocol, verified toolchain, and full-image runner",
        packages: &[
            "wrela-test-model",
            "wrela-test-protocol",
            "wrela-target",
            "wrela-toolchain",
            "wrela-test-runner",
        ],
        upstream: &["artifact"],
        downstream: &["cli"],
        fixture_families: &["package/v1", "protocol/v1", "target/v1", "toolchain/v1"],
        native_requirements: &[
            "installed target and runtime object",
            "system qemu-system-aarch64 + EDK2 firmware (on disk)",
        ],
        full_route: FullRoute::Distribution,
        fast_budget_seconds: 90,
    },
    DevelopmentSlice {
        name: "cli",
        purpose: "public driver, CLI surface, and sealed headless engine process",
        packages: &["wrela-driver", "wrela-compiler", "wrela-cli"],
        upstream: &["frontend", "backend", "testing"],
        downstream: &[],
        fixture_families: &[
            "package/v1",
            "protocol/v1",
            "syntax/v3",
            "target/v1",
            "toolchain/v1",
        ],
        native_requirements: &[
            "system LLVM/LLD backend (on disk)",
            "installed target, runtime, and system QEMU + firmware (on disk)",
        ],
        full_route: FullRoute::Distribution,
        fast_budget_seconds: 180,
    },
    DevelopmentSlice {
        name: "all",
        purpose: "entire workspace",
        packages: &[],
        upstream: &[],
        downstream: &[],
        fixture_families: &[
            "package/v1",
            "protocol/v1",
            "syntax/v3",
            "target/v1",
            "toolchain/v1",
        ],
        native_requirements: &["system LLVM/LLD + QEMU toolchain on disk"],
        full_route: FullRoute::Distribution,
        fast_budget_seconds: 300,
    },
];

struct CrateContract {
    name: &'static str,
    directory: &'static str,
    normal: &'static [&'static str],
    dev: &'static [&'static str],
}

struct ExternalDependencyContract {
    owner: &'static str,
    name: &'static str,
    kind: DependencySection,
    requirement: &'static str,
    optional: bool,
    default_features: bool,
    features: &'static [&'static str],
}

struct ReviewedExternalPackage {
    name: &'static str,
    version: &'static str,
    dependencies: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateRequest {
    target: String,
    full: bool,
}

#[derive(Debug, Clone)]
struct GateTarget {
    name: String,
    purpose: String,
    packages: Vec<String>,
    upstream: Vec<String>,
    downstream: Vec<String>,
    fixture_families: Vec<String>,
    native_requirements: Vec<String>,
    full_route: FullRoute,
    fast_budget_seconds: u64,
    all_workspace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateClosure {
    workspace: BTreeSet<String>,
    external: BTreeSet<String>,
}

#[derive(Debug)]
struct ResolvedPackage {
    name: String,
    version: String,
    workspace: bool,
}

#[derive(Debug)]
struct ResolvedDependency {
    package_id: String,
    kinds: BTreeSet<DependencySection>,
}

#[derive(Debug)]
struct ResolvedMetadata {
    packages: BTreeMap<String, ResolvedPackage>,
    workspace_ids_by_name: BTreeMap<String, String>,
    dependencies: BTreeMap<String, Vec<ResolvedDependency>>,
}

type FeatureContract = (&'static str, &'static [&'static str]);
type CrateFeatureContract = (&'static str, &'static [FeatureContract]);

const EXTERNAL_DEPENDENCIES: &[ExternalDependencyContract] = &[
    ExternalDependencyContract {
        owner: "wrela-backend",
        name: "sha2",
        kind: DependencySection::Normal,
        requirement: "=0.10.9",
        optional: false,
        default_features: false,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-codegen-llvm",
        name: "inkwell",
        kind: DependencySection::Normal,
        requirement: "=0.9.0",
        optional: true,
        default_features: false,
        features: &["llvm22-1-force-static", "target-aarch64"],
    },
    ExternalDependencyContract {
        owner: "wrela-image-report",
        name: "serde_json",
        kind: DependencySection::Development,
        requirement: "^1",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-package",
        name: "unicode-ident",
        kind: DependencySection::Normal,
        requirement: "=1.0.18",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-package",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "=0.1.24",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-source",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "=0.1.24",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-package-loader",
        name: "toml",
        kind: DependencySection::Normal,
        requirement: "=0.9.9",
        optional: false,
        default_features: false,
        features: &["parse", "std"],
    },
    ExternalDependencyContract {
        owner: "wrela-package-loader",
        name: "toml_parser",
        kind: DependencySection::Normal,
        requirement: "=1.0.5",
        optional: false,
        default_features: false,
        features: &["alloc", "std"],
    },
    ExternalDependencyContract {
        owner: "wrela-syntax",
        name: "unicode-ident",
        kind: DependencySection::Normal,
        requirement: "=1.0.18",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-syntax",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "=0.1.24",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-link-efi",
        name: "sha2",
        kind: DependencySection::Normal,
        requirement: "=0.10.9",
        optional: false,
        default_features: false,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "xtask",
        name: "serde_json",
        kind: DependencySection::Normal,
        requirement: "^1",
        optional: false,
        default_features: true,
        features: &[],
    },
];

// cpufeatures only links libc on aarch64 (Apple/Linux) and loongarch64 Linux —
// matching its Cargo target cfg. x86_64 Linux must not expect that edge or the
// host-filtered resolve closure drifts.
#[cfg(any(
    all(target_arch = "aarch64", target_os = "linux"),
    all(target_arch = "aarch64", target_vendor = "apple"),
    all(target_arch = "loongarch64", target_os = "linux"),
))]
const CPUFEATURES_DEPENDENCIES: &[&str] = &["libc"];
#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "linux"),
    all(target_arch = "aarch64", target_vendor = "apple"),
    all(target_arch = "loongarch64", target_os = "linux"),
)))]
const CPUFEATURES_DEPENDENCIES: &[&str] = &[];

// This is the reviewed fast-gate transitive registry closure. Optional native
// dependencies are deliberately absent and are exercised only by `--full`.
const REVIEWED_EXTERNAL_PACKAGES: &[ReviewedExternalPackage] = &[
    ReviewedExternalPackage {
        name: "block-buffer",
        version: "0.10.4",
        dependencies: &["generic-array"],
    },
    ReviewedExternalPackage {
        name: "cfg-if",
        version: "1.0.4",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "cpufeatures",
        version: "0.2.17",
        dependencies: CPUFEATURES_DEPENDENCIES,
    },
    ReviewedExternalPackage {
        name: "crypto-common",
        version: "0.1.7",
        dependencies: &["generic-array", "typenum"],
    },
    ReviewedExternalPackage {
        name: "digest",
        version: "0.10.7",
        dependencies: &["block-buffer", "crypto-common"],
    },
    ReviewedExternalPackage {
        name: "equivalent",
        version: "1.0.2",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "hashbrown",
        version: "0.17.1",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "generic-array",
        version: "0.14.7",
        dependencies: &["typenum", "version_check"],
    },
    ReviewedExternalPackage {
        name: "indexmap",
        version: "2.14.0",
        dependencies: &["equivalent", "hashbrown"],
    },
    ReviewedExternalPackage {
        name: "itoa",
        version: "1.0.18",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "memchr",
        version: "2.8.3",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "libc",
        version: "0.2.186",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "serde_core",
        version: "1.0.228",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "serde_json",
        version: "1.0.150",
        dependencies: &["itoa", "memchr", "serde_core", "zmij"],
    },
    ReviewedExternalPackage {
        name: "serde_spanned",
        version: "1.1.1",
        dependencies: &["serde_core"],
    },
    ReviewedExternalPackage {
        name: "sha2",
        version: "0.10.9",
        dependencies: &["cfg-if", "cpufeatures", "digest"],
    },
    ReviewedExternalPackage {
        name: "tinyvec",
        version: "1.12.0",
        dependencies: &["tinyvec_macros"],
    },
    ReviewedExternalPackage {
        name: "tinyvec_macros",
        version: "0.1.1",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "typenum",
        version: "1.20.1",
        dependencies: &[],
    },
    // Cargo requirements intentionally omit semver build metadata because
    // Cargo warns that it is ignored. These reviewed resolved versions retain
    // the exact TOML-spec-bearing package identity from Cargo.lock.
    ReviewedExternalPackage {
        name: "toml",
        version: "0.9.9+spec-1.0.0",
        dependencies: &[
            "indexmap",
            "serde_core",
            "serde_spanned",
            "toml_datetime",
            "toml_parser",
            "toml_writer",
            "winnow",
        ],
    },
    ReviewedExternalPackage {
        name: "toml_datetime",
        version: "0.7.5+spec-1.1.0",
        dependencies: &["serde_core"],
    },
    ReviewedExternalPackage {
        name: "toml_parser",
        version: "1.0.5+spec-1.0.0",
        dependencies: &["winnow"],
    },
    ReviewedExternalPackage {
        name: "toml_writer",
        version: "1.1.2+spec-1.1.0",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "unicode-ident",
        version: "1.0.18",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "unicode-normalization",
        version: "0.1.24",
        dependencies: &["tinyvec"],
    },
    ReviewedExternalPackage {
        name: "version_check",
        version: "0.9.5",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "winnow",
        version: "0.7.15",
        dependencies: &[],
    },
    ReviewedExternalPackage {
        name: "zmij",
        version: "1.0.23",
        dependencies: &[],
    },
];

const FEATURE_CONTRACTS: &[CrateFeatureContract] = &[
    (
        "wrela-backend",
        &[
            (
                "bundled-backend",
                &["wrela-codegen-llvm/llvm", "wrela-link-efi/bundled-lld"],
            ),
            ("default", &[]),
        ],
    ),
    (
        "wrela-codegen-llvm",
        &[("default", &[]), ("llvm", &["dep:inkwell"])],
    ),
    (
        "wrela-link-efi",
        &[
            ("bundled-lld", &["wrela-lld-sys/bundled-lld"]),
            ("default", &[]),
        ],
    ),
    ("wrela-lld-sys", &[("bundled-lld", &[]), ("default", &[])]),
];

const CONTRACTS: &[CrateContract] = &[
    CrateContract {
        name: "wrela-backend",
        directory: "crates/wrela-backend",
        normal: &[
            "wrela-backend-protocol",
            "wrela-build-model",
            "wrela-codegen-llvm",
            "wrela-flow-opt",
            "wrela-flow-wir",
            "wrela-flow-wir-codec",
            "wrela-image-report",
            "wrela-link-efi",
            "wrela-machine-lower",
            "wrela-target",
        ],
        dev: &["wrela-source"],
    },
    CrateContract {
        name: "wrela-backend-protocol",
        directory: "crates/wrela-backend-protocol",
        normal: &["wrela-build-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-build-model",
        directory: "crates/wrela-build-model",
        normal: &[],
        dev: &[],
    },
    CrateContract {
        name: "wrela-cli",
        directory: "crates/wrela-cli",
        normal: &["wrela-build-model", "wrela-compiler", "wrela-driver"],
        dev: &[
            "wrela-package",
            "wrela-package-loader",
            "wrela-test-model",
            "wrela-toolchain",
        ],
    },
    CrateContract {
        name: "wrela-codegen-llvm",
        directory: "crates/wrela-codegen-llvm",
        normal: &[
            "wrela-build-model",
            "wrela-machine-wir",
            "wrela-runtime-abi",
            "wrela-target",
        ],
        dev: &[
            "wrela-flow-lower",
            "wrela-flow-opt",
            "wrela-machine-lower",
            "wrela-semantic-wir",
            "wrela-source",
            "wrela-test-model",
            "wrela-test-protocol",
        ],
    },
    CrateContract {
        name: "wrela-compiler",
        directory: "crates/wrela-compiler",
        normal: &[
            "wrela-backend",
            "wrela-build-model",
            "wrela-diagnostics",
            "wrela-driver",
            "wrela-flow-lower",
            "wrela-flow-wir-codec",
            "wrela-format",
            "wrela-hir",
            "wrela-hir-lower",
            "wrela-image-report",
            "wrela-lint",
            "wrela-package",
            "wrela-package-loader",
            "wrela-sema",
            "wrela-semantic-lower",
            "wrela-source",
            "wrela-syntax",
            "wrela-target",
            "wrela-test-model",
            "wrela-test-runner",
            "wrela-toolchain",
        ],
        dev: &["wrela-link-efi"],
    },
    CrateContract {
        name: "wrela-diagnostics",
        directory: "crates/wrela-diagnostics",
        normal: &["wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-driver",
        directory: "crates/wrela-driver",
        normal: &[
            "wrela-build-model",
            "wrela-diagnostics",
            "wrela-format",
            "wrela-image-report",
            "wrela-lint",
            "wrela-source",
            "wrela-test-model",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-lower",
        directory: "crates/wrela-flow-lower",
        normal: &["wrela-diagnostics", "wrela-flow-wir", "wrela-semantic-wir"],
        dev: &[
            "wrela-build-model",
            "wrela-source",
            "wrela-test-model",
            "wrela-test-protocol",
        ],
    },
    CrateContract {
        name: "wrela-flow-opt",
        directory: "crates/wrela-flow-opt",
        normal: &["wrela-build-model", "wrela-flow-wir", "wrela-test-model"],
        dev: &["wrela-flow-lower", "wrela-semantic-wir", "wrela-source"],
    },
    CrateContract {
        name: "wrela-flow-wir",
        directory: "crates/wrela-flow-wir",
        normal: &["wrela-build-model", "wrela-source", "wrela-test-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-wir-codec",
        directory: "crates/wrela-flow-wir-codec",
        normal: &[
            "wrela-build-model",
            "wrela-flow-wir",
            "wrela-source",
            "wrela-test-model",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-format",
        directory: "crates/wrela-format",
        normal: &["wrela-source", "wrela-syntax"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-hir",
        directory: "crates/wrela-hir",
        normal: &["wrela-package", "wrela-source"],
        dev: &["wrela-build-model"],
    },
    CrateContract {
        name: "wrela-hir-lower",
        directory: "crates/wrela-hir-lower",
        normal: &[
            "wrela-build-model",
            "wrela-diagnostics",
            "wrela-hir",
            "wrela-package",
            "wrela-source",
            "wrela-syntax",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-image-report",
        directory: "crates/wrela-image-report",
        normal: &["wrela-build-model", "wrela-source", "wrela-test-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-link-efi",
        directory: "crates/wrela-link-efi",
        normal: &["wrela-build-model", "wrela-lld-sys", "wrela-target"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-lld-sys",
        directory: "crates/wrela-lld-sys",
        normal: &[],
        dev: &[],
    },
    CrateContract {
        name: "wrela-lint",
        directory: "crates/wrela-lint",
        normal: &[
            "wrela-diagnostics",
            "wrela-hir",
            "wrela-sema",
            "wrela-syntax",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-machine-lower",
        directory: "crates/wrela-machine-lower",
        normal: &[
            "wrela-build-model",
            "wrela-flow-opt",
            "wrela-flow-wir",
            "wrela-machine-wir",
            "wrela-runtime-abi",
            "wrela-target",
            "wrela-test-model",
            "wrela-test-protocol",
        ],
        dev: &["wrela-flow-lower", "wrela-semantic-wir", "wrela-source"],
    },
    CrateContract {
        name: "wrela-machine-wir",
        directory: "crates/wrela-machine-wir",
        normal: &[
            "wrela-build-model",
            "wrela-runtime-abi",
            "wrela-source",
            "wrela-target",
            "wrela-test-model",
            "wrela-test-protocol",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-package",
        directory: "crates/wrela-package",
        normal: &["wrela-build-model", "wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-package-loader",
        directory: "crates/wrela-package-loader",
        normal: &["wrela-build-model", "wrela-package", "wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-runtime-abi",
        directory: "crates/wrela-runtime-abi",
        normal: &[],
        dev: &[],
    },
    CrateContract {
        name: "wrela-sema",
        directory: "crates/wrela-sema",
        normal: &[
            "wrela-build-model",
            "wrela-diagnostics",
            "wrela-hir",
            "wrela-package",
            "wrela-source",
            "wrela-target",
            "wrela-test-model",
        ],
        dev: &["wrela-hir-lower", "wrela-syntax"],
    },
    CrateContract {
        name: "wrela-semantic-lower",
        directory: "crates/wrela-semantic-lower",
        normal: &[
            "wrela-hir",
            "wrela-sema",
            "wrela-semantic-wir",
            "wrela-test-model",
            "wrela-test-protocol",
        ],
        dev: &[
            "wrela-build-model",
            "wrela-hir-lower",
            "wrela-package",
            "wrela-source",
            "wrela-syntax",
            "wrela-target",
        ],
    },
    CrateContract {
        name: "wrela-semantic-wir",
        directory: "crates/wrela-semantic-wir",
        normal: &["wrela-build-model", "wrela-source", "wrela-test-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-source",
        directory: "crates/wrela-source",
        normal: &["wrela-build-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-syntax",
        directory: "crates/wrela-syntax",
        normal: &["wrela-build-model", "wrela-diagnostics", "wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-target",
        directory: "crates/wrela-target",
        normal: &["wrela-build-model", "wrela-runtime-abi"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-test-model",
        directory: "crates/wrela-test-model",
        normal: &["wrela-build-model", "wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-test-protocol",
        directory: "crates/wrela-test-protocol",
        normal: &["wrela-source", "wrela-test-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-test-runner",
        directory: "crates/wrela-test-runner",
        normal: &[
            "wrela-build-model",
            "wrela-target",
            "wrela-test-model",
            "wrela-test-protocol",
            "wrela-toolchain",
        ],
        dev: &["wrela-package", "wrela-package-loader"],
    },
    CrateContract {
        name: "wrela-toolchain",
        directory: "crates/wrela-toolchain",
        normal: &[
            "wrela-build-model",
            "wrela-package",
            "wrela-package-loader",
            "wrela-target",
        ],
        dev: &[],
    },
    CrateContract {
        name: "xtask",
        directory: "xtask",
        normal: &[],
        dev: &[],
    },
];

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        None | Some("help" | "-h" | "--help") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("slices") => match workspace_root().and_then(|root| print_slices(&root)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Some("architecture-check") => {
            let remaining = arguments.collect::<Vec<_>>();
            match architecture_root(&remaining).and_then(|root| check_architecture(&root)) {
                Ok(()) => {
                    println!("crate architecture matches the declared contracts");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("diagnostic-index") => {
            let remaining = arguments.collect::<Vec<_>>();
            match architecture_root(&remaining).and_then(|root| check_diagnostic_index(&root)) {
                Ok(()) => {
                    println!("diagnostic code index matches the workspace sources");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(command @ ("check" | "test" | "lint")) => {
            let Some(slice) = arguments.next() else {
                eprintln!("error: xtask {command} requires a slice\n");
                print_slice_names();
                return ExitCode::from(2);
            };
            let extra: Vec<_> = arguments.collect();
            match workspace_root()
                .and_then(|root| run_development_slice(&root, command, &slice, &extra))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("gate") => {
            let request = match parse_gate_arguments(arguments.collect()) {
                Ok(request) => request,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(2);
                }
            };
            match workspace_root().and_then(|root| run_gate(&root, &request)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("nightly") => {
            if arguments.next().is_some() {
                eprintln!("error: xtask nightly accepts no arguments\n\n{HELP}");
                return ExitCode::from(2);
            }
            match workspace_root().and_then(|root| run_nightly(&root)) {
                Ok(report_path) => {
                    println!("nightly report: {}", report_path.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(command) => {
            eprintln!("error: unknown xtask command `{command}`\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

fn print_slice_names() {
    eprintln!("development slices:");
    for slice in DEVELOPMENT_SLICES {
        eprintln!("  {:<10} {}", slice.name, slice.purpose);
    }
}

fn print_slices(root: &Path) -> Result<(), String> {
    validate_development_slice_metadata()?;
    validate_fixture_inventory(root)?;
    let metadata = resolved_cargo_metadata(root)?;
    eprintln!("authoritative development slice inventory:");
    for slice in DEVELOPMENT_SLICES {
        let target = gate_target(slice.name)?;
        let closure = validate_gate_closure(&target, &metadata)?;
        eprintln!();
        print_gate_metadata(&target, &closure);
    }
    Ok(())
}

fn parse_gate_arguments(arguments: Vec<String>) -> Result<GateRequest, String> {
    match arguments.as_slice() {
        [target] if target != "--full" => Ok(GateRequest {
            target: target.clone(),
            full: false,
        }),
        [target, full] if target != "--full" && full == "--full" => Ok(GateRequest {
            target: target.clone(),
            full: true,
        }),
        [] => Err("xtask gate requires exactly one slice or workspace crate".to_owned()),
        _ => Err(
            "usage: cargo xgate <slice-or-exact-workspace-crate> [--full]; test filters and other extra arguments are forbidden"
                .to_owned(),
        ),
    }
}

fn gate_target(name: &str) -> Result<GateTarget, String> {
    if let Some(slice) = DEVELOPMENT_SLICES.iter().find(|slice| slice.name == name) {
        let all_workspace = slice.name == "all";
        let packages = if all_workspace {
            CONTRACTS
                .iter()
                .map(|contract| contract.name.to_owned())
                .collect()
        } else {
            slice
                .packages
                .iter()
                .map(|package| (*package).to_owned())
                .collect()
        };
        return Ok(GateTarget {
            name: slice.name.to_owned(),
            purpose: slice.purpose.to_owned(),
            packages,
            upstream: slice
                .upstream
                .iter()
                .map(|boundary| (*boundary).to_owned())
                .collect(),
            downstream: slice
                .downstream
                .iter()
                .map(|boundary| (*boundary).to_owned())
                .collect(),
            fixture_families: slice
                .fixture_families
                .iter()
                .map(|fixture| (*fixture).to_owned())
                .collect(),
            native_requirements: slice
                .native_requirements
                .iter()
                .map(|requirement| (*requirement).to_owned())
                .collect(),
            full_route: slice.full_route,
            fast_budget_seconds: slice.fast_budget_seconds,
            all_workspace,
        });
    }

    let contract = CONTRACTS
        .iter()
        .find(|contract| contract.name == name)
        .ok_or_else(|| {
            format!(
                "unknown development slice or exact workspace crate {name:?}; run `cargo xtask slices`"
            )
        })?;
    let upstream: BTreeSet<_> = contract
        .normal
        .iter()
        .chain(contract.dev)
        .map(|dependency| (*dependency).to_owned())
        .collect();
    let downstream: BTreeSet<_> = CONTRACTS
        .iter()
        .filter(|candidate| {
            candidate.normal.contains(&contract.name) || candidate.dev.contains(&contract.name)
        })
        .map(|candidate| candidate.name.to_owned())
        .collect();
    let (full_route, native_requirements, fast_budget_seconds) = exact_crate_full_profile(name);
    let mut target = GateTarget {
        name: name.to_owned(),
        purpose: format!("exact workspace crate at {}", contract.directory),
        packages: vec![name.to_owned()],
        upstream: upstream.into_iter().collect(),
        downstream: downstream.into_iter().collect(),
        fixture_families: Vec::new(),
        native_requirements: native_requirements
            .iter()
            .map(|requirement| (*requirement).to_owned())
            .collect(),
        full_route,
        fast_budget_seconds,
        all_workspace: false,
    };
    let workspace = expected_workspace_closure(&target.packages)?;
    target.fixture_families = reviewed_fixture_families(&workspace).into_iter().collect();
    Ok(target)
}

fn exact_crate_full_profile(name: &str) -> (FullRoute, &'static [&'static str], u64) {
    match name {
        "wrela-codegen-llvm" | "wrela-lld-sys" | "wrela-link-efi" => (
            FullRoute::ArtifactNative,
            &["system LLVM 22 (llvm-config on disk)", "system lld-link"],
            90,
        ),
        "wrela-backend" => (
            FullRoute::BackendNative,
            &["system LLVM 22 (llvm-config on disk)", "system lld-link"],
            120,
        ),
        "wrela-compiler" | "wrela-cli" | "wrela-test-runner" | "wrela-toolchain" | "xtask" => (
            FullRoute::Distribution,
            &["system LLVM/LLD + QEMU toolchain on disk"],
            180,
        ),
        _ => (FullRoute::None, &[], 60),
    }
}

fn validate_development_slice_metadata() -> Result<(), String> {
    let workspace_names: BTreeSet<_> = CONTRACTS.iter().map(|contract| contract.name).collect();
    let slice_names: BTreeSet<_> = DEVELOPMENT_SLICES.iter().map(|slice| slice.name).collect();
    if slice_names.len() != DEVELOPMENT_SLICES.len() {
        return Err("development slice names must be unique".to_owned());
    }
    if !slice_names.contains("all") {
        return Err("development slice inventory must include all".to_owned());
    }
    for slice in DEVELOPMENT_SLICES {
        if slice.name.trim().is_empty()
            || slice.purpose.trim().is_empty()
            || slice.fast_budget_seconds == 0
        {
            return Err(format!(
                "development slice {} has incomplete purpose or timing metadata",
                slice.name
            ));
        }
        let packages: BTreeSet<_> = slice.packages.iter().copied().collect();
        if packages.len() != slice.packages.len()
            || (slice.name == "all" && !packages.is_empty())
            || (slice.name != "all" && packages.is_empty())
            || packages
                .iter()
                .any(|package| !workspace_names.contains(package))
        {
            return Err(format!(
                "development slice {} has duplicate, empty, or unknown package entries",
                slice.name
            ));
        }
        for (kind, boundaries) in [
            ("upstream", slice.upstream),
            ("downstream", slice.downstream),
        ] {
            let unique: BTreeSet<_> = boundaries.iter().copied().collect();
            if unique.len() != boundaries.len()
                || boundaries
                    .iter()
                    .any(|boundary| *boundary == slice.name || !slice_names.contains(boundary))
            {
                return Err(format!(
                    "development slice {} has duplicate, self, or unknown {kind} boundaries",
                    slice.name
                ));
            }
        }
        let fixtures: BTreeSet<_> = slice.fixture_families.iter().copied().collect();
        if fixtures.len() != slice.fixture_families.len()
            || slice
                .fixture_families
                .iter()
                .any(|fixture| fixture.trim().is_empty())
        {
            return Err(format!(
                "development slice {} has invalid fixture metadata",
                slice.name
            ));
        }
        if (slice.full_route == FullRoute::None) != slice.native_requirements.is_empty() {
            return Err(format!(
                "development slice {} has inconsistent native/full metadata",
                slice.name
            ));
        }
    }

    let reviewed_by_name: BTreeMap<_, _> = REVIEWED_EXTERNAL_PACKAGES
        .iter()
        .map(|package| (package.name, package))
        .collect();
    if reviewed_by_name.len() != REVIEWED_EXTERNAL_PACKAGES.len() {
        return Err("reviewed external package names must be unique".to_owned());
    }
    for package in REVIEWED_EXTERNAL_PACKAGES {
        if package.name.trim().is_empty()
            || package.version.trim().is_empty()
            || package.dependencies.iter().any(|dependency| {
                *dependency == package.name || !reviewed_by_name.contains_key(dependency)
            })
        {
            return Err(format!(
                "reviewed external package {} has incomplete or unknown dependency metadata",
                package.name
            ));
        }
    }
    for dependency in EXTERNAL_DEPENDENCIES
        .iter()
        .filter(|dependency| !dependency.optional)
    {
        if !reviewed_by_name.contains_key(dependency.name) {
            return Err(format!(
                "non-optional external dependency {}/{} has no reviewed transitive package entry",
                dependency.owner, dependency.name
            ));
        }
    }
    Ok(())
}

fn validate_fixture_inventory(root: &Path) -> Result<(), String> {
    let declared: BTreeSet<_> = DEVELOPMENT_SLICES
        .iter()
        .flat_map(|slice| slice.fixture_families.iter().copied())
        .collect();
    let fixture_root = root.join("tests/contracts");
    for family in &declared {
        let path = fixture_root.join(family);
        if !path.is_dir() || !directory_contains_file(&path)? {
            return Err(format!(
                "declared fixture family {family} has no checked-in fixture files"
            ));
        }
    }
    let mut files = Vec::new();
    collect_files(&fixture_root, &mut files)?;
    for file in files {
        let relative = file
            .strip_prefix(&fixture_root)
            .map_err(|_| format!("fixture {} escaped fixture root", file.display()))?;
        if relative.file_name().is_some_and(|name| name == "README.md") {
            continue;
        }
        if !declared
            .iter()
            .any(|family| relative.starts_with(Path::new(family)))
        {
            return Err(format!(
                "checked-in fixture {} has no declared gate fixture family",
                relative.display()
            ));
        }
    }
    Ok(())
}

fn directory_contains_file(directory: &Path) -> Result<bool, String> {
    let mut files = Vec::new();
    collect_files(directory, &mut files)?;
    Ok(files
        .iter()
        .any(|path| path.file_name().is_some_and(|name| name != "README.md")))
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut directories = VecDeque::from([directory.to_owned()]);
    while let Some(current) = directories.pop_front() {
        for entry in fs::read_dir(&current)
            .map_err(|error| format!("cannot read {}: {error}", current.display()))?
        {
            let entry =
                entry.map_err(|error| format!("cannot inspect {}: {error}", current.display()))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if kind.is_symlink() {
                return Err(format!(
                    "fixture inventory forbids symbolic link {}",
                    path.display()
                ));
            }
            if kind.is_dir() {
                directories.push_back(path);
            } else if kind.is_file() {
                output.push(path);
            } else {
                return Err(format!(
                    "fixture inventory contains unsupported entry {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn expected_workspace_closure(roots: &[String]) -> Result<BTreeSet<String>, String> {
    let contracts: BTreeMap<_, _> = CONTRACTS
        .iter()
        .map(|contract| (contract.name, contract))
        .collect();
    let mut workspace = BTreeSet::new();
    let mut queue: VecDeque<_> = roots.iter().cloned().collect();
    while let Some(name) = queue.pop_front() {
        if !workspace.insert(name.clone()) {
            continue;
        }
        let contract = contracts
            .get(name.as_str())
            .ok_or_else(|| format!("gate root or dependency {name} lacks a crate contract"))?;
        // Every reviewed workspace package in the closure is passed to Cargo as
        // a selected package, so its all-target/test dev edges are reviewed too.
        for dependency in contract.normal.iter().chain(contract.dev) {
            queue.push_back((*dependency).to_owned());
        }
    }
    Ok(workspace)
}

fn reviewed_fixture_families(workspace: &BTreeSet<String>) -> BTreeSet<String> {
    let mut fixtures = BTreeSet::new();
    if workspace.contains("wrela-package-loader") {
        fixtures.insert("package/v1".to_owned());
    }
    if workspace.contains("wrela-syntax") {
        fixtures.insert("syntax/v3".to_owned());
    }
    if workspace.contains("wrela-target") {
        fixtures.insert("target/v1".to_owned());
    }
    if workspace.contains("wrela-test-protocol") {
        fixtures.insert("protocol/v1".to_owned());
    }
    if workspace.contains("wrela-toolchain") {
        fixtures.insert("toolchain/v1".to_owned());
    }
    fixtures
}

fn expected_gate_closure(target: &GateTarget) -> Result<GateClosure, String> {
    let workspace = expected_workspace_closure(&target.packages)?;

    let reviewed_by_name: BTreeMap<_, _> = REVIEWED_EXTERNAL_PACKAGES
        .iter()
        .map(|package| (package.name, package))
        .collect();
    let mut external_names = BTreeSet::new();
    let mut external_queue = VecDeque::new();
    for dependency in EXTERNAL_DEPENDENCIES {
        if dependency.optional || !workspace.contains(dependency.owner) {
            continue;
        }
        external_queue.push_back(dependency.name);
    }
    while let Some(name) = external_queue.pop_front() {
        if !external_names.insert(name) {
            continue;
        }
        let package = reviewed_by_name
            .get(name)
            .ok_or_else(|| format!("external package {name} lacks reviewed closure metadata"))?;
        external_queue.extend(package.dependencies.iter().copied());
    }
    let mut external = BTreeSet::new();
    for name in external_names {
        let package = reviewed_by_name
            .get(name)
            .ok_or_else(|| format!("external package {name} disappeared from reviewed metadata"))?;
        external.insert(format!("{}@{}", package.name, package.version));
    }
    Ok(GateClosure {
        workspace,
        external,
    })
}

fn actual_gate_closure(
    target: &GateTarget,
    metadata: &ResolvedMetadata,
) -> Result<GateClosure, String> {
    let mut root_ids = BTreeSet::new();
    for package in &target.packages {
        root_ids.insert(
            metadata
                .workspace_ids_by_name
                .get(package)
                .cloned()
                .ok_or_else(|| format!("cargo metadata omitted gate root {package}"))?,
        );
    }
    let mut visited = BTreeSet::new();
    let mut queue: VecDeque<_> = root_ids.iter().cloned().collect();
    while let Some(package_id) = queue.pop_front() {
        if !visited.insert(package_id.clone()) {
            continue;
        }
        let include_dev = metadata
            .packages
            .get(&package_id)
            .is_some_and(|package| package.workspace);
        for dependency in metadata.dependencies.get(&package_id).into_iter().flatten() {
            if dependency.kinds.contains(&DependencySection::Normal)
                || dependency.kinds.contains(&DependencySection::Build)
                || (include_dev && dependency.kinds.contains(&DependencySection::Development))
            {
                queue.push_back(dependency.package_id.clone());
            }
        }
    }

    let mut workspace = BTreeSet::new();
    let mut external = BTreeSet::new();
    for package_id in visited {
        let package = metadata
            .packages
            .get(&package_id)
            .ok_or_else(|| format!("cargo resolve references unknown package {package_id}"))?;
        if package.workspace {
            workspace.insert(package.name.clone());
        } else {
            external.insert(format!("{}@{}", package.name, package.version));
        }
    }
    Ok(GateClosure {
        workspace,
        external,
    })
}

fn compare_gate_closure(
    target_name: &str,
    expected: &GateClosure,
    actual: &GateClosure,
) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let missing_workspace: Vec<_> = expected
        .workspace
        .difference(&actual.workspace)
        .cloned()
        .collect();
    let unexpected_workspace: Vec<_> = actual
        .workspace
        .difference(&expected.workspace)
        .cloned()
        .collect();
    let missing_external: Vec<_> = expected
        .external
        .difference(&actual.external)
        .cloned()
        .collect();
    let unexpected_external: Vec<_> = actual
        .external
        .difference(&expected.external)
        .cloned()
        .collect();
    Err(format!(
        "gate closure drift for {target_name}\n  missing workspace: {missing_workspace:?}\n  unexpected workspace: {unexpected_workspace:?}\n  missing external: {missing_external:?}\n  unexpected external: {unexpected_external:?}"
    ))
}

fn validate_gate_closure(
    target: &GateTarget,
    metadata: &ResolvedMetadata,
) -> Result<GateClosure, String> {
    let expected = expected_gate_closure(target)?;
    let expected_fixtures = reviewed_fixture_families(&expected.workspace);
    let declared_fixtures: BTreeSet<_> = target.fixture_families.iter().cloned().collect();
    if expected_fixtures != declared_fixtures {
        return Err(format!(
            "gate fixture metadata drift for {}\n  expected from reviewed closure: {expected_fixtures:?}\n  declared: {declared_fixtures:?}",
            target.name
        ));
    }
    let actual = actual_gate_closure(target, metadata)?;
    compare_gate_closure(&target.name, &expected, &actual)?;
    Ok(actual)
}

fn print_gate_metadata(target: &GateTarget, closure: &GateClosure) {
    eprintln!("gate target: {}", target.name);
    eprintln!("  purpose: {}", target.purpose);
    eprintln!("  selected roots: {}", target.packages.join(", "));
    eprintln!(
        "  reviewed workspace closure ({}): {}",
        closure.workspace.len(),
        join_set(&closure.workspace)
    );
    eprintln!(
        "  reviewed external closure ({}): {}",
        closure.external.len(),
        join_set(&closure.external)
    );
    eprintln!("  immediate upstream: {}", join_list(&target.upstream));
    eprintln!("  immediate downstream: {}", join_list(&target.downstream));
    if target.fixture_families.is_empty() {
        eprintln!("  fixture families: none checked in for this gate target");
    } else {
        eprintln!("  fixture families: {}", target.fixture_families.join(", "));
    }
    eprintln!(
        "  native requirements: {}",
        join_list(&target.native_requirements)
    );
    eprintln!("  fast command: cargo xgate {}", target.name);
    if target.full_route == FullRoute::None {
        eprintln!(
            "  full command: cargo xgate {} --full (no additional check applies after fast)",
            target.name
        );
    } else {
        eprintln!("  full command: cargo xgate {} --full", target.name);
    }
    eprintln!(
        "  full route: {}",
        full_route_description(target.full_route)
    );
    eprintln!("  fast timing budget: {}s", target.fast_budget_seconds);
}

fn join_set(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn join_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

fn full_route_description(route: FullRoute) -> &'static str {
    match route {
        FullRoute::None => "none; the fast gate is complete for this non-native target",
        FullRoute::ArtifactNative => {
            "system LLVM/LLD on disk: cargo test with wrela-backend/bundled-backend"
        }
        FullRoute::BackendNative => {
            "system LLVM/LLD on disk: cargo test with wrela-backend/bundled-backend"
        }
        FullRoute::Distribution => {
            "system LLVM/LLD (+ QEMU) on disk: cargo test with wrela-backend/bundled-backend"
        }
    }
}

fn run_gate(root: &Path, request: &GateRequest) -> Result<(), String> {
    let started = Instant::now();
    validate_development_slice_metadata()?;
    let target = gate_target(&request.target)?;
    let metadata = resolved_cargo_metadata(root)?;
    let closure = validate_gate_closure(&target, &metadata)?;
    print_gate_metadata(&target, &closure);

    let mut format_arguments = vec![
        "--locked".to_owned(),
        "--offline".to_owned(),
        "fmt".to_owned(),
    ];
    append_package_selection(
        &mut format_arguments,
        &target,
        &closure,
        "--all",
        "--package",
    );
    format_arguments.extend(["--".to_owned(), "--check".to_owned()]);
    run_cargo(root, "scoped rustfmt", &format_arguments)?;

    let mut check_arguments = vec![
        "check".to_owned(),
        "--all-targets".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
    ];
    append_package_selection(
        &mut check_arguments,
        &target,
        &closure,
        "--workspace",
        "--package",
    );
    run_cargo(root, "cargo check --all-targets", &check_arguments)?;

    let mut test_arguments = vec![
        "test".to_owned(),
        "--no-fail-fast".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
    ];
    append_package_selection(
        &mut test_arguments,
        &target,
        &closure,
        "--workspace",
        "--package",
    );
    run_cargo(root, "unfiltered unit and contract tests", &test_arguments)?;

    let mut lint_arguments = vec![
        "clippy".to_owned(),
        "--all-targets".to_owned(),
        "--no-deps".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
    ];
    append_package_selection(
        &mut lint_arguments,
        &target,
        &closure,
        "--workspace",
        "--package",
    );
    lint_arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
    run_cargo(root, "Clippy with warnings denied", &lint_arguments)?;

    eprintln!("gate step architecture: validating reviewed contracts and closures");
    check_architecture(root)?;

    let fast_elapsed = started.elapsed();
    println!(
        "fast gate {} completed in {:.3}s (budget {}s)",
        target.name,
        fast_elapsed.as_secs_f64(),
        target.fast_budget_seconds
    );
    if fast_elapsed.as_secs_f64() > target.fast_budget_seconds as f64 {
        return Err(format!(
            "fast gate {} exceeded its {}s timing budget ({:.3}s)",
            target.name,
            target.fast_budget_seconds,
            fast_elapsed.as_secs_f64()
        ));
    }

    if request.full {
        run_full_route(root, &target, &closure)?;
    }
    Ok(())
}

fn append_package_selection(
    arguments: &mut Vec<String>,
    target: &GateTarget,
    closure: &GateClosure,
    all_flag: &str,
    package_flag: &str,
) {
    if target.all_workspace {
        arguments.push(all_flag.to_owned());
    } else {
        for package in &closure.workspace {
            arguments.extend([package_flag.to_owned(), package.clone()]);
        }
    }
}

fn run_cargo(root: &Path, label: &str, arguments: &[String]) -> Result<(), String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("gate step {label}: cargo {}", arguments.join(" "));
    let mut command = Command::new(cargo);
    command.args(arguments).current_dir(root);
    configure_cargo_gate_environment(&mut command);
    let status = command
        .status()
        .map_err(|error| format!("cannot execute cargo for {label}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed with {status}"))
    }
}

fn configure_cargo_gate_environment(command: &mut Command) {
    // System LLVM/LLD/QEMU are on disk; LLVM_SYS_221_PREFIX and the
    // WRELA_LLVM_* environment come from the workspace .cargo/config.toml
    // [env] table, so the gate itself only needs to stay offline.
    command.env("CARGO_NET_OFFLINE", "true");
}

/// Local no-CI nightly: evaluate HEAD in a clean git worktree, run the full
/// workspace gate plus architecture-check and every native `--full` route,
/// and write a timestamped pass/fail report under `target/gate-reports/`.
fn run_nightly(root: &Path) -> Result<PathBuf, String> {
    let reports = root.join("target/gate-reports");
    fs::create_dir_all(&reports)
        .map_err(|error| format!("cannot create gate-reports directory: {error}"))?;
    let stamp = nightly_stamp();
    let worktree = root.join(format!("target/nightly-worktree-{stamp}"));
    let report_path = reports.join(format!("nightly-{stamp}.txt"));
    let mut report = String::new();
    report.push_str(&format!(
        "wrela nightly\nstamp: {stamp}\nroot: {}\n",
        root.display()
    ));

    let mut failures = Vec::new();
    if let Err(error) = create_nightly_worktree(root, &worktree) {
        failures.push(format!("worktree: {error}"));
        report.push_str(&format!("status: FAIL\nworktree: {error}\n"));
        write_nightly_report(&report_path, &report)?;
        return Err(format!(
            "nightly failed; report at {}: {error}",
            report_path.display()
        ));
    }
    report.push_str(&format!("worktree: {}\n", worktree.display()));

    report.push_str("step: cargo xtask gate all\n");
    match run_gate(
        &worktree,
        &GateRequest {
            target: "all".to_owned(),
            full: false,
        },
    ) {
        Ok(()) => report.push_str("  result: PASS\n"),
        Err(error) => {
            report.push_str(&format!("  result: FAIL\n  error: {error}\n"));
            failures.push(format!("cargo xtask gate all: {error}"));
        }
    }

    report.push_str("step: cargo xtask architecture-check\n");
    match check_architecture(&worktree) {
        Ok(()) => report.push_str("  result: PASS\n"),
        Err(error) => {
            report.push_str(&format!("  result: FAIL\n  error: {error}\n"));
            failures.push(format!("cargo xtask architecture-check: {error}"));
        }
    }

    report.push_str("step: cargo xtask diagnostic-index\n");
    match check_diagnostic_index(&worktree) {
        Ok(()) => report.push_str("  result: PASS\n"),
        Err(error) => {
            report.push_str(&format!("  result: FAIL\n  error: {error}\n"));
            failures.push(format!("cargo xtask diagnostic-index: {error}"));
        }
    }

    report.push_str("step: native --full gates\n");
    match run_nightly_full_gates(&worktree) {
        Ok(()) => report.push_str("  result: PASS\n"),
        Err(error) => {
            report.push_str(&format!("  result: FAIL\n  error: {error}\n"));
            failures.push(format!("native --full gates: {error}"));
        }
    }

    remove_nightly_worktree(root, &worktree);

    if failures.is_empty() {
        report.push_str("status: PASS\n");
        write_nightly_report(&report_path, &report)?;
        Ok(report_path)
    } else {
        report.push_str("status: FAIL\n");
        for failure in &failures {
            report.push_str(&format!("failure: {failure}\n"));
        }
        write_nightly_report(&report_path, &report)?;
        Err(format!(
            "nightly failed; report at {}: {}",
            report_path.display(),
            failures.join("; ")
        ))
    }
}

fn nightly_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{nanos}")
}

fn create_nightly_worktree(root: &Path, worktree: &Path) -> Result<(), String> {
    if worktree.exists() {
        return Err(format!(
            "nightly worktree path already exists: {}",
            worktree.display()
        ));
    }
    let status = Command::new("git")
        .args([
            "worktree",
            "add",
            "--detach",
            &worktree.display().to_string(),
            "HEAD",
        ])
        .current_dir(root)
        .status()
        .map_err(|error| format!("cannot create nightly worktree: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git worktree add failed with {status}"))
    }
}

fn remove_nightly_worktree(root: &Path, worktree: &Path) {
    let _ = Command::new("git")
        .args([
            "worktree",
            "remove",
            "--force",
            &worktree.display().to_string(),
        ])
        .current_dir(root)
        .status();
    let _ = fs::remove_dir_all(worktree);
}

fn run_nightly_full_gates(root: &Path) -> Result<(), String> {
    // The fast `gate all` step already ran; this only adds the native LLVM/LLD
    // feature matrix for the workspace-wide distribution route.
    let metadata = resolved_cargo_metadata(root)?;
    let target = gate_target("all")?;
    let closure = validate_gate_closure(&target, &metadata)?;
    run_full_route(root, &target, &closure)
}

fn write_nightly_report(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|error| format!("cannot write nightly report: {error}"))
}

fn run_full_route(root: &Path, target: &GateTarget, closure: &GateClosure) -> Result<(), String> {
    let steps = full_route_steps(target, closure);
    if steps.is_empty() {
        println!(
            "full gate {} has no additional native check; fast evidence is complete",
            target.name
        );
        return Ok(());
    }
    for step in &steps {
        run_cargo(root, step.label, &step.arguments)?;
    }
    Ok(())
}

fn full_route_steps(target: &GateTarget, closure: &GateClosure) -> Vec<CargoStep> {
    if target.full_route == FullRoute::None {
        return Vec::new();
    }
    let mut arguments = vec![
        "test".to_owned(),
        "--all-targets".to_owned(),
        "--no-fail-fast".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
    ];
    append_package_selection(&mut arguments, target, closure, "--workspace", "--package");
    // Artifact-only closures do not include `wrela-backend`, so enable the LLVM
    // feature on the codegen package directly. Backend and distribution closures
    // include `wrela-backend` and use its bundled-backend feature.
    let feature = match target.full_route {
        FullRoute::ArtifactNative => "wrela-codegen-llvm/llvm",
        FullRoute::BackendNative | FullRoute::Distribution => "wrela-backend/bundled-backend",
        FullRoute::None => return Vec::new(),
    };
    arguments.extend(["--features".to_owned(), feature.to_owned()]);
    vec![CargoStep {
        label: "native system LLVM/LLD (+ QEMU) gate",
        arguments,
    }]
}

fn run_development_slice(
    root: &Path,
    operation: &str,
    slice_name: &str,
    extra: &[String],
) -> Result<(), String> {
    let slice = DEVELOPMENT_SLICES
        .iter()
        .find(|slice| slice.name == slice_name);
    let crate_name = CONTRACTS
        .iter()
        .find(|contract| contract.name == slice_name)
        .map(|contract| contract.name);
    if slice.is_none() && crate_name.is_none() {
        return Err(format!(
            "unknown development slice or crate {slice_name:?}; run `cargo xtask slices`"
        ));
    }
    if operation == "lint" && !extra.is_empty() {
        return Err("xtask lint does not accept extra arguments".to_owned());
    }
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(root);
    match operation {
        "check" => {
            command.args(["check", "--all-targets", "--locked", "--offline"]);
        }
        "test" => {
            command.args(["test", "--no-fail-fast", "--locked", "--offline"]);
        }
        "lint" => {
            command.args([
                "clippy",
                "--all-targets",
                "--no-deps",
                "--locked",
                "--offline",
            ]);
        }
        _ => return Err(format!("unsupported development operation {operation}")),
    }
    if slice.is_some_and(|slice| slice.name == "all") {
        command.arg("--workspace");
    } else if let Some(slice) = slice {
        for package in slice.packages {
            command.args(["-p", package]);
        }
    } else if let Some(package) = crate_name {
        command.args(["-p", package]);
    }
    command.args(extra);
    if operation == "lint" {
        command.args(["--", "-D", "warnings"]);
    }
    eprintln!("running {operation} for {slice_name}");
    let status = command
        .env("CARGO_NET_OFFLINE", "true")
        .status()
        .map_err(|error| format!("cannot execute cargo {operation}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cargo {operation} failed for {slice_name} with {status}"
        ))
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_owned)
        .ok_or_else(|| "xtask manifest has no workspace parent".to_owned())
}

fn architecture_root(arguments: &[String]) -> Result<PathBuf, String> {
    match arguments {
        [] => workspace_root(),
        [option, value] if option == "--root" => {
            let selected = PathBuf::from(value);
            if !selected.is_absolute() {
                return Err("architecture-check --root must be absolute".to_owned());
            }
            let canonical = fs::canonicalize(&selected).map_err(|error| {
                format!(
                    "cannot canonicalize architecture-check root {}: {error}",
                    selected.display()
                )
            })?;
            if canonical != selected || !canonical.is_dir() {
                return Err("architecture-check --root must be a canonical directory".to_owned());
            }
            Ok(canonical)
        }
        _ => Err("architecture-check accepts only --root <absolute-workspace>".to_owned()),
    }
}

pub(crate) fn check_architecture(root: &Path) -> Result<(), String> {
    validate_development_slice_metadata()?;
    validate_fixture_inventory(root)?;
    let workspace_names: BTreeSet<_> = CONTRACTS.iter().map(|contract| contract.name).collect();
    let expected_members: BTreeSet<_> = CONTRACTS
        .iter()
        .map(|contract| contract.directory.to_owned())
        .collect();
    let metadata = cargo_metadata(root)?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_owned())?;
    let package_names_by_id: BTreeMap<_, _> = packages
        .iter()
        .map(|package| {
            let id = metadata_string(package, "id")?;
            let name = metadata_string(package, "name")?;
            Ok((id.to_owned(), name.to_owned()))
        })
        .collect::<Result<_, String>>()?;
    let member_names = |field: &str| -> Result<BTreeSet<String>, String> {
        metadata
            .get(field)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("cargo metadata omitted {field}"))?
            .iter()
            .map(|id| {
                let id = id
                    .as_str()
                    .ok_or_else(|| format!("cargo metadata {field} contains a non-string ID"))?;
                package_names_by_id
                    .get(id)
                    .cloned()
                    .ok_or_else(|| format!("cargo metadata {field} names unknown package {id}"))
            })
            .collect()
    };
    let workspace_member_names = member_names("workspace_members")?;
    let expected_member_names: BTreeSet<_> = CONTRACTS
        .iter()
        .map(|contract| contract.name.to_owned())
        .collect();
    if workspace_member_names != expected_member_names {
        return Err(format!(
            "Cargo's workspace members differ from crate contracts\n  expected: {expected_member_names:?}\n  actual: {workspace_member_names:?}"
        ));
    }
    let default_members = member_names("workspace_default_members")?;
    if default_members != BTreeSet::from(["wrela-cli".to_owned()]) {
        return Err(format!(
            "workspace default-members must contain only wrela-cli, got {default_members:?}"
        ));
    }
    let workspace_members: BTreeSet<_> = packages
        .iter()
        .filter(|package| {
            metadata_string(package, "name").is_ok_and(|name| workspace_names.contains(name))
        })
        .map(|package| {
            let manifest = PathBuf::from(metadata_string(package, "manifest_path")?);
            let directory = manifest
                .parent()
                .ok_or_else(|| format!("{} has no parent", manifest.display()))?;
            directory
                .strip_prefix(root)
                .map(|path| path.to_string_lossy().into_owned())
                .map_err(|_| format!("{} is outside workspace root", manifest.display()))
        })
        .collect::<Result<_, String>>()?;
    if workspace_members != expected_members {
        return Err(format!(
            "root workspace members differ from crate contracts\n  expected: {expected_members:?}\n  actual: {workspace_members:?}"
        ));
    }
    let discovered = discover_workspace_crates(root)?;
    let declared: BTreeSet<_> = CONTRACTS
        .iter()
        .map(|contract| contract.name.to_owned())
        .collect();
    if discovered != declared {
        return Err(format!(
            "crate contract inventory differs from workspace directories\n  declared: {declared:?}\n  discovered: {discovered:?}"
        ));
    }
    check_documented_contract_inventory(root, &workspace_names)?;
    check_interface_contract_tests(root)?;

    for contract in CONTRACTS {
        let package = packages
            .iter()
            .find(|package| {
                metadata_string(package, "name").is_ok_and(|name| name == contract.name)
            })
            .ok_or_else(|| format!("cargo metadata omitted {}", contract.name))?;
        let dependencies = metadata_dependencies(package, &workspace_names)?;
        compare_set(
            contract.name,
            "normal",
            contract.normal,
            &dependencies.normal,
        )?;
        compare_set(
            contract.name,
            "development",
            contract.dev,
            &dependencies.dev,
        )?;
        check_declared_dependency_usage(root, contract)?;
        if !dependencies.build.is_empty() {
            return Err(format!(
                "{} has forbidden workspace build dependencies: {:?}",
                contract.name, dependencies.build
            ));
        }
        check_features(contract.name, package)?;
    }
    check_external_dependencies(packages, &workspace_names)?;
    check_toolchain_contracts(root)?;
    validate_gate_inventory_against_metadata(root)?;
    Ok(())
}

fn validate_gate_inventory_against_metadata(root: &Path) -> Result<(), String> {
    let metadata = resolved_cargo_metadata(root)?;
    for slice in DEVELOPMENT_SLICES {
        let target = gate_target(slice.name)?;
        validate_gate_closure(&target, &metadata)?;
    }
    Ok(())
}

fn check_interface_contract_tests(root: &Path) -> Result<(), String> {
    for contract in CONTRACTS {
        let source_path = root.join(contract.directory).join("src/lib.rs");
        if !source_path.is_file() {
            continue;
        }
        let source = fs::read_to_string(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        let exposes_interface = source.contains("pub trait ")
            || source.contains("pub fn seal")
            || source.contains("pub fn finish_")
            || source.contains("pub fn decode_and_verify");
        if exposes_interface && !source.contains("#[test]") {
            return Err(format!(
                "{} exposes a phase/capability interface without contract tests",
                contract.name
            ));
        }
    }
    Ok(())
}

fn check_declared_dependency_usage(root: &Path, contract: &CrateContract) -> Result<(), String> {
    let mut rust_source = String::new();
    collect_rust_source(&root.join(contract.directory).join("src"), &mut rust_source)?;
    collect_rust_source(
        &root.join(contract.directory).join("tests"),
        &mut rust_source,
    )?;
    for dependency in contract.normal.iter().chain(contract.dev) {
        let identifier = dependency.replace('-', "_");
        if !rust_source.contains(&identifier) {
            return Err(format!(
                "{} declares unused workspace dependency {dependency}",
                contract.name
            ));
        }
    }
    Ok(())
}

fn collect_rust_source(directory: &Path, output: &mut String) -> Result<(), String> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_source(&path, output)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push_str(
                &fs::read_to_string(&path)
                    .map_err(|error| format!("cannot read {}: {error}", path.display()))?,
            );
        }
    }
    Ok(())
}

fn check_documented_contract_inventory(
    root: &Path,
    workspace_names: &BTreeSet<&str>,
) -> Result<(), String> {
    let path = root.join("docs/crate-contracts.md");
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut counts = BTreeMap::<String, u32>::new();
    for line in text.lines() {
        let Some(name) = line
            .strip_prefix("### `")
            .and_then(|line| line.strip_suffix('`'))
            .filter(|name| name.starts_with("wrela-") || *name == "xtask")
        else {
            continue;
        };
        let count = counts.entry(name.to_owned()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| format!("documented crate count overflowed for {name}"))?;
    }
    let duplicates: Vec<_> = counts
        .iter()
        .filter(|(_, count)| **count != 1)
        .map(|(name, count)| format!("{name} ({count} sections)"))
        .collect();
    let documented: BTreeSet<_> = counts.keys().map(String::as_str).collect();
    if documented != *workspace_names || !duplicates.is_empty() {
        return Err(format!(
            "documented crate contracts differ from the enforced workspace\n  expected: {workspace_names:?}\n  documented: {documented:?}\n  duplicates: {duplicates:?}"
        ));
    }
    let start_marker = "<!-- architecture-check: dependency graph begin -->";
    let end_marker = "<!-- architecture-check: dependency graph end -->";
    let documented_graph = text
        .split_once(start_marker)
        .and_then(|(_, rest)| rest.split_once(end_marker).map(|(graph, _)| graph))
        .ok_or_else(|| "crate contracts omit the enforced dependency graph markers".to_owned())?;
    let mut expected_graph = String::from("\n```text\n");
    for contract in CONTRACTS {
        expected_graph.push_str(contract.name);
        expected_graph.push_str(" -> ");
        if contract.normal.is_empty() {
            expected_graph.push_str("no workspace dependencies");
        } else {
            expected_graph.push_str(&contract.normal.join(", "));
        }
        expected_graph.push('\n');
        if !contract.dev.is_empty() {
            expected_graph.push_str(contract.name);
            expected_graph.push_str(" -[dev]-> ");
            expected_graph.push_str(&contract.dev.join(", "));
            expected_graph.push('\n');
        }
    }
    expected_graph.push_str("```\n");
    if documented_graph != expected_graph {
        return Err(format!(
            "documented workspace dependency graph has drifted; replace the marked block with:\n{expected_graph}"
        ));
    }
    Ok(())
}

fn cargo_metadata(root: &Path) -> Result<serde_json::Value, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"));
    configure_architecture_command(&mut command, root);
    let output = command
        .output()
        .map_err(|error| format!("cannot execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))
}

fn resolved_cargo_metadata(root: &Path) -> Result<ResolvedMetadata, String> {
    let host = rustc_host_triple(root)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .args(["--filter-platform"])
        .arg(&host);
    configure_architecture_command(&mut command, root);
    let output = command
        .output()
        .map_err(|error| format!("cannot execute resolved cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "resolved cargo metadata failed for host {host}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot decode resolved cargo metadata: {error}"))?;
    decode_resolved_metadata(&value)
}

fn rustc_host_triple(root: &Path) -> Result<String, String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut command = Command::new(rustc);
    command.arg("-vV");
    configure_architecture_command(&mut command, root);
    let output = command
        .output()
        .map_err(|error| format!("cannot query rustc host triple: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc host query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV omitted its host triple".to_owned())
}

fn configure_architecture_command(command: &mut Command, root: &Path) {
    command.current_dir(root).env("CARGO_NET_OFFLINE", "true");
}

fn decode_resolved_metadata(value: &serde_json::Value) -> Result<ResolvedMetadata, String> {
    let workspace_ids: BTreeSet<_> = value
        .get("workspace_members")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "resolved cargo metadata omitted workspace_members".to_owned())?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "resolved cargo metadata has a non-string workspace ID".to_owned())
        })
        .collect::<Result<_, String>>()?;
    let package_values = value
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "resolved cargo metadata omitted packages".to_owned())?;
    let mut packages = BTreeMap::new();
    let mut workspace_ids_by_name = BTreeMap::new();
    for package in package_values {
        let id = metadata_string(package, "id")?.to_owned();
        let name = metadata_string(package, "name")?.to_owned();
        let version = metadata_string(package, "version")?.to_owned();
        let workspace = workspace_ids.contains(&id);
        if workspace
            && workspace_ids_by_name
                .insert(name.clone(), id.clone())
                .is_some()
        {
            return Err(format!(
                "resolved cargo metadata contains duplicate workspace package {name}"
            ));
        }
        if packages
            .insert(
                id.clone(),
                ResolvedPackage {
                    name,
                    version,
                    workspace,
                },
            )
            .is_some()
        {
            return Err(format!(
                "resolved cargo metadata contains duplicate package ID {id}"
            ));
        }
    }
    if workspace_ids_by_name.len() != workspace_ids.len() {
        return Err("resolved cargo metadata omitted a workspace package record".to_owned());
    }

    let node_values = value
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "resolved cargo metadata omitted resolve.nodes".to_owned())?;
    let mut dependencies = BTreeMap::new();
    for node in node_values {
        let id = metadata_string(node, "id")?.to_owned();
        let dependency_values = node
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("cargo resolve node {id} omitted deps"))?;
        let mut resolved = Vec::new();
        for dependency in dependency_values {
            let package_id = metadata_string(dependency, "pkg")?.to_owned();
            if !packages.contains_key(&package_id) {
                return Err(format!(
                    "cargo resolve node {id} references unknown package {package_id}"
                ));
            }
            let kind_values = dependency
                .get("dep_kinds")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    format!("cargo resolve dependency {id} -> {package_id} omitted dep_kinds")
                })?;
            let mut kinds = BTreeSet::new();
            if kind_values.is_empty() {
                kinds.insert(DependencySection::Normal);
            }
            for kind in kind_values {
                let section = match kind.get("kind") {
                    None | Some(serde_json::Value::Null) => DependencySection::Normal,
                    Some(value) if value.as_str() == Some("normal") => DependencySection::Normal,
                    Some(value) if value.as_str() == Some("dev") => DependencySection::Development,
                    Some(value) if value.as_str() == Some("build") => DependencySection::Build,
                    Some(value) => {
                        return Err(format!(
                            "cargo resolve dependency {id} -> {package_id} has unknown kind {value}"
                        ));
                    }
                };
                kinds.insert(section);
            }
            resolved.push(ResolvedDependency { package_id, kinds });
        }
        if dependencies.insert(id.clone(), resolved).is_some() {
            return Err(format!("cargo resolve contains duplicate node {id}"));
        }
    }
    Ok(ResolvedMetadata {
        packages,
        workspace_ids_by_name,
        dependencies,
    })
}

fn metadata_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("cargo metadata field {field} is missing or not a string"))
}

fn metadata_dependencies(
    package: &serde_json::Value,
    workspace_names: &BTreeSet<&str>,
) -> Result<DependencySets, String> {
    let mut output = DependencySets::default();
    for dependency in package
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cargo metadata package omitted dependencies".to_owned())?
    {
        let name = metadata_string(dependency, "name")?;
        if dependency
            .get("source")
            .is_some_and(|source| !source.is_null())
            || !workspace_names.contains(name)
        {
            continue;
        }
        let destination = match dependency.get("kind").and_then(serde_json::Value::as_str) {
            None | Some("normal") => &mut output.normal,
            Some("dev") => &mut output.dev,
            Some("build") => &mut output.build,
            Some(kind) => return Err(format!("unknown cargo dependency kind {kind}")),
        };
        destination.insert(name.to_owned());
    }
    Ok(output)
}

fn check_features(crate_name: &str, package: &serde_json::Value) -> Result<(), String> {
    let actual_object = package
        .get("features")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("cargo metadata omitted features for {crate_name}"))?;
    let actual: BTreeMap<String, BTreeSet<String>> = actual_object
        .iter()
        .map(|(name, values)| {
            let values = values
                .as_array()
                .ok_or_else(|| format!("feature {crate_name}/{name} is not an array"))?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        format!("feature {crate_name}/{name} contains a non-string value")
                    })
                })
                .collect::<Result<_, String>>()?;
            Ok((name.clone(), values))
        })
        .collect::<Result<_, String>>()?;
    let expected: BTreeMap<String, BTreeSet<String>> = FEATURE_CONTRACTS
        .iter()
        .find(|(owner, _)| *owner == crate_name)
        .map(|(_, features)| {
            features
                .iter()
                .map(|(name, values)| {
                    (
                        (*name).to_owned(),
                        values.iter().map(|value| (*value).to_owned()).collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{crate_name} feature contract failed\n  expected: {expected:?}\n  actual: {actual:?}"
        ))
    }
}

fn check_external_dependencies(
    packages: &[serde_json::Value],
    workspace_names: &BTreeSet<&str>,
) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    for package in packages {
        let owner = metadata_string(package, "name")?;
        if !workspace_names.contains(owner) {
            continue;
        }
        for dependency in package
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("cargo metadata omitted dependencies for {owner}"))?
        {
            let name = metadata_string(dependency, "name")?;
            if workspace_names.contains(name)
                && dependency
                    .get("source")
                    .is_none_or(serde_json::Value::is_null)
            {
                continue;
            }
            let source = dependency
                .get("source")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{owner} has forbidden non-workspace path dependency {name}; every external dependency must come from the registry"
                    )
                })?;
            if !source.starts_with("registry+") {
                return Err(format!(
                    "{owner} dependency {name} is not registry-pinned: {source}"
                ));
            }
            let requirement = metadata_string(dependency, "req")?;
            let optional = dependency
                .get("optional")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| format!("cargo metadata omitted optional for {owner}/{name}"))?;
            let default_features = dependency
                .get("uses_default_features")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    format!("cargo metadata omitted default features for {owner}/{name}")
                })?;
            let mut features: Vec<_> = dependency
                .get("features")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| format!("cargo metadata omitted features for {owner}/{name}"))?
                .iter()
                .map(|feature| {
                    feature.as_str().map(str::to_owned).ok_or_else(|| {
                        format!("cargo metadata has a non-string feature for {owner}/{name}")
                    })
                })
                .collect::<Result<_, String>>()?;
            features.sort_unstable();
            actual.insert(external_dependency_key(
                owner,
                name,
                dependency_kind(dependency)?,
                requirement,
                optional,
                default_features,
                &features,
            ));
        }
    }
    let expected: BTreeSet<_> = EXTERNAL_DEPENDENCIES
        .iter()
        .map(|dependency| {
            let mut features: Vec<_> = dependency
                .features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect();
            features.sort_unstable();
            external_dependency_key(
                dependency.owner,
                dependency.name,
                dependency.kind,
                dependency.requirement,
                dependency.optional,
                dependency.default_features,
                &features,
            )
        })
        .collect();
    if actual == expected {
        Ok(())
    } else {
        let missing: Vec<_> = expected.difference(&actual).cloned().collect();
        let forbidden: Vec<_> = actual.difference(&expected).cloned().collect();
        Err(format!(
            "external dependency contract failed\n  missing: {missing:?}\n  forbidden: {forbidden:?}"
        ))
    }
}

fn dependency_kind(dependency: &serde_json::Value) -> Result<DependencySection, String> {
    match dependency.get("kind").and_then(serde_json::Value::as_str) {
        None | Some("normal") => Ok(DependencySection::Normal),
        Some("dev") => Ok(DependencySection::Development),
        Some("build") => Ok(DependencySection::Build),
        Some(kind) => Err(format!("unknown cargo dependency kind {kind}")),
    }
}

fn external_dependency_key(
    owner: &str,
    name: &str,
    kind: DependencySection,
    requirement: &str,
    optional: bool,
    default_features: bool,
    features: &[String],
) -> String {
    format!(
        "{owner}|{name}|{}|{requirement}|optional={optional}|default={default_features}|{}",
        match kind {
            DependencySection::Normal => "normal",
            DependencySection::Development => "dev",
            DependencySection::Build => "build",
        },
        features.join(",")
    )
}

fn check_toolchain_contracts(root: &Path) -> Result<(), String> {
    let checks: &[(&str, &[&str])] = &[
        (
            "crates/wrela-toolchain/src/lib.rs",
            &["REQUIRED_LLVM_PROJECT_REVISION: &str = \"llvmorg-22.1.3\""],
        ),
        (
            "crates/wrela-codegen-llvm/src/lib.rs",
            &["PINNED_LLVM_VERSION: (u32, u32, u32) = (22, 1, 3)"],
        ),
        (
            "toolchain/targets/aarch64-qemu-virt-uefi/target.toml",
            &[
                "llvm_triple = \"aarch64-unknown-uefi\"",
                "llvm_cpu = \"cortex-a57\"",
                "llvm_features = [\"+reserve-x18\"]",
                "machine = \"virt-10.0,gic-version=3,secure=off\"",
                "emulator = \"qemu-system-aarch64\"",
            ],
        ),
    ];
    for (relative, required) in checks {
        let path = root.join(relative);
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        for fragment in *required {
            if !text.contains(fragment) {
                return Err(format!(
                    "{} is missing required AArch64 contract fragment {fragment:?}",
                    path.display()
                ));
            }
        }
    }
    if root.join("toolchain/targets/x86_64-uefi").exists() {
        return Err("forbidden x86 target remains in the AArch64-only toolchain".to_owned());
    }
    check_compatibility_tuple(root)?;
    Ok(())
}

fn check_compatibility_tuple(root: &Path) -> Result<(), String> {
    let contracts = [
        (
            "build_profile_encoding",
            "crates/wrela-build-model/src/lib.rs",
            "PROFILE_ENCODING_VERSION",
        ),
        (
            "backend_protocol",
            "crates/wrela-backend-protocol/src/lib.rs",
            "PROTOCOL_VERSION",
        ),
        (
            "target_package",
            "crates/wrela-target/src/lib.rs",
            "TARGET_PACKAGE_SCHEMA",
        ),
        (
            "semantic_wir",
            "crates/wrela-semantic-wir/src/lib.rs",
            "SEMANTIC_WIR_VERSION",
        ),
        (
            "flow_wir",
            "crates/wrela-flow-wir/src/lib.rs",
            "FLOW_WIR_VERSION",
        ),
        (
            "flow_wir_wire",
            "crates/wrela-flow-wir-codec/src/lib.rs",
            "FLOW_WIR_WIRE_VERSION",
        ),
        (
            "machine_wir",
            "crates/wrela-machine-wir/src/lib.rs",
            "MACHINE_WIR_VERSION",
        ),
        (
            "runtime_abi",
            "crates/wrela-runtime-abi/src/lib.rs",
            "RUNTIME_ABI_VERSION",
        ),
        (
            "image_report",
            "crates/wrela-image-report/src/lib.rs",
            "REPORT_SCHEMA_VERSION",
        ),
        (
            "test_plan",
            "crates/wrela-test-model/src/lib.rs",
            "TEST_PLAN_SCHEMA",
        ),
        (
            "test_report",
            "crates/wrela-test-model/src/lib.rs",
            "TEST_REPORT_SCHEMA",
        ),
        (
            "image_scenario",
            "crates/wrela-test-model/src/lib.rs",
            "IMAGE_SCENARIO_SCHEMA",
        ),
        (
            "test_event",
            "crates/wrela-test-model/src/lib.rs",
            "TEST_PROTOCOL_VERSION",
        ),
        (
            "test_frame",
            "crates/wrela-test-protocol/src/lib.rs",
            "TEST_FRAME_VERSION",
        ),
    ];
    let toolchain_path = root.join("crates/wrela-toolchain/src/lib.rs");
    let toolchain = fs::read_to_string(&toolchain_path)
        .map_err(|error| format!("cannot read {}: {error}", toolchain_path.display()))?;
    let current = toolchain
        .split_once("pub const fn current() -> Self {")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n    }\n}").map(|(body, _)| body))
        .ok_or_else(|| "cannot locate ToolchainCompatibility::current".to_owned())?;
    for (field, relative, constant) in contracts {
        let path = root.join(relative);
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let marker = format!("pub const {constant}: u32 = ");
        let value = source
            .lines()
            .find_map(|line| line.trim().strip_prefix(&marker))
            .and_then(|value| value.strip_suffix(';'))
            .ok_or_else(|| format!("cannot read {constant} from {}", path.display()))?;
        if !current.contains(&format!("{field}: {value},")) {
            return Err(format!(
                "ToolchainCompatibility::current field {field} does not match {constant}={value}"
            ));
        }
    }
    Ok(())
}

fn discover_workspace_crates(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    let crates = fs::read_dir(root.join("crates"))
        .map_err(|error| format!("cannot read crates directory: {error}"))?;
    for entry in crates {
        let entry = entry.map_err(|error| format!("cannot inspect crate directory: {error}"))?;
        if entry.path().join("Cargo.toml").is_file() {
            names.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    if root.join("xtask/Cargo.toml").is_file() {
        names.insert("xtask".to_owned());
    }
    Ok(names)
}

#[derive(Debug, Default)]
struct DependencySets {
    normal: BTreeSet<String>,
    dev: BTreeSet<String>,
    build: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DependencySection {
    Normal,
    Development,
    Build,
}

fn compare_set(
    crate_name: &str,
    kind: &str,
    expected: &[&str],
    actual: &BTreeSet<String>,
) -> Result<(), String> {
    let expected: BTreeSet<_> = expected.iter().map(|name| (*name).to_owned()).collect();
    if &expected == actual {
        return Ok(());
    }
    let missing: Vec<_> = expected.difference(actual).cloned().collect();
    let forbidden: Vec<_> = actual.difference(&expected).cloned().collect();
    Err(format!(
        "{crate_name} {kind} dependency contract failed\n  missing: {missing:?}\n  forbidden: {forbidden:?}"
    ))
}

/// Checked-in inventory of every stable source diagnostic code.
const DIAGNOSTIC_INDEX_PATH: &str = "docs/language/diagnostic-index.md";
const DIAGNOSTIC_INDEX_CODES_BEGIN: &str = "<!-- diagnostic-index: codes begin -->";
const DIAGNOSTIC_INDEX_CODES_END: &str = "<!-- diagnostic-index: codes end -->";
const DIAGNOSTIC_INDEX_EXCLUSIONS_BEGIN: &str = "<!-- diagnostic-index: exclusions begin -->";
const DIAGNOSTIC_INDEX_EXCLUSIONS_END: &str = "<!-- diagnostic-index: exclusions end -->";

/// Bounded-copy helpers that move a code into limit-checked storage without
/// changing its text. Extraction looks through them at their first argument.
const DIAGNOSTIC_CODE_COPY_HELPERS: &[&str] = &[
    "clone_text",
    "copy_builtin_attribute_diagnostic_text",
    "copy_static_analysis_text",
    "try_copy_string_cancellable",
];

/// Conversions that may follow a code literal without changing its text.
const DIAGNOSTIC_CODE_LITERAL_SUFFIXES: &[&str] = &["", ".to_owned()", ".to_string()", ".into()"];

/// A diagnostic-code construction site the source-based extractor cannot read.
/// Every entry must still be present, or the check fails: silently dropping a
/// site would make the index under-report.
struct DiagnosticCodeExclusion {
    path: &'static str,
    expression: &'static str,
    reason: &'static str,
}

const DIAGNOSTIC_CODE_EXCLUSIONS: &[DiagnosticCodeExclusion] = &[DiagnosticCodeExclusion {
    path: "crates/wrela-compiler/src/local_lint.rs",
    expression: "lint.as_str().to_owned()",
    reason: "lint findings carry the registered lint name, not a phase-owned code",
}];

/// One workspace source file considered by the diagnostic-code extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticSourceUnit {
    crate_name: String,
    path: String,
    text: String,
}

/// A construction site whose code the extractor refused to guess.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticCodeRejection {
    path: String,
    line: usize,
    context: String,
    expression: String,
}

impl DiagnosticCodeRejection {
    fn describe(&self) -> String {
        format!(
            "{}:{} {}: `{}`",
            self.path, self.line, self.context, self.expression
        )
    }
}

/// Result of reading every admitted code carrier out of workspace source.
#[derive(Debug, Default)]
struct DiagnosticCodeScan {
    codes: BTreeMap<String, BTreeSet<String>>,
    rejections: Vec<DiagnosticCodeRejection>,
}

/// A function body and its parameter list, located in masked source.
struct MaskedFunction {
    name: String,
    parameters: String,
    signature_start: usize,
    body_start: usize,
    body_end: usize,
}

/// Source with comments and string contents blanked so that byte offsets stay
/// aligned with the original text while delimiter nesting stays readable.
struct MaskedSource {
    bytes: Vec<u8>,
    literals: BTreeMap<usize, String>,
    test_regions: Vec<(usize, usize)>,
    functions: Vec<MaskedFunction>,
    constants: BTreeMap<String, String>,
}

fn mask_rust_source(text: &str) -> MaskedSource {
    let source = text.as_bytes();
    let mut bytes = source.to_vec();
    let mut literals = BTreeMap::new();
    let mut index = 0;
    while index < source.len() {
        match source[index] {
            b'/' if source.get(index + 1) == Some(&b'/') => {
                while index < source.len() && source[index] != b'\n' {
                    bytes[index] = b' ';
                    index += 1;
                }
            }
            b'/' if source.get(index + 1) == Some(&b'*') => {
                let mut depth = 1u32;
                bytes[index] = b' ';
                bytes[index + 1] = b' ';
                index += 2;
                while index < source.len() && depth > 0 {
                    if source[index] == b'/' && source.get(index + 1) == Some(&b'*') {
                        depth += 1;
                    } else if source[index] == b'*' && source.get(index + 1) == Some(&b'/') {
                        depth -= 1;
                    }
                    if source[index] != b'\n' {
                        bytes[index] = b' ';
                    }
                    index += 1;
                }
            }
            b'"' | b'r' | b'b' => {
                let Some((start, content, end)) = read_string_literal(source, index) else {
                    index += 1;
                    continue;
                };
                literals.insert(start, content);
                for byte in &mut bytes[start..end] {
                    if *byte != b'\n' {
                        *byte = b'\0';
                    }
                }
                bytes[start] = b'"';
                index = end;
            }
            b'\'' => {
                index += read_char_literal(source, index);
            }
            _ => index += 1,
        }
    }
    let test_regions = masked_test_regions(&bytes);
    let functions = masked_functions(&bytes);
    let constants = masked_constants(&bytes, &literals);
    MaskedSource {
        bytes,
        literals,
        test_regions,
        functions,
        constants,
    }
}

/// Read `"..."`, `r#"..."#`, `b"..."`, or `br#"..."#` starting at `index`.
/// Returns the opening-quote offset, the raw content, and the end offset.
fn read_string_literal(source: &[u8], index: usize) -> Option<(usize, String, usize)> {
    let mut cursor = index;
    if source[cursor] == b'b' {
        cursor += 1;
    }
    let raw = source.get(cursor) == Some(&b'r');
    if raw {
        cursor += 1;
    }
    let mut hashes = 0usize;
    while source.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if source.get(cursor) != Some(&b'"') || (hashes > 0 && !raw) {
        return None;
    }
    let quote = cursor;
    cursor += 1;
    let content_start = cursor;
    if raw {
        loop {
            if cursor >= source.len() {
                return None;
            }
            if source[cursor] == b'"'
                && source[cursor + 1..]
                    .iter()
                    .take(hashes)
                    .filter(|byte| **byte == b'#')
                    .count()
                    == hashes
            {
                let content = String::from_utf8_lossy(&source[content_start..cursor]).into_owned();
                return Some((quote, content, cursor + 1 + hashes));
            }
            cursor += 1;
        }
    }
    loop {
        if cursor >= source.len() {
            return None;
        }
        match source[cursor] {
            b'\\' => cursor += 2,
            b'"' => {
                let content = String::from_utf8_lossy(&source[content_start..cursor]).into_owned();
                return Some((quote, content, cursor + 1));
            }
            _ => cursor += 1,
        }
    }
}

/// Length of a character literal at `index`, or 1 when the quote opens a
/// lifetime instead.
fn read_char_literal(source: &[u8], index: usize) -> usize {
    let rest = &source[index + 1..];
    match rest.first() {
        Some(b'\\') => {
            let mut cursor = 1;
            while index + 1 + cursor < source.len() && source[index + 1 + cursor] != b'\'' {
                cursor += 1;
            }
            cursor + 2
        }
        Some(_) if rest.get(1) == Some(&b'\'') => 3,
        _ => 1,
    }
}

fn masked_test_regions(bytes: &[u8]) -> Vec<(usize, usize)> {
    const MARKER: &[u8] = b"#[cfg(test)]";
    let mut regions = Vec::new();
    let mut index = 0;
    while index + MARKER.len() <= bytes.len() {
        if &bytes[index..index + MARKER.len()] != MARKER {
            index += 1;
            continue;
        }
        let mut cursor = index + MARKER.len();
        while cursor < bytes.len() && bytes[cursor] != b'{' && bytes[cursor] != b';' {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b'{' {
            regions.push((index, matching_delimiter(bytes, cursor)));
        } else {
            regions.push((index, cursor.min(bytes.len())));
        }
        index += MARKER.len();
    }
    regions
}

fn matching_delimiter(bytes: &[u8], open: usize) -> usize {
    let mut depth = 0i32;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
        index += 1;
    }
    bytes.len().saturating_sub(1)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_at(bytes: &[u8], index: usize) -> Option<String> {
    if index >= bytes.len() || !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_') {
        return None;
    }
    let mut end = index;
    while end < bytes.len() && is_identifier_byte(bytes[end]) {
        end += 1;
    }
    Some(String::from_utf8_lossy(&bytes[index..end]).into_owned())
}

fn skip_whitespace(bytes: &[u8], mut index: usize, limit: usize) -> usize {
    while index < limit && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn masked_functions(bytes: &[u8]) -> Vec<MaskedFunction> {
    let mut functions = Vec::new();
    let mut index = 0;
    while index + 2 <= bytes.len() {
        if &bytes[index..index + 2] != b"fn"
            || (index > 0 && is_identifier_byte(bytes[index - 1]))
            || bytes
                .get(index + 2)
                .is_some_and(|byte| is_identifier_byte(*byte))
        {
            index += 1;
            continue;
        }
        let name_start = skip_whitespace(bytes, index + 2, bytes.len());
        let Some(name) = identifier_at(bytes, name_start) else {
            index += 2;
            continue;
        };
        let mut cursor = name_start + name.len();
        // Skip an optional generic parameter list before the value parameters.
        cursor = skip_whitespace(bytes, cursor, bytes.len());
        if bytes.get(cursor) == Some(&b'<') {
            let mut depth = 0i32;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'<' => depth += 1,
                    b'>' => {
                        depth -= 1;
                        if depth == 0 {
                            cursor += 1;
                            break;
                        }
                    }
                    b'{' | b';' => break,
                    _ => {}
                }
                cursor += 1;
            }
            cursor = skip_whitespace(bytes, cursor, bytes.len());
        }
        if bytes.get(cursor) != Some(&b'(') {
            index += 2;
            continue;
        }
        let parameters_end = matching_delimiter(bytes, cursor);
        let parameters = String::from_utf8_lossy(&bytes[cursor + 1..parameters_end]).into_owned();
        let mut body = parameters_end + 1;
        while body < bytes.len() && bytes[body] != b'{' && bytes[body] != b';' {
            body += 1;
        }
        if body >= bytes.len() || bytes[body] == b';' {
            index = parameters_end + 1;
            continue;
        }
        let body_end = matching_delimiter(bytes, body);
        functions.push(MaskedFunction {
            name,
            parameters,
            signature_start: index,
            body_start: body,
            body_end,
        });
        index = body + 1;
    }
    functions
}

/// Whether a function is reachable outside its own file. Carrier call sites are
/// only searched within the defining file, so an exported carrier must be
/// rejected instead of silently under-reporting.
fn function_is_exported(bytes: &[u8], function: &MaskedFunction) -> bool {
    let mut cursor = function.signature_start;
    loop {
        while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
            cursor -= 1;
        }
        if cursor > 0 && bytes[cursor - 1] == b')' {
            // A visibility restriction such as `pub(crate)`.
            let mut depth = 0i32;
            let mut open = cursor - 1;
            loop {
                match bytes[open] {
                    b')' => depth += 1,
                    b'(' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                if open == 0 {
                    return false;
                }
                open -= 1;
            }
            cursor = open;
            continue;
        }
        let mut start = cursor;
        while start > 0 && is_identifier_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start == cursor {
            return false;
        }
        match &bytes[start..cursor] {
            b"pub" => return true,
            b"const" | b"async" | b"unsafe" | b"default" => cursor = start,
            _ => return false,
        }
    }
}

fn masked_constants(bytes: &[u8], literals: &BTreeMap<usize, String>) -> BTreeMap<String, String> {
    let mut constants = BTreeMap::new();
    let mut index = 0;
    while index + 5 <= bytes.len() {
        if &bytes[index..index + 5] != b"const"
            || (index > 0 && is_identifier_byte(bytes[index - 1]))
        {
            index += 1;
            continue;
        }
        let name_start = skip_whitespace(bytes, index + 5, bytes.len());
        let Some(name) = identifier_at(bytes, name_start) else {
            index += 5;
            continue;
        };
        let mut cursor = skip_whitespace(bytes, name_start + name.len(), bytes.len());
        if bytes.get(cursor) != Some(&b':') {
            index += 5;
            continue;
        }
        let statement_end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b';')
            .map_or(bytes.len(), |offset| cursor + offset);
        let Some(equals) = bytes[cursor..statement_end]
            .iter()
            .position(|byte| *byte == b'=')
        else {
            index += 5;
            continue;
        };
        cursor = skip_whitespace(bytes, cursor + equals + 1, statement_end);
        if let Some(value) = literals.get(&cursor) {
            constants.insert(name, value.clone());
        }
        index = statement_end.max(index + 5);
    }
    constants
}

/// Split a delimited list at top-level commas, returning byte ranges relative
/// to the start of `bytes`.
fn split_top_level(bytes: &[u8], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut depth = 0i32;
    let mut item = start;
    let mut index = start;
    while index < end {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'<' if bytes.get(index + 1) != Some(&b'-') => depth += 1,
            b'>' if index > start && bytes[index - 1] != b'-' && bytes[index - 1] != b'=' => {
                depth -= 1;
            }
            b',' if depth == 0 => {
                ranges.push((item, index));
                item = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    if bytes[item..end]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        ranges.push((item, end));
    }
    ranges
}

/// Parameter names of a function, with any receiver dropped so that indices
/// line up with method-call argument positions.
fn parameter_names(parameters: &str) -> Vec<String> {
    let bytes = parameters.as_bytes();
    split_top_level(bytes, 0, bytes.len())
        .into_iter()
        .map(|(start, end)| {
            let text = parameters[start..end].trim();
            text.split(':').next().unwrap_or(text).trim().to_owned()
        })
        .filter(|name| !name.ends_with("self"))
        .collect()
}

fn is_code_shaped(value: &str) -> bool {
    let mut segments = value.split('-');
    let first = segments.next().unwrap_or_default();
    let mut count = 1;
    if first.is_empty()
        || !first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return false;
    }
    for segment in segments {
        count += 1;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return false;
        }
    }
    count >= 2
}

/// Mutable state threaded through the extraction fixed point.
#[derive(Default)]
struct CodeScanState {
    codes: BTreeMap<String, BTreeSet<String>>,
    rejections: Vec<DiagnosticCodeRejection>,
    carriers: BTreeSet<(usize, String, usize)>,
    field_units: BTreeSet<usize>,
}

struct MaskedUnit<'a> {
    unit: &'a DiagnosticSourceUnit,
    masked: MaskedSource,
}

impl MaskedUnit<'_> {
    fn line(&self, offset: usize) -> usize {
        self.masked.bytes[..offset.min(self.masked.bytes.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    }

    fn in_test(&self, offset: usize) -> bool {
        self.masked
            .test_regions
            .iter()
            .any(|(start, end)| *start <= offset && offset <= *end)
    }

    fn enclosing_function(&self, offset: usize) -> Option<&MaskedFunction> {
        self.masked
            .functions
            .iter()
            .filter(|function| function.body_start <= offset && offset <= function.body_end)
            .min_by_key(|function| function.body_end - function.body_start)
    }

    fn expression_text(&self, start: usize, end: usize) -> String {
        self.unit.text[start.min(self.unit.text.len())..end.min(self.unit.text.len())]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The identifier that immediately precedes the innermost enclosing brace,
    /// or `None` when the innermost enclosing delimiter is not a brace.
    fn enclosing_brace_owner(&self, offset: usize) -> Option<Option<String>> {
        let bytes = &self.masked.bytes;
        let mut depth = 0i32;
        let mut index = offset;
        while index > 0 {
            index -= 1;
            match bytes[index] {
                b'}' | b']' | b')' => depth += 1,
                b'{' | b'[' | b'(' => {
                    if depth == 0 {
                        if bytes[index] != b'{' {
                            return Some(None);
                        }
                        let mut name_end = index;
                        while name_end > 0 && bytes[name_end - 1].is_ascii_whitespace() {
                            name_end -= 1;
                        }
                        let mut name_start = name_end;
                        while name_start > 0 && is_identifier_byte(bytes[name_start - 1]) {
                            name_start -= 1;
                        }
                        if name_start == name_end {
                            return Some(None);
                        }
                        return Some(Some(
                            String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned(),
                        ));
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        Some(None)
    }
}

/// Read every diagnostic code the workspace assigns to `Diagnostic::code`.
fn scan_diagnostic_codes(units: &[DiagnosticSourceUnit]) -> DiagnosticCodeScan {
    let masked: Vec<_> = units
        .iter()
        .map(|unit| MaskedUnit {
            unit,
            masked: mask_rust_source(&unit.text),
        })
        .collect();
    let mut state = CodeScanState::default();

    for (index, unit) in masked.iter().enumerate() {
        for offset in find_all(&unit.masked.bytes, b".code") {
            let after = skip_whitespace(&unit.masked.bytes, offset + 5, unit.masked.bytes.len());
            if unit.masked.bytes.get(after) != Some(&b'=')
                || unit.masked.bytes.get(after + 1) == Some(&b'=')
            {
                continue;
            }
            seed_code_position(&masked, index, after + 1, "diagnostic code", &mut state);
        }
        for offset in struct_field_positions(unit, "code") {
            // Only initializers inside a function body are struct literals;
            // a `code:` at item level is a struct or enum field declaration.
            if unit.enclosing_function(offset).is_none()
                || unit.enclosing_brace_owner(offset).flatten().as_deref() != Some("Diagnostic")
            {
                continue;
            }
            seed_code_position(&masked, index, offset, "diagnostic code", &mut state);
        }
    }

    let mut resolved_carriers = BTreeSet::new();
    let mut resolved_field_units = BTreeSet::new();
    loop {
        let pending_carriers: Vec<_> = state
            .carriers
            .difference(&resolved_carriers)
            .cloned()
            .collect();
        let pending_fields: Vec<_> = state
            .field_units
            .difference(&resolved_field_units)
            .copied()
            .collect();
        if pending_carriers.is_empty() && pending_fields.is_empty() {
            break;
        }
        for carrier in pending_carriers {
            resolved_carriers.insert(carrier.clone());
            resolve_carrier_calls(&masked, &carrier, &mut state);
        }
        for index in pending_fields {
            resolved_field_units.insert(index);
            resolve_code_fields(&masked, index, &mut state);
        }
    }

    state
        .rejections
        .sort_by(|left, right| (&left.path, left.line).cmp(&(&right.path, right.line)));
    state.rejections.dedup();
    DiagnosticCodeScan {
        codes: state.codes,
        rejections: state.rejections,
    }
}

fn find_all(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut index = 0;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            hits.push(index);
            index += needle.len();
        } else {
            index += 1;
        }
    }
    hits
}

/// Offsets just past `name:` for every struct-literal-shaped field of that name.
fn struct_field_positions(unit: &MaskedUnit<'_>, name: &str) -> Vec<usize> {
    let bytes = &unit.masked.bytes;
    let mut positions = Vec::new();
    for offset in find_all(bytes, name.as_bytes()) {
        if offset > 0 && (is_identifier_byte(bytes[offset - 1]) || bytes[offset - 1] == b'.') {
            continue;
        }
        let after = offset + name.len();
        if bytes.get(after) != Some(&b':') || bytes.get(after + 1) == Some(&b':') {
            continue;
        }
        positions.push(skip_whitespace(bytes, after + 1, bytes.len()));
    }
    positions
}

/// Resolve one code position, recording either its codes or a rejection.
fn seed_code_position(
    masked: &[MaskedUnit<'_>],
    index: usize,
    offset: usize,
    context: &str,
    state: &mut CodeScanState,
) {
    let unit = &masked[index];
    if unit.in_test(offset) {
        return;
    }
    let bytes = &unit.masked.bytes;
    let start = skip_whitespace(bytes, offset, bytes.len());
    let (start, end) = if identifier_at(bytes, start).as_deref() == Some("Some")
        && bytes.get(skip_whitespace(bytes, start + 4, bytes.len())) == Some(&b'(')
    {
        let open = skip_whitespace(bytes, start + 4, bytes.len());
        (open + 1, matching_delimiter(bytes, open))
    } else {
        (start, statement_end(bytes, start))
    };
    record_resolution(masked, index, start, end, context, state);
}

fn statement_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0i32;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return index;
                }
                depth -= 1;
            }
            b',' | b';' if depth == 0 => return index,
            _ => {}
        }
        index += 1;
    }
    bytes.len()
}

fn record_resolution(
    masked: &[MaskedUnit<'_>],
    index: usize,
    start: usize,
    end: usize,
    context: &str,
    state: &mut CodeScanState,
) {
    let unit = &masked[index];
    match resolve_code_expression(masked, index, start, end, 0, state) {
        Ok(codes) => {
            for code in codes {
                state
                    .codes
                    .entry(code)
                    .or_default()
                    .insert(unit.unit.crate_name.clone());
            }
        }
        Err(()) => state.rejections.push(DiagnosticCodeRejection {
            path: unit.unit.path.clone(),
            line: unit.line(start),
            context: format!("{context} is not a literal"),
            expression: unit.expression_text(start, end),
        }),
    }
}

fn resolve_code_expression(
    masked: &[MaskedUnit<'_>],
    index: usize,
    start: usize,
    end: usize,
    depth: u32,
    state: &mut CodeScanState,
) -> Result<Vec<String>, ()> {
    if depth > 4 {
        return Err(());
    }
    let unit = &masked[index];
    let bytes = &unit.masked.bytes;
    let start = skip_whitespace(bytes, start, end.min(bytes.len()));
    let mut end = end.min(bytes.len());
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if start >= end {
        return Err(());
    }

    // Rule 1: a string literal, optionally followed by a no-op conversion.
    if let Some(value) = unit.masked.literals.get(&start) {
        let literal_end = start + value.len() + 2;
        let suffix = unit
            .unit
            .text
            .get(literal_end.min(unit.unit.text.len())..end)
            .unwrap_or_default()
            .trim();
        if DIAGNOSTIC_CODE_LITERAL_SUFFIXES.contains(&suffix) {
            return Ok(vec![value.clone()]);
        }
        return Err(());
    }

    if let Some(name) = identifier_at(bytes, start) {
        let after = skip_whitespace(bytes, start + name.len(), end);

        // Rule 2: a file-local `&str` constant.
        if after == end {
            if let Some(value) = unit.masked.constants.get(&name) {
                return Ok(vec![value.clone()]);
            }
        }
        if let Some(value) = unit.masked.constants.get(&name) {
            let suffix = unit
                .unit
                .text
                .get(start + name.len()..end)
                .unwrap_or_default()
                .trim();
            if DIAGNOSTIC_CODE_LITERAL_SUFFIXES.contains(&suffix) {
                return Ok(vec![value.clone()]);
            }
        }

        // Rule 3: a bounded copy helper, read through at its first argument.
        if DIAGNOSTIC_CODE_COPY_HELPERS.contains(&name.as_str()) && bytes.get(after) == Some(&b'(')
        {
            let close = matching_delimiter(bytes, after);
            let arguments = split_top_level(bytes, after + 1, close);
            if let Some((argument_start, argument_end)) = arguments.first() {
                return resolve_code_expression(
                    masked,
                    index,
                    *argument_start,
                    *argument_end,
                    depth + 1,
                    state,
                );
            }
            return Err(());
        }

        // Rule 4: an `if`/`else` selection between code expressions.
        if name == "if" {
            let Some(then_open) = bytes[start..end].iter().position(|byte| *byte == b'{') else {
                return Err(());
            };
            let then_open = start + then_open;
            let then_close = matching_delimiter(bytes, then_open);
            let mut codes = resolve_code_expression(
                masked,
                index,
                then_open + 1,
                then_close,
                depth + 1,
                state,
            )?;
            let Some(else_open) = bytes[then_close..end].iter().position(|byte| *byte == b'{')
            else {
                return Err(());
            };
            let else_open = then_close + else_open;
            let else_close = matching_delimiter(bytes, else_open);
            codes.extend(resolve_code_expression(
                masked,
                index,
                else_open + 1,
                else_close,
                depth + 1,
                state,
            )?);
            return Ok(codes);
        }

        // Rule 5/6: the identifier `code`, bound by a parameter or a local
        // binder within the enclosing function.
        let code_suffix = unit
            .unit
            .text
            .get(start + name.len()..end)
            .unwrap_or_default()
            .trim();
        if name == "code" && DIAGNOSTIC_CODE_LITERAL_SUFFIXES.contains(&code_suffix) {
            if let Some(function) = unit.enclosing_function(start) {
                let names = parameter_names(&function.parameters);
                if let Some(position) = names.iter().position(|parameter| parameter == "code") {
                    // Call sites are only searched in the defining file, so an
                    // exported carrier could hide codes and must be rejected.
                    if function_is_exported(bytes, function) {
                        return Err(());
                    }
                    state
                        .carriers
                        .insert((index, function.name.clone(), position));
                    return Ok(Vec::new());
                }
                if let Some(initializer) = local_code_binder(unit, function, start) {
                    if let Ok(codes) = resolve_code_expression(
                        masked,
                        index,
                        initializer,
                        statement_end(bytes, initializer),
                        depth + 1,
                        state,
                    ) {
                        return Ok(codes);
                    }
                    let codes =
                        code_shaped_literals(unit, initializer, statement_end(bytes, initializer));
                    if !codes.is_empty() {
                        return Ok(codes);
                    }
                }
            }
            return Err(());
        }
    }

    // Rule 8: a field access ending in `.code`, seeded from the struct literals
    // of the same file.
    if unit.unit.text[start..end].ends_with(".code")
        && unit.unit.text[start..end]
            .bytes()
            .all(|byte| is_identifier_byte(byte) || byte == b'.')
    {
        state.field_units.insert(index);
        return Ok(Vec::new());
    }

    // Rule 7: a selector call whose arguments are all code-shaped literals.
    if let Some(open) = bytes[start..end].iter().position(|byte| *byte == b'(') {
        let open = start + open;
        let path = unit.unit.text[start..open].trim();
        if !path.is_empty()
            && path
                .bytes()
                .all(|byte| is_identifier_byte(byte) || byte == b'.')
        {
            let close = matching_delimiter(bytes, open);
            let mut codes = Vec::new();
            for (argument_start, argument_end) in split_top_level(bytes, open + 1, close) {
                let argument_start = skip_whitespace(bytes, argument_start, argument_end);
                match unit.masked.literals.get(&argument_start) {
                    Some(value) if is_code_shaped(value) => codes.push(value.clone()),
                    _ => return Err(()),
                }
            }
            if !codes.is_empty() {
                return Ok(codes);
            }
        }
    }

    Err(())
}

/// Offset of the initializer of the nearest `let`/`for` binder before `offset`
/// that binds the name `code`.
fn local_code_binder(
    unit: &MaskedUnit<'_>,
    function: &MaskedFunction,
    offset: usize,
) -> Option<usize> {
    let bytes = &unit.masked.bytes;
    let mut best = None;
    for keyword in ["let", "for"] {
        for start in find_all(&bytes[function.body_start..offset], keyword.as_bytes()) {
            let start = function.body_start + start;
            if start > 0 && is_identifier_byte(bytes[start - 1]) {
                continue;
            }
            let pattern_start = skip_whitespace(bytes, start + keyword.len(), offset);
            if pattern_start == start + keyword.len() {
                continue;
            }
            let separator = if keyword == "let" { b'=' } else { b'\0' };
            let mut cursor = pattern_start;
            let mut depth = 0i32;
            let mut binder_end = None;
            while cursor < offset {
                match bytes[cursor] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b'=' if depth == 0
                        && separator == b'='
                        && bytes.get(cursor + 1) != Some(&b'=') =>
                    {
                        binder_end = Some(cursor);
                        break;
                    }
                    b'{' | b';' => break,
                    _ => {}
                }
                if keyword == "for"
                    && depth == 0
                    && identifier_at(bytes, cursor).as_deref() == Some("in")
                    && !is_identifier_byte(bytes[cursor.saturating_sub(1)])
                {
                    binder_end = Some(cursor);
                    break;
                }
                cursor += 1;
            }
            let Some(binder_end) = binder_end else {
                continue;
            };
            let pattern = &unit.unit.text[pattern_start..binder_end];
            if !pattern
                .split(|character: char| !is_identifier_byte(character as u8))
                .any(|token| token == "code")
            {
                continue;
            }
            let initializer = skip_whitespace(
                bytes,
                binder_end + if keyword == "let" { 1 } else { 2 },
                offset,
            );
            best = Some(best.map_or(initializer, |previous: usize| previous.max(initializer)));
        }
    }
    best
}

fn code_shaped_literals(unit: &MaskedUnit<'_>, start: usize, end: usize) -> Vec<String> {
    unit.masked
        .literals
        .range(start..end)
        .map(|(_, value)| value.clone())
        .filter(|value| is_code_shaped(value))
        .collect()
}

fn resolve_carrier_calls(
    masked: &[MaskedUnit<'_>],
    carrier: &(usize, String, usize),
    state: &mut CodeScanState,
) {
    let (index, name, position) = carrier;
    let unit = &masked[*index];
    let bytes = &unit.masked.bytes;
    for offset in find_all(bytes, name.as_bytes()) {
        if offset > 0 && is_identifier_byte(bytes[offset - 1]) {
            continue;
        }
        let open = skip_whitespace(bytes, offset + name.len(), bytes.len());
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let before = unit.unit.text[..offset].trim_end();
        if before.ends_with("fn") || before.ends_with(':') {
            continue;
        }
        if unit.in_test(offset) {
            continue;
        }
        let close = matching_delimiter(bytes, open);
        let arguments = split_top_level(bytes, open + 1, close);
        let Some((argument_start, argument_end)) = arguments.get(*position) else {
            state.rejections.push(DiagnosticCodeRejection {
                path: unit.unit.path.clone(),
                line: unit.line(offset),
                context: format!("`code` argument to `{name}`"),
                expression: unit.expression_text(offset, close + 1),
            });
            continue;
        };
        record_resolution(
            masked,
            *index,
            *argument_start,
            *argument_end,
            &format!("`code` argument to `{name}`"),
            state,
        );
    }
}

fn resolve_code_fields(masked: &[MaskedUnit<'_>], index: usize, state: &mut CodeScanState) {
    let unit = &masked[index];
    for offset in struct_field_positions(unit, "code") {
        if unit.enclosing_function(offset).is_none() {
            continue;
        }
        let Some(Some(owner)) = unit.enclosing_brace_owner(offset) else {
            continue;
        };
        if owner == "Diagnostic" {
            continue;
        }
        seed_code_position(masked, index, offset, "diagnostic code field", state);
    }
}

/// Every workspace production source file, in canonical order.
fn collect_diagnostic_sources(root: &Path) -> Result<Vec<DiagnosticSourceUnit>, String> {
    let mut units = Vec::new();
    for crate_name in discover_workspace_crates(root)? {
        let directory = if crate_name == "xtask" {
            root.join("xtask/src")
        } else {
            root.join("crates").join(&crate_name).join("src")
        };
        if !directory.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        collect_files(&directory, &mut files)?;
        files.sort();
        for path in files {
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("{} is outside the workspace", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            units.push(DiagnosticSourceUnit {
                crate_name: crate_name.clone(),
                path: relative,
                text,
            });
        }
    }
    units.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(units)
}

fn render_diagnostic_index(codes: &BTreeMap<String, BTreeSet<String>>) -> String {
    let mut block = String::from("\n```text\n");
    for (code, owners) in codes {
        block.push_str(code);
        block.push(' ');
        block.push_str(&owners.iter().cloned().collect::<Vec<_>>().join(", "));
        block.push('\n');
    }
    block.push_str("```\n");
    block
}

fn render_diagnostic_exclusions() -> String {
    let mut block = String::from("\n```text\n");
    for exclusion in DIAGNOSTIC_CODE_EXCLUSIONS {
        block.push_str(exclusion.path);
        block.push_str(" `");
        block.push_str(exclusion.expression);
        block.push_str("` — ");
        block.push_str(exclusion.reason);
        block.push('\n');
    }
    block.push_str("```\n");
    block
}

fn parse_diagnostic_index(block: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut entries = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("```") {
            continue;
        }
        let (code, owners) = line
            .split_once(' ')
            .ok_or_else(|| format!("diagnostic index entry {line:?} has no owning crate"))?;
        entries.push((
            code.to_owned(),
            owners
                .split(',')
                .map(|owner| owner.trim().to_owned())
                .collect(),
        ));
    }
    Ok(entries)
}

fn reconcile_diagnostic_index(
    block: &str,
    codes: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    let entries = parse_diagnostic_index(block)?;
    let mut counts = BTreeMap::<String, u32>::new();
    let mut documented = BTreeMap::<String, Vec<String>>::new();
    for (code, owners) in entries {
        *counts.entry(code.clone()).or_default() += 1;
        documented.insert(code, owners);
    }
    let duplicated: Vec<_> = counts
        .iter()
        .filter(|(_, count)| **count != 1)
        .map(|(code, count)| format!("{code} ({count} entries)"))
        .collect();
    let documented_codes: BTreeSet<_> = documented.keys().cloned().collect();
    let source_codes: BTreeSet<_> = codes.keys().cloned().collect();
    let added: Vec<_> = source_codes
        .difference(&documented_codes)
        .cloned()
        .collect();
    let removed: Vec<_> = documented_codes
        .difference(&source_codes)
        .cloned()
        .collect();
    let owner_drift: Vec<_> = documented
        .iter()
        .filter_map(|(code, owners)| {
            let expected = codes.get(code)?;
            let expected: Vec<_> = expected.iter().cloned().collect();
            (owners != &expected).then(|| {
                format!(
                    "{code}: documented {}, source {}",
                    owners.join(", "),
                    expected.join(", ")
                )
            })
        })
        .collect();
    if added.is_empty() && removed.is_empty() && duplicated.is_empty() && owner_drift.is_empty() {
        return Ok(());
    }
    Err(format!(
        "documented diagnostic index has drifted\n  added by source: {added:?}\n  removed from source: {removed:?}\n  duplicated in the index: {duplicated:?}\n  owner drift: {owner_drift:?}\nreplace the marked block with:{}",
        render_diagnostic_index(codes)
    ))
}

fn marked_block<'a>(text: &'a str, begin: &str, end: &str, path: &Path) -> Result<&'a str, String> {
    text.split_once(begin)
        .and_then(|(_, rest)| rest.split_once(end).map(|(block, _)| block))
        .ok_or_else(|| format!("{} omits the {begin} / {end} markers", path.display()))
}

/// Every refused construction site must be a declared exclusion, and every
/// declared exclusion must still exist.
fn reconcile_diagnostic_exclusions(
    rejections: &[DiagnosticCodeRejection],
    exclusions: &[DiagnosticCodeExclusion],
) -> Result<(), String> {
    let declared: BTreeSet<_> = exclusions
        .iter()
        .map(|exclusion| (exclusion.path, exclusion.expression))
        .collect();
    let observed: BTreeSet<_> = rejections
        .iter()
        .map(|rejection| (rejection.path.as_str(), rejection.expression.as_str()))
        .collect();
    let unexcluded: Vec<_> = rejections
        .iter()
        .filter(|rejection| {
            !declared.contains(&(rejection.path.as_str(), rejection.expression.as_str()))
        })
        .map(DiagnosticCodeRejection::describe)
        .collect();
    if !unexcluded.is_empty() {
        return Err(format!(
            "diagnostic codes are constructed non-literally at sites the index does not declare\n  {}\nadd a DIAGNOSTIC_CODE_EXCLUSIONS entry with its reason, or build the code from a literal",
            unexcluded.join("\n  ")
        ));
    }
    let stale: Vec<_> = declared
        .difference(&observed)
        .map(|(path, expression)| format!("{path} `{expression}`"))
        .collect();
    if !stale.is_empty() {
        return Err(format!(
            "declared diagnostic-code exclusions no longer exist in source: {stale:?}\nremove them from DIAGNOSTIC_CODE_EXCLUSIONS and from {DIAGNOSTIC_INDEX_PATH}"
        ));
    }
    Ok(())
}

pub(crate) fn check_diagnostic_index(root: &Path) -> Result<(), String> {
    let units = collect_diagnostic_sources(root)?;
    let scan = scan_diagnostic_codes(&units);
    reconcile_diagnostic_exclusions(&scan.rejections, DIAGNOSTIC_CODE_EXCLUSIONS)?;

    let path = root.join(DIAGNOSTIC_INDEX_PATH);
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    reconcile_diagnostic_index(
        marked_block(
            &text,
            DIAGNOSTIC_INDEX_CODES_BEGIN,
            DIAGNOSTIC_INDEX_CODES_END,
            &path,
        )?,
        &scan.codes,
    )?;
    let documented_exclusions = marked_block(
        &text,
        DIAGNOSTIC_INDEX_EXCLUSIONS_BEGIN,
        DIAGNOSTIC_INDEX_EXCLUSIONS_END,
        &path,
    )?;
    let expected_exclusions = render_diagnostic_exclusions();
    if documented_exclusions != expected_exclusions {
        return Err(format!(
            "documented diagnostic-code exclusions have drifted; replace the marked block with:{expected_exclusions}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::process::Command;

    use std::collections::BTreeMap;

    use super::{
        DEVELOPMENT_SLICES, DIAGNOSTIC_CODE_EXCLUSIONS, DiagnosticCodeExclusion,
        DiagnosticCodeRejection, DiagnosticSourceUnit, EXTERNAL_DEPENDENCIES, FullRoute,
        GateClosure, GateRequest, REVIEWED_EXTERNAL_PACKAGES, architecture_root,
        check_architecture, check_diagnostic_index, collect_diagnostic_sources,
        compare_gate_closure, configure_cargo_gate_environment, expected_gate_closure,
        full_route_steps, gate_target, parse_gate_arguments, reconcile_diagnostic_exclusions,
        reconcile_diagnostic_index, render_diagnostic_index, scan_diagnostic_codes,
        validate_development_slice_metadata, workspace_root,
    };

    fn strings(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn environment_value(command: &Command, name: &str) -> Option<String> {
        command
            .get_envs()
            .find(|(candidate, _)| candidate == &OsStr::new(name))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    #[test]
    fn cargo_gate_environment_disables_network_access() {
        let mut command = Command::new("cargo");
        configure_cargo_gate_environment(&mut command);
        assert_eq!(
            environment_value(&command, "CARGO_NET_OFFLINE").as_deref(),
            Some("true")
        );
    }

    #[test]
    fn slice_metadata_is_complete_and_coherent() {
        validate_development_slice_metadata().expect("complete slice metadata");
        let names: BTreeSet<_> = DEVELOPMENT_SLICES.iter().map(|slice| slice.name).collect();
        for required in [
            "input", "syntax", "hir", "semantic", "flow", "machine", "artifact", "backend",
            "testing", "cli",
        ] {
            assert!(
                names.contains(required),
                "missing required slice {required}"
            );
        }
    }

    #[test]
    fn expected_closures_are_transitive_and_scoped() {
        let syntax = gate_target("syntax").expect("syntax target");
        let syntax_closure = expected_gate_closure(&syntax).expect("syntax closure");
        assert_eq!(
            syntax_closure.workspace,
            strings(&[
                "wrela-build-model",
                "wrela-diagnostics",
                "wrela-format",
                "wrela-source",
                "wrela-syntax",
            ])
        );
        assert_eq!(
            syntax_closure.external,
            strings(&[
                "tinyvec@1.12.0",
                "tinyvec_macros@0.1.1",
                "unicode-ident@1.0.18",
                "unicode-normalization@0.1.24",
            ])
        );

        let cli =
            expected_gate_closure(&gate_target("cli").expect("cli target")).expect("cli closure");
        assert!(cli.workspace.contains("wrela-backend"));
        assert!(cli.workspace.contains("wrela-test-protocol"));
        assert!(!cli.workspace.contains("xtask"));
        assert!(cli.external.contains("serde_json@1.0.150"));

        let all =
            expected_gate_closure(&gate_target("all").expect("all target")).expect("all closure");
        assert!(all.workspace.contains("wrela-test-protocol"));
        assert!(all.workspace.contains("xtask"));
        assert!(all.external.contains("serde_json@1.0.150"));
    }

    #[test]
    fn toml_parser_requirements_and_spec_versions_are_exact() {
        let toml = EXTERNAL_DEPENDENCIES
            .iter()
            .find(|dependency| {
                dependency.owner == "wrela-package-loader" && dependency.name == "toml"
            })
            .expect("direct toml dependency contract");
        assert_eq!(toml.requirement, "=0.9.9");
        assert!(!toml.default_features);
        assert_eq!(toml.features, ["parse", "std"]);

        let parser = EXTERNAL_DEPENDENCIES
            .iter()
            .find(|dependency| {
                dependency.owner == "wrela-package-loader" && dependency.name == "toml_parser"
            })
            .expect("direct toml_parser dependency contract");
        assert_eq!(parser.requirement, "=1.0.5");
        assert!(!parser.default_features);
        assert_eq!(parser.features, ["alloc", "std"]);

        for (name, version) in [
            ("equivalent", "1.0.2"),
            ("hashbrown", "0.17.1"),
            ("indexmap", "2.14.0"),
            ("serde_core", "1.0.228"),
            ("serde_spanned", "1.1.1"),
            ("toml", "0.9.9+spec-1.0.0"),
            ("toml_datetime", "0.7.5+spec-1.1.0"),
            ("toml_parser", "1.0.5+spec-1.0.0"),
            ("toml_writer", "1.1.2+spec-1.1.0"),
            ("winnow", "0.7.15"),
        ] {
            assert_eq!(
                REVIEWED_EXTERNAL_PACKAGES
                    .iter()
                    .find(|package| package.name == name)
                    .map(|package| package.version),
                Some(version),
                "resolved {name} package identity must retain its spec metadata"
            );
        }
    }

    #[test]
    fn closure_drift_is_rejected_precisely() {
        let expected = expected_gate_closure(&gate_target("syntax").expect("syntax target"))
            .expect("syntax closure");
        let mut actual = expected.clone();
        actual.workspace.insert("wrela-backend".to_owned());
        actual.external.remove("unicode-ident@1.0.18");
        let error = compare_gate_closure("syntax", &expected, &actual)
            .expect_err("closure drift must fail");
        assert!(error.contains("unexpected workspace: [\"wrela-backend\"]"));
        assert!(error.contains("missing external: [\"unicode-ident@1.0.18\"]"));

        compare_gate_closure(
            "empty",
            &GateClosure {
                workspace: BTreeSet::new(),
                external: BTreeSet::new(),
            },
            &GateClosure {
                workspace: BTreeSet::new(),
                external: BTreeSet::new(),
            },
        )
        .expect("identical closure");
    }

    #[test]
    fn gate_arguments_reject_filters_and_arbitrary_extras() {
        assert_eq!(
            parse_gate_arguments(vec!["syntax".to_owned()]).expect("fast gate"),
            GateRequest {
                target: "syntax".to_owned(),
                full: false,
            }
        );
        assert_eq!(
            parse_gate_arguments(vec!["syntax".to_owned(), "--full".to_owned()])
                .expect("full gate"),
            GateRequest {
                target: "syntax".to_owned(),
                full: true,
            }
        );
        for invalid in [
            vec![],
            vec!["--full"],
            vec!["syntax", "parser_filter"],
            vec!["syntax", "--", "parser_filter"],
            vec!["syntax", "--full", "--full"],
        ] {
            assert!(
                parse_gate_arguments(invalid.into_iter().map(str::to_owned).collect()).is_err(),
                "accepted invalid gate arguments"
            );
        }
    }

    #[test]
    fn full_routes_are_explicit_without_executing_native_work() {
        assert_eq!(
            gate_target("syntax").expect("syntax target").full_route,
            FullRoute::None
        );
        assert_eq!(
            gate_target("artifact").expect("artifact target").full_route,
            FullRoute::ArtifactNative
        );
        assert_eq!(
            gate_target("wrela-backend")
                .expect("backend crate")
                .full_route,
            FullRoute::BackendNative
        );
        assert_eq!(
            gate_target("testing").expect("testing target").full_route,
            FullRoute::Distribution
        );

        let artifact = gate_target("artifact").expect("artifact target");
        let artifact_closure = expected_gate_closure(&artifact).expect("artifact closure");
        let artifact_steps = full_route_steps(&artifact, &artifact_closure);
        assert_eq!(artifact_steps.len(), 1);
        assert!(artifact_steps[0].arguments.contains(&"test".to_owned()));
        assert!(
            artifact_steps[0]
                .arguments
                .contains(&"wrela-codegen-llvm/llvm".to_owned())
        );
        assert!(
            artifact_steps[0]
                .arguments
                .iter()
                .any(|argument| argument == "wrela-codegen-llvm")
        );

        let syntax = gate_target("syntax").expect("syntax target");
        let syntax_closure = expected_gate_closure(&syntax).expect("syntax closure");
        assert!(full_route_steps(&syntax, &syntax_closure).is_empty());
    }

    #[test]
    fn architecture_root_accepts_only_an_explicit_canonical_workspace() {
        let root = workspace_root().expect("workspace root");
        assert_eq!(
            architecture_root(&["--root".to_owned(), root.display().to_string()])
                .expect("explicit workspace"),
            root
        );
        assert!(architecture_root(&["--root".to_owned(), "relative".to_owned()]).is_err());
        assert!(architecture_root(&["unexpected".to_owned()]).is_err());
    }

    #[test]
    fn workspace_matches_dependency_contracts() {
        let root = workspace_root().expect("workspace root");
        check_architecture(&root).expect("architecture contract");
    }

    fn unit(path: &str, text: &str) -> DiagnosticSourceUnit {
        DiagnosticSourceUnit {
            crate_name: "wrela-example".to_owned(),
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    fn scanned(units: &[DiagnosticSourceUnit]) -> Vec<String> {
        let scan = scan_diagnostic_codes(units);
        assert!(
            scan.rejections.is_empty(),
            "unexpected rejections: {:?}",
            scan.rejections
        );
        scan.codes.keys().cloned().collect()
    }

    #[test]
    fn extraction_reads_every_admitted_code_carrier_form() {
        // Rule 1 (literal), rule 2 (file-local `&str` constant), rule 3 (bounded
        // copy helper), rule 4 (`if`/`else` selection).
        let direct = unit(
            "crates/wrela-example/src/direct.rs",
            r#"
const PENDING: &str = "example-const-code";
fn one(request: &Request) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, span, "message");
    diagnostic.code = Some("example-direct-code".to_owned());
    diagnostic.code = Some(PENDING.to_owned());
    diagnostic.code = Some(copy_static_analysis_text("example-copied-code", limit)?);
    diagnostic.code = Some(if flag {
        "example-then-code"
    } else {
        "example-else-code"
    });
    diagnostic
}
#[cfg(test)]
mod tests {
    #[test]
    fn ignored() {
        let mut diagnostic = Diagnostic::error(Category::TYPE, span, "message");
        diagnostic.code = Some("example-test-only-code".to_owned());
    }
}
"#,
        );
        assert_eq!(
            scanned(std::slice::from_ref(&direct)),
            [
                "example-const-code",
                "example-copied-code",
                "example-direct-code",
                "example-else-code",
                "example-then-code",
            ]
        );

        // Rule 5 (carrier parameter named `code`, resolved at same-file call
        // sites, transitively through a second carrier).
        let carrier = unit(
            "crates/wrela-example/src/carrier.rs",
            r#"
fn emit(source: Span, code: &'static str, message: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, source, message);
    diagnostic.code = Some(code.to_owned());
    diagnostic
}
fn relay(source: Span, code: &'static str) -> Diagnostic {
    emit(source, code, "relayed")
}
fn call_sites() {
    emit(span, "example-carrier-code", "direct call");
    relay(span, "example-relayed-code");
}
"#,
        );
        assert_eq!(
            scanned(std::slice::from_ref(&carrier)),
            ["example-carrier-code", "example-relayed-code"]
        );

        // Rule 6 (`let`/`for` binder whose initializer selects among code-shaped
        // literals) and rule 7 (selector call whose arguments are all
        // code-shaped literals).
        let selection = unit(
            "crates/wrela-example/src/selection.rs",
            r#"
fn emit(source: Span, code: &'static str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, source, "message");
    diagnostic.code = Some(code.to_owned());
    diagnostic
}
fn selected(form: Form) -> Diagnostic {
    let (code, message) = match form {
        Form::Function => ("example-function-code", "a function needs more work"),
        Form::Method => ("example-method-code", "a method needs more work"),
    };
    let _ = message;
    emit(span, code)
}
fn selector(form: Form) -> Diagnostic {
    emit(span, form.code("example-selector-a", "example-selector-b"))
}
"#,
        );
        assert_eq!(
            scanned(std::slice::from_ref(&selection)),
            [
                "example-function-code",
                "example-method-code",
                "example-selector-a",
                "example-selector-b",
            ]
        );

        // Rule 8 (struct field named `code`, seeded from every struct literal in
        // the same file that initializes such a field).
        let field = unit(
            "crates/wrela-example/src/field.rs",
            r#"
struct EscapeDiagnostic {
    code: &'static str,
    message: &'static str,
}
fn emit(source: Span, code: &'static str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::SYNTAX, source, "message");
    diagnostic.code = Some(code.to_owned());
    diagnostic
}
fn scan(decoded: DecodedEscape) -> Diagnostic {
    emit(span, decoded.code)
}
fn decode() -> EscapeDiagnostic {
    EscapeDiagnostic {
        code: "example-field-code",
        message: "invalid escape",
    }
}
"#,
        );
        assert_eq!(
            scanned(std::slice::from_ref(&field)),
            ["example-field-code"]
        );
    }

    #[test]
    fn extraction_records_the_owning_crate_of_every_code() {
        let scan = scan_diagnostic_codes(&[
            DiagnosticSourceUnit {
                crate_name: "wrela-first".to_owned(),
                path: "crates/wrela-first/src/lib.rs".to_owned(),
                text: "fn f() { diagnostic.code = Some(\"example-shared\".to_owned()); }"
                    .to_owned(),
            },
            DiagnosticSourceUnit {
                crate_name: "wrela-second".to_owned(),
                path: "crates/wrela-second/src/lib.rs".to_owned(),
                text: "fn f() { diagnostic.code = Some(\"example-shared\".to_owned()); \
                       diagnostic.code = Some(\"example-owned\".to_owned()); }"
                    .to_owned(),
            },
        ]);
        assert!(scan.rejections.is_empty(), "{:?}", scan.rejections);
        assert_eq!(
            scan.codes
                .get("example-shared")
                .map(|owners| owners.iter().cloned().collect::<Vec<_>>()),
            Some(vec!["wrela-first".to_owned(), "wrela-second".to_owned()])
        );
        assert_eq!(
            scan.codes
                .get("example-owned")
                .map(|owners| owners.iter().cloned().collect::<Vec<_>>()),
            Some(vec!["wrela-second".to_owned()])
        );
    }

    #[test]
    fn extraction_fails_closed_on_a_non_literal_construction_site() {
        let scan = scan_diagnostic_codes(&[unit(
            "crates/wrela-example/src/lint.rs",
            "fn f() { diagnostic.code = Some(lint.as_str().to_owned()); }",
        )]);
        assert!(scan.codes.is_empty(), "{:?}", scan.codes);
        assert_eq!(
            scan.rejections
                .iter()
                .map(DiagnosticCodeRejection::describe)
                .collect::<Vec<_>>(),
            [
                "crates/wrela-example/src/lint.rs:1 diagnostic code is not a literal: \
                 `lint.as_str().to_owned()`"
                    .to_owned()
            ]
        );
        assert_eq!(
            scan.rejections[0].path,
            "crates/wrela-example/src/lint.rs".to_owned()
        );
        assert_eq!(
            scan.rejections[0].expression,
            "lint.as_str().to_owned()".to_owned()
        );
    }

    #[test]
    fn extraction_fails_closed_on_an_exported_code_carrier() {
        let private = unit(
            "crates/wrela-example/src/private.rs",
            r#"
fn emit(source: Span, code: &'static str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, source, "message");
    diagnostic.code = Some(code.to_owned());
    diagnostic
}
fn call() { emit(span, "example-private-carrier"); }
"#,
        );
        assert_eq!(
            scanned(std::slice::from_ref(&private)),
            ["example-private-carrier"]
        );

        // The same carrier, exported: its call sites may live in another file,
        // so it must be refused rather than searched same-file only.
        let exported = unit(
            "crates/wrela-example/src/exported.rs",
            r#"
pub(crate) fn emit(source: Span, code: &'static str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(Category::TYPE, source, "message");
    diagnostic.code = Some(code.to_owned());
    diagnostic
}
fn call() { emit(span, "example-exported-carrier"); }
"#,
        );
        let scan = scan_diagnostic_codes(std::slice::from_ref(&exported));
        assert!(scan.codes.is_empty(), "{:?}", scan.codes);
        assert_eq!(
            scan.rejections
                .iter()
                .map(DiagnosticCodeRejection::describe)
                .collect::<Vec<_>>(),
            [
                "crates/wrela-example/src/exported.rs:4 diagnostic code is not a literal: \
                 `code.to_owned()`"
                    .to_owned()
            ]
        );
    }

    fn index_codes(entries: &[(&str, &str)]) -> BTreeMap<String, BTreeSet<String>> {
        entries
            .iter()
            .map(|(code, owner)| ((*code).to_owned(), BTreeSet::from([(*owner).to_owned()])))
            .collect()
    }

    #[test]
    fn reconciliation_accepts_an_exact_index_and_names_drift_in_each_direction() {
        let codes = index_codes(&[
            ("example-first", "wrela-example"),
            ("example-second", "wrela-example"),
        ]);
        let exact = render_diagnostic_index(&codes);
        assert_eq!(
            exact,
            "\n```text\nexample-first wrela-example\nexample-second wrela-example\n```\n"
        );
        reconcile_diagnostic_index(&exact, &codes).expect("exact index");

        let added =
            reconcile_diagnostic_index("\n```text\nexample-first wrela-example\n```\n", &codes)
                .expect_err("added code must fail");
        assert!(
            added.contains("added by source: [\"example-second\"]"),
            "{added}"
        );

        let removed = reconcile_diagnostic_index(
            "\n```text\nexample-first wrela-example\nexample-second wrela-example\n\
             example-third wrela-example\n```\n",
            &codes,
        )
        .expect_err("removed code must fail");
        assert!(
            removed.contains("removed from source: [\"example-third\"]"),
            "{removed}"
        );

        let duplicated = reconcile_diagnostic_index(
            "\n```text\nexample-first wrela-example\nexample-first wrela-example\n\
             example-second wrela-example\n```\n",
            &codes,
        )
        .expect_err("duplicate code must fail");
        assert!(
            duplicated.contains("duplicated in the index: [\"example-first (2 entries)\"]"),
            "{duplicated}"
        );

        let reowned = reconcile_diagnostic_index(
            "\n```text\nexample-first wrela-other\nexample-second wrela-example\n```\n",
            &codes,
        )
        .expect_err("owner drift must fail");
        assert!(
            reowned.contains(
                "owner drift: [\"example-first: documented wrela-other, source wrela-example\"]"
            ),
            "{reowned}"
        );
    }

    #[test]
    fn workspace_diagnostic_codes_have_only_the_declared_non_literal_exclusions() {
        let root = workspace_root().expect("workspace root");
        let units = collect_diagnostic_sources(&root).expect("diagnostic sources");
        let scan = scan_diagnostic_codes(&units);
        assert_eq!(
            scan.rejections
                .iter()
                .map(|rejection| (rejection.path.clone(), rejection.expression.clone()))
                .collect::<Vec<_>>(),
            DIAGNOSTIC_CODE_EXCLUSIONS
                .iter()
                .map(|exclusion| (exclusion.path.to_owned(), exclusion.expression.to_owned()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            scan.codes
                .values()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>(),
            strings(&["wrela-hir-lower", "wrela-sema", "wrela-syntax"])
        );
    }

    #[test]
    fn exclusion_reconciliation_rejects_undeclared_and_stale_non_literal_sites() {
        let rejection = DiagnosticCodeRejection {
            path: "crates/wrela-example/src/lint.rs".to_owned(),
            line: 7,
            context: "diagnostic code is not a literal".to_owned(),
            expression: "lint.as_str().to_owned()".to_owned(),
        };
        let declared = [DiagnosticCodeExclusion {
            path: "crates/wrela-example/src/lint.rs",
            expression: "lint.as_str().to_owned()",
            reason: "lint findings carry the registered lint name",
        }];
        reconcile_diagnostic_exclusions(std::slice::from_ref(&rejection), &declared)
            .expect("declared exclusion");

        let undeclared = reconcile_diagnostic_exclusions(std::slice::from_ref(&rejection), &[])
            .expect_err("undeclared non-literal site must fail");
        assert!(
            undeclared.contains(
                "crates/wrela-example/src/lint.rs:7 diagnostic code is not a literal: \
                 `lint.as_str().to_owned()`"
            ),
            "{undeclared}"
        );

        let stale =
            reconcile_diagnostic_exclusions(&[], &declared).expect_err("stale exclusion must fail");
        assert!(
            stale.contains(
                "declared diagnostic-code exclusions no longer exist in source: \
                 [\"crates/wrela-example/src/lint.rs `lint.as_str().to_owned()`\"]"
            ),
            "{stale}"
        );
    }

    #[test]
    fn documented_diagnostic_index_matches_workspace_sources() {
        let root = workspace_root().expect("workspace root");
        check_diagnostic_index(&root).expect("diagnostic index");
    }
}
