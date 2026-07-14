//! Maintainer-only toolchain build, architecture, and distribution tasks.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const HELP: &str = "\
xtask commands:
  architecture-check  enforce crate dependency contracts
  slices              list focused development slices
  check <slice|crate> [...]  cargo check --all-targets for one boundary
  test <slice|crate> [...]   cargo test for one boundary
  lint <slice|crate>         clippy -D warnings for one boundary
  llvm                fetch, verify, and build pinned LLVM/LLD (next milestone)
  dist                assemble and validate an atomic toolchain bundle (next milestone)
";

struct DevelopmentSlice {
    name: &'static str,
    description: &'static str,
    packages: &'static [&'static str],
}

const DEVELOPMENT_SLICES: &[DevelopmentSlice] = &[
    DevelopmentSlice {
        name: "input",
        description: "build identity, source, package graph, and package loading",
        packages: &[
            "wrela-build-model",
            "wrela-source",
            "wrela-package",
            "wrela-package-loader",
        ],
    },
    DevelopmentSlice {
        name: "syntax",
        description: "lossless parsing and AST-only formatting",
        packages: &["wrela-syntax", "wrela-format"],
    },
    DevelopmentSlice {
        name: "hir",
        description: "normalized HIR model and package-wide name lowering",
        packages: &["wrela-hir", "wrela-hir-lower"],
    },
    DevelopmentSlice {
        name: "semantic",
        description: "whole-image analysis, semantic linting, and SemanticWir",
        packages: &[
            "wrela-sema",
            "wrela-lint",
            "wrela-semantic-wir",
            "wrela-semantic-lower",
        ],
    },
    DevelopmentSlice {
        name: "flow",
        description: "FlowWir lowering, optimization, and canonical codec",
        packages: &[
            "wrela-flow-wir",
            "wrela-flow-lower",
            "wrela-flow-opt",
            "wrela-flow-wir-codec",
        ],
    },
    DevelopmentSlice {
        name: "machine",
        description: "runtime ABI, AArch64 target binding, and MachineWir lowering",
        packages: &[
            "wrela-runtime-abi",
            "wrela-target",
            "wrela-machine-wir",
            "wrela-machine-lower",
        ],
    },
    DevelopmentSlice {
        name: "artifact",
        description: "AArch64 COFF emission, EFI link inspection, and report assembly",
        packages: &[
            "wrela-codegen-llvm",
            "wrela-lld-sys",
            "wrela-link-efi",
            "wrela-image-report",
        ],
    },
    DevelopmentSlice {
        name: "frontend",
        description: "input through sealed semantic analysis and SemanticWir",
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
    },
    DevelopmentSlice {
        name: "ir",
        description: "three named IRs, lowering, optimization, codec, target, and runtime ABI",
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
    },
    DevelopmentSlice {
        name: "backend",
        description: "backend protocol through COFF, EFI linking, and image report",
        packages: &[
            "wrela-backend-protocol",
            "wrela-codegen-llvm",
            "wrela-lld-sys",
            "wrela-link-efi",
            "wrela-image-report",
            "wrela-backend",
        ],
    },
    DevelopmentSlice {
        name: "testing",
        description: "test plan/protocol, verified toolchain, and full-image runner",
        packages: &[
            "wrela-test-model",
            "wrela-test-protocol",
            "wrela-target",
            "wrela-toolchain",
            "wrela-test-runner",
        ],
    },
    DevelopmentSlice {
        name: "cli",
        description: "public driver and CLI surface",
        packages: &["wrela-driver", "wrela-compiler", "wrela-cli"],
    },
    DevelopmentSlice {
        name: "all",
        description: "entire workspace",
        packages: &[],
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

type FeatureContract = (&'static str, &'static [&'static str]);
type CrateFeatureContract = (&'static str, &'static [FeatureContract]);

const EXTERNAL_DEPENDENCIES: &[ExternalDependencyContract] = &[
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
        owner: "wrela-hir",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "^0.1.25",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-package",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "^0.1.25",
        optional: false,
        default_features: true,
        features: &[],
    },
    ExternalDependencyContract {
        owner: "wrela-source",
        name: "unicode-normalization",
        kind: DependencySection::Normal,
        requirement: "^0.1.25",
        optional: false,
        default_features: true,
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
        dev: &[],
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
        dev: &[],
    },
    CrateContract {
        name: "wrela-codegen-llvm",
        directory: "crates/wrela-codegen-llvm",
        normal: &["wrela-build-model", "wrela-machine-wir", "wrela-target"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-compiler",
        directory: "crates/wrela-compiler",
        normal: &[
            "wrela-backend",
            "wrela-build-model",
            "wrela-driver",
            "wrela-flow-lower",
            "wrela-flow-wir-codec",
            "wrela-format",
            "wrela-hir-lower",
            "wrela-image-report",
            "wrela-lint",
            "wrela-package",
            "wrela-package-loader",
            "wrela-sema",
            "wrela-semantic-lower",
            "wrela-syntax",
            "wrela-target",
            "wrela-test-model",
            "wrela-test-runner",
            "wrela-toolchain",
        ],
        dev: &[],
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
            "wrela-test-model",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-lower",
        directory: "crates/wrela-flow-lower",
        normal: &["wrela-diagnostics", "wrela-flow-wir", "wrela-semantic-wir"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-opt",
        directory: "crates/wrela-flow-opt",
        normal: &["wrela-build-model", "wrela-flow-wir"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-wir",
        directory: "crates/wrela-flow-wir",
        normal: &["wrela-build-model", "wrela-source"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-flow-wir-codec",
        directory: "crates/wrela-flow-wir-codec",
        normal: &["wrela-build-model", "wrela-flow-wir"],
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
        normal: &["wrela-build-model"],
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
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-machine-wir",
        directory: "crates/wrela-machine-wir",
        normal: &[
            "wrela-build-model",
            "wrela-runtime-abi",
            "wrela-source",
            "wrela-target",
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
            "wrela-source",
            "wrela-target",
            "wrela-test-model",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-semantic-lower",
        directory: "crates/wrela-semantic-lower",
        normal: &["wrela-sema", "wrela-semantic-wir"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-semantic-wir",
        directory: "crates/wrela-semantic-wir",
        normal: &["wrela-build-model", "wrela-source"],
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
        normal: &["wrela-test-model"],
        dev: &[],
    },
    CrateContract {
        name: "wrela-test-runner",
        directory: "crates/wrela-test-runner",
        normal: &[
            "wrela-build-model",
            "wrela-target",
            "wrela-test-model",
            "wrela-toolchain",
        ],
        dev: &[],
    },
    CrateContract {
        name: "wrela-toolchain",
        directory: "crates/wrela-toolchain",
        normal: &["wrela-build-model"],
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
        Some("slices") => {
            print_slices();
            ExitCode::SUCCESS
        }
        Some("architecture-check") => {
            match workspace_root().and_then(|root| check_architecture(&root)) {
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
        Some(command @ ("check" | "test" | "lint")) => {
            let Some(slice) = arguments.next() else {
                eprintln!("error: xtask {command} requires a slice\n");
                print_slices();
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
        Some(command @ ("llvm" | "dist")) => {
            eprintln!("error: xtask command `{command}` is scaffolded but not implemented");
            ExitCode::FAILURE
        }
        Some(command) => {
            eprintln!("error: unknown xtask command `{command}`\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

fn print_slices() {
    println!("development slices:");
    for slice in DEVELOPMENT_SLICES {
        println!("  {:<10} {}", slice.name, slice.description);
    }
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
            command.args(["check", "--all-targets", "--locked"]);
        }
        "test" => {
            command.args(["test", "--no-fail-fast", "--locked"]);
        }
        "lint" => {
            command.args(["clippy", "--all-targets", "--no-deps", "--locked"]);
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

fn check_architecture(root: &Path) -> Result<(), String> {
    let workspace_names: BTreeSet<_> = CONTRACTS.iter().map(|contract| contract.name).collect();
    let mut slice_names = BTreeSet::new();
    for slice in DEVELOPMENT_SLICES {
        if !slice_names.insert(slice.name) {
            return Err(format!("duplicate development slice {}", slice.name));
        }
        let packages: BTreeSet<_> = slice.packages.iter().copied().collect();
        if packages.len() != slice.packages.len()
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
    }
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
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root)
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
            "toolchain/llvm.lock.toml",
            &[
                "version = \"22.1.3\"",
                "projects = [\"lld\"]",
                "targets = [\"AArch64\"]",
            ],
        ),
        (
            "toolchain/emulation.lock.toml",
            &[
                "version = \"10.0.11\"",
                "system_targets = [\"aarch64-softmmu\"]",
                "machine_contract = \"virt-10.0\"",
                "cpu_contract = \"cortex-a57\"",
                "source_path = \"pc-bios/edk2-aarch64-code.fd.bz2\"",
                "source_path = \"pc-bios/edk2-arm-vars.fd.bz2\"",
            ],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::{check_architecture, workspace_root};

    #[test]
    fn workspace_matches_dependency_contracts() {
        let root = workspace_root().expect("workspace root");
        check_architecture(&root).expect("architecture contract");
    }
}
