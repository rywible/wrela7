use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "src/archive.rs"]
mod archive;

const MAX_TOOL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LLVM_LIBRARIES: usize = 4096;
const MAX_SHIM_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const PINNED_LLVM_VERSION: &str = "22.1.3";
const MACOS_DEPLOYMENT_TARGET: &str = "13.0";

fn main() {
    println!("cargo:rerun-if-changed=src/lld_shim.cpp");
    for variable in [
        "LLVM_SYS_221_PREFIX",
        "WRELA_LLVM_PREFIX",
        "WRELA_LLVM_CXX",
        "WRELA_LLVM_AR",
        "WRELA_LLVM_SYSROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "CXX",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if env::var_os("CARGO_FEATURE_BUNDLED_LLD").is_none() {
        return;
    }
    if let Err(error) = build_bundled_lld() {
        panic!("cannot build the pinned bundled LLD boundary: {error}");
    }
}

fn build_bundled_lld() -> Result<(), String> {
    let prefix = exact_prefix()?;
    let target_os = required_env("CARGO_CFG_TARGET_OS")?;
    if !matches!(target_os.as_str(), "macos" | "linux") {
        return Err(format!("unsupported bundled-LLD host {target_os}"));
    }
    let executable_suffix = "";
    let llvm_config = prefix.join(format!("bin/llvm-config{executable_suffix}"));
    exact_regular_file(&llvm_config, "llvm-config")?;
    let version = tool_text(&llvm_config, &["--version"])?;
    if version.trim() != PINNED_LLVM_VERSION {
        return Err(format!(
            "llvm-config reported {:?}, expected {PINNED_LLVM_VERSION}",
            version.trim()
        ));
    }
    let include = exact_directory(&prefix.join("include"), "LLVM include directory")?;
    let lib = exact_directory(&prefix.join("lib"), "LLVM library directory")?;
    let reported_include = canonical_reported_directory(
        &tool_text(&llvm_config, &["--includedir"])?,
        "llvm-config include directory",
    )?;
    let reported_lib = canonical_reported_directory(
        &tool_text(&llvm_config, &["--libdir"])?,
        "llvm-config library directory",
    )?;
    if reported_include != include || reported_lib != lib {
        return Err("llvm-config escaped the verified prefix include/lib directories".to_owned());
    }

    let cxx = exact_tool("WRELA_LLVM_CXX", "CXX")?;
    let ar = exact_tool("WRELA_LLVM_AR", "AR")?;
    let out = exact_directory(
        &PathBuf::from(required_env_os("OUT_DIR")?),
        "Cargo output directory",
    )?;
    let object_suffix = ".o";
    let archive_name = "libwrela_lld_shim.a";
    let object = out.join(format!("wrela_lld_shim{object_suffix}"));
    let archive = out.join(archive_name);
    let verification_archive = out.join("libwrela_lld_shim.verify.a");
    let source = fs::canonicalize("src/lld_shim.cpp")
        .map_err(|error| format!("cannot canonicalize the LLD shim source: {error}"))?;
    let mut compile = Command::new(&cxx);
    compile.env_clear().args([
        OsString::from("-std=c++17"),
        OsString::from("-fno-exceptions"),
        OsString::from("-fno-rtti"),
        OsString::from("-fvisibility=hidden"),
        OsString::from("-fno-common"),
        OsString::from("-DNDEBUG"),
        OsString::from("-Werror"),
        OsString::from("-Wall"),
        OsString::from("-Wextra"),
        OsString::from("-isystem"),
        include.as_os_str().to_owned(),
    ]);
    if target_os == "macos" {
        let deployment_target = required_env("MACOSX_DEPLOYMENT_TARGET")?;
        if deployment_target != MACOS_DEPLOYMENT_TARGET {
            return Err(format!(
                "MACOSX_DEPLOYMENT_TARGET must be exactly {MACOS_DEPLOYMENT_TARGET}, got {deployment_target:?}"
            ));
        }
        let sysroot = exact_directory(
            &PathBuf::from(required_env_os("WRELA_LLVM_SYSROOT")?),
            "macOS SDK",
        )?;
        compile.args([
            OsString::from(format!("-mmacosx-version-min={MACOS_DEPLOYMENT_TARGET}")),
            OsString::from("-isysroot"),
            sysroot.into_os_string(),
        ]);
    }
    compile.args([
        OsString::from("-c"),
        source.into_os_string(),
        OsString::from("-o"),
        object.as_os_str().to_owned(),
    ]);
    run(&mut compile, "C++ shim compilation")?;

    create_deterministic_archive(&ar, &archive, &object)?;
    create_deterministic_archive(&ar, &verification_archive, &object)?;
    let archive_bytes = read_bounded_archive(&archive, "deterministic LLD shim archive")?;
    let verification_bytes =
        read_bounded_archive(&verification_archive, "verification LLD shim archive")?;
    if archive_bytes != verification_bytes {
        return Err(
            "authenticated archiver did not produce byte-identical normalized archives".to_owned(),
        );
    }
    fs::remove_file(&verification_archive)
        .map_err(|error| format!("cannot remove verification LLD shim archive: {error}"))?;
    exact_regular_file(&archive, "compiled LLD shim archive")?;

    for name in ["lldCOFF", "lldCommon"] {
        exact_regular_file(
            &lib.join(format!("lib{name}.a")),
            "required LLD static archive",
        )?;
    }
    let llvm_libraries = tool_text(&llvm_config, &["--libnames", "--link-static"])?;
    let llvm_libraries = static_library_names(&llvm_libraries, &lib, &target_os)?;
    let system_libraries = tool_text(&llvm_config, &["--system-libs", "--link-static"])?;
    let system_libraries = system_library_names(&system_libraries, &target_os)?;

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=wrela_lld_shim");
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=lldCOFF");
    println!("cargo:rustc-link-lib=static=lldCommon");
    for library in llvm_libraries {
        println!("cargo:rustc-link-lib=static={library}");
    }
    for library in system_libraries {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
    match target_os.as_str() {
        "macos" => println!("cargo:rustc-link-lib=dylib=c++"),
        "linux" => println!("cargo:rustc-link-lib=dylib=stdc++"),
        other => return Err(format!("unsupported bundled-LLD host {other}")),
    }
    Ok(())
}

fn exact_prefix() -> Result<PathBuf, String> {
    let llvm = PathBuf::from(required_env_os("LLVM_SYS_221_PREFIX")?);
    let wrela = PathBuf::from(required_env_os("WRELA_LLVM_PREFIX")?);
    let llvm = exact_directory(&llvm, "LLVM_SYS_221_PREFIX")?;
    let wrela = exact_directory(&wrela, "WRELA_LLVM_PREFIX")?;
    if llvm != wrela {
        return Err("LLVM_SYS_221_PREFIX and WRELA_LLVM_PREFIX disagree".to_owned());
    }
    Ok(llvm)
}

fn exact_tool(primary: &str, fallback: &str) -> Result<PathBuf, String> {
    let primary_value = env::var_os(primary);
    let fallback_value = env::var_os(fallback);
    let primary_path = primary_value
        .as_ref()
        .map(|value| resolve_explicit_tool(Path::new(value), primary))
        .transpose()?;
    let fallback_path = fallback_value
        .as_ref()
        .map(|value| resolve_explicit_tool(Path::new(value), fallback))
        .transpose()?;
    match (primary_path, fallback_path) {
        (Some(primary_path), Some(fallback_path)) if primary_path != fallback_path => Err(format!(
            "{primary} and {fallback} resolve to different authenticated tools"
        )),
        (Some(path), _) | (_, Some(path)) => Ok(path),
        (None, None) => Err(format!(
            "required environment variable {primary} or {fallback} is absent"
        )),
    }
}

fn resolve_explicit_tool(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!("{label} must be an absolute normalized path"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.is_file() && metadata.len() != 0 {
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
        if canonical == path {
            return Ok(canonical);
        }
        return Err(format!("{label} path {} is not canonical", path.display()));
    }
    if !metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} {} is not a nonempty regular file or a local tool alias",
            path.display()
        ));
    }
    let target = fs::read_link(path)
        .map_err(|error| format!("cannot read {label} alias {}: {error}", path.display()))?;
    if target.is_absolute()
        || target.components().count() != 1
        || !matches!(
            target.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(format!(
            "{label} {} is not a one-component local tool alias",
            path.display()
        ));
    }
    let resolved = path
        .parent()
        .ok_or_else(|| format!("{label} has no parent directory"))?
        .join(target);
    exact_regular_file(&resolved, label)?;
    Ok(resolved)
}

fn create_deterministic_archive(ar: &Path, output: &Path, object: &Path) -> Result<(), String> {
    match fs::remove_file(output) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot remove stale LLD shim archive {}: {error}",
                output.display()
            ));
        }
    }
    let mut command = Command::new(ar);
    command.env_clear().env("ZERO_AR_DATE", "1").args([
        OsString::from("rcs"),
        output.as_os_str().to_owned(),
        object.as_os_str().to_owned(),
    ]);
    run(&mut command, "deterministic shim archive")?;
    let mut bytes = read_bounded_archive(output, "LLD shim archive for normalization")?;
    archive::normalize_archive(&mut bytes)?;
    fs::write(output, bytes)
        .map_err(|error| format!("cannot write normalized LLD shim archive: {error}"))
}

fn read_bounded_archive(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SHIM_ARCHIVE_BYTES {
        return Err(format!(
            "{label} {} is not a nonempty regular file within {MAX_SHIM_ARCHIVE_BYTES} bytes",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} changed length while being read"));
    }
    Ok(bytes)
}

fn exact_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "{label} {} is not a nonempty regular file",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("{label} path {} is not canonical", path.display()));
    }
    Ok(())
}

fn exact_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{label} {} is not a real directory",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("{label} path {} is not canonical", path.display()));
    }
    Ok(canonical)
}

fn canonical_reported_directory(value: &str, label: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(format!("{label} is empty or multiline"));
    }
    exact_directory(Path::new(value), label)
}

fn static_library_names(
    output: &str,
    directory: &Path,
    target_os: &str,
) -> Result<Vec<String>, String> {
    let mut libraries = Vec::new();
    for token in output.split_ascii_whitespace() {
        if libraries.len() >= MAX_LLVM_LIBRARIES {
            return Err(format!(
                "llvm-config returned more than {MAX_LLVM_LIBRARIES} static libraries"
            ));
        }
        let name = if target_os == "windows" {
            token
                .strip_suffix(".lib")
                .ok_or_else(|| format!("invalid LLVM static library name {token:?}"))?
        } else {
            token
                .strip_prefix("lib")
                .and_then(|value| value.strip_suffix(".a"))
                .ok_or_else(|| format!("invalid LLVM static library name {token:?}"))?
        };
        valid_library_name(name)?;
        exact_regular_file(&directory.join(token), "LLVM static archive")?;
        libraries.push(name.to_owned());
    }
    if libraries.is_empty() {
        return Err("llvm-config returned no static LLVM libraries".to_owned());
    }
    Ok(libraries)
}

fn system_library_names(output: &str, target_os: &str) -> Result<Vec<String>, String> {
    let mut libraries = Vec::new();
    for token in output.split_ascii_whitespace() {
        if libraries.len() >= MAX_LLVM_LIBRARIES {
            return Err(format!(
                "llvm-config returned more than {MAX_LLVM_LIBRARIES} system libraries"
            ));
        }
        let name = if target_os == "windows" {
            token
                .strip_suffix(".lib")
                .ok_or_else(|| format!("invalid LLVM system library {token:?}"))?
        } else {
            token
                .strip_prefix("-l")
                .ok_or_else(|| format!("invalid LLVM system library flag {token:?}"))?
        };
        valid_library_name(name)?;
        libraries.push(name.to_owned());
    }
    Ok(libraries)
}

fn valid_library_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'.'))
    {
        Err(format!("invalid native library name {name:?}"))
    } else {
        Ok(())
    }
}

fn tool_text(tool: &Path, arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new(tool);
    command.env_clear().args(arguments);
    let output = run(&mut command, "llvm-config query")?;
    String::from_utf8(output.stdout).map_err(|_| "llvm-config output is not UTF-8".to_owned())
}

fn run(command: &mut Command, label: &str) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    if output.stdout.len() > MAX_TOOL_OUTPUT_BYTES || output.stderr.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(format!(
            "{label} output exceeds {MAX_TOOL_OUTPUT_BYTES} bytes"
        ));
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{label} failed with {}: {stderr}", output.status));
    }
    Ok(output)
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("required environment variable {name} is absent or invalid"))
}

fn required_env_os(name: &str) -> Result<OsString, String> {
    env::var_os(name).ok_or_else(|| format!("required environment variable {name} is absent"))
}
