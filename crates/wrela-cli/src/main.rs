//! Thin public `wrela` command-line adapter. Compilation policy and terminal-
//! independent outcomes live in `wrela-driver`.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::path::{Component, Path};
use std::process::ExitCode;

use wrela_driver::{
    Command, CommandOutput, DiagnosticOptions, DriverError, TestSelection, WorkspaceSelection,
};

const HELP: &str = "\
wrela — build sealed AArch64 machine images

USAGE:
    wrela check <wrela.toml> <IMAGE> [--target aarch64-qemu-virt-uefi]
                [--profile <PROFILE>] [--warnings-as-errors]
                [--maximum-diagnostics <COUNT>]
    wrela build <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
                [--target aarch64-qemu-virt-uefi] [--profile <PROFILE>]
                [--warnings-as-errors] [--maximum-diagnostics <COUNT>]
    wrela test <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
               [--comptime | --integration | --images | --name-contains <TEXT>]
               [--target aarch64-qemu-virt-uefi] [--profile <PROFILE>]
               [--warnings-as-errors] [--maximum-diagnostics <COUNT>]
    wrela lint <wrela.toml> <IMAGE> [--target aarch64-qemu-virt-uefi]
               [--profile <PROFILE>] [--warnings-as-errors]
               [--maximum-diagnostics <COUNT>]
    wrela format [--check] <wrela.toml> <FILE>...
    wrela doctor
    wrela version

EXIT STATUS:
    0  command completed successfully
    1  command was unsuccessful or execution failed
    2  command invocation was invalid
";
const MAX_WORKSPACE_PATH_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_PATH_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_ARGUMENTS: usize = MAX_FORMAT_FILES + 16;
const MAX_COMMAND_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FORMAT_FILES: usize = 1_000_000;
const MAX_TEST_FILTER_BYTES: usize = 4096;
const MAX_SELECTION_BYTES: usize = wrela_build_model::MAX_PROFILE_ATOM_BYTES;
const MAXIMUM_DIAGNOSTICS: u32 = 100_000;
const MAX_RENDERED_ARGUMENT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ExitCategory {
    Success = 0,
    Unsuccessful = 1,
    Usage = 2,
}

impl From<ExitCategory> for ExitCode {
    fn from(category: ExitCategory) -> Self {
        Self::from(category as u8)
    }
}

fn main() -> ExitCode {
    run().into()
}

fn run() -> ExitCategory {
    let parsed = decode_arguments(
        env::args_os().skip(1),
        MAX_COMMAND_ARGUMENTS,
        MAX_COMMAND_LINE_BYTES,
    )
    .and_then(|arguments| parse(arguments.into_iter()));
    match parsed {
        Ok(Parsed::Help) => {
            write_stdout(HELP).map_or_else(output_write_failed, |()| ExitCategory::Success)
        }
        Ok(Parsed::Version) => {
            let version = format!("wrela {}\n", env!("CARGO_PKG_VERSION"));
            write_stdout(&version).map_or_else(output_write_failed, |()| ExitCategory::Success)
        }
        Ok(Parsed::Command(command)) => execute(command),
        Err(error) => {
            write_stderr(&format!("error: {error}\n\n{HELP}"));
            ExitCategory::Usage
        }
    }
}

fn write_stdout(rendered: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_all(rendered.as_bytes())?;
    output.flush()
}

fn write_stderr(rendered: &str) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    let _ = output.write_all(rendered.as_bytes());
    let _ = output.flush();
}

fn output_write_failed(error: io::Error) -> ExitCategory {
    write_stderr(&format!("error: cannot write command output: {error}\n"));
    ExitCategory::Unsuccessful
}

fn write_driver_error(error: &DriverError) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    if let Some(report) = error.diagnostic_report() {
        let rendered = report.render_text();
        let _ = output.write_all(rendered.as_bytes());
    }
    let _ = writeln!(output, "error: {error}");
    let _ = output.flush();
}

fn decode_arguments(
    arguments: impl Iterator<Item = OsString>,
    maximum_arguments: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, String> {
    let mut decoded = Vec::new();
    let mut total_bytes = 0usize;
    for argument in arguments {
        if decoded.len() >= maximum_arguments {
            return Err(format!(
                "command line exceeds the {maximum_arguments}-argument limit"
            ));
        }
        total_bytes = total_bytes
            .checked_add(argument.as_encoded_bytes().len())
            .ok_or_else(|| "command-line byte length overflow".to_owned())?;
        if total_bytes > maximum_bytes {
            return Err(format!(
                "command line exceeds the {maximum_bytes}-byte limit"
            ));
        }
        let argument = argument
            .into_string()
            .map_err(|_| "command arguments must be valid UTF-8".to_owned())?;
        decoded
            .try_reserve(1)
            .map_err(|_| "cannot allocate command arguments".to_owned())?;
        decoded.push(argument);
    }
    Ok(decoded)
}

fn execute(command: Command) -> ExitCategory {
    let command = match command {
        Command::Doctor => Command::Doctor,
        command => {
            let base = match env::current_dir() {
                Ok(base) => base,
                Err(error) => {
                    write_stderr(&format!(
                        "error: cannot determine the command working directory: {error}\n"
                    ));
                    return ExitCategory::Unsuccessful;
                }
            };
            match resolve_command_paths(command, &base) {
                Ok(command) => command,
                Err(error) => {
                    write_stderr(&format!("error: {error}\n"));
                    return ExitCategory::Usage;
                }
            }
        }
    };
    match wrela_compiler::run(&command) {
        Ok(output) => {
            let category = output_category(&output);
            write_stdout(&output.render_text()).map_or_else(output_write_failed, |()| category)
        }
        Err(error) => {
            let category = driver_error_category(&error);
            write_driver_error(&error);
            category
        }
    }
}

fn output_category(output: &CommandOutput) -> ExitCategory {
    match output {
        CommandOutput::Doctor(outcome) if !outcome.is_healthy() => ExitCategory::Unsuccessful,
        CommandOutput::Test(outcome) if !outcome.report().passed() => ExitCategory::Unsuccessful,
        CommandOutput::Format(outcome) if outcome.check_only() && outcome.changed_files() != 0 => {
            ExitCategory::Unsuccessful
        }
        CommandOutput::Doctor(_)
        | CommandOutput::Check(_)
        | CommandOutput::Build(_)
        | CommandOutput::Test(_)
        | CommandOutput::Format(_)
        | CommandOutput::Lint(_) => ExitCategory::Success,
    }
}

fn driver_error_category(error: &DriverError) -> ExitCategory {
    if matches!(error, DriverError::InvalidCommand(_)) {
        ExitCategory::Usage
    } else {
        ExitCategory::Unsuccessful
    }
}

fn resolve_command_paths(command: Command, base: &Path) -> Result<Command, String> {
    let base = normalize_absolute(base, MAX_OUTPUT_PATH_BYTES, true)?;
    let resolve = |path: PathBuf, maximum_bytes: usize| {
        let path = if path.is_absolute() {
            path
        } else {
            let combined_bytes = base
                .as_os_str()
                .as_encoded_bytes()
                .len()
                .checked_add(1)
                .and_then(|bytes| bytes.checked_add(path.as_os_str().as_encoded_bytes().len()))
                .ok_or_else(|| "command path length overflow".to_owned())?;
            if combined_bytes > maximum_bytes {
                return Err(format!("command path exceeds {maximum_bytes} bytes"));
            }
            let mut combined = PathBuf::new();
            combined
                .try_reserve(combined_bytes)
                .map_err(|_| "cannot allocate command path".to_owned())?;
            combined.push(&base);
            combined.push(path);
            combined
        };
        normalize_absolute(&path, maximum_bytes, false)
    };
    let resolve_workspace = |mut workspace: WorkspaceSelection| {
        workspace.manifest = resolve(workspace.manifest, MAX_WORKSPACE_PATH_BYTES)?;
        workspace.lockfile = resolve(workspace.lockfile, MAX_WORKSPACE_PATH_BYTES)?;
        Ok::<_, String>(workspace)
    };
    match command {
        Command::Doctor => Ok(Command::Doctor),
        Command::Check {
            workspace,
            diagnostics,
        } => Ok(Command::Check {
            workspace: resolve_workspace(workspace)?,
            diagnostics,
        }),
        Command::Build {
            workspace,
            output_directory,
            diagnostics,
        } => Ok(Command::Build {
            workspace: resolve_workspace(workspace)?,
            output_directory: resolve(output_directory, MAX_OUTPUT_PATH_BYTES)?,
            diagnostics,
        }),
        Command::Test {
            workspace,
            output_directory,
            selection,
            diagnostics,
        } => Ok(Command::Test {
            workspace: resolve_workspace(workspace)?,
            output_directory: resolve(output_directory, MAX_OUTPUT_PATH_BYTES)?,
            selection,
            diagnostics,
        }),
        Command::Format {
            manifest,
            files,
            check_only,
        } => {
            let mut resolved_files = Vec::new();
            resolved_files
                .try_reserve_exact(files.len())
                .map_err(|_| "cannot allocate resolved source paths".to_owned())?;
            for file in files {
                resolved_files.push(resolve(file, MAX_WORKSPACE_PATH_BYTES)?);
            }
            Ok(Command::Format {
                manifest: resolve(manifest, MAX_WORKSPACE_PATH_BYTES)?,
                files: resolved_files,
                check_only,
            })
        }
        Command::Lint {
            workspace,
            diagnostics,
        } => Ok(Command::Lint {
            workspace: resolve_workspace(workspace)?,
            diagnostics,
        }),
    }
}

fn normalize_absolute(
    path: &Path,
    maximum_bytes: usize,
    allow_filesystem_root: bool,
) -> Result<PathBuf, String> {
    let path_bytes = path.as_os_str().as_encoded_bytes().len();
    if path_bytes > maximum_bytes {
        return Err(format!("command path exceeds {maximum_bytes} bytes"));
    }
    if !path.is_absolute() {
        return Err("command path is not absolute".to_owned());
    }
    let mut output = PathBuf::new();
    output
        .try_reserve(path_bytes)
        .map_err(|_| "cannot allocate normalized command path".to_owned())?;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                output.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(output.components().next_back(), Some(Component::Normal(_))) {
                    return Err("command path escapes its filesystem root".to_owned());
                }
                output.pop();
            }
        }
    }
    if !output.is_absolute()
        || (!allow_filesystem_root && output.components().count() <= 1)
        || output
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("command path is not a normalized file path".to_owned());
    }
    Ok(output)
}

enum Parsed {
    Help,
    Version,
    Command(Command),
}

fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Parsed, String> {
    match arguments.next().as_deref() {
        None => Ok(Parsed::Help),
        Some("help" | "-h" | "--help") => no_extra_arguments(arguments).map(|()| Parsed::Help),
        Some("version" | "-V" | "--version") => {
            no_extra_arguments(arguments).map(|()| Parsed::Version)
        }
        Some("doctor") => no_extra_arguments(arguments).map(|()| Parsed::Command(Command::Doctor)),
        Some("check") => {
            let (workspace, diagnostics) = workspace_diagnostic_arguments("check", &mut arguments)?;
            Ok(Parsed::Command(Command::Check {
                workspace,
                diagnostics,
            }))
        }
        Some("build") => {
            let (workspace, output_directory, diagnostics) = build_arguments(&mut arguments)?;
            Ok(Parsed::Command(Command::Build {
                workspace,
                output_directory,
                diagnostics,
            }))
        }
        Some("test") => {
            let (workspace, output_directory, selection, diagnostics) =
                test_arguments(&mut arguments)?;
            Ok(Parsed::Command(Command::Test {
                workspace,
                output_directory,
                selection,
                diagnostics,
            }))
        }
        Some("lint") => {
            let (workspace, diagnostics) = workspace_diagnostic_arguments("lint", &mut arguments)?;
            Ok(Parsed::Command(Command::Lint {
                workspace,
                diagnostics,
            }))
        }
        Some("format") => {
            let mut check_only = false;
            let mut positional = Vec::new();
            let mut parse_options = true;
            for argument in arguments {
                if parse_options && argument == "--" {
                    parse_options = false;
                    continue;
                }
                if parse_options && argument == "--check" {
                    if check_only {
                        return Err("duplicate option `--check`".to_owned());
                    }
                    check_only = true;
                    continue;
                }
                if parse_options && argument.starts_with('-') {
                    return Err(unexpected_argument(&argument));
                }
                if !format_positional_has_capacity(positional.len(), MAX_FORMAT_FILES) {
                    return Err(format!(
                        "`format` accepts at most {MAX_FORMAT_FILES} source files"
                    ));
                }
                positional
                    .try_reserve(1)
                    .map_err(|_| "cannot allocate format arguments".to_owned())?;
                positional.push(argument);
            }
            let mut positional = positional.into_iter();
            let manifest = positional
                .next()
                .ok_or_else(|| "`format` requires a manifest path".to_owned())?;
            let manifest = path_argument("manifest", manifest, MAX_WORKSPACE_PATH_BYTES)?;
            let file_count = positional.len();
            if file_count == 0 {
                return Err("`format` requires at least one source file".to_owned());
            }
            let mut files = Vec::new();
            files
                .try_reserve_exact(file_count)
                .map_err(|_| "cannot allocate format source paths".to_owned())?;
            for file in positional {
                files.push(path_argument(
                    "source file",
                    file,
                    MAX_WORKSPACE_PATH_BYTES,
                )?);
            }
            Ok(Parsed::Command(Command::Format {
                manifest,
                files,
                check_only,
            }))
        }
        Some(command) => Err(format!("unknown command `{}`", rendered_argument(command))),
    }
}

const fn format_positional_has_capacity(
    current_positional_arguments: usize,
    maximum_source_files: usize,
) -> bool {
    // The positional vector contains one manifest followed by source files.
    // Before a push, `maximum_source_files` existing entries therefore still
    // leave room for the final source file.
    current_positional_arguments <= maximum_source_files
}

fn workspace_diagnostic_arguments(
    command: &str,
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(WorkspaceSelection, DiagnosticOptions), String> {
    let mut workspace = workspace_arguments(command, arguments)?;
    let mut diagnostics = diagnostics();
    let mut saw_target = false;
    let mut saw_profile = false;
    let mut saw_warnings_as_errors = false;
    let mut saw_maximum = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--target" if !saw_target => {
                let target = arguments
                    .next()
                    .ok_or_else(|| "`--target` requires a target name".to_owned())?;
                select_target(&mut workspace, target)?;
                saw_target = true;
            }
            "--profile" if !saw_profile => {
                let profile = arguments
                    .next()
                    .ok_or_else(|| "`--profile` requires a profile name".to_owned())?;
                workspace.profile = selection_argument("profile", profile)?;
                saw_profile = true;
            }
            "--warnings-as-errors" if !saw_warnings_as_errors => {
                diagnostics.warnings_as_errors = true;
                saw_warnings_as_errors = true;
            }
            "--maximum-diagnostics" if !saw_maximum => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "`--maximum-diagnostics` requires a count".to_owned())?;
                diagnostics.maximum_diagnostics = maximum_diagnostics(&value)?;
                saw_maximum = true;
            }
            "--target" | "--profile" | "--warnings-as-errors" | "--maximum-diagnostics" => {
                return Err(format!("duplicate option `{argument}`"));
            }
            _ => return Err(unexpected_argument(&argument)),
        }
    }
    Ok((workspace, diagnostics))
}

fn build_arguments(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(WorkspaceSelection, PathBuf, DiagnosticOptions), String> {
    let mut workspace = workspace_arguments("build", arguments)?;
    let mut output_directory = None;
    let mut diagnostics = diagnostics();
    let mut saw_target = false;
    let mut saw_profile = false;
    let mut saw_warnings_as_errors = false;
    let mut saw_maximum = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--target" if !saw_target => {
                let target = arguments
                    .next()
                    .ok_or_else(|| "`--target` requires a target name".to_owned())?;
                select_target(&mut workspace, target)?;
                saw_target = true;
            }
            "--profile" if !saw_profile => {
                let profile = arguments
                    .next()
                    .ok_or_else(|| "`--profile` requires a profile name".to_owned())?;
                workspace.profile = selection_argument("profile", profile)?;
                saw_profile = true;
            }
            "--warnings-as-errors" if !saw_warnings_as_errors => {
                diagnostics.warnings_as_errors = true;
                saw_warnings_as_errors = true;
            }
            "--maximum-diagnostics" if !saw_maximum => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "`--maximum-diagnostics` requires a count".to_owned())?;
                diagnostics.maximum_diagnostics = maximum_diagnostics(&value)?;
                saw_maximum = true;
            }
            "--target" | "--profile" | "--warnings-as-errors" | "--maximum-diagnostics" => {
                return Err(format!("duplicate option `{argument}`"));
            }
            value if value.starts_with('-') => return Err(unexpected_argument(&argument)),
            _ if output_directory.is_some() => return Err(unexpected_argument(&argument)),
            _ => {
                output_directory = Some(path_argument(
                    "output directory",
                    argument,
                    MAX_OUTPUT_PATH_BYTES,
                )?);
            }
        }
    }
    Ok((
        workspace,
        output_directory.unwrap_or_else(|| PathBuf::from("build/wrela")),
        diagnostics,
    ))
}

fn test_arguments(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<
    (
        WorkspaceSelection,
        PathBuf,
        TestSelection,
        DiagnosticOptions,
    ),
    String,
> {
    let mut workspace = workspace_arguments("test", arguments)?;
    let mut output_directory = None;
    let mut selection = None;
    let mut diagnostics = diagnostics();
    let mut saw_target = false;
    let mut saw_profile = false;
    let mut saw_warnings_as_errors = false;
    let mut saw_maximum = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--target" if !saw_target => {
                let target = arguments
                    .next()
                    .ok_or_else(|| "`--target` requires a target name".to_owned())?;
                select_target(&mut workspace, target)?;
                saw_target = true;
            }
            "--comptime" => set_test_selection(&mut selection, TestSelection::Comptime)?,
            "--integration" => set_test_selection(&mut selection, TestSelection::Integration)?,
            "--images" => set_test_selection(&mut selection, TestSelection::Images)?,
            "--name-contains" => {
                let filter = arguments
                    .next()
                    .ok_or_else(|| "`--name-contains` requires text".to_owned())?;
                if filter.is_empty() || filter.len() > MAX_TEST_FILTER_BYTES {
                    return Err(format!(
                        "`--name-contains` text must contain 1 to {MAX_TEST_FILTER_BYTES} bytes"
                    ));
                }
                set_test_selection(&mut selection, TestSelection::NameContains(filter))?;
            }
            "--profile" if !saw_profile => {
                let profile = arguments
                    .next()
                    .ok_or_else(|| "`--profile` requires a profile name".to_owned())?;
                workspace.profile = selection_argument("profile", profile)?;
                saw_profile = true;
            }
            "--warnings-as-errors" if !saw_warnings_as_errors => {
                diagnostics.warnings_as_errors = true;
                saw_warnings_as_errors = true;
            }
            "--maximum-diagnostics" if !saw_maximum => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "`--maximum-diagnostics` requires a count".to_owned())?;
                diagnostics.maximum_diagnostics = maximum_diagnostics(&value)?;
                saw_maximum = true;
            }
            "--target" | "--profile" | "--warnings-as-errors" | "--maximum-diagnostics" => {
                return Err(format!("duplicate option `{argument}`"));
            }
            value if value.starts_with('-') => {
                return Err(unexpected_argument(&argument));
            }
            _ if output_directory.is_some() => {
                return Err(unexpected_argument(&argument));
            }
            _ => {
                output_directory = Some(path_argument(
                    "output directory",
                    argument,
                    MAX_OUTPUT_PATH_BYTES,
                )?);
            }
        }
    }
    Ok((
        workspace,
        output_directory.unwrap_or_else(|| PathBuf::from("build/wrela-tests")),
        selection.unwrap_or(TestSelection::All),
        diagnostics,
    ))
}

fn set_test_selection(
    selection: &mut Option<TestSelection>,
    candidate: TestSelection,
) -> Result<(), String> {
    if selection.replace(candidate).is_some() {
        Err("test selection options are mutually exclusive".to_owned())
    } else {
        Ok(())
    }
}

fn workspace_arguments(
    command: &str,
    arguments: &mut impl Iterator<Item = String>,
) -> Result<WorkspaceSelection, String> {
    let manifest = required_path(command, arguments)?;
    let image = arguments
        .next()
        .ok_or_else(|| format!("`{command}` requires an image name"))?;
    let image = selection_argument("image", image)?;
    let lockfile = manifest
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("wrela.lock");
    Ok(WorkspaceSelection {
        manifest,
        lockfile,
        image,
        target: wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi(),
        profile: "development".to_owned(),
    })
}

fn select_target(workspace: &mut WorkspaceSelection, value: String) -> Result<(), String> {
    let value = selection_argument("target", value)?;
    let supported = wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi();
    if value != supported.as_str() {
        return Err(format!(
            "unsupported target `{}`; revision 0.1 supports only `{}`",
            rendered_argument(&value),
            supported.as_str()
        ));
    }
    workspace.target = supported;
    Ok(())
}

fn required_path(
    command: &str,
    arguments: &mut impl Iterator<Item = String>,
) -> Result<PathBuf, String> {
    let argument = arguments
        .next()
        .ok_or_else(|| format!("`{command}` requires a manifest path"))?;
    path_argument("manifest", argument, MAX_WORKSPACE_PATH_BYTES)
}

fn diagnostics() -> DiagnosticOptions {
    DiagnosticOptions::default()
}

fn maximum_diagnostics(value: &str) -> Result<u32, String> {
    let value = value
        .parse::<u32>()
        .map_err(|_| "`--maximum-diagnostics` must be an unsigned 32-bit integer".to_owned())?;
    if value == 0 {
        Err("`--maximum-diagnostics` must be greater than zero".to_owned())
    } else if value > MAXIMUM_DIAGNOSTICS {
        Err(format!(
            "`--maximum-diagnostics` must not exceed {MAXIMUM_DIAGNOSTICS}"
        ))
    } else {
        Ok(value)
    }
}

fn selection_argument(kind: &str, value: String) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_SELECTION_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        Err(format!(
            "{kind} name must be a nonempty atom of at most {MAX_SELECTION_BYTES} UTF-8 bytes"
        ))
    } else {
        Ok(value)
    }
}

fn path_argument(kind: &str, value: String, maximum_bytes: usize) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!("{kind} path must not be empty"));
    }
    if value.len() > maximum_bytes {
        return Err(format!("{kind} path exceeds {maximum_bytes} UTF-8 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{kind} path contains a control character"));
    }
    Ok(PathBuf::from(value))
}

fn unexpected_argument(argument: &str) -> String {
    format!("unexpected argument `{}`", rendered_argument(argument))
}

fn rendered_argument(argument: &str) -> String {
    const TRUNCATION_MARKER: &str = "…";
    let mut rendered = String::with_capacity(MAX_RENDERED_ARGUMENT_BYTES);
    for character in argument.chars().flat_map(char::escape_debug) {
        let next_bytes = character.len_utf8();
        if rendered.len().saturating_add(next_bytes) > MAX_RENDERED_ARGUMENT_BYTES {
            let maximum_prefix = MAX_RENDERED_ARGUMENT_BYTES - TRUNCATION_MARKER.len();
            while rendered.len() > maximum_prefix {
                rendered.pop();
            }
            rendered.push_str(TRUNCATION_MARKER);
            return rendered;
        }
        rendered.push(character);
    }
    rendered
}

fn no_extra_arguments(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    arguments
        .next()
        .map_or(Ok(()), |argument| Err(unexpected_argument(&argument)))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::{
        ExitCategory, Parsed, decode_arguments, driver_error_category,
        format_positional_has_capacity, maximum_diagnostics, output_category, parse, path_argument,
        rendered_argument, resolve_command_paths, selection_argument,
    };

    #[test]
    fn operating_system_arguments_are_utf8_and_resource_bounded_before_parsing() {
        assert_eq!(
            decode_arguments(
                [OsString::from("check"), OsString::from("wrela.toml")].into_iter(),
                2,
                16,
            )
            .expect("bounded UTF-8 arguments"),
            ["check", "wrela.toml"]
        );
        assert!(
            decode_arguments(
                [OsString::from("one"), OsString::from("two")].into_iter(),
                1,
                16,
            )
            .is_err()
        );
        assert!(decode_arguments([OsString::from("oversized")].into_iter(), 1, 8).is_err());
        assert!(decode_arguments([OsString::from("12345678")].into_iter(), 1, 8).is_ok());
        assert!(decode_arguments([OsString::from("12345678")].into_iter(), 1, 7).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_operating_system_arguments_are_structured_usage_errors() {
        assert!(decode_arguments([OsString::from_vec(vec![0xff])].into_iter(), 1, 1).is_err());
    }

    #[test]
    fn unhealthy_doctor_output_is_a_command_failure() {
        let missing = wrela_driver::DoctorCheck::new(
            "private-backend".to_owned(),
            PathBuf::from("/toolchain/bin/wrela-backend"),
            false,
        )
        .expect("valid doctor check");
        let output = wrela_driver::CommandOutput::Doctor(
            wrela_driver::DoctorOutcome::new(vec![missing]).expect("valid doctor outcome"),
        );
        assert_eq!(output_category(&output), ExitCategory::Unsuccessful);
        assert_eq!(
            driver_error_category(&wrela_driver::DriverError::InvalidCommand(
                "bad selection".to_owned()
            )),
            ExitCategory::Usage
        );
        assert_eq!(
            driver_error_category(&wrela_driver::DriverError::Toolchain(
                "missing installation".to_owned()
            )),
            ExitCategory::Unsuccessful
        );
    }

    #[test]
    fn parses_aarch64_build_selection() {
        let parsed = parse(
            [
                "build".to_owned(),
                "wrela.toml".to_owned(),
                "appliance".to_owned(),
            ]
            .into_iter(),
        )
        .expect("valid command");
        let Parsed::Command(wrela_driver::Command::Build { workspace, .. }) = parsed else {
            panic!("expected build command");
        };
        assert_eq!(workspace.target.as_str(), "aarch64-qemu-virt-uefi");
        assert_eq!(workspace.lockfile, std::path::Path::new("wrela.lock"));
    }

    #[test]
    fn resolves_every_command_path_against_one_explicit_base() {
        let Parsed::Command(command) = parse(
            [
                "build".to_owned(),
                "project/./wrela.toml".to_owned(),
                "appliance".to_owned(),
                "../artifacts".to_owned(),
            ]
            .into_iter(),
        )
        .expect("valid command") else {
            panic!("expected build command")
        };
        let command = resolve_command_paths(command, Path::new("/work/checkout"))
            .expect("absolute command paths");
        let wrela_driver::Command::Build {
            workspace,
            output_directory,
            ..
        } = command
        else {
            panic!("expected build command")
        };
        assert_eq!(
            workspace.manifest,
            PathBuf::from("/work/checkout/project/wrela.toml")
        );
        assert_eq!(
            workspace.lockfile,
            PathBuf::from("/work/checkout/project/wrela.lock")
        );
        assert_eq!(output_directory, PathBuf::from("/work/artifacts"));
    }

    #[test]
    fn path_resolution_rejects_root_escape() {
        let Parsed::Command(command) = parse(
            [
                "check".to_owned(),
                "../../../../../../wrela.toml".to_owned(),
                "appliance".to_owned(),
            ]
            .into_iter(),
        )
        .expect("syntactically valid command") else {
            panic!("expected check command")
        };
        assert!(resolve_command_paths(command, Path::new("/work/checkout")).is_err());
    }

    #[test]
    fn filesystem_root_is_a_valid_resolution_base_but_not_a_final_file_path() {
        let Parsed::Command(command) = parse(
            ["check", "wrela.toml", "appliance"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("syntactically valid command") else {
            panic!("expected check command")
        };
        let wrela_driver::Command::Check { workspace, .. } =
            resolve_command_paths(command, Path::new("/")).expect("root-relative command paths")
        else {
            panic!("expected check command")
        };
        assert_eq!(workspace.manifest, PathBuf::from("/wrela.toml"));
        assert_eq!(workspace.lockfile, PathBuf::from("/wrela.lock"));
        assert!(
            super::normalize_absolute(Path::new("/"), super::MAX_WORKSPACE_PATH_BYTES, false)
                .is_err()
        );
    }

    #[test]
    fn path_and_rendered_argument_values_are_independently_bounded() {
        assert!(path_argument("manifest", "abc".to_owned(), 3).is_ok());
        assert!(path_argument("manifest", "abcd".to_owned(), 3).is_err());
        assert!(path_argument("manifest", "line\nbreak".to_owned(), 32).is_err());

        let rendered = rendered_argument(&format!("{}\n", "x".repeat(1024)));
        assert!(rendered.len() <= super::MAX_RENDERED_ARGUMENT_BYTES);
        assert!(rendered.ends_with('…'));
        assert!(!rendered.contains('\n'));
        assert_eq!(rendered_argument("line\nbreak"), "line\\nbreak");

        assert!(selection_argument("image", "x".repeat(super::MAX_SELECTION_BYTES)).is_ok());
        assert!(selection_argument("image", "x".repeat(super::MAX_SELECTION_BYTES + 1)).is_err());
        assert!(selection_argument("profile", "two words".to_owned()).is_err());

        assert!(format_positional_has_capacity(2, 2));
        assert!(!format_positional_has_capacity(3, 2));
        assert_eq!(
            maximum_diagnostics(&super::MAXIMUM_DIAGNOSTICS.to_string()),
            Ok(super::MAXIMUM_DIAGNOSTICS)
        );
        assert!(maximum_diagnostics(&(super::MAXIMUM_DIAGNOSTICS + 1).to_string()).is_err());
    }

    #[test]
    fn check_accepts_an_explicit_profile_and_diagnostic_policy() {
        let Parsed::Command(wrela_driver::Command::Check {
            workspace,
            diagnostics,
        }) = parse(
            [
                "check",
                "wrela.toml",
                "appliance",
                "--target",
                "aarch64-qemu-virt-uefi",
                "--profile",
                "release-sealed",
                "--warnings-as-errors",
                "--maximum-diagnostics",
                "17",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid check options")
        else {
            panic!("expected check command")
        };
        assert_eq!(workspace.target.as_str(), "aarch64-qemu-virt-uefi");
        assert_eq!(workspace.profile, "release-sealed");
        assert!(diagnostics.warnings_as_errors);
        assert_eq!(diagnostics.maximum_diagnostics, 17);
    }

    #[test]
    fn build_and_lint_share_the_pinned_target_profile_and_diagnostic_policy() {
        let Parsed::Command(wrela_driver::Command::Build {
            workspace,
            output_directory,
            diagnostics,
        }) = parse(
            [
                "build",
                "wrela.toml",
                "appliance",
                "--profile",
                "release-sealed",
                "--target",
                "aarch64-qemu-virt-uefi",
                "artifacts/image",
                "--warnings-as-errors",
                "--maximum-diagnostics",
                "23",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid build policy")
        else {
            panic!("expected build command")
        };
        assert_eq!(workspace.target.as_str(), "aarch64-qemu-virt-uefi");
        assert_eq!(workspace.profile, "release-sealed");
        assert_eq!(output_directory, PathBuf::from("artifacts/image"));
        assert!(diagnostics.warnings_as_errors);
        assert_eq!(diagnostics.maximum_diagnostics, 23);

        let Parsed::Command(wrela_driver::Command::Lint {
            workspace,
            diagnostics,
        }) = parse(
            [
                "lint",
                "wrela.toml",
                "appliance",
                "--target",
                "aarch64-qemu-virt-uefi",
                "--profile",
                "development",
                "--maximum-diagnostics",
                "29",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid lint policy")
        else {
            panic!("expected lint command")
        };
        assert_eq!(workspace.target.as_str(), "aarch64-qemu-virt-uefi");
        assert_eq!(workspace.profile, "development");
        assert!(!diagnostics.warnings_as_errors);
        assert_eq!(diagnostics.maximum_diagnostics, 29);

        for arguments in [
            &[
                "build",
                "wrela.toml",
                "appliance",
                "--target",
                "x86_64-hosted",
            ][..],
            &[
                "lint",
                "wrela.toml",
                "appliance",
                "--target",
                "aarch64-qemu-virt-uefi",
                "--target",
            ][..],
        ] {
            assert!(parse(arguments.iter().copied().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn check_rejects_duplicate_or_zero_diagnostic_options() {
        assert!(
            parse(
                [
                    "check",
                    "wrela.toml",
                    "appliance",
                    "--profile",
                    "one",
                    "--profile",
                    "two",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .is_err()
        );
        assert!(
            parse(
                [
                    "check",
                    "wrela.toml",
                    "appliance",
                    "--maximum-diagnostics",
                    "0",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .is_err()
        );
        assert!(
            parse(
                [
                    "check",
                    "wrela.toml",
                    "appliance",
                    "--maximum-diagnostics",
                    "100001",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .is_err()
        );
        assert!(
            parse(
                ["check", "wrela.toml", "bad image"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .is_err()
        );
        assert_eq!(
            wrela_driver::DiagnosticOptions::default().maximum_diagnostics,
            super::MAXIMUM_DIAGNOSTICS
        );
    }

    #[test]
    fn test_accepts_exact_selection_output_and_diagnostic_policy() {
        let Parsed::Command(wrela_driver::Command::Test {
            workspace,
            output_directory,
            selection,
            diagnostics,
        }) = parse(
            [
                "test",
                "wrela.toml",
                "appliance",
                "artifacts/tests",
                "--name-contains",
                "network::",
                "--profile",
                "release-sealed",
                "--warnings-as-errors",
                "--maximum-diagnostics",
                "19",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid test options")
        else {
            panic!("expected test command")
        };
        assert_eq!(workspace.profile, "release-sealed");
        assert_eq!(output_directory, PathBuf::from("artifacts/tests"));
        assert_eq!(
            selection,
            wrela_driver::TestSelection::NameContains("network::".to_owned())
        );
        assert!(diagnostics.warnings_as_errors);
        assert_eq!(diagnostics.maximum_diagnostics, 19);
    }

    #[test]
    fn test_selections_are_mutually_exclusive_and_filters_are_bounded() {
        assert!(
            parse(
                ["test", "wrela.toml", "appliance", "--comptime", "--images",]
                    .into_iter()
                    .map(str::to_owned),
            )
            .is_err()
        );
        assert!(
            parse(
                ["test", "wrela.toml", "appliance", "--name-contains", ""]
                    .into_iter()
                    .map(str::to_owned),
            )
            .is_err()
        );
        let oversized = "x".repeat(super::MAX_TEST_FILTER_BYTES + 1);
        let maximum = "x".repeat(super::MAX_TEST_FILTER_BYTES);
        assert!(
            parse(
                [
                    "test".to_owned(),
                    "wrela.toml".to_owned(),
                    "appliance".to_owned(),
                    "--name-contains".to_owned(),
                    maximum,
                ]
                .into_iter(),
            )
            .is_ok()
        );
        assert!(
            parse(
                [
                    "test".to_owned(),
                    "wrela.toml".to_owned(),
                    "appliance".to_owned(),
                    "--name-contains".to_owned(),
                    oversized,
                ]
                .into_iter(),
            )
            .is_err()
        );
    }

    #[test]
    fn format_accepts_check_in_either_position_and_rejects_duplicates() {
        for arguments in [
            ["format", "--check", "wrela.toml", "app/main.wr"],
            ["format", "wrela.toml", "app/main.wr", "--check"],
        ] {
            let Parsed::Command(wrela_driver::Command::Format {
                manifest,
                files,
                check_only,
            }) = parse(arguments.into_iter().map(str::to_owned)).expect("valid format --check")
            else {
                panic!("expected format command")
            };
            assert_eq!(manifest, PathBuf::from("wrela.toml"));
            assert_eq!(files, [PathBuf::from("app/main.wr")]);
            assert!(check_only);
        }
        assert!(
            parse(
                ["format", "--check", "wrela.toml", "--check", "app/main.wr",]
                    .into_iter()
                    .map(str::to_owned),
            )
            .is_err()
        );

        let Parsed::Command(wrela_driver::Command::Format {
            manifest,
            files,
            check_only,
        }) = parse(
            ["format", "--check", "--", "--manifest", "--check"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("option terminator permits dash-prefixed paths")
        else {
            panic!("expected format command")
        };
        assert_eq!(manifest, PathBuf::from("--manifest"));
        assert_eq!(files, [PathBuf::from("--check")]);
        assert!(check_only);

        assert!(
            parse(
                ["format", "--unknown", "wrela.toml", "app/main.wr"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .is_err()
        );
        assert!(
            parse(["version", "extra"].into_iter().map(str::to_owned)).is_err(),
            "informational commands must not silently ignore arguments"
        );
    }
}
