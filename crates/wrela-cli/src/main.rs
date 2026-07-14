//! Thin public `wrela` command-line adapter. Compilation policy and terminal-
//! independent outcomes live in `wrela-driver`.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use wrela_driver::{Command, DiagnosticOptions, TestSelection, WorkspaceSelection};

const HELP: &str = "\
wrela — build sealed AArch64 machine images

USAGE:
    wrela check <wrela.toml> <IMAGE>
    wrela build <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
    wrela test <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
    wrela lint <wrela.toml> <IMAGE>
    wrela format <wrela.toml> <FILE>...
    wrela doctor
    wrela version
";

fn main() -> ExitCode {
    match parse(env::args().skip(1)) {
        Ok(Parsed::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(Parsed::Version) => {
            println!("wrela {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Parsed::Command(command)) => match wrela_compiler::run(&command) {
            Ok(output) => {
                print!("{}", output.render_text());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

enum Parsed {
    Help,
    Version,
    Command(Command),
}

fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Parsed, String> {
    match arguments.next().as_deref() {
        None | Some("help" | "-h" | "--help") => Ok(Parsed::Help),
        Some("version" | "-V" | "--version") => Ok(Parsed::Version),
        Some("doctor") => no_extra_arguments(arguments).map(|()| Parsed::Command(Command::Doctor)),
        Some("check") => {
            let workspace = workspace_arguments("check", &mut arguments)?;
            no_extra_arguments(arguments)?;
            Ok(Parsed::Command(Command::Check {
                workspace,
                diagnostics: diagnostics(),
            }))
        }
        Some("build") => {
            let workspace = workspace_arguments("build", &mut arguments)?;
            let output_directory = arguments
                .next()
                .map_or_else(|| PathBuf::from("build/wrela"), PathBuf::from);
            no_extra_arguments(arguments)?;
            Ok(Parsed::Command(Command::Build {
                workspace,
                output_directory,
                diagnostics: diagnostics(),
            }))
        }
        Some("test") => {
            let workspace = workspace_arguments("test", &mut arguments)?;
            let output_directory = arguments
                .next()
                .map_or_else(|| PathBuf::from("build/wrela-tests"), PathBuf::from);
            no_extra_arguments(arguments)?;
            Ok(Parsed::Command(Command::Test {
                workspace,
                output_directory,
                selection: TestSelection::All,
                diagnostics: diagnostics(),
            }))
        }
        Some("lint") => {
            let workspace = workspace_arguments("lint", &mut arguments)?;
            no_extra_arguments(arguments)?;
            Ok(Parsed::Command(Command::Lint {
                workspace,
                diagnostics: diagnostics(),
            }))
        }
        Some("format") => {
            let manifest = required_path("format", &mut arguments)?;
            let files: Vec<PathBuf> = arguments.map(PathBuf::from).collect();
            if files.is_empty() {
                return Err("`format` requires at least one source file".to_owned());
            }
            Ok(Parsed::Command(Command::Format {
                manifest,
                files,
                check_only: false,
            }))
        }
        Some(command) => Err(format!("unknown command `{command}`")),
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

fn required_path(
    command: &str,
    arguments: &mut impl Iterator<Item = String>,
) -> Result<PathBuf, String> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("`{command}` requires a manifest path"))
}

fn diagnostics() -> DiagnosticOptions {
    DiagnosticOptions {
        warnings_as_errors: false,
        maximum_diagnostics: 100_000,
    }
}

fn no_extra_arguments(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    arguments.next().map_or(Ok(()), |argument| {
        Err(format!("unexpected argument `{argument}`"))
    })
}

#[cfg(test)]
mod tests {
    use super::{Parsed, parse};

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
}
