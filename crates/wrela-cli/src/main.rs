//! Public `wrela` command-line executable.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use wrela_driver::Command;

const HELP: &str = "\
wrela — build sealed machine images

USAGE:
    wrela <COMMAND>

COMMANDS:
    build <ROOT>    Compile and link a bootable image
    check <ROOT>    Analyze an image without loading LLVM
    doctor          Validate the installed toolchain bundle
    version         Print version information
    help            Print this help
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
        Ok(Parsed::Command(command)) => match wrela_driver::run(&command) {
            Ok(output) => {
                print!("{output}");
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
        Some("check") => one_path_argument("check", arguments)
            .map(|root| Parsed::Command(Command::Check { root })),
        Some("build") => one_path_argument("build", arguments)
            .map(|root| Parsed::Command(Command::Build { root })),
        Some(command) => Err(format!("unknown command `{command}`")),
    }
}

fn one_path_argument(
    command: &str,
    mut arguments: impl Iterator<Item = String>,
) -> Result<PathBuf, String> {
    let path = arguments
        .next()
        .ok_or_else(|| format!("`{command}` requires a root source path"))?;
    no_extra_arguments(arguments)?;
    Ok(PathBuf::from(path))
}

fn no_extra_arguments(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    match arguments.next() {
        Some(argument) => Err(format!("unexpected argument `{argument}`")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Parsed, parse};

    #[test]
    fn parses_build_root() {
        let parsed = parse(["build".to_owned(), "appliance.wr".to_owned()].into_iter())
            .expect("valid command");
        let Parsed::Command(command) = parsed else {
            panic!("expected driver command");
        };
        assert_eq!(
            command,
            wrela_driver::Command::Build {
                root: "appliance.wr".into()
            }
        );
    }
}
