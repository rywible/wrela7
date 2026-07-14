//! Maintainer-only toolchain build and distribution tasks.

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        None | Some("help" | "-h" | "--help") => {
            println!(
                "xtask commands:\n  llvm    fetch, verify, and build pinned LLVM/LLD (next milestone)\n  dist    assemble and validate an atomic toolchain bundle (next milestone)"
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("error: xtask command `{command}` is scaffolded but not implemented");
            ExitCode::FAILURE
        }
    }
}
