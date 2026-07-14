//! Private code-generation process. This is not installed on the user's PATH.

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("--protocol-version") => {
            println!("{}", wrela_backend_protocol::PROTOCOL_VERSION);
            ExitCode::SUCCESS
        }
        Some("--version") => {
            println!("wrela-backend {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("error: the LLVM backend is scaffolded but not linked yet");
            ExitCode::FAILURE
        }
    }
}
