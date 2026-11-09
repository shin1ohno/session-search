mod conformance;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "_buildinfo" {
        println!("{}", ccs::buildinfo());
        return ExitCode::SUCCESS;
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("ccs {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|arg| arg == "_conformance") {
        if args.get(1).is_some_and(|arg| arg == "codex") {
            // Preserve the staging refusal contract until the remaining suite is implemented.
            eprintln!("ccs: conformance is not implemented in S1");
            return ExitCode::from(ccs::errors::ExitStatus::Internal.code());
        }
        return conformance::run(&args[1..]);
    }
    eprintln!("ccs: this S1 foundation binary cannot run client commands; use the Python launcher");
    ExitCode::from(ccs::errors::ExitStatus::Usage.code())
}
