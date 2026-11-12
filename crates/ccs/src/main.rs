mod conformance;

use std::process::ExitCode;

fn run() -> ExitCode {
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
        return conformance::run(&args[1..]);
    }
    match ccs::cli::dispatch(&args) {
        Ok(status) => ExitCode::from(status.code()),
        Err(error) => {
            ccs::cli::stderr_line(&format!("ccs: {}", ccs::cli::message(&error)));
            ExitCode::from(error.exit_status().code())
        }
    }
}

fn guarded(body: impl FnOnce() -> ExitCode + std::panic::UnwindSafe) -> ExitCode {
    std::panic::set_hook(Box::new(|_| ccs::cli::stderr_line("ccs: internal error")));
    // Set before dispatch can read credentials; core dumps can contain secrets.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            ccs::cli::stderr_line("ccs: cannot disable core dumps");
            return ExitCode::from(1);
        }
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    std::panic::catch_unwind(body).unwrap_or(ExitCode::from(1))
}

fn main() -> ExitCode {
    guarded(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn panic_boundary_never_formats_the_payload() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::panic_child", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stderr, b"ccs: internal error\n");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-secret-payload"));
    }

    #[test]
    #[ignore = "only the isolated parent test starts this process"]
    fn panic_child() {
        let code = guarded(|| panic!("synthetic-secret-payload"));
        std::process::exit(if code == ExitCode::from(1) { 1 } else { 42 });
    }
}
