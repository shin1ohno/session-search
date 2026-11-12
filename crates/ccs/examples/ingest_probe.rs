//! Function-level ingest adapter used by the Python oracle.
use ccs::ingest::{run_ingest, IngestMode, IngestRequest};
fn main() {
    let mut args = std::env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("file") => IngestMode::File(args.next().expect("path").into()),
        Some("sweep") => IngestMode::Sweep,
        Some("backfill") => IngestMode::Backfill,
        _ => std::process::exit(2),
    };
    let options: Vec<_> = args.collect();
    let status = run_ingest(&IngestRequest {
        mode,
        with_subagents: options.iter().any(|s| s == "--with-subagents"),
        quiet: options.iter().any(|s| s == "--quiet"),
    })
    .unwrap_or_else(|error| {
        use std::io::Write;
        let _ = std::io::stderr().write(b"ccs: ingest failed\n");
        error.exit_status()
    });
    std::process::exit(i32::from(status.code()));
}
