//! S1 build and error boundary. User-facing commands remain in Python.

pub mod api;
pub mod breaker;
pub mod cli;
pub mod codex;
pub mod config;
pub mod errors;
pub mod extract;
pub mod fallback;
pub mod helper;
pub mod ingest;
pub mod picker;
pub mod query;
pub mod resume;
pub mod session_codex;
pub mod token;
pub mod util;

pub fn buildinfo() -> String {
    format!(
        "{{\"version\":\"{}\",\"commit\":\"{}\",\"target\":\"{}\",\"redact_version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION"),
        env!("CCS_BUILD_COMMIT"),
        env!("CCS_BUILD_TARGET"),
        ccs_redact::REDACT_VERSION,
    )
}
