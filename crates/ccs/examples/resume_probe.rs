//! Function-level process adapter used by the Python differential oracle.
use ccs::resume::{resume, ResumeRequest};
use ccs::util::{get, text, truthy};
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
fn main() {
    let raw = std::env::args().nth(1).expect("JSON request argument");
    let request = ccs::util::parse_json(&raw).unwrap();
    let mut req = ResumeRequest {
        session_key: text(get(&request, "session_key")).unwrap(),
        print: truthy(get(&request, "print")),
        fork: truthy(get(&request, "fork")),
        to_dir: text(get(&request, "to_dir")).map(Into::into),
        force: truthy(get(&request, "force")),
    };
    if let Some(bytes) = text(get(&request, "_to_dir_bytes")) {
        let bytes = (0..bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap())
            .collect();
        req.to_dir = Some(std::ffi::OsString::from_vec(bytes).into());
    }
    if truthy(get(&request, "close_stderr")) {
        // SAFETY: this disposable process deliberately tests a closed stderr.
        // Close after runtime initialization, as the Python function adapter does.
        unsafe {
            libc::close(libc::STDERR_FILENO);
        }
    }
    let code = match resume(&req) {
        Ok(status) => status.code(),
        Err(error) => {
            let _ = std::io::stderr().write(b"ccs: internal error\n");
            error.exit_status().code()
        }
    };
    std::process::exit(i32::from(code));
}
