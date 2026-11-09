# Wave 0 interfaces

S1 fixes crate boundaries, error/status mapping, JSON value representation and
module entry signatures before S2 streams begin. Every stub returns
`Error::NotImplemented`; it performs no I/O. The Python command contract remains
in [contract.md](contract.md). Rust command dispatch is enabled only in S2.

- `ccs-pytext::json::Value` keeps object order, number spellings and Python code
  points (including unpaired surrogates until the line policy handles them).
  `loads(&[u32])` and `dumps(&Value, ensure_ascii, sort_keys)` are the shared
  reader/writer boundary. These stubs do not parse or serialize.
- `ccs::errors::{Error, Result, ExitStatus}` fixes usage=2, unavailable=3,
  resume-precondition=4, internal=1 and signal=128+signal.
- The modules exported by `ccs::lib` accept the shared `Value`, OS arguments or
  paths as appropriate. Each module owns its later private state and types;
  signatures are the Wave 0 cross-stream boundary, not a new wire format.
- `ccs-redact` remains I/O-free and forbids unsafe code. Its ruleset constant is
  build metadata, not evidence of conformance.

`tools/check_conformance.py` defines the emit protocol used by both the release
gate and setup's policy copy. Masking ops emit one `{id, result}` row in corpus
order; detector-only vectors do not emit content. This protocol is test-only.

Until S2, `_conformance` always exits 1 and the publication gate refuses every
foundation artifact. Python CI and deployment stay active through S5.
