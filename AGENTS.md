# AGENTS.md

`ccs` searches and resumes Claude Code and Codex sessions. This repository holds the package and its tests. shin1ohno/setup pins it by commit SHA and owns fetching, placing and configuring it, along with the launcher, the sweep unit, the session-ingest hook and the skill.

## Where things are

| You need | Look at |
|---|---|
| Client package | `ccs/` |
| Rust workspace (S1 foundation, S2 implementation) | `crates/` |
| External-process contract | `tests/contract/`, `docs/contract.md` |
| Build and conformance gates | `tools/` |
| Tests and their hermetic helpers | `tests/`, `tests/support.py` |
| Server-owned modules shipped inside the package | `vendor/memory-mcp/` |
| Where the vendored files came from | `vendor/memory-mcp/SOURCE` |

## Rules

**Transition (S1–S5): Python remains the shipped implementation on every S1
host. Keep it compatible with Python 3.9 and retain both Python CI jobs until
S6. The Rust binary currently implements only build metadata and rejects
conformance and client commands. The following runtime policy takes effect
after S6; vendor Python continues to ship with the Python package until then.**

- `ccs` is a Rust binary. Python is not needed at run time on any host from S6.
- Dependencies: `Cargo.lock` is committed and every build uses `--locked`. A new or updated crate needs a `cargo deny check` pass and the `cargo tree` diff in the pull request. `ccs-redact` may depend only on `regex-automata`, `ring` and the `ccs-pytext` path crate. `serde_json` is banned: transcript and server JSON goes through `ccs-pytext::json` only.
- Never edit `vendor/` by hand. Replace a file from the server tree and update `SOURCE` in the same commit. In the Rust distribution, `vendor/memory-mcp/*.py` are CI-only oracles and are never shipped.
- Never edit `crates/ccs-redact/src/tables.rs` by hand. Regenerate it with `tools/gen_redact_tables.py` (introduced in S2).
- A change to masking behaviour starts on the server: regenerate the conformance corpus there, then update the copy here.

## How to run the tests

```sh
export CCS_BUILD_COMMIT=$(git rev-parse HEAD)
cargo test --locked --workspace
cargo build --locked --release
python3 tools/test_foundation.py
python3 tools/test_crosscheck.py
python3 -m unittest discover -s tests -v
```

From S2, also run `CCS_UNDER_TEST=target/release/ccs python3 -m unittest
discover -s tests/contract` and `target/release/ccs _conformance redact <
vendor/memory-mcp/conformance/session_redact_r1.jsonl`. In S1 the latter must
fail explicitly; `tools/release_gate.py` prevents publishing that skeleton.

The suite is hermetic: a fake HTTP server on 127.0.0.1, a fake redactor and a temporary `$HOME`.

- The offline fallback cases need `rg` on `PATH`. The tests change `$HOME`, so a version-manager shim such as mise's can fail there; put the real binary first on `PATH`.
- The native Codex cases skip unless `CCS_TEST_CODEX` points at a native Codex binary.

CI (`.github/workflows/ci.yml`) runs the suite on the runner's `python3` and on Python 3.9 with `-W error::ResourceWarning`.
