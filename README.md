# session-search

ccs: Claude Code / Codex session search client (deployed by shin1ohno/setup at a pinned SHA)

This repository holds the `ccs` package and its tests. shin1ohno/setup pins a commit by SHA, fetches it on each host, and owns the launcher, the sweep unit, the session-ingest hook and the skill.

The Rust migration is at S1 (foundation). Python 3.9+ is still the shipped
client; no host is switched by this stage. The Rust binary exposes `_buildinfo`
and `--version`, and explicitly rejects unimplemented commands.

Build the pinned Rust workspace:

```sh
export CCS_BUILD_COMMIT=$(git rev-parse HEAD)
cargo build --locked --release
target/release/ccs _buildinfo
```

`release.yml` builds Linux x86_64, Linux aarch64 and macOS aarch64 artifacts.
The macOS build uses `macos-15` with an explicit macOS 11.0 deployment target;
CI checks the binary's `LC_BUILD_VERSION` and its ad-hoc signature.
PRs and manual runs only upload workflow artifacts. Publication on main also
requires both conformance suites and the output cross-check, so S1 publishes
nothing. See [the publication gate](tools/release_gate.py).

The contract's pass limit is 8. Detections for corpus `pass-limit` vectors must
equal the reference implementation's kinds and counts; other vectors require
zero detections ([cross-check](tools/check_conformance.py)).

## Layout

| Path | Contents |
|---|---|
| `ccs/` | The client package |
| `crates/` | Three-crate Rust workspace, currently foundation only |
| `tests/contract/` | Process-level Python/Rust compatibility contract |
| `tools/` | Release verification and interoperability probes |
| `tests/` | The test suite, hermetic (fake server, fake redactor, temporary `$HOME`) |
| `vendor/memory-mcp/` | `session_redact.py` and `session_codex.py`, owned by the server tree and shipped inside the package; `SOURCE` records their origin |

## Tests

```sh
python3 -m unittest discover -s tests -v
```

See `AGENTS.md` for the test prerequisites and the rules for changing this repository.

## License

CC0 1.0. See `LICENSE`.
