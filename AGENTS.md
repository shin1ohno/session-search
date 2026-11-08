# AGENTS.md

`ccs` searches and resumes Claude Code and Codex sessions. This repository holds the package and its tests. shin1ohno/setup pins it by commit SHA and owns fetching, placing and configuring it, along with the launcher, the sweep unit, the session-ingest hook and the skill.

## Where things are

| You need | Look at |
|---|---|
| Client package | `ccs/` |
| Tests and their hermetic helpers | `tests/`, `tests/support.py` |
| Server-owned modules shipped inside the package | `vendor/memory-mcp/` |
| Where the vendored files came from | `vendor/memory-mcp/SOURCE` |

## Rules

- Standard library only. `ccs` has no third-party dependencies.
- Keep the code compatible with Python 3.9, because macOS runs it on the system python.
- Never edit `vendor/` by hand. Replace a file from the server tree and update `SOURCE` in the same commit.

## How to run the tests

```sh
python3 -m unittest discover -s tests -v
```

The suite is hermetic: a fake HTTP server on 127.0.0.1, a fake redactor and a temporary `$HOME`.

- The offline fallback cases need `rg` on `PATH`. The tests change `$HOME`, so a version-manager shim such as mise's can fail there; put the real binary first on `PATH`.
- The native Codex cases skip unless `CCS_TEST_CODEX` points at a native Codex binary.

CI (`.github/workflows/ci.yml`) runs the suite on the runner's `python3` and on Python 3.9 with `-W error::ResourceWarning`.
