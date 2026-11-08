# session-search

ccs: Claude Code / Codex session search client (deployed by shin1ohno/setup at a pinned SHA)

This repository holds the `ccs` package and its tests. shin1ohno/setup pins a commit by SHA, fetches it on each host, and owns the launcher, the sweep unit, the session-ingest hook and the skill.

`ccs` is standard library only and runs on Python 3.9 and later.

## Layout

| Path | Contents |
|---|---|
| `ccs/` | The client package |
| `tests/` | The test suite, hermetic (fake server, fake redactor, temporary `$HOME`) |
| `vendor/memory-mcp/` | `session_redact.py` and `session_codex.py`, owned by the server tree and shipped inside the package; `SOURCE` records their origin |

## Tests

```sh
python3 -m unittest discover -s tests -v
```

See `AGENTS.md` for the test prerequisites and the rules for changing this repository.

## License

CC0 1.0. See `LICENSE`.
