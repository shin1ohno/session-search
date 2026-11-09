# Approved compatibility differences (D1–D9)

These are the bounded exceptions approved for the Python-to-Rust migration.
They are future Rust expectations, not changes made by S0. The Python baseline
is `527735dfe48a706a04638edaf1b6a83373d3cad5`; all other behavior remains governed
by [contract.md](contract.md). Tests must not excuse arbitrary differences under
these labels. S2 must exercise the listed Rust-specific expectations explicitly.

| ID | Baseline and permitted Rust behavior | Verification |
|---|---|---|
| D1 | Python validation regex `$` can match before a final newline. Rust uses absolute end-of-input (`\z`) for host/session/tool-result/path identifiers and rejects trailing newlines. Redaction regex semantics are not changed by this exception. | CLI/path validation boundary cases; baseline `ccs/util.py:22,26,27`, `ccs/ingest.py:32`. |
| D2 | A1 tombstones a line only if a lone surrogate remains after Python masking. Rust detects any escaped lone surrogate before masking and tombstones the whole line, including a secret value later masked or an overwritten duplicate-key value. A valid pair remains Unicode. | Raw-line corpus and differential tests; baseline `ccs/ingest.py:328–334`. Lost text is an accepted stricter result; sending a surrogate is not. |
| D3 | Rust locally tombstones any value deeper than 64 with reason `too-deep`, or integers of 4,301+ digits with `invalid-json`; kinds is empty. Python may send masked/text input, then replace it after the server rejects it, or fail at an interpreter-dependent recursion threshold. Overwritten duplicate-key values are included. NaN/Infinity/overflow are not a new exception. | Raw-line corpus, object-root depth 63–66 and 127–130 (plus array controls), giant integer and server parser checks; baseline `ccs/ingest.py:168–172,381`, server `sessions_app.py:703–733`. |
| D4 | Help and usage wording may differ from argparse. Valid options/abbreviations stay supported and usage errors still exit 2. | `tests/contract/test_cli_picker.py`; baseline `ccs/cli.py:33–116`. |
| D5 | Rust skips non-UTF-8 filesystem paths with WARN. Python can carry surrogateescape paths and fail at the server. Normal UTF-8 paths retain their semantics. | Filesystem-path cases with raw non-UTF-8 names in S2; baseline `ccs/ingest.py` path discovery. |
| D6 | An uncaught internal error becomes one diagnostic line without secrets or traceback; exit remains 1. Expected usage/server/resume failures retain their distinct codes. | Controlled internal-error process in S2; baseline `ccs/cli.py` dispatch and `ccs/util.py:17–20`. |
| D7 | The per-keystroke helper transport changes from curl to `ccs _backend` talking to the Unix socket. Absence of curl no longer disables the helper. Rows, prompt, preview, permissions, cleanup and fallback remain observable contracts. | `tests/contract/test_helper.py`; remove the old no-curl implementation test, retain bind-failure/dead-helper cases. |
| D8 | Add one token-status line to `ccs status` and persist token state as specified by the separately reviewed token design. Keep all prior lines and their order; never print secrets. S0 writes no token cache. | S2 token tests and security review; baseline `ccs/cli.py:149–178`, `ccs/api.py:79–116`. |
| D9 | Configure Rust ureq connect/send/receive timeouts separately, matching Python's per-socket-operation timeout. Do not substitute a single global deadline. | `test_backend_timeout_counts_as_failure_and_falls_back`; baseline `ccs/api.py:62–73,121–145`. |

Each raw-line vector keeps `expect` as the real Python result and separately
records `rust_expect` (route, output, counts, offsets), `compat` (`D2`, `D3`, or
empty), `raw_facts` (maximum depth, integer digits, lone-surrogate presence),
and `server_expect` from the real `sessions_app.strict_load`. The client methods
are extracted from the complete frozen `ingest.py` in the header and checked
against the live client during generation and by client CI. Python replay never
uses the Rust exception as its oracle.

D2's surrogate and D3's too-deep/invalid-json cases require the exact local
tombstone with empty kinds/counts and the original offset. Overwritten duplicate
values count toward both guards. N14 (retaining Python's record/text route for a
D3 input) and N12 (sending depth >128 as text) fail `rust_expect` comparison;
neither is an allowed exception or a skip. Valid surrogate pairs, depths <=64,
NaN/Infinity, malformed JSON and non-object roots do not receive a blanket D3
waiver. Rust-specific execution remains S2; S0 freezes and validates the data
and exercises these deliberately incorrect policy outputs in its mutation audit.
