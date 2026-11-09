# ccs compatibility contract (S0)

The baseline is the Python client at `527735dfe48a706a04638edaf1b6a83373d3cad5`.
S0 freezes observable behavior before the Rust implementation begins. This
document describes the contract; [compat-deviations.md](compat-deviations.md)
records the approved future differences. S0 changes no production client code.

## Running the contract

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests/contract -t tests -v
CCS_UNDER_TEST='/absolute/path/to/ccs' python3 -m unittest discover -s tests/contract -t tests -v
CCS_UNDER_TEST='/absolute/path/to/ccs' CCS_INTEROP_PEER='/absolute/path/to/python-ccs' \
  python3 -m unittest discover -s tests/contract -t tests -p test_state_interop.py -v
```

The variables contain shell-quoted argv, parsed with `shlex.split`, never shell
programs. With no override, `tests/contract/harness.py` stages `ccs/` plus the two
real vendored server modules in a temporary installation. Every client invocation
is a subprocess. Temporary HOME, config, state and CODEX_HOME, a loopback HTTP
server, a fixed test HMAC key, and PATH executables isolate the test from real
credentials and sessions. The contract never uses `FakeRedactor` or injects client
functions. `tests/support.py` remains shared fixture support for unit tests.

Provide a native `rg` on PATH (or `CCS_TEST_RG`). Set `CCS_TEST_CODEX` to the native
Codex executable used in CI to run all three archive/resume compatibility cases;
they explicitly skip without it. The helper bind-failure test uses a disposable
Linux subprocess with `bind(2)` denied, checks that fault independently, and then
exercises the actual picker. It skips outside Linux x86_64/aarch64. This is test
fault injection only. The ordinary helper tests run without that restriction.

`test_state_interop.py` alternates writers and readers in both directions. In S0
both commands are Python; S2 supplies Rust and Python with the two variables.
Both Python CI jobs explicitly set
`CCS_UNDER_TEST` to the current interpreter and a staged copy of the real client
with the real server modules. This exercises the external-command contract in CI as well as locally.
S0 also runs the N8 negative control through the Python corpus runners.
The Rust build workflow belongs to S1. A passing S0 run does not establish
Python/Rust interoperability.

## CLI and output

Sources below refer to the baseline commit, making line references stable.

| Surface | Required behavior | Source |
|---|---|---|
| Commands | Default picker, `search`, `preview`, `resume`, `ingest`, `status`, `purge`, `_backend`, `_preview`, `_toggle`, `_fuse` | `ccs/cli.py:33–116` |
| Picker/search options | `--deep`, `--semantic`, `--all`, `--sidechain`, `--here`, repeated `--host`, `--since`, `--offline`, `--print`, `--fork`, `--version`; search also `--limit` in 1..50 | `ccs/cli.py:33–52` |
| Other options | preview key/query; resume key/`--print`/`--fork`/`--to`/`--force`; ingest exactly one of `--file`/`--sweep`/`--backfill`, `--with-subagents` requiring `--file`, `--quiet`; purge key; internal callback arguments | `ccs/cli.py:55–87` |
| Parsing | Unique long-option abbreviations such as `--sem`; negative-looking query words; duration suffix m/h/d/w; host-label validation | `ccs/cli.py:90–116`, `ccs/util.py:183–192` |
| Search/preview | One JSON object followed by LF; Unicode unescaped; separators `, ` and `: `; stable key order and fields including `session_key`, `agent`, `degraded`; `local:` key format | `ccs/cli.py:181–250` |
| Status | Preserve line order; server JSON sorted with ASCII escapes; future token line is D8 | `ccs/cli.py:149–178` |
| Purge/ingest | Purge JSON sorted with ASCII escapes; ingest `ccs ingest: {...}` sorted, suppressed by `--quiet` | `ccs/cli.py:281`, `ccs/ingest.py:567` |
| Resume print | Shell-quoted `cd <cwd> && claude --resume <sid>` or `codex resume`/`fork`; actual execution uses the same local cwd and argv | `ccs/resume.py:48–52` |
| Picker rows | `<session_key>\t<mark><age> <host> <short cwd> │ <title> │ <hits>`, including view-only mark, Codex marker and ANSI banner | `ccs/picker.py:149–171` |
| fzf | Keep bindings, preview and `ccs:sda> ` prompt state; cancel succeeds, Enter resumes, ctrl-y prints, banner rows do nothing | `ccs/picker.py:46–48,115–131,474–514` |
| Diagnostics | `ccs: <message>` lines; parser help/usage wording is excluded (D4) | `ccs/cli.py:226,253` |

Exit codes are 0 for success/cancel, 2 for usage/config errors, 3 for unavailable
server with no usable fallback, 4 for unmet resume preconditions, and 1 for internal
errors (`ccs/util.py:17–20`). Ingest lock contention or absent configuration returns
0; a configured client without its HMAC key returns 3 (`ccs/ingest.py:499–524`).
Per-file ingest failures accumulate `errors` and leave the cursor unchanged while
the command returns 0 (`ccs/ingest.py:546–570`); they must not be confused with the
startup failure codes. Future signal handling is 141 for SIGPIPE, 130 for SIGINT;
picker SIGTERM/SIGHUP already uses `128 + signum` (`ccs/picker.py:487–488`).

## State, configuration and security boundaries

| File/surface | Contract | Baseline source |
|---|---|---|
| `~/.claude/session-search/state.json` | `{"version":1,"files":{absolute_path:{dev,inode,size,offset,generation,session_key,last_ok,blobs?}}}`; preserve unknown keys and actual stat dev/inode; atomic 0600 writes, sorted JSON with indent 1 | `ccs/ingest.py:128–141,198–205`, `ccs/util.py:134–149` |
| `lock` in the same directory | Nonblocking `flock(2)` exclusion shared across implementations | `ccs/ingest.py:471–488` |
| `breaker.json` | `{failures:int, open_until:epoch_float}` shared by processes; two failures open the circuit, success resets it | `ccs/api.py:171–196` |
| `restored.json` | `{"version":1,"sessions":{"<project>/<sid>":{...}}}`; a restored session resumes only in the locally recorded directory | `ccs/resume.py:175–189,206–232` |
| `picker-<port>.seq`, `.rows` | Temporary callback sequencing/cache files | `ccs/picker.py:276–277,313–314` |
| `~/.claude/session-search.log` | ISO8601Z, level, message on one line; no secrets or transcript bodies; status reads WARN/ERROR | `ccs/util.py:168–180`, `ccs/cli.py:257–263` |
| `~/.config/session-search/config.json` | Existing schema/validation; `CCS_CONFIG` override; setup remains the config owner | `ccs/config.py:1–100`, `ccs/util.py:71–72` |
| `client.secret`, `hmac.key` | Strip surrounding whitespace when reading | `ccs/config.py:92–100`, `vendor/memory-mcp/session_redact.py:49–59` |

Environment inputs remain `HOME`, `CCS_CONFIG`, `CCS_LAUNCHER`, `CCS_PICK`,
`CCS_PICK_STATE`, `FZF_PROMPT`, `FZF_PORT`, `FZF_API_KEY`, `CODEX_HOME`,
`CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`, `SSL_CERT_FILE` and proxy variables
(`ccs/util.py:34–36,72`, `ccs/picker.py:62–93`, `ccs/codex.py:15`).

Restore must validate session IDs, local cwd, archive hashes, member names, symlinks
and directory collisions. Server-supplied cwd cannot select a local directory with
hooks. Noninteractive restoration needs `--to`; interactive acceptance is tested
through a real PTY. Ingest never reads symlinked transcript/blob paths or FIFOs.
The cases in `test_resume.py`, `test_ingest.py` and `test_codex_review.py` freeze
these boundaries using received bytes and files, not an internal success return.

## HTTP and ingestion

Keep the server API route/method/query/body definitions in setup's
`docs/design/claude-session-search.md` section 7.2. The client currently uses
POST `/search`, GET `/preview`, GET `/archive`, GET `/archive/tool-results`, GET `/status`, POST `/ingest`,
POST `/blob`, POST `/state`, DELETE `/session`, plus the configured token endpoint.
These call sites are `ccs/{picker,cli,resume,ingest}.py`; token acquisition is
`ccs/api.py:79–116`. The server API also exposes its own complete route set;
the client contract does not invent calls absent from the baseline.

`User-Agent` is `ccs/<VERSION>`, Accept is application/json, JSON request bodies
are UTF-8 with compact separators, and gzip bodies deliberately omit
Content-Encoding (`ccs/api.py:121–145`). Redirects are refused. OAuth uses
client-secret Basic authentication with percent-encoded credentials, form
`grant_type=client_credentials` and optional audience; one 401 refresh is allowed.
Tailnet authentication sends no bearer token (`ccs/api.py:53–60,79–145`). S0 does
not introduce token persistence or modify authentication.

The `/ingest` envelope preserves source/host/session/subagent metadata, generation,
byte offsets and segment SHA256 of the exact sent lines (`ccs/ingest.py:176–191`).
Partial trailing lines wait; successful acknowledgements advance offsets; 409
resynchronizes to the expected offset, 413 reduces segment size, and 422 replaces
the named lines with tombstones before retrying (`ccs/ingest.py:287–387`). A1
replaces masked lines still containing lone surrogates before UTF-8 encoding;
valid surrogate pairs remain Unicode (`ccs/ingest.py:328–334`). Inode changes or
shrinks increment generation. Tool-result blobs are masked and shipped once by
content hash. Sweep marks disappeared files (`ccs/ingest.py:392–447`).

## Server-owned conformance corpus

`vendor/memory-mcp/SOURCE` records the upstream commit and Git blob OID for each
copied corpus. Never edit these files locally. Their owner is ai-memory, alongside
the real `session_redact.py` and `session_codex.py` implementations.

The JSONL header records `format`, `ruleset`, `source_blob`, Python/Unicode versions,
fixed `hmac_key_hex`, seed, minimum/count and SHA256 of every subsequent byte.
The redactor header contains the exact client `ingest.py` source and its blob,
and identifies only the selected `strict_load` functions/constants with a
SHA256 fingerprint. Unrelated server definitions or line shifts do not alter
that fingerprint. Changes to the selected parser dependencies invalidate it,
and replay also checks the real parser's results for every raw-line vector.
Standalone server replay extracts the
real frozen `_mask_line`/`_mask_chunk` methods; it does not reproduce their logic.
`--client-tree` additionally checks the live client blob; client CI always
checks it against this checkout's `ccs/ingest.py`. The generator
uses Python 3.13.5 / Unicode 15.1.0, seed 20261109 and public test key
`test-key-not-a-secret`. This identifies the generation interpreter, not an
unverified claim about a running host. Each vector has `id`, `op`, `input`,
`expect`; the only compression syntax is `{"$repeat":[string,count]}`. Comparisons
preserve JSON types and dictionary key order.

The r1 corpus contains 54,472 vectors (18,843,525 bytes), and v1 Codex contains
154 (149,457 bytes). The 2 MiB planning target is exceeded: the full required
Cartesian boundary coverage and legacy budget cases are retained instead of
discarding cases or introducing a new compression format. The committed corpus
is finite evidence, not proof of redactor equivalence for arbitrary input.

Redactor coverage includes all four functions, the 47 boundary characters,
Cartesian boundaries for the seven word-boundary rules, Unicode case/space,
placeholder/pass-limit/prefilter behavior, secret keys and collision suffixes,
record budgets and depth through 64, and legacy in-domain vectors. Lone surrogates
and deeper values belong to the raw `mask_line` path, whose expected values come
from the actual baseline client, including object-root depths 63–66 and 127–130, whitespace-only skip, special serde keys,
invalid UTF-8 and JSON grammar edges. Codex normalization compares only fields
consumed by the client: type, message.content, cwd, entrypoint, timestamp,
gitBranch and version. Generated uuid/message.id remain server unit-test scope.
IndexState sequences check acceptance and serialized state after each input.

In the ai-memory checkout:

```sh
python3.13 memory-mcp/conformance/gen_vectors.py --client-tree /path/to/session-search
python3 -I memory-mcp/test_session_redact_conformance.py
python3 -I memory-mcp/test_session_codex_conformance.py
```

The server runner validates source blobs, vector count/minimum, body hash, IDs,
Python expectations and the separate bounded D2/D3 line contract. Every normal
runner invocation also executes N8 in a scratch copy: one expected character is
changed, the body checksum is repaired, and the same runner must identify that
vector and exit 1. `--no-n8` is used only by that child to prevent recursion.
Thus the existing ai-memory CI runs N8 for both corpora (plan section 3.5); a
checksum error or environment failure is not accepted as the negative control.
Rust's runner remains S2. Client `test_corpus.py` independently checks vendor
provenance/count/hash and the live client source.

The pass limit is 8. The result after the last pass is returned even when it
is not a fixed point. Rust must reproduce that result exactly, including the
existing early stop when a pass leaves the value unchanged. The corpus tests
limits 2, 3, 4, 7 and 9 against the real Python implementation.

## Existing-test migration

At the actual baseline, AST enumeration finds 118 methods: 95 contract (C), 22
future Rust unit (U), and one retired helper wiring case (R). The plan's 116/93
count predates the two A1 ingest tests added by `527735d`; both are included.

| Original file | C moved | U retained | R removed |
|---|---:|---:|---:|
| test_breaker_fallback.py | 5 | 5 | 0 |
| test_cli_picker.py | 11 | 5 | 0 |
| test_codex.py | 9 | 0 | 0 |
| test_codex_review.py | 11 | 1 | 0 |
| test_config.py | 0 | 5 | 0 |
| test_helper.py | 13 | 3 | 1 |
| test_ingest.py | 26 | 1 | 0 |
| test_resume.py | 20 | 2 | 0 |

The C methods now execute the external client. U methods retain Python regression
coverage until S2 supplies their Rust equivalents. Inherited duplicate executions
and the obsolete no-curl wiring case are removed; bind failure and dead-helper
fallback remain explicit C cases. Two output-format tests, four state interop
tests and one provenance test bring the S0 contract suite to 102 tests. With the
22 unit tests, full discovery runs 124 tests, without replaying inherited methods.

## Merge and rollback

Merge the session-search vendor/contract PR first. The trusted GitHub App then
imports the corpora, generator and runners from that merged default-branch
commit into ai-memory, preserving every file's mode and blob OID. After the
App-authored import PR is approved and merged, merge setup's server-copy and
pin PR, following setup ADR 0013 and ADR 0014. Setup's `ai-memory.pin` must name a commit already on ai-memory main, and
all mapped copies must match its mode/OID. In SOURCE, the recorded blob OID is
the content authority. The recorded ai-memory branch commit is content provenance, not a main
ancestor or a deploy pin. These vendored files supply the App import; the
resulting ai-memory main commit will become the server pin. The import must
preserve the blobs. Do not manufacture a main ancestor or weaken the check.
The initial A1 session-search pin can use the already merged baseline commit.

R0 reverts this contract PR and setup's separate corpus/ai-memory-pin commit.
The independent A1 session-search pin commit can be reverted separately. No Rust
artifact or host switch is part of S0.
