"""C7 picker (§6.6): fzf wiring, the `_backend` / `_preview` callbacks, toggles and debounce.

fzf runs with --disabled, so fzf itself never filters: every keystroke reloads
`ccs _backend {q}`, which asks the server (or the C9 fallback) and prints rows

    <session_key>\\t<mark><age> <host> <short cwd> │ <title> │ <hits>

Field 1 is hidden (--with-nth=2..) and is what `_preview` and `resume` get.
Toggles (ctrl-s semantic, ctrl-d deep, ctrl-a all) are kept in the fzf prompt
(`ccs:sda> `), which fzf exports to callbacks as $FZF_PROMPT; fzf builds that
predate $FZF_PROMPT fall back to the per-picker state file in $CCS_PICK_STATE.

When curl is on PATH, `run` serves those callbacks from the picker process itself
(ccs.helper, a unix socket in the 0700 picker temp dir) and fzf calls them with
`curl --unix-socket … || ccs _backend {q}`, so a keystroke no longer pays for a
Python start and the HTTP-stack imports. The per-process commands stay as the
fallback and as the wiring when curl is missing or the socket cannot be bound.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from . import api as api_mod, config as config_mod, extract, fallback, util

TOGGLES = "sda"  # semantic, deep, all
_PROMPT_RE = re.compile(r"^ccs(?::([sda]{1,3}))?> $")
SEP = " │ "
DEBOUNCE = 0.4
FUSED_TIMEOUT = 2.0
LIMIT = 50


# --- prompt / toggle state ------------------------------------------------

def prompt_for(flags) -> str:
    f = "".join(c for c in TOGGLES if c in set(flags))
    return "ccs:%s> " % f if f else "ccs> "


def parse_prompt(prompt) -> set | None:
    if not isinstance(prompt, str):
        return None
    m = _PROMPT_RE.match(prompt)
    if not m:
        return None
    return set(m.group(1) or "")


def current_flags(env=None) -> set:
    env = os.environ if env is None else env
    flags = parse_prompt(env.get("FZF_PROMPT"))
    if flags is not None:
        return flags
    path = env.get("CCS_PICK_STATE")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                flags = parse_prompt(fh.read())
        except OSError:
            flags = None
        if flags is not None:
            return flags
    return set(json.loads(env.get("CCS_PICK") or "{}").get("flags") or "")


def toggle(letter: str, env=None) -> str:
    """`ccs _toggle X`: flip one toggle, persist it, print the new prompt."""
    env = os.environ if env is None else env
    flags = current_flags(env)
    if letter in TOGGLES:
        flags ^= {letter}
    p = prompt_for(flags)
    path = env.get("CCS_PICK_STATE")
    if path:
        util.atomic_write(path, p)
    return p


# --- fzf argv ---------------------------------------------------------------

def launcher() -> str:
    return os.environ.get("CCS_LAUNCHER") or shutil.which("ccs") or "ccs"


def fzf_argv(query: str, flags, self_cmd: str, banner: str | None = None, listen: bool = True,
             helper_sock: str | None = None):
    """With `helper_sock`, every callback goes through `curl --unix-socket` to the picker's
    own helper (ccs.helper) and falls back to the per-process command if curl fails."""
    s = shlex.quote(self_cmd)

    def cmd(sub, args, path, fields):
        plain = "%s %s %s" % (s, sub, args)
        if not helper_sock:
            return plain
        from . import helper as helper_mod

        return "%s || %s" % (helper_mod.curl_cmd(helper_sock, path, fields), plain)

    def toggle_cmd(letter):
        return cmd("_toggle", letter, "/toggle", [("letter", letter)])

    backend = "reload(%s)" % cmd("_backend", "{q}", "/backend", [("q", "{q}")])
    preview_cmd = cmd("_preview", "{1} {q}", "/preview", [("key", "{1}"), ("q", "{q}")])
    argv = [
        "fzf", "--disabled", "--ansi", "--layout=reverse", "--delimiter=\t", "--with-nth=2..",
        "--prompt", prompt_for(flags), "--query", query or "",
        "--bind", "start:" + backend,
        "--bind", "change:" + backend,
        "--bind", "ctrl-s:transform-prompt(%s)+%s" % (toggle_cmd("s"), backend),
        "--bind", "ctrl-d:transform-prompt(%s)+%s" % (toggle_cmd("d"), backend),
        "--bind", "ctrl-a:transform-prompt(%s)+%s" % (toggle_cmd("a"), backend),
        "--preview", preview_cmd,
        "--preview-window", "down,45%,wrap",
        "--expect=ctrl-y",
    ]
    if listen:
        argv.append("--listen")
    if banner:
        argv += ["--header", banner]
    return argv


# --- rows -------------------------------------------------------------------

def _clean(text, width=None) -> str:
    t = " ".join(str(text or "").replace("\t", " ").split())
    if width and len(t) > width:
        t = t[:width - 1] + "…"
    return t


def resumable(s: dict, local_host: str) -> bool:
    if s.get("host") == local_host and s.get("jsonl_exists"):
        return True
    return bool(s.get("archived") and s.get("archive_complete"))


def server_row(s: dict, local_host: str, now: float | None = None) -> str:
    now = time.time() if now is None else now
    ts = util.parse_ts(s.get("updated_at"))
    age = util.human_age(now - ts) if ts else "?"
    mark = "  " if resumable(s, local_host) else "· "
    hits = s.get("hit_count")
    tail = SEP + str(hits) if isinstance(hits, int) and hits > 0 else ""
    agent = " [Codex]" if str(s.get("entrypoint") or "").startswith("codex-") else ""
    return "%s\t%s%s %s %s%s%s%s" % (
        _clean(s.get("session_key")), mark, age, _clean(s.get("host")), util.short_cwd(s.get("cwd") or ""),
        SEP, _clean(s.get("title") or "(untitled)", 80) + agent, tail)


def local_row(ls, host: str, now: float | None = None) -> str:
    now = time.time() if now is None else now
    tail = SEP + str(ls.hits) if ls.hits else ""
    return "local:%s\t  %s %s %s%s%s%s" % (
        ls.path, util.human_age(now - ls.mtime), host, util.short_cwd(ls.cwd), SEP,
        _clean(ls.title or "(untitled)", 80) + (" [Codex]" if getattr(ls, "agent", "claude") == "codex" else ""), tail)


def banner_row(text: str) -> str:
    return "-\t\x1b[33m%s\x1b[0m" % text


# --- backend ------------------------------------------------------------------

def pick_opts(env=None) -> dict:
    env = os.environ if env is None else env
    try:
        d = json.loads(env.get("CCS_PICK") or "{}")
    except ValueError:
        d = {}
    return d if isinstance(d, dict) else {}


def search_body(q: str, flags, opts: dict, mode: str | None = None) -> dict:
    q = (q or "").strip()
    body = {
        "q": q if len(q) >= 2 else "",
        "mode": mode or ("hybrid" if "s" in flags else "lexical"),
        "deep": "d" in flags,
        "include_headless": "a" in flags,
        "include_sidechain": bool(opts.get("sidechain")),
        "limit": LIMIT,
    }
    if opts.get("hosts"):
        body["hosts"] = list(opts["hosts"])
    if opts.get("cwd_prefix"):
        body["cwd_prefix"] = opts["cwd_prefix"]
    if opts.get("since"):
        body["since"] = opts["since"]
    return body


def offline_rows(q: str, flags, opts: dict, host: str, env=None) -> list:
    env = os.environ if env is None else env
    since = util.parse_ts(opts.get("since")) if opts.get("since") else None
    if opts.get("hosts") and host not in opts["hosts"]:
        return [banner_row(fallback.BANNER), banner_row("(this host is not in --host; nothing local to show)")]
    try:
        found = fallback.search(q, include_headless="a" in flags, cwd_prefix=opts.get("cwd_prefix"),
                                since_epoch=since, exclude_session_id=util.current_session_id(env))
    except fallback.FallbackUnavailable as e:
        return [banner_row(fallback.BANNER), banner_row(str(e))]
    return [banner_row(fallback.BANNER)] + [local_row(s, host) for s in found]


def _host_label(cfg) -> str:
    return cfg.host_label if cfg else (os.uname().nodename.split(".")[0].lower() or "local")


def server_rows(cfg, api, q, flags, opts, env=None, mode=None, timeout=None) -> list:
    env = os.environ if env is None else env
    body = search_body(q, flags, opts, mode=mode)
    resp = api.post("/search", body, timeout=api_mod.Breaker.TIMEOUT if timeout is None else timeout)
    if resp.status != 200:
        raise api_mod.Unreachable("/search answered HTTP %d" % resp.status)
    data = resp.json() or {}
    me = util.current_session_id(env)
    rows = []
    for s in data.get("sessions") or []:
        if not isinstance(s, dict) or (me and s.get("session_id") == me):
            continue
        rows.append(server_row(s, cfg.host_label))
    if data.get("degraded"):
        rows.insert(0, banner_row("degraded: %s" % _clean(data["degraded"], 40)))
    return rows


def backend(q: str, env=None, api_factory=None, breaker=None, out=None, fuse_scheduler=None) -> int:
    """`ccs _backend Q` — print rows for fzf. Never raises; prints something."""
    env = os.environ if env is None else env
    out = out or sys.stdout
    flags = current_flags(env)
    opts = pick_opts(env)
    try:
        cfg = config_mod.load()
    except config_mod.ConfigError:
        cfg = None
    host = _host_label(cfg)
    breaker = breaker or api_mod.Breaker()
    if opts.get("offline") or cfg is None or breaker.is_open():
        rows = offline_rows(q, flags, opts, host, env)
    else:
        api = (api_factory or api_mod.Api)(cfg)
        # Semantic on: lexical rows now, fused rows after the idle window when
        # fzf exposes its --listen port; without the port, hybrid inline.
        fused_later = "s" in flags and bool(env.get("FZF_PORT"))
        hybrid_inline = "s" in flags and not fused_later
        try:
            rows = server_rows(cfg, api, q, flags, opts, env, mode="lexical" if fused_later else None,
                               timeout=FUSED_TIMEOUT if hybrid_inline else None)
            breaker.record_success()
        except (api_mod.Unreachable, api_mod.AuthError, config_mod.ConfigError):
            breaker.record_failure()
            rows = offline_rows(q, flags, opts, host, env)
            fused_later = False
        if fused_later:
            (fuse_scheduler or schedule_fuse)(q, env)
    out.write("\n".join(rows) + ("\n" if rows else ""))
    out.flush()
    return util.EXIT_OK


# --- semantic debounce ----------------------------------------------------------

def _seq_path(env) -> str:
    return os.path.join(util.state_dir(), "picker-%s.seq" % re.sub(r"[^0-9]", "", env.get("FZF_PORT", "0")))


def schedule_fuse(q: str, env) -> None:
    """Record this keystroke and start a detached `_fuse` that fires after ≥400 ms idle."""
    seq = "%d-%s" % (time.time_ns(), secrets.token_hex(4))
    util.atomic_write(_seq_path(env), seq)
    try:
        subprocess.Popen([launcher(), "_fuse", seq, q], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, env=dict(env))
    except OSError:
        pass


def fuse(seq: str, q: str, env=None, api_factory=None, sleep=time.sleep, post=None) -> int:
    """`ccs _fuse SEQ Q`: after the idle window, swap in the hybrid (RRF-fused) rows."""
    env = os.environ if env is None else env
    sleep(DEBOUNCE)
    path = _seq_path(env)
    try:
        if _read(path) != seq:
            return util.EXIT_OK  # a newer keystroke superseded this one
    except OSError:
        return util.EXIT_OK
    try:
        cfg = config_mod.load()
        api = (api_factory or api_mod.Api)(cfg)
        rows = server_rows(cfg, api, q, current_flags(env), pick_opts(env), env, mode="hybrid",
                           timeout=FUSED_TIMEOUT)
    except (api_mod.Unreachable, api_mod.AuthError, config_mod.ConfigError):
        return util.EXIT_OK  # lexical rows stay on screen
    try:
        if _read(path) != seq:
            return util.EXIT_OK
    except OSError:
        return util.EXIT_OK
    cache = os.path.join(util.state_dir(), "picker-%s.rows" % re.sub(r"[^0-9]", "", env.get("FZF_PORT", "0")))
    util.atomic_write(cache, "\n".join(rows) + "\n")
    action = "reload(cat %s)" % shlex.quote(cache)
    (post or _post_fzf)(env, action)
    return util.EXIT_OK


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _post_fzf(env, action: str) -> None:
    port = re.sub(r"[^0-9]", "", env.get("FZF_PORT", ""))
    if not port:
        return
    req = urllib.request.Request("http://127.0.0.1:%s" % port, data=action.encode("utf-8"), method="POST")
    if env.get("FZF_API_KEY"):
        req.add_header("x-api-key", env["FZF_API_KEY"])
    try:
        urllib.request.urlopen(req, timeout=1).close()
    except OSError:
        pass


# --- preview ----------------------------------------------------------------------

def _hl(fragment: str) -> str:
    return re.sub(r"</?em>", lambda m: "\x1b[1m" if m.group(0) == "<em>" else "\x1b[0m", fragment or "")


def view_only_reason(s: dict, local_host: str) -> str | None:
    if resumable(s, local_host):
        return None
    if s.get("archived") and not s.get("archive_complete"):
        return "archive incomplete"
    if not s.get("archived"):
        return "not archived (subagent)" if s.get("kind") == "subagent" or s.get("is_sidechain") else "not archived"
    return "older than retention"


def preview(key: str, q: str, env=None, api_factory=None, breaker=None, out=None) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    if key == "-":
        out.write("Offline fallback: only this host's local transcripts are searched (text only, no archive,\n"
                  "no other hosts, no semantic). Resume works for local files only.\n")
        return util.EXIT_OK
    if key.startswith("local:"):
        ls = extract.scan(key[len("local:"):], q)
        out.write("\x1b[1m%s\x1b[0m\n%s\n%s\n\n" % (_clean(ls.title or "(untitled)"), ls.resume_cwd, ls.path))
        ql = (q or "").casefold()
        for role, text in ls.last_texts:
            if not ql or ql in text.casefold():
                out.write("[%s] %s\n\n" % (role, _clean(text, 400)))
        return util.EXIT_OK
    breaker = breaker or api_mod.Breaker()
    try:
        cfg = config_mod.load()
    except config_mod.ConfigError as e:
        out.write("ccs: %s\n" % e)
        return util.EXIT_OK
    if breaker.is_open():
        out.write("server unavailable (circuit open); preview needs the server\n")
        return util.EXIT_OK
    api = (api_factory or api_mod.Api)(cfg)
    try:
        resp = api.get("/preview", params={"session_key": key, "q": q or ""}, timeout=1.5)
    except (api_mod.Unreachable, api_mod.AuthError) as e:
        breaker.record_failure()
        out.write("server unreachable: %s\n" % e)
        return util.EXIT_OK
    if resp.status != 200:
        out.write("preview: HTTP %d\n" % resp.status)
        return util.EXIT_OK
    data = resp.json() or {}
    s = data.get("session") or {}
    out.write("\x1b[1m%s\x1b[0m\n" % _clean(s.get("title") or "(untitled)"))
    out.write("%s  %s  %s\n" % (_clean(s.get("host")), s.get("resume_cwd") or s.get("cwd") or "?",
                                _clean(s.get("updated_at"))))
    reason = view_only_reason(s, cfg.host_label)
    out.write(("view-only: %s\n" % reason) if reason else "Enter: resume  ctrl-y: print command\n")
    out.write("\n")
    for sn in data.get("snippets") or []:
        if isinstance(sn, dict):
            out.write("[%s %s] %s\n\n" % (_clean(sn.get("ts"), 20), _clean(sn.get("role"), 10),
                                          _hl(" ".join(str(sn.get("fragment") or "").split()))))
    return util.EXIT_OK


# --- the picker itself ---------------------------------------------------------------

def start_helper(env, tmpdir: str, which=shutil.which, api_factory=None):
    """-> (helper, sock_dir) or (None, None) when curl is missing or the socket cannot be bound."""
    if not which("curl"):
        return None, None
    try:
        from . import helper as helper_mod
    except ImportError:  # a partial install without helper.py keeps the per-process wiring
        return None, None

    sock_dir = tmpdir
    if len(os.path.join(tmpdir, helper_mod.SOCK_NAME).encode("utf-8")) > helper_mod.MAX_SOCK_PATH:
        try:
            sock_dir = tempfile.mkdtemp(prefix="ccs-", dir="/tmp")  # a long $TMPDIR would overflow sun_path
        except OSError:
            return None, None
    h = helper_mod.Helper(env, api_factory=api_factory)
    try:
        os.chmod(sock_dir, 0o700)
        h.start(sock_dir)
    except (OSError, ValueError):
        h.close()
        if sock_dir != tmpdir:
            shutil.rmtree(sock_dir, ignore_errors=True)
        return None, None
    return h, sock_dir


class _Terminated(BaseException):
    pass


def _raise_terminated(signum, frame):
    raise _Terminated(signum)


def _trap_signals():
    """SIGTERM / SIGHUP unwind through `finally` so the socket directory is removed."""
    import signal
    import threading

    if threading.current_thread() is not threading.main_thread():
        return []
    saved = []
    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            saved.append((sig, signal.signal(sig, _raise_terminated)))
        except (OSError, ValueError):
            pass
    return saved


def _restore_signals(saved):
    import signal

    for sig, handler in saved:
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError):
            pass


def run(query: str, flags, opts: dict, do_print: bool, fork: bool, runner=subprocess.run, which=shutil.which,
        resume_fn=None, api_factory=None) -> int:
    if not which("fzf"):
        sys.stderr.write("ccs: fzf is not installed; the picker needs it (ccs resume KEY still works)\n")
        return util.EXIT_UNREACHABLE
    tmpdir = tempfile.mkdtemp(prefix="ccs-pick-")
    helper, sock_dir = None, None
    saved = _trap_signals()
    try:
        state = os.path.join(tmpdir, "prompt")
        util.atomic_write(state, prompt_for(flags))
        env = dict(os.environ)
        env["CCS_PICK"] = json.dumps(dict(opts, flags="".join(sorted(flags))))
        env["CCS_PICK_STATE"] = state
        env["CCS_LAUNCHER"] = launcher()
        env.setdefault("FZF_API_KEY", secrets.token_hex(16))
        banner = fallback.BANNER if opts.get("offline") else None
        helper, sock_dir = start_helper(env, tmpdir, which=which, api_factory=api_factory)
        argv = fzf_argv(query, flags, env["CCS_LAUNCHER"], banner=banner,
                        helper_sock=helper.path if helper else None)
        proc = runner(argv, stdout=subprocess.PIPE, env=env)
    except _Terminated as e:
        return 128 + int(e.args[0])
    finally:
        if helper is not None:
            helper.close()
        if sock_dir and sock_dir != tmpdir:
            shutil.rmtree(sock_dir, ignore_errors=True)
        shutil.rmtree(tmpdir, ignore_errors=True)
        _restore_signals(saved)
    if proc.returncode in (1, 130):
        return util.EXIT_OK  # no match / cancelled
    if proc.returncode != 0:
        sys.stderr.write("ccs: fzf exited %d\n" % proc.returncode)
        return util.EXIT_UNREACHABLE
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    key_pressed = lines[0] if lines else ""
    selected = lines[1] if len(lines) > 1 else ""
    session_key = selected.split("\t", 1)[0]
    if not session_key or session_key == "-":
        return util.EXIT_OK
    from . import resume as resume_mod

    fn = resume_fn or resume_mod.resume
    return fn(session_key, do_print=do_print or key_pressed == "ctrl-y", fork=fork)
