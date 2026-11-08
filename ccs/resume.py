"""`ccs resume SESSION_KEY` (§6.6 Resume).

Trust rule: the directory `claude` starts in decides which .claude/settings.json
hooks and CLAUDE.md it loads, so it is code execution. The server (or anyone who
can write its ES or archive) never chooses it:
- local resume takes the cwd only from the local JSONL — a recorded cwd (or
  relocatedCwd) is accepted only when its encoding equals the JSONL's parent
  directory name and it exists here; the server's jsonl_path is a lookup hint,
  accepted only as ~/.claude/projects/<dir>/<sid>.jsonl, a regular non-symlink
  file inside realpath(~/.claude/projects);
- restore resumes in --to DIR or the current directory; the server's resume_cwd
  is offered only when it exists here AND the user confirms it at a TTY prompt
  that shows the path; --print or a non-TTY run needs --to;
- `claude` is resolved from PATH with a fixed argv; the only server string in
  it is the session_id, validated against ^[0-9a-f-]{36}$.

1. Local file: this host's session and its JSONL exists -> chdir(cwd from the JSONL), exec claude --resume.
2. No local file, archived and archive_complete -> restore the masked archive, then exec.
   Hardening: the project dir is computed locally (encode(local_cwd)); nothing the
   server sends is used as a path; session_id must match ^[0-9a-f-]{36}$; the
   tool-results tar is extracted member by member with tarfile's `data` filter
   (or an equivalent manual validation on Pythons without it) and every name must
   match TOOL_RESULT_NAME_RE; X-Archive-Sha256 is verified before the rename; a
   different existing file is never overwritten without --force.
3. Otherwise view-only (exit 4 with the reason).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import sys
import tarfile

from . import api as api_mod, codex, config as config_mod, extract, picker, util

RESTORED_NOTE = "restored masked transcript (secrets appear as [REDACTED:…])"


class ResumeError(Exception):
    """Precondition failure -> exit 4."""


def command_line(cwd: str, session_id: str, fork: bool, agent: str = "claude") -> str:
    if agent == "codex":
        return "cd %s && codex %s %s" % (shlex.quote(cwd), "fork" if fork else "resume", shlex.quote(session_id))
    cmd = "cd %s && claude --resume %s" % (shlex.quote(cwd), shlex.quote(session_id))
    return cmd + (" --fork-session" if fork else "")


def claude_argv(session_id: str, fork: bool):
    return ["claude", "--resume", session_id] + (["--fork-session"] if fork else [])


def exec_agent(cwd: str, session_id: str, fork: bool, do_print: bool, execvp=os.execvp, chdir=os.chdir,
                out=None, agent="claude") -> int:
    out = out or sys.stdout
    if not os.path.isdir(cwd):
        raise ResumeError("resume cwd %s does not exist on this host; not resuming from a different directory"
                          % cwd)
    if do_print:
        out.write(command_line(cwd, session_id, fork, agent) + "\n")
        return util.EXIT_OK
    validate_session_id(session_id)
    chdir(cwd)
    try:
        if agent == "codex":
            execvp("codex", ["codex", "fork" if fork else "resume", session_id])
        else:
            execvp("claude", claude_argv(session_id, fork))
    except FileNotFoundError:
        raise ResumeError("%s is not on PATH" % agent)
    return util.EXIT_OK  # only reached with a stubbed execvp


def validate_session_id(sid) -> str:
    if not isinstance(sid, str) or not util.SESSION_ID_RE.match(sid):
        raise ResumeError("refusing session_id %r: it does not match ^[0-9a-f-]{36}$" % (sid,))
    return sid


def rewrite_tool_result_paths(text: str, original_project_dir: str, session_id: str, new_dir: str) -> str:
    """Point absolute …/.claude/projects/<orig>/<sid>/tool-results/ strings at the restored copy."""
    pat = re.compile(r"(?:/[^\s\"'\\]*)?/\.claude/projects/%s/%s/tool-results/"
                     % (re.escape(original_project_dir), re.escape(session_id)))
    repl = new_dir.rstrip("/") + "/"
    return pat.sub(lambda _m: repl, text)


def _member_ok(m: tarfile.TarInfo) -> bool:
    return m.isfile() and util.TOOL_RESULT_NAME_RE.match(m.name) is not None


def extract_tool_results(tar_bytes: bytes, dest: str) -> int:
    """Extract only regular files with a safe flat name into `dest`. Returns the count."""
    count = 0
    os.makedirs(dest, mode=0o700, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        members = tf.getmembers()
        for m in members:
            if not _member_ok(m):
                raise ResumeError("refusing tool-results archive: unsafe member %r" % m.name)
        has_filter = hasattr(tarfile, "data_filter")
        for m in members:
            if has_filter:
                tf.extract(m, dest, filter="data")
            else:
                # Manual equivalent of the data filter for this flat, regular-file-only set.
                target = os.path.join(dest, m.name)
                if os.path.dirname(os.path.realpath(target)) != os.path.realpath(dest):
                    raise ResumeError("refusing tool-results member %r" % m.name)
                src = tf.extractfile(m)
                data = src.read() if src else b""
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            count += 1
    return count


def _file_sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


_PROJECT_DIR_RE = re.compile(r"^[A-Za-z0-9-]{1,255}$")


def local_jsonl_ok(path, sid: str) -> bool:
    """path is ~/.claude/projects/<dir>/<sid>.jsonl: no symlink anywhere below the root, regular file."""
    if not isinstance(path, str) or not path:
        return False
    root = os.path.abspath(util.projects_dir())
    p = os.path.abspath(path)
    parent = os.path.dirname(p)
    if os.path.basename(p) != sid + ".jsonl" or os.path.dirname(parent) != root:
        return False
    if os.path.islink(parent) or os.path.islink(p) or not util.is_within(p, root):
        return False
    try:
        os.close(util.open_regular(p, root))
    except (OSError, util.UnsafePath):
        return False
    return True


def find_local_jsonl(sid: str, hint=None):
    """The local JSONL for sid: the server's hint if it passes local_jsonl_ok, else a scan."""
    validate_session_id(sid)
    if local_jsonl_ok(hint, sid):
        return os.path.abspath(hint)
    root = util.projects_dir()
    try:
        dirs = [e.path for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return None
    for d in sorted(dirs):
        c = os.path.join(d, sid + ".jsonl")
        if local_jsonl_ok(c, sid):
            return c
    return None


def _restored_key(project_dir: str, sid: str) -> str:
    return "%s/%s" % (project_dir, sid)


def load_restored() -> dict:
    d = util.read_json(util.restored_path(), {})
    if not isinstance(d, dict) or d.get("version") != 1 or not isinstance(d.get("sessions"), dict):
        return {"version": 1, "sessions": {}}
    return d


def record_restore(sid: str, project_dir: str, cwd: str) -> None:
    """Remember where a restored session was placed; later resumes use only this cwd."""
    d = load_restored()
    d["sessions"][_restored_key(project_dir, sid)] = {
        "session_id": sid, "project_dir": project_dir, "cwd": os.path.realpath(cwd),
        "restored_at": util.iso(util.now_utc()),
    }
    util.atomic_write(util.restored_path(), json.dumps(d, sort_keys=True, indent=1), mode=0o600)


def local_resume_cwd(path: str, to_dir=None) -> str:
    """Where a local JSONL resumes.

    - A session this client restored resumes ONLY in the cwd recorded at restore
      time; the cwd fields inside a restored JSONL came from the server.
    - --to DIR is accepted when its realpath encodes to the JSONL's directory.
    - Otherwise the recorded cwd / relocatedCwd values are candidates. Encoding is
      lossy (/a/b and /a-b both become -a-b), so a candidate must also exist, be
      its own realpath (no symlink components) and be the only one that matches;
      two or more matches are refused.
    """
    abspath = os.path.abspath(path)
    project_dir = os.path.basename(os.path.dirname(abspath))
    sid = os.path.basename(abspath)[:-len(".jsonl")]
    rec = load_restored()["sessions"].get(_restored_key(project_dir, sid))
    if isinstance(rec, dict):
        cwd = rec.get("cwd")
        if not (isinstance(cwd, str) and cwd.startswith("/") and os.path.isdir(cwd)
                and util.encode_cwd(cwd) == project_dir):
            raise ResumeError("restored session %s was placed in %r, which is gone; pass --to DIR" % (sid, cwd))
        return cwd
    if to_dir:
        d = os.path.realpath(os.path.expanduser(to_dir))
        if not os.path.isdir(d) or util.encode_cwd(d) != project_dir:
            raise ResumeError("--to %s does not encode to %s, the directory this transcript lives in"
                              % (to_dir, project_dir))
        return d
    found = []
    for c in extract.scan(path).cwd_candidates:
        if (isinstance(c, str) and c.startswith("/") and util.encode_cwd(c) == project_dir
                and os.path.isdir(c) and os.path.realpath(c) == c and c not in found):
            found.append(c)
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        raise ResumeError("%d recorded directories match %s (%s); pass --to DIR to choose"
                          % (len(found), project_dir, ", ".join(found)))
    raise ResumeError("no cwd recorded in %s encodes to %s and exists on this host as a real path; not "
                      "resuming from a guessed directory (pass --to DIR)" % (path, project_dir))


def choose_restore_cwd(meta: dict, to_dir, do_print: bool, ask=input, isatty=None, err=None) -> str:
    """Where a restored session resumes: --to DIR, or (TTY only) a confirmed choice."""
    err = err or sys.stderr
    if to_dir:
        d = os.path.realpath(os.path.expanduser(to_dir))
        if not os.path.isdir(d):
            raise ResumeError("--to %s is not a directory" % to_dir)
        return d
    tty = sys.stdin.isatty() if isatty is None else isatty
    if do_print or not tty:
        raise ResumeError("this session must be restored from the archive; pass --to DIR to choose where it "
                          "resumes (required with --print or without a terminal)")
    here = os.path.realpath(os.getcwd())
    rc = meta.get("resume_cwd")
    if isinstance(rc, str) and rc.startswith("/") and os.path.isdir(rc):
        err.write("The session's original directory exists on this host:\n  %s\n"
                  "Starting an agent there loads that directory's project settings and instructions.\n" % rc)
        if ask("Resume in that directory? [y/N] ").strip().lower() in ("y", "yes"):
            return os.path.realpath(rc)
    ans = ask("Directory to resume in [%s]: " % here).strip()
    d = os.path.realpath(os.path.expanduser(ans)) if ans else here
    if not os.path.isdir(d):
        raise ResumeError("%s is not a directory" % d)
    return d


def restore(api, meta: dict, local_cwd: str, force: bool, session_key: str, out=None) -> str:
    """Download + verify + place the masked archive. Returns the session_id."""
    out = out or sys.stderr
    sid = validate_session_id(meta.get("session_id"))
    proj = util.encode_cwd(local_cwd)
    pdir = os.path.join(util.projects_dir(), proj)
    target = os.path.join(pdir, sid + ".jsonl")
    tmp = target + ".tmp"
    resp = api.get("/archive", params={"session_key": session_key}, timeout=120)
    if resp.status == 409:
        data = resp.json() or {}
        raise ResumeError("archive refused by the server: %s" % (data.get("error") or "conflict"))
    if resp.status != 200:
        raise ResumeError("archive download answered HTTP %d" % resp.status)
    want = (resp.header("X-Archive-Sha256") or "").strip().lower()
    got = hashlib.sha256(resp.body).hexdigest()
    if not re.match(r"^[0-9a-f]{64}$", want) or want != got:
        raise ResumeError("archive sha256 mismatch (header %s, body %s); nothing restored" % (want or "missing", got))
    tr_dir = os.path.join(pdir, sid, "tool-results")
    for pth in (pdir, os.path.join(pdir, sid), tr_dir, target):
        if os.path.islink(pth):
            raise ResumeError("%s is a symlink; refusing to restore through it" % pth)
    orig_proj = meta.get("project_dir")
    # Used only as a literal inside the rewrite pattern, and only in its expected shape.
    orig_proj = orig_proj if isinstance(orig_proj, str) and _PROJECT_DIR_RE.match(orig_proj) else ""
    text = resp.body.decode("utf-8", "replace")
    if orig_proj:
        text = rewrite_tool_result_paths(text, orig_proj, sid, tr_dir)
    data = text.encode("utf-8")
    if os.path.exists(target) and not force:
        if hashlib.sha256(data).hexdigest() != _file_sha(target):
            raise ResumeError("%s already exists and differs from the archive; pass --force to replace it" % target)
    os.makedirs(pdir, mode=0o700, exist_ok=True)
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        tres = api.get("/archive/tool-results", params={"session_key": session_key}, timeout=120)
        if tres.status == 200 and tres.body:
            extract_tool_results(tres.body, tr_dir)
        elif tres.status not in (200, 404):
            raise ResumeError("tool-results download answered HTTP %d" % tres.status)
        os.replace(tmp, target)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)
    record_restore(sid, proj, local_cwd)
    out.write(RESTORED_NOTE + "\n")
    return sid


def restore_codex(api, meta: dict, local_cwd: str, force: bool, session_key: str, out=None) -> str:
    """Restore native rollout history; local configuration chooses permissions.

    turn_context stores the originating host's permission and cwd settings.
    Omitting it retains response history without importing those settings.
    """
    import datetime

    out = out or sys.stderr
    sid = validate_session_id(meta.get("session_id"))
    resp = api.get("/archive", params={"session_key": session_key}, timeout=120)
    if resp.status != 200:
        raise ResumeError("archive download answered HTTP %d" % resp.status)
    want = (resp.header("X-Archive-Sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want) or hashlib.sha256(resp.body).hexdigest() != want:
        raise ResumeError("archive sha256 mismatch; nothing restored")
    lines = []
    try:
        from . import session_codex

        records = [extract.loads_strict(raw.decode("utf-8")) for raw in resp.body.split(b"\n") if raw.strip()]
        first = records[0]
        if first.get("type") != "session_meta" or first["payload"].get("id") != sid:
            raise ValueError("session metadata mismatch")
        rebuild_display = first["payload"].get("history_mode") == "paginated"
        has_display_events = any(isinstance(r, dict) and r.get("type") == "event_msg"
                                 and isinstance(r.get("payload"), dict)
                                 and r["payload"].get("type") in ("user_message", "agent_message")
                                 for r in records)
        index_state = session_codex.IndexState(sid)
        own_start = None
        for index, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise ValueError("non-object record")
            owned = index_state.accept(rec)
            if index and owned and own_start is None:
                own_start = len(lines)
            # Forks copy the parent's metadata after their own first header.
            # Only the first header describes the session being restored.
            if index and rec.get("type") == "session_meta":
                continue
            if rec.get("type") in ("turn_context", "world_state"):
                continue
            if rec.get("type") == "event_msg" and isinstance(rec.get("payload"), dict) \
                    and rec["payload"].get("type") == "thread_settings_applied":
                continue
            if rebuild_display and rec.get("type") == "event_msg" and isinstance(rec.get("payload"), dict) \
                    and rec["payload"].get("type") in ("user_message", "agent_message"):
                continue
            if rec.get("type") == "session_meta":
                rec["payload"].update(cwd=local_cwd, session_id=sid, history_mode="legacy",
                                      runtime_workspace_roots=[local_cwd])
            # Paginated rollouts mirror model-visible response items, while
            # their display items live in SQLite. Rebuild legacy display events
            # so a restored CLI also shows the conversation before continuing.
            payload = rec.get("payload")
            if (rebuild_display or not has_display_events) and rec.get("type") == "response_item" and isinstance(payload, dict) \
                    and payload.get("type") == "message" and payload.get("role") in ("user", "assistant") \
                    and payload.get("channel") != "analysis":
                common = session_codex.normalize(rec)
                text = "\n".join(b.get("text", "") for b in common.get("message", {}).get("content", []))
                if text:
                    event = {"type": "event_msg", "timestamp": rec.get("timestamp"),
                             "payload": {"type": "user_message" if payload["role"] == "user" else "agent_message",
                                         "message": text, "images": [], "local_images": [], "text_elements": []}}
                    lines.append(event)
            lines.append(rec)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        raise ResumeError("invalid Codex archive; nothing restored")
    if (first["payload"].get("forked_from_id") or "subagent_history_start_ordinal" in first["payload"]
            or "ccs_index_start_ordinal" in first["payload"]):
        # Restoring removes settings/ancestor headers and may add display rows.
        # Preserve the indexing boundary in the transformed file's coordinates.
        first["payload"]["ccs_index_start_ordinal"] = own_start if own_start is not None else len(lines)
        if "subagent_history_start_ordinal" in first["payload"]:
            first["payload"]["subagent_history_start_ordinal"] = first["payload"]["ccs_index_start_ordinal"]
    for ordinal, rec in enumerate(lines):
        rec["ordinal"] = ordinal
    data = "\n".join(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) for rec in lines) + "\n"
    now = datetime.datetime.now(datetime.timezone.utc)
    root = codex.sessions_dir()
    pdir = os.path.join(root, now.strftime("%Y"), now.strftime("%m"), now.strftime("%d"))
    target = os.path.join(pdir, "rollout-%s-%s.jsonl" % (now.strftime("%Y-%m-%dT%H-%M-%S"), sid))
    existing = codex.find_local(sid)
    if existing:
        target = existing
        pdir = os.path.dirname(target)
    check = pdir
    while True:
        if os.path.islink(check):
            raise ResumeError("%s is a symlink; refusing to restore through it" % check)
        if check == root:
            break
        check = os.path.dirname(check)
    if os.path.lexists(target):
        if os.path.islink(target) or not os.path.isfile(target):
            raise ResumeError("unsafe Codex restore target")
        if not force and _file_sha(target) != hashlib.sha256(data.encode()).hexdigest():
            raise ResumeError("%s already exists and differs from the archive; pass --force to replace it" % target)
    util.atomic_write(target, data)
    out.write(RESTORED_NOTE + "\n")
    return sid


def codex_resume_cwd(path: str, to_dir=None) -> str:
    cwd = to_dir or codex.metadata(path).get("cwd")
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isdir(cwd):
        raise ResumeError("Codex session directory does not exist here; pass --to DIR")
    return os.path.realpath(cwd)


def resume(session_key: str, do_print: bool = False, fork: bool = False, to_dir: str | None = None,
           force: bool = False, api_factory=None, execvp=os.execvp, chdir=os.chdir, ask=input, isatty=None,
           out=None) -> int:
    out = out or sys.stdout
    try:
        if session_key.startswith("local:"):
            path = session_key[len("local:"):]
            if codex.is_path(path):
                info = codex.classify(path)
                if info is None:
                    raise ResumeError("local Codex transcript is missing or unsafe")
                return exec_agent(codex_resume_cwd(path, to_dir), info["session_id"], fork,
                                   do_print, execvp, chdir, out, agent="codex")
            sid = os.path.basename(path)[:-len(".jsonl")] if path.endswith(".jsonl") else ""
            validate_session_id(sid)
            if not local_jsonl_ok(path, sid):
                raise ResumeError("local transcript %s no longer exists or is not a plain file under %s"
                                  % (path, util.projects_dir()))
            return exec_agent(local_resume_cwd(path, to_dir), sid, fork, do_print, execvp, chdir, out)
        try:
            cfg = config_mod.load()
        except config_mod.ConfigError as e:
            sys.stderr.write("ccs: %s\n" % e)
            return util.EXIT_UNREACHABLE
        api = (api_factory or api_mod.Api)(cfg)
        try:
            resp = api.get("/preview", params={"session_key": session_key, "q": ""}, timeout=10)
        except (api_mod.Unreachable, api_mod.AuthError) as e:
            sys.stderr.write("ccs: server unreachable: %s\n" % e)
            return util.EXIT_UNREACHABLE
        if resp.status == 404:
            raise ResumeError("unknown session_key %s" % session_key)
        if resp.status != 200:
            sys.stderr.write("ccs: preview answered HTTP %d\n" % resp.status)
            return util.EXIT_UNREACHABLE
        meta = (resp.json() or {}).get("session") or {}
        sid = validate_session_id(meta.get("session_id"))
        agent = "codex" if str(meta.get("entrypoint") or "").startswith("codex-") else "claude"
        if meta.get("host") == cfg.host_label:
            local = (codex.find_local(sid, hint=meta.get("jsonl_path")) if agent == "codex"
                     else find_local_jsonl(sid, hint=meta.get("jsonl_path")))
            if local:
                cwd = codex_resume_cwd(local, to_dir) if agent == "codex" else local_resume_cwd(local, to_dir)
                return exec_agent(cwd, sid, fork, do_print, execvp, chdir, out, agent=agent)
        if meta.get("archived") and meta.get("archive_complete"):
            local_cwd = choose_restore_cwd(meta, to_dir, do_print, ask=ask, isatty=isatty)
            try:
                restore_fn = restore_codex if agent == "codex" else restore
                sid = restore_fn(api, meta, local_cwd, force, session_key)
            except api_mod.Unreachable as e:
                sys.stderr.write("ccs: server unreachable: %s\n" % e)
                return util.EXIT_UNREACHABLE
            return exec_agent(local_cwd, sid, fork, do_print, execvp, chdir, out, agent=agent)
        raise ResumeError("view-only: %s" % (picker.view_only_reason(meta, cfg.host_label) or "not resumable"))
    except ResumeError as e:
        sys.stderr.write("ccs: %s\n" % e)
        return util.EXIT_RESUME
