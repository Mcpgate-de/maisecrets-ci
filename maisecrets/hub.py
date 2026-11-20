"""The /maisecrets panel of the Claude Code mod (claude-mod/maisecrets-mod.mjs): its rows and each change the person
presses there, through `hooks/dispatch.py mod-settings`.

A press in the panel is the person's own act: the model cannot press a mod's button, and a tool call that names the
entry is refused (shell_commands.py, the mod's entries). Each change goes through the writer of the typed path
(settings.apply_typed, Vault.forget, not_a_secret.allow_typed), so the panel enforces what a typed prompt enforces:
the policy, the allowed keys and values, the shape of a key, the two steps for a key type on the allow list. No answer
holds a stored value: a row carries the key and the masked form only. What stays open is C22's limit of one user: a
program of the same user can start the entry, or write config.json, without a tool call that names it
(docs/THREAT-MODEL.md, C22).
"""
from __future__ import annotations

import os
import re

from .home import HOME, load_config
from .settings import (_CHOICES, _LIST_KEYS, LABEL, MAIN_GROUPS, MORE_GROUPS, TITLE, TTL_LABELS,
                       TTL_WORDS, _mark, _regions_of, _shown, apply_typed, region_codes, ttl_word)
PANE_ROUTE = "settings pane"
VALUES_PAGE = 20
_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,40}_c\d{1,9}")          # a stored value's key, as /maisecrets:list shows it
_SETTING_RE = re.compile(r"[a-z][a-z_]{1,40}")
_SERVER_RE = re.compile(r"[\w.-]{1,64}")
# the sentence the panel sends with "forget all" after the person's yes: a question that forgot to ask cannot wipe
WIPE_CONFIRM = "forget every stored value"


def _pane_choices(key: str, cfg: dict) -> list:
    if key == "regions":
        return ["auto"] + region_codes()
    if key in _CHOICES:
        return list(_CHOICES[key])
    if isinstance(cfg.get(key), bool):
        return ["on", "off"]
    return []


def pane_rows(cfg: dict | None = None, show_all: bool = False) -> list:
    cfg = cfg if cfg is not None else load_config()
    groups = []
    for title, keys in MAIN_GROUPS + (MORE_GROUPS if show_all else ()):
        items = []
        for key in keys:
            value = _shown(cfg.get(key), key)
            labels, values, hint = {}, None, ""
            if key == "ttl_seconds":
                value = ttl_word(cfg.get(key)) or value
                labels = {w: TTL_LABELS[w] for w in TTL_WORDS}
            if key == "regions":
                values = _regions_of(cfg.get(key))
                value = ", ".join(values)
            items.append({"key": key, "label": LABEL.get(key, TITLE.get(key, key)), "labels": labels,
                          "values": values, "multi": key == "regions", "note": hint,
                          "value": value, "choices": _pane_choices(key, cfg),
                          "mark": _mark(key, cfg), "locked": key in (cfg.get("policy_keys") or []),
                          "list": key in _LIST_KEYS,
                          "count": len(cfg.get(key) or []) if key in _LIST_KEYS else 0})
        groups.append({"title": title, "items": items})
    return groups


# a tool call the mod saw counts only after this many seconds: its PreToolUse row comes within the call
TOOL_CALL_GRACE = 2.0


def pane_status(session: str, tool_call_at: float = 0.0) -> dict:
    """The verdict /maisecrets:status prints first, for the session of the pane: its head line and the names of the
    checks that failed. The hooks check differs: the pane is no tool call, and no row of this session in hooks.log is
    no proof that a hook failed (before the first tool call a session can have none, and the capped log can drop a
    session's rows), so it is a note. A positive signal of a failure gives FAIL: the self-test, or the last tool call
    of this session that the mod saw (`tool_call_at`, its start in epoch seconds) with no pre-tool row at or after it.
    The PreToolUse hook writes that row within the call, so the newest pre-tool row of the session is compared, not a
    count of rows (hooks.log keeps 2000 lines). Its time is cut to whole seconds, so a row of the call's own second
    is the earliest a real row can have. Limit: a row of an earlier call in the same second hides a miss; a hook that
    stops running stops for the whole session, so the next call in a later second shows it."""
    import time
    from pathlib import Path
    from . import selftest
    from . import status_verdict as sv
    from .codex_vault import codex_home
    root = Path(__file__).resolve().parent.parent
    claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    log = HOME / "hooks.log"
    session = session if isinstance(session, str) and session else None

    def hooks() -> "sv.Check":
        runs = sv.last_runs(log, session) if session else {}
        if not session:
            return sv.Check("warn", "hooks", "no session id", None, None)
        if tool_call_at > 0 and time.time() - tool_call_at > TOOL_CALL_GRACE \
                and runs.get("pre-tool", 0) < int(tool_call_at):
            return sv.Check("FAIL", "hooks", "did not run for a tool call", sv.reload_next("claude"),
                            f"the last tool call of this session started {sv.ago(time.time() - tool_call_at)}; "
                            "hooks.log holds no tool-call row of it")
        if not runs:
            return sv.Check("warn", "hooks", "not seen in this session yet", "/maisecrets:status",
                            "hooks.log holds no row of this session (none before its first tool call)")
        return sv.Check("ok", "hooks", "ran in this session", None, ", ".join(sorted(runs)))

    t0 = time.time()
    version = sv.installed_version(root)
    checks = [sv._guarded(hooks),
              sv._guarded(lambda: sv.version_verdict(sv.newest(root, claude_dir, codex_home()))),
              sv._guarded(sv.store_verdict),
              sv._guarded(sv.incidents_verdict),
              sv._guarded(lambda: selftest.verdict(None, [session] if session else [], version, client="claude"))]
    names = sv.names_verdict()          # the name source: a warn when it is set and cannot be used
    if names:
        checks.append(names)
    head = sv.head_line(version, checks, "claude").split(" \u00b7 ")[0]
    failed = [c.name for c in checks if c.state == "FAIL"]
    if failed:
        head += " \u2192 /maisecrets:status (" + ", ".join(failed) + ")"
    notes = [{"name": c.name, "fact": c.fact, "next": c.next or ""} for c in checks if c.state == "warn"]
    return {"line": head, "notes": notes, "ms": round((time.time() - t0) * 1000)}


def _age(seconds: float) -> str:
    seconds = max(0, seconds)
    return f"{int(seconds // 60)}m" if seconds < 3600 else f"{int(seconds // 3600)}h" if seconds < 86400 \
        else f"{int(seconds // 86400)}d"


def pane_values(offset: int = 0) -> dict:
    """The stored values, newest first, a page of VALUES_PAGE: key, type, masked form, age, uses, expiry. No value."""
    import time
    from .vault import Vault
    v = Vault()
    rows = sorted(v.list(), key=lambda e: -e.created)
    now = time.time()
    page = rows[max(0, offset):max(0, offset) + VALUES_PAGE]
    return {"rows": [{"key": e.key, "type": e.type, "shown": e.display or "-", "age": _age(now - e.created),
                      "uses": e.uses, "expires": "expired" if e.purged else _age(e.expires - now),
                      "live": not e.purged} for e in page],
            "total": len(rows), "offset": max(0, offset), "test_mode": bool(v.backend.test_mode)}


def pane_forget(key: str) -> str:
    from .vault import Vault
    status = Vault().forget(key, route=PANE_ROUTE, typed=True)
    return {"ok": f"Forgot {key}. A placeholder for it no longer works anywhere.",
            "unknown": f"There is no {key}."}.get(status, f"The store refused to delete {key}; nothing was changed.")


def pane_forget_all() -> str:
    """Every stored value, one forget each (its index row and its destination record go with it, and each writes its
    events.log line). The logs, the incidents and the other records stay: the full wipe is `run.sh wipe --yes` in a
    terminal (docs/USING.md)."""
    from .vault import Vault
    v = Vault()
    keys = [e.key for e in v.list()]
    refused = [k for k in keys if v.forget(k, route=PANE_ROUTE, typed=True) == "store"]
    gone = len(keys) - len(refused)
    return (f"Forgot {gone} stored value(s). The logs and records stay."
            + (f" The store refused {len(refused)}; they are still stored." if refused else ""))


def _pane_session(session: str) -> str:
    return "pane:" + (session if _SERVER_RE.fullmatch(session or "") else "-")


def pane_allow_ask(key: str, session: str) -> str:
    """The first of the two steps for the allow list, as a typed prompt types the command twice: the panel sends this
    when the person presses "not a secret", and the person's "yes" sends `allow`, the second step."""
    from . import not_a_secret
    try:
        not_a_secret._confirmed(key, _pane_session(session))
    except OSError:
        return "The allow list cannot be written now."
    return f"{key} is no secret?"


def pane_not_a_secret(key: str, session: str) -> str:
    """The second step: not_a_secret.allow_typed, the writer of the typed path, with every check it makes (a key type
    needs the first step of this session within its minutes; a term or an import is refused)."""
    from . import not_a_secret
    return not_a_secret.allow_typed(key, _pane_session(session), PANE_ROUTE).replace("maisecrets: ", "", 1)


def pane_ner() -> dict:
    """The source of names as the pane draws it: the source word, the servers a gateway pick takes, the check lines
    of /maisecrets:ner. A source set by a policy is locked."""
    from . import ner_setup, ner_view
    cfg = load_config()
    conf = cfg.get("remote_detector")
    url = conf.get("url") if isinstance(conf, dict) else None
    source = ("off" if not url else "gateway" if conf.get("gateway") else
              "local" if str(url).rstrip("/") == ner_setup.LOCAL_URL.rstrip("/") else "url")
    servers = sorted(n for n, u in ner_setup._servers().items()
                     if re.fullmatch(r"[\w.-]{1,64}", n) and str(u).lower().startswith("https://"))
    try:
        code, lines = ner_view.render(conf, 0.0, False, "claude")
    except Exception as exc:  # noqa: BLE001 - the view shows the failure, never a traceback
        code, lines = 1, [f"the check failed ({type(exc).__name__})"]
    lines = [ln for ln in lines if not ln.startswith(("all details:", "to turn it on:"))]
    # answers: the source can be used now; starting: a start of the local service runs in the background
    return {"source": source, "locked": "remote_detector" in (cfg.get("policy_keys") or []),
            "servers": servers, "lines": lines, "answers": code == 0, "starting": ner_setup.start_running(),
            "gateway_name": next(
                (n for n, u in ner_setup._servers().items() if url and str(u).rstrip("/") == str(url).rstrip("/")),
                None)}


def pane_ner_set(value: str) -> dict:
    """off, local (and its start in the background, as `run.sh ner start`), or gateway:NAME: a server of the person's
    configuration, by name. An address is typed (/maisecrets:ner url URL), never sent by the panel."""
    name = value[len("gateway:"):] if value.startswith("gateway:") else None
    if value not in ("off", "local") and not (name and _SERVER_RE.fullmatch(name)):
        return {"note": "That source cannot be set here."}
    changed, text = apply_typed("remote_detector", "ner:" + value, route=PANE_ROUTE)
    out = {"note": text.replace("maisecrets: ", "", 1), "changed": changed}
    # the press is the person's typed choice: apply_typed started the service (ner_setup.start_typed)
    if changed and value == "local":
        from . import ner_setup
        out["starting"] = ner_setup.start_running()
    if changed and value.startswith("gateway:"):
        out["login"] = value[len("gateway:"):]
    return out


def mod_answer(payload: dict) -> dict:
    """The panel's question, by `action`: list (the rows), set (key, value), status (session_id), values (offset),
    forget (key), allow_ask and allow (key, session_id), forget_all (confirm), ner, ner_set (value)."""
    action = payload.get("action")
    if action == "status":
        at = payload.get("tool_call_at")
        ok = isinstance(at, (int, float)) and not isinstance(at, bool) and at > 0
        return pane_status(str(payload.get("session_id") or ""), float(at) if ok else 0.0)
    if action == "values":
        off = payload.get("offset")
        return pane_values(off if isinstance(off, int) and not isinstance(off, bool) and off >= 0 else 0)
    if action in ("forget", "allow_ask", "allow"):
        key, session = str(payload.get("key") or ""), str(payload.get("session_id") or "")
        if not _KEY_RE.fullmatch(key):
            return {"note": "That is no key.", **pane_values(0)}
        note = (pane_forget(key) if action == "forget" else pane_allow_ask(key, session) if action == "allow_ask"
                else pane_not_a_secret(key, session))
        return {"note": note, **pane_values(0)}
    if action == "forget_all":
        if payload.get("confirm") != WIPE_CONFIRM:
            return {"note": "Nothing was forgotten: the panel did not confirm it.", **pane_values(0)}
        return {"note": pane_forget_all(), **pane_values(0)}
    if action == "ner":
        return pane_ner()
    if action == "login_offer":
        from . import sref_hooks
        return {"fill": sref_hooks.login_offer(str(payload.get("session_id") or "")) or None}
    if action == "connector":
        from . import sref_hooks
        return sref_hooks.connector_answer(str(payload.get("session_id") or ""), str(payload.get("server") or ""),
                                           str(payload.get("answer") or ""), str(payload.get("cwd") or "") or None)
    if action == "login_offered":
        from . import sref_hooks
        return {"recorded": sref_hooks.login_offered(str(payload.get("session_id") or ""),
                                                     str(payload.get("fill") or ""))}
    if action == "ner_set":
        return {**pane_ner_set(str(payload.get("value") or "")), **pane_ner()}
    note = None
    if action == "set":
        key, word = str(payload.get("key") or ""), str(payload.get("value") or "").lower()
        cfg = load_config()
        listed = _SETTING_RE.fullmatch(key) and any(key in keys for _, keys in MAIN_GROUPS + MORE_GROUPS)
        if not listed or word not in _pane_choices(key, cfg):
            note = "That setting cannot be changed here."
        else:
            changed, text = apply_typed(key, ("toggle:" + word) if key == "regions" else word, route=PANE_ROUTE)
            note = ("Saved. " if changed else "") + text.replace("maisecrets: ", "", 1)
    return {"groups": pane_rows(show_all=True), "note": note}
