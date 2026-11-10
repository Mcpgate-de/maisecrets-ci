"""The values behind placeholders, for the person's screen only (the mod's `ui.render`, show_values).

The mod draws a reply again with each value in place of its placeholder. It asks here through `dispatch.py
mod-values`, a fixed command line, and keeps the answer in its own memory: never in `$.state`, a log or a file. The
drawing reaches no model request, transcript or debug log (measured with claude-mod on Claude Code 2.1.319, the
harness scenario `show_values_stay_on_screen`).

Only a value of this computer's store (a key with `c`, as `NAME_c1`) and only one the session may use (the session
rule of Vault.status). A server token and a Sensitive Reference are never resolved for the screen: each resolve costs
the gateway's quota and writes its audit. A display is no use of the value: no grant, no limiter, no renewal.

The agent cannot ask the same question: a Bash command that names a hook entry is refused (C8), and a value in a tool
output is masked again (C2).
"""
from __future__ import annotations

import os
import re

MODES = ("always", "click", "off")
MAX_KEYS = 200
_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,40}_c\d{1,9}")
_REF_RE = re.compile(r"sref:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{20,128}")


def mode(cfg: dict) -> str:
    m = cfg.get("show_values")
    return m if m in MODES else "off"


def links(environ=None) -> bool:
    """A click on a link reaches the mod without its URL on the screen: Terminal.app has no OSC 8 links, and Claude
    Code writes the URL in brackets after the text there (measured 2026-11-08). The process sees the client's
    environment."""
    environ = os.environ if environ is None else environ
    return environ.get("TERM_PROGRAM") != "Apple_Terminal"


def reveal(payload: dict, cfg: dict | None = None) -> dict:
    """{"value": ...} for one Sensitive Reference that a click on the screen asks for, or {"reason": ...}: the gateway
    resolves it for the screen (sink display, its own scope), only when this session got the reference from a
    user-scope gateway in the last 24 hours (sref_notes), with the limiter and the audit of every server value and its
    release, so a paste of it into a prompt or a tool output is masked again (#30)."""
    from . import sref_client, sref_hooks
    from .server_values import _server_release
    from .vault import Vault, load_config
    cfg = load_config() if cfg is None else cfg
    ref = payload.get("ref") if isinstance(payload.get("ref"), str) else ""
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    if mode(cfg) == "off" or not session or not ref.startswith("sref:") or len(ref) > 200:
        return {"reason": "maisecrets shows no value here."}
    if not sref_client.find(f"\u27e6{ref}\u27e7"):
        return {"reason": "maisecrets shows no value here."}
    vault = Vault(cfg)
    try:
        got = sref_hooks.fetch(cfg, vault.backend, [ref], session, ("display", "screen"))
    except sref_client.Refused as exc:
        # the client names the plugin before a toast itself: "maisecrets: maisecrets: …" otherwise
        why = str(exc)
        return {"reason": why[len("maisecrets: "):] if why.startswith("maisecrets: ") else why}
    if ref not in got:
        return {"reason": "maisecrets: this reference did not come from a gateway result of this session."}
    released, why = _server_release(vault, got, session, "Display", "screen")
    if why:
        return {"reason": why}
    return {"value": released[ref]}


def answer(payload: dict, cfg: dict | None = None, vault=None) -> dict:
    """{"mode": ..., "links": ..., "values": {key: value}} for the keys of the payload that this session may use; the
    others are left out. With the mode off no value is read."""
    from .vault import Vault, load_config
    cfg = load_config() if cfg is None else cfg
    m = mode(cfg)
    keys = payload.get("keys") if isinstance(payload.get("keys"), list) else []
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    keys = [k for k in dict.fromkeys(keys) if isinstance(k, str) and _KEY_RE.fullmatch(k)][:MAX_KEYS]
    refs = payload.get("refs") if isinstance(payload.get("refs"), list) else []
    refs = [r for r in dict.fromkeys(refs) if isinstance(r, str) and _REF_RE.fullmatch(r)][:MAX_KEYS]
    shown = {}
    ner = cfg.get("remote_detector")
    names = isinstance(ner, dict) and bool(ner.get("url"))    # the mod's first hint names NER only when it is off
    if not names:
        from .ner_setup import container_tool
        docker = bool(container_tool())                         # NER needs docker or podman; else the term list
    if m != "off" and refs and session:
        from . import sref_notes
        shown = sref_notes.displays(refs, session)
    if m == "off" or not keys or not session:
        return {"mode": m, "links": links(), "values": {}, "displays": shown, "names": names,
                **({} if names else {"docker": docker})}
    v = vault if vault is not None else Vault(cfg)
    values = {}
    for key in keys:
        if v.status(key, session) != "ok":
            continue
        value = v.backend.get(key)
        # a term entry stores its id, never the term (term_files.STORE_PREFIX): its placeholder stays
        if isinstance(value, str) and value and not value.startswith("maisecrets-term:"):
            values[key] = value
    return {"mode": m, "links": links(), "values": values, "displays": shown, "names": names,
            **({} if names else {"docker": docker})}
