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


def mode(cfg: dict) -> str:
    m = cfg.get("show_values")
    return m if m in MODES else "off"


def links(environ=None) -> bool:
    """A click on a link reaches the mod without its URL on the screen: Terminal.app has no OSC 8 links, and Claude
    Code writes the URL in brackets after the text there (measured 2026-11-08). The process sees the client's
    environment."""
    environ = os.environ if environ is None else environ
    return environ.get("TERM_PROGRAM") != "Apple_Terminal"


def answer(payload: dict, cfg: dict | None = None, vault=None) -> dict:
    """{"mode": ..., "links": ..., "values": {key: value}} for the keys of the payload that this session may use; the
    others are left out. With the mode off no value is read."""
    from .vault import Vault, load_config
    cfg = load_config() if cfg is None else cfg
    m = mode(cfg)
    keys = payload.get("keys") if isinstance(payload.get("keys"), list) else []
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    keys = [k for k in dict.fromkeys(keys) if isinstance(k, str) and _KEY_RE.fullmatch(k)][:MAX_KEYS]
    if m == "off" or not keys or not session:
        return {"mode": m, "links": links(), "values": {}}
    v = vault if vault is not None else Vault(cfg)
    values = {}
    for key in keys:
        if v.status(key, session) != "ok":
            continue
        value = v.backend.get(key)
        if isinstance(value, str) and value:
            values[key] = value
    return {"mode": m, "links": links(), "values": values}
