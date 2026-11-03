"""Sensitive References in the hooks (hooks.py calls these): the references a command or a file of this session may
resolve, their values from the gateway's resolver, and their name in the audit. Kept apart from hooks.py, whose file
must stay under the size limit of the plugin directory."""
from __future__ import annotations

import os
import re


def note(payload: dict) -> None:
    """PostToolUse of an MCP tool: note the references of its result for this session (sref_notes.py)."""
    import json
    if not str(payload.get("tool_name") or "").startswith("mcp__") or \
            "sref:" not in json.dumps(payload.get("tool_response"), ensure_ascii=False):
        return
    from . import sref_notes
    from .hooks import client_of
    if client_of(payload) == "codex":
        from . import codex_vault
        payload = {**payload, "mcp_server": codex_vault.mcp_server_of(payload) or {}}
    sref_notes.note_result(payload)


def canonical(text: str, session: str | None, cfg: dict | None = None) -> str:
    """text with each server token (vault_refs.canonical_noted) and each reference this session received in its
    canonical form, without the display part. The display is chosen by whoever wrote the text; a quote or `$(` in it
    moved the shell analysis of a command (Fable review, 2026-11-02: `⟦sref:email:ID:'⟧ | base64` passed the
    refusals). The canonical form holds [A-Za-z0-9_:-] only."""
    from . import vault_refs
    text = vault_refs.canonical_noted(text, cfg, session)
    if "sref:" not in text:
        return text
    from . import sref_client, sref_notes
    found = sref_client.find(text)
    here = sref_notes.noted([r for r, _c, _a, _b in found], session)
    out = text
    for r, c, a, b in sorted(found, key=lambda x: -x[2]):
        if r in here:
            out = out[:a] + c + out[b:]
    return out


def refs(text: str, session: str | None, ctxs=None) -> tuple[list, list]:
    """The Sensitive References of text (sref_notes.py): (key, start, end) of each one this session received, the
    key being the reference without its brackets, and the ones it did not receive (they get a reason)."""
    if "sref:" not in text:
        return [], []
    from . import sref_client, sref_notes
    found = [(r, a, b) for r, _c, a, b in sref_client.find(text) if ctxs is None or ctxs[a] != "comment"]
    refs = [r for r, _a, _b in found]
    here = sref_notes.noted(refs, session)
    return [(r[1:-1], a, b) for r, a, b in found if r in here], sref_notes.noted_elsewhere(refs, session)


def audit_name(key: str) -> str:
    """The name of a server key in the audit; a Sensitive Reference by its kind and 4 characters of its id only (the
    id resolves for its user, so it is never written whole)."""
    if key.startswith("sref:"):
        kind, _sep, rest = key[5:].partition(":")
        return f"sref:{kind}:{rest[:4]}…"
    return key


def fetch(cfg: dict, backend, keys: list[str], session: str | None, sink: tuple[str, str]) -> dict:
    """key -> (value, origin) for each Sensitive Reference, from the resolver of the gateway that sent it, all or
    none; raises Refused (fixed text and counts only) otherwise."""
    from urllib.parse import urlsplit

    from . import sref_client, sref_notes
    here = sref_notes.noted([f"⟦{k}⟧" for k in keys], session)
    by_gateway: dict = {}
    for k in keys:
        if f"⟦{k}⟧" in here:               # only noted keys come here; any other one stays text
            by_gateway.setdefault(here[f"⟦{k}⟧"], []).append(k)
    out: dict = {}
    for (origin, url), ks in by_gateway.items():
        host = urlsplit(origin).hostname
        found = sref_client.discover(cfg, url)
        if not found:
            raise sref_client.Refused(f"{host} offers no resolver for references")
        if not sref_client.logged_in(backend, origin):
            raise sref_client.Refused(f"maisecrets has no login to {host} yet; the user runs /maisecrets:sref login "
                                      "once (in Codex: run.sh sref login)")
        canon = {k: sref_client.find(f"⟦{k}⟧")[0][1] for k in ks}
        values = sref_client.resolve(cfg, backend, found, list(dict.fromkeys(canon.values())), sink[0], sink[1])
        out.update({k: (values[c], origin) for k, c in canon.items()})
    return out


def precheck(cfg: dict, backend, keys: list[str], session: str | None) -> str | None:
    """Before a Bash command: each reference has a gateway that offers a resolver and a login there; else the reason,
    as server_values._server_fetch words it. It resolves nothing: the command fetches the value itself when it starts
    (the child that serves it, when the command reads it)."""
    from urllib.parse import urlsplit

    from . import sref_client, sref_notes
    here = sref_notes.noted([f"⟦{k}⟧" for k in keys], session)
    why = None
    for origin, url in dict.fromkeys(here[f"⟦{k}⟧"] for k in keys if f"⟦{k}⟧" in here):
        host = urlsplit(origin).hostname
        if not sref_client.discover(cfg, url):
            why = f"{host} offers no resolver for references"
        elif not sref_client.logged_in(backend, origin):
            why = f"maisecrets has no login to {host} yet; the user runs /maisecrets:sref login once (in Codex: " \
                  "run.sh sref login)"
        if why:
            names = ", ".join(f"⟦{k}⟧" for k in keys)
            return (f"maisecrets: cannot get the value of {names} from the server that sent it: {why}. Do not ask "
                    "the user for the value; tell them this reason.")
    return None


def serve(key: str, session: str | None, program: str, command: str) -> str:
    """The value of one reference of a Bash command, for the child that serves it through a FIFO
    (hooks._serve_value_later): called only once the command opened the FIFO, so a command that never starts
    costs no resolve. The resolve (sink process), the audit line and the release for the echo replacement happen
    here. Raises Refused."""
    from . import vault_refs
    from .server_values import _server_release
    from .vault import Vault, load_config
    cfg = load_config()
    vault = Vault(cfg)
    got = fetch(cfg, vault.backend, [key], session, ("process", program or "sh"))
    _released, why = _server_release(vault, got, session, "Bash", command)
    if why:
        raise vault_refs.Refused(why)
    return got[key][0]


def program_of(command: str) -> str:
    """The name of the program a command runs, for the process sink: the first word after any VAR=value."""
    for word in command.split():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", word):
            return os.path.basename(word)[:255] or "sh"
    return "sh"
