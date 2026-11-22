"""Sensitive References in the hooks (hooks.py calls these): the references a command or a file of this session may
resolve, their values from the gateway's resolver, and their name in the audit. Kept apart from hooks.py, whose file
must stay under the size limit of the plugin directory."""
from __future__ import annotations

import os
import re

from .lazy_regex import LazyRx as _LazyRx


def note(payload: dict) -> str | None:
    """_note, and then the references of this result that a gateway gave this session become trusted (trust): after
    the noting, so a fresh result's own references count. Also the account of each login, for the person only."""
    try:
        out = _note(payload)
    finally:
        try:
            trust(payload)      # every tool: a gateway reference may come back in a command's output
        except Exception:  # noqa: BLE001 - no trusted reference: detection and replacement treat all as text
            from . import placeholder
            placeholder.TRUSTED.clear()
    try:
        extra = account_notice(payload)
    except Exception as exc:  # noqa: BLE001 - no account line; the status itself is unchanged
        from .vault import is_store_timeout
        if is_store_timeout(exc):
            raise                       # a store that does not answer fails the hook closed (C12)
        extra = None
    return " ".join(x for x in (out, extra) if x) or None


_SREF_COMMAND_RE = _LazyRx(r'/hooks/run\.(?:sh|cmd)" sref --args-stdin')


def account_notice(payload: dict) -> str | None:
    """After /maisecrets sref (status or login): the masked account of each gateway login, as a message for the
    person. The command prints no account, because the AI reads its output (the specification: the account hint
    never goes to the model)."""
    if payload.get("tool_name") not in ("Bash", "PowerShell"):
        return None
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str) or not _SREF_COMMAND_RE.search(command):
        return None
    from . import sref_client
    from .vault import Vault, load_config
    from .vault_refs import origin_of, user_servers
    backend = Vault(load_config()).backend
    seen: dict = {}
    for name, url in sorted(user_servers().items()):
        origin = origin_of(url)
        if origin and origin not in seen and sref_client.logged_in(backend, origin):
            seen[origin] = (name, sref_client.account(backend, origin))
    lines = [f"{name} as {who}" for name, who in seen.values() if who]
    return "maisecrets, for you only (not the AI): logged in at " + "; ".join(lines) + "." if lines else None


def _note(payload: dict) -> str | None:
    """PostToolUse of an MCP tool: note the references of its result for this session (sref_notes.py). Returns a
    notice for the person, once per session and gateway, when the gateway sends references and this computer has no
    login there: without it a command with a reference is refused. The login stays the person's own step."""
    import json
    if not str(payload.get("tool_name") or "").startswith("mcp__") or \
            "sref:" not in json.dumps(payload.get("tool_response"), ensure_ascii=False):
        return None
    from . import sref_notes
    from .hooks import client_of
    if client_of(payload) == "codex":
        from . import codex_vault
        payload = {**payload, "mcp_server": codex_vault.mcp_server_of(payload) or {}}
    # only references the gateway really sent this session: not a text with "sref:" in it, not one the model sent
    if not sref_notes.note_result(payload):
        return None
    return _login_hint(payload)


def trust(payload: dict) -> None:
    """The references of this tool result that a gateway gave this session (noted before the redaction): detection
    and the exact replacement leave their kind and id alone. Any other reference is text (a forged one around a
    token hid the token, Opus review of 0.9.3)."""
    import json
    from . import placeholder
    placeholder.TRUSTED.clear()
    text = json.dumps(payload.get("tool_response"), ensure_ascii=False)
    if "sref:" not in text:
        return
    from . import sref_client, sref_notes
    found = sref_client.find(text)
    here = sref_notes.noted([r for r, _c, _a, _b in found], payload.get("session_id"))
    placeholder.TRUSTED.update(c for r, c, _a, _b in found if r in here)


def _login_hint(payload: dict) -> str | None:
    from urllib.parse import urlsplit

    from . import sref_client, sref_notes
    from .hooks import client_of
    from .vault import Vault, load_config
    key = sref_notes.server_key(payload)
    if not key:
        return None
    origin = sref_notes.origin_of(sref_notes.user_servers().get(key))
    if not origin or sref_client.logged_in(Vault(load_config()).backend, origin):
        return None
    name = key if _SERVER_NAME_RE.fullmatch(key) else ""
    if not sref_notes.first_hint(origin, payload.get("session_id"), sender=name or None):
        return None
    host = urlsplit(origin).hostname
    command = ("run.sh sref login" if client_of(payload) == "codex" else "/maisecrets sref login") + \
        (" " + name if name else "")
    return (f"maisecrets: {host} offers Sensitive References: its results hold references that maisecrets can put "
            f"into your commands and files as their values. To allow that, send {command} once: your browser opens, "
            "and you give your consent at the gateway. Until then a command with such a reference is refused.")


# a server name that may go into the input box as an argument of the login: ASCII, as the mod's LOGIN_FILL
_SERVER_NAME_RE = _LazyRx(r"[A-Za-z0-9_.-]{1,64}")


def login_offer(session: str | None) -> str | None:
    """The login command for the input box (Claude Code, the mod at the end of a turn), or None: for a gateway that
    sent this session references (_login_hint), by the name of the server that sent them, while this computer has no
    login there and the box has not got it yet. Records nothing: the mod reports a fill (login_offered). The person's
    Enter starts the login, never this."""
    from . import sref_client, sref_notes
    from .vault import Vault, load_config
    servers = sref_notes.user_servers()
    backend = None
    for origin in sorted({o for o in map(sref_notes.origin_of, servers.values()) if o}):
        # a sender is recorded only with the hint (first_hint), and only an ASCII name (_login_hint)
        name = sref_notes.sender(origin, session)
        if not name or sref_notes.origin_of(servers.get(name)) != origin or sref_notes.offered(origin, session):
            continue
        backend = backend or Vault(load_config()).backend
        if sref_client.logged_in(backend, origin):
            continue
        return f"/maisecrets sref login {name}"
    return None


def connector_answer(session: str | None, server: str, answer: str, cwd: str | None = None) -> dict:
    """The mod asked a claude.ai connector that showed references for its gateway (vault_refs.CONNECTOR_TOOL). Its
    answer is kept as a proposal; the login command goes into the input box with a line that names the host, once per
    session and gateway. The person's Enter on it binds the connector (cli sref login). Returns {"fill", "note"}."""
    from urllib.parse import urlsplit

    from . import sref_notes
    from .vault_refs import connectors, propose_connector
    key, url, why = propose_connector(server, answer, cwd)
    origin = sref_notes.origin_of(url)
    if why or not key or not origin or key in connectors() or sref_notes.offered(origin, session) or \
            not _SERVER_NAME_RE.fullmatch(key):
        return {"fill": None, "note": None}
    host = urlsplit(origin).hostname
    return {"fill": f"/maisecrets sref login {key}",
            "note": f"maisecrets: your claude.ai connector {key} names {host} as its gateway for Sensitive References: "
                    "values that a command or a file of yours can use. Only if this connector is your gateway at "
                    f"{host}, press Enter on the command in your input box: your browser opens at {host}, and you "
                    "give your consent there. Only your login binds the connector to that gateway."}


PAIR_DISCOVERY_S = 6.0      # the pairing runs inside the mod's wait (PAIR_MS, 20 s): one discovery, one request
PAIR_REQUEST_S = 8.0


# #91: the mod's own call of a connector's pairing tool has a tool_use_id of this form (measured on Claude Code
# 2.1.330); the AI's calls do not, and it cannot choose one
_PLUGIN_CALL = "toolu_plugin_"


def pairing_call_refusal(payload: dict) -> str | None:
    """The reason to refuse a call of a server's `sensitive_references_resource` with any argument that the AI made,
    not the mod (#91): the AI never needs a pairing proof, and with the nonce of a running pairing it could carry the
    proof of the person's own gateway connector to the connector that pairs. The AI needs no argument for this tool, so
    any argument counts, in any shape (`Nonce`, a nested `args`), not only the key `nonce`. None for any other call."""
    tool = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if not (tool.startswith("mcp__") and tool.endswith("__sensitive_references_resource")):
        return None
    if not tool_input:
        return None
    if str(payload.get("tool_use_id") or "").startswith(_PLUGIN_CALL):
        return None
    return ("maisecrets: a pairing proof is only for the maisecrets mod; the AI never asks a gateway for one. Nothing "
            "ran.")


def pair_due(key: str) -> bool:
    """The mod asks after a login of KEY succeeded: does a proposed connector wait for its pairing proof?"""
    from .vault_refs import login_mark_due
    return _SERVER_NAME_RE.fullmatch(key or "") is not None and login_mark_due(key)


def pair_cancel(key: str) -> bool:
    """The mod's pairing could not run (no answer from Python, the connector failed): the unused login mark goes, so
    only a new typed login allows a pairing."""
    from .vault_refs import clear_login_mark
    if _SERVER_NAME_RE.fullmatch(key or "") is None:
        return False
    clear_login_mark(key)
    return True


def pair_connector(key: str, nonce: str, answer: str) -> dict:
    """#91: the connector's answer to the mod's nonce. It binds the proposed connector KEY only when the person's
    typed login for it left a fresh mark (used once here), the answer names the proposed URL, and its proof equals
    the one the gateway gives the person's own login for that nonce (compared in constant time). {"bound", "note"}:
    the note is one line for the person; it never holds the nonce, a proof or a token, and the proof is not kept."""
    import hmac
    import json
    import time
    from urllib.parse import urlsplit

    from . import sref_client, vault_refs
    from .vault import load_config, make_backend

    def no(why: str) -> dict:
        return {"bound": False, "note": f"maisecrets: the claude.ai connector {key} was not bound: {why}. To try "
                                        f"again, send /maisecrets:sref login {key}."}
    if not _SERVER_NAME_RE.fullmatch(key or "") or vault_refs.connector_key("claude_ai_" + key) != key:
        return {"bound": False, "note": "maisecrets: that is no claude.ai connector."}
    if not isinstance(nonce, str) or not sref_client.NONCE_RE.fullmatch(nonce):
        return no("the proof request had no valid form")
    url, why = vault_refs.take_login_mark(key)
    if why == "expired":
        return no("its proposal expired (an hour after the connector named its gateway); it is proposed again after "
                  "it shows a reference")
    if not url:
        return no("no login of yours for it in the last 15 minutes")
    host = urlsplit(url).hostname
    try:
        data = json.loads(answer) if isinstance(answer, str) and answer else None
    except (ValueError, RecursionError):
        data = None
    data = data if isinstance(data, dict) else {}
    resource = data.get("resource").strip() if isinstance(data.get("resource"), str) else ""
    proof = data.get("proof")
    if not isinstance(proof, str):
        # a refusal of the gateway (its error_code; the tool answers it with isError false or true): a fixed text
        code = data.get("error_code") or data.get("error")
        code = code.upper() if isinstance(code, str) else ""
        if code in sref_client.PAIRING_REFUSALS:
            return no(f"{host} gave the connector no proof: {sref_client.PAIRING_REFUSALS[code]}")
    if resource != url:
        return no(f"it no longer names {host} as its gateway")
    if not isinstance(proof, str) or not sref_client.PROOF_RE.fullmatch(proof):
        return no("it gave no pairing proof")
    cfg = load_config()
    found, _note = sref_client.discover_typed(cfg, url, budget=PAIR_DISCOVERY_S, tries=1)
    if not found:
        return no(f"the discovery at {host} failed")
    if not found.get("pairing"):
        return no(f"{host} gives no pairing proof now")
    try:
        mine = sref_client.pairing_proof(cfg, make_backend(cfg), found, nonce, time.monotonic() + PAIR_REQUEST_S)
    except sref_client.Refused as exc:
        return no(str(exc))
    if not hmac.compare_digest(mine.encode("ascii"), proof.encode("ascii")):
        return no(f"its proof does not match your login at {host}, so it is not your gateway there or it uses "
                  "another account")
    from . import deposit
    if not vault_refs.bind_connector(key, url, deposit.seal(make_backend(cfg), key, url)):
        return no("another server or connector holds that gateway now")
    return {"bound": True, "note": f"maisecrets: the claude.ai connector {key} is bound to {host}: it proved that it "
                                   "reaches that gateway with your account."}


def login_offered(session: str | None, command: str) -> bool:
    """The mod put this login command into the input box: no second offer of that gateway in this session."""
    from . import sref_notes
    name = command[len("/maisecrets:sref login "):] if command.startswith("/maisecrets:sref login ") else ""
    origin = sref_notes.origin_of(sref_notes.user_servers().get(name)) if _SERVER_NAME_RE.fullmatch(name) else None
    return bool(origin) and sref_notes.first_offer(origin, session)


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


def refs(text: str, session: str | None, ctxs=None) -> tuple[list, list, list]:
    """The Sensitive References of text (sref_notes.py): (key, start, end) of each one this session received, the
    key being the reference without its brackets; the ones another session received; and the ones no session
    received. The last two get a reason: the command would run with the reference's text instead of its value."""
    if "sref:" not in text:
        return [], [], []
    from . import sref_client, sref_notes
    found = [(r, a, b) for r, _c, a, b in sref_client.find(text) if ctxs is None or ctxs[a] != "comment"]
    refs = [r for r, _a, _b in found]
    here = sref_notes.noted(refs, session)
    elsewhere = sref_notes.noted_elsewhere(refs, session)
    never = list(dict.fromkeys(r for r in refs if r not in here and r not in elsewhere))
    return [(r[1:-1], a, b) for r, a, b in found if r in here], elsewhere, never


def never_reason(refs: list) -> str:
    """The refusal for references no session received: maisecrets cannot put their values in, and the call would work
    with the reference's text (a gateway pilot, 2026-11-05: a command ran with the token and found nothing)."""
    names = ", ".join(refs)
    return (f"maisecrets: {names} is a Sensitive Reference that this session did not receive in a tool result, so "
            "maisecrets cannot put its value in; the call would work with the reference's text instead. If maisecrets "
            "has no login to the gateway yet, the user runs /maisecrets sref login once. Then call the tool that "
            "showed the reference again in this session and use the reference it returns.")


def audit_name(key: str) -> str:
    """The name of a server key in the audit; a Sensitive Reference by its kind and 4 characters of its id only (the
    id resolves for its user, so it is never written whole)."""
    if key.startswith("sref:"):
        kind, _sep, rest = key[5:].partition(":")
        return f"sref:{kind}:{rest[:4]}…"
    return key


class Got(tuple):
    """(value, origin) of one released reference, with `audit_id`: the gateway's audit id of the release, or None."""
    audit_id: str | None = None


def fetch(cfg: dict, backend, keys: list[str], session: str | None, sink: tuple[str, str]) -> dict:
    """key -> Got (value, origin) for each Sensitive Reference, from the resolver of the gateway that sent it, all or
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
            raise sref_client.Refused(f"maisecrets has no login to {host} yet; the user runs /maisecrets sref login "
                                      "once (in Codex: run.sh sref login)")
        canon = {k: sref_client.find(f"⟦{k}⟧")[0][1] for k in ks}
        values = sref_client.resolve(cfg, backend, found, list(dict.fromkeys(canon.values())), sink[0], sink[1])
        for k, c in canon.items():
            out[k] = Got((values[c], origin))
            out[k].audit_id = getattr(values, "audit_id", None)
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
            why = f"maisecrets has no login to {host} yet; the user runs /maisecrets sref login once (in Codex: " \
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
