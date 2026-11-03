"""The values of server tokens (vault_refs.py) and of Sensitive References (sref_client.py) for the hooks: fetch them
from the server that sent them, record and release them, and find their places in a text. Moved out of hooks.py, whose
file must stay under the size limit of the plugin directory; the code is the same."""
from __future__ import annotations

from .placeholder import find_refs
from .sref_hooks import audit_name as _audit_name, fetch as _sref_fetch
from .vault import Vault


def _server_limit_keys(keys: list[str], session: str | None) -> list[str]:
    """The limiter names of server keys: `KEY@host` of the origin that noted the key for this session."""
    if not keys:
        return []
    from urllib.parse import urlsplit

    from . import vault_refs
    origins = vault_refs.noted(keys, session)
    return [f"{k}@{urlsplit(origins[k][0]).hostname}" for k in keys if origins.get(k)]


def _server_fetch(cfg: dict, vault: Vault, keys: list[str], session: str | None,
                  sink: tuple[str, str] = ("process", "sh")) -> tuple[dict, str | None]:
    """Vault references (vault_refs.py) and Sensitive References (sref_client.py): the values of server tokens, from
    the server that sent them, all or none. Returns (key -> (value, origin), None) or ({}, the reason without a
    value). Nothing is recorded yet."""
    if not keys:
        return {}, None
    from . import vault_refs
    names = ", ".join(f"⟦{k}⟧" for k in keys)
    srefs = [k for k in keys if k.startswith("sref:")]
    try:
        got = vault_refs.resolve(cfg, vault.backend, [k for k in keys if k not in srefs], session) \
            if len(srefs) < len(keys) else {}
        if srefs:
            got.update(_sref_fetch(cfg, vault.backend, srefs, session, sink))
        return got, None
    except vault_refs.Refused as exc:
        return {}, (f"maisecrets: cannot get the value of {names} from the server that sent it: {exc}. Do not ask "
                    "the user for the value; tell them this reason.")


def _server_release(vault: Vault, got: dict, session: str | None, tool: str, context: str) -> tuple[dict, str | None]:
    """The limiter record and one audit line per server value (`KEY@host`, rotated like every audit line), then
    the values are kept for an hour, so an echo in a later tool result is redacted to the server's token.
    Returns (key -> value, None) or ({}, the reason)."""
    if not got:
        return {}, None
    from urllib.parse import urlsplit

    from . import vault_refs
    status = vault.record_server([f"{_audit_name(k)}@{urlsplit(o).hostname}" for k, (_v, o) in got.items()], session,
                                 tool,
                                 context)
    if status != "ok":
        return {}, (f"maisecrets: no value from the server is released ({status}). Tell the user.")
    vault_refs.remember_released(vault.backend, session, got)
    return {k: v for k, (v, _origin) in got.items()}, None


def _elsewhere_reason(keys: list[str]) -> str:
    names = ", ".join(f"⟦{k}⟧" for k in keys)
    return (f"maisecrets: {names} came from a server in another session or more than 24 hours ago, so it does not "
            "resolve here. Call that server's tool again in this session and use the new tokens.")


def _all_refs(text: str, values: dict) -> list[tuple[str, int, int]]:
    """The stored-value placeholders of text, and the server-range tokens that have a value in `values`."""
    from . import vault_refs
    out = find_refs(text) + [r for r in vault_refs.find(text) if r[0] in values]
    if "sref:" in text:
        from . import sref_client
        out += [(r[1:-1], a, b) for r, _c, a, b in sref_client.find(text) if r[1:-1] in values]
    return out
