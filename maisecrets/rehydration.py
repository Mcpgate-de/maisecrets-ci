"""Rehydration: when a placeholder becomes its real value in a tool call.

Two layers, kept apart on purpose.

Capability (maisecrets/hooks.py, not configurable): can the value go into this call as data,
away from the model? A shell context the rewrite cannot place, a command word that would parse
or encode the value, a remote shell after ssh, a placeholder used as a JSON key, a write into the
maisecrets home, a path a client does not support: each is refused, whatever the policy says.

Policy (this module): for a path that can take the value, does maisecrets add its own confirm?

  automatic  the default. maisecrets adds no confirm. Claude Code: the hook returns no
             permission decision, so the user's own permission rules decide. Codex: the hook
             returns "allow", the only decision that carries a rewritten input there.
  confirm    the user confirms each call. Claude Code: "ask", which also holds in auto mode.
             Codex cannot ask with a rewritten input, so the call is refused.
  block      the value is never put in; the call is refused before anything is resolved.

Whatever the policy, the value stays out of the model: the rewritten input goes to the tool, not
into the context, and the transcript scrub, the session rule, the limiter and the audit line
apply on every path.
"""
from __future__ import annotations

PATHS = ("bash", "ssh", "mcp", "file")
POLICIES = ("automatic", "confirm", "block")
DEFAULT = "automatic"


def policy(cfg: dict, path: str) -> str:
    """The policy for one path. An unknown value or path is "block": a typo must not grant."""
    raw = cfg.get("rehydration", DEFAULT)
    if raw not in POLICIES or path not in PATHS:
        return "block"
    if path == "file" and not cfg.get("resolve_in_files", True):
        return "block"
    return raw


def outcome(client: str, pol: str) -> str:
    """The hook decision for a path that can take the value: defer (the client's own permission
    rules decide), allow, ask or deny."""
    if pol == "automatic":
        return "allow" if client == "codex" else "defer"
    if pol == "confirm":
        return "deny" if client == "codex" else "ask"
    return "deny"


def refusal(cfg: dict, path: str, client: str, names: str, did_not: str) -> str | None:
    """The reason to refuse before anything is resolved, or None. `did_not` is the sentence that
    says what did not happen ("The command did not run.")."""
    pol = policy(cfg, path)
    if outcome(client, pol) != "deny":
        return None
    if path == "file" and not cfg.get("resolve_in_files", True):
        return (f"maisecrets: {names} is not put into a file tool on this machine (resolve_in_files is off). "
                f"{did_not} To put the value into a file, use a Bash command the user approves, "
                "for example printf '%s' ⟦KEY⟧ > file.")
    raw = cfg.get("rehydration", DEFAULT)
    if cfg.get("rehydration_fallback"):
        # the fallback for a config it cannot read as written set block, not the user: name the cause
        return (f"maisecrets: {names} gets no value while the maisecrets settings cannot be read as written "
                f"({cfg['config_warning']}). {did_not} Tell the user to fix the file; /maisecrets:status names it.")
    if raw not in POLICIES:
        return (f"maisecrets: {names} gets no value: the rehydration setting is not one of "
                f"{', '.join(POLICIES)}. {did_not} Tell the user to check the maisecrets config.")
    if pol == "confirm":
        return (f"maisecrets: {names} gets no value: rehydration is set to confirm, and Codex cannot ask the "
                f"user first. {did_not} Ask the user to run it themselves, or to change the setting.")
    return (f"maisecrets: {names} gets no value: rehydration is set to block on this machine. {did_not} "
            "Ask the user to do this step themselves.")
