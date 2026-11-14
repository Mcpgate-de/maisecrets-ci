"""Whether a prompt holds what the prompt hook would take out (#44): the check before a settings command that
runs on with its arguments. Kept out of hooks.py, which is at the size limit of a release file."""
from __future__ import annotations


def carries_value(prompt: str, cfg: dict, session: str | None, typed: bool = False) -> bool:
    """Whether the prompt holds what a rewrite would take out: a detected value, a name marked with {{…}}, a value
    the store holds, or a name the name service finds (codex review of #44). A dry run: nothing is stored or
    recorded."""
    from . import hooks as H, terms
    hits = H._prompt_hits(prompt)
    if hits or terms.markers(prompt):
        return True
    if H._has_live(cfg):
        vault = H.Vault(cfg)
        resolved = [(v, r) for v, r in H._resolved_values(vault, session, prompt=True) if len(v) >= H._EXACT_MIN_LEN]
        if H._exact_spans(prompt, vault, session, resolved, prompt=True):
            return True
    return bool(H._prompt_names(cfg, prompt, hits, session, typed)[0])
