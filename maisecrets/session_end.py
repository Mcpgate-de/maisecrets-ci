"""SessionEnd (hooks/dispatch.py session-end): the values a server gave this session leave the store, and the demo of
this session ends (maisecrets/demo.py). Each step runs on its own, so a store that fails does not keep the demo on.
Never an answer: the session is over."""
from __future__ import annotations


def run(payload) -> bool:
    """True when every step ran; False when one failed (the dispatcher writes its incident marker)."""
    session = payload.get("session_id") if isinstance(payload, dict) else None
    if not isinstance(session, str):
        return True
    ok = True
    try:
        # a crashed session sends no SessionEnd: then the values go at their expiry, at the latest at the next start
        from . import vault_refs
        from .vault import Vault, load_config
        vault_refs.end_session(Vault(load_config()).backend, session)
    except Exception:  # noqa: BLE001 - the expiry and the next session start are the backstop
        ok = False
    try:
        from . import demo
        demo.end_session(session)
    except Exception:  # noqa: BLE001 - the demo state stays; /maisecrets:demo off ends it
        ok = False
    return ok
