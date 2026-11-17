"""SessionEnd (hooks/dispatch.py session-end): the values a server gave this session leave the store. The demo does
not end here (maisecrets/demo.py): its lines stay in the session's transcript, so a resumed session stays in the demo,
and only /clear (a new session) leaves them behind. Never an answer: the session is over."""
from __future__ import annotations


def run(payload) -> bool:
    """True when every step ran; False when one failed (the dispatcher writes its incident marker)."""
    session = payload.get("session_id") if isinstance(payload, dict) else None
    if not isinstance(session, str):
        return True
    try:
        # a crashed session sends no SessionEnd: then the values go at their expiry, at the latest at the next start
        from . import vault_refs
        from .vault import Vault, load_config
        vault_refs.end_session(Vault(load_config()).backend, session)
    except Exception:  # noqa: BLE001 - the expiry and the next session start are the backstop
        return False
    return True
