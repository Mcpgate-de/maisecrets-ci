"""The debug log of the hooks (hooks.py imports _debug again, so hooks._debug is this function)."""
from __future__ import annotations

import os


def _debug(msg: str) -> None:
    """Append a line to $MAISECRETS_DEBUG_LOG when set (harness and troubleshooting); never a value."""
    log = os.environ.get("MAISECRETS_DEBUG_LOG")
    if log:
        try:
            with open(log, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass
