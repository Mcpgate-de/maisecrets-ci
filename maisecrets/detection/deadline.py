"""A deadline for a scan: findings(..., deadline=) and leaves.findings_by_leaf(..., deadline=) stop between rules and
between record segments when time.monotonic() has passed it, and raise ScanIncomplete with what they found so far.

A caller with a time budget (a gateway that scans each response inline) cannot cut off a running scan; it can only
not start the next one. Without a deadline nothing changes. One rule's regex on one text is not interruptible, so a
scan can pass its deadline by the time of its slowest single step (docs/DETECTION.md, "Deadline")."""
from __future__ import annotations

import contextvars
import time

_DEADLINE: contextvars.ContextVar = contextvars.ContextVar("maisecrets_deadline", default=None)


class ScanIncomplete(Exception):
    """A scan that passed its deadline. `findings` holds what it found so far, in the return shape of the call that
    raised (a list of Match for findings(), a list of (leaf, Match) for findings_by_leaf()); the text after the last
    finding is not scanned by every rule. `reason` is "deadline". `read` (findings_by_leaf only): the leaves whose
    findings are complete."""

    def __init__(self, findings: list, reason: str = "deadline", read=None) -> None:
        super().__init__(f"the scan stopped at its {reason} with {len(findings)} findings")
        self.findings, self.reason = findings, reason
        # findings_by_leaf: the leaves whose own scan ran to its end, so their findings in `findings` are complete; a
        # value found only in a leaf outside it is not spread to them. None for findings()
        self.read = read


def current():
    """The deadline of the running scan, a time.monotonic() value, or None."""
    return _DEADLINE.get()


def passed(deadline=None) -> bool:
    """Whether the deadline (or the running scan's) has passed."""
    d = _DEADLINE.get() if deadline is None else deadline
    return d is not None and time.monotonic() > d


def set_for(deadline):
    """Set the deadline of the scans in this context; returns the token for reset(), or None without a deadline."""
    return _DEADLINE.set(deadline) if deadline is not None else None


def reset(token) -> None:
    if token is not None:
        _DEADLINE.reset(token)
