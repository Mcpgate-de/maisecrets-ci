"""The setting business_addresses (#49): with `mask`, the address of a company, an office, a shop or a public place is
masked as any address. personal.py's address rules leave such an address as text when a word of a business or a
place stands near it; each of those regexes is wrapped here and finds nothing while the setting is on. Kept out of
personal.py, which is at the size limit of a release file."""
from __future__ import annotations


def masked() -> bool:
    """Whether the active configuration of the detector masks business addresses (Active.business_addresses)."""
    from .core import _det
    active = _det()._active
    return bool(active is not None and getattr(active, "business_addresses", False))


class Unless:
    """A regex of a business or a place that finds nothing while business addresses are masked."""

    def __init__(self, rx) -> None:
        self._rx = rx

    def search(self, *args):
        return None if masked() else self._rx.search(*args)

    def finditer(self, *args):
        return iter(()) if masked() else self._rx.finditer(*args)

    def __getattr__(self, name):
        return getattr(self._rx, name)
