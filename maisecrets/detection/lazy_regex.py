"""A regex that compiles at its first use: maisecrets imports its modules in every hook process, and a compilation at
import costs each of them (tests/test_hook_start.py). The detector and the plugin modules share this one class."""
from __future__ import annotations

import re


class LazyRx:
    """A module-level regex compiled at its first use, with every method of a pattern: a hook process paid each
    compilation at import, and most texts never reach most of these checks (0.6.24). After the first use the methods
    of the compiled pattern sit in the instance, so a call costs one attribute lookup, as on the pattern itself."""
    _METHODS = ("search", "match", "fullmatch", "finditer", "findall", "sub", "subn", "split", "scanner")

    def __init__(self, *args) -> None:
        self._args = args

    @property
    def pattern(self):
        return self._args[0]      # the source, without a compilation: a regex built from another one at import

    def __getattr__(self, name: str):
        rx = self.__dict__.get("_rx")
        if rx is None:
            rx = self.__dict__["_rx"] = re.compile(*self._args)
            for method in self._METHODS:
                self.__dict__[method] = getattr(rx, method)
        return getattr(rx, name)
