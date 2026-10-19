"""The sources of a scan in the plugin: the rules of your own and the allow list (user_rules.py), the term lists
(term_files.py, terms.py) and the imported values (value_files.py, values.py), all read from the home folder.

The detector takes these when no caller gives its own (detect.use_sources); a caller without a home folder gives
detect.NO_SOURCES or an object of its own. The bodies are the ones detect.py had: the term list and the imports are
probed first, so a process without any list imports neither terms.py nor values.py.
"""
from __future__ import annotations

import sys

from .detect import Sources


class PluginSources(Sources):
    def user_rules(self) -> list:
        from . import user_rules
        return list(user_rules.load().rules)

    def allow_list(self) -> tuple:
        from . import user_rules
        return user_rules.allow_list()

    def term_matches(self, text: str) -> list:
        try:
            from . import term_files
        except ImportError:   # a copy of the detector without the term lists: no terms
            return []
        if not term_files.present():
            return []
        from . import terms
        return terms.matches(text)

    def import_matches(self, text: str) -> list:
        try:
            from . import value_files
        except ImportError:   # a copy of the detector without the imports: no imports
            return []
        if not value_files.present():
            return []
        from . import values
        return values.matches(text)

    def note_slow(self, rule, ms: float) -> None:
        from . import user_rules
        user_rules.note_slow(rule, ms)

    def reset(self) -> None:
        from . import user_rules
        user_rules.reset()
        for name in ("terms", "term_files", "values", "value_files"):   # term lists and imports are read again too,
            loaded = sys.modules.get(__name__.rsplit(".", 1)[0] + "." + name)   # without importing them
            if loaded is not None:
                (loaded.reset if name in ("terms", "values") else loaded.forget)()


PLUGIN_SOURCES = PluginSources()
