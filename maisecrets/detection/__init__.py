"""The detection core of maisecrets: it finds secrets and personal data in text, and holds no plugin, home folder or
reference form of its own. A caller gives those to a Detector:

    from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES
    d = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="mine"),
                 sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="me", year=2026))
    hits = d.scan(text, channel="prompt")

Each argument left None takes the plugin's default when the plugin is there (the config of this computer, the
readers of the home folder, the placeholder form, this computer's user name and year). The names below are the API.
The rule tables and the helpers of maisecrets/detection/core.py are not: maisecrets.detect keeps them for the
plugin and its tests, and they change with the rules.
"""
from .core import NO_REFERENCES, NO_SOURCES, THIS_COMPUTER, Detector, Host, LazyRegex, Match, References, Rule, Sources
from .regions import Active, resolve as resolve_regions

__all__ = ["Active", "Detector", "Host", "LazyRegex", "Match", "NO_REFERENCES", "NO_SOURCES", "References", "Rule",
           "Sources", "THIS_COMPUTER", "resolve_regions"]
