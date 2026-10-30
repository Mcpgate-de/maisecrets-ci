"""The remote detector in the plugin (setting `remote_detector`; docs/DETECTION.md, "A remote detector"). Off
unless the setting names a URL. Tool results only: a typed prompt keeps the rules alone (a name in a prompt would
block or rewrite it, and that path has no measurement yet).

One request per hook call. A tool result is many strings (a JSON result is walked leaf by leaf), and a request per
string let one call wait 1.6 s against a budget of 0.3 s in the NER experiment (docs/NER-EXPERIMENT.md, B5). So
before the walk, `prepare` scans each string with the rules, joins the strings into one text, asks the service once
within `timeout_ms`, and hands each string its spans back. The walk then takes the findings from here and scans
nothing twice.

A finding of the service is stored like any other, so its placeholder resolves, but it is weak (vault.is_weak): it is
masked where the model found it and never hunted in other texts. A false name such as "Build" then costs one mask.
"""
from __future__ import annotations

import bisect
import math
import time

from .detection import remote

SEPARATOR = "\n\n"       # between the strings of one tool result: a line break ends a name for the model


def from_config(cfg: dict) -> tuple:
    """(RemoteDetector or None, the reason it is not used, or ""). A setting it cannot use leaves the rules alone."""
    conf = cfg.get("remote_detector") or {}
    if not isinstance(conf, dict) or not conf.get("url"):
        return None, ""
    url = str(conf["url"])
    ms = conf.get("timeout_ms", 300)
    try:
        ms = float(ms) if isinstance(ms, (int, float)) and not isinstance(ms, bool) else math.nan
    except OverflowError:
        ms = math.inf
    if not math.isfinite(ms):
        return None, "timeout_ms is no number of milliseconds"
    # the filler costs names (21 of 2,482 on the V3 samples, docs/NER-EXPERIMENT.md "The remote path"), so a service
    # on this computer may read the rules' findings as they are; any other host always gets the filler
    mask = conf.get("mask") is not False or not remote.is_local(url)
    try:
        return remote.RemoteDetector(
            url, format=str(conf.get("format", "hf")), model=str(conf.get("model", "")),
            classes=conf.get("classes"), min_score=conf.get("min_score"),
            # at most 5 s: the hook's watchdog is 16 s, and the rules' scan of a large result needs its share
            timeout=min(ms, 5000) / 1000, max_chars=int(conf.get("max_chars", 20000)),
            language=str(conf.get("language", "en")), allow_network=conf.get("allow_network") is True,
            mask=mask), ""
    except (ValueError, TypeError, AttributeError) as exc:
        return None, str(exc)


class Layer:
    """The findings of the strings of one tool result: the rules' (as `scan` gave them) and the service's."""

    def __init__(self, found: dict, status: remote.RemoteStatus):
        self.found, self.status = found, status

    def matches(self, text: str, scan) -> list:
        got = self.found.get(text)
        return scan(text) if got is None else got


def prepare(cfg: dict, strings: list, scan, protect=None) -> Layer | None:
    """One request for all strings of a tool result. `scan(text)` gives the rules' findings of a string; `protect(text)`
    the (start, end) of the stored values in it, which go out as filler like the findings and take no name. None when
    no remote detector is set. A service that fails leaves each string with the rules' findings."""
    ner, _why = from_config(cfg)
    if ner is None:
        return None
    from .detection.core import Match
    found: dict = {}
    pieces: list = []          # (text, offset in the joined text)
    at = 0
    for s in dict.fromkeys(strings):
        found[s] = list(scan(s))
        if s.strip():
            pieces.append((s, at))
            at += len(s) + len(SEPARATOR)
    if not pieces:
        return Layer(found, ner.status("ok"))
    joined = SEPARATOR.join(s for s, _ in pieces)
    occupied = [(off + m.start, off + m.end) for s, off in pieces for m in found[s]]
    if protect is not None:
        occupied += [(off + a, off + b) for s, off in pieces for a, b in protect(s)]
    spans, status = ner.ask(joined, occupied, time.monotonic() + ner.timeout)
    starts = [off for _s, off in pieces]
    added: dict = {}
    for a, b, type_, score in spans:
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0:
            s, off = pieces[i]
            if b <= off + len(s):          # a span over two strings is no name of either: dropped
                added.setdefault(s, []).append(Match("remote:" + ner.format, type_, s[a - off:b - off], a - off,
                                                     b - off, score))
    for s, extra in added.items():
        found[s] = sorted(found[s] + extra, key=lambda m: (m.start, m.end))
    return Layer(found, status)
