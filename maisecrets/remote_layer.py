"""The remote detector in the plugin (setting `remote_detector`; docs/DETECTION.md, "A remote detector"). Off
unless the setting names a URL. Tool results here; a typed prompt only through the mod's rewrite in Claude Code and
only to a service on this computer (hooks._prompt_names): a name never blocks a prompt.

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
# The wait for a tool result grows with its length (#1764): a fixed 300 ms let the service answer for almost no tool
# result above 2,000 characters on a laptop (ner.log of one day: 94 % of 2k to 10k went to the rules alone).
# wait = timeout_ms + SAFETY * rate * characters / 1000, at most max_timeout_ms. The rate (ms per 1,000 characters) is
# the one this computer showed in its last answers; until it has RATE_MIN of them, DEFAULT_RATE, measured on the
# reference host (docs/NER-EXPERIMENT.md, "The wait grows with the text").
DEFAULT_RATE = 60.0      # netcup RS 2000 G12 (AMD EPYC 9645, Zen 5), --cpus 4 --memory 1536m: 54 to 64, median 57
SAFETY = 1.5
MAX_TIMEOUT_MS = 3000    # the default cap; the setting may raise it to 5,000 (the hook's watchdog is 16 s)
RATE_SAMPLES, RATE_MIN, RATE_MIN_CHARS = 40, 5, 500


def from_config(cfg: dict, fallback: bool = False) -> tuple:
    """(RemoteDetector or None, the reason it is not used, or ""). A setting it cannot use leaves the rules alone.
    fallback: the detector of the setting's `fallback` (/maisecrets:ner fallback url URL), with the tuning keys of the
    setting itself."""
    conf = cfg.get("remote_detector") or {}
    if not isinstance(conf, dict) or not conf.get("url"):
        return None, ""
    if fallback:
        fb = conf.get("fallback")
        if not isinstance(fb, dict) or not fb.get("url"):
            return None, ""
        conf = {**{k: v for k, v in conf.items() if k not in ("url", "allow_network", "format", "mask", "fallback")},
                **fb}
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
    # the container maisecrets started proves its secret before each text (#1699); only `run.sh ner start` records one
    secret = _stored_secret(cfg, url) if remote.is_local(url) else ""
    try:
        return remote.RemoteDetector(
            url, format=str(conf.get("format", "hf")), model=str(conf.get("model", "")),
            classes=conf.get("classes"), min_score=conf.get("min_score"),
            # at most 5 s: the hook's watchdog is 16 s, and the rules' scan of a large result needs its share
            timeout=min(ms, 5000) / 1000, max_chars=int(conf.get("max_chars", 20000)),
            language=str(conf.get("language", "en")), allow_network=conf.get("allow_network") is True,
            mask=mask, ask_labels=conf.get("ask_labels") is True, private_http_only=True, secret=secret), ""
    except (ValueError, TypeError, AttributeError) as exc:
        return None, str(exc)


def _stored_secret(cfg: dict, url: str) -> str:
    """The secret `run.sh ner start` kept for this endpoint, or "" (a container started by hand: no check)."""
    from . import ner_secret
    ep = ner_secret.endpoint(url)
    # the store is asked only when `run.sh ner start` recorded a container here: a keychain read for each tool result
    # of every person who started the container by hand (or of none) would cost time for nothing
    if not ep or not ner_secret.container_of(ep):
        return ""
    from .vault import make_backend
    secret = ner_secret.secret_of(make_backend(cfg), ep)
    if not secret:
        # a container is recorded but its secret is gone or cannot be read: closed, not open. A fresh random secret
        # that no listener knows makes every proof fail, so no text goes out (codex review of #1699)
        import secrets
        return secrets.token_urlsafe(32)
    return secret


class Layer:
    """The findings of the strings of one tool result: the rules' (as `scan` gave them) and the service's."""

    def __init__(self, found: dict, status: remote.RemoteStatus):
        self.found, self.status = found, status

    def matches(self, text: str, scan) -> list:
        got = self.found.get(text)
        return scan(text) if got is None else got


def conf_of(cfg: dict) -> dict:
    conf = cfg.get("remote_detector")
    return conf if isinstance(conf, dict) else {}


def _number(v, default: float) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else default


def _rate_path():
    from .vault import HOME
    return HOME / "ner-rate.json"


def _samples() -> list:
    import json
    try:
        data = json.loads(_rate_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [s for s in data if isinstance(s, list) and len(s) == 2 and all(isinstance(x, (int, float)) for x in s)
            and s[0] >= RATE_MIN_CHARS and s[1] >= 0] if isinstance(data, list) else []


def rate() -> float:
    """ms per 1,000 characters on this computer: the 90th percentile of the last answers (a timeout counts with the
    time it waited, so a rate that was too low grows), or DEFAULT_RATE until there are RATE_MIN of them."""
    try:
        got = sorted(float(ms) * 1000 / float(chars) for chars, ms in _samples())
    except (ArithmeticError, ValueError):
        return DEFAULT_RATE      # a damaged file must not take the name service away (Fable review)
    if len(got) < RATE_MIN:
        return DEFAULT_RATE
    return got[min(len(got) - 1, int(len(got) * 0.9))]


def wait_ms(conf: dict, chars: int) -> float:
    """How long a tool result of `chars` characters waits for the service: timeout_ms plus its share, at most the
    cap (max_timeout_ms, 3,000 by default, never above 5,000), never below timeout_ms."""
    base = min(max(_number(conf.get("timeout_ms"), 300.0), 0.0), 5000.0)
    cap = min(max(_number(conf.get("max_timeout_ms"), MAX_TIMEOUT_MS), base), 5000.0)
    return min(cap, base + SAFETY * rate() * chars / 1000)


def note_rate(chars: int, status) -> None:
    """One sample of this computer's rate: an answer with its time, or a timeout with the time it waited."""
    if chars < RATE_MIN_CHARS or not (status.available or status.reason == "timeout") or status.ms <= 0:
        return
    import json
    from .vault import atomic_write
    try:
        samples = (_samples() + [[chars, round(status.ms, 1)]])[-RATE_SAMPLES:]
        atomic_write(_rate_path(), json.dumps(samples))
    except OSError:
        pass                 # the default rate and the old samples still give a wait


def prepare(cfg: dict, strings: list, scan, protect=None, use_fallback: bool = True,
            kind: str = "tool") -> Layer | None:
    """One request for all strings of a tool result. `scan(text)` gives the rules' findings of a string; `protect(text)`
    the (start, end) of the stored values in it, which go out as filler like the findings and take no name. None when
    no remote detector is set. A service that fails leaves each string with the rules' findings. When the service
    refuses the connection (not running) and the setting has a fallback, the fallback is asked once instead; a
    timeout, an HTTP error or a broken answer never switches (a busy laptop must not send text over the network).
    A prompt never goes to the fallback (use_fallback False). Each call adds a line to the NER log (ner_setup.log):
    time, source, kind, characters, names; never text."""
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
    scaled = kind == "tool" and conf_of(cfg).get("timeout_scales", True) is not False
    if scaled:
        ner.timeout = wait_ms(conf_of(cfg), len(joined)) / 1000
    spans, status = ner.ask(joined, occupied, time.monotonic() + ner.timeout)
    if scaled:
        note_rate(len(joined), status)
    source = "local" if remote.is_local(ner.url) else "url"
    asked = ner
    # only a local service that nothing answers for (refused: not running) hands over: never a network primary, a
    # timeout, a name, TLS or a policy refusal (codex review of 0.8.7)
    if status.state == "unavailable" and status.reason == "refused" and use_fallback and source == "local":
        fb, _why = from_config(cfg, fallback=True)
        if fb is not None:
            spans, status = fb.ask(joined, occupied, time.monotonic() + fb.timeout)
            source, asked = "fallback", fb
    from . import ner_setup
    ner_setup.log(source if status.available else "rules", kind, len(joined), len(spans),
                  why="" if status.available else (status.reason or status.state), ms=status.ms)
    starts = [off for _s, off in pieces]
    added: dict = {}
    for a, b, type_, score in spans:
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0:
            s, off = pieces[i]
            if b <= off + len(s):          # a span over two strings is no name of either: dropped
                added.setdefault(s, []).append(Match("remote:" + asked.format, type_, s[a - off:b - off], a - off,
                                                     b - off, score))
    for s, extra in added.items():
        found[s] = sorted(found[s] + extra, key=lambda m: (m.start, m.end))
    return Layer(found, status)


PROMPT_TIMEOUT_MS = 1000    # a person waits for a prompt anyway; 300 ms left a long or a busy prompt to the rules


def prompt_names(cfg: dict, prompt: str, matches: list, protect_of) -> tuple:
    """(names, why) for a prompt the mod rewrites (Claude Code): the names the service of /maisecrets:ner finds
    become placeholders like the rules' findings (`matches`), and nothing is blocked for a name. `why` is "" when the
    service answered or was not asked, else why it did not check the prompt (the reason or the state of its status:
    timeout, too_long, refused, unauthorized …): the prompt keeps the rules alone, and the person is told.
    Only a service on this computer reads a prompt: the home page promises that no prompt goes to a server by default,
    so a service on the network (url), a fallback and the setting `"prompts": false` leave the prompt to the rules.
    The rules' findings and the stored values (`protect_of()`) go out as filler. A prompt waits up to
    `prompt_timeout_ms` (1,000 by default, at most 5,000), never less than `timeout_ms`."""
    conf = cfg.get("remote_detector")
    if not (isinstance(conf, dict) and conf.get("url")) or conf.get("prompts") is False:
        return [], ""
    if not remote.is_local(str(conf["url"])):
        return [], ""
    wait = conf.get("prompt_timeout_ms", PROMPT_TIMEOUT_MS)
    if not isinstance(wait, (int, float)) or isinstance(wait, bool) or not 0 < wait <= 5000:
        wait = PROMPT_TIMEOUT_MS
    own = conf.get("timeout_ms", 300)
    if isinstance(own, (int, float)) and not isinstance(own, bool) and own > wait:
        wait = own
    # the network stays shut for a prompt whatever the setting says: a "localhost" that resolves to another host is
    # refused when it connects (codex review of 0.8.7)
    local_only = {**cfg, "remote_detector": {**conf, "allow_network": False, "timeout_ms": wait}}
    layer = prepare(local_only, [prompt], lambda s: list(matches), protect_of(), use_fallback=False, kind="prompt")
    if layer is None:
        return [], ""
    st = layer.status
    return [m for m in layer.found.get(prompt, []) if m.kind.startswith("remote:")], (
        "" if st.available else (st.reason or st.state))


UNCHECKED_NOTE = ("maisecrets: the names in this prompt were not checked by the name service ({why}); the rules "
                  "ran. /maisecrets:ner shows the service. This note comes once per session.")
_WHY = {"timeout": "no answer in time", "too_long": "the prompt is longer than max_chars", "refused": "not running",
        "unauthorized": "it wants another bearer", "policy": "the address is not on this computer"}


def unchecked_note(session: str | None, why: str) -> str | None:
    """The note for a prompt whose names the service did not check (`why` from prompt_names), once per session: the
    record of the tool-result note, with its own key. None for a session that had it, or without a session."""
    from . import ner_setup
    from .vault import HOME
    if not (session and ner_setup.claim_down_note(HOME, f"{session}:prompt")):
        return None
    return UNCHECKED_NOTE.format(why=_WHY.get(why, "it gave no usable answer"))


def for_tool_result(cfg: dict, response, binary, strip, scan, protect_of):
    """prepare() for one tool result: its strings as the walk of hooks.post_tool sees them (`strip`: the hidden
    characters removed, or None), a key scanned too, a binary path left out. `protect_of()` gives the stored values,
    which go out as filler: a password stored with `put` has no shape, and the rules alone would let the service read
    it (codex review)."""
    leaves: list = []

    def collect(node, at: tuple = ()) -> None:
        if at in binary:
            return
        if isinstance(node, str):
            leaves.append(strip(node) if strip else node)
        elif isinstance(node, list):
            for i, x in enumerate(node):
                collect(x, at + (i,))
        elif isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str):
                    collect(k)          # a key is scanned too (the walk in hooks): one request covers it
                collect(v, at + (k,))
    collect(response)
    return prepare(cfg, leaves, scan, protect_of())


# the remote detector of the last tool result did not answer (set by hooks.post_tool, read by hint() of the same call)
NER_DOWN = {"v": False}


def note_result(layer) -> None:
    NER_DOWN["v"] = layer is not None and layer.status.state == "unavailable"
    NER_DOWN["not_ours"] = layer is not None and layer.status.reason == "not_ours"
    if layer is not None:
        from . import ner_setup
        NER_DOWN["fallback"] = ner_setup.LAST["source"] == "fallback"


def hint(payload: dict):
    """Once per session, when the service of /maisecrets:ner did not answer: the person learns that names went
    unmasked by it. Not in a subagent: it has no conversation with the person."""
    from . import ner_setup
    from .vault import HOME
    if NER_DOWN.pop("fallback", False) and not payload.get("agent_id"):
        # the first tool result of the session that the fallback checked: where text goes now (akruse-7a, G)
        if ner_setup.claim_down_note(HOME, str(payload.get("session_id")) + ":fallback"):
            return ner_setup.FALLBACK_NOTE
    if not NER_DOWN["v"] or payload.get("agent_id"):
        return None
    NER_DOWN["v"] = False
    note = ner_setup.NOT_OURS_NOTE if NER_DOWN.pop("not_ours", False) else ner_setup.DOWN_NOTE
    return note if ner_setup.claim_down_note(HOME, payload.get("session_id")) else None
