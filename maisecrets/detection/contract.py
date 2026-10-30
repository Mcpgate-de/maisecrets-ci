"""The JSON entry point of the detection core: the contract maisecrets.detect/1 (docs/DETECTION.md, "The JSON entry
point"; the schema is detect-1.schema.json next to this file).

    python3 -m maisecrets.detection < request.json > response.json

One request on stdin, one response on stdout, nothing on stderr. The response holds offsets, types and rule ids, never
a value of the text: the caller has the text. An error is a response too, with a code of ERRORS and the path of the
field; its message is a fixed text of this module and never holds a value of the request."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

CONTRACT = "maisecrets.detect/1"
SCHEMA = Path(__file__).with_name("detect-1.schema.json")
CHANNELS = ("prompt", "tool")
# the exit status of each outcome; any other status (1 from the interpreter itself) means no response was written
EXIT = {"ok": 0, "invalid_json": 2, "unsupported_contract": 2, "invalid_request": 2, "internal_error": 3}
ERRORS = ("invalid_json", "unsupported_contract", "invalid_request", "internal_error")
_KEYS = {"contract", "text", "channel", "regions", "languages", "context"}
_CONTEXT_KEYS = {"path", "fields"}
_FIELD_KEYS = {"start", "end", "name", "format"}


class RequestError(Exception):
    """A request the engine does not take. `message` is a fixed text of this module, never a part of the request."""

    def __init__(self, code: str, path: str, message: str):
        super().__init__(code)
        self.code, self.path, self.message = code, path, message


def known_regions() -> frozenset:
    """Every region a rule names: the regional rules, the Presidio recognizers and the regions with a language."""
    from . import core, regions
    presidio = json.loads((core.RULES_DIR / "presidio.json").read_text(encoding="utf-8"))["recognizers"]
    return frozenset({"generic"} | set(regions.REGION_LANGUAGE) | {d["region"] for d in core.REGIONAL_RULES}
                     | {core.presidio_region(r["id"]) for r in presidio})


def _no_duplicate_keys(pairs: list) -> dict:
    out = {}
    for k, v in pairs:
        if k in out:
            raise RequestError("invalid_json", "", "a key appears twice in one object")
        out[k] = v
    return out


def _no_constant(_name: str):
    raise RequestError("invalid_json", "", "NaN and Infinity are no JSON")


def _strings(value, path: str, allowed: frozenset, what: str) -> list:
    if not isinstance(value, list):
        raise RequestError("invalid_request", path, "must be a list of strings")
    for i, v in enumerate(value):
        if not isinstance(v, str):
            raise RequestError("invalid_request", f"{path}[{i}]", "must be a string")
        if v not in allowed:
            raise RequestError("invalid_request", f"{path}[{i}]", f"is no known {what}")
    return list(set(value))


def parse(raw: bytes) -> dict:
    """The request of these bytes, checked: {text, channel, regions, languages, path}. Raises RequestError."""
    try:
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except RequestError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise RequestError("invalid_json", "", "the request is not one JSON document in UTF-8") from None
    if not isinstance(doc, dict):
        raise RequestError("invalid_request", "", "the request must be a JSON object")
    if "contract" not in doc:
        raise RequestError("invalid_request", "contract", "is required")
    if doc["contract"] != CONTRACT:
        raise RequestError("unsupported_contract", "contract", "this engine speaks " + CONTRACT)
    if set(doc) - _KEYS:
        # the key is not named: a key of a request is input like its value
        raise RequestError("invalid_request", "", "holds a key the contract does not define")
    for key in ("text", "channel", "regions", "languages"):
        if key not in doc:
            raise RequestError("invalid_request", key, "is required")
    if not isinstance(doc["text"], str):
        raise RequestError("invalid_request", "text", "must be a string")
    if doc["channel"] not in CHANNELS:
        raise RequestError("invalid_request", "channel", "must be prompt or tool")
    from .regions import label_languages_available
    regions = _strings(doc["regions"], "regions", known_regions(), "region")
    languages = _strings(doc["languages"], "languages", frozenset(label_languages_available()), "label language")
    context = doc.get("context", {})
    if not isinstance(context, dict):
        raise RequestError("invalid_request", "context", "must be an object")
    if set(context) - _CONTEXT_KEYS:
        raise RequestError("invalid_request", "context", "holds a key the contract does not define")
    path = context.get("path", "")
    if not isinstance(path, str):
        raise RequestError("invalid_request", "context.path", "must be a string")
    return {"text": doc["text"], "channel": doc["channel"], "path": path,
            "fields": _fields(context["fields"], len(doc["text"])) if "fields" in context else None,
            # generic and English are always on, as in the plugin (regions.resolve): a request may name them. The
            # order of a list says nothing: sorted, the same sets give the same ruleset digest
            "regions": ("generic", *sorted(r for r in regions if r != "generic")),
            "languages": ("en", *sorted(x for x in languages if x != "en"))}


def _integer(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _fields(given, length: int) -> tuple:
    """context.fields as Detector.findings takes them: ((start, end, name path), ...). A field is
    {start, end, name, format?}: the span of a value in code points of the text and its field path, outermost first."""
    if not isinstance(given, list):
        raise RequestError("invalid_request", "context.fields", "must be a list")
    out = []
    for i, f in enumerate(given):
        at = f"context.fields[{i}]"
        if not isinstance(f, dict):
            raise RequestError("invalid_request", at, "must be an object")
        if set(f) - _FIELD_KEYS:
            raise RequestError("invalid_request", at, "holds a key the contract does not define")
        for key in ("start", "end", "name"):
            if key not in f:
                raise RequestError("invalid_request", f"{at}.{key}", "is required")
        for key in ("start", "end"):
            if not _integer(f[key]):
                raise RequestError("invalid_request", f"{at}.{key}", "must be an integer")
        if not 0 <= f["start"] < f["end"] <= length:
            raise RequestError("invalid_request", at, "must have 0 <= start < end <= the length of the text")
        name = f["name"]
        if not isinstance(name, list) or not name:
            raise RequestError("invalid_request", f"{at}.name", "must be a non-empty list")
        for j, part in enumerate(name):
            if not (isinstance(part, str) or _integer(part)):
                raise RequestError("invalid_request", f"{at}.name[{j}]", "must be a string or an integer")
        if not isinstance(f.get("format", ""), str):
            raise RequestError("invalid_request", f"{at}.format", "must be a string")
        out.append((f["start"], f["end"], tuple(name)))
    return tuple(out)


def engine_version() -> str:
    """The version of this copy: the plugin's manifest next to the package (a checkout, the plugin), else the
    installed wheel's metadata."""
    manifest = Path(__file__).resolve().parent.parent.parent / ".claude-plugin" / "plugin.json"
    try:
        return str(json.loads(manifest.read_text(encoding="utf-8"))["version"])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        from importlib import metadata
        return metadata.version("maisecrets")
    except Exception:  # noqa: BLE001 - neither a manifest nor metadata: a copy of the folder
        return "unknown"


def ruleset(detector) -> str:
    """sha256 over the rule list the detector loaded, in scan order, with what each rule matches and checks, and over
    the regions, the label languages and the year of its host. It is computed from the loaded rules, not from the
    files: a line end of a checkout (CRLF on Windows) and the split files of the release tree give the same digest.
    A betterleaks filter (Rule.drop, a function) and the code of the passes are named by the engine version."""
    active = detector.regions()
    rows = []
    for r in detector.rules():
        rx = r.regex
        rows.append([r.key, r.type, str(getattr(rx, "pattern", "")), int(getattr(rx, "flags", 0)), list(r.keywords),
                     r.entropy, r.secret_group, [[str(p.pattern), int(p.flags), t] for p, t in r.allow_regexes],
                     list(r.stopwords), r.validator, r.score, list(r.context), r.require_context, r.whole_match,
                     r.quote_group, r.form, r.matcher, sorted(r.filters or ()), r.region, r.phase])
    doc = {"regions": list(active.regions), "languages": list(active.languages), "year": detector.host.this_year(),
           "rules": rows}
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(data.encode("ascii")).hexdigest()


def detect(request: dict) -> dict:
    """The response to a checked request (parse)."""
    from . import NO_REFERENCES, NO_SOURCES, Active, Detector, Host
    # the year is read once, so the scan and the ruleset digest name the same one; no user name: the request says
    # nothing of a host, and a home path then is a finding whoever runs the engine
    d = Detector(regions=Active(regions=request["regions"], languages=request["languages"], source=CONTRACT),
                 sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=time.gmtime().tm_year))
    found = d.findings(request["text"], channel=request["channel"], path=request["path"], fields=request.get("fields"))
    rows = sorted({(m.start, m.end, m.type, m.kind) for m in found})
    return {"contract": CONTRACT,
            "engine": {"name": "maisecrets", "version": engine_version(), "ruleset": ruleset(d)},
            "findings": [{"start": s, "end": e, "type": t,
                          "provenance": {"rule": k, "origin": "builtin", "layer": "deterministic"}}
                         for s, e, t, k in rows]}


_ORIGINS = (("user:", "user"), ("term:", "term"), ("import:", "import"), ("remote:", "model"))


def finding(m) -> dict:
    """One finding of a response: offsets, type and provenance; `score` only for a model finding."""
    origin = next((o for prefix, o in _ORIGINS if m.kind.startswith(prefix)), "builtin")
    row = {"start": m.start, "end": m.end, "type": m.type,
           "provenance": {"rule": m.kind, "origin": origin, "layer": "model" if origin == "model" else "deterministic"}}
    if m.score is not None:
        row["score"] = m.score
    return row


def result_response(detector, result) -> dict:
    """The maisecrets.detect/1 response for a Result of Detector.findings_with, for a host that embeds the library
    and sends its findings on. A finding of the remote detector carries its `score`; `engine.remote` names the wire
    format, the model the operator stated (the service's answer names none) and what the service did in this call.
    The entry point (detect) never asks a remote detector: it reads no network."""
    engine = {"name": "maisecrets", "version": engine_version(), "ruleset": ruleset(detector)}
    st = result.remote
    if st.state != "off":
        engine["remote"] = {"format": st.format, "model": st.model, "state": st.state}
        if st.reason:
            engine["remote"]["reason"] = st.reason
    rows = sorted(result.findings, key=lambda m: (m.start, m.end, m.type, m.kind))
    return {"contract": CONTRACT, "engine": engine, "findings": [finding(m) for m in rows]}


def error(code: str, path: str, message: str) -> dict:
    return {"contract": CONTRACT, "error": {"code": code, "path": path, "message": message}}


def respond(raw: bytes, argv: list) -> tuple:
    """(exit status, response line) for the bytes of a request. Never raises, and never puts a part of the request
    into an error."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # nothing on stderr
            if argv:
                raise RequestError("invalid_request", "", "the entry point takes no arguments: the request comes on "
                                                          "stdin")
            out, status = detect(parse(raw)), EXIT["ok"]
    except RequestError as e:
        out, status = error(e.code, e.path, e.message), EXIT[e.code]
    except Exception as e:  # noqa: BLE001 - the class name only: an exception's text can hold a value of the text
        out, status = error("internal_error", "", "the engine failed: " + type(e).__name__), EXIT["internal_error"]
    return status, json.dumps(out, ensure_ascii=True, separators=(",", ":")) + "\n"


def main(argv: list | None = None) -> int:
    import sys
    raw = sys.stdin.buffer.read()
    status, line = respond(raw, sys.argv[1:] if argv is None else argv)
    sys.stdout.write(line)
    sys.stdout.flush()
    return status
