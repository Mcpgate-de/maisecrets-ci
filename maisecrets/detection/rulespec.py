"""The spec of a rule (maisecrets/detection/registry.py): the data model, the patch records and the upstream digests.

Loaded only when a spec is asked for: `maisecrets rules list`, the tests and the measurement scripts. A hook reads
maisecrets/detection/registry.py alone.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .registry import BANDS, OWN_SPECIAL, PASSES, PHASES, VENDORED, filters_of, form_of, key_of, matcher_of, rule_class


@dataclass(frozen=True)
class Upstream:
    source: str          # betterleaks | detect-secrets | presidio
    version: str         # rules/<SOURCE>_VERSION
    upstream_id: str     # the id of the rule upstream (a Presidio recognizer for each of its patterns)
    sha256: str          # of the upstream rule as canonical JSON: a re-sync that changes it shows in `rules list`
    license: str         # the licence file in rules/


@dataclass(frozen=True)
class Patch:
    rule_key: str        # the spec it changes; "detect-secrets:*" for every rule of that source
    field: str           # regex | keywords | validator | context | context_rule | region | load
    op: str              # replace | add | set | wrap | skip
    value: str           # what the patch puts there, short
    reason: str          # why, in one line
    upstream_sha256: str = ""   # the upstream rule the patch was written against; "" when it applies to a source


@dataclass(frozen=True)
class RuleSpec:
    key: str             # unique: "<source>:<id>"
    id: str              # Match.kind as before; stored data in the vault index
    source: str          # one of SOURCES
    origin: str          # term (terms pass) | import (imports pass) | vendored | patched | own | fallback | user
    priority: tuple      # (phase, band, seq)
    channel: str         # prompt | tool | both
    region: str          # "generic" or a country code
    type: str            # the placeholder type: SECRET, EMAIL, IBAN, DE_ID_CARD, ...
    rule_class: str      # what it finds: "provider:github", "label:keyword", "pii:email", ...
    form: str            # keyword | label | shape; a rule of a pass that needs a label or a form is a label rule
    matcher: str = "regex"   # matcher_of
    filters: frozenset = frozenset()   # filters_of
    language: str = ""   # the label languages of a label source ("en,de"), else ""
    needs: str = ""      # a rule of a pass: "label" (a word before the value names it) or "form" (a fixed syntax)
    upstream: Upstream | None = None
    patches: tuple = field(default=())


# The upstream state each correction of a vendored betterleaks rule (detect.BETTERLEAKS_PATCHES) was written
# against: canonical_sha256 of the rule in rules/betterleaks.json, kept in rules/patched_upstream.txt (a digest in
# the tree outside rules/ reads as a secret to the tree scan). After a sync that changes one of these rules,
# tests/test_registry.py goes red: check the correction against the new rule, then update the digest or drop it.
UPSTREAM_FILE = "patched_upstream.txt"


def patched_upstream(rules_dir) -> dict:
    """{"<source>:<id>": sha256} from rules/patched_upstream.txt."""
    out = {}
    for line in (rules_dir / UPSTREAM_FILE).read_text(encoding="utf-8").splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) == 2:
            out[fields[1]] = fields[0]
    return out


_BETTERLEAKS_REASONS = {
    "add_keywords": "the keyword list named only the provider; the token's own prefix is a keyword too (0.6.20)",
    "regex": "the key is waka_ and a UUID; the upstream regex took no hyphen (0.6.20)",
}


# What detect._load_detect_secrets changes in each vendored detect-secrets rule. The loader applies them; these records
# say what and why, for `maisecrets rules list`
DETECT_SECRETS_PATCHES = (
    Patch("detect-secrets:*", "regex", "replace", "denylist + the label words of the active languages",
          "the labels detect-secrets lacks (pass:, token:, passwort:) and the product's own name (mai-secrets)"),
    Patch("detect-secrets:*", "regex", "replace", "a value may start with ! # $ % & * + - @ ^ ~ ? .",
          "a value had to start with a word character, so $+4j... was never a value (2026-09-27)"),
    Patch("detect-secrets:*", "regex", "replace", "up to three spaces before the colon",
          "`mot de passe : x` and `password : x` (2026-09-28)"),
    Patch("detect-secrets:*", "regex", "replace", "an escaped quote around the label and before the value",
          "JSON inside a string, as a log line shows it (CredData, 2026-10-12)"),
    Patch("detect-secrets:*", "regex", "replace", "_KeywordTail: the same matches in linear time",
          "a long word run after a keyword was quadratic (0.6.15)"),
    Patch("detect-secrets:*", "validator", "set", "ds_value", "detect-secrets' own value check, ported"),
    Patch("detect-secrets:ds-basic-auth", "keywords", "set", "none", "a URL with user and password has no label"),
)


def betterleaks_patches(table: dict, upstream: dict) -> dict:
    """{rule id: (Patch, ...)} from detect.BETTERLEAKS_PATCHES; upstream is patched_upstream()."""
    out = {}
    for rule_id, patch in table.items():
        recs = []
        if patch.get("add_keywords"):
            recs.append(Patch("betterleaks:" + rule_id, "keywords", "add", " ".join(patch["add_keywords"]),
                              _BETTERLEAKS_REASONS["add_keywords"], upstream.get("betterleaks:" + rule_id, "")))
        if patch.get("regex"):
            recs.append(Patch("betterleaks:" + rule_id, "regex", "replace", patch["regex"],
                              patch.get("reason") or _BETTERLEAKS_REASONS["regex"],
                              upstream.get("betterleaks:" + rule_id, "")))
        out[rule_id] = tuple(recs)
    return out


def presidio_patches(detect) -> dict:
    """{recognizer id or pattern id: (Patch, ...)} from the six Presidio tables of detect.py, which the loader
    applies."""
    out: dict = {}

    def add(rid, *a):
        out.setdefault(rid, []).append(Patch("presidio:" + rid, *a))
    for rid in sorted(detect.PRESIDIO_SKIP):
        add(rid, "load", "skip", "", "an own rule covers it, or it is no personal data worth a placeholder")
    for rid, v in sorted(detect.PRESIDIO_VALIDATOR.items()):
        add(rid, "validator", "set", v, "a check digit Presidio does not run here")
    for rid in sorted(detect.PRESIDIO_ALWAYS_CONTEXT):
        add(rid, "context_rule", "set", "required", "a plain digit run: a check digit alone passes 1 in 10 to 26")
    for rid in sorted(detect.PRESIDIO_DIGIT_BOUNDED):
        add(rid, "regex", "wrap", "(?<!\\d)...(?!\\d)", "the pattern matched inside a longer digit run")
    for rid in sorted(detect.PRESIDIO_LEFT_SUBFIELD):
        add(rid, "regex", "replace", "left boundary: also after ?NN", "an MT940 subfield code before the IBAN (0.6.24)")
    for rid in sorted(detect.PRESIDIO_PATTERN_CONTEXT):
        add(rid, "context_rule", "set", "required", "the same digits are also FIX tags and XML identifiers")
    for rid, words in sorted(detect.PRESIDIO_EXTRA_CONTEXT.items()):
        add(rid, "context", "add", " ".join(words), "the vendored context words are English only")
    for rid, region in sorted(detect.REGION_OF_ID.items()):
        add(rid, "region", "set", region, "the id names no country")
    return {k: tuple(v) for k, v in out.items()}


def canonical_sha256(rule: dict) -> str:
    return hashlib.sha256(json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def pass_specs(export_rule: str, export_type: str, personal_rules: tuple, prompt_rules: frozenset,
               personal_types: dict, regions: dict | None = None, needs: dict | None = None) -> list:
    """The specs of the passes outside the rule list: the password export (tool channel only), the personal-data
    rules (tool channel; the ones in personal.PROMPT_RULES in both), each with its region and what it needs, and the
    terms pass and the imports pass (both channels; one spec for every list or import, the placeholder type is
    each entry's own)."""
    out = [make("export", export_rule, export_type, 0, channel="tool", needs="form"),
           make("terms", "term", "NAME", 0, channel="both"),
           make("imports", "import", "NAME", 0, channel="both")]
    for seq, rid in enumerate(personal_rules):
        out.append(make("personal", rid, personal_types.get(rid, "PERSON"), seq,
                        channel="both" if rid in prompt_rules else "tool",
                        region=(regions or {}).get(rid, "generic"), needs=(needs or {}).get(rid, "")))
    return out


def _form(rule_id: str, needs: str) -> str:
    """The form of a spec: form_of by the id, and `label` for a personal-data rule that finds a value only by the words
    around it (`Name:`, a phone word, a vCard field, a form): it is no shape that is found alone. A spec only: a rule
    of a pass has no Rule.form, so the scan and the fixture check (detect._shape_rule_ids) do not change."""
    form = form_of(rule_id)
    return "label" if form == "shape" and needs else form


def make(source: str, rule_id: str, type_: str, seq: int, *, region: str = "generic", channel: str = "both",
         language: str = "", upstream: Upstream | None = None, patches: tuple = (), needs: str = "") -> RuleSpec:
    origin = "vendored" if source in VENDORED else OWN_SPECIAL.get(source, "own")
    if source in PASSES:
        origin = OWN_SPECIAL.get(source, "own")     # the terms pass: origin term; the imports: import
    if origin == "vendored" and patches:
        origin = "patched"
    phase = PHASES["user"] if source == "user" else PASSES.get(source, PHASES["rules"])
    return RuleSpec(key=key_of(source, rule_id), id=rule_id, source=source, origin=origin,
                    priority=(phase, BANDS.get(source, 0), seq), channel=channel, region=region, type=type_,
                    rule_class=rule_class(source, rule_id, type_), form=_form(rule_id, needs),
                    matcher=matcher_of(rule_id, source), filters=filters_of(rule_id), language=language,
                    needs=needs, upstream=upstream, patches=tuple(patches))
