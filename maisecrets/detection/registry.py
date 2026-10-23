"""The rule registry: where each detection rule comes from, its rank, its channel, its region and its class, as data.

detect.rules() was a sum of loaders in a fixed order, and the first rule to claim a span wins: the order decided which
rule id a hit gets, and the id decides what scan() and the vault do with it (a label rule in test code is a fixture, a
label hit is stored quiet). A measurement of the order (2026-10-15) found ten such dependencies between the sources.
Here each rule gets a RuleSpec with an explicit rank, `priority = (phase, band, seq)`, and detect.rules() sorts by it.

- `phase` orders the passes of a scan: 0 the password export, 1 the rule list, 2 the personal-data step and the
  cleaned copy of a tool result, 3 the rules of your own, 4 the terms (maisecrets/terms.py), 5 the imported values
  (maisecrets/values.py).
- `band` is the source inside the rule list (BANDS), with gaps for a source to come.
- `seq` is the position in the source file.

The rule id (`Match.kind`) stays what it was: the vault index and the event log store it. Three ids are loaded twice
(mailchimp-api-key, new-relic-insert-key, flutterwave-secret-key), so each spec also gets a unique `key`
(`<source>:<id>`). Standard library only; Python 3.9.

This module is what a hook reads: the bands, the phases and the functions that mark a rule. The spec itself, the patch
records and the upstream digests are in maisecrets/detection/rulespec.py, which loads only when a spec is asked for
(`maisecrets rules list`, the tests, the measurement scripts): three frozen dataclasses cost about 3 ms at import, and
a hook pays every millisecond. Their names are still read here (registry.RuleSpec, registry.make, ...).
"""
from __future__ import annotations


# the bands of the rule list, in scan order. The order between them was measured, not chosen (2026-10-15, every
# CredData line with the sources moved): a label rule before a shape rule, detect-secrets before generic-api-key, the
# own SECRET rules before the vendored ones, the literal rules last.
BANDS = {
    "own-secret": 100,       # OWN_RULES of type SECRET
    "prefixes": 150,         # rules/prefixes.txt
    "detect-secrets": 200,   # rules/detect_secrets.json, rewritten at load
    "betterleaks": 300,      # rules/betterleaks.json
    "own-json": 400,         # rules/own_secret_rules.json
    "fallback": 450,         # FALLBACK_RULES: forms of a key whose vendored rule fixes one length
    "regional": 500,         # REGIONAL_RULES
    "presidio": 600,         # rules/presidio.json
    "own-pii": 700,          # OWN_RULES of any other type
    "literal": 800,          # LITERAL_RULES
    "user": 900,             # the rules of your own (maisecrets/user_rules.py)
}
SOURCES = tuple(BANDS)
PHASES = {"export": 0, "rules": 1, "personal": 2, "user": 3, "terms": 4, "imports": 5}
# The passes of a scan outside the rule list, as sources of their own. Each runs where its phase says: the password
# export before every rule (a cell is a value as a whole), the personal-data rules (maisecrets/detection/personal.py)
# and the
# cleaned copy of a tool result after every built-in rule and before the rules of your own.
# The cleaned copy has no rule of its own: it runs every rule again on a cleaned text. The terms (names, case numbers
# and customer names from your own lists, maisecrets/terms.py) run after the rules of your own: a listed name never
# cuts a value that a rule takes, and a term that a rule found too (an email address) claims the whole span.
# The imported values (maisecrets/values.py, values from your own tools) run after the terms: an import only adds
# masking where no rule, no term and no stored value masks, and never changes how those are masked or resolved.
PASSES = {"export": PHASES["export"], "personal": PHASES["personal"], "terms": PHASES["terms"],
          "imports": PHASES["imports"]}
# the channels a source runs in. Every rule of the rule list runs in both; the literal rules judge a value by the
# channel (detect._pw_literal_ok: a tool result takes a password without evidence of chance), which is a rule of
# their own, not a channel switch
CHANNEL = {source: "both" for source in BANDS}
VENDORED = frozenset({"detect-secrets", "betterleaks", "presidio"})   # synced from upstream by scripts/sync_*.py
OWN_SPECIAL = {"fallback": "fallback", "user": "user", "terms": "term", "imports": "import"}

# a label rule finds a value by its label alone; a keyword rule is a label rule with no `=` or `:` of its own. Until
# the registry these were id prefixes (detect.LABEL_RULES, detect.KEYWORD_RULES), and a stored kind still is one
LABEL_PREFIXES = ("ds-keyword", "label-", "generic-api-key", "url-query-secret", "auth-scheme")
KEYWORD_PREFIXES = ("ds-keyword", "label-")


def form_of(rule_id: str) -> str:
    """keyword, label or shape, by the id: the kind of a stored hit has no spec, so this stays readable from the id."""
    if rule_id.startswith(KEYWORD_PREFIXES):
        return "keyword"
    if rule_id.startswith(LABEL_PREFIXES):
        return "label"
    return "shape"


def is_label(kind: str) -> bool:
    """Whether a hit of this kind (a rule id, also one read from the vault index) came from a label rule."""
    return str(kind).startswith(LABEL_PREFIXES)


# The checks scan() runs on a hit of these rules, by name (detect._scan). Until the registry each was a test of the id.
FILTERS = {
    "private-key-base64": ("base64-wrapped-end",),             # the further lines of a wrapped value
    # JSON inside a string: the value must be escaped too. A constant's name (PROD-DB-PASS_7) and a time or a ratio
    # (0:default) after the label are no value (from a fork, danszymkowiak/maisecrets f2c9ee2, Apache-2.0)
    "ds-keyword-colon": ("escaped-label-quote", "constant-name", "time-or-ratio"),
    "ds-keyword-colon-quotes-required": ("escaped-label-quote", "constant-name", "time-or-ratio"),
    "ds-keyword-equal-signs": ("constant-name",),
    "generic-api-key": ("word-path", "derived-label"),
    "url-query-secret": ("template-value",),                    # ?token={...}
    "auth-scheme": ("words-not-token",),                        # Bearer and words joined by - or _
    "ds-basic-auth": ("user-equals-password",),
    "curl-auth-user": ("user-equals-password",),
    "aws-access-token": ("sigv4-scope",),                       # the key id of a SigV4 credential scope
    "label-cli-password": ("pg-password-switch",),              # psql --password <database>
    "url-password-no-user": ("url-password-value",),
    "hashicorp-tf-password": ("password-value",),               # detect-secrets' value check
    "email-percent-encoded": ("encoded-mail-context",),         # name%40host only where an address is expected
    "phone": ("phone-shape",),
    "email": ("cjk-head",),                                     # an address glued to CJK text: the words are no part
    "crypto-seed-phrase": ("seed-phrase",),                     # no placeholder check; compared as single-spaced words
}
# the filters of every rule whose id starts so: a value that ends in a backslash before its quote
PREFIX_FILTERS = (("ds-keyword", ("escaped-value-quote",)),)
_NO_FILTERS: frozenset = frozenset()


def filters_of(rule_id: str) -> frozenset:
    """The named checks of a rule: FILTERS, PREFIX_FILTERS, and `derived-label` for every keyword rule (a UUID, an
    elided value, or a label that names a derived thing such as secret_id is no value)."""
    if rule_id not in FILTERS and not rule_id.startswith(KEYWORD_PREFIXES):
        return _NO_FILTERS    # most rules: no filter (a keyword prefix covers PREFIX_FILTERS and derived-label)
    out = set(FILTERS.get(rule_id, ()))
    for prefix, names in PREFIX_FILTERS:
        if rule_id.startswith(prefix):
            out.update(names)
    if form_of(rule_id) == "keyword":
        out.add("derived-label")
    return frozenset(out)


def matcher_of(rule_id: str, source: str = "") -> str:
    """How scan() runs a rule: `regex` (finditer), `lines` (the detect-secrets keyword rules, per line, a label at the
    end of a line with the next line), `windowed` (generic-api-key on a long text: windows around its keywords),
    `curl` (a curl command, split at its head), `list` (the values of a labelled list), `literal` (a password after a
    password label, judged by detect._judge_literal), `seed` (a BIP39 seed phrase by its checksum)."""
    if source == "terms":
        return "term"      # one index of every list (maisecrets/terms.py), not a regex per term
    if source == "imports":
        return "import"    # one index of every import (maisecrets/values.py), not a regex per value
    if rule_id.startswith("curl-"):
        return "curl"
    if rule_id in ("label-secret-list", "label-env-key-list"):
        return "list"
    if source == "literal":
        return "literal"
    if rule_id == "crypto-seed-phrase":
        return "seed"
    if rule_id == "generic-api-key":
        return "windowed"
    if rule_id.startswith("ds-keyword"):
        return "lines"
    return "regex"


def _provider(rule_id: str) -> str:
    head = rule_id.split("#", 1)[0].split(".", 1)[0]
    return head.split("-", 1)[0]


def rule_class(source: str, rule_id: str, type_: str) -> str:
    """The class a rule belongs to, for `maisecrets rules list` and scripts/measure_rule_classes.py."""
    form = form_of(rule_id)
    if source == "user":
        return "user"
    if source == "terms":
        return "term"
    if source == "imports":
        return "import"
    if source == "literal":
        return "label:literal"
    if form == "keyword":
        return "label:keyword"
    if form == "label":
        return "label:" + rule_id.split("#", 1)[0]
    if type_ != "SECRET":
        return "pii:" + type_.lower()
    if source == "personal":
        return "form:" + rule_id    # a secret in a fixed form (personal.FORMS): ::add-mask::, SharedAccessKey=
    if source == "fallback":
        return "provider:" + _provider(rule_id)
    return "provider:" + _provider(rule_id)


def coarse_class(spec) -> str:
    """A class of a few dozen members: the source for a token rule, the class for label and PII rules."""
    if spec.rule_class.startswith("provider:"):
        return "token:" + spec.source
    if spec.rule_class.startswith("pii:"):
        return spec.rule_class + ("" if spec.region == "generic" else "@" + spec.region)
    return spec.rule_class


def key_of(source: str, rule_id: str) -> str:
    """The unique key of a rule: `<source>:<id>`; a rule of your own keeps its id, which has its own prefix `user:`."""
    return rule_id if source == "user" else source + ":" + rule_id


_LAZY = {"Upstream", "Patch", "RuleSpec", "UPSTREAM_FILE", "patched_upstream", "DETECT_SECRETS_PATCHES",
         "betterleaks_patches", "presidio_patches", "canonical_sha256", "pass_specs", "make"}


def __getattr__(name: str):
    """registry.RuleSpec, registry.make, ...: from maisecrets/detection/rulespec.py, imported at the first use (PEP
    562)."""
    if name in _LAZY:
        from . import rulespec
        return getattr(rulespec, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
