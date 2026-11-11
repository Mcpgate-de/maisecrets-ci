"""Whether a field label can make a number a finding: Detector.label_names_a_number (since 0.8.30, ai-gateway #1795).

A caller that scans numbers only up to a cap (the gateway scans at most 2,000 numbers of a response) must still scan a
number whose label makes it personal data: a tax id stored as an int in a large table stayed in clear. The question
"can this label make a digit-only value a finding?" is answered by the rules themselves, not by a copy of their words:

- SAMPLES holds, for each rule that reads a digit-only value of 7 to 19 digits only after a label, a recipe for one
  valid synthetic value (its length, its first digits and the check of the core that it must pass). The values are
  made at run time, so the tree holds no shape of a real one.
- A label names a number when one sample under it gives a finding that the bare sample does not give. "Under it" is
  the field form of the gateway (`fields=` with the path `(label,)`) and the text form `label: <value>` of
  leaves.findings_by_leaf; the answer is the union of both, in the tool and the prompt channel.
- A rule of your own (Sources.user_rules) has no recipe: its samples are digit runs of 7 to 19 digits that its own
  regex can match (`digit_samples`), tried in the same two forms, scanned with those rules.

The answer is cached per detector and label, and computed again after Detector.reset(). It never scans a value of
the caller. tests/test_label_number.py finds the rules that read a number only after a label from the rules' own data
and fails on one that has no recipe here.
"""
from __future__ import annotations

import random
import re
import threading
import weakref

try:                      # Python 3.11 and later
    from re import _constants as _sre, _parser as _sre_parse
except ImportError:       # Python 3.9 and 3.10
    import sre_constants as _sre
    import sre_parse as _sre_parse

DIGITS_MIN, DIGITS_MAX = 7, 19
_CHANNELS = ("tool", "prompt")

# rule id -> (length, first digits, check). The check is a name of core.VALIDATORS, "phone" for a national number
# (personal._national_phone_ok), "re:" and the shape of a rule without a value check, "after:<word>" (the generic rule
# reads the value after the word: its own filters decide), a tuple of these, or None. A rule of a region that is not
# active finds nothing, so its sample costs a scan and gives no finding.
SAMPLES = {
    # generic
    "ds-keyword-colon": (12, "", None),               # password: <digits>, api_key: <digits>
    "label-secret-literal": (12, "", "after:bearer"),  # bearer, access_key
    "id-number-after-label": (9, "", None),           # passport, driver's licence, beneficiary number
    "id-number-after-record-label": (9, "", None),    # patient, member_id, social insurance
    "phone-after-phone-word": (11, "01", "phone"),    # phone, telefon, mobile, fax (a national number)
    "credit-card": (13, "4", "luhn"),                 # card, credit: a 13-digit Visa (16 digits are found bare)
    "birth-date-after-label": (8, "19", r"re:19[5-9]\d(?:0[1-9]|1[0-2])(?:0[1-9]|1\d|2[0-8])"),  # a date
    "label-otp-seed": (16, "", r"re:[2-7]{16}"),       # otp, totp, mfa_seed: base32 digits only (Opus review)
    # betterleaks rules whose keyword is the label and whose value can be digits only
    "airtable-api-key": (17, "", "after:airtable"),
    "asana-client-id": (16, "", "after:asana"),
    "confluent-access-token": (16, "", "after:confluent"),
    "discord-client-id": (18, "", None),
    "dropbox-api-token": (15, "", None),
    "linkedin-client-id": (14, "", "after:linkedin"),
    "linkedin-client-secret": (16, "", "after:linkedin"),
    # Germany
    "de-tax-id": (11, "", "de_tax_id"),
    "de-tax-number#0": (13, "01", None),
    "de-bsnr": (9, "", "de_bsnr"),
    "de-lanr": (9, "", "de_lanr"),
    # Switzerland, Italy, Sweden, Turkey, United Kingdom
    "ch-ahv-digits": (13, "756", "ch_ahv"),
    "it-vat-code": (11, "", None),
    "se-organisationsnummer#0": (10, "", "se_organisationsnummer"),
    "se-organisationsnummer#1": (12, "", "se_organisationsnummer_head"),
    "se-personnummer#0": (10, "", None),
    "se-personnummer#1": (13, "", None),
    "tr-national-id": (11, "1", None),
    "at-social-security": (10, "", ("at_social_security",
                                    r"re:[1-9]\d{3}(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d\d")),
    "pl-pesel": (11, "", ("pl_pesel", r"re:\d\d(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5}")),
    "nhs": (10, "", "uk_nhs"),
    # Australia, Canada, India, Korea, Nigeria, Philippines, Thailand, South Africa
    "au-abn#1": (11, "", None),
    "au-acn#1": (9, "", None),
    "au-medicare#1": (10, "2", None),
    "au-tfn#1": (9, "", None),
    "ca-sin#0": (9, "1", None),
    "in-aadhaar#0": (12, "", None),
    "kr-brn#1": (10, "", None),
    "kr-driver-license": (12, "", None),
    "kr-frn": (13, "", r"re:\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[5-8]\d{6}"),
    "kr-rrn": (13, "", r"re:\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[1-4]\d{6}"),
    "ng-nin": (11, "", None),
    "ph-tin#1": (9, "", None),
    "ph-umid#1": (12, "", None),
    "th-tnin": (13, "11", None),
    "za-driver-license": (10, "", None),
    "za-income-tax-number": (10, "0", None),
    "za-traffic-register-number": (13, "", None),
    "za-vat-number": (10, "4", None),
    "za-id-number": (13, "", r"re:\d{10}[0-2][89]\d"),
    # United States
    "aba-routing#0": (9, "0", "us_aba"),
    "us-bank": (10, "", None),
    "us-itin#1": (9, "9", r"re:9\d\d(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\d{4}"),
    "us-license#1": (8, "", None),
    "us-npi#0": (10, "1", "us_npi"),
    "us-passport#0": (9, "", None),
    "us-prescription-number#0": (8, "", None),        # rx: <digits> (the label is in the regex)
    "us-prescription-number#1": (8, "", None),
    "us-referral-number#0": (8, "", None),
    "us-ssn#3": (9, "", "us_ssn"),
}


def _check(name, rule_id: str = ""):
    """The check of a recipe as a function of the digits (SAMPLES); a tuple passes when each of its checks does."""
    if name is None:
        return lambda v: True
    if isinstance(name, tuple):
        parts = [_check(n, rule_id) for n in name]
        return lambda v: all(p(v) for p in parts)
    if name.startswith("after:"):   # a generic rule with filters of its own: the rule must read the value there
        return lambda v: rule_id in {m.kind for m in _generic().scan(f"{name[6:]}: {v}", enabled={rule_id},
                                                                      channel="tool")}
    if name.startswith("re:"):
        rx = re.compile(name[3:])
        return lambda v: rx.fullmatch(v) is not None
    if name == "phone":
        from .personal import _national_phone_ok
        return _national_phone_ok
    if name == "se_organisationsnummer_head":   # the rule without \b reads the first ten digits of a longer run
        from .core import VALIDATORS
        return lambda v: VALIDATORS["se_organisationsnummer"](v[:10])
    from .core import VALIDATORS
    return VALIDATORS[name]


_GENERIC: list = []


def _generic():
    """A detector of the generic rules alone, without sources: the check `after:` of a recipe."""
    if not _GENERIC:
        from .core import NO_REFERENCES, NO_SOURCES, Detector, Host
        from .regions import Active
        _GENERIC.append(Detector(regions=Active(regions=("generic",), languages=("en",), source="label_number"),
                                 sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026)))
    return _GENERIC[0]


def sample(rule_id: str) -> str:
    """The synthetic value of a recipe: the first digits, then seeded random digits until the check passes. The same
    recipe gives the same value in every process."""
    n, first, check = SAMPLES[rule_id]
    ok = _check(check, rule_id)
    rng = random.Random(f"{n}:{first}:{check}")
    for _ in range(200_000):
        v = first + "".join(rng.choice("0123456789") for _ in range(n - len(first)))
        if len(set(v)) >= 4 and ok(v):
            return v
    raise RuntimeError(f"no sample for {rule_id}")


_SAMPLES_LOCK = threading.Lock()
_BUILT_IN: list = []


def built_in_samples() -> tuple:
    """The distinct values of SAMPLES (several recipes give the same value)."""
    with _SAMPLES_LOCK:
        if not _BUILT_IN:
            _BUILT_IN.append(tuple(dict.fromkeys(sample(r) for r in SAMPLES)))
        return _BUILT_IN[0]


# ------------------------------------------------------------------------------ the samples of a regex --
def _in_set(items, ch: str) -> bool:
    """Whether the character class of a parsed regex (IN) takes the character."""
    neg, hit = False, False
    for op, av in items:
        if op is _sre.NEGATE:
            neg = True
        elif op is _sre.LITERAL:
            hit = hit or ord(ch) == av
        elif op is _sre.RANGE or str(op) == "RANGE_UNI_IGNORE":
            hit = hit or av[0] <= ord(ch) <= av[1]
        elif op is _sre.CATEGORY:
            name = str(av)
            kind = (ch.isdigit() if "DIGIT" in name else ch.isalnum() or ch == "_" if "WORD" in name
                    else ch.isspace() if "SPACE" in name else ch == "\n")
            hit = hit or (kind != ("NOT_" in name))
    return hit != neg


_FILL = "aA_- :.#/"


def _char(items, rng) -> str:
    """A character of the class, a digit where it takes one."""
    d = rng.choice("0123456789")
    if _in_set(items, d):
        return d
    c = next((c for c in "0123456789" + _FILL if _in_set(items, c)), "")
    if c:
        return c
    for op, av in items:   # a class of letters or signs: its first one
        if op is _sre.LITERAL:
            return chr(av)
        if op is _sre.RANGE:
            return chr(av[0])
    return "x"


def _digit_class(node) -> bool:
    """A repeat of digits: a class that takes a digit and no letter."""
    return len(node) == 1 and node[0][0] is _sre.IN and _in_set(node[0][1], "5") and not _in_set(node[0][1], "a")


ANSWERS_MAX = 4096   # labels kept per detector; the oldest goes first
_CAP = 8   # strings per alternation: a regex with many alternatives samples the first ones


def _walk(nodes, t: int, rng) -> list:
    """Strings that the parsed regex can match, digits where a class takes them, each digit repeat as near to t
    as its bounds allow. An assertion, an anchor and a back reference add nothing."""
    outs = [""]
    for op, av in nodes:
        if op is _sre.LITERAL:
            parts = [chr(av)]
        elif op is _sre.NOT_LITERAL:
            parts = ["4" if av != ord("4") else "5"]
        elif op is _sre.ANY:
            parts = [rng.choice("0123456789")]
        elif op is _sre.IN:
            parts = [_char(av, rng)]
        elif op is _sre.BRANCH:
            parts = [s for alt in av[1][:_CAP] for s in _walk(alt, t, rng)][:_CAP]
        elif op is _sre.SUBPATTERN:
            parts = _walk(av[-1], t, rng)
        elif op in (_sre.MAX_REPEAT, _sre.MIN_REPEAT) or str(op) == "POSSESSIVE_REPEAT":
            lo, hi, item = av
            hi = DIGITS_MAX if hi is _sre.MAXREPEAT else hi
            count = max(lo, min(t, hi)) if _digit_class(item) else lo
            parts = ["".join(_walk(item, t, rng)[0] for _ in range(count))]
        elif op is _sre.GROUPREF_EXISTS:
            parts = _walk(av[1], t, rng)
        else:
            parts = [""]
        outs = [a + b for a in outs for b in parts][:_CAP]
    return outs


def digit_samples(pattern: str, seed: str = "", tries: int = 1) -> list:
    """(string, start, end): strings that the regex can match, for each length a digit repeat can take, and in each
    a run of 7 to 19 digits at [start, end). An empty list for a pattern the parser does not read."""
    try:
        nodes = list(_sre_parse.parse(pattern))
    except Exception:   # noqa: BLE001  a pattern Python's own parser refuses has no samples
        return []
    rng = random.Random(f"{seed}:{pattern}")
    out = {}
    for _ in range(tries):
        for t in range(1, DIGITS_MAX + 1):
            for s in _walk(nodes, t, rng):
                start = None
                for i, c in enumerate(s + " "):
                    if "0" <= c <= "9":
                        start = i if start is None else start
                        continue
                    if start is not None and DIGITS_MIN <= i - start <= DIGITS_MAX:
                        out[(s, start, i)] = None
                    start = None
    return list(out)


def digit_runs(pattern: str, seed: str = "", tries: int = 1) -> list:
    """The distinct digit runs of digit_samples."""
    return list(dict.fromkeys(s[a:b] for s, a, b in digit_samples(pattern, seed, tries)))


# -------------------------------------------------------------------------------------------- the answer --
_CACHE: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()


class _State:
    """The answers of one detector for one configuration (Detector._generation)."""

    def __init__(self, generation: int) -> None:
        self.generation, self.answers, self.bare, self.own = generation, {}, {}, None
        self.changes: dict = {}         # label -> label_changes_a_number


def _state(detector) -> _State:
    with _LOCK:
        st = _CACHE.get(detector)
        if st is None or st.generation != detector._generation:
            st = _CACHE[detector] = _State(detector._generation)
        return st


def _spans(found, shift: int, length: int) -> set:
    return {(m.start - shift, m.end - shift, m.type) for m in found if m.start < shift + length and m.end > shift}


def _own_samples(detector) -> tuple:
    """(value, rules) of the rules of your own: the digit runs their regexes can match, scanned with those rules."""
    own = [r for r in detector.rules() if r.phase == 3 or r.id.startswith("user:")]
    values = {}
    for r in own:
        for v in digit_runs(getattr(r.regex, "pattern", "") or "", r.id):
            values[v] = None
    return tuple(values), own


def _adds(detector, st: _State, label: str, value: str, channel: str, rule_list) -> bool:
    """Whether the value under the label gives a finding the bare value does not give."""
    key = (value, channel, rule_list is not None)
    if key not in st.bare:
        st.bare[key] = _spans(_find(detector, value, channel, None, rule_list), 0, len(value))
    bare = st.bare[key]
    fields = [(0, len(value), (label,))]
    if _spans(_find(detector, value, channel, fields, rule_list), 0, len(value)) - bare:
        return True
    lead = f"{label}: "
    return bool(_spans(_find(detector, lead + value, channel, None, rule_list), len(lead), len(value)) - bare)


def _find(detector, text: str, channel: str, fields, rule_list):
    if rule_list is None:
        return detector.findings(text, channel=channel, fields=fields)
    return detector.scan(text, channel=channel, rule_list=rule_list, fields=fields)


def _changes(detector, st: _State, label: str, value: str, channel: str, rule_list) -> bool:
    """Whether the value under the label gives other findings than the bare value: one more, one fewer or another."""
    key = (value, channel, rule_list is not None)
    if key not in st.bare:
        st.bare[key] = _spans(_find(detector, value, channel, None, rule_list), 0, len(value))
    bare = st.bare[key]
    if _spans(_find(detector, value, channel, [(0, len(value), (label,))], rule_list), 0, len(value)) != bare:
        return True
    lead = f"{label}: "
    return _spans(_find(detector, lead + value, channel, None, rule_list), len(lead), len(value)) != bare


_BARE_LOCK = threading.Lock()
_BARE: list = []


def bare_samples() -> tuple:
    """Digit runs that a rule finds without a label: a Luhn-valid number of each card length from 13 to 19 digits
    under the first digits of the card networks, made at run time from a fixed seed. A label can take such a finding
    away (an `id` field holds no card): label_changes_a_number asks them too."""
    with _BARE_LOCK:
        if not _BARE:
            rng, out = random.Random("bare-samples"), []
            for n in range(13, 20):
                for first in ("4", "51", "37", "6011", "35"):
                    for _ in range(200_000):
                        v = first + "".join(rng.choice("0123456789") for _ in range(n - len(first)))
                        if len(set(v)) >= 4 and _check("luhn", "credit-card")(v):
                            out.append(v)
                            break
            _BARE.append(tuple(out))
        return _BARE[0]


def _decide_changes(detector, st: _State, label: str) -> bool:
    if not label.strip():
        return False
    if st.own is None:
        st.own = _own_samples(detector)
    own_values, own_rules = st.own
    values = tuple(dict.fromkeys(built_in_samples() + bare_samples()))
    for channel in _CHANNELS:
        if any(_changes(detector, st, label, v, channel, None) for v in values):
            return True
        if own_rules and any(_changes(detector, st, label, v, channel, own_rules) for v in own_values):
            return True
    return False


def _decide(detector, st: _State, label: str) -> bool:
    if not label.strip():
        return False
    if st.own is None:
        st.own = _own_samples(detector)
    own_values, own_rules = st.own
    for channel in _CHANNELS:
        if any(_adds(detector, st, label, v, channel, None) for v in built_in_samples()):
            return True
        if own_rules and any(_adds(detector, st, label, v, channel, own_rules) for v in own_values):
            return True
    return False


class LabelNumbers:
    """The part of Detector that answers for a label (core.Detector inherits it; this module keeps core.py small)."""

    def label_changes_a_number(self, label: str) -> bool:
        """Whether a digit-only value of 7 to 19 digits under this label can give other findings than the same digits
        without it: one more (label_names_a_number) or one fewer (a card under `id` is no card). False: the findings of
        such a value are the same under the label and bare, so a caller may take the findings of one form for the
        other. The forms are those of label_names_a_number, `label: <digits>` and `fields=`, in the tool and the prompt
        channel; the values are its samples and a Luhn-valid number of each card length (bare_samples). An empty label
        is False. Cached per label until reset() (since 0.9.6, ai-gateway #1822)."""
        if not isinstance(label, str):
            raise TypeError(f"label must be a str, not {type(label).__name__}")
        st = _state(self)
        hit = st.changes.get(label)
        if hit is None:
            hit = _decide_changes(self, st, label)
            with _LOCK:
                if len(st.changes) >= ANSWERS_MAX:
                    st.changes.pop(next(iter(st.changes)))
                st.changes[label] = hit
        return hit

    def label_names_a_number(self, label: str) -> bool:
        """Whether a digit-only value of 7 to 19 digits under this label can give a finding that the same digits do
        not give without it, under the active regions, label languages and rules of your own of this detector.
        `label` is what maisecrets.detection.leaves.label(path) returns for a leaf. False: no such value gets a
        finding from the label. True: some active rule can read such a number because of the label; a label that
        gives a finding only for some numbers is True. Cached per label until reset(); it scans synthetic values
        only (docs/DETECTION.md, "The API")."""
        if not isinstance(label, str):
            raise TypeError(f"label must be a str, not {type(label).__name__}")
        st = _state(self)
        hit = st.answers.get(label)
        if hit is None:
            hit = _decide(self, st, label)
            with _LOCK:
                if len(st.answers) >= ANSWERS_MAX:   # a response with ever new keys (dates, ids) must not grow it
                    st.answers.pop(next(iter(st.answers)))
                st.answers[label] = hit
        return hit
