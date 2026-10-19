"""Rules of your own: detection rules from folders, and an allow list (README "Rules of your own", C25).

The sources, read once per process (detect.rules() keeps the result):

- `~/.maisecrets/rules.d`, the person's own folder. The agent cannot write there (C8).
- each folder of the setting `rule_dirs`; only a prompt the person typed adds or removes one (C22).
- each folder of `rule_dirs` in the machine policy; the person cannot remove those.

A folder holds `*.json` (the gitleaks form of rules/own_secret_rules.json) and `*.prefixes` (the line form of
rules/prefixes.txt, `id  regex`). When it has a subfolder `rules/`, that subfolder is read instead (a team repository
keeps its rules there), and maisecrets/terms.py reads `*.terms` there (a team term list with a floor). Nothing else
is read: no code, no allow list, no symbolic link, no git metadata.
A folder is data that a hook reads in every call, so each rule passes checks at load; a rule that fails one is
QUARANTINED: it is left out, and /maisecrets:rules, the status and events.log name it with its reason. A refused rule
is named by its place (`rule 3`, `line 7`), never by a text of its own: a refused line can be a pasted value. A broken
rule file or folder never stops a hook and never costs the rules of another folder. A broken machine policy still
does (home.load_config).

The checks: a literal of 4 characters; at most 300 characters of regex; no shape that backtracks (a repeat inside a
repeat, a repeat of something that can be empty, branches that start alike inside a repeat, two repeats in a row that
take the same characters, a backreference); no quantifier at the start. Then each new rule runs once on test texts
that make a backtracking regex slow (a child process that is ended at PROBE_DEADLINE); a rule slower than
PROBE_LIMIT_MS is quarantined. The verdicts are kept in `.rules-state` by a hash of the rule, so a hook pays for the
checks once per rule. A rule that is still too slow in a real scan (detect.USER_RULE_BUDGET), or that runs when the
hook's watchdog answers, is quarantined there too, from the next call on.

The allow list only loosens, so only the person (`~/.maisecrets/allow.txt`) and the administrator (`allow` in the
policy) write it: one exact value per line, or `rule: <id>` to switch a rule off. Never a pattern: a pattern in an allow
list lets through values nobody looked at. A folder of rule_dirs carries no allow list: an agent can write a shared
checkout, and an agent may only make detection stricter.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import stat
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from . import detect
from .home import HOME

try:   # the regex parser of the standard library: re._parser from 3.11, sre_parse before
    from re import _parser as _sre
except ImportError:   # pragma: no cover - Python 3.9 and 3.10
    import sre_parse as _sre

OWN_DIR = HOME / "rules.d"
ALLOW_FILE = HOME / "allow.txt"
STATE_FILE = HOME / ".rules-state"
ID_PREFIX = "user:"                  # every user rule id gets it: no user id can take the name of a built-in rule
MAX_RULES_PER_FOLDER = 500
MAX_LOOKED = 2000                    # rules and lines a folder may hold, refused ones included
MAX_ENTRIES = 2000                   # entries looked at per folder: many files cannot stall a hook
MAX_FILES = 200                      # rule files read per folder
MAX_FILE_BYTES = 64 * 1024
MAX_FOLDER_BYTES = 1024 * 1024       # bytes read per folder
MAX_REGEX = 300
MIN_LITERAL = 4
TYPES = ("SECRET", "NAME", "EMAIL", "PHONE", "IBAN", "CARD", "IP")
TARGETS = ("secret", "match", "line")
CHECK_VERSION = 6                    # a new check makes every cached verdict old
PROBE_LIMIT_MS = 50.0                # a rule slower than this on the test texts is quarantined
PROBE_DEADLINE = 1.0                 # seconds; the test child is ended when one rule takes longer
PROBE_BUDGET = 2.0                   # seconds of tests per hook call; the rest are tested in the next call
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT} | {getattr(_sre, "POSSESSIVE_REPEAT", _sre.MAX_REPEAT)}   # 3.11+
_ZERO_WIDTH = {_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT}
_ANY_CHAR = None                     # a character set that holds every character


@dataclass(frozen=True)
class Quarantined:
    folder: str     # as configured, `~` kept
    file: str       # the file name in the folder; "" for the whole folder
    rule: str       # "rule N" or "line N" for a refused rule, user:<id> for a loaded rule left out; "" for the file
    reason: str     # fixed text, never a regex or a value
    kept: bool = False   # True: the rule loads, only a part of it was dropped (a note, not a refusal)


@dataclass(frozen=True)
class Folder:
    shown: str      # as configured
    path: Path      # the folder that is read: the configured one, or its subfolder rules/
    source: str     # own | setting | policy
    state: str = "ok"            # ok | missing | refused: <why>
    rules: int = 0
    digest: str = ""
    files: int = 0               # the rule files read


@dataclass
class Loaded:
    rules: list = field(default_factory=list)          # detect.Rule
    quarantined: list = field(default_factory=list)    # Quarantined
    folders: list = field(default_factory=list)        # Folder


@dataclass(frozen=True)
class _Source:
    """Where a loaded rule comes from, and what its test needs."""
    hash: str
    folder: str
    file: str
    pattern: str
    literals: tuple
    allows: tuple
    fills: tuple = ()      # runs of the characters the rule's own repeats take (_fills)


# ----------------------------------------------------------- regex shapes --
def _children(op, av) -> list:
    if op in _REPEATS:
        return [av[2]]
    if op == _sre.SUBPATTERN:
        return [av[-1]]
    if op == _sre.BRANCH:
        return list(av[1])
    if op in (_sre.ASSERT, _sre.ASSERT_NOT):
        return [av[1]]
    if op == _sre.GROUPREF_EXISTS:
        return [x for x in av[1:] if x is not None]
    if op == getattr(_sre, "ATOMIC_GROUP", None):
        return [av]
    return []


def _sequences(items):
    """Every sequence of the pattern: the top, and each group, branch, repeat and lookaround body."""
    yield items
    for op, av in items:
        for child in _children(op, av):
            yield from _sequences(list(child))


def _cased(chars) -> set:
    out = set()
    for c in chars:
        out.update((c, c.lower(), c.upper()))
    return out


_CATEGORY = {"CATEGORY_DIGIT": "0123456789", "CATEGORY_SPACE": " \t\n\r\f\v",
             "CATEGORY_WORD": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"}


def _union(a, b):
    return _ANY_CHAR if a is _ANY_CHAR or b is _ANY_CHAR else a | b


def _overlap(a, b) -> bool:
    if a is not _ANY_CHAR and not a or b is not _ANY_CHAR and not b:
        return False
    return a is _ANY_CHAR or b is _ANY_CHAR or bool(a & b)


def _set_of(op, av):
    """The characters one item can take (both cases: the check does not know the flags), or _ANY_CHAR."""
    if op == _sre.LITERAL:
        return frozenset(_cased(chr(av)))
    if op == _sre.IN:
        out: set = set()
        for iop, iav in av:
            if iop == _sre.LITERAL:
                out |= _cased(chr(iav))
            elif iop == _sre.RANGE and iav[1] - iav[0] <= 512:
                out |= _cased(chr(c) for c in range(iav[0], iav[1] + 1))
            elif iop == _sre.CATEGORY and str(iav) in _CATEGORY:
                out |= set(_CATEGORY[str(iav)])
            else:
                return _ANY_CHAR       # a negated set, a wide range, a negated category
        return frozenset(out)
    return _ANY_CHAR


def _chars(items):
    """Every character the sequence can take."""
    out = frozenset()
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue
        kids = _children(op, av)
        if op in (_sre.LITERAL, _sre.IN):
            got = _set_of(op, av)
        elif kids:
            got = frozenset()
            for kid in kids:
                got = _union(got, _chars(list(kid)))
        else:
            got = _ANY_CHAR
        out = _union(out, got)
    return out


def _empty(items) -> bool:
    """Whether the sequence can match the empty string."""
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS:
            if av[0] > 0 and not _empty(list(av[2])):
                return False
        elif op == _sre.SUBPATTERN:
            if not _empty(list(av[-1])):
                return False
        elif op == _sre.BRANCH:
            if not any(_empty(list(b)) for b in av[1]):
                return False
        elif op not in (_sre.GROUPREF, _sre.GROUPREF_EXISTS):
            return False
    return True


def _firsts(items):
    """The characters the sequence can start with."""
    out = frozenset()
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS:
            got, can_skip = _firsts(list(av[2])), av[0] == 0 or _empty(list(av[2]))
        elif op == _sre.SUBPATTERN:
            got, can_skip = _firsts(list(av[-1])), _empty(list(av[-1]))
        elif op == _sre.BRANCH:
            got = frozenset()
            for b in av[1]:
                got = _union(got, _firsts(list(b)))
            can_skip = any(_empty(list(b)) for b in av[1])
        elif op in (_sre.LITERAL, _sre.IN):
            got, can_skip = _set_of(op, av), False
        else:
            got, can_skip = _ANY_CHAR, op in (_sre.GROUPREF, _sre.GROUPREF_EXISTS)
        out = _union(out, got)
        if not can_skip:
            return out
    return out


def _unbounded(items):
    """The characters of every unbounded repeat in the sequence (frozenset() when it has none)."""
    out = frozenset()
    for op, av in items:
        if op in _REPEATS and av[1] == _sre.MAXREPEAT:
            out = _union(out, _chars(list(av[2])))
        for kid in _children(op, av):
            out = _union(out, _unbounded(list(kid)))
    return out


def _nested(items, outer: int = 0) -> bool:
    """A repeat inside a repeat, with one of them unbounded: `(a+)+`, `(?:\\.[a-z]+)+`. That is the shape of
    catastrophic backtracking; `(?:-[a-z0-9]{4}){3}` and `(?:\\.[a-z]{1,63}){1,5}` stay bounded and pass."""
    for op, av in items:
        hi = av[1] if op in _REPEATS else 0
        if op in _REPEATS and hi > 1 and outer > 1 and _sre.MAXREPEAT in (hi, outer):
            return True
        inner = hi if hi > 1 else outer
        if any(_nested(child, inner) for child in _children(op, av)):
            return True
    return False


def _in_a_row(seq) -> bool:
    """Two unbounded repeats in one sequence that can take the same characters, with nothing between them that the
    first cannot take: `.*.*Z`, `\\w+\\d+Z`, `.*-.*Z`. Each split of a run between them is one more try: the time grows
    with a power of the length (3 KB took 20 s, Opus review of block 1). `[a-z]+-[a-z]+` passes: the `-` ends the
    first run."""
    open_ = frozenset()          # what an earlier unbounded repeat can still take
    for op, av in seq:
        if op in _ZERO_WIDTH:
            continue
        item = [(op, av)]
        inner = _unbounded(item)
        barrier = not _empty(item) and not _overlap(open_, _firsts(item))
        if inner is _ANY_CHAR or inner:
            if not barrier and _overlap(open_, inner):
                return True
            open_ = inner if barrier else _union(open_, inner)
        elif barrier:
            open_ = frozenset()
    return False


def _backtracks(items) -> str:
    """The name of a shape that backtracks, or ""."""
    if _nested(items):
        return "a nested quantifier (a repeat inside a repeat)"
    for seq in _sequences(items):
        for op, av in seq:
            if op in (_sre.GROUPREF, _sre.GROUPREF_EXISTS):
                return "a backreference"
            if op not in _REPEATS or av[1] <= 1:
                continue
            body = list(av[2])
            if _empty(body):
                return "a repeat of something that can be empty"
            if av[0] == av[1]:
                continue
            first = next(((o, a) for o, a in body if o not in _ZERO_WIDTH), None)
            while first is not None and first[0] == _sre.SUBPATTERN:
                first = next(((o, a) for o, a in first[1][-1] if o not in _ZERO_WIDTH), None)
            if first is not None and first[0] in _REPEATS and first[1][0] != first[1][1]:
                return "a repeat whose part starts with a repeat"
            again = _firsts(body)         # what the next round of the repeat starts with
            for inner in _sequences(body):
                for iop, iav in inner:
                    if iop != _sre.BRANCH:
                        continue
                    # the parser takes a common start out of the branches: (a|aa) is a(?:|a), (a|a) is a(?:|)
                    heads = [_firsts(list(b)) for b in iav[1]]
                    empty = [_empty(list(b)) for b in iav[1]]
                    if (sum(empty) > 1
                            or any(empty) and any(_overlap(h, again) for h, e in zip(heads, empty) if not e)
                            or any(_overlap(heads[i], heads[j]) for i in range(len(heads))
                                   for j in range(i + 1, len(heads)))):
                        return "branches that start alike inside a repeat"
        if _in_a_row(seq):
            return "two repeats in a row that take the same characters"
    return ""


def _leading_repeat(items) -> bool:
    """The pattern starts with a quantifier of variable length (`.*`, `\\w+`, `[\\w.-]{0,50}`, also after an optional
    part: `x?[a-z]+`): the engine then tries it at every position of the text. generic-api-key started so and took
    80 % of a scan (detect._WINDOWED); `x?[a-z]+abcd` took 7.8 s on 64 KB (Opus review of block 1)."""
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue     # an anchor or a lookaround consumes nothing
        if op in _REPEATS:
            if av[1] > 1 and av[0] != av[1]:
                return True
            if av[0] == 0:
                continue  # an optional part: the pattern can start with what follows it
            return _leading_repeat(list(av[2]))
        if op == _sre.SUBPATTERN:
            if _leading_repeat(list(av[-1])):
                return True
            if _empty(list(av[-1])):
                continue
            return False
        if op == _sre.BRANCH:
            return any(_leading_repeat(list(b)) for b in av[1])
        return False
    return False


def _literal(items) -> str:
    """The longest run of plain characters the pattern always needs (descending into plain groups)."""
    best, run = "", ""
    for op, av in items:
        if op == _sre.LITERAL:
            run += chr(av)
            continue
        best, run = max(best, run, key=len), ""
        if op == _sre.SUBPATTERN:
            best = max(best, _literal(av[-1]), key=len)
    return max(best, run, key=len)


def check_regex(rx: str, keywords: tuple = (), allowlist: bool = False):
    """(reason, compiled, prefilter keywords). A reason means the rule is refused; it names the check, never the
    regex. The prefilter: the rule's own keywords when each has MIN_LITERAL characters, else the longest literal of
    the regex. An allowlist regex needs no literal (it runs only on a hit), but it must not backtrack either."""
    if not isinstance(rx, str) or not rx:
        return "no regex", None, ()
    if len(rx) > MAX_REGEX:
        return f"a regex longer than {MAX_REGEX} characters", None, ()
    rx = detect.re2_to_python(rx)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            parsed = _sre.parse(rx)
            compiled = re.compile(rx)
    except (re.error, RecursionError, OverflowError, ValueError):
        return "a regex that does not compile", None, ()
    items = list(parsed)
    try:
        why = _backtracks(items)
    except RecursionError:
        why = "a regex nested too deep"
    if why:
        return why, None, ()
    if allowlist:
        return None, compiled, ()
    if _leading_repeat(items):
        return "a regex that starts with a quantifier", None, ()
    kws = tuple(k.lower() for k in keywords if isinstance(k, str))
    if kws and all(len(k) >= MIN_LITERAL for k in kws):
        return None, compiled, kws
    lit = _literal(items)
    if len(lit) >= MIN_LITERAL:
        return None, compiled, (lit.lower(),)
    return f"no keyword or literal of {MIN_LITERAL} characters", None, ()


def _one(chars) -> str:
    """One character of a set to build a test run from: a small letter first, as the sets of rules are written."""
    for group in (str.islower, str.isupper, str.isdigit, lambda c: True):
        got = sorted(c for c in chars if group(c))
        if got:
            return got[0]
    return ""


def _example(items) -> str:
    """A short text one round of a repeat body can take: one character per item (a repeat: its least count)."""
    out = ""
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS:
            out += _example(list(av[2])) * max(1, min(av[0], 3))
        elif op == _sre.SUBPATTERN:
            out += _example(list(av[-1]))
        elif op == _sre.BRANCH:
            out += _example(list(av[1][0])) if av[1] else ""
        else:
            got = _chars([(op, av)])
            out += _one(got) if got is not _ANY_CHAR else "a"
    return out


def _fills(rx: str) -> tuple:
    """Runs for the timing texts that the rule's own repeats take: the fixed runs (a, Z, 0, space) never hold a
    `[b-y]`, and `abcd[b-y]{1,99}[b-y]{1,99}…Z` passed them in 0.5 ms and ran for 8 s on a run of b (Fable review,
    round 2). One run per repeat: a character of its set, and one round of its body."""
    out: list = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            items = list(_sre.parse(rx))
        for seq in _sequences(items):
            for op, av in seq:
                if op not in _REPEATS:
                    continue
                body = list(av[2])
                chars = _chars(body)
                for fill in ((_one(chars) if chars is not _ANY_CHAR else ""), _example(body)):
                    if fill and fill not in out:
                        out.append(fill)
            # two repeats of one sequence whose sets overlap: a run of a character both take (Opus review, round 3:
            # `[ac-y]{1,99}[bc-y]{1,99}…` took neither the a of one nor the b of the other for long)
            sets = [_chars(list(av[2])) for op, av in seq if op in _REPEATS]
            for i in range(len(sets)):
                for j in range(i + 1, len(sets)):
                    both = sets[j] if sets[i] is _ANY_CHAR else sets[i] if sets[j] is _ANY_CHAR else sets[i] & sets[j]
                    fill = _one(both) if both is not _ANY_CHAR and both else ""
                    if fill and fill not in out:
                        out.insert(0, fill)
    except Exception:  # noqa: BLE001 - the fixed runs still run
        return ()
    return tuple(out[:8])


def _all_literals(items, out: list) -> list:
    """Each run of 2+ plain characters anywhere in the pattern: in a group, a branch or a repeat body."""
    run = ""
    for op, av in items:
        if op == _sre.LITERAL:
            run += chr(av)
            continue
        if len(run) >= 2:
            out.append(run)
        run = ""
        if op == _sre.SUBPATTERN:
            _all_literals(av[-1], out)
        elif op == _sre.BRANCH:
            for alt in av[1]:
                _all_literals(alt, out)
        elif op in _REPEATS:
            _all_literals(av[2], out)
    if len(run) >= 2:
        out.append(run)
    return out


def _test_literals(rx: str, keywords: tuple) -> tuple:
    """The starts the timed test puts before its runs: the needed literal, the first keyword, and the longest runs of
    each branch (an alternative `abcd[a-z]{0,99}…|safe…` hid its slow start from a test of `safe` alone; Gate A
    round 2 of block 1). At most 4."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            more = sorted(_all_literals(list(_sre.parse(rx)), []), key=len, reverse=True)
    except Exception:  # noqa: BLE001 - only a hint for the test texts
        more = []
    return tuple(dict.fromkeys(x for x in (_regex_literal(rx),) + tuple(keywords[:1]) + tuple(more) if x))[:4]


def _regex_literal(rx: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return _literal(list(_sre.parse(rx)))
    except Exception:  # noqa: BLE001 - only a hint for the test texts
        return ""


# --------------------------------------------------------------- the tests --
_PROBE_CHILD = r"""
import json, re, sys, time
spec = json.loads(sys.stdin.read())
limit = spec["limit"] / 1000.0
print("ready", flush=True)

def texts(lits, fills):
    for lit in lits:
        for n in (25, 40, 16384):        # a short run makes an exponential regex fail slowly, a long one a polynomial
            for fill in ("a", "Z", "0", " ", "aZ0_", "a-0.", "\t\n") + tuple(fills):
                yield lit + (fill * (n // len(fill) + 1))[:n] + "!"
        yield (lit + " ") * (65536 // (len(lit) + 1))
        yield "a" * 65536 + lit
        # the literal again and again, each time before a long run: bounded repeats in a row
        # (`abcd[a-z]{0,99}[a-z]{0,99}[a-z]{0,99}Q`) cost a power of 99 at each start (Gate B of block 1)
        for fill in ("a", " ") + tuple(fills):
            yield (lit + (fill * (200 // len(fill) + 1))[:200]) * 60

def once(rx, allows, lits, fills):
    # the slowest start: four starts must not sum a correct rule past the limit (Gate B round 2 of block 1)
    worst = 0.0
    for lit in lits:
        t = time.perf_counter()
        for text in texts((lit,), fills):
            for _ in rx.finditer(text):
                pass
            for a in allows:
                a.search(text)
        worst = max(worst, time.perf_counter() - t)
    return worst

for key, pattern, lits, allows, fills in spec["rules"]:
    rx = re.compile(pattern)
    allows = [re.compile(a) for a in allows]
    took = once(rx, allows, lits, fills)
    if took > limit:
        took = min(took, once(rx, allows, lits, fills))     # a busy machine: the second run decides
    print(key, round(took * 1000, 1), flush=True)
"""


def probe(sources: list, budget: float | None = None, limit_ms: float | None = None, info: dict | None = None) -> dict:
    """{hash: ms, or None for a rule ended at PROBE_DEADLINE} of the rules tested before `budget` seconds ran out.
    The tests run in a child process: a regex that backtracks holds the interpreter and cannot be stopped from
    inside, but a child can be ended. A rule not tested (the budget, no child) is not in the answer."""
    import queue
    import subprocess
    import threading
    limit_ms = PROBE_LIMIT_MS if limit_ms is None else limit_ms
    results: dict = {}
    todo = [s for s in sources]
    end = None if budget is None else time.monotonic() + budget
    while todo and sys.executable:
        if end is not None and time.monotonic() >= end:
            if info is not None:
                info["budget"] = True
            break
        try:
            child = subprocess.Popen([sys.executable, "-I", "-S", "-c", _PROBE_CHILD], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except (OSError, ValueError):
            break
        if info is not None:
            info["child"] = True
        lines: queue.Queue = queue.Queue()

        def read(out=child.stdout, lines=lines) -> None:
            for raw in out:
                lines.put(raw.decode("ascii", "replace").split())
            lines.put(None)
        threading.Thread(target=read, daemon=True).start()
        spec = {"limit": limit_ms,
                "rules": [[s.hash, s.pattern, list(s.literals), list(s.allows), list(s.fills)] for s in todo]}
        try:
            child.stdin.write(json.dumps(spec).encode("utf-8"))
            child.stdin.close()
            # the child starts within the budget too (Fable review, round 2: the wait was 10 s whatever the budget)
            ready = lines.get(timeout=10 if end is None else max(0.0, min(10.0, end - time.monotonic())))
        except (OSError, queue.Empty):
            ready = None
        stop = ready != ["ready"]
        done = 0
        while not stop and done < len(todo):
            wait = PROBE_DEADLINE if end is None else min(PROBE_DEADLINE, end - time.monotonic())
            try:
                got = lines.get(timeout=max(wait, 0.0))
            except queue.Empty:
                got = "late"
            if got == "late":
                if end is not None and time.monotonic() >= end and wait < PROBE_DEADLINE:
                    stop = True        # the budget ran out, not the rule's own time: test it next time
                    break
                results[todo[done].hash] = None
                done += 1
                break
            if not got or len(got) != 2 or got[0] != todo[done].hash:
                stop = True
                break
            try:
                results[got[0]] = float(got[1])
            except ValueError:
                stop = True
                break
            done += 1
        try:
            child.kill()
        except OSError:
            pass
        try:
            child.wait(timeout=2)
        except Exception:  # noqa: BLE001 - a child that does not end is left to the system
            pass
        if stop:
            break
        todo = todo[done:]
    return results


def _slow_reason(ms) -> str:
    if ms is None:
        return f"slow: a test text took more than {PROBE_DEADLINE * 1000:.0f} ms (a regex that backtracks)"
    return f"slow: the test texts took {ms:.0f} ms, the limit is {PROBE_LIMIT_MS:.0f} ms (a regex that backtracks)"


# ------------------------------------------------------------------ state --
def _read_state() -> dict:
    try:
        text = STATE_FILE.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return {}
    try:
        state = json.loads(text)
    except ValueError:
        return {"note": text}              # the form of 0.6.14: the digest line alone
    return state if isinstance(state, dict) else {}


def _write_state(state: dict) -> bool:
    try:
        from .home import atomic_write
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n")
        return True
    except (OSError, TypeError, ValueError):
        return False


def _hash(*parts) -> str:
    return hashlib.sha256(json.dumps([CHECK_VERSION, *parts], sort_keys=True, default=str)
                          .encode("utf-8", "surrogatepass")).hexdigest()[:20]


# ------------------------------------------------------------------- rules --
def _lazy(pattern: str) -> "detect.LazyRegex":
    return detect.LazyRegex(pattern, 0)


def _allowlists(lists, dropped) -> tuple[list, list, str]:
    """(allow regexes, stopwords, reason) of a rule's allowlists. An allowlist with condition AND whose parts each
    alone would allow less is dropped, the stricter side, as `rules import` does (codex review of block 1)."""
    allow: list = []
    stop: list = []
    for al in lists if isinstance(lists, list) else ():
        if not isinstance(al, dict):
            continue
        regexes = al.get("regexes") if isinstance(al.get("regexes"), list) else []
        words = al.get("stopwords") if isinstance(al.get("stopwords"), list) else []
        cond = al.get("condition", "OR")
        if not isinstance(cond, str) or cond.upper() not in ("OR", "AND"):
            return [], [], "an allowlist condition that is not OR or AND"
        if cond.upper() == "AND" and (bool(regexes) + bool(words) + bool(al.get("paths"))) > 1:
            dropped("an allowlist with condition AND was dropped (stricter)")
            continue
        target = al.get("regexTarget", "secret")
        if target not in TARGETS:
            return [], [], "an allowlist regexTarget that is not secret, match or line"
        for arx in regexes:
            awhy, _, _ = check_regex(arx, allowlist=True)
            if awhy:
                return [], [], "in an allowlist: " + awhy
            allow.append((detect.re2_to_python(arx), target))
        stop += [s.lower() for s in words if isinstance(s, str)]
    return allow, stop, ""


def _json_rule(r: dict, place: str, kept, refuse, dropped, cache: dict) -> None:
    rid = r.get("id")
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        refuse(place, "an id that is not 1 to 64 letters, digits, '.', '_' or '-'")
        return
    type_ = r.get("type", "SECRET")
    if type_ not in TYPES:
        refuse(place, "a type that is not one of " + ", ".join(TYPES))
        return
    keywords = r.get("keywords") or ()
    if not isinstance(keywords, (list, tuple)):
        refuse(place, "keywords that are not a list")
        return
    raw = r.get("entropy", 0) or 0
    group = r.get("secretGroup", 0) or 0
    if isinstance(raw, bool) or isinstance(group, bool):
        refuse(place, "an entropy or secretGroup that is not a number")
        return
    try:
        entropy = float(raw)
        group = int(group)
    except (TypeError, ValueError, OverflowError):
        refuse(place, "an entropy or secretGroup that is not a number")
        return
    if not 0 <= entropy <= 8 or not 0 <= group <= 99:      # also inf and nan
        refuse(place, "an entropy (0 to 8) or secretGroup (0 to 99) out of range")
        return
    notes: list = []
    allow, stop, why = _allowlists(r.get("allowlists"), notes.append)
    if why:
        refuse(place, why)
        return
    for text in notes:
        dropped(rid, text)
    key = _hash("json", r.get("regex"), list(keywords), allow, stop)
    verdict = cache.get(key)
    if not isinstance(verdict, dict) or "kw" not in verdict:
        why, compiled, prefilter = check_regex(r.get("regex"), tuple(keywords))
        verdict = {"why": why, "kw": list(prefilter)}
        cache[key] = verdict
    if verdict.get("why"):
        refuse(place, str(verdict["why"]))
        return
    pattern = detect.re2_to_python(r["regex"])
    rule = detect.Rule(id=ID_PREFIX + rid, type=type_, regex=_lazy(pattern), keywords=tuple(verdict["kw"]),
                       entropy=entropy, secret_group=group,
                       allow_regexes=tuple((_lazy(p), t) for p, t in allow), stopwords=tuple(stop))
    kept(rid, rule, place, key, pattern, tuple(a for a, _ in allow))


def _json_rules(data, kept, refuse, dropped, cache: dict) -> None:
    """The rules of one *.json file in the gitleaks form."""
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        refuse("", "not the rules form (an object with a rules list)")
        return
    for n, r in enumerate(data["rules"], 1):
        place = f"rule {n}"
        try:
            if not isinstance(r, dict):
                refuse(place, "a rule that is not an object")
                continue
            _json_rule(r, place, kept, refuse, dropped, cache)
        except Exception:  # noqa: BLE001 - one odd rule never costs the others
            refuse(place, "a rule that cannot be read")


def _prefix_rules(text: str, kept, refuse, cache: dict) -> None:
    """The rules of one *.prefixes file: `id  regex` per line, `#` comments; the whole match is the secret. A refused
    line is named by its number only: its text can be a pasted value."""
    for n, line in enumerate(text.splitlines(), 1):
        place = f"line {n}"
        try:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            rid = parts[0]
            if not _ID_RE.fullmatch(rid):
                refuse(place, "an id that is not 1 to 64 letters, digits, '.', '_' or '-'")
                continue
            if len(parts) < 2:
                refuse(place, "a line without a regex")
                continue
            rx = parts[1].strip()
            key = _hash("prefixes", rx)
            verdict = cache.get(key)
            if not isinstance(verdict, dict) or "kw" not in verdict:
                why, _, prefilter = check_regex(rx)
                verdict = {"why": why, "kw": list(prefilter)}
                cache[key] = verdict
            if verdict.get("why"):
                refuse(place, str(verdict["why"]))
                continue
            pattern = detect.re2_to_python(rx)
            kept(rid, detect.Rule(id=ID_PREFIX + rid, type="SECRET", regex=_lazy(pattern),
                                  keywords=tuple(verdict["kw"])), place, key, pattern, ())
        except Exception:  # noqa: BLE001 - one odd line never costs the others
            refuse(place, "a line that cannot be read")


class _Full(BaseException):
    """The folder holds its limit of rules, or of rules looked at: no later rule is checked (a BaseException, so the
    per-rule `except Exception` of the readers lets it through)."""


def _shown_name(name: str) -> str:
    """A file name as text that can be printed: an undecodable byte becomes a replacement character, a control
    character a `?` (an agent names the files of a folder it can write; Gate B of block 1)."""
    return "".join(c if c.isprintable() else "?" for c in os.fsencode(name).decode("utf-8", "replace"))


def _read(path: Path) -> bytes:
    """The bytes of a regular file, never through a symbolic link, at most MAX_FILE_BYTES + 1."""
    # O_NONBLOCK: a FIFO put in place of the file after the listing does not hold the open (Gate B of block 1)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IsADirectoryError(str(path))
        chunks, size = [], 0
        while size <= MAX_FILE_BYTES:
            chunk = os.read(fd, MAX_FILE_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_folder(path: Path, shown: str, taken: set | None = None, cache: dict | None = None,
                sources: dict | None = None) -> tuple[list, list, str]:
    """(rules, quarantined, digest) of one folder. `taken` holds the ids of earlier folders. A second rule with an id
    of the same folder is quarantined. A rule whose id an earlier folder has runs as `<id>#2` (#3, ...): an agent that
    can write one folder must not take out the rule of another folder by its id (Gate A of block 1). The allow list
    switches `<id>` and every `<id>#n` off together (switched_off). `cache` holds the
    verdicts of the checks by rule hash; `sources` gets the _Source of each loaded rule by its id."""
    taken = set() if taken is None else taken
    cache = {} if cache is None else cache
    rules: list = []
    quarantined: list = []
    digest = hashlib.sha256()
    names = []
    seen = 0
    with os.scandir(path) as entries:
        for entry in entries:
            seen += 1
            if seen > MAX_ENTRIES:
                quarantined.append(Quarantined(shown, "", "", f"a folder of more than {MAX_ENTRIES} entries; "
                                                              "the rest is not read"))
                break
            if not entry.name.endswith((".json", ".prefixes")):
                continue
            if entry.is_symlink():
                quarantined.append(Quarantined(shown, _shown_name(entry.name), "",
                                               "a symbolic link; a rule file is read only as a plain file"))
            elif entry.is_file(follow_symlinks=False):
                names.append(entry.name)
    names.sort()
    if len(names) > MAX_FILES:
        quarantined.append(Quarantined(shown, "", "", f"{len(names) - MAX_FILES} rule file(s) past the limit of "
                                                      f"{MAX_FILES} per folder"))
        names = names[:MAX_FILES]
    full = False
    size = 0
    looked = [0]

    def look() -> None:
        """One more rule looked at. Past MAX_LOOKED the folder is read no further: refused and duplicate rules cost a
        check each too (Gate A round 2 of block 1)."""
        looked[0] += 1
        if looked[0] > MAX_LOOKED:
            raise _Full
    mine: set = set()     # the ids of this folder
    for name in names:
        file = _shown_name(name)

        def refuse(place: str, reason: str, file: str = file) -> None:
            if place:
                look()
            quarantined.append(Quarantined(shown, file, place, reason))

        def dropped(rid: str, text: str, file: str = file) -> None:
            quarantined.append(Quarantined(shown, file, ID_PREFIX + rid, text, kept=True))

        def kept(rid: str, rule, place: str, key: str, pattern: str, allows: tuple, file: str = file) -> None:
            look()
            if rid in mine:
                quarantined.append(Quarantined(shown, file, place, "an id that an earlier rule has"))
                return
            if len(rules) >= MAX_RULES_PER_FOLDER:
                raise _Full
            mine.add(rid)
            if rid in taken:
                n = 2
                while f"{rid}#{n}" in taken:
                    n += 1
                quarantined.append(Quarantined(shown, file, ID_PREFIX + rid, f"an id that a rule of an earlier folder "
                                               f"has; this rule runs as {ID_PREFIX}{rid}#{n}", kept=True))
                rid = f"{rid}#{n}"
                rule = dataclasses.replace(rule, id=ID_PREFIX + rid)
            taken.add(rid)
            rules.append(rule)
            if sources is not None:
                lits = _test_literals(pattern, rule.keywords)
                sources[rule.id] = _Source(key, shown, file, pattern, lits, allows, _fills(pattern))
        try:
            digest.update(os.fsencode(name) + b"\0")
            try:
                raw = _read(path / name)
            except OSError:
                refuse("", "a file that cannot be read")
                continue
            size += len(raw)          # an oversized file was read too, to its limit: it counts (Gate A round 2)
            if size > MAX_FOLDER_BYTES:
                quarantined.append(Quarantined(shown, "", "", f"more than {MAX_FOLDER_BYTES // 1024} KB of rule files; "
                                                              f"{file} and the files after it are not read"))
                break
            if len(raw) > MAX_FILE_BYTES:
                refuse("", f"a file larger than {MAX_FILE_BYTES // 1024} KB")
                continue
            digest.update(raw)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                refuse("", "a file that is not UTF-8")
                continue
            if name.endswith(".json"):
                try:
                    data = json.loads(text)
                except (ValueError, RecursionError):
                    refuse("", "not valid JSON")
                    continue
                _json_rules(data, kept, refuse, dropped, cache)
            else:
                _prefix_rules(text, kept, refuse, cache)
        except _Full:
            full = True
            break
        except Exception:  # noqa: BLE001 - one broken file never costs the other files
            refuse("", "a file that cannot be read")
    if full:
        # the rest is not even checked: rules past the limit cost a check at each load (Gate B of block 1)
        quarantined.append(Quarantined(shown, "", "", f"rules past the limit of {MAX_RULES_PER_FOLDER} per folder "
                                                      f"(or of {MAX_LOOKED} looked at); the rest of the folder is "
                                                      "not read"))
    return rules, quarantined, digest.hexdigest()[:12]


# ------------------------------------------------------------------ folders --
def expand(shown: str) -> Path:
    return Path(os.path.expanduser(shown.strip()))


def rule_folder(path: Path) -> Path:
    """The folder whose files are read: `rules/` of a team repository when it has one, else the folder itself. The
    hook and `maisecrets rules check` both read through here (Opus review of block 1: the check read rules/, the hook
    the top, and the folder loaded no rule without a word)."""
    sub = path / "rules"
    try:
        if stat.S_ISDIR(os.lstat(sub).st_mode):
            return sub
    except (OSError, ValueError):
        pass
    return path


def refused_folder(path: Path) -> str:
    """Why a folder is not read, or "". The maisecrets home holds config.json and index.json, which are *.json too;
    rules.d is read as the person's own folder anyway."""
    try:
        if not path.is_absolute():
            return "refused: not an absolute path"
        real, home = path.resolve(), HOME.resolve()
    except (OSError, RuntimeError, ValueError):
        return "refused: the path cannot be resolved"
    if real == home or home in real.parents:
        return "refused: inside the maisecrets folder"
    return ""


def _key(path: Path, shown: str) -> str:
    try:
        return os.path.normcase(str(path.resolve())) if path.is_absolute() else shown
    except (OSError, RuntimeError, ValueError):
        return shown


def folders(cfg: dict) -> list[tuple[str, Path, str]]:
    """(shown, path, source) of every folder, policy first: on a duplicate id the administrator's rule stays. One
    folder named twice (a link to it, `~/x` and the full path) is read once."""
    out = [(d, expand(d), "policy") for d in cfg.get("policy_rule_dirs") or [] if isinstance(d, str) and d.strip()]
    out.append(("~/.maisecrets/rules.d" if HOME == Path.home() / ".maisecrets" else str(OWN_DIR), OWN_DIR, "own"))
    out += [(d, expand(d), "setting") for d in cfg.get("rule_dirs") or [] if isinstance(d, str) and d.strip()]
    seen: set = set()
    unique = []
    for shown, path, source in out:
        key = _key(path, shown)
        if key not in seen:
            seen.add(key)
            unique.append((shown, path, source))
    return unique


def _config() -> dict:
    from .home import load_config
    try:
        return load_config()
    except Exception:  # noqa: BLE001 - a broken policy fails closed in the hook itself; here it means no folder
        return {}


_LOADED: list = []
_SOURCES: dict = {}      # rule id -> _Source of the rules this process loaded


def _one_folder(out: Loaded, shown: str, path: Path, source: str, taken: set, cache: dict, sources: dict) -> None:
    why = refused_folder(path) if source != "own" else ""
    if why:
        out.folders.append(Folder(shown, path, source, why))
        return
    target = rule_folder(path)
    if not target.is_dir():
        out.folders.append(Folder(shown, target, source, "missing"))
        return
    rules, quarantined, digest = load_folder(target, shown, taken, cache, sources)
    files = sum(1 for _ in _rule_files(target))
    out.rules += rules
    out.quarantined += quarantined
    out.folders.append(Folder(shown, target, source, "ok", len(rules), digest, files))


def _rule_files(path: Path):
    """The rule files of a folder, from its first MAX_ENTRIES entries (as load_folder reads it)."""
    try:
        with os.scandir(path) as entries:
            out = []
            for n, e in enumerate(entries):
                if n >= MAX_ENTRIES:
                    break
                if e.name.endswith((".json", ".prefixes")):
                    out.append(e.name)
            return out
    except OSError:
        return []


def _test_new_rules(out: Loaded, sources: dict, tested: dict, slow: dict, budget: float | None) -> None:
    """Leave out each rule that a scan found too slow, and test the rules not tested yet (within `budget`)."""
    keep, new = [], []
    for rule in out.rules:
        src = sources.get(rule.id)
        if src is None:
            keep.append(rule)
            continue
        if src.hash in slow:
            ms = slow[src.hash].get("ms") if isinstance(slow[src.hash], dict) else None
            out.quarantined.append(Quarantined(src.folder, src.file, rule.id, (
                f"slow: one scan took {ms:.0f} ms (a regex that backtracks)" if isinstance(ms, (int, float))
                else "slow: the hook's watchdog stopped a scan while it ran (a regex that backtracks)")))
            continue
        ms = tested.get(src.hash)
        if src.hash not in tested:
            new.append(src)
        if src.hash in tested and (ms is None or ms > PROBE_LIMIT_MS):
            out.quarantined.append(Quarantined(src.folder, src.file, rule.id, _slow_reason(ms)))
            continue
        keep.append(rule)
    if new:
        info: dict = {}
        got = probe(new, budget, info=info)
        tested.update(got)
        if info.get("child") or info.get("budget"):
            # a rule the budget left untested waits for the next call: before its timed test, a backtracking rule
            # that passed the static checks could hold this call (Gate A of block 1). Where no test child can start,
            # the static checks alone stand, as before.
            untested = {s.hash for s in new if s.hash not in got}
            keep = [r for r in keep if r.id not in sources or sources[r.id].hash not in untested]
        bad = {h for h, ms in got.items() if ms is None or ms > PROBE_LIMIT_MS}
        if bad:
            gone = {rid for rid, s in sources.items() if s.hash in bad}
            for rule in keep:
                if rule.id in gone:
                    src = sources[rule.id]
                    out.quarantined.append(Quarantined(src.folder, src.file, rule.id, _slow_reason(got[src.hash])))
            keep = [r for r in keep if r.id not in gone]
    out.rules = keep


def load(cfg: dict | None = None, budget: float | None = PROBE_BUDGET) -> Loaded:
    """Every folder, read once per process. Never raises: a folder or a file that fails is named, and the rules of
    every other one stay."""
    if cfg is None and _LOADED:
        return _LOADED[0]
    remember = cfg is None
    out = Loaded()
    sources: dict = {}
    try:
        cfg = _config() if cfg is None else cfg
        state = _read_state()
        checks = state.get("checks") if isinstance(state.get("checks"), dict) else {}
        tested = state.get("tested") if isinstance(state.get("tested"), dict) else {}
        slow = state.get("slow") if isinstance(state.get("slow"), dict) else {}
        before = json.dumps([checks, tested, slow], sort_keys=True)
        cache = dict(checks)
        taken: set = set()
        for shown, path, source in folders(cfg):
            try:
                _one_folder(out, shown, path, source, taken, cache, sources)
            except Exception:  # noqa: BLE001 - one folder never costs the others
                out.folders.append(Folder(shown, path, source, "refused: the folder cannot be read"))
        _test_new_rules(out, sources, tested, slow, budget)
        # keep only what the folders hold now: a rule that changed is checked and tested again
        hashes = {s.hash for s in sources.values()}
        state["checks"] = {k: v for k, v in cache.items() if k in hashes or (isinstance(v, dict) and v.get("why"))}
        state["checks"] = dict(list(state["checks"].items())[-5000:])
        state["tested"] = {k: v for k, v in tested.items() if k in hashes}
        state["slow"] = {k: v for k, v in slow.items() if k in hashes}
        if json.dumps([state["checks"], state["tested"], state["slow"]], sort_keys=True) != before:
            _write_state(state)
    except Exception:  # noqa: BLE001 - whatever was read stays; nothing here stops a hook
        pass
    if remember:
        _LOADED[:] = [out]
        _SOURCES.clear()
        _SOURCES.update(sources)
    return out


def note_slow(rule, ms) -> None:
    """A rule of your own took too long in a scan (`ms`), or ran when the hook's watchdog answered (`ms` None): it is
    left out from the next load on, until it changes. One events.log line names it. Never raises."""
    try:
        src = _SOURCES.get(rule.id)
        if src is None:
            return
        state = _read_state()
        slow = state.get("slow") if isinstance(state.get("slow"), dict) else {}
        slow[src.hash] = {"ms": round(ms, 1) if isinstance(ms, (int, float)) else None}
        state["slow"] = slow
        _write_state(state)
        from types import SimpleNamespace
        from . import events
        events.record("-", "-", [SimpleNamespace(key="", type="RULE", kind=rule.id)],
                      outcome="quarantined: slow in a scan" + (f" ({ms:.0f} ms)" if ms else " (watchdog)"))
    except Exception:  # noqa: BLE001 - the rule is out of this process either way
        pass


# --------------------------------------------------------------- allow list --
def _allow_lines(lines) -> tuple[frozenset, frozenset]:
    values, ids = set(), set()
    for line in lines:
        line = line.rstrip("\r\n").strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("rule:"):
            rid = line[5:].strip()
            if rid:
                ids.add(rid)
        else:
            values.add(line)
    return frozenset(values), frozenset(ids)


def allow_list(cfg: dict | None = None) -> tuple[frozenset, frozenset]:
    """(exact values, rule ids) from ~/.maisecrets/allow.txt and the policy's `allow`. A file that cannot be read
    allows nothing: the stricter side."""
    try:
        own = ALLOW_FILE.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        own = []
    cfg = _config() if cfg is None else cfg
    policy = [x for x in cfg.get("policy_allow") or [] if isinstance(x, str)]
    return _allow_lines(own + policy)


switched_off = detect.switched_off   # a rule id on the allow list; the detector owns the rule (rules_cli uses it here)


def reset() -> None:
    """Forget what this process read (tests, and `rules check` of another folder)."""
    _LOADED.clear()
    _SOURCES.clear()


# ------------------------------------------------------------ session start --
def session_note() -> str | None:
    """At session start: when the set of quarantined rules changed since the last start, one events.log line and
    one sentence for the person. Unchanged, it says nothing again."""
    loaded = load()
    left_out = [q for q in loaded.quarantined if not q.kept]
    names = sorted(f"{q.folder}/{q.file}:{q.rule}:{q.reason}" for q in left_out)
    digest = hashlib.sha256("\n".join(names).encode("utf-8", "surrogatepass")).hexdigest()[:16]
    state = _read_state()
    if digest == state.get("note"):
        return None
    state["note"] = digest
    if not _write_state(state):
        return None    # a state that cannot be written would repeat the sentence at every start
    if not left_out:
        return None
    from types import SimpleNamespace
    from . import events
    events.record("SessionStart", "-", [SimpleNamespace(
        key="", type="RULE", kind=q.rule if q.rule.startswith(ID_PREFIX) else ID_PREFIX + "?")
        for q in left_out[:20]],
        outcome="quarantined: " + "; ".join(sorted({q.reason for q in left_out}))[:300])
    return (f"{len(left_out)} rule(s) of your own were left out because they fail a check; "
            "/maisecrets:rules says which and why.")


_WHY = {"missing": "is missing", "refused: the folder cannot be read": "cannot be read",
        "refused: not an absolute path": "is not an absolute path",
        "refused: inside the maisecrets folder": "is inside the maisecrets folder",
        "refused: the path cannot be resolved": "cannot be resolved"}


def _shown(text: str) -> str:
    """A folder name for a message: printable characters only, at most 120 of them."""
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text if len(text) <= 120 else text[:117] + "..."


def active_phrase(loaded: Loaded | None = None) -> str:
    """The part of the session start line that names the active rules of your own: ", with 12 rules of your own from
    2 folders", or "" when no rule of your own runs (the line then stays as it was)."""
    loaded = load() if loaded is None else loaded
    n = len(loaded.rules)
    if not n:
        return ""
    names = {_SOURCES[r.id].folder for r in loaded.rules if r.id in _SOURCES}
    m = len(names) or sum(1 for f in loaded.folders if f.state == "ok" and f.rules) or 1
    return (f", with {n} rule{'s' if n != 1 else ''} of your own from {m} folder{'s' if m != 1 else ''}")


def broken_folders_note(loaded: Loaded | None = None) -> str | None:
    """One sentence that names each folder of `rule_dirs` (the setting or the machine policy) that is missing or
    cannot be read, or None. It comes at every session start while the folder is missing: that is a broken setup, and
    without it only `maisecrets rules check` said so. The person's own rules.d may be absent."""
    loaded = load() if loaded is None else loaded
    bad = [f for f in loaded.folders if f.source in ("setting", "policy") and f.state != "ok"]
    if not bad:
        return None
    where = {"setting": "setting", "policy": "machine policy"}
    if len(bad) == 1:
        f = bad[0]
        why = _WHY.get(f.state, "cannot be read")
        return (f"Warning: the rule folder {_shown(f.shown)} ({where[f.source]}) {why}, "
                "so its rules of your own do not run.")
    parts = "; ".join(f"{_shown(f.shown)} ({where[f.source]}, {_WHY.get(f.state, 'cannot be read')})" for f in bad)
    return f"Warning: {len(bad)} rule folders do not load, so their rules of your own do not run: {parts}."
