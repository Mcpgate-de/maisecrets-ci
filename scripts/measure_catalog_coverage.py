#!/usr/bin/env python3
"""Measure maisecrets against the built-in examples of other secret catalogs. docs/BENCHMARKS.md has the pinned
commits and the results.

    python3 scripts/measure_catalog_coverage.py <catalogs dir> [--maisecrets DIR] [--baseline DIR] [--max-examples 6]
        [--workers N] [--out result.json]

<catalogs dir> holds one clone per catalog; a missing one is left out:

    noseyparker   https://github.com/praetorian-inc/noseyparker        YAML rules with examples
    kingfisher    https://github.com/mongodb/kingfisher                 YAML rules with examples
    gitleaks      https://github.com/gitleaks/gitleaks                  examples in the Go rule generator
    betterleaks   https://github.com/betterleaks/betterleaks            the Match tests in rules/*.go
    trufflehog    https://github.com/trufflesecurity/trufflehog         the expected values of the detector tests
    gitlab        https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules

The catalogs are read as data; none of their code runs. An example is a text and its secret: the part that the
catalog's own regex reports (its first non-empty group, else the whole match), or the whole example where that regex
does not compile in Python or does not match. The Go catalogs count the examples built from string literals (also
joined with +, and through GenerateSampleSecret) and from secrets.NewSecret, whose random string is seeded by the
rule id, so each run builds the same examples.
For trufflehog, an example is an expected value of a detector test that is a string literal of the test file, in the
shortest literal of that file that holds it.

Each rule with examples is probed with up to --max-examples of them, in two forms: the secret alone ("bare") and the
secret after `token = ` ("after a label"). The form counts as found when the hits of maisecrets, in the prompt or the
tool channel, cover the whole secret. A rule counts as found when one of its examples is found.

The script prints counts only, never an example. The store is a fresh temp directory, never ~/.maisecrets. The
gitleaks, betterleaks and gitlab catalogs need tomllib (Python 3.11+).

A clone that gives 0 rules is named with its commit and left out of the table; the script then exits 3, after it
writes the table and --out for the other catalogs.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABEL = "token = "
CATALOGS = ("noseyparker", "kingfisher", "gitleaks", "betterleaks", "trufflehog", "gitlab")
UNREAD = 3   # the exit code when a catalog clone gave 0 rules; the table and --out are still written


def _re2_to_python(rx: str) -> str:
    """RE2 to Python: a leading or inline (?i), \\z and the POSIX classes (as maisecrets' detect does)."""
    flags = ""
    if "(?i)" in rx:
        rx, flags = rx.replace("(?i)", ""), "(?i)"
    for posix, chars in (("[:alnum:]", "A-Za-z0-9"), ("[:alpha:]", "A-Za-z"), ("[:digit:]", "0-9"),
                         ("[:xdigit:]", "0-9A-Fa-f"), ("[:upper:]", "A-Z"), ("[:lower:]", "a-z"),
                         ("[:word:]", "0-9A-Za-z_")):
        rx = rx.replace(posix, chars)
    return flags + rx.replace(r"\z", r"\Z")


def compile_rx(rx: str | None):
    if not rx:
        return None
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for cand in (_re2_to_python(rx), rx):   # translated first: Python compiles [[:alnum:]] with another meaning
            try:
                return re.compile(cand)
            except (re.error, OverflowError, RecursionError):
                continue
    return None


def secret_of(crx, text: str, group: int | None = None) -> str:
    """The span the catalog's regex reports in an example: its group, the first non-empty group, or the match."""
    m = crx.search(text) if crx is not None else None
    if not m:
        return text.strip()
    if group is None or group > (m.lastindex or 0):
        group = next((i for i in range(1, (m.lastindex or 0) + 1) if m.group(i)), 0)
    return m.group(group) or m.group(0)


def rule(catalog: str, rule_id: str, texts: list, crx=None, group: int | None = None, secrets: list | None = None):
    pos = []
    for i, t in enumerate(texts):
        if not isinstance(t, str) or not t.strip():
            continue
        s = (secrets[i] if secrets else secret_of(crx, t, group)).strip().strip("'\"`")
        if s and s in t:
            pos.append({"text": t, "secret": s})
    return {"catalog": catalog, "rule": str(rule_id), "pos": pos}


# ------------------------------------------------------------------ YAML catalogs
def yaml_rules(catalog: str, files: list) -> list:
    import yaml
    out = []
    for f in sorted(files):
        try:
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:   # the message quotes the source line, which can be an example: name the file only
            print(f"{catalog}: {os.path.basename(f)} left out ({type(e).__name__})")
            continue
        for r in doc.get("rules", []) or []:
            out.append(rule(catalog, r.get("id") or r.get("name"), r.get("examples") or [],
                            compile_rx(r.get("pattern"))))
    return out


# ------------------------------------------------------------------ TOML catalogs
def gitlab_rules(root: Path) -> list:
    import tomllib
    out = []
    for f in sorted(glob.glob(str(root / "rules" / "**" / "*.toml"), recursive=True)):
        try:
            conf = tomllib.loads(Path(f).read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            print(f"gitlab: {os.path.basename(f)} left out ({type(e).__name__})")
            continue
        for r in conf.get("rules", []):
            out.append(rule("gitlab", r.get("id"), r.get("examples") or [], compile_rx(r.get("regex")),
                            r.get("secretGroup") or None))
    return out


# ------------------------------------------------------------------ Go string literals
_GOLIT = re.compile(r'"(?:[^"\\\n]|\\.)*"|`[^`]*`')
_IDENT = re.compile(r"[\w.]+")


def _go_unquote(tok: str) -> str:
    if tok[0] == "`":
        return tok[1:-1]
    try:
        return json.loads(tok)
    except ValueError:
        return tok[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape", "replace")


def go_tokens(src: str) -> list:
    """String literals ("s"), identifiers ("id") and punctuation ("p"); comments dropped."""
    toks, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i)
            i = n if j < 0 else j + 2
        elif c in "\"`":
            m = _GOLIT.match(src, i)
            if not m:
                i += 1
                continue
            toks.append(("s", _go_unquote(m.group())))
            i = m.end()
        elif c.isalnum() or c == "_":
            m = _IDENT.match(src, i)
            toks.append(("id", m.group()))
            i = m.end()
        elif c.isspace():
            i += 1
        else:
            toks.append(("p", c))
            i += 1
    return toks


class Sample(str):
    """A text built by GenerateSampleSecret: it knows its secret."""
    secret = ""


try:
    from re import _parser as _sre_parse, _constants as _sre_c
except ImportError:   # Python before 3.11
    import sre_parse as _sre_parse
    import sre_constants as _sre_c

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_CATEGORY = {_sre_c.CATEGORY_DIGIT: "0123456789", _sre_c.CATEGORY_WORD: _ALNUM + "_", _sre_c.CATEGORY_SPACE: " ",
             _sre_c.CATEGORY_NOT_SPACE: _ALNUM, _sre_c.CATEGORY_NOT_DIGIT: "abcdefXYZ", _sre_c.CATEGORY_NOT_WORD: "-"}
# the character classes of gitleaks' cmd/generate/config/utils
_GO_PATTERNS = {"Numeric": "[0-9]{%s}", "Hex": "[a-f0-9]{%s}", "AlphaNumeric": "[a-z0-9]{%s}",
                "AlphaNumericExtendedShort": "[a-z0-9_-]{%s}", "AlphaNumericExtended": r"[a-z0-9=_\-]{%s}",
                "AlphaNumericExtendedLong": r"[a-z0-9\/=_\+\-]{%s}"}


_REPEATS = tuple(c for c in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT, getattr(_sre_c, "POSSESSIVE_REPEAT", None)) if c)


def _charset(items) -> list:
    neg, chars = False, set()
    for op, av in items:
        if op is _sre_c.NEGATE:
            neg = True
        elif op is _sre_c.LITERAL:
            chars.add(chr(av))
        elif op is _sre_c.RANGE:
            chars.update(chr(c) for c in range(av[0], min(av[1], 0x24f) + 1))
        elif op is _sre_c.CATEGORY:
            chars.update(_CATEGORY.get(av, ""))
    if neg:
        return [c for c in _ALNUM if c not in chars] or ["x"]
    return sorted(c for c in chars if c.isprintable()) or ["x"]


def _gen(parsed, rng, groups: dict) -> str:
    """A string the parsed regex matches, as secrets.NewSecret builds one: each repeat at its minimum length or a
    little more."""
    s = ""
    for op, av in parsed:
        if op is _sre_c.LITERAL:
            s += chr(av)
        elif op is _sre_c.NOT_LITERAL:
            s += rng.choice([c for c in _ALNUM if ord(c) != av])
        elif op is _sre_c.ANY:
            s += rng.choice(_ALNUM)
        elif op is _sre_c.IN:
            s += rng.choice(_charset(av))
        elif op is _sre_c.BRANCH:
            s += _gen(rng.choice(av[1]), rng, groups)
        elif op is _sre_c.SUBPATTERN:
            g = _gen(av[-1], rng, groups)
            if av[0]:
                groups[av[0]] = g
            s += g
        elif op in _REPEATS:
            lo, hi, sub = av
            hi = lo + 40 if hi == _sre_c.MAXREPEAT else min(hi, lo + 40)
            n = rng.choice([lo, lo, rng.randint(lo, min(hi, lo + 8))]) if lo >= 8 else rng.randint(lo, hi)
            s += "".join(_gen(sub, rng, groups) for _ in range(n))
        elif op is _sre_c.GROUPREF:
            s += groups.get(av, "")
        elif op is getattr(_sre_c, "ATOMIC_GROUP", None):
            s += _gen(av, rng, groups)
    return s


def _entropy(s: str) -> float:
    import math
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def new_secret(rx: str, rng, min_entropy: float = 0.0) -> str | None:
    """secrets.NewSecret(rx) of the Go generators: a random string that rx matches, seeded per rule."""
    try:
        parsed = _sre_parse.parse(_re2_to_python(rx))
    except (re.error, OverflowError, RecursionError):
        return None
    s = None
    for _ in range(50):
        s = _gen(parsed, rng, {})
        if not s or _entropy(s) >= min_entropy:
            break
    return s or None


class GoExamples:
    """Evaluates the small expression language of the gitleaks and betterleaks rule generators: string literals, +,
    variables, []string{...}, append(...), GenerateSampleSecret(s), the character classes of utils and
    secrets.NewSecret (a random string, seeded by the rule id). Anything else evaluates to None and is left out."""

    def __init__(self, toks: list, rng=None):
        import random
        self.t, self.vars, self.rng = toks, {}, rng or random.Random(0)

    def _split(self, a: int, b: int, sep: str) -> list:
        parts, depth, start = [], 0, a
        for j in range(a, b):
            tk = self.t[j]
            if tk[0] == "p" and tk[1] in "([{":
                depth += 1
            elif tk[0] == "p" and tk[1] in ")]}":
                depth -= 1
            elif tk == ("p", sep) and depth == 0:
                parts.append((start, j))
                start = j + 1
        parts.append((start, b))
        return [(x, y) for x, y in parts if y > x]

    def expr(self, a: int, b: int):
        vals = [self.term(x, y) for x, y in self._split(a, b, "+")]
        if not vals or any(v is None for v in vals):
            return None
        if len(vals) == 1:
            return vals[0]
        if any(isinstance(v, list) for v in vals):
            return None
        out = Sample("".join(vals))
        out.secret = next((v.secret for v in vals if isinstance(v, Sample) and v.secret), "")
        return out

    def term(self, a: int, b: int):
        t = self.t
        if b - a == 1:
            return t[a][1] if t[a][0] == "s" else self.vars.get(t[a][1]) if t[a][0] == "id" else None
        if t[a][0] == "id" and t[a + 1] == ("p", "(") and t[b - 1] == ("p", ")"):
            name = t[a][1].split(".")[-1]
            spans = self._split(a + 2, b - 1, ",")
            args = [self.expr(x, y) for x, y in spans]
            if name in _GO_PATTERNS and len(args) == 1 and isinstance(args[0], str):
                return _GO_PATTERNS[name] % args[0]
            if name == "Hex8_4_4_4_12":
                return "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            if name in ("NewSecret", "NewSecretWithEntropy") and args and isinstance(args[0], str):
                ent = 0.0
                if len(spans) > 1 and spans[1][1] - spans[1][0] == 1:
                    try:
                        ent = float(t[spans[1][0]][1])
                    except (TypeError, ValueError):
                        ent = 0.0
                return new_secret(args[0], self.rng, ent)
            if name == "Repeat" and len(args) == 2 and isinstance(args[0], str) and spans[1][1] - spans[1][0] == 1:
                try:
                    return args[0] * int(t[spans[1][0]][1])
                except (TypeError, ValueError):
                    return None
            if name in ("GenerateSampleSecret", "GenerateSampleSecrets") and len(args) == 2 \
                    and all(isinstance(x, str) for x in args):
                ident, sec = args[0], (args[1].secret or args[1]) if isinstance(args[1], Sample) else args[1]
                forms = ([f'{ident}_api_token = "{sec}"'] if name == "GenerateSampleSecret"
                         else [f'{ident}Token = "{sec}"', f"{ident}_token: {sec}", f"{ident.upper()}_TOKEN={sec}"])
                res = []
                for f in forms:
                    s = Sample(f)
                    s.secret = sec
                    res.append(s)
                return res[0] if name == "GenerateSampleSecret" else res
            if name == "append" and args and isinstance(args[0], list):
                out = list(args[0])
                for x in args[1:]:
                    if x is not None:
                        out.extend(x if isinstance(x, list) else [x])
                return out
            return None
        if t[a] == ("p", "[") and t[b - 1] == ("p", "}"):   # []string{...}
            k = next((j for j in range(a, b) if t[j] == ("p", "{")), None)
            if k is None:
                return None
            vals = []
            for x, y in self._split(k + 1, b - 1, ","):
                v = self.expr(x, y)
                if isinstance(v, list):
                    vals.extend(v)
                elif v is not None:
                    vals.append(v)
            return vals
        return None

    def run(self) -> list:
        """The true positives of one rule function: the value of tps / truePositives."""
        t, tps, i = self.t, [], 0
        while i < len(t):
            if t[i][0] == "id" and i + 2 < len(t) and (t[i + 1] == ("p", "=") or (t[i + 1] == ("p", ":")
                                                                                and t[i + 2] == ("p", "="))):
                k = i + 2 if t[i + 1] == ("p", "=") else i + 3
                depth, j = 0, k
                while j < len(t):
                    tk = t[j]
                    if tk[0] == "p" and tk[1] in "([{":
                        depth += 1
                    elif tk[0] == "p" and tk[1] in ")]}":
                        if depth == 0:
                            break
                        depth -= 1
                    elif (depth == 0 and j > k and tk[0] == "id" and t[j - 1] not in (("p", "+"), ("p", ","))
                          and (tk[1] in ("return", "if", "for", "var")
                               or (j + 1 < len(t) and t[j + 1][0] == "p" and t[j + 1][1] in ":="))):
                        break                                   # the next statement
                    j += 1
                v = self.expr(k, j)
                if t[i][1] in ("tps", "truePositives"):
                    tps = v if isinstance(v, list) else [v] if isinstance(v, str) else []
                elif v is not None:
                    self.vars[t[i][1]] = v
                i = max(j, i + 1)
            else:
                i += 1
        return [x for x in tps if isinstance(x, str)]


_TEST_CALLS = ("Match", "MatchComponent")


def rulebuilder_rules(catalog: str, files: list, rxs: dict) -> list:
    """The layout of betterleaks since 2026-11: rules/*.go, one `rulebuilder.Add(config.Rule{ID: ..., Tests: ...})`
    per rule, each true positive a `rulebuilder.Match(name, input, secret)` that names its secret. The regex of the
    rule (config/<catalog>.toml) goes along for scripts/draft_format_rules.py."""
    out = []
    for f in files:
        for chunk in Path(f).read_text(encoding="utf-8").split("rulebuilder.Add(")[1:]:
            t = go_tokens(chunk)
            rid = next((t[i + 2][1] for i in range(len(t) - 2)
                        if t[i] == ("id", "ID") and t[i + 1] == ("p", ":") and t[i + 2][0] == "s"), None)
            if rid is None:
                continue
            ev, texts, secrets = GoExamples(t), [], []
            for i in range(len(t) - 1):
                if t[i][0] != "id" or t[i][1].split(".")[-1] not in _TEST_CALLS or t[i + 1] != ("p", "("):
                    continue
                depth, j = 0, i + 1
                while j < len(t):
                    if t[j][0] == "p" and t[j][1] in "([{":
                        depth += 1
                    elif t[j][0] == "p" and t[j][1] in ")]}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                args = [ev.expr(a, b) for a, b in ev._split(i + 2, j, ",")]
                if len(args) == 3 and all(isinstance(x, str) for x in args[1:]):
                    texts.append(args[1])
                    secrets.append(args[2])
            rx, group = rxs.get(rid, (None, None))
            out.append(rule(catalog, rid, texts, compile_rx(rx), group or None, secrets=secrets))
    return out


def go_rules(catalog: str, root: Path) -> list:
    import tomllib
    cfg = root / "config" / f"{catalog}.toml"
    conf = tomllib.loads(cfg.read_text(encoding="utf-8")) if cfg.is_file() else {}
    rxs = {r["id"]: (r.get("regex"), r.get("secretGroup")) for r in conf.get("rules", [])}
    new = sorted(f for f in glob.glob(str(root / "rules" / "**" / "*.go"), recursive=True)
                 if not f.endswith("_test.go"))
    if not (root / "cmd" / "generate" / "config" / "rules").is_dir() and new:
        return rulebuilder_rules(catalog, new, rxs)
    out = []
    for f in sorted(glob.glob(str(root / "cmd" / "generate" / "config" / "rules" / "*.go"))):
        if f.endswith("_test.go"):
            continue
        for chunk in re.split(r"\nfunc ", Path(f).read_text(encoding="utf-8"))[1:]:
            m = re.search(r'\b(?:Rule)?ID:\s*"([^"]+)"', chunk)
            if not m:
                continue
            rx, group = rxs.get(m.group(1), (None, None))
            crx = compile_rx(rx)
            texts, secrets = [], []
            import random
            for ex in GoExamples(go_tokens(chunk[chunk.find("{") + 1:]), random.Random(m.group(1))).run():
                texts.append(str(ex))
                secrets.append(ex.secret if isinstance(ex, Sample) and ex.secret else secret_of(crx, ex, group or None))
            out.append(rule(catalog, m.group(1), texts, secrets=secrets))
    return out


def trufflehog_rules(root: Path) -> list:
    out = []
    base = root / "pkg" / "detectors"
    for f in sorted(glob.glob(str(base / "**" / "*_test.go"), recursive=True)):
        if "integration" in os.path.basename(f):
            continue
        toks = go_tokens(Path(f).read_text(encoding="utf-8"))
        lits = [v for k, v in toks if k == "s"]
        names = {}
        for i, (k, v) in enumerate(toks[:-2]):
            if k == "id" and toks[i + 1][0] == "p" and toks[i + 1][1] in ":=":
                j = i + 2 if toks[i + 1][1] == "=" else i + 3 if toks[i + 2] == ("p", "=") else i + 2
                if j < len(toks) and toks[j][0] == "s" and (j + 1 >= len(toks) or toks[j + 1] != ("p", "+")):
                    names[v] = toks[j][1]
        texts, secrets = [], []
        for i, tk in enumerate(toks[:-3]):
            if tk == ("id", "want") and toks[i + 1] == ("p", ":") and toks[i + 2] == ("p", "["):
                k = next((j for j in range(i + 2, min(i + 8, len(toks))) if toks[j] == ("p", "{")), None)
                if k is None:
                    continue
                j = k + 1
                while j < len(toks) and toks[j] != ("p", "}"):
                    v = toks[j][1] if toks[j][0] == "s" else names.get(toks[j][1]) if toks[j][0] == "id" else None
                    nxt = toks[j + 1] if j + 1 < len(toks) else ("p", "}")
                    if v and nxt in (("p", ","), ("p", "}")) and v not in secrets:
                        host = [x for x in lits if v in x]
                        if host:
                            texts.append(min(host, key=len))
                            secrets.append(v)
                    j += 1
        out.append(rule("trufflehog", os.path.relpath(os.path.dirname(f), base), texts, secrets=secrets))
    return out


def load_catalog(name: str, root: Path) -> list:
    if name == "noseyparker":
        return yaml_rules(name, glob.glob(str(root / "crates" / "noseyparker" / "data" / "default" / "builtin"
                                                / "rules" / "*.yml")))
    if name == "kingfisher":
        return yaml_rules(name, glob.glob(str(root / "crates" / "kingfisher-rules" / "data" / "rules" / "*.yml"))
                          or glob.glob(str(root / "data" / "rules" / "*.yml")))
    if name in ("gitleaks", "betterleaks"):
        return go_rules(name, root)
    if name == "trufflehog":
        return trufflehog_rules(root)
    return gitlab_rules(root)


# ------------------------------------------------------------------ probe
_detect = None


def _init(tree: str) -> None:
    global _detect
    home = tempfile.mkdtemp(prefix="maisecrets-coverage-")
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": ["de"]}, fh)
    os.environ["MAISECRETS_" + "HOME"] = home
    os.environ["MAISECRETS_LOCALE"] = "de_DE"
    sys.path.insert(0, tree)
    from maisecrets import detect
    _detect = detect


def _found(text: str, a: int, b: int) -> bool:
    """Whether the hits of one channel together cover text[a:b] whole: a hit on a part leaves the rest in the clear."""
    for ch in ("prompt", "tool"):
        pos = a
        for m in sorted(_detect.scan(text, channel=ch), key=lambda m: m.start):
            if m.start <= pos < m.end:
                pos = m.end
        if pos >= b:
            return True
    return False


def _probe(job: tuple) -> tuple:
    key, examples = job
    bare = label = False
    for ex in examples:
        s = ex["secret"]
        bare = bare or _found(s, 0, len(s))
        label = label or _found(LABEL + s, len(LABEL), len(LABEL) + len(s))
        if bare and label:
            break
    return key, bare, label


def probe(tree: str, rules: list, max_examples: int, workers: int) -> dict:
    jobs = [(i, r["pos"][:max_examples]) for i, r in enumerate(rules) if r["pos"]]
    with Pool(workers, initializer=_init, initargs=(tree,)) as pool:
        return {k: (b, lab) for k, b, lab in pool.imap_unordered(_probe, jobs, chunksize=8)}


def commit_of(path: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=30).stdout.strip() or "-"
    except (OSError, subprocess.SubprocessError):
        return "-"


def table(rules: list, results: dict) -> dict:
    out = collections.OrderedDict()
    for i, r in enumerate(rules):
        c = out.setdefault(r["catalog"], collections.Counter())
        c["rules"] += 1
        if not r["pos"]:
            continue
        c["with_examples"] += 1
        bare, label = results[i]
        c["bare"] += bare
        c["label"] += label
    return out


def pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f} %" if d else "-"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("catalogs", help="directory with one clone per catalog")
    ap.add_argument("--maisecrets", default=str(ROOT), help="maisecrets checkout to measure (default: this one)")
    ap.add_argument("--baseline", help="a second maisecrets checkout, such as the last release")
    ap.add_argument("--max-examples", type=int, default=6)
    ap.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)))
    ap.add_argument("--out", help="write the counts and the per-rule results (rule ids, no example) to this file")
    a = ap.parse_args(argv)
    root = Path(a.catalogs)
    rules, commits, unread = [], {}, {}
    for name in CATALOGS:
        if not (root / name).is_dir():
            continue
        try:
            got = load_catalog(name, root / name)
        except ImportError as e:   # tomllib before 3.11, or no PyYAML: a partial table would read as the full one
            print(f"{name}: cannot be read ({e}); use Python 3.11+ with PyYAML")
            return 2
        if not got:   # a clone that reads as no rule at all: its layout changed, and the table would lack its row
            unread[name] = commit_of(root / name)
            print(f"{name}: 0 rules read at {unread[name][:12]}; its layout changed, adapt load_catalog()")
            continue
        rules += got
        commits[name] = commit_of(root / name)
    trees = [("maisecrets", a.maisecrets)] + ([("baseline", a.baseline)] if a.baseline else [])
    res, per_rule = {}, {}
    for label, tree in trees:
        got = probe(tree, rules, a.max_examples, a.workers)
        res[label] = table(rules, got)
        per_rule[label] = [[rules[i]["catalog"], rules[i]["rule"], bare, lab] for i, (bare, lab) in sorted(got.items())]
    print(f"Catalog coverage, up to {a.max_examples} examples per rule, found = the hits of one channel cover the "
          "whole secret")
    print(f"{'catalog':12s} {'commit':12s} {'rules':>6s} {'w/ examples':>11s}  " + "  ".join(
        f"{lab + ' bare':>20s} {lab + ' label':>21s}" for lab, _ in trees))
    for name in commits:
        c0 = res["maisecrets"][name]
        cells = []
        for lab, _ in trees:
            c = res[lab][name]
            w = c["with_examples"]
            cells.append(f"{c['bare']:6d} ({pct(c['bare'], w):>7s})      {c['label']:6d} ({pct(c['label'], w):>7s})")
        print(f"{name:12s} {commits[name][:12]:12s} {c0['rules']:6d} {c0['with_examples']:11d}  " + "  ".join(cells))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump({"commits": commits, "unread": unread, "max_examples": a.max_examples, "counts": res,
                       "rules": per_rule}, fh, indent=1)
    return UNREAD if unread else 0


if __name__ == "__main__":
    sys.exit(main())
