#!/usr/bin/env python3
"""Draft prefix rules for catalog rules that maisecrets misses without a label (docs/DETECTION-COVERAGE.md, loop 2).

    python3 scripts/draft_format_rules.py CATALOGS RESULT.json [--out DIR]

RESULT.json is the output of scripts/measure_catalog_coverage.py (or of scripts/coverage_drift.py) on CATALOGS. For
each catalog rule whose examples maisecrets does not find bare, the script reads the rule's secret group, keeps its
literal start of four characters or more as the prefix, writes the rest back as a regex in the form of
maisecrets/detection/rules/prefixes.txt, and keeps the rule only when it finds every example of the catalog rule
whole, bare and in a sentence. It writes, never with an example value:

- DIR/prefixes-draft.txt: the rule lines, to paste into prefixes.txt after review;
- DIR/templates-draft.txt: per rule the prefix and a class template of one example (a, A, 9), the oracle of
  tests/test_catalog_prefixes.py;
- DIR/dropped.txt: the rules left out and why.

A person or an agent reviews the draft, runs the false-positive bank and the gate, and merges; nothing is added by
itself. Left out on purpose: prefixes of fewer than four characters, names of public ids (client id, publishable key,
public key) and connection strings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import measure_catalog_coverage as mcc  # noqa: E402

try:
    from re import _constants as C, _parser as P
except ImportError:  # Python before 3.11
    import sre_constants as C
    import sre_parse as P

PUBLIC = re.compile(r"(?i)client.?id|app.?id|publishable|public|pub.?key|site.?key|connection|\bur[li]\b|webhook")

CAT = {C.CATEGORY_DIGIT: r"\d", C.CATEGORY_NOT_DIGIT: r"\D", C.CATEGORY_WORD: r"\w", C.CATEGORY_NOT_WORD: r"\W",
       C.CATEGORY_SPACE: r"\s", C.CATEGORY_NOT_SPACE: r"\S"}
AT = {C.AT_BOUNDARY: r"\b", C.AT_NON_BOUNDARY: r"\B", C.AT_BEGINNING: "^", C.AT_END: "$",
      C.AT_BEGINNING_STRING: r"\A", C.AT_END_STRING: r"\Z"}


def lit(c: int, in_class: bool = False) -> str:
    ch = chr(c)
    if ch.isalnum() or ch == "_":
        return ch
    if in_class and ch not in "]\\^-":
        return ch
    return "\\" + ch if ch in ".^$*+?{}[]\\|()-/" or in_class else re.escape(ch)


def unparse(items) -> str:
    out = []
    for op, av in items:
        if op is C.LITERAL:
            out.append(lit(av))
        elif op is C.NOT_LITERAL:
            out.append("[^" + lit(av, True) + "]")
        elif op is C.ANY:
            out.append(".")
        elif op is C.IN:
            neg = av and av[0][0] is C.NEGATE
            parts = []
            for o, a in av[1:] if neg else av:
                if o is C.LITERAL:
                    parts.append(lit(a, True))
                elif o is C.RANGE:
                    parts.append(lit(a[0], True) + "-" + lit(a[1], True))
                elif o is C.CATEGORY:
                    parts.append(CAT[a])
                else:
                    raise ValueError(f"class item {o}")
            out.append("[" + ("^" if neg else "") + "".join(parts) + "]")
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            lo, hi, sub = av
            inner = unparse(sub)
            if len(sub) != 1 or sub[0][0] in (C.SUBPATTERN, C.BRANCH) and not inner.startswith("(?:"):
                inner = "(?:" + inner + ")"
            if (lo, hi) == (0, C.MAXREPEAT):
                q = "*"
            elif (lo, hi) == (1, C.MAXREPEAT):
                q = "+"
            elif (lo, hi) == (0, 1):
                q = "?"
            elif hi == C.MAXREPEAT:
                q = "{%d,}" % lo
            elif lo == hi:
                q = "{%d}" % lo
            else:
                q = "{%d,%d}" % (lo, hi)
            out.append(inner + q + ("?" if op is C.MIN_REPEAT else ""))
        elif op is C.SUBPATTERN:
            gid, add, dele, sub = av
            if add or dele:
                raise ValueError("inline flags in a group")
            out.append("(?:" + unparse(sub) + ")")
        elif op is C.BRANCH:
            out.append("(?:" + "|".join(unparse(alt) for alt in av[1]) + ")")
        elif op is C.AT:
            out.append(AT[av])
        elif op is C.CATEGORY:
            out.append(CAT[av])
        elif op in (C.ASSERT, C.ASSERT_NOT):
            direction, sub = av
            out.append("(?" + ("<" if direction < 0 else "") + ("=" if op is C.ASSERT else "!") + unparse(sub) + ")")
        else:
            raise ValueError(f"op {op}")
    return "".join(out)


def secret_items(tree, group):
    def walk(items):
        for op, av in items:
            if op is C.SUBPATTERN:
                if av[0] is not None and (group is None or av[0] == group):
                    return list(av[-1])
                inner = walk(av[-1])
                if inner is not None:
                    return inner
            elif op is C.BRANCH:
                for alt in av[1]:
                    inner = walk(alt)
                    if inner is not None:
                        return inner
        return None
    got = walk(list(tree))
    return got if got is not None else list(tree)


def split_prefix(items, prefix):
    """The items after the literal prefix, or None when the secret does not start with exactly that literal."""
    got, i = "", 0
    while i < len(items) and len(got) < len(prefix):
        op, av = items[i]
        if op is C.LITERAL:
            got += chr(av)
        elif op is C.IN and len(av) == 1 and av[0][0] is C.LITERAL:
            got += chr(av[0][1])
        else:
            return None
        i += 1
    return items[i:] if got == prefix else None




def lead_split(items):
    """(the literal start, the items after it) of a parsed pattern."""
    lit_s, i = "", 0
    while i < len(items):
        op, av = items[i]
        if op is C.LITERAL:
            lit_s += chr(av)
        elif op is C.IN and len(av) == 1 and av[0][0] is C.LITERAL:
            lit_s += chr(av[0][1])
        else:
            break
        i += 1
    return lit_s, items[i:]


def template(value: str) -> str:
    return "".join("a" if c.islower() else "A" if c.isupper() else "9" if c.isdigit() else c for c in value)


def draft(rules: list, found: dict) -> tuple:
    """(kept, dropped): kept are dicts with id, line, prefix, template; dropped maps an id to its reason."""
    kept, dropped, seen = [], {}, set()
    for r in rules:
        key = (r["catalog"], r["rule"])
        if found.get(key, (False,))[0] or not r["pos"] or not r.get("rx"):
            continue
        rid = re.sub(r"[^a-z0-9]+", "-", f"{r['catalog']} {r['rule']}".lower()).strip("-")[:60]
        if PUBLIC.search(r["rule"]):
            dropped[rid] = "public id, connection string or URL"
            continue
        try:
            lead, rest = lead_split(secret_items(P.parse(r["rx"]), r.get("group")))
            body = unparse(rest)
        except Exception as e:  # noqa: BLE001 - an unusual pattern is left out, with its reason
            dropped[rid] = f"pattern: {type(e).__name__}"
            continue
        body = re.sub(r"(?:\\b|\$|\\Z)+$", "", body)
        if len(lead) < 4 or not re.search(r"[A-Za-z]", lead):
            dropped[rid] = "no literal start of four characters"
            continue
        if lead in seen:
            dropped[rid] = "prefix already drafted"
            continue
        esc = "".join(lit(ord(ch)) for ch in lead)
        rx = f"{esc}(?:(?<![A-Za-z0-9_-]{esc})|(?<=\\\\[nrt]{esc})){body}(?![A-Za-z0-9_-])"
        try:
            crx = re.compile(rx)
        except re.error:
            dropped[rid] = "does not compile"
            continue
        secrets = [p["secret"] for p in r["pos"]]
        if not all(any(m.group(0) == s for m in crx.finditer(t)) for s in secrets for t in (s, f"x {s} y")):
            dropped[rid] = "misses an example of its catalog rule"
            continue
        seen.add(lead)
        ex = next(s for s in secrets if s.startswith(lead))
        kept.append({"id": rid, "line": f"{rid:44s}{rx}", "prefix": lead, "template": template(ex[len(lead):])})
    return kept, dropped


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("catalogs", type=Path)
    ap.add_argument("result", type=Path)
    ap.add_argument("--out", type=Path, default=Path("format-drafts"))
    a = ap.parse_args(argv)
    rows = json.loads(a.result.read_text(encoding="utf-8"))["rules"]["maisecrets"]
    found = {(c, r): (b, lab) for c, r, b, lab in rows}
    original = mcc.rule

    def rule(catalog, rule_id, texts, crx=None, group=None, secrets=None):
        out = original(catalog, rule_id, texts, crx, group, secrets)
        out["rx"], out["group"] = getattr(crx, "pattern", None), group
        return out
    mcc.rule = rule
    rules = []
    for name in mcc.CATALOGS:
        if (a.catalogs / name).is_dir():
            rules += mcc.load_catalog(name, a.catalogs / name)
    kept, dropped = draft(rules, found)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "prefixes-draft.txt").write_text("".join(k["line"] + "\n" for k in kept), encoding="utf-8")
    (a.out / "templates-draft.txt").write_text("".join(f"{k['id']}\t{k['prefix']}\t{k['template']}\n" for k in kept),
                                               encoding="utf-8")
    (a.out / "dropped.txt").write_text("".join(f"{k}\t{v}\n" for k, v in sorted(dropped.items())), encoding="utf-8")
    print(f"drafted {len(kept)} prefix rules; left out {len(dropped)} (see {a.out / 'dropped.txt'})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
