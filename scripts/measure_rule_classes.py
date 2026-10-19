"""Measure what each class of rules adds: the credentials it alone catches and the false alarms it alone causes.

    python3 scripts/measure_rule_classes.py [--creddata DIR] [--holdout DIR] [--regions de] [--channels prompt,tool]
        [--level coarse|class] [--workers N] [--out result.json]

For each class of rules (maisecrets/detection/registry.py: coarse_class, or rule_class with --level class) the
script scans
every input once with all rules (the base) and once with that class switched off (`detect.scan(enabled=...)` with the
keys of every other rule and pass). The difference is what the class adds at the margin: when it is off, another rule
can still take the span.

- recall lost: the labelled values the base masks and the variant does not (CredData rows with GroundTruth T, the
  HIT values of tests/fp_corpus.py, the POSITIVE values of tests/fp_corpus_pii.py, FORMS_HIT of
  tests/fp_corpus_forms.py, the planted values of the Cloakroom holdout sets v2 to v7);
- false hits saved: the inputs that have a hit in the base and none in the variant (CredData rows with GroundTruth F,
  whose value is masked; the NO_HIT snippets of tests/fp_corpus.py; PII_NO_HIT of tests/fp_corpus_pii.py;
  FORMS_NO_HIT of tests/fp_corpus_forms.py; the clean holdout samples).

A value counts as masked when it no longer appears after every match is replaced, as in measure_creddata.py. Only an
input with a hit of the class in the base can change when the class is off: a rule that took no span blocked no other
rule. The script scans the variant on those inputs only, and checks on a sample of the others that the base with
every rule enabled by key equals the base with enabled=None.

The output holds counts and class names, never a value or a line. The store is a fresh temp directory.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import shutil
import sys
import tempfile
from multiprocessing import get_context
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
_HOME_VAR = "MAISECRETS" + "_HOME"
_detect = None
_enabled_of: dict = {}
_class_of_kind: dict = {}


# ------------------------------------------------------------------------------------------------- inputs --
def inputs(creddata: str | None, holdout: str | None) -> list:
    """(corpus, text, positives, negative): positives are the values that must be masked; negative is True for a text
    that must have no hit, and for a CredData F row the value that must stay (a false alarm when masked)."""
    out = []
    if creddata:
        sys.path.insert(0, str(ROOT / "scripts"))
        import measure_creddata as mc
        by_line: dict = collections.defaultdict(lambda: ([], []))
        for gt, _cat, line, value, _a, _b, _fp, _rid in mc.load_items(creddata):
            by_line[line][0 if gt == "T" else 1].append(value)
        out += [("creddata", line, tuple(t), tuple(f)) for line, (t, f) in sorted(by_line.items())]
    sys.path.insert(0, str(TESTS))
    import fp_corpus
    out += [("fp_corpus", text.replace("§", ""), (), True) for _, text in fp_corpus.NO_HIT]
    out += [("fp_corpus", text.replace("§", ""), tuple(v.replace("§", "") for _, v in exp), ())
            for _, text, exp in fp_corpus.HIT]
    if (TESTS / "fp_corpus_pii.py").exists():
        import fp_corpus_pii
        out += [("fp_corpus_pii", text, (), True) for _, text in fp_corpus_pii.PII_NO_HIT]
        out += [("fp_corpus_pii", text, tuple(vals), ()) for _, text, vals in fp_corpus_pii.POSITIVE]
    if (TESTS / "fp_corpus_forms.py").exists():
        import fp_corpus_forms
        out += [("fp_corpus_forms", text, (), True) for _, text in fp_corpus_forms.FORMS_NO_HIT]
        out += [("fp_corpus_forms", text, tuple(vals), ()) for _, text, vals in fp_corpus_forms.FORMS_HIT]
    if holdout:
        for n in range(2, 8):
            path = Path(holdout) / f"holdout_v{n}.jsonl"
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                it = json.loads(line)
                out.append(("holdout", it["text"], tuple(it["planted"]), not it["planted"]))
    return out


# ----------------------------------------------------------------------------------------------- the scan --
def _init(home: str, level: str) -> None:
    global _detect
    os.environ[_HOME_VAR] = home
    os.environ["MAISECRETS_LOCALE"] = "de_DE"
    for k in list(os.environ):
        if k.startswith(("CODEX_", "CLAUDE_CODE_", "CLAUDE_PLUGIN_OPTION_")) or k in ("CLAUDECODE",
                                                                                     "MAISECRETS_TEST_HOME_OWNED"):
            del os.environ[k]
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect, registry
    _detect = detect
    specs = [s for s, _ in detect.rule_specs()] + detect.pass_specs()
    name = registry.coarse_class if level == "coarse" else (lambda s: s.rule_class)
    every = {s.key for s in specs if s.source not in registry.PASSES} | {s.id for s in specs
                                                                           if s.source in registry.PASSES}
    by_class: dict = collections.defaultdict(set)
    for s in specs:
        by_class[name(s)].add(s.id if s.source in registry.PASSES else s.key)
        _class_of_kind.setdefault(s.id, set()).add(name(s))
    _enabled_of.clear()
    _enabled_of["*"] = frozenset(every)
    for c, keys in by_class.items():
        _enabled_of[c] = frozenset(every - keys)


def _classes(_=None) -> dict:
    return {c: len(_enabled_of["*"] - e) for c, e in _enabled_of.items() if c != "*"}


def _masked(text: str, ms) -> str:
    out = text
    for i, m in enumerate(sorted(ms, key=lambda m: -m.start)):
        out = out[:m.start] + f"[{m.type}_{i}]" + out[m.end:]
    return out


def _outcome(text, ms, positives, negative) -> tuple:
    """(positives masked: tuple of bool, the negative side flagged: bool)."""
    out = _masked(text, ms)
    pos = tuple(v not in out for v in positives)
    if negative is True:
        neg = bool(ms)
    elif negative:
        neg = any(v not in out for v in negative)
    else:
        neg = False
    return pos, neg


def _base(item):
    i, text, positives, negative, channel, check = item
    ms = _detect.scan(text, channel=channel)
    if check and ms != _detect.scan(text, channel=channel, enabled=_enabled_of["*"]):
        raise SystemExit("the base with every rule enabled by key differs from enabled=None")
    classes = sorted({c for m in ms for c in _class_of_kind.get(m.kind, {"(unknown)"})})
    return i, _outcome(text, ms, positives, negative), classes


def _variant(item):
    i, c, text, positives, negative, channel = item
    return i, c, _outcome(text, _detect.scan(text, channel=channel, enabled=_enabled_of[c]), positives, negative)


def measure(items: list, regions: tuple, channels: tuple, level: str, workers: int) -> dict:
    home = tempfile.mkdtemp(prefix="maisecrets-classes-")
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": list(regions)}, fh)
    rnd = random.Random(7)
    result: dict = {"regions": list(regions), "level": level, "channels": {}}
    try:
        with get_context("spawn").Pool(max(1, workers), initializer=_init, initargs=(home, level)) as pool:
            sizes = pool.apply(_classes)
            result["rules_per_class"] = dict(sorted(sizes.items()))
            for ch in channels:
                work = [(i, t, p, n, ch, rnd.random() < 0.02) for i, (_, t, p, n) in enumerate(items)]
                base, touched = {}, collections.defaultdict(list)
                for i, outcome, classes in pool.imap_unordered(_base, work, chunksize=40):
                    base[i] = outcome
                    for c in classes:
                        touched[c].append(i)
                var_work = [(i, c, items[i][1], items[i][2], items[i][3], ch)
                            for c in sizes for i in touched.get(c, ())]
                table = {c: collections.Counter() for c in sizes}
                for i, c, (pos, neg) in pool.imap_unordered(_variant, var_work, chunksize=20):
                    corpus = items[i][0]
                    bpos, bneg = base[i]
                    lost = sum(1 for a, b in zip(bpos, pos) if a and not b)
                    gained = sum(1 for a, b in zip(bpos, pos) if b and not a)
                    table[c][corpus + ":recall_lost"] += lost
                    table[c][corpus + ":recall_gained"] += gained
                    table[c][corpus + ":false_hits_saved"] += int(bneg and not neg)
                    table[c][corpus + ":false_hits_added"] += int(neg and not bneg)
                totals = collections.Counter()
                for i, (pos, neg) in base.items():
                    corpus = items[i][0]
                    totals[corpus + ":positives"] += len(pos)
                    totals[corpus + ":positives_masked"] += sum(pos)
                    totals[corpus + ":negatives"] += int(bool(items[i][3]))
                    totals[corpus + ":false_hits"] += int(neg)
                result["channels"][ch] = {"base": dict(sorted(totals.items())),
                                          "classes": {c: dict(sorted(v.items())) for c, v in sorted(table.items())}}
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--creddata", help="a CredData checkout")
    ap.add_argument("--holdout", help="Cloakroom's bench/ folder with holdout_v2.jsonl to holdout_v7.jsonl")
    ap.add_argument("--regions", default="de")
    ap.add_argument("--channels", default="prompt,tool")
    ap.add_argument("--level", default="coarse", choices=("coarse", "class"))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    items = inputs(a.creddata, a.holdout)
    res = measure(items, tuple(x for x in a.regions.split(",") if x), tuple(a.channels.split(",")), a.level,
                  a.workers)
    res["inputs"] = dict(collections.Counter(c for c, *_ in items))
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    corpora = sorted(res["inputs"])
    for ch, r in res["channels"].items():
        print(f"channel {ch}, regions {','.join(res['regions']) or 'none'}: base " + ", ".join(
            f"{k} {v}" for k, v in r["base"].items()))
        print("class  rules  " + "  ".join(f"{c} lost/saved" for c in corpora))
        for c, row in r["classes"].items():
            cells = [f"{row.get(x + ':recall_lost', 0)}/{row.get(x + ':false_hits_saved', 0)}" for x in corpora]
            print(f"{c}  {res['rules_per_class'][c]}  " + "  ".join(cells))
    return 0


if __name__ == "__main__":
    sys.exit(main())
