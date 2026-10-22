"""The scoring of Benchmark V1 (docs/BENCHMARK-V1.md, "When a span counts as found" and "Metrics").

A finding is (start, end, cls). Recall asks "is all sensitive text masked?": only a span whose core the findings
cover whole counts as found ("full"); a span covered in part is "partial" and counts as missed in the strict recall.
Precision asks "is what was masked sensitive?": a finding is right when it lies on an expected span, also when it
does not cover all of it (that shortfall is the recall's)."""
from __future__ import annotations

import collections

from bench.cases import family, in_scope

MIN_RATE = 30     # a class with fewer spans reports counts and no rate
LABEL_CHARS = 40  # the text before a span on its line that a finding may mask as the span's label
SLACK = 8         # characters a finding may extend beyond the spans and labels before it is "too wide"


def _covered(intervals, lo: int, hi: int) -> int:
    """The number of characters of [lo, hi) inside the union of the intervals."""
    n, pos = 0, lo
    for s, e in sorted(intervals):
        s, e = max(s, pos), min(e, hi)
        if e > s:
            n += e - s
            pos = e
    return n


def _label_start(text: str, start: int) -> int:
    """Where the label of a span may start: the start of its line, at most LABEL_CHARS before the span."""
    return max(text.rfind("\n", 0, start) + 1, start - LABEL_CHARS)


def _full(intervals, sp) -> tuple:
    lo, hi = sp.get("core") or (sp["start"], sp["end"])
    got = _covered(intervals, lo, hi)
    full = got == hi - lo or any(_covered(intervals, a, b) == b - a for a, b in sp.get("alt", ()))
    return full, got, hi - lo


def score_case(case: dict, findings, scope) -> dict:
    """The outcome of each span in scope, and the false positives and too wide findings of one case."""
    spans = [s for s in case["spans"] if in_scope(s["class"], scope) and not s.get("neutral")]
    removed = [s for s in case["spans"] if not in_scope(s["class"], scope) or s.get("neutral")]
    found = [(int(s), int(e), c) for s, e, c in findings if int(e) > int(s)]
    cover = [(s, e) for s, e, _ in found]
    outcomes = []
    for sp in spans:
        full, got, n = _full(cover, sp)
        same = [(s, e) for s, e, c in found if family(c) == family(sp["class"])]
        outcomes.append({"class": sp["class"], "outcome": "full" if full else "partial" if got else "missed",
                         "chars": n, "covered": got, "family_right": full and _full(same, sp)[0]})
    allowed = [(_label_start(case["text"], s["start"]), s["end"]) for s in case["spans"]]
    fp, too_wide, fp_found = 0, 0, []
    on_target, fp_family = collections.Counter(), collections.Counter()
    for s, e, c in found:
        hits = [sp for sp in spans if s < sp["end"] and e > sp["start"]]
        extra = (e - s) - _covered(allowed, s, e)
        if hits:
            # the span the finding covers most owns it; a tie goes to the family first in name order, so the order
            # of the annotations never decides
            owner = max(hits, key=lambda sp: (min(e, sp["end"]) - max(s, sp["start"]), -ord(family(sp["class"])[0])))
            on_target[family(owner["class"])] += 1
            if extra > max(SLACK, max(sp["end"] - sp["start"] for sp in hits)):
                too_wide += 1
        elif any(s < sp["end"] and e > sp["start"] for sp in removed) and extra <= SLACK:
            continue    # on a span this scanner is not scored on: neither right nor wrong
        else:
            fp += 1
            fp_family[family(c)] += 1
            fp_found.append((s, e, c))
    return {"spans": outcomes, "fp": fp, "fp_family": dict(fp_family), "on_target": dict(on_target),
            "fp_found": fp_found,   # the false positives themselves, for the scope of Benchmark V3 (bench/v3.py)
            "too_wide": too_wide, "negative": not spans,   # no span to find after scope and neutral removal
            "bytes": len(case["text"].encode("utf-8")), "lines": case["text"].count("\n") + 1}


def _rate(num: float, den: float):
    return round(num / den, 4) if den else None


def _f1(p, r):
    if p is None or r is None:
        return None
    return round(2 * p * r / (p + r), 4) if p + r else 0.0


def aggregate(results, group=lambda case, span: span["class"]) -> dict:
    """Metrics per group of spans (default: per class), per family and in total. results: (case, score) pairs."""
    rows = collections.defaultdict(collections.Counter)
    total = collections.Counter()
    for case, sc in results:
        for sp in sc["spans"]:
            for key in (group(case, sp), family(sp["class"]), "all"):
                r = rows[key]
                r["spans"] += 1
                r[sp["outcome"]] += 1
                r["chars"] += sp["chars"]
                r["covered"] += sp["covered"]
                r["family_right"] += sp["family_right"]
        for fam, n in sc["fp_family"].items():
            rows[fam]["fp"] += n
        for fam, n in sc["on_target"].items():
            rows[fam]["on_target"] += n
        rows["all"]["fp"] += sc["fp"]
        rows["all"]["on_target"] += sum(sc["on_target"].values())
        total["too_wide"] += sc["too_wide"]
        total["cases"] += 1
        total["negative"] += sc["negative"]
        total["fp_negative"] += sc["fp"] if sc["negative"] else 0
        total["bytes"] += sc["bytes"]
        total["lines"] += sc["lines"]
    out = {}
    for key, r in sorted(rows.items()):
        m = dict(r)
        if r["spans"] >= MIN_RATE:
            m["recall_strict"] = _rate(r["full"], r["spans"])
            m["recall_lenient"] = _rate(r["full"] + r["partial"], r["spans"])
            m["char_recall"] = _rate(r["covered"], r["chars"])
            m["family_right_rate"] = _rate(r["family_right"], r["full"])
        else:
            m["too_few"] = bool(r["spans"])
        if key in ("all", "secret", "pii"):
            findings = r["on_target"] + r["fp"]
            m["findings"] = findings
            m["precision"] = _rate(r["on_target"], findings)
            m["f1"] = _f1(m["precision"], m.get("recall_strict"))
        out[key] = m
    a = out.setdefault("all", {})
    a.update({"too_wide": total["too_wide"], "cases": total["cases"], "negative_cases": total["negative"],
              "fp_per_1000_negative": _rate(total["fp_negative"] * 1000, total["negative"]),
              "fp_per_mb": _rate(a.get("fp", 0) * 2 ** 20, total["bytes"]),
              "fp_per_10000_lines": _rate(a.get("fp", 0) * 10000, total["lines"])})
    return out
