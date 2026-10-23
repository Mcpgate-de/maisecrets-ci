"""Benchmark V3 (docs/BENCHMARK-V3.md): precision counted only where a dataset labels what a finding claims.

V2 counts a finding as a false positive when it lies on no labelled span, also when the dataset never labels its
kind: an e-mail address in Privy, whose test split has no e-mail label. V3 keeps every span outcome of V2 (recall
does not change) and splits the false positives:

- **scored**: the finding's class is one the dataset labels (`SCOPE`), so a missing label means a wrong finding;
- **out of scope**: the dataset labels no value of that class, or of that shape inside it (`EXCLUDED_SHAPES`, Privy's
  national ids hold no SSN). Reported per class beside the score, never as right and never as wrong.

`LOWER_BOUND` names the classes whose labels a read sample showed not exhaustive (docs/BENCHMARK-V3-DRAFT.md, the
false-positive audit); their precision is a lower bound and the report says so.

The scope comes from the label mapping of scripts/measure_datasets.py, fixed before a run and the same for every
scanner; `python3 bench/v3.py --inventory` prints it, and bench/v3_scope.json holds the committed copy that a test
compares. Counts only: no value and no case text is printed. A shape test runs on the text of a finding inside the
scorer; nobody reads a case."""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAMILIES = ("secret", "pii")

# the sources this project wrote: they label every class they use, so every class is in scope
OWN_SOURCES = ("bank", "holdout", "holdout-v2", "traces", "catalogs")

# a class a dataset reaches only through the label cleaning is out of its scope: Privy has no IBAN label, its 7 IBAN
# spans are US_BANK_NUMBER labels retyped because the value is a valid IBAN (docs/BENCHMARK-V3-DRAFT.md, finding 1)
RETYPED_ONLY = {"privy": ("pii.iban",)}

# a shape inside a labelled class that the dataset does not label: Privy labels driver licenses, passports and ITINs
# as national ids, and no SSN
EXCLUDED_SHAPES = {"privy": {"pii.national_id": r"\d{3}[- ]?\d{2}[- ]?\d{4}"}}

# classes whose labels a read sample showed not exhaustive (2026-10-20, 160 false positives read on dev): Nemotron's
# SSNs (38 of 40 sampled false positives real) and Gretel's bank accounts (32 of 40)
LOWER_BOUND = {"nemotron": ("pii.national_id",), "gretel": ("pii.bank_account",)}


def _measure_datasets():
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_datasets
    return measure_datasets


def inventory() -> dict:
    """{dataset: {"labelled": [source label types], "scored": [classes], ...}} from the label mapping."""
    from bench import sources
    md = _measure_datasets()
    out = {}
    for name, labels in sorted(md.LABELS.items()):
        kept = sorted(k for k, t in labels.items() if t != md.OUT_OF_SCOPE)
        classes = set()
        for label in kept:
            t = labels[label]
            classes.add(sources.secret_class(name, label) if t == "SECRET" else sources.TYPE_CLASS[t])
        classes -= set(RETYPED_ONLY.get(name, ()))
        out[name] = {"labelled": kept, "not_labelled": sorted(k for k, t in labels.items() if t == md.OUT_OF_SCOPE),
                     "scored": sorted(classes), "excluded_shapes": EXCLUDED_SHAPES.get(name, {}),
                     "lower_bound": sorted(LOWER_BOUND.get(name, ()))}
    return out


def _family(cls: str) -> str:
    return cls.split(".", 1)[0]


def scored(source: str, scope: dict, cls: str, value: str) -> bool:
    """Whether a false positive of class `cls` with the text `value` counts against precision on `source`."""
    if source in OWN_SOURCES or source not in scope:
        return True
    entry = scope[source]
    if cls not in entry["scored"]:
        # a secret finding of a dataset that labels some secrets: `secret` is one family there, its labels no class
        if not (_family(cls) == "secret" and any(c.startswith("secret.") for c in entry["scored"])):
            return False
    # the shape anywhere in the finding, not only as all of it: a scanner that masks `SSN: 123-45-6789` with its label
    # found the same value as one that masks the digits alone (codex Gate A, 2026-10-22)
    shape = entry["excluded_shapes"].get(cls)
    return not (shape and re.search(r"(?<!\d)(?:" + shape + r")(?!\d)", value))


def metrics(source: str, results, scope: dict | None = None) -> dict:
    """The V3 block of a result file: per family and in total the on-target findings (as V2), the false positives
    that count, the ones out of scope per class, precision and F1 under V3, and the lower-bound classes."""
    scope = inventory() if scope is None else scope
    rows = collections.defaultdict(collections.Counter)
    out_of_scope = collections.defaultdict(collections.Counter)
    for case, sc in results:
        for fam, n in sc["on_target"].items():
            rows[fam]["on_target"] += n
            rows["all"]["on_target"] += n
        for s, e, cls in sc.get("fp_found", ()):
            fam = _family(cls) if _family(cls) in FAMILIES else "pii"
            if scored(source, scope, cls, case["text"][s:e]):
                rows[fam]["fp"] += 1
                rows["all"]["fp"] += 1
            else:
                out_of_scope[fam][cls] += 1
                out_of_scope["all"][cls] += 1
    out = {"scope": scope.get(source, "every class (written by this project)" if source in OWN_SOURCES else None),
           "lower_bound": sorted(LOWER_BOUND.get(source, ()))}
    for fam in ("all",) + FAMILIES:
        r = rows[fam]
        found = r["on_target"] + r["fp"]
        out[fam] = {"on_target": r["on_target"], "fp": r["fp"], "out_of_scope": dict(sorted(out_of_scope[fam].items())),
                    "precision": round(r["on_target"] / found, 4) if found else None}
    return out


def main(argv: list) -> int:
    if argv[:1] == ["--inventory"]:
        print(json.dumps(inventory(), indent=1, sort_keys=True))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    sys.exit(main(sys.argv[1:]))
