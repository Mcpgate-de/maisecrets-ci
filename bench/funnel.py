"""The opportunity funnel: every span maisecrets left partial or missed in a result file, put into one category by the
text around it. Counts only, never a value or its context.

    python3 bench/funnel.py RESULT_DIR --maisecrets CHECKOUT [--split dev|val|all] [--csv FILE] SOURCE...

RESULT_DIR holds `<source>-all-maisecrets.json` (the full runs of bench/run_all.sh). CHECKOUT is the maisecrets that
was measured: its placeholder policy and its known record fields decide two buckets, so the funnel of a release reads
that release's code. The cases are loaded again and must have the sha256 of the result file, or the script stops.

The buckets come from the frontier block of 2026-10-20 and were fixed before this script read a result of 0.7.3. The
first that applies:

  placeholder   a value the policy keeps as text on purpose (placeholder digits, documentation names)
  record-field  a cell of a table row or CSV line, a JSON or XML value, or the value after a known record field
  label-same    a label of the span's own class stands before it on its line, within 40 characters
  label-other   another label stands right before it (`Name:` before an address)
  person-cue    a name right after a person cue (Dear, Mr, Dr, Sincerely, by, between, from, I am)
  prose         none of these: running text without a cue

and the category of each (docs/BENCHMARKS.md, "Opportunity funnel"):

  A  deterministic, low risk     not separable by context alone; the reading of 2026-10-20 found about 1,500
                                 (a subset of label-same); the script reports A+B together and names it
  B  deterministic, FP risk      label-same, person-cue, and prose of a class with a shape (address, phone, id,
                                 username, birth date, card, bank account, email, ip)
  C  structural / parser         record-field
  D  likely NER / semantic       prose of a name, and prose of a secret (a password in a sentence)
  E  dataset / label error       placeholder
  F  unclear                     label-other
"""
from __future__ import annotations

import argparse
import collections
import csv
import importlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

LABELS = {
    "pii.name": r"name|naam|namn|nom|nombre|nome|vorname|nachname|apellidos?|cognome|surname|holder|patient|customer"
                r"|client|employee|contact|user|signed|signature|beneficiary|insured|applicant|tenant|owner|agent",
    "pii.address": r"address|adresse|adres|adress|direcci[oó]n|indirizzo|endere[cç]o|anschrift|stra(?:ss|ß)e|street"
                   r"|domicilio|wohnort|location|residence",
    "pii.phone": r"phone|tel|telefon|t[ée]l[ée]phone|tel[ée]fono|mobile?|cell|fax|handy|contact",
    "pii.national_id": r"ssn|social|security|passport|license|licence|id|number|nr|no|nif|nie|tax|insurance|dni|nir",
    "pii.username": r"user(?:name)?|login|handle|account|benutzer",
    "pii.bank_account": r"account|konto|iban|bank|acct|routing",
    "secret.password": r"pass(?:word)?|pwd|kennwort|passwort|contrase[nñ]a|mot de passe|pin",
    "secret.generic": r"key|token|secret|api|credential|auth",
}
ANY_LABEL = re.compile(r"(?i)([a-zà-ÿ][\w .'-]{0,30}?)\s*[:=]\s*[\"']?\s*$")
CUE = re.compile(r"(?:Dear|Hi|Hello|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Sincerely,?|Regards,?|by|between|and|I am"
                 r"|I'm|from|to|with)\s*$")
CATEGORY = {"placeholder": "E", "record-field": "C", "label-same": "A+B", "person-cue": "A+B", "label-other": "F"}


def category(cls: str, bucket: str) -> str:
    if bucket != "prose":
        return CATEGORY[bucket]
    return "D" if cls == "pii.name" or cls.startswith("secret.") else "A+B"


def bucket(p, text: str, sp: dict) -> str:
    s = sp["start"]
    v = text[s:sp["end"]]
    if sp["class"] in ("pii.national_id", "pii.phone", "pii.bank_account", "pii.card") and p._placeholder_digits(v):
        return "placeholder"
    if sp["class"] == "pii.name" and (v.lower() in p.PLACEHOLDER_NAMES or v.lower() in p._PLACEHOLDER_NAME_WORDS):
        return "placeholder"
    line0 = text.rfind("\n", 0, s) + 1
    line_end = text.find("\n", s)
    line = text[line0:line_end if line_end >= 0 else len(text)]
    before = text[max(line0, s - 40):s]
    if line.count("|") >= 2 or line.count(",") >= 3 and "," in text[s - 1:s] or \
            re.search(r"[\"']\s*:\s*[\"']?$", before) or re.search(r"<[\w:.-]+[^<>]*>$", before):
        return "record-field"
    m = ANY_LABEL.search(before)
    if m:
        field = p._md_column(m.group(1).strip().strip("*-# "))
        cls_re = LABELS.get(sp["class"])
        if cls_re and re.search(r"(?i)(?:^|[\s_])(?:" + cls_re + r")", m.group(1)):
            return "label-same"
        if field in p._STRONG_COLS or field in p._WEAK_COLS:
            return "record-field"
        return "label-other"
    if sp["class"] == "pii.name" and CUE.search(text[max(line0, s - 15):s]):
        return "person-cue"
    return "prose"


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("result_dir", type=Path)
    ap.add_argument("sources", nargs="+")
    ap.add_argument("--maisecrets", type=Path, required=True)
    ap.add_argument("--split", default="all")
    ap.add_argument("--csv", type=Path)
    a = ap.parse_args(argv)
    # the bench of this tree, the detection of the measured checkout: both trees have both packages, so each is
    # imported from its own path and checked (a funnel of the wrong release reads like a right one)
    sys.path.insert(0, str(HERE))
    run = importlib.import_module("bench.run")
    sources = importlib.import_module("bench.sources")
    for name in [m for m in sys.modules if m == "maisecrets" or m.startswith("maisecrets.")]:
        del sys.modules[name]
    sys.path.insert(0, str(a.maisecrets.resolve()))
    p = importlib.import_module("maisecrets.detection.personal")
    assert Path(p.__file__).resolve().is_relative_to(a.maisecrets.resolve()), p.__file__
    counts = collections.Counter()
    for source in a.sources:
        res = json.loads((a.result_dir / f"{source}-all-maisecrets.json").read_text(encoding="utf-8"))
        selected = list(sources.load(source, None, None, 0, collections.Counter()))
        if run.cases_hash(selected) != res["cases_sha256"]:
            raise SystemExit(f"{source}: the cases differ from the result file (cases sha256)")
        per_case = res["per_case"]
        for c in selected:
            if a.split != "all" and c["split"] != a.split:
                continue
            outs = [o for o in per_case[c["id"]] if o != "fp"]
            spans = [s for s in c["spans"] if not s.get("neutral")]
            if len(outs) != len(spans):
                raise SystemExit(f"{source}: a case has {len(outs)} outcomes for {len(spans)} spans")
            for sp, o in zip(spans, outs):
                if o != "full":
                    b = bucket(p, c["text"], sp)
                    counts[(source, sp["class"], o, b, category(sp["class"], b))] += 1
    rows = sorted(counts.items(), key=lambda kv: (kv[0][4], -kv[1]))
    out = csv.writer(open(a.csv, "w", newline="", encoding="utf-8") if a.csv else sys.stdout)
    out.writerow(["source", "class", "outcome", "bucket", "category", "spans"])
    for k, v in rows:
        out.writerow([*k, v])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
