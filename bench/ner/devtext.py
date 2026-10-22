"""The developer-text false-alarm bank of the NER experiment (docs/NER-EXPERIMENT.md, "Developer text"): what a
PERSON layer marks in the text maisecrets sees most, where nearly every person-shaped word is no person. Counts only,
never a value.

    python3 bench/ner/devtext.py CHECKOUT ROOT OUT.json

ROOT holds the trees (the false-alarm bank's cache of scripts/measure_fp_bank.py plus the trees named in CATEGORIES,
cloned at the commits docs/NER-EXPERIMENT.md lists, and the fixed issue lists). Each category is read up to
MAX_CHARS, its files in the order of sha256 of their path, cut into cases of up to 4,000 characters at line ends. The
deterministic detector of CHECKOUT runs first, then the layer of BENCH_NER in BENCH_NER_PYTHON
(bench/adapters/maisecrets_ner.py). Each span the layer adds is put into one family by the line around it; the
families are fixed here, before a run."""
from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent.parent
MAX_CHARS = 2_000_000
CASE_CHARS = 4000

# category -> [(tree, glob)], read in this order of trees, files ordered by sha256 of their path within the category
CATEGORIES = {
    "python code": [("fpbank-cache/cpython-Lib", "**/*.py"), ("fpbank-cache/detect-secrets", "**/*.py")],
    "js/ts code": [("devbank/ky", "source/**/*.ts"), ("devbank/express", "lib/**/*.js")],
    "tests and examples": [("fpbank-cache/cpython-Lib", "test/**/*.py"), ("devbank/ky", "test/**/*.ts"),
                           ("devbank/express", "test/**/*.js"), ("devbank/express", "examples/**/*.js")],
    "config": [("fpbank-cache/awesome-compose", "**/*.y*ml"), ("fpbank-cache/awesome-compose", "**/*.json"),
               ("fpbank-cache/starter-workflows", "**/*.yml")],
    "logs": [("devbank/loghub", "*/*_2k.log")],
    "stack traces": [("devbank/tickets", "tracebacks_*.json")],
    "tickets": [("devbank/tickets", "psf_requests.json"), ("devbank/tickets", "expressjs_express.json")],
    "technical docs": [("fpbank-cache/tldr-pages", "pages/common/*.md"), ("devbank/ky", "*.md"),
                       ("devbank/express", "*.md")],
}

_AUTHOR = re.compile(r"(?i)copyright|\bauthors?\b|maintainer|contributor|signed-off-by|©|\(c\)")
_CODE = re.compile(r"\bdef\b|\bclass\b|\bimport\b|\bfrom\b.*\bimport\b|\bfunction\b|\bconst\b|\blet\b|\bvar\b"
                   r"|\breturn\b|=>|;\s*$|\{\s*$|^\s*[})\]]|\bself\.|\bthis\.")
_COMMENT = re.compile(r"^\s*(?:#|//|/?\*|<!--|\"\"\"|''')")
_IDENT_NEIGHBOUR = set("._/\\:=()[]<>`'\"{}$@#")


def family(category: str, text: str, s: int, e: int) -> str:
    v = text[s:e]
    line0 = text.rfind("\n", 0, s) + 1
    line1 = text.find("\n", e)
    line = text[line0:line1 if line1 >= 0 else len(text)]
    before, after = text[s - 1:s], text[e:e + 1]
    if _AUTHOR.search(line):
        return "author or copyright line"
    if before == "@" or re.search(r"https?://\S*$", text[line0:s]):
        return "handle or URL"
    if before in _IDENT_NEIGHBOUR or after in _IDENT_NEIGHBOUR or "_" in v or re.search(r"[a-z][A-Z]|\d", v):
        return "identifier, path or literal"
    if category == "logs":
        return "word in a log line"
    if _COMMENT.match(line):
        return "comment or docstring"
    if _CODE.search(line):
        return "code line"
    return "prose"


def _files(root: Path, category: str):
    paths = []
    for tree, pattern in CATEGORIES[category]:
        base = root / tree
        paths += [p for p in base.glob(pattern) if p.is_file()]
    return sorted(set(paths), key=lambda p: hashlib.sha256(str(p.relative_to(root)).encode()).hexdigest())


def _texts(p: Path):
    if p.suffix == ".json" and p.parent.name == "tickets":
        for issue in json.loads(p.read_text(encoding="utf-8")):
            yield f"{issue.get('title') or ''}\n\n{issue.get('body') or ''}"
    else:
        yield p.read_text(encoding="utf-8", errors="replace")


def cases(root: Path, category: str) -> list:
    out, total = [], 0
    for p in _files(root, category):
        for text in _texts(p):
            buf = ""
            for line in text.splitlines(keepends=True):
                if len(buf) + len(line) > CASE_CHARS and buf:
                    out.append({"id": f"{category}/{len(out)}", "text": buf, "channel": "tool", "path": None})
                    total += len(buf)
                    buf = ""
                buf += line[:CASE_CHARS]
            if buf.strip():
                out.append({"id": f"{category}/{len(out)}", "text": buf, "channel": "tool", "path": None})
                total += len(buf)
            if total >= MAX_CHARS:
                return out
    return out


def main(argv: list) -> int:
    checkout, root, out_path = Path(argv[0]).resolve(), Path(argv[1]), Path(argv[2])
    sys.path.insert(0, str(HERE))
    from bench.adapters import maisecrets_ner as ner
    report = {"backend": os.environ.get("BENCH_NER", "").split("/")[-1] if "onnx" not in os.environ.get(
        "BENCH_NER", "") else os.environ["BENCH_NER"].rsplit("/", 1)[-1], "categories": {}}
    side = out_path.with_suffix(".sidecar.jsonl")
    for category in CATEGORIES:
        cs = cases(root, category)
        os.environ["BENCH_NER_SIDECAR"] = str(side)
        found, timing = ner.scan(cs, checkout)
        rows = [json.loads(line) for line in side.open(encoding="utf-8")]
        fams = collections.Counter()
        added = 0
        for c, row in zip(cs, rows):
            for s, e, _score in row["add"]:
                added += 1
                fams[family(category, c["text"], s, e)] += 1
        chars = sum(len(c["text"]) for c in cs)
        det = sum(len(f) for f in found) - added
        report["categories"][category] = {
            "cases": len(cs), "chars": chars, "deterministic_findings": det, "ner_added": added,
            "ner_added_per_100kb": round(added / chars * 100_000, 1) if chars else None,
            "dropped_on_a_finding": sum(len(r["conflicts"]) for r in rows), "families": dict(fams.most_common()),
            "ner_median_ms": round(1000 * sorted(timing["ner_times_s"])[len(timing["ner_times_s"]) // 2], 2)}
        print(category, report["categories"][category]["ner_added"], report["categories"][category]["families"],
              flush=True)
    side.unlink(missing_ok=True)
    out_path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
