#!/usr/bin/env python3
"""Holdout V2: the procedure, without its templates (docs/BENCHMARK-V2.md, "Holdout V2").

    python3 bench/holdout_v2.py check    TEMPLATES                     the templates, the attestation, the generators
    python3 bench/holdout_v2.py generate TEMPLATES SEED_FILE OUT_DIR   render the cases into a private directory
    python3 bench/holdout_v2.py seal     TEMPLATES SEED_FILE OUT_DIR   write bench/holdout-v2.manifest, once
    python3 bench/holdout_v2.py verify   OUT_DIR                       the cases still match the sealed manifest

The templates, the generators of their values and the seed live in a private directory and stay there: a public
template could not be unseen by whoever writes the next rule. The manifest commits their sha256, the sha256 of each
case file and the counts per class. A second seal is refused; a changed template set is a new holdout with a new
manifest and a new log section.

A template directory holds:

- `ATTESTATION.json`: who wrote the templates (a role, no name), the date, and `"seen_miss_lists": false`. The author
  has not seen a list of maisecrets misses, partial hits or false positives. `check` refuses any other value.
- `templates/*.json`: one template per file (TEMPLATE_KEYS). `text` holds `{value}` where the value goes; a template
  without `value` is a negative case. `spec` names an entry of bench/holdout_v2_specs.json.
- `generators.py` (optional): the value generators, each `def name(rnd: random.Random, **params) -> str`, listed in
  `GENERATORS = {"name": function}`.

bench/run.py --source holdout-v2 runs the sealed cases, only on a release candidate, and writes one row to
bench/HOLDOUT-LOG.md."""
from __future__ import annotations

import collections
import datetime
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bench import cases as casefmt  # noqa: E402

SPECS = ROOT / "bench" / "holdout_v2_specs.json"
MANIFEST = ROOT / "bench" / "holdout-v2.manifest"
CASES_FILE = "cases.jsonl"
TEMPLATE_KEYS = {"id", "class", "channel", "context", "spec", "text", "value", "count"}
REQUIRED_KEYS = {"id", "class", "channel", "context", "spec", "text", "count"}
MAX_COUNT = 500


class HoldoutError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def specs() -> dict:
    return {s["id"]: s for s in json.loads(SPECS.read_text(encoding="utf-8"))["specs"]}


def _generators(directory: Path) -> dict:
    f = directory / "generators.py"
    if not f.is_file():
        return {}
    spec = importlib.util.spec_from_file_location("holdout_v2_generators", f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    gens = getattr(mod, "GENERATORS", None)
    if not isinstance(gens, dict) or not all(callable(g) for g in gens.values()):
        raise HoldoutError("generators.py has no GENERATORS dict of functions")
    return gens


def load(directory: Path) -> tuple:
    """(attestation, templates, generators) of a template directory, each checked."""
    directory = Path(directory)
    try:
        att = json.loads((directory / "ATTESTATION.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HoldoutError("no readable ATTESTATION.json") from None
    if att.get("seen_miss_lists") is not False or not att.get("author_role") or not att.get("date"):
        raise HoldoutError("the attestation must name an author role and a date and say seen_miss_lists: false")
    known, gens = specs(), _generators(directory)
    out, ids = [], set()
    for f in sorted((directory / "templates").glob("*.json")):
        t = json.loads(f.read_text(encoding="utf-8"))
        where = f.name
        if set(t) - TEMPLATE_KEYS or REQUIRED_KEYS - set(t):
            raise HoldoutError(f"{where}: keys must be {sorted(REQUIRED_KEYS)} and optional value")
        if t["id"] in ids:
            raise HoldoutError(f"{where}: the id {t['id']} is there twice")
        ids.add(t["id"])
        if t["class"] not in casefmt.CLASSES or t["channel"] not in casefmt.CHANNELS \
                or t["context"] not in casefmt.CONTEXTS:
            raise HoldoutError(f"{where}: class, channel or context is not one of the known values")
        if t["spec"] not in known:
            raise HoldoutError(f"{where}: the spec {t['spec']!r} is not in bench/holdout_v2_specs.json")
        if not isinstance(t["count"], int) or not 1 <= t["count"] <= MAX_COUNT:
            raise HoldoutError(f"{where}: count must be 1 to {MAX_COUNT}")
        value = t.get("value")
        if value is None:
            if "{value}" in t["text"]:
                raise HoldoutError(f"{where}: a negative template has no {{value}}")
        else:
            if t["text"].count("{value}") != 1:
                raise HoldoutError(f"{where}: the text holds {{value}} exactly once")
            if value.get("generator") not in gens:
                raise HoldoutError(f"{where}: the generator {value.get('generator')!r} is not in generators.py")
        out.append(t)
    if not out:
        raise HoldoutError("no template")
    return att, out, gens


def templates_hash(directory: Path) -> str:
    """One sha256 over the attestation, every template file and generators.py, by relative path."""
    directory = Path(directory)
    h = hashlib.sha256()
    files = [directory / "ATTESTATION.json", *sorted((directory / "templates").glob("*.json"))]
    if (directory / "generators.py").is_file():
        files.append(directory / "generators.py")
    for f in files:
        h.update(f.relative_to(directory).as_posix().encode() + b"\0" + _sha(f.read_bytes()).encode() + b"\n")
    return h.hexdigest()


def render(templates: list, gens: dict, seed: bytes) -> list:
    """The cases, the same for the same templates and seed: each template draws from its own seeded generator."""
    out = []
    for t in templates:
        rnd = random.Random(_sha(seed + b"\0" + t["id"].encode()))
        for n in range(t["count"]):
            before, _, after = t["text"].partition("{value}")
            spans = []
            if t.get("value") is not None:
                v = gens[t["value"]["generator"]](rnd, **t["value"].get("params", {}))
                if not isinstance(v, str) or not v:
                    raise HoldoutError(f"{t['id']}: the generator gave no value")
                spans = [{"start": len(before), "end": len(before) + len(v), "class": t["class"]}]
                text = before + v + after
            else:
                text = t["text"]
            record = f"{t['id']}/{n}"
            out.append({"id": f"holdout-v2/{record}", "text": text, "channel": t["channel"], "context": t["context"],
                        "spans": spans, "split": "holdout", "tags": [f"spec:{t['spec']}"],
                        "source": {"name": "holdout-v2", "record": record}})
    return out


def write(cs: list, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    f = out_dir / CASES_FILE
    f.write_text("".join(json.dumps(c, sort_keys=True, ensure_ascii=False) + "\n" for c in cs), encoding="utf-8")
    return f


def seal(directory: Path, seed: bytes, out_dir: Path, manifest: Path = MANIFEST) -> dict:
    """Write the manifest once: the hashes of the template set, the seed and the case file, and counts per class.
    The cases are rendered again and must be the bytes on disk."""
    if manifest.exists():
        raise HoldoutError(f"{manifest.name} exists: the holdout is sealed; a new template set is a new holdout")
    att, templates, gens = load(directory)
    f = Path(out_dir) / CASES_FILE
    rendered = "".join(json.dumps(c, sort_keys=True, ensure_ascii=False) + "\n" for c in render(templates, gens, seed))
    if not f.is_file() or f.read_text(encoding="utf-8") != rendered:
        raise HoldoutError("the case file is not what the templates and the seed render")
    cs = [json.loads(line) for line in rendered.splitlines()]
    m = {"sealed": datetime.date.today().isoformat(), "author_role": att["author_role"],
         "templates_sha256": templates_hash(directory), "seed_sha256": _sha(seed),
         "files": {CASES_FILE: _sha(f.read_bytes())}, "cases": len(cs),
         "negative_cases": sum(1 for c in cs if not c["spans"]),
         "spans_by_class": dict(sorted(collections.Counter(s["class"] for c in cs for s in c["spans"]).items())),
         "runs": "release candidates only (bench/run.py --source holdout-v2 --release-candidate)"}
    manifest.write_text(json.dumps(m, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return m


def verify(out_dir: Path, manifest: Path = MANIFEST) -> list:
    """The sealed cases: refused when no manifest is there or a file differs from it."""
    if not manifest.is_file():
        raise HoldoutError("no sealed manifest: Holdout V2 has no cases yet")
    m = json.loads(manifest.read_text(encoding="utf-8"))
    have = {p.name: _sha(p.read_bytes()) for p in sorted(Path(out_dir).glob("*.jsonl"))}
    if have != m["files"]:
        raise HoldoutError("the holdout directory does not match bench/holdout-v2.manifest")
    cs = [json.loads(line) for line in (Path(out_dir) / CASES_FILE).read_text(encoding="utf-8").splitlines()]
    if len(cs) != m["cases"] or any(c["split"] != "holdout" for c in cs):
        raise HoldoutError("the case count or a split differs from the manifest")
    return cs


def main(argv) -> int:
    if not argv or argv[0] not in ("check", "generate", "seal", "verify"):
        sys.stderr.write(__doc__)
        return 2
    try:
        if argv[0] == "check":
            att, templates, gens = load(Path(argv[1]))
            print(f"{len(templates)} templates, {len(gens)} generators, author {att['author_role']}: ok")
        elif argv[0] == "generate":
            att, templates, gens = load(Path(argv[1]))
            f = write(render(templates, gens, Path(argv[2]).read_bytes()), Path(argv[3]))
            print(f"cases: {f}")
        elif argv[0] == "seal":
            m = seal(Path(argv[1]), Path(argv[2]).read_bytes(), Path(argv[3]))
            print(f"sealed: {m['cases']} cases, {MANIFEST}")
        else:
            print(f"{len(verify(Path(argv[1])))} cases match the manifest")
    except HoldoutError as e:
        print(f"refused: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
