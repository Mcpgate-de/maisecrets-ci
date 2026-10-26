"""The sources of Benchmark V1 (docs/BENCHMARK-V1.md, "Sources"). Each source gives cases in the format of
bench/cases.py; a public source reads its pinned files from the data directory and copies nothing into the
repository.

    bank                          bench/bank/ (this repository)
    nemotron gretel mendeley piilo  the labelled PII datasets of scripts/measure_datasets.py, with its label cleaning
    privy                         a PII set of protocol traces, totals only (docs/BENCHMARK-V2.md)
    aparte llmredactor credsweeper  the labelled secret datasets of scripts/measure_datasets.py (docs/BENCHMARK-V3.md,
                                  "Secret datasets")
    catalogs                      the rule examples of six secret catalogs (scripts/measure_catalog_coverage.py)
    catalogs-example              the same examples as each catalog wrote them, with their own context
    ghissues                      real secrets in GitHub issues, two sealed halves dev and holdout (bench/ghissues.py)
    traces                        protocol traces made at run time by bench/traces.py (development data)
    nym dialogpii                 external PII sets, sealed dev, val and holdout splits (bench/nym.py,
                                  bench/dialogpii.py), one split at a time
    structured                    structured text made at run time by bench/structgen.py, template set A
                                  (development data, docs/BENCHMARK-STRUCTURED.md)"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

from bench import cases

ROOT = Path(__file__).resolve().parent.parent
BANK = ROOT / "bench" / "bank"
DATASETS = ("nemotron", "gretel", "mendeley", "piilo", "privy", "aparte", "llmredactor", "credsweeper")
SEALED_SETS = ("nym", "dialogpii")
HOLDOUT_SETS = SEALED_SETS + ("ghissues",)   # sources with a sealed holdout split: totals only
SOURCES = ("bank",) + DATASETS + ("catalogs", "catalogs-example", "traces", "ghissues", "structured") + SEALED_SETS

# a type to its class, from the published vocabulary (docs/DETECTION.md, "The type vocabulary"): the types of
# scripts/measure_datasets.py and those maisecrets finds (bench/adapters/maisecrets.py). A dataset's SECRET span takes
# its class from the dataset's own label (secret_class)
TYPE_CLASS = {t: v["class"] for t, v in json.loads(
    (ROOT / "maisecrets" / "detection" / "types.json").read_text(encoding="utf-8"))["types"].items()}
SECRET_LABEL = {"password": "secret.password", "PASSWORD": "secret.password"}
# a secret dataset that says which kind of secret a span holds: its labels to the classes of the benchmark
SECRET_CLASS = {
    "aparte": {"api_key": "secret.token", "token": "secret.token", "private_key": "secret.private_key"},
    "llmredactor": {"api_key": "secret.token", "bearer_token": "secret.token", "aws_access_key": "secret.token",
                    "pem_private_key": "secret.private_key"},
    "credsweeper": {"token": "secret.token", "private_key": "secret.private_key"},
}
REGION_OF_LANG = {"en": "us", "de": "de", "fr": "fr", "es": "es", "it": "it", "nl": "nl", "sv": "se"}


def secret_class(dataset: str, label: str) -> str:
    return SECRET_CLASS.get(dataset, {}).get(label) or SECRET_LABEL.get(label, "secret.generic")


def _measure_datasets():
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_datasets
    return measure_datasets


def dataset_cases(name: str, data: Path, stats: collections.Counter, limit: int = 0):
    """The cases of one labelled PII dataset. A label the cleaning marks oos or uncertain becomes a neutral span (a
    finding on it is neither a hit nor a false alarm); a label error is left out."""
    md = _measure_datasets()
    counts: dict = {}
    n = 0
    for sample in md.load(name, data, stats):
        record = str(sample["id"])
        spans = []
        for g in md.clean(name, sample, counts):
            if g["gold"] == "neg":
                continue
            if g["type"] == md.OUT_OF_SCOPE:
                cls = "pii.other"
            elif g["type"] == "SECRET":
                cls = secret_class(name, g["label"])
            else:
                cls = TYPE_CLASS[g["type"]]
            sp = {"start": g["start"], "end": g["end"], "class": cls, "label": g["label"]}
            if g["gold"] != "pos":
                sp["neutral"] = True
            spans.append(sp)
        lang = sample.get("lang", "en")
        # a loader may give the split (a config of the dataset that is its holdout), the channel, the context and the
        # path; else the split rule, a tool output, a document
        yield {"id": f"{name}/{record}", "text": sample["text"], "channel": sample.get("channel", "tool"),
               "context": sample.get("context", "doc"), "path": sample.get("path"), "spans": spans,
               "split": sample.get("split") or cases.split_of(name, record), "tags": sample.get("tags", []),
               "region": REGION_OF_LANG.get(lang, lang), "lang": lang,
               "source": {"name": name, **{k: md.SOURCES[name].get(k) for k in ("url", "revision", "licence")
                                            if k in md.SOURCES[name]}, "record": record}}
        n += 1
        if limit and n >= limit:
            return


# the catalogs at the commits their numbers were taken on (docs/BENCHMARK-V1.md, "Repeat a measurement")
CATALOGS = {
    "noseyparker": ("2e6e7f36ce36619852532bbe698d8cb7a26d2da7", "https://github.com/praetorian-inc/noseyparker",
                    "Apache-2.0"),
    "kingfisher": ("82d050530cdef9af070b8f9a75701c9c27a948c3", "https://github.com/mongodb/kingfisher", "Apache-2.0"),
    "gitleaks": ("b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b", "https://github.com/gitleaks/gitleaks", "MIT"),
    "betterleaks": ("c613797a684337a014168063577bb6fa6e3b6296", "https://github.com/betterleaks/betterleaks", "MIT"),
    "trufflehog": ("048de9ff07098d943136cd5231a0e93fbb3ea443", "https://github.com/trufflesecurity/trufflehog",
                   "AGPL-3.0 (read as data at run time, never copied)"),
    "gitlab": ("cae5670b0d83aaea0ff37c085119e82ff394f283",
               "https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules", "MIT"),
}


def _catalog_state(root: Path) -> tuple:
    import subprocess
    env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("GIT_")}
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, env=env)
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True,
                            env=env)
    if head.returncode or status.returncode:
        raise SystemExit(f"catalog {root.name}: git cannot read its commit or its state")
    return head.stdout.strip(), bool(status.stdout.strip())


def catalog_cases(catalogs: Path, max_examples: int = 6, forms=("bare", "label")):
    """Each example of a secret catalog twice: the secret alone and after `token = `, as
    scripts/measure_catalog_coverage.py probes it. The expected span is the catalog's secret. The form `example` is
    the example text as the catalog wrote it (its key names and context), for a scanner whose rules need them."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_catalog_coverage as mcc
    missing = [cat for cat in mcc.CATALOGS if not (Path(catalogs) / cat).is_dir()]
    if missing:
        raise SystemExit(f"the catalog source needs all six catalogs; missing: {', '.join(missing)}")
    for cat in mcc.CATALOGS:
        root = Path(catalogs) / cat
        commit, dirty = _catalog_state(root)
        want, url, licence = CATALOGS[cat]
        if commit != want or dirty:
            raise SystemExit(f"catalog {cat}: at {commit[:12] or '?'}{' with changes' if dirty else ''}, "
                             f"pinned {want[:12]}")
        for r in mcc.load_catalog(cat, root):
            rule = r["rule"]
            for i, ex in enumerate(r["pos"][:max_examples]):
                yield from _catalog_forms(cat, commit, rule, i, ex["secret"], url, licence, ex.get("text"), forms)


def _catalog_forms(cat: str, commit: str, rule: str, i: int, secret: str, url: str = "", licence: str = "",
                   example: str | None = None, forms=("bare", "label")):
    if secret:
        bodies = {"bare": secret, "label": "token = " + secret, "example": example}
        for form, body in ((f, bodies[f]) for f in forms if bodies.get(f) and secret in bodies[f]):
            start = body.index(secret)
            cls = "secret.webhook" if secret.startswith("http") else "secret.token"
            record = f"{cat}/{rule}/{i}/{form}"
            yield {"id": f"catalogs/{record}", "text": body, "channel": "tool", "context": "prose",
                   "spans": [{"start": start, "end": start + len(secret), "class": cls}],
                   "split": cases.split_of("catalogs", f"{cat}/{rule}"), "tags": [f"catalog:{cat}", f"form:{form}"],
                   "source": {"name": cat, "commit": commit, "url": url, "licence": licence,
                              "record": f"{rule}/{i}"}}


def load(name: str, data: Path | None = None, catalogs: Path | None = None, limit: int = 0,
         stats: collections.Counter | None = None, split: str | None = None):
    stats = stats if stats is not None else collections.Counter()
    if name == "ghissues":
        # one sealed half at a time: the holdout half is read only when it is asked for by name
        from bench import ghissues
        if data is None:
            raise SystemExit("the ghissues source needs --data DIR (the directory with dev/ and holdout/)")
        try:
            return list(ghissues.load(Path(data), split or "dev", stats, limit))
        except ghissues.DataError as e:
            raise SystemExit(f"ghissues: {e}") from None
    if name in SEALED_SETS:
        # one sealed split at a time: the holdout is read only when it is asked for by name
        import importlib
        from bench import sealed
        mod = importlib.import_module(f"bench.{name}")
        if data is None:
            raise SystemExit(f"the {name} source needs --data DIR (the directory with dev/, val/ and holdout/)")
        try:
            return list(mod.load(Path(data), split or "dev", stats, limit))
        except sealed.DataError as e:
            raise SystemExit(f"{name}: {e}") from None
    if name == "bank":
        return iter(cases.load_bank(BANK))
    if name in DATASETS:
        md = _measure_datasets()
        return dataset_cases(name, Path(data or md.DEFAULT_DATA), stats, limit)
    if name == "traces":
        from bench import traces
        return traces.generate()
    if name == "structured":
        from bench import structgen
        return structgen.generate()
    if name == "catalogs":
        if catalogs is None:
            raise SystemExit("the catalogs source needs --catalogs DIR (one clone per catalog)")
        return catalog_cases(catalogs)
    if name == "catalogs-example":
        if catalogs is None:
            raise SystemExit("the catalogs-example source needs --catalogs DIR (one clone per catalog)")
        return catalog_cases(catalogs, forms=("example",))
    raise SystemExit(f"no source {name}; known: {', '.join(SOURCES)}")
