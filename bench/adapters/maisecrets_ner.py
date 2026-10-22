"""maisecrets with the PERSON layer of the NER experiment (docs/NER-EXPERIMENT.md): the deterministic detector of the
checkout first, unchanged, then bench/ner/person_worker.py in the Python of BENCH_NER_PYTHON with the backend of
BENCH_NER (`spacy:en_core_web_sm`, `gliner:<model directory>:0.5`). The layer adds `pii.name` findings only where
no deterministic finding lies; every deterministic finding is kept as it is.

BENCH_NER_SIDECAR, when set, names a JSONL file that gets per case its id, the spans the layer added and the types of
the deterministic findings a dropped span overlapped (for the analysis; no text)."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from bench.adapters import _proc
from bench.adapters import maisecrets as det

NAME = "maisecrets+ner"
SCOPE = det.SCOPE
WORKER = Path(__file__).resolve().parent.parent / "ner" / "person_worker.py"


def _python() -> str:
    p = os.environ.get("BENCH_NER_PYTHON")
    if not p:
        raise _proc.AdapterError("maisecrets_ner: BENCH_NER_PYTHON names no Python")
    return p


def _backend() -> str:
    b = os.environ.get("BENCH_NER", "")
    if not b.startswith(("spacy:", "gliner:", "hf:", "onnx:")):
        raise _proc.AdapterError("maisecrets_ner: BENCH_NER must be spacy:<model>, gliner:<dir>:<threshold>, "
                                 "hf:<dir> or onnx:<dir>[::int8]")
    return b


def describe(root: Path, regions: str) -> dict:
    d = det.describe(root, regions)
    backend = _backend()
    kind, _, arg = backend.partition(":")
    shown = backend if kind == "spacy" else f"{kind}:" + arg.split("/snapshots/")[0].split("/")[-1]
    d.update(scanner=NAME, ner={"backend": shown, "python": _python(), "installed": _proc.installed(_python())},
             dependencies="Python standard library; the layer: " + shown)
    return d


def scan(cases, root: Path, regions: str = "de,us"):
    found, timing = det.scan(cases, root, regions)
    tmp = tempfile.mkdtemp(prefix="bench-ner-")
    try:
        home = os.path.join(tmp, "home")
        os.mkdir(home)
        inp, out = os.path.join(tmp, "in.jsonl"), os.path.join(tmp, "out.jsonl")
        with open(inp, "w", encoding="utf-8") as f:
            for c, fs in zip(cases, found):
                f.write(json.dumps({"text": c["text"], "occupied": [[s, e, cls] for s, e, cls, _ in fs]}) + "\n")
        # offline: the model and the encoder's tokenizer come from the local cache of HF_HOME, never the network
        env = _proc.minimal_env(home, {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                                       **({"HF_HOME": os.environ["HF_HOME"]} if os.environ.get("HF_HOME") else {})})
        p = _proc.run([_python(), "-I", str(WORKER), inp, out, _backend()], "maisecrets_ner", env=env, cwd=tmp)
        if p.returncode:
            raise _proc.AdapterError(f"maisecrets_ner: the NER worker failed with exit code {p.returncode}")
        ner = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            layer = [json.loads(line) for line in f]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if len(layer) != len(cases):
        raise _proc.AdapterError(f"maisecrets_ner: {len(layer)} results for {len(cases)} cases")
    side = os.environ.get("BENCH_NER_SIDECAR")
    if side:
        with open(side, "w", encoding="utf-8") as f:
            for c, row in zip(cases, layer):
                f.write(json.dumps({"id": c["id"], **row}) + "\n")
    merged = [list(fs) + [(s, e, "pii.name", "ner:person") for s, e, _score in row["add"]]
              for fs, row in zip(found, layer)]
    # the time of a case is both layers; the NER worker's own figures go along for the report
    t = [a + b for a, b in zip(timing.get("times_s", []), ner["times_s"])] or ner["times_s"]
    timing = {**timing, "times_s": t, "ner": {k: v for k, v in ner.items() if k != "times_s"},
              "ner_times_s": ner["times_s"]}
    return _proc.check("maisecrets_ner", cases, merged), timing


if __name__ == "__main__":
    sys.exit("run through bench/run.py --scanner maisecrets_ner")
