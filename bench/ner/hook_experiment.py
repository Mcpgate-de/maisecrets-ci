"""The proofs of the PERSON layer in the real hook path (docs/NER-EXPERIMENT.md, "The hook path"), with the real
PostToolUse hook of a maisecrets checkout in a new temp home per run. Counts only, never a value.

    python3 bench/ner/hook_experiment.py CHECKOUT NER_PYTHON BACKEND OUT.json

The corpus: tool results built from the bank's cases (dev), the salted V3 sample of Nemotron's val split and the
developer-text bank's Python code and logs, each as the stdout of a Bash call, in a fixed order. Each run is a new
process with a new temp home, so the placeholders count from c1 in each. The runs:

1. off: the hook as it is (the layer not installed);
2. installed, switched off: must answer byte for byte as off;
3. on, the service answering: every value the off run masked stays masked; the layer adds names; time per call;
4. on, the service 2 s slow with a 300 ms budget: byte for byte as off, and no call waits much longer than the budget;
5. on, the service dying after 20 requests: byte for byte as off for every later call, and no error text;
6. on, the service answering nonsense: byte for byte as off."""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME_VAR = "MAISECRETS" + "_HOME"

_RUNNER = r'''
import json, os, sys, time
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
from maisecrets import hooks
import hook_layer
mode, sock = sys.argv[3], sys.argv[4]
if mode != "off":
    hook_layer.install(sock, budget_ms=300, active=(mode != "inactive"))
out = []
for line in open(sys.argv[5], encoding="utf-8"):
    p = json.loads(line)
    t = time.perf_counter()
    r = hooks.post_tool(p)            # the layer's install() gives each hook call its one budget
    out.append({"answer": json.dumps(r, sort_keys=True, ensure_ascii=False), "ms": (time.perf_counter() - t) * 1000})
json.dump({"out": out, "state": {k: v for k, v in hook_layer.STATE.items() if k != "ner_s"},
           "ner_ms": [x * 1000 for x in hook_layer.STATE["ner_s"]]}, open(sys.argv[6], "w"))
'''


def corpus(root_v3: Path, devroot: Path) -> list:
    sys.path.insert(0, str(root_v3))
    from bench import cases as casefmt, run, sources
    texts = [c["text"] for c in casefmt.load_bank(sources.BANK) if c["split"] == "dev"]
    texts += [c["text"] for c in sources.load("nemotron", None, None, 0, collections.Counter())
              if c["split"] == "val" and run.in_sample(c["id"], 25, "v3/")][:200]
    sys.path.insert(0, str(HERE))
    import devtext
    for cat in ("python code", "logs"):
        texts += [c["text"] for c in devtext.cases(devroot, cat)][:60]
    return [{"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
             "tool_input": {"command": "cat data.txt"},
             "tool_response": {"stdout": t, "stderr": "", "interrupted": False, "isImage": False}} for t in texts]


def run_mode(checkout: Path, mode: str, sock: str, payloads: Path, tmp: Path) -> dict:
    home = Path(tempfile.mkdtemp(prefix="ms-hook-", dir=tmp))
    (home / "ms").mkdir()
    (home / "ms" / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS", "CLAUDE"))}
    env.update(HOME=str(home), **{HOME_VAR: str(home / "ms")})
    runner = tmp / "runner.py"
    runner.write_text(_RUNNER)
    out = tmp / f"out-{mode}-{time.monotonic_ns()}.json"
    p = subprocess.run([sys.executable, str(runner), str(checkout), str(HERE), mode, sock, str(payloads), str(out)],
                       env=env, cwd=str(home), capture_output=True, text=True, timeout=7200)
    if p.returncode:
        raise SystemExit(f"run {mode} failed with exit code {p.returncode}")
    return json.loads(out.read_text())


def sidecar(ner_python: str, backend: str, sock: str, *extra: str) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "HF_HOME")}
    env.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    p = subprocess.Popen([ner_python, "-I", str(HERE / "sidecar.py"), sock, backend, *extra], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if p.stdout.readline().strip() != "ready":
        raise SystemExit("the service did not start")
    return p


def main(argv: list) -> int:
    checkout, ner_python, backend, out_path = Path(argv[0]).resolve(), argv[1], argv[2], Path(argv[3])
    _CHECKOUT.append(checkout)
    sys.path.insert(0, str(checkout))
    from maisecrets import detect as _d   # noqa: F401  first, so the bench tree's copy never shadows it
    devroot = Path(os.environ["BENCH_DEVROOT"])
    tmp = Path(tempfile.mkdtemp(prefix="ms-hook-exp-"))
    payloads = tmp / "payloads.jsonl"
    items = corpus(HERE.parent.parent, devroot)
    payloads.write_text("".join(json.dumps(p) + "\n" for p in items), encoding="utf-8")
    sock = str(tmp / "ner.sock")
    report = {"payloads": len(items), "chars": sum(len(p["tool_response"]["stdout"]) for p in items)}

    off = run_mode(checkout, "off", sock, payloads, tmp)
    base = [o["answer"] for o in off["out"]]
    report["off_ms_median"] = sorted(o["ms"] for o in off["out"])[len(base) // 2]
    inactive = run_mode(checkout, "inactive", sock, payloads, tmp)
    report["inactive_byte_identical"] = [o["answer"] for o in inactive["out"]] == base

    raw = [p["tool_response"]["stdout"] for p in items]

    def compare(res: dict) -> dict:
        ans = [o["answer"] for o in res["out"]]
        same = sum(a == b for a, b in zip(ans, base))
        # a value masked without the layer stays masked: per answer, each placeholder type other than NAME occurs at
        # least as often as without the layer (the numbers of the placeholders shift when a name comes first), and
        # the answer holds no more deterministic hits than without the layer
        kept = all(all(_types(a)[k] >= n for k, n in _types(b).items() if k != "NAME") for a, b in zip(ans, base))
        # per answer: a deterministic hit in the text the model gets with the layer whose value the answer without the
        # layer does not show in plain text. A count of hits alone is not enough: a rule that needs a context word
        # can find a value next to a new placeholder that it does not find next to the old text (2026-10-22, a tax id
        # in plain text in both answers). The values are compared here and never written out.
        more = [sum(v not in _text(b, r) for v in _residue_values(a, r)) for a, b, r in zip(ans, base, raw)]
        residue = sum(x for x in more if x > 0)
        residue_at = [i for i, x in enumerate(more) if x > 0]
        # which rule kinds stay in an answer of this run and not in the answer without the layer (kinds only)
        extra_kinds = collections.Counter()
        for a, b, r in zip(ans, base, raw):
            ka, kb = collections.Counter(_residue_kinds(a, r)), collections.Counter(_residue_kinds(b, r))
            extra_kinds.update(ka - kb)
        ms = sorted(o["ms"] for o in res["out"])
        return {"identical_to_off": same, "of": len(ans), "off_placeholders_kept": kept,
                "more_deterministic_hits_left_than_off": residue, "residue_at": residue_at,
                "extra_kinds": dict(extra_kinds),
                "state": res["state"],
                "hook_ms_median": ms[len(ms) // 2], "hook_ms_p95": ms[int(0.95 * (len(ms) - 1))],
                "hook_ms_max": ms[-1]}

    for name, extra in (("on", ()), ("slow", ("--delay-ms", "2000")), ("dies", ("--crash-after", "20")),
                        ("nonsense", ("--garbage",))):
        p = sidecar(ner_python, backend, sock, *extra)
        try:
            report[name] = compare(run_mode(checkout, "on", sock, payloads, tmp))
        finally:
            p.kill()
            p.wait()
    report["violations"] = violations(report)
    out_path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: (v if not isinstance(v, dict) else {kk: vv for kk, vv in v.items() if kk != "state"})
                      for k, v in report.items()}, indent=1))
    return 1 if report["violations"] else 0


def violations(report: dict) -> list:
    """The promises of the layer that this run broke (docs/NER-EXPERIMENT.md, B5); the run fails on any."""
    out = []
    if not report["inactive_byte_identical"]:
        out.append("installed and switched off, an answer differs from the hook without the layer")
    for name in ("on", "slow", "dies", "nonsense"):
        r = report[name]
        if not r["off_placeholders_kept"]:
            out.append(f"{name}: a value masked without the layer is no longer masked")
        if r["more_deterministic_hits_left_than_off"]:
            out.append(f"{name}: an answer leaves a deterministic hit that the answer without the layer masks")
        # a slow or garbled service may change nothing; a dying one answered its first requests, which may add names
        if name in ("slow", "nonsense") and r["identical_to_off"] != r["of"]:
            out.append(f"{name}: a failing service changed {r['of'] - r['identical_to_off']} answers")
    return out


def _types(answer: str) -> collections.Counter:
    import re
    return collections.Counter(m.group(1) for m in re.finditer(r"⟦([A-Z_]+)_c\d+⟧", answer))


def _text(answer: str, raw: str) -> str:
    """The text the model gets: the rewritten stdout of the answer, or the raw one when the hook leaves it as it is."""
    out = json.loads(answer).get("hookSpecificOutput", {}).get("updatedToolOutput", {})
    return out.get("stdout", "") if out else raw


def _residue_values(answer: str, raw: str) -> list:
    """The values of the deterministic hits in the text the model gets."""
    sys.path.insert(0, str(_CHECKOUT[0]))
    from maisecrets import detect
    assert Path(detect.__file__).resolve().is_relative_to(_CHECKOUT[0]), detect.__file__
    return [m.value for m in detect.scan(_text(answer, raw), channel="tool")]


def _residue_kinds(answer: str, raw: str) -> list:
    from maisecrets import detect
    out = json.loads(answer).get("hookSpecificOutput", {}).get("updatedToolOutput", {})
    return [m.kind for m in detect.scan(out.get("stdout", "") if out else raw, channel="tool")]


_CHECKOUT: list = []


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
