"""Profile the CPU time of one maisecrets hook call: where it goes (interpreter, import, rule list, regex compilation,
scan, rest of the hook), which rule classes and rules take the scan time, and the top functions.

    python3 scripts/profile_hook.py --tree DIR [--tree DIR ...] [--runs 15] [--cprofile] [--top 12]

Each --tree is a maisecrets checkout (a worktree of a tag). Three synthetic payloads, the same as the hook time table
of docs/BENCHMARKS.md: a typed prompt of 1 KB (UserPromptSubmit, 957 characters), a Bash result of 20 KB of log lines
and a Read result of "70 KB" of Python code (PostToolUse; 1,200 functions, 62,311 characters). Every measurement runs
in a new process, with one temp home per tree (regions de, locale de_DE) and the client variables removed.

- hook: the CPU time (user + system) of `python -B hooks/dispatch.py <event>` with the payload on stdin, the median of
  --runs calls after one warm-up, round robin over the trees; "interpreter" is the same for `python -B -c pass`.
  POSIX only (resource).
- phases: in one new process that has loaded only what the interpreter loads, time.process_time around the import of
  re and maisecrets.hooks ("import"), detect.rules(), the first scan of the payload text and a second scan. A module
  that maisecrets imports at its first use counts in the phase that uses it (rules() and the first scan load a few).
  "regex compile" is the time of the compilations that miss the cache of re, per phase; the module that asks for each
  is in the table of compilations. "rest of the hook" is the hook call minus the interpreter, import, rules and first
  scan. The median of --runs processes, round robin as above.
- classes: the steady scan time (median of 5 scans after one) per rule class of maisecrets/detection/registry.py
(coarse_class),
  per pass (personal data, cleaned copy, export cells) and the top rules. The time is exclusive: a pass that scans a
  copy does not count the rules it runs again. "scan loop" is the rest of detect._scan: the keyword and context gates of
  every rule, the filters and the checks after a hit, and the loop of the scan of the cleaned copy.
- --cprofile: the top functions by own time of one hook call in process.

The payloads are synthetic and the output holds times, rule ids and function names only. The machine's load changes
the numbers: run at a low load average and compare medians of several rounds. On macOS a reniced process often runs on
an efficiency core, where the same work takes up to twice the CPU time; the round robin spreads that over the trees,
so compare trees within one run, not across runs.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

_HOME_VAR = "MAISECRETS" + "_HOME"
_DISPATCH = "disp" + "atch.py"
_CLIENT_PREFIXES = ("CLAUDE", "CODEX", "MAISECRETS")


# ------------------------------------------------------------------------------------------------------ payloads
def payloads() -> dict:
    """name -> (event, channel, payload, text). The texts of the hook time table of 0.6.24 (seed 7)."""
    rnd = random.Random(7)
    words = ["deploy", "service", "config", "request", "value", "update", "build", "error", "retry", "cache", "user",
             "session", "table", "index", "the", "and", "for", "with", "from", "into"]
    prompt = " ".join(rnd.choice(words) for _ in range(160))[:1000]
    log = "\n".join(f"2026-10-16T01:{i % 60:02d}:{i % 60:02d}Z INFO {rnd.choice(words)} {rnd.choice(words)} took "
                    f"{rnd.randint(1, 900)} ms id={rnd.randint(10**6, 10**7)}" for i in range(600))[:20000]
    code = "\n".join(f"def f{i}(x, y):\n    return x.{rnd.choice(words)}(y) + {rnd.randint(1, 99)}  # "
                     f"{rnd.choice(words)}" for i in range(1200))[:70000]
    base = {"session_id": "s-profile", "transcript_path": "/nonexistent/t.jsonl", "cwd": "/tmp",
            "permission_mode": "default"}
    return {
        "prompt 1 KB": ("user-prompt", "prompt", {**base, "hook_event_name": "UserPromptSubmit", "prompt": prompt},
                        prompt),
        "Bash 20 KB": ("post-tool", "tool", {**base, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                                             "tool_input": {"command": "tail -n 600 app.log"},
                                             "tool_response": {"stdout": log, "stderr": "", "interrupted": False},
                                             "tool_use_id": "t1"}, log),
        "Read 70 KB": ("post-tool", "tool", {**base, "hook_event_name": "PostToolUse", "tool_name": "Read",
                                             "tool_input": {"file_path": "/tmp/app/main.py"},
                                             "tool_response": {"type": "text",
                                                               "file": {"filePath": "/tmp/app/main.py",
                                                                        "content": code}},
                                             "tool_use_id": "t2"}, code),
    }


# ------------------------------------------------------------------------------------------------------ helpers
def make_env(home: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(_CLIENT_PREFIXES)}
    env[_HOME_VAR] = home
    env["MAISECRETS_LOCALE"] = "de_DE"
    env["PYTHONUTF8"] = "1"
    return env


def new_home() -> str:
    home = tempfile.mkdtemp(prefix="maisecrets-profile-")
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": ["de"]}, fh)
    return home


def _children_cpu() -> float:
    import resource
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def child_cpu(cmd: list, data: bytes, env: dict) -> float:
    c0 = _children_cpu()
    subprocess.run(cmd, input=data, capture_output=True, env=env, check=False, cwd=env[_HOME_VAR])
    return _children_cpu() - c0


def run_child(mode: str, tree: str, name: str, env: dict) -> dict:
    r = subprocess.run([sys.executable, "-B", os.path.abspath(__file__), mode, tree, name], capture_output=True,
                       text=True, env=env, cwd=env[_HOME_VAR])
    if r.returncode != 0:
        raise RuntimeError(f"{mode} on {tree} failed (exit {r.returncode}): {r.stderr.strip().splitlines()[-1:]}")
    return json.loads(r.stdout)


# ------------------------------------------------------------------------------------------------------ children
class _Clock:
    """Exclusive CPU time per label: a label's time leaves out the time of the labels that run inside it."""

    def __init__(self) -> None:
        self.excl: dict = {}
        self.stack: list = []

    def enter(self, label: str) -> None:
        self.stack.append([label, time.process_time(), 0.0])

    def leave(self) -> None:
        label, t0, inner = self.stack.pop()
        spent = time.process_time() - t0
        self.excl[label] = self.excl.get(label, 0.0) + spent - inner
        if self.stack:
            self.stack[-1][2] += spent


def _wrap_call(clock: _Clock, label: str, fn):
    def wrapped(*a, **k):
        clock.enter(label)
        try:
            return fn(*a, **k)
        finally:
            clock.leave()
    return wrapped


def _wrap_gen(clock: _Clock, label: str, gen):
    """A generator whose every step is timed under label."""
    while True:
        clock.enter(label)
        try:
            m = next(gen)
        except StopIteration:
            clock.leave()
            return
        except BaseException:
            clock.leave()
            raise
        clock.leave()
        yield m


def _import_tree(tree: str):
    sys.path.insert(0, tree)
    from maisecrets import hooks  # noqa: F401
    from maisecrets import detect
    return detect


# The phases child runs as `python -B -c PHASES_CHILD <tree> <text file> <channel>`: before its clock starts it has
# loaded only what the interpreter loads, so the import phase is the import of a real hook (review of this script:
# the profiler module itself loaded json, subprocess and tempfile first, and their time fell into "rest").
PHASES_CHILD = r"""
import sys, time
t_start = time.process_time()
import re
try:
    from re import _compiler as sre
except ImportError:
    import sre_compile as sre
t_re = time.process_time() - t_start
tree, path, channel = sys.argv[1:4]
with open(path, encoding="utf-8") as fh:
    text = fh.read()
phase = ["import"]
spent = {}
orig = sre.compile

def timed(*a, **k):
    t = time.process_time()
    try:
        return orig(*a, **k)
    finally:
        d = time.process_time() - t
        f = sys._getframe(1)
        while f is not None and f.f_globals.get("__name__", "").split(".")[0] in ("re", "sre_compile", "sre_parse"):
            f = f.f_back
        key = phase[0] + "|" + (f.f_globals.get("__name__", "?") if f is not None else "?")
        v = spent.get(key, [0.0, 0])
        spent[key] = [v[0] + d, v[1] + 1]

sre.compile = timed
sys.path.insert(0, tree)
# modules a hook imports that must not be loaded yet, or their import time would be missing from the import phase
preloaded = [m for m in ("json", "subprocess", "tempfile", "shutil", "argparse", "random", "statistics", "hashlib")
             if m in sys.modules]
t0 = time.process_time()
from maisecrets import hooks
from maisecrets import detect
t1 = time.process_time()
phase[0] = "rules"
detect.rules()
t2 = time.process_time()
phase[0] = "first scan"
detect.scan(text, channel=channel)
t3 = time.process_time()
phase[0] = "second scan"
detect.scan(text, channel=channel)
t4 = time.process_time()
sre.compile = orig
import json
out = {"import": t_re + t1 - t0, "import of re": t_re, "rules": t2 - t1, "first scan": t3 - t2,
       "second scan": t4 - t3, "regex compile": sum(v[0] for v in spent.values()),
       "compiles": sum(v[1] for v in spent.values()), "preloaded": preloaded}
for ph in ("import", "rules", "first scan", "second scan"):
    out["compile " + ph] = sum(v[0] for k, v in spent.items() if k.startswith(ph + "|"))
    out["compiles " + ph] = sum(v[1] for k, v in spent.items() if k.startswith(ph + "|"))
out["by module"] = spent
json.dump(out, sys.stdout)
"""


def run_phases(tree: str, name: str, env: dict) -> dict:
    _, channel, _payload, text = payloads()[name]
    path = os.path.join(env[_HOME_VAR], "payload-" + name.replace(" ", "_") + ".txt")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    r = subprocess.run([sys.executable, "-B", "-c", PHASES_CHILD, tree, path, channel], capture_output=True,
                       text=True, env=env, cwd=env[_HOME_VAR])
    if r.returncode != 0:
        raise RuntimeError(f"phases on {tree} failed (exit {r.returncode}): {r.stderr.strip().splitlines()[-1:]}")
    return json.loads(r.stdout)


def _class_of(detect, rule) -> str:
    """registry.coarse_class of a rule; a tree before the registry (0.6.23) gives the type."""
    reg = getattr(detect, "_registry", None)
    key = getattr(rule, "key", "") or ""
    if reg is None or not key or not hasattr(reg, "rule_class"):
        return "type:" + rule.type.lower()
    source = "user" if key.startswith("user:") else key.split(":", 1)[0]
    rc = reg.rule_class(source, rule.id, rule.type)
    if rc.startswith("provider:"):
        return "token:" + source
    if rc.startswith("pii:"):
        region = getattr(rule, "region", "generic")
        return rc + ("" if region == "generic" else "@" + region)
    return rc


def _child_classes(tree: str, name: str) -> int:
    _, channel, _payload, text = payloads()[name]
    detect = _import_tree(tree)
    clock = _Clock()
    orig_matches = detect._matches

    def matches(rule, t, *a, **k):     # the channel of the scan passes on (detect._matches(rule, text, channel))
        return _wrap_gen(clock, "rule|" + rule.id + "|" + _class_of(detect, rule), orig_matches(rule, t, *a, **k))
    detect._matches = matches
    for fn, label in (("_personal_hits", "pass|personal data"), ("_scan_cleaned_copy", "pass|cleaned copy"),
                      ("_export_hits", "pass|export cells")):
        if hasattr(detect, fn):
            setattr(detect, fn, _wrap_call(clock, label, getattr(detect, fn)))
    detect._scan = _wrap_call(clock, "loop|scan loop (gates, filters, checks)", detect._scan)
    detect.scan(text, channel=channel)               # the first scan compiles the regexes
    rounds = []
    for _ in range(5):
        clock.excl = {}
        t = time.process_time()
        detect.scan(text, channel=channel)
        total = time.process_time() - t
        rounds.append((total, dict(clock.excl)))
    rounds.sort(key=lambda r: r[0])
    total, excl = rounds[len(rounds) // 2]
    json.dump({"total": total, "excl": excl}, sys.stdout)
    return 0


def _child_cprofile(tree: str, name: str) -> int:
    import cProfile
    import io
    import pstats
    event, _channel, payload, _text = payloads()[name]
    sys.path.insert(0, tree)
    from maisecrets import hooks
    sys.argv = [os.path.join(tree, "hooks", _DISPATCH), event]
    sys.stdin = io.StringIO(json.dumps(payload))
    out, sys.stdout = sys.stdout, io.StringIO()
    pr = cProfile.Profile()
    pr.enable()
    try:
        hooks.main(["hook", event])            # as hooks/dispatch.py calls it
    except SystemExit:
        pass
    pr.disable()
    sys.stdout = out
    st = pstats.Stats(pr)
    rows = []
    for (path, line, func), (_cc, nc, tt, ct, _callers) in st.stats.items():
        where = os.path.relpath(path, tree) if path.startswith(tree) else os.path.basename(path)
        rows.append([f"{where}:{line}({func})", nc, tt, ct])
    rows.sort(key=lambda r: -r[2])
    json.dump({"rows": rows[:40], "total": sum(r[2] for r in rows)}, sys.stdout)
    return 0


def importtime(tree: str, env: dict, n: int = 12) -> list:
    """The modules with the largest own import time (python -X importtime), as [module, self us, cumulative us]."""
    code = f"import sys; sys.path.insert(0, {tree!r}); import maisecrets.hooks"
    r = subprocess.run([sys.executable, "-B", "-X", "importtime", "-c", code], capture_output=True, text=True,
                       env=env, cwd=env[_HOME_VAR])
    rows = []
    for line in r.stderr.splitlines():
        if line.startswith("import time:") and line.count("|") == 2:
            own, cum, mod = line[len("import time:"):].split("|")
            if own.strip().isdigit():
                rows.append([mod.strip(), int(own), int(cum)])
    rows.sort(key=lambda r: -r[1])
    return rows[:n]


# ------------------------------------------------------------------------------------------------------ report
def _ms(x: float) -> str:
    return f"{x * 1000:.1f}"


def _median(xs: list) -> float:
    return statistics.median(xs) if xs else 0.0


def measure(trees: list, runs: int, do_cprofile: bool) -> dict:
    pl = payloads()
    labels = [os.path.basename(os.path.normpath(t)) for t in trees]
    res = {"python": sys.version.split()[0], "runs": runs, "load_before": os.getloadavg(), "trees": labels,
           "hook": {}, "phases": {}, "classes": {}, "cprofile": {}}
    # one temp home per tree: a hook call writes its log and state there, and no tree sees another one's
    homes = {label: new_home() for label in labels + ["-interpreter-"]}
    envs = {label: make_env(home) for label, home in homes.items()}
    try:
        for tree, label in zip(trees, labels):
            res.setdefault("importtime", {})[label] = importtime(tree, envs[label])
        # round robin: every run measures each case once, so a change of the machine's speed during the measurement
        # (other load, a core of another kind) falls on every tree alike; the first round is a warm-up
        cases = [("interp", key, [sys.executable, *flags, "-c", "pass"], b"", envs["-interpreter-"])
                 for key, flags in (("interpreter", ["-B"]), ("interpreter -S", ["-B", "-S"]),
                                    ("interpreter -I -S", ["-B", "-I", "-S"]))]
        for name, (event, _ch, payload, _t) in pl.items():
            for tree, label in zip(trees, labels):
                cases.append(("hook", f"{label}|{name}",
                              [sys.executable, "-B", os.path.join(tree, "hooks", _DISPATCH), event],
                              json.dumps(payload).encode(), envs[label]))
        samples: dict = {}
        phases: dict = {}
        for i in range(runs + 1):
            for _kind, key, cmd, data, env in cases:
                x = child_cpu(cmd, data, env)
                if i:
                    samples.setdefault(key, []).append(x)
            if i:
                for name in pl:
                    for tree, label in zip(trees, labels):
                        phases.setdefault(f"{label}|{name}", []).append(run_phases(tree, name, envs[label]))
        for kind, key, _cmd, _data, _env in cases:
            (res if kind == "interp" else res["hook"])[key] = _median(samples[key])
        for key, ph in phases.items():
            res["phases"][key] = {k: _median([p[k] for p in ph]) for k in ph[0] if k not in ("by module", "preloaded")}
            res["phases"][key]["by module"] = {
                k: [_median([p["by module"].get(k, [0.0, 0])[0] for p in ph]), ph[0]["by module"][k][1]]
                for k in ph[0]["by module"]}
        for name in pl:
            for tree, label in zip(trees, labels):
                res["classes"][f"{label}|{name}"] = run_child("_classes", tree, name, envs[label])
                if do_cprofile:
                    res["cprofile"][f"{label}|{name}"] = run_child("_cprofile", tree, name, envs[label])
    finally:
        for home in homes.values():
            shutil.rmtree(home, ignore_errors=True)
    res["load_after"] = os.getloadavg()
    return res


def rest_of_hook(res: dict, label: str, name: str) -> float:
    """The CPU time of a hook call that no phase holds: the hook's own work after the scan (placeholders, the answer,
    the log) and what a hook loads that the phases child does not."""
    ph = res["phases"][f"{label}|{name}"]
    return res["hook"][f"{label}|{name}"] - res["interpreter"] - sum(ph[k] for k in ("import", "rules", "first scan"))


def report(res: dict, top: int) -> None:
    labels, names = res["trees"], list(payloads())
    print(f"Python {res['python']}, median of {res['runs']} runs; load {res['load_before'][0]:.1f} before, "
          f"{res['load_after'][0]:.1f} after. Interpreter alone (python -B -c pass): {_ms(res['interpreter'])} ms; "
          f"with -S {_ms(res['interpreter -S'])} ms; with -I -S {_ms(res['interpreter -I -S'])} ms.\n")
    print("Hook call, CPU ms (user + system of the process):\n")
    print("| Payload | " + " | ".join(labels) + " |")
    print("|---|" + "---|" * len(labels))
    for n in names:
        print(f"| {n} | " + " | ".join(_ms(res["hook"][f"{lb}|{n}"]) for lb in labels) + " |")
    keys = ["import", "import of re", "rules", "first scan", "second scan", "regex compile", "compile import",
            "compile rules", "compile first scan", "compile second scan"]
    for n in names:
        print(f"\nPhases, {n}, CPU ms (regex compile is a part of the phases above it):\n")
        print("| Phase | " + " | ".join(labels) + " |")
        print("|---|" + "---|" * len(labels))
        for k in keys:
            print(f"| {k} | " + " | ".join(_ms(res["phases"][f"{lb}|{n}"][k]) for lb in labels) + " |")
        print("| compilations | " + " | ".join(str(int(res["phases"][f"{lb}|{n}"]["compiles"])) for lb in labels)
              + " |")
        for ph in ("import", "rules", "first scan", "second scan"):
            print(f"| compilations, {ph} | " + " | ".join(str(int(res["phases"][f"{lb}|{n}"]["compiles " + ph]))
                                                         for lb in labels) + " |")
        rest = [rest_of_hook(res, lb, n) for lb in labels]
        print("| rest of the hook | " + " | ".join(_ms(x) for x in rest) + " |")
    # a tree before the registry (0.6.23) has no class: its rules take the class that a later tree gives the same id
    class_of_id = {}
    for v in res["classes"].values():
        for label in v["excl"]:
            parts = label.split("|")
            if parts[0] == "rule" and not parts[2].startswith("type:"):
                class_of_id[parts[1]] = parts[2]
    for n in names:
        per_class: dict = {}
        per_rule: dict = {}
        for lb in labels:
            excl = res["classes"][f"{lb}|{n}"]["excl"]
            for label, t in excl.items():
                parts = label.split("|")
                if parts[0] != "rule":
                    cls = parts[1]
                elif parts[2].startswith("type:"):
                    cls = class_of_id.get(parts[1], parts[2])
                else:
                    cls = parts[2]
                per_class.setdefault(cls, {})[lb] = per_class.setdefault(cls, {}).get(lb, 0.0) + t
                if parts[0] == "rule":
                    by = per_rule.setdefault(parts[1], {})
                    by[lb] = by.get(lb, 0.0) + t        # an id that two sources share: both rules
        print(f"\nSteady scan, {n}, CPU ms by rule class and pass (exclusive; classes over 0.2 ms):\n")
        print("| Class or pass | " + " | ".join(labels) + " |")
        print("|---|" + "---|" * len(labels))
        last = labels[-1]
        for cls, by in sorted(per_class.items(), key=lambda kv: -max(kv[1].values())):
            if max(by.values()) >= 0.0002:
                print(f"| {cls} | " + " | ".join(_ms(by.get(lb, 0.0)) for lb in labels) + " |")
        print("| total scan | " + " | ".join(_ms(res["classes"][f"{lb}|{n}"]["total"]) for lb in labels) + " |")
        print(f"\nTop {top} rules, {n}, by the time in their matcher in {last} (ms):\n")
        print("| Rule | " + " | ".join(labels) + " |")
        print("|---|" + "---|" * len(labels))
        for rid, by in sorted(per_rule.items(), key=lambda kv: -kv[1].get(last, 0.0))[:top]:
            print(f"| `{rid}` | " + " | ".join(_ms(by.get(lb, 0.0)) if lb in by else "–" for lb in labels) + " |")
    for lb in labels:
        by = res["phases"][f"{lb}|{names[-1]}"]["by module"]
        print(f"\nRegex compilations, {lb}, {names[-1]}: by phase and the module that asks (ms; count)\n")
        for k, (t, c) in sorted(by.items(), key=lambda kv: -kv[1][0])[:12]:
            print(f"  {t * 1000:6.1f} {c:5d}  {k.replace('|', ', ')}")
    for lb in labels:
        print(f"\nImport of maisecrets.hooks, {lb}: modules with the largest own time (python -X importtime, one "
              "process; ms own / cumulative)\n")
        for mod, own, cum in res["importtime"][lb]:
            print(f"  {own / 1000:6.1f} {cum / 1000:7.1f}  {mod}")
    for key, cp in res["cprofile"].items():
        print(f"\ncProfile, {key.replace('|', ', ')}: top {top} functions by own time (ms; calls)\n")
        for where, nc, tt, ct in cp["rows"][:top]:
            print(f"  {tt * 1000:7.1f} {ct * 1000:7.1f} {nc:7d}  {where}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    child = {"_classes": _child_classes, "_cprofile": _child_cprofile}
    if argv[:1] and argv[0] in child:
        return child[argv[0]](argv[1], argv[2])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tree", action="append", required=True, help="a maisecrets checkout; repeat to compare")
    ap.add_argument("--runs", type=int, default=15)
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--cprofile", action="store_true")
    ap.add_argument("--out", help="write the raw medians as JSON")
    a = ap.parse_args(argv)
    trees = [os.path.abspath(t) for t in a.tree]
    names = [os.path.basename(os.path.normpath(t)) for t in trees]
    if len(set(names)) < len(names):
        ap.error("two trees have the same folder name; the tables name a tree by it")
    for t in trees:
        if not os.path.isfile(os.path.join(t, "hooks", _DISPATCH)):
            ap.error(f"{t} is no maisecrets checkout (hooks/{_DISPATCH} is missing)")
    if a.runs < 1:
        ap.error("--runs must be 1 or more")
    res = measure(trees, a.runs, a.cprofile)
    report(res, a.top)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
