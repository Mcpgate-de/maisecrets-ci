#!/usr/bin/env python3
"""Replay the detector over recorded agent sessions and report what it WOULD have caught.

Sources: Claude Code transcripts (~/.claude/projects/**/*.jsonl) and Codex
rollouts (~/.codex/sessions/**/*.jsonl). Every JSON string inside every line
is scanned. Nothing this script prints is a value: only rule ids, counts,
fingerprint prefixes (sha256[:8]) and file paths.

Usage:
  scripts/replay_sessions.py [--claude] [--codex] [--legacy PATH] [--out report.md] [--limit N]

--legacy PATH   also run an older detect.py (a file) and diff the two:
                distinct values only the new one finds, only the old one finds.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from maisecrets import detect  # noqa: E402


def fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def strings_of(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from strings_of(x)
    elif isinstance(node, dict):
        for v in node.values():
            yield from strings_of(v)


def load_legacy(path: str):
    spec = importlib.util.spec_from_file_location("detect_legacy", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod   # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--claude", action="store_true")
    ap.add_argument("--codex", action="store_true")
    ap.add_argument("--legacy")
    ap.add_argument("--out", default="harness/out/replay.md")
    ap.add_argument("--limit", type=int, default=0, help="max files per source (0 = all)")
    a = ap.parse_args()
    if not (a.claude or a.codex):
        a.claude = a.codex = True
    sources = []
    if a.claude:
        sources.append(("claude", Path.home() / ".claude" / "projects"))
    if a.codex:
        sources.append(("codex", Path.home() / ".codex" / "sessions"))
    legacy = load_legacy(a.legacy) if a.legacy else None

    t0 = time.time()
    per_source = {}
    for name, base in sources:
        files = sorted(base.rglob("*.jsonl"))
        if a.limit:
            files = files[: a.limit]
        hits_by_rule: Counter = Counter()
        distinct_by_rule: dict[str, set] = defaultdict(set)
        new_fps: dict[str, set] = defaultdict(set)      # rule -> fps (new detector)
        old_fps: dict[str, set] = defaultdict(set)      # legacy kind -> fps
        files_with_hits: Counter = Counter()
        n_lines = n_bytes = 0
        for i, f in enumerate(files, 1):
            if i % 25 == 0 or i == len(files):
                print(f"  {name}: {i}/{len(files)} files, {n_bytes / 1e6:.0f} MB, {time.time() - t0:.0f} s",
                      file=sys.stderr, flush=True)
            try:
                data = f.read_bytes()
            except OSError:
                continue
            n_bytes += len(data)
            for line in data.decode("utf-8", errors="ignore").splitlines():
                n_lines += 1
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                for s in strings_of(obj):
                    if len(s) < 8:
                        continue
                    for m in detect.scan(s):
                        hits_by_rule[m.kind] += 1
                        distinct_by_rule[m.kind].add(fp(m.value))
                        new_fps[m.type].add(fp(m.value))
                        files_with_hits[str(f.relative_to(base))] += 1
                    if legacy is not None:
                        for m in legacy.scan(s):
                            old_fps[m.type].add(fp(m.value))
        per_source[name] = dict(files=len(files), lines=n_lines, mb=n_bytes / 1e6, hits=hits_by_rule,
                                distinct=distinct_by_rule, new=new_fps, old=old_fps, top_files=files_with_hits)

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# Replay report ({time.strftime('%Y-%m-%d %H:%M')}), detector rules: {len(detect.rules())}, "
             f"betterleaks {(ROOT / 'maisecrets/detection/rules/BETTERLEAKS_VERSION').read_text().strip()}", ""]
    for name, r in per_source.items():
        lines += [f"## {name}: {r['files']} files, {r['lines']} lines, {r['mb']:.0f} MB", "",
                  "| rule | hits | distinct values |", "|---|---:|---:|"]
        for rule, n in r["hits"].most_common():
            lines.append(f"| {rule} | {n} | {len(r['distinct'][rule])} |")
        tot_new = {t: len(v) for t, v in r["new"].items()}
        lines += ["", f"distinct values by type (new detector): {tot_new}"]
        if legacy is not None:
            for t in sorted(set(r["new"]) | set(r["old"])):
                n, o = r["new"].get(t, set()), r["old"].get(t, set())
                lines.append(f"- {t}: new-only {len(n - o)}, legacy-only {len(o - n)}, both {len(n & o)}")
        lines += ["", "top files by hits (paths only):"]
        for path, n in r["top_files"].most_common(8):
            lines.append(f"- {n:5d}  {path}")
        lines.append("")
    lines.append(f"runtime {time.time() - t0:.0f} s")
    out.write_text("\n".join(lines))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
