"""Mission coverage: does every product promise rest on beliefs that can fail?

mission/M*.toml names one promise each, the controls (C*) and invariants (I*) of docs/THREAT-MODEL.md that serve
it, and its parts: one sentence each, with an id (M1.3). Each belief of beliefs/*.toml names the parts it proves in
`serves`, so a new belief counts for no part until its author says which. scripts/replay_can_fail.py proves that
each belief's test goes red under its mutation. mission/claims.toml maps the promises that README.md and
PRIVACY.md make to users onto the missions. This script joins them and reports:

- a part with no belief (the sentence rests on prose, or on tests no mutation proves), or with one only (thin),
- a mission without an invariant (only per-line proofs, no check over every path),
- a documented control or invariant that no mission names, and beliefs that no part names,
- a name in a mission or a belief that the threat model does not document, a belief without `serves`, a part id
  in `serves` that no mission has, a part without its id or with one that another part has, two files of one
  mission, or a belief whose control (or label, such as "operations") its mission does not name,
- a claim whose quote no longer stands in its source, a bullet of a gated section of README.md or PRIVACY.md that
  no claim maps, and a gated section that is gone,
- each mission's measured number (`[measure]`: a source file, the row that holds it and its column, and the gate
  that keeps its bound), or why it has none (`none`); a measure that cannot be read is a finding,
- the other direction, from the code up (mission/code.toml): a program file of the plugin (CODE) that the register
  does not declare; an entry for a file that is gone; a file declared for a control that no belief's proof in that
  file names; a proof in a file whose entry does not declare the proof's control; a file that the threat model names
  for a control but that does not exist, or that the register does not declare for that control.

Without --strict it only reports and exits 0. With --strict it exits 1 on a gap, an orphan control, an unknown name,
a claim finding or a code finding. Python 3.11+ (tomllib), like replay_can_fail.py.
"""
import argparse
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROL_ROW = re.compile(r"^\| (C\d+[a-z]?) \|", re.M)
# the program files of the plugin: what it runs (one pattern, in mission_touch.py, which runs on Python 3.9 too)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mission_touch import CODE  # noqa: E402
CODE_DIRS = ("maisecrets", "hooks", "claude-mod", "skills")
# a key of a hook's answer (quoted, or bare before : or = as in JavaScript or dict(...)), and a hook's exit 2: a file
# that names one is no `none` file. Text only: a key built at run time escapes it
_KEYS = ("updatedToolOutput|updatedMCPToolOutput|updatedInput|permissionDecision|decision|suppressOriginalPrompt|"
         "additionalContext|systemMessage|continue|stopReason")
ANSWER_KEY = re.compile(rf"""["']({_KEYS})["']|\b({_KEYS})\s*[:=](?!=)|\b(sys\.exit\(2\)|exit\s+(?:/b\s+)?2\b)""")
# a path of the repository in a row of the threat model, in backticks
NAMED_PATH = re.compile(r"`((?:maisecrets|hooks|claude-mod|skills|harness|tests|scripts)/[\w./-]+)`")
INVARIANT_ITEM = re.compile(r"^- \*\*(I\d+)\*\*", re.M)
# the sections whose every bullet is a promise, a limit or a feature that claims.toml must map
GATED_SECTIONS = (("README.md", "What it does"), ("docs/HOW-IT-WORKS.md", "What the Claude Code mod does"),
                  ("README.md", "What it does not protect"), ("PRIVACY.md", "What it reads"),
                  ("PRIVACY.md", "What it stores, and where"), ("PRIVACY.md", "What leaves the machine"))
KINDS = ("promise", "limit", "feature")


def documented(threat_model: str):
    return set(CONTROL_ROW.findall(threat_model)), set(INVARIANT_ITEM.findall(threat_model))


def named_paths(threat_model: str) -> dict[str, set[str]]:
    """control or invariant -> the repository paths its row (or item) of the threat model names."""
    out: dict[str, set[str]] = {}
    for m in re.finditer(r"^\| (C\d+[a-z]?) \|(.*)$|^- \*\*(I\d+)\*\*(.*)$", threat_model, re.M):
        name, text = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        out.setdefault(name, set()).update(NAMED_PATH.findall(text))
    return out


def code_files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for d in CODE_DIRS if (root / d).is_dir() for p in (root / d).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and CODE.match(p.relative_to(root).as_posix())}


def check_code(root: Path, names: set[str], loaded: list[dict], threat_model: str) -> tuple[list[str], dict]:
    """The register of mission/code.toml against the files, the proofs and the threat model. (findings, counts)."""
    path = root / "mission" / "code.toml"
    if not path.exists():
        return ["mission/code.toml not found: no program file says which controls it carries"], {}
    raw = tomllib.loads(path.read_text(encoding="utf-8")).get("file", {})
    findings: list[str] = []
    if not isinstance(raw, dict):
        return ["mission/code.toml: file is not a table of paths"], {}
    declared: dict[str, set[str]] = {}
    nones_of: set[str] = set()
    nones = withs = 0
    for f, entry in sorted(raw.items()):
        controls = entry.get("controls") if isinstance(entry, dict) else None
        none = entry.get("none") if isinstance(entry, dict) else None
        if isinstance(controls, list) and controls and all(isinstance(c, str) for c in controls) and none is None:
            declared[f] = set(controls)
            withs += 1
            for c in controls:
                if c not in names:
                    findings.append(f"{f}: declares {c}, which docs/THREAT-MODEL.md does not document")
        elif isinstance(none, str) and none.strip() and controls is None:
            declared[f] = set()
            nones_of.add(f)
            nones += 1
        else:
            findings.append(f"{f}: the entry needs controls (a list of C or I names) or none (a reason), not both")
            declared[f] = set()
    files = code_files(root)
    findings += [f"{f}: a program file that mission/code.toml does not declare" for f in sorted(files - set(raw))]
    findings += [f"{f}: declared in mission/code.toml, but the file is gone" for f in sorted(set(raw) - files)]
    # control -> files: proofs of a belief that serves a promise. A belief with serves = [] proves no promise, so it
    # proves no control of a file either. An injection proof (its replace keeps the find text and adds code, as I5
    # adds an import to an alias module) proves the control, but it does not make its file carry the control and it
    # breaks no line of the file; every other proof does both, of any kind and of any control or label
    proven: dict[str, set[str]] = {}
    forced: dict[str, set[str]] = {}
    targeted: set[str] = set()
    for b in loaded:
        proofs = b.get("proof", [])
        for p in ([proofs] if isinstance(proofs, dict) else proofs if isinstance(proofs, list) else []):
            if not (isinstance(p, dict) and isinstance(p.get("file"), str)):
                continue
            find, replace = p.get("find"), p.get("replace")
            injects = isinstance(find, str) and isinstance(replace, str) and find in replace
            if not injects:
                targeted.add(p["file"])
            if b.get("serves"):
                proven.setdefault(p["file"], set()).add(b.get("control", ""))
                if not injects:
                    forced.setdefault(p["file"], set()).add(b.get("control", ""))
    for f in sorted(declared):
        for c in sorted(declared[f] - proven.get(f, set())):
            findings.append(f"{f}: declares {c}, but no belief of {c} has a proof in this file")
        if f in files:
            for c in sorted((forced.get(f, set()) & names) - declared[f]):
                findings.append(f"{f}: a belief of {c} has a proof in this file, but its entry does not declare {c}")
            if f in nones_of:
                # `none` is a judgement the check cannot read; these two signs of a decision it can
                if f in targeted:
                    findings.append(f"{f}: declared none, but a belief's mutation breaks a line of it")
                text = (root / f).read_text(encoding="utf-8", errors="replace")
                keys = sorted({next(g for g in m.groups() if g) for m in ANSWER_KEY.finditer(text)})
                if keys:
                    findings.append(f"{f}: declared none, but it names a hook answer key ({', '.join(keys)})")
    for c, paths in sorted(named_paths(threat_model).items()):
        for f in sorted(paths):
            if not (root / f).exists():
                findings.append(f"docs/THREAT-MODEL.md names {f} for {c}, but the file does not exist")
            elif CODE.match(f) and c not in declared.get(f, {c}):
                findings.append(f"docs/THREAT-MODEL.md names {f} for {c}, but mission/code.toml does not declare it")
    return findings, {"files": len(files), "with controls": withs, "none": nones}


def flat(text: str) -> str:
    return " ".join(text.split())


def bullets(markdown: str, section: str) -> list[str] | None:
    """The top-level bullets of one `## section`, each as one line of text without its `- `; None without the
    section."""
    m = re.search(rf"^## {re.escape(section)}\n(.*?)(?=^## |\Z)", markdown, re.M | re.S)
    if not m:
        return None
    out: list[str] = []
    for line in m.group(1).splitlines():
        if line.startswith("- "):
            out.append(line[2:])
        elif out and line.startswith("  ") and line.strip():
            out[-1] += " " + line.strip()
    return [flat(b) for b in out]


def check_claims(root: Path, missions: set[str]) -> list[str]:
    path = root / "mission" / "claims.toml"
    if not path.exists():
        return ["mission/claims.toml not found: no promise of README.md or PRIVACY.md is checked"]
    claims = tomllib.loads(path.read_text(encoding="utf-8")).get("claim", [])
    findings: list[str] = []
    texts: dict[str, str] = {}
    if not isinstance(claims, list) or not all(isinstance(c, dict) for c in claims):
        return ["mission/claims.toml: claim is not a list of [[claim]] tables"]
    for c in claims:
        if not isinstance(c.get("quote", ""), str) or not isinstance(c.get("source", ""), str):
            findings.append(f"claim with a quote or a source that is no text: {c.get('quote')!r}"[:90])
            c["quote"], c["source"] = "", str(c.get("source", ""))
        src, quote, kind = c.get("source", ""), flat(c.get("quote", "")), c.get("kind")
        if src not in texts:
            texts[src] = (root / src).read_text(encoding="utf-8") if src and (root / src).is_file() else ""
        if not quote or quote not in flat(texts[src]):
            findings.append(f"claim not found in {src}: {quote[:70]}")
        if kind not in KINDS:
            findings.append(f"claim kind {kind!r} is not one of {', '.join(KINDS)}: {quote[:50]}")
        elif kind != "feature" and c.get("mission") not in missions:
            findings.append(f"claim names no existing mission ({c.get('mission')}): {quote[:50]}")
    for src, section in GATED_SECTIONS:
        if src not in texts:
            texts[src] = (root / src).read_text(encoding="utf-8") if src and (root / src).is_file() else ""
        found = bullets(texts[src], section)
        if not found:
            # a renamed section, or one whose bullets moved, would end its gate without a word
            findings.append(f"{src} has no section \"{section}\" with a bullet (GATED_SECTIONS)")
            continue
        quotes = [flat(c.get("quote", "")) for c in claims if c.get("source") == src]
        for b in found:
            if not any(q and b.startswith(q) for q in quotes):
                findings.append(f"{Path(src).stem} \"{section}\" bullet no claim maps: {b[:70]}")
    return findings


def read_measure(root: Path, measure: dict) -> tuple[float | None, str]:
    """The newest value of a measure: the last table row of `source` that holds `row`, its `column` (1-based, as the
    cells of a Markdown row split on "|"). (value, "") or (None, why)."""
    path = root / measure.get("source", "")
    if not path.is_file():
        return None, f"source {measure.get('source')} not found"
    lines = path.read_text(encoding="utf-8").splitlines()
    rows = [r for r in lines if r.startswith("|") and measure.get("row", "") in r]
    if not rows:
        return None, f"no row with {measure.get('row')!r} in {measure.get('source')}"
    try:
        return float(rows[-1].split("|")[int(measure["column"])]), ""
    except (KeyError, IndexError, ValueError):
        return None, f"column {measure.get('column')} of the last {measure.get('row')!r} row is no number"


def analyse(root: Path):
    controls, invariants = documented((root / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8"))
    loaded = [tomllib.loads(p.read_text(encoding="utf-8")) for p in sorted((root / "beliefs").glob("*.toml"))]
    beliefs = {b["belief"]: b.get("control", "") for b in loaded}
    serves = {b["belief"]: b.get("serves") for b in loaded}
    missions = [(p, tomllib.loads(p.read_text(encoding="utf-8"))) for p in sorted((root / "mission").glob("M*.toml"))]
    typed: list[str] = []
    for path, m in missions:
        if not isinstance(m.get("mission"), str):
            typed.append(f"{path.name}: mission is not a name")
            m["mission"] = path.stem.split("-")[0]
        for key in ("controls", "invariants", "labels"):
            value = m.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                typed.append(f"{m['mission']}: {key} is not a list of names")
                m[key] = [x for x in value if isinstance(x, str)] if isinstance(value, list) else []
        if not isinstance(m.get("promise"), str):
            typed.append(f"{m['mission']}: promise is not a sentence")
            m["promise"] = ""
        if not isinstance(m.get("measure", {}), dict):
            typed.append(f"{m['mission']}: measure is not a [measure] table")
            m["measure"] = {}
        found = m.get("part", [])
        if not isinstance(found, list) or not all(isinstance(x, dict) for x in found):
            typed.append(f"{m['mission']}: part is not a list of [[part]] tables")
            m["part"] = [x for x in found if isinstance(x, dict)] if isinstance(found, list) else []
    served: set[str] = set()
    # part id -> the controls, invariants and labels its mission names (a belief labelled "operations" or "detector"
    # serves a part only when its mission names that label in `labels`)
    parts: dict[str, set[str]] = {}
    twice = [f"{mid}: {n} files name this mission" for mid, n in
             sorted(Counter(m["mission"] for _p, m in missions).items()) if n > 1]
    part_ids = Counter(part.get("id") for _p, m in missions for part in m.get("part", [])
                       if isinstance(part.get("id"), str))
    for _path, m in missions:
        for part in m.get("part", []):
            pid = part.get("id")
            if isinstance(pid, str) and re.fullmatch(rf"{re.escape(str(m.get('mission')))}\.\d+", pid):
                names = set(m.get("controls", [])) | set(m.get("invariants", [])) | set(m.get("labels", []))
                parts.setdefault(pid, set()).update(names)
    r = {"_dup": set(), "missions": [], "gaps": [], "thin": [], "no_invariant": [], "orphans": [], "unknown": [],
         "claims": [],
         "measures": [],
         "code": [],
         "unowned_beliefs": Counter(),
         "undocumented_belief_controls": sorted({c for c in beliefs.values()
                                                 if c not in controls and c not in invariants})}
    r["unknown"].extend(typed + twice)
    for path, m in missions:
        mid = m["mission"]
        if not path.stem.startswith(mid + "-"):
            r["unknown"].append(f"{path.name}: the file name does not start with {mid}-")
        for name in m.get("controls", []) + m.get("invariants", []):
            served.add(name)
            if name not in controls and name not in invariants:
                r["unknown"].append(f"{mid}: {name} is not in docs/THREAT-MODEL.md")
        if not m.get("invariants"):
            r["no_invariant"].append(mid)
        rows = []
        for label in m.get("labels", []):
            if label in controls or label in invariants:
                r["unknown"].append(f"{mid}: {label} is a control; name it in controls or invariants, not labels")
        for i, part in enumerate(m.get("part", []), 1):
            pid = part.get("id", "")
            if not isinstance(pid, str) or not re.fullmatch(rf"{re.escape(mid)}\.\d+", pid):
                r["unknown"].append(f"{mid}, part {i}: the id {pid!r} is not {mid}.<number>")
                pid = ""
            elif part_ids[pid] > 1 and pid not in r["_dup"]:
                r["unknown"].append(f"{pid}: {part_ids[pid]} parts have this id")
                r["_dup"].add(pid)
            if not isinstance(part.get("says"), str):
                r["unknown"].append(f"{pid or mid}: the part has no sentence in says")
                part["says"] = ""
            if "beliefs" in part:
                r["unknown"].append(f"{pid or mid}: a part names no beliefs; each belief names its parts in serves")
            got = {b for b, s in serves.items() if pid and pid in (s or [])}
            rows.append((pid, part["says"], len(got)))
            elsewhere = f" (tested only in {', '.join(part['tests'])}, which no mutation proves)" \
                if part.get("tests") else ""
            if not got:
                r["gaps"].append(f"{pid}: no belief{elsewhere}: {part['says']}")
            elif len(got) == 1:
                r["thin"].append(f"{pid}: one belief: {part['says']}")
        if not m.get("part"):
            r["gaps"].append(f"{mid}: no part names a belief")
        measure = m.get("measure") or {}
        if measure.get("none"):
            r["measures"].append(f"{mid}: none: {measure['none']}")
        elif measure:
            value, why = read_measure(root, measure)
            if value is None:
                r["unknown"].append(f"{mid}: the measure cannot be read: {why}")
            else:
                r["measures"].append(f"{mid}: {value} = {measure.get('what')} (bound: {measure.get('gate')})")
        else:
            r["unknown"].append(f"{mid}: no [measure], and no `none` that says why")
        r["missions"].append((mid, m["promise"], rows))
    for name in sorted(controls | invariants, key=lambda s: (s[0], int(s[1:].rstrip("abcdefghijklmnopqrstuvwxyz")), s)):
        if name not in served:
            r["orphans"].append(f"{name} serves no mission")
    for b, control in beliefs.items():
        s = serves[b]
        if not isinstance(s, list) or not all(isinstance(x, str) for x in s):
            r["unknown"].append(f"{b}: no serves list of part ids (serves = [] when it serves no promise)")
            continue
        if not s:
            r["unowned_beliefs"][control] += 1
        for pid in s:
            if pid not in parts:
                r["unknown"].append(f"{b}: serves {pid}, which no mission has")
            elif control not in parts[pid]:
                r["unknown"].append(f"{b}: serves {pid}, but {pid.split('.')[0]} does not name its control {control}")
    r["claims"] = check_claims(root, {m["mission"] for _, m in missions})
    r["code"], r["code_counts"] = check_code(root, controls | invariants, loaded,
                                             (root / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8"))
    del r["_dup"]
    return r


def render(r) -> str:
    out = []
    for mid, promise, rows in r["missions"]:
        out.append(f"{mid}  {promise}")
        out.extend(f"    {pid}  {n:4} beliefs  {says}" for pid, says, n in rows)
    unowned = [f"{c or '-'}: {n}" for c, n in sorted(r["unowned_beliefs"].items())]
    sections = (("gaps", "parts with no belief", r["gaps"]), ("thin", "parts with one belief", r["thin"]),
                ("no_invariant", "missions without an invariant", r["no_invariant"]),
                ("orphans", "documented controls in no mission", r["orphans"]),
                ("unowned", "beliefs that serve no promise (serves = []), by control", unowned),
                ("unknown", "unknown names and broken links", r["unknown"]),
                ("claims", "claims of README.md and PRIVACY.md", r["claims"]),
                ("code", "program files and their controls (mission/code.toml: "
                 + ", ".join(f"{k} {v}" for k, v in r["code_counts"].items()) + ")", r["code"]),
                ("measures", "the measured number of each mission", r["measures"]),
                ("labels", "belief control labels that are no documented control",
                 r["undocumented_belief_controls"]))
    for _key, title, lines in sections:
        out.append(f"\n{title}: {len(lines)}")
        out.extend(f"  {line}" for line in lines)
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 on a gap, an orphan control, an unknown name, a claim or a code finding")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    r = analyse(args.root)
    print(render(r))
    return 1 if args.strict and (r["gaps"] or r["orphans"] or r["unknown"] or r["claims"] or r["code"]) else 0


if __name__ == "__main__":
    sys.exit(main())
