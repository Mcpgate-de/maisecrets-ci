"""`maisecrets rules`: show, check, test, start and import the rules of your own (maisecrets/user_rules.py).

Every line names a folder, a file, a rule id or the place of a refused rule, a reason, a count or a time. None prints
a regex match, a sample text, the text of a refused line or a value: the output goes to the model when the agent runs
the command.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from . import detect, user_rules

USAGE = ("maisecrets rules                       the folders, their rules and what was left out\n"
         "maisecrets rules list [--json]         every rule: key, id, origin, rank, channel, region, class, needs,\n"
         "                                       upstream\n"
         "maisecrets rules check [DIR]           check a folder (or every folder the hooks read) and its samples.txt\n"
         "maisecrets rules test [text]           what the rules find in the text (or stdin); never the value\n"
         "maisecrets rules init DIR              start a rule folder for a team\n"
         "maisecrets rules import FILE.toml      a gitleaks or betterleaks config in the JSON form (Python 3.11+)")

_NO_FILES = "no *.json or *.prefixes file here (a team repository keeps them in rules/)"


def _q(q: "user_rules.Quarantined") -> str:
    where = f"{q.folder}/{q.file}" if q.file else q.folder
    return f"{where} · {q.rule or '(whole file)' if q.file else '(folder)'} · {q.reason}"


def show() -> int:
    loaded = user_rules.load()
    values, ids = detect.allow_list()
    print("maisecrets rules of your own\n")
    for f in loaded.folders:
        if f.state != "ok":
            print(f"  {f.shown} ({f.source}) · {f.state}")
            continue
        print(f"  {f.shown} ({f.source}) · {f.rules} rule(s) · hash {f.digest}"
              + (f" · {_NO_FILES}" if not f.files and f.source != "own" else ""))
    print(f"\nRules of your own loaded: {len(loaded.rules)}; all rules: {len(detect.rules())}")
    left = [q for q in loaded.quarantined if not q.kept]
    notes = [q for q in loaded.quarantined if q.kept]
    if left:
        print(f"\nLeft out ({len(left)}), each with the check it failed:")
        for q in left:
            print(f"  {_q(q)}")
    if notes:
        print(f"\nLoaded with a part dropped ({len(notes)}):")
        for q in notes:
            print(f"  {_q(q)}")
    from . import terms
    tl = terms.load(strict=False)
    print(f"\nTerms: {terms.summary(tl)[7:]}")
    for f in tl.files:
        print(f"  {f.source} · {f.entities} term(s) · hash {f.digest}")
    for r in tl.refused:
        print(f"  left out: {r.source}" + (f" line {r.line}" if r.line else "") + f" · {r.reason}")
    from . import value_files
    if value_files.present():
        from . import values as imports
        line = imports.summary_line()
        print(f"\n{line[0].upper()}{line[1:]}; /maisecrets:list shows each import")
    print(f"\nAllow list: {len(values)} exact value(s), {len(ids)} rule id(s) switched off"
          + (f" ({', '.join(sorted(ids))})" if ids else ""))
    print("\nAdd a folder: /maisecrets:settings rule_dirs add DIR (type it as your own prompt)\n"
          "Check a folder: maisecrets rules check DIR")
    return 0


def _samples_file(target: Path, folder: Path) -> Path | None:
    """samples.txt at the top of a team repository, or in the rule folder itself."""
    for cand in (target / "samples.txt", folder / "samples.txt"):
        if cand.is_file():
            return cand
    return None


def _samples(path: Path, rules: list) -> list[str]:
    """The failures of samples.txt: `hit <rule-id> <text>` must be found by that rule, `miss <text>` by no rule of
    the folder. A failure names the line, never its text."""
    failed = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        verb, _, rest = line.strip().partition(" ")
        if verb == "hit":
            rid, _, text = rest.strip().partition(" ")
            kind = rid if rid.startswith(user_rules.ID_PREFIX) else user_rules.ID_PREFIX + rid
            kinds = {m.kind for m in detect.scan(text, rule_list=rules)}
            if kind not in kinds:
                failed.append(f"samples.txt line {n}: no hit of {kind}"
                              + (f" (found: {', '.join(sorted(kinds))})" if kinds else ""))
        elif verb == "miss":
            kinds = {m.kind for m in detect.scan(rest, rule_list=rules)}
            if kinds:
                failed.append(f"samples.txt line {n}: a hit of {', '.join(sorted(kinds))} where none belongs")
        else:
            failed.append(f"samples.txt line {n}: neither `hit <rule-id> <text>` nor `miss <text>`")
    return failed


def _check_folder(shown: str, folder: Path, samples: Path | None, taken: set, need_rules: bool) -> int:
    """Check one folder as the hook reads it, and time each rule on the texts that make a backtracking regex slow.
    Returns the number of problems."""
    sources: dict = {}
    rules, quarantined, digest = user_rules.load_folder(folder, shown, taken, sources=sources)
    left = [q for q in quarantined if not q.kept]
    print(f"{shown}: {len(rules)} rule(s), {len(left)} refused, hash {digest}")
    bad = len(left)
    if not user_rules._rule_files(folder):
        print(f"  {_NO_FILES}")
        bad += need_rules
    info: dict = {}
    timed = user_rules.probe([sources[r.id] for r in rules if r.id in sources], info=info)
    # A rule that a real scan found too slow stays out until the rule changes: this check reruns only the test texts,
    # which the rule passed before, so it cannot clear that verdict (Opus review, round 3). It shows it, with the way
    # out. A verdict of the test texts alone is the check's own, and a pass now replaces it.
    state = user_rules._read_state()
    slow = state.get("slow") if isinstance(state.get("slow"), dict) else {}
    tested = state.get("tested") if isinstance(state.get("tested"), dict) else {}
    renewed = 0
    fast = []
    for rule in rules:
        key = sources[rule.id].hash if rule.id in sources else ""
        ms = timed.get(key, "untested")
        if key in slow:
            print(f"  slow    {rule.id}  the hooks leave it out: a real scan found it slow; change the rule to have "
                  "it checked again")
            bad += 1
        elif ms == "untested" and info.get("child"):
            # the child started and gave no answer for it: the hook leaves such a rule out (Gate A round 2)
            print(f"  slow    {rule.id}  the timed test gave no answer for it; the hooks leave it out until it has one")
            bad += 1
        elif ms == "untested":
            print(f"  ok      {rule.id}  (not timed)")
            fast.append(rule)
        elif ms is None or ms > user_rules.PROBE_LIMIT_MS:
            print(f"  slow    {rule.id}  {user_rules._slow_reason(ms)}")
            bad += 1
        else:
            print(f"  ok      {rule.id}  {ms:.1f} ms")
            fast.append(rule)
            old = tested.get(key, 0.0)
            if key not in tested or old is None or old > user_rules.PROBE_LIMIT_MS:
                # a new rule, or test texts that were slow once (a busy machine): the hooks need not time it again,
                # so a folder of many rules runs at the next call, not over several (Gate B round 2)
                tested[key] = ms
                renewed += 1
    if renewed:
        state["tested"] = tested
        user_rules._write_state(state)
    for q in quarantined:
        if q.kept:
            print(f"  note    {q.file}:{q.rule}  {q.reason}")
        else:
            print(f"  refused {q.file}:{q.rule or '(whole file)'}  {q.reason}" if q.file else f"  refused {q.reason}")
    if samples is not None:
        failed = _samples(samples, fast)
        print(f"  samples: {'all pass' if not failed else f'{len(failed)} failed'}")
        for line in failed:
            print(f"  {line}")
        bad += len(failed)
    return bad


def check(args: list[str]) -> int:
    """`rules check DIR` checks one folder; `rules check` every folder the hooks read. Exit 1 on a refused or slow
    rule, a failed sample, a folder without rule files, and a missing or refused folder of the setting or the
    policy (codex review of block 1: a folder that was gone passed)."""
    taken: set = set()
    if args:
        target = Path(args[0]).expanduser()
        if not target.is_dir():
            print(f"maisecrets rules check: {args[0]} is no folder", file=sys.stderr)
            return 2
        folder = user_rules.rule_folder(target)
        return 1 if _check_folder(str(folder), folder, _samples_file(target, folder), taken, True) else 0
    bad = 0
    for shown, path, source in user_rules.folders(user_rules._config()):
        why = user_rules.refused_folder(path) if source != "own" else ""
        folder = user_rules.rule_folder(path)
        if why or not folder.is_dir():
            print(f"{shown} ({source}): {why or 'missing'}")
            bad += source != "own"     # the own folder rules.d need not exist
            continue
        try:
            bad += _check_folder(f"{shown} ({source})", folder, _samples_file(path, folder), taken, source != "own")
        except OSError:
            print(f"{shown} ({source}): refused: the folder cannot be read")
            bad += 1
    return 1 if bad else 0


def test(args: list[str]) -> int:
    """What the rules find: type, rule id, span and length; never the value."""
    text = " ".join(args) if args else sys.stdin.buffer.read().decode("utf-8", errors="replace")
    found = detect.scan(text)
    if not found:
        print("no finding")
    for m in found:
        print(f"{m.type:<7} {m.kind:<18} at {m.start}-{m.end} (len {len(m.value)})")
    return 0


_README = """# Detection rules for maisecrets

maisecrets reads the rules in `rules/` in addition to its own. To use them, clone this repository and type this as
your own prompt in Claude Code, with the folder you cloned it to:

    /maisecrets:settings rule_dirs add {path}

In Codex, send this alone as your prompt: `maisecrets: set rule_dirs add {path}`

`/maisecrets:rules` then shows the folder and how many rules it loaded.

- `rules/*.json`: rules in the gitleaks form (`id`, `regex`, `keywords`, `entropy`, `secretGroup`, `allowlists`).
- `rules/*.prefixes`: one rule per line, `id  regex`; the whole match is the secret.
- `samples.txt`: `hit <rule-id> <text>` must be found by that rule, `miss <text>` by none.

Check a change before you commit it: `maisecrets rules check .` (the CI files here run the same).

A rule needs a keyword or a literal of 4 characters and at most 300 characters of regex. It must not backtrack: no
repeat inside a repeat, no quantifier at the start, no two repeats in a row that take the same characters. Each rule
is also timed on test texts; a rule slower than 50 ms is left out. A folder holds at most 500 rules, a file at most
64 KB. A rule that fails a check is left out, not the folder.

No names, no customer data and no real values in here. A rule describes a shape; the samples use made-up values.
"""

# The CI files take maisecrets from the newest release (the `release` branch), not from a fixed version: the hooks of
# the team update to the newest release too, so CI checks with the checks that the hooks run. A fixed version
# (`--branch v0.6.N`) makes the CI repeatable; it must be one that has `maisecrets rules check`.
_GITHUB = """name: rules
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # the newest maisecrets release: the same checks the hooks of your team run. For a fixed version, write
      # --branch v0.6.N (a release that has `maisecrets rules check`)
      - run: git clone --depth 1 --branch release https://github.com/Mcpgate-de/maisecrets.git "$RUNNER_TEMP/ms"
      - run: python3 -m maisecrets.cli rules check .
        env:
          PYTHONPATH: ${{ runner.temp }}/ms
          MAISECRETS_HOME: ${{ runner.temp }}/ms-home
"""

_GITLAB = """rules:
  image: python:3.12
  script:
    # the newest maisecrets release: the same checks the hooks of your team run. For a fixed version, write
    # --branch v0.6.N (a release that has `maisecrets rules check`)
    - git clone --depth 1 --branch release https://github.com/Mcpgate-de/maisecrets.git /tmp/ms
    - PYTHONPATH=/tmp/ms MAISECRETS_HOME=/tmp/ms-home python3 -m maisecrets.cli rules check .
"""


def _home_form(path: Path) -> str:
    """The path as a person types it: `~/…` under the home folder."""
    for home in (Path.home(), Path.home().resolve()):
        try:
            return "~/" + path.relative_to(home).as_posix()
        except ValueError:
            continue
    return str(path)


def init(args: list[str]) -> int:
    if len(args) != 1:
        print("maisecrets rules init: give one folder", file=sys.stderr)
        return 2
    top = Path(args[0]).expanduser()
    files = {
        "README.md": _README.format(path=_home_form(top.resolve())),
        "rules/example.json": json.dumps({"rules": [{
            "id": "example-internal-token", "description": "An example: a token of an internal service.",
            "regex": r"exmpl_[A-Za-z0-9]{24}", "keywords": ["exmpl_"], "entropy": 3.0}]}, indent=2) + "\n",
        "rules/example.prefixes": "# id                regex (the whole match is the secret)\n"
                                  "example-build-key   exbk-[0-9a-f]{32}\n",
        # made-up values, built here so that no value is written in this source file
        "samples.txt": ("hit example-internal-token token exmpl_" + "abcdefghijklmnopqrstuvwx" + "\n"
                        "miss exmpl_short\n"
                        "hit example-build-key exbk-" + "0123456789abcdef" * 2 + "\n"),
        ".github/workflows/rules.yml": _GITHUB,
        ".gitlab-ci.yml": _GITLAB,
    }
    there = [name for name in files if (top / name).exists()]
    if there:
        print(f"maisecrets rules init: {', '.join(there)} exist(s) in {top}; nothing was written", file=sys.stderr)
        return 1
    for name, text in files.items():
        path = top / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


# betterleaks writes a pure entropy floor as an Expr filter; that one form is read, every other filter is refused
_ENTROPY_FILTER_RE = re.compile(r'\s*entropy\(\s*finding\["secret"\]\s*\)\s*(?:<|<=)\s*([0-9]+(?:\.[0-9]+)?)\s*')


def convert(cfg: dict) -> tuple[list, list[str]]:
    """The rules of a gitleaks or betterleaks config in the JSON form, and one note per rule or part left out."""
    rules, notes = [], []
    if cfg.get("allowlist") or cfg.get("allowlists"):
        notes.append("the global allowlist is not taken over (a rule folder loosens only its own rules)")
    for r in cfg.get("rules") or []:
        rid = r.get("id", "?")
        if "regex" not in r:
            notes.append(f"refused {rid}: a rule by file path only")
            continue
        out = {"id": rid, "regex": r["regex"]}
        for key in ("description", "keywords", "entropy", "secretGroup"):
            if key in r:
                out[key] = r[key]
        if r.get("filter"):
            m = _ENTROPY_FILTER_RE.fullmatch(r["filter"])
            if not m:
                notes.append(f"refused {rid}: a filter maisecrets cannot read")
                continue
            out["entropy"] = float(m.group(1))
        lists = r.get("allowlists") or ([r["allowlist"]] if isinstance(r.get("allowlist"), dict) else [])
        kept = []
        for al in lists:
            parts = [k for k in ("regexes", "stopwords") if al.get(k)]
            if al.get("condition", "OR").upper() == "AND" and len(parts) + bool(al.get("paths")) > 1:
                notes.append(f"note {rid}: an allowlist with condition AND was dropped (stricter)")
                continue
            if not parts:
                if al.get("paths"):
                    notes.append(f"note {rid}: an allowlist by file path was dropped (stricter)")
                continue
            kept.append({k: al[k] for k in ("regexes", "regexTarget", "stopwords") if al.get(k)})
        if kept:
            out["allowlists"] = kept
        rules.append(out)
    return rules, notes


def import_toml(args: list[str]) -> int:
    if len(args) != 1:
        print("maisecrets rules import: give one .toml file", file=sys.stderr)
        return 2
    try:
        import tomllib
    except ImportError:
        print("maisecrets rules import: needs Python 3.11 or later (tomllib)", file=sys.stderr)
        return 2
    try:
        cfg = tomllib.loads(Path(args[0]).expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"maisecrets rules import: {args[0]} cannot be read ({type(exc).__name__})", file=sys.stderr)
        return 2
    rules, notes = convert(cfg)
    loadable = []
    for r in rules:
        why, _, _ = user_rules.check_regex(r["regex"], tuple(r.get("keywords") or ()))
        if why:
            notes.append(f"refused {r['id']}: {why}")
        else:
            loadable.append(r)
    print(json.dumps({"rules": loadable}, indent=2))
    for note in notes:
        print(note, file=sys.stderr)
    print(f"{len(loadable)} rule(s) converted, {sum(n.startswith('refused') for n in notes)} refused",
          file=sys.stderr)
    return 1 if any(n.startswith("refused") for n in notes) else 0


_LIST_COLUMNS = ("key", "id", "origin", "rank", "channel", "region", "class", "needs", "upstream", "patches")


def _list_row(spec, off: frozenset) -> dict:
    up = spec.upstream
    return {"key": spec.key, "id": spec.id, "origin": spec.origin,
            "rank": ".".join(str(x) for x in spec.priority), "channel": spec.channel, "region": spec.region,
            "class": spec.rule_class, "needs": spec.needs, "upstream": f"{up.source} {up.version}" if up else "",
            "patches": ", ".join(f"{p.field} {p.op}" for p in spec.patches),
            "off": spec.source != "export" and user_rules.switched_off(spec.id, off)}


def list_rules(args: list[str]) -> int:
    """Every rule in scan order with where it comes from (maisecrets/detection/registry.py): the passes outside the
    rule list
    too. A rule that the allow list switches off is marked. Ids, keys and names only: never a regex or a value."""
    if args not in ([], ["--json"]):
        print(USAGE, file=sys.stderr)
        return 2
    off = detect.allow_list()[1]
    specs = [s for s, _ in detect.rule_specs()] + detect.pass_specs()
    rows = [_list_row(s, off) for s in sorted(specs, key=lambda s: s.priority)]
    if args == ["--json"]:
        print(json.dumps(rows, indent=1))
        return 0
    width = {c: max(len(c), *(len(r[c]) for r in rows)) for c in _LIST_COLUMNS[:-1]}
    print("  ".join(c.ljust(width[c]) for c in _LIST_COLUMNS[:-1]) + "  patches")
    for r in rows:
        mark = "  (off: allow list)" if r["off"] else ""
        print("  ".join(r[c].ljust(width[c]) for c in _LIST_COLUMNS[:-1]) + "  " + r["patches"] + mark)
    origins = {}
    for r in rows:
        origins[r["origin"]] = origins.get(r["origin"], 0) + 1
    print(f"{len(rows)} rules: " + ", ".join(f"{n} {o}" for o, n in sorted(origins.items())))
    return 0


def main(args: list[str], scan=None) -> int:
    if not args:
        return show()
    sub, rest = args[0], args[1:]
    if sub == "list":
        return list_rules(rest)
    if sub == "check":
        return check(rest)
    if sub == "test":
        return test(rest)
    if sub == "init":
        return init(rest)
    if sub == "import":
        return import_toml(rest)
    print(USAGE, file=sys.stderr)
    return 2
