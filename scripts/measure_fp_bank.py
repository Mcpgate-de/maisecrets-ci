"""The false-alarm bank: seven public trees on fixed commits, measured with scripts/measure_false_alarms.py. A fixed
instrument for a detector change: run it before and after, and compare.

    python3 scripts/measure_fp_bank.py fetch <cache>                  clone each tree at its commit (once)
    python3 scripts/measure_fp_bank.py measure <cache> [--json <out>]  count the hits per tree and rule
    python3 scripts/measure_fp_bank.py compare <before.json> <after.json>

The trees hold no real secrets that we know of; what the detector finds there is a false alarm or a test value of
the project. The output holds no value and no line: per tree and rule, the hits and the hits a Read would act on
(`acted`, after the test-code rule). `compare` prints each rule whose acted count changed. It exits 2 when a tree is
missing on one side or at another commit, 1 when the total of acted hits rose, else 0, so a change that adds false
alarms shows up as a failure. It is a measurement, not a CI gate: the fetch needs the network. The clones are only
read: fetch makes each one new, and measure counts only a clean clone at its commit.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_false_alarms as mfa  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# (commit, name, repository, the subdirectory to measure or ""). The commit comes first, before any word that the
# detector reads as a label. A new commit here is a new baseline: measure both commits on the same detector first.
TREES = (
    ("ebf955df7a89ed0c7968f79faec1de49f61ed7cb", "cpython-Lib", "https://github.com/python/cpython.git", "Lib"),
    ("5e141933554a0b74e7341841f318be21e895339c", "detect-secrets", "https://github.com/Yelp/detect-secrets.git", ""),
    ("e8c6fe2467818e2054c179ce000dc223300c4778", "ferret-scan", "https://github.com/awslabs/ferret-scan.git", ""),
    ("01dbd7710de79e21bef851aaa8b6cbfb4b1188ad", "Preserve", "https://github.com/thirtysix/Preserve.git", ""),
    # Benchmark V1 (docs/BENCHMARK-V1.md): CI files, configuration samples, and shell commands in documentation
    ("e3c451d60f119b71caebf13c98ac45da6e15b4b7", "starter-workflows", "https://github.com/actions/starter-workflows.git",
     ""),
    ("30f4b7f6a6c3b0c0ecf4d4efb0de203c48d11562", "awesome-compose", "https://github.com/docker/awesome-compose.git",
     ""),
    ("481978fcfbac2229ccfe0dca91ce2e7d67d34ebc", "tldr-pages", "https://github.com/tldr-pages/tldr.git",
     "pages/common"),
)


def git(cwd: Path, *args: str) -> str:
    # core.fsmonitor names a command in the repository config; a clone of ours never sets it, and we never run one.
    # No GIT_* of a calling hook: with GIT_DIR or GIT_INDEX_FILE set, git -C <clone> works on the repository of the
    # hook, and an init or a fetch would change it (tests/test_skill.py, 2026-09-27)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True, env=env).stdout.strip()


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def blobs_on_disk(d: Path, sub: str) -> dict:
    """path -> what each entry under the subdirectory can stand for, as `link:<blob>` or `file:<blob>`. A symlink is
    its target. A regular file is its bytes, or its bytes with CRLF read as LF, because a checkout writes a file with
    the attribute eol=crlf that way. The kind counts: the measurement skips a broken symlink and reads a file, so a
    checkout that writes a symlink as a file (core.symlinks=false) is other input."""
    out = {}
    for dp, dn, fn in os.walk(d / sub if sub else d):
        dn[:] = [x for x in dn if not (Path(dp) == d and x == ".git")]
        for f in fn + [x for x in dn if Path(dp, x).is_symlink()]:   # walk lists a link to a directory in dn
            p = Path(dp, f)
            if p.is_symlink():
                kinds = {"link:" + blob_id(os.readlink(p).encode())}
            else:
                data = p.read_bytes()
                kinds = {"file:" + blob_id(data), "file:" + blob_id(data.replace(b"\r\n", b"\n"))}
            out[p.relative_to(d).as_posix()] = kinds
    return out


def blobs_of_commit(d: Path, commit: str, sub: str) -> dict:
    """path -> `link:<blob>` or `file:<blob>` of each entry under the subdirectory in the commit."""
    out = {}
    for entry in git(d, "ls-tree", "-r", "-z", commit, "--", sub or ".").split("\0"):
        if entry:
            meta, path = entry.split("\t", 1)
            mode, kind, blob = meta.split()
            if kind == "blob":
                out[path] = ("link:" if mode == "120000" else "file:") + blob
    return out


def remove_tree(path: Path) -> None:
    """shutil.rmtree that also removes read-only files: git writes its objects read-only, and Windows refuses to delete
    such a file."""
    def writable(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=writable)
    else:
        shutil.rmtree(path, onerror=writable)


def at_commit(d: Path, commit: str, sub: str) -> bool:
    """A clean clone at the commit: HEAD is the commit, and the files under the subdirectory are exactly the files of
    the commit, byte for byte. A tree that is only partly there would give lower counts that look like an
    improvement. The check does not ask the index or `git status`: those can be told to skip a file, and a status may
    write the index, which runs a hook of the repository. rev-parse and ls-tree only read refs and objects."""
    if not (d / ".git").is_dir() or not (d / sub if sub else d).is_dir():
        return False
    if git(d, "rev-parse", "HEAD") != commit:
        return False
    disk, tree = blobs_on_disk(d, sub), blobs_of_commit(d, commit, sub)
    return disk.keys() == tree.keys() and all(tree[p] in disk[p] for p in tree)


def fetch(cache: Path) -> None:
    """A shallow clone of each tree at its commit, with only its subdirectory checked out. Each clone is made in a new
    directory and moved into place when it is complete. In a directory that this script did not make, it only reads
    (rev-parse, ls-tree, see at_commit), so no hook or filter of that repository runs. A clean clone at the commit is
    kept; any other directory with the name stops the fetch and stays as it is."""
    cache.mkdir(parents=True, exist_ok=True)
    for commit, name, url, sub in TREES:
        d = cache / name
        if d.exists():
            if at_commit(d, commit, sub):
                print(f"{name}: at {commit[:8]}")
                continue
            raise SystemExit(f"{name}: {d} is not a clean clone at {commit[:8]}; remove it and fetch again")
        new = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=cache))
        try:
            git(new, "init", "-q")
            git(new, "remote", "add", "origin", url)
            if sub:
                git(new, "sparse-checkout", "set", sub)
            git(new, "fetch", "-q", "--depth", "1", "origin", commit)
            git(new, "checkout", "-q", "--detach", "FETCH_HEAD")
            if not at_commit(new, commit, sub):
                raise SystemExit(f"{name}: the new clone is not a clean tree at {commit[:8]}")
            new.rename(d)
        finally:
            if new.exists():
                remove_tree(new)
        print(f"{name}: fetched {commit[:8]}")


def measure(cache: Path, detect) -> dict:
    """Per tree: its commit, the files and characters read, and per rule key `where|type|rule` the [hits, acted]."""
    out = {"maisecrets": git(ROOT, "rev-parse", "HEAD"), "trees": {}}
    for commit, name, _url, sub in TREES:
        d = cache / name
        if not at_commit(d, commit, sub):
            raise SystemExit(f"{name}: no clean clone at {commit[:8]} in {cache}; run fetch first")
        r = mfa.measure(d / sub if sub else d, detect)
        out["trees"][name] = {
            "commit": commit, "files": r["files"], "chars": r["size"],
            "rules": {"|".join(k): [r["raw"][k], r["acted"][k]] for k in sorted(r["raw"])},
        }
    return out


def totals(tree: dict) -> tuple[int, int, int]:
    """hits, acted, and acted outside test code."""
    rules = tree["rules"]
    return (sum(h for h, _ in rules.values()), sum(a for _, a in rules.values()),
            sum(a for k, (_, a) in rules.items() if k.startswith("other|")))


def report(result: dict) -> None:
    print(f"maisecrets {result['maisecrets'][:8]}")
    print(f"{'tree':16} {'commit':8} {'files':>6} {'MB':>6} {'hits':>6} {'acted':>6} {'acted, not tests':>17}")
    for name, t in result["trees"].items():
        hits, acted, other = totals(t)
        print(f"{name:16} {t['commit'][:8]} {t['files']:6} {t['chars'] / 1e6:6.1f} {hits:6} {acted:6} {other:17}")


def compare(before: dict, after: dict) -> int:
    """Each rule whose acted count changed, per tree. 2 when a tree is missing on one side or at another commit (the
    two runs do not measure the same input), else 1 when the total of acted hits rose, else 0."""
    rose = 0
    apart = []
    for name in sorted(set(before["trees"]) | set(after["trees"])):
        b, a = before["trees"].get(name), after["trees"].get(name)
        if b is None or a is None or b["commit"] != a["commit"]:
            apart.append(name)
            print(f"{name}: not comparable (missing on one side, or at another commit)")
            continue
        for key in sorted(set(b["rules"]) | set(a["rules"])):
            x, y = b["rules"].get(key, [0, 0])[1], a["rules"].get(key, [0, 0])[1]
            if x != y:
                print(f"{name:16} {key:60} {x:6} -> {y:6}")
        rose += totals(a)[1] - totals(b)[1]
    print(f"acted hits, compared trees: {'+' if rose >= 0 else ''}{rose}")
    if apart:
        return 2
    return 1 if rose > 0 else 0


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("fetch", "measure", "compare"):
        print(__doc__.strip())
        return 2
    if argv[0] == "fetch":
        fetch(Path(argv[1]))
        return 0
    if argv[0] == "compare":
        return compare(json.loads(Path(argv[1]).read_text()), json.loads(Path(argv[2]).read_text()))
    result = measure(Path(argv[1]), mfa.load_detect())
    report(result)
    if "--json" in argv:
        Path(argv[argv.index("--json") + 1]).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
