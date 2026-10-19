"""Run the worker of an adapter in a new process: a minimal environment, a temp directory that is always removed, an
error that names only the scanner and the exit code (stderr can hold a case value), and output that is checked
before it is scored."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile

from bench.cases import safe_path

KEEP_ENV = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
TIMEOUT = int(os.environ.get("BENCH_TIMEOUT", "7200"))   # seconds for one worker; a hung scanner ends the run

# the installed distributions of the scanner's Python, for the result file (no lock file can be trusted more)
_FREEZE = ("import json, importlib.metadata as m; print(json.dumps(sorted({d.metadata['Name'] + '==' + d.version "
           "for d in m.distributions()})))")


class AdapterError(RuntimeError):
    pass


def minimal_env(home: str, extra: dict | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if k in KEEP_ENV}
    env["HOME"] = home
    env.update(extra or {})
    return env


def installed(python: str) -> list:
    tmp = tempfile.mkdtemp(prefix="bench-freeze-")
    try:
        p = run([python, "-I", "-c", _FREEZE], "inventory", env=minimal_env(tmp), cwd=tmp, timeout=120)
        if p.returncode:
            raise AdapterError(f"the package inventory of {python} failed with exit code {p.returncode}")
        return json.loads(p.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_IDENTITY = ("import json, sys, importlib.metadata as m; d = m.distribution(sys.argv[1]); u = d.read_text("
             "'direct_url.json'); print(json.dumps({'version': d.version, 'python_version': sys.version.split()[0], "
             "'commit': ((json.loads(u) if u else {}).get('vcs_info') or {}).get('commit_id')}))")


def identity(python: str, dist: str, version: str = "", commit: str = "") -> dict:
    """The version of a scanner's distribution, the commit it was installed from (pip's direct_url.json) and the
    Python, read in an isolated process. A pinned version or commit that does not match is an error: a result never
    names a commit it did not check."""
    tmp = tempfile.mkdtemp(prefix="bench-id-")
    try:
        p = run([python, "-I", "-c", _IDENTITY, dist], dist, env=minimal_env(tmp), cwd=tmp, timeout=120)
        if p.returncode:
            raise AdapterError(f"{dist}: not installed in {python} (exit code {p.returncode})")
        got = json.loads(p.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if version and got["version"] != version:
        raise AdapterError(f"{dist}: version {got['version']} installed, {version} pinned")
    if commit and got["commit"] != commit:
        raise AdapterError(f"{dist}: installed from {got['commit'] or 'no commit'}, {commit[:12]} pinned "
                           f"(pip install git+<url>@{commit})")
    return got


def run(cmd: list, name: str, env: dict, cwd: str, timeout: int = 0) -> subprocess.CompletedProcess:
    """subprocess.run in a session of its own: on a timeout the whole process group ends, and the error names only
    the scanner."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=cwd,
                         start_new_session=os.name != "nt")
    try:
        out, err = p.communicate(timeout=timeout or TIMEOUT)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(p.pid, signal.SIGKILL)
        else:
            p.kill()
        p.communicate()
        raise AdapterError(f"{name}: no result after {timeout or TIMEOUT} s (BENCH_TIMEOUT)") from None
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


def check(name: str, cases: list, found: list) -> list:
    """One list per case; each finding (start, end, cls, rule) with int offsets inside the text of its case."""
    if len(found) != len(cases):
        raise AdapterError(f"{name}: {len(found)} results for {len(cases)} cases")
    out = []
    for i, (c, fs) in enumerate(zip(cases, found)):
        row = []
        for f in fs:
            if len(f) != 4 or not all(isinstance(x, int) and not isinstance(x, bool) for x in f[:2]):
                raise AdapterError(f"{name}: case {i}: a finding is not (start, end, class, rule)")
            s, e = f[0], f[1]
            if not 0 <= s < e <= len(c["text"]):
                raise AdapterError(f"{name}: case {i}: a finding outside the text")
            row.append((s, e, str(f[2]), str(f[3])))
        out.append(row)
    return out


def run_worker(name: str, python: str, worker_src: str, cases: list, fields=("text", "path"), argv=(),
               extra_env: dict | None = None):
    """Write the cases, run the worker (`python -I worker.py IN OUT [argv]`), read and check its findings."""
    tmp = tempfile.mkdtemp(prefix=f"bench-{name}-")
    try:
        home = os.path.join(tmp, "home")
        os.mkdir(home)
        inp, out, worker = (os.path.join(tmp, n) for n in ("in.jsonl", "out.jsonl", "worker.py"))
        with open(worker, "w", encoding="utf-8") as f:
            f.write(worker_src)
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                if not safe_path(c.get("path")):
                    raise AdapterError(f"{name}: a case path is absolute or leaves its folder")
                f.write(json.dumps({k: c.get(k) for k in fields}) + "\n")
        p = run([python, "-I", worker, inp, out, *argv], name, env=minimal_env(home, extra_env), cwd=tmp)
        if p.returncode:
            raise AdapterError(f"{name}: the worker failed with exit code {p.returncode} (its stderr is not shown: "
                               f"it can hold a case value)")
        timing = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            found = [json.loads(line) for line in f]
        return check(name, cases, found), timing
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
