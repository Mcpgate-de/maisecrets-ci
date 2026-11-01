#!/usr/bin/env python3
"""Windows and macOS for a merge request, and one green run that serves the release.

GitLab runs the Linux tests. The GitHub Actions matrix (`.github/workflows/ci.yml`, windows-latest
and macos-latest) is the only Windows and macOS CI. Before this script the matrix ran only after a
merge (the release job waits for it on the branch `ci`), so 0.6.17, 0.6.19 and 0.6.22 went red only
after the merge, 0.6.22 in three rounds of about 45 minutes.

Subcommands:

  mr              GitLab merge request job. Builds the commit that main would get (the MR head merged
                  into the current target branch; the head alone on a conflict), pushes it to the
                  branch ci-mr/<iid>-<sha12> of the CI repository, waits for the matrix and names each
                  failing test. Deletes the older ci-mr branches of the same MR and every ci-mr branch
                  older than MAX_AGE_DAYS. Never a force push: each commit gets a new branch name.
  reuse <sha>     Mirror job before a release. Prints the URL of a green push run of the matrix whose
                  commit has exactly the git tree of <sha>, exit 0; exit 1 when there is none. The
                  same tree is the same files, so the run tested what the release ships.
  unit            GitHub side. Runs the unit suite and writes each failing test as an annotation,
                  which the public API serves without a token (the job log needs one).

The CI repository is a separate public repository, not the mirror: the merge request job runs on any
branch, so its deploy key is no protected variable. A key that leaks from there can write only the
CI repository; the mirror's key reaches the install source (main, the tags) and stays protected.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wait_for_github_checks  # noqa: E402

MIRROR_REPO = "Mcpgate-de/maisecrets"
CI_REPO = "Mcpgate-de/maisecrets-ci"
CI_REMOTE = f"ssh://git@github.com/{CI_REPO}.git"
WORKFLOW_PATH = ".github/workflows/ci.yml"
BRANCH_PREFIX = "ci-mr/"
MAX_AGE_DAYS = 14
API = "https://api.github.com"
_TREE = re.compile(r"[0-9a-f]{40}")
_SEP_EQ = "=" * 70
_SEP_DASH = "-" * 70
_HEADER = re.compile(r"^(FAIL|ERROR|UNEXPECTED SUCCESS): (.+)$")
# GitHub shows at most 10 error annotations of one step
MAX_ANNOTATIONS = 10


# ---- pure parts (unit tested) ---------------------------------------------------------------------

def branch_name(iid: int | str, sha: str) -> str:
    """One branch per tested commit: a new commit is a new name, so no push ever needs force."""
    if not re.fullmatch(r"\d+", str(iid)) or not re.fullmatch(r"[0-9a-f]{12,40}", sha):
        raise ValueError(f"no merge request iid or sha: {iid!r} {sha!r}")
    return f"{BRANCH_PREFIX}{iid}-{sha[:12]}"


def branches_to_delete(refs: dict[str, int], iid: int | str, keep: str, now: float,
                       max_age_days: float = MAX_AGE_DAYS) -> list[str]:
    """The ci-mr branches to delete: the other branches of this MR (an older commit of it) and every
    branch whose commit is older than max_age_days (its MR is merged or abandoned).

    refs maps a branch name (without refs/heads/) to its committer time.
    """
    mine = f"{BRANCH_PREFIX}{iid}-"
    out = []
    for name, ctime in sorted(refs.items()):
        if name == keep or not name.startswith(BRANCH_PREFIX):
            continue
        if name.startswith(mine) or now - ctime > max_age_days * 86400:
            out.append(name)
    return out


def reusable_run(tree: str, runs: list[dict], jobs_of) -> dict | None:
    """The newest run that tested exactly this tree on a push and passed every job.

    A push run checks out the pushed commit, so its head_commit tree is what it tested. A
    pull_request run tests GitHub's merge of the PR into its base, another tree: it never counts.
    A run whose jobs were all skipped (the release commit) concludes success too: it counts only
    when every job ran and passed.
    """
    if not isinstance(tree, str) or not _TREE.fullmatch(tree):
        raise ValueError(f"not a full git tree hash: {tree!r}")
    for run in runs:
        head = run.get("head_commit") or {}
        if (run.get("event") != "push" or run.get("status") != "completed"
                or run.get("conclusion") != "success" or run.get("path") != WORKFLOW_PATH
                or head.get("tree_id") != tree):
            continue
        jobs = jobs_of(run)
        if jobs and all(j.get("status") == "completed" and j.get("conclusion") == "success" for j in jobs):
            return run
    return None


def unittest_failures(text: str) -> list[tuple[str, str]]:
    """(test, the exception line of its traceback) for each FAIL/ERROR block of a unittest report."""
    out = []
    blocks = text.split(_SEP_EQ + "\n")
    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines:
            continue
        m = _HEADER.match(lines[0])
        if not m:
            continue
        body = []
        for ln in lines[2:] if len(lines) > 1 and lines[1] == _SEP_DASH else lines[1:]:
            if ln == _SEP_DASH:
                break
            body.append(ln)
        out.append((m.group(2).strip(), _exception_line(body, m.group(1))[:300]))
    return out


def _exception_line(body: list[str], fallback: str) -> str:
    """The exception line of the last traceback: the first unindented line after its frames (the
    lines after it are the message's own continuation, an assertEqual diff for example)."""
    starts = [i for i, ln in enumerate(body) if ln.startswith("Traceback (most recent call last)")]
    for ln in body[starts[-1] + 1:] if starts else body:
        if ln.strip() and not ln.startswith((" ", "\t")):
            return ln.strip()
    return next((ln.strip() for ln in body if ln.strip()), fallback)


def _esc_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def annotations(failures: list[tuple[str, str]], rc: int) -> list[str]:
    """GitHub workflow commands for the failures; the last one lists the rest past the limit."""
    if not failures:
        return [f"::error title=unit tests::the suite exited {rc} without a FAIL or ERROR line (a crash or a "
                "kill); the job log has the end of the output"]
    lines = []
    head = failures if len(failures) <= MAX_ANNOTATIONS else failures[:MAX_ANNOTATIONS - 1]
    for name, reason in head:
        lines.append(f"::error title={_esc_prop(name)}::{_esc_data(reason)}")
    rest = failures[len(head):]
    if rest:
        lines.append(f"::error title={len(rest)} more failing tests::" + _esc_data("\n".join(n for n, _r in rest)))
    return lines


# ---- GitHub API (unauthenticated: public repositories, 60 requests per hour) ----------------------

def _get(url: str, tries: int = 3) -> dict | list:
    last: Exception | None = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "maisecrets-ci"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
            if i + 1 < tries:
                time.sleep(20)
    raise RuntimeError(f"github api {url}: {type(last).__name__}: {last}")


def find_reuse(tree: str, repos: tuple[str, ...] = (CI_REPO, MIRROR_REPO)) -> dict | None:
    """Search the newest 100 green push runs of each repository for this tree."""
    for repo in repos:
        data = _get(f"{API}/repos/{repo}/actions/runs?event=push&status=success&per_page=100")
        run = reusable_run(tree, data.get("workflow_runs", []),
                           lambda r: _get(r["jobs_url"] + "?filter=latest&per_page=100").get("jobs", []))
        if run is not None:
            return run
    return None


def _git(*args: str, check: bool = True) -> str:
    return subprocess.run(["git", *args], check=check, capture_output=True, text=True).stdout.strip()


def tree_of(sha: str) -> str:
    return _git("rev-parse", f"{sha}^{{tree}}")


# ---- subcommands ----------------------------------------------------------------------------------

def cmd_reuse(sha: str) -> int:
    tree = tree_of(sha)
    try:
        run = find_reuse(tree)
    except RuntimeError as e:
        # no answer is no reuse: the release then waits for its own run as before
        print(f"no reuse: {e}", file=sys.stderr)
        return 1
    if run is None:
        print(f"no green run of the matrix on tree {tree[:12]} (commit {sha[:12]})", file=sys.stderr)
        return 1
    print(f"reuse: run {run['html_url']} tested commit {run['head_sha'][:12]} with the same tree {tree[:12]} "
          f"as {sha[:12]}", file=sys.stderr)
    print(run["html_url"])
    return 0


def _report_failures(runs: list[dict]) -> None:
    for c in runs:
        if c.get("status") == "completed" and c.get("conclusion") not in ("success", "skipped"):
            print(f"\n{c['name']}: {c.get('conclusion')}  {c.get('html_url', '')}")
            try:
                notes = _get(f"{API}/repos/{CI_REPO}/check-runs/{c['id']}/annotations")
                job = _get(f"{API}/repos/{CI_REPO}/actions/jobs/{c['id']}")
            except RuntimeError as e:
                print(f"  (no details: {e})")
                continue
            steps = [s["name"] for s in job.get("steps", []) if s.get("conclusion") == "failure"]
            if steps:
                print("  failed step:", ", ".join(steps))
            for a in notes:
                if a.get("annotation_level") != "failure" or a.get("message", "").startswith("Process completed"):
                    continue
                title = a.get("title") or ""
                print(f"  {title}: {a.get('message', '')}" if title else f"  {a.get('message', '')}")


def _merged_commit(head: str, target: str) -> str:
    """The commit main would get: head merged into the target branch tip, or head when it already
    contains the tip. A conflict tests the head alone (GitLab shows the conflict anyway)."""
    _git("fetch", "--quiet", "origin", f"+refs/heads/{target}:refs/remotes/origin/{target}")
    base = _git("rev-parse", f"refs/remotes/origin/{target}")
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head]).returncode == 0:
        print(f"the MR head contains {target} {base[:12]}: testing the head itself")
        return head
    _git("checkout", "--quiet", "--detach", base)
    env = dict(os.environ, GIT_AUTHOR_NAME="maisecrets ci", GIT_AUTHOR_EMAIL="ci@maisecrets.local",
               GIT_COMMITTER_NAME="maisecrets ci", GIT_COMMITTER_EMAIL="ci@maisecrets.local")
    r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "-m",
                        f"ci-mr: {head[:12]} merged into {target} {base[:12]}", head],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        subprocess.run(["git", "merge", "--abort"], capture_output=True)
        print(f"the MR head does not merge cleanly into {target}: testing the head alone")
        return head
    merged = _git("rev-parse", "HEAD")
    print(f"testing {merged[:12]}: the MR head {head[:12]} merged into {target} {base[:12]}")
    return merged


def _cleanup(iid: str, keep: str) -> None:
    out = _git("ls-remote", "--heads", CI_REMOTE, f"refs/heads/{BRANCH_PREFIX}*", check=False)
    names = [ln.split("\trefs/heads/", 1)[1] for ln in out.splitlines() if "\trefs/heads/" in ln]
    if not names:
        return
    _git("fetch", "--quiet", CI_REMOTE, *[f"+refs/heads/{n}:refs/ci-mr-remote/{n}" for n in names], check=False)
    refs = {}
    for n in names:
        t = _git("log", "-1", "--format=%ct", f"refs/ci-mr-remote/{n}", check=False)
        if t.isdigit():
            refs[n] = int(t)
    gone = branches_to_delete(refs, iid, keep, time.time())
    if gone:
        r = subprocess.run(["git", "push", "--quiet", CI_REMOTE, *[f":refs/heads/{n}" for n in gone]],
                           capture_output=True, text=True)
        print(("deleted " if r.returncode == 0 else "could not delete ") + ", ".join(gone))


def cmd_mr() -> int:
    iid = os.environ["CI_MERGE_REQUEST_IID"]
    head = os.environ["CI_COMMIT_SHA"]
    target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
    sha = _merged_commit(head, target)
    tree = tree_of(sha)
    try:
        run = find_reuse(tree)
    except RuntimeError as e:
        print(f"reuse lookup failed ({e}); running the matrix")
        run = None
    if run is not None:
        print(f"the matrix is already green on this tree: {run['html_url']} (commit {run['head_sha'][:12]})")
        return 0
    branch = branch_name(iid, sha)
    r = subprocess.run(["git", "push", "--quiet", CI_REMOTE, f"{sha}:refs/heads/{branch}"], capture_output=True,
                       text=True)
    if r.returncode != 0:
        print(f"push to {CI_REPO} {branch} failed: {r.stderr.strip()}")
        return 1
    print(f"pushed {sha[:12]} to github.com/{CI_REPO} {branch}")
    print(f"runs: https://github.com/{CI_REPO}/actions?query=branch%3A{urllib.parse.quote(branch, safe='')}")
    _cleanup(iid, branch)
    rc, runs = wait_for_github_checks.wait(sha, CI_REPO, float(os.environ.get("MATRIX_TIMEOUT_MIN", "40")),
                                           poll=20)
    if rc != 0:
        _report_failures(runs)
    return rc


def cmd_unit() -> int:
    """The unit suite, one test file per process (scripts/run_tests_parallel.py: the same tests and the same -v
    report, about 4x faster), then one annotation per failing test."""
    cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_tests_parallel.py")]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    chunks = []
    assert p.stdout is not None
    for raw in p.stdout:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        chunks.append(raw.decode("utf-8", "replace").replace("\r\n", "\n"))
    rc = p.wait()
    if rc != 0:
        for line in annotations(unittest_failures("".join(chunks)), rc):
            print(line, flush=True)
    return rc


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "mr":
        return cmd_mr()
    if len(argv) >= 3 and argv[1] == "reuse":
        return cmd_reuse(argv[2])
    if len(argv) >= 2 and argv[1] == "unit":
        return cmd_unit()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
