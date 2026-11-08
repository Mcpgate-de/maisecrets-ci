#!/usr/bin/env python3
"""Open the merge request on the website repository that shows a new release (mcpgate/mcpgate.de).

The website keeps the current release in one data file (src/data/maisecretsRelease.ts): its version and date.
Without this job the start page stayed at 0.8.20 for eight releases. The tag pipeline runs this after the tag is
verified and mirrored:

    python3 scripts/notify_website.py

It reads the version from CI_COMMIT_TAG and the date from this release's section of CHANGELOG.md, writes
the data file in a clone of the website, and pushes the branch chore/maisecrets-<version> with the push options that
open a merge request into main, merged when its pipeline succeeds. The push uses the write deploy key of the website
(MAISECRETS_WEBSITE_DEPLOY_KEY, a protected file variable); main there is protected, so a change reaches it only
through that merge request and its pipeline. Without the key (a fork) it says so and exits 0. A data file that has the
version already, or a branch of it that is open, is no error: nothing is pushed.
"""
from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "git@gitlab.com:mcpgate/mcpgate.de.git"
DATA = "src/data/maisecretsRelease.ts"
# the sections a user reads; API lines are for library callers, the docs have them
USER_SECTIONS = ("Breaking", "Features", "Fixes", "Security", "Performance", "Dependencies", "Reverts")


def release_section(changelog: str, version: str) -> tuple[str, list[str]]:
    """(date, the points for a user) of `## [version] - date` in CHANGELOG.md."""
    m = re.search(rf"^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})\n(.*?)(?=^## |\Z)", changelog,
                  re.M | re.S)
    if not m:
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    points, section = [], ""
    for line in m.group(2).splitlines():
        head = re.match(r"^### (.+)$", line)
        if head:
            section = head.group(1).strip()
        elif line.startswith("- ") and section in USER_SECTIONS:
            text = re.sub(r"\s*\([0-9a-f]{7,40}\)\s*$", "", line[2:]).strip()
            if text:
                # a word starts with a capital; a name of code (leaves.label, /maisecrets:ner) stays as it is
                first = text.split(" ", 1)[0]
                text = text[0].upper() + text[1:] if first.isalpha() and first.islower() else text
                points.append(text + ("" if text.endswith((".", "!", "?")) else "."))
    return m.group(1), points


def _q(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def rewrite(data: str, version: str, date: str) -> str:
    """The data file with msRelease of this release; every other line as it was. The notes stay in the changelog: the
    page under Install names the version and links the changelog (the maintainer, after 0.9.0 listed ten points
    there)."""
    release = f"export const msRelease: MsVersion = {{ version: {_q(version)}, date: {_q(date)} }};"
    new, n = re.subn(r"^export const msRelease: MsVersion = \{[^}]*\};$", lambda _m: release, data, flags=re.M)
    if n != 1:
        raise SystemExit(f"{DATA}: msRelease not found once")
    return new


def current_version(data: str) -> str | None:
    m = re.search(r"^export const msRelease: MsVersion = \{ version: '([^']+)'", data, re.M)
    return m.group(1) if m else None


def _git(cwd, *args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)


def main() -> int:
    key = os.environ.get("MAISECRETS_WEBSITE_DEPLOY_KEY", "")
    tag = os.environ.get("CI_COMMIT_TAG", "")
    if not key or not Path(key).is_file() or not Path(key).stat().st_size:
        print("no website deploy key (MAISECRETS_WEBSITE_DEPLOY_KEY): the website is not told (a fork)")
        return 0
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise SystemExit(f"not a release tag: {tag!r}")
    version = tag[1:]
    date, _points = release_section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    known = ROOT / ".ci-known-hosts-gitlab"
    # GitLab writes a file variable with mode 0644, and ssh ignores a private key that others can read
    keydir = tempfile.mkdtemp()
    atexit.register(shutil.rmtree, keydir, True)
    private = Path(keydir) / "deploy_key"
    private.write_bytes(Path(key).read_bytes())
    private.chmod(0o600)
    key = str(private)
    env = dict(os.environ, GIT_SSH_COMMAND=f"ssh -i {key} -o IdentitiesOnly=yes -o UserKnownHostsFile={known} "
                                           "-o StrictHostKeyChecking=yes",
               GIT_AUTHOR_NAME="maisecrets release", GIT_AUTHOR_EMAIL="release@maisecrets.invalid",
               GIT_COMMITTER_NAME="maisecrets release", GIT_COMMITTER_EMAIL="release@maisecrets.invalid")
    branch = f"chore/maisecrets-{version}"
    with tempfile.TemporaryDirectory() as tmp:
        r = _git(tmp, "clone", "--quiet", "--depth", "1", REPO, "site", env=env)
        if r.returncode:
            raise SystemExit(f"clone of the website failed: {r.stderr.strip()[-300:]}")
        site = Path(tmp) / "site"
        if _git(site, "ls-remote", "--exit-code", "--heads", "origin", branch, env=env).returncode == 0:
            print(f"{branch} is open on the website already: nothing pushed")
            return 0
        path = site / DATA
        data = path.read_text(encoding="utf-8")
        if current_version(data) == version:
            print(f"the website shows {version} already: nothing pushed")
            return 0
        path.write_text(rewrite(data, version, date), encoding="utf-8")
        for args in (("checkout", "-q", "-b", branch), ("add", DATA),
                     ("commit", "-q", "-m", f"chore(maisecrets): the site shows release {version}",
                      "-m", f"Opened by the tag pipeline of maisecrets {tag}.")):
            r = _git(site, *args, env=env)
            if r.returncode:
                raise SystemExit(f"git {args[0]} failed: {r.stderr.strip()[-300:]}")
        r = _git(site, "push", "--quiet", "origin", f"{branch}:refs/heads/{branch}",
                 "-o", "merge_request.create", "-o", "merge_request.target=main",
                 "-o", "merge_request.merge_when_pipeline_succeeds", "-o", "merge_request.remove_source_branch",
                 "-o", f"merge_request.title=chore(maisecrets): the site shows release {version}", env=env)
        if r.returncode:
            raise SystemExit(f"push to the website failed: {r.stderr.strip()[-300:]}")
        print(f"website: {branch} pushed, merge request into main opened, merged when its pipeline succeeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
