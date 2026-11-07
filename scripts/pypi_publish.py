#!/usr/bin/env python3
"""Publish the wheel and the sdist of a release tag to TestPyPI or PyPI with Trusted Publishing, then prove it.

    python3 scripts/pypi_publish.py --index testpypi|pypi DIST

DIST holds the files the job `pypi_build` built once from the release commit, with their SHA256SUMS. This script:

1. checks the files against SHA256SUMS and their version against the tag (CI_COMMIT_TAG);
2. never overwrites: when the index has the version already, it succeeds only if every file there has the same sha256
   as here (a rerun of the same tag), and fails otherwise;
3. exchanges the GitLab OIDC token (TESTPYPI_ID_TOKEN or PYPI_ID_TOKEN, `id_tokens` of the job) for a short-lived
   upload token at the index's mint endpoint; no PyPI token is stored anywhere;
4. uploads with twine (pinned in the job);
5. waits until the index lists the version, compares the sha256 of each published file with the built one, installs
   `maisecrets==<version>` from the index into a fresh venv with --no-deps, and runs a detection there.

It prints no token. Exit 0 when the version is on the index with the built files, 1 otherwise.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

INDEXES = {
    "testpypi": {"host": "https://test.pypi.org", "upload": "https://test.pypi.org/legacy/",
                 "simple": "https://test.pypi.org/simple/", "token_var": "TESTPYPI_ID_TOKEN"},
    "pypi": {"host": "https://pypi.org", "upload": "https://upload.pypi.org/legacy/",
             "simple": "https://pypi.org/simple/", "token_var": "PYPI_ID_TOKEN"},
}
PROJECT = "maisecrets"
# a detection in the installed copy: a value built from parts, so no literal here is a secret
PROBE = ("import maisecrets.detection as d; v = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0' + 'k1L2m3N4o5P6q7R8'; "
         "print(sorted({f.type for f in d.Detector().findings('token: ' + v, channel='tool')}))")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def built_files(dist: Path) -> dict:
    """{file name: sha256} of the wheel and the sdist, checked against SHA256SUMS."""
    sums = {}
    for line in (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        sums[name.strip()] = digest.strip()
    files = {p.name: sha256(p) for p in sorted(dist.iterdir()) if p.suffix in (".whl", ".gz")}
    if sorted(files) != sorted(sums) or any(files[n] != sums[n] for n in files):
        raise SystemExit("the files in dist do not match SHA256SUMS: the build of pypi_build is not what is here")
    if len([n for n in files if n.endswith(".whl")]) != 1 or len([n for n in files if n.endswith(".tar.gz")]) != 1:
        raise SystemExit(f"dist must hold one wheel and one sdist, holds {sorted(files)}")
    return files


def version_of(files: dict) -> str:
    wheel = next(n for n in files if n.endswith(".whl"))
    version = wheel.split("-")[1]
    if f"{PROJECT}-{version}.tar.gz" not in files:
        raise SystemExit(f"the sdist does not carry the version of the wheel ({version}): {sorted(files)}")
    return version


def published(host: str, version: str) -> dict | None:
    """{file name: sha256} of the version on the index, or None when the index does not have it."""
    try:
        with urllib.request.urlopen(f"{host}/pypi/{PROJECT}/{version}/json", timeout=30) as r:
            data = json.load(r)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return {u["filename"]: u["digests"]["sha256"] for u in data.get("urls", [])}


def decide(built: dict, on_index: dict | None) -> str:
    """"upload" (none or a part of the built files is there, each with its built hash: a rerun after a partial upload
    completes it), "done" (all of them are there already) or "conflict" (a file there that is not the built one)."""
    if on_index is None:
        return "upload"
    if any(built.get(name) != digest for name, digest in on_index.items()):
        return "conflict"
    return "done" if on_index == built else "upload"


def mint_token(host: str, id_token: str) -> str:
    req = urllib.request.Request(f"{host}/_/oidc/mint-token", data=json.dumps({"token": id_token}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)["token"]
    except urllib.error.HTTPError as exc:
        # the answer names the reason (no pending publisher, wrong environment …); it holds no token
        raise SystemExit(f"the index refused the OIDC token (HTTP {exc.code}): {exc.read().decode()[:600]}") from None


def wait_listed(host: str, version: str, built: dict, seconds: int = 300) -> None:
    end = time.time() + seconds
    while True:
        try:
            on_index = published(host, version)
        except (urllib.error.URLError, OSError) as exc:   # a 5xx or a dropped connection: ask again
            if time.time() > end:
                raise SystemExit(f"the index did not answer: {exc}") from None
            time.sleep(10)
            continue
        if on_index == built:
            return
        if on_index is not None and set(on_index) == set(built):
            raise SystemExit(f"the index serves other files under {version}: {on_index} != {built}")
        if time.time() > end:
            raise SystemExit(f"the index does not list {version} with the built files after {seconds} s: {on_index}")
        time.sleep(10)


def install_and_probe(simple: str, version: str, built: dict) -> None:
    """A fresh venv installs the version from the index alone; the downloaded wheel is the built one."""
    with tempfile.TemporaryDirectory() as tmp:
        venv, dl = Path(tmp, "venv"), Path(tmp, "dl")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        py = venv / ("Scripts" if os.name == "nt" else "bin") / "python"
        for attempt in range(10):   # the simple index lags the JSON API by a minute at times
            r = subprocess.run([str(py), "-m", "pip", "download", "--no-deps", "--no-cache-dir", "--only-binary",
                                ":all:", "--index-url", simple, "-d", str(dl), f"{PROJECT}=={version}"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                break
            time.sleep(15)
        else:
            raise SystemExit(f"pip download from the index failed: {r.stderr[-600:]}")
        got = {p.name: sha256(p) for p in dl.iterdir()}
        if not got or any(built.get(n) != d for n, d in got.items()):
            raise SystemExit(f"the downloaded file is not the built one: {got}")
        wheel = next(p for p in dl.iterdir() if p.suffix == ".whl")    # the file whose hash was compared
        subprocess.run([str(py), "-m", "pip", "install", "--no-deps", "--no-cache-dir", str(wheel)], check=True,
                       capture_output=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "MAISECRETS"))}
        env["HOME"] = tmp
        out = subprocess.run([str(py), "-I", "-c", PROBE], capture_output=True, text=True, env=env, cwd=tmp)
        if out.returncode or "SECRET" not in out.stdout:
            raise SystemExit(f"the installed copy did not detect the probe: {out.stdout} {out.stderr[-400:]}")
        print(f"installed {PROJECT}=={version} from {simple} in a fresh venv: {', '.join(sorted(got))} "
              f"match the build; the probe found {out.stdout.strip()}")


def main(argv: list) -> int:
    if len(argv) != 3 or argv[0] != "--index" or argv[1] not in INDEXES:
        print(__doc__)
        return 2
    idx, dist = INDEXES[argv[1]], Path(argv[2])
    built = built_files(dist)
    version = version_of(built)
    tag = os.environ.get("CI_COMMIT_TAG", "")
    if tag and tag != f"v{version}":
        raise SystemExit(f"the files carry {version}, the tag is {tag}")
    state = decide(built, published(idx["host"], version))
    if state == "conflict":
        raise SystemExit(f"{argv[1]} has other files under {PROJECT} {version}; a published version is never "
                         "replaced. Release a new version.")
    if state == "upload":
        id_token = os.environ.get(idx["token_var"], "")
        if not id_token:
            raise SystemExit(f"no {idx['token_var']}: the job needs `id_tokens` with the audience of {argv[1]}")
        token = mint_token(idx["host"], id_token)
        env = dict(os.environ, TWINE_USERNAME="__token__", TWINE_PASSWORD=token, TWINE_NON_INTERACTIVE="1")
        on_index = published(idx["host"], version) or {}
        files = [str(dist / n) for n in sorted(built) if n not in on_index]   # never a file name the index has
        r = subprocess.run([sys.executable, "-m", "twine", "upload", "--repository-url", idx["upload"], *files],
                           env=env)
        if r.returncode:
            return 1
        print(f"uploaded {', '.join(sorted(built))} to {argv[1]}")
    else:
        print(f"{argv[1]} has {PROJECT} {version} with the built files already: nothing uploaded")
    wait_listed(idx["host"], version, built)
    install_and_probe(idx["simple"], version, built)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
