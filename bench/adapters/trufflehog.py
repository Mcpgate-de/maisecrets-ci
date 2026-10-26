"""The trufflehog adapter (trufflesecurity/trufflehog, AGPL-3.0, run as a separate program): the release binary that
BENCH_TRUFFLEHOG names, pinned by version.

`trufflehog filesystem` scans the folder of case files once with all detectors of the release, `--no-verification`
(no detector calls its service), `--no-update`, and every result kind (verified, unverified, unknown), offline
(bench/adapters/_filescan.py). A finding is the `Raw` value of a result at its line, else `RawV2`; a value that is not
in the text (a decoded one) is left out. Its detectors find secrets, so its scope is `secret.`."""
from __future__ import annotations

import json

from bench.adapters import _filescan

NAME = "trufflehog"
SCOPE = ("secret.",)
VERSION = "3.99.2"
ENV = "BENCH_TRUFFLEHOG"


def describe() -> dict:
    path = _filescan.binary(ENV, NAME)
    got = _filescan.version_of(path, ["--version"], NAME)
    _filescan.check_version(got, VERSION, NAME)
    return {"scanner": NAME, "version": VERSION, "commit": None, "binary": path,
            "binary_sha256": _filescan.sha256_file(path),
            "configuration": "filesystem over the folder of case files, --no-verification --no-update "
                             "--results=verified,unverified,unknown --concurrency 4",
            "detectors": "all detectors of the release", "network": False,
            "network_guard": _filescan.network_guard(), "region": "none", "scope": list(SCOPE)}


def scan(cases):
    path = _filescan.binary(ENV, NAME)
    r = _filescan.Run(NAME, cases)
    try:
        p = r.run([path, "filesystem", _filescan.CASE_DIR, "--json", "--no-verification", "--no-update",
                   "--results=verified,unverified,unknown", "--concurrency", "4", "--no-color"])
        for line in p.stdout.splitlines():
            if not line.startswith("{"):
                continue
            x = json.loads(line)
            fs = ((x.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
            if not fs.get("file"):
                continue
            n = _filescan.case_of(r.files, r.tmp, fs["file"])
            text = r.cases[n]["text"] if n is not None else ""
            raw, raw2 = x.get("Raw") or "", x.get("RawV2") or ""
            value = raw if raw and raw in text else raw2 if raw2 and raw2 in text else raw
            r.add(fs["file"], value, fs.get("line"), x.get("DetectorName", ""))
        return r.finish("trufflehog filesystem, one run over all cases")
    finally:
        r.close()
