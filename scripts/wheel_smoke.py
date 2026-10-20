#!/usr/bin/env python3
"""Build the detection core as a wheel, install it into a fresh venv and use it from there (docs/DETECTION.md).

    python3 scripts/wheel_smoke.py [--python PY] [--wheel FILE]

Without --wheel it builds one with `pip wheel` (pip fetches the pinned hatchling of pyproject.toml). --python picks the
interpreter of the venv, default this one; run it once with the oldest supported Python too. The installed copy runs
outside the checkout, with -I and an empty HOME, and must:

- carry the plugin's version and every file of maisecrets/detection/ (the code and the rule data), and no other module;
- find a token and an SSN with an explicit Detector, and with one built from defaults, and the value of a rule
  of your own made with user_rule;
- load no module of the plugin and leave the empty HOME empty, so a library caller never reads a user's config.

It prints one line per check and exits 1 when one fails. It changes nothing in the checkout."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "maisecrets" / "detection"

# runs in the venv: no value here is real, the parts are joined at run time
PROBE = r'''
import json, os, sys
from importlib import metadata
from pathlib import Path
import maisecrets.detection as det
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES, Sources, user_rule

text = "SSN " + "-".join(("536", "22", "8726")) + "\ntoken " + "ghp_" + "A1b2C3d4" * 4 + "Zz9y"
given = Detector(regions=Active(regions=("generic", "us"), languages=("en",), source="lib"),
                 sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="lib", year=2030))
defaults = Detector(regions=Active(regions=("generic", "us"), languages=("en",), source="lib"))
class Mine(Sources):
    def user_rules(self):
        return [user_rule("order-ref", "SECRET", r"ORD-(\d{6})", secret_group=1)]
own = Detector(regions=Active(regions=("generic",), languages=("en",), source="lib"), sources=Mine(),
               references=NO_REFERENCES, host=Host(user="lib", year=2030))
pkg = Path(det.__file__).parent
print(json.dumps({
    "version": metadata.version("maisecrets"),
    "files": sorted(p.relative_to(pkg).as_posix() for p in pkg.rglob("*") if p.is_file()
                    and "__pycache__" not in p.parts),
    "top": sorted(p.name for p in pkg.parent.iterdir() if p.name != "__pycache__"),
    "given": sorted(m.type for m in given.findings(text, channel="tool")),
    "defaults": sorted(m.type for m in defaults.findings(text, channel="tool")),
    "modules": sorted(m for m in sys.modules if m.startswith("maisecrets")),
    "home": sorted(os.listdir(os.environ["HOME"])),
    "own": [(m.kind, m.value) for m in own.findings("ref ORD-" + "123456", channel="tool")],
}))
'''


def _run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600, **kw)


def main(argv) -> int:
    py = argv[argv.index("--python") + 1] if "--python" in argv else sys.executable
    wheel = Path(argv[argv.index("--wheel") + 1]).resolve() if "--wheel" in argv else None
    expected_version = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]
    expected_files = sorted(p.relative_to(CORE).as_posix() for p in CORE.rglob("*")
                            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
    with tempfile.TemporaryDirectory(prefix="ms-lib-") as tmp:
        tmp = Path(tmp)
        if wheel is None:
            r = _run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(tmp / "dist"), str(ROOT)])
            if r.returncode:
                print("FAIL build:", r.stderr.strip()[-2000:])
                return 1
            wheel = next((tmp / "dist").glob("maisecrets-*.whl"))
        print("wheel:", wheel.name)
        r = _run([py, "-m", "venv", str(tmp / "venv")])
        vpy = tmp / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        r = r if r.returncode else _run([str(vpy), "-m", "pip", "install", "-q", "--no-index", "--no-deps", str(wheel)])
        if r.returncode:
            print("FAIL install:", r.stderr.strip()[-2000:])
            return 1
        home = tmp / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS", "PYTHON"))}
        env.update(HOME=str(home), USERPROFILE=str(home))
        r = _run([str(vpy), "-I", "-c", PROBE], cwd=str(home), env=env)
        if r.returncode:
            print("FAIL probe:", r.stderr.strip()[-2000:])
            return 1
        got = json.loads(r.stdout)
    checks = [
        ("version is the plugin's", got["version"] == expected_version, f"{got['version']} vs {expected_version}"),
        ("every file of the core and its rule data", got["files"] == expected_files,
         f"missing {sorted(set(expected_files) - set(got['files']))[:5]}, "
         f"extra {sorted(set(got['files']) - set(expected_files))[:5]}"),
        ("no module of the plugin in the package", got["top"] == ["__init__.py", "detection"], str(got["top"])),
        ("explicit detector finds the token and the SSN", got["given"] == ["SECRET", "US_SSN"], str(got["given"])),
        ("detector from defaults finds the same", got["defaults"] == got["given"], str(got["defaults"])),
        ("no plugin module loaded", all(m == "maisecrets" or m.startswith("maisecrets.detection")
                                        for m in got["modules"]), str(got["modules"])),
        ("the empty HOME stays empty", got["home"] == [], str(got["home"])),
        ("a rule of your own through user_rule", got["own"] == [["user:order-ref", "123456"]], str(got["own"])),
    ]
    for name, ok, detail in checks:
        print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f": {detail}"))
    return 0 if all(ok for _, ok, _ in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
