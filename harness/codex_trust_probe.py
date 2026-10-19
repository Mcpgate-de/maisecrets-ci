"""Does maisecrets/codex_trust.py compute the plugin content hash as the real Codex does? (measurement, not a test)

usage: python harness/codex_trust_probe.py <codex binary>
Installs a fixture plugin into a temp CODEX_HOME, asks `codex app-server` for hooks/list (currentHash is
"<declaration>/<contents>") and compares both parts with the recipe here, with the paths spelled with "/" and
with "\\". Exit 0 when the recipe of this platform matches, 1 otherwise. Measured on macOS with codex-cli
0.164.0-alpha.4 (2026-10-19); the Windows answer decides whether /maisecrets:status may say "trusted" there.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from maisecrets import codex_trust  # noqa: E402
from tests.test_codex_trust import FIXTURE  # noqa: E402

FIXTURE_MARKETPLACE = "fxm"


def walk_hash(root: Path, sep: str) -> str:
    h = hashlib.sha256(b"codex-plugin-bundle-v1")
    pending = [root]
    while pending:
        path = pending.pop()
        rel = "" if path == root else path.relative_to(root).as_posix().replace("/", sep)
        name = path.name if rel else ""
        if name in ("__pycache__", ".venv") or name.endswith(".pyc") or name.endswith(".egg-info"):
            continue
        b = rel.encode("utf-8")
        h.update(struct.pack("<Q", len(b)) + b)
        if path.is_dir():
            h.update(b"directory")
            pending.extend(sorted(path.iterdir(), key=lambda p: os.fsencode(p.name), reverse=True))
        else:
            data = path.read_bytes()
            h.update(b"file" + struct.pack("<Q", len(data)) + data)
    return "sha256:" + h.hexdigest()


def main() -> int:
    codex = sys.argv[1]
    work = Path(tempfile.mkdtemp(prefix="codex-trust-probe-"))
    src = work / "src"
    for name, text in FIXTURE.items():
        p = src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    home = work / "codex_home"
    home.mkdir()
    env = dict(os.environ, CODEX_HOME=str(home))
    for cmd in (["plugin", "marketplace", "add", str(src)], ["plugin", "add", "fx@" + FIXTURE_MARKETPLACE]):
        r = subprocess.run([codex, *cmd], env=env, capture_output=True, text=True, timeout=120)
        print("$ codex", " ".join(cmd[:3]), "->", r.returncode, (r.stderr or r.stdout).strip()[:200])
        if r.returncode:
            return 2
    root = next(home.glob("plugins/cache/*/fx/*"))
    p = subprocess.Popen([codex, "app-server"], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, encoding="utf-8")

    def call(i, method, params):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n")
        p.stdin.flush()
        for line in p.stdout:
            m = json.loads(line)
            if m.get("id") == i:
                return m

    call(1, "initialize", {"clientInfo": {"name": "probe", "version": "0"}, "capabilities": {"experimentalApi": True}})
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "initialized"}) + "\n")
    p.stdin.flush()
    r = call(2, "hooks/list", {"cwds": [str(work)]})
    p.terminate()
    hooks = [h for e in r["result"]["data"] for h in e["hooks"]]
    if len(hooks) != 1:
        print("expected one hook, got", hooks)
        return 2
    declaration, contents = hooks[0]["currentHash"].split("/", 1)
    group = json.loads(FIXTURE["hooks/hooks.json"])["hooks"]["UserPromptSubmit"][0]
    mine_decl = codex_trust.declaration_hash("UserPromptSubmit", group, group["hooks"][0], os.name == "nt")
    slash, backslash = walk_hash(root, "/"), walk_hash(root, "\\")
    print("platform:", sys.platform, "codex:", subprocess.run([codex, "--version"], capture_output=True,
                                                              text=True).stdout.strip())
    print("declaration  codex", declaration, "recipe", mine_decl, "match" if declaration == mine_decl else "DIFFER")
    print("contents     codex", contents)
    print("  with '/'  ", slash, "match" if slash == contents else "-")
    print("  with '\\\\'  ", backslash, "match" if backslash == contents else "-")
    print("  codex_trust.content_hash", "match" if codex_trust.content_hash(root) == contents else "DIFFER")
    return 0 if declaration == mine_decl and codex_trust.content_hash(root) == contents else 1


if __name__ == "__main__":
    sys.exit(main())
