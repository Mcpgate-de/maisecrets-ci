"""Whether Codex runs the hooks of this plugin folder, read from Codex's own config (read only).

Codex runs a plugin hook only while the trust the person gave it matches the hook. Per hook it keeps, in config.toml,
`[hooks.state."<plugin id>:hooks/hooks.json:<event>:<group>:<handler>"]`:
- `trusted_hash`: the hook's declaration (event, matcher, command, timeout; codex-rs hooks/src/engine/discovery.rs);
- `trusted_content_hash`, from Codex 0.164 on: the contents of the whole plugin folder
  (hooks/src/engine/plugin_fingerprint.rs, openai/codex#54619). A new maisecrets version is a new folder, so Codex
  asks again after each update, and until then it lets every prompt and tool call through (measured with
  codex-cli 0.164.0-alpha.4, 2026-10-19).
No hook can say that it does not run, so /maisecrets:status says it. Both hashes are recomputed here; the values
Codex itself gave for a fixture plugin pin the recipe (tests/test_codex_trust.py).
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from pathlib import Path

EVENTS = {"SessionStart": "session_start", "UserPromptSubmit": "user_prompt_submit",
          "PreToolUse": "pre_tool_use", "PostToolUse": "post_tool_use"}
_SKIPPED = ("__pycache__", ".venv")


def declaration_hash(event: str, group: dict, handler: dict, windows: bool) -> str:
    command = (handler.get("commandWindows") or handler["command"]) if windows else handler["command"]
    identity = {"event_name": EVENTS[event],
                "hooks": [{"type": "command", "command": command, "timeout": handler.get("timeout", 600),
                           "async": False}]}
    if group.get("matcher") is not None:
        identity["matcher"] = group["matcher"]
    blob = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def content_hash(root: Path) -> str:
    """The plugin folder as Codex fingerprints it: depth first in byte order of the names, without bytecode,
    virtual environments and package metadata. A symlink makes Codex fail the check, and this raises."""
    h = hashlib.sha256(b"codex-plugin-bundle-v1")
    pending = [root]
    while pending:
        path = pending.pop()
        rel = "" if path == root else path.relative_to(root).as_posix()
        name = path.name if rel else ""
        if name in _SKIPPED or name.endswith(".pyc") or name.endswith(".egg-info"):
            continue
        if os.name == "nt":
            rel = rel.replace("/", "\\")
        encoded = rel.encode("utf-8", "surrogateescape")
        h.update(struct.pack("<Q", len(encoded)))
        h.update(encoded)
        mode = os.lstat(path).st_mode
        if stat.S_ISDIR(mode):
            h.update(b"directory")
            pending.extend(sorted(path.iterdir(), key=lambda p: os.fsencode(p.name), reverse=True))
        elif stat.S_ISREG(mode):
            data = path.read_bytes()
            h.update(b"file")
            h.update(struct.pack("<Q", len(data)))
            h.update(data)
        else:
            raise OSError(f"Codex does not fingerprint {rel}: not a file or a folder")
    return "sha256:" + h.hexdigest()


def _plugin_id(root: Path, codex_home: Path) -> str | None:
    """<plugin>@<marketplace> for a folder Codex installed: <codex home>/plugins/cache/<marketplace>/<plugin>/<v>."""
    try:
        parts = root.resolve().relative_to((codex_home / "plugins" / "cache").resolve()).parts
    except (OSError, ValueError):
        return None
    return f"{parts[1]}@{parts[0]}" if len(parts) == 3 else None


def _legacy_baseline(codex_home: Path, plugin_id: str) -> str | None:
    """The contents an approval from before Codex 0.164 is pinned to, at its first run on 0.164 or newer
    (hooks/src/engine/plugin_trust.rs, legacy_trust_path: the real path of config.toml and the plugin id)."""
    config = os.path.realpath(codex_home / "config.toml")
    h = hashlib.sha256()
    for part in (os.fsencode(config), plugin_id.encode("utf-8")):
        h.update(struct.pack("<Q", len(part)))
        h.update(part)
    try:
        return (Path(config).parent / ".hook-trust" / h.hexdigest()).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _load_toml(path: Path) -> dict | None:
    try:
        import tomllib
    except ImportError:              # Python 3.10 and older
        return None
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, ValueError):
        return None


def status_lines(root: Path, codex_home: Path, windows: bool | None = None) -> list[str]:
    """The lines /maisecrets:status prints for Codex; none for a folder Codex did not install."""
    windows = os.name == "nt" if windows is None else windows
    plugin_id = _plugin_id(root, codex_home)
    if plugin_id is None:
        return []
    cfg = _load_toml(codex_home / "config.toml")
    if cfg is None:
        return ["codex hooks: unknown (needs Python 3.11 or newer to read Codex's config.toml)"]
    out = []
    others = sorted(k for k, v in (cfg.get("plugins") or {}).items()
                    if k.startswith("maisecrets@") and k != plugin_id and (v or {}).get("enabled", True))
    if others:
        out.append(f"codex: another maisecrets is installed too ({', '.join(others)}): remove it with "
                   f"codex plugin remove, so that one version runs the hooks")
    try:
        hooks = json.loads((root / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        # Windows: how Codex spells the paths in its hash is not measured there, so no answer about the contents
        current = None if windows else content_hash(root)
    except (OSError, ValueError, KeyError) as e:
        return out + [f"codex hooks: unknown ({type(e).__name__})"]
    state = (cfg.get("hooks") or {}).get("state") or {}
    baseline = _legacy_baseline(codex_home, plugin_id)
    untrusted = changed = old = unknown = total = 0
    for event, groups in hooks.items():
        if event not in EVENTS:
            continue
        for gi, group in enumerate(groups):
            for hi, handler in enumerate(group.get("hooks", [])):
                total += 1
                entry = state.get(f"{plugin_id}:hooks/hooks.json:{EVENTS[event]}:{gi}:{hi}") or {}
                if entry.get("trusted_hash") != declaration_hash(event, group, handler, windows):
                    untrusted += 1
                elif entry.get("trusted_content_hash") is None and baseline is None:
                    old += 1
                elif current is None:
                    unknown += 1
                elif (entry.get("trusted_content_hash") or baseline) != current:
                    changed += 1
    fix = "open /hooks in Codex and trust the maisecrets entries; until then Codex lets prompts and tool calls through"
    if untrusted:
        out.append(f"codex hooks: {untrusted} of {total} not trusted: {fix}")
    elif changed:
        out.append(f"codex hooks: trusted for other contents of this folder (an update, or a changed file), "
                   f"so Codex 0.164 and newer skip them: {fix}")
    elif unknown:
        out.append("codex hooks: trusted for these hooks; whether Codex 0.164 and newer accept the contents of this "
                   "folder is unknown on Windows (not measured): if a prompt with a secret is not blocked, " + fix)
    elif old:
        out.append("codex hooks: trusted (an approval from before Codex 0.164: after the next maisecrets update, "
                   "Codex 0.164 and newer ask again in /hooks)")
    else:
        out.append(f"codex hooks: trusted ({total} of {total})")
    return out
