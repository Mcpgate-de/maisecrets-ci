#!/usr/bin/env python3
"""Refresh the vendored Presidio pattern recognizers (regexes, scores, context words).

Usage: scripts/sync_presidio.py 2.2.364

Presidio ships its recognizers as Python classes. This script reads them from the source of the
presidio-analyzer wheel as data (scripts/_static_python.py) and executes none of it: the wheel is
downloaded from PyPI, checked against the sha256 PyPI lists, and opened as a zip. The plugin reads
the resulting maisecrets/detection/rules/presidio.json as data.

Checksum validators are NOT exported (they are code); maisecrets/detection/value_checks.py
ports the ones it needs (generic + DE) and marks the rest as "context only".
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static_python import bind  # noqa: E402

PACKAGE = "presidio_analyzer/predefined_recognizers"
BASE = "PatternRecognizer"
MAX_DOWNLOAD = 20_000_000        # the 2.2.364 wheel is about 0.3 MB
MAX_MEMBER = 2_000_000           # one source file of the wheel
UNREADABLE = object()


class Refused(Exception):
    """A form the static reading cannot take as data: the sync stops, Renovate shows it on the MR."""


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise Refused(f"{url}: larger than {MAX_DOWNLOAD} bytes")
    return data


def source(z: zipfile.ZipFile, name: str) -> bytes:
    if z.getinfo(name).file_size > MAX_MEMBER:
        raise Refused(f"{name}: larger than {MAX_MEMBER} bytes")
    return z.read(name)


def wheel(ver: str) -> zipfile.ZipFile:
    meta = json.loads(fetch(f"https://pypi.org/pypi/presidio-analyzer/{ver}/json"))
    files = [u for u in meta["urls"] if u["packagetype"] == "bdist_wheel" and u["filename"].endswith("-none-any.whl")]
    if len(files) != 1:
        sys.exit(f"expected one pure-Python wheel for {ver}, found {len(files)}")
    data = fetch(files[0]["url"])
    if hashlib.sha256(data).hexdigest() != files[0]["digests"]["sha256"]:
        sys.exit("the wheel does not match the sha256 PyPI lists")
    return zipfile.ZipFile(io.BytesIO(data))


def walk(names: set[str], pkg: str) -> list[str]:
    """The module order of pkgutil.walk_packages: a sorted directory listing, a package before its
    modules (the order the vendored JSON had when the recognizers were imported)."""
    prefix = pkg + "/"
    entries = sorted({n[len(prefix):].split("/")[0] for n in names if n.startswith(prefix)})
    order = []
    for fn in entries:
        if fn.endswith(".py") and fn != "__init__.py" and "." not in fn[:-3]:
            order.append(prefix + fn)
        elif "." not in fn and prefix + fn + "/__init__.py" in names:
            order.append(prefix + fn + "/__init__.py")
            order += walk(names, prefix + fn)
    return order


def init_default(cls: ast.ClassDef, arg: str):
    for f in cls.body:
        if isinstance(f, ast.FunctionDef) and f.name == "__init__":
            a = f.args
            pos = a.posonlyargs + a.args
            for p, d in [*zip(pos[len(pos) - len(a.defaults):], a.defaults), *zip(a.kwonlyargs, a.kw_defaults)]:
                if p.arg == arg:
                    return d.value if isinstance(d, ast.Constant) and isinstance(d.value, str) else UNREADABLE
    return None


def shape_ok(patterns, context) -> bool:
    return (isinstance(patterns, list) and bool(patterns)
            and all(isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("regex"), str)
                    and len(p["regex"]) <= 20_000 and isinstance(p.get("score"), (int, float))
                    and not isinstance(p.get("score"), bool) for p in patterns)
            and isinstance(context, list) and all(isinstance(w, str) for w in context))


def main(argv: list[str]) -> int:
    ver = argv[0] if argv else ""
    if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
        print("usage: sync_presidio.py X.Y.Z")
        return 2
    try:
        out = recognizers(wheel(ver))
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    dst = Path(__file__).resolve().parent.parent / "maisecrets" / "detection" / "rules"
    json.dump({"presidio_version": ver, "recognizers": out}, open(dst / "presidio.json", "w"), indent=1)
    (dst / "PRESIDIO_VERSION").write_text(ver + "\n")
    (dst / "LICENSE-presidio").write_bytes(fetch("https://raw.githubusercontent.com/microsoft/presidio/main/LICENSE"))
    print(f"vendored {len(out)} presidio pattern recognizers, version {ver}")
    return 0


def recognizers(z: zipfile.ZipFile) -> list[dict]:
    """Every PatternRecognizer subclass of the package, read as data. A class the reading cannot take
    whole (another base form, two bases, a computed default, a duplicate name, patterns that are no
    literal list) stops the sync: importing the package took it, so skipping it would drop rules."""
    names = set(z.namelist())
    classes: dict[str, tuple[ast.ClassDef, dict]] = {}
    per_module: list[tuple[str, list[str]]] = []
    aliases: dict[str, str] = {}
    for mod in walk(names, PACKAGE):
        tree = ast.parse(source(z, mod))
        for a in tree.body:                          # `PR = PatternRecognizer`, used as a base later
            if isinstance(a, ast.Assign) and isinstance(a.value, ast.Name):
                aliases.update({t.id: a.value.id for t in a.targets if isinstance(t, ast.Name)})
        env: dict = {}
        bind(tree.body, env)
        here = []
        for c in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            body_env = dict(env)
            bind(c.body, body_env, {"Pattern": lambda name, regex, score: {"name": name, "score": score,
                                                                             "regex": regex}})
            if c.name in classes:
                raise Refused(f"two classes named {c.name}")
            classes[c.name] = (c, body_env)
            here.append(c.name)
        per_module.append((mod, sorted(here)))       # inspect.getmembers sorts by name

    def base_names(name: str) -> list[str]:
        named = [b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else "?"
                 for b in classes[name][0].bases]
        return [aliases.get(n, n) for n in named]

    def reaches(name: str, seen=frozenset()) -> bool:
        return name == BASE or (name in classes and name not in seen
                                and any(reaches(b, seen | {name}) for b in base_names(name)))

    def chain(name: str) -> list[str]:
        out = []
        while name in classes:
            out.append(name)
            node = classes[name][0]
            if len(node.bases) != 1 or not isinstance(node.bases[0], ast.Name):
                raise Refused(f"{out[0]}: its bases {base_names(name)} are not one plain name")
            name = base_names(name)[0]
            if name in out:
                raise Refused(f"{out[0]}: a cycle in its bases")
        if name != BASE:
            raise Refused(f"{out[0]}: the bases end at {name}, not {BASE}")
        return out + [BASE]

    def attr(c: list[str], key: str):
        for n in c[:-1]:                              # the nearest class that assigns it in its own body
            node, body_env = classes[n]
            own = {t.id for s in node.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
            own |= {s.target.id for s in node.body if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)}
            if key in own:
                return body_env.get(key)
        return None

    out = []
    for _, here in per_module:
        for name in here:
            if name == BASE or not any(reaches(b) for b in base_names(name)):
                continue
            c = chain(name)
            nodes = [classes[n][0] for n in c[:-1]]
            entity = next((v for v in (init_default(n, "supported_entity") for n in nodes) if v is not None), None)
            language = next((v for v in (init_default(n, "supported_language") for n in nodes) if v is not None),
                            "en")
            patterns, context = attr(c, "PATTERNS"), list(attr(c, "CONTEXT") or [])
            if entity is None or UNREADABLE in (entity, language):
                raise Refused(f"{name}: supported_entity or supported_language has no literal default")
            if not shape_ok(patterns, context):
                raise Refused(f"{name}: PATTERNS or CONTEXT is no literal list of the expected form")
            rid = re.sub(r"(?<!^)(?=[A-Z])", "-", name.replace("Recognizer", "")).lower()
            out.append({
                "id": rid, "class": name, "entity": entity, "language": language,
                "patterns": patterns,
                "context": context,
                "validator": any(isinstance(f, ast.FunctionDef) and f.name == "validate_result"
                                 for n in nodes for f in n.body),
            })
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
