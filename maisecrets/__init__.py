"""maisecrets: keep secrets and PII out of cloud models, locally."""


def __getattr__(name: str):
    # __version__ on first use only: a hook imports this package on every call and must not pay for the lookup
    if name != "__version__":
        raise AttributeError(f"module 'maisecrets' has no attribute {name!r}")
    import json
    from pathlib import Path
    manifest = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"   # the plugin and a checkout
    try:
        return json.loads(manifest.read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("maisecrets")                                                     # the installed wheel
    except (ImportError, PackageNotFoundError):
        return "unknown"
