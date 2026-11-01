"""The secret of the name service maisecrets starts itself (#1699): `run.sh ner start` makes it, gives it to the
container as NER_CLIENT_SECRET, and keeps it here; the remote detector then asks that container to prove it before
each text (RemoteDetector(secret=...)).

The secret lives in the store's backend (the keychain, the Credential Locker, or the store file), under a fixed name
per endpoint, never in config.json and never in the index, as the store's own fingerprint key does. The id of the
container that got it is no secret and lies in ner-containers.json beside the index: when that container is gone, the
person learns the one command that makes a new one, and the secret is never dropped silently (an attacker who stops
the container must not turn the check off).

Without a stored secret there is no check: a container the person started by hand keeps working, its identity
unknown, as before #1699."""
from __future__ import annotations

import json
import secrets
from urllib.parse import urlsplit

PREFIX = "_maisecrets_ner_secret_"


def endpoint(url: str) -> str:
    """host:port of a service URL, the name the secret is kept under; "" for anything else."""
    p = urlsplit(str(url))
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return ""
    return f"{p.hostname}:{port}" if p.scheme in ("http", "https") and p.hostname else ""


def _entry(ep: str) -> str:
    return PREFIX + ep.replace(":", "_")


def _containers_path():
    from .vault import HOME
    return HOME / "ner-containers.json"


def _containers() -> dict:
    try:
        data = json.loads(_containers_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def keep(backend, ep: str, secret: str, container: str) -> None:
    """Store the secret of `ep` and the id of the container that got it."""
    from .home import atomic_write
    backend.put(_entry(ep), secret, label=f"maisecrets name service {ep}",
                comment="maisecrets: the secret of the name service it started (NER_CLIENT_SECRET); not a placeholder "
                        "value.")
    data = _containers()
    data[ep] = {"container": str(container)}
    atomic_write(_containers_path(), json.dumps(data, indent=1) + "\n")


def secret_of(backend, ep: str) -> str:
    """The stored secret of `ep`, or ""."""
    try:
        return backend.get(_entry(ep)) or ""
    except Exception:  # noqa: BLE001 - a store that cannot be read: no check, as without a secret
        return ""


def container_of(ep: str) -> str:
    entry = _containers().get(ep)
    return str(entry.get("container", "")) if isinstance(entry, dict) else ""
