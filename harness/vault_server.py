"""A fake MCP server for vault references (docs/PROTOCOL.md section 4): metadata, resolve, token and a small MCP.

It plays the server side of the contract so that the client side can be tested without a real server:

- `GET /.well-known/oauth-protected-resource/mcp` names `client_vault_endpoint` (RFC 9728 metadata).
- `POST /vault/resolve` takes `Authorization: Bearer <K>` and answers with all values or one error code.
- `POST /token` binds the kid of a `Client-Vault` header, active at once (the login path).
- `POST /mcp` speaks enough JSON-RPC for one tool, `customers`, whose result carries server-range tokens; a kid
  that arrives here and is not bound becomes pending (the path of an existing login).

Every request is recorded in `server.log` (method, path, header names and the Client-Vault value). `server.mode`
switches a fault on: redirect, sleep, rate_limited, disabled, wrong_type, too_big, not_text, missing_key.
`activate()` plays the person on the server's connections page (pending to active); `quarantine()` plays a second
account that brought the same kid (the kid answers `401 unknown_key` for good).
Standard library and the openssl command only. Run alone for a manual test:

    python3 harness/vault_server.py      # prints the URL and the CA file
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPEN, CLOSE = "⟦", "⟧"


def make_cert(folder: str) -> tuple[str, str]:
    """A test CA and a certificate for 127.0.0.1 and localhost signed by it: (cert file, key file). The cert file holds
    the leaf and then the CA, so it is both the server's chain and the CA file of a client. Codex (rustls) refuses a
    self-signed CA certificate as the server's own certificate, and Python 3.13+ needs the key identifiers."""
    cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    ca, ca_key = os.path.join(folder, "ca.pem"), os.path.join(folder, "ca-key.pem")
    csr, ext = os.path.join(folder, "leaf.csr"), os.path.join(folder, "leaf.ext")
    leaf = os.path.join(folder, "leaf.pem")

    def run(*args: str) -> None:
        subprocess.run(list(args), check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=maisecrets test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", ca_key, "-out", ca)
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", key, "-out", csr)
    with open(ext, "w") as f:
        f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    run("openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
        "-extfile", ext, "-out", leaf)
    with open(cert, "w") as f, open(leaf) as a, open(ca) as b:
        f.write(a.read() + b.read())
    return cert, key


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> float:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def kid_from_header(value: str) -> str | None:
    """The kid of `v=1, kid=:<base64>:`, or None."""
    parts = dict(p.strip().split("=", 1) for p in value.split(",") if "=" in p)
    kid = parts.get("kid", "")
    if parts.get("v") != "1" or len(kid) < 3 or kid[0] != ":" or kid[-1] != ":":
        return None
    try:
        return kid[1:-1] if len(base64.b64decode(kid[1:-1], validate=True)) == 32 else None
    except ValueError:
        return None


class _QuietServer(ThreadingHTTPServer):
    """A client that closes before it reads the answer is no fault of the server: a test of a timeout or a size limit
    closes on purpose. socketserver printed a traceback for each one (BrokenPipeError, or an SSLError on the TLS
    socket), and the noise hid the real failures of a CI log (2026-10-16). Any other error is printed as before."""

    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


class VaultServer:
    def __init__(self, folder: str | None = None, cert: tuple[str, str] | None = None) -> None:
        self.folder = folder or tempfile.mkdtemp(prefix="vault-server-")
        self.cert, self.key = cert or make_cert(self.folder)
        self.log: list[dict] = []
        self.bindings: dict[str, dict] = {}      # kid -> {"state": "active" | "pending", "activates_at": iso}
        self.values: dict[str, tuple[str, float]] = {}   # key -> (value, minted_at)
        self.mode: str | None = None
        self.sleep = 0.0
        self.redirect_to = ""
        self.metadata: dict | None = None        # None: the default metadata; {}: no field
        self.clock_offset = 0.0                  # the server's clock against the real one
        self.resolved: list[dict] = []           # what the resolve endpoint released
        self.meta_status = 200                   # another status: the metadata endpoint fails (a deploy)
        self.auto_bind = False                   # True: a new kid on /mcp is active at once (as after a login)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:
                pass

            def _send(self, status: int, body: object, ctype: str = "application/json", extra: dict | None = None):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _record(self) -> None:
                server.log.append({"method": self.command, "path": self.path, "headers": sorted(self.headers.keys()),
                                   "client_vault": self.headers.get("Client-Vault")})

            def do_GET(self) -> None:
                self._record()
                if self.path == "/.well-known/oauth-protected-resource/mcp" and server.meta_status != 200:
                    return self._send(server.meta_status, {"error": "unavailable"})
                if self.path == "/.well-known/oauth-protected-resource/mcp":
                    meta = {"resource": server.url + "/mcp", "authorization_servers": [server.url]}
                    meta.update({"client_vault_endpoint": server.url + "/vault/resolve"}
                                if server.metadata is None else server.metadata)
                    return self._send(200, meta)
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                self._record()
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                header = self.headers.get("Client-Vault")
                if self.path == "/token":
                    kid = kid_from_header(header or "")
                    if kid and server.bindings.get(kid, {}).get("state") != "quarantined":   # it never binds again
                        server.bindings[kid] = {"state": "active"}
                    return self._send(200, {"access_token": "fake", "token_type": "Bearer"})
                if self.path == "/mcp":
                    kid = kid_from_header(header or "")
                    if kid and kid not in server.bindings:
                        server.bindings[kid] = ({"state": "active"} if server.auto_bind else
                                                {"state": "pending", "activates_at": _iso(time.time() + 86400)})
                    return self._mcp(json.loads(raw or b"{}"))
                if self.path == "/vault/resolve":
                    return self._resolve(raw)
                self._send(404, {"error": "not_found"})

            def _mcp(self, msg: dict) -> None:
                method, ident = msg.get("method"), msg.get("id")
                if ident is None:
                    self.send_response(202)
                    self.end_headers()
                    return
                if method == "initialize":
                    result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                              "capabilities": {"tools": {}}, "serverInfo": {"name": "vault-demo", "version": "1"}}
                elif method == "tools/list":
                    result = {"tools": [{"name": "customers", "description": "List the customers.",
                                         "inputSchema": {"type": "object", "properties": {}}}]}
                elif method == "tools/call":
                    text = "\n".join(f"{OPEN}{k}:{v[0][:2]}•••{CLOSE}" for k, v in server.values.items())
                    result = {"content": [{"type": "text", "text": "customers:\n" + text}]}
                else:
                    result = {}
                self._send(200, {"jsonrpc": "2.0", "id": ident, "result": result})

            def _resolve(self, raw: bytes) -> None:
                if server.sleep:
                    time.sleep(server.sleep)
                mode = server.mode
                if mode == "drip":
                    # one header line every 2 s: each read is short, the whole answer is not
                    self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                    for i in range(10):
                        self.wfile.flush()
                        time.sleep(2)
                        self.wfile.write(f"X-Drip-{i}: x\r\n".encode())
                    return
                if mode == "redirect":
                    return self._send(302, b"", "text/plain", {"Location": server.redirect_to})
                if mode == "rate_limited":
                    return self._send(429, {"error": "rate_limited"}, extra={"Retry-After": "30"})
                if mode == "audit_unavailable":
                    return self._send(503, {"error": "audit_unavailable"})
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return self._send(401, {"error": "unknown_key"})
                token = auth[len("Bearer "):]
                try:
                    k = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
                except ValueError:
                    return self._send(401, {"error": "unknown_key"})
                kid = base64.b64encode(hashlib.sha256(k).digest()).decode()
                binding = server.bindings.get(kid)
                # the order of the contract (SPEC 8.4): the key, then the switch, then the state of the binding. A
                # quarantined kid answers as an unknown one: a client cannot tell it from a revoke
                if len(k) != 32 or not binding or binding["state"] == "quarantined":
                    return self._send(401, {"error": "unknown_key"})
                if mode == "disabled":
                    return self._send(503, {"error": "disabled"})
                if binding["state"] == "pending":
                    return self._send(403, {"error": "pending", "activates_at": binding["activates_at"]})
                body = json.loads(raw)
                now = time.time() + server.clock_offset
                skew = now - _parse(body["now"])
                if abs(skew) > 300:
                    return self._send(403, {"error": "clock_skew"})
                values = {}
                for ref in body["refs"]:
                    if ref["key"] not in server.values:
                        return self._send(404, {"error": "unknown_ref"})
                    value, minted = server.values[ref["key"]]
                    if minted > _parse(ref["seen_at"]) + skew:
                        return self._send(410, {"error": "expired"})
                    values[ref["key"]] = value
                server.resolved.append(values)
                if mode == "wrong_type":
                    return self._send(200, {"values": values}, "text/plain")
                if mode == "too_big":
                    return self._send(200, {"values": values, "pad": "x" * (1024 * 1024 + 10)})
                if mode == "not_text":
                    return self._send(200, {"values": {k: 1 for k in values}})
                if mode == "missing_key":
                    return self._send(200, {"values": dict(list(values.items())[1:])})
                self._send(200, {"values": values})

        self.httpd = _QuietServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "VaultServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def quarantine(self) -> None:
        """Every bound kid is quarantined, as when a second account brought it (SPEC 6.4): it never resolves again."""
        for kid in self.bindings:
            self.bindings[kid] = {"state": "quarantined"}

    def activate(self) -> None:
        """The person activates every pending binding on the connections page of the server (SPEC 6.7)."""
        for kid, b in self.bindings.items():
            if b["state"] == "pending":
                self.bindings[kid] = {"state": "active"}

    def mint(self, key: str, value: str, minted_at: float | None = None) -> str:
        """Put a value into the server's map; returns the token the server sends in its results."""
        self.values[key] = (value, time.time() - 60 if minted_at is None else minted_at)
        return f"{OPEN}{key}{CLOSE}"


if __name__ == "__main__":
    with VaultServer() as s:
        s.mint("EMAIL_1", "someone@example.org")
        print(f"MCP URL: {s.url}/mcp\nCA file: {s.cert}\nCtrl-C ends it.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
