"""A fake gateway for Sensitive References (ai-gateway docs/security/sensitive-references-1576/
16-resolver-client-contract.md): the resolver side, so that maisecrets/sref_client.py can be tested without a gateway.

- `GET /.well-known/oauth-protected-resource/mcp`: the `sensitive_references` block (resolve endpoint, scope, sink
  profiles local-file-1 and mcpgate-process-1).
- `GET /.well-known/oauth-authorization-server`: the authorize, token and registration endpoints.
- `POST /register` (RFC 7591): a client id for a loopback redirect only.
- `GET /auth/authorize`: PKCE S256 required, scope `sensitive-references.resolve`; the person's consent is given at
  once (`consent = True`) and the answer redirects to the loopback with `code` and `state`.
- `POST /auth/token`: the code (with its verifier) or a refresh token for an access token of one hour and a refresh
  token that rotates on each use.
- `POST /sensitive-references/resolve`: all values or one error with counts (`unresolvable` 409, `quota_exceeded`
  429, `ineligible_sink` 403, `invalid_token` 401), as the contract says.

`mint(kind, value)` makes a canonical reference; `revoke(ref)` withdraws one; `withdraw()` ends the consent, so every
token dies. Every resolve is recorded in `resolved` (sink type, destination, count; never a value). Standard library
and the openssl command (harness/vault_server.py makes the certificate).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlsplit

from vault_server import _QuietServer, make_cert

PROCESS_SCOPE = "sensitive-references.resolve.process"
SINK_PROFILES = {"local_file": "local-file-1", "process": "mcpgate-process-1"}


class SrefServer:
    def __init__(self, folder: str | None = None, cert: tuple | None = None) -> None:
        self.folder = folder or tempfile.mkdtemp(prefix="sref-server-")
        self.cert, self.key = cert or make_cert(self.folder)
        self.values: dict = {}           # canonical reference -> value
        self.revoked: set = set()
        self.clients: dict = {}          # client_id -> redirect uri
        self.codes: dict = {}            # code -> (client_id, redirect, challenge)
        self.access: dict = {}           # access token -> expiry
        self.refresh: dict = {}          # refresh token -> client_id
        self.consent = True
        self.quota = 1000
        self.used = 0
        self.sinks = list(SINK_PROFILES.values())
        self.resolved: list = []
        self.access_ttl = 3600
        self.evil = False                # True: the error answers carry a reference id in their strings
        self.token_answer = None         # (status, body): the token endpoint answers this to a refresh
        self.refresh_delay = 0.0         # seconds the token endpoint waits before it spends a refresh token
        self.refreshes: list = []        # every refresh token presented, in order (a reuse shows twice)
        self.process_scope = True        # mcpgate 2.0.3815: the process sink needs its own scope
        self.scopes: dict = {}           # access or refresh token -> the scope it was granted
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:
                pass

            def _send(self, status: int, body: object, extra: dict | None = None) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path == "/.well-known/oauth-protected-resource/mcp":
                    return self._send(200, {
                        "resource": server.url + "/mcp", "authorization_servers": [server.url],
                        "sensitive_references": {"resolve_endpoint": server.url + "/sensitive-references/resolve",
                                                 "resolve_scope": "sensitive-references.resolve",
                                                 **({"process_scope": PROCESS_SCOPE} if server.process_scope else {}),
                                                 "resolver_profiles": ["oauth-resolver-1"],
                                                 "sink_profiles": server.sinks, "status": "experimental"}})
                if parts.path == "/.well-known/oauth-authorization-server":
                    return self._send(200, {"issuer": server.url,
                                            "authorization_endpoint": server.url + "/auth/authorize",
                                            "token_endpoint": server.url + "/auth/token",
                                            "registration_endpoint": server.url + "/register",
                                            "code_challenge_methods_supported": ["S256"]})
                if parts.path == "/auth/authorize":
                    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
                    redirect = q.get("redirect_uri", "")
                    if (server.clients.get(q.get("client_id")) != redirect or q.get("code_challenge_method") != "S256"
                            or q.get("scope") not in server._login_scopes() or not server.consent
                            or q.get("response_type") != "code" or q.get("resource") != server.url):
                        return self._send(400, {"error": "invalid_request"})
                    code = secrets.token_urlsafe(16)
                    server.codes[code] = (q["client_id"], redirect, q.get("code_challenge", ""), q["scope"])
                    self.send_response(302)
                    self.send_header("Location",
                                     redirect + "?" + urlencode({"code": code, "state": q.get("state", "")}))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if self.path == "/register":
                    body = json.loads(raw or b"{}")
                    uris = body.get("redirect_uris") or []
                    target = urlsplit(uris[0]) if len(uris) == 1 else None
                    if (target is None or target.scheme != "http" or target.hostname not in ("127.0.0.1", "::1")
                            or not target.port or target.path != "/callback"):
                        return self._send(400, {"error": "invalid_redirect_uri"})
                    if (body.get("grant_types") != ["authorization_code", "refresh_token"]
                            or body.get("response_types") != ["code"]
                            or body.get("token_endpoint_auth_method") != "none"
                            or body.get("scope") not in server._login_scopes()):
                        return self._send(400, {"error": "invalid_client_metadata"})
                    cid = "c_" + secrets.token_hex(8)
                    server.clients[cid] = uris[0]
                    return self._send(201, {"client_id": cid, "redirect_uris": uris})
                if self.path == "/auth/token":
                    form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    if form.get("grant_type") == "authorization_code":
                        got = server.codes.pop(form.get("code", ""), None)
                        verifier = form.get("code_verifier", "")
                        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()) \
                            .rstrip(b"=").decode()
                        if not got or got[1] != form.get("redirect_uri") or got[2] != challenge \
                                or got[0] != form.get("client_id"):
                            return self._send(400, {"error": "invalid_grant"})
                        return self._send(200, server._pair(got[0], got[3]))
                    if form.get("grant_type") == "refresh_token" and server.token_answer is not None:
                        return self._send(*server.token_answer)
                    if form.get("grant_type") == "refresh_token":
                        server.refreshes.append(form.get("refresh_token", ""))
                        time.sleep(server.refresh_delay)
                        cid = server.refresh.pop(form.get("refresh_token", ""), None)   # it rotates: used once
                        if not cid or not server.consent or cid != form.get("client_id"):
                            return self._send(400, {"error": "invalid_grant"})
                        return self._send(200, server._pair(cid, server.scopes.get(form["refresh_token"],
                                                                                   "sensitive-references.resolve")))
                    return self._send(400, {"error": "unsupported_grant_type"})
                if self.path == "/sensitive-references/resolve":
                    return self._resolve(raw)
                self._send(404, {"error": "not_found"})

            def _resolve(self, raw: bytes) -> None:
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if not server.consent or server.access.get(token, 0) < time.time():
                    return self._send(401, {"error": "invalid_token"},
                                      {"WWW-Authenticate": 'Bearer error="invalid_token"'})
                if len(raw) > 64 * 1024:
                    return self._send(413, {"error": "request_too_large"})
                try:
                    body = json.loads(raw)
                except ValueError:
                    return self._send(400, {"error": "invalid_request"})
                refs, sink, dest = body.get("references"), body.get("sink_type"), body.get("destination")
                if not isinstance(refs, list) or not refs or not isinstance(dest, str) or not 1 <= len(dest) <= 4096:
                    return self._send(400, {"error": "invalid_request"})
                if len(refs) > 100:
                    return self._send(413, {"error": "too_many_references"})
                if server.evil:
                    leak = refs[0] if refs else "x"
                    return self._send(409 if sink == "local_file" else 403,
                                      {"error": "unresolvable" if sink == "local_file" else leak,
                                       "reasons": {leak: 1, "unknown": True, "revoked": -1}})
                if SINK_PROFILES.get(sink) not in server.sinks:
                    return self._send(403, {"error": "ineligible_sink"})
                if sink == "process" and server.process_scope \
                        and PROCESS_SCOPE not in server.scopes.get(token, "").split():
                    need = f"sensitive-references.resolve {PROCESS_SCOPE}"
                    text = ("This sign-in does not allow real values in commands. Sign in again and allow commands "
                            "on the consent page.")
                    return self._send(403, {"error": "insufficient_scope", "error_description": text, "scope": need},
                                      {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{need}"'})
                reasons: dict = {}
                for r in refs:
                    if r in server.revoked:
                        reasons["revoked"] = reasons.get("revoked", 0) + 1
                    elif r not in server.values:
                        reasons["unknown"] = reasons.get("unknown", 0) + 1
                if reasons:
                    return self._send(409, {"error": "unresolvable", "reasons": reasons})
                if server.used + len(refs) > server.quota:
                    return self._send(429, {"error": "quota_exceeded"})
                server.used += len(refs)
                server.resolved.append({"sink_type": sink, "destination": dest, "count": len(refs)})
                return self._send(200, {"values": {r: server.values[r] for r in refs}})

        self.httpd = _QuietServer(("127.0.0.1", 0), Handler)
        ctx = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _login_scopes(self) -> tuple:
        base = "sensitive-references.resolve"
        return (base, f"{base} {PROCESS_SCOPE}") if self.process_scope else (base,)

    def _pair(self, client_id: str, scope: str = "sensitive-references.resolve") -> dict:
        access, refresh = "srefr_" + secrets.token_urlsafe(24), "srefr_refresh_" + secrets.token_urlsafe(24)
        self.access[access] = time.time() + self.access_ttl
        self.refresh[refresh] = client_id
        self.scopes[access] = self.scopes[refresh] = scope
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl,
                "refresh_token": refresh, "scope": scope}

    def __enter__(self) -> "SrefServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def mint(self, kind: str, value: str) -> str:
        ref = f"⟦sref:{kind}:{secrets.token_urlsafe(24)}⟧"
        self.values[ref] = value
        return ref

    def revoke(self, ref: str) -> None:
        self.revoked.add(ref)

    def withdraw(self) -> None:
        self.consent = False
        self.access.clear()
        self.refresh.clear()
