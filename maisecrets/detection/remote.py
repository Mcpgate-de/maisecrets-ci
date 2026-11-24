"""An optional remote detector: a named-entity service that the library asks after its deterministic rules
(docs/DETECTION.md, "A remote detector"). Standard library only; Python 3.9.

    remote = RemoteDetector("http://127.0.0.1:8765/", format="hf", model="d3-onnx-fp32@d421f57d")
    result = detector.findings_with(text, channel="tool", remote=remote)
    result.findings     # the deterministic findings, unchanged, and the spans the service added
    result.remote       # a RemoteStatus: ok, partial (checked_to < total), unavailable (and why), too_long or off

What it promises:

- **It only adds.** A span of the service is kept only where no deterministic finding and no span kept before it
  lies. A deterministic finding is never removed, made smaller, moved or retyped.
- **It fails to the deterministic result.** A slow, refused, dead or broken service, or an answer it cannot read,
  gives the deterministic findings alone, and the status says the service was unavailable. A text longer than
  `max_chars` goes in pieces of `max_chars` (since 0.9.29, #105); with `pieces=False` it is not sent (`too_long`).
  When the deadline or a refusal ends the pieces early, the spans of the checked pieces stay and the status is
  `partial`: `checked_to` says where the unchecked rest of the text starts.
- **The service never sees a deterministic finding.** Each one is replaced by filler of the same length before the
  text leaves, so the offsets of the answer still fit the text.
- **No network unless asked.** Only a loopback address (127.0.0.0/8, ::1, localhost) or a Unix socket
  (`unix:/path/to.sock`), unless `allow_network=True`.

Two wire formats: `hf` (Hugging Face token classification: `{"inputs": text}` -> `[{"entity_group", "start", "end",
"score"}]`) and `presidio` (Presidio Analyzer `POST /analyze`: `{"text", "language"}` -> `[{"entity_type",
"start", "end", "score"}]`). The model version comes from `model`, as the operator states it: the service's answer
names none, so the version is only as true as that setting."""
from __future__ import annotations

import bisect
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from .wordlists import words as _words

FORMATS = ("hf", "presidio")
# the entity classes of the service and the maisecrets type each becomes; only names by default, the class the NER
# experiment measured (docs/NER-EXPERIMENT.md). An operator adds more in `classes`
DEFAULT_CLASSES = {"PER": "NAME", "PERSON": "NAME"}
FILLER = "_"                 # a deterministic finding goes out as a run of this: no word, no name, same length
OVERLAP = 200                # characters a piece reads past each cut, so a name on a cut lies whole in one piece
# the time a piece is expected to take before one of the same text was measured: 60 ms per 1,000 characters (the
# reference host, docs/NER-EXPERIMENT.md "The wait grows with the text") times 1.5; it decides whether a retry fits
ESTIMATE_MS_PER_1000, ESTIMATE_SAFETY = 60.0, 1.5
KINDS = ("prompt", "result")  # the optional `kind` of a request (hf): a service may give prompts priority
MAX_ANSWER_BYTES = 4 * 1024 * 1024
_LOOPBACK_NAMES = ("localhost", "localhost.")
_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")


@dataclass(frozen=True)
class RemoteStatus:
    """What the remote detector did in one call. `state`: ok, unavailable (with a `reason`: timeout, refused (nothing
    listens), network (name, TLS, route), policy (an address this detector may not use), unauthorized (401: a bearer is
    missing or wrong), not_ours (the listener could not prove the secret of the service maisecrets started), http,
    answer), partial (the pieces up to `checked_to` were checked, the rest was not: `reason` says why), too_long, or
    off (no remote detector). `added` is the count of spans it added. `checked_to`: the offset in the text where the
    first unchecked character stands (`total` when all was checked, 0 when nothing was); `total`: the length of the
    text. Both are 0 in a status made without them (OFF, an older caller)."""
    format: str = ""
    model: str = ""
    state: str = "off"
    reason: str = ""
    added: int = 0
    ms: float = 0.0
    checked_to: int = 0
    total: int = 0

    @property
    def available(self) -> bool:
        return self.state == "ok"


OFF = RemoteStatus()


@dataclass(frozen=True)
class Result:
    """The findings of one call, sorted by start, and what the remote detector did (`remote`, OFF without one)."""
    findings: list = field(default_factory=list)
    remote: RemoteStatus = OFF


_SHARED = ipaddress.ip_network("100.64.0.0/10")


class _Policy(ConnectionError):
    """A connection this detector refuses to make (an address it may not use): reason `policy`."""


def _private(addr: str) -> bool:
    """A loopback, private (RFC 1918, ULA), link-local or shared (100.64.0.0/10, the range of carrier NAT and of
    Tailscale) address: plain http to it does not cross the internet."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_link_local or (ip.is_private and not ip.is_reserved)
            or (ip.version == 4 and ip in _SHARED))


def _loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class _PinnedConnection(http.client.HTTPConnection):
    """A connection to the address that _connection checked, not to a second lookup of the name; TLS still checks the
    certificate against the name. Without allow_network the peer is checked again before a byte is sent."""

    def __init__(self, host: str, port: int, addr, timeout: float, tls: bool, allow_network: bool,
                 cafile: str = ""):
        super().__init__(host, port, timeout=timeout)
        self._addr, self._tls, self._allow, self._cafile = addr, tls, allow_network, cafile

    def connect(self) -> None:
        family, type_, proto, _canon, sockaddr = self._addr
        s = socket.socket(family, type_, proto)
        s.settimeout(self.timeout)
        try:
            s.connect(sockaddr)
            if not self._allow and not _loopback(s.getpeername()[0]):
                raise ConnectionError("not a loopback peer")
            if self._tls:
                import ssl
                ctx = ssl.create_default_context(cafile=self._cafile) if self._cafile else ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=self.host)
        except BaseException:
            s.close()
            raise
        self.sock = s


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def is_local(url: str) -> bool:
    """A Unix socket or a loopback host: the text stays on this computer."""
    if url.startswith("unix:"):
        return True
    host = (urlsplit(url).hostname or "").lower()
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RemoteDetector:
    """One named-entity service. `classes` maps an entity class of the service to a maisecrets type (DEFAULT_CLASSES:
    names only); `min_score` the least score per maisecrets type (none by default: no threshold is chosen here);
    `timeout` the seconds one request may take; `max_chars` the longest text it is sent. `mask=False` sends the
    findings of the rules as they are: for a service on this computer whose model loses names next to the filler,
    and for the benchmark that compares this path with the NER experiment, whose model read the whole text.
    `bearer`: the token of a service that wants one (mcpgate/ner with NER_CLIENT_SECRET: hmac_sha256(secret, "bearer"),
    64 lowercase hex characters); it goes out as `Authorization: Bearer` and is never in a status, a reason, repr, a
    log line or an error text. The object keeps it, as any client keeps its token. `pieces=False` keeps a text over
    `max_chars` from the service (`too_long`), as before 0.9.29: for a service whose quota a long text would spend
    (the gateway, until it shares its quota under load)."""

    def __init__(self, url: str, format: str = "hf", model: str = "", classes: dict | None = None,
                 min_score: dict | None = None, timeout: float = 0.3, max_chars: int = 20000,
                 language: str = "en", allow_network: bool = False, mask: bool = True, ask_labels: bool = False,
                 private_http_only: bool = False, bearer: str = "", secret: str = "", token: str = "",
                 cafile: str = "", pieces: bool = True):
        if format not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")
        parts = urlsplit(url)
        if not (url.startswith("unix:") or parts.scheme in ("http", "https")) or (
                not url.startswith("unix:") and not parts.hostname):
            raise ValueError("the url must be http://, https:// or unix:/path")
        try:
            port = parts.port
        except ValueError:
            raise ValueError("the url has a port that is no number") from None
        if port == 0:
            raise ValueError("the url has port 0")     # _connection would take the default port instead
        if not isinstance(allow_network, bool):
            raise ValueError("allow_network is True or False")    # "false" as a string must not open the network
        if allow_network is not True and not is_local(url):
            raise ValueError("the url is no loopback address or Unix socket; set allow_network to send text there")
        self.url, self.format, self.model = url, format, str(model)
        self.allow_network = bool(allow_network)
        self.classes = dict(DEFAULT_CLASSES if classes is None else classes)
        if not all(isinstance(k, str) and isinstance(v, str) and _TYPE_RE.fullmatch(v)
                   for k, v in self.classes.items()):
            raise ValueError("classes maps a class name to a type such as NAME")
        self.min_score = dict(min_score or {})
        if not all(isinstance(k, str) and isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1
                   for k, v in self.min_score.items()):
            raise ValueError("min_score maps a type to a number from 0 to 1")
        if not (isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and 0 < timeout < 3600):
            raise ValueError("timeout is a number of seconds above 0")
        if not (isinstance(max_chars, int) and not isinstance(max_chars, bool) and max_chars > 0):
            raise ValueError("max_chars is a whole number above 0")
        self.timeout, self.max_chars, self.language = float(timeout), max_chars, str(language)
        self.mask = bool(mask)
        self.ask_labels = ask_labels is True
        # plain http only to a private address (the plugin's rule: tool results never cross a public network in
        # clear text); https anywhere. Checked at each connection, on the addresses the name gives then
        self.private_http_only = private_http_only is True
        # the derived token only, never the secret; the hex shape also keeps CR and LF out of the header. No status,
        # reason, log line or error text holds it (the gateway passes it, ai-gateway !2965)
        if not (isinstance(bearer, str) and (bearer == "" or re.fullmatch(r"[0-9a-f]{64}", bearer))):
            raise ValueError("bearer: 64 lowercase hex characters")
        # the secret of a service maisecrets started (NER_CLIENT_SECRET of mcpgate/ner, #1699): before each text the
        # service proves that it holds it (GET /health?challenge=), and the bearer comes from it. Never sent itself
        if not (isinstance(secret, str) and (secret == "" or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", secret))):
            raise ValueError("secret: 32 to 128 url-safe characters")
        if secret and bearer:
            raise ValueError("secret or bearer, not both")
        # `token`: the access token of a login (the gateway of /maisecrets:sref login, #33). Only over https, and only
        # a token's characters: no CR, LF or blank reaches the header
        if not (isinstance(token, str) and (token == "" or re.fullmatch(r"[A-Za-z0-9._~+/=-]{16,4096}", token))):
            raise ValueError("token: 16 to 4096 token characters")
        if token and (secret or bearer):
            raise ValueError("a token, a bearer or a secret, only one")
        if token and parts.scheme != "https":
            raise ValueError("a token goes only over https")
        self.__secret = secret
        self.__bearer = _mac(secret, "bearer") if secret else (bearer or token)
        # a CA file to trust besides the system's (a company CA, the test gateway): client_vault_cafile, as the login
        self.cafile = str(cafile or "")
        self.pieces = pieces is not False

    def status(self, state: str, reason: str = "", added: int = 0, ms: float = 0.0, checked_to: int = 0,
               total: int = 0) -> RemoteStatus:
        return RemoteStatus(self.format, self.model, state, reason, added, ms, checked_to, total)

    # ------------------------------------------------------------------ wire --
    def _request(self, body: bytes, deadline: float, gate: dict | None = None) -> bytes:
        """The answer of one POST (name lookup, connect, send, headers, body), or an exception. ask() runs it, the
        reading of the answer and the choice of spans in one thread that it leaves at the deadline."""
        return self._exchange(body, deadline, gate)

    def _connection(self, left: float, pin: dict | None = None):
        """(connection, target). A host name is looked up here, and without allow_network every address it gives must
        be a loopback address: `localhost` that a hosts file sends elsewhere is refused (codex review)."""
        if self.url.startswith("unix:"):
            path = self.url[len("unix:"):]
            path = path[2:] if path.startswith("//") else path
            return _UnixConnection(path, left), "/"
        p = urlsplit(self.url)
        port = p.port or (443 if p.scheme == "https" else 80)
        # one lookup for the proof and the text of one ask(): `pin` keeps it, so the text goes to the address that
        # gave the proof, not to a second answer of the name (codex review of #1699)
        addrs = pin.get("addrs") if pin is not None and pin.get("addrs") else \
            socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        if pin is not None:
            pin["addrs"] = addrs
        if not addrs:
            raise ConnectionError("no address")
        if not self.allow_network and not all(_loopback(a[4][0]) for a in addrs):
            raise _Policy("not a loopback address")
        if self.private_http_only and p.scheme == "http" and not all(_private(a[4][0]) for a in addrs):
            raise _Policy("plain http to an address that is not private")
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        return _PinnedConnection(p.hostname, port, addrs[0], left, p.scheme == "https", self.allow_network,
                                 self.cafile), target

    @property
    def proves(self) -> bool:
        """True for the service maisecrets started (a secret is stored for it): it must prove the secret (_prove)."""
        return bool(self.__secret)

    def _prove(self, deadline: float, pin: dict | None = None) -> None:
        """GET /health?challenge=<a fresh nonce> and compare the proof (#1699). Raises _NotOurs on any other answer.
        The proof and the text go over two connections to one address (the service closes each one): a process that
        takes the port in the moment between them gets the text. Only one that can stop the container can do that, and
        it can read the secret from the container anyway; the proof stops a listener that holds the port while the
        container is down."""
        nonce = secrets.token_urlsafe(24)
        conn, target = self._connection(max(0.001, deadline - time.monotonic()), pin)
        base = target.split("?", 1)[0].rstrip("/")
        try:
            conn.request("GET", f"{base}/health?challenge={nonce}")
            if conn.sock is not None:
                conn.sock.settimeout(max(0.001, deadline - time.monotonic()))
            resp = conn.getresponse()
            data = b""
            while len(data) < 4096:            # read to the deadline: a dribbled answer cannot stretch it
                if time.monotonic() > deadline:
                    raise TimeoutError
                if conn.sock is not None:
                    conn.sock.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = resp.read1(4096 - len(data)) if hasattr(resp, "read1") else resp.read(4096 - len(data))
                if not chunk:
                    break
                data += chunk
            try:
                proof = json.loads(data.decode("utf-8")).get("proof") if resp.status == 200 else None
            except (ValueError, AttributeError):
                proof = None
            if not (isinstance(proof, str) and hmac.compare_digest(proof, _mac(self.__secret, "health:" + nonce))):
                raise _NotOurs
        finally:
            conn.close()

    def _exchange(self, body: bytes, deadline: float, gate: dict | None = None) -> bytes:
        conn, target = self._connection(max(0.001, deadline - time.monotonic()), gate)
        if self.format == "presidio" and not target.rstrip("/").endswith("/analyze"):
            target = target.rstrip("/") + "/analyze"
        try:
            headers = {"Content-Type": "application/json"}
            if self.__bearer:
                headers["Authorization"] = "Bearer " + self.__bearer
            if gate is None:
                conn.request("POST", target, body=body, headers=headers)
            else:
                # the text goes out only under the lock that ask() takes when it gives up: after ask() said timeout,
                # nothing is sent, however late this thread runs on (codex review of #1699)
                with gate["lock"]:
                    if gate["cancelled"] or time.monotonic() > deadline:
                        raise TimeoutError
                    conn.request("POST", target, body=body, headers=headers)
            if conn.sock is not None:
                conn.sock.settimeout(max(0.001, deadline - time.monotonic()))
            resp = conn.getresponse()
            if resp.status == 401:
                raise _Unauthorized
            if resp.status != 200:
                # the gateway names a busy client slot in the body: 503 before ai-gateway v2.0.39xx, 429 with
                # {"error": "busy"} after (a 503 took a gateway container out of the load balancer)
                error, wait = "", _seconds(resp.getheader("Retry-After"))
                if resp.status in (404, 429, 503):        # 404 {"error": "ner_not_enabled"}: switched off
                    try:
                        doc = json.loads(resp.read(4096).decode("utf-8"))
                        error = str(doc.get("error") or "") if isinstance(doc, dict) else ""
                        if wait is None and isinstance(doc, dict):
                            wait = _seconds(doc.get("retry_after"))    # the gateway's body: {"retry_after": 1}
                    except (OSError, ValueError, UnicodeError):
                        error = ""
                refused = _HttpStatus(resp.status, error)
                refused.retry_after = wait
                raise refused
            chunks, size = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError
                if conn.sock is not None:
                    conn.sock.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ANSWER_BYTES:
                    raise ValueError("answer too long")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            conn.close()

    def _body(self, text: str, kind: str | None = None) -> bytes:
        doc = {"inputs": text} if self.format == "hf" else {"text": text, "language": self.language}
        if self.format == "hf" and kind in KINDS:
            doc["kind"] = kind      # top level: a service that does not know it ignores it (the gateway's parse)
        wanted = [k for k in self.classes if k not in DEFAULT_CLASSES]
        if self.format == "hf" and self.ask_labels and wanted:
            # a class beyond names, to a service that takes `labels` (examples/ner_service.py, mcpgate/ner): ask for
            # it. The Hugging Face API has no such parameter, so only `ask_labels` sends it (codex review)
            # PERSON is the same class as PER: dropped only when PER is asked for (codex review, round 2)
            doc["parameters"] = {"labels": [k for k in self.classes if k != "PERSON" or "PER" not in self.classes]}
        return json.dumps(doc, ensure_ascii=False).encode("utf-8")

    def _parse(self, data: bytes, n: int) -> list:
        """(start, end, maisecrets type, score) per entity of a class in `classes`. Raises ValueError on any item it
        cannot read: a half-read answer is no answer."""
        doc = json.loads(data.decode("utf-8"))
        if self.format == "hf" and isinstance(doc, list) and len(doc) == 1 and isinstance(doc[0], list):
            doc = doc[0]                          # a batch of one
        if not isinstance(doc, list):
            raise ValueError("no list")
        if len(doc) > max(64, n // 2):
            # more entities than a text can hold words: 60,000 items took 12 s to sort out (Fable review)
            raise ValueError("too many items")
        out = []
        for item in doc:
            if not isinstance(item, dict):
                raise ValueError("no object")
            label = item.get("entity_group", item.get("entity")) if self.format == "hf" else item.get("entity_type")
            s, e, score = item.get("start"), item.get("end"), item.get("score")
            if not isinstance(label, str) or type(s) is not int or type(e) is not int or \
                    not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score):
                raise ValueError("bad item")
            if not (0 <= s < e <= n) or not (0.0 <= float(score) <= 1.0):
                raise ValueError("out of range")
            label = label[2:] if label[:2] in ("B-", "I-") else label
            type_ = self.classes.get(label)
            if type_ is not None and float(score) >= float(self.min_score.get(type_, 0.0)):
                out.append((s, e, type_, float(score)))
        return out

    # ------------------------------------------------------------------- ask --
    def ask(self, text: str, occupied: list, deadline: float | None = None, kind: str | None = None) -> tuple:
        """(spans, status) for one text. `occupied`: (start, end) of the deterministic findings; they go out as filler
        and no span may overlap one. Each span is (start, end, type, score), widened to whole words, in the order of
        the answers. Never raises, and never takes longer than the deadline: the request, the reading of the answer
        and the choice of spans run in a thread that ask() leaves at the deadline (a dribbled answer, a slow name
        lookup and a valid answer that is costly to sort out all count; codex review). Each request (the first with
        the proof) waits at most `timeout`; `deadline`, when given, ends the whole text, all its pieces and retries,
        earlier than their caps when it comes first (#105). Without a deadline the whole text gets `timeout`.
        `kind` ("prompt" or "result"): sent as a top-level field of an hf request, for a service that orders by it."""
        t0 = time.monotonic()
        total = len(text)
        if not self.pieces and total > self.max_chars:
            return [], self.status("too_long", total=total)
        deadline = t0 + self.timeout if deadline is None else deadline
        if deadline - t0 <= 0:
            return [], self.status("unavailable", "timeout", total=total)
        # the spans of the pieces checked so far, in the offsets of `text`, and where the unchecked rest starts there;
        # one tuple, replaced whole after each piece, so the caller reads a consistent pair at the deadline
        box: dict = {"progress": ((), 0)}
        gate = {"lock": threading.Lock(), "cancelled": False}

        def work() -> None:
            try:
                # the service reads the text with its JSON escapes turned into their characters (a guest list of
                # `\r\nAlexander` was the word nAlexander to it, #39); each span comes back in the offsets of the text.
                # The cuts are made here too, on the characters: a cut inside an escape would bring #39 back
                plain, starts, ends = unescape_json(text)
                occ = occupied if starts is None else [(bisect.bisect_right(ends, a), bisect.bisect_left(starts, b))
                                                       for a, b in occupied]
                sent = list(plain)
                for a, b in occ if self.mask else ():
                    sent[a:b] = FILLER * (b - a)       # occupied over a cut: each piece gets its own part as filler
                sent_text = "".join(sent)
                # each request waits at most `timeout` from its start, the first one from the start of ask() (the
                # proof included): a one-piece text waits as before 0.9.29. `deadline` ends the whole text
                cap = min(deadline, t0 + self.timeout)
                if self.__secret:
                    self._prove(cap, gate)    # no text goes to a listener that cannot prove the secret; once a text
                    if time.monotonic() > cap:
                        raise TimeoutError     # a proof after the deadline: the caller was told "timeout"
                keeper = _Keeper(plain, occ)
                mapped: list = []
                took = None                    # the measured seconds of the last piece of this text
                for n, (p, c0, c1, e) in enumerate(plan_pieces(plain, self.max_chars)):
                    body = self._body(sent_text[p:e], kind)
                    began, retried = time.monotonic(), False
                    if n:
                        cap = min(deadline, began + self.timeout)
                    while True:
                        try:
                            raw = self._request(body, cap, gate)
                            break
                        except _HttpStatus as exc:
                            # Retry-After once per piece, only for `busy` (the one client slot frees in a second;
                            # after `rate_limited` the quota of the minute is spent: no further piece), and only when
                            # the wait and the piece fit the deadline
                            wait = exc.retry_after
                            guess = took if took is not None else \
                                ESTIMATE_SAFETY * ESTIMATE_MS_PER_1000 * (e - p) / 1000 / 1000
                            if retried or _why(exc) != "busy" or wait is None or \
                                    time.monotonic() + wait + guess > deadline:
                                raise
                            retried = True
                            time.sleep(wait)
                            began = time.monotonic()
                            cap = min(deadline, began + self.timeout)     # the second request waits its own time
                    found = self._parse(raw, e - p)
                    # a span belongs to the piece whose core (the part without the overlap) holds its start. Each piece
                    # reads `overlap` characters past its core on both sides, so a name that starts in a core lies
                    # whole in that piece, and a name on a cut is taken once, whole
                    new = keeper.add([(p + s, p + t, ty, sc) for s, t, ty, sc in found if c0 <= p + s < c1], cap)
                    mapped += new if starts is None else [(starts[a], ends[b - 1], ty, sc) for a, b, ty, sc in new]
                    took = time.monotonic() - began
                    box["progress"] = (tuple(mapped), total if c1 >= len(plain) else
                                       (c1 if starts is None else starts[c1]))
            except BaseException as exc:  # noqa: BLE001 - handed to the caller as it is
                box["error"] = exc
        t = threading.Thread(target=work, name="maisecrets-remote", daemon=True)
        t.start()
        t.join(max(0.0, deadline - time.monotonic()))
        if t.is_alive():
            with gate["lock"]:
                gate["cancelled"] = True
            why = "timeout"
        else:
            exc = box.get("error")
            why = "" if exc is None else _why(exc)
        kept, checked = box["progress"]
        kept = list(kept)
        if not why and checked >= total:
            return kept, self.status("ok", added=len(kept), ms=_ms(t0), checked_to=total, total=total)
        if checked > 0:
            # the checked pieces keep their spans; the rest of the text got the rules alone
            return kept, self.status("partial", why or "answer", added=len(kept), ms=_ms(t0), checked_to=checked,
                                     total=total)
        return [], self.status("unavailable", why or "answer", ms=_ms(t0), total=total)

    @staticmethod
    def _keep(text: str, spans: list, occupied: list, deadline: float) -> list:
        """The spans widened to whole words that overlap no occupied span and no span kept before them. Linear in the
        text and the spans (an answer of 10,000 spans over one long word took 4.5 s with a widening per span)."""
        return _Keeper(text, occupied).add(spans, deadline)


def plan_pieces(text: str, size: int, overlap: int = OVERLAP) -> list:
    """The pieces of a text for a service that takes at most `size` characters: (start, core start, core end, end)
    each. The cores cut the text without gap or overlap, at a line break, else at a space, else where the size ends;
    each piece reads `overlap` characters past its core on each side (a quarter of `size` at most), so a name on a cut
    lies whole in the piece that owns its start. One piece for a text of `size` or less."""
    n = len(text)
    if n <= size:
        return [(0, 0, n, n)]
    overlap = max(0, min(overlap, size // 4))
    out: list = []
    core = 0
    while True:
        p = max(0, core - overlap)
        if p + size >= n:
            out.append((p, core, n, n))
            return out
        hi = p + size - overlap            # the latest end of this core: its piece still ends within `size`
        lo = max(core + 1, (core + hi) // 2)   # never a core of less than half the room
        cut = text.rfind("\n", lo, hi)
        if cut < 0:
            cut = text.rfind(" ", lo, hi)
        cut = hi if cut < 0 else cut + 1   # after the line break or the space
        out.append((p, core, cut, min(n, cut + overlap)))
        core = cut


class _Keeper:
    """_keep for the spans of one text that come piece by piece: the words of the whole text (a span widens across a
    cut), the occupied spans and the spans kept so far."""

    def __init__(self, text: str, occupied: list):
        self.text, self.words = text, None
        self.occ = _merged(occupied)       # disjoint and sorted: a stored value may lie inside a finding
        self.ends = [b for _a, b in self.occ]
        self.taken: list = []              # the kept spans, sorted: they never overlap each other
        self.n = 0

    def add(self, spans: list, deadline: float) -> list:
        """The spans of `spans` that are kept, widened; they are kept for the next call too."""
        kept: list = []
        for s, e, type_, score in spans:
            if self.n % 512 == 0 and time.monotonic() > deadline:
                raise TimeoutError
            self.n += 1
            if self.words is None:
                self.words = _Words(self.text)
            s, e = self.words.widen(s, e)
            if s >= e:
                continue                          # white space only: no word to take
            if type_ == "NAME" and is_no_person_in(self.text, s, e):
                continue                          # a product, a greeting, a UI label word or a company is no person
            if _overlaps(self.occ, self.ends, s, e):
                continue
            taken = self.taken
            i = bisect.bisect_left(taken, (s, e))
            if (i > 0 and taken[i - 1][1] > s) or (i < len(taken) and taken[i][0] < e):
                continue
            taken.insert(i, (s, e))
            kept.append((s, e, type_, score))
        return kept


def _why(exc: BaseException) -> str:
    """The reason of an unavailable status for the error of one request."""
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, _NotOurs):
        return "not_ours"
    if isinstance(exc, _Unauthorized):
        return "unauthorized"
    if isinstance(exc, _HttpStatus):
        # a gateway's refusals by name (ai-gateway #1819): 403 the login lacks the name scope, 413 the text is too
        # long, 429 a limit per person, 503 the gateway's own name lookups run first, 504 its deadline passed
        code = exc.args[0] if exc.args else 0
        error = exc.args[1] if len(exc.args) > 1 else ""
        reason = {403: "forbidden", 413: "too_long", 429: "rate_limited", 503: "busy", 504: "timeout"}.get(code, "http")
        if error == "busy":
            reason = "busy"                  # 429 {"error": "busy"}: the one client slot, not the quota
        elif code == 503 and error:
            # a 503 with another error (temporarily_unavailable: the gateway's store; ner_unavailable: no service) is
            # an outage, not a busy slot: its own reason, and no retry. Only a 503 without an error is an older
            # gateway's busy slot
            reason = "unavailable"
        if code == 404 and len(exc.args) > 1 and exc.args[1] == "ner_not_enabled":
            reason = "not_enabled"           # the gateway's operator has not switched name detection on
        return reason
    if isinstance(exc, (ConnectionRefusedError, FileNotFoundError)):
        # nothing listens there (no service, no socket file): the one reason a caller may take for "not running"
        return "refused"
    if isinstance(exc, _Policy):
        return "policy"
    if isinstance(exc, (ConnectionError, OSError)) and not isinstance(exc, ValueError):
        # a name that does not resolve, TLS, a route: the network, not a stopped service
        return "timeout" if "timed out" in str(exc) else "network"
    return "answer"


def _seconds(value) -> float | None:
    """A Retry-After in seconds (a header's text or a body's number), or None: an HTTP date is not read."""
    try:
        v = float(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else math.nan
    except ValueError:
        return None
    return v if math.isfinite(v) and v >= 0 else None


# product and model words that the cased model takes for a person when they stand alone (ghissues dev, 2026-11-01:
# 141 of 1,670 name spans; Claude and Jenkins most often). Never a word that is also a first name in the data: two
# such words are real names in DialogPII. A full name that holds one of them as a surname is not touched
PRODUCT_WORDS = _words("name-service/product-words")


# greetings that the model takes for a person when they stand alone before a name (`Hallo` in "Hallo Lena, …": 88 of
# 117 false names on a corpus of gateway responses, 2026-11-02); the name after them stays a name. On the DialogPII
# dev split: 27 fewer false names, no name lost (netcup, prompt NER). The word is dropped wherever it stands alone, not
# only before a name: a quoted greeting ("the greeting Hallo") is no person either. None of these words is a name or a
# part of a name among the 20,671 person spans of DialogPII dev (2026-11-13, also hoi and hej); "lieben" came back
# alone as a name from the reference service for "Hallo Ihr Lieben," (#41). Lieben is also a rare surname: alone,
# without a given name, it is dropped; a full name with it stays
GREETING_WORDS = _words("name-service/greetings")
# the words that address a group after a greeting ("Hallo Ihr Lieben", "Hallo zusammen"): the service returned the
# whole phrase as one person (#95). Only a span of greetings and these words is dropped; "Ihr" alone and a span with
# one other word ("Hallo Anke") stay. Du, Sie, Ihr and Alle are parts of real names (du Bois): never alone here
GREETING_ADDRESS_WORDS = _words("name-service/greeting-address-words")
# an initial and one to three technical acronyms of ACRONYMS ("G. PII", "B. MCP"): a list label or a table cell, not
# a person (#93). A word of ACRONYMS alone is no person either: "NER" alone was masked as a name (Cowork, 0.9.22).
# Only words of the list: an all-caps surname of 2 to 4 letters after an initial ("J. LEE", "T. KOCH")
# is a name on a form or a label (Gate B)
ACRONYMS = _words("name-service/acronyms")
# common words that are no person alone in capitals ("NEUTRAL", a label of a review or a log level): in title case a
# word of this list keeps the service's answer
CAPS_WORDS = _words("name-service/caps-words")
_INITIAL_AND_ACRONYMS_RE = re.compile(r"[A-Z]\.((?:[ \t]+[A-Z]{2,4}){1,3})")
# the words of buttons and links that the model takes for a person when two of them stand next to "and" or "or"
# before a noun ("the Allow and Deny buttons": scores of 0.91 to 0.999 on int8 and fp32, reported in #41). A score
# threshold does not tell them from a real one-word name, which scored down to 0.40 there. Never a word that is also
# a given name or a surname: not edit (a Hungarian given name), not ok (a Korean surname). None of these is a name or a
# part of a name among the 20,671 person spans of DialogPII dev
UI_LABEL_WORDS = _words("name-service/ui-labels")
# words of a test runner's or a build's summary line that the model takes for a person at the start of a line
# ("Ran 3561 tests in 606 s", "Passed 12, Skipped 3"); "Ok" stays out: it is a Korean surname
RUNNER_WORDS = _words("name-service/test-runner-words")
# the words after a product word in a product name ("Claude Code", "GitHub Actions", "Docker Desktop"): the model
# takes the whole name for a person. Never a word that is also a first name (no "max", no "pro")
PRODUCT_TAILS = _words("name-service/product-name-tails")
# the words of PRODUCT_TAILS that are also a given name or a surname: after a product word they stay a name ("Server"
# is a Turkish given name). "Code" is a rare surname, but "Claude Code" is in nearly every session: it stays a tail
TAILS_THAT_ARE_NAMES = _words("name-service/product-tails-that-are-names")
# words that are never a name in any language: no person alone, and never stored (is_never_stored_name). A word that
# is a name somewhere ("Bash", "Edit", "Home", "Code") is freed only where the text shows its context. None is in a
# person span of DialogPII dev (2026-11-17)
NEVER_A_NAME = _words("name-service/never-a-name")
# the tool names and the hook events of Claude Code and Codex: "PostToolUse:Bash" in a hook's notice was taken for a
# person, and "Bash" then masked in every text (2026-11-17)
TOOL_NAMES = _words("name-service/tool-names")
HOOK_EVENTS = _words("name-service/hook-events")
# the folder names of a file path: "Users" of /Users/x was taken for a person (2026-11-17). A login name in a home
# path is personal data and stays a name
PATH_WORDS = _words("name-service/path-words")
_PATH_SPLIT_RE = re.compile(r"[/\\]+")
# the words before a tool name that show a tool: "ran Bash", "via Bash"
_TOOL_VERBS = frozenset({"ran", "run", "runs", "via"})


# a JSON escape, also escaped again (`\\n` in a JSON text inside a JSON string): the backslashes and what they stand for
_ESCAPE_RE = re.compile(r"\\+(?:u([0-9A-Fa-f]{4})|([nrtbf\"/]))")
_ESCAPED = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", '"': '"', "/": "/"}


def unescape_json(text: str) -> tuple:
    """(plain, starts, ends): the text with each JSON escape (\\n \\r \\t \\" \\uXXXX, also with more backslashes) as
    the character it stands for, and for each character of `plain` the start and the end of the characters of `text`
    it came from. (text, None, None) when the text holds no escape. A span of `plain` from a to b covers
    text[starts[a]:ends[b - 1]]: whole escapes, never half of one."""
    if "\\" not in text:
        return text, None, None
    plain: list = []
    starts: list = []
    ends: list = []
    at = 0
    found = list(_ESCAPE_RE.finditer(text))
    skip = False
    for n, m in enumerate(found):
        if skip:
            skip = False
            continue
        for i in range(at, m.start()):
            plain.append(text[i])
            starts.append(i)
            ends.append(i + 1)
        code = int(m.group(1), 16) if m.group(1) else -1
        if 0xD800 <= code <= 0xDFFF:
            # an emoji is two escapes, a high and a low surrogate: one character for both. A lone surrogate stays its
            # raw text: as a character it cannot be sent as UTF-8, and one emoji failed the request of a whole result
            nxt = found[n + 1] if n + 1 < len(found) else None
            low = int(nxt.group(1), 16) if nxt is not None and nxt.start() == m.end() and nxt.group(1) else -1
            if code <= 0xDBFF and 0xDC00 <= low <= 0xDFFF:
                plain.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                starts.append(m.start())
                ends.append(nxt.end())
                at, skip = nxt.end(), True
                continue
            for i in range(m.start(), m.end()):
                plain.append(text[i])
                starts.append(i)
                ends.append(i + 1)
            at = m.end()
            continue
        plain.append(chr(code) if code >= 0 else _ESCAPED[m.group(2)])
        starts.append(m.start())
        ends.append(m.end())
        at = m.end()
    if not plain:
        return text, None, None
    for i in range(at, len(text)):
        plain.append(text[i])
        starts.append(i)
        ends.append(i + 1)
    return "".join(plain), starts, ends


def is_product_name(span: str) -> bool:
    """Whether a name span is a product word alone, or a product word followed only by product words and
    PRODUCT_TAILS ("Claude Code"). Public since 0.8.15: a caller that applies the spans itself drops these."""
    words = span.strip().lower().split()
    return bool(words) and words[0] in PRODUCT_WORDS and all(
        w in PRODUCT_WORDS or (w in PRODUCT_TAILS and w not in TAILS_THAT_ARE_NAMES) for w in words[1:])


def is_no_person(span: str) -> bool:
    """Whether a NAME span is no person: a product name (is_product_name), a word of GREETING_WORDS, of
    UI_LABEL_WORDS, of RUNNER_WORDS or of NEVER_A_NAME alone, a hook label (is_hook_label), a path of folder names
    (is_path_words), a span with a digit, a word of ACRONYMS alone in capitals or after an initial, or a greeting phrase
    (is_greeting_phrase). Public since 0.9.8: a caller that applies the spans itself drops these, the same rule as the
    remote path here (#41)."""
    word = span.strip().lower()
    return (is_product_name(span) or word in GREETING_WORDS or word in UI_LABEL_WORDS
            or word in RUNNER_WORDS or word in NEVER_A_NAME or _is_acronym(span) or is_hook_label(span)
            or is_path_words(span)
            or _has_digit(span) or _is_initial_and_acronyms(span) or is_greeting_phrase(span))


def _has_digit(span: str) -> bool:
    """A code with a digit and no word of three letters or a capital and a small letter ("Li2") is no person ("D8",
    "(D8)", a decision label; #93). A
    name with a digit next to it stays: the span is widened to whole words, so "Schmidt2" or "Schmidt¹" (a footnote)
    holds the name (Gate B)."""
    return any(c.isdigit() for c in span) and not _WORD_OF_3_RE.search(span)


_WORD_OF_3_RE = re.compile(r"[^\W\d_]{3}|[A-Z][a-z]")


def _is_acronym(span: str) -> bool:
    """A word of ACRONYMS or of CAPS_WORDS alone, in capitals ("NER", "MCP", "NEUTRAL"): "Ner" and "Api" are given
    names."""
    word = span.strip()
    return word.isupper() and (word.lower() in ACRONYMS or word.lower() in CAPS_WORDS)


def _is_initial_and_acronyms(span: str) -> bool:
    m = _INITIAL_AND_ACRONYMS_RE.fullmatch(span.strip())
    return m is not None and all(w.lower() in ACRONYMS for w in m.group(1).split())


def is_greeting_phrase(span: str) -> bool:
    """Whether every word of a NAME span is a greeting or a word that addresses a group, and one is a greeting
    ("Hallo Ihr Lieben", "Liebe alle"). A comma or a mark after a word does not count. Public since 0.9.22 (#95)."""
    words = [w.strip(",.!?:;") for w in span.lower().split()]
    return (any(w in GREETING_WORDS for w in words)
            and all(w in GREETING_WORDS or w in GREETING_ADDRESS_WORDS for w in words))


def is_hook_label(span: str) -> bool:
    """Whether a NAME span is a hook label: a hook event, a colon and a tool name ("PostToolUse:Bash"). Public since
    0.9.15."""
    head, _sep, tail = span.strip().lower().partition(":")
    return head in HOOK_EVENTS and tail in TOOL_NAMES


def is_path_words(span: str) -> bool:
    """Whether a NAME span is a path of only folder names and product words, with a separator in it
    ("Users/Shared", "AppData\\Roaming"). A path with any other part ("Users/" and a login name) stays a name.
    Public since 0.9.15."""
    parts = [p for p in _PATH_SPLIT_RE.split(span.strip().lower()) if p]
    return (_PATH_SPLIT_RE.search(span) is not None and bool(parts)
            and all(p in PATH_WORDS or p in PRODUCT_WORDS for p in parts)
            and not any(p in ("users", "home") for p in parts[:-1]))     # "Users/Home": the login stays a name


def is_product_tail(text: str, start: int, end: int) -> bool:
    """Whether the NAME span text[start:end] holds only PRODUCT_TAILS and stands right after a product name, with
    only spaces between ("Code" in "Claude Code", "Actions" in "GitHub Actions"): the service cut the product name.
    Public since 0.9.15."""
    words = text[start:end].lower().split()
    if not words or not all(w in PRODUCT_TAILS and w not in TAILS_THAT_ARE_NAMES for w in words):
        return False
    i = start
    while True:
        j = i
        while j > 0 and text[j - 1] in " \t":
            j -= 1
        k = j
        while k > 0 and text[k - 1].isalnum():
            k -= 1
        if j == i:
            return False                 # no space before the span
        word = text[k:j].lower()
        if word in PRODUCT_WORDS:
            return True
        if word not in PRODUCT_TAILS:
            return False
        i = k                            # "Claude Code Desktop": go back over the tails to the product word


def _word_before(text: str, start: int) -> tuple:
    """(the word before text[start], the characters between it and start)."""
    j = start
    while j > 0 and text[j - 1] in " \t":
        j -= 1
    k = j
    while k > 0 and text[k - 1].isalnum():
        k -= 1
    return text[k:j], text[j:start]


def is_hook_label_tail(text: str, start: int, end: int) -> bool:
    """Whether the NAME span text[start:end] is a tool name right after a hook event and a colon ("Edit" in
    "PostToolUse:Edit"). Public since 0.9.15."""
    word, gap = _word_before(text, start - 1) if text[start - 1:start] == ":" else ("", "")
    return not gap and word.lower() in HOOK_EVENTS and text[start:end].lower() in TOOL_NAMES


def is_tool_in_context(text: str, start: int, end: int) -> bool:
    """Whether the NAME span text[start:end] is a tool name that the text shows as a tool: "Bash(git status)",
    "the Bash tool", "ran Bash", "via Bash". Public since 0.9.15."""
    if text[start:end].lower() not in TOOL_NAMES:
        return False
    if text[end:end + 1] == "(" or re.match(r"[ \t]+tools?\b", text[end:end + 7]):
        return True
    word, gap = _word_before(text, start)
    return bool(gap) and word.lower() in _TOOL_VERBS


def _after_home_root(text: str, i: int) -> bool:
    """Whether text[i:] starts the segment after a home root (/Users/x, /home/x, C:\\Users\\x): the login, a name.
    Repeated and escaped separators count as one ("/Users//x", "C:\\\\Users\\\\x" in JSON)."""
    j = i
    while j > 0 and text[j - 1] in "/\\":
        j -= 1
    k = j
    while k > 0 and text[k - 1].isalnum():
        k -= 1
    return j < i and text[k:j].lower() in ("users", "home") and (k == 0 or text[k - 1] in "/\\")


def is_path_segment(text: str, start: int, end: int) -> bool:
    """Whether the NAME span text[start:end] is one folder name or product word with a path separator right before
    or after it ("Library" in /Users/x/Library/, "home" in /home/x). Public since 0.9.15."""
    word = text[start:end].lstrip(".").lower()
    i = start - 1 if text[start - 1:start] == "." else start     # ".claude" with the dot outside the span
    before = text[i - 1:i] if i > 0 else ""
    if _after_home_root(text, i):
        return False                     # /Users/Home/: the login stays a name, also when it is a folder name
    return ((word in PATH_WORDS or word in PRODUCT_WORDS)
            and (before in ("/", "\\") or text[end:end + 1] in ("/", "\\")))


def is_never_stored_name(value: str) -> bool:
    """Whether a NAME value of the name service is only words of NEVER_A_NAME (one word, or a hook label or a path
    of them): never stored, whatever the filters before let through. A stored value is masked in every text.
    Public since 0.9.15."""
    parts = [p for p in re.split(r"[:/\\]+", value.strip().lower()) if p]
    return bool(parts) and all(p in NEVER_A_NAME for p in parts)


def is_no_person_in(text: str, start: int, end: int) -> bool:
    """The whole rule of the remote path for the NAME span text[start:end]: is_no_person, or a context the text
    shows (is_company_name, is_product_tail, is_hook_label_tail, is_tool_in_context, is_path_segment). Public since
    0.9.15: a caller that applies the spans itself calls this one."""
    return (is_no_person(text[start:end]) or is_company_name(text, start, end)
            or is_product_tail(text, start, end) or is_hook_label_tail(text, start, end)
            or is_tool_in_context(text, start, end) or is_path_segment(text, start, end))


# a legal form that is never a job title, an initial or a short word of another meaning, in its usual spelling, as
# the last word of a name span or right after it (#46: the name service took company names of the Mendeley sample for
# persons). Not SE, AG, KG, Group, S.A. or N.V.: "Jane Doe, SE at Acme", "Hi Tom, Group chat", "Raghav N.V. Rao" are
# persons (Gate A of #46); no comma before it and no hyphen after it ("Herr Mueller AG-Leiter")
_COMPANY_TAIL = r"(?:GmbH|mbH|LLC|LLP|Ltd\.?|Inc\.?|Corp\.?|Limited|PLC|plc)"
_COMPANY_END_RE = re.compile(_COMPANY_TAIL + r"$")
_COMPANY_AFTER_RE = re.compile(r"[ \t]+" + _COMPANY_TAIL + r"(?![\w-])")


def is_company_name(text: str, start: int, end: int) -> bool:
    """Whether the NAME span text[start:end] names a company: it ends in a legal form (Ltd, LLC, GmbH, Inc), or one
    follows it ("Becker-Lindqvist Ltd"). Public since 0.9.11: a caller that applies the
    spans itself drops these too (#46)."""
    return bool(_COMPANY_END_RE.search(text, start, end) or _COMPANY_AFTER_RE.match(text, end))


class _HttpStatus(Exception):
    retry_after: float | None = None       # seconds from Retry-After or the body's retry_after, when given


class _NotOurs(Exception):
    """The listener could not prove the secret of the service maisecrets started: no text goes there."""


def _mac(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


class _Unauthorized(_HttpStatus):
    """401: the service wants a bearer this client did not send, or another one."""


def _merged(spans: list) -> list:
    """The spans joined into disjoint ones, sorted: a stored value inside a finding of the rules made the ends of the
    sorted list fall, and a search by end then started past the finding that covers it (Fable review)."""
    out: list = []
    for a, b in sorted(spans):
        if out and a < out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _overlaps(occ: list, ends: list, s: int, e: int) -> bool:
    """Does [s, e) overlap a span of `occ` (disjoint, sorted; `ends` their ends, rising)? The first span that ends
    after s decides."""
    i = bisect.bisect_right(ends, s)
    return i < len(occ) and occ[i][0] < e


def _ms(t0: float) -> float:
    return round((time.monotonic() - t0) * 1000, 1)


class _Words:
    """whole_words for many spans of one text, in time linear in the text: the next and the previous character that is
    no white space, and the start and end of each run of letters and digits, computed once."""

    def __init__(self, text: str):
        n = len(text)
        self.n, self.text = n, text
        self.next_ns = [n] * (n + 1)
        for i in range(n - 1, -1, -1):
            self.next_ns[i] = i if not text[i].isspace() else self.next_ns[i + 1]
        self.prev_ns = [-1] * (n + 1)              # prev_ns[e]: the last j < e that is no white space
        for i in range(1, n + 1):
            self.prev_ns[i] = i - 1 if not text[i - 1].isspace() else self.prev_ns[i - 1]
        self.run_start, self.run_end = [0] * n, [0] * n
        i = 0
        while i < n:
            if text[i].isalnum():
                j = i
                while j < n and text[j].isalnum():
                    j += 1
                for k in range(i, j):
                    self.run_start[k], self.run_end[k] = i, j
                i = j
            else:
                i += 1

    def widen(self, s: int, e: int) -> tuple:
        s = self.next_ns[s]
        if s >= e:
            return s, s
        e = self.prev_ns[e] + 1
        if s >= e:
            return s, s
        if s > 0 and self.text[s - 1].isalnum():
            s = self.run_start[s - 1]
        if e < self.n and self.text[e].isalnum():
            e = self.run_end[e]
        return s, e


def whole_words(text: str, s: int, e: int) -> tuple:
    """The span widened to whole words: a service that aggregates word pieces can end inside a word, and a mask
    there leaves half a name (docs/NER-EXPERIMENT.md, candidate D)."""
    while s < e and text[s].isspace():
        s += 1
    while e > s and text[e - 1].isspace():
        e -= 1
    if s >= e:
        return s, s
    while s > 0 and text[s - 1].isalnum():
        s -= 1
    while e < len(text) and text[e].isalnum():
        e += 1
    return s, e
