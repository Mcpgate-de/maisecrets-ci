"""An optional remote detector: a named-entity service that the library asks after its deterministic rules
(docs/DETECTION.md, "A remote detector"). Standard library only; Python 3.9.

    remote = RemoteDetector("http://127.0.0.1:8765/", format="hf", model="d3-onnx-fp32@d421f57d")
    result = detector.findings_with(text, channel="tool", remote=remote)
    result.findings     # the deterministic findings, unchanged, and the spans the service added
    result.remote       # a RemoteStatus: ok, unavailable (and why), too_long or off

What it promises:

- **It only adds.** A span of the service is kept only where no deterministic finding and no span kept before it
  lies. A deterministic finding is never removed, made smaller, moved or retyped.
- **It fails to the deterministic result.** A slow, refused, dead or broken service, or an answer it cannot read,
  gives the deterministic findings alone, and the status says the service was unavailable. A text longer than
  `max_chars` is not sent (status `too_long`).
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
import http.client
import ipaddress
import json
import math
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

FORMATS = ("hf", "presidio")
# the entity classes of the service and the maisecrets type each becomes; only names by default, the class the NER
# experiment measured (docs/NER-EXPERIMENT.md). An operator adds more in `classes`
DEFAULT_CLASSES = {"PER": "NAME", "PERSON": "NAME"}
FILLER = "_"                 # a deterministic finding goes out as a run of this: no word, no name, same length
MAX_ANSWER_BYTES = 4 * 1024 * 1024
_LOOPBACK_NAMES = ("localhost", "localhost.")
_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")


@dataclass(frozen=True)
class RemoteStatus:
    """What the remote detector did in one call. `state`: ok, unavailable (with a `reason`: timeout, refused, http,
    answer), too_long, or off (no remote detector). `added` is the count of spans it added."""
    format: str = ""
    model: str = ""
    state: str = "off"
    reason: str = ""
    added: int = 0
    ms: float = 0.0

    @property
    def available(self) -> bool:
        return self.state == "ok"


OFF = RemoteStatus()


@dataclass(frozen=True)
class Result:
    """The findings of one call, sorted by start, and what the remote detector did (`remote`, OFF without one)."""
    findings: list = field(default_factory=list)
    remote: RemoteStatus = OFF


def _loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class _PinnedConnection(http.client.HTTPConnection):
    """A connection to the address that _connection checked, not to a second lookup of the name; TLS still checks the
    certificate against the name. Without allow_network the peer is checked again before a byte is sent."""

    def __init__(self, host: str, port: int, addr, timeout: float, tls: bool, allow_network: bool):
        super().__init__(host, port, timeout=timeout)
        self._addr, self._tls, self._allow = addr, tls, allow_network

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
                s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
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
    and for the benchmark that compares this path with the NER experiment, whose model read the whole text."""

    def __init__(self, url: str, format: str = "hf", model: str = "", classes: dict | None = None,
                 min_score: dict | None = None, timeout: float = 0.3, max_chars: int = 20000,
                 language: str = "en", allow_network: bool = False, mask: bool = True):
        if format not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")
        parts = urlsplit(url)
        if not (url.startswith("unix:") or parts.scheme in ("http", "https")) or (
                not url.startswith("unix:") and not parts.hostname):
            raise ValueError("the url must be http://, https:// or unix:/path")
        try:
            parts.port
        except ValueError:
            raise ValueError("the url has a port that is no number") from None
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

    def status(self, state: str, reason: str = "", added: int = 0, ms: float = 0.0) -> RemoteStatus:
        return RemoteStatus(self.format, self.model, state, reason, added, ms)

    # ------------------------------------------------------------------ wire --
    def _request(self, body: bytes, deadline: float) -> bytes:
        """The answer of one POST (name lookup, connect, send, headers, body), or an exception. ask() runs it, the
        reading of the answer and the choice of spans in one thread that it leaves at the deadline."""
        return self._exchange(body, deadline)

    def _connection(self, left: float):
        """(connection, target). A host name is looked up here, and without allow_network every address it gives must
        be a loopback address: `localhost` that a hosts file sends elsewhere is refused (codex review)."""
        if self.url.startswith("unix:"):
            path = self.url[len("unix:"):]
            path = path[2:] if path.startswith("//") else path
            return _UnixConnection(path, left), "/"
        p = urlsplit(self.url)
        port = p.port or (443 if p.scheme == "https" else 80)
        addrs = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        if not addrs:
            raise ConnectionError("no address")
        if not self.allow_network and not all(_loopback(a[4][0]) for a in addrs):
            raise ConnectionError("not a loopback address")
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        return _PinnedConnection(p.hostname, port, addrs[0], left, p.scheme == "https", self.allow_network), target

    def _exchange(self, body: bytes, deadline: float) -> bytes:
        conn, target = self._connection(max(0.001, deadline - time.monotonic()))
        if self.format == "presidio" and not target.rstrip("/").endswith("/analyze"):
            target = target.rstrip("/") + "/analyze"
        try:
            conn.request("POST", target, body=body, headers={"Content-Type": "application/json"})
            if conn.sock is not None:
                conn.sock.settimeout(max(0.001, deadline - time.monotonic()))
            resp = conn.getresponse()
            if resp.status != 200:
                raise _HttpStatus
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

    def _body(self, text: str) -> bytes:
        doc = {"inputs": text} if self.format == "hf" else {"text": text, "language": self.language}
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
    def ask(self, text: str, occupied: list, deadline: float | None = None) -> tuple:
        """(spans, status) for one text. `occupied`: (start, end) of the deterministic findings; they go out as filler
        and no span may overlap one. Each span is (start, end, type, score), widened to whole words, in the order of
        the answer. Never raises, and never takes longer than the deadline: the request, the reading of the answer
        and the choice of spans run in a thread that ask() leaves at the deadline (a dribbled answer, a slow name
        lookup and a valid answer that is costly to sort out all count; codex review)."""
        t0 = time.monotonic()
        if len(text) > self.max_chars:
            return [], self.status("too_long")
        deadline = min(deadline if deadline is not None else math.inf, t0 + self.timeout)
        if deadline - t0 <= 0:
            return [], self.status("unavailable", "timeout")
        box: dict = {}

        def work() -> None:
            try:
                sent = list(text)
                for a, b in occupied if self.mask else ():
                    sent[a:b] = FILLER * (b - a)
                raw = self._request(self._body("".join(sent)), deadline)
                box["kept"] = self._keep(text, self._parse(raw, len(text)), occupied, deadline)
            except BaseException as exc:  # noqa: BLE001 - handed to the caller as it is
                box["error"] = exc
        t = threading.Thread(target=work, name="maisecrets-remote", daemon=True)
        t.start()
        t.join(max(0.0, deadline - time.monotonic()))
        if t.is_alive():
            return [], self.status("unavailable", "timeout", ms=_ms(t0))
        exc = box.get("error")
        if exc is None:
            return box["kept"], self.status("ok", added=len(box["kept"]), ms=_ms(t0))
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return [], self.status("unavailable", "timeout", ms=_ms(t0))
        if isinstance(exc, _HttpStatus):
            return [], self.status("unavailable", "http", ms=_ms(t0))
        if isinstance(exc, (ConnectionError, FileNotFoundError)) or (
                isinstance(exc, OSError) and not isinstance(exc, ValueError)):
            return [], self.status("unavailable", "timeout" if "timed out" in str(exc) else "refused", ms=_ms(t0))
        return [], self.status("unavailable", "answer", ms=_ms(t0))

    @staticmethod
    def _keep(text: str, spans: list, occupied: list, deadline: float) -> list:
        """The spans widened to whole words that overlap no occupied span and no span kept before them. Linear in the
        text and the spans (an answer of 10,000 spans over one long word took 4.5 s with a widening per span)."""
        words = _Words(text)
        kept: list = []
        taken: list = []                           # the kept spans, sorted: they never overlap each other
        occ = _merged(occupied)                    # disjoint and sorted: a stored value may lie inside a finding
        ends = [b for _a, b in occ]
        for n, (s, e, type_, score) in enumerate(spans):
            if n % 512 == 0 and time.monotonic() > deadline:
                raise TimeoutError
            s, e = words.widen(s, e)
            if s >= e:
                continue                          # white space only: no word to take
            if _overlaps(occ, ends, s, e):
                continue
            i = bisect.bisect_left(taken, (s, e))
            if (i > 0 and taken[i - 1][1] > s) or (i < len(taken) and taken[i][0] < e):
                continue
            taken.insert(i, (s, e))
            kept.append((s, e, type_, score))
        return kept


class _HttpStatus(Exception):
    pass


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
