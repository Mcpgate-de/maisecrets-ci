"""A reference named-entity service for the remote detector (docs/DETECTION.md, "A remote detector"): the model of
the NER experiment (D3, Davlan/distilbert-base-multilingual-cased-ner-hrl at d421f57d, exported to ONNX by
bench/ner/export_onnx.py) behind the Hugging Face token-classification format. An example, not part of the plugin:
it needs numpy, onnxruntime and tokenizers, which the plugin never installs.

    python examples/ner_service.py ONNX_DIR [--host 127.0.0.1] [--port 8765 | --unix /path/to.sock] [--int8]
        [--model NAME]

    POST /       {"inputs": text}  ->  [{"entity_group": "PER", "start", "end", "score", "word"}, ...]
    POST /       {"inputs": text, "parameters": {"labels": ["PER", "ORG", "LOC"]}}  ->  the spans of those types
    GET  /info   {"model", "file", "sha256", "library", "aggregation", "labels"}
    GET  /health {"status": "ok"}

Without "labels" it answers the PER spans of bench/ner/person_worker.py (backend onnx:ONNX_DIR), so the remote path
and the experiment see the same spans; "labels" asks for other types of the model, those that /info lists. It
listens on 127.0.0.1 or a Unix socket (--host for a container port: the service has no authentication, so bind it
only to a network that only its callers reach), answers one request at a time and writes no log line with text.
Then, in ~/.maisecrets/config.json:

    "remote_detector": {"url": "http://127.0.0.1:8765/", "format": "hf", "model": "<the model of GET /info>"}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bench" / "ner"))
import person_worker  # noqa: E402

MAX_BODY = 4 * 1024 * 1024


def labels_of(doc: dict, known) -> tuple:
    """The entity types a request asks for: PER without "parameters", else its "labels", each one the model knows.
    Raises ValueError on anything else, so a request gets all it asked for or an error, never a part."""
    params = doc.get("parameters")
    if params is None:
        return ("PER",)
    labels = params.get("labels") if isinstance(params, dict) else None
    if not isinstance(labels, list) or not labels or not all(isinstance(x, str) and x in known for x in labels):
        raise ValueError
    return tuple(dict.fromkeys(labels))


def make_handler(find, info: dict):
    """`find(text, labels)` gives (start, end, score, type) per span."""
    known = tuple(info.get("labels") or ("PER",))
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, doc) -> None:
            body = json.dumps(doc, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 - http.server API
            path = self.path.rstrip("/")
            if path == "/info":
                return self._send(200, info)
            if path == "/health":
                return self._send(200, {"status": "ok"})
            self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802 - http.server API
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            try:
                doc = json.loads(self.rfile.read(n))
                text = doc["inputs"]
                if not isinstance(text, str):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": "expected {\"inputs\": text}"})
            try:
                labels = labels_of(doc, known)
            except ValueError:
                return self._send(400, {"error": f"parameters.labels: a non-empty list of {list(known)}"})
            self._send(200, [{"entity_group": t, "start": s, "end": e, "score": score, "word": text[s:e]}
                             for s, e, score, t in find(text, labels)])

        def log_message(self, *args):
            pass                                   # no log line: a request is someone's text

        def address_string(self):
            return "local"
    return Handler


def make_server(handler, host: str = "127.0.0.1", port: int = 8765, unix: str | None = None):
    """The server on a Unix socket (mode 0600) or on host:port."""
    if unix:
        # Windows has no UnixStreamServer, so the class exists only where a socket is asked for
        class UnixHTTPServer(socketserver.UnixStreamServer):
            def get_request(self):
                conn, _ = super().get_request()
                return conn, ("local", 0)

        if os.path.exists(unix):
            os.unlink(unix)
        server = UnixHTTPServer(unix, handler)
        os.chmod(unix, 0o600)
        return server
    return HTTPServer((host, port), handler)


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("onnx_dir")
    where = ap.add_mutually_exclusive_group()
    where.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="the address to bind (0.0.0.0 in a container); the service has no authentication")
    where.add_argument("--unix")
    ap.add_argument("--int8", action="store_true", help="model.int8.onnx: a different model in effect (B1)")
    ap.add_argument("--model", default="Davlan/distilbert-base-multilingual-cased-ner-hrl@d421f57d")
    a = ap.parse_args(argv)
    if a.unix and a.host != "127.0.0.1":
        ap.error("--host binds a TCP port; a Unix socket has no host")
    find, desc = person_worker.onnx_labeled(a.onnx_dir + ("::int8" if a.int8 else ""))
    model_file = Path(a.onnx_dir) / desc["model"]
    info = {"model": a.model + (" int8" if a.int8 else " fp32"), "file": desc["model"],
            "sha256": hashlib.sha256(model_file.read_bytes()).hexdigest(), "library": desc["library"],
            "library_version": desc["library_version"], "aggregation": desc["aggregation"], "labels": desc["labels"]}
    server = make_server(make_handler(find, info), host=a.host, port=a.port, unix=a.unix)
    print("ready", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
