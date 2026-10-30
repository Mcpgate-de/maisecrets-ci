"""A reference named-entity service for the remote detector (docs/DETECTION.md, "A remote detector"): the model of
the NER experiment (D3, Davlan/distilbert-base-multilingual-cased-ner-hrl at d421f57d, exported to ONNX by
bench/ner/export_onnx.py) behind the Hugging Face token-classification format. An example, not part of the plugin:
it needs numpy, onnxruntime and tokenizers, which the plugin never installs.

    python examples/ner_service.py ONNX_DIR [--port 8765 | --unix /path/to.sock] [--int8] [--model NAME]

    POST /       {"inputs": text}  ->  [{"entity_group": "PER", "start", "end", "score", "word"}, ...]
    GET  /info   {"model", "file", "sha256", "library", "aggregation"}

It answers the PER spans of bench/ner/person_worker.py (backend onnx:ONNX_DIR), so the remote path and the
experiment see the same spans. It listens on 127.0.0.1 or a Unix socket only, answers one request at a time and
writes no log line with text. Then, in ~/.maisecrets/config.json:

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


def make_handler(find, info: dict):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, doc) -> None:
            body = json.dumps(doc, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 - http.server API
            self._send(200, info) if self.path.rstrip("/") == "/info" else self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802 - http.server API
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            try:
                text = json.loads(self.rfile.read(n))["inputs"]
                if not isinstance(text, str):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": "expected {\"inputs\": text}"})
            spans = find(text)
            self._send(200, [{"entity_group": "PER", "start": s, "end": e, "score": score, "word": text[s:e]}
                             for s, e, score in spans])

        def log_message(self, *args):
            pass                                   # no log line: a request is someone's text

        def address_string(self):
            return "local"
    return Handler


class UnixHTTPServer(socketserver.UnixStreamServer):
    def get_request(self):
        conn, _ = super().get_request()
        return conn, ("local", 0)


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("onnx_dir")
    where = ap.add_mutually_exclusive_group()
    where.add_argument("--port", type=int, default=8765)
    where.add_argument("--unix")
    ap.add_argument("--int8", action="store_true", help="model.int8.onnx: a different model in effect (B1)")
    ap.add_argument("--model", default="Davlan/distilbert-base-multilingual-cased-ner-hrl@d421f57d")
    a = ap.parse_args(argv)
    backend = f"onnx:{a.onnx_dir}" + ("::int8" if a.int8 else "")
    find, desc = person_worker.load(backend)
    model_file = Path(a.onnx_dir) / desc["model"]
    info = {"model": a.model + (" int8" if a.int8 else " fp32"), "file": desc["model"],
            "sha256": hashlib.sha256(model_file.read_bytes()).hexdigest(), "library": desc["library"],
            "library_version": desc["library_version"], "aggregation": desc["aggregation"]}
    handler = make_handler(find, info)
    if a.unix:
        if os.path.exists(a.unix):
            os.unlink(a.unix)
        server = UnixHTTPServer(a.unix, handler)
        os.chmod(a.unix, 0o600)
    else:
        server = HTTPServer(("127.0.0.1", a.port), handler)
    print("ready", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
