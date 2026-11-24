"""A fake name service (hf format) on this computer for the harness scenarios of #105, B11.

It answers each POST with no names. A piece whose text holds `stall_on` waits `stall_s` seconds before the answer:
longer than the wait of one piece, so a long text ends `partial` (the pieces before it checked, the rest not). The
prompt goes to the service too, so the stall follows the text, not the count of requests. `stall_on=""` never waits.
It runs in a thread of the harness; `close()` stops it.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeNer:
    def __init__(self, stall_on: str = "", stall_s: float = 6.0):
        self.received = 0
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                try:
                    text = str(json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)))).get("inputs"))
                except (ValueError, AttributeError):
                    text = ""
                svc.received += 1
                if stall_on and stall_on in text:
                    time.sleep(stall_s)
                out = json.dumps([]).encode()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                except OSError:
                    pass          # the client gave up on this piece

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
