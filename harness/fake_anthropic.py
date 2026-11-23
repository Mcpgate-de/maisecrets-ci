"""A fake Anthropic Messages endpoint for the hook harness.

Claude Code is pointed here with ANTHROPIC_BASE_URL. The server answers
/v1/messages with a scripted sequence of SSE responses (tool_use, then
end_turn) and records EVERY request body to disk. The harness then scans the
bodies: a secret that appears in any body reached "the cloud".

Scenario file (JSON): {"turns": [ {"tool": "Bash", "input": {...}} | {"text": "..."} ]}
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SCENARIO = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {"turns": [{"text": "ok"}]}
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "harness/out"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8791
os.makedirs(OUT_DIR, exist_ok=True)
_lock = threading.Lock()
_state = {"n": 0, "used": set()}


def _last_text(body: bytes) -> str:
    try:
        msgs = json.loads(body).get("messages") or []
    except ValueError:
        return ""
    # the last message of the user: Claude Code 2.1.285 ends a request with system messages of its own
    users = [m for m in msgs if isinstance(m, dict) and m.get("role") == "user"]
    return json.dumps(users[-1]) if users else ""


def _pick(i: int, body: bytes) -> dict:
    """The turn for request i. A scenario whose turns carry `match` is served by content, not by order: a subagent
    in the background sends its requests between those of the session, in no fixed order. A turn with `match` goes
    to the first request whose last message holds that text; a request that matches none takes the next turn
    without `match`."""
    turns = SCENARIO["turns"]
    if not any("match" in t for t in turns):
        return turns[i] if i < len(turns) else {"text": "done"}
    last = _last_text(body)
    with _lock:
        for pick in ([j for j, t in enumerate(turns) if "match" in t and t["match"] in last],
                     [j for j, t in enumerate(turns) if "match" not in t]):
            for j in pick:
                if j not in _state["used"]:
                    _state["used"].add(j)
                    return turns[j]
    return {"text": "done"}


def _sse(events: list[tuple[str, dict]]) -> bytes:
    return b"".join(f"event: {e}\ndata: {json.dumps(d)}\n\n".encode() for e, d in events)


def _response_for(turn: dict, model: str) -> bytes:
    msg = {"id": f"msg_{_state['n']}", "type": "message", "role": "assistant", "model": model,
           "content": [], "stop_reason": None, "stop_sequence": None,
           "usage": {"input_tokens": 10, "output_tokens": 1}}
    ev: list[tuple[str, dict]] = [("message_start", {"type": "message_start", "message": msg})]
    if "tool" in turn:
        ev += [
            ("content_block_start", {
                "type": "content_block_start", "index": 0,
                "content_block": {"type": "tool_use", "id": f"toolu_{_state['n']}", "name": turn["tool"], "input": {}},
            }),
            ("content_block_delta", {
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": json.dumps(turn["input"])},
            }),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {
                "type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 20},
            }),
        ]
    else:
        ev += [
            ("content_block_start", {
                "type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""},
            }),
            ("content_block_delta", {
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": turn.get("text", "ok")},
            }),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {
                "type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 5},
            }),
        ]
    ev.append(("message_stop", {"type": "message_stop"}))
    return _sse(ev)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        if self.path.startswith("/v1/messages/count_tokens"):
            self._json(200, {"input_tokens": 100})
            return
        if not self.path.startswith("/v1/messages"):
            self._json(404, {"error": "nope"})
            return
        with _lock:
            i = _state["n"]
            _state["n"] += 1
        with open(os.path.join(OUT_DIR, f"request_{i:02d}.json"), "wb") as f:
            f.write(body)
        try:
            model = json.loads(body).get("model", "claude")
        except ValueError:
            model = "claude"
        turn = _pick(i, body)
        # a step before the answer: `{"rename": [src, dst]}` moves the plugin folder while the
        # session runs, as a synced plugin update does (anthropics/claude-code#97847)
        for src, dst in [turn["before"]["rename"]] if "rename" in turn.get("before", {}) else []:
            os.rename(src, dst)
        payload = _response_for(turn, model)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        # what api.anthropic.com answers for an account with no policy: a Code Mode scenario reaches this server as
        # api.anthropic.com (harness/tls_front.py), and Code Mode stays off while these two cannot be read
        if self.path.startswith("/api/claude_code/policy_limits"):
            self._json(200, {"restrictions": {}})
            return
        if self.path.startswith("/api/claude_code/settings"):
            self.send_response(204)
            self.end_headers()
            return
        self._json(200, {"ok": True, "requests": _state["n"]})

    def _json(self, code: int, obj: dict) -> None:
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
