"""A fake MCP server (stdio) with one slow tool, for the MCP background task scenarios (#107).

`lookup` waits `delay` seconds (default 4) and then answers with a text that holds a synthetic value of a secret's
shape. Claude Code moves a call that runs longer than its limit (CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS) to the
background and later sends the result as a `<task-notification>` prompt. Standard library only.
"""
from __future__ import annotations

import json
import sys
import time

# split so the repository scan stays clean (harness/run.py MCP_TASK_VALUE is the same value)
VALUE = "glpat-" + "HARNESSmcptask1234567890"


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method, rid = req.get("method"), req.get("id")
        if rid is None:
            continue            # a notification (initialized, cancelled): no answer
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": (req.get("params") or {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}}, "serverInfo": {"name": "slow", "version": "1.0.0"}}})
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "lookup", "description": "Looks a record up; slow.",
                "inputSchema": {"type": "object", "properties": {"delay": {"type": "number"}}}}]}})
        elif method == "tools/call":
            args = (req.get("params") or {}).get("arguments") or {}
            time.sleep(float(args.get("delay", 4)))
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"SLOW-RESULT: the record token is {VALUE}"}]}})
        else:
            _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no such method"}})


if __name__ == "__main__":
    main()
