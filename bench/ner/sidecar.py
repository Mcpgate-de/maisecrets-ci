"""The NER experiment's local PERSON service (docs/NER-EXPERIMENT.md, "The hook path"): one model, loaded once, on a
Unix socket; one JSON line in ({"text", "occupied"}), one JSON line out ({"add": [[start, end, score], ...]}).

    python -I bench/ner/sidecar.py SOCKET BACKEND [--delay-ms N] [--crash-after N] [--garbage]

BACKEND as for bench/ner/person_worker.py. The three switches exist only to prove what the hook does when the service
is slow, dies or answers nonsense; a product would have none of them. Nothing here opens a network socket."""
from __future__ import annotations

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import person_worker  # noqa: E402


def main(argv: list) -> int:
    path, backend = argv[0], argv[1]
    delay = int(argv[argv.index("--delay-ms") + 1]) / 1000 if "--delay-ms" in argv else 0.0
    crash_after = int(argv[argv.index("--crash-after") + 1]) if "--crash-after" in argv else 0
    garbage = "--garbage" in argv
    find, _desc = person_worker.load(backend)
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    print("ready", flush=True)
    served = 0
    while True:
        conn, _ = srv.accept()
        with conn:
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if crash_after and served >= crash_after:
                os._exit(3)            # the process dies with a request open
            served += 1
            if delay:
                time.sleep(delay)
            if garbage:
                conn.sendall(b'{"add": [[-5, 10000000, 1.0], "x"]\n')
                continue
            try:
                req = json.loads(buf)
                keep, _conflicts = person_worker.disjoint(req["text"], find(req["text"]), req["occupied"])
                conn.sendall((json.dumps({"add": keep}) + "\n").encode())
            except Exception:          # a request it cannot read gets no answer; the client keeps its findings
                pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
