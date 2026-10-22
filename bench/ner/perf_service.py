"""The cost of the PERSON service as a hook would use it (docs/NER-EXPERIMENT.md, "Runtime"): the service of
bench/ner/sidecar.py, asked over its socket by clients as the hook layer asks it. Counts and times only.

    python3 bench/ner/perf_service.py NER_PYTHON BACKEND TEXTS.jsonl OUT.json [--idle-s N]

Measured: the start to the first ready line (a cold start, as after a reboot or an update) and its repeat (a restart,
the files in the page cache); the first request; each document once (median, 95th percentile); 1,000 short requests
in a row; 2, 4 and 8 clients at once (the service answers one at a time); a request after N seconds of idle; one input
of 1 MB; and the peak memory of the service process (ps, resident set)."""
from __future__ import annotations

import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def ask(sock: str, text: str, timeout: float = 120.0) -> float:
    t = time.perf_counter()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock)
    s.sendall((json.dumps({"text": text, "occupied": []}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return (time.perf_counter() - t) * 1000


def rss_mb(pid: int) -> float:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return round(int(out or 0) / 1024, 1)


def start(py: str, backend: str, sock: str):
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "HF_HOME")}
    env.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    t = time.perf_counter()
    p = subprocess.Popen([py, "-I", str(HERE / "sidecar.py"), sock, backend], env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    assert p.stdout.readline().strip() == "ready"
    return p, round(time.perf_counter() - t, 2)


def pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1)))], 1)


def main(argv: list) -> int:
    py, backend, texts_path, out_path = argv[:4]
    idle = int(argv[argv.index("--idle-s") + 1]) if "--idle-s" in argv else 300
    texts = [json.loads(line)["text"] for line in open(texts_path, encoding="utf-8")]
    sock = os.path.join(tempfile.mkdtemp(prefix="ms-ner-perf-"), "s")
    r = {"backend": backend.split("/")[-1] if "onnx" not in backend else backend.rsplit("/", 1)[-1],
         "documents": len(texts)}
    p, r["cold_start_s"] = start(py, backend, sock)
    peak = rss_mb(p.pid)
    r["first_request_ms"] = round(ask(sock, texts[0]), 1)
    times = [ask(sock, t) for t in texts]
    peak = max(peak, rss_mb(p.pid))
    r.update(warm_p50_ms=pct(times, 0.5), warm_p95_ms=pct(times, 0.95), warm_mean_ms=round(statistics.mean(times), 1))
    short = "Please forward the invoice to the team before Friday."
    seq = [ask(sock, short) for _ in range(1000)]
    r.update(sustained_1000_p50_ms=pct(seq, 0.5), sustained_1000_p95_ms=pct(seq, 0.95),
             sustained_first_100_mean=round(statistics.mean(seq[:100]), 2),
             sustained_last_100_mean=round(statistics.mean(seq[-100:]), 2))
    for n in (2, 4, 8):
        lat, lock = [], threading.Lock()

        def client(chunk):
            for t in chunk:
                ms = ask(sock, t)
                with lock:
                    lat.append(ms)
        work = texts[:96]
        t0 = time.perf_counter()
        threads = [threading.Thread(target=client, args=(work[i::n],)) for i in range(n)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        wall = time.perf_counter() - t0
        r[f"clients_{n}"] = {"p50_ms": pct(lat, 0.5), "p95_ms": pct(lat, 0.95),
                             "docs_per_s": round(len(work) / wall, 1)}
        peak = max(peak, rss_mb(p.pid))
    time.sleep(idle)
    r[f"after_idle_{idle}s_ms"] = round(ask(sock, texts[1]), 1)
    big = "\n".join(texts)
    while len(big.encode()) < 1_000_000:
        big += "\n" + big
    big = big.encode()[:1_000_000].decode("utf-8", "ignore")
    r["one_mb_s"] = round(ask(sock, big, timeout=1800) / 1000, 1)
    peak = max(peak, rss_mb(p.pid))
    r["rss_now_mb"] = rss_mb(p.pid)
    r["rss_peak_seen_mb"] = peak
    p.kill()
    p.wait()
    p, r["restart_s"] = start(py, backend, sock)
    r["after_restart_first_ms"] = round(ask(sock, texts[0]), 1)
    p.kill()
    p.wait()
    Path(out_path).write_text(json.dumps(r, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
