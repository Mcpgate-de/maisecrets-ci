"""A proxy that ends TLS for api.anthropic.com and relays to the fake upstream (harness/fake_anthropic.py).

Claude Code starts Code Mode only when it talks to api.anthropic.com itself: with ANTHROPIC_BASE_URL set to another
address it starts the ordinary tools (2.1.330). So a Code Mode scenario of harness/run.py leaves ANTHROPIC_BASE_URL
unset and gives the client HTTPS_PROXY (this proxy) and NODE_EXTRA_CA_CERTS (a test CA made for the run). Every other
host is refused, so nothing leaves the machine.

Usage: tls_front.py LISTEN_PORT UPSTREAM_PORT CERT KEY
"""
from __future__ import annotations

import socket
import ssl
import sys
import threading

HOST = "api.anthropic.com:443"


def _pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _handle(c: socket.socket, ctx: ssl.SSLContext, upstream: int) -> None:
    head = b""
    while b"\r\n\r\n" not in head:
        d = c.recv(4096)
        if not d:
            c.close()
            return
        head += d
    parts = head.split(b"\r\n", 1)[0].decode(errors="replace").split()
    if len(parts) < 2 or parts[0] != "CONNECT" or parts[1] != HOST:
        c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        c.close()
        return
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except (ssl.SSLError, OSError):
        c.close()
        return
    u = socket.create_connection(("127.0.0.1", upstream))
    threading.Thread(target=_pipe, args=(t, u), daemon=True).start()
    _pipe(u, t)


def main() -> None:
    listen, upstream, cert, key = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.listen(50)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle, args=(conn, ctx, upstream), daemon=True).start()


if __name__ == "__main__":
    main()
