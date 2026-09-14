"""Network containment: every name the sample resolves points back here.

Two tiny stdlib servers run on the host for the duration of a detonation:

  * a DNS server that answers **every** query with the sinkhole address, so the
    sample can never reach a real C2, and
  * an HTTP server that accepts whatever the sample sends and records it.

That combination is what makes local detonation safe on a personal machine: the
malware behaves as though it has connectivity - which is what makes it act at
all - while nothing leaves the host. What would have been exfiltrated is written
down instead of delivered.

DNS responses are hand-assembled; a full resolver is unnecessary when the answer
is always the same address, and it keeps the project dependency-free.
"""
from __future__ import annotations
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from ..config import SINKHOLE_DNS_PORT, SINKHOLE_HTTP_PORT, SINKHOLE_IP


def _decode_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    labels = []
    while offset < len(data) and data[offset]:
        length = data[offset]
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += length + 1
    return ".".join(labels), offset + 1


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if len(data) < 13:
            return
        try:
            host, end = _decode_qname(data)
        except Exception:
            return
        self.server.queries.append(host)                      # type: ignore[attr-defined]
        tid = data[:2]
        question = data[12:end + 4]
        answer = (b"\xc0\x0c"                                  # pointer to the question
                  + struct.pack(">HHIH", 1, 1, 60, 4)          # A, IN, TTL 60, 4 bytes
                  + socket.inet_aton(self.server.sink_ip))     # type: ignore[attr-defined]
        # QR=1, RD/RA set; one question, one answer.
        response = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0) + question + answer
        sock.sendto(response, self.client_address)


class _DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, addr, sink_ip: str) -> None:
        super().__init__(addr, _DNSHandler)
        self.sink_ip = sink_ip
        self.queries: list[str] = []


class _HTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        host = self.headers.get("Host", "").split(":")[0]
        path = self.path
        self.server.requests.append(                           # type: ignore[attr-defined]
            {"method": self.command, "host": host, "path": path[:200]})
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = _record

    def log_message(self, *args: Any) -> None:
        """Silence the default stderr logging."""


class _HTTPServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, addr) -> None:
        super().__init__(addr, _HTTPHandler)
        self.requests: list[dict[str, str]] = []


class Sinkhole:
    """Context manager owning both servers for one detonation."""

    def __init__(self, sink_ip: str = SINKHOLE_IP,
                 dns_port: int = SINKHOLE_DNS_PORT,
                 http_port: int = SINKHOLE_HTTP_PORT) -> None:
        self.sink_ip = sink_ip
        self.dns_port = dns_port
        self.http_port = http_port
        self._dns: _DNSServer | None = None
        self._http: _HTTPServer | None = None
        self.errors: list[str] = []

    def __enter__(self) -> "Sinkhole":
        for name, factory, attr in (
                ("DNS", lambda: _DNSServer(("0.0.0.0", self.dns_port), self.sink_ip), "_dns"),
                ("HTTP", lambda: _HTTPServer(("0.0.0.0", self.http_port)), "_http")):
            try:
                server = factory()
            except OSError as exc:
                # A busy port must not abort the run: the emulator still has no
                # route out, so containment holds - only the record is poorer.
                self.errors.append(f"{name} sinkhole could not start: {exc}")
                continue
            setattr(self, attr, server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: Any) -> None:
        for server in (self._dns, self._http):
            if server is not None:
                server.shutdown()
                server.server_close()

    @property
    def observations(self) -> dict[str, Any]:
        return {
            "dns_queries": list(dict.fromkeys(self._dns.queries)) if self._dns else [],
            "http_requests": list(self._http.requests) if self._http else [],
            "contacted_ips": [self.sink_ip] if (self._http and self._http.requests) else [],
        }
