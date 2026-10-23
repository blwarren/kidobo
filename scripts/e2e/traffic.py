#!/usr/bin/env python3
"""Stdlib TCP and HTTP fixtures for guest firewall and source checks."""

import errno
import hashlib
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SERVER_BIND_TIMEOUT_SECONDS = 5.0


def source_handler(feed: Path) -> type[BaseHTTPRequestHandler]:
    """Build a feed handler whose validators change with content, even within a second."""

    class FeedHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Serve the feed with a content ETag and honor conditional requests."""
            if self.path != "/feed.txt":
                self.send_error(404)
                return
            try:
                body = feed.read_bytes()
            except OSError:
                self.send_error(503, "feed unavailable")
                return
            etag = f'"{hashlib.sha256(body).hexdigest()}"'
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("ETag", etag)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return FeedHandler


def serve(address: str, port: int, ready_file: Path) -> None:
    """Listen on an assigned test address and publish readiness after listen."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    deadline = time.monotonic() + SERVER_BIND_TIMEOUT_SECONDS
    try:
        while True:
            try:
                server.bind((address, port))
                break
            except OSError as error:
                if error.errno != errno.EADDRNOTAVAIL or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        server.listen(8)
        ready_file.write_text("ready\n", encoding="utf-8")
        while True:
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"kidobo-e2e\n")
    finally:
        server.close()


def main() -> int:
    usage = "usage: traffic.py serve ADDRESS PORT READY_FILE | probe ADDRESS PORT | source FEED PORT"
    marker = Path("/etc/kidobo-e2e-owned")
    if not marker.is_file() or marker.read_bytes() != b"kidobo-e2e-v1\n":
        raise SystemExit("traffic fixture requires the E2E guest ownership marker")
    if len(sys.argv) < 2 or sys.argv[1] not in {"serve", "probe", "source"}:
        raise SystemExit(usage)
    mode = sys.argv[1]
    expected_args = 5 if mode == "serve" else 4
    if len(sys.argv) != expected_args:
        raise SystemExit(usage)
    address, raw_port = sys.argv[2:4]
    port = int(raw_port)
    if mode == "source":
        with HTTPServer(("127.0.0.1", port), source_handler(Path(address))) as http:
            http.serve_forever()
        return 0
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    if mode == "serve":
        ready_file = Path(sys.argv[4])
        ready_file.unlink(missing_ok=True)
        serve(address, port, ready_file)
    else:
        deadline = time.monotonic() + 3
        last_error = None
        while time.monotonic() < deadline:
            try:
                with socket.socket(family, socket.SOCK_STREAM) as client:
                    client.settimeout(0.4)
                    client.connect((address, port))
                    response = client.recv(32)
                if response != b"kidobo-e2e\n":
                    raise SystemExit("fixture response mismatch")
                return 0
            except OSError as error:
                last_error = error
                time.sleep(0.05)
        print(f"probe failed: {last_error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
