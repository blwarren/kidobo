#!/usr/bin/env python3
"""Tiny stdlib TCP fixture used to observe INPUT policy across a netns veth."""

import errno
import socket
import sys
import time
from pathlib import Path

SERVER_BIND_TIMEOUT_SECONDS = 5.0


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
    marker = Path("/etc/kidobo-e2e-owned")
    if not marker.is_file() or marker.read_bytes() != b"kidobo-e2e-v1\n":
        raise SystemExit("traffic fixture requires the E2E guest ownership marker")
    if len(sys.argv) < 2 or sys.argv[1] not in {"serve", "probe"}:
        raise SystemExit(
            "usage: traffic.py serve ADDRESS PORT READY_FILE | probe ADDRESS PORT"
        )
    mode = sys.argv[1]
    expected_args = 5 if mode == "serve" else 4
    if len(sys.argv) != expected_args:
        raise SystemExit(
            "usage: traffic.py serve ADDRESS PORT READY_FILE | probe ADDRESS PORT"
        )
    address, raw_port = sys.argv[2:4]
    port = int(raw_port)
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
