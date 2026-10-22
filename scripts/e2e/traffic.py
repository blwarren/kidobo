#!/usr/bin/env python3
"""Tiny stdlib TCP fixture used to observe INPUT policy across a netns veth."""

import socket
import sys
import time
from pathlib import Path


def main() -> int:
    marker = Path("/etc/kidobo-e2e-owned")
    if not marker.is_file() or marker.read_bytes() != b"kidobo-e2e-v1\n":
        raise SystemExit("traffic fixture requires the E2E guest ownership marker")
    if len(sys.argv) != 4 or sys.argv[1] not in {"serve", "probe"}:
        raise SystemExit("usage: traffic.py serve|probe ADDRESS PORT")
    mode, address, raw_port = sys.argv[1:]
    port = int(raw_port)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    if mode == "serve":
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, port))
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"kidobo-e2e\n")
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
