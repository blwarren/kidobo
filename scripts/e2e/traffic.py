#!/usr/bin/env python3
"""Stdlib TCP and HTTP fixtures for guest firewall and source checks."""

from __future__ import annotations

import errno
import hashlib
import json
import shutil
import socket
import socketserver
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SERVER_BIND_TIMEOUT_SECONDS = 5.0
FIXTURE_RESPONSE = b"kidobo-e2e\n"
PROBE_TIMEOUT_SECONDS = 1.0


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
                conn.sendall(FIXTURE_RESPONSE)
    finally:
        server.close()


def probe(
    address: str, port: int, source: str | None = None
) -> tuple[int, dict[str, str]]:
    """Distinguish a dropped connection from fixture or networking failures."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    observation = {
        "address": address,
        "source": source or "default",
        "outcome": "infrastructure-error",
    }
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(PROBE_TIMEOUT_SECONDS)
            if source is not None:
                client.bind((source, 0))
            try:
                client.connect((address, port))
            except TimeoutError:
                observation["outcome"] = "connect-timeout"
                return 10, observation
            deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
            response = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("fixture response deadline exceeded")
                client.settimeout(remaining)
                chunk = client.recv(len(FIXTURE_RESPONSE) + 1 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > len(FIXTURE_RESPONSE):
                    raise ValueError("fixture response is oversized")
            if response != FIXTURE_RESPONSE:
                raise ValueError("fixture response mismatch or premature EOF")
    except (OSError, ValueError) as error:
        observation["error"] = str(error)
        return 20, observation
    observation["outcome"] = "allowed"
    return 0, observation


def irr_handler(log: Path, error_file: Path) -> type[socketserver.StreamRequestHandler]:
    """Build a strict deterministic IRRd protocol endpoint for the packaged resolver."""

    class IrrHandler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            """Answer only the commands used by the actual bgpq4 executable."""
            self.connection.settimeout(5)
            while True:
                raw = self.rfile.readline(4097)
                if not raw:
                    return
                if len(raw) > 4096 or not raw.endswith(b"\n"):
                    error_file.write_text(
                        "invalid IRR request framing\n", encoding="utf-8"
                    )
                    return
                query = raw.decode("ascii", errors="replace").strip()
                with log.open("a", encoding="utf-8") as output:
                    output.write(query + "\n")
                normalized = query.lower()
                if query == "!!":
                    continue
                if normalized == "!q":
                    return
                if normalized == "!s-lc":
                    body = b"TEST\n"
                elif normalized == "!gas13335":
                    body = b"203.0.113.80/32\n"
                elif normalized == "!6as13335":
                    body = b"2001:db8::80/128\n"
                elif normalized.startswith("!nbgpq4 ") or normalized == "!stest":
                    self.wfile.write(b"C\n")
                    self.wfile.flush()
                    continue
                else:
                    error_file.write_text(
                        "unexpected IRR request: " + query + "\n", encoding="utf-8"
                    )
                    self.wfile.write(b"F unsupported fixture query\n")
                    self.wfile.flush()
                    return
                self.wfile.write(
                    b"A" + str(len(body)).encode("ascii") + b"\n" + body + b"C\n"
                )
                self.wfile.flush()

    return IrrHandler


def baseline_download(arguments: list[str], directory: Path, tag: str) -> None:
    """Supply only the two frozen release assets requested by the old installer."""
    if len(arguments) != 4 or arguments[:2] != ["-fsSL", "-o"]:
        raise ValueError("unexpected baseline curl arguments")
    destination, url = arguments[2:]
    prefix = f"https://github.com/blwarren/kidobo/releases/download/{tag}/"
    allowed = {f"kidobo-{tag}-linux-x86_64.tar.gz", "SHA256SUMS"}
    if not url.startswith(prefix) or url[len(prefix) :] not in allowed:
        raise ValueError("unexpected baseline release URL")
    shutil.copyfile(directory / url[len(prefix) :], destination)


def baseline_firewall(directory: Path, program: str, arguments: list[str]) -> int:
    """Keep old-cache generation isolated while satisfying the old wiring contract."""
    if program == "ipset":
        if arguments and arguments[0] == "list":
            print("The set with the given name does not exist", file=sys.stderr)
            return 1
        if arguments and arguments[0] == "restore":
            sys.stdin.read()
        return 0
    if program not in {"iptables", "ip6tables"}:
        raise ValueError("unexpected isolated firewall program")
    args = arguments[2:] if arguments[:2] == ["-w", "5"] else arguments
    if len(args) < 2:
        raise ValueError("unexpected isolated firewall arguments")
    state_file = directory / f"{program}.json"
    chains = (
        json.loads(state_file.read_text(encoding="utf-8"))
        if state_file.exists()
        else {"INPUT": []}
    )
    operation, chain = args[:2]
    rules = chains.setdefault(chain, [])
    if operation == "-S":
        if chain == "INPUT":
            print("-P INPUT ACCEPT")
        for rule in rules:
            print("-A " + chain + " " + " ".join(rule))
        return 0
    if operation == "-A":
        rules.append(args[2:])
    elif operation == "-I":
        rules.insert(int(args[2]) - 1, args[3:])
    elif operation == "-D":
        if args[2].isdigit():
            del rules[int(args[2]) - 1]
        else:
            rules.remove(args[2:])
    elif operation == "-F":
        chains[chain] = []
    elif operation == "-X":
        del chains[chain]
    elif operation == "-N":
        chains[chain] = []
    elif operation == "-C":
        return 0 if args[2:] in rules else 1
    else:
        raise ValueError("unsupported isolated firewall operation")
    state_file.write_text(json.dumps(chains), encoding="utf-8")
    return 0


def main() -> int:
    usage = "usage: traffic.py serve ADDRESS PORT READY_FILE | probe ADDRESS PORT [SOURCE] | source FEED PORT | irr PORT READY LOG ERROR | baseline-download DIRECTORY TAG CURL_ARGS..."
    marker = Path("/etc/kidobo-e2e-owned")
    if not marker.is_file() or marker.read_bytes() != b"kidobo-e2e-v1\n":
        raise SystemExit("traffic fixture requires the E2E guest ownership marker")
    if len(sys.argv) < 2:
        raise SystemExit(usage)
    mode = sys.argv[1]
    if mode == "baseline-firewall" and len(sys.argv) >= 5:
        return baseline_firewall(Path(sys.argv[2]), sys.argv[3], sys.argv[4:])
    if mode == "baseline-download" and len(sys.argv) >= 5:
        baseline_download(sys.argv[4:], Path(sys.argv[2]), sys.argv[3])
        return 0
    if mode == "irr" and len(sys.argv) == 6:
        port, ready, log, errors = sys.argv[2:]
        with socketserver.TCPServer(
            ("127.0.0.1", int(port)), irr_handler(Path(log), Path(errors))
        ) as server:
            Path(ready).write_text("ready\n", encoding="utf-8")
            server.serve_forever()
        return 0
    if mode not in {"serve", "probe", "source"} or len(sys.argv) not in {4, 5}:
        raise SystemExit(usage)
    address, raw_port = sys.argv[2:4]
    port = int(raw_port)
    if mode == "source" and len(sys.argv) == 4:
        with HTTPServer(("127.0.0.1", port), source_handler(Path(address))) as http:
            http.serve_forever()
        return 0
    if mode == "serve" and len(sys.argv) == 5:
        ready_file = Path(sys.argv[4])
        ready_file.unlink(missing_ok=True)
        serve(address, port, ready_file)
        return 0
    if mode == "probe":
        status, observation = probe(
            address, port, sys.argv[4] if len(sys.argv) == 5 else None
        )
        print(json.dumps(observation, sort_keys=True))
        return status
    raise SystemExit(usage)


if __name__ == "__main__":
    raise SystemExit(main())
