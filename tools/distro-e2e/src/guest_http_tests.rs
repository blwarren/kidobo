use super::{read_text, tests::TestDir};
use std::fs::{self, FileTimes};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct SourceServer(Child);

impl Drop for SourceServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(port: u16, headers: &str) -> (String, String, String) {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect to HTTP fixture");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("bound HTTP response read");
    write!(
        socket,
        "GET /feed.txt HTTP/1.0\r\nHost: localhost\r\n{headers}\r\n"
    )
    .expect("write HTTP request");
    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .expect("read HTTP response");
    let (headers, body) = response.split_once("\r\n\r\n").expect("HTTP headers");
    let status = headers.lines().next().expect("status line").to_owned();
    let etag = headers
        .lines()
        .find_map(|line| line.strip_prefix("ETag: "))
        .expect("content validator")
        .to_owned();
    (status, etag, body.to_owned())
}

#[test]
fn source_fixture_revalidates_same_timestamp_rewrites_without_sleeping() {
    let temp = TestDir::new();
    let feed = temp.path().join("feed.txt");
    let ready = temp.path().join("port");
    fs::write(&feed, "198.51.100.44\n").expect("initial feed");
    let modified = fs::metadata(&feed)
        .expect("feed metadata")
        .modified()
        .expect("feed timestamp");
    // Import the real handler without the VM-only CLI entry point. The server
    // uses an ephemeral loopback port and only this test's temporary feed.
    let mut server = SourceServer(
        Command::new("python3")
            .args([
                "-c",
                "import runpy, sys\nfrom pathlib import Path\nfrom http.server import HTTPServer\nhandler = runpy.run_path(sys.argv[1])['source_handler'](Path(sys.argv[2]))\nwith HTTPServer(('127.0.0.1', 0), handler) as server:\n Path(sys.argv[3]).write_text(str(server.server_port))\n server.serve_forever()\n",
            ])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/e2e/traffic.py"))
            .arg(&feed)
            .arg(&ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start isolated source fixture"),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let port = loop {
        if let Ok(port) = read_text(&ready)
            && let Ok(port) = port.parse::<u16>()
        {
            break port;
        }
        assert_eq!(server.0.try_wait().expect("source fixture status"), None);
        assert!(
            Instant::now() < deadline,
            "source fixture startup timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let (status, original_etag, body) = request(port, "");
    assert!(status.ends_with("200 OK"));
    assert_eq!(body, "198.51.100.44\n");
    let (status, _, body) = request(port, &format!("If-None-Match: {original_etag}\r\n"));
    assert!(status.ends_with("304 Not Modified"));
    assert_eq!(body, "");

    fs::write(&feed, "198.51.100.46\n").expect("rewrite feed");
    fs::File::options()
        .write(true)
        .open(&feed)
        .expect("open rewritten feed")
        .set_times(FileTimes::new().set_modified(modified))
        .expect("preserve identical modification timestamp");
    let (status, new_etag, body) = request(
        port,
        &format!(
            "If-None-Match: {original_etag}\r\nIf-Modified-Since: Wed, 31 Dec 2098 23:59:59 GMT\r\n"
        ),
    );
    assert!(status.ends_with("200 OK"));
    assert_eq!(body, "198.51.100.46\n");
    assert_ne!(new_etag, original_etag);
    let (status, _, body) = request(port, &format!("If-None-Match: {new_etag}\r\n"));
    assert!(status.ends_with("304 Not Modified"));
    assert_eq!(body, "");
}

#[test]
fn fixture_http_probe_bounds_a_server_that_accepts_without_responding() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stalled HTTP fixture");
    listener.set_nonblocking(true).expect("nonblocking accept");
    let port = listener.local_addr().expect("fixture address").port();
    let (stop, stopping) = mpsc::channel();
    let server = std::thread::spawn(move || {
        loop {
            if let Ok((socket, _)) = listener.accept() {
                let _ = stopping.recv_timeout(Duration::from_secs(5));
                drop(socket);
                break;
            }
            match stopping.recv_timeout(Duration::from_millis(10)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
    });
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = script.find("fixture_curl() {").expect("HTTP probe helper");
    let end = script.find("\nserve_dir() {").expect("end of HTTP probe");
    let output = Command::new("timeout")
        .args(["3", "bash", "-c"])
        .arg(format!(
            "{}\nfixture_curl -fsS 'http://127.0.0.1:{port}/'",
            &script[start..end]
        ))
        .env("http_proxy", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("run real bounded HTTP probe");
    let _ = stop.send(());
    server.join().expect("stop stalled fixture");
    assert_eq!(
        output.status.code(),
        Some(28),
        "curl must time out itself, before the outer guard: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tcp_probe_distinguishes_timeout_refusal_and_response_failures() {
    let output = Command::new("python3")
        .args([
            "-c",
            r"
import runpy, socket, sys
fixture = runpy.run_path(sys.argv[1])
probe = fixture['probe']
class LegacySocketTimeout(OSError): pass
class Client:
 def __init__(self, failure, response): self.failure=failure; self.response=list(response)
 def __enter__(self): return self
 def __exit__(self, *args): return False
 def settimeout(self, value): pass
 def bind(self, address): pass
 def connect(self, address):
  if self.failure: raise self.failure
 def recv(self, count):
  value = self.response.pop(0)
  if isinstance(value, BaseException): raise value
  return value
original = socket.socket
original_timeout = socket.timeout
# Python 3.9 uses a distinct OSError subclass for socket timeouts.
socket.timeout = LegacySocketTimeout
for error, response, expected, outcome in [
 (TimeoutError('drop'), [], 10, 'connect-timeout'),
 (LegacySocketTimeout('timed out'), [], 10, 'connect-timeout'),
 (ConnectionRefusedError('refused'), [], 20, 'infrastructure-error'),
 (OSError('route missing'), [], 20, 'infrastructure-error'),
 (None, [TimeoutError('response timeout')], 20, 'infrastructure-error'),
 (None, [LegacySocketTimeout('timed out')], 20, 'infrastructure-error'),
 (None, [b'kid', b'obo-e2e\n', b''], 0, 'allowed'),
 (None, [b'wrong', b''], 20, 'infrastructure-error'),
 (None, [b'kid', b''], 20, 'infrastructure-error'),
 (None, [b'kidobo-e2e\nextra'], 20, 'infrastructure-error'),
]:
 socket.socket = lambda *args: Client(error, response)
 status, observation = probe('127.0.0.1', 1234, '127.0.0.2')
 assert status == expected, (status, observation)
 assert observation['outcome'] == outcome, observation
def unavailable(*args): raise OSError('address family unavailable')
socket.socket = unavailable
status, observation = probe('::1', 1234)
assert status == 20 and observation['outcome'] == 'infrastructure-error', observation
socket.socket = original
socket.timeout = original_timeout
",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/e2e/traffic.py"
        ))
        .output()
        .expect("exercise actual probe with deterministic sockets");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn irr_fixture_frames_both_families_and_rejects_unknown_requests() {
    let temp = TestDir::new();
    let output = Command::new("python3")
        .args([
            "-c",
            r"
import runpy, socket, socketserver, sys, threading
from pathlib import Path
handler = runpy.run_path(sys.argv[1])['irr_handler']
root = Path(sys.argv[2]); log=root/'protocol'; errors=root/'error'
with socketserver.TCPServer(('127.0.0.1', 0), handler(log, errors)) as server:
 worker=threading.Thread(target=server.handle_request); worker.start()
 with socket.create_connection(server.server_address, timeout=2) as client:
  client.settimeout(2); reader=client.makefile('rb')
  client.sendall(b'!!\n!nbgpq4 test\n!s-lc\n!sTEST\n!gas13335\n!6as13335\n!q\n')
  assert reader.readline() == b'C\n'
  def body(expected):
   size=reader.readline(); assert size.startswith(b'A'), size
   assert reader.read(int(size[1:])) == expected
   assert reader.readline() == b'C\n'
  body(b'TEST\n'); assert reader.readline() == b'C\n'
  body(b'203.0.113.80/32\n'); body(b'2001:db8::80/128\n')
 worker.join(3); assert not worker.is_alive()
 assert not errors.exists()
 worker=threading.Thread(target=server.handle_request); worker.start()
 with socket.create_connection(server.server_address, timeout=2) as client:
  client.settimeout(2); client.sendall(b'!unexpected\n')
  assert client.recv(1024) == b'F unsupported fixture query\n'
 worker.join(3); assert not worker.is_alive()
 assert errors.read_text() == 'unexpected IRR request: !unexpected\n'
 assert '!gas13335\n' in log.read_text() and '!6as13335\n' in log.read_text()
",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/e2e/traffic.py"
        ))
        .arg(temp.path())
        .output()
        .expect("exercise strict IRRd protocol over loopback");
    assert!(output.status.success(), "{output:?}");
}
