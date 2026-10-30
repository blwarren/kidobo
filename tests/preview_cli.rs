#![cfg(unix)]

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use kidobo_adapters::limited_io::{read_bytes_with_limit, read_to_string_with_limit};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const INVENTORY_LIMIT: usize = 16 * 1024 * 1024;
const FEED_URL: &str = "https://feed.example/list";

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    bin: PathBuf,
    tool_log: PathBuf,
}

impl Fixture {
    fn new(config: &str, blocklist: &str) -> Self {
        let temp = TempDir::new().expect("preview fixture");
        let root = temp.path().join("root");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&root).expect("create root");
        for directory in ["config", "data", "cache/remote", "cache/asn"] {
            fs::create_dir_all(root.join(directory)).expect("create fixture directory");
        }
        fs::create_dir_all(&bin).expect("create fake binaries");
        fs::write(root.join("config/config.toml"), config).expect("write config");
        fs::write(root.join("data/blocklist.txt"), blocklist).expect("write blocklist");
        fs::write(root.join("data/temporary-bans.toml"), "version = 1\n")
            .expect("write temporary state");
        fs::write(root.join("cache/sync.lock"), "").expect("write sync lock");
        let fixture = Self {
            tool_log: temp.path().join("tool.log"),
            _temp: temp,
            root,
            bin,
        };
        fixture.write_tool("sudo", "exit 98\n");
        fixture.write_tool("curl", "exit 97\n");
        fixture.write_tool("systemctl", "exit 96\n");
        fixture.write_tool(
            "bgpq4",
            r#"[ "${KIDOBO_TEST_BGPQ4_FAIL:-no}" = "yes" ] && exit 95
case "$1" in
  -4) printf '192.0.2.0/24\n' ;;
  -6) printf '2001:db8::/64\n' ;;
  *) exit 94 ;;
esac
"#,
        );
        for binary in ["ipset", "iptables", "ip6tables"] {
            fixture.write_tool(binary, "exit 92\n");
        }
        fixture
    }

    fn write_tool(&self, name: &str, body: &str) {
        let path = self.bin.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' '{name}' \"$*\" >> \"$KIDOBO_TEST_TOOL_LOG\"\n{body}"
            ),
        )
        .expect("write fake command");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake command");
    }

    fn command(&self, args: &[&str]) -> Command {
        let binary = env::var_os("KIDOBO_TEST_BINARY").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_kidobo")),
            PathBuf::from,
        );
        let mut command = Command::new(binary);
        command
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            // Keep instrumentation output outside the state whose immutability is tested.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env("KIDOBO_ROOT", &self.root)
            .env("PATH", &self.bin)
            .env("KIDOBO_TEST_TOOL_LOG", &self.tool_log)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("LANG", "C.UTF-8")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run Kidobo preview")
    }

    fn run_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        self.command(args)
            .envs(envs.iter().copied())
            .output()
            .expect("run Kidobo preview with fixture environment")
    }

    fn log(&self) -> String {
        read_to_string_with_limit(&self.tool_log, 65_536).unwrap_or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                String::new()
            } else {
                panic!("read fake tool log: {error}");
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryEntry {
    path: String,
    kind: &'static str,
    size: u64,
    mode: u32,
    modified: SystemTime,
    bytes: Option<Vec<u8>>,
}

fn inventory(root: &Path) -> Vec<InventoryEntry> {
    fn walk(root: &Path, directory: &Path, entries: &mut Vec<InventoryEntry>) {
        let mut children = fs::read_dir(directory)
            .expect("inventory directory")
            .map(|entry| entry.expect("inventory entry").path())
            .collect::<Vec<_>>();
        children.sort();
        for path in children {
            let metadata = fs::symlink_metadata(&path).expect("inventory metadata");
            let relative = path
                .strip_prefix(root)
                .expect("inventory path under root")
                .to_string_lossy()
                .into_owned();
            let kind = if metadata.is_dir() {
                "directory"
            } else {
                "file"
            };
            let bytes = if metadata.is_file() {
                Some(read_bytes_with_limit(&path, INVENTORY_LIMIT).expect("bounded inventory read"))
            } else {
                None
            };
            entries.push(InventoryEntry {
                path: relative,
                kind,
                size: metadata.len(),
                mode: metadata.permissions().mode() & 0o7777,
                modified: metadata.modified().expect("inventory modification time"),
                bytes,
            });
            if metadata.is_dir() {
                walk(root, &path, entries);
            }
        }
    }

    let mut entries = Vec::new();
    let metadata = fs::symlink_metadata(root).expect("inventory root metadata");
    entries.push(InventoryEntry {
        path: ".".to_string(),
        kind: "directory",
        size: metadata.len(),
        mode: metadata.permissions().mode() & 0o7777,
        modified: metadata.modified().expect("root modification time"),
        bytes: None,
    });
    walk(root, root, &mut entries);
    entries
}

fn fixture_config(url: Option<&str>, asns: &[u32], include_github: bool) -> String {
    let feeds = url.map_or_else(String::new, |url| format!("urls = ['{url}']\n"));
    let asns = asns
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[ipset]\nset_name = 'kidobo'\nmaxelem = 100\n[safe]\ninclude_github_meta = {include_github}\ngithub_meta_categories = ['api']\n[remote]\n{feeds}timeout_secs = 2\n[asn]\nbanned = [{asns}]\ncache_stale_after_secs = 86400\n"
    )
}

fn write_remote_generation(fixture: &Fixture, url: &str, entries: &str) -> PathBuf {
    let raw = entries.as_bytes();
    let metadata = serde_json::json!({
        "url": url,
        "etag": null,
        "last_modified": null,
        "sha256_raw": kidobo_adapters::hash::sha256_hex(raw),
        "sha256_iplist": kidobo_adapters::hash::sha256_hex(raw),
    })
    .to_string();
    let files = [
        ("iplist", entries.as_bytes()),
        ("meta.json", metadata.as_bytes()),
        ("raw", raw),
    ];
    let mut hasher = Sha256::new();
    for (name, bytes) in files {
        hasher.update(name.len().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(bytes.len().to_le_bytes());
        hasher.update(bytes);
    }
    let generation = kidobo_adapters::hash::hex_lower(&hasher.finalize());
    let store = fixture
        .root
        .join("cache/remote/v2/remote")
        .join(kidobo_adapters::http_cache::url_hash_prefix(url));
    let generation_dir = store.join("generations").join(&generation);
    fs::create_dir_all(&generation_dir).expect("create cache generation");
    fs::write(generation_dir.join("iplist"), entries).expect("write generation iplist");
    fs::write(generation_dir.join("meta.json"), metadata).expect("write generation metadata");
    fs::write(generation_dir.join("raw"), raw).expect("write generation raw data");
    fs::write(
        store.join("current.json"),
        serde_json::json!({"version": 2, "current": generation, "previous": null}).to_string(),
    )
    .expect("write current manifest");
    let orphan = store.join("generations/.staging-orphan-42");
    fs::create_dir_all(&orphan).expect("create orphan cache stage");
    fs::write(orphan.join("sentinel"), "must remain untouched\n").expect("write stage sentinel");
    store
}

fn write_offline_caches(fixture: &Fixture, include_github: bool) {
    write_remote_generation(fixture, FEED_URL, "198.51.100.0/24\n");
    fs::write(
        fixture.root.join("cache/blocklist-normalize.fast-state"),
        "fast-state sentinel\n",
    )
    .expect("write fast-state sentinel");
    fs::write(
        fixture.root.join("cache/asn/as64512.iplist"),
        "# kidobo-asn-cache-v1\n203.0.113.0/24\n",
    )
    .expect("write ASN cache");
    if include_github {
        fs::write(
            fixture.root.join("cache/remote/github-meta.raw.json"),
            r#"{"api":["192.0.2.0/25"]}"#,
        )
        .expect("write GitHub cache");
        fs::write(
            fixture
                .root
                .join("cache/remote/github-meta.categories.json"),
            r#"{"mode":"selected","categories":["api"]}"#,
        )
        .expect("write GitHub category cache");
    }
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
        .saturating_add(3_600);
    fs::write(
        fixture.root.join("data/temporary-bans.toml"),
        format!("version = 1\n[[ips]]\ncidr = '192.0.2.9'\nexpires_at = {expiry}\n"),
    )
    .expect("write active temporary ban");
}

fn write_asn_cache(fixture: &Fixture, asn: u32, prefixes: &str, age: Duration) {
    let path = fixture.root.join(format!("cache/asn/as{asn}.iplist"));
    fs::write(&path, format!("# kidobo-asn-cache-v1\n{prefixes}")).expect("write ASN cache");
    if age != Duration::ZERO {
        let modified = SystemTime::now()
            .checked_sub(age)
            .expect("past cache modification time");
        fs::File::options()
            .write(true)
            .open(path)
            .expect("open ASN cache to age")
            .set_modified(modified)
            .expect("age ASN cache");
    }
}

fn hold_http_once(
    listener: TcpListener,
    release: mpsc::Receiver<()>,
) -> (thread::JoinHandle<()>, mpsc::Receiver<()>) {
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept loopback request");
        read_http_headers(&mut stream);
        accepted_tx.send(()).expect("report accepted request");
        if release.recv_timeout(Duration::from_secs(5)).is_ok() {
            let body = "198.51.100.0/24\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (handle, accepted_rx)
}

fn serve_http_once(listener: TcpListener, status: &str, body: &str) -> thread::JoinHandle<()> {
    let status = status.to_string();
    let body = body.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept loopback feed request");
        read_http_headers(&mut stream);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write loopback response");
    })
}

fn read_http_headers(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set loopback read timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 512];
    while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 16 * 1024 {
        let count = stream.read(&mut buffer).expect("read loopback request");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[test]
fn completions_render_without_reading_config_or_invoking_tools() {
    let fixture = Fixture::new("not valid TOML = [", "");
    let original = read_to_string_with_limit(&fixture.root.join("config/config.toml"), 65_536)
        .expect("read bounded invalid config");

    for (shell, marker) in [
        ("bash", "kidobo"),
        ("zsh", "#compdef kidobo"),
        ("fish", "complete -c kidobo"),
    ] {
        let output = fixture.run(&["completions", shell]);
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 completion");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(output.status.success(), "{shell}: {stderr}");
        assert!(stdout.contains(marker), "{shell}: {stdout}");
        assert!(!stdout.contains('\u{1b}'));
        assert_eq!(stderr, "");
        assert_eq!(fixture.log(), "");

        if shell == "bash" {
            let status = Command::new("bash")
                .arg("-n")
                .arg("-c")
                .arg(&stdout)
                .status()
                .expect("run bash syntax check");
            assert!(status.success(), "generated Bash completion is invalid");
        }
    }

    assert_eq!(
        read_to_string_with_limit(&fixture.root.join("config/config.toml"), 65_536)
            .expect("reread bounded invalid config"),
        original
    );
    fs::remove_file(fixture.root.join("config/config.toml")).expect("remove config fixture");
    let missing_config = fixture.run(&["completions", "fish"]);
    let stdout = String::from_utf8(missing_config.stdout).expect("UTF-8 completion");
    let stderr = String::from_utf8(missing_config.stderr).expect("UTF-8 stderr");
    assert!(missing_config.status.success(), "{stderr}");
    assert!(stdout.contains("complete -c kidobo"));
    assert_eq!(fixture.log(), "");
    assert!(!fixture.root.join("config/config.toml").exists());
}

fn completion_script(fixture: &Fixture, shell: &str) -> String {
    let output = fixture.run(&["completions", shell]);
    assert!(output.status.success(), "{shell}: {output:?}");
    assert_eq!(output.stderr, b"");
    assert_eq!(fixture.log(), "");
    String::from_utf8(output.stdout).expect("UTF-8 completion")
}

fn bash_completion_candidates(
    fixture: &Fixture,
    script: &Path,
    words: &[&str],
) -> (Vec<String>, Vec<String>) {
    let output = Command::new("bash")
        .args(["--noprofile", "--norc", "-c"])
        .arg(
            r#"source "$1"
shift
compopt() { printf '%s\n' "$*" >&2; }
COMP_WORDS=("$@")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
_kidobo "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
if ((${#COMPREPLY[@]})); then
    printf '%s\0' "${COMPREPLY[@]}"
fi
"#,
        )
        .arg("completion-test")
        .arg(script)
        .args(words)
        .current_dir(&fixture.root)
        .env_remove("BASH_ENV")
        .env("LC_ALL", "C")
        .output()
        .expect("exercise generated Bash completion");
    assert!(output.status.success(), "{words:?}: {output:?}");
    let candidates = String::from_utf8(output.stdout)
        .expect("UTF-8 candidates")
        .split_terminator('\0')
        .map(str::to_owned)
        .collect();
    let options = String::from_utf8(output.stderr)
        .expect("UTF-8 completion options")
        .lines()
        .map(str::to_owned)
        .collect();
    (candidates, options)
}

#[test]
fn bash_completions_preserve_file_paths_containing_spaces() {
    let fixture = Fixture::new("", "");
    let script = fixture.root.join("kidobo.bash");
    fs::write(&script, completion_script(&fixture, "bash")).expect("completion script");
    fs::write(fixture.root.join("completion input.targets"), "").expect("target file");

    for command in ["ban", "unban", "lookup"] {
        let (candidates, options) = bash_completion_candidates(
            &fixture,
            &script,
            &["kidobo", command, "--file", "completion"],
        );
        assert_eq!(candidates, ["completion input.targets"], "{command}");
        assert_eq!(options, ["-o filenames"], "{command}");
    }
}

#[test]
fn bash_completions_do_not_offer_files_for_scalar_values() {
    let fixture = Fixture::new("", "");
    let script = fixture.root.join("kidobo.bash");
    fs::write(&script, completion_script(&fixture, "bash")).expect("completion script");
    fs::write(fixture.root.join("completion input.targets"), "").expect("target file");

    for (command, option) in [
        ("ban", "--for"),
        ("ban", "--asn"),
        ("unban", "--asn"),
        ("bans", "--limit"),
    ] {
        let (candidates, options) = bash_completion_candidates(
            &fixture,
            &script,
            &["kidobo", command, option, "completion"],
        );
        assert_eq!(candidates, ["completion"], "{command} {option}");
        assert_eq!(options, ["-o nospace"], "{command} {option}");
    }
}

#[test]
fn zsh_completions_distinguish_files_urls_and_scalar_values() {
    let fixture = Fixture::new("", "");
    let script = completion_script(&fixture, "zsh");
    assert_eq!(script.matches(":PATH:_files").count(), 3);
    assert_eq!(script.matches("':url:_urls'").count(), 2);

    for (label, count) in [
        (":DURATION:", 1),
        (":ASN:", 2),
        (":LIMIT:", 1),
        ("':ip:", 1),
        ("'::ip -- ", 1),
        ("':target:", 2),
        ("'::target -- ", 2),
    ] {
        let arguments: Vec<_> = script.lines().filter(|line| line.contains(label)).collect();
        assert_eq!(arguments.len(), count, "{label}: {arguments:?}");
        for argument in arguments {
            assert!(argument.ends_with(":' \\"), "{argument}");
        }
    }
}

fn fish_completion_option<'a>(script: &'a str, command: &str, option: &str) -> &'a str {
    let context = format!("-n \"__fish_kidobo_using_subcommand {command}\"");
    let option = format!(" -l {option} ");
    script
        .split("complete -c kidobo ")
        .find(|entry| entry.starts_with(&context) && entry.contains(&option))
        .expect("command-specific Fish option")
}

#[test]
fn fish_completions_offer_files_only_for_file_options() {
    let fixture = Fixture::new("", "");
    let script = completion_script(&fixture, "fish");
    for command in ["ban", "unban", "lookup"] {
        let option = fish_completion_option(&script, command, "file");
        assert!(option.trim_end().ends_with(" -r -F"), "{option}");
    }
    for (command, name) in [
        ("ban", "for"),
        ("ban", "asn"),
        ("unban", "asn"),
        ("bans", "limit"),
    ] {
        let option = fish_completion_option(&script, command, name);
        assert!(option.trim_end().ends_with(" -r -f"), "{option}");
    }
}

#[test]
fn completions_preserve_supported_enum_choices() {
    let fixture = Fixture::new("", "");
    let bash = completion_script(&fixture, "bash");
    let zsh = completion_script(&fixture, "zsh");
    let fish = completion_script(&fixture, "fish");
    let script = fixture.root.join("kidobo.bash");
    fs::write(&script, bash).expect("completion script");
    for (prefix, shell) in [("b", "bash"), ("z", "zsh"), ("f", "fish")] {
        let (candidates, options) =
            bash_completion_candidates(&fixture, &script, &["kidobo", "completions", prefix]);
        assert_eq!(candidates, [shell]);
        assert_eq!(options, Vec::<String>::new());
    }
    let (candidates, options) =
        bash_completion_candidates(&fixture, &script, &["kidobo", "--log-level", ""]);
    assert_eq!(candidates, ["trace", "debug", "info", "warn", "error"]);
    assert_eq!(options, Vec::<String>::new());
    assert!(zsh.contains(":shell:(bash zsh fish)"));
    assert!(zsh.contains(":LOG_LEVEL:(trace debug info warn error)"));
    let levels = fish_completion_option(&fish, "completions", "log-level");
    assert!(
        levels.contains(" -r -f -a \"trace\\t''\ndebug\\t''\ninfo\\t''\nwarn\\t''\nerror\\t''\"")
    );

    for (command, formats) in [
        ("status", ["human", "json"]),
        ("check", ["human", "json"]),
        ("doctor", ["human", "json"]),
        ("lookup", ["human", "tsv"]),
    ] {
        let (candidates, options) =
            bash_completion_candidates(&fixture, &script, &["kidobo", command, "--format", ""]);
        assert_eq!(candidates, formats, "{command}");
        assert_eq!(options, Vec::<String>::new());
        let (_, block) = zsh
            .split_once(&format!("\n({command})\n"))
            .expect("Zsh command block");
        let (block, _) = block.split_once("\n;;").expect("end of Zsh command block");
        assert!(block.contains(&format!(":FORMAT:({})", formats.join(" "))));
        let option = fish_completion_option(&fish, command, "format");
        let choices = formats.map(|value| format!("{value}\\t''")).join("\n");
        assert!(
            option.contains(&format!(" -r -f -a \"{choices}\"")),
            "{option}"
        );
    }
}

#[test]
fn preview_rejects_oversized_ipset_timeouts_before_fetch_or_enforcement() {
    for timeout in [2_147_484, 2_592_000] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fetch sentinel");
        let address = listener.local_addr().expect("fetch sentinel address");
        let url = format!("http://{address}/feed");
        let config = fixture_config(Some(&url), &[], false).replace(
            "maxelem = 100",
            &format!("maxelem = 100\ntimeout = {timeout}"),
        );
        let fixture = Fixture::new(&config, "");
        let mut child = fixture
            .command(&["sync", "--dry-run", "--allow-network"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn timeout preview");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut timed_out = false;
        loop {
            if child.try_wait().expect("poll timeout preview").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill stalled timeout preview");
                timed_out = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().expect("reap timeout preview");
        assert!(!timed_out, "ipset.timeout={timeout} preview hung");
        assert_eq!(
            output.status.code(),
            Some(1),
            "ipset.timeout={timeout} should fail config validation: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("ipset.timeout"),
            "missing timeout field diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fixture.log(), "", "validation must precede tool execution");
        listener
            .set_nonblocking(true)
            .expect("make fetch sentinel nonblocking");
        assert!(
            matches!(
                listener.accept(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ),
            "ipset.timeout={timeout} reached the source fetch"
        );
    }
}

#[test]
fn allow_network_requires_a_dry_run_and_usage_errors_do_not_call_tools() {
    let fixture = Fixture::new("[ipset]\nset_name = 'kidobo'\n", "");
    let output = fixture.run(&["sync", "--allow-network"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fixture.log(), "");
}

#[test]
fn offline_preview_uses_validated_local_remote_asn_github_and_temporary_inputs_read_only() {
    let fixture = Fixture::new(
        &fixture_config(Some(FEED_URL), &[64512], true),
        "203.0.113.0/25\n",
    );
    write_offline_caches(&fixture, true);
    let before = inventory(&fixture.root);

    let output = fixture.run(&["sync", "--dry-run"]);
    let after = inventory(&fixture.root);
    let log = fixture.log();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("IPv4"),
        "missing IPv4 preview totals: {stdout}"
    );
    assert!(
        stdout.contains("IPv6"),
        "missing IPv6 preview totals: {stdout}"
    );
    assert!(
        stdout.to_ascii_lowercase().contains("capacity"),
        "missing capacity result: {stdout}"
    );
    assert!(stdout.contains("Source evidence"));
    assert!(stdout.contains("Validated cache"));
    assert!(stdout.contains("AS64512"));
    assert!(stdout.contains("github-metadata"));
    assert!(stdout.contains("Exact live delta unavailable"));
    assert!(!stdout.contains('\u{1b}'));
    assert_eq!(
        before, after,
        "offline preview changed files or filesystem metadata"
    );
    assert_eq!(log, "", "offline preview invoked external tools: {log}");
}

#[test]
fn offline_preview_fails_without_required_asn_cache_without_partial_success() {
    let fixture = Fixture::new(&fixture_config(None, &[64512], false), "203.0.113.0/24\n");
    let before = inventory(&fixture.root);
    let output = fixture.run(&["sync", "--dry-run"]);
    let after = inventory(&fixture.root);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("asn")
    );
    assert!(!stdout.contains("Preview complete"));
    assert_eq!(
        before, after,
        "failed offline preview changed filesystem state"
    );
    let log = fixture.log();
    assert_eq!(log, "", "offline preview invoked external tools: {log}");
}

#[test]
fn preview_rejects_a_family_capacity_excess_without_claiming_success() {
    let config = fixture_config(None, &[], false).replace("maxelem = 100", "maxelem = 1");
    let fixture = Fixture::new(&config, "192.0.2.0/24\n198.51.100.0/24\n2001:db8::/64\n");
    let before = inventory(&fixture.root);
    let output = fixture.run(&["sync", "--dry-run"]);
    let after = inventory(&fixture.root);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("entries=2"), "unexpected error: {stderr}");
    assert!(stderr.contains("maxelem=1"), "unexpected error: {stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Preview completed"));
    assert_eq!(before, after, "capacity failure changed filesystem state");
    assert_eq!(fixture.log(), "");
}

#[test]
fn online_preview_uses_only_the_loopback_feed_and_in_memory_bgpq_result() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback-only test feed");
    let address = listener.local_addr().expect("loopback test feed address");
    let url = format!("http://127.0.0.1:{}/feed", address.port());
    let config = fixture_config(Some(&url), &[64512], false).replace(
        "cache_stale_after_secs = 86400",
        "cache_stale_after_secs = 1",
    );
    let fixture = Fixture::new(&config, "203.0.113.0/24\n");
    write_remote_generation(&fixture, &url, "198.51.100.0/24\n");
    write_asn_cache(
        &fixture,
        64512,
        "203.0.113.0/25\n",
        Duration::from_secs(3_600),
    );
    fs::write(
        fixture.root.join("cache/blocklist-normalize.fast-state"),
        "fast-state sentinel\n",
    )
    .expect("write fast-state sentinel");
    let before = inventory(&fixture.root);
    let server = serve_http_once(listener, "200 OK", "198.51.100.0/24\n");

    let output = fixture.run(&["sync", "--dry-run", "--allow-network"]);
    server.join().expect("join loopback server");
    let after = inventory(&fixture.root);
    let log = fixture.log();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("IPv4"));
    assert!(stdout.contains("IPv6"));
    assert_eq!(
        before, after,
        "network-enabled preview persisted fetched data or changed files"
    );
    assert!(
        log.contains("bgpq4 -4"),
        "stale ASN cache was not refreshed in memory: {log}"
    );
    for forbidden in [
        "curl ",
        "sudo ",
        "systemctl ",
        "ipset ",
        "iptables ",
        "ip6tables ",
    ] {
        assert!(
            !log.contains(forbidden),
            "preview invoked {forbidden}: {log}"
        );
    }
}

#[test]
fn online_preview_failure_does_not_publish_a_fallback_or_partial_totals() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback-only test feed");
    let address = listener.local_addr().expect("loopback test feed address");
    let url = format!("http://127.0.0.1:{}/feed", address.port());
    let fixture = Fixture::new(
        &fixture_config(Some(&url), &[64512], false),
        "203.0.113.0/24\n",
    );
    write_remote_generation(&fixture, &url, "198.51.100.0/24\n");
    fs::write(
        fixture.root.join("cache/blocklist-normalize.fast-state"),
        "fast-state sentinel\n",
    )
    .expect("write fast-state sentinel");
    let before = inventory(&fixture.root);
    let server = serve_http_once(listener, "200 OK", "198.51.100.0/24\n");
    let output = fixture.run_with_env(
        &["sync", "--dry-run", "--allow-network"],
        &[("KIDOBO_TEST_BGPQ4_FAIL", "yes")],
    );
    server.join().expect("join loopback server");
    let after = inventory(&fixture.root);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let log = fixture.log();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("bgpq4"));
    assert!(!stdout.contains("Preview complete"));
    assert_eq!(
        before, after,
        "failed online preview changed filesystem state"
    );
    assert!(log.contains("bgpq4 -4"));
    for forbidden in ["sudo ", "systemctl ", "ipset ", "iptables ", "ip6tables "] {
        assert!(
            !log.contains(forbidden),
            "preview invoked {forbidden}: {log}"
        );
    }
}

#[test]
fn sigint_during_loopback_preview_leaves_all_files_and_metadata_unchanged() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback-only test feed");
    let address = listener.local_addr().expect("loopback test feed address");
    let url = format!("http://127.0.0.1:{}/feed", address.port());
    let fixture = Fixture::new(&fixture_config(Some(&url), &[], false), "203.0.113.0/24\n");
    write_remote_generation(&fixture, &url, "198.51.100.0/24\n");
    fs::write(
        fixture.root.join("cache/blocklist-normalize.fast-state"),
        "fast-state sentinel\n",
    )
    .expect("write fast-state sentinel");
    let before = inventory(&fixture.root);
    let (release_tx, release_rx) = mpsc::channel();
    let (server, accepted_rx) = hold_http_once(listener, release_rx);
    let mut child = fixture
        .command(&["sync", "--dry-run", "--allow-network"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn preview for SIGINT test");
    if let Err(error) = accepted_rx.recv_timeout(Duration::from_secs(5)) {
        let _kill_result = child.kill();
        let _wait_result = child.wait();
        panic!("preview did not issue its local feed request: {error}");
    }
    if let Err(error) = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child pid fits i32")),
        nix::sys::signal::Signal::SIGINT,
    ) {
        let _kill_result = child.kill();
        let _wait_result = child.wait();
        panic!("send SIGINT to child preview process: {error}");
    }
    release_tx
        .send(())
        .expect("release local response after SIGINT");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("inspect preview process") {
            break status;
        }
        if Instant::now() >= deadline {
            let _kill_result = child.kill();
            let _wait_result = child.wait();
            panic!("preview did not stop after SIGINT");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let _output = child
        .wait_with_output()
        .expect("collect interrupted preview output");
    server.join().expect("join loopback server");
    let after = inventory(&fixture.root);

    assert_eq!(status.code(), Some(130));
    assert_eq!(
        before, after,
        "interrupted preview changed files or filesystem metadata"
    );
    let log = fixture.log();
    for forbidden in ["sudo ", "systemctl ", "ipset ", "iptables ", "ip6tables "] {
        assert!(
            !log.contains(forbidden),
            "preview invoked {forbidden}: {log}"
        );
    }
}

#[test]
fn preview_requires_an_existing_uncontended_lock_without_creating_one() {
    let missing = Fixture::new(&fixture_config(None, &[], false), "");
    fs::remove_file(missing.root.join("cache/sync.lock")).expect("remove sync lock");
    let before = inventory(&missing.root);
    let missing_output = missing.run(&["sync", "--dry-run"]);
    assert_eq!(missing_output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing_output.stderr)
            .to_ascii_lowercase()
            .contains("lock")
    );
    assert!(!missing.root.join("cache/sync.lock").exists());
    assert_eq!(before, inventory(&missing.root));
    assert_eq!(missing.log(), "");

    let contended = Fixture::new(&fixture_config(None, &[], false), "");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(contended.root.join("cache/sync.lock"))
        .expect("open sync lock");
    lock.lock_exclusive().expect("hold sync lock");
    let before = inventory(&contended.root);
    let output = contended.run(&["sync", "--dry-run"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("lock")
    );
    assert_eq!(before, inventory(&contended.root));
    assert_eq!(contended.log(), "");
}
