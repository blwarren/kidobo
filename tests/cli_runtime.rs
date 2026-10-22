use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use kidobo_adapters::temporary_bans::{FileTemporaryBanRepository, TEMPORARY_BANS_READ_LIMIT};
use kidobo_app::temporary_bans::TemporaryBanRepository;
use tempfile::TempDir;

const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

fn kidobo_binary() -> PathBuf {
    env::var_os("KIDOBO_TEST_BINARY").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_kidobo")),
        PathBuf::from,
    )
}

fn run_kidobo(args: &[&str]) -> Output {
    Command::new(kidobo_binary())
        .args(args)
        .output()
        .expect("run kidobo")
}

fn kidobo_with_root_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(kidobo_binary());
    command
        .args(args)
        .env("KIDOBO_ROOT", root)
        .env_remove("KIDOBO_TEST_SANDBOX")
        .env_remove("KIDOBO_DISABLE_TEST_SANDBOX");
    command
}

fn run_kidobo_with_root(root: &Path, args: &[&str]) -> Output {
    kidobo_with_root_command(root, args)
        .output()
        .expect("run kidobo with root")
}

fn run_interactive_kidobo<F>(
    root: &Path,
    args: &[&str],
    response: &str,
    after_prompt: F,
) -> (Option<i32>, String, String)
where
    F: FnOnce(&mut std::process::Child),
{
    let mut child = kidobo_with_root_command(root, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn interactive kidobo");
    let mut stdout = child.stdout.take().expect("stdout pipe");
    let mut stderr = child.stderr.take().expect("stderr pipe");
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            match stdout.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    output.push(byte[0]);
                    let _send_result = stdout_tx.send(byte[0]);
                }
                Err(err) => panic!("read child stdout: {err}"),
            }
        }
        output
    });
    let stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).expect("read child stderr");
        output
    });

    let prompt = b"Remove these entries as well? [y/N]: ";
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut observed = Vec::new();
    while !observed.ends_with(prompt) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for unban prompt");
        observed.push(
            stdout_rx
                .recv_timeout(remaining)
                .expect("interactive command ended before prompting"),
        );
    }

    after_prompt(&mut child);
    let mut stdin = child.stdin.take().expect("stdin pipe");
    stdin
        .write_all(response.as_bytes())
        .expect("write prompt response");
    drop(stdin);

    let status = child.wait().expect("wait for interactive kidobo");
    let stdout = stdout_reader.join().expect("join stdout reader");
    let stderr = stderr_reader.join().expect("join stderr reader");
    (
        status.code(),
        String::from_utf8(stdout).expect("UTF-8 stdout"),
        String::from_utf8(stderr).expect("UTF-8 stderr"),
    )
}

fn create_root(config_contents: &str, blocklist_contents: &str) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    fs::create_dir_all(root.join("config")).expect("create config dir");
    fs::create_dir_all(root.join("data")).expect("create data dir");
    fs::create_dir_all(root.join("cache/remote")).expect("create remote cache dir");

    fs::write(root.join("config/config.toml"), config_contents).expect("write config");
    fs::write(root.join("data/blocklist.txt"), blocklist_contents).expect("write blocklist");

    temp
}

fn create_lookup_root(blocklist_contents: &str) -> TempDir {
    create_root("[ipset]\nset_name='kidobo'\n", blocklist_contents)
}

fn create_lookup_root_without_config(blocklist_contents: &str) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    fs::create_dir_all(root.join("data")).expect("create data dir");
    fs::create_dir_all(root.join("cache/remote")).expect("create remote cache dir");
    fs::write(root.join("data/blocklist.txt"), blocklist_contents).expect("write blocklist");

    temp
}

fn create_sync_root(config_contents: &str) -> TempDir {
    create_root(config_contents, "")
}

fn temporary_bans_path(root: &Path) -> PathBuf {
    root.join("data/temporary-bans.toml")
}

fn future_expiry(seconds: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_secs()
        .checked_add(seconds)
        .expect("expiry fits")
}

fn read_to_string_with_limit(path: &Path, limit: usize) -> io::Result<String> {
    let len = fs::metadata(path)?.len();
    if len > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} byte limit"),
        ));
    }

    let mut file = fs::File::open(path)?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(len).expect("file length is within usize limit"));
    file.read_to_end(&mut bytes)?;
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn hold_lock(lock_path: &Path) -> std::fs::File {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock parent");
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .expect("open lock file");

    file.try_lock_exclusive().expect("hold lock");
    file
}

fn path_with_bin_prefix(bin_dir: &Path) -> String {
    match env::var("PATH") {
        Ok(path) if !path.is_empty() => format!("{}:{path}", bin_dir.display()),
        _ => bin_dir.display().to_string(),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the stateful fake command's embedded shell fixture alongside its installation"
)]
fn write_fake_sudo_script(temp: &TempDir) -> PathBuf {
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let script_path = bin_dir.join("sudo");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${KIDOBO_TEST_SUDO_TOUCHED:-}" ]]; then
  : > "${KIDOBO_TEST_SUDO_TOUCHED}"
fi

if [[ -n "${KIDOBO_TEST_SUDO_LOG:-}" ]]; then
  printf '%s\n' "$*" >> "${KIDOBO_TEST_SUDO_LOG}"
fi

if [[ "${KIDOBO_TEST_INTERRUPT_AT_RESTORE:-0}" == "1" && "${2:-}" == "ipset" && "${3:-}" == "restore" && ! -f "${KIDOBO_ROOT}/interrupted-restore" ]]; then
  : > "${KIDOBO_ROOT}/interrupted-restore"
  kill -INT "${PPID}"
  if [[ "${KIDOBO_TEST_FAIL_INTERRUPTED_RESTORE:-0}" == "1" ]]; then
    echo "injected interrupted restore failure" >&2
    exit 9
  fi
fi

if [[ "${KIDOBO_TEST_FAIL_SUDO:-0}" == "1" ]]; then
  echo "injected sudo failure" >&2
  exit 9
fi

if [[ "${KIDOBO_TEST_SLEEP_ONCE:-0}" == "1" ]]; then
  marker="${KIDOBO_TEST_SLEEP_MARKER:-/tmp/kidobo-sudo-sleep.marker}"
  if [[ ! -f "${marker}" ]]; then
    : > "${marker}"
    sleep 2
  fi
fi

if [[ "${1:-}" != "-n" ]]; then
  echo "sudo: expected -n" >&2
  exit 1
fi

cmd="${2:-}"
shift 2

case "${cmd}" in
  ipset)
    case "${1:-}" in
      list|destroy)
        echo "The set with the given name does not exist" >&2
        exit 1
        ;;
      restore)
        if [[ -n "${KIDOBO_TEST_RESTORE_LOG:-}" ]]; then
          cat "${3}" >> "${KIDOBO_TEST_RESTORE_LOG}"
        fi
        exit 0
        ;;
      create)
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  iptables|ip6tables)
    if [[ "${1:-}" == "-w" ]]; then
      shift 2
    fi
    state_dir="${KIDOBO_ROOT:-/tmp}/cache/test-${cmd}"
    input_state="${state_dir}/INPUT"
    mkdir -p "${state_dir}"
    case "${1:-}" in
      -S)
        if [[ "${2:-}" == "INPUT" ]]; then
          if [[ -f "${input_state}" ]]; then
            cat "${input_state}"
          fi
          exit 0
        fi
        chain_state="${state_dir}/${2:-missing}"
        if [[ -f "${chain_state}" ]]; then
          cat "${chain_state}"
          exit 0
        fi
        echo "No chain/target/match by that name" >&2
        exit 1
        ;;
      -N)
        : > "${state_dir}/${2}"
        exit 0
        ;;
      -A)
        chain="${2}"
        shift 2
        printf '%s\n' "-A ${chain} $*" >> "${state_dir}/${chain}"
        exit 0
        ;;
      -I)
        if [[ "${2:-}" == "INPUT" && "${3:-}" == "1" && "${4:-}" == "-j" ]]; then
          temporary="${input_state}.tmp"
          printf '%s\n' "-A INPUT -j ${5}" > "${temporary}"
          if [[ -f "${input_state}" ]]; then
            cat "${input_state}" >> "${temporary}"
          fi
          mv "${temporary}" "${input_state}"
          exit 0
        fi
        exit 2
        ;;
      -F)
        chain_state="${state_dir}/${2}"
        if [[ -f "${chain_state}" ]]; then
          : > "${chain_state}"
          exit 0
        fi
        echo "No chain/target/match by that name" >&2
        exit 1
        ;;
      -D)
        if [[ "${2:-}" == "INPUT" && "${3:-}" == "-j" ]]; then
          if [[ ! -f "${state_dir}/${4}" ]]; then
            echo "${cmd} v1.8.10 (nf_tables): Chain '${4}' does not exist" >&2
            exit 2
          fi
          expected="-A INPUT -j ${4}"
          if [[ -f "${input_state}" ]] && grep -Fxq -- "${expected}" "${input_state}"; then
            temporary="${input_state}.tmp"
            grep -Fvx -- "${expected}" "${input_state}" > "${temporary}" || true
            mv "${temporary}" "${input_state}"
            exit 0
          fi
        elif [[ "${3:-}" == "1" && -s "${state_dir}/${2}" ]]; then
          temporary="${state_dir}/${2}.tmp"
          tail -n +2 "${state_dir}/${2}" > "${temporary}"
          mv "${temporary}" "${state_dir}/${2}"
          exit 0
        fi
        echo "Bad rule (does a matching rule exist in that chain?)." >&2
        exit 1
        ;;
      -X)
        rm -f "${state_dir}/${2}"
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  *)
    exit 0
    ;;
esac
"#,
    )
    .expect("write fake sudo");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod fake sudo");
    }

    script_path
}

fn write_fake_bgpq4_script(temp: &TempDir) -> PathBuf {
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let script_path = bin_dir.join("bgpq4");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${KIDOBO_TEST_BGPQ4_TOUCHED:-}" ]]; then
  : > "${KIDOBO_TEST_BGPQ4_TOUCHED}"
fi

family="${1:-}"

case "${family}" in
  -4)
    printf '203.0.113.0/24\n'
    ;;
  -6)
    printf '2001:db8::/64\n'
    ;;
  *)
    echo "unexpected family flag: ${family}" >&2
    exit 1
    ;;
esac
"#,
    )
    .expect("write fake bgpq4");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod fake bgpq4");
    }

    script_path
}

#[test]
fn flush_cache_only_succeeds_without_config_and_never_invokes_sudo() {
    let root = TempDir::new().expect("tempdir");
    let remote_cache = root.path().join("cache/remote");
    fs::create_dir_all(&remote_cache).expect("mkdir remote cache");
    fs::write(remote_cache.join("cached.iplist"), "198.51.100.0/24\n").expect("write cache");
    fs::create_dir_all(root.path().join("data")).expect("mkdir data directory");
    let temporary_bans = temporary_bans_path(root.path());
    fs::write(&temporary_bans, "version = 1\n").expect("write temporary-ban state");
    let fake_sudo = write_fake_sudo_script(&root);
    let sudo_marker = root.path().join("sudo-touched");

    let mut command = kidobo_with_root_command(root.path(), &["flush", "--cache-only"]);
    command
        .env(
            "PATH",
            path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
        )
        .env("KIDOBO_TEST_SUDO_TOUCHED", &sudo_marker);
    let output = command.output().expect("run cache-only flush");

    assert_eq!(output.status.code(), Some(0));
    assert!(!sudo_marker.exists());
    assert_eq!(
        read_to_string_with_limit(&temporary_bans, TEMPORARY_BANS_READ_LIMIT)
            .expect("temporary-ban state preserved"),
        "version = 1\n"
    );
    assert!(
        fs::read_dir(&remote_cache)
            .expect("read remote cache")
            .next()
            .is_none()
    );
}

#[test]
fn flush_cache_only_ignores_invalid_config() {
    let root = create_root("this is not toml", "");
    let remote_cache = root.path().join("cache/remote");
    fs::write(remote_cache.join("cached.raw"), "raw").expect("write cache");

    let output = run_kidobo_with_root(root.path(), &["flush", "--cache-only"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "cache-only flush unexpectedly parsed config: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::read_dir(&remote_cache)
            .expect("read remote cache")
            .next()
            .is_none()
    );
}

#[test]
fn flush_cache_only_respects_the_nonblocking_lock() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let remote_cache = root.path().join("cache/remote");
    let cached = remote_cache.join("cached.iplist");
    fs::write(&cached, "198.51.100.0/24\n").expect("write cache");
    let _lock = hold_lock(&root.path().join("cache/sync.lock"));

    let output = run_kidobo_with_root(root.path(), &["flush", "--cache-only"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(cached.exists(), "lock failure must leave cache untouched");
}

#[test]
fn flush_succeeds_when_transient_firewall_chain_is_absent() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let temporary_bans = temporary_bans_path(root.path());
    fs::write(&temporary_bans, "version = 1\n").expect("write temporary-ban state");
    let fake_sudo = write_fake_sudo_script(&root);

    let mut command = kidobo_with_root_command(root.path(), &["flush"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let output = command.output().expect("run flush");

    assert_eq!(
        output.status.code(),
        Some(0),
        "flush rejected already-absent transient chains: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_to_string_with_limit(&temporary_bans, TEMPORARY_BANS_READ_LIMIT)
            .expect("temporary-ban state preserved"),
        "version = 1\n"
    );
}

#[test]
fn flush_command_failure_maps_to_one_after_attempting_cache_cleanup() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let remote_cache = root.path().join("cache/remote");
    fs::write(remote_cache.join("cached.iplist"), "198.51.100.0/24\n").expect("write cache");
    let fake_sudo = write_fake_sudo_script(&root);
    let sudo_marker = root.path().join("sudo-touched");

    let mut command = kidobo_with_root_command(root.path(), &["flush"]);
    command
        .env(
            "PATH",
            path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
        )
        .env("KIDOBO_TEST_SUDO_TOUCHED", &sudo_marker)
        .env("KIDOBO_TEST_FAIL_SUDO", "1");
    let output = command.output().expect("run flush");

    assert_eq!(output.status.code(), Some(1));
    assert!(sudo_marker.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("flush cleanup incomplete"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::read_dir(&remote_cache)
            .expect("read remote cache")
            .next()
            .is_none()
    );
}

#[test]
fn help_exits_with_zero() {
    let output = run_kidobo(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn version_exits_with_zero() {
    let output = run_kidobo(&["--version"]);
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "unexpected version output: {stdout}"
    );
}

#[test]
fn usage_error_exits_with_two() {
    let output = run_kidobo(&["lookup"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn lookup_uses_local_sources_and_exits_zero() {
    let root = create_lookup_root("203.0.113.7\n");
    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7", "--format", "tsv"]);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("203.0.113.7\tinternal:blocklist\t203.0.113.7"),
        "unexpected lookup output: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn lookup_ignores_unrelated_non_unicode_environment_values() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let root = create_lookup_root("203.0.113.7\n");
    let output =
        kidobo_with_root_command(root.path(), &["lookup", "203.0.113.7", "--format", "tsv"])
            .env(
                "KIDOBO_TEST_UNRELATED_NON_UNICODE",
                OsString::from_vec(vec![0xff]),
            )
            .output()
            .expect("run lookup with non-Unicode environment value");

    assert_eq!(
        output.status.code(),
        Some(0),
        "lookup panicked: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("203.0.113.7\tinternal:blocklist\t203.0.113.7")
    );
}

#[cfg(unix)]
#[test]
fn lookup_preserves_a_non_unicode_root_path() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join(OsString::from_vec(b"root-\xff".to_vec()));
    fs::create_dir_all(root.join("data")).expect("create data dir");
    fs::create_dir_all(root.join("cache/remote")).expect("create remote cache dir");
    fs::write(root.join("data/blocklist.txt"), "203.0.113.7\n").expect("write blocklist");

    let output = run_kidobo_with_root(&root, &["lookup", "203.0.113.7", "--format", "tsv"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("203.0.113.7\tinternal:blocklist\t203.0.113.7")
    );
}

#[test]
fn lookup_tsv_single_no_match_preserves_empty_legacy_output() {
    let root = create_lookup_root("");
    let output = run_kidobo_with_root(root.path(), &["lookup", "198.51.100.9", "--format", "tsv"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "legacy stdout changed");
}

#[test]
fn lookup_escapes_legacy_cache_labels_in_both_formats() {
    let root = create_lookup_root("");
    fs::write(
        root.path().join("cache/remote/feed.iplist"),
        "203.0.113.7\n",
    )
    .expect("write cache");
    fs::write(
        root.path().join("cache/remote/feed.meta.json"),
        serde_json::json!({"url": "feed\t\u{1b}\\label"}).to_string(),
    )
    .expect("write metadata");
    for format in ["tsv", "human"] {
        let output =
            run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7", "--format", format]);
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
        assert!(
            stdout.contains(r"feed\t\x1B\\label"),
            "unescaped label: {stdout:?}"
        );
        assert!(!stdout.contains('\u{1b}'));
        if format == "tsv" {
            assert_eq!(stdout, "203.0.113.7\tfeed\\t\\x1B\\\\label\t203.0.113.7\n");
        }
    }
}

#[test]
fn lookup_escapes_validated_generation_labels_in_both_formats() {
    use sha2::{Digest, Sha256};
    let root = create_lookup_root("");
    let url = "https://feed.test/\t\u{1b}\\";
    let payload = "203.0.113.7/32\n";
    let checksum = kidobo_adapters::hash::sha256_hex(payload.as_bytes());
    let metadata = serde_json::json!({
        "url": url, "etag": null, "last_modified": null,
        "sha256_raw": checksum, "sha256_iplist": checksum,
    })
    .to_string();
    let files = [
        ("iplist", payload),
        ("meta.json", metadata.as_str()),
        ("raw", payload),
    ];
    let mut hasher = Sha256::new();
    for (name, contents) in files {
        hasher.update(name.len().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(contents.len().to_le_bytes());
        hasher.update(contents.as_bytes());
    }
    let generation = kidobo_adapters::hash::hex_lower(&hasher.finalize());
    let store = root
        .path()
        .join("cache/remote/v2/remote")
        .join(kidobo_adapters::http_cache::url_hash_prefix(url));
    let directory = store.join("generations").join(&generation);
    fs::create_dir_all(&directory).expect("create generation");
    for (name, contents) in files {
        fs::write(directory.join(name), contents).expect("generation member");
    }
    fs::write(
        store.join("current.json"),
        serde_json::json!({
            "version": 2, "current": generation, "previous": null,
        })
        .to_string(),
    )
    .expect("manifest");
    for format in ["tsv", "human"] {
        let output =
            run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7", "--format", format]);
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8");
        assert!(
            stdout.contains(r"https://feed.test/\t\x1B\\"),
            "missing escaped generation label: {stdout:?}"
        );
        assert!(!stdout.contains('\u{1b}'));
        if format == "tsv" {
            assert_eq!(
                stdout,
                "203.0.113.7\thttps://feed.test/\\t\\x1B\\\\\t203.0.113.7/32\n"
            );
        }
    }
}

#[test]
fn lookup_source_loading_failure_emits_no_human_table() {
    let root = create_lookup_root("");
    fs::remove_file(root.path().join("data/blocklist.txt")).expect("remove file");
    fs::create_dir(root.path().join("data/blocklist.txt")).expect("unreadable source");
    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
}

#[cfg(target_os = "linux")]
#[test]
fn lookup_streams_two_million_matches_within_192_mib() {
    use std::fmt::Write as _;
    let mut entries = String::new();
    for index in 0..1_000 {
        writeln!(entries, "10.0.{}.{}/32", index / 256, index % 256).expect("entry");
    }
    let root = create_lookup_root(&entries);
    let mut targets = String::new();
    for index in 0..2_000 {
        writeln!(targets, "192.0.{}.{}/0", index / 256, index % 256).expect("target");
    }
    let target_path = root.path().join("targets.txt");
    fs::write(&target_path, targets).expect("write targets");
    let mut child = Command::new("bash")
        .args(["-c", "ulimit -v 196608; exec \"$@\"", "lookup-memory-test"])
        .arg(kidobo_binary())
        .args(["lookup", "--file"])
        .arg(target_path)
        .args(["--format", "tsv"])
        .env("KIDOBO_ROOT", root.path())
        .env_remove("KIDOBO_TEST_SANDBOX")
        .env_remove("KIDOBO_DISABLE_TEST_SANDBOX")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capped lookup");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("poll capped lookup").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("kill stalled lookup");
            let _status = child.wait();
            panic!("capped lookup exceeded 60 seconds");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("wait capped lookup");
    assert!(
        output.status.success(),
        "capped lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lookup_reports_every_matching_source_without_refreshing_caches() {
    let root = create_root(
        "[ipset]\n\
         set_name = 'kidobo'\n\
         [safe]\n\
         ips = ['198.51.100.0/24', '203.0.113.0/26']\n\
         include_github_meta = true\n\
         github_meta_categories = ['api']\n\
         [asn]\n\
         banned = [64512, 64513]\n",
        "203.0.113.7\n",
    );
    fs::write(
        root.path().join("cache/remote/feed.iplist"),
        "203.0.113.0/25\n",
    )
    .expect("write remote cache");
    fs::write(
        root.path().join("cache/remote/feed.meta.json"),
        r#"{"url":"https://example.com/feed.txt"}"#,
    )
    .expect("write remote metadata");
    fs::write(
        root.path().join("cache/remote/github-meta.raw.json"),
        r#"{"api":["203.0.113.0/27"]}"#,
    )
    .expect("write GitHub cache");
    fs::write(
        root.path().join("cache/remote/github-meta.categories.json"),
        r#"{"mode":"selected","categories":["api"]}"#,
    )
    .expect("write GitHub category cache");
    fs::create_dir_all(root.path().join("cache/asn")).expect("create ASN cache dir");
    fs::write(
        root.path().join("cache/asn/as64513.iplist"),
        "# kidobo-asn-cache-v1\n203.0.113.0/28\n",
    )
    .expect("write ASN cache");

    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    let marker = root.path().join("bgpq4-touched");
    let output =
        kidobo_with_root_command(root.path(), &["lookup", "203.0.113.7", "--format", "tsv"])
            .env(
                "PATH",
                path_with_bin_prefix(fake_bgpq4.parent().expect("fake binary parent")),
            )
            .env("KIDOBO_TEST_BGPQ4_TOUCHED", &marker)
            .output()
            .expect("run lookup");

    assert_eq!(output.status.code(), Some(0));
    assert!(!marker.exists(), "lookup must not invoke bgpq4");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lookup ASN cache unavailable for AS64512"),
        "missing incomplete ASN coverage warning: {stderr}"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "203.0.113.7\tasn:AS64513\t203.0.113.0/28",
            "203.0.113.7\thttps://example.com/feed.txt\t203.0.113.0/25",
            "203.0.113.7\tinternal:blocklist\t203.0.113.7",
            "203.0.113.7\tsafelist:config\t203.0.113.0/26",
            "203.0.113.7\tsafelist:github-meta\t203.0.113.0/27",
        ]
    );
}

#[test]
fn lookup_file_mode_uses_local_sources_and_exits_zero() {
    let root = create_lookup_root("203.0.113.7\n");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n198.51.100.9\n").expect("write lookup targets");
    let target_path = targets.display().to_string();
    let args = vec!["lookup", "--file", target_path.as_str(), "--format", "tsv"];
    let output = run_kidobo_with_root(root.path(), &args);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "203.0.113.7\tinternal:blocklist\t203.0.113.7",
            "198.51.100.9\tNO_MATCH",
            "summary: total_ips=2 matched_ips=1 matched_pct=50%",
        ],
        "file lookup ordering changed: {stdout}"
    );
}

#[test]
fn lookup_file_mode_counts_safelist_and_asn_matches() {
    let root = create_root(
        "[ipset]\n\
         set_name = 'kidobo'\n\
         [safe]\n\
         ips = ['192.0.2.0/24', '198.51.100.0/25']\n\
         include_github_meta = false\n\
         [asn]\n\
         banned = [64512]\n",
        "",
    );
    fs::create_dir_all(root.path().join("cache/asn")).expect("create ASN cache dir");
    fs::write(
        root.path().join("cache/asn/as64512.iplist"),
        "# kidobo-asn-cache-v1\n198.51.100.0/24\n",
    )
    .expect("write ASN cache");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "192.0.2.7\n198.51.100.9\n203.0.113.11\n").expect("write lookup targets");
    let target_path = targets.display().to_string();
    let output = run_kidobo_with_root(
        root.path(),
        &["lookup", "--file", target_path.as_str(), "--format", "tsv"],
    );

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "192.0.2.7\tsafelist:config\t192.0.2.0/24",
            "198.51.100.9\tasn:AS64512\t198.51.100.0/24",
            "198.51.100.9\tsafelist:config\t198.51.100.0/25",
            "203.0.113.11\tNO_MATCH",
            "summary: total_ips=3 matched_ips=2 matched_pct=66%",
        ]
    );
}

#[test]
fn lookup_human_output_shows_matches_no_matches_and_summary() {
    let root = create_lookup_root("203.0.113.7\n");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n198.51.100.9\n").expect("write lookup targets");
    let target_path = targets.display().to_string();
    let output = run_kidobo_with_root(root.path(), &["lookup", "--file", &target_path]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_borders = [
        format!(
            "┌{}┬{}┬{}┬{}┐",
            "─".repeat(32),
            "─".repeat(10),
            "─".repeat(46),
            "─".repeat(32)
        ),
        format!(
            "├{}┼{}┼{}┼{}┤",
            "─".repeat(32),
            "─".repeat(10),
            "─".repeat(46),
            "─".repeat(32)
        ),
        format!(
            "└{}┴{}┴{}┴{}┘",
            "─".repeat(32),
            "─".repeat(10),
            "─".repeat(46),
            "─".repeat(32)
        ),
    ];
    let actual_borders = stdout
        .lines()
        .filter(|line| matches!(line.chars().next(), Some('┌' | '├' | '└')))
        .collect::<Vec<_>>();
    assert_eq!(
        actual_borders,
        expected_borders
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "lookup table borders changed: {stdout}"
    );
    assert!(
        stdout.contains("│ Target"),
        "missing table header: {stdout}"
    );
    assert!(
        stdout.contains("203.0.113.7")
            && stdout.contains("MATCH")
            && stdout.contains("internal:blocklist"),
        "missing match row: {stdout}"
    );
    assert!(
        stdout.contains("198.51.100.9") && stdout.contains("NO MATCH"),
        "missing no-match row: {stdout}"
    );
    assert!(stdout.contains("Summary"), "missing summary: {stdout}");
    assert!(stdout.contains("Targets:    2"), "wrong total: {stdout}");
    assert!(stdout.contains("Matched:    1"), "wrong matches: {stdout}");
    assert!(stdout.contains("Unmatched:  1"), "wrong misses: {stdout}");
    assert!(stdout.contains("Match rate: 50%"), "wrong rate: {stdout}");
    assert!(
        !stdout.contains("\x1b["),
        "redirected human output must not contain ANSI escapes: {stdout:?}"
    );
    assert_eq!(
        stdout,
        format!(
            "{}\n│ {:<30} │ {:<8} │ {:<44} │ {:<30} │\n{}\n│ {:<30} │ {:<8} │ {:<44} │ {:<30} │\n│ {:<30} │ {:<8} │ {:<44} │ {:<30} │\n{}\n\nSummary\n  Targets:    2\n  Matched:    1\n  Unmatched:  1\n  Match rate: 50%\n",
            expected_borders[0],
            "Target",
            "Status",
            "Source",
            "Matched Entry",
            expected_borders[1],
            "198.51.100.9",
            "NO MATCH",
            "—",
            "—",
            "203.0.113.7",
            "MATCH",
            "internal:blocklist",
            "203.0.113.7",
            expected_borders[2],
        )
    );
}

#[test]
fn lookup_human_single_no_match_is_explicit() {
    let root = create_lookup_root("");
    let output = run_kidobo_with_root(root.path(), &["lookup", "198.51.100.9"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("198.51.100.9"), "missing target: {stdout}");
    assert!(stdout.contains("NO MATCH"), "missing status: {stdout}");
    assert!(stdout.contains("Targets:    1"), "missing total: {stdout}");
    assert!(
        stdout.contains("Unmatched:  1"),
        "missing miss count: {stdout}"
    );
}

#[test]
fn lookup_human_wraps_long_source_without_losing_it() {
    let root = create_lookup_root("");
    let source_url = "https://example.com/a/very/long/path/to/a/blocklist/source/feed.txt";
    fs::write(
        root.path().join("cache/remote/feed.iplist"),
        "203.0.113.0/24\n",
    )
    .expect("write remote cache");
    fs::write(
        root.path().join("cache/remote/feed.meta.json"),
        format!(r#"{{"url":"{source_url}"}}"#),
    )
    .expect("write remote metadata");

    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("https://example.com/a/very/long/path/to/a/bl")
            && stdout.contains("ocklist/source/feed.txt"),
        "wrapped source must remain complete: {stdout}"
    );
}

#[test]
fn lookup_invalid_target_exits_with_one() {
    let root = create_lookup_root("203.0.113.7\n");
    let output = run_kidobo_with_root(root.path(), &["lookup", "not-an-ip"]);

    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: not-an-ip"),
        "missing invalid-target message: {stderr}"
    );
    assert!(
        stderr.contains("lookup failed for 1 invalid target(s)"),
        "missing final lookup error message: {stderr}"
    );
}

#[test]
fn lookup_tsv_escapes_target_controls_without_changing_structure() {
    let root = create_lookup_root("203.0.113.7\n");
    let target = "\t203.0.113.7\n";
    let output = run_kidobo_with_root(root.path(), &["lookup", target, "--format", "tsv"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "\\t203.0.113.7\\n\tinternal:blocklist\t203.0.113.7\n"
    );
    assert!(!output.stdout.contains(&0x1b));
}

#[test]
fn lookup_invalid_target_escapes_terminal_control_sequences() {
    let root = create_lookup_root("");
    let target = "bad\x1b]0;owned\x07";
    let output = run_kidobo_with_root(root.path(), &["lookup", target]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: bad\\x1B]0;owned\\x07"),
        "escaped invalid target missing: {stderr:?}"
    );
    assert!(!output.stderr.contains(&0x1b));
    assert!(!output.stderr.contains(&0x07));
}

#[test]
fn lookup_succeeds_without_config_file() {
    let root = create_lookup_root_without_config("203.0.113.7\n");
    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7", "--format", "tsv"]);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lookup config-backed sources unavailable"),
        "missing config coverage warning: {stderr}"
    );
    assert!(
        stdout.contains("203.0.113.7\tinternal:blocklist\t203.0.113.7"),
        "unexpected lookup output: {stdout}"
    );
}

#[test]
fn lookup_succeeds_when_config_is_invalid() {
    let root = create_root("not valid = [", "203.0.113.7\n");
    fs::write(
        root.path().join("cache/remote/feed.iplist"),
        "203.0.113.0/25\n",
    )
    .expect("write remote cache");
    fs::write(
        root.path().join("cache/remote/feed.meta.json"),
        r#"{"url":"https://example.com/feed.txt"}"#,
    )
    .expect("write remote metadata");
    fs::write(
        root.path().join("cache/remote/github-meta.raw.json"),
        r#"{"api":["203.0.113.0/27"]}"#,
    )
    .expect("write GitHub cache");
    fs::write(
        root.path().join("cache/remote/github-meta.categories.json"),
        r#"{"mode":"selected","categories":["api"]}"#,
    )
    .expect("write GitHub category cache");
    fs::create_dir_all(root.path().join("cache/asn")).expect("create ASN cache dir");
    fs::write(
        root.path().join("cache/asn/as64512.iplist"),
        "203.0.113.0/28\n",
    )
    .expect("write ASN cache");

    let output = run_kidobo_with_root(root.path(), &["lookup", "203.0.113.7", "--format", "tsv"]);

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lookup config-backed sources unavailable"),
        "missing config coverage warning: {stderr}"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "203.0.113.7\thttps://example.com/feed.txt\t203.0.113.0/25",
            "203.0.113.7\tinternal:blocklist\t203.0.113.7",
        ],
        "invalid config must not gate legacy sources or activate config-backed caches"
    );
}

#[test]
fn analyze_umbrella_is_rejected_as_a_usage_error() {
    let output = run_kidobo(&["analyze", "overlap"]);
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand 'analyze'"),
        "unexpected usage error: {stderr}"
    );
}

#[test]
fn sync_reports_config_parse_error_before_lock_check() {
    let root = create_sync_root("not valid = [");
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));

    let output = run_kidobo_with_root(root.path(), &["sync"]);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config parse/validation failed"),
        "missing config parse failure in stderr: {stderr}"
    );
    assert!(
        !stderr.contains("lock already held"),
        "sync acquired lock before config parse: {stderr}"
    );
}

#[test]
fn sync_lock_held_fails_before_invoking_sudo() {
    let root = create_sync_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
    );
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));
    let fake_sudo = write_fake_sudo_script(&root);
    let touched = root.path().join("sudo-touched");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    let output = command.output().expect("run sync with held lock");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock already held"),
        "missing lock-held error message: {stderr}"
    );
    assert!(
        !touched.exists(),
        "side-effect command runner was invoked before lock failure"
    );
}

#[test]
fn invalid_configuration_prevents_all_blocklist_mutations() {
    for config in [
        "not valid = [",
        "unknown_key = true",
        "[ipset]\nmaxelem=0\n",
    ] {
        for command in [
            vec!["ban", "203.0.113.7"],
            vec!["unban", "203.0.113.7"],
            vec!["ban", "--file"],
            vec!["unban", "--file"],
            vec!["unban", "--asn", "64500"],
        ] {
            let initial = "203.0.113.0/24\n";
            let root = create_root(config, initial);
            let targets = root.path().join("targets.txt");
            fs::write(&targets, "203.0.113.7\n").expect("targets");
            let asn_cache = root.path().join("cache/asn/64500.iplist");
            fs::create_dir_all(asn_cache.parent().expect("parent")).expect("asn dir");
            fs::write(&asn_cache, initial).expect("asn cache");
            let mut args = command;
            if args.last() == Some(&"--file") {
                args.push(targets.to_str().expect("UTF-8 fixture"));
            }
            let output = run_kidobo_with_root(root.path(), &args);
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("config parse/validation failed")
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("[y/N]"));
            assert_eq!(
                read_to_string_with_limit(
                    &root.path().join("data/blocklist.txt"),
                    BLOCKLIST_READ_LIMIT
                )
                .expect("blocklist"),
                initial
            );
            assert_eq!(
                read_to_string_with_limit(&root.path().join("config/config.toml"), 65536)
                    .expect("config"),
                config
            );
            assert_eq!(
                read_to_string_with_limit(&asn_cache, 1024).expect("cache"),
                initial
            );
        }
    }
}

#[test]
fn unban_revalidates_configuration_after_the_prompt() {
    let initial = "203.0.113.0/24\n";
    let root = create_lookup_root(initial);
    let (code, _, stderr) =
        run_interactive_kidobo(root.path(), &["unban", "203.0.113.7"], "yes\n", |_| {
            fs::write(
                root.path().join("config/config.toml"),
                "[ipset]\nmaxelem=0\n",
            )
            .expect("invalidate config");
        });
    assert_eq!(code, Some(1));
    assert!(stderr.contains("config parse/validation failed"));
    assert_eq!(
        read_to_string_with_limit(
            &root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("blocklist"),
        initial
    );
}

#[test]
fn sigint_cancels_idle_and_partial_unban_prompts_without_mutating() {
    for partial in ["", "y"] {
        let initial = "203.0.113.0/24\n203.0.113.7\n";
        let root = create_lookup_root(initial);
        let (code, stdout, stderr) =
            run_interactive_kidobo(root.path(), &["unban", "203.0.113.7"], "", |child| {
                child
                    .stdin
                    .as_mut()
                    .expect("stdin")
                    .write_all(partial.as_bytes())
                    .expect("partial response");
                assert!(
                    Command::new("kill")
                        .args(["-INT", &child.id().to_string()])
                        .status()
                        .expect("SIGINT")
                        .success()
                );
                let deadline = Instant::now() + Duration::from_secs(2);
                while child.try_wait().expect("poll child").is_none() {
                    if Instant::now() >= deadline {
                        child.kill().expect("kill hung fixture");
                        child.wait().expect("reap fixture");
                        panic!("SIGINT did not cancel the prompt while stdin remained open");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            });
        assert_eq!(code, Some(130), "{stderr}");
        assert!(!stdout.contains("removed "));
        assert_eq!(
            read_to_string_with_limit(
                &root.path().join("data/blocklist.txt"),
                BLOCKLIST_READ_LIMIT
            )
            .expect("blocklist"),
            initial
        );
    }
}

#[test]
fn sync_full_families_emit_supported_restore_entries() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=true\nmaxelem=2\n[safe]\ninclude_github_meta=false\n",
        "0.0.0.0/1\n128.0.0.0/1\n::/1\n8000::/1\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let restore_log = root.path().join("restore.log");
    let output = kidobo_with_root_command(root.path(), &["sync"])
        .env(
            "PATH",
            path_with_bin_prefix(fake_sudo.parent().expect("bin")),
        )
        .env("KIDOBO_TEST_RESTORE_LOG", &restore_log)
        .output()
        .expect("sync");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let scripts = read_to_string_with_limit(&restore_log, 65536).expect("restore scripts");
    let entries: Vec<_> = scripts
        .lines()
        .filter_map(|line| {
            line.strip_prefix("add ")
                .map(|entry| entry.split_once(' ').expect("set and network").1)
        })
        .collect();
    assert_eq!(
        entries,
        vec!["::/1", "8000::/1", "0.0.0.0/1", "128.0.0.0/1"]
    );
    let creates: Vec<_> = scripts
        .lines()
        .filter(|line| line.starts_with("create "))
        .collect();
    assert_eq!(creates.len(), 2);
    assert!(creates[0].contains("hash:net family inet6 "));
    assert!(creates[1].contains("hash:net family inet "));
}

#[cfg(unix)]
#[test]
fn sync_preserves_non_unicode_restore_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=true\n[safe]\ninclude_github_meta=false\n",
        "203.0.113.0/24\n2001:db8::/64\n",
    );
    let temporary = root.path().join(OsString::from_vec(b"tmp-\xff".to_vec()));
    fs::create_dir(&temporary).expect("create non-Unicode temporary directory");
    let fake_sudo = write_fake_sudo_script(&root);
    let restore_log = root.path().join("restore.log");
    let output = kidobo_with_root_command(root.path(), &["sync"])
        .env("TMPDIR", &temporary)
        .env(
            "PATH",
            path_with_bin_prefix(fake_sudo.parent().expect("bin")),
        )
        .env("KIDOBO_TEST_RESTORE_LOG", &restore_log)
        .output()
        .expect("sync with non-Unicode temporary directory");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let scripts = read_to_string_with_limit(&restore_log, 65536).expect("restore scripts");
    let entries: Vec<_> = scripts
        .lines()
        .filter_map(|line| {
            line.strip_prefix("add ")
                .map(|entry| entry.split_once(' ').expect("set and CIDR").1)
        })
        .collect();
    assert_eq!(entries, ["2001:db8::/64", "203.0.113.0/24"]);
    assert_eq!(
        scripts
            .lines()
            .filter(|line| line.starts_with("swap "))
            .count(),
        2
    );
    assert_eq!(
        fs::read_dir(&temporary)
            .expect("read temporary directory")
            .count(),
        0
    );
}

#[test]
fn sigint_during_first_replacement_finishes_enforcement_and_preserves_failures() {
    for fail in [false, true] {
        let root = create_root(
            "[ipset]\nset_name='kidobo'\nenable_ipv6=true\n[safe]\ninclude_github_meta=false\n",
            "203.0.113.0/24\n2001:db8::/64\n",
        );
        let fake_sudo = write_fake_sudo_script(&root);
        let log = root.path().join("sudo.log");
        let output = kidobo_with_root_command(root.path(), &["sync"])
            .env(
                "PATH",
                path_with_bin_prefix(fake_sudo.parent().expect("parent")),
            )
            .env("KIDOBO_TEST_SUDO_LOG", &log)
            .env("KIDOBO_TEST_INTERRUPT_AT_RESTORE", "1")
            .env(
                "KIDOBO_TEST_FAIL_INTERRUPTED_RESTORE",
                if fail { "1" } else { "0" },
            )
            .output()
            .expect("fixture sync");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(130), "{stderr}");
        assert!(!stderr.contains("sync completed:"));
        let log = read_to_string_with_limit(&log, 65536).expect("command log");
        if fail {
            assert!(
                stderr.contains("injected interrupted restore failure"),
                "{stderr}"
            );
            assert_eq!(
                log.lines()
                    .filter(|line| line.contains("ipset restore"))
                    .count(),
                1
            );
        } else {
            assert_eq!(
                log.lines()
                    .filter(|line| line.contains("ipset restore"))
                    .count(),
                2
            );
            for family in ["iptables", "ip6tables"] {
                let state = root.path().join(format!("cache/test-{family}/INPUT"));
                assert_eq!(
                    read_to_string_with_limit(&state, 65536).expect("INPUT"),
                    "-A INPUT -j kidobo-input\n"
                );
            }
        }
    }
}

#[test]
fn sync_sigint_exits_with_130() {
    let root = create_sync_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let touched = root.path().join("sudo-touched");
    let sleep_marker = root.path().join("sudo-sleep-once.marker");
    let command_log = root.path().join("sudo.log");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    command.env("KIDOBO_TEST_SLEEP_ONCE", "1");
    command.env("KIDOBO_TEST_SLEEP_MARKER", &sleep_marker);
    command.env("KIDOBO_TEST_SUDO_LOG", &command_log);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let child = command.spawn().expect("spawn sync");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sleep_marker.exists() {
        assert!(
            Instant::now() < deadline,
            "sync did not enter the fake runner"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let signal_status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signal_status.success(), "failed to deliver SIGINT");

    let output = child.wait_with_output().expect("wait for sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(130),
        "expected SIGINT exit code 130, stderr:\n{stderr}"
    );
    assert!(
        touched.exists(),
        "test did not reach command execution before SIGINT"
    );
    let commands = read_to_string_with_limit(&command_log, 65536).expect("command log");
    assert!(!commands.contains("ipset restore"));
    assert!(!commands.contains("-I INPUT"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "keep the feed, bounded child wait, and warning assertions in one deadlock regression"
)]
fn sync_remote_worker_warning_does_not_deadlock() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind remote feed listener");
    listener
        .set_nonblocking(true)
        .expect("set remote feed listener nonblocking");
    let address = listener.local_addr().expect("remote feed listener address");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for remote feed request"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept remote feed request: {error}"),
            }
        };
        let mut request = [0_u8; 1024];
        let _bytes_read = socket.read(&mut request).expect("read remote feed request");
        let body = b"ip,score\n161.117.138.100,0.164985\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket
            .write_all(response.as_bytes())
            .and_then(|()| socket.write_all(body))
            .expect("write remote feed response");
    });
    let root = create_sync_root(&format!(
        "[ipset]\n\
         set_name='kidobo'\n\
         enable_ipv6=false\n\
         [remote]\n\
         urls=['http://{address}/feed.csv']\n\
         timeout_secs=5\n\
         [safe]\n\
         include_github_meta=false\n"
    ));
    let fake_sudo = write_fake_sudo_script(&root);

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command
        .env(
            "PATH",
            path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn sync with warning feed");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .expect("poll sync with warning feed")
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill deadlocked sync");
            let output = child.wait_with_output().expect("reap deadlocked sync");
            panic!(
                "sync did not finish within five seconds: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }

    let output = child.wait_with_output().expect("collect warning-feed sync");
    server.join().expect("join remote feed server");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "warning-feed sync failed: {stderr}"
    );
    assert!(
        stderr.contains("ignored 1 invalid line(s)"),
        "missing remote parser warning: {stderr}"
    );
    assert!(
        stderr.contains("sync completed: ipv4_entries=1 ipv6_entries=0"),
        "missing sync completion: {stderr}"
    );

    let remote_cache = root.path().join("cache/remote");
    let cached_sources = kidobo_adapters::cached_sources::load_remote_sources(&remote_cache)
        .expect("load cached remote sources");
    assert_eq!(cached_sources.len(), 1);
    assert!(
        cached_sources[0]
            .path
            .starts_with(remote_cache.join("v2/remote"))
    );
    assert_eq!(cached_sources[0].entries.len(), 1);
    assert_eq!(
        cached_sources[0].entries[0].cidr.to_string(),
        "161.117.138.100/32"
    );
}

#[test]
fn sync_skips_local_blocklist_normalization_when_unchanged() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
        "203.0.113.7\n203.0.113.0/24\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let sidecar = root.path().join("cache/blocklist-normalize.fast-state");
    let blocklist = root.path().join("data/blocklist.txt");
    let expected_canonical = "203.0.113.0/24\n";

    let mut first = kidobo_with_root_command(root.path(), &["sync"]);
    first.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let first_output = first.output().expect("run first sync");
    assert_eq!(
        first_output.status.code(),
        Some(0),
        "first sync failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(
        sidecar.exists(),
        "fast-state sidecar was not created at {}",
        sidecar.display()
    );
    let first_blocklist = read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT)
        .expect("read canonicalized blocklist");
    assert_eq!(first_blocklist, expected_canonical);

    let mut second = kidobo_with_root_command(root.path(), &["sync"]);
    second.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let second_output = second.output().expect("run second sync");
    assert_eq!(
        second_output.status.code(),
        Some(0),
        "second sync failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    let second_stderr = String::from_utf8_lossy(&second_output.stderr);
    assert!(
        second_stderr.contains("sync blocklist normalization skipped: unchanged path="),
        "missing unchanged-blocklist skip log in second sync stderr: {second_stderr}"
    );

    let second_blocklist = read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT)
        .expect("read blocklist after second sync");
    assert_eq!(second_blocklist, expected_canonical);
}

#[test]
fn sync_normalization_drops_non_header_comments() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
        "# header comment \n203.0.113.7\n# dropped comment\n203.0.113.0/24\n",
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let blocklist = root.path().join("data/blocklist.txt");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let output = command.output().expect("run sync");
    assert_eq!(
        output.status.code(),
        Some(0),
        "sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let normalized =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(normalized, "# header comment\n\n203.0.113.0/24\n");
}

#[test]
fn sync_rejects_invalid_local_blocklist_without_rewriting_file() {
    let original = "# header comment\n203.0.113.7 trailing-junk\n";
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
        original,
    );
    let fake_sudo = write_fake_sudo_script(&root);
    let blocklist = root.path().join("data/blocklist.txt");

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let output = command.output().expect("run sync");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid blocklist entry in"),
        "missing invalid blocklist error: {stderr}"
    );
    assert!(stderr.contains("line 2"), "missing line number: {stderr}");
    assert!(
        stderr.contains("203.0.113.7 trailing-junk"),
        "missing offending line: {stderr}"
    );

    let after =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(after, original);
}

#[test]
fn sync_oversized_blocklist_fails_with_read_error() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\ninclude_github_meta=false\n",
        &"1".repeat(BLOCKLIST_READ_LIMIT + 1),
    );
    let fake_sudo = write_fake_sudo_script(&root);

    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let output = command.output().expect("run sync");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read blocklist file"),
        "missing blocklist read error: {stderr}"
    );
    assert!(
        stderr.contains("file exceeds 16777216 byte limit"),
        "missing size-limit detail: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn sync_unreadable_blocklist_stops_before_enforcement() {
    let root = create_sync_root("[ipset]\nset_name='kidobo'\n[safe]\ninclude_github_meta=false\n");
    let blocklist = root.path().join("data/blocklist.txt");
    fs::remove_file(&blocklist).expect("remove blocklist");
    std::os::unix::fs::symlink("blocklist.txt", &blocklist).expect("blocklist loop");
    let fake_sudo = write_fake_sudo_script(&root);
    let log = root.path().join("sudo.log");
    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_LOG", &log);

    let output = command.output().expect("run isolated sync");

    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to read blocklist file"));
    let commands = read_to_string_with_limit(&log, 64 * 1024).expect("commands");
    for command in commands.lines() {
        let args = command.split_whitespace().collect::<Vec<_>>();
        assert!(
            !args.contains(&"restore") && !args.contains(&"swap") && !args.contains(&"destroy"),
            "unexpected replacement: {command}"
        );
        assert!(
            !["-A", "-I", "-D", "-F", "-X", "-R"]
                .iter()
                .any(|operation| args.contains(operation)),
            "unexpected activation: {command}"
        );
    }
    assert_eq!(
        fs::read_link(&blocklist).expect("preserved blocklist"),
        Path::new("blocklist.txt")
    );
    assert!(!root.path().join("cache/remote/v2").exists());
}

#[cfg(unix)]
#[test]
fn optional_config_inspection_failure_keeps_lookup_and_cache_only_flush_usable() {
    let root = create_lookup_root("203.0.113.7\n");
    let config = root.path().join("config/config.toml");
    fs::remove_file(&config).expect("remove config");
    std::os::unix::fs::symlink("config.toml", &config).expect("config loop");
    let fake_sudo = write_fake_sudo_script(&root);
    let touched = root.path().join("sudo-touched");
    let mut command = kidobo_with_root_command(root.path(), &["lookup", "203.0.113.7"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    let output = command.output().expect("offline lookup");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("MATCH"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to read config file"));

    let mut command = kidobo_with_root_command(root.path(), &["flush", "--cache-only"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    command.env("KIDOBO_TEST_SUDO_TOUCHED", &touched);
    let output = command.output().expect("cache-only flush");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !touched.exists(),
        "offline operations must not execute sudo"
    );
    assert_eq!(
        fs::read_link(&config).expect("preserved config"),
        Path::new("config.toml")
    );
}

#[cfg(unix)]
#[test]
fn doctor_reports_path_inspection_failure_without_mutating_it() {
    let root = create_lookup_root("203.0.113.7\n");
    let blocklist = root.path().join("data/blocklist.txt");
    fs::remove_file(&blocklist).expect("remove blocklist");
    std::os::unix::fs::symlink("blocklist.txt", &blocklist).expect("blocklist loop");
    let fake_sudo = write_fake_sudo_script(&root);
    let mut command = kidobo_with_root_command(root.path(), &["doctor"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );

    let output = command.output().expect("isolated doctor");

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(report["overall"], "FAIL");
    let check = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "file_blocklist")
        .expect("blocklist check");
    assert_eq!(check["status"], "FAIL");
    assert!(
        check["detail"]
            .as_str()
            .expect("detail")
            .starts_with("failed to inspect ")
    );
    assert_eq!(
        fs::read_link(&blocklist).expect("preserved blocklist"),
        Path::new("blocklist.txt")
    );
}

#[test]
fn doctor_forced_human_color_emits_ansi_level_label() {
    let root = create_lookup_root("203.0.113.7\n");
    let mut command = kidobo_with_root_command(root.path(), &["doctor"]);
    command
        .env("KIDOBO_LOG_FORMAT", "human")
        .env("KIDOBO_LOG_COLOR", "always")
        .env_remove("NO_COLOR");
    let output = command.output().expect("run doctor with forced color");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("\u{1b}[32mINFO\u{1b}[0m: doctor summary: overall="),
        "missing ANSI-colored INFO label in stderr (status {:?}): {stderr}",
        output.status.code()
    );
}

#[test]
fn ban_and_unban_target_flow_is_idempotent_and_updates_blocklist() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");

    let first_ban = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7"]);
    assert_eq!(
        first_ban.status.code(),
        Some(0),
        "first ban failed: {}",
        String::from_utf8_lossy(&first_ban.stderr)
    );
    let first_stdout = String::from_utf8_lossy(&first_ban.stdout);
    assert!(
        first_stdout.contains("added blocklist entry 203.0.113.7/32"),
        "unexpected first ban output: {first_stdout}"
    );

    let second_ban = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7"]);
    assert_eq!(
        second_ban.status.code(),
        Some(0),
        "second ban failed: {}",
        String::from_utf8_lossy(&second_ban.stderr)
    );
    let second_stdout = String::from_utf8_lossy(&second_ban.stdout);
    assert!(
        second_stdout.contains("blocklist already contains 203.0.113.7/32"),
        "unexpected second ban output: {second_stdout}"
    );

    let unban = run_kidobo_with_root(root.path(), &["unban", "203.0.113.7"]);
    assert_eq!(
        unban.status.code(),
        Some(0),
        "unban failed: {}",
        String::from_utf8_lossy(&unban.stderr)
    );
    let unban_stdout = String::from_utf8_lossy(&unban.stdout);
    assert!(
        unban_stdout.contains("removed 1 blocklist entries for 203.0.113.7/32"),
        "unexpected unban output: {unban_stdout}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(contents.is_empty(), "blocklist should be empty: {contents}");
}

#[test]
fn ban_rejects_target_with_trailing_junk() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");

    let output = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7 trailing-junk"]);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to parse blocklist target 203.0.113.7 trailing-junk"),
        "missing parse error: {stderr}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(
        contents.is_empty(),
        "blocklist should remain empty: {contents}"
    );
}

#[test]
fn unban_rejects_target_with_trailing_junk() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "203.0.113.7/32\n");
    let blocklist = root.path().join("data/blocklist.txt");

    let output = run_kidobo_with_root(root.path(), &["unban", "203.0.113.7 trailing-junk"]);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to parse blocklist target 203.0.113.7 trailing-junk"),
        "missing parse error: {stderr}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(contents, "203.0.113.7/32\n");
}

#[test]
fn ban_file_mode_updates_blocklist_and_preserves_per_target_results() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n198.51.100.0/24\n203.0.113.7\n").expect("write targets");
    let target_path = targets.display().to_string();
    let args = vec!["ban", "--file", target_path.as_str()];

    let output = run_kidobo_with_root(root.path(), &args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "ban --file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("added blocklist entry 203.0.113.7/32"),
        "missing first add output: {stdout}"
    );
    assert!(
        stdout.contains("added blocklist entry 198.51.100.0/24"),
        "missing second add output: {stdout}"
    );
    assert!(
        stdout.contains("blocklist already contains 203.0.113.7/32"),
        "missing duplicate output: {stdout}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(contents, "203.0.113.7/32\n198.51.100.0/24\n");
}

#[test]
fn ban_file_mode_invalid_target_fails_without_writes() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\nnot-an-ip\n").expect("write targets");
    let target_path = targets.display().to_string();
    let args = vec!["ban", "--file", target_path.as_str()];

    let output = run_kidobo_with_root(root.path(), &args);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: not-an-ip"),
        "missing invalid-target output: {stderr}"
    );
    assert!(
        stderr.contains("blocklist update failed for 1 invalid target(s)"),
        "missing final invalid-target error: {stderr}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(
        contents.is_empty(),
        "blocklist should remain unchanged: {contents}"
    );
}

#[test]
fn ban_file_mode_rejects_target_with_trailing_junk() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7 trailing-junk\n").expect("write targets");
    let target_path = targets.display().to_string();
    let args = vec!["ban", "--file", target_path.as_str()];

    let output = run_kidobo_with_root(root.path(), &args);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: 203.0.113.7 trailing-junk"),
        "missing invalid-target output: {stderr}"
    );
    assert!(
        stderr.contains("blocklist update failed for 1 invalid target(s)"),
        "missing final invalid-target error: {stderr}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(
        contents.is_empty(),
        "blocklist should remain empty: {contents}"
    );
}

#[test]
fn ban_fails_when_lock_is_held() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let blocklist = root.path().join("data/blocklist.txt");
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));

    let output = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7"]);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock already held"),
        "missing lock-held error message: {stderr}"
    );
    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(
        contents.is_empty(),
        "blocklist should remain unchanged: {contents}"
    );
}

#[test]
fn ban_asn_lock_failure_does_not_resolve_prefixes() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let _held_lock = hold_lock(&root.path().join("cache/sync.lock"));
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    let touched = root.path().join("bgpq4-touched");

    let mut command = kidobo_with_root_command(root.path(), &["ban", "--asn", "64512"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_bgpq4.parent().expect("bgpq4 parent")),
    );
    command.env("KIDOBO_TEST_BGPQ4_TOUCHED", &touched);
    let output = command.output().expect("run ban --asn");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock already held"),
        "missing lock-held error message: {stderr}"
    );
    assert!(
        !touched.exists(),
        "ASN resolution should not run after lock acquisition fails"
    );
}

#[test]
fn inline_asn_ban_and_unban_preserve_configuration() {
    let root = create_root(
        "asn = { banned = [64512], cache_stale_after_secs = 123 }\n# keep\n[ipset]\nset_name='kidobo'\n",
        "",
    );
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    for (args, expected) in [
        (vec!["ban", "--asn", "64513"], vec![64512, 64513]),
        (vec!["unban", "--asn", "64512"], vec![64513]),
    ] {
        let mut command = kidobo_with_root_command(root.path(), &args);
        command.env(
            "PATH",
            path_with_bin_prefix(fake_bgpq4.parent().expect("bin")),
        );
        let output = command.output().expect("command");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = read_to_string_with_limit(&root.path().join("config/config.toml"), 65536)
            .expect("config");
        assert!(rendered.starts_with("asn = {"));
        assert!(rendered.contains("# keep\n[ipset]\nset_name='kidobo'"));
        let config = kidobo_core::config::Config::from_toml_str(&rendered).expect("valid config");
        assert_eq!(config.asn.banned, expected);
    }
}

#[test]
fn ban_asn_empty_resolution_leaves_configuration_unchanged() {
    let initial_config = "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[]\n";
    let root = create_root(initial_config, "");
    let bin_dir = root.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let fake_bgpq4 = bin_dir.join("bgpq4");
    fs::write(&fake_bgpq4, "#!/bin/bash\nexit 0\n").expect("write fake bgpq4");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&fake_bgpq4)
            .expect("fake bgpq4 metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_bgpq4, permissions).expect("chmod fake bgpq4");
    }

    let mut command = kidobo_with_root_command(root.path(), &["ban", "--asn", "64512"]);
    command.env("PATH", path_with_bin_prefix(&bin_dir));
    let output = command.output().expect("run ban --asn");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bgpq4 returned no IPv4 or IPv6 prefixes"),
        "missing empty-result diagnostic: {stderr}"
    );
    let config_text = read_to_string_with_limit(
        &root.path().join("config/config.toml"),
        BLOCKLIST_READ_LIMIT,
    )
    .expect("read config");
    assert_eq!(config_text, initial_config);
}

#[test]
fn ban_asn_oversized_resolution_preserves_configuration() {
    use std::fmt::Write as _;

    let initial_config = "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[]\n";
    let blocklist = "203.0.113.0/24\n";
    let root = create_root(initial_config, blocklist);
    let mut response = String::new();
    for index in 0..250_000 {
        writeln!(
            response,
            "2001:db8:1111:2222:3333:4444:{:x}:{:x}/128",
            index / 65_536,
            index % 65_536
        )
        .expect("write fake resolver response");
    }
    assert!(response.len() > 8 * 1024 * 1024);
    assert!(response.len() < 16 * 1024 * 1024);
    fs::write(root.path().join("asn-response"), response).expect("resolver fixture");
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    fs::write(&fake_bgpq4, "#!/bin/bash\nset -euo pipefail\nif [[ \"$1\" == '-4' ]]; then\n  printf '203.0.113.0/24\\n'\nelse\n  cat \"${KIDOBO_ROOT}/asn-response\"\nfi\n")
        .expect("write oversized fake resolver");
    let mut command = kidobo_with_root_command(root.path(), &["ban", "--asn", "64512"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_bgpq4.parent().expect("fake bin")),
    );
    let output = command.output().expect("run ban --asn");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ASN cache write failed"), "{stderr}");
    assert!(
        stderr.contains("file exceeds 8388608 byte limit"),
        "{stderr}"
    );
    assert_eq!(
        read_to_string_with_limit(&root.path().join("config/config.toml"), 1024).expect("config"),
        initial_config
    );
    assert_eq!(
        read_to_string_with_limit(&root.path().join("data/blocklist.txt"), 1024)
            .expect("blocklist"),
        blocklist
    );
    assert!(
        !root
            .path()
            .join("cache/asn/as64512.iplist")
            .try_exists()
            .expect("cache inspection")
    );
}

#[test]
fn ban_asn_cleanup_failure_warns_without_reverting_config_update() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    let blocklist = root.path().join("data/blocklist.txt");
    fs::remove_file(&blocklist).expect("remove blocklist file");
    fs::create_dir(&blocklist).expect("create blocking directory");

    let mut command = kidobo_with_root_command(root.path(), &["ban", "--asn", "64512"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_bgpq4.parent().expect("bgpq4 parent")),
    );
    let output = command.output().expect("run ban --asn");

    assert_eq!(
        output.status.code(),
        Some(0),
        "ban --asn should succeed despite cleanup warning: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ASN ban duplicate cleanup failed after config update"),
        "missing cleanup warning: {stderr}"
    );

    let config_text = read_to_string_with_limit(
        &root.path().join("config/config.toml"),
        BLOCKLIST_READ_LIMIT,
    )
    .expect("read config");
    let config = kidobo_core::config::Config::from_toml_str(&config_text).expect("parse config");
    assert_eq!(config.asn.banned, vec![64512], "config was not updated");
}

#[test]
fn unban_asn_cleanup_failure_warns_without_reverting_config_update() {
    let root = create_root("[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64512]\n", "");
    let asn_cache_file = root.path().join("cache/asn/as64512.iplist");
    fs::create_dir_all(asn_cache_file.parent().expect("asn cache parent")).expect("mkdir asn");
    fs::create_dir(&asn_cache_file).expect("create blocking cache directory");

    let output = run_kidobo_with_root(root.path(), &["unban", "--asn", "64512"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "unban --asn should succeed despite cleanup warning: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ASN cache cleanup failed for AS64512"),
        "missing cleanup warning: {stderr}"
    );

    let config_text = read_to_string_with_limit(
        &root.path().join("config/config.toml"),
        BLOCKLIST_READ_LIMIT,
    )
    .expect("read config");
    let config = kidobo_core::config::Config::from_toml_str(&config_text).expect("parse config");
    assert!(
        config.asn.banned.is_empty(),
        "config update was reverted or not written: {config_text}"
    );
}

#[test]
fn unban_yes_removes_overlapping_entries_without_prompt() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n",
        "203.0.113.0/24\n198.51.100.0/24\n",
    );
    let blocklist = root.path().join("data/blocklist.txt");

    let output = run_kidobo_with_root(root.path(), &["unban", "203.0.113.7", "--yes"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "unban --yes failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("auto-approving removal of partial matches"),
        "missing auto-approve message: {stdout}"
    );
    assert!(
        stdout.contains("removed 1 blocklist entries for 203.0.113.7/32"),
        "unexpected unban --yes output: {stdout}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(contents, "198.51.100.0/24\n");
}

#[test]
fn interactive_unban_decline_removes_exact_but_preserves_partial_matches() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n",
        "203.0.113.7/32\n203.0.113.0/24\n198.51.100.0/24\n",
    );
    let blocklist = root.path().join("data/blocklist.txt");

    let (code, stdout, stderr) =
        run_interactive_kidobo(root.path(), &["unban", "203.0.113.7"], "n\n", |_| {});

    assert_eq!(code, Some(0), "interactive unban failed: {stderr}");
    assert!(stdout.contains("removed 1 blocklist entries for 203.0.113.7/32"));
    assert_eq!(
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist"),
        "203.0.113.0/24\n198.51.100.0/24\n"
    );
}

#[test]
fn interactive_unban_accept_removes_exact_and_partial_matches() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n",
        "203.0.113.7/32\n203.0.113.0/24\n198.51.100.0/24\n",
    );
    let blocklist = root.path().join("data/blocklist.txt");

    let (code, stdout, stderr) =
        run_interactive_kidobo(root.path(), &["unban", "203.0.113.7"], "yes\n", |_| {});

    assert_eq!(code, Some(0), "interactive unban failed: {stderr}");
    assert!(stdout.contains("removed 2 blocklist entries for 203.0.113.7/32"));
    assert_eq!(
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist"),
        "198.51.100.0/24\n"
    );
}

#[test]
fn interactive_unban_target_detects_blocklist_change_after_preview() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "203.0.113.0/24\n");
    let blocklist = root.path().join("data/blocklist.txt");
    let externally_updated = "203.0.112.0/23\n198.51.100.0/24\n";

    let (code, _stdout, stderr) =
        run_interactive_kidobo(root.path(), &["unban", "203.0.113.7"], "y\n", |_| {
            fs::write(&blocklist, externally_updated).expect("external blocklist update");
        });

    assert_eq!(code, Some(1));
    assert!(stderr.contains("blocklist changed while preparing the update"));
    assert_eq!(
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist"),
        externally_updated
    );
}

#[test]
fn interactive_unban_file_detects_blocklist_change_after_preview() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n",
        "203.0.113.0/24\n198.51.100.0/24\n",
    );
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n198.51.100.0/24\n").expect("write targets");
    let target_path = targets.display().to_string();
    let externally_updated = "203.0.112.0/23\n198.51.100.0/24\n192.0.2.0/24\n";

    let (code, _stdout, stderr) = run_interactive_kidobo(
        root.path(),
        &["unban", "--file", target_path.as_str()],
        "y\n",
        |_| {
            fs::write(&blocklist, externally_updated).expect("external blocklist update");
        },
    );

    assert_eq!(code, Some(1));
    assert!(stderr.contains("blocklist changed while preparing the update"));
    assert_eq!(
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist"),
        externally_updated
    );
}

#[test]
fn unban_file_mode_yes_removes_exact_and_partial_matches() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n",
        "203.0.113.0/24\n198.51.100.0/24\n",
    );
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\n198.51.100.0/24\n").expect("write targets");
    let target_path = targets.display().to_string();
    let args = vec!["unban", "--file", target_path.as_str(), "--yes"];

    let output = run_kidobo_with_root(root.path(), &args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "unban --file --yes failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("file targets also match the following blocklist entries:"),
        "missing partial-match heading: {stdout}"
    );
    assert!(
        stdout.contains("203.0.113.0/24"),
        "missing partial-match entry: {stdout}"
    );
    assert!(
        stdout.contains("auto-approving removal of partial matches"),
        "missing auto-approve output: {stdout}"
    );
    assert!(
        stdout.contains("removed 2 blocklist entries for 2 file target(s)"),
        "unexpected removal summary: {stdout}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert!(contents.is_empty(), "blocklist should be empty: {contents}");
}

#[test]
fn unban_file_mode_invalid_target_fails_without_writes() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "203.0.113.0/24\n");
    let blocklist = root.path().join("data/blocklist.txt");
    let targets = root.path().join("targets.txt");
    fs::write(&targets, "203.0.113.7\nnot-an-ip\n").expect("write targets");
    let target_path = targets.display().to_string();
    let args = vec!["unban", "--file", target_path.as_str(), "--yes"];

    let output = run_kidobo_with_root(root.path(), &args);
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid target: not-an-ip"),
        "missing invalid-target output: {stderr}"
    );
    assert!(
        stderr.contains("blocklist update failed for 1 invalid target(s)"),
        "missing final invalid-target error: {stderr}"
    );

    let contents =
        read_to_string_with_limit(&blocklist, BLOCKLIST_READ_LIMIT).expect("read blocklist");
    assert_eq!(contents, "203.0.113.0/24\n");
}

#[test]
fn temporary_ban_accepts_direct_ipv4_and_ipv6_with_trimmed_duration() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n[safe]\ninclude_github_meta=false\n",
        "",
    );
    let temporary_file = temporary_bans_path(root.path());

    for (target, duration, expected) in [
        ("203.0.113.7", " 12H ", "203.0.113.7/32"),
        ("2001:db8::1/64", "1d", "2001:db8::/64"),
    ] {
        let output = run_kidobo_with_root(root.path(), &["ban", target, "--for", duration]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "temporary ban failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            read_to_string_with_limit(&temporary_file, TEMPORARY_BANS_READ_LIMIT)
                .expect("temporary state")
                .contains(&format!("cidr = \"{expected}\"")),
            "temporary state omitted {expected}"
        );
    }
    assert!(
        read_to_string_with_limit(
            &root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("permanent blocklist")
        .is_empty(),
        "temporary bans must not edit the permanent blocklist"
    );
}

#[test]
fn temporary_file_ban_uses_one_deadline_and_invalid_batch_writes_nothing() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let targets = root.path().join("targets.txt");
    let temporary_file = temporary_bans_path(root.path());
    fs::write(&targets, "203.0.113.7\n2001:db8::/64\n").expect("write valid targets");
    let target_path = targets.display().to_string();
    let output = run_kidobo_with_root(root.path(), &["ban", "--file", &target_path, "--for", "3d"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "temporary file ban failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = FileTemporaryBanRepository
        .load(&temporary_file)
        .expect("valid temporary state");
    assert_eq!(state.ips.len(), 2);
    assert_eq!(
        state
            .ips
            .values()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1,
        "one file operation must use one deadline"
    );

    let invalid_root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let invalid_targets = invalid_root.path().join("targets.txt");
    fs::write(&invalid_targets, "203.0.113.7\nnot-an-ip\n").expect("write invalid targets");
    let invalid_path = invalid_targets.display().to_string();
    let invalid_output = run_kidobo_with_root(
        invalid_root.path(),
        &["ban", "--file", &invalid_path, "--for", "3d"],
    );
    assert_eq!(invalid_output.status.code(), Some(1));
    assert!(
        !temporary_bans_path(invalid_root.path()).exists(),
        "invalid file batch must not create or update temporary state"
    );
    assert_eq!(
        read_to_string_with_limit(
            &invalid_root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT,
        )
        .expect("permanent blocklist"),
        ""
    );
}

#[test]
fn temporary_asn_ban_uses_stale_cache_without_downgrading_permanent_asn() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n[safe]\ninclude_github_meta=false\n[asn]\nbanned=[64496]\ncache_stale_after_secs=1\n",
        "",
    );
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    fs::write(&fake_bgpq4, "#!/usr/bin/env bash\nexit 1\n").expect("make resolver fail");
    let cache_dir = root.path().join("cache/asn");
    fs::create_dir_all(&cache_dir).expect("create ASN cache");
    for (asn, prefix) in [(64496, "203.0.113.0/24"), (64497, "2001:db8::/48")] {
        let cache_path = cache_dir.join(format!("as{asn}.iplist"));
        fs::write(&cache_path, format!("# kidobo-asn-cache-v1\n{prefix}\n"))
            .expect("write stale ASN cache");
        fs::File::open(&cache_path)
            .expect("open ASN cache")
            .set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH))
            .expect("age ASN cache");
    }

    let mut command = kidobo_with_root_command(
        root.path(),
        &["ban", "--for", "3d", "--asn", "AS64496", "64497"],
    );
    command.env(
        "PATH",
        path_with_bin_prefix(fake_bgpq4.parent().expect("bgpq4 directory")),
    );
    let output = command.output().expect("temporary ASN ban");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "ASN ban failed: {stderr}");
    assert!(stderr.contains("ASN cache stale fallback used for AS64496"));
    assert!(stderr.contains("ASN cache stale fallback used for AS64497"));

    let state = FileTemporaryBanRepository
        .load(&temporary_bans_path(root.path()))
        .expect("temporary ASN state");
    assert_eq!(state.asns.keys().copied().collect::<Vec<_>>(), [64497]);
    let config_text = read_to_string_with_limit(&root.path().join("config/config.toml"), 65_536)
        .expect("configuration unchanged");
    assert!(config_text.contains("banned=[64496]"));

    let unban = run_kidobo_with_root(root.path(), &["unban", "--asn", "AS64496", "64497"]);
    assert_eq!(unban.status.code(), Some(0), "ASN unban failed");
    assert!(
        FileTemporaryBanRepository
            .load(&temporary_bans_path(root.path()))
            .expect("temporary ASN state after unban")
            .asns
            .is_empty()
    );
    let config_text = read_to_string_with_limit(&root.path().join("config/config.toml"), 65_536)
        .expect("configuration after ASN unban");
    assert!(!config_text.contains("banned=[64496]"));
}

#[test]
fn temporary_deadline_can_be_shortened_and_permanent_duplicate_stays_permanent() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "203.0.113.9/32\n");
    let temporary_file = temporary_bans_path(root.path());

    let first = run_kidobo_with_root(root.path(), &["ban", "198.51.100.7", "--for", "30d"]);
    assert_eq!(first.status.code(), Some(0));
    let first_state = FileTemporaryBanRepository
        .load(&temporary_file)
        .expect("initial temporary state");
    let first_deadline = *first_state.ips.values().next().expect("first deadline");

    let shortened = run_kidobo_with_root(root.path(), &["ban", "198.51.100.7", "--for", "1h"]);
    assert_eq!(shortened.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&shortened.stdout).contains("rescheduled temporary ban"));
    let shortened_state = FileTemporaryBanRepository
        .load(&temporary_file)
        .expect("shortened temporary state");
    let shortened_deadline = *shortened_state
        .ips
        .values()
        .next()
        .expect("shortened deadline");
    assert!(shortened_deadline < first_deadline);

    let permanent = run_kidobo_with_root(root.path(), &["ban", "203.0.113.9", "--for", "1d"]);
    assert_eq!(permanent.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&permanent.stdout).contains("already permanently banned"));
    let state = FileTemporaryBanRepository
        .load(&temporary_file)
        .expect("temporary state after permanent duplicate");
    assert!(
        !state
            .ips
            .keys()
            .any(|target| target.to_string() == "203.0.113.9/32")
    );
    assert!(
        read_to_string_with_limit(
            &root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("permanent source")
        .contains("203.0.113.9/32")
    );

    let temporary = run_kidobo_with_root(root.path(), &["ban", "192.0.2.7", "--for", "1d"]);
    assert_eq!(temporary.status.code(), Some(0));
    let promoted_target_state = FileTemporaryBanRepository
        .load(&temporary_file)
        .expect("temporary state before promotion");
    let promoted = run_kidobo_with_root(root.path(), &["ban", "192.0.2.7"]);
    assert_eq!(promoted.status.code(), Some(0));
    assert!(
        read_to_string_with_limit(
            &root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("permanent source after promotion")
        .contains("192.0.2.7/32"),
        "permanent ban should promote the target into the permanent source"
    );
    assert_eq!(
        FileTemporaryBanRepository
            .load(&temporary_file)
            .expect("temporary state after promotion"),
        promoted_target_state,
        "permanent promotion preserves the temporary record until it expires"
    );
}

#[test]
fn unban_removes_temporary_only_and_mixed_permanent_temporary_matches() {
    let temporary_only = create_root("[ipset]\nset_name='kidobo'\n", "");
    fs::write(
        temporary_bans_path(temporary_only.path()),
        format!(
            "version = 1\n\n[[ips]]\ncidr = \"203.0.113.7/32\"\nexpires_at = {}\n",
            future_expiry(86_400)
        ),
    )
    .expect("write temporary-only target");
    let output = run_kidobo_with_root(temporary_only.path(), &["unban", "203.0.113.7"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        FileTemporaryBanRepository
            .load(&temporary_bans_path(temporary_only.path()))
            .expect("temporary-only state after unban")
            .ips
            .is_empty()
    );

    let mixed = create_root("[ipset]\nset_name='kidobo'\n", "198.51.100.9/32\n");
    fs::write(
        temporary_bans_path(mixed.path()),
        format!(
            "version = 1\n\n[[ips]]\ncidr = \"198.51.100.9/32\"\nexpires_at = {}\n\n[[ips]]\ncidr = \"203.0.113.0/24\"\nexpires_at = {}\n",
            future_expiry(86_400),
            future_expiry(86_400)
        ),
    )
    .expect("write mixed targets");
    let targets = mixed.path().join("targets.txt");
    fs::write(&targets, "198.51.100.9\n203.0.113.8\n").expect("write unban targets");
    let target_path = targets.display().to_string();
    let output = run_kidobo_with_root(mixed.path(), &["unban", "--file", &target_path, "--yes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file targets also match the following blocklist entries:"));
    assert!(stdout.contains("auto-approving removal of partial matches"));
    assert_eq!(
        read_to_string_with_limit(
            &mixed.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("permanent state after unban"),
        ""
    );
    assert!(
        FileTemporaryBanRepository
            .load(&temporary_bans_path(mixed.path()))
            .expect("temporary state after mixed unban")
            .ips
            .is_empty()
    );
}

#[test]
fn temporary_state_doctor_reports_bad_and_oversized_data_without_rewriting_it() {
    let root = create_root("[ipset]\nset_name='kidobo'\n", "");
    let temporary_file = temporary_bans_path(root.path());
    let fake_sudo = write_fake_sudo_script(&root);
    let path = path_with_bin_prefix(fake_sudo.parent().expect("sudo parent"));

    let missing_output = kidobo_with_root_command(root.path(), &["doctor"])
        .env("PATH", &path)
        .output()
        .expect("doctor missing optional state");
    let report: serde_json::Value =
        serde_json::from_slice(&missing_output.stdout).expect("missing-state doctor report");
    assert_eq!(
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["name"] == "file_temporary_bans")
            .expect("temporary-ban check")["status"],
        "OK"
    );
    assert!(
        !temporary_file.exists(),
        "doctor must accept a missing optional state file without creating it"
    );

    fs::write(&temporary_file, "malformed temporary state").expect("write malformed state");
    let malformed_output = kidobo_with_root_command(root.path(), &["doctor"])
        .env("PATH", &path)
        .output()
        .expect("doctor malformed state");
    assert_eq!(malformed_output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&malformed_output.stdout).expect("malformed-state doctor report");
    assert_eq!(
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["name"] == "file_temporary_bans")
            .expect("temporary-ban check")["status"],
        "FAIL"
    );
    assert_eq!(
        read_to_string_with_limit(&temporary_file, TEMPORARY_BANS_READ_LIMIT)
            .expect("malformed state unchanged"),
        "malformed temporary state"
    );

    fs::write(&temporary_file, "version = 1\n").expect("write oversized-state prefix");
    fs::File::options()
        .write(true)
        .open(&temporary_file)
        .expect("open temporary state")
        .set_len(u64::try_from(TEMPORARY_BANS_READ_LIMIT + 1).expect("size fits u64"))
        .expect("make temporary state oversized");
    let oversized_output = kidobo_with_root_command(root.path(), &["doctor"])
        .env("PATH", &path)
        .output()
        .expect("doctor oversized state");
    assert_eq!(oversized_output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&oversized_output.stdout).expect("oversized-state doctor report");
    assert_eq!(
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["name"] == "file_temporary_bans")
            .expect("temporary-ban check")["status"],
        "FAIL"
    );
    assert_eq!(
        fs::metadata(&temporary_file)
            .expect("oversized file metadata")
            .len(),
        u64::try_from(TEMPORARY_BANS_READ_LIMIT + 1).expect("size fits u64")
    );
}

#[test]
fn temporary_lookup_uses_active_entries_and_cached_asn_prefixes_only() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\n[safe]\ninclude_github_meta=false\n[asn]\nbanned=[]\n",
        "",
    );
    let temporary_file = temporary_bans_path(root.path());
    fs::write(
        &temporary_file,
        format!(
            "version = 1\n\n[[ips]]\ncidr = \"203.0.113.7/32\"\nexpires_at = {}\n\n[[ips]]\ncidr = \"198.51.100.9/32\"\nexpires_at = 1\n\n[[asns]]\nasn = 64512\nexpires_at = {}\n\n[[asns]]\nasn = 64513\nexpires_at = 1\n",
            future_expiry(86_400),
            future_expiry(86_400)
        ),
    )
    .expect("write temporary lookup state");
    let cache_dir = root.path().join("cache/asn");
    fs::create_dir_all(&cache_dir).expect("create lookup ASN cache");
    fs::write(cache_dir.join("as64512.iplist"), "192.0.2.0/24\n").expect("active ASN cache");
    fs::write(cache_dir.join("as64513.iplist"), "198.51.100.0/24\n").expect("expired ASN cache");
    let targets = root.path().join("lookup-targets.txt");
    fs::write(
        &targets,
        "203.0.113.7\n198.51.100.9\n192.0.2.7\n198.51.100.7\n",
    )
    .expect("write lookup targets");
    let fake_bgpq4 = write_fake_bgpq4_script(&root);
    let touched = root.path().join("bgpq4-touched");
    let target_path = targets.display().to_string();
    let mut command = kidobo_with_root_command(
        root.path(),
        &["lookup", "--file", &target_path, "--format", "tsv"],
    );
    command
        .env(
            "PATH",
            path_with_bin_prefix(fake_bgpq4.parent().expect("bgpq4 parent")),
        )
        .env("KIDOBO_TEST_BGPQ4_TOUCHED", &touched);
    let output = command.output().expect("offline temporary lookup");
    assert_eq!(output.status.code(), Some(0));
    assert!(!touched.exists(), "lookup must not invoke bgpq4");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("203.0.113.7\ttemporary:blocklist\t203.0.113.7/32"));
    assert!(stdout.contains("192.0.2.7\ttemporary:asn:AS64512\t192.0.2.0/24"));
    assert!(
        stdout.contains("198.51.100.9\tNO_MATCH"),
        "expired IP ban should not match: {stdout}"
    );
    assert!(
        stdout.contains("198.51.100.7\tNO_MATCH"),
        "expired ASN cache should not match: {stdout}"
    );
}

#[test]
fn temporary_timeout_warns_when_recording_and_syncing_active_bans() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\ntimeout=30\n[safe]\ninclude_github_meta=false\n",
        "",
    );
    let ban = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7", "--for", "1d"]);
    assert_eq!(ban.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&ban.stderr).contains("ipset.timeout is nonzero"));

    let fake_sudo = write_fake_sudo_script(&root);
    let mut command = kidobo_with_root_command(root.path(), &["sync"]);
    command.env(
        "PATH",
        path_with_bin_prefix(fake_sudo.parent().expect("sudo parent")),
    );
    let output = command.output().expect("sync with active temporary ban");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "sync failed: {stderr}");
    assert!(stderr.contains("ipset.timeout is nonzero"));
}

#[test]
fn temporary_ban_is_restored_until_expiry_then_pruned_after_sync() {
    let root = create_root(
        "[ipset]\nset_name='kidobo'\nenable_ipv6=false\nmaxelem=2\n[safe]\ninclude_github_meta=false\n",
        "",
    );
    let target = "203.0.113.7/32";
    let temporary_file = temporary_bans_path(root.path());
    let ban = run_kidobo_with_root(root.path(), &["ban", "203.0.113.7", "--for", "1d"]);
    assert_eq!(ban.status.code(), Some(0));

    let fake_sudo = write_fake_sudo_script(&root);
    let restore_log = root.path().join("restore.log");
    let path = path_with_bin_prefix(fake_sudo.parent().expect("sudo parent"));
    let mut first_sync = kidobo_with_root_command(root.path(), &["sync"]);
    first_sync
        .env("PATH", &path)
        .env("KIDOBO_TEST_RESTORE_LOG", &restore_log);
    let first_output = first_sync.output().expect("sync active temporary ban");
    assert_eq!(
        first_output.status.code(),
        Some(0),
        "first sync failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    let first_restore = read_to_string_with_limit(&restore_log, 65_536).expect("first restore");
    assert!(
        first_restore.contains(target),
        "first sync did not restore the saved temporary target: {first_restore}"
    );

    fs::write(
        &temporary_file,
        format!("version = 1\n\n[[ips]]\ncidr = \"{target}\"\nexpires_at = 1\n"),
    )
    .expect("expire fixture record");
    fs::write(&restore_log, "").expect("reset restore log");
    let mut second_sync = kidobo_with_root_command(root.path(), &["sync"]);
    second_sync
        .env("PATH", &path)
        .env("KIDOBO_TEST_RESTORE_LOG", &restore_log);
    let second_output = second_sync.output().expect("sync expired temporary ban");
    assert_eq!(
        second_output.status.code(),
        Some(0),
        "second sync failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    let second_restore = read_to_string_with_limit(&restore_log, 65_536).expect("second restore");
    assert!(
        !second_restore.contains(target),
        "expired target remained in restore input: {second_restore}"
    );
    assert!(
        FileTemporaryBanRepository
            .load(&temporary_file)
            .expect("pruned temporary state")
            .ips
            .is_empty(),
        "successful sync should prune expired temporary records"
    );
    assert!(
        read_to_string_with_limit(
            &root.path().join("data/blocklist.txt"),
            BLOCKLIST_READ_LIMIT
        )
        .expect("permanent source unchanged")
        .is_empty(),
        "temporary sync lifecycle must leave the permanent blocklist unchanged"
    );
}
