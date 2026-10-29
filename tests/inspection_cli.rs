#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use kidobo_adapters::limited_io::read_to_string_with_limit;
use tempfile::TempDir;

const TOOL_LOG_LIMIT: usize = 16 * 1024;
const IPSET_MEMBERSHIP: &str = "203.0.113.7";

struct Fixture {
    temp: TempDir,
    root: PathBuf,
    bin: PathBuf,
}

impl Fixture {
    fn new(config: Option<&str>, blocklist: Option<&str>, temporary: Option<&str>) -> Self {
        let temp = TempDir::new().expect("fixture directory");
        let root = temp.path().join("root");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&root).expect("root directory");
        fs::create_dir_all(&bin).expect("binary directory");
        if let Some(config) = config {
            fs::create_dir_all(root.join("config")).expect("config directory");
            fs::write(root.join("config/config.toml"), config).expect("config file");
        }
        if let Some(blocklist) = blocklist {
            fs::create_dir_all(root.join("data")).expect("data directory");
            fs::write(root.join("data/blocklist.txt"), blocklist).expect("blocklist file");
        }
        if let Some(temporary) = temporary {
            fs::create_dir_all(root.join("data")).expect("data directory");
            fs::write(root.join("data/temporary-bans.toml"), temporary)
                .expect("temporary-bans file");
        }
        let fixture = Self { temp, root, bin };
        fixture.install_tools();
        fixture
    }

    fn run(&self, args: &[&str], extra_environment: &[(&str, &str)]) -> Output {
        let binary = std::env::var_os("KIDOBO_TEST_BINARY").map_or_else(
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
            .env("KIDOBO_TEST_TOOL_LOG", self.temp.path().join("tool.log"))
            .env("KIDOBO_LOG_FORMAT", "journal")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env("LANG", "C.UTF-8")
            .envs(extra_environment.iter().copied());
        command.output().expect("run Kidobo with fake system tools")
    }

    fn tool_log(&self) -> String {
        read_to_string_with_limit(&self.temp.path().join("tool.log"), TOOL_LOG_LIMIT)
            .unwrap_or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    String::new()
                } else {
                    panic!("read fake tool log: {error}");
                }
            })
    }

    fn install_tools(&self) {
        self.write_tool(
            "sudo",
            "printf 'sudo %s\\n' \"$*\" >> \"$KIDOBO_TEST_TOOL_LOG\"\nexit 99\n",
        );
        self.write_tool(
            "ipset",
            r#"case "$1" in
    list)
        if [ "$2" = "-name" ]; then
            if [ "${KIDOBO_TEST_SET_NAMES+x}" = x ]; then
                printf '%s\n' "$KIDOBO_TEST_SET_NAMES"
            else
                printf 'kidobo\nkidobo-v6\n'
            fi
        elif [ "$3" = "-terse" ]; then
            case "$2" in
                kidobo) family=inet; count=7 ;;
                kidobo-v6) family=inet6; count=9 ;;
                *) exit 91 ;;
            esac
            printf 'Name: %s\nType: hash:net\nRevision: 7\nHeader: family %s hashsize 64 maxelem 500000 timeout 0\nNumber of entries: %s\n' "$2" "$family" "$count"
        else
            exit 92
        fi
        ;;
    test)
        case "${KIDOBO_TEST_MEMBERSHIP:-present}" in
            present) exit 0 ;;
            absent) printf '%s is NOT in set %s.\n' "$3" "$2" >&2; exit 1 ;;
            *) echo 'Operation not permitted' >&2; exit 2 ;;
        esac
        ;;
    *) exit 93 ;;
esac
"#,
        );
        self.write_tool(
            "iptables",
            r#"[ "$1" = "-S" ] || exit 94
printf '%s\n' '-P INPUT ACCEPT' '-N kidobo-input' '-A INPUT -j kidobo-input' '-A kidobo-input -m set --match-set kidobo src -j DROP'
"#,
        );
        self.write_tool(
            "ip6tables",
            r#"[ "$1" = "-S" ] || exit 95
printf '%s\n' '-P INPUT ACCEPT' '-N kidobo-input' '-A INPUT -j kidobo-input' '-A kidobo-input -m set --match-set kidobo-v6 src -j DROP'
"#,
        );
        self.write_tool("systemctl", "exit 98\n");
        self.write_tool("bgpq4", "exit 97\n");
        self.write_tool("curl", "exit 96\n");
    }

    fn write_tool(&self, name: &str, body: &str) {
        let path = self.bin.join(name);
        let contents = format!(
            "#!/bin/sh\nprintf '%s %s\\n' '{name}' \"$*\" >> \"$KIDOBO_TEST_TOOL_LOG\"\n{body}"
        );
        fs::write(&path, contents).expect("write fake command");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake command");
    }
}

fn config(enable_ipv6: bool) -> String {
    format!(
        "[ipset]\nset_name = 'kidobo'\nenable_ipv6 = {enable_ipv6}\n[safe]\ninclude_github_meta = false\n[remote]\nurls = ['https://feed-one.example/list', 'https://feed-two.example/list']\n[asn]\nbanned = [64512, 64513]\n"
    )
}

fn json_output(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON command output")
}

#[test]
fn bare_uninitialized_status_succeeds_without_creating_files_or_running_tools() {
    let fixture = Fixture::new(None, None, None);

    let output = fixture.run(&[], &[]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Welcome"));
    assert_eq!(
        fs::read_dir(&fixture.root)
            .expect("root after status")
            .count(),
        0,
        "status must not initialize missing state"
    );
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn status_json_separates_kernel_header_counts_from_configured_feed_count() {
    let fixture = Fixture::new(Some(&config(true)), Some(""), Some("version = 1\n"));

    let output = fixture.run(&["status", "--format", "json"], &[]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = json_output(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["configured_feeds"], 2);
    assert_eq!(report["ipv4"]["entries"], 7);
    assert_eq!(report["ipv6"]["entries"], 9);
    assert_eq!(report["last_successful_sync"], serde_json::Value::Null);
    let tool_log = fixture.tool_log();
    assert!(tool_log.contains("ipset list -name\n"), "{tool_log}");
    assert!(
        tool_log.contains("ipset list kidobo -terse\n"),
        "{tool_log}"
    );
    assert!(
        tool_log.contains("ipset list kidobo-v6 -terse\n"),
        "{tool_log}"
    );
    assert!(
        !tool_log.contains("sudo "),
        "status must use direct probes: {tool_log}"
    );
    assert!(
        !tool_log.contains("systemctl "),
        "alternate roots have no host timer: {tool_log}"
    );
    assert!(
        !tool_log.contains("bgpq4 "),
        "status must not enumerate remote AS sources: {tool_log}"
    );
    assert!(
        !tool_log.contains("curl "),
        "status must not fetch remote sources: {tool_log}"
    );
}

#[test]
fn check_verifies_membership_and_keeps_offline_matches_separate() {
    let fixture = Fixture::new(
        Some(&config(true)),
        Some("203.0.113.7\n"),
        Some("version = 1\n"),
    );

    let not_blocked = fixture.run(
        &["check", IPSET_MEMBERSHIP, "--format", "json"],
        &[("KIDOBO_TEST_MEMBERSHIP", "absent")],
    );
    assert_eq!(not_blocked.status.code(), Some(0), "{not_blocked:?}");
    let report = json_output(&not_blocked);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["verdict"], "not_blocked");
    assert_eq!(report["family"]["membership"], "absent");
    assert_eq!(report["offline_matches"][0]["entry"], "203.0.113.7");
    assert_ne!(
        report["offline_matches"].as_array().expect("matches").len(),
        0
    );
    assert!(!fixture.tool_log().contains("sudo "));

    let blocked = fixture.run(
        &["check", IPSET_MEMBERSHIP, "--format", "json"],
        &[("KIDOBO_TEST_MEMBERSHIP", "present")],
    );
    assert_eq!(blocked.status.code(), Some(0), "{blocked:?}");
    let report = json_output(&blocked);
    assert_eq!(report["verdict"], "blocked");
    assert_eq!(report["family"]["membership"], "present");
    assert_ne!(
        report["offline_matches"].as_array().expect("matches").len(),
        0
    );
}

#[test]
fn unrelated_set_names_do_not_change_status_or_membership_verdicts() {
    let fixture = Fixture::new(Some(&config(true)), Some(""), Some("version = 1\n"));
    let names = "other:valid\nkidobo\nother+valid\nkidobo-v6\nkidobo:shadow\nkidobo-v6:shadow";
    let status = fixture.run(
        &["status", "--format", "json"],
        &[("KIDOBO_TEST_SET_NAMES", names)],
    );
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    let report = json_output(&status);
    for (family, entries) in [("ipv4", 7), ("ipv6", 9)] {
        assert_eq!(report[family]["set_state"], "verified");
        assert_eq!(report[family]["enforcement"], "verified");
        assert_eq!(report[family]["entries"], entries);
        assert_eq!(report[family]["stable"], true);
    }

    for (address, family) in [("203.0.113.7", "ipv4"), ("2001:db8::7", "ipv6")] {
        for (membership, verdict) in [("present", "blocked"), ("absent", "not_blocked")] {
            let output = fixture.run(
                &["check", address, "--format", "json"],
                &[
                    ("KIDOBO_TEST_SET_NAMES", names),
                    ("KIDOBO_TEST_MEMBERSHIP", membership),
                ],
            );
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let report = json_output(&output);
            assert_eq!(report["verdict"], verdict);
            assert_eq!(report["family"]["family"], family);
            assert_eq!(report["family"]["set_state"], "verified");
            assert_eq!(report["family"]["membership"], membership);
            assert_eq!(report["family"]["stable"], true);
        }
    }
    let log = fixture.tool_log();
    assert!(!log.contains("sudo "), "{log}");
    assert!(!log.contains("other:valid -terse"), "{log}");
    assert!(!log.contains("other+valid -terse"), "{log}");
}

#[test]
fn unrelated_set_names_do_not_hide_managed_set_absence() {
    let fixture = Fixture::new(Some(&config(true)), Some(""), Some("version = 1\n"));
    for program in ["iptables", "ip6tables"] {
        fixture.write_tool(
            program,
            "[ \"$*\" = '-S' ] || exit 94\nprintf '%s\\n' '-P INPUT ACCEPT'\n",
        );
    }
    let environment = [(
        "KIDOBO_TEST_SET_NAMES",
        "kidobo:shadow\nkidobo-v6:shadow\nother+valid",
    )];
    let status = fixture.run(&["status", "--format", "json"], &environment);
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    let report = json_output(&status);
    for family in ["ipv4", "ipv6"] {
        assert_eq!(report[family]["set_state"], "absent");
        assert_eq!(report[family]["enforcement"], "absent");
        assert_eq!(report[family]["entries"], serde_json::Value::Null);
    }
    for address in ["203.0.113.7", "2001:db8::7"] {
        let output = fixture.run(&["check", address, "--format", "json"], &environment);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report = json_output(&output);
        assert_eq!(report["verdict"], "not_blocked");
        assert_eq!(report["family"]["set_state"], "absent");
        assert_eq!(report["family"]["stable"], true);
    }
    let log = fixture.tool_log();
    assert!(!log.contains("-terse"), "{log}");
    assert!(!log.contains("ipset test"), "{log}");
}

#[test]
fn check_unknown_and_invalid_cidr_have_distinct_exit_statuses() {
    let fixture = Fixture::new(Some(&config(true)), Some(""), Some("version = 1\n"));

    let unknown = fixture.run(
        &["check", IPSET_MEMBERSHIP, "--format", "json"],
        &[("KIDOBO_TEST_MEMBERSHIP", "unknown")],
    );
    assert_eq!(unknown.status.code(), Some(1), "{unknown:?}");
    assert_eq!(json_output(&unknown)["verdict"], "unknown");
    let before_usage = fixture.tool_log();

    let invalid = fixture.run(&["check", "203.0.113.0/24"], &[]);
    assert_eq!(invalid.status.code(), Some(2), "{invalid:?}");
    assert_eq!(
        fixture.tool_log(),
        before_usage,
        "usage errors must not probe tools"
    );
}

#[test]
fn disabled_ipv6_with_residual_managed_wiring_is_unknown() {
    let fixture = Fixture::new(Some(&config(false)), Some(""), Some("version = 1\n"));

    let output = fixture.run(&["check", "2001:db8::7", "--format", "json"], &[]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json_output(&output);
    assert_eq!(report["verdict"], "unknown");
    assert_eq!(report["family"]["configured_enabled"], false);
    assert_eq!(report["family"]["wiring"], "verified");
    assert_eq!(report["family"]["enforcement"], "unknown");
    assert!(
        report["family"]["detail"]
            .as_str()
            .expect("family detail")
            .contains("disabled in configuration")
    );
}

#[test]
fn bans_apply_default_limit_filters_and_expiry_utc_format() {
    let mut blocklist = String::new();
    for octet in 0..51 {
        writeln!(blocklist, "198.51.100.{octet}").expect("write blocklist fixture");
    }
    let temporary = "version = 1\n\
        [[ips]]\n\
        cidr = '192.0.2.1'\n\
        expires_at = 2000000000\n\
        [[ips]]\n\
        cidr = '192.0.2.2'\n\
        expires_at = 1\n\
        [[asns]]\n\
        asn = 64496\n\
        expires_at = 2000000000\n";
    let fixture = Fixture::new(Some(&config(true)), Some(&blocklist), Some(temporary));

    let default = fixture.run(&["bans"], &[]);
    assert_eq!(default.status.code(), Some(0), "{default:?}");
    let default_stdout = String::from_utf8_lossy(&default.stdout);
    assert!(default_stdout.contains("50 shown of 56 matching entries; 6 omitted."));

    let all = fixture.run(&["bans", "--all"], &[]);
    assert_eq!(all.status.code(), Some(0), "{all:?}");
    let all_stdout = String::from_utf8_lossy(&all.stdout);
    assert!(all_stdout.contains("56 shown of 56 matching entries; 0 omitted."));

    let temporary = fixture.run(&["bans", "--temporary"], &[]);
    assert_eq!(temporary.status.code(), Some(0), "{temporary:?}");
    let temporary_stdout = String::from_utf8_lossy(&temporary.stdout);
    assert!(temporary_stdout.contains("3 shown of 3 matching entries; 0 omitted."));
    assert!(temporary_stdout.contains("1970-01-01 00:00:01 UTC"));
    assert!(temporary_stdout.contains("2033-05-18 03:33:20 UTC"));
    assert!(temporary_stdout.contains("expired"));
    assert!(temporary_stdout.contains("remaining"));

    let permanent_asns = fixture.run(&["bans", "--permanent", "--asn"], &[]);
    assert_eq!(permanent_asns.status.code(), Some(0), "{permanent_asns:?}");
    let permanent_stdout = String::from_utf8_lossy(&permanent_asns.stdout);
    assert!(permanent_stdout.contains("2 shown of 2 matching entries; 0 omitted."));
    assert!(permanent_stdout.contains("AS64512"));
    assert!(permanent_stdout.contains("AS64513"));
    assert!(!permanent_stdout.contains("198.51.100."));

    let temporary_asns = fixture.run(&["bans", "--temporary", "--asn"], &[]);
    assert_eq!(temporary_asns.status.code(), Some(0), "{temporary_asns:?}");
    let temporary_asn_stdout = String::from_utf8_lossy(&temporary_asns.stdout);
    assert!(temporary_asn_stdout.contains("1 shown of 1 matching entries; 0 omitted."));
    assert!(temporary_asn_stdout.contains("AS64496"));
    assert_eq!(
        fixture.tool_log(),
        "",
        "saved bans must not inspect live commands"
    );
}
