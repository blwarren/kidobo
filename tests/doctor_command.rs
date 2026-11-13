#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fake command");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake");
}

#[test]
fn doctor_checks_large_ipsets_without_collecting_members() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).expect("mkdir bin");
    for directory in ["config", "data", "cache/remote"] {
        fs::create_dir_all(root.join(directory)).expect("mkdir root");
    }
    fs::write(
        root.join("config/config.toml"),
        "[ipset]\nset_name='kidobo'\n",
    )
    .expect("write config");
    fs::write(root.join("data/blocklist.txt"), "").expect("write blocklist");
    write_executable(
        &bin.join("sudo"),
        "#!/bin/sh\n[ \"$1\" = \"-n\" ] || exit 99\nshift\nexec \"$@\"\n",
    );
    for name in ["bgpq4", "iptables", "ip6tables"] {
        write_executable(&bin.join(name), "#!/bin/sh\nexit 0\n");
    }
    write_executable(
        &bin.join("ipset"),
        r#"#!/bin/sh
if [ "$*" = 'list -name' ]; then
    printf 'kidobo\nkidobo-v6\n'
else
    awk 'BEGIN { for (i = 0; i < 450000; i++) printf "fd00:1111:2222:3333:4444:5555:%04x:%04x\n", 32768 + int(i / 61440), 4096 + i % 61440 }'
fi
"#,
    );
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_kidobo"))
        .arg("doctor")
        .env("KIDOBO_ROOT", &root)
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .output()
        .expect("run doctor with fake commands");

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(report["overall"], "OK");
    let probe = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "sudo_probe_ipset")
        .expect("ipset check");
    assert_eq!(probe["status"], "OK");
    assert_eq!(probe["detail"], "sudo -n ipset list -name succeeded");
}

fn assert_doctor_redacts_configuration_error(arguments: &[&str], json_output: bool, scheme: &str) {
    let config = format!(
        "[ipset]\nset_name='kidobo'\n[remote]\nurls=['{scheme}://reviewuser:reviewpass@feed.example/list?token=reviewquery#reviewfragment'] INVALID\n"
    );
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let bin = temp.path().join("empty-bin");
    fs::create_dir_all(&bin).expect("empty command path");
    for directory in ["config", "data"] {
        fs::create_dir_all(root.join(directory)).expect("fixture directory");
    }
    let sources = [
        ("config/config.toml", config.as_str()),
        ("data/blocklist.txt", "203.0.113.7\n"),
        ("data/temporary-bans.toml", "version = 1\n"),
    ];
    for (path, contents) in sources {
        fs::write(root.join(path), contents).expect("saved source fixture");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_kidobo"))
        .args(arguments)
        .env_clear()
        .env("KIDOBO_ROOT", &root)
        .env("PATH", &bin)
        .output()
        .expect("doctor with no available system commands");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    let unwrapped = stdout.split_whitespace().collect::<String>();
    for secret in ["reviewuser", "reviewpass", "reviewquery", "reviewfragment"] {
        assert!(!unwrapped.contains(secret), "stdout exposed {secret}");
        assert!(!stderr.contains(secret), "stderr exposed {secret}");
    }

    if json_output {
        let report: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
        assert_eq!(report.as_object().expect("report object").len(), 2);
        assert_eq!(report["overall"], "FAIL");
        let checks = report["checks"].as_array().expect("checks array");
        for check in checks {
            assert_eq!(check.as_object().expect("check object").len(), 3);
            assert!(check["name"].is_string());
            assert!(check["status"].is_string());
            assert!(check["detail"].is_string());
        }
        let failed_config = checks
            .iter()
            .find(|check| check["name"] == "config_parse")
            .expect("configuration check");
        assert_eq!(failed_config["status"], "FAIL");
        let detail = failed_config["detail"].as_str().expect("failure detail");
        assert!(detail.contains("TOML parse error at line 4"));
        assert!(detail.contains("unexpected key or value"));
        assert!(detail.contains("https://REDACTED@feed.example/list?REDACTED#REDACTED"));
    } else {
        assert!(unwrapped.contains("[FAIL]configparse"));
        assert!(unwrapped.contains("TOMLparseerroratline4"));
        assert!(unwrapped.contains("unexpectedkeyorvalue"));
        assert!(unwrapped.contains("https://REDACTED@feed.example/list?REDACTED#REDACTED"));
    }
    for (path, contents) in sources {
        assert_eq!(
            kidobo_adapters::limited_io::read_to_string_with_limit(&root.join(path), 65_536)
                .expect("saved source remains readable"),
            contents
        );
    }
    assert!(!root.join("cache").exists());
    assert!(!root.join("systemd").exists());
}

#[test]
fn doctor_explicit_json_redacts_configuration_errors() {
    for scheme in ["https", "ht\ttps"] {
        assert_doctor_redacts_configuration_error(&["doctor", "--format", "json"], true, scheme);
    }
}

#[test]
fn doctor_redirected_default_redacts_configuration_errors() {
    for scheme in ["https", "ht\ttps"] {
        assert_doctor_redacts_configuration_error(&["doctor"], true, scheme);
    }
}

#[test]
fn doctor_human_redacts_configuration_errors() {
    for scheme in ["https", "ht\ttps"] {
        assert_doctor_redacts_configuration_error(&["doctor", "--format", "human"], false, scheme);
    }
}
