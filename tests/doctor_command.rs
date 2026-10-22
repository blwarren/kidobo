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
