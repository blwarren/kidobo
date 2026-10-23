use super::{
    read_text,
    tests::{TestDir, executable},
};
use std::fs;
use std::process::Command;

fn extracted_os_upgrade_phase() -> &'static str {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("os_upgrade_phase() {")
        .expect("find OS upgrade function");
    let end = lifecycle[start..]
        .find("\nstart_phase() {")
        .map(|offset| start + offset)
        .expect("find next lifecycle phase");
    &lifecycle[start..end]
}

fn exercise_upgrade(family: &str, manager_status: i32) -> (i32, String, String) {
    let temp = TestDir::new();
    let fake_bin = temp.path().join("bin");
    let state = temp.path().join("state");
    fs::create_dir(&fake_bin).expect("create fake bin directory");
    fs::create_dir(&state).expect("create fake state directory");
    fs::write(state.join("provision.txt"), format!("family={family}\n"))
        .expect("write provisioning metadata");

    executable(
        &fake_bin.join("package-manager"),
        "#!/bin/sh\nprintf '%s' \"${0##*/}\" >> \"$CALL_LOG\"\nfor arg in \"$@\"; do printf ' <%s>' \"$arg\" >> \"$CALL_LOG\"; done\nprintf '\\n' >> \"$CALL_LOG\"\nexit \"$UPGRADE_STATUS\"\n",
    );
    for manager in ["apt-get", "dnf", "zypper"] {
        let link = fake_bin.join(manager);
        #[cfg(unix)]
        std::os::unix::fs::symlink(fake_bin.join("package-manager"), link)
            .expect("link fake package manager");
    }
    executable(
        &fake_bin.join("dpkg-query"),
        "#!/bin/sh\nprintf 'dpkg-query\\n' >> \"$CALL_LOG\"\nprintf 'pkg=1\\n'\n",
    );
    executable(
        &fake_bin.join("rpm"),
        "#!/bin/sh\nprintf 'rpm\\n' >> \"$CALL_LOG\"\nprintf 'pkg=1\\n'\n",
    );

    let script = temp.path().join("exercise.sh");
    let body = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nexec 9>&2\nSTATE='{}'\ne2e_check_start() {{ :; }}\ne2e_check_pass() {{ :; }}\nfail() {{ printf '%s\\n' \"$*\" >&2; exit 1; }}\n{}\nos_upgrade_phase\n",
        state.display(),
        extracted_os_upgrade_phase()
    );
    executable(&script, &body);

    let log = temp.path().join("calls.log");
    let output = Command::new("bash")
        .arg(&script)
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("CALL_LOG", &log)
        .env("UPGRADE_STATUS", manager_status.to_string())
        .output()
        .expect("run extracted upgrade phase");
    let calls = read_text(&log).unwrap_or_default();
    let metadata = read_text(&state.join("provision.txt")).expect("read metadata");
    (output.status.code().unwrap_or(128), calls, metadata)
}

#[test]
fn os_upgrade_reuses_provisioned_metadata_for_all_package_families() {
    let cases = [
        ("apt", "apt-get <-y> <full-upgrade>", "dpkg-query\n"),
        ("dnf", "dnf <-y> <upgrade>", "rpm\n"),
        ("dnf-epel", "dnf <-y> <upgrade>", "rpm\n"),
        (
            "zypper",
            "zypper <--no-refresh> <--non-interactive> <update>",
            "rpm\n",
        ),
    ];

    for (family, expected_transaction, expected_inventory) in cases {
        for status in [0, 102, 103] {
            let (exit_code, calls, metadata) = exercise_upgrade(family, status);
            assert_eq!(exit_code, 0, "{family} status {status} should be accepted");
            assert_eq!(
                calls,
                format!("{expected_transaction}\n{expected_inventory}"),
                "{family} must perform its upgrade and inventory without refreshing metadata"
            );
            assert!(metadata.contains("os_upgrade_completed_utc="));
            if status == 0 {
                assert!(!metadata.contains("package_manager_reboot_status="));
            } else {
                assert!(metadata.contains(&format!("package_manager_reboot_status={status}")));
            }
        }

        let (exit_code, calls, metadata) = exercise_upgrade(family, 7);
        assert_eq!(exit_code, 7, "{family} must propagate transaction failure");
        assert_eq!(calls, format!("{expected_transaction}\n"));
        assert!(!metadata.contains("os_upgrade_completed_utc="));
        assert!(!metadata.contains("package_manager_reboot_status="));
    }
}
