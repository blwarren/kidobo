use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard};

// Parallel fixture writes and process creation intermittently cause ETXTBSY on Linux.
static TEST_FIXTURE_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TEST_DIR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) struct TestDir {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl TestDir {
    pub(super) fn new() -> Self {
        let guard = TEST_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kidobo-distro-e2e-tests-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self {
            path,
            _guard: guard,
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove test directory");
    }
}

pub(super) fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write test executable");
    let mut permissions = fs::metadata(path)
        .expect("read executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make test executable");
}

fn command_metadata_text(dir: &Path, id: usize) -> Result<String> {
    let document: serde_json::Value = serde_json::from_str(&read_text(&dir.join("results.json"))?)?;
    Ok(serde_json::to_string(&document["commands"][id - 1])?)
}
fn command_output(dir: &Path, id: usize, stream: &str) -> Result<String> {
    let transcript = read_text(&dir.join("transcript.log"))?;
    let marker = format!(" | command {id} | {stream}] ");
    Ok(transcript
        .lines()
        .filter_map(|line| {
            line.split_once(&marker)
                .map(|(_, text)| format!("{text}\n"))
        })
        .collect())
}
fn lifecycle_reporting_helpers() -> &'static str {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let end = lifecycle
        .find("readonly ROOT=")
        .expect("end of reporting preamble");
    &lifecycle[..end]
}

fn lifecycle_traffic_server_function() -> String {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("start_traffic_servers() {")
        .expect("find traffic server function in guest lifecycle script");
    let end = lifecycle[start..]
        .find("\nprobe() {")
        .map(|offset| start + offset)
        .expect("find probe function after traffic server function");
    format!(
        "{}\n{}",
        lifecycle_reporting_helpers(),
        &lifecycle[start..end]
    )
}

fn lifecycle_setup_namespace_function() -> String {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("setup_namespace() {")
        .expect("find namespace setup function in guest lifecycle script");
    let end = lifecycle[start..]
        .find("\nstart_traffic_servers() {")
        .map(|offset| start + offset)
        .expect("find traffic server function after namespace setup");
    format!(
        "{}\n{}",
        lifecycle_reporting_helpers(),
        &lifecycle[start..end]
    )
}

fn lifecycle_baseline_recovery_functions() -> String {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("debian12_baseline_recovery_allowed() {")
        .expect("find baseline recovery helpers in guest lifecycle script");
    let end = lifecycle[start..]
        .find("\ntest_uninstall_failure_preserves_runtime() {")
        .map(|offset| start + offset)
        .expect("find end of baseline recovery helpers");
    format!(
        "{}\n{}",
        lifecycle_reporting_helpers(),
        &lifecycle[start..end]
    )
}

fn lifecycle_upgrade_test_helpers() -> String {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("ensure_unrelated_sentinels() {")
        .expect("find firewall helpers in guest lifecycle script");
    let end = lifecycle[start..]
        .find("\ntest_uninstall_failure_preserves_runtime() {")
        .map(|offset| start + offset)
        .expect("find end of upgrade test helpers");
    format!(
        "{}\n{}",
        lifecycle_reporting_helpers(),
        &lifecycle[start..end]
    )
}

fn lifecycle_probe_function() -> String {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle
        .find("probe() {")
        .expect("find traffic probe helper in guest lifecycle script");
    let end = lifecycle[start..]
        .find("\nwrite_config() {")
        .map(|offset| start + offset)
        .expect("find end of traffic probe helper");
    format!(
        "{}\n{}",
        lifecycle_reporting_helpers(),
        &lifecycle[start..end]
    )
}

fn fake_baseline_check_script(temp: &TestDir, scenario: &str) -> (PathBuf, PathBuf) {
    let fake_bin = temp.path().join("baseline-bin");
    let state = temp.path().join("baseline-state");
    fs::create_dir(&fake_bin).expect("create baseline fake binary directory");
    fs::create_dir(&state).expect("create baseline state directory");
    for binary in ["iptables", "ip6tables"] {
        executable(
            &fake_bin.join(binary),
            r#"#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$FAKE_CALLS"
case "$*" in
  --version) [[ "$(basename "$0")" == ip6tables ]] && printf 'ip6tables v1.8.9 (nf_tables)\n' || printf 'iptables v1.8.9 (nf_tables)\n' ;;
  '-S kidobo-input') if [[ "$(basename "$0")" == ip6tables ]]; then printf '%s\n' '-A kidobo-input -m set --match-set kidobo-e2e-v6 src -j DROP'; else printf '%s\n' '-A kidobo-input -m set --match-set kidobo-e2e src -j DROP'; fi ;;
  '-S INPUT') printf '%s\n' '-A INPUT -j kidobo-input' '-A INPUT -j E2E-UNRELATED-SENTINEL' ;;
  '-S kidobo-input-stage') exit 1 ;;
  *) exit 0 ;;
esac
"#,
        );
    }
    executable(
        &fake_bin.join("iptables-save"),
        "#!/bin/bash\nif [[ \"${FAKE_ACTIVE_JUMP:-0}\" == 1 ]]; then printf '%s\\n' '-A INPUT -j kidobo-input'; else printf '%s\\n' '-A INPUT -j E2E-UNRELATED-SENTINEL'; fi\n",
    );
    executable(
        &fake_bin.join("ip6tables-save"),
        "#!/bin/bash\nif [[ \"${FAKE_ACTIVE_JUMP:-0}\" == 1 ]]; then printf '%s\\n' '-A INPUT -j kidobo-input'; else printf '%s\\n' '-A INPUT -j E2E-UNRELATED-SENTINEL'; fi\n",
    );
    executable(
        &fake_bin.join("ipset"),
        "#!/bin/bash\ncase \"$1\" in save) printf '%s\\n' 'create E2E-UNRELATED hash:ip';; list) printf '%s\\n' '192.0.2.239';; *) exit 0;; esac\n",
    );
    executable(
        &fake_bin.join("ip"),
        "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_CALLS\"\nexit 1\n",
    );
    let error = "firewall operation failed: firewall command failed `iptables -w 5 -S kidobo-input` with status Exited(1): iptables v1.8.9 (nf_tables): chain `kidobo-input' in table `filter' is incompatible, use 'nft' tool.";
    let error_shell = error.replace('\'', "'\\''");
    executable(
        &fake_bin.join("kidobo"),
        &format!(
            "#!/bin/bash\nprintf 'kidobo %s\\n' \"$*\" >> \"$FAKE_CALLS\"\ncase \"$FAKE_SYNC_RESULT\" in healthy) exit 0;; expected) printf '%s\\n' '{error_shell}' >&2; exit 1;; unexpected) printf '%s\\n' 'firewall operation failed: permission denied' >&2; exit 1;; esac\n"
        ),
    );
    let config = temp.path().join("config.toml");
    let blocklist = temp.path().join("blocklist.txt");
    let temporary = temp.path().join("temporary-bans.toml");
    let preserved_config = temp.path().join("config.preserved");
    let preserved_blocklist = temp.path().join("blocklist.preserved");
    let preserved_temporary = temp.path().join("temporary.preserved");
    fs::write(&config, "[ipset]\nset_name = 'test'\n").expect("write test config");
    fs::write(&blocklist, "198.51.100.1\n").expect("write test blocklist");
    fs::write(&temporary, "[bans]\nitems = []\n").expect("write test temporary bans");
    fs::copy(&config, &preserved_config).expect("preserve test config");
    fs::copy(&blocklist, &preserved_blocklist).expect("preserve test blocklist");
    fs::copy(&temporary, &preserved_temporary).expect("preserve test temporary bans");

    let calls = temp.path().join("baseline-calls.log");
    let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
    writeln!(script, "PATH='{}':$PATH", fake_bin.display()).expect("write fake PATH");
    writeln!(script, "STATE='{}'", state.display()).expect("write state path");
    writeln!(script, "CONFIG='{}'", config.display()).expect("write config path");
    writeln!(script, "BLOCKLIST='{}'", blocklist.display()).expect("write blocklist path");
    writeln!(script, "TEMPORARY='{}'", temporary.display()).expect("write temporary path");
    writeln!(script, "CALLS='{}'", calls.display()).expect("write call log path");
    writeln!(script, "FAKE_CALLS='{}'", calls.display()).expect("write fake call log path");
    script.push_str("ROOT=/opt/kidobo-e2e\nSET4=kidobo-e2e\nSET6=kidobo-e2e-v6\nTEST_NS=kidobo-e2e\nV4_HOST=198.18.77.1\nV6_HOST=fd42:6b69:646f:626f::1\nTRAFFIC_PORT=39471\n");
    writeln!(script, "FAKE_SYNC_RESULT='{scenario}'").expect("write fake sync behavior");
    let allow_recovery = i32::from(scenario != "healthy");
    writeln!(script, "FAKE_ALLOW_RECOVERY='{allow_recovery}'")
        .expect("write recovery guard behavior");
    script.push_str("FAKE_ACTIVE_JUMP=0\nexport FAKE_CALLS FAKE_SYNC_RESULT FAKE_ACTIVE_JUMP FAKE_ALLOW_RECOVERY\n");
    script.push_str("fail() { printf 'FAIL: %s\\n' \"$*\" >&2; exit 1; }\n");
    script.push_str(&lifecycle_probe_function());
    script.push('\n');
    script.push_str(&lifecycle_upgrade_test_helpers());
    script.push('\n');
    script.push_str(
        "debian12_baseline_recovery_allowed() { [[ \"${FAKE_ALLOW_RECOVERY:-0}\" == 1 ]]; }\n",
    );
    writeln!(
        script,
        "run_baseline_enforcement_check v0.14.3 '{}' '{}' '{}' '{}'\nprintf candidate-installed > '{}.candidate'\n",
        preserved_config.display(),
        preserved_blocklist.display(),
        preserved_temporary.display(),
        temporary.display(),
        state.join("candidate").display()
    )
    .expect("write baseline flow invocation");
    let script_path = temp.path().join("exercise-baseline-check.sh");
    executable(&script_path, &script);
    (script_path, calls)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "The extracted-shell regression covers the exact recovery gate and its rejected variants together"
)]
fn upgrade_recovery_guard_is_limited_to_recorded_debian12_baselines_and_error() {
    let temp = TestDir::new();
    let os_release = temp.path().join("os-release");
    let stderr = temp.path().join("baseline-sync.stderr");
    fs::write(&os_release, "ID=debian\nVERSION_ID=12\n").expect("write fake Debian os-release");
    let diagnostic = "firewall operation failed: firewall command failed `iptables -w 5 -S kidobo-input` with status Exited(1): iptables v1.8.9 (nf_tables): chain `kidobo-input' in table `filter' is incompatible, use 'nft' tool.";
    fs::write(&stderr, format!("{diagnostic}\n")).expect("write recorded baseline diagnostic");

    let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
    script.push_str(&lifecycle_baseline_recovery_functions());
    script.push('\n');
    writeln!(
        script,
        "debian12_baseline_recovery_allowed v0.14.3 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (nf_tables)'",
        os_release.display()
    )
    .expect("write positive recovery guard assertion");
    writeln!(
        script,
        "debian12_baseline_recovery_allowed v0.14.2 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (nf_tables)'",
        os_release.display()
    )
    .expect("write earlier baseline recovery guard assertion");
    writeln!(
        script,
        "! debian12_baseline_recovery_allowed v0.14.4 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (nf_tables)'",
        os_release.display()
    )
    .expect("write version guard assertion");
    writeln!(
        script,
        "! debian12_baseline_recovery_allowed v0.14.3 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (legacy)'",
        os_release.display()
    )
    .expect("write backend guard assertion");
    let non_debian = temp.path().join("ubuntu-release");
    fs::write(&non_debian, "ID=ubuntu\nVERSION_ID=24.04\n").expect("write fake Ubuntu os-release");
    writeln!(
        script,
        "! debian12_baseline_recovery_allowed v0.14.3 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (nf_tables)'",
        non_debian.display()
    )
    .expect("write distro guard assertion");
    let wrong_debian_release = temp.path().join("debian-release");
    fs::write(&wrong_debian_release, "ID=debian\nVERSION_ID=13\n")
        .expect("write fake Debian 13 os-release");
    writeln!(
        script,
        "! debian12_baseline_recovery_allowed v0.14.3 '{}' 'iptables v1.8.9 (nf_tables)' 'ip6tables v1.8.9 (nf_tables)'",
        wrong_debian_release.display()
    )
    .expect("write release guard assertion");
    writeln!(
        script,
        "baseline_missing_chain_diagnostic_matches 1 '{}'",
        stderr.display()
    )
    .expect("write positive diagnostic assertion");
    writeln!(
        script,
        "! baseline_missing_chain_diagnostic_matches 2 '{}'",
        stderr.display()
    )
    .expect("write status guard assertion");
    let wrong_error = temp.path().join("wrong-error.stderr");
    fs::write(&wrong_error, "iptables: permission denied\n").expect("write unrelated error");
    writeln!(
        script,
        "! baseline_missing_chain_diagnostic_matches 1 '{}'",
        wrong_error.display()
    )
    .expect("write diagnostic guard assertion");
    writeln!(
        script,
        "! debian12_baseline_recovery_allowed v0.14.3 '{}' 'iptables v1.8.9 (legacy)' 'ip6tables v1.8.9 (nf_tables)'",
        os_release.display()
    )
    .expect("write IPv4 backend guard assertion");
    for (name, wrong) in [
        (
            "command",
            diagnostic.replace("iptables -w 5 -S", "iptables -w 5 -C"),
        ),
        ("status", diagnostic.replace("Exited(1)", "Exited(2)")),
        (
            "chain",
            diagnostic.replace("kidobo-input", "kidobo-input-stage"),
        ),
        ("table", diagnostic.replace("table `filter'", "table `nat'")),
    ] {
        let path = temp.path().join(format!("wrong-{name}.stderr"));
        fs::write(&path, format!("{wrong}\n")).expect("write altered diagnostic");
        writeln!(
            script,
            "! baseline_missing_chain_diagnostic_matches 1 '{}'",
            path.display()
        )
        .expect("write exact-line diagnostic assertion");
    }

    let script_path = temp.path().join("exercise-baseline-recovery-guard.sh");
    executable(&script_path, &script);
    let mut runner = runner(temp.path());
    if let Err(error) = runner.command("bash", &[script_path.to_string_lossy().into_owned()], 5) {
        let stderr = command_output(temp.path(), 1, "stderr").unwrap_or_default();
        panic!(
            "only the recorded Debian 12 failure should qualify for recovery: {error}; {stderr}"
        );
    }
}

#[test]
fn upgrade_recovery_requires_baseline_firewall_to_have_no_kidobo_input_jump() {
    let temp = TestDir::new();
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake firewall command directory");
    for binary in ["iptables-save", "ip6tables-save"] {
        executable(
            &fake_bin.join(binary),
            "#!/bin/bash\nprintf '%s\\n' \"${FAKE_FIREWALL_RULES:-}\"\n",
        );
    }

    let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
    writeln!(script, "PATH='{}':$PATH", fake_bin.display()).expect("write fake PATH");
    script.push_str("fail() { printf 'FAIL: %s\\n' \"$*\" >&2; exit 1; }\n");
    script.push_str(&lifecycle_baseline_recovery_functions());
    script.push('\n');
    script.push_str("FAKE_FIREWALL_RULES='-A INPUT -j E2E-UNRELATED-SENTINEL'\nexport FAKE_FIREWALL_RULES\nassert_no_managed_firewall_jumps\n");
    let clean_script = temp.path().join("exercise-clean-baseline-firewall.sh");
    executable(&clean_script, &script);

    let mut runner = runner(temp.path());
    runner
        .command("bash", &[clean_script.to_string_lossy().into_owned()], 5)
        .expect("unrelated rules without a Kidobo jump should be accepted");

    script.push_str("FAKE_FIREWALL_RULES='-A INPUT -j kidobo-input'\nexport FAKE_FIREWALL_RULES\nassert_no_managed_firewall_jumps\n");
    let active_script = temp.path().join("exercise-active-baseline-firewall.sh");
    executable(&active_script, &script);
    let error = runner
        .command("bash", &[active_script.to_string_lossy().into_owned()], 5)
        .expect_err("a managed INPUT jump must reject the recovery path");
    assert!(error.to_string().contains("exited exit status: 1"));
    let stderr = command_output(temp.path(), 2, "stderr").expect("read rejection output");
    assert!(stderr.contains("shows active Kidobo enforcement"));
}

#[test]
fn upgrade_firewall_evidence_capture_fails_for_each_unavailable_save_command() {
    for failing in ["ipset", "iptables-save", "ip6tables-save"] {
        let temp = TestDir::new();
        let fake_bin = temp.path().join("bin");
        fs::create_dir(&fake_bin).expect("create fake save-command directory");
        executable(
            &fake_bin.join("ipset"),
            "#!/bin/bash\n[[ \"$1\" != save || \"$FAIL_CAPTURE\" != ipset ]] || exit 7\nprintf 'set evidence\\n'\n",
        );
        executable(
            &fake_bin.join("iptables-save"),
            "#!/bin/bash\n[[ \"$FAIL_CAPTURE\" != iptables-save ]] || exit 8\nprintf 'v4 evidence\\n'\n",
        );
        executable(
            &fake_bin.join("ip6tables-save"),
            "#!/bin/bash\n[[ \"$FAIL_CAPTURE\" != ip6tables-save ]] || exit 9\nprintf 'v6 evidence\\n'\n",
        );
        let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
        writeln!(script, "PATH='{}':$PATH", fake_bin.display()).expect("write fake PATH");
        writeln!(script, "FAIL_CAPTURE='{failing}'").expect("write failing command");
        script
            .push_str("export FAIL_CAPTURE\nfail() { printf 'FAIL: %s\\n' \"$*\" >&2; exit 1; }\n");
        script.push_str(&lifecycle_upgrade_test_helpers());
        script.push('\n');
        writeln!(
            script,
            "capture_upgrade_firewall_evidence '{}'",
            temp.path().join("firewall-evidence.txt").display()
        )
        .expect("write evidence capture call");
        let script_path = temp.path().join("exercise-firewall-capture.sh");
        executable(&script_path, &script);
        let mut runner = runner(temp.path());

        let error = runner
            .command("bash", &[script_path.to_string_lossy().into_owned()], 5)
            .expect_err("save failure must abort evidence capture");
        assert!(error.to_string().contains("exited exit status: 1"));
        let stderr = command_output(temp.path(), 1, "stderr").expect("read capture failure");
        let expected_error = if failing == "ipset" {
            "ipset save failed while capturing firewall evidence".to_owned()
        } else {
            format!("{failing} failed while capturing firewall evidence")
        };
        assert!(
            stderr.contains(&expected_error),
            "wrong failure for {failing}: {stderr}"
        );
    }
}

#[test]
fn baseline_check_keeps_healthy_dual_stack_enforcement_probes() {
    let temp = TestDir::new();
    let (script, calls) = fake_baseline_check_script(&temp, "healthy");
    let mut runner = runner(temp.path());

    if let Err(error) = runner.command("bash", &[script.to_string_lossy().into_owned()], 5) {
        let stderr = command_output(temp.path(), 1, "stderr").unwrap_or_default();
        panic!("healthy baseline sync and both enforcement probes should pass: {error}; {stderr}");
    }

    let calls = read_text(&calls).expect("read fake baseline calls");
    assert!(calls.contains(
        "netns exec kidobo-e2e python3 /opt/kidobo-e2e/traffic.py probe 198.18.77.1 39471"
    ));
    assert!(calls.contains("netns exec kidobo-e2e python3 /opt/kidobo-e2e/traffic.py probe fd42:6b69:646f:626f::1 39471"));
    assert_eq!(
        read_text(&temp.path().join("baseline-state/baseline-sync.status"))
            .expect("read baseline status"),
        "0\n"
    );
    assert!(
        !temp
            .path()
            .join("baseline-state/upgrade-recovery.txt")
            .exists()
    );
    assert!(
        temp.path()
            .join("baseline-state/candidate.candidate")
            .exists()
    );
}

#[test]
fn baseline_check_accepts_only_exact_recovery_and_preserves_evidence_and_state() {
    let temp = TestDir::new();
    let (script, calls) = fake_baseline_check_script(&temp, "expected");
    let mut runner = runner(temp.path());

    if let Err(error) = runner.command("bash", &[script.to_string_lossy().into_owned()], 5) {
        let stderr = command_output(temp.path(), 1, "stderr").unwrap_or_default();
        let sync_error =
            read_text(&temp.path().join("baseline-state/baseline-sync.stderr")).unwrap_or_default();
        panic!(
            "exact known failure should proceed to candidate recovery: {error}; {stderr}; sync: {sync_error}"
        );
    }

    let state = temp.path().join("baseline-state");
    let calls = read_text(&calls).expect("read fake baseline calls");
    assert!(
        calls.contains("kidobo sync"),
        "baseline sync must always run"
    );
    assert!(calls.contains("-C INPUT -j E2E-UNRELATED-SENTINEL"));
    assert_eq!(
        read_text(&state.join("baseline-sync.status")).unwrap(),
        "1\n"
    );
    assert!(
        read_text(&state.join("baseline-sync.stderr"))
            .unwrap()
            .contains("iptables -w 5 -S kidobo-input")
    );
    assert!(state.join("baseline-firewall-before.txt").is_file());
    assert!(state.join("baseline-firewall-after.txt").is_file());
    assert!(
        read_text(&state.join("upgrade-recovery.txt"))
            .unwrap()
            .contains("candidate enforcement is required next")
    );
    assert!(state.join("candidate.candidate").is_file());
    for (live, saved) in [
        ("config.toml", "config.preserved"),
        ("blocklist.txt", "blocklist.preserved"),
        ("temporary-bans.toml", "temporary.preserved"),
    ] {
        assert_eq!(
            read_text(&temp.path().join(live)).unwrap(),
            read_text(&temp.path().join(saved)).unwrap()
        );
    }
}

#[test]
fn baseline_check_aborts_on_unexpected_error_before_candidate_install() {
    let temp = TestDir::new();
    let (script, _) = fake_baseline_check_script(&temp, "unexpected");
    let mut runner = runner(temp.path());

    let error = runner
        .command("bash", &[script.to_string_lossy().into_owned()], 5)
        .expect_err("unexpected baseline sync errors must abort before candidate install");

    assert!(error.to_string().contains("exited exit status: 1"));
    let state = temp.path().join("baseline-state");
    let stderr = command_output(temp.path(), 1, "stderr").expect("read phase failure");
    assert!(
        stderr.contains("published baseline sync failed unexpectedly"),
        "unexpected fake baseline error: {stderr}"
    );
    assert_eq!(
        read_text(&state.join("baseline-sync.status")).unwrap(),
        "1\n"
    );
    assert!(!state.join("candidate.candidate").exists());
    assert!(!state.join("upgrade-recovery.txt").exists());
}

fn fake_namespace_runner_script(temp: &TestDir, network_manager_state: &str) -> (PathBuf, PathBuf) {
    let fake_bin = temp.path().join("bin");
    let call_log = temp.path().join("namespace-calls.log");
    fs::create_dir(&fake_bin).expect("create fake namespace bin directory");
    executable(
        &fake_bin.join("ip"),
        r#"#!/bin/bash
set -eu
printf 'ip %s\n' "$*" >> "$CALL_LOG"
"#,
    );
    executable(
        &fake_bin.join("nmcli"),
        r#"#!/bin/bash
set -eu
printf 'nmcli %s\n' "$*" >> "$CALL_LOG"
case "$*" in
  '-g RUNNING general') printf 'running\n' ;;
  '-g GENERAL.DEVICE device show ke2eh0') printf 'ke2eh0\n' ;;
  '-w 10 device set ke2eh0 managed no') ;;
  '-g GENERAL.STATE device show ke2eh0') printf '%s\n' "$FAKE_NM_STATE" ;;
  *) printf 'unexpected nmcli call: %s\n' "$*" >&2; exit 91 ;;
esac
"#,
    );

    let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
    writeln!(script, "PATH='{}':$PATH", fake_bin.display()).expect("write fake PATH");
    writeln!(script, "CALL_LOG='{}'", call_log.display()).expect("write call log path");
    writeln!(script, "FAKE_NM_STATE='{network_manager_state}'")
        .expect("write fake NetworkManager state");
    script.push_str("export CALL_LOG FAKE_NM_STATE\n");
    script.push_str(
        "TEST_NS=kidobo-e2e\nHOST_IF=ke2eh0\nPEER_IF=ke2ep0\nV4_HOST=198.18.77.1\nV4_PEER=198.18.77.2\nV6_HOST=fd42:6b69:646f:626f::1\nV6_PEER=fd42:6b69:646f:626f::2\n",
    );
    script.push_str(
        r#"
fail() { printf 'e2e lifecycle: %s\n' "$*" >&2; exit 1; }
ensure_clean_namespace() { printf 'ensure-clean\n' >> "$CALL_LOG"; }
"#,
    );
    script.push_str(&lifecycle_setup_namespace_function());
    script.push_str("\nsetup_namespace\n");
    let script_path = temp.path().join("exercise-namespace-setup.sh");
    executable(&script_path, &script);
    (script_path, call_log)
}

fn fake_traffic_runner_script(temp: &TestDir, failing_address: Option<&str>) -> PathBuf {
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&state).expect("create fake fixture state directory");
    fs::create_dir(&fake_bin).expect("create fake fixture bin directory");
    let python = fake_bin.join("python3");
    executable(
        &python,
        r#"#!/bin/bash
set -euo pipefail
if [[ "$2" != serve || $# -ne 5 ]]; then
  printf 'unexpected fake python3 arguments: %s\n' "$*" >&2
  exit 90
fi
if [[ "${FAKE_FAIL_ADDRESS:-}" == "$3" ]]; then
  printf 'deliberate fixture startup failure for %s\n' "$3" >&2
  exit 23
fi
printf 'ready\n' > "$5"
exec -a "$1 $2 $3 $4" sleep 30
"#,
    );

    let mut script = String::from("#!/bin/bash\nset -euo pipefail\n");
    writeln!(script, "ROOT='{}'", temp.path().display()).expect("write fake root");
    writeln!(script, "STATE='{}'", state.display()).expect("write fake state path");
    writeln!(script, "PATH='{}':$PATH", fake_bin.display()).expect("write fake PATH");
    script.push_str("V4_HOST=198.18.77.1\nV6_HOST=fd42:6b69:646f:626f::1\nTRAFFIC_PORT=39471\n");
    if let Some(address) = failing_address {
        writeln!(script, "FAKE_FAIL_ADDRESS='{address}'").expect("write failing address");
        script.push_str("export FAKE_FAIL_ADDRESS\n");
    }
    script.push_str(
        r#"
fail() { printf 'e2e lifecycle: %s\n' "$*" >&2; exit 1; }
stop_fixture() { :; }
cleanup_fakes() {
  for pid_file in "$STATE"/server-*.pid; do
    [[ -f "$pid_file" ]] || continue
    pid=$(<"$pid_file")
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup_fakes EXIT
"#,
    );
    script.push_str(&lifecycle_traffic_server_function());
    script.push_str(
        r#"
start_traffic_servers
for address in "$V4_HOST" "$V6_HOST"; do
  if [[ "$address" == *:* ]]; then label=v6; else label=v4; fi
  pid=$(<"$STATE/server-$label.pid")
  [[ -s "$STATE/server-$label.ready" ]] || fail "$label fixture did not publish readiness"
  [[ -r "/proc/$pid/cmdline" ]] || fail "$label fixture proc cmdline is unreadable"
  [[ ! -s "/proc/$pid/cmdline" ]] || fail "$label fixture expected proc cmdline st_size to be zero"
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
  [[ "$cmdline" == *"$ROOT/traffic.py serve $address $TRAFFIC_PORT"* ]] || fail "$label fixture PID does not match expected command"
done
"#,
    );
    let script_path = temp.path().join("exercise-traffic-servers.sh");
    executable(&script_path, &script);
    script_path
}

#[test]
fn guest_traffic_server_readiness_uses_proc_content_not_file_size() {
    let temp = TestDir::new();
    let script = fake_traffic_runner_script(&temp, None);
    let mut runner = runner(temp.path());

    runner
        .command("bash", &[script.to_string_lossy().into_owned()], 5)
        .expect("both fake traffic servers should become ready");
}

#[test]
fn guest_traffic_server_startup_failure_is_reported_and_cleaned_up() {
    let temp = TestDir::new();
    let script = fake_traffic_runner_script(&temp, Some("fd42:6b69:646f:626f::1"));
    let mut runner = runner(temp.path());

    let error = runner
        .command("bash", &[script.to_string_lossy().into_owned()], 5)
        .expect_err("a fixture child that exits before readiness must fail the phase");

    let stderr = command_output(temp.path(), 1, "stderr").expect("read startup failure log");
    assert!(
        error.to_string().contains("exited exit status: 1"),
        "unexpected runner error: {error}; stderr: {stderr}"
    );
    assert!(stderr.contains("traffic fixture v6 exited before readiness"));
    assert!(stderr.contains("deliberate fixture startup failure"));
    assert!(temp.path().join("state/server-v4.ready").exists());
    assert!(!temp.path().join("state/server-v6.ready").exists());
}

#[test]
fn guest_background_fixtures_release_exec_streams_while_still_running() {
    let lifecycle = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = lifecycle.find("fixture_curl() {").expect("HTTP helpers");
    let end = lifecycle
        .find("defer_timer_until_configuration_is_ready() {")
        .expect("end of HTTP helpers");
    let traffic_start = lifecycle
        .find("start_traffic_servers() {")
        .expect("traffic startup helper");
    let traffic_end = lifecycle
        .find("\nprobe() {")
        .expect("end of traffic startup");
    for invocation in [
        "serve_dir \"$ROOT/release\" 39472 release",
        "start_source_fixture",
        "start_traffic_servers",
    ] {
        let temp = TestDir::new();
        let bin = temp.path().join("bin");
        let state = temp.path().join("state");
        fs::create_dir(&bin).expect("fake command directory");
        fs::create_dir(&state).expect("fixture state directory");
        executable(
            &bin.join("python3"),
            r#"#!/bin/bash
set -eu
if [[ "$1" == -m ]]; then
  printf ready > "$STATE/http-${!#}.ready"
elif [[ "$2" == source ]]; then
  printf ready > "$STATE/http-$4.ready"
else
  printf ready > "$5"
fi
exec -a "$*" sleep 30
"#,
        );
        executable(
            &bin.join("curl"),
            r#"#!/bin/bash
set -eu
url=${!#}
port=${url#http://127.0.0.1:}
port=${port%%/*}
[[ -f "$STATE/http-$port.ready" ]]
"#,
        );
        let script = temp.path().join("fixtures.sh");
        executable(
            &script,
            &format!(
                "{}\nROOT='{}'\nSTATE='{}'\nexport STATE\nPATH='{}':$PATH\n\
                 SOURCE_PORT=39474 TRAFFIC_PORT=39471\n\
                 V4_HOST=198.18.77.1 V6_HOST=fd42:6b69:646f:626f::1\n\
                 fail() {{ printf '%s\\n' \"$*\" >&2; exit 1; }}\n\
                 {}\n{}\n{invocation}\n",
                lifecycle_reporting_helpers(),
                temp.path().display(),
                state.display(),
                bin.display(),
                &lifecycle[start..end],
                &lifecycle[traffic_start..traffic_end],
            ),
        );
        let mut runner = runner(temp.path());
        // The reader must see EOF before the fake servers are stopped. A host
        // runner using regular capture files alone cannot detect guest FD leaks.
        let outcome = runner.command(
            "bash",
            &strings(&[
                "-c",
                r#"
set -o pipefail
bash "$1" 2>&1 | cat
status=$?
for pid_file in "$2"/*.pid; do
  pid=$(<"$pid_file")
  kill -0 "$pid" || status=91
  kill "$pid" || status=92
done
exit "$status"
"#,
                "fixture-stream-test",
                script.to_str().expect("script path"),
                state.to_str().expect("state path"),
            ]),
            3,
        );
        let output = command_output(temp.path(), 1, "stdout").expect("fixture trace");
        outcome.unwrap_or_else(|error| {
            panic!("{invocation} kept exec streams open after shell exit: {error}; {output}")
        });
        assert!(output.contains("TRACE"), "parent tracing must stay enabled");
    }
}

#[test]
fn guest_namespace_setup_unmanages_host_veth_before_assigning_addresses() {
    let temp = TestDir::new();
    let (script, call_log) = fake_namespace_runner_script(&temp, "10 (unmanaged)");
    let mut runner = runner(temp.path());

    runner
        .command("bash", &[script.to_string_lossy().into_owned()], 5)
        .expect("namespace setup should succeed after NetworkManager releases the veth");

    let calls = read_text(&call_log).expect("read fake network command log");
    let managed = calls
        .lines()
        .position(|line| line == "nmcli -w 10 device set ke2eh0 managed no")
        .expect("NetworkManager managed=no call");
    let host_address = calls
        .lines()
        .position(|line| line == "ip addr add 198.18.77.1/30 dev ke2eh0")
        .expect("host IPv4 address assignment");
    assert!(
        managed < host_address,
        "NetworkManager call must precede address assignment:\n{calls}"
    );
    assert!(calls.contains("ip -6 addr add fd42:6b69:646f:626f::1/64 dev ke2eh0 nodad"));
    assert!(calls.contains("ip netns exec kidobo-e2e ip addr add 198.18.77.2/30 dev ke2ep0"));
}

#[test]
fn guest_namespace_setup_stops_before_addressing_when_nm_state_is_not_unmanaged() {
    let temp = TestDir::new();
    let (script, call_log) = fake_namespace_runner_script(&temp, "100 (connecting)");
    let mut runner = runner(temp.path());

    let error = runner
        .command("bash", &[script.to_string_lossy().into_owned()], 5)
        .expect_err("namespace setup must fail if NetworkManager has not released the veth");

    assert!(error.to_string().contains("exited exit status: 1"));
    let stderr = command_output(temp.path(), 1, "stderr").expect("read namespace failure log");
    assert!(stderr.contains("NetworkManager still manages the fixture veth"));
    let calls = read_text(&call_log).expect("read fake network command log");
    assert!(
        !calls.contains("addr add"),
        "no addresses may be assigned before unmanaged state:\n{calls}"
    );
}

fn runner(dir: &Path) -> Runner {
    Runner {
        project: "test-project".into(),
        dir: dir.to_path_buf(),
        incus_program: PathBuf::from("incus"),
        cancelled: Arc::new(AtomicBool::new(false)),
        report: Report::open(dir).expect("open test report"),
    }
}

fn runner_with_incus(dir: &Path, program: &Path) -> Runner {
    let mut runner = runner(dir);
    runner.incus_program = program.to_path_buf();
    runner
}

fn fake_incus(temp: &TestDir) -> (PathBuf, PathBuf) {
    let program = temp.path().join("fake-incus");
    let log = temp.path().join("incus-args.log");
    executable(
        &program,
        &format!(
            "#!/bin/bash\nset -eu\nprintf '<%s>' \"$@\" >> '{}'\nprintf '\\n' >> '{}'\nif [[ \"${{3:-}}\" == list ]]; then\n  case \"${{4:-}}\" in\n    vm-owned) printf '%s\\n' '[{{\"name\":\"vm-owned\",\"type\":\"virtual-machine\",\"config\":{{\"user.kidobo-e2e\":\"{OWNER}\"}}}}]' ;;\n    vm-container) printf '%s\\n' '[{{\"name\":\"vm-container\",\"type\":\"container\",\"config\":{{\"user.kidobo-e2e\":\"{OWNER}\"}}}}]' ;;\n    vm-unowned) printf '%s\\n' '[{{\"name\":\"vm-unowned\",\"type\":\"virtual-machine\",\"config\":{{\"user.kidobo-e2e\":\"someone-else\"}}}}]' ;;\n    *) printf '[]\\n' ;;\n  esac\nelse\n  printf 'fake-incus-output\\n'\nfi\n",
            log.display(),
            log.display()
        ),
    );
    (program, log)
}

fn fake_setup_incus(temp: &TestDir, profile_owner: &str, mode: &str) -> (PathBuf, PathBuf) {
    let program = temp.path().join("fake-setup-incus");
    let log = temp.path().join("setup-incus-args.log");
    let script = r#"#!/bin/bash
set -eu
printf '<%s>' "$@" >> '__LOG__'
printf '\n' >> '__LOG__'
if [[ "$1" != --project ]]; then exit 90; fi
if [[ "$2" == default ]]; then
  case "${4:-}" in
    show) printf 'description: kidobo-e2e-v1\n'; exit 0 ;;
    get) printf '%s\n' 'kidobo-e2e-v1'; exit 0 ;;
  esac
fi
if [[ "${3:-}" == profile ]]; then
  case "${4:-}" in
    show) printf 'description: kidobo-e2e-v1\n'; exit 0 ;;
    get)
      case "${6:-}" in
        user.kidobo-e2e) printf '%s\n' '__PROFILE_OWNER__' ;;
        limits.cpu) if [[ '__MODE__' == drift ]]; then printf '2\n'; else printf '4\n'; fi ;;
        limits.memory) printf '4GiB\n' ;;
        *) exit 91 ;;
      esac
      exit 0
      ;;
    device)
      case "${5:-}" in
        get)
          device="${7:-}"
          property="${8:-}"
          if [[ "$property" == type ]]; then
            case "__MODE__:$device" in
              missing-root:root|missing-eth0:eth0) exit 1 ;;
              wrong-root:root) printf 'nic\n' ;;
              wrong-eth0:eth0) printf 'disk\n' ;;
              *) if [[ "$device" == root ]]; then printf 'disk\n'; else printf 'nic\n'; fi ;;
            esac
          else
            case "$device:$property" in
              root:path) printf '/\n' ;;
              root:pool) printf 'test-pool\n' ;;
              root:size) if [[ '__MODE__' == drift ]]; then printf '8GiB\n'; else printf '20GiB\n'; fi ;;
              eth0:network) if [[ '__MODE__' == drift ]]; then printf 'other-network\n'; else printf 'test-network\n'; fi ;;
              eth0:name) printf 'eth0\n' ;;
              *) exit 92 ;;
            esac
          fi
          exit 0
          ;;
        add|set) exit 0 ;;
      esac
      ;;
    set|create) exit 0 ;;
  esac
fi
exit 93
"#
    .replace("__LOG__", &log.display().to_string())
    .replace("__PROFILE_OWNER__", profile_owner)
    .replace("__MODE__", mode);
    executable(&program, &script);
    (program, log)
}

fn setup_config() -> Config {
    Config {
        project: "test-project".into(),
        profile: "test-profile".into(),
        network: "test-network".into(),
        pool: "test-pool".into(),
        cpus: 4,
        memory: "4GiB".into(),
        disk: "20GiB".into(),
        distros: vec![],
    }
}

fn setup_calls(log: &Path) -> Vec<String> {
    read_text(log)
        .expect("read setup fake Incus log")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn setup_rejects_profile_owner_suffix_and_description_only_marker() {
    for owner in [format!("{OWNER}-suffix"), String::new()] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, &owner, "unchanged");
        let mut runner = runner_with_incus(temp.path(), &program);

        let error =
            setup(&mut runner, &setup_config()).expect_err("spoofed profile must be rejected");

        assert!(
            error
                .to_string()
                .contains("existing profile is not suite-owned")
        );
        let calls = setup_calls(&log);
        assert!(
            calls
                .iter()
                .any(|call| call.contains("<profile><show><test-profile>"))
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("<profile><get><test-profile><user.kidobo-e2e>"))
        );
        assert!(!calls.iter().any(|call| call.contains("<device><add>")));
        assert!(!calls.iter().any(|call| call.contains("<device><set>")));
    }
}

#[test]
fn setup_recovers_each_missing_owned_profile_device() {
    for (mode, device, kind) in [
        ("missing-root", "root", "disk"),
        ("missing-eth0", "eth0", "nic"),
    ] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, OWNER, mode);
        let mut runner = runner_with_incus(temp.path(), &program);

        setup(&mut runner, &setup_config()).expect("partial profile should be repaired");

        let calls = setup_calls(&log);
        let add = if device == "root" {
            "<profile><device><add><test-profile><root><disk><path=/><pool=test-pool><size=20GiB>"
        } else {
            "<profile><device><add><test-profile><eth0><nic><network=test-network><name=eth0>"
        };
        assert!(
            calls.iter().any(|call| call.contains(add)),
            "missing {device} add"
        );
        assert!(calls.iter().any(|call| call.contains(&format!(
            "<profile><device><get><test-profile><{device}><type>"
        ))));
        assert!(!calls.iter().any(|call| {
            call.contains(&format!("<profile><device><set><test-profile><{device}>"))
                || (kind == "disk" && call.contains("<profile><device><add><test-profile><eth0>"))
                || (kind == "nic" && call.contains("<profile><device><add><test-profile><root>"))
        }));
    }
}

#[test]
fn setup_rejects_wrong_type_for_existing_owned_profile_devices() {
    for (mode, device) in [("wrong-root", "root"), ("wrong-eth0", "eth0")] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, OWNER, mode);
        let mut runner = runner_with_incus(temp.path(), &program);

        let error = setup(&mut runner, &setup_config()).expect_err("wrong device type must fail");

        let error = error.to_string();
        assert!(
            error.contains(&format!("device {device} has type")),
            "wrong-device-type setup failed for an unexpected reason: {error}"
        );
        let calls = setup_calls(&log);
        assert!(!calls.iter().any(|call| {
            call.contains(&format!("<profile><device><add><test-profile><{device}>"))
                || call.contains(&format!("<profile><device><set><test-profile><{device}>"))
        }));
    }
}

#[test]
fn setup_updates_only_drifted_properties_and_leaves_current_profile_unchanged() {
    let temp = TestDir::new();
    let (program, log) = fake_setup_incus(&temp, OWNER, "drift");
    let mut runner = runner_with_incus(temp.path(), &program);

    setup(&mut runner, &setup_config()).expect("owned profile drift should be reconciled");

    let calls = setup_calls(&log);
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><device><set><test-profile><root><size=20GiB>"
    }));
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><device><set><test-profile><eth0><network=test-network>"
    }));
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><set><test-profile><limits.cpu=4>"
    }));
    assert!(!calls.iter().any(|call| call.contains("<device><add>")));
    drop(temp);

    let temp = TestDir::new();
    let (program, log) = fake_setup_incus(&temp, OWNER, "unchanged");
    let mut runner = runner_with_incus(temp.path(), &program);

    setup(&mut runner, &setup_config()).expect("owned current profile should remain unchanged");

    let calls = setup_calls(&log);
    assert!(!calls.iter().any(|call| {
        call.contains("<create>") || call.contains("<add>") || call.contains("<set>")
    }));
}

#[test]
fn freeze_archive_preserves_private_archive_and_checksum_snapshot() {
    let temp = TestDir::new();
    fs::create_dir(temp.path().join("inputs")).expect("create input snapshot directory");
    let source = temp.path().join("candidate.tar.gz");
    let manifest = temp.path().join("SHA256SUMS");
    let archive_bytes = b"candidate archive bytes";
    let manifest_bytes = b"original digest  candidate.tar.gz\n";
    fs::write(&source, archive_bytes).expect("write source archive");
    fs::write(&manifest, manifest_bytes).expect("write source checksum manifest");

    let frozen = freeze_archive(&source, temp.path()).expect("freeze candidate archive");
    let frozen_manifest = temp.path().join("inputs/release/SHA256SUMS");

    fs::write(&source, b"mutated caller archive").expect("mutate caller archive");
    fs::write(&manifest, b"mutated caller manifest").expect("mutate caller manifest");

    assert_eq!(
        read_text(&frozen).expect("read frozen archive").as_bytes(),
        archive_bytes
    );
    assert_eq!(
        read_text(&frozen_manifest)
            .expect("read frozen checksum manifest")
            .as_bytes(),
        manifest_bytes
    );
    assert_ne!(
        hash(&frozen).expect("hash frozen archive"),
        hash(&source).expect("hash mutated caller archive")
    );
    assert_ne!(
        hash(&frozen_manifest).expect("hash frozen manifest"),
        hash(&manifest).expect("hash mutated caller manifest")
    );
}

#[test]
fn identifiers_cannot_escape_resource_namespace() {
    for name in ["../default", "", "other:vm", "/", "a b"] {
        assert!(!safe_name(name));
    }
    assert!(safe_name("run-123-debian-13"));
}

#[test]
fn rejects_version_injection() {
    assert!(tag_valid("v0.14.3"));
    assert!(!tag_valid("v1/../../"));
    assert!(!tag_valid("latest"));
}

#[test]
fn runner_records_nonzero_exit_and_keeps_both_output_streams() {
    let temp = TestDir::new();
    let program = temp.path().join("fail-command");
    executable(
        &program,
        "#!/bin/sh\nprintf 'stdout evidence\\n'\nprintf 'stderr evidence\\n' >&2\nexit 17\n",
    );
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("nonzero command must fail");

    assert!(error.to_string().contains("exited exit status: 17"));
    assert_eq!(
        command_output(temp.path(), 1, "stdout").expect("read stdout log"),
        "stdout evidence\n"
    );
    assert_eq!(
        command_output(temp.path(), 1, "stderr").expect("read stderr log"),
        "stderr evidence\n"
    );
    let metadata: serde_json::Value = serde_json::from_str(
        &command_metadata_text(temp.path(), 1).expect("read command metadata"),
    )
    .expect("parse command metadata");
    assert_eq!(metadata["code"], 17);
    assert_eq!(
        metadata["program"],
        program.to_str().expect("program path is UTF-8")
    );
}

#[test]
fn runner_records_spawn_failure_metadata() {
    let temp = TestDir::new();
    let program = temp.path().join("missing-command");
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("missing program must fail");

    assert!(error.to_string().contains("failed to start"));
    let metadata: serde_json::Value =
        serde_json::from_str(&command_metadata_text(temp.path(), 1).expect("read spawn metadata"))
            .expect("parse spawn metadata");
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert!(
        metadata["error"]
            .as_str()
            .expect("spawn error is a string")
            .contains("spawn failed")
    );
    assert_eq!(metadata["program"], program.to_str().expect("UTF-8 path"));
}

#[test]
fn runner_timeout_kills_descendants_in_its_process_group() {
    let temp = TestDir::new();
    let program = temp.path().join("spawn-descendant");
    let marker = temp.path().join("descendant-finished");
    let spawned = temp.path().join("descendant-started");
    executable(
        &program,
        &format!(
            "#!/bin/sh\n(sleep 2; printf alive > '{}') &\nprintf started > '{}'\nwait\n",
            marker.display(),
            spawned.display()
        ),
    );
    let mut runner = runner(temp.path());

    let args = vec!["--probe".to_owned()];
    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &args, 1)
        .expect_err("command must time out");

    assert!(error.to_string().contains("timed out"));
    let metadata: serde_json::Value = serde_json::from_str(
        &command_metadata_text(temp.path(), 1).expect("read timeout metadata"),
    )
    .expect("parse timeout metadata");
    assert_eq!(metadata["args"], json!(["--probe"]));
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert_eq!(metadata["error"], "timed out");
    assert!(metadata["seconds"].as_f64().is_some());
    assert!(spawned.exists(), "the test descendant should have started");
    std::thread::sleep(Duration::from_millis(2200));
    assert!(
        !marker.exists(),
        "timed-out descendant must not keep running"
    );
}

#[test]
fn runner_records_interruption_metadata() {
    let temp = TestDir::new();
    let program = temp.path().join("wait");
    executable(&program, "#!/bin/sh\nsleep 30\n");
    let mut runner = runner(temp.path());
    runner.cancelled.store(true, Ordering::Relaxed);

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 30)
        .expect_err("cancelled command must fail");

    assert!(error.to_string().contains("interrupted"));
    let metadata: serde_json::Value = serde_json::from_str(
        &command_metadata_text(temp.path(), 1).expect("read interruption metadata"),
    )
    .expect("parse interruption metadata");
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert_eq!(metadata["error"], "interrupted");
    assert!(metadata["seconds"].as_f64().is_some());
}

#[test]
fn runner_reports_stdout_larger_than_capture_limit() {
    let temp = TestDir::new();
    let program = temp.path().join("large-output");
    executable(
        &program,
        "#!/bin/sh\ndd if=/dev/zero bs=16777217 count=1 status=none\n",
    );
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("oversized output must not be silently truncated");

    assert!(
        error
            .to_string()
            .contains("stdout exceeds the 16777216-byte capture limit")
    );
    assert_eq!(
        runner.report.document["commands"][0]["stdout_bytes"]
            .as_u64()
            .expect("stdout byte count"),
        16 * 1024 * 1024 + 1
    );
}

#[test]
fn vm_validation_accepts_only_suite_owned_virtual_machines() {
    let owned_vm = json!({
        "type": "virtual-machine",
        "config": {"user.kidobo-e2e": OWNER}
    });
    validate_vm_config(&owned_vm).expect("owned VM accepted");

    for unowned in [
        json!({"type": "container", "config": {"user.kidobo-e2e": OWNER}}),
        json!({"type": "virtual-machine", "config": {"user.kidobo-e2e": "someone-else"}}),
        json!({"type": "virtual-machine", "config": {}}),
        json!({"type": "virtual-machine"}),
        json!(null),
    ] {
        assert!(
            validate_vm_config(&unowned).is_err(),
            "unexpectedly accepted {unowned}"
        );
    }
}

#[test]
fn ownership_manifest_must_match_project_owner_and_run_id() {
    let owned = Owned {
        owner: OWNER.into(),
        project: "test-project".into(),
        instances: vec!["run-123-debian".into(), "run-123-alpine".into()],
    };
    validate_owned_manifest(&owned, "test-project", "run-123").expect("valid owned manifest");

    assert!(validate_owned_manifest(&owned, "other-project", "run-123").is_err());
    assert!(validate_owned_manifest(&owned, "test-project", "other-run").is_err());
    assert!(validate_owned_manifest(&owned, "test-project", "../run-123").is_err());

    let mut wrong_owner = Owned {
        owner: "someone-else".into(),
        project: owned.project.clone(),
        instances: owned.instances.clone(),
    };
    assert!(validate_owned_manifest(&wrong_owner, "test-project", "run-123").is_err());

    wrong_owner.owner = OWNER.into();
    wrong_owner.instances.push("run-999-unrelated".into());
    assert!(validate_owned_manifest(&wrong_owner, "test-project", "run-123").is_err());
}

#[test]
fn rendered_summary_includes_target_state_and_image_fingerprint() {
    let results = vec![json!({
        "distro": "debian-13",
        "phase": "application",
        "error": null,
        "seconds": 12.5,
        "image": "debian/13",
        "image_fingerprint": "sha256:abc123",
        "diagnostic_errors": [],
    })];

    let temp = TestDir::new();
    let mut report = Report::open(temp.path()).expect("open report");
    report.document["tag"] = json!("v1.2.3");
    report.document["archive_sha256"] = json!("sha256:archive");
    report.document["results"] = json!(results);
    report.save().expect("save summary");
    let summary = read_text(&temp.path().join("summary.txt")).expect("read summary");
    assert!(summary.contains("tag: v1.2.3"));
    assert!(summary.contains("sha256:archive"));
    assert!(summary.contains("debian-13: PASS"));
    assert!(summary.contains("debian/13"));
    assert!(summary.contains("sha256:abc123"));
}

#[test]
fn guest_push_and_delete_route_only_through_verified_incus_vm() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);
    let host_marker = temp.path().join("host-payload-ran");
    let payload = format!("touch {}", host_marker.display());
    let guest_output = runner
        .guest("vm-owned", &strings(&["sh", "-c", &payload]), 5)
        .expect("guest command is routed through Incus");
    assert_eq!(guest_output, "fake-incus-output\n");

    let source = temp.path().join("artifact with spaces.txt");
    fs::write(&source, "fixture").expect("write push fixture");
    runner
        .push("vm-owned", &source, "/tmp/artifact.txt", false)
        .expect("file push is routed through Incus");
    runner
        .delete("vm-owned")
        .expect("delete is routed through Incus");

    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 6, "each operation verifies before acting");
    assert_eq!(
        calls[0],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert!(calls[1].contains("<exec><vm-owned><--mode=non-interactive><-->"));
    assert_eq!(
        calls[2],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert!(calls[3].contains("<file><push>"));
    assert!(calls[3].contains("<vm-owned/tmp/artifact.txt>"));
    assert_eq!(
        calls[4],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert_eq!(
        calls[5],
        "<--project><test-project><delete><vm-owned><--force>"
    );
    assert!(
        !host_marker.exists(),
        "guest payload must never run on the host"
    );
}

#[test]
fn guest_push_and_delete_reject_unowned_or_non_vm_targets_before_action() {
    for (vm, operation) in [
        ("vm-container", "guest"),
        ("vm-unowned", "push"),
        ("vm-container", "delete"),
    ] {
        let temp = TestDir::new();
        let (program, log) = fake_incus(&temp);
        let mut runner = runner_with_incus(temp.path(), &program);
        let source = temp.path().join("source");
        fs::write(&source, "fixture").expect("write push fixture");

        let result = match operation {
            "guest" => runner.guest(vm, &strings(&["true"]), 5).map(|_| ()),
            "push" => runner.push(vm, &source, "/tmp/source", false),
            "delete" => runner.delete(vm),
            _ => unreachable!(),
        };

        assert!(result.is_err(), "{operation} unexpectedly accepted {vm}");
        let error = result.expect_err("invalid target must be rejected");
        assert!(
            error.to_string().contains("unowned or non-VM"),
            "{operation} on {vm} failed for an unexpected reason: {error}"
        );
        let calls = read_text(&log).expect("read fake Incus log");
        let calls: Vec<_> = calls.lines().collect();
        assert_eq!(
            calls.len(),
            1,
            "rejected {operation} must not issue an action"
        );
        assert!(calls[0].contains(&format!("<list><{vm}><--format=json>")));
    }
}

#[test]
fn create_vm_verifies_ownership_before_agent_disk_and_start() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);

    runner
        .create_vm("debian/13", "vm-owned", "test-profile")
        .expect("owned VM receives agent disk and starts");

    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[0],
        "<--project><test-project><init><images:debian/13><vm-owned><--vm><--profile><test-profile><-c><user.kidobo-e2e=kidobo-e2e-v1>"
    );
    assert_eq!(
        calls[1],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert_eq!(
        calls[2],
        "<--project><test-project><config><device><add><vm-owned><agent><disk><source=agent:config>"
    );
    assert_eq!(calls[3], "<--project><test-project><start><vm-owned>");
}

#[test]
fn create_vm_refuses_agent_disk_and_start_when_ownership_check_fails() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);

    let error = runner
        .create_vm("alma/10", "vm-unowned", "test-profile")
        .expect_err("unowned VM must not be mutated");

    assert!(
        error.to_string().contains("unowned or non-VM"),
        "create_vm failed for an unexpected reason: {error}"
    );
    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 2, "only init and verification may run");
    assert!(calls[0].contains("<init><images:alma/10><vm-unowned>"));
    assert!(calls[1].contains("<list><vm-unowned><--format=json>"));
}

#[test]
fn runner_streams_both_outputs_before_command_completes() {
    let temp = TestDir::new();
    let root = temp.path().to_owned();
    let release = root.join("release");
    let child_root = root.clone();
    let handle = std::thread::spawn(move || {
        let mut runner = runner(&child_root);
        let result = runner.command("sh", &strings(&["-c",
            "printf partial; printf diagnostic >&2; while [ ! -f \"$1\" ]; do sleep 0.01; done; printf done", "sh",
            child_root.join("release").to_str().expect("fixture path")]), 5);
        (result.map_err(|e| e.to_string()), runner.report.document)
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let streamed = loop {
        let text = read_text(&root.join("transcript.log")).unwrap_or_default();
        if text.contains("stdout] partial") && text.contains("stderr] diagnostic") {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let incomplete = !handle.is_finished();
    fs::write(release, "release").expect("release fake command");
    let (result, document) = handle.join().expect("join fake runner");
    assert!(
        streamed && incomplete,
        "both partial streams must be visible before exit"
    );
    assert_eq!(result.expect("successful command"), "partialdone");
    assert_eq!(document["commands"][0]["code"], 0);
    assert!(!root.join(".capture").exists());
    assert!(!root.join("0001.stdout").exists());
}

#[test]
fn heartbeat_uses_silence_and_repeat_intervals_without_sleeping() {
    let mut heartbeat = Heartbeat::default();
    assert!(!heartbeat.due(Duration::from_secs(14), false));
    assert!(heartbeat.due(Duration::from_secs(15), false));
    assert!(!heartbeat.due(Duration::from_secs(29), false));
    assert!(heartbeat.due(Duration::from_secs(30), false));
    assert!(!heartbeat.due(Duration::from_secs(44), true));
    assert!(!heartbeat.due(Duration::from_secs(58), false));
    assert!(heartbeat.due(Duration::from_secs(59), false));
}

#[test]
fn runner_rejects_successful_exit_with_an_aborted_check() {
    let temp = TestDir::new();
    let mut runner = runner(temp.path());
    let error = runner
        .command(
            "sh",
            &strings(&[
                "-c",
                "printf 'E2E_CHECK\tunfinished\tSTART\texpect a result\n' >&2",
            ]),
            5,
        )
        .expect_err("missing assertion outcome cannot pass");
    assert!(error.to_string().contains("unfinished"));
    assert_eq!(runner.report.document["checks"][0]["status"], "failed");
    assert_eq!(runner.report.document["commands"][0]["code"], 0);
}

#[test]
fn runner_archives_raw_evidence_and_leaves_five_files() {
    let temp = TestDir::new();
    let mut runner = runner(temp.path());
    fs::create_dir_all(runner.evidence().join("inputs")).expect("create frozen inputs");
    let snapshot = runner.evidence().join("inputs/SHA256.json");
    fs::write(&snapshot, "{\"fixture\":\"hash\"}\n").expect("write frozen evidence");
    fs::write(runner.dir.join("ownership.json"), "{}").expect("ownership fixture");
    runner.command("true", &[], 5).expect("silent fake command");
    archive_evidence(&mut runner).expect("archive local fixture only");
    runner.report.save().expect("save report");
    let mut files: Vec<_> = fs::read_dir(temp.path())
        .expect("read results")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "evidence.tar.gz",
            "ownership.json",
            "results.json",
            "summary.txt",
            "transcript.log"
        ]
        .map(std::ffi::OsString::from)
    );
    let extracted = Command::new("tar")
        .args(["-xOf"])
        .arg(temp.path().join("evidence.tar.gz"))
        .arg("./inputs/SHA256.json")
        .output()
        .expect("read archived snapshot");
    assert!(extracted.status.success());
    assert_eq!(extracted.stdout, b"{\"fixture\":\"hash\"}\n");
    assert_eq!(
        runner.report.document["evidence"]["sha256"],
        hash(&temp.path().join("evidence.tar.gz")).expect("archive hash")
    );
}

#[test]
fn runner_keeps_evidence_when_archiving_fails() {
    let temp = TestDir::new();
    let mut runner = runner(temp.path());
    fs::create_dir_all(runner.evidence()).expect("create evidence");
    let snapshot = runner.evidence().join("snapshot");
    fs::write(&snapshot, "important evidence").expect("write snapshot");
    assert!(archive_evidence_using(&mut runner, "false").is_err());
    assert_eq!(
        read_text(&snapshot).expect("retained snapshot"),
        "important evidence"
    );
    assert!(!runner.dir.join("evidence.tar.gz").exists());
}

#[test]
fn runner_cleanup_preserves_legacy_results_and_ignores_stale_captures() {
    let temp = TestDir::new();
    let root = temp.path().join("run-123");
    fs::create_dir(&root).expect("legacy run");
    fs::create_dir(root.join(".capture")).expect("capture left by a killed old runner");
    fs::write(root.join("0001.stdout"), "old raw evidence").expect("old log");
    let original_result =
        json!({"tag":"v1.2.3", "results":[{"distro":"debian-13","error":"original failure"}]});
    fs::write(
        root.join("results.json"),
        serde_json::to_vec(&original_result).expect("serialize"),
    )
    .expect("legacy results");
    fs::write(
        root.join("ownership.json"),
        serde_json::to_vec(&Owned {
            owner: OWNER.into(),
            project: "test-project".into(),
            instances: vec!["run-123-debian-13".into()],
        })
        .expect("serialize ownership"),
    )
    .expect("legacy ownership");
    let (program, _) = fake_incus(&temp);
    let mut runner = runner_with_incus(&root, &program);
    clean(&mut runner, &setup_config()).expect("already deleted guest cleans successfully");
    assert_eq!(
        runner.report.document["results"],
        original_result["results"]
    );
    assert_eq!(
        read_text(&root.join("0001.stdout")).expect("old evidence"),
        "old raw evidence"
    );
    assert_eq!(runner.report.document["commands"][0]["code"], 0);
}
