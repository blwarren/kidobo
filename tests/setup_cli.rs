#![cfg(unix)]

use std::fs;

use kidobo_adapters::limited_io::read_to_string_with_limit;

#[path = "support/terminal.rs"]
mod terminal;

use terminal::{Fixture, OutputDestination};

const EXISTING_CONFIG: &str = "# keep existing settings\n[ipset]\nset_name = 'custom'\n[safe]\nips = ['192.0.2.7']\ninclude_github_meta = false\n[remote]\nurls = ['https://old.example/feed']\n[asn]\nbanned = [64512]\n";

const IPV6_PROMPT: &str = "Enable IPv6 enforcement?";
const GITHUB_PROMPT: &str = "Use the bounded GitHub metadata safelist?";
const FEED_PROMPT: &str = "Add a remote feed URL (blank to keep existing feeds):";
const ALLOW_PROMPT: &str = "Add a safelist IP/CIDR (blank to keep existing exemptions):";
const SAVE_PROMPT: &str = "Save these settings and provision missing files?";
const FIRST_SYNC_PROMPT: &str = "Run the first synchronization now?";

fn config(fixture: &Fixture) -> String {
    read_to_string_with_limit(&fixture.root().join("config/config.toml"), 65_536)
        .expect("read bounded config")
}

fn no_sync_mutations(log: &str) {
    for mutation in ["create", "swap", "flush", "destroy", "-N", "-A", "-I"] {
        assert!(
            !log.lines()
                .any(|line| line.split_whitespace().any(|part| part == mutation)),
            "unexpected live mutation `{mutation}` in fake command log:\n{log}"
        );
    }
}

fn setup_responses(
    final_response: &str,
    first_sync_response: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut responses = vec![
        (IPV6_PROMPT, "n\n".to_string()),
        (GITHUB_PROMPT, "\n".to_string()),
        (
            FEED_PROMPT,
            "https://alice:feed-secret@new.example/list?token=query-secret#fragment-secret\n"
                .to_string(),
        ),
        (FEED_PROMPT, "\n".to_string()),
        (ALLOW_PROMPT, "\n".to_string()),
        (SAVE_PROMPT, final_response.to_string()),
    ];
    if let Some(response) = first_sync_response {
        responses.push((FIRST_SYNC_PROMPT, response.to_string()));
    }
    responses
}

fn borrowed_responses<'a>(responses: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    responses
        .iter()
        .map(|(prompt, response)| (*prompt, response.as_str()))
        .collect()
}

#[test]
fn noninteractive_setup_exits_with_guidance_without_creating_files() {
    let fixture = Fixture::new(EXISTING_CONFIG, "");
    fs::remove_file(fixture.root().join("config/config.toml")).expect("remove config fixture");
    let output = fixture
        .spawn(&["setup"], 80, OutputDestination::Pipe, &[])
        .wait();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.contains("Setup requires interactive stdin"));
    assert!(!fixture.root().join("config/config.toml").exists());
    assert!(!fixture.root().join("systemd/system").exists());
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn final_review_decline_leaves_existing_configuration_and_files_unchanged() {
    let fixture = Fixture::new(EXISTING_CONFIG, "");
    let before = config(&fixture);
    let responses = setup_responses("n\n", None);
    let output = fixture
        .spawn(&["setup"], 80, OutputDestination::Terminal, &[])
        .respond_to_all(&borrowed_responses(&responses));

    assert!(output.status.success(), "{}", output.stderr);
    assert!(
        output
            .stdout
            .contains("Setup cancelled; no files were changed")
    );
    assert_eq!(config(&fixture), before);
    assert!(!fixture.root().join("systemd/system").exists());
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn eof_at_final_review_is_a_safe_decline() {
    let fixture = Fixture::new(EXISTING_CONFIG, "");
    let before = config(&fixture);
    let responses = setup_responses("\u{4}", None);
    let output = fixture
        .spawn(&["setup"], 80, OutputDestination::Terminal, &[])
        .respond_to_all(&borrowed_responses(&responses));

    assert!(output.status.success(), "{}", output.stderr);
    assert!(
        output
            .stdout
            .contains("Setup cancelled; no files were changed")
    );
    assert_eq!(config(&fixture), before);
    assert!(!fixture.root().join("systemd/system").exists());
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn setup_saves_reviewed_values_runs_doctor_then_allows_first_sync_decline() {
    let fixture = Fixture::new(EXISTING_CONFIG, "");
    let responses = setup_responses("y\n", Some("n\n"));
    let response_refs = borrowed_responses(&responses);
    let output = fixture
        .spawn(&["setup"], 100, OutputDestination::Terminal, &[])
        .respond_to_all(&response_refs);

    assert!(
        output.status.success(),
        "{}\n{}",
        output.stdout,
        output.stderr
    );
    assert!(output.stdout.contains("Kidobo doctor"));
    assert!(output.stdout.contains("Run the first synchronization now?"));
    assert!(
        output
            .stdout
            .contains("Alternate root: systemd units were provisioned locally")
    );
    let saved = config(&fixture);
    assert!(saved.contains("# keep existing settings"));
    assert!(saved.contains("set_name = 'custom'"));
    assert!(saved.contains("enable_ipv6 = false"));
    assert!(saved.contains("https://old.example/feed"));
    assert!(saved.contains("new.example/list"));
    let review = output
        .stdout
        .split_once("Review before saving")
        .expect("setup review section")
        .1;
    for secret in ["alice", "feed-secret", "query-secret", "fragment-secret"] {
        assert!(!review.contains(secret), "setup review leaked {secret}");
    }
    assert!(fixture.root().join("data/blocklist.txt").exists());
    assert!(
        fixture
            .root()
            .join("systemd/system/kidobo-sync.service")
            .exists()
    );
    assert!(
        fixture
            .root()
            .join("systemd/system/kidobo-sync.timer")
            .exists()
    );
    no_sync_mutations(&fixture.tool_log());
    assert!(!fixture.tool_log().contains("systemctl"));
}

#[test]
fn failed_doctor_stops_before_first_sync_and_timer_activation() {
    let fixture = Fixture::new(EXISTING_CONFIG, "");
    fixture.write_tool("iptables", "exit 73\n");
    let responses = setup_responses("y\n", None);
    let response_refs = borrowed_responses(&responses);
    let output = fixture
        .spawn(&["setup"], 100, OutputDestination::Terminal, &[])
        .respond_to_all(&response_refs);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.contains("doctor"));
    assert!(!output.stdout.contains("Run the first synchronization now?"));
    assert!(
        !output
            .stdout
            .contains("Enable scheduled synchronization with kidobo-sync.timer?")
    );
    assert!(config(&fixture).contains("enable_ipv6 = false"));
    assert!(
        fixture
            .root()
            .join("systemd/system/kidobo-sync.timer")
            .exists()
    );
    no_sync_mutations(&fixture.tool_log());
    assert!(!fixture.tool_log().contains("systemctl"));
}
