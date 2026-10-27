#![cfg(unix)]

use std::fs;

use kidobo_adapters::limited_io::read_to_string_with_limit;

#[path = "support/terminal.rs"]
mod terminal;

use terminal::{Fixture, OutputDestination};

const CONFIG: &str = "[ipset]\nset_name = 'kidobo'\n[safe]\ninclude_github_meta = false\n";
const APPLY_PROMPT: &str = "Apply to the firewall now? [y/N]: ";
const FLUSH_PROMPT: &str = "Remove the managed firewall state and remote cache? [y/N]: ";

fn source(fixture: &Fixture) -> String {
    read_to_string_with_limit(&fixture.root().join("data/blocklist.txt"), 16 * 1024 * 1024)
        .expect("read saved blocklist")
}

fn fail_fake_sync(fixture: &Fixture) {
    fixture.write_tool("sudo", "echo 'injected fake sync failure' >&2\nexit 77\n");
}

#[test]
fn nonterminal_ban_saves_without_prompt_or_sync() {
    let fixture = Fixture::new(CONFIG, "");

    let output = fixture
        .spawn(&["ban", "203.0.113.7"], 80, OutputDestination::Pipe, &[])
        .wait();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(source(&fixture).contains("203.0.113.7/32"));
    assert!(!output.stdout.contains(APPLY_PROMPT));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn no_apply_on_a_terminal_saves_without_prompt_or_sync() {
    let fixture = Fixture::new(CONFIG, "");

    let output = fixture
        .spawn(
            &["ban", "203.0.113.7", "--no-apply"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .wait();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(source(&fixture).contains("203.0.113.7/32"));
    assert!(!output.stdout.contains(APPLY_PROMPT));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn interactive_decline_keeps_saved_ban_pending() {
    let fixture = Fixture::new(CONFIG, "");

    let output = fixture
        .spawn(
            &["ban", "203.0.113.7"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .respond_after(APPLY_PROMPT, "n\n");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.contains("Source change saved"), "{output:?}");
    assert!(
        output.stdout.contains("Live enforcement is pending."),
        "{output:?}"
    );
    assert!(source(&fixture).contains("203.0.113.7/32"));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn interactive_apply_failure_reports_saved_source_and_leaves_it_persistent() {
    let fixture = Fixture::new(CONFIG, "");
    fail_fake_sync(&fixture);

    let output = fixture
        .spawn(
            &["ban", "203.0.113.7"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .respond_after(APPLY_PROMPT, "y\n");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        output
            .stderr
            .starts_with("Source change saved; live firewall update failed"),
        "unexpected apply failure diagnostic: {output:?}"
    );
    assert!(source(&fixture).contains("203.0.113.7/32"));
    assert!(
        fixture.tool_log().contains("sudo -n "),
        "sync was not attempted"
    );
}

#[test]
fn explicit_apply_runs_sync_for_noop_changes_after_the_mutation_lock_is_released() {
    let fixture = Fixture::new(CONFIG, "203.0.113.7\n");
    fail_fake_sync(&fixture);

    let output = fixture
        .spawn(
            &["ban", "203.0.113.7", "--apply"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        output
            .stderr
            .starts_with("Source state unchanged; live firewall update failed"),
        "unexpected no-op apply diagnostic: {output:?}"
    );
    assert!(
        fixture.tool_log().contains("sudo -n "),
        "explicit apply skipped sync"
    );
    assert!(source(&fixture).contains("203.0.113.7"));
}

#[test]
fn unban_yes_approves_overlap_removal_but_still_prompts_before_sync() {
    let fixture = Fixture::new(CONFIG, "203.0.113.0/24\n");

    let output = fixture
        .spawn(
            &["unban", "203.0.113.7", "--yes"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .respond_after(APPLY_PROMPT, "n\n");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        output
            .stdout
            .contains("auto-approving removal of partial matches")
    );
    assert!(output.stdout.contains(APPLY_PROMPT));
    assert_eq!(source(&fixture).trim(), "");
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn apply_flag_conflicts_are_usage_errors_without_mutation() {
    let fixture = Fixture::new(CONFIG, "203.0.113.7\n");

    for arguments in [
        &["ban", "203.0.113.7", "--apply", "--no-apply"][..],
        &["unban", "203.0.113.7", "--apply", "--no-apply"][..],
    ] {
        let output = fixture
            .spawn(arguments, 80, OutputDestination::Pipe, &[])
            .wait();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
    }
    assert_eq!(source(&fixture), "203.0.113.7\n");
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn flush_terminal_decline_preserves_cache_and_runs_no_system_commands() {
    let fixture = Fixture::new(CONFIG, "");
    let cached = fixture.root().join("cache/remote/feed.iplist");
    fs::write(&cached, "203.0.113.0/24\n").expect("cached feed");

    let output = fixture
        .spawn(&["flush"], 80, OutputDestination::Terminal, &[])
        .respond_after(FLUSH_PROMPT, "n\n");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.contains("Remove Kidobo enforcement"));
    assert!(
        output.stdout.contains(
            "Full flush removes Kidobo's managed firewall rules, ipsets, and remote cache."
        )
    );
    assert!(
        output
            .stdout
            .contains("An enabled sync timer may recreate enforcement")
    );
    assert!(output.stdout.contains("cancelled"), "{output:?}");
    assert_eq!(
        read_to_string_with_limit(&cached, 1024).expect("preserved cached feed"),
        "203.0.113.0/24\n"
    );
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn flush_yes_skips_tty_prompt_and_runs_only_the_fake_backend() {
    let fixture = Fixture::new(CONFIG, "");
    fail_fake_sync(&fixture);

    let output = fixture
        .spawn(&["flush", "--yes"], 80, OutputDestination::Terminal, &[])
        .wait();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!output.stdout.contains(FLUSH_PROMPT));
    assert!(
        fixture.tool_log().contains("sudo -n "),
        "cleanup was not attempted"
    );
}

#[test]
fn cache_only_flush_needs_no_confirmation_and_flush_help_describes_removal() {
    let fixture = Fixture::new(CONFIG, "");
    let cached = fixture.root().join("cache/remote/feed.iplist");
    fs::write(&cached, "203.0.113.0/24\n").expect("cached feed");

    let cache_only = fixture
        .spawn(
            &["flush", "--cache-only"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .wait();
    assert_eq!(cache_only.status.code(), Some(0), "{cache_only:?}");
    assert!(!cache_only.stdout.contains(FLUSH_PROMPT));
    assert!(!cached.exists());
    assert_eq!(fixture.tool_log(), "");

    let help = fixture
        .spawn(&["flush", "--help"], 80, OutputDestination::Pipe, &[])
        .wait();
    assert_eq!(help.status.code(), Some(0), "{help:?}");
    assert!(help.stdout.contains("destructive removal operation"));
    assert!(help.stdout.contains("--yes"));
    assert_eq!(fixture.tool_log(), "");
}
