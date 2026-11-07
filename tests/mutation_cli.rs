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

fn asn_fixture(banned: &[u32], blocklist: &str) -> Fixture {
    let fixture = Fixture::new(&format!("{CONFIG}[asn]\nbanned={banned:?}\n"), blocklist);
    let cache = fixture.root().join("cache/asn");
    fs::create_dir_all(&cache).expect("ASN cache directory");
    for asn in [398_324, 398_705] {
        fs::write(
            cache.join(format!("as{asn}.iplist")),
            "203.0.113.0/24\n2001:db8:1::/48\n",
        )
        .expect("fresh ASN cache");
    }
    fixture
}

#[test]
fn asn_cleanup_only_prompts_and_preserves_overlapping_local_bans() {
    let fixture = asn_fixture(
        &[398_324],
        "# keep\n203.0.113.0/24\n203.0.113.7\n2001:db8:1::/48\n2001:db8::/32\n198.51.100.0/24\n",
    );
    let output = fixture
        .spawn(
            &["ban", "--asn", "AS398324"],
            100,
            OutputDestination::Terminal,
            &[],
        )
        .respond_after(APPLY_PROMPT, "n\n");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        output
            .stdout
            .contains("Already permanently banned: AS398324"),
        "{output:?}"
    );
    assert!(
        output
            .stdout
            .contains("Removed 2 local entries matching ASN prefixes."),
        "{output:?}"
    );
    assert_eq!(output.stdout.matches(APPLY_PROMPT).count(), 1);
    assert_eq!(output.stdout.matches("Next: sudo kidobo sync").count(), 1);
    assert_eq!(
        source(&fixture),
        "# keep\n203.0.113.7\n2001:db8::/32\n198.51.100.0/24\n"
    );
    assert_eq!(fixture.tool_log(), "");

    for token in ["AS398324", "398324", "as398324"] {
        let repeated = fixture
            .spawn(&["ban", "--asn", token], 100, OutputDestination::Pipe, &[])
            .wait();
        assert_eq!(repeated.status.code(), Some(0), "{repeated:?}");
        assert_eq!(repeated.stdout, "Already permanently banned: AS398324\n");
    }
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn asn_cleanup_only_no_apply_saves_without_prompting_or_syncing() {
    for destination in [OutputDestination::Terminal, OutputDestination::Pipe] {
        let fixture = asn_fixture(&[398_324], "203.0.113.0/24\n");
        let output = fixture
            .spawn(
                &["ban", "--asn", "398324", "--no-apply"],
                100,
                destination,
                &[],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(
            output.stdout,
            "Already permanently banned: AS398324\nRemoved 1 local entry matching ASN prefixes.\nNext: sudo kidobo sync\n"
        );
        assert_eq!(source(&fixture), "");
        assert_eq!(fixture.tool_log(), "");
    }
}

#[test]
fn asn_cleanup_and_noop_explicit_apply_preserve_saved_state_after_failure() {
    for blocklist in ["203.0.113.0/24\n198.51.100.0/24\n", "198.51.100.0/24\n"] {
        let fixture = asn_fixture(&[398_324], blocklist);
        fail_fake_sync(&fixture);
        let output = fixture
            .spawn(
                &["ban", "--asn", "AS398324", "--apply"],
                100,
                OutputDestination::Pipe,
                &[],
            )
            .wait();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let expected_context = if blocklist.starts_with("203") {
            "Source change saved"
        } else {
            "Source state unchanged"
        };
        assert!(
            output
                .stderr
                .starts_with(&format!("{expected_context}; live firewall update failed")),
            "{output:?}"
        );
        assert_eq!(source(&fixture), "198.51.100.0/24\n");
        let config = read_to_string_with_limit(&fixture.root().join("config/config.toml"), 65_536)
            .expect("saved ASN configuration");
        assert!(config.contains("398324"));
        assert!(fixture.tool_log().contains("sudo -n "), "sync was skipped");
    }
}

#[test]
fn asn_new_and_mixed_requests_report_normalized_results_once() {
    for (existing, expected) in [
        (
            vec![],
            "Added 2 ASN bans: AS398324, AS398705\nNext: sudo kidobo sync\n",
        ),
        (
            vec![398_324],
            "Added 1 ASN ban: AS398705\nAlready permanently banned: AS398324\nNext: sudo kidobo sync\n",
        ),
    ] {
        let fixture = asn_fixture(&existing, "");
        let output = fixture
            .spawn(
                &["ban", "--asn", "AS398705", "398324", "as398705"],
                100,
                OutputDestination::Pipe,
                &[],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, expected);
        let text = read_to_string_with_limit(&fixture.root().join("config/config.toml"), 65_536)
            .expect("saved ASNs");
        let config =
            kidobo_core::config::Config::from_toml_str(&text).expect("valid configuration");
        assert_eq!(config.asn.banned, [398_324, 398_705]);
        assert_eq!(fixture.tool_log(), "");
    }
}

#[test]
fn asn_unban_reports_counts_and_omits_zero_cache_deletions() {
    for (banned, expected) in [
        (
            vec![398_324, 398_705],
            "Removed 2 ASN bans: AS398324, AS398705\nDeleted 2 ASN cache files.\nNext: sudo kidobo sync\n",
        ),
        (
            vec![398_324],
            "Removed 1 ASN ban: AS398324\nDeleted 2 ASN cache files.\nNext: sudo kidobo sync\n",
        ),
    ] {
        let fixture = asn_fixture(&banned, "");
        let output = fixture
            .spawn(
                &["unban", "--asn", "AS398324", "398705"],
                100,
                OutputDestination::Pipe,
                &[],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, expected);
        let repeated = fixture
            .spawn(
                &["unban", "--asn", "AS398324", "398705"],
                100,
                OutputDestination::Pipe,
                &[],
            )
            .wait();
        assert_eq!(repeated.status.code(), Some(0), "{repeated:?}");
        assert_eq!(repeated.stdout, "No saved ASN bans matched the request.\n");
        assert_eq!(fixture.tool_log(), "");
    }
}

#[test]
fn temporary_ban_output_keeps_one_utc_expiry_and_one_next_step() {
    let fixture = Fixture::new(CONFIG, "");
    let output = fixture
        .spawn(
            &["ban", "203.0.113.7", "--for", "12h"],
            100,
            OutputDestination::Pipe,
            &[],
        )
        .wait();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        output
            .stdout
            .starts_with("added temporary ban 203.0.113.7/32 (expires "),
        "{output:?}"
    );
    assert_eq!(output.stdout.matches("UTC").count(), 1);
    assert_eq!(output.stdout.matches("Next: sudo kidobo sync").count(), 1);
    for removed in [
        "Unix",
        "remaining",
        "for 12h",
        "The duration started",
        "Source change saved",
        "Live enforcement is pending",
    ] {
        assert!(
            !output.stdout.contains(removed),
            "unexpected text {removed}: {output:?}"
        );
    }
    assert_eq!(source(&fixture), "");
    assert_eq!(fixture.tool_log(), "");
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
    assert_eq!(output.stdout.matches("Next: sudo kidobo sync").count(), 1);
    assert!(!output.stdout.contains("Live enforcement is pending."));
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
fn explicit_apply_does_not_approve_partial_unban_removal() {
    let fixture = Fixture::new(CONFIG, "203.0.113.7\n203.0.113.0/24\n");
    fail_fake_sync(&fixture);
    let output = fixture
        .spawn(
            &["unban", "203.0.113.7", "--apply"],
            100,
            OutputDestination::Pipe,
            &[],
        )
        .wait();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.contains("use --yes"));
    assert!(
        output
            .stderr
            .starts_with("Source change saved; live firewall update failed")
    );
    assert_eq!(source(&fixture), "203.0.113.0/24\n");
    assert!(fixture.tool_log().contains("sudo -n "));
}

#[test]
fn systemd_unban_preserves_partial_matches_without_prompting() {
    for environment in ["INVOCATION_ID", "JOURNAL_STREAM"] {
        let fixture = Fixture::new(CONFIG, "203.0.113.7\n203.0.113.0/24\n");
        let output = fixture
            .spawn(
                &["unban", "203.0.113.7"],
                100,
                OutputDestination::Terminal,
                &[(environment, "fixture")],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.contains("use --yes"));
        assert!(!output.stdout.contains("Remove these entries as well?"));
        assert!(!output.stdout.contains(APPLY_PROMPT));
        assert_eq!(source(&fixture), "203.0.113.0/24\n");
        assert_eq!(fixture.tool_log(), "");
    }
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
    assert!(
        help.stdout
            .contains("Remove Kidobo's managed firewall rules, ipsets, and remote cache.")
    );
    assert!(help.stdout.contains("--yes"));
    assert_eq!(fixture.tool_log(), "");
}
