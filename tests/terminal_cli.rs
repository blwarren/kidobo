#![cfg(unix)]

use std::fs;

use unicode_width::UnicodeWidthStr;

#[path = "support/terminal.rs"]
mod terminal;

use terminal::{Fixture, OutputDestination};

const CONFIG: &str = "[ipset]\nset_name = 'kidobo'\n[safe]\ninclude_github_meta = false\n";

#[test]
fn doctor_uses_human_output_for_a_real_terminal_and_preserves_explicit_json() {
    let fixture = Fixture::new(CONFIG, "203.0.113.7\n");
    let human = fixture
        .spawn(&["doctor"], 80, OutputDestination::Terminal, &[])
        .wait();
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert!(human.stdout.contains("Kidobo doctor"), "{human:?}");
    assert!(human.stdout.contains("[PASS]"), "{human:?}");
    assert!(human.stdout.contains("\u{1b}[1m"), "{human:?}");
    assert!(human.stderr.contains("doctor summary:"), "{human:?}");

    let explicit = fixture
        .spawn(
            &["doctor", "--format", "json"],
            60,
            OutputDestination::Terminal,
            &[],
        )
        .wait();
    let piped = fixture
        .spawn(&["doctor"], 80, OutputDestination::Pipe, &[])
        .wait();
    assert_eq!(explicit.status.code(), Some(0), "{explicit:?}");
    assert_eq!(piped.status.code(), Some(0), "{piped:?}");
    assert_eq!(explicit.stdout, piped.stdout);
    let report: serde_json::Value = serde_json::from_str(&explicit.stdout).expect("doctor JSON");
    assert_eq!(report["overall"], "OK");
    assert_eq!(report.as_object().expect("report object").len(), 2);
    assert!(!explicit.stdout.contains('\u{1b}'));
    assert!(!explicit.stdout.contains("Kidobo doctor"));
}

#[test]
fn terminal_human_output_respects_no_color_and_dumb_terminals() {
    for environment in [[("NO_COLOR", "1")], [("TERM", "dumb")]] {
        let fixture = Fixture::new(CONFIG, "");
        let output = fixture
            .spawn(&["doctor"], 60, OutputDestination::Terminal, &environment)
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.contains("[PASS]"), "{output:?}");
        assert!(!output.stdout.contains('\u{1b}'), "{output:?}");
        assert!(!output.stderr.contains('\u{1b}'), "{output:?}");
        assert!(
            output
                .stdout
                .lines()
                .all(|line| UnicodeWidthStr::width(line) <= 60),
            "{output:?}"
        );
    }
}

#[test]
fn real_terminal_lookup_preserves_ipv6_and_escapes_untrusted_unicode_labels_at_all_widths() {
    let address = "2001:db8:1234:5678:9abc:def0:1234:5678";
    let fixture = Fixture::new(CONFIG, &format!("{address}\n"));
    fs::write(
        fixture.root().join("cache/remote/feed.iplist"),
        format!("{address}\n"),
    )
    .expect("cached feed");
    fs::write(
        fixture.root().join("cache/remote/feed.meta.json"),
        serde_json::json!({"url": "fe\u{301}ed界\u{1b}[31m\nFAKE"}).to_string(),
    )
    .expect("cached feed label");
    for width in [60, 80, 120] {
        let output = fixture
            .spawn(
                &["lookup", address],
                width,
                OutputDestination::Terminal,
                &[("NO_COLOR", "1")],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.contains(address), "{output:?}");
        assert!(output.stdout.contains("fe\u{301}ed界"), "{output:?}");
        assert!(output.stdout.contains("\\x1B[31m\\nFAKE"), "{output:?}");
        assert!(!output.stdout.contains('\u{1b}'), "{output:?}");
        assert!(!output.stdout.lines().any(|line| line == "FAKE"));
        assert!(
            output
                .stdout
                .lines()
                .all(|line| UnicodeWidthStr::width(line) <= usize::from(width)),
            "width={width}: {output:?}"
        );
    }
    assert_eq!(fixture.tool_log(), "", "offline lookup invoked a command");
}

#[test]
fn terminal_stdin_with_piped_stdout_remains_noninteractive_and_machine_readable() {
    let fixture = Fixture::new(CONFIG, "");
    let output = fixture
        .spawn(&["doctor"], 60, OutputDestination::Pipe, &[])
        .wait();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_str(&output.stdout).expect("piped doctor JSON");
    assert_eq!(report["overall"], "OK");
    assert!(!output.stdout.contains('\u{1b}'));
    assert!(!output.stdout.contains("[y/N]"));
    assert!(!output.stderr.contains("[y/N]"));
}

#[test]
fn help_and_usage_errors_do_not_inspect_invalid_configuration_or_run_probes() {
    let fixture = Fixture::new("this is invalid TOML", "invalid source data");
    for arguments in [&["--help"][..], &["doctor", "--help"], &["sync", "--help"]] {
        let output = fixture
            .spawn(
                arguments,
                60,
                OutputDestination::Terminal,
                &[("NO_COLOR", "1")],
            )
            .wait();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.contains("Usage:"), "{output:?}");
        assert!(!output.stdout.contains("config parse"), "{output:?}");
    }
    let invalid = fixture
        .spawn(
            &["lookup"],
            60,
            OutputDestination::Terminal,
            &[("NO_COLOR", "1")],
        )
        .wait();
    assert_eq!(invalid.status.code(), Some(2), "{invalid:?}");
    assert!(invalid.stderr.contains("Usage:"), "{invalid:?}");
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn existing_overlap_confirmation_can_be_declined_through_a_real_terminal() {
    let fixture = Fixture::new(CONFIG, "203.0.113.0/24\n");
    let output = fixture
        .spawn(
            &["unban", "203.0.113.7"],
            80,
            OutputDestination::Terminal,
            &[("NO_COLOR", "1")],
        )
        .respond_after("Remove these entries as well? [y/N]: ", "n\n");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.contains("203.0.113.0/24"), "{output:?}");
    let blocklist = kidobo_adapters::limited_io::read_to_string_with_limit(
        &fixture.root().join("data/blocklist.txt"),
        1024,
    )
    .expect("saved blocklist");
    assert_eq!(blocklist, "203.0.113.0/24\n");
    assert_eq!(fixture.tool_log(), "");
}
