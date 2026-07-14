use std::collections::BTreeSet;
use std::path::Path;

use crate::adapters::blocklist_file::{
    BLOCKLIST_READ_LIMIT, BlocklistDocument, ensure_blocklist_parent,
};
use crate::adapters::limited_io::{read_to_string_with_limit, write_string_atomic};
use crate::adapters::lock::acquire_non_blocking;
use crate::core::blocklist::{BanClassification, classify_ban_targets, plan_unban_many};
use crate::core::network::CanonicalCidr;
use crate::error::KidoboError;

use super::confirm::{UnbanPreview, build_file_unban_preview, confirm_partial_matches};
use super::plan::{
    PartialMatch, UnbanPlan, apply_unban_plan, build_unban_plan, parse_blocklist_target,
};

pub(super) const BLOCKLIST_TARGET_FILE_READ_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub(super) enum BanOutcome {
    Added(String),
    AlreadyPresent(String),
}

impl From<BanClassification> for BanOutcome {
    fn from(value: BanClassification) -> Self {
        match value {
            BanClassification::Added(cidr) => Self::Added(cidr.to_string()),
            BanClassification::AlreadyPresent(cidr) => Self::AlreadyPresent(cidr.to_string()),
        }
    }
}

#[derive(Debug)]
struct FileUnbanRequest {
    requested_target_count: usize,
    plan: UnbanPlan,
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI command writes results and diagnostics to the terminal"
)]
pub(super) fn run_ban_file_command(
    blocklist_path: &Path,
    target_file: &Path,
) -> Result<(), KidoboError> {
    let target_lines = read_blocklist_target_lines(target_file)?;
    let targets = parse_blocklist_targets_or_report(&target_lines)?;

    if targets.is_empty() {
        println!("no blocklist targets loaded from file");
        return Ok(());
    }

    let outcomes = ban_targets_in_file(blocklist_path, &targets)?;
    for outcome in outcomes {
        match outcome {
            BanOutcome::Added(value) => println!("added blocklist entry {value}"),
            BanOutcome::AlreadyPresent(value) => println!("blocklist already contains {value}"),
        }
    }

    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its result to standard output"
)]
pub(super) fn run_ban_target_command(
    blocklist_path: &Path,
    target: &str,
) -> Result<(), KidoboError> {
    let outcome = ban_target_in_file(blocklist_path, target)?;

    match outcome {
        BanOutcome::Added(value) => println!("added blocklist entry {value}"),
        BanOutcome::AlreadyPresent(value) => println!("blocklist already contains {value}"),
    }

    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its result to standard output"
)]
pub(super) fn run_unban_file_command(
    blocklist_path: &Path,
    lock_path: &Path,
    target_file: &Path,
    yes: bool,
) -> Result<(), KidoboError> {
    let target_lines = read_blocklist_target_lines(target_file)?;
    let targets = parse_blocklist_targets_or_report(&target_lines)?;

    if targets.is_empty() {
        println!("no blocklist targets loaded from file");
        return Ok(());
    }

    let preview_request = build_unban_file_request(blocklist_path, &targets)?;
    let preview = build_file_unban_preview(
        preview_request.requested_target_count,
        &preview_request.plan.blocklist,
        &preview_request.plan.exact_indexes,
        &preview_request.plan.partial_matches,
    );
    let remove_partial = confirm_partial_matches(
        "file targets also match the following blocklist entries:",
        &preview_request.plan.partial_matches,
        yes,
    )?;

    let _lock = acquire_non_blocking(lock_path)?;
    let mut request = build_unban_file_request(blocklist_path, &targets)?;
    if build_file_unban_preview(
        request.requested_target_count,
        &request.plan.blocklist,
        &request.plan.exact_indexes,
        &request.plan.partial_matches,
    ) != preview
    {
        return Err(KidoboError::BlocklistChanged);
    }
    request.plan.remove_partial = remove_partial;

    if request.plan.total_removal() == 0 {
        if request.plan.partial_matches.is_empty() {
            println!(
                "no blocklist entries matched {} file target(s)",
                request.requested_target_count
            );
        } else {
            println!(
                "no blocklist entries were removed for {} file target(s)",
                request.requested_target_count
            );
        }
        return Ok(());
    }

    let result = apply_unban_plan(blocklist_path, &request.plan)?;
    println!(
        "removed {} blocklist entries for {} file target(s)",
        result.total(),
        request.requested_target_count
    );
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its result to standard output"
)]
pub(super) fn run_unban_target_command(
    blocklist_path: &Path,
    lock_path: &Path,
    target: &str,
    yes: bool,
) -> Result<(), KidoboError> {
    let preview_plan = build_unban_plan(blocklist_path, target)?;
    let preview = UnbanPreview::from_plan(&preview_plan);
    let remove_partial = confirm_partial_matches(
        &format!(
            "{} also matches the following blocklist entries:",
            preview_plan.target
        ),
        &preview_plan.partial_matches,
        yes,
    )?;

    let _lock = acquire_non_blocking(lock_path)?;
    let mut plan = build_unban_plan(blocklist_path, target)?;
    if UnbanPreview::from_plan(&plan) != preview {
        return Err(KidoboError::BlocklistChanged);
    }
    plan.remove_partial = remove_partial;

    if plan.total_removal() == 0 {
        println!("no blocklist entries match {}", plan.target);
        return Ok(());
    }

    let result = apply_unban_plan(blocklist_path, &plan)?;
    println!(
        "removed {} blocklist entries for {}",
        result.total(),
        plan.target
    );
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

pub(super) fn ban_targets_in_file(
    path: &Path,
    targets: &[CanonicalCidr],
) -> Result<Vec<BanOutcome>, KidoboError> {
    let blocklist = BlocklistDocument::load(path)?;
    let existing = blocklist
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    let classifications = classify_ban_targets(&existing, targets);
    let mut appended_entries = Vec::new();
    let mut outcomes = Vec::with_capacity(classifications.len());

    for classification in classifications {
        if let BanClassification::Added(cidr) = classification {
            appended_entries.push(cidr.to_string());
        }
        outcomes.push(BanOutcome::from(classification));
    }

    if !appended_entries.is_empty() {
        ensure_blocklist_parent(path)?;
        append_blocklist_entries(
            path,
            &appended_entries,
            blocklist.has_content,
            blocklist.trailing_newline,
        )?;
    }

    Ok(outcomes)
}

pub(super) fn ban_target_in_file(path: &Path, input: &str) -> Result<BanOutcome, KidoboError> {
    let canonical = parse_blocklist_target(input)?;
    let blocklist = BlocklistDocument::load(path)?;
    let existing = blocklist
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    let Some(classification) = classify_ban_targets(&existing, &[canonical])
        .into_iter()
        .next()
    else {
        unreachable!("single target must produce a classification");
    };
    let outcome = BanOutcome::from(classification);

    if matches!(outcome, BanOutcome::Added(_)) {
        let canonical_str = canonical.to_string();
        ensure_blocklist_parent(path)?;
        append_blocklist_entries(
            path,
            &[canonical_str.as_str()],
            blocklist.has_content,
            blocklist.trailing_newline,
        )?;
    }

    Ok(outcome)
}

fn append_blocklist_entries<S: AsRef<str>>(
    path: &Path,
    entries: &[S],
    has_content: bool,
    trailing_newline: bool,
) -> Result<(), KidoboError> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut contents = if path.exists() {
        read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?
    } else {
        String::new()
    };
    if has_content && !trailing_newline {
        contents.push('\n');
    }
    for entry in entries {
        contents.push_str(entry.as_ref());
        contents.push('\n');
    }

    write_string_atomic(path, &contents).map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

pub(super) fn read_blocklist_target_lines(path: &Path) -> Result<Vec<String>, KidoboError> {
    let contents =
        read_to_string_with_limit(path, BLOCKLIST_TARGET_FILE_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistTargetFileRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;

    Ok(contents.lines().map(ToString::to_string).collect())
}

#[allow(
    clippy::print_stderr,
    reason = "CLI parser reports invalid targets to standard error"
)]
fn parse_blocklist_targets_or_report(inputs: &[String]) -> Result<Vec<CanonicalCidr>, KidoboError> {
    let mut targets = Vec::with_capacity(inputs.len());
    let mut invalid_inputs = Vec::new();

    for input in inputs {
        match parse_blocklist_target(input) {
            Ok(target) => targets.push(target),
            Err(_) => invalid_inputs.push(input.clone()),
        }
    }

    for invalid in &invalid_inputs {
        eprintln!("invalid target: {invalid}");
    }

    if invalid_inputs.is_empty() {
        Ok(targets)
    } else {
        Err(KidoboError::BlocklistInvalidTargets {
            count: invalid_inputs.len(),
        })
    }
}

fn build_unban_file_request(
    path: &Path,
    targets: &[CanonicalCidr],
) -> Result<FileUnbanRequest, KidoboError> {
    let blocklist = BlocklistDocument::load(path)?;
    let line_canonicals = blocklist
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let index_plan = plan_unban_many(&line_canonicals, targets);
    let partial_matches = partial_matches_for_indexes(&blocklist, &index_plan.partial_indexes);

    Ok(FileUnbanRequest {
        requested_target_count: targets.len(),
        plan: UnbanPlan {
            target: format!("{} file target(s)", targets.len()),
            blocklist,
            exact_indexes: index_plan.exact_indexes,
            partial_matches,
            remove_partial: false,
        },
    })
}

fn partial_matches_for_indexes(
    blocklist: &BlocklistDocument,
    indexes: &[usize],
) -> Vec<PartialMatch> {
    let partial_indexes = indexes.iter().copied().collect::<BTreeSet<_>>();

    blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            if !partial_indexes.contains(&index) {
                return None;
            }

            line.canonical.map(|canonical| PartialMatch {
                index,
                entry: canonical.to_string(),
            })
        })
        .collect()
}
