use std::io::{self, Write};

use crate::adapters::blocklist_file::BlocklistDocument;
use crate::error::KidoboError;

use super::plan::{PartialMatch, UnbanPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnbanPreview {
    target: String,
    exact_entries: Vec<String>,
    partial_entries: Vec<String>,
}

impl UnbanPreview {
    pub(super) fn from_plan(plan: &UnbanPlan) -> Self {
        Self {
            target: plan.target.clone(),
            exact_entries: plan_entry_strings(&plan.blocklist, &plan.exact_indexes),
            partial_entries: partial_entry_strings(&plan.partial_matches),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileUnbanPreview {
    requested_target_count: usize,
    exact_entries: Vec<String>,
    partial_entries: Vec<String>,
}

pub(super) fn build_file_unban_preview(
    requested_target_count: usize,
    blocklist: &BlocklistDocument,
    exact_indexes: &[usize],
    partial_matches: &[PartialMatch],
) -> FileUnbanPreview {
    FileUnbanPreview {
        requested_target_count,
        exact_entries: plan_entry_strings(blocklist, exact_indexes),
        partial_entries: partial_entry_strings(partial_matches),
    }
}

fn plan_entry_strings(blocklist: &BlocklistDocument, indexes: &[usize]) -> Vec<String> {
    let mut entries = indexes
        .iter()
        .filter_map(|idx| blocklist.lines.get(*idx))
        .filter_map(|line| line.canonical.map(|canonical| canonical.to_string()))
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries
}

fn partial_entry_strings(partial_matches: &[PartialMatch]) -> Vec<String> {
    let mut entries = partial_matches
        .iter()
        .map(|partial| partial.entry.clone())
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries
}

#[allow(
    clippy::print_stdout,
    reason = "Interactive CLI prompt writes directly to standard output"
)]
fn prompt_confirmation() -> Result<bool, KidoboError> {
    print!("Remove these entries as well? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|err| KidoboError::BlocklistPrompt {
            reason: err.to_string(),
        })?;

    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .map_err(|err| KidoboError::BlocklistPrompt {
            reason: err.to_string(),
        })?;

    let response = buffer.trim().to_ascii_lowercase();
    Ok(matches!(response.as_str(), "y" | "yes"))
}

#[allow(
    clippy::print_stdout,
    reason = "Interactive CLI confirmation writes directly to standard output"
)]
pub(super) fn confirm_partial_matches(
    heading: &str,
    partial_matches: &[PartialMatch],
    yes: bool,
) -> Result<bool, KidoboError> {
    if partial_matches.is_empty() {
        return Ok(false);
    }

    println!("{heading}");
    for partial in partial_matches {
        println!("  - {}", partial.entry);
    }

    if yes {
        println!("auto-approving removal of partial matches");
        Ok(true)
    } else {
        prompt_confirmation()
    }
}
