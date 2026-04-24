use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use log::{info, warn};

use crate::adapters::asn::{
    Bgpq4AsnPrefixResolver, delete_asn_cache_file, load_asn_prefixes_with_cache,
    normalize_asn_tokens,
};
use crate::adapters::blocklist_file::{BlocklistDocument, write_blocklist_lines};
use crate::adapters::config::load_config_from_file;
use crate::adapters::config_edit::update_asn_bans;
use crate::adapters::lock::acquire_non_blocking;
use crate::core::blocklist::exact_match_indexes;
use crate::core::network::CanonicalCidr;
use crate::error::KidoboError;

#[allow(clippy::print_stdout)]
pub(super) fn run_ban_asn_command(
    config_path: &Path,
    blocklist_path: &Path,
    cache_dir: &Path,
    lock_path: &Path,
    asn_tokens: &[String],
) -> Result<(), KidoboError> {
    let requested_asns = normalize_asn_tokens(asn_tokens)?;
    let _lock = acquire_non_blocking(lock_path)?;
    let config = load_config_from_file(config_path)?;
    let stale_after = Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get()));
    let asn_cache_dir = cache_dir.join("asn");
    let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();

    let mut resolved_prefixes = Vec::new();
    for asn in &requested_asns {
        let cached = load_asn_prefixes_with_cache(*asn, &asn_cache_dir, stale_after, &resolver)?;
        if cached.stale {
            warn!("ASN cache stale fallback used for AS{asn}");
        }
        resolved_prefixes.extend(cached.prefixes);
    }
    resolved_prefixes.sort_unstable();
    resolved_prefixes.dedup();

    let update = update_asn_bans(config_path, &requested_asns, &[])?;
    let removed_dups = match remove_exact_blocklist_duplicates(blocklist_path, &resolved_prefixes) {
        Ok(removed) => removed,
        Err(err) => {
            warn!("ASN ban duplicate cleanup failed after config update: {err}");
            0
        }
    };

    println!(
        "added {} ASN ban(s): {}",
        update.added.len(),
        format_asn_list(&update.added)
    );
    if removed_dups > 0 {
        println!("removed {removed_dups} duplicate IP/CIDR entry(ies) from local blocklist");
    }
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

#[allow(clippy::print_stdout)]
pub(super) fn run_unban_asn_command(
    config_path: &Path,
    cache_dir: &Path,
    lock_path: &Path,
    asn_tokens: &[String],
) -> Result<(), KidoboError> {
    let requested_asns = normalize_asn_tokens(asn_tokens)?;
    let update = {
        let _lock = acquire_non_blocking(lock_path)?;
        update_asn_bans(config_path, &[], &requested_asns)?
    };
    let asn_cache_dir = cache_dir.join("asn");
    let mut deleted_cache_count = 0_usize;
    for asn in &requested_asns {
        match delete_asn_cache_file(*asn, &asn_cache_dir) {
            Ok(true) => deleted_cache_count += 1,
            Ok(false) => {}
            Err(err) => warn!("ASN cache cleanup failed for AS{asn}: {err}"),
        }
    }

    println!(
        "removed {} ASN ban(s): {}",
        update.removed.len(),
        format_asn_list(&update.removed)
    );
    println!("deleted {deleted_cache_count} ASN cache file(s)");
    println!("changes take effect after running `sudo kidobo sync`");
    Ok(())
}

fn format_asn_list(asns: &[u32]) -> String {
    asns.iter()
        .map(|asn| format!("AS{asn}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn remove_exact_blocklist_duplicates(
    path: &Path,
    duplicates: &[CanonicalCidr],
) -> Result<usize, KidoboError> {
    if duplicates.is_empty() || !path.exists() {
        return Ok(0);
    }
    let blocklist = BlocklistDocument::load(path)?;
    let line_canonicals = blocklist
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let removal_indexes = exact_match_indexes(&line_canonicals, duplicates)
        .into_iter()
        .collect::<HashSet<_>>();
    let kept_lines = blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if removal_indexes.contains(&idx) {
                None
            } else {
                Some(line.original.as_str())
            }
        })
        .collect::<Vec<_>>();

    let removed = blocklist.lines.len().saturating_sub(kept_lines.len());
    if removed > 0 {
        write_blocklist_lines(path, &kept_lines)?;
        info!("removed duplicate local blocklist entries covered by ASN bans: removed={removed}");
    }
    Ok(removed)
}
