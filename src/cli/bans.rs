use crate::cli::CliIo;
use crate::cli::presentation::{format_utc, remaining_duration};
use crate::error::KidoboError;
use kidobo_adapters::bans::FileSavedBanReader;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::temporary_bans::SystemClock;
use kidobo_app::bans::{self, BanLifetimeFilter, BanListDependencies, BanListRequest};

pub fn run(
    lifetime: BanLifetimeFilter,
    asn_only: bool,
    limit: Option<usize>,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let outcome = bans::execute(
        &BanListRequest {
            paths: path_resolution_input_from_process(None),
            lifetime,
            asn_only,
            limit,
        },
        &BanListDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            configs: &FileConfigRepository,
            clock: &SystemClock,
            reader: &FileSavedBanReader,
        },
    )?;
    let view = io.presentation();
    view.heading(io.stdout, "Saved operator bans")?;
    view.paragraph(io.stdout, "Saved source state, not necessarily applied to the live firewall. Expired records can remain enforced until a successful sync.")?;
    let rows = outcome
        .records
        .iter()
        .map(|record| {
            let (expiry, state) = record.expires_at.map_or_else(
                || ("Permanent".to_string(), "Saved".to_string()),
                |expires_at| {
                    (
                        format_utc(expires_at),
                        remaining_duration(expires_at, outcome.cutoff),
                    )
                },
            );
            vec![record.target.clone(), expiry, state]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        view.paragraph(io.stdout, "No saved bans match these filters.")?;
    } else {
        view.table(io.stdout, &["Target", "Expires", "Saved lifetime"], &rows)?;
    }
    view.paragraph(
        io.stdout,
        &format!(
            "{} shown of {} matching entries; {} omitted.",
            outcome.records.len(),
            outcome.total,
            outcome.omitted
        ),
    )?;
    if outcome.omitted > 0 {
        view.next(io.stdout, "kidobo bans --all (retain any desired filters)")?;
    }
    view.next(io.stdout, "sudo kidobo sync to apply saved source changes")?;
    Ok(())
}
