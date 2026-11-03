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
    let rows = outcome
        .records
        .iter()
        .map(|record| {
            let (expiry, state) = record.expires_at.map_or_else(
                || ("Permanent".to_string(), "—".to_string()),
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
        view.table(io.stdout, &["Target", "Expires", "Remaining"], &rows)?;
    }
    let noun = if outcome.total == 1 { "ban" } else { "bans" };
    if outcome.omitted > 0 {
        view.paragraph(
            io.stdout,
            &format!(
                "{} of {} {noun} shown; {} omitted.",
                outcome.records.len(),
                outcome.total,
                outcome.omitted
            ),
        )?;
        let lifetime_filter = match lifetime {
            BanLifetimeFilter::All => "",
            BanLifetimeFilter::Permanent => " --permanent",
            BanLifetimeFilter::Temporary => " --temporary",
        };
        view.next(
            io.stdout,
            &format!(
                "kidobo bans{lifetime_filter}{} --all",
                if asn_only { " --asn" } else { "" }
            ),
        )?;
    } else if outcome.total > 0 {
        view.paragraph(io.stdout, &format!("{} {noun}.", outcome.total))?;
    }
    Ok(())
}
