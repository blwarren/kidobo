//! Thin CLI orchestration for saved feeds, exemptions, and effective configuration.

use std::collections::BTreeSet;
use std::fmt::Display;

use kidobo_adapters::config_management::{FileConfigurationManager, FileSourceCacheInspector};
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::configuration::{
    self, ApplyDependencies, CacheAvailability, ConfigurationDecision, ConfigurationEdit,
    ConfigurationOutcome, ConfigurationPreview, ConfigurationRequest, PreviewDependencies,
    ReadDependencies, SettingOrigin, SettingValue, SourceListDependencies,
};

use crate::cli::CliIo;
use crate::cli::args::{AllowAction, ConfigAction, SourceAction};
use crate::cli::mutation::confirm;
use crate::cli::presentation::{escape, redact_urls};
use crate::error::KidoboError;

pub fn sources(action: SourceAction, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    match action {
        SourceAction::List => list_sources(io),
        SourceAction::Add { url } => edit(ConfigurationEdit::AddSource(url), false, io),
        SourceAction::Remove { url } => edit(ConfigurationEdit::RemoveSource(url), false, io),
    }
}

fn list_sources(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let sources = configuration::sources(
        &path_resolution_input_from_process(None),
        &SourceListDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
            cache_inspector: &FileSourceCacheInspector,
        },
    )?;
    let view = io.presentation();
    view.heading(io.stdout, "Configured remote feeds")?;
    view.paragraph(io.stdout, "Saved settings; enforcement changes at the next successful sync. Cache availability does not establish feed freshness.")?;
    if sources.is_empty() {
        view.paragraph(io.stdout, "No remote feeds are configured.")?;
        view.next(
            io.stdout,
            "sudo kidobo sources add https://example.org/feed.txt",
        )?;
    }
    for source in sources {
        let availability = match source.cache.availability {
            CacheAvailability::Available => "Available",
            CacheAvailability::Unavailable => "Unavailable",
            CacheAvailability::Unknown => "Unknown",
        };
        view.record(
            io.stdout,
            &[
                ("URL", &source.url),
                ("Cache", availability),
                (
                    "Provenance",
                    source.cache.provenance.as_deref().unwrap_or("Unknown"),
                ),
                (
                    "Freshness",
                    source.freshness.as_deref().unwrap_or("Unknown"),
                ),
                ("Evidence", &source.cache.detail),
            ],
        )?;
        writeln!(io.stdout)?;
    }
    Ok(())
}

pub fn allow(action: AllowAction, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    match action {
        AllowAction::List => list_allow(io),
        AllowAction::Add { target, yes } => edit(ConfigurationEdit::AddAllow(target), yes, io),
        AllowAction::Remove { target } => edit(ConfigurationEdit::RemoveAllow(target), false, io),
    }
}

fn list_allow(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let targets = configuration::allow_list(
        &path_resolution_input_from_process(None),
        &ReadDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
        },
    )?;
    let view = io.presentation();
    view.heading(io.stdout, "Operator safelist")?;
    view.paragraph(io.stdout, "Saved exemptions subtract addresses from Kidobo's effective blocklist at the next successful sync. They do not install firewall ACCEPT rules.")?;
    if targets.is_empty() {
        view.paragraph(
            io.stdout,
            "No operator-controlled exemptions are configured.",
        )?;
    } else {
        let rows = targets
            .into_iter()
            .map(|target| vec![target])
            .collect::<Vec<_>>();
        view.table(io.stdout, &["Saved exemption"], &rows)?;
    }
    view.next(io.stdout, "kidobo allow add --help")?;
    Ok(())
}

fn edit(change: ConfigurationEdit, yes: bool, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let request = ConfigurationRequest {
        paths: path_resolution_input_from_process(None),
        edit: change,
        allow_missing: false,
    };
    let preview = configuration::prepare(
        &request,
        &PreviewDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
            editor: &FileConfigurationManager,
        },
    )?;
    let mut approve_exemption = yes;
    if preview.expands_exemption() && !yes {
        if !io.interactive() {
            return Err(KidoboError::Usage {
                message: "allow add expands an exemption; use --yes to approve it explicitly, or run from an interactive terminal".to_string(),
            });
        }
        render_exemption_preview(&request.edit, &preview, io)?;
        approve_exemption = confirm(io, "Expand the saved safelist exemption?")?;
        if !approve_exemption {
            io.presentation()
                .paragraph(io.stdout, "Safelist unchanged.")?;
            return Ok(());
        }
    }
    let outcome = configuration::apply(
        &preview,
        &ConfigurationDecision { approve_exemption },
        &ApplyDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            locks: &FileLockManager,
            reader: &FileConfigurationManager,
            writer: &FileConfigurationManager,
        },
    )?;
    report_edit(&outcome, &saved_changes(&request.edit, &preview), io)
}

fn render_exemption_preview(
    change: &ConfigurationEdit,
    preview: &ConfigurationPreview,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let view = io.presentation();
    view.heading(io.stdout, "Expand an operator exemption")?;
    if let ConfigurationEdit::AddAllow(target) = change {
        view.key_values(io.stdout, &[("Requested", target)])?;
    }
    for target in added_values(&preview.before().safe.ips, &preview.after().safe.ips) {
        view.record(io.stdout, &[("New exemption", &target)])?;
    }
    view.paragraph(io.stdout, "Addresses in this range will be exempt from every Kidobo blocklist source at the next successful sync. Broad CIDRs can exempt an entire address family.")?;
    Ok(())
}

fn added_values<T: Ord + Display>(before: &[T], after: &[T]) -> Vec<String> {
    let before = before.iter().collect::<BTreeSet<_>>();
    let after = after.iter().collect::<BTreeSet<_>>();
    after.difference(&before).map(ToString::to_string).collect()
}

fn saved_changes(
    change: &ConfigurationEdit,
    preview: &ConfigurationPreview,
) -> Vec<(&'static str, String)> {
    let before = preview.before();
    let after = preview.after();
    let (action, targets) = match change {
        ConfigurationEdit::AddSource(_) => (
            "Added feed",
            added_values(&before.remote.urls, &after.remote.urls),
        ),
        ConfigurationEdit::RemoveSource(_) => (
            "Removed feed",
            added_values(&after.remote.urls, &before.remote.urls),
        ),
        ConfigurationEdit::AddAllow(_) => (
            "Added exemption",
            added_values(&before.safe.ips, &after.safe.ips),
        ),
        ConfigurationEdit::RemoveAllow(_) => (
            "Removed exemption",
            added_values(&after.safe.ips, &before.safe.ips),
        ),
        ConfigurationEdit::SetBasic { .. } => (
            "Changed setting",
            preview
                .changed_fields()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
    };
    targets.into_iter().map(|target| (action, target)).collect()
}

fn report_edit(
    outcome: &ConfigurationOutcome,
    changes: &[(&str, String)],
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let view = io.presentation();
    if !outcome.changed {
        view.paragraph(io.stdout, "No configuration change was needed.")?;
        return Ok(());
    }
    let result = (|| {
        view.paragraph(
            io.stdout,
            "Configuration change saved; live enforcement is pending.",
        )?;
        for (action, target) in changes {
            view.record(io.stdout, &[("Action", action), ("Target", target)])?;
        }
        view.next(io.stdout, "sudo kidobo sync")
    })();
    result.map_err(|source| KidoboError::SavedConfirmationFailed {
        source: Box::new(source.into()),
    })
}

pub fn config(action: ConfigAction, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let request = path_resolution_input_from_process(None);
    if matches!(action, ConfigAction::Path) {
        let path = configuration::config_path(&request, &SystemPathResolver)?;
        writeln!(io.stdout, "{}", escape(&path.display().to_string()))?;
        return Ok(());
    }
    let configuration = configuration::read(
        &request,
        false,
        &ReadDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
        },
    )?;
    let view = io.presentation();
    view.heading(io.stdout, "Effective Kidobo configuration")?;
    let paths = [
        (
            "Configuration",
            configuration.paths.config_file.display().to_string(),
        ),
        (
            "Local blocklist",
            configuration.paths.blocklist_file.display().to_string(),
        ),
        (
            "Temporary bans",
            configuration
                .paths
                .temporary_bans_file()
                .display()
                .to_string(),
        ),
        ("Cache", configuration.paths.cache_dir.display().to_string()),
    ];
    let fields = paths
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();
    view.key_values(io.stdout, &fields)?;
    view.paragraph(io.stdout, "Origins: explicit values come from the file; default values use built-in defaults; derived values depend on another setting.")?;
    for setting in configuration.settings {
        let value = format_setting(&setting.value)?;
        let origin = match setting.origin {
            SettingOrigin::Explicit => "explicit",
            SettingOrigin::Default => "default",
            SettingOrigin::Derived => "derived",
        };
        view.record(
            io.stdout,
            &[
                ("Setting", setting.key),
                ("Value", &value),
                ("Origin", origin),
            ],
        )?;
        if let Some(note) = setting.note {
            view.paragraph(io.stdout, note)?;
        }
        writeln!(io.stdout)?;
    }
    view.paragraph(
        io.stdout,
        "Manual file editing remains supported. Saved changes take effect after a successful sync.",
    )?;
    Ok(())
}

fn format_setting(value: &SettingValue) -> Result<String, KidoboError> {
    Ok(match value {
        SettingValue::Text(value) => redact_urls(value),
        SettingValue::Boolean(value) => value.to_string(),
        SettingValue::Number(value) => value.to_string(),
        SettingValue::Strings(values) => {
            let redacted = values
                .iter()
                .map(|value| redact_urls(value))
                .collect::<Vec<_>>();
            serde_json::to_string(&redacted)?
        }
        SettingValue::Numbers(values) => serde_json::to_string(values)?,
        SettingValue::NotSet => "Not set".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::cli::PromptInput;
    use kidobo_app::configuration::{ConfigurationDocument, ConfigurationReader};
    use kidobo_app::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use kidobo_app::ports::{NoCancellation, PathResolver};

    const CONFIG: &str = "[ipset]\nset_name='kidobo'\n[safe]\nips=[]\n[remote]\nurls=[]\n";

    struct Paths;

    impl PathResolver for Paths {
        fn resolve(
            &self,
            _: &PathResolutionInput,
            _: ConfigRequirement,
        ) -> Result<ResolvedPaths, kidobo_app::AppError> {
            Ok(ResolvedPaths {
                root_override: Some(PathBuf::from("/fixture")),
                config_dir: PathBuf::from("/fixture"),
                config_file: PathBuf::from("/fixture/config.toml"),
                data_dir: PathBuf::from("/fixture/data"),
                blocklist_file: PathBuf::from("/fixture/data/blocklist.txt"),
                cache_dir: PathBuf::from("/fixture/cache"),
                remote_cache_dir: PathBuf::from("/fixture/cache/remote"),
                lock_file: PathBuf::from("/fixture/cache/sync.lock"),
            })
        }
    }

    struct Reader<'a>(&'a str);

    impl ConfigurationReader for Reader<'_> {
        fn read(&self, _: &Path) -> Result<Option<ConfigurationDocument>, kidobo_app::AppError> {
            Ok(Some(ConfigurationDocument {
                contents: self.0.to_string(),
                explicit_fields: BTreeSet::new(),
                legacy_remote_stale_after_secs: None,
            }))
        }
    }

    fn preview(change: &ConfigurationEdit, contents: &str) -> ConfigurationPreview {
        configuration::prepare(
            &ConfigurationRequest {
                paths: PathResolutionInput {
                    explicit_config_path: None,
                    temp_dir: PathBuf::from("/tmp"),
                    env: std::collections::BTreeMap::new(),
                },
                edit: change.clone(),
                allow_missing: false,
            },
            &PreviewDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                reader: &Reader(contents),
                editor: &FileConfigurationManager,
            },
        )
        .expect("reviewed configuration")
    }

    struct UnusedInput;

    impl PromptInput for UnusedInput {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            panic!("rendering must not read input");
        }
    }

    fn rendered(action: impl FnOnce(&mut CliIo<'_>) -> Result<(), KidoboError>) -> String {
        let mut stdout = Vec::new();
        action(&mut CliIo {
            input: &mut UnusedInput,
            stdout: &mut stdout,
            stderr: &mut Vec::new(),
            stdin_is_terminal: true,
            stdout_is_terminal: true,
            stderr_is_terminal: false,
            terminal_width: 60,
            term_dumb: false,
            under_systemd: false,
            no_color: true,
        })
        .expect("human rendering");
        String::from_utf8(stdout).expect("UTF-8")
    }

    #[test]
    fn effective_values_retain_types_without_confusing_absent_legacy_values_with_defaults() {
        for (value, expected) in [
            (SettingValue::Text("DROP".to_string()), "DROP"),
            (SettingValue::Boolean(false), "false"),
            (SettingValue::Number(500_000), "500000"),
            (
                SettingValue::Strings(vec!["value".to_string()]),
                "[\"value\"]",
            ),
            (SettingValue::Numbers(vec![64496]), "[64496]"),
            (SettingValue::NotSet, "Not set"),
        ] {
            assert_eq!(format_setting(&value).expect("formatted value"), expected);
        }
    }

    #[test]
    fn exemption_review_and_saved_report_show_the_canonical_network() {
        let change = ConfigurationEdit::AddAllow("192.0.2.129/24".to_string());
        let preview = preview(&change, CONFIG);
        let review = rendered(|io| render_exemption_preview(&change, &preview, io));
        assert!(review.contains("Requested: 192.0.2.129/24"));
        assert!(review.contains("New exemption: 192.0.2.0/24"));
        let changes = saved_changes(&change, &preview);
        assert_eq!(
            changes,
            vec![("Added exemption", "192.0.2.0/24".to_string())]
        );
        let saved = rendered(|io| {
            report_edit(
                &ConfigurationOutcome {
                    changed: true,
                    created: false,
                    changed_fields: vec!["safe.ips"],
                },
                &changes,
                io,
            )
        });
        assert!(saved.contains("Configuration change saved; live enforcement is pending."));
        assert!(saved.contains("Action: Added exemption"));
        assert!(saved.contains("Target: 192.0.2.0/24"));
        assert!(!saved.contains("192.0.2.129/24"));
        assert!(saved.ends_with("Next: sudo kidobo sync\n"));
    }

    #[test]
    fn saved_feed_report_identifies_the_action_without_leaking_url_values() {
        let change = ConfigurationEdit::AddSource(
            "https://alice:source-password@e.test/f?token=api-key-secret#section-secret"
                .to_string(),
        );
        let preview = preview(&change, CONFIG);
        let saved = rendered(|io| {
            report_edit(
                &ConfigurationOutcome {
                    changed: true,
                    created: false,
                    changed_fields: vec!["remote.urls"],
                },
                &saved_changes(&change, &preview),
                io,
            )
        });
        assert!(saved.contains("Action: Added feed"));
        assert!(saved.contains("https://REDACTED@e.test/f?REDACTED#REDACTED"));
        for secret in [
            "alice",
            "source-password",
            "api-key-secret",
            "section-secret",
        ] {
            assert!(!saved.contains(secret), "leaked {secret}: {saved}");
        }
    }

    #[test]
    fn removal_reports_saved_canonical_identity_and_noop_does_not_claim_an_action() {
        let change = ConfigurationEdit::RemoveAllow("192.0.2.129/24".to_string());
        let preview = preview(
            &change,
            "[ipset]\nset_name='kidobo'\n[safe]\nips=['192.0.2.0/24']\n",
        );
        assert_eq!(
            saved_changes(&change, &preview),
            vec![("Removed exemption", "192.0.2.0/24".to_string())]
        );
        let unchanged = rendered(|io| {
            report_edit(
                &ConfigurationOutcome {
                    changed: false,
                    created: false,
                    changed_fields: Vec::new(),
                },
                &saved_changes(&change, &preview),
                io,
            )
        });
        assert_eq!(unchanged, "No configuration change was needed.\n");
    }
}
