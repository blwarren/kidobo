use std::path::PathBuf;

use crate::cli::CliIo;
use crate::cli::args::ReportFormat;
use crate::cli::mutation::confirm;
use crate::cli::presentation::Status;
use crate::error::KidoboError;
use kidobo_adapters::config_management::FileConfigurationManager;
use kidobo_adapters::init::SystemInitProvisioner;
use kidobo_adapters::inspection::SystemLiveProbe;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::configuration::{
    self, ApplyDependencies, ConfigurationDecision, ConfigurationEdit, ConfigurationPreview,
    ConfigurationRequest, ConfigurationView, PreviewDependencies, ReadDependencies,
};
use kidobo_app::init::{
    self, DEFAULT_KIDOBO_BINARY_PATH, FALLBACK_KIDOBO_BINARY_PATH, InitDependencies,
    InitProvisioner, InitRequest,
};
use kidobo_app::inspection::LiveProbe;

const MAX_SETUP_DATA_BYTES: usize = 64 * 1024;

pub fn run(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    if !io.interactive() {
        io.presentation().paragraph(io.stdout, "Setup requires interactive stdin and terminal output. For automation use sudo kidobo init, sudo kidobo sources add URL, sudo kidobo allow add IP_OR_CIDR --yes, kidobo doctor, then sudo kidobo sync. At default paths init enables the sync timer immediately.")?;
        return Err(KidoboError::Usage {
            message:
                "Run sudo kidobo setup in a terminal, or use the noninteractive commands above."
                    .to_string(),
        });
    }
    let preview = collect_preview(io)?;
    let alternate_root = preview.paths().root_override.is_some();
    let view = io.presentation();
    review(&preview, io)?;
    let executable_candidates = if alternate_root {
        vec![std::env::current_exe().map_err(KidoboError::from)?]
    } else {
        vec![
            PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH),
            PathBuf::from(FALLBACK_KIDOBO_BINARY_PATH),
        ]
    };
    let request = InitRequest {
        paths: path_resolution_input_from_process(None),
        executable_candidates,
    };
    SystemInitProvisioner::default()
        .resolve_installed_executable(&request.executable_candidates)?;
    if !confirm(io, "Save these settings and provision missing files?")? {
        view.paragraph(io.stdout, "Setup cancelled; no files were changed.")?;
        return Ok(());
    }
    configuration::apply(
        &preview,
        &ConfigurationDecision {
            approve_exemption: true,
        },
        &ApplyDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            locks: &FileLockManager,
            reader: &FileConfigurationManager,
            writer: &FileConfigurationManager,
        },
    )?;
    let dependencies = InitDependencies {
        cancellation: &super::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        provisioner: &SystemInitProvisioner::default(),
    };
    after_save(
        io,
        alternate_root,
        &mut SetupSteps {
            provision: &mut |io| {
                let outcome = init::provision(&request, &dependencies)?;
                super::init::write_init_outcome(&outcome, io)?;
                Ok(())
            },
            doctor: &mut |io| super::doctor::run_doctor_command(Some(ReportFormat::Human), io),
            sync: &mut |io| super::sync::run_sync_command(false, io),
            timer: &mut || {
                init::activate_timer(&request, &dependencies)
                    .map(|_| ())
                    .map_err(KidoboError::from)
            },
        },
    )
    .map_err(|source| match source {
        source @ KidoboError::SetupAfterSave { .. } => source,
        source => saved_error("post-save reporting", source),
    })
}

fn collect_preview(io: &mut CliIo<'_>) -> Result<ConfigurationPreview, KidoboError> {
    let input = path_resolution_input_from_process(None);
    let current = configuration::read(
        &input,
        true,
        &ReadDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
        },
    )?;
    introduction(&current, io)?;
    let enable_ipv6 = choice(
        io,
        "Enable IPv6 enforcement?",
        current.config.ipset.enable_ipv6,
    )?;
    let include_github_meta = choice(
        io,
        "Use the bounded GitHub metadata safelist?",
        current.config.safe.include_github_meta,
    )?;
    let remote_urls = additions(
        io,
        "Add a remote feed URL (blank to keep existing feeds):",
        current.config.remote.urls.clone(),
    )?;
    let safe_ips = additions(
        io,
        "Add a safelist IP/CIDR (blank to keep existing exemptions):",
        current
            .config
            .safe
            .ips
            .iter()
            .map(ToString::to_string)
            .collect(),
    )?;
    let preview = configuration::prepare(
        &ConfigurationRequest {
            paths: input,
            allow_missing: true,
            edit: ConfigurationEdit::SetBasic {
                enable_ipv6,
                include_github_meta,
                remote_urls,
                safe_ips,
            },
        },
        &PreviewDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            reader: &FileConfigurationManager,
            editor: &FileConfigurationManager,
        },
    )?;
    let expected_existing = !preview.creates_file();
    if current.exists != expected_existing || preview.before() != &current.config {
        return Err(kidobo_app::AppError::ConfigurationChanged.into());
    }
    Ok(preview)
}

fn introduction(current: &ConfigurationView, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let view = io.presentation();
    view.heading(io.stdout, "Kidobo setup")?;
    view.paragraph(io.stdout, "Kidobo runs one-shot syncs using ipset, iptables/ip6tables, and optional bgpq4 for ASN refresh. Install prerequisites with your distribution's package manager. This assistant does not install packages or elevate privileges.")?;
    view.paragraph(io.stdout, "Existing files are preserved. Review choices before any writes. IPv4 is always managed; IPv6 is optional. New scheduling stays inactive until separately confirmed after doctor.")?;
    view.key_values(
        io.stdout,
        &[
            (
                "Configuration",
                &current.paths.config_file.display().to_string(),
            ),
            (
                "Starting from",
                if current.exists {
                    "Existing configuration"
                } else {
                    "Virtual starter; no files have been created"
                },
            ),
        ],
    )?;
    let alternate_root = current.paths.root_override.is_some();
    if !alternate_root {
        let timer =
            SystemLiveProbe::default().inspect_timer(&super::interrupt::SigintCancellation)?;
        view.paragraph(io.stdout, &format!("Existing timer: {}. An already active timer is not stopped and may apply saved changes before setup finishes.", timer.detail))?;
    }
    Ok(())
}

fn choice(io: &mut CliIo<'_>, question: &str, current: bool) -> Result<bool, KidoboError> {
    loop {
        io.presentation().paragraph(io.stdout, question)?;
        write!(
            io.stdout,
            "{} (blank keeps current): ",
            if current { "[Y/n]" } else { "[y/N]" }
        )?;
        io.stdout.flush()?;
        let response = io.input.read_response()?;
        match response.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(current),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => io.presentation().paragraph(
                io.stdout,
                "Enter yes, no, or a blank line to retain the current value.",
            )?,
        }
    }
}

fn additions(
    io: &mut CliIo<'_>,
    question: &str,
    mut values: Vec<String>,
) -> Result<Vec<String>, KidoboError> {
    let mut bytes = values.iter().map(String::len).sum::<usize>();
    loop {
        io.presentation().paragraph(io.stdout, question)?;
        io.stdout.flush()?;
        let response = io.input.read_response()?;
        let value = response.trim();
        if value.is_empty() {
            return Ok(values);
        }
        bytes = bytes.checked_add(value.len() + 1).filter(|bytes| *bytes <= MAX_SETUP_DATA_BYTES).ok_or_else(|| KidoboError::Usage { message: "Setup choices exceed the 65536-byte configuration budget; no settings were saved.".to_string() })?;
        values.push(value.to_string());
    }
}

fn review(preview: &ConfigurationPreview, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let view = io.presentation();
    let config = preview.after();
    view.heading(io.stdout, "Review before saving")?;
    view.key_values(
        io.stdout,
        &[
            (
                "Configuration",
                &preview.paths().config_file.display().to_string(),
            ),
            ("IPv4", "Enabled"),
            (
                "IPv6",
                if config.ipset.enable_ipv6 {
                    "Enabled"
                } else {
                    "Disabled"
                },
            ),
            (
                "GitHub safelist",
                if config.safe.include_github_meta {
                    "Enabled with existing admission limits"
                } else {
                    "Disabled"
                },
            ),
            ("Fields changing", &preview.changed_fields().join(", ")),
        ],
    )?;
    for url in &config.remote.urls {
        view.key_values(io.stdout, &[("Feed", url)])?;
    }
    for cidr in &config.safe.ips {
        view.key_values(io.stdout, &[("Exemption", &cidr.to_string())])?;
    }
    if preview.expands_exemption() {
        view.status(io.stdout, Status::Warn, "Exemption coverage expands", "Safelist entries subtract from all Kidobo blocklist sources after sync. A /0 exempts the entire address family; this does not install a kernel ACCEPT rule.")?;
    }
    view.paragraph(io.stdout, "Saving writes configuration and provisions only missing files. Saved choices do not themselves update the firewall. Doctor runs next; first sync and new timer activation require separate affirmative answers.")?;
    Ok(())
}

type SetupAction<'a> = &'a mut dyn FnMut(&mut CliIo<'_>) -> Result<(), KidoboError>;

struct SetupSteps<'a> {
    provision: SetupAction<'a>,
    doctor: SetupAction<'a>,
    sync: SetupAction<'a>,
    timer: &'a mut dyn FnMut() -> Result<(), KidoboError>,
}

fn saved_error(stage: &'static str, source: KidoboError) -> KidoboError {
    KidoboError::SetupAfterSave {
        stage,
        source: Box::new(source),
    }
}

fn after_save(
    io: &mut CliIo<'_>,
    alternate_root: bool,
    steps: &mut SetupSteps<'_>,
) -> Result<(), KidoboError> {
    (steps.provision)(io).map_err(|source| saved_error("provisioning missing files", source))?;
    (steps.doctor)(io).map_err(|source| saved_error("doctor checks", source))?;
    if confirm(io, "Run the first synchronization now?")
        .map_err(|source| saved_error("first-sync confirmation", source))?
    {
        (steps.sync)(io).map_err(|source| saved_error("first synchronization", source))?;
    } else {
        io.presentation().paragraph(io.stdout, "Setup did not request an initial sync. Saved choices take effect through sync; existing scheduling may apply them.")?;
    }
    if alternate_root {
        io.presentation().paragraph(io.stdout, "Alternate root: systemd units were provisioned locally; the host timer was not activated.")?;
    } else {
        io.presentation().paragraph(io.stdout, "Enabling scheduling authorizes periodic sync and can apply saved settings even if the manual first sync was declined. Existing active timers are not stopped.")?;
        if confirm(
            io,
            "Enable scheduled synchronization with kidobo-sync.timer?",
        )
        .map_err(|source| saved_error("timer confirmation", source))?
        {
            (steps.timer)().map_err(|source| saved_error("timer activation", source))?;
        }
    }
    io.presentation()
        .next(io.stdout, "kidobo status; sudo kidobo sync when ready")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::cli::PromptInput;

    struct Input(VecDeque<String>);
    impl PromptInput for Input {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            Ok(self
                .0
                .pop_front()
                .expect("unexpected prompt after a stop boundary"))
        }
    }

    fn with_io<T>(answers: &[&str], action: impl FnOnce(&mut CliIo<'_>) -> T) -> (T, String) {
        let mut input = Input(answers.iter().map(|answer| (*answer).to_string()).collect());
        let mut output = Vec::new();
        let result = action(&mut CliIo {
            input: &mut input,
            stdout: &mut output,
            stderr: &mut Vec::new(),
            stdin_is_terminal: true,
            stdout_is_terminal: true,
            stderr_is_terminal: false,
            terminal_width: 60,
            term_dumb: false,
            under_systemd: false,
            no_color: true,
        });
        (result, String::from_utf8(output).expect("terminal output"))
    }

    fn follow_up(
        answers: &[&str],
        alternate: bool,
        fail_at: Option<&str>,
    ) -> (Result<(), KidoboError>, Vec<&'static str>, String) {
        let events = RefCell::new(Vec::new());
        let execute = |stage: &'static str| {
            events.borrow_mut().push(stage);
            if fail_at == Some(stage) {
                Err(KidoboError::DoctorFailed)
            } else {
                Ok(())
            }
        };
        let (result, output) = with_io(answers, |io| {
            after_save(
                io,
                alternate,
                &mut SetupSteps {
                    provision: &mut |_| execute("provision"),
                    doctor: &mut |_| execute("doctor"),
                    sync: &mut |_| execute("sync"),
                    timer: &mut || execute("timer"),
                },
            )
        });
        (result, events.into_inner(), output)
    }

    #[test]
    fn failed_doctor_stops_before_any_apply_or_timer_confirmation() {
        let (result, events, _) = follow_up(&[], false, Some("doctor"));
        match result.expect_err("doctor blocks follow-up") {
            KidoboError::SetupAfterSave { stage, source } => {
                assert_eq!(stage, "doctor checks");
                assert!(matches!(*source, KidoboError::DoctorFailed));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(events, ["provision", "doctor"]);
    }

    #[test]
    fn failed_explicit_first_sync_stops_before_timer_activation() {
        let (result, events, _) = follow_up(&["yes"], false, Some("sync"));
        assert!(matches!(
            result.expect_err("sync failed"),
            KidoboError::SetupAfterSave {
                stage: "first synchronization",
                ..
            }
        ));
        assert_eq!(events, ["provision", "doctor", "sync"]);
    }

    #[test]
    fn scheduling_has_separate_default_no_consent() {
        let (result, events, output) = follow_up(&["n", ""], false, None);
        result.expect("all optional actions declined");
        assert_eq!(events, ["provision", "doctor"]);
        assert!(output.contains("periodic sync"));
        let (result, events, _) = follow_up(&["n", "yes"], false, None);
        result.expect("scheduling explicitly approved");
        assert_eq!(events, ["provision", "doctor", "timer"]);
        let (result, events, _) = follow_up(&["yes", "n"], false, None);
        result.expect("only first sync approved");
        assert_eq!(events, ["provision", "doctor", "sync"]);
    }

    #[test]
    fn alternate_root_never_offers_or_activates_host_scheduling() {
        let (result, events, output) = follow_up(&["n"], true, None);
        result.expect("alternate root");
        assert_eq!(events, ["provision", "doctor"]);
        assert!(output.contains("host timer was not activated"));
    }

    #[test]
    fn choices_retain_current_values_and_reject_ambiguous_answers() {
        let (result, output) = with_io(&["maybe", ""], |io| choice(io, "Use IPv6?", true));
        assert!(result.expect("retained current value"));
        assert!(output.contains("Enter yes, no"));
        let (result, _) = with_io(&["NO"], |io| choice(io, "Use IPv6?", true));
        assert!(!result.expect("explicit disable"));
    }

    #[test]
    fn setup_collection_enforces_a_total_input_budget_before_saving() {
        let oversized = "x".repeat(MAX_SETUP_DATA_BYTES + 1);
        let (result, _) = with_io(&[&oversized], |io| {
            additions(io, "Add a source:", Vec::new())
        });
        assert!(matches!(
            result.expect_err("collection bounded"),
            KidoboError::Usage { .. }
        ));
    }
}
