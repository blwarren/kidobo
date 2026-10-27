use crate::cli::CliIo;
use crate::cli::mutation::confirm;
use crate::cli::presentation::Status;
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::flush::SystemFlushBackend;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::AppError;
use kidobo_app::flush::{self, FlushDependencies, FlushOutcome, FlushRequest};

pub fn run_flush_command(
    cache_only: bool,
    yes: bool,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    run_flush_with(cache_only, yes, io, &mut || execute_flush(cache_only))
}

fn execute_flush(cache_only: bool) -> Result<FlushOutcome, KidoboError> {
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let locks = FileLockManager;
    let backend = SystemFlushBackend::default();
    flush::execute(
        &FlushRequest {
            paths: path_resolution_input_from_process(None),
            cache_only,
        },
        &FlushDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &paths,
            configs: &configs,
            locks: &locks,
            backend: &backend,
        },
    )
    .map_err(KidoboError::from)
}

fn run_flush_with(
    cache_only: bool,
    yes: bool,
    io: &mut CliIo<'_>,
    execute: &mut dyn FnMut() -> Result<FlushOutcome, KidoboError>,
) -> Result<(), KidoboError> {
    if !cache_only && !yes {
        if io.interactive() {
            let view = io.presentation();
            view.heading(io.stdout, "Remove Kidobo enforcement")?;
            view.paragraph(io.stdout, "Full flush removes Kidobo's managed firewall rules, ipsets, and remote cache. Saved bans and configuration remain.")?;
            view.paragraph(io.stdout, "An enabled sync timer may recreate enforcement on its next run. This is a removal operation; use doctor to diagnose problems.")?;
            if !confirm(io, "Remove the managed firewall state and remote cache?")? {
                view.paragraph(io.stdout, "Flush cancelled; no cleanup was started.")?;
                return Ok(());
            }
        } else {
            writeln!(
                io.stderr,
                "Warning: full flush removes Kidobo's managed firewall rules, ipsets, and remote cache. Use --yes to acknowledge this in scripts."
            )?;
        }
    }
    let outcome = execute()?;
    let rendering = render_outcome(&outcome, cache_only, io);
    if !outcome.failed.is_empty() {
        return Err(AppError::FlushIncomplete {
            failures: outcome.failed.len(),
            details: outcome.failure_details(),
        }
        .into());
    }
    rendering
}

fn render_outcome(
    outcome: &FlushOutcome,
    cache_only: bool,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let view = io.presentation();
    view.heading(io.stdout, "Kidobo cleanup")?;
    for operation in &outcome.completed {
        view.status(
            io.stdout,
            Status::Pass,
            operation,
            "Removed or confirmed absent.",
        )?;
    }
    for failure in &outcome.failed {
        view.status(io.stdout, Status::Fail, &failure.operation, &failure.reason)?;
    }
    view.paragraph(
        io.stdout,
        &format!(
            "{} cleanup steps completed; {} incomplete.",
            outcome.completed.len(),
            outcome.failed.len()
        ),
    )?;
    if outcome.failed.is_empty() {
        view.next(
            io.stdout,
            if cache_only {
                "sudo kidobo sync to refresh cached sources"
            } else {
                "sudo kidobo sync to restore enforcement from saved sources"
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::PromptInput;
    use kidobo_app::flush::CleanupFailure;

    struct Input(Option<&'static str>);

    impl PromptInput for Input {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            Ok(self
                .0
                .take()
                .expect("unexpected flush confirmation")
                .to_string())
        }
    }

    fn with_io<T>(
        input: &mut Input,
        terminals: (bool, bool),
        action: impl FnOnce(&mut CliIo<'_>) -> T,
    ) -> (T, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = action(&mut CliIo {
            input,
            stdout: &mut stdout,
            stderr: &mut stderr,
            stdin_is_terminal: terminals.0,
            stdout_is_terminal: terminals.1,
            stderr_is_terminal: false,
            terminal_width: 60,
            term_dumb: false,
            under_systemd: false,
            no_color: true,
        });
        (
            result,
            String::from_utf8(stdout).expect("stdout"),
            String::from_utf8(stderr).expect("stderr"),
        )
    }

    #[test]
    fn interactive_full_flush_requires_affirmative_consent_before_backend_work() {
        for answer in ["", "n", "no"] {
            let mut calls = 0;
            let (result, stdout, _) = with_io(&mut Input(Some(answer)), (true, true), |io| {
                run_flush_with(false, false, io, &mut || {
                    calls += 1;
                    Ok(FlushOutcome::default())
                })
            });
            result.expect("declined flush");
            assert_eq!(calls, 0);
            assert!(stdout.contains("Flush cancelled; no cleanup was started."));
            assert!(stdout.contains("Saved bans and configuration remain."));
        }
    }

    #[test]
    fn scripts_yes_and_cache_only_paths_preserve_execution_without_prompting() {
        for (cache_only, yes, terminals, warning) in [
            (true, false, (true, true), false),
            (false, true, (true, true), false),
            (false, false, (false, false), true),
            (false, false, (true, false), true),
            (false, false, (false, true), true),
        ] {
            let mut calls = 0;
            let (result, _, stderr) = with_io(&mut Input(None), terminals, |io| {
                run_flush_with(cache_only, yes, io, &mut || {
                    calls += 1;
                    Ok(FlushOutcome::default())
                })
            });
            result.expect("unprompted flush");
            assert_eq!(calls, 1);
            assert_eq!(stderr.contains("Warning: full flush"), warning);
        }
    }

    #[test]
    fn incomplete_cleanup_retains_ledger_error_and_escapes_backend_diagnostics() {
        let (result, stdout, _) = with_io(&mut Input(Some("yes")), (true, true), |io| {
            run_flush_with(false, false, io, &mut || {
                Ok(FlushOutcome {
                    completed: vec!["IPv4 firewall".to_string()],
                    failed: vec![CleanupFailure {
                        operation: "IPv6 firewall".to_string(),
                        reason: "permission denied\n\u{1b}[31m".to_string(),
                    }],
                })
            })
        });
        let error = result.expect_err("incomplete cleanup");
        match error {
            KidoboError::Application {
                source: AppError::FlushIncomplete { failures, details },
            } => {
                assert_eq!(failures, 1);
                assert_eq!(details, "permission denied\n\u{1b}[31m");
            }
            other => panic!("lost cleanup outcome: {other:?}"),
        }
        assert!(stdout.contains("[PASS] IPv4 firewall"));
        assert!(stdout.contains("[FAIL] IPv6 firewall"));
        assert!(stdout.contains("permission denied\\n\\x1B[31m"));
        assert!(!stdout.contains('\u{1b}'));
    }

    #[test]
    fn pre_cleanup_interruption_keeps_the_existing_exit_contract() {
        let (result, _, _) = with_io(&mut Input(None), (false, false), |io| {
            run_flush_with(false, true, io, &mut || Err(AppError::Interrupted.into()))
        });
        assert_eq!(result.expect_err("interrupted cleanup").exit_code(), 130);
    }
}
