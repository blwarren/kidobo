//! Shared confirmation and post-save application controls.

use crate::cli::CliIo;
use crate::cli::presentation::wrap;
use crate::error::KidoboError;

/// Whether a saved source change should be synchronized immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Offer application only after a change and with interactive input and output.
    Prompt,
    /// Synchronize explicitly, including unchanged saved state.
    Apply,
    /// Save only and never read confirmation input.
    SaveOnly,
}

/// Completes the CLI orchestration after a source-only use case has released its lock.
pub fn finish_change(
    mode: ApplyMode,
    changed: bool,
    io: &mut CliIo<'_>,
    sync: &mut dyn FnMut(&mut CliIo<'_>) -> Result<(), KidoboError>,
) -> Result<(), KidoboError> {
    if !changed && mode != ApplyMode::Apply {
        return Ok(());
    }
    let source_state = if changed {
        "Source change saved"
    } else {
        "Source state unchanged"
    };
    io.presentation()
        .paragraph(io.stdout, source_state)
        .map_err(|source| {
            let source = KidoboError::from(source);
            if changed {
                KidoboError::SavedConfirmationFailed {
                    source: Box::new(source),
                }
            } else {
                source
            }
        })?;

    let apply = match mode {
        ApplyMode::Apply => true,
        ApplyMode::Prompt if io.interactive() => confirm(io, "Apply to the firewall now?")
            .map_err(|source| KidoboError::SavedConfirmationFailed {
                source: Box::new(source),
            })?,
        ApplyMode::Prompt | ApplyMode::SaveOnly => false,
    };
    if apply {
        sync(io).map_err(|source| KidoboError::SourceApplyFailed {
            source_state,
            source: Box::new(source),
        })
    } else {
        let view = io.presentation();
        view.paragraph(io.stdout, "Live enforcement is pending.")
            .and_then(|()| view.next(io.stdout, "sudo kidobo sync"))
            .map_err(|source| KidoboError::SavedConfirmationFailed {
                source: Box::new(source.into()),
            })
    }
}

/// Asks a terminal-safe default-no question and accepts only an explicit `y` or `yes`.
///
/// Callers decide whether the current invocation may prompt. Empty input and EOF decline.
pub fn confirm(io: &mut CliIo<'_>, question: &str) -> Result<bool, KidoboError> {
    const SUFFIX: &str = " [y/N]: ";
    let width = if io.terminal_width == 0 {
        80
    } else {
        io.terminal_width
    };
    let mut lines = wrap(question, width.saturating_sub(SUFFIX.len()))
        .into_iter()
        .peekable();
    while let Some(line) = lines.next() {
        if lines.peek().is_some() {
            writeln!(io.stdout, "{line}")?;
        } else {
            write!(io.stdout, "{line}{SUFFIX}")?;
        }
    }
    io.stdout.flush()?;
    let response = io.input.read_response()?;
    Ok(response.trim().eq_ignore_ascii_case("y") || response.trim().eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::*;
    use crate::cli::PromptInput;

    struct Input {
        response: Option<Result<String, KidoboError>>,
        reads: usize,
    }

    impl Input {
        fn unused() -> Self {
            Self {
                response: None,
                reads: 0,
            }
        }

        fn answer(answer: &str) -> Self {
            Self {
                response: Some(Ok(answer.to_string())),
                reads: 0,
            }
        }
    }

    impl PromptInput for Input {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            self.reads += 1;
            self.response.take().expect("unexpected confirmation read")
        }
    }

    fn with_io<T>(
        input: &mut Input,
        terminals: (bool, bool),
        under_systemd: bool,
        action: impl FnOnce(&mut CliIo<'_>) -> T,
    ) -> (T, String) {
        let mut stdout = Vec::new();
        let result = action(&mut CliIo {
            input,
            stdout: &mut stdout,
            stderr: &mut Vec::new(),
            stdin_is_terminal: terminals.0,
            stdout_is_terminal: terminals.1,
            stderr_is_terminal: false,
            terminal_width: 60,
            term_dumb: false,
            under_systemd,
            no_color: true,
        });
        (result, String::from_utf8(stdout).expect("UTF-8 stdout"))
    }

    #[test]
    fn new_application_never_prompts_with_pipes_or_systemd() {
        for (terminals, systemd) in [
            ((false, false), false),
            ((false, true), false),
            ((true, false), false),
            ((true, true), true),
        ] {
            let mut input = Input::unused();
            let mut calls = 0;
            let (result, stdout) = with_io(&mut input, terminals, systemd, |io| {
                finish_change(ApplyMode::Prompt, true, io, &mut |_| {
                    calls += 1;
                    Ok(())
                })
            });
            result.expect("save only");
            assert_eq!(calls, 0);
            assert_eq!(input.reads, 0);
            assert_eq!(
                stdout,
                "Source change saved\nLive enforcement is pending.\nNext: sudo kidobo sync\n"
            );
        }
    }

    #[test]
    fn interactive_application_requires_an_explicit_affirmative_answer() {
        for (answer, expected_calls) in [
            ("y", 1),
            (" YES \n", 1),
            ("", 0),
            ("\n", 0),
            ("n", 0),
            ("no", 0),
            ("yeah", 0),
        ] {
            let mut input = Input::answer(answer);
            let mut calls = 0;
            let (result, stdout) = with_io(&mut input, (true, true), false, |io| {
                finish_change(ApplyMode::Prompt, true, io, &mut |_| {
                    calls += 1;
                    Ok(())
                })
            });
            result.expect("confirmed source workflow");
            assert_eq!(calls, expected_calls, "answer={answer:?}");
            assert_eq!(input.reads, 1);
            assert!(stdout.contains("Apply to the firewall now? [y/N]: "));
            assert_eq!(
                stdout.contains("Live enforcement is pending."),
                expected_calls == 0
            );
        }
    }

    #[test]
    fn explicit_apply_runs_without_input_even_when_saved_state_is_unchanged() {
        for terminals in [(false, false), (false, true), (true, false), (true, true)] {
            let mut input = Input::unused();
            let mut calls = 0;
            let (result, stdout) = with_io(&mut input, terminals, false, |io| {
                finish_change(ApplyMode::Apply, false, io, &mut |_| {
                    calls += 1;
                    Ok(())
                })
            });
            result.expect("explicit apply");
            assert_eq!(calls, 1);
            assert_eq!(input.reads, 0);
            assert_eq!(stdout, "Source state unchanged\n");
        }
    }

    #[test]
    fn save_only_and_unchanged_default_never_read_input_or_call_sync() {
        for (mode, changed) in [(ApplyMode::SaveOnly, true), (ApplyMode::Prompt, false)] {
            let mut input = Input::unused();
            let mut calls = 0;
            let (result, stdout) = with_io(&mut input, (true, true), false, |io| {
                finish_change(mode, changed, io, &mut |_| {
                    calls += 1;
                    Ok(())
                })
            });
            result.expect("source only");
            assert_eq!(calls, 0);
            assert_eq!(input.reads, 0);
            assert_eq!(stdout.contains("Source change saved"), changed);
        }
    }

    #[test]
    fn apply_failures_retain_saved_state_context_and_interruption_status() {
        for changed in [false, true] {
            let mut input = Input::unused();
            let (result, _) = with_io(&mut input, (false, false), false, |io| {
                finish_change(ApplyMode::Apply, changed, io, &mut |_| {
                    Err(KidoboError::DoctorFailed)
                })
            });
            let error = result.expect_err("application failure");
            match &error {
                KidoboError::SourceApplyFailed {
                    source_state,
                    source,
                } => {
                    assert_eq!(
                        *source_state,
                        if changed {
                            "Source change saved"
                        } else {
                            "Source state unchanged"
                        }
                    );
                    assert!(matches!(source.as_ref(), KidoboError::DoctorFailed));
                }
                other => panic!("missing saved state context: {other:?}"),
            }
            assert_eq!(error.exit_code(), 1);
        }
        let (result, _) = with_io(&mut Input::unused(), (false, false), false, |io| {
            finish_change(ApplyMode::Apply, true, io, &mut |_| {
                Err(KidoboError::Interrupted)
            })
        });
        assert_eq!(result.expect_err("interrupted apply").exit_code(), 130);
    }

    #[test]
    fn confirmation_read_failures_preserve_saved_state_and_never_apply() {
        for source in [
            KidoboError::Interrupted,
            KidoboError::BlocklistPrompt {
                source: io::Error::other("read failure"),
            },
        ] {
            let expected_exit = source.exit_code();
            let mut input = Input {
                response: Some(Err(source)),
                reads: 0,
            };
            let mut calls = 0;
            let (result, _) = with_io(&mut input, (true, true), false, |io| {
                finish_change(ApplyMode::Prompt, true, io, &mut |_| {
                    calls += 1;
                    Ok(())
                })
            });
            let error = result.expect_err("confirmation read failure");
            assert_eq!(error.exit_code(), expected_exit);
            assert!(matches!(error, KidoboError::SavedConfirmationFailed { .. }));
            assert_eq!(calls, 0);
            assert_eq!(input.reads, 1);
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn post_save_output_failures_keep_context_and_do_not_start_enforcement() {
        let mut input = Input::unused();
        let mut calls = 0;
        let error = finish_change(
            ApplyMode::Apply,
            true,
            &mut CliIo {
                input: &mut input,
                stdout: &mut FailingWriter,
                stderr: &mut Vec::new(),
                stdin_is_terminal: true,
                stdout_is_terminal: true,
                stderr_is_terminal: false,
                terminal_width: 60,
                term_dumb: false,
                under_systemd: false,
                no_color: true,
            },
            &mut |_| {
                calls += 1;
                Ok(())
            },
        )
        .expect_err("post-save output failure");
        assert!(matches!(error, KidoboError::SavedConfirmationFailed { .. }));
        assert_eq!(calls, 0);
        assert_eq!(input.reads, 0);
    }

    #[test]
    fn confirmation_questions_wrap_unicode_and_escape_untrusted_controls() {
        let question =
            "Confirm this broad exception for 界界界 and its source label \u{1b}[31m\nFAKE";
        let (result, stdout) = with_io(&mut Input::answer("no"), (true, true), false, |io| {
            confirm(io, question)
        });
        assert!(!result.expect("declined question"));
        assert!(stdout.lines().count() > 1);
        assert!(stdout.contains("\\x1B[31m\\nFAKE"));
        assert!(!stdout.contains('\u{1b}'));
        assert!(stdout.ends_with(" [y/N]: "));
        assert!(
            stdout
                .lines()
                .all(|line| unicode_width::UnicodeWidthStr::width(line) <= 60)
        );
    }
}
