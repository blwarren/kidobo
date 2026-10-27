mod args;
mod bans;
mod blocklist;
mod commands;
mod configuration;
mod doctor;
mod flush;
mod init;
mod inspection;
mod interrupt;
mod mutation;
pub(crate) mod presentation;
mod preview;
mod setup;
mod sync;

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use crate::error::KidoboError;

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent terminal and environment capabilities are injected for each stream"
)]
pub struct CliIo<'a> {
    pub input: &'a mut dyn PromptInput,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub stdout_is_terminal: bool,
    pub stdin_is_terminal: bool,
    pub stderr_is_terminal: bool,
    pub terminal_width: usize,
    pub term_dumb: bool,
    pub under_systemd: bool,
    pub no_color: bool,
}

impl CliIo<'_> {
    fn presentation(&self) -> presentation::Presentation {
        presentation::Presentation::new(
            self.terminal_width,
            presentation::color_enabled(
                self.stdout_is_terminal && !self.under_systemd,
                self.no_color,
                self.term_dumb,
            ),
        )
    }

    fn interactive(&self) -> bool {
        self.stdin_is_terminal && self.stdout_is_terminal && !self.under_systemd
    }
}

pub trait PromptInput {
    fn read_response(&mut self) -> Result<String, KidoboError>;
}

struct StdinPrompt(std::io::Stdin);

impl PromptInput for StdinPrompt {
    fn read_response(&mut self) -> Result<String, KidoboError> {
        kidobo_adapters::prompt::read_line_interruptibly(&self.0, &interrupt::SigintCancellation)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::Interrupted {
                    KidoboError::Interrupted
                } else {
                    KidoboError::BlocklistPrompt { source: error }
                }
            })
    }
}

pub fn run() -> ExitCode {
    let mut stderr = io::stderr();

    if let Err(err) = interrupt::install_handler() {
        report_error(&mut stderr, &err);
        return ExitCode::from(err.exit_code());
    }

    let cli = match args::Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let exit = clap_error_exit_code(&err);
            let _print_result = err.print();
            return ExitCode::from(exit);
        }
    };

    if let Err(err) = crate::logging::init(cli.log_level.into()) {
        report_error(&mut stderr, &err);
        return ExitCode::from(err.exit_code());
    }

    if interrupt::was_interrupted() {
        return ExitCode::from(130);
    }

    let mut stdout = io::stdout();
    let stdout_is_terminal = stdout.is_terminal();
    let stderr_is_terminal = stderr.is_terminal();
    let mut input = StdinPrompt(io::stdin());
    let dispatch_result = commands::dispatch_with(
        cli.command.unwrap_or(args::Command::Status {
            format: args::ReportFormat::Human,
        }),
        &mut CliIo {
            input: &mut input,
            stdout: &mut stdout,
            stderr: &mut stderr,
            stdout_is_terminal,
            stdin_is_terminal: io::stdin().is_terminal(),
            stderr_is_terminal,
            terminal_width: terminal_size::terminal_size()
                .map_or(80, |(terminal_size::Width(width), _)| usize::from(width)),
            term_dumb: env::var_os("TERM").is_some_and(|term| term == "dumb"),
            under_systemd: env::var_os("INVOCATION_ID").is_some()
                || env::var_os("JOURNAL_STREAM").is_some(),
            no_color: env::var_os("NO_COLOR").is_some(),
        },
    );

    if interrupt::was_interrupted() {
        if let Err(error) = &dispatch_result
            && !matches!(
                error,
                KidoboError::Interrupted
                    | KidoboError::Application {
                        source: kidobo_app::AppError::Interrupted
                    }
            )
        {
            report_error(&mut stderr, error);
        }
        return ExitCode::from(130);
    }

    match dispatch_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(KidoboError::Interrupted) => ExitCode::from(130),
        Err(KidoboError::DoctorFailed) => ExitCode::from(1),
        Err(err) => {
            report_error(&mut stderr, &err);
            ExitCode::from(err.exit_code())
        }
    }
}

fn report_error(output: &mut dyn Write, error: &KidoboError) {
    let _write_result = writeln!(
        output,
        "{}",
        presentation::escape(&presentation::redact_urls(&error.to_string()))
    );
}

fn clap_error_exit_code(err: &clap::Error) -> u8 {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::clap_error_exit_code;
    use crate::cli::args::Cli;
    use clap::Parser;
    use clap::error::ErrorKind;

    #[test]
    fn cli_usage_errors_map_to_exit_code_2() {
        let err =
            Cli::try_parse_from(["kidobo", "lookup"]).expect_err("lookup without target must fail");
        assert_eq!(clap_error_exit_code(&err), 2);
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn help_maps_to_exit_code_0() {
        let err = Cli::try_parse_from(["kidobo", "--help"]).expect_err("help should early-exit");
        assert_eq!(clap_error_exit_code(&err), 0);
    }
}
