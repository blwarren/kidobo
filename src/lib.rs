#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::cargo_common_metadata,
    clippy::wildcard_dependencies
)]

//! Command-line composition, rendering, logging, and exit mapping for Kidobo.
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::suspicious_command_arg_space,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::panic_in_result_fn,
        clippy::needless_pass_by_value,
        clippy::trivially_copy_pass_by_ref,
        clippy::format_push_string,
        clippy::uninlined_format_args,
        clippy::inefficient_to_string,
        clippy::to_string_in_format_args,
        clippy::implicit_clone,
        clippy::as_conversions,
        clippy::iter_over_hash_type,
        clippy::large_stack_frames,
        clippy::let_underscore_must_use,
        clippy::path_buf_push_overwrite,
        clippy::redundant_clone
    )
)]

mod cli;
pub mod error;
pub mod logging;

use std::process::ExitCode;

#[must_use]
/// Runs the command-line application and returns its stable process exit status.
pub fn run() -> ExitCode {
    cli::run()
}
