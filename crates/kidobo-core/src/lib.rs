#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(clippy::all)]
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

pub mod blocklist;
pub mod config;
mod config_validation;
pub mod lookup;
pub mod network;
mod network_types;
pub mod sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}
