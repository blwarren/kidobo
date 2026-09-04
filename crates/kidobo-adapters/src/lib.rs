#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(missing_docs)]
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

//! System adapter implementations for Kidobo.

pub mod asn;
pub mod blocklist_file;
pub mod blocklist_operations;
mod cache_generation;
pub mod cached_fetch;
pub mod cached_sources;
pub mod command_common;
pub mod command_runner;
pub mod config;
pub mod config_edit;
pub mod doctor;
pub mod enforcement;
pub mod flush;
pub mod github_meta;
pub mod hash;
pub mod http_cache;
pub mod http_fetch;
pub mod init;
pub mod ipset;
pub mod iptables;
pub mod limited_io;
pub mod lock;
pub mod lookup_sources;
pub mod path;
pub mod prompt;
mod remote_parse;
pub mod source_files;
pub mod source_load;
pub mod sync_observer;
pub mod sync_sources;
pub mod target_file;
