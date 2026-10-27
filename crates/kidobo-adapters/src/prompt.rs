//! Interruptible terminal input without detached reader threads.

use std::io;
use std::os::fd::AsFd;

use kidobo_app::ports::Cancellation;
use nix::poll::{PollFd, PollFlags, poll};

const MAX_PROMPT_LINE_BYTES: usize = 64 * 1024;

/// Reads one confirmation line, checking cancellation while input is idle or incomplete.
///
/// # Errors
///
/// Returns an interrupted I/O error on cancellation, or the underlying input/UTF-8 error.
pub fn read_line_interruptibly(
    input: &impl AsFd,
    cancellation: &dyn Cancellation,
) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        if cancellation.is_cancelled() {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, 50_u16) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        // Reading a byte after readiness never waits for a newline on partially written pipes.
        let mut byte = [0];
        match nix::unistd::read(input, &mut byte) {
            Ok(0) => break,
            Ok(_) if byte == *b"\n" => break,
            Ok(_) => {
                if bytes.len() == MAX_PROMPT_LINE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "interactive response exceeds the 65536-byte limit",
                    ));
                }
                bytes.extend_from_slice(&byte);
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if cancellation.is_cancelled() {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    #[test]
    fn response_limit_accepts_the_boundary_and_rejects_overflow() {
        let directory = tempfile::tempdir().expect("input fixture");
        let path = directory.path().join("response");
        for size in [MAX_PROMPT_LINE_BYTES, MAX_PROMPT_LINE_BYTES + 1] {
            fs::write(&path, format!("{}\n", "y".repeat(size))).expect("write response");
            let result = read_line_interruptibly(
                &File::open(&path).expect("input"),
                &kidobo_app::ports::NoCancellation,
            );
            if size == MAX_PROMPT_LINE_BYTES {
                assert_eq!(result.expect("bounded response").len(), size);
            } else {
                assert_eq!(
                    result.expect_err("overflow rejected").kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }
}
