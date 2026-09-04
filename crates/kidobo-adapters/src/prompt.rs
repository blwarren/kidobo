//! Interruptible terminal input without detached reader threads.

use std::io;
use std::os::fd::AsFd;

use kidobo_app::ports::Cancellation;
use nix::poll::{PollFd, PollFlags, poll};

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
            Ok(_) => bytes.extend_from_slice(&byte),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if cancellation.is_cancelled() {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
