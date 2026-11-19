//! Bounded streaming subprocess capture and owned process-group cleanup.
use crate::Result;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, pipe2};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) struct Request<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub seconds: u64,
    pub cancelled: &'a AtomicBool,
    pub ignore_cancellation: bool,
    pub poll_interval: Duration,
}

pub(super) struct Outcome {
    pub code: Option<i32>,
    pub output: String,
    pub error: Option<String>,
}

pub(super) enum Event<'a> {
    Output {
        stream: &'static str,
        bytes: &'a [u8],
    },
    Heartbeat(Duration),
    ByteCount {
        stream: &'static str,
        bytes: u64,
    },
}

struct ManagedChild {
    child: Child,
    reaped: bool,
}

impl ManagedChild {
    fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.child.id()).expect("Linux PIDs fit in pid_t"))
    }

    fn exited(&self) -> Result<Option<bool>> {
        // Keep the PID reserved until capture finishes, so a reporting failure can still
        // terminate descendants in this group without racing process-group ID reuse.
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
        match waitid(Id::Pid(self.pid()), flags) {
            Ok(WaitStatus::Exited(_, code)) => Ok(Some(code == 0)),
            Ok(WaitStatus::Signaled(..)) => Ok(Some(false)),
            Ok(_) | Err(Errno::EINTR) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn finish(&mut self, success: bool) -> std::io::Result<ExitStatus> {
        if !success {
            let _ = killpg(self.pid(), Signal::SIGKILL);
        }
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish(false);
        }
    }
}

struct Stream {
    name: &'static str,
    reader: File,
    observed: usize,
    // Limit the final drain to one pipe capacity. This includes all output still queued
    // by the direct child even if a descendant keeps writing after the child exits.
    remaining: usize,
    stdout: Option<Vec<u8>>,
}

impl Stream {
    fn pipe(name: &'static str) -> Result<(Self, Stdio)> {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC)?;
        fcntl(&reader, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        Ok((
            Self {
                name,
                reader: File::from(reader),
                observed: 0,
                remaining: usize::MAX,
                stdout: (name == "stdout").then(Vec::new),
            },
            Stdio::from(writer),
        ))
    }

    fn finish_buffered(&mut self) -> Result<()> {
        let capacity = usize::try_from(fcntl(&self.reader, FcntlArg::F_GETPIPE_SZ)?)?;
        self.remaining = self.remaining.min(capacity);
        Ok(())
    }

    fn read_chunk(
        &mut self,
        limit: usize,
        observe: &mut impl FnMut(Event<'_>) -> Result<()>,
    ) -> Result<bool> {
        let mut buffer = [0; 8192];
        let available = buffer.len().min(self.remaining);
        if available == 0 {
            return Ok(false);
        }
        let count = match self.reader.read(&mut buffer[..available]) {
            Ok(0) => {
                self.remaining = 0;
                return Ok(false);
            }
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        self.remaining -= count;
        let keep = count.min(limit - self.observed);
        self.observed += count;
        if keep > 0 {
            observe(Event::Output {
                stream: self.name,
                bytes: &buffer[..keep],
            })?;
            if let Some(output) = &mut self.stdout {
                output.extend_from_slice(&buffer[..keep]);
            }
        }
        if keep != count {
            return Err(format!(
                "{} exceeds the {limit}-byte capture limit; transcript truncated",
                self.name
            )
            .into());
        }
        Ok(true)
    }
}

#[derive(Default)]
pub(super) struct Heartbeat {
    last_notice: Duration,
}
impl Heartbeat {
    pub(super) fn due(&mut self, elapsed: Duration) -> bool {
        if elapsed.saturating_sub(self.last_notice) >= Duration::from_secs(15) {
            self.last_notice = elapsed;
            true
        } else {
            false
        }
    }
}
pub(super) fn capture(
    request: &Request<'_>,
    observe: impl FnMut(Event<'_>) -> Result<()>,
) -> Result<Outcome> {
    capture_with_limit(request, 16 * 1024 * 1024, observe)
}

fn capture_with_limit(
    request: &Request<'_>,
    limit: usize,
    mut observe: impl FnMut(Event<'_>) -> Result<()>,
) -> Result<Outcome> {
    let (stdout, out_writer) = Stream::pipe("stdout")?;
    let (stderr, err_writer) = Stream::pipe("stderr")?;
    let mut streams = [stdout, stderr];
    let child = Command::new(request.program)
        .args(request.args)
        .stdin(Stdio::null())
        .stdout(out_writer)
        .stderr(err_writer)
        .process_group(0)
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let mut child = ManagedChild {
        child,
        reaped: false,
    };
    let result = drain(request, &child, &mut streams, limit, &mut observe);
    let counts = streams.iter().try_for_each(|stream| {
        observe(Event::ByteCount {
            stream: stream.name,
            bytes: stream.observed as u64,
        })
    });
    let success = result?;
    counts?;
    let output = if success {
        String::from_utf8(streams[0].stdout.take().unwrap_or_default())?
    } else {
        String::new()
    };
    let status = child.finish(success)?;
    Ok(Outcome {
        code: status.code(),
        output,
        error: (!success).then(|| format!("{} exited {status}", request.program)),
    })
}

fn drain(
    request: &Request<'_>,
    child: &ManagedChild,
    streams: &mut [Stream; 2],
    limit: usize,
    observe: &mut impl FnMut(Event<'_>) -> Result<()>,
) -> Result<bool> {
    let started = Instant::now();
    let timeout = Duration::from_secs(request.seconds);
    let mut heartbeat = Heartbeat::default();
    let mut exited = None;
    loop {
        let elapsed = started.elapsed();
        if !request.ignore_cancellation && request.cancelled.load(Ordering::Relaxed) {
            return Err("interrupted".into());
        }
        if elapsed >= timeout {
            return Err("timed out".into());
        }
        if heartbeat.due(elapsed) {
            observe(Event::Heartbeat(elapsed))?;
        }
        if exited.is_none() {
            exited = child.exited()?;
            if exited.is_some() {
                for stream in &mut *streams {
                    stream.finish_buffered()?;
                }
            }
        }
        let mut activity = false;
        for stream in &mut *streams {
            activity |= stream.read_chunk(limit, observe)?;
        }
        if activity {
            continue;
        }
        if let Some(success) = exited {
            return Ok(success);
        }
        let mut descriptors = streams
            .iter()
            .filter(|stream| stream.remaining > 0)
            .map(|stream| PollFd::new(stream.reader.as_fd(), PollFlags::POLLIN))
            .collect::<Vec<_>>();
        let interval = request
            .poll_interval
            .min(timeout.saturating_sub(started.elapsed()));
        match poll(&mut descriptors, PollTimeout::try_from(interval)?) {
            Ok(_) | Err(Errno::EINTR) => (),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_streams_allow_exactly_the_limit_and_transcribe_only_the_prefix_on_overflow() {
        let cancelled = AtomicBool::new(false);
        for (stdout, stderr, overflow) in [
            ("1234", "abcd", None),
            ("12345", "abcd", Some("stdout")),
            ("1234", "abcde", Some("stderr")),
        ] {
            let args = [
                "-c".into(),
                format!("printf '%s' '{stdout}'; printf '%s' '{stderr}' >&2"),
            ];
            let request = Request {
                program: "sh",
                args: &args,
                seconds: 5,
                cancelled: &cancelled,
                ignore_cancellation: false,
                poll_interval: Duration::from_millis(1),
            };
            let mut captured_out = Vec::new();
            let mut captured_err = Vec::new();
            let mut counts = Vec::new();
            let result = capture_with_limit(&request, 4, |event| {
                match event {
                    Event::Output {
                        stream: "stdout",
                        bytes,
                    } => captured_out.extend_from_slice(bytes),
                    Event::Output {
                        stream: "stderr",
                        bytes,
                    } => captured_err.extend_from_slice(bytes),
                    Event::ByteCount { stream, bytes } => counts.push((stream, bytes)),
                    _ => (),
                }
                Ok(())
            });
            if let Some(stream) = overflow {
                let Err(error) = result else {
                    panic!("overflow on {stream} must fail capture")
                };
                assert!(
                    error
                        .to_string()
                        .contains(&format!("{stream} exceeds the 4-byte capture limit"))
                );
                let prefix = if stream == "stdout" {
                    &captured_out
                } else {
                    &captured_err
                };
                assert_eq!(prefix, if stream == "stdout" { b"1234" } else { b"abcd" });
                assert!(counts.contains(&(stream, 5)));
            } else {
                assert_eq!(result.expect("capture exact limits").output, "1234");
                assert_eq!(captured_out, b"1234");
                assert_eq!(captured_err, b"abcd");
            }
        }
    }

    #[test]
    fn interruption_during_output_preserves_the_reported_prefix() {
        let cancelled = AtomicBool::new(false);
        let args = ["-c".into(), "printf ready; exec sleep 30".into()];
        let request = Request {
            program: "sh",
            args: &args,
            seconds: 5,
            cancelled: &cancelled,
            ignore_cancellation: false,
            poll_interval: Duration::from_millis(1),
        };
        let mut prefix = Vec::new();
        let result = capture(&request, |event| {
            if let Event::Output {
                stream: "stdout",
                bytes,
            } = event
            {
                prefix.extend_from_slice(bytes);
                cancelled.store(true, Ordering::Relaxed);
            }
            Ok(())
        });
        let Err(error) = result else {
            panic!("interrupted command succeeded")
        };
        assert_eq!(error.to_string(), "interrupted");
        assert_eq!(prefix, b"ready");
    }

    #[test]
    fn output_callback_failure_reaps_command_and_records_byte_count() {
        let cancelled = AtomicBool::new(false);
        let args = vec!["-c".into(), "printf '%s\\n' \"$$\"; exec sleep 30".into()];
        let request = Request {
            program: "sh",
            args: &args,
            seconds: 5,
            cancelled: &cancelled,
            ignore_cancellation: false,
            poll_interval: Duration::from_millis(1),
        };
        let mut pid = None;
        let mut byte_count = None;
        let result = capture(&request, |event| {
            match event {
                Event::Output {
                    stream: "stdout",
                    bytes,
                } => {
                    pid = Some(std::str::from_utf8(bytes)?.trim().parse::<i32>()?);
                    return Err("fixture transcript failure".into());
                }
                Event::ByteCount {
                    stream: "stdout",
                    bytes,
                } => byte_count = Some(bytes),
                _ => {}
            }
            Ok(())
        });
        let Err(error) = result else {
            panic!("report failure must fail capture");
        };
        assert_eq!(error.to_string(), "fixture transcript failure");
        let pid = pid.expect("command announced its PID");
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
        assert!(byte_count.is_some_and(|bytes| bytes > 0));
    }

    #[test]
    fn direct_child_completion_does_not_wait_for_background_descriptors() {
        let cancelled = AtomicBool::new(false);
        let args = vec!["-c".into(), "sleep 30 & printf '%s\\n' \"$!\"".into()];
        let request = Request {
            program: "sh",
            args: &args,
            seconds: 2,
            cancelled: &cancelled,
            ignore_cancellation: false,
            poll_interval: Duration::from_millis(1),
        };
        let mut output = Vec::new();
        let started = Instant::now();
        let result = capture(&request, |event| {
            if let Event::Output {
                stream: "stdout",
                bytes,
            } = event
            {
                output.extend_from_slice(bytes);
            }
            Ok(())
        });
        // Always stop the test-owned background process before asserting the outcome.
        let pid: i32 = std::str::from_utf8(&output)
            .expect("PID output")
            .trim()
            .parse()
            .expect("background PID");
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let outcome = result.expect("capture parent completion");
        assert_eq!(outcome.code, Some(0));
        assert_eq!(outcome.error, None);
        assert_eq!(outcome.output.trim(), pid.to_string());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
