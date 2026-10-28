//! File-backed subprocess capture with bounded draining and owned process cleanup.
use crate::Result;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) struct Request<'a> {
    pub directory: &'a Path,
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

/// Each command owns only one pair of temporary files, removed even on failure.
struct Capture {
    dir: PathBuf,
    stdout: File,
    stderr: File,
}
struct ManagedChild {
    child: Child,
    completed: bool,
}
impl std::ops::Deref for ManagedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl ManagedChild {
    fn terminate(&mut self) {
        if !self.completed {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = self.child.wait();
            self.completed = true;
        }
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.terminate();
    }
}
impl Capture {
    fn new(root: &Path) -> Result<Self> {
        static NEXT_CAPTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = root.join(format!(
            ".capture-{}-{}",
            std::process::id(),
            NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let result = (|| -> Result<Self> {
            Ok(Self {
                stdout: File::create(dir.join("stdout"))?,
                stderr: File::create(dir.join("stderr"))?,
                dir: dir.clone(),
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        result
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
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
    mut observe: impl FnMut(Event<'_>) -> Result<()>,
) -> Result<Outcome> {
    const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;
    let Request {
        program,
        args,
        seconds,
        ..
    } = *request;
    let capture = Capture::new(request.directory)?;
    let mut out = File::open(capture.dir.join("stdout"))?;
    let mut err = File::open(capture.dir.join("stderr"))?;
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(capture.stdout.try_clone()?)
        .stderr(capture.stderr.try_clone()?)
        .process_group(0)
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let mut child = ManagedChild {
        child,
        completed: false,
    };
    let started = Instant::now();
    let mut heartbeat = Heartbeat::default();
    // Regular-file readers cannot block on inherited pipes. Bound each drain so
    // continuous output never prevents cancellation or timeout checks.
    let result = (|| -> Result<(Option<i32>, Option<String>)> {
        loop {
            let activity =
                drain(&mut observe, "stdout", &mut out)? | drain(&mut observe, "stderr", &mut err)?;
            let elapsed = started.elapsed();
            if heartbeat.due(elapsed) {
                observe(Event::Heartbeat(elapsed))?;
            }
            if let Some(status) = child.try_wait()? {
                child.completed = true;
                // The direct child is done; drain the bytes already captured without
                // waiting for EOF from background descendants.
                let out_len = out.metadata()?.len();
                let err_len = err.metadata()?.len();
                while out.stream_position()? < out_len {
                    drain(&mut observe, "stdout", &mut out)?;
                }
                while err.stream_position()? < err_len {
                    drain(&mut observe, "stderr", &mut err)?;
                }
                return Ok((
                    status.code(),
                    (!status.success()).then(|| format!("{program} exited {status}")),
                ));
            }
            if !request.ignore_cancellation && request.cancelled.load(Ordering::Relaxed) {
                return Ok((None, Some("interrupted".into())));
            }
            if elapsed > Duration::from_secs(seconds) {
                return Ok((None, Some("timed out".into())));
            }
            if !activity {
                std::thread::sleep(request.poll_interval);
            }
        }
    })();
    if !child.completed {
        child.terminate();
        // Best effort on failure; preserve the original reporting/command error.
        for (stream, source) in [("stdout", &mut out), ("stderr", &mut err)] {
            let end = source.metadata()?.len();
            while source.stream_position()? < end {
                if drain(&mut observe, stream, source).is_err() {
                    break;
                }
            }
        }
    }
    observe(Event::ByteCount {
        stream: "stdout",
        bytes: out.metadata()?.len(),
    })?;
    observe(Event::ByteCount {
        stream: "stderr",
        bytes: err.metadata()?.len(),
    })?;
    let (code, mut error) = result?;
    let mut output = String::new();
    if error.is_none() {
        if out.metadata()?.len() > OUTPUT_LIMIT {
            error = Some(format!(
                "{program} stdout exceeds the {OUTPUT_LIMIT}-byte capture limit"
            ));
        } else {
            out.seek(SeekFrom::Start(0))?;
            out.take(OUTPUT_LIMIT).read_to_string(&mut output)?;
        }
    }
    Ok(Outcome {
        code,
        output,
        error,
    })
}

fn drain(
    observe: &mut impl FnMut(Event<'_>) -> Result<()>,
    stream: &'static str,
    source: &mut File,
) -> Result<bool> {
    let mut buffer = [0; 8192];
    let mut activity = false;
    for _ in 0..32 {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        activity = true;
        observe(Event::Output {
            stream,
            bytes: &buffer[..count],
        })?;
    }
    Ok(activity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestDir;

    #[test]
    fn output_callback_failure_reaps_command_and_removes_capture_files() {
        let temp = TestDir::new();
        let cancelled = AtomicBool::new(false);
        let args = vec!["-c".into(), "printf '%s\\n' \"$$\"; exec sleep 30".into()];
        let request = Request {
            directory: temp.path(),
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
        assert_eq!(fs::read_dir(temp.path()).expect("capture root").count(), 0);
    }

    #[test]
    fn direct_child_completion_does_not_wait_for_background_descriptors() {
        let temp = TestDir::new();
        let cancelled = AtomicBool::new(false);
        let args = vec!["-c".into(), "sleep 30 & printf '%s\\n' \"$!\"".into()];
        let request = Request {
            directory: temp.path(),
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
        assert_eq!(fs::read_dir(temp.path()).expect("capture root").count(), 0);
    }
}
