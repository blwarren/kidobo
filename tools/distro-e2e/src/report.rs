//! Append-only human evidence alongside additive structured results.
use super::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, SyncSender};
use std::time::Instant;

pub(super) enum Event {
    Write(String, Sender<std::result::Result<(usize, usize), String>>),
    Snapshot(Value, Sender<std::result::Result<(), String>>),
}

pub(super) struct Report {
    dir: PathBuf,
    transcript: File,
    pub(super) document: Value,
    pub(super) context: String,
    pub(super) line: usize,
    marker_buffers: BTreeMap<usize, Vec<u8>>,
    sink: Option<SyncSender<Event>>,
    quiet: bool,
    command_ids: Arc<AtomicUsize>,
    check_ids: Arc<AtomicUsize>,
    stage_started: Option<Instant>,
}

impl Report {
    pub(super) fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let document_path = dir.join("results.json");
        let mut document = match File::open(document_path) {
            Ok(file) => {
                const LIMIT: u64 = 64 * 1024 * 1024;
                let mut bytes = Vec::new();
                file.take(LIMIT + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > LIMIT {
                    return Err("results.json exceeds the 64 MiB read limit".into());
                }
                serde_json::from_slice::<Value>(&bytes)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(error) => return Err(error.into()),
        };
        if !document.is_object() {
            return Err("results.json must contain an object".into());
        }
        for key in ["commands", "checks", "stages"] {
            if document[key].is_null() {
                document[key] = json!([]);
            } else if !document[key].is_array() {
                return Err(format!("results.json {key} must contain an array").into());
            }
        }
        if document["results"].is_null() {
            document["results"] = json!([]);
        }
        if document["status"].is_null() {
            document["status"] = json!("running");
        }
        let mut transcript = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(dir.join("transcript.log"))?;
        if transcript.metadata()?.len() > 0 {
            transcript.seek(SeekFrom::End(-1))?;
            let mut last = [0];
            transcript.read_exact(&mut last)?;
            if last[0] != b'\n' {
                transcript.write_all(b"\n")?;
                transcript.flush()?;
            }
        }
        let line = BufReader::new(File::open(dir.join("transcript.log"))?)
            .split(b'\n')
            .try_fold(0, |count, row| row.map(|_| count + 1))?;
        let command_id = next_id(&document["commands"]);
        let check_id = next_id(&document["checks"]);
        Ok(Self {
            dir: dir.to_owned(),
            transcript,
            document,
            context: "preparation".into(),
            line,
            marker_buffers: BTreeMap::new(),
            sink: None,
            quiet: false,
            command_ids: Arc::new(AtomicUsize::new(command_id)),
            check_ids: Arc::new(AtomicUsize::new(check_id)),
            stage_started: None,
        })
    }

    pub(super) fn worker(&self, sink: SyncSender<Event>) -> Result<Self> {
        let mut report = self.silent()?;
        report.sink = Some(sink);
        report.quiet = false;
        Ok(report)
    }

    pub(super) fn silent(&self) -> Result<Self> {
        Ok(Self {
            dir: self.dir.clone(),
            transcript: OpenOptions::new().write(true).open("/dev/null")?,
            document: json!({"commands":[], "checks":[], "stages":[], "results":[]}),
            context: "preparation".into(),
            line: self.line,
            marker_buffers: BTreeMap::new(),
            sink: None,
            quiet: true,
            command_ids: Arc::clone(&self.command_ids),
            check_ids: Arc::clone(&self.check_ids),
            stage_started: None,
        })
    }

    pub(super) fn next_command_id(&self) -> usize {
        self.command_ids.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn command_mut(&mut self, id: usize) -> Result<&mut Value> {
        self.document["commands"]
            .as_array_mut()
            .and_then(|records| records.iter_mut().find(|record| record["id"] == id))
            .ok_or_else(|| format!("missing command {id}").into())
    }

    pub(super) fn accept(&mut self, event: Event, failed: Option<&str>) -> Result<()> {
        match event {
            Event::Write(record, reply) => {
                let result = if let Some(error) = failed {
                    Err(error.into())
                } else {
                    self.write_record(record)
                };
                let acknowledgement = result
                    .as_ref()
                    .map(|line| (*line, self.line))
                    .map_err(ToString::to_string);
                let _ = reply.send(acknowledgement);
                result.map(|_| ())
            }
            Event::Snapshot(document, reply) => {
                let result = if let Some(error) = failed {
                    Err(error.into())
                } else {
                    self.merge(&document).and_then(|()| self.save())
                };
                let _ = reply.send(result.as_ref().copied().map_err(ToString::to_string));
                result
            }
        }
    }

    fn merge(&mut self, document: &Value) -> Result<()> {
        for (key, identity) in [("commands", "id"), ("checks", "id"), ("stages", "name")] {
            let records = self.document[key]
                .as_array_mut()
                .ok_or("invalid report records")?;
            for record in document[key].as_array().ok_or("invalid worker records")? {
                if let Some(current) = records
                    .iter_mut()
                    .find(|item| item[identity] == record[identity])
                {
                    current.clone_from(record);
                } else {
                    records.push(record.clone());
                }
            }
            if identity == "id" {
                records.sort_by_key(|record| record["id"].as_u64());
            }
        }
        Ok(())
    }

    /// Returns the first one-based line reference of this record.
    pub(super) fn emit(&mut self, text: &str) -> Result<usize> {
        self.write_record(escape(text.as_bytes()))
    }

    fn write_record(&mut self, mut record: String) -> Result<usize> {
        if let Some(sink) = &self.sink {
            let (reply, acknowledgement) = std::sync::mpsc::channel();
            sink.send(Event::Write(record, reply))?;
            let (first, last) = acknowledgement
                .recv()?
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
            self.line = last;
            return Ok(first);
        }
        if self.quiet {
            self.line += 1;
            return Ok(self.line);
        }
        let first = self.line + 1;
        if !record.ends_with('\n') {
            record.push('\n');
        }
        // Persist first so a broken terminal cannot erase failure evidence.
        self.transcript.write_all(record.as_bytes())?;
        self.transcript.flush()?;
        self.line += record.bytes().filter(|byte| *byte == b'\n').count();
        if !cfg!(test) {
            let stdout = std::io::stdout();
            let mut terminal = stdout.lock();
            terminal.write_all(record.as_bytes())?;
            terminal.flush()?;
        }
        Ok(first)
    }

    pub(super) fn output(&mut self, command: usize, stream: &str, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(8192) {
            for part in chunk.split_inclusive(|byte| *byte == b'\n') {
                let text = escape(part);
                self.write_record(format!(
                    "[{} | command {command} | {stream}] {text}",
                    escape(self.context.as_bytes())
                ))?;
                if stream == "stderr" {
                    self.markers(command, part)?;
                }
            }
        }
        Ok(())
    }

    fn markers(&mut self, command: usize, bytes: &[u8]) -> Result<()> {
        let pending = self.marker_buffers.entry(command).or_default();
        pending.extend_from_slice(bytes);
        if pending.last() != Some(&b'\n') {
            // Normal command output may have arbitrarily long lines. Retain only
            // a bounded suffix; a valid marker must start at a line boundary.
            if pending.len() > 16384 {
                pending.clear();
                pending.push(0);
            }
            return Ok(());
        }
        let complete = std::mem::take(pending);
        let Ok(text) = std::str::from_utf8(&complete) else {
            return Ok(());
        };
        let Some(marker) = text
            .trim_end_matches(['\r', '\n'])
            .strip_prefix("E2E_CHECK\t")
        else {
            return Ok(());
        };
        let mut fields = marker.splitn(3, '\t');
        let (Some(name), Some(status), Some(detail)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return self.marker_error(command, "incomplete check marker");
        };
        let label = match status {
            "PLAN" => "PLANNED",
            "START" => "CHECK",
            "PASS" => "PASS",
            "FAIL" => "FAIL",
            _ => return self.marker_error(command, &format!("unknown check outcome: {status}")),
        };
        if matches!(status, "PASS" | "FAIL")
            && !self.document["checks"].as_array().is_some_and(|checks| {
                checks.iter().any(|check| {
                    check["command"] == command
                        && check["name"] == name
                        && check["status"] == "running"
                })
            })
        {
            return self.marker_error(
                command,
                &format!("unmatched check outcome: {name} ({status})"),
            );
        }
        let detail_label = if matches!(status, "START" | "PLAN") {
            "expected"
        } else {
            "observed"
        };
        let line = self.emit(&format!(
            "[{}] {label}: {name}\n  {detail_label}: {detail}",
            self.context
        ))?;
        let checks = self.document["checks"]
            .as_array_mut()
            .ok_or("checks is not an array")?;
        match status {
            "PLAN" | "START" => {
                if let Some(check) = checks.iter_mut().rev().find(|check| {
                    check["command"] == command
                        && check["context"] == self.context
                        && check["name"] == name
                        && check["status"] == "not-run"
                }) {
                    if status == "START" {
                        check["status"] = json!("running");
                        check["expectation"] = json!(detail);
                        check["line"] = json!(line);
                    }
                    return self.save();
                }
                let id = self.check_ids.fetch_add(1, Ordering::Relaxed);
                checks.push(json!({
                    "id": id, "command": command, "context": self.context,
                    "name": name, "status": if status == "PLAN" { "not-run" } else { "running" }, "expectation": detail,
                    "observation": null, "line": line,
                }));
            }
            "PASS" | "FAIL" => {
                if let Some(check) = checks.iter_mut().rev().find(|check| {
                    check["command"] == command
                        && check["name"] == name
                        && check["status"] == "running"
                }) {
                    check["status"] = json!(if status == "PASS" { "passed" } else { "failed" });
                    check["observation"] = json!(detail);
                    check["end_line"] = json!(line);
                }
            }
            _ => return Ok(()),
        }
        self.save()
    }

    fn marker_error(&mut self, command: usize, error: &str) -> Result<()> {
        if self.document["check_protocol_errors"].is_null() {
            self.document["check_protocol_errors"] = json!([]);
        }
        self.document["check_protocol_errors"]
            .as_array_mut()
            .ok_or("invalid check errors")?
            .push(json!({"command":command,"error":error}));
        self.emit(&format!(
            "[{}] Invalid check protocol: {error}",
            self.context
        ))?;
        self.save()
    }

    pub(super) fn finish_checks(&mut self, command: usize, status: &str) -> Result<()> {
        self.marker_buffers.remove(&command);
        if let Some(checks) = self.document["checks"].as_array_mut() {
            for check in checks {
                if check["command"] == command
                    && (check["status"] == "running"
                        || (matches!(status, "passed" | "incomplete")
                            && check["status"] == "not-run"))
                {
                    check["status"] = json!(if status == "interrupted" {
                        "interrupted"
                    } else {
                        "failed"
                    });
                    check["observation"] = json!("command ended before an explicit check outcome");
                    check["end_line"] = json!(self.line);
                }
            }
        }
        self.save()
    }

    pub(super) fn stage(&mut self, context: &str) -> Result<()> {
        self.stage_started = Some(Instant::now());
        context.clone_into(&mut self.context);
        let line = self.emit(&format!("[{}] STAGE", self.context))?;
        self.document["current_stage"] = json!(context);
        let stages = self.document["stages"]
            .as_array_mut()
            .ok_or("stages is not an array")?;
        if let Some(stage) = stages.iter_mut().find(|stage| stage["name"] == context) {
            stage["status"] = json!("running");
            stage["line"] = json!(line);
        } else {
            stages.push(json!({"name": context, "status": "running", "line": line}));
        }
        self.save()
    }

    pub(super) fn finish_stage(&mut self, status: &str) -> Result<()> {
        if let Some(stages) = self.document["stages"].as_array_mut() {
            for stage in stages {
                if stage["name"] == self.context && stage["status"] == "running" {
                    stage["status"] = json!(status);
                    stage["end_line"] = json!(self.line);
                    let seconds = self
                        .stage_started
                        .take()
                        .map_or(0.0, |start| start.elapsed().as_secs_f64());
                    stage["active_seconds"] =
                        json!(stage["active_seconds"].as_f64().unwrap_or(0.0) + seconds);
                }
            }
        }
        self.save()
    }

    pub(super) fn save(&self) -> Result<()> {
        if let Some(sink) = &self.sink {
            let (reply, acknowledgement) = std::sync::mpsc::channel();
            sink.send(Event::Snapshot(self.document.clone(), reply))?;
            return acknowledgement.recv()?.map_err(Into::into);
        }
        if self.quiet {
            return Ok(());
        }
        atomic_write(
            &self.dir,
            "results.json",
            &serde_json::to_vec_pretty(&self.document)?,
        )?;
        atomic_write(&self.dir, "summary.txt", summary(&self.document).as_bytes())
    }
}

fn next_id(records: &Value) -> usize {
    records
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|record| record["id"].as_u64())
        .filter_map(|id| usize::try_from(id).ok())
        .max()
        .unwrap_or(0)
        + 1
}

fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = dir.join(format!(".{name}.tmp"));
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, dir.join(name))?;
    Ok(())
}

/// Printable UTF-8 remains readable; all other bytes have explicit escapes.
fn escape(bytes: &[u8]) -> String {
    let mut text = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(remaining) {
            Ok(valid) => (valid, 0),
            Err(error) => (
                std::str::from_utf8(&remaining[..error.valid_up_to()]).unwrap_or_default(),
                error
                    .error_len()
                    .unwrap_or(remaining.len() - error.valid_up_to()),
            ),
        };
        for ch in valid.chars() {
            match ch {
                '\n' => text.push('\n'),
                '\\' => text.push_str("\\\\"),
                ch if ch.is_control()
                    || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
                {
                    let _ = write!(text, "\\u{{{:x}}}", u32::from(ch));
                }
                ch => text.push(ch),
            }
        }
        remaining = &remaining[valid.len()..];
        for byte in &remaining[..invalid] {
            let _ = write!(text, "\\x{byte:02x}");
        }
        remaining = &remaining[invalid..];
    }
    text
}

fn display(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

#[expect(
    clippy::too_many_lines,
    reason = "Summary rendering keeps ordered evidence sections together"
)]
fn summary(document: &Value) -> String {
    let mut text = String::from(
        "Kidobo e2e results\nFull evidence: transcript.log (references below are line numbers)\n\n",
    );
    for key in [
        "run_id",
        "status",
        "tag",
        "archive_sha256",
        "archive",
        "targets",
        "required_targets",
        "configured_required_targets",
        "advisory_targets",
        "resume_from",
        "coverage",
        "validation_contract",
        "requested_parallelism",
        "effective_parallelism",
        "run_wall_seconds",
        "release_gate_passed",
        "all_selected_targets_passed",
        "active_targets",
        "platforms",
        "current_stage",
        "evidence",
        "warnings",
        "error",
        "evidence_error",
        "emergency_cleanup",
    ] {
        if !document[key].is_null() {
            let _ = writeln!(text, "{key}: {}", display(&document[key]));
        }
    }
    if let Some(results) = document["results"].as_array() {
        text.push_str("\nDistro results\n");
        for result in results {
            let status = if !result["error"].is_null() {
                format!("FAIL: {}", display(&result["error"]))
            } else if !result["cleanup_error"].is_null() {
                format!("FAIL: cleanup: {}", display(&result["cleanup_error"]))
            } else if result["diagnostic_errors"].is_array()
                && result["diagnostic_errors"] != json!([])
            {
                "FAIL: diagnostics incomplete".to_owned()
            } else {
                "PASS".to_owned()
            };
            let _ = writeln!(
                text,
                "{}: {status}; phase {}; residence {} seconds",
                display(&result["distro"]),
                display(&result["phase"]),
                display(&result["seconds"])
            );
            for key in [
                "required",
                "active_seconds",
                "parked_seconds",
                "source_seconds",
                "preparation",
                "reused_from",
                "source_transcript_line",
                "image",
                "image_fingerprint",
                "transcript_line",
            ] {
                if !result[key].is_null() {
                    let _ = writeln!(text, "  {key}: {}", display(&result[key]));
                }
            }
            for key in ["diagnostic_errors", "cleanup_error"] {
                if !result[key].is_null() && result[key] != json!([]) {
                    let _ = writeln!(text, "  {key}: {}", display(&result[key]));
                }
            }
        }
        if let Some(targets) = document["targets"].as_array() {
            for target in targets {
                if !results.iter().any(|result| result["distro"] == *target) {
                    let status = if document["active_target"] == *target {
                        document["status"].as_str().unwrap_or("incomplete")
                    } else {
                        "not-run"
                    };
                    let _ = writeln!(text, "{}: {status}", display(target));
                }
            }
        }
    }
    if let Some(stages) = document["stages"].as_array() {
        text.push_str("\nStages\n");
        for stage in stages {
            let _ = write!(
                text,
                "{}: {}",
                display(&stage["name"]),
                display(&stage["status"])
            );
            if let Some(line) = stage["line"].as_u64() {
                let _ = write!(text, " (transcript.log:{line})");
            }
            text.push('\n');
        }
    }
    if let Some(checks) = document["checks"].as_array() {
        text.push_str("\nChecks\n");
        for check in checks {
            let _ = writeln!(
                text,
                "[{}] {}: {} (transcript.log:{})\n  expected: {}\n  observed: {}",
                display(&check["context"]),
                display(&check["status"]),
                display(&check["name"]),
                display(&check["line"]),
                display(&check["expectation"]),
                display(&check["observation"])
            );
        }
    }
    escape(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "kidobo-e2e-report-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create report test directory");
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove report test directory");
        }
    }

    #[test]
    fn output_is_flushed_and_escaped_without_losing_partial_lines() -> Result<()> {
        let dir = Directory::new();
        let mut report = Report::open(&dir.0)?;
        report.output(1, "stdout", b"partial\x1b[31m\xff\\literal")?;
        let log = crate::read_text(&dir.0.join("transcript.log"))?;
        assert_eq!(
            log,
            "[preparation | command 1 | stdout] partial\\u{1b}[31m\\xff\\\\literal\n"
        );
        assert_eq!(report.line, 1);
        assert_eq!(escape("héllo\u{202e}".as_bytes()), "héllo\\u{202e}");
        Ok(())
    }

    #[test]
    fn fragmented_stderr_markers_create_verifiable_check_and_summary() -> Result<()> {
        let dir = Directory::new();
        let mut report = Report::open(&dir.0)?;
        report.document["targets"] = json!(["debian-13", "ubuntu"]);
        report.stage("debian-13 | traffic")?;
        report.output(1, "stderr", b"E2E_CHECK\tipv6\tSTA")?;
        assert_eq!(report.document["checks"], json!([]));
        report.output(1, "stderr", b"RT\tconnection fails\n")?;
        report.output(1, "stderr", b"E2E_CHECK\tipv6\tPASS\tprobe exited 1\n")?;
        let check = &report.document["checks"][0];
        assert_eq!(check["status"], "passed");
        assert_eq!(check["expectation"], "connection fails");
        assert_eq!(check["observation"], "probe exited 1");
        let log = crate::read_text(&dir.0.join("transcript.log"))?;
        let line = usize::try_from(check["line"].as_u64().expect("check line"))?;
        assert_eq!(
            log.lines().nth(line - 1),
            Some("[debian-13 | traffic] CHECK: ipv6")
        );
        let summary = crate::read_text(&dir.0.join("summary.txt"))?;
        assert!(summary.contains("passed: ipv6"));
        assert!(summary.contains("ubuntu: not-run"));
        assert!(summary.contains("observed: probe exited 1"));
        Ok(())
    }

    #[test]
    fn stdout_markers_and_tracing_cannot_finish_checks() -> Result<()> {
        let dir = Directory::new();
        let mut report = Report::open(&dir.0)?;
        report.output(1, "stderr", b"E2E_CHECK\tinstall\tSTART\tinstalled\n")?;
        report.output(1, "stdout", b"E2E_CHECK\tinstall\tPASS\tfake\n")?;
        report.output(
            1,
            "stderr",
            b"+ printf 'E2E_CHECK\\tinstall\\tPASS\\tfake'\n",
        )?;
        report.finish_checks(1, "interrupted")?;
        assert_eq!(report.document["checks"][0]["status"], "interrupted");
        report.output(1, "stderr", b"E2E_CHECK\tinstall\tPASS\tlate\n")?;
        assert_eq!(report.document["checks"][0]["status"], "interrupted");
        Ok(())
    }

    #[test]
    fn successful_command_cannot_pass_an_unfinished_assertion() -> Result<()> {
        let dir = Directory::new();
        let mut report = Report::open(&dir.0)?;
        report.output(1, "stderr", b"E2E_CHECK\tsnapshot\tSTART\tunchanged\n")?;
        report.finish_checks(1, "passed")?;
        assert_eq!(report.document["checks"][0]["status"], "failed");
        Ok(())
    }

    #[test]
    fn planned_checks_and_stages_preserve_failure_and_not_run_states() -> Result<()> {
        let dir = Directory::new();
        let mut report = Report::open(&dir.0)?;
        report.document["stages"] = json!([
            {"name": "debian | application", "status": "not-run"},
            {"name": "debian | diagnostics", "status": "not-run"},
            {"name": "debian | reboot", "status": "not-run"},
        ]);
        report.stage("debian | application")?;
        report.output(
            1,
            "stderr",
            b"E2E_CHECK\tinstall\tPLAN\tinstalled\nE2E_CHECK\ttraffic\tPLAN\tblocked\n",
        )?;
        report.output(1, "stderr", b"E2E_CHECK\tinstall\tSTART\tinstalled\n")?;
        assert_eq!(report.document["checks"][0]["id"], 1);
        assert_eq!(
            report.document["checks"].as_array().expect("checks").len(),
            2
        );
        report.finish_checks(1, "failed")?;
        report.finish_stage("failed")?;
        report.stage("debian | diagnostics")?;
        assert_eq!(report.document["stages"][0]["status"], "failed");
        assert_eq!(report.document["stages"][1]["status"], "running");
        assert_eq!(report.document["stages"][2]["status"], "not-run");
        assert_eq!(report.document["checks"][0]["status"], "failed");
        assert_eq!(report.document["checks"][1]["status"], "not-run");
        Ok(())
    }

    #[test]
    fn append_preserves_legacy_metadata_and_line_references() -> Result<()> {
        let dir = Directory::new();
        fs::write(
            dir.0.join("results.json"),
            br#"{"tag":"v1","results":[{"distro":"old","error":null}]}"#,
        )?;
        fs::write(dir.0.join("transcript.log"), "existing")?;
        let mut report = Report::open(&dir.0)?;
        assert_eq!(report.emit("cleanup")?, 2);
        report.save()?;
        let restored = Report::open(&dir.0)?;
        assert_eq!(restored.line, 2);
        assert_eq!(restored.document["tag"], "v1");
        assert_eq!(restored.document["results"][0]["distro"], "old");
        assert_eq!(
            crate::read_text(&dir.0.join("transcript.log"))?,
            "existing\ncleanup\n"
        );
        Ok(())
    }

    #[test]
    fn cleanup_failure_cannot_appear_as_a_pass() {
        let text = summary(
            &json!({"results": [{"distro": "debian-13", "error": null, "cleanup_error": "deletion failed"}]}),
        );
        assert!(text.contains("debian-13: FAIL: cleanup: deletion failed"));
        assert!(!text.contains("PASS"));
    }

    #[test]
    fn coordinator_keeps_interleaved_workers_ids_contexts_and_line_references() -> Result<()> {
        let dir = Directory::new();
        let mut coordinator = Report::open(&dir.0)?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(8);
        std::thread::scope(|scope| -> Result<()> {
            let mut handles = Vec::new();
            for target in ["one", "two"] {
                let mut worker = coordinator.worker(sender.clone())?;
                handles.push(scope.spawn(move || -> Result<()> {
                    worker.stage(&format!("{target} | scenario"))?;
                    let id = worker.next_command_id();
                    let line = worker.emit(&format!("{target} command {id}"))?;
                    worker.document["commands"]
                        .as_array_mut()
                        .ok_or("commands")?
                        .push(json!({"id":id,"context":worker.context,"line":line}));
                    worker.save()?;
                    worker.output(id, "stderr", b"E2E_CHECK\tsame name\tSTA")?;
                    worker.output(id, "stderr", b"RT\texpected\n")?;
                    worker.output(id, "stderr", b"E2E_CHECK\tsame name\tPASS\tobserved\n")?;
                    worker.finish_checks(id, "passed")?;
                    worker.finish_stage("passed")
                }));
            }
            drop(sender);
            for event in receiver {
                coordinator.accept(event, None)?;
            }
            for handle in handles {
                handle.join().expect("worker must not panic")?;
            }
            Ok(())
        })?;
        assert_eq!(
            coordinator.document["commands"]
                .as_array()
                .expect("commands")
                .len(),
            2
        );
        let checks = coordinator.document["checks"].as_array().expect("checks");
        assert_eq!(checks.len(), 2);
        assert_ne!(checks[0]["id"], checks[1]["id"]);
        assert_ne!(checks[0]["context"], checks[1]["context"]);
        assert!(checks.iter().all(|check| check["status"] == "passed"));
        let transcript = crate::read_text(&dir.0.join("transcript.log"))?;
        for check in checks {
            let line = usize::try_from(check["line"].as_u64().expect("line"))?;
            assert!(
                transcript
                    .lines()
                    .nth(line - 1)
                    .expect("line exists")
                    .contains("CHECK: same name")
            );
        }
        Ok(())
    }

    #[test]
    fn coordinator_reports_write_failure_to_waiting_worker() -> Result<()> {
        let dir = Directory::new();
        let mut coordinator = Report::open(&dir.0)?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut worker = coordinator.worker(sender)?;
        let handle = std::thread::spawn(move || worker.emit("record"));
        let event = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
        coordinator
            .accept(event, Some("report failure"))
            .expect_err("sink failure");
        assert_eq!(
            handle
                .join()
                .expect("worker exits")
                .expect_err("worker notified")
                .to_string(),
            "report failure"
        );
        Ok(())
    }

    #[test]
    fn transcript_write_errors_are_returned() -> Result<()> {
        let dir = Directory::new();
        // Opening /dev/full read-only for line counting never reaches EOF, so
        // substitute it only after normal report initialization.
        let mut report = Report::open(&dir.0)?;
        report.transcript = OpenOptions::new().write(true).open("/dev/full")?;
        let error = report
            .emit("must be persisted")
            .expect_err("full device must fail");
        assert!(error.to_string().contains("No space left"));
        Ok(())
    }
}
