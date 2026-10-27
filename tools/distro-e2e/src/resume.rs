//! Verified, read-only reuse of completed candidate evidence.
use super::{Config, Distro, Result, Runner, hash, read_text, safe_name, strings, tag_valid};
use serde_json::Value;
use serde_json::json;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub(super) struct Resume {
    pub(super) id: String,
    pub(super) document: Value,
    archive: PathBuf,
    digest: String,
    config: Config,
}

impl Resume {
    pub(super) fn load(runner: &mut Runner, id: &str) -> Result<Self> {
        const LIMIT: u64 = 64 * 1024 * 1024;
        if !safe_name(id) {
            return Err("invalid resume run ID".into());
        }
        let dir = runner.dir.parent().ok_or("missing results root")?.join(id);
        let mut bytes = Vec::new();
        File::open(dir.join("results.json"))?
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > LIMIT {
            return Err("resume report exceeds 64 MiB".into());
        }
        let document: Value = serde_json::from_slice(&bytes)?;
        if document["run_id"] != id
            || document["validation_contract"] != super::contract::VERSION
            || !matches!(
                document["status"].as_str(),
                Some("passed" | "failed" | "interrupted")
            )
            || !document["coverage"]
                .as_str()
                .is_some_and(|v| v.starts_with("Candidate lifecycle"))
            || !document["evidence_error"].is_null()
        {
            return Err("resume requires finalized candidate evidence".into());
        }
        let archive = dir.join("evidence.tar.gz");
        let digest = hash(&archive)?;
        if document["evidence"]["sha256"] != digest {
            return Err("resume evidence archive SHA-256 mismatch".into());
        }
        let config = toml_edit::de::from_str(&Self::member(runner, &archive, "inputs/e2e.toml")?)?;
        Ok(Self {
            id: id.into(),
            document,
            archive,
            digest,
            config,
        })
    }

    fn member(runner: &mut Runner, archive: &Path, member: &str) -> Result<String> {
        runner.command(
            "tar",
            &strings(&[
                "-xOf",
                archive.to_str().ok_or("non-UTF-8 resume path")?,
                &format!("./{member}"),
            ]),
            300,
        )
    }

    pub(super) fn verify_inputs(
        &self,
        runner: &mut Runner,
        tag: &str,
        archive: &Path,
    ) -> Result<()> {
        if self.document["tag"] != tag || self.document["archive_sha256"] != hash(archive)? {
            return Err(
                "resume candidate tag or archive SHA-256 mismatch; start a fresh run".into(),
            );
        }
        self.verify_test_inputs(runner)
    }

    fn verify_test_inputs(&self, runner: &mut Runner) -> Result<()> {
        let old: Value =
            serde_json::from_str(&Self::member(runner, &self.archive, "inputs/SHA256.json")?)?;
        let current: Value =
            serde_json::from_str(&read_text(&runner.evidence().join("inputs/SHA256.json"))?)?;
        for name in [
            "installer.sh",
            "provision.sh",
            "lifecycle.sh",
            "traffic.py",
            "checks.json",
            "harness",
        ] {
            if !old[name].is_string() || old[name] != current[name] {
                return Err(format!("resume test input changed: {name}; start a fresh run").into());
            }
        }
        let checksums = Self::member(runner, &self.archive, "inputs/release/SHA256SUMS")?;
        if checksums != read_text(&runner.evidence().join("inputs/release/SHA256SUMS"))? {
            return Err("resume candidate checksum manifest mismatch".into());
        }
        Ok(())
    }

    pub(super) fn restore_candidate(&self, runner: &mut Runner) -> Result<PathBuf> {
        let tag = self.document["tag"].as_str().ok_or("resume tag missing")?;
        if !tag_valid(tag) {
            return Err("invalid resume tag".into());
        }
        let dir = runner.dir.join(".resume-candidate");
        fs::create_dir(&dir)?;
        let filename = format!("kidobo-{tag}-linux-x86_64.tar.gz");
        // Extract only these two regular inputs; never unpack guest diagnostics or paths wholesale.
        runner.command(
            "tar",
            &strings(&[
                "-xzf",
                self.archive.to_str().ok_or("non-UTF-8 resume path")?,
                "--no-same-owner",
                "--no-same-permissions",
                "-C",
                dir.to_str().ok_or("non-UTF-8 candidate path")?,
                &format!("./inputs/release/{filename}"),
                "./inputs/release/SHA256SUMS",
            ]),
            300,
        )?;
        Ok(dir.join("inputs/release").join(filename))
    }

    pub(super) fn restore_baseline(&self, runner: &mut Runner) -> Result<()> {
        for name in [
            "baseline-tag",
            "baseline-installer.sh",
            "baseline-SHA256SUMS",
        ] {
            let contents = Self::member(runner, &self.archive, name)?;
            if name == "baseline-tag" && !tag_valid(contents.trim()) {
                return Err("invalid resume baseline tag".into());
            }
            fs::write(runner.evidence().join(name), contents)?;
        }
        runner.command(
            "tar",
            &strings(&[
                "-xzf",
                self.archive.to_str().ok_or("non-UTF-8 evidence path")?,
                "--no-same-owner",
                "--no-same-permissions",
                "-C",
                runner
                    .evidence()
                    .to_str()
                    .ok_or("non-UTF-8 evidence directory")?,
                "./baseline-archive.tar.gz",
            ]),
            300,
        )?;
        if self.document["baseline_archive_sha256"]
            != hash(&runner.evidence().join("baseline-archive.tar.gz"))?
        {
            return Err("resume baseline archive hash mismatch".into());
        }
        runner.report.document["resume_from"] =
            json!({"run_id": self.id, "evidence_sha256": self.digest});
        fs::write(
            runner.evidence().join("resume-source.json"),
            serde_json::to_vec_pretty(&self.document)?,
        )?;
        Ok(())
    }

    pub(super) fn reusable(
        &self,
        runner: &mut Runner,
        config: &Config,
        target: &Distro,
    ) -> Result<bool> {
        let matching_target = self.config.distros.iter().any(|old| {
            old.id == target.id
                && old.image == target.image
                && old.family == target.family
                && old.packages == target.packages
                && old.selinux == target.selinux
        });
        let matches = matching_target
            && self.config.project == config.project
            && self.config.profile == config.profile
            && self.config.network == config.network
            && self.config.pool == config.pool
            && self.config.cpus == config.cpus
            && self.config.memory == config.memory
            && self.config.disk == config.disk
            && self.document["validation_contract"] == super::contract::VERSION
            && completed_target(&self.document, &target.id);
        if !matches {
            return Ok(false);
        }
        let preparation = self.document["results"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|result| result["distro"] == target.id)
            .and_then(|result| result["preparation"]["preparation"]["prepared_at_unix"].as_u64());
        if !preparation.is_some_and(|created| {
            super::prepared::now()
                .ok()
                .and_then(|time| time.checked_sub(created))
                .is_some_and(|age| age < config.prepared_images.max_age_hours * 3600)
        }) {
            return Ok(false);
        }
        let result = self.document["results"]
            .as_array()
            .and_then(|v| v.iter().find(|r| r["distro"] == target.id))
            .ok_or("missing resume result")?;
        if let Some(id) = result["reused_from"]["run_id"].as_str() {
            if id == self.id {
                return Err("resume evidence has a cyclic source link".into());
            }
            let original = Self::load(runner, id)?;
            if result["reused_from"]["evidence_sha256"] != original.digest
                || original.document["tag"] != self.document["tag"]
                || original.document["archive_sha256"] != self.document["archive_sha256"]
                || original.document["results"]
                    .as_array()
                    .and_then(|v| v.iter().find(|r| r["distro"] == target.id))
                    .is_none_or(|r| !r["reused_from"].is_null())
            {
                return Err("original resume evidence identity mismatch".into());
            }
            original.verify_test_inputs(runner)?;
            if original.document["baseline_archive_sha256"]
                != hash(&runner.evidence().join("baseline-archive.tar.gz"))?
            {
                return Err("original resume baseline archive changed".into());
            }
            for name in [
                "baseline-tag",
                "baseline-installer.sh",
                "baseline-SHA256SUMS",
            ] {
                if Self::member(runner, &original.archive, name)?
                    != read_text(&runner.evidence().join(name))?
                {
                    return Err("original resume baseline changed".into());
                }
            }
            return original.reusable(runner, config, target);
        }
        Ok(true)
    }

    pub(super) fn result(&self, id: &str, required: bool) -> Result<Value> {
        let mut result = self.document["results"]
            .as_array()
            .and_then(|v| v.iter().find(|r| r["distro"] == id))
            .cloned()
            .ok_or("missing resume target result")?;
        result["required"] = json!(required);
        if result["reused_from"].is_null() {
            result["reused_from"] = json!({"run_id": self.id, "evidence_sha256": self.digest});
        }
        Ok(result)
    }
}

pub(super) const LIFECYCLE_STAGES: &[&str] = &[
    "VM creation",
    "provisioning",
    "upgrade baseline preparation",
    "OS reboot and kernel verification",
    "clone admission",
    "installation and application checks",
    "application reboot and timer recovery",
    "upgrade and preservation",
    "flush and uninstall",
    "diagnostics",
    "cleanup",
];

fn completed_target(document: &Value, id: &str) -> bool {
    let Some(results) = document["results"].as_array() else {
        return false;
    };
    let matching: Vec<_> = results.iter().filter(|r| r["distro"] == id).collect();
    if matching.len() != 1 {
        return false;
    }
    let result = matching[0];
    if result["phase"] != "application"
        || !result["error"].is_null()
        || !result["cleanup_error"].is_null()
        || result["diagnostic_errors"] != json!([])
        || !result["image_fingerprint"].is_string()
    {
        return false;
    }
    let Some(stages) = document["stages"].as_array() else {
        return false;
    };
    if !LIFECYCLE_STAGES.iter().all(|name| {
        stages.iter().any(|s| {
            s["name"] == format!("{id} | {name}")
                && matches!(s["status"].as_str(), Some("passed" | "reused" | "cached"))
        })
    }) {
        return false;
    }
    if !result["reused_from"].is_null() {
        // Each resumed report retains the original evidence link. The archive digest is checked
        // on load; the original completed stages were checked before recording these as reused.
        return document["resume_from"].is_object();
    }
    let Some(checks) = document["checks"].as_array() else {
        return false;
    };
    let checks: Vec<_> = checks
        .iter()
        .filter(|c| {
            c["context"]
                .as_str()
                .is_some_and(|v| v.starts_with(&format!("{id} | ")))
        })
        .collect();
    checks.iter().all(|c| c["status"] == "passed")
        && [
            "clone admission",
            "installation and application checks",
            "application reboot and timer recovery",
            "upgrade and preservation",
            "flush and uninstall",
        ]
        .iter()
        .all(|stage| {
            checks
                .iter()
                .any(|c| c["context"] == format!("{id} | {stage}"))
        })
}

#[cfg(test)]
mod tests;
