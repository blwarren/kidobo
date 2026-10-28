//! Advisory, bounded discovery; this module never adopts an image or changes the matrix.
use crate::{Config, Result, Runner, strings};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const FEDORA_RELEASES: &str = "https://fedoraproject.org/releases.json";
const ALMA_RELEASES: &str = "https://repo.almalinux.org/almalinux/";
const DEBIAN_RELEASE: &str = "https://deb.debian.org/debian/dists/stable/Release";
const UBUNTU_RELEASES: &str = "https://changelogs.ubuntu.com/meta-release-lts";
const RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;

pub(super) struct DiscoveryPin {
    pub(super) id: String,
    pub(super) url: String,
    pub(super) sha256: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Candidate {
    pub(super) id: String,
    pub(super) url: String,
    pub(super) sha256: String,
    pub(super) checksum_url: String,
    pub(super) signature_url: Option<String>,
}

#[derive(Default, Serialize)]
pub(super) struct Discovery {
    pub(super) candidates: Vec<Candidate>,
    pub(super) notices: Vec<String>,
    pub(super) warnings: Vec<String>,
}

struct DiscoverySession<'a> {
    runner: &'a mut Runner,
    curl_program: &'a str,
    deadline: Instant,
    result: Discovery,
    request_number: usize,
}

impl DiscoverySession<'_> {
    fn fetch(&mut self, label: &str, url: &str) -> Result<Option<String>> {
        if self.runner.cancelled.load(Ordering::Relaxed) {
            return Err("image discovery interrupted".into());
        }
        self.runner.report.ensure_healthy()?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.unknown(label, "30-second discovery budget exhausted");
            return Ok(None);
        }
        self.request_number += 1;
        let dir = self.runner.evidence().join("image-discovery");
        fs::create_dir_all(&dir)?;
        let destination = dir.join(format!("{:02}.response", self.request_number));
        let timeout = remaining.min(Duration::from_secs(10));
        let timeout_text = format!("{:.3}", timeout.as_secs_f64());
        let output = self.runner.command(
            self.curl_program,
            &strings(&[
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-redirs",
                "3",
                "--connect-timeout",
                "5",
                "--max-time",
                &timeout_text,
                "--max-filesize",
                &RESPONSE_LIMIT.to_string(),
                "--output",
                destination.to_str().ok_or("non-UTF-8 discovery path")?,
                url,
            ]),
            timeout.as_secs().saturating_add(1),
        );
        self.runner.report.ensure_healthy()?;
        if self.runner.cancelled.load(Ordering::Relaxed) {
            return Err("image discovery interrupted".into());
        }
        if let Err(error) = output {
            self.unknown(label, &error.to_string());
            return Ok(None);
        }
        let mut bytes = Vec::new();
        File::open(destination)?
            .take(RESPONSE_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > RESPONSE_LIMIT {
            self.unknown(label, "response exceeds 4 MiB");
            return Ok(None);
        }
        if let Ok(text) = String::from_utf8(bytes) {
            Ok(Some(text))
        } else {
            self.unknown(label, "response is not UTF-8");
            Ok(None)
        }
    }

    fn unknown(&mut self, label: &str, error: &str) {
        self.result
            .warnings
            .push(format!("{label}: update status unknown: {error}"));
    }

    fn release(&mut self, config: &Config, family: &str, release: Result<Vec<u64>>) {
        match release {
            Ok(latest) => {
                let configured = configured_release(config, family);
                if configured.is_none_or(|current| latest > current) {
                    self.result.notices.push(format!(
                        "{family}: stable release {} is available; explicit coverage review required",
                        version_text(&latest)
                    ));
                } else {
                    self.result
                        .notices
                        .push(format!("{family}: no newer stable release found"));
                }
            }
            Err(error) => self.unknown(family, &error.to_string()),
        }
    }

    fn vendor(&mut self, pin: &DiscoveryPin) -> Result<()> {
        let (family, major) = pin.id.rsplit_once('-').ok_or("invalid vendor target ID")?;
        if numeric_version(major).is_none() || major.contains('.') {
            self.unknown(&pin.id, "unrecognized target release");
            return Ok(());
        }
        let (base, checksum_url, signature_url) = match family {
            "fedora" => {
                let base = format!(
                    "https://dl.fedoraproject.org/pub/fedora/linux/releases/{major}/Cloud/x86_64/images/"
                );
                let Some(listing) = self.fetch(&pin.id, &base)? else {
                    return Ok(());
                };
                let checksum = match fedora_checksum_name(&listing, major) {
                    Ok(name) => name,
                    Err(error) => {
                        self.unknown(&pin.id, &error.to_string());
                        return Ok(());
                    }
                };
                let checksum_url = format!("{base}{checksum}");
                (base, checksum_url, None)
            }
            "almalinux" => {
                let base =
                    format!("https://repo.almalinux.org/almalinux/{major}/cloud/x86_64/images/");
                (
                    base.clone(),
                    format!("{base}CHECKSUM"),
                    Some(format!("{base}CHECKSUM.asc")),
                )
            }
            _ => {
                self.unknown(&pin.id, "unsupported vendor family");
                return Ok(());
            }
        };
        let Some(checksums) = self.fetch(&pin.id, &checksum_url)? else {
            return Ok(());
        };
        match latest_candidate(pin, &base, &checksum_url, signature_url, &checksums) {
            Ok(candidate) => {
                if file_name(&candidate.url) == file_name(&pin.url)
                    && candidate.sha256 == pin.sha256
                {
                    self.result
                        .notices
                        .push(format!("{}: pinned vendor image is current", pin.id));
                } else {
                    self.result.notices.push(format!(
                        "{}: vendor image {} available; review with just e2e-images-refresh {}",
                        pin.id,
                        file_name(&candidate.url),
                        pin.id
                    ));
                }
                self.result.candidates.push(candidate);
            }
            Err(error) => self.unknown(&pin.id, &error.to_string()),
        }
        Ok(())
    }
}

pub(super) fn discover(
    runner: &mut Runner,
    pins: &[DiscoveryPin],
    config: &Config,
) -> Result<Discovery> {
    discover_using(runner, pins, config, "curl", Duration::from_secs(30))
}

fn discover_using(
    runner: &mut Runner,
    pins: &[DiscoveryPin],
    config: &Config,
    curl_program: &str,
    budget: Duration,
) -> Result<Discovery> {
    let mut session = DiscoverySession {
        runner,
        curl_program,
        deadline: Instant::now() + budget,
        result: Discovery::default(),
        request_number: 0,
    };
    // Family discovery always runs, even when application testing selects one target.
    for (family, url, parser) in [
        (
            "fedora",
            FEDORA_RELEASES,
            fedora_release as fn(&str) -> Result<Vec<u64>>,
        ),
        ("almalinux", ALMA_RELEASES, alma_release),
        ("debian", DEBIAN_RELEASE, debian_release),
        ("ubuntu", UBUNTU_RELEASES, ubuntu_release),
    ] {
        if let Some(text) = session.fetch(family, url)? {
            session.release(config, family, parser(&text));
        }
    }
    for pin in pins {
        session.vendor(pin)?;
    }
    Ok(session.result)
}

fn numeric_version(text: &str) -> Option<Vec<u64>> {
    text.split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        })
        .collect()
}

fn version_text(version: &[u64]) -> String {
    version
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn configured_release(config: &Config, family: &str) -> Option<Vec<u64>> {
    config
        .distros
        .iter()
        .filter_map(|target| {
            let value = target.id.strip_prefix(&format!("{family}-"))?;
            if family == "ubuntu" {
                if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                Some(vec![value[..2].parse().ok()?, value[2..].parse().ok()?])
            } else {
                numeric_version(value)
            }
        })
        .max()
}

fn fedora_release(text: &str) -> Result<Vec<u64>> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(text)?;
    rows.iter()
        .filter(|row| row["arch"] == "x86_64" && row["variant"] == "Cloud")
        .filter_map(|row| numeric_version(row["version"].as_str()?))
        .max()
        .ok_or_else(|| "no recognized stable Fedora Cloud release".into())
}

fn links(text: &str) -> impl Iterator<Item = &str> {
    text.split("href=").skip(1).filter_map(|tail| {
        let quote = tail.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        tail[1..].split(quote).next()
    })
}

fn alma_release(text: &str) -> Result<Vec<u64>> {
    links(text)
        .filter_map(|link| {
            let release = link.strip_suffix('/')?;
            if release.contains('.') {
                return None;
            }
            numeric_version(release)
        })
        .max()
        .ok_or_else(|| "no recognized stable AlmaLinux release".into())
}

fn debian_release(text: &str) -> Result<Vec<u64>> {
    let fields = fields(text)?;
    if fields.get("Origin") != Some(&"Debian")
        || fields.get("Suite") != Some(&"stable")
        || !fields.contains_key("Codename")
    {
        return Err("unrecognized Debian stable Release metadata".into());
    }
    let version = numeric_version(fields.get("Version").ok_or("missing Debian version")?)
        .ok_or("invalid Debian stable version")?;
    Ok(vec![*version.first().ok_or("empty Debian version")?])
}

fn fields(text: &str) -> Result<BTreeMap<&str, &str>> {
    let mut result = BTreeMap::new();
    for line in text
        .lines()
        .filter(|line| !line.starts_with(char::is_whitespace))
    {
        if let Some((name, value)) = line.split_once(':')
            && result.insert(name, value.trim()).is_some()
        {
            return Err(format!("duplicate release metadata field {name}").into());
        }
    }
    Ok(result)
}

fn ubuntu_release(text: &str) -> Result<Vec<u64>> {
    let normalized = text.replace("\r\n", "\n");
    let mut versions = Vec::new();
    for paragraph in normalized
        .split("\n\n")
        .filter(|part| !part.trim().is_empty())
    {
        let fields = fields(paragraph)?;
        if !fields.contains_key("Dist")
            || !fields.contains_key("Supported")
            || !fields.contains_key("Version")
        {
            return Err("unrecognized Ubuntu LTS release metadata".into());
        }
        if fields.get("Supported") != Some(&"1") {
            continue;
        }
        let Some(version) = fields
            .get("Version")
            .and_then(|value| value.strip_suffix(" LTS"))
            .and_then(numeric_version)
        else {
            continue;
        };
        if version.len() < 2 {
            return Err("invalid Ubuntu LTS version".into());
        }
        versions.push(version[..2].to_vec());
    }
    versions
        .into_iter()
        .max()
        .ok_or_else(|| "no recognized supported Ubuntu LTS release".into())
}

fn fedora_checksum_name(text: &str, major: &str) -> Result<String> {
    let prefix = format!("Fedora-Cloud-{major}-");
    links(text)
        .filter_map(|name| {
            let build = name
                .strip_prefix(&prefix)?
                .strip_suffix("-x86_64-CHECKSUM")?;
            Some((numeric_version(build)?, name))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, name)| name.into())
        .ok_or_else(|| "no recognized Fedora Cloud x86_64 checksum listing".into())
}

fn file_name(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

pub(super) fn image_version(id: &str, name: &str) -> Option<Vec<u64>> {
    let (family, major) = id.rsplit_once('-')?;
    let stem = name.strip_suffix(".x86_64.qcow2")?;
    let version = match family {
        "fedora" => stem.strip_prefix(&format!("Fedora-Cloud-Base-Generic-{major}-"))?,
        "almalinux" => stem.strip_prefix(&format!("AlmaLinux-{major}-GenericCloud-"))?,
        _ => return None,
    };
    let parts: Option<Vec<Vec<u64>>> = version.split('-').map(numeric_version).collect();
    let version: Vec<u64> = parts?.into_iter().flatten().collect();
    if family == "almalinux" && version.first()? != &major.parse::<u64>().ok()? {
        return None;
    }
    Some(version)
}

pub(super) fn checksum_entries(text: &str) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let entry = if let Some(rest) = line.strip_prefix("SHA256 (") {
            rest.split_once(") = ")
        } else {
            line.split_once(char::is_whitespace)
                .and_then(|(hash, name)| {
                    (hash.len() == 64).then_some((name.trim().trim_start_matches('*'), hash))
                })
        };
        let Some((name, hash)) = entry else {
            continue;
        };
        if hash.len() != 64
            || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err("invalid checksum entry".into());
        }
        if entries
            .insert(name.into(), hash.to_ascii_lowercase())
            .is_some()
        {
            return Err(format!("duplicate checksum entry for {name}").into());
        }
    }
    if entries.is_empty() {
        return Err("no SHA-256 checksum entries".into());
    }
    Ok(entries)
}

fn latest_candidate(
    pin: &DiscoveryPin,
    base: &str,
    checksum_url: &str,
    signature_url: Option<String>,
    text: &str,
) -> Result<Candidate> {
    let entries = checksum_entries(text)?;
    let (version, name, sha256) = entries
        .into_iter()
        .filter_map(|(name, hash)| Some((image_version(&pin.id, &name)?, name, hash)))
        .max_by(|left, right| left.0.cmp(&right.0))
        .ok_or("no recognized stable x86_64 GenericCloud artifact")?;
    let pinned_version = image_version(&pin.id, file_name(&pin.url))
        .ok_or("unrecognized pinned artifact filename")?;
    if version < pinned_version {
        return Err("catalogue is older than the pinned image; refusing downgrade".into());
    }
    Ok(Candidate {
        id: pin.id.clone(),
        url: format!("{base}{name}"),
        sha256,
        checksum_url: checksum_url.into(),
        signature_url,
    })
}

#[cfg(test)]
mod tests;
