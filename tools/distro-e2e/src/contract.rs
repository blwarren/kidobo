//! Expected guest assertions are independent of process exit status.
use super::{Result, read_text};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) const VERSION: u64 = 4;

pub(super) fn validate(
    document: &Value,
    command: usize,
    args: &[String],
    manifest_path: &Path,
) -> Result<()> {
    let selection = args
        .iter()
        .position(|arg| arg == "/opt/kidobo-e2e/lifecycle.sh")
        .map(|index| {
            (
                args.get(index + 3).map_or("", String::as_str),
                args.get(index + 1).map_or("", String::as_str),
            )
        })
        .or_else(|| {
            args.iter()
                .position(|arg| arg == "/opt/kidobo-e2e/provision.sh")
                .and_then(|index| args.get(index + 1))
                .map(|phase| ("preparation", phase.as_str()))
        });
    let Some((profile, phase)) = selection else {
        return Ok(());
    };
    let manifest: Value = serde_json::from_str(&read_text(manifest_path)?)?;
    if manifest["version"] != 1 {
        return Err("unsupported guest check manifest version".into());
    }
    let expected = manifest["profiles"][profile][phase]
        .as_object()
        .ok_or_else(|| format!("unknown guest check profile {profile}/{phase}"))?;
    validate_inventory(document, command, expected)
}

fn validate_inventory(
    document: &Value,
    command: usize,
    expected: &serde_json::Map<String, Value>,
) -> Result<()> {
    if expected.is_empty() {
        return Err("empty expected guest check inventory".into());
    }
    let checks = document["checks"].as_array().ok_or("missing checks")?;
    let mut observed = BTreeMap::<&str, u64>::new();
    for check in checks.iter().filter(|check| check["command"] == command) {
        let name = check["name"].as_str().ok_or("unnamed guest check")?;
        if !expected.contains_key(name) || check["status"] != "passed" {
            return Err(format!("unexpected or unsuccessful guest check {name}").into());
        }
        *observed.entry(name).or_default() += 1;
    }
    for (name, count) in expected {
        if count.as_u64().filter(|count| *count > 0)
            != Some(observed.get(name.as_str()).copied().unwrap_or(0))
        {
            return Err(format!(
                "guest check inventory mismatch: {name}, expected {count}, observed {}",
                observed.get(name.as_str()).copied().unwrap_or(0)
            )
            .into());
        }
    }
    if document["check_protocol_errors"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|record| record["command"] == command)
    {
        return Err("invalid guest check marker sequence".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn expected_inventory_rejects_missing_unknown_duplicate_and_unrun_checks() {
        let expected = json!({"one":1,"two":1});
        for checks in [
            json!([]),
            json!([{"name":"one","status":"passed"}]),
            json!([{"name":"one","status":"passed"},{"name":"two","status":"not-run"}]),
            json!([{"name":"one","status":"passed"},{"name":"one","status":"passed"},{"name":"two","status":"passed"}]),
            json!([{"name":"one","status":"passed"},{"name":"two","status":"passed"},{"name":"unknown","status":"passed"}]),
        ] {
            let mut document = json!({"checks":checks});
            for check in document["checks"].as_array_mut().expect("array") {
                check["command"] = json!(1);
            }
            assert!(
                validate_inventory(&document, 1, expected.as_object().expect("expected"))
                    .expect_err("incomplete inventory")
                    .to_string()
                    .contains("guest check")
            );
        }
        let document = json!({"checks":[{"name":"one","command":1,"status":"passed"},{"name":"two","command":1,"status":"passed"}]});
        validate_inventory(&document, 1, expected.as_object().expect("expected"))
            .expect("complete inventory");
    }
}
