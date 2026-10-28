use super::super::{Config, Distro};
use serde::Serialize;
use serde_json::{Value, json};

/// Policy decisions and display summaries derived from recorded target results.
pub(super) struct Summary {
    pub(super) warnings: Vec<String>,
    pub(super) platforms: Vec<PlatformSummary>,
    pub(super) all_selected_targets_passed: bool,
    pub(super) release_gate_passed: bool,
    pub(super) matrix_succeeded: bool,
}

#[derive(Serialize)]
pub(super) struct PlatformSummary {
    target: Value,
    iptables_backend: Value,
    ip6tables_backend: Value,
    selinux: Value,
}

pub(super) fn summarize(
    config: &Config,
    targets: &[&Distro],
    results: &[Value],
    cancelled: bool,
) -> Summary {
    let mut warnings = results
        .iter()
        .filter(|result| result["required"] == false && result_failed(result))
        .map(|result| {
            format!(
                "advisory target {} failed; see retained evidence",
                result["distro"]
            )
        })
        .collect::<Vec<_>>();
    for result in results {
        warnings.extend(
            result["diagnostic_warnings"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }

    let all_selected_targets_passed =
        results.len() == targets.len() && results.iter().all(|result| !result_failed(result));
    let selected_required_passed = targets
        .iter()
        .filter(|target| target.required)
        .all(|target| {
            results
                .iter()
                .any(|result| result["distro"] == target.id && !result_failed(result))
        });
    let configured_required_passed =
        config
            .distros
            .iter()
            .filter(|target| target.required)
            .all(|target| {
                results
                    .iter()
                    .any(|result| result["distro"] == target.id && !result_failed(result))
            });
    let cleanup_passed = results
        .iter()
        .all(|result| result["cleanup_error"].is_null());
    let release_gate_passed = configured_required_passed && cleanup_passed && !cancelled;
    let matrix_succeeded =
        !cancelled && results.len() == targets.len() && selected_required_passed && cleanup_passed;
    let platforms = results
        .iter()
        .map(|result| PlatformSummary {
            target: result["distro"].clone(),
            iptables_backend: result["preparation"]["preparation"]["iptables_backend"].clone(),
            ip6tables_backend: result["preparation"]["preparation"]["ip6tables_backend"].clone(),
            selinux: result["preparation"]["preparation"]["selinux"].clone(),
        })
        .collect();

    Summary {
        warnings,
        platforms,
        all_selected_targets_passed,
        release_gate_passed,
        matrix_succeeded,
    }
}

pub(super) fn result_failed(result: &Value) -> bool {
    !result["error"].is_null()
        || !result["cleanup_error"].is_null()
        || result["diagnostic_errors"] != json!([])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, required: bool) -> Distro {
        Distro {
            id: id.into(),
            image: "fixture/image".into(),
            vendor_image: None,
            family: "apt".into(),
            packages: vec![],
            required,
            selinux: "image-default".into(),
        }
    }

    fn result(id: &str, required: bool) -> Value {
        json!({
            "distro": id,
            "required": required,
            "error": null,
            "cleanup_error": null,
            "diagnostic_errors": [],
            "diagnostic_warnings": [],
            "preparation": {"preparation": {
                "iptables_backend": "nft",
                "ip6tables_backend": "legacy",
                "selinux": "enforcing"
            }}
        })
    }

    fn config() -> Config {
        Config {
            project: "test-project".into(),
            profile: "test-profile".into(),
            network: "test-network".into(),
            pool: "test-pool".into(),
            cpus: 2,
            memory: "4GiB".into(),
            disk: "30GiB".into(),
            max_parallel_vms: 1,
            distros: vec![target("required", true), target("advisory", false)],
        }
    }

    #[test]
    fn outcome_policy_distinguishes_selected_coverage_configured_gate_and_cleanup() {
        let config = config();
        let mut advisory_failed = result("advisory", false);
        advisory_failed["error"] = json!("application failed");
        let mut advisory_cleanup_failed = result("advisory", false);
        advisory_cleanup_failed["cleanup_error"] = json!("delete failed");
        let mut with_supplemental_warning = result("required", true);
        with_supplemental_warning["diagnostic_warnings"] = json!(["console log unavailable"]);
        let mut required_failed = result("required", true);
        required_failed["error"] = json!("application failed");
        let mut fatal_diagnostic = result("required", true);
        fatal_diagnostic["diagnostic_errors"] = json!(["required runtime evidence failed"]);

        let cases = [
            (
                "complete success",
                vec![0, 1],
                vec![result("required", true), result("advisory", false)],
                false,
                (true, true, true, 0),
            ),
            (
                "advisory failure",
                vec![0, 1],
                vec![result("required", true), advisory_failed],
                false,
                (false, true, true, 1),
            ),
            (
                "incomplete advisory result",
                vec![0, 1],
                vec![result("required", true)],
                false,
                (false, true, false, 0),
            ),
            (
                "advisory cleanup failure",
                vec![0, 1],
                vec![result("required", true), advisory_cleanup_failed],
                false,
                (false, false, false, 1),
            ),
            (
                "supplemental diagnostic warning",
                vec![0],
                vec![with_supplemental_warning],
                false,
                (true, true, true, 1),
            ),
            (
                "cancellation",
                vec![0, 1],
                vec![result("required", true), result("advisory", false)],
                true,
                (true, false, false, 0),
            ),
            (
                "required application failure",
                vec![0, 1],
                vec![required_failed, result("advisory", false)],
                false,
                (false, false, false, 0),
            ),
            (
                "fatal diagnostic error",
                vec![0, 1],
                vec![fatal_diagnostic, result("advisory", false)],
                false,
                (false, false, false, 0),
            ),
        ];

        for (name, indices, results, cancelled, expected) in cases {
            let targets = indices
                .iter()
                .map(|index| &config.distros[*index])
                .collect::<Vec<_>>();
            let summary = summarize(&config, &targets, &results, cancelled);
            assert_eq!(
                (
                    summary.all_selected_targets_passed,
                    summary.release_gate_passed,
                    summary.matrix_succeeded,
                    summary.warnings.len(),
                ),
                expected,
                "{name}"
            );
        }

        let mut config_with_another_required = config.clone();
        config_with_another_required
            .distros
            .push(target("other-required", true));
        let filtered = summarize(
            &config_with_another_required,
            &[&config_with_another_required.distros[0]],
            &[result("required", true)],
            false,
        );
        assert!(filtered.matrix_succeeded);
        assert!(filtered.all_selected_targets_passed);
        assert!(!filtered.release_gate_passed);
    }

    #[test]
    fn platform_summaries_preserve_result_order_and_missing_metadata_as_null() {
        let config = config();
        let summary = summarize(
            &config,
            &[&config.distros[0]],
            &[result("required", true), json!({"distro":"unprepared"})],
            false,
        );
        let platforms = serde_json::to_value(summary.platforms).expect("serialize platforms");
        assert_eq!(
            platforms,
            json!([
                {
                    "target":"required",
                    "iptables_backend":"nft",
                    "ip6tables_backend":"legacy",
                    "selinux":"enforcing"
                },
                {
                    "target":"unprepared",
                    "iptables_backend":null,
                    "ip6tables_backend":null,
                    "selinux":null
                }
            ])
        );
    }
}
