//! Cache orchestration tests execute a stateful fake Incus boundary, never a VM.
use super::*;
use crate::tests::{TestDir, executable};
use crate::{Report, read_text};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

struct Fixture {
    temporary: TestDir,
    config: Config,
}

impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "The stateful fake daemon and its preparation configuration form one isolated fixture"
    )]
    fn new() -> Self {
        let temporary = TestDir::new();
        let root = temporary.path();
        fs::write(
            root.join("state.json"),
            serde_json::to_vec(&json!({
                "images":{}, "instances":{}, "events":[], "scenario":"", "serial":0,
                "profile":{"config":{"user.kidobo-e2e":OWNER,"limits.cpu":"2","limits.memory":"4GiB"},
                    "devices":{"root":{"type":"disk","path":"/","pool":"test-pool","size":"30GiB"},
                        "eth0":{"type":"nic","name":"eth0","network":"test-network"}}}
            }))
            .expect("fake daemon state"),
        )
        .expect("write daemon state");
        fs::write(
            root.join("checks.json"),
            include_str!("../../../../scripts/e2e/checks.json"),
        )
        .expect("fake guest check inventory");
        executable(
            &root.join("fake-incus"),
            r#"#!/usr/bin/env python3
import json
import sys
import time
from pathlib import Path

root = Path(__file__).parent
state_path = root / 'state.json'
state = json.loads(state_path.read_text())
args = sys.argv[1:]
assert args[:2] == ['--project', 'test-project'], args
args = args[2:]
state['events'].append(args)
scenario = state['scenario']


def save():
    state_path.write_text(json.dumps(state))


def fail(status):
    save()
    raise SystemExit(status)


def describe(name):
    vm = state['instances'][name]
    return {'name':name, 'type':'virtual-machine', 'status':vm['status'],
            'config':{'user.kidobo-e2e':'kidobo-e2e-v1', 'volatile.base_image':vm['base']}}


def markers(phase):
    checks = json.loads((root / 'checks.json').read_text())['profiles']['preparation'][phase]
    for name, count in checks.items():
        for _ in range(count):
            print(f'E2E_CHECK\t{name}\tSTART\tfixture expectation', file=sys.stderr)
            print(f'E2E_CHECK\t{name}\tPASS\tfixture observation', file=sys.stderr)


operation = args[0]
if operation == 'query':
    print(json.dumps({'metadata':state['profile']}))
elif operation == 'image':
    action = args[1]
    if action == 'list':
        print(json.dumps(list(state['images'].values())))
    elif action == 'info':
        print('Fingerprint: ' + 'a' * 64)
    elif action == 'set-property':
        state['images'][args[2]]['properties'][args[3]] = args[4]
    elif action == 'delete':
        del state['images'][args[2]]
    else:
        raise AssertionError(args)
elif operation == 'init':
    source, name = args[1:3]
    assert name not in state['instances'], name
    state['serial'] += 1
    if source.startswith('images:'):
        manifest = None
        base = source.split(':', 1)[1]
    else:
        base = source
        manifest = json.loads(state['images'][base]['properties']['kidobo_e2e_manifest'])
    state['instances'][name] = {'base':base, 'status':'Stopped', 'manifest':manifest,
                                'machine_id':f"{state['serial']:032x}", 'boot':0}
elif operation == 'list':
    names = list(state['instances']) if args[1] == '--format=json' else [args[1]]
    print(json.dumps([describe(name) for name in names if name in state['instances']]))
elif operation == 'config':
    pass
elif operation in {'start','stop','restart'}:
    vm = state['instances'][args[1]]
    if operation == 'stop':
        vm['status'] = 'Stopped'
    else:
        vm['status'] = 'Running'
        vm['boot'] += 1
elif operation == 'delete':
    del state['instances'][args[1]]
elif operation == 'publish':
    vm = state['instances'][args[1]]
    assert vm['status'] == 'Stopped', args
    properties = dict(argument.split('=',1) for argument in args[2:] if '=' in argument and not argument.startswith('--'))
    fingerprint = f"{len(state['images'])+1:064x}"
    state['images'][fingerprint] = {'fingerprint':fingerprint, 'public':False,
                                    'type':'virtual-machine', 'properties':properties}
    if scenario == 'publish-failure':
        fail(72)
elif operation == 'file':
    if args[1] == 'push':
        assert Path(args[-2]).is_file(), args
    elif args[1] == 'pull':
        Path(args[-1]).mkdir(parents=True, exist_ok=True)
    else:
        raise AssertionError(args)
elif operation == 'exec':
    name = args[1]
    vm = state['instances'][name]
    assert vm['status'] == 'Running', name
    command = args[4:]
    if command[0] == 'cat':
        path = command[1]
        if path == '/proc/sys/kernel/random/boot_id':
            print(f"{name}-boot-{vm['boot']}")
        elif path.endswith('/relabel-scheduled'):
            print('0')
        elif path.endswith('/manifest.json'):
            print(json.dumps(vm['manifest']))
        elif path.endswith('/admission.json'):
            print(json.dumps({'format':1, 'machine_id':vm['machine_id'],
                              'boot_id':f"{name}-boot-{vm['boot']}",
                              'kernel':'fixture-kernel', 'selinux':'Disabled'}))
        else:
            raise AssertionError(command)
    elif command[0] in {'true','sh','test'}:
        pass
    elif command[:2] == ['bash','/opt/kidobo-e2e/provision.sh']:
        phase = command[2]
        if phase == '--prepare' and scenario == 'prepare-failure':
            fail(70)
        if phase == '--check-kernel':
            vm['manifest'] = {'format':1, 'prepared_at_unix':int(time.time()), 'family':'apt',
                              'architecture':'x86_64', 'expected_kernel':'fixture-kernel',
                              'selinux_requested':'image-default', 'selinux_actual':'Disabled',
                              'source_machine_id':vm['machine_id'],
                              'source_boot_id':f"{name}-boot-{vm['boot']}",
                              'packages_sha256':'b'*64, 'provision_sha256':'c'*64,
                              'iptables_backend':'iptables v1.8.11 (nf_tables)',
                              'ip6tables_backend':'ip6tables v1.8.11 (nf_tables)'}
        if phase == '--admit' and vm['base'] == state.get('rejected_fingerprint'):
            print('E2E_CHECK\tprepared clone admission\tSTART\tfixture expectation', file=sys.stderr)
            print('E2E_CHECK\tprepared clone admission\tFAIL\tcorrupt cached clone', file=sys.stderr)
            fail(71)
        markers(phase)
    else:
        raise AssertionError(command)
else:
    raise AssertionError(args)
save()
"#,
        );
        let config = Config {
            project: "test-project".into(),
            profile: "test-profile".into(),
            network: "test-network".into(),
            pool: "test-pool".into(),
            cpus: 2,
            memory: "4GiB".into(),
            disk: "30GiB".into(),
            max_parallel_vms: 2,
            prepared_images: Settings::default(),
            distros: vec![Distro {
                id: "primary".into(),
                image: "fixture/image".into(),
                family: "apt".into(),
                packages: vec!["bash".into()],
                required: true,
                selinux: "image-default".into(),
            }],
        };
        Self { temporary, config }
    }

    fn state(&self) -> Value {
        serde_json::from_str(
            &read_text(&self.temporary.path().join("state.json")).expect("daemon state"),
        )
        .expect("valid daemon state")
    }

    fn change(&self, update: impl FnOnce(&mut Value)) {
        let mut state = self.state();
        update(&mut state);
        fs::write(
            self.temporary.path().join("state.json"),
            serde_json::to_vec(&state).expect("updated state"),
        )
        .expect("save updated state");
    }

    fn runner(&self, run: u32) -> Runner {
        let dir = self.temporary.path().join(format!("run-100-{run}"));
        let report = Report::open(&dir).expect("cache report");
        fs::create_dir_all(dir.join(".evidence/inputs")).expect("frozen inputs");
        for (name, contents) in [
            (
                "provision.sh",
                include_str!("../../../../scripts/e2e/provision.sh"),
            ),
            (
                "checks.json",
                include_str!("../../../../scripts/e2e/checks.json"),
            ),
        ] {
            fs::write(dir.join(".evidence/inputs").join(name), contents)
                .expect("freeze preparation input");
        }
        fs::write(
            dir.join(".evidence/inputs/SHA256.json"),
            r#"{"harness":"stable-fixture"}"#,
        )
        .expect("freeze host preparation identity");
        Runner {
            project: self.config.project.clone(),
            dir,
            incus_program: self.temporary.path().join("fake-incus"),
            cancelled: Arc::new(AtomicBool::new(false)),
            report,
            command_poll_interval: Duration::from_millis(1),
            ignore_cancellation: false,
        }
    }

    fn prepare(&self, run: u32, refresh: bool) -> (Runner, Result<Value>) {
        let mut runner = self.runner(run);
        let result = super::prepare(
            &mut runner,
            &self.config,
            &self.config.distros[0],
            &format!("run-100-{run}-primary"),
            refresh,
        );
        (runner, result)
    }

    fn count(&self, first: &str, second: Option<&str>) -> usize {
        self.state()["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter(|event| event[0] == first && second.is_none_or(|value| event[1] == value))
            .count()
    }

    fn guest_count(&self, phase: &str) -> usize {
        self.state()["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter(|event| {
                event
                    .as_array()
                    .is_some_and(|arguments| arguments.iter().any(|value| value == phase))
            })
            .count()
    }
}

#[test]
fn cold_preparation_publishes_a_private_image_only_after_clone_admission() {
    let fixture = Fixture::new();
    let (runner, outcome) = fixture.prepare(1, false);
    let metadata = outcome.expect("cold preparation");
    assert_eq!(metadata["cache_hit"], false);
    assert_eq!(fixture.count("publish", None), 1);
    assert_eq!(fixture.guest_count("--prepare"), 1);
    assert_eq!(fixture.guest_count("--sanitize"), 1);
    assert_eq!(fixture.guest_count("--admit"), 1);
    let state = fixture.state();
    let image = state["images"]
        .as_object()
        .expect("images")
        .values()
        .next()
        .expect("published image");
    assert_eq!(image["public"], false);
    assert_eq!(image["properties"]["user.kidobo-e2e"], OWNER);
    assert_eq!(image["properties"]["kidobo_e2e_ready"], "true");
    assert_ne!(
        metadata["admission"]["machine_id"],
        metadata["preparation"]["source_machine_id"]
    );
    let events = state["events"].as_array().expect("events");
    let admitted = events
        .iter()
        .position(|event| {
            event
                .as_array()
                .is_some_and(|args| args.iter().any(|arg| arg == "--admit"))
        })
        .expect("clone admission event");
    let ready = events
        .iter()
        .position(|event| {
            event[0] == "image"
                && event[1] == "set-property"
                && event[3] == "kidobo_e2e_ready"
                && event[4] == "true"
        })
        .expect("ready event");
    assert!(admitted < ready);
    assert!(runner.evidence().join("primary/preparation.json").is_file());
    let saved: Value = serde_json::from_str(
        &read_text(&runner.evidence().join("primary/preparation.json"))
            .expect("saved cold preparation metadata"),
    )
    .expect("saved cold metadata JSON");
    assert_eq!(saved, metadata);
}

#[test]
fn warm_hit_preserves_preparation_age_and_avoids_packages_alias_lookup_and_publish() {
    let fixture = Fixture::new();
    let (_, first) = fixture.prepare(1, false);
    let first = first.expect("cold preparation");
    let fingerprint = first["image_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();
    let created =
        fixture.state()["images"][&fingerprint]["properties"]["kidobo_e2e_prepared_at"].clone();
    fixture.change(|state| {
        state["images"][&fingerprint]["properties"]["kidobo_e2e_last_used"] = json!("0");
    });
    let (runner, second) = fixture.prepare(2, false);
    let second = second.expect("warm preparation");
    assert_eq!(second["cache_hit"], true);
    assert_eq!(second["image_fingerprint"], fingerprint);
    assert_eq!(fixture.guest_count("--prepare"), 1);
    assert_eq!(fixture.count("image", Some("info")), 1);
    assert_eq!(fixture.count("publish", None), 1);
    let state = fixture.state();
    assert_eq!(
        state["images"][&fingerprint]["properties"]["kidobo_e2e_prepared_at"],
        created
    );
    assert_ne!(
        state["images"][&fingerprint]["properties"]["kidobo_e2e_last_used"],
        "0"
    );
    let saved: Value = serde_json::from_str(
        &read_text(&runner.evidence().join("primary/preparation.json"))
            .expect("saved warm preparation metadata"),
    )
    .expect("saved warm metadata JSON");
    assert_eq!(saved, second);
}

#[test]
fn forced_refresh_builds_a_new_generation_despite_a_fresh_cache() {
    let fixture = Fixture::new();
    let (_, first) = fixture.prepare(1, false);
    let first = first.expect("cold preparation");
    let (_, second) = fixture.prepare(2, true);
    let second = second.expect("forced refresh");
    assert_eq!(second["cache_hit"], false);
    assert_ne!(first["image_fingerprint"], second["image_fingerprint"]);
    assert_eq!(fixture.guest_count("--prepare"), 2);
    assert_eq!(fixture.count("image", Some("info")), 2);
    assert_eq!(fixture.count("publish", None), 2);
}

#[test]
fn expired_generation_is_never_used_when_its_refresh_fails() {
    let fixture = Fixture::new();
    let (_, first) = fixture.prepare(1, false);
    let fingerprint = first.expect("cold preparation")["image_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();
    let expired =
        (now().expect("clock") - fixture.config.prepared_images.max_age_hours * 3600).to_string();
    fixture.change(|state| {
        state["images"][&fingerprint]["properties"]["kidobo_e2e_prepared_at"] = json!(expired);
        state["scenario"] = json!("prepare-failure");
    });
    let (_, outcome) = fixture.prepare(2, false);
    assert!(
        outcome
            .expect_err("expired image cannot replace failed refresh")
            .to_string()
            .contains("exited")
    );
    assert_eq!(fixture.guest_count("--admit"), 1);
    assert_eq!(fixture.guest_count("--prepare"), 2);
    assert_eq!(fixture.count("publish", None), 1);
}

#[test]
fn failed_cached_admission_invalidates_and_rebuilds_once_with_diagnostics() {
    let fixture = Fixture::new();
    let (_, first) = fixture.prepare(1, false);
    let fingerprint = first.expect("cold preparation")["image_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();
    fixture.change(|state| state["rejected_fingerprint"] = json!(fingerprint));
    let (runner, outcome) = fixture.prepare(2, false);
    let metadata = outcome.expect("one fresh rebuild");
    assert_eq!(metadata["cache_hit"], false);
    assert_ne!(metadata["image_fingerprint"], fingerprint);
    assert_eq!(metadata["rejected_cache"]["fingerprint"], fingerprint);
    assert_eq!(fixture.guest_count("--prepare"), 2);
    assert_eq!(fixture.guest_count("--admit"), 3);
    assert_eq!(
        fixture.state()["images"][&fingerprint]["properties"]["kidobo_e2e_ready"],
        "false"
    );
    assert!(
        runner.report.document["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .filter(|check| check["status"] == "failed")
            .all(|check| check["context"]
                .as_str()
                .is_some_and(|context| context.starts_with("cache diagnostics | ")))
    );
}

#[test]
fn interrupted_publish_leaves_an_unready_generation_that_cannot_be_reused() {
    let fixture = Fixture::new();
    fixture.change(|state| state["scenario"] = json!("publish-failure"));
    let (_, failed) = fixture.prepare(1, false);
    assert!(
        failed
            .expect_err("publish failure")
            .to_string()
            .contains("exited")
    );
    let state = fixture.state();
    let failed_fingerprint = state["images"]
        .as_object()
        .expect("images")
        .keys()
        .next()
        .expect("partial image")
        .clone();
    assert_eq!(
        state["images"][&failed_fingerprint]["properties"]["kidobo_e2e_ready"],
        "false"
    );
    assert_eq!(fixture.guest_count("--admit"), 0);
    fixture.change(|state| state["scenario"] = json!(""));
    let (_, retried) = fixture.prepare(2, false);
    let retried = retried.expect("replacement generation");
    assert_eq!(retried["cache_hit"], false);
    assert_ne!(retried["image_fingerprint"], failed_fingerprint);
    assert_eq!(fixture.count("publish", None), 2);
}

fn image(id: u8, target: &str, created: u64, last_used: u64) -> Value {
    json!({"fingerprint":format!("{id:064x}"),"type":"virtual-machine","public":false,
        "properties":{"user.kidobo-e2e":OWNER,"kidobo_e2e_target":target,"kidobo_e2e_ready":"true",
            "kidobo_e2e_key":"identity","kidobo_e2e_prepared_at":created.to_string(),
            "kidobo_e2e_last_used":last_used.to_string()}})
}

#[test]
fn pruning_preserves_foreign_public_and_in_use_images_and_two_ready_generations() {
    let fixture = Fixture::new();
    let time = now().expect("clock");
    let mut entries = vec![
        image(1, "primary", time, time),
        image(2, "primary", time - 1, time),
        image(3, "primary", time - 2, time),
        image(4, "primary", time - 3, time),
        image(5, "other-target", time, time - 336 * 3600),
        image(6, "primary", time + 1, time),
        image(7, "foreign", time, time),
        image(8, "public", time, time),
    ];
    entries[5]["properties"]["kidobo_e2e_ready"] = json!("false");
    entries[6]["properties"]["user.kidobo-e2e"] = json!("another-suite");
    entries[7]["public"] = json!(true);
    fixture.change(|state| {
        for entry in entries {
            let fingerprint = entry["fingerprint"].as_str().expect("fingerprint").to_owned();
            state["images"][fingerprint] = entry;
        }
        state["instances"]["run-100-in-use"] = json!({"base":format!("{:064x}",4),"status":"Stopped","manifest":null,"machine_id":"d".repeat(32),"boot":0});
    });
    let mut runner = fixture.runner(1);
    prune(&mut runner, &fixture.config).expect("prune owned unused images");
    let state = fixture.state();
    for kept in [1, 2, 4, 7, 8] {
        assert!(
            state["images"].get(format!("{kept:064x}")).is_some(),
            "image {kept} should be retained"
        );
    }
    for removed in [3, 5, 6] {
        assert!(
            state["images"].get(format!("{removed:064x}")).is_none(),
            "image {removed} should be pruned"
        );
    }
}

#[test]
fn cache_identity_tracks_frozen_preparation_target_resources_and_profile() {
    let fixture = Fixture::new();
    let runner = fixture.runner(1);
    let original_profile = fixture.state()["profile"].clone();
    let original = super::key(
        &runner,
        &fixture.config,
        &fixture.config.distros[0],
        &original_profile,
    )
    .expect("original identity");
    for changed in [
        "preparation",
        "harness",
        "image",
        "family",
        "packages",
        "security",
        "cpu",
        "memory",
        "disk",
        "pool",
        "network",
        "profile-name",
        "profile-device",
    ] {
        let mut config = fixture.config.clone();
        let mut target = config.distros[0].clone();
        let mut profile = original_profile.clone();
        match changed {
            "preparation" => fs::write(
                runner.evidence().join("inputs/provision.sh"),
                "changed preparation",
            )
            .expect("changed frozen preparation"),
            "harness" => fs::write(
                runner.evidence().join("inputs/SHA256.json"),
                r#"{"harness":"changed"}"#,
            )
            .expect("changed frozen harness"),
            "image" => target.image = "fixture/new-release".into(),
            "family" => target.family = "dnf".into(),
            "packages" => target.packages.push("another-prerequisite".into()),
            "security" => target.selinux = "enforcing".into(),
            "cpu" => config.cpus = 3,
            "memory" => config.memory = "6GiB".into(),
            "disk" => config.disk = "40GiB".into(),
            "pool" => config.pool = "other-pool".into(),
            "network" => config.network = "other-network".into(),
            "profile-name" => config.profile = "other-profile".into(),
            "profile-device" => profile["devices"]["root"]["size"] = json!("40GiB"),
            _ => unreachable!(),
        }
        let current = super::key(&runner, &config, &target, &profile).expect("changed identity");
        assert_ne!(
            current, original,
            "changed {changed} must invalidate preparation"
        );
        fs::write(
            runner.evidence().join("inputs/provision.sh"),
            include_str!("../../../../scripts/e2e/provision.sh"),
        )
        .expect("restore frozen preparation");
        fs::write(
            runner.evidence().join("inputs/SHA256.json"),
            r#"{"harness":"stable-fixture"}"#,
        )
        .expect("restore frozen harness");
    }
    let mut policy = fixture.config.clone();
    policy.max_parallel_vms = 1;
    policy.prepared_images.max_age_hours = 24;
    policy.prepared_images.max_generations = 1;
    assert_eq!(
        super::key(&runner, &policy, &policy.distros[0], &original_profile)
            .expect("policy-only identity"),
        original
    );
}

#[test]
fn fresh_image_property_cannot_hide_an_expired_preparation_manifest() {
    let fixture = Fixture::new();
    let (_, first) = fixture.prepare(1, false);
    let fingerprint = first.expect("cold preparation")["image_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();
    fixture.change(|state| {
        let properties = &mut state["images"][&fingerprint]["properties"];
        let mut manifest: Value = serde_json::from_str(
            properties["kidobo_e2e_manifest"]
                .as_str()
                .expect("manifest property"),
        )
        .expect("stored manifest");
        manifest["prepared_at_unix"] = json!(now().expect("clock") - 168 * 3600);
        properties["kidobo_e2e_manifest"] =
            json!(serde_json::to_string(&manifest).expect("expired manifest"));
    });
    let (_, outcome) = fixture.prepare(2, false);
    let metadata = outcome.expect("refresh inconsistent provenance");
    assert_eq!(metadata["cache_hit"], false);
    assert_ne!(metadata["image_fingerprint"], fingerprint);
    assert_eq!(fixture.guest_count("--prepare"), 2);
    assert_eq!(fixture.guest_count("--admit"), 2);
}
